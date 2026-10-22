"""Real unified state/repair/verifiers, synthetic guest and service execution."""
import copy
import json
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

from experiments.retirement_observer import controller as c
from scripts.run_unified_pipeline import parser, prepare, run_session
from taintforge_env import input_retirement as m3, retirement_evidence as evidence
from taintforge_env import phase1_retirement as r, retirement_mappings as mappings
from taintforge_env import capsule_resources as resources
from taintforge_env.phase1_runtime import Phase1Runtime
from taintforge_env.prebuilt_runner import PrebuiltRootfsRunner
from taintforge_env.synthesis_loop import EnvironmentSynthesisLoop
from tests import test_execution_capsule as fixture
from tests.test_unified_finalization import ObservedExecutor
from tests.test_phase1_retirement_integration import capture
from tests.test_capsule_unified_lifecycle import resource_entry


def synthetic_evidence(run, code, fault=None):
    binding = c.read_json(run / "config/capsule_binding.json")
    output, out = run / "logs/capsule", r.directory(binding)
    pc = binding["input_retirement"]["entry_point"] + 4096
    data = dict(candidate_id=1, oep=pc, decision_pc=pc+8, decision_trace_seq=23,
        continuation_pc=pc+9, epoch=0, generation=1, policy="heuristic_candidate",
        oep_proven=False, trigger=r.VERDICT_TRIGGER)
    release = dict(pages_released=2, bitmaps_released=2, register_buffers_released=1,
        explicitly_wiped_bytes=1024, owner_roots_remaining=0, all_bytes_zeroed=False,
        allocator_residue_verified=False, guest_memory_modified=False)
    packets = [dict(protocol=2, event=event, nonce=binding["lifecycle_attempt"], host_pid=77,
        **{k: binding[k] for k in ("session_id", "attempt_id", "analysis_instance_id")}, data=value)
        for event, value in zip(r.EVENTS, [data, {}, {}, {}, release])]
    analyzer = capture(binding, packets)
    hashes = r.preserve_export(binding, analyzer)
    digest = c.p.sha(analyzer.paths["manifest"])
    c.p.write_json(out / "retirement.json", dict(status="released", qemu_pid=77, events=packets,
        nonce=binding["lifecycle_attempt"], permit_sent=True, stream_closed=True,
        permit_after_verified_export=True, accepted_manifest_sha256=digest, preserved_sha256=hashes,
        permit=f"RETIRE {binding['lifecycle_attempt']} 1 {digest}\n", fault="none", claims=r.CLAIMS))
    identity = mappings.record_identity(binding, 77, 12345)
    c.p.write_json(out / "mapping-identity.json", identity)
    def maps(point):
        rows = []
        for index, (role, path) in enumerate(mappings.module_paths(binding).items()):
            if point == 2 and role == "phase1": continue
            (major, minor), inode = r.maps.file_identity(path)
            start = 0x10000 + index*0x2000
            rows.append(f"{start:x}-{start+4096:x} r-xp 00000000 {major:02x}:{minor:02x} {inode} /{role}.so\n")
        (out / f"maps-{point}.txt").write_text("".join(rows))
        (out / f"process-{point}.stat").write_text("77 (synthetic qemu) S " + "0 "*18 + "12345 0\n")
        return dict(event="maps_held", point=point, mapping_schema=1,
            mapping_identity_sha256=c.p.sha(out / "mapping-identity.json"), process_start_ticks=12345,
            process_stat_sha256=c.p.sha(out / f"process-{point}.stat"),
            maps_sha256=c.p.sha(out / f"maps-{point}.txt"),
            mapping_evidence=mappings.verdict(identity, "".join(rows), point == 2))
    def snap(point, sample):
        return dict(event="snapshot", protocol=3, pc_source=c.PC_SOURCE, qemu_eip=pc-4,
            host_pid=77, point=point, sample=sample, seq=1 if point == 1 else 500,
            pc=binding["input_retirement"]["entry_point"] if point==1 else pc+point,
            monotonic_ms=point*1000+sample*binding["observer"]["hold_ms"],
            regs=[1,2,3,4,5,6,7,0x1000], stack_readable=True, stack_hex="00"*32)
    def command(value): return dict(event="command", command=value)
    def resumed(point): return dict(event="resumed", protocol=3, point=point, seq=1 if point == 1 else 500)
    before, after = maps(1), maps(2)
    for name, suffix in (("maps", ".txt"), ("process", ".stat")):
        shutil.copyfile(out / (name+"-2"+suffix), out / (name+"-unmapped"+suffix))
    events = [snap(1,1), before, command("CHECK 1"), snap(1,2), command("RESUME 1"), resumed(1),
        dict(event="export_ready"), command("STAMP"), dict(event="stamp",protocol=3,host_pid=77,seq=80,monotonic_ms=1500),
        dict(event="permit_grant",pre_permit_seq=80), dict(event="released"),
        dict(event="module_unmapped", maps_sha256=c.p.sha(out / "maps-unmapped.txt"),
             process_stat_sha256=c.p.sha(out / "process-unmapped.stat")), command("HOLD 2"),
        snap(2,1), after, command("CHECK 2"), snap(2,2), command("RESUME 2"), resumed(2),
        dict(event="progress_window",scope=c.WINDOW,lower_seq=80,upper_seq=500,entries=420,
             exact_uninstall_interval=False,exact_oep_cutover=False), dict(event="done",protocol=3,host_pid=77,seq=520)]
    status = "passed"
    if fault == "early":
        events = events[:11] + [dict(event="early_exit",protocol=3,host_pid=77,seq=100)]
        status = "inconclusive"
    c.p.write_json(output / "observer-events.json", dict(schema=2, events=[
        e | dict(controller_seq=i, controller_ns=i*1000) for i,e in enumerate(events, 1)]))
    c.p.write_json(output / "controller.json", dict(status=status, profile=c.PROFILE))
    result = dict(status=status, qemu_exit=code, qemu_pid=77, controller_exit=0, supervisor_kill=False,
        **{k:binding[k] for k in mappings.IDENTITY})
    c.p.write_json(output / "supervisor.json", result)
    c.p.write_json(output / "resources.json", resource_entry(binding))
    if fault == "export":
        (out / "export/unpacked.json").write_text("{}")
    elif fault == "verdict":
        saved=c.read_json(out / "retirement.json");saved["events"][0]["data"]["oep"]+=4
        c.p.write_json(out / "retirement.json", saved)
    elif fault == "missing-verdict":
        (out / "retirement.json").unlink()
    elif fault == "identity":
        result["attempt_id"] = "previous-attempt"
        c.p.write_json(output / "supervisor.json", result)
    elif fault in {"disconnect", "timeout"}:
        c.p.write_json(output / "controller.json", dict(status="failed", error=fault))
    return binding, result


class InputExecutor(ObservedExecutor):
    def __init__(self, *, repair=False, fault=None):
        super().__init__()
        self.repair, self.fault, self.runs = repair, fault, []

    def run(self, command, **kwargs):
        guest = "unshare" in command and str(command[-1]).endswith("run_prebuilt_sandbox.sh")
        if guest:
            self.guest_exit_code = (42 if self.repair and not (self.rootfs / "var/lib/taintforge-m3").exists() else 0)
            if self.fault == "early": self.guest_exit_code = 123
            if self.fault == "timeout": self.guest_exit_code = 124
            if self.fault == "disconnect": self.guest_exit_code = 125
        result = super().run(command, **kwargs)
        if not guest: return result
        run = Path(command[-1]).parent
        code = self.guest_exit_code
        (run / "logs/runtime_stdout.log").write_text("M3_INPUT_OK\n" if code == 0 else "")
        trace = ('77 open("/var/lib/taintforge-m3/output",O_WRONLY|O_CREAT|O_TRUNC,0600) = -1 errno=2 (No such file or directory)\n' if code == 42 else
                 '77 write(1,0x8049000,12) = 12\n')
        if self.fault == "early": trace += "OBSERVER_ABORT code=123 reason=exit_before_observation\n"
        (run / "logs/qemu_strace.log").write_text(trace+f"77 exit({code})\n")
        if self.runs and (self.rootfs / "tmp/attempt-only").exists():
            raise AssertionError("Runtime mutation leaked into repaired attempt")
        (self.rootfs / "tmp/attempt-only").write_text("discard on restart")
        binding, saved = synthetic_evidence(run, code, self.fault)
        if self.fault == "stale" and self.runs:
            previous = r.directory(self.runs[0][1]) / "retirement.json"
            shutil.copyfile(previous, r.directory(binding) / "retirement.json")
        self.runs.append((run,binding,saved))
        return result


class InputRetirementTests(unittest.TestCase):
    setUp = fixture.UnifiedCapsuleTests.setUp

    def prepare_input(self, *, name="m3", extra=()):
        sidecar = Path(str(self.plugin)+".runtime.json")
        manifest = c.read_json(sidecar)
        manifest["formats"] = {"cooperative_retirement":1,"verdict_retirement":2}
        c.p.write_json(sidecar,manifest)
        self.goal = self.base / "goal.json"
        c.p.write_json(self.goal, dict(schema_version=1, goal_id="input-complete", description="Benign input completes", mode="all", rules=[
            dict(id="stdout",type="text_contains",source="stdout",needle="M3_INPUT_OK\n",min_count=1)]))
        args = parser().parse_args(["run","--retire-phase1","--binary",self.built["guest"],
            "--qemu",str(self.qemu),"--plugin",str(self.plugin),"--out",str(self.base/name),
            "--target-spec",str(self.goal),"--max-iterations","3",*extra])
        built = dict(plugin=self.built["plugin"],source_sha256={"observer.c":"a"*64,"qemu-plugin.h":"b"*64})
        with patch.object(resources,"preflight"), patch.object(c,"build_plugin",return_value=built), \
             patch.object(c.p,"load_phase1",return_value=(None,Phase1Runtime.load(self.plugin),None)):
            launch = prepare(args)
        return self.base/name,launch

    def invoke(self,out,launch,executor,steps=1):
        original = EnvironmentSynthesisLoop.run
        def loop_run(loop):
            loop.runner_factory = lambda config: PrebuiltRootfsRunner(config,executor=executor)
            return original(loop)
        def service(binding,command,executor,**kwargs):
            result=executor.run(command,**kwargs)
            code=result.returncode
            c.p.write_json(Path(binding["run_dir"])/"logs/capsule/service.json",dict(
                status="verified",unit=resources.unit_name(binding),attempt_id=binding["attempt_id"],
                attempt_contract_sha256=binding["attempt_contract_sha256"],tree_empty=True,
                wrapper_exit=code, service={"Result":"success" if code==0 else "exit-code"}))
            return result
        with patch.object(EnvironmentSynthesisLoop,"run",loop_run), \
             patch.object(PrebuiltRootfsRunner,"_check_host_dependencies"),patch.object(resources,"execute",service):
            return run_session(out,launch,max_steps=steps)

    def test_original_input_no_fixture_oracle_and_portable_evidence(self):
        out,launch=self.prepare_input()
        source=Path(self.built["guest"])
        expected=c.p.sha(source); source.unlink()
        executor=InputExecutor()
        report,code=self.invoke(out,launch,executor)
        self.assertEqual(code,0,report.get("error"))
        self.assertEqual(report["outcome"],"completed")
        self.assertEqual(report["stop_reason"],"goal_reached")
        run,binding,_=executor.runs[0]
        self.assertNotIn("symbols",binding["capsule"])
        self.assertEqual(c.p.sha(run/"guest-i386"),expected)
        self.assertTrue(report["capsule"]["phase1_retirement"]["phase1_retired"])
        self.assertFalse(report["capsule"]["claims"]["oep_proven"])
        portable=report["capsule"]["portable_evidence"]
        with tempfile.TemporaryDirectory() as tmp:
            dest=Path(tmp)/"moved";shutil.copytree(run/"retirement-evidence",dest)
            checked=evidence.verify(dest,expected_sha256=portable["manifest_sha256"])
            self.assertEqual(checked["attempt_outcome"],"passed")
        self.assertTrue(EnvironmentSynthesisLoop.verify_session(out/"session")["binding_verified"])
        from scripts.run_input_retirement_e2e import validate_case
        self.assertEqual(len(validate_case("normal",out,report,code)),1)

    def test_repair_creates_fresh_attempt_and_preserves_original_elf(self):
        out,launch=self.prepare_input()
        executor=InputExecutor(repair=True)
        report,code=self.invoke(out,launch,executor,steps=2)
        self.assertEqual(code,0,report.get("error"))
        self.assertEqual(report["outcome"],"completed",report)
        self.assertEqual(report["stop_reason"],"goal_reached",report)
        self.assertEqual(len(executor.runs),2)
        first,second=[x[1] for x in executor.runs]
        for field in ("attempt_id","analysis_instance_id","attempt_contract_sha256","lifecycle_attempt","rootfs"):
            self.assertNotEqual(first[field],second[field],field)
        self.assertEqual(first["input_retirement"],second["input_retirement"])
        self.assertTrue((Path(second["rootfs"])/"var/lib/taintforge-m3").is_dir())
        self.assertEqual(executor.runs[0][2]["qemu_exit"],42)
        for run,_,_ in executor.runs:
            self.assertEqual(evidence.verify(run/"retirement-evidence")["attempt_outcome"],"passed")
        from scripts.run_input_retirement_e2e import validate_case
        self.assertEqual(len(validate_case("repair",out,report,code)),2)

    def test_failed_finalization_blocks_resume_and_false_goal(self):
        for fault in ("export","verdict","identity","missing-verdict","disconnect","timeout","early"):
            with self.subTest(fault=fault):
                out,launch=self.prepare_input(name=fault)
                executor=InputExecutor(fault=fault)
                report,code=self.invoke(out,launch,executor)
                self.assertEqual(code,1,report)
                self.assertEqual(report["outcome"],"intervention_required")
                self.assertEqual(report["finalization"]["stages"]["capsule"]["status"],"failed")
                self.assertEqual(self.invoke(out,launch,executor)[1],1)
                self.assertEqual(len(executor.runs),1)
                if fault=="early":
                    self.assertEqual(evidence.verify(executor.runs[0][0]/"retirement-evidence")["attempt_outcome"],"inconclusive")

    def test_old_retirement_cannot_authorize_repaired_attempt(self):
        out,launch=self.prepare_input()
        executor=InputExecutor(repair=True,fault="stale")
        report,code=self.invoke(out,launch,executor,steps=2)
        self.assertEqual(code,1)
        self.assertEqual(len(executor.runs),2)
        self.assertIn("Incomplete retirement evidence",report["capsule"]["error"])

    def test_unsupported_inputs_and_conflicting_flags_rejected_before_creation(self):
        original=Path(self.built["guest"]).read_bytes()
        for kind in ("pie","x64","dynamic","bad-entry","symlink"):
            with self.subTest(kind=kind):
                data=bytearray(original)
                if kind=="pie":struct.pack_into("<H",data,16,3)
                if kind=="x64":struct.pack_into("<H",data,18,62)
                if kind=="dynamic":
                    phoff=struct.unpack_from("<I",data,28)[0];struct.pack_into("<I",data,phoff,2)
                if kind=="bad-entry":struct.pack_into("<I",data,24,0xffffffff)
                sample=self.base/("invalid-"+kind)
                if kind=="symlink":sample.symlink_to(self.built["guest"])
                else:sample.write_bytes(data)
                with self.assertRaises((ValueError,RuntimeError)):
                    m3.inspect_input(sample)
        for i,extra in enumerate((["--phase1-option","ir-probe=1"],["--capsule-probe"],
                                  ["--retirement-max-insns","8"],["--capsule-pause-ms","6000"])):
            with self.subTest(extra=extra),self.assertRaises((ValueError,RuntimeError)):
                self.prepare_input(name="invalid-options-"+str(i),extra=extra)
        self.assertFalse(any(self.base.glob("invalid-options-*")))

    def test_copied_attempt_or_input_contract_is_rejected(self):
        out,launch=self.prepare_input();executor=InputExecutor()
        report,code=self.invoke(out,launch,executor);self.assertEqual(code,0,report.get("error"))
        run,binding,result=executor.runs[0]
        for name in ("config/input-attempt.json","config/observer-contract.json","guest-i386"):
            with self.subTest(name=name):
                path=run/name;before=path.read_bytes();path.chmod(0o600);path.write_bytes(before+b"x")
                with self.assertRaises((ValueError,RuntimeError)):c.verify_attempt(binding,result)
                path.write_bytes(before)

    def test_supervisor_uses_bound_plugins_and_reaps_timeout(self):
        for timeout in (False,True):
            with self.subTest(timeout=timeout):
                out,launch=self.prepare_input(name="supervisor-"+str(timeout))
                executor=InputExecutor();report,code=self.invoke(out,launch,executor)
                self.assertEqual(code,0,report.get("error"))
                run,binding,_=executor.runs[0]
                context=Mock()
                context.Pipe.side_effect=lambda:(Mock(),Mock())
                workers=[Mock(pid=111,exitcode=0),Mock(pid=112,exitcode=0)]
                for worker in workers:worker.is_alive.return_value=False
                context.Process.side_effect=workers
                process=Mock(pid=77)
                process.poll.return_value=None if timeout else 0
                process.wait.side_effect=([subprocess.TimeoutExpired("qemu",35),-9] if timeout else [0])
                with tempfile.TemporaryDirectory() as ipc,patch.object(m3.mp,"get_context",return_value=context), \
                     patch.object(m3.p,"wait_worker_ready"),patch.object(resources,"inspect_self",return_value=resource_entry(binding)), \
                     patch.object(m3.subprocess,"Popen",return_value=process) as start:
                    code=m3.supervise(binding,ipc)
                saved=c.read_json(run/"logs/capsule/supervisor.json")
                argv=start.call_args.args[0]
                self.assertEqual(argv[-1],"/bin/sample.elf")
                self.assertEqual(argv.count("-plugin"),2)
                self.assertIn("retire-trigger=verdict",argv[argv.index("-plugin")+1])
                self.assertNotIn("retire-boundary="," ".join(argv))
                self.assertIn("stdout",start.call_args.kwargs)
                for worker in workers:self.assertTrue(worker.join.called)
                if timeout:
                    self.assertEqual(code,137);self.assertTrue(saved["supervisor_kill"])
                    self.assertEqual(saved["status"],"failed");process.kill.assert_called_once()
                else:
                    self.assertEqual(code,0);self.assertEqual(saved["status"],"passed")
                    process.kill.assert_not_called()

    def test_runtime_settings_and_observer_code_are_bound_for_resume(self):
        out,launch=self.prepare_input();executor=InputExecutor(repair=True)
        report,code=self.invoke(out,launch,executor)
        self.assertEqual(code,0,report.get("error"))
        binding=c.read_json(out/"session/synthesis_loop.json")
        paths={item["path"] for item in binding["analysis_stack_files"]}
        self.assertIn(str(c.HERE/"controller.py"),paths)
        runtime=out/"template/config/runtime.json"
        data=c.read_json(runtime);data["capsule"]["phase1_retirement"]["max_instructions"]+=1
        c.p.write_json(runtime,data)
        resumed,code=self.invoke(out,launch,executor)
        self.assertEqual(code,1);self.assertEqual(len(executor.runs),1)


if __name__ == "__main__":
    unittest.main()
