"""New unified route with synthetic QEMU/systemd evidence; no VM claims."""
import copy
import json
from pathlib import Path
import subprocess
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from scripts.run_unified_pipeline import parser, prepare
from taintforge_env import phase1_retirement as retirement, capsule_resources as resources
from taintforge_env.phase1_runtime import Phase1Runtime
from tests import test_execution_capsule as fixture
from tests.test_capsule_unified_lifecycle import resource_entry

probe, capsule, write_json = fixture.probe, fixture.capsule, fixture.write_json


def capture(binding, packets):
    run = Path(binding["run_dir"])
    analyzer = retirement.analysis(binding)
    identity = {key: binding[key] for key in ("session_id", "attempt_id", "analysis_instance_id")}
    verdict = packets[0]["data"]
    records = [
        ("analysis_started", {"build_id": analyzer.runtime.build_id, "plugin_api": 6,
                              "analysis_detach": "cooperative-controlled-v1"}),
        ("runtime_observation", {"kind": "instruction_callback"}),
        ("oep_candidate_selected", {"candidate_id": 1, "address": verdict["oep"]}),
        ("oep_verdict", {k: v for k, v in verdict.items() if k not in {"epoch", "generation"}} | {"rewind": False}),
        ("analysis_finished", {})]
    events = [{"schema_version": 1, **identity, "event_type": name, "event_seq": index,
               "event_id": identity["analysis_instance_id"] + f":{index}", "data": data,
               "status": "selected_candidate" if name == "oep_verdict" else "partial",
               "analysis_epoch": 0, "code_generation": 1} for index, (name, data) in enumerate(records, 1)]
    if packets[0]["protocol"] == 2:
        events[2].update(status="candidate", current_pc=verdict["decision_pc"], trace_seq=verdict["decision_trace_seq"])
        events[2]["data"]["decision_trace_seq"] = verdict["decision_trace_seq"]
        events[3].update(current_pc=verdict["continuation_pc"], trace_seq=verdict["decision_trace_seq"])
    analyzer.paths["events"].write_text("".join(json.dumps(e) + "\n" for e in events))
    analyzer.paths["dump"].write_bytes(b"A" * 4096)
    report = {"schema_version": 1, **identity, "capture_status": "success", "capture_pc": verdict["continuation_pc"],
              "capture_trace_seq": verdict["decision_trace_seq"], "capture_generation": verdict["generation"],
              "capture_epoch": 0, "oep": hex(verdict["oep"]), "regions": [{"addr": hex(verdict["oep"]),
                  "size": 4096, "prot": 5, "offset": 0, "sha256": probe.sha(analyzer.paths["dump"])}]}
    write_json(analyzer.paths["report"], report)
    artifacts = {"ir": None}
    for name in ("events", "dump", "report"):
        path = analyzer.paths[name]
        artifacts[name] = {"path": str(path), "size": path.stat().st_size, "sha256": probe.sha(path)}
    write_json(analyzer.paths["manifest"], {"schema_version": 1, **identity, "storage_status": "ok",
        "capture_status": "success", "analysis_status": "partial", "artifacts": artifacts, "event_count": len(events)})
    packets[1]["data"] = {"sha256": probe.sha(analyzer.paths["manifest"]), "size": analyzer.paths["manifest"].stat().st_size}
    return analyzer


class SyntheticRetirementExecutor(fixture.CapsuleExecutor):
    def __init__(self, fault="none", corruption=None):
        super().__init__("phase1-first")
        self.fault, self.corruption = fault, corruption
        self.guest_exit_code = retirement.FAULTS[fault]

    def run(self, command, **kwargs):
        result = super().run(command, **kwargs)
        if "unshare" not in command:
            return result
        run = Path(command[-1]).parent
        binding = capsule.read_json(run / "config/capsule_binding.json")
        out = retirement.directory(binding)
        symbols = binding["capsule"]["symbols"]
        protocol = binding["settings"]["phase1_retirement"]["protocol"]
        data = {"candidate_id": 1, "oep": symbols["phase1_payload_entry"], "decision_pc": symbols["phase1_payload_entry"]+8,
                "decision_trace_seq": 23, "continuation_pc": (symbols["phase1_payload_entry"]+9 if protocol == 2
                                                             else symbols["phase1_retire_boundary"]),
                "epoch": 0, "generation": 1,
                "policy": "heuristic_candidate", "oep_proven": False}
        if protocol == 2:
            data["trigger"] = retirement.VERDICT_TRIGGER
        payloads = [data, {}, {}, {}, {"pages_released": 3, "bitmaps_released": 2, "register_buffers_released": 1,
                    "explicitly_wiped_bytes": 1024, "owner_roots_remaining": 0, "all_bytes_zeroed": False,
                    "allocator_residue_verified": False, "guest_memory_modified": False}]
        packets = [{"protocol": protocol, "event": name, "nonce": binding["lifecycle_attempt"], "host_pid": 77,
                    **{k: binding[k] for k in ("session_id", "attempt_id", "analysis_instance_id")}, "data": d}
                   for name, d in zip(retirement.EVENTS, payloads)]
        analyzer = capture(binding, packets)
        hashes = retirement.preserve_export(binding, analyzer)
        digest = probe.sha(analyzer.paths["manifest"])
        saved = {"status": "released" if not self.guest_exit_code else "fault_injected", "qemu_pid": 77,
            "events": packets if not self.guest_exit_code else packets[:2], "nonce": binding["lifecycle_attempt"],
            "permit_sent": not bool(self.guest_exit_code), "stream_closed": not bool(self.guest_exit_code),
            "permit_after_verified_export": True, "accepted_manifest_sha256": digest,
            "preserved_sha256": hashes, "permit": f"RETIRE {binding['lifecycle_attempt']} 1 {digest}\n",
            "fault": self.fault, "claims": retirement.CLAIMS}
        write_json(out / "retirement.json", saved)
        output = run / "logs/capsule"
        journal = [json.loads(line) for line in (output / "observations.jsonl").read_text().splitlines()]
        if self.guest_exit_code:
            journal = journal[:5]
        from taintforge_env import retirement_mappings
        write_json(out / "mapping-identity.json", retirement_mappings.record_identity(binding, 77, 12345))
        for event in journal:
            if event["event"] != "handoff":
                continue
            event.update(claims=retirement.CLAIMS, phase1_retired=event["point"] == 2)
            if event["state"] not in {"handoff_ready", "continuation_observed"}:
                continue
            point = event["point"]
            bundle = run / "config/analyzer_runtime"
            phase = capsule.read_json(run / "config/phase1_binding.json")
            paths = [binding["capsule"]["plugin"]] + ([phase["plugin"]] if point == 1 else [])
            rows = []
            for index, path in enumerate(paths):
                (major, minor), inode = retirement.maps.file_identity(bundle / path)
                start = 0x10000 + index * 0x2000
                rows.append(f"{start:x}-{start+4096:x} r-xp 00000000 {major:02x}:{minor:02x} {inode} /{path}\n")
            text = "".join(rows)
            path = out / f"maps-{point}.txt"
            path.write_text(text)
            stat_path = out / f"process-{point}.stat"
            stat_path.write_text("77 (synthetic qemu) S " + "0 " * 18 + "12345 0\n")
            event.update(mapping_schema=1, mapping_identity_sha256=probe.sha(out / "mapping-identity.json"),
                         process_stat_sha256=probe.sha(stat_path), process_start_ticks=12345, maps_sha256=probe.sha(path),
                         mapping_evidence=retirement.mapping_verdict(binding, text, point == 2))
        (output / "observations.jsonl").write_text("".join(json.dumps(e)+"\n" for e in journal))
        report = capsule.read_json(output / "supervisor.json")
        report.update(qemu_exit=self.guest_exit_code, status="aborted" if self.guest_exit_code else "passed")
        write_json(output / "supervisor.json", report)
        write_json(output / "resources.json", resource_entry(binding))
        if self.guest_exit_code:
            (output / "capsule-fd.txt").write_bytes(b"before\n")
            (run / "logs/runtime_stdout.log").write_bytes(b"")
            with (run / "logs/qemu_strace.log").open("a") as log:
                log.write(f"CAPSULE_PHASE1_ABORT code={self.guest_exit_code} reason=synthetic_test\n")
            write_json(output / "controller.json", {"status": "failed"})
        if self.corruption:
            self.corruption(binding)
        return result


class RetirementUnifiedTests(unittest.TestCase):
    setUp = fixture.UnifiedCapsuleTests.setUp

    def prepare(self, fault="none", *, trigger="boundary"):
        manifest = capsule.read_json(Path(str(self.plugin)+".runtime.json"))
        manifest["formats"] = {"cooperative_retirement": 1, "verdict_retirement": 2}
        write_json(Path(str(self.plugin)+".runtime.json"), manifest)
        built = copy.deepcopy(self.built)
        protocol = retirement.settings(trigger=trigger)["protocol"]
        source, extra = retirement.fixture(protocol)
        built["phase1_retirement"] = {"protocol": protocol, "guest_source_sha256": probe.sha(source)}
        # Real fixed ELF symbol layout; plugin and execution are synthetic.
        subprocess.run(["as", "--32", str(source), "-o", str(self.base / "new.o")], check=True)
        subprocess.run(["ld", "-m", "elf_i386", "-z", "noexecstack", str(self.base / "new.o"), "-o", built["guest"]], check=True)
        names = {*built["symbols"], *extra}
        built["symbols"] = {p[0]: int(p[2],16) for line in probe.command("nm", "-P", "--defined-only", built["guest"]).splitlines()
                            if (p := line.split())[0] in names}
        built["hashes"].update({"guest.S": probe.sha(source),
                                "capsule_guest_i386": probe.sha(built["guest"])})
        out = self.base / f"run-{len(list(self.base.glob('run-*')))}"
        args = parser().parse_args(["run", "--capsule-phase1-retirement", "--capsule-retirement-fault", fault,
            "--capsule-retirement-trigger", trigger,
            "--out", str(out), "--plugin", str(self.plugin), "--qemu", str(self.qemu), "--max-iterations", "1"])
        with patch.object(probe, "load_phase1", return_value=(None, Phase1Runtime.load(self.plugin), {})), \
             patch.object(retirement, "build", return_value=built), patch.object(resources, "preflight"):
            launch = prepare(args)
        return out, launch

    def invoke(self, out, launch, executor):
        status = {"LoadState": "loaded", "ActiveState": "inactive" if not executor.guest_exit_code else "failed",
                  "Result": "success" if not executor.guest_exit_code else "exit-code"}
        with patch.object(resources, "control", return_value=SimpleNamespace(returncode=0, stderr="")), \
             patch.object(resources, "status", return_value=status), patch.object(resources, "CGROUP", self.base / "cgroup"):
            return fixture.UnifiedCapsuleTests.invoke(self, out, launch, executor)

    def test_real_retirement_profile_finalizes_and_binds_artifacts(self):
        out, launch = self.prepare()
        report, code = self.invoke(out, launch, SyntheticRetirementExecutor())
        self.assertEqual(code, 0, report.get("error"))
        self.assertTrue(report["capsule"]["phase1_retirement"]["phase1_retired"])
        self.assertTrue(report["capsule"]["resources"]["tree_empty"])
        self.assertTrue(fixture.EnvironmentSynthesisLoop.verify_session(out / "session")["artifacts_verified"])

    def test_verdict_profile_finalizes_without_a_fixed_retirement_symbol(self):
        out, launch = self.prepare(trigger="verdict")
        report, code = self.invoke(out, launch, SyntheticRetirementExecutor())
        self.assertEqual(code, 0, report.get("error"))
        self.assertEqual(report["capsule"]["phase1_retirement"]["verdict"]["trigger"], retirement.VERDICT_TRIGGER)
        binding = capsule.read_json(Path(report["run_dir"]) / "config/capsule_binding.json")
        self.assertNotIn("phase1_retire_boundary", binding["capsule"]["symbols"])
        self.assertTrue(fixture.EnvironmentSynthesisLoop.verify_session(out / "session")["artifacts_verified"])

    def test_verdict_export_delayed_capture_is_rejected_independently(self):
        out, launch = self.prepare(trigger="verdict")
        def corrupt(binding):
            saved = capsule.read_json(retirement.directory(binding) / "retirement.json")
            packets = saved["events"]
            packets[0]["data"]["decision_trace_seq"] += 1
            write_json(retirement.directory(binding) / "retirement.json", saved)
        report, code = self.invoke(out, launch, SyntheticRetirementExecutor(corruption=corrupt))
        self.assertEqual(code, 1)
        self.assertEqual(report["finalization"]["stages"]["capsule"]["status"], "failed")

    def test_bad_digest_refusal_marks_attempt_failed_and_blocks_resume(self):
        out, launch = self.prepare("bad-digest")
        report, code = self.invoke(out, launch, SyntheticRetirementExecutor("bad-digest"))
        self.assertEqual(code, 1)
        self.assertEqual(report["capsule"]["status"], "aborted", report.get("error"))
        self.assertEqual(report["capsule"]["qemu_exit"], 88)
        resumed, code = fixture.run_session(out, launch, max_steps=1)
        self.assertEqual(code, 1)
        self.assertEqual(resumed["executions_this_invocation"], 0)

    def test_preserved_export_tampering_fails_independent_finalization(self):
        out, launch = self.prepare()
        def corrupt(binding):
            (retirement.directory(binding) / "export/unpacked.bin").write_bytes(b"changed")
        report, code = self.invoke(out, launch, SyntheticRetirementExecutor(corruption=corrupt))
        self.assertEqual(code, 1)
        self.assertEqual(report["finalization"]["stages"]["capsule"]["status"], "failed")


if __name__ == "__main__":
    unittest.main()
