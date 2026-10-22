"""M2 native protocol + synthetic evidence tests. No QEMU execution claims."""
import copy
import json
import os
from pathlib import Path
import shlex
import shutil
import socket
import subprocess
import tempfile
import time
import unittest

from experiments.retirement_observer import controller as c
from taintforge_env import retirement_evidence as evidence, retirement_mappings as mappings
from taintforge_env import phase1_retirement as r
from tests import test_phase1_retirement_integration as old


class NativeObserverTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.binary = Path(cls.temporary.name) / "native-test"
        flags = shlex.split(c.p.command("pkg-config", "--cflags", "--libs", "glib-2.0"))
        if os.environ.get("TF_OBSERVER_SANITIZERS") == "1":
            flags += ["-fsanitize=address,undefined", "-fno-omit-frame-pointer", "-fno-pie", "-no-pie"]
        c.p.command("cc", "-std=c11", "-O1", "-g", "-Wall", "-Wextra", "-Werror", "-pthread",
                    "-ffunction-sections", "-fdata-sections", "-Wl,--gc-sections",
                    "-I", c.p.HERE / "vendor", c.HERE / "native_test.c", "-o", cls.binary, *flags)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def start(self, mode="normal"):
        parent, child = socket.socketpair()
        process = subprocess.Popen([str(self.binary), str(child.fileno()), mode], pass_fds=(child.fileno(),),
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        child.close()
        self.addCleanup(parent.close)
        def reap():
            if process.poll() is None: process.kill()
            process.communicate(timeout=2)
        self.addCleanup(reap)
        return process, parent, c.Channel(parent, lambda event: None, timeout=2)

    def hold(self, channel, point):
        first = channel.receive("snapshot")
        c.snapshot_ok(first, first["host_pid"], point, 1)
        channel.command("CHECK " + str(point))
        second = channel.receive("snapshot")
        c.snapshot_ok(second, first["host_pid"], point, 2)
        c.same_hold(first, second, 0)
        return first

    def resume(self, channel, point):
        channel.command("RESUME " + str(point))
        return channel.receive("resumed")

    def test_counter_stamp_while_vcpu_blocked_and_dynamic_hold(self):
        process, parent, channel = self.start()
        first = self.hold(channel, 1)
        self.assertEqual(first["seq"], 1)
        self.resume(channel, 1)
        channel.command("STAMP")
        stamp = channel.receive("stamp")
        self.assertEqual(stamp["seq"], 1)  # vCPU has not advanced out of its mock permit wait.
        channel.command("HOLD 2")
        second = self.hold(channel, 2)
        self.assertGreater(second["seq"], stamp["seq"])
        self.assertNotEqual(first["pc"], second["pc"])
        self.resume(channel, 2)
        done = channel.receive("done")
        self.assertGreater(done["seq"], second["seq"])
        self.assertEqual(process.wait(timeout=2), 0)

    def test_lazy_eip_is_preserved_separately_through_both_holds(self):
        process, _, channel = self.start("lazy-eip")
        first = self.hold(channel, 1)
        self.assertEqual(first["pc"] - first["qemu_eip"], 4)
        self.assertEqual(first["pc_source"], c.PC_SOURCE)
        self.assertEqual(len(first["regs"]), 8)
        self.resume(channel, 1)
        channel.command("STAMP"); channel.receive("stamp")
        channel.command("HOLD 2")
        second = self.hold(channel, 2)
        self.assertEqual(second["pc"] - second["qemu_eip"], 4)
        self.resume(channel, 2)
        channel.receive("done")
        self.assertEqual(process.wait(timeout=2), 0)

    def test_disconnect_and_timeout_on_each_hold_are_terminal(self):
        for point in (1, 2):
            for fault, code in (("disconnect",125),("timeout",124)):
                with self.subTest(point=point, fault=fault):
                    process, parent, channel = self.start()
                    self.hold(channel, 1)
                    if point == 2:
                        self.resume(channel, 1)
                        channel.command("STAMP"); channel.receive("stamp")
                        channel.command("HOLD 2"); self.hold(channel, 2)
                    if fault == "disconnect": parent.close()
                    self.assertEqual(process.wait(timeout=2), code)
                    self.assertIn(f"OBSERVER_ABORT code={code}".encode(), process.stderr.read())

    def test_invalid_duplicate_premature_and_oversized_commands_are_terminal(self):
        for command in ("RESUME 1", "HOLD 2", "STAMP", "CHECK 2", "A"*40):
            with self.subTest(command=command):
                process, _, channel = self.start()
                channel.receive("snapshot")
                channel.command(command)
                self.assertEqual(process.wait(timeout=2),126)
        process, _, channel = self.start()
        self.hold(channel,1); self.resume(channel,1)
        channel.command("STAMP"); channel.receive("stamp")
        channel.command("STAMP")
        self.assertEqual(process.wait(timeout=2),126)

    def test_early_exit_has_no_successful_done(self):
        process, _, channel = self.start("early")
        self.hold(channel,1); self.resume(channel,1)
        with self.assertRaises(c.EarlyExit): channel.receive()
        self.assertEqual(process.wait(timeout=2),123)

    def test_watchdog_during_running_state_and_persistent_process_guard(self):
        process, parent, channel = self.start()
        self.hold(channel,1); self.resume(channel,1)
        parent.close()
        self.assertEqual(process.wait(timeout=2),125)
        for mode, expected in (("total-timeout",124),("second-vcpu",126),("fork",126)):
            with self.subTest(mode=mode):
                process, _, channel = self.start(mode)
                self.hold(channel,1); self.resume(channel,1)
                self.assertEqual(process.wait(timeout=2),expected)
        process, _, channel = self.start("fork-after")
        self.hold(channel,1); self.resume(channel,1)
        channel.command("STAMP"); channel.receive("stamp")
        channel.command("HOLD 2"); self.hold(channel,2); self.resume(channel,2)
        self.assertEqual(process.wait(timeout=2),126)


class ObserverEvidenceTests(unittest.TestCase):
    setUp = old.RetirementUnifiedTests.setUp
    prepare = old.RetirementUnifiedTests.prepare
    invoke = old.RetirementUnifiedTests.invoke

    def make_run(self, protocol=c.PROTOCOL):
        out, launch = self.prepare(trigger="verdict")
        report, code = self.invoke(out, launch, old.SyntheticRetirementExecutor())
        self.assertEqual(code,0,report.get("error"))
        run = Path(report["run_dir"])
        binding = c.read_json(run / "config/capsule_binding.json")
        paths = mappings.module_paths(binding)
        (run / "guest-i386").write_bytes(b"synthetic ELF bytes, not an executed guest")
        binding["observer"] = config = dict(profile=c.PROFILE, fault="none", variant="long",
            plugin_order="phase1-first", hold_ms=20, pause_ms=5000, total_ms=30000,
            after_release_delay_ms=0, guest_sha256=c.p.sha(run / "guest-i386"), stripped=True)
        if protocol == c.PROTOCOL:
            config.update(protocol=protocol, pc_source=c.PC_SOURCE)
        contract = run / "config/observer-contract.json"
        c.p.write_json(contract, config | dict(selection_delay=16,
            phase1_sha256=c.p.sha(paths["phase1"]),observer_sha256=c.p.sha(paths["observer"])))
        binding["attempt_contract_sha256"] = c.p.sha(contract)
        binding["capsule"]["symbols"] = {"phase1_payload_entry":binding["capsule"]["symbols"]["phase1_payload_entry"]}
        for name in ("config/phase1_binding.json", "logs/capsule/phase1-retirement/mapping-identity.json",
                     "logs/capsule/supervisor.json"):
            path = run / name
            value = c.read_json(path); value["attempt_contract_sha256"] = binding["attempt_contract_sha256"]
            c.p.write_json(path,value)
        c.p.write_json(run / "config/capsule_binding.json",binding)
        output = run / "logs/capsule"
        old_journal = [json.loads(line) for line in (output / "observations.jsonl").read_text().splitlines()]
        def maps(point):
            old_map = next(e for e in old_journal if e.get("point")==point and "maps_sha256" in e)
            return dict(event="maps_held",point=point,**{key:old_map[key] for key in (
                "mapping_schema","process_start_ticks","process_stat_sha256","maps_sha256","mapping_evidence")},
                mapping_identity_sha256=c.p.sha(r.directory(binding)/"mapping-identity.json"))
        def snapshot(point, sample):
            pc = 0x1000*point+point
            fields = dict(pc_source=c.PC_SOURCE, qemu_eip=pc-4) if protocol == c.PROTOCOL else {}
            return dict(event="snapshot",protocol=protocol,host_pid=77,point=point,sample=sample,
                seq=1 if point==1 else 500,pc=pc,monotonic_ms=point*1000+sample*20,
                regs=[1,2,3,4,5,6,7,0x1000]+([pc] if protocol==2 else []),
                stack_readable=True,stack_hex="00"*32,**fields)
        def command(value): return dict(event="command",command=value)
        def resumed(point): return dict(event="resumed",protocol=protocol,point=point,seq=1 if point==1 else 500)
        for name in ("maps", "process"):
            suffix = ".txt" if name=="maps" else ".stat"
            shutil.copyfile(r.directory(binding)/(name+"-2"+suffix),r.directory(binding)/(name+"-unmapped"+suffix))
        events = [snapshot(1,1), maps(1),command("CHECK 1"),snapshot(1,2),command("RESUME 1"),resumed(1),
            dict(event="export_ready"),command("STAMP"),dict(event="stamp",protocol=protocol,host_pid=77,seq=80,monotonic_ms=1500),
            dict(event="permit_grant",pre_permit_seq=80),dict(event="released"),
            dict(event="module_unmapped",maps_sha256=c.p.sha(r.directory(binding)/"maps-unmapped.txt"),
                 process_stat_sha256=c.p.sha(r.directory(binding)/"process-unmapped.stat")),command("HOLD 2"),
            snapshot(2,1),maps(2),command("CHECK 2"),snapshot(2,2),command("RESUME 2"),resumed(2),
            dict(event="progress_window",scope=c.WINDOW,lower_seq=80,upper_seq=500,entries=420,
                 exact_uninstall_interval=False,exact_oep_cutover=False),
            dict(event="done",protocol=protocol,host_pid=77,seq=520)]
        self.save_events(output, events)
        result = c.read_json(output / "supervisor.json")
        c.p.write_json(output / "controller.json",dict(status="passed",profile=c.PROFILE))
        self.assertEqual(c.verify_attempt(binding,result)["status"],"passed")
        return run,binding,result,events

    def save_events(self, output, events):
        c.p.write_json(output / "observer-events.json", dict(schema=2, events=[
            event | dict(controller_seq=i,controller_ns=i*1000) for i,event in enumerate(events,1)]))

    def test_portable_bundle_survives_copy_and_source_removal(self):
        run,binding,result,events = self.make_run()
        bundle=self.base/"m2-evidence"
        packed=evidence.pack(run,bundle)
        with tempfile.TemporaryDirectory() as temporary:
            moved=Path(temporary)/"moved"
            shutil.copytree(bundle,moved)
            shutil.rmtree(self.base)
            checked=evidence.verify(moved,expected_sha256=packed["manifest_sha256"])
            self.assertEqual(checked["attempt_outcome"],"passed")
            self.assertTrue(checked["phase1_retirement"]["phase1_retired"])

    def test_hold_before_unmap_sequence_regression_and_invented_progress_fail(self):
        run,binding,result,events = self.make_run()
        for case in ("order","progress","regression","registers","done","pid","raw-eip","callback-pc"):
            with self.subTest(case=case):
                changed=copy.deepcopy(events)
                if case=="order": changed[11],changed[12]=changed[12],changed[11]
                elif case=="progress": changed[-2]["entries"]+=1
                elif case=="regression": changed[8]["seq"]=1000
                elif case=="registers": changed[16]["regs"][0]+=1
                elif case=="done": changed[-1]["seq"]=500
                elif case=="raw-eip": changed[16]["qemu_eip"]+=1
                elif case=="callback-pc": changed[16]["pc"]+=1
                else: changed[13]["host_pid"]+=1
                self.save_events(run/"logs/capsule",changed)
                with self.assertRaises(RuntimeError): c.verify_attempt(binding,result)

    def test_pc_sources_and_protocol_cannot_be_silently_reinterpreted(self):
        run,binding,result,events = self.make_run()
        for case in ("missing-raw", "wrong-source", "extra-register", "bool-eip", "wide-eip",
                     "wide-pc", "mixed-snapshot", "mixed-stamp", "mixed-resume", "mixed-done"):
            with self.subTest(case=case):
                changed = copy.deepcopy(events)
                if case == "missing-raw": changed[13].pop("qemu_eip")
                elif case == "wrong-source": changed[13]["pc_source"] = "raw_eip"
                elif case == "extra-register": changed[13]["regs"].append(changed[13]["pc"])
                elif case == "bool-eip": changed[13]["qemu_eip"] = True
                elif case == "wide-eip": changed[13]["qemu_eip"] = 1 << 32
                elif case == "wide-pc": changed[13]["pc"] = 1 << 32
                else:
                    index = {"mixed-snapshot":13,"mixed-stamp":8,"mixed-resume":5,"mixed-done":-1}[case]
                    changed[index]["protocol"] = 2
                self.save_events(run/"logs/capsule",changed)
                with self.assertRaises(RuntimeError): c.verify_attempt(binding,result)
        for config in ({"protocol":2}, {"pc_source":c.PC_SOURCE},
                       {"protocol":3,"pc_source":"raw_eip"}, {"protocol":True}):
            with self.subTest(config=config), self.assertRaises(RuntimeError):
                c.observation_protocol(config)

    def test_legacy_evidence_retains_its_original_pc_equality_requirement(self):
        run,binding,result,events = self.make_run(protocol=2)
        packed = evidence.pack(run,self.base/"legacy-m2-evidence")
        self.assertEqual(packed["attempt_outcome"], "passed")
        for event in events:
            if event["event"] == "snapshot": event["regs"][8] -= 4
        self.save_events(run/"logs/capsule",events)
        with self.assertRaisesRegex(RuntimeError, "legacy observer PC"):
            c.verify_attempt(binding,result)

    def test_tampered_input_contract_and_unmap_bytes_fail(self):
        run,binding,result,events = self.make_run()
        for name in ("guest-i386","config/observer-contract.json",
                     "logs/capsule/phase1-retirement/maps-unmapped.txt"):
            with self.subTest(name=name):
                path=run/name; original=path.read_bytes(); path.write_bytes(original+b"changed")
                with self.assertRaises((ValueError,RuntimeError)): c.verify_attempt(binding,result)
                path.write_bytes(original)

    def test_early_exit_is_inconclusive_and_cannot_claim_success(self):
        run,binding,result,events = self.make_run()
        early=events[:11]+[dict(event="early_exit",protocol=c.PROTOCOL,host_pid=77,seq=200)]
        self.save_events(run/"logs/capsule",early)
        c.p.write_json(run/"logs/capsule/controller.json",dict(status="inconclusive"))
        (run/"logs/qemu_strace.log").write_text("OBSERVER_ABORT code=123 reason=exit_before_observation\n")
        result["qemu_exit"]=123
        checked=c.verify_attempt(binding,result)
        self.assertEqual(checked["status"],"inconclusive")
        self.assertFalse(checked["continuation_observed"])
        self.assertFalse(checked["phase1_retirement"]["phase1_retired"])
        result["qemu_exit"]=0
        with self.assertRaises(RuntimeError): c.verify_attempt(binding,result)

    def test_faults_before_and_after_removal_preserve_distinct_evidence(self):
        for fault in ("disconnect-before", "timeout-before", "disconnect-after", "timeout-after"):
            with self.subTest(fault=fault):
                run,binding,result,events = self.make_run()
                binding["observer"]["fault"]=fault
                contract=run/"config/observer-contract.json"
                value=c.read_json(contract); value["fault"]=fault; c.p.write_json(contract,value)
                binding["attempt_contract_sha256"]=c.p.sha(contract)
                result["attempt_contract_sha256"]=binding["attempt_contract_sha256"]
                for name in ("config/phase1_binding.json", "logs/capsule/phase1-retirement/mapping-identity.json"):
                    path=run/name; value=c.read_json(path)
                    value["attempt_contract_sha256"]=binding["attempt_contract_sha256"]; c.p.write_json(path,value)
                c.p.write_json(run/"config/capsule_binding.json",binding)
                before=fault.endswith("-before")
                events=events[:4 if before else 17]+[dict(event="fault_injected",fault=fault)]
                for event in events:
                    if event["event"]=="maps_held":
                        event["mapping_identity_sha256"]=c.p.sha(r.directory(binding)/"mapping-identity.json")
                self.save_events(run/"logs/capsule",events)
                c.p.write_json(run/"logs/capsule/controller.json",dict(status="fault_injected",fault=fault))
                result.update(qemu_exit=c.FAULTS[fault],status="aborted")
                (run/"logs/qemu_strace.log").write_text(f"OBSERVER_ABORT code={c.FAULTS[fault]} reason=test\n")
                checked=c.verify_attempt(binding,result)
                self.assertEqual(checked["status"],"aborted")
                self.assertFalse(checked["continuation_observed"])
                self.assertEqual(checked["phase1_retirement"]["phase1_retired"],not before)
                c.p.write_json(run/"logs/capsule/supervisor.json",result)
                packed=evidence.pack(run,self.base/("bundle-"+fault))
                self.assertEqual(packed["attempt_outcome"],"aborted")


if __name__ == "__main__":
    unittest.main()
