"""Unified contracts with synthetic execution; these tests do not run QEMU."""
import copy
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from experiments.execution_capsule_probe import controller as probe
from scripts.run_unified_pipeline import parser, prepare, run_session
from taintforge_env import execution_capsule as capsule
from taintforge_env.elf_runtime import canonical_hash
from taintforge_env.prebuilt_runner import PrebuiltRootfsRunner
from taintforge_env.prebuilt_runner import PrebuiltRunnerConfig
from taintforge_env.iteration_controller import IterationController
from taintforge_env.synthesis_loop import EnvironmentSynthesisLoop
from taintforge_env.unified_runtime import write_json, verify_bundle
from tests.test_unified_pipeline import fake_toolchain
from tests.test_unified_finalization import ObservedExecutor

PROJECT = Path(__file__).resolve().parents[1]
SYMBOLS = {"capsule_point_one": 0x1000, "capsule_point_two": 0x2000, "capsule_buffer": 0x3000}


def snapshot(point, sample, symbols=SYMBOLS, pid=77):
    esp, fd = 0x40800000, 7
    regs = {"eax": point * 0x11111111, "ebx": fd, "ecx": symbols["capsule_buffer"], "edx": 16,
            "esi": pid, "edi": fd, "ebp": esp, "esp": esp,
            "eip": symbols["capsule_point_one" if point == 1 else "capsule_point_two"]}
    return {"protocol": 1, "event": "snapshot", "point": point, "sample": sample,
            "host_pid": pid, "vcpu": 0, "monotonic_ms": point * 1000 + sample * 200, "regs": regs,
            "buffer_hex": (probe.BEFORE if point == 1 else probe.AFTER).hex(),
            "stack_hex": struct.pack("<8I", 0x11223344, 0x55667788, 0x99aabbcc, fd, pid, esp,
                                     0xdeadbeef, 0xcafebabe).hex()}


class GateTests(unittest.TestCase):
    def test_live_evidence_rejects_missing_failed_or_terminal_analysis(self):
        base = [{"event_id": "a:1", "event_type": "analysis_started", "data": {"build_id": "b", "plugin_api": 6}},
                {"event_id": "a:2", "event_type": "runtime_observation", "data": {"kind": "instruction_callback"}}]
        analysis = SimpleNamespace(runtime=SimpleNamespace(build_id="b"), events=Mock(return_value=base))
        self.assertEqual(capsule.live_phase1_evidence(analysis)["phase1_instruction_event"], "a:2")
        for kind in ("profile_lost", "data_loss", "error", "analysis_finished", "analysis_invalidated"):
            with self.subTest(kind=kind):
                analysis.events.return_value = base + [{"event_id": "a:3", "event_type": kind}]
                with self.assertRaises(probe.ProbeError):
                    capsule.live_phase1_evidence(analysis)
                # Finalization may see later events, but checks the actual live prefix.
                capsule.live_phase1_evidence(analysis, "a:2")
        analysis.events.return_value = base[:1]
        with self.assertRaisesRegex(probe.ProbeError, "instruction callback"):
            capsule.live_phase1_evidence(analysis)
        analysis.events.return_value = copy.deepcopy(base)
        analysis.events.return_value[0]["data"]["plugin_api"] = 5
        with self.assertRaisesRegex(probe.ProbeError, "build/API"):
            capsule.live_phase1_evidence(analysis)

    def worker(self, directory, transition):
        connection = Mock()
        connection.getsockopt.return_value = struct.pack("3i", 77, os.getuid(), os.getgid())
        listener = Mock()
        listener.accept.return_value = (connection, None)
        frames = Mock(buffer=b"")
        frames.receive.side_effect = [snapshot(1, 1), snapshot(1, 2), snapshot(2, 1), snapshot(2, 2),
                                      {"event": "done", "protocol": 1, "points": 2}]
        pipe = Mock()
        pipe.recv.return_value = 77
        fd_path = directory / "guest-fd.txt"
        fd_path.write_bytes(b"before\n")
        endpoint = directory / "socket"
        endpoint.touch()  # Fake listener: only the pathname chmod is real here.
        with patch.object(probe.socket, "socket", return_value=listener), \
             patch.object(probe, "Frames", return_value=frames), \
             patch.object(probe.select, "select", return_value=([], [], [])):
            probe.control_worker(str(endpoint), pipe, directory, SYMBOLS, "phase1-first", 200, 30000,
                                 fd_path=fd_path, transition=transition)
        return connection, capsule.read_json(directory / "controller.json")

    def test_rejected_gate_cannot_send_continue(self):
        with tempfile.TemporaryDirectory() as temporary:
            transition = Mock(side_effect=probe.ProbeError("denied by gate"))
            connection, result = self.worker(Path(temporary), transition)
            self.assertEqual(result["status"], "failed")
            self.assertEqual([call.args[0] for call in connection.sendall.call_args_list], [b"CHECK 1\n"])
            self.assertTrue(connection.close.called)

    def test_worker_hooks_follow_verified_holds_and_completion(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            actions = []
            def transition(action, point, sample, record):
                actions.append((action, point))
                self.assertEqual(sample["sample"], 2)
                if action == "resuming" and point == 1:
                    (directory / "guest-fd.txt").write_bytes(b"before\nbetween\n")
            connection, result = self.worker(directory, transition)
            self.assertEqual(result["status"], "passed")
            self.assertEqual(actions, [("held", 1), ("resuming", 1), ("held", 2), ("resuming", 2), ("done", 2)])
            self.assertIn(b"TINUE 2\n", [call.args[0] for call in connection.sendall.call_args_list])

    def test_deadline_relationships_are_checked_before_execution(self):
        for options in ({"hold_ms": 1001}, {"pause_ms": 500}, {"total_ms": 60000, "timeout": 60}):
            with self.subTest(options=options), self.assertRaises(probe.ProbeError):
                capsule.settings(**options)


class CapsuleExecutor(ObservedExecutor):
    def __init__(self, case, mutation=None):
        code = capsule.expected_exit(case)
        super().__init__(mode="incomplete" if code else "complete", guest_exit_code=code)
        self.case, self.mutation = case, mutation

    def run(self, command, **kwargs):
        result = super().run(command, **kwargs)
        if "unshare" not in command:
            return result
        run = Path(command[-1]).parent
        binding = capsule.read_json(run / "config/capsule_binding.json")
        output = run / "logs/capsule"
        code = capsule.expected_exit(self.case)
        last = 2 if code == 0 or self.case.endswith("-2") else 1
        events = []
        def handoff(state, point):
            event = {"event": "handoff", "state": state, "point": point, "qemu_pid": 77,
                     "handoff_seq": 1 + sum(e["event"] == "handoff" for e in events),
                     **{key: binding[key] for key in capsule.IDENTITY}, **capsule.LIMITS}
            if state in {"handoff_ready", "continuation_observed"}:
                instance = binding["analysis_instance_id"]
                event.update(phase1_started_event=instance + ":1", phase1_instruction_event=instance + ":2",
                             phase1_last_event=instance + ":2")
            events.append(event)
        for point in range(1, last + 1):
            events += [snapshot(point, sample, binding["capsule"]["symbols"]) for sample in (1, 2)]
            events.append({"event": "hold_verified", "point": point, "elapsed_ms": 200})
            handoff("handoff_ready" if point == 1 else "continuation_observed", point)
            if point < last or code == 0:
                handoff("resume_requested", point)
        if code == 0:
            events.append({"event": "done", "protocol": 1, "points": 2})
            handoff("guest_completed", 2)
        elif self.case.startswith("kill-controller"):
            events.append({"event": "controller_kill", "point": last})
        data = probe.FILE_BYTES if code == 0 else (b"before\n" if last == 1 else b"before\nbetween\n")
        (Path(binding["rootfs"]) / "capsule-fd.txt").write_bytes(data)
        (output / "capsule-fd.txt").write_bytes(data)
        (run / "logs/runtime_stdout.log").write_bytes(b"CAPSULE_OK\n" if code == 0 else b"")
        if code:
            with (run / "logs/qemu_strace.log").open("a") as stream:
                stream.write(f"CAPSULE_ABORT code={code} reason=synthetic_failure\n")
        report = {"schema_version": 1, "status": "passed" if code == 0 else "aborted",
                  "qemu_exit": code, "case": self.case, "qemu_pid": 77,
                  "controller_exit": -9 if self.case.startswith("kill-controller") else 0,
                  "supervisor_kill": False, **{key: binding[key] for key in capsule.IDENTITY}}
        if self.mutation:
            self.mutation(events, report)
        (output / "observations.jsonl").write_text("".join(json.dumps(e) + "\n" for e in events))
        write_json(output / "supervisor.json", report)
        if not self.case.startswith("kill-controller"):
            write_json(output / "controller.json", {"status": "passed"})
        return result


@unittest.skipUnless(shutil.which("gcc") and shutil.which("as") and shutil.which("ld"), "ELF toolchain required")
class UnifiedCapsuleTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.qemu, self.plugin = fake_toolchain(self.base / "tools")
        sidecar = Path(str(self.plugin) + ".runtime.json")
        manifest = capsule.read_json(sidecar)
        manifest["build_inputs"]["plugin_api"] = 6
        manifest["requirements"]["plugin_api"] = 6
        manifest["build_id"] = canonical_hash(manifest["build_inputs"])
        write_json(sidecar, manifest)
        guest = self.base / "capsule_guest_i386"
        subprocess.run(["as", "--32", str(probe.HERE / "guest.S"), "-o", str(self.base / "guest.o")], check=True)
        subprocess.run(["ld", "-m", "elf_i386", "-z", "noexecstack", "--build-id=none",
                        str(self.base / "guest.o"), "-o", str(guest)], check=True)
        symbols = {line.split()[0]: int(line.split()[2], 16)
                   for line in probe.command("nm", "-P", "--defined-only", guest).splitlines()
                   if line.split()[0] in SYMBOLS}
        native = self.base / "libcapsule_probe.so"
        shutil.copyfile(self.plugin, native)  # ELF metadata only; never loaded by a QEMU backend.
        self.built = {"plugin": str(native), "guest": str(guest), "symbols": symbols, "plugin_api": 6,
                      "qemu_source_revision": capsule.read_json(probe.HERE / "BASELINE.json")["qemu_revision"],
                      "hashes": {"capsule_guest_i386": probe.sha(guest),
                                 **{name: probe.sha(probe.HERE / relative) for name, relative in
                                    (("probe.c", "probe.c"), ("guest.S", "guest.S"), ("qemu-plugin.h", "vendor/qemu-plugin.h"))}}}

    def prepare(self, case="phase1-first", extra=()):
        out = self.base / case
        args = parser().parse_args(["run", "--capsule-probe", "--capsule-case", case,
            "--out", str(out), "--qemu", str(self.qemu), "--plugin", str(self.plugin),
            "--max-iterations", "1", *extra])
        with patch.object(probe, "load_phase1"), patch.object(probe, "build", return_value=self.built):
            launch = prepare(args)
        return out, launch

    def invoke(self, out, launch, executor):
        original = EnvironmentSynthesisLoop.run
        def run(loop):
            loop.runner_factory = lambda config: PrebuiltRootfsRunner(config, executor=executor)
            with patch.object(PrebuiltRootfsRunner, "_check_host_dependencies"):
                return original(loop)
        with patch.object(EnvironmentSynthesisLoop, "run", run):
            return run_session(out, launch, max_steps=1)

    def test_positive_handoff_is_bound_and_in_verified_attempt_artifacts(self):
        out, launch = self.prepare()
        report, code = self.invoke(out, launch, CapsuleExecutor("phase1-first"))
        self.assertEqual(code, 0, report.get("error"))
        self.assertEqual(report["capsule"]["status"], "passed")
        self.assertTrue(report["capsule"]["continuation_observed"])
        self.assertFalse(report["capsule"]["limitations"]["phase1_detached"])
        self.assertEqual(report["finalization"]["stages"]["capsule"]["status"], "completed")
        script = (Path(report["run_dir"]) / "run_prebuilt_sandbox.sh").read_text()
        self.assertIn("-m taintforge_env.execution_capsule", script)
        self.assertIn("mount --bind \"$CAPSULE_IPC\"", script)
        self.assertTrue(EnvironmentSynthesisLoop.verify_session(out / "session")["binding_verified"])
        artifacts = out / "session/iterations/0000/artifacts"
        (artifacts / "config/capsule_result.json").write_text("{}")
        with self.assertRaises((RuntimeError, ValueError)):
            EnvironmentSynthesisLoop.verify_session(out / "session")

    def test_aborts_preserve_evidence_and_block_resume(self):
        for case in ("timeout-1", "disconnect-1", "kill-controller-1", "bad-command", "disconnect-2"):
            with self.subTest(case=case):
                out, launch = self.prepare(case)
                executor = CapsuleExecutor(case)
                report, code = self.invoke(out, launch, executor)
                self.assertEqual(code, 1)
                self.assertEqual(report["capsule"]["status"], "aborted", report.get("error"))
                self.assertEqual(report["execution"]["guest_exit_code"], capsule.expected_exit(case))
                stages = report["finalization"]["stages"]
                self.assertEqual(stages["capsule"]["status"], "failed")
                self.assertEqual(stages["filesystem"]["status"], "completed")
                self.assertEqual(stages["syscalls"]["status"], "completed")
                resumed, status = self.invoke(out, launch, executor)
                self.assertEqual(status, 1)
                self.assertEqual(resumed["executions_this_invocation"], 0)
                self.assertEqual(sum("unshare" in cmd for cmd in executor.commands), 1)

    def test_supervisor_kill_cannot_pass_finalization(self):
        out, launch = self.prepare()
        report, code = self.invoke(out, launch, CapsuleExecutor("phase1-first", lambda events, result: result.update(supervisor_kill=True)))
        self.assertEqual(code, 1)
        self.assertEqual(report["capsule"]["status"], "failed")

    def test_supervisor_reaps_stuck_qemu_and_records_fallback_failure(self):
        out, launch = self.prepare()
        run_session(out, launch, max_steps=1, initialize_only=True)
        IterationController(out / "session").prepare_next()
        runner = PrebuiltRootfsRunner(PrebuiltRunnerConfig(session_dir=out / "session", iteration_index=0,
                                      template_run_dir=out / "template", project_root=PROJECT))
        context = runner.validate()
        runner._prepare_run_directory(context)
        binding = capsule.read_json(context.run_dir / "config/capsule_binding.json")
        (context.execution_rootfs / "capsule-fd.txt").write_bytes(b"before\n")
        ipc = self.base / "ipc"
        ipc.mkdir()
        parent, child = Mock(), Mock()
        parent.recv.return_value = "ready"
        worker = Mock(pid=42, exitcode=0)
        worker.is_alive.return_value = False
        multiprocess = Mock()
        multiprocess.Pipe.return_value = parent, child
        multiprocess.Process.return_value = worker
        process = Mock(pid=77)
        process.wait.side_effect = [subprocess.TimeoutExpired("qemu", 35), -9]
        process.poll.return_value = -9
        with patch.object(capsule.mp, "get_context", return_value=multiprocess), \
             patch.object(capsule.subprocess, "Popen", return_value=process) as popen:
            code = capsule.supervise(binding, ipc)
        self.assertEqual(code, 137)
        self.assertTrue(process.kill.called)
        self.assertTrue(worker.join.called)
        saved = capsule.read_json(context.run_dir / "logs/capsule/supervisor.json")
        self.assertEqual(saved["status"], "failed")
        self.assertTrue(saved["supervisor_kill"])
        self.assertEqual(saved["qemu_exit"], -9)
        command = popen.call_args.args[0]
        self.assertEqual(command.count("-plugin"), 2)
        self.assertTrue(any("controller=42" in part for part in command))
        self.assertNotIn("start_new_session", popen.call_args.kwargs)

    def test_corrupt_snapshot_and_event_reference_are_rejected(self):
        changes = [lambda events, result: events[0]["regs"].update(esi=999),
                   lambda events, result: events[1].update(stack_hex="00" * 32),
                   lambda events, result: events[3].update(phase1_last_event="absent:1"),
                   lambda events, result: events[3].update(attempt_id="another-attempt")]
        for index, change in enumerate(changes):
            with self.subTest(change=index):
                out, launch = self.prepare(CASES_FOR_MUTATION[index])
                report, code = self.invoke(out, launch, CapsuleExecutor(CASES_FOR_MUTATION[index], change))
                self.assertEqual(code, 1)
                self.assertEqual(report["capsule"]["status"], "failed")

    def test_resume_record_must_precede_the_next_snapshot(self):
        out, launch = self.prepare()
        def reorder(events, result):
            events[4], events[5] = events[5], events[4]
        report, code = self.invoke(out, launch, CapsuleExecutor("phase1-first", reorder))
        self.assertEqual(code, 1)
        self.assertIn("sequence", report["capsule"]["error"])

    def test_fixture_or_bundle_drift_refuses_execution(self):
        out, launch = self.prepare()
        bundle = out / "template/config/analyzer_runtime"
        (bundle / "capsule/guest_i386").chmod(0o600)
        (bundle / "capsule/guest_i386").write_bytes(b"changed")
        with self.assertRaisesRegex(RuntimeError, "changed"):
            verify_bundle(bundle)

    def test_cli_refuses_arbitrary_binary_and_multiple_attempts(self):
        for extra in (("--binary", self.built["guest"]), ("--max-iterations", "2")):
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                self.prepare(extra=extra)


CASES_FOR_MUTATION = ("phase1-first", "capsule-first", "timeout-1", "disconnect-1")

if __name__ == "__main__":
    unittest.main()
