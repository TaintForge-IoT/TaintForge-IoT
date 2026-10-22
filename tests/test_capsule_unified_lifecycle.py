"""Contract integration with synthetic QEMU/systemd, not VM acceptance.

The separate native lifecycle tests exercise actual mmap, IPC and dlclose.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from experiments.execution_capsule_lifecycle import controller as lifecycle
from scripts.run_unified_pipeline import parser, prepare
from taintforge_env import capsule_lifecycle as owner
from taintforge_env import capsule_resources as resources
from taintforge_env import execution_capsule as capsule
from taintforge_env.unified_runtime import write_json, verify_bundle
from tests import test_execution_capsule as fixtures

CapsuleExecutor = fixtures.CapsuleExecutor

probe, retirement = lifecycle.probe, lifecycle.retirement


def producer_events(binding):
    page, start = os.sysconf("SC_PAGE_SIZE"), 0x10000000
    payload = lifecycle.payload(binding["lifecycle_attempt"])
    data = [{"producer": "capsule-fixture-v1", "api": 6, "mapping_start": start,
             "mapping_size": retirement.ARENA_SIZE + 2 * page, "page_size": page,
             "arena_start": start + page, "arena_size": retirement.ARENA_SIZE},
            {"size": len(payload), "sha256": hashlib.sha256(payload).hexdigest()},
            {"callbacks": 5}, {"callbacks": 7, "pending": 2},
            {"owned_mappings": 0, "owned_bytes": 0, "zeroed_bytes": retirement.ARENA_SIZE}]
    return [{"protocol": 1, "attempt": binding["lifecycle_attempt"], "seq": index,
             "pid": 77, "event": name, "data": fields}
            for index, (name, fields) in enumerate(zip(lifecycle.EVENTS, data))]


def maps_text(binding, arena, released, leak=False):
    bundle = Path(binding["run_dir"]) / "config/analyzer_runtime"
    phase1 = capsule.read_json(Path(binding["run_dir"]) / "config/phase1_binding.json")
    lines = []
    paths = [binding["capsule"]["plugin"], phase1["plugin"], owner.OWNER_PATH]
    for index, path in enumerate(paths):
        if released and path == owner.OWNER_PATH:
            continue
        (major, minor), inode = retirement.file_identity(bundle / path)
        start = 0x10000 + index * 0x2000
        lines.append(f"{start:x}-{start + 4096:x} r-xp 00000000 {major:02x}:{minor:02x} {inode} /{path}\n")
    if not released or leak:
        low, start = arena["mapping_start"], arena["arena_start"]
        end, high = start + arena["arena_size"], low + arena["mapping_size"]
        for lo, hi, perms in ((low, start, "---p"), (start, end, "rw-p"), (end, high, "---p")):
            lines.append(f"{lo:x}-{hi:x} {perms} 00000000 00:00 0\n")
    return "".join(lines)


def resource_entry(binding):
    policy = binding["settings"]["resources"]
    return {"status": "verified", "unit": resources.unit_name(binding),
            "attempt_id": binding["attempt_id"], "attempt_contract_sha256": binding["attempt_contract_sha256"],
            "cgroup": "/system.slice/" + resources.unit_name(binding),
            "limits": {"memory.max": str(policy["memory_bytes"]), "memory.swap.max": "0",
                       "memory.oom.group": "1", "pids.max": "64"},
            "no_new_privs": True, "core_rlimit": [0, 0],
            "memory_isolation": False, "hostile_sample_ready": False}


class LifecycleExecutor(CapsuleExecutor):
    def __init__(self, case="phase1-first", mode="remove", first_rejection=False, mutation=None):
        self.selected_case, self.owner_mode = case, mode
        synthetic_case = ("disconnect-1" if first_rejection else "disconnect-2") if mode != "remove" else case
        super().__init__(synthetic_case)
        self.lifecycle_mutation = mutation

    def run(self, command, **kwargs):
        result = super().run(command, **kwargs)
        if "unshare" not in command:
            return result
        run = Path(command[-1]).parent
        binding = capsule.read_json(run / "config/capsule_binding.json")
        output = run / "logs/capsule"
        directory = output / "lifecycle"
        journal = [json.loads(line) for line in (output / "observations.jsonl").read_text().splitlines()]
        producer = producer_events(binding)
        (directory / "export.bin").write_bytes(lifecycle.payload(binding["lifecycle_attempt"]))
        points = max(event.get("point", 0) for event in journal)
        events = []
        for event in journal:
            events.append(event)
            if event.get("state") not in {"handoff_ready", "continuation_observed"}:
                continue
            point = event["point"]
            rejected = self.owner_mode != "remove" and point == points
            packets = copy.deepcopy(producer if point == 2 else producer[:1])
            eof = point == 2
            if rejected and self.owner_mode in {"keep", "bad-export"}:
                packets = copy.deepcopy(producer[:2 if self.owner_mode == "keep" else 1])
                eof = self.owner_mode == "keep"
            saved = {"status": "rejected" if rejected else "observed" if point == 1 else "verified",
                     "point": point, "claims": lifecycle.CLAIMS, "producer_events": packets,
                     "stream_closed": eof, "export_verified_on_receipt": len(packets) >= 2,
                     "callbacks_removed_reported": len(packets) >= 4,
                     "resources_released_reported": len(packets) == 5}
            if not rejected or self.owner_mode == "leak-arena":
                text = maps_text(binding, producer[0]["data"], point == 2, rejected)
                (directory / f"maps-point-{point}.txt").write_text(text)
                mapping = {"owner_library_absent": point == 2,
                           "arena_range_absent": point == 2 and not rejected}
                if not rejected:
                    mapping.update(observer_present=True, phase1_present=True)
                saved.update(qemu_pid=77, process_start_ticks=12345, mapping_evidence=mapping,
                             maps_sha256=hashlib.sha256(text.encode()).hexdigest())
            if rejected:
                saved["error"] = owner.MODES[self.owner_mode]
                if self.owner_mode == "bad-export":
                    wrong = copy.deepcopy(producer[1])
                    wrong["data"]["sha256"] = "0" * 64
                    saved["last_packet"] = json.dumps(wrong)
                else:
                    saved["last_packet"] = json.dumps(packets[-1])
            write_json(directory / f"evidence-point-{point}.json", saved)
            events.append({"event": "lifecycle_rejected" if rejected else "lifecycle_observed", **saved})
        supervisor = capsule.read_json(output / "supervisor.json")
        supervisor["case"] = self.selected_case
        if self.owner_mode != "remove":
            write_json(output / "controller.json", {"status": "failed",
                       "error": "EvidenceError: " + owner.MODES[self.owner_mode]})
        write_json(output / "resources.json", resource_entry(binding))
        if self.lifecycle_mutation:
            self.lifecycle_mutation(binding, events, supervisor)
        (output / "observations.jsonl").write_text("".join(json.dumps(e) + "\n" for e in events))
        write_json(output / "supervisor.json", supervisor)
        return result


@unittest.skipUnless(shutil.which("gcc") and shutil.which("as") and shutil.which("ld"), "ELF toolchain required")
class UnifiedLifecycleTests(unittest.TestCase):
    setUp = fixtures.UnifiedCapsuleTests.setUp

    def prepare(self, case="phase1-first", mode="remove", order="after"):
        native = self.base / "libcapsule_lifecycle.so"
        shutil.copyfile(self.plugin, native)
        built = {**self.built, "lifecycle_plugin": str(native)}
        out = self.base / f"run-{len(list(self.base.glob('run-*')))}"
        args = parser().parse_args(["run", "--capsule-lifecycle", "--capsule-case", case,
            "--capsule-owner-mode", mode, "--capsule-owner-order", order,
            "--out", str(out), "--qemu", str(self.qemu), "--plugin", str(self.plugin), "--max-iterations", "1"])
        with patch.object(probe, "load_phase1"), patch.object(lifecycle, "audit"), \
             patch.object(lifecycle, "build", return_value=built), patch.object(resources, "preflight"):
            launch = prepare(args)
        return out, launch

    def invoke(self, out, launch, executor, service_result=None):
        code = executor.guest_exit_code
        status = {"LoadState": "loaded", "ActiveState": "inactive" if code == 0 else "failed",
                  "Result": service_result or ("exit-code" if code else "success")}
        with patch.object(resources, "control", return_value=SimpleNamespace(returncode=0, stderr="")), \
             patch.object(resources, "status", return_value=status), patch.object(resources, "CGROUP", self.base / "cgroup"):
            return fixtures.UnifiedCapsuleTests.invoke(self, out, launch, executor)

    def test_supervisor_passes_three_plugins_in_selected_order(self):
        for order in ("before", "after"):
            with self.subTest(order=order):
                out, launch = self.prepare(case="capsule-first", order=order)
                fixtures.run_session(out, launch, max_steps=1, initialize_only=True)
                fixtures.IterationController(out / "session").prepare_next()
                runner = fixtures.PrebuiltRootfsRunner(fixtures.PrebuiltRunnerConfig(
                    session_dir=out / "session", iteration_index=0, template_run_dir=out / "template",
                    project_root=fixtures.PROJECT))
                context = runner.validate()
                runner._prepare_run_directory(context)
                binding = capsule.read_json(context.run_dir / "config/capsule_binding.json")
                (context.execution_rootfs / "capsule-fd.txt").write_bytes(b"before\n")
                ipc = out / "ipc"
                ipc.mkdir()
                parent, child = Mock(), Mock()
                parent.recv.return_value = "ready"
                worker = Mock(pid=42, exitcode=0)
                worker.is_alive.return_value = False
                multiprocess = Mock()
                multiprocess.Pipe.return_value = parent, child
                multiprocess.Process.return_value = worker
                process = Mock(pid=77)
                process.wait.return_value = process.poll.return_value = 0
                with patch.object(capsule.mp, "get_context", return_value=multiprocess), \
                     patch.object(owner, "gate", return_value=Mock()), \
                     patch.object(resources, "inspect_self", return_value={}), \
                     patch.object(capsule.subprocess, "Popen", return_value=process) as popen:
                    capsule.supervise(binding, ipc)
                command = popen.call_args.args[0]
                plugins = [command[i + 1].split(",")[0] for i, item in enumerate(command) if item == "-plugin"]
                self.assertEqual(len(plugins), 3)
                self.assertTrue(plugins[0 if order == "before" else 2].endswith(owner.OWNER_PATH))
                self.assertTrue(plugins[1 if order == "before" else 0].endswith("libcapsule_probe.so"))

    def test_three_plugins_bundled_and_lifecycle_rechecked_at_finalization(self):
        out, launch = self.prepare(order="before")
        executor = LifecycleExecutor()
        report, code = self.invoke(out, launch, executor)
        self.assertEqual(code, 0, report.get("error"))
        self.assertTrue(report["capsule"]["lifecycle"]["owner_retired"])
        self.assertFalse(report["capsule"]["lifecycle"]["claims"]["phase1_retired"])
        self.assertTrue(report["capsule"]["resources"]["tree_empty"])
        self.assertEqual(report["phase1"]["artifact_integrity"], "verified")
        run = Path(report["run_dir"])
        binding = capsule.read_json(run / "config/capsule_binding.json")
        self.assertEqual(binding["settings"]["lifecycle"]["owner_order"], "before")
        self.assertIn("systemd-run", next(cmd for cmd in executor.commands if "unshare" in cmd))
        bundle = verify_bundle(run / "config/analyzer_runtime")
        self.assertIn(owner.OWNER_PATH, {file["path"] for file in bundle["files"]})
        with patch.object(lifecycle, "LifecycleGate") as constructor:
            owner.gate(binding, self.base / "ipc")
            self.assertEqual(constructor.call_args.kwargs["proc_root"], Path(binding["rootfs"]) / "proc")
            self.assertEqual(constructor.call_args.kwargs["artifact"], self.base / "ipc/export.bin")

    def test_owner_refusals_abort_once_and_cannot_be_resumed(self):
        for mode, first in (("keep", False), ("keep", True), ("bad-export", False),
                            ("bad-export", True), ("leak-arena", False)):
            with self.subTest(mode=mode, first=first):
                out, launch = self.prepare(mode=mode)
                executor = LifecycleExecutor(mode=mode, first_rejection=first)
                report, code = self.invoke(out, launch, executor)
                self.assertEqual(code, 1)
                self.assertEqual(report["capsule"]["status"], "aborted", report.get("error"))
                self.assertEqual(report["capsule"]["lifecycle"]["rejection"], owner.MODES[mode])
                self.assertFalse(report["capsule"]["lifecycle"]["owner_retired"])
                self.assertTrue(report["capsule"]["resources"]["tree_empty"])
                resumed, code = self.invoke(out, launch, executor)
                self.assertEqual(code, 1)
                self.assertEqual(resumed["executions_this_invocation"], 0)
                self.assertEqual(sum("unshare" in cmd for cmd in executor.commands), 1)

    def test_controller_abort_retains_correct_partial_lifecycle(self):
        for case in ("disconnect-1", "timeout-2", "kill-controller-2"):
            with self.subTest(case=case):
                out, launch = self.prepare(case=case)
                report, code = self.invoke(out, launch, LifecycleExecutor(case=case))
                self.assertEqual(code, 1)
                self.assertEqual(report["capsule"]["status"], "aborted", report.get("error"))
                self.assertEqual(report["capsule"]["lifecycle"]["owner_retired"], case.endswith("-2"))

    def test_changed_export_maps_identity_and_missing_observation_fail(self):
        def mutate_export(binding, events, result):
            (owner.output_directory(binding) / "export.bin").write_bytes(b"changed")
        def mutate_maps(binding, events, result):
            (owner.output_directory(binding) / "maps-point-2.txt").write_text("corrupted\n")
        def mutate_identity(binding, events, result):
            events[4]["producer_events"][0]["attempt"] = "00" * 16
            saved = {key: value for key, value in events[4].items() if key != "event"}
            write_json(owner.output_directory(binding) / "evidence-point-1.json", saved)
        def omit_observation(binding, events, result):
            events[:] = [e for e in events if not (e.get("event") == "lifecycle_observed" and e["point"] == 2)]
        for mutation in (mutate_export, mutate_maps, mutate_identity, omit_observation):
            with self.subTest(mutation=mutation.__name__):
                out, launch = self.prepare()
                report, code = self.invoke(out, launch, LifecycleExecutor(mutation=mutation))
                self.assertEqual(code, 1)
                self.assertEqual(report["capsule"]["status"], "failed")

    def test_oom_attribution_cannot_be_overridden_by_guest_success(self):
        out, launch = self.prepare()
        report, code = self.invoke(out, launch, LifecycleExecutor(), service_result="oom-kill")
        self.assertEqual(code, 1)
        self.assertEqual(report["capsule"]["status"], "failed")
        self.assertIn("oom-kill", report["capsule"]["error"])


class ResourceTests(unittest.TestCase):
    def test_kernel_policy_is_checked_before_guest_launch(self):
        import tempfile
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / "logs/capsule").mkdir(parents=True)
            binding = {"run_dir": str(directory), "lifecycle_attempt": "ab" * 16,
                       "attempt_id": "test", "attempt_contract_sha256": "a" * 64,
                       "settings": {"resources": resources.policy()}}
            expected = resource_entry(binding)
            group = directory / "cgroup" / expected["cgroup"].lstrip("/")
            group.mkdir(parents=True)
            for name, value in expected["limits"].items():
                (group / name).write_text(value)
            original = Path.read_text
            def proc(path, *args, **kwargs):
                if str(path) == "/proc/self/cgroup":
                    return "0::" + expected["cgroup"] + "\n"
                if str(path) == "/proc/self/status":
                    return "NoNewPrivs:\t1\n"
                return original(path, *args, **kwargs)
            with patch.object(resources, "CGROUP", directory / "cgroup"), \
                 patch.object(Path, "read_text", proc), patch.object(resources.resource, "getrlimit", return_value=(0, 0)):
                self.assertEqual(resources.inspect_self(binding), expected)
                (group / "memory.max").write_text("max")
                with self.assertRaisesRegex(probe.ProbeError, "Kernel resource limits"):
                    resources.inspect_self(binding)

    def test_service_scopes_limits_and_guarantees_cleanup_on_executor_error(self):
        import tempfile
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / "logs/capsule").mkdir(parents=True)
            binding = {"run_dir": str(directory), "lifecycle_attempt": "ab" * 16,
                       "attempt_id": "test", "attempt_contract_sha256": "a" * 64,
                       "settings": {"resources": resources.policy()}}
            command = ["sudo", "unshare", "--mount", "--pid", "--fork", "--net", "--", "bash", "/test/script"]
            argv = resources.command(binding, command)
            self.assertIn("--property=KillMode=control-group", argv)
            self.assertIn("--property=MemorySwapMax=0", argv)
            self.assertIn("--property=OOMPolicy=kill", argv)
            self.assertEqual(argv[-len(command) + 1:], command[1:])
            executor = Mock()
            executor.run.side_effect = RuntimeError("executor interrupted")
            with patch.object(resources, "control", return_value=SimpleNamespace(returncode=0, stderr="")) as control, \
                 patch.object(resources, "status", return_value={"LoadState": "not-found"}), \
                 patch.object(resources, "CGROUP", directory / "cgroup"):
                with self.assertRaisesRegex(RuntimeError, "interrupted"):
                    resources.execute(binding, command, executor)
            control.assert_any_call("sudo", "-n", "systemctl", "stop", resources.unit_name(binding))
            record = capsule.read_json(directory / "logs/capsule/service.json")
            self.assertTrue(record["tree_empty"])
            self.assertIn("executor interrupted", record["error"])

    def test_unconfirmed_cleanup_is_failure(self):
        import tempfile
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / "logs/capsule").mkdir(parents=True)
            binding = {"run_dir": str(directory), "lifecycle_attempt": "ab" * 16,
                       "attempt_id": "test", "attempt_contract_sha256": "a" * 64,
                       "settings": {"resources": resources.policy()}}
            executor = Mock()
            executor.run.return_value = SimpleNamespace(returncode=0)
            with patch.object(resources, "control", return_value=SimpleNamespace(returncode=1, stderr="still active")), \
                 patch.object(resources, "status", return_value={"ActiveState": "active"}):
                resources.execute(binding, ["sudo", "unshare", "--", "/test"], executor)
            record = capsule.read_json(directory / "logs/capsule/service.json")
            self.assertEqual(record["status"], "failed")
            self.assertFalse(record["tree_empty"])


if __name__ == "__main__":
    unittest.main()
