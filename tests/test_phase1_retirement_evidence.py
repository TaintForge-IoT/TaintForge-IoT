"""Portable evidence and startup failures; fixtures are synthetic, not VM runs."""
import copy
import errno
import json
import multiprocessing as mp
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

from taintforge_env import retirement_evidence as evidence, retirement_mappings as mappings
from taintforge_env import phase1_retirement as retirement
from tests import test_phase1_retirement_integration as fixtures
from tests import test_execution_capsule as baseline

probe = retirement.probe


class PortableEvidenceTests(unittest.TestCase):
    setUp = fixtures.RetirementUnifiedTests.setUp
    prepare = fixtures.RetirementUnifiedTests.prepare
    invoke = fixtures.RetirementUnifiedTests.invoke

    def make_bundle(self, fault="none"):
        out, launch = self.prepare(fault, trigger="verdict")
        report, code = self.invoke(out, launch, fixtures.SyntheticRetirementExecutor(fault))
        self.assertEqual(code, int(fault != "none"), report.get("error"))
        run = Path(report["run_dir"])
        bundle = self.base / "evidence"
        packed = evidence.pack(run, bundle)
        return out, run, bundle, packed

    def reseal(self, root):
        manifest = json.loads((root / "bundle.json").read_text())
        for item in manifest["files"]:
            path = root / item["path"]
            item.update(size=path.stat().st_size, sha256=probe.sha(path))
        probe.write_json(root / "bundle.json", manifest)

    def test_copy_checks_original_manifest_without_source_or_original_inodes(self):
        out, run, bundle, packed = self.make_bundle()
        original_capture = retirement.analysis(baseline.capsule.read_json(run / "config/capsule_binding.json")).paths["manifest"].read_bytes()
        self.assertEqual((bundle / "phase1/capture_manifest.json").read_bytes(), original_capture)
        before = evidence.verify(bundle, expected_sha256=packed["manifest_sha256"])
        with tempfile.TemporaryDirectory() as temporary:
            moved = Path(temporary) / "copy"
            shutil.copytree(bundle, moved)
            a = bundle / "config/analyzer_runtime/observer/plugin.so"
            b = moved / "config/analyzer_runtime/observer/plugin.so"
            self.assertNotEqual(a.stat().st_ino, b.stat().st_ino)
            # Remove the original attempt, package and external fixture modules.
            shutil.rmtree(self.base)
            after = evidence.verify(moved, expected_sha256=packed["manifest_sha256"])
            self.assertEqual(before, after)
            self.assertTrue(after["phase1_retirement"]["phase1_retired"])
            self.assertEqual(after["authenticity"], "not_asserted")

    def test_refused_attempt_is_portable_but_not_successful_retirement(self):
        _, _, bundle, packed = self.make_bundle("bad-digest")
        checked = evidence.verify(bundle, expected_sha256=packed["manifest_sha256"])
        self.assertEqual(checked["attempt_outcome"], "aborted")
        self.assertFalse(checked["phase1_retirement"]["phase1_retired"])

    def test_tampering_missing_files_and_supplied_digest_are_rejected(self):
        _, _, bundle, packed = self.make_bundle()
        names = ["phase1/unpacked.bin", "logs/capsule/observations.jsonl",
                 "logs/capsule/phase1-retirement/maps-2.txt",
                 "logs/capsule/phase1-retirement/process-1.stat",
                 "logs/capsule/phase1-retirement/mapping-identity.json",
                 "config/analyzer_runtime/observer/plugin.so"]
        for index, name in enumerate(names):
            with self.subTest(name=name):
                target = self.base / f"modified-{index}"
                shutil.copytree(bundle, target)
                (target / name).write_bytes(b"changed")
                with self.assertRaises((RuntimeError, OSError)):
                    evidence.verify(target)
        (bundle / names[0]).unlink()
        with self.assertRaises((RuntimeError, OSError)):
            evidence.verify(bundle)
        with self.assertRaisesRegex(RuntimeError, "trusted reference"):
            evidence.verify(bundle, expected_sha256="0" * 64)

    def test_semantic_checks_survive_recomputed_untrusted_inventory(self):
        _, _, bundle, packed = self.make_bundle()
        cases = ("pid", "starttime", "maps", "order", "module", "build", "capture_path", "nonce")
        for case in cases:
            with self.subTest(case=case):
                root = self.base / case
                shutil.copytree(bundle, root)
                output = root / "logs/capsule/phase1-retirement"
                if case in {"pid", "starttime", "nonce"}:
                    path = output / "mapping-identity.json"
                    value = json.loads(path.read_text())
                    value[{"pid": "qemu_pid", "starttime": "process_start_ticks", "nonce": "nonce"}[case]] = 999 if case != "nonce" else "f" * 32
                    probe.write_json(path, value)
                    journal = root / "logs/capsule/observations.jsonl"
                    events = [json.loads(l) for l in journal.read_text().splitlines()]
                    for event in events:
                        if "mapping_identity_sha256" in event:
                            event["mapping_identity_sha256"] = probe.sha(path)
                    journal.write_text("".join(json.dumps(e) + "\n" for e in events))
                elif case == "maps":
                    shutil.copyfile(output / "maps-1.txt", output / "maps-2.txt")
                    journal = root / "logs/capsule/observations.jsonl"
                    events = [json.loads(l) for l in journal.read_text().splitlines()]
                    for event in events:
                        if event.get("point") == 2 and "maps_sha256" in event:
                            event["maps_sha256"] = probe.sha(output / "maps-2.txt")
                    journal.write_text("".join(json.dumps(e) + "\n" for e in events))
                elif case == "order":
                    path = root / "logs/capsule/observations.jsonl"
                    lines = path.read_text().splitlines()
                    lines[3], lines[4] = lines[4], lines[3]
                    path.write_text("\n".join(lines) + "\n")
                elif case == "module":
                    (root / "config/analyzer_runtime/observer/plugin.so").write_bytes(b"replacement")
                elif case == "build":
                    path = next((root / "config/analyzer_runtime/phase1").glob("*.runtime.json"))
                    value = json.loads(path.read_text()); value["build_id"] = "0" * 64
                    probe.write_json(path, value)
                else:
                    path = root / "phase1/capture_manifest.json"
                    value = json.loads(path.read_text()); value["artifacts"]["dump"]["path"] = "/wrong/unpacked.bin"
                    probe.write_json(path, value)
                self.reseal(root)
                with self.assertRaises((RuntimeError, OSError)):
                    evidence.verify(root)
                with self.assertRaisesRegex(RuntimeError, "trusted reference"):
                    evidence.verify(root, expected_sha256=packed["manifest_sha256"])

    def test_legacy_evidence_is_inconclusive_and_cli_returns_two(self):
        out, run, bundle, _ = self.make_bundle()
        (retirement.directory({"run_dir": str(run)}) / "mapping-identity.json").unlink()
        binding_path = run / "config/capsule_binding.json"
        binding = json.loads(binding_path.read_text())
        with self.assertRaisesRegex(probe.ProbeError, "Missing required"):
            evidence.pack(run, self.base / "missing-new-evidence")
        binding.pop("retirement_evidence_schema")
        probe.write_json(binding_path, binding)
        dest = self.base / "legacy"
        with self.assertRaises(mappings.EvidenceInconclusive):
            evidence.pack(run, dest)
        completed = subprocess.run([sys.executable, "-m", "scripts.phase1_retirement_evidence", "pack",
            "--run-dir", str(run), "--out", str(dest)], capture_output=True, text=True)
        self.assertEqual(completed.returncode, 2, completed.stderr)
        self.assertEqual(json.loads(completed.stdout)["status"], "inconclusive")
        self.assertFalse(dest.exists())

    def test_symlink_path_escape_and_duplicate_inventory_are_rejected(self):
        _, _, bundle, _ = self.make_bundle()
        for case in ("symlink", "escape", "duplicate", "extra"):
            with self.subTest(case=case):
                root = self.base / case
                shutil.copytree(bundle, root)
                path = root / "bundle.json"
                value = json.loads(path.read_text())
                if case == "symlink":
                    module = root / "config/analyzer_runtime/observer/plugin.so"
                    module.unlink(); module.symlink_to(bundle / "config/analyzer_runtime/observer/plugin.so")
                elif case == "extra":
                    (root / "unlisted.txt").write_text("extra")
                else:
                    if case == "escape": value["files"][0]["path"] = "../escape"
                    else: value["files"].append(copy.deepcopy(value["files"][0]))
                    probe.write_json(path, value)
                with self.assertRaises((RuntimeError, OSError)):
                    evidence.verify(root)

    def test_live_capture_and_offline_checks_use_recorded_process_and_modules(self):
        _, run, _, _ = self.make_bundle()
        binding = baseline.capsule.read_json(run / "config/capsule_binding.json")
        output = retirement.directory(binding)
        proc = self.base / "fake-proc-root/proc/77"
        proc.mkdir(parents=True)
        (proc / "stat").write_bytes((output / "process-1.stat").read_bytes())
        (proc / "maps").write_bytes((output / "maps-1.txt").read_bytes())
        (output / "mapping-identity.json").unlink()
        binding["rootfs"] = str(proc.parents[1])
        event = {"point": 1, **mappings.capture(binding, 77, 1)}
        mappings.verify_observation(binding, event, 77)
        (proc / "stat").write_text("78 (other) S " + "0 " * 18 + "12345 0\n")
        with self.assertRaisesRegex(RuntimeError, "Process changed"):
            mappings.capture(binding, 77, 2)


class StartupDiagnosticsTests(unittest.TestCase):
    def test_supervisor_preflight_failure_is_reported_without_starting_qemu(self):
        from taintforge_env import execution_capsule as capsule, unified_runtime
        with tempfile.TemporaryDirectory() as temporary:
            run = Path(temporary)
            (run / "logs/capsule").mkdir(parents=True)
            binding = {key: "test" for key in capsule.IDENTITY}
            binding.update(run_dir=temporary, rootfs=temporary, capsule={}, guest_binary="/guest",
                           settings={"case": "phase1-first", "total_ms": 30000, "pause_ms": 5000})
            with patch.object(unified_runtime, "verify_bundle", side_effect=RuntimeError("test manifest changed")), \
                 patch.object(capsule.subprocess, "Popen") as popen:
                code = capsule.supervise(binding, run)
            self.assertEqual(code, 126)
            popen.assert_not_called()
            result = json.loads((run / "logs/capsule/supervisor.json").read_text())
            self.assertEqual(result["failure"]["category"], "startup_failure")
            self.assertEqual(result["failure"]["stage"], "preflight")

    def test_peer_refusal_keeps_controller_stage_in_saved_diagnostics(self):
        with tempfile.TemporaryDirectory() as temporary:
            binding = {"run_dir": temporary, "lifecycle_attempt": "1" * 32, "settings": {"total_ms": 10000}}
            output = retirement.directory(binding); output.mkdir(parents=True)
            endpoint = Path(temporary) / "socket"; endpoint.touch()
            pipe = Mock(); pipe.recv.return_value = 77
            connection = Mock(); connection.getsockopt.return_value = struct.pack("3i", 78, 999, 999)
            listener = Mock(); listener.accept.return_value = connection, None
            with patch.object(retirement.socket, "socket", return_value=listener):
                retirement.permit_worker(endpoint, pipe, binding)
            failures = probe.saved_worker_failures(Path(temporary) / "logs/capsule")
            self.assertEqual(failures[0]["category"], "controller_failure")
            self.assertEqual(failures[0]["stage"], "peer_identity")
            self.assertEqual(pipe.send.call_args_list[0].args, ("ready",))

    def test_permit_socket_eperm_is_reported_before_eof(self):
        with tempfile.TemporaryDirectory() as temporary:
            binding = {"run_dir": temporary, "lifecycle_attempt": "1" * 32}
            output = retirement.directory(binding); output.mkdir(parents=True)
            parent, child = mp.Pipe()
            self.addCleanup(parent.close)
            with patch.object(retirement.socket, "socket", side_effect=PermissionError(errno.EPERM, "test socket denied")):
                retirement.permit_worker(Path(temporary) / "socket", child, binding)
            with self.assertRaises(probe.WorkerStartupError) as caught:
                probe.wait_worker_ready(parent, "permit")
            self.assertEqual(caught.exception.failure["errno"], errno.EPERM)
            self.assertEqual(caught.exception.failure["stage"], "socket")
            self.assertEqual(json.loads((output / "retirement.json").read_text())["failure"], caught.exception.failure)

    def test_observer_bind_failure_is_reported_and_socket_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent, child = mp.Pipe(); self.addCleanup(parent.close)
            listener = Mock(); listener.bind.side_effect = OSError(errno.EADDRINUSE, "test endpoint busy")
            with patch.object(probe.socket, "socket", return_value=listener):
                probe.control_worker(str(Path(temporary) / "socket"), child, temporary, {}, "phase1-first", 50, 10000)
            with self.assertRaises(probe.WorkerStartupError) as caught:
                probe.wait_worker_ready(parent, "observer")
            self.assertEqual(caught.exception.failure["stage"], "bind")
            self.assertEqual(caught.exception.failure["errno"], errno.EADDRINUSE)
            self.assertTrue(listener.close.called)

    def test_eof_and_timeout_have_explicit_startup_classification(self):
        for exc in (EOFError("worker exited"), TimeoutError("too slow")):
            pipe = Mock(); pipe.poll.return_value = True; pipe.recv.side_effect = exc
            with self.assertRaises(probe.WorkerStartupError) as caught:
                probe.wait_worker_ready(pipe, "permit")
            self.assertEqual(caught.exception.failure["category"], "startup_failure")
            self.assertEqual(caught.exception.failure["exception_type"], type(exc).__name__)

    def test_execution_failures_keep_distinct_categories(self):
        cases = [(None, None, False, "startup_failure"), (77, -9, True, "execution_timeout"),
                 (77, 139, False, "guest_failure"), (77, 0, False, "evidence_failure")]
        for pid, code, killed, expected in cases:
            result = {"qemu_pid": pid, "qemu_exit": code, "supervisor_kill": killed, "expected_qemu_exit": 0}
            actual = probe.execution_failure(RuntimeError("test failure"), result, "verification")
            self.assertEqual(actual["category"], expected)


if __name__ == "__main__":
    unittest.main()
