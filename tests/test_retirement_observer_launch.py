"""Regression for the actual staged ELF path, not just the executable build output."""
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from experiments.retirement_observer import controller as c, local_check as launch


class GuestLaunchTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def test_staging_sets_execute_and_does_not_inherit_special_permissions(self):
        source = self.root / "source"
        source.write_bytes(b"fixture bytes")
        source.chmod(0o6755)
        old_mask = os.umask(0o077)
        try:
            target = launch.stage_guest(source, self.root / "staged", c.p.sha(source))
        finally:
            os.umask(old_mask)
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o700)
        self.assertEqual(target.read_bytes(), source.read_bytes())
        with self.assertRaises(FileExistsError):
            launch.stage_guest(source, target, c.p.sha(source))

    def test_staging_rejects_wrong_bytes_and_symlink_source(self):
        source = self.root / "source"
        source.write_bytes(b"changed")
        with self.assertRaisesRegex(RuntimeError, "bytes differ"):
            launch.stage_guest(source, self.root / "wrong-digest", "0"*64)
        linked = self.root / "linked"
        linked.symlink_to(source)
        with self.assertRaisesRegex(RuntimeError, "regular file"):
            launch.stage_guest(linked, self.root / "from-link", c.p.sha(source))
        self.assertFalse((self.root / "from-link").exists())

    def test_qemu_loader_error_is_primary_and_diagnostics_are_bounded(self):
        logs = self.root / "logs"
        logs.mkdir()
        message = "Error while loading /tmp/guest-i386: Exec format error\n"
        (logs / "runtime_stdout.log").write_bytes(b"x"*10000 + message.encode())
        (logs / "qemu_strace.log").write_bytes(b"y"*9000)
        diagnostic = launch.runtime_diagnostics(self.root)
        self.assertEqual(len(diagnostic["stdout_tail"]), 4096)
        self.assertEqual(len(diagnostic["stderr_tail"]), 4096)
        with self.assertRaisesRegex(launch.QemuLoadError, "Error while loading"):
            launch.check_qemu_exit(1, {0,123}, diagnostic)
        with self.assertRaisesRegex(c.p.ProbeError, "code 126"):
            launch.check_qemu_exit(126, {0}, {"stderr_tail":"OBSERVER_ABORT code=126 reason=pc_mismatch"})
        launch.check_qemu_exit(125, {125}, diagnostic)

    def test_real_qemu_rejects_old_copy_and_runs_new_staged_guest(self):
        qemu = os.environ.get("TF_OBSERVER_QEMU")
        if not qemu:
            self.skipTest("TF_OBSERVER_QEMU is required for the pinned QEMU loader regression")
        qemu = Path(qemu).expanduser().resolve(strict=True)
        version = c.p.command(qemu, "--version").splitlines()[0]
        self.assertRegex(version, r"\bversion 11\.0\.1(?:\s|$)")
        obj, source = self.root / "guest.o", self.root / "built-guest"
        c.p.command("as", "--32", "--defsym", "WORK_LOOPS=128", c.HERE / "guest.S", "-o", obj)
        c.p.command("ld", "-m", "elf_i386", "-z", "noexecstack", "--build-id=none", obj, "-o", source)
        c.p.command("strip", "--strip-all", source)
        broken = self.root / "old-copy"
        shutil.copyfile(source, broken)
        self.assertEqual(broken.stat().st_mode & 0o111, 0)
        before = subprocess.run([str(qemu), str(broken)], cwd=self.root, capture_output=True, timeout=10)
        self.assertEqual(before.returncode, 1)
        self.assertIn(b"Error while loading ", before.stdout+before.stderr)
        fixed = launch.stage_guest(source, self.root / "guest-i386", c.p.sha(source))
        after = subprocess.run([str(qemu), str(fixed)], cwd=self.root, capture_output=True, timeout=10)
        self.assertEqual(after.returncode, 0, (after.stdout+after.stderr).decode(errors="replace"))
        self.assertEqual(after.stdout, b"CAPSULE_OK\n")
        self.assertEqual((self.root / "capsule-fd.txt").read_bytes(), c.p.FILE_BYTES)

    def test_fail_fast_preserves_failed_report_and_never_claims_complete_acceptance(self):
        qemu, plugin, sidecar = (self.root / name for name in ("qemu", "plugin.so", "plugin.so.runtime.json"))
        for path in (qemu, plugin, sidecar): path.write_bytes(b"synthetic runtime fixture")
        runtime = SimpleNamespace(plugin=plugin, manifest=sidecar, plugin_sha256=c.p.sha(plugin),
                                  manifest_sha256=c.p.sha(sidecar))
        output = self.root / "run"
        with patch("sys.argv", ["local_check", "--qemu", str(qemu), "--plugin", str(plugin),
                                  "--out", str(output), "--fail-fast"]), \
             patch("builtins.print"), \
             patch.object(launch.Phase1Runtime, "load", return_value=runtime), \
             patch.object(launch.r, "check_runtime"), patch.object(c.p, "load_phase1"), \
             patch.object(c, "build", return_value={}), \
             patch.object(launch, "run_case", return_value={"check_passed":False,"status":"failed",
                          "error":"synthetic guest failure","failure":{"category":"guest_failure"}}) as run:
            self.assertEqual(launch.main(), 1)
        report = c.read_json(output / "report.json")
        self.assertEqual(run.call_count, 1)
        self.assertEqual(len(report["cases"]), 1)
        self.assertEqual(report["status"], "failed")
        self.assertFalse(report["acceptance_complete"])
        self.assertIn("stopped_after_failed_case", report)


if __name__ == "__main__":
    unittest.main()
