"""Namespace metadata remains verifiable when its parent is private to root."""
import errno
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from taintforge_env import network_namespace as ns


class NamespaceIdentityTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.enterContext(patch.object(ns, "NETNS_ROOT", self.root))
        self.name = "tf-0123abcd"
        self.handle = self.root / self.name
        self.handle.touch()
        info = self.handle.stat()
        self.identity = {"name": self.name, "device": info.st_dev, "inode": info.st_ino}

    def test_accessible_handle_needs_no_privileged_process(self):
        with patch.object(ns.subprocess, "run") as run:
            self.assertEqual(ns.namespace_identity(self.name), self.identity)
            self.assertTrue(ns.namespace_exists(self.name))
        run.assert_not_called()

    def test_a_handle_does_not_need_read_permission_for_metadata(self):
        self.handle.chmod(0)
        self.assertEqual(ns.namespace_identity(self.name), self.identity)
        self.assertEqual(stat.S_IMODE(self.handle.stat().st_mode), 0)

    def test_absence_is_distinct_from_an_identity(self):
        self.handle.unlink()
        with patch.object(ns.subprocess, "run") as run:
            self.assertFalse(ns.namespace_exists(self.name))
            with self.assertRaises(FileNotFoundError):
                ns.namespace_identity(self.name)
        run.assert_not_called()

    def test_missing_namespace_directory_is_absent(self):
        with patch.object(ns, "NETNS_ROOT", self.root / "missing"):
            self.assertFalse(ns.namespace_exists(self.name))

    def test_symlink_and_dangling_symlink_are_never_absence(self):
        self.handle.unlink()
        for target in ("/proc/self/ns/net", str(self.root / "missing")):
            with self.subTest(target=target):
                self.handle.symlink_to(target)
                try:
                    with self.assertRaisesRegex(ns.NamespaceInspectionError, "symlink"):
                        ns.namespace_exists(self.name)
                finally:
                    self.handle.unlink()

    def test_parent_symlink_is_rejected(self):
        alias = self.root / "alias"
        alias.symlink_to(self.root, target_is_directory=True)
        with patch.object(ns, "NETNS_ROOT", alias), self.assertRaises(OSError):
            ns.namespace_exists(self.name)

    def test_directory_and_fifo_are_not_namespace_handles(self):
        self.handle.unlink()
        self.handle.mkdir()
        with self.assertRaisesRegex(ns.NamespaceInspectionError, "regular file"):
            ns.namespace_exists(self.name)
        self.handle.rmdir()
        os.mkfifo(self.handle)
        with self.assertRaisesRegex(ns.NamespaceInspectionError, "regular file"):
            ns.namespace_exists(self.name)

    def test_invalid_names_are_rejected_before_filesystem_or_sudo_access(self):
        for name in ("../tf-0123abcd", "tf-0123abcd/extra", "foreign", "tf-0123ABCD", "tf-0123abcd\n", None):
            with self.subTest(name=name), patch.object(ns.os, "open") as opened, \
                 patch.object(ns.subprocess, "run") as run, self.assertRaises(ns.NamespaceInspectionError):
                ns.namespace_identity(name)
            opened.assert_not_called()
            run.assert_not_called()

    def test_metadata_descriptors_close_after_success_and_failure(self):
        before = len(os.listdir("/proc/self/fd"))
        for _ in range(10):
            ns.namespace_identity(self.name)
        with patch.object(ns.os, "fstat", side_effect=OSError(errno.EIO, "injected failure")), self.assertRaises(OSError):
            ns.namespace_identity(self.name)
        self.assertEqual(len(os.listdir("/proc/self/fd")), before)

    def test_private_parent_uses_read_only_probe_without_chmod(self):
        real_uid = os.geteuid()
        direct_probe = ns._probe_namespace
        self.root.chmod(0)
        try:
            if real_uid != 0:
                with self.assertRaises(PermissionError):
                    self.handle.stat()

            def local_probe(name):
                if real_uid == 0:
                    raise PermissionError(errno.EACCES, "private parent", str(self.handle))
                return direct_probe(name)

            def privileged(command, **options):
                self.assertEqual(command, ["sudo", "-n", "--", sys.executable, "-I",
                    str(Path(ns.__file__).resolve()), "--probe", self.name])
                self.assertEqual(options["stdin"], subprocess.DEVNULL)
                self.assertEqual(options["timeout"], 5)
                self.assertNotIn("shell", options)
                # Simulate only the elevated reader; production never changes modes.
                self.root.chmod(0o700)
                try:
                    value = direct_probe(self.name)
                finally:
                    self.root.chmod(0)
                return subprocess.CompletedProcess(command, 0, json.dumps(value).encode(), b"")

            with patch.object(ns, "_probe_namespace", side_effect=local_probe), \
                 patch.object(ns.os, "geteuid", return_value=1000), \
                 patch.object(ns.subprocess, "run", side_effect=privileged) as run:
                self.assertEqual(ns.namespace_identity(self.name), self.identity)
                self.assertTrue(ns.namespace_exists(self.name))
                self.assertEqual(run.call_count, 2)
            self.assertEqual(stat.S_IMODE(self.root.stat().st_mode), 0)
        finally:
            self.root.chmod(0o700)

    def privileged_result(self, value=None, *, code=0, output=None, error=b""):
        return subprocess.CompletedProcess([], code, json.dumps(value).encode() if output is None else output, error)

    def inspect_with_result(self, result, *, identity=False):
        with patch.object(ns, "_probe_namespace", side_effect=PermissionError(errno.EACCES, "denied")), \
             patch.object(ns.os, "geteuid", return_value=1000), \
             patch.object(ns.subprocess, "run", return_value=result):
            return ns.namespace_identity(self.name) if identity else ns.namespace_exists(self.name)

    def test_confirmed_privileged_absence_is_accepted(self):
        result = self.privileged_result({"name": self.name, "present": False})
        self.assertFalse(self.inspect_with_result(result))
        with self.assertRaises(FileNotFoundError):
            self.inspect_with_result(result, identity=True)

    def test_sudo_failure_is_never_reported_as_successful_cleanup(self):
        result = self.privileged_result(code=1, error=b"sudo: a password is required")
        with self.assertRaisesRegex(ns.NamespaceInspectionError, "password is required"):
            self.inspect_with_result(result)

    def test_missing_sudo_and_probe_timeout_are_errors(self):
        for error in (FileNotFoundError("sudo"), subprocess.TimeoutExpired(["sudo"], 5)):
            with self.subTest(error=type(error).__name__), \
                 patch.object(ns, "_probe_namespace", side_effect=PermissionError(errno.EACCES, "denied")), \
                 patch.object(ns.os, "geteuid", return_value=1000), \
                 patch.object(ns.subprocess, "run", side_effect=error), self.assertRaises(ns.NamespaceInspectionError):
                ns.namespace_exists(self.name)

    def test_invalid_privileged_response_cannot_supply_an_identity(self):
        good = {**self.identity, "present": True}
        values = ({}, {**good, "name": "tf-00000000"}, {**good, "present": 1},
                  {**good, "device": True}, {**good, "inode": 0}, {**good, "inode": "123"},
                  {**good, "extra": True}, {"name": self.name, "present": False, "inode": 1})
        for value in values:
            with self.subTest(value=value), self.assertRaises(ns.NamespaceInspectionError):
                self.inspect_with_result(self.privileged_result(value), identity=True)

    def test_invalid_json_and_oversized_probe_output_are_rejected(self):
        for output in (b"not JSON", b"{}\n{}", b"\xff", b" " * 4097):
            with self.subTest(output=output[:20]), self.assertRaises(ns.NamespaceInspectionError):
                self.inspect_with_result(self.privileged_result(output=output))

    def test_root_denial_is_reported_without_recursive_sudo(self):
        with patch.object(ns, "_probe_namespace", side_effect=PermissionError(errno.EACCES, "denied")), \
             patch.object(ns.os, "geteuid", return_value=0), patch.object(ns.subprocess, "run") as run:
            with self.assertRaises(PermissionError):
                ns.namespace_exists(self.name)
        run.assert_not_called()

    def test_other_filesystem_errors_do_not_invoke_sudo(self):
        with patch.object(ns, "_probe_namespace", side_effect=OSError(errno.EIO, "I/O failure")), \
             patch.object(ns.subprocess, "run") as run:
            with self.assertRaises(OSError):
                ns.namespace_exists(self.name)
        run.assert_not_called()

    def test_standalone_isolated_helper_validates_names(self):
        result = subprocess.run([sys.executable, "-I", str(Path(ns.__file__).resolve()),
                                 "--probe", "../unrelated"], capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 1)
        self.assertIn(b"invalid owned network namespace name", result.stderr)
        self.assertEqual(result.stdout, b"")


if __name__ == "__main__":
    unittest.main()
