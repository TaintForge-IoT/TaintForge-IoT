"""Real, benign loader tests; the target is built here without libc."""
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile
import unittest

from taintforge_env.elf_runtime import DependencyResolver, ElfImage, ElfRuntimeError, in_sysroot, provision_guest
from taintforge_env.elf_target import ElfTargetError
from tests.elf_fixture import write_elf


@unittest.skipUnless(platform.machine() == "x86_64" and shutil.which("gcc") and shutil.which("ld"), "x86-64 ELF toolchain required")
class ElfRuntimeTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.sysroot = self.base / "sysroot"
        self.lib = self.sysroot / "lib"
        self.lib.mkdir(parents=True)
        (self.base / "b.c").write_text("int tf_b(void) { return 17; }\n")
        (self.base / "a.c").write_text("int tf_b(void); int tf_a(void) { return tf_b()+25; }\n")
        self.command("gcc", "-shared", "-nostdlib", "-fPIC", "-Wl,-soname,libtf_b.so", str(self.base / "b.c"), "-o", str(self.lib / "libtf_b.so"))
        self.command("gcc", "-shared", "-nostdlib", "-fPIC", "-Wl,-soname,libtf_a.so", str(self.base / "a.c"), "-L", str(self.lib), "-ltf_b", "-o", str(self.lib / "libtf_a.so"))
        (self.base / "start.S").write_text(".global _start\n.text\n_start:\ncall tf_a@PLT\nsub $42,%eax\nmov %eax,%edi\nmov $60,%eax\nsyscall\n.section .note.GNU-stack,\"\",@progbits\n")
        self.command("as", "--64", str(self.base / "start.S"), "-o", str(self.base / "start.o"))
        self.interpreter = ElfImage(Path(shutil.which("true"))).target.interpreter
        self.binary = self.base / "program"
        self.command("ld", "--dynamic-linker", self.interpreter, str(self.base / "start.o"), "-L", str(self.lib), "-ltf_a", "-rpath-link", str(self.lib), "-o", str(self.binary))
        destination = self.sysroot / self.interpreter.lstrip("/")
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(self.interpreter, destination)
        destination.chmod(0o755)

    def command(self, *args):
        return subprocess.run(args, check=True, capture_output=True)

    def test_recursive_dependencies_and_real_dynamic_loader(self):
        rootfs = self.base / "guest"
        report = provision_guest(self.binary, rootfs, sysroot=self.sysroot, binary_guest_path="/bin/sample")
        self.assertEqual(ElfImage(self.binary).dynamic()["needed"], ["libtf_a.so"])
        self.assertTrue((rootfs / "lib/libtf_b.so").is_file())
        self.assertEqual(report["headers"], "original_valid_elf")
        self.assertEqual((rootfs / "bin/sample").read_bytes(), self.binary.read_bytes())
        result = subprocess.run([str(rootfs / self.interpreter.lstrip("/")), "--inhibit-cache", "--library-path",
                                 str(rootfs / "lib"), str(rootfs / "bin/sample")], env={"PATH": "/usr/bin:/bin"}, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr.decode())

    def test_missing_transitive_dependency_rejected_before_copy(self):
        (self.lib / "libtf_b.so").unlink()
        rootfs = self.base / "guest"
        with self.assertRaisesRegex(ElfRuntimeError, "libtf_b.so"):
            provision_guest(self.binary, rootfs, sysroot=self.sysroot)
        self.assertFalse(rootfs.exists())

    def test_wrong_arch_library_is_not_accepted(self):
        write_elf(self.lib / "libtf_b.so", arch="i386")
        with self.assertRaisesRegex(ElfRuntimeError, "libtf_b.so"):
            provision_guest(self.binary, self.base / "guest", sysroot=self.sysroot)

    def test_missing_interpreter_is_not_hidden_by_host(self):
        (self.sysroot / self.interpreter.lstrip("/")).unlink()
        with self.assertRaisesRegex(ElfRuntimeError, "interpreter"):
            provision_guest(self.binary, self.base / "guest", sysroot=self.sysroot)

    def test_absolute_symlink_stays_inside_sysroot(self):
        path = self.lib / "libtf_b.so"
        real = self.sysroot / "vendor/libtf_b.so"
        real.parent.mkdir()
        path.rename(real)
        path.symlink_to("/vendor/libtf_b.so")
        self.assertEqual(in_sysroot(self.sysroot, "/lib/libtf_b.so"), real)
        report = provision_guest(self.binary, self.base / "guest", sysroot=self.sysroot)
        self.assertEqual(len(report["files"]), 4)

    def test_symlink_escape_and_loop_rejected(self):
        path = self.sysroot / "escape"
        path.symlink_to("../../outside")
        with self.assertRaisesRegex(ElfRuntimeError, "escapes"):
            in_sysroot(self.sysroot, "/escape")
        path.unlink()
        path.symlink_to("/escape")
        with self.assertRaisesRegex(ElfRuntimeError, "too many"):
            in_sysroot(self.sysroot, "/escape")

    def test_raw_dump_is_not_mistaken_for_standalone_elf(self):
        self.binary.write_bytes(b"\x90" * 4096)
        with self.assertRaises((ElfRuntimeError, ElfTargetError)):
            provision_guest(self.binary, self.base / "guest", sysroot=self.sysroot)

    def test_additional_library_directory_is_reported_for_guest_loader(self):
        vendor = self.sysroot / "opt/vendor"
        vendor.mkdir(parents=True)
        for name in ("libtf_a.so", "libtf_b.so"):
            (self.lib / name).rename(vendor / name)
        rootfs = self.base / "guest"
        report = provision_guest(self.binary, rootfs, sysroot=self.sysroot, library_dirs=["/opt/vendor"])
        self.assertIn("/opt/vendor", report["library_path"])
        result = subprocess.run([str(rootfs / self.interpreter.lstrip("/")), "--inhibit-cache", "--library-path",
                                 str(rootfs / "opt/vendor"), str(rootfs / "bin/unpacked.elf")], capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr.decode())

    def test_invalid_elf_library_is_reported_as_missing(self):
        (self.lib / "libtf_b.so").write_bytes(b"not an ELF")
        with self.assertRaisesRegex(ElfRuntimeError, "libtf_b.so"):
            provision_guest(self.binary, self.base / "guest", sysroot=self.sysroot)


if __name__ == "__main__":
    unittest.main()
