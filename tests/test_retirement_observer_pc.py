"""Real pinned QEMU, production snapshot code, benign guests; no retirement IPC."""
import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest

from experiments.retirement_observer import controller as c


class QemuSnapshotTests(unittest.TestCase):
    def test_callback_pc_and_raw_eip_survive_real_instruction_snapshots(self):
        configured = os.environ.get("TF_OBSERVER_QEMU")
        if not configured:
            self.skipTest("TF_OBSERVER_QEMU is required for the pinned QEMU snapshot regression")
        qemu = Path(configured).expanduser().resolve(strict=True)
        self.assertRegex(c.p.command(qemu, "--version").splitlines()[0],
                         r"\bversion 11\.0\.1(?:\s|$)")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            plugin = root / "pc-probe.so"
            flags = shlex.split(c.p.command("pkg-config", "--cflags", "--libs", "glib-2.0"))
            c.p.command("cc", "-std=c11", "-O2", "-g", "-Wall", "-Wextra", "-Werror", "-Wshadow",
                        "-Wformat=2", "-shared", "-fPIC", "-fvisibility=hidden", "-pthread",
                        "-I", c.p.HERE / "vendor", c.HERE / "pc_probe.c", "-o", plugin, *flags)
            for base in (0x08048000, 0x09048000, 0x0a048000):
                with self.subTest(base=hex(base)):
                    run = root / hex(base)
                    run.mkdir()
                    obj, guest = run / "guest.o", run / "guest"
                    c.p.command("as", "--32", "--defsym", "WORK_LOOPS=128",
                                c.HERE / "guest.S", "-o", obj)
                    c.p.command("ld", "-m", "elf_i386", "-Ttext-segment=" + hex(base),
                                "-z", "noexecstack", "--build-id=none", obj, "-o", guest)
                    c.p.command("strip", "--strip-all", guest)
                    executed = subprocess.run([str(qemu), "-plugin", str(plugin), str(guest)],
                        cwd=run, capture_output=True, text=True, timeout=10)
                    self.assertEqual(executed.returncode, 0, executed.stderr[-2000:])
                    self.assertEqual(executed.stdout, "CAPSULE_OK\n")
                    self.assertEqual((run / "capsule-fd.txt").read_bytes(), c.p.FILE_BYTES)
                    frames = []
                    total = None
                    for line in executed.stderr.splitlines():
                        if line.startswith("M2_PC_PROBE "):
                            self.assertIsNone(total, "Snapshot after completion")
                            frames.append(json.loads(line.removeprefix("M2_PC_PROBE ")))
                        elif line.startswith("M2_PC_PROBE_DONE "):
                            self.assertIsNone(total, "Duplicate completion")
                            total = int(line.removeprefix("M2_PC_PROBE_DONE "))
                        else:
                            self.fail("Unexpected QEMU diagnostic: " + line)
                    self.assertIsNotNone(total)
                    self.assertGreater(total, 100)
                    self.assertEqual(len(frames), 2*total)
                    differing = 0
                    pid = frames[0]["host_pid"]
                    for seq in range(1, total+1):
                        first, second = frames[2*(seq-1):2*seq]
                        c.snapshot_ok(first, pid, 1, 1)
                        c.snapshot_ok(second, pid, 1, 2)
                        c.same_hold(first, second, 0)
                        self.assertEqual(first["seq"], seq)
                        differing += first["pc"] != first["qemu_eip"]
                    self.assertGreater(differing, 0, "The regression did not exercise lazy EIP")


if __name__ == "__main__":
    unittest.main()
