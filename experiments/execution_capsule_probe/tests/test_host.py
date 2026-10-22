#!/usr/bin/env python3
"""Host tests with a mock CPU API. Never report them as QEMU/Phase-1 E2E.

Build host_harness.c with the pinned header + GLib, then set CAPSULE_HARNESS.
"""
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("capsule_controller", ROOT / "controller.py")
controller = importlib.util.module_from_spec(spec)
spec.loader.exec_module(controller)
SYMBOLS = {"capsule_point_one": 0x1000, "capsule_point_two": 0x2000, "capsule_buffer": 0x3000}


class NativeTransport(unittest.TestCase):
    def start(self, pause=700, total=4000, **variables):
        temporary = tempfile.TemporaryDirectory(prefix="tfc-test-", dir="/tmp")
        self.addCleanup(temporary.cleanup)
        directory = Path(temporary.name)
        connection, child = socket.socketpair()
        self.addCleanup(connection.close)
        self.addCleanup(child.close)
        endpoint = str(directory / "socket")
        stderr = (directory / "stderr").open("wb")
        self.addCleanup(stderr.close)
        process = subprocess.Popen([
            os.environ["CAPSULE_HARNESS"], "socket=" + endpoint,
            "p1=0x1000", "p2=0x2000", "buffer=0x3000", f"pause-ms={pause}",
            f"total-ms={total}", f"controller={os.getpid()}"], stderr=stderr,
            pass_fds=(child.fileno(),),
            env={**os.environ, **variables, "MOCK_SOCKET_FD": str(child.fileno())})
        child.close()
        def cleanup():
            if process.poll() is None:
                process.kill()
            process.wait(timeout=3)
        self.addCleanup(cleanup)
        if variables.get("MOCK_BAD_API"):
            return process, None, None, directory
        frames = controller.Frames(connection, time.monotonic() + 6)
        return process, connection, frames, directory

    def verify_exit(self, process, directory, expected):
        self.assertEqual(process.wait(timeout=6), expected)
        if expected >= 124:
            self.assertIn(f"CAPSULE_ABORT code={expected} ", (directory / "stderr").read_text())

    def check_point(self, process, connection, frames, point):
        first = frames.receive()
        controller.validate_snapshot(first, point, 1, SYMBOLS, process.pid)
        # Commands and JSON replies are streams, not packet boundaries.
        connection.sendall(b"CH")
        connection.sendall(f"ECK {point}\n".encode())
        second = frames.receive()
        controller.validate_snapshot(second, point, 2, SYMBOLS, process.pid, first)
        self.assertEqual(first["regs"], second["regs"])
        return first, second

    def test_two_points_bool_api_null_eax_handle_and_same_stack(self):
        p, c, f, d = self.start()
        first, _ = self.check_point(p, c, f, 1)
        c.sendall(b"CONTINUE 1\n")
        second, _ = self.check_point(p, c, f, 2)
        self.assertEqual(first["stack_hex"], second["stack_hex"])
        self.assertNotEqual(first["buffer_hex"], second["buffer_hex"])
        c.sendall(b"CONTINUE 2\n")
        self.assertEqual(f.receive()["event"], "done")
        self.verify_exit(p, d, 0)

    def test_pause_timeout(self):
        p, c, f, d = self.start(pause=300)
        f.receive()
        self.verify_exit(p, d, 124)

    def test_second_pause_timeout(self):
        p, c, f, d = self.start(pause=300)
        self.check_point(p, c, f, 1)
        c.sendall(b"CONTINUE 1\n")
        f.receive()
        self.verify_exit(p, d, 124)

    def test_actual_controller_process_killed(self):
        p, c, f, d = self.start()
        child = subprocess.Popen([sys.executable, "-c",
            "import os,signal,socket,sys; "
            "c=socket.socket(fileno=int(sys.argv[1])); "
            "c.recv(4096); os.kill(os.getpid(),signal.SIGKILL)", str(c.fileno())],
            pass_fds=(c.fileno(),))
        c.close()  # only the doomed controller owns the peer endpoint now
        self.assertEqual(child.wait(timeout=3), -9)
        self.verify_exit(p, d, 125)

    def test_disconnect_at_first_and_second_point(self):
        for point in (1, 2):
            with self.subTest(point=point):
                p, c, f, d = self.start()
                if point == 2:
                    self.check_point(p, c, f, 1)
                    c.sendall(b"CONTINUE 1\n")
                f.receive()
                c.close()
                self.verify_exit(p, d, 125)

    def test_wrong_continue_token(self):
        p, c, f, d = self.start()
        self.check_point(p, c, f, 1)
        c.sendall(b"CONTINUE 2\n")
        self.verify_exit(p, d, 126)

    def test_oversized_and_nul_commands(self):
        for command in (b"x" * 80, b"CHECK\x001\n"):
            with self.subTest(command=repr(command)):
                p, c, f, d = self.start()
                f.receive()
                c.sendall(command)
                self.verify_exit(p, d, 126)

    def test_partial_bytes_cannot_extend_deadline(self):
        p, c, f, d = self.start(pause=350)
        f.receive()
        begin = time.monotonic()
        for byte in b"CHE":
            c.sendall(bytes([byte]))
            time.sleep(0.1)
        self.verify_exit(p, d, 124)
        self.assertLess(time.monotonic() - begin, 1.5)

    def test_total_watchdog_without_cpu_callbacks(self):
        p, c, f, d = self.start(total=350, MOCK_HANG="1")
        self.verify_exit(p, d, 124)
        self.assertIn("reason=total_timeout", (d / "stderr").read_text())

    def test_disconnect_without_cpu_callbacks(self):
        p, c, f, d = self.start(MOCK_HANG="1")
        c.close()
        self.verify_exit(p, d, 125)

    def test_fail_closed_for_api_read_errors_and_second_vcpu(self):
        for variable in ("MOCK_FAIL_REGISTER", "MOCK_FAIL_MEMORY", "MOCK_MISSING_REG",
                         "MOCK_BAD_PC", "MOCK_SECOND_VCPU"):
            with self.subTest(variable=variable):
                p, c, f, d = self.start(**{variable: "1"})
                self.verify_exit(p, d, 126)

    def test_wrong_api_rejected(self):
        p, c, f, d = self.start(MOCK_BAD_API="1")
        self.verify_exit(p, d, 1)


class PythonProtocol(unittest.TestCase):
    def test_combined_frames_preserved(self):
        a, b = socket.socketpair()
        self.addCleanup(a.close)
        self.addCleanup(b.close)
        b.sendall(b'{"protocol":1,"a":1}\n{"protocol":1,"a":2}\n')
        frames = controller.Frames(a, time.monotonic() + 1)
        self.assertEqual(frames.receive()["a"], 1)
        self.assertEqual(frames.receive()["a"], 2)

    def test_oversized_json_rejected(self):
        a, b = socket.socketpair()
        self.addCleanup(a.close)
        self.addCleanup(b.close)
        b.sendall(b"x" * 9000)
        with self.assertRaises(controller.ProbeError):
            controller.Frames(a, time.monotonic() + 1).receive()


if __name__ == "__main__":
    unittest.main(verbosity=2)
