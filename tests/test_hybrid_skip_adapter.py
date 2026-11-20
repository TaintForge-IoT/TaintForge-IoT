import os
import shutil
import socket
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path

from experiments.hybrid_rebuilt_v1.telemetry import audit_hook_trace


@unittest.skipUnless(shutil.which("cc"), "C compiler required for the adapter test")
class SkipFrameTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        build = tempfile.TemporaryDirectory()
        cls.addClassCleanup(build.cleanup)
        cls.executable = Path(build.name) / "adapter-test"
        source = Path(__file__).with_name("hybrid_skip_adapter.c")
        subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                        str(source), "-o", str(cls.executable)], check=True)

    def run_adapter(self, skip_mask_size=0, skip_payload_size=0):
        peer, adapter = socket.socketpair()
        with peer, adapter:
            skip = struct.pack("!4s4I", b"TFH2", 1, 0, skip_mask_size, skip_payload_size)
            data = struct.pack("!4s4I", b"TFH2", 2, 1, 1, 1) + b"\x01@"
            peer.sendall(skip + data)
            peer.shutdown(socket.SHUT_WR)
            return subprocess.run([self.executable], stdin=adapter, capture_output=True,
                                  text=True, timeout=5)

    def test_empty_skip_then_data(self):
        result = self.run_adapter()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "C 2\nS 1\nF 1\nX 1\n")

    def test_nonempty_skip_is_rejected(self):
        for mask_size, payload_size in ((1, 0), (0, 1)):
            with self.subTest(mask_size=mask_size, payload_size=payload_size):
                result = self.run_adapter(mask_size, payload_size)
                self.assertEqual(result.returncode, 2)
                self.assertIn("invalid_skip_frame", result.stderr)
                self.assertEqual(result.stdout, "C 2\n")

    def run_skip_streak(self, *, custom_only, ignore_signal=False):
        env = os.environ.copy()
        env.pop("AFL_CUSTOM_MUTATOR_ONLY", None)
        if custom_only:
            env["AFL_CUSTOM_MUTATOR_ONLY"] = "1"
        mode = "ignore-signal" if ignore_signal else "honor-signal"
        peer, adapter = socket.socketpair()
        with peer, adapter, tempfile.TemporaryDirectory() as directory:
            peer.settimeout(5)
            path = Path(directory) / "hooks.log"
            with path.open("wb") as log, peer.makefile("rb") as requests:
                proc = subprocess.Popen([self.executable, mode], env=env, stdin=adapter,
                                        stdout=log, stderr=subprocess.PIPE)
                try:
                    adapter.close()
                    while header := requests.read(12):
                        magic, seq, size = struct.unpack("!4sII", header)
                        self.assertEqual((magic, size, requests.read(size)), (b"TFH2", 1, b"A"))
                        if seq == 1024:
                            reply = struct.pack("!4s4I", magic, seq, 1, 1, 1) + b"\x01@"
                        else:
                            reply = struct.pack("!4s4I", magic, seq, 0, 0, 0)
                        peer.sendall(reply)
                    _, stderr = proc.communicate(timeout=5)
                finally:
                    if proc.poll() is None:
                        proc.kill()
                        proc.communicate()
            return proc.returncode, stderr, audit_hook_trace(path)

    def test_output_resets_streak_before_clean_stop(self):
        code, stderr, report = self.run_skip_streak(custom_only=True)
        self.assertEqual(code, 0, stderr)
        self.assertEqual(report["custom_fuzz_callbacks"], 2048)
        self.assertEqual(report["custom_skips"], 2047)
        self.assertTrue(report["clean_deinit_observed"])
        self.assertEqual(report.get("skip_limit_request"),
                         {"callback": 2048, "consecutive_skips": 1024})

    def test_mixed_mode_keeps_running_after_custom_skips(self):
        code, stderr, report = self.run_skip_streak(custom_only=False)
        self.assertEqual(code, 0, stderr)
        self.assertEqual(report["custom_fuzz_callbacks"], 2100)
        self.assertNotIn("skip_limit_request", report)

    def test_ignored_stop_has_bounded_hook_output(self):
        code, stderr, report = self.run_skip_streak(custom_only=True, ignore_signal=True)
        self.assertEqual(code, 2)
        self.assertIn(b"skip_limit_stop_ignored", stderr)
        self.assertLessEqual(report["custom_fuzz_callbacks"], 2048 + 32)
        self.assertFalse(report["clean_deinit_observed"])
