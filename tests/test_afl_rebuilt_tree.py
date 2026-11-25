from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import unittest

from taintforge_env.afl_rebuilt_tree import verify_signals


class TreeEvidence(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.output = Path(temp.name)
        self.log = self.output / 'qemu.17.log'
        self.events = (b'user_queue_signal env=0xabc signal 4\n'
                       b'user_handle_signal env=0xabc signal 4\n'
                       b'user_dump_core_and_abort env=0xabc signal 4 (host 4)\n')
        self.rows = [{'pid': 4, 'signal': None}, {'pid': 17, 'signal': signal.SIGILL}]
        self.traps = {17: 0x8049123}

    def test_requires_matching_pid_guest_trap_and_fatal_trace(self):
        self.log.write_bytes(self.events)
        self.assertEqual(verify_signals(self.output, self.rows, self.traps),
                         [{'pid': 17, 'guest_pc': 0x8049123, 'signal': signal.SIGILL}])
        for traps in ({}, {4: 0x8049123}):
            with self.subTest(traps=traps), self.assertRaises(RuntimeError):
                verify_signals(self.output, self.rows, traps)
        with self.assertRaises(RuntimeError):
            verify_signals(self.output, [{'pid': 17, 'signal': None}], self.traps)

    def test_incomplete_and_mismatched_native_signals(self):
        for data in (b'', self.events.splitlines(keepends=True)[-1],
                     self.events.replace(b'host 4', b'host 9'),
                     self.events.replace(b'signal env=0xabc', b'signal env=0xdef', 1)):
            self.log.write_bytes(data)
            with self.subTest(data=data), self.assertRaises(RuntimeError):
                verify_signals(self.output, self.rows, self.traps)

    def test_ordinary_process_can_handle_sigchld(self):
        self.log.write_bytes(b'user_handle_signal env=0xabc signal 17\n')
        self.assertEqual(verify_signals(self.output, [{'pid': 17, 'signal': None}], {}), [])

    def test_foreign_evidence_rejected(self):
        (self.output / 'qemu.21.log').write_bytes(self.events)
        with self.assertRaises(RuntimeError):
            verify_signals(self.output, self.rows, self.traps)

    def test_reap_after_root_exits(self):
        # Keep subreaper status and waitpid(-1) local to this subprocess.
        subprocess.run([sys.executable, '-c', """
import ctypes, os, time
from taintforge_env.afl_rebuilt_tree import reap_tree
assert ctypes.CDLL(None).prctl(36, 1, 0, 0, 0) == 0
root = os.fork()
if root == 0:
    r, w = os.pipe()
    if os.fork() == 0:
        os.close(w)
        os.read(r, 1)
        os._exit(132)
    os._exit(0)
statuses = reap_tree(root, time.monotonic() + 4)
assert statuses[root] == 0 and sorted(statuses.values()) == [0, 132], statuses
"""], check=True, timeout=8)
