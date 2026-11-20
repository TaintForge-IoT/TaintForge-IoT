"""Regression checks for cancellation and the full host fixture's failure oracle."""
from pathlib import Path
import socket
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from scripts.verify_afl_phase2_e2e import verify_fault_fixture, verify_saved_faults
from taintforge_env import afl_file as f
from taintforge_env import afl_transport as transport
from taintforge_env.afl_warm import WarmAttemptServer


class ReviewRegressions(unittest.TestCase):
    def test_afl_exit_is_preserved_when_warm_finalization_fails(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root/'afl-fuzz'
            binary.write_text('#!/bin/sh\nexit 0\n'); binary.chmod(0o700)
            manifest = {'status': 'prepared', 'max_input': 4096, 'launch': {'timeout_seconds': 1},
                        'build': {'bridge': '/bin/true'},
                        'warm': {'campaign_seconds': 10, 'timeout_ms': 100, 'phase2': {}}}
            class Server(transport.AttemptServer):
                def start(self):
                    pass
                def close(self):
                    self.channel.close(); self.peer.close()
                    raise RuntimeError('Warm finalization failed')
            with patch.object(f, 'verify_campaign', return_value=manifest), \
                 patch('taintforge_env.afl_warm.WarmAttemptServer', Server):
                with self.assertRaisesRegex(RuntimeError, 'Warm finalization failed'):
                    transport.run_campaign(root, afl_bin=root, seconds=1)
            saved = f.read_json(root/'campaign.json')
            self.assertEqual(saved['status'], 'failed')
            self.assertEqual(saved['afl_exit'], 0)

    def test_final_report_failure_is_saved_as_failed_campaign(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root/'afl-fuzz'
            binary.write_text('#!/bin/sh\nexit 0\n'); binary.chmod(0o700)
            manifest = {'status': 'prepared', 'max_input': 4096, 'launch': {'timeout_seconds': 1},
                        'build': {'bridge': '/bin/true'},
                        'warm': {'campaign_seconds': 10, 'timeout_ms': 100, 'phase2': {}}}
            f.atomic_json(root/'warm-ready.json', {'status': 'ready', 'run_dir': str(root)})
            f.atomic_json(root/'phase2-progress.json', {'status': 'passed', 'completed': 0})
            (root/'warm-session-result.json').write_text('{broken')
            class Server(transport.AttemptServer):
                def start(self):
                    pass
                def close(self):
                    self.channel.close(); self.peer.close()
            with patch.object(f, 'verify_campaign', return_value=manifest), \
                 patch('taintforge_env.afl_warm.WarmAttemptServer', Server):
                result = transport.run_campaign(root, afl_bin=root, seconds=1)
            self.assertEqual(result['status'], 'failed')
            saved = f.read_json(root/'campaign.json')
            self.assertEqual(saved['status'], 'failed')
            self.assertIn('report_error', saved)

    def test_closing_wakes_a_blocked_warm_child_transport(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            client, worker = socket.socketpair()
            self.addCleanup(worker.close)
            self.addCleanup(client.close)
            client.settimeout(3)
            waiting, finished = threading.Event(), threading.Event()
            peer_errors = []

            def blocked_receive():
                try:
                    waiting.set()
                    self.assertEqual(client.recv(1), b'')
                except BaseException as exc:
                    peer_errors.append(exc)
                finally:
                    finished.set()

            server = WarmAttemptServer(root, deadline=60)
            self.addCleanup(server.close)
            server.active_worker = client
            receiver = threading.Thread(target=blocked_receive, daemon=True)
            receiver.start()
            self.assertTrue(waiting.wait(3))
            start = time.monotonic()
            server.close()
            self.assertTrue(finished.wait(1), 'close did not wake the blocked worker socket')
            receiver.join(3)
            self.assertLess(time.monotonic()-start, 2)
            self.assertEqual(peer_errors, [])
            self.assertEqual(server.completed, 0)

    def test_fixture_accepts_expected_exit86_but_rejects_setup_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root/'input').write_bytes(b'E')
            result = {'outcome': {'kind': 'normal', 'guest_signal': None}, 'guest_exit': 86,
                      'input': {'input_sha256': f.p.sha(root/'input')}}
            verify_fault_fixture(root, result)
            with self.assertRaisesRegex(RuntimeError, 'unexpected child outcome'):
                verify_fault_fixture(root, result | {'guest_exit': 77})

    def test_fixture_rejects_an_exit_in_place_of_expected_crash(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root/'input').write_bytes(b'C')
            result = {'outcome': {'kind': 'normal', 'guest_signal': None}, 'guest_exit': 0,
                      'input': {'input_sha256': f.p.sha(root/'input')}}
            with self.assertRaisesRegex(RuntimeError, 'unexpected child outcome'):
                verify_fault_fixture(root, result)

    def test_fixture_rejects_timeout_of_normal_input(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root/'input').write_bytes(b'A')
            result = {'outcome': {'kind': 'timeout', 'guest_signal': None}, 'guest_exit': None,
                      'input': {'input_sha256': f.p.sha(root/'input')}}
            with self.assertRaisesRegex(RuntimeError, 'unexpected child outcome'):
                verify_fault_fixture(root, result)


class SavedFaultRegressions(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.crashes = self.root/'afl/default/crashes'; self.crashes.mkdir(parents=True)
        self.hangs = self.root/'afl/default/hangs'; self.hangs.mkdir()
        for index, (data, sig) in enumerate(((b'C', 4), (b'S', 11), (b'B', 6))):
            (self.crashes/f'id:{index:06d},sig:{sig:02d},src:000000').write_bytes(data)
        (self.hangs/'id:000000,src:000000').write_bytes(b'H')

    def test_all_three_signals_and_real_hang_are_accepted(self):
        self.assertEqual(verify_saved_faults(self.root),
                         {'afl_crashes': 3, 'afl_hangs': 1, 'afl_crash_signals': [4, 6, 11]})

    def test_a_missing_crash_class_is_rejected(self):
        next(self.crashes.glob('*sig:04*')).unlink()
        with self.assertRaisesRegex(RuntimeError, 'all three'):
            verify_saved_faults(self.root)

    def test_crash_reported_as_hang_is_rejected(self):
        (self.hangs/'id:000001,src:000000').write_bytes(b'C')
        with self.assertRaisesRegex(RuntimeError, 'misclassified crash'):
            verify_saved_faults(self.root)

    def test_wrong_signal_is_rejected(self):
        next(self.crashes.glob('*sig:04*')).write_bytes(b'S')
        with self.assertRaisesRegex(RuntimeError, 'wrong input or signal'):
            verify_saved_faults(self.root)


if __name__ == '__main__':
    unittest.main()
