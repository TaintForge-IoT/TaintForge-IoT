"""Startup failures must not leak workers, descriptors, or signal handlers."""
from pathlib import Path
import signal
import tempfile
import unittest
from unittest.mock import patch

from taintforge_env import afl_file as f, afl_transport as t, afl_warm as w


class CampaignLifecycleTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.binary = self.root/'afl-fuzz'
        self.binary.write_text('#!/bin/sh\nexit 0\n'); self.binary.chmod(0o700)
        self.manifest = {'status': 'prepared', 'max_input': 4096,
                         'launch': {'timeout_seconds': 1}, 'build': {'bridge': '/bin/true'}}
        self.servers = []
        owners = self.servers
        class ProbeServer(t.AttemptServer):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self.started = self.closed = False
                owners.append(self)
            def start(self):
                self.started = True
            def close(self):
                self.closed = True
                self.channel.close(); self.peer.close()
        self.server_type = ProbeServer
        def cleanup():
            for server in self.servers: server.close()
        self.addCleanup(cleanup)
        self.handlers = {number: signal.getsignal(number) for number in (signal.SIGINT, signal.SIGTERM)}
        def restore_handlers():
            for number, handler in self.handlers.items(): signal.signal(number, handler)
        self.addCleanup(restore_handlers)

    def run_campaign(self):
        with patch.object(f, 'verify_campaign', return_value=self.manifest), \
             patch.object(t, 'AttemptServer', self.server_type):
            return t.run_campaign(self.root, afl_bin=self.root, seconds=1)

    def test_directory_in_place_of_afl_binary_fails_before_worker_preparation(self):
        self.binary.unlink(); self.binary.mkdir()
        with self.assertRaises((OSError, RuntimeError)):
            self.run_campaign()
        self.assertEqual(self.servers, [])

    def test_unreadable_afl_fails_before_worker_preparation(self):
        with patch.object(t.p, 'sha', side_effect=OSError('cannot hash AFL')):
            with self.assertRaisesRegex(OSError, 'cannot hash AFL'):
                self.run_campaign()
        self.assertEqual(self.servers, [])

    def test_afl_hash_is_refreshed_after_long_preparation(self):
        binary = self.binary
        start = self.server_type.start
        def prepare_then_update(server):
            start(server)
            binary.write_text('#!/bin/sh\nexit 0\n# updated during preparation\n')
        with patch.object(self.server_type, 'start', prepare_then_update):
            value = self.run_campaign()
        self.assertEqual(value['status'], 'completed')
        self.assertEqual(value['afl_sha256'], f.p.sha(binary))
        self.assertTrue(self.servers[0].closed)

    def test_running_manifest_failure_closes_worker_and_restores_handlers(self):
        write = f.atomic_json
        def fail_running(path, value):
            if Path(path) == self.root/'campaign.json' and value.get('status') == 'running':
                raise OSError('cannot save running manifest')
            return write(path, value)
        with patch.object(f, 'atomic_json', side_effect=fail_running):
            with self.assertRaisesRegex(OSError, 'cannot save running manifest'):
                self.run_campaign()
        self.assertTrue(self.servers[0].started)
        self.assertTrue(self.servers[0].closed)
        self.assertEqual(self.servers[0].channel.fileno(), -1)
        self.assertEqual(self.servers[0].peer.fileno(), -1)
        self.assertEqual(f.read_json(self.root/'campaign.json')['status'], 'failed')
        self.assertEqual({n: signal.getsignal(n) for n in self.handlers}, self.handlers)

    def test_close_before_start_releases_descriptors(self):
        server = t.AttemptServer(self.root)
        self.addCleanup(server.channel.close); self.addCleanup(server.peer.close)
        server.close()
        server.close()
        self.assertEqual(server.channel.fileno(), -1)
        self.assertEqual(server.peer.fileno(), -1)

    def test_partial_signal_setup_is_cleaned_up(self):
        real_signal = signal.signal
        calls = 0
        def fail_second(number, handler):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError('cannot install signal handler')
            return real_signal(number, handler)
        with patch.object(t.signal, 'signal', side_effect=fail_second):
            with self.assertRaisesRegex(OSError, 'cannot install signal handler'):
                self.run_campaign()
        self.assertFalse(self.servers[0].started)
        self.assertTrue(self.servers[0].closed)
        self.assertEqual({n: signal.getsignal(n) for n in self.handlers}, self.handlers)

    def test_failed_warm_worker_launch_closes_log_and_transport(self):
        f.atomic_json(self.root/'campaign.json', {'warm': {'bootstrap_seconds': 10}})
        server = w.WarmAttemptServer(self.root)
        self.addCleanup(server.close)
        with patch.object(w.subprocess, 'Popen', side_effect=OSError('worker launch failed')):
            with self.assertRaisesRegex(OSError, 'worker launch failed'):
                server.start()
        self.assertTrue(server.closed)
        self.assertTrue(server.output.closed)
        self.assertEqual(server.channel.fileno(), -1)
        self.assertEqual(server.peer.fileno(), -1)


if __name__ == '__main__':
    unittest.main()
