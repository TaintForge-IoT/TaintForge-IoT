"""Bounded control-plane liveness under delays observed on the native host."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from taintforge_env import network_runtime as runtime


PROJECT = Path(__file__).resolve().parents[1]


class ControlledLivenessProfileTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.enterContext(patch.object(runtime.NetworkRuntimeOwner, '_heartbeat'))
        self.owner = runtime.NetworkRuntimeOwner(self.root / 'control', self.root / 'logs',
            attempt_id='controlled-profile', heartbeat_profile=runtime.CONTROLLED_HEARTBEAT_PROFILE,
            limits=runtime.NetworkRuntimeLimits.parse({'max_received_bytes': 4, 'max_log_bytes': 4096}))
        self.addCleanup(self.owner.close)
        self.client = runtime.NetworkRuntimeClient(self.owner.client_path)
        self.now = 100.0

    def pulse(self, age):
        path = self.owner.directory / runtime.OWNER_HEARTBEAT_FILE
        value = json.loads(path.read_text())
        value['owner_last_seen'] = self.now - age
        runtime._private_json(path, value, durable=False)

    def clock(self):
        return patch.object(runtime.time, 'monotonic', return_value=self.now)

    def test_controlled_profile_reports_both_finite_deadlines(self):
        self.assertEqual(self.client.descriptor['heartbeat_profile'], 'owner-heartbeat-v2')
        self.assertEqual(self.owner.snapshot()['heartbeat'], {
            'profile': 'owner-heartbeat-v2', 'owner_timeout_seconds': 5, 'peer_timeout_seconds': 5})

    def test_backend_selects_the_controlled_profile_when_it_creates_its_owner(self):
        from tests.test_controlled_network_backend import ControlledNetworkBackendTests
        fixture = ControlledNetworkBackendTests('test_plan_separates_host_and_loopback_services')
        fixture.setUp()
        try:
            with patch('taintforge_env.controlled_network_backend.shutil.which', return_value='/bin/tool'):
                backend = fixture.make_backend()
                try:
                    backend.setup()
                    self.assertEqual(backend.runtime.descriptor['heartbeat_profile'], runtime.CONTROLLED_HEARTBEAT_PROFILE)
                    self.assertEqual(backend.runtime.snapshot()['heartbeat']['peer_timeout_seconds'], 5)
                finally:
                    backend.cleanup()
        finally:
            fixture.tearDown()

    def test_observed_pauses_are_accepted_for_status_and_a_real_quota_transaction(self):
        with self.clock():
            for age in (1.381945692, 1.463815317, 4.999, 5.0):
                self.pulse(age)
                self.assertIsNone(self.client.call('status')['termination_reason'])
                self.client.call('send', size=1)
            self.assertEqual(self.owner.snapshot()['budget_usage']['sent_bytes_reserved'], 4)

    def test_expired_controlled_pulse_blocks_status_and_all_mutations_without_a_write(self):
        self.pulse(5.001)
        before = (self.owner.directory / 'state.json').read_bytes()
        with self.clock(), patch.object(runtime.time, 'sleep'):
            for operation, fields in (('status', {}), ('heartbeat', {}), ('send', {'size': 1}),
                                      ('slot', {'kind': 'tcp'})):
                with self.subTest(operation=operation), self.assertRaises(runtime.NetworkRuntimeError) as caught:
                    self.client.call(operation, **fields)
                self.assertEqual(caught.exception.details['check'], 'owner_heartbeat_stale')
                self.assertEqual(caught.exception.details['timeout_seconds'], 5)
        self.assertEqual((self.owner.directory / 'state.json').read_bytes(), before)

    def test_peer_liveness_uses_the_same_controlled_window(self):
        path = self.owner.directory / 'state.json'
        value = json.loads(path.read_text())
        peer = runtime.proc_self() + 1000
        value['peers'] = {str(peer): [96.0, '100']}
        runtime._private_json(path, value, durable=False)
        with self.clock(), patch.object(runtime, 'process_alive', return_value=True):
            self.owner.check_peers()
            self.assertIsNone(self.owner.snapshot()['termination_reason'])
            value['peers'][str(peer)][0] = 94.999
            runtime._private_json(path, value, durable=False)
            self.owner.check_peers()
            self.assertEqual(self.owner.snapshot()['termination_reason'], 'network_service_heartbeat_lost')

    def test_descriptor_cannot_downgrade_or_remove_the_bound_profile(self):
        original = dict(self.client.descriptor)
        for profile in ('owner-heartbeat-v1', None, 'unknown', []):
            self.client.descriptor = {**original, 'heartbeat_profile': profile}
            with self.subTest(profile=profile), self.assertRaises(runtime.NetworkRuntimeError):
                self.client.call('status')
        self.client.descriptor = {key: value for key, value in original.items() if key != 'heartbeat_profile'}
        with self.assertRaises(runtime.NetworkRuntimeError):
            self.client.call('send', size=1)
        self.client.descriptor = original

    def test_controlled_pulse_must_carry_the_same_profile(self):
        path = self.owner.directory / runtime.OWNER_HEARTBEAT_FILE
        value = json.loads(path.read_text())
        value['heartbeat_profile'] = 'owner-heartbeat-v1'
        runtime._private_json(path, value, durable=False)
        with self.assertRaises(runtime.NetworkRuntimeError) as caught:
            self.client.call('status')
        self.assertEqual(caught.exception.details['check'], 'owner_heartbeat_binding')

    def test_dead_process_is_rejected_without_waiting_for_the_five_second_window(self):
        with patch.object(runtime, 'process_start', return_value=None), patch.object(runtime.time, 'sleep') as sleep:
            with self.assertRaises(runtime.NetworkRuntimeError) as caught:
                self.client.call('status')
            self.assertEqual(caught.exception.details['check'], 'owner_process_identity')
            sleep.assert_not_called()

    def test_quota_failure_is_still_terminal_even_when_the_pulse_recovers(self):
        self.pulse(1.464)
        with self.clock():
            reservation = self.client.call('receive', size=4)
            self.client.call('release', lease=reservation['lease'], used=reservation['size'])
            with self.assertRaisesRegex(runtime.NetworkRuntimeError, 'network_receive_budget_exceeded'):
                self.client.call('receive', size=1)
            self.pulse(0)
            self.assertEqual(self.client.call('status')['termination_reason'], 'network_receive_budget_exceeded')

    def test_legacy_profile_keeps_its_original_one_and_two_second_deadlines(self):
        owner = runtime.NetworkRuntimeOwner(self.root / 'legacy', self.root / 'legacy-logs', attempt_id='legacy')
        try:
            self.assertEqual(owner.descriptor['heartbeat_profile'], 'owner-heartbeat-v1')
            self.assertEqual(runtime.OWNER_HEARTBEAT_PROFILES['owner-heartbeat-v1'], (1, 2))
            self.assertNotIn('heartbeat_profile', json.loads((owner.directory / 'state.json').read_text()))
            pulse = json.loads((owner.directory / runtime.OWNER_HEARTBEAT_FILE).read_text())
            pulse['owner_last_seen'] = self.now - 1.01
            runtime._private_json(owner.directory / runtime.OWNER_HEARTBEAT_FILE, pulse, durable=False)
            with self.clock(), patch.object(runtime.time, 'sleep'):
                with self.assertRaises(runtime.NetworkRuntimeError) as caught:
                    runtime.NetworkRuntimeClient(owner.client_path).call('status')
            self.assertEqual(caught.exception.details['timeout_seconds'], 1)
        finally:
            owner.close()

    def test_unknown_profile_is_rejected_before_creating_the_ledger(self):
        for number, profile in enumerate(('unknown', None, [], False)):
            directory = self.root / f'invalid-{number}'
            with self.subTest(profile=profile), self.assertRaises(ValueError):
                runtime.NetworkRuntimeOwner(directory, self.root / 'invalid-logs', attempt_id='invalid',
                                            heartbeat_profile=profile)
            self.assertFalse(directory.exists())


class LiveControlledLivenessTests(unittest.TestCase):
    def test_live_health_pause_observed_in_the_archive_can_recover(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            entered, release = threading.Event(), threading.Event()
            owner = runtime.NetworkRuntimeOwner(root / 'control', root / 'logs', attempt_id='live-pause',
                                                heartbeat_profile=runtime.CONTROLLED_HEARTBEAT_PROFILE)
            def delayed_health():
                entered.set()
                release.wait(4)
            owner.health_check = delayed_health
            try:
                self.assertTrue(entered.wait(2))
                time.sleep(1.5)
                self.assertIsNone(runtime.NetworkRuntimeClient(owner.client_path).call('status')['termination_reason'])
            finally:
                release.set()
                result = owner.close()
            self.assertEqual(result['cleanup_status'], 'cleaned')

    def test_guard_stops_a_real_child_after_its_controlled_owner_dies(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            control, logs = root / 'control', root / 'logs'
            owner_code = ('from taintforge_env.network_runtime import NetworkRuntimeOwner,NetworkRuntimeLimits;'
                'import time;NetworkRuntimeOwner(' + repr(str(control)) + ',' + repr(str(logs)) +
                ',attempt_id="controlled-death",heartbeat_profile="owner-heartbeat-v2",'
                'limits=NetworkRuntimeLimits(shutdown_timeout_ms=500));time.sleep(60)')
            env = {**os.environ, 'PYTHONPATH': str(PROJECT)}
            owner = subprocess.Popen([sys.executable, '-B', '-c', owner_code], cwd=PROJECT, env=env)
            guard = None
            try:
                deadline = time.monotonic() + 3
                while not (control / 'client.json').exists():
                    self.assertLess(time.monotonic(), deadline)
                    time.sleep(.01)
                ready, result = root / 'ready', root / 'result.json'
                child = ('from pathlib import Path;import time;Path(' + repr(str(ready)) +
                         ').write_text("ready");time.sleep(60)')
                guard = subprocess.Popen([sys.executable, '-B', str(PROJECT / 'scripts/run_network_guard.py'),
                    '--runtime', str(control / 'client.json'), '--result', str(result), '--',
                    sys.executable, '-B', '-c', child], cwd=PROJECT, env=env)
                while not ready.exists():
                    self.assertLess(time.monotonic(), deadline)
                    time.sleep(.01)
                owner.kill()
                owner.wait(timeout=2)
                self.assertNotEqual(guard.wait(timeout=3), 0)
                saved = json.loads(result.read_text())
                self.assertTrue(saved['guest_process_stopped'])
                self.assertEqual(saved['runtime_error']['details']['check'], 'owner_process_identity')
            finally:
                if owner.poll() is None:
                    owner.kill()
                    owner.wait(timeout=2)
                if guard is not None and guard.poll() is None:
                    guard.terminate()
                    guard.wait(timeout=3)
