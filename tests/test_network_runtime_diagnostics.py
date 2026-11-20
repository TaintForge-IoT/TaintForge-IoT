"""Preserve the specific failed owner check through guard and capsule shutdown."""
import errno
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from scripts import run_network_guard
from taintforge_env import network_capsule as capsule
from taintforge_env import network_runtime as runtime
from tests import test_network_capsule as fixtures


class RuntimeDiagnosticsTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.enterContext(patch.object(runtime.NetworkRuntimeOwner, '_heartbeat'))
        self.owner = runtime.NetworkRuntimeOwner(self.root / 'control', self.root / 'logs', attempt_id='diagnostics')
        self.addCleanup(self.owner.close)
        self.client = runtime.NetworkRuntimeClient(self.owner.client_path)

    def stale_pulse(self):
        path = self.owner.directory / runtime.OWNER_HEARTBEAT_FILE
        value = json.loads(path.read_text())
        value['owner_last_seen'] = time.monotonic() - 2
        runtime._private_json(path, value, durable=False)
        return path

    def test_stale_heartbeat_is_distinguished_from_a_dead_process(self):
        self.stale_pulse()
        self.assertTrue(runtime.process_alive(self.owner.descriptor['owner_pid'], self.owner.descriptor['owner_start']))
        with self.assertRaises(runtime.NetworkRuntimeError) as caught:
            self.client.call('status')
        detail = caught.exception.details
        self.assertEqual(str(caught.exception), 'network_runtime_owner_lost')
        self.assertEqual(detail['check'], 'owner_heartbeat_stale')
        self.assertGreaterEqual(detail['age_seconds'], 2)
        self.assertEqual(detail['timeout_seconds'], 1)
        self.assertEqual(detail['operation'], 'status')
        self.assertNotIn(self.owner.token, json.dumps(detail))

    def test_identity_mismatch_retains_the_expected_and_observed_start(self):
        self.client.descriptor = {**self.client.descriptor, 'owner_start': '0'}
        with self.assertRaises(runtime.NetworkRuntimeError) as caught:
            self.client.call('status')
        detail = caught.exception.details
        self.assertEqual(detail['check'], 'owner_process_identity')
        self.assertEqual(detail['owner_pid'], self.owner.descriptor['owner_pid'])
        self.assertEqual(detail['expected_start'], '0')
        self.assertEqual(detail['observed_start'], self.owner.descriptor['owner_start'])
        self.assertEqual(detail['caller_uid'], os.geteuid())

    def test_read_failure_preserves_errno_and_the_failing_path(self):
        path = self.owner.directory / 'state.json'
        original = runtime._regular

        def read(selected, maximum=16384):
            if Path(selected) == path:
                raise PermissionError(errno.EACCES, 'private state', str(path))
            return original(selected, maximum)

        with patch.object(runtime, '_regular', side_effect=read):
            with self.assertRaises(runtime.NetworkRuntimeError) as caught:
                self.client.call('status')
        detail = caught.exception.details
        self.assertEqual(detail['check'], 'ledger_io')
        self.assertEqual(detail['exception_type'], 'PermissionError')
        self.assertEqual(detail['errno'], errno.EACCES)
        self.assertEqual(detail['path'], str(path))

    def test_invalid_json_is_identified_without_copying_the_ledger(self):
        path = self.owner.directory / 'state.json'
        before = path.read_bytes()
        path.write_text('{"broken":')
        try:
            with self.assertRaises(runtime.NetworkRuntimeError) as caught:
                self.client.call('status')
        finally:
            path.write_bytes(before)
        detail = caught.exception.details
        self.assertEqual(detail['check'], 'ledger_data')
        self.assertEqual(detail['exception_type'], 'JSONDecodeError')
        self.assertNotIn(self.owner.token, json.dumps(detail))

    def test_write_lock_deadline_retains_the_specific_failure_and_wait(self):
        with patch.object(runtime.fcntl, 'flock', side_effect=BlockingIOError), \
             patch.object(runtime.time, 'monotonic', side_effect=[100, 101, 101]):
            with self.assertRaises(runtime.NetworkRuntimeError) as caught:
                self.client.call('send', size=1)
        detail = caught.exception.details
        self.assertEqual(str(caught.exception), 'network_runtime_lock_timeout')
        self.assertEqual(detail['check'], 'ledger_lock_timeout')
        self.assertEqual(detail['wait_seconds'], 1)
        self.assertEqual(detail['timeout_seconds'], 0.5)
        self.assertEqual(detail['operation'], 'send')

    def test_health_reads_do_not_wait_for_a_held_writer_lock(self):
        path = self.owner.directory / 'state.json'
        before = path.read_bytes(), path.stat().st_ino, path.stat().st_mtime_ns
        with runtime.ledger_lock(self.owner.directory):
            try:
                status = self.client.call('status')
                owned = self.owner.snapshot()
                self.owner.check_peers()
            except runtime.NetworkRuntimeError as exc:
                self.fail('read-only health check waited for the writer lock: ' + str(exc))
        self.assertIsNone(status['termination_reason'])
        self.assertEqual(status, owned)
        self.assertEqual((path.read_bytes(), path.stat().st_ino, path.stat().st_mtime_ns), before)

    def test_status_reads_old_commit_until_atomic_publication_then_new_commit(self):
        path = self.owner.directory / 'state.json'
        before = path.read_bytes()
        publishing, release = threading.Event(), threading.Event()
        errors = []
        replace = runtime.os.replace

        def paused_replace(source, destination):
            if Path(destination) == path:
                publishing.set()
                if not release.wait(3):
                    raise RuntimeError('test did not release publication')
            return replace(source, destination)

        def writer():
            try:
                self.client.call('send', size=7)
            except Exception as exc:
                errors.append(exc)

        with patch.object(runtime.os, 'replace', side_effect=paused_replace):
            worker = threading.Thread(target=writer)
            worker.start()
            try:
                self.assertTrue(publishing.wait(3))
                self.assertEqual(self.client.call('status')['budget_usage']['sent_bytes_reserved'], 0)
                self.assertEqual(path.read_bytes(), before)
                self.assertTrue(worker.is_alive())
            finally:
                release.set()
                worker.join(3)
        self.assertFalse(worker.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(self.client.call('status')['budget_usage']['sent_bytes_reserved'], 7)

    def test_status_checks_attempt_token_and_limits_without_mutating_state(self):
        path = self.owner.directory / 'state.json'
        before = path.read_bytes()
        original = self.client.descriptor
        changed_limits = {**original['limits'], 'max_sent_bytes': original['limits']['max_sent_bytes'] + 1}
        alterations = ({'token': '0' * 64}, {'attempt_id': 'foreign'}, {'limits': changed_limits})
        try:
            for change in alterations:
                with self.subTest(change=list(change)), runtime.ledger_lock(self.owner.directory):
                    self.client.descriptor = {**original, **change}
                    with self.assertRaises(runtime.NetworkRuntimeError):
                        self.client.call('status')
                    self.assertEqual(path.read_bytes(), before)
        finally:
            self.client.descriptor = original

    def test_stale_status_still_fails_when_a_writer_holds_the_lock(self):
        self.stale_pulse()
        with runtime.ledger_lock(self.owner.directory), self.assertRaises(runtime.NetworkRuntimeError) as caught:
            self.client.call('status')
        self.assertEqual(caught.exception.details['check'], 'owner_heartbeat_stale')

    def test_committed_terminal_reason_is_visible_while_writer_lock_is_held(self):
        self.owner.fail('network_receive_budget_exceeded')
        with runtime.ledger_lock(self.owner.directory):
            status = self.client.call('status')
        self.assertEqual(status['termination_reason'], 'network_receive_budget_exceeded')
        self.assertFalse(status['evidence_complete'])

    def test_concurrent_budget_writers_remain_serialized_during_status_reads(self):
        owner = runtime.NetworkRuntimeOwner(self.root / 'concurrent', self.root / 'concurrent-logs',
            attempt_id='concurrent', limits=runtime.NetworkRuntimeLimits(max_sent_bytes=6))
        self.addCleanup(owner.close)
        client = runtime.NetworkRuntimeClient(owner.client_path)
        path = owner.directory / 'state.json'
        publishing, blocked, release = (threading.Event() for _ in range(3))
        outcomes = []
        replace, flock = runtime.os.replace, runtime.fcntl.flock

        def paused_replace(source, destination):
            if Path(destination) == path and threading.current_thread().name == 'first-writer':
                publishing.set()
                if not release.wait(3):
                    raise RuntimeError('test did not release first writer')
            return replace(source, destination)

        def observed_lock(fd, operation):
            try:
                return flock(fd, operation)
            except BlockingIOError:
                if threading.current_thread().name == 'second-writer':
                    blocked.set()
                raise

        def writer():
            try:
                client.call('send', size=4)
                outcomes.append('reserved')
            except runtime.NetworkRuntimeError as exc:
                outcomes.append(str(exc))

        workers = [threading.Thread(target=writer, name=name) for name in ('first-writer', 'second-writer')]
        with patch.object(runtime.os, 'replace', side_effect=paused_replace), \
             patch.object(runtime.fcntl, 'flock', side_effect=observed_lock):
            workers[0].start()
            try:
                self.assertTrue(publishing.wait(3))
                workers[1].start()
                self.assertTrue(blocked.wait(3), 'second mutation bypassed the writer lock')
                self.assertEqual(client.call('status')['budget_usage']['sent_bytes_reserved'], 0)
            finally:
                release.set()
                for worker in workers:
                    if worker.ident is not None:
                        worker.join(3)
        self.assertTrue(all(not worker.is_alive() for worker in workers))
        self.assertCountEqual(outcomes, ['reserved', 'network_send_budget_exceeded'])
        status = client.call('status')
        self.assertEqual(status['budget_usage']['sent_bytes_reserved'], 4)
        self.assertEqual(status['termination_reason'], 'network_send_budget_exceeded')


    def test_fresh_pulse_admits_work_without_refreshing_an_old_ledger_tick(self):
        path = self.owner.directory / 'state.json'
        state = json.loads(path.read_text())
        state['owner_last_seen'] = time.monotonic() - 3
        runtime._private_json(path, state, durable=False)
        pulse = self.owner.directory / runtime.OWNER_HEARTBEAT_FILE
        before = pulse.read_bytes()
        self.client.call('heartbeat')
        self.client.call('send', size=1)
        self.assertEqual(self.client.call('status')['budget_usage']['sent_bytes_reserved'], 1)
        self.assertEqual(pulse.read_bytes(), before)
        self.assertEqual(json.loads(path.read_text())['owner_last_seen'], state['owner_last_seen'])

    def test_fresh_ledger_does_not_hide_a_stale_owner_pulse(self):
        pulse = self.stale_pulse()
        state = self.owner.directory / 'state.json'
        before = state.read_bytes(), pulse.read_bytes()
        for operation, fields in (('status', {}), ('heartbeat', {}), ('send', {'size': 1})):
            with self.subTest(operation=operation), self.assertRaises(runtime.NetworkRuntimeError) as caught:
                self.client.call(operation, **fields)
            self.assertEqual(caught.exception.details['check'], 'owner_heartbeat_stale')
            self.assertEqual((state.read_bytes(), pulse.read_bytes()), before)

    def test_stale_pulse_allows_only_failure_to_commit_and_first_reason_wins(self):
        pulse = self.stale_pulse()
        before = pulse.read_bytes()
        usage = self.owner.snapshot()['budget_usage']
        self.client.fail('network_runtime_owner_lost')
        self.client.fail('network_capsule_timeout')
        status = self.client.call('status')
        self.assertEqual(status['termination_reason'], 'network_runtime_owner_lost')
        self.assertFalse(status['evidence_complete'])
        self.assertEqual(pulse.read_bytes(), before)
        with self.assertRaises(runtime.NetworkRuntimeError):
            self.client.call('send', size=1)
        self.assertEqual(self.owner.snapshot()['budget_usage'], usage)
        pulse.unlink()
        self.assertEqual(self.client.call('status')['termination_reason'], 'network_runtime_owner_lost')
        final = self.owner.close()
        self.assertEqual(final['termination_reason'], 'network_runtime_owner_lost')
        self.assertEqual(final['cleanup_status'], 'cleaned')
        self.assertFalse(self.owner.directory.exists())

    def test_stale_failure_still_checks_the_owner_and_attempt_identity(self):
        self.stale_pulse()
        original = self.client.descriptor
        changed_limits = {**original['limits'], 'max_sent_bytes': original['limits']['max_sent_bytes'] + 1}
        try:
            for change in ({'token': '0' * 64}, {'attempt_id': 'foreign'}, {'owner_start': '0'},
                           {'limits': changed_limits}):
                with self.subTest(change=list(change)):
                    self.client.descriptor = {**original, **change}
                    with self.assertRaises(runtime.NetworkRuntimeError):
                        self.client.call('fail', reason='network_runtime_owner_lost')
                    self.assertIsNone(self.owner.snapshot()['termination_reason'])
        finally:
            self.client.descriptor = original

    def test_owner_pulse_cannot_be_reused_from_another_runtime(self):
        path = self.owner.directory / runtime.OWNER_HEARTBEAT_FILE
        original = json.loads(path.read_text())
        for field, replacement in (('owner_pid', original['owner_pid'] + 1), ('owner_start', '0'),
                                   ('token', '0' * 64), ('attempt_id', 'foreign'),
                                   ('limits_sha256', '0' * 64)):
            with self.subTest(field=field):
                runtime._private_json(path, {**original, field: replacement}, durable=False)
                with self.assertRaises(runtime.NetworkRuntimeError) as caught:
                    self.client.call('status')
                self.assertEqual(caught.exception.details['check'], 'owner_heartbeat_binding')
                self.assertNotIn(self.owner.token, json.dumps(caught.exception.details))
        runtime._private_json(path, original, durable=False)

    def test_invalid_pulse_is_rejected_without_authorizing_budget_work(self):
        path = self.owner.directory / runtime.OWNER_HEARTBEAT_FILE
        original = path.read_bytes()
        value = json.loads(original)
        invalid = [b'{"broken":', b'x' * 16385, b'[]']
        invalid.extend(json.dumps({**value, 'owner_last_seen': item}).encode()
                       for item in (None, True, 'now', float('nan'), float('inf'), 10**400,
                                    -1, time.monotonic() + 3600))
        before = self.owner.snapshot()['budget_usage']
        for index, data in enumerate(invalid):
            with self.subTest(index=index):
                path.write_bytes(data)
                with self.assertRaises(runtime.NetworkRuntimeError):
                    self.client.call('send', size=1)
                self.assertEqual(self.owner.snapshot()['budget_usage'], before)
        path.write_bytes(original)

    def test_pulse_must_remain_a_regular_file(self):
        path = self.owner.directory / runtime.OWNER_HEARTBEAT_FILE
        original = path.read_bytes()
        copy = self.root / 'pulse-copy.json'
        copy.write_bytes(original)
        for kind in ('missing', 'symlink', 'fifo'):
            with self.subTest(kind=kind):
                path.unlink(missing_ok=True)
                if kind == 'symlink':
                    path.symlink_to(copy)
                elif kind == 'fifo':
                    os.mkfifo(path)
                with self.assertRaises(runtime.NetworkRuntimeError):
                    self.client.call('status')
        path.unlink()
        path.write_bytes(original)

    def test_pulse_permissions_are_private_and_the_profile_is_explicit(self):
        path = self.owner.directory / runtime.OWNER_HEARTBEAT_FILE
        info = path.stat()
        self.assertEqual((info.st_uid, info.st_gid), (os.geteuid(), os.getegid()))
        self.assertEqual(stat.S_IMODE(info.st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.owner.directory.stat().st_mode), 0o700)
        self.assertEqual(self.client.descriptor['heartbeat_profile'], runtime.OWNER_HEARTBEAT_PROFILE)
        descriptor = self.root / 'unknown-profile.json'
        runtime._private_json(descriptor, {**self.client.descriptor, 'heartbeat_profile': 'unknown'})
        with self.assertRaisesRegex(runtime.NetworkRuntimeError, 'unsupported network owner heartbeat profile'):
            runtime.NetworkRuntimeClient(descriptor)

    def test_a_descheduled_reader_rechecks_the_latest_pulse_once(self):
        path = self.owner.directory / runtime.OWNER_HEARTBEAT_FILE
        fresh = path.read_bytes()
        stale = json.loads(fresh)
        stale['owner_last_seen'] = time.monotonic() - 2
        stale = json.dumps(stale).encode()
        read = runtime._regular
        observations = []

        def delayed_read(selected, maximum=16384):
            if Path(selected) == path:
                observations.append(True)
                return stale if len(observations) == 1 else fresh
            return read(selected, maximum)

        with patch.object(runtime, '_regular', side_effect=delayed_read):
            self.assertIsNone(self.client.call('status')['termination_reason'])
        self.assertEqual(len(observations), 2)

    def test_legacy_descriptor_keeps_its_ledger_freshness_check(self):
        descriptor = self.root / 'legacy.json'
        value = dict(self.client.descriptor)
        value.pop('heartbeat_profile')
        runtime._private_json(descriptor, value)
        client = runtime.NetworkRuntimeClient(descriptor)
        self.assertIsNone(client.call('status')['termination_reason'])
        path = self.owner.directory / 'state.json'
        state = json.loads(path.read_text())
        state['owner_last_seen'] = time.monotonic() - 2
        runtime._private_json(path, state, durable=False)
        with self.assertRaises(runtime.NetworkRuntimeError) as caught:
            client.call('status')
        self.assertEqual(caught.exception.details['check'], 'owner_heartbeat_stale')

    def test_guard_commits_real_stale_owner_failure_after_stopping_its_child(self):
        self.stale_pulse()
        result_path = self.root / 'guard.json'
        code = run_network_guard.run(self.owner.client_path,
            [sys.executable, '-c', 'import time; time.sleep(60)'], result_path=result_path)
        self.assertNotEqual(code, 0)
        result = json.loads(result_path.read_text())
        self.assertTrue(result['guest_process_stopped'])
        self.assertEqual(result['runtime_error']['details']['check'], 'owner_heartbeat_stale')
        final = self.owner.close()
        self.assertEqual(result['termination_reason'], 'network_runtime_owner_lost')
        self.assertEqual(final['termination_reason'], result['termination_reason'])


class OwnerHeartbeatLoopTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        self.owner = runtime.NetworkRuntimeOwner(root / 'control', root / 'logs', attempt_id='heartbeat-loop')
        self.addCleanup(self.owner.close)
        self.client = runtime.NetworkRuntimeClient(self.owner.client_path)

    def test_live_health_loop_publishes_while_a_real_quota_writer_holds_the_lock(self):
        path = self.owner.directory / 'state.json'
        pulse = self.owner.directory / runtime.OWNER_HEARTBEAT_FILE
        before = path.read_bytes()
        first = json.loads(pulse.read_text())['owner_last_seen']
        checked = threading.Event()
        self.owner.health_check = checked.set
        with runtime.ledger_lock(self.owner.directory):
            self.assertTrue(checked.wait(2))
            deadline = time.monotonic() + 1.15
            while time.monotonic() < deadline:
                self.assertIsNone(self.client.call('status')['termination_reason'])
                time.sleep(0.025)
            self.assertEqual(path.read_bytes(), before)
            self.assertGreater(json.loads(pulse.read_text())['owner_last_seen'] - first, 1)
            self.assertTrue(self.owner.thread.is_alive())
        self.client.call('send', size=1)
        self.assertEqual(self.client.call('status')['budget_usage']['sent_bytes_reserved'], 1)

    def test_a_stalled_health_check_still_stales_the_owner_pulse(self):
        entered, release = threading.Event(), threading.Event()

        def stalled_health():
            entered.set()
            release.wait(3)

        self.owner.health_check = stalled_health
        try:
            self.assertTrue(entered.wait(2))
            path = self.owner.directory / runtime.OWNER_HEARTBEAT_FILE
            before = path.read_bytes()
            time.sleep(1.1)
            with self.assertRaises(runtime.NetworkRuntimeError) as caught:
                self.client.call('status')
            self.assertEqual(caught.exception.details['check'], 'owner_heartbeat_stale')
            self.assertEqual(caught.exception.details['timeout_seconds'], 1)
            self.assertEqual(path.read_bytes(), before)
        finally:
            release.set()


class CapsuleDiagnosticsTests(unittest.TestCase):
    setUp = fixtures.NetworkCapsuleContractTests.setUp
    bind = fixtures.NetworkCapsuleContractTests.bind

    def failure(self):
        return runtime.NetworkRuntimeError('network_runtime_owner_lost', details={
            'check': 'owner_heartbeat_stale', 'age_seconds': 1.2, 'timeout_seconds': 1,
        })

    def test_supervisor_failure_keeps_the_original_runtime_check(self):
        self.bind()
        monitor = capsule.Monitor(self.binding)
        error = self.failure()
        with patch.object(monitor.client, 'call', side_effect=error):
            with self.assertRaises(capsule.NetworkCapsuleStopped) as caught:
                monitor.check()
        recorded = caught.exception.failure['runtime_error']
        self.assertEqual(recorded, {'error': str(error), 'details': error.details})

    def test_capsule_status_poll_does_not_treat_writer_contention_as_owner_loss(self):
        self.bind()
        monitor = capsule.Monitor(self.binding)
        monitor.arm()
        with runtime.ledger_lock(self.owner.directory):
            monitor.check()
        self.assertIsNone(self.owner.snapshot()['termination_reason'])
        self.assertFalse((self.root / 'logs/capsule/network_cancel.json').exists())

    def test_supervisor_commits_a_real_stale_pulse_failure_without_claiming_retirement(self):
        self.bind()
        monitor = capsule.Monitor(self.binding)
        self.owner.stop_event.set()
        self.owner.thread.join(2)
        self.assertFalse(self.owner.thread.is_alive())
        path = self.owner.directory / runtime.OWNER_HEARTBEAT_FILE
        value = json.loads(path.read_text())
        value['owner_last_seen'] = time.monotonic() - 2
        runtime._private_json(path, value, durable=False)
        with self.assertRaises(capsule.NetworkCapsuleStopped) as caught:
            monitor.check()
        self.assertEqual(caught.exception.failure['runtime_error']['details']['check'], 'owner_heartbeat_stale')
        self.assertEqual(self.owner.snapshot()['termination_reason'], 'network_runtime_owner_lost')
        self.assertNotIn('phase1_retired', caught.exception.failure)

    def test_guard_result_and_cooperative_cancellation_retain_the_cause(self):
        self.bind()
        result_path = self.root / 'guard.json'
        copied = self.root / 'cancel-copy.json'
        cancel = self.root / 'logs/capsule/network_cancel.json'
        script = '''import sys
import time
from pathlib import Path
source = Path(sys.argv[1])
while not source.exists():
    time.sleep(0.005)
Path(sys.argv[2]).write_text(source.read_text())
raise SystemExit(14)
'''
        client = runtime.NetworkRuntimeClient(self.owner.client_path)
        error = self.failure()
        with patch.object(run_network_guard, 'NetworkRuntimeClient', return_value=client), \
             patch.object(client, 'call', side_effect=error):
            code = run_network_guard.run(self.owner.client_path,
                [sys.executable, '-c', script, str(cancel), str(copied)],
                result_path=result_path, capsule_binding=self.root / 'config/capsule_binding.json')
        self.assertEqual(code, 14)
        expected = {'error': str(error), 'details': error.details}
        self.assertEqual(json.loads(copied.read_text())['runtime_error'], expected)
        result = json.loads(result_path.read_text())
        self.assertTrue(result['guest_process_stopped'])
        self.assertEqual(result['runtime_error'], expected)


if __name__ == '__main__':
    unittest.main()
