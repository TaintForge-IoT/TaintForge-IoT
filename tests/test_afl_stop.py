"""Real signals and FD transport for draining; native M4 acceptance is separate."""
import contextlib
import io
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from taintforge_env import afl_file as f, afl_stop as stop, afl_transport as transport
from taintforge_env import afl_storage as storage, afl_phase2 as phase2, afl_continue as continuation
from taintforge_env.afl_evidence import reusable
from tests import test_afl_continue as previous


class StopStateTests(unittest.TestCase):
    def setUp(self):
        self.server = SimpleNamespace(graceful_stop=threading.Event(), stop=threading.Event(),
            active_attempt=threading.Event(), executed=1, completed=0, errors=[],
            phase2=SimpleNamespace(submitted=1, completed=0, errors=[]))
        self.process = SimpleNamespace(pid=123456, poll=lambda: None)
        self.request = stop.StopRequest(self.server, 1)

    def test_first_signal_stops_admission_without_cancelling_accepted_work(self):
        self.request.request(int(signal.SIGINT))
        self.assertTrue(self.server.graceful_stop.is_set())
        self.assertFalse(self.server.stop.is_set())
        with patch.object(stop.os, 'killpg') as kill:
            self.request.poll(self.process)
        kill.assert_not_called()

    def test_afl_is_stopped_only_after_delivery_and_phase2_complete(self):
        self.request.request(int(signal.SIGTERM))
        self.server.completed = 1
        with patch.object(stop.os, 'killpg') as kill:
            self.request.poll(self.process)
            kill.assert_not_called()
            self.server.phase2.completed = 1
            self.server.active_attempt.set()
            self.request.poll(self.process)
            kill.assert_not_called()
            self.server.active_attempt.clear()
            self.request.poll(self.process)
            self.request.poll(self.process)
        kill.assert_called_once_with(self.process.pid, signal.SIGINT)
        self.assertIsNotNone(self.request.drained_ns)

    def test_second_signal_forces_cleanup(self):
        self.request.request(int(signal.SIGINT))
        self.request.request(int(signal.SIGINT))
        with patch.object(stop.os, 'killpg') as kill:
            self.request.poll(self.process)
        kill.assert_called_once_with(self.process.pid, signal.SIGKILL)
        self.assertTrue(self.server.stop.is_set())
        self.assertTrue(self.request.forced)

    def test_expired_budget_does_not_become_success_when_work_finishes_late(self):
        self.request.request(int(signal.SIGINT))
        self.request.requested_ns -= 2*10**9
        self.server.completed = self.server.phase2.completed = 1
        with patch.object(stop.os, 'killpg') as kill:
            self.request.poll(self.process)
        self.assertTrue(self.request.timed_out)
        self.assertIsNone(self.request.drained_ns)
        kill.assert_called_once_with(self.process.pid, signal.SIGKILL)

    def test_reaped_process_is_never_signalled_by_a_reused_pid(self):
        self.request.request(int(signal.SIGINT))
        self.server.completed = self.server.phase2.completed = 1
        self.process.poll = lambda: 0
        with patch.object(stop.os, 'killpg') as kill:
            self.request.finish_wait(self.process)
        kill.assert_not_called()

    def test_invalid_timeout_is_rejected(self):
        for value in (True, 0, -1, 601, 1.5):
            with self.subTest(value=value), self.assertRaises(RuntimeError):
                stop.StopRequest(self.server, value)

    def test_analysis_failure_does_not_wait_for_the_drain_deadline(self):
        self.request.request(int(signal.SIGINT))
        self.server.phase2.errors.append('analysis failed')
        with patch.object(stop.os, 'killpg') as kill:
            self.request.finish_wait(self.process)
        self.assertTrue(self.request.work_failed)
        self.assertFalse(self.request.timed_out)
        self.assertIsNone(self.request.drained_ns)
        kill.assert_called_once_with(self.process.pid, signal.SIGKILL)


class ReceiptTests(unittest.TestCase):
    def setUp(self):
        self.fixture = previous.ContinuationTests('test_prepare_only_never_starts_a_worker')
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.source, self.root = self.fixture.source, self.fixture.root
        value = f.read_json(self.source/'campaign.json')
        policy = storage.policy()
        storage.bind(value, policy)
        budget = storage.Budget(self.source, policy)
        self.addCleanup(budget.release_reserve)
        value.update(status='interrupted', afl_exit=0,
                     phase2=f.read_json(self.source/'phase2-progress.json'), storage_result=budget.report())
        request = stop.StopRequest(SimpleNamespace(graceful_stop=threading.Event()))
        request.request(int(signal.SIGINT))
        request.drained_ns = request.requested_ns
        request.save(self.source, value)
        f.atomic_json(self.source/'campaign.json', value)
        self.manifest = value

    def test_verified_interrupt_can_continue_and_retains_receipt_identity(self):
        self.assertTrue(reusable(self.manifest))
        stop.verify_receipt(self.source, self.manifest)
        out = self.root/'continued-interrupt'
        value = continuation.prepare_continuation(self.source, out)
        self.assertEqual(value['status'], 'prepared')
        self.assertEqual(value['assets'][str(self.source/'interruption.json')], self.manifest['interruption_sha256'])
        self.assertIn('interruption.json', f.read_json(out/'continuation.json')['source_evidence_sha256'])

    def test_changed_receipt_or_finalization_evidence_is_refused_before_copy(self):
        path = self.source/'interruption.json'
        original = path.read_bytes()
        path.write_text('{}')
        with self.assertRaisesRegex(RuntimeError, 'receipt changed'):
            continuation.prepare_continuation(self.source, self.root/'changed-receipt')
        path.write_bytes(original)
        f.atomic_json(self.source/'warm-executor.json', {'status': 'passed', 'children': 999})
        with self.assertRaisesRegex(RuntimeError, 'evidence changed'):
            continuation.prepare_continuation(self.source, self.root/'changed-evidence')

    def test_forced_timeout_error_and_pending_work_cannot_be_reused(self):
        import copy
        for key, value in (('forced', True), ('timed_out', True), ('status', 'incomplete'),
                           ('signals', [2, 2]), ('signals', [2.0]), ('delivered_cases', 0),
                           ('phase2_completed', True), ('drained_ns', None)):
            with self.subTest(key=key, value=value):
                manifest = copy.deepcopy(self.manifest)
                manifest['interruption'][key] = value
                self.assertFalse(reusable(manifest))
        for updates in ({'evidence_complete': False}, {'cleanup_error': 'failed'},
                        {'executor_errors': ['lost']}, {'afl_exit': 86}):
            self.assertFalse(reusable(self.manifest | updates))

    def test_clone_and_replay_cannot_bypass_receipt_verification(self):
        from taintforge_env.afl_replay import clone_campaign
        (self.source/'interruption.json').write_text('{}')
        with self.assertRaisesRegex(RuntimeError, 'receipt changed'):
            clone_campaign(self.source, self.root/'bypass')
        self.assertFalse((self.root/'bypass').exists())

    def test_zero_case_stop_uses_bound_seeds_before_afl_dry_run(self):
        import shutil
        shutil.rmtree(self.source/'cases')
        self.fixture.fixture.closed(self.source)
        value = f.read_json(self.source/'campaign.json')
        value['phase2'] = f.read_json(self.source/'phase2-progress.json')
        request = stop.StopRequest(SimpleNamespace(graceful_stop=threading.Event()))
        request.request(int(signal.SIGTERM))
        request.drained_ns = request.requested_ns
        request.save(self.source, value)
        f.atomic_json(self.source/'campaign.json', value)
        for queue_exists in (True, False):
            if not queue_exists:
                shutil.rmtree(self.source/'afl/default/queue')
            out = self.root/('zero-case-'+str(queue_exists))
            continuation.prepare_continuation(self.source, out)
            self.assertEqual({p.read_bytes() for p in (out/'seeds').iterdir()}, {b'A', b'B'})


DRIVER = r'''
import array, os, signal, socket, struct, sys
signal.signal(signal.SIGINT, lambda *_: sys.exit(0))
control = socket.socket(fileno=int(sys.argv[-2]))
for _ in range(10000):
    child, peer = socket.socketpair()
    control.sendmsg([b'C'], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [peer.fileno()]))])
    peer.close()
    child.sendall(struct.pack('!I', 1)+b'A')
    result = b''
    while len(result) < 16:
        chunk = child.recv(16-len(result))
        if not chunk: raise SystemExit(86)
        result += chunk
    child.close()
'''


class SignalTransportTests(unittest.TestCase):
    def invoke(self, mode, number, point='child', force=False, expire=False):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        binary = root/'afl-fuzz'
        binary.write_text('#!'+sys.executable+'\n'+DRIVER)
        binary.chmod(0o700)
        child_started, analysis_started = threading.Event(), threading.Event()
        cleanup_started, release_cleanup = threading.Event(), threading.Event()
        release_child, release_analysis, interrupter_done = threading.Event(), threading.Event(), threading.Event()
        servers, thread_errors = [], []
        if point == 'cleanup':
            binary.write_text('#!'+sys.executable+'\n'+DRIVER.replace('range(10000)', 'range(1)'))
            release_child.set()
            release_analysis.set()
        config = phase2.settings(mode, 2)
        manifest = {'status': 'prepared', 'max_input': 4096, 'launch': {'timeout_seconds': 1},
            'build': {'bridge': '/bin/true'}, 'warm': {'campaign_seconds': 20, 'timeout_ms': 100,
            'capsule_profile': 'warm-m5-capsule-v1', 'phase2': config}}

        class Server(transport.AttemptServer):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                servers.append(self)
                def analyze(case, config):
                    analysis_started.set()
                    if not release_analysis.wait(5):
                        raise RuntimeError('Test analysis release timed out')
                    f.atomic_json(case/'analyzed.json', {'status': 'passed'})
                self.phase2 = phase2.Processor(root, config, process=analyze, on_complete=self.storage.complete)

            def start(self):
                f.atomic_json(root/'warm-ready.json', {'status': 'ready', 'run_dir': str(root)})
                self.phase2.start()
                super().start()

            def execute(self, connection):
                transport.recv_exact(connection, 5)
                self.admit_case(self.executed)
                index = self.executed
                self.executed += 1
                case = root/'cases'/f'{index:08d}'
                case.mkdir()
                (case/'input').write_bytes(b'A')
                child_started.set()
                while not release_child.wait(.02):
                    if self.stop.is_set():
                        raise ConnectionError('Forced test child stop')
                f.atomic_json(case/'result.json', {'status': 'passed'})
                self.phase2.submit(case)
                connection.sendall(bytes(16))
                self.completed += 1
                f.atomic_json(case/'transport.json', {'status': 'delivered'})

            def close(self):
                super().close()
                if point == 'cleanup':
                    cleanup_started.set()
                    if not release_cleanup.wait(5):
                        raise RuntimeError('Test cleanup release timed out')
                self.phase2.close()
                f.atomic_json(root/'warm-executor.json', {'status': 'passed', 'children': self.executed, 'phase1_runs': 1})
                f.atomic_json(root/'warm-session-result.json', {'capsule': {'status': 'passed',
                    'resources': {'tree_empty': True}, 'phase1_retirement': {'phase1_retired': True}}})

        def interrupt():
            try:
                event = cleanup_started if point == 'cleanup' else analysis_started if point == 'phase2' else child_started
                if point == 'phase2':
                    release_child.set()
                if not event.wait(5):
                    raise RuntimeError('Test did not reach interruption point')
                os.kill(os.getpid(), number)
                if not servers[0].graceful_stop.wait(2):
                    raise RuntimeError('Signal handler did not close admission')
                if force:
                    os.kill(os.getpid(), number)
                if expire:
                    if not servers[0].stop.wait(3):
                        raise RuntimeError('Drain timeout did not trigger cleanup')
                release_child.set()
                release_analysis.set()
                release_cleanup.set()
            except BaseException as exc:
                thread_errors.append(str(exc))
                release_child.set()
                release_analysis.set()
                release_cleanup.set()
            finally:
                interrupter_done.set()

        thread = threading.Thread(target=interrupt, daemon=True)
        thread.start()
        error = None
        with patch.object(f, 'verify_campaign', return_value=manifest), \
             patch('taintforge_env.afl_warm.WarmAttemptServer', Server):
            try:
                result = transport.run_campaign(root, afl_bin=root, seconds=5, stop_timeout=1 if expire else 5)
            except RuntimeError as exc:
                error = str(exc)
                result = f.read_json(root/'campaign.json')
        self.assertTrue(interrupter_done.wait(5))
        thread.join(1)
        self.assertEqual(thread_errors, [])
        self.assertFalse(servers[0].thread.is_alive())
        self.assertFalse(servers[0].phase2.thread is not None and servers[0].phase2.thread.is_alive())
        self.assertEqual(result['status'], 'interrupted', error)
        return root, result

    def test_real_sigint_and_sigterm_drain_child_and_phase2_in_both_modes(self):
        for mode in ('parallel', 'sequential'):
            for number in (signal.SIGINT, signal.SIGTERM):
                for point in ('child', 'phase2', 'cleanup'):
                    with self.subTest(mode=mode, signal=number, point=point):
                        root, result = self.invoke(mode, number, point)
                        self.assertTrue(result['evidence_complete'])
                        self.assertEqual(result['cases'], result['completed_cases'])
                        self.assertEqual(result['phase2']['pending'], 0)
                        self.assertEqual(result['interruption']['status'], 'drained')
                        stop.verify_receipt(root, result)

    def test_second_signal_and_drain_timeout_are_not_resumable(self):
        for options in ({'force': True}, {'expire': True}):
            with self.subTest(options=options):
                root, result = self.invoke('parallel', signal.SIGINT, **options)
                self.assertFalse(reusable(result))
                self.assertEqual(result['interruption']['status'], 'incomplete')


class EntryPointTests(unittest.TestCase):
    def test_resume_records_interruption_during_bootstrap_without_claiming_failure(self):
        fixture = previous.ContinuationTests('test_prepare_only_never_starts_a_worker')
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        binary = fixture.root/'afl-bin'
        binary.mkdir()
        (binary/'afl-fuzz').write_text('#!/bin/sh\nexit 0\n')
        (binary/'afl-fuzz').chmod(0o700)
        target = fixture.root/'interrupted-bootstrap'
        with patch.object(transport, 'run_campaign', side_effect=InterruptedError('bootstrap interrupted')):
            with self.assertRaises(InterruptedError):
                continuation.resume(fixture.source, target, seconds=10, afl_bin=binary)
        self.assertEqual(f.read_json(target/'continuation-result.json')['status'], 'interrupted')

    def test_cli_forwards_timeout_and_returns_interrupted_status(self):
        from scripts.run_afl_file import main
        args = ['run_afl_file', 'run', '--out', '/tmp/stopped', '--stop-timeout', '17']
        with patch.object(sys, 'argv', args), contextlib.redirect_stdout(io.StringIO()), \
             patch.object(transport, 'run_campaign', return_value={'status': 'interrupted'}) as run:
            self.assertEqual(main(), 130)
        self.assertEqual(run.call_args.kwargs['stop_timeout'], 17)

    def test_signal_before_readiness_never_creates_a_resumable_receipt(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root/'afl-fuzz'
            binary.write_text('#!/bin/sh\nexit 0\n')
            binary.chmod(0o700)
            entered = threading.Event()
            servers = []
            class Server(transport.AttemptServer):
                def __init__(self, *args, **kwargs):
                    super().__init__(*args, **kwargs)
                    servers.append(self)
                def start(self):
                    entered.set()
                    self.stop.wait(5)
            manifest = {'status': 'prepared', 'max_input': 4096, 'launch': {'timeout_seconds': 1},
                        'build': {'bridge': '/bin/true'}}
            def interrupt():
                if entered.wait(3):
                    os.kill(os.getpid(), signal.SIGINT)
            thread = threading.Thread(target=interrupt, daemon=True)
            thread.start()
            with patch.object(f, 'verify_campaign', return_value=manifest), \
                 patch.object(transport, 'AttemptServer', Server):
                with self.assertRaises(InterruptedError):
                    transport.run_campaign(root, afl_bin=root, seconds=1)
            thread.join(1)
            saved = f.read_json(root/'campaign.json')
            self.assertEqual(saved['status'], 'interrupted')
            self.assertFalse(reusable(saved))
            self.assertEqual(servers[0].executed, 0)
            self.assertFalse((root/'interruption.json').exists())
            self.assertFalse((root/storage.RESERVE).exists())

    def test_native_environment_block_never_claims_signal_acceptance(self):
        from scripts import verify_afl_stop_e2e as native
        with tempfile.TemporaryDirectory() as temporary:
            with patch.object(native.baseline, 'verify', return_value={
                    'status': 'blocked_environment', 'missing': ['native environment']}):
                result = native.verify(Path(temporary)/'r', qemu=Path('/missing/qemu'))
        self.assertEqual(result['status'], 'blocked_environment')
        self.assertFalse(result['native_graceful_stop_verified'])


if __name__ == '__main__':
    unittest.main()
