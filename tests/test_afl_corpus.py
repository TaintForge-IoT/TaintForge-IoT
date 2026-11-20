import copy
import errno
import hashlib
import json
import os
from pathlib import Path
import random
import resource
import subprocess
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from experiments.afl_campaign_corpus import build as corpus
from scripts import verify_afl_corpus_e2e as host
from scripts.verify_afl_corpus_components import stock_launcher
from taintforge_env import afl_file as f, afl_storage as storage, afl_transport as transport
from taintforge_env.afl_resources import sample_parent
from taintforge_env.afl_validation import CaseLedger, verify_loss_diagnostic
from taintforge_env.afl_warm import FilesystemBaseline
from tests import test_afl_lifecycle as lifecycle


class OracleTests(unittest.TestCase):
    def test_prefix_matches_count_only_until_first_difference(self):
        for data, code in ((b'Z', 0), (b'A', 1), (b'AF', 2), (b'AFL', 3),
                           (b'AFL!', 4), (b'AFL!tail', 4), (b'AFZ!', 2)):
            self.assertEqual(corpus.expected('prefix', data), ('normal', code, None))

    def test_record_parser_has_independent_length_tag_and_checksum_outcomes(self):
        values = {b'\x01': 20, b'\x01\x02A': 21, b'\x03\x00': 22,
                  b'\x01\x00': 32, b'\x01\x03ABC': 38,
                  b'\x02\x01X': 49, b'\x02\x01Y': 48}
        for data, code in values.items():
            self.assertEqual(corpus.expected('record', data), ('normal', code, None))

    def test_deliberate_faults_are_separate_from_positive_targets(self):
        for data, wanted in corpus.FAULTS.items():
            self.assertEqual(corpus.expected('fault-prefix', data+b'tail'), wanted)
            for target in corpus.TARGETS:
                self.assertEqual(corpus.expected(target, data)[0], 'normal')

    def test_invalid_inputs_and_targets_are_rejected(self):
        for target, data in (('other', b'A'), ('prefix', b''), ('prefix', b'A'*4097), ('prefix', 'A')):
            with self.assertRaises(ValueError): corpus.expected(target, data)

    def test_control_sequence_revisits_anchor_after_every_probe(self):
        for target in corpus.ALL_TARGETS:
            sequence = corpus.check_sequence(target)
            self.assertEqual(sequence[0], sequence[-1])
            self.assertGreater(sequence.count(sequence[0]), 5)
            self.assertTrue(all(corpus.expected(target, seed)[0] == 'normal' for seed in corpus.seeds(target)))


class ResourceTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        (self.root/'self/ns').mkdir(parents=True)
        (self.root/'self/ns/pid').symlink_to('pid:[1]')

    def process(self, outer, inner, start=100, state='S'):
        root = self.root/str(outer)
        (root/'ns').mkdir(parents=True); (root/'fd').mkdir()
        (root/'ns/pid').symlink_to('pid:[1]')
        (root/'status').write_text('NSpid:\t'+str(outer)+'\t'+str(inner)+'\n')
        (root/'stat').write_text(f'{outer} (a tricky) name) '+state+' '+'0 '*18+str(start)+' 0\n')
        (root/'fd/3').symlink_to('/private/control')
        return root

    def test_outer_procfs_is_resolved_by_namespace_and_nspid(self):
        self.process(1234, 7)
        result = sample_parent(7, proc=self.root)
        self.assertEqual((result['namespace_pid'], result['start_ticks'], result['fd_count']), (7, 100, 1))

    def test_pid_reuse_is_rejected_even_with_same_number_and_fds(self):
        root = self.process(7, 7)
        first = sample_parent(7, proc=self.root)
        (root/'stat').write_text('7 (new) S '+'0 '*18+'101 0\n')
        with self.assertRaisesRegex(RuntimeError, 'identity changed'):
            sample_parent(7, proc=self.root, expected=first)

    def test_replaced_fd_is_detected_even_if_count_matches(self):
        root = self.process(7, 7)
        first = sample_parent(7, proc=self.root)
        (root/'fd/3').unlink(); (root/'fd/3').symlink_to('/other/control')
        second = sample_parent(7, proc=self.root, expected=first)
        self.assertEqual(first['fd_count'], second['fd_count'])
        self.assertNotEqual(first['fd_sha256'], second['fd_sha256'])

    def test_missing_ambiguous_and_zombie_processes_are_rejected(self):
        with self.assertRaisesRegex(RuntimeError, 'uniquely'): sample_parent(7, proc=self.root)
        self.process(700, 7); self.process(701, 7)
        with self.assertRaisesRegex(RuntimeError, 'uniquely'): sample_parent(7, proc=self.root)
        self.process(8, 8, state='Z')
        with self.assertRaisesRegex(RuntimeError, 'zombie'): sample_parent(8, proc=self.root)


class StorageMonitorTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.budget = storage.Budget(self.root, storage.policy(artifact_mib=4, case_mib=1, reserve_mib=1, min_free_mib=1))
        self.budget.open()
        self.addCleanup(self.budget.release_reserve)
        self.addCleanup(self.budget.stop_monitor)

    def wait_for(self, predicate):
        deadline = time.monotonic()+5
        while not predicate():
            self.assertLess(time.monotonic(), deadline)
            threading.Event().wait(.01)

    def test_scan_does_not_hold_admission_lock_and_completions_are_retained(self):
        started, finish = threading.Event(), threading.Event()
        usage = storage.usage
        def blocked(root, *, heartbeat=None):
            sampled = usage(root)
            started.set()
            while not finish.wait(.01): heartbeat()
            return sampled
        with patch.object(storage, 'usage', side_effect=blocked):
            self.budget.start_monitor(interval=.01)
            self.assertTrue(started.wait(3))
            before = time.monotonic(); self.budget.admit(0)
            self.assertLess(time.monotonic()-before, .5)
            case = self.root/'cases/00000000'; case.mkdir(parents=True); (case/'input').write_bytes(b'bytes')
            self.budget.complete(case)
            finish.set()
            self.wait_for(lambda: self.budget.completed_bytes_total == 5 and self.budget.last_sample > before)
            self.assertGreaterEqual(self.budget.check()['artifact_bytes'], 5)

    def test_healthy_slow_scan_uses_progress_instead_of_snapshot_age(self):
        self.budget.last_sample = time.monotonic()-100
        self.budget.monitor = object()
        self.budget.last_progress = time.monotonic()
        self.budget.check()
        self.budget.last_progress -= 31
        with self.assertRaisesRegex(RuntimeError, 'no progress'): self.budget.check()
        self.budget.monitor = None

    def test_monitor_error_preserves_io_failure_and_storage_classification(self):
        for code, limited in ((errno.EIO, False), (errno.ENOSPC, True), (errno.EDQUOT, True)):
            with self.subTest(errno=code):
                self.budget.monitor_error = self.budget.reason = None
                with patch.object(storage, 'usage', side_effect=OSError(code, 'injected')):
                    self.budget.start_monitor(interval=.01)
                    self.wait_for(lambda: self.budget.reason is not None or self.budget.monitor_error is not None)
                    with self.assertRaises(storage.ResourceLimit if limited else RuntimeError): self.budget.check()
                    self.budget.stop_monitor()

    def test_stopping_cancels_an_in_progress_scan_without_hiding_failure(self):
        started = threading.Event()
        def scanning(root, *, heartbeat=None):
            started.set()
            while True:
                heartbeat()
                threading.Event().wait(.01)
        with patch.object(storage, 'usage', side_effect=scanning):
            self.budget.start_monitor(interval=.01)
            self.assertTrue(started.wait(3))
            self.budget.stop_monitor()
        self.assertEqual(self.budget.cancelled_scans, 1)
        self.assertIsNone(self.budget.monitor_error)
        self.assertEqual(self.budget.report()['pending_reservations'], 0)

    def test_cleanup_failure_has_priority_over_a_resource_limit(self):
        with patch.object(storage, 'usage', side_effect=storage.ResourceLimit('artifact_bytes')), \
             patch.object(self.budget, 'release_reserve', side_effect=OSError('reserve cleanup failed')):
            self.budget.start_monitor(interval=.01)
            self.wait_for(lambda: self.budget.monitor_error is not None)
            with self.assertRaisesRegex(RuntimeError, 'cleanup failed'): self.budget.check()
            self.budget.stop_monitor()

    def test_async_private_measurement_keeps_admission_and_cleanup_working(self):
        self.budget.allow_privileged = True
        measured = storage.usage(self.root)
        with patch.object(storage, 'usage', side_effect=PermissionError(errno.EACCES, 'private export')), \
             patch.object(storage, 'privileged_usage', return_value=measured) as helper:
            self.budget.start_monitor(interval=.01)
            self.wait_for(lambda: self.budget.privileged_measurement)
            self.budget.admit(0)
            case = self.root/'cases/00000000'; case.mkdir(parents=True)
            (case/'input').write_bytes(b'A')
            self.budget.complete(case)
            self.budget.stop_monitor()
            report = self.budget.report()
        self.assertTrue(helper.called)
        self.assertEqual(report['measurement_backend'], 'sudo_read_only')
        self.assertEqual(report['pending_reservations'], 0)
        self.assertIsNone(report['monitor_error'])


class FilesystemResetTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        self.fs = root/'fs'; self.fs.mkdir()
        (self.fs/'input').write_bytes(b'A')
        self.baseline = FilesystemBaseline(self.fs, root/'baseline')

    def test_one_partial_copy_can_be_retried_but_must_match_the_checkpoint(self):
        original = self.baseline._copy
        calls = []
        def copy_once(*args):
            original(*args)
            calls.append(1)
            if len(calls) == 1: (self.fs/'input').write_bytes(b'bad copy')
        with patch.object(self.baseline, '_copy', side_effect=copy_once): self.baseline.restore()
        self.assertEqual((self.fs/'input').read_bytes(), b'A')
        self.assertEqual(self.baseline.restore_retries, 1)

    def test_repeated_corruption_is_fatal_and_names_the_changed_path(self):
        original = self.baseline._copy
        def corrupt(*args):
            original(*args); (self.fs/'input').write_bytes(b'bad copy')
        with patch.object(self.baseline, '_copy', side_effect=corrupt):
            with self.assertRaisesRegex(RuntimeError, '/input'): self.baseline.restore()

    def test_changed_checkpoint_is_never_retried_or_accepted(self):
        (self.baseline.backup/'input').write_bytes(b'changed')
        with self.assertRaisesRegex(RuntimeError, 'Checkpoint filesystem changed'): self.baseline.restore()


class SessionHookTests(unittest.TestCase):
    def setUp(self): lifecycle.CampaignLifecycleTests.setUp(self)

    def run_hook(self, hook):
        with patch.object(f, 'verify_campaign', return_value=self.manifest), \
             patch.object(transport, 'AttemptServer', self.server_type):
            return transport.run_campaign(self.root, afl_bin=self.root, seconds=1, session_check=hook)

    def test_both_stages_use_the_same_running_server(self):
        observed = []
        def hook(server, stage):
            self.assertTrue(server.started and not server.closed)
            observed.append((id(server), stage))
            return {'status': 'passed'}
        result = self.run_hook(hook)
        self.assertEqual(result['status'], 'completed')
        self.assertEqual(observed, [(id(self.servers[0]), 'before_afl'), (id(self.servers[0]), 'after_afl')])

    def test_failed_precheck_never_launches_afl(self):
        with patch.object(transport.subprocess, 'Popen') as launch:
            with self.assertRaisesRegex(RuntimeError, 'precheck'):
                self.run_hook(lambda server, stage: (_ for _ in ()).throw(RuntimeError('precheck')))
        launch.assert_not_called()
        self.assertTrue(self.servers[0].closed)
        self.assertEqual(f.read_json(self.root/'campaign.json')['status'], 'failed')

    def test_failed_postcheck_marks_campaign_incomplete(self):
        def hook(server, stage):
            if stage == 'after_afl': raise RuntimeError('postcheck')
            return {'status': 'passed'}
        with self.assertRaisesRegex(RuntimeError, 'postcheck'): self.run_hook(hook)
        result = f.read_json(self.root/'campaign.json')
        self.assertEqual(result['afl_exit'], 0)
        self.assertEqual(result['status'], 'failed')
        self.assertFalse(result['evidence_complete'])

    def test_failed_afl_does_not_run_postcheck(self):
        self.binary.write_text('#!/bin/sh\nexit 1\n')
        observed = []
        with self.assertRaises(RuntimeError): self.run_hook(lambda server, stage: observed.append(stage) or {})
        self.assertEqual(observed, ['before_afl'])


class DiagnosticsTests(unittest.TestCase):
    def loss(self, role='qemu', code=-9):
        from taintforge_env.capsule_supervision import exit_status
        return {'role': role, 'qemu_exit_status': exit_status(code), 'wrapper_exit': exit_status(code)['wrapper_exit'],
                'supervisor_error': 'Primary controller transport failure', 'capsule_error': 'controller failed',
                'worker_exit': {'component': 'observer', 'exitcode': -9}}

    def test_qemu_signal_and_observer_loss_with_qemu_exit86_are_preserved(self):
        self.assertEqual(verify_loss_diagnostic(self.loss())['status'], 'passed')
        self.assertEqual(verify_loss_diagnostic(self.loss('observer', 86))['status'], 'passed')

    def test_wrong_wrapper_exit_or_generic_mismatch_cannot_pass(self):
        for result in (self.loss() | {'wrapper_exit': -9},
                       self.loss() | {'capsule_error': 'M3 recorded exit differs from wrapper exit'},
                       self.loss() | {'supervisor_error': ''}, self.loss(code=137)):
            with self.assertRaises(RuntimeError): verify_loss_diagnostic(result)

    def test_observer_loss_requires_actual_controller_evidence(self):
        with self.assertRaisesRegex(RuntimeError, 'controller failure'):
            verify_loss_diagnostic(self.loss('observer', 86) | {'worker_exit': {}})

    def test_supervisor_retains_observer_death_when_qemu_exits_first(self):
        from unittest.mock import Mock
        from tests import test_capsule_lifecycle as boundaries
        from tests import test_input_retirement as base
        from tests import test_capsule_control as guarded
        from taintforge_env import input_retirement as m3
        fixture = boundaries.SupervisorFailureTests()
        fixture.setUp(); self.addCleanup(fixture.doCleanups)
        out, launch = fixture.prepare_input()
        executor = base.InputExecutor()
        report, code = fixture.invoke(out, launch, executor)
        self.assertEqual(code, 0, report.get('error'))
        run, binding, _ = executor.runs[0]
        context = Mock(); context.Pipe.side_effect = lambda: (Mock(), Mock())
        workers = [Mock(pid=111, exitcode=0), Mock(pid=112, exitcode=-9)]
        for worker in workers: worker.is_alive.return_value = False
        context.Process.side_effect = workers
        process = Mock(pid=77); process.poll.return_value = 86
        with tempfile.TemporaryDirectory() as ipc, patch.object(m3.mp, 'get_context', return_value=context), \
             patch.object(m3.p, 'wait_worker_ready'), \
             patch.object(base.resources, 'inspect_self', return_value=base.resource_entry(binding)), \
             patch.object(m3.subprocess, 'Popen', return_value=process), \
             patch.object(m3.observer, 'verify_attempt', side_effect=RuntimeError('native observer channel closed')):
            self.assertEqual(m3.supervise(binding, ipc), 86)
        saved = f.read_json(run/'logs/capsule/supervisor.json')
        self.assertIn({'component': 'observer', 'pid': 112, 'exitcode': -9}, saved['controller_failures'])
        self.assertFalse(saved['supervisor_kill'])
        process.kill.assert_not_called()


class HostSetupTests(unittest.TestCase):
    def test_invalid_limits_fail_before_privileged_or_filesystem_setup(self):
        with patch.object(host, 'preflight') as preflight:
            for executions, seconds, growth in ((64, 1800, 16), (10000, 1, 16), (True, 1800, 16), (10000, 1800, -1)):
                with self.assertRaises(ValueError):
                    host.verify('/must-not-create', qemu='/missing', executions=executions,
                                seconds=seconds, max_rss_growth_mib=growth)
        preflight.assert_not_called()

    def test_stock_launcher_preserves_transport_timeout_and_has_no_custom_mutator(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            executable = root/'real-afl'
            executable.write_text('#!/bin/sh\nprintf "%s\\n" "$@"\n'); executable.chmod(0o700)
            path = stock_launcher(root/'bin', executable)
            result = subprocess.check_output([str(path/'afl-fuzz'), '-t', '35500', '--', 'target'], text=True)
            self.assertEqual(result.splitlines(), ['-t', '35500', '--', 'target'])
            self.assertNotIn('AFL_CUSTOM_MUTATOR', (path/'afl-fuzz').read_text())


@unittest.skipUnless(os.environ.get('TF_WARM_QEMU'), 'Set TF_WARM_QEMU for real QEMU warm checks')
class NativeCorpusTests(unittest.TestCase):
    def test_all_parsers_match_oracle_and_repeated_inputs_restore_private_state(self):
        from experiments.afl_file.build import components
        from scripts.verify_afl_warm_components import NativeSession
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            built = components(root/'build')
            for target in corpus.ALL_TARGETS:
                with self.subTest(target=target), (root/(target+'.stdout')).open('wb') as stdout:
                    selected = built | {'guest': str(corpus.build(root/(target+'-fixture'), target))}
                    session = NativeSession(root/target, selected, os.environ['TF_WARM_QEMU'],
                                            guard='/__taintforge_capsule', stdout=stdout)
                    try:
                        trace = (root/target/'qemu.log').read_text()
                        self.assertNotIn('nanosleep(', trace)
                        self.assertNotIn('open("'+str(session.input), trace)
                        baseline = sample_parent(session.pid)
                        anchor, maps = corpus.seeds(target)[0], {}
                        rng = random.Random(42)
                        sequence = (*corpus.check_sequence(target), *(rng.randbytes(rng.randrange(1, 65)) for _ in range(64)))
                        for data in sequence:
                            value, _, bitmap = session.attempt_outcome(data, timeout_ms=500)
                            self.assertEqual((value['kind'], value['guest_exit'], value['guest_signal']), corpus.expected(target, data))
                            self.assertEqual(sample_parent(session.pid, expected=baseline), baseline)
                            if value['kind'] != 'timeout':
                                if data in maps: self.assertEqual(maps[data], bitmap)
                                maps[data] = bitmap
                        self.assertEqual(len(set(session.children)), len(session.children))
                    finally: session.close()
                    self.assertEqual(session.process.returncode, 0)

    def test_guest_fd_open_at_checkpoint_is_rejected(self):
        from experiments.afl_file.build import components
        from scripts.verify_afl_warm_components import NativeSession
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            built = components(root/'build')
            selected = built | {'guest': str(corpus.build(root/'fixture', 'prefix', leak_fd=True))}
            with self.assertRaises((EOFError, RuntimeError, ConnectionError)):
                NativeSession(root/'native', selected, os.environ['TF_WARM_QEMU'])
            self.assertIn('inherited_guest_or_unknown_fd', (root/'native/qemu.log').read_text())

    def test_input_open_is_rejected_if_retirement_was_never_armed(self):
        from experiments.afl_file.build import components
        from scripts.verify_afl_warm_components import NativeSession
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            built = components(root/'build')
            selected = built | {'guest': str(corpus.build(root/'fixture', 'prefix'))}
            with self.assertRaises((EOFError, RuntimeError, ConnectionError)):
                NativeSession(root/'native', selected, os.environ['TF_WARM_QEMU'], extra='unarmed=on')
            self.assertIn('TF_WARM_ABORT reason=input_opened_before_retirement',
                          (root/'native/qemu.log').read_text())


@unittest.skipUnless(os.environ.get('TF_WARM_QEMU') and os.environ.get('TF_PHASE1_PLUGIN'),
                     'Set TF_WARM_QEMU and TF_PHASE1_PLUGIN for standalone current Phase 1 checks')
class NativePhase1CompatibilityTests(unittest.TestCase):
    def test_real_phase1_observes_oep_before_any_mutable_input_open(self):
        from taintforge_env.phase1_runtime import Phase1Runtime, Phase1Run
        runtime = Phase1Runtime.load(Path(os.environ['TF_PHASE1_PLUGIN']))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for target in corpus.ALL_TARGETS:
                with self.subTest(target=target):
                    out = root/target; out.mkdir()
                    guest = corpus.build(out/'fixture', target)
                    input_path = out/'input'; input_path.write_bytes(corpus.seeds(target)[0])
                    run = Phase1Run(runtime=runtime, directory=out/'phase1', session_id='corpus-session',
                                    attempt_id='corpus-attempt', analysis_instance_id='corpus-instance', require_flags=False)
                    argument = run.plugin_argument(extra=('tf-selection-delay=16',))
                    def limits(): resource.setrlimit(resource.RLIMIT_AS, (8*1024**3, 8*1024**3))
                    result = subprocess.run([os.environ['TF_WARM_QEMU'], '-strace', '-plugin', argument,
                        str(guest), str(input_path), str(out/'marker'), str(out/'prepared')],
                        capture_output=True, timeout=90, preexec_fn=limits)
                    self.assertEqual(result.returncode, corpus.expected(target, input_path.read_bytes())[1], result.stderr[-2000:])
                    self.assertEqual(result.stdout, bytes([result.returncode]))
                    trace = result.stderr.decode(errors='replace')
                    input_open = trace.index('open("'+str(input_path))
                    self.assertLess(trace.index('[OEP-FINAL'), input_open)
                    self.assertNotIn('nanosleep(', trace)
                    self.assertEqual(run.verify()['capture_status'], 'success')


if __name__ == '__main__':
    unittest.main()
