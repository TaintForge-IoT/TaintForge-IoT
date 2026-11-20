import errno
import contextlib
import io
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from taintforge_env import afl_file as f, afl_storage as s, afl_transport as t
from taintforge_env import capsule_supervision as supervision, input_retirement as retirement
from taintforge_env.afl_evidence import reusable
from tests import test_afl_replay_epochs as replay_tests
from tests import test_afl_capsule as capsule_tests, test_input_retirement as input_tests


class StorageTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def budget(self, **options):
        value = s.policy(artifact_mib=2, case_mib=1, reserve_mib=1, min_free_mib=1, **options)
        result = s.Budget(self.root, value)
        self.addCleanup(result.release_reserve)
        return result

    def test_policy_is_bound_to_campaign_and_warm_configuration(self):
        manifest = {'warm': {}}
        s.bind(manifest, s.policy())
        self.assertEqual(s.verify_manifest(manifest), s.policy())
        manifest['warm']['storage'] = s.policy(log_mib=3)
        with self.assertRaisesRegex(ValueError, 'differs'):
            s.verify_manifest(manifest)
        manifest.pop('storage')
        with self.assertRaisesRegex(ValueError, 'Missing'):
            s.verify_manifest(manifest)

    def test_invalid_numbers_and_changed_policy_are_refused(self):
        for value in (True, 0, -1, 1.0, 1048577):
            with self.subTest(value=value), self.assertRaises(ValueError):
                s.policy(case_mib=value)
        manifest = {}
        s.bind(manifest, s.policy())
        manifest['storage'] = s.policy(case_mib=2)
        with self.assertRaisesRegex(ValueError, 'changed'):
            s.verify_manifest(manifest)

    def test_usage_separates_rootfs_logs_and_artifacts_and_never_follows_links(self):
        paths = {'cases/00000000/input': b'abc', 'warm-session/run/rootfs/tmp/state': b'guest',
                 'baseline-snapshots/objects/one': b'baseline', 'warm-session/run/logs/qemu_strace.log': b'log',
                 'build/file': b'prepare'}
        for name, data in paths.items():
            path = self.root/name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(data)
        (self.root/'cases/outside').symlink_to('/proc', target_is_directory=True)
        os.mkfifo(self.root/'cases/pipe')
        result = s.usage(self.root)
        self.assertEqual(result['artifact_bytes'], 3)
        self.assertEqual(result['rootfs_bytes'], 13)
        self.assertEqual(result['log_bytes'], 3)
        self.assertEqual(result['preparation_bytes'], 7)
        self.assertEqual(result['total_bytes'], 26)

    def test_mounts_are_not_traversed_and_hardlinked_inodes_are_not_double_counted(self):
        (self.root/'cases').mkdir(); (self.root/'cases/a').write_bytes(b'123')
        os.link(self.root/'cases/a', self.root/'cases/b')
        (self.root/'external').mkdir(); (self.root/'external/secret').write_bytes(b'outside')
        with patch.object(s, '_mounts', return_value={self.root/'external'}):
            result = s.usage(self.root)
        self.assertEqual(result['artifact_bytes'], 3)
        self.assertEqual(result['skipped_mounts'], 1)

    def test_reserve_is_physically_allocated_and_released_idempotently(self):
        budget = self.budget(); budget.open()
        info = (self.root/s.RESERVE).stat()
        self.assertEqual(info.st_size, s.MIB)
        self.assertGreaterEqual(info.st_blocks*512, s.MIB)
        descriptor = budget.reserve_fd
        budget.release_reserve(); budget.release_reserve()
        self.assertFalse((self.root/s.RESERVE).exists())
        with self.assertRaises(OSError): os.fstat(descriptor)

    def test_failed_preallocation_preserves_errno_and_leaks_no_reserve(self):
        budget = self.budget()
        with patch.object(s.os, 'posix_fallocate', side_effect=OSError(errno.ENOSPC, 'full')):
            with self.assertRaises(OSError) as caught: budget.open()
        self.assertEqual(caught.exception.errno, errno.ENOSPC)
        self.assertEqual(s.from_oserror(caught.exception).record['errno'], errno.ENOSPC)
        self.assertFalse((self.root/s.RESERVE).exists())
        self.assertIsNone(budget.reserve_fd)

    def test_real_enospc_syscall_is_classified_without_filling_the_host_filesystem(self):
        budget = self.budget(); budget.open()
        descriptor = os.open('/dev/full', os.O_WRONLY)
        try:
            with self.assertRaises(OSError) as caught: os.write(descriptor, b'failure probe')
        finally:
            os.close(descriptor)
        self.assertEqual(caught.exception.errno, errno.ENOSPC)
        limited = s.from_oserror(caught.exception)
        budget.stop(limited.record)
        self.assertEqual(budget.reason['errno'], errno.ENOSPC)
        self.assertFalse((self.root/s.RESERVE).exists())

    def test_failure_notice_uses_only_preallocated_space_and_releases_it(self):
        budget = self.budget(); budget.open()
        names = sorted(p.name for p in self.root.iterdir())
        reason = s.ResourceLimit('write_failed', errno=errno.ENOSPC).record
        s.notify(self.root, reason)
        self.assertEqual(sorted(p.name for p in self.root.iterdir()), names)
        with self.assertRaises(s.ResourceLimit) as caught: budget.check()
        self.assertEqual(caught.exception.record['errno'], errno.ENOSPC)
        self.assertEqual(budget.reason, reason)
        self.assertFalse((self.root/s.RESERVE).exists())

    def test_finalization_reads_a_notice_even_without_another_monitor_poll(self):
        budget = self.budget(); budget.open()
        reason = s.ResourceLimit('write_failed', errno=errno.EDQUOT).record
        s.notify(self.root, reason); budget.release_reserve()
        self.assertEqual(budget.reason, reason)
        self.assertTrue(budget.report()['reserve_released'])

    def test_corrupt_notice_is_rejected_and_its_reserve_is_still_released(self):
        budget = self.budget(); budget.open()
        os.pwrite(budget.reserve_fd, s.NOTICE.pack(s.NOTICE_MAGIC, 4000, bytes(32)), 0)
        with self.assertRaisesRegex(ValueError, 'notice size'): budget.release_reserve()
        self.assertIsNone(budget.reserve_fd)
        self.assertFalse((self.root/s.RESERVE).exists())

    def test_existing_reserve_or_symlink_is_not_overwritten(self):
        target = self.root/'existing'; target.write_bytes(b'keep')
        (self.root/s.RESERVE).symlink_to(target)
        with self.assertRaises(FileExistsError): self.budget().open()
        self.assertEqual(target.read_bytes(), b'keep')

    def test_admission_reserves_pending_analysis_before_starting_another_case(self):
        budget = self.budget(); budget.open()
        budget.admit(0); budget.admit(1)
        with self.assertRaises(s.ResourceLimit) as caught: budget.admit(2)
        self.assertEqual(caught.exception.record['reason'], 'case_reservation')
        case = self.root/'cases/00000000'; case.mkdir(parents=True)
        (case/'input').write_bytes(b'A')
        budget.complete(case)
        after = budget.extra_artifact_bytes
        budget.complete(case)
        self.assertEqual(budget.extra_artifact_bytes, after)
        self.assertEqual(budget.pending, {1})

    def test_log_and_rootfs_limits_are_checked_independently(self):
        for name, category in (('afl.log', 'log_bytes'), ('baseline/rootfs/state', 'rootfs_bytes')):
            with self.subTest(category=category):
                path = self.root/name; path.parent.mkdir(parents=True, exist_ok=True)
                with path.open('wb') as output: output.truncate(s.MIB)
                value = s.policy(log_mib=1, rootfs_mib=1, min_free_mib=1)
                with self.assertRaises(s.ResourceLimit) as caught: s.Budget(self.root, value).check()
                self.assertEqual(caught.exception.record['reason'], category)
                path.unlink()

    def test_pending_phase2_causes_backpressure_and_releases_the_next_admission(self):
        budget = self.budget(); budget.admit(0); budget.admit(1)
        admitted, stop = threading.Event(), threading.Event()
        errors = []
        def next_case():
            try:
                budget.admit(2, stop=stop); admitted.set()
            except Exception as exc:
                errors.append(exc)
        worker = threading.Thread(target=next_case)
        worker.start()
        try:
            self.assertFalse(admitted.wait(.1))
            case = self.root/'cases/00000000'; case.mkdir(parents=True)
            budget.complete(case)
            self.assertTrue(admitted.wait(2))
        finally:
            stop.set(); worker.join(2)
        self.assertFalse(worker.is_alive())
        self.assertEqual(errors, [])

    def test_cancel_wakes_a_storage_reservation_waiter(self):
        budget = self.budget(); budget.admit(0); budget.admit(1)
        stop, errors = threading.Event(), []
        def blocked():
            try: budget.admit(2, stop=stop)
            except Exception as exc: errors.append(exc)
        worker = threading.Thread(target=blocked); worker.start()
        stop.set(); worker.join(2)
        self.assertFalse(worker.is_alive())
        self.assertEqual(len(errors), 1)
        self.assertIsInstance(errors[0], ConnectionError)

    def test_free_space_is_reserved_for_pending_cases(self):
        budget = self.budget()
        free = SimpleNamespace(f_bavail=s.MIB+1, f_frsize=1)
        with patch.object(s.os, 'statvfs', return_value=free):
            with self.assertRaises(s.ResourceLimit) as caught: budget.admit(0)
        self.assertEqual(caught.exception.record['reason'], 'free_space_reservation')

    def test_oversized_project_json_is_rejected_before_replacing_evidence(self):
        manifest = {}; s.bind(manifest, self.budget().policy)
        f.atomic_json(self.root/'campaign.json', manifest)
        case = self.root/'cases/00000000'; case.mkdir(parents=True)
        path = case/'result.json'; f.atomic_json(path, {'state': 'original'})
        with self.assertRaises(s.ResourceLimit): f.atomic_json(path, {'payload': 'x'*s.MIB})
        self.assertEqual(f.read_json(path), {'state': 'original'})
        self.assertEqual(sorted(p.name for p in case.iterdir()), ['result.json'])

    def test_copy_fallback_preserves_bytes_and_never_deletes_existing_destination(self):
        source, target = self.root/'source', self.root/'target'
        source.write_bytes(b'original'); source.chmod(0o640)
        with patch.object(s.fcntl, 'ioctl', side_effect=OSError(errno.EOPNOTSUPP, 'no reflink')):
            s.copy_file(source, target)
        self.assertEqual(target.read_bytes(), b'original')
        self.assertEqual(target.stat().st_mode & 0o777, 0o640)
        self.assertEqual(target.stat().st_nlink, 1)
        with self.assertRaises(FileExistsError): s.copy_file(source, target)
        self.assertEqual(target.read_bytes(), b'original')

    def test_reflink_io_error_removes_only_the_new_partial_file(self):
        source, target = self.root/'source', self.root/'target'; source.write_bytes(b'data')
        with patch.object(s.fcntl, 'ioctl', side_effect=OSError(errno.ENOSPC, 'full')):
            with self.assertRaises(OSError): s.copy_file(source, target)
        self.assertFalse(target.exists())
        self.assertEqual(source.read_bytes(), b'data')

    def test_exports_do_not_consume_the_runtime_log_budget(self):
        for name in ('warm-session/iterations/0000/run/logs/phase1/unpacked.bin',
                     'warm-session/iterations/0000/run/logs/capsule/phase1-retirement/export/unpacked.bin'):
            path = self.root/name; path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b'export')
        result = s.usage(self.root)
        self.assertEqual(result['log_bytes'], 0)
        self.assertEqual(result['preparation_bytes'], 12)

    def test_incomplete_or_inconsistent_resource_stop_cannot_be_reused(self):
        budget = self.budget()
        reason = s.ResourceLimit('case_reservation').record
        budget.stop(reason)
        manifest = {'status': 'resource_limited', 'cases': 2, 'completed_cases': 2,
                    'evidence_complete': True, 'stop_reason': 'storage_limit', 'storage_stop': reason,
                    'storage_result': budget.report()}
        s.bind(manifest, budget.policy)
        self.assertTrue(reusable(manifest))
        for change in ({'evidence_complete': False}, {'completed_cases': 1}, {'storage_stop': {}}, {'cases': True}):
            self.assertFalse(reusable(manifest | change))
        manifest['storage_result']['pending_reservations'] = 1
        self.assertFalse(reusable(manifest))
        manifest['storage_result']['pending_reservations'] = False
        self.assertFalse(reusable(manifest))


class ExitStatusTests(unittest.TestCase):
    def test_real_sigkill_has_the_same_wrapper_status_as_137(self):
        child = subprocess.Popen([sys.executable, '-c', 'import sys; sys.stdin.buffer.read()'], stdin=subprocess.PIPE)
        try:
            child.kill(); child.wait(timeout=3)
            self.assertEqual(child.returncode, -signal.SIGKILL)
            self.assertEqual(supervision.exit_status(child.returncode),
                             {'returncode': -9, 'signal': 9, 'wrapper_exit': 137})
        finally:
            if child.poll() is None: child.kill(); child.wait(timeout=3)
            child.stdin.close()

    def test_finalization_keeps_the_supervisor_cause_after_signal_normalization(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); (root/'config').mkdir(); (root/'logs/capsule').mkdir(parents=True)
            binding = {'attempt_id': 'attempt', 'attempt_contract_sha256': 'a'*64}
            f.atomic_json(root/'config/capsule_binding.json', binding)
            f.atomic_json(root/'logs/capsule/supervisor.json',
                          {'status': 'failed', 'qemu_exit': -9, 'error': 'observer controller lost',
                           'controller_failure': {'component': 'observer', 'exitcode': -9}})
            context = SimpleNamespace(run_dir=root, attempt_contract=SimpleNamespace(attempt_id='attempt', contract_sha256='a'*64))
            for wrapper, expected in ((137, 'observer verification failed'), (130, 'recorded exit differs'), (True, 'recorded exit differs')):
                with self.subTest(wrapper=wrapper), patch.object(retirement.observer, 'verify_attempt',
                        side_effect=RuntimeError('observer verification failed')) as verify:
                    with self.assertRaisesRegex(RuntimeError, expected): retirement.finish_attempt(context, wrapper)
                    result = f.read_json(root/'config/capsule_result.json')
                    self.assertEqual(result['status'], 'failed')
                    self.assertEqual(result['supervisor_error'], 'observer controller lost')
                    self.assertEqual(result['controller_failure']['component'], 'observer')
                    self.assertEqual(result['qemu_exit_status']['signal'], 9)
                    self.assertEqual(verify.call_count, 1 if wrapper == 137 else 0)

    def test_exit_and_signal_ranges_remain_distinct(self):
        for code, wrapper in ((0, 0), (86, 86), (255, 255), (-15, 143)):
            self.assertEqual(supervision.exit_status(code)['wrapper_exit'], wrapper)
        for bad in (True, None, -128, 256, 0.0):
            with self.assertRaises(ValueError): supervision.exit_status(bad)


class CampaignStorageTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(); self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.binary = self.root/'afl-fuzz'
        self.binary.write_text('''#!/usr/bin/env python3
import array,os,signal,socket,struct,sys
signal.signal(signal.SIGINT,lambda *_:sys.exit(0))
control=socket.socket(fileno=int(sys.argv[-2]))
while True:
    child,peer=socket.socketpair()
    control.sendmsg([b'C'],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',[peer.fileno()]))])
    peer.close()
    child.sendall(struct.pack('!I',1)+b'A')
    data=b''
    while len(data)<16: data+=child.recv(16-len(data))
    child.close()
''')
        self.binary.chmod(0o700)
        self.manifest = {'status': 'prepared', 'max_input': 4096, 'launch': {'timeout_seconds': 1},
                         'build': {'bridge': '/bin/true'}}
        self.servers = []
        owners = self.servers
        class InputServer(t.AttemptServer):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs); owners.append(self)
            def execute(self, connection):
                t.recv_exact(connection, 5)
                self.admit_case(self.executed)
                case = self.root/'cases'/f'{self.executed:08d}'; case.mkdir()
                self.executed += 1
                (case/'input').write_bytes(b'A')
                (case/'observation').write_bytes(b'x'*(256*1024))
                f.atomic_json(case/'result.json', {'status': 'passed'})
                connection.sendall(bytes(16)); self.completed += 1
                self.storage.complete(case)
        self.server_type = InputServer

    def invoke(self):
        with patch.object(f, 'verify_campaign', return_value=self.manifest), patch.object(t, 'AttemptServer', self.server_type):
            return t.run_campaign(self.root, afl_bin=self.root, seconds=5, max_artifact_mib=16,
                                  max_case_mib=1, reserve_mib=1, min_free_mib=1)

    def test_real_input_driver_stops_on_admission_without_a_fake_crash(self):
        result = self.invoke()
        server = self.servers[0]
        self.assertEqual(result['status'], 'resource_limited')
        self.assertTrue(result['evidence_complete'])
        self.assertGreater(result['cases'], 0)
        self.assertEqual(result['cases'], result['completed_cases'])
        self.assertEqual(result['storage_stop']['reason'], 'case_reservation')
        self.assertEqual(server.errors, [])
        self.assertFalse(server.thread.is_alive())
        self.assertFalse((self.root/'findings').exists())
        self.assertFalse((self.root/s.RESERVE).exists())
        self.assertEqual(result['storage_result']['pending_reservations'], 0)
        self.assertLess(result['storage_result']['usage']['artifact_bytes'], 16*s.MIB)

    def test_enospc_before_bootstrap_starts_no_worker_and_saves_the_reason(self):
        with patch.object(s.os, 'posix_fallocate', side_effect=OSError(errno.ENOSPC, 'full')):
            result = self.invoke()
        self.assertEqual(result['status'], 'resource_limited')
        self.assertFalse(result['evidence_complete'])
        self.assertEqual(result['storage_stop']['errno'], errno.ENOSPC)
        self.assertFalse(self.servers[0].thread.is_alive())
        self.assertEqual(self.servers[0].executed, 0)
        self.assertFalse((self.root/s.RESERVE).exists())


class StorageReplayTests(unittest.TestCase):
    setUp = replay_tests.ReplayEpochTests.setUp
    closed = replay_tests.ReplayEpochTests.closed

    def test_replay_clone_preserves_the_policy_and_uses_a_new_campaign_path(self):
        from taintforge_env.afl_replay import clone_campaign
        from taintforge_env.afl_capsule import PROFILE
        self.manifest['warm']['capsule_profile'] = PROFILE
        value = s.policy(log_mib=3, rootfs_mib=40, case_mib=2)
        s.bind(self.manifest, value)
        f.atomic_json(self.source/'campaign.json', self.manifest)
        output = self.root/'storage-clone'
        cloned = clone_campaign(self.source, output)
        self.assertEqual(s.verify_manifest(cloned), value)
        self.assertEqual(cloned['warm']['capsule_profile'], PROFILE)
        self.assertEqual(cloned['warm']['campaign_root'], str(output))
        self.assertFalse((output/s.RESERVE).exists())

    def test_resource_limited_cli_has_a_distinct_exit_code_and_forwards_limits(self):
        from scripts.run_afl_file import main
        arguments = ['run_afl_file', 'run', '--out', str(self.root/'campaign'),
                     '--max-artifact-mib', '64', '--max-log-mib', '8', '--max-case-mib', '2',
                     '--max-rootfs-mib', '128', '--max-preparation-mib', '512', '--reserve-mib', '1']
        with patch.object(sys, 'argv', arguments), patch.object(t, 'run_campaign',
                return_value={'status': 'resource_limited'}) as run, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(), 3)
        self.assertEqual(run.call_args.kwargs['max_case_mib'], 2)
        self.assertEqual(run.call_args.kwargs['max_preparation_mib'], 512)
        self.assertIsNone(run.call_args.kwargs['min_free_mib'])


class Phase2StorageFailureTests(unittest.TestCase):
    def test_enospc_and_failure_report_refusal_drain_the_queue_and_keep_the_cause(self):
        from taintforge_env import afl_phase2 as phase2, afl_warm
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = {}; s.bind(manifest, s.policy(min_free_mib=1, reserve_mib=1))
            f.atomic_json(root/'campaign.json', manifest)
            case = root/'cases/00000000'; (case/'phase2').mkdir(parents=True)
            server = afl_warm.WarmAttemptServer(root); self.addCleanup(server.close)
            server.storage.open()
            def fail(case, config): raise OSError(errno.ENOSPC, 'injected full disk')
            worker = phase2.Processor(root, phase2.settings('parallel', 1), process=fail,
                                      on_error=server.phase2_error)
            original = f.atomic_json
            def save(path, value):
                if Path(path) == case/'phase2/result.json':
                    raise OSError(errno.ENOSPC, 'cannot save failed child result')
                return original(path, value)
            with patch.object(f, 'atomic_json', side_effect=save):
                worker.start()
                try: worker.submit(case)
                except RuntimeError: pass
                with self.assertRaises(RuntimeError): worker.close()
            self.assertFalse(worker.thread.is_alive())
            self.assertEqual(worker.completed, 1)
            self.assertTrue(server.admission_closed.is_set())
            self.assertEqual(server.storage.reason['errno'], errno.ENOSPC)
            self.assertFalse((root/s.RESERVE).exists())
            progress = f.read_json(root/'phase2-progress.json')
            self.assertEqual(progress['status'], 'failed')
            self.assertEqual(progress['pending'], 0)


class CapsuleStorageBindingTests(unittest.TestCase):
    setUp = capsule_tests.CapsuleWarmIntegrationTests.setUp
    prepare_input = capsule_tests.CapsuleWarmIntegrationTests.prepare_input
    invoke = capsule_tests.CapsuleWarmIntegrationTests.invoke
    prepare_guarded = capsule_tests.CapsuleWarmIntegrationTests.prepare_guarded
    prepare_warm = capsule_tests.CapsuleWarmIntegrationTests.prepare_warm
    evidence = staticmethod(capsule_tests.CapsuleWarmIntegrationTests.evidence)

    def test_storage_policy_reaches_the_bound_m5_attempt_and_finalization(self):
        out, launch = self.prepare_warm()
        path = Path(launch['template_run_dir'])/'config/runtime.json'
        runtime = f.read_json(path)
        value = s.policy(log_mib=8)
        runtime['afl_warm']['storage'] = value
        f.atomic_json(path, runtime)
        executor = input_tests.InputExecutor()
        with patch.object(input_tests, 'synthetic_evidence', side_effect=self.evidence):
            report, code = self.invoke(out, launch, executor)
        self.assertEqual(code, 0)
        self.assertEqual(executor.runs[0][1]['afl_warm']['storage'], value)
        self.assertEqual(report['capsule']['afl_checkpoint']['profile'], 'warm-m5-capsule-v1')
        self.assertEqual(report['capsule']['control_guard']['status'], 'verified')
