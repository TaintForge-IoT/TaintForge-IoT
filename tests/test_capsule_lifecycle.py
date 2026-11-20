from contextlib import ExitStack
import copy
import errno
import json
import multiprocessing
import os
from pathlib import Path
import socket
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock, patch

from taintforge_env import input_retirement as m3, capsule_supervision as supervision
from taintforge_env import phase1_retirement as retirement
from tests import test_analysis_quality as quality
from tests import test_capsule_control as guarded
from tests import test_input_retirement as base
from tests import test_phase1_retirement as packets
from scripts import inject_capsule_lifecycle_fault as faults
from scripts.audit_capsule_strict_evidence import audit


class ChildWorker:
    def __init__(self, process):
        self.process = process
        self.pid = process.pid

    @property
    def exitcode(self):
        return self.process.poll()


class ProcessWatchTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        (self.root/'phase1-retirement').mkdir()
        self.children = []
        self.addCleanup(self.reap)

    def child(self, source):
        process = subprocess.Popen([sys.executable, '-c', source], stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.children.append(process)
        return process

    def reap(self):
        for process in self.children:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=3)
            process.stdin.close()

    def guest(self):
        return self.child('import sys; sys.stdin.buffer.read()')

    def ended_worker(self, code=0):
        process = self.child('raise SystemExit('+str(code)+')')
        process.wait(timeout=3)
        return ChildWorker(process)

    def result(self, name, value):
        path = self.root/supervision.WORKERS[name][0]
        retirement.probe.write_json(path, value)
        return path

    def test_real_killed_controller_is_detected_with_its_role_and_signal(self):
        for name in supervision.WORKERS:
            with self.subTest(name=name):
                process = self.guest()
                process.kill(); process.wait(timeout=3)
                guest = self.guest()
                with self.assertRaises(supervision.ControllerExitError) as caught:
                    supervision.wait_qemu(guest, ((name, ChildWorker(process)),), self.root, 2)
                self.assertEqual(caught.exception.record['component'], name)
                self.assertEqual(caught.exception.record['exitcode'], -9)
                self.assertEqual(caught.exception.failure['category'], 'controller_failure')

    def test_nonzero_controller_exit_is_not_a_guest_timeout(self):
        with self.assertRaises(supervision.ControllerExitError) as caught:
            supervision.wait_qemu(self.guest(), (('permit', self.ended_worker(7)),), self.root, 2)
        self.assertEqual(caught.exception.record['exitcode'], 7)

    def test_controller_death_after_waiting_started_is_detected(self):
        child = self.child('import sys; sys.stdin.buffer.read(); raise SystemExit(7)')
        timer = threading.Timer(.05, child.stdin.close)
        timer.start()
        try:
            with self.assertRaises(supervision.ControllerExitError) as caught:
                supervision.wait_qemu(self.guest(), (('observer', ChildWorker(child)),), self.root, 2)
            self.assertEqual(caught.exception.record['exitcode'], 7)
        finally:
            timer.join(3)

    def test_zero_exit_requires_a_complete_readable_result(self):
        for name in supervision.WORKERS:
            with self.subTest(name=name):
                with self.assertRaises(supervision.ControllerExitError):
                    supervision.wait_qemu(self.guest(), ((name, self.ended_worker()),), self.root, 2)

    def test_failed_and_oversized_results_do_not_authorize_waiting(self):
        worker = self.ended_worker()
        path = self.result('observer', {'status': 'failed', 'error': 'storage unavailable'})
        for raw in (path.read_bytes(), b'{"status":"passed","status":"failed"}', b'x'*(256*1024+1)):
            with self.subTest(size=len(raw)):
                path.write_bytes(raw)
                with self.assertRaises(supervision.ControllerExitError):
                    supervision.wait_qemu(self.guest(), (('observer', worker),), self.root, 2)

    def test_success_status_with_a_persistence_failure_is_rejected(self):
        self.result('observer', {'status': 'passed', 'evidence_persistence_error': 'ENOSPC'})
        with self.assertRaises(supervision.ControllerExitError):
            supervision.wait_qemu(self.guest(), (('observer', self.ended_worker()),), self.root, 2)

    def test_completed_permit_is_allowed_while_guest_continues(self):
        self.result('permit', {'status': 'released'})
        with self.assertRaises(subprocess.TimeoutExpired):
            supervision.wait_qemu(self.guest(), (('permit', self.ended_worker()),), self.root, .4)

    def test_expected_denial_does_not_become_a_controller_crash(self):
        self.result('permit', {'status': 'analysis_rejected'})
        guest = self.child('import time; time.sleep(.05); raise SystemExit(88)')
        code = supervision.wait_qemu(guest, (('permit', self.ended_worker()),), self.root, 2)
        self.assertEqual(code, 88)

    def test_native_guard_exit_wins_the_controller_eof_race(self):
        self.result('observer', {'status': 'failed', 'error': 'Observer channel closed'})
        worker = self.ended_worker()
        guest = self.child('import time; time.sleep(.05); raise SystemExit(126)')
        self.assertEqual(supervision.wait_qemu(guest, (('observer', worker),), self.root, 2), 126)

    def test_resource_sampling_error_is_not_swallowed(self):
        sample = Mock(side_effect=RuntimeError('export budget exceeded'))
        with self.assertRaisesRegex(RuntimeError, 'export budget'):
            supervision.wait_qemu(self.guest(), (), self.root, 2, sample=sample)
        sample.assert_called_once()

    def test_real_guest_deadline_and_invalid_bounds(self):
        guest = self.guest()
        with self.assertRaises(subprocess.TimeoutExpired):
            supervision.wait_qemu(guest, (), self.root, .03)
        for seconds, interval in ((0, .01), (86406, .01), (1, 0), (1, 2)):
            with self.subTest(seconds=seconds, interval=interval), self.assertRaises(ValueError):
                supervision.wait_qemu(guest, (), self.root, seconds, poll_seconds=interval)


class PermitBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.fixture = quality.AnalysisPolicyTests('test_strict_acceptance_never_promotes_global_proof')
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.root, self.binding = self.fixture.root, self.fixture.binding
        self.binding['settings'].update(total_ms=200, phase1_retirement=retirement.settings())
        output = retirement.directory(self.binding)
        output.mkdir(parents=True)
        source = packets.RetirementEvidenceTests()
        source.setUp()
        self.addCleanup(source.doCleanups)
        self.packets = copy.deepcopy(source.packets)
        for packet in self.packets:
            packet.update(host_pid=os.getpid(), nonce=self.binding['lifecycle_attempt'],
                **{k: self.binding[k] for k in ('session_id', 'attempt_id', 'analysis_instance_id')})

    def exchange(self, *, count=5, copy_error=False, grant='grant', extra=False, reject=False, residue=False):
        if reject:
            self.fixture.partial()
        decision = self.fixture.assess('strict' if reject else 'research')
        control, child = multiprocessing.Pipe()
        progress, worker_progress = multiprocessing.Pipe()
        client, server = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        client.settimeout(3)
        errors, notices = [], []

        def worker():
            try:
                retirement.permit_worker(self.root/'permit.sock', child, self.binding, progress_pipe=worker_progress)
            except BaseException as exc:
                errors.append(exc)

        with ExitStack() as stack:
            listener = Mock()
            listener.bind.side_effect = lambda path: Path(path).touch()
            listener.accept.return_value = server, None
            stack.enter_context(patch.object(retirement.socket, 'socket', return_value=listener))
            verify = stack.enter_context(patch.object(retirement, 'verify_export',
                return_value=(self.fixture.run, {'analysis_quality': decision})))
            preserve = stack.enter_context(patch.object(retirement, 'preserve_export', return_value={}))
            if copy_error:
                preserve.side_effect = OSError(errno.ENOSPC, 'No space left on device')
            thread = threading.Thread(target=worker, daemon=True)
            thread.start()
            try:
                self.assertTrue(control.poll(3), 'Permit worker did not become ready')
                self.assertEqual(control.recv(), 'ready')
                control.send(os.getpid())
                for packet in self.packets[:min(count, 2)]:
                    client.sendall(json.dumps(packet).encode())
                command = b''
                if count >= 2 and not copy_error and not reject:
                    self.assertTrue(progress.poll(3))
                    notices.append(progress.recv())
                    if grant is None:
                        progress.close()
                    else:
                        progress.send(grant)
                if count >= 2:
                    command = client.recv(2048)
                if command.startswith(b'RETIRE '):
                    suffix = copy.deepcopy(self.packets[2:count])
                    if residue and suffix:
                        suffix[-1]['data']['owner_roots_remaining'] = 1
                    for packet in suffix:
                        client.sendall(json.dumps(packet).encode())
                    if extra:
                        client.sendall(b'{}')
                client.shutdown(socket.SHUT_WR)
                thread.join(3)
                if not progress.closed and progress.poll(.1):
                    try:
                        notices.append(progress.recv())
                    except EOFError:
                        pass
            finally:
                client.close(); control.close(); progress.close()
                thread.join(7)
            self.assertFalse(thread.is_alive(), 'Permit worker leaked')
            self.assertEqual(errors, [])
            return base.c.read_json(retirement.directory(self.binding)/'retirement.json'), command, notices, verify.call_count

    def test_real_ipc_success_preserves_order_and_acknowledges_release(self):
        saved, command, notices, verified = self.exchange()
        self.assertEqual(saved['status'], 'released', saved.get('error'))
        self.assertTrue(command.startswith(b'RETIRE '))
        self.assertEqual(notices, ['export_ready', 'released'])
        self.assertEqual(verified, 2)
        marks = saved['permit_timeline_ns']
        stages = ('export_verification', 'analysis_policy', 'copy_export', 'recheck_export',
                  'notify_observer', 'wait_for_observer_grant', 'send_permit_reply', 'permit_reply_sent')
        times = [marks[key] for key in stages]
        self.assertEqual(times, sorted(times))
        self.assertNotIn('failure_observed', marks)

    def test_incomplete_export_disconnect_never_requests_a_permit(self):
        saved, command, notices, verified = self.exchange(count=1)
        self.assertEqual(saved['status'], 'failed')
        self.assertFalse(saved['permit_sent'])
        self.assertEqual((command, notices, verified), (b'', [], 0))

    def test_export_copy_disk_full_never_grants_progress(self):
        saved, command, notices, _ = self.exchange(copy_error=True)
        self.assertEqual(saved['status'], 'failed')
        self.assertFalse(saved['permit_sent'])
        self.assertIn('No space left', saved['error'])
        self.assertEqual(saved['failure']['stage'], 'copy_export')
        marks = saved['permit_timeline_ns']
        self.assertGreaterEqual(marks['failure_observed'], marks['copy_export'])
        self.assertNotIn('notify_observer', marks)
        self.assertEqual((command, notices), (b'', []))

    def test_observer_gate_disconnect_never_sends_a_permit(self):
        saved, command, notices, _ = self.exchange(grant=None)
        self.assertFalse(saved['permit_sent'])
        self.assertEqual(saved['failure']['exception_type'], 'EOFError')
        self.assertEqual(saved['failure']['stage'], 'wait_for_observer_grant')
        self.assertNotIn('send_permit_reply', saved['permit_timeline_ns'])
        self.assertEqual((command, notices), (b'', ['export_ready']))

    def test_invalid_observer_grant_never_sends_a_permit(self):
        saved, command, notices, _ = self.exchange(grant='old-grant')
        self.assertEqual(saved['status'], 'failed')
        self.assertFalse(saved['permit_sent'])
        self.assertEqual((command, notices), (b'', ['export_ready']))

    def test_disconnect_during_removal_never_acknowledges_release(self):
        for count in (2, 3, 4):
            with self.subTest(count=count):
                if count != 2:
                    self.setUp()
                saved, _, notices, _ = self.exchange(count=count)
                self.assertEqual(saved['status'], 'failed')
                self.assertTrue(saved['permit_sent'])
                self.assertEqual(len(saved['events']), count)
                self.assertEqual(notices, ['export_ready'])

    def test_reported_residue_and_trailing_packets_are_rejected(self):
        for changes in ({'residue': True}, {'extra': True}):
            with self.subTest(changes=changes):
                if 'extra' in changes:
                    self.setUp()
                saved, _, notices, _ = self.exchange(**changes)
                self.assertEqual(saved['status'], 'failed')
                self.assertTrue(saved['permit_sent'])
                self.assertEqual(notices, ['export_ready'])

    def test_real_ipc_strict_denial_precedes_any_progress_grant(self):
        saved, command, notices, _ = self.exchange(reject=True, count=2)
        self.assertEqual(saved['status'], 'analysis_rejected')
        self.assertFalse(saved['permit_sent'])
        self.assertTrue(saved['stream_closed'])
        self.assertEqual((command, notices), (b'DENY\n', []))


class FinalizationBoundaryTests(unittest.TestCase):
    setUp = base.InputRetirementTests.setUp
    prepare_input = base.InputRetirementTests.prepare_input
    prepare_guarded = guarded.ControlIntegrationTests.prepare_guarded
    invoke = base.InputRetirementTests.invoke

    def check_boundary(self, point):
        out, launch = self.prepare_guarded()
        executor = base.InputExecutor()

        def interrupt(run, code, fault=None):
            binding, result = guarded.guarded_evidence(run, code, fault)
            directory = retirement.directory(binding)
            path = directory/'retirement.json'
            saved = base.c.read_json(path)
            journal_path = run/'logs/capsule/observer-events.json'
            journal = base.c.read_json(journal_path)
            if point == 'partial-export':
                saved.update(status='failed', permit_sent=False, events=saved['events'][:1])
            elif point == 'before-permit':
                saved.update(status='failed', permit_sent=False, events=saved['events'][:2])
            elif point == 'during-cleanup':
                saved.update(status='failed', events=saved['events'][:4])
            elif point == 'before-unmap':
                index = next(i for i, e in enumerate(journal['events']) if e['event'] == 'module_unmapped')
                journal['events'] = journal['events'][:index]
            elif point == 'before-resume':
                index = next(i for i, e in enumerate(journal['events']) if e.get('command') == 'RESUME 2')
                journal['events'] = journal['events'][:index]
            elif point == 'before-done':
                journal['events'] = journal['events'][:-1]
            base.c.p.write_json(path, saved)
            base.c.p.write_json(journal_path, journal)
            return binding, result

        with patch.object(base, 'synthetic_evidence', side_effect=interrupt):
            report, code = self.invoke(out, launch, executor)
            self.assertEqual(code, 1, report)
            self.assertEqual(report['outcome'], 'intervention_required')
            self.assertEqual(report['capsule']['status'], 'failed')
            run = executor.runs[0][0]
            claim_path = run.parent/'execution_attempt.json'
            claim = base.c.read_json(claim_path)
            self.assertEqual(claim['stage'], 'failed')
            self.assertFalse(claim['retry_safe'])
            digest = base.c.p.sha(claim_path)
            resumed, code = self.invoke(out, launch, executor)
            self.assertEqual(code, 1)
            self.assertEqual(resumed['executions_this_invocation'], 0)
            self.assertEqual(base.c.p.sha(claim_path), digest)
            self.assertEqual(len(executor.runs), 1)

    def test_partial_export_cannot_finalize(self):
        self.check_boundary('partial-export')

    def test_accepted_decision_without_permit_cannot_finalize(self):
        self.check_boundary('before-permit')

    def test_callbacks_removed_without_release_cannot_finalize(self):
        self.check_boundary('during-cleanup')

    def test_release_without_unmap_observation_cannot_finalize(self):
        self.check_boundary('before-unmap')

    def test_unmap_without_second_resume_cannot_finalize(self):
        self.check_boundary('before-resume')

    def test_resume_without_native_completion_cannot_finalize(self):
        self.check_boundary('before-done')

    def test_strict_reassessment_does_not_modify_or_promote_a_research_export(self):
        out, launch = self.prepare_guarded()
        executor = base.InputExecutor()
        with patch.object(base, 'synthetic_evidence', side_effect=guarded.guarded_evidence):
            report, code = self.invoke(out, launch, executor)
        self.assertEqual(code, 0, report.get('error'))
        proof = executor.runs[0][0]/'retirement-evidence'
        digest = base.c.p.sha(proof/'bundle.json')
        result = audit(proof, digest)
        self.assertEqual(result['status'], 'blocked_by_export_quality')
        self.assertEqual(result['source_decision']['status'], 'accepted')
        self.assertEqual(result['strict_assessment']['status'], 'rejected')
        self.assertIn('unverified_flags', result['strict_assessment']['rejection_reasons'])
        self.assertFalse(result['native_strict_positive_verified'])
        self.assertFalse(result['permit_sent_by_audit'])
        self.assertEqual(base.c.p.sha(proof/'bundle.json'), digest)


class InjectionIdentityTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.proc, self.cgroup = self.root/'proc', self.root/'cgroup'
        self.binding = {'lifecycle_attempt': '1'*32, **{k: k+'-fixture' for k in base.mappings.IDENTITY}}
        self.unit = base.resources.unit_name(self.binding)
        self.record = {'schema': 1, 'identity': {k: self.binding[k] for k in base.mappings.IDENTITY},
            'unit': self.unit, 'pid_scope': 'sandbox_pid_namespace', 'pid_namespace': 'pid:[123]',
            'supervisor_pid': 10, 'supervisor_start_ticks': 987, 'workers': {'permit': 11, 'observer': 12},
            'qemu_pid': 13}
        directory = self.cgroup/'system.slice'/self.unit
        directory.mkdir(parents=True)
        (directory/'cgroup.procs').write_text('200\n201\n202\n203\n')
        for pid, namespace_pid, parent in ((200, 10, 1), (201, 11, 200), (202, 12, 200), (203, 13, 200)):
            directory = self.proc/str(pid)
            (directory/'ns').mkdir(parents=True)
            (directory/'status').write_text(f'PPid:\t{parent}\nNSpid:\t{pid} {namespace_pid}\n')
            (directory/'stat').write_text(f'{pid} (python fixture) S '+'0 '*18+'987 0\n')
            (directory/'cgroup').write_text('0::/system.slice/'+self.unit+'\n')
            (directory/'ns/pid').symlink_to('pid:[123]')

    def resolve(self, role='permit'):
        return faults.target_identity(self.binding, self.record, role, proc=self.proc, cgroup=self.cgroup)

    def test_each_role_resolves_only_a_direct_child_in_the_bound_cgroup(self):
        for role, pid in (('permit', 201), ('observer', 202), ('qemu', 203)):
            with self.subTest(role=role):
                resolved = self.resolve(role)
                self.assertEqual(resolved['pid'], pid)
                self.assertEqual(resolved['parent_pid'], 200)
                self.assertEqual(resolved['supervisor_host_pid'], 200)

    def test_wrong_cgroup_namespace_and_parent_are_refused(self):
        paths = {'cgroup': '0::/unrelated.service\n', 'status': 'PPid:\t999\nNSpid:\t201 11\n'}
        for name, replacement in paths.items():
            path = self.proc/'201'/name
            original = path.read_text()
            with self.subTest(name=name):
                path.write_text(replacement)
                with self.assertRaisesRegex(RuntimeError, 'child not found'):
                    self.resolve()
                path.write_text(original)
        path = self.proc/'201/ns/pid'
        path.unlink(); path.symlink_to('pid:[999]')
        with self.assertRaisesRegex(RuntimeError, 'child not found'):
            self.resolve()

    def test_other_attempt_and_reused_supervisor_are_refused(self):
        for changes in ({'unit': 'other.service'}, {'supervisor_start_ticks': 988},
                        {'schema': True}, {'supervisor_pid': True}):
            with self.subTest(changes=changes):
                original = self.record
                self.record = original | changes
                with self.assertRaises(RuntimeError):
                    self.resolve()
                self.record = original

    def test_resumed_or_unobserved_boundary_is_not_eligible(self):
        self.assertFalse(faults.at_boundary({'events': []}, 1))
        held = {'events': [{'event': 'maps_held', 'point': 1}]}
        self.assertTrue(faults.at_boundary(held, 1))
        held['events'].append({'event': 'command', 'command': 'RESUME 1'})
        self.assertFalse(faults.at_boundary(held, 1))
        self.assertFalse(faults.at_boundary({'events': [{'event': 'maps_held', 'point': 2}]}, 2))

    def test_cancelled_and_missing_cases_never_send_a_signal(self):
        directory = self.root/'case'
        directory.mkdir()
        (directory/'fault-cancel').touch()
        with patch.object(faults.signal, 'pidfd_send_signal') as send:
            with self.assertRaisesRegex(RuntimeError, 'cancelled'):
                faults.inject(directory, 'kill-permit-before-permit')
            (directory/'fault-cancel').unlink()
            with patch.object(faults.time, 'monotonic', side_effect=(0, 1, 40)), \
                 patch.object(faults.time, 'sleep'):
                with self.assertRaises(TimeoutError):
                    faults.inject(directory, 'kill-permit-before-permit')
            send.assert_not_called()

    def test_pidfd_is_checked_again_and_closed_after_the_signal(self):
        directory = self.root/'case'
        run = directory/'session/iterations/0000/run'
        config = run/'config'
        output = run/'logs/capsule'
        config.mkdir(parents=True); output.mkdir(parents=True)
        binding = self.binding | {'run_dir': str(run), 'settings': {'analysis_policy': {}, 'control_guard': {}}}
        base.c.p.write_json(config/'capsule_binding.json', binding)
        base.c.p.write_json(output/'workers.json', self.record)
        base.c.p.write_json(output/'observer-events.json', {'schema': 2, 'events': [{'event': 'maps_held', 'point': 1}]})
        original = faults.target_identity
        def resolve(bound, record, role):
            return original(bound, record, role, proc=self.proc, cgroup=self.cgroup)
        with patch.object(faults, 'target_identity', side_effect=resolve) as checked, \
             patch.object(faults.os, 'pidfd_open', return_value=71) as opened, \
             patch.object(faults.signal, 'pidfd_send_signal') as send, \
             patch.object(faults.os, 'close') as close:
            result = faults.inject(directory, 'kill-permit-before-permit')
            self.assertEqual(result['status'], 'injected')
            self.assertEqual(checked.call_count, 2)
            opened.assert_called_once_with(201)
            send.assert_called_once_with(71, faults.signal.SIGKILL)
            close.assert_called_once_with(71)


class LifecycleCollectionTests(unittest.TestCase):
    setUp = base.InputRetirementTests.setUp
    prepare_guarded = guarded.ControlIntegrationTests.prepare_guarded
    invoke = base.InputRetirementTests.invoke

    def prepare_input(self, **kwargs):
        kwargs['name'] = self.case_name
        return base.InputRetirementTests.prepare_input(self, **kwargs)

    def fixture(self):
        from scripts import collect_capsule_lifecycle_evidence as collector
        from scripts.run_capsule_lifecycle_tests import SOURCES
        from scripts.run_capsule_lifecycle_e2e import PROFILE
        root = self.base
        self.case_name = 'analysis/e2e/research-normal'
        out, launch = self.prepare_guarded()
        executor = base.InputExecutor()
        with patch.object(base, 'synthetic_evidence', side_effect=guarded.guarded_evidence):
            report, code = self.invoke(out, launch, executor)
        self.assertEqual(code, 0, report.get('error'))
        proof = executor.runs[0][0]/'retirement-evidence'
        digest = base.c.p.sha(proof/'bundle.json')
        hashes = {'qemu_sha256': base.c.p.sha(self.qemu), 'phase1_sha256': base.c.p.sha(self.plugin)}
        base.c.p.write_json(root/'analysis/e2e/report.json', hashes | {'cases': [{'attempts': [{'bundle_sha256': digest}]}]})
        cases = []
        for name, (role, point) in faults.CASES.items():
            self.case_name = 'e2e/'+name
            out, launch = self.prepare_guarded()
            executor = base.InputExecutor(exit_code=125 if point == 2 else 137)
            def interrupted(run, code, fault=None):
                binding, result = guarded.guarded_evidence(run, code)
                result.update(status='failed', qemu_exit=125 if point == 2 else -9)
                base.c.p.write_json(run/'logs/capsule/supervisor.json', result)
                path = run/'logs/capsule/observer-events.json'
                journal = base.c.read_json(path)
                index = next(i for i, e in enumerate(journal['events']) if e['event'] == 'maps_held' and e['point'] == point)
                journal['events'] = journal['events'][:index+1]
                base.c.p.write_json(path, journal)
                if point == 1:
                    path = retirement.directory(binding)/'retirement.json'
                    saved = base.c.read_json(path)
                    saved.update(status='failed', permit_sent=False, events=[])
                    base.c.p.write_json(path, saved)
                else:
                    trace = run/'logs/qemu_strace.log'
                    trace.write_text(trace.read_text()+'OBSERVER_ABORT code=125 reason=controller_lost\n')
                return binding, result
            with patch.object(base, 'synthetic_evidence', side_effect=interrupted):
                report, code = self.invoke(out, launch, executor)
                self.assertEqual(code, 1)
                resumed, code = self.invoke(out, launch, executor)
            run, binding, supervisor = executor.runs[0]
            identity = {k: binding[k] for k in base.mappings.IDENTITY}
            workers = {'schema': 1, 'identity': identity, 'unit': base.resources.unit_name(binding),
                'pid_scope': 'sandbox_pid_namespace', 'pid_namespace': 'pid:[123]', 'supervisor_pid': 10,
                'supervisor_start_ticks': 987, 'workers': {'permit': 11, 'observer': 12}, 'qemu_pid': 77}
            base.c.p.write_json(run/'logs/capsule/workers.json', workers)
            injection = {'schema': 1, 'case': name, 'status': 'injected', 'signal': 'SIGKILL',
                'identity': identity, 'unit': workers['unit'], 'point': point,
                'pre_signal_journal': base.c.read_json(run/'logs/capsule/observer-events.json'),
                'target': {'role': role, 'pid': 201, 'parent_pid': 200, 'supervisor_host_pid': 200,
                    'start_ticks': 987, 'namespace_pid': 77 if role == 'qemu' else workers['workers'][role],
                    'pid_namespace': workers['pid_namespace'], 'cgroup': '0::/system.slice/'+workers['unit']}}
            base.c.p.write_json(out/'fault-injection.json', injection)
            base.c.p.write_json(out/'resume_report.json', resumed)
            (out/'fault-helper.log').write_text('synthetic collection fixture\n')
            cases.append({'name': name, 'status': 'passed', 'injection': injection, 'supervisor': supervisor,
                'claim_sha256': base.c.p.sha(run.parent/'execution_attempt.json'), 'resume_executions': 0})
        base.c.p.write_json(root/'e2e/report.json', hashes | {'profile': PROFILE, 'status': 'passed',
            'cases': cases, 'runtime_unchanged': True, 'native_cleanup_interruption_tested': False,
            'native_strict_positive_verified': False})
        validation = root/'validation'
        validation.mkdir()
        project = Path(__file__).resolve().parents[1]
        base.c.p.write_json(validation/'lifecycle-tests.json', {'successful': True, 'tests_run': 25,
            'tests_expected': 25, 'skipped': 0, 'failures': 0, 'errors': 0,
            'native_qemu_faults_tested_by_this_suite': False,
            'source_sha256': {name: base.c.p.sha(project/name) for name in SOURCES}})
        for name in ('lifecycle-tests.log', 'analysis.log', 'e2e.log'):
            (validation/name).write_text('synthetic collection fixture\n')
        base.c.p.write_json(validation/'strict-audit.json', audit(proof, digest))
        return collector, root

    def test_complete_archive_replays_after_relocation_and_rejects_changed_semantics(self):
        collector, root = self.fixture()
        with patch.object(collector.analysis, 'check_results'):
            result = collector.collect(root, 0)
            self.assertTrue(result['complete'], result)
            with tempfile.TemporaryDirectory() as temporary:
                with tarfile.open(result['archive']) as archive:
                    archive.extractall(temporary, filter='data')
                moved = Path(temporary)/'evidence'
                original = {str(p.relative_to(moved)): base.c.p.sha(p) for p in moved.rglob('*') if p.is_file()}
                collector.check_results(moved)
                self.assertEqual(original, {str(p.relative_to(moved)): base.c.p.sha(p) for p in moved.rglob('*') if p.is_file()})
                path = moved/'validation/strict-audit.json'
                original_bytes = path.read_bytes()
                value = base.c.read_json(path)
                value['native_strict_positive_verified'] = True
                base.c.p.write_json(path, value)
                with self.assertRaisesRegex(RuntimeError, 'Strict capability'):
                    collector.check_results(moved)
                path.write_bytes(original_bytes)
                path = moved/'e2e/kill-permit-before-permit/fault-injection.json'
                value = base.c.read_json(path)
                value['target']['namespace_pid'] = 999
                base.c.p.write_json(path, value)
                report_path = moved/'e2e/report.json'
                report = base.c.read_json(report_path)
                report['cases'][0]['injection'] = value
                base.c.p.write_json(report_path, report)
                with self.assertRaisesRegex(RuntimeError, 'bound capsule child'):
                    collector.check_results(moved)

    def test_partial_collection_preserves_exit_and_cannot_claim_acceptance(self):
        from scripts.collect_capsule_lifecycle_evidence import collect
        root = self.base/'partial'
        (root/'validation').mkdir(parents=True)
        (root/'validation/failure.log').write_text('controlled failure\n')
        result = collect(root, 42)
        self.assertFalse(result['complete'])
        with tarfile.open(result['archive']) as archive:
            saved = json.load(archive.extractfile('evidence/collection.json'))
        self.assertEqual(saved['command_exit_code'], 42)
        self.assertTrue(saved['missing_required'])


class SupervisorFailureTests(unittest.TestCase):
    setUp = base.InputRetirementTests.setUp
    prepare_input = base.InputRetirementTests.prepare_input
    prepare_guarded = guarded.ControlIntegrationTests.prepare_guarded
    invoke = base.InputRetirementTests.invoke

    def check_worker_loss(self, role, *, hardened=False):
        out, launch = self.prepare_guarded() if hardened else self.prepare_input()
        executor = base.InputExecutor()
        with patch.object(base, 'synthetic_evidence', side_effect=guarded.guarded_evidence if hardened else base.synthetic_evidence):
            report, code = self.invoke(out, launch, executor)
        self.assertEqual(code, 0, report.get('error'))
        run, binding, _ = executor.runs[0]
        context = Mock()
        context.Pipe.side_effect = lambda: (Mock(), Mock())
        workers = [Mock(pid=111, exitcode=-9 if role == 'permit' else None),
                   Mock(pid=112, exitcode=-9 if role == 'observer' else None)]
        context.Process.side_effect = workers
        for worker in workers:
            worker.is_alive.return_value = False
        process = Mock(pid=77)
        process.poll.side_effect = lambda: -9 if process.kill.called else None

        def wait(timeout):
            if process.kill.called:
                return -9
            time.sleep(min(timeout, .01))
            raise subprocess.TimeoutExpired('qemu', timeout)

        process.wait.side_effect = wait
        with tempfile.TemporaryDirectory() as ipc, \
             patch.object(m3.mp, 'get_context', return_value=context), \
             patch.object(m3.p, 'wait_worker_ready'), \
             patch.object(base.resources, 'inspect_self', return_value=base.resource_entry(binding)), \
             patch.object(m3.subprocess, 'Popen', return_value=process):
            self.assertEqual(m3.supervise(binding, ipc), 137)
        saved = base.c.read_json(run/'logs/capsule/supervisor.json')
        self.assertEqual(saved['failure']['component'], role)
        self.assertEqual(saved['failure']['category'], 'controller_failure')
        self.assertEqual(saved['worker_exit']['exitcode'], -9)
        self.assertTrue(saved['supervisor_kill'])
        process.kill.assert_called_once()

    def test_dead_permit_worker_is_reported_before_the_guest_deadline(self):
        self.check_worker_loss('permit')

    def test_dead_observer_worker_is_reported_before_the_guest_deadline(self):
        self.check_worker_loss('observer')

    def test_m4_budget_sampling_keeps_controller_failure_identity(self):
        self.check_worker_loss('permit', hardened=True)


if __name__ == '__main__':
    unittest.main()
