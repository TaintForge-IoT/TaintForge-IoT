"""NET-5 expected interruptions retain incomplete observer evidence as incomplete."""
from contextlib import redirect_stderr, redirect_stdout
import inspect
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from scripts import run_network_runtime_e2e as runner
from taintforge_env.network_runtime import NetworkRuntimeLimits
from tests.test_network_endpoints import capture_rows


RECEIVE = 'network_receive_budget_exceeded'


def rows_for(session, attempt, mode='complete'):
    rows = capture_rows()
    for row in rows:
        row.update(session_id=session, attempt_id=attempt)
    if mode == 'incomplete':
        rows.pop()
    elif mode == 'missing_start':
        rows = []
    elif mode == 'identity_mismatch':
        rows[1]['attempt_id'] = 'foreign'
    elif mode == 'unsupported_profile':
        rows[0]['profile'] = 'unsupported'
    elif mode == 'uncorrelated':
        rows[2]['fd'] = 7
    return rows


TRACE = ('24 socket(PF_INET,SOCK_STREAM,IPPROTO_IP) = 4\n'
         '24 connect(4,0x804a000,16) = -1 errno=111 (Connection refused)\n')


class RuntimeGuestEvidenceTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.ordinal = 0

    def guest(self, *, mode='incomplete', expected=RECEIVE, runtime=RECEIVE, reason=RECEIVE,
              code=143, goal=False, expected_goal=False, guard_change=None):
        root = self.root / str(self.ordinal)
        self.ordinal += 1
        root.mkdir()
        attempt = runner.Attempt.__new__(runner.Attempt)
        attempt.root, attempt.name = root, 'shared_receive'
        attempt.qemu, attempt.observer, attempt.binary = (root / name for name in ('qemu', 'observer', 'client'))
        attempt.owner = SimpleNamespace(attempt_id='net5-shared_receive', client_path=root / 'runtime.json',
            snapshot=lambda: {'termination_reason': runtime})
        attempt.limits = NetworkRuntimeLimits()
        attempt.ports, attempt.executions = [4444, 4445], []
        guard = {'schema_version': 1, 'attempt_id': attempt.owner.attempt_id,
                 'guest_process_stopped': True, 'command_exit_code': -15 if code == 143 else code,
                 'termination_reason': reason, **(guard_change or {})}

        def spawn(command, **kwargs):
            directory = Path(kwargs['stdout'].name).parent
            kwargs['stdout'].write(b'NET4_OK\n' if goal else b'')
            kwargs['stdout'].flush()
            kwargs['stderr'].write(TRACE.encode())
            kwargs['stderr'].flush()
            (directory / 'endpoints.jsonl').write_text(''.join(json.dumps(row) + '\n'
                for row in rows_for(attempt.name, attempt.owner.attempt_id, mode)))
            (directory / 'guard.json').write_text(json.dumps(guard))
            return SimpleNamespace(wait=lambda timeout=None: code, poll=lambda: code)

        options = {'expected_goal': expected_goal}
        if 'expected_reason' in inspect.signature(runner.Attempt.guest).parameters:
            options['expected_reason'] = expected
        with patch.object(runner.subprocess, 'Popen', side_effect=spawn), \
             patch.object(runner, 'plugin_argument', return_value='fixture-observer'):
            attempt.guest(**options)
        return attempt.executions[0]

    def test_expected_receive_stop_accepts_a_missing_footer_without_claiming_correlation(self):
        observed = self.guest()
        self.assertEqual(observed['net2_observer_status'], 'incomplete')
        self.assertEqual(observed['observer']['matched'], 0)
        self.assertEqual(observed['observer']['reason'], 'missing complete observer footer')
        self.assertFalse(observed['goal_reached'])
        self.assertEqual(observed['guard_reason'], RECEIVE)

    def test_success_still_requires_complete_correlated_evidence(self):
        with self.assertRaisesRegex(RuntimeError, 'did not correlate'):
            self.guest(expected=None, runtime=None, reason=None, code=0, goal=True, expected_goal=True)

    def test_complete_successful_observation_is_preserved(self):
        observed = self.guest(mode='complete', expected=None, runtime=None, reason=None,
                              code=0, goal=True, expected_goal=True)
        self.assertEqual(observed['net2_observer_status'], 'correlated')
        self.assertEqual(observed['observer']['matched'], 2)

    def test_complete_negative_observation_is_preserved(self):
        self.assertEqual(self.guest(mode='complete', code=14)['net2_observer_status'], 'correlated')

    def test_expected_budget_and_responder_interruptions_share_the_same_checks(self):
        for reason in (RECEIVE, 'network_send_budget_exceeded', 'network_log_budget_exceeded',
                       'network_connection_budget_exceeded', 'network_responder_exited'):
            with self.subTest(reason=reason):
                self.assertEqual(self.guest(expected=reason, runtime=reason, reason=reason)['guard_reason'], reason)

    def test_foreign_guard_attempt_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError, 'bound guest exit'):
            self.guest(guard_change={'attempt_id': 'foreign'})

    def test_unconfirmed_guest_stop_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError, 'bound guest exit'):
            self.guest(guard_change={'guest_process_stopped': False})

    def test_guard_exit_mismatch_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError, 'wrapper exit'):
            self.guest(guard_change={'command_exit_code': 0})

    def test_boolean_guard_exit_is_not_an_integer_exit(self):
        with self.assertRaisesRegex(RuntimeError, 'wrapper exit'):
            self.guest(code=1, guard_change={'command_exit_code': True})

    def test_guard_and_ledger_must_match_the_expected_reason(self):
        for changes in ({'reason': 'network_responder_exited'}, {'runtime': 'network_responder_exited'},
                        {'runtime': None}, {'reason': None}):
            with self.subTest(changes=changes), self.assertRaisesRegex(RuntimeError, 'unexpected runtime/guard'):
                self.guest(**changes)

    def test_unexpected_infrastructure_stop_is_not_an_expected_budget_stop(self):
        with self.assertRaises(ValueError):
            self.guest(expected='network_runtime_owner_lost', runtime='network_runtime_owner_lost',
                       reason='network_runtime_owner_lost')

    def test_negative_case_cannot_report_a_zero_exit(self):
        with self.assertRaisesRegex(RuntimeError, 'incorrect client goal'):
            self.guest(code=0)

    def test_budget_interruption_cannot_claim_the_positive_goal(self):
        with self.assertRaises(ValueError):
            self.guest(goal=True, expected_goal=True)

    def test_missing_start_and_invalid_observer_profiles_remain_failures(self):
        for mode in ('missing_start', 'identity_mismatch', 'unsupported_profile', 'uncorrelated'):
            with self.subTest(mode=mode), self.assertRaisesRegex(RuntimeError, 'did not correlate') as caught:
                self.guest(mode=mode)
            self.assertIn('incomplete' if mode == 'missing_start' else mode, str(caught.exception))

    def test_case_calls_pass_the_declared_reason_to_negative_guests(self):
        for name, reason in (('shared_receive', RECEIVE), ('shared_send', 'network_send_budget_exceeded'),
                             ('total_connections', 'network_connection_budget_exceeded'),
                             ('log_budget', 'network_log_budget_exceeded'), ('responder_crash', 'network_responder_exited')):
            calls = []
            owner = SimpleNamespace(closed=False)
            def close():
                owner.closed = True
                return {'termination_reason': reason, 'cleanup_status': 'cleaned',
                        'budget_usage': {'received_bytes': 0, 'sent_bytes_reserved': 0}}, 0
            attempt = SimpleNamespace(owner=owner, start=lambda: None, close=close,
                guest=lambda *args, **kwargs: calls.append(kwargs), limits=NetworkRuntimeLimits(), executions=[])
            with self.subTest(name=name), patch.object(runner, 'Attempt', return_value=attempt):
                runner.run_case(self.root / name, name, None, None, None, expected_reason=reason)
            negative = [call for call in calls if call.get('expected_goal') is False]
            self.assertEqual(len(negative), 1)
            self.assertEqual(negative[0]['expected_reason'], reason)

    def test_namespace_adapter_uses_the_same_interruption_rule(self):
        root = self.root / 'privileged'
        state = {'reason': None}
        class Backend:
            def __init__(backend, *args, **kwargs):
                backend.runtime = SimpleNamespace(attempt_id='net5-privileged',
                    snapshot=lambda: {'termination_reason': state['reason']})
                backend.plan = SimpleNamespace(host_services=[1], loopback_services=[1],
                    namespace_name='tf-fixture', veth_host='tfhfixture')
            def setup(backend): pass
            def guest_command(backend, script): return ['fixture-owned-guest', str(script)]
            def cleanup(backend):
                runner.write(root / 'logs/network_runtime_status.json',
                             {'termination_reason': RECEIVE, 'cleanup_status': 'cleaned'})

        def command(argv, **kwargs):
            if argv[0] == 'fixture-owned-guest':
                index = int(Path(argv[1]).stem.split('-')[-1])
                state['reason'] = None if index == 0 else RECEIVE
                rows = rows_for('net5-privileged', 'net5-privileged', 'complete' if index == 0 else 'incomplete')
                (root / 'logs' / f'privileged-{index}-endpoints.jsonl').write_text(
                    ''.join(json.dumps(row) + '\n' for row in rows))
                runner.write(root / 'config/network_guard_result.json', {'schema_version': 1,
                    'attempt_id': 'net5-privileged', 'guest_process_stopped': True,
                    'command_exit_code': 0 if index == 0 else -15, 'termination_reason': state['reason']})
                return subprocess.CompletedProcess(argv, 0 if index == 0 else 143,
                    b'NET4_OK\n' if index == 0 else b'', TRACE.encode())
            return subprocess.CompletedProcess(argv, 1 if argv[:3] == ['ip', 'link', 'show'] else 0, '', '')

        with patch.object(runner, 'ControlledNetworkBackend', Backend), \
             patch.object(runner.subprocess, 'run', side_effect=command), \
             patch.object(runner, 'plugin_argument', return_value='fixture-observer'):
            result = runner.privileged_case(root, Path('/fixture/qemu'), Path('/fixture/observer'), Path('/fixture/client'))
        self.assertEqual(result['status'], 'passed')
        summary = json.loads((root / 'logs/privileged-1-syscalls.summary.json').read_text())
        self.assertEqual(summary['network_endpoint_observer']['status'], 'incomplete')
        self.assertEqual(json.loads((root / 'logs/privileged-1-guard.json').read_text())['termination_reason'], RECEIVE)


class RuntimeFailureReportTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.qemu, self.observer = self.root / 'qemu', self.root / 'observer'
        self.qemu.write_text('fixture')
        self.observer.write_text('fixture')
        self.output = self.root / 'result'

    def invoke(self, run_case, *, metadata=None):
        arguments = ['net5-fixture', '--out', str(self.output), '--qemu', str(self.qemu), '--observer', str(self.observer)]
        with patch.object(sys, 'argv', arguments), patch.object(runner, 'validate_observer',
                side_effect=metadata or (lambda path: {'plugin_api': 6})), \
             patch.object(runner.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, 'QEMU fixture\n', '')), \
             patch.object(runner, 'run_case', side_effect=run_case), redirect_stderr(io.StringIO()), redirect_stdout(io.StringIO()):
            runner.main()

    @staticmethod
    def passed(root, name, *args):
        return {'case': name, 'status': 'passed', 'guest_executions': []}

    def test_failure_preserves_the_case_and_original_error_in_a_report(self):
        def case(root, name, *args):
            if name == 'shared_receive':
                raise RuntimeError('observer incomplete: missing complete observer footer')
            return self.passed(root, name, *args)
        with self.assertRaises(SystemExit) as caught:
            self.invoke(case)
        self.assertEqual(caught.exception.code, 1)
        report = json.loads((self.output / 'report.json').read_text())
        self.assertEqual(report['status'], 'failed')
        self.assertEqual([row['case'] for row in report['cases']], ['mixed_protocols', 'shared_receive'])
        self.assertEqual(report['cases'][-1]['status'], 'failed')
        self.assertIn('missing complete observer footer', report['cases'][-1]['error'])

    def test_setup_failure_still_has_a_failed_report(self):
        def metadata(path): raise RuntimeError('invalid observer fixture')
        with self.assertRaises(SystemExit):
            self.invoke(self.passed, metadata=metadata)
        report = json.loads((self.output / 'report.json').read_text())
        self.assertEqual(report['cases'], [])
        self.assertEqual(report['status'], 'failed')
        self.assertIn('invalid observer fixture', report['error'])

    def test_existing_output_is_not_rewritten(self):
        self.output.mkdir()
        saved = self.output / 'report.json'
        saved.write_text('previous evidence')
        with self.assertRaises(SystemExit): self.invoke(self.passed)
        self.assertEqual(saved.read_text(), 'previous evidence')

    def test_successful_matrix_keeps_the_component_scope(self):
        self.invoke(self.passed)
        report = json.loads((self.output / 'report.json').read_text())
        self.assertEqual(report['status'], 'passed')
        self.assertEqual(len(report['cases']), 7)
        self.assertFalse(report['phase1_executed'])
        self.assertFalse(report['capsule_executed'])
        self.assertFalse(report['namespace_executed'])


if __name__ == '__main__':
    unittest.main()
