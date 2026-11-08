"""Sudo lifecycle tests with fake authentication and command execution only."""
from contextlib import contextmanager
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import types
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import sudo_session as module
from taintforge_env.prebuilt_runner import CommandResult, SubprocessCommandExecutor


class ManualThread:
    def __init__(self, *, target, name, daemon):
        self.target, self.name, self.daemon = target, name, daemon
        self.started = self.joined = False

    def start(self):
        self.started = True

    def join(self, timeout):
        self.joined = True

    def is_alive(self):
        return False


class OneTick:
    def __init__(self):
        self.waits = 0
        self.stopped = False

    def wait(self, interval):
        self.waits += 1
        return self.stopped or self.waits > 1

    def set(self):
        self.stopped = True


class SudoSessionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='tf-sudo-session-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.calls, self.executions, self.terminals = [], [], []
        self.creds = (1000, 1000, 1000, 1000, ())
        self.source_changed = False
        self.runner_effect = None
        self.execution_effect = None

        def original(executor, command, **kwargs):
            self.executions.append((list(command), kwargs))
            if self.execution_effect is not None:
                raise self.execution_effect
            return CommandResult(returncode=0, stdout='kept stdout', stderr='kept stderr')

        self.original = original
        self.patch = patch.object(SubprocessCommandExecutor, 'run', original)
        self.patch.start()
        self.addCleanup(self.patch.stop)
        self.addCleanup(self.assert_no_session)

    def assert_no_session(self):
        self.assertIsNone(module._ACTIVE)

    def runner(self, argv, **kwargs):
        self.calls.append((list(argv), kwargs))
        if self.runner_effect is not None:
            return self.runner_effect(argv, kwargs)
        return types.SimpleNamespace(returncode=0, stdout='', stderr='')

    def pin(self, path):
        return dict(path=str(path), sha256=('2' if self.source_changed else '1') * 64, size=123)

    @contextmanager
    def tty(self):
        sentinel = object()
        self.terminals.append(sentinel)
        yield sentinel

    def guard(self, name='sudo.json', **kwargs):
        parameters = dict(out=self.root / name, _runner=self.runner, _identity=self.pin,
            _credentials=lambda: self.creds, _resolve=lambda: Path('/usr/bin/sudo'),
            _tty=self.tty, _thread=ManualThread)
        parameters.update(kwargs)
        return module.SudoSession(**parameters)

    def test_cached_authentication_stays_unprivileged_and_restores_executor(self):
        guard = self.guard()
        with guard:
            self.assertTrue(guard.active)
            result = SubprocessCommandExecutor().run(['sudo', 'systemd-run', '--wait', 'true'], cwd=self.root)
            self.assertEqual(result.stdout, 'kept stdout')
        summary = json.loads(guard.out.read_text())
        self.assertTrue(summary['healthy'])
        self.assertFalse(summary['active'])
        self.assertTrue(summary['thread_stopped'])
        self.assertTrue(summary['executor_binding_restored'])
        self.assertEqual(summary['initial_authentication'], 'cached')
        self.assertIs(SubprocessCommandExecutor.run, self.original)

    def test_effective_sudo_argv_adds_noninteractive_option_and_preserves_payload(self):
        guard = self.guard()
        logical = ['sudo', 'systemd-run', '--property=MemoryMax=1024', 'unshare', '--', 'sample']
        with guard:
            SubprocessCommandExecutor().run(logical, cwd=self.root, check=False)
        effective, kwargs = self.executions[0]
        self.assertEqual(effective, ['/usr/bin/sudo', '-n', *logical[1:]])
        self.assertEqual(kwargs, dict(cwd=self.root, check=False))
        row = guard.summary()['commands'][0]
        self.assertEqual(row['original_logical_argv'], logical)
        self.assertEqual(row['effective_executor_argv'], effective)

    def test_existing_noninteractive_option_is_not_duplicated(self):
        with self.guard() as guard:
            SubprocessCommandExecutor().run(['sudo', '-n', 'true'], cwd=self.root)
        self.assertEqual(self.executions[0][0], ['/usr/bin/sudo', '-n', 'true'])
        self.assertEqual(guard.summary()['injected_noninteractive_options'], 0)

    def test_nonprivileged_commands_pass_through_unchanged(self):
        argv = ['python3', '-B', 'script.py']
        with self.guard() as guard:
            SubprocessCommandExecutor().run(argv, cwd=self.root)
        self.assertEqual(self.executions[0][0], argv)
        self.assertEqual(guard.summary()['privileged_commands'], 0)

    def test_initial_cache_miss_authenticates_only_on_explicit_foreground_tty(self):
        seen = 0

        def effect(argv, kwargs):
            nonlocal seen
            seen += 1
            return types.SimpleNamespace(returncode=1 if seen == 1 else 0)

        self.runner_effect = effect
        with self.guard() as guard:
            pass
        interactive = [(argv, kwargs) for argv, kwargs in self.calls if argv == ['/usr/bin/sudo', '-v']]
        self.assertEqual(len(interactive), 1)
        for field in ('stdin', 'stdout', 'stderr'):
            self.assertIs(interactive[0][1][field], self.terminals[0])
        self.assertNotIn('input', interactive[0][1])
        self.assertEqual(guard.summary()['initial_authentication'], 'foreground_tty')
        self.assertEqual(guard.summary()['initial_cached_auth_failures'], 1)
        self.assertEqual(guard.summary()['refresh_failures'], 0)
        self.assertTrue(guard.summary()['healthy'])

    def test_background_authentication_never_requests_or_captures_a_password(self):
        with self.guard() as guard:
            guard._stop = OneTick()
            guard._refresh_loop()
        for argv, kwargs in self.calls:
            self.assertEqual(argv[1], '-n')
            self.assertIs(kwargs['stdin'], subprocess.DEVNULL)
            self.assertNotIn('input', kwargs)
            self.assertNotIn('start_new_session', kwargs)
            self.assertNotIn('preexec_fn', kwargs)
        self.assertEqual(guard.summary()['refresh_successes'], 1)

    def test_refresh_rejection_blocks_new_launches_and_marks_final_result_failed(self):
        guard = self.guard()
        with self.assertRaises(RuntimeError):
            with guard:
                self.runner_effect = lambda argv, kwargs: types.SimpleNamespace(returncode=1)
                guard._stop = OneTick()
                guard._refresh_loop()
                with self.assertRaises(RuntimeError):
                    SubprocessCommandExecutor().run(['sudo', 'systemd-run', 'true'], cwd=self.root)
        self.assertFalse(self.executions)
        self.assertEqual(guard.summary()['refresh_failures'], 1)
        self.assertFalse(guard.summary()['healthy'])

    def test_exact_ownership_cleanup_is_still_attempted_after_authentication_failure(self):
        guard = self.guard()
        with self.assertRaises(RuntimeError):
            with guard:
                guard._fail('expired during a previous operation')
                SubprocessCommandExecutor().run(['sudo', 'chown', '-R', '--no-dereference', '--',
                    '1000:1000', str(self.root / 'case')], cwd=self.root)
        self.assertEqual(len(self.executions), 1)
        self.assertEqual(self.executions[0][0][1:3], ['-n', 'chown'])
        self.assertEqual(guard.summary()['cleanup_attempts_while_unhealthy'], 1)

    def test_other_chown_commands_do_not_bypass_unhealthy_session(self):
        guard = self.guard()
        with self.assertRaises(RuntimeError):
            with guard:
                guard._fail('expired')
                SubprocessCommandExecutor().run(['sudo', 'chown', '-R', '--no-dereference', '--',
                    '0:0', str(self.root)], cwd=self.root)
        self.assertFalse(self.executions)

    def test_expiry_detected_before_each_payload_is_not_retried_interactively(self):
        guard = self.guard()
        with self.assertRaises(RuntimeError):
            with guard:
                self.runner_effect = lambda argv, kwargs: types.SimpleNamespace(returncode=1)
                SubprocessCommandExecutor().run(['sudo', 'systemd-run', 'true'], cwd=self.root)
        self.assertEqual(guard.summary()['command_auth_failures'], 1)
        self.assertFalse(self.terminals)
        self.assertFalse(self.executions)

    def test_cleanup_executor_failure_keeps_original_exception_semantics(self):
        guard = self.guard()
        failure = ValueError('original executor cleanup failed')
        self.execution_effect = failure
        with self.assertRaises(ValueError) as caught:
            with guard:
                SubprocessCommandExecutor().run(['sudo', 'chown', '-R', '--no-dereference', '--',
                    '1000:1000', str(self.root)], cwd=self.root)
        self.assertIs(caught.exception, failure)
        self.assertEqual(guard.summary()['executor_failures'], 1)
        self.assertIs(SubprocessCommandExecutor.run, self.original)

    def test_concurrent_health_failure_is_not_undone_by_successful_command_validation(self):
        guard = self.guard()

        def fail_during_success(argv, kwargs):
            guard._fail('background refresh failed during the command check')
            return types.SimpleNamespace(returncode=0)

        with self.assertRaises(RuntimeError):
            with guard:
                self.runner_effect = fail_during_success
                SubprocessCommandExecutor().run(['sudo', 'systemd-run', 'true'], cwd=self.root)
        self.assertFalse(self.executions)
        self.assertFalse(guard.summary()['healthy'])

    def test_active_primary_exception_is_not_masked_by_journal_failure(self):
        guard = self.guard()
        primary = LookupError('active primary failure')
        with self.assertRaises(LookupError) as caught:
            with guard:
                guard._save = lambda: (_ for _ in ()).throw(OSError('journal write failed'))
                raise primary
        self.assertIs(caught.exception, primary)
        self.assertIs(SubprocessCommandExecutor.run, self.original)

    def test_journal_failure_without_primary_prevents_success(self):
        guard = self.guard()
        with self.assertRaises(OSError):
            with guard:
                guard._save = lambda: (_ for _ in ()).throw(OSError('journal write failed'))
        self.assertIs(SubprocessCommandExecutor.run, self.original)

    def test_root_driver_is_rejected_without_authentication(self):
        self.creds = (0, 0, 0, 0, ())
        with self.assertRaises(RuntimeError):
            with self.guard():
                pass
        self.assertFalse(self.calls)

    def test_existing_journal_and_nested_context_are_rejected(self):
        guard = self.guard()
        guard.out.write_bytes(b'keep existing evidence')
        with self.assertRaises(RuntimeError):
            guard.__enter__()
        with self.guard('other.json'):
            with self.assertRaises(RuntimeError):
                self.guard('nested.json').__enter__()
        self.assertEqual(guard.out.read_bytes(), b'keep existing evidence')

    def test_same_session_cannot_be_reused(self):
        guard = self.guard()
        with guard:
            pass
        with self.assertRaises(RuntimeError):
            guard.__enter__()

    def test_identity_or_path_mutation_prevents_payload_execution(self):
        guard = self.guard()
        with self.assertRaises(RuntimeError):
            with guard:
                self.source_changed = True
                SubprocessCommandExecutor().run(['sudo', 'true'], cwd=self.root)
        self.assertFalse(self.executions)

    def test_credentials_cannot_change_after_authentication(self):
        guard = self.guard()
        with self.assertRaises(RuntimeError):
            with guard:
                self.creds = (1001, 1001, 1001, 1001, ())
                SubprocessCommandExecutor().run(['sudo', 'true'], cwd=self.root)
        self.assertFalse(self.executions)

    def test_changed_executor_binding_is_restored_and_fails_acceptance(self):
        guard = self.guard()
        with self.assertRaises(RuntimeError):
            with guard:
                SubprocessCommandExecutor.run = lambda *args, **kwargs: None
        self.assertIs(SubprocessCommandExecutor.run, self.original)
        self.assertFalse(guard.summary()['healthy'])

    def test_refresh_timeout_is_bounded_and_counted(self):
        guard = self.guard()
        with self.assertRaises(RuntimeError):
            with guard:
                self.runner_effect = lambda argv, kwargs: (_ for _ in ()).throw(subprocess.TimeoutExpired(argv, 10))
                guard._stop = OneTick()
                guard._refresh_loop()
        self.assertEqual(guard.summary()['refresh_failures'], 1)
        self.assertFalse(guard.summary()['healthy'])

    def test_controlled_real_refresh_thread_stops_before_context_returns(self):
        guard = self.guard(_thread=threading.Thread, _event=OneTick)
        with guard:
            guard._thread.join(timeout=2)
            self.assertFalse(guard._thread.is_alive())
        self.assertTrue(guard.summary()['thread_stopped'])
        self.assertEqual(guard.summary()['process_id'], os.getpid())
        self.assertEqual(guard.summary()['refresh_checks'], 1)

    def test_thread_that_does_not_stop_prevents_acceptance(self):
        class Stuck(ManualThread):
            def is_alive(self):
                return True
        guard = self.guard(_thread=Stuck)
        with self.assertRaises(RuntimeError):
            with guard:
                pass
        self.assertFalse(guard.summary()['thread_stopped'])
        self.assertIs(SubprocessCommandExecutor.run, self.original)

    def test_command_budget_and_owned_summary_do_not_hide_execution(self):
        guard = self.guard(max_commands=1)
        with self.assertRaises(RuntimeError):
            with guard:
                SubprocessCommandExecutor().run(['sudo', 'true'], cwd=self.root)
                snapshot = guard.summary()
                snapshot['commands'][0]['original_logical_argv'][0] = 'changed outside guard'
                self.assertEqual(guard.summary()['commands'][0]['original_logical_argv'][0], 'sudo')
                SubprocessCommandExecutor().run(['sudo', 'true'], cwd=self.root)
        self.assertEqual(len(self.executions), 1)

    def test_foreground_terminal_contract_refuses_background_authentication(self):
        terminal = types.SimpleNamespace(fileno=lambda: 44, close=lambda: None)
        with patch('builtins.open', return_value=terminal), patch.object(os, 'isatty', return_value=True), \
             patch.object(os, 'tcgetpgrp', return_value=999), patch.object(os, 'getpgrp', return_value=555):
            with self.assertRaises(RuntimeError):
                module.foreground_terminal()

    def test_one_bounded_cleanup_slot_remains_after_last_payload_exhausts_journal(self):
        guard = self.guard(max_commands=1)
        with self.assertRaises(RuntimeError):
            with guard:
                SubprocessCommandExecutor().run(['sudo', 'systemd-run', 'true'], cwd=self.root)
                guard._fail('ticket refresh failed after the last launch')
                cleanup = ['sudo', 'chown', '-R', '--no-dereference', '--', '1000:1000', str(self.root)]
                SubprocessCommandExecutor().run(cleanup, cwd=self.root)
                with self.assertRaises(RuntimeError):
                    SubprocessCommandExecutor().run(cleanup, cwd=self.root)
        self.assertEqual(len(self.executions), 2)
        self.assertEqual(guard.summary()['emergency_cleanup_records'], 1)
        self.assertEqual(guard.summary()['command_count'], 2)


if __name__ == '__main__':
    unittest.main()
