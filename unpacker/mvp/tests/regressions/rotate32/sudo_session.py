"""Bounded sudo ticket maintenance for the unprivileged recovery driver.

No password is captured, saved or sent through a pipe. Optional authentication
uses only the foreground controlling terminal. The background validator and
executor children have this Python process as their parent. Project source
files and sudo policy are not modified. Normal validation refreshes the existing
credential ticket; this helper never invalidates it.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import threading
import time

from taintforge_env.prebuilt_runner import SubprocessCommandExecutor


_ACTIVE = None
MAX_COMMANDS = 4096
MAX_JOURNAL_BYTES = 8 * 1024**2


def require(value, message):
    if not value:
        raise RuntimeError(message)


def credentials():
    return os.getuid(), os.geteuid(), os.getgid(), os.getegid(), tuple(sorted(os.getgroups()))


def identity(path):
    path = Path(path).resolve(strict=True)
    before = path.stat()
    require(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= 64 * 1024**2,
            'Sudo control input is not a bounded regular file')
    with path.open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    after = path.stat()
    fields = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
    require(all(getattr(before, key) == getattr(after, key) for key in fields),
            'Sudo control input changed during read')
    return dict(path=str(path), sha256=digest, size=after.st_size,
                metadata={key: getattr(after, key) for key in fields})


def foreground_terminal():
    stream = open('/dev/tty', 'r+b', buffering=0)
    try:
        require(os.isatty(stream.fileno()) and os.tcgetpgrp(stream.fileno()) == os.getpgrp(),
                'Sudo authentication requires the foreground controlling terminal')
    except BaseException:
        stream.close()
        raise
    return stream


def resolve_sudo():
    result = shutil.which('sudo')
    require(result is not None, 'sudo is not in PATH')
    return Path(result).resolve(strict=True)


class SudoSession:
    """One non-root process session; refresh a ticket without changing policy.

    ``out`` is a new external JSON journal. Underscored dependencies allow local
    tests to exercise lifecycle failures without executing sudo or a guest.
    """

    def __init__(self, *, out, interval=30, timeout=10, max_commands=MAX_COMMANDS,
                 _runner=subprocess.run, _identity=identity, _credentials=credentials,
                 _resolve=resolve_sudo, _tty=foreground_terminal,
                 _event=threading.Event, _thread=threading.Thread, _clock=time.monotonic_ns):
        require(type(interval) in (int, float) and 1 <= interval <= 60 and
                type(timeout) in (int, float) and 1 <= timeout <= 30 and
                type(max_commands) is int and 1 <= max_commands <= MAX_COMMANDS,
                'Invalid sudo session budgets')
        self.out = Path(out).expanduser().absolute()
        require('..' not in self.out.parts and not any(path.is_symlink() for path in (self.out, *self.out.parents)),
                'Sudo journal must use normalized paths without symlinks')
        self.interval, self.timeout, self.max_commands = interval, timeout, max_commands
        self.runner, self.pin, self.read_credentials = _runner, _identity, _credentials
        self.resolve, self.tty, self.event_factory, self.thread_factory, self.clock = _resolve, _tty, _event, _thread, _clock
        self.active = self.healthy = self._used = False
        self._lock = threading.Lock()
        self._commands = []
        self._metrics = dict(initial_authentication=None, initial_cached_auth_failures=0,
            validation_checks=0, command_auth_checks=0, command_auth_failures=0,
            refresh_checks=0, refresh_successes=0,
            refresh_failures=0, privileged_commands=0, injected_noninteractive_options=0,
            cleanup_attempts_while_unhealthy=0, emergency_cleanup_records=0,
            executor_failures=0, thread_stopped=True)
        self._failure = None
        self._restored = False
        self._thread = None
        self._stop = None

    def _fail(self, message):
        with self._lock:
            self.healthy = False
            if self._failure is None:
                self._failure = str(message)[:2048]

    def _intact(self):
        require(os.getpid() == self._pid and self.read_credentials() == self._credentials,
                'Sudo control process or credentials changed')
        require(os.environ.get('PATH') == self._path and self.resolve() == self._sudo,
                'sudo PATH binding changed during recovery')
        require(self.pin(self._sudo) == self._sudo_identity,
                'sudo executable changed during recovery')
        require(all(self.pin(path) == expected for path, expected in self._sources.items()),
                'Sudo guard or original command executor changed')
        require(SubprocessCommandExecutor.run is self._installed and
                self._original.__code__ is self._original_code,
                'Sudo executor binding changed')

    def _validate(self, phase):
        # No setsid/start_new_session: retain the same terminal and Python PPID.
        with self._lock:
            self._metrics['validation_checks'] += 1
            if phase == 'refresh':
                self._metrics['refresh_checks'] += 1
            elif phase == 'command':
                self._metrics['command_auth_checks'] += 1
        try:
            result = self.runner([str(self._sudo), '-n', '-v'], stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=self.timeout, check=False)
        except BaseException:
            with self._lock:
                if phase == 'refresh':
                    self._metrics['refresh_failures'] += 1
                elif phase == 'command':
                    self._metrics['command_auth_failures'] += 1
            raise
        with self._lock:
            if phase == 'refresh':
                self._metrics['refresh_successes' if result.returncode == 0 else 'refresh_failures'] += 1
            elif phase == 'command' and result.returncode != 0:
                self._metrics['command_auth_failures'] += 1
            elif phase == 'initial' and result.returncode != 0:
                self._metrics['initial_cached_auth_failures'] += 1
        return result.returncode == 0

    def _refresh_loop(self):
        while not self._stop.wait(self.interval):
            try:
                self._intact()
                require(self._validate('refresh'), 'Noninteractive sudo ticket refresh failed')
            except BaseException as exc:
                self._fail(type(exc).__name__ + ': ' + str(exc))
                self._stop.set()
                return

    def __enter__(self):
        global _ACTIVE
        require(_ACTIVE is None and not self._used and not self.out.exists(),
                'Sudo session must be new and not nested')
        self._used = True
        self._pid, self._control_thread = os.getpid(), threading.get_ident()
        self._credentials, self._path = self.read_credentials(), os.environ.get('PATH')
        require(self._credentials[0] != 0 and self._credentials[1] != 0,
                'Run the recovery driver as the original unprivileged user')
        self._sudo = self.resolve()
        self._sudo_identity = self.pin(self._sudo)
        self._original = SubprocessCommandExecutor.run
        self._original_code = getattr(self._original, '__code__', None)
        require(self._original_code is not None, 'Original command executor is unavailable')
        self._sources = {Path(__file__).resolve(): self.pin(Path(__file__).resolve()),
            Path(self._original_code.co_filename).resolve(): self.pin(Path(self._original_code.co_filename).resolve())}
        self.out.parent.mkdir(parents=True, exist_ok=True)
        self._stop = self.event_factory()
        try:
            if self._validate('initial'):
                self._metrics['initial_authentication'] = 'cached'
            else:
                # Explicit tty attachment keeps the password away from logs and
                # captured stdout/stderr. Refuse background terminal use first.
                with self.tty() as terminal:
                    result = self.runner([str(self._sudo), '-v'], stdin=terminal,
                        stdout=terminal, stderr=terminal, text=True, timeout=120, check=False)
                require(result.returncode == 0 and self._validate('initial'),
                        'Foreground sudo authentication did not establish a usable ticket')
                self._metrics['initial_authentication'] = 'foreground_tty'
            check = self.runner([str(self._sudo), '-n', 'true'], stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=self.timeout, check=False)
            require(check.returncode == 0, 'Noninteractive sudo preflight failed')
            self.healthy = True

            def guarded(executor, command, **kwargs):
                return self._run(executor, command, **kwargs)

            self._installed = guarded
            SubprocessCommandExecutor.run = guarded
            self.active = True
            _ACTIVE = self
            self._intact()
            self._thread = self.thread_factory(target=self._refresh_loop,
                name='taintforge-sudo-ticket', daemon=True)
            self._metrics['thread_stopped'] = False
            self._thread.start()
            return self
        except BaseException as exc:
            self._fail(type(exc).__name__ + ': ' + str(exc))
            self._restore()
            self._save_preserving(exc)
            raise

    def _is_cleanup(self, command):
        return len(command) == 7 and command[1:5] == ['chown', '-R', '--no-dereference', '--'] and \
            command[5] == f'{self._credentials[0]}:{self._credentials[2]}'

    def _run(self, executor, command, **kwargs):
        argv = list(command)
        if not argv or argv[0] != 'sudo':
            return self._original(executor, command, **kwargs)
        require(self.active and _ACTIVE is self and threading.get_ident() == self._control_thread,
                'Privileged execution requires the original recovery control thread')
        cleanup = self._is_cleanup(argv)
        try:
            self._intact()
        except BaseException as exc:
            self._fail(type(exc).__name__ + ': ' + str(exc))
            raise
        with self._lock:
            healthy = self.healthy
        if healthy:
            try:
                require(self._validate('command'), 'Noninteractive sudo command ticket check failed')
            except BaseException as exc:
                self._fail(type(exc).__name__ + ': ' + str(exc))
        # A background refresh can fail while the command validation succeeds.
        # Health is sticky: a successful check must never undo that failure.
        with self._lock:
            healthy = self.healthy
        require(healthy or cleanup, 'Sudo session is unhealthy; refusing another privileged launch')
        emergency = cleanup and len(self._commands) == self.max_commands and \
            self._metrics['emergency_cleanup_records'] == 0
        capacity = len(self._commands) < self.max_commands or emergency
        if not capacity:
            self._fail('Sudo command journal budget exceeded')
        require(capacity and len(argv) <= 128 and
                all(isinstance(value, str) and len(value) <= 4096 for value in argv),
                'Sudo command journal budget exceeded')
        effective = [str(self._sudo)] + ([] if len(argv) > 1 and argv[1] == '-n' else ['-n']) + argv[1:]
        row = dict(index=len(self._commands), original_logical_argv=argv,
            effective_executor_argv=effective, cleanup=cleanup, session_healthy_at_start=healthy,
            started_ns=self.clock(), completed=False, emergency_cleanup_record=emergency)
        self._commands.append(row)
        self._metrics['privileged_commands'] += 1
        self._metrics['emergency_cleanup_records'] += int(emergency)
        self._metrics['injected_noninteractive_options'] += int(effective[1:] != argv[1:])
        if cleanup and not healthy:
            self._metrics['cleanup_attempts_while_unhealthy'] += 1
        try:
            result = self._original(executor, effective, **kwargs)
            row.update(completed=True, returncode=result.returncode)
            return result
        except BaseException as exc:
            self._metrics['executor_failures'] += 1
            row.update(exception_type=type(exc).__name__)
            raise
        finally:
            row['ended_ns'] = self.clock()

    def _restore(self):
        global _ACTIVE
        if self._stop is not None:
            self._stop.set()
        if self._thread is not None:
            try:
                self._thread.join(timeout=self.timeout + 5)
                self._metrics['thread_stopped'] = not self._thread.is_alive()
                if not self._metrics['thread_stopped']:
                    self._fail('Sudo ticket thread did not stop within its explicit timeout')
            except BaseException as exc:
                self._fail(type(exc).__name__ + ': ' + str(exc))
        if hasattr(self, '_installed'):
            if SubprocessCommandExecutor.run is not self._installed:
                self._fail('Sudo executor binding changed before restoration')
            SubprocessCommandExecutor.run = self._original
            self._restored = True
        else:
            self._restored = True
        self.active = False
        if _ACTIVE is self:
            _ACTIVE = None

    def summary(self):
        with self._lock:
            metrics, healthy, failure = dict(self._metrics), self.healthy, self._failure
        return dict(schema=1, profile='same-process-noninteractive-sudo-session-v1',
            status='HEALTHY_SUDO_SESSION' if healthy else 'FAILED_SUDO_SESSION',
            active=self.active, healthy=healthy, error=failure, process_id=getattr(self, '_pid', None),
            credentials_unchanged=hasattr(self, '_credentials') and self.read_credentials() == self._credentials,
            executor_binding_restored=self._restored, interval_seconds=self.interval,
            validation_timeout_seconds=self.timeout, sudo=getattr(self, '_sudo_identity', None),
            commands=copy.deepcopy(self._commands), command_count=len(self._commands), **metrics,
            journal_scope='logical_and_effective_executor_argv_not_all_physical_descendant_processes',
            password_captured=False, sudo_policy_changed=False, credential_cache_invalidated=False,
            proof_scope_promoted=False, protected_control_channel=False)

    def _save(self):
        raw = (json.dumps(self.summary(), indent=2, sort_keys=True, allow_nan=False) + '\n').encode()
        require(len(raw) <= MAX_JOURNAL_BYTES, 'Sudo journal byte budget exceeded')
        require(not self.out.exists() and not self.out.is_symlink(), 'Sudo journal output appeared')
        descriptor, temporary = tempfile.mkstemp(prefix='.sudo-session-', dir=self.out.parent)
        try:
            with os.fdopen(descriptor, 'wb') as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.out)
        finally:
            Path(temporary).unlink(missing_ok=True)

    def _save_preserving(self, primary):
        try:
            self._save()
        except BaseException as exc:
            self._fail('Sudo journal publication failed: ' + type(exc).__name__)
            if primary is None:
                raise

    def __exit__(self, kind, exception, traceback):
        if exception is None:
            try:
                self._intact()
            except BaseException as exc:
                self._fail(type(exc).__name__ + ': ' + str(exc))
        self._restore()
        self._save_preserving(exception)
        if exception is None:
            require(self.healthy and self._metrics['thread_stopped'] and self._restored,
                    'Sudo control session did not complete with its original binding restored')
        return False
