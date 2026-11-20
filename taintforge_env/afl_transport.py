"""Trusted AFL forkserver-to-attempt transport; guest never receives AFL SHM."""
from __future__ import annotations

import os
import array
from pathlib import Path
import re
import select
import signal
import socket
import struct
import subprocess
import sys
import threading
import time
import traceback

from . import afl_file as f
from experiments.execution_capsule_probe import controller as p
from . import afl_storage as storage
from .afl_stop import AdmissionStopped, StopRequest, validate_timeout


def recv_exact(connection, size):
    result = bytearray()
    while len(result) < size:
        data = connection.recv(size-len(result))
        if not data: raise ConnectionError('AFL child disconnected')
        result.extend(data)
    return bytes(result)


def stop_case(process, case):
    """Stop this process group and only systemd units bound below this case."""
    try: os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError: pass
    from .capsule_resources import unit_name, control
    for path in Path(case).glob('**/iterations/*/run/config/capsule_binding.json'):
        binding = f.read_json(path)
        p.require(Path(binding['run_dir']).resolve().is_relative_to(Path(case).resolve()),
                  'Cleanup binding escapes its case')
        name = unit_name(binding)
        if re.fullmatch(r'taintforge-capsule-[0-9a-f]{32}\.service', name):
            result = control('sudo', '-n', 'systemctl', 'stop', name)
            after = control('systemctl', 'show', name, '--property=ActiveState,LoadState')
            p.require('LoadState=not-found' in after.stdout or
                      any('ActiveState='+s in after.stdout for s in ('inactive', 'failed')),
                      'Case service cleanup not confirmed: '+result.stderr[-1000:])
    try: process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=5)


class AttemptServer:
    def __init__(self, root, *, command=None, deadline=120):
        self.root = Path(root)
        manifest = f.read_json(self.root/'campaign.json') if (self.root/'campaign.json').is_file() else {}
        value = storage.verify_manifest(manifest)
        self.storage = storage.Budget(self.root, value, allow_privileged='warm' in manifest) if value is not None else None
        self.channel, self.peer = socket.socketpair()
        self.channel.settimeout(.1)
        self.command = command or [sys.executable, '-m', 'scripts.run_afl_file', 'attempt',
                                   '--out', str(self.root)]
        self.deadline = deadline
        self.stop = threading.Event()
        self.graceful_stop = threading.Event()
        self.active_attempt = threading.Event()
        self.ready = threading.Event()
        self.errors = []
        self.executed = 0
        self.completed = 0
        self.admission_closed = threading.Event()
        self.execution_incomplete = threading.Event()
        self.budget_reason = None
        from .afl_metrics import Metrics
        self.metrics = Metrics(self.root)
        self.thread = threading.Thread(target=self.serve, name='tf-afl-attempts', daemon=True)

    def start(self):
        self.thread.start()
        p.require(self.ready.wait(5) and not self.errors, 'Attempt transport failed to start: '+str(self.errors))

    def close(self):
        self.stop.set()
        if self.thread.ident is not None:
            self.thread.join(45)
        self.peer.close()
        p.require(not self.thread.is_alive(), 'Attempt worker did not stop')
        self.channel.close()

    @property
    def control_fd(self):
        return self.peer.fileno()

    def connect(self):
        """In-process component tests use the same per-attempt FD transport."""
        child, controller = socket.socketpair()
        try:
            self.peer.sendmsg([b'C'], [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
                                       array.array('i', [controller.fileno()]))])
        except BaseException:
            child.close(); raise
        finally:
            controller.close()
        return child

    def stop_admission(self, record):
        if self.storage is not None:
            record = self.storage.stop(record)
        if self.budget_reason is None:
            self.budget_reason = dict(record)
        self.admission_closed.set()

    def admit_case(self, index):
        if self.graceful_stop.is_set():
            raise AdmissionStopped()
        if self.admission_closed.is_set():
            raise storage.ResourceLimit('admission_closed')
        if self.storage is not None:
            self.storage.admit(index, stop=self.stop)

    def serve(self):
        try:
            (self.root/'cases').mkdir(exist_ok=True)
            self.ready.set()
            while not self.stop.is_set():
                try:
                    marker, controls, flags, _ = self.channel.recvmsg(1, socket.CMSG_SPACE(4))
                except socket.timeout: continue
                descriptors = []
                for level, kind, data in controls:
                    if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                        received = array.array('i'); received.frombytes(data)
                        descriptors.extend(received)
                if marker != b'C' or flags or len(descriptors) != 1:
                    for fd in descriptors: os.close(fd)
                    raise RuntimeError('Invalid attempt descriptor transfer')
                with socket.socket(fileno=descriptors[0]) as connection:
                    self.active_attempt.set()
                    try: self.execute(connection)
                    except AdmissionStopped:
                        self.active_attempt.clear()
                        self.stop.wait()
                    except storage.ResourceLimit as exc:
                        self.stop_admission(exc.record)
                        if self.executed != self.completed:
                            self.execution_incomplete.set()
                        self.stop.wait()
                    except (BrokenPipeError, ConnectionError): pass
                    except Exception as exc:
                        self.errors.append(str(exc))
                        limited = storage.from_oserror(exc)
                        if limited is not None:
                            self.stop_admission(limited.record)
                        try:
                            with (self.root/'executor-error.log').open('a') as log:
                                log.write(traceback.format_exc())
                        except OSError:
                            pass
                        self.stop.set()
                        try: connection.sendall(struct.pack('!4I', 0x54464131, 3, 0, 0))
                        except OSError: pass
                    finally:
                        self.active_attempt.clear()
        except Exception as exc:
            self.errors.append(str(exc)); self.ready.set()
        finally:
            self.channel.close()

    def execute(self, connection):
        connection.settimeout(5)
        size = struct.unpack('!I', recv_exact(connection, 4))[0]
        manifest = f.read_json(self.root/'campaign.json')
        p.require(1 <= size <= manifest['max_input'], 'AFL input exceeds the campaign limit')
        data = recv_exact(connection, size)
        self.admit_case(self.executed)
        case = self.root/'cases'/f'{self.executed:08d}'
        case.mkdir(exist_ok=False)
        self.executed += 1
        (case/'input').write_bytes(data)
        environment = {k: os.environ[k] for k in ('PATH', 'LD_LIBRARY_PATH') if k in os.environ}
        environment.update(PYTHONPATH=str(f.PROJECT), LANG='C', LC_ALL='C')
        with (case/'worker.log').open('wb') as output:
            process = subprocess.Popen([*self.command, '--case', str(case)], cwd=f.PROJECT,
                env=environment, stdin=subprocess.DEVNULL, stdout=output, stderr=output,
                process_group=0, close_fds=True)
            started = time.monotonic()
            terminal = {'status': 'failed'}
            cleanup_done = False
            try:
                while process.poll() is None:
                    if self.stop.is_set(): raise ConnectionError('Campaign stopped')
                    if time.monotonic()-started > self.deadline:
                        raise TimeoutError('Attempt exceeded its controller deadline')
                    if select.select([connection], [], [], 0.05)[0]:
                        if connection.recv(1, socket.MSG_PEEK) == b'':
                            raise ConnectionError('AFL child stopped during the attempt')
                        raise RuntimeError('Unexpected bytes after the testcase')
                p.require(process.returncode == 0, 'Attempt worker failed; inspect '+str(case/'worker.log'))
                result = f.read_json(case/'result.json')
                bitmap = (case/'coverage.map').read_bytes()
                p.require(result['status'] == 'passed' and len(bitmap) == f.MAP_SIZE and any(bitmap),
                          'Attempt did not return valid guest coverage')
                import hashlib
                p.require(hashlib.sha256(bitmap).hexdigest() == result['coverage']['map_sha256'],
                          'Coverage transport hash mismatch')
                stop_case(process, case)
                cleanup_done = True
                connection.sendall(struct.pack('!4I', 0x54464131, 0, 0, f.MAP_SIZE)+bitmap)
                terminal = {'status': 'delivered'}
                self.completed += 1
            except (BrokenPipeError, ConnectionError) as exc:
                terminal = {'status': 'cancelled', 'error': str(exc)}
                raise
            except Exception as exc:
                terminal = {'status': 'failed', 'error': str(exc)}
                raise
            finally:
                try:
                    if not cleanup_done: stop_case(process, case)
                    terminal['cleanup_confirmed'] = True
                except Exception as exc:
                    terminal.update(status='failed', cleanup_confirmed=False, cleanup_error=str(exc))
                    raise
                finally:
                    f.atomic_json(case/'transport.json', terminal)
                    if self.storage is not None:
                        self.storage.complete(case)


def run_campaign(root, *, afl_bin=None, seconds=300, executions=None, max_artifact_mib=None,
                 max_log_mib=None, max_rootfs_mib=None, max_case_mib=None,
                 reserve_mib=None, min_free_mib=None, max_preparation_mib=None, session_check=None, stop_timeout=120):
    import fcntl
    root = Path(root).resolve(strict=True)
    manifest = f.verify_campaign(root)
    p.require(type(seconds) is int and 1 <= seconds <= 604800, 'Invalid campaign time')
    p.require(session_check is None or callable(session_check), 'Invalid live-session checker')
    validate_timeout(stop_timeout)
    if max_artifact_mib is not None:
        p.require(type(max_artifact_mib) is int and 16 <= max_artifact_mib <= 1048576, 'Invalid artifact budget')
    if executions is not None:
        p.require(type(executions) is int and executions >= 1, 'Invalid execution budget')
    binary = str(Path(afl_bin).resolve()/'afl-fuzz') if afl_bin else __import__('shutil').which('afl-fuzz')
    p.require(binary and Path(binary).is_file() and os.access(binary, os.X_OK), 'afl-fuzz is not installed')
    p.sha(Path(binary))  # Fail on unreadable AFL before expensive preparation.
    p.require(manifest['status'] == 'prepared', 'A new prepared campaign is required')
    with (root/'.campaign.lock').open('a+') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        manifest = f.verify_campaign(root)
        p.require(manifest['status'] == 'prepared', 'A new prepared campaign is required')
        value = storage.limits(manifest, artifact_bytes=max_artifact_mib, log_bytes=max_log_mib,
            rootfs_bytes=max_rootfs_mib, case_bytes=max_case_mib,
            reserve_bytes=reserve_mib, min_free_bytes=min_free_mib, preparation_bytes=max_preparation_mib)
        storage.bind(manifest, value)
        f.atomic_json(root/'campaign.json', manifest)
        server_class = AttemptServer
        if 'warm' in manifest:
            from .afl_warm import WarmAttemptServer
            p.require(seconds <= manifest['warm']['campaign_seconds'], 'Campaign exceeds prepared warm lifetime')
            server_class = WarmAttemptServer
        attempt_deadline = manifest['warm']['timeout_ms']/1000+30 if 'warm' in manifest else manifest['launch']['timeout_seconds']+60
        server = server_class(root, deadline=attempt_deadline)
        signals = []
        shutdown = StopRequest(server, stop_timeout)
        process = None
        budget_stop = False
        budget_stop_started = None
        handlers = {}
        def stopped(number, frame):
            signals.append(number)
            shutdown.request(number)
        bootstrap_started = False
        bootstrap_succeeded = False
        bootstrap_signals = []
        def bootstrap_stop(number, frame):
            bootstrap_signals.append(number)
            server.stop.set()
            raise InterruptedError('Campaign interrupted during preparation')
        bootstrap_handlers = {}
        try:
            for number in (signal.SIGINT, signal.SIGTERM):
                bootstrap_handlers[number] = signal.signal(number, bootstrap_stop)
            manifest['status'] = 'preparing'
            f.atomic_json(root/'campaign.json', manifest)
            server.storage.open()
            bootstrap_started = True
            server.start()
            server.storage.start_monitor()
            if session_check is not None:
                manifest['session_checks'] = {'before_afl': session_check(server, 'before_afl')}
                f.atomic_json(root/'campaign.json', manifest)
            # Install the running handlers before leaving the bootstrap cleanup scope.
            for number in bootstrap_handlers:
                signal.signal(number, stopped)
            handlers.update(bootstrap_handlers)
            bootstrap_succeeded = True
        except BaseException as exc:
            manifest.update(status='interrupted' if bootstrap_signals else 'failed', error=str(exc))
            limited = exc if isinstance(exc, storage.ResourceLimit) else storage.from_oserror(exc)
            if limited is not None:
                server.stop_admission(limited.record)
                manifest.update(status='incomplete' if bootstrap_started else 'resource_limited',
                                stop_reason='storage_limit', storage_stop=server.budget_reason,
                                evidence_complete=False)
            try:
                server.storage.release_reserve()
                server.close()
            except BaseException as cleanup:
                manifest.update(status='failed', cleanup_error=str(cleanup))
                raise
            finally:
                manifest['storage_result'] = server.storage.report()
                f.atomic_json(root/'campaign.json', manifest)
            if limited is not None:
                return manifest
            raise
        finally:
            if not bootstrap_succeeded:
                for number, handler in bootstrap_handlers.items(): signal.signal(number, handler)
        try:
            command = [binary, '-i', str(root/'seeds'), '-o', str(root/'afl'),
                '-V', str(seconds), '-t', str(int((attempt_deadline+5)*1000)),
                '-m', '256', '-g', '1', '-G', str(manifest['max_input']), '-p', 'explore', '-s', '42']
            if executions is not None: command += ['-E', str(executions)]
            command += ['--', manifest['build']['bridge'], str(server.control_fd), '@@']
            env = {k: os.environ[k] for k in ('PATH', 'LD_LIBRARY_PATH') if k in os.environ}
            env.update(AFL_NO_UI='1', AFL_NO_AFFINITY='1', AFL_SKIP_CPUFREQ='1',
                       AFL_FAST_CAL='1', AFL_MAP_SIZE=str(f.MAP_SIZE))
            if os.environ.get('AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES') == '1':
                env['AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES'] = '1'
            server.metrics.started = time.monotonic()
            manifest['artifact_budget_mib'] = value['artifact_bytes']//storage.MIB
            manifest.update(status='running', command=command, afl_sha256=p.sha(Path(binary)),
                            afl_started_ns=time.monotonic_ns())
            f.atomic_json(root/'campaign.json', manifest)
            with (root/'afl.log').open('wb') as log:
                process = subprocess.Popen(command, cwd=f.PROJECT, env=env, stdin=subprocess.DEVNULL,
                    stdout=log, stderr=log, start_new_session=True, pass_fds=(server.control_fd,))
                try:
                    deadline = time.monotonic()+seconds+manifest['launch']['timeout_seconds']+90
                    while True:
                        try:
                            code = process.wait(timeout=.25)
                            break
                        except subprocess.TimeoutExpired:
                            shutdown.poll(process)
                            if time.monotonic() > deadline:
                                raise
                            metrics = server.metrics.publish(executed=server.executed, completed=server.completed)
                            try:
                                server.storage.check()
                            except storage.ResourceLimit as exc:
                                server.stop_admission(exc.record)
                            if server.admission_closed.is_set():
                                if budget_stop_started is None:
                                    budget_stop_started = time.monotonic()
                                budget_stop = True
                                manifest.update(stop_reason='storage_limit', storage_stop=server.budget_reason)
                                server.storage.release_reserve()
                                drained = server.executed == server.completed
                                if drained or server.execution_incomplete.is_set() or server.errors or time.monotonic()-budget_stop_started > attempt_deadline+5:
                                    try: os.killpg(process.pid, signal.SIGINT)
                                    except ProcessLookupError: pass
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL); process.wait(); raise
            manifest['afl_finished_ns'] = time.monotonic_ns()
            manifest['afl_exit'] = code
            shutdown.finish_wait(process)
            if session_check is not None and code == 0 and not server.admission_closed.is_set() and not signals:
                manifest['session_checks']['after_afl'] = session_check(server, 'after_afl')
            server.storage.release_reserve()
            server.close()
            shutdown.finish_wait(process)
            server.storage.stop_monitor()
            try:
                server.storage.check(force=True)
            except storage.ResourceLimit as exc:
                server.stop_admission(exc.record)
            p.require(signals or server.completed == server.executed, 'Campaign left undelivered children')
            if 'warm' in manifest:
                manifest['phase1_runs'] = 1
                manifest['checkpoint'] = f.read_json(root/'warm-ready.json')
                if 'phase2' in manifest['warm']:
                    manifest['phase2'] = f.read_json(root/'phase2-progress.json')
                    p.require(manifest['phase2']['status'] == 'passed' and
                              manifest['phase2']['completed'] == server.executed,
                              'Per-child Phase 2 did not finish all executions')
            if server.storage.reason is not None:
                budget_stop = True
                manifest.update(stop_reason='storage_limit', storage_stop=server.storage.reason)
            complete = (server.completed == server.executed and not server.errors and not server.storage.pending
                        and not shutdown.forced and not shutdown.timed_out)
            manifest.update(status='interrupted' if signals else
                            'resource_limited' if budget_stop and complete and code in (0, -signal.SIGINT, 130) else
                            'completed' if code == 0 and not server.errors else 'failed',
                            evidence_complete=complete,
                            afl_exit=code, cases=server.executed, executor_errors=server.errors)
            p.require(manifest['status'] != 'failed', 'AFL campaign failed; inspect afl.log and case worker.log')
            return manifest
        except BaseException as exc:
            manifest.update(status='interrupted' if signals else 'failed', error=str(exc), evidence_complete=False)
            limited = exc if isinstance(exc, storage.ResourceLimit) else storage.from_oserror(exc)
            if limited is not None:
                server.stop_admission(limited.record)
                manifest.update(stop_reason='storage_limit', storage_stop=server.budget_reason,
                                evidence_complete=False)
            raise
        finally:
            try:
                server.storage.release_reserve()
                if process is not None and process.poll() is None:
                    try: os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError: pass
                    process.wait()
                server.close()
            except Exception as exc:
                manifest.update(status='failed', cleanup_error=str(exc))
                raise
            finally:
                manifest['cases'] = server.executed
                manifest['completed_cases'] = server.completed
                manifest['executor_errors'] = server.errors
                try:
                    manifest['metrics'] = server.metrics.publish(executed=server.executed, completed=server.completed, final=True)
                    manifest['storage_result'] = server.storage.report()
                    if server.storage.reason is not None:
                        manifest.update(stop_reason='storage_limit', storage_stop=server.storage.reason)
                    manifest['artifact_budget_exceeded'] = manifest['storage_result']['usage']['artifact_bytes'] >= value['artifact_bytes']
                except Exception as exc:
                    manifest.update(status='failed', metrics_error=str(exc))
                try:
                    if (root/'phase2-progress.json').is_file():
                        manifest['phase2'] = f.read_json(root/'phase2-progress.json')
                    shutdown.save(root, manifest)
                    if 'phase2' in manifest.get('warm', {}):
                        from .afl_phase2 import campaign_report
                        f.atomic_json(root/'pipeline-report.json', campaign_report(root, manifest))
                except Exception as exc:
                    manifest.update(status='failed', report_error=str(exc))
                finally:
                    try:
                        f.atomic_json(root/'campaign.json', manifest)
                    finally:
                        for number, handler in handlers.items(): signal.signal(number, handler)
