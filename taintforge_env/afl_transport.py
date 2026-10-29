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

from . import afl_file as f
from experiments.execution_capsule_probe import controller as p


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
        self.channel, self.peer = socket.socketpair()
        self.channel.settimeout(.1)
        self.command = command or [sys.executable, '-m', 'scripts.run_afl_file', 'attempt',
                                   '--out', str(self.root)]
        self.deadline = deadline
        self.stop = threading.Event()
        self.ready = threading.Event()
        self.errors = []
        self.executed = 0
        self.completed = 0
        self.thread = threading.Thread(target=self.serve, name='tf-afl-attempts', daemon=True)

    def start(self):
        self.thread.start()
        p.require(self.ready.wait(5) and not self.errors, 'Attempt transport failed to start: '+str(self.errors))

    def close(self):
        self.stop.set()
        self.thread.join(45)
        self.peer.close()
        p.require(not self.thread.is_alive(), 'Attempt worker did not stop')

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
                    try: self.execute(connection)
                    except (BrokenPipeError, ConnectionError): pass
                    except Exception as exc:
                        self.errors.append(str(exc))
                        self.stop.set()
                        try: connection.sendall(struct.pack('!4I', 0x54464131, 3, 0, 0))
                        except OSError: pass
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
        case = self.root/'cases'/f'{self.executed:08d}'
        case.mkdir(exist_ok=False)
        self.executed += 1
        (case/'input').write_bytes(data)
        environment = {k: os.environ[k] for k in ('PATH', 'LD_LIBRARY_PATH') if k in os.environ}
        environment.update(PYTHONPATH=str(f.PROJECT), LANG='C', LC_ALL='C')
        with (case/'worker.log').open('wb') as output:
            process = subprocess.Popen([*self.command, '--case', str(case)], cwd=f.PROJECT,
                env=environment, stdin=subprocess.DEVNULL, stdout=output, stderr=output,
                start_new_session=True, close_fds=True)
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


def run_campaign(root, *, afl_bin=None, seconds=300, executions=None):
    import fcntl
    root = Path(root).resolve(strict=True)
    manifest = f.verify_campaign(root)
    p.require(type(seconds) is int and 1 <= seconds <= 604800, 'Invalid campaign time')
    if executions is not None:
        p.require(type(executions) is int and executions >= 1, 'Invalid execution budget')
    binary = str(Path(afl_bin).resolve()/'afl-fuzz') if afl_bin else __import__('shutil').which('afl-fuzz')
    p.require(binary and os.access(binary, os.X_OK), 'afl-fuzz is not installed')
    p.require(manifest['status'] == 'prepared', 'A new prepared campaign is required')
    with (root/'.campaign.lock').open('a+') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        server_class = AttemptServer
        if 'warm' in manifest:
            from .afl_warm import WarmAttemptServer
            p.require(seconds <= manifest['warm']['campaign_seconds'], 'Campaign exceeds prepared warm lifetime')
            server_class = WarmAttemptServer
        attempt_deadline = manifest['warm']['timeout_ms']/1000+30 if 'warm' in manifest else manifest['launch']['timeout_seconds']+60
        server = server_class(root, deadline=attempt_deadline)
        bootstrap_signals = []
        def bootstrap_stop(number, frame):
            bootstrap_signals.append(number)
            server.stop.set()
            raise InterruptedError('Campaign interrupted during preparation')
        bootstrap_handlers = {number: signal.signal(number, bootstrap_stop)
                              for number in (signal.SIGINT, signal.SIGTERM)}
        try:
            manifest['status'] = 'preparing'
            f.atomic_json(root/'campaign.json', manifest)
            server.start()
        except BaseException as exc:
            manifest.update(status='interrupted' if bootstrap_signals else 'failed', error=str(exc))
            try: server.close()
            finally: f.atomic_json(root/'campaign.json', manifest)
            raise
        finally:
            for number, handler in bootstrap_handlers.items(): signal.signal(number, handler)
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
        signals = []
        process = None
        def stopped(number, frame):
            signals.append(number)
            server.stop.set()
            if process is not None:
                try: os.killpg(process.pid, number)
                except ProcessLookupError: pass
        handlers = {s: signal.signal(s, stopped) for s in (signal.SIGINT, signal.SIGTERM)}
        manifest.update(status='running', command=command, afl_sha256=p.sha(Path(binary)))
        f.atomic_json(root/'campaign.json', manifest)
        try:
            with (root/'afl.log').open('wb') as log:
                process = subprocess.Popen(command, cwd=f.PROJECT, env=env, stdin=subprocess.DEVNULL,
                    stdout=log, stderr=log, start_new_session=True, pass_fds=(server.control_fd,))
                try: code = process.wait(timeout=seconds+manifest['launch']['timeout_seconds']+90)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL); process.wait(); raise
            server.close()
            if 'warm' in manifest:
                manifest['phase1_runs'] = 1
                manifest['checkpoint'] = f.read_json(root/'warm-ready.json')
            manifest.update(status='interrupted' if signals else 'completed' if code == 0 and not server.errors else 'failed',
                            afl_exit=code, cases=server.executed, executor_errors=server.errors)
            p.require(manifest['status'] != 'failed', 'AFL campaign failed; inspect afl.log and case worker.log')
            return manifest
        except BaseException as exc:
            manifest.update(status='failed', error=str(exc))
            raise
        finally:
            try:
                if process is not None and process.poll() is None:
                    try: os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError: pass
                    process.wait()
                server.close()
            except Exception as exc:
                manifest.update(status='failed', cleanup_error=str(exc))
                raise
            finally:
                for number, handler in handlers.items(): signal.signal(number, handler)
                manifest['cases'] = server.executed
                manifest['completed_cases'] = server.completed
                manifest['executor_errors'] = server.errors
                f.atomic_json(root/'campaign.json', manifest)
