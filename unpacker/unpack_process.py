"""Bounded fresh QEMU processes and explicit differential input cases."""
import base64
import binascii
import ctypes
from contextlib import ExitStack
import errno
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import re
import resource
import signal
import socket
import stat
import struct
import subprocess
import sys
import time


MAX_INPUT = 1024**2
MAX_TIMEOUT = 600
MAX_EXTENDED_TIMEOUT = 1200
RUN_NOFILE = 128
NAME = re.compile(r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,95}\Z')
RESERVED = {'stdout', 'stderr', 'stdin.bin', 'result.json', 'command.json'}


def _parent_death_control():
    if not sys.platform.startswith('linux'):
        return None
    try:
        control = ctypes.CDLL(None, use_errno=True).prctl
    except (OSError, AttributeError):
        return None
    control.argtypes = [ctypes.c_int, *([ctypes.c_ulong] * 4)]
    control.restype = ctypes.c_int
    return control


# Resolve libc in the parent, before Popen forks and invokes preexec_fn.
_PARENT_DEATH_CONTROL = _parent_death_control()


def _prepare_child(parent_pid, timeout, file_limit):
    if _PARENT_DEATH_CONTROL is not None:
        if _PARENT_DEATH_CONTROL(1, signal.SIGKILL, 0, 0, 0) != 0:  # PR_SET_PDEATHSIG
            raise OSError(ctypes.get_errno(), 'Cannot set direct-child parent-death signal')
        # The parent may have exited between fork and arming the signal.
        if os.getppid() != parent_pid:
            os.kill(os.getpid(), signal.SIGKILL)
    _limits(timeout, file_limit)


class UnpackError(ValueError):
    def __init__(self, reason, detail):
        self.reason = reason
        super().__init__(detail)


def require(condition, reason, detail):
    if not condition:
        raise UnpackError(reason, detail)


def save(path, value):
    Path(path).write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')


def _name(value):
    return type(value) is str and NAME.fullmatch(value) is not None and value not in RESERVED


def _decode(value):
    require(type(value) is str and len(value) <= 4 * ((MAX_INPUT + 2) // 3),
            'INVALID_CASE', 'Input is not bounded base64 text')
    try:
        data = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as error:
        raise UnpackError('INVALID_CASE', 'Invalid base64 input') from error
    require(len(data) <= MAX_INPUT, 'INVALID_CASE', 'Input exceeds 1 MiB')
    return data


def validate_cases(cases):
    require(type(cases) is list and 1 <= len(cases) <= 64,
            'INVALID_CASE', 'Require one to 64 input cases')
    normalized, ids = [], set()
    for case in cases:
        require(type(case) is dict and set(case) <= {'id', 'argv', 'stdin_base64', 'files', 'output_files'},
                'INVALID_CASE', 'Unknown input-case fields')
        name = case.get('id')
        require(_name(name) and name not in ids, 'INVALID_CASE', 'Case IDs must be unique simple names')
        ids.add(name)
        argv, files, outputs = case.get('argv', []), case.get('files', {}), case.get('output_files', [])
        require(type(argv) is list and len(argv) <= 32
                and all(type(a) is str and '\0' not in a and len(a.encode()) <= 4096 for a in argv)
                and sum(len(a.encode()) for a in argv) <= 16384,
                'INVALID_CASE', 'Invalid or oversized guest argv')
        require(type(files) is dict and len(files) <= 16 and all(_name(n) for n in files),
                'INVALID_CASE', 'Input files require bounded simple filenames')
        require(type(outputs) is list and len(outputs) <= 16 and all(_name(n) for n in outputs)
                and len(set(outputs)) == len(outputs), 'INVALID_CASE', 'Invalid output filenames')
        stdin = case.get('stdin_base64', '')
        total = len(_decode(stdin)) + sum(len(_decode(data)) for data in files.values())
        require(total <= 8 * MAX_INPUT, 'INVALID_CASE', 'Case input exceeds 8 MiB')
        normalized.append({'id': name, 'argv': list(argv), 'stdin_base64': stdin,
                           'files': dict(files), 'output_files': list(outputs)})
    return normalized


def _digest(path, limit):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_size <= limit,
            'INVALID_OUTPUT', 'Output is not a bounded regular file: ' + path.name)
    value = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024**2), b''):
            value.update(block)
    return {'present': True, 'bytes': info.st_size, 'sha256': value.hexdigest()}


def _rss(pid):
    try:
        for line in Path(f'/proc/{pid}/status').read_text().splitlines():
            if line.startswith('VmRSS:'):
                return int(line.split()[1])
    except (OSError, ValueError):
        pass
    return 0


def _live_group(pgid):
    """The leader is held waitable so its PID/PGID cannot be recycled."""
    live = []
    for entry in Path('/proc').iterdir():
        if entry.name.isdecimal():
            try:
                # comm is parenthesized and may itself contain spaces and ')'.
                fields = (entry / 'stat').read_bytes().rsplit(b') ', 1)[1].split()
                if int(fields[2]) == pgid and fields[0] not in (b'Z', b'X'):
                    live.append(int(entry.name))
            except (FileNotFoundError, ProcessLookupError, PermissionError):
                continue
    return live


def _limits(timeout, file_limit):
    for which, soft, hard in ((resource.RLIMIT_CORE, 0, 0),
            (resource.RLIMIT_FSIZE, file_limit, file_limit),
            (resource.RLIMIT_AS, 8 * 1024**3, 8 * 1024**3),
            (resource.RLIMIT_CPU, math.ceil(timeout) + 1, math.ceil(timeout) + 2),
            (resource.RLIMIT_NOFILE, RUN_NOFILE, RUN_NOFILE)):
        maximum = resource.getrlimit(which)[1]
        if maximum != resource.RLIM_INFINITY:
            hard = min(hard, maximum)
        resource.setrlimit(which, (min(soft, hard), hard))


def run_process(command, case, directory, *, timeout=10, file_limit=1024**2,
                rss_limit_mib=2048, environment=None, extended_timeout=False, wait_for_group=False,
                pass_fds=()):
    case = validate_cases([case])[0]
    require(type(command) is list and command and all(type(a) is str and '\0' not in a for a in command),
            'INVALID_COMMAND', 'Require an explicit command argument list')
    maximum_timeout = MAX_EXTENDED_TIMEOUT if extended_timeout is True else MAX_TIMEOUT
    require(type(timeout) in (int, float) and math.isfinite(timeout) and 0 < timeout <= maximum_timeout,
            'INVALID_BUDGET', f'Timeout must be positive and at most {maximum_timeout} seconds')
    require(type(file_limit) is int and 1 <= file_limit <= 64 * 1024**2
            and type(rss_limit_mib) is int and 32 <= rss_limit_mib <= 4096,
            'INVALID_BUDGET', 'Invalid file or resident-memory budget')
    require(environment is None or type(environment) is dict
            and set(environment) <= {'LC_ALL', 'TZ', 'LD_LIBRARY_PATH'}
            and all(type(v) is str and '\0' not in v for v in environment.values()),
            'INVALID_ENVIRONMENT', 'Only explicit locale/timezone/library paths are accepted')
    env = {'LC_ALL': 'C', 'TZ': 'UTC', **(environment or {})}
    directory = Path(directory).resolve()
    require(not directory.exists(), 'OUTPUT_EXISTS', 'Execution directory already exists')
    directory.mkdir(parents=True, exist_ok=False)
    parent_pid = os.getpid()
    parent_death = {'supported': _PARENT_DEATH_CONTROL is not None,
        'signal': 'SIGKILL' if _PARENT_DEATH_CONTROL is not None else None,
        'scope': 'direct_child_before_exec'}
    data = _decode(case['stdin_base64'])
    (directory / 'stdin.bin').write_bytes(data)
    for name, content in case['files'].items():
        (directory / name).write_bytes(_decode(content))
    save(directory / 'command.json', {'argv': command, 'case': case, 'environment': env,
        'cwd': str(directory), 'timeout_seconds': timeout, 'file_limit_bytes': file_limit,
        'rss_limit_mib': rss_limit_mib, 'address_space_bytes': 8 * 1024**3,
        'close_fds': True, 'fresh_session': True, 'process_group_cleanup': True,
        'parent_death_guard': parent_death, 'wait_for_process_group': wait_for_group,
        'guest_isolation_established': False})
    clock, timed_out, rss_hit, peak = time.monotonic(), False, False, 0
    usage = None
    def kill_group(child):
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    with (directory / 'stdin.bin').open('rb') as stdin, \
         (directory / 'stdout').open('wb') as stdout, (directory / 'stderr').open('wb') as stderr:
        child = subprocess.Popen(command, stdin=stdin, stdout=stdout, stderr=stderr,
            cwd=directory, env=env, close_fds=True, pass_fds=pass_fds, start_new_session=True,
            preexec_fn=lambda: _prepare_child(parent_pid, timeout, file_limit))
        try:
            while True:
                if wait_for_group:
                    # A final fork may race a /proc scan. Observe leader exit
                    # first and keep it waitable until the group is drained.
                    exited = os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
                    live = _live_group(child.pid)
                    peak = max(peak, sum(_rss(pid) for pid in live))
                    if exited and not live:
                        break
                else:
                    peak = max(peak, _rss(child.pid))
                    waited, status, measured = os.wait4(child.pid, os.WNOHANG)
                    if waited:
                        child.returncode, usage = os.waitstatus_to_exitcode(status), measured
                        break
                timed_out |= time.monotonic() - clock >= timeout
                rss_hit |= peak > rss_limit_mib * 1024
                if timed_out or rss_hit:
                    kill_group(child)
                time.sleep(0.01)
        finally:
            kill_group(child)
            if wait_for_group and child.returncode is None:
                _, status, usage = os.wait4(child.pid, 0)
                child.returncode = os.waitstatus_to_exitcode(status)
            elif child.returncode is None:
                child.wait(timeout=5)
    peak = max(peak, usage.ru_maxrss if usage else 0)
    outputs = {}
    for name in case['output_files']:
        path = directory / name
        outputs[name] = _digest(path, file_limit) if path.exists() or path.is_symlink() else {
            'present': False, 'bytes': 0, 'sha256': None}
    result = {'returncode': child.returncode, 'timed_out': timed_out,
        'rss_limit_hit': rss_hit or peak > rss_limit_mib * 1024,
        'max_rss_kib': peak, 'wall_seconds': time.monotonic() - clock,
        'parent_death_guard': parent_death,
        'output_files': outputs, 'output_limit_exceeded': False}
    if wait_for_group:
        result['root_pid'] = child.pid
    for stream in ('stdout', 'stderr'):
        item = _digest(directory / stream, file_limit)
        result[stream + '_sha256'], result[stream + '_bytes'] = item['sha256'], item['bytes']
        result['output_limit_exceeded'] |= item['bytes'] == file_limit
    result['output_limit_exceeded'] |= any(v['bytes'] == file_limit for v in outputs.values())
    save(directory / 'result.json', result)
    return result


def _child_returncode(pidfd, pid):
    # Linux UAPI: PIDFD_GET_INFO, version-zero struct pidfd_info (64 bytes).
    # The kernel retains the wait status on the pidfd after its parent reaps it.
    def retained_status():
        info = bytearray(64)
        struct.pack_into('=Q', info, 0, 1 << 3)  # PIDFD_INFO_EXIT
        try:
            fcntl.ioctl(pidfd, 0xc040ff0b, info)
        except OSError as error:
            raise UnpackError('INCOMPLETE_PROCESS_EXIT',
                              f'Cannot read PIDFD_GET_INFO for child {pid}: {error}') from error
        if struct.unpack_from('=Q', info)[0] & (1 << 3):
            return struct.unpack_from('=i', info, 60)[0]

    status = retained_status()
    if status is None:
        # An orphan can still be a zombie. /proc stat field 52 then contains
        # the wait status. Recheck the pidfd in case it was reaped during the read.
        zombie_status = None
        try:
            # stat masks exit_code to zero when its ptrace read check fails.
            # The namespace link uses the same check and reports denial.
            os.readlink(f'/proc/{pid}/ns/pid')
            data = Path(f'/proc/{pid}/stat').read_bytes().rsplit(b') ', 1)[-1].split()
            if len(data) >= 50 and data[0] == b'Z':
                zombie_status = int(data[49])
        except (FileNotFoundError, ProcessLookupError, PermissionError):
            pass
        status = retained_status()
        if status is None:
            status = zombie_status
    require(status is not None and (os.WIFEXITED(status) or os.WIFSIGNALED(status)),
            'INCOMPLETE_PROCESS_EXIT', 'Kernel terminal status unavailable for child ' + str(pid))
    return os.waitstatus_to_exitcode(status)


def _exit_packets(channel, root_pid, deadline):
    # SCM_CREDENTIALS identifies the sender. SCM_RIGHTS transfers a reference
    # to the child before its PID can disappear from /proc.
    space = socket.CMSG_SPACE(12) + socket.CMSG_SPACE(4)
    while True:
        # The last process can become a zombie just before the kernel releases
        # its socket. Wait for EOF within the original execution budget.
        channel.settimeout(max(0, deadline - time.monotonic()))
        try:
            packet, control, flags, _ = channel.recvmsg(8, space, socket.MSG_CMSG_CLOEXEC)
        except (BlockingIOError, TimeoutError) as error:
            raise UnpackError('INCOMPLETE_PROCESS_EXIT', 'Process observation channel did not close in time') from error
        with ExitStack() as handles:
            pid = pidfd = None
            valid = True
            for level, kind, data in control:
                if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                    for (fd,) in struct.iter_unpack('=i', data):
                        handles.callback(os.close, fd)
                        if pidfd is not None:
                            valid = False
                        pidfd = fd
                elif level == socket.SOL_SOCKET and kind == socket.SCM_CREDENTIALS and len(data) == 12:
                    pid = struct.unpack('=iII', data)[0]
                else:
                    valid = False
            if not packet and not control:
                return
            require(valid and not flags & (socket.MSG_CTRUNC | socket.MSG_TRUNC)
                    and len(packet) == 8 and pid is not None and pid > 0,
                    'INCOMPLETE_PROCESS_EXIT', 'Invalid process observation packet')
            kind, value = struct.unpack('=ii', packet)
            child_code = None
            if pidfd is not None:
                require((kind == ord('F') and value > 0 and value != pid)
                        or (kind == ord('C') and pid != root_pid and value == 0),
                        'INCOMPLETE_PROCESS_EXIT', 'Unexpected process descriptor')
                child_code = _child_returncode(pidfd, value if kind == ord('F') else pid)
        yield pid, kind, value, child_code


def _process_tree(channel, root_pid, root_code, deadline, max_processes, *, traps=None):
    started, requested, parents = set(), {}, {root_pid: None}
    kernel_codes = {root_pid: root_code}
    for count, (pid, kind, value, child_code) in enumerate(_exit_packets(channel, root_pid, deadline), 1):
        require(count <= (4 if traps is not None else 3) * max_processes - 1, 'INCOMPLETE_PROCESS_EXIT', 'Too many process observation packets')
        if kind == ord('L') and value == max_processes:
            raise UnpackError('PROCESS_LIMIT', f'Tree replay reached the limit of {max_processes} processes')
        if kind == ord('!'):
            raise UnpackError('UNSUPPORTED_FORK_PROFILE', f'Unsupported process transition in replay (syscall {value})')
        if traps is not None and kind == ord('U'):
            raise UnpackError('UNVERIFIED_GUEST_IO', f'Syscall {value} outside fixed-input replay')
        if traps is not None and kind == ord('T') and value and pid not in traps:
            traps[pid] = value & 0xffffffff
            continue
        if kind == (ord('S') if pid == root_pid else ord('C')) and value == 0 and pid not in started:
            started.add(pid)
        elif kind == ord('F') and value > 0 and value != pid and value not in parents:
            require(len(parents) < max_processes, 'INCOMPLETE_PROCESS_EXIT', 'Unexpected extra child')
            parents[value] = pid
        elif kind == ord('X') and pid not in requested and 0 <= value <= 255:
            requested[pid] = value
        else:
            raise UnpackError('INCOMPLETE_PROCESS_EXIT', 'Unexpected or duplicate process observation')
        if child_code is not None:
            child = value if kind == ord('F') else pid
            require(kernel_codes.setdefault(child, child_code) == child_code,
                    'INCOMPLETE_PROCESS_EXIT', 'Conflicting kernel child exit statuses')
    require(root_pid in started and started <= parents.keys() and requested.keys() <= parents.keys()
            and kernel_codes.keys() == parents.keys(), 'INCOMPLETE_PROCESS_EXIT',
            'Missing fork relationship, process descriptor or kernel wait status')
    rows = []
    for pid, parent in parents.items():
        current, visited = pid, set()
        while current != root_pid:
            require(current in parents and current not in visited,
                    'INCOMPLETE_PROCESS_EXIT', 'Disconnected fork tree')
            visited.add(current)
            current = parents[current]
        code = kernel_codes[pid]
        require(code < 0 or requested.get(pid) == code, 'INCOMPLETE_PROCESS_EXIT',
                'Guest exit and kernel terminal status disagree for PID ' + str(pid))
        rows.append({'pid': pid, 'parent_pid': parent, 'returncode': code, 'signal': -code if code < 0 else None})
    return rows


def _process_exits(channel, root_pid, root_code, deadline):
    exits = {}
    for row in _process_tree(channel, root_pid, root_code, deadline, 2):
        role = 'parent' if row.pop('parent_pid') is None else 'child'
        exits[role] = row
    return exits


def run_observed_process(command, case, directory, *, plugin_option, max_processes=None, **limits):
    receiver, sender = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    with receiver, sender, ExitStack() as handles:
        receiver.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        fd = sender.fileno()
        # Keep the guest's ordinary open/dup numbers available. The parent
        # can pass an existing fd above the limit set before QEMU's exec.
        soft_limit = resource.getrlimit(resource.RLIMIT_NOFILE)[0]
        minimum = RUN_NOFILE if soft_limit == resource.RLIM_INFINITY else min(RUN_NOFILE, soft_limit - 1)
        if minimum > fd:
            try:
                fd = fcntl.fcntl(fd, fcntl.F_DUPFD_CLOEXEC, minimum)
            except OSError as error:
                if error.errno != errno.EMFILE:
                    raise
            else:
                handles.callback(os.close, fd)
        command = [command[0], '-plugin', f'{plugin_option}{fd}', *command[1:]]
        result = run_process(command, case, directory, wait_for_group=True, pass_fds=(fd,), **limits)
        handles.close()
        sender.close()
        deadline = time.monotonic() + max(0, limits.get('timeout', 10) - result['wall_seconds'])
        try:
            args = (receiver, result['root_pid'], result['returncode'], deadline)
            if max_processes is None:
                result['process_exits'] = _process_exits(*args)
            else:
                result['process_tree'] = _process_tree(*args, max_processes)
        except (OSError, UnpackError) as error:
            result['process_exit_error'] = dict(reason=getattr(error, 'reason', 'INCOMPLETE_PROCESS_EXIT'),
                                                detail=str(error))
        return result


def run_fork_replay(command, case, directory, *, plugin, payload_role, **limits):
    result = run_observed_process(command, case, directory, plugin_option=f'{plugin},tf-replay-exits=', **limits)
    result['payload_role'] = payload_role
    save(Path(directory) / 'result.json', result)
    return result


def compare_results(results, *, same_process_tree=False):
    if type(results) is not list or not results:
        return False
    observations = []
    for row in results:
        if (type(row) is not dict or type(row.get('returncode')) is not int
                or row['returncode'] < 0
                or any(row.get(key) is not False for key in ('timed_out', 'rss_limit_hit', 'output_limit_exceeded'))):
            return False
        for stream in ('stdout', 'stderr'):
            if (type(row.get(stream + '_bytes')) is not int or not 0 <= row[stream + '_bytes'] <= 64 * 1024**2
                    or type(row.get(stream + '_sha256')) is not str
                    or re.fullmatch('[0-9a-f]{64}', row[stream + '_sha256']) is None):
                return False
        files = row.get('output_files')
        if type(files) is not dict or len(files) > 16:
            return False
        for name, item in files.items():
            if (not _name(name) or type(item) is not dict or set(item) != {'present', 'bytes', 'sha256'}
                    or type(item['present']) is not bool or type(item['bytes']) is not int
                    or not 0 <= item['bytes'] <= 64 * 1024**2):
                return False
            if item['present']:
                if type(item['sha256']) is not str or re.fullmatch('[0-9a-f]{64}', item['sha256']) is None:
                    return False
            elif item['bytes'] != 0 or item['sha256'] is not None:
                return False
        family = None
        if 'payload_role' in row or 'process_exits' in row or 'process_exit_error' in row:
            exits, role = row.get('process_exits'), row.get('payload_role')
            if ('process_exit_error' in row or type(exits) is not dict
                    or set(exits) not in ({'parent'}, {'parent', 'child'})
                    or role not in ('parent', 'child') or role not in exits):
                return False
            codes = {}
            for name, item in exits.items():
                if (type(item) is not dict or type(item.get('pid')) is not int or item['pid'] <= 0
                        or type(item.get('returncode')) is not int or not 0 <= item['returncode'] <= 255
                        or 'signal' not in item or item['signal'] is not None):
                    return False
                codes[name] = item['returncode']
            if (codes['parent'] != row['returncode'] or exits['parent']['pid'] != row.get('root_pid')
                    or len({p['pid'] for p in exits.values()}) != len(exits)):
                return False
            # The captured child can become the rebuilt root. An additional
            # successful wrapper is allowed; its abnormal exit is observable.
            other = 'child' if role == 'parent' else 'parent'
            family = (codes[role], codes.get(other, 0))
            if same_process_tree:
                family += (codes,)
        observations.append((family, row['returncode'], row['stdout_bytes'], row['stdout_sha256'],
                             row['stderr_bytes'], row['stderr_sha256'], files))
    return all(item == observations[0] for item in observations[1:])
