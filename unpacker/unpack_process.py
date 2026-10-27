"""Bounded fresh QEMU processes and explicit differential input cases."""
import base64
import binascii
import ctypes
import hashlib
import json
import math
import os
from pathlib import Path
import re
import resource
import signal
import stat
import subprocess
import sys
import time


MAX_INPUT = 1024**2
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


def _limits(timeout, file_limit):
    for which, soft, hard in ((resource.RLIMIT_CORE, 0, 0),
            (resource.RLIMIT_FSIZE, file_limit, file_limit),
            (resource.RLIMIT_AS, 8 * 1024**3, 8 * 1024**3),
            (resource.RLIMIT_CPU, math.ceil(timeout) + 1, math.ceil(timeout) + 2),
            (resource.RLIMIT_NOFILE, 128, 128)):
        maximum = resource.getrlimit(which)[1]
        if maximum != resource.RLIM_INFINITY:
            hard = min(hard, maximum)
        resource.setrlimit(which, (min(soft, hard), hard))


def run_process(command, case, directory, *, timeout=10, file_limit=1024**2,
                rss_limit_mib=2048, environment=None):
    case = validate_cases([case])[0]
    require(type(command) is list and command and all(type(a) is str and '\0' not in a for a in command),
            'INVALID_COMMAND', 'Require an explicit command argument list')
    require(type(timeout) in (int, float) and math.isfinite(timeout) and 0 < timeout <= 600,
            'INVALID_BUDGET', 'Timeout must be positive and at most 600 seconds')
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
        'parent_death_guard': parent_death,
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
            cwd=directory, env=env, close_fds=True, start_new_session=True,
            preexec_fn=lambda: _prepare_child(parent_pid, timeout, file_limit))
        try:
            while True:
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
            if child.returncode is None:
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
    for stream in ('stdout', 'stderr'):
        item = _digest(directory / stream, file_limit)
        result[stream + '_sha256'], result[stream + '_bytes'] = item['sha256'], item['bytes']
        result['output_limit_exceeded'] |= item['bytes'] == file_limit
    result['output_limit_exceeded'] |= any(v['bytes'] == file_limit for v in outputs.values())
    save(directory / 'result.json', result)
    return result


def compare_results(results):
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
        observations.append((row['returncode'], row['stdout_bytes'], row['stdout_sha256'],
                             row['stderr_bytes'], row['stderr_sha256'], files))
    return all(item == observations[0] for item in observations[1:])
