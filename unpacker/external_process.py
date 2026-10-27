"""Measured, bounded build/proof phases with their own child accounting.

Guest input execution remains the responsibility of unpack_process. This
supervisor preserves build variables and permits larger producer ledgers.
Linux process-group RSS is sampled; it is not a simultaneous unique-memory
measurement, and descendants that create another process group are not tracked.
"""
import hashlib
import json
import math
import os
from pathlib import Path
import resource
import signal
import stat
import subprocess
import time


MIB = 1024**2
POLL_SECONDS = 0.02


def _number(value, label, maximum):
    if type(value) not in (int, float) or not 0 < value <= maximum or not math.isfinite(value):
        raise ValueError(label + ' must be finite, positive and bounded')
    return value


def _plain_path(path, label):
    """Reject output redirects before resolve() can hide an existing symlink."""
    path = Path(os.path.abspath(os.fspath(path)))
    for part in (path, *path.parents):
        if part.is_symlink():
            raise ValueError(label + ' contains a symlink: ' + str(part))
    return path


def _save_new(path, value):
    with path.open('x', encoding='utf-8') as stream:
        json.dump(value, stream, sort_keys=True, indent=2, allow_nan=False)
        stream.write('\n')


def _digest(path):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode):
        raise ValueError('Phase output is not a regular file: ' + str(path))
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for data in iter(lambda: stream.read(MIB), b''):
            h.update(data)
    return {'bytes': info.st_size, 'sha256': h.hexdigest()}


def _group_rss(process_group, proc='/proc'):
    """Return sampled aggregate RSS, member count and unreadable member count."""
    total = members = unreadable = 0
    page_kib = os.sysconf('SC_PAGE_SIZE') // 1024
    for process in Path(proc).iterdir():
        if not process.name.isdecimal():
            continue
        try:
            # The comm field can contain spaces and parentheses.
            fields = (process / 'stat').read_text().rsplit(')', 1)[1].split()
            if int(fields[2]) != process_group:  # state, ppid, pgrp
                continue
            members += 1
            total += int((process / 'statm').read_text().split()[1]) * page_kib
        except (OSError, ValueError, IndexError):
            # Processes may exit between the two reads. Do not invent zeros as
            # complete accounting: retain this uncertainty in the receipt.
            unreadable += 1
    return total, members, unreadable


def _kill_group(process_group):
    try:
        os.killpg(process_group, signal.SIGKILL)
    except ProcessLookupError:
        return False
    return True


def _requested_limits(timeout, address_space_mib, file_limit_mib, cpu_seconds):
    cpu = math.ceil(cpu_seconds if cpu_seconds is not None else timeout + 1)
    requested = {
        resource.RLIMIT_CORE: (0, 0),
        resource.RLIMIT_FSIZE: (math.ceil(file_limit_mib * MIB),) * 2,
        resource.RLIMIT_AS: (math.ceil(address_space_mib * MIB),) * 2,
        resource.RLIMIT_CPU: (cpu, cpu + 1),
    }
    limits = {}
    for which, (soft, hard) in requested.items():
        inherited = resource.getrlimit(which)[1]
        if inherited != resource.RLIM_INFINITY:
            hard = min(hard, inherited)
        limits[which] = min(soft, hard), hard
    return limits


def run_phase(command, directory, *, cwd=None, env=None, timeout=900,
              rss_limit_mib=4096, address_space_mib=8192,
              file_limit_mib=2048, cpu_seconds=None, stdin_path=None):
    """Run one explicit argv and retain its measured outcome, including failures.

    Invalid requests and occupied outputs raise before spawning. Runtime exits,
    signals, resource stops and spawn failures return a result record. cwd=None
    preserves the caller's working directory. Environment inheritance is
    intentional: compiler, SDK and TF_* overrides must survive into build/proof
    children. The receipt hashes that environment instead of exposing its values.
    """
    if (type(command) not in (list, tuple) or not command or len(command) > 4096 or
            any(type(arg) is not str or '\0' in arg for arg in command) or not command[0] or
            sum(len(os.fsencode(arg)) for arg in command) > MIB):
        raise ValueError('Phase command must be a bounded explicit argument vector')
    timeout = _number(timeout, 'timeout', 86400)
    rss_limit_mib = _number(rss_limit_mib, 'rss_limit_mib', 1024**2)
    address_space_mib = _number(address_space_mib, 'address_space_mib', 1024**2)
    file_limit_mib = _number(file_limit_mib, 'file_limit_mib', 65536)
    if cpu_seconds is not None:
        _number(cpu_seconds, 'cpu_seconds', 86400)
    if env is not None and (type(env) is not dict or any(
            type(key) is not str or not key or '=' in key or '\0' in key or
            type(value) is not str or '\0' in value for key, value in env.items())):
        raise ValueError('Phase environment overrides must contain valid strings')
    output = _plain_path(directory, 'Phase output')
    if output.exists():
        raise FileExistsError('Phase output already exists: ' + str(output))
    working = Path(cwd if cwd is not None else Path.cwd()).resolve(strict=True)
    if not working.is_dir():
        raise ValueError('Phase working directory is not a directory')
    incoming = None
    if stdin_path is not None:
        incoming = Path(stdin_path).resolve(strict=True)
        if not incoming.is_file():
            raise ValueError('Phase stdin must be a regular file')
    effective_env = dict(os.environ)
    effective_env.update(env or {})
    environment_sha256 = hashlib.sha256(json.dumps(effective_env, sort_keys=True,
        separators=(',', ':'), ensure_ascii=True).encode()).hexdigest()
    limits = _requested_limits(timeout, address_space_mib, file_limit_mib, cpu_seconds)
    output.mkdir(parents=True, mode=0o700, exist_ok=False)
    launch = {'argv': list(command), 'cwd': str(working),
        'environment_policy': 'inherit_with_explicit_overrides',
        'environment_overrides_keys': sorted(env or {}),
        'effective_environment_sha256': environment_sha256,
        'stdin_path': str(incoming) if incoming is not None else None,
        'timeout_seconds': timeout, 'rss_limit_mib': rss_limit_mib,
        'address_space_mib': address_space_mib, 'file_limit_mib': file_limit_mib,
        'resource_limits': {str(k): list(v) for k, v in limits.items()},
        'fresh_process_group': True, 'close_fds': True, 'shell': False,
        'poll_seconds': POLL_SECONDS, 'guest_isolation_established': False}
    _save_new(output / 'command.json', launch)
    clock = time.monotonic()
    child = usage = None
    returncode = None
    timed_out = rss_hit = cleanup_signal_sent = False
    peak_group = peak_members = unreadable = 0
    spawn_error = None

    def apply_limits():
        for which, bounds in limits.items():
            resource.setrlimit(which, bounds)

    with (incoming or Path(os.devnull)).open('rb') as stdin, \
         (output / 'stdout').open('xb') as stdout, (output / 'stderr').open('xb') as stderr:
        try:
            child = subprocess.Popen(list(command), cwd=working, env=effective_env,
                stdin=stdin, stdout=stdout, stderr=stderr, close_fds=True,
                start_new_session=True, preexec_fn=apply_limits)
        except (OSError, subprocess.SubprocessError) as error:
            spawn_error = type(error).__name__ + ': ' + str(error)
        if child is not None:
            try:
                while True:
                    sampled, members, missing = _group_rss(child.pid)
                    peak_group = max(peak_group, sampled)
                    peak_members = max(peak_members, members)
                    unreadable += missing
                    rss_hit |= peak_group > rss_limit_mib * 1024
                    try:
                        waited, status, measured = os.wait4(child.pid, os.WNOHANG)
                    except InterruptedError:
                        continue
                    if waited:
                        returncode = child.returncode = os.waitstatus_to_exitcode(status)
                        usage = measured
                        break
                    timed_out |= time.monotonic() - clock >= timeout
                    if timed_out or rss_hit:
                        cleanup_signal_sent |= _kill_group(child.pid)
                    time.sleep(POLL_SECONDS)
            finally:
                # A leader can finish while its children keep running. Clean
                # the original owned group even after wait4 reaps the leader.
                cleanup_signal_sent |= _kill_group(child.pid)
                if child.returncode is None:
                    while True:
                        try:
                            _, status, usage = os.wait4(child.pid, 0)
                            child.returncode = returncode = os.waitstatus_to_exitcode(status)
                            break
                        except InterruptedError:
                            continue
    wall = time.monotonic() - clock
    streams = {name: _digest(output / name) for name in ('stdout', 'stderr')}
    # wait4 is specific to this phase, unlike cumulative RUSAGE_CHILDREN.
    peak = int(usage.ru_maxrss) if usage is not None else 0
    rss_hit |= peak > rss_limit_mib * 1024
    cpu = float(usage.ru_utime + usage.ru_stime) if usage is not None else 0.0
    file_hit = (returncode == -signal.SIGXFSZ or any(
        value['bytes'] >= limits[resource.RLIMIT_FSIZE][0] for value in streams.values()))
    cpu_hit = (returncode == -signal.SIGXCPU or
        returncode == -signal.SIGKILL and cpu >= limits[resource.RLIMIT_CPU][0])
    status = ('SPAWN_ERROR' if spawn_error else 'TIMEOUT' if timed_out else
              'RSS_LIMIT' if rss_hit else 'FILE_LIMIT' if file_hit else
              'CPU_LIMIT' if cpu_hit else 'SIGNALED' if returncode < 0 else
              'NONZERO_EXIT' if returncode else 'COMPLETED')
    result = {'schema_version': 1, 'status': status, 'returncode': returncode,
        'spawn_error': spawn_error, 'timed_out': timed_out, 'rss_limit_hit': rss_hit,
        'file_limit_hit': file_hit, 'cpu_limit_hit': cpu_hit,
        'wall_seconds': wall, 'cpu_seconds': cpu, 'max_rss_kib': peak,
        'rss_metric': 'Linux_wait4_phase_child_ru_maxrss_not_cumulative_RUSAGE_CHILDREN',
        'max_rss_is_simultaneous_process_tree_sum': False,
        'sampled_group_peak_rss_kib': peak_group,
        'sampled_group_peak_processes': peak_members,
        'group_rss_metric': 'sampled_sum_of_member_RSS_shared_pages_may_be_counted_multiple_times',
        'rss_enforcement': 'sampled_owned_process_group_and_final_wait4_peak',
        'rss_enforcement_is_hard_kernel_limit': False,
        'sampled_process_group_RSS_complete': False,
        'proc_read_races_or_failures': unreadable,
        'process_group_cleanup_attempted': child is not None,
        'process_group_cleanup_signal_sent': cleanup_signal_sent,
        'descendants_that_leave_process_group_tracked': False,
        'all_descendants_verified_terminated': False,
        'environment_sha256': environment_sha256}
    for name, value in streams.items():
        result[name + '_bytes'] = value['bytes']
        result[name + '_sha256'] = value['sha256']
    _save_new(output / 'result.json', result)
    return result
