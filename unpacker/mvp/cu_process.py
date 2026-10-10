"""Fresh QEMU execution and wait4 resource accounting, adapted from 7ct."""
from pathlib import Path
import base64
import json
import os
import signal
import subprocess
import sys
import time

from ct_elf import CaptureError, sha256

ROOT = Path(__file__).resolve().parent


def save(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def memory_sample(pid):
    try:
        return {line.split(':', 1)[0]: int(line.split()[1])
                for line in Path(f'/proc/{pid}/status').read_text().splitlines()
                if line.split(':', 1)[0] in ('VmRSS', 'VmHWM', 'VmSize', 'VmSwap')}
    except (OSError, ValueError):
        return {}


def run(command, case, directory, environment, timeout=10, address_space_mib=8192,
        file_size_mib=1, plugin=False, rss_limit_mib=None):
    directory.mkdir(parents=True, exist_ok=False)
    data = base64.b64decode(case.get('stdin_base64', ''), validate=True)
    files = case.get('files', {})
    if not isinstance(files, dict) or len(data) > 1024**2:
        raise CaptureError('INVALID_CASE', 'Invalid input data or file table')
    file_hashes = {}
    for name, encoded in files.items():
        if not isinstance(name, str) or Path(name).name != name or name in ('', '.', '..', 'stdout', 'stderr', 'command.json', 'stdin.bin', 'result.json'):
            raise CaptureError('INVALID_CASE', 'Input files require distinct simple filenames')
        raw = base64.b64decode(encoded, validate=True)
        if len(raw) > 1024**2:
            raise CaptureError('RESOURCE_LIMIT', 'Input file exceeds 1 MiB')
        (directory / name).write_bytes(raw)
        file_hashes[name] = sha256(directory / name)
    (directory / 'stdin.bin').write_bytes(data)
    env = os.environ.copy()
    for key in list(env):
        if key.startswith('QEMU_'):
            env.pop(key)
    env.update(environment)
    save(directory / 'command.json', dict(argv=command, cwd=str(directory),
         stdin_sha256=sha256(directory / 'stdin.bin'), input_files=file_hashes,
         environment=environment, plugin=plugin, timeout_seconds=timeout,
         address_space_mib=address_space_mib, file_size_mib=file_size_mib, rss_limit_mib=rss_limit_mib))
    wrapped = [sys.executable, str(ROOT / 'cu_limit_exec.py'), str(address_space_mib * 1024**2),
               str(file_size_mib * 1024**2), *command]
    timed_out, rss_limit_hit, samples, peaks = False, False, 0, {}
    with (directory / 'stdin.bin').open('rb') as stdin, (directory / 'stdout').open('wb') as stdout, (directory / 'stderr').open('wb') as stderr:
        started = time.monotonic()
        child = subprocess.Popen(wrapped, cwd=directory, env=env, stdin=stdin, stdout=stdout,
                                 stderr=stderr, start_new_session=True)
        try:
            while True:
                values = memory_sample(child.pid)
                if values:
                    samples += 1
                    for key, value in values.items():
                        peaks[key] = max(peaks.get(key, 0), value)
                waited, status, usage = os.wait4(child.pid, os.WNOHANG)
                if waited:
                    child.returncode = os.waitstatus_to_exitcode(status)
                    break
                exceeded = rss_limit_mib is not None and values.get('VmRSS', 0) > rss_limit_mib * 1024
                if (not timed_out and time.monotonic() - started >= timeout) or (exceeded and not rss_limit_hit):
                    timed_out |= time.monotonic() - started >= timeout
                    rss_limit_hit |= exceeded
                    try:
                        os.killpg(child.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                time.sleep(0.02)
        finally:
            if child.returncode is None:
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                child.wait()
    result = dict(returncode=child.returncode, timed_out=timed_out,
                  rss_limit_mib=rss_limit_mib,
                  rss_limit_hit=rss_limit_hit or (rss_limit_mib is not None and usage.ru_maxrss > rss_limit_mib * 1024),
                  wall_seconds=time.monotonic() - started, max_rss_kib=usage.ru_maxrss,
                  user_seconds=usage.ru_utime, system_seconds=usage.ru_stime,
                  memory_samples=samples, sampled_peaks_kib=peaks)
    for name in ('stdout', 'stderr'):
        result[name + '_sha256'] = sha256(directory / name)
        result[name + '_bytes'] = (directory / name).stat().st_size
    save(directory / 'result.json', result)
    return result


def compare_runs(original, restored):
    return (not original['timed_out'] and not restored['timed_out']
            and original['returncode'] >= 0 and restored['returncode'] >= 0
            and all(original[k] == restored[k] for k in ('returncode', 'stdout_sha256', 'stderr_sha256')))


def cold_check(qemu, original, restored, cases, output, environment):
    comparisons = []
    for i, case in enumerate(cases):
        pair = dict(id=case['id'])
        for name, binary in (('original', original), ('restored', restored)):
            pair[name] = run([str(qemu), '-0', 'target.elf', str(binary), *case.get('argv', [])],
                             case, output / f'case-{i:03d}' / name, environment)
        pair['status'] = 'MATCH' if compare_runs(pair['original'], pair['restored']) else 'MISMATCH'
        comparisons.append(pair)
    return dict(status='RUNNABLE_ON_TESTED_CASES' if comparisons and all(p['status'] == 'MATCH' for p in comparisons) else 'COLD_RUN_MISMATCH',
                cases=len(cases), distinct_inputs=len({json.dumps({k: c.get(k) for k in ('stdin_base64', 'argv', 'files')}, sort_keys=True) for c in cases}),
                comparisons=comparisons,
                observation_scope='exit status, stdout, stderr; recorded stdin and file inputs; separate fresh QEMU processes')
