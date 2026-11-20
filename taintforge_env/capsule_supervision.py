from pathlib import Path
import subprocess
import time

from .phase1_runtime import read_json

GRACE_SECONDS = .25
WORKERS = {
    'permit': ('phase1-retirement/retirement.json', {'released', 'analysis_rejected'}),
    'observer': ('controller.json', {'passed'}),
}


def exit_status(returncode):
    if type(returncode) is not int or not -127 <= returncode <= 255:
        raise ValueError('Invalid QEMU process returncode')
    return {'returncode': returncode, 'signal': -returncode if returncode < 0 else None,
            'wrapper_exit': 128-returncode if returncode < 0 else returncode}


class ControllerExitError(RuntimeError):
    def __init__(self, record):
        self.record = record
        message = (f"{record['component']} controller exited with code {record['exitcode']}: "
                   f"{record.get('error') or record.get('status', 'missing result')}")
        self.failure = {
            'category': 'controller_failure', 'component': record['component'],
            'stage': 'process_exit', 'exception_type': type(self).__name__,
            'errno': None, 'message': message[:3000],
        }
        super().__init__(message)


def worker_problem(name, worker, directory):
    code = worker.exitcode
    if code is None:
        return None
    record = {'component': name, 'pid': worker.pid, 'exitcode': code}
    if code != 0:
        return record
    relative, accepted = WORKERS[name]
    try:
        saved = read_json(Path(directory)/relative, 256*1024)
        status = saved.get('status')
        if status in accepted and not any(k in saved for k in ('error', 'failure', 'evidence_persistence_error')):
            return None
        record['status'] = str(status)[:128]
        record['error'] = str(saved.get('error') or saved.get('evidence_persistence_error') or 'Invalid controller completion')[:3000]
    except (OSError, ValueError, RuntimeError, TypeError, AttributeError) as exc:
        record['error'] = f'{type(exc).__name__}: {exc}'[:3000]
    return record


def wait_qemu(process, workers, directory, seconds, *, poll_seconds=.01, sample=None):
    if not 0 < poll_seconds <= 1 or not 0 < seconds <= 86405:
        raise ValueError('Invalid capsule supervision deadline')
    deadline = time.monotonic() + seconds
    pending, observed = {}, {}
    while True:
        code = process.poll()
        if code is not None:
            return code
        if sample is not None:
            sample()
        now = time.monotonic()
        for name, worker in workers:
            if name not in observed and worker.exitcode is not None:
                problem = worker_problem(name, worker, directory)
                observed[name] = problem
                if problem is not None:
                    pending[name] = now
            if name in pending and now-pending[name] >= GRACE_SECONDS:
                code = process.poll()
                if code is not None:
                    return code
                raise ControllerExitError(observed[name])
        remaining = deadline-time.monotonic()
        if remaining <= 0:
            raise subprocess.TimeoutExpired(process.args, seconds)
        try:
            return process.wait(timeout=min(poll_seconds, remaining))
        except subprocess.TimeoutExpired:
            pass
