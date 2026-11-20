"""Bounded signal shutdown and verifiable receipts for corpus continuation."""
from __future__ import annotations

import os
from pathlib import Path
import signal
import time

from . import afl_file as f

PROFILE = 'afl-graceful-stop-v1'
EVIDENCE = ('warm-ready.json', 'warm-executor.json', 'warm-session-result.json', 'phase2-progress.json')


class AdmissionStopped(Exception):
    """The input was refused before assigning a case number."""


def validate_timeout(value):
    f.p.require(type(value) is int and 1 <= value <= 600, 'Invalid graceful stop timeout')
    return value


class StopRequest:
    def __init__(self, server, timeout=120):
        self.server, self.timeout = server, validate_timeout(timeout)
        self.signals = []
        self.requested_ns = self.drained_ns = None
        self.sent = self.timed_out = False
        self.work_failed = False

    def request(self, number, frame=None):
        # Signal handlers only record intent; worker locks and IPC stay outside them.
        if self.requested_ns is None:
            self.requested_ns = time.monotonic_ns()
        self.signals.append(number)
        self.server.graceful_stop.set()

    @property
    def forced(self):
        return len(self.signals) > 1

    def drained(self):
        phase2 = getattr(self.server, 'phase2', None)
        return (not self.server.active_attempt.is_set() and
                self.server.executed == self.server.completed and
                not self.server.errors and
                (phase2 is None or phase2.completed == phase2.submitted and not phase2.errors))

    def poll(self, process):
        if self.requested_ns is None:
            return
        now = time.monotonic_ns()
        phase2 = getattr(self.server, 'phase2', None)
        incomplete = getattr(self.server, 'execution_incomplete', None)
        self.work_failed |= bool(self.server.errors or (phase2 is not None and phase2.errors) or
                                 (incomplete is not None and incomplete.is_set()))
        if self.drained_ns is None and now-self.requested_ns >= self.timeout*10**9:
            self.timed_out = True
        if not self.forced and not self.timed_out and not self.work_failed and self.drained():
            if self.drained_ns is None:
                self.drained_ns = now
            if not self.sent:
                if process.poll() is None:
                    try:
                        os.killpg(process.pid, signal.SIGINT)
                    except ProcessLookupError:
                        pass
                self.sent = True
            return
        if self.forced or self.work_failed or self.timed_out:
            self.server.stop.set()
            if process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass

    def finish_wait(self, process):
        if self.requested_ns is None:
            return
        while not self.forced and not self.timed_out and not self.work_failed:
            self.poll(process)
            if self.drained_ns is not None:
                return
            time.sleep(.02)

    def save(self, root, manifest):
        if self.requested_ns is None:
            return
        # A first signal may arrive while the capsule is already being finalized.
        if self.drained_ns is None and not (self.forced or self.timed_out or self.work_failed) and self.drained():
            now = time.monotonic_ns()
            if now-self.requested_ns <= self.timeout*10**9:
                self.drained_ns = now
            else:
                self.timed_out = True
        if manifest.get('status') in ('completed', 'resource_limited'):
            manifest['status'] = 'interrupted'
        if self.forced or self.timed_out or self.work_failed:
            manifest['evidence_complete'] = False
        root = Path(root)
        phase2 = manifest.get('phase2', {})
        session = f.read_json(root/'warm-session-result.json') if (root/'warm-session-result.json').is_file() else {}
        capsule = session.get('capsule', {})
        worker = f.read_json(root/'warm-executor.json') if (root/'warm-executor.json').is_file() else {}
        record = {'schema': 1, 'profile': PROFILE, 'status': 'incomplete',
                  'signals': list(self.signals), 'requested_ns': self.requested_ns,
                  'drained_ns': self.drained_ns, 'finished_ns': time.monotonic_ns(),
                  'timeout_seconds': self.timeout, 'forced': self.forced, 'timed_out': self.timed_out,
                  'work_failed': self.work_failed,
                  'capsule_cleanup_verified': (capsule.get('status') == 'passed' and
                      capsule.get('resources', {}).get('tree_empty') is True and
                      capsule.get('phase1_retirement', {}).get('phase1_retired') is True and
                      worker.get('status') == 'passed' and type(worker.get('phase1_runs')) is int and
                      worker['phase1_runs'] == 1 and type(worker.get('children')) is int and
                      worker['children'] == manifest.get('cases')),
                  'accepted_cases': manifest.get('cases'), 'delivered_cases': manifest.get('completed_cases'),
                  'phase2_submitted': phase2.get('submitted'), 'phase2_completed': phase2.get('completed'),
                  'evidence_sha256': {name: f.p.sha(root/name) for name in EVIDENCE if (root/name).is_file()}}
        manifest['stop_reason'] = 'user_signal'
        manifest['interruption'] = record
        record['status'] = 'drained'
        if not resumable(manifest):
            record['status'] = 'incomplete'
        f.atomic_json(root/'interruption.json', record)
        manifest['interruption_sha256'] = f.p.sha(root/'interruption.json')


def resumable(manifest):
    """Manifest-level checks; callers still verify capsule and per-child artifacts."""
    from . import afl_capsule, afl_storage
    record = manifest.get('interruption', {})
    state = manifest.get('phase2', {})
    budget = manifest.get('storage_result', {})
    count = manifest.get('cases')
    try:
        policy = afl_storage.verify_manifest(manifest)
        requested, drained, finished = (record.get(key) for key in ('requested_ns', 'drained_ns', 'finished_ns'))
        return (manifest.get('status') == 'interrupted' and manifest.get('stop_reason') == 'user_signal' and
                manifest.get('evidence_complete') is True and
                afl_capsule.enabled(manifest.get('warm', {})) and 'phase2' in manifest['warm'] and
                type(manifest.get('phase1_runs')) is int and manifest['phase1_runs'] == 1 and
                not any(manifest.get(key) for key in
                        ('error', 'cleanup_error', 'report_error', 'metrics_error', 'executor_errors')) and
                manifest.get('afl_exit') in (0, -signal.SIGINT, 130) and type(manifest.get('afl_exit')) is int and
                record.get('profile') == PROFILE and record.get('schema') == 1 and record.get('status') == 'drained' and
                record.get('signals') in ([signal.SIGINT], [signal.SIGTERM]) and
                all(type(value) is int for value in record['signals']) and
                record.get('forced') is False and record.get('timed_out') is False and
                record.get('work_failed') is False and
                record.get('capsule_cleanup_verified') is True and
                type(record.get('timeout_seconds')) is int and 1 <= record['timeout_seconds'] <= 600 and
                all(type(value) is int for value in (requested, drained, finished)) and
                0 < requested <= drained <= finished and drained-requested <= record['timeout_seconds']*10**9 and
                type(count) is int and count >= 0 and
                all(type(value) is int and value == count for value in
                    (manifest.get('completed_cases'), record.get('accepted_cases'), record.get('delivered_cases'),
                     record.get('phase2_submitted'), record.get('phase2_completed'), state.get('submitted'), state.get('completed'))) and
                state.get('status') == 'passed' and type(state.get('pending')) is int and state['pending'] == 0 and
                policy is not None and budget.get('policy') == policy and
                budget.get('policy_sha256') == manifest.get('storage_policy_sha256') and
                type(budget.get('pending_reservations')) is int and budget['pending_reservations'] == 0 and
                budget.get('reserve_released') is True and set(record.get('evidence_sha256', {})) == set(EVIDENCE))
    except (KeyError, TypeError, ValueError):
        return False


def verify_receipt(root, manifest):
    root = Path(root)
    f.p.require(resumable(manifest), 'Interrupted campaign was not verifiably drained')
    f.p.require(f.p.sha(root/'interruption.json') == manifest.get('interruption_sha256') and
                f.read_json(root/'interruption.json') == manifest['interruption'],
                'Interruption receipt changed')
    for name, digest in manifest['interruption']['evidence_sha256'].items():
        f.p.require(f.p.sha(root/name) == digest, 'Interruption evidence changed: '+name)
