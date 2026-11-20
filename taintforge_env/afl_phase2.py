"""Per-child Phase 2 observations and analysis for the live warm campaign."""
from __future__ import annotations

import os
import json
from pathlib import Path
import queue
import stat
import threading
import time

from . import afl_file as f

PROFILE = 'warm-child-phase2-v1'
LOG_NAMES = ('qemu_strace.log', 'runtime_stdout.log', 'runtime_stderr.log')


def settings(mode='parallel', pending=4):
    f.p.require(isinstance(mode, str) and mode in {'parallel', 'sequential'} and
                type(pending) is int and 1 <= pending <= 32,
                'Invalid per-child Phase 2 configuration')
    return {'profile': PROFILE, 'mode': mode, 'pending': pending,
            'max_log_bytes': 1024 * 1024, 'max_artifact_bytes': 16 * 1024 * 1024}


def validate(value):
    f.p.require(isinstance(value, dict) and value == settings(value.get('mode'), value.get('pending')),
                'Invalid per-child Phase 2 binding')
    return dict(value)


def regular(path, maximum):
    info = Path(path).lstat()
    f.p.require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= maximum,
                'Invalid Phase 2 artifact: ' + str(path))
    return info


class Capture:
    """Capture while the child is stopped; analysis never reads the live rootfs."""
    def __init__(self, rootfs, parent_run, case, *, excluded, config, owner=None, log_paths=None,
                 phase1_runs=1):
        self.rootfs = Path(rootfs).resolve(strict=True)
        self.parent_run, self.case = Path(parent_run), Path(case)
        self.output = self.case / 'phase2'
        self.config = validate(config)
        self.excluded = tuple(sorted(excluded))
        self.owner = owner
        self.logs = log_paths or {name: self.parent_run / 'logs' / name for name in LOG_NAMES}
        self.positions = {}
        self.phase1_runs = phase1_runs

    def snapshot(self):
        from .rootfs_diff import SnapshotOptions, snapshot_rootfs
        return snapshot_rootfs(self.rootfs, options=SnapshotOptions(exclude_paths=self.excluded))

    def before(self):
        self.output.mkdir(mode=0o700)
        (self.output / 'config').mkdir()
        (self.output / 'logs').mkdir()
        runtime = f.read_json(self.parent_run / 'config/runtime.json')
        f.p.require(runtime.get('network_mode') == 'none', 'Warm child Phase 2 requires network=none')
        runtime['afl_case'] = {'profile': PROFILE, 'case': self.case.name,
                               'input_sha256': f.p.sha(self.case / 'input'), 'phase1_runs': self.phase1_runs}
        f.atomic_json(self.output / 'config/runtime.json', runtime)
        for name in ('library_plan.json', 'library_resolution.json', 'network_policy.json'):
            path = self.parent_run / 'config' / name
            if path.is_file():
                regular(path, self.config['max_artifact_bytes'])
                (self.output / 'config' / name).write_bytes(path.read_bytes())
        f.atomic_json(self.output / 'config/rootfs_before.json', self.snapshot())
        for name, path in self.logs.items():
            path = Path(path)
            if path.exists():
                info = regular(path, 2**63 - 1)
                self.positions[name] = (info.st_dev, info.st_ino, info.st_size)
            else:
                self.positions[name] = None
        self.started_ns = time.monotonic_ns()

    def finish(self, result):
        from .rootfs_diff import diff_snapshots
        before = f.read_json(self.output / 'config/rootfs_before.json')
        after = self.snapshot()
        f.atomic_json(self.output / 'config/rootfs_after.json', after)
        f.atomic_json(self.output / 'config/rootfs_diff.json', diff_snapshots(before, after))
        segments = {}
        for name, source in self.logs.items():
            source = Path(source)
            position = self.positions[name]
            data = b''
            if source.exists():
                info = regular(source, 2**63 - 1)
                start = position[2] if position else 0
                f.p.require(position is None or (info.st_dev, info.st_ino) == position[:2],
                            'Runtime log was replaced during child execution')
                f.p.require(0 <= info.st_size - start <= self.config['max_log_bytes'],
                            'Child log exceeds its Phase 2 budget or was truncated')
                with source.open('rb') as stream:
                    stream.seek(start)
                    data = stream.read(info.st_size - start)
                f.p.require(len(data) == info.st_size - start, 'Incomplete child log capture')
                segments[name] = {'start': start, 'end': info.st_size,
                                  'device': info.st_dev, 'inode': info.st_ino}
            else:
                f.p.require(position is None, 'Runtime log disappeared during child execution')
            (self.output / 'logs' / name).write_bytes(data)
        f.atomic_json(self.output / 'config/prebuilt_execution.json', {
            'schema_version': 1, 'guest_exit_code': result['guest_exit'], 'timed_out': result.get('outcome', {}).get('timed_out', False),
            'outcome': result.get('outcome'),
            'execution_backend': 'qemu_plugin', 'trace_backend': 'qemu_strace', 'target_arch': 'i386',
            'child_namespace_pid': result['child_namespace_pid'], 'phase1_runs': self.phase1_runs})
        files = {str(path.relative_to(self.output)): f.p.sha(path)
                 for path in sorted(self.output.glob('*/*')) if path.is_file()}
        for name in files:
            regular(self.output / name, self.config['max_artifact_bytes'])
        capture = {'schema': 1, 'profile': PROFILE, 'case': self.case.name,
                   'input_sha256': f.p.sha(self.case / 'input'),
                   'result_sha256': f.p.sha(self.case / 'result.json'),
                   'coverage_sha256': f.p.sha(self.case / 'coverage.map'),
                   'child_namespace_pid': result['child_namespace_pid'],
                   'phase1_runs': self.phase1_runs,
                   'started_ns': self.started_ns, 'finished_ns': time.monotonic_ns(),
                   'log_segments': segments, 'source_files': files}
        f.atomic_json(self.output / 'capture.json', capture)
        if self.owner is not None and os.geteuid() == 0:
            for directory, names, files in os.walk(self.output, followlinks=False):
                os.chown(directory, self.owner.st_uid, self.owner.st_gid, follow_symlinks=False)
                for name in names + files:
                    os.chown(Path(directory) / name, self.owner.st_uid, self.owner.st_gid, follow_symlinks=False)
        return capture


def analyze(case, config):
    """Use the existing Phase 2 parser, requirement extractor, planner and report."""
    from .observations import load_observation_bundle
    from .qemu_strace_parser import parse_qemu_strace
    from .repair_planner import RepairPlanner
    from .requirement_extractor import RequirementExtractor
    from .report_generator import generate_report

    config = validate(config)
    case = Path(case)
    output = case / 'phase2'
    started = time.monotonic_ns()
    capture = f.read_json(output / 'capture.json')
    f.p.require(capture['profile'] == PROFILE and capture['case'] == case.name,
                'Phase 2 capture belongs to another child')
    required = {'config/runtime.json', 'config/rootfs_before.json', 'config/rootfs_after.json',
                'config/rootfs_diff.json', 'config/prebuilt_execution.json',
                *(str(Path('logs') / name) for name in LOG_NAMES)}
    f.p.require(required <= capture['source_files'].keys(), 'Incomplete Phase 2 capture manifest')
    for name, expected in capture['source_files'].items():
        relative = Path(name)
        f.p.require(not relative.is_absolute() and '..' not in relative.parts,
                    'Phase 2 capture path escapes its case')
        path = output / relative
        regular(path, config['max_artifact_bytes'])
        f.p.require(f.p.sha(path) == expected, 'Phase 2 observation changed: ' + name)
    for name, key in (('input', 'input_sha256'), ('result.json', 'result_sha256'),
                      ('coverage.map', 'coverage_sha256')):
        f.p.require(f.p.sha(case / name) == capture[key], 'Phase 2 case identity changed: ' + name)
    result = f.read_json(case / 'result.json')
    f.p.require(result['status'] == 'passed' and result['child_namespace_pid'] == capture['child_namespace_pid']
                and result['phase1_runs'] == capture['phase1_runs'],
                'Phase 2 child result mismatch')
    summary = parse_qemu_strace(output / 'logs/qemu_strace.log', output / 'logs/syscall_events.jsonl',
                               target_arch='i386')
    # QEMU prints fatal-signal records without a PID. Their immutable segment
    # belongs to exactly this reaped child; never infer a PID for a syscall.
    events_path = output / 'logs/syscall_events.jsonl'
    events = [json.loads(line) for line in events_path.read_text().splitlines()]
    for event in events:
        if event.get('event') == 'signal' and event.get('pid') is None:
            event['pid'] = capture['child_namespace_pid']
            event['pid_source'] = 'exclusive_child_capture'
    events_path.write_text(''.join(json.dumps(event)+'\n' for event in events))
    bundle = load_observation_bundle(output)
    f.p.require(bundle.syscall_events and all(event['pid'] == capture['child_namespace_pid']
                for event in bundle.syscall_events), 'Missing or mixed child syscall observations')
    requirements = RequirementExtractor().extract(bundle)
    requirements.save(output / 'config/runtime_requirements.json')
    plan = RepairPlanner().plan_file(output / 'config/runtime_requirements.json',
                                     output / 'config/repair_plan.json')
    report = generate_report(output)
    f.p.require(report['syscalls']['events_total'] == summary['events_total'] > 0,
                'Phase 2 report lost child syscall observations')
    result = {'schema': 1, 'profile': PROFILE, 'status': 'passed', 'case': case.name,
              'input_sha256': capture['input_sha256'], 'child_namespace_pid': capture['child_namespace_pid'],
              'capture_sha256': f.p.sha(output / 'capture.json'),
              'requirements_sha256': f.p.sha(output / 'config/runtime_requirements.json'),
              'repair_plan_sha256': f.p.sha(output / 'config/repair_plan.json'), 'guest_exit': result['guest_exit'],
              'outcome': result.get('outcome'),
              'phase1_runs': capture['phase1_runs'], 'syscall_events': summary['events_total'],
              'requirements': len(requirements.requirements), 'repair_plan': plan.summary(),
              'repairs_applied': False, 'environment_changes_require_new_checkpoint': True,
              'started_ns': started, 'finished_ns': time.monotonic_ns(),
              'report': str(output / 'report.json')}
    f.atomic_json(output / 'result.json', result)
    return result


class Processor:
    """A bounded host-side queue; the guest execution path remains serial."""
    def __init__(self, root, config, *, process=analyze, on_complete=None, on_error=None):
        self.root, self.config, self.process = Path(root), validate(config), process
        self.queue = queue.Queue(maxsize=self.config['pending'])
        self.slots = threading.BoundedSemaphore(self.config['pending'])
        self.lock = threading.Lock()
        self.errors = []
        self.submitted = self.completed = 0
        self.closed = False
        self.thread = None
        self.maximum_pending = 0
        self.on_complete = on_complete
        self.on_error = on_error

    def publish(self, status='running'):
        with self.lock:
            f.atomic_json(self.root / 'phase2-progress.json', {
                'schema': 1, 'profile': PROFILE, 'status': 'failed' if self.errors else status,
                'mode': self.config['mode'], 'submitted': self.submitted, 'completed': self.completed,
                'pending': self.submitted - self.completed, 'maximum_pending': self.maximum_pending,
                'errors': list(self.errors), 'updated_ns': time.monotonic_ns()})

    def start(self):
        self.publish()
        if self.config['mode'] == 'parallel':
            self.thread = threading.Thread(target=self.serve, name='tf-phase2-analysis', daemon=True)
            self.thread.start()

    def handle(self, case):
        try:
            self.process(case, self.config)
            if self.on_complete is not None:
                self.on_complete(case)
        except Exception as exc:
            message = (str(case) + ': ' + str(exc))[:3000]
            with self.lock:
                self.errors.append(message)
            if self.on_error is not None:
                self.on_error(exc)
            try:
                f.atomic_json(Path(case) / 'phase2/result.json',
                              {'schema': 1, 'status': 'failed', 'error': message})
            except Exception as persistence:
                with self.lock:
                    self.errors.append(('Cannot save failed Phase 2 result: '+str(persistence))[:3000])
                if self.on_error is not None:
                    self.on_error(persistence)
        finally:
            with self.lock:
                self.completed += 1
            self.slots.release()
            self.publish()

    def serve(self):
        while True:
            case = self.queue.get()
            try:
                if case is None:
                    return
                self.handle(case)
            finally:
                self.queue.task_done()

    def submit(self, case):
        f.p.require(not self.closed and not self.errors, 'Phase 2 analysis failed: ' + str(self.errors))
        while not self.slots.acquire(timeout=.2):
            f.p.require(not self.errors and self.thread is not None and self.thread.is_alive(),
                        'Phase 2 analysis worker failed')
        with self.lock:
            self.submitted += 1
            self.maximum_pending = max(self.maximum_pending, self.submitted - self.completed)
        if self.config['mode'] == 'sequential':
            self.handle(case)
        else:
            self.queue.put_nowait(Path(case))
        self.publish()
        f.p.require(not self.errors, 'Phase 2 analysis failed: ' + str(self.errors))

    def close(self):
        if self.closed:
            return
        self.closed = True
        if self.thread is not None:
            deadline = time.monotonic() + 60
            while True:
                try:
                    self.queue.put(None, timeout=.2)
                    break
                except queue.Full:
                    f.p.require(self.thread.is_alive(), 'Phase 2 analysis worker stopped')
                    f.p.require(time.monotonic() < deadline, 'Phase 2 queue did not drain')
            self.thread.join(max(0, deadline - time.monotonic()))
            f.p.require(not self.thread.is_alive(), 'Phase 2 analysis did not finish')
        self.publish('passed')
        f.p.require(self.completed == self.submitted and not self.errors,
                    'Phase 2 analysis failed or left pending children: ' + str(self.errors))
        if (self.root / 'campaign.json').is_file():
            manifest = f.read_json(self.root / 'campaign.json')
            if manifest.get('profile') == f.PROFILE:
                f.verify_campaign(self.root)


def campaign_report(root, manifest):
    root = Path(root)
    path = root / 'warm-session-result.json'
    session = f.read_json(path) if path.is_file() else {}
    capsule = session.get('capsule', {})
    return {'schema': 1, 'status': manifest['status'], 'execution_mode': manifest.get('execution_mode'),
            'phase1_runs': manifest.get('phase1_runs'), 'cases': manifest.get('cases'),
            'capsule_status': capsule.get('status'),
            'capsule_profile': manifest.get('warm',{}).get('capsule_profile'),
            'afl_checkpoint': capsule.get('afl_checkpoint'),
            'analysis_quality': capsule.get('analysis_quality'),
            'control_guard': capsule.get('control_guard'),
            'retirement': capsule.get('phase1_retirement', {}),
            'resources': capsule.get('resources', {}), 'phase2': manifest.get('phase2'),
            'afl_started_ns': manifest.get('afl_started_ns'),
            'afl_finished_ns': manifest.get('afl_finished_ns'),
            'repair_policy': 'plans_only_in_live_campaign; explicit_evolve_creates_new_checkpoint',
            'metrics': manifest.get('metrics'), 'findings_directory': str(root/'findings'),
            'storage': manifest.get('storage_result'), 'stop_reason': manifest.get('stop_reason'),
            'evidence_complete': manifest.get('evidence_complete'),
            'source_manifest': str(root/'campaign.json'), 'afl_statistics': str(root/'afl/default/fuzzer_stats'),
            'case_reports': [str(path) for path in sorted((root/'cases').glob('*/phase2/result.json'))]}
