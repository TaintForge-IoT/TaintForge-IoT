"""Fixed-size runtime counters and a polled budget for retained observations."""
from __future__ import annotations

from collections import Counter
import os
from pathlib import Path
import threading
import time

from . import afl_file as f


def artifact_bytes(root):
    """Walk retained host artifacts only, never execution rootfs or service mounts."""
    total = 0
    for name in ('cases', 'findings', 'afl'):
        start = Path(root)/name
        if not start.exists():
            continue
        for directory, dirs, files in os.walk(start, followlinks=False):
            dirs[:] = [name for name in dirs if name != 'rootfs' and not (Path(directory)/name).is_symlink()]
            for name in files:
                path = Path(directory)/name
                if not path.is_symlink():
                    try:
                        total += path.stat().st_size
                    except FileNotFoundError:
                        pass  # An atomic publisher or AFL replaced a temporary file.
    ready = Path(root)/'warm-ready.json'
    if ready.is_file():
        run = Path(f.read_json(ready)['run_dir'])
        for name in ('qemu_strace.log', 'runtime_stdout.log', 'runtime_stderr.log'):
            path = run/'logs'/name
            if path.is_file() and not path.is_symlink():
                total += path.stat().st_size
    return total


class Metrics:
    def __init__(self, root):
        self.root = Path(root)
        self.lock = threading.Lock()
        self.started = time.monotonic()
        self.counts = Counter()
        self.latencies = Counter()
        self.peak_child_rss_kib = 0
        self.child_time_ms = 0
        self.peak_parent_rss_mib = 0
        self.peak_parent_fds = 0
        self.last_disk_poll = float('-inf')
        self.bytes = 0

    def record(self, result):
        value = result['outcome']
        with self.lock:
            self.counts[value['kind']] += 1
            self.peak_parent_rss_mib = max(self.peak_parent_rss_mib, value.get('parent_rss_mib', 0))
            self.peak_parent_fds = max(self.peak_parent_fds, value.get('parent_fd_count', 0))
            ms = value['duration_ms']
            self.child_time_ms += ms
            self.latencies[str(max(1, ms).bit_length())] += 1
            self.peak_child_rss_kib = max(self.peak_child_rss_kib, value['child_peak_rss_kib'])

    def publish(self, *, executed, completed, final=False):
        now = time.monotonic()
        if final or now-self.last_disk_poll >= 5:
            self.bytes = artifact_bytes(self.root)
            self.last_disk_poll = now
        phase2_path = self.root/'phase2-progress.json'
        phase2 = f.read_json(phase2_path) if phase2_path.is_file() else {}
        ready_path = self.root/'warm-ready.json'
        ready = f.read_json(ready_path) if ready_path.is_file() else {}
        with self.lock:
            value = {'schema': 1, 'elapsed_seconds': now-self.started,
                'cases': executed, 'delivered_cases': completed,
                'executions_per_second': completed/max(now-self.started, .001),
                'outcomes': dict(self.counts), 'child_runtime_ms_total': self.child_time_ms,
                'child_peak_rss_kib': self.peak_child_rss_kib,
                'checkpoint_rss_mib': ready.get('rss_mib'), 'parent_rss_peak_mib': self.peak_parent_rss_mib,
                'checkpoint_parent_fds': ready.get('parent_resources', {}).get('fd_count'),
                'parent_fd_peak': self.peak_parent_fds,
                'latency_log2_ms_histogram': dict(self.latencies),
                'retained_artifact_bytes': self.bytes,
                'artifact_scope': 'cases_findings_afl_and_runtime_logs; excludes_preparation_and_rootfs',
                'budget_poll_seconds': 5, 'budget_is_filesystem_quota': False,
                'phase2_pending': phase2.get('pending'), 'phase2_completed': phase2.get('completed')}
        f.atomic_json(self.root/'metrics.json', value)
        return value
