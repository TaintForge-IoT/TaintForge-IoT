"""One unpack/retirement per live campaign, followed by serial QEMU forks."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import select
import shutil
import signal
import socket
import struct
import subprocess
import sys
import threading
import time

from . import afl_file as f
from .afl_transport import AttemptServer, recv_exact, stop_case

MAGIC = 0x54465731
PROFILE = 'afl-post-retirement-fork-v1'
EXCLUDED = {'proc', 'sys', 'dev', '__taintforge', '__taintforge_capsule'}


def configuration(root, *, bootstrap_seconds, campaign_seconds, timeout_ms, max_rss_mib):
    f.p.require(all(type(x) is int for x in
                    (bootstrap_seconds, campaign_seconds, timeout_ms, max_rss_mib)), 'Invalid warm limits')
    f.p.require(1 <= bootstrap_seconds <= 7200 and 1 <= campaign_seconds <= 72000 and
                10 <= timeout_ms <= 600000 and 64 <= max_rss_mib <= 131072, 'Invalid warm limits')
    root = Path(root).resolve()
    f.p.require(len(os.fsencode(root/'warm.sock')) < 108, 'Campaign path exceeds the Unix socket limit')
    return {'profile': PROFILE, 'campaign_root': str(root),
            'bootstrap_seconds': bootstrap_seconds, 'campaign_seconds': campaign_seconds,
            'timeout_ms': timeout_ms, 'max_rss_mib': max_rss_mib}


def validate(value):
    f.p.require(value == configuration(value['campaign_root'], **{k: value[k] for k in
                ('bootstrap_seconds', 'campaign_seconds', 'timeout_ms', 'max_rss_mib')}),
                'Invalid warm binding')
    return dict(value)


def prepare_campaign(out, *, binary, qemu, plugin, guest_path, seeds, max_input=4096,
                     bootstrap_seconds=1200, campaign_seconds=3600, timeout_ms=2000,
                     max_rss_mib=2048, memory_mib=65536, analysis_mib=49152):
    config = configuration(out, bootstrap_seconds=bootstrap_seconds, campaign_seconds=campaign_seconds,
                           timeout_ms=timeout_ms, max_rss_mib=max_rss_mib)
    # The private ABI must actually be exported, not just a matching version string.
    symbols = f.p.command('nm', '-D', str(qemu))
    f.p.require(' qemu_plugin_tf_warm_configure' in symbols and ' qemu_plugin_tf_warm_arm' in symbols,
                'QEMU lacks TaintForge warm ABI 1; apply experiments/afl_file/qemu/apply.py and rebuild')
    lifetime = bootstrap_seconds + campaign_seconds + 60
    options = ['--timeout', str(lifetime+15), '--capsule-total-ms', str(lifetime*1000),
               '--capsule-memory-mib', str(memory_mib), '--analysis-memory-mib', str(analysis_mib)]
    value = f.prepare_campaign(out, binary=binary, qemu=qemu, plugin=plugin, guest_path=guest_path,
                               seeds=seeds, max_input=max_input, pipeline_options=options)
    value['warm'] = config
    value['execution_mode'] = PROFILE
    for name in ('taintforge_env/afl_warm.py', 'experiments/afl_file/qemu/tf-warm.h'):
        value['source_sha256'][name] = f.p.sha(f.PROJECT/name)
    f.atomic_json(Path(out)/'campaign.json', value)
    return value


class FilesystemBaseline:
    """Restore the paused parent's root inode in place; no child is alive here."""
    def __init__(self, root, backup):
        self.root, self.backup = Path(root).resolve(), Path(backup).resolve()
        f.p.require(self.root != Path('/') and not self.backup.is_relative_to(self.root),
                    'Invalid checkpoint filesystem paths')
        self.backup.mkdir(parents=True, exist_ok=False)
        for directory, names, files in os.walk(self.root, followlinks=False):
            if Path(directory) == self.root: names[:] = [n for n in names if n not in EXCLUDED]
            for name in files:
                path = Path(directory)/name
                f.p.require(path.is_symlink() or path.is_file() and path.stat().st_nlink == 1,
                            'Checkpoint cannot preserve a special file or hardlink')
        self._copy(self.root, self.backup)
        from .environment_snapshot import scan_environment, tree_digest
        self.digest = tree_digest(scan_environment(self.backup))

    @staticmethod
    def _copy(source, destination):
        for item in source.iterdir():
            if item.name in EXCLUDED: continue
            target = destination/item.name
            if item.is_symlink(): target.symlink_to(os.readlink(item))
            elif item.is_dir(): shutil.copytree(item, target, symlinks=True)
            else:
                f.p.require(item.is_file() and item.stat().st_nlink == 1,
                            'Checkpoint requires private regular files')
                shutil.copy2(item, target)

    def restore(self):
        from .environment_snapshot import scan_environment, tree_digest
        f.p.require(tree_digest(scan_environment(self.backup)) == self.digest,
                    'Checkpoint filesystem changed')
        for item in self.root.iterdir():
            if item.name in EXCLUDED: continue
            if item.is_dir() and not item.is_symlink(): shutil.rmtree(item)
            else: item.unlink()
        self._copy(self.backup, self.root)
        # Files were prepared for the unprivileged M4 execution identity.
        if os.geteuid() == 0:
            owner = self.root.stat()
            for directory, names, files in os.walk(self.root, followlinks=False):
                if Path(directory) == self.root:
                    names[:] = [n for n in names if n not in EXCLUDED]
                os.chown(directory, owner.st_uid, owner.st_gid, follow_symlinks=False)
                for name in names+files:
                    os.chown(Path(directory)/name, owner.st_uid, owner.st_gid, follow_symlinks=False)


class Broker:
    """Lives in the capsule supervisor; only one child can execute at a time."""
    def __init__(self, binding, ipc):
        self.binding, self.ipc = binding, Path(ipc)
        self.config = validate(binding['afl_warm'])
        self.root = Path(self.config['campaign_root'])
        self.owner = self.root.stat()
        self.stop = threading.Event()
        self.ready = threading.Event()
        self.errors = []
        self.native = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.native.bind(str(self.ipc/'afl-warm.sock'))
        from .capsule_hardening import socket_permissions
        socket_permissions(self.ipc/'afl-warm.sock', binding)
        self.native.listen(1)
        self.native.settimeout(.2)
        self.requests = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.requests.bind(str(self.root/'warm.sock'))
        if os.geteuid() == 0: os.chown(self.root/'warm.sock', self.owner.st_uid, self.owner.st_gid)
        os.chmod(self.root/'warm.sock', 0o600)
        self.requests.listen(1)
        self.requests.settimeout(.2)
        self.thread = threading.Thread(target=self.serve, daemon=True, name='tf-warm-broker')
        self.connection = None
        self.executions = 0
        self.closed = False

    def start(self): self.thread.start()

    def publish(self, path, value):
        f.atomic_json(path, value)
        if os.geteuid() == 0: os.chown(path, self.owner.st_uid, self.owner.st_gid)

    def close(self):
        if self.closed: return
        self.closed = True
        self.stop.set()
        self.thread.join(5)
        if self.thread.is_alive() and self.connection:
            self.connection.shutdown(socket.SHUT_RDWR)
            self.thread.join(5)
        self.native.close(); self.requests.close()
        for path in (self.ipc/'afl-warm.sock', self.root/'warm.sock'): path.unlink(missing_ok=True)
        f.p.require(not self.thread.is_alive(), 'Warm broker did not stop')

    def serve(self):
        report = {'status': 'failed', 'phase1_runs': 1, 'children': 0}
        baseline = None
        try:
            while not self.stop.is_set():
                try: self.connection, _ = self.native.accept(); break
                except socket.timeout: continue
            if self.connection is None: return
            with self.connection as connection:
                connection.settimeout(self.config['timeout_ms']/1000+10)
                magic, version, pid, rss = struct.unpack('!4I', recv_exact(connection, 16))
                f.p.require((magic, version) == (MAGIC, 1), 'Warm backend ABI mismatch')
                from .capsule_hardening import peer_uid
                credentials = struct.unpack('3i', connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                f.p.require(credentials[:2] == (pid, peer_uid(self.binding)), 'Wrong warm backend peer')
                # The native checkpoint follows verified retirement and RESUME 2.
                from .phase1_retirement import verify_retirement
                verify_retirement(self.binding, pid)
                baseline = FilesystemBaseline(self.binding['rootfs'], self.root/'checkpoint-rootfs')
                self.ready.set()
                self.publish(self.root/'warm-ready.json', {'schema': 1, 'status': 'ready',
                    'pid_namespace_pid': pid, 'rss_mib': rss, 'phase1_runs': 1,
                    'run_dir': self.binding['run_dir'], 'filesystem_sha256': baseline.digest})
                deadline = time.monotonic()+self.config['campaign_seconds']+30
                while not self.stop.is_set():
                    f.p.require(time.monotonic() < deadline, 'Warm campaign lifetime exceeded')
                    try: request, _ = self.requests.accept()
                    except socket.timeout: continue
                    with request:
                        request.settimeout(5)
                        credentials = struct.unpack('3i', request.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                        f.p.require(credentials[1] == self.owner.st_uid, 'Wrong warm campaign client')
                        operation = recv_exact(request, 1)
                        if operation == b'S':
                            request.sendall(b'K'); break
                        f.p.require(operation == b'R', 'Invalid warm client request')
                        index, size = struct.unpack('!2I', recv_exact(request, 8))
                        manifest = f.read_json(self.root/'campaign.json')
                        f.p.require(1 <= size <= manifest['max_input'], 'Warm input too large')
                        data = recv_exact(request, size)
                        baseline.restore()
                        f.guest_file(self.binding['rootfs'], self.binding['afl_file']['guest_path']).write_bytes(data)
                        map_path = self.ipc/f.MAP_NAME
                        # Keep the mapped inode; replacing it would leave QEMU on a stale bitmap.
                        with map_path.open('r+b') as output:
                            output.write(f.HEADER.pack(b'TFACOV1\0', 1, f.MAP_SIZE, 0, 0, 0, 0, 0, 0))
                            output.write(bytes(f.MAP_SIZE))
                        connection.sendall(struct.pack('!3I', MAGIC, 1, self.config['timeout_ms']))
                        magic, child, status, timed_out = struct.unpack('!4I', recv_exact(connection, 16))
                        self.executions += 1
                        f.p.require(magic == MAGIC and not timed_out and os.WIFEXITED(status) and
                                    os.WEXITSTATUS(status) != 86,
                                    'Warm child timed out or executor failed; inspect qemu_strace.log')
                        coverage, bitmap = f.inspect_map(map_path)
                        case = self.root/'cases'/f'{index:08d}'
                        f.p.require(case.is_dir() and not case.is_symlink() and
                                    not (case/'input').is_symlink() and (case/'input').read_bytes() == data,
                                    'Warm case identity changed')
                        result = {'schema': 1, 'status': 'passed', 'phase1_runs': 1,
                            'child_namespace_pid': child, 'guest_exit': os.WEXITSTATUS(status),
                            'input': f.settings(self.binding['afl_file']['guest_path'], data),
                            'coverage': coverage, 'filesystem_sha256': baseline.digest}
                        (case/'coverage.map').write_bytes(bitmap)
                        if os.geteuid() == 0: os.chown(case/'coverage.map', self.owner.st_uid, self.owner.st_gid)
                        self.publish(case/'result.json', result)
                        request.sendall(struct.pack('!4I', 0x54464131, 0, 0, f.MAP_SIZE)+bitmap)
                connection.sendall(struct.pack('!3I', MAGIC, 0, 0))
                report['status'] = 'passed'
        except Exception as exc:
            self.errors.append(str(exc)); report['error'] = str(exc)
        finally:
            self.ready.set()
            report['children'] = self.executions
            if baseline is not None and os.geteuid() == 0:
                for directory, names, files in os.walk(baseline.backup, followlinks=False):
                    os.chown(directory, self.owner.st_uid, self.owner.st_gid, follow_symlinks=False)
                    for name in names+files:
                        os.chown(Path(directory)/name, self.owner.st_uid, self.owner.st_gid, follow_symlinks=False)
            self.publish(self.root/'warm-executor.json', report)


def execute_session(root):
    """Exactly one call to the existing unified pipeline for the live campaign."""
    from scripts.run_unified_pipeline import run_session
    root = Path(root).resolve(strict=True)
    manifest = f.verify_campaign(root)
    validate(manifest['warm'])
    original = manifest['launch']
    template = root/'warm-template'; template.mkdir()
    rootfs = template/'rootfs'
    f.EnvironmentSnapshotStore(manifest['snapshot_store']).clone(manifest['snapshot_id'], rootfs)
    shutil.copytree(Path(original['template_run_dir'])/'config', template/'config')
    runtime = f.read_json(template/'config/runtime.json')
    runtime['rootfs'] = str(rootfs)
    runtime['phase1']['bundle_path'] = str(template/'config/analyzer_runtime')
    runtime['afl_file'] = f.settings(manifest['guest_path'], f.guest_file(rootfs, manifest['guest_path']).read_bytes())
    runtime['afl_warm'] = manifest['warm']
    f.atomic_json(template/'config/runtime.json', runtime)
    launch = original | {'session_dir': str(root/'warm-session'), 'template_run_dir': str(template),
        'snapshot_store': str(root/'warm-snapshots'), 'seed_rootfs': str(rootfs),
        'max_iterations': 1, 'target_spec_path': None, 'replay_store_path': None}
    report, code = run_session(root, launch, max_steps=1)
    f.p.require(code == 0 and report['capsule']['status'] == 'passed', 'Warm session failed final verification')
    f.atomic_json(root/'warm-session-result.json', report)
    return report


class WarmAttemptServer(AttemptServer):
    def __init__(self, root, **kwargs):
        super().__init__(root, **kwargs)
        self.worker = None
        self.output = None
        self.closed = False
        self.started = False

    def start(self):
        self.output = (self.root/'warm-worker.log').open('wb')
        self.worker = subprocess.Popen([sys.executable, '-m', 'scripts.run_afl_file', 'warm-session',
            '--out', str(self.root)], cwd=f.PROJECT, stdout=self.output, stderr=self.output,
            start_new_session=True)
        config = f.read_json(self.root/'campaign.json')['warm']
        deadline = time.monotonic()+config['bootstrap_seconds']
        try:
            while not (self.root/'warm-ready.json').is_file():
                f.p.require(self.worker.poll() is None, 'Warm bootstrap failed; inspect warm-worker.log')
                f.p.require(time.monotonic() < deadline, 'Warm bootstrap deadline exceeded')
                if self.stop.wait(.1): raise InterruptedError('Warm bootstrap interrupted')
            f.p.require(f.read_json(self.root/'warm-ready.json')['status'] == 'ready', 'Invalid warm readiness')
            super().start()
            self.started = True
        except BaseException:
            self.close(); raise

    def close(self):
        if self.closed: return
        self.closed = True
        if self.thread.ident is not None: super().close()
        else:
            self.channel.close(); self.peer.close()
        if self.worker is not None:
            if self.worker.poll() is None:
                try:
                    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                        connection.settimeout(2); connection.connect(str(self.root/'warm.sock'))
                        connection.sendall(b'S'); recv_exact(connection, 1)
                    self.worker.wait(timeout=20)
                except (OSError, subprocess.TimeoutExpired): stop_case(self.worker, self.root)
            self.output.close()
            if self.started:
                f.p.require(self.worker.returncode == 0, 'Warm pipeline failed; inspect warm-worker.log')

    def execute(self, connection):
        connection.settimeout(self.deadline)
        size = struct.unpack('!I', recv_exact(connection, 4))[0]
        manifest = f.read_json(self.root/'campaign.json')
        f.p.require(1 <= size <= manifest['max_input'], 'Input exceeds warm campaign limit')
        data = recv_exact(connection, size)
        index = self.executed; self.executed += 1
        case = self.root/'cases'/f'{index:08d}'; case.mkdir()
        (case/'input').write_bytes(data)
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as worker:
            worker.settimeout(self.deadline); worker.connect(str(self.root/'warm.sock'))
            worker.sendall(b'R'+struct.pack('!2I', index, size)+data)
            response = recv_exact(worker, 16+f.MAP_SIZE)
        f.p.require(struct.unpack('!4I', response[:16]) == (0x54464131, 0, 0, f.MAP_SIZE), 'Invalid warm response')
        try:
            connection.sendall(response)
            self.completed += 1
            f.atomic_json(case/'transport.json', {'status': 'delivered', 'cleanup_confirmed': True})
        except OSError:
            f.atomic_json(case/'transport.json', {'status': 'cancelled', 'cleanup_confirmed': True})
            raise ConnectionError('AFL bridge cancelled; child already reaped')
