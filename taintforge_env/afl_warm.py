"""One unpack/retirement per live campaign, followed by serial QEMU forks."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import select
import shutil
import signal
import socket
import stat
import struct
import subprocess
import sys
import threading
import time

from . import afl_file as f
from . import afl_outcome as outcome
from .afl_transport import AttemptServer, recv_exact, stop_case

MAGIC = 0x54465731
PROFILE = 'afl-post-retirement-fork-v1'
EXCLUDED = {'proc', 'sys', 'dev', '__taintforge', '__taintforge_capsule'}


def configuration(root, *, bootstrap_seconds, campaign_seconds, timeout_ms, max_rss_mib,
                  phase2_mode='off', phase2_pending=4, capsule_m5=False, storage=None):
    f.p.require(all(type(x) is int for x in
                    (bootstrap_seconds, campaign_seconds, timeout_ms, max_rss_mib)), 'Invalid warm limits')
    f.p.require(1 <= bootstrap_seconds <= 7200 and 1 <= campaign_seconds <= 72000 and
                10 <= timeout_ms <= 600000 and 64 <= max_rss_mib <= 131072, 'Invalid warm limits')
    root = Path(root).resolve()
    f.p.require(len(os.fsencode(root/'warm.sock')) < 108, 'Campaign path exceeds the Unix socket limit')
    result = {'profile': PROFILE, 'campaign_root': str(root),
            'bootstrap_seconds': bootstrap_seconds, 'campaign_seconds': campaign_seconds,
            'timeout_ms': timeout_ms, 'max_rss_mib': max_rss_mib}
    if capsule_m5:
        from .afl_capsule import PROFILE as capsule_profile
        result['capsule_profile'] = capsule_profile
    if phase2_mode != 'off':
        from .afl_phase2 import settings
        result['phase2'] = settings(phase2_mode, phase2_pending)
    if storage is not None:
        from .afl_storage import validate as storage_policy
        result['storage'] = storage_policy(storage)
    return result


def validate(value):
    required = {'profile', 'campaign_root', 'bootstrap_seconds', 'campaign_seconds',
                'timeout_ms', 'max_rss_mib'}
    f.p.require(isinstance(value, dict) and
                required <= set(value) <= required | {'phase2', 'capsule_profile', 'storage'} and
                isinstance(value.get('campaign_root'), str), 'Invalid warm binding')
    options = {k: value[k] for k in ('bootstrap_seconds', 'campaign_seconds', 'timeout_ms', 'max_rss_mib')}
    if 'capsule_profile' in value:
        options['capsule_m5'] = True
    if 'phase2' in value:
        from .afl_phase2 import validate as validate_phase2
        config = validate_phase2(value['phase2'])
        options.update(phase2_mode=config['mode'], phase2_pending=config['pending'])
    if 'storage' in value:
        options['storage'] = value['storage']
    f.p.require(value == configuration(value['campaign_root'], **options),
                'Invalid warm binding')
    return dict(value)


def prepare_campaign(out, *, binary, qemu, plugin, guest_path, seeds, max_input=4096,
                     bootstrap_seconds=1200, campaign_seconds=3600, timeout_ms=2000,
                     max_rss_mib=2048, memory_mib=65536, analysis_mib=49152,
                     phase2_mode='off', phase2_pending=4, analysis_policy='strict',
                     flags_receipt=None, ir_start=None):
    config = configuration(out, bootstrap_seconds=bootstrap_seconds, campaign_seconds=campaign_seconds,
                           timeout_ms=timeout_ms, max_rss_mib=max_rss_mib,
                           phase2_mode=phase2_mode, phase2_pending=phase2_pending, capsule_m5=True)
    # The private ABI must actually be exported, not just a matching version string.
    symbols = f.p.command('nm', '-D', str(qemu))
    f.p.require(' qemu_plugin_tf_warm_configure' in symbols and ' qemu_plugin_tf_warm_arm' in symbols and ' qemu_plugin_tf_warm_abi2' in symbols,
                'QEMU lacks TaintForge warm ABI 2; apply experiments/afl_file/qemu/apply.py and rebuild')
    lifetime = bootstrap_seconds + campaign_seconds + 60
    options = ['--timeout', str(lifetime+15), '--capsule-total-ms', str(lifetime*1000),
               '--capsule-memory-mib', str(memory_mib), '--analysis-memory-mib', str(analysis_mib),
               '--capsule-control-guard']
    if flags_receipt is not None:
        options += ['--phase1-flags-receipt', str(flags_receipt)]
    if ir_start is not None:
        options += ['--retirement-ir-start', hex(ir_start)]
    value = f.prepare_campaign(out, binary=binary, qemu=qemu, plugin=plugin, guest_path=guest_path,
                               seeds=seeds, max_input=max_input, analysis_policy=analysis_policy, pipeline_options=options)
    value['warm'] = config
    value['execution_mode'] = PROFILE
    from .afl_capsule import SOURCES
    for name in SOURCES:
        value['source_sha256'][name] = f.p.sha(f.PROJECT/name)
    for name in ('taintforge_env/afl_warm.py', 'taintforge_env/afl_session.py', 'taintforge_env/iteration_controller.py', 'taintforge_env/afl_outcome.py', 'taintforge_env/afl_findings.py', 'taintforge_env/afl_metrics.py', 'taintforge_env/afl_replay.py', 'taintforge_env/afl_evidence.py', 'taintforge_env/afl_epochs.py', 'experiments/afl_file/qemu/tf-warm.h'):
        value['source_sha256'][name] = f.p.sha(f.PROJECT/name)
    for path in sorted((f.PROJECT/'taintforge_env').glob('*.py')):
        value['source_sha256'][str(path.relative_to(f.PROJECT))] = f.p.sha(path)
    f.atomic_json(Path(out)/'campaign.json', value)
    return value


def rootfs_mounts(root):
    """Read mount identities, including bind mounts on the same filesystem."""
    root = Path(root)
    result = {}
    text = Path('/proc/self/mountinfo').read_text(encoding='utf-8', errors='surrogateescape')
    for line in text.splitlines():
        fields = line.split()
        f.p.require(len(fields) >= 10 and '-' in fields[6:], 'Invalid mountinfo record')
        name = re.sub(r'\\([0-7]{3})', lambda match: chr(int(match[1], 8)), fields[4])
        point = Path(name)
        if point.is_relative_to(root):
            result.setdefault(point.relative_to(root), []).append(tuple(fields))
    return {name: tuple(records) for name, records in result.items()}


class FilesystemBaseline:
    """Reset guest files in place while retaining bound service mounts and their ancestors."""
    def __init__(self, root, backup, *, protected_mounts=()):
        self.root, self.backup = Path(root).resolve(), Path(backup).resolve()
        f.p.require(self.root != Path('/') and not self.backup.is_relative_to(self.root)
                    and not self.root.is_relative_to(self.backup), 'Invalid checkpoint filesystem paths')
        protected = set()
        for name in protected_mounts:
            path = Path(name)
            f.p.require(path.is_absolute() and path != self.root and path.is_relative_to(self.root)
                        and '..' not in path.parts, 'Invalid protected checkpoint mount')
            protected.add(path.relative_to(self.root))
        self.protected_mounts = frozenset(protected)
        self.excluded = frozenset(Path(name) for name in EXCLUDED) | self.protected_mounts
        self.ancestors = {parent for name in self.excluded for parent in name.parents
                          if parent != Path('.')}
        info = self.root.stat()
        self.root_identity = (info.st_dev, info.st_ino)
        self.mounts = rootfs_mounts(self.root)
        self._check_layout()
        self.backup.mkdir(parents=True, exist_ok=False)
        self._copy(self.root, self.backup)
        from .environment_snapshot import scan_environment, tree_digest
        self.digest = tree_digest(scan_environment(self.backup))
        self.content_entries = self._content_entries(self.backup)
        self.content_digest = self._content_digest(self.backup)
        self.restore_retries = 0

    def _excluded(self, relative):
        return any(relative == name or relative.is_relative_to(name) for name in self.excluded)

    def _check_layout(self):
        info = self.root.lstat()
        f.p.require(stat.S_ISDIR(info.st_mode) and (info.st_dev, info.st_ino) == self.root_identity,
                    'Checkpoint root directory changed')
        f.p.require(rootfs_mounts(self.root) == self.mounts, 'Checkpoint mount layout changed')
        for name in self.mounts:
            f.p.require(name == Path('.') or self._excluded(name),
                        'Unsupported checkpoint mount: /'+str(name))
        for name in self.protected_mounts:
            f.p.require(name in self.mounts, 'Required service mount is missing: /'+str(name))
        for name in sorted(self.ancestors, key=lambda path: len(path.parts)):
            f.p.require(stat.S_ISDIR((self.root/name).lstat().st_mode),
                        'Service mount ancestor is not a directory: /'+str(name))

    def _copy(self, source, destination, relative=Path('.')):
        for item in list(source.iterdir()):
            name = relative/item.name
            if self._excluded(name): continue
            target = destination/item.name
            info = item.lstat()
            if stat.S_ISLNK(info.st_mode):
                target.symlink_to(os.readlink(item))
            elif stat.S_ISDIR(info.st_mode):
                f.p.require(not target.is_symlink(), 'Checkpoint destination traverses a symlink')
                target.mkdir(exist_ok=name in self.ancestors)
                self._copy(item, target, name)
                shutil.copystat(item, target, follow_symlinks=False)
            else:
                f.p.require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1,
                            'Checkpoint requires private regular files')
                from .afl_storage import copy_file
                copy_file(item, target)

    def _clear(self, directory, relative=Path('.')):
        for item in list(directory.iterdir()):
            name = relative/item.name
            if self._excluded(name): continue
            if stat.S_ISDIR(item.lstat().st_mode):
                self._clear(item, name)
                if name not in self.ancestors: item.rmdir()
            else:
                f.p.require(name not in self.ancestors, 'Service mount ancestor changed')
                item.unlink()

    def _set_owner(self, directory, owner, relative=Path('.')):
        for item in directory.iterdir():
            name = relative/item.name
            if self._excluded(name): continue
            info = item.lstat()
            os.chown(item, owner.st_uid, owner.st_gid, follow_symlinks=False)
            if stat.S_ISDIR(info.st_mode): self._set_owner(item, owner, name)

    def _content_entries(self, root):
        from .rootfs_diff import SnapshotOptions, snapshot_rootfs
        value = snapshot_rootfs(root, options=SnapshotOptions(exclude_paths=tuple('/'+str(n) for n in self.excluded)))
        return {name: {key: item.get(key) for key in ('type', 'mode', 'size', 'sha256', 'symlink_target')}
                   for name, item in value['entries'].items() if name != '/'}

    def _content_digest(self, root):
        import json
        entries = self._content_entries(root)
        return hashlib.sha256(json.dumps(entries, sort_keys=True).encode()).hexdigest()

    def restore(self):
        from .environment_snapshot import scan_environment, tree_digest
        self._check_layout()
        f.p.require(tree_digest(scan_environment(self.backup)) == self.digest,
                    'Checkpoint filesystem changed')
        owner = self.root.stat()
        # No guest runs during reset. Retry a transient collision/partial copy
        # once, and accept only a fully checked replacement of the whole tree.
        for attempt in range(2):
            self._check_layout()
            self._clear(self.root)
            try:
                self._copy(self.backup, self.root)
            except FileExistsError:
                if attempt:
                    raise
                self.restore_retries += 1
                continue
            if os.geteuid() == 0: self._set_owner(self.root, owner)
            actual = self._content_entries(self.root)
            if actual == self.content_entries:
                return
            changed = sorted(name for name in actual.keys() | self.content_entries.keys()
                             if actual.get(name) != self.content_entries.get(name))
            f.p.require(not attempt, 'Restored guest filesystem differs from the checkpoint: '+str(changed[:20]))
            self.restore_retries += 1


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
                f.p.require((magic, version) == (MAGIC, outcome.VERSION), 'Warm backend ABI mismatch; rebuild warm QEMU')
                from .capsule_hardening import peer_uid
                credentials = struct.unpack('3i', connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                f.p.require(credentials[:2] == (pid, peer_uid(self.binding)), 'Wrong warm backend peer')
                # The native checkpoint follows verified retirement and RESUME 2.
                from .phase1_retirement import verify_retirement
                verify_retirement(self.binding, pid)
                from . import afl_capsule
                admission = None
                if afl_capsule.enabled(self.config):
                    admission = afl_capsule.checkpoint(self.binding, pid)
                    f.p.write_json(Path(self.binding['run_dir'])/'logs/capsule/afl-checkpoint.json', admission)
                rootfs = Path(self.binding['rootfs']).resolve()
                phase_output = Path(self.binding['run_dir'])/'logs/phase1'
                phase_binding = f.read_json(Path(self.binding['run_dir'])/'config/phase1_binding.json')
                f.p.require(phase_output == Path(phase_binding['output_directory']),
                            'Warm Phase 1 output mount differs from its binding')
                output_mount = rootfs/phase_output.relative_to('/')
                from .capsule_exec_identity import warm_mounts
                baseline = FilesystemBaseline(rootfs, self.root/'checkpoint-rootfs',
                                              protected_mounts=(output_mount, *warm_mounts(self.binding, pid)))
                from .afl_resources import sample_parent
                parent_resources = sample_parent(pid)
                self.ready.set()
                self.publish(self.root/'warm-ready.json', {'schema': 1, 'status': 'ready',
                    'pid_namespace_pid': pid, 'rss_mib': rss, 'phase1_runs': 1, 'backend_abi': outcome.VERSION,
                    'parent_resources': parent_resources,
                    'run_dir': self.binding['run_dir'], 'filesystem_sha256': baseline.digest,
                    **({'capsule_checkpoint': admission} if admission is not None else {}),
                    'preserved_mounts': sorted('/'+str(name) for name in baseline.mounts
                                               if name != Path('.'))})
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
                        case = self.root/'cases'/f'{index:08d}'
                        f.p.require(case.is_dir() and not case.is_symlink() and
                                    not (case/'input').is_symlink() and (case/'input').read_bytes() == data,
                                    'Warm case identity changed')
                        baseline.restore()
                        f.guest_file(self.binding['rootfs'], self.binding['afl_file']['guest_path']).write_bytes(data)
                        capture = None
                        if 'phase2' in self.config:
                            from .afl_phase2 import Capture
                            capture = Capture(rootfs, self.binding['run_dir'], case,
                                excluded=('/'+str(name) for name in baseline.excluded),
                                config=self.config['phase2'], owner=self.owner)
                            capture.before()
                        map_path = self.ipc/f.MAP_NAME
                        # Keep the mapped inode; replacing it would leave QEMU on a stale bitmap.
                        with map_path.open('r+b') as output:
                            output.write(f.HEADER.pack(b'TFACOV1\0', 1, f.MAP_SIZE, 0, 0, 0, 0, 0, 0))
                            output.write(bytes(f.MAP_SIZE))
                        connection.sendall(struct.pack('!3I', MAGIC, 1, self.config['timeout_ms']))
                        child_outcome = outcome.decode(recv_exact(connection, outcome.RESPONSE.size))
                        self.executions += 1
                        resources = sample_parent(pid, expected=parent_resources)
                        child_outcome['parent_fd_count'] = resources['fd_count']
                        if child_outcome['kind'] == 'infra_error':
                            self.publish(case/'outcome.json', child_outcome)
                            raise RuntimeError('Warm backend infrastructure failure: '+str(child_outcome))
                        coverage, bitmap = f.inspect_map(map_path, complete=child_outcome['kind'] == 'normal')
                        f.p.require(coverage['started'] == 1 and coverage['blocks'] > 0 and any(bitmap),
                                    'Child did not produce post-input guest coverage')
                        case = self.root/'cases'/f'{index:08d}'
                        f.p.require(case.is_dir() and not case.is_symlink() and
                                    not (case/'input').is_symlink() and (case/'input').read_bytes() == data,
                                    'Warm case identity changed')
                        result = {'schema': 1, 'status': 'passed', 'phase1_runs': 1,
                            'child_namespace_pid': child_outcome['child_namespace_pid'], 'guest_exit': child_outcome['guest_exit'],
                            'outcome': child_outcome,
                            'parent_resources': resources,
                            'input': f.settings(self.binding['afl_file']['guest_path'], data),
                            'coverage': coverage, 'filesystem_sha256': baseline.digest,
                            'filesystem_content_sha256': baseline.content_digest,
                            'filesystem_restore_retries': baseline.restore_retries}
                        (case/'coverage.map').write_bytes(bitmap)
                        if os.geteuid() == 0: os.chown(case/'coverage.map', self.owner.st_uid, self.owner.st_gid)
                        self.publish(case/'result.json', result)
                        if capture is not None:
                            capture.finish(result)
                        request.sendall(outcome.bridge_header(child_outcome)+bitmap)
                connection.sendall(struct.pack('!3I', MAGIC, 0, 0))
                report['status'] = 'passed'
        except Exception as exc:
            self.errors.append(str(exc)); report['error'] = str(exc)
            from . import afl_storage
            limited = exc if isinstance(exc, afl_storage.ResourceLimit) else afl_storage.from_oserror(exc)
            if limited is not None:
                report['storage_stop'] = limited.record
                try: afl_storage.notify(self.root, limited.record)
                except (OSError, ValueError) as notice_error:
                    report['storage_notice_error'] = str(notice_error)
        finally:
            self.ready.set()
            report['children'] = self.executions
            if baseline is not None and os.geteuid() == 0:
                for directory, names, files in os.walk(baseline.backup, followlinks=False):
                    os.chown(directory, self.owner.st_uid, self.owner.st_gid, follow_symlinks=False)
                    for name in names+files:
                        os.chown(Path(directory)/name, self.owner.st_uid, self.owner.st_gid, follow_symlinks=False)
            self.publish(self.root/'warm-executor.json', report)


def executor_failure(root):
    """Keep the original executor failure visible when finalization also fails."""
    try:
        value = f.read_json(Path(root)/'warm-executor.json')
    except (OSError, ValueError, RuntimeError):
        return None
    if isinstance(value, dict) and value.get('status') == 'failed' and value.get('error'):
        return str(value['error'])
    return None


def session_failure(root):
    try:
        report = f.read_json(Path(root)/'warm-session-result.json')
    except (OSError, ValueError, RuntimeError):
        return None
    if isinstance(report, dict) and report.get('outcome') == 'intervention_required':
        return str(report.get('error') or report.get('stop_reason') or 'unified session failed')
    return None


def execute_session(root):
    """Exactly one call to the existing unified pipeline for the live campaign."""
    from scripts.run_unified_pipeline import run_session
    root = Path(root).resolve(strict=True)
    manifest = f.verify_campaign(root)
    validate(manifest['warm'])
    # Check authorization in the worker's actual session before starting M4.
    # The parent launcher refreshes the terminal's sudo timestamp while waiting.
    f.p.command('sudo', '-n', 'true', timeout=15)
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
    f.atomic_json(root/'warm-session-result.json', report)
    capsule = report.get('capsule', {})
    detail = executor_failure(root) or report.get('error') or capsule.get('error') or report.get('stop_reason') or 'no verified capsule result'
    f.p.require(code == 0 and capsule.get('status') == 'passed',
                'Warm session failed final verification: '+str(detail)+
                '\nReport: '+str(root/'warm-session-result.json'))
    return report


class WarmAttemptServer(AttemptServer):
    def __init__(self, root, **kwargs):
        super().__init__(root, **kwargs)
        self.worker = None
        self.output = None
        self.closed = False
        self.started = False
        self.phase2 = None
        self.active_worker = None
        self.worker_lock = threading.Lock()

    def start(self):
        try:
            config = f.read_json(self.root/'campaign.json')['warm']
            deadline = time.monotonic()+config['bootstrap_seconds']
            self.output = (self.root/'warm-worker.log').open('wb')
            self.worker = subprocess.Popen([sys.executable, '-m', 'scripts.run_afl_file', 'warm-session',
                '--out', str(self.root)], cwd=f.PROJECT, stdout=self.output, stderr=self.output,
                # Retain sudo's terminal session, with a separate cleanup group.
                stdin=subprocess.DEVNULL, process_group=0)
            while not (self.root/'warm-ready.json').is_file():
                f.p.require(self.worker.poll() is None, 'Warm bootstrap failed; inspect warm-worker.log')
                f.p.require(time.monotonic() < deadline, 'Warm bootstrap deadline exceeded')
                if self.stop.wait(.1): raise InterruptedError('Warm bootstrap interrupted')
                if self.storage is not None:
                    self.storage.check()
            f.p.require(f.read_json(self.root/'warm-ready.json')['status'] == 'ready', 'Invalid warm readiness')
            from . import afl_capsule
            if afl_capsule.enabled(config):
                manifest = f.read_json(self.root/'campaign.json')
                runtime = f.read_json(Path(manifest['launch']['template_run_dir'])/'config/runtime.json')
                from .attempt import AttemptStore
                from .iteration_controller import IterationController
                ready = f.read_json(self.root/'warm-ready.json')
                admitted = afl_capsule.verify_ready(ready, runtime['capsule']['analysis_policy'])
                contract = AttemptStore(self.root/'warm-session/attempts').load_contract(admitted['identity']['attempt_id'])
                session = IterationController(self.root/'warm-session').load()
                afl_capsule.verify_ready(ready, runtime['capsule']['analysis_policy'],
                    contract=contract, session_id=session.session_id,
                    run_dir=self.root/'warm-session/iterations/0000/run')
            if 'phase2' in config:
                from .afl_phase2 import Processor
                self.phase2 = Processor(self.root, config['phase2'],
                    on_complete=self.storage.complete if self.storage is not None else None,
                    on_error=self.phase2_error)
                self.phase2.start()
            super().start()
            self.started = True
        except BaseException:
            self.close(); raise

    def phase2_error(self, exc):
        from . import afl_storage
        limited = exc if isinstance(exc, afl_storage.ResourceLimit) else afl_storage.from_oserror(exc)
        if limited is not None:
            self.stop_admission(limited.record)

    def close(self):
        with self.worker_lock:
            if self.closed: return
            self.closed = True
            self.stop.set()
            active = self.active_worker
        if active is not None:
            try: active.shutdown(socket.SHUT_RDWR)
            except OSError: pass
        try:
            if self.thread.ident is not None: super().close()
            else:
                self.channel.close(); self.peer.close()
        finally:
            try:
                if self.worker is not None:
                    if self.worker.poll() is None:
                        try:
                            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                                connection.settimeout(2); connection.connect(str(self.root/'warm.sock'))
                                connection.sendall(b'S'); recv_exact(connection, 1)
                        except OSError:
                            pass
                        try: self.worker.wait(timeout=20)
                        except subprocess.TimeoutExpired: stop_case(self.worker, self.root)
                    if self.started:
                        detail = executor_failure(self.root) or session_failure(self.root)
                        f.p.require(self.worker.returncode == 0,
                                    'Warm pipeline failed'+(': '+detail if detail else '')+
                                    '; inspect '+str(self.root/'warm-worker.log'))
            finally:
                if self.output is not None:
                    self.output.close()
                phase2 = getattr(self, 'phase2', None)
                if phase2 is not None:
                    try: phase2.close()
                    finally: self.errors.extend(phase2.errors)

    def execute(self, connection):
        connection.settimeout(self.deadline)
        size = struct.unpack('!I', recv_exact(connection, 4))[0]
        manifest = f.read_json(self.root/'campaign.json')
        f.p.require(1 <= size <= manifest['max_input'], 'Input exceeds warm campaign limit')
        data = recv_exact(connection, size)
        index = self.executed
        self.admit_case(index)
        self.executed += 1
        case = self.root/'cases'/f'{index:08d}'; case.mkdir()
        (case/'input').write_bytes(data)
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as worker:
            with self.worker_lock:
                if self.closed or self.stop.is_set():
                    raise ConnectionError('Warm executor is stopping')
                self.active_worker = worker
            try:
                worker.settimeout(self.deadline); worker.connect(str(self.root/'warm.sock'))
                worker.sendall(b'R'+struct.pack('!2I', index, size)+data)
                response = recv_exact(worker, 16+f.MAP_SIZE)
            finally:
                with self.worker_lock:
                    self.active_worker = None
        outcome.check_bridge(response[:16])
        from .afl_findings import record
        record(self.root, case)
        self.metrics.record(f.read_json(case/'result.json'))
        if self.phase2 is not None:
            self.phase2.submit(case)
        try:
            connection.sendall(response)
            self.completed += 1
            f.atomic_json(case/'transport.json', {'status': 'delivered', 'cleanup_confirmed': True})
            if self.storage is not None and self.phase2 is None:
                self.storage.complete(case)
        except OSError:
            f.atomic_json(case/'transport.json', {'status': 'cancelled', 'cleanup_confirmed': True})
            raise ConnectionError('AFL bridge cancelled; child already reaped')
