"""AFL feedback for an already recovered static i386 ELF, without retirement."""
from __future__ import annotations

import array
import hashlib
import json
import os
from pathlib import Path
import resource
import shlex
import shutil
import signal
import socket
import stat
import struct
import subprocess
import sys
import threading
import time
from uuid import uuid4

from . import afl_file, capsule_hardening, capsule_resources
from .elf_runtime import canonical_hash, provision_guest
from .environment_snapshot import EnvironmentSnapshotStore
from .input_retirement import inspect_input
from .phase1_runtime import digest, read_json
from .prebuilt_runner import SubprocessCommandExecutor
from .unified_runtime import build_bundle, verify_bundle, write_json

PROFILE = 'rebuilt-i386-file-afl-v1'
PROJECT = Path(__file__).resolve().parents[1]
MAP_SIZE = 65536
MAX_BRANCHES = 4096
HEADER = struct.Struct('<8sII10Q')
BRANCH = struct.Struct('<QII')
RECORD_SIZE = HEADER.size + MAP_SIZE + MAX_BRANCHES * BRANCH.size
NAMESPACES = ('mnt', 'pid', 'net', 'uts', 'ipc')


def require(value, message):
    if not value:
        raise RuntimeError(message)


def private_path(value):
    path = Path(value).expanduser().absolute()
    require(path != Path('/') and '..' not in path.parts, 'Invalid artifact path')
    require(all(not p.is_symlink() for p in (path, *path.parents)), 'Symlink in artifact path')
    return path


def write_map(path):
    with Path(path).open('xb') as stream:
        stream.write(HEADER.pack(b'TFRCOV1\0', 1, MAP_SIZE, *([0] * 10)))
        stream.write(bytes(RECORD_SIZE - HEADER.size))


def parse_map(path, exit_code):
    path = Path(path)
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size == RECORD_SIZE,
            'Invalid native coverage file')
    data = path.read_bytes()
    magic, version, size, *fields = HEADER.unpack_from(data)
    started, finished, blocks, first, last, exit_seen, observed_exit, input_bytes, count, errors = fields
    require(magic == b'TFRCOV1\0' and version == 1 and size == MAP_SIZE,
            'Coverage format mismatch')
    require(started == finished == exit_seen == 1 and errors == 0 and observed_exit == exit_code
            and 0 <= exit_code <= 255 and input_bytes > 0 and blocks > 0
            and 0 < first <= 0xffffffff and 0 < last <= 0xffffffff and count <= MAX_BRANCHES,
            'No complete, normal guest execution with post-input coverage')
    bitmap = data[HEADER.size:HEADER.size + MAP_SIZE]
    require(any(bitmap), 'Empty native guest coverage')
    outcomes = set()
    addresses = set()
    offset = HEADER.size + MAP_SIZE
    for index in range(count):
        pc, bits, reserved = BRANCH.unpack_from(data, offset + index * BRANCH.size)
        require(0 < pc <= 0xffffffff and pc not in addresses and bits in (1, 2, 3) and not reserved,
                'Invalid conditional branch observation')
        addresses.add(pc)
        for direction in (0, 1):
            if bits & (1 << direction):
                outcomes.add((pc, direction))
    require(not any(data[offset + count * BRANCH.size:]), 'Unexpected coverage tail')
    return {'status': 'verified', 'scope': 'guest_tb_edges_after_first_input_read',
            'map_sha256': hashlib.sha256(bitmap).hexdigest(), 'blocks': blocks,
            'nonzero_slots': sum(bool(value) for value in bitmap), 'first_pc': first,
            'last_pc': last, 'input_bytes_read': input_bytes, 'guest_exit': exit_code,
            'branch_scope': 'observed_i386_rel8_rel32_conditional_successors',
            'branch_outcomes': sorted(outcomes)}, bitmap


def partial_coverage_candidate(path):
    """Return only a bounded *unverified* signal from a partially ended run.

    A missing guest exit after a proven input read might be a target fault,
    QEMU fault, or instrumentation failure. Never promote it to a crash.
    Invalid record format, plugin errors, or no input read fail closed.
    """
    path = Path(path)
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and
            info.st_size == RECORD_SIZE, 'Invalid partial coverage record size')
    data = path.read_bytes()
    magic, version, size, *fields = HEADER.unpack_from(data)
    started, finished, blocks, first, last, exit_seen, guest_code, input_bytes, count, errors = fields
    if (magic != b'TFRCOV1\0' or version != 1 or size != MAP_SIZE or
            started != 1 or finished not in (0, 1) or exit_seen != 0 or
            input_bytes < 1 or blocks < 1 or not 0 < first <= 0xffffffff or
            not 0 < last <= 0xffffffff or count > MAX_BRANCHES or errors != 0):
        return None
    return {'input_bytes_read': input_bytes, 'blocks': blocks,
            'plugin_atexit_seen': bool(finished), 'guest_exit_was_not_observed': True,
            'record_sha256': hashlib.sha256(data).hexdigest()}


def contract(binding):
    return canonical_hash({key: value for key, value in binding.items() if key != 'attempt_contract_sha256'})


def verify_binding(binding, binding_path):
    require(binding.get('profile') == PROFILE and binding.get('schema') == 1
            and binding.get('attempt_contract_sha256') == contract(binding), 'Rebuilt case binding changed')
    run = private_path(binding['run_dir'])
    root = private_path(binding['rootfs'])
    bundle = private_path(binding['bundle'])
    require(root == run / 'rootfs' and private_path(binding_path) == run / 'config/rebuilt_binding.json',
            'Rebuilt case escaped its output directory')
    require(not bundle.is_relative_to(run), 'Runtime must be outside the mutable case')
    manifest = verify_bundle(bundle, binding['bundle_sha256'])
    capsule_resources.validate(binding['settings']['resources'])
    capsule_hardening.config(binding)
    require(type(binding['seconds']) is int and 1 <= binding['seconds'] <= 30, 'Invalid case CPU budget')
    require(binding['input_path'] == '/etc/dta-input', 'Unsupported recovered input path')
    for relative, expected in [('bin/sample.elf', binding['target_sha256']),
                               ('etc/dta-input', binding['input_sha256'])]:
        require(digest(afl_file.guest_file(root, '/' + relative)) == expected, 'Rebuilt input identity changed')
    plugin = private_path(binding['coverage_plugin'])
    require(plugin.is_file() and plugin.stat().st_nlink == 1
            and digest(plugin) == binding['coverage_plugin_sha256'], 'Coverage plugin changed')
    record = run / 'output/coverage.bin'
    require(record.is_file() and not record.is_symlink() and record.stat().st_nlink == 1
            and record.stat().st_size == RECORD_SIZE, 'Coverage output changed')
    return run, root, bundle, manifest, plugin


def launch(binding_path):
    require(os.geteuid() == 0, 'Namespace setup requires the privileged wrapper')
    binding = read_json(binding_path)
    run, root, bundle, manifest, plugin = verify_binding(binding, binding_path)
    capsule_resources.inspect_self(binding)
    observed = {name: os.readlink('/proc/self/ns/' + name) for name in NAMESPACES}
    require(all(observed[name] != binding['host_namespaces'][name] for name in NAMESPACES),
            'Rebuilt launcher is outside the required namespaces')
    write_json(run / 'logs/capsule/namespaces.json', {'profile': PROFILE,
        'request_sha256': binding['attempt_contract_sha256'], 'host': binding['host_namespaces'],
        'observed': observed})
    with open('/dev/null', 'rb') as stream:
        os.dup2(stream.fileno(), 0)
    subprocess.run(['mount', '--make-rprivate', '/'], check=True)
    for name in ('proc', '__taintforge', '__tf_coverage', '__tf_output'):
        target = root / name
        require(not target.is_symlink() and (not target.exists() or target.is_dir() and not any(target.iterdir())),
                'Runtime mount hides a guest resource')
        target.mkdir(exist_ok=True)
    uid, gid = 65534, 65534
    for directory, names, files in os.walk(root, followlinks=False):
        os.chown(directory, uid, gid, follow_symlinks=False)
        for name in names + files:
            os.chown(Path(directory) / name, uid, gid, follow_symlinks=False)
    os.chown(run / 'output', uid, gid)
    os.chown(run / 'output/coverage.bin', uid, gid)
    (run / 'output').chmod(0o700)
    (run / 'output/coverage.bin').chmod(0o600)
    subprocess.run(['mount', '-t', 'proc', '-o', 'ro,nosuid,nodev,noexec', 'proc', str(root / 'proc')], check=True)
    for source, destination, readonly in [
            (bundle, root / '__taintforge', True), (plugin.parent, root / '__tf_coverage', True),
            (run / 'output', root / '__tf_output', False),
            (root / 'bin/sample.elf', root / 'bin/sample.elf', True),
            (root / 'etc/dta-input', root / 'etc/dta-input', True)]:
        subprocess.run(['mount', '--bind', str(source), str(destination)], check=True)
        options = 'remount,bind,nosuid,nodev' + (',ro' if readonly else '')
        subprocess.run(['mount', '-o', options, str(destination)], check=True)
    resource.setrlimit(resource.RLIMIT_CPU, (binding['seconds'], binding['seconds'] + 1))
    argument = '/__tf_coverage/' + plugin.name + ',output=/__tf_output/coverage.bin,input=/etc/dta-input'
    command = ['/__taintforge/bin/loader', '--inhibit-cache', '--library-path', '/__taintforge/lib',
               '/__taintforge/bin/qemu-i386', '-L', '/', '-plugin', argument, '/bin/sample.elf']
    capsule_hardening.launch(binding, command)


def execute_case(root, data, out, active=None):
    manifest = read_json(root / 'campaign.json')
    require(1 <= len(data) <= 4096, 'Input must contain 1..4096 bytes')
    out = private_path(out)
    out.mkdir(parents=True, exist_ok=False)
    for name in ('config', 'logs/capsule', 'output'):
        (out / name).mkdir(parents=True, exist_ok=True)
    (out / 'input').write_bytes(data)
    write_map(out / 'output/coverage.bin')
    store = EnvironmentSnapshotStore(root / 'snapshots')
    store.clone(manifest['snapshot_id'], out / 'rootfs')
    target = afl_file.guest_file(out / 'rootfs', '/etc/dta-input')
    target.chmod(0o600)
    target.write_bytes(data)
    target.chmod(0o444)
    nonce = uuid4().hex
    binding = {'schema': 1, 'profile': PROFILE, 'run_dir': str(out), 'rootfs': str(out / 'rootfs'),
        'bundle': manifest['runtime'], 'bundle_sha256': manifest['runtime_sha256'],
        'coverage_plugin': manifest['coverage_plugin'], 'coverage_plugin_sha256': manifest['coverage_plugin_sha256'],
        'input_path': '/etc/dta-input', 'input_sha256': hashlib.sha256(data).hexdigest(),
        'target_sha256': manifest['target_sha256'], 'seconds': manifest['case_seconds'],
        'attempt_id': 'rebuilt-' + nonce, 'lifecycle_attempt': nonce,
        'host_namespaces': {name: os.readlink('/proc/self/ns/' + name) for name in NAMESPACES},
        'settings': {'resources': capsule_resources.policy(512, manifest['case_seconds'] + 20),
                     'hardening': capsule_hardening.policy(analysis_mib=256, export_mib=1, journal_mib=1)}}
    if 'campaign_id' in manifest:
        binding['campaign_id'] = manifest['campaign_id']
    binding['attempt_contract_sha256'] = contract(binding)
    path = out / 'config/rebuilt_binding.json'
    write_json(path, binding)
    receipt = {'schema': 1, 'profile': PROFILE, 'status': 'failed',
               'input_sha256': binding['input_sha256'], 'phase1_executed': False,
               'retirement_required': False, 'protected_control_channel': False, 'hostile_sample_ready': False}
    if 'campaign_id' in binding:
        receipt.update(campaign_id=binding['campaign_id'], attempt_id=binding['attempt_id'])
    if active is not None:
        active(binding)
    try:
        command = ['sudo', 'unshare', '--mount', '--pid', '--fork', '--uts', '--ipc', '--net', '--',
            'env', 'PYTHONPATH=' + str(PROJECT), sys.executable, '-m', 'scripts.run_afl_rebuilt',
            'launch', '--binding', str(path)]
        executor = SubprocessCommandExecutor()
        try:
            result = capsule_resources.execute(binding, command, executor, cwd=PROJECT, check=False,
                stdout_path=out / 'logs/stdout.log', stderr_path=out / 'logs/stderr.log')
        finally:
            subprocess.run(['sudo', '-n', 'chown', '-R', '--no-dereference', '--',
                            f'{os.getuid()}:{os.getgid()}', str(out)], check=True)
        receipt['returncode'] = result.returncode
        service = read_json(out / 'logs/capsule/service.json')
        abnormal = (not 0 <= result.returncode <= 255 or
                    service.get('service', {}).get('Result') in
                    {'signal', 'timeout', 'watchdog', 'core-dump', 'oom-kill'})
        if abnormal:
            # A wrapper/supervisor signal is NOT proof of a guest vulnerability.
            # Continue only after confirmed isolation cleanup and matching input
            # identities; zero feedback prevents AFL inventing crash coverage.
            require(service.get('status') == 'verified' and service.get('tree_empty') is True
                    and service.get('attempt_contract_sha256') == binding['attempt_contract_sha256']
                    and service.get('wrapper_exit') == result.returncode,
                    'Abnormal worker lacks isolation/cleanup evidence')
            namespaces = read_json(out / 'logs/capsule/namespaces.json')
            require(namespaces['request_sha256'] == binding['attempt_contract_sha256']
                    and all(namespaces['observed'][n] != namespaces['host'][n] for n in NAMESPACES),
                    'Abnormal worker did not run in the expected namespaces')
            require(digest(out / 'rootfs/etc/dta-input') == binding['input_sha256'] and
                    digest(out / 'rootfs/bin/sample.elf') == manifest['target_sha256'],
                    'Abnormal worker changed its input or guest binary')
            receipt.update(status='quarantined', classification='unverified_abnormal_exit',
                           error_scope='guest_or_infrastructure_undetermined',
                           service_result=service.get('service', {}).get('Result'),
                           outcome={'kind': 'unverified_abnormal_exit'},
                           coverage={'status': 'unavailable', 'map_sha256': None},
                           must_reproduce_before_crash_claim=True)
            (out / 'coverage.map').write_bytes(bytes(MAP_SIZE))
            return receipt, bytes(MAP_SIZE)
        resources = capsule_resources.verify_saved(binding, result.returncode)
        namespaces = read_json(out / 'logs/capsule/namespaces.json')
        require(namespaces['request_sha256'] == binding['attempt_contract_sha256']
                and namespaces['host'] == binding['host_namespaces']
                and all(namespaces['observed'][n] != namespaces['host'][n] for n in NAMESPACES),
                'Namespace receipt does not match this input')
        try:
            report, bitmap = parse_map(out / 'output/coverage.bin', result.returncode)
        except RuntimeError:
            partial = partial_coverage_candidate(out / 'output/coverage.bin')
            if partial is None:
                raise  # Invalid instrumentation evidence is an infrastructure failure.
            receipt.update(status='quarantined', classification='unverified_abnormal_exit',
                           error_scope='guest_or_infrastructure_undetermined',
                           partial_coverage=partial,
                           outcome={'kind': 'unverified_abnormal_exit'},
                           coverage={'status': 'unavailable', 'map_sha256': None},
                           must_reproduce_before_crash_claim=True)
            (out / 'coverage.map').write_bytes(bytes(MAP_SIZE))
            return receipt, bytes(MAP_SIZE)
        (out / 'coverage.map').write_bytes(bitmap)
        require(digest(out / 'rootfs/etc/dta-input') == binding['input_sha256'], 'Guest input changed')
        require(digest(out / 'rootfs/bin/sample.elf') == manifest['target_sha256'], 'Guest image changed')
        receipt.update(status='passed', guest_exit=result.returncode, coverage=report, resources=resources,
                       isolation={'network': 'none', 'namespaces': namespaces['observed'],
                                  'chroot': True, 'configured_uid': 65534, 'configured_gid': 65534})
        return receipt, bitmap
    except Exception as exc:
        receipt['error'] = f'{type(exc).__name__}: {exc}'
        raise
    finally:
        write_json(out / 'result.json', receipt)
        if active is not None:
            active(None)


def prepare(root, binary, seeds, qemu, plugin, case_seconds=5):
    root = private_path(root)
    require(not root.exists(), 'Use a new campaign directory')
    require(type(case_seconds) is int and 1 <= case_seconds <= 30, 'Invalid case deadline')
    inspect_input(binary)
    corpus = []
    for path in sorted(Path(seeds).iterdir()):
        require(not path.is_symlink() and path.is_file() and 1 <= path.stat().st_size <= 4096, 'Invalid seed')
        corpus.append(path.read_bytes())
    require(corpus, 'Empty seed corpus')
    capsule_resources.preflight()
    root.mkdir(parents=True)
    for name in ('build', 'build/plugin', 'seeds', 'cases', 'baseline', 'proof'):
        (root / name).mkdir(parents=True, exist_ok=True)
    for data in corpus:
        (root / 'seeds' / hashlib.sha256(data).hexdigest()).write_bytes(data)
    header = PROJECT / 'experiments/execution_capsule_probe/vendor/qemu-plugin.h'
    source = PROJECT / 'experiments/afl_rebuilt/coverage.c'
    native = root / 'build/plugin/rebuilt_coverage.so'
    flags = shlex.split(subprocess.check_output(['pkg-config', '--cflags', '--libs', 'glib-2.0'], text=True))
    subprocess.run(['cc', '-std=c11', '-O2', '-g', '-shared', '-fPIC', '-Wall', '-Wextra', '-Werror',
                    '-I' + str(header.parent), str(source), '-o', str(native), *flags], check=True)
    bridge = root / 'build/tf-afl-bridge'
    subprocess.run(['cc', '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
                    str(PROJECT / 'experiments/afl_file/bridge.c'), '-o', str(bridge)], check=True)
    runtime = build_bundle(root / 'runtime', qemu=Path(qemu), plugin=Path(plugin))
    for directory, names, files in os.walk(root / 'runtime'):
        Path(directory).chmod(0o555)
        for name in files:
            path = Path(directory) / name
            require(not path.is_symlink(), 'Unexpected runtime symlink')
            path.chmod(0o555 if path.stat().st_mode & 0o111 else 0o444)
    native.chmod(0o555)
    (root / 'build/plugin').chmod(0o555)
    template = root / 'template-rootfs'
    for name in ('bin', 'etc', 'tmp', 'dev', 'proc', 'sys'):
        (template / name).mkdir(parents=True, exist_ok=True)
    (template / 'tmp').chmod(0o1777)
    provision_guest(Path(binary), template, sysroot=Path('/'), binary_guest_path='/bin/sample.elf')
    afl_file.create_guest_file(template, '/etc/dta-input', corpus[0])
    snapshot = EnvironmentSnapshotStore(root / 'snapshots').capture(template).manifest
    manifest = {'schema': 1, 'profile': PROFILE, 'status': 'prepared', 'target_sha256': digest(Path(binary)),
        'campaign_id': uuid4().hex,
        'runtime': str(root / 'runtime'), 'runtime_sha256': runtime['bundle_sha256'],
        'coverage_plugin': str(native), 'coverage_plugin_sha256': digest(native),
        'bridge': str(bridge), 'bridge_sha256': digest(bridge), 'snapshot_id': snapshot.snapshot_id,
        'case_seconds': case_seconds, 'phase1_executed': False, 'retirement_required': False,
        'coverage_scope': 'guest_tb_edges_after_first_input_read', 'parser_domain_provided': False,
        'protected_control_channel': False, 'hostile_sample_ready': False, 'cases': 0}
    write_json(root / 'campaign.json', manifest)
    return manifest


def receive(connection, count):
    data = bytearray()
    while len(data) < count:
        part = connection.recv(count - len(data))
        if not part:
            raise ConnectionError('AFL child disconnected')
        data.extend(part)
    return bytes(data)


class Server:
    def __init__(self, root, max_cases, *, campaign_id=None):
        self.root, self.max_cases = root, max_cases
        self.campaign_id = campaign_id
        self.channel, self.peer = socket.socketpair()
        self.channel.settimeout(0.2)
        self.stop = threading.Event()
        self.error = None
        self.count = 0
        self.delivered = 0
        self.receipt_observer = None
        self.delivery_error = None
        self.quarantined = []
        self.current = None
        self.lock = threading.Lock()
        self.thread = threading.Thread(target=self.serve, daemon=True)

    def active(self, value):
        with self.lock:
            self.current = value

    def cancel(self):
        self.stop.set()
        with self.lock:
            current = self.current
        if current is not None:
            capsule_resources.control('sudo', '-n', 'systemctl', 'stop', capsule_resources.unit_name(current))

    def publish_delivery(self, case, result, bitmap, *, started_ns, finished_ns):
        sent_ns = time.monotonic_ns()
        index = self.count - 1
        require(index == self.delivered and case.name == f'{index:08d}', 'Out-of-order transport receipt')
        record = {'schema': 1, 'status': 'delivered', 'case': index,
            'input_sha256': result['input_sha256'],
            'coverage_sha256': hashlib.sha256(bitmap).hexdigest(),
            'feedback': 'zero_unverified' if result['status'] == 'quarantined' else 'verified_guest_coverage',
            'verified_target_crash': False, 'verified_target_hang': False}
        if self.campaign_id is not None:
            require(result.get('campaign_id') == self.campaign_id, 'Transport result belongs to a different campaign')
            record.update(schema=2, campaign_id=self.campaign_id, attempt_id=result['attempt_id'],
                          execution_started_ns=started_ns, execution_finished_ns=finished_ns,
                          transport_sent_ns=sent_ns)
        afl_file.atomic_json(case / 'transport.json', record)
        try:
            if self.receipt_observer is not None:
                self.receipt_observer(index)
        except Exception as exc:
            self.error = f'Receipt observer failed for case {index}: {exc}'
            raise
        finally:
            # A telemetry error cannot undo a completed transport write.
            self.delivered += 1

    def serve(self):
        try:
            while not self.stop.is_set():
                try:
                    marker, ancillary, flags, _ = self.channel.recvmsg(1, socket.CMSG_SPACE(4))
                except socket.timeout:
                    continue
                if not marker and not ancillary:
                    break
                descriptors = []
                for level, kind, raw in ancillary:
                    if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                        values = array.array('i')
                        values.frombytes(raw[:len(raw) - len(raw) % values.itemsize])
                        descriptors.extend(values)
                if marker != b'C' or flags or len(descriptors) != 1:
                    for fd in descriptors:
                        os.close(fd)
                    raise RuntimeError('Invalid AFL descriptor transfer')
                with socket.socket(fileno=descriptors[0]) as connection:
                    connection.settimeout(10)
                    size = struct.unpack('!I', receive(connection, 4))[0]
                    require(1 <= size <= 4096, 'AFL input length exceeds profile')
                    require(self.count < self.max_cases, 'Campaign execution budget exhausted')
                    data = receive(connection, size)
                    case = self.root / 'cases' / f'{self.count:08d}'
                    started_ns = time.monotonic_ns()
                    result, bitmap = execute_case(self.root, data, case, self.active)
                    finished_ns = time.monotonic_ns()
                    if result.get('status') == 'quarantined':
                        self.quarantined.append({'case': self.count,
                            'input_sha256': result['input_sha256'],
                            'classification': result['classification'],
                            'returncode': result.get('returncode'),
                            'scope': 'UNVERIFIED; not an AFL target crash'})
                    self.count += 1
                    try:
                        connection.sendall(struct.pack('!4I', 0x54464131, 0, 0, MAP_SIZE) + bitmap)
                    except (BrokenPipeError, ConnectionResetError) as exc:
                        # AFL may terminate its child when its campaign timer expires.
                        # The caller must still verify AFL's own successful exit.
                        self.delivery_error = str(exc)
                        break
                    self.publish_delivery(case, result, bitmap, started_ns=started_ns, finished_ns=finished_ns)
        except Exception as exc:
            if not self.stop.is_set():
                self.error = f'{type(exc).__name__}: {exc}'
            self.stop.set()


def measured_bytes(root):
    from .afl_storage import usage, privileged_usage
    try:
        result = usage(root)
    except PermissionError:
        result = privileged_usage(root)
    return result['total_bytes']


def build_afl_command(*, afl, root, manifest, seconds, max_cases, afl_seed,
                      peer_fd, afl_stage_policy):
    """Build an auditable AFL command with identical stage policy semantics.

    ``-z`` bypasses enhanced deterministic stages on current AFL++ while
    preserving custom-mutator and stock havoc stages. It is an experiment
    variable, not a hidden per-arm optimization.
    """
    require(afl_stage_policy in ('full', 'fast'), 'Invalid AFL stage policy')
    require(type(max_cases) is int and max_cases >= 128, 'Invalid AFL case budget')
    command = [str(afl), '-i', str(root / 'seeds'), '-o', str(root / 'afl'),
        '-V', str(seconds), '-E', str(max_cases - 64),
        '-t', str((manifest['case_seconds'] + 35) * 1000), '-m', '256',
        '-g', '1', '-G', '4096', '-s', str(afl_seed)]
    if afl_stage_policy == 'fast':
        command.append('-z')
    command += ['--', manifest['bridge'], str(peer_fd), '@@']
    return command


def campaign(root, afl, seconds=180, max_cases=512, disk_mib=1024, *, hybrid=None,
             hybrid_library=None, afl_seed=42, afl_stage_policy='full'):
    root = private_path(root)
    try:
        return run_campaign(root, afl, seconds, max_cases, disk_mib,
            hybrid=hybrid, hybrid_library=hybrid_library, afl_seed=afl_seed,
            afl_stage_policy=afl_stage_policy)
    except BaseException as exc:
        manifest = read_json(root / 'campaign.json')
        manifest.update(status='failed', error=f'{type(exc).__name__}: {exc}')
        write_json(root / 'campaign.json', manifest)
        raise


def run_campaign(root, afl, seconds, max_cases, disk_mib, *, hybrid=None,
                 hybrid_library=None, afl_seed=42, afl_stage_policy='full'):
    root = private_path(root)
    manifest = read_json(root / 'campaign.json')
    require(manifest['profile'] == PROFILE and manifest['status'] == 'prepared', 'Expected a new rebuilt campaign')
    require(1 <= seconds <= 3600 and 128 <= max_cases <= 4096 and 256 <= disk_mib <= 4096, 'Invalid campaign budgets')
    require(type(afl_seed) is int and 1 <= afl_seed <= 2147483647, 'Invalid AFL random seed')
    require(afl_stage_policy in ('full', 'fast'), 'Invalid AFL deterministic-stage policy')
    require(digest(Path(manifest['bridge'])) == manifest['bridge_sha256'], 'AFL bridge changed')
    afl = shutil.which(os.fspath(afl))
    require(afl is not None, 'AFL executable was not found')
    afl = Path(afl).resolve(strict=True)
    manifest.setdefault('campaign_id', uuid4().hex)
    manifest.update(status='calibrating', seconds=seconds, max_cases=max_cases,
                    disk_mib=disk_mib, afl_seed=afl_seed,
                    afl_executable_sha256=digest(Path(afl)),
                    afl_stage_policy=afl_stage_policy,
                    enhanced_deterministic_skipped=(afl_stage_policy == 'fast'))
    write_json(root / 'campaign.json', manifest)
    known, baseline_maps = set(), {}
    for index, seed in enumerate(sorted((root / 'seeds').iterdir())):
        repeated = []
        for repetition in range(2):
            result, bitmap = execute_case(root, seed.read_bytes(), root / 'baseline' / f'{index:02d}-{repetition}')
            repeated.append((result['coverage']['map_sha256'], result['coverage']['branch_outcomes'], result['guest_exit']))
        require(repeated[0] == repeated[1], 'Seed coverage or conditional outcomes are unstable')
        known.update(tuple(item) for item in repeated[0][1])
        baseline_maps[seed.name] = repeated[0][0]
        print(f'Baseline: {index + 1} seeds, each repeated twice', flush=True)
        require(measured_bytes(root) <= disk_mib * 1024 ** 2, 'Campaign disk budget exhausted')
    write_json(root / 'baseline.json', {'stable': True, 'maps': baseline_maps, 'branch_outcomes': sorted(known),
                                      'parser_domain_provided': False})
    require((hybrid is None) == (hybrid_library is None),
            'The hybrid controller and mutator must be configured together')
    if hybrid is not None:
        library = private_path(hybrid_library)
        require(library.is_file() and library.stat().st_nlink == 1,
                'Hybrid mutator library is missing or has multiple hardlinks')
        recorded = manifest.get('hybrid', {})
        require(recorded.get('library_sha256') == digest(library) and
                recorded.get('initial_target_sha256') == manifest['target_sha256'],
                'Hybrid preflight provenance differs from the prepared campaign')
    server = Server(root, max_cases, campaign_id=manifest['campaign_id'])
    server.thread.start()
    if hybrid is not None:
        try:
            hybrid.bind(server)
        except BaseException:
            server.cancel()
            server.thread.join(45)
            server.peer.close()
            server.channel.close()
            hybrid.close()
            raise
    environment = {key: os.environ[key] for key in ('PATH', 'LD_LIBRARY_PATH') if key in os.environ}
    environment.update(AFL_NO_UI='1', AFL_NO_AFFINITY='1', AFL_SKIP_CPUFREQ='1', AFL_FAST_CAL='1',
        AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES='1', AFL_MAP_SIZE=str(MAP_SIZE))
    if hybrid is not None:
        environment.update(hybrid.environment(library))
    command = build_afl_command(afl=afl, root=root, manifest=manifest,
        seconds=seconds, max_cases=max_cases, afl_seed=afl_seed,
        peer_fd=server.peer.fileno(), afl_stage_policy=afl_stage_policy)
    process = None
    interrupted = []
    def stop(number, frame):
        interrupted.append(number)
        server.cancel()
        if process is not None and process.poll() is None:
            os.killpg(process.pid, signal.SIGINT)
    handlers = {sig: signal.signal(sig, stop) for sig in (signal.SIGINT, signal.SIGTERM)}
    failure = None
    try:
        manifest.update(status='running', command=command)
        write_json(root / 'campaign.json', manifest)
        with (root / 'afl.log').open('wb') as log:
            process = subprocess.Popen(command, cwd=PROJECT, env=environment, stdin=subprocess.DEVNULL,
                stdout=log, stderr=log, start_new_session=True, pass_fds=(server.peer.fileno(),))
            process_window = {'pid': process.pid, 'clock': 'host_monotonic_ns',
                              'started_ns': time.monotonic_ns(), 'last_alive_ns': None}
            manifest['afl_process_window'] = process_window
            deadline = time.monotonic() + seconds + 60
            checked = time.monotonic()
            while True:
                before_poll = time.monotonic_ns()
                if process.poll() is not None:
                    break
                process_window['last_alive_ns'] = before_poll
                if server.error:
                    raise RuntimeError(server.error)
                if hybrid is not None and hybrid.error:
                    raise RuntimeError('Hybrid controller failed: ' + hybrid.error)
                require(time.monotonic() < deadline, 'AFL wrapper deadline expired')
                if time.monotonic() - checked >= 10:
                    require(measured_bytes(root) <= disk_mib * 1024 ** 2, 'Campaign disk budget exhausted')
                    print(f'AFL: {server.count} completed executions', flush=True)
                    checked = time.monotonic()
                time.sleep(0.1)
        require(not interrupted, 'Campaign interrupted')
        require(process.returncode == 0 and not server.error, server.error or f'AFL exited with {process.returncode}')
    except Exception as exc:
        failure = f'{type(exc).__name__}: {exc}'
    finally:
        server.cancel()
        if process is not None and process.poll() is None:
            os.killpg(process.pid, signal.SIGINT)
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=5)
        if process is not None:
            manifest['afl_process_window']['exit_observed_ns'] = time.monotonic_ns()
        server.thread.join(45)
        if hybrid is not None:
            try:
                hybrid.close()
            except BaseException as exc:
                failure = f'Hybrid cleanup failed: {type(exc).__name__}: {exc}'
        server.peer.close()
        server.channel.close()
        if server.thread.is_alive():
            failure = 'Rebuilt execution worker did not finish cleanup'
        if server.error and failure is None:
            failure = server.error
        if failure is None and server.count != server.delivered:
            if server.count != server.delivered + 1 or not server.delivery_error:
                failure = 'Missing committed receipt for a completed AFL transport'
        for sig, handler in handlers.items():
            signal.signal(sig, handler)
        write_json(root / 'quarantined.json', {'schema': 1, 'cases': server.quarantined,
            'AFL_crash_proof': False, 'scope': 'manual_reproduction_required'})
        manifest.update(status='failed' if failure else 'fuzzed', cases=server.count, delivered_cases=server.delivered,
                        quarantined_cases=len(server.quarantined), final_delivery_error=server.delivery_error,
                        afl_exit=process.returncode if process is not None else None, error=failure)
        write_json(root / 'campaign.json', manifest)
    require(failure is None, failure)
    proof = None
    for index, path in enumerate(sorted((root / 'afl/default/queue').glob('id:*'))):
        if ',orig:' in path.name:
            continue
        require(measured_bytes(root) <= disk_mib * 1024 ** 2, 'Campaign disk budget exhausted during replay')
        first, _ = execute_case(root, path.read_bytes(), root / 'proof' / f'{index:06d}-0')
        fresh = set(map(tuple, first['coverage']['branch_outcomes'])) - known
        if not fresh:
            continue
        second, _ = execute_case(root, path.read_bytes(), root / 'proof' / f'{index:06d}-1')
        require(first['coverage']['map_sha256'] == second['coverage']['map_sha256']
                and first['coverage']['branch_outcomes'] == second['coverage']['branch_outcomes']
                and first['guest_exit'] == second['guest_exit'],
                'Queue replay is not deterministic')
        proof = {'input': str(path), 'input_sha256': digest(path), 'repetitions': 2,
                 'new_branch_outcomes': [{'pc': hex(pc), 'taken': bool(taken)} for pc, taken in sorted(fresh)],
                 'scope': 'guest_conditional_branches', 'parser_domain_provided': False,
                 'parser_specific_claim': False, 'map_sha256': first['coverage']['map_sha256']}
        break
    write_json(root / 'new-branches.json', {'status': 'verified' if proof else 'no_new_branch_verified', 'proof': proof})
    hybrid_summary = None
    if hybrid is not None:
        hybrid_summary = hybrid.finish()
        require(hybrid_summary['mutator_hooks'] is not None,
                'AFL custom mutator did not produce its independent hook trace')
    manifest.update(status='completed', baseline_stable=True, branch_novelty_verified=proof is not None,
                    parser_specific_claim=False)
    if hybrid_summary is not None:
        # 'hybrid' was prepared before AFL began; do not leave a stale False
        # beside the independently verified final controller result.
        manifest['hybrid']['automatic_live_cycle_verified'] = hybrid_summary['automatic_live_cycle_verified']
        manifest['hybrid']['DTA_mask_refresh_count'] = hybrid_summary['DTA_mask_refresh_count']
        manifest['hybrid']['focused_mutations_generated'] = hybrid_summary['focused_mutations_generated']
        manifest['hybrid']['full_union_fallback_mutations_generated'] = hybrid_summary['full_union_fallback_mutations_generated']
        manifest['hybrid']['unattributed_deliveries'] = hybrid_summary['unattributed_deliveries']
        manifest['hybrid']['adaptive_focus_quota_per_16'] = hybrid_summary['adaptive_focus_quota_per_16']
        manifest['hybrid']['mutator_hooks'] = hybrid_summary['mutator_hooks']
        manifest['hybrid']['dse_callback_lags'] = hybrid_summary['dse_callback_lags']
        manifest['hybrid_result'] = {'status': hybrid_summary['status'],
            'automatic_live_cycle_verified': hybrid_summary['automatic_live_cycle_verified'],
            'DSE_seed_retained_by_AFL': hybrid_summary['DSE_seed_retained_by_AFL'],
            'masked_mutations_delivered': hybrid_summary['masked_mutations_delivered'],
            'unattributed_deliveries': hybrid_summary['unattributed_deliveries'],
            'mixed_mutations': hybrid_summary['mixed_mutations'],
            'live_dse_enabled': hybrid_summary['live_dse_enabled'],
            'DSE_jobs': len(hybrid_summary['DSE_jobs']),
            'mutator_hooks': hybrid_summary['mutator_hooks'],
            'dse_callback_lags': hybrid_summary['dse_callback_lags']}
    write_json(root / 'campaign.json', manifest)
    return manifest
