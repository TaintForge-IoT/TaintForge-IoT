"""One guest-file input per fresh M4 attempt; no network input or solver."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import struct
import tempfile

from .environment_snapshot import EnvironmentSnapshotStore
from .phase1_runtime import read_json
from .unified_runtime import verify_bundle
from experiments.execution_capsule_probe import controller as p

PROFILE = 'afl-guest-file-v1'
MAP_SIZE = 65536
HEADER = struct.Struct('<8sII6Q')
MAP_NAME = 'afl-coverage.bin'
PROJECT = Path(__file__).resolve().parents[1]


def validate_guest_path(guest_path):
    p.require(isinstance(guest_path, str) and len(guest_path.encode()) <= 4095,
              'Invalid guest-file path')
    q = PurePosixPath(guest_path)
    p.require(q.is_absolute() and str(q) == guest_path and not guest_path.startswith('//') and
              '..' not in q.parts and len(q.parts) > 1 and
              not any(c in guest_path for c in ',\n\r\x00') and
              q.parts[1] not in {'proc', 'sys', 'dev', '__taintforge', '__taintforge_capsule'},
              'Invalid or reserved guest-file path')
    return q


def settings(guest_path, data):
    validate_guest_path(guest_path)
    p.require(isinstance(data, bytes) and 1 <= len(data) <= 1024**2, 'Invalid input size')
    return {'schema': 1, 'profile': PROFILE, 'guest_path': guest_path,
            'input_sha256': hashlib.sha256(data).hexdigest(), 'input_size': len(data)}


def guest_file(rootfs, guest_path):
    q = validate_guest_path(guest_path)
    rootfs = Path(rootfs).resolve(strict=True)
    p.require(rootfs != Path('/'), 'Host root cannot be a guest rootfs')
    current = rootfs
    for component in q.parts[1:]:
        current = current / component
        p.require(not current.is_symlink(), 'Guest input traverses a symlink')
    p.require(current.is_file(), 'Guest input must be an existing regular file')
    st = current.lstat()
    p.require(stat.S_ISREG(st.st_mode) and st.st_nlink == 1, 'Guest input is not a private regular file')
    return current


def create_guest_file(rootfs, guest_path, data):
    q = validate_guest_path(guest_path)
    rootfs = Path(rootfs).resolve(strict=True)
    p.require(rootfs != Path('/'), 'Host root cannot be a guest rootfs')
    current = rootfs
    for component in q.parts[1:-1]:
        current = current / component
        p.require(not current.is_symlink(), 'Guest input traverses a symlink')
        current.mkdir(exist_ok=True)
        p.require(current.is_dir(), 'Guest input parent is not a directory')
    target = current / q.name
    fd = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o644)
    with os.fdopen(fd, 'wb') as output: output.write(data)
    return guest_file(rootfs, guest_path)


def validate_setting(value, rootfs, guest_binary):
    p.require(isinstance(value, dict) and set(value) ==
              {'schema', 'profile', 'guest_path', 'input_sha256', 'input_size'}, 'Invalid AFL file binding')
    p.require(type(value['schema']) is int and type(value['input_size']) is int,
              'Invalid AFL file binding types')
    p.require(value['guest_path'] != guest_binary, 'The executable cannot be the fuzz input')
    target = guest_file(rootfs, value['guest_path'])
    p.require(target.stat().st_size <= 1024**2, 'Guest input exceeds the size limit')
    p.require(value == settings(value['guest_path'], target.read_bytes()), 'Guest input binding mismatch')
    return dict(value)


def create_map(path):
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as f:
        f.write(HEADER.pack(b'TFACOV1\0', 1, MAP_SIZE, 0, 0, 0, 0, 0, 0))
        f.write(bytes(MAP_SIZE))


def prepare_map(binding, ipc):
    path = Path(ipc) / MAP_NAME
    create_map(path)
    if 'hardening' in binding['settings']:
        config = binding['settings']['hardening']
        os.chown(path, config['uid'], config['gid'])
    return ['afl-coverage=/__taintforge_capsule/' + MAP_NAME,
            'afl-input=' + binding['afl_file']['guest_path']]


def inspect_map(path, *, complete=True):
    path = Path(path)
    st = path.lstat()
    p.require(stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and
              st.st_size == HEADER.size + MAP_SIZE, 'Invalid coverage file')
    data = path.read_bytes()
    magic, version, size, started, finished, blocks, first, last, reserved = HEADER.unpack_from(data)
    p.require(magic == b'TFACOV1\0' and version == 1 and size == MAP_SIZE and not reserved and
              started in (0, 1) and finished in (0, 1) and first <= 0xffffffff and last <= 0xffffffff,
              'Coverage header mismatch')
    bitmap = data[HEADER.size:]
    if complete:
        p.require(started == finished == 1 and blocks > 0 and first > 0 and last > 0 and any(bitmap),
                  'No complete post-retirement guest-file coverage')
    return {'status': 'verified' if started == finished == 1 and blocks and any(bitmap) else 'incomplete',
            'scope': 'guest_tb_edges_after_resume2_and_first_input_read',
            'started': started, 'finished': finished, 'blocks': blocks,
            'first_pc': first, 'last_pc': last, 'nonzero_slots': sum(v != 0 for v in bitmap),
            'map_sha256': hashlib.sha256(bitmap).hexdigest()}, bitmap


def save_map(binding, ipc):
    source = Path(ipc) / MAP_NAME
    output = Path(binding['run_dir']) / 'logs/capsule'
    if source.is_file():
        st = source.lstat()
        p.require(stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and
                  st.st_size == HEADER.size + MAP_SIZE, 'Coverage output changed type/size')
        destination = output / MAP_NAME
        p.require(not destination.exists() and not destination.is_symlink(), 'Coverage destination exists')
        shutil.copyfile(source, destination)
        report, _ = inspect_map(destination, complete=False)
        p.write_json(output / 'afl-coverage.json', report)


def verify_map(binding):
    output = Path(binding['run_dir']) / 'logs/capsule'
    report, _ = inspect_map(output / MAP_NAME)
    p.require(read_json(output / 'afl-coverage.json') == report, 'Coverage report changed')
    return report


def atomic_json(path, value):
    path = Path(path)
    fd, temporary = tempfile.mkstemp(dir=path.parent, prefix='.' + path.name)
    try:
        import json
        with os.fdopen(fd, 'w') as f:
            json.dump(value, f, indent=2, sort_keys=True); f.write('\n')
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def build(directory):
    directory = Path(directory).resolve()
    directory.mkdir(parents=True, exist_ok=False)
    from experiments.retirement_observer.controller import build_plugin
    observer = build_plugin(directory / 'observer')
    source = PROJECT / 'experiments/afl_file'
    bridge = directory / 'tf-afl-bridge'
    p.command('cc', '-std=c11', '-O2', '-g', '-Wall', '-Wextra', '-Werror',
              source / 'bridge.c', '-o', bridge)
    return {'bridge': str(bridge), 'observer': observer,
            'source_sha256': {str(x.relative_to(PROJECT)): p.sha(x) for x in
                              (source/'bridge.c', source/'coverage.h')}}


def prepare_campaign(out, *, binary, qemu, plugin, guest_path, seeds, max_input=4096, pipeline_options=()):
    from scripts.run_unified_pipeline import parser, prepare
    p.require(type(max_input) is int and 1 <= max_input <= 1024**2, 'Invalid maximum input length')
    seed_dir = Path(seeds).resolve(strict=True)
    inputs = []
    for source in sorted(seed_dir.iterdir()):
        st = source.lstat()
        p.require(stat.S_ISREG(st.st_mode) and 1 <= st.st_size <= max_input,
                  'Seeds must be nonempty regular files within the input limit')
        inputs.append(source.read_bytes())
    p.require(inputs, 'Empty seed corpus')
    settings(guest_path, inputs[0])
    out = Path(out).absolute()
    p.require(not out.exists() and not out.is_symlink() and not out.resolve().is_relative_to(seed_dir),
              'A new campaign directory outside seeds is required')
    out = out.resolve()
    out.mkdir(parents=True)
    options = parser().parse_args(['run', '--retire-phase1', '--capsule-hardening',
        '--binary', str(Path(binary).resolve()), '--qemu', str(Path(qemu).resolve()),
        '--plugin', str(Path(plugin).resolve()), '--out', str(out/'baseline'),
        '--capsule-hold-ms', '20', '--max-iterations', '1', *pipeline_options])
    launch = prepare(options)
    template = Path(launch['template_run_dir'])
    runtime = read_json(template / 'config/runtime.json')
    p.require(runtime['network_mode'] == 'none' and runtime['allow_internet'] is False and
              'hardening' in runtime['capsule'], 'AFL MVP requires the M4 network-none profile')
    rootfs = Path(launch['seed_rootfs'])
    p.require(guest_path != runtime['guest_binary'], 'Cannot fuzz the executable')
    create_guest_file(rootfs, guest_path, inputs[0])
    store = EnvironmentSnapshotStore(out/'baseline-snapshots')
    captured = store.capture(rootfs)
    seed_dir = out/'seeds'; seed_dir.mkdir()
    for data in inputs:
        (seed_dir/hashlib.sha256(data).hexdigest()).write_bytes(data)
    built = build(out/'build')
    bundle = verify_bundle(Path(runtime['phase1']['bundle_path']), runtime['phase1']['bundle_sha256'])
    p.require(bundle['capsule']['source_sha256'].get('afl_coverage.h') ==
              p.sha(PROJECT/'experiments/afl_file/coverage.h'), 'Observer has no matching AFL coverage implementation')
    manifest = {'schema': 1, 'profile': PROFILE, 'status': 'prepared',
        'project_root': str(PROJECT), 'guest_path': guest_path, 'max_input': max_input,
        'launch': launch, 'snapshot_id': captured.manifest.snapshot_id,
        'snapshot_store': str(store.store_dir), 'build': built, 'cases': 0,
        'protected_control_channel': False, 'hostile_sample_ready': False,
        'assets': {str(path): p.sha(path) for path in
            [Path(built['bridge']), Path(launch['binary_path']), template/'config/runtime.json']},
        'source_sha256': {str(path.relative_to(PROJECT)): p.sha(path) for path in
            [PROJECT/'taintforge_env/afl_file.py', PROJECT/'taintforge_env/afl_transport.py',
             PROJECT/'taintforge_env/input_retirement.py', PROJECT/'experiments/retirement_observer/observer.c',
             PROJECT/'experiments/afl_file/coverage.h', PROJECT/'experiments/afl_file/bridge.c',
             PROJECT/'experiments/retirement_observer/controller.py', PROJECT/'scripts/run_afl_file.py']}}
    atomic_json(out/'campaign.json', manifest)
    return manifest


def verify_campaign(root):
    root = Path(root).resolve(strict=True)
    value = read_json(root/'campaign.json')
    p.require(value['schema'] == 1 and value['profile'] == PROFILE and
              Path(value['project_root']) == PROJECT, 'Campaign belongs to another source tree/profile')
    for name, sha in value['assets'].items(): p.require(p.sha(Path(name)) == sha, 'Campaign asset changed: '+name)
    for name, sha in value['source_sha256'].items():
        p.require(p.sha(PROJECT/name) == sha, 'Executor source changed: '+name)
    EnvironmentSnapshotStore(value['snapshot_store']).verify(value['snapshot_id'])
    runtime = read_json(Path(value['launch']['template_run_dir'])/'config/runtime.json')
    verify_bundle(Path(runtime['phase1']['bundle_path']), runtime['phase1']['bundle_sha256'])
    return value


def execute_attempt(root, case):
    from scripts.run_unified_pipeline import run_session
    root, case = Path(root).resolve(strict=True), Path(case).resolve(strict=True)
    manifest = verify_campaign(root)
    p.require(case.parent == root/'cases' and re.fullmatch(r'[0-9]{8}', case.name), 'Invalid case directory')
    data = (case/'input').read_bytes()
    p.require(1 <= len(data) <= manifest['max_input'], 'Input exceeds campaign size limit')
    original = manifest['launch']
    template = case/'template'
    template.mkdir()
    rootfs = template/'rootfs'
    EnvironmentSnapshotStore(manifest['snapshot_store']).clone(manifest['snapshot_id'], rootfs)
    before = hashlib.sha256(guest_file(rootfs, manifest['guest_path']).read_bytes()).hexdigest()
    guest_file(rootfs, manifest['guest_path']).write_bytes(data)
    shutil.copytree(Path(original['template_run_dir'])/'config', template/'config')
    runtime = read_json(template/'config/runtime.json')
    runtime['rootfs'] = str(rootfs)
    runtime['phase1']['bundle_path'] = str(template/'config/analyzer_runtime')
    runtime['afl_file'] = settings(manifest['guest_path'], data)
    p.write_json(template/'config/runtime.json', runtime)
    launch = original | {'session_dir': str(case/'session'), 'template_run_dir': str(template),
        'snapshot_store': str(case/'snapshots'), 'seed_rootfs': str(rootfs),
        'max_iterations': 1, 'target_spec_path': None, 'replay_store_path': None, 'network_mode': 'none'}
    p.write_json(case/'unified_launch.json', launch)
    report, code = run_session(case, launch, max_steps=1)
    p.require(code == 0 and report['capsule']['status'] == 'passed' and
              report['capsule']['phase1_retirement']['phase1_retired'] is True,
              'Attempt failed capsule retirement/continuation verification')
    binding = read_json(Path(report['run_dir'])/'config/capsule_binding.json')
    coverage = verify_map(binding)
    _, bitmap = inspect_map(Path(report['run_dir'])/'logs/capsule'/MAP_NAME)
    (case/'coverage.map').write_bytes(bitmap)
    result = {'schema': 1, 'status': 'passed', 'input': runtime['afl_file'],
              'run_dir': report['run_dir'], 'coverage': coverage,
              'baseline_input_sha256': before, 'snapshot_id': manifest['snapshot_id'],
              'guest_exit': report['execution']['guest_exit_code']}
    atomic_json(case/'result.json', result)
    return result
