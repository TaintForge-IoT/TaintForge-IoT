#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
if [[ $# -gt 2 ]]; then
    printf 'Usage: %s [QEMU_SOURCE_DIRECTORY] [INSTALL_PREFIX]\n' "$0" >&2
    exit 2
fi
"${TF_PYTHON:-python3}" -B - "$@" <<'PY'
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile

PROJECT = Path.cwd()
PINNED_COMMIT = '6e9a825c1d4e7b62d072e99a89ecd1a74c7f0d55'

def require(value, message):
    if not value:
        raise RuntimeError(message)

def checked(value):
    path = Path(value).expanduser().absolute()
    require('..' not in path.parts and not any(c in str(path) for c in (',', '\n', '\r')),
            'Build paths must be normalized and contain no commas/newlines')
    require(not any(item.is_symlink() for item in (path, *path.parents)),
            'Build path traverses a symlink: ' + str(path))
    return path

def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()

def query(command):
    return subprocess.check_output(command, stderr=subprocess.STDOUT, timeout=30)

def git(*arguments):
    return query(['git', '-C', str(source), *arguments])

def save(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + '\n')

def publish(path, data, mode=0o644):
    checked(path)
    require(not path.exists() or path.is_file() and path.stat().st_nlink == 1,
            'Publication destination is not a private regular file: ' + str(path))
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix='.' + path.name + '-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)

source = checked(sys.argv[1] if len(sys.argv) > 1 else Path.home() / '.cache/taintforge/qemu-11.0.1-warm-source')
prefix = checked(sys.argv[2] if len(sys.argv) > 2 else Path.home() / '.local/opt/taintforge/qemu-11.0.1-warm')
for path in (source, prefix):
    require(path != Path('/') and path != Path.home() and not Path.home().is_relative_to(path),
            'Build source/prefix must not contain the home directory')
    require(not path.is_relative_to(PROJECT) and not PROJECT.is_relative_to(path),
            'Build source/prefix must be independent of the project')
require(not source.is_relative_to(prefix) and not prefix.is_relative_to(source),
        'QEMU source and installation prefix must be independent')
jobs = os.environ.get('TF_BUILD_JOBS', '4')
require(jobs.isdecimal() and int(jobs) > 0, 'TF_BUILD_JOBS must be a positive integer')
tool_names = tuple(dict.fromkeys((sys.executable, 'git', 'gcc', os.environ.get('TF_IR_CC', 'gcc'),
                                  'as', 'ld', 'nm', 'ninja', 'pkg-config')))
tools = {}
for name in tool_names:
    found = shutil.which(name)
    require(found is not None, 'Build tool not found: ' + name)
    path = Path(found).resolve(strict=True)
    tools[name] = {'path': str(path), 'sha256': digest(path),
                   'version': query([str(path), '--version']).decode(errors='replace')}
subprocess.run(['pkg-config', '--exists', 'glib-2.0', 'capstone', 'z3'], check=True)
dependencies = {name: query(['pkg-config', '--modversion', name]).decode().strip()
                for name in ('glib-2.0', 'capstone', 'z3')}
if not source.exists():
    source.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(['git', 'clone', '--depth', '1', '--branch', 'v11.0.1',
                    'https://gitlab.com/qemu-project/qemu.git', str(source)], check=True)
require(git('rev-parse', 'HEAD').decode().strip() == PINNED_COMMIT,
        'QEMU source must be exact pinned v11.0.1 commit ' + PINNED_COMMIT)
require(subprocess.run(['git', '-C', str(source), 'diff', '--cached', '--quiet']).returncode == 0,
        'QEMU source index contains staged changes')
spec = importlib.util.spec_from_file_location('tf_warm_installer', PROJECT / 'experiments/afl_file/qemu/apply.py')
installer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installer)
allowed = set(installer.BASELINES) | {'linux-user/tf-warm.h'}
changed = {name.decode() for name in git('diff', '--name-only', '-z', 'HEAD', '--').split(b'\0') if name}
require(not changed - allowed, 'Unexpected tracked QEMU source edits: ' + ', '.join(sorted(changed - allowed)))
installer.changes(source)
relative_artifacts = {'qemu': 'bin/qemu-i386', 'plugin': 'lib/taintforge/libtaintforge_ir.so',
    'runtime_manifest': 'lib/taintforge/libtaintforge_ir.so.runtime.json', 'header': 'include/taintforge/qemu-plugin.h'}
for name in (*relative_artifacts.values(), 'share/taintforge/runtime.json', 'share/taintforge/environment.sh'):
    checked(prefix / name)
state = prefix / 'share/taintforge'
state.mkdir(parents=True, exist_ok=True)
attempt = Path(tempfile.mkdtemp(prefix='build.', dir=state))
ready, environment = state / 'runtime.json', state / 'environment.sh'
locks, commands, installing = [], [], False
print('Runtime build logs: ' + str(attempt), flush=True)

def run(command, log_name, *, cwd=PROJECT, env=None):
    commands.append([str(value) for value in command])
    save(attempt / 'commands.json', commands)
    with (attempt / log_name).open('wb') as output:
        try:
            subprocess.run(command, cwd=cwd, env=env, stdout=output, stderr=subprocess.STDOUT, check=True)
        except subprocess.CalledProcessError:
            print((attempt / log_name).read_bytes()[-12000:].decode(errors='replace'), file=sys.stderr)
            raise

try:
    for lock in (source / '.taintforge-runtime-build.lock', state / '.build.lock'):
        lock.mkdir()
        locks.append(lock)
    run([sys.executable, '-B', 'experiments/afl_file/qemu/apply.py', '--qemu-source', str(source), '--check'], 'source-check.log')
    run([sys.executable, '-B', 'experiments/afl_file/qemu/apply.py', '--qemu-source', str(source)], 'source-patch.log')
    diff = git('diff', '--binary', 'HEAD', '--')
    (attempt / 'qemu-source.patch').write_bytes(diff)
    critical = {PROJECT / name for name in ('scripts/build_afl_warm_qemu.sh',
        'experiments/afl_file/qemu/apply.py', 'experiments/afl_file/qemu/tf-warm.h',
        'scripts/calibrate_runtime_flags.py', 'taintforge_env/runtime_flags.py',
        'taintforge_env/phase1_runtime.py', 'taintforge_env/elf_target.py',
        'unpacker/mvp/check_runtime_flags.py', 'unpacker/mvp/fixtures/core_flags_observer.c',
        'unpacker/mvp/fixtures/core_flags32.S')}
    critical.update(path for path in (PROJECT / 'unpacker/test').iterdir()
                    if path.is_file() and path.suffix in ('.c', '.h', '.py', '.sh'))
    require(all(path.is_file() and not path.is_symlink() for path in critical), 'Unsafe or missing project build input')
    inputs = {'schema_version': 1, 'project': str(PROJECT), 'source': str(source), 'prefix': str(prefix),
        'qemu_commit': PINNED_COMMIT, 'qemu_source_diff_sha256': hashlib.sha256(diff).hexdigest(),
        'qemu_added_sources': {'linux-user/tf-warm.h': digest(source / 'linux-user/tf-warm.h')},
        'project_sources': {str(path): digest(path) for path in sorted(critical)},
        'tools': tools, 'dependencies': dependencies,
        'environment': {key: os.environ.get(key) for key in ('CC', 'CFLAGS', 'CXXFLAGS', 'LDFLAGS',
            'TF_IR_CC', 'TF_PLUGIN_CPPFLAGS', 'TF_PLUGIN_LIBS', 'TF_PLUGIN_LDFLAGS',
            'PKG_CONFIG_PATH', 'PKG_CONFIG_LIBDIR', 'PKG_CONFIG_SYSROOT_DIR', 'TF_BUILD_JOBS')}}
    save(attempt / 'inputs.json', inputs)

    def intact():
        require(not installer.changes(source), 'Patched QEMU inputs changed while building')
        require(git('rev-parse', 'HEAD').decode().strip() == PINNED_COMMIT and
                hashlib.sha256(git('diff', '--binary', 'HEAD', '--')).hexdigest() == inputs['qemu_source_diff_sha256'],
                'QEMU source changed while building')
        for name, expected in inputs['qemu_added_sources'].items():
            require(digest(source / name) == expected, 'Added QEMU source changed: ' + name)
        for name, expected in inputs['project_sources'].items():
            require(digest(name) == expected, 'Project build input changed: ' + name)
        for identity in tools.values():
            require(digest(identity['path']) == identity['sha256'], 'Build tool changed during runtime construction')

    build = source / 'build-taintforge-warm'
    checked(build)
    build.mkdir(exist_ok=True)
    print('runtime: QEMU build', flush=True)
    run(['../configure', '--python=' + sys.executable, '--target-list=i386-linux-user', '--enable-plugins',
         '--disable-docs', '--disable-system', '--without-default-features', '--prefix=' + str(prefix)],
        'qemu-configure.log', cwd=build)
    run(['ninja', '-j', jobs, 'qemu-i386'], 'qemu-build.log', cwd=build)
    stage = attempt / 'stage'
    for name in relative_artifacts.values():
        (stage / name).parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(build / 'qemu-i386', stage / relative_artifacts['qemu'])
    shutil.copy2(source / 'include/plugins/qemu-plugin.h', stage / relative_artifacts['header'])
    symbols = query(['nm', '-D', '--defined-only', str(stage / relative_artifacts['qemu'])])
    (attempt / 'exported-symbols.txt').write_bytes(symbols)
    exported = {line.split()[-1] for line in symbols.decode().splitlines() if line.split()}
    require({'qemu_plugin_tf_warm_configure', 'qemu_plugin_tf_warm_arm'} <= exported,
            'Built QEMU does not export the required warm ABI')
    print('runtime: matching Phase 1 plugin build', flush=True)
    plugin_env = dict(os.environ, TF_QEMU_INCLUDE=str(stage / 'include/taintforge'), TF_PYTHON=sys.executable)
    run(['bash', 'unpacker/test/build_group7_4c1_plugin.sh', 'unpacker/test', str(stage / relative_artifacts['plugin'])],
        'plugin-build.log', env=plugin_env)
    intact()
    installing = True
    for path in (ready, environment):
        checked(path)
        require(not path.exists() or path.is_file() and path.stat().st_nlink == 1, 'Unsafe prior readiness artifact')
        path.unlink(missing_ok=True)
    for name in relative_artifacts.values():
        artifact = stage / name
        publish(prefix / name, artifact.read_bytes(), stat.S_IMODE(artifact.stat().st_mode))
    print('runtime: exact installed binary calibration and full-plugin load', flush=True)
    run([sys.executable, '-B', '-m', 'scripts.calibrate_runtime_flags',
         '--qemu', str(prefix / relative_artifacts['qemu']), '--plugin', str(prefix / relative_artifacts['plugin']),
         '--qemu-include', str(prefix / 'include/taintforge'), '--out', str(attempt / 'calibration')], 'calibration.log')
    calibration_path = attempt / 'calibration/summary.json'
    calibration_hash = digest(calibration_path)
    calibration = json.loads(calibration_path.read_bytes())
    require(calibration.get('status') == 'READY_X86_FLAGS_RUNTIME' and
            calibration.get('full_plugin_smoke', {}).get('status') == 'PASS_FULL_PHASE1_PLUGIN_FLAGS_LOAD',
            'Calibration did not establish the bounded runtime contract')
    intact()
    for role, name in relative_artifacts.items():
        identity = calibration['sources'][role]
        require(identity['path'] == str(prefix / name) and digest(prefix / name) == identity['sha256'] and
                digest(stage / name) == identity['sha256'], 'Staged, installed or calibrated artifact differs: ' + role)
    receipt = checked(calibration['flags_receipt'])
    require(receipt.is_relative_to(attempt / 'calibration') and
            digest(receipt) == calibration['flags_receipt_sha256'], 'Calibration receipt changed or escaped its attempt')
    require(calibration['qemu_sha256'] == calibration['sources']['qemu']['sha256'] and
            digest(calibration_path) == calibration_hash, 'Calibration identities changed')
    manifest = {'schema_version': 1, 'status': 'READY_TAINTFORGE_DSE_RUNTIME',
        'scope': 'source_built_i386_runtime_bounded_flags_calibration_and_full_plugin_load',
        'qemu': str(prefix / relative_artifacts['qemu']), 'plugin': str(prefix / relative_artifacts['plugin']),
        'runtime_manifest': str(prefix / relative_artifacts['runtime_manifest']),
        'qemu_include': str(prefix / 'include/taintforge'), 'flags_receipt': str(receipt),
        'flags_receipt_sha256': calibration['flags_receipt_sha256'], 'plugin_api': calibration['plugin_api'],
        'artifacts': {role: calibration['sources'][role] for role in relative_artifacts},
        'calibration_summary': {'path': str(calibration_path), 'sha256': calibration_hash},
        'build_inputs': inputs, 'build_attempt': str(attempt),
        'cross_host_bit_reproducibility_established': False, 'guest_isolation_verified': False,
        'hostile_sample_ready': False, 'universal_equivalence': False}
    exports = {'TF_OBSERVER_QEMU': manifest['qemu'], 'TF_WARM_QEMU': manifest['qemu'],
        'TF_PHASE1_PLUGIN': manifest['plugin'], 'TAINTFORGE_QEMU_PLUGIN': manifest['plugin'],
        'TF_X86_FLAGS_RECEIPT': str(receipt), 'TF_QEMU_INCLUDE': manifest['qemu_include'],
        'TF_RUNTIME_MANIFEST': str(ready)}
    shell = '# Source after a successful runtime build.\n' + ''.join(
        'export ' + key + '=' + shlex.quote(value) + '\n' for key, value in exports.items())
    publish(environment, shell.encode())
    publish(ready, (json.dumps(manifest, indent=2, sort_keys=True) + '\n').encode())
    print('READY_TAINTFORGE_DSE_RUNTIME\nQEMU: ' + manifest['qemu'] + '\nEnvironment: ' + str(environment), flush=True)
except BaseException as error:
    if installing:
        ready.unlink(missing_ok=True)
        environment.unlink(missing_ok=True)
    save(attempt / 'failure.json', {'status': 'FAILED_RUNTIME_BUILD', 'error': type(error).__name__ + ': ' + str(error)})
    print('Runtime build failed; logs: ' + str(attempt), file=sys.stderr)
    raise
finally:
    for lock in reversed(locks):
        lock.rmdir()
PY
