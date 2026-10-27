#!/usr/bin/env python3
"""Capture and replay the selected packed ELF with a source-built QEMU observer.

This creates a new execution. Historical M362/M366 observations are not promoted
to observations of this run. QEMU, the host toolchain and dependency libraries
remain trusted inputs.
"""

import argparse
import hashlib
import os
from pathlib import Path, PurePosixPath
import resource
import shlex
import signal
import subprocess
import sys
import tempfile
import time
import uuid
import zipfile

sys.dont_write_bytecode = True
try:
    from . import oep_verify as verifier
except ImportError:
    import oep_verify as verifier

ROOT = Path(__file__).resolve().parent
PROJECT = ROOT.parent
RUNTIME_ROOT = PROJECT / 'unpacker/ir-mappings.D95hOnBI/qemu'
API_NAMES = tuple('qemu_plugin_taintforge_user_' + name + '_v1' for name in ('vmas', 'entry', 'brk'))
CONTROLLED_ENVIRONMENT = {'LC_ALL': 'C'}
BUILD_ENVIRONMENT = {'LC_ALL': 'C', 'TZ': 'UTC', 'PATH': os.environ.get('PATH', '/usr/bin:/bin')}
TIMEOUT_SECONDS = 600


def file_digest(path):
    value = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            value.update(block)
    return value.hexdigest()


def run_command(command, log, *, timeout=120, check=True, cwd=None):
    result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, timeout=timeout,
                            env=BUILD_ENVIRONMENT, cwd=cwd)
    verifier.require(not check or result.returncode == 0, 'Command failed; inspect ' + str(log.name))
    return result


def configured_source_binding(source, build):
    path = build / 'compile_commands.json'
    verifier.require(path.is_file(), 'Configured QEMU compile_commands.json missing')
    with path.open('rb') as stream:
        data = stream.read(32 * 1024**2 + 1)
    verifier.require(len(data) <= 32 * 1024**2, 'QEMU compilation database exceeds bound')
    rows = verifier.strict_json(data)
    verifier.require(type(rows) is list, 'QEMU compilation database must be an array')
    expected = {source / name for name in ('plugins/api-user.c', 'linux-user/elfload.c')}
    selected = set()
    for row in rows:
        verifier.require(type(row) is dict and type(row.get('file')) is str
                         and type(row.get('directory')) is str, 'QEMU compilation source record')
        directory = Path(row['directory'])
        verifier.require(directory.is_absolute(), 'QEMU compilation directory must be absolute')
        selected.add((directory / row['file']).resolve())
    verifier.require(expected <= selected, 'QEMU build is not configured for the selected source tree')
    return {'compilation_database_sha256': verifier.digest(data),
            'selected_source_files': sorted(map(str, expected))}


def apply_observer_patch(source, patch, log):
    """Apply relative to QEMU even when its source is inside the project Git tree."""
    source, patch = Path(source).resolve(), Path(patch).resolve()
    # -C alone retains a parent repository's root and can silently skip every
    # patch path as outside the current subdirectory, returning success.
    command_base = ['git', '-C', str(source), '--work-tree=' + str(source), 'apply']
    commands = [command_base + ['--check', str(patch)]]
    if run_command(commands[-1], log, check=False).returncode == 0:
        commands.append(command_base + [str(patch)])
        run_command(commands[-1], log)
        commands.append(command_base + ['--reverse', '--check', str(patch)])
        verifier.require(run_command(commands[-1], log, check=False).returncode == 0,
                         'Applied QEMU observer patch failed reverse verification; inspect ' + str(log.name))
        state = 'APPLIED'
    else:
        commands.append(command_base + ['--reverse', '--check', str(patch)])
        verifier.require(run_command(commands[-1], log, check=False).returncode == 0,
                         'QEMU sources differ from both observer patch states; inspect ' + str(log.name))
        state = 'ALREADY_APPLIED'
    return state, commands


def audit_runtime_exports(source, build, output, qemu):
    """Save export diagnostics before rejecting a successfully linked runtime."""
    receipt = {'schema_version': 1, 'qemu_sha256': file_digest(qemu),
               'required_exported_APIs': list(API_NAMES), 'export_inputs': {}}
    inputs = (('symbol-generator.py', source / 'scripts/qemu-plugin-symbols.py'),
              ('plugin-sdk.h', source / 'include/plugins/qemu-plugin.h'),
              ('qemu-plugin.symbols', build / 'plugins/qemu-plugin.symbols'))
    for name, path in inputs:
        if path.is_file() and not path.is_symlink():
            with path.open('rb') as stream:
                data = stream.read(4 * 1024**2 + 1)
            if len(data) <= 4 * 1024**2:
                (output / name).write_bytes(data)
                receipt['export_inputs'][name] = {'path': str(path), 'sha256': verifier.digest(data)}
    command = ['nm', '-D', '--defined-only', str(qemu)]
    receipt['dynamic_symbols_command'] = command
    try:
        symbols = subprocess.check_output(command, text=True, timeout=30,
                                          stderr=subprocess.STDOUT, env=BUILD_ENVIRONMENT)
    except (OSError, subprocess.SubprocessError) as error:
        receipt['dynamic_symbols_error'] = type(error).__name__ + ': ' + str(error)
        verifier.save(output / 'export-check.json', receipt)
        raise ValueError('Cannot inspect QEMU exports; inspect ' + str(output / 'export-check.json')) from error
    (output / 'nm-dynamic.txt').write_text(symbols)
    receipt['dynamic_symbols_sha256'] = verifier.digest(symbols.encode())
    exported = {line.split()[-1].split('@')[0] for line in symbols.splitlines() if line.split()}
    missing = sorted(set(API_NAMES) - exported)
    receipt['present_exported_APIs'] = sorted(set(API_NAMES) & exported)
    receipt['missing_exported_APIs'] = missing
    if missing:
        command = ['nm', '--defined-only', str(qemu)]
        receipt['defined_symbols_command'] = command
        try:
            defined = subprocess.check_output(command, text=True, timeout=30,
                                              stderr=subprocess.STDOUT, env=BUILD_ENVIRONMENT)
            (output / 'nm-defined.txt').write_text(defined)
            receipt['defined_symbols_sha256'] = verifier.digest(defined.encode())
            names = {line.split()[-1].split('@')[0] for line in defined.splitlines() if line.split()}
            receipt['present_defined_APIs'] = sorted(set(API_NAMES) & names)
        except (OSError, subprocess.SubprocessError) as error:
            receipt['defined_symbols_error'] = type(error).__name__ + ': ' + str(error)
    verifier.save(output / 'export-check.json', receipt)
    verifier.require(not missing, 'Built QEMU does not export all observer APIs: ' + ', '.join(missing)
                     + '; inspect ' + str(output / 'export-check.json'))
    return receipt


def prepare_runtime(source, build, output):
    """Build the observer separately from the pinned historical QEMU runtime."""
    source, build = Path(source).resolve(), Path(build).resolve()
    patch = ROOT / 'qemu_oep_observer.patch'
    verifier.require(source.is_dir() and (source / 'VERSION').is_file(), 'QEMU source directory missing')
    historical_builds = {(RUNTIME_ROOT / 'verified/build').resolve(),
                         (source.parent / 'verified/build').resolve()}
    historical_qemu = os.environ.get('TF_QEMU_I386')
    verifier.require(build not in historical_builds
                     and (historical_qemu is None or (build / 'qemu-i386').resolve() != Path(historical_qemu).resolve()),
                     'Observer build must not overwrite the pinned historical QEMU runtime')
    verifier.require(patch.is_file(), 'Project QEMU observer patch missing')
    configured = (build / 'build.ninja').is_file()
    if configured:
        configured_source_binding(source, build)
    else:
        verifier.require((source / 'configure').is_file(), 'Full QEMU source configure script missing')
        marker = build / '.taintforge-observer-source'
        verifier.require(not build.exists() or not any(build.iterdir())
                         or marker.is_file() and marker.read_text() == str(source),
                         'Observer build directory is not empty and is not an observer build')
        build.mkdir(parents=True, exist_ok=True)
        marker.write_text(str(source))
    output.mkdir()
    with (output / 'build.log').open('wb') as log:
        state, commands = apply_observer_patch(source, patch, log)
        if not configured:
            command = [str(source / 'configure'), '--target-list=i386-linux-user', '--enable-plugins']
            commands.append(command)
            print('runtime: configuring separate observer build ' + str(build), flush=True)
            run_command(command, log, timeout=1800, cwd=build)
            verifier.require((build / 'build.ninja').is_file(), 'QEMU configure did not produce build.ninja')
            configured_source_binding(source, build)
        command = ['ninja', '-C', str(build), '-j', str(min(8, os.cpu_count() or 1)), 'qemu-i386']
        commands.append(command)
        print('runtime: rebuilding qemu-i386; log=' + str(log.name), flush=True)
        run_command(command, log, timeout=1800)
    qemu = build / 'qemu-i386'
    verifier.require(qemu.is_file() and os.access(qemu, os.X_OK), 'Built qemu-i386 unavailable')
    export_check = audit_runtime_exports(source, build, output, qemu)
    sdk = source / 'include/plugins/qemu-plugin.h'
    verifier.require(sdk.is_file(), 'Matching QEMU plugin SDK missing')
    inputs = {'VERSION', 'target/i386/gdbstub.c', 'linux-user/i386/cpu_loop.c'}
    for line in patch.read_text().splitlines():
        if line.startswith('+++ b/'):
            name = line[6:]
            relative = PurePosixPath(name)
            verifier.require(not relative.is_absolute() and '..' not in relative.parts
                             and str(relative) == name, 'Unsafe QEMU patch path')
            inputs.add(name)
    copies = output / 'source'
    copies.mkdir()
    source_hashes = {}
    for name in sorted(inputs):
        path = source / name
        verifier.require(path.is_file() and not path.is_symlink(), 'QEMU observation source missing: ' + name)
        data = path.read_bytes()
        source_hashes[name] = verifier.digest(data)
        target = copies / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    receipt = {'schema_version': 1, 'patch_state': state, 'commands': commands,
               'source_directory': str(source), 'build_directory': str(build),
               'qemu_sha256': file_digest(qemu), 'sdk_sha256': file_digest(sdk),
               'observer_patch_sha256': file_digest(patch), 'source_files_sha256': source_hashes,
               'configured_source_binding': configured_source_binding(source, build),
               'required_exported_APIs': list(API_NAMES), 'export_check': export_check,
               'configured_build_and_toolchain_trusted': True,
               'historical_flags_receipt_reused': False, 'historical_environment_file_modified': False,
               'historical_runtime_binary_overwritten': False, 'separate_observer_build': True,
               'configured_QEMU_build_requested': True, 'clean_full_QEMU_rebuild_requested': False}
    verifier.save(output / 'receipt.json', receipt)
    return qemu, receipt


def build_plugin(source, output):
    output.mkdir()
    sdk = Path(source) / 'include/plugins'
    cpp, libraries = os.environ.get('TF_PLUGIN_CPPFLAGS'), os.environ.get('TF_PLUGIN_LIBS')
    if cpp is None:
        cpp = subprocess.check_output(['pkg-config', '--cflags', 'glib-2.0'], text=True, timeout=30)
    if libraries is None:
        libraries = subprocess.check_output(['pkg-config', '--libs', 'glib-2.0'], text=True, timeout=30)
    binary = output / 'oep_capture.so'
    command = [os.environ.get('TF_IR_CC', 'gcc'), '-std=gnu11', '-O2', '-Wall', '-Wextra', '-Werror',
               '-fPIC', '-shared', '-fvisibility=hidden', '-I', str(sdk), '-I', str(ROOT / 'test'),
               *shlex.split(cpp), str(ROOT / 'oep_capture.c'), *shlex.split(libraries), '-o', str(binary)]
    with (output / 'build.log').open('wb') as log:
        run_command(command, log)
    receipt = {'schema_version': 1, 'commands': [command], 'plugin_sha256': file_digest(binary),
               'native_source_sha256': file_digest(ROOT / 'oep_capture.c'),
               'compatibility_header_sha256': file_digest(ROOT / 'test/qemu_plugin_compat.h'),
               'SDK_sha256': file_digest(sdk / 'qemu-plugin.h'),
               'compiler_linker_configuration_and_dependencies_trusted': True,
               'historical_native_objects_selected': False}
    verifier.save(output / 'receipt.json', receipt)
    return binary, receipt


def child_limits():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_AS, (8 * 1024**3, 8 * 1024**3))
    resource.setrlimit(resource.RLIMIT_FSIZE, (64 * 1024**2, 64 * 1024**2))
    resource.setrlimit(resource.RLIMIT_CPU, (TIMEOUT_SECONDS, TIMEOUT_SECONDS + 5))
    resource.setrlimit(resource.RLIMIT_NOFILE, (1024, 1024))


def stop_capture(process):
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait(timeout=10)


def capture(qemu, plugin, packed, output, runtime_receipt, plugin_receipt):
    directory = output / 'capture'
    directory.mkdir()
    target = directory / 'packed.upx'
    target.write_bytes(packed)
    target.chmod(0o755)
    run_id = uuid.uuid4().hex
    paths = (plugin, target, directory / 'events.jsonl', directory / 'report.json')
    verifier.require(all(',' not in str(path) and '\n' not in str(path) for path in paths),
                     'Comma or newline in a plugin path is unsupported')
    options = (str(plugin) + ',guest=' + str(target) + ',events=' + str(paths[2])
               + ',report=' + str(paths[3]) + ',run-id=' + run_id)
    command = [str(qemu), '-plugin', options, '-0', 'target.elf', str(target), '-q', '-H0']
    launch = {'schema_version': 1, 'run_id': run_id, 'source_elf_sha256': verifier.digest(packed),
              'guest_argv': ['target.elf', '-q', '-H0'],
              'guest_environ': [key + '=' + value for key, value in CONTROLLED_ENVIRONMENT.items()],
              'argv': command, 'cwd': str(directory), 'controlled_host_environment': CONTROLLED_ENVIRONMENT,
              'qemu_sha256': runtime_receipt['qemu_sha256'], 'plugin_sha256': plugin_receipt['plugin_sha256'],
              'runtime_receipt_sha256': file_digest(output / 'runtime/receipt.json'),
              'plugin_receipt_sha256': file_digest(output / 'native/receipt.json'),
              'timeout_seconds': TIMEOUT_SECONDS, 'stdin_empty': True, 'close_fds': True,
              'descriptor_limit': 1024, 'new_independent_execution': True,
              'same_execution_as_historical_M362': False, 'payload_instruction_execution_allowed': False}
    verifier.save(output / 'launch.json', launch)
    print('capture: new run ' + run_id + '; stop before 0x08049096', flush=True)
    with (directory / 'stdout').open('wb') as stdout, (directory / 'stderr').open('wb') as stderr:
        process = subprocess.Popen(command, cwd=directory, env=dict(CONTROLLED_ENVIRONMENT),
                                   stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                                   close_fds=True, start_new_session=True, preexec_fn=child_limits)
        deadline = time.monotonic() + TIMEOUT_SECONDS
        try:
            while True:
                remaining = deadline - time.monotonic()
                verifier.require(remaining > 0, 'Capture timed out')
                try:
                    process.wait(timeout=min(30, remaining))
                    break
                except subprocess.TimeoutExpired:
                    print('capture: still running; stderr=' + str(directory / 'stderr'), flush=True)
        finally:
            if process.poll() is None:
                stop_capture(process)
    launch['returncode'] = process.returncode
    verifier.save(output / 'launch.json', launch)
    verifier.require(process.returncode == 0, 'Capture failed; inspect ' + str(directory / 'stderr'))
    report = verifier.strict_json((directory / 'report.json').read_bytes())
    verifier.require(report.get('success') is True, 'Capture did not complete at the selected boundary')
    try:
        from .oep_observations import read_capture
    except ImportError:
        from oep_observations import read_capture
    return read_capture((directory / 'events.jsonl').read_bytes(), launch), launch


def archive_results(output):
    files = [p for p in sorted(output.rglob('*')) if p.is_file()
             and p.name not in ('oep-evidence.zip', 'evidence-files.json')]
    verifier.require(not any(p.is_symlink() for p in output.rglob('*')), 'Result symlink')
    verifier.require(len(files) <= 500 and sum(p.stat().st_size for p in files) <= 512 * 1024**2,
                     'Capture evidence exceeds bound')
    verifier.save(output / 'evidence-files.json',
                  {p.relative_to(output).as_posix(): file_digest(p) for p in files})
    with zipfile.ZipFile(output / 'oep-evidence.zip', 'w', zipfile.ZIP_DEFLATED) as archive:
        for path in [*files, output / 'evidence-files.json']:
            archive.write(path, path.relative_to(output).as_posix())


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--m366', required=True, type=Path, help='Successful M366 evidence ZIP or result directory')
    parser.add_argument('--original-elf', required=True, type=Path)
    parser.add_argument('--qemu-source', type=Path, default=RUNTIME_ROOT / 'qemu-source')
    parser.add_argument('--qemu-build', type=Path, default=RUNTIME_ROOT / 'oep-observer-build')
    parser.add_argument('--output', type=Path)
    args = parser.parse_args(argv)
    output = args.output.resolve() if args.output else Path(tempfile.mkdtemp(prefix='oep-capture.', dir=ROOT)) / 'probe'
    output.mkdir(parents=True, exist_ok=False)
    print('Results:', output, flush=True)
    summary = {'schema_version': 1, 'status': 'FAIL', 'errors': [], 'oep_proof': 'NOT_ESTABLISHED',
               'unconditional_oep_proven': False, 'target_instruction_executed': False,
               'new_capture_completed': False}
    try:
        with verifier.Evidence(args.m366) as baseline:
            packed = baseline.read('reduced-inputs/source.elf')
            verifier.require(verifier.digest(packed) == verifier.ELF_SHA, 'Selected packed ELF differs')
            source_evidence_sha = baseline.sha256
        original, identity = verifier.read_original_reference(args.original_elf)
        verifier.require(identity['matches_historical_M312_original_sha256'], 'Selected original ELF differs from historical pin')
        verifier.save(output / 'input-receipt.json', {'M366_evidence_sha256': source_evidence_sha,
                      'source_elf_sha256': verifier.ELF_SHA, 'original_reference': identity,
                      'historical_observations_used_as_current_observations': False})
        qemu, runtime_receipt = prepare_runtime(args.qemu_source, args.qemu_build, output / 'runtime')
        plugin, plugin_receipt = build_plugin(args.qemu_source, output / 'native')
        rows, launch = capture(qemu, plugin, packed, output, runtime_receipt, plugin_receipt)
        summary['new_capture_completed'] = True
        try:
            from .oep_current_run import verify_capture
        except ImportError:
            from oep_current_run import verify_capture
        report = verify_capture(rows, launch, packed, original, output)
        verifier.require(type(report) is dict and report.get('status') not in (None, 'FAIL'), 'Fresh verification report missing or failed')
        verifier.require(report.get('unconditional_oep_proven') is False
                         and report.get('target_instruction_executed') is False
                         and report.get('oep_proof') == 'NOT_ESTABLISHED', 'Fresh verification report promoted unconditional proof scope')
        summary.update(report)
        summary['errors'] = []
        print(summary['status'], flush=True)
    except (ValueError, OSError, KeyError, TypeError, RecursionError, ImportError,
            subprocess.SubprocessError, zipfile.BadZipFile) as error:
        summary['errors'].append(type(error).__name__ + ': ' + str(error))
        print('FAIL:', summary['errors'][-1], flush=True)
    finally:
        verifier.save(output / 'summary.json', summary)
    try:
        archive_results(output)
        print('Evidence:', output / 'oep-evidence.zip', flush=True)
    except (ValueError, OSError, zipfile.BadZipFile) as error:
        summary['status'] = 'FAIL'
        summary['errors'].append('Evidence archive: ' + str(error))
        verifier.save(output / 'summary.json', summary)
        print('FAIL:', summary['errors'][-1], flush=True)
    return 0 if not summary['errors'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
