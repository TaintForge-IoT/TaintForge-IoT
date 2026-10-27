#!/usr/bin/env python3
"""Source-build bounded flags/DSE fixtures and verify actual QEMU reruns.

Six inversions and two non-reached-branch controls cover one static i386
fixture. General CFG completeness and arbitrary-target DSE remain open.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tempfile


FILES = ('unpacker/mvp/check_runtime_flags.py', 'unpacker/mvp/run_runtime_dse_audit.py',
         'unpacker/mvp/fixtures/core_flags32.S', 'unpacker/mvp/fixtures/core_flags_observer.c',
         'unpacker/mvp/fixtures/core_dse32.S', 'unpacker/mvp/fixtures/core_dse32.ld',
         'unpacker/test/qemu_plugin_compat.h', 'taintforge_env/__init__.py',
         'taintforge_env/concolic_file.py', 'taintforge_env/phase1_runtime.py',
         'taintforge_env/elf_target.py')


def require(value, message):
    if not value:
        raise ValueError(message)


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def save(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + '\n')


def build_flags():
    cpp = os.environ.get('TF_IR_CPPFLAGS', os.environ.get('TF_PLUGIN_CPPFLAGS'))
    libs = os.environ.get('TF_IR_LIBS', os.environ.get('TF_PLUGIN_LIBS'))
    ld = os.environ.get('TF_IR_LDFLAGS', os.environ.get('TF_PLUGIN_LDFLAGS', ''))
    if cpp is None:
        cpp = subprocess.check_output(['pkg-config', '--cflags', 'glib-2.0'], text=True, timeout=30)
    if libs is None:
        libs = subprocess.check_output(['pkg-config', '--libs', 'glib-2.0'], text=True, timeout=30)
    return shlex.split(cpp), shlex.split(libs), shlex.split(ld)


def run(project, qemu, qemu_include, plugin, output):
    project = Path(project).resolve(strict=True)
    qemu, qemu_include, plugin = (Path(p).resolve(strict=True) for p in (qemu, qemu_include, plugin))
    output = Path(output).absolute()
    require(not output.exists() and not output.is_symlink(), 'Runtime DSE output must be new')
    require(all(',' not in str(p) and '\n' not in str(p) for p in (output, plugin)),
            'Plugin argument paths cannot contain commas/newlines')
    output.mkdir(parents=True)
    result = {'schema_version': 1, 'status': 'FAIL_BOUNDED_QEMU_DSE_AUDIT',
              'project': str(project), 'bounded_fixture_only': True, 'complete_cfg': False,
              'universal_dse_soundness_proven': False, 'all_fixtures_built_from_source': True,
              'guest_executed': False, 'commands': [], 'artifacts': {}, 'runs': [], 'errors': []}
    pinned = result['artifacts']
    try:
        sys.path.insert(0, str(project))
        sys.path.insert(0, str(project / 'unpacker/mvp'))
        from check_runtime_flags import check_flags
        from taintforge_env.concolic_file import run_file_inversion
        from taintforge_env.phase1_runtime import Phase1Runtime, read_json
        runtime = Phase1Runtime.load(plugin)
        runtime.validate_qemu(qemu)
        manifest = read_json(runtime.manifest)
        header = qemu_include / 'qemu-plugin.h'
        require(header.is_file(), 'Matching qemu-plugin.h is missing')
        require(manifest['build_inputs'].get('qemu_header_sha256') == digest(header),
                'Plugin manifest does not match the selected QEMU header')
        source_files = manifest['build_inputs'].get('source_files')
        require(isinstance(source_files, dict) and source_files, 'Plugin manifest lacks source inventory')
        paths = [project / name for name in FILES]
        for name, expected in source_files.items():
            require(isinstance(name, str) and Path(name).name == name and isinstance(expected, str)
                    and re.fullmatch('[0-9a-f]{64}', expected), 'Invalid plugin source inventory')
            path = project / 'unpacker/test' / name
            require(path.is_file() and not path.is_symlink() and digest(path) == expected,
                    'Selected plugin does not match current core source: ' + name)
            paths.append(path)
        paths += [qemu, plugin, runtime.manifest, header]
        snapshot = output / 'source'
        snapshot.mkdir()
        copied = result['snapshot_files_sha256'] = {}
        for path in dict.fromkeys(paths):
            require(path.is_file() and not path.is_symlink() and path.stat().st_size <= 512 * 1024**2,
                    'Missing, symlink or oversized runtime input: ' + str(path))
            pinned[str(path)] = digest(path)
            if path.is_relative_to(project):
                destination = snapshot / path.relative_to(project)
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(path.read_bytes())
                require(digest(destination) == pinned[str(path)],
                        'Runtime source changed while copying: ' + str(path))
                copied[str(destination)] = pinned[str(path)]
        sdk = output / 'include'
        sdk.mkdir()
        (sdk / 'qemu-plugin.h').write_bytes(header.read_bytes())
        require(digest(sdk / 'qemu-plugin.h') == pinned[str(header)],
                'QEMU header changed while copying')
        copied[str(sdk / 'qemu-plugin.h')] = pinned[str(header)]
        native = output / 'native'
        native.mkdir()
        fixtures = snapshot / 'unpacker/mvp/fixtures'
        cpp, libs, ld = build_flags()
        cc = os.environ.get('TF_IR_CC', 'gcc')
        commands = [[cc, '-std=gnu11', '-O2', '-g', '-Wall', '-Wextra', '-Werror', '-fPIC', '-shared',
                     '-I', str(sdk), '-I', str(snapshot / 'unpacker/test'), *cpp,
                     str(fixtures / 'core_flags_observer.c'), *ld, *libs,
                     '-o', str(native / 'flags_observer.so')]]
        for name in ('core_flags32', 'core_dse32'):
            commands += [['as', '--32', '-o', str(native / (name + '.o')), str(fixtures / (name + '.S'))],
                         ['ld', '-m', 'elf_i386', '-T', str(fixtures / 'core_dse32.ld'),
                          '-o', str(native / (name + '.elf')), str(native / (name + '.o'))]]
        with (output / 'build.log').open('wb') as log:
            for command in commands:
                result['commands'].append(command)
                subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, check=True, timeout=180)
        for path in native.glob('*.elf'):
            path.chmod(0o700)
        built = {str(path): digest(path) for path in native.iterdir() if path.is_file()}
        result['built_artifacts_sha256'] = built
        result['guest_executed'] = True
        flags = check_flags(qemu, native / 'flags_observer.so', native / 'core_flags32.elf', output / 'flags')
        result['flags_probe'] = flags['status']
        require(flags['status'] == 'PASS_QEMU_PUSHF_BOUNDARY_PROBE',
                'EFLAGS observer differs from guest PUSHFL; inspect flags/summary.json; DSE was not run')
        receipt_hash = digest(output / 'flags/flags.receipt')
        symbols = subprocess.run(['nm', '-n', str(native / 'core_dse32.elf')], check=True,
                                 text=True, capture_output=True, timeout=30).stdout
        (output / 'dse-symbols.txt').write_text(symbols)
        matches = re.findall(r'^([0-9a-fA-F]+) T selected_branch$', symbols, re.MULTILINE)
        require(len(matches) == 1, 'Selected DSE branch symbol is missing/ambiguous')
        branch = int(matches[0], 16)
        result['branch_pc'] = branch
        seeds = result['seed_files_sha256'] = {}
        for mode in ('normal', 'single'):
            for seed in (65, 66, 128, 31):
                name = mode + '-' + str(seed)
                seed_file = output / (name + '.seed')
                seed_file.write_bytes(bytes([seed]))
                seeds[str(seed_file)] = digest(seed_file)
                directory = output / name
                run_result = run_file_inversion(
                    qemu=qemu, plugin=plugin, binary=native / 'core_dse32.elf', input_file=seed_file,
                    flags_receipt=output / 'flags/flags.receipt', branch_pc=branch, output=directory,
                    max_steps=128, single_step=mode == 'single')
                stdout = (directory / 'solve/stdout').read_bytes()
                if seed == 31:
                    valid = (run_result['status'] == 'UNKNOWN' and stdout == b'X' and
                             not (directory / 'candidate.bin').exists())
                else:
                    value = run_result.get('candidate_byte')
                    observed_path = directory / 'observe/stdout'
                    observed = observed_path.read_bytes() if observed_path.is_file() else None
                    valid = (run_result['status'] == 'VERIFIED' and type(value) is int and
                             value >= 32 and stdout == (b'E' if seed == 65 else b'N') and
                             observed == (b'E' if value == 65 else b'N') and observed != stdout)
                result['runs'].append({'mode': mode, 'seed': seed, 'status': run_result['status'],
                                       'reason': run_result.get('reason'), 'valid': valid,
                                       'candidate': run_result.get('candidate_byte')})
                print('runtime DSE:', name, run_result['status'], run_result.get('reason'), flush=True)
                require(valid, 'Runtime DSE fixture failed: ' + name + '; inspect its result.json')
        require(all(digest(Path(path)) == value for path, value in pinned.items()),
                'Pinned runtime input/source changed during the audit')
        require(all(digest(Path(path)) == value for path, value in built.items()) and
                digest(output / 'flags/flags.receipt') == receipt_hash,
                'Source-built fixture, observer or flags receipt changed during the audit')
        require(all(digest(Path(path)) == value for path, value in {**copied, **seeds}.items()),
                'Copied source/header or seed changed during the audit')
        result['artifacts_unchanged'] = True
        result['status'] = 'PASS_BOUNDED_QEMU_DSE_AUDIT'
        result['verified_external_replays'] = 6
        result['non_reached_branch_unknown_controls'] = 2
        return result
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        result['errors'].append(type(error).__name__ + ': ' + str(error))
        raise
    finally:
        result['output_files_sha256'] = {str(path.relative_to(output)): digest(path)
                                        for path in sorted(output.rglob('*'))
                                        if path.is_file() and path != output / 'summary.json'}
        save(output / 'summary.json', result)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--project', type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument('--qemu', type=Path, default=os.environ.get('TF_QEMU_I386'),
                        required=not os.environ.get('TF_QEMU_I386'))
    parser.add_argument('--qemu-include', type=Path, default=os.environ.get('TF_QEMU_INCLUDE'),
                        required=not os.environ.get('TF_QEMU_INCLUDE'))
    parser.add_argument('--plugin', type=Path, required=True)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    output = args.output
    if output is None:
        output = Path(tempfile.mkdtemp(prefix='unpack-proof.runtime-dse-', dir=args.project / 'unpacker')) / 'probe'
    print('Results:', output, flush=True)
    try:
        result = run(args.project, args.qemu, args.qemu_include, args.plugin, output)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        print('FAIL:', error, file=sys.stderr)
        return 1
    print(result['status'], flush=True)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
