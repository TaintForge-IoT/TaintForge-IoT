"""Build and calibrate a bounded x86 flag observer for one exact runtime."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import stat
import subprocess

from .phase1_runtime import Phase1Run, Phase1Runtime, read_json


PROJECT = Path(__file__).resolve().parents[1]
MAX_ARTIFACT = 16 * 1024**2


def _require(value, message):
    if not value:
        raise ValueError(message)


def _path(value):
    path = Path(value).expanduser().absolute()
    _require('..' not in path.parts, 'Parent traversal in calibration path')
    _require(all(not item.is_symlink() for item in (path, *path.parents)),
             'Calibration paths must not traverse symlinks')
    return path


def _pin(value, maximum=MAX_ARTIFACT, *, private=True):
    path = _path(value)
    info = path.lstat()
    _require(stat.S_ISREG(info.st_mode) and (not private or info.st_nlink == 1) and info.st_size <= maximum,
             'Expected bounded ' + ('private ' if private else '') + 'regular calibration input: ' + str(path))
    digest, size = hashlib.sha256(), 0
    with path.open('rb') as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
            size += len(chunk)
            _require(size <= maximum, 'Calibration input exceeds its byte limit')
    _require(path.stat().st_size == size, 'Calibration input changed while reading')
    return {'path': str(path), 'size': size, 'sha256': digest.hexdigest()}


def _save(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + '\n')


def _tool(name):
    found = shutil.which(name)
    _require(found is not None, 'Calibration build tool not found: ' + name)
    path = Path(found).resolve(strict=True)
    return _pin(path, 512 * 1024**2, private=False)


def _build_tools(sources, directory):
    directory.mkdir()
    source = directory / 'source'
    source.mkdir()
    for role, name in (('header', 'qemu-plugin.h'), ('compat', 'qemu_plugin_compat.h'),
                       ('observer_source', 'core_flags_observer.c'), ('guest_source', 'core_flags32.S')):
        original = Path(sources[role]['path'])
        shutil.copy2(original, source / name)
        _require(_pin(source / name)['sha256'] == sources[role]['sha256'],
                 'Calibration source changed while copying')
    tools = {role: _tool(name) for role, name in
             (('compiler', os.environ.get('TF_IR_CC', 'gcc')), ('assembler', 'as'),
              ('linker', 'ld'), ('symbols', 'nm'), ('pkg_config', 'pkg-config'))}
    commands = []

    def run(command):
        commands.append(command)
        _save(directory / 'commands.json', commands)
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                check=True, timeout=120)
        _require(len(result.stdout) + len(result.stderr) <= MAX_ARTIFACT,
                 'Calibration build output exceeded its limit')
        with (directory / 'build.log').open('ab') as log:
            log.write(result.stdout)
            log.write(result.stderr)
        return result.stdout.decode('utf-8', errors='strict')

    versions = {role: run([identity['path'], '--version']) for role, identity in tools.items()}
    pkg = tools['pkg_config']['path']
    cflags = shlex.split(os.environ['TF_PLUGIN_CPPFLAGS']) if os.environ.get('TF_PLUGIN_CPPFLAGS') else \
        shlex.split(run([pkg, '--cflags', 'glib-2.0']))
    libs = shlex.split(os.environ['TF_PLUGIN_LIBS']) if os.environ.get('TF_PLUGIN_LIBS') else \
        shlex.split(run([pkg, '--libs', 'glib-2.0']))
    _require(libs, 'GLib calibration link flags must not be empty')
    ldflags = shlex.split(os.environ.get('TF_PLUGIN_LDFLAGS', ''))
    run([tools['compiler']['path'], '-std=gnu11', '-O2', '-Wall', '-Wextra', '-Werror',
         '-fPIC', '-shared', '-I', str(source), *cflags, str(source / 'core_flags_observer.c'),
         *ldflags, *libs, '-o', str(directory / 'flags-observer.so')])
    run([tools['assembler']['path'], '--32', str(source / 'core_flags32.S'), '-o', str(directory / 'core_flags32.o')])
    run([tools['linker']['path'], '-m', 'elf_i386', '-z', 'noexecstack',
         str(directory / 'core_flags32.o'), '-o', str(directory / 'core_flags32.elf')])
    return {'toolchain': tools, 'tool_versions': versions, 'commands': commands}


def _run_probe(qemu, observer, binary, output):
    path = PROJECT / 'unpacker/mvp/check_runtime_flags.py'
    spec = importlib.util.spec_from_file_location('taintforge_runtime_flags_probe', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.check_flags(qemu, observer, binary, output)


def _phase1_smoke(qemu, runtime, binary, receipt, out, expected_stdout):
    out.mkdir()
    analysis = Phase1Run(runtime, 'runtime-flags', 'runtime-flags-load', 'runtime-flags-plugin',
                         out / 'phase1', require_flags=True, flags_receipt=receipt)
    argument = analysis.plugin_argument(ir=False, extra=('runtime-log=summary', 'dse-check=off',
        'tf-capture=exit', 'tf-max-capture-bytes=1048576', 'ir-trace-capacity=16384', 'tf-max-events=4096'))
    command = [str(qemu), '-plugin', argument, str(binary)]
    _save(out / 'command.json', command)
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
    (out / 'stdout').write_bytes(result.stdout)
    (out / 'stderr').write_bytes(result.stderr)
    _require(result.returncode == 0 and result.stdout == expected_stdout and len(result.stdout) == 128,
             'Full Phase 1 plugin smoke did not preserve the PUSHFL fixture output')
    phase, events = analysis.verify(), analysis.events()
    capabilities = events[0].get('data', {})
    _require(phase['runtime_observed'] is True and phase['artifact_integrity'] == 'verified' and
             phase['stream_status'] in ('completed', 'partial') and
             capabilities.get('profile') == 'linux-i386-single-thread-v1' and
             capabilities.get('ir_enabled') is False and
             capabilities.get('flags_contract') == 'taintforge_x86_flags_v1',
             'Full Phase 1 plugin load or flags contract was not observed')
    _require(not any(event['event_type'] in ('profile_lost', 'data_loss') or
             event['event_type'] == 'runtime_observation' and
             event.get('status') in ('partial', 'error', 'unsupported') for event in events),
             'Full Phase 1 smoke lost its runtime profile or observations')
    summaries = [event['data'] for event in events if event['event_type'] == 'analysis_summary']
    _require(len(summaries) == 1 and summaries[0].get('flags_verified') is True and
             summaries[0].get('shadow_knowledge_valid') is True and
             all(type(summaries[0].get(name)) is int and summaries[0][name] == 0
                 for name in ('trace_dropped', 'trace_incomplete')),
             'Full Phase 1 smoke flag or trace collection was incomplete')
    _require(all(event.get('incomplete_reasons') == ['empty_capture'] for event in events
                 if event['event_type'] == 'error'), 'Full Phase 1 smoke reported an unexpected error')
    terminal = events[-1].get('data', {})
    _require(terminal.get('storage_status') == 'ok' and type(terminal.get('dropped_events')) is int and
             terminal['dropped_events'] == 0, 'Full Phase 1 smoke did not commit its artifacts')
    return {'status': 'PASS_FULL_PHASE1_PLUGIN_FLAGS_LOAD', 'guest_exit': 0,
            'stdout_sha256': _pin(out / 'stdout')['sha256'], 'phase1': phase,
            'flags_verified': True, 'command': command}


def calibrate_flags(*, qemu, qemu_include, plugin, out):
    """Grant a receipt only after fresh PUSHFL checks and full-plugin loading.

    These are controlled native smoke runs, without namespaces or cgroup claims.
    The receipt binds only the exact QEMU and bounded i386 observation contract.
    """
    qemu, plugin, include, out = (_path(path) for path in (qemu, plugin, qemu_include, out))
    _require(include.is_dir(), 'QEMU include directory does not exist')
    _require(not out.exists() and not out.is_symlink(), 'Calibration output must be new')
    sources = {'qemu': _pin(qemu, 512 * 1024**2), 'plugin': _pin(plugin, 512 * 1024**2),
        'runtime_manifest': _pin(Path(str(plugin) + '.runtime.json')),
        'header': _pin(include / 'qemu-plugin.h'),
        'compat': _pin(PROJECT / 'unpacker/test/qemu_plugin_compat.h'),
        'observer_source': _pin(PROJECT / 'unpacker/mvp/fixtures/core_flags_observer.c'),
        'guest_source': _pin(PROJECT / 'unpacker/mvp/fixtures/core_flags32.S'),
        'probe_source': _pin(PROJECT / 'unpacker/mvp/check_runtime_flags.py'),
        'runtime_source': _pin(Path(__file__)),
        'phase1_source': _pin(PROJECT / 'taintforge_env/phase1_runtime.py')}
    _require(all(not Path(item['path']).is_relative_to(out) and not out.is_relative_to(Path(item['path']))
                 for item in sources.values()), 'Calibration output overlaps one of its inputs')
    _require(all(',' not in str(path) and '\n' not in str(path) for path in (plugin, out)),
             'Calibration plugin argument paths contain commas or newlines')
    runtime = Phase1Runtime.load(plugin)
    runtime.validate_qemu(qemu)
    manifest = read_json(runtime.manifest)
    api = re.findall(r'^\s*#\s*define\s+QEMU_PLUGIN_VERSION\s+(\d+)\s*$',
                     (include / 'qemu-plugin.h').read_text(), re.MULTILINE)
    _require(len(api) == 1 and int(api[0]) == runtime.plugin_api and
             manifest['build_inputs'].get('qemu_header_sha256') == sources['header']['sha256'],
             'The Phase 1 plugin and selected QEMU SDK header differ')
    out.mkdir(parents=True)
    receipt = out / 'flags/flags.receipt'
    summary = {'schema_version': 1, 'status': 'FAILED_X86_FLAGS_RUNTIME',
        'scope': 'bounded_i386_flags_calibration_and_full_plugin_smoke', 'sources': sources,
        'qemu': str(qemu), 'qemu_sha256': sources['qemu']['sha256'], 'plugin': str(plugin),
        'runtime_manifest': str(runtime.manifest), 'qemu_include': str(include),
        'plugin_api': runtime.plugin_api, 'bounded_probe_only': True,
        'guest_isolation_verified': False, 'hostile_sample_ready': False, 'universal_equivalence': False}
    limits = {'qemu': 512 * 1024**2, 'plugin': 512 * 1024**2}
    try:
        summary['build'] = _build_tools(sources, out / 'tools')
        observer, binary = out / 'tools/flags-observer.so', out / 'tools/core_flags32.elf'
        artifacts = {'observer': _pin(observer), 'binary': _pin(binary)}
        result = _run_probe(qemu, observer, binary, out / 'flags')
        _require(result == read_json(out / 'flags/summary.json') and
                 result.get('status') == 'PASS_QEMU_PUSHF_BOUNDARY_PROBE' and
                 result.get('qemu_sha256') == sources['qemu']['sha256'] and
                 result.get('artifacts_unchanged') is True and set(result.get('runs', {})) == {'normal', 'single'} and
                 all(row.get('valid') is True and type(row.get('checked')) is int and row['checked'] == 32 and
                     type(row.get('exit')) is int and row['exit'] == 0 and row.get('mismatches') == []
                     for row in result['runs'].values()), 'Exact QEMU PUSHFL calibration failed')
        expected = ('TAINTFORGE_X86_FLAGS_V1\nqemu_sha256=' + sources['qemu']['sha256'] +
            '\nprobe=pushf-boundary-v1\ntarget=i386-linux-user\nnormal_checked=32\n'
            'single_checked=32\nmismatches=0\n').encode()
        receipt_identity = _pin(receipt, 4096)
        _require(receipt.read_bytes() == expected and result.get('receipt_sha256') == receipt_identity['sha256'],
                 'Flags receipt differs from the checked exact-binary result')
        expected_stdout = (out / 'flags/normal.stdout').read_bytes()
        summary['full_plugin_smoke'] = _phase1_smoke(qemu, runtime, binary, receipt,
                                                    out / 'full-plugin-smoke', expected_stdout)
        for role, identity in sources.items():
            _require(_pin(identity['path'], limits.get(role, MAX_ARTIFACT)) == identity,
                     'Calibration input changed before publication: ' + role)
        for identity in summary['build']['toolchain'].values():
            _require(_pin(identity['path'], 512 * 1024**2, private=False) == identity, 'Calibration build tool changed')
        for identity in artifacts.values():
            _require(_pin(identity['path']) == identity, 'Calibration native artifact changed')
        _require(_pin(receipt, 4096) == receipt_identity, 'Flags receipt changed during full-plugin smoke')
        summary.update(status='READY_X86_FLAGS_RUNTIME', native_probe=result, artifacts=artifacts,
            flags_receipt=str(receipt), flags_receipt_sha256=receipt_identity['sha256'])
        return summary
    except BaseException as exc:
        receipt.unlink(missing_ok=True)
        summary['error'] = f'{type(exc).__name__}: {exc}'
        raise
    finally:
        _save(out / 'summary.json', summary)
