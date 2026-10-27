"""Fresh, resource-bounded file DTA cases with no retirement or solver."""
from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import resource
import stat
import subprocess
import sys
from uuid import uuid4

from . import afl_file, capsule_hardening, capsule_resources
from .elf_runtime import canonical_hash
from .elf_target import inspect_elf_target
from .environment_snapshot import EnvironmentSnapshotStore
from .phase1_runtime import Phase1Run, Phase1Runtime, digest, read_json
from .prebuilt_runner import SubprocessCommandExecutor
from .unified_runtime import verify_bundle, write_json

PROFILE = 'dta-file-analysis-v1'
DSE_PROFILE = 'dse-file-analysis-v1'
MAX_LOG_BYTES = 16 * 1024**2
NAMESPACES = ('mnt', 'pid', 'net', 'uts', 'ipc')


def _require(value, message):
    if not value:
        raise RuntimeError(message)


def _path(value):
    path = Path(value).expanduser().absolute()
    _require('..' not in path.parts and path != Path('/'), 'Invalid DTA capsule path')
    for parent in (path, *path.parents):
        _require(not parent.is_symlink(), 'Symlink in DTA capsule path')
    return path


def _argv(value):
    _require(isinstance(value, (list, tuple)) and len(value) <= 32 and
             all(isinstance(item, str) and '\0' not in item for item in value) and
             sum(len(item.encode()) + 1 for item in value) <= 16384, 'Invalid bounded guest argv')
    return list(value)


def _contract(binding):
    return canonical_hash({key: value for key, value in binding.items()
                           if key != 'attempt_contract_sha256'})


def verify_dta_diagnostics(analysis):
    """Accept bounded data hints without promoting global flags or OEP capture."""
    phase = analysis.verify()
    events = analysis.events()
    _require(phase['runtime_observed'] is True and phase['stream_status'] in ('completed', 'partial'),
             'DTA Phase 1 observation is missing or unfinished')
    _require(not any(event['event_type'] in ('profile_lost', 'data_loss') for event in events),
             'DTA execution profile or event stream was lost')
    capabilities = events[0].get('data', {})
    _require(capabilities.get('ir_enabled') is False and
             capabilities.get('profile') == 'linux-i386-single-thread-v1' and
             not any(event['event_type'] == 'runtime_observation' and
                     event.get('status') in ('partial', 'error', 'unsupported') for event in events),
             'DTA observation does not satisfy its bounded runtime profile')
    summaries = [event['data'] for event in events if event['event_type'] == 'analysis_summary']
    _require(len(summaries) == 1 and all(type(summaries[0].get(key)) is int and
             summaries[0][key] == 0 for key in ('trace_dropped', 'trace_incomplete')) and
             summaries[0].get('shadow_knowledge_valid') is True and
             type(summaries[0].get('flags_verified')) is bool,
             'DTA trace or shadow knowledge is incomplete')
    _require(phase['stream_status'] != 'partial' or summaries[0]['flags_verified'] is False,
             'DTA runtime has unexplained partial analysis')
    errors = [event for event in events if event['event_type'] == 'error']
    _require(all(event.get('incomplete_reasons') == ['empty_capture'] for event in errors),
             'DTA runtime reported an unexpected error')
    terminal = events[-1].get('data', {})
    _require(terminal.get('storage_status') == 'ok' and type(terminal.get('dropped_events')) is int and
             terminal['dropped_events'] == 0,
             'DTA diagnostics were not fully stored')
    return phase | {'dta_diagnostics_accepted': True,
        'flags_verified': summaries[0].get('flags_verified') is True,
        'oep_capture_required': False, 'diagnostic_scope': 'selected_complete_file_data_roots'}


def verify_dse_diagnostics(analysis):
    """Preserve global statuses; admit only complete, flag-checked collection."""
    phase, events = analysis.verify(), analysis.events()
    capabilities = events[0].get('data', {})
    _require(phase['runtime_observed'] is True and phase['stream_status'] in ('completed', 'partial') and
             capabilities.get('ir_enabled') is True and capabilities.get('profile') == 'linux-i386-single-thread-v1' and
             capabilities.get('flags_contract') == 'taintforge_x86_flags_v1', 'DSE runtime/flags profile was not observed')
    _require(not any(event['event_type'] in ('profile_lost', 'data_loss') or
             event['event_type'] == 'runtime_observation' and event.get('status') in ('partial', 'error', 'unsupported')
             for event in events), 'DSE execution profile or observation was lost')
    summaries = [event['data'] for event in events if event['event_type'] == 'analysis_summary']
    _require(len(summaries) == 1 and summaries[0].get('flags_verified') is True and
             summaries[0].get('shadow_knowledge_valid') is True and
             type(summaries[0].get('trace_dropped')) is int and summaries[0]['trace_dropped'] == 0 and
             type(summaries[0].get('trace_incomplete')) is int and 0 <= summaries[0]['trace_incomplete'] < 1 << 64,
             'DSE trace/shadow/flag observations are incomplete')
    _require(all(event.get('incomplete_reasons') == ['empty_capture'] for event in events if event['event_type'] == 'error'),
             'DSE runtime reported an unexpected error')
    terminal = events[-1].get('data', {})
    _require(terminal.get('storage_status') == 'ok' and type(terminal.get('dropped_events')) is int and
             terminal['dropped_events'] == 0, 'DSE output storage is incomplete')
    return phase | {'flags_verified': True, 'concolic_prefix_collection': True,
                    'global_trace_incomplete': summaries[0]['trace_incomplete'],
                    'prefix_completeness_requires_native_report': True,
                    'oep_capture_required': False, 'diagnostic_scope': 'selected_concolic_file_prefix'}


def _concolic_spec(value, size):
    _require(isinstance(value, dict) and set(value) == {'mode', 'branch_pc', 'occurrence', 'max_steps',
             'offsets', 'flags_receipt_sha256'}, 'Invalid concolic request inventory')
    _require(value['mode'] in ('solve', 'observe') and type(value['branch_pc']) is int and
             0 <= value['branch_pc'] <= 0xffffffff and type(value['occurrence']) is int and
             1 <= value['occurrence'] <= 1024 and type(value['max_steps']) is int and
             1 <= value['max_steps'] <= 1024, 'Invalid concolic selector or prefix budget')
    offsets = value['offsets']
    _require(isinstance(offsets, list) and 1 <= len(offsets) <= 16 and
             all(type(offset) is int and 0 <= offset < size for offset in offsets) and
             offsets == sorted(set(offsets)), 'Invalid concolic file offsets')
    sha = value['flags_receipt_sha256']
    _require(isinstance(sha, str) and len(sha) == 64 and all(char in '0123456789abcdef' for char in sha),
             'Invalid flags receipt identity')
    return value


def _check_flags(raw, qemu_sha256):
    expected = ('TAINTFORGE_X86_FLAGS_V1\nqemu_sha256=' + qemu_sha256 +
        '\nprobe=pushf-boundary-v1\ntarget=i386-linux-user\nnormal_checked=32\nsingle_checked=32\nmismatches=0\n').encode()
    _require(raw == expected, 'Flags receipt does not describe the selected QEMU and complete calibration')


def _concolic_path(value):
    from .concolic_environment import _guest_path
    _guest_path(value)
    _require(Path(value).parts[1] != '__taintforge_dse' and value not in
             ('/bin/sample.elf', '/etc/ld.so.preload', '/etc/ld.so.cache'), 'DSE input overlaps runtime controls')
    return value


def _interpreter(bundle, manifest):
    path = inspect_elf_target(bundle / manifest['qemu']).interpreter
    _require(path in ('/lib64/ld-linux-x86-64.so.2', '/lib/ld-linux.so.2'), 'Unsupported direct-QEMU kernel interpreter')
    return path


def _concolic_argument(analysis, manifest, input_path, spec):
    _require(analysis.require_flags is True and analysis.flags_receipt is not None, 'DSE requires a flags-bound Phase 1 run')
    argument = analysis.plugin_argument(ir=True, diagnostic_roots=True, extra=('runtime-log=roots', 'dse-check=off', 'tf-capture=exit',
        'tf-max-capture-bytes=1048576', 'ir-trace-capacity=16384', 'tf-max-events=4096',
        'ir-flat-memory=on', 'ir-ssa=on'))
    options = argument.split(',')
    options[0] = '/__taintforge/' + manifest['plugin']
    options = ['x86-flags-receipt=/__taintforge_dse/flags.receipt' if option.startswith('x86-flags-receipt=') else option
               for option in options]
    options += [f'concolic-report={analysis.directory / "concolic.json"}',
        f'concolic-branch={spec["branch_pc"]}', f'concolic-occurrence={spec["occurrence"]}',
        f'concolic-max-steps={spec["max_steps"]}', f'concolic-mode={spec["mode"]}',
        f'concolic-file={input_path}', f'concolic-seed={input_path}',
        'concolic-offsets=' + ':'.join(str(offset) for offset in spec['offsets'])]
    return ','.join(options)


def _verify_concolic_argument(binding, runtime, manifest):
    run = Path(binding['run_dir'])
    analysis = Phase1Run(runtime, **binding['phase1'], directory=run / 'logs/phase1', require_flags=True)
    spec = binding['concolic']
    options = binding['plugin_argument'].split(',')
    _require(options[0] == '/__taintforge/' + manifest['plugin'] and
             all('=' in option for option in options[1:]), 'DSE plugin identity or options changed')
    pairs = [option.split('=', 1) for option in options[1:]]
    values = dict(pairs)
    _require(len(values) == len(pairs), 'Duplicate DSE runtime option')
    expected = {'tf-session-id': analysis.session_id, 'tf-attempt-id': analysis.attempt_id,
        'tf-instance-id': analysis.analysis_instance_id, 'tf-require-flags': 'on',
        'x86-flags-receipt': '/__taintforge_dse/flags.receipt', 'ir-check': 'on',
        'runtime-log': 'roots', 'dse-check': 'off', 'tf-capture': 'exit',
        'tf-max-capture-bytes': '1048576', 'ir-trace-capacity': '16384', 'tf-max-events': '4096',
        'ir-flat-memory': 'on', 'ir-ssa': 'on', 'concolic-report': str(analysis.directory / 'concolic.json'),
        'concolic-branch': str(spec['branch_pc']), 'concolic-occurrence': str(spec['occurrence']),
        'concolic-max-steps': str(spec['max_steps']), 'concolic-mode': spec['mode'],
        'concolic-file': binding['input_path'], 'concolic-seed': binding['input_path'],
        'concolic-offsets': ':'.join(str(offset) for offset in spec['offsets']),
        'm4-memory-bytes': str(capsule_hardening.config(binding)['analysis_bytes'])}
    expected.update({f"tf-{'ir-report' if key == 'ir' else key}": str(path) for key, path in analysis.paths.items()})
    _require(values == expected, 'DSE runtime options differ from their bounded request')


def _verify(binding, binding_path=None):
    _require(type(binding.get('schema')) is int and binding['schema'] == 1 and binding.get('profile') in (PROFILE, DSE_PROFILE) and
             binding.get('attempt_contract_sha256') == _contract(binding), 'DTA request identity changed')
    run, root, bundle = (_path(binding[key]) for key in ('run_dir', 'rootfs', 'bundle'))
    _require(root == run / 'rootfs' and root.is_dir() and not bundle.is_relative_to(root),
             'DTA rootfs or analyzer path escaped its case')
    if binding_path is not None:
        _require(_path(binding_path) == run / 'config/dta_binding.json', 'DTA binding path changed')
    _argv(binding['argv'])
    capsule_resources.validate(binding['settings']['resources'])
    capsule_hardening.config(binding)
    _require(type(binding['seconds']) is int and 1 <= binding['seconds'] <= 120,
             'Invalid DTA execution deadline')
    manifest = verify_bundle(bundle, binding['bundle_sha256'])
    target = afl_file.guest_file(root, '/bin/sample.elf')
    _require(digest(target) == binding['target_sha256'], 'DTA target changed')
    source = afl_file.guest_file(root, binding['input_path'])
    _require(source.stat().st_size == binding['input_size'] and
             digest(source) == binding['input_sha256'], 'DTA input changed')
    if binding['profile'] == DSE_PROFILE:
        capsule_resources.unit_name(binding)
        nonce = binding['lifecycle_attempt']
        _require(binding['attempt_id'] == 'case-' + nonce and binding['phase1'] == {
            'session_id': 'dta-' + nonce, 'attempt_id': 'case-' + nonce,
            'analysis_instance_id': 'analysis-' + nonce}, 'DSE runtime identities do not match their case')
        _concolic_path(binding['input_path'])
        _require(all(not (root / name).exists() and not (root / name).is_symlink()
                     for name in ('etc/ld.so.preload', 'etc/ld.so.cache')), 'DSE rootfs overrides native loader controls')
        spec = _concolic_spec(binding['concolic'], binding['input_size'])
        flags = _path(run / 'controls/flags.receipt')
        _require(flags.is_file() and flags.stat().st_nlink == 1 and flags.stat().st_size <= 4096 and
                 digest(flags) == spec['flags_receipt_sha256'], 'DSE flags control changed')
        _check_flags(flags.read_bytes(), digest(bundle / manifest['qemu']))
        _require(binding['qemu_interpreter'] == _interpreter(bundle, manifest), 'DSE kernel interpreter changed')
        placeholder = afl_file.guest_file(root, binding['qemu_interpreter'])
        _require(placeholder.stat().st_size == 0, 'DSE interpreter placeholder changed')
        _require(sorted(path.name for path in (run / 'controls').iterdir()) == ['flags.receipt'], 'DSE controls inventory changed')
        _verify_concolic_argument(binding, Phase1Runtime.load(bundle / manifest['plugin']), manifest)
    return run, root, bundle, manifest


def run_case(*, project, bundle, bundle_sha256, store, snapshot_id, input_path, data,
             argv, out, seconds=10, memory_mib=1024, concolic=None):
    """Run one case; failure leaves a failed receipt and never returns accepted data."""
    _require(type(seconds) is int and 1 <= seconds <= 120 and type(memory_mib) is int and
             256 <= memory_mib <= 65536, 'Invalid DTA case resource budgets')
    _require(isinstance(data, bytes) and 1 <= len(data) <= 4096, 'DTA seed must contain 1..4096 bytes')
    argv = _argv(argv)
    afl_file.validate_guest_path(input_path)
    _require(input_path != '/bin/sample.elf', 'DTA input cannot be the executable')
    project, bundle, store, out = (_path(path) for path in (project, bundle, store, out))
    _require(not out.exists() and not out.is_relative_to(bundle) and
             not bundle.is_relative_to(out) and not out.is_relative_to(store) and
             not store.is_relative_to(out), 'DTA case output must be new and outside its inputs')
    manifest = verify_bundle(bundle, bundle_sha256)
    spec, flags_raw, flags_source = None, None, None
    if concolic is not None:
        _concolic_path(input_path)
        _require(isinstance(concolic, dict) and
                 set(concolic) == {'mode', 'branch_pc', 'occurrence', 'max_steps', 'offsets', 'flags_receipt'},
                 'Invalid isolated DSE request')
        flags_source = _path(concolic['flags_receipt'])
        info = flags_source.lstat()
        _require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= 4096, 'Invalid flags source')
        flags_raw = flags_source.read_bytes()
        _check_flags(flags_raw, digest(bundle / manifest['qemu']))
        spec = _concolic_spec({key: value for key, value in concolic.items() if key != 'flags_receipt'} |
            {'flags_receipt_sha256': hashlib.sha256(flags_raw).hexdigest()}, len(data))
    for directory, names, files in os.walk(bundle, followlinks=False):
        Path(directory).chmod(0o555)
        for name in files:
            path = Path(directory) / name
            path.chmod(0o555 if path.stat().st_mode & 0o111 else 0o444)
    verify_bundle(bundle, bundle_sha256)
    snapshots = EnvironmentSnapshotStore(store)
    snapshot = snapshots.verify(snapshot_id)
    capsule_resources.preflight()
    out.mkdir(parents=True, exist_ok=False)
    (out / 'config').mkdir()
    (out / 'logs/capsule').mkdir(parents=True)
    profile = DSE_PROFILE if spec else PROFILE
    receipt = {'schema': 1, 'profile': profile, 'status': 'failed',
               'scope': 'selected_concolic_file_prefix' if spec else 'fresh_file_input_DTA_diagnostics_not_proof', 'dse_status': 'NOT_RUN',
               'protected_control_channel': False, 'hostile_sample_ready': False}
    binding = None
    try:
        root = out / 'rootfs'
        snapshots.clone(snapshot_id, root)
        selected = afl_file.guest_file(root, input_path)
        mode = stat.S_IMODE(selected.stat().st_mode)
        selected.chmod(mode | 0o200)
        selected.write_bytes(data)
        selected.chmod(mode)
        seed = out / 'input.bin'
        seed.write_bytes(data)
        seed.chmod(0o400)
        flags_copy = None
        if spec:
            controls = out / 'controls'
            controls.mkdir(mode=0o755)
            flags_copy = controls / 'flags.receipt'
            flags_copy.write_bytes(flags_raw)
            flags_copy.chmod(0o444)
            controls.chmod(0o555)
            _require(not (root / '__taintforge_dse').exists() and not (root / '__taintforge_dse').is_symlink(),
                     'DSE control mount hides an existing guest resource')
            afl_file.create_guest_file(root, _interpreter(bundle, manifest), b'')
        nonce = uuid4().hex
        runtime = Phase1Runtime.load(bundle / manifest['plugin'])
        analysis = Phase1Run(runtime, 'dta-' + nonce, 'case-' + nonce,
                             'analysis-' + nonce, out / 'logs/phase1', require_flags=spec is not None, flags_receipt=flags_copy)
        if spec:
            argument = _concolic_argument(analysis, manifest, input_path, spec)
        else:
            argument = analysis.plugin_argument(ir=False, diagnostic_roots=True, extra=(
                'runtime-log=roots', 'dse-check=off', 'tf-capture=exit',
                'tf-max-capture-bytes=1048576', 'ir-trace-capacity=16384', 'tf-max-events=4096'))
            argument = '/__taintforge/' + manifest['plugin'] + ',' + argument.partition(',')[2]
        hardening = capsule_hardening.policy(analysis_mib=memory_mib // 2,
                                             export_mib=16, journal_mib=16)
        argument += ',m4-memory-bytes=' + str(hardening['analysis_bytes'])
        binding = {'schema': 1, 'profile': profile, 'run_dir': str(out), 'rootfs': str(root),
            'project': str(project), 'bundle': str(bundle), 'bundle_sha256': bundle_sha256,
            'snapshot_store': str(store), 'snapshot_id': snapshot.snapshot_id,
            'snapshot_tree_sha256': snapshot.tree_sha256, 'argv': argv, 'seconds': seconds,
            'input_path': input_path, 'input_size': len(data),
            'input_sha256': hashlib.sha256(data).hexdigest(),
            'target_sha256': digest(root / 'bin/sample.elf'),
            'attempt_id': 'case-' + nonce, 'lifecycle_attempt': nonce,
            'plugin_argument': argument, 'phase1': {'session_id': analysis.session_id,
                'attempt_id': analysis.attempt_id, 'analysis_instance_id': analysis.analysis_instance_id},
            'host_namespaces': {name: os.readlink('/proc/self/ns/' + name) for name in NAMESPACES},
            'settings': {'resources': capsule_resources.policy(memory_mib, seconds + 20),
                'hardening': hardening}}
        if spec:
            binding.update(concolic=spec, qemu_interpreter=_interpreter(bundle, manifest))
        binding['attempt_contract_sha256'] = _contract(binding)
        binding_path = out / 'config/dta_binding.json'
        write_json(binding_path, binding)
        write_json(out / 'config/phase1_binding.json', {'output_directory': str(analysis.directory)})
        _verify(binding, binding_path)
        command = ['sudo', 'unshare', '--mount', '--pid', '--fork', '--uts', '--ipc', '--net', '--',
            'env', 'PYTHONPATH=' + str(project), sys.executable, '-m', 'taintforge_env.dta_capsule',
            'launch', '--binding', str(binding_path)]
        executor = SubprocessCommandExecutor()
        try:
            result = capsule_resources.execute(binding, command, executor, cwd=project, check=False,
                stdout_path=out / 'logs/runtime_stdout.log', stderr_path=out / 'logs/trace.log')
        finally:
            executor.run(['sudo', 'chown', '-R', '--no-dereference', '--',
                          f'{os.getuid()}:{os.getgid()}', str(out)], cwd=project, check=True)
        receipt['guest_exit'] = result.returncode
        _require(0 <= result.returncode < 128, 'DTA case stopped abnormally; inspect logs/trace.log')
        resources = capsule_resources.verify_saved(binding, result.returncode)
        namespaces = read_json(out / 'logs/capsule/namespaces.json', maximum=16384)
        _require(type(namespaces.get('schema')) is int and namespaces['schema'] == 1 and
                 namespaces.get('profile') == profile and namespaces.get('request_sha256') == binding['attempt_contract_sha256'] and
                 namespaces.get('host_namespaces') == binding['host_namespaces'] and
                 isinstance(namespaces.get('namespaces'), dict) and
                 set(namespaces['namespaces']) == set(NAMESPACES) and
                 all(isinstance(namespaces['namespaces'][name], str) and
                     namespaces['namespaces'][name] != binding['host_namespaces'][name]
                     for name in NAMESPACES), 'DTA namespace separation was not observed')
        phase = verify_dse_diagnostics(analysis) if spec else verify_dta_diagnostics(analysis)
        _verify(binding, binding_path)
        _require(snapshots.verify(snapshot_id).tree_sha256 == snapshot.tree_sha256,
                 'DTA source snapshot changed')
        _require(digest(seed) == binding['input_sha256'], 'DTA immutable seed changed')
        if spec:
            _require(digest(flags_source) == spec['flags_receipt_sha256'], 'DSE original flags receipt changed')
            report_path = analysis.directory / 'concolic.json'
            native = read_json(report_path, maximum=1024**2)
            _require(native.get('status') in ('UNKNOWN', 'UNSAT', 'BOUNDARY_WITNESS', 'OBSERVED'), 'Invalid native concolic status')
            receipt.update(dse_status=native['status'], concolic_report=str(report_path),
                concolic_report_sha256=digest(report_path), flags_receipt_sha256=spec['flags_receipt_sha256'])
        total = 0
        for path in (out / 'logs').rglob('*'):
            info = path.lstat()
            if stat.S_ISDIR(info.st_mode):
                continue
            _require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1,
                     'DTA diagnostics contain an unsafe file or alias')
            total += info.st_size
        _require(total <= MAX_LOG_BYTES, 'DTA aggregate diagnostic byte budget exceeded')
        trace, stdout = out / 'logs/trace.log', out / 'logs/runtime_stdout.log'
        receipt.update(status='passed', trace=str(trace), stdout=str(stdout), input=str(seed),
            input_path=input_path, input_sha256=binding['input_sha256'], target_sha256=binding['target_sha256'],
            trace_sha256=digest(trace), stdout_sha256=digest(stdout), phase1=phase, resources=resources,
            request_sha256=binding['attempt_contract_sha256'],
            isolation={'mount_namespace': True, 'pid_namespace': True, 'network_namespace': True,
                'network': 'none', 'chroot': True, 'execution_uid': 65534, 'capabilities': 'dropped',
                'cpu_seconds': seconds, 'service_wall_seconds': seconds + 20,
                'per_file_limit_bytes': MAX_LOG_BYTES, 'observed_namespaces': namespaces['namespaces']})
        if spec:
            receipt['isolation'].update(direct_qemu=True, kernel_interpreter=binding['qemu_interpreter'])
        return receipt
    except Exception as exc:
        receipt['error'] = f'{type(exc).__name__}: {exc}'
        raise
    finally:
        write_json(out / 'receipt.json', receipt)


def launch(binding_path):
    """Privileged namespace entry; the target is executed after credential drop."""
    _require(os.geteuid() == 0, 'DTA namespace setup requires the privileged wrapper')
    binding = read_json(binding_path, maximum=1024 * 1024)
    run, root, bundle, manifest = _verify(binding, binding_path)
    capsule_resources.inspect_self(binding)
    namespaces = {name: os.readlink('/proc/self/ns/' + name) for name in NAMESPACES}
    _require(set(binding['host_namespaces']) == set(NAMESPACES) and
             all(namespaces[name] != binding['host_namespaces'][name] for name in NAMESPACES),
             'DTA launcher did not enter fresh namespaces')
    write_json(run / 'logs/capsule/namespaces.json', {
        'schema': 1, 'profile': binding['profile'], 'request_sha256': binding['attempt_contract_sha256'],
        'host_namespaces': binding['host_namespaces'], 'namespaces': namespaces})
    with Path('/dev/null').open('rb') as null:
        os.dup2(null.fileno(), 0)
    subprocess.run(['mount', '--make-rprivate', '/'], check=True)
    direct = binding['profile'] == DSE_PROFILE
    for name in ('proc', '__taintforge', *(('__taintforge_dse',) if direct else ())):
        path = root / name
        _require(not path.is_symlink() and (not path.exists() or path.is_dir() and not any(path.iterdir())),
                 'DTA runtime mount hides a guest resource')
        path.mkdir(exist_ok=True)
    (root / 'proc').chmod(0o555)
    subprocess.run(['mount', '-t', 'proc', '-o', 'ro,nosuid,nodev,noexec', 'proc', str(root / 'proc')], check=True)
    subprocess.run(['mount', '--bind', str(bundle), str(root / '__taintforge')], check=True)
    subprocess.run(['mount', '-o', 'remount,bind,ro,nosuid,nodev', str(root / '__taintforge')], check=True)
    if direct:
        subprocess.run(['mount', '--bind', str(run / 'controls'), str(root / '__taintforge_dse')], check=True)
        subprocess.run(['mount', '-o', 'remount,bind,ro,nosuid,nodev', str(root / '__taintforge_dse')], check=True)
    phase = run / 'logs/phase1'
    current = root
    for part in phase.parts[1:]:
        current /= part
        _require(not current.is_symlink() and (not current.exists() or current.is_dir()),
                 'DTA output mount traverses an unsafe guest path')
    _require(not current.exists(), 'DTA output mount hides an existing guest directory')
    current.mkdir(parents=True)
    uid, gid = capsule_hardening.config(binding)['uid'], capsule_hardening.config(binding)['gid']
    for directory, names, files in os.walk(root, followlinks=False):
        if Path(directory) == root:
            names[:] = [name for name in names if name not in ('proc', '__taintforge', *(('__taintforge_dse',) if direct else ()))]
        os.chown(directory, uid, gid, follow_symlinks=False)
        for name in names + files:
            os.chown(Path(directory) / name, uid, gid, follow_symlinks=False)
    os.chown(phase, uid, gid)
    phase.chmod(0o700)
    subprocess.run(['mount', '--bind', str(phase), str(current)], check=True)
    resource.setrlimit(resource.RLIMIT_CPU, (binding['seconds'], binding['seconds'] + 1))
    if direct:
        destination = root / binding['qemu_interpreter'].lstrip('/')
        for source, target in ((bundle / manifest['loader'], destination),
                               (afl_file.guest_file(root, binding['input_path']), afl_file.guest_file(root, binding['input_path'])),
                               (root / 'bin/sample.elf', root / 'bin/sample.elf')):
            subprocess.run(['mount', '--bind', str(source), str(target)], check=True)
            subprocess.run(['mount', '-o', 'remount,bind,ro,nosuid,nodev', str(target)], check=True)
        _require(digest(destination) == digest(bundle / manifest['loader']), 'Mounted kernel interpreter changed')
        command = ['/__taintforge/bin/qemu-i386', '-U', 'LD_LIBRARY_PATH', '-L', '/', '-plugin', binding['plugin_argument'],
                   '/bin/sample.elf', *binding['argv']]
        capsule_hardening.launch(binding, command, direct_qemu=True)
    else:
        command = ['/__taintforge/bin/loader', '--inhibit-cache', '--library-path', '/__taintforge/lib',
            '/__taintforge/bin/qemu-i386', '-L', '/', '-plugin', binding['plugin_argument'],
            '/bin/sample.elf', *binding['argv']]
        capsule_hardening.launch(binding, command)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('launch',))
    parser.add_argument('--binding', type=Path, required=True)
    args = parser.parse_args()
    launch(args.binding)


if __name__ == '__main__':
    main()
