"""Bounded file inversion with fresh isolated solve and concrete rerun cases."""
from __future__ import annotations

import hashlib
from pathlib import Path

from . import capsule_hardening, capsule_resources, dta_capsule
from .afl_file import atomic_json, create_guest_file
from .concolic_environment import register_file, validate_file_observation, verify_file_rerun
from .concolic_file import _integer
from .dta_analysis import _arguments
from .dta_corpus import _canonical, _limit, _pin, _require
from .elf_runtime import canonical_hash, provision_guest
from .environment_snapshot import EnvironmentSnapshotStore
from .input_retirement import inspect_input
from .phase1_runtime import Phase1Run, Phase1Runtime, read_json
from .unified_runtime import build_bundle, check_runtime_inputs, verify_bundle


PROJECT = Path(__file__).resolve().parents[1]
PROFILE = 'dse-file-analysis-v1'
MAX_EVIDENCE_BYTES = 16 * 1024**2
INVERSION_SCOPE = 'one_file_one_read_bounded_branch_inversion'
OBSERVATION_SCOPE = 'one_file_one_read_bounded_prefix_observation'
SOURCE_LIMITS = {'seed': 4096, 'binary': 64 * 1024**2, 'qemu': 512 * 1024**2,
                 'plugin': 512 * 1024**2, 'runtime_manifest': 16 * 1024**2, 'flags_receipt': 4096}


def _json(path, maximum=1024 * 1024):
    path, identity = _pin(path, maximum)
    value = read_json(path, maximum=maximum)
    _require(_pin(path, maximum)[1] == identity, 'DSE evidence changed while reading')
    return value, identity


def _case_evidence(*, directory, returned, raw, binary_sha256, input_path, argv,
                   snapshots, snapshot, bundle, bundle_sha256, flags_sha256,
                   mode, branch_pc, occurrence, max_steps, offsets, seconds, memory_mib,
                   expected=None):
    """Reopen the case evidence; a returned ``passed`` dictionary is insufficient."""
    receipt, receipt_identity = _json(directory / 'receipt.json')
    _require(receipt == returned, 'Returned DSE receipt differs from its saved evidence')
    binding_path = directory / 'config/dta_binding.json'
    binding, binding_identity = _json(binding_path)
    expected_concolic = {'mode': mode, 'branch_pc': branch_pc, 'occurrence': occurrence,
        'max_steps': max_steps, 'offsets': list(offsets), 'flags_receipt_sha256': flags_sha256}
    raw_sha256 = hashlib.sha256(raw).hexdigest()
    _require(type(receipt.get('schema')) is int and receipt['schema'] == 1 and receipt.get('profile') == PROFILE and
             receipt.get('status') == 'passed' and
             type(receipt.get('guest_exit')) is int and 0 <= receipt['guest_exit'] < 128 and
             receipt.get('protected_control_channel') is False and receipt.get('hostile_sample_ready') is False and
             receipt.get('scope') == 'selected_concolic_file_prefix',
             'DSE case is not a completed supported isolated execution')
    _require(type(binding.get('schema')) is int and binding['schema'] == 1 and binding.get('profile') == PROFILE and
             binding.get('attempt_contract_sha256') == dta_capsule._contract(binding) and
             receipt.get('request_sha256') == binding['attempt_contract_sha256'] and
             binding.get('run_dir') == str(directory) and binding.get('rootfs') == str(directory / 'rootfs') and
             binding.get('project') == str(PROJECT) and binding.get('bundle') == str(bundle) and
             binding.get('bundle_sha256') == bundle_sha256 and
             binding.get('snapshot_store') == str(snapshots.store_dir) and
             binding.get('snapshot_id') == snapshot.snapshot_id and
             binding.get('snapshot_tree_sha256') == snapshot.tree_sha256 and
             binding.get('input_path') == input_path and binding.get('input_size') == len(raw) and
             binding.get('input_sha256') == raw_sha256 and binding.get('target_sha256') == binary_sha256 and
             binding.get('argv') == argv and binding.get('seconds') == seconds and
             binding.get('concolic') == expected_concolic,
             'DSE request is not bound to the selected source, snapshot, branch and budgets')
    _require(receipt.get('input_path') == input_path and receipt.get('input_sha256') == raw_sha256 and
             receipt.get('target_sha256') == binary_sha256 and
             receipt.get('flags_receipt_sha256') == flags_sha256,
             'DSE receipt source or flags binding mismatch')
    _require(binding.get('settings', {}).get('resources') == capsule_resources.policy(memory_mib, seconds + 20),
             'DSE case resource policy differs from its requested budget')
    hardening = capsule_hardening.config(binding)
    _require(hardening == capsule_hardening.policy(analysis_mib=memory_mib // 2,
             export_mib=16, journal_mib=16), 'DSE case hardening policy differs from its requested budget')
    dta_capsule._verify(binding, binding_path)
    manifest = verify_bundle(bundle, bundle_sha256)
    resources = capsule_resources.verify_saved(binding, receipt['guest_exit'])
    _require(receipt.get('resources') == resources and resources.get('status') == 'verified' and
             resources.get('tree_empty') is True, 'DSE case lacks verified service and cleanup evidence')

    namespaces, namespaces_identity = _json(directory / 'logs/capsule/namespaces.json', 16384)
    observed, host = namespaces.get('namespaces'), binding.get('host_namespaces')
    _require(type(namespaces.get('schema')) is int and namespaces['schema'] == 1 and namespaces.get('profile') == PROFILE and
             namespaces.get('request_sha256') == binding['attempt_contract_sha256'] and
             isinstance(host, dict) and namespaces.get('host_namespaces') == host and
             isinstance(observed, dict) and set(observed) == set(host) == set(dta_capsule.NAMESPACES) and
             all(isinstance(observed[name], str) and observed[name] and
                 isinstance(host[name], str) and observed[name] != host[name] for name in observed),
             'DSE namespace identities are missing or do not establish separation')
    isolation = receipt.get('isolation', {})
    interpreter = binding.get('qemu_interpreter')
    _require(isinstance(interpreter, str) and interpreter.startswith('/') and
             all(isolation.get(key) is True for key in
                 ('mount_namespace', 'pid_namespace', 'network_namespace', 'chroot', 'direct_qemu')) and
             isolation.get('network') == 'none' and isolation.get('execution_uid') == 65534 and
             isolation.get('capabilities') == 'dropped' and isolation.get('cpu_seconds') == seconds and
             isolation.get('service_wall_seconds') == seconds + 20 and
             isolation.get('per_file_limit_bytes') == MAX_EVIDENCE_BYTES and
             isolation.get('observed_namespaces') == observed and
             isolation.get('kernel_interpreter') == interpreter,
             'DSE case lacks the direct-QEMU namespace isolation evidence')

    control, control_identity = _pin(directory / 'controls/flags.receipt', 4096)
    _require(control_identity['sha256'] == flags_sha256, 'DSE case flags receipt changed')
    phase_ids = binding.get('phase1', {})
    runtime = Phase1Runtime.load(bundle / manifest['plugin'])
    analysis = Phase1Run(runtime, phase_ids['session_id'], phase_ids['attempt_id'],
        phase_ids['analysis_instance_id'], directory / 'logs/phase1', require_flags=True, flags_receipt=control)
    phase = dta_capsule.verify_dse_diagnostics(analysis)
    _require(receipt.get('phase1') == phase and phase.get('runtime_observed') is True and
             phase.get('artifact_integrity') == 'verified' and phase.get('flags_verified') is True and
             phase.get('concolic_prefix_collection') is True,
             'DSE case lacks complete flags and Phase 1 artifact evidence')
    for key, filename in (('input', 'input.bin'), ('trace', 'logs/trace.log'),
                          ('stdout', 'logs/runtime_stdout.log')):
        path, identity = _pin(directory / filename, MAX_EVIDENCE_BYTES)
        _require(receipt.get(key) == str(path) and receipt.get(key + '_sha256') == identity['sha256'],
                 f'DSE case {key} artifact changed or escaped its case')
    report_path = directory / 'logs/phase1/concolic.json'
    native, native_identity = _json(report_path)
    _require(receipt.get('concolic_report') == str(report_path) and
             receipt.get('concolic_report_sha256') == native_identity['sha256'] and
             type(native.get('schema')) is int and native['schema'] == 2 and
             (native.get('status') == 'UNKNOWN' or native.get('flags_verified') is True) and
             receipt.get('dse_status') == native.get('status') and
             native.get('status') in (('BOUNDARY_WITNESS', 'UNSAT', 'UNKNOWN') if mode == 'solve'
                                      else ('OBSERVED', 'UNKNOWN')),
             'DSE native report is unbound or has an unsupported status')
    evidence = {'case': str(directory.name), 'mode': mode, 'guest_exit': receipt['guest_exit'],
        'input_sha256': raw_sha256, 'target_sha256': binary_sha256,
        'flags_receipt_sha256': flags_sha256, 'request_sha256': receipt['request_sha256'],
        'receipt_sha256': receipt_identity['sha256'], 'binding_sha256': binding_identity['sha256'],
        'namespaces_sha256': namespaces_identity['sha256'],
        'concolic_report': str(report_path), 'concolic_report_sha256': native_identity['sha256'],
        'dse_status': native['status'], 'resources': resources, 'isolation': isolation}
    _require(expected is None or evidence == expected, 'DSE case evidence changed before publication')
    return native, evidence


def _parameters(*, input_path, branch_pc, offsets, occurrence, max_steps, argv, seconds, memory_mib):
    _limit(seconds, 120, 'case seconds')
    _require(type(memory_mib) is int and 256 <= memory_mib <= 4096, 'Invalid DSE memory budget')
    _require(_integer(branch_pc, 0xffffffff) and _integer(occurrence, 1024) and occurrence and
             _integer(max_steps, 1024) and max_steps, 'Invalid DSE branch or prefix budget')
    _require(isinstance(offsets, (list, tuple)) and 1 <= len(offsets) <= 16 and
             all(_integer(offset, 4095) for offset in offsets) and
             list(offsets) == sorted(set(offsets)), 'Select 1..16 distinct, increasing file offsets')
    offsets, argv = list(offsets), _arguments(argv)
    dta_capsule._concolic_path(input_path)
    return offsets, argv


def _initial_report(*, inputs, input_path, branch_pc, offsets, occurrence, max_steps,
                    argv, seconds, memory_mib, observation):
    return {'schema': 1, 'status': 'failed', 'profile': PROFILE, 'dse_status': 'UNKNOWN',
        'scope': OBSERVATION_SCOPE if observation else INVERSION_SCOPE, 'dse_adapter_isolated': False,
        'protected_control_channel': False, 'universal_equivalence': False,
        'afl_campaign_executed': False, 'successor_execution_proven': False,
        'input_path': input_path, 'argv': argv, 'branch_pc': branch_pc, 'occurrence': occurrence,
        'offsets': offsets, 'max_steps': max_steps, 'accepted_seed_count': 0, 'accepted': [],
        'concrete_runs': 0, 'runs': [], 'inputs': inputs,
        'budgets': {'case_cpu_seconds': seconds, 'memory_mib': memory_mib}}


def _candidate_bytes(baseline, source, raw, branch_pc, occurrence, max_steps):
    validate_file_observation(baseline, source, raw, branch_pc, occurrence, max_steps)
    changed, changes = bytearray(raw), []
    for row in baseline['bindings']:
        offset, value = row['offset'], row['candidate']
        if value != raw[offset]:
            changes.append({'offset': offset, 'before': raw[offset], 'after': value})
        changed[offset] = value
    _require(changes, 'DSE witness does not change any selected byte')
    return bytes(changed), changes


def _verified_fields(*, baseline, rerun, source, raw, candidate, changes,
                     branch_pc, occurrence, max_steps, binary_sha256, flags_sha256, runs):
    edge = verify_file_rerun(baseline, rerun, source, raw, candidate, branch_pc, occurrence, max_steps)
    candidate_sha256 = hashlib.sha256(candidate).hexdigest()
    edge.update(binary_sha256=binary_sha256, seed_sha256=source.sha256,
        candidate_sha256=candidate_sha256, seed_snapshot_id=source.snapshot_id,
        seed_tree_sha256=source.tree_sha256, flags_receipt_sha256=flags_sha256,
        reports={run['concolic_report']: run['concolic_report_sha256'] for run in runs})
    return {'dse_status': 'VERIFIED', 'reason': 'prefix_preserved_branch_inverted',
        'changes': changes, 'candidate_sha256': candidate_sha256,
        'observed_edge': edge, 'successor_boundary_observed': True}


def _observed_fields(native, source, raw, branch_pc, occurrence, max_steps):
    if native['status'] == 'OBSERVED':
        validate_file_observation(native, source, raw, branch_pc, occurrence, max_steps)
        return {'dse_status': 'OBSERVED', 'reason': 'bounded_prefix_observed',
                'successor_boundary_observed': True}
    _require(native['status'] == 'UNKNOWN', 'Observe case produced an unsupported result')
    return {'dse_status': 'UNKNOWN', 'reason': native.get('reason', 'baseline_unknown')}


def _run_file(*, binary, qemu, plugin, seed, input_path, branch_pc, flags_receipt,
              out, offsets, occurrence, max_steps, argv, seconds, memory_mib, observation):
    offsets, argv = _parameters(input_path=input_path, branch_pc=branch_pc, offsets=offsets,
        occurrence=occurrence, max_steps=max_steps, argv=argv, seconds=seconds, memory_mib=memory_mib)
    seed, seed_identity = _pin(seed, 4096)
    _require(seed_identity['size'] > 0 and offsets[-1] < seed_identity['size'],
             'DSE offsets must select existing bytes in a nonempty seed')
    binary, binary_identity = _pin(binary, 64 * 1024**2)
    inspect_input(binary)
    qemu, qemu_identity = _pin(qemu, 512 * 1024**2)
    plugin, plugin_identity = _pin(plugin, 512 * 1024**2)
    sidecar, sidecar_identity = _pin(Path(str(plugin) + '.runtime.json'), 16 * 1024**2)
    flags_receipt, flags_identity = _pin(flags_receipt, 4096)
    check_runtime_inputs(PROJECT, qemu=qemu, plugin=plugin)
    sources = [(seed, seed_identity, 4096), (binary, binary_identity, 64 * 1024**2),
        (qemu, qemu_identity, 512 * 1024**2), (plugin, plugin_identity, 512 * 1024**2),
        (sidecar, sidecar_identity, 16 * 1024**2), (flags_receipt, flags_identity, 4096)]
    out = _canonical(out)
    _require(not out.exists() and all(not path.is_relative_to(out) and not out.is_relative_to(path)
             for path, _, _ in sources), 'DSE output must be new and outside its inputs')
    raw = seed.read_bytes()
    _require(hashlib.sha256(raw).hexdigest() == seed_identity['sha256'], 'DSE seed changed before capture')
    out.mkdir(parents=True)
    report = _initial_report(inputs={'seed': seed_identity, 'binary': binary_identity, 'qemu': qemu_identity,
        'plugin': plugin_identity, 'runtime_manifest': sidecar_identity, 'flags_receipt': flags_identity},
        input_path=input_path, branch_pc=branch_pc, offsets=offsets, occurrence=occurrence,
        max_steps=max_steps, argv=argv, seconds=seconds, memory_mib=memory_mib, observation=observation)
    try:
        runtime = build_bundle(out / 'runtime', qemu=qemu, plugin=plugin)
        rootfs = out / 'template-rootfs'
        for name in ('proc', 'dev', 'sys', 'tmp', 'bin', 'etc'):
            (rootfs / name).mkdir(parents=True, exist_ok=True)
        (rootfs / 'tmp').chmod(0o1777)
        provision_guest(binary, rootfs, sysroot=Path('/'), binary_guest_path='/bin/sample.elf')
        create_guest_file(rootfs, input_path, raw)
        snapshots = EnvironmentSnapshotStore(out / 'snapshots')
        snapshot = snapshots.capture(rootfs).manifest
        source = register_file(snapshots, snapshot.snapshot_id, input_path, offsets, binary_identity['sha256'])
        _require(source.sha256 == seed_identity['sha256'], 'Registered DSE seed identity changed')
        report.update(snapshot={'snapshot_id': snapshot.snapshot_id, 'tree_sha256': snapshot.tree_sha256},
                      resource=source.to_dict(), bundle_sha256=runtime['bundle_sha256'])

        def intact():
            _require(snapshots.verify(snapshot.snapshot_id).tree_sha256 == snapshot.tree_sha256,
                     'DSE original snapshot changed')
            verify_bundle(out / 'runtime', runtime['bundle_sha256'])
            for path, identity, maximum in sources:
                _require(_pin(path, maximum)[1] == identity, f'DSE source changed: {path}')

        cases = []

        def execute(mode, data):
            intact()
            directory = out / mode
            receipt = dta_capsule.run_case(project=PROJECT, bundle=out / 'runtime',
                bundle_sha256=runtime['bundle_sha256'], store=snapshots.store_dir,
                snapshot_id=snapshot.snapshot_id, input_path=input_path, data=data, argv=argv,
                out=directory, seconds=seconds, memory_mib=memory_mib,
                concolic={'mode': mode, 'branch_pc': branch_pc, 'occurrence': occurrence,
                    'max_steps': max_steps, 'offsets': offsets, 'flags_receipt': flags_receipt})
            arguments = dict(directory=directory, returned=receipt, raw=data,
                binary_sha256=binary_identity['sha256'], input_path=input_path, argv=argv,
                snapshots=snapshots, snapshot=snapshot, bundle=out / 'runtime',
                bundle_sha256=runtime['bundle_sha256'], flags_sha256=flags_identity['sha256'],
                mode=mode, branch_pc=branch_pc, occurrence=occurrence, max_steps=max_steps,
                offsets=offsets, seconds=seconds, memory_mib=memory_mib)
            native, evidence = _case_evidence(**arguments)
            cases.append((arguments, evidence))
            report['runs'].append(evidence)
            report['concrete_runs'] = len(cases)
            intact()
            return native

        baseline = execute('observe' if observation else 'solve', raw)
        report['baseline'] = baseline['status']
        candidate = None
        if observation:
            report.update(_observed_fields(baseline, source, raw, branch_pc, occurrence, max_steps))
        elif baseline['status'] == 'UNSAT':
            validate_file_observation(baseline, source, raw, branch_pc, occurrence, max_steps)
            report.update(dse_status='UNSAT', reason='no_witness_in_selected_model')
        elif baseline['status'] == 'UNKNOWN':
            report.update(dse_status='UNKNOWN', reason=baseline.get('reason', 'baseline_unknown'))
        else:
            candidate, changes = _candidate_bytes(baseline, source, raw, branch_pc, occurrence, max_steps)
            rerun = execute('observe', candidate)
            report.update(_verified_fields(baseline=baseline, rerun=rerun, source=source, raw=raw,
                candidate=candidate, changes=changes, branch_pc=branch_pc, occurrence=occurrence,
                max_steps=max_steps, binary_sha256=binary_identity['sha256'],
                flags_sha256=flags_identity['sha256'], runs=report['runs']))

        intact()
        for arguments, evidence in cases:
            _case_evidence(**arguments, expected=evidence)
        intact()
        if observation:
            _require(len(cases) == 1, 'DSE observation must have exactly one fresh case')
            report['dse_adapter_isolated'] = True
        if report['dse_status'] == 'VERIFIED':
            _require(len(cases) == 2 and candidate is not None, 'DSE verified rerun evidence is missing')
            pending = out / '.accepted-seeds.pending'
            pending.mkdir()
            destination = pending / report['candidate_sha256']
            destination.write_bytes(candidate)
            _require(_pin(destination, 4096)[1]['sha256'] == report['candidate_sha256'],
                     'DSE accepted seed changed while publishing')
            pending.rename(out / 'accepted-seeds')
            report.update(dse_adapter_isolated=True, accepted_seed_count=1,
                accepted=[{'sha256': report['candidate_sha256'], 'case': 'observe'}])
        report.update(status='passed', concrete_runs=len(cases), original_inputs_unchanged=True,
                      baseline_snapshot_unchanged=True, input_execution_binding='fresh_snapshot_bound_launch')
        return report
    except Exception as exc:
        report.update(status='failed', dse_status='UNKNOWN', dse_adapter_isolated=False,
                      successor_execution_proven=False, error=f'{type(exc).__name__}: {exc}')
        raise
    finally:
        atomic_json(out / 'summary.json', report)


def invert_file(*, binary, qemu, plugin, seed, input_path, branch_pc, flags_receipt,
                out, offsets, occurrence=1, max_steps=128, argv=(), seconds=30, memory_mib=1024):
    """Invert one selected file-dependent branch and publish only a verified rerun."""
    return _run_file(binary=binary, qemu=qemu, plugin=plugin, seed=seed, input_path=input_path,
        branch_pc=branch_pc, flags_receipt=flags_receipt, out=out, offsets=offsets,
        occurrence=occurrence, max_steps=max_steps, argv=argv, seconds=seconds,
        memory_mib=memory_mib, observation=False)


def observe_file(*, binary, qemu, plugin, seed, input_path, branch_pc, flags_receipt,
                 out, offsets, occurrence=1, max_steps=128, argv=(), seconds=30, memory_mib=1024):
    """Collect one complete file prefix in a fresh capsule without invoking inversion.

    An inconclusive native result remains UNKNOWN. Neither outcome publishes a
    candidate or proves execution beyond the observed successor boundary.
    """
    return _run_file(binary=binary, qemu=qemu, plugin=plugin, seed=seed, input_path=input_path,
        branch_pc=branch_pc, flags_receipt=flags_receipt, out=out, offsets=offsets,
        occurrence=occurrence, max_steps=max_steps, argv=argv, seconds=seconds,
        memory_mib=memory_mib, observation=True)


def audit_file_run(*, directory):
    """Revalidate a saved observation or inversion without executing any guest.

    All original input paths must still exist with their pinned contents. The
    returned value is the exact saved summary, admitted only after rebuilding
    its claims from the snapshot, case evidence and native prefix validators.
    """
    directory = _canonical(directory)
    summary_path = directory / 'summary.json'
    summary, summary_identity = _json(summary_path)
    _require(type(summary.get('schema')) is int and summary['schema'] == 1 and
             summary.get('profile') == PROFILE and summary.get('status') == 'passed' and
             summary.get('scope') in (INVERSION_SCOPE, OBSERVATION_SCOPE),
             'Saved DSE run has an unsupported summary schema, profile, scope or status')
    observation = summary['scope'] == OBSERVATION_SCOPE
    _require(summary.get('dse_status') in (('OBSERVED', 'UNKNOWN') if observation
                                           else ('VERIFIED', 'UNSAT', 'UNKNOWN')),
             'Saved DSE run has an unsupported result for its scope')
    budgets = summary['budgets']
    parameters = {key: summary[key] for key in
        ('input_path', 'branch_pc', 'offsets', 'occurrence', 'max_steps', 'argv')}
    parameters.update(seconds=budgets['case_cpu_seconds'], memory_mib=budgets['memory_mib'])
    offsets, argv = _parameters(**parameters)
    parameters.update(offsets=offsets, argv=argv)
    inputs = summary.get('inputs')
    _require(isinstance(inputs, dict) and set(inputs) == set(SOURCE_LIMITS),
             'Saved DSE run lacks its exact source inventory')
    pinned, paths = {}, {}
    for name, maximum in SOURCE_LIMITS.items():
        identity = inputs[name]
        _require(isinstance(identity, dict) and set(identity) == {'path', 'sha256', 'size'} and
                 isinstance(identity['path'], str) and type(identity['size']) is int,
                 'Saved DSE source identity is malformed')
        paths[name], pinned[name] = _pin(identity['path'], maximum)
        _require(pinned[name] == identity, f'Saved DSE source changed: {name}')
        _require(not paths[name].is_relative_to(directory) and not directory.is_relative_to(paths[name]),
                 'Saved DSE source overlaps its output directory')
    _require(paths['runtime_manifest'] == Path(str(paths['plugin']) + '.runtime.json'),
             'Saved DSE runtime manifest is not the selected plugin sidecar')
    raw = paths['seed'].read_bytes()
    _require(raw and offsets[-1] < len(raw) and hashlib.sha256(raw).hexdigest() == pinned['seed']['sha256'],
             'Saved DSE seed or selected offsets changed')
    inspect_input(paths['binary'])
    check_runtime_inputs(PROJECT, qemu=paths['qemu'], plugin=paths['plugin'])
    manifest = verify_bundle(directory / 'runtime', summary['bundle_sha256'])
    inventory = {item['path']: item for item in manifest['files']}
    _require(Path(manifest['plugin']).name == paths['plugin'].name and
             inventory[manifest['qemu']]['sha256'] == pinned['qemu']['sha256'] and
             inventory[manifest['plugin']]['sha256'] == pinned['plugin']['sha256'] and
             inventory[manifest['plugin'] + '.runtime.json']['sha256'] == pinned['runtime_manifest']['sha256'],
             'Saved DSE runtime bundle differs from its pinned sources')
    snapshots = EnvironmentSnapshotStore(_canonical(directory / 'snapshots'))
    snapshot = snapshots.verify(summary['snapshot']['snapshot_id'])
    source = register_file(snapshots, snapshot.snapshot_id, parameters['input_path'], offsets,
                           pinned['binary']['sha256'])
    _require(source.sha256 == pinned['seed']['sha256'] and source.size == len(raw),
             'Saved DSE snapshot input differs from its pinned seed')
    target = next((entry for entry in snapshot.entries if entry.path == '/bin/sample.elf'), None)
    _require(target is not None and target.type == 'file' and target.hardlink_group is None and
             target.sha256 == pinned['binary']['sha256'] and target.size == pinned['binary']['size'],
             'Saved DSE snapshot target differs from its pinned executable')
    expected = _initial_report(inputs=pinned, **parameters, observation=observation)
    expected.update(snapshot={'snapshot_id': snapshot.snapshot_id, 'tree_sha256': snapshot.tree_sha256},
                    resource=source.to_dict(), bundle_sha256=manifest['bundle_sha256'])
    runs = summary.get('runs')
    _require(isinstance(runs, list) and len(runs) == (2 if summary['dse_status'] == 'VERIFIED' else 1),
             'Saved DSE run has an unexpected case inventory')
    audited = []

    def case(mode, data):
        index = len(expected['runs'])
        receipt, _ = _json(directory / mode / 'receipt.json')
        arguments = dict(directory=directory / mode, returned=receipt, raw=data,
            binary_sha256=pinned['binary']['sha256'], snapshots=snapshots, snapshot=snapshot,
            bundle=directory / 'runtime', bundle_sha256=manifest['bundle_sha256'],
            flags_sha256=pinned['flags_receipt']['sha256'], mode=mode, **parameters)
        native, evidence = _case_evidence(**arguments, expected=runs[index])
        audited.append((arguments, evidence))
        expected['runs'].append(evidence)
        return native

    baseline = case('observe' if observation else 'solve', raw)
    expected['baseline'] = baseline['status']
    candidate = None
    if observation:
        expected.update(_observed_fields(baseline, source, raw, parameters['branch_pc'],
                                         parameters['occurrence'], parameters['max_steps']))
        expected['dse_adapter_isolated'] = True
    elif baseline['status'] == 'UNSAT':
        validate_file_observation(baseline, source, raw, parameters['branch_pc'],
                                  parameters['occurrence'], parameters['max_steps'])
        expected.update(dse_status='UNSAT', reason='no_witness_in_selected_model')
    elif baseline['status'] == 'UNKNOWN':
        expected.update(dse_status='UNKNOWN', reason=baseline.get('reason', 'baseline_unknown'))
    else:
        candidate, changes = _candidate_bytes(baseline, source, raw, parameters['branch_pc'],
                                              parameters['occurrence'], parameters['max_steps'])
        rerun = case('observe', candidate)
        expected.update(_verified_fields(baseline=baseline, rerun=rerun, source=source, raw=raw,
            candidate=candidate, changes=changes, branch_pc=parameters['branch_pc'],
            occurrence=parameters['occurrence'], max_steps=parameters['max_steps'],
            binary_sha256=pinned['binary']['sha256'], flags_sha256=pinned['flags_receipt']['sha256'],
            runs=expected['runs']))
        expected.update(dse_adapter_isolated=True, accepted_seed_count=1,
            accepted=[{'sha256': expected['candidate_sha256'], 'case': 'observe'}])
    publication = directory / 'accepted-seeds'
    pending = directory / '.accepted-seeds.pending'

    def publication_intact():
        _require(not pending.exists() and not pending.is_symlink(), 'Saved DSE run contains an unfinished publication')
        if candidate is None:
            _require(not publication.exists() and not publication.is_symlink(),
                     'Saved DSE run published a seed without a verified inversion')
            unused = directory / ('solve' if observation else 'observe')
            _require(not unused.exists() and not unused.is_symlink(),
                     'Saved DSE run contains an unexpected case')
        else:
            _canonical(publication)
            _require(publication.is_dir() and sorted(path.name for path in publication.iterdir()) ==
                     [expected['candidate_sha256']], 'Saved DSE accepted seed inventory changed')
            accepted, accepted_identity = _pin(publication / expected['candidate_sha256'], 4096)
            _require(accepted_identity['sha256'] == expected['candidate_sha256'] and accepted.read_bytes() == candidate,
                     'Saved DSE accepted seed differs from the validated model and concrete rerun')

    publication_intact()
    expected.update(status='passed', concrete_runs=len(expected['runs']), original_inputs_unchanged=True,
                    baseline_snapshot_unchanged=True, input_execution_binding='fresh_snapshot_bound_launch')
    _require(canonical_hash(summary) == canonical_hash(expected),
             'Saved DSE summary differs from its independently revalidated evidence')
    _require(snapshots.verify(snapshot.snapshot_id).tree_sha256 == snapshot.tree_sha256,
             'Saved DSE snapshot changed during audit')
    verify_bundle(directory / 'runtime', manifest['bundle_sha256'])
    for name, maximum in SOURCE_LIMITS.items():
        _require(_pin(paths[name], maximum)[1] == pinned[name], f'Saved DSE source changed during audit: {name}')
    for arguments, evidence in audited:
        _case_evidence(**arguments, expected=evidence)
    publication_intact()
    _require(_pin(summary_path, 1024 * 1024)[1] == summary_identity, 'Saved DSE summary changed during audit')
    return summary
