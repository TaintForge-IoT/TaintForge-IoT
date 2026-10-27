"""Audit a completed DTA worker run and export seeds plus non-executable hints.

This is an offline consistency audit. It neither repeats historical isolation
measurements nor supplies the exact instruction/IR selectors required by DSE.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import shutil
import stat
import tempfile

from . import capsule_hardening, capsule_resources
from .afl_file import guest_file, validate_guest_path
from .dta_capsule import NAMESPACES, PROFILE, _contract, verify_dta_diagnostics
from .dta_corpus import _canonical, _limit, _pin, _require, generate_corpus, parse_trace
from .elf_runtime import canonical_hash
from .environment_snapshot import EnvironmentSnapshotStore
from .phase1_runtime import Phase1Run, Phase1Runtime
from .unified_runtime import verify_bundle


def _pairs(items):
    result = {}
    for key, value in items:
        _require(key not in result, 'Duplicate JSON key in DTA evidence')
        result[key] = value
    return result


def _equal(left, right, message):
    _require(canonical_hash(left) == canonical_hash(right), message)


def export_handoff(*, analysis, out, max_sites=256):
    """Read original Stage 2 paths, recheck receipts, publish only after auditing."""
    _limit(max_sites, 4096, 'handoff sites')
    analysis, out = _canonical(analysis), _canonical(out)
    _require(analysis.is_dir() and not out.exists() and not out.is_relative_to(analysis) and
             not analysis.is_relative_to(out), 'Handoff output must be new and outside the analysis')
    inventory = {}

    def pin(path, maximum):
        path, identity = _pin(path, maximum)
        _require(path.is_relative_to(analysis), 'DTA evidence escaped the analysis directory')
        name = path.relative_to(analysis).as_posix()
        if name in inventory:
            _equal(inventory[name], identity, 'DTA evidence changed during audit')
        else:
            inventory[name] = identity
        return path, identity

    def read(path, maximum=1024 * 1024):
        path, identity = pin(path, maximum)
        raw = path.read_bytes()
        _require(hashlib.sha256(raw).hexdigest() == identity['sha256'], 'DTA JSON changed during audit')
        def nonfinite(value):
            raise ValueError('Non-finite JSON number: ' + value)
        value = json.loads(raw, object_pairs_hook=_pairs, parse_constant=nonfinite)
        _require(isinstance(value, dict), 'Expected a DTA evidence object')
        return value

    report = read(analysis / 'summary.json', 4 * 1024**2)
    _require(type(report.get('schema')) is int and report['schema'] == 1 and
             report.get('status') == 'passed' and report.get('profile') == PROFILE and
             report.get('dse_status') == 'NOT_RUN' and report.get('afl_campaign_executed') is False and
             report.get('protected_diagnostic_channel') is False and
             report.get('universal_equivalence') is False and
             report.get('novelty_scope') == 'observed_diagnostic_branch_outcomes' and
             report.get('input_execution_binding') == 'fresh_snapshot_bound_launch' and
             report.get('original_inputs_unchanged') is True and
             report.get('baseline_snapshot_unchanged') is True,
             'DTA run is failed, unsupported or has promoted its scope')
    input_path, argv = report['input_path'], report['argv']
    validate_guest_path(input_path)
    _require(isinstance(argv, list) and len(argv) <= 32 and
             all(isinstance(arg, str) and '\0' not in arg and len(arg.encode()) <= 4096 for arg in argv) and
             sum(len(arg.encode()) + 1 for arg in argv) <= 16384, 'Invalid recorded argv')
    budgets = report['budgets']
    _limit(budgets['max_candidates'], 128, 'recorded candidates')
    _limit(budgets['case_cpu_seconds'], 120, 'recorded case time')
    _require(type(budgets['memory_mib']) is int and 256 <= budgets['memory_mib'] <= 4096,
             'Invalid recorded memory budget')
    store = EnvironmentSnapshotStore(analysis / 'snapshots')
    _require(isinstance(report['snapshot']['snapshot_id'], str) and
             re.fullmatch('env_[0-9a-f]{16}', report['snapshot']['snapshot_id']), 'Invalid snapshot selector')
    read(store.store_dir / report['snapshot']['snapshot_id'] / 'manifest.json', 16 * 1024**2)
    snapshot = store.verify(report['snapshot']['snapshot_id'])
    _equal(report['snapshot'], {'snapshot_id': snapshot.snapshot_id, 'tree_sha256': snapshot.tree_sha256},
           'DTA snapshot identity changed')
    snapshot_root = store.store_dir / snapshot.snapshot_id / 'rootfs'
    target, target_identity = pin(guest_file(snapshot_root, '/bin/sample.elf'), 64 * 1024**2)
    seed, seed_identity = pin(guest_file(snapshot_root, input_path), 4096)
    _require(seed_identity['size'] > 0, 'DTA seed is empty')
    for name, identity in (('seed', seed_identity), ('binary', target_identity)):
        _equal({key: report['inputs'][name][key] for key in ('sha256', 'size')},
               {key: identity[key] for key in ('sha256', 'size')}, 'DTA source identity mismatch')
    # Verify both the runtime inventory and its original source identities.
    bundle = verify_bundle(analysis / 'runtime')
    for item in bundle['files']:
        pin(analysis / 'runtime' / item['path'], 512 * 1024**2)
    read(analysis / 'runtime/bundle.json')
    runtime = Phase1Runtime.load(analysis / 'runtime' / bundle['plugin'])
    for role, path in (('qemu', analysis / 'runtime' / bundle['qemu']),
                       ('plugin', runtime.plugin), ('runtime_manifest', runtime.manifest)):
        _, identity = pin(path, 512 * 1024**2)
        _equal({key: report['inputs'][role][key] for key in ('sha256', 'size')},
               {key: identity[key] for key in ('sha256', 'size')}, 'DTA runtime source changed')
    seed_data = seed.read_bytes()
    corpus = read(analysis / 'corpus/manifest.json', 4 * 1024**2)
    baseline_trace = analysis / 'baseline/logs/trace.log'
    # Recreate the deterministic plan instead of trusting changed groups/counts.
    with tempfile.TemporaryDirectory(prefix='tf-dta-plan-audit-') as temporary:
        regenerated = generate_corpus(seed=seed, binary=target, trace=baseline_trace,
            input_path=input_path, out=Path(temporary) / 'corpus',
            max_candidates=budgets['max_candidates'])
        _equal({key: value for key, value in corpus.items() if key != 'inputs'},
               {key: value for key, value in regenerated.items() if key != 'inputs'},
               'Recorded corpus differs from the deterministic source-derived plan')
        for role in ('seed', 'binary', 'trace'):
            _equal({key: corpus['inputs'][role][key] for key in ('sha256', 'size')},
                   {key: regenerated['inputs'][role][key] for key in ('sha256', 'size')},
                   'Corpus source binding changed')
        candidates = corpus['candidates']
        expected_names = {candidate['sha256'] for candidate in candidates}
        _equal(sorted(path.name for path in (analysis / 'corpus/seeds').iterdir()),
               sorted(expected_names), 'Unexpected corpus seed inventory')
        for candidate in candidates:
            path, identity = pin(analysis / 'corpus/seeds' / candidate['sha256'], 4096)
            _require(identity['sha256'] == candidate['sha256'] and
                     path.read_bytes() == (Path(temporary) / 'corpus/seeds' / path.name).read_bytes(),
                     'Corpus candidate bytes changed')

    names = ['baseline', 'repeat'] + [f'replays/{i:04d}' for i, c in enumerate(candidates) if not c['baseline']]
    _equal(sorted(path.name for path in (analysis / 'replays').iterdir()),
           sorted(Path(name).name for name in names[2:]), 'Unexpected DTA replay inventory')
    rows = report['runs']
    _require(isinstance(rows, list) and [row.get('case') for row in rows] == names,
             'DTA cases are incomplete, reordered or duplicated')
    raw_cases = [seed_data, seed_data] + [(analysis / 'corpus/seeds' / c['sha256']).read_bytes()
                                        for c in candidates if not c['baseline']]
    audited = []
    nonces = set()
    for name, raw, row in zip(names, raw_cases, rows):
        directory = analysis / name
        receipt = read(directory / 'receipt.json')
        binding = read(directory / 'config/dta_binding.json')
        _require(type(binding.get('schema')) is int and binding['schema'] == 1 and
                 binding.get('profile') == PROFILE and
                 binding.get('attempt_contract_sha256') == _contract(binding) == receipt.get('request_sha256'),
                 'DTA request binding changed')
        nonce = binding['lifecycle_attempt']
        _require(isinstance(nonce, str) and re.fullmatch('[0-9a-f]{32}', nonce) and nonce not in nonces,
                 'DTA cases reused their execution identity')
        nonces.add(nonce)
        _equal(binding['phase1'], {'session_id': 'dta-' + nonce, 'attempt_id': 'case-' + nonce,
                                  'analysis_instance_id': 'analysis-' + nonce}, 'Phase 1 request identities changed')
        _require(binding['attempt_id'] == 'case-' + nonce and binding['run_dir'] == str(directory) and
                 binding['rootfs'] == str(directory / 'rootfs') and
                 binding['bundle'] == str(analysis / 'runtime') and binding['bundle_sha256'] == bundle['bundle_sha256'] and
                 binding['snapshot_store'] == str(store.store_dir) and binding['snapshot_id'] == snapshot.snapshot_id and
                 binding['snapshot_tree_sha256'] == snapshot.tree_sha256 and
                 binding['input_path'] == input_path and binding['target_sha256'] == target_identity['sha256'],
                 'DTA case no longer describes the source environment')
        _equal(binding['argv'], argv, 'DTA argv changed')
        _require(type(binding['seconds']) is int and 1 <= binding['seconds'] <= budgets['case_cpu_seconds'],
                 'Invalid recorded case CPU limit')
        _equal(binding['settings']['resources'], capsule_resources.policy(budgets['memory_mib'], binding['seconds'] + 20),
               'DTA case resource policy changed')
        hardening = capsule_hardening.policy(analysis_mib=budgets['memory_mib'] // 2, export_mib=16, journal_mib=16)
        _equal(binding['settings']['hardening'], hardening, 'DTA case hardening policy changed')
        data_path, data_identity = pin(directory / 'input.bin', 4096)
        _require(data_path.read_bytes() == raw and binding['input_sha256'] == data_identity['sha256'] and
                 type(binding['input_size']) is int and binding['input_size'] == len(raw), 'DTA case input changed')
        for guest_path, expected in (('/bin/sample.elf', target_identity['sha256']), (input_path, data_identity['sha256'])):
            _, identity = pin(guest_file(directory / 'rootfs', guest_path), 64 * 1024**2)
            _require(identity['sha256'] == expected, 'Saved executed target/input changed')
        _require(receipt.get('status') == 'passed' and receipt.get('profile') == PROFILE and
                 receipt.get('scope') == 'fresh_file_input_DTA_diagnostics_not_proof' and
                 receipt.get('dse_status') == 'NOT_RUN' and receipt.get('protected_control_channel') is False and
                 receipt.get('hostile_sample_ready') is False and type(receipt.get('guest_exit')) is int and
                 0 <= receipt['guest_exit'] < 128, 'DTA receipt is failed or has promoted its scope')
        for key, value in (('input', str(data_path)), ('input_path', input_path),
                           ('input_sha256', data_identity['sha256']), ('target_sha256', target_identity['sha256'])):
            _require(receipt.get(key) == value, 'DTA receipt source identity changed')
        for filename in ('resources.json', 'service.json'):
            read(directory / 'logs/capsule' / filename)
        resources = capsule_resources.verify_saved(binding, receipt['guest_exit'])
        _equal(resources, receipt['resources'], 'Recorded resource receipt changed')
        namespaces = read(directory / 'logs/capsule/namespaces.json')
        _require(type(namespaces.get('schema')) is int and namespaces['schema'] == 1 and namespaces.get('profile') == PROFILE and
                 namespaces.get('request_sha256') == binding['attempt_contract_sha256'], 'Namespace request changed')
        _equal(namespaces['host_namespaces'], binding['host_namespaces'], 'Host namespace binding changed')
        _require(set(namespaces['namespaces']) == set(NAMESPACES) == set(binding['host_namespaces']) and
                 all(isinstance(namespaces['namespaces'][key], str) and
                     namespaces['namespaces'][key] != binding['host_namespaces'][key] for key in NAMESPACES),
                 'Namespace separation record is incomplete')
        _equal(receipt['isolation'], {'mount_namespace': True, 'pid_namespace': True, 'network_namespace': True,
            'network': 'none', 'chroot': True, 'execution_uid': 65534, 'capabilities': 'dropped',
            'cpu_seconds': binding['seconds'], 'service_wall_seconds': binding['seconds'] + 20,
            'per_file_limit_bytes': 16 * 1024**2, 'observed_namespaces': namespaces['namespaces']},
            'Namespace/isolation receipt changed')
        phase = Phase1Run(runtime, **binding['phase1'], directory=directory / 'logs/phase1')
        _equal(read(directory / 'config/phase1_binding.json'), {'output_directory': str(phase.directory)},
               'Phase 1 output binding changed')
        options = ['/__taintforge/' + bundle['plugin'],
            f'tf-session-id={phase.session_id}', f'tf-attempt-id={phase.attempt_id}',
            f'tf-instance-id={phase.analysis_instance_id}', 'tf-require-flags=off']
        options += [f"tf-{'ir-report' if key == 'ir' else key}={path}" for key, path in phase.paths.items()]
        options += ['ir-check=off', 'runtime-log=roots', 'dse-check=off', 'tf-capture=exit',
                    'tf-max-capture-bytes=1048576', 'ir-trace-capacity=16384', 'tf-max-events=4096',
                    'm4-memory-bytes=' + str(hardening['analysis_bytes'])]
        _require(binding['plugin_argument'] == ','.join(options), 'DTA collection profile changed')
        for path in (directory / 'logs/phase1').iterdir():
            pin(path, 16 * 1024**2)
            if path.suffix == '.json':
                read(path, 16 * 1024**2)
        phase_summary = verify_dta_diagnostics(phase)
        _equal(receipt['phase1'], phase_summary, 'Recorded Phase 1 diagnostic admission changed')
        log_bytes = 0
        for path in (directory / 'logs').rglob('*'):
            info = path.lstat()
            if stat.S_ISDIR(info.st_mode):
                continue
            _, identity = pin(path, 16 * 1024**2)
            log_bytes += identity['size']
        _require(log_bytes <= 16 * 1024**2, 'DTA aggregate log budget changed')
        trace, trace_identity = pin(directory / 'logs/trace.log', 16 * 1024**2)
        stdout, stdout_identity = pin(directory / 'logs/runtime_stdout.log', 16 * 1024**2)
        _require(receipt['trace'] == str(trace) and receipt['stdout'] == str(stdout) and
                 receipt['trace_sha256'] == trace_identity['sha256'] and
                 receipt['stdout_sha256'] == stdout_identity['sha256'], 'DTA trace/stdout binding changed')
        parsed = parse_trace(trace, input_path, len(raw))
        signatures = sorted({(g['pc'], g['outcome']) for g in parsed['groups']})
        _equal(row, {'case': name, 'input_sha256': data_identity['sha256'], 'guest_exit': receipt['guest_exit'],
                    'trace_sha256': parsed['trace_sha256'], 'observed_branch_outcomes': signatures},
               'Recorded branch outcomes differ from actual diagnostics')
        audited.append({'case': name, 'raw': raw, 'sha256': data_identity['sha256'], 'signature': signatures,
                        'groups': parsed['groups'], 'binding': binding, 'phase': phase_summary,
                        'receipt_sha256': inventory[name + '/receipt.json']['sha256'],
                        'trace_sha256': trace_identity['sha256'], 'guest_exit': receipt['guest_exit']})

    _equal(audited[0]['signature'], audited[1]['signature'], 'DTA baseline branch outcomes are unstable')
    _require(audited[0]['guest_exit'] == audited[1]['guest_exit'], 'DTA baseline exit status is unstable')
    known = {tuple(item) for item in audited[0]['signature']}
    accepted = [{'sha256': seed_identity['sha256'], 'case': 'baseline', 'new_outcomes': []}]
    new_outcomes = set()
    for case in audited[2:]:
        signature = {tuple(item) for item in case['signature']}
        fresh = signature - known
        if fresh:
            accepted.append({'sha256': case['sha256'], 'case': case['case'], 'new_outcomes': sorted(fresh)})
        known.update(signature)
        new_outcomes.update(fresh)
    _equal(report['accepted'], accepted, 'Accepted corpus is not the recorded ordered novelty selection')
    for key, value in (('candidate_count', len(candidates)), ('concrete_runs', len(audited)),
                       ('baseline_repetitions', 2), ('new_branch_outcomes', len(new_outcomes)),
                       ('accepted_seed_count', len(accepted))):
        _equal(report[key], value, 'DTA summary count changed: ' + key)
    _equal(sorted(path.name for path in (analysis / 'accepted-seeds').iterdir()),
           sorted(row['sha256'] for row in accepted), 'Unexpected accepted seed inventory')
    for row in accepted:
        path, identity = pin(analysis / 'accepted-seeds' / row['sha256'], 4096)
        _require(identity['sha256'] == row['sha256'], 'Accepted seed bytes changed')

    requests = []
    by_case = {case['case']: case for case in audited}
    for accepted_row in accepted:
        case = by_case[accepted_row['case']]
        for group in case['groups']:
            _require(len(requests) < max_sites, 'DTA handoff site budget exceeded')
            opposite = 'not-taken' if group['outcome'] == 'taken' else 'taken'
            request = {'schema': 1, 'kind': 'DTA_SITE_RECAPTURE_REQUEST',
                'status': 'NEEDS_FRESH_IR_AND_FLAGS', 'dse_eligible': False, 'solver_executed': False,
                'source_case': case['case'], 'source_receipt_sha256': case['receipt_sha256'],
                'trace_sha256': case['trace_sha256'], 'input_sha256': case['sha256'],
                'target_sha256': target_identity['sha256'], 'snapshot': report['snapshot'],
                'runtime_bundle_sha256': bundle['bundle_sha256'], 'input_path': input_path, 'argv': argv,
                'observed_site': group,
                'diagnostic_occurrence_semantics': 'all_logged_conditional_events_at_PC_per_vCPU',
                'exact_instruction_generation': None, 'instruction_bytes': None, 'ir_origin': None,
                'executable_selector': None, 'flags_verified_in_source_run': case['phase']['flags_verified'],
                'desired_outcome': opposite, 'opposite_observed_elsewhere': (group['pc'], opposite) in known,
                'required_checks': ['fresh_exact_instruction_and_IR_origin', 'post_read_occurrence_mapping',
                    'verified_x86_flag_contract', 'file_read_identity', 'supported_complete_prefix',
                    'solver_result', 'concrete_prefix_preserved_branch_inversion'],
                'protected_diagnostic_channel': False}
            request['request_id'] = canonical_hash(request)
            requests.append(request)
    requests.sort(key=lambda item: (item['opposite_observed_elsewhere'], item['source_case'], item['observed_site']['seq']))
    result = {'schema': 1, 'status': 'AUDITED_DTA_CORPUS_AND_RECAPTURE_HINTS',
        'audit_scope': 'offline_artifact_consistency_not_independent_runtime_reverification',
        'analysis': str(analysis), 'analysis_summary_sha256': inventory['summary.json']['sha256'],
        'target_sha256': target_identity['sha256'], 'input_path': input_path, 'argv': argv,
        'snapshot': report['snapshot'], 'runtime_bundle_sha256': bundle['bundle_sha256'],
        'accepted_seeds': accepted, 'audited_runs': len(audited), 'new_branch_outcomes': len(new_outcomes),
        'recapture_sites': len(requests), 'sites_with_unseen_opposite': sum(not row['opposite_observed_elsewhere'] for row in requests),
        'dse_status': 'NOT_RUN', 'afl_campaign_executed': False, 'protected_diagnostic_channel': False,
        'historical_isolation_independently_reexecuted': False, 'universal_equivalence': False,
        'evidence': {key: {field: value[field] for field in ('sha256', 'size')}
                     for key, value in sorted(inventory.items())}}
    # Recheck all consumed artifacts before creating anything at the destination.
    for identity in inventory.values():
        _equal(_pin(identity['path'], identity['size'])[1], identity, 'DTA evidence changed before publication')
    _require(store.verify(snapshot.snapshot_id).tree_sha256 == snapshot.tree_sha256, 'DTA snapshot changed during audit')
    out.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix='.tf-dta-handoff-', dir=out.parent))
    try:
        (staging / 'seeds').mkdir()
        for row in accepted:
            raw = by_case[row['case']]['raw']
            _require(hashlib.sha256(raw).hexdigest() == row['sha256'], 'Accepted source bytes changed')
            (staging / 'seeds' / row['sha256']).write_bytes(raw)
        for name, value in (('manifest.json', result), ('recapture-requests.json', {'schema': 1, 'requests': requests})):
            (staging / name).write_text(json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + '\n')
        _require(not out.exists(), 'Handoff output appeared during publication')
        staging.rename(out)
    finally:
        if staging.exists():
            shutil.rmtree(staging)
    return result
