"""Fulfil audited DTA hints with freshly mapped, isolated file DSE jobs."""
from __future__ import annotations

import hashlib
from pathlib import Path
import re
import tempfile

from . import dse_analysis
from .afl_file import atomic_json, guest_file
from .dta_corpus import _canonical, _limit, _pin, _require, parse_trace
from .dta_handoff import export_handoff
from .elf_runtime import canonical_hash
from .environment_snapshot import EnvironmentSnapshotStore
from .phase1_runtime import read_json


PROFILE = 'dta-dse-file-controller-v1'


def _request_ids(request_ids):
    if request_ids is None:
        return None
    _require(isinstance(request_ids, (tuple, list)) and 1 <= len(request_ids) <= 32 and
             all(isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value) for value in request_ids) and
             len(set(request_ids)) == len(request_ids), 'Invalid selected DTA request IDs')
    return list(request_ids)


def _select_requests(requests, request_ids):
    eligible = [request for request in requests if request['opposite_observed_elsewhere'] is False]
    if request_ids is None:
        return eligible
    by_id = {request['request_id']: request for request in eligible}
    _require(len(by_id) == len(eligible), 'Regenerated eligible request IDs are duplicated')
    _require(all(request_id in by_id for request_id in request_ids),
             'Selected DTA request ID is unknown or ineligible')
    return [by_id[request_id] for request_id in request_ids]


def _read(path, maximum=4 * 1024**2):
    path, identity = _pin(path, maximum)
    value = read_json(path, maximum=maximum)
    _require(_pin(path, maximum)[1] == identity, 'Controller evidence changed while reading')
    return value, identity


def _same_environment(original, fresh, input_path, seed_sha256):
    before = {entry.path: entry.to_dict() for entry in original.entries}
    after = {entry.path: entry.to_dict() for entry in fresh.entries}
    _require(set(before) == set(after) and input_path in before,
             'Fresh worker omitted or added an original environment resource')
    expected = dict(before[input_path], sha256=seed_sha256)
    _require(after[input_path] == expected and
             all(after[name] == value for name, value in before.items() if name != input_path),
             'Fresh worker environment differs beyond the selected seed bytes')


def _group_for_hint(request, native, parsed, *, candidate=False):
    hint = request['observed_site']
    matching = [group for group in parsed['groups'] if
        (group['vcpu'], group['pc'], group['occurrence']) ==
        (hint['vcpu'], hint['pc'], hint['occurrence'])]
    _require(len(matching) == 1, 'Fresh run lacks one unambiguous data-dependent hinted occurrence')
    group = matching[0]
    outcome = request['desired_outcome'] if candidate else hint['outcome']
    _require(group['offsets'] == hint['offsets'] and group['outcome'] == outcome and
             (candidate or group['next'] == hint['next']),
             'Fresh hinted branch changed its offsets, outcome or successor')
    return group


def _map_occurrence(request, native, parsed, *, candidate=False):
    """Only same-run exact sequence equality maps the two occurrence domains."""
    group = _group_for_hint(request, native, parsed, candidate=candidate)
    if native['selected_seq'] != group['seq']:
        return None
    origin, edge = native['trace'][-1]['instruction'], native['dcfg_edge']
    _require(origin['seq'] == group['seq'] and origin['pc'] == group['pc'] and
             origin['vcpu'] == group['vcpu'] == 0 and
             native['successor']['pc'] == group['next'] and
             native['taken'] == (group['outcome'] == 'taken') and
             edge['id'] == group['edge'] and edge['target_pc'] == group['next'] and
             edge['source_generation'] == group['source_block_generation'],
             'Native origin and same-run DTA/DCFG branch evidence differ')
    return {'diagnostic_occurrence': group['occurrence'],
        'native_occurrence': native['occurrence'], 'selected_seq': native['selected_seq'],
        'read_seq': native['read_seq'], 'branch_origin': origin, 'fresh_site': group,
        'mapping_scope': 'fresh_same_run_instruction_sequence_and_branch_evidence',
        'historical_instruction_identity_proven': False}


def _same_prefix(observed, solved):
    def route(report):
        return [(row['instruction']['pc'], row['instruction']['bytes'], row['instruction']['vcpu'],
                 row['next_pc'], row['branch_outcome']) for row in report['trace']]
    def calls(report):
        ordinal = {row['instruction']['seq']: index for index, row in enumerate(report['trace'])}
        return [(ordinal[row['seq']], row['number'], row['args'], row['result']) for row in report['syscalls']]
    keys = ('file', 'read_offset', 'read_size', 'requested', 'fd', 'address', 'fixed_inputs_sha256', 'taken')
    _require(route(observed) == route(solved) and calls(observed) == calls(solved) and
             all(observed[key] == solved[key] for key in keys) and
             [(b['offset'], b['address'], b['byte'], b['input_id']) for b in observed['bindings']] ==
             [(b['offset'], b['address'], b['byte'], b['input_id']) for b in solved['bindings']] and
             tuple(observed['successor'][key] for key in ('pc', 'bytes', 'vcpu')) ==
             tuple(solved['successor'][key] for key in ('pc', 'bytes', 'vcpu')),
             'Inversion baseline diverged from the mapped fresh observation')


def extend_corpus(*, analysis, qemu, plugin, flags_receipt, out, max_jobs=4,
                  max_occurrences=8, max_steps=128, max_sites=256, seconds=30, memory_mib=1024,
                  request_ids=None):
    request_ids = _request_ids(request_ids)
    _limit(max_jobs, 32, 'DSE jobs')
    _limit(max_occurrences, 32, 'native recapture occurrences')
    _limit(max_steps, 1024, 'native prefix steps')
    _limit(max_sites, 4096, 'DTA sites')
    _limit(seconds, 120, 'DSE case time')
    _require(type(memory_mib) is int and 256 <= memory_mib <= 4096, 'Invalid DSE memory budget')
    analysis, out = _canonical(analysis), _canonical(out)
    _require(analysis.is_dir() and not out.exists() and not out.is_relative_to(analysis) and
             not analysis.is_relative_to(out), 'Controller output must be new and outside its source analysis')
    sources = []
    for path, maximum in ((qemu, 512 * 1024**2), (plugin, 512 * 1024**2),
                          (Path(str(plugin) + '.runtime.json'), 16 * 1024**2), (flags_receipt, 4096)):
        path, identity = _pin(path, maximum)
        _require(not path.is_relative_to(out) and not out.is_relative_to(path),
                 'Controller output overlaps a runtime source')
        sources.append((path, identity, maximum))
    qemu, plugin, _, flags_receipt = [item[0] for item in sources]
    out.mkdir(parents=True)
    report = {'schema': 1, 'profile': PROFILE, 'status': 'failed', 'dse_status': 'NOT_RUN',
        'scope': 'audited_DTA_hints_fresh_isolated_DSE_corpus_extension',
        'analysis': str(analysis), 'handoff': str(out / 'handoff'), 'jobs': [], 'deferred': [], 'skipped': [],
        'new_seed_count': 0, 'corpus_seed_count': 0, 'dse_adapter_isolated': False,
        'afl_campaign_executed': False, 'protected_control_channel': False,
        'universal_equivalence': False, 'historical_instruction_identity_proven': False,
        'successor_execution_proven': False,
        'novelty_scope': 'selected_concrete_branch_outcomes_vs_audited_DTA',
        'budgets': {'max_jobs': max_jobs, 'max_occurrences': max_occurrences,
            'max_steps': max_steps, 'max_sites': max_sites, 'case_seconds': seconds, 'memory_mib': memory_mib}}
    if request_ids is not None:
        report['selected_request_ids'] = request_ids
    try:
        handoff = export_handoff(analysis=analysis, out=out / 'handoff', max_sites=max_sites)
        saved_handoff, handoff_identity = _read(out / 'handoff/manifest.json')
        _require(canonical_hash(saved_handoff) == canonical_hash(handoff), 'Returned handoff differs from its saved manifest')
        requests_doc, requests_identity = _read(out / 'handoff/recapture-requests.json')
        _require(type(requests_doc.get('schema')) is int and requests_doc['schema'] == 1 and
                 isinstance(requests_doc.get('requests'), list), 'Invalid regenerated recapture inventory')
        requests = requests_doc['requests']
        original_report, _ = _read(analysis / 'summary.json')
        old_store = EnvironmentSnapshotStore(analysis / 'snapshots')
        original_snapshot = old_store.verify(handoff['snapshot']['snapshot_id'])
        target = guest_file(old_store.store_dir / original_snapshot.snapshot_id / 'rootfs', '/bin/sample.elf')
        target, target_identity = _pin(target, 64 * 1024**2)
        _require(target_identity['sha256'] == handoff['target_sha256'], 'Audited target identity changed')
        known = {tuple(pair) for row in original_report['runs'] for pair in row['observed_branch_outcomes']}
        seeds, baseline = {}, set()
        for row in handoff['accepted_seeds']:
            path, identity = _pin(out / 'handoff/seeds' / row['sha256'], 4096)
            _require(identity['sha256'] == row['sha256'], 'Audited seed changed')
            seeds[row['sha256']] = path.read_bytes()
            baseline.add(row['sha256'])
        eligible = _select_requests(requests, request_ids)
        report.update(audited_runs=handoff['audited_runs'], requested_unseen_sites=len(eligible),
            source_snapshot=handoff['snapshot'], source_runtime_bundle_sha256=handoff['runtime_bundle_sha256'])
        completed = []
        identities = set()
        for request in eligible:
            hint = request['observed_site']
            key = (request['input_sha256'], hint['vcpu'], hint['pc'], hint['occurrence'], tuple(hint['offsets']))
            if key in identities:
                report['skipped'].append({'request_id': request['request_id'], 'reason': 'duplicate_site'})
                continue
            identities.add(key)
            _require(request['request_id'] == canonical_hash({k: v for k, v in request.items() if k != 'request_id'}) and
                     request['input_sha256'] in seeds and request['target_sha256'] == target_identity['sha256'] and
                     request['input_path'] == handoff['input_path'] and request['argv'] == handoff['argv'] and
                     request['snapshot'] == handoff['snapshot'] and request['dse_eligible'] is False and
                     request['executable_selector'] is None and request['ir_origin'] is None,
                     'Regenerated hint changed or promoted its authority')
            if hint['vcpu'] != 0:
                report['skipped'].append({'request_id': request['request_id'], 'reason': 'unsupported_vcpu'})
                continue
            if (hint['pc'], request['desired_outcome']) in known:
                report['skipped'].append({'request_id': request['request_id'], 'reason': 'outcome_already_verified'})
                continue
            if len(report['jobs']) == max_jobs:
                report['deferred'].append(request['request_id'])
                continue
            directory = out / 'jobs' / f'{len(report["jobs"]):04d}'
            directory.mkdir(parents=True)
            seed = out / 'handoff/seeds' / request['input_sha256']
            row = {'request_id': request['request_id'], 'status': 'UNKNOWN', 'mapping': None,
                   'worker': None, 'mapping_observation': None, 'attempts': []}
            report['jobs'].append(row)
            parameters = dict(binary=target, qemu=qemu, plugin=plugin, seed=seed,
                input_path=handoff['input_path'], flags_receipt=flags_receipt, offsets=hint['offsets'],
                branch_pc=hint['pc'], argv=handoff['argv'], max_steps=max_steps,
                seconds=seconds, memory_mib=memory_mib)
            mapping = mapped_native = None
            for occurrence in range(1, max_occurrences + 1):
                capture = directory / f'recapture-{occurrence:04d}'
                captured = dse_analysis.observe_file(**parameters, occurrence=occurrence, out=capture)
                _require(dse_analysis.audit_file_run(directory=capture) == captured,
                         'Fresh recapture evidence changed')
                snapshot = EnvironmentSnapshotStore(capture / 'snapshots').verify(captured['snapshot']['snapshot_id'])
                _same_environment(original_snapshot, snapshot, handoff['input_path'], request['input_sha256'])
                row['attempts'].append({'occurrence': occurrence, 'directory': str(capture),
                    'status': captured['dse_status']})
                completed.append((capture, captured))
                if captured['dse_status'] != 'OBSERVED':
                    continue
                native, _ = _read(capture / 'observe/logs/phase1/concolic.json')
                parsed = parse_trace(capture / 'observe/logs/trace.log', handoff['input_path'], len(seeds[request['input_sha256']]))
                mapping = _map_occurrence(request, native, parsed)
                if mapping is not None:
                    mapped_native = native
                    row.update(mapping=mapping, mapping_observation=str(capture))
                    break
            if mapping is None:
                row['reason'] = 'no_validated_mapping_within_occurrence_budget'
                continue
            worker = directory / 'inversion'
            row['worker'] = str(worker)
            solved = dse_analysis.invert_file(**parameters, occurrence=mapping['native_occurrence'], out=worker)
            _require(dse_analysis.audit_file_run(directory=worker) == solved, 'Inversion evidence changed')
            completed.append((worker, solved))
            snapshot = EnvironmentSnapshotStore(worker / 'snapshots').verify(solved['snapshot']['snapshot_id'])
            _same_environment(original_snapshot, snapshot, handoff['input_path'], request['input_sha256'])
            row['status'] = solved['dse_status']
            if solved['dse_status'] == 'UNKNOWN':
                continue
            native, _ = _read(worker / 'solve/logs/phase1/concolic.json')
            _same_prefix(mapped_native, native)
            if solved['dse_status'] != 'VERIFIED':
                continue
            observed, _ = _read(worker / 'observe/logs/phase1/concolic.json')
            candidate, identity = _pin(worker / 'accepted-seeds' / solved['candidate_sha256'], 4096)
            parsed = parse_trace(worker / 'observe/logs/trace.log', handoff['input_path'], identity['size'])
            candidate_mapping = _map_occurrence(request, observed, parsed, candidate=True)
            _require(candidate_mapping is not None and observed['taken'] == (request['desired_outcome'] == 'taken'),
                     'Verified candidate does not fulfil the selected fresh hint')
            seeds[identity['sha256']] = candidate.read_bytes()
            row.update(candidate_sha256=identity['sha256'], verified_outcome=request['desired_outcome'],
                       fresh_runtime_bundle_sha256=solved['bundle_sha256'], fresh_snapshot=solved['snapshot'])
            known.add((hint['pc'], request['desired_outcome']))

        # Re-audit every historical source and fresh job before publishing the corpus.
        checked = export_handoff(analysis=analysis, out=out / 'handoff-recheck', max_sites=max_sites)
        rerequests, _ = _read(out / 'handoff-recheck/recapture-requests.json')
        _require(checked == handoff and rerequests == requests_doc, 'Audited DTA source changed before publication')
        _require(_read(out / 'handoff/manifest.json') == (saved_handoff, handoff_identity) and
                 _read(out / 'handoff/recapture-requests.json') == (requests_doc, requests_identity),
                 'Published handoff artifacts changed before corpus publication')
        for directory, expected in completed:
            _require(dse_analysis.audit_file_run(directory=directory) == expected, 'DSE evidence changed before publication')
        for path, identity, maximum in sources + [(target, target_identity, 64 * 1024**2)]:
            _require(_pin(path, maximum)[1] == identity, 'Controller source changed before publication')
        _require(old_store.verify(original_snapshot.snapshot_id).tree_sha256 == original_snapshot.tree_sha256,
                 'Original DTA snapshot changed')
        for sha in baseline:
            _require(hashlib.sha256(seeds[sha]).hexdigest() == sha and
                     _pin(out / 'handoff/seeds' / sha, 4096)[1]['sha256'] == sha,
                     'Audited seed changed before publication')
        pending = out / '.seeds.pending'
        pending.mkdir()
        for sha, raw in sorted(seeds.items()):
            _require(hashlib.sha256(raw).hexdigest() == sha, 'Corpus seed hash changed')
            (pending / sha).write_bytes(raw)
        manifest = {'schema': 1, 'profile': PROFILE, 'scope': report['scope'],
            'target_sha256': target_identity['sha256'], 'input_path': handoff['input_path'], 'argv': handoff['argv'],
            'source_analysis_summary_sha256': handoff['analysis_summary_sha256'],
            'source_snapshot': handoff['snapshot'], 'source_runtime_bundle_sha256': handoff['runtime_bundle_sha256'],
            'source_handoff': {'path': str(out / 'handoff'), 'manifest_sha256': handoff_identity['sha256']},
            'fresh_runtime_inputs': {role: {key: identity[key] for key in ('sha256', 'size')}
                for role, (_, identity, _) in zip(('qemu', 'plugin', 'runtime_manifest', 'flags_receipt'), sources)},
            'seeds': [{'sha256': sha, 'origin': 'audited_DTA' if sha in baseline else 'verified_isolated_DSE'}
                      for sha in sorted(seeds)],
            'jobs': report['jobs'], 'protected_control_channel': False, 'universal_equivalence': False}
        if request_ids is not None:
            manifest['selected_request_ids'] = request_ids
            manifest['fresh_runtime_paths'] = {role: str(path) for role, (path, _, _) in
                zip(('qemu', 'plugin', 'runtime_manifest', 'flags_receipt'), sources)}
        atomic_json(out / 'manifest.json', manifest)
        pending.rename(out / 'seeds')
        verified = [row for row in report['jobs'] if row['status'] == 'VERIFIED']
        report.update(status='passed', dse_status='VERIFIED' if verified else 'NOT_ESTABLISHED',
            new_seed_count=len(set(seeds) - baseline), corpus_seed_count=len(seeds),
            dse_adapter_isolated=bool(verified), deferred_unseen_sites=len(report['deferred']),
            source_and_worker_evidence_reaudited=True, successor_boundary_observed=bool(verified))
        return report
    except Exception as exc:
        report.update(status='failed', error=f'{type(exc).__name__}: {exc}', dse_adapter_isolated=False)
        raise
    finally:
        atomic_json(out / 'summary.json', report)


def audit_selected_corpus(*, directory, analysis, qemu, plugin, flags_receipt, request_id,
                          max_occurrences=8, max_steps=128, max_sites=256, seconds=30, memory_mib=1024):
    """Rebuild one saved selected-hint result without running a guest or solver.

    This admits only a complete publication, including complete UNKNOWN/UNSAT
    workers. Partial directories cannot establish cleanup and are not reusable.
    The source handoff and each isolated worker are audited again; summary and
    manifest fields are reconstructed rather than used as proof authorities.
    """
    request_ids = _request_ids([request_id])
    for value, maximum, name in ((max_occurrences, 32, 'native recapture occurrences'),
            (max_steps, 1024, 'native prefix steps'), (max_sites, 4096, 'DTA sites'),
            (seconds, 120, 'DSE case time')):
        _limit(value, maximum, name)
    _require(type(memory_mib) is int and 256 <= memory_mib <= 4096, 'Invalid DSE memory budget')
    directory, analysis = _canonical(directory), _canonical(analysis)
    _require(directory.is_dir() and analysis.is_dir() and not directory.is_relative_to(analysis) and
             not analysis.is_relative_to(directory), 'Saved controller overlaps its DTA source')
    inventory = {}

    def pin(path, maximum):
        path, identity = _pin(path, maximum)
        _require(path not in inventory or inventory[path] == (identity, maximum),
                 'Controller evidence changed during audit')
        inventory[path] = (identity, maximum)
        return path, identity

    def read(path, maximum=4 * 1024**2):
        path, identity = pin(path, maximum)
        value, checked = _read(path, maximum)
        _require(checked == identity, 'Controller JSON changed during audit')
        return value, identity

    def equal(left, right, message):
        _require(canonical_hash(left) == canonical_hash(right), message)

    def names(path, expected, *, optional=False):
        path = _canonical(path)
        if optional and not path.exists():
            _require(not expected, 'Missing controller directory')
            return
        _require(path.is_dir() and sorted(item.name for item in path.iterdir()) == sorted(expected),
                 'Saved controller directory inventory changed: ' + str(path))

    summary, _ = read(directory / 'summary.json')
    manifest, _ = read(directory / 'manifest.json')
    _require(summary.get('status') == 'passed' and summary.get('selected_request_ids') == request_ids and
             manifest.get('selected_request_ids') == request_ids,
             'Saved result is not one completed selected-hint controller attempt')
    roles = ('qemu', 'plugin', 'runtime_manifest', 'flags_receipt')
    source_values = (qemu, plugin, Path(str(plugin) + '.runtime.json'), flags_receipt)
    source_limits = (512 * 1024**2, 512 * 1024**2, 16 * 1024**2, 4096)
    sources = {role: pin(value, maximum) for role, value, maximum in zip(roles, source_values, source_limits)}
    _require(all(not path.is_relative_to(directory) and not directory.is_relative_to(path)
                 for path, _ in sources.values()), 'Saved controller overlaps its selected runtime')
    worker_reports = []
    with tempfile.TemporaryDirectory(prefix='.tf-selected-audit-', dir=directory.parent) as temporary:
        fresh = Path(temporary) / 'handoff'
        handoff = export_handoff(analysis=analysis, out=fresh, max_sites=max_sites)
        fresh_manifest, _ = read(fresh / 'manifest.json')
        equal(fresh_manifest, handoff, 'Returned handoff differs from its regenerated manifest')
        request_doc, _ = read(fresh / 'recapture-requests.json')
        _require(type(request_doc.get('schema')) is int and request_doc['schema'] == 1 and
                 isinstance(request_doc.get('requests'), list), 'Invalid regenerated recapture inventory')
        request = _select_requests(request_doc['requests'], request_ids)[0]
        baseline, seeds = set(), {}
        for row in handoff['accepted_seeds']:
            seed, identity = pin(fresh / 'seeds' / row['sha256'], 4096)
            _require(identity['sha256'] == row['sha256'], 'Regenerated DTA seed changed')
            baseline.add(row['sha256'])
            seeds[row['sha256']] = seed.read_bytes()

        handoff_identity = None
        for name in ('handoff', 'handoff-recheck'):
            saved = directory / name
            names(saved, ('manifest.json', 'recapture-requests.json', 'seeds'))
            saved_manifest, identity = read(saved / 'manifest.json')
            saved_requests, _ = read(saved / 'recapture-requests.json')
            equal(saved_manifest, handoff, 'Saved handoff differs from re-audited DTA evidence')
            equal(saved_requests, request_doc, 'Saved recapture requests differ from re-audited DTA evidence')
            names(saved / 'seeds', baseline)
            for sha in baseline:
                seed, identity_seed = pin(saved / 'seeds' / sha, 4096)
                _require(identity_seed['sha256'] == sha and seed.read_bytes() == seeds[sha],
                         'Saved handoff seed differs from its audited source')
            if name == 'handoff':
                handoff_identity = identity
        old_store = EnvironmentSnapshotStore(analysis / 'snapshots')
        snapshot = old_store.verify(handoff['snapshot']['snapshot_id'])
        target = guest_file(old_store.store_dir / snapshot.snapshot_id / 'rootfs', '/bin/sample.elf')
        target, target_identity = pin(target, 64 * 1024**2)
        _require(target_identity['sha256'] == handoff['target_sha256'], 'Audited target identity changed')
        hint = request['observed_site']
        _require(request['request_id'] == canonical_hash({k: v for k, v in request.items() if k != 'request_id'}) and
                 request['input_sha256'] in seeds and request['target_sha256'] == target_identity['sha256'] and
                 request['input_path'] == handoff['input_path'] and request['argv'] == handoff['argv'] and
                 request['snapshot'] == handoff['snapshot'] and request['dse_eligible'] is False and
                 request['executable_selector'] is None and request['ir_origin'] is None,
                 'Regenerated hint changed or promoted its authority')
        original, _ = read(analysis / 'summary.json')
        known = {tuple(pair) for row in original['runs'] for pair in row['observed_branch_outcomes']}
        expected = {'schema': 1, 'profile': PROFILE, 'status': 'failed', 'dse_status': 'NOT_RUN',
            'scope': 'audited_DTA_hints_fresh_isolated_DSE_corpus_extension',
            'analysis': str(analysis), 'handoff': str(directory / 'handoff'), 'jobs': [], 'deferred': [], 'skipped': [],
            'new_seed_count': 0, 'corpus_seed_count': 0, 'dse_adapter_isolated': False,
            'afl_campaign_executed': False, 'protected_control_channel': False,
            'universal_equivalence': False, 'historical_instruction_identity_proven': False,
            'successor_execution_proven': False,
            'novelty_scope': 'selected_concrete_branch_outcomes_vs_audited_DTA',
            'budgets': {'max_jobs': 1, 'max_occurrences': max_occurrences, 'max_steps': max_steps,
                'max_sites': max_sites, 'case_seconds': seconds, 'memory_mib': memory_mib},
            'selected_request_ids': request_ids, 'audited_runs': handoff['audited_runs'],
            'requested_unseen_sites': 1, 'source_snapshot': handoff['snapshot'],
            'source_runtime_bundle_sha256': handoff['runtime_bundle_sha256']}

        def worker(path, occurrence, observation):
            checked = dse_analysis.audit_file_run(directory=path)
            worker_reports.append((path, checked))
            scope = dse_analysis.OBSERVATION_SCOPE if observation else dse_analysis.INVERSION_SCOPE
            _require(checked['scope'] == scope and checked['input_path'] == handoff['input_path'] and
                     checked['argv'] == handoff['argv'] and checked['branch_pc'] == hint['pc'] and
                     checked['occurrence'] == occurrence and checked['max_steps'] == max_steps and
                     checked['offsets'] == hint['offsets'] and checked['budgets'] ==
                     {'case_cpu_seconds': seconds, 'memory_mib': memory_mib},
                     'Saved DSE worker differs from the selected hint or budgets')
            expected_inputs = {role: identity for role, (_, identity) in sources.items()}
            seed_path, seed_identity = pin(directory / 'handoff/seeds' / request['input_sha256'], 4096)
            expected_inputs.update(binary=target_identity, seed=seed_identity)
            equal(checked['inputs'], expected_inputs, 'Saved DSE worker uses a different source or runtime path')
            fresh_snapshot = EnvironmentSnapshotStore(path / 'snapshots').verify(checked['snapshot']['snapshot_id'])
            _same_environment(snapshot, fresh_snapshot, handoff['input_path'], request['input_sha256'])
            return checked

        if hint['vcpu'] != 0:
            expected['skipped'].append({'request_id': request_id, 'reason': 'unsupported_vcpu'})
        elif (hint['pc'], request['desired_outcome']) in known:
            expected['skipped'].append({'request_id': request_id, 'reason': 'outcome_already_verified'})
        else:
            names(directory / 'jobs', ('0000',))
            job = directory / 'jobs/0000'
            children = sorted(item.name for item in job.iterdir())
            captures = [name for name in children if re.fullmatch('recapture-[0-9]{4}', name)]
            _require(1 <= len(captures) <= max_occurrences and captures ==
                     [f'recapture-{occurrence:04d}' for occurrence in range(1, len(captures) + 1)] and
                     set(children) <= set(captures) | {'inversion'}, 'Saved recapture inventory is incomplete')
            row = {'request_id': request_id, 'status': 'UNKNOWN', 'mapping': None,
                'worker': None, 'mapping_observation': None, 'attempts': []}
            expected['jobs'].append(row)
            mapping = mapped_native = None
            for occurrence, name in enumerate(captures, 1):
                path = job / name
                captured = worker(path, occurrence, True)
                row['attempts'].append({'occurrence': occurrence, 'directory': str(path),
                                        'status': captured['dse_status']})
                if captured['dse_status'] != 'OBSERVED':
                    continue
                native, _ = read(path / 'observe/logs/phase1/concolic.json')
                trace, _ = pin(path / 'observe/logs/trace.log', 16 * 1024**2)
                parsed = parse_trace(trace, handoff['input_path'], len(seeds[request['input_sha256']]))
                mapping = _map_occurrence(request, native, parsed)
                if mapping is not None:
                    _require(occurrence == len(captures), 'Saved controller continued after its mapped occurrence')
                    mapped_native = native
                    row.update(mapping=mapping, mapping_observation=str(path))
                    break
            if mapping is None:
                _require(len(captures) == max_occurrences and 'inversion' not in children,
                         'Unmapped controller did not finish its exact occurrence budget')
                row['reason'] = 'no_validated_mapping_within_occurrence_budget'
            else:
                _require('inversion' in children, 'Mapped controller is missing its completed inversion')
                path = job / 'inversion'
                row['worker'] = str(path)
                solved = worker(path, mapping['native_occurrence'], False)
                row['status'] = solved['dse_status']
                if solved['dse_status'] != 'UNKNOWN':
                    native, _ = read(path / 'solve/logs/phase1/concolic.json')
                    _same_prefix(mapped_native, native)
                    if solved['dse_status'] == 'VERIFIED':
                        observed, _ = read(path / 'observe/logs/phase1/concolic.json')
                        candidate, identity = pin(path / 'accepted-seeds' / solved['candidate_sha256'], 4096)
                        trace, _ = pin(path / 'observe/logs/trace.log', 16 * 1024**2)
                        candidate_mapping = _map_occurrence(request, observed,
                            parse_trace(trace, handoff['input_path'], identity['size']), candidate=True)
                        _require(candidate_mapping is not None and observed['taken'] ==
                                 (request['desired_outcome'] == 'taken'), 'Saved candidate does not fulfil its hint')
                        seeds[identity['sha256']] = candidate.read_bytes()
                        row.update(candidate_sha256=identity['sha256'], verified_outcome=request['desired_outcome'],
                            fresh_runtime_bundle_sha256=solved['bundle_sha256'], fresh_snapshot=solved['snapshot'])
        if not expected['jobs']:
            names(directory / 'jobs', (), optional=True)
        verified = [row for row in expected['jobs'] if row['status'] == 'VERIFIED']
        expected.update(status='passed', dse_status='VERIFIED' if verified else 'NOT_ESTABLISHED',
            new_seed_count=len(set(seeds) - baseline), corpus_seed_count=len(seeds),
            dse_adapter_isolated=bool(verified), deferred_unseen_sites=0,
            source_and_worker_evidence_reaudited=True, successor_boundary_observed=bool(verified))
        expected_manifest = {'schema': 1, 'profile': PROFILE, 'scope': expected['scope'],
            'target_sha256': target_identity['sha256'], 'input_path': handoff['input_path'], 'argv': handoff['argv'],
            'source_analysis_summary_sha256': handoff['analysis_summary_sha256'],
            'source_snapshot': handoff['snapshot'], 'source_runtime_bundle_sha256': handoff['runtime_bundle_sha256'],
            'source_handoff': {'path': str(directory / 'handoff'), 'manifest_sha256': handoff_identity['sha256']},
            'fresh_runtime_inputs': {role: {key: identity[key] for key in ('sha256', 'size')}
                                     for role, (_, identity) in sources.items()},
            'fresh_runtime_paths': {role: str(path) for role, (path, _) in sources.items()},
            'selected_request_ids': request_ids,
            'seeds': [{'sha256': sha, 'origin': 'audited_DTA' if sha in baseline else 'verified_isolated_DSE'}
                      for sha in sorted(seeds)],
            'jobs': expected['jobs'], 'protected_control_channel': False, 'universal_equivalence': False}
        equal(summary, expected, 'Saved controller summary differs from its re-audited evidence')
        equal(manifest, expected_manifest, 'Saved controller manifest differs from its re-audited evidence')
        _require(not (directory / '.seeds.pending').exists() and not (directory / '.seeds.pending').is_symlink(),
                 'Saved controller publication is incomplete')
        names(directory / 'seeds', seeds)
        for sha, raw in seeds.items():
            path, identity = pin(directory / 'seeds' / sha, 4096)
            _require(identity['sha256'] == sha and path.read_bytes() == raw,
                     'Saved controller corpus differs from its audited sources')
        root_names = {'handoff', 'handoff-recheck', 'manifest.json', 'summary.json', 'seeds'}
        if (directory / 'jobs').exists():
            root_names.add('jobs')
        names(directory, root_names)
        checked = export_handoff(analysis=analysis, out=Path(temporary) / 'handoff-recheck', max_sites=max_sites)
        equal(checked, handoff, 'DTA source changed during selected-controller audit')
        second_requests, _ = read(Path(temporary) / 'handoff-recheck/recapture-requests.json')
        equal(second_requests, request_doc, 'DTA request inventory changed during selected-controller audit')
        for path, value in worker_reports:
            equal(dse_analysis.audit_file_run(directory=path), value, 'DSE evidence changed during selected-controller audit')
        for path, (identity, maximum) in inventory.items():
            _require(_pin(path, maximum)[1] == identity, 'Controller input changed during selected-controller audit')
        _require(old_store.verify(snapshot.snapshot_id).tree_sha256 == snapshot.tree_sha256,
                 'Original DTA snapshot changed during selected-controller audit')
        return {'report': summary, 'manifest': manifest, 'seeds': seeds, 'request': request, 'handoff': handoff}
