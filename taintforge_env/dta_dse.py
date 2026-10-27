"""Fulfil audited DTA hints with freshly mapped, isolated file DSE jobs."""
from __future__ import annotations

import hashlib
from pathlib import Path

from . import dse_analysis
from .afl_file import atomic_json, guest_file
from .dta_corpus import _canonical, _limit, _pin, _require, parse_trace
from .dta_handoff import export_handoff
from .elf_runtime import canonical_hash
from .environment_snapshot import EnvironmentSnapshotStore
from .phase1_runtime import read_json


PROFILE = 'dta-dse-file-controller-v1'


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
                  max_occurrences=8, max_steps=128, max_sites=256, seconds=30, memory_mib=1024):
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
        eligible = [request for request in requests if request['opposite_observed_elsewhere'] is False]
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
