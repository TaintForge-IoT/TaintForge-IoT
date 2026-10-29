"""Export the content union of completed, freshly reaudited file corpora.

The original selected-execution auditors establish admission. The portable
verifier checks exported bytes and receipt consistency; it is not a solver or
an independent proof of the upstream execution records.
"""
from __future__ import annotations

import argparse
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys
import tempfile
from unittest.mock import patch

from taintforge_env import dta_dse_eval, dta_dse_queue
from taintforge_env.dta_corpus import _canonical, _require
from taintforge_env.elf_runtime import canonical_hash
from scripts import dta_dse_diagnostics


PROFILE = 'audited-file-DTA-DSE-corpus-union-v1'
MAX_SOURCES = 8
MAX_SEEDS = 8192
MAX_SEED_BYTES = 4096
MAX_JSON = 32 * 1024**2
MAX_TREE_BYTES = 8 * 1024**3
MAX_TREE_FILES = 131072
PROJECT = Path(__file__).resolve().parents[1]
SCOPE = dict(guest_execution=False, SMT_execution=False, afl_campaign_executed=False,
    full_execution_SMT_proven=False, universal_equivalence=False,
    protected_control_channel=False, coverage_feedback_verified=False,
    historical_instruction_identity_proven=False, proof_scope_promoted=False)


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _metadata(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_uid,
        info.st_gid, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _file(path, maximum=MAX_JSON, *, retain=False):
    path = _canonical(path)
    before = path.lstat()
    _require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
        0 <= before.st_size <= maximum, 'Expected bounded private regular input: ' + str(path))
    digest, chunks, size = hashlib.sha256(), [], 0
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as stream:
        _require(_metadata(os.fstat(stream.fileno())) == _metadata(before), 'Input changed before read')
        while chunk := stream.read(1024 * 1024):
            size += len(chunk)
            _require(size <= before.st_size, 'Input grew during read')
            digest.update(chunk)
            if retain:
                chunks.append(chunk)
        _require(size == before.st_size and _metadata(os.fstat(stream.fileno())) == _metadata(before),
            'Input changed during read')
    _require(_metadata(path.lstat()) == _metadata(before), 'Input was replaced during read')
    return dict(path=str(path), size=size, sha256=digest.hexdigest()), b''.join(chunks) if retain else None


def _json(path):
    identity, raw = _file(path, retain=True)

    def pairs(items):
        result = {}
        for name, value in items:
            _require(name not in result, 'Duplicate JSON field')
            result[name] = value
        return result

    def nonfinite(value):
        raise ValueError('Nonfinite JSON number: ' + value)

    value = json.loads(raw, object_pairs_hook=pairs, parse_constant=nonfinite)
    _require(isinstance(value, dict), 'Expected a JSON object')
    return value, identity


def _encoded(value):
    raw = (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + '\n').encode()
    _require(len(raw) <= MAX_JSON, 'Export JSON byte budget exceeded')
    return raw


def _write(path, raw):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def _pairs(rows):
    _require(isinstance(rows, list) and len(rows) <= 65536 and all(
        isinstance(row, list) and len(row) == 2 and type(row[0]) is int and
        0 <= row[0] < 2**64 and row[1] in ('taken', 'not-taken') for row in rows),
        'Invalid diagnostic PC/outcome inventory')
    result = {tuple(row) for row in rows}
    _require(len(result) == len(rows) and rows == [list(row) for row in sorted(result)],
        'Diagnostic outcomes must be canonical, sorted and unique')
    return result


def seal_evaluation(directory, *, max_files=MAX_TREE_FILES, max_bytes=MAX_TREE_BYTES):
    """Bind retained evidence, allowing original auditors' temporary directories.

    Directory activity timestamps/size/link counts are excluded across audits;
    every entry's complete metadata is checked during each individual seal.
    """
    _require(type(max_files) is int and 1 <= max_files <= MAX_TREE_FILES and
        type(max_bytes) is int and 1 <= max_bytes <= MAX_TREE_BYTES, 'Invalid evidence sealing budgets')
    directory = _canonical(directory)
    _require(directory.is_dir(), 'Evaluation directory is missing')
    digest, entries, total = hashlib.sha256(), [], 0

    def add(value):
        raw = json.dumps(value, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode()
        digest.update(len(raw).to_bytes(8, 'big'))
        digest.update(raw)

    def visit(path):
        nonlocal total
        info = path.lstat()
        _require(len(entries) < max_files, 'Evidence file budget exceeded')
        before = _metadata(info)
        entries.append((path, before))
        relative = path.relative_to(directory).as_posix()
        if stat.S_ISDIR(info.st_mode):
            _require(path == directory or not path.is_mount(), 'Retained nested mount in completed evidence')
            names = sorted(child.name for child in path.iterdir())
            _require(len(names) <= max_files - len(entries), 'Evidence directory exceeds its file budget')
            stable = (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid)
            add((relative, stable, 'directory', names))
            for name in names:
                visit(path / name)
            _require(sorted(child.name for child in path.iterdir()) == names, 'Evidence directory changed')
        elif stat.S_ISREG(info.st_mode):
            total += info.st_size
            _require(0 <= info.st_size <= max_bytes and total <= max_bytes, 'Evidence byte budget exceeded')
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(descriptor, 'rb') as stream:
                _require(_metadata(os.fstat(stream.fileno())) == before, 'Evidence changed before sealing')
                hashed, size = hashlib.sha256(), 0
                while chunk := stream.read(1024 * 1024):
                    size += len(chunk)
                    _require(size <= info.st_size, 'Evidence grew during sealing')
                    hashed.update(chunk)
                _require(size == info.st_size and _metadata(os.fstat(stream.fileno())) == before,
                    'Evidence changed during sealing')
            add((relative, before, 'file', hashed.hexdigest()))
        elif stat.S_ISLNK(info.st_mode):
            add((relative, before, 'symlink', os.readlink(path)))
        else:
            raise ValueError('Unsupported completed evidence file type: ' + str(path))
        _require(_metadata(path.lstat()) == before, 'Evidence entry changed during sealing')

    visit(directory)
    _require(all(_metadata(path.lstat()) == before for path, before in entries),
        'Evidence changed before its complete seal finished')
    return dict(sha256=digest.hexdigest(), entries=len(entries), file_bytes=total,
        scope='host_bound_retained_file_bytes_and_metadata_directory_identity_and_names')


def _code():
    files = set((PROJECT / 'taintforge_env').glob('*.py'))
    files.update((PROJECT / 'experiments/execution_capsule_probe').rglob('*.py'))
    files.update((Path(__file__).resolve(), PROJECT / 'scripts/dta_dse_diagnostics.py'))
    _require(0 < len(files) <= 1024, 'Invalid analysis implementation inventory')
    return {str(path): _file(path, 4 * 1024**2)[0] for path in sorted(files)}


def _uncached():
    for name, field in (('dta_dse_audit_cache', '_ACTIVE_SESSION'),
        ('dta_handoff_cache', '_ACTIVE_HANDOFF_SESSION'),
        ('dta_dse_priority', '_ACTIVE_SESSION'), ('profile_dta_dse', '_ACTIVE_PROFILE')):
        module = sys.modules.get('scripts.' + name)
        _require(module is None or getattr(module, field) is None,
            'Close optional audit, scheduling and profiling sessions before corpus export')


def _inside(value, root):
    path = _canonical(value)
    _require(path != root and path.is_relative_to(root), 'Evidence path escaped its original source')
    return path


def _run_record(directory, case, seed_sha):
    root = _inside(directory / case, directory)
    receipt, identity = _json(root / 'receipt.json')
    _require(receipt.get('status') == 'passed' and receipt.get('input_sha256') == seed_sha and
        receipt.get('resources', {}).get('status') == 'verified' and
        receipt['resources'].get('tree_empty') is True, 'Source run lacks verified input and cleanup evidence')
    trace = _file(root / 'logs/trace.log', 16 * 1024**2)[0]
    _require(trace['sha256'] == receipt.get('trace_sha256'), 'Source trace receipt changed')
    return dict(directory=str(root), receipt_sha256=identity['sha256'],
        trace_sha256=trace['sha256'], stdout_sha256=receipt['stdout_sha256'], guest_exit=receipt['guest_exit'])


def _collect(label, evaluation, audit_directory, original_seal):
    checked = dta_dse_diagnostics.inspect_evaluation(evaluation=evaluation, out=audit_directory)
    _require(checked.get('status') == 'AUDITED_DTA_DSE_DIAGNOSTICS' and
        checked.get('original_evidence_file_bytes_unchanged') is True and
        checked.get('proof_scope_promoted') is False and checked.get('guest_execution') is False and
        checked.get('SMT_execution') is False, 'Original completed-run evidence audit did not pass')
    report, summary_identity = _json(evaluation / 'summary.json')
    _require(report.get('profile') == dta_dse_eval.PROFILE and
        report.get('status') == 'COMPLETED_BOUNDED_DTA_DSE_EVALUATION' and
        report.get('measurement_completed') is True and all(report.get(key) is False for key in
        ('all_machine_branch_coverage', 'universal_equivalence', 'protected_control_channel',
         'successor_execution_proven', 'afl_campaign_executed')), 'Invalid completed evaluation scope')
    baseline = _pairs(report['DTA_observed_outcomes'])
    full = _pairs(report['DSE_full_run_outcomes'])
    _require(_pairs(report['new_full_run_outcomes']) == full - baseline, 'Source novelty union changed')
    queue = evaluation / 'queue'
    with dta_dse_queue._lock(queue):
        state = dta_dse_queue._load(queue)
        corpus, corpus_identity = _json(queue / 'corpus.json')
        _require(corpus['binding_id'] == state['binding_id'] and corpus['scope'] == state['scope'] and
            state['scope']['target_sha256'] == report['inputs'][0]['sha256'] and
            state['scope']['input_path'] == report['input_path'] and state['scope']['argv'] == report['argv'],
            'Audited queue, target or launch contract changed')
        analyses, replays, measured = {}, {}, {row['job_id']: row for row in report['jobs']}
        for row in report['analyses']:
            path = _inside(row['directory'], evaluation)
            value, identity = _json(path / 'summary.json')
            _require(identity['sha256'] == row['summary_sha256'], 'DTA source summary changed')
            analyses[str(path)] = (value, identity)
        for row in report['candidate_replays']:
            _require(row['sha256'] not in replays and row['full_runs'] == 2,
                'Duplicated or incomplete full candidate validation')
            path = _inside(row['directory'], evaluation)
            value, identity = _json(path / 'summary.json')
            _require(identity['sha256'] == row['summary_sha256'] and value['concrete_runs'] == 2,
                'Candidate validation summary changed')
            replays[row['sha256']] = (row, value)
        seeds, origins, baseline_seeds = {}, {}, set()
        _require(len(corpus['seeds']) <= MAX_SEEDS, 'Source corpus seed budget exceeded')
        for row in corpus['seeds']:
            sha = row['sha256']
            _require(dta_dse_queue._id(sha) and sha not in seeds and
                isinstance(row.get('origins'), list) and row['origins'] and
                len(row['origins']) == len(set(row['origins'])), 'Invalid seed or origin inventory')
            identity, raw = _file(evaluation / 'seeds' / sha, MAX_SEED_BYTES, retain=True)
            _require(identity['sha256'] == sha and 0 < len(raw), 'Export source seed bytes changed')
            seeds[sha], origins[sha] = raw, []
            for origin in row['origins']:
                kind, separator, identifier = origin.partition(':')
                _require(separator and dta_dse_queue._id(identifier), 'Malformed audited queue seed origin')
                record = dict(source=label, queue_origin=origin,
                    evaluation_summary_sha256=summary_identity['sha256'])
                if kind == 'DTA':
                    _require(identifier in state['analyses'], 'Unknown DTA source origin')
                    path = Path(state['analyses'][identifier]['path'])
                    value, analysis_identity = analyses[str(path)]
                    accepted = [item for item in value['accepted'] if item['sha256'] == sha]
                    _require(len(accepted) == 1, 'DTA origin does not identify one accepted source case')
                    case = accepted[0]['case']
                    cases = ['baseline', 'repeat'] if case == 'baseline' else [case]
                    record.update(kind='audited_DTA', analysis_id=identifier, analysis=str(path),
                        analysis_summary_sha256=analysis_identity['sha256'], accepted_case=case,
                        runs=[_run_record(path, name, sha) for name in cases])
                    baseline_seeds.add(sha)
                elif kind == 'DSE':
                    _require(identifier in state['jobs'] and identifier in measured and sha in replays,
                        'Unknown or unvalidated DSE seed origin')
                    job, item = state['jobs'][identifier], measured[identifier]
                    replay, value = replays[sha]
                    _require(job['status'] == item['status'] == 'VERIFIED' and item['candidate_sha256'] == sha and
                        identifier in replay['job_ids'] and [run['case'] for run in value['runs']] == ['baseline', 'repeat'],
                        'Nonproof or foreign task cannot authorize a DSE seed')
                    path = Path(replay['directory'])
                    record.update(kind='verified_DSE_and_two_full_replays', job_id=identifier,
                        request_id=job['request_id'], analysis_id=job['analysis_id'], branch_pc=item['branch_pc'],
                        desired_outcome=item['desired_outcome'], controller_result=job['result'],
                        validation_directory=str(path), validation_summary_sha256=replay['summary_sha256'],
                        full_run_outcomes=[list(pair) for pair in sorted(dta_dse_eval._pairs(value))],
                        runs=[_run_record(path, name, sha) for name in ('baseline', 'repeat')])
                else:
                    raise ValueError('Unknown audited seed origin kind')
                origins[sha].append(record)
        _require(len(seeds) == report['corpus_seed_count'] and len(baseline_seeds) == report['baseline_seed_count'],
            'Audited source corpus cardinality changed')
        _require(sorted(path.name for path in (evaluation / 'seeds').iterdir()) == sorted(seeds),
            'Unexpected source corpus file inventory')
        _require(dta_dse_queue._load(queue) == state, 'Queue changed while collecting provenance')
    audit_identity = _file(audit_directory / 'summary.json')[0]
    source = dict(label=label, evaluation=str(evaluation), summary_sha256=summary_identity['sha256'],
        queue_corpus_sha256=corpus_identity['sha256'], queue_binding_id=state['binding_id'],
        scope_id=canonical_hash(state['scope']), budgets=report['budgets'],
        target_identity=report['inputs'][0], runtime_inputs_sha256=canonical_hash(report['inputs'][1:5]),
        seed_sha256=sorted(seeds), baseline_seed_sha256=sorted(baseline_seeds),
        DTA_observed_outcomes=report['DTA_observed_outcomes'],
        DSE_full_run_outcomes=report['DSE_full_run_outcomes'],
        new_full_run_outcomes=report['new_full_run_outcomes'],
        audit='audits/' + label + '/summary.json', audit_sha256=audit_identity['sha256'],
        caller_label_is_policy_proof=False)
    contract = dict(inputs=report['inputs'], input_path=report['input_path'], argv=report['argv'],
        environment_scope=state['scope'], baseline_seed_sha256=sorted(baseline_seeds),
        DTA_observed_outcomes=report['DTA_observed_outcomes'])
    return dict(source=source, contract=contract, seeds=seeds, origins=origins,
        queue=queue, state=state, seal=original_seal)


def verify_export(directory):
    """Check exported bytes and manifest consistency, without reopening sources."""
    directory = _canonical(directory)
    manifest, identity = _json(directory / 'manifest.json')
    _require(manifest.get('schema') == 1 and manifest.get('profile') == PROFILE and
        manifest.get('status') == 'AUDITED_DTA_DSE_CORPUS_UNION' and
        manifest.get('provenance_scope') ==
            'original_offline_audits_of_recorded_DTA_and_selected_DSE_with_full_candidate_replays' and
        manifest.get('verifier_scope') == 'export_bytes_and_receipt_consistency_not_independent_execution_or_SMT' and
        manifest.get('manifest_payload_sha256') == canonical_hash({k: v for k, v in manifest.items()
            if k != 'manifest_payload_sha256'}) and all(manifest.get(k) == v for k, v in SCOPE.items()),
        'Export manifest integrity or scope changed')
    sources = manifest['sources']
    _require(isinstance(sources, list) and 1 <= len(sources) <= MAX_SOURCES and
        len({row['label'] for row in sources}) == len(sources), 'Invalid exported source inventory')
    source_ids = {row['label'] for row in sources}
    baseline, full, memberships, source_audits = None, set(), {}, {}
    for row in sources:
        _require(re.fullmatch('[a-z][a-z0-9_-]{0,31}', row['label']) is not None and
            row['audit'] == 'audits/' + row['label'] + '/summary.json', 'Invalid exported audit reference')
        audit, audit_identity = _json(directory / row['audit'])
        _require(audit_identity['sha256'] == row['audit_sha256'] and
            audit.get('status') == 'AUDITED_DTA_DSE_DIAGNOSTICS' and
            audit.get('evaluation') == row['evaluation'] and audit.get('guest_execution') is False and
            audit.get('SMT_execution') is False and audit.get('proof_scope_promoted') is False and
            audit.get('original_evidence_file_bytes_unchanged') is True, 'Exported source audit receipt changed')
        source_audits[row['label']] = (row, audit)
        observed = _pairs(row['DTA_observed_outcomes'])
        _require(baseline is None or observed == baseline, 'Exported DTA baselines differ')
        baseline = observed
        actual = _pairs(row['DSE_full_run_outcomes'])
        _require(_pairs(row['new_full_run_outcomes']) == actual - observed, 'Exported source novelty changed')
        full.update(actual)
        _require(row['seed_sha256'] == sorted(set(row['seed_sha256'])) and
            set(row['baseline_seed_sha256']) <= set(row['seed_sha256']) and
            row.get('caller_label_is_policy_proof') is False, 'Invalid source membership inventory or policy scope')
        for sha in row['seed_sha256']:
            memberships.setdefault(sha, set()).add(row['label'])
    rows = manifest['seeds']
    _require(isinstance(rows, list) and 1 <= len(rows) <= MAX_SEEDS and
        [row['sha256'] for row in rows] == sorted(memberships) and
        sorted(path.name for path in (directory / 'seeds').iterdir()) == sorted(memberships),
        'Exported seed inventory differs from its sources')
    for row in rows:
        sha = row['sha256']
        _require(dta_dse_queue._id(sha) and type(row['size']) is int and row['file'] == 'seeds/' + sha and
            isinstance(row['origins'], list) and row['origins'] and
            len(row['origins']) == len({canonical_hash(origin) for origin in row['origins']}) and
            {origin['source'] for origin in row['origins']} == memberships[sha] <= source_ids,
            'Exported seed provenance or pathname changed')
        for origin in row['origins']:
            common = {'source', 'queue_origin', 'evaluation_summary_sha256', 'kind', 'runs'}
            dta_fields = {'analysis_id', 'analysis', 'analysis_summary_sha256', 'accepted_case'}
            dse_fields = {'job_id', 'request_id', 'analysis_id', 'branch_pc', 'desired_outcome',
                'controller_result', 'validation_directory', 'validation_summary_sha256', 'full_run_outcomes'}
            kind = origin.get('kind')
            _require(kind in ('audited_DTA', 'verified_DSE_and_two_full_replays') and
                set(origin) == common | (dta_fields if kind == 'audited_DTA' else dse_fields) and
                isinstance(origin['runs'], list), 'Exported validation schema changed')
            source, audit = source_audits[origin['source']]
            _require(origin['evaluation_summary_sha256'] == source['summary_sha256'] and
                dta_dse_queue._id(origin['analysis_id']), 'Exported origin source identity changed')
            if kind == 'audited_DTA':
                case = origin['accepted_case']
                _require(isinstance(case, str) and not Path(case).is_absolute() and '..' not in Path(case).parts and
                    origin['queue_origin'] == 'DTA:' + origin['analysis_id'] and
                    dta_dse_queue._id(origin['analysis_summary_sha256']), 'Invalid DTA origin')
                expected = [str(Path(origin['analysis']) / name) for name in
                    (('baseline', 'repeat') if case == 'baseline' else (case,))]
            else:
                jobs = [job for job in audit['jobs'] if job['job_id'] == origin['job_id']]
                _require(origin['queue_origin'] == 'DSE:' + origin['job_id'] and
                    dta_dse_queue._id(origin['job_id']) and dta_dse_queue._id(origin['request_id']) and
                    dta_dse_queue._id(origin['validation_summary_sha256']) and len(jobs) == 1 and
                    jobs[0]['classification'] == 'VERIFIED' and jobs[0]['candidate_sha256'] == sha and
                    jobs[0]['request_id'] == origin['request_id'] and jobs[0]['branch_pc'] == origin['branch_pc'] and
                    jobs[0]['desired_outcome'] == origin['desired_outcome'] and
                    _pairs(origin['full_run_outcomes']) <= _pairs(source['DSE_full_run_outcomes']) and
                    set(origin['controller_result']) == {'summary.json', 'manifest.json'} and
                    all(dta_dse_queue._id(value) for value in origin['controller_result'].values()),
                    'DSE origin is not the exact VERIFIED diagnostic task')
                expected = [str(Path(origin['validation_directory']) / name) for name in ('baseline', 'repeat')]
            _require([run['directory'] for run in origin['runs']] == expected and all(
                set(run) == {'directory', 'receipt_sha256', 'trace_sha256', 'stdout_sha256', 'guest_exit'} and
                all(dta_dse_queue._id(run[key]) for key in ('receipt_sha256', 'trace_sha256', 'stdout_sha256')) and
                type(run['guest_exit']) is int and 0 <= run['guest_exit'] < 128 for run in origin['runs']),
                'Exported original run receipt inventory changed')
        seed_identity, raw = _file(directory / row['file'], MAX_SEED_BYTES, retain=True)
        _require(0 < len(raw) == row['size'] and seed_identity['sha256'] == sha, 'Exported seed bytes changed')
    coverage = manifest['coverage']
    _require(coverage.get('scope') == 'diagnostic_PC_outcome_pairs_from_complete_file_data_roots' and
        coverage['DTA_baseline'] == [list(pair) for pair in sorted(baseline)] and
        coverage['DSE_full_run_union'] == [list(pair) for pair in sorted(full)] and
        coverage['new_vs_DTA_baseline'] == [list(pair) for pair in sorted(full - baseline)] and
        coverage['new_outcome_count'] == len(full - baseline) and
        type(manifest['seed_count']) is int and manifest['seed_count'] == len(rows) and
        type(manifest['source_seed_occurrences']) is int and manifest['source_seed_occurrences'] == sum(
            len(row['seed_sha256']) for row in sources) and
        type(manifest['deduplicated_seed_occurrences']) is int and
        manifest['deduplicated_seed_occurrences'] == manifest['source_seed_occurrences'] - len(rows),
        'Exported counts or coverage union changed')
    launch, launch_identity = _json(directory / 'launch.json')
    _require(launch_identity['sha256'] == manifest['launch_sha256'] and
        launch == manifest['launch'] and launch['tested_seed_lengths'] == sorted({row['size'] for row in rows}) and
        launch['transport'] == 'guest_file_whole_contents' and launch['external_execution_adapter_required'] is True and
        launch['input_path'] == launch['environment_scope']['input_path'] and
        launch['argv'] == launch['environment_scope']['argv'] and
        launch['target']['sha256'] == launch['environment_scope']['target_sha256'] and all(
            source['scope_id'] == canonical_hash(launch['environment_scope']) and
            source['target_identity'] == launch['target'] and
            source['runtime_inputs_sha256'] == canonical_hash(launch['runtime_inputs']) for source in sources) and
        launch['coverage_feedback_verified'] is False and launch['afl_campaign_executed'] is False,
        'Exported launch contract changed')
    return dict(schema=1, status='VERIFIED_EXPORTED_CORPUS_BYTES_AND_MANIFEST',
        profile=PROFILE, manifest_file_sha256=identity['sha256'], seed_count=len(rows),
        new_outcome_count=len(full - baseline), original_evidence_reaudited=False,
        verification_scope='export_bytes_and_receipt_consistency_not_independent_execution_or_SMT', **SCOPE)


def merge_corpora(*, sources, out):
    _uncached()
    _require(isinstance(sources, (list, tuple)) and 1 <= len(sources) <= MAX_SOURCES,
        'Merge between one and eight named completed evaluations')
    named = []
    for label, value in sources:
        _require(isinstance(label, str) and re.fullmatch('[a-z][a-z0-9_-]{0,31}', label) is not None,
            'Invalid source label')
        named.append((label, _canonical(value)))
    named.sort()
    _require(len({name for name, _ in named}) == len(named) and
        len({str(path) for _, path in named}) == len(named), 'Duplicate source label or evaluation')
    out = _canonical(out)
    _require(not out.exists() and all(path.is_dir() and not out.is_relative_to(path) and
        not path.is_relative_to(out) for _, path in named), 'Output must be new and outside its sources')
    _require(all(not left.is_relative_to(right) and not right.is_relative_to(left)
        for index, (_, left) in enumerate(named) for _, right in named[index + 1:]), 'Source evaluations overlap')
    code = _code()
    out.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix='.tf-corpus-merge-', dir=out.parent))
    try:
        (staging / 'audits').mkdir()
        collected = []
        with patch('subprocess.Popen', side_effect=RuntimeError('Offline corpus export cannot launch a process')):
            for label, evaluation in named:
                print('corpus-merge: original audit ' + label, flush=True)
                seal = seal_evaluation(evaluation)
                collected.append(_collect(label, evaluation, staging / 'audits' / label, seal))
            contract = collected[0]['contract']
            _require(all(row['contract'] == contract for row in collected),
                'Corpus sources differ in target, runtime, input, environment or DTA baseline')
            seeds, origins = {}, {}
            for row in collected:
                for sha, raw in row['seeds'].items():
                    _require(sha not in seeds or seeds[sha] == raw, 'Conflicting bytes for one content identity')
                    seeds[sha] = raw
                    origins.setdefault(sha, []).extend(row['origins'][sha])
            _require(1 <= len(seeds) <= MAX_SEEDS and sum(map(len, seeds.values())) <= 32 * 1024**2,
                'Merged corpus byte or file budget exceeded')
            baseline = _pairs(contract['DTA_observed_outcomes'])
            full = set().union(*(_pairs(row['source']['DSE_full_run_outcomes']) for row in collected))
            launch = dict(schema=1, transport='guest_file_whole_contents', input_path=contract['input_path'],
                argv=contract['argv'], target=contract['inputs'][0], runtime_inputs=contract['inputs'][1:5],
                environment_scope=contract['environment_scope'],
                tested_seed_lengths=sorted({len(raw) for raw in seeds.values()}),
                external_execution_adapter_required=True, coverage_feedback_verified=False,
                afl_campaign_executed=False)
            launch_raw = _encoded(launch)
            manifest = dict(schema=1, profile=PROFILE, status='AUDITED_DTA_DSE_CORPUS_UNION',
                provenance_scope='original_offline_audits_of_recorded_DTA_and_selected_DSE_with_full_candidate_replays',
                verifier_scope='export_bytes_and_receipt_consistency_not_independent_execution_or_SMT',
                sources=[row['source'] for row in collected], launch=launch, launch_sha256=_sha(launch_raw),
                seed_count=len(seeds), source_seed_occurrences=sum(len(row['seeds']) for row in collected),
                deduplicated_seed_occurrences=sum(len(row['seeds']) for row in collected) - len(seeds),
                seeds=[dict(sha256=sha, file='seeds/' + sha, size=len(seeds[sha]),
                    origins=sorted(origins[sha], key=lambda value: (value['source'], value['queue_origin'])))
                    for sha in sorted(seeds)],
                coverage=dict(scope='diagnostic_PC_outcome_pairs_from_complete_file_data_roots',
                    DTA_baseline=[list(pair) for pair in sorted(baseline)],
                    DSE_full_run_union=[list(pair) for pair in sorted(full)],
                    new_vs_DTA_baseline=[list(pair) for pair in sorted(full - baseline)],
                    new_outcome_count=len(full - baseline)), **SCOPE)
            manifest['manifest_payload_sha256'] = canonical_hash(manifest)
            (staging / 'seeds').mkdir(mode=0o700)
            for sha, raw in sorted(seeds.items()):
                _write(staging / 'seeds' / sha, raw)
            _write(staging / 'launch.json', launch_raw)
            _write(staging / 'manifest.json', _encoded(manifest))
            verification = verify_export(staging)
            with ExitStack() as locks:
                for row in sorted(collected, key=lambda item: str(item['queue'])):
                    locks.enter_context(dta_dse_queue._lock(row['queue']))
                _require(all(dta_dse_queue._load(row['queue']) == row['state'] and
                    seal_evaluation(Path(row['source']['evaluation'])) == row['seal'] for row in collected),
                    'Original evidence changed before union publication')
                _require(_code() == code, 'Analysis implementation changed during union export')
                _uncached()
                _require(not out.exists() and not out.is_symlink(), 'Export destination appeared')
                staging.rename(out)
                staging = None
        return dict(schema=1, status='AUDITED_DTA_DSE_CORPUS_UNION', profile=PROFILE,
            seed_count=len(seeds), source_seed_occurrences=manifest['source_seed_occurrences'],
            deduplicated_seed_occurrences=manifest['deduplicated_seed_occurrences'],
            new_outcome_count=len(full - baseline), corpus=str(out / 'seeds'),
            manifest=str(out / 'manifest.json'), exported_bytes_verified=True,
            source_evidence_seals={row['source']['label']: row['seal'] for row in collected},
            original_evidence_file_bytes_unchanged=True, portable_verification=verification, **SCOPE)
    finally:
        if staging is not None and staging.exists():
            shutil.rmtree(staging)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', action='append', default=[])
    parser.add_argument('--out', type=Path)
    parser.add_argument('--verify', type=Path)
    args = parser.parse_args(argv)
    if args.verify is not None:
        if args.source or args.out:
            parser.error('--verify cannot be combined with --source or --out')
        report = verify_export(args.verify)
    else:
        if not args.source or args.out is None:
            parser.error('Provide --source LABEL=COMPLETED_EVALUATION and --out NEW_DIRECTORY')
        sources = []
        for item in args.source:
            label, separator, path = item.partition('=')
            if not separator or not path:
                parser.error('Each source must be LABEL=COMPLETED_EVALUATION')
            sources.append((label, Path(path)))
        report = merge_corpora(sources=sources, out=args.out)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
