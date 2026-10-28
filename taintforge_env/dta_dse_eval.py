"""Measure bounded file DTA/DSE with fresh full-run validation of DSE seeds.

This is a diagnostic branch-outcome experiment. It does not measure all machine
coverage, prove parser correctness or execute an AFL campaign.
"""
from __future__ import annotations

import csv
import hashlib
import io
from pathlib import Path
import tempfile
import time

from . import dta_analysis, dta_dse, dta_dse_queue
from .afl_file import atomic_json, validate_guest_path
from .dta_corpus import _canonical, _limit, _pin, _require, parse_trace
from .dta_handoff import export_handoff
from .elf_runtime import canonical_hash
from .environment_snapshot import EnvironmentSnapshotStore
from .phase1_runtime import read_json


PROFILE = 'bounded-file-dta-dse-evaluation-v1'
PROJECT = Path(__file__).resolve().parents[1]


def _json(path, maximum=8 * 1024**2):
    path, identity = _pin(path, maximum)
    value = read_json(path, maximum=maximum)
    _require(_pin(path, maximum)[1] == identity, 'Evaluation evidence changed during read')
    return value


def _pairs(report):
    return {tuple(pair) for row in report['runs'] for pair in row['observed_branch_outcomes']}


def _saved_analysis(path, returned, *, candidate=False, max_sites=4096):
    saved = _json(path / 'summary.json')
    # The DTA producer returns tuple pairs; JSON stores the same pairs as arrays.
    _require(canonical_hash(saved) == canonical_hash(returned) and saved.get('status') == 'passed',
             'Returned DTA analysis differs from its completed saved evidence')
    with tempfile.TemporaryDirectory(prefix='tf-eval-dta-audit-') as temporary:
        handoff = export_handoff(analysis=path, out=Path(temporary) / 'handoff', max_sites=max_sites)
    _require(handoff.get('status') == 'AUDITED_DTA_CORPUS_AND_RECAPTURE_HINTS',
             'DTA source did not pass its original evidence audit')
    # analyze_file already compares outcomes and exit; also bind deterministic
    # stdout, which is significant for a parser's returned result.
    outputs = []
    for case in ('baseline', 'repeat'):
        receipt = _json(path / case / 'receipt.json')
        stdout, identity = _pin(path / case / 'logs/runtime_stdout.log', 16 * 1024**2)
        _require(receipt.get('stdout_sha256') == identity['sha256'], 'Replay stdout receipt changed')
        outputs.append((stdout.read_bytes(), receipt.get('guest_exit')))
    _require(outputs[0] == outputs[1], 'Full repeated execution has unstable stdout or exit')
    if candidate:
        _require(saved.get('candidate_count') == 1 and saved.get('concrete_runs') == 2 and
                 len(saved['runs']) == 2 and [row['case'] for row in saved['runs']] == ['baseline', 'repeat'],
                 'DSE candidate validation must contain exactly two unmutated full executions')
    return saved, handoff, outputs[0]


def _inside(value, root):
    path = _canonical(value)
    _require(path != root and path.is_relative_to(root) and path.is_dir(),
             'Job evidence escapes its original queue attempt')
    return path


def _full_environment(original, fresh, input_path, candidate_sha256):
    """A full launch must retain the source launch's libraries and resources."""
    before = _json(original / 'summary.json')['snapshot']['snapshot_id']
    after = _json(fresh / 'summary.json')['snapshot']['snapshot_id']
    source = EnvironmentSnapshotStore(original / 'snapshots').verify(before)
    replay = EnvironmentSnapshotStore(fresh / 'snapshots').verify(after)
    dta_dse._same_environment(source, replay, input_path, candidate_sha256)


def _job_reasons(directory, report):
    reasons = []
    for job in report['jobs']:
        if job.get('reason'):
            reasons.append(job['reason'])
        workers = [attempt['directory'] for attempt in job['attempts']]
        if job.get('worker'):
            workers.append(job['worker'])
        for value in workers:
            worker = _inside(value, directory)
            summary = _json(worker / 'summary.json')
            if summary.get('reason'):
                reasons.append(summary['reason'])
            for run in summary.get('runs', []):
                native_path = _canonical(run['concolic_report'])
                _require(native_path.is_relative_to(worker), 'Native diagnostic report escaped its worker')
                native = _json(native_path, 16 * 1024**2)
                _require(_pin(native_path, 16 * 1024**2)[1]['sha256'] == run['concolic_report_sha256'],
                         'Audited native diagnostic reason changed')
                if native.get('reason'):
                    reasons.append(native['reason'])
    _require(all(isinstance(reason, str) and len(reason) <= 2048 for reason in reasons),
             'Invalid native nonproof diagnosis')
    return sorted(set(reasons))


def _write_csv(path, rows):
    stream = io.StringIO(newline='')
    fields = ('job_id', 'analysis_id', 'request_id', 'status', 'branch_pc',
              'candidate_sha256', 'wall_seconds', 'new_full_run_outcomes', 'reasons')
    writer = csv.DictWriter(stream, fieldnames=fields)
    writer.writeheader()
    for row in rows:
        writer.writerow({key: ';'.join(row[key]) if key == 'reasons' else row.get(key, '') for key in fields})
    path.write_text(stream.getvalue())


def evaluate_file(*, binary, qemu, plugin, flags_receipt, seeds, input_path, argv=(), out,
                  max_candidates=24, max_jobs=8, max_occurrences=4, max_steps=1024,
                  max_sites=4096, seconds=30, memory_mib=1024, wall_seconds=3600):
    """Run a fresh bounded experiment; a nonproof measurement is a valid result.

    ``wall_seconds`` is checked between operations, never used as evidence that
    a running isolated service has finished. No partially validated seed is
    copied into the final ``seeds`` directory.
    """
    _require(isinstance(seeds, (list, tuple)) and 1 <= len(seeds) <= 4,
             'Evaluate one to four initial seed files')
    _limit(max_candidates, 128, 'DTA candidates')
    _limit(max_jobs, 128, 'evaluation DSE starts')
    _limit(wall_seconds, 172800, 'soft evaluation wall time')
    limits = dta_dse_queue._limits(max_total_starts=max_jobs, max_queue_jobs=4096,
        max_occurrences=max_occurrences, max_steps=max_steps, max_sites=max_sites,
        seconds=seconds, memory_mib=memory_mib)
    argv = dta_analysis._arguments(argv)
    validate_guest_path(input_path)
    out = _canonical(out)
    sources = []
    for value, maximum in ((binary, 64 * 1024**2), (qemu, 512 * 1024**2),
                           (plugin, 512 * 1024**2), (str(plugin) + '.runtime.json', 16 * 1024**2),
                           (flags_receipt, 4096), *((seed, 64) for seed in seeds)):
        path, identity = _pin(value, maximum)
        _require(not path.is_relative_to(out) and not out.is_relative_to(path), 'Evaluation output overlaps an input')
        sources.append((path, identity, maximum))
    _require(not out.exists() and all(identity['size'] > 0 for _, identity, _ in sources),
             'Evaluation inputs must be nonempty and output must be new')
    binary, qemu, plugin, _, flags_receipt = [item[0] for item in sources[:5]]
    seed_paths = [item[0] for item in sources[5:]]
    _require(len({identity['sha256'] for _, identity, _ in sources[5:]}) == len(seed_paths),
             'Initial seed contents must be distinct')
    out.mkdir(parents=True)
    started = time.monotonic()
    deadline = started + wall_seconds
    report = {'schema': 1, 'profile': PROFILE, 'status': 'FAILED_FILE_DTA_DSE_EVALUATION',
        'scope': 'fresh_isolated_file_runs_and_diagnostic_tainted_branch_outcomes',
        'coverage_scope': 'observed_PC_outcome_pairs_from_complete_file_data_roots',
        'all_machine_branch_coverage': False, 'universal_equivalence': False,
        'protected_control_channel': False, 'successor_execution_proven': False,
        'afl_campaign_executed': False, 'dse_status': 'NOT_ESTABLISHED',
        'measurement_completed': False, 'inputs': [identity for _, identity, _ in sources],
        'input_path': input_path, 'argv': argv, 'budgets': dict(limits, soft_wall_seconds=wall_seconds),
        'analyses': [], 'jobs': [], 'candidate_replays': [], 'timings': {},
        'queue': str(out / 'queue')}

    def intact():
        for path, identity, maximum in sources:
            _require(_pin(path, maximum)[1] == identity, 'Evaluation original input changed')

    def remaining():
        return int(deadline - time.monotonic())

    def analyze(seed, directory, candidates):
        budget = remaining()
        _require(budget >= 1, 'Evaluation soft wall budget exhausted before a required full replay')
        intact()
        t0 = time.monotonic()
        seed_identity = _pin(seed, 4096)[1]
        result = dta_analysis.analyze_file(binary=binary, qemu=qemu, plugin=plugin, seed=seed,
            input_path=input_path, argv=argv, out=directory, max_candidates=candidates,
            seconds=seconds, memory_mib=memory_mib, wall_seconds=min(7200, budget))
        saved, handoff, stdout = _saved_analysis(directory, result, candidate=candidates == 1, max_sites=max_sites)
        _require(saved['inputs']['binary']['sha256'] == sources[0][1]['sha256'] and
                 saved['inputs']['seed']['sha256'] == seed_identity['sha256'] and
                 saved['input_path'] == input_path and saved['argv'] == argv and
                 _pin(seed, 4096)[1] == seed_identity,
                 'Fresh DTA evidence does not match the requested binary, seed or launch')
        intact()
        return saved, handoff, stdout, time.monotonic() - t0

    try:
        baseline_outcomes, baseline_seeds = set(), set()
        for index, seed in enumerate(seed_paths):
            print(f'dta-dse-eval: DTA seed {index + 1}/{len(seed_paths)}', flush=True)
            directory = out / 'analyses' / f'{index:02d}'
            saved, handoff, stdout, duration = analyze(seed, directory, max_candidates)
            baseline_outcomes.update(_pairs(saved))
            baseline_seeds.update(row['sha256'] for row in handoff['accepted_seeds'])
            report['analyses'].append({'directory': str(directory), 'summary_sha256':
                _pin(directory / 'summary.json', 8 * 1024**2)[1]['sha256'],
                'wall_seconds': duration, 'concrete_runs': saved['concrete_runs'],
                'candidate_count': saved['candidate_count'], 'new_branch_outcomes': saved['new_branch_outcomes'],
                'baseline_stdout_sha256': hashlib.sha256(stdout[0]).hexdigest(),
                'baseline_guest_exit': stdout[1]})
            atomic_json(out / 'summary.json', report)
        report['timings']['DTA_wall_seconds'] = sum(row['wall_seconds'] for row in report['analyses'])
        queue = out / 'queue'
        dta_dse_queue.create_queue(queue=queue, qemu=qemu, plugin=plugin, flags_receipt=flags_receipt,
                                  **limits)
        admitted = dta_dse_queue.enqueue_analyses(queue=queue,
            analyses=[Path(row['directory']) for row in report['analyses']])
        atomic_json(out / 'admission.json', admitted)
        durations = {}
        for index in range(max_jobs):
            if remaining() < 1:
                break
            snapshot = dta_dse_queue.queue_status(queue=queue)
            if snapshot['counts']['PENDING'] == 0 or snapshot['counts']['BLOCKED_RECOVERY']:
                break
            before = _json(queue / 'state.json')
            pending = next(identifier for identifier in before['order'] if before['jobs'][identifier]['status'] == 'PENDING')
            print(f'dta-dse-eval: DSE job {index + 1}/{max_jobs} {pending[:12]}', flush=True)
            t0 = time.monotonic()
            result = dta_dse_queue.run_queue(queue=queue, max_jobs=1, wall_seconds=max(1, remaining()))
            duration = time.monotonic() - t0
            if result['started_this_run'] == 0:
                break
            durations[pending] = duration
            atomic_json(out / 'job-timings.json', durations)
            if result['status'] in ('QUEUE_BLOCKED', 'QUEUE_STOPPED'):
                break
        audited = dta_dse_queue.audit_queue(queue=queue)
        _require(audited['evidence_audited'] is True and audited['counts']['BLOCKED_RECOVERY'] == 0,
                 'Queue ended with incomplete worker or cleanup evidence')
        atomic_json(out / 'queue-audit.json', audited)
        state = _json(queue / 'state.json')
        candidates = {}
        for identifier in state['order']:
            item = state['jobs'][identifier]
            row = {'job_id': identifier, 'analysis_id': item['analysis_id'], 'request_id': item['request_id'],
                   'status': item['status'], 'wall_seconds': durations.get(identifier),
                   'candidate_sha256': None, 'new_full_run_outcomes': 0, 'reasons': []}
            report['jobs'].append(row)
            if item['status'] == 'PENDING':
                row['reasons'] = ['evaluation_start_or_soft_wall_budget']
                continue
            directory = _inside(item['attempts'][0]['directory'], queue)
            source = Path(state['analyses'][item['analysis_id']]['path'])
            checked = dta_dse.audit_selected_corpus(directory=directory, analysis=source,
                qemu=qemu, plugin=plugin, flags_receipt=flags_receipt,
                request_id=item['request_id'], max_occurrences=max_occurrences, max_steps=max_steps,
                max_sites=max_sites, seconds=seconds, memory_mib=memory_mib)
            request = checked['request']
            row['branch_pc'] = request['observed_site']['pc']
            row['desired_outcome'] = request['desired_outcome']
            row['reasons'] = _job_reasons(directory, checked['report'])
            if item['status'] == 'VERIFIED':
                native_jobs = checked['report']['jobs']
                _require(len(native_jobs) == 1 and native_jobs[0]['status'] == 'VERIFIED',
                         'Verified queue task does not identify exactly one verified native inversion')
                candidate_sha = native_jobs[0]['candidate_sha256']
                raw = checked['seeds'][candidate_sha]
                _require(hashlib.sha256(raw).hexdigest() == candidate_sha,
                         'Verified DSE candidate contents changed')
                row['candidate_sha256'] = candidate_sha
                candidates.setdefault(candidate_sha, {'raw': raw, 'jobs': []})['jobs'].append((row, request, source))
        full_outcomes, validated_seeds = set(), {}
        for candidate_sha, candidate in sorted(candidates.items()):
            print('dta-dse-eval: full candidate reruns ' + candidate_sha[:12], flush=True)
            seed = queue / 'seeds' / candidate_sha
            _require(_pin(seed, 4096)[1]['sha256'] == candidate_sha and seed.read_bytes() == candidate['raw'],
                     'Published queue candidate changed')
            directory = out / 'candidate-replays' / candidate_sha
            saved, handoff, stdout, duration = analyze(seed, directory, 1)
            for _, _, source in candidate['jobs']:
                _full_environment(source, directory, input_path, candidate_sha)
            signatures = [set(tuple(pair) for pair in row['observed_branch_outcomes']) for row in saved['runs']]
            _require(signatures[0] == signatures[1], 'Repeated full candidate branch outcomes differ')
            for case in ('baseline', 'repeat'):
                groups = parse_trace(directory / case / 'logs/trace.log', input_path, len(candidate['raw']))['groups']
                for job, request, _ in candidate['jobs']:
                    site = request['observed_site']
                    matching = [group for group in groups if (group['vcpu'], group['pc'], group['occurrence']) ==
                                (site['vcpu'], site['pc'], site['occurrence'])]
                    _require(len(matching) == 1 and matching[0]['offsets'] == site['offsets'] and
                             matching[0]['outcome'] == request['desired_outcome'],
                             'Full DSE candidate rerun lost its selected diagnostic branch occurrence')
            fresh = signatures[0] - baseline_outcomes
            for job, _, _ in candidate['jobs']:
                job['new_full_run_outcomes'] = len(fresh)
            full_outcomes.update(signatures[0])
            validated_seeds[candidate_sha] = candidate['raw']
            report['candidate_replays'].append({'sha256': candidate_sha, 'directory': str(directory),
                'new_outcomes_vs_all_DTA': [list(pair) for pair in sorted(fresh)], 'wall_seconds': duration,
                'full_runs': 2, 'stdout_sha256': hashlib.sha256(stdout[0]).hexdigest(),
                'summary_sha256': _pin(directory / 'summary.json', 8 * 1024**2)[1]['sha256'],
                'guest_exit': stdout[1], 'job_ids': [row['job_id'] for row, _, _ in candidate['jobs']]})
        # Reopen the original queue and every candidate's complete evidence after
        # all execution, before publishing a separate corpus for downstream use.
        final_audit = dta_dse_queue.audit_queue(queue=queue)
        _require(final_audit == audited, 'Queue evidence changed during full candidate validation')
        for candidate in report['candidate_replays']:
            directory = Path(candidate['directory'])
            _require(_pin(directory / 'summary.json', 8 * 1024**2)[1]['sha256'] == candidate['summary_sha256'],
                     'Measured candidate summary changed before final publication')
            _, _, stdout = _saved_analysis(directory, _json(directory / 'summary.json'),
                                            candidate=True, max_sites=max_sites)
            _require(hashlib.sha256(stdout[0]).hexdigest() == candidate['stdout_sha256'] and
                     stdout[1] == candidate['guest_exit'],
                     'Measured candidate stdout or exit changed before final publication')
        intact()
        corpus = _json(queue / 'corpus.json')
        rows = corpus['seeds']
        _require(len(rows) == len({row['sha256'] for row in rows}), 'Queue corpus has duplicate identities')
        accepted = {}
        for row in rows:
            sha = row['sha256']
            seed, identity = _pin(queue / 'seeds' / sha, 4096)
            _require(identity['sha256'] == sha, 'Final source corpus bytes changed')
            if sha in baseline_seeds or sha in validated_seeds:
                accepted[sha] = seed.read_bytes()
            else:
                _require(False, 'Final corpus contains an unvalidated candidate')
        pending = out / '.seeds.pending'
        pending.mkdir()
        for sha, raw in sorted(accepted.items()):
            (pending / sha).write_bytes(raw)
        fresh_outcomes = full_outcomes - baseline_outcomes
        verified = sum(row['status'] == 'VERIFIED' for row in report['jobs'])
        report.update(status='COMPLETED_BOUNDED_DTA_DSE_EVALUATION',
            gain_status='VERIFIED_NEW_FULL_RUN_OUTCOMES' if verified and fresh_outcomes else
                'NONPROOF_NO_NEW_FULL_RUN_OUTCOMES', measurement_completed=True,
            dse_status='VERIFIED' if verified else 'NOT_ESTABLISHED',
            DTA_observed_outcomes=[list(pair) for pair in sorted(baseline_outcomes)],
            DSE_full_run_outcomes=[list(pair) for pair in sorted(full_outcomes)],
            new_full_run_outcomes=[list(pair) for pair in sorted(fresh_outcomes)],
            verified_jobs=verified, nonproof_jobs=sum(row['status'] == 'NONPROOF' for row in report['jobs']),
            pending_jobs=sum(row['status'] == 'PENDING' for row in report['jobs']),
            baseline_seed_count=len(baseline_seeds), corpus_seed_count=len(accepted),
            new_seed_count=len(set(accepted) - baseline_seeds), full_validation_runs=2 * len(validated_seeds),
            seeds=str(out / 'seeds'), queue_status=audited['status'],
            reason_counts={reason: sum(reason in row['reasons'] for row in report['jobs'])
                           for reason in sorted({value for row in report['jobs'] for value in row['reasons']})})
        report['timings'].update(DSE_job_wall_seconds=sum(durations.values()),
            full_replay_wall_seconds=sum(row['wall_seconds'] for row in report['candidate_replays']))
        atomic_json(out / 'manifest.json', {'schema': 1, 'profile': PROFILE,
            'target_sha256': sources[0][1]['sha256'], 'input_path': input_path, 'argv': argv,
            'queue': str(queue), 'seeds': [{'sha256': sha,
                'origin': 'audited_DTA' if sha in baseline_seeds else 'verified_DSE_and_two_full_replays'}
                for sha in sorted(accepted)], 'universal_equivalence': False,
            'coverage_scope': report['coverage_scope'], 'protected_control_channel': False})
        _write_csv(out / 'jobs.csv', report['jobs'])
        intact()
        pending.rename(out / 'seeds')
        return report
    except BaseException as exc:
        report.update(status='FAILED_FILE_DTA_DSE_EVALUATION', measurement_completed=False)
        report['error'] = type(exc).__name__ + ': ' + str(exc)
        raise
    finally:
        report['timings']['total_wall_seconds'] = time.monotonic() - started
        atomic_json(out / 'summary.json', report)
