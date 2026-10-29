"""Audit completed DTA/DSE evidence and describe recorded nonproof results.

This tool executes neither a guest nor an SMT solver. Locations and reasons
are observations in existing native reports, not independently proved causes.
"""
from __future__ import annotations

import csv
import hashlib
import io
import json
from pathlib import Path

from taintforge_env import dta_dse, dta_dse_eval, dta_dse_queue
from taintforge_env.afl_file import atomic_json
from taintforge_env.dta_corpus import _canonical, _pin, _require, parse_trace
from taintforge_env.elf_runtime import canonical_hash
from taintforge_env.phase1_runtime import read_json


PROFILE = 'audited-dta-dse-diagnostics-v1'


def _location(native):
    """Report an available observation without inventing a failure location."""
    trace = native.get('trace', [])
    _require(isinstance(trace, list) and len(trace) <= 1024, 'Invalid bounded native trace')
    result = {'location_status': 'UNAVAILABLE_IN_RECORDED_REPORT',
              'last_observed_instruction': None, 'last_recorded_syscall': None,
              'first_blocking_instruction_established': False}
    if trace:
        instruction = trace[-1].get('instruction')
        _require(isinstance(instruction, dict), 'Native last trace row lacks an instruction')
        pc, data = instruction.get('pc'), instruction.get('bytes')
        _require(type(pc) is int and 0 <= pc < 2**32 and isinstance(data, str) and
                 0 < len(data) <= 30 and len(data) % 2 == 0 and
                 all(character in '0123456789abcdef' for character in data),
                 'Invalid recorded native instruction location')
        result.update(location_status='LAST_OBSERVED_INSTRUCTION_ONLY',
            last_observed_instruction={key: instruction[key] for key in
                ('pc', 'bytes', 'seq', 'vcpu', 'generation', 'descriptor') if key in instruction})
    calls = native.get('syscalls', [])
    _require(isinstance(calls, list) and len(calls) <= 32, 'Invalid native syscall inventory')
    if calls:
        call = calls[-1]
        _require(isinstance(call, dict) and type(call.get('number')) is int and
                 isinstance(call.get('args'), list) and len(call['args']) <= 6,
                 'Invalid last recorded syscall')
        result['last_recorded_syscall'] = {key: call[key] for key in
            ('seq', 'number', 'args', 'result') if key in call}
    return result


def _classification(queue_status, native_job):
    if queue_status == 'PENDING':
        return 'PENDING_NOT_EXECUTED'
    if queue_status == 'VERIFIED':
        _require(native_job['status'] == 'VERIFIED', 'Verified queue task lacks its verified native job')
        return 'VERIFIED'
    _require(queue_status == 'NONPROOF' and native_job['status'] in ('UNKNOWN', 'UNSAT'),
             'Unsupported or incomplete diagnostic task status')
    if native_job['status'] == 'UNSAT':
        return 'UNSAT_SELECTED_MODEL'
    return ('UNKNOWN_UNMAPPED' if native_job.get('mapping') is None else 'UNKNOWN_NATIVE')


def _csv(path, jobs):
    stream = io.StringIO(newline='')
    fields = ('job_id', 'request_id', 'queue_status', 'classification', 'branch_pc',
              'desired_outcome', 'recorded_job_wall_seconds', 'reason', 'native_attempt_count')
    writer = csv.DictWriter(stream, fieldnames=fields)
    writer.writeheader()
    for row in jobs:
        writer.writerow({name: len(row['native_attempts']) if name == 'native_attempt_count'
                         else row.get(name) for name in fields})
    path.write_text(stream.getvalue())


def _candidate_inventory(rows, expected):
    _require(isinstance(rows, list) and all(isinstance(row, dict) and
             isinstance(row.get('sha256'), str) for row in rows), 'Invalid full candidate replay inventory')
    identifiers = [row['sha256'] for row in rows]
    _require(len(identifiers) == len(set(identifiers)) and set(identifiers) == set(expected),
             'Full candidate replay inventory is duplicated or differs from verified jobs')


def inspect_evaluation(*, evaluation, out):
    """Reaudit completed selected executions and preserve original evidence bytes.

    Existing queue state and corpus are never republished or migrated. Native
    audits may create and remove their own temporary audit directories. A
    partial/hard-interrupted queue cannot authorize this completed-run report.
    """
    evaluation, out = _canonical(evaluation), _canonical(out)
    _require(evaluation.is_dir() and not out.exists() and not out.is_relative_to(evaluation) and
             not evaluation.is_relative_to(out), 'Diagnostic output must be new and outside its evaluation')
    inventory = {}

    def pin(value, maximum=8 * 1024**2):
        path, identity = _pin(value, maximum)
        _require(path not in inventory or inventory[path] == (identity, maximum),
                 'Diagnostic evidence changed during audit')
        inventory[path] = (identity, maximum)
        _require(not out.is_relative_to(path) and not path.is_relative_to(out), 'Output overlaps diagnostic input')
        return path, identity

    def read(value, maximum=8 * 1024**2):
        path, identity = pin(value, maximum)
        result = read_json(path, maximum=maximum)
        _require(_pin(path, maximum)[1] == identity, 'Diagnostic JSON changed during read')
        return result

    def inside(value, parent, *, directory=False):
        path = _canonical(value)
        _require(path != parent and path.is_relative_to(parent) and
                 (path.is_dir() if directory else path.is_file()), 'Diagnostic evidence escaped its original directory')
        return path

    summary = read(evaluation / 'summary.json')
    _require(summary.get('schema') == 1 and summary.get('profile') == dta_dse_eval.PROFILE and
             summary.get('status') == 'COMPLETED_BOUNDED_DTA_DSE_EVALUATION' and
             summary.get('measurement_completed') is True and summary.get('universal_equivalence') is False and
             summary.get('afl_campaign_executed') is False,
             'Diagnostic input is not a completed bounded file evaluation')
    queue = inside(summary['queue'], evaluation, directory=True)
    _require(queue == evaluation / 'queue', 'Original evaluation queue path changed')
    # Do not let _lock create a missing lock and do not invoke public audit_queue,
    # which republishes corpus metadata even when its bytes are unchanged.
    pin(queue / 'controller.lock', 1024)
    with dta_dse_queue._lock(queue):
        state = dta_dse_queue._load(queue)
        pin(queue / 'state.json')
        _require(all(row['status'] in ('PENDING', 'VERIFIED', 'NONPROOF') for row in state['jobs'].values()),
                 'Incomplete or blocked queue cannot supply completed diagnostics')
        sources = dta_dse_queue._sources(queue, state)
        seeds, origins, changed, adopted = dta_dse_queue._collect(queue, state, sources)
        _require(not changed and adopted == 0, 'Historical queue requires recovery rather than offline diagnosis')
        corpus = read(queue / 'corpus.json')
        _require(corpus == dta_dse_queue._corpus_manifest(state, seeds, origins), 'Queue corpus manifest changed')
        _require(sorted(path.name for path in (queue / 'seeds').iterdir()) == sorted(seeds),
                 'Queue corpus seed inventory changed')
        for name, data in seeds.items():
            path, identity = pin(queue / 'seeds' / name, 4096)
            _require(identity['sha256'] == name and path.read_bytes() == data, 'Queue corpus seed changed')
        audited = dta_dse_queue._summary(queue, state, audited=True, action='audited',
                                        adopted_completed_attempts=0)
        _require(audited == read(evaluation / 'queue-audit.json'), 'Original final queue audit summary differs')
        rows = summary['jobs']
        _require(isinstance(rows, list) and [row['job_id'] for row in rows] == state['order'],
                 'Evaluation task inventory differs from its original queue')
        runtime = {name: row['path'] for name, row in state['config']['runtime'].items()}
        for name, identity in state['config']['runtime'].items():
            _require(pin(identity['path'], dta_dse_queue.RUNTIME_LIMITS[name])[1] == identity,
                     'Historical runtime identity changed')
        arguments = dta_dse_queue._controller_arguments(state)
        jobs, requests, candidate_jobs = [], [], {}
        for measured in rows:
            identifier = measured['job_id']
            item = state['jobs'][identifier]
            _require(measured['status'] == item['status'] and measured['analysis_id'] == item['analysis_id'] and
                     measured['request_id'] == item['request_id'], 'Evaluation task status or identity changed')
            source = state['analyses'][item['analysis_id']]['path']
            row = dict(job_id=identifier, request_id=item['request_id'], analysis=source,
                queue_status=item['status'], native_status=None, classification='PENDING_NOT_EXECUTED',
                branch_pc=None, desired_outcome=None, candidate_sha256=None, reason=None,
                recorded_job_wall_seconds=measured.get('wall_seconds'), native_attempts=[])
            jobs.append(row)
            if item['status'] == 'PENDING':
                continue
            directory = inside(item['attempts'][0]['directory'], queue, directory=True)
            checked = dta_dse.audit_selected_corpus(directory=directory, analysis=source,
                request_id=item['request_id'], **arguments)
            for name, expected in item['result'].items():
                _require(pin(directory / name)[1]['sha256'] == expected, 'Committed controller result changed')
            request, controller = checked['request'], checked['report']
            _require(len(controller['jobs']) == 1, 'Selected controller has an unexpected native job inventory')
            native_job = controller['jobs'][0]
            row.update(branch_pc=request['observed_site']['pc'], desired_outcome=request['desired_outcome'],
                native_status=native_job['status'], classification=_classification(item['status'], native_job),
                reason=native_job.get('reason'))
            _require(measured.get('branch_pc') == row['branch_pc'] and
                     measured.get('desired_outcome') == row['desired_outcome'], 'Measured task changed its selected site')
            if item['status'] == 'VERIFIED':
                candidate_sha = native_job['candidate_sha256']
                _require(measured.get('candidate_sha256') == candidate_sha, 'Measured candidate identity changed')
                row['candidate_sha256'] = candidate_sha
                candidate_jobs.setdefault(candidate_sha, []).append((source, request))
            workers = [('recapture', attempt['directory']) for attempt in native_job['attempts']]
            if native_job.get('worker'):
                workers.append(('inversion', native_job['worker']))
            for stage, value in workers:
                worker = inside(value, directory, directory=True)
                worker_summary = read(worker / 'summary.json')
                for run in worker_summary['runs']:
                    native_path = inside(run['concolic_report'], worker)
                    native = read(native_path, 16 * 1024**2)
                    native_sha = pin(native_path, 16 * 1024**2)[1]['sha256']
                    _require(native_sha == run['concolic_report_sha256'], 'Native diagnostic source hash changed')
                    status, reason = native['status'], native.get('reason')
                    _require(isinstance(status, str) and (reason is None or isinstance(reason, str) and len(reason) <= 2048),
                             'Native status or reason is invalid')
                    row['native_attempts'].append(dict(stage=stage, mode=run['mode'], directory=str(worker),
                        native_report=str(native_path), native_report_sha256=native_sha, status=status, reason=reason,
                        worker_status=worker_summary['dse_status'], worker_reason=worker_summary.get('reason'),
                        occurrence=worker_summary['occurrence'], max_steps=worker_summary['max_steps'],
                        budgets=worker_summary['budgets'], **_location(native)))
            if item['status'] == 'NONPROOF':
                terminal_attempts = [attempt for attempt in row['native_attempts'] if
                    attempt['stage'] == ('recapture' if row['classification'] == 'UNKNOWN_UNMAPPED' else 'inversion') and
                    attempt['status'] in ('UNKNOWN', 'UNSAT')]
                row['first_recorded_nonproof_attempt'] = terminal_attempts[0] if terminal_attempts else None
                if row['reason'] is None and terminal_attempts:
                    row['reason'] = terminal_attempts[0]['reason'] or terminal_attempts[0]['worker_reason']
                requests.append(dict(job_id=identifier, analysis=source, request_id=item['request_id'],
                    target_sha256=checked['handoff']['target_sha256'], runtime=runtime,
                    budgets=state['config']['limits'], diagnostic_site=request['observed_site'],
                    desired_outcome=request['desired_outcome'], automatic_retry_authorized=False,
                    executable_selector=None, ir_origin=None,
                    required_action='fresh_handoff_audit_recap_and_explicit_new_attempt_budget'))

        _require(len(summary['analyses']) == len(state['analyses']) and
                 {row['directory'] for row in summary['analyses']} == {row['path'] for row in state['analyses'].values()},
                 'Measured DTA source inventory changed')
        baseline_outcomes, baseline_seeds = set(), set()
        for row in summary['analyses']:
            directory = _canonical(row['directory'])
            _require(pin(directory / 'summary.json')[1]['sha256'] == row['summary_sha256'], 'Measured DTA summary changed')
            original = read(directory / 'summary.json')
            baseline_outcomes.update(dta_dse_eval._pairs(original))
        for data in sources.values():
            baseline_seeds.update(data['seeds'])
        full_outcomes = set()
        _candidate_inventory(summary['candidate_replays'], candidate_jobs)
        for row in summary['candidate_replays']:
            directory = inside(row['directory'], evaluation, directory=True)
            _require(pin(directory / 'summary.json')[1]['sha256'] == row['summary_sha256'], 'Measured candidate summary changed')
            saved, _, output = dta_dse_eval._saved_analysis(directory, read(directory / 'summary.json'),
                candidate=True, max_sites=state['config']['limits']['max_sites'])
            _require(saved['inputs']['seed']['sha256'] == row['sha256'] and
                     hashlib.sha256(output[0]).hexdigest() == row['stdout_sha256'] and output[1] == row['guest_exit'],
                     'Measured candidate data or output changed')
            full_outcomes.update(dta_dse_eval._pairs(saved))
            for source, request in candidate_jobs[row['sha256']]:
                dta_dse_eval._full_environment(_canonical(source), directory,
                    summary['input_path'], row['sha256'])
                site = request['observed_site']
                for case in ('baseline', 'repeat'):
                    groups = parse_trace(directory / case / 'logs/trace.log', summary['input_path'],
                        saved['inputs']['seed']['size'])['groups']
                    matching = [group for group in groups if (group['vcpu'], group['pc'], group['occurrence']) ==
                        (site['vcpu'], site['pc'], site['occurrence'])]
                    _require(len(matching) == 1 and matching[0]['offsets'] == site['offsets'] and
                             matching[0]['outcome'] == request['desired_outcome'], 'Full replay lost its selected outcome')
        _require(summary['DTA_observed_outcomes'] == [list(pair) for pair in sorted(baseline_outcomes)] and
                 summary['DSE_full_run_outcomes'] == [list(pair) for pair in sorted(full_outcomes)] and
                 summary['new_full_run_outcomes'] == [list(pair) for pair in sorted(full_outcomes - baseline_outcomes)],
                 'Measured outcome union changed')
        _require(sorted(path.name for path in (evaluation / 'seeds').iterdir()) == sorted(seeds),
                 'Final evaluation corpus differs from its audited queue')
        for name, expected in seeds.items():
            path, identity = pin(evaluation / 'seeds' / name, 4096)
            _require(identity['sha256'] == name and path.read_bytes() == expected, 'Final evaluated seed changed')
        expected_counts = dict(
            verified_jobs=sum(row['queue_status'] == 'VERIFIED' for row in jobs),
            nonproof_jobs=sum(row['queue_status'] == 'NONPROOF' for row in jobs),
            pending_jobs=sum(row['queue_status'] == 'PENDING' for row in jobs),
            baseline_seed_count=len(baseline_seeds), corpus_seed_count=len(seeds),
            new_seed_count=len(set(seeds) - baseline_seeds), full_validation_runs=2 * len(candidate_jobs))
        _require(all(type(summary.get(name)) is int and summary[name] == value for name, value in expected_counts.items()),
                 'Measured evaluation counts differ from their audited inventories')
        _require(dta_dse_queue._load(queue) == state, 'Queue journal changed during diagnostics')
        for path, (identity, maximum) in inventory.items():
            _require(_pin(path, maximum)[1] == identity, 'Audited evidence changed before diagnostic publication')

    counts = {name: sum(row['classification'] == name for row in jobs) for name in sorted({row['classification'] for row in jobs})}
    report = dict(schema=1, profile=PROFILE, status='AUDITED_DTA_DSE_DIAGNOSTICS', evaluation=str(evaluation),
        queue=str(queue), evaluated_jobs=len(jobs), classifications=counts, jobs=jobs,
        nonproof_jobs=sum(row['queue_status'] == 'NONPROOF' for row in jobs),
        diagnostic_scope='offline_consistency_audit_of_recorded_selected_executions',
        reason_scope='recorded_native_diagnostics_not_independent_causal_proof',
        reason_counts_are_attempt_counts=False, guest_execution=False, SMT_execution=False,
        original_evidence_file_bytes_unchanged=True, original_directory_metadata_unchanged=False,
        automatic_retries_executed=False, universal_equivalence=False, protected_control_channel=False,
        proof_scope_promoted=False, recorded_timings=summary['timings'],
        recorded_timing_scope='historical_aggregate_wall_time_not_a_stage_breakdown')
    reproductions = dict(schema=1, profile=PROFILE, requests=requests,
                         executable_selectors=False, automatic_retry_authorized=False)
    _require(len(json.dumps(report, allow_nan=False).encode()) <= 32 * 1024**2 and
             len(json.dumps(reproductions, allow_nan=False).encode()) <= 32 * 1024**2,
             'Diagnostic publication exceeds its byte budget')
    out.mkdir(parents=True)
    _csv(out / 'jobs.csv', jobs)
    atomic_json(out / 'reproduction-requests.json', reproductions)
    atomic_json(out / 'summary.json', report)
    return report
