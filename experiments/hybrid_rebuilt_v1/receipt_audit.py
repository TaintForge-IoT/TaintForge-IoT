"""Check recorded deliveries and event times without starting the target or the solver."""
from __future__ import annotations

from collections import Counter
import re

from .forensics import read_bytes, safe_json
from .policy import CoveragePlateau, MAX_INPUT, checked_mask, digest, require
from .receipts import read_delivery, verify_case_target


def is_sha(value):
    return isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value) is not None


def mutation_counts(rows):
    revision = attempts = unchanged = 0
    outputs = {}
    union, focused = (), set()
    for row in rows:
        if row['event'] in ('live_AFL_bound', 'DTA_mask_refreshed'):
            refreshing = row['event'] == 'DTA_mask_refreshed'
            revision += int(refreshing)
            union = checked_mask(row['mask' if refreshing else 'initial_mask'])
            focused = {checked_mask(mask) for mask in row['focused_site_masks']}
            require(union and all(mask and set(mask) < set(union) for mask in focused),
                    'Invalid DTA mask revision')
        if row['event'] != 'masked_mutation':
            continue
        parent, output = row['parent_sha256'], row['input_sha256']
        scope = row['scheduling_scope']
        active = checked_mask(row['active_mask'])
        require(is_sha(parent) and is_sha(output) and
                ((scope == 'branch_focus' and active in focused) or
                 (scope == 'full_union_fallback' and active == union)) and
                type(row['offset']) is int and row['offset'] in active, 'Invalid masked-mutation receipt')
        outputs.setdefault((revision, parent, output), set()).add(scope)
        attempts += 1
        unchanged += int(parent == output)
    return {'attempts': attempts, 'unique_per_parent_and_revision': len(outputs),
            'duplicate_attempts': attempts - len(outputs), 'unchanged_attempts': unchanged,
            'outputs_seen_in_both_scopes': sum(len(scopes) == 2 for scopes in outputs.values())}


def by_id(rows, label, key):
    result = {}
    for row in rows:
        if row['event'] == label:
            number = row.get(key)
            require(type(number) is int and number >= 0 and number not in result,
                    f'Invalid or repeated {key} in {label}')
            result[number] = row
    return result


def audit_cases(root, campaign, hybrid, rows):
    folder = root / 'cases'
    require(folder.is_dir() and not folder.is_symlink(), 'Missing case directory')
    names = {f'{i:08d}' for i in range(campaign['cases'])}
    require({p.name for p in folder.iterdir()} == names, 'Case directories differ from the manifest')
    plateau = CoveragePlateau(campaign['hybrid']['stall_cases'])
    edges = by_id(rows, 'coverage_plateau_reached', 'case')
    deliveries = {}
    matched = Counter()
    attempts = set()
    quarantines = matched_quarantines = 0
    checked_edges = set()
    active_edge = None
    pending_kind = pending_sha = None
    pending_matched = False
    verified_payloads = set()
    for row in rows:
        if row['event'] == 'masked_mutation':
            pending_kind, pending_sha, pending_matched = 'masked', row['input_sha256'], False
        elif row['event'] == 'mutation_skipped':
            pending_kind, pending_sha, pending_matched = None, None, False
        elif row['event'] == 'DSE_seed_returned_to_live_AFL':
            pending_kind, pending_sha, pending_matched = 'dse', row['candidate_sha256'], False
        elif row['event'] == 'DSE_seed_executed_by_live_AFL':
            verified_payloads.add(row['sha256'])
        if row['event'] == 'DSE_trigger':
            lag = row.get('plateau_callback_lag')
            require(active_edge is not None and plateau.stalled and
                    row.get('completed_cases') == len(deliveries) and
                    row.get('plateau_quiet') == plateau.quiet and row.get('threshold') == plateau.threshold and
                    isinstance(lag, dict) and lag.get('plateau_case') == active_edge and
                    lag.get('completed_cases_at_DSE_trigger') == len(deliveries) and
                    lag.get('completed_case_lag') == len(deliveries) - active_edge - 1,
                    'DSE trigger does not refer to the active plateau')
        if row['event'] in ('DSE_candidate_verified', 'DSE_job_failed'):
            plateau.quiet = 0
            active_edge = None
        if row['event'] != 'case_delivered':
            continue
        index = row['case']
        path = folder / f'{index:08d}'
        receipt, bitmap = read_delivery(path, index, verify_native=True)
        binding_sha = verify_case_target(path, campaign['target_sha256'], receipt)
        require(receipt.campaign_id == row.get('campaign_id') == campaign['campaign_id'] and
                receipt.attempt_id == row.get('attempt_id') and receipt.attempt_id not in attempts,
                f'Wrong campaign or repeated attempt at case {index}')
        attempts.add(receipt.attempt_id)
        kind = row['matched_kind']
        first_verified_retry = (pending_kind == 'dse' and not receipt.quarantined and
                                pending_sha not in verified_payloads)
        matches = receipt.input_sha256 == pending_sha and (not pending_matched or first_verified_retry)
        require(kind == (pending_kind if matches else None) and row['matched_mutator_output'] is matches,
                f'Invalid delivery match at case {index}')
        if matches:
            pending_matched = True
        require(row['input_sha256'] == receipt.input_sha256 and
                row['coverage_sha256'] == receipt.coverage_sha256 and
                row.get('result_sha256') == receipt.result_sha256 and
                row.get('binding_sha256') == binding_sha and
                row.get('transport_sha256') == receipt.transport_sha256 and
                row.get('execution_started_ns') == receipt.started_ns and
                row.get('execution_finished_ns') == receipt.finished_ns and
                row['quarantined'] is receipt.quarantined and type(row['guest_exit']) is type(receipt.guest_exit) and
                row['guest_exit'] == receipt.guest_exit and
                receipt.sent_ns is not None and receipt.sent_ns == row['transport_sent_ns'] and
                receipt.sent_ns <= row['monotonic_ns'] and
                row['observed_by'] in ('transport', 'catch_up', 'callback', 'finalize'),
                f'Case {index} differs from the observation ledger')
        eligible = not receipt.quarantined and kind != 'dse' and (hybrid['mixed_mutations'] or kind == 'masked')
        was_stalled = plateau.stalled
        fresh = 0 if receipt.quarantined else plateau.observe(bitmap, eligible=eligible)
        require(row['plateau_eligible'] is eligible and row['fresh_hitcount_slots'] == fresh,
                f'Coverage history differs at case {index}')
        if not was_stalled and plateau.stalled:
            edge = edges.get(index)
            require(edge and edge['seq'] < row['seq'] and edge['observed_by'] == row['observed_by'] and
                    edge['eligible_cases'] == plateau.eligible and edge['threshold'] == plateau.threshold and
                    edge['transport_sent_ns'] == receipt.sent_ns <= edge['monotonic_ns'],
                    f'Plateau evidence differs at case {index}')
            checked_edges.add(index)
            active_edge = index
        elif not plateau.stalled:
            active_edge = None
        matched[kind] += 1
        quarantines += int(receipt.quarantined)
        matched_quarantines += int(receipt.quarantined and kind == 'dse')
        deliveries[index] = row
    require(checked_edges == edges.keys() and plateau.observations == hybrid['plateau_observations'],
            'Unsubstantiated plateau events or observation count')
    require(matched['dse'] == hybrid['matched_DSE_deliveries'] and
            matched['masked'] == hybrid['masked_mutations_delivered'] and
            matched[None] == hybrid['unattributed_deliveries'] and
            matched_quarantines == hybrid['matched_quarantined_DSE_deliveries'],
            'Delivery match or quarantine counters differ from the ledger')
    # A timer may close the final transport after the guest has already returned.
    if campaign['cases'] > campaign['delivered_cases']:
        tail = folder / f"{campaign['delivered_cases']:08d}"
        transport = tail / 'transport.json'
        require(not tail.is_symlink() and not transport.exists() and not transport.is_symlink(),
                'Cancelled tail has a transport receipt')
        result, _ = safe_json(tail / 'result.json')
        require(result.get('status') in ('quarantined', 'passed'), 'Invalid final guest result')
        quarantines += int(result['status'] == 'quarantined')
    require(quarantines == campaign['quarantined_cases'], 'Quarantine inventory differs from the manifest')
    return deliveries, edges


def verify_candidate(root, job, sha, target):
    number, request = job['job'], job['request_id']
    evidence = job['evidence']
    require(is_sha(sha) and is_sha(request) and isinstance(evidence, dict) and job.get('status') == 'VERIFIED' and
            evidence.get('candidate_sha256') == sha and evidence.get('target_sha256') == target and
            evidence.get('request_id') == request and evidence.get('status') == 'VERIFIED' and
            evidence.get('replayed_and_reaudited') is True, 'Candidate evidence does not match job')
    directory = root / 'dse' / f'job-{number:02d}'
    for parent in (root / 'dse', directory, directory / 'seeds', root / 'verified-dse-seeds'):
        require(parent.is_dir() and not parent.is_symlink(), 'Invalid DSE evidence directory')
    summary, checksum = safe_json(directory / 'summary.json')
    manifest, _ = safe_json(directory / 'manifest.json')
    require(checksum == evidence.get('summary_sha256') and summary.get('status') == 'passed' and
            summary.get('dse_status') == 'VERIFIED' and summary.get('new_seed_count') == 1 and
            summary.get('source_and_worker_evidence_reaudited') is True and
            manifest.get('target_sha256') == target and
            summary.get('selected_request_ids') == manifest.get('selected_request_ids') == [request] and
            isinstance(summary.get('jobs'), list) and len(summary['jobs']) == 1 and
            isinstance(summary['jobs'][0], dict) and summary['jobs'] == manifest.get('jobs') and
            [r.get('candidate_sha256') for r in summary['jobs']
             if r.get('status') == 'VERIFIED' and r.get('request_id') == request] == [sha] and
            {'sha256': sha, 'origin': 'verified_isolated_DSE'} in manifest['seeds'],
            'Recorded DSE worker result or target differs from candidate')
    for path in (directory / 'seeds' / sha, root / 'verified-dse-seeds' / sha):
        require(digest(read_bytes(path, MAX_INPUT)) == sha, 'Published candidate bytes changed')


def verified_cycles(root, campaign, hybrid, rows, deliveries, edges):
    window = campaign['afl_process_window']
    start, alive, exit_seen = (window[k] for k in ('started_ns', 'last_alive_ns', 'exit_observed_ns'))
    require(window.get('clock') == 'host_monotonic_ns' and type(window.get('pid')) is int and
            window['pid'] > 0 and type(start) is int and type(exit_seen) is int and
            0 < start <= exit_seen and (alive is None or type(alive) is int and start <= alive <= exit_seen),
            'Invalid AFL process observation window')
    triggers = by_id(rows, 'DSE_trigger', 'job')
    verified = by_id(rows, 'DSE_candidate_verified', 'job')
    failed = by_id(rows, 'DSE_job_failed', 'job')
    offers = by_id(rows, 'DSE_seed_returned_to_live_AFL', 'job')
    executions = by_id(rows, 'DSE_seed_executed_by_live_AFL', 'job')
    require(isinstance(hybrid['DSE_jobs'], list) and all(isinstance(j, dict) and
            type(j.get('job')) is int and 1 <= j['job'] <= 8 and j.get('status') in ('VERIFIED', 'FAILED')
            for j in hybrid['DSE_jobs']), 'Invalid DSE job summary')
    jobs = {job['job']: job for job in hybrid['DSE_jobs']}
    require(len(jobs) == len(hybrid['DSE_jobs']) == len(triggers) and jobs.keys() == triggers.keys() and
            verified.keys() == {n for n, j in jobs.items() if j['status'] == 'VERIFIED'} and
            failed.keys() == jobs.keys() - verified.keys() and
            executions.keys() <= offers.keys() <= verified.keys(), 'DSE job inventory differs from ledger')
    require(len(executions) == hybrid['verified_DSE_payloads'] == len(hybrid['DSE_live_executions']),
            'Verified DSE execution count differs from the ledger')
    live_edges = [i for i, e in edges.items() if e['observed_by'] == 'transport' and
                  alive is not None and start <= e['transport_sent_ns'] <= e['monotonic_ns'] <= alive]
    live_jobs = []
    witnessed = []
    history = []
    seen_candidates = set()
    for number, job in jobs.items():
        trigger = triggers[number]
        outcome = verified[number] if number in verified else failed[number]
        began = job['worker_call_started_ns']
        edge = edges[trigger['plateau_callback_lag']['plateau_case']]
        require(trigger['request_id'] == job['request_id'] and trigger.get('dispatch_source') == 'mutator_callback' and
                all(outcome.get(k) == v for k, v in job.items()) and edge['seq'] < trigger['seq'] < outcome['seq'] and
                type(began) is int and trigger['monotonic_ns'] <= began <= outcome['monotonic_ns'],
                'DSE job differs from its trigger or worker record')
        if alive is not None and start <= began <= alive:
            live_jobs.append(number)
        if number in failed:
            continue
        ended = job['worker_call_finished_ns']
        require(type(ended) is int and began <= ended <= outcome['monotonic_ns'], 'Invalid worker completion time')
        sha = job['candidate_sha256']
        verify_candidate(root, job, sha, campaign['target_sha256'])
        require(sha not in seen_candidates, 'Multiple verified jobs claim the same candidate SHA-256')
        seen_candidates.add(sha)
        candidate = {'job': number, 'seed_sha256': sha, 'verified_ns': outcome['monotonic_ns'],
                     'offered_ns': None, 'matching_attempts': []}
        history.append(candidate)
        if number not in offers:
            continue
        offer = offers[number]
        require(all(offer.get(k) == v for k, v in job.items()) and outcome['seq'] < offer['seq'],
                'DSE offer differs from the verified result')
        candidate['offered_ns'] = offer['monotonic_ns']
        delivered = None
        for case in deliveries.values():
            if (case['input_sha256'] != sha or case['execution_started_ns'] < offer['monotonic_ns']
                    or case['seq'] <= offer['seq']):
                continue
            candidate['matching_attempts'].append({
                'case': case['case'], 'attempt_id': case['attempt_id'],
                'quarantined': case['quarantined'], 'coverage_sha256': case['coverage_sha256']})
            if delivered is None and not case['quarantined']:
                delivered = case
        if delivered is None:
            require(number not in executions, 'No verified guest execution after this offer')
            continue
        executed = executions.get(number)
        require(executed and executed.get('match_basis') == 'input_sha256_after_offer' and executed['sha256'] == sha and
                type(executed['case']) is int and executed['case'] == delivered['case'] and delivered['seq'] < executed['seq'] and
                delivered['coverage_sha256'] == executed['coverage_sha256'] and
                delivered['guest_exit'] == executed['guest_exit'] and
                any(isinstance(item, dict) and all(executed.get(k) == item.get(k) for k in
                        ('job', 'case', 'sha256', 'coverage_sha256', 'guest_exit', 'match_basis'))
                    for item in hybrid['DSE_live_executions']), 'Unverified candidate execution receipt')
        if (edge['case'] in live_edges and delivered['observed_by'] == 'transport' and
                number in live_jobs and executed['monotonic_ns'] <= alive):
            witnessed.append({'job': number, 'plateau_case': edge['case'], 'case': executed['case'],
                              'seed_sha256': sha, 'coverage_sha256': delivered['coverage_sha256'],
                              'dispatch_source': trigger['dispatch_source']})
    return witnessed, live_edges, live_jobs, history
