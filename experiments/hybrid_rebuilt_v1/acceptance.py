"""Read-only verification of native rebuilt AFL campaign receipts.

Does not execute the target, confirm a hostile-sample sandbox, or claim that
unmatched cases originated from a specific stock mutation stage.
"""
from __future__ import annotations

from collections import Counter
from pathlib import Path

from .forensics import MAX_JSON, evidence_file, json_object, safe_json
from .policy import checked_mask
from .receipt_audit import audit_cases, is_sha, mutation_counts, verified_cycles
from .telemetry import audit_hook_trace


def require(condition, explanation):
    if not condition:
        raise RuntimeError(explanation)


def read_ledger(path):
    # Large DTA masks recur on successive outputs. Keep a single copy of each.
    rows, masks = [], {}
    with evidence_file(path, 256 * 1024**2) as (stream, size):
        while raw := stream.readline(MAX_JSON + 1):
            require(raw.endswith(b'\n') and len(raw) <= MAX_JSON and len(rows) < 262144,
                    'Incomplete or oversized event ledger')
            row = json_object(raw)
            require(isinstance(row.get('event'), str), 'Invalid event record')
            if row['event'] == 'masked_mutation' and 'active_mask' in row:
                mask = checked_mask(row['active_mask'])
                row['active_mask'] = masks.setdefault(mask, mask)
            rows.append(row)
        require(stream.tell() == size, 'Incomplete event ledger')
    return rows


def audit_native_campaign(root, *, expected_target_sha256=None):
    root = Path(root).expanduser().resolve(strict=True)
    campaign, _ = safe_json(root / 'campaign.json')
    hybrid, _ = safe_json(root / 'hybrid-result.json')
    current = 'receipt_observer_version' in hybrid or 'afl_process_window' in campaign
    if current:
        require(type(hybrid.get('receipt_observer_version')) is int and
                hybrid['receipt_observer_version'] == 1, 'Unsupported receipt observer version')
        require(isinstance(campaign.get('campaign_id'), str) and len(campaign['campaign_id']) == 32 and
                campaign['campaign_id'] == hybrid.get('campaign_id'), 'Campaign identity differs')
        require(campaign.get('profile') == 'rebuilt-i386-file-afl-v1' and
                hybrid.get('profile') == 'rebuilt-i386-live-hybrid-v4' and
                is_sha(campaign.get('afl_executable_sha256')), 'Missing rebuilt profile or AFL executable identity')
    require(campaign.get('status') == 'completed' and type(campaign.get('afl_exit')) is int and
            campaign['afl_exit'] == 0,
            'AFL campaign did not complete successfully')
    settings = campaign.get('hybrid')
    mixed = hybrid.get('mixed_mutations')
    require(isinstance(settings, dict) and type(mixed) is bool and settings.get('mixed_mutations') is mixed and
            (current or mixed) and hybrid.get('status') == 'completed', 'Missing completed hybrid campaign')
    stage = campaign.get('afl_stage_policy')
    command = campaign.get('command')
    require(stage in ('fast', 'full') and isinstance(command, list) and '--' in command,
            'Missing AFL stage-policy and command receipts')
    opts = command[:command.index('--')]
    require(('-z' in opts) is (stage == 'fast') and
            campaign.get('enhanced_deterministic_skipped') is (stage == 'fast'),
            'AFL command did not enforce the reported stage policy')
    require(all(type(campaign.get(k)) is int for k in ('cases', 'delivered_cases')) and
            0 <= campaign['delivered_cases'] <= campaign['cases'] <= 4096 and
            type(hybrid.get('processed_cases')) is int and hybrid['processed_cases'] == campaign['delivered_cases'],
            'AFL case/delivery counters disagree')
    tail = campaign['cases'] - campaign['delivered_cases']
    require(tail == 0 or (current and tail == 1 and campaign.get('final_delivery_error')),
            'Unexplained undelivered AFL cases')
    require(is_sha(campaign.get('target_sha256')) and campaign['target_sha256'] == hybrid.get('target_sha256'),
            'Target identity differs across campaign receipts')
    if expected_target_sha256 is not None:
        require(campaign['target_sha256'] == expected_target_sha256, 'Target differs from expected SHA-256')

    hooks = audit_hook_trace(root / 'mutator-hooks.log')
    require(hooks == hybrid.get('mutator_hooks') == campaign.get('hybrid', {}).get('mutator_hooks'),
            'Independent native hook trace differs from saved summaries')
    if not current:
        require(hooks['custom_stage_entries'] > 0 and hooks['custom_fuzz_callbacks'] > 0,
                'No real custom stage entries/fuzz callbacks were observed')
    rows = read_ledger(root / 'events.jsonl')
    counts = Counter(r['event'] for r in rows)
    ids = [r.get('case') for r in rows if r['event'] == 'case_delivered']
    require(all(type(i) is int for i in ids) and ids == list(range(campaign['delivered_cases'])),
            'Case ledger is incomplete or contains out-of-order case IDs')
    skips = counts['mutation_skipped']
    skipped = [row for row in rows if row['event'] == 'mutation_skipped']
    require(all(type(row.get('callback')) is int and 1 <= row['callback'] <= hooks['custom_fuzz_callbacks'] and
                row.get('reason') in ('no_applicable_offsets', 'unchanged_input',
                                      'duplicate_output', 'options_exhausted') and
                is_sha(row.get('parent_sha256')) and type(row.get('parent_length')) is int and
                1 <= row['parent_length'] <= 4096 for row in skipped) and
            len({row['callback'] for row in skipped}) == skips,
            'Invalid skipped callback receipt')
    require(skips == hooks.get('custom_skips', 0) == hybrid.get('mutations_skipped', 0),
            'Skipped callbacks differ across controller and native receipts')
    stop_request = hooks.get('skip_limit_request')
    if stop_request is not None:
        last = stop_request['callback']
        first = last - stop_request['consecutive_skips'] + 1
        recorded = {row['callback'] for row in skipped}
        require(not mixed and all(number in recorded for number in range(first, last + 1)),
                'Skip-limit stop differs from controller receipts or campaign mode')
    require(skips + counts['masked_mutation'] + counts['DSE_seed_returned_to_live_AFL'] ==
            hooks['custom_fuzz_callbacks'],
            'C callbacks do not match controller-produced custom outputs')
    require(hybrid.get('mutations_generated') == counts['masked_mutation'],
            'Mutation generation counter differs from controller event log')
    require(hybrid.get('DSE_triggers') == counts['DSE_trigger'],
            'DSE triggers differ from event ledger')
    if not current:
        require(hybrid.get('matched_DSE_deliveries') == counts['DSE_seed_executed_by_live_AFL'],
                'DSE execution does not match event ledger')
    require(hybrid.get('masked_mutations_delivered', 0) +
            hybrid.get('matched_DSE_deliveries', 0) +
            hybrid.get('unattributed_deliveries', 0) == campaign['delivered_cases'],
            'Delivery-origin accounting is incomplete')
    cycles, live_edges, live_jobs = [], [], []
    history = None
    diversity = None
    if current:
        previous = 0
        for ordinal, row in enumerate(rows, 1):
            stamp = row.get('monotonic_ns')
            require(type(row.get('seq')) is int and row['seq'] == ordinal and type(stamp) is int and
                    stamp >= previous and stamp > 0, 'Event ordinal or monotonic clock changed')
            previous = stamp
        require(hybrid.get('AFL_unacknowledged_cases') == tail, 'Undelivered tail count differs')
        deliveries, edges = audit_cases(root, campaign, hybrid, rows)
        cycles, live_edges, live_jobs, history = verified_cycles(root, campaign, hybrid, rows, deliveries, edges)
        diversity = mutation_counts(rows)
    return {'status': 'passed_case_receipt_audit' if current else 'passed_v51_native_receipt_audit',
            'evidence_level': 'primary_case_receipts' if current else 'legacy_summary',
            'live_cycle_observed': bool(cycles), 'witnessed_cycles': cycles,
            'plateau_cases_while_afl_alive': live_edges, 'dse_jobs_started_while_afl_alive': live_jobs,
            'independent_dse_dispatch_verified': False,
            'candidate_history': history, 'mutations_skipped': skips, 'skip_limit_request': stop_request,
            'mutation_diversity': diversity,
            'scope': 'reviewed_rebuilt_i386_only',
            'target_sha256': hybrid['target_sha256'], 'mixed_mutations': mixed,
            'campaign_id': campaign.get('campaign_id'),
            'afl_executable_sha256': campaign.get('afl_executable_sha256'),
            'afl_stage_policy': stage,
            'delivered_cases': campaign['delivered_cases'],
            'custom_stage_entries': hooks['custom_stage_entries'],
            'custom_fuzz_callbacks': hooks['custom_fuzz_callbacks'],
            'custom_outputs_delivered': (hybrid.get('masked_mutations_delivered', 0) +
                                         hybrid.get('matched_DSE_deliveries', 0)),
            'unattributed_deliveries': hybrid.get('unattributed_deliveries', 0),
            'dse_triggers': hybrid.get('DSE_triggers', 0),
            'dse_callback_lags': hybrid.get('dse_callback_lags', []),
            'stock_stage_provenance_verified': False,
            'hostile_sample_ready': False}
