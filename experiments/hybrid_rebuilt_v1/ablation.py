"""Validated comparable coverage measurements from isolated rebuilt AFL campaigns.

Counts are observed guest conditional (PC, outcome) pairs and AFL bitmap slots.
They are not discovered vulnerabilities or deduplicated native basic blocks.
"""
from __future__ import annotations

import csv
from hashlib import sha256
import json
from pathlib import Path
import stat
from statistics import mean, median

from .policy import MAP_SIZE
from .forensics import safe_json


def file_sha(path, maximum=64 * 1024 * 1024):
    path = Path(path)
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > maximum:
        raise ValueError('Untrusted or oversized campaign artifact: ' + str(path))
    return sha256(path.read_bytes()).hexdigest()


def pairs(values):
    if not isinstance(values, list):
        raise ValueError('Invalid branch outcome inventory')
    result = set()
    for value in values:
        if not isinstance(value, (list, tuple)) or len(value) != 2 or \
                type(value[0]) is not int or not 0 < value[0] <= 0xffffffff or \
                type(value[1]) not in (bool, int) or value[1] not in (0, 1):
            raise ValueError('Invalid observed branch outcome pair')
        result.add((value[0], int(value[1])))
    return result


def bitmap_merge(seen, incoming):
    if len(incoming) != MAP_SIZE:
        raise ValueError('Untrusted map length')
    for index, value in enumerate(incoming):
        if value:
            seen[index] = 1


def read_verified_case(path, *, expected_sha, transport=False):
    """Check input, target, coverage and transport, never silently count failures."""
    path = Path(path)
    result, _ = safe_json(path / 'result.json')
    if result.get('status') != 'passed':
        return None
    data = (path / 'input').read_bytes()
    if not 1 <= len(data) <= 4096 or sha256(data).hexdigest() != result.get('input_sha256'):
        raise ValueError('Case input evidence does not match: ' + str(path))
    binding, _ = safe_json(path / 'config/rebuilt_binding.json')
    from taintforge_env.afl_rebuilt import contract
    if binding.get('target_sha256') != expected_sha or             binding.get('input_sha256') != result['input_sha256'] or             binding.get('attempt_contract_sha256') != contract(binding):
        raise ValueError('Case target/input/contract identity mismatch: ' + str(path))
    record = result.get('coverage')
    if not isinstance(record, dict) or record.get('status') != 'verified':
        raise ValueError('Unverified case coverage: ' + str(path))
    if result.get('phase1_executed') is not False or result.get('hostile_sample_ready') is not False:
        raise ValueError('Unsupported security claim in case receipt')
    bitmap = (path / 'coverage.map').read_bytes()
    if len(bitmap) != MAP_SIZE or sha256(bitmap).hexdigest() != record.get('map_sha256'):
        raise ValueError('Case bitmap identity mismatch: ' + str(path))
    if transport:
        trans, _ = safe_json(path / 'transport.json')
        if trans.get('status') != 'delivered' or trans.get('input_sha256') != result['input_sha256'] or \
                trans.get('coverage_sha256') != record['map_sha256'] or \
                trans.get('case') != int(path.name) or \
                trans.get('feedback') != 'verified_guest_coverage':
            raise ValueError('Case transport identity mismatch: ' + str(path))
    return pairs(record['branch_outcomes']), bitmap


def measure_campaign(campaign, *, target_sha256):
    root = Path(campaign).expanduser().resolve(strict=True)
    manifest, manifest_sha = safe_json(root / 'campaign.json')
    if manifest.get('status') != 'completed' or manifest.get('afl_exit') != 0 or \
            manifest.get('target_sha256') != target_sha256 or \
            manifest.get('phase1_executed') is not False:
        raise ValueError('Campaign is not a completed, identity-matched rebuilt ELF run')
    # Start from the *observed* calibrated corpus, not from an unverifiable
    # comparison of hash-only baseline map summaries.
    global_pairs = set()
    bits = bytearray(MAP_SIZE)
    baseline_cases = sorted((root / 'baseline').iterdir())
    if not baseline_cases:
        raise ValueError('No recorded baseline executions')
    for path in baseline_cases:
        if not path.is_dir() or path.is_symlink():
            raise ValueError('Unexpected baseline evidence path')
        report = read_verified_case(path, expected_sha=target_sha256)
        if report is None:
            raise ValueError('Unverified baseline execution')
        branch_set, bitmap = report
        global_pairs.update(branch_set)
        bitmap_merge(bits, bitmap)
    baseline_doc, _ = safe_json(root / 'baseline.json')
    if baseline_doc.get('stable') is not True or \
            pairs(baseline_doc.get('branch_outcomes')) != global_pairs:
        raise ValueError('Baseline branch outcomes changed')
    cases = root / 'cases'
    paths = sorted(path for path in cases.iterdir() if path.is_dir())
    if len(paths) != manifest['cases']:
        raise ValueError('Case inventory does not match the campaign receipt')
    history = [{'case': 0, 'branch_outcomes': len(global_pairs), 'map_slots': sum(bits)}]
    delivered = 0
    quarantined = 0
    for path in paths:
        receipt, _ = safe_json(path / 'result.json')
        if receipt['status'] == 'quarantined':
            quarantined += 1
            # Quarantine is never counted as coverage; it is not a target crash.
            if (path / 'transport.json').is_file():
                trans, _ = safe_json(path / 'transport.json')
                if trans.get('status') == 'delivered' and trans.get('feedback') == 'zero_unverified':
                    delivered += 1
                    history.append({'case': delivered, 'branch_outcomes': len(global_pairs), 'map_slots': sum(bits)})
            continue
        if not (path / 'transport.json').is_file():
            continue  # Completed but not sent to AFL before the stop deadline.
        result = read_verified_case(path, expected_sha=target_sha256, transport=True)
        if result is None:
            raise ValueError('Completed case with unsupported status')
        new_pairs, bitmap = result
        global_pairs.update(new_pairs)
        bitmap_merge(bits, bitmap)
        delivered += 1
        history.append({'case': delivered, 'branch_outcomes': len(global_pairs), 'map_slots': sum(bits)})
    if delivered != manifest['delivered_cases'] or quarantined != manifest.get('quarantined_cases', 0):
        raise ValueError('Delivered/quarantine accounting does not match the manifest')
    return {'schema': 1, 'campaign': str(root), 'campaign_sha256': manifest_sha,
            'target_sha256': target_sha256, 'afl_seed': manifest.get('afl_seed'),
            'delivered': delivered, 'all_attempted_cases': manifest['cases'],
            'quarantined': quarantined, 'baseline_branch_outcomes': len(pairs(baseline_doc['branch_outcomes'])),
            'final_branch_outcomes': len(global_pairs), 'final_map_slots': sum(bits),
            'history': history, 'scope': 'observed_guest_conditional_pairs_and_AFL_map_slots',
            'verified_target_crashes': False}


def at_case(report, count):
    if count < 0 or report['delivered'] < count:
        raise ValueError('Cannot compare at an unobserved execution count')
    return report['history'][count]


ARMS_V5 = ('A', 'B', 'C1', 'C2', 'D')


def comparisons(reports, *, required_arms=('A', 'B', 'C')):
    """Require complete arms and compare at one common delivered budget.

    Explicit required_arms retains read-only compatibility with old A/B/C
    reports, while the v5 runner always requests all five arms.
    """
    if len(set(required_arms)) != len(required_arms) or not required_arms:
        raise ValueError('Invalid ablation arm inventory')
    by_rep = {}
    for record in reports:
        by_rep.setdefault(record['replicate'], {})[record['arm']] = record
    final = []
    for replicate, arms in sorted(by_rep.items()):
        if set(arms) != set(required_arms):
            raise ValueError(f'Missing or extra ablation arm in replicate {replicate}')
        if len({row['metrics']['target_sha256'] for row in arms.values()}) != 1 or \
                len({row['metrics']['afl_seed'] for row in arms.values()}) != 1:
            raise ValueError('Ablation target or RNG identity diverged')
        common = min(row['metrics']['delivered'] for row in arms.values())
        if common < 1:
            raise ValueError('Cannot compare replicates without delivered executions')
        for arm, row in sorted(arms.items()):
            values = at_case(row['metrics'], common)
            final.append({'replicate': replicate, 'arm': arm,
                          'afl_seed': row['metrics']['afl_seed'],
                          'common_delivered_executions': common,
                          'branch_outcomes': values['branch_outcomes'],
                          'map_slots': values['map_slots'],
                          'total_elapsed_seconds': row['total_elapsed_seconds'],
                          'campaign_dir': row['metrics']['campaign']})
    return final


def aggregate(rows):
    arms = tuple(sorted({item['arm'] for item in rows}))
    if not arms:
        raise ValueError('Empty ablation comparison')
    return {arm: {metric: {'mean': mean(item[metric] for item in rows if item['arm'] == arm),
                           'median': median(item[metric] for item in rows if item['arm'] == arm)}
                  for metric in ('branch_outcomes', 'map_slots', 'total_elapsed_seconds')}
            for arm in arms}


def write_csv(path, rows):
    fields = ('replicate', 'arm', 'afl_seed', 'common_delivered_executions',
              'branch_outcomes', 'map_slots', 'total_elapsed_seconds', 'campaign_dir')
    with Path(path).open('x', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
