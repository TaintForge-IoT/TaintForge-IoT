"""Run reproducible five-arm AFL / DTA corpus / focused / DSE / mixed study.

Runs are sequential. No arbitrary packed ELF is executed; the target must be a
known, reviewed static i386 ELF accepted by the existing rebuilt backend.
This script does not promote hostile_sample_ready, Phase 1 or OEP claims.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

if __package__ in (None, ''):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from experiments.hybrid_rebuilt_v1.ablation import (ARMS_V5, aggregate, comparisons, file_sha,
                                                      measure_campaign, write_csv)
from experiments.hybrid_rebuilt_v1.controller import analyze_seed
from taintforge_env.afl_rebuilt import private_path

PROJECT = Path(__file__).resolve().parents[1]
ARM_MODES = {'A': 'afl', 'B': 'afl', 'C1': 'focus',
             'C2': 'hybrid', 'D': 'hybrid-mixed'}


def save(path, data):
    temporary = path.with_name(path.name + '.pending')
    with temporary.open('x') as stream:
        json.dump(data, stream, indent=2, sort_keys=True, allow_nan=False)
        stream.write('\n')
    temporary.replace(path)


def arguments(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('binary', 'seeds', 'qemu', 'plugin', 'flags-receipt', 'out'):
        p.add_argument('--' + name, required=True, type=Path)
    p.add_argument('--replicates', type=int, default=5)
    p.add_argument('--seconds', type=int, default=900)
    p.add_argument('--case-seconds', type=int, default=5)
    p.add_argument('--max-cases', type=int, default=512)
    p.add_argument('--disk-mib', type=int, default=2048)
    p.add_argument('--stall-cases', type=int, default=16)
    p.add_argument('--max-dse-jobs', type=int, default=2)
    p.add_argument('--max-candidates', type=int, default=16)
    p.add_argument('--seed-base', type=int, default=42)
    p.add_argument('--afl-stage-policy', choices=('full', 'fast'), default='fast',
                   help='Shared policy for ALL five arms; fast=-z retains stock havoc')
    p.add_argument('--mixed-custom-fuzz-count', type=int, default=8)
    p.add_argument('--phase1-unpack-output', type=Path)
    p.add_argument('--plan-only', action='store_true')
    return p.parse_args(argv)


def prepare_input(root, seed_files):
    source = root / 'input-seeds'
    source.mkdir()
    hashes = set()
    for path in seed_files:
        raw = path.read_bytes()
        digest = file_sha(path, 4096)
        if not 1 <= len(raw) <= 4096:
            raise ValueError('Invalid AFL source seed size')
        hashes.add(digest)
        (source / digest).write_bytes(raw)
    if len(hashes) != 1:
        raise ValueError('For causal comparison this study requires exactly one distinct initial seed')
    return source, hashes


def create_dta_seeds(root, *, original, source_hash, target, qemu, plugin, max_candidates):
    initial = analyze_seed(root / 'source-DTA', binary=target, qemu=qemu, plugin=plugin,
                           seed=next(original.iterdir()).read_bytes(), max_candidates=max_candidates)
    corpus = root / 'DTA-seeds'
    corpus.mkdir()
    hashes = set(source_hash)
    for name in source_hash:
        (corpus / name).write_bytes((original / name).read_bytes())
    accepted = Path(initial['directory']) / 'accepted-seeds'
    for path in accepted.iterdir():
        if not path.is_file() or path.is_symlink() or file_sha(path, 4096) != path.name:
            raise ValueError('Unverified accepted DTA corpus member')
        raw = path.read_bytes()
        (corpus / path.name).write_bytes(raw)
        hashes.add(path.name)
    return corpus, hashes, initial


def run(args):
    if set(ARM_MODES) != set(ARMS_V5):
        raise RuntimeError('Arm mode inventory changed without study update')
    if not 1 <= args.mixed_custom_fuzz_count <= 16:
        raise ValueError('Mixed mutator attempts must be between 1 and 16')
    if not 1 <= args.replicates <= 10 or not 1 <= args.seconds <= 3600 or \
            not 128 <= args.max_cases <= 4096 or not 256 <= args.disk_mib <= 4096 or \
            not 1 <= args.case_seconds <= 30 or not 4 <= args.stall_cases <= 256 or \
            not 1 <= args.max_dse_jobs <= 8 or not 1 <= args.max_candidates <= 128 or \
            not 1 <= args.seed_base <= 2147483647 - args.replicates:
        raise ValueError('Requested study parameters are outside bounded runner limits')
    out = private_path(args.out)
    if out.exists():
        raise ValueError('Use a new ablation output directory')
    paths = {name: getattr(args, name.replace('-', '_')).expanduser().resolve(strict=True)
             for name in ('binary', 'seeds', 'qemu', 'plugin', 'flags-receipt')}
    if not paths['seeds'].is_dir() or not (Path(str(paths['plugin']) + '.runtime.json')).is_file():
        raise ValueError('Missing source corpus or QEMU plugin runtime manifest')
    entries = sorted(paths['seeds'].iterdir())
    if len(entries) != 1 or any(not path.is_file() or path.is_symlink() for path in entries):
        raise ValueError('Ablation requires exactly one reviewed initial seed file')
    hashes = {name: file_sha(path) for name, path in paths.items() if path.is_file()}
    target_sha = hashes['binary']
    # Latin-square rotation: each arm occupies each position once in 5 repeats.
    runs = [{'replicate': repetition, 'arm': arm, 'afl_seed': args.seed_base + repetition - 1}
            for repetition in range(1, args.replicates + 1)
            for arm in ARMS_V5[(repetition - 1) % len(ARMS_V5):] +
                       ARMS_V5[:(repetition - 1) % len(ARMS_V5)]]
    plan = {'schema': 2, 'profile': 'rebuilt_hybrid_ablation_v2',
            'arm_configuration': {
                'A': {'corpus': 'initial', 'mutator': 'stock', 'live_dse': False, 'cli_mode': ARM_MODES['A']},
                'B': {'corpus': 'DTA', 'mutator': 'stock', 'live_dse': False, 'cli_mode': ARM_MODES['B']},
                'C1': {'corpus': 'DTA', 'mutator': 'legacy_focus_only', 'live_dse': False, 'cli_mode': ARM_MODES['C1']},
                'C2': {'corpus': 'DTA', 'mutator': 'legacy_focus_only', 'live_dse': True, 'cli_mode': ARM_MODES['C2']},
                'D': {'corpus': 'DTA', 'mutator': 'stock_plus_adaptive_focus', 'live_dse': True, 'cli_mode': ARM_MODES['D']}}, 'target_sha256': target_sha,
            'input_sha256': file_sha(entries[0], 4096), 'runtime_hashes': hashes,
            'replicates': args.replicates, 'cases_cap': args.max_cases,
            'afl_stage_policy_all_arms': args.afl_stage_policy,
            'mixed_custom_fuzz_count': args.mixed_custom_fuzz_count,
            'seconds_AFL_per_run': args.seconds, 'requested_runs': runs,
            'source_status': 'reviewed_ELF_required', 'hostile_sample_ready': False,
            'phase1_executed_in_campaign': False,
            'maximum_reserved_disk_mib': len(runs) * args.disk_mib,
            'phase1_unpack_source': str(args.phase1_unpack_output) if args.phase1_unpack_output else None,
            'caveat': ('C1 versus C2 isolates live DSE under legacy custom-only mutation; '
                       'C2 versus D changes both stock/custom mixing and focused scheduling; '
                       'neither comparison proves performance advantage from one run')}
    if args.plan_only:
        print(json.dumps(plan, indent=2, sort_keys=True))
        return plan
    if shutil.disk_usage(out.parent).free < len(runs) * args.disk_mib * 1024**2:
        raise ValueError('Insufficient free disk for the bounded multi-run study (see --plan-only)')
    out.mkdir(mode=0o700)
    save(out / 'study-plan.json', plan)
    completed = []
    summary = dict(plan, status='running', finished_runs=0, results=[])
    try:
        original, source_set = prepare_input(out, entries)
        dta_started = time.monotonic()
        dta_corpus, expected_dta_set, initial = create_dta_seeds(out,
            original=original, source_hash=source_set, target=paths['binary'],
            qemu=paths['qemu'], plugin=paths['plugin'], max_candidates=args.max_candidates)
        summary['DTA_preparation_seconds'] = round(time.monotonic() - dta_started, 3)
        summary['DTA_source_summary_sha256'] = initial['DTA_summary_sha256']
        summary['DTA_seed_sha256'] = sorted(expected_dta_set)
        save(out / 'prepared-corpus.json', {'source_seed_sha256': sorted(source_set),
             'DTA_seed_sha256': sorted(expected_dta_set), 'target_sha256': target_sha,
             'DTA_summary_sha256': initial['DTA_summary_sha256']})
        for item in runs:
            # A/B/C are not comparable if QEMU, ELF, DTA plugin or flags change
            # between arms. Fail closed before allocating another campaign.
            for role, expected_hash in hashes.items():
                if file_sha(paths[role]) != expected_hash:
                    raise RuntimeError('Study source changed before next arm: ' + role)
            arm, replicate = item['arm'], item['replicate']
            campaign = out / 'runs' / f'{replicate:02d}-{arm}'
            campaign.parent.mkdir(exist_ok=True)
            corpus = original if arm == 'A' else dta_corpus
            mode = ARM_MODES[arm]
            command = [sys.executable, '-B', str(PROJECT / 'scripts/run_afl_rebuilt.py'),
                'campaign', '--mode', mode,
                '--binary', str(paths['binary']), '--seeds', str(corpus),
                '--qemu', str(paths['qemu']), '--plugin', str(paths['plugin']),
                '--out', str(campaign), '--seconds', str(args.seconds),
                '--case-seconds', str(args.case_seconds), '--max-cases', str(args.max_cases),
                '--disk-mib', str(args.disk_mib), '--afl-seed', str(item['afl_seed']),
                '--afl-stage-policy', args.afl_stage_policy]
            if args.phase1_unpack_output is not None:
                command += ['--phase1-unpack-output', str(args.phase1_unpack_output)]
            if arm in ('C1', 'C2', 'D'):
                command += ['--dta-source-sha256', plan['input_sha256']]
                command += ['--stall-cases', str(args.stall_cases),
                    '--max-dse-jobs', str(args.max_dse_jobs),
                    '--max-candidates', str(args.max_candidates)]
                if arm in ('C2', 'D'):
                    command += ['--flags-receipt', str(paths['flags-receipt'])]
                if arm == 'D':
                    command += ['--custom-fuzz-count', str(args.mixed_custom_fuzz_count)]
            environment = dict(os.environ, PYTHONPATH=str(PROJECT), PYTHONDONTWRITEBYTECODE='1',
                               PYTHONHASHSEED='0')
            logfile = out / f'{replicate:02d}-{arm}.log'
            print(f'ABLATION {replicate}/{args.replicates} arm={arm} afl_seed={item["afl_seed"]}', flush=True)
            start = time.monotonic()
            with logfile.open('xb') as log:
                result = subprocess.run(command, cwd=PROJECT, env=environment,
                    stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT, check=False)
            elapsed = time.monotonic() - start
            if result.returncode:
                raise RuntimeError(f'Ablation arm {arm} replication {replicate} failed; inspect {logfile}')
            for role, expected_hash in hashes.items():
                if file_sha(paths[role]) != expected_hash:
                    raise RuntimeError('Study source changed during AFL arm: ' + role)
            if arm in ('B', 'C1', 'C2', 'D'):
                actual_seeds = {path.name for path in (campaign / 'seeds').iterdir()}
                if actual_seeds != expected_dta_set or any(
                    file_sha(path, 4096) != path.name
                    for path in (campaign / 'seeds').iterdir()):
                    raise RuntimeError('DTA corpus differs between study arms')
            receipt, _ = __import__('experiments.hybrid_rebuilt_v1.forensics',
                                  fromlist=['safe_json']).safe_json(campaign / 'campaign.json')
            expected = plan['arm_configuration'][arm]
            if receipt.get('afl_stage_policy') != args.afl_stage_policy or \
                    receipt.get('enhanced_deterministic_skipped') is not (args.afl_stage_policy == 'fast'):
                raise RuntimeError('Ablation AFL stage policy differs from shared plan')
            if arm == 'D' and receipt.get('hybrid', {}).get('custom_fuzz_count') != args.mixed_custom_fuzz_count:
                raise RuntimeError('Ablation mixed custom fuzz count differs from plan')
            if expected['cli_mode'] != mode or (arm in ('A', 'B') and receipt.get('hybrid') is not None) or (
                arm not in ('A', 'B') and
                (receipt.get('hybrid', {}).get('mixed_mutations') != (arm == 'D') or
                 receipt.get('hybrid', {}).get('live_dse_enabled') != expected['live_dse'] or
                 receipt.get('hybrid', {}).get('DTA_analysis_seed_sha256') != plan['input_sha256'])):
                raise RuntimeError('Ablation mode receipt differs from requested arm')
            metrics = measure_campaign(campaign, target_sha256=target_sha)
            if metrics['afl_seed'] != item['afl_seed']:
                raise ValueError('AFL RNG seed receipt does not match requested replicate')
            row = {**item, 'metrics': metrics, 'total_elapsed_seconds': round(elapsed, 3),
                   'log_path': str(logfile)}
            completed.append(row)
            summary.update(finished_runs=len(completed), results=[
                {k: value for k, value in record.items() if k != 'metrics'} | {
                    'delivered': record['metrics']['delivered'],
                    'final_branch_outcomes': record['metrics']['final_branch_outcomes'],
                    'final_map_slots': record['metrics']['final_map_slots']}
                for record in completed])
            save(out / 'study-status.json', summary)
        aligned = comparisons(completed, required_arms=ARMS_V5)
        write_csv(out / 'ablation-comparison.csv', aligned)
        summary.update(status='completed', matched_case_comparison=aligned,
                       descriptive_statistics=aggregate(aligned),
                       conclusion='Descriptive differences only; no statistical significance claim',
                       result_scope='same_case_budget_and_rng_seed_per_replicate_no_phase1')
        save(out / 'ablation-summary.json', summary)
        print(json.dumps({'status': 'completed', 'comparison': aligned,
                          'descriptive_statistics': summary['descriptive_statistics']}, indent=2))
        return summary
    except BaseException as exc:
        summary.update(status='failed', error=f'{type(exc).__name__}: {exc}',
                       finished_runs=len(completed))
        save(out / 'ablation-summary.json', summary)
        raise


def main(argv=None):
    args = arguments(argv)
    try:
        run(args)
        return 0
    except (OSError, RuntimeError, ValueError, KeyError) as exc:
        print(f'ABLATION_FAILED: {exc}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
