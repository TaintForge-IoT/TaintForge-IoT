"""Run stock AFL or the audited live hybrid controller on recovered static i386 ELF.

This is a bounded, isolated file-input research profile. It does not execute
Phase 1 or claim to be safe for unknown hostile samples without further review.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

# Support direct execution from any working directory without PYTHONPATH.
if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from taintforge_env import afl_rebuilt as backend


def prepare_hybrid(root, *, binary, qemu, plugin, flags_receipt,
                   stall_cases, max_dse_jobs, max_candidates, mixed=False, live_dse=True,
                   dta_source_sha256=None, custom_fuzz_count=None):
    from experiments.hybrid_rebuilt_v1.controller import LiveRebuiltController, analyze_seed
    from experiments.hybrid_rebuilt_v1.mutator_build import build_mutator
    from experiments.hybrid_rebuilt_v1.policy import digest

    root = backend.private_path(root)
    manifest = backend.read_json(root / 'campaign.json')
    backend.require(manifest['status'] == 'prepared' and manifest['target_sha256'] == backend.digest(binary),
                    'Hybrid preflight requires the same prepared ELF')
    originals = sorted((root / 'seeds').iterdir())
    backend.require(originals, 'Hybrid requires an initial corpus')
    if dta_source_sha256 is not None:
        backend.require(type(dta_source_sha256) is str and len(dta_source_sha256) == 64 and
                        all(c in '0123456789abcdef' for c in dta_source_sha256),
                        'Invalid pinned DTA analysis source identity')
        selected = root / 'seeds' / dta_source_sha256
        backend.require(selected in originals and backend.digest(selected) == dta_source_sha256,
                        'Pinned DTA analysis source missing or modified')
    else:
        selected = originals[0]
    receipt = (Path(flags_receipt).expanduser().resolve(strict=True)
               if live_dse else None)
    initial = analyze_seed(root / 'dta' / 'initial', binary=binary, qemu=qemu, plugin=plugin,
                           seed=selected.read_bytes(), max_candidates=max_candidates)
    backend.require(initial['mask'], 'DTA did not produce a mask; choose --mode afl')
    # The accepted DTA corpus is verified by the analysis worker. AFL calibrates
    # every seed again inside the isolated rebuilt backend.
    accepted = Path(initial['directory']) / 'accepted-seeds'
    for candidate in sorted(accepted.iterdir()):
        backend.require(candidate.is_file() and not candidate.is_symlink(), 'Invalid DTA seed')
        raw = candidate.read_bytes()
        backend.require(1 <= len(raw) <= 4096 and candidate.name == digest(raw), 'Unaudited DTA seed')
        (root / 'seeds' / digest(raw)).write_bytes(raw)
    lib = build_mutator(root / 'build' / 'hybrid_mutator.so')
    receipt_sources = ('taintforge_env/afl_rebuilt.py', 'scripts/run_afl_rebuilt.py',
                       'experiments/afl_file/bridge.c', 'experiments/afl_rebuilt/coverage.c',
                       'experiments/hybrid_rebuilt_v1/controller.py', 'experiments/hybrid_rebuilt_v1/receipts.py',
                       'experiments/hybrid_rebuilt_v1/policy.py', 'experiments/hybrid_rebuilt_v1/mutator.c',
                       'experiments/hybrid_rebuilt_v1/telemetry.py', 'experiments/hybrid_rebuilt_v1/forensics.py')
    source_hashes = {name: backend.digest(backend.PROJECT / name) for name in receipt_sources}
    controller = LiveRebuiltController(root, initial=initial, binary=binary,
        qemu=qemu, plugin=plugin, flags_receipt=receipt,
        stall_cases=stall_cases, max_dse_jobs=max_dse_jobs,
        mixed_mutations=mixed, live_dse=live_dse,
        custom_fuzz_count=custom_fuzz_count)
    manifest['hybrid'] = {'profile': 'rebuilt-i386-live-hybrid-v3',
        'mixed_mutations': mixed, 'live_dse_enabled': live_dse,
        'initial_target_sha256': initial['target_sha256'],
        'initial_seed_sha256': initial['source_seed_sha256'],
        'DTA_analysis_seed_sha256': backend.digest(selected),
        'initial_DTA_summary_sha256': initial['DTA_summary_sha256'],
        'DTA_mask': initial['mask'], 'DTA_accepted_seeds': len(list(accepted.iterdir())),
        'library': str(lib), 'library_sha256': backend.digest(lib),
        'receipt_source_sha256': source_hashes,
        'stall_cases': stall_cases, 'max_dse_jobs': max_dse_jobs,
        'custom_fuzz_count': controller.custom_fuzz_count,
        'flags_receipt_sha256': backend.digest(receipt) if receipt else None,
        'automatic_live_cycle_verified': False}
    backend.write_json(root / 'campaign.json', manifest)
    return controller, lib


def resolve_afl_stage_policy(mode, requested):
    """Select explicit policy without silently biasing a five-arm comparison."""
    backend.require(mode in ('afl', 'focus', 'hybrid', 'hybrid-mixed') and
                    requested in ('auto', 'full', 'fast'),
                    'Invalid AFL stage-policy selection')
    return ('fast' if mode == 'hybrid-mixed' else 'full') if requested == 'auto' else requested


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='action', required=True)
    run = commands.add_parser('campaign')
    for name in ('binary', 'seeds', 'qemu', 'plugin', 'out'):
        run.add_argument('--' + name, type=Path, required=True)
    run.add_argument('--mode', choices=('afl', 'focus', 'hybrid', 'hybrid-mixed', 'fork-replay'), default='afl',
                     help='afl=stock, focus=custom without DSE, hybrid=legacy custom+DSE, '
                          'hybrid-mixed=stock AFL stages plus adaptive custom+DSE, '
                          'fork-replay=fixed corpus with /etc/dta-input as argv[1]')
    run.add_argument('--seconds', type=int, default=180)
    run.add_argument('--case-seconds', type=int, default=5)
    run.add_argument('--max-cases', type=int, default=512)
    run.add_argument('--disk-mib', type=int, default=1024)
    run.add_argument('--flags-receipt', type=Path)
    run.add_argument('--stall-cases', type=int, default=16)
    run.add_argument('--max-dse-jobs', type=int, default=2)
    run.add_argument('--max-candidates', type=int, default=16)
    run.add_argument('--afl-seed', type=int, default=42)
    run.add_argument('--afl-stage-policy', choices=('auto', 'full', 'fast'), default='auto',
        help='auto=fast for hybrid-mixed, full otherwise; fast=-z skips enhanced '
             'deterministic AFL stages but retains custom and havoc')
    run.add_argument('--custom-fuzz-count', type=int,
        help='AFL custom fuzz attempts per queue entry, 1..16; default mixed=8, legacy=16')
    run.add_argument('--phase1-unpack-output', type=Path)
    run.add_argument('--target-sha256', help='Require this SHA-256 for the input ELF')
    run.add_argument('--dta-source-sha256',
                     help='Pin the exact reviewed source seed for all DTA-enabled study arms')
    launch = commands.add_parser('launch')
    launch.add_argument('--binding', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.action == 'launch':
            return backend.launch(args.binding)
        fixed = args.mode == 'fork-replay'
        afl = shutil.which(os.environ.get('TF_AFL_SHOWMAP', 'afl-showmap') if fixed else 'afl-fuzz')
        backend.require(afl, 'Missing afl-showmap' if fixed else 'Missing afl-fuzz')
        live_dse = args.mode in ('hybrid', 'hybrid-mixed')
        backend.require(args.custom_fuzz_count is None or
                        1 <= args.custom_fuzz_count <= 16,
                        '--custom-fuzz-count must be between 1 and 16')
        backend.require(args.mode != 'afl' or args.custom_fuzz_count is None,
                        '--custom-fuzz-count requires a hybrid/focus mutator')
        stage_policy = None if fixed else resolve_afl_stage_policy(args.mode, args.afl_stage_policy)
        backend.require(not live_dse or args.flags_receipt is not None,
                        '--flags-receipt is required for audited DSE')
        root = backend.private_path(args.out)
        binary = args.binary.expanduser().resolve(strict=True)
        if args.target_sha256 is not None:
            backend.require(backend.digest(binary) == args.target_sha256,
                            'Selected ELF differs from --target-sha256')
        seeds = args.seeds.expanduser().resolve(strict=True)
        qemu = args.qemu.expanduser().resolve(strict=True)
        plugin = args.plugin.expanduser().resolve(strict=True)
        phase1_record = None
        if args.phase1_unpack_output is not None:
            from experiments.hybrid_rebuilt_v1.boundary import phase1_source
            phase1_record = phase1_source(args.phase1_unpack_output, target_sha256=backend.digest(binary))
        prepared = backend.prepare(root, binary, seeds, qemu, plugin, args.case_seconds, fixed_fork_replay=fixed)
        if args.target_sha256 is not None:
            backend.require(prepared['target_sha256'] == args.target_sha256,
                            'Prepared ELF differs from --target-sha256')
        if phase1_record is not None:
            manifest = backend.read_json(root / 'campaign.json')
            manifest['phase1_source_consistency'] = phase1_record
            backend.write_json(root / 'campaign.json', manifest)
        controller, lib = None, None
        try:
            if fixed:
                from taintforge_env.afl_rebuilt_tree import replay_corpus
                print(json.dumps(replay_corpus(root, backend.read_json(root / 'campaign.json'), afl), indent=2))
                return 0
            if args.mode != 'afl':
                controller, lib = prepare_hybrid(root, binary=binary, qemu=qemu, plugin=plugin,
                    flags_receipt=args.flags_receipt, stall_cases=args.stall_cases,
                    max_dse_jobs=args.max_dse_jobs if live_dse else 0,
                    max_candidates=args.max_candidates,
                    mixed=args.mode == 'hybrid-mixed', live_dse=live_dse,
                    dta_source_sha256=args.dta_source_sha256,
                    custom_fuzz_count=args.custom_fuzz_count)
            result = backend.campaign(root, Path(afl).resolve(), args.seconds,
                args.max_cases, args.disk_mib, hybrid=controller, hybrid_library=lib,
                afl_seed=args.afl_seed, afl_stage_policy=stage_policy)
            if phase1_record is not None:
                from experiments.hybrid_rebuilt_v1.boundary import phase1_source
                backend.require(phase1_source(args.phase1_unpack_output,
                    target_sha256=backend.digest(binary)) == phase1_record,
                    'Phase 1 source artifacts changed during the campaign')
        except BaseException as exc:
            report = backend.read_json(root / 'campaign.json')
            if report.get('status') in ('prepared', 'completed'):
                report.update(status='hybrid_preflight_failed' if report['status'] == 'prepared' else 'failed',
                              error=f'{type(exc).__name__}: {exc}')
                backend.write_json(root / 'campaign.json', report)
            if controller is not None and controller.thread.ident is None:
                controller.close()
            raise
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (OSError, RuntimeError, ValueError, KeyError, subprocess.SubprocessError) as exc:
        print(f'{type(exc).__name__}: {exc}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
