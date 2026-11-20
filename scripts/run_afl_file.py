"""AFL++ guest-file MVP using the original TaintForge M4 pipeline."""
import argparse
import json
from pathlib import Path
import sys

from taintforge_env import afl_file as f


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='action', required=True)
    prepare = commands.add_parser('prepare')
    campaign = commands.add_parser('campaign', help='One Phase 1/capsule session with AFL and per-child Phase 2')
    for name in ('binary', 'qemu', 'plugin', 'seeds'):
        prepare.add_argument('--'+name, type=Path, required=True)
        campaign.add_argument('--'+name, type=Path, required=True)
    prepare.add_argument('--guest-file', required=True)
    prepare.add_argument('--mode', choices=('warm', 'fresh'), default='warm')
    prepare.add_argument('--analysis-policy', choices=('strict', 'research'), default='strict')
    prepare.add_argument('--flags-receipt', type=Path)
    prepare.add_argument('--ir-start', type=lambda value: int(value, 0))
    prepare.add_argument('--bootstrap-seconds', type=int, default=1200)
    prepare.add_argument('--campaign-seconds', type=int, default=3600)
    prepare.add_argument('--timeout-ms', type=int, default=2000)
    prepare.add_argument('--max-rss-mib', type=int, default=2048)
    prepare.add_argument('--memory-mib', type=int, default=65536)
    prepare.add_argument('--analysis-mib', type=int, default=49152)
    prepare.add_argument('--max-input', type=int, default=4096)
    for action in (prepare, campaign):
        action.add_argument('--phase2-mode', choices=('off', 'sequential', 'parallel'),
                            default='parallel' if action is campaign else 'off')
        action.add_argument('--phase2-pending', type=int, default=4)
    campaign.add_argument('--guest-file', required=True)
    campaign.add_argument('--mode', choices=('warm',), default='warm')
    campaign.add_argument('--analysis-policy', choices=('strict', 'research'), default='strict')
    campaign.add_argument('--flags-receipt', type=Path)
    campaign.add_argument('--ir-start', type=lambda value: int(value, 0))
    for name, default in (('bootstrap-seconds',1200), ('campaign-seconds',3600), ('timeout-ms',2000),
                          ('max-rss-mib',2048), ('memory-mib',65536), ('analysis-mib',49152), ('max-input',4096)):
        campaign.add_argument('--'+name, type=int, default=default)
    run = commands.add_parser('run')
    run.add_argument('--seconds', type=int, default=300)
    run.add_argument('--executions', type=int)
    run.add_argument('--afl-bin', type=Path)
    campaign.add_argument('--seconds', type=int, default=300)
    campaign.add_argument('--executions', type=int)
    campaign.add_argument('--afl-bin', type=Path)
    for action in (run, campaign):
        action.add_argument('--stop-timeout', type=int, default=120,
                            help='Seconds to drain accepted work after SIGINT/SIGTERM before forced cleanup')
        action.add_argument('--max-artifact-mib', type=int)
        action.add_argument('--max-log-mib', type=int)
        action.add_argument('--max-rootfs-mib', type=int)
        action.add_argument('--max-preparation-mib', type=int)
        action.add_argument('--max-case-mib', type=int)
        action.add_argument('--reserve-mib', type=int)
        action.add_argument('--min-free-mib', type=int)
    replay = commands.add_parser('replay', help='Reproduce and optionally minimize a saved fault')
    replay.add_argument('--campaign', type=Path, required=True)
    replay.add_argument('--finding', type=Path, required=True)
    replay.add_argument('--repetitions', type=int, default=3)
    replay.add_argument('--minimize', action='store_true')
    replay.add_argument('--minimize-budget', type=int, default=128)
    evolve = commands.add_parser('evolve', help='Run bounded repair epochs after a completed campaign')
    evolve.add_argument('--campaign', type=Path, required=True)
    evolve.add_argument('--max-epochs', type=int, default=3)
    evolve.add_argument('--seconds', type=int, help='Defaults to the original capsule lifetime, capped at 300 seconds')
    evolve.add_argument('--executions', type=int)
    evolve.add_argument('--afl-bin', type=Path)
    evolve.add_argument('--max-artifact-mib', type=int)
    resume = commands.add_parser('resume', help='Continue a stopped M5 campaign corpus in a new warm session')
    resume.add_argument('--campaign', type=Path, required=True)
    resume.add_argument('--seconds', type=int, default=300)
    resume.add_argument('--executions', type=int)
    resume.add_argument('--afl-bin', type=Path)
    resume.add_argument('--max-artifact-mib', type=int)
    resume.add_argument('--max-corpus-files', type=int, default=100000)
    resume.add_argument('--max-corpus-mib', type=int, default=64)
    resume.add_argument('--prepare-only', action='store_true')
    resume.add_argument('--stop-timeout', type=int, default=120)
    attempt = commands.add_parser('attempt', help=argparse.SUPPRESS)
    attempt.add_argument('--case', type=Path, required=True)
    warm = commands.add_parser('warm-session', help=argparse.SUPPRESS)
    for command in (prepare, run, attempt, warm, campaign, replay, evolve, resume): command.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    disk_limits = {name: getattr(args, name) for name in
                   ('max_artifact_mib', 'max_log_mib', 'max_rootfs_mib', 'max_preparation_mib', 'max_case_mib', 'reserve_mib', 'min_free_mib')
                   if hasattr(args, name)}
    if args.action in {'run', 'campaign'}:
        disk_limits['stop_timeout'] = args.stop_timeout
    try:
        if hasattr(args, 'stop_timeout'):
            from taintforge_env.afl_stop import validate_timeout
            validate_timeout(args.stop_timeout)
        if args.action in {'prepare', 'campaign'}:
            prepare_function = f.prepare_campaign
            limits = {}
            if args.mode == 'warm':
                from taintforge_env.afl_strict import prepare_campaign as prepare_function
                limits = dict(bootstrap_seconds=args.bootstrap_seconds, campaign_seconds=args.campaign_seconds,
                    timeout_ms=args.timeout_ms, max_rss_mib=args.max_rss_mib,
                    memory_mib=args.memory_mib, analysis_mib=args.analysis_mib,
                    phase2_mode=args.phase2_mode, phase2_pending=args.phase2_pending,
                    flags_receipt=args.flags_receipt, ir_start=args.ir_start)
            elif args.phase2_mode != 'off':
                raise ValueError('Per-child Phase 2 requires --mode warm')
            elif args.flags_receipt is not None or args.ir_start is not None:
                raise ValueError('Flags receipt and IR start require --mode warm')
            result = prepare_function(args.out, binary=args.binary, qemu=args.qemu, plugin=args.plugin,
                guest_path=args.guest_file, seeds=args.seeds, max_input=args.max_input,
                analysis_policy=args.analysis_policy, **limits)
            if args.action == 'campaign':
                from taintforge_env.afl_transport import run_campaign
                result = run_campaign(args.out, afl_bin=args.afl_bin, seconds=args.seconds,
                                      executions=args.executions, **disk_limits)
        elif args.action == 'run':
            from taintforge_env.afl_transport import run_campaign
            result = run_campaign(args.out, afl_bin=args.afl_bin, seconds=args.seconds,
                                  executions=args.executions, **disk_limits)
        elif args.action == 'resume':
            from taintforge_env.afl_continue import resume as continue_campaign
            result = continue_campaign(args.campaign, args.out, seconds=args.seconds, executions=args.executions,
                afl_bin=args.afl_bin, max_artifact_mib=args.max_artifact_mib,
                max_corpus_files=args.max_corpus_files, max_corpus_bytes=args.max_corpus_mib*1024**2,
                prepare_only=args.prepare_only, stop_timeout=args.stop_timeout)
        elif args.action == 'evolve':
            from taintforge_env.afl_epochs import evolve as repair_epochs
            result = repair_epochs(args.campaign, args.out, max_epochs=args.max_epochs, seconds=args.seconds,
                executions=args.executions, afl_bin=args.afl_bin, max_artifact_mib=args.max_artifact_mib)
        elif args.action == 'replay':
            from taintforge_env.afl_replay import replay as replay_finding
            result = replay_finding(args.campaign, args.finding, args.out, repetitions=args.repetitions,
                                    reduce=args.minimize, budget=args.minimize_budget)
        elif args.action == 'warm-session':
            from taintforge_env.afl_warm import execute_session
            result = execute_session(args.out)
        else:
            result = f.execute_attempt(args.out, args.case)
        print(json.dumps(result, indent=2))
        return 130 if result.get('status') == 'interrupted' else 1 if result.get('status') == 'not_reproduced' else 2 if result.get('status') in {'failed', 'incomplete'} else 3 if result.get('status') == 'resource_limited' else 0
    except InterruptedError as exc:
        print(str(exc), file=sys.stderr)
        return 130
    except (OSError, ValueError, RuntimeError, KeyError) as exc:
        print(str(exc), file=sys.stderr)
        if args.action == 'attempt':
            f.atomic_json(args.case/'result.json', {'schema':1, 'status':'failed', 'error':str(exc)})
        return 2


if __name__ == '__main__': raise SystemExit(main())
