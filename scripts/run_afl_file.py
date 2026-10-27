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
    for name in ('binary', 'qemu', 'plugin', 'seeds'):
        prepare.add_argument('--'+name, type=Path, required=True)
    prepare.add_argument('--guest-file', required=True)
    prepare.add_argument('--mode', choices=('warm', 'fresh'), default='warm')
    prepare.add_argument('--bootstrap-seconds', type=int, default=1200)
    prepare.add_argument('--campaign-seconds', type=int, default=3600)
    prepare.add_argument('--timeout-ms', type=int, default=2000)
    prepare.add_argument('--max-rss-mib', type=int, default=2048)
    prepare.add_argument('--memory-mib', type=int, default=65536)
    prepare.add_argument('--analysis-mib', type=int, default=49152)
    prepare.add_argument('--max-input', type=int, default=4096)
    run = commands.add_parser('run')
    run.add_argument('--seconds', type=int, default=300)
    run.add_argument('--executions', type=int)
    run.add_argument('--afl-bin', type=Path)
    attempt = commands.add_parser('attempt', help=argparse.SUPPRESS)
    attempt.add_argument('--case', type=Path, required=True)
    warm = commands.add_parser('warm-session', help=argparse.SUPPRESS)
    for command in (prepare, run, attempt, warm): command.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.action == 'prepare':
            prepare_function = f.prepare_campaign
            limits = {}
            if args.mode == 'warm':
                from taintforge_env.afl_warm import prepare_campaign as prepare_function
                limits = dict(bootstrap_seconds=args.bootstrap_seconds, campaign_seconds=args.campaign_seconds,
                    timeout_ms=args.timeout_ms, max_rss_mib=args.max_rss_mib,
                    memory_mib=args.memory_mib, analysis_mib=args.analysis_mib)
            result = prepare_function(args.out, binary=args.binary, qemu=args.qemu, plugin=args.plugin,
                guest_path=args.guest_file, seeds=args.seeds, max_input=args.max_input, **limits)
        elif args.action == 'run':
            from taintforge_env.afl_transport import run_campaign
            result = run_campaign(args.out, afl_bin=args.afl_bin, seconds=args.seconds, executions=args.executions)
        elif args.action == 'warm-session':
            from taintforge_env.afl_warm import execute_session
            result = execute_session(args.out)
        else:
            result = f.execute_attempt(args.out, args.case)
        print(json.dumps(result, indent=2))
        return 130 if result.get('status') == 'interrupted' else 0
    except (OSError, ValueError, RuntimeError, KeyError) as exc:
        print(str(exc), file=sys.stderr)
        if args.action == 'attempt':
            f.atomic_json(args.case/'result.json', {'schema':1, 'status':'failed', 'error':str(exc)})
        return 2


if __name__ == '__main__': raise SystemExit(main())
