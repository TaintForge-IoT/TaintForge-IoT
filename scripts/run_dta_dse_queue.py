"""Manage a durable queue of audited DTA hints and isolated DSE jobs."""
import argparse
import json
from pathlib import Path
import subprocess
import sys

from taintforge_env import dta_dse_queue


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    descriptions = {
        'init': 'create a new queue bound to its runtime and budgets',
        'enqueue': 'audit completed DTA analyses and enqueue unseen requests',
        'run': 'process pending jobs and resume audited completed attempts',
        'status': 'read a scheduler snapshot without reauditing proof evidence',
        'audit': 'reaudit source and completed worker evidence without launching guests',
        'stop': 'request a cooperative stop after the current job',
    }
    subparsers = {}
    for name, description in descriptions.items():
        command = commands.add_parser(name, help=description, description=description)
        command.add_argument('--queue', type=Path, required=True)
        subparsers[name] = command
    init = subparsers['init']
    for name in ('qemu', 'plugin', 'flags-receipt'):
        init.add_argument('--' + name, type=Path, required=True)
    for name, default in (('max-total-starts', 128), ('max-queue-jobs', 512),
                          ('max-occurrences', 8), ('max-steps', 128), ('max-sites', 256),
                          ('seconds', 30), ('memory-mib', 1024)):
        init.add_argument('--' + name, type=int, default=default)
    subparsers['enqueue'].add_argument('--analysis', dest='analyses', type=Path,
        action='append', required=True, help='original completed DTA analysis; repeat for several analyses')
    subparsers['run'].add_argument('--max-jobs', type=int, default=1,
        help='maximum new attempts started by this invocation')
    subparsers['run'].add_argument('--wall-seconds', type=int, default=900,
        help='soft scheduling limit checked between jobs; does not interrupt an active worker')
    args = vars(parser.parse_args(argv))
    name = args.pop('command')
    functions = {
        'init': dta_dse_queue.create_queue,
        'enqueue': dta_dse_queue.enqueue_analyses,
        'run': dta_dse_queue.run_queue,
        'status': dta_dse_queue.queue_status,
        'audit': dta_dse_queue.audit_queue,
        'stop': dta_dse_queue.request_stop,
    }
    try:
        report = functions[name](**args)
    except KeyboardInterrupt:
        print('DTA_DSE_QUEUE_INTERRUPTED: inspect queue state before resuming; '
              'incomplete attempts do not authorize candidate publication', file=sys.stderr)
        return 130
    except (OSError, ValueError, RuntimeError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        print(f'DTA_DSE_QUEUE_FAILED: {exc}', file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2, sort_keys=True, allow_nan=False))
    if name in ('run', 'audit') and report.get('status') in (
            'QUEUE_BLOCKED', 'QUEUE_BUDGET_EXHAUSTED'):
        return 2
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
