"""Invert a bounded file-dependent branch in fresh isolated DSE cases."""
import argparse
import json
from pathlib import Path
import sys

from taintforge_env.dse_analysis import invert_file


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('binary', 'qemu', 'plugin', 'seed', 'flags-receipt', 'out'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--input-path', required=True)
    parser.add_argument('--branch-pc', type=lambda value: int(value, 0), required=True)
    parser.add_argument('--offset', dest='offsets', action='append', type=lambda value: int(value, 0),
                        required=True, help='selected file offset; repeat 1..16 times in increasing order')
    parser.add_argument('--occurrence', type=int, default=1)
    parser.add_argument('--max-steps', type=int, default=128)
    parser.add_argument('--arg', dest='argv', action='append', default=[])
    parser.add_argument('--seconds', type=int, default=30)
    parser.add_argument('--memory-mib', type=int, default=1024)
    args = parser.parse_args(argv)
    try:
        report = invert_file(**vars(args))
    except (OSError, ValueError, RuntimeError, KeyError, TypeError) as exc:
        print(f'DSE_ANALYSIS_FAILED: {exc}', file=sys.stderr)
        return 1
    print(json.dumps({key: report[key] for key in ('status', 'profile', 'dse_status',
        'concrete_runs', 'accepted_seed_count', 'dse_adapter_isolated',
        'protected_control_channel', 'universal_equivalence')}, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
