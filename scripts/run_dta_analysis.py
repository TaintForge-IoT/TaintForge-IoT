"""Run isolated DTA file-input analysis and concretely replay generated seeds."""
import argparse
import json
from pathlib import Path
import sys

from taintforge_env.dta_analysis import analyze_file


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('binary', 'qemu', 'plugin', 'seed', 'out'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--input-path', required=True)
    parser.add_argument('--arg', dest='argv', action='append', default=[])
    parser.add_argument('--max-candidates', type=int, default=40)
    parser.add_argument('--seconds', type=int, default=10)
    parser.add_argument('--memory-mib', type=int, default=1024)
    parser.add_argument('--wall-seconds', type=int, default=900)
    args = parser.parse_args(argv)
    try:
        report = analyze_file(**vars(args))
    except (OSError, ValueError, RuntimeError, KeyError) as exc:
        print(f'DTA_ANALYSIS_FAILED: {exc}', file=sys.stderr)
        return 1
    print(json.dumps({key: report[key] for key in (
        'status', 'profile', 'candidate_count', 'concrete_runs', 'new_branch_outcomes',
        'accepted_seed_count', 'dse_status', 'novelty_scope')}, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
