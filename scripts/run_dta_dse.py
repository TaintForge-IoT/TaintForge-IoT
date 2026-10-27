"""Extend an audited DTA file corpus through fresh isolated DSE jobs."""
import argparse
import json
from pathlib import Path
import sys

from taintforge_env.dta_dse import extend_corpus


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('analysis', 'qemu', 'plugin', 'flags-receipt', 'out'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--max-jobs', type=int, default=4)
    parser.add_argument('--max-occurrences', type=int, default=8)
    parser.add_argument('--max-steps', type=int, default=128)
    parser.add_argument('--max-sites', type=int, default=256)
    parser.add_argument('--seconds', type=int, default=30)
    parser.add_argument('--memory-mib', type=int, default=1024)
    args = parser.parse_args(argv)
    try:
        report = extend_corpus(**vars(args))
    except (OSError, ValueError, RuntimeError, KeyError, TypeError) as exc:
        print(f'DTA_DSE_FAILED: {exc}', file=sys.stderr)
        return 1
    print(json.dumps({key: report[key] for key in (
        'status', 'dse_status', 'new_seed_count', 'corpus_seed_count')}, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
