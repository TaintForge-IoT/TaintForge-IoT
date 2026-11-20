"""Inspect a saved unsuccessful DSE job without running QEMU or changing the campaign."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

if __package__ in (None, ''):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from experiments.hybrid_rebuilt_v1.forensics import diagnose


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--campaign', required=True, type=Path)
    parser.add_argument('--job', type=int, default=2)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args(argv)
    try:
        report = diagnose(args.campaign, args.job)
        content = json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2) + '\n'
        if args.output is not None:
            destination = args.output.expanduser().absolute()
            with destination.open('x') as output:
                output.write(content)
        print(content, end='')
        return 0
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f'DSE_DIAGNOSIS_FAILED: {exc}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
