"""Read-only Capsule/Phase-1 source-receipt consistency audit for rebuilt AFL."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

if __package__ in (None, ''):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from experiments.hybrid_rebuilt_v1.boundary import audit_campaign


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--campaign', required=True, type=Path)
    p.add_argument('--phase1-unpack-output', type=Path)
    p.add_argument('--output', type=Path)
    args = p.parse_args(argv)
    try:
        report = audit_campaign(args.campaign, source=args.phase1_unpack_output)
        content = json.dumps(report, indent=2, sort_keys=True) + '\n'
        if args.output is not None:
            with args.output.expanduser().absolute().open('x') as stream:
                stream.write(content)
        print(json.dumps({key: value for key, value in report.items() if key != 'case_receipts'},
                         indent=2, sort_keys=True))
        return 0
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f'BOUNDARY_AUDIT_FAILED: {exc}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
