"""Verify an existing rebuilt AFL campaign and its available live-cycle evidence."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

if __package__ in (None, ''):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from experiments.hybrid_rebuilt_v1.acceptance import audit_native_campaign


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--campaign', required=True, type=Path)
    p.add_argument('--output', type=Path)
    p.add_argument('--target-sha256', help='Expected identity of the reviewed ELF')
    p.add_argument('--require-live-cycle', action='store_true',
                   help='Exit 1 if no complete cycle is witnessed while AFL was known to be alive')
    args = p.parse_args(argv)
    try:
        result = audit_native_campaign(args.campaign, expected_target_sha256=args.target_sha256)
        report = json.dumps(result, indent=2, sort_keys=True) + '\n'
        if args.output:
            path = args.output.expanduser()
            with path.open('x') as out:
                out.write(report)
        print(report, end='')
        return int(args.require_live_cycle and not result['live_cycle_observed'])
    except (OSError, RuntimeError, ValueError, KeyError, TypeError) as exc:
        print(f'HYBRID_V51_RECEIPT_AUDIT_FAILED: {exc}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
