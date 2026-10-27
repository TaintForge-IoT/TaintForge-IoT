#!/usr/bin/env python3
"""Audit a completed file DTA worker run and export its corpus and recapture hints."""
import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from taintforge_env.dta_handoff import export_handoff


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--analysis', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--max-sites', type=int, default=256)
    args = parser.parse_args()
    try:
        result = export_handoff(analysis=args.analysis, out=args.out, max_sites=args.max_sites)
    except (OSError, ValueError, RuntimeError, KeyError, TypeError) as exc:
        parser.exit(1, f'FAIL_DTA_HANDOFF: {type(exc).__name__}: {exc}\n')
    print(json.dumps({key: result[key] for key in ('status', 'audited_runs', 'new_branch_outcomes',
        'recapture_sites', 'sites_with_unseen_opposite', 'dse_status')}, indent=2))
    print('Corpus:', args.out / 'seeds')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
