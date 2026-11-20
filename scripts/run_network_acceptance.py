#!/usr/bin/env python3
"""Run the NET-1..NET-9 matrix and report complete or partial acceptance."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import signal
import sys

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT))

from taintforge_env.network_acceptance import CHECKS, run_acceptance


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--profile", choices=("full", "component"), default="full")
    parser.add_argument("--qemu", type=Path)
    parser.add_argument("--plugin", type=Path)
    parser.add_argument("--observer", type=Path)
    parser.add_argument("--list-checks", action="store_true")
    args = parser.parse_args()
    if args.list_checks:
        print(json.dumps([{"name": c.name, "coverage": c.coverage, "kind": c.kind,
                           "component_profile": c.component} for c in CHECKS], indent=2))
        return 0
    if args.out is None:
        parser.error("--out is required")
    os.umask(0o077)

    def interrupted(signum, frame):
        raise KeyboardInterrupt

    previous = signal.signal(signal.SIGTERM, interrupted)
    try:
        report = run_acceptance(PROJECT, args.out, profile=args.profile,
                                qemu=args.qemu, plugin=args.plugin, observer=args.observer)
    except (OSError, ValueError) as exc:
        print(f"NET-9: {exc}", file=sys.stderr)
        return 1
    finally:
        signal.signal(signal.SIGTERM, previous)
    print(json.dumps({key: report[key] for key in ("status", "full_acceptance", "counts", "exit_code")}, indent=2))
    print("Report: " + str(args.out.expanduser().absolute() / "report.json"))
    return report["exit_code"]


if __name__ == "__main__":
    raise SystemExit(main())
