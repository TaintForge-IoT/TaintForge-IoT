#!/usr/bin/env python3
"""Pack or verify portable retirement evidence without executing QEMU."""
import argparse
import json
from pathlib import Path

from taintforge_env import retirement_evidence as evidence
from taintforge_env.retirement_mappings import EvidenceInconclusive


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    pack = commands.add_parser("pack")
    pack.add_argument("--run-dir", type=Path, required=True)
    pack.add_argument("--out", type=Path, required=True)
    check = commands.add_parser("verify")
    check.add_argument("directory", type=Path)
    check.add_argument("--expected-sha256")
    args = parser.parse_args()
    try:
        result = (evidence.pack(args.run_dir, args.out) if args.command == "pack" else
                  evidence.verify(args.directory, expected_sha256=args.expected_sha256))
        code = 0
    except EvidenceInconclusive as exc:
        result, code = {"status": "inconclusive", "reason": str(exc)}, 2
    except (OSError, ValueError, RuntimeError, KeyError, TypeError) as exc:
        result, code = {"status": "failed", "reason": f"{type(exc).__name__}: {exc}"}, 1
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
