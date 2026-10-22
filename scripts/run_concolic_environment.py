#!/usr/bin/env python3
"""Invert a branch using selected bytes of a file in a copied environment."""
import argparse
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from taintforge_env.concolic_environment import run_environment_inversion


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--qemu", type=Path, default=os.environ.get("TF_QEMU_I386"))
    parser.add_argument("--plugin", type=Path, required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--rootfs", type=Path, required=True)
    parser.add_argument("--guest-file", required=True)
    parser.add_argument("--offset", action="append", type=lambda s: int(s, 0), required=True,
                        help="mutable file offset; repeat up to 16 times, in increasing order")
    parser.add_argument("--environment-manifest", type=Path)
    parser.add_argument("--flags-receipt", type=Path, required=True)
    parser.add_argument("--branch", type=lambda s: int(s, 0), required=True)
    parser.add_argument("--occurrence", type=int, default=1)
    parser.add_argument("--max-steps", type=int, default=256)
    parser.add_argument("--timeout", type=float, default=30)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not args.qemu:
        parser.error("set TF_QEMU_I386 or pass --qemu")
    try:
        result = run_environment_inversion(qemu=args.qemu, plugin=args.plugin, binary=args.binary,
            rootfs=args.rootfs, guest_file=args.guest_file, offsets=args.offset,
            flags_receipt=args.flags_receipt, branch_pc=args.branch, output=args.output,
            occurrence=args.occurrence, max_steps=args.max_steps, timeout=args.timeout,
            environment_manifest=args.environment_manifest)
    except (OSError, ValueError, RuntimeError) as error:
        parser.exit(2, f"ERROR: {error}\n")
    print(json.dumps(result, indent=2))
    return 0 if result["status"] == "VERIFIED" else 2


if __name__ == "__main__":
    sys.exit(main())
