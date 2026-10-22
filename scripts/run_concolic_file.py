#!/usr/bin/env python3
"""Invert one observed branch by changing one stdin file byte and replaying."""
import argparse
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from taintforge_env.concolic_file import run_file_inversion


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--qemu", type=Path, default=os.environ.get("TF_QEMU_I386"))
    parser.add_argument("--plugin", type=Path, required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--flags-receipt", type=Path, required=True)
    parser.add_argument("--branch", type=lambda text: int(text, 0), required=True)
    parser.add_argument("--occurrence", type=int, default=1)
    parser.add_argument("--max-steps", type=int, default=256)
    parser.add_argument("--timeout", type=float, default=30)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not args.qemu:
        parser.error("set TF_QEMU_I386 or pass --qemu")
    try:
        result = run_file_inversion(qemu=args.qemu, plugin=args.plugin, binary=args.binary,
                                   input_file=args.input, flags_receipt=args.flags_receipt,
                                   branch_pc=args.branch, occurrence=args.occurrence,
                                   max_steps=args.max_steps, timeout=args.timeout, output=args.output)
    except (OSError, ValueError, RuntimeError) as error:
        parser.exit(2, f"ERROR: {error}\n")
    print(json.dumps(result, indent=2))
    return 0 if result["status"] == "VERIFIED" else 2


if __name__ == "__main__":
    sys.exit(main())
