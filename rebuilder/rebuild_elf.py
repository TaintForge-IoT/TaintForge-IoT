#!/usr/bin/env python3
"""Rebuild a static i386 ELF from Phase 1 capture metadata and observed pages."""
import argparse
import json
from pathlib import Path
import sys

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from unpacker.mvp.ct_elf import CaptureError, rebuild


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("-b", "--bin", type=Path, required=True, help="Phase 1 unpacked.bin")
    parser.add_argument("-j", "--json", type=Path, required=True, help="Phase 1 unpacked.json")
    parser.add_argument("-e", "--elf", type=Path,
                        help="legacy optional packed input, unused in capture-based reconstruction")
    parser.add_argument("-o", "--output", type=Path, default=Path("rebuilt.elf"))
    parser.add_argument("-v", "--verbose", action="store_true", help="print the reconstruction receipt")
    args = parser.parse_args(argv)
    try:
        if args.elf is not None and not args.elf.is_file():
            raise FileNotFoundError(f"packed reference does not exist: {args.elf}")
        receipt = rebuild(args.json, args.bin, args.output)
    except CaptureError as exc:
        print(f"{exc.reason}: {exc}", file=sys.stderr)
        return 1
    except (OSError, ValueError) as exc:
        print(f"Reconstruction failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(receipt, indent=2) if args.verbose else f"{args.output}  sha256={receipt['elf_sha256']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
