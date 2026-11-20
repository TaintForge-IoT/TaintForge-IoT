#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from taintforge_env.network_observer import build_observer, NetworkObserverError


def main():
    parser = argparse.ArgumentParser(description="Build the independent Phase 2 network endpoint observer")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--qemu-include", type=Path)
    args = parser.parse_args()
    try:
        result = build_observer(Path(__file__).resolve().parents[1], args.out, qemu_include=args.qemu_include)
    except (OSError, ValueError, NetworkObserverError) as error:
        parser.exit(1, f"Observer build failed: {error}\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
