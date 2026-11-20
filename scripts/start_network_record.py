#!/usr/bin/env python3
"""Run explicit DNS/UDP/TCP recording endpoints; external access is policy-bound."""
from __future__ import annotations

import argparse
import asyncio
import os
from pathlib import Path
import sys

from taintforge_env.network_policy import load_network_policy
from taintforge_env.network_record import RecordNetwork
from taintforge_env.network_runtime import run_network_service, NetworkRuntimeLimits


async def run(policy: Path, log_dir: Path):
    network = RecordNetwork(load_network_policy(policy), log_dir)
    try:
        await network.start()
        print("Network recording services ready", flush=True)
        await asyncio.Future()
    finally:
        await network.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--log-dir", type=Path, required=True)
    parser.add_argument("--runtime", type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    try:
        policy = load_network_policy(args.policy)
        asyncio.run(run_network_service(lambda: run(args.policy, args.log_dir), log_dir=args.log_dir,
            runtime_path=args.runtime, limits=NetworkRuntimeLimits.parse(policy.runtime_limits)))
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"Network recording failed: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
