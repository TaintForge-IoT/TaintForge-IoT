#!/usr/bin/env python3
"""Run explicit DNS/UDP/TCP recording endpoints; external access is policy-bound."""
from __future__ import annotations

import argparse
import asyncio
import os
from pathlib import Path
import signal
import sys

from taintforge_env.network_policy import load_network_policy
from taintforge_env.network_record import RecordNetwork


async def run(policy: Path, log_dir: Path):
    network = RecordNetwork(load_network_policy(policy), log_dir)
    stopped = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stopped.set)
    try:
        await network.start()
        print("Network recording services ready", flush=True)
        await stopped.wait()
    finally:
        await network.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--log-dir", type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    try:
        asyncio.run(run(args.policy, args.log_dir))
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"Network recording failed: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
