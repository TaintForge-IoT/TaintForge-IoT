#!/usr/bin/env python3
from __future__ import annotations

import argparse
import asyncio
from pathlib import Path

from taintforge_env.network_policy import load_network_policy
from taintforge_env.network_replay import NetworkReplayError, run_network_replay
from taintforge_env.replay_store import ReplayStore, ReplayStoreError


def main() -> int:
    parser = argparse.ArgumentParser(description="Serve exact TCP exchanges from a TaintForge replay store")
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--store", type=Path, required=True)
    parser.add_argument("--expected-store-sha256", required=True)
    parser.add_argument("--log-dir", type=Path, required=True)
    args = parser.parse_args()

    args.log_dir.mkdir(parents=True, exist_ok=True)
    try:
        store = ReplayStore(args.store)
        validation = store.validate()
        if validation["store_sha256"] != args.expected_store_sha256:
            raise NetworkReplayError(
                f"replay store digest does not match the bound execution contract: expected {args.expected_store_sha256}, got {validation['store_sha256']}"
            )
        asyncio.run(run_network_replay(policy=load_network_policy(args.policy),replay_store=store,log_dir=args.log_dir))
    except KeyboardInterrupt:
        return 0
    except (NetworkReplayError, ReplayStoreError, OSError, ValueError) as exc:
        print(f"Network replay failed: {exc}")
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
