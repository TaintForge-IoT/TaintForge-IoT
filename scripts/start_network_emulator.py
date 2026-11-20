import argparse
import asyncio
from pathlib import Path
from taintforge_env.network_policy import load_network_policy
from taintforge_env.network_stub import run_network_emulator
from taintforge_env.network_runtime import run_network_service, NetworkRuntimeLimits

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--policy", required=True)
    parser.add_argument("--log-dir", required=True)
    parser.add_argument("--runtime", type=Path)
    args = parser.parse_args()

    policy = load_network_policy(args.policy)

    log_dir = Path(args.log_dir)
    log_dir.mkdir(parents=True, exist_ok=True)

    try:
        asyncio.run(run_network_service(lambda: run_network_emulator(policy=policy, log_dir=log_dir),
            log_dir=log_dir, runtime_path=args.runtime, limits=NetworkRuntimeLimits.parse(policy.runtime_limits)))
    except KeyboardInterrupt:
        print("Network emulator stopped")

if __name__ == "__main__":
    main()
