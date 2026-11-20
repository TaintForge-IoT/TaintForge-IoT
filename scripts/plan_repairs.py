#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path

from taintforge_env.repair_planner import RepairPlanner, RepairPlanningError


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Build a passive, auditable Phase 2 repair plan from "
            "runtime_requirements.json. The command never mutates the rootfs."
        )
    )
    parser.add_argument(
        "--requirements",
        required=True,
        type=Path,
        help="Path to config/runtime_requirements.json",
    )
    parser.add_argument(
        "--out",
        required=True,
        type=Path,
        help="Output path for repair_plan.json",
    )
    parser.add_argument("--network-repair-policy", type=Path)
    parser.add_argument("--network-policy", type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        from taintforge_env.network_repair import NetworkRepairPolicy
        from taintforge_env.network_policy import load_network_policy
        authorization = NetworkRepairPolicy.load(args.network_repair_policy) if args.network_repair_policy else None
        active = load_network_policy(args.network_policy) if args.network_policy else None
        plan = RepairPlanner(network_repair_policy=authorization, network_policy=active).plan_file(args.requirements, args.out)
    except (RepairPlanningError, ValueError, OSError) as exc:
        print(f"[!] Repair planning failed: {exc}")
        return 2

    summary = plan.summary()
    print(f"[+] Repair plan: {args.out}")
    print(f"[+] Decisions: {summary['decisions_total']}")
    print(f"[+] Automatic candidates: {summary['automatic_candidates']}")
    for disposition, count in summary["by_disposition"].items():
        print(f"    {disposition}: {count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
