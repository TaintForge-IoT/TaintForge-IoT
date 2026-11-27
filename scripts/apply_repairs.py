#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path

from taintforge_env.repair_files import load_catalog
from taintforge_env.repair_applier import (
    RepairApplicationError,
    RepairApplier,
    RepairApplierConfig,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Apply only planner-authorized automatic repairs to a disposable "
            "Phase 2 rootfs. The command verifies the exact requirements "
            "artifact, preflights every selected decision, and writes an "
            "auditable application report."
        )
    )
    parser.add_argument(
        "--plan",
        required=True,
        type=Path,
        help="Path to config/repair_plan.json",
    )
    parser.add_argument(
        "--requirements",
        required=True,
        type=Path,
        help="Path to the exact config/runtime_requirements.json used by planner",
    )
    parser.add_argument(
        "--rootfs",
        required=True,
        type=Path,
        help="Disposable Phase 2 rootfs to mutate",
    )
    parser.add_argument(
        "--out",
        required=True,
        type=Path,
        help="Output path for repair_application.json",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate and report changes without mutating rootfs",
    )
    parser.add_argument("--network-repair-policy", type=Path)
    parser.add_argument("--repair-files", type=Path, help="catalog of explicitly supplied guest files")
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    try:
        from taintforge_env.network_repair import NetworkRepairPolicy
        authorization = NetworkRepairPolicy.load(args.network_repair_policy) if args.network_repair_policy else None
        supplied = load_catalog(args.repair_files) if args.repair_files else {}
        report = RepairApplier(
            RepairApplierConfig(network_repair_policy=authorization), supplied_files=supplied,
        ).apply_file(
            plan_path=args.plan,
            requirements_path=args.requirements,
            rootfs=args.rootfs,
            out_path=args.out,
            dry_run=args.dry_run,
        )
    except (RepairApplicationError, ValueError, OSError) as exc:
        print(f"[!] Repair application failed: {exc}")
        if args.out.exists():
            print(f"[!] Failure report: {args.out}")
        return 2

    summary = report.summary()
    print(f"[+] Repair application report: {args.out}")
    print(f"[+] State: {report.state.value}")
    print(f"[+] Selected decisions: {summary['selected_total']}")
    print(f"[+] Applied decisions: {summary['applied_total']}")
    print(
        "[+] Already satisfied: "
        f"{summary['already_satisfied_total']}"
    )
    print(f"[+] Created paths: {summary['created_paths_total']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
