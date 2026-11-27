#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from taintforge_env.repair_files import load_catalog
from taintforge_env.iteration_controller import (
    DEFAULT_DISCOVERY_GOAL_ID,
    IterationController,
    IterationControllerError,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Manage immutable TaintForge-IoT environment-repair iterations. The controller prepares clean execution rootfs clones and records Phase 2 artifacts, but does not launch malware itself."
        )
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    init = subparsers.add_parser("init", help="create a new iteration session")
    init.add_argument("--session-dir", type=Path, required=True)
    init.add_argument("--snapshot-store", type=Path, required=True)
    init.add_argument("--seed-rootfs", type=Path, required=True)
    init.add_argument(
        "--sample-binary",
        type=Path,
        required=True,
        help="exact packed ELF whose SHA-256 will bind the session",
    )
    init.add_argument("--goal-id", default=DEFAULT_DISCOVERY_GOAL_ID)
    init.add_argument("--max-iterations", type=int, default=5)

    prepare = subparsers.add_parser(
        "prepare",
        help="prepare the next clean execution rootfs",
    )
    prepare.add_argument("--session-dir", type=Path, required=True)
    prepare.add_argument("--repair-files", type=Path, help="catalog of explicitly supplied guest files")

    complete = subparsers.add_parser(
        "complete",
        help="record externally produced Phase 2 artifacts",
    )
    complete.add_argument("--session-dir", type=Path, required=True)
    complete.add_argument("--iteration", type=int, required=True)
    complete.add_argument("--artifacts-dir", type=Path, required=True)
    complete.add_argument("--goal-reached", action="store_true")
    complete.add_argument("--goal-reason", default=None)
    complete.add_argument("--guest-exit-code", type=int, default=None)
    complete.add_argument("--timed-out", action="store_true")

    status = subparsers.add_parser("status", help="show session state")
    status.add_argument("--session-dir", type=Path, required=True)

    verify = subparsers.add_parser("verify", help="verify snapshots and artifacts")
    verify.add_argument("--session-dir", type=Path, required=True)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        if args.command == "init":
            sample_sha256 = _sha256_file(args.sample_binary)
            manifest = IterationController.initialize(
                session_dir=args.session_dir,
                snapshot_store=args.snapshot_store,
                seed_rootfs=args.seed_rootfs,
                sample_sha256=sample_sha256,
                packed_binary_sha256=sample_sha256,
                goal_id=args.goal_id,
                max_iterations=args.max_iterations,
            )
            print(f"[+] Session created: {manifest.session_id}")
            print(f"[+] Session directory: {manifest.session_dir}")
            print(f"[+] Seed snapshot: {manifest.seed_snapshot_id}")
            print(
                "[+] Seed environment manifest: "
                f"{manifest.seed_environment_manifest_id}"
            )
            print(f"[+] Packed sample SHA-256: {manifest.packed_binary_sha256}")
            print(f"[+] Goal: {manifest.goal_id}")
            print(f"[+] Iteration budget: {manifest.max_iterations}")
            return 0

        controller = IterationController(args.session_dir)
        if args.command == "prepare":
            supplied = load_catalog(args.repair_files) if args.repair_files else {}
            prepared = controller.prepare_next(supplied_files=supplied)
            print(f"[+] Prepared iteration: {prepared.record.index}")
            print(f"[+] Environment snapshot: {prepared.environment_snapshot_id}")
            print(f"[+] Environment manifest: {prepared.environment_manifest_id}")
            print(f"[+] Attempt: {prepared.attempt_id}")
            print(f"[+] Attempt contract: {prepared.attempt_contract_path}")
            print(f"[+] Execution rootfs: {prepared.execution_rootfs}")
            return 0
        if args.command == "complete":
            record = controller.complete_iteration(
                iteration_index=args.iteration,
                artifacts_dir=args.artifacts_dir,
                goal_reached=args.goal_reached,
                goal_reason=args.goal_reason,
                guest_exit_code=args.guest_exit_code,
                timed_out=args.timed_out,
            )
            print(f"[+] Completed iteration: {record.index}")
            print(f"[+] Progress: {record.progress['classification']}")
            print(f"[+] Stop reason: {record.stop_reason}")
            print(f"[+] Attempt result: {record.attempt_result}")
            return 0
        if args.command == "status":
            print(json.dumps(controller.load().to_dict(), indent=2))
            return 0
        if args.command == "verify":
            manifest = controller.verify()
            print(f"[+] Session verified: {manifest.session_id}")
            print(f"[+] State: {manifest.state.value}")
            print(f"[+] Iterations: {len(manifest.iterations)}")
            return 0
        raise AssertionError(args.command)
    except (IterationControllerError, OSError, ValueError) as exc:
        print(f"[!] Iteration controller failed: {exc}")
        return 2


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


if __name__ == "__main__":
    raise SystemExit(main())
