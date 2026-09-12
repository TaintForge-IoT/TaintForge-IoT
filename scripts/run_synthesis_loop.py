#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from taintforge_env.synthesis_loop import (
    EnvironmentSynthesisLoop,
    LoopOutcome,
    SynthesisLoopConfig,
    SynthesisLoopError,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Drive the TaintForge-IoT environment synthesis state machine: "
            "prepare an immutable iteration, execute its prebuilt rootfs, "
            "complete the observation, and repeat until a controller stop "
            "condition or invocation step limit is reached. Native and "
            "static QEMU user-mode execution are selected automatically from "
            "the bound ELF target."
        )
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    run = subparsers.add_parser("run", help="initialize/resume and advance a session")
    run.add_argument("--session-dir", type=Path, required=True)
    run.add_argument("--template-run-dir", type=Path, required=True)
    run.add_argument("--project-root", type=Path, default=Path.cwd())
    run.add_argument("--snapshot-store", type=Path)
    run.add_argument("--seed-rootfs", type=Path)
    run.add_argument("--binary", type=Path)
    run.add_argument(
        "--target-spec",
        type=Path,
        help=(
            "Versioned target-state JSON. It is hashed into the session "
            "binding and evaluated after every iteration."
        ),
    )
    run.add_argument("--max-iterations", type=int, default=5)
    run.add_argument("--timeout", type=int, default=60)
    run.add_argument(
        "--network",
        choices=("none", "controlled", "replay"),
        default="none",
        help=(
            "Execution network backend. controlled preserves known endpoints, "
            "captures unknown TCP/UDP attempts, and blocks real Internet egress; "
            "replay answers only exact stored TCP requests and fails closed."
        ),
    )
    run.add_argument(
        "--replay-store",
        type=Path,
        help=(
            "ReplayStore directory required by --network replay. The store "
            "digest becomes part of the immutable synthesis binding."
        ),
    )
    run.add_argument(
        "--network-self-test",
        action="store_true",
        help=(
            "Validate controlled network infrastructure before every malware "
            "execution and keep probe traffic outside malware evidence."
        ),
    )
    run.add_argument(
        "--max-steps",
        type=int,
        default=1,
        help=(
            "Maximum malware executions in this invocation. The session-wide "
            "limit remains --max-iterations. Default 1 is intentionally cautious."
        ),
    )
    run.add_argument("--adopt-existing-session", action="store_true")
    run.add_argument("--initialize-only", action="store_true")

    status = subparsers.add_parser("status", help="show loop and controller state")
    status.add_argument("--session-dir", type=Path, required=True)

    verify = subparsers.add_parser(
        "verify",
        help="verify bound target hashes, snapshots, and iteration artifacts",
    )
    verify.add_argument("--session-dir", type=Path, required=True)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        if args.command == "status":
            print(
                json.dumps(
                    EnvironmentSynthesisLoop.status(args.session_dir),
                    indent=2,
                    ensure_ascii=False,
                )
            )
            return 0
        if args.command == "verify":
            print(
                json.dumps(
                    EnvironmentSynthesisLoop.verify_session(args.session_dir),
                    indent=2,
                    ensure_ascii=False,
                )
            )
            return 0

        result = EnvironmentSynthesisLoop(
            SynthesisLoopConfig(
                session_dir=args.session_dir,
                template_run_dir=args.template_run_dir,
                project_root=args.project_root,
                snapshot_store=args.snapshot_store,
                seed_rootfs=args.seed_rootfs,
                binary_path=args.binary,
                target_spec_path=args.target_spec,
                network_mode=args.network,
                network_self_test=args.network_self_test,
                replay_store_path=args.replay_store,
                max_iterations=args.max_iterations,
                timeout_seconds=args.timeout,
                max_steps=args.max_steps,
                adopt_existing_session=args.adopt_existing_session,
                initialize_only=args.initialize_only,
            )
        ).run()
        print("[+] Environment synthesis loop finished")
        print(f"[+] Session: {result.session_id}")
        print(f"[+] Outcome: {result.outcome.value}")
        print(f"[+] Stop reason: {result.stop_reason}")
        print(f"[+] Executions this invocation: {result.executions_this_invocation}")
        print(f"[+] Total iterations: {result.total_iterations}")
        print(f"[+] JSON report: {result.report_json}")
        print(f"[+] Markdown report: {result.report_markdown}")
        return 2 if result.outcome == LoopOutcome.INTERVENTION_REQUIRED else 0
    except SynthesisLoopError as exc:
        print(f"[!] Environment synthesis loop failed: {exc}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
