#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from taintforge_env.prebuilt_runner import (
    PrebuiltRootfsRunner,
    PrebuiltRunnerConfig,
    PrebuiltRunnerError,
)


def add_execution_arguments(command: argparse.ArgumentParser) -> None:
    command.add_argument("--session-dir", type=Path, required=True)
    command.add_argument("--iteration", type=int, required=True)
    command.add_argument("--template-run-dir", type=Path, required=True)
    command.add_argument(
        "--project-root",
        type=Path,
        default=Path.cwd(),
    )
    command.add_argument(
        "--binary",
        type=Path,
        default=None,
        help=(
            "Host sample path. Defaults to host_binary from the template "
            "runtime.json."
        ),
    )
    command.add_argument("--timeout", type=int, default=60)
    command.add_argument(
        "--network",
        choices=("none", "controlled", "replay"),
        default="none",
        help=(
            "none creates a disconnected private namespace; controlled adds "
            "known local responders and transparent TCP/UDP capture without "
            "Internet forwarding; replay serves only exact TCP exchanges from "
            "--replay-store and drops unknown traffic."
        ),
    )
    command.add_argument(
        "--replay-store",
        type=Path,
        default=None,
        help=(
            "ReplayStore directory required by --network replay. Its semantic "
            "digest is verified and a private per-attempt copy is executed."
        ),
    )
    command.add_argument(
        "--network-self-test",
        action="store_true",
        help=(
            "Probe controlled network routes before malware execution, archive "
            "the probe traffic separately, and restart clean responders."
        ),
    )
    command.add_argument(
        "--target-spec",
        type=Path,
        default=None,
        help=(
            "Versioned target-state JSON evaluated after runtime artifacts "
            "are produced. A satisfied target marks the iteration goal reached."
        ),
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Validate or execute one IterationController-prepared rootfs "
            "without rebuilding the environment. Selects native or static "
            "QEMU user-mode execution from verified ELF metadata and supports "
            "isolated network-none, controlled local-responder, and exact "
            "replay modes."
        )
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    validate = subparsers.add_parser("validate")
    add_execution_arguments(validate)

    run = subparsers.add_parser("run")
    add_execution_arguments(run)
    run.add_argument("--goal-reached", action="store_true")
    run.add_argument("--goal-reason", default=None)

    reset = subparsers.add_parser("reset-safe-failure")
    reset.add_argument("--session-dir", type=Path, required=True)
    reset.add_argument("--iteration", type=int, required=True)
    return parser


def make_config(args: argparse.Namespace) -> PrebuiltRunnerConfig:
    if args.command == "reset-safe-failure":
        return PrebuiltRunnerConfig(
            session_dir=args.session_dir,
            iteration_index=args.iteration,
            template_run_dir=Path("."),
            project_root=Path.cwd(),
        )
    return PrebuiltRunnerConfig(
        session_dir=args.session_dir,
        iteration_index=args.iteration,
        template_run_dir=args.template_run_dir,
        project_root=args.project_root,
        timeout_seconds=args.timeout,
        binary_path=args.binary,
        target_spec_path=getattr(args, "target_spec", None),
        network_mode=getattr(args, "network", "none"),
        network_self_test=getattr(args, "network_self_test", False),
        replay_store_path=getattr(args, "replay_store", None),
        goal_reached=getattr(args, "goal_reached", False),
        goal_reason=getattr(args, "goal_reason", None),
    )


def main() -> int:
    args = build_parser().parse_args()
    try:
        runner = PrebuiltRootfsRunner(make_config(args))
        if args.command == "reset-safe-failure":
            runner.reset_safe_failure()
            print("[+] Retry-safe failed attempt was reset")
            return 0

        if args.command == "validate":
            context = runner.validate()
            print("[+] Prepared iteration is valid")
            print(f"[+] Session: {context.session.session_id}")
            print(f"[+] Iteration: {context.iteration.index}")
            print(
                "[+] Environment snapshot: "
                f"{context.iteration.environment_snapshot_id}"
            )
            print(
                "[+] Environment SHA-256: "
                f"{context.environment_tree_sha256}"
            )
            print(f"[+] Execution rootfs: {context.execution_rootfs}")
            print(f"[+] Guest binary: {context.guest_binary}")
            print(
                "[+] Execution backend: "
                f"{context.execution_plan.backend.value}"
            )
            print(f"[+] Target architecture: {context.execution_plan.target.arch}")
            print(
                "[+] Trace backend: "
                f"{context.execution_plan.trace_backend.value}"
            )
            if context.execution_plan.qemu_host_path is not None:
                print(f"[+] QEMU host path: {context.execution_plan.qemu_host_path}")
                print(
                    "[+] QEMU SHA-256: "
                    f"{context.execution_plan.qemu_host_sha256}"
                )
            return 0

        result = runner.run_and_complete()
        print("[+] Prebuilt iteration executed and completed")
        print(f"[+] Iteration: {result.iteration_index}")
        print(f"[+] Guest exit code: {result.guest_exit_code}")
        print(f"[+] Timed out: {result.timed_out}")
        print(f"[+] Stop reason: {result.stop_reason}")
        print(f"[+] Target reached: {result.target_reached}")
        print(f"[+] Target evaluation: {result.target_evaluation_path}")
        print(f"[+] Network mode: {result.network_mode}")
        print(f"[+] Network manifest: {result.network_manifest_path}")
        print(f"[+] Execution backend: {result.execution_backend}")
        print(f"[+] Target architecture: {result.target_arch}")
        print(
            "[+] Execution backend manifest: "
            f"{result.execution_backend_manifest_path}"
        )
        print(
            "[+] Progress: "
            + json.dumps(result.progress, ensure_ascii=False)
        )
        print(f"[+] Run artifacts: {result.run_dir}")
        print(f"[+] Execution claim: {result.claim_path}")
        return 0
    except PrebuiltRunnerError as exc:
        print(f"[!] Prebuilt iteration runner failed: {exc}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
