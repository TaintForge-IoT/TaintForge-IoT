#!/usr/bin/env python3
"""Reprocess saved QEMU logs in a new directory, without executing the guest.

Large input logs are linked, not copied. The original failed session and its
claims, hashes and Phase 1 artifacts are not modified or marked successful.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from taintforge_env.log_io import read_log_preview
from taintforge_env.observations import load_observation_bundle
from taintforge_env.qemu_strace_parser import parse_qemu_strace
from taintforge_env.repair_planner import RepairPlanner
from taintforge_env.report_generator import RunReportGenerator
from taintforge_env.requirement_extractor import RequirementExtractor


def write_json(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def reprocess(run_dir: Path, out: Path) -> dict:
    source = run_dir.expanduser().resolve(strict=True)
    output = out.expanduser().absolute()
    if not source.is_dir():
        raise ValueError(f"run directory does not exist: {source}")
    if output.exists() or output.is_symlink():
        raise ValueError(f"use a new output directory: {output}")
    if output.resolve().is_relative_to(source):
        raise ValueError("reprocessing output must be outside the original run directory")
    raw_trace = source / "logs/qemu_strace.log"
    if raw_trace.is_symlink() or not raw_trace.is_file():
        raise ValueError(f"missing regular QEMU trace: {raw_trace}")
    runtime_path = source / "config/runtime.json"
    runtime = json.loads(runtime_path.read_text(encoding="utf-8"))
    if not isinstance(runtime, dict) or not isinstance(runtime.get("arch"), str):
        raise ValueError("runtime.json must contain the guest architecture")

    output.mkdir(parents=True, exist_ok=False)
    (output / "logs").mkdir()
    (output / "config").mkdir()
    metadata = {
        "schema_version": 1, "status": "processing", "source_run_dir": str(source),
        "output_dir": str(output), "guest_executed": False, "session_resumed": False,
        "phase1_artifacts_verified": False, "fuzzing_ready": False,
        "input_storage": "links_to_original_files_keep_source_directory",
    }
    write_json(output / "reprocessing.json", metadata)
    try:
        # All links are input-only. New derived files have different fixed names.
        for relative in (
            "config/runtime.json", "config/prebuilt_execution.json", "config/runtime_status.json",
            "config/prebuilt_runner_manifest.json",
            "config/rootfs_before.json", "config/rootfs_after.json", "config/rootfs_diff.json",
            "config/network_policy.json", "config/library_plan.json", "config/library_resolution.json",
            "config/guest_runtime.json", "logs/runtime_stdout.log", "logs/runtime_stderr.log",
            "logs/network_events.jsonl", "logs/runtime_status.json", "logs/security_status.json",
            "logs/rootfs_snapshot_before.json", "logs/rootfs_snapshot_after.json", "logs/rootfs_diff.json",
            "runtime_status.json", "rootfs_diff.json",
        ):
            path = source / relative
            if path.exists():
                if not path.is_file():
                    raise ValueError(f"expected a regular input file: {path}")
                (output / relative).symlink_to(path.resolve(strict=True))

        # Older failed runners had not yet written prebuilt_execution.json.
        execution_path = output / "config/prebuilt_execution.json"
        if not execution_path.exists():
            exit_path = source / "logs/guest_exit_code"
            if exit_path.is_file():
                value, truncated = read_log_preview(exit_path, 64)
                if truncated:
                    raise ValueError("invalid guest_exit_code artifact")
                code = int(value.strip())
                if not 0 <= code <= 255:
                    raise ValueError("guest_exit_code is outside the shell status range")
                write_json(execution_path, {
                    "schema_version": 1, "guest_exit_code": code, "timed_out": code == 124,
                    "target_arch": runtime["arch"], "trace_backend": "qemu_strace",
                    "recovered_from": str(exit_path),
                    "timeout_classification": "wrapper_exit_code_124",
                })

        summary = parse_qemu_strace(raw_trace, output / "logs/syscall_events.jsonl",
                                   target_arch=runtime["arch"])
        bundle = load_observation_bundle(output)
        requirements = RequirementExtractor().extract(bundle)
        requirements_path = output / "config/runtime_requirements.json"
        requirements.save(requirements_path)
        plan = RepairPlanner().plan_file(requirements_path, output / "config/repair_plan.json")
        generator = RunReportGenerator(output)
        report = generator.generate()
        metadata.update(
            status="reprocessed", events_total=summary["events_total"],
            requirements_total=len(requirements.requirements), repair_plan_summary=plan.summary(),
            filesystem_observation_available=report["filesystem"]["observation_available"],
            execution=bundle.runtime_status,
            report_json=str(output / "report.json"), report_markdown=str(output / "report.md"),
        )
        report["reprocessing"] = metadata
        generator.save_json_report(report)
        prefix = (
            "# Offline log reprocessing\n\n"
            f"Source: `{source}`\n\n"
            "The guest was not executed. The original session was not resumed. "
            "Phase 1 capture integrity and fuzzing readiness are not established by this report.\n\n"
            f"Filesystem observation available: `{metadata['filesystem_observation_available']}`.\n\n"
        )
        (output / "report.md").write_text(prefix + generator.render_markdown(report), encoding="utf-8")
        write_json(output / "reprocessing.json", metadata)
        return metadata
    except Exception as exc:
        metadata.update(status="failed", error=f"{type(exc).__name__}: {exc}")
        write_json(output / "reprocessing.json", metadata)
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    try:
        result = reprocess(args.run_dir, args.out)
    except (OSError, ValueError, RuntimeError) as exc:
        parser.exit(1, f"Log reprocessing failed: {exc}\n")
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
