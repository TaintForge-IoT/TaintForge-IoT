#!/usr/bin/env python3
"""VM acceptance for the controlled capsule handoff inside the unified sandbox."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import time

from experiments.execution_capsule_probe import controller as probe
from taintforge_env.execution_capsule import expected_exit, read_json
from taintforge_env.synthesis_loop import EnvironmentSynthesisLoop

PROJECT = Path(__file__).resolve().parents[1]
DEFAULT_CASES = ("phase1-first", "capsule-first", "timeout-1", "disconnect-1", "kill-controller-1")


def run_case(out, case, qemu, plugin, *, lifecycle=False, mode="remove", order="after", memory_mib=1024):
    result = {"case": case, "status": "failed", "scope": "unified_controlled_i386"}
    label = case if not lifecycle else f"{case}-{mode}-{order}"
    result.update(label=label, lifecycle=lifecycle, owner_mode=mode, owner_order=order)
    started = time.monotonic()
    directory = out / label
    command = [sys.executable, "-m", "scripts.run_unified_pipeline", "run",
               "--capsule-lifecycle" if lifecycle else "--capsule-probe",
               "--capsule-case", case, "--qemu", str(qemu), "--plugin", str(plugin),
               "--network", "none", "--max-iterations", "1", "--max-steps", "1",
               "--timeout", "60", "--out", str(directory)]
    if lifecycle:
        command += ["--capsule-owner-mode", mode, "--capsule-owner-order", order,
                    "--capsule-memory-mib", str(memory_mib)]
    result["command"] = command
    try:
        with (out / f"{label}.stdout.log").open("w") as stdout, (out / f"{label}.stderr.log").open("w") as stderr:
            completed = subprocess.run(command, cwd=PROJECT, stdout=stdout, stderr=stderr, check=False)
        report = read_json(directory / "unified_report.json")
        result["unified_report"] = report
        code = 125 if mode != "remove" else expected_exit(case)
        capsule = report["capsule"]
        probe.require(completed.returncode == (0 if code == 0 else 1), "Unexpected unified CLI exit")
        probe.require(capsule["status"] == ("passed" if code == 0 else "aborted"), "Capsule outcome mismatch")
        probe.require(capsule["qemu_exit"] == code and not capsule["supervisor_kill"], "Native termination was not verified")
        probe.require(report["execution"]["guest_exit_code"] == code, "Unified exit does not match capsule")
        probe.require(report["executions_this_invocation"] == 1, "Expected exactly one guest execution")
        run = Path(report["run_dir"])
        binding = read_json(run / "config/capsule_binding.json")
        for key in ("attempt_id", "attempt_contract_sha256", "session_id", "analysis_instance_id", "bundle_sha256"):
            probe.require(capsule[key] == binding[key], f"Capsule {key} mismatch")
        probe.require(not (Path(binding["rootfs"]) / "__taintforge_capsule").exists(), "Capsule mount directory survived cleanup")
        probe.require(not (Path(binding["rootfs"]) / "__taintforge").exists(), "Analyzer mount directory survived cleanup")
        if lifecycle:
            from taintforge_env.capsule_lifecycle import MODES
            owner = capsule["lifecycle"]
            probe.require(capsule["resources"]["status"] == "verified" and capsule["resources"]["tree_empty"]
                          and report["capsule_resources"]["tree_empty"], "Resource policy or cleanup failed")
            probe.require(owner["attempt"] == binding["lifecycle_attempt"] and
                          owner["claims"]["phase1_retired"] is False, "Invalid lifecycle scope or identity")
            probe.require(owner["rejection"] == MODES[mode], "Unexpected lifecycle rejection")
            retired = mode == "remove" and (code == 0 or case.endswith("-2"))
            probe.require(owner["owner_retired"] is retired, "Owner retirement verdict mismatch")
        if code == 0:
            probe.require(report["phase1"]["artifact_integrity"] == "verified" and
                          report["phase1"]["runtime_observed"] and report["finalization"]["status"] == "completed",
                          "Positive run did not finalize Phase 1 and the attempt")
            verification = EnvironmentSynthesisLoop.verify_session(directory / "session")
            probe.require(verification["binding_verified"] and verification["artifacts_verified"], "Session verification failed")
            result["session_verified"] = True
        else:
            probe.require(report["outcome"] == "intervention_required" and
                          report["finalization"]["stages"]["capsule"]["status"] == "failed",
                          "Aborted handoff was treated as a completed attempt")
            claim = read_json(run.parent / "execution_attempt.json")
            probe.require(claim["stage"] == "failed" and not claim["retry_safe"], "Aborted attempt is retryable")
            observations = run / "logs/capsule/observations.jsonl"
            before = probe.sha(observations)
            retry = subprocess.run([sys.executable, "-m", "scripts.run_unified_pipeline", "resume",
                                    "--out", str(directory)], cwd=PROJECT, capture_output=True, text=True, check=False)
            (out / f"{label}.resume.log").write_text(retry.stdout + retry.stderr)
            resumed = read_json(directory / "unified_report.json")
            probe.require(retry.returncode == 1 and resumed["executions_this_invocation"] == 0 and
                          probe.sha(observations) == before, "Resume executed a failed attempt again")
            result["resume_blocked"] = True
        result["status"] = "passed"
    except (OSError, ValueError, RuntimeError, KeyError) as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
    result["elapsed_seconds"] = round(time.monotonic() - started, 3)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--qemu", type=Path, default=Path("/usr/bin/qemu-i386"))
    parser.add_argument("--plugin", type=Path, default=Path("build/libtaintforge_ir.so"))
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--all-cases", action="store_true", help="also exercise point-2 aborts and command/total timeouts")
    parser.add_argument("--lifecycle", action="store_true", help="include the owner plugin, cgroup limits and retirement faults")
    parser.add_argument("--memory-mib", type=int, default=1024)
    args = parser.parse_args()
    os.umask(0o077)
    out = args.out.resolve()
    qemu, plugin = args.qemu.resolve(), args.plugin.resolve()
    probe.load_phase1(PROJECT, plugin, qemu)
    if args.lifecycle:
        from taintforge_env.capsule_resources import preflight, policy
        policy(args.memory_mib)
        preflight()
    out.mkdir(parents=True, exist_ok=False)
    hashes = {str(path): probe.sha(path) for path in (qemu, plugin, Path(str(plugin) + ".runtime.json"))}
    report = {"schema_version": 1, "status": "failed", "cases": [], "runtime_before": hashes,
              "scope": "unified_controlled_i386_handoff", "whole_qemu_stop": False,
              "analyzer_quiescence": False, "memory_isolation": False, "fuzzing_ready": False}
    if args.lifecycle:
        report.update(scope="unified_controlled_i386_lifecycle", phase1_retired=False, hostile_sample_ready=False)
    try:
        cases = probe.CASES[1:] if args.all_cases else DEFAULT_CASES
        scenarios = [(case, "remove", "after") for case in cases]
        if args.lifecycle:
            scenarios += [("phase1-first", "remove", "before"),
                          *(("phase1-first", mode, "after") for mode in ("keep", "leak-arena", "bad-export"))]
            if not args.all_cases:
                scenarios += [(case, "remove", "after") for case in ("timeout-2", "disconnect-2", "kill-controller-2")]
        for case, mode, order in scenarios:
            result = run_case(out, case, qemu, plugin, lifecycle=args.lifecycle, mode=mode,
                              order=order, memory_mib=args.memory_mib)
            report["cases"].append(result)
            probe.write_json(out / "report.json", report)
            print(f"{result['label']}: {result['status']}" + (" — " + result["error"] if "error" in result else ""), flush=True)
        probe.require(all(probe.sha(path) == value for path, value in hashes.items()), "QEMU/Phase 1 runtime changed")
        report["status"] = "passed" if all(case["status"] == "passed" for case in report["cases"]) else "failed"
    except (OSError, ValueError, RuntimeError) as exc:
        report["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        probe.write_json(out / "report.json", report)
    print(out / "report.json")
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
