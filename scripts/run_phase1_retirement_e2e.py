#!/usr/bin/env python3
"""VM acceptance for real Phase 1 retirement inside the unified Capsule."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

from experiments.execution_capsule_probe import controller as probe
from taintforge_env.phase1_retirement import FAULTS, check_runtime
from taintforge_env.synthesis_loop import EnvironmentSynthesisLoop

PROJECT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--qemu", type=Path, required=True)
    parser.add_argument("--plugin", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--memory-mib", type=int, default=1024)
    parser.add_argument("--trigger", choices=("boundary", "verdict"), default="boundary")
    args = parser.parse_args()
    os.umask(0o077)
    qemu, plugin, out = args.qemu.resolve(), args.plugin.resolve(), args.out.resolve()
    _, runtime, _ = probe.load_phase1(PROJECT, plugin, qemu)
    check_runtime(runtime, trigger=args.trigger)
    from taintforge_env.capsule_resources import preflight, policy
    policy(args.memory_mib)
    preflight()
    out.mkdir(parents=True, exist_ok=False)
    before = {str(p): probe.sha(p) for p in (qemu, plugin, runtime.manifest)}
    report = {"schema_version": 1, "status": "failed", "cases": [], "runtime_before": before,
              "scope": "real_phase1_controlled_retirement", "hostile_sample_ready": False,
              "oep_proven": False, "residue_free": False}
    report["trigger"] = args.trigger
    delays = (16, 17, 64) if args.trigger == "verdict" else (16,)
    scenarios = [(case, "none", delay) for delay in delays for case in ("phase1-first", "capsule-first")]
    scenarios += [("phase1-first", fault, 16) for fault in FAULTS if fault != "none"]
    for case, fault, delay in scenarios:
        label = f"{case}-{fault}"
        if args.trigger == "verdict":
            label += f"-delay-{delay}"
        directory = out / label
        result = {"label": label, "status": "failed", "fault": fault}
        command = [sys.executable, "-m", "scripts.run_unified_pipeline", "run",
            "--capsule-phase1-retirement", "--capsule-case", case, "--capsule-retirement-fault", fault,
            "--capsule-retirement-trigger", args.trigger, "--capsule-selection-delay", str(delay),
            "--capsule-memory-mib", str(args.memory_mib), "--qemu", str(qemu), "--plugin", str(plugin),
            "--network", "none", "--max-iterations", "1", "--max-steps", "1", "--timeout", "90",
            "--out", str(directory)]
        result["command"] = command
        try:
            with (out / (label + ".stdout.log")).open("wb") as stdout, (out / (label + ".stderr.log")).open("wb") as stderr:
                completed = subprocess.run(command, cwd=PROJECT, stdout=stdout, stderr=stderr,
                                           timeout=150, check=False)
            saved = json.loads((directory / "unified_report.json").read_text())
            result["report"] = saved
            capsule = saved["capsule"]
            if capsule.get("failure"):
                result["failure"] = capsule["failure"]
                raise RuntimeError("Capsule " + capsule["failure"]["category"] + ": " + capsule.get("error", ""))
            code = FAULTS[fault]
            probe.require(completed.returncode == (0 if code == 0 else 1) and
                          capsule["status"] == ("passed" if code == 0 else "aborted") and
                          capsule["qemu_exit"] == code and not capsule["supervisor_kill"] and
                          saved["executions_this_invocation"] == 1, "Unexpected execution outcome")
            probe.require(capsule["resources"]["tree_empty"] is True and
                          saved["capsule_resources"]["tree_empty"] is True, "Process-tree cleanup failed")
            probe.require(capsule["phase1_retirement"]["phase1_retired"] is (code == 0),
                          "Retirement verdict mismatch")
            if code == 0:
                verified = EnvironmentSynthesisLoop.verify_session(directory / "session")
                probe.require(verified["binding_verified"] and verified["artifacts_verified"], "Session integrity failed")
                result["session_verified"] = True
            else:
                run = Path(saved["run_dir"])
                observations = run / "logs/capsule/observations.jsonl"
                digest = probe.sha(observations)
                resumed = subprocess.run([sys.executable, "-m", "scripts.run_unified_pipeline", "resume",
                    "--out", str(directory)], cwd=PROJECT, capture_output=True, text=True, timeout=30)
                (out / (label + ".resume.log")).write_text(resumed.stdout + resumed.stderr)
                retry = json.loads((directory / "unified_report.json").read_text())
                probe.require(resumed.returncode == 1 and retry["executions_this_invocation"] == 0 and
                              probe.sha(observations) == digest, "Failed retirement attempt was executed again")
                result["resume_blocked"] = True
            from taintforge_env.retirement_evidence import pack
            result["portable_evidence"] = pack(Path(saved["run_dir"]), directory / "retirement-evidence")
            result["status"] = "passed"
        except (OSError, ValueError, RuntimeError, KeyError, subprocess.TimeoutExpired) as exc:
            result["error"] = f"{type(exc).__name__}: {exc}"
        report["cases"].append(result)
        probe.write_json(out / "report.json", report)
        print(label + ": " + result["status"] + (" — " + result["error"] if "error" in result else ""), flush=True)
    unchanged = all(probe.sha(path) == value for path, value in before.items())
    report["runtime_unchanged"] = unchanged
    passed = unchanged and all(x["status"] == "passed" for x in report["cases"])
    if passed and args.trigger == "verdict":
        verdicts = [x["report"]["capsule"]["phase1_retirement"]["verdict"] for x in report["cases"] if x["fault"] == "none"]
        report["dynamic_trigger_verified"] = (len({v["oep"] for v in verdicts}) == 1 and
            len({v["decision_trace_seq"] for v in verdicts}) == len(delays) and
            len({v["continuation_pc"] for v in verdicts}) > 1 and
            all(v["trigger"] == "next_instruction_after_selection" for v in verdicts))
        passed = report["dynamic_trigger_verified"]
    report["status"] = "passed" if passed else "failed"
    probe.write_json(out / "report.json", report)
    print(out / "report.json")
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
