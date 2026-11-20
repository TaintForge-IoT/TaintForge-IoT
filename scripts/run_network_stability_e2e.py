#!/usr/bin/env python3
"""NET-9: bounded repetitions of benign native capsules, faults and cleanup audits."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT))

from scripts import run_network_capsule_e2e as net6
from scripts import run_network_capsule_sessions_e2e as net8
from taintforge_env.capsule_resources import preflight
from taintforge_env.network_acceptance import (
    CHECKS, prerequisites, read_json, require, runtime_identity, source_identity, write_json,
)
from taintforge_env.network_stability import (
    DEFAULT_ROUNDS, IDENTITIES, MAX_ROUNDS, SCOPE, SUITES, attempts, audit_run,
    capture_ownership, host_snapshot, validate_result, validate_round,
)


class OwnershipMixin:
    def _execute_guest(self, context, *, network_backend=None):
        ownership = capture_ownership(context, network_backend)
        write_json(context.run_dir / "logs/net9_ownership.json", ownership)
        return super()._execute_guest(context, network_backend=network_backend)


class AuditedRunner(OwnershipMixin, net6.PrebuiltRootfsRunner):
    pass


class AuditedFaultRunner(OwnershipMixin, net6.FaultRunner):
    pass


def execution_inventory(root):
    phases, supervisors, errors = [], [], []
    for suffix, values in (("config/phase1_result.json", phases), ("logs/capsule/supervisor.json", supervisors)):
        for path in sorted(root.glob("*/pipeline/session/iterations/*/run/" + suffix)):
            try:
                value = read_json(path)
                if suffix.startswith("logs/"):
                    require(isinstance(value.get("network_namespace", {}), dict), "invalid namespace evidence")
                values.append(value)
            except (OSError, ValueError) as exc:
                errors.append({"path": str(path.relative_to(root)), "error": str(exc)[:1000]})
    return {"guest_executions": sum(p.get("runtime_observed") is True for p in phases),
            "qemu_launch_attempts": sum(type(s.get("qemu_pid")) is int for s in supervisors),
            "phase1_executed": any(p.get("runtime_observed") is True for p in phases),
            "capsule_executed": any(type(s.get("qemu_pid")) is int for s in supervisors),
            "namespace_executed": any(s.get("network_namespace", {}).get("status") == "verified" for s in supervisors),
            "artifact_errors": errors}


def run_audited_case(root, suite, name, binaries):
    before = host_snapshot()
    write_json(root.parent / (name + ".before.json"), before)
    row = {"case": name, "status": "failed"}
    interrupted = False
    try:
        if suite == "capsule":
            row = net6.run_case(root, name, *binaries,
                               runner_factory=AuditedFaultRunner if name == "responder_crash" else AuditedRunner)
        else:
            row = net8.run_case(root, net8.BY_NAME[name], *binaries, runner_factory=AuditedRunner)
    except KeyboardInterrupt:
        interrupted = True
        row.update(status="interrupted", error="interrupted; successful cleanup is not certified")
    except (OSError, ValueError, RuntimeError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        row.update(status="failed", error=f"{type(exc).__name__}: {exc}")
    finally:
        audits = []
        errors = []
        try:
            after = host_snapshot()
            write_json(root.parent / (name + ".after.json"), after)
            runs = sorted(root.glob("pipeline/session/iterations/*/run"))
            for run in runs:
                try:
                    audit = audit_run(run, before, after)
                    audit["run"] = run.relative_to(root).as_posix()
                    audits.append(audit)
                except (OSError, ValueError, RuntimeError, KeyError, TypeError, subprocess.SubprocessError) as exc:
                    errors.append({"run": run.relative_to(root).as_posix(), "error": f"{type(exc).__name__}: {exc}"})
            if row["status"] == "passed":
                native = attempts(suite, row)
                failures = [a["attempt_id"] + ": " + ", ".join(k for k, v in a["checks"].items() if not v)
                            for a in audits if a["status"] != "passed"]
                require(len(audits) == len(native) and all(a["status"] == "passed" for a in audits),
                        "independent cleanup audit failed: " + ("; ".join(failures) or "missing attempt audit"))
                require([a["attempt_id"] for a in audits] == [a["attempt_id"] for a in native],
                        "cleanup audit order or identities differ")
                if suite == "capsule" and name == "responder_crash":
                    row["fault"] = read_json(runs[0] / "logs/net6_fault.json")
        except (OSError, ValueError, RuntimeError, KeyError, TypeError, subprocess.SubprocessError) as exc:
            errors.append({"error": f"{type(exc).__name__}: {exc}"})
        row["cleanup_audit"] = audits
        row["audit_errors"] = errors
        if errors and not interrupted:
            row.update(status="failed", error=row.get("error") or errors[0]["error"])
        write_json(root.parent / (name + ".result.json"), row)
    if interrupted:
        raise KeyboardInterrupt
    return row


def run_campaign(out, *, qemu, plugin, observer, rounds=DEFAULT_ROUNDS):
    require(type(rounds) is int and 1 <= rounds <= MAX_ROUNDS, "rounds must be between 1 and 10")
    out = Path(out).expanduser().absolute()
    require(not out.is_symlink(), "output cannot be a symlink")
    out.mkdir(parents=True, mode=0o700, exist_ok=False)
    report = {"schema_version": 1, "scope": SCOPE, "status": "blocked", "full_stability": False,
              "rounds_requested": rounds, "rounds": [], "guest_executions": 0, "qemu_launch_attempts": 0,
              "phase1_executed": False, "capsule_executed": False, "namespace_executed": False,
              "oep_proven": False, "hostile_sample_ready": False, "source_unchanged": False, "runtime_unchanged": False}
    write_json(out / "report.json", report)
    paths = {"qemu": qemu, "plugin": plugin, "observer": observer}
    initial_source = initial_runtime = None
    started = time.monotonic()
    try:
        initial_runtime = runtime_identity(paths)
        problems = prerequisites(next(check for check in CHECKS if check.name == "capsule"), "full", initial_runtime)
        require(not problems, "; ".join(problems))
        preflight()
        selected = net6.check_runtime_inputs(PROJECT, qemu=qemu, plugin=plugin)
        metadata = net6.validate_observer(observer)
        require(selected["plugin_api"] == metadata["plugin_api"] == 6, "NET-9 requires plugin API 6")
        binaries = [Path(initial_runtime[name]["resolved_path"]) for name in ("qemu", "plugin", "observer")]
        initial_source = source_identity(PROJECT)
        write_json(out / "source.json", initial_source)
        report.update(status="failed", runtime_sha256={str(path): initial_runtime[name]["sha256"]
                      for name, path in zip(("qemu", "plugin", "observer"), binaries)}, plugin_api=6,
                      source_sha256=initial_source["sha256"])
        seen = {key: set() for key in IDENTITIES}
        reference = None
        for index in range(1, rounds + 1):
            row = {"index": index, "status": "running", "suites": {}}
            report["rounds"].append(row)
            for suite in SUITES:
                root = out / f"round-{index:02d}" / suite
                root.mkdir(parents=True, mode=0o700)
                data = {"schema_version": 1, "status": "failed", "cases": [], "plugin_api": 6,
                        "scope": "native_phase1_retirement_capsule_network" if suite == "capsule" else net8.SCOPE,
                        "runtime_sha256": report["runtime_sha256"], "oep_proven": False, "hostile_sample_ready": False}
                row["suites"][suite] = data
                names = net6.CASES if suite == "capsule" else tuple(net8.BY_NAME)
                for name in names:
                    print(f"round {index}/{rounds} {suite}/{name}: running", flush=True)
                    write_json(out / "report.json", report)
                    try:
                        case = run_audited_case(root / name, suite, name, binaries)
                        data["cases"].append(case)
                    finally:
                        data.update(execution_inventory(root))
                        write_json(root / "report.json", data)
                        write_json(out / "report.json", report)
                    print(f"round {index}/{rounds} {suite}/{name}: {case['status']}", flush=True)
                    require(case["status"] == "passed", f"round {index} {suite}/{name}: " + str(case.get("error")))
                data["status"] = "passed"
                write_json(root / "report.json", data)
            signature = validate_round({**row, "status": "passed"}, initial_runtime, seen)
            row["semantic_sha256"] = signature
            require(reference is None or reference == signature, "native outcomes changed between rounds")
            reference = signature
            row["status"] = "passed"
            write_json(out / "report.json", report)
        report["status"] = "passed" if rounds >= DEFAULT_ROUNDS else "incomplete"
    except KeyboardInterrupt:
        report.update(status="interrupted", error="interrupted; full cleanup is not certified")
    except (OSError, ValueError, RuntimeError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        report["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        for row in report["rounds"]:
            if row["status"] == "running":
                row["status"] = "interrupted" if report["status"] == "interrupted" else "failed"
        suites = [data for row in report["rounds"] for data in row["suites"].values()]
        for key in ("guest_executions", "qemu_launch_attempts"):
            report[key] = sum(data.get(key, 0) for data in suites)
        for key in ("phase1_executed", "capsule_executed", "namespace_executed"):
            report[key] = any(data.get(key) is True for data in suites)
        try:
            if initial_source is not None:
                report["source_unchanged"] = source_identity(PROJECT) == initial_source
            if initial_runtime is not None:
                report["runtime_unchanged"] = runtime_identity(paths) == initial_runtime
            if report["status"] in {"passed", "incomplete"}:
                require(report["source_unchanged"] and report["runtime_unchanged"], "sources or native runtime changed")
                if report["status"] == "passed":
                    report["full_stability"] = True
                    validate_result(report, initial_runtime)
        except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as exc:
            report.update(status="failed", error=f"{type(exc).__name__}: {exc}")
        report["full_stability"] = report["status"] == "passed"
        report["elapsed_seconds"] = round(time.monotonic() - started, 3)
        report["exit_code"] = {"passed": 0, "failed": 1, "blocked": 2, "incomplete": 2, "interrupted": 130}[report["status"]]
        write_json(out / "report.json", report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("out", "qemu", "plugin", "observer"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--rounds", type=int, default=DEFAULT_ROUNDS, choices=range(1, MAX_ROUNDS + 1))
    args = parser.parse_args()
    os.umask(0o077)
    def interrupted(signum, frame):
        raise KeyboardInterrupt
    previous = signal.signal(signal.SIGTERM, interrupted)
    try:
        report = run_campaign(args.out, qemu=args.qemu, plugin=args.plugin, observer=args.observer, rounds=args.rounds)
    except (OSError, ValueError) as exc:
        print(f"NET-9: {exc}", file=sys.stderr)
        return 1
    finally:
        signal.signal(signal.SIGTERM, previous)
    print(json.dumps({key: report[key] for key in ("status", "full_stability", "guest_executions", "exit_code")}, indent=2))
    print("Report: " + str(args.out.absolute() / "report.json"))
    return report["exit_code"]


if __name__ == "__main__":
    raise SystemExit(main())
