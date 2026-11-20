#!/usr/bin/env python3
"""NET-8: ordered TCP sessions through fresh Phase 1 retirement capsules."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import signal
import socket
import subprocess

from scripts.run_network_capsule_e2e import PROJECT, read, sha, validate_attempt
from scripts.run_unified_pipeline import parser as unified_parser, prepare, run_session
from taintforge_env.capsule_resources import preflight
from taintforge_env.network_capsule_sessions import BY_NAME, CASES, MARKER, SCOPE, require, specification, validate_transcript
from taintforge_env.network_observer import validate_observer
from taintforge_env.network_policy import NetworkPolicy, NetworkServicePolicy, CatchAllPolicy
from taintforge_env.replay_store import ReplayStore
from taintforge_env.synthesis_loop import EnvironmentSynthesisLoop
from taintforge_env.unified_runtime import check_runtime_inputs, write_json


EXIT_OBSERVATION_GRACE_MS = 5000


def build_guest(directory, *, port, mode, work=20000000, exit_grace_ms=0):
    require(type(port) is int and 1 <= port <= 65535, "invalid fixture port")
    require(type(mode) is int and mode in {case.mode for case in CASES}, "invalid fixture mode")
    require(type(work) is int and 1 <= work <= 20000000, "invalid fixture work count")
    require(type(exit_grace_ms) is int and 0 <= exit_grace_ms <= 10000 and exit_grace_ms % 10 == 0,
            "fixture exit grace must be 0..10000 ms in 10 ms steps")
    directory.mkdir(parents=True, exist_ok=False)
    source = PROJECT / "samples/network_capsule_session_i386.S"
    obj, binary = directory / "client.o", directory / "client.elf"
    definitions = {"NET8_PORT": port, "NET8_MODE": mode, "NET8_WORK": work,
                   "NET8_EXIT_GRACE_MS": exit_grace_ms}
    command = ["as", "--32"]
    for name, value in definitions.items():
        command += ["--defsym", f"{name}={value}"]
    command += [str(source), "-o", str(obj)]
    subprocess.run(command, check=True, capture_output=True)
    subprocess.run(["ld", "-m", "elf_i386", str(obj), "-o", str(binary)], check=True, capture_output=True)
    write_json(directory / "build.json", {"source_sha256": sha(source), "binary_sha256": sha(binary),
        "definitions": definitions, "assembler_command": command})
    return binary


def prepare_policy(root, case, port):
    store = ReplayStore(root / "store")
    session = store.add_session(specification(case, port))
    service = NetworkServicePolicy("tcp", "net8_benign", "127.0.0.1", port, None, "127.0.0.1", port,
                                   protocol_hint="net4_test", replay_session_id=session.session_id)
    policy = NetworkPolicy(mode="replay", services=[service],
                           catch_all=CatchAllPolicy(enabled=False, udp_enabled=False))
    write_json(root / "policy.json", policy.to_dict())
    return store, session


def run_case(root, case, qemu, plugin, observer, *, runner_factory=None):
    root.mkdir()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as guard:
        guard.bind(("127.0.0.1", 0))
        port = guard.getsockname()[1]
    binary = build_guest(root / "input", port=port, mode=case.mode,
                         exit_grace_ms=EXIT_OBSERVATION_GRACE_MS)
    store, session = prepare_policy(root, case, port)
    original_store = store.validate()["store_sha256"]
    write_json(root / "goal.json", {"schema_version": 1, "goal_id": "net8_validated_dialogue", "mode": "all",
        "description": "The benign guest compares all reply bytes before printing its marker",
        "rules": [{"id": "validated_dialogue", "type": "text_contains", "source": "stdout",
                   "needle": MARKER.decode()}]})
    pipeline = root / "pipeline"
    arguments = ["run", "--retire-phase1", "--analysis-policy", "research", "--capsule-hardening",
        "--binary", str(binary), "--qemu", str(qemu), "--plugin", str(plugin), "--network-observer", str(observer),
        "--network", "replay", "--network-policy", str(root / "policy.json"), "--replay-store", str(store.root),
        "--out", str(pipeline), "--target-spec", str(root / "goal.json"), "--max-iterations", "2", "--max-steps", "2"]
    launch = prepare(unified_parser().parse_args(arguments))
    report, code = run_session(pipeline, launch, max_steps=2, runner_factory=runner_factory)
    require(code == 0, "NET-8 unified execution failed: " + str(report.get("error")))
    runs = sorted((pipeline / "session/iterations").glob("*/run"))
    require(len(runs) == 1, "NET-8 must execute exactly one fresh attempt per case")
    run = runs[0]
    attempt = validate_attempt(run, goal=case.goal)
    require(attempt["input_sha256"] == sha(binary), "capsule executed another input ELF")
    capsule = read(run / "config/capsule_result.json")
    attempt["guest_exit"] = capsule["qemu_exit_status"]["returncode"]
    require(attempt["guest_exit"] == case.guest_exit, "guest exited for an unexpected reason")
    require((run / "logs/runtime_stdout.log").read_bytes() == (MARKER if case.goal else b""),
            "guest output differs from its application outcome")
    events_path = run / "logs/network_loopback/network_events.jsonl"
    require(events_path.stat().st_size <= 1024 * 1024, "NET-8 transcript is unexpectedly large")
    events = [json.loads(line) for line in events_path.read_text().splitlines() if line.strip()]
    transcript = validate_transcript(case, events, session, attempt_id=attempt["attempt_id"])
    transcript["sha256"] = sha(events_path)
    transcript["source"] = events_path.relative_to(run).as_posix()
    saved_session = read(pipeline / "session/session.json")
    require(saved_session["stop_reason"] == ("goal_reached" if case.goal else "no_automatic_repairs"),
            "session goal or automatic repair decision differs")
    EnvironmentSynthesisLoop.verify_session(pipeline / "session")
    require(store.validate()["store_sha256"] == original_store, "NET-8 mutated the replay store")
    return {"case": case.name, "status": "passed", "guest_executions": 1,
            "attempt": attempt, "transcript": transcript, "store_unchanged": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("qemu", "plugin", "observer", "out"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--case", choices=tuple(BY_NAME), action="append", dest="cases")
    args = parser.parse_args()
    names = args.cases or list(BY_NAME)
    if len(names) != len(set(names)):
        parser.error("duplicate --case")
    os.umask(0o077)
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    report = {"schema_version": 1, "status": "blocked", "scope": SCOPE, "cases": [],
        "phase1_executed": False, "capsule_executed": False, "namespace_executed": False,
        "hostile_sample_ready": False, "oep_proven": False, "guest_executions": 0, "qemu_launch_attempts": 0}
    write_json(out / "report.json", report)
    def interrupted(signum, frame):
        raise KeyboardInterrupt
    previous = signal.signal(signal.SIGTERM, interrupted)
    try:
        preflight()
        selected = check_runtime_inputs(PROJECT, qemu=args.qemu, plugin=args.plugin)
        metadata = validate_observer(args.observer)
        require(metadata["plugin_api"] == selected["plugin_api"] == 6, "NET-8 requires plugin API 6")
        binaries = [path.resolve(strict=True) for path in (args.qemu, args.plugin, args.observer)]
        identities = {str(path): sha(path) for path in binaries}
        report.update(status="failed", runtime_sha256=identities, plugin_api=6)
        for name in names:
            try:
                row = run_case(out / name, BY_NAME[name], *binaries)
            except (OSError, ValueError, RuntimeError, KeyError, subprocess.SubprocessError) as exc:
                row = {"case": name, "status": "failed", "error": f"{type(exc).__name__}: {exc}"}
            report["cases"].append(row)
            write_json(out / "report.json", report)
            print(f"{name}: {row['status']}", flush=True)
            if row["status"] != "passed":
                break
        require(all(sha(Path(path)) == value for path, value in identities.items()), "native runtime changed")
        if len(report["cases"]) == len(names) and all(row["status"] == "passed" for row in report["cases"]):
            report["status"] = "passed"
    except KeyboardInterrupt:
        report["status"] = "interrupted"
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        report["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        signal.signal(signal.SIGTERM, previous)
        phases, supervisors = [], []
        for pattern, values in (("config/phase1_result.json", phases), ("logs/capsule/supervisor.json", supervisors)):
            for path in out.glob("*/pipeline/session/iterations/*/run/" + pattern):
                try:
                    values.append(read(path))
                except (OSError, ValueError) as exc:
                    report.setdefault("artifact_errors", []).append({"path": str(path), "error": str(exc)})
        report.update(guest_executions=sum(p.get("runtime_observed") is True for p in phases),
                      qemu_launch_attempts=sum(type(s.get("qemu_pid")) is int for s in supervisors),
                      phase1_executed=any(p.get("runtime_observed") is True for p in phases),
                      capsule_executed=any(type(s.get("qemu_pid")) is int for s in supervisors),
                      namespace_executed=any(s.get("network_namespace", {}).get("status") == "verified" for s in supervisors))
        if report["status"] == "passed" and (report.get("artifact_errors") or
                report["guest_executions"] != len(names) or report["qemu_launch_attempts"] != len(names)):
            report.update(status="failed", error="NET-8 native execution inventory differs")
        write_json(out / "report.json", report)
    print(json.dumps(report, indent=2))
    return {"passed": 0, "failed": 1, "blocked": 2, "interrupted": 130}[report["status"]]


if __name__ == "__main__":
    raise SystemExit(main())
