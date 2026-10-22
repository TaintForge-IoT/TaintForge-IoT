"""Opt-in unified handoff experiment for the shipped single-thread i386 ELF.

The native reader and wire protocol stay in experiments/execution_capsule_probe.
This adapter binds their evidence to a real attempt, runs the controller in the
same PID namespace as QEMU, and validates the result before attempt completion.
An authorized handoff is NOT Phase 1 completion, analyzer quiescence or an OEP.
"""
from __future__ import annotations

import argparse
import json
import multiprocessing as mp
from pathlib import Path
import shlex
import shutil
import signal
import subprocess
import sys
import time
import uuid

from experiments.execution_capsule_probe import controller as probe

PROFILE = "controlled-i386-handoff-v1"
IPC_GUEST = "/__taintforge_capsule"
CASES = probe.CASES[1:]
IDENTITY = ("session_id", "attempt_id", "attempt_contract_sha256", "analysis_instance_id", "bundle_sha256")
LIMITS = {"phase1_detached": False, "phase1_finished_at_handoff": False,
          "whole_qemu_stop": False, "analyzer_quiescence": False,
          "memory_isolation": False, "checkpoint": False, "oep_proven": False,
          "fuzzing_ready": False, "protected_control_channel": False}


def read_json(path):
    value = json.loads(Path(path).read_text())
    probe.require(isinstance(value, dict), f"Expected an object: {path}")
    return value


def expected_exit(case):
    return (0 if case in {"phase1-first", "capsule-first"} else
            125 if case.startswith(("disconnect", "kill-controller")) else
            126 if case == "bad-command" else 124)


def bundle_profile(built):
    probe.require(built["plugin_api"] == 6, "Capsule requires API 6")
    result = {"profile": PROFILE, "plugin": "capsule/libcapsule_probe.so",
            "fixture": "capsule/guest_i386", "fixture_sha256": built["hashes"]["capsule_guest_i386"],
            "symbols": built["symbols"], "qemu_version": "11.0.1",
            "qemu_source_revision": built["qemu_source_revision"],
            "source_hashes": {key: built["hashes"][key] for key in ("probe.c", "guest.S", "qemu-plugin.h")}}
    if "lifecycle_plugin" in built:
        from .capsule_lifecycle import bundle_profile as owner_profile
        result["lifecycle"] = owner_profile(built)
    return result


def verify_profile(manifest):
    profile = manifest["capsule"]
    probe.require(isinstance(profile, dict) and profile.get("profile") == PROFILE and
                  profile.get("qemu_version") == "11.0.1" and manifest["plugin_api"] == 6,
                  "Unsupported capsule profile")
    inventory = {item["path"]: item for item in manifest["files"]}
    probe.require(profile.get("plugin") == "capsule/libcapsule_probe.so" and
                  profile.get("fixture") == "capsule/guest_i386" and
                  profile["plugin"] in inventory and profile["fixture"] in inventory and
                  inventory[profile["fixture"]]["sha256"] == profile.get("fixture_sha256"),
                  "Capsule fixture/plugin are not bound to the runtime bundle")
    symbols = profile.get("symbols", {})
    probe.require(set(symbols) == {"capsule_point_one", "capsule_point_two", "capsule_buffer"} and
                  all(type(value) is int and 0 < value <= 0xfffffff0 for value in symbols.values()) and
                  len(set(symbols.values())) == 3, "Invalid capsule observation addresses")
    if "lifecycle" in profile:
        from .capsule_lifecycle import verify_profile as verify_owner
        verify_owner(profile["lifecycle"], inventory)


def settings(case="phase1-first", *, hold_ms=200, pause_ms=5000, total_ms=30000, timeout=60):
    probe.require(case in CASES, "Unsupported unified capsule case")
    probe.require(50 <= hold_ms <= 1000 and hold_ms + 500 <= pause_ms <= 60000 and
                  10000 <= total_ms <= 600000 and timeout * 1000 >= total_ms + 12000,
                  "Capsule budgets require hold+500 <= pause and wrapper timeout >= total+12 seconds")
    return {"profile": PROFILE, "case": case, "hold_ms": hold_ms,
            "pause_ms": pause_ms, "total_ms": total_ms}


def prepare_binding(context, temporary, manifest, phase1):
    runtime = read_json(context.template_runtime_path)
    config = runtime.get("capsule", {})
    probe.require(config.get("profile") == PROFILE and runtime.get("network_mode") == "none",
                  "Capsule experiment requires explicit settings and network=none")
    settings(config["case"], hold_ms=config["hold_ms"], pause_ms=config["pause_ms"],
             total_ms=config["total_ms"], timeout=(config["total_ms"] / 1000 + 12))
    profile = manifest["capsule"]
    probe.require(context.execution_plan.target.sha256 == profile["fixture_sha256"],
                  "Capsule mode only accepts its bound controlled ELF")
    reserved = context.execution_rootfs / IPC_GUEST.lstrip("/")
    probe.require(not reserved.exists() and not reserved.is_symlink(), "Capsule IPC mount collides with guest path")
    fd_path = context.execution_rootfs / "capsule-fd.txt"
    probe.require(not fd_path.exists() and not fd_path.is_symlink(), "Capsule fixture output already exists")
    binding = {key: phase1[key] for key in IDENTITY}
    binding.update(schema_version=1, profile=PROFILE, settings=config, capsule=profile,
                   rootfs=str(context.execution_rootfs), run_dir=str(context.run_dir),
                   guest_binary=context.guest_binary, limitations=LIMITS)
    (temporary / "logs/capsule").mkdir()
    probe.require(("lifecycle" in config) == ("lifecycle" in profile) == ("resources" in config),
                  "Lifecycle settings, resource policy and bundled owner must be enabled together")
    if "lifecycle" in config:
        from .capsule_lifecycle import settings as owner_settings
        from .capsule_resources import validate
        owner_config = config["lifecycle"]
        probe.require(owner_config == owner_settings(owner_config["mode"], owner_config["owner_order"]),
                      "Unsupported lifecycle configuration")
        validate(config["resources"])
        binding["lifecycle_attempt"] = uuid.uuid4().hex
        (temporary / "logs/capsule/lifecycle").mkdir()
    probe.write_json(temporary / "config/capsule_binding.json", binding)


def sandbox_fragments(context):
    """Host Python and QEMU share the wrapper's PID namespace, not its chroot."""
    quote = shlex.quote
    mount = quote(str(context.execution_rootfs / IPC_GUEST.lstrip("/")))
    setup = f"""
CAPSULE_IPC=$(mktemp -d /tmp/tfc-unified.XXXXXXXX)
mkdir -m 0700 {mount}
mount --bind "$CAPSULE_IPC" {mount}
"""
    cleanup = f"""umount -l {mount} >/dev/null 2>&1 || true
rmdir {mount} >/dev/null 2>&1 || true
if [[ -n "${{CAPSULE_IPC:-}}" ]]; then
    rm -f -- "$CAPSULE_IPC/control.sock" "$CAPSULE_IPC/events.sock" "$CAPSULE_IPC/export.bin"
    rmdir -- "$CAPSULE_IPC" >/dev/null 2>&1 || true
fi"""
    # The outer timeout remains a last resort. Its firing cannot pass capsule
    # finalization: a complete, independently validated supervisor result is needed.
    execution = f"""timeout --signal=TERM --kill-after=2s "$TIMEOUT_SECONDS" \\
    env -i PATH=/usr/bin:/bin HOME=/ LANG=C LC_ALL=C \\
    PYTHONPATH={quote(str(Path(__file__).resolve().parents[1]))} \\
    {quote(sys.executable)} -m taintforge_env.execution_capsule \\
    --binding {quote(str(context.run_dir / 'config/capsule_binding.json'))} --ipc "$CAPSULE_IPC"
"""
    return setup, cleanup, execution


def live_phase1_evidence(analysis, through_event=None):
    """Check the complete prefix available at the boundary; later export is separate."""
    events = analysis.events(final=False)
    if through_event is not None:
        positions = [index for index, event in enumerate(events) if event["event_id"] == through_event]
        probe.require(len(positions) == 1, "Handoff references an absent Phase 1 event")
        events = events[:positions[0] + 1]
    capabilities = events[0].get("data", {})
    probe.require(capabilities.get("build_id") == analysis.runtime.build_id and
                  capabilities.get("plugin_api") == 6, "Handoff: wrong loaded Phase 1 build/API")
    probe.require(not any(event["event_type"] in {
        "profile_lost", "data_loss", "error", "analysis_finished", "analysis_invalidated"
    } for event in events), "Handoff: Phase 1 stream is failed, incomplete or already finished")
    observed = next((event for event in events if event["event_type"] == "runtime_observation" and
                     event.get("data", {}).get("kind") == "instruction_callback"), None)
    probe.require(observed is not None, "Handoff: Phase 1 instruction callback is missing")
    return {"phase1_started_event": events[0]["event_id"],
            "phase1_instruction_event": observed["event_id"], "phase1_last_event": events[-1]["event_id"]}


class Handoff:
    """Gate CONTINUE on attempt-bound live Phase 1 evidence, without waiting for export."""
    def __init__(self, binding):
        from .phase1_runtime import Phase1Run, Phase1Runtime
        self.binding = binding
        run = Path(binding["run_dir"])
        phase1 = read_json(run / "config/phase1_binding.json")
        probe.require(all(phase1.get(key) == binding[key] for key in IDENTITY), "Phase 1/capsule attempt identity mismatch")
        self.analysis = Phase1Run(Phase1Runtime.load(run / "config/analyzer_runtime" / phase1["plugin"]),
                                 phase1["session_id"], phase1["attempt_id"], phase1["analysis_instance_id"],
                                 Path(phase1["output_directory"]))
        self.sequence = 0

    def __call__(self, action, point, snapshot, record):
        if action == "held":
            state = "handoff_ready" if point == 1 else "continuation_observed"
            evidence = live_phase1_evidence(self.analysis)
        else:
            state = "resume_requested" if action == "resuming" else "guest_completed"
            evidence = {}
        self.sequence += 1
        record({"event": "handoff", "state": state, "handoff_seq": self.sequence,
                **{key: self.binding[key] for key in IDENTITY}, **evidence,
                "point": point, "qemu_pid": snapshot["host_pid"],
                "pid_scope": "sandbox_pid_namespace", "monotonic_ns": time.monotonic_ns(),
                "boundary_source": "controlled_fixture_symbol", **LIMITS})


def verify_evidence(binding, result):
    """Run after QEMU exit, and again during independent attempt finalization."""
    run = Path(binding["run_dir"])
    output = run / "logs/capsule"
    case = binding["settings"]["case"]
    owner_fault = binding["settings"].get("lifecycle", {}).get("mode", "remove") != "remove"
    exit_code = 125 if owner_fault else expected_exit(case)
    probe.require(all(result.get(key) == binding[key] for key in IDENTITY), "Capsule result belongs to another attempt")
    probe.require(not result["supervisor_kill"] and result["qemu_exit"] == exit_code,
                  "QEMU did not finish with the expected capsule exit")
    events = [json.loads(line) for line in (output / "observations.jsonl").read_text().splitlines()]
    owner_result = None
    if "lifecycle" in binding["settings"]:
        from .capsule_lifecycle import verify_saved
        owner_result = verify_saved(binding, result, events)
        probe.require((owner_result["status"] == "rejected") == owner_fault, "Lifecycle rejection does not match the selected scenario")
        if exit_code == 0:
            probe.require(owner_result["status"] == "verified", "Owner retirement was not independently verified")
        lifecycle_events = [event for event in events if event.get("event") in {"lifecycle_observed", "lifecycle_rejected"}]
        for event in lifecycle_events:
            index = events.index(event)
            probe.require(index > 0 and events[index - 1].get("event") == "handoff"
                          and events[index - 1].get("point") == event["point"]
                          and events[index - 1].get("state") in {"handoff_ready", "continuation_observed"},
                          "Lifecycle verdict is outside the held observation point")
        events = [event for event in events if event.get("event") not in {"lifecycle_observed", "lifecycle_rejected"}]
    snapshots = [event for event in events if event.get("event") == "snapshot"]
    last_point = owner_result["points"] if owner_fault else 2 if exit_code == 0 or case.endswith("-2") else 1
    if owner_result is not None:
        probe.require(owner_result["points"] == last_point, "Missing lifecycle check at an observed boundary")
    probe.require(len(snapshots) == last_point * 2, "Missing capsule snapshots")
    for index, event in enumerate(snapshots):
        probe.validate_snapshot(event, index // 2 + 1, index % 2 + 1, binding["capsule"]["symbols"],
                                result["qemu_pid"], snapshots[0])
        if index % 2:
            probe.require(event["regs"] == snapshots[index - 1]["regs"] and
                          event["buffer_hex"] == snapshots[index - 1]["buffer_hex"] and
                          event["monotonic_ms"] >= snapshots[index - 1]["monotonic_ms"] + binding["settings"]["hold_ms"] - 2,
                          "Snapshot changed during hold or hold was too short")
    handoffs = [event for event in events if event.get("event") == "handoff"]
    expected_order = []
    for point in range(1, last_point + 1):
        expected_order += [("snapshot", point, 1), ("snapshot", point, 2), ("hold_verified", point, None),
                           ("handoff", point, "handoff_ready" if point == 1 else "continuation_observed")]
        if point < last_point or exit_code == 0:
            expected_order.append(("handoff", point, "resume_requested"))
    if exit_code == 0:
        expected_order += [("done", None, None), ("handoff", 2, "guest_completed")]
    elif case.startswith("kill-controller"):
        expected_order.append(("controller_kill", last_point, None))
    actual_order = [(event.get("event"), event.get("point"), event.get("state", event.get("sample"))) for event in events]
    probe.require(actual_order == expected_order,
                  "Invalid handoff sequence; continuation must be observed, not inferred from send()")
    analysis = Handoff(binding).analysis
    for index, event in enumerate(handoffs, 1):
        probe.require(event["handoff_seq"] == index and event["qemu_pid"] == result["qemu_pid"] and
                      all(event.get(key) == binding[key] for key in IDENTITY) and
                      all(event.get(key) is False for key in LIMITS), "Handoff identity or scope mismatch")
        if event["state"] in {"handoff_ready", "continuation_observed"}:
            evidence = live_phase1_evidence(analysis, event["phase1_last_event"])
            probe.require(all(event.get(key) == value for key, value in evidence.items()),
                          "Handoff Phase 1 evidence reference mismatch")
    if case.startswith("kill-controller"):
        probe.require(result["controller_exit"] == -signal.SIGKILL and
                      events[-1].get("event") == "controller_kill", "Controller SIGKILL was not exercised")
    else:
        controller = read_json(output / "controller.json")
        if owner_fault:
            probe.require(result["controller_exit"] == 0 and controller.get("status") == "failed"
                          and controller.get("error") == "EvidenceError: " + owner_result["rejection"],
                          "Expected lifecycle refusal was not observed by the controller")
        else:
            probe.require(result["controller_exit"] == 0 and controller.get("status") == "passed",
                          controller.get("error", "Capsule controller failed"))
    fd_path = output / "capsule-fd.txt"
    stdout = (run / "logs/runtime_stdout.log").read_bytes()
    if exit_code == 0:
        probe.require(events[-2].get("event") == "done" and stdout == b"CAPSULE_OK\n" and
                      fd_path.read_bytes() == probe.FILE_BYTES, "Guest stack/PID/FD oracle failed")
    else:
        prefix = b"before\nbetween\n" if last_point == 2 else b"before\n"
        probe.require(fd_path.read_bytes() == prefix and stdout == b"", "Guest continued after capsule abort")
        diagnostic = (run / "logs/qemu_strace.log").read_text(errors="replace")
        probe.require(f"CAPSULE_ABORT code={exit_code} " in diagnostic, "Missing native plugin abort evidence")
    verification = {"status": "passed" if exit_code == 0 else "aborted",
            "fault_exercised": binding["settings"]["lifecycle"]["mode"] if owner_fault else None if exit_code == 0 else case,
            "snapshots": len(snapshots), "handoff_ready": True,
            "continuation_observed": last_point == 2, "guest_completed": exit_code == 0}
    if owner_result is not None:
        verification["lifecycle"] = owner_result
    return verification


def supervise(binding, ipc):
    """Runs inside the sandbox PID namespace; the worker alone owns the socket."""
    from .unified_runtime import verify_bundle
    run = Path(binding["run_dir"])
    output = run / "logs/capsule"
    manifest = verify_bundle(run / "config/analyzer_runtime", binding["bundle_sha256"])
    probe.require(manifest["capsule"] == binding["capsule"], "Capsule bundle/binding mismatch")
    probe.require(probe.sha(Path(binding["rootfs"]) / binding["guest_binary"].lstrip("/")) ==
                  binding["capsule"]["fixture_sha256"], "Controlled ELF changed before launch")
    config = binding["settings"]
    case = config["case"]
    total = 5000 if case == "total-timeout" else config["total_ms"]
    pause = 60000 if case == "total-timeout" else config["pause_ms"]
    result = {"schema_version": 1, "status": "failed", "case": case,
              **{key: binding[key] for key in IDENTITY}, "qemu_exit": None,
              "supervisor_kill": False, "limitations": LIMITS,
              "pid_scope": "sandbox_pid_namespace"}
    worker = process = parent = child = None
    owner_gate = None
    started = time.monotonic()
    try:
        if "resources" in config:
            from .capsule_resources import inspect_self
            result["resource_entry"] = inspect_self(binding)
        handoff = Handoff(binding)
        if "lifecycle" in config:
            from . import capsule_lifecycle
            owner_gate = capsule_lifecycle.gate(binding, ipc)
            handoff = capsule_lifecycle.Transition(handoff, owner_gate)
        ctx = mp.get_context("fork")
        parent, child = ctx.Pipe()
        endpoint = Path(ipc) / "control.sock"
        worker = ctx.Process(target=probe.control_worker,
            args=(str(endpoint), child, str(output), binding["capsule"]["symbols"], case, config["hold_ms"], total),
            kwargs={"fd_path": str(Path(binding["rootfs"]) / "capsule-fd.txt"), "transition": handoff})
        worker.start()
        child.close()
        probe.require(parent.poll(5) and parent.recv() == "ready", "Capsule controller did not become ready")
        symbols = binding["capsule"]["symbols"]
        argument = ",".join(["/__taintforge/" + binding["capsule"]["plugin"],
            "socket=" + IPC_GUEST + "/control.sock", "p1=" + hex(symbols["capsule_point_one"]),
            "p2=" + hex(symbols["capsule_point_two"]), "buffer=" + hex(symbols["capsule_buffer"]),
            f"pause-ms={pause}", f"total-ms={total}", f"controller={worker.pid}"])
        phase1 = read_json(run / "config/phase1_binding.json")
        plugins = [phase1["plugin_argument"], argument]
        if case == "capsule-first":
            plugins.reverse()
        if owner_gate is not None:
            owner_argument = capsule_lifecycle.plugin_argument(binding, IPC_GUEST)
            if config["lifecycle"]["owner_order"] == "before":
                plugins.insert(0, owner_argument)
            else:
                plugins.append(owner_argument)
        command = ["chroot", binding["rootfs"], "/__taintforge/bin/loader", "--inhibit-cache",
                   "--library-path", "/__taintforge/lib", "/__taintforge/bin/qemu-i386", "-L", "/", "-strace"]
        for plugin in plugins:
            command += ["-plugin", plugin]
        command.append(binding["guest_binary"])
        result["command"] = command
        with (run / "logs/qemu_strace.log").open("wb") as trace:
            process = subprocess.Popen(command, cwd=binding["rootfs"], close_fds=True, stderr=trace,
                                       env={"PATH": "/usr/bin:/bin", "HOME": "/", "LANG": "C", "LC_ALL": "C"})
            result.update(qemu_pid=process.pid, controller_pid=worker.pid)
            parent.send(process.pid)
            try:
                result["qemu_exit"] = process.wait(timeout=total / 1000 + 5)
            except subprocess.TimeoutExpired:
                result["supervisor_kill"] = True
                process.kill()
                result["qemu_exit"] = process.wait(timeout=3)
        worker.join(timeout=4)
        probe.require(not worker.is_alive(), "Capsule controller did not terminate")
        result["controller_exit"] = worker.exitcode
        # Capture while the privileged supervisor can still read mode-0600
        # guest output. The ordinary runner later owns the logs, not the rootfs.
        shutil.copyfile(Path(binding["rootfs"]) / "capsule-fd.txt", output / "capsule-fd.txt")
        if owner_gate is not None:
            capsule_lifecycle.capture_export(binding, ipc)
        result.update(verify_evidence(binding, result))
    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"[-6000:]
    finally:
        if process is not None and process.poll() is None:
            result["supervisor_kill"] = True
            process.kill()
            result["qemu_exit"] = process.wait(timeout=3)
        if worker is not None and worker.pid is not None:
            if worker.is_alive():
                worker.kill()
            worker.join(timeout=3)
            result["controller_exit"] = worker.exitcode
        for pipe in (parent, child):
            if pipe is not None:
                pipe.close()
        if owner_gate is not None:
            owner_gate.close()
            try:
                capsule_lifecycle.capture_export(binding, ipc)
            except (OSError, RuntimeError) as exc:
                result.update(status="failed", export_capture_error=str(exc))
        for name in ("events.sock", "export.bin"):
            (Path(ipc) / name).unlink(missing_ok=True)
        (Path(ipc) / "control.sock").unlink(missing_ok=True)
        result["elapsed_seconds"] = round(time.monotonic() - started, 3)
        probe.write_json(output / "supervisor.json", result)
        if (run / "logs/qemu_strace.log").is_file():
            with (run / "logs/qemu_strace.log").open("rb") as trace:
                shutil.copyfileobj(trace, sys.stderr.buffer)
    code = result["qemu_exit"]
    return (128 - code if code < 0 else code) if code is not None else 126


def finish_attempt(context, guest_exit_code):
    """Preserve abort evidence, fail the attempt, and prevent automatic reuse."""
    run = context.run_dir
    binding = read_json(run / "config/capsule_binding.json")
    summary = {"schema_version": 1, "profile": PROFILE, "status": "failed",
               **{key: binding[key] for key in IDENTITY}, "limitations": LIMITS}
    try:
        result = read_json(run / "logs/capsule/supervisor.json")
        summary.update(result)
        probe.require(binding["attempt_id"] == context.attempt_contract.attempt_id and
                      binding["attempt_contract_sha256"] == context.attempt_contract.contract_sha256 and
                      result["qemu_exit"] == guest_exit_code, "Capsule attempt/exit binding mismatch")
        verification = verify_evidence(binding, result)
        if "resources" in binding["settings"]:
            from .capsule_resources import verify_saved
            verification["resources"] = verify_saved(binding, guest_exit_code)
        probe.require(result["status"] == verification["status"], "Capsule supervisor verification failed")
        summary.update(verification)
        summary["evidence_sha256"] = {name: probe.sha(run / "logs/capsule" / name)
                                      for name in ("observations.jsonl", "supervisor.json")}
    except Exception as exc:
        summary.update(status="failed", error=f"{type(exc).__name__}: {exc}"[-6000:])
        raise
    finally:
        probe.write_json(run / "config/capsule_result.json", summary)
    probe.require(summary["status"] == "passed", "Capsule handoff aborted; this attempt cannot be resumed")
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binding", type=Path, required=True)
    parser.add_argument("--ipc", type=Path, required=True)
    args = parser.parse_args()
    try:
        return supervise(read_json(args.binding), args.ipc)
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"Capsule supervisor failed: {exc}", file=sys.stderr)
        return 126


if __name__ == "__main__":
    raise SystemExit(main())
