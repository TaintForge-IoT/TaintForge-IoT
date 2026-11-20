#!/usr/bin/env python3
"""Verify ordered NET-4 repairs with a real benign i386 guest on host loopback."""
from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path
import shutil
import socket
import subprocess

from scripts.run_network_repair_e2e import LoopbackAcceptanceRunner, QemuLoopbackResolver, write
from taintforge_env.iteration_controller import IterationController
from taintforge_env.network_observer import plugin_argument, validate_observer
from taintforge_env.network_policy import CatchAllPolicy, NetworkPolicy, load_network_policy
from taintforge_env.network_replay import replay_service
from taintforge_env.replay_store import ReplayStore
from taintforge_env.synthesis_loop import EnvironmentSynthesisLoop, SynthesisLoopConfig


PROJECT = Path(__file__).resolve().parents[1]


class SessionAcceptanceRunner(LoopbackAcceptanceRunner):
    async def exercise(self, context, mode, port):
        listeners, responders = [], []
        process = None
        try:
            policy = load_network_policy(context.run_dir / "config/network_policy.json")
            for service in policy.services:
                responder = replay_service(service=service, store=ReplayStore(context.run_dir / "config/replay_store"),
                                           log_dir=context.run_dir / "logs")
                responders.append(responder)
                listeners.append(await responder.start())
            logs = context.run_dir / "logs/network_endpoints"
            logs.mkdir()
            argument = plugin_argument(str(self.observer), logs / "events.jsonl",
                                       context.session.session_id, context.attempt_contract.attempt_id)
            process = await asyncio.create_subprocess_exec(str(self.qemu), "-plugin", argument, "-strace",
                str(context.host_binary), str(mode), str(port),
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            stdout, stderr = await asyncio.wait_for(process.communicate(), 5)
            for name, data in (("runtime_stdout.log", stdout), ("runtime_stderr.log", stderr),
                               ("qemu_strace.log", stderr)):
                (context.run_dir / "logs" / name).write_bytes(data)
            async with asyncio.timeout(2):
                while any(responder.tasks for responder in responders):
                    await asyncio.sleep(0.005)
            return process.returncode
        finally:
            if process is not None and process.returncode is None:
                process.kill()
                await process.communicate()
            for listener in listeners:
                listener.close()
            await asyncio.gather(*(listener.wait_closed() for listener in listeners))


def run_case(root, binary, qemu, observer, name, mode, *, reason=None, limits=None, wrong_response=False):
    root.mkdir()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as guard:
        guard.bind(("127.0.0.1", 0))
        port = guard.getsockname()[1]
    resource = f"tcp://127.0.0.1:{port}"
    seed, template = root / "seed", root / "template"
    (seed / "bin").mkdir(parents=True)
    (seed / "proc").mkdir()
    shutil.copy2(binary, seed / "bin/unpacked.elf")
    write(template / "config/runtime.json", {"arch": "i386", "host_binary": str(binary),
        "guest_binary": "/bin/unpacked.elf", "qemu_required": False, "rootfs": str(seed),
        "net3_test_mode": mode, "net3_test_port": port})
    write(template / "config/network_policy.json", NetworkPolicy(
        catch_all=CatchAllPolicy(enabled=False, udp_enabled=False)).to_dict())
    pairs = [(b"HELLO\n", b"READY\n"), (b"AUTH test\n", b"OK\n"),
             (b"GET CONFIG\n", b"interval=99\n" if wrong_response else b"interval=30\n")]
    specification = {"schema_version": 1, "transport": "tcp", "remote_ip": "127.0.0.1", "remote_port": port,
        "protocol_hint": "net4_test", "framing": "exact_bytes", "limits": limits or {},
        "steps": [{"request_hex": request.hex(), "response_hex": response.hex()} for request, response in pairs]}
    store = ReplayStore(root / "store")
    contract = store.add_session(specification)
    store_hash = store.validate()["store_sha256"]
    write(root / "authorization.json", {"schema_version": 1, "network_mode": "replay",
        "replay_store": {"path": str(store.root), "sha256": store_hash},
        "rules": [{"resource": resource, "provider": "replay", "protocol_hint": "net4_test",
                   "replay_session_id": contract.session_id}]})
    write(root / "goal.json", {"schema_version": 1, "goal_id": "net4_validated_dialogue",
        "description": "The benign client verifies every response byte before writing NET4_OK",
        "mode": "all", "rules": [{"id": "validated_dialogue", "type": "text_contains",
                                  "source": "stdout", "needle": "NET4_OK"}]})
    loop = EnvironmentSynthesisLoop(SynthesisLoopConfig(session_dir=root / "session",
        template_run_dir=template, project_root=PROJECT, snapshot_store=root / "snapshots", seed_rootfs=seed,
        target_spec_path=root / "goal.json", network_mode="replay", replay_store_path=store.root,
        network_repair_policy_path=root / "authorization.json", max_iterations=3, max_steps=3),
        runner_factory=lambda config: SessionAcceptanceRunner(config, qemu, observer))
    loop.execution_resolver = QemuLoopbackResolver(qemu)
    loop.run()
    session = IterationController(root / "session").verify()
    if len(session.iterations) != 2:
        raise RuntimeError(f"{name}: expected real failure then exactly one authorized retry")
    first, second = session.iterations
    if (first.environment_snapshot_id != second.environment_snapshot_id
            or first.environment_manifest_id == second.environment_manifest_id or first.attempt_id == second.attempt_id):
        raise RuntimeError(f"{name}: network-only repair lost its manifest/attempt transition")
    initial = json.loads((root / "session/iterations/0000/artifacts/repair_plan.json").read_text())
    if initial["summary"]["automatic_candidates"] != 1:
        raise RuntimeError(f"{name}: real initial failure did not select exactly one session repair")
    initial_trace = (root / "session/iterations/0000/run/logs/qemu_strace.log").read_text()
    initial_events = [json.loads(line) for line in
        (root / "session/iterations/0000/run/logs/syscall_events.jsonl").read_text().splitlines()]
    if not any(event.get("syscall") == "connect" and event.get("errno") == "ECONNREFUSED"
               and event.get("remote_ip") == "127.0.0.1" and event.get("remote_port") == port
               and event.get("endpoint_observer_status") == "correlated"
               and event.get("raw") in initial_trace for event in initial_events):
        raise RuntimeError(f"{name}: initial failure is not present in the real QEMU trace")
    run = root / "session/iterations/0001/run"
    events = [json.loads(line) for line in (run / "logs/network_events.jsonl").read_text().splitlines()]
    transcript = [event for event in events if event["event"] in {"replay_hit", "session_complete", "session_abort"}]
    if any(event.get("replay_session_id") != contract.session_id for event in events):
        raise RuntimeError(f"{name}: responder events are not bound to the selected session")
    expected_goal = reason is None and not wrong_response
    stdout = (run / "logs/runtime_stdout.log").read_bytes()
    if expected_goal:
        expected_connections = 2 if mode in {9, 10} else 1
        complete = [event for event in events if event["event"] == "session_complete"]
        if (session.stop_reason != "goal_reached" or stdout != b"NET4_OK\n"
                or len(complete) != expected_connections or any(event["event"] == "session_abort" for event in events)):
            raise RuntimeError(f"{name}: ordered dialogue did not reach its verified client goal")
        for connection in complete:
            steps = [event["step_index"] for event in events
                     if event["event"] == "replay_hit" and event["connection_id"] == connection["connection_id"]]
            if steps != [0, 1, 2]:
                raise RuntimeError(f"{name}: connection reused or skipped session state")
    else:
        if session.stop_reason != "no_automatic_repairs" or stdout:
            raise RuntimeError(f"{name}: negative scenario fabricated a goal or repeated repair")
        if reason and not any(event.get("reason") == reason for event in events):
            raise RuntimeError(f"{name}: missing real termination reason {reason}")
        if wrong_response and not any(event["event"] == "session_complete" for event in events):
            raise RuntimeError("wrong response case must distinguish completed wire dialogue from the client goal")
    report = json.loads((run / "report.json").read_text())
    if (len(report["network"]["authorized_repair_services"]) != 1
            or report["network"]["session_replay"]["configured"][0]["replay_session_id"] != contract.session_id
            or report["network"]["semantic_satisfaction"] != "unknown"
            or not report["network"]["session_replay"]["transcript"]):
        raise RuntimeError(f"{name}: report lost session provenance or confused wire completion with the application goal")
    if store.validate()["store_sha256"] != store_hash:
        raise RuntimeError(f"{name}: replay mutated its input store")
    EnvironmentSynthesisLoop.verify_session(root / "session")
    return {"case": name, "status": "passed", "attempts": 2, "resource": resource,
            "replay_session_id": contract.session_id, "explicit_goal_reached": expected_goal,
            "wire_sessions_completed": sum(event["event"] == "session_complete" for event in events),
            "same_rootfs_snapshot": True, "new_manifest_and_attempt": True,
            "initial_failure_from_real_qemu_strace": True, "net2_observer_correlated": True,
            "automatic_retry_stopped": not expected_goal, "termination_reason": reason,
            "transcript_events": len(transcript), "store_unchanged": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--qemu", type=Path, required=True)
    parser.add_argument("--observer", type=Path, required=True)
    args = parser.parse_args()
    root = args.out.resolve(strict=False)
    try:
        root.mkdir(parents=True, exist_ok=False)
        qemu, observer = args.qemu.resolve(strict=True), args.observer.resolve(strict=True)
        metadata = validate_observer(observer)
        binary, obj = root / "benign-session-client", root / "client.o"
        subprocess.run(["as", "--32", str(PROJECT / "samples/network_session_i386.S"), "-o", str(obj)],
                       check=True, capture_output=True)
        subprocess.run(["ld", "-m", "elf_i386", str(obj), "-o", str(binary)], check=True, capture_output=True)
        definitions = [("ordered", 0, {}), ("fragmented", 1, {}), ("coalesced", 2, {}),
            ("reconnect", 9, {}), ("interleaved_connections", 10, {}),
            ("wrong_order", 3, {"reason": "unexpected_request_at_step"}),
            ("unknown_step", 4, {"reason": "unexpected_request_at_step"}),
            ("premature_eof", 5, {"reason": "connection_closed_before_complete_session"}),
            ("idle_timeout", 6, {"reason": "idle_timeout", "limits": {"idle_timeout_ms": 100}}),
            ("session_timeout", 6, {"reason": "session_timeout", "limits": {
                "idle_timeout_ms": 1000, "session_timeout_ms": 100}}),
            ("wrong_response", 0, {"wrong_response": True}),
            ("trailing_bytes", 7, {"reason": "trailing_bytes_after_final_request"}),
            ("receive_budget", 8, {"reason": "receive_byte_limit", "limits": {"max_received_bytes": 27}})]
        cases = [run_case(root / name, binary, qemu, observer, name, mode, **options)
                 for name, mode, options in definitions]
        report = {"status": "passed", "cases": cases, "guest_executions": sum(case["attempts"] for case in cases),
            "qemu": subprocess.run([str(qemu), "--version"], check=True, capture_output=True, text=True).stdout.splitlines()[0],
            "plugin_api": metadata["plugin_api"], "benign_client_executed": True,
            "execution_adapter": "qemu_host_loopback", "phase1_executed": False,
            "namespace_executed": False, "capsule_executed": False, "only_loopback_destinations": True}
        write(root / "report.json", report)
        print(json.dumps(report, indent=2))
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError, TimeoutError) as exc:
        parser.exit(1, f"NET-4 acceptance failed: {exc}\n")


if __name__ == "__main__":
    main()
