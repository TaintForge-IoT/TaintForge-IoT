#!/usr/bin/env python3
"""Exercise real benign i386 TCP/UDP/DNS repairs under QEMU on host loopback."""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
from pathlib import Path
import shutil
import socket
import subprocess

from taintforge_env.dns_emulator import DNSStaticService
from taintforge_env.iteration_controller import IterationController
from taintforge_env.elf_target import inspect_elf_target
from taintforge_env.execution_backend import ExecutionBackendResolver, ExecutionBackendKind, ExecutionPlan, TraceBackend
from taintforge_env.network_observer import plugin_argument, validate_observer
from taintforge_env.network_policy import NetworkPolicy, CatchAllPolicy, load_network_policy
from taintforge_env.network_replay import replay_service
from taintforge_env.observations import load_observation_bundle
from taintforge_env.prebuilt_runner import PrebuiltRootfsRunner, PrebuiltRunnerResult
from taintforge_env.replay_store import ReplayStore
from taintforge_env.requirement_extractor import RequirementExtractor
from taintforge_env.qemu_strace_parser import parse_qemu_strace
from taintforge_env.synthesis_loop import EnvironmentSynthesisLoop, SynthesisLoopConfig


PROJECT = Path(__file__).resolve().parents[1]


def write(path: Path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n")


class QemuLoopbackResolver(ExecutionBackendResolver):
    """The acceptance adapter executes QEMU on the host and never injects it into a chroot."""
    def __init__(self, qemu):
        super().__init__()
        self.qemu = qemu

    def resolve(self, *, runtime, host_binary, rootfs, guest_binary):
        target = inspect_elf_target(host_binary)
        if target.arch != "i386" or target.interpreter is not None:
            raise ValueError("NET-3 acceptance requires its static benign i386 fixture")
        if (rootfs / guest_binary.lstrip("/")).read_bytes() != host_binary.read_bytes():
            raise ValueError("acceptance rootfs binary differs from the bound input")
        return ExecutionPlan(backend=ExecutionBackendKind.QEMU_USER, trace_backend=TraceBackend.QEMU_STRACE,
            host_arch=self.host_arch, target=target, guest_binary=guest_binary, guest_interpreter=None,
            qemu_binary_name="qemu-i386", qemu_host_path=str(self.qemu),
            qemu_host_sha256=hashlib.sha256(self.qemu.read_bytes()).hexdigest(),
            qemu_guest_path="/__taintforge/qemu-user-static")


class LoopbackAcceptanceRunner(PrebuiltRootfsRunner):
    """Use production preparation/planning/controller with an explicit QEMU host-loopback adapter."""
    def __init__(self, config, qemu, observer):
        super().__init__(config)
        self.qemu, self.observer = qemu, observer
        self.execution_resolver = QemuLoopbackResolver(qemu)

    def run_and_complete(self):
        context = self.validate()
        self._prepare_run_directory(context)
        mode = json.loads(context.template_runtime_path.read_text())["net3_test_mode"]
        port = json.loads(context.template_runtime_path.read_text())["net3_test_port"]
        result = asyncio.run(self.exercise(context, mode, port))
        self.guest_execution_observed = True
        summary = parse_qemu_strace(context.run_dir / "logs/qemu_strace.log",
            context.run_dir / "logs/syscall_events.jsonl", target_arch="i386",
            endpoint_events=context.run_dir / "logs/network_endpoints/events.jsonl",
            session_id=context.session.session_id, attempt_id=context.attempt_contract.attempt_id)
        if summary["network_endpoint_observer"]["status"] != "correlated":
            raise RuntimeError("real NET-2 observer evidence did not correlate")
        RequirementExtractor().extract(load_observation_bundle(context.run_dir)).save(
            context.run_dir / "config/runtime_requirements.json")
        self._plan_repairs(context)
        evaluation = self._evaluate_target_state(context)
        goal, reason = self._resolve_goal(evaluation)
        self._generate_report(context)
        completed = self.controller.complete_iteration(iteration_index=context.iteration.index,
            artifacts_dir=context.run_dir, guest_exit_code=result, goal_reached=goal, goal_reason=reason)
        return PrebuiltRunnerResult(iteration_index=context.iteration.index, run_dir=context.run_dir,
            guest_exit_code=result, timed_out=False, stop_reason=completed.stop_reason,
            progress=completed.progress or {}, claim_path=context.claim_path,
            attempt_id=completed.attempt_id, attempt_result_path=self.config.session_dir / completed.attempt_result,
            target_reached=goal, network_mode=self.config.network_mode)

    async def exercise(self, context, mode, port):
        policy = load_network_policy(context.run_dir / "config/network_policy.json")
        servers = []
        try:
            for service in policy.services:
                responder = (DNSStaticService(service, context.run_dir / "logs") if mode == "dns" else
                    replay_service(service=service, store=ReplayStore(context.run_dir / "config/replay_store"),
                                   log_dir=context.run_dir / "logs"))
                servers.append(await responder.start())
            (context.run_dir / "logs/network_endpoints").mkdir()
            argument = plugin_argument(str(self.observer), context.run_dir / "logs/network_endpoints/events.jsonl",
                context.session.session_id, context.attempt_contract.attempt_id)
            process = await asyncio.create_subprocess_exec(str(self.qemu), "-plugin", argument, "-strace",
                str(context.host_binary), mode, str(port),
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=5)
            (context.run_dir / "logs/runtime_stdout.log").write_bytes(stdout)
            (context.run_dir / "logs/runtime_stderr.log").write_bytes(stderr)
            (context.run_dir / "logs/qemu_strace.log").write_bytes(stderr)
            return process.returncode
        finally:
            for server in servers:
                server.close()
            await asyncio.gather(*(server.wait_closed() for server in servers))


def run_case(root: Path, binary: Path, mode: str, qemu: Path, observer: Path, fault: str | None = None):
    root.mkdir()
    kind = socket.SOCK_STREAM if mode == "tcp" else socket.SOCK_DGRAM
    with socket.socket(socket.AF_INET, kind) as guard:
        guard.bind(("127.0.0.1", 0))
        port = guard.getsockname()[1]
    resource = f"{'tcp' if mode == 'tcp' else 'udp'}://127.0.0.1:{port}"
    seed = root / "seed"
    (seed / "bin").mkdir(parents=True)
    (seed / "proc").mkdir()
    shutil.copy2(binary, seed / "bin/unpacked.elf")
    template = root / "template"
    write(template / "config/runtime.json", {"arch": "i386", "host_binary": str(binary),
        "guest_binary": "/bin/unpacked.elf", "qemu_required": False, "rootfs": str(seed),
        "net3_test_mode": mode, "net3_test_port": port})
    write(template / "config/network_policy.json", NetworkPolicy(
        catch_all=CatchAllPolicy(enabled=False, udp_enabled=False)).to_dict())
    authorization = {"schema_version": 1, "network_mode": "controlled" if mode == "dns" else "replay",
        "rules": [{"resource": resource, "provider": "dns_records" if mode == "dns" else "replay"}]}
    store = None
    if mode == "dns":
        authorization["rules"][0]["dns_records"] = {"net3.example": ["192.0.2.7"]}
    else:
        store = ReplayStore(root / "store")
        store.add(transport=mode, remote_ip="127.0.0.2" if fault == "missing_exchange" else "127.0.0.1", remote_port=port,
            request_bytes=b"OTHER\n" if fault == "unknown_request" else b"HELLO\n" if mode == "tcp" else b"ping",
            response_bytes=b"WRONG" if fault == "wrong_response" else b"OK\n" if mode == "tcp" else b"pong")
        authorization["replay_store"] = {"path": str(store.root), "sha256": store.validate()["store_sha256"]}
    if fault == "unlisted_endpoint":
        authorization["rules"][0]["resource"] = f"tcp://127.0.0.2:{port}"
    elif fault == "wrong_transport":
        authorization["rules"][0]["resource"] = f"udp://127.0.0.1:{port}"
    write(root / "authorization.json", authorization)
    write(root / "goal.json", {"schema_version": 1, "goal_id": "net3_expected_reply", "description":
        "Benign client checks the exact response and writes its success marker", "mode": "all",
        "rules": [{"id": "validated_reply", "type": "text_contains", "source": "stdout", "needle": "NET3_OK"}]})
    loop = EnvironmentSynthesisLoop(SynthesisLoopConfig(session_dir=root / "session",
        template_run_dir=template, project_root=PROJECT, snapshot_store=root / "snapshots", seed_rootfs=seed,
        target_spec_path=root / "goal.json", network_mode=authorization["network_mode"],
        replay_store_path=store.root if store else None, network_repair_policy_path=root / "authorization.json",
        max_iterations=3, max_steps=3), runner_factory=lambda config: LoopbackAcceptanceRunner(config, qemu, observer))
    loop.execution_resolver = QemuLoopbackResolver(qemu)
    result = loop.run()
    session = IterationController(root / "session").verify()
    if fault is not None:
        expected_attempts = 2 if fault in {"wrong_response", "unknown_request"} else 1
        if (len(session.iterations) != expected_attempts or session.stop_reason == "goal_reached"
                or session.stop_reason != "no_automatic_repairs"):
            raise RuntimeError(f"fault {fault} did not stop without a fabricated application goal")
        tail = root / f"session/iterations/{expected_attempts - 1:04d}/run"
        if (tail / "logs/runtime_stdout.log").read_bytes():
            raise RuntimeError("refused or wrong response unexpectedly reached the client success marker")
        if fault == "unknown_request":
            events = [json.loads(line) for line in (tail / "logs/network_events.jsonl").read_text().splitlines()]
            if not any(item.get("event") == "replay_miss" for item in events):
                raise RuntimeError("unknown request did not produce a real replay miss")
        EnvironmentSynthesisLoop.verify_session(root / "session")
        return {"status": "passed", "fault": fault, "attempts": expected_attempts,
            "automatic_retry_stopped": True, "explicit_goal_reached": False}
    if len(session.iterations) != 2 or session.stop_reason != "goal_reached":
        raise RuntimeError(f"expected two attempts ending at the explicit goal: {result.to_dict()}")
    first, second = session.iterations
    if (first.environment_snapshot_id != second.environment_snapshot_id
            or first.environment_manifest_id == second.environment_manifest_id or first.attempt_id == second.attempt_id):
        raise RuntimeError("network-only repair did not preserve the rootfs and create a fresh bound attempt")
    initial_plan = json.loads((root / "session/iterations/0000/artifacts/repair_plan.json").read_text())
    if initial_plan["summary"]["automatic_candidates"] != 1:
        raise RuntimeError("initial real syscall failure did not select exactly one authorized service")
    first_stdout = (root / "session/iterations/0000/run/logs/runtime_stdout.log").read_bytes()
    final_stdout = (root / "session/iterations/0001/run/logs/runtime_stdout.log").read_bytes()
    if first_stdout or final_stdout != b"NET3_OK\n":
        raise RuntimeError("unexpected client outputs")
    final_report = json.loads((root / "session/iterations/0001/run/report.json").read_text())
    if (not final_report["network"]["repair_policy_sha256"]
            or len(final_report["network"]["authorized_repair_services"]) != 1
            or final_report["network"]["semantic_satisfaction"] != "unknown"):
        raise RuntimeError("repair provenance or transport/application separation disappeared from the report")
    EnvironmentSynthesisLoop.verify_session(root / "session")
    return {"status": "passed", "transport_case": mode, "attempts": 2, "resource": resource,
        "same_rootfs_snapshot": True, "new_manifest_and_attempt": True, "explicit_goal_reached": True,
        "initial_failure_from_real_qemu_strace": True, "net2_observer_correlated": True,
        "progress": second.progress}


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
        binary = root / "benign-client"
        obj = root / "client.o"
        subprocess.run(["as", "--32", str(PROJECT / "samples/network_repair_i386.S"), "-o", str(obj)],
                       check=True, capture_output=True)
        subprocess.run(["ld", "-m", "elf_i386", str(obj), "-o", str(binary)], check=True, capture_output=True)
        cases = [run_case(root / name, binary, name, qemu, observer) for name in ("tcp", "udp", "dns")]
        cases.extend(run_case(root / fault, binary, "tcp", qemu, observer, fault) for fault in
            ("unlisted_endpoint", "wrong_transport", "missing_exchange", "wrong_response", "unknown_request"))
        report = {"status": "passed", "cases": cases, "benign_client_executed": True,
            "qemu": subprocess.run([str(qemu), "--version"], capture_output=True, text=True, check=True).stdout.splitlines()[0],
            "plugin_api": metadata["plugin_api"], "execution_adapter": "qemu_host_loopback", "phase1_executed": False,
            "namespace_executed": False, "capsule_executed": False, "only_loopback_destinations": True}
        write(root / "report.json", report)
        print(json.dumps(report, indent=2))
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        parser.exit(1, f"NET-3 acceptance failed: {exc}\n")


if __name__ == "__main__":
    main()
