#!/usr/bin/env python3
"""NET-6 host acceptance: actual Phase 1, retirement, capsule, network and cleanup."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import socket
import struct
import subprocess
import sys
import threading
import time

from scripts.run_unified_pipeline import parser as unified_parser, prepare, run_session
from taintforge_env.capsule_resources import preflight
from taintforge_env.dns_protocol import build_query, canonical_exchange, question
from taintforge_env.network_capsule import verify_runtime, require
from taintforge_env.network_observer import validate_observer
from taintforge_env.network_namespace import namespace_exists
from taintforge_env.network_policy import NetworkPolicy, NetworkServicePolicy, CatchAllPolicy
from taintforge_env.prebuilt_runner import PrebuiltRootfsRunner
from taintforge_env.replay_store import ReplayStore
from taintforge_env.synthesis_loop import EnvironmentSynthesisLoop
from taintforge_env.unified_runtime import check_runtime_inputs, write_json


PROJECT = Path(__file__).resolve().parents[1]
CASES = ("tcp", "udp", "dns_udp", "dns_tcp", "receive_budget", "responder_crash", "timeout", "repair")
REPAIR_FAILURE_GRACE_MS = 5000
SUCCESS_OBSERVATION_GRACE_MS = 5000
FAULT_SIGNAL_TIMEOUT_SECONDS = 2.0


def read(path):
    return json.loads(path.read_text())


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build_guest(directory, *, port, transport=0, stall=False, remote="127.0.0.1", work=20000000,
                failure_grace_ms=0, success_grace_ms=0):
    require(type(failure_grace_ms) is int and 0 <= failure_grace_ms <= 10000 and failure_grace_ms % 10 == 0,
            "fixture failure grace must be 0..10000 ms in 10 ms steps")
    require(type(success_grace_ms) is int and 0 <= success_grace_ms <= 10000 and success_grace_ms % 10 == 0,
            "fixture success grace must be 0..10000 ms in 10 ms steps")
    directory.mkdir(parents=True, exist_ok=False)
    source = PROJECT / "samples/network_capsule_i386.S"
    obj, binary = directory / "client.o", directory / "client.elf"
    definitions = {"NET6_PORT": port, "NET6_TRANSPORT": transport, "NET6_STALL": int(stall), "NET6_WORK": work}
    definitions["NET6_FAILURE_GRACE_MS"] = failure_grace_ms
    definitions["NET6_SUCCESS_GRACE_MS"] = success_grace_ms
    definitions.update({"NET6_IP" + str(index): int(part) for index, part in enumerate(remote.split("."))})
    command = ["as", "--32"]
    for name, value in definitions.items():
        command += ["--defsym", f"{name}={value}"]
    command += [str(source), "-o", str(obj)]
    subprocess.run(command, check=True, capture_output=True)
    subprocess.run(["ld", "-m", "elf_i386", str(obj), "-o", str(binary)], check=True, capture_output=True)
    write_json(directory / "build.json", {"source_sha256": sha(source), "binary_sha256": sha(binary),
        "definitions": definitions, "assembler_command": command})
    return binary


def policy_and_store(root, name, *, port, remote):
    transport = "udp" if name in {"udp", "dns_udp"} else "tcp"
    hint = "dns" if name.startswith("dns_") else "net4_test" if transport == "tcp" else None
    store = ReplayStore(root / "store")
    session_id = None
    if hint == "net4_test":
        specification = read(PROJECT / "examples/network_session_tcp.json")
        specification.update(remote_ip=remote, remote_port=port)
        session_id = store.add_session(specification).session_id
    else:
        request, response = b"ping", b"pong"
        if hint == "dns":
            request = build_query("net6.invalid", transaction_id=0x1234)
            response = request[:2] + struct.pack("!5H", 0x8180, 1, 1, 0, 0) + request[12:question(request).end]
            response += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton("192.0.2.7")
            request, response = canonical_exchange(request, response)
        store.add(transport=transport, remote_ip=remote, remote_port=port, protocol_hint=hint,
                  request_bytes=request, response_bytes=response)
    service = NetworkServicePolicy(transport, "net6_benign", remote, port, None, "127.0.0.1", port,
        protocol_hint=hint, replay_session_id=session_id)
    policy = NetworkPolicy(mode="replay", services=[] if name == "repair" else [service],
        catch_all=CatchAllPolicy(enabled=False, udp_enabled=False),
        runtime_limits={"max_received_bytes": 12} if name == "receive_budget" else None)
    write_json(root / "policy.json", policy.to_dict())
    if name == "repair":
        write_json(root / "authorization.json", {"schema_version": 1, "network_mode": "replay",
            "replay_store": {"path": str(store.root), "sha256": store.validate()["store_sha256"]},
            "rules": [{"resource": f"tcp://{remote}:{port}", "provider": "replay",
                       "protocol_hint": hint, "replay_session_id": session_id}]})
    return store


class FaultRunner(PrebuiltRootfsRunner):
    def _fault_probe(self, context, *, timeout):
        # The live service owns mode-0600 evidence. Read it with the same sudo
        # authorization, without changing permissions or the runtime protocol.
        command = ["sudo", "-n", "timeout", "--kill-after=1s", "4s", "env",
            "PYTHONPATH=" + str(PROJECT), sys.executable,
            str(PROJECT / "scripts/check_network_capsule_fault_gate.py"),
            "--run", str(context.run_dir), "--attempt-id", context.attempt_contract.attempt_id,
            "--contract-sha256", context.attempt_contract.contract_sha256]
        result = subprocess.run(command, stdin=subprocess.DEVNULL, capture_output=True,
                                text=True, timeout=timeout)
        require(result.returncode == 0, "responder fault gate failed: " + (result.stdout + result.stderr)[-2000:])
        value = json.loads(result.stdout)
        require(isinstance(value, dict) and value.get("status") in {"pending", "ready"}
                and value.get("attempt_id") == context.attempt_contract.attempt_id
                and value.get("attempt_contract_sha256") == context.attempt_contract.contract_sha256,
                "responder fault gate returned an invalid attempt/result")
        return value

    def _execute_guest(self, context, *, network_backend=None):
        stop = threading.Event()
        injection_lock = threading.Lock()
        outcome = []
        def inject():
            deadline = time.monotonic() + 45
            gate = {"status": "pending", "reason": "waiting_for_network_exchange"}
            try:
                while not stop.wait(.05):
                    # Reserve the six-second outer bound for the privileged
                    # probe (its own TERM/KILL bound is five seconds).
                    require(time.monotonic() + 6 < deadline,
                            "responder fault did not reach verified post-unmap resume: " + str(gate))
                    usage = network_backend.runtime.snapshot()["budget_usage"]
                    if usage["received_bytes"] < 6 or usage["sent_bytes_reserved"] < 6:
                        continue
                    gate = self._fault_probe(context, timeout=6)
                    if gate["status"] != "ready":
                        continue
                    with injection_lock:
                        if stop.is_set():
                            break
                        selected = [p for p in network_backend.processes
                            if any(str(value).endswith("network_policy_loopback.json") for value in p.command)]
                        require(len(selected) == 1, "cannot identify the exact owned namespace responder")
                        process = selected[0]
                        require(process.poll() is None, "owned responder exited before fault injection")
                        signal_timeout = min(FAULT_SIGNAL_TIMEOUT_SECONDS, deadline - time.monotonic())
                        require(signal_timeout > 0, "responder fault signal deadline expired")
                        process.kill(timeout=signal_timeout)
                        value = {"status": "injected", "attempt_id": context.attempt_contract.attempt_id,
                                 "signal": "SIGKILL", "owned_process_pid": process.process.pid,
                                 "procfs_pid": process.proc_pid, "namespace": network_backend.plan.namespace_name,
                                 "gate": gate, "injected_monotonic_ns": time.monotonic_ns()}
                        write_json(context.run_dir / "logs/net6_fault.json", value)
                        outcome.append(value)
                        return
                outcome.append({"status": "cancelled", "attempt_id": context.attempt_contract.attempt_id,
                                "gate": gate, "error": "guest execution ended before responder fault injection"})
            except Exception as exc:
                outcome.append({"status": "failed", "attempt_id": context.attempt_contract.attempt_id,
                                "gate": gate, "error": f"{type(exc).__name__}: {exc}"[:2000]})
            write_json(context.run_dir / "logs/net6_fault.json", outcome[-1])
        worker = threading.Thread(target=inject, name="net6-owned-responder-fault", daemon=True)
        worker.start()
        completed = False
        try:
            result = super()._execute_guest(context, network_backend=network_backend)
            completed = True
            return result
        finally:
            with injection_lock:
                stop.set()
            worker.join(7)
            if completed:
                require(not worker.is_alive() and len(outcome) == 1 and outcome[0]["status"] == "injected",
                        "real responder failure injection was not completed: " + str(outcome))


def validate_attempt(run, *, expected_reason=None, goal=True):
    capsule_binding = read(run / "config/capsule_binding.json")
    network_contract = verify_runtime(capsule_binding)
    try:
        capsule = read(run / "config/capsule_result.json")
    except FileNotFoundError as exc:
        try:
            claim = read(run.parent / "execution_attempt.json")
        except (OSError, ValueError):
            claim = {}
        detail = claim.get("error") if isinstance(claim, dict) else None
        require(False, "capsule_result.json was not produced; original attempt failure: "
                + str(detail or exc)[-4000:])
    phase1 = read(run / "config/phase1_result.json")
    network = read(run / "logs/network_runtime_status.json")
    backend = read(run / "config/network_backend_manifest.json")
    service = read(run / "logs/capsule/service.json")
    finalization = read(run / "config/finalization_status.json")
    integration = read(run / 'config/network_capsule_result.json')
    failed = [key for key, valid in {
        'status': integration['status'] == ('passed' if expected_reason is None else 'interrupted'),
        'phase1_runtime_verified': integration['phase1_runtime_verified'] is True,
        'phase1_retired': integration['phase1_retired'] is True,
    }.items() if not valid]
    require(not failed, 'joint capsule/network receipt did not preserve the verified component outcomes: '
            + ', '.join(failed) + '; retirement: ' + str(capsule.get('retirement_before_stop', {}))[:2000])
    endpoint = read(run / 'logs/syscall_events.summary.json')['network_endpoint_observer']
    require(endpoint['status'] in ({'correlated'} if expected_reason is None else {'correlated','incomplete'}),
            'endpoint observer result is invalid for this native scenario')
    require(network["attempt_id"] == capsule_binding["attempt_id"]
            and network["termination_reason"] == expected_reason and network["cleanup_status"] == "cleaned",
            "network termination or cleanup differs from the expected attempt")
    require(backend["state"] == "cleaned" and service["tree_empty"] is True,
            "network topology or capsule process tree did not clean up")
    require(not network["budget_usage"]["active_jobs"] and not network["ready_listeners"],
            "network runtime retained jobs or listeners")
    require(phase1["artifact_integrity"] == "verified" and phase1["runtime_observed"],
            "actual Phase 1 execution was not verified")
    observed_goal = read(run / "config/target_state_evaluation.json")["reached"]
    require(observed_goal is goal, "application goal differs from the expected response validation")
    if expected_reason is None:
        require(capsule["status"] == "passed" and capsule["phase1_retirement"]["phase1_retired"],
                "successful attempt lacks verified Phase 1 retirement and continuation")
        require(finalization["status"] == "completed", "successful attempt did not finalize")
    else:
        require(capsule.get("network_termination", {}).get("reason") == expected_reason
                and capsule.get("retirement_before_stop", {}).get("status") == "verified",
                "network failure lost its verified post-unmap prefix")
        require(finalization["status"] == "failed", "network failure was treated as successful finalization")
        require(not (run / "config/repair_plan.json").exists(), "network failure produced an automatic repair")
        claim = read(run.parent / "execution_attempt.json")
        require(claim["stage"] == "failed" and claim["retry_safe"] is False, "network failure can be retried automatically")
    namespace = network_contract["namespace"]["name"]
    require(not namespace_exists(namespace), "owned namespace survived cleanup")
    veth = backend["plan"]["veth_host"]
    require(subprocess.run(["ip", "link", "show", veth], capture_output=True).returncode != 0,
            "owned veth survived cleanup")
    return {"attempt_id": capsule_binding["attempt_id"], "analysis_instance_id": capsule_binding["analysis_instance_id"],
        "lifecycle_attempt": capsule_binding["lifecycle_attempt"], "input_sha256": capsule_binding["input_retirement"]["sha256"],
        "phase1_executed": True, "capsule_executed": True, "namespace_executed": True,
        "phase1_retired": True, "goal_reached": goal, "termination_reason": expected_reason,
        "network_cleanup": "cleaned", "capsule_tree_empty": True, "namespace_removed": True, "veth_removed": True,
        "observer": endpoint}


def run_case(root, name, qemu, plugin, observer, *, runner_factory=None):
    root.mkdir()
    remote = "192.0.2.10" if name == "udp" else "127.0.0.1"
    transport = {"udp": 1, "dns_udp": 2, "dns_tcp": 3}.get(name, 0)
    if name.startswith("dns_"):
        port = 53
    else:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM if transport == 1 else socket.SOCK_STREAM) as sock:
            sock.bind(("127.0.0.1", 0)); port = sock.getsockname()[1]
    binary = build_guest(root / "input", port=port, transport=transport, remote=remote,
                         stall=name in {"responder_crash", "timeout"},
                         failure_grace_ms=REPAIR_FAILURE_GRACE_MS if name == "repair" else 0,
                         success_grace_ms=SUCCESS_OBSERVATION_GRACE_MS)
    store = policy_and_store(root, name, port=port, remote=remote)
    original_store = store.validate()["store_sha256"]
    write_json(root / "goal.json", {"schema_version": 1, "goal_id": "net6_validated_reply",
        "description": "Benign guest compares every reply byte after its unpacking loop", "mode": "all",
        "rules": [{"id": "validated_reply", "type": "text_contains", "source": "stdout", "needle": "NET6_OK\n"}]})
    pipeline = root / "pipeline"
    arguments = ["run", "--retire-phase1", "--analysis-policy", "research", "--capsule-hardening",
        "--binary", str(binary), "--qemu", str(qemu), "--plugin", str(plugin), "--network-observer", str(observer),
        "--network", "replay", "--network-policy", str(root / "policy.json"), "--replay-store", str(store.root),
        "--out", str(pipeline), "--target-spec", str(root / "goal.json"), "--max-iterations", "2",
        "--max-steps", "2" if name == "repair" else "1"]
    if name == "repair":
        arguments += ["--network-repair-policy", str(root / "authorization.json")]
    if name == "timeout":
        arguments += ["--capsule-total-ms", "10000", "--timeout", "30"]
    launch = prepare(unified_parser().parse_args(arguments))
    report, code = run_session(pipeline, launch, max_steps=2 if name == "repair" else 1,
        runner_factory=runner_factory if runner_factory is not None else FaultRunner if name == "responder_crash" else None)
    reasons = {"receive_budget": "network_receive_budget_exceeded", "responder_crash": "network_responder_exited",
               "timeout": "network_capsule_timeout"}
    reason = reasons.get(name)
    require(code == (1 if reason else 0), "unified outcome differs: " + str(report.get("error")))
    runs = sorted((pipeline / "session/iterations").glob("*/run"))
    require(len(runs) == (2 if name == "repair" else 1), "unexpected number of fresh native attempts")
    attempts = [validate_attempt(run, expected_reason=reason, goal=reason is None and not (name == "repair" and index == 0))
                for index, run in enumerate(runs)]
    if name == "responder_crash":
        fault = read(runs[0] / "logs/net6_fault.json")
        gate = fault.get("gate", {})
        require(fault.get("status") == "injected" and fault.get("signal") == "SIGKILL"
                and fault.get("attempt_id") == gate.get("attempt_id") == attempts[0]["attempt_id"]
                and gate.get("status") == "ready" and gate.get("retirement", {}).get("phase1_retired") is True
                and type(gate.get("observed_monotonic_ns")) is int
                and type(fault.get("injected_monotonic_ns")) is int
                and fault["injected_monotonic_ns"] >= gate["observed_monotonic_ns"],
                "responder fault lacks its pre-injection retirement verification")
    if name == "repair":
        require(attempts[0]["input_sha256"] == attempts[1]["input_sha256"], "network repair replaced the original ELF")
        for key in ("attempt_id", "analysis_instance_id", "lifecycle_attempt"):
            require(attempts[0][key] != attempts[1][key], "network repair reused " + key)
    if reason is None:
        EnvironmentSynthesisLoop.verify_session(pipeline / "session")
    else:
        before = sha(runs[0].parent / "execution_attempt.json")
        resumed, resume_code = run_session(pipeline, launch, max_steps=1)
        require(resume_code == 1 and resumed["executions_this_invocation"] == 0
                and before == sha(runs[0].parent / "execution_attempt.json"), "resume reran an interrupted native attempt")
    require(store.validate()["store_sha256"] == original_store, "acceptance mutated the replay store")
    return {"case": name, "status": "passed", "attempts": attempts, "guest_executions": len(attempts),
            "store_unchanged": True, "resume_blocked": reason is not None}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--qemu", type=Path, required=True)
    parser.add_argument("--plugin", type=Path, required=True)
    parser.add_argument("--observer", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--case", choices=CASES, action="append", dest="cases")
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    report = {"schema_version": 1, "status": "blocked", "scope": "native_phase1_retirement_capsule_network",
        "cases": [], "phase1_executed": False, "capsule_executed": False, "namespace_executed": False,
        "hostile_sample_ready": False, "oep_proven": False, "guest_executions": 0}
    try:
        preflight()
        selected = check_runtime_inputs(PROJECT, qemu=args.qemu, plugin=args.plugin)
        metadata = validate_observer(args.observer)
        require(metadata["plugin_api"] == selected["plugin_api"] == 6,
                "NET-6 retirement requires matching QEMU 11.0.1 / API 6 Phase 1 and endpoint observer")
        qemu, plugin, observer = args.qemu.resolve(strict=True), args.plugin.resolve(strict=True), args.observer.resolve(strict=True)
        identities = {str(path): sha(path) for path in (qemu, plugin, observer)}
        report.update(status="failed", runtime_sha256=identities, plugin_api=6)
        for name in args.cases or CASES:
            try:
                case = run_case(out / name, name, qemu, plugin, observer)
            except (OSError, ValueError, RuntimeError, KeyError, subprocess.SubprocessError) as exc:
                case = {"case": name, "status": "failed", "error": f"{type(exc).__name__}: {exc}"}
            report["cases"].append(case)
            write_json(out / "report.json", report)
            print(f"{name}: {case['status']}", flush=True)
            if case["status"] != "passed":
                break
        require(all(sha(Path(path)) == value for path, value in identities.items()), "selected native runtime changed")
        if len(report["cases"]) == len(args.cases or CASES) and all(c["status"] == "passed" for c in report["cases"]):
            report.update(status="passed", phase1_executed=True, capsule_executed=True, namespace_executed=True,
                          guest_executions=sum(c["guest_executions"] for c in report["cases"]))
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        report["error"] = f"{type(exc).__name__}: {exc}"
    def artifacts(pattern):
        values=[]
        for path in out.glob(pattern):
            try:
                values.append(read(path))
            except (OSError, ValueError) as exc:
                report.setdefault('artifact_errors',[]).append({'path':str(path),'error':str(exc)[:1000]})
        return values
    supervisors = artifacts('*/pipeline/session/iterations/*/run/logs/capsule/supervisor.json')
    phases = artifacts('*/pipeline/session/iterations/*/run/config/phase1_result.json')
    report.update(phase1_executed=any(p.get('runtime_observed') is True for p in phases),
                  capsule_executed=any(type(s.get('qemu_pid')) is int for s in supervisors),
                  namespace_executed=any(s.get('network_namespace', {}).get('status') == 'verified' for s in supervisors),
                  guest_executions=sum(p.get('runtime_observed') is True for p in phases),
                  qemu_launch_attempts=sum(type(s.get('qemu_pid')) is int for s in supervisors))
    write_json(out / "report.json", report)
    print(json.dumps(report, indent=2))
    return 0 if report["status"] == "passed" else 2 if report["status"] == "blocked" else 1


if __name__ == "__main__":
    raise SystemExit(main())
