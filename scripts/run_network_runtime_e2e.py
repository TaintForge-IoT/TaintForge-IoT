#!/usr/bin/env python3
"""Exercise NET-5 budgets with real responders, guard processes and a benign i386 ELF."""
from __future__ import annotations

import argparse
from dataclasses import asdict
import json
import os
from pathlib import Path
import shlex
import socket
import struct
import subprocess
import sys
import time

from taintforge_env.controlled_network_backend import ControlledNetworkBackend, ControlledNetworkConfig
from taintforge_env.dns_protocol import build_query, canonical_exchange, question, validate_response
from taintforge_env.network_aggregation import aggregate_network_events
from taintforge_env.network_observer import plugin_argument, validate_observer
from taintforge_env.network_policy import NetworkPolicy, NetworkServicePolicy, CatchAllPolicy
from taintforge_env.network_process import CapturedNetworkProcess
from taintforge_env.network_runtime import NetworkRuntimeOwner, NetworkRuntimeLimits
from taintforge_env.prebuilt_runner import SubprocessCommandExecutor
from taintforge_env.qemu_strace_parser import parse_qemu_strace
from taintforge_env.replay_store import ReplayStore


PROJECT = Path(__file__).resolve().parents[1]
ENV = {**os.environ, "PYTHONPATH": str(PROJECT)}
EXPECTED_STOPS = {"network_receive_budget_exceeded", "network_send_budget_exceeded",
                  "network_log_budget_exceeded", "network_connection_budget_exceeded",
                  "network_responder_exited"}


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n")


def wait_for(test, timeout=4):
    deadline = time.monotonic() + timeout
    while not test():
        if time.monotonic() >= deadline:
            raise RuntimeError("network acceptance deadline expired")
        time.sleep(0.01)


def free_port(kind=socket.SOCK_STREAM):
    with socket.socket(socket.AF_INET, kind) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def session(store, port):
    raw = json.loads((PROJECT / "examples/network_session_tcp.json").read_text())
    raw["remote_port"] = port
    return store.add_session(raw).session_id


def service(transport, port, hint=None, session_id=None, remote="127.0.0.1"):
    return NetworkServicePolicy(transport, "net5_acceptance", remote, port, None,
        "127.0.0.1", port, protocol_hint=hint, replay_session_id=session_id)


def exchange(store, transport, port, request, response, hint=None, remote="127.0.0.1"):
    store.add(transport=transport, remote_ip=remote, remote_port=port,
        protocol_hint=hint, request_bytes=request, response_bytes=response)


def validate_guest(observer, guard, *, attempt_id, runtime_reason, code, goal, expected_goal, expected_reason=None):
    if not isinstance(observer, dict) or not isinstance(guard, dict) or type(code) is not int:
        raise RuntimeError("invalid guest observation or guard result")
    if expected_reason is not None and (expected_reason not in EXPECTED_STOPS or expected_goal):
        raise ValueError("invalid expected NET-5 interruption")
    if (type(guard.get("schema_version")) is not int or guard["schema_version"] != 1
            or guard.get("attempt_id") != attempt_id or guard.get("guest_process_stopped") is not True):
        raise RuntimeError("guard did not confirm the bound guest exit")
    observed = guard.get("command_exit_code")
    normalized = observed if type(observed) is int and observed >= 0 else 128 - observed if type(observed) is int else None
    if normalized != code:
        raise RuntimeError("guard command exit differs from the wrapper exit")
    if guard.get("termination_reason") != expected_reason or runtime_reason != expected_reason:
        raise RuntimeError(f"unexpected runtime/guard termination: expected={expected_reason}, "
                           f"runtime={runtime_reason}, guard={guard.get('termination_reason')}")
    if goal != expected_goal or goal and code or expected_reason is not None and code == 0:
        raise RuntimeError(f"incorrect client goal result, exit={code}, goal={goal}")
    correlated = observer.get("status") == "correlated" and type(observer.get("matched")) is int and observer["matched"] > 0
    interrupted = (expected_reason is not None and observer.get("status") == "incomplete"
                   and observer.get("reason") == "missing complete observer footer")
    if not (correlated or interrupted):
        raise RuntimeError("real QEMU endpoints did not correlate with NET-2: "
                           + json.dumps(observer, sort_keys=True))


class Attempt:
    """Component adapter: two real CLI workers on host loopback share one ledger."""
    def __init__(self, root, name, qemu, observer, binary, limits):
        self.root, self.name = root, name
        (root / "config").mkdir(parents=True)
        (root / "logs").mkdir()
        self.qemu, self.observer, self.binary = qemu, observer, binary
        self.limits = NetworkRuntimeLimits.parse(limits)
        self.store = ReplayStore(root / "store")
        self.ports, self.policies = [], []
        for _ in range(2):
            port = free_port()
            while port in self.ports:
                port = free_port()
            self.ports.append(port)
            self.policies.append([service("tcp", port, "net4_test", session(self.store, port))])
        self.owner = NetworkRuntimeOwner(root / "config/runtime", root / "logs",
            attempt_id="net5-" + name, limits=self.limits)
        config = ControlledNetworkConfig(PROJECT, root, root / "config/policy.json", self.name, 0)
        self.backend = ControlledNetworkBackend(config, executor=SubprocessCommandExecutor())
        self.backend.runtime = self.owner
        self.owner.health_check = self.backend._runtime_health
        self.executions, self.connections = [], []

    def start(self):
        digest = self.store.validate()["store_sha256"]
        for index, name in enumerate(("host", "loopback")):
            log_dir = self.root / "logs" / ("network_" + name)
            log_dir.mkdir()
            policy = self.root / "config" / (name + ".json")
            write(policy, NetworkPolicy(mode="replay", services=self.policies[index],
                catch_all=CatchAllPolicy(enabled=False, udp_enabled=False), runtime_limits=asdict(self.limits)).to_dict())
            command = [sys.executable, str(PROJECT / "scripts/start_network_replay.py"),
                "--policy", str(policy), "--store", str(self.store.root), "--expected-store-sha256", digest,
                "--log-dir", str(log_dir), "--runtime", str(self.owner.client_path)]
            process = CapturedNetworkProcess(command, cwd=PROJECT,
                stdout_path=log_dir / "stdout.log", stderr_path=log_dir / "stderr.log", runtime=self.owner)
            self.backend.processes.append(process)
        expected = sum(map(len, self.policies))
        def ready():
            status = self.owner.snapshot()
            if status["termination_reason"]:
                raise RuntimeError("responder start failed: " + status["termination_reason"])
            return status["ready_listeners"] == expected
        wait_for(ready)

    def guest(self, worker=0, mode=0, interrupt=None, expected_goal=True, expected_reason=None):
        ordinal = len(self.executions)
        directory = self.root / "guests" / str(ordinal)
        directory.mkdir(parents=True)
        capture, result = directory / "endpoints.jsonl", directory / "guard.json"
        argument = plugin_argument(str(self.observer), capture, self.name, self.owner.attempt_id)
        command = [sys.executable, str(PROJECT / "scripts/run_network_guard.py"),
            "--runtime", str(self.owner.client_path), "--result", str(result), "--",
            str(self.qemu), "-plugin", argument, "-strace", str(self.binary), str(mode), str(self.ports[worker])]
        with (directory / "stdout.log").open("wb") as stdout, (directory / "qemu_strace.log").open("wb") as stderr:
            process = subprocess.Popen(command, cwd=PROJECT, env=ENV, stdout=stdout, stderr=stderr)
            try:
                if interrupt is not None:
                    wait_for(lambda: self.owner.snapshot()["budget_usage"]["active_connections"] > 0)
                    interrupt()
                code = process.wait(timeout=6)
            finally:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=self.limits.shutdown_timeout_ms / 1000 + 1)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=2)
                        raise RuntimeError("guest guard did not complete its cancellation cleanup")
        summary = parse_qemu_strace(directory / "qemu_strace.log", directory / "syscalls.jsonl",
            target_arch="i386", endpoint_events=capture, session_id=self.name, attempt_id=self.owner.attempt_id)
        correlated = summary["network_endpoint_observer"]
        goal = (directory / "stdout.log").read_bytes() == b"NET4_OK\n"
        guard = json.loads(result.read_text())
        validate_guest(correlated, guard, attempt_id=self.owner.attempt_id,
            runtime_reason=self.owner.snapshot()["termination_reason"], code=code, goal=goal,
            expected_goal=expected_goal, expected_reason=expected_reason)
        self.executions.append({"goal_reached": goal, "exit_code": code,
            "net2_observer_status": correlated["status"], "observer": correlated,
            "guard_reason": guard.get("termination_reason")})

    def close(self):
        for connection in self.connections:
            connection.close()
        owned = tuple(self.backend.processes)
        self.backend._stop_services()
        aggregate_network_events(self.root / "logs", runtime=self.owner)
        status = self.owner.close()
        if (status["cleanup_status"] != "cleaned" or status["budget_usage"]["active_jobs"]
                or status["ready_listeners"] or any(p.poll() is None or p._group_alive()
                    or any(t.is_alive() for t in p.threads) for p in owned)):
            raise RuntimeError("network acceptance leaked owned resources")
        # Count regular data once, including hardlink aliases only once.
        files, actual_bytes = set(), 0
        for path in (self.root / "logs").rglob("*"):
            if path.is_file():
                info = path.stat()
                identity = info.st_dev, info.st_ino
                if identity not in files:
                    files.add(identity)
                    actual_bytes += info.st_size
        if actual_bytes > self.limits.max_log_bytes:
            raise RuntimeError("network logs exceeded their shared physical byte limit")
        for port in self.ports:
            with socket.socket() as sock:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.bind(("127.0.0.1", port))
        return status, actual_bytes


def mixed_protocols(attempt):
    udp, dns_udp, dns_tcp = free_port(socket.SOCK_DGRAM), free_port(socket.SOCK_DGRAM), free_port()
    exchange(attempt.store, "udp", udp, b"ping", b"pong")
    attempt.policies[0].append(service("udp", udp))
    query = build_query("net5.invalid", transaction_id=521)
    response = query[:2] + struct.pack("!5H", 0x8180, 1, 1, 0, 0) + query[12:question(query).end]
    response += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton("192.0.2.7")
    key, stored = canonical_exchange(query, response)
    for transport, port, worker in (("udp", dns_udp, 0), ("tcp", dns_tcp, 1)):
        exchange(attempt.store, transport, port, key, stored, "dns")
        attempt.policies[worker].append(service(transport, port, "dns"))
    attempt.start()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(2)
        sock.sendto(b"ping", ("127.0.0.1", udp))
        if sock.recv(32) != b"pong":
            raise RuntimeError("UDP replay response mismatch")
        sock.sendto(query, ("127.0.0.1", dns_udp))
        validate_response(query, sock.recv(65535))
    with socket.create_connection(("127.0.0.1", dns_tcp), timeout=2) as sock:
        sock.sendall(len(query).to_bytes(2, "big") + query)
        header = b""
        while len(header) < 2:
            data = sock.recv(2 - len(header))
            if not data:
                raise RuntimeError("DNS/TCP closed before its frame")
            header += data
        data, size = b"", int.from_bytes(header, "big")
        while len(data) < size:
            piece = sock.recv(size - len(data))
            if not piece:
                raise RuntimeError("DNS/TCP truncated its response")
            data += piece
        validate_response(query, data)
    attempt.guest(0)
    attempt.guest(1)


def run_case(root, name, qemu, observer, binary, limits=None, expected_reason=None):
    attempt = Attempt(root, name, qemu, observer, binary, limits)
    try:
        if name == "mixed_protocols":
            mixed_protocols(attempt)
        else:
            attempt.start()
            if name in {"shared_receive", "shared_send", "total_connections"}:
                attempt.guest(0, mode=9 if name == "total_connections" else 0)
                attempt.guest(1, expected_goal=False, expected_reason=expected_reason)
            elif name == "concurrent_capacity":
                for worker in (0, 1):
                    attempt.connections.append(socket.create_connection(("127.0.0.1", attempt.ports[worker]), timeout=2))
                wait_for(lambda: attempt.owner.snapshot()["budget_usage"]["active_connections"] == 2)
                with socket.create_connection(("127.0.0.1", attempt.ports[0]), timeout=2) as rejected:
                    try:
                        rejected.sendall(b"HELLO\n")
                        if rejected.recv(32):
                            raise RuntimeError("over-capacity connection received a response")
                    except ConnectionError:
                        pass
                wait_for(lambda: attempt.owner.snapshot()["budget_usage"]["rejected_connections"] == 1)
                for connection in attempt.connections:
                    connection.close()
                wait_for(lambda: attempt.owner.snapshot()["budget_usage"]["active_connections"] == 0)
                attempt.guest(1)
            elif name == "responder_crash":
                attempt.guest(0, mode=6, expected_goal=False, expected_reason=expected_reason,
                              interrupt=lambda: attempt.backend.processes[0].kill())
            elif name == "log_budget":
                attempt.guest(0, expected_goal=False, expected_reason=expected_reason)
            elif name == "listener_budget":
                raise RuntimeError("listener admission must be tested before readiness")
        status, physical = attempt.close()
        if status["termination_reason"] != expected_reason:
            raise RuntimeError(f"{name}: expected {expected_reason}, got {status['termination_reason']}")
        if status["budget_usage"]["received_bytes"] > attempt.limits.max_received_bytes:
            raise RuntimeError("receive usage exceeded its shared bound")
        if status["budget_usage"]["sent_bytes_reserved"] > attempt.limits.max_sent_bytes:
            raise RuntimeError("send usage exceeded its shared bound")
        return {"case": name, "status": "passed", "termination_reason": expected_reason,
            "guest_executions": attempt.executions, "budget_usage": status["budget_usage"],
            "physical_log_bytes": physical, "cleanup_status": status["cleanup_status"],
            "listeners_closed": True, "owned_processes_stopped": True}
    finally:
        if not attempt.owner.closed:
            for connection in attempt.connections:
                connection.close()
            try:
                attempt.backend._stop_services()
            finally:
                attempt.owner.close(cleanup_status="cleanup_failed")


def privileged_case(root, qemu, observer, binary):
    """Host + namespace responders share a real backend budget; never silently skip."""
    (root / "config").mkdir(parents=True)
    (root / "logs").mkdir()
    tcp, udp = free_port(), free_port(socket.SOCK_DGRAM)
    store = ReplayStore(root / "store")
    sid = session(store, tcp)
    exchange(store, "udp", udp, b"ping", b"pong", remote="192.0.2.10")
    policy_path = root / "config/requested.json"
    write(policy_path, NetworkPolicy(mode="replay", services=[service("tcp", tcp, "net4_test", sid),
        service("udp", udp, remote="192.0.2.10")], runtime_limits={"max_received_bytes": 40},
        catch_all=CatchAllPolicy(enabled=False, udp_enabled=False)).to_dict())
    backend = ControlledNetworkBackend(ControlledNetworkConfig(PROJECT, root, policy_path,
        "net5-privileged-" + str(os.getpid()), 0, responder_mode="replay", replay_store_path=store.root,
        replay_store_expected_sha256=store.validate()["store_sha256"], attempt_id="net5-privileged"),
        executor=SubprocessCommandExecutor())
    try:
        backend.setup()
        plan = backend.plan
        if not plan.host_services or not plan.loopback_services:
            raise RuntimeError("privileged acceptance did not create both responder scopes")
        udp_client = ("import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(2); "
                      f"s.sendto(b'ping',('192.0.2.10',{udp})); assert s.recv(32)==b'pong'; s.close()")
        subprocess.run(["sudo", "-n", "ip", "netns", "exec", plan.namespace_name,
            sys.executable, "-c", udp_client], check=True, timeout=4, capture_output=True)
        for index in range(2):
            capture = root / "logs" / f"privileged-{index}-endpoints.jsonl"
            argument = plugin_argument(str(observer), capture, "net5-privileged", "net5-privileged")
            script = root / "config" / f"guest-{index}.sh"
            script.write_text("#!/bin/bash\nset -euo pipefail\nexec " + shlex.join([
                str(qemu), "-plugin", argument, "-strace", str(binary), "0", str(tcp)]) + "\n")
            completed = subprocess.run(backend.guest_command(script), cwd=PROJECT, env=ENV,
                capture_output=True, timeout=8)
            # QEMU runs as root in this acceptance adapter; return its exact owned log to the caller.
            subprocess.run(["sudo", "-n", "chown", f"{os.getuid()}:{os.getgid()}", str(capture)], check=True)
            trace = root / "logs" / f"privileged-{index}-strace.log"
            trace.write_bytes(completed.stderr)
            summary = parse_qemu_strace(trace, root / "logs" / f"privileged-{index}-syscalls.jsonl",
                target_arch="i386", endpoint_events=capture, session_id="net5-privileged", attempt_id="net5-privileged")
            guard = json.loads((root / "config/network_guard_result.json").read_text())
            write(root / "logs" / f"privileged-{index}-guard.json", guard)
            validate_guest(summary["network_endpoint_observer"], guard,
                attempt_id=backend.runtime.attempt_id,
                runtime_reason=backend.runtime.snapshot()["termination_reason"], code=completed.returncode,
                goal=completed.stdout == b"NET4_OK\n", expected_goal=index == 0,
                expected_reason=None if index == 0 else "network_receive_budget_exceeded")
    finally:
        backend.cleanup()
    status = json.loads((root / "logs/network_runtime_status.json").read_text())
    if status["cleanup_status"] != "cleaned" or status["termination_reason"] != "network_receive_budget_exceeded":
        raise RuntimeError("privileged quota or cleanup result is incorrect")
    namespaces = subprocess.run(["sudo", "-n", "ip", "netns", "list"], check=True, capture_output=True, text=True).stdout
    link = subprocess.run(["ip", "link", "show", plan.veth_host], capture_output=True)
    if plan.namespace_name in namespaces or link.returncode == 0:
        raise RuntimeError("privileged acceptance retained its owned topology")
    return {"case": "real_host_and_namespace_quota", "status": "passed", "namespace_executed": True,
        "guest_executions": 2, "termination_reason": status["termination_reason"],
        "cleanup_status": status["cleanup_status"], "namespace_removed": True, "veth_removed": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--qemu", type=Path, required=True)
    parser.add_argument("--observer", type=Path, required=True)
    parser.add_argument("--privileged", action="store_true", help="also require a real sudo/ip/iptables namespace run")
    args = parser.parse_args()
    created = False
    current_case = None
    report = {"status": "failed", "cases": [], "phase1_executed": False, "capsule_executed": False,
              "namespace_executed": False}
    try:
        root = args.out.resolve()
        root.mkdir(parents=True, exist_ok=False)
        created = True
        write(root / "report.json", report)
        qemu, observer = args.qemu.resolve(strict=True), args.observer.resolve(strict=True)
        metadata = validate_observer(observer)
        binary, obj = root / "benign-client", root / "client.o"
        subprocess.run(["as", "--32", str(PROJECT / "samples/network_session_i386.S"), "-o", str(obj)], check=True, capture_output=True)
        subprocess.run(["ld", "-m", "elf_i386", str(obj), "-o", str(binary)], check=True, capture_output=True)
        definitions = [("mixed_protocols", {}, None),
            ("shared_receive", {"max_received_bytes": 40}, "network_receive_budget_exceeded"),
            ("shared_send", {"max_sent_bytes": 30}, "network_send_budget_exceeded"),
            ("log_budget", {"max_log_bytes": 4096}, "network_log_budget_exceeded"),
            ("total_connections", {"max_total_connections": 2}, "network_connection_budget_exceeded"),
            ("concurrent_capacity", {"max_connections": 2}, None),
            ("responder_crash", {}, "network_responder_exited")]
        for name, limits, reason in definitions:
            current_case = name
            report["cases"].append(run_case(root / name, name, qemu, observer, binary, limits, reason))
            current_case = None
            write(root / "report.json", report)
        if args.privileged:
            current_case = "real_host_and_namespace_quota"
            report["cases"].append(privileged_case(root / "privileged", qemu, observer, binary))
            current_case = None
        cases = report["cases"]
        report.update({"status": "passed",
            "guest_executions": sum(len(case["guest_executions"]) if isinstance(case["guest_executions"], list)
                                    else case["guest_executions"] for case in cases),
            "qemu": subprocess.run([str(qemu), "--version"], check=True, capture_output=True, text=True).stdout.splitlines()[0],
            "plugin_api": metadata["plugin_api"], "execution_adapter": "real_cli_workers_qemu_host_loopback",
            "namespace_executed": args.privileged, "phase1_executed": False, "capsule_executed": False,
            "only_loopback_destinations": not args.privileged})
        write(root / "report.json", report)
        print(json.dumps(report, indent=2))
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError, TimeoutError) as exc:
        error = f"{type(exc).__name__}: {exc}"
        report.update(status="failed", error=error)
        if current_case is not None:
            report["cases"].append({"case": current_case, "status": "failed", "error": error})
        if created:
            write(root / "report.json", report)
        parser.exit(1, f"NET-5 acceptance failed: {exc}\n")


if __name__ == "__main__":
    main()
