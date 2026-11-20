#!/usr/bin/env python3
"""Run a benign i386 endpoint-observation fixture under real QEMU, on loopback."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import socket
import subprocess

from taintforge_env.network_observer import plugin_argument, validate_observer
from taintforge_env.qemu_strace_parser import parse_qemu_strace
from taintforge_env.observations import load_observation_bundle
from taintforge_env.requirement_extractor import RequirementExtractor
from taintforge_env.repair_planner import RepairPlanner


PROJECT = Path(__file__).resolve().parents[1]


def command(*args):
    return subprocess.run([str(arg) for arg in args], check=True, capture_output=True, text=True, timeout=20)


def run(qemu: Path, observer: Path, out: Path) -> dict:
    qemu, observer = qemu.resolve(strict=True), observer.resolve(strict=True)
    metadata = validate_observer(observer)
    out = out.expanduser().absolute()
    out.mkdir(parents=True, exist_ok=False)
    (out / "logs").mkdir()
    (out / "config").mkdir()
    version = command(qemu, "--version").stdout.splitlines()[0]
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcp_guard, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
        tcp_guard.bind(("127.0.0.1", 0))  # Reserved, deliberately not listening.
        udp.bind(("127.0.0.1", 0))
        udp.settimeout(2)
        tcp_port, udp_port = tcp_guard.getsockname()[1], udp.getsockname()[1]
        obj, binary = out / "client.o", out / "client"
        command("as", "--32", "--defsym", f"TCP_PORT_NET={socket.htons(tcp_port)}",
                "--defsym", f"UDP_PORT_NET={socket.htons(udp_port)}",
                PROJECT / "samples/network_endpoint_i386.S", "-o", obj)
        command("ld", "-m", "elf_i386", obj, "-o", binary)
        events_path = out / "logs/network_endpoint_events.jsonl"
        argument = plugin_argument(str(observer), events_path, "net2-e2e", "benign-i386")
        result = subprocess.run([str(qemu), "-plugin", argument, "-strace", str(binary)],
            capture_output=True, env={**os.environ, "LC_ALL": "C"}, timeout=15)
        (out / "logs/qemu_strace.log").write_bytes(result.stderr)
        (out / "logs/runtime_stdout.log").write_bytes(result.stdout)
        if result.returncode:
            raise RuntimeError(f"QEMU fixture exited {result.returncode}: {result.stderr.decode(errors='replace')[-3000:]}")
        packets = [udp.recvfrom(64)[0] for _ in range(5)]
        if packets != [b"ping"] * 5:
            raise RuntimeError("UDP fixture did not deliver the five expected loopback messages")
    summary = parse_qemu_strace(out / "logs/qemu_strace.log", out / "logs/syscall_events.jsonl",
        target_arch="i386", endpoint_events=events_path, session_id="net2-e2e", attempt_id="benign-i386")
    calls = [json.loads(line) for line in (out / "logs/syscall_events.jsonl").read_text().splitlines()]
    if summary["network_endpoint_observer"]["status"] != "correlated":
        raise RuntimeError(f"endpoint events did not correlate: {summary['network_endpoint_observer']}")
    connects = [e for e in calls if e["syscall"] == "connect"]
    observed_tcp = [e for e in connects if e["transport"] == "tcp" and e["remote_ip"] is not None]
    if [(e["remote_ip"], e["remote_port"]) for e in observed_tcp] != [("127.0.0.1", tcp_port), ("127.0.0.2", tcp_port)]:
        raise RuntimeError("reusing the same sockaddr pointer lost its observed contents")
    sends = [e for e in calls if e["syscall"] in {"send", "sendto", "sendmsg"}]
    if len(sends) != 5 or any((e["transport"], e["remote_ip"], e["remote_port"]) !=
                              ("udp", "127.0.0.1", udp_port) for e in sends):
        raise RuntimeError("legacy/direct UDP or dup descriptor tracking is incorrect")
    bad = [e for e in connects if e.get("endpoint_reason") == "unreadable_sockaddr"]
    unix = [e for e in connects if e.get("endpoint_reason") == "unsupported_address_family"]
    if len(bad) != 1 or bad[0]["remote_ip"] is not None or bad[0]["transport"] != "tcp":
        raise RuntimeError("an unreadable sockaddr borrowed a stale UDP endpoint")
    if len(unix) != 1 or unix[0]["remote_ip"] is not None or unix[0]["transport"] != "unknown":
        raise RuntimeError("AF_UNIX was incorrectly promoted to an IPv4 endpoint")
    requirements = RequirementExtractor().extract(load_observation_bundle(out))
    requirements.save(out / "config/runtime_requirements.json")
    RepairPlanner().plan_file(out / "config/runtime_requirements.json", out / "config/repair_plan.json")
    report = {"status": "passed", "qemu": version, "plugin_api": metadata["plugin_api"],
        "guest_executed": True, "phase1_executed": False, "namespace_executed": False,
        "observer_status": summary["network_endpoint_observer"], "udp_packets": len(packets),
        "direct_and_socketcall": True, "dup_alias_and_fd_reuse": True,
        "sockaddr_snapshot_before_reuse": True, "unreadable_and_unix_stay_unresolved": True,
        "requirements": len(requirements.requirements), "only_loopback_destinations": True}
    (out / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--qemu", type=Path, required=True)
    parser.add_argument("--observer", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    try:
        report = run(args.qemu, args.observer, args.out)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        parser.exit(1, f"NET-2 acceptance failed: {error}\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
