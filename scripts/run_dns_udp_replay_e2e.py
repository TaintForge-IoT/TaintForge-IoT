#!/usr/bin/env python3
"""Record DNS/TCP/UDP from a benign domain-only C client, then replay offline.

--sandbox additionally records AND replays through the public prebuilt runner,
including libc DNS on loopback, a hardcoded DNS endpoint, TCP fallback and DNAT.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
from pathlib import Path
import platform
import shutil
import socket
import struct
import sys

from scripts.run_c2_replay_local_e2e import PROJECT_ROOT, check, command
from taintforge_env.capture_importer import import_capture
from taintforge_env.dns_protocol import build_query, question, validate_response
from taintforge_env.iteration_controller import IterationController
from taintforge_env.message_transport import MessageServer
from taintforge_env.network_policy import NetworkPolicy, NetworkServicePolicy
from taintforge_env.network_record import RecordNetwork
from taintforge_env.network_replay import replay_service, validate_replay_policy
from taintforge_env.replay_store import ReplayStore


def answer(query: bytes, address: str, *, truncated=False) -> bytes:
    end = question(query).end
    wire = query[:2] + struct.pack("!5H", 0x8180 | (0x0200 if truncated else 0), 1, int(not truncated), 0, 0) + query[12:end]
    if not truncated:
        wire += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton(address)
    return wire


class MockNetwork:
    def __init__(self, address):
        self.address = address
        self.listeners = []
        self.counts = {"dns_udp": 0, "dns_tcp": 0, "tcp": 0, "udp": 0}

    async def start(self):
        async def dns_udp(data, peer):
            self.counts["dns_udp"] += 1
            return answer(data, self.address, truncated=True)

        async def dns_tcp(data, peer):
            self.counts["dns_tcp"] += 1
            return answer(data, self.address)

        async def udp(data, peer):
            self.counts["udp"] += 1
            check(data == b"hello", "unexpected UDP client request")
            return b"world"

        async def tcp(reader, writer):
            self.counts["tcp"] += 1
            try:
                check(await asyncio.wait_for(reader.readexactly(5), 3) == b"hello", "unexpected TCP request")
                check(await asyncio.wait_for(reader.read(1), 3) == b"", "TCP request did not end")
                writer.write(b"world")
                await writer.drain()
            finally:
                writer.close()
                await writer.wait_closed()

        for handler, transport in ((dns_udp, "udp"), (dns_tcp, "tcp"), (udp, "udp")):
            self.listeners.append(await MessageServer(handler).start("127.0.0.1", 0, transport))
        self.listeners.append(await asyncio.start_server(tcp, "127.0.0.1", 0))
        self.dns_udp, self.dns_tcp, self.udp, self.tcp = [s.sockets[0].getsockname()[1] for s in self.listeners]
        return self

    async def close(self):
        for listener in self.listeners:
            listener.close()
        await asyncio.gather(*(s.wait_closed() for s in self.listeners))

    def policy(self, *, loopback_dns=False):
        services = []
        for dns_ip in (("198.51.100.53", "127.0.0.1") if loopback_dns else ("198.51.100.53",)):
            for transport, upstream in (("udp", self.dns_udp), ("tcp", self.dns_tcp)):
                services.append(NetworkServicePolicy(transport, "dns", dns_ip, 53, None,
                    "127.0.0.1", 0, "dns", "127.0.0.1", upstream))
        for transport, port, upstream in (("tcp", 48101, self.tcp), ("udp", 48102, self.udp)):
            services.append(NetworkServicePolicy(transport, "c2", self.address, port, "c2.example",
                "127.0.0.2", 0, "c2_binary" if transport == "tcp" else "udp", "127.0.0.1", upstream))
        return NetworkPolicy(mode="record", services=services,
            recording={"capture_kind": "local_test", "run_id": "dns-udp-e2e", "timeout_seconds": 3})


def replay_policy(policy):
    raw = policy.to_dict()
    raw["mode"] = "replay"
    raw.pop("recording", None)
    for item in raw["services"]:
        item.pop("upstream_ip", None)
        item.pop("upstream_port", None)
    return raw


def import_all(capture_root: Path, store: ReplayStore):
    sessions = sorted(capture_root.rglob("session.json"))
    check(bool(sessions), "no captures were published")
    receipts = [import_capture(path.parent, store).to_dict() for path in sessions]
    digest = store.validate()["store_sha256"]
    for path in sessions:
        check(not import_capture(path.parent, store).created, "repeat import changed an exchange")
    check(store.validate()["store_sha256"] == digest, "repeat import changed the store")
    return receipts


async def prepare(out: Path, client: Path, policy: dict, *, mode: str, store: Path | None, execute: bool):
    template = out / "template"
    rootfs, config = template / "rootfs", template / "config"
    for directory in ("bin", "etc", "proc", "dev", "tmp"):
        (rootfs / directory).mkdir(parents=True)
    config.mkdir()
    shutil.copy2(client, rootfs / "bin/unpacked.elf")
    dns_ip = "127.0.0.1" if any(s["remote_ip"] == "127.0.0.1" and s["protocol_hint"] == "dns" for s in policy["services"]) else "198.51.100.53"
    (rootfs / "etc/resolv.conf").write_text(f"nameserver {dns_ip}\noptions timeout:2 attempts:1\n")
    (rootfs / "etc/nsswitch.conf").write_text("hosts: dns\n")
    (rootfs / "etc/taintforge-network-probe.conf").write_text("198.51.100.53 53 53 48101 48102 c2.example\n")
    (config / "runtime.json").write_text(json.dumps({"arch": "x86_64", "host_binary": str(client),
        "guest_binary": "/bin/unpacked.elf", "qemu_required": False, "rootfs": str(rootfs)}))
    (config / "network_policy.json").write_text(json.dumps(policy, indent=2))
    session = out / "session"
    network_args = ("--network", mode, *(("--replay-store", str(store)) if store else ()))
    await command(sys.executable, "scripts/run_synthesis_loop.py", "run", "--session-dir", str(session),
        "--template-run-dir", str(template), "--project-root", str(PROJECT_ROOT), "--seed-rootfs", str(rootfs),
        "--snapshot-store", str(out / "snapshots"), *network_args, "--initialize-only")
    IterationController(session).prepare_next()
    args = ("--session-dir", str(session), "--iteration", "0", "--template-run-dir", str(template),
            "--project-root", str(PROJECT_ROOT), *network_args, "--timeout", "25")
    validation = await command(sys.executable, "scripts/run_prebuilt_iteration.py", "validate", *args)
    (out / "validate.stdout").write_bytes(validation)
    run_dir = session / "iterations/0000/run"
    if execute:
        result = await command(sys.executable, "scripts/run_prebuilt_iteration.py", "run", *args, timeout=90)
        (out / "run.stdout").write_bytes(result)
        execution = json.loads((run_dir / "config/prebuilt_execution.json").read_text())
        check(execution["guest_exit_code"] == 0 and not execution["timed_out"], f"sandbox {mode} client failed")
        check((run_dir / "logs/runtime_stdout.log").read_bytes() == b"dns tcp udp ok\n", "sandbox output mismatch")
        events = [json.loads(line) for line in (run_dir / "logs/network_events.jsonl").read_text().splitlines()]
        if mode == "replay":
            check(any(e.get("event") == "dns_replay_hit" for e in events), "sandbox DNS hit missing")
            check(any(e.get("event") == "replay_hit" and e.get("transport") == "udp" for e in events), "sandbox UDP hit missing")
    verified = json.loads(await command(sys.executable, "scripts/run_synthesis_loop.py", "verify", "--session-dir", str(session)))
    check(verified["binding_verified"], "synthesis binding failed")
    return run_dir


async def local(out: Path, client: Path):
    mocks = await MockNetwork("127.0.0.2").start()
    policy = mocks.policy()
    recorder = RecordNetwork(policy, out / "record")
    try:
        await recorder.start()
        ports = [str(s.bind_port) for s in policy.services]
        result = await command(str(client), "127.0.0.1", *ports, "c2.example")
        check(result == b"dns tcp udp ok\n", "recording client failed")
        async with asyncio.timeout(3):
            while any(b.active_sessions for b in recorder.brokers):
                await asyncio.sleep(0.01)
    finally:
        await recorder.close()
        await mocks.close()
    before = dict(mocks.counts)
    check(all(before.values()), "recording did not exercise every transport")
    policy_path = out / "record_policy.json"
    policy_path.write_text(json.dumps(policy.to_dict(), indent=2))
    await command(sys.executable, "scripts/import_network_recording.py", "--capture-dir", str(out / "record/captures"),
                  "--policy", str(policy_path), "--out", str(out / "replay_bundle"))
    store = ReplayStore(out / "replay_bundle/replay_store")
    receipts = import_all(out / "record/captures", store)
    validation = store.validate()
    validate_replay_policy(policy=policy, replay_store=store)
    listeners = []
    try:
        for service in policy.services:
            service.bind_port = 0
            listener = await replay_service(service=service, store=store, log_dir=out / "replay").start()
            service.bind_port = listener.sockets[0].getsockname()[1]
            listeners.append(listener)
        result = await command(str(client), "127.0.0.1", *(str(s.bind_port) for s in policy.services), "c2.example")
        check(result == b"dns tcp udp ok\n", "offline domain replay failed")
        query = build_query("unknown.example", transaction_id=54321)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.setblocking(False)
            loop = asyncio.get_running_loop()
            await loop.sock_sendto(sock, query, ("127.0.0.1", policy.services[0].bind_port))
            response, _ = await asyncio.wait_for(loop.sock_recvfrom(sock, 65536), 2)
            check(validate_response(query, response)["rcode"] == 2, "unknown DNS did not fail explicitly")
        check(mocks.counts == before, "replay contacted upstream")
    finally:
        for listener in listeners:
            listener.close()
        await asyncio.gather(*(s.wait_closed() for s in listeners))
    check(store.validate() == validation, "replay modified the bound store")
    await prepare(out / "prebuilt", client, replay_policy(policy), mode="replay", store=store.root, execute=False)
    return {"recording_client": "passed", "offline_client": "passed", "upstream_stopped_before_replay": True,
        "upstream_counts": before, "dns_tcp_fallback": True, "unknown_dns_rejected": True,
        "prebuilt_validated": True, "repeat_import": "already_present", "captures": len(receipts), **validation}


async def sandbox(out: Path, client: Path):
    mocks = await MockNetwork("198.51.100.10").start()
    policy = mocks.policy(loopback_dns=True)
    # The backend allocates listener ports from these requested endpoints.
    for service in policy.services:
        service.bind_port = service.remote_port
    try:
        recorded = await prepare(out / "record", client, policy.to_dict(), mode="record", store=None, execute=True)
    finally:
        await mocks.close()
    counts = dict(mocks.counts)
    check(all(counts.values()), "sandbox recording missed a transport")
    await command(sys.executable, "scripts/import_network_recording.py", "--capture-dir", str(recorded / "logs"),
        "--policy", str(out / "record/template/config/network_policy.json"), "--out", str(out / "replay_bundle"))
    store = ReplayStore(out / "replay_bundle/replay_store")
    receipts = import_all(recorded / "logs", store)
    await prepare(out / "replay", client, replay_policy(policy), mode="replay", store=store.root, execute=True)
    check(mocks.counts == counts, "sandbox replay contacted upstream")
    return {"record_executed": True, "replay_executed": True, "libc_dns": True,
            "loopback_dns": True, "hardcoded_dns": True, "dns_tcp_fallback": True,
            "tcp_udp_dnat": True, "upstream_stopped_before_replay": True, "captures": len(receipts)}


async def run(out: Path, *, with_sandbox=False):
    check(platform.system() == "Linux" and platform.machine() in ("x86_64", "amd64"), "this fixture needs Linux x86-64")
    out.mkdir(parents=True, exist_ok=False)
    client = out / "dns_udp_replay_client"
    await command("gcc", "-static", "-O2", "-Wall", "-Wextra", "-Werror",
                  "samples/dns_udp_replay_client.c", "-o", str(client))
    report = {"status": "passed", "local": await local(out / "local", client),
              "sandbox_executed": with_sandbox}
    if with_sandbox:
        report["sandbox"] = await sandbox(out / "sandbox", client)
    (out / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--sandbox", action="store_true")
    args = parser.parse_args()
    os.umask(0o077)
    try:
        report = asyncio.run(run(args.out.absolute(), with_sandbox=args.sandbox))
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"DNS/UDP record/replay failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
