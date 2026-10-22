"""Explicit upstream recording for DNS, UDP RPC and the existing TCP broker."""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import ipaddress
import json
import math
from pathlib import Path
import socket
import struct

from .c2_record_broker import C2RecordBroker
from .c2_record_policy import parse_c2_record_policy
from .dns_protocol import DNSError, canonical_query, error_response, question, validate_response
from .message_capture import publish_capture
from .message_transport import MessageServer
from .network_policy import NetworkPolicy, NetworkServicePolicy


class NetworkRecordError(ValueError):
    pass


def record_options(policy: NetworkPolicy) -> dict:
    raw = policy.recording
    if policy.allow_internet or not isinstance(raw, dict):
        raise NetworkRecordError("recording requires an explicit recording policy and no direct guest Internet")
    allowed = {"capture_kind", "run_id", "live_capture_acknowledged", "max_exchanges", "max_pending", "timeout_seconds", "quiet_seconds"}
    if set(raw) - allowed:
        raise NetworkRecordError("unknown recording options: " + ", ".join(sorted(set(raw) - allowed)))
    if raw.get("capture_kind") not in ("local_test", "live"):
        raise NetworkRecordError("recording.capture_kind must be local_test or live")
    if raw["capture_kind"] == "live" and raw.get("live_capture_acknowledged") is not True:
        raise NetworkRecordError("live recording requires live_capture_acknowledged=true")
    run_id = raw.get("run_id")
    if not isinstance(run_id, str) or not 1 <= len(run_id) <= 120 or any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-" for c in run_id):
        raise NetworkRecordError("invalid recording.run_id")
    options = {"capture_kind": raw["capture_kind"], "run_id": run_id,
               "live_capture_acknowledged": raw.get("live_capture_acknowledged", False)}
    for name, default, lower, upper in (("max_exchanges", 256, 1, 10000), ("max_pending", 16, 1, 128),
                                       ("timeout_seconds", 5.0, 0.1, 30), ("quiet_seconds", 0.05, 0.01, 1)):
        value = raw.get(name, default)
        if type(value) not in (int, float) or not math.isfinite(value) or not lower <= value <= upper:
            raise NetworkRecordError(f"invalid recording.{name}")
        if name in ("max_exchanges", "max_pending") and type(value) is not int:
            raise NetworkRecordError(f"recording.{name} must be an integer")
        options[name] = value
    return options


def c2_policy(service: NetworkServicePolicy, options: dict):
    return parse_c2_record_policy({"schema_version": 1, "mode": "brokered_record",
        "capture_kind": options["capture_kind"], "default_action": "deny", "listen_port": 41000,
        "live_capture_acknowledged": options["live_capture_acknowledged"],
        "target": {"original_ip": service.remote_ip, "original_port": service.remote_port,
                   "upstream_ip": service.upstream_ip, "upstream_port": service.upstream_port},
        "limits": {"max_connections": min(options["max_pending"], 4),
                   "connect_timeout_seconds": min(options["timeout_seconds"], 15)}})


def validate_record_policy(policy: NetworkPolicy) -> dict:
    options = record_options(policy)
    if not policy.services:
        raise NetworkRecordError("recording needs at least one endpoint")
    seen = set()
    for service in policy.services:
        if service.service_type not in ("tcp", "udp"):
            raise NetworkRecordError("recording supports TCP and UDP only")
        for value in (service.remote_ip, service.upstream_ip, service.bind_ip):
            if not isinstance(value, str):
                raise NetworkRecordError("recording requires explicit IP literals")
            try:
                address = ipaddress.ip_address(value)
            except ValueError as exc:
                raise NetworkRecordError("recording requires explicit IP literals") from exc
            if address.version != 4:
                raise NetworkRecordError("recording v1 uses IPv4 endpoints")
        for port in (service.remote_port, service.upstream_port):
            if type(port) is not int or not 1 <= port <= 65535:
                raise NetworkRecordError("invalid recording endpoint port")
        if type(service.bind_port) is not int or not 0 <= service.bind_port <= 65535:
            raise NetworkRecordError("invalid recording bind port")
        key = service.service_type, service.remote_ip, service.remote_port
        if key in seen:
            raise NetworkRecordError("duplicate recording endpoint")
        seen.add(key)
        # Apply the existing live/local-test upstream restrictions to every
        # transport, including DNS. Never resolve an upstream hostname here.
        if service.protocol_hint == "dns":
            upstream = ipaddress.ip_address(service.upstream_ip)
            if options["capture_kind"] == "live" and not upstream.is_global:
                raise NetworkRecordError("live DNS recording requires a globally routable upstream")
            if options["capture_kind"] == "local_test" and not (upstream.is_loopback or upstream.is_private):
                raise NetworkRecordError("local DNS recording requires a loopback or private upstream")
        else:
            c2_policy(service, options)
    return options


class MessageRecordService:
    def __init__(self, *, service: NetworkServicePolicy, options: dict, log_dir: Path):
        self.service = service
        self.options = options
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.count = 0

    async def start(self):
        return await MessageServer(self.handle, max_pending=self.options["max_pending"],
            timeout=self.options["timeout_seconds"] + 2).start(
                self.service.bind_ip, self.service.bind_port, self.service.service_type)

    async def handle(self, request: bytes, peer: tuple) -> bytes | None:
        dns = self.service.protocol_hint == "dns"
        self.count += 1
        exchange_number = self.count
        event = {"timestamp_utc": datetime.now(timezone.utc).isoformat(),
                 "event": "dns_record" if dns else "udp_record", "transport": self.service.service_type,
                 "service_role": self.service.role, "protocol_hint": self.service.protocol_hint,
                 "original_remote_ip": self.service.remote_ip, "original_remote_port": self.service.remote_port,
                 "peer_host": peer[0], "peer_port": peer[1], "run_id": self.options["run_id"]}
        response = None
        status, reason = "completed", None
        try:
            if exchange_number > self.options["max_exchanges"]:
                raise NetworkRecordError("recording exchange limit reached")
            if dns:
                canonical_query(request)
                event.update(dns_query=question(request).name, dns_qtype=question(request).qtype)
            async with asyncio.timeout(self.options["timeout_seconds"]):
                response = await self._upstream(request)
            if dns:
                event["dns"] = validate_response(request, response)
        except (OSError, ValueError, TimeoutError) as exc:
            status, reason = "failed", f"{type(exc).__name__}: {exc}"
        except asyncio.CancelledError:
            publish_capture(self.log_dir / "captures", **self._capture_args(request, response),
                            status="cancelled", reason="service stopped")
            raise
        if exchange_number <= self.options["max_exchanges"]:
            directory = publish_capture(self.log_dir / "captures", **self._capture_args(request, response),
                                        status=status, reason=reason)
            event["capture_directory"] = str(directory)
        event.update(status=status, reason=reason)
        delivered = response if status == "completed" else None
        if dns:
            if status != "completed":
                try:
                    delivered = error_response(request)
                except DNSError:
                    pass
            event["dns_response_prepared"] = delivered is not None
            event["response_origin"] = "upstream" if status == "completed" else "synthetic_error"
        with (self.log_dir / "network_events.jsonl").open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(event, sort_keys=True) + "\n")
        return delivered

    def _capture_args(self, request, response):
        return dict(run_id=self.options["run_id"], transport=self.service.service_type,
            protocol_hint=self.service.protocol_hint, remote_ip=self.service.remote_ip,
            remote_port=self.service.remote_port, upstream_ip=self.service.upstream_ip,
            upstream_port=self.service.upstream_port, capture_kind=self.options["capture_kind"],
            request=request, response=response, quiet_seconds=self.options["quiet_seconds"])

    async def _upstream(self, request: bytes) -> bytes:
        if self.service.service_type == "tcp":
            reader, writer = await asyncio.open_connection(self.service.upstream_ip, self.service.upstream_port,
                                                            family=socket.AF_INET)
            try:
                writer.write(struct.pack("!H", len(request)) + request)
                await writer.drain()
                size = struct.unpack("!H", await reader.readexactly(2))[0]
                return await reader.readexactly(size)
            finally:
                writer.close()
                await writer.wait_closed()
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.setblocking(False)
            loop = asyncio.get_running_loop()
            await loop.sock_connect(sock, (self.service.upstream_ip, self.service.upstream_port))
            await loop.sock_sendto(sock, request, (self.service.upstream_ip, self.service.upstream_port))
            response = await loop.sock_recv(sock, 65536)
            if len(response) > 65507:
                raise NetworkRecordError("oversized upstream UDP datagram")
            # UDP has no EOF. The capture explicitly records this bounded
            # observation window; additional replies make the profile unsupported.
            try:
                await asyncio.wait_for(loop.sock_recv(sock, 65536), self.options["quiet_seconds"])
            except TimeoutError:
                return response
            raise NetworkRecordError("multiple upstream datagrams are outside the one-response profile")


class RecordNetwork:
    def __init__(self, policy: NetworkPolicy, log_dir: str | Path):
        self.policy = policy
        self.options = validate_record_policy(policy)
        self.log_dir = Path(log_dir)
        self.servers = []
        self.brokers = []

    async def start(self):
        try:
            for service in self.policy.services:
                if service.service_type == "tcp" and service.protocol_hint != "dns":
                    broker = C2RecordBroker(policy=c2_policy(service, self.options), bind_ip=service.bind_ip,
                        capture_root=self.log_dir / "captures", run_id=self.options["run_id"],
                        event_path=self.log_dir / "network_events.jsonl", listen_port_override=service.bind_port,
                        protocol_hint=service.protocol_hint)
                    await broker.start()
                    service.bind_port = broker.bound_port
                    self.brokers.append(broker)
                else:
                    server = await MessageRecordService(service=service, options=self.options, log_dir=self.log_dir).start()
                    service.bind_port = server.sockets[0].getsockname()[1]
                    self.servers.append(server)
            return self
        except BaseException:
            await self.close()
            raise

    async def close(self):
        for server in self.servers:
            server.close()
        await asyncio.gather(*(server.wait_closed() for server in self.servers))
        for broker in self.brokers:
            await broker.close()
