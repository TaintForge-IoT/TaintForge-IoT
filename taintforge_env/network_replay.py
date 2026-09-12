from __future__ import annotations

import asyncio
import ipaddress
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .network_policy import NetworkPolicy, NetworkServicePolicy
from .replay_store import (
    ReplayExchange,
    ReplayStore,
    ReplayStoreValidationError,
    sha256_bytes
)


class NetworkReplayError(RuntimeError):
    """Raised when a deterministic replay service cannot start safely."""


class TCPReplayService:
    """Replay exact TCP request/response exchanges without protocol guessing."""

    def __init__(self,*,service: NetworkServicePolicy,store: ReplayStore,log_dir: str | Path) -> None:
        if service.service_type != "tcp":
            raise NetworkReplayError(f"TCP replay received unsupported service type: {service.service_type}")
        if service.remote_ip is None or service.remote_port is None:
            raise NetworkReplayError("TCP replay service requires an original remote IP and port")
        self.service = service
        self.store = store
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.events_log_path = self.log_dir / "network_events.jsonl"
        self.connection_counter = 0
        try:
            self.exchanges = store.exchanges_for_endpoint(transport="tcp",remote_ip=service.remote_ip,remote_port=service.remote_port,protocol_hint=service.protocol_hint)
        except ReplayStoreValidationError as exc:
            raise NetworkReplayError(str(exc)) from exc
        if not self.exchanges:
            raise NetworkReplayError("Replay store has no exact TCP exchange for " f"{service.remote_ip}:{service.remote_port} protocol_hint={service.protocol_hint!r}")

    async def start(self) -> asyncio.AbstractServer:
        server = await asyncio.start_server(self.handle_client,host=self.service.bind_ip,port=self.service.bind_port)
        print(
            f"[+] Deterministic TCP replay listening on {self.service.bind_ip}:{self.service.bind_port}; original target {self.service.remote_ip}:{self.service.remote_port}; exchanges={len(self.exchanges)}")
        return server

    async def handle_client(self,reader: asyncio.StreamReader,writer: asyncio.StreamWriter) -> None:
        self.connection_counter += 1
        connection_id = self.connection_counter
        peer_host, peer_port = self._parse_peer(writer.get_extra_info("peername"))
        payload_name = (f"replay_tcp_{self.service.bind_port}_conn_{connection_id}.bin")
        payload_path = self.log_dir / payload_name
        pending = bytearray()
        self._write_event(
            {
                "event": "tcp_connection_open",
                "listener_type": "deterministic_replay",
                "connection_id": connection_id,
                "service_role": self.service.role,
                "protocol_hint": self.service.protocol_hint,
                "peer_host": peer_host,
                "peer_port": peer_port,
                "bind_ip": self.service.bind_ip,
                "bind_port": self.service.bind_port,
                "original_remote_ip": self.service.remote_ip,
                "original_remote_port": self.service.remote_port,
                "payload_file": payload_name,
            }
        )

        try:
            with payload_path.open("ab") as payload_stream:
                while True:
                    data = await reader.read(4096)
                    if not data:
                        if pending:
                            self._write_miss(connection_id=connection_id,peer_host=peer_host,peer_port=peer_port,payload_name=payload_name,observed=bytes(pending),reason=("connection_closed_before_complete_request"))
                        self._write_event(
                            {
                                "event": "tcp_connection_close",
                                "listener_type": "deterministic_replay",
                                "connection_id": connection_id,
                                "service_role": self.service.role,
                                "peer_host": peer_host,
                                "peer_port": peer_port,
                                "bind_ip": self.service.bind_ip,
                                "bind_port": self.service.bind_port,
                                "original_remote_ip": self.service.remote_ip,
                                "original_remote_port": (
                                    self.service.remote_port
                                ),
                                "payload_file": payload_name
                            }
                        )
                        return

                    payload_stream.write(data)
                    payload_stream.flush()
                    pending.extend(data)
                    self._write_event(
                        {
                            "event": "tcp_data",
                            "listener_type": "deterministic_replay",
                            "connection_id": connection_id,
                            "service_role": self.service.role,
                            "protocol_hint": self.service.protocol_hint,
                            "peer_host": peer_host,
                            "peer_port": peer_port,
                            "bind_ip": self.service.bind_ip,
                            "bind_port": self.service.bind_port,
                            "original_remote_ip": self.service.remote_ip,
                            "original_remote_port": self.service.remote_port,
                            "payload_file": payload_name,
                            "bytes_received": len(data),
                            "payload_hex_preview": data[:64].hex(),
                        }
                    )

                    should_close = await self._consume_pending(pending=pending,writer=writer,connection_id=connection_id,peer_host=peer_host,peer_port=peer_port,payload_name=payload_name)
                    if should_close:
                        return
        except Exception as exc:
            self._write_event(
                {
                    "event": "tcp_connection_error",
                    "listener_type": "deterministic_replay",
                    "connection_id": connection_id,
                    "service_role": self.service.role,
                    "original_remote_ip": self.service.remote_ip,
                    "original_remote_port": self.service.remote_port,
                    "payload_file": payload_name,
                    "error": f"{type(exc).__name__}: {exc}"
                }
            )
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except ConnectionError:
                pass

    async def _consume_pending(self,*,pending: bytearray,writer: asyncio.StreamWriter,connection_id: int,peer_host: str | None,peer_port: int | None,payload_name: str) -> bool:
        while pending:
            exact_prefixes = [exchange for exchange in self.exchanges if bytes(pending).startswith(exchange.request_bytes)]
            if exact_prefixes:
                exchange = exact_prefixes[0]
                del pending[: len(exchange.request_bytes)]
                await self._send_hit(exchange=exchange,writer=writer,connection_id=connection_id,peer_host=peer_host,peer_port=peer_port,payload_name=payload_name)
                if exchange.entry.response.close_after_send:
                    if pending:
                        self._write_event(
                            {
                                "event": "replay_trailing_bytes_discarded",
                                "connection_id": connection_id,
                                "entry_id": exchange.entry.entry_id,
                                "bytes_discarded": len(pending),
                                "payload_file": payload_name
                            }
                        )
                    return True
                continue

            observed = bytes(pending)
            if any(exchange.request_bytes.startswith(observed) for exchange in self.exchanges):
                return False

            self._write_miss(
                connection_id=connection_id,
                peer_host=peer_host,
                peer_port=peer_port,
                payload_name=payload_name,
                observed=observed,
                reason="no_known_request_prefix"
            )
            return True
        return False

    async def _send_hit(self,*,exchange: ReplayExchange,writer: asyncio.StreamWriter,connection_id: int,peer_host: str | None,peer_port: int | None,payload_name: str) -> None:
        response = exchange.entry.response
        if response.delay_ms:
            await asyncio.sleep(response.delay_ms / 1000)
        if exchange.response_bytes:
            writer.write(exchange.response_bytes)
            await writer.drain()
        self._write_event(
            {
                "event": "replay_hit",
                "listener_type": "deterministic_replay",
                "connection_id": connection_id,
                "service_role": self.service.role,
                "protocol_hint": self.service.protocol_hint,
                "peer_host": peer_host,
                "peer_port": peer_port,
                "bind_ip": self.service.bind_ip,
                "bind_port": self.service.bind_port,
                "original_remote_ip": self.service.remote_ip,
                "original_remote_port": self.service.remote_port,
                "payload_file": payload_name,
                "entry_id": exchange.entry.entry_id,
                "request_sha256": exchange.entry.request.payload_sha256,
                "request_size": exchange.entry.request.payload_size,
                "response_sha256": response.sha256,
                "response_size": response.size,
                "delay_ms": response.delay_ms,
                "close_after_send": response.close_after_send
            }
        )

    def _write_miss(self,*,connection_id: int,peer_host: str | None,peer_port: int | None,payload_name: str,observed: bytes,reason: str,) -> None:
        self._write_event(
            {
                "event": "replay_miss",
                "listener_type": "deterministic_replay",
                "connection_id": connection_id,
                "service_role": self.service.role,
                "protocol_hint": self.service.protocol_hint,
                "peer_host": peer_host,
                "peer_port": peer_port,
                "bind_ip": self.service.bind_ip,
                "bind_port": self.service.bind_port,
                "original_remote_ip": self.service.remote_ip,
                "original_remote_port": self.service.remote_port,
                "payload_file": payload_name,
                "observed_request_sha256": sha256_bytes(observed),
                "observed_request_size": len(observed),
                "observed_hex_preview": observed[:64].hex(),
                "reason": reason
            }
        )

    def _write_event(self, event: dict[str, Any]) -> None:
        payload = {"timestamp_utc": datetime.now(timezone.utc).isoformat(),**event}
        with self.events_log_path.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n")

    @staticmethod
    def _parse_peer(peer: Any) -> tuple[str | None, int | None]:
        if isinstance(peer, tuple) and len(peer) >= 2:
            return str(peer[0]), int(peer[1])
        if peer is None:
            return None, None
        return str(peer), None


async def run_network_replay(*,policy: NetworkPolicy,replay_store: ReplayStore,log_dir: str | Path) -> None:

    validate_replay_policy(policy=policy, replay_store=replay_store)

    services = [TCPReplayService(service=service,store=replay_store,log_dir=log_dir) for service in policy.services]
    if not services:
        raise NetworkReplayError("deterministic replay policy contains no TCP services")
    servers = [await service.start() for service in services]
    try:
        await asyncio.gather(*(server.serve_forever() for server in servers))
    except asyncio.CancelledError:
        pass
    finally:
        for server in servers:
            server.close()
        await asyncio.gather(*(server.wait_closed() for server in servers))


def validate_replay_policy(*,policy: NetworkPolicy,replay_store: ReplayStore) -> dict[str, Any]:

    if policy.allow_internet:
        raise NetworkReplayError("deterministic replay policy must not allow Internet access")
    try:
        store_validation = replay_store.validate()
    except ReplayStoreValidationError as exc:
        raise NetworkReplayError(str(exc)) from exc
    if not policy.services:
        raise NetworkReplayError("deterministic replay policy contains no TCP services")

    covered_exchanges = 0
    for service in policy.services:
        if service.service_type != "tcp":
            raise NetworkReplayError(f"deterministic replay v1 supports TCP services only: {service.service_type}")
        if service.remote_ip is None or service.remote_port is None:
            raise NetworkReplayError("deterministic replay service requires remote_ip and remote_port")
        try:
            remote_ip = ipaddress.ip_address(service.remote_ip)
        except ValueError as exc:
            raise NetworkReplayError(f"deterministic replay service has invalid remote_ip: {service.remote_ip}") from exc
        if remote_ip.version != 4:
            raise NetworkReplayError(f"deterministic replay v1 supports IPv4 services only: {service.remote_ip}")
        try:
            exchanges = replay_store.exchanges_for_endpoint(transport="tcp",remote_ip=service.remote_ip,remote_port=service.remote_port,protocol_hint=service.protocol_hint)
        except ReplayStoreValidationError as exc:
            raise NetworkReplayError(str(exc)) from exc
        if not exchanges:
            raise NetworkReplayError(f"replay store has no exact TCP exchange for {service.remote_ip}:{service.remote_port} protocol_hint={service.protocol_hint!r}")
        covered_exchanges += len(exchanges)
    return {**store_validation,"covered_services": len(policy.services),"covered_exchanges": covered_exchanges}
