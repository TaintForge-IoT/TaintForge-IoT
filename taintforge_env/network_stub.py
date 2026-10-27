from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path

from .network_policy import NetworkPolicy, NetworkServicePolicy
from .dns_emulator import DNSStaticService


class TCPFakeService:
    def __init__(
        self,
        service: NetworkServicePolicy,
        log_dir: str | Path,
        is_catch_all: bool = False,
    ):
        self.service = service
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.connection_counter = 0
        self.is_catch_all = is_catch_all
        self.events_log_path = self.log_dir / "network_events.jsonl"

    async def start(self) -> asyncio.AbstractServer:
        server = await asyncio.start_server(
            self.handle_client,
            host=self.service.bind_ip,
            port=self.service.bind_port,
        )

        if self.is_catch_all:
            print(
                f"[+] Catch-all TCP listener on "
                f"{self.service.bind_ip}:{self.service.bind_port}"
            )
        else:
            print(
                f"[+] Fake TCP {self.service.role} listening on "
                f"{self.service.bind_ip}:{self.service.bind_port}"
            )
            print(
                f"    original target: "
                f"{self.service.domain or self.service.remote_ip}:"
                f"{self.service.remote_port}"
            )

        return server

    async def handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        self.connection_counter += 1
        conn_id = self.connection_counter

        peer = writer.get_extra_info("peername")
        peer_host, peer_port = self.parse_peer(peer)

        print(f"[+] conn={conn_id} from {peer}")

        if self.is_catch_all:
            log_name = f"catchall_tcp_{self.service.bind_port}_conn_{conn_id}.bin"
        else:
            log_name = f"tcp_{self.service.bind_port}_conn_{conn_id}.bin"

        log_path = self.log_dir / log_name

        self.write_event(
            event={
                "event": "tcp_connection_open",
                "connection_id": conn_id,
                "listener_type": self.listener_type(),
                "service_role": self.service.role,
                "protocol_hint": self.service.protocol_hint,
                "peer_host": peer_host,
                "peer_port": peer_port,
                "bind_ip": self.service.bind_ip,
                "bind_port": self.service.bind_port,
                "original_remote_ip": self.original_remote_ip(),
                "original_remote_port": self.original_remote_port(),
                "payload_file": log_name,
            }
        )

        try:
            with log_path.open("ab") as log_file:
                while True:
                    data = await reader.read(4096)

                    if not data:
                        print(f"[+] connection {conn_id} closed")

                        self.write_event(
                            event={
                                "event": "tcp_connection_close",
                                "connection_id": conn_id,
                                "listener_type": self.listener_type(),
                                "service_role": self.service.role,
                                "peer_host": peer_host,
                                "peer_port": peer_port,
                                "bind_ip": self.service.bind_ip,
                                "bind_port": self.service.bind_port,
                                "original_remote_ip": self.original_remote_ip(),
                                "original_remote_port": self.original_remote_port(),
                                "payload_file": log_name,
                            }
                        )

                        break

                    print(
                        f"[+] connection {conn_id} received "
                        f"{len(data)} bytes hex={data.hex()}"
                    )

                    log_file.write(data)
                    log_file.flush()

                    self.write_event(
                        event={
                            "event": "tcp_data",
                            "connection_id": conn_id,
                            "listener_type": self.listener_type(),
                            "service_role": self.service.role,
                            "protocol_hint": self.service.protocol_hint,
                            "peer_host": peer_host,
                            "peer_port": peer_port,
                            "bind_ip": self.service.bind_ip,
                            "bind_port": self.service.bind_port,
                            "original_remote_ip": self.original_remote_ip(),
                            "original_remote_port": self.original_remote_port(),
                            "payload_file": log_name,
                            "bytes_received": len(data),
                            "payload_hex_preview": data[:64].hex(),
                        }
                    )

                    response = self.build_response(data)

                    if response:
                        writer.write(response)
                        await writer.drain()

                        print(
                            f"[+] connection {conn_id} sent "
                            f"{len(response)} bytes hex={response.hex()}"
                        )

                        self.write_event(
                            event={
                                "event": "tcp_response",
                                "connection_id": conn_id,
                                "listener_type": self.listener_type(),
                                "service_role": self.service.role,
                                "protocol_hint": self.service.protocol_hint,
                                "peer_host": peer_host,
                                "peer_port": peer_port,
                                "bind_ip": self.service.bind_ip,
                                "bind_port": self.service.bind_port,
                                "original_remote_ip": self.original_remote_ip(),
                                "original_remote_port": self.original_remote_port(),
                                "payload_file": log_name,
                                "bytes_sent": len(response),
                                "response_hex_preview": response[:64].hex(),
                            }
                        )

        except ConnectionResetError:
            print(f"[!] connection {conn_id} reset by peer")

            self.write_event(
                event={
                    "event": "tcp_connection_reset",
                    "connection_id": conn_id,
                    "listener_type": self.listener_type(),
                    "service_role": self.service.role,
                    "peer_host": peer_host,
                    "peer_port": peer_port,
                    "bind_ip": self.service.bind_ip,
                    "bind_port": self.service.bind_port,
                    "original_remote_ip": self.original_remote_ip(),
                    "original_remote_port": self.original_remote_port(),
                    "payload_file": log_name,
                }
            )

        except Exception as e:
            print(f"[!] connection {conn_id} error: {e}")

            self.write_event(
                event={
                    "event": "tcp_connection_error",
                    "connection_id": conn_id,
                    "listener_type": self.listener_type(),
                    "service_role": self.service.role,
                    "peer_host": peer_host,
                    "peer_port": peer_port,
                    "bind_ip": self.service.bind_ip,
                    "bind_port": self.service.bind_port,
                    "original_remote_ip": self.original_remote_ip(),
                    "original_remote_port": self.original_remote_port(),
                    "payload_file": log_name,
                    "error": str(e),
                }
            )

        finally:
            writer.close()
            await writer.wait_closed()

    def build_response(self, data: bytes) -> bytes:
        if self.service.protocol_hint in {"mirai-like", "c2_binary"}:
            return b"\x00\x00\x00\x00"

        if self.service.protocol_hint == "text":
            return b"OK\n"

        if self.service.protocol_hint == "catch_all":
            return b"OK\n"

        return b"OK\n"

    def listener_type(self) -> str:
        if self.is_catch_all:
            return "catch_all"

        return "known"

    def original_remote_ip(self) -> str | None:
        if self.is_catch_all:
            return None

        return self.service.remote_ip

    def original_remote_port(self) -> int | None:
        if self.is_catch_all:
            return None

        return self.service.remote_port

    def write_event(self, event: dict) -> None:
        event_with_time = {
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            **event,
        }

        with self.events_log_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(event_with_time, ensure_ascii=False) + "\n")

    @staticmethod
    def parse_peer(peer) -> tuple[str | None, int | None]:
        if not peer:
            return None, None

        if isinstance(peer, tuple) and len(peer) >= 2:
            return str(peer[0]), int(peer[1])

        return str(peer), None

async def run_network_emulator(
    policy: NetworkPolicy,
    log_dir: str | Path,
) -> None:
    servers = []
    try:
        for service in policy.services:
            if service.protocol_hint == "dns":
                servers.append(await DNSStaticService(service, log_dir).start())
            elif service.service_type == "tcp":
                servers.append(await TCPFakeService(service, log_dir).start())
        if not servers:
            print("[!] No known services enabled")
            return
        print("[+] Known-service network emulator is running. Press Ctrl+C to stop.")
        await asyncio.gather(*(server.serve_forever() for server in servers))
    except asyncio.CancelledError:
        pass
    finally:
        for server in servers:
            server.close()
        await asyncio.gather(*(server.wait_closed() for server in servers))
