"""Ordered TCP replay with independent state and bounded connection lifetimes."""
from __future__ import annotations

from .network_runtime import payload_scope, network_open
from .network_runtime_transport import start_server as runtime_start_server

import asyncio
import hashlib
from pathlib import Path

from .event_logger import append_jsonl_event
from .replay_session import ReplaySession


class SessionStopped(Exception):
    pass


class SessionListener:
    def __init__(self, service, server):
        self.service, self.server = service, server

    @property
    def sockets(self):
        return self.server.sockets

    def is_serving(self):
        return self.server.is_serving()

    async def serve_forever(self):
        await self.server.serve_forever()

    def close(self):
        self.service.closing = True
        self.server.close()
        for task in tuple(self.service.tasks):
            task.cancel()

    async def wait_closed(self):
        await self.server.wait_closed()
        while self.service.tasks:
            await asyncio.gather(*tuple(self.service.tasks), return_exceptions=True)


class TCPSessionService:
    def __init__(self, *, service, session: ReplaySession, log_dir):
        self.service, self.session = service, session
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.tasks = set()
        self.active_connections = 0
        self.connection_counter = 0
        self.closing = False
        self.rejections_logged = set()

    async def start(self):
        if self.closing:
            raise RuntimeError("closed session service cannot restart; create a fresh service")
        server = await runtime_start_server(self.handle_client, self.service.bind_ip,
                                            self.service.bind_port, limit=65536)
        return SessionListener(self, server)

    def event(self, name, identity, **fields):
        append_jsonl_event(self.log_dir / "network_events.jsonl", {
            "network_event_version": 1, "event": name, "transport": "tcp",
            "listener_type": "deterministic_session", "service_role": self.service.role,
            "protocol_hint": self.service.protocol_hint, "bind_ip": self.service.bind_ip,
            "bind_port": self.service.bind_port, "original_remote_ip": self.service.remote_ip,
            "original_remote_port": self.service.remote_port,
            "replay_session_id": self.session.session_id,
            "response_prepared": False, "response_sent": False,
            **identity, **fields})

    async def handle_client(self, reader, writer):
        task = asyncio.current_task()
        self.tasks.add(task)
        admitted = False
        identity = {}
        completed_steps = 0
        step_index = 0
        received = sent = 0
        limits = self.session.limits
        try:
            reason = ("service_closed" if self.closing else
                      "total_connection_limit" if self.connection_counter >= limits.max_total_connections else
                      "concurrent_connection_limit" if self.active_connections >= limits.max_connections else None)
            if reason:
                if reason not in self.rejections_logged:
                    self.event("session_rejected", {}, reason=reason, status="failed")
                    self.rejections_logged.add(reason)
                return
            self.connection_counter += 1
            self.active_connections += 1
            admitted = True
            peer = writer.get_extra_info("peername")
            payload_name = f"session_tcp_{self.service.bind_port}{payload_scope(self.service)}_conn_{self.connection_counter}.bin"
            identity = {"connection_id": self.connection_counter,
                        "peer_host": peer[0] if peer else None, "peer_port": peer[1] if peer else None,
                        "payload_file": payload_name}
            self.event("session_start", identity, steps=len(self.session.steps))
            loop = asyncio.get_running_loop()
            deadline = loop.time() + limits.session_timeout_ms / 1000
            idle_deadline = loop.time() + limits.idle_timeout_ms / 1000
            pending = bytearray()

            async def wait(factory, *, receiving=False):
                nonlocal idle_deadline
                now = loop.time()
                idle = idle_deadline if receiving else now + limits.idle_timeout_ms / 1000
                timeout = min(deadline, idle) - now
                reason = "session_timeout" if deadline <= idle else "idle_timeout"
                if timeout <= 0:
                    raise SessionStopped(reason)
                try:
                    async with asyncio.timeout(timeout):
                        return await factory()
                except TimeoutError as exc:
                    raise SessionStopped(reason) from exc

            with network_open(self.log_dir / payload_name, "wb") as payload:
                for step_index, step in enumerate(self.session.steps):
                    if loop.time() >= deadline:
                        raise SessionStopped("session_timeout")
                    request = step.request
                    while True:
                        prefix_length = min(len(pending), len(request))
                        if pending[:prefix_length] != request[:prefix_length]:
                            self.event("replay_miss", identity, step_index=step_index,
                                       replay_status="miss", reason="unexpected_request_at_step",
                                       observed_request_sha256=hashlib.sha256(pending).hexdigest(),
                                       observed_request_size=len(pending))
                            raise SessionStopped("unexpected_request_at_step")
                        if len(pending) >= len(request):
                            break
                        data = await wait(lambda: reader.read(min(4096, limits.max_received_bytes - received + 1)),
                                          receiving=True)
                        if not data:
                            raise SessionStopped("connection_closed_before_complete_session")
                        received += len(data)
                        if received > limits.max_received_bytes:
                            raise SessionStopped("receive_byte_limit")
                        payload.write(data)
                        payload.flush()
                        pending.extend(data)
                        idle_deadline = loop.time() + limits.idle_timeout_ms / 1000
                    del pending[:len(request)]
                    if step_index == len(self.session.steps) - 1 and pending:
                        raise SessionStopped("trailing_bytes_after_final_request")
                    fields = {"step_index": step_index, "exchange_id": f"{identity['connection_id']}:{step_index}",
                              "request_sha256": hashlib.sha256(request).hexdigest(), "request_size": len(request),
                              "response_sha256": hashlib.sha256(step.response).hexdigest(),
                              "response_size": len(step.response), "response_origin": "replay",
                              "response_prepared": True, "replay_status": "hit"}
                    self.event("replay_response_prepared", identity, **fields)
                    if step.delay_ms:
                        remaining = deadline - loop.time()
                        if remaining <= 0:
                            raise SessionStopped("session_timeout")
                        try:
                            async with asyncio.timeout(remaining):
                                await asyncio.sleep(step.delay_ms / 1000)
                        except TimeoutError as exc:
                            raise SessionStopped("session_timeout") from exc
                    if sent + len(step.response) > limits.max_sent_bytes:
                        raise SessionStopped("send_byte_limit")
                    if loop.time() >= deadline:
                        raise SessionStopped("session_timeout")
                    if step.response:
                        try:
                            writer.write(step.response)
                            await wait(writer.drain)
                        except (ConnectionError, OSError, SessionStopped, asyncio.CancelledError):
                            self.event("network_response_failed", identity, **fields, source_event="replay_hit")
                            raise
                    sent += len(step.response)
                    self.event("replay_hit", identity, **fields, response_sent=bool(step.response))
                    completed_steps += 1
                    idle_deadline = loop.time() + limits.idle_timeout_ms / 1000
            self.event("session_complete", identity, completed_steps=completed_steps,
                       bytes_received=received, bytes_sent=sent, semantic_satisfaction="unknown")
        except asyncio.CancelledError:
            if admitted:
                self.event("session_abort", identity, reason="service_shutdown", status="cancelled",
                           completed_steps=completed_steps, step_index=step_index)
            raise
        except (SessionStopped, ConnectionError, OSError) as exc:
            if admitted:
                self.event("session_abort", identity, reason=str(exc), status="failed",
                           completed_steps=completed_steps, step_index=step_index,
                           bytes_received=received, bytes_sent=sent)
        finally:
            writer.close()
            try:
                async with asyncio.timeout(1):
                    await writer.wait_closed()
            except (TimeoutError, ConnectionError, OSError):
                writer.transport.abort()
            finally:
                if admitted:
                    self.active_connections -= 1
                self.tasks.discard(task)
