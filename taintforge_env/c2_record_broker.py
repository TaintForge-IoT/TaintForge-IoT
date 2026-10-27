from __future__ import annotations

import asyncio
import hashlib
import json
import os
import secrets
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .c2_record_policy import C2RecordPolicy
from .event_logger import append_jsonl_event


CHUNK_SIZE = 65536


class C2RecordBrokerError(RuntimeError):
    pass


class DirectionLimitExceeded(C2RecordBrokerError):
    def __init__(self, direction: str, limit: int) -> None:
        super().__init__(f"{direction} byte limit exceeded: {limit}")
        self.direction = direction
        self.limit = limit


@dataclass(slots=True)
class DirectionState:
    direction: str
    limit: int
    aggregate_path: Path
    total: int = 0
    chunks: int = 0
    digest: hashlib._Hash | None = None

    def __post_init__(self) -> None:
        self.digest = hashlib.sha256()


class C2RecordBroker:
    def __init__(
        self,
        *,
        policy: C2RecordPolicy,
        bind_ip: str,
        capture_root: str | Path,
        run_id: str,
        event_path: str | Path | None = None,
        listen_port_override: int | None = None,
        protocol_hint: str | None = None,
    ) -> None:
        self.policy = policy
        self.bind_ip = bind_ip
        self.capture_root = Path(capture_root)
        self.run_id = run_id
        self.protocol_hint = protocol_hint
        self.event_path = (
            Path(event_path)
            if event_path is not None
            else self.capture_root / "broker_events.jsonl"
        )
        self.listen_port = (
            policy.listen_port
            if listen_port_override is None
            else listen_port_override
        )

        self.server: asyncio.AbstractServer | None = None
        self.accepted_connections = 0
        self.active_sessions: set[asyncio.Task] = set()
        self.bound_port: int | None = None

    async def start(self) -> None:
        self.capture_root.mkdir(parents=True, exist_ok=True)
        os.chmod(self.capture_root, 0o700)

        self.server = await asyncio.start_server(
            self._accept_client,
            self.bind_ip,
            self.listen_port,
            start_serving=True,
        )

        sockets = self.server.sockets or []
        if not sockets:
            raise C2RecordBrokerError("broker has no listening socket")

        self.bound_port = int(sockets[0].getsockname()[1])
        append_jsonl_event(
            self.event_path,
            {
                "event": "broker_started",
                "listener_type": "brokered_record",
                "bind_ip": self.bind_ip,
                "bind_port": self.bound_port,
                "capture_kind": self.policy.capture_kind,
                "original_remote_ip": self.policy.target.original_ip,
                "original_remote_port": self.policy.target.original_port,
                "upstream_ip": self.policy.target.upstream_ip,
                "upstream_port": self.policy.target.upstream_port,
                "max_connections": self.policy.limits.max_connections,
            },
        )

    async def serve_forever(self) -> None:
        if self.server is None:
            await self.start()
        assert self.server is not None
        async with self.server:
            await self.server.serve_forever()

    async def close(self) -> None:
        if self.server is not None:
            self.server.close()
            await self.server.wait_closed()
            self.server = None

        tasks = list(self.active_sessions)
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _accept_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        if self.accepted_connections >= self.policy.limits.max_connections:
            append_jsonl_event(
                self.event_path,
                {
                    "event": "broker_connection_rejected",
                    "listener_type": "brokered_record",
                    "reason": "max_connections_reached",
                    "max_connections": self.policy.limits.max_connections,
                },
            )
            writer.close()
            await writer.wait_closed()
            return

        self.accepted_connections += 1
        task = asyncio.current_task()
        if task is not None:
            self.active_sessions.add(task)

        try:
            await self._handle_session(reader, writer)
        finally:
            if task is not None:
                self.active_sessions.discard(task)

    async def _handle_session(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
    ) -> None:
        session_id = (
            datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
            + "-"
            + secrets.token_hex(4)
        )
        session_dir = self.capture_root / session_id
        chunks_dir = session_dir / "chunks"
        chunks_dir.mkdir(parents=True, exist_ok=False)
        os.chmod(session_dir, 0o700)
        os.chmod(chunks_dir, 0o700)

        events_path = session_dir / "events.jsonl"
        client_path = session_dir / "client_to_server.bin"
        server_path = session_dir / "server_to_client.bin"
        summary_path = session_dir / "session.json"

        client_state = DirectionState(
            direction="client_to_server",
            limit=self.policy.limits.max_client_bytes,
            aggregate_path=client_path,
        )
        server_state = DirectionState(
            direction="server_to_client",
            limit=self.policy.limits.max_server_bytes,
            aggregate_path=server_path,
        )

        peer = client_writer.get_extra_info("peername")
        started_wall = datetime.now(timezone.utc)
        started_monotonic = time.monotonic()
        last_activity = [started_monotonic]
        close_reason = "unknown"
        error_text: str | None = None

        append_jsonl_event(
            events_path,
            {
                "event": "session_started",
                "session_id": session_id,
                "peer": repr(peer),
                "original_remote_ip": self.policy.target.original_ip,
                "original_remote_port": self.policy.target.original_port,
                "upstream_ip": self.policy.target.upstream_ip,
                "upstream_port": self.policy.target.upstream_port,
                "capture_kind": self.policy.capture_kind,
            },
        )
        append_jsonl_event(
            self.event_path,
            {
                "event": "broker_session_started",
                "listener_type": "brokered_record",
                "session_id": session_id,
                "original_remote_ip": self.policy.target.original_ip,
                "original_remote_port": self.policy.target.original_port,
            },
        )

        upstream_writer: asyncio.StreamWriter | None = None
        try:
            upstream_reader, upstream_writer = await asyncio.wait_for(
                asyncio.open_connection(
                    self.policy.target.upstream_ip,
                    self.policy.target.upstream_port,
                ),
                timeout=self.policy.limits.connect_timeout_seconds,
            )

            append_jsonl_event(
                events_path,
                {
                    "event": "upstream_connected",
                    "session_id": session_id,
                    "upstream_ip": self.policy.target.upstream_ip,
                    "upstream_port": self.policy.target.upstream_port,
                },
            )

            c2s_task = asyncio.create_task(
                self._pump(
                    session_id=session_id,
                    source=client_reader,
                    destination=upstream_writer,
                    state=client_state,
                    chunks_dir=chunks_dir,
                    events_path=events_path,
                    last_activity=last_activity,
                    started_monotonic=started_monotonic,
                )
            )
            s2c_task = asyncio.create_task(
                self._pump(
                    session_id=session_id,
                    source=upstream_reader,
                    destination=client_writer,
                    state=server_state,
                    chunks_dir=chunks_dir,
                    events_path=events_path,
                    last_activity=last_activity,
                    started_monotonic=started_monotonic,
                )
            )
            monitor_task = asyncio.create_task(
                self._monitor_timeouts(
                    last_activity=last_activity,
                    started_monotonic=started_monotonic,
                )
            )

            tasks = {c2s_task, s2c_task, monitor_task}
            while tasks:
                done, pending = await asyncio.wait(
                    tasks,
                    return_when=asyncio.FIRST_COMPLETED,
                )

                for finished in done:
                    if finished is monitor_task:
                        reason = finished.result()
                        close_reason = reason
                        for pending_task in pending:
                            pending_task.cancel()
                        tasks = set()
                        break

                    try:
                        direction, result = finished.result()
                    except DirectionLimitExceeded as exc:
                        close_reason = f"{exc.direction}_limit_exceeded"
                        for pending_task in pending:
                            pending_task.cancel()
                        tasks = set()
                        break
                    except Exception as exc:
                        close_reason = "relay_error"
                        error_text = f"{type(exc).__name__}: {exc}"
                        for pending_task in pending:
                            pending_task.cancel()
                        tasks = set()
                        break

                    tasks.discard(finished)

                    if direction == "server_to_client" and result == "eof":
                        close_reason = "upstream_closed"
                        for pending_task in pending:
                            pending_task.cancel()
                        tasks = set()
                        break

                    if direction == "client_to_server" and result == "eof":
                        if upstream_writer.can_write_eof():
                            try:
                                upstream_writer.write_eof()
                            except (OSError, RuntimeError):
                                pass
                        if not tasks or tasks == {monitor_task}:
                            close_reason = "client_closed"

            await asyncio.gather(
                c2s_task,
                s2c_task,
                monitor_task,
                return_exceptions=True,
            )

            if close_reason == "unknown":
                close_reason = "completed"

        except asyncio.TimeoutError:
            close_reason = "upstream_connect_timeout"
        except OSError as exc:
            close_reason = "upstream_connect_error"
            error_text = f"{type(exc).__name__}: {exc}"
        finally:
            if upstream_writer is not None:
                upstream_writer.close()
                try:
                    await upstream_writer.wait_closed()
                except OSError:
                    pass

            client_writer.close()
            try:
                await client_writer.wait_closed()
            except OSError:
                pass

            finished_wall = datetime.now(timezone.utc)
            duration = time.monotonic() - started_monotonic

            summary = {
                "schema_version": 1,
                **({"protocol_hint": self.protocol_hint} if self.protocol_hint is not None else {}),
                "run_id": self.run_id,
                "session_id": session_id,
                "capture_kind": self.policy.capture_kind,
                "started_at_utc": started_wall.isoformat(),
                "finished_at_utc": finished_wall.isoformat(),
                "duration_seconds": round(duration, 6),
                "close_reason": close_reason,
                "error": error_text,
                "peer": repr(peer),
                "original_remote_ip": self.policy.target.original_ip,
                "original_remote_port": self.policy.target.original_port,
                "upstream_ip": self.policy.target.upstream_ip,
                "upstream_port": self.policy.target.upstream_port,
                "client_to_server": {
                    "bytes": client_state.total,
                    "chunks": client_state.chunks,
                    "sha256": client_state.digest.hexdigest(),
                    "path": client_path.name,
                },
                "server_to_client": {
                    "bytes": server_state.total,
                    "chunks": server_state.chunks,
                    "sha256": server_state.digest.hexdigest(),
                    "path": server_path.name,
                },
                "limits": {
                    "max_connections": self.policy.limits.max_connections,
                    "connect_timeout_seconds": self.policy.limits.connect_timeout_seconds,
                    "session_timeout_seconds": self.policy.limits.session_timeout_seconds,
                    "idle_timeout_seconds": self.policy.limits.idle_timeout_seconds,
                    "max_client_bytes": self.policy.limits.max_client_bytes,
                    "max_server_bytes": self.policy.limits.max_server_bytes,
                },
            }
            self._atomic_json(summary_path, summary)

            append_jsonl_event(
                events_path,
                {
                    "event": "session_finished",
                    "session_id": session_id,
                    "close_reason": close_reason,
                    "client_bytes": client_state.total,
                    "server_bytes": server_state.total,
                    "error": error_text,
                },
            )
            append_jsonl_event(
                self.event_path,
                {
                    "event": "broker_session_finished",
                    "listener_type": "brokered_record",
                    "session_id": session_id,
                    "original_remote_ip": self.policy.target.original_ip,
                    "original_remote_port": self.policy.target.original_port,
                    "close_reason": close_reason,
                    "client_bytes": client_state.total,
                    "server_bytes": server_state.total,
                },
            )

    async def _pump(
        self,
        *,
        session_id: str,
        source: asyncio.StreamReader,
        destination: asyncio.StreamWriter,
        state: DirectionState,
        chunks_dir: Path,
        events_path: Path,
        last_activity: list[float],
        started_monotonic: float,
    ) -> tuple[str, str]:
        while True:
            data = await source.read(CHUNK_SIZE)
            if not data:
                append_jsonl_event(
                    events_path,
                    {
                        "event": "stream_eof",
                        "session_id": session_id,
                        "direction": state.direction,
                    },
                )
                return state.direction, "eof"

            if state.total + len(data) > state.limit:
                raise DirectionLimitExceeded(state.direction, state.limit)

            state.total += len(data)
            state.chunks += 1
            state.digest.update(data)
            last_activity[0] = time.monotonic()

            self._append_bytes(state.aggregate_path, data)
            chunk_name = f"{state.chunks:06d}_{state.direction}.bin"
            chunk_path = chunks_dir / chunk_name
            chunk_path.write_bytes(data)
            os.chmod(chunk_path, 0o600)

            append_jsonl_event(
                events_path,
                {
                    "event": "stream_chunk",
                    "session_id": session_id,
                    "direction": state.direction,
                    "chunk_index": state.chunks,
                    "size": len(data),
                    "sha256": hashlib.sha256(data).hexdigest(),
                    "elapsed_seconds": round(
                        time.monotonic() - started_monotonic,
                        6,
                    ),
                    "payload_file": f"chunks/{chunk_name}",
                },
            )

            destination.write(data)
            await destination.drain()

    async def _monitor_timeouts(
        self,
        *,
        last_activity: list[float],
        started_monotonic: float,
    ) -> str:
        while True:
            await asyncio.sleep(0.1)
            now = time.monotonic()
            if now - started_monotonic >= self.policy.limits.session_timeout_seconds:
                return "session_timeout"
            if now - last_activity[0] >= self.policy.limits.idle_timeout_seconds:
                return "idle_timeout"

    @staticmethod
    def _append_bytes(path: Path, data: bytes) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(
            path,
            os.O_APPEND | os.O_CREAT | os.O_WRONLY,
            0o600,
        )
        try:
            os.write(fd, data)
        finally:
            os.close(fd)

    @staticmethod
    def _atomic_json(path: Path, value: dict) -> None:
        temp = path.with_suffix(path.suffix + ".tmp")
        temp.write_text(
            json.dumps(value, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        os.chmod(temp, 0o600)
        os.replace(temp, path)
