from __future__ import annotations

import asyncio
import json
import tempfile
import unittest
from pathlib import Path

from taintforge_env.network_policy import NetworkServicePolicy
from taintforge_env.network_replay import TCPReplayService
from taintforge_env.replay_store import ReplayStore


class TCPReplayServiceTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.store = ReplayStore(self.root / "store")
        self.log_dir = self.root / "logs"
        self.service_policy = NetworkServicePolicy(
            service_type="tcp",
            role="c2",
            remote_ip="203.0.113.10",
            remote_port=48101,
            domain=None,
            bind_ip="127.0.0.1",
            bind_port=0,
            protocol_hint="c2_binary",
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    async def _start(self) -> tuple[asyncio.AbstractServer, int]:
        service = TCPReplayService(
            service=self.service_policy,
            store=self.store,
            log_dir=self.log_dir,
        )
        server = await service.start()
        assert server.sockets
        port = int(server.sockets[0].getsockname()[1])
        return server, port

    async def test_segmented_exact_request_is_replayed(self) -> None:
        entry = self.store.add(
            transport="tcp",
            remote_ip="203.0.113.10",
            remote_port=48101,
            request_bytes=b"hello",
            response_bytes=b"world",
            protocol_hint="c2_binary",
        )
        server, port = await self._start()
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            writer.write(b"he")
            await writer.drain()
            await asyncio.sleep(0.01)
            writer.write(b"llo")
            await writer.drain()
            self.assertEqual(await reader.readexactly(5), b"world")
            self.assertEqual(await reader.read(), b"")
            writer.close()
            await writer.wait_closed()
        finally:
            server.close()
            await server.wait_closed()

        events = self._events()
        hit = next(item for item in events if item["event"] == "replay_hit")
        self.assertEqual(hit["entry_id"], entry.entry_id)
        self.assertEqual(hit["request_sha256"], entry.request.payload_sha256)

    async def test_unknown_request_fails_closed_without_response(self) -> None:
        self.store.add(
            transport="tcp",
            remote_ip="203.0.113.10",
            remote_port=48101,
            request_bytes=b"known",
            response_bytes=b"response",
            protocol_hint="c2_binary",
        )
        server, port = await self._start()
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            writer.write(b"unknown")
            await writer.drain()
            self.assertEqual(await reader.read(), b"")
            writer.close()
            await writer.wait_closed()
        finally:
            server.close()
            await server.wait_closed()

        miss = next(
            item for item in self._events() if item["event"] == "replay_miss"
        )
        self.assertEqual(miss["reason"], "no_known_request_prefix")
        self.assertEqual(miss["observed_request_size"], len(b"unknown"))

    async def test_keep_open_supports_two_pipelined_exchanges(self) -> None:
        self.store.add(
            transport="tcp",
            remote_ip="203.0.113.10",
            remote_port=48101,
            request_bytes=b"one",
            response_bytes=b"1",
            protocol_hint="c2_binary",
            close_after_send=False,
        )
        self.store.add(
            transport="tcp",
            remote_ip="203.0.113.10",
            remote_port=48101,
            request_bytes=b"two",
            response_bytes=b"2",
            protocol_hint="c2_binary",
        )
        server, port = await self._start()
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            writer.write(b"onetwo")
            await writer.drain()
            self.assertEqual(await reader.readexactly(2), b"12")
            self.assertEqual(await reader.read(), b"")
            writer.close()
            await writer.wait_closed()
        finally:
            server.close()
            await server.wait_closed()

        hits = [
            item for item in self._events() if item["event"] == "replay_hit"
        ]
        self.assertEqual(len(hits), 2)

    def _events(self) -> list[dict]:
        path = self.log_dir / "network_events.jsonl"
        return [
            json.loads(line)
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]


if __name__ == "__main__":
    unittest.main()
