from __future__ import annotations

import asyncio
import json
import tempfile
import unittest
from pathlib import Path

from taintforge_env.c2_record_broker import C2RecordBroker
from taintforge_env.c2_record_policy import parse_c2_record_policy
from taintforge_env.observations import ObservationBundle
from taintforge_env.requirement_extractor import RequirementExtractor
from taintforge_env.requirements import RequirementStatus


class C2RecordBrokerTests(unittest.IsolatedAsyncioTestCase):
    async def test_local_relay_and_capture(self) -> None:
        async def mock_handler(reader, writer):
            request = await reader.read(1024)
            self.assertEqual(request, b"hello")
            writer.write(b"world")
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        mock_server = await asyncio.start_server(
            mock_handler,
            "127.0.0.1",
            0,
        )
        upstream_port = mock_server.sockets[0].getsockname()[1]

        policy = parse_c2_record_policy(
            {
                "schema_version": 1,
                "mode": "brokered_record",
                "capture_kind": "local_test",
                "default_action": "deny",
                "listen_port": 41000,
                "target": {
                    "original_ip": "198.51.100.10",
                    "original_port": 48101,
                    "upstream_ip": "127.0.0.1",
                    "upstream_port": upstream_port,
                },
                "limits": {
                    "max_connections": 1,
                    "connect_timeout_seconds": 2,
                    "session_timeout_seconds": 5,
                    "idle_timeout_seconds": 2,
                    "max_client_bytes": 1024,
                    "max_server_bytes": 1024,
                },
            }
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            capture_root = Path(temp_dir) / "captures"
            broker = C2RecordBroker(
                policy=policy,
                bind_ip="127.0.0.1",
                capture_root=capture_root,
                run_id="unit-test",
                listen_port_override=0,
            )
            await broker.start()

            reader, writer = await asyncio.open_connection(
                "127.0.0.1",
                broker.bound_port,
            )
            writer.write(b"hello")
            await writer.drain()
            response = await reader.read(1024)
            self.assertEqual(response, b"world")
            writer.close()
            await writer.wait_closed()

            for _ in range(50):
                session_files = list(capture_root.glob("*/session.json"))
                if session_files:
                    break
                await asyncio.sleep(0.02)

            self.assertEqual(len(session_files), 1)
            summary = json.loads(session_files[0].read_text())
            session_dir = session_files[0].parent
            self.assertEqual(
                (session_dir / "client_to_server.bin").read_bytes(),
                b"hello",
            )
            self.assertEqual(
                (session_dir / "server_to_client.bin").read_bytes(),
                b"world",
            )
            self.assertEqual(summary["client_to_server"]["bytes"], 5)
            self.assertEqual(summary["server_to_client"]["bytes"], 5)

            await broker.close()
            events = [json.loads(line) for line in broker.event_path.read_text().splitlines()]
            finished = next(event for event in events if event["event"] == "broker_session_finished")
            self.assertTrue(finished["response_sent"])
            self.assertEqual(finished["response_size"], 5)
            requirements = RequirementExtractor().extract(ObservationBundle(
                run_dir=Path(temp_dir), network_events=tuple(events))).requirements
            self.assertEqual(len(requirements), 1)
            self.assertEqual(requirements[0].status, RequirementStatus.PROVIDED)

        mock_server.close()
        await mock_server.wait_closed()


if __name__ == "__main__":
    unittest.main()
