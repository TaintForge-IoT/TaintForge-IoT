from __future__ import annotations

import asyncio
from dataclasses import asdict
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from taintforge_env.network_policy import NetworkPolicy, load_network_policy
from taintforge_env.network_runtime import (NetworkRuntimeOwner, NetworkRuntimeClient,
    NetworkRuntimeLimits, NetworkRuntimeError, _CURRENT, network_open, network_write)
from taintforge_env.network_runtime_transport import start_server


PROJECT = Path(__file__).resolve().parents[1]


class NetworkBudgetTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.owners = []

    def tearDown(self):
        for owner in self.owners:
            owner.close()

    def owner(self, **limits):
        owner = NetworkRuntimeOwner(self.root / f"control-{len(self.owners)}", self.root / "logs",
            attempt_id=f"attempt-{len(self.owners)}", limits=NetworkRuntimeLimits.parse(limits))
        self.owners.append(owner)
        return owner

    def test_limits_validate_types_unknown_fields_and_hard_bounds(self):
        for values in ({"max_received_bytes": True}, {"max_sent_bytes": "1"}, {"max_connections": 0},
                       {"max_log_bytes": 33 * 1024**2}, {"max_pending": 1.5}, {"command": "id"}):
            with self.subTest(values=values), self.assertRaises(ValueError):
                NetworkRuntimeLimits.parse(values)

    def test_policy_round_trip_includes_runtime_limits(self):
        path = self.root / "policy.json"
        path.write_text(json.dumps(NetworkPolicy(runtime_limits={"max_connections": 2}).to_dict()))
        loaded = load_network_policy(path)
        self.assertEqual(loaded.runtime_limits["max_connections"], 2)
        self.assertEqual(NetworkRuntimeLimits.parse(loaded.runtime_limits).max_received_bytes, 16 * 1024**2)

    def test_two_clients_share_the_same_send_budget(self):
        owner = self.owner(max_sent_bytes=8)
        first, second = owner.client(), owner.client()
        first.call("send", size=5)
        with self.assertRaisesRegex(NetworkRuntimeError, "send_budget"):
            second.call("send", size=4)
        self.assertEqual(owner.snapshot()["budget_usage"]["sent_bytes_reserved"], 5)
        self.assertEqual(owner.snapshot()["termination_reason"], "network_send_budget_exceeded")

    def test_client_cannot_change_limits_even_with_a_recomputed_descriptor_hash(self):
        owner = self.owner(max_sent_bytes=8)
        raw = json.loads(owner.client_path.read_text())
        raw["limits"]["max_sent_bytes"] = 1000
        raw["limits_sha256"] = NetworkRuntimeLimits.parse(raw["limits"]).sha256
        altered = self.root / "altered.json"
        altered.write_text(json.dumps(raw))
        client = NetworkRuntimeClient(altered)
        with self.assertRaisesRegex(NetworkRuntimeError, "limits binding"):
            client.call("send", size=9)
        self.assertEqual(owner.snapshot()["budget_usage"]["sent_bytes_reserved"], 0)

    def test_udp_and_dns_tcp_share_the_message_count(self):
        owner = self.owner(max_messages=2)
        client = owner.client()
        lease = client.call("slot", kind="message")
        client.call("release", lease=lease)
        client.call("message")
        with self.assertRaisesRegex(NetworkRuntimeError, "message_budget"):
            client.call("message")
        self.assertEqual(owner.snapshot()["budget_usage"]["messages"], 2)

    def test_receive_reservations_and_commits_are_exact(self):
        owner = self.owner(max_received_bytes=10)
        client = owner.client()
        allocation = client.call("receive", size=8, exact=True)
        client.call("release", lease=allocation["lease"], used=3)
        usage = owner.snapshot()["budget_usage"]
        self.assertEqual(usage["received_bytes"], 3)
        self.assertEqual(usage["received_reserved"], 0)

    def test_concurrent_slots_and_total_connection_limit(self):
        owner = self.owner(max_connections=1, max_total_connections=3)
        client = owner.client()
        lease = client.call("slot", kind="tcp")
        self.assertIsNone(client.call("slot", kind="tcp"))
        client.call("release", lease=lease)
        lease = client.call("slot", kind="tcp")
        client.call("release", lease=lease)
        with self.assertRaisesRegex(NetworkRuntimeError, "connection_budget"):
            client.call("slot", kind="tcp")
        self.assertEqual(owner.snapshot()["budget_usage"]["peak_connections"], 1)

    def test_udp_jobs_and_messages_have_a_global_limit(self):
        owner = self.owner(max_pending=1, max_messages=2)
        client = owner.client()
        lease = client.call("slot", kind="message")
        self.assertIsNone(client.call("slot", kind="message"))
        client.call("release", lease=lease)
        with self.assertRaisesRegex(NetworkRuntimeError, "message_budget"):
            client.call("slot", kind="message")

    def test_log_budget_preserves_finalization_reserve(self):
        owner = self.owner(max_log_bytes=4096)
        client = owner.client()
        path = self.root / "logs/payload.bin"
        token = _CURRENT.set(client)
        try:
            network_write(path, b"x" * owner.producer_limit)
            with self.assertRaisesRegex(NetworkRuntimeError, "log_budget"):
                network_write(self.root / "logs/extra.bin", b"x")
            with network_open(self.root / "logs/aggregate.jsonl", "wb", finalizing=True) as stream:
                stream.write(b"{}\n")
        finally:
            _CURRENT.reset(token)
        status = owner.close()
        self.assertTrue(owner.status_path.is_file())
        self.assertLess(status["budget_usage"]["log_bytes_reserved"], 4096)
        self.assertFalse(status["evidence_complete"])

    def test_log_file_count_is_bounded(self):
        owner = self.owner(max_log_files=1)
        client = owner.client()
        token = _CURRENT.set(client)
        try:
            network_write(self.root / "logs/one", b"")
            with self.assertRaisesRegex(NetworkRuntimeError, "log_file_budget"):
                network_write(self.root / "logs/two", b"")
        finally:
            _CURRENT.reset(token)

    def test_short_writes_do_not_truncate_the_payload(self):
        owner = self.owner()
        token = _CURRENT.set(owner.client())
        original = os.write
        try:
            with patch("taintforge_env.network_runtime.os.write", side_effect=lambda fd, data: original(fd, data[:2])):
                network_write(self.root / "logs/payload", b"abcdef")
        finally:
            _CURRENT.reset(token)
        self.assertEqual((self.root / "logs/payload").read_bytes(), b"abcdef")
        self.assertEqual(owner.snapshot()["budget_usage"]["log_bytes_reserved"], 6)

    def test_writer_refuses_escape_symlink_and_fifo(self):
        owner = self.owner()
        token = _CURRENT.set(owner.client())
        try:
            with self.assertRaises(NetworkRuntimeError):
                network_write(self.root / "outside", b"x")
            (self.root / "logs/link").symlink_to(self.root / "outside")
            with self.assertRaises(NetworkRuntimeError):
                network_write(self.root / "logs/link", b"x")
            os.mkfifo(self.root / "logs/fifo")
            with self.assertRaises((OSError, NetworkRuntimeError)):
                network_write(self.root / "logs/fifo", b"x")
        finally:
            _CURRENT.reset(token)

    def test_separate_processes_cannot_multiply_the_budget(self):
        owner = self.owner(max_sent_bytes=100)
        code = '''from taintforge_env.network_runtime import NetworkRuntimeClient, NetworkRuntimeError
import sys
c=NetworkRuntimeClient(sys.argv[1])
for _ in range(100):
    try:c.call("send",size=1)
    except NetworkRuntimeError:break
'''
        children = [subprocess.Popen([sys.executable, "-c", code, str(owner.client_path)], cwd=PROJECT,
                                    env={**os.environ, "PYTHONPATH": str(PROJECT)}) for _ in range(3)]
        for process in children:
            self.assertEqual(process.wait(timeout=10), 0)
        self.assertEqual(owner.snapshot()["budget_usage"]["sent_bytes_reserved"], 100)

    def test_lost_owner_identity_is_rejected(self):
        owner = self.owner()
        client = owner.client()
        client.descriptor = {**client.descriptor, "owner_start": "0"}
        with self.assertRaisesRegex(NetworkRuntimeError, "owner_lost"):
            client.call("send", size=1)

    def test_close_is_idempotent_and_leaves_no_owner_thread(self):
        owner = self.owner()
        first = owner.close()
        self.assertEqual(owner.close(), first)
        self.assertFalse(owner.thread.is_alive())
        self.assertFalse(owner.directory.exists())


class NetworkTransportBudgetTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.owner = NetworkRuntimeOwner(self.root / "control", self.root / "logs", attempt_id="transport",
            limits=NetworkRuntimeLimits(max_received_bytes=16, max_sent_bytes=16, max_connections=2))
        self.token = _CURRENT.set(self.owner.client())
        self.listeners, self.writers = [], []

    async def asyncTearDown(self):
        for listener in self.listeners:
            listener.close()
        await asyncio.gather(*(listener.wait_closed() for listener in self.listeners))
        for writer in self.writers:
            writer.close()
        await asyncio.gather(*(writer.wait_closed() for writer in self.writers), return_exceptions=True)
        _CURRENT.reset(self.token)
        self.owner.close()

    async def listen(self, handler):
        listener = await start_server(handler, "127.0.0.1", 0)
        self.listeners.append(listener)
        return listener.sockets[0].getsockname()[1]

    async def connect(self, port):
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        self.writers.append(writer)
        return reader, writer

    async def test_two_services_share_input_and_output_quota(self):
        async def echo(reader, writer):
            writer.write(await reader.read(12))
            await writer.drain()
        first, second = await self.listen(echo), await self.listen(echo)
        reader, writer = await self.connect(first)
        writer.write(b"abcdefghijkl")
        await writer.drain()
        self.assertEqual(await reader.read(), b"abcdefghijkl")
        reader, writer = await self.connect(second)
        writer.write(b"12345")
        await writer.drain()
        self.assertEqual(await reader.read(), b"")
        self.assertEqual(self.owner.snapshot()["termination_reason"], "network_receive_budget_exceeded")

    async def test_admission_limits_connections_before_creating_handler_tasks(self):
        async def waiting(reader, writer):
            await reader.read(1)
        port = await self.listen(waiting)
        await self.connect(port)
        await self.connect(port)
        reader, _ = await self.connect(port)
        self.assertEqual(await reader.read(), b"")
        snapshot = self.owner.snapshot()
        self.assertEqual(snapshot["budget_usage"]["active_connections"], 2)
        self.assertEqual(snapshot["budget_usage"]["rejected_connections"], 1)


class BudgetedRecordingTests(unittest.IsolatedAsyncioTestCase):
    async def test_recording_charges_both_relay_legs_and_blocks_over_budget_reply(self):
        from taintforge_env.c2_record_broker import C2RecordBroker
        from taintforge_env.c2_record_policy import parse_c2_record_policy
        async def upstream(reader, writer):
            self.assertEqual(await reader.read(5), b"hello")
            writer.write(b"world")
            await writer.drain()
            writer.close()
            await writer.wait_closed()
        server = await asyncio.start_server(upstream, "127.0.0.1", 0)
        try:
            for limit in (100, 9):
                with tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    owner = NetworkRuntimeOwner(root / "control", root / "logs", attempt_id="record",
                        limits=NetworkRuntimeLimits.parse({"max_received_bytes": limit}))
                    token = _CURRENT.set(owner.client())
                    policy = parse_c2_record_policy({"schema_version": 1, "mode": "brokered_record",
                        "capture_kind": "local_test", "default_action": "deny", "listen_port": 41000,
                        "target": {"original_ip": "192.0.2.10", "original_port": 41000,
                            "upstream_ip": "127.0.0.1", "upstream_port": server.sockets[0].getsockname()[1]},
                        "limits": {"max_connections": 1, "connect_timeout_seconds": 1,
                            "session_timeout_seconds": 2, "idle_timeout_seconds": 1,
                            "max_client_bytes": 1024, "max_server_bytes": 1024}})
                    broker = C2RecordBroker(policy=policy, bind_ip="127.0.0.1", capture_root=root / "logs/captures",
                                            run_id="net5-record", listen_port_override=0)
                    try:
                        await broker.start()
                        reader, writer = await asyncio.open_connection("127.0.0.1", broker.bound_port)
                        try:
                            writer.write(b"hello")
                            await writer.drain()
                            response = await asyncio.wait_for(reader.read(), 3)
                            self.assertEqual(response, b"world" if limit == 100 else b"")
                        finally:
                            writer.close()
                            await writer.wait_closed()
                    finally:
                        await broker.close()
                        _CURRENT.reset(token)
                        status = owner.close()
                    usage = status["budget_usage"]
                    self.assertEqual(status["cleanup_status"], "cleaned")
                    self.assertEqual(usage["received_bytes"], 10 if limit == 100 else 5)
                    self.assertEqual(usage["sent_bytes_reserved"], 10 if limit == 100 else 5)
                    self.assertEqual(status["termination_reason"], None if limit == 100 else "network_receive_budget_exceeded")
        finally:
            server.close()
            await server.wait_closed()


if __name__ == "__main__":
    unittest.main()
