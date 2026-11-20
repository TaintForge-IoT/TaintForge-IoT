from __future__ import annotations

import asyncio
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import AsyncMock, patch

from taintforge_env.dns_protocol import build_query, canonical_exchange
from taintforge_env.message_transport import MessageServer
from taintforge_env.network_events import normalize_network_event
from taintforge_env.network_policy import NetworkServicePolicy
from taintforge_env.network_replay import MessageReplayService, TCPReplayService
from taintforge_env.network_stub import TCPFakeService
from taintforge_env.observations import ObservationBundle
from taintforge_env.replay_store import ReplayStore
from taintforge_env.report_generator import RunReportGenerator
from taintforge_env.requirement_extractor import RequirementExtractor
from taintforge_env.requirements import RequirementStatus
from tests.test_dns_udp_replay import dns_answer, udp_request


class FailingWriter:
    def get_extra_info(self, name):
        return ("127.0.0.1", 41000)

    def write(self, data):
        pass

    async def drain(self):
        raise OSError("injected send failure")

    def close(self):
        pass

    async def wait_closed(self):
        pass


class NetworkDeliveryTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.listeners = []

    async def asyncTearDown(self):
        for listener in self.listeners:
            listener.close()
        await asyncio.gather(*(listener.wait_closed() for listener in self.listeners))

    def replay(self, *, transport="udp", dns=False, request=b"hello", response=b"world"):
        policy = NetworkServicePolicy(transport, "dns" if dns else "c2", "192.0.2.10",
            53 if dns else 4444, None, "127.0.0.1", 0, "dns" if dns else transport)
        store = ReplayStore(self.root / "store")
        if dns:
            request, response = canonical_exchange(request, response)
        store.add(transport=transport, remote_ip=policy.remote_ip, remote_port=policy.remote_port,
            request_bytes=request, response_bytes=response, protocol_hint=policy.protocol_hint)
        cls = MessageReplayService if transport == "udp" or dns else TCPReplayService
        return cls(service=policy, store=store, log_dir=self.root / "logs")

    def events(self):
        return [json.loads(line) for line in (self.root / "logs/network_events.jsonl").read_text().splitlines()]

    def requirement(self):
        requirements = RequirementExtractor().extract(ObservationBundle(
            run_dir=self.root, network_events=tuple(self.events()))).requirements
        self.assertEqual(len(requirements), 1)
        return requirements[0]

    async def test_real_udp_delivery_and_zero_length_reply_are_observable(self):
        replay = self.replay(request=b"", response=b"")
        server = await replay.start()
        self.listeners.append(server)
        self.assertEqual(await udp_request(server.sockets[0].getsockname()[1], b""), b"")
        self.assertEqual(self.requirement().status, RequirementStatus.PROVIDED)
        self.assertEqual([event["event"] for event in self.events()], ["replay_hit", "network_response_sent"])

    async def test_controlled_tcp_reply_has_delivery_and_payload_evidence(self):
        policy = NetworkServicePolicy("tcp", "c2", "192.0.2.10", 4444, None, "127.0.0.1", 0, "text")
        server = await TCPFakeService(policy, self.root / "logs").start()
        self.listeners.append(server)
        reader, writer = await asyncio.open_connection("127.0.0.1", server.sockets[0].getsockname()[1])
        try:
            writer.write(b"hello")
            await writer.drain()
            self.assertEqual(await asyncio.wait_for(reader.readline(), 2), b"OK\n")
            self.assertEqual(self.requirement().status, RequirementStatus.PROVIDED)
            response = next(e for e in self.events() if e["event"] == "tcp_response")
            self.assertTrue(response["response_sent"])
            self.assertEqual(len(response["request_sha256"]), 64)
            self.assertEqual(len(response["response_sha256"]), 64)
        finally:
            writer.close()
            await writer.wait_closed()
            await asyncio.sleep(0)

    async def test_udp_send_failure_is_logged_and_remains_unmet(self):
        replay = self.replay()
        server = await replay.start()
        self.listeners.append(server)
        loop = asyncio.get_running_loop()
        with patch.object(loop, "sock_sendto", new=AsyncMock(side_effect=OSError("injected send failure"))):
            await server._udp(b"hello", ("127.0.0.1", 41000))
        self.assertEqual(self.requirement().status, RequirementStatus.UNMET)
        self.assertEqual(dict(self.requirement().details)["response_observed"], "false")
        self.assertEqual(self.events()[-1]["event"], "network_response_failed")

    async def test_cancellation_after_preparation_never_logs_a_sent_response(self):
        replay = self.replay()
        server = await replay.start()
        self.listeners.append(server)
        loop = asyncio.get_running_loop()
        with patch.object(loop, "sock_sendto", new=AsyncMock(side_effect=asyncio.CancelledError)):
            with self.assertRaises(asyncio.CancelledError):
                await server._udp(b"hello", ("127.0.0.1", 41000))
        self.assertEqual(self.events()[-1]["event"], "network_response_failed")
        self.assertFalse(any(normalize_network_event(e)["response_observed"] for e in self.events()))

    async def test_dns_tcp_drain_failure_does_not_satisfy_the_requirement(self):
        query = build_query("c2.example")
        replay = self.replay(transport="tcp", dns=True, request=query, response=dns_answer(query))
        reader = asyncio.StreamReader()
        reader.feed_data(struct.pack("!H", len(query)) + query)
        reader.feed_eof()
        await MessageServer(replay.handle)._tcp(reader, FailingWriter())
        self.assertEqual(self.requirement().status, RequirementStatus.UNMET)
        self.assertEqual(self.events()[-1]["event"], "network_response_failed")

    async def test_tcp_replay_drain_failure_has_no_successful_hit(self):
        replay = self.replay(transport="tcp")
        reader = asyncio.StreamReader()
        reader.feed_data(b"hello")
        reader.feed_eof()
        await replay.handle_client(reader, FailingWriter())
        self.assertEqual(self.requirement().status, RequirementStatus.UNMET)
        self.assertFalse(any(e["event"] == "replay_hit" for e in self.events()))
        self.assertTrue(any(e["event"] == "replay_response_prepared" for e in self.events()))

    async def test_dns_canonical_evidence_is_stable_across_transaction_ids_and_case(self):
        first_query = build_query("c2.example", transaction_id=22)
        replay = self.replay(dns=True, request=first_query, response=dns_answer(first_query))
        server = await replay.start()
        self.listeners.append(server)
        port = server.sockets[0].getsockname()[1]
        await udp_request(port, first_query)
        first = [normalize_network_event(e) for e in self.events()]
        await udp_request(port, build_query("C2.ExAmPlE", transaction_id=65000))
        second = [normalize_network_event(e) for e in self.events()[len(first):]]
        self.assertEqual(first, second)
        self.assertEqual(self.requirement().status, RequirementStatus.PROVIDED)

    async def test_report_counts_prepared_and_sent_dns_replies_separately(self):
        query = build_query("c2.example")
        replay = self.replay(dns=True, request=query, response=dns_answer(query))
        server = await replay.start()
        self.listeners.append(server)
        port = server.sockets[0].getsockname()[1]
        await udp_request(port, query)
        report = RunReportGenerator(self.root).build_network_section({}, self.events())
        self.assertEqual(report["dns_responses_prepared"], 1)
        self.assertEqual(report["dns_responses_sent"], 1)
        self.assertEqual(report["udp_datagrams"], 1)
        self.assertEqual(report["replay_hits"], 1)
        self.assertEqual(report["responses_sent"], 1)
        self.assertEqual(report["semantic_satisfaction"], "unknown")


if __name__ == "__main__":
    unittest.main()
