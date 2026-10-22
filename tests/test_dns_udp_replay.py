from __future__ import annotations

import asyncio
import json
from pathlib import Path
import socket
import struct
import tempfile
import unittest

from taintforge_env.capture_importer import CaptureImportError, import_capture
from taintforge_env.dns_protocol import (DNSError, build_query, canonical_exchange,
    canonical_query, question, replay_response, validate_response, answer_addresses)
from taintforge_env.dns_emulator import DNSStaticService
from taintforge_env.message_transport import MessageServer
from taintforge_env.network_policy import NetworkPolicy, NetworkServicePolicy
from taintforge_env.network_record import MessageRecordService, record_options
from taintforge_env.network_replay import MessageReplayService, NetworkReplayError, validate_replay_policy
from taintforge_env.replay_store import ReplayStore, sha256_bytes


def dns_answer(query, ip="127.0.0.2", *, rcode=0, truncated=False):
    end = question(query).end
    flags = 0x8180 | rcode | (0x0200 if truncated else 0)
    response = query[:2] + struct.pack("!5H", flags, 1, int(not rcode and not truncated), 0, 0) + query[12:end]
    if not rcode and not truncated:
        response += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton(ip)
    return response


async def udp_request(port, data, *, host="127.0.0.1", timeout=2):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.setblocking(False)
        loop = asyncio.get_running_loop()
        await loop.sock_connect(sock, (host, port))
        await loop.sock_sendto(sock, data, (host, port))
        return await asyncio.wait_for(loop.sock_recv(sock, 65536), timeout)


async def tcp_dns(port, data):
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        # Deliberately split both the length and payload across writes.
        wire = struct.pack("!H", len(data)) + data
        writer.write(wire[:1])
        await writer.drain()
        writer.write(wire[1:5])
        await writer.drain()
        writer.write(wire[5:])
        await writer.drain()
        size = struct.unpack("!H", await asyncio.wait_for(reader.readexactly(2), 2))[0]
        return await asyncio.wait_for(reader.readexactly(size), 2)
    finally:
        writer.close()
        await writer.wait_closed()


class DNSProtocolTests(unittest.TestCase):
    def test_case_id_and_pointer_preserved(self):
        query = build_query("c2.example", transaction_id=10)
        request, response = canonical_exchange(query, dns_answer(query))
        changed = build_query("C2.ExAmPlE", transaction_id=65530)
        result = replay_response(changed, request, response)
        self.assertEqual(result[:2], changed[:2])
        self.assertEqual(result[12:question(changed).end], changed[12:question(changed).end])
        self.assertEqual(validate_response(changed, result)["records"][0]["address"], "127.0.0.2")

    def test_significant_flags_are_not_erased(self):
        query = build_query("c2.example")
        changed = query[:2] + b"\0\0" + query[4:]
        self.assertNotEqual(canonical_query(query), canonical_query(changed))

    def test_bad_packets_and_wrong_reply_rejected(self):
        query = build_query("c2.example")
        for data in (b"", query[:-1], query + b"x", query[:12] + b"\xc0\x0c\0\1\0\1"):
            with self.subTest(packet=data):
                with self.assertRaises(DNSError):
                    canonical_query(data)
        with self.assertRaises(DNSError):
            validate_response(query, dns_answer(build_query("other.example")))
        with self.assertRaises(DNSError):
            validate_response(query, b"\0\2" + dns_answer(query)[2:])

    def test_negative_and_truncated_responses(self):
        query = build_query("absent.example")
        self.assertEqual(validate_response(query, dns_answer(query, rcode=3))["rcode"], 3)
        self.assertTrue(validate_response(query, dns_answer(query, truncated=True))["truncated"])

    def test_error_and_truncation_do_not_bind_a_domain(self):
        query = build_query("c2.example")
        response = dns_answer(query)
        report = validate_response(query, response)
        self.assertEqual(answer_addresses([report], "c2.example"), {"127.0.0.2"})
        for flags in (0x8182, 0x8380):
            changed = response[:2] + struct.pack("!H", flags) + response[4:]
            self.assertFalse(answer_addresses([validate_response(query, changed)], "c2.example"))


class MessageRoundTripTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.listeners = []
        self.options = record_options(NetworkPolicy(recording={"capture_kind": "local_test", "run_id": "test",
                                     "timeout_seconds": 0.15, "quiet_seconds": 0.01}))

    async def asyncTearDown(self):
        for listener in self.listeners:
            listener.close()
        await asyncio.gather(*(listener.wait_closed() for listener in self.listeners))

    async def start(self, handler, transport="udp"):
        listener = await MessageServer(handler).start("127.0.0.1", 0, transport)
        self.listeners.append(listener)
        return listener

    async def scenario(self, *, dns=False, transport="udp", request=b"hello", response=b"world"):
        calls = 0
        async def upstream(data, peer):
            nonlocal calls
            calls += 1
            self.assertEqual(data, request)
            return dns_answer(data) if dns else response
        source = await self.start(upstream, transport)
        service = NetworkServicePolicy(transport, "dns" if dns else "c2", "198.51.100.53" if dns else "198.51.100.10",
            53 if dns else 48102, None, "127.0.0.1", 0, "dns" if dns else "udp",
            upstream_ip="127.0.0.1", upstream_port=source.sockets[0].getsockname()[1])
        recorder = await MessageRecordService(service=service, options=self.options, log_dir=self.root / "record").start()
        self.listeners.append(recorder)
        exchange = tcp_dns if transport == "tcp" else udp_request
        captured = await exchange(recorder.sockets[0].getsockname()[1], request)
        source.close()
        await source.wait_closed()
        recorder.close()
        await recorder.wait_closed()
        capture = next((self.root / "record/captures").iterdir())
        store = ReplayStore(self.root / "store")
        receipt = import_capture(capture, store)
        self.assertTrue(receipt.created)
        before = store.validate()
        self.assertFalse(import_capture(capture, store).created)
        replay = await MessageReplayService(service=service, store=store, log_dir=self.root / "replay").start()
        self.listeners.append(replay)
        changed = build_query("C2.Example", transaction_id=40000) if dns else request
        result = await exchange(replay.sockets[0].getsockname()[1], changed)
        if dns:
            self.assertEqual(result[:2], changed[:2])
            self.assertEqual(validate_response(changed, result)["records"][0]["address"], "127.0.0.2")
        else:
            self.assertEqual(result, captured)
        self.assertEqual(calls, 1)
        self.assertEqual(store.validate(), before)
        (capture / "response.bin").write_bytes(b"damaged")
        with self.assertRaises(CaptureImportError):
            import_capture(capture, store)
        self.assertEqual(store.validate(), before)
        return replay, store, service

    async def test_udp_record_import_replay_and_miss(self):
        replay, _, _ = await self.scenario()
        with self.assertRaises(TimeoutError):
            await udp_request(replay.sockets[0].getsockname()[1], b"unknown", timeout=0.05)

    async def test_empty_udp_datagrams(self):
        await self.scenario(request=b"", response=b"")

    async def test_dns_udp_and_unknown_name(self):
        replay, store, service = await self.scenario(dns=True, request=build_query("c2.example"))
        query = build_query("unknown.example", transaction_id=100)
        answer = await udp_request(replay.sockets[0].getsockname()[1], query)
        self.assertEqual(validate_response(query, answer)["rcode"], 2)
        bound = NetworkServicePolicy("udp", "c2", "127.0.0.2", 48102, "c2.example", "127.0.0.1", 12345, "udp")
        store.add(transport="udp", remote_ip=bound.remote_ip, remote_port=bound.remote_port,
                  protocol_hint="udp", request_bytes=b"hello", response_bytes=b"world")
        policy = NetworkPolicy(services=[service, bound])
        validate_replay_policy(policy=policy, replay_store=store)
        bound.remote_ip = "127.0.0.3"
        store.add(transport="udp", remote_ip=bound.remote_ip, remote_port=bound.remote_port,
                  protocol_hint="udp", request_bytes=b"hello", response_bytes=b"world")
        with self.assertRaisesRegex(NetworkReplayError, "does not bind"):
            validate_replay_policy(policy=policy, replay_store=store)

    async def test_dns_tcp_framing(self):
        await self.scenario(dns=True, transport="tcp", request=build_query("c2.example"))

    async def test_timeout_capture_cannot_be_imported(self):
        async def silent(data, peer):
            return None
        source = await self.start(silent)
        service = NetworkServicePolicy("udp", "c2", "198.51.100.10", 48102, None, "127.0.0.1", 0,
            upstream_ip="127.0.0.1", upstream_port=source.sockets[0].getsockname()[1])
        recorder = await MessageRecordService(service=service, options=self.options, log_dir=self.root / "record").start()
        self.listeners.append(recorder)
        with self.assertRaises(TimeoutError):
            await udp_request(recorder.sockets[0].getsockname()[1], b"hello", timeout=0.3)
        capture = next((self.root / "record/captures").iterdir())
        store = ReplayStore(self.root / "store")
        with self.assertRaisesRegex(CaptureImportError, "incomplete"):
            import_capture(capture, store)
        self.assertFalse(store.root.exists())

    async def test_multiple_response_datagrams_are_not_silently_merged(self):
        source = None
        async def multiple(data, peer):
            await asyncio.get_running_loop().sock_sendto(source.udp_socket, b"first", peer)
            return b"second"
        source = await self.start(multiple)
        service = NetworkServicePolicy("udp", "c2", "198.51.100.10", 48102, None, "127.0.0.1", 0,
            upstream_ip="127.0.0.1", upstream_port=source.sockets[0].getsockname()[1])
        recorder = await MessageRecordService(service=service, options=self.options, log_dir=self.root / "record").start()
        self.listeners.append(recorder)
        with self.assertRaises(TimeoutError):
            await udp_request(recorder.sockets[0].getsockname()[1], b"hello", timeout=0.3)
        capture = next((self.root / "record/captures").iterdir())
        summary = json.loads((capture / "session.json").read_text())
        self.assertIn("multiple upstream datagrams", summary["reason"])
        with self.assertRaises(CaptureImportError):
            import_capture(capture, ReplayStore(self.root / "store"))

    async def test_concurrent_udp_replies_are_not_crossed(self):
        async def reverse(data, peer):
            await asyncio.sleep(0.02 if data == b"slow" else 0)
            return data[::-1]
        source = await self.start(reverse)
        service = NetworkServicePolicy("udp", "c2", "198.51.100.10", 48102, None, "127.0.0.1", 0,
            upstream_ip="127.0.0.1", upstream_port=source.sockets[0].getsockname()[1])
        recorder = await MessageRecordService(service=service, options=self.options, log_dir=self.root / "record").start()
        self.listeners.append(recorder)
        responses = await asyncio.gather(*(udp_request(recorder.sockets[0].getsockname()[1], request)
                                          for request in (b"slow", b"fast", b"third")))
        self.assertEqual(responses, [b"wols", b"tsaf", b"driht"])
        self.assertEqual(len(list((self.root / "record/captures").iterdir())), 3)

    async def test_synthetic_dns_uses_explicit_records(self):
        service = NetworkServicePolicy("udp", "dns", "127.0.0.1", 53, None, "127.0.0.1", 0,
            "dns", dns_records={"c2.example": ["192.0.2.7"]})
        server = await DNSStaticService(service, self.root / "synthetic").start()
        self.listeners.append(server)
        query = build_query("c2.example", transaction_id=22)
        reply = await udp_request(server.sockets[0].getsockname()[1], query)
        self.assertEqual(validate_response(query, reply)["records"][0]["address"], "192.0.2.7")
        unknown = build_query("absent.example", transaction_id=23)
        reply = await udp_request(server.sockets[0].getsockname()[1], unknown)
        self.assertEqual(validate_response(unknown, reply)["rcode"], 3)
        events = [json.loads(line) for line in (self.root / "synthetic/network_events.jsonl").read_text().splitlines()]
        self.assertTrue(all(e["response_origin"] == "synthetic" for e in events))


if __name__ == "__main__":
    unittest.main()
