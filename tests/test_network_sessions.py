from __future__ import annotations

import asyncio
from copy import deepcopy
from dataclasses import replace
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from taintforge_env.network_events import network_flow_key
from taintforge_env.network_policy import CatchAllPolicy, NetworkPolicy, NetworkServicePolicy
from taintforge_env.network_repair import NetworkRepairError, NetworkRepairPolicy
from taintforge_env.network_replay import NetworkReplayError, replay_service, validate_replay_policy
from taintforge_env.replay_session import ReplaySession, ReplaySessionError
from taintforge_env.replay_store import ReplayEntryExistsError, ReplayStore, ReplayStoreValidationError
from taintforge_env.repair_applier import RepairApplier, RepairApplierConfig, RepairApplicationError
from taintforge_env.repair_planner import RepairPlanner
from taintforge_env.report_generator import RunReportGenerator
from tests.test_network_repairs import observed, write


PROJECT = Path(__file__).resolve().parents[1]


def specification(*, host="127.0.0.1", port=4444, limits=None, pairs=None):
    pairs = pairs or [(b"HELLO\n", b"READY\n"), (b"AUTH test\n", b"OK\n"),
                      (b"GET CONFIG\n", b"interval=30\n")]
    return {"schema_version": 1, "transport": "tcp", "remote_ip": host, "remote_port": port,
            "protocol_hint": "net4_test", "framing": "exact_bytes", "limits": limits or {},
            "steps": [{"request_hex": request.hex(), "response_hex": response.hex()}
                      for request, response in pairs]}


def service_for(session, **changes):
    service = NetworkServicePolicy("tcp", "net4_session", session.remote_ip, session.remote_port,
                                   None, "127.0.0.1", 0, session.protocol_hint,
                                   replay_session_id=session.session_id)
    return replace(service, **changes)


class SessionContractTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.store = ReplayStore(self.root / "store")
        self.spec = specification()

    def test_contract_canonical_round_trip(self):
        session = ReplaySession.parse(self.spec)
        self.assertEqual(ReplaySession.parse(session.to_dict()), session)
        self.assertEqual(len(session.session_id), 64)
        self.assertEqual(session.steps[1].request, b"AUTH test\n")

    def test_identity_binds_order_responses_and_limits(self):
        identity = ReplaySession.parse(self.spec).session_id
        for change in ("order", "response", "limit", "endpoint"):
            spec = deepcopy(self.spec)
            if change == "order":
                spec["steps"].reverse()
            elif change == "response":
                spec["steps"][1]["response_hex"] = b"DENIED\n".hex()
            elif change == "limit":
                spec["limits"]["session_timeout_ms"] = 100
            else:
                spec["remote_port"] += 1
            self.assertNotEqual(ReplaySession.parse(spec).session_id, identity)

    def test_commands_unknown_fields_and_non_tcp_are_rejected(self):
        for key, value in [("command", "id"), ("schema_version", True), ("transport", "udp"),
                           ("protocol_hint", "dns"), ("remote_ip", 2130706433),
                           ("remote_ip", "0.0.0.0"), ("remote_ip", "224.0.0.1"),
                           ("remote_ip", "::1"), ("remote_port", True), ("framing", "guess")]:
            with self.subTest(key=key, value=value), self.assertRaises(ReplaySessionError):
                ReplaySession.parse({**self.spec, key: value})

    def test_payload_validation_is_strict(self):
        for key, value in [("request_hex", ""), ("request_hex", "a"), ("request_hex", "AA"),
                           ("request_hex", "00 01"), ("response_hex", False),
                           ("delay_ms", True), ("delay_ms", 60001), ("command", "id")]:
            spec = deepcopy(self.spec)
            spec["steps"][0][key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ReplaySessionError):
                ReplaySession.parse(spec)

    def test_hard_limits_and_boolean_values_are_rejected(self):
        cases = {"max_steps": 33, "max_message_bytes": 65537, "max_received_bytes": 1048577,
                 "max_sent_bytes": 1048577, "idle_timeout_ms": 60001,
                 "session_timeout_ms": 300001, "max_connections": 33, "max_total_connections": 1025}
        for key, value in cases.items():
            for bad in (value, True, 1.5, "1", -1):
                with self.subTest(key=key, value=bad), self.assertRaises(ReplaySessionError):
                    ReplaySession.parse({**self.spec, "limits": {key: bad}})

    def test_transcript_must_fit_its_limits(self):
        for limits in ({"max_steps": 2}, {"max_message_bytes": 2},
                       {"max_received_bytes": 2}, {"max_sent_bytes": 0}, {"unknown": 1}):
            with self.subTest(limits=limits), self.assertRaises(ReplaySessionError):
                ReplaySession.parse({**self.spec, "limits": limits})

    def test_session_store_survives_adding_legacy_exchanges(self):
        session = self.store.add_session(self.spec)
        self.store.add(transport="udp", remote_ip="192.0.2.1", remote_port=1234,
                       request_bytes=b"ping", response_bytes=b"pong")
        self.assertEqual(self.store.load_session(session.session_id), session)
        self.assertEqual(self.store.validate()["sessions"], 1)
        self.assertEqual(self.store.validate()["entries"], 1)

    def test_session_changes_store_identity(self):
        self.store.initialize()
        before = self.store.validate()["store_sha256"]
        self.store.add_session(self.spec)
        self.assertNotEqual(self.store.validate()["store_sha256"], before)

    def test_duplicate_session_addition_is_refused(self):
        self.store.add_session(self.spec)
        before = self.store.index_path.read_bytes()
        with self.assertRaises(ReplayEntryExistsError):
            self.store.add_session(self.spec)
        self.assertEqual(before, self.store.index_path.read_bytes())

    def test_tampered_session_is_rejected(self):
        self.store.add_session(self.spec)
        index = json.loads(self.store.index_path.read_text())
        index["sessions"][0]["steps"][0]["response_hex"] = "00"
        write(self.store.index_path, index)
        with self.assertRaisesRegex(ReplayStoreValidationError, "changed"):
            self.store.validate()

    def test_duplicate_and_malformed_session_records_are_rejected(self):
        self.store.add_session(self.spec)
        original = json.loads(self.store.index_path.read_text())
        for records in ([original["sessions"][0]] * 2, {}, [{}], [original["sessions"][0]] * 129):
            write(self.store.index_path, {**original, "sessions": records})
            with self.subTest(records_type=type(records)), self.assertRaises(ReplayStoreValidationError):
                self.store.validate()

    def test_index_symlinks_duplicate_keys_and_fifo_are_rejected(self):
        self.store.initialize()
        self.store.index_path.write_text('{"schema_version":1,"entries":[],"entries":[]}')
        with self.assertRaises(ReplayStoreValidationError):
            self.store.validate()
        self.store.index_path.unlink()
        os.mkfifo(self.store.index_path)
        with self.assertRaises(ReplayStoreValidationError):
            self.store.validate()
        self.store.index_path.unlink()
        target = self.root / "index"
        write(target, {"schema_version": 1, "entries": []})
        self.store.index_path.symlink_to(target)
        with self.assertRaises(ReplayStoreValidationError):
            self.store.validate()

    def test_service_requires_explicit_matching_selector(self):
        session = self.store.add_session(self.spec)
        service = service_for(session)
        policy = NetworkPolicy(services=[service])
        self.assertEqual(validate_replay_policy(policy=policy, replay_store=self.store)["covered_sessions"], 1)
        for changes in ({"replay_session_id": None}, {"replay_session_id": "0" * 64},
                        {"remote_port": 4445}, {"service_type": "udp"}, {"protocol_hint": None},
                        {"upstream_ip": "192.0.2.1"}, {"remote_port": 4444.0}):
            with self.subTest(changes=changes), self.assertRaises(NetworkReplayError):
                validate_replay_policy(policy=NetworkPolicy(services=[replace(service, **changes)]),
                                       replay_store=self.store)

    def test_cli_add_list_and_validate(self):
        path = self.root / "session.json"
        write(path, self.spec)
        base = [sys.executable, str(PROJECT / "scripts/replay_store.py")]
        added = subprocess.run([*base, "session-add", "--store", str(self.store.root), "--spec", str(path)],
                               check=True, capture_output=True, text=True, cwd=PROJECT)
        listed = subprocess.run([*base, "session-list", "--store", str(self.store.root)],
                                check=True, capture_output=True, text=True, cwd=PROJECT)
        self.assertEqual(json.loads(added.stdout)["session_id"], json.loads(listed.stdout)[0]["session_id"])


class SessionRepairTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.store = ReplayStore(self.root / "store")
        self.session = self.store.add_session(specification(host="192.0.2.10"))
        self.resource = "tcp://192.0.2.10:4444"
        self.raw = {"schema_version": 1, "network_mode": "replay",
                    "replay_store": {"path": str(self.store.root), "sha256": self.store.validate()["store_sha256"]},
                    "rules": [{"resource": self.resource, "provider": "replay", "protocol_hint": "net4_test",
                               "replay_session_id": self.session.session_id}]}
        self.path = self.root / "authorization.json"
        write(self.path, self.raw)
        self.requirements = self.root / "requirements.json"
        observed(self.root, self.resource).save(self.requirements)
        self.plan = self.root / "plan.json"
        self.rootfs = self.root / "rootfs"
        self.rootfs.mkdir()

    def planning(self):
        policy = NetworkRepairPolicy.load(self.path)
        return policy, RepairPlanner(network_repair_policy=policy).plan_file(self.requirements, self.plan)

    def test_session_selection_and_application_use_existing_net3_contract(self):
        policy, plan = self.planning()
        decision = plan.decisions[0]
        self.assertTrue(decision.automatic_allowed)
        selection = dict(decision.parameters)["network_repair"]
        self.assertEqual(selection["replay_session"]["session_id"], self.session.session_id)
        self.assertEqual(selection["replay_session"]["steps"], 3)
        result = RepairApplier(RepairApplierConfig(network_repair_policy=policy)).apply_file(
            plan_path=self.plan, requirements_path=self.requirements, rootfs=self.rootfs,
            out_path=self.root / "application.json")
        self.assertEqual(result.results[0].status.value, "applied")
        self.assertEqual(result.results[0].network_service, selection)
        self.assertEqual(list(self.rootfs.iterdir()), [])

    def test_changed_session_after_planning_is_rejected(self):
        policy, _ = self.planning()
        index = json.loads(self.store.index_path.read_text())
        index["sessions"][0]["limits"]["idle_timeout_ms"] += 1
        write(self.store.index_path, index)
        with self.assertRaises(RepairApplicationError):
            RepairApplier(RepairApplierConfig(network_repair_policy=policy)).apply_file(
                plan_path=self.plan, requirements_path=self.requirements, rootfs=self.rootfs,
                out_path=self.root / "application.json")

    def test_unknown_session_is_review_only(self):
        self.raw["rules"][0]["replay_session_id"] = "0" * 64
        write(self.path, self.raw)
        self.assertFalse(self.planning()[1].decisions[0].automatic_allowed)

    def test_policy_cannot_attach_session_to_udp_or_dns(self):
        for changes in ({"resource": "udp://192.0.2.10:4444"}, {"protocol_hint": "dns"},
                        {"replay_session_id": True}):
            raw = deepcopy(self.raw)
            raw["rules"][0].update(changes)
            write(self.path, raw)
            with self.subTest(changes=changes), self.assertRaises(NetworkRepairError):
                NetworkRepairPolicy.load(self.path)

    def test_delivery_identity_includes_step(self):
        event = {"transport": "tcp", "listener_type": "deterministic_session", "connection_id": 1,
                 "original_remote_ip": "192.0.2.10", "original_remote_port": 4444}
        self.assertNotEqual(network_flow_key({**event, "step_index": 0}),
                            network_flow_key({**event, "step_index": 1}))

    def test_report_does_not_promote_session_completion_to_semantic_success(self):
        event = {"event": "session_complete", "listener_type": "deterministic_session",
                 "replay_session_id": self.session.session_id, "connection_id": 1, "completed_steps": 3}
        report = RunReportGenerator(self.root).build_network_section(
            NetworkPolicy(services=[service_for(self.session)]).to_dict(), [event])
        self.assertEqual(report["session_replay"]["completed"], 1)
        self.assertEqual(report["semantic_satisfaction"], "unknown")
        self.assertEqual(report["session_replay"]["semantic_satisfaction"], "unknown")
        self.assertEqual(len(report["authorized_repair_services"]), 1)

    def test_report_transcript_is_bounded(self):
        events = [{"event": "replay_hit", "listener_type": "deterministic_session",
                   "step_index": index, "connection_id": 1} for index in range(1100)]
        section = RunReportGenerator(self.root).build_network_section({}, events)["session_replay"]
        self.assertEqual(len(section["transcript"]), 1024)
        self.assertTrue(section["transcript_truncated"])

    def backend(self, *, mode="replay", changes=None):
        from taintforge_env.controlled_network_backend import ControlledNetworkBackend, ControlledNetworkConfig
        from tests.test_controlled_network_backend import FakeExecutor, FakeSupervisor, FakePortAllocator
        run = self.root / "run"
        (run / "logs").mkdir(parents=True)
        policy_path = run / "config/network_policy.json"
        write(policy_path, NetworkPolicy(services=[service_for(self.session, **(changes or {}))]).to_dict())
        supervisor = FakeSupervisor()
        backend = ControlledNetworkBackend(ControlledNetworkConfig(PROJECT, run, policy_path, "net4-test", 0,
            responder_mode=mode, replay_store_path=self.store.root if mode == "replay" else None,
            replay_store_expected_sha256=self.store.validate()["store_sha256"] if mode == "replay" else None,
            process_start_grace_seconds=0), executor=FakeExecutor(), process_supervisor=supervisor,
            port_allocator=FakePortAllocator())
        return backend, supervisor

    @patch("taintforge_env.controlled_network_backend.shutil.which", return_value="/usr/bin/tool")
    def test_namespace_backend_retains_session_selector_in_host_mapping(self, _which):
        backend, supervisor = self.backend()
        result = backend.setup()
        try:
            effective = json.loads(result.effective_policy_path.read_text())
            self.assertEqual(result.plan.host_services[0].replay_session_id, self.session.session_id)
            self.assertEqual(effective["services"][0]["replay_session_id"], self.session.session_id)
            self.assertEqual(json.loads(backend.host_policy_path.read_text())["services"][0]["replay_session_id"],
                             self.session.session_id)
            self.assertTrue(all(any(arg.endswith("start_network_replay.py") for arg in process.command)
                                for process in supervisor.started))
            self.assertFalse(result.plan.catch_all_enabled)
        finally:
            backend.cleanup()

    @patch("taintforge_env.controlled_network_backend.shutil.which", return_value="/usr/bin/tool")
    def test_namespace_backend_refuses_wrong_session_before_starting_services(self, _which):
        from taintforge_env.controlled_network_backend import ControlledNetworkError
        backend, supervisor = self.backend(changes={"replay_session_id": "0" * 64})
        with self.assertRaises(ControlledNetworkError):
            backend.setup()
        self.assertEqual(supervisor.started, [])

    @patch("taintforge_env.controlled_network_backend.shutil.which", return_value="/usr/bin/tool")
    def test_namespace_backend_retains_selector_for_loopback_placement(self, _which):
        self.session = self.store.add_session(specification())
        backend, _ = self.backend()
        result = backend.setup()
        try:
            self.assertEqual(result.plan.loopback_services[0].replay_session_id, self.session.session_id)
            policy = json.loads(backend.loopback_policy_path.read_text())
            self.assertEqual(policy["services"][0]["replay_session_id"], self.session.session_id)
        finally:
            backend.cleanup()

    @patch("taintforge_env.controlled_network_backend.shutil.which", return_value="/usr/bin/tool")
    def test_session_policy_cannot_silently_use_emulated_backend(self, _which):
        from taintforge_env.controlled_network_backend import ControlledNetworkError
        backend, supervisor = self.backend(mode="emulated")
        with self.assertRaises(ControlledNetworkError):
            backend.setup()
        self.assertEqual(supervisor.started, [])


class SessionRuntimeTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.listeners, self.writers = [], []

    async def asyncTearDown(self):
        for listener in self.listeners:
            listener.close()
        for writer in self.writers:
            writer.close()
        await asyncio.gather(*(listener.wait_closed() for listener in self.listeners))
        await asyncio.gather(*(writer.wait_closed() for writer in self.writers), return_exceptions=True)

    async def start(self, spec=None):
        store = ReplayStore(self.root / f"store-{len(self.listeners)}")
        session = store.add_session(spec or specification())
        self.responder = replay_service(service=service_for(session), store=store,
                                        log_dir=self.root / f"logs-{len(self.listeners)}")
        listener = await self.responder.start()
        self.listeners.append(listener)
        self.port = listener.sockets[0].getsockname()[1]
        return listener

    async def connect(self):
        reader, writer = await asyncio.open_connection("127.0.0.1", self.port)
        self.writers.append(writer)
        return reader, writer

    def events(self):
        path = self.responder.log_dir / "network_events.jsonl"
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    async def finish(self, reader):
        return await asyncio.wait_for(reader.read(), timeout=2)

    async def dialogue(self, reader, writer):
        for request, response in [(b"HELLO\n", b"READY\n"), (b"AUTH test\n", b"OK\n"),
                                  (b"GET CONFIG\n", b"interval=30\n")]:
            writer.write(request)
            await writer.drain()
            self.assertEqual(await asyncio.wait_for(reader.readexactly(len(response)), 2), response)
        self.assertEqual(await self.finish(reader), b"")

    async def test_complete_ordered_dialogue(self):
        await self.start()
        await self.dialogue(*await self.connect())
        self.assertEqual([e["step_index"] for e in self.events() if e["event"] == "replay_hit"], [0, 1, 2])
        self.assertEqual(sum(e["event"] == "session_complete" for e in self.events()), 1)

    async def test_segmented_and_coalesced_input(self):
        await self.start()
        reader, writer = await self.connect()
        writer.write(b"HE")
        await writer.drain()
        await asyncio.sleep(0.01)
        writer.write(b"LLO\nAUTH test\nGET CONFIG\n")
        await writer.drain()
        self.assertEqual(await self.finish(reader), b"READY\nOK\ninterval=30\n")

    async def test_repeated_binary_request_can_have_different_answers_by_step(self):
        await self.start(specification(pairs=[(b"\x00\xff", b"first"), (b"\x00\xff", b"second")]))
        reader, writer = await self.connect()
        writer.write(b"\x00\xff\x00\xff")
        await writer.drain()
        self.assertEqual(await self.finish(reader), b"firstsecond")

    async def test_wrong_order_is_refused_without_any_reply(self):
        await self.start()
        reader, writer = await self.connect()
        writer.write(b"GET CONFIG\n")
        await writer.drain()
        self.assertEqual(await self.finish(reader), b"")
        self.assertFalse(any(e["event"] == "replay_hit" for e in self.events()))
        self.assertTrue(any(e.get("reason") == "unexpected_request_at_step" for e in self.events()))

    async def test_unknown_second_request_does_not_reuse_first_step(self):
        await self.start()
        reader, writer = await self.connect()
        writer.write(b"HELLO\nHELLO\n")
        await writer.drain()
        self.assertEqual(await self.finish(reader), b"READY\n")
        self.assertEqual(sum(e["event"] == "replay_hit" for e in self.events()), 1)

    async def test_premature_eof_is_not_session_completion(self):
        await self.start()
        reader, writer = await self.connect()
        writer.write(b"HEL")
        writer.write_eof()
        self.assertEqual(await self.finish(reader), b"")
        self.assertTrue(any(e.get("reason") == "connection_closed_before_complete_session" for e in self.events()))
        self.assertFalse(any(e["event"] == "session_complete" for e in self.events()))

    async def test_idle_timeout_closes_connection(self):
        await self.start(specification(limits={"idle_timeout_ms": 50}))
        reader, _ = await self.connect()
        self.assertEqual(await self.finish(reader), b"")
        self.assertTrue(any(e.get("reason") == "idle_timeout" for e in self.events()))

    async def test_total_session_timeout_is_independent_of_idle_limit(self):
        await self.start(specification(limits={"idle_timeout_ms": 500, "session_timeout_ms": 50}))
        reader, writer = await self.connect()
        writer.write(b"H")
        await writer.drain()
        self.assertEqual(await self.finish(reader), b"")
        self.assertTrue(any(e.get("reason") == "session_timeout" for e in self.events()))

    async def test_response_delay_is_within_session_deadline(self):
        spec = specification(limits={"session_timeout_ms": 50})
        spec["steps"][0]["delay_ms"] = 500
        await self.start(spec)
        reader, writer = await self.connect()
        writer.write(b"HELLO\n")
        await writer.drain()
        self.assertEqual(await self.finish(reader), b"")
        self.assertFalse(any(e["event"] == "replay_hit" for e in self.events()))

    async def test_trailing_received_bytes_do_not_get_final_reply(self):
        await self.start()
        reader, writer = await self.connect()
        writer.write(b"HELLO\nAUTH test\nGET CONFIG\nX")
        await writer.drain()
        self.assertEqual(await self.finish(reader), b"READY\nOK\n")
        self.assertTrue(any(e.get("reason") == "trailing_bytes_after_final_request" for e in self.events()))

    async def test_receive_budget_stops_oversized_input(self):
        await self.start(specification(pairs=[(b"HELLO", b"OK")], limits={"max_received_bytes": 5}))
        reader, writer = await self.connect()
        writer.write(b"HELLOX")
        await writer.drain()
        self.assertEqual(await self.finish(reader), b"")
        self.assertTrue(any(e.get("reason") == "receive_byte_limit" for e in self.events()))

    async def test_two_connections_have_independent_state(self):
        await self.start()
        first, second = await self.connect(), await self.connect()
        first[1].write(b"HELLO\n")
        await first[1].drain()
        self.assertEqual(await first[0].readexactly(6), b"READY\n")
        await self.dialogue(*second)
        first[1].write(b"AUTH test\nGET CONFIG\n")
        await first[1].drain()
        self.assertEqual(await self.finish(first[0]), b"OK\ninterval=30\n")
        self.assertEqual(sum(e["event"] == "session_complete" for e in self.events()), 2)

    async def test_new_connection_starts_at_first_step(self):
        await self.start()
        await self.dialogue(*await self.connect())
        reader, writer = await self.connect()
        writer.write(b"AUTH test\n")
        await writer.drain()
        self.assertEqual(await self.finish(reader), b"")
        await self.dialogue(*await self.connect())

    async def test_connection_limits_release_active_slot(self):
        await self.start(specification(limits={"max_connections": 1}))
        first = await self.connect()
        second = await self.connect()
        self.assertEqual(await self.finish(second[0]), b"")
        self.assertTrue(any(e.get("reason") == "concurrent_connection_limit" for e in self.events()))
        await self.dialogue(*first)
        await asyncio.sleep(0.01)
        await self.dialogue(*await self.connect())

    async def test_total_connection_limit_rejects_further_dialogues(self):
        await self.start(specification(limits={"max_total_connections": 1}))
        await self.dialogue(*await self.connect())
        reader, _ = await self.connect()
        self.assertEqual(await self.finish(reader), b"")
        self.assertTrue(any(e.get("reason") == "total_connection_limit" for e in self.events()))

    async def test_listener_shutdown_closes_active_connections_and_tasks(self):
        listener = await self.start()
        reader, writer = await self.connect()
        writer.write(b"HEL")
        await writer.drain()
        await asyncio.sleep(0.01)
        listener.close()
        await listener.wait_closed()
        self.assertEqual(await self.finish(reader), b"")
        self.assertFalse(self.responder.tasks)
        self.assertEqual(self.responder.active_connections, 0)

    async def test_failed_send_does_not_claim_delivery(self):
        from tests.test_network_delivery import FailingWriter
        await self.start(specification(pairs=[(b"HELLO\n", b"OK\n")]))
        reader = asyncio.StreamReader()
        reader.feed_data(b"HELLO\n")
        await self.responder.handle_client(reader, FailingWriter())
        events = self.events()
        self.assertTrue(any(e["event"] == "network_response_failed" for e in events))
        self.assertFalse(any(e["event"] == "replay_hit" or e.get("response_sent") is True for e in events))

    async def test_fresh_responder_resets_state_after_partial_previous_attempt(self):
        listener = await self.start()
        first_identity = self.responder.session.session_id
        reader, writer = await self.connect()
        writer.write(b"HELLO\n")
        await writer.drain()
        self.assertEqual(await reader.readexactly(6), b"READY\n")
        listener.close()
        await listener.wait_closed()
        await self.start()
        self.assertEqual(self.responder.session.session_id, first_identity)
        reader, writer = await self.connect()
        writer.write(b"AUTH test\n")
        await writer.drain()
        self.assertEqual(await self.finish(reader), b"")
        self.assertTrue(any(e.get("step_index") == 0 and e.get("reason") == "unexpected_request_at_step"
                            for e in self.events()))
        await self.dialogue(*await self.connect())

    async def test_slow_partial_reads_cannot_extend_total_deadline(self):
        await self.start(specification(pairs=[(b"HELLO" * 100, b"OK")],
                                       limits={"idle_timeout_ms": 100, "session_timeout_ms": 100}))
        reader, writer = await self.connect()
        for byte in b"HELLO":
            writer.write(bytes([byte]))
            await writer.drain()
            await asyncio.sleep(0.025)
        self.assertEqual(await self.finish(reader), b"")
        self.assertTrue(any(e.get("reason") == "session_timeout" for e in self.events()))


if __name__ == "__main__":
    unittest.main()
