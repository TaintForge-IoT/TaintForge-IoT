"""NET-8 contracts plus benign i386 builds and actual local TCP replay."""
from __future__ import annotations

import asyncio
import copy
import json
from pathlib import Path
import socket
import tempfile
import unittest
from unittest.mock import patch

from scripts import run_network_capsule_sessions_e2e as runner
from taintforge_env import network_acceptance as acceptance
from taintforge_env.network_capsule_sessions import (
    BY_NAME, CASES, MARKER, SCOPE, specification, validate_connections, validate_result, validate_transcript,
)
from taintforge_env.network_policy import load_network_policy
from taintforge_env.network_replay import replay_service
from taintforge_env.replay_session import ReplaySession
from tests.test_network_acceptance import runtime_reference


def connection_rows(case):
    steps = {"unknown_step": [0], "trailing_bytes": [0, 1]}.get(case.name, []) if case.reason else [0, 1, 2]
    rows = [{"connection_id": i + 1, "steps": steps.copy(), "start_index": i * 10, "terminal_index": i * 10 + 9,
             "terminal": "session_abort" if case.reason else "session_complete", "reason": case.reason}
            for i in range(case.connections)]
    if case.mode == 10:
        rows[0]["terminal_index"] = 20
    return rows


def native_report():
    data = {"status": "passed", "scope": SCOPE, "plugin_api": 6, "guest_executions": 13,
            "qemu_launch_attempts": 13, "phase1_executed": True, "capsule_executed": True,
            "namespace_executed": True, "oep_proven": False, "hostile_sample_ready": False,
            "runtime_sha256": {r["resolved_path"]: r["sha256"] for r in runtime_reference().values()}, "cases": []}
    for case in CASES:
        session = ReplaySession.parse(specification(case, 4444))
        data["cases"].append({"case": case.name, "status": "passed", "guest_executions": 1, "store_unchanged": True,
            "attempt": {"attempt_id": case.name, "analysis_instance_id": case.name, "lifecycle_attempt": case.name,
                "phase1_executed": True, "capsule_executed": True, "namespace_executed": True, "phase1_retired": True,
                "capsule_tree_empty": True, "namespace_removed": True, "veth_removed": True, "network_cleanup": "cleaned",
                "termination_reason": None, "goal_reached": case.goal, "guest_exit": case.guest_exit,
                "observer": {"status": "correlated"}},
            "transcript": {"replay_session_id": session.session_id, "connections": connection_rows(case),
                "completed": case.connections if not case.reason else 0, "aborted": case.connections if case.reason else 0}})
    return data


class SessionContractTests(unittest.TestCase):
    def test_native_matrix_has_all_thirteen_net4_scenarios(self):
        self.assertEqual(tuple(BY_NAME), acceptance.SESSION_CASES)
        validate_result(native_report(), runtime_reference())

    def test_component_scope_and_missing_native_execution_cannot_pass(self):
        for key, value in (("scope", "host_loopback"), ("phase1_executed", False),
                           ("namespace_executed", False), ("capsule_executed", False),
                           ("guest_executions", 12), ("qemu_launch_attempts", 14), ("oep_proven", True)):
            with self.subTest(key=key):
                data = native_report(); data[key] = value
                with self.assertRaises(ValueError): validate_result(data, runtime_reference())

    def test_missing_duplicate_failed_and_reused_attempts_are_rejected(self):
        for mutate in (lambda d: d["cases"].pop(),
                       lambda d: d["cases"].__setitem__(1, copy.deepcopy(d["cases"][0])),
                       lambda d: d["cases"][0].update(status="failed"),
                       lambda d: d["cases"][1]["attempt"].update(attempt_id="ordered")):
            data = native_report(); mutate(data)
            with self.assertRaises(ValueError): validate_result(data, runtime_reference())

    def test_cleanup_retirement_and_payload_store_are_required(self):
        for key, value in (("phase1_retired", False), ("namespace_removed", False),
                           ("veth_removed", False), ("capsule_tree_empty", False),
                           ("network_cleanup", "cleanup_failed"), ("termination_reason", "network_responder_exited")):
            data = native_report(); data["cases"][0]["attempt"][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): validate_result(data, runtime_reference())
        data = native_report(); data["cases"][0]["store_unchanged"] = False
        with self.assertRaises(ValueError): validate_result(data, runtime_reference())

    def test_wrong_response_is_wire_complete_but_not_an_application_success(self):
        data = native_report(); row = next(c for c in data["cases"] if c["case"] == "wrong_response")
        self.assertEqual(row["transcript"]["completed"], 1)
        self.assertEqual(row["attempt"]["guest_exit"], 14)
        row["attempt"]["goal_reached"] = True
        with self.assertRaises(ValueError): validate_result(data, runtime_reference())

    def test_wrong_exit_observer_or_runtime_identity_is_rejected(self):
        for mutate in (lambda d: d["cases"][0]["attempt"].update(guest_exit=14),
                       lambda d: d["cases"][0]["attempt"].update(observer={"status": "incomplete"}),
                       lambda d: d["runtime_sha256"].update({"/runtime/qemu": "0" * 64})):
            data = native_report(); mutate(data)
            with self.assertRaises(ValueError): validate_result(data, runtime_reference())

    def test_malformed_observer_and_boolean_counters_fail_with_a_report_error(self):
        for mutate in (lambda d: d["cases"][0]["attempt"].update(observer=[]),
                       lambda d: d["cases"][0].update(guest_executions=True),
                       lambda d: d["cases"][0]["attempt"].update(guest_exit=False),
                       lambda d: d["cases"][0]["transcript"].update(completed=True),
                       lambda d: d.update(guest_executions=13.0)):
            data = native_report(); mutate(data)
            with self.assertRaises(ValueError): validate_result(data, runtime_reference())

    def test_reconnect_and_interleaving_require_independent_complete_connections(self):
        for name in ("reconnect", "interleaved_connections"):
            case = BY_NAME[name]
            for mutate in (lambda r: r.pop(), lambda r: r[1].update(connection_id=1),
                           lambda r: r[1].update(steps=[1, 2]), lambda r: r[0].update(steps=[0, 1, 1, 2])):
                rows = connection_rows(case); mutate(rows)
                with self.subTest(name=name), self.assertRaises(ValueError): validate_connections(case, rows)

    def test_rejection_reason_and_progress_must_match(self):
        for case in CASES:
            if not case.reason: continue
            rows = connection_rows(case); rows[0]["reason"] = "service_shutdown"
            with self.subTest(case=case.name), self.assertRaises(ValueError): validate_connections(case, rows)

    def test_interleaved_case_cannot_be_satisfied_by_two_sequential_connections(self):
        with self.assertRaises(ValueError):
            validate_connections(BY_NAME["interleaved_connections"], connection_rows(BY_NAME["reconnect"]))
        with self.assertRaises(ValueError):
            validate_connections(BY_NAME["reconnect"], connection_rows(BY_NAME["interleaved_connections"]))

    def test_empty_foreign_or_unstarted_transcript_is_rejected(self):
        case = BY_NAME["ordered"]; session = ReplaySession.parse(specification(case, 4444))
        for events in ([], [None], [{"listener_type": "deterministic_session", "replay_session_id": "0" * 64}],
                       [{"listener_type": "deterministic_session", "replay_session_id": session.session_id,
                         "original_remote_ip": session.remote_ip, "original_remote_port": session.remote_port,
                         "connection_id": 1, "event": "session_complete", "completed_steps": 0}]):
            with self.assertRaises(ValueError): validate_transcript(case, events, session)

    def test_aggregate_dispatch_requires_net8_and_passes_all_binary_arguments(self):
        check = next(c for c in acceptance.CHECKS if c.name == "capsule_sessions")
        names = [check.name for check in acceptance.CHECKS]
        self.assertEqual(names.index("capsule_sessions"), names.index("capsule") + 1)
        self.assertFalse(check.component)
        self.assertTrue(check.namespace and check.qemu)
        runtime = runtime_reference()
        with tempfile.TemporaryDirectory() as tmp:
            cmd, env, out = acceptance.command_for(check, Path(tmp), Path(tmp), "full", runtime, "run")
        for flag in ("--qemu", "--plugin", "--observer"):
            self.assertIn(flag, cmd)
        self.assertEqual(acceptance.validate_report(check, native_report(), "full", "run", runtime), "passed")
        rows = [{"name": c.name, "status": "passed"} for c in acceptance.CHECKS if c.name != "capsule_sessions"]
        self.assertFalse(acceptance.aggregate(rows, "full")["full_acceptance"])

    def test_missing_native_preflight_is_blocked_with_zero_guest_claims(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "out"
            args = ["net8", "--out", str(out), "--qemu", "/absent/qemu", "--plugin", "/absent/plugin", "--observer", "/absent/observer"]
            with patch("sys.argv", args), patch.object(runner, "preflight", side_effect=RuntimeError("no cgroup")):
                self.assertEqual(runner.main(), 2)
            report = json.loads((out / "report.json").read_text())
            self.assertEqual(report["guest_executions"], 0)
            self.assertFalse(report["phase1_executed"])

    def test_net8_preflight_requires_the_phase1_plugin(self):
        check = next(c for c in acceptance.CHECKS if c.name == "capsule_sessions")
        runtime = runtime_reference()
        runtime["plugin"] = {"status": "not_supplied"}
        with patch.object(acceptance.shutil, "which", return_value=None):
            problems = acceptance.prerequisites(check, "full", runtime)
        self.assertIn("plugin: not_supplied", problems)

    def test_fixture_builder_rejects_invalid_parameters_before_writing(self):
        with tempfile.TemporaryDirectory() as tmp:
            for values in ({"port": 0, "mode": 0}, {"port": 1, "mode": 11}, {"port": 1, "mode": 0, "work": 0}):
                with self.assertRaises(ValueError): runner.build_guest(Path(tmp) / "invalid", **values)
                self.assertFalse((Path(tmp) / "invalid").exists())


class SessionReplayTests(unittest.IsolatedAsyncioTestCase):
    async def exercise(self, case):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with socket.socket() as sock:
                sock.bind(("127.0.0.1", 0)); port = sock.getsockname()[1]
            store, session = runner.prepare_policy(root, case, port)
            original = store.validate()["store_sha256"]
            binary = runner.build_guest(root / "input", port=port, mode=case.mode, work=1)
            service = load_network_policy(root / "policy.json").services[0]
            responder = replay_service(service=service, store=store, log_dir=root / "logs")
            listener = await responder.start()
            try:
                self.assertEqual(binary.read_bytes()[:5], b"\x7fELF\x01")
                self.assertEqual(int.from_bytes(binary.read_bytes()[18:20], "little"), 3)
                stdout, returncode = await asyncio.wait_for(self.client(case, port), 3)
                async with asyncio.timeout(2):
                    while responder.tasks:
                        await asyncio.sleep(.005)
                self.assertEqual(returncode, case.guest_exit)
                self.assertEqual(stdout, MARKER if case.goal else b"")
                events = [json.loads(line) for line in (root / "logs/network_events.jsonl").read_text().splitlines()]
                validate_transcript(case, events, session)
                with self.assertRaises(ValueError): validate_transcript(case, events, session, attempt_id="another-attempt")
                self.assertEqual(store.validate()["store_sha256"], original)
                if case.goal:
                    damaged = copy.deepcopy(events)
                    next(e for e in damaged if e["event"] == "replay_hit")["response_sha256"] = "0" * 64
                    with self.assertRaises(ValueError): validate_transcript(case, damaged, session)
                    damaged = copy.deepcopy(events)
                    damaged.append(copy.deepcopy(next(e for e in damaged if e["event"] == "replay_hit")))
                    with self.assertRaises(ValueError): validate_transcript(case, damaged, session)
            finally:
                listener.close(); await listener.wait_closed()

    async def client(self, case, port):
        writers = []
        async def connect():
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            writers.append(writer)
            return reader, writer
        async def exchange(pair, request, response):
            reader, writer = pair
            writer.write(request); await writer.drain()
            actual = await reader.readexactly(len(response))
            if actual != response:
                raise ValueError("wrong reply")
        async def hello(pair):
            await exchange(pair, b"HELLO\n", b"READY\n")
        async def finish(pair):
            await exchange(pair, b"AUTH test\n", b"OK\n")
            await exchange(pair, b"GET CONFIG\n", b"interval=30\n")
        try:
            pair = await connect(); reader, writer = pair
            if case.mode == 1:
                writer.write(b"HE"); await writer.drain(); await asyncio.sleep(.02)
                await exchange(pair, b"LLO\n", b"READY\n"); await finish(pair)
            elif case.mode == 2:
                await exchange(pair, b"HELLO\nAUTH test\nGET CONFIG\n", b"READY\nOK\ninterval=30\n")
            elif case.mode == 10:
                await hello(pair)
                second = await connect(); await hello(second); await finish(second)
                second[1].close(); await second[1].wait_closed(); await finish(pair)
            elif case.mode in {0, 9}:
                await hello(pair); await finish(pair)
                if case.mode == 9:
                    writer.close(); await writer.wait_closed()
                    pair = await connect(); await hello(pair); await finish(pair)
            else:
                if case.mode == 3: writer.write(b"GET CONFIG\n")
                elif case.mode == 4:
                    await hello(pair); writer.write(b"HELLO\n")
                elif case.mode == 5:
                    writer.write(b"HEL"); await writer.drain(); writer.write_eof()
                elif case.mode == 6: await asyncio.sleep(.3)
                elif case.mode in {7, 8}: writer.write(b"HELLO\nAUTH test\nGET CONFIG\nX")
                await writer.drain()
                if case.mode == 7: self.assertEqual(await reader.readexactly(9), b"READY\nOK\n")
                self.assertEqual(await reader.read(), b"")
                return b"", 20
            return MARKER, 0
        except ValueError as exc:
            if str(exc) != "wrong reply": raise
            return b"", 14
        finally:
            for writer in writers:
                writer.close()
                await writer.wait_closed()


def client_test(case):
    async def test(self):
        await self.exercise(case)
    return test


for _case in CASES:
    setattr(SessionReplayTests, "test_session_replay_" + _case.name, client_test(_case))


if __name__ == "__main__":
    unittest.main()
