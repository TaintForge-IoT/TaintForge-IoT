"""A stale status sample needs a bounded fresh observation before cancellation."""
import json
from contextlib import ExitStack
from pathlib import Path
import signal
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from scripts import run_network_guard
from taintforge_env import network_runtime as runtime


class OwnerStatusConfirmationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.enterContext(patch.object(runtime.NetworkRuntimeOwner, "_heartbeat"))
        self.owner = runtime.NetworkRuntimeOwner(self.root / "control", self.root / "logs", attempt_id="status-confirmation")
        self.addCleanup(self.owner.close)
        self.client = runtime.NetworkRuntimeClient(self.owner.client_path)
        self.pulse = self.owner.directory / runtime.OWNER_HEARTBEAT_FILE
        self.now = 101.01
        self.sleeps = []
        self.write_pulse(100.0)

    def write_pulse(self, seen, **changes):
        value = json.loads(self.pulse.read_text())
        value.update(owner_last_seen=seen, **changes)
        runtime._private_json(self.pulse, value, durable=False)

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now += seconds

    def clock(self, sleep=None):
        stack = self.enterContext(ExitStack())
        stack.enter_context(patch.object(runtime.time, "monotonic", side_effect=lambda: self.now))
        stack.enter_context(patch.object(runtime.time, "sleep", side_effect=sleep or self.sleep))

    def test_delayed_live_owner_is_rechecked_and_no_state_is_written(self):
        before = (self.owner.directory / "state.json").read_bytes()

        def renewed(seconds):
            self.sleep(seconds)
            self.owner._publish_heartbeat()

        self.clock(renewed)
        result = self.client.call("status")
        self.assertIsNone(result["termination_reason"])
        self.assertGreaterEqual(len(self.sleeps), 1)
        self.assertLessEqual(sum(self.sleeps), 0.15)
        self.assertEqual((self.owner.directory / "state.json").read_bytes(), before)

    def test_one_more_publication_cycle_can_recover(self):
        def renewed(seconds):
            self.sleep(seconds)
            if len(self.sleeps) == 2:
                self.owner._publish_heartbeat()

        self.clock(renewed)
        self.assertIsNone(self.client.call("status")["termination_reason"])
        self.assertEqual(len(self.sleeps), 2)

    def test_persistent_staleness_is_bounded_and_retains_diagnostics(self):
        self.clock()
        with self.assertRaises(runtime.NetworkRuntimeError) as caught:
            self.client.call("status")
        detail = caught.exception.details
        self.assertEqual(detail["check"], "owner_heartbeat_stale")
        self.assertEqual(detail["timeout_seconds"], 1)
        self.assertEqual(detail["operation"], "status")
        self.assertEqual(detail["status_confirmation"]["attempts"], 3)
        self.assertLessEqual(detail["status_confirmation"]["elapsed_seconds"], 0.15)
        self.assertEqual(len(self.sleeps), 2)
        self.assertNotIn(self.owner.token, json.dumps(detail))

    def test_quota_mutations_reject_stale_owner_immediately(self):
        self.clock()
        state = self.owner.directory / "state.json"
        before = state.read_bytes()
        for operation, fields in (("send", {"size": 1}), ("heartbeat", {}), ("admit", {"kind": "tcp"})):
            with self.subTest(operation=operation), self.assertRaises(runtime.NetworkRuntimeError):
                self.client.call(operation, **fields)
        self.assertEqual(self.sleeps, [])
        self.assertEqual(state.read_bytes(), before)

    def test_identity_binding_is_rechecked_after_the_wait(self):
        def wrong_binding(seconds):
            self.sleep(seconds)
            self.write_pulse(self.now, attempt_id="different-attempt")

        self.clock(wrong_binding)
        with self.assertRaises(runtime.NetworkRuntimeError) as caught:
            self.client.call("status")
        self.assertEqual(caught.exception.details["check"], "owner_heartbeat_binding")
        self.assertEqual(len(self.sleeps), 1)

    def test_owner_pid_identity_is_rechecked_after_the_wait(self):
        real_start = runtime.process_start
        observations = []

        def identity(pid):
            observations.append(pid)
            return real_start(pid) if not self.sleeps else None

        self.clock()
        with patch.object(runtime, "process_start", side_effect=identity), self.assertRaises(runtime.NetworkRuntimeError) as caught:
            self.client.call("status")
        self.assertEqual(caught.exception.details["check"], "owner_process_identity")
        self.assertEqual(len(self.sleeps), 1)

    def test_terminal_reason_committed_during_confirmation_is_returned(self):
        def terminal(seconds):
            self.sleep(seconds)
            self.owner.fail("network_receive_budget_exceeded")

        self.clock(terminal)
        result = self.client.call("status")
        self.assertEqual(result["termination_reason"], "network_receive_budget_exceeded")
        self.assertEqual(len(self.sleeps), 1)

    def test_overslept_deadline_cannot_accept_a_late_fresh_pulse(self):
        def overslept(seconds):
            self.sleeps.append(seconds)
            self.now += 0.16
            self.owner._publish_heartbeat()

        self.clock(overslept)
        with self.assertRaises(runtime.NetworkRuntimeError) as caught:
            self.client.call("status")
        self.assertEqual(caught.exception.details["check"], "owner_heartbeat_stale")
        self.assertGreater(caught.exception.details["status_confirmation"]["elapsed_seconds"], 0.15)

    def test_new_ledger_identity_is_checked_instead_of_using_a_cached_status(self):
        def replace_identity(seconds):
            self.sleep(seconds)
            path = self.owner.directory / "state.json"
            original = path.read_bytes()
            self.addCleanup(path.write_bytes, original)
            state = json.loads(original)
            state["token"] = "changed"
            runtime._private_json(path, state, durable=False)
            self.owner._publish_heartbeat()

        self.clock(replace_identity)
        with self.assertRaisesRegex(runtime.NetworkRuntimeError, "another attempt"):
            self.client.call("status")

    def test_a_retry_that_finishes_after_deadline_cannot_return_success(self):
        transaction = runtime.ledger_transaction
        calls = []

        def slow_read(*args, **kwargs):
            calls.append(args[1])
            if len(calls) == 2:
                self.now += 0.16
                self.owner._publish_heartbeat()
            return transaction(*args, **kwargs)

        self.clock()
        with patch.object(runtime, "ledger_transaction", side_effect=slow_read), self.assertRaises(runtime.NetworkRuntimeError) as caught:
            self.client.call("status")
        self.assertEqual(caught.exception.details["check"], "owner_heartbeat_stale")
        self.assertGreater(caught.exception.details["status_confirmation"]["elapsed_seconds"], 0.15)

    def test_fresh_status_and_committed_failure_never_wait(self):
        self.clock()
        self.owner._publish_heartbeat()
        self.assertIsNone(self.client.call("status")["termination_reason"])
        self.owner.fail("network_responder_exited")
        self.write_pulse(1)
        self.assertEqual(self.client.call("status")["termination_reason"], "network_responder_exited")
        self.assertEqual(self.sleeps, [])

    def test_dead_owner_and_corrupt_pulse_never_wait(self):
        self.clock()
        with patch.object(runtime, "process_start", return_value=None), self.assertRaises(runtime.NetworkRuntimeError) as caught:
            self.client.call("status")
        self.assertEqual(caught.exception.details["check"], "owner_process_identity")
        self.pulse.write_text("{")
        with self.assertRaises(runtime.NetworkRuntimeError) as caught:
            self.client.call("status")
        self.assertEqual(caught.exception.details["check"], "ledger_data")
        self.assertEqual(self.sleeps, [])

    def test_legacy_status_does_not_gain_a_confirmation_window(self):
        self.client.descriptor.pop("heartbeat_profile")
        path = self.owner.directory / "state.json"
        state = json.loads(path.read_text())
        state["owner_last_seen"] = 100.0
        runtime._private_json(path, state, durable=False)
        self.clock()
        with self.assertRaises(runtime.NetworkRuntimeError):
            self.client.call("status")
        self.assertEqual(self.sleeps, [])


class OwnerStatusGuardTests(unittest.TestCase):
    def test_real_guard_survives_a_renewed_owner_and_stops_on_a_persistent_stall(self):
        for renew in (True, False):
            with self.subTest(renew=renew), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                with patch.object(runtime.NetworkRuntimeOwner, "_heartbeat"):
                    owner = runtime.NetworkRuntimeOwner(root / "control", root / "logs", attempt_id="guard-pulse")
                pulse = owner.directory / runtime.OWNER_HEARTBEAT_FILE
                value = json.loads(pulse.read_text())
                value["owner_last_seen"] = time.monotonic() - 1.01
                runtime._private_json(pulse, value, durable=False)
                stop = threading.Event()

                def publisher():
                    if stop.wait(0.025):
                        return
                    while not stop.is_set():
                        owner._publish_heartbeat()
                        stop.wait(0.025)

                thread = threading.Thread(target=publisher) if renew else None
                if thread:
                    thread.start()
                result = root / "guard.json"
                child = [sys.executable, "-c", "import time; time.sleep(0.25)"]
                try:
                    code = run_network_guard.run(owner.client_path, child, result_path=result)
                    saved = json.loads(result.read_text())
                    self.assertTrue(saved["guest_process_stopped"])
                    if renew:
                        self.assertEqual(code, 0)
                        self.assertIsNone(saved["termination_reason"])
                        self.assertIsNone(owner.snapshot()["termination_reason"])
                    else:
                        self.assertEqual(code, 128 + signal.SIGTERM)
                        self.assertEqual(saved["termination_reason"], "network_runtime_owner_lost")
                        self.assertEqual(saved["runtime_error"]["details"]["check"], "owner_heartbeat_stale")
                finally:
                    stop.set()
                    if thread:
                        thread.join(2)
                    owner.close()
