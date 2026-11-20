"""Owner thread diagnostics explain delays without changing liveness decisions."""
import json
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from taintforge_env import network_runtime as runtime
from taintforge_env.network_owner_diagnostics import (
    MAX_BYTES, OwnerHeartbeatDiagnostics, OWNER_DIAGNOSTIC_FILE, bounded_record,
)


class OwnerDiagnosticDataTests(unittest.TestCase):
    def test_slow_span_has_a_stage_and_is_kept_in_a_bounded_history(self):
        now = [0]
        data = OwnerHeartbeatDiagnostics(attempt_id="test", owner_pid=1, owner_start="2", clock=lambda: now[0])
        for _ in range(30):
            data.step("publishing")
            now[0] += 300_000_000
            data.step("published")
        value = data.summary(None)
        self.assertEqual(value["published_pulses"], 30)
        self.assertEqual(len(value["long_spans"]), 8)
        self.assertTrue(all(row["phase"] == "publishing" for row in value["long_spans"]))
        self.assertTrue(all(row["elapsed_ns"] == 300_000_000 for row in value["long_spans"]))

    def test_capture_omits_local_values_and_source_text(self):
        private_token = "DO_NOT_EXPORT_OWNER_SECRET"
        data = OwnerHeartbeatDiagnostics(attempt_id="test", owner_pid=1, owner_start="2")
        value = data.capture(threading.current_thread())
        encoded = json.dumps(value)
        self.assertNotIn(private_token, encoded)
        self.assertTrue(value["thread_stack"])
        for row in value["thread_stack"]:
            self.assertEqual(set(row), {"file", "function", "line"})
            self.assertNotIn("/", row["file"])

    def test_exception_diagnostics_omit_the_message_and_keep_type_and_location(self):
        data = OwnerHeartbeatDiagnostics(attempt_id="test", owner_pid=1, owner_start="2")
        data.step("checking_services")
        try:
            raise PermissionError(13, "PRIVATE_TOKEN_AND_DATA")
        except OSError as error:
            data.failure(error)
        value = data.summary(None)
        self.assertEqual(value["exceptions"][0]["type"], "PermissionError")
        self.assertEqual(value["exceptions"][0]["errno"], 13)
        self.assertNotIn("PRIVATE_TOKEN_AND_DATA", json.dumps(value))

    def test_optional_artifact_is_bounded_even_for_oversized_input(self):
        value = {"attempt_id": "test", "main_stack": [{"file": "x" * 5000}] * 8,
                 "thread_stack": [], "long_spans": []}
        result = bounded_record(value)
        self.assertLessEqual(len(json.dumps(result, sort_keys=True).encode()), MAX_BYTES)


class OwnerDiagnosticLoopTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.owner = runtime.NetworkRuntimeOwner(self.root / "control", self.root / "logs", attempt_id="diagnostic-loop")
        self.addCleanup(self.owner.close)

    def read_diagnostic(self):
        return json.loads((self.root / OWNER_DIAGNOSTIC_FILE).read_text())

    def test_real_health_stall_is_visible_and_still_rejects_stale_status(self):
        entered, release = threading.Event(), threading.Event()

        def stalled_health():
            entered.set()
            release.wait(4)

        self.owner.health_check = stalled_health
        try:
            self.assertTrue(entered.wait(2))
            time.sleep(1.1)
            with self.assertRaises(runtime.NetworkRuntimeError) as caught:
                runtime.NetworkRuntimeClient(self.owner.client_path).call("status")
            self.assertEqual(caught.exception.details["check"], "owner_heartbeat_stale")
            before = self.owner.owner_diagnostics.capture(self.owner.thread)
            self.assertEqual(before["phase"], "checking_services")
            self.assertGreater(before["phase_elapsed_ns"], 1_000_000_000)
            self.assertTrue(any(row["function"] == "stalled_health" for row in before["thread_stack"]))
        finally:
            release.set()
        self.owner.close()
        saved = self.read_diagnostic()
        self.assertTrue(any(row["phase"] == "checking_services" and row["elapsed_ns"] >= 1_000_000_000
                            for row in saved["after_join"]["long_spans"]))

    def test_slow_heartbeat_file_publication_is_distinguished_from_health(self):
        entered, release = threading.Event(), threading.Event()
        real_write = runtime._private_json

        def delayed_write(path, value, **kwargs):
            if Path(path).name == runtime.OWNER_HEARTBEAT_FILE and threading.current_thread() == self.owner.thread:
                entered.set()
                release.wait(3)
            return real_write(path, value, **kwargs)

        with patch.object(runtime, "_private_json", side_effect=delayed_write):
            try:
                self.assertTrue(entered.wait(2))
                time.sleep(.25)
                value = self.owner.owner_diagnostics.capture(self.owner.thread)
                self.assertEqual(value["phase"], "publishing")
                self.assertTrue(any(row["function"] == "delayed_write" for row in value["thread_stack"]))
            finally:
                release.set()
            self.owner.close()
        value = self.read_diagnostic()
        self.assertTrue(any(row["phase"] == "publishing" for row in value["after_join"]["long_spans"]))

    def test_healthy_cleanup_preserves_the_diagnostic_after_ledger_removal(self):
        value = self.owner.close()
        self.assertEqual(value["cleanup_status"], "cleaned")
        self.assertEqual(value["owner_diagnostic"]["status"], "saved")
        self.assertFalse(self.owner.directory.exists())
        saved = self.read_diagnostic()
        self.assertEqual(saved["attempt_id"], self.owner.attempt_id)
        self.assertFalse(saved["after_join"]["thread_alive"])
        self.assertNotIn(self.owner.token, json.dumps(saved))
        self.assertLessEqual((self.root / OWNER_DIAGNOSTIC_FILE).stat().st_size, MAX_BYTES)
        self.assertEqual((self.root / OWNER_DIAGNOSTIC_FILE).stat().st_mode & 0o777, 0o600)

    def test_diagnostic_write_failure_does_not_change_cleanup_or_quota_outcomes(self):
        real_write = runtime._private_json

        def denied(path, value, **kwargs):
            if Path(path).name == OWNER_DIAGNOSTIC_FILE:
                raise OSError(28, "diagnostic disk full")
            return real_write(path, value, **kwargs)

        self.owner.fail("network_receive_budget_exceeded")
        with patch.object(runtime, "_private_json", side_effect=denied):
            value = self.owner.close()
        self.assertEqual(value["cleanup_status"], "cleaned")
        self.assertEqual(value["termination_reason"], "network_receive_budget_exceeded")
        self.assertEqual(value["owner_diagnostic"]["status"], "unavailable")
        self.assertFalse(self.owner.directory.exists())

    def test_small_log_budget_still_has_space_for_the_terminal_footer(self):
        self.owner.close()
        owner = runtime.NetworkRuntimeOwner(self.root / "small", self.root / "small-logs", attempt_id="small",
                                           limits=runtime.NetworkRuntimeLimits.parse({"max_log_bytes": 4096}))
        try:
            value = owner.close()
            self.assertEqual(value["cleanup_status"], "cleaned")
            self.assertLessEqual(owner.status_path.stat().st_size, owner.footer_reserve)
        finally:
            owner.close()
