"""Acceptance must not turn missing or component evidence into native success."""
from __future__ import annotations

from contextlib import redirect_stderr
import copy
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from taintforge_env import network_acceptance as acceptance
from scripts import run_network_acceptance_tests as worker


def unit_report(check, run_id="run-1", **changes):
    return {"schema_version": 1, "kind": "network_unittest_result", "run_id": run_id,
            "requested": list(check.tests), "discovered": ["fixture.test_ok"], "tests_run": 1,
            "status": "passed", "failures": [], "errors": [], "skipped": [],
            "expected_failures": [], "unexpected_successes": [], "execution_uid": os.geteuid(), **changes}


def runtime_reference():
    return {name: {"status": "recorded", "path": "/runtime/" + name, "resolved_path": "/runtime/" + name,
                   "sha256": str(index) * 64} for index, name in enumerate(("qemu", "plugin", "observer"), 1)}


def capsule_report():
    runtime = runtime_reference()
    result = {"status": "passed", "scope": "native_phase1_retirement_capsule_network",
              "phase1_executed": True, "capsule_executed": True, "namespace_executed": True,
              "oep_proven": False, "hostile_sample_ready": False, "guest_executions": 9,
              "qemu_launch_attempts": 9, "plugin_api": 6,
              "runtime_sha256": {row["resolved_path"]: row["sha256"] for row in runtime.values()},
              "cases": []}
    reasons = {"receive_budget": "network_receive_budget_exceeded", "responder_crash": "network_responder_exited",
               "timeout": "network_capsule_timeout"}
    for name in acceptance.CAPSULE_CASES:
        attempts = []
        for index in range(2 if name == "repair" else 1):
            attempts.append({"phase1_executed": True, "capsule_executed": True, "namespace_executed": True,
                "phase1_retired": True, "capsule_tree_empty": True, "namespace_removed": True, "veth_removed": True,
                "network_cleanup": "cleaned", "termination_reason": reasons.get(name),
                "goal_reached": name not in reasons and (name != "repair" or index == 1),
                "observer": {"status": "incomplete" if name in {"responder_crash", "timeout"} else "correlated"}})
        result["cases"].append({"case": name, "status": "passed", "attempts": attempts,
                                "guest_executions": len(attempts), "store_unchanged": True, "resume_blocked": name in reasons})
    return result


class AcceptanceContractTests(unittest.TestCase):
    def test_only_complete_matrix_can_pass(self):
        checks = [{"name": check.name, "status": "passed"} for check in acceptance.CHECKS]
        self.assertTrue(acceptance.aggregate(checks, "full")["full_acceptance"])
        for rows in ([], checks[:-1], checks + [checks[0]]):
            with self.subTest(rows=len(rows)):
                self.assertFalse(acceptance.aggregate(rows, "full")["full_acceptance"])
        for profile in ("component",):
            self.assertFalse(acceptance.aggregate(checks, profile)["full_acceptance"])

    def test_child_failure_preserves_failed_case_reason(self):
        data = {"status": "failed", "cases": [{"case": "tcp", "status": "failed",
            "error": "SynthesisLoopError: [Errno 13] Permission denied: '/run/netns/tf-72d12aa3'"}]}
        reason = acceptance.child_failure(1, data)
        self.assertIn("tcp: SynthesisLoopError", reason)
        self.assertIn("/run/netns/tf-72d12aa3", reason)

    def test_child_failure_handles_top_level_and_malformed_details(self):
        self.assertIn("setup failed", acceptance.child_failure(1, {"error": "setup failed"}))
        self.assertEqual(acceptance.child_failure(1, {"cases": "invalid"}), "child exited with status 1")
        self.assertEqual(acceptance.child_failure(1, {"cases": [None, 1]}), "child exited with status 1")
        text = acceptance.child_failure(1, {"cases": [{"case": "tcp", "status": "failed", "error": "x" * 10000}] * 20})
        self.assertLess(len(text), 9000)

    def test_missing_skipped_failed_or_interrupted_checks_cannot_pass(self):
        checks = [{"name": check.name, "status": "passed"} for check in acceptance.CHECKS]
        for status, overall, code in (("not_run", "incomplete", 2), ("skipped", "incomplete", 2),
                                      ("blocked", "blocked", 2), ("failed", "failed", 1)):
            with self.subTest(status=status):
                checks[0]["status"] = status
                actual = acceptance.aggregate(checks, "full")
                self.assertEqual((actual["status"], actual["exit_code"]), (overall, code))
        checks[0]["status"] = "passed"
        self.assertEqual(acceptance.aggregate(checks, "full", stable=False)["status"], "failed")
        self.assertEqual(acceptance.aggregate(checks, "full", interrupted=True)["exit_code"], 130)

    def test_unittest_identity_and_execution_counts_are_checked(self):
        check = acceptance.CHECKS[0]
        data = unit_report(check)
        self.assertEqual(acceptance.validate_unittest(data, check, "run-1"), "passed")
        for changes in ({"run_id": "older-run"}, {"requested": []}, {"tests_run": 0},
                        {"discovered": []}, {"tests_run": True}, {"errors": [{"detail": "ImportError"}]},
                        {"failures": [{"detail": "AssertionError"}]}, {"unexpected_successes": ["fixture"]}):
            with self.subTest(changes=changes), self.assertRaises(acceptance.AcceptanceError):
                acceptance.validate_unittest({**data, **changes}, check, "run-1")

    def test_skipped_and_expected_failure_are_not_successful_acceptance(self):
        check = acceptance.CHECKS[0]
        for changes in ({"skipped": [{"test": "fixture", "detail": "root unavailable"}]},
                        {"expected_failures": [{"test": "fixture", "detail": "known bug"}]}):
            self.assertEqual(acceptance.validate_unittest(unit_report(check, **changes), check, "run-1"), "skipped")

    def test_privileged_worker_must_really_be_root(self):
        check = next(check for check in acceptance.CHECKS if check.name == "ownership")
        with self.assertRaises(acceptance.AcceptanceError):
            acceptance.validate_unittest(unit_report(check, execution_uid=1000), check, "run-1")
        self.assertEqual(acceptance.validate_unittest(unit_report(check, execution_uid=0), check, "run-1"), "passed")

    def test_net6_expected_interruptions_keep_incomplete_observer_evidence(self):
        data = capsule_report()
        acceptance.validate_capsule(data, runtime_reference())
        self.assertEqual(data["cases"][5]["attempts"][0]["observer"]["status"], "incomplete")
        self.assertFalse(data["cases"][4]["attempts"][0]["goal_reached"])

    def test_net6_missing_duplicate_and_failed_cases_are_rejected(self):
        for mutation in (lambda data: data["cases"].pop(),
                         lambda data: data["cases"].append(copy.deepcopy(data["cases"][0])),
                         lambda data: data["cases"][0].update(status="failed")):
            data = capsule_report()
            mutation(data)
            with self.assertRaises(acceptance.AcceptanceError):
                acceptance.validate_capsule(data, runtime_reference())

    def test_net6_wrong_runtime_scope_or_claims_are_rejected(self):
        for changes in ({"guest_executions": 8}, {"qemu_launch_attempts": 10}, {"namespace_executed": False},
                        {"phase1_executed": False}, {"runtime_sha256": {}}, {"oep_proven": True},
                        {"hostile_sample_ready": True}, {"scope": "qemu_host_loopback"}, {"plugin_api": None}):
            with self.subTest(changes=changes), self.assertRaises(acceptance.AcceptanceError):
                acceptance.validate_capsule({**capsule_report(), **changes}, runtime_reference())

    def test_qemu_protocol_report_requires_guest_observation_and_cleanup(self):
        data = {"scope": "actual_qemu_components", "phase1_executed": False,
                "capsule_executed": False, "namespace_executed": False,
                "cases": [{"case": name, "status": "passed", "guest_executed": True, "plugin_api": 6,
                           "observer_status": "correlated", "cleanup_status": "cleaned"}
                          for name in acceptance.CAPSULE_CASES[:4]]}
        acceptance.validate_qemu_components(data, {"observer": {"plugin_api": 6}})
        for changes in ({"guest_executed": False}, {"observer_status": "incomplete"},
                        {"cleanup_status": "failed"}, {"plugin_api": 4}):
            broken = copy.deepcopy(data)
            broken["cases"][0].update(changes)
            with self.subTest(changes=changes), self.assertRaises(acceptance.AcceptanceError):
                acceptance.validate_qemu_components(broken, {"observer": {"plugin_api": 6}})

    def test_net6_leaks_wrong_goal_and_missing_retirement_are_rejected(self):
        for changes in ({"network_cleanup": "failed"}, {"namespace_removed": False}, {"veth_removed": False},
                        {"capsule_tree_empty": False}, {"phase1_retired": False}, {"goal_reached": False},
                        {"termination_reason": "network_runtime_owner_lost"}, {"observer": {"status": "incomplete"}}):
            with self.subTest(changes=changes):
                data = capsule_report()
                data["cases"][0]["attempts"][0].update(changes)
                with self.assertRaises(acceptance.AcceptanceError):
                    acceptance.validate_capsule(data, runtime_reference())

    def test_net6_repair_needs_two_executions_and_changed_outcome(self):
        data = capsule_report()
        data["cases"][-1]["attempts"][0]["goal_reached"] = True
        with self.assertRaises(acceptance.AcceptanceError):
            acceptance.validate_capsule(data, runtime_reference())
        data = capsule_report()
        data["cases"][-1]["store_unchanged"] = False
        with self.assertRaises(acceptance.AcceptanceError):
            acceptance.validate_capsule(data, runtime_reference())

    def test_loopback_recording_cannot_claim_full_namespace_acceptance(self):
        check = next(c for c in acceptance.CHECKS if c.name == "record_replay")
        data = {"status": "passed", "prebuilt_validated": True, "synthesis_binding_verified": True,
                "upstream_stopped_before_replay": True, "corrupt_capture_rejected": True, "sandbox_executed": False}
        self.assertEqual(acceptance.validate_report(check, data, "component", "run-1", {}), "passed")
        with self.assertRaises(acceptance.AcceptanceError):
            acceptance.validate_report(check, data, "full", "run-1", {})

    def test_session_suite_requires_all_thirteen_cases(self):
        check = next(c for c in acceptance.CHECKS if c.name == "sessions")
        data = {"status": "passed", "phase1_executed": False, "capsule_executed": False,
                "namespace_executed": False, "guest_executions": 26,
                "cases": [{"case": name, "status": "passed", "store_unchanged": True} for name in acceptance.SESSION_CASES]}
        self.assertEqual(acceptance.validate_report(check, data, "full", "run-1", {}), "passed")
        data["cases"].pop()
        with self.assertRaises(acceptance.AcceptanceError):
            acceptance.validate_report(check, data, "full", "run-1", {})

    def test_source_inventory_ignores_workdir_but_detects_source_changes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "taintforge_env").mkdir()
            source = root / "taintforge_env/module.py"
            source.write_text("value = 1\n")
            before = acceptance.source_identity(root)
            (root / "workdir").mkdir()
            (root / "workdir/report.json").write_text("{}")
            self.assertEqual(acceptance.source_identity(root), before)
            source.write_text("value = 2\n")
            self.assertNotEqual(acceptance.source_identity(root), before)

    def test_source_symlinks_are_not_silently_followed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "scripts").mkdir()
            (root / "scripts/external.py").symlink_to("/etc/passwd")
            with self.assertRaises(acceptance.AcceptanceError):
                acceptance.source_identity(root)

    def test_component_commands_do_not_inherit_guest_report_environment(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with patch.dict(os.environ, {"TF_NET6_COMPONENT_REPORT": "/old/report.json", "TF_NET6_QEMU": "/old/qemu"}):
                command, env, report = acceptance.command_for(acceptance.CHECKS[0], root, root, "component", {}, "run-1")
            self.assertNotIn("TF_NET6_COMPONENT_REPORT", env)
            self.assertNotIn("TF_NET6_QEMU", env)
            self.assertEqual(report.stat().st_uid, os.geteuid())
            self.assertIn("run-1", command)

    def test_full_commands_require_the_existing_privileged_modes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name, argument in (("record_replay", "--sandbox"), ("dns_udp_replay", "--sandbox"),
                                   ("runtime", "--privileged"), ("capsule", "--plugin")):
                check = next(c for c in acceptance.CHECKS if c.name == name)
                command, env, report = acceptance.command_for(check, root, root, "full", runtime_reference(), "run-1")
                self.assertIn(argument, command)

    def test_child_process_group_keeps_the_callers_session(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            code = "import json, os; print(json.dumps([os.getpid(), os.getpgrp(), os.getsid(0)]))"
            status = acceptance.run_child([sys.executable, "-c", code], dict(os.environ), root,
                                          root / "stdout.log", root / "stderr.log")
            self.assertEqual(status, 0)
            pid, group, session = json.loads((root / "stdout.log").read_text())
            self.assertEqual(pid, group)
            self.assertEqual(session, os.getsid(0))

    def test_interrupted_child_gets_a_graceful_signal_in_its_own_group(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with patch.object(acceptance.subprocess, "Popen") as popen, patch.object(acceptance.os, "killpg") as kill:
                process = popen.return_value
                process.pid = 456789
                process.poll.return_value = None
                process.wait.side_effect = [KeyboardInterrupt, 0]
                with self.assertRaises(KeyboardInterrupt):
                    acceptance.run_child([sys.executable], dict(os.environ), root, root / "out", root / "err")
                kill.assert_called_once_with(process.pid, acceptance.signal.SIGINT)
                self.assertEqual(popen.call_args.kwargs["process_group"], 0)


class AcceptanceRunnerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.project = self.root / "repo"
        (self.project / "examples").mkdir(parents=True)
        (self.project / "taintforge_env").mkdir()
        self.source = self.project / "taintforge_env/sample.py"
        self.source.write_text("value = 1\n")
        (self.project / acceptance.BASELINE_PATH).write_text(json.dumps({"schema_version": 1,
            "reference": "NET-6 routecheck 2026-11-11", "files": {"taintforge_env/sample.py": acceptance.digest(self.source)}}))
        self.check = acceptance.Check("unit", "fixture", "component", tests=("fixture",), component=True)

    def run_fixture(self, action=None, problems=(), profile="full"):
        def child(command, env, project, stdout, stderr):
            report_path = Path(command[command.index("--report") + 1])
            run_id = command[command.index("--run-id") + 1]
            data = unit_report(self.check, run_id)
            stdout.write_text("")
            stderr.write_text("")
            if action:
                action(data)
            if data is not None:
                report_path.write_text(json.dumps(data))
            return 0
        with patch.object(acceptance, "CHECKS", (self.check,)), \
             patch.object(acceptance, "prerequisites", return_value=list(problems)), \
             patch.object(acceptance, "run_child", side_effect=child):
            return acceptance.run_acceptance(self.project, self.root / "out", profile=profile)

    def test_success_records_fresh_reports_logs_and_source_identity(self):
        report = self.run_fixture()
        self.assertEqual(report["status"], "passed")
        self.assertTrue(report["source"]["unchanged"])
        self.assertTrue(report["runtime_unchanged"])
        child = report["checks"][0]
        self.assertEqual(child["report_sha256"], acceptance.digest(self.root / "out" / child["report"]))
        self.assertEqual(json.loads((self.root / "out/report.json").read_text())["run_id"], report["run_id"])
        self.assertTrue((self.root / "out/report.md").is_file())

    def test_component_success_has_exit_two_and_no_full_claim(self):
        report = self.run_fixture(profile="component")
        self.assertEqual((report["status"], report["exit_code"]), ("incomplete", 2))
        self.assertFalse(report["full_acceptance"])

    def test_missing_dependency_is_blocked_without_launch(self):
        report = self.run_fixture(problems=("missing executable: sudo",))
        self.assertEqual(report["status"], "blocked")
        self.assertNotIn("command", report["checks"][0])
        self.assertFalse((self.root / "out/unit").exists())

    def test_changed_source_invalidates_an_otherwise_successful_run(self):
        report = self.run_fixture(action=lambda data: self.source.write_text("value = 2\n"))
        self.assertEqual(report["status"], "failed")
        self.assertFalse(report["source"]["unchanged"])
        self.assertTrue((self.root / "out/source-after.json").is_file())

    def test_old_unittest_report_is_rejected(self):
        report = self.run_fixture(action=lambda data: data.update(run_id="previous-run"))
        self.assertEqual(report["status"], "failed")
        self.assertIn("another invocation", report["checks"][0]["reason"])

    def test_skips_are_preserved_in_the_aggregate(self):
        report = self.run_fixture(action=lambda data: data.update(skipped=[{"test": "fixture", "detail": "requires root"}]))
        self.assertEqual(report["status"], "incomplete")
        self.assertEqual(report["checks"][0]["skipped"][0]["detail"], "requires root")

    def test_existing_output_is_never_reused(self):
        output = self.root / "out"
        output.mkdir()
        (output / "report.json").write_text("previous evidence")
        with self.assertRaises(FileExistsError):
            self.run_fixture()
        self.assertEqual((output / "report.json").read_text(), "previous evidence")

    def test_missing_baseline_stops_before_running_children(self):
        self.source.unlink()
        report = self.run_fixture()
        self.assertEqual(report["status"], "failed")
        self.assertIn("missing baseline files", report["error"])

    def test_modified_baseline_is_identified_and_current_sources_are_tested(self):
        self.source.write_text("value = 3\n")
        report = self.run_fixture()
        self.assertEqual(report["baseline"]["status"], "modified")
        self.assertEqual(report["baseline"]["modified"], ["taintforge_env/sample.py"])
        self.assertEqual(report["status"], "passed")

    def test_interruption_publishes_partial_evidence(self):
        def interrupt(data):
            raise KeyboardInterrupt
        report = self.run_fixture(action=interrupt)
        self.assertEqual((report["status"], report["exit_code"]), ("interrupted", 130))
        self.assertEqual(report["checks"][0]["status"], "interrupted")

    def test_changed_runtime_binary_invalidates_success(self):
        before = {"plugin": {"status": "recorded", "sha256": "a" * 64}}
        after = {"plugin": {"status": "recorded", "sha256": "b" * 64}}
        with patch.object(acceptance, "runtime_identity", side_effect=[before, after]):
            report = self.run_fixture()
        self.assertEqual(report["status"], "failed")
        self.assertFalse(report["runtime_unchanged"])
        self.assertEqual(report["runtime_after"], after)

    def test_bad_report_cannot_pass_with_zero_exit_status(self):
        report = self.run_fixture(action=lambda data: data.update(status="failed", failures=[{"detail": "failure"}]))
        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["checks"][0]["returncode"], 0)

    def test_failure_stops_later_checks_and_keeps_their_not_run_status(self):
        second = acceptance.Check("second", "fixture", "component", tests=("fixture",), component=True)
        with patch.object(acceptance, "CHECKS", (self.check, second)), \
             patch.object(acceptance, "prerequisites", return_value=[]), \
             patch.object(acceptance, "run_child", return_value=1) as child:
            report = acceptance.run_acceptance(self.project, self.root / "out")
        self.assertEqual(report["status"], "failed")
        child.assert_called_once()
        self.assertEqual(report["checks"][1]["status"], "not_run")
        self.assertIn("stopped after unit", report["checks"][1]["reason"])

    def test_failed_child_report_is_carried_into_the_aggregate(self):
        check = acceptance.Check("capsule", "fixture", "native", "fixture.py")
        def child(command, env, project, stdout, stderr):
            output = Path(command[command.index("--out") + 1])
            output.mkdir()
            (output / "report.json").write_text(json.dumps({"status": "failed", "cases": [
                {"case": "tcp", "status": "failed", "error": "Permission denied: /run/netns/tf-72d12aa3"}]}))
            stdout.write_text(""); stderr.write_text("")
            return 1
        with patch.object(acceptance, "CHECKS", (check,)), \
             patch.object(acceptance, "prerequisites", return_value=[]), \
             patch.object(acceptance, "runtime_identity", return_value=runtime_reference()), \
             patch.object(acceptance, "run_child", side_effect=child):
            report = acceptance.run_acceptance(self.project, self.root / "out")
        self.assertEqual(report["status"], "failed")
        self.assertIn("tcp: Permission denied: /run/netns/tf-72d12aa3", report["checks"][0]["reason"])


class UnittestWorkerTests(unittest.TestCase):
    def execute_fixture(self, body):
        fixture = type("WorkerFixture", (unittest.TestCase,), body)
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(fixture)
        with patch.object(unittest.defaultTestLoader, "loadTestsFromNames", return_value=suite), redirect_stderr(io.StringIO()):
            return worker.execute(["fixture"], "worker-run")

    def test_worker_keeps_skip_details(self):
        def skip(self):
            self.skipTest("namespace unavailable")
        data = self.execute_fixture({"test_skip": skip})
        self.assertEqual(data["status"], "incomplete")
        self.assertEqual(data["tests_run"], 1)
        self.assertEqual(data["skipped"][0]["detail"], "namespace unavailable")

    def test_worker_records_failure_instead_of_only_exit_status(self):
        def fail(self):
            self.fail("deliberate assertion")
        data = self.execute_fixture({"test_fail": fail})
        self.assertEqual(data["status"], "failed")
        self.assertIn("deliberate assertion", data["failures"][0]["detail"])

    def test_worker_rejects_an_empty_suite(self):
        data = self.execute_fixture({})
        self.assertEqual(data["status"], "incomplete")
        self.assertEqual(data["tests_run"], 0)

    def test_real_worker_preserves_precreated_report_ownership_and_mode(self):
        project = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            module = root / "net7_worker_fixture.py"
            module.write_text("import unittest\nclass Fixture(unittest.TestCase):\n    def test_ok(self):\n        self.assertEqual(2 + 3, 5)\n")
            report = root / "report.json"
            report.touch(mode=0o600)
            before = report.stat()
            process = subprocess.run([sys.executable, str(project / "scripts/run_network_acceptance_tests.py"),
                "--test", "net7_worker_fixture", "--report", str(report), "--run-id", "real-worker"],
                env={**os.environ, "PYTHONPATH": str(root)}, capture_output=True, text=True, timeout=20)
            self.assertEqual(process.returncode, 0, process.stderr)
            actual = json.loads(report.read_text())
            self.assertEqual((actual["run_id"], actual["tests_run"], actual["status"]), ("real-worker", 1, "passed"))
            self.assertEqual((report.stat().st_uid, report.stat().st_mode), (before.st_uid, before.st_mode))


if __name__ == "__main__":
    unittest.main()
