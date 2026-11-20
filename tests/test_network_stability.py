"""NET-9 contracts, read-only cleanup inspection and failure accounting."""
from __future__ import annotations

import copy
from contextlib import redirect_stdout
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from scripts import run_network_stability_e2e as runner
from taintforge_env import network_acceptance as acceptance
from taintforge_env import network_stability as stability
from taintforge_env.attempt import RunPurpose, make_attempt_id
from tests.test_network_acceptance import capsule_report, runtime_reference
from tests.test_network_capsule_sessions import native_report


def round_fixture(index):
    row = {"index": index, "status": "passed", "suites": {"capsule": capsule_report(), "capsule_sessions": native_report()}}
    for suite, data in row["suites"].items():
        for case in data["cases"]:
            case.update(audit_errors=[], cleanup_audit=[])
            for number, attempt in enumerate(stability.attempts(suite, case)):
                token = hashlib.sha256(f"{index}:{suite}:{case['case']}:{number}".encode()).hexdigest()
                attempt.update({key: token[:32] for key in stability.IDENTITIES})
                audit = {"status": "passed", **{key: attempt[key] for key in stability.IDENTITIES},
                         "checks": dict.fromkeys(stability.AUDIT_CHECKS, True), "namespace": "tf-" + token[:8],
                         "veth": "tfh" + token[:8], "unit": "taintforge-capsule-" + token[:32] + ".service",
                         "ownership_sha256": token, "responder_groups": [{"group": 12345, "start": "100"}],
                         "remaining_processes": {12345: []}}
                case["cleanup_audit"].append(audit)
            if suite == "capsule" and case["case"] == "responder_crash":
                case["fault"] = {"status": "injected", "signal": "SIGKILL", "procfs_pid": 12345,
                                 "attempt_id": attempt["attempt_id"], "namespace": audit["namespace"]}
    return row


def campaign_fixture(rounds=3):
    report = {"status": "passed", "scope": stability.SCOPE, "rounds_requested": rounds, "rounds": [],
              "full_stability": True, "source_unchanged": True, "runtime_unchanged": True,
              "phase1_executed": True, "capsule_executed": True, "namespace_executed": True,
              "guest_executions": 22 * rounds, "qemu_launch_attempts": 22 * rounds,
              "runtime_sha256": {r["resolved_path"]: r["sha256"] for r in runtime_reference().values()},
              "oep_proven": False, "hostile_sample_ready": False}
    seen = {key: set() for key in stability.IDENTITIES}
    for index in range(1, rounds + 1):
        row = round_fixture(index)
        row["semantic_sha256"] = stability.validate_round(row, runtime_reference(), seen)
        report["rounds"].append(row)
    return report


class StabilityContractTests(unittest.TestCase):
    @staticmethod
    def logical_identity(case, value, analysis=None):
        attempt = case["attempts"][0]
        attempt.update(attempt_id=value, analysis_instance_id=analysis or "phase1-" + value)
        case["cleanup_audit"][0].update(attempt_id=attempt["attempt_id"],
                                         analysis_instance_id=attempt["analysis_instance_id"])

    def test_identical_dns_contracts_in_fresh_rounds_keep_their_logical_identity(self):
        data = campaign_fixture()
        for row in data["rounds"]:
            for number, name in enumerate(("dns_udp", "dns_tcp"), 1):
                case = next(item for item in row["suites"]["capsule"]["cases"] if item["case"] == name)
                value = make_attempt_id(attempt_index=0, purpose=RunPurpose.DISCOVERY,
                    sample_sha256=str(number) * 64, environment_manifest_id="manifest-v0000-stable")
                self.logical_identity(case, value)
        stability.validate_result(json.loads(json.dumps(data)), runtime_reference())

    def test_independent_case_sessions_can_share_a_logical_contract(self):
        data = campaign_fixture()
        cases = data["rounds"][0]["suites"]["capsule"]["cases"]
        first, second = (next(item for item in cases if item["case"] == name) for name in ("dns_udp", "dns_tcp"))
        self.logical_identity(second, first["attempts"][0]["attempt_id"], first["attempts"][0]["analysis_instance_id"])
        stability.validate_result(data, runtime_reference())

    def test_a_case_session_cannot_repeat_a_logical_attempt(self):
        data = campaign_fixture()
        case = next(item for item in data["rounds"][0]["suites"]["capsule"]["cases"] if item["case"] == "repair")
        case["attempts"][1]["attempt_id"] = case["attempts"][0]["attempt_id"]
        case["cleanup_audit"][1]["attempt_id"] = case["attempts"][1]["attempt_id"]
        with self.assertRaisesRegex(ValueError, "reused or missing attempt_id"):
            stability.validate_result(data, runtime_reference())

    def test_a_case_session_cannot_repeat_an_analysis_instance(self):
        data = campaign_fixture()
        case = next(item for item in data["rounds"][0]["suites"]["capsule"]["cases"] if item["case"] == "repair")
        case["attempts"][1]["analysis_instance_id"] = case["attempts"][0]["analysis_instance_id"]
        case["cleanup_audit"][1]["analysis_instance_id"] = case["attempts"][1]["analysis_instance_id"]
        with self.assertRaisesRegex(ValueError, "reused or missing analysis_instance_id"):
            stability.validate_result(data, runtime_reference())

    def test_fresh_contracts_cannot_reuse_a_lifecycle_from_another_round(self):
        data = campaign_fixture()
        first = data["rounds"][0]["suites"]["capsule"]["cases"][0]
        second = data["rounds"][1]["suites"]["capsule"]["cases"][0]
        lifecycle = first["attempts"][0]["lifecycle_attempt"]
        second["attempts"][0]["lifecycle_attempt"] = lifecycle
        second["cleanup_audit"][0].update(lifecycle_attempt=lifecycle,
            unit="taintforge-capsule-" + lifecycle + ".service")
        with self.assertRaisesRegex(ValueError, "reused or missing lifecycle_attempt"):
            stability.validate_result(data, runtime_reference())

    def test_scoped_ids_still_have_to_match_their_cleanup_audit(self):
        for key in stability.IDENTITIES:
            data = campaign_fixture()
            case = data["rounds"][1]["suites"]["capsule"]["cases"][0]
            case["cleanup_audit"][0][key] = "foreign-identity"
            with self.subTest(key=key), self.assertRaises(ValueError):
                stability.validate_result(data, runtime_reference())

    def test_missing_or_nonstring_identities_cannot_pass(self):
        for key in stability.IDENTITIES:
            for value in (None, "", 1, False):
                data = campaign_fixture()
                case = data["rounds"][1]["suites"]["capsule"]["cases"][0]
                case["attempts"][0][key] = value
                case["cleanup_audit"][0][key] = value
                with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                    stability.validate_result(data, runtime_reference())

    def test_three_complete_rounds_pass_after_json_roundtrip(self):
        data = json.loads(json.dumps(campaign_fixture()))
        stability.validate_result(data, runtime_reference())
        check = next(c for c in acceptance.CHECKS if c.name == "stability")
        self.assertEqual(acceptance.validate_report(check, data, "full", "test", runtime_reference()), "passed")
        self.assertEqual(acceptance.CHECKS[-1].name, "stability")
        rows = [{"name": c.name, "status": "passed"} for c in acceptance.CHECKS if c.name != "stability"]
        self.assertFalse(acceptance.aggregate(rows, "full")["full_acceptance"])

    def test_short_campaign_or_missing_round_cannot_pass(self):
        for count in (1, 2):
            with self.subTest(count=count), self.assertRaises(ValueError):
                stability.validate_result(campaign_fixture(count), runtime_reference())
        data = campaign_fixture(); data["rounds"].pop()
        with self.assertRaises(ValueError): stability.validate_result(data, runtime_reference())

    def test_invalid_counts_and_claims_are_rejected(self):
        for key, value in (("rounds_requested", True), ("rounds_requested", 11), ("guest_executions", 65),
                           ("guest_executions", 66.0), ("qemu_launch_attempts", 67), ("full_stability", False),
                           ("source_unchanged", False), ("runtime_unchanged", False), ("phase1_executed", False),
                           ("oep_proven", True), ("hostile_sample_ready", True), ("scope", "component")):
            data = campaign_fixture(); data[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                stability.validate_result(data, runtime_reference())

    def test_repeated_attempts_or_reordered_rounds_are_rejected(self):
        data = campaign_fixture(); data["rounds"][1] = copy.deepcopy(data["rounds"][0]); data["rounds"][1]["index"] = 2
        with self.assertRaisesRegex(ValueError, "reused"): stability.validate_result(data, runtime_reference())
        data = campaign_fixture(); data["rounds"].reverse()
        with self.assertRaisesRegex(ValueError, "reordered"): stability.validate_result(data, runtime_reference())

    def test_missing_audit_and_false_or_nonboolean_cleanup_are_rejected(self):
        for key, value in (("namespace_removed", False), ("capsule_cgroup_empty", 1), ("host_rules_unchanged", None)):
            data = campaign_fixture()
            data["rounds"][0]["suites"]["capsule"]["cases"][0]["cleanup_audit"][0]["checks"][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): stability.validate_result(data, runtime_reference())
        data = campaign_fixture(); data["rounds"][0]["suites"]["capsule"]["cases"][0]["cleanup_audit"] = []
        with self.assertRaises(ValueError): stability.validate_result(data, runtime_reference())

    def test_audit_errors_cannot_be_hidden_by_passed_status(self):
        data = campaign_fixture()
        data["rounds"][0]["suites"]["capsule"]["cases"][0]["audit_errors"] = [{"error": "permission denied"}]
        with self.assertRaises(ValueError): stability.validate_result(data, runtime_reference())

    def test_foreign_audit_and_live_process_inventory_are_rejected(self):
        for changes in ({"attempt_id": "old-attempt"}, {"unit": "foreign.service"},
                        {"remaining_processes": {12345: [{"pid": 12346, "start": "100"}]}},
                        {"responder_groups": [{"group": True, "start": "100"}]}):
            data = campaign_fixture(); data["rounds"][0]["suites"]["capsule"]["cases"][0]["cleanup_audit"][0].update(changes)
            with self.subTest(changes=changes), self.assertRaises(ValueError): stability.validate_result(data, runtime_reference())

    def test_fault_must_match_the_owned_responder_and_attempt(self):
        for key, value in (("procfs_pid", 999), ("procfs_pid", True), ("signal", "SIGTERM"),
                           ("attempt_id", "old"), ("namespace", "tf-00000000"), ("status", "not_injected")):
            data = campaign_fixture()
            fault = next(c for c in data["rounds"][0]["suites"]["capsule"]["cases"] if c["case"] == "responder_crash")["fault"]
            fault[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): stability.validate_result(data, runtime_reference())

    def test_runtime_mismatch_bad_child_or_signature_is_rejected(self):
        for action in (lambda d: d.update(runtime_sha256={}),
                       lambda d: d["rounds"][0]["suites"]["capsule"].update(guest_executions=9.0),
                       lambda d: d["rounds"][0]["suites"]["capsule_sessions"].update(cases=[]),
                       lambda d: d["rounds"][0]["suites"]["capsule"].update(artifact_errors=["bad JSON"]),
                       lambda d: d["rounds"][0].update(semantic_sha256="0" * 64)):
            data = campaign_fixture(); action(data)
            with self.assertRaises(ValueError): stability.validate_result(data, runtime_reference())

    def test_allowed_incomplete_crash_observer_does_not_create_flakiness(self):
        data = campaign_fixture()
        for case in data["rounds"][1]["suites"]["capsule"]["cases"]:
            if case["case"] in {"responder_crash", "timeout"}:
                case["attempts"][0]["observer"]["status"] = "correlated"
        stability.validate_result(data, runtime_reference())

    def test_allowed_budget_abort_prefix_does_not_create_flakiness(self):
        data = campaign_fixture()
        for index, steps in ((1, [0]), (2, [0, 1])):
            case = next(c for c in data["rounds"][index]["suites"]["capsule_sessions"]["cases"] if c["case"] == "receive_budget")
            case["transcript"]["connections"][0]["steps"] = steps
        stability.validate_result(data, runtime_reference())
        case["transcript"]["connections"][0]["steps"] = [0, 1, 2]
        with self.assertRaises(ValueError): stability.validate_result(data, runtime_reference())


class ResourceAuditTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.run = self.root / "run"
        self.run.mkdir()
        self.plan = {"namespace_name": "tf-12345678", "veth_host": "tfh12345678", "veth_namespace": "tfn12345678",
                     "host_ip": "10.203.25.1", "namespace_ip": "10.203.25.2", "host_services": [],
                     "loopback_services": [{"name": "test"}], "catch_all_enabled": False}
        self.binding = {key: "a" * 32 for key in stability.IDENTITIES}
        self.unit = "taintforge-capsule-" + "a" * 32 + ".service"
        self.ownership = {**self.binding, "namespace": {"name": "tf-12345678", "device": 1, "inode": 2},
                          "plan": self.plan, "unit": self.unit, "processes": [{"group": 12345, "start": "100"}]}
        self.write("logs/net9_ownership.json", self.ownership)
        self.write("config/capsule_binding.json", self.binding)
        self.write("config/network_capsule_runtime.json", {"namespace": self.ownership["namespace"], "attempt_id": "a" * 32})
        self.backend = {"plan": self.plan, "state": "cleaned", "cleanup_errors": [], "host_reply_routing": None}
        self.write("config/network_backend_manifest.json", self.backend)
        self.write("logs/network_runtime_status.json", {"attempt_id": "a" * 32, "owner_closed": True,
                   "cleanup_status": "cleaned", "remaining_resources": [], "remaining_resources_total": 0,
                   "ready_listeners": 0, "budget_usage": {"active_jobs": 0}})
        self.write("logs/capsule/service.json", {"unit": self.unit, "attempt_id": "a" * 32})
        self.before = {"namespace": {"device": 10, "inode": 20}, "rules": [{"priority": 9002, "table": "vpn"}],
                       "routes": [{"dst": "default", "dev": "tun0"}], "links": [{"ifname": "tun0"}]}

    def write(self, name, data):
        path = self.run / name; path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data))

    def audit(self, after=None, namespace=False, groups=None, cgroup=True):
        with patch.object(stability, "namespace_exists", return_value=namespace), \
             patch.object(stability, "process_groups", return_value={12345: []} if groups is None else groups), \
             patch.object(stability, "cgroup_empty", return_value=cgroup):
            return stability.audit_run(self.run, self.before, after or self.before)

    def test_complete_cleanup_preserves_existing_vpn_rules(self):
        self.assertEqual(self.audit()["status"], "passed")

    def test_namespace_veth_rules_route_and_process_leaks_fail_independently(self):
        self.assertFalse(self.audit(namespace=True)["checks"]["namespace_removed"])
        self.assertFalse(self.audit(groups={12345: [{"pid": 12346, "start": "101"}]})["checks"]["responder_groups_empty"])
        self.assertFalse(self.audit(cgroup=False)["checks"]["capsule_cgroup_empty"])
        for key, value, check in (("links", {"ifname": "tfh12345678"}, "veth_removed"),
                                  ("rules", {"priority": 1, "table": "main"}, "host_rules_unchanged"),
                                  ("routes", {"dst": "10.203.25.2", "dev": "tfh12345678"}, "owned_routes_restored")):
            after = copy.deepcopy(self.before); after[key].append(value)
            with self.subTest(key=key): self.assertFalse(self.audit(after)["checks"][check])

    def test_existing_route_and_rule_order_are_preserved_as_multisets(self):
        self.before["rules"].append({"priority": 32766, "table": "main"})
        self.before["routes"].append({"dst": "10.203.25.2/32", "prefsrc": "10.203.25.1", "dev": "tun0"})
        after = copy.deepcopy(self.before); after["rules"].reverse()
        self.assertEqual(self.audit(after)["status"], "passed")
        after["rules"].append(after["rules"][0])
        self.assertEqual(self.audit(after)["status"], "failed")

    def test_permission_errors_are_not_absence(self):
        with patch.object(stability, "namespace_exists", side_effect=PermissionError("netns denied")), \
             patch.object(stability, "process_groups", return_value={12345: []}):
            with self.assertRaises(PermissionError): stability.audit_run(self.run, self.before, self.before)
        with patch.object(Path, "read_text", side_effect=PermissionError("cgroup denied")):
            with self.assertRaises(PermissionError): stability.cgroup_empty(self.unit)

    def test_unremoved_ledger_and_route_ownership_prevent_cleanup_claim(self):
        (self.run / "config/network_runtime").mkdir()
        self.assertFalse(self.audit()["checks"]["runtime_ledger_removed"])
        self.backend["host_reply_routing"] = {"status": "cleanup_failed", "remaining_resources": ["host_reply_rule"]}
        self.write("config/network_backend_manifest.json", self.backend)
        self.assertFalse(self.audit()["checks"]["backend_cleaned"])

    def test_ownership_cannot_be_rebound_to_another_manifest(self):
        self.backend["plan"] = {**self.plan, "veth_host": "tfh00000000"}
        self.write("config/network_backend_manifest.json", self.backend)
        with self.assertRaises(ValueError): self.audit()

    def test_captured_namespace_inode_must_match_the_execution_contract(self):
        self.write("config/network_capsule_runtime.json", {"namespace": {**self.ownership["namespace"], "inode": 99},
                   "attempt_id": "a" * 32})
        with self.assertRaisesRegex(ValueError, "live contract"): self.audit()

    def test_audit_rejects_an_omitted_responder_group(self):
        self.ownership["processes"] = []
        self.write("logs/net9_ownership.json", self.ownership)
        with self.assertRaisesRegex(ValueError, "incomplete"): self.audit()

    def test_real_process_group_is_seen_until_reaped(self):
        process = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(10)"], process_group=0)
        try:
            self.assertIn(process.pid, [row["pid"] for row in stability.process_groups([process.pid])[process.pid]])
        finally:
            process.terminate(); process.wait(timeout=5)
        self.assertEqual(stability.process_groups([process.pid]), {process.pid: []})

    def test_procfs_denial_does_not_hide_a_live_group(self):
        fake = self.root / "proc"; (fake / "12345").mkdir(parents=True)
        with patch.object(stability, "PROC", fake), patch.object(Path, "read_text", side_effect=PermissionError("proc denied")):
            with self.assertRaises(PermissionError): stability.process_groups([12345])

    def test_cgroup_population_checks_descendants_and_rejects_missing_field(self):
        events = self.root / "system.slice" / self.unit / "cgroup.events"
        events.parent.mkdir(parents=True)
        with patch.object(stability, "CGROUP", self.root):
            for contents, expected in (("populated 0\nfrozen 0\n", True), ("populated 1\nfrozen 0\n", False)):
                events.write_text(contents); self.assertIs(stability.cgroup_empty(self.unit), expected)
            events.write_text("frozen 0\n")
            with self.assertRaises(ValueError): stability.cgroup_empty(self.unit)
            events.unlink(); self.assertTrue(stability.cgroup_empty(self.unit))
            with self.assertRaises(ValueError): stability.cgroup_empty("../../foreign")

    def test_ip_command_failure_and_bad_json_never_mean_empty_resources(self):
        for result in (SimpleNamespace(returncode=1, stdout="", stderr="permission denied"),
                       SimpleNamespace(returncode=0, stdout="{}", stderr=""),
                       SimpleNamespace(returncode=0, stdout="invalid", stderr="")):
            with patch.object(stability.subprocess, "run", return_value=result), self.assertRaises(ValueError):
                stability._rows("-4", "rule", "show")

    def test_capture_binds_live_responder_identity_and_rejects_missing_identity(self):
        context = SimpleNamespace(run_dir=self.run, attempt_contract=SimpleNamespace(attempt_id="a" * 32))
        plan = {**self.plan, "host_services": [], "loopback_services": [{"name": "test"}], "catch_all_enabled": False}
        process = SimpleNamespace(proc_pid=12345, birth="100", poll=lambda: None)
        backend = SimpleNamespace(plan=SimpleNamespace(to_dict=lambda: plan),
                                  runtime=SimpleNamespace(attempt_id="a" * 32), processes=[process])
        with patch.object(stability, "namespace_identity", return_value=self.ownership["namespace"]):
            data = stability.capture_ownership(context, backend)
            self.assertEqual(data["processes"], [{"group": 12345, "start": "100"}])
            process.birth = None
            with self.assertRaises(ValueError): stability.capture_ownership(context, backend)
            backend.processes = []
            with self.assertRaises(ValueError): stability.capture_ownership(context, backend)
            plan["loopback_services"] = []
            self.assertEqual(stability.capture_ownership(context, backend)["processes"], [])


class AuditedCaseTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name) / "tcp"
        self.case = round_fixture(1)["suites"]["capsule"]["cases"][0]
        self.run = self.root / "pipeline/session/iterations/0000/run"

    def execute(self, *, failure=None, audit_failed=False, inspection_denied=False):
        def original(*args, **kwargs):
            self.run.mkdir(parents=True)
            self.assertIs(kwargs["runner_factory"], runner.AuditedRunner)
            if failure is not None: raise failure
            return copy.deepcopy(self.case)
        audit = copy.deepcopy(self.case["cleanup_audit"][0])
        if audit_failed:
            audit["status"] = "failed"
            audit["checks"]["responder_groups_empty"] = False
        snapshots = [{}, PermissionError("inspection denied")] if inspection_denied else [{}, {}]
        with patch.object(runner, "host_snapshot", side_effect=snapshots), \
             patch.object(runner.net6, "run_case", side_effect=original), \
             patch.object(runner, "audit_run", return_value=audit) as inspect:
            try:
                return runner.run_audited_case(self.root, "capsule", "tcp", [None] * 3)
            finally:
                if not inspection_denied: inspect.assert_called_once()

    def test_independent_audit_can_veto_a_successful_native_case(self):
        row = self.execute(audit_failed=True)
        self.assertEqual(row["status"], "failed")
        self.assertIn("cleanup audit failed", row["error"])
        saved = json.loads((self.root.parent / "tcp.result.json").read_text())
        self.assertFalse(saved["cleanup_audit"][0]["checks"]["responder_groups_empty"])

    def test_original_failure_still_audits_partial_resources(self):
        row = self.execute(failure=RuntimeError("native failure"))
        self.assertEqual(row["status"], "failed")
        self.assertIn("native failure", row["error"])
        self.assertEqual(len(row["cleanup_audit"]), 1)

    def test_interrupt_saves_case_evidence_then_propagates(self):
        with self.assertRaises(KeyboardInterrupt): self.execute(failure=KeyboardInterrupt())
        saved = json.loads((self.root.parent / "tcp.result.json").read_text())
        self.assertEqual(saved["status"], "interrupted")
        self.assertEqual(len(saved["cleanup_audit"]), 1)

    def test_failed_postrun_inspection_cannot_pass(self):
        row = self.execute(inspection_denied=True)
        self.assertEqual(row["status"], "failed")
        self.assertIn("inspection denied", row["error"])

    def test_success_persists_both_host_snapshots_and_audit(self):
        row = self.execute()
        self.assertEqual(row["status"], "passed")
        for name in ("tcp.before.json", "tcp.after.json", "tcp.result.json"):
            self.assertTrue((self.root.parent / name).is_file())


class StabilityRunnerTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def run_fixture(self, *, rounds=3, failed=False, interrupted=False, source_changed=False):
        def case(root, suite, name, binaries):
            index = int(root.parent.parent.name.split("-")[1])
            if interrupted: raise KeyboardInterrupt
            result = next(c for c in round_fixture(index)["suites"][suite]["cases"] if c["case"] == name)
            if failed: result.update(status="failed", error="injected case failure")
            return result
        def inventory(root):
            return {"guest_executions": 9 if root.name == "capsule" else 13,
                    "qemu_launch_attempts": 9 if root.name == "capsule" else 13,
                    "phase1_executed": True, "capsule_executed": True, "namespace_executed": True, "artifact_errors": []}
        source = {"sha256": "a" * 64, "files": {}}
        with patch.object(runner, "runtime_identity", return_value=runtime_reference()), \
             patch.object(runner, "prerequisites", return_value=[]), patch.object(runner, "preflight"), \
             patch.object(runner.net6, "check_runtime_inputs", return_value={"plugin_api": 6}), \
             patch.object(runner.net6, "validate_observer", return_value={"plugin_api": 6}), \
             patch.object(runner, "source_identity", side_effect=[source, {**source, "sha256": "b" * 64} if source_changed else source]), \
             patch.object(runner, "run_audited_case", side_effect=case) as cases, \
             patch.object(runner, "execution_inventory", side_effect=inventory), redirect_stdout(io.StringIO()):
            report = runner.run_campaign(self.root / "out", qemu=Path("qemu"), plugin=Path("plugin"), observer=Path("observer"), rounds=rounds)
            return report, cases.call_count

    def test_complete_campaign_writes_66_execution_report(self):
        report, calls = self.run_fixture()
        self.assertEqual((report["status"], report["guest_executions"], calls), ("passed", 66, 63))
        self.assertTrue(report["full_stability"])
        self.assertEqual(json.loads((self.root / "out/report.json").read_text())["status"], "passed")

    def test_short_diagnostic_run_is_incomplete(self):
        report, calls = self.run_fixture(rounds=1)
        self.assertEqual((report["status"], report["exit_code"], calls), ("incomplete", 2, 21))
        self.assertFalse(report["full_stability"])

    def test_failure_stops_without_retrying_or_hiding_partial_round(self):
        report, calls = self.run_fixture(failed=True)
        self.assertEqual((report["status"], calls, len(report["rounds"])), ("failed", 1, 1))
        self.assertEqual(report["rounds"][0]["status"], "failed")
        self.assertIn("injected case failure", report["error"])

    def test_interruption_keeps_partial_report_and_no_acceptance_claim(self):
        report, calls = self.run_fixture(interrupted=True)
        self.assertEqual((report["status"], report["exit_code"], calls), ("interrupted", 130, 1))
        self.assertFalse(report["full_stability"])

    def test_source_change_invalidates_completed_rounds(self):
        report, calls = self.run_fixture(source_changed=True)
        self.assertEqual(report["status"], "failed")
        self.assertFalse(report["source_unchanged"])

    def test_blocked_preflight_does_not_launch_or_claim_executions(self):
        with patch.object(runner, "runtime_identity", return_value={}), \
             patch.object(runner, "prerequisites", return_value=["missing sudo"]), \
             patch.object(runner, "run_audited_case") as child:
            report = runner.run_campaign(self.root / "out", qemu=None, plugin=None, observer=None)
        child.assert_not_called()
        self.assertEqual((report["status"], report["exit_code"], report["guest_executions"]), ("blocked", 2, 0))

    def test_invalid_rounds_or_existing_output_do_not_overwrite_evidence(self):
        for value in (True, 0, 11, 3.0):
            with self.assertRaises(ValueError): runner.run_campaign(self.root / "out", qemu=None, plugin=None, observer=None, rounds=value)
        self.assertFalse((self.root / "out").exists())
        (self.root / "out").mkdir(); (self.root / "out/report.json").write_text("previous evidence")
        with self.assertRaises(FileExistsError): runner.run_campaign(self.root / "out", qemu=None, plugin=None, observer=None)
        self.assertEqual((self.root / "out/report.json").read_text(), "previous evidence")

    def test_aggregate_passes_all_binaries_and_requires_native_preflight(self):
        check = next(c for c in acceptance.CHECKS if c.name == "stability")
        command, env, path = acceptance.command_for(check, self.root, self.root, "full", runtime_reference(), "run")
        for name in ("qemu", "plugin", "observer"):
            self.assertEqual(command[command.index("--" + name) + 1], "/runtime/" + name)
        self.assertTrue(check.namespace and check.qemu and not check.component)
        runtime = runtime_reference(); runtime["plugin"] = {"status": "not_supplied"}
        with patch.object(acceptance.shutil, "which", return_value=None):
            self.assertIn("plugin: not_supplied", acceptance.prerequisites(check, "full", runtime))

    def test_missing_or_malformed_artifacts_cannot_invent_guest_execution(self):
        data = runner.execution_inventory(self.root)
        self.assertEqual(data["guest_executions"], 0)
        path = self.root / "tcp/pipeline/session/iterations/0000/run/config/phase1_result.json"
        path.parent.mkdir(parents=True); path.write_text("invalid JSON")
        data = runner.execution_inventory(self.root)
        self.assertEqual(data["guest_executions"], 0)
        self.assertEqual(len(data["artifact_errors"]), 1)


if __name__ == "__main__":
    unittest.main()
