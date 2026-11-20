from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
import tempfile
import unittest

from taintforge_env.network_policy import NetworkPolicy, CatchAllPolicy
from taintforge_env.network_repair import NetworkRepairPolicy, NetworkRepairError, effective_policy, digest
from taintforge_env.observations import ObservationBundle
from taintforge_env.repair_applier import RepairApplier, RepairApplierConfig, RepairApplicationError
from taintforge_env.repair_planner import RepairPlanner
from taintforge_env.requirement_extractor import RequirementExtractor
from taintforge_env.replay_store import ReplayStore
from taintforge_env.synthesis_loop import EnvironmentSynthesisLoop, SynthesisLoopConfig, SynthesisLoopError
from taintforge_env.iteration_controller import IterationController
from taintforge_env.environment_manifest import EnvironmentManifestStore
from tests.elf_fixture import write_elf


PROJECT = Path(__file__).resolve().parents[1]


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n")


def observed(root, resource="tcp://192.0.2.10:4444"):
    from taintforge_env.network_repair import endpoint
    transport, host, port = endpoint(resource)
    event = {"event": "syscall", "syscall": "connect", "execution_context": "guest",
        "errno": "ECONNREFUSED", "return_value": -1, "remote_ip": host, "remote_port": port,
        "transport": transport, "endpoint_resolution": "observed", "source_file": "strace.24",
        "line_number": 2, "pid": 24, "raw": "observed failed connect"}
    return RequirementExtractor().extract(ObservationBundle(run_dir=root, syscall_events=(event,)))


class NetworkRepairTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.store = ReplayStore(self.root / "store")
        self.store.add(transport="tcp", remote_ip="192.0.2.10", remote_port=4444,
                       request_bytes=b"HELLO\n", response_bytes=b"OK\n")
        self.policy_path = self.root / "authorization.json"
        self.raw = {"schema_version": 1, "network_mode": "replay",
            "replay_store": {"path": str(self.store.root), "sha256": self.store.validate()["store_sha256"]},
            "rules": [{"resource": "tcp://192.0.2.10:4444", "provider": "replay"}]}
        write(self.policy_path, self.raw)
        self.policy = NetworkRepairPolicy.load(self.policy_path)
        self.requirements_path = self.root / "requirements.json"
        self.report = observed(self.root)
        self.report.save(self.requirements_path)
        self.plan_path = self.root / "plan.json"
        self.rootfs = self.root / "rootfs"
        self.rootfs.mkdir()

    def plan(self, policy=True, active=None):
        return RepairPlanner(network_repair_policy=self.policy if policy else None,
            network_policy=active).plan_file(self.requirements_path, self.plan_path)

    def apply(self, policy=True, dry_run=False):
        return RepairApplier(RepairApplierConfig(network_repair_policy=self.policy if policy else None)).apply_file(
            plan_path=self.plan_path, requirements_path=self.requirements_path, rootfs=self.rootfs,
            out_path=self.root / "application.json", dry_run=dry_run)

    def test_default_planning_remains_review_only(self):
        decision = self.plan(False).decisions[0]
        self.assertFalse(decision.automatic_allowed)
        self.assertEqual(decision.disposition.value, "review_required")

    def test_exact_authorization_selects_existing_exchange(self):
        decision = self.plan().decisions[0]
        selection = dict(decision.parameters)["network_repair"]
        self.assertTrue(decision.automatic_allowed)
        self.assertEqual(selection["entry_ids"], [self.store.load_entries()[0].entry_id])
        self.assertEqual(selection["policy_sha256"], self.policy.sha256)

    def test_unlisted_endpoint_stays_review_only(self):
        observed(self.root, "tcp://192.0.2.11:4444").save(self.requirements_path)
        self.assertFalse(self.plan().decisions[0].automatic_allowed)

    def test_wrong_transport_cannot_use_tcp_authorization(self):
        observed(self.root, "udp://192.0.2.10:4444").save(self.requirements_path)
        self.assertFalse(self.plan().decisions[0].automatic_allowed)

    def test_missing_exchange_is_explained_without_automatic_application(self):
        self.raw["rules"][0]["resource"] = "tcp://192.0.2.11:4444"
        write(self.policy_path, self.raw)
        self.policy = NetworkRepairPolicy.load(self.policy_path)
        observed(self.root, "tcp://192.0.2.11:4444").save(self.requirements_path)
        decision = self.plan().decisions[0]
        self.assertFalse(decision.automatic_allowed)
        self.assertIn("does not cover", decision.reason)

    def test_unknown_transport_stays_manual_with_authorization(self):
        event = {"event": "syscall", "syscall": "connect", "execution_context": "guest",
            "errno": "ECONNREFUSED", "return_value": -1, "remote_ip": "192.0.2.10",
            "remote_port": 4444, "transport": "unknown"}
        RequirementExtractor().extract(ObservationBundle(run_dir=self.root, syscall_events=(event,))).save(self.requirements_path)
        self.assertEqual(self.plan().decisions[0].disposition.value, "manual_analysis")

    def test_existing_service_is_not_automatically_applied_again(self):
        from taintforge_env.network_policy import NetworkServicePolicy
        active = NetworkPolicy(services=[NetworkServicePolicy(**self.policy.selection(self.report.requirements[0].resource)["service"])])
        decision = self.plan(active=active).decisions[0]
        self.assertFalse(decision.automatic_allowed)
        self.assertIn("already configured", decision.reason)

    def test_network_configuration_application_preserves_rootfs_and_store(self):
        self.plan()
        before = {str(p.relative_to(self.store.root)): p.read_bytes() for p in self.store.root.rglob("*") if p.is_file()}
        result = self.apply()
        self.assertEqual(result.results[0].status.value, "applied")
        self.assertEqual(list(self.rootfs.iterdir()), [])
        self.assertEqual(before, {str(p.relative_to(self.store.root)): p.read_bytes() for p in self.store.root.rglob("*") if p.is_file()})
        self.assertIsNotNone(result.results[0].network_service)

    def test_dry_run_does_not_claim_applied_configuration(self):
        self.plan()
        result = self.apply(dry_run=True)
        self.assertEqual(result.state.value, "dry_run")
        self.assertEqual(result.results[0].status.value, "planned")
        self.assertEqual(list(self.rootfs.iterdir()), [])

    def test_automatic_network_action_needs_applier_authorization(self):
        self.plan()
        with self.assertRaises(RepairApplicationError):
            self.apply(False)

    def test_changed_policy_after_planning_is_rejected_before_directory_creation(self):
        self.plan()
        self.policy_path.write_text(self.policy_path.read_text() + " ")
        with self.assertRaises(RepairApplicationError):
            self.apply()
        self.assertEqual(list(self.rootfs.iterdir()), [])

    def test_changed_replay_blob_is_rejected(self):
        self.plan()
        blob = self.store.response_blob_path(self.store.load_entries()[0])
        blob.write_bytes(b"changed")
        with self.assertRaises(RepairApplicationError):
            self.apply()

    def test_forged_selected_service_is_rejected(self):
        plan = self.plan()
        decision = plan.decisions[0]
        parameters = dict(decision.parameters)
        parameters["network_repair"]["service"]["remote_port"] = 5555
        replace(plan, decisions=(replace(decision, parameters=tuple(sorted(parameters.items()))),)).save(self.plan_path)
        with self.assertRaises(RepairApplicationError):
            self.apply()

    def test_policy_strict_schema_duplicate_and_symlink_checks(self):
        for field, value in [("schema_version", True), ("network_mode", "record"), ("command", "/bin/true")]:
            with self.subTest(field=field):
                bad = {**self.raw, field: value}
                write(self.policy_path, bad)
                with self.assertRaises(NetworkRepairError):
                    NetworkRepairPolicy.load(self.policy_path)
        self.policy_path.write_text('{"schema_version":1,"schema_version":1}')
        with self.assertRaises(NetworkRepairError):
            NetworkRepairPolicy.load(self.policy_path)
        link = self.root / "link.json"
        link.symlink_to(self.policy_path)
        with self.assertRaises(NetworkRepairError):
            NetworkRepairPolicy.load(link)

    def test_explicit_dns_provider_without_upstream(self):
        write(self.policy_path, {"schema_version": 1, "network_mode": "controlled", "rules": [
            {"resource": "udp://192.0.2.53:53", "provider": "dns_records",
             "dns_records": {"test.example": ["192.0.2.10"]}}]})
        self.policy = NetworkRepairPolicy.load(self.policy_path)
        observed(self.root, "udp://192.0.2.53:53").save(self.requirements_path)
        decision = self.plan().decisions[0]
        self.assertTrue(decision.automatic_allowed)
        self.assertEqual(dict(decision.parameters)["network_repair"]["service"]["protocol_hint"], "dns")

    def initialize_loop(self):
        binary = write_elf(self.root / "sample", arch="x86_64")
        (self.rootfs / "bin").mkdir()
        (self.rootfs / "proc").mkdir()
        guest = self.rootfs / "bin/unpacked.elf"
        guest.write_bytes(binary.read_bytes())
        guest.chmod(0o755)
        template = self.root / "template"
        write(template / "config/runtime.json", {"arch": "x86_64", "host_binary": str(binary),
            "guest_binary": "/bin/unpacked.elf", "qemu_required": False, "rootfs": str(self.rootfs)})
        write(template / "config/network_policy.json", NetworkPolicy(
            catch_all=CatchAllPolicy(enabled=False, udp_enabled=False)).to_dict())
        self.loop_config = SynthesisLoopConfig(session_dir=self.root / "session", template_run_dir=template,
            project_root=PROJECT, snapshot_store=self.root / "snapshots", seed_rootfs=self.rootfs,
            network_mode="replay", replay_store_path=self.store.root,
            network_repair_policy_path=self.policy_path, initialize_only=True)
        EnvironmentSynthesisLoop(self.loop_config).run()
        return IterationController(self.loop_config.session_dir)

    def test_network_only_repair_derives_new_manifest_and_attempt(self):
        controller = self.initialize_loop()
        first = controller.prepare_next()
        artifacts = self.root / "first-artifacts"
        artifacts.mkdir()
        self.report.save(artifacts / "runtime_requirements.json")
        RepairPlanner(network_repair_policy=self.policy).plan_file(
            artifacts / "runtime_requirements.json", artifacts / "repair_plan.json")
        write(artifacts / "syscall_events.jsonl", {})
        controller.complete_iteration(iteration_index=0, artifacts_dir=artifacts, guest_exit_code=1)
        second = controller.prepare_next()
        self.assertEqual(first.environment_snapshot_id, second.environment_snapshot_id)
        self.assertNotEqual(first.environment_manifest_id, second.environment_manifest_id)
        self.assertNotEqual(first.attempt_id, second.attempt_id)
        session = controller.verify()
        manifest = EnvironmentManifestStore(session.environment_manifest_store).load(1)
        self.assertEqual(manifest.entries[0].kind.value, "network_service")
        self.assertEqual(manifest.entries[0].confidence.value, "hypothesis")
        effective = effective_policy(NetworkPolicy(services=[]), manifest, self.policy)
        self.assertEqual(effective.services[0].remote_port, 4444)
        self.assertEqual(manifest.entries[0].value_sha256, digest(self.policy.selection("tcp://192.0.2.10:4444")))
        from taintforge_env.prebuilt_runner import PrebuiltRootfsRunner, PrebuiltRunnerConfig
        runner = PrebuiltRootfsRunner(PrebuiltRunnerConfig(session_dir=self.loop_config.session_dir,
            iteration_index=1, template_run_dir=self.loop_config.template_run_dir, project_root=PROJECT,
            network_mode="replay", replay_store_path=self.store.root))
        context = runner.validate()
        runner._prepare_run_directory(context)
        raw = json.loads((context.run_dir / "config/network_policy.json").read_text())
        self.assertEqual(raw["services"][0]["remote_ip"], "192.0.2.10")
        self.assertTrue((context.run_dir / "config/network_repair_policy.json").is_file())
        requested = runner._create_network_backend(context)
        self.assertTrue(requested.config.allow_empty_replay)

    def test_session_binding_rejects_policy_change(self):
        self.initialize_loop()
        self.policy_path.write_text(self.policy_path.read_text() + " ")
        with self.assertRaises(SynthesisLoopError):
            EnvironmentSynthesisLoop.verify_session(self.loop_config.session_dir)

    def test_applied_service_evidence_cannot_be_changed(self):
        self.test_network_only_repair_derives_new_manifest_and_attempt()
        path = self.loop_config.session_dir / "iterations/0001/repair_application.json"
        path.write_text(path.read_text() + " ")
        from taintforge_env.iteration_controller import IterationControllerError
        with self.assertRaisesRegex(IterationControllerError, "application changed"):
            IterationController(self.loop_config.session_dir).verify()

    def test_network_preflight_failure_does_not_apply_directory_repairs(self):
        from taintforge_env.requirements import (RuntimeRequirement, RequirementKind, RequirementStatus,
            BlockingAssessment, make_requirement_id)
        directory = RuntimeRequirement(requirement_id=make_requirement_id(kind=RequirementKind.FILESYSTEM,
            resource="/var/lib/net3", operation="directory_exists"), kind=RequirementKind.FILESYSTEM, resource="/var/lib/net3",
            operation="directory_exists", status=RequirementStatus.UNMET, blocking=BlockingAssessment.LIKELY,
            confidence=1.0, repairable=True, errno="ENOENT", evidence=(), details=())
        replace(self.report, requirements=self.report.requirements + (directory,)).save(self.requirements_path)
        self.plan()
        self.store.response_blob_path(self.store.load_entries()[0]).write_bytes(b"changed")
        with self.assertRaises(RepairApplicationError):
            self.apply()
        self.assertEqual(list(self.rootfs.iterdir()), [])

    def test_store_duplicates_and_boolean_metadata_are_rejected(self):
        original = self.store.index_path.read_bytes()
        for change in ("duplicate", "boolean", "identity"):
            with self.subTest(change=change):
                value = json.loads(original)
                if change == "duplicate":
                    value["entries"].append(value["entries"][0])
                elif change == "boolean":
                    value["entries"][0]["response"]["close_after_send"] = "false"
                else:
                    value["entries"][0]["request"]["transport"] = {}
                write(self.store.index_path, value)
                with self.assertRaises(NetworkRepairError):
                    self.policy.verify_store()
        self.store.index_path.write_bytes(original)

    def test_incompatible_mode_is_rejected_before_session_creation(self):
        self.initialize_loop()
        import shutil
        shutil.rmtree(self.loop_config.session_dir)
        from dataclasses import replace
        config = replace(self.loop_config, network_mode="controlled", replay_store_path=None)
        with self.assertRaises(SynthesisLoopError):
            EnvironmentSynthesisLoop(config).run()
        self.assertFalse(config.session_dir.exists())

    def test_missing_authorization_store_and_ambiguous_tcp_prefixes_stay_closed(self):
        original = self.store.index_path.read_bytes()
        self.store.add(transport="tcp", remote_ip="192.0.2.10", remote_port=4444,
            request_bytes=b"HELLO\nMORE", response_bytes=b"OTHER")
        decision = self.plan().decisions[0]
        self.assertFalse(decision.automatic_allowed)
        self.assertIn("replay store", decision.reason)
        self.store.index_path.write_bytes(original)
        self.store.index_path.unlink()
        self.assertFalse(self.plan().decisions[0].automatic_allowed)

    def test_dns_records_reject_commands_boolean_addresses_and_bad_names(self):
        for rule in (
            {"resource": "udp://192.0.2.53:53", "provider": "dns_records", "command": "/bin/true"},
            {"resource": "udp://192.0.2.53:53", "provider": "dns_records", "dns_records": {"test.example": [True]}},
            {"resource": "udp://192.0.2.53:53", "provider": "dns_records", "dns_records": {"Test.Example": ["192.0.2.7"]}},
        ):
            write(self.policy_path, {"schema_version": 1, "network_mode": "controlled", "rules": [rule]})
            with self.assertRaises(NetworkRepairError):
                NetworkRepairPolicy.load(self.policy_path)

    def test_dns_replay_selection_validates_canonical_exchange(self):
        from taintforge_env.dns_protocol import build_query, canonical_exchange
        from tests.test_dns_udp_replay import dns_answer
        query = build_query("net3.example")
        request, response = canonical_exchange(query, dns_answer(query, "192.0.2.7"))
        self.store.add(transport="udp", remote_ip="192.0.2.53", remote_port=53,
            request_bytes=request, response_bytes=response, protocol_hint="dns")
        self.raw["rules"] = [{"resource": "udp://192.0.2.53:53", "provider": "replay", "protocol_hint": "dns"}]
        self.raw["replay_store"]["sha256"] = self.store.validate()["store_sha256"]
        write(self.policy_path, self.raw)
        self.policy = NetworkRepairPolicy.load(self.policy_path)
        observed(self.root, "udp://192.0.2.53:53").save(self.requirements_path)
        decision = self.plan().decisions[0]
        self.assertTrue(decision.automatic_allowed)
        self.assertEqual(dict(decision.parameters)["network_repair"]["service"]["protocol_hint"], "dns")


if __name__ == "__main__":
    unittest.main()
