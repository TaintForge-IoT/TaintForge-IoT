from __future__ import annotations

from dataclasses import replace
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from scripts.reprocess_prebuilt_logs import reprocess
from taintforge_env.observations import ObservationBundle
from taintforge_env.qemu_strace_parser import parse_qemu_strace
from taintforge_env.repair_plan import RepairActionKind, RepairDisposition
from taintforge_env.repair_planner import RepairPlanner
from taintforge_env.requirement_extractor import RequirementExtractor
from taintforge_env.requirements import RequirementKind, RequirementReport, RequirementStatus


POINTER_CONNECT = "24 connect(5,0x40800d3c,16) = -1 errno=111 (Connection refused)"


class UnresolvedNetworkRequirementTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def event(self, **overrides):
        return {
            "event": "syscall", "syscall": "connect", "category": "network",
            "execution_context": "guest", "errno": "ECONNREFUSED", "return_value": -1,
            "args": "5,0x40800d3c,16", "raw": POINTER_CONNECT, "pid": 24,
            "remote_ip": None, "remote_port": None,
            "source_file": "qemu_strace.log", "line_number": 142546767,
            **overrides,
        }

    def extract(self, *events):
        bundle = ObservationBundle(run_dir=self.root, syscall_events=tuple(events))
        return RequirementExtractor().extract(bundle)

    def plan(self, report):
        source = self.root / "requirements.json"
        report.save(source)
        loaded = RequirementReport.load(source)
        self.assertEqual(loaded.requirements, report.requirements)
        return RepairPlanner().plan_file(source, self.root / "plan.json")

    def test_real_qemu_pointer_syntax_roundtrips_to_manual_requirement(self):
        raw = self.root / "qemu_strace.log"
        raw.write_text(POINTER_CONNECT + "\n")
        normalized = self.root / "syscall_events.jsonl"
        parse_qemu_strace(raw, normalized, target_arch="i386")
        event = json.loads(normalized.read_text())
        report = self.extract(event)
        self.assertEqual(len(report.requirements), 1)
        requirement = report.requirements[0]
        self.assertEqual(requirement.kind, RequirementKind.NETWORK)
        self.assertEqual(requirement.operation, "connect")
        self.assertEqual(requirement.status, RequirementStatus.UNMET)
        self.assertEqual(requirement.errno, "ECONNREFUSED")
        self.assertFalse(requirement.repairable)
        self.assertEqual(requirement.evidence[0].raw, POINTER_CONNECT)
        self.assertEqual(requirement.evidence[0].event_index, 0)
        details = dict(requirement.details)
        self.assertEqual(details["endpoint_resolution"], "unresolved")
        self.assertEqual(details["transport"], "unknown")
        self.assertEqual(details["pid"], "24")
        self.assertEqual(details["source_file"], "qemu_strace.log")
        self.assertEqual(details["line_number"], "1")
        self.assertNotIn("remote_ip", details)
        self.assertNotIn("remote_port", details)
        decision = self.plan(report).decisions[0]
        self.assertEqual(decision.action, RepairActionKind.NONE)
        self.assertEqual(decision.disposition, RepairDisposition.MANUAL_ANALYSIS)
        self.assertFalse(decision.automatic_allowed)
        self.assertEqual(decision.parameters, ())
        self.assertIn("no complete remote IP and port", decision.reason)

    def test_partial_endpoint_preserves_only_observed_components(self):
        cases = (
            ({}, "remote_ip,remote_port", {}),
            ({"remote_ip": "192.0.2.10"}, "remote_port", {"remote_ip": "192.0.2.10"}),
            ({"remote_port": 443}, "remote_ip", {"remote_port": "443"}),
        )
        for fields, missing, observed in cases:
            with self.subTest(fields=fields):
                report = self.extract(self.event(**fields))
                requirement = report.requirements[0]
                details = dict(requirement.details)
                self.assertEqual(details["missing_endpoint_fields"], missing)
                self.assertEqual({k: details[k] for k in ("remote_ip", "remote_port") if k in details}, observed)
                self.assertFalse(requirement.repairable)
                self.assertEqual(self.plan(report).decisions[0].action, RepairActionKind.NONE)

    def test_unknown_attempts_are_distinct_and_repeat_deterministically(self):
        # Even the same PID/fd/pointer may be reused for another destination.
        events = (self.event(), self.event(line_number=142546800), self.event(pid=25))
        report = self.extract(*events)
        self.assertEqual(len(report.requirements), 3)
        self.assertEqual(len({r.requirement_id for r in report.requirements}), 3)
        self.assertEqual({r.evidence[0].event_index for r in report.requirements}, {0, 1, 2})
        self.assertEqual(report.requirements, self.extract(*events).requirements)
        self.assertEqual(self.plan(report).summary()["automatic_candidates"], 0)

    def test_known_endpoint_keeps_existing_plan_and_does_not_absorb_unknown(self):
        events = (
            self.event(),
            self.event(remote_ip="192.0.2.10", remote_port=443),
        )
        report = self.extract(*events)
        self.assertEqual(len(report.requirements), 2)
        decisions = {d.resource: d for d in self.plan(report).decisions}
        known = decisions["tcp://192.0.2.10:443"]
        self.assertEqual(known.action, RepairActionKind.CONFIGURE_TCP_SERVICE)
        self.assertEqual(known.disposition, RepairDisposition.REVIEW_REQUIRED)
        unknown = next(d for d in decisions.values() if d is not known)
        self.assertEqual(unknown.action, RepairActionKind.NONE)
        self.assertEqual(unknown.disposition, RepairDisposition.MANUAL_ANALYSIS)
        self.assertFalse(any(d.automatic_allowed for d in decisions.values()))

    def test_existing_connection_failure_errnos_are_retained(self):
        for errno in ("ECONNREFUSED", "ETIMEDOUT", "ENETUNREACH", "EHOSTUNREACH", "EADDRNOTAVAIL"):
            with self.subTest(errno=errno):
                report = self.extract(self.event(errno=errno, raw=f"connect failed: {errno}"))
                self.assertEqual(len(report.requirements), 1)
                self.assertEqual(report.requirements[0].errno, errno)
                self.assertFalse(report.requirements[0].repairable)

    def test_success_pending_and_host_wrapper_calls_do_not_create_failures(self):
        report = self.extract(
            self.event(errno=None, return_value=0),
            self.event(errno="EINPROGRESS"),
            self.event(execution_context="host_wrapper"),
        )
        self.assertEqual(report.requirements, ())

    def test_unresolved_marker_prevents_service_plan_even_if_repairable_is_true(self):
        report = self.extract(self.event())
        changed = replace(report.requirements[0], repairable=True)
        decision = self.plan(replace(report, requirements=(changed,))).decisions[0]
        self.assertEqual(decision.action, RepairActionKind.NONE)
        self.assertEqual(decision.disposition, RepairDisposition.MANUAL_ANALYSIS)
        self.assertFalse(decision.automatic_allowed)
        self.assertIn("no complete remote IP and port", decision.reason)

    def test_offline_run_adds_network_requirement_without_reclassifying_enosys(self):
        source = self.root / "source"
        (source / "logs").mkdir(parents=True)
        (source / "config").mkdir()
        (source / "config/runtime.json").write_text('{"arch":"i386","network_mode":"none"}')
        (source / "logs/guest_exit_code").write_text("0\n")
        (source / "logs/qemu_strace.log").write_text(
            "24 set_robust_list(0x813c3ec,12) = -1 errno=38 (Function not implemented)\n"
            "24 rseq(0x813c320,32,0,0x53053053) = -1 errno=38 (Function not implemented)\n"
            '24 openat(AT_FDCWD,"/tmp/testfile.txt",O_WRONLY|O_CREAT|O_TRUNC,0644) = 5\n'
            "24 write(5,0x80ba02a,16) = 16\n"
            "24 close(5) = 0\n"
            "24 socket(PF_INET,SOCK_STREAM,IPPROTO_IP) = 5\n"
            + POINTER_CONNECT + "\n"
            "24 close(5) = 0\n"
            "24 write(1,0x80ba045,13) = 13\n"
        )
        def fingerprint():
            return {str(p.relative_to(source)): hashlib.sha256(p.read_bytes()).hexdigest()
                    for p in source.rglob("*") if p.is_file()}
        before = fingerprint()
        output = self.root / "reprocessed"
        metadata = reprocess(source, output)
        self.assertEqual(before, fingerprint())
        self.assertEqual(metadata["status"], "reprocessed")
        self.assertEqual(metadata["requirements_total"], 4)
        self.assertEqual(metadata["repair_plan_summary"]["by_disposition"], {"manual_analysis": 3, "not_required": 1})
        self.assertEqual(metadata["repair_plan_summary"]["automatic_candidates"], 0)
        self.assertEqual(metadata["execution"]["guest_exit_code"], 0)
        self.assertFalse(metadata["guest_executed"])
        self.assertFalse(metadata["session_resumed"])
        self.assertFalse(metadata["phase1_artifacts_verified"])
        report = RequirementReport.load(output / "config/runtime_requirements.json")
        syscall_requirements = [r for r in report.requirements if r.kind == RequirementKind.SYSCALL]
        self.assertEqual({r.resource for r in syscall_requirements}, {"rseq", "set_robust_list"})
        for requirement in syscall_requirements:
            self.assertEqual(requirement.errno, "ENOSYS")
            self.assertEqual(requirement.status, RequirementStatus.UNMET)
            self.assertFalse(requirement.repairable)


if __name__ == "__main__":
    unittest.main()
