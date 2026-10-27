from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from scripts.reprocess_prebuilt_logs import reprocess
from taintforge_env.report_generator import RunReportGenerator


class ReportEvidenceTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.run = self.root / "run"
        (self.run / "config").mkdir(parents=True)
        (self.run / "logs").mkdir()

    def write_json(self, name, value):
        (self.run / name).write_text(json.dumps(value), encoding="utf-8")

    def generate(self):
        report = RunReportGenerator(self.run).generate()
        return report, (self.run / "report.md").read_text(encoding="utf-8")

    def test_offline_zero_exit_and_pointer_connect_preserve_evidence(self):
        self.write_json("config/runtime.json", {
            "arch": "i386", "network_mode": "none", "allow_internet": False,
        })
        self.write_json("config/prebuilt_runner_manifest.json", {
            "isolation": {"chroot": True, "pid_namespace": True, "user_namespace": False},
        })
        (self.run / "logs/guest_exit_code").write_text("0\n")
        (self.run / "logs/runtime_stdout.log").write_text("привет\n", encoding="utf-8")
        (self.run / "logs/qemu_strace.log").write_text(
            "[PLUGIN] diagnostic\n"
            "100 socket(PF_INET,SOCK_STREAM,IPPROTO_IP) = 3\n"
            "100 connect(3,0x40800100,16) = -1 errno=111 (Connection refused)\n"
        )
        before = {str(p.relative_to(self.run)): hashlib.sha256(p.read_bytes()).hexdigest()
                  for p in self.run.rglob("*") if p.is_file()}
        output = self.root / "reprocessed"
        metadata = reprocess(self.run, output)
        report = json.loads((output / "report.json").read_text())
        markdown = (output / "report.md").read_text()

        self.assertEqual(metadata["execution"]["guest_exit_code"], 0)
        self.assertFalse(metadata["execution"]["timed_out"])
        self.assertFalse(metadata["guest_executed"])
        self.assertFalse(metadata["session_resumed"])
        self.assertFalse(metadata["phase1_artifacts_verified"])
        self.assertIn("- Exit code: `0`", markdown)
        self.assertEqual(report["syscalls"]["events_total"], 2)
        self.assertEqual(report["syscalls"]["network_attempts_count"], 1)
        self.assertEqual(report["syscalls"]["network_attempts_without_endpoint_count"], 1)
        attempt = report["syscalls"]["network_attempts"][0]
        self.assertEqual(attempt["syscall"], "connect")
        self.assertIsNone(attempt["target"])
        self.assertEqual(attempt["errno"], "ECONNREFUSED")
        self.assertEqual(attempt["line_number"], 3)
        self.assertIn("unknown (endpoint not decoded)", markdown)
        self.assertNotIn("No network attempts recorded", markdown)
        self.assertEqual(report["network"]["mode"], "none")
        self.assertIs(report["network"]["allow_internet"], False)
        self.assertFalse(report["network"]["events_available"])
        self.assertIsNone(report["security"]["isolation_ready"])
        self.assertIsNone(report["security"]["pid_namespace_enabled"])
        self.assertTrue(report["security"]["configured_isolation"]["pid_namespace"])
        self.assertFalse(report["security"]["configured_isolation"]["user_namespace"])
        self.assertIsNone(report["filesystem"]["created_count"])
        self.assertIn("Filesystem changes are unknown", markdown)
        self.assertNotIn("No created entries.", markdown)
        self.assertTrue((output / "config/prebuilt_runner_manifest.json").is_symlink())
        self.assertEqual(before, {str(p.relative_to(self.run)): hashlib.sha256(p.read_bytes()).hexdigest()
                                  for p in self.run.rglob("*") if p.is_file()})

    def test_explicit_runtime_network_mode_and_false_override_template_policy(self):
        self.write_json("config/runtime.json", {"network_mode": "none", "allow_internet": False})
        self.write_json("config/network_policy.json", {"mode": "record", "allow_internet": True})
        report, _ = self.generate()
        self.assertEqual(report["network"]["mode"], "none")
        self.assertEqual(report["network"]["mode_source"], "config/runtime.json:network_mode")
        self.assertIs(report["network"]["allow_internet"], False)
        self.assertIs(report["security"]["allow_internet"], False)

    def test_legacy_exit_policy_and_recorded_security_false_are_preserved(self):
        self.write_json("logs/runtime_status.json", {"exit_code": 0, "timed_out": False})
        self.write_json("config/network_policy.json", {"mode": "controlled", "allow_internet": False})
        self.write_json("logs/security_status.json", {
            "isolation_ready": True, "network_namespace": True, "pid_namespace": False,
            "user_namespace": False, "strace_enabled": False, "proc_mode": "static_rootfs_stubs",
        })
        self.write_json("config/rootfs_diff.json", {
            "created": [], "modified": [], "deleted": [],
            "created_count": 0, "modified_count": 0, "deleted_count": 0,
        })
        (self.run / "logs/network_events.jsonl").write_text("")
        report, markdown = self.generate()
        self.assertIn("- Exit code: `0`", markdown)
        self.assertEqual(report["network"]["mode"], "controlled")
        self.assertEqual(report["network"]["mode_source"], "config/network_policy.json:mode")
        self.assertTrue(report["network"]["events_available"])
        self.assertTrue(report["security"]["status_available"])
        self.assertTrue(report["security"]["isolation_ready"])
        self.assertIs(report["security"]["pid_namespace_enabled"], False)
        self.assertIs(report["security"]["strace_enabled"], False)
        self.assertIsNone(report["security"]["chroot_enabled"])
        self.assertEqual(report["filesystem"]["created_count"], 0)
        self.assertIn("No created entries.", markdown)
        self.assertNotIn("Filesystem changes are unknown", markdown)

    def test_prebuilt_exit_code_has_precedence_and_preserves_zero(self):
        self.write_json("logs/runtime_status.json", {"exit_code": 9})
        self.write_json("config/prebuilt_execution.json", {"guest_exit_code": 0, "exit_code": 7})
        report, markdown = self.generate()
        self.assertEqual(report["runtime"]["status"]["guest_exit_code"], 0)
        self.assertIn("- Exit code: `0`", markdown)
        self.assertNotIn("- Exit code: `7`", markdown)
        self.assertNotIn("- Exit code: `9`", markdown)

    def test_absent_or_invalid_status_does_not_invent_security(self):
        for content in (None, "{", "[]", "null", "{}"):
            with self.subTest(content=content):
                if content is not None:
                    (self.run / "logs/security_status.json").write_text(content)
                    (self.run / "config/rootfs_diff.json").write_text(content)
                report, markdown = self.generate()
                self.assertFalse(report["security"]["status_available"])
                for key in (
                    "isolation_ready", "chroot_enabled", "network_namespace_enabled",
                    "pid_namespace_enabled", "mount_namespace_enabled", "proc_mode",
                    "strace_enabled", "known_endpoint_dnat", "tcp_catch_all_redirect",
                    "iptables_default_deny_expected", "allow_internet",
                ):
                    self.assertIsNone(report["security"][key], key)
                self.assertIsNone(report["network"]["mode"])
                self.assertIsNone(report["network"]["allow_internet"])
                self.assertIsNone(report["filesystem"]["created_count"])
                self.assertNotIn("No created entries.", markdown)
                self.assertNotIn("No modified entries.", markdown)
                self.assertNotIn("No deleted entries.", markdown)

    def test_network_attempts_exclude_host_and_local_or_inbound_calls(self):
        events = [
            {"context": "guest", "syscall": name, "remote_ip": "192.0.2.1", "remote_port": 80}
            for name in ("socket", "bind", "accept", "recvfrom", "connect", "sendto")
        ]
        events.append({"context": "host_wrapper", "syscall": "connect", "remote_ip": "192.0.2.2", "remote_port": 81})
        (self.run / "logs/syscall_events.jsonl").write_text("\n".join(map(json.dumps, events)))
        report, _ = self.generate()
        section = report["syscalls"]
        self.assertEqual(section["events_total"], 6)
        self.assertEqual(section["network_attempts_count"], 2)
        self.assertEqual(section["network_attempts_without_endpoint_count"], 0)
        self.assertEqual(section["network_targets"], ["192.0.2.1:80"])
        self.assertEqual([e["syscall"] for e in section["network_attempts"]], ["connect", "sendto"])

    def test_network_totals_survive_preview_limit_and_summary_path(self):
        events = [{"syscall": "connect", "result": "-1"}] * 105
        events.append({"syscall": "sendto", "remote_ip": "192.0.2.1", "remote_port": 53})
        for summary in ({}, {"events_total": 106, "by_syscall": {"connect": 105, "sendto": 1}}):
            with self.subTest(summary=bool(summary)):
                section = RunReportGenerator(self.run).build_syscalls_section(events, summary)
                self.assertEqual(section["events_total"], 106)
                self.assertEqual(section["network_attempts_count"], 106)
                self.assertEqual(section["network_attempts_without_endpoint_count"], 105)
                self.assertEqual(len(section["network_attempts"]), 100)
                self.assertEqual(section["network_targets"], ["192.0.2.1:53"])


if __name__ == "__main__":
    unittest.main()
