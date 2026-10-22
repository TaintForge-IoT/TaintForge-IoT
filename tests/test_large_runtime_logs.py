from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from scripts.reprocess_prebuilt_logs import reprocess
from taintforge_env.log_io import MAX_LOG_LINE_BYTES, OBSERVATION_PREVIEW_CHARS
from taintforge_env.observations import load_observation_bundle
from taintforge_env.qemu_strace_parser import parse_qemu_strace, QemuStraceParserError
from taintforge_env.report_generator import RunReportGenerator
from taintforge_env.requirement_extractor import RequirementExtractor


class LargeRuntimeLogTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def make_run(self):
        source = self.root / "source"
        (source / "logs").mkdir(parents=True)
        (source / "config").mkdir()
        (source / "config/runtime.json").write_text(json.dumps({"arch": "i386", "network_mode": "none"}))
        (source / "logs/guest_exit_code").write_text("124\n")
        (source / "logs/runtime_stdout.log").write_text("")
        return source

    def test_parser_preserves_events_counters_errno_and_line_numbers(self):
        source = self.root / "trace.log"
        source.write_text(
            "[BRANCH-ROOT] event=1 path=/bin/sample.elf\n"
            '100 openat(AT_FDCWD, "/etc/device.conf", O_RDONLY) = -1 errno=2 (No such file or directory)\n'
            + "100 ptrace(0,0,0,0) = -1 errno=1 (Operation not permitted)\n" * 100
            + "100 read(0, <unfinished ...>\n"
            + "[BRANCH-PROV] event=2\n"
        )
        output = self.root / "events.jsonl"
        summary = parse_qemu_strace(source, output, target_arch="i386")
        events = [json.loads(line) for line in output.read_text().splitlines()]
        self.assertEqual(summary["events_total"], 101)
        self.assertEqual(summary["by_syscall"], {"openat": 1, "ptrace": 100})
        self.assertEqual(summary["by_context"], {"guest": 101})
        self.assertEqual(summary["guest_paths"], ["/etc/device.conf"])
        self.assertEqual(summary["high_risk_count"], 100)
        self.assertEqual(len(summary["high_risk_events"]), 50)
        self.assertEqual(summary["high_risk_events"][0]["errno"], "EPERM")
        self.assertEqual(summary["input_statistics"]["ignored_lines"], 2)
        self.assertEqual(summary["input_statistics"]["skipped_unfinished_lines"], 1)
        self.assertEqual(events[0]["line_number"], 2)
        self.assertEqual(events[0]["errno"], "ENOENT")
        self.assertEqual(events[-1]["line_number"], 102)

    def test_oversized_record_preserves_previous_outputs(self):
        source, output = self.root / "trace.log", self.root / "events.jsonl"
        source.write_bytes(b"100 write(1,0,1) = 1\n" + b"x" * (MAX_LOG_LINE_BYTES + 1))
        output.write_text("old events\n")
        summary = output.with_suffix(".summary.json")
        summary.write_text("old summary\n")
        with self.assertRaisesRegex(QemuStraceParserError, "line exceeds.*:2"):
            parse_qemu_strace(source, output, target_arch="i386")
        self.assertEqual(output.read_text(), "old events\n")
        self.assertEqual(summary.read_text(), "old summary\n")
        self.assertEqual(sorted(path.name for path in self.root.iterdir()),
                         ["events.jsonl", "events.summary.json", "trace.log"])

    def test_output_aliases_cannot_replace_raw_input(self):
        source = self.root / "trace.log"
        content = "100 write(1,0,1) = 1\n"
        source.write_text(content)
        alias = self.root / "alias.jsonl"
        alias.hardlink_to(source)
        for output in (source, alias):
            with self.subTest(output=output.name):
                with self.assertRaisesRegex(QemuStraceParserError, "replace its input"):
                    parse_qemu_strace(source, output, target_arch="i386")
        self.assertEqual(source.read_text(), content)

    def test_full_stderr_is_scanned_beyond_the_preview(self):
        source = self.make_run()
        error = "sample: error while loading shared libraries: libdevice.so: cannot open shared object file\n"
        (source / "logs/runtime_stderr.log").write_text(
            "diagnostic\n" * OBSERVATION_PREVIEW_CHARS + error + "more diagnostics\n" * OBSERVATION_PREVIEW_CHARS)
        (source / "logs/syscall_events.jsonl").write_text("")
        (source / "config/prebuilt_execution.json").write_text('{"guest_exit_code":124,"timed_out":true}')
        bundle = load_observation_bundle(source)
        self.assertLessEqual(len(bundle.stderr_text), OBSERVATION_PREVIEW_CHARS)
        self.assertNotIn("libdevice.so", bundle.stderr_text)
        self.assertEqual(bundle.runtime_status["guest_exit_code"], 124)
        self.assertFalse(any("network events not found" in item or "runtime status not found" in item
                             for item in bundle.warnings))
        requirements = RequirementExtractor().extract(bundle)
        self.assertTrue(any(item.resource == "libdevice.so" for item in requirements.requirements))

    def test_report_uses_prebuilt_status_and_config_filesystem_diff(self):
        source = self.make_run()
        (source / "logs/runtime_stderr.log").write_text("")
        (source / "logs/syscall_events.jsonl").write_text("")
        (source / "logs/runtime_status.json").write_text('{"guest_exit_code":0}')
        (source / "config/prebuilt_execution.json").write_text('{"guest_exit_code":124,"timed_out":true}')
        (source / "config/rootfs_diff.json").write_text(json.dumps({
            "created_count": 1, "modified_count": 0, "deleted_count": 0,
            "created": [{"path": "/tmp/result", "type": "file"}],
        }))
        (source / "logs/rootfs_diff.json").write_text('{"created_count":9}')
        self.assertEqual(load_observation_bundle(source).rootfs_diff["created_count"], 1)
        report = RunReportGenerator(source).generate()
        self.assertEqual(report["runtime"]["status"]["guest_exit_code"], 124)
        self.assertTrue(report["filesystem"]["observation_available"])
        self.assertEqual(report["filesystem"]["created_count"], 1)
        self.assertEqual(report["paths"]["rootfs_diff"], "config/rootfs_diff.json")

    def test_reprocessing_preserves_source_and_does_not_claim_missing_capture(self):
        source = self.make_run()
        (source / "logs/qemu_strace.log").write_text(
            '100 openat(AT_FDCWD, "/etc/device.conf", O_RDONLY) = -1 errno=2 (No such file or directory)\n')
        (source / "logs/runtime_stderr.log").write_text("diagnostic\n")
        def fingerprints():
            return {str(path.relative_to(source)): hashlib.sha256(path.read_bytes()).hexdigest()
                    for path in source.rglob("*") if path.is_file()}
        before = fingerprints()
        output = self.root / "reprocessed"
        result = reprocess(source, output)
        self.assertEqual(before, fingerprints())
        self.assertEqual(result["status"], "reprocessed")
        self.assertFalse(result["guest_executed"])
        self.assertFalse(result["session_resumed"])
        self.assertFalse(result["phase1_artifacts_verified"])
        self.assertFalse(result["filesystem_observation_available"])
        self.assertEqual(result["execution"]["guest_exit_code"], 124)
        self.assertEqual(result["requirements_total"], 1)
        report = json.loads((output / "report.json").read_text())
        self.assertIsNone(report["filesystem"]["created_count"])
        self.assertIn("Offline log reprocessing", (output / "report.md").read_text())
        with self.assertRaisesRegex(ValueError, "new output directory"):
            reprocess(source, output)
        with self.assertRaisesRegex(ValueError, "outside the original"):
            reprocess(source, source / "new")

    @unittest.skipUnless(sys.platform == "linux", "requires RLIMIT_AS")
    def test_reprocessing_large_mixed_log_with_128_mib_address_space(self):
        source = self.make_run()
        raw = source / "logs/qemu_strace.log"
        chunk = b"[BRANCH-ROOT] event=211314 channel=address path=/bin/sample.elf offset=304044\n" * 10000
        with raw.open("wb") as stream:
            stream.write(b'100 openat(AT_FDCWD, "/etc/device.conf", O_RDONLY) = -1 errno=2 (No such file or directory)\n')
            for _ in range(75):
                stream.write(chunk)
            stream.write(b"sample: error while loading shared libraries: libmiddle.so: cannot open shared object file\n")
            for _ in range(75):
                stream.write(chunk)
            stream.write(b"100 write(1,0,1) = 1\n")
        (source / "logs/runtime_stderr.log").hardlink_to(raw)
        output = self.root / "bounded"
        code = '''import resource, sys, json
from pathlib import Path
resource.setrlimit(resource.RLIMIT_AS, (128*1024*1024,128*1024*1024))
from scripts.reprocess_prebuilt_logs import reprocess
result = reprocess(Path(sys.argv[1]), Path(sys.argv[2]))
print(json.dumps({"events": result["events_total"], "requirements": result["requirements_total"],
"max_rss_kib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss}))
'''
        result = subprocess.run([sys.executable, "-c", code, str(source), str(output)],
                                cwd=Path(__file__).resolve().parents[1], capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr)
        stats = json.loads(result.stdout)
        self.assertEqual(stats["events"], 2)
        self.assertEqual(stats["requirements"], 2)
        self.assertLess(stats["max_rss_kib"], 128 * 1024)
        self.assertGreater(raw.stat().st_size, 100 * 1024 * 1024)


if __name__ == "__main__":
    unittest.main()
