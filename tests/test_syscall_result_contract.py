from __future__ import annotations

from dataclasses import asdict
import json
from pathlib import Path
import tempfile
import unittest

from taintforge_env.qemu_strace_parser import parse_qemu_strace
from taintforge_env.strace_parser import parse_strace_line, parse_strace_logs
from taintforge_env.target_state_oracle import TargetStateOracle, TargetStateSpec


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests/fixtures/test_stat_qemu_returns.log"


class SyscallResultContractTests(unittest.TestCase):
    def test_native_return_contract(self):
        cases = [
            ("16", 16, None, True), ("0", 0, None, True),
            ("0x40805000", 0x40805000, None, True),
            ("0XABCDEF", 0xABCDEF, None, True), ("0008", 8, None, True),
            ("5</tmp/testfile.txt>", 5, None, True),
            ("-1 ENOENT (No such file or directory)", -1, "ENOENT", False),
            ("-1 errno=38 (Function not implemented)", -1, "ENOSYS", False),
            ("-1 errno=9999 (Unknown error)", -1, "ERRNO_9999", False),
            ("-1 errno=0", -1, None, None),
            ("-1", -1, None, None), ("-15", -15, None, None),
            ("?", None, None, None), ("? ERESTARTSYS (restart)", None, None, None),
            ("<unavailable>", None, None, None), ("0xinvalid", None, None, None),
            ("99broken", None, None, None), ("1" * 5000, None, None, None),
        ]
        for raw, value, error, success in cases:
            with self.subTest(result=raw[:80]):
                event = parse_strace_line(f'write(1,"x",16) = {raw}', "strace.1", 1, "guest")
                self.assertIsNotNone(event)
                payload = asdict(event)
                self.assertEqual(payload["return_value"], value)
                self.assertEqual(payload["errno"], error)
                self.assertIs(payload["success"], success)

    def test_exit_signal_and_unfinished_do_not_prove_syscall_success(self):
        for raw in ('+++ exited with 0 +++', '--- SIGTERM {si_signo=SIGTERM} ---'):
            event = parse_strace_line(raw, "strace.1", 1, "guest")
            self.assertIsNone(event.success)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "qemu_strace.log"
            source.write_text('24 write(1,0x1234,13 <unfinished ...>\n'
                              '24 <... write resumed>) = 13\n')
            destination = root / "events.jsonl"
            summary = parse_qemu_strace(source, destination, target_arch="i386")
            self.assertEqual(summary["events_total"], 0)
            self.assertEqual(summary["input_statistics"]["skipped_unfinished_lines"], 2)
            self.assertEqual(destination.read_bytes(), b"")

    def test_actual_qemu_lines_reach_goal_with_errors_preserved(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "logs").mkdir()
            destination = root / "logs/syscall_events.jsonl"
            parse_qemu_strace(FIXTURE, destination, target_arch="i386")
            (root / "logs/runtime_stdout.log").write_text("привет\n", encoding="utf-8")
            evaluation = TargetStateOracle().evaluate(root, ROOT / "examples/targets/test_stat_stdout.json")
            self.assertTrue(evaluation.reached)
            self.assertEqual(evaluation.matched_rules, 2)
            self.assertEqual(evaluation.rules[1].observed_count, 3)
            self.assertEqual([e["return_value"] for e in evaluation.rules[1].evidence], [3905, 16, 13])
            events = [json.loads(line) for line in destination.read_text().splitlines()]
            memory = next(e for e in events if e["syscall"] == "mmap2")
            self.assertEqual(memory["return_value"], 0x40805000)
            self.assertIs(memory["success"], True)
            errors = {e["syscall"]: e for e in events if e["success"] is False}
            self.assertEqual(set(errors), {"set_robust_list", "rseq", "connect"})
            self.assertEqual(errors["rseq"]["errno"], "ENOSYS")
            self.assertEqual(errors["connect"]["errno"], "ECONNREFUSED")
            self.assertIsNone(errors["connect"]["remote_ip"])
            self.assertIsNone(errors["connect"]["remote_port"])

    def test_native_log_keeps_host_events_out_of_guest_goal(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            logs = root / "logs"
            logs.mkdir()
            trace = logs / "strace.1"
            target = TargetStateSpec.from_dict({
                "schema_version": 1, "goal_id": "write", "description": "guest write",
                "rules": [{"id": "write", "type": "event_count", "source": "syscall",
                           "where": {"syscall": "write", "success": True}}],
            })
            trace.write_text('write(1,"wrapper log",11) = 11\nchroot("/rootfs") = 0\n'
                             'write(1,"x",1) = -1 EIO (Input/output error)\n')
            output = logs / "syscall_events.jsonl"
            parse_strace_logs(logs, output)
            self.assertFalse(TargetStateOracle().evaluate(root, target).reached)
            with trace.open("a") as stream:
                stream.write('write(1,"x",1) = 1\n')
            parse_strace_logs(logs, output)
            result = TargetStateOracle().evaluate(root, target)
            self.assertTrue(result.reached)
            self.assertEqual(result.rules[0].observed_count, 1)

    def test_errno_text_in_arguments_does_not_change_successful_return(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "qemu_strace.log"
            source.write_text('24 write(1,"message = -1 ENOSYS (error)",29) = 29\n')
            destination = root / "events.jsonl"
            parse_qemu_strace(source, destination, target_arch="i386")
            event = json.loads(destination.read_text())
            self.assertIs(event["success"], True)
            self.assertIsNone(event["errno"])
            self.assertEqual(event["return_value"], 29)


if __name__ == "__main__":
    unittest.main()
