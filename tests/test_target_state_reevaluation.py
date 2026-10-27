from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from scripts.reevaluate_target_state import reevaluate


ROOT = Path(__file__).resolve().parents[1]


class TargetStateReevaluationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name)
        self.session = self.base / "session"
        self.run = self.session / "iterations/0000/run"
        (self.run / "config").mkdir(parents=True)
        (self.run / "logs").mkdir()
        (self.session / "session.json").write_text('{"state":"completed"}\n')
        (self.run / "config/target_state_spec.json").write_bytes(
            (ROOT / "examples/targets/test_stat_stdout.json").read_bytes())
        (self.run / "config/target_state_evaluation.json").write_text('{"reached":false}\n')
        (self.run / "config/phase1_result.json").write_text('{"analysis_status":"partial"}\n')
        (self.run / "logs/runtime_stdout.log").write_text("привет\n", encoding="utf-8")
        self.events = self.run / "logs/syscall_events.jsonl"
        self.events.write_text(json.dumps({"event": "syscall", "execution_context": "guest",
                                          "syscall": "write", "return_value": 13, "errno": None}) + "\n")

    def tearDown(self):
        self.temporary.cleanup()

    def hashes(self):
        return {str(p.relative_to(self.session)): hashlib.sha256(p.read_bytes()).hexdigest()
                for p in self.session.rglob("*") if p.is_file()}

    def test_cli_and_repeat_write_new_results_leave_source_unchanged(self):
        before = self.hashes()
        out = self.base / "evaluation.json"
        process = subprocess.run([sys.executable, str(ROOT / "scripts/reevaluate_target_state.py"),
                                  "--run-dir", str(self.run), "--out", str(out)],
                                 cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(process.returncode, 0, process.stderr)
        result = json.loads(process.stdout)
        self.assertEqual(json.loads(out.read_text()), result)
        self.assertTrue(result["goal_reached"])
        self.assertEqual(result["evaluation"]["matched_rules"], 2)
        self.assertEqual(result["evaluation"]["oracle_version"], 2)
        for name in ("guest_executed", "session_resumed", "phase1_artifacts_verified", "fuzzing_ready"):
            self.assertIs(result[name], False)
        self.assertEqual(self.hashes(), before)
        repeat = reevaluate(self.run, self.base / "second.json")
        self.assertEqual(repeat["evaluation"]["rules"], result["evaluation"]["rules"])
        self.assertEqual(self.hashes(), before)
        existing = out.read_bytes()
        with self.assertRaisesRegex(ValueError, "new output file"):
            reevaluate(self.run, out)
        self.assertEqual(out.read_bytes(), existing)

    def test_rejects_output_inside_source_session_including_symlink_parent(self):
        before = self.hashes()
        alias = self.base / "alias"
        alias.symlink_to(self.session, target_is_directory=True)
        for output in (self.run / "new.json", self.session / "new.json", alias / "new.json"):
            with self.subTest(output=output), self.assertRaisesRegex(ValueError, "outside"):
                reevaluate(self.run, output)
        self.assertEqual(self.hashes(), before)

    def test_existing_output_aliases_do_not_overwrite_evidence(self):
        before = self.hashes()
        symbolic = self.base / "symlink.json"
        symbolic.symlink_to(self.events)
        hard = self.base / "hardlink.json"
        hard.hardlink_to(self.events)
        for output in (symbolic, hard):
            with self.subTest(output=output), self.assertRaisesRegex(ValueError, "new output file"):
                reevaluate(self.run, output)
        self.assertEqual(self.hashes(), before)

    def test_error_write_does_not_reach_goal_and_cli_exits_one(self):
        self.events.write_text(json.dumps({"event": "syscall", "execution_context": "guest",
                                          "syscall": "write", "result": "-1 EIO (Input/output error)"}) + "\n")
        process = subprocess.run([sys.executable, str(ROOT / "scripts/reevaluate_target_state.py"),
                                  "--run-dir", str(self.run), "--out", str(self.base / "failed-goal.json")],
                                 cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(process.returncode, 1, process.stderr)
        self.assertFalse(json.loads(process.stdout)["goal_reached"])


if __name__ == "__main__":
    unittest.main()
