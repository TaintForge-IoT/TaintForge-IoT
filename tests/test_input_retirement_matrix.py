from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from experiments.input_retirement.cases import CASES, build_guests, is_stripped
from experiments.execution_capsule_probe import controller as p
from scripts import run_input_retirement_e2e as acceptance
from taintforge_env.phase1_runtime import read_json
from tests.test_input_retirement import InputExecutor
from tests import test_input_retirement as fixture


class MatrixBuildTests(unittest.TestCase):
    def test_distinct_stripped_bodies_and_address_layouts(self):
        with tempfile.TemporaryDirectory() as temporary:
            guests = build_guests(Path(temporary) / "inputs")
            self.assertEqual(list(guests), list(CASES))
            positive = [guests[k] for k in ("normal", "relocated-branch", "page-offset")]
            for key in ("source_sha256", "expected_oep", "load_base"):
                self.assertEqual(len({entry[key] for entry in positive}), 3)
            self.assertEqual(guests["page-offset"]["expected_oep"] % 4096, 256)
            self.assertIsNone(guests["missing-verdict"]["expected_oep"])
            for entry in guests.values():
                self.assertTrue(is_stripped(entry["path"]))
                self.assertEqual(p.sha(entry["path"]), entry["input"]["sha256"])
            with self.assertRaises(FileExistsError):
                build_guests(Path(temporary) / "inputs")


class AcceptanceTests(unittest.TestCase):
    setUp = fixture.InputRetirementTests.setUp
    prepare_input = fixture.InputRetirementTests.prepare_input
    invoke = fixture.InputRetirementTests.invoke

    def test_selected_candidate_must_match_external_test_oracle(self):
        out, launch = self.prepare_input()
        executor = InputExecutor()
        report, code = self.invoke(out, launch, executor)
        run, binding, _ = executor.runs[0]
        entry = dict(input=binding["input_retirement"], expected_stdout="M3_INPUT_OK\n",
                     expected_oep=binding["input_retirement"]["entry_point"] + 4096)
        acceptance.validate_case("normal", out, report, code, entry)
        entry["expected_oep"] += 1
        with self.assertRaisesRegex(p.ProbeError, "test oracle"):
            acceptance.validate_case("normal", out, report, code, entry)

    def test_repair_receipt_is_bound_to_first_attempt(self):
        out, launch = self.prepare_input()
        executor = InputExecutor(repair=True)
        report, code = self.invoke(out, launch, executor, steps=2)
        acceptance.validate_case("repair", out, report, code)
        path = executor.runs[1][0].parent / "repair_application.json"
        receipt = read_json(path)
        for changes in ({"plan_sha256": "0" * 64}, {"dry_run": True}, {"results": []}):
            with self.subTest(changes=changes):
                p.write_json(path, receipt | changes)
                with self.assertRaises(p.ProbeError):
                    acceptance.validate_case("repair", out, report, code)

    def test_refusal_reports_survive_resume_without_a_new_attempt(self):
        out, launch = self.prepare_input()
        executor = InputExecutor(fault="missing-verdict")
        report, code = self.invoke(out, launch, executor)
        run = executor.runs[0][0]
        for path, key in ((run / "config/prebuilt_execution.json", "guest_exit_code"),
                          (run / "logs/capsule/supervisor.json", "qemu_exit"),
                          (run.parent / "execution_attempt.json", "guest_exit_code")):
            p.write_json(path, read_json(path) | {key: 89})
        (run / "logs/qemu_strace.log").write_text("CAPSULE_PHASE1_ABORT code=89 test\n")
        with patch.object(acceptance, "run_session", side_effect=lambda *a, **k: self.invoke(out, launch, executor)):
            acceptance.validate_case("missing-verdict", out, report, code)
        self.assertEqual(read_json(out / "initial_unified_report.json"), report)
        self.assertEqual(read_json(out / "resume_report.json")["executions_this_invocation"], 0)
        self.assertEqual(len(executor.runs), 1)
