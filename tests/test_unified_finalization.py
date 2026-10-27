"""Failure injection with real observers/parsers/reports and synthetic guest execution."""
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import shutil
import sys
import unittest
from unittest.mock import patch

from scripts.reprocess_prebuilt_logs import reprocess
from scripts.run_unified_pipeline import run_session
from taintforge_env.prebuilt_runner import CommandResult, PrebuiltRootfsRunner, SubprocessCommandExecutor
from taintforge_env.qemu_strace_parser import parse_qemu_strace
from taintforge_env.repair_planner import RepairPlanner
from taintforge_env.report_generator import RunReportGenerator
from taintforge_env.runtime_observer import RuntimeObservationSession
from taintforge_env.synthesis_loop import EnvironmentSynthesisLoop
from tests import test_unified_pipeline as fixtures


def document(path):
    return json.loads(path.read_text())


def hashes(directory):
    return {str(path.relative_to(directory)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in directory.rglob("*") if path.is_file()}


class ObservedExecutor(fixtures.InstrumentedExecutor):
    def __init__(self, *, fail=None, **kwargs):
        super().__init__(**kwargs)
        self.fail = fail
        self.rootfs = None
        self.before_parser = None

    def run(self, command, **kwargs):
        cmd = list(map(str, command))
        if "scripts/capture_runtime_observations.py" in cmd:
            self.commands.append(cmd)
            phase = cmd[cmd.index("scripts/capture_runtime_observations.py") + 1]
            run = Path(cmd[cmd.index("--run-dir") + 1])
            self.rootfs = Path(cmd[cmd.index("--rootfs") + 1])
            observer = RuntimeObservationSession(run_dir=run, rootfs=self.rootfs, require_rootfs_inside_run_dir=False)
            if phase == "requirements" and self.fail == "requirements":
                raise RuntimeError("injected requirement extraction failure")
            {"before": observer.capture_before, "after": observer.capture_after,
             "requirements": observer.extract_requirements}[phase]()
            if phase == "after" and self.fail == "filesystem":
                raise OSError("injected snapshot publication failure")
            return CommandResult(0)
        if "scripts/parse_qemu_strace.py" in cmd:
            self.commands.append(cmd)
            output = Path(cmd[cmd.index("--out") + 1])
            run = output.parent.parent
            self.before_parser = {
                "execution": document(run / "config/prebuilt_execution.json"),
                "phase1": document(run / "config/phase1_result.json"),
                "diff": document(run / "config/rootfs_diff.json"),
            }
            if self.fail == "parser":
                # A real child process leaves partial JSONL and exits by SIGKILL.
                return SubprocessCommandExecutor().run([
                    sys.executable, "-c",
                    "import os,signal,sys; open(sys.argv[1],'w').write('{\"execution_context\":\"guest\",\"syscall\":\"connect\"}\\n'); os.kill(os.getpid(),signal.SIGKILL)",
                    str(output)], cwd=kwargs["cwd"], check=True)
            parse_qemu_strace(Path(cmd[cmd.index("--input") + 1]), output, target_arch="i386")
            return CommandResult(0)
        if "scripts/plan_repairs.py" in cmd:
            self.commands.append(cmd)
            if self.fail == "repair_plan":
                raise RuntimeError("injected repair planning failure")
            RepairPlanner().plan_file(Path(cmd[cmd.index("--requirements") + 1]), Path(cmd[cmd.index("--out") + 1]))
            return CommandResult(0)
        if "scripts/generate_report.py" in cmd:
            self.commands.append(cmd)
            if self.fail == "report":
                raise RuntimeError("injected report generation failure")
            RunReportGenerator(Path(cmd[cmd.index("--out") + 1])).generate()
            return CommandResult(0)
        result = super().run(command, **kwargs)
        if cmd and cmd[-1].endswith("run_prebuilt_sandbox.sh") and "unshare" in cmd and not self.infrastructure_fail:
            (self.rootfs / "tmp").mkdir(exist_ok=True)
            (self.rootfs / "tmp/observed.txt").write_text("guest mutation fixture\n")
        return result


@unittest.skipUnless(shutil.which("gcc") and shutil.which("true"), "host ELF fixture compiler required")
class UnifiedFinalizationTests(unittest.TestCase):
    setUp = fixtures.UnifiedPipelineTests.setUp

    def invoke(self, executor):
        launch = {"schema_version": 1, **asdict(self.loop_config)}
        for key in ("initialize_only", "max_steps", "adopt_existing_session"):
            launch.pop(key)
        original = EnvironmentSynthesisLoop.run

        def run(loop):
            loop.runner_factory = lambda config: PrebuiltRootfsRunner(config, executor=executor)
            with patch.object(PrebuiltRootfsRunner, "_check_host_dependencies"):
                return original(loop)

        with patch.object(EnvironmentSynthesisLoop, "run", run):
            report, code = run_session(self.base, launch, max_steps=1)
        self.assertEqual(report, document(self.base / "unified_report.json"))
        return report, code

    def assert_failed_attempt(self, report, code):
        self.assertEqual(code, 1)
        self.assertEqual(report["outcome"], "intervention_required")
        self.assertEqual(report["executions_this_invocation"], 1)
        self.assertFalse(report["fuzzing_ready"])
        iteration = self.base / "session/iterations/0000"
        claim = document(iteration / "execution_attempt.json")
        self.assertEqual(claim["stage"], "failed")
        self.assertFalse(claim["retry_safe"])
        self.assertTrue(claim["malware_started"])
        self.assertEqual(document(self.base / "session/session.json")["iterations"][0]["state"], "prepared")
        self.assertFalse((iteration / "attempt_result.json").exists())
        self.assertTrue((Path(report["run_dir"]) / "report.json").is_file())
        return Path(report["run_dir"])

    def test_parser_sigkill_preserves_phase1_and_filesystem_and_blocks_resume(self):
        executor = ObservedExecutor(fail="parser")
        report, code = self.invoke(executor)
        run = self.assert_failed_attempt(report, code)
        self.assertIn("exit code -9", report["error"])
        self.assertEqual(report["execution"]["guest_exit_code"], 0)
        self.assertEqual(report["phase1"]["artifact_integrity"], "verified")
        before = executor.before_parser
        self.assertEqual(before["phase1"], report["phase1"])
        self.assertIn("/tmp/observed.txt", [entry["path"] for entry in before["diff"]["created"]])
        stages = report["finalization"]["stages"]
        self.assertEqual(stages["syscalls"]["status"], "failed")
        self.assertEqual(stages["requirements"]["status"], "skipped")
        self.assertFalse((run / "config/runtime_requirements.json").exists())
        self.assertFalse((run / "config/repair_plan.json").exists())
        phase2 = document(run / "report.json")
        self.assertTrue(phase2["filesystem"]["observation_available"])
        self.assertFalse(phase2["syscalls"]["observation_available"])
        self.assertIsNone(phase2["syscalls"]["events_total"])
        self.assertIsNone(phase2["syscalls"]["network_attempts_count"])
        self.assertIn("network attempts are unknown", (run / "report.md").read_text())
        original_claim = (run.parent / "execution_attempt.json").read_bytes()
        resumed, resumed_code = self.invoke(executor)
        self.assertEqual(resumed_code, 1)
        self.assertEqual(resumed["executions_this_invocation"], 0)
        self.assertEqual(sum("unshare" in cmd for cmd in executor.commands), 1)
        self.assertEqual((run.parent / "execution_attempt.json").read_bytes(), original_claim)

    def test_offline_reprocessing_is_repeatable_and_does_not_finalize_original_attempt(self):
        report, code = self.invoke(ObservedExecutor(fail="parser"))
        run = self.assert_failed_attempt(report, code)
        original = hashes(self.base / "session")
        for index in range(2):
            recovered = reprocess(run, self.base / f"reprocessed{index}")
            self.assertTrue(recovered["filesystem_observation_available"])
            self.assertFalse(recovered["guest_executed"])
            self.assertFalse(recovered["session_resumed"])
            self.assertFalse(recovered["phase1_artifacts_verified"])
            self.assertGreater(recovered["events_total"], 0)
            self.assertEqual(hashes(self.base / "session"), original)

    def test_success_persists_all_stages_and_verifiable_artifact_bundle(self):
        report, code = self.invoke(ObservedExecutor())
        self.assertEqual(code, 0)
        self.assertEqual(report["finalization"]["status"], "completed")
        self.assertTrue(EnvironmentSynthesisLoop.verify_session(self.base / "session")["binding_verified"])
        saved = document(Path(report["run_dir"]) / "report.json")
        self.assertTrue(saved["syscalls"]["observation_available"])
        self.assertTrue(saved["filesystem"]["observation_available"])

    def test_timeout_preserves_incomplete_capture_without_claiming_integrity(self):
        report, code = self.invoke(ObservedExecutor(mode="incomplete", guest_exit_code=124))
        self.assertTrue(report["execution"]["timed_out"])
        self.assertEqual(report["phase1"]["artifact_integrity"], "incomplete")
        self.assertEqual(report["finalization"]["status"], "completed")
        self.assertFalse(report["phase1"]["oep_proven"])
        self.assertEqual(report["stop_reason"], "execution_timed_out")

    def test_corrupt_capture_and_parser_failure_both_remain_visible(self):
        report, code = self.invoke(ObservedExecutor(mode="corrupt", fail="parser", guest_exit_code=124))
        self.assert_failed_attempt(report, code)
        self.assertEqual(report["phase1"]["verification_status"], "failed")
        self.assertEqual(report["phase1"]["artifact_integrity"], "unverified")
        self.assertIn("integrity mismatch", report["phase1"]["reason"])
        self.assertEqual(report["finalization"]["stages"]["phase1"]["status"], "failed")
        self.assertEqual(report["finalization"]["stages"]["syscalls"]["status"], "failed")

    def test_missing_capture_does_not_prevent_phase2_observation(self):
        report, code = self.invoke(ObservedExecutor(mode="missing"))
        run = self.assert_failed_attempt(report, code)
        self.assertEqual(report["phase1"]["verification_status"], "failed")
        self.assertEqual(report["finalization"]["stages"]["repair_plan"]["status"], "completed")
        self.assertTrue(document(run / "report.json")["filesystem"]["observation_available"])

    def test_filesystem_failure_does_not_prevent_phase1_or_parser(self):
        report, code = self.invoke(ObservedExecutor(fail="filesystem"))
        run = self.assert_failed_attempt(report, code)
        self.assertEqual(report["phase1"]["artifact_integrity"], "verified")
        self.assertEqual(report["finalization"]["stages"]["syscalls"]["status"], "completed")
        self.assertEqual(report["finalization"]["stages"]["requirements"]["status"], "skipped")
        self.assertFalse(document(run / "report.json")["filesystem"]["observation_available"])

    def test_requirement_failure_keeps_evidence_and_skips_plan(self):
        report, code = self.invoke(ObservedExecutor(fail="requirements"))
        self.assert_failed_attempt(report, code)
        self.assertEqual(report["finalization"]["stages"]["requirements"]["status"], "failed")
        self.assertEqual(report["finalization"]["stages"]["repair_plan"]["status"], "skipped")

    def test_plan_failure_keeps_requirements(self):
        report, code = self.invoke(ObservedExecutor(fail="repair_plan"))
        run = self.assert_failed_attempt(report, code)
        self.assertTrue((run / "config/runtime_requirements.json").is_file())
        self.assertEqual(report["finalization"]["stages"]["repair_plan"]["status"], "failed")

    def test_report_failure_writes_bounded_diagnostic_fallback(self):
        report, code = self.invoke(ObservedExecutor(fail="report"))
        run = self.assert_failed_attempt(report, code)
        saved = document(run / "report.json")
        self.assertEqual(saved["report_status"], "diagnostic_only")
        self.assertEqual(saved["phase1"]["artifact_integrity"], "verified")
        self.assertEqual(report["finalization"]["stages"]["report"]["status"], "failed")

    def test_infrastructure_failure_does_not_claim_guest_stop_or_capture(self):
        report, code = self.invoke(ObservedExecutor(mode="missing", infrastructure_fail=True))
        self.assertEqual(code, 1)
        self.assertEqual(report["executions_this_invocation"], 0)
        self.assertEqual(report["execution"]["status"], "unavailable")
        self.assertEqual(report["finalization"]["status"], "unavailable")
        self.assertFalse((Path(report["run_dir"]) / "config/rootfs_after.json").exists())
