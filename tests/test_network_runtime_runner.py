"""Network infrastructure failures must preserve diagnostics and prevent repair retries."""
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from taintforge_env.prebuilt_runner import PrebuiltRunnerError, CommandResult
from tests import test_prebuilt_runner as fixtures


class NetworkFailureBackend(fixtures.FakeNetworkBackend):
    def cleanup(self, *, finalize_logs=True):
        super().cleanup(finalize_logs=finalize_logs)
        path = self.config.run_dir / "logs/network_runtime_status.json"
        path.write_text(json.dumps({"schema_version": 1, "attempt_id": self.config.attempt_id,
            "termination_reason": "network_receive_budget_exceeded", "cleanup_status": "cleaned"}))


class NetworkRuntimeRunnerTests(unittest.TestCase):
    setUp = fixtures.PrebuiltRunnerTests.setUp
    tearDown = fixtures.PrebuiltRunnerTests.tearDown
    make_runner = fixtures.PrebuiltRunnerTests.make_runner

    def test_budget_failure_preserves_goal_observation_and_blocks_automatic_plan(self):
        target = self.base / "goal.json"
        fixtures._write_json(target, {"schema_version": 1, "goal_id": fixtures.GOAL_ID,
            "description": "Independent observed application output", "mode": "all",
            "rules": [{"id": "output", "type": "text_contains", "source": "stdout", "needle": "guest stdout"}]})
        executor = fixtures.FakeExecutor()
        runner = self.make_runner(executor, network_mode="controlled", target_spec=target,
                                  network_backend_factory=NetworkFailureBackend)
        with patch.object(runner, "_check_host_dependencies"), self.assertRaisesRegex(PrebuiltRunnerError, "network runtime"):
            runner.run_and_complete()
        run = self.session / "iterations/0000/run"
        stages = json.loads((run / "config/finalization_status.json").read_text())["stages"]
        self.assertEqual(stages["execution"]["status"], "completed")
        self.assertEqual(stages["network_runtime"]["status"], "failed")
        self.assertEqual(stages["repair_plan"]["status"], "failed")
        self.assertTrue(json.loads((run / "config/target_state_evaluation.json").read_text())["reached"])
        self.assertFalse(any("scripts/plan_repairs.py" in cmd for cmd in executor.commands))
        self.assertFalse((run.parent / "attempt_result.json").exists())
        self.assertFalse(json.loads((run.parent / "execution_attempt.json").read_text())["retry_safe"])

    def test_guard_result_recovers_execution_without_a_wrapper_exit_artifact(self):
        class StoppedExecutor(fixtures.FakeExecutor):
            def run(self, command, **kwargs):
                result = super().run(command, **kwargs)
                cmd = list(map(str, command))
                if "unshare" in cmd and cmd[-1].endswith("run_prebuilt_sandbox.sh"):
                    run = Path(cmd[-1]).parent
                    (run / "logs/guest_exit_code").unlink()
                    attempt = json.loads((run.parent / "execution_attempt.json").read_text())["attempt_id"]
                    fixtures._write_json(run / "config/network_guard_result.json", {"schema_version": 1,
                        "attempt_id": attempt, "guest_process_stopped": True,
                        "termination_reason": "network_receive_budget_exceeded", "command_exit_code": -15})
                    return CommandResult(143)
                return result
        runner = self.make_runner(StoppedExecutor(), network_mode="controlled", network_backend_factory=NetworkFailureBackend)
        with patch.object(runner, "_check_host_dependencies"), self.assertRaisesRegex(PrebuiltRunnerError, "network runtime"):
            runner.run_and_complete()
        run = self.session / "iterations/0000/run"
        value = json.loads((run / "config/prebuilt_execution.json").read_text())
        self.assertEqual(value["guest_exit_code"], 143)
        self.assertEqual(value["exit_code_source"], "network_guard_command")
        self.assertEqual(value["network_termination_reason"], "network_receive_budget_exceeded")
        self.assertTrue((run / "report.json").is_file())

    def test_foreign_guard_result_cannot_replace_the_wrapper_exit(self):
        runner = self.make_runner(fixtures.FakeExecutor(infrastructure_fail=True), network_mode="controlled",
                                  network_backend_factory=fixtures.FakeNetworkBackend)
        context = runner.validate()
        runner._prepare_run_directory(context)
        fixtures._write_json(context.run_dir / "config/network_guard_result.json", {"schema_version": 1,
            "attempt_id": "another-attempt", "guest_process_stopped": True,
            "termination_reason": "network_responder_exited", "command_exit_code": 1})
        backend = fixtures.FakeNetworkBackend(type("Config", (), {"run_dir": context.run_dir})(), runner.executor)
        with self.assertRaisesRegex(PrebuiltRunnerError, "before recording"):
            runner._execute_guest(context, network_backend=backend)

    def test_unconfirmed_cleanup_before_guest_start_blocks_even_a_safe_rootfs_reset(self):
        class FailedStartup(fixtures.FakeNetworkBackend):
            def setup(self):
                super().setup()
                raise RuntimeError("network startup failed")
            def cleanup(self, *, finalize_logs=True):
                fixtures._write_json(self.config.run_dir / "logs/network_runtime_status.json", {
                    "attempt_id": self.config.attempt_id, "cleanup_status": "cleanup_failed"})
                raise RuntimeError("owned namespace is still present")
        runner = self.make_runner(network_mode="controlled", network_backend_factory=FailedStartup)
        with patch.object(runner, "_check_host_dependencies"), self.assertRaisesRegex(PrebuiltRunnerError, "startup failed"):
            runner.run_and_complete()
        claim_path = self.session / "iterations/0000/execution_attempt.json"
        claim = json.loads(claim_path.read_text())
        self.assertFalse(claim["malware_started"])
        self.assertFalse(claim["retry_safe"])
        with self.assertRaisesRegex(PrebuiltRunnerError, "retry-safe"):
            runner.reset_safe_failure()
        # Old or manually edited retry-safe metadata must not erase retained cleanup evidence.
        claim["retry_safe"] = True
        claim_path.write_text(json.dumps(claim))
        with self.assertRaisesRegex(PrebuiltRunnerError, "network cleanup is unconfirmed"):
            runner.reset_safe_failure()
        self.assertTrue((claim_path.parent / "run/logs/network_runtime_status.json").is_file())


if __name__ == "__main__":
    unittest.main()
