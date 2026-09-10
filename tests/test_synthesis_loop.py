from __future__ import annotations

import fcntl
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from taintforge_env.iteration_controller import (
    DEFAULT_DISCOVERY_GOAL_ID,
    IterationController,
    SessionState,
)
from taintforge_env.prebuilt_runner import (
    PrebuiltRunnerConfig,
    PrebuiltRunnerError,
    PrebuiltRunnerResult,
)
from taintforge_env.repair_plan import (
    RepairActionKind,
    RepairDisposition,
    RepairPriority,
    RepairRisk,
    make_decision_id,
)
from taintforge_env.replay_store import ReplayStore
from taintforge_env.synthesis_loop import (
    EnvironmentSynthesisLoop,
    LoopOutcome,
    SynthesisLoopConfig,
    SynthesisLoopError,
)
from tests.elf_fixture import write_elf


class FakeRunnerFactory:
    def __init__(
        self,
        *,
        automatic_sequence: list[bool] | None = None,
        fail: bool = False,
        guest_exit_code: int = 0,
    ) -> None:
        self.automatic_sequence = list(automatic_sequence or [False])
        self.fail = fail
        self.guest_exit_code = guest_exit_code
        self.calls: list[int] = []
        self.configs: list[PrebuiltRunnerConfig] = []

    def __call__(self, config: PrebuiltRunnerConfig):
        factory = self

        class FakeRunner:
            def run_and_complete(self) -> PrebuiltRunnerResult:
                factory.calls.append(config.iteration_index)
                factory.configs.append(config)
                if factory.fail:
                    raise PrebuiltRunnerError("simulated runner failure")
                automatic = factory.automatic_sequence[
                    min(config.iteration_index, len(factory.automatic_sequence) - 1)
                ]
                artifacts = (
                    config.session_dir.parent
                    / f"fake-artifacts-{config.iteration_index}"
                )
                if artifacts.exists():
                    import shutil

                    shutil.rmtree(artifacts)
                write_artifacts(
                    artifacts,
                    automatic=automatic,
                    resource=f"/var/run/repair-{config.iteration_index}",
                )
                record = IterationController(config.session_dir).complete_iteration(
                    iteration_index=config.iteration_index,
                    artifacts_dir=artifacts,
                    guest_exit_code=factory.guest_exit_code,
                    timed_out=factory.guest_exit_code == 124,
                )
                run_dir = (
                    config.session_dir
                    / "iterations"
                    / f"{config.iteration_index:04d}"
                    / "run"
                )
                run_dir.mkdir(exist_ok=True)
                return PrebuiltRunnerResult(
                    iteration_index=config.iteration_index,
                    run_dir=run_dir,
                    guest_exit_code=factory.guest_exit_code,
                    timed_out=factory.guest_exit_code == 124,
                    stop_reason=record.stop_reason,
                    progress=record.progress or {},
                    claim_path=(
                        config.session_dir
                        / "iterations"
                        / f"{config.iteration_index:04d}"
                        / "execution_attempt.json"
                    ),
                    attempt_id=record.attempt_id,
                    attempt_result_path=(
                        config.session_dir / str(record.attempt_result)
                    ),
                )

        return FakeRunner()


class SynthesisLoopTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.project = self.root / "project"
        self.project.mkdir()
        for relative in (
            "scripts/capture_runtime_observations.py",
            "scripts/parse_strace.py",
            "scripts/parse_qemu_strace.py",
            "scripts/plan_repairs.py",
            "scripts/generate_report.py",
            "scripts/start_network_emulator.py",
            "scripts/start_transparent_logger.py",
        ):
            path = self.project / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("# test placeholder\n", encoding="utf-8")
        self.binary = write_elf(
            self.root / "sample",
            arch="x86_64",
        )
        self.seed = make_seed(self.root, self.binary)
        self.template = self.root / "template"
        (self.template / "config").mkdir(parents=True)
        write_json(
            self.template / "config" / "runtime.json",
            {
                "arch": "x86_64",
                "host_binary": str(self.binary),
                "guest_binary": "/bin/unpacked.elf",
                "qemu_required": False,
                "rootfs": str(self.seed),
            },
        )
        write_json(
            self.template / "config" / "network_policy.json",
            {
                "mode": "local_test",
                "allow_internet": False,
                "services": [],
                "catch_all": {"enabled": True},
            },
        )
        self.target = self.root / "target.json"
        write_json(
            self.target,
            {
                "schema_version": 1,
                "goal_id": "test_goal",
                "description": "test target",
                "mode": "all",
                "rules": [
                    {
                        "id": "open",
                        "type": "event_count",
                        "source": "syscall",
                        "where": {"syscall": "openat"},
                        "min_count": 1,
                    }
                ],
            },
        )
        self.session = self.root / "session"
        self.store = self.root / "snapshots"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def config(self, **overrides) -> SynthesisLoopConfig:
        values = {
            "session_dir": self.session,
            "template_run_dir": self.template,
            "project_root": self.project,
            "snapshot_store": self.store,
            "seed_rootfs": self.seed,
            "max_iterations": 4,
            "timeout_seconds": 10,
            "max_steps": 4,
        }
        values.update(overrides)
        return SynthesisLoopConfig(**values)

    def test_new_session_runs_and_stops_without_automatic_repairs(self) -> None:
        factory = FakeRunnerFactory(automatic_sequence=[False])
        result = EnvironmentSynthesisLoop(
            self.config(),
            runner_factory=factory,
        ).run()
        self.assertEqual(result.outcome, LoopOutcome.COMPLETED)
        self.assertEqual(result.stop_reason, "no_automatic_repairs")
        self.assertEqual(factory.calls, [0])
        self.assertTrue(result.report_json.is_file())
        self.assertTrue(result.report_markdown.is_file())
        report = json.loads(result.report_json.read_text(encoding="utf-8"))
        self.assertTrue(
            report["iterations"][0]["environment_manifest_id"].startswith(
                "manifest-v0000-"
            )
        )
        self.assertTrue(
            report["iterations"][0]["attempt_id"].startswith("attempt-000-")
        )
        self.assertTrue(report["iterations"][0]["attempt_result"])
        self.assertEqual(
            IterationController(self.session).load().state,
            SessionState.COMPLETED,
        )

    def test_multi_iteration_loop_applies_repairs_until_stop(self) -> None:
        factory = FakeRunnerFactory(automatic_sequence=[True, False])
        result = EnvironmentSynthesisLoop(
            self.config(),
            runner_factory=factory,
        ).run()
        self.assertEqual(result.outcome, LoopOutcome.COMPLETED)
        self.assertEqual(factory.calls, [0, 1])
        manifest = IterationController(self.session).load()
        self.assertEqual(len(manifest.iterations), 2)
        second_rootfs = (
            self.session / "iterations" / "0001" / "execution" / "rootfs"
        )
        self.assertTrue((second_rootfs / "var" / "run" / "repair-0").is_dir())

    def test_step_limit_pauses_without_preparing_unused_iteration(self) -> None:
        first_factory = FakeRunnerFactory(automatic_sequence=[True, False])
        first = EnvironmentSynthesisLoop(
            self.config(max_steps=1),
            runner_factory=first_factory,
        ).run()
        self.assertEqual(first.outcome, LoopOutcome.PAUSED)
        manifest = IterationController(self.session).load()
        self.assertEqual(len(manifest.iterations), 1)
        self.assertEqual(manifest.iterations[0].state.value, "completed")

        second_factory = FakeRunnerFactory(automatic_sequence=[True, False])
        second = EnvironmentSynthesisLoop(
            self.config(max_steps=1),
            runner_factory=second_factory,
        ).run()
        self.assertEqual(second.outcome, LoopOutcome.COMPLETED)
        self.assertEqual(second_factory.calls, [1])

    def test_completed_session_resume_is_idempotent(self) -> None:
        factory = FakeRunnerFactory(automatic_sequence=[False])
        loop = EnvironmentSynthesisLoop(self.config(), runner_factory=factory)
        loop.run()
        second_factory = FakeRunnerFactory(automatic_sequence=[False])
        result = EnvironmentSynthesisLoop(
            self.config(),
            runner_factory=second_factory,
        ).run()
        self.assertEqual(result.outcome, LoopOutcome.COMPLETED)
        self.assertEqual(second_factory.calls, [])

    def test_timeout_returns_intervention_required_terminal_result(self) -> None:
        result = EnvironmentSynthesisLoop(
            self.config(),
            runner_factory=FakeRunnerFactory(guest_exit_code=124),
        ).run()

        self.assertEqual(result.outcome, LoopOutcome.INTERVENTION_REQUIRED)
        self.assertEqual(result.stop_reason, "execution_timed_out")
        self.assertEqual(
            IterationController(self.session).load().state,
            SessionState.FAILED,
        )

    def test_initialize_only_binds_target_without_preparing_iteration(self) -> None:
        result = EnvironmentSynthesisLoop(
            self.config(initialize_only=True),
            runner_factory=FakeRunnerFactory(),
        ).run()
        self.assertEqual(result.outcome, LoopOutcome.INITIALIZED)
        self.assertEqual(len(IterationController(self.session).load().iterations), 0)
        self.assertTrue((self.session / "synthesis_loop.json").is_file())

    def test_controlled_network_is_bound_and_passed_to_runner(self) -> None:
        factory = FakeRunnerFactory(automatic_sequence=[False])
        result = EnvironmentSynthesisLoop(
            self.config(
                network_mode="controlled",
                network_self_test=True,
            ),
            runner_factory=factory,
        ).run()
        self.assertEqual(result.outcome, LoopOutcome.COMPLETED)
        self.assertEqual(factory.configs[0].network_mode, "controlled")
        self.assertTrue(factory.configs[0].network_self_test)
        binding = json.loads(
            (self.session / "synthesis_loop.json").read_text()
        )
        self.assertEqual(binding["network_mode"], "controlled")
        self.assertTrue(binding["network_self_test"])
        self.assertFalse(binding["allow_internet"])

    def test_controlled_network_requires_template_policy(self) -> None:
        (self.template / "config" / "network_policy.json").unlink()
        with self.assertRaisesRegex(SynthesisLoopError, "network policy"):
            EnvironmentSynthesisLoop(
                self.config(network_mode="controlled"),
                runner_factory=FakeRunnerFactory(),
            ).run()
        self.assertFalse(self.session.exists())

    def test_controlled_service_script_drift_is_rejected(self) -> None:
        loop = EnvironmentSynthesisLoop(
            self.config(network_mode="controlled", initialize_only=True),
            runner_factory=FakeRunnerFactory(),
        )
        loop.run()
        for name in ("start_network_emulator.py", "start_transparent_logger.py"):
            with self.subTest(script=name):
                script = self.project / "scripts" / name
                original = script.read_bytes()
                try:
                    script.write_bytes(original + b"\n# changed responder\n")
                    with self.assertRaisesRegex(SynthesisLoopError, "modified"):
                        EnvironmentSynthesisLoop.verify_session(self.session)
                    with self.assertRaisesRegex(SynthesisLoopError, "configuration drift"):
                        loop.run()
                finally:
                    script.write_bytes(original)

    def test_replay_store_is_bound_and_passed_to_runner(self) -> None:
        replay_script = self.project / "scripts" / "start_network_replay.py"
        replay_script.write_text("# test replay entrypoint\n", encoding="utf-8")
        write_json(
            self.template / "config" / "network_policy.json",
            {
                "mode": "replay",
                "allow_internet": False,
                "services": [
                    {
                        "service_type": "tcp",
                        "role": "c2",
                        "remote_ip": "203.0.113.10",
                        "remote_port": 48101,
                        "domain": None,
                        "bind_ip": "127.0.0.1",
                        "bind_port": 48101,
                        "protocol_hint": "c2_binary",
                    }
                ],
                "catch_all": {"enabled": True},
            },
        )
        replay = ReplayStore(self.root / "replay-store")
        replay.add(
            transport="tcp",
            remote_ip="203.0.113.10",
            remote_port=48101,
            request_bytes=b"hello",
            response_bytes=b"world",
            protocol_hint="c2_binary",
        )
        digest = replay.validate()["store_sha256"]
        factory = FakeRunnerFactory(automatic_sequence=[False])

        result = EnvironmentSynthesisLoop(
            self.config(
                network_mode="replay",
                replay_store_path=replay.root,
            ),
            runner_factory=factory,
        ).run()

        self.assertEqual(result.outcome, LoopOutcome.COMPLETED)
        self.assertEqual(factory.configs[0].network_mode, "replay")
        self.assertEqual(factory.configs[0].replay_store_path, replay.root.resolve())
        self.assertEqual(
            factory.configs[0].replay_store_expected_sha256,
            digest,
        )
        binding = json.loads((self.session / "synthesis_loop.json").read_text())
        self.assertEqual(binding["replay_store_path"], str(replay.root.resolve()))
        self.assertEqual(binding["replay_store_sha256"], digest)
        self.assertEqual(binding["replay_store_entries"], 1)
        self.assertTrue(
            EnvironmentSynthesisLoop.verify_session(self.session)[
                "binding_verified"
            ]
        )

    def test_replay_store_drift_is_rejected_on_resume_and_verify(self) -> None:
        replay_script = self.project / "scripts" / "start_network_replay.py"
        replay_script.write_text("# test replay entrypoint\n", encoding="utf-8")
        write_json(
            self.template / "config" / "network_policy.json",
            {
                "mode": "replay",
                "allow_internet": False,
                "services": [
                    {
                        "service_type": "tcp",
                        "role": "c2",
                        "remote_ip": "203.0.113.10",
                        "remote_port": 48101,
                        "domain": None,
                        "bind_ip": "127.0.0.1",
                        "bind_port": 48101,
                        "protocol_hint": "c2_binary",
                    }
                ],
            },
        )
        replay = ReplayStore(self.root / "replay-store")
        replay.add(
            transport="tcp",
            remote_ip="203.0.113.10",
            remote_port=48101,
            request_bytes=b"hello",
            response_bytes=b"first",
            protocol_hint="c2_binary",
        )
        EnvironmentSynthesisLoop(
            self.config(
                network_mode="replay",
                replay_store_path=replay.root,
                initialize_only=True,
            ),
            runner_factory=FakeRunnerFactory(),
        ).run()
        replay.add(
            transport="tcp",
            remote_ip="203.0.113.10",
            remote_port=48101,
            request_bytes=b"hello",
            response_bytes=b"changed",
            protocol_hint="c2_binary",
            replace=True,
        )

        with self.assertRaisesRegex(SynthesisLoopError, "configuration drift"):
            EnvironmentSynthesisLoop(
                self.config(network_mode="replay", replay_store_path=None),
                runner_factory=FakeRunnerFactory(),
            ).run()
        with self.assertRaisesRegex(SynthesisLoopError, "modified"):
            EnvironmentSynthesisLoop.verify_session(self.session)

    def test_template_configuration_drift_is_rejected(self) -> None:
        EnvironmentSynthesisLoop(
            self.config(max_steps=1),
            runner_factory=FakeRunnerFactory(automatic_sequence=[True]),
        ).run()
        runtime = self.template / "config" / "runtime.json"
        payload = json.loads(runtime.read_text())
        payload["new_field"] = True
        write_json(runtime, payload)
        with self.assertRaisesRegex(SynthesisLoopError, "configuration drift"):
            EnvironmentSynthesisLoop(
                self.config(max_steps=1),
                runner_factory=FakeRunnerFactory(),
            ).run()

    def test_existing_session_requires_explicit_adoption(self) -> None:
        IterationController.initialize(
            session_dir=self.session,
            snapshot_store=self.store,
            seed_rootfs=self.seed,
            sample_sha256=hashlib.sha256(self.binary.read_bytes()).hexdigest(),
            packed_binary_sha256=hashlib.sha256(
                self.binary.read_bytes()
            ).hexdigest(),
            goal_id=DEFAULT_DISCOVERY_GOAL_ID,
            max_iterations=4,
        )
        with self.assertRaisesRegex(SynthesisLoopError, "adopt-existing-session"):
            EnvironmentSynthesisLoop(
                self.config(snapshot_store=None, seed_rootfs=None),
                runner_factory=FakeRunnerFactory(),
            ).run()

        result = EnvironmentSynthesisLoop(
            self.config(
                snapshot_store=None,
                seed_rootfs=None,
                adopt_existing_session=True,
            ),
            runner_factory=FakeRunnerFactory(automatic_sequence=[False]),
        ).run()
        self.assertEqual(result.outcome, LoopOutcome.COMPLETED)

    def test_failed_claim_requires_operator_intervention(self) -> None:
        EnvironmentSynthesisLoop(
            self.config(initialize_only=True),
            runner_factory=FakeRunnerFactory(),
        ).run()
        controller = IterationController(self.session)
        prepared = controller.prepare_next()
        claim = self.session / prepared.record.directory / "execution_attempt.json"
        write_json(
            claim,
            {
                "stage": "failed",
                "malware_started": False,
                "retry_safe": True,
            },
        )
        factory = FakeRunnerFactory()
        with self.assertRaisesRegex(SynthesisLoopError, "reset-safe-failure"):
            EnvironmentSynthesisLoop(
                self.config(),
                runner_factory=factory,
            ).run()
        self.assertEqual(factory.calls, [])
        binding = json.loads((self.session / "synthesis_loop.json").read_text())
        self.assertEqual(binding["outcome"], "intervention_required")

    def test_runner_failure_is_audited(self) -> None:
        with self.assertRaisesRegex(SynthesisLoopError, "simulated runner failure"):
            EnvironmentSynthesisLoop(
                self.config(),
                runner_factory=FakeRunnerFactory(fail=True),
            ).run()
        binding = json.loads((self.session / "synthesis_loop.json").read_text())
        self.assertEqual(binding["outcome"], "intervention_required")
        self.assertIn("simulated runner failure", binding["last_error"])
        self.assertTrue((self.session / "synthesis_report.json").is_file())

    def test_verify_detects_bound_binary_tampering(self) -> None:
        EnvironmentSynthesisLoop(
            self.config(initialize_only=True),
            runner_factory=FakeRunnerFactory(),
        ).run()
        self.binary.write_bytes(b"changed")
        with self.assertRaisesRegex(SynthesisLoopError, "host binary was modified"):
            EnvironmentSynthesisLoop.verify_session(self.session)

    def test_verify_detects_session_provenance_binding_tampering(self) -> None:
        EnvironmentSynthesisLoop(
            self.config(initialize_only=True),
            runner_factory=FakeRunnerFactory(),
        ).run()
        binding_path = self.session / "synthesis_loop.json"
        binding = json.loads(binding_path.read_text(encoding="utf-8"))
        binding["packed_binary_sha256"] = "f" * 64
        write_json(binding_path, binding)

        with self.assertRaisesRegex(
            SynthesisLoopError,
            "session binding mismatch",
        ):
            EnvironmentSynthesisLoop.verify_session(self.session)

    def test_adoption_rejects_mismatched_target_goal(self) -> None:
        digest = hashlib.sha256(self.binary.read_bytes()).hexdigest()
        IterationController.initialize(
            session_dir=self.session,
            snapshot_store=self.store,
            seed_rootfs=self.seed,
            sample_sha256=digest,
            packed_binary_sha256=digest,
            goal_id="different_goal",
            max_iterations=4,
        )

        with self.assertRaisesRegex(
            SynthesisLoopError,
            "session goal does not match",
        ):
            EnvironmentSynthesisLoop(
                self.config(
                    snapshot_store=None,
                    seed_rootfs=None,
                    target_spec_path=self.target,
                    adopt_existing_session=True,
                ),
                runner_factory=FakeRunnerFactory(),
            ).run()

    def test_qemu_identity_is_bound_and_verified(self) -> None:
        self.binary = write_elf(
            self.root / "sample-arm",
            arch="arm",
        )
        guest = self.seed / "bin" / "unpacked.elf"
        guest.write_bytes(self.binary.read_bytes())
        guest.chmod(0o755)
        qemu = write_elf(
            self.root / "qemu-arm-static",
            arch="x86_64",
        )
        runtime_path = self.template / "config" / "runtime.json"
        runtime = json.loads(runtime_path.read_text(encoding="utf-8"))
        runtime.update(
            {
                "arch": "arm",
                "host_binary": str(self.binary),
                "qemu_required": True,
                "qemu_binary_name": "qemu-arm-static",
                "qemu_host_path": str(qemu),
            }
        )
        write_json(runtime_path, runtime)

        EnvironmentSynthesisLoop(
            self.config(initialize_only=True),
            runner_factory=FakeRunnerFactory(),
        ).run()
        binding = json.loads(
            (self.session / "synthesis_loop.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(binding["execution_backend"], "qemu_user")
        self.assertEqual(binding["target_arch"], "arm")
        self.assertEqual(binding["qemu_host_path"], str(qemu.resolve()))
        self.assertTrue(binding["qemu_host_sha256"])

        qemu.write_bytes(qemu.read_bytes() + b"changed")
        with self.assertRaisesRegex(
            SynthesisLoopError,
            "QEMU executable was modified",
        ):
            EnvironmentSynthesisLoop.verify_session(self.session)

    def test_verify_detects_analysis_stack_tampering(self) -> None:
        EnvironmentSynthesisLoop(
            self.config(initialize_only=True),
            runner_factory=FakeRunnerFactory(),
        ).run()
        script = self.project / "scripts" / "parse_strace.py"
        script.write_text("# changed analyzer\n", encoding="utf-8")
        with self.assertRaisesRegex(SynthesisLoopError, "analysis stack file was modified"):
            EnvironmentSynthesisLoop.verify_session(self.session)

    def test_target_spec_is_bound_and_passed_to_runner(self) -> None:
        factory = FakeRunnerFactory(automatic_sequence=[False])
        result = EnvironmentSynthesisLoop(
            self.config(target_spec_path=self.target),
            runner_factory=factory,
        ).run()
        self.assertEqual(result.outcome, LoopOutcome.COMPLETED)
        self.assertEqual(factory.configs[0].target_spec_path, self.target.resolve())
        binding = json.loads((self.session / "synthesis_loop.json").read_text())
        self.assertEqual(binding["target_goal_id"], "test_goal")
        self.assertEqual(binding["target_spec_path"], str(self.target.resolve()))
        self.assertEqual(
            binding["target_spec_sha256"],
            hashlib.sha256(self.target.read_bytes()).hexdigest(),
        )

    def test_target_spec_tampering_is_rejected_on_resume(self) -> None:
        EnvironmentSynthesisLoop(
            self.config(target_spec_path=self.target, initialize_only=True),
            runner_factory=FakeRunnerFactory(),
        ).run()
        payload = json.loads(self.target.read_text())
        payload["description"] = "changed"
        write_json(self.target, payload)
        with self.assertRaisesRegex(SynthesisLoopError, "configuration drift"):
            EnvironmentSynthesisLoop(
                self.config(target_spec_path=self.target),
                runner_factory=FakeRunnerFactory(),
            ).run()
        with self.assertRaisesRegex(SynthesisLoopError, "was modified"):
            EnvironmentSynthesisLoop.verify_session(self.session)

    def test_resume_reuses_bound_target_path_when_cli_omits_it(self) -> None:
        EnvironmentSynthesisLoop(
            self.config(target_spec_path=self.target, initialize_only=True),
            runner_factory=FakeRunnerFactory(),
        ).run()
        factory = FakeRunnerFactory(automatic_sequence=[False])
        EnvironmentSynthesisLoop(
            self.config(target_spec_path=None),
            runner_factory=factory,
        ).run()
        self.assertEqual(factory.configs[0].target_spec_path, self.target.resolve())

    def test_invalid_target_does_not_create_session(self) -> None:
        (self.project / "scripts" / "generate_report.py").unlink()
        with self.assertRaisesRegex(SynthesisLoopError, "analysis script"):
            EnvironmentSynthesisLoop(
                self.config(),
                runner_factory=FakeRunnerFactory(),
            ).run()
        self.assertFalse(self.session.exists())

    def test_loop_lock_rejects_concurrent_driver(self) -> None:
        lock = self.session.parent / f".{self.session.name}.synthesis-loop.lock"
        lock.touch()
        with lock.open("a+") as stream:
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaisesRegex(SynthesisLoopError, "another synthesis-loop"):
                EnvironmentSynthesisLoop(
                    self.config(),
                    runner_factory=FakeRunnerFactory(),
                ).run()
            fcntl.flock(stream.fileno(), fcntl.LOCK_UN)

    def test_event_log_records_state_transitions(self) -> None:
        EnvironmentSynthesisLoop(
            self.config(),
            runner_factory=FakeRunnerFactory(automatic_sequence=[False]),
        ).run()
        events = [
            json.loads(line)
            for line in (self.session / "synthesis_events.jsonl").read_text().splitlines()
        ]
        names = [event["event"] for event in events]
        self.assertIn("loop_bound", names)
        self.assertIn("iteration_prepared", names)
        self.assertIn("iteration_execution_started", names)
        self.assertIn("iteration_completed", names)
        self.assertIn("invocation_finished", names)


def make_seed(root: Path, binary: Path) -> Path:
    seed = root / "seed"
    (seed / "etc").mkdir(parents=True)
    (seed / "tmp").mkdir()
    (seed / "proc").mkdir()
    (seed / "bin").mkdir()
    (seed / "etc" / "seed.conf").write_text("seed\n", encoding="utf-8")
    guest = seed / "bin" / "unpacked.elf"
    guest.write_bytes(binary.read_bytes())
    guest.chmod(0o755)
    return seed


def write_artifacts(root: Path, *, automatic: bool, resource: str) -> None:
    (root / "config").mkdir(parents=True, exist_ok=True)
    (root / "logs").mkdir(parents=True, exist_ok=True)
    requirement_id = f"req_{hashlib.sha256(resource.encode()).hexdigest()[:10]}"
    operation = "directory_exists" if automatic else "path_exists"
    requirements = {
        "schema_version": 1,
        "requirements": [
            {
                "requirement_id": requirement_id,
                "kind": "filesystem",
                "resource": resource,
                "operation": operation,
                "status": "unmet",
                "blocking": "likely",
                "confidence": 1.0,
                "repairable": True,
                "errno": "ENOENT",
                "evidence": [],
                "details": {},
            }
        ],
    }
    requirements_path = root / "config" / "runtime_requirements.json"
    write_json(requirements_path, requirements)
    source_sha = hashlib.sha256(requirements_path.read_bytes()).hexdigest()
    action = (
        RepairActionKind.CREATE_DIRECTORY
        if automatic
        else RepairActionKind.PROVIDE_FILE
    )
    disposition = (
        RepairDisposition.AUTO_CANDIDATE
        if automatic
        else RepairDisposition.REVIEW_REQUIRED
    )
    plan = {
        "schema_version": 1,
        "planner_version": 1,
        "generated_at_utc": "2026-01-01T00:00:00+00:00",
        "source_requirements": str(requirements_path),
        "source_sha256": source_sha,
        "warnings": [],
        "decisions": [
            {
                "decision_id": make_decision_id(
                    requirement_id,
                    action,
                    disposition,
                    resource,
                ),
                "requirement_id": requirement_id,
                "requirement_kind": "filesystem",
                "resource": resource,
                "operation": operation,
                "action": action.value,
                "disposition": disposition.value,
                "priority": RepairPriority.CRITICAL.value,
                "risk": (
                    RepairRisk.LOW if automatic else RepairRisk.MEDIUM
                ).value,
                "automatic_allowed": automatic,
                "reason": "test decision",
                "parameters": (
                    {"mode": "0755", "parents": True}
                    if automatic
                    else {"create_empty": False}
                ),
            }
        ],
    }
    write_json(root / "config" / "repair_plan.json", plan)
    (root / "logs" / "syscall_events.jsonl").write_text(
        json.dumps(
            {
                "event": "syscall",
                "execution_context": "guest",
                "syscall": "openat",
                "path": resource,
                "return_value": -1,
                "errno": "ENOENT",
            }
        )
        + "\n",
        encoding="utf-8",
    )


def write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    unittest.main()
