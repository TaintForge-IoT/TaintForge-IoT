from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from dataclasses import asdict, replace
from pathlib import Path
from unittest.mock import patch

from taintforge_env.attempt import AttemptOutcome, AttemptStore
from taintforge_env.iteration_controller import (
    IterationController,
    IterationControllerError,
    SessionState,
)
from taintforge_env.prebuilt_runner import (
    CommandResult,
    PrebuiltRootfsRunner,
    PrebuiltRunnerConfig,
    PrebuiltRunnerError,
    SubprocessCommandExecutor,
)
from taintforge_env.replay_store import ReplayStore
from taintforge_env.strace_parser import parse_strace_line
from tests.elf_fixture import write_elf


GOAL_ID = "guest_write_reached"


class FakeExecutor:
    def __init__(self, *, guest_exit_code: int = 0, infrastructure_fail: bool = False):
        self.guest_exit_code = guest_exit_code
        self.infrastructure_fail = infrastructure_fail
        self.commands: list[list[str]] = []

    def run(
        self,
        command,
        *,
        cwd: Path,
        check: bool = True,
        stdout_path: Path | None = None,
        stderr_path: Path | None = None,
    ) -> CommandResult:
        cmd = [str(value) for value in command]
        self.commands.append(cmd)
        if stdout_path is not None:
            stdout_path.parent.mkdir(parents=True, exist_ok=True)
            stdout_path.write_text("guest stdout\n", encoding="utf-8")
        if stderr_path is not None:
            stderr_path.parent.mkdir(parents=True, exist_ok=True)
            stderr_path.write_text("", encoding="utf-8")

        if any(value.endswith("capture_runtime_observations.py") for value in cmd):
            script_index = next(i for i, value in enumerate(cmd) if value.endswith("capture_runtime_observations.py"))
            phase = cmd[script_index + 1]
            run_dir = Path(cmd[cmd.index("--run-dir") + 1])
            config = run_dir / "config"
            config.mkdir(parents=True, exist_ok=True)
            if phase == "before":
                _write_json(config / "rootfs_before.json", {"entries_count": 3})
            elif phase in {"after", "finalize"}:
                _write_json(config / "rootfs_after.json", {"entries_count": 3})
                _write_json(
                    config / "rootfs_diff.json",
                    {
                        "created_count": 0,
                        "modified_count": 0,
                        "deleted_count": 0,
                    },
                )
            if phase in {"requirements", "finalize"}:
                _write_json(
                    config / "runtime_requirements.json",
                    {
                        "schema_version": 1,
                        "requirements": [],
                        "warnings": [],
                    },
                )
                _write_json(
                    config / "observation_lifecycle.json",
                    {"status": "completed"},
                )
            return CommandResult(0)

        if any(
            value.endswith("parse_strace.py")
            or value.endswith("parse_qemu_strace.py")
            for value in cmd
        ):
            out = Path(cmd[cmd.index("--out") + 1])
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(
                json.dumps(
                    asdict(parse_strace_line(
                        'write(1,"x",1) = 1', "strace.1", 1, "guest"
                    ))
                )
                + "\n",
                encoding="utf-8",
            )
            return CommandResult(0)

        if any(value.endswith("plan_repairs.py") for value in cmd):
            requirements = Path(cmd[cmd.index("--requirements") + 1])
            out = Path(cmd[cmd.index("--out") + 1])
            source_hash = hashlib.sha256(requirements.read_bytes()).hexdigest()
            _write_json(
                out,
                {
                    "schema_version": 1,
                    "planner_version": 1,
                    "generated_at_utc": "2026-01-01T00:00:00+00:00",
                    "source_requirements": str(requirements),
                    "source_sha256": source_hash,
                    "warnings": [],
                    "decisions": [],
                },
            )
            return CommandResult(0)

        if any(value.endswith("generate_report.py") for value in cmd):
            run_dir = Path(cmd[cmd.index("--out") + 1])
            _write_json(run_dir / "report.json", {"status": "ok"})
            (run_dir / "report.md").write_text("# Report\n", encoding="utf-8")
            return CommandResult(0)

        if cmd and cmd[-1].endswith("run_prebuilt_sandbox.sh") and "unshare" in cmd:
            if self.infrastructure_fail:
                return CommandResult(1, stderr="unshare failed")
            script = Path(cmd[-1])
            run_dir = script.parent
            logs = run_dir / "logs"
            logs.mkdir(parents=True, exist_ok=True)
            (logs / "malware_started").write_text("now\n", encoding="utf-8")
            (logs / "guest_exit_code").write_text(
                f"{self.guest_exit_code}\n",
                encoding="utf-8",
            )
            script_text = script.read_text(encoding="utf-8")
            if "QEMU_GUEST=" in script_text:
                (logs / "qemu_strace.log").write_text(
                    '100 write(1,0x40001000,1) = 1\n',
                    encoding="utf-8",
                )
            else:
                (logs / "strace.1").write_text(
                    'write(1, "x", 1) = 1\n',
                    encoding="utf-8",
                )
            return CommandResult(self.guest_exit_code)

        return CommandResult(0)


class FakeNetworkResult:
    def __init__(self, manifest_path: Path) -> None:
        self.manifest_path = manifest_path


class FakeNetworkBackend:
    def __init__(self, config, executor) -> None:
        self.config = config
        self.executor = executor
        self.manifest_path = config.run_dir / "config" / "network_backend_manifest.json"
        self.cleaned = False

    def setup(self):
        config_dir = self.config.run_dir / "config"
        logs_dir = self.config.run_dir / "logs"
        requested = config_dir / "network_policy_requested.json"
        requested.write_text(
            (config_dir / "network_policy.json").read_text(),
            encoding="utf-8",
        )
        _write_json(
            config_dir / "network_policy.json",
            {
                "mode": "controlled",
                "allow_internet": False,
                "services": [],
                "catch_all": {"enabled": True},
            },
        )
        _write_json(
            self.manifest_path,
            {
                "state": "ready",
                "allow_internet": False,
                "namespace": "tf-test",
            },
        )
        (logs_dir / "network_events.jsonl").write_text(
            json.dumps(
                {
                    "event": "tcp_connection_open",
                    "original_remote_ip": "203.0.113.10",
                    "original_remote_port": 48101,
                }
            )
            + "\n",
            encoding="utf-8",
        )
        return FakeNetworkResult(self.manifest_path)

    def guest_command(self, sandbox_script: Path):
        return [
            "sudo",
            "ip",
            "netns",
            "exec",
            "tf-test",
            "unshare",
            "--mount",
            "--pid",
            "--fork",
            "--uts",
            "--ipc",
            "--",
            "bash",
            str(sandbox_script),
        ]

    def cleanup(self, *, finalize_logs: bool = True):
        self.cleaned = True
        _write_json(
            self.manifest_path,
            {
                "state": "cleaned",
                "allow_internet": False,
                "namespace": "tf-test",
            },
        )


class PrebuiltRunnerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name)
        self.project = self.base / "project"
        self.project.mkdir()
        for relative in (
            "scripts/capture_runtime_observations.py",
            "scripts/parse_strace.py",
            "scripts/parse_qemu_strace.py",
            "scripts/plan_repairs.py",
            "scripts/generate_report.py",
        ):
            path = self.project / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("# placeholder\n", encoding="utf-8")

        self.binary = write_elf(
            self.base / "sample",
            arch="x86_64",
        )
        self.seed = self.base / "seed-rootfs"
        (self.seed / "bin").mkdir(parents=True)
        (self.seed / "proc").mkdir()
        guest = self.seed / "bin" / "unpacked.elf"
        guest.write_bytes(self.binary.read_bytes())
        guest.chmod(0o755)

        self.template = self.base / "template-run"
        (self.template / "config").mkdir(parents=True)
        _write_json(
            self.template / "config" / "runtime.json",
            {
                "arch": "x86_64",
                "rootfs": str(self.seed),
                "host_binary": str(self.binary),
                "guest_binary": "/bin/unpacked.elf",
                "qemu_required": False,
            },
        )
        _write_json(
            self.template / "config" / "library_plan.json",
            {"requirements": []},
        )
        _write_json(
            self.template / "config" / "library_resolution.json",
            {"resolved": [], "missing": []},
        )
        _write_json(
            self.template / "config" / "network_policy.json",
            {"mode": "local_test", "allow_internet": False, "services": []},
        )

        self.session = self.base / "session"
        IterationController.initialize(
            session_dir=self.session,
            snapshot_store=self.base / "snapshots",
            seed_rootfs=self.seed,
            sample_sha256=_sha256_file(self.binary),
            packed_binary_sha256=_sha256_file(self.binary),
            goal_id=GOAL_ID,
            max_iterations=3,
        )
        IterationController(self.session).prepare_next()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def make_runner(
        self,
        executor: FakeExecutor | None = None,
        *,
        target_spec: Path | None = None,
        network_mode: str = "none",
        network_self_test: bool = False,
        replay_store: Path | None = None,
        replay_store_expected_sha256: str | None = None,
        network_backend_factory=None,
    ) -> PrebuiltRootfsRunner:
        return PrebuiltRootfsRunner(
            PrebuiltRunnerConfig(
                session_dir=self.session,
                iteration_index=0,
                template_run_dir=self.template,
                project_root=self.project,
                timeout_seconds=5,
                target_spec_path=target_spec,
                network_mode=network_mode,
                network_self_test=network_self_test,
                replay_store_path=replay_store,
                replay_store_expected_sha256=(
                    replay_store_expected_sha256
                ),
            ),
            executor=executor or FakeExecutor(),
            network_backend_factory=network_backend_factory,
        )

    def test_validate_binds_exact_prepared_rootfs(self) -> None:
        context = self.make_runner().validate()
        self.assertEqual(context.iteration.index, 0)
        self.assertEqual(
            context.execution_rootfs,
            self.session / "iterations" / "0000" / "execution" / "rootfs",
        )
        self.assertEqual(context.guest_binary, "/bin/unpacked.elf")

    def test_tampered_execution_rootfs_is_rejected_before_claim(self) -> None:
        rootfs = self.session / "iterations" / "0000" / "execution" / "rootfs"
        (rootfs / "tmp").mkdir()
        with self.assertRaisesRegex(
            PrebuiltRunnerError,
            "no longer matches",
        ):
            self.make_runner().validate()
        self.assertFalse(
            (self.session / "iterations" / "0000" / "execution_attempt.json").exists()
        )

    def test_modified_packed_binary_is_rejected_before_claim(self) -> None:
        self.binary.write_bytes(self.binary.read_bytes() + b"modified")
        with self.assertRaisesRegex(
            PrebuiltRunnerError,
            "different packed binary",
        ):
            self.make_runner().validate()
        self.assertFalse(
            (self.session / "iterations" / "0000" / "execution_attempt.json").exists()
        )

    def test_tampered_environment_manifest_is_rejected_before_claim(self) -> None:
        manifest_path = (
            self.session
            / "manifests"
            / "environment_manifest_v0000.json"
        )
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
        payload["change_reason"] = "tampered"
        _write_json(manifest_path, payload)

        with self.assertRaisesRegex(
            PrebuiltRunnerError,
            "manifest digest mismatch",
        ):
            self.make_runner().validate()
        self.assertFalse(
            (self.session / "iterations" / "0000" / "execution_attempt.json").exists()
        )

    def test_qemu_runtime_builds_bind_mounted_execution_plan(self) -> None:
        import shutil

        shutil.rmtree(self.session)
        self.binary = write_elf(
            self.base / "sample-arm",
            arch="arm",
        )
        guest = self.seed / "bin" / "unpacked.elf"
        guest.write_bytes(self.binary.read_bytes())
        guest.chmod(0o755)
        qemu = write_elf(
            self.base / "qemu-arm-static",
            arch="x86_64",
        )
        runtime_path = self.template / "config" / "runtime.json"
        runtime = json.loads(runtime_path.read_text())
        runtime.update(
            {
                "arch": "arm",
                "host_binary": str(self.binary),
                "guest_binary": "/bin/unpacked.elf",
                "qemu_required": True,
                "qemu_binary_name": "qemu-arm-static",
                "qemu_host_path": str(qemu),
            }
        )
        _write_json(runtime_path, runtime)
        IterationController.initialize(
            session_dir=self.session,
            snapshot_store=self.base / "snapshots-arm",
            seed_rootfs=self.seed,
            sample_sha256=_sha256_file(self.binary),
            packed_binary_sha256=_sha256_file(self.binary),
            goal_id=GOAL_ID,
            max_iterations=3,
        )
        IterationController(self.session).prepare_next()

        executor = FakeExecutor()
        runner = self.make_runner(executor)
        with patch.object(runner, "_check_host_dependencies", return_value=None):
            result = runner.run_and_complete()

        self.assertEqual(result.execution_backend, "qemu_user")
        self.assertEqual(result.target_arch, "arm")
        script = (
            self.session
            / "iterations"
            / "0000"
            / "run"
            / "run_prebuilt_sandbox.sh"
        ).read_text(encoding="utf-8")
        self.assertIn('mount --bind "$QEMU_HOST" "$QEMU_MOUNT"', script)
        self.assertIn('"$QEMU_GUEST" -strace "$GUEST_BINARY"', script)
        self.assertNotIn("strace -ff", script)
        import subprocess
        syntax = subprocess.run(
            ["bash", "-n", str(
                self.session
                / "iterations"
                / "0000"
                / "run"
                / "run_prebuilt_sandbox.sh"
            )],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(syntax.returncode, 0, syntax.stderr)
        backend = json.loads(
            result.execution_backend_manifest_path.read_text(encoding="utf-8")
        )
        self.assertEqual(backend["backend"], "qemu_user")
        self.assertEqual(backend["target"]["arch"], "arm")
        self.assertTrue((result.run_dir / "logs" / "qemu_strace.log").is_file())

    def test_missing_guest_binary_is_rejected(self) -> None:
        runtime_path = self.template / "config" / "runtime.json"
        runtime = json.loads(runtime_path.read_text())
        runtime["guest_binary"] = "/bin/missing"
        _write_json(runtime_path, runtime)
        with self.assertRaisesRegex(PrebuiltRunnerError, "guest binary is absent"):
            self.make_runner().validate()

    def test_runtime_template_symlink_is_rejected(self) -> None:
        runtime_path = self.template / "config" / "runtime.json"
        real = self.base / "runtime-real.json"
        runtime_path.replace(real)
        runtime_path.symlink_to(real)
        with self.assertRaisesRegex(PrebuiltRunnerError, "symlink"):
            self.make_runner().validate()

    def test_run_closes_iteration_and_rewrites_runtime(self) -> None:
        executor = FakeExecutor(guest_exit_code=0)
        runner = self.make_runner(executor)
        with patch.object(runner, "_check_host_dependencies", return_value=None):
            result = runner.run_and_complete()

        self.assertEqual(result.guest_exit_code, 0)
        self.assertTrue(result.attempt_result_path.is_file())
        attempt_result = AttemptStore(self.session / "attempts").load_result(
            result.attempt_id
        )
        self.assertEqual(attempt_result.outcome, AttemptOutcome.EXITED)
        self.assertEqual(result.stop_reason, "no_automatic_repairs")
        manifest = IterationController(self.session).load()
        self.assertEqual(manifest.state, SessionState.COMPLETED)
        runtime = json.loads(
            (result.run_dir / "config" / "runtime.json").read_text()
        )
        self.assertEqual(
            runtime["rootfs"],
            str(self.session / "iterations" / "0000" / "execution" / "rootfs"),
        )
        self.assertEqual(runtime["prebuilt_environment"]["iteration_index"], 0)
        self.assertEqual(
            runtime["prebuilt_environment"]["attempt_id"],
            result.attempt_id,
        )
        self.assertTrue(
            runtime["prebuilt_environment"]["environment_manifest_id"].startswith(
                "manifest-v0000-"
            )
        )
        self.assertTrue(
            (self.session / "iterations" / "0000" / "artifacts" / "repair_plan.json").is_file()
        )

    def test_target_spec_marks_iteration_goal_reached(self) -> None:
        target = self.base / "target.json"
        _write_json(
            target,
            {
                "schema_version": 1,
                "goal_id": "guest_write_reached",
                "description": "guest write syscall reached",
                "mode": "all",
                "rules": [
                    {
                        "id": "write",
                        "type": "event_count",
                        "source": "syscall",
                        "where": {"syscall": "write", "success": True},
                        "min_count": 1,
                    }
                ],
            },
        )
        runner = self.make_runner(FakeExecutor(), target_spec=target)
        with patch.object(runner, "_check_host_dependencies", return_value=None):
            result = runner.run_and_complete()
        self.assertTrue(result.target_reached)
        self.assertEqual(result.stop_reason, "goal_reached")
        self.assertTrue(result.target_evaluation_path.is_file())
        evaluation = json.loads(result.target_evaluation_path.read_text())
        self.assertTrue(evaluation["reached"])
        copied = result.run_dir / "config" / "target_state_spec.json"
        self.assertTrue(copied.is_file())
        manifest = IterationController(self.session).load()
        self.assertEqual(manifest.state, SessionState.COMPLETED)
        self.assertEqual(manifest.stop_reason, "goal_reached")

    def test_invalid_target_spec_is_rejected_before_claim(self) -> None:
        target = self.base / "invalid-target.json"
        target.write_text("{}\n", encoding="utf-8")
        with self.assertRaisesRegex(PrebuiltRunnerError, "schema"):
            self.make_runner(target_spec=target).validate()
        self.assertFalse(
            (self.session / "iterations" / "0000" / "execution_attempt.json").exists()
        )

    def test_target_goal_must_match_prepared_contract(self) -> None:
        target = self.base / "different-target.json"
        _write_json(
            target,
            {
                "schema_version": 1,
                "goal_id": "different_goal",
                "description": "different goal",
                "mode": "all",
                "rules": [
                    {
                        "id": "write",
                        "type": "event_count",
                        "source": "syscall",
                        "where": {"syscall": "write"},
                        "min_count": 1,
                    }
                ],
            },
        )
        with self.assertRaisesRegex(PrebuiltRunnerError, "does not match"):
            self.make_runner(target_spec=target).validate()

    def test_timeout_is_observation_not_runner_failure(self) -> None:
        runner = self.make_runner(FakeExecutor(guest_exit_code=124))
        with patch.object(runner, "_check_host_dependencies", return_value=None):
            result = runner.run_and_complete()
        self.assertTrue(result.timed_out)
        self.assertEqual(result.guest_exit_code, 124)
        attempt_result = AttemptStore(self.session / "attempts").load_result(
            result.attempt_id
        )
        self.assertEqual(attempt_result.outcome, AttemptOutcome.TIMED_OUT)
        self.assertIsNotNone(attempt_result.failure_fingerprint)
        self.assertEqual(result.stop_reason, "execution_timed_out")
        self.assertEqual(
            IterationController(self.session).load().state,
            SessionState.FAILED,
        )

    def test_execution_status_exists_before_parser_and_final_observation(self):
        from taintforge_env.observations import load_observation_bundle

        checked = []

        class CheckingExecutor(FakeExecutor):
            def run(self, command, **kwargs):
                cmd = list(map(str, command))
                if any(value.endswith("parse_strace.py") or value.endswith("parse_qemu_strace.py") for value in cmd):
                    output = Path(cmd[cmd.index("--out") + 1])
                    status = output.parent.parent / "config/prebuilt_execution.json"
                    checked.append(json.loads(status.read_text())["guest_exit_code"])
                if any(value.endswith("capture_runtime_observations.py") for value in cmd) and "after" in cmd:
                    run = Path(cmd[cmd.index("--run-dir") + 1])
                    checked.append(load_observation_bundle(run).runtime_status["guest_exit_code"])
                return super().run(command, **kwargs)

        self.make_runner(CheckingExecutor(guest_exit_code=124)).run_and_complete()
        self.assertEqual(checked, [124, 124])

    def test_sandbox_uses_private_namespaces(self) -> None:
        executor = FakeExecutor()
        runner = self.make_runner(executor)
        with patch.object(runner, "_check_host_dependencies", return_value=None):
            runner.run_and_complete()
        unshare = next(command for command in executor.commands if command[:2] == ["sudo", "unshare"])
        for option in ("--mount", "--pid", "--uts", "--ipc", "--net"):
            self.assertIn(option, unshare)
        script = (
            self.session / "iterations" / "0000" / "run" / "run_prebuilt_sandbox.sh"
        ).read_text()
        self.assertIn("mount --make-rprivate /", script)
        self.assertIn("ip link set lo up", script)
        self.assertIn("mount -t proc", script)

    def test_native_sandbox_script_passes_real_bash_syntax_check(self) -> None:
        runner = self.make_runner()
        context = runner.validate()
        for suffix in ("plain", "spaces and 'quotes' and $dollars"):
            with self.subTest(path=suffix):
                candidate = replace(
                    context,
                    run_dir=context.run_dir / suffix,
                    execution_rootfs=context.execution_rootfs / suffix,
                )
                script = runner._build_sandbox_script(candidate, candidate.run_dir)
                syntax = subprocess.run(
                    ["bash", "-n"], input=script, text=True,
                    capture_output=True, check=False,
                )
                self.assertEqual(syntax.returncode, 0, syntax.stderr)

    def test_invalid_wrapper_is_rejected_before_privileged_setup(self) -> None:
        executor = FakeExecutor()
        runner = self.make_runner(executor, network_mode="controlled")
        with patch.object(runner, "_build_sandbox_script", return_value='#!/bin/bash\necho "'), \
                patch.object(runner, "_create_network_backend") as network:
            with self.assertRaisesRegex(PrebuiltRunnerError, "failed bash -n"):
                runner.run_and_complete()
        network.assert_not_called()
        self.assertEqual(executor.commands, [])
        iteration = self.session / "iterations/0000"
        self.assertFalse((iteration / "run").exists())
        claim = json.loads((iteration / "execution_attempt.json").read_text())
        self.assertEqual(claim["stage"], "failed")
        self.assertFalse(claim["malware_started"])
        self.assertTrue(claim["retry_safe"])

    def test_guest_exit_two_is_not_an_infrastructure_failure(self) -> None:
        runner = self.make_runner(FakeExecutor(guest_exit_code=2))
        with patch.object(runner, "_check_host_dependencies", return_value=None):
            result = runner.run_and_complete()
        self.assertEqual(result.guest_exit_code, 2)
        self.assertFalse(result.timed_out)
        self.assertTrue(result.attempt_result_path.is_file())

    def test_private_privileged_outputs_are_owned_before_reading(self) -> None:
        protected: set[Path] = set()
        created: set[Path] = set()
        original_read_text = Path.read_text

        def unprivileged_read(path, *args, **kwargs):
            if path in protected:
                raise PermissionError(f"root-owned private artifact: {path}")
            return original_read_text(path, *args, **kwargs)

        class PrivateOutputExecutor(FakeExecutor):
            def run(self, command, **kwargs):
                cmd = list(command)
                if cmd[:2] == ["sudo", "chown"]:
                    targets = [Path(value) for value in cmd[cmd.index("--") + 2:]]
                    protected.difference_update(
                        path for path in list(protected)
                        if any(path == target or target in path.parents for target in targets)
                    )
                if "scripts/plan_repairs.py" in cmd:
                    Path(cmd[cmd.index("--requirements") + 1]).read_text()
                result = super().run(command, **kwargs)
                private_path = None
                if cmd and cmd[-1].endswith("run_prebuilt_sandbox.sh") and "unshare" in cmd:
                    private_path = Path(cmd[-1]).parent / "logs/guest_exit_code"
                elif "scripts/capture_runtime_observations.py" in cmd and "requirements" in cmd:
                    private_path = Path(cmd[cmd.index("--run-dir") + 1]) / "config/runtime_requirements.json"
                if private_path is not None:
                    private_path.chmod(0o600)
                    protected.add(private_path)
                    created.add(private_path)
                return result

        runner = self.make_runner(PrivateOutputExecutor())
        with patch.object(runner, "_check_host_dependencies", return_value=None), \
                patch.object(Path, "read_text", unprivileged_read):
            result = runner.run_and_complete()
        self.assertEqual(result.guest_exit_code, 0)
        self.assertEqual(len(created), 2)
        self.assertFalse(protected)
        for path in created:
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_infrastructure_error_includes_redirected_stderr_tail(self) -> None:
        runner = self.make_runner()
        context = runner.validate()
        runner.executor = SubprocessCommandExecutor()

        class FailingWrapper:
            def guest_command(self, sandbox_script):
                # Emit real redirected stderr without entering any namespace.
                return [
                    sys.executable, "-c",
                    "import sys; "
                    "sys.stderr.buffer.write(b'old log prefix\\n' + b'x' * 9000 "
                    "+ b'\\xff\\nunexpected EOF while looking for matching quote\\n'); "
                    "sys.exit(2)",
                ]

        with self.assertRaises(PrebuiltRunnerError) as raised:
            runner._execute_guest(context, network_backend=FailingWrapper())
        message = str(raised.exception)
        self.assertIn("wrapper exit code 2", message)
        self.assertIn("unexpected EOF while looking for matching quote", message)
        self.assertIn(str(context.run_dir / "logs/runtime_stderr.log"), message)
        self.assertNotIn("old log prefix", message)
        self.assertLess(len(message), 5000)

    def test_observer_explicitly_allows_external_rootfs(self) -> None:
        executor = FakeExecutor()
        runner = self.make_runner(executor)
        with patch.object(runner, "_check_host_dependencies", return_value=None):
            runner.run_and_complete()
        observer_commands = [
            command
            for command in executor.commands
            if any(value.endswith("capture_runtime_observations.py") for value in command)
        ]
        self.assertEqual(len(observer_commands), 3)
        self.assertTrue(
            all("--allow-external-rootfs" in command for command in observer_commands)
        )

    def test_controlled_network_run_uses_named_namespace_backend(self) -> None:
        executor = FakeExecutor()
        created: list[FakeNetworkBackend] = []

        def factory(config, command_executor):
            backend = FakeNetworkBackend(config, command_executor)
            created.append(backend)
            return backend

        runner = self.make_runner(
            executor,
            network_mode="controlled",
            network_self_test=True,
            network_backend_factory=factory,
        )
        with patch.object(runner, "_check_host_dependencies", return_value=None):
            result = runner.run_and_complete()
        self.assertEqual(result.network_mode, "controlled")
        self.assertTrue(result.network_manifest_path.is_file())
        self.assertTrue(created[0].cleaned)
        execution = next(
            command
            for command in executor.commands
            if command and command[-1].endswith("run_prebuilt_sandbox.sh")
        )
        self.assertEqual(execution[:4], ["sudo", "ip", "netns", "exec"])
        self.assertNotIn("--net", execution)
        runtime = json.loads(
            (result.run_dir / "config" / "runtime.json").read_text()
        )
        self.assertEqual(runtime["network_mode"], "controlled")
        self.assertFalse(runtime["allow_internet"])
        self.assertTrue(
            (result.run_dir / "logs" / "network_events.jsonl").is_file()
        )

    def test_controlled_network_requires_template_policy(self) -> None:
        (self.template / "config" / "network_policy.json").unlink()
        with self.assertRaisesRegex(PrebuiltRunnerError, "network policy"):
            self.make_runner(network_mode="controlled").validate()

    def test_cleanup_error_does_not_skip_post_run_observation(self) -> None:
        class BrokenCleanup(FakeNetworkBackend):
            def cleanup(self, *, finalize_logs=True):
                super().cleanup(finalize_logs=finalize_logs)
                if finalize_logs:
                    execution = self.config.run_dir / "config/prebuilt_execution.json"
                    if not execution.is_file():
                        raise AssertionError("exit status must be published before network cleanup")
                    raise RuntimeError("injected network log cleanup failure")

        runner = self.make_runner(network_mode="controlled", network_backend_factory=BrokenCleanup)
        with patch.object(runner, "_check_host_dependencies"):
            with self.assertRaisesRegex(PrebuiltRunnerError, "network log cleanup failure"):
                runner.run_and_complete()
        run = self.session / "iterations/0000/run"
        journal = json.loads((run / "config/finalization_status.json").read_text())
        self.assertEqual(journal["stages"]["network_cleanup"]["status"], "failed")
        self.assertEqual(journal["stages"]["filesystem"]["status"], "completed")
        self.assertTrue((run / "config/rootfs_diff.json").is_file())
        self.assertEqual(journal["stages"]["repair_plan"]["status"], "completed")
        self.assertEqual(json.loads((run.parent / "execution_attempt.json").read_text())["stage"], "failed")

    def test_failed_observer_recovers_ownership_of_partial_artifacts(self) -> None:
        class BrokenObserver(FakeExecutor):
            def run(self, command, **kwargs):
                result = super().run(command, **kwargs)
                if "scripts/capture_runtime_observations.py" in command and "after" in command:
                    raise RuntimeError("injected observer failure after writing files")
                return result

        executor = BrokenObserver()
        runner = self.make_runner(executor)
        with patch.object(runner, "_check_host_dependencies"):
            with self.assertRaisesRegex(PrebuiltRunnerError, "observer failure"):
                runner.run_and_complete()
        run = self.session / "iterations/0000/run"
        self.assertTrue(any(cmd[:2] == ["sudo", "chown"] and str(run / "config/rootfs_after.json") in cmd
                            for cmd in executor.commands))
        journal = json.loads((run / "config/finalization_status.json").read_text())
        self.assertEqual(journal["stages"]["filesystem"]["status"], "failed")
        self.assertEqual(journal["stages"]["requirements"]["status"], "skipped")

    def test_network_self_test_requires_controlled_mode(self) -> None:
        with self.assertRaisesRegex(PrebuiltRunnerError, "requires"):
            self.make_runner(network_self_test=True)

    def test_replay_mode_requires_store(self) -> None:
        with self.assertRaisesRegex(PrebuiltRunnerError, "requires replay_store"):
            self.make_runner(network_mode="replay")

    def test_replay_run_binds_and_copies_exact_store(self) -> None:
        _write_json(
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
        replay_path = self.base / "replay-store"
        replay = ReplayStore(replay_path)
        replay.add(
            transport="tcp",
            remote_ip="203.0.113.10",
            remote_port=48101,
            request_bytes=b"hello",
            response_bytes=b"world",
            protocol_hint="c2_binary",
        )
        digest = replay.validate()["store_sha256"]
        executor = FakeExecutor()
        created: list[FakeNetworkBackend] = []

        def factory(config, command_executor):
            backend = FakeNetworkBackend(config, command_executor)
            created.append(backend)
            return backend

        runner = self.make_runner(
            executor,
            network_mode="replay",
            replay_store=replay_path,
            replay_store_expected_sha256=digest,
            network_backend_factory=factory,
        )
        with patch.object(runner, "_check_host_dependencies", return_value=None):
            result = runner.run_and_complete()

        copied = result.run_dir / "config" / "replay_store"
        self.assertEqual(result.network_mode, "replay")
        self.assertEqual(created[0].config.responder_mode, "replay")
        self.assertEqual(created[0].config.replay_store_path, copied)
        self.assertEqual(
            created[0].config.replay_store_expected_sha256,
            digest,
        )
        self.assertEqual(ReplayStore(copied).validate()["store_sha256"], digest)
        manifest = json.loads(
            (result.run_dir / "config" / "prebuilt_runner_manifest.json").read_text()
        )
        self.assertEqual(manifest["replay_store_sha256"], digest)
        self.assertEqual(manifest["copied_replay_store_path"], str(copied))

    def test_replay_store_drift_is_rejected_before_claim(self) -> None:
        _write_json(
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
        replay = ReplayStore(self.base / "replay-store")
        replay.add(
            transport="tcp",
            remote_ip="203.0.113.10",
            remote_port=48101,
            request_bytes=b"hello",
            response_bytes=b"first",
            protocol_hint="c2_binary",
        )
        expected = replay.validate()["store_sha256"]
        replay.add(
            transport="tcp",
            remote_ip="203.0.113.10",
            remote_port=48101,
            request_bytes=b"hello",
            response_bytes=b"changed",
            protocol_hint="c2_binary",
            replace=True,
        )

        with self.assertRaisesRegex(PrebuiltRunnerError, "changed after"):
            self.make_runner(
                network_mode="replay",
                replay_store=replay.root,
                replay_store_expected_sha256=expected,
            ).validate()
        self.assertFalse(
            (self.session / "iterations" / "0000" / "execution_attempt.json").exists()
        )

    def test_infrastructure_failure_records_retry_safe_claim(self) -> None:
        runner = self.make_runner(FakeExecutor(infrastructure_fail=True))
        with patch.object(runner, "_check_host_dependencies", return_value=None):
            with self.assertRaisesRegex(PrebuiltRunnerError, "infrastructure failed"):
                runner.run_and_complete()
        claim = json.loads(
            (
                self.session
                / "iterations"
                / "0000"
                / "execution_attempt.json"
            ).read_text()
        )
        self.assertEqual(claim["stage"], "failed")
        self.assertFalse(claim["malware_started"])
        self.assertTrue(claim["retry_safe"])


    def test_claim_blocks_manual_completion_while_runner_is_active(self) -> None:
        claim = self.session / "iterations" / "0000" / "execution_attempt.json"
        _write_json(
            claim,
            {
                "session_id": IterationController(self.session).load().session_id,
                "iteration_index": 0,
                "attempt_id": IterationController(self.session)
                .load()
                .iterations[0]
                .attempt_id,
                "stage": "executing",
            },
        )
        with self.assertRaisesRegex(Exception, "not ready for completion"):
            IterationController(self.session).complete_iteration(
                iteration_index=0,
                artifacts_dir=self.template,
            )

    def test_claim_contract_binding_is_checked_before_completion(self) -> None:
        controller = IterationController(self.session)
        session = controller.load()
        record = session.iterations[0]
        contract = AttemptStore(self.session / "attempts").load_contract(
            record.attempt_id
        )
        claim = self.session / record.directory / "execution_attempt.json"
        _write_json(
            claim,
            {
                "session_id": session.session_id,
                "iteration_index": record.index,
                "attempt_id": record.attempt_id,
                "attempt_contract_sha256": "f" * 64,
                "environment_manifest_id": record.environment_manifest_id,
                "environment_manifest_version": (
                    record.environment_manifest_version
                ),
                "environment_snapshot_id": record.environment_snapshot_id,
                "stage": "completing",
            },
        )
        self.assertNotEqual("f" * 64, contract.contract_sha256)

        with self.assertRaisesRegex(
            IterationControllerError,
            "contract digest mismatch",
        ):
            controller.complete_iteration(
                iteration_index=0,
                artifacts_dir=self.template,
            )

    def test_retry_safe_failure_can_be_reset(self) -> None:
        runner = self.make_runner(FakeExecutor(infrastructure_fail=True))
        with patch.object(runner, "_check_host_dependencies", return_value=None):
            with self.assertRaises(PrebuiltRunnerError):
                runner.run_and_complete()
        runner.reset_safe_failure()
        iteration = self.session / "iterations" / "0000"
        self.assertFalse((iteration / "execution_attempt.json").exists())
        self.assertFalse((iteration / "run").exists())
        runner.validate()

    def test_failure_after_guest_start_cannot_be_reset(self) -> None:
        iteration = self.session / "iterations" / "0000"
        _write_json(
            iteration / "execution_attempt.json",
            {
                "attempt_id": IterationController(self.session)
                .load()
                .iterations[0]
                .attempt_id,
                "stage": "failed",
                "malware_started": True,
                "retry_safe": False,
            },
        )
        with self.assertRaisesRegex(
            PrebuiltRunnerError,
            "after malware started",
        ):
            self.make_runner().reset_safe_failure()

    def test_existing_claim_prevents_second_execution(self) -> None:
        claim = self.session / "iterations" / "0000" / "execution_attempt.json"
        _write_json(claim, {"stage": "failed"})
        with self.assertRaisesRegex(PrebuiltRunnerError, "execution attempt"):
            self.make_runner().validate()


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


if __name__ == "__main__":
    unittest.main()
