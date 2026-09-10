from __future__ import annotations

import fcntl
import hashlib
import json
import os
import pwd
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Protocol, Sequence

from .attempt import AttemptContract, AttemptStore, AttemptValidationError
from .controlled_network_backend import (
    ControlledNetworkBackend,
    ControlledNetworkConfig,
    ControlledNetworkError
)
from .environment_snapshot import (
    EnvironmentSnapshotError,
    EnvironmentSnapshotStore,
    scan_environment,
    tree_digest
)
from .execution_backend import (
    ExecutionBackendError,
    ExecutionBackendKind,
    ExecutionBackendResolver,
    ExecutionPlan,
    TraceBackend,
    resolve_runtime_guest_binary,
    resolve_runtime_host_binary
)
from .iteration_controller import (
    IterationController,
    IterationControllerError,
    IterationRecord,
    IterationState,
    SessionManifest,
    SessionState
)
from .network_policy import load_network_policy
from .network_replay import NetworkReplayError, validate_replay_policy
from .replay_store import ReplayStore, ReplayStoreValidationError
from .target_state_oracle import (
    TargetStateError,
    TargetStateEvaluation,
    TargetStateOracle,
    TargetStateSpec
)


class PrebuiltRunnerError(RuntimeError):
    """Raised when a prepared iteration cannot be executed safely."""


class RunnerStage(StrEnum):
    CLAIMED = "claimed"
    VALIDATED = "validated"
    PREPARED = "prepared"
    EXECUTING = "executing"
    POSTPROCESSING = "postprocessing"
    COMPLETING = "completing"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass(slots=True, frozen=True)
class CommandResult:
    returncode: int
    stdout: str = ""
    stderr: str = ""


class CommandExecutor(Protocol):
    def run(self,command: Sequence[str],*,cwd: Path,check: bool = True,stdout_path: Path | None = None,stderr_path: Path | None = None) -> CommandResult: ...


class NetworkBackendLike(Protocol):
    manifest_path: Path

    def setup(self) -> Any: ...

    def guest_command(self, sandbox_script: Path) -> list[str]: ...

    def cleanup(self, *, finalize_logs: bool = True) -> None: ...


NetworkBackendFactory = Callable[[ControlledNetworkConfig, CommandExecutor],NetworkBackendLike]


class SubprocessCommandExecutor:

    def run(self,command: Sequence[str],*,cwd: Path,check: bool = True,stdout_path: Path | None = None,stderr_path: Path | None = None) -> CommandResult:
        env = os.environ.copy()
        env["PYTHONPATH"] = str(cwd)

        stdout_handle = None
        stderr_handle = None
        try:
            if stdout_path is not None:
                stdout_path.parent.mkdir(parents=True, exist_ok=True)
                stdout_handle = stdout_path.open("w", encoding="utf-8")
            if stderr_path is not None:
                stderr_path.parent.mkdir(parents=True, exist_ok=True)
                stderr_handle = stderr_path.open("w", encoding="utf-8")

            completed = subprocess.run(list(command),cwd=cwd,env=env,text=True,stdout=stdout_handle if stdout_handle is not None else subprocess.PIPE,stderr=stderr_handle if stderr_handle is not None else subprocess.PIPE,check=False)
        finally:
            if stdout_handle is not None:
                stdout_handle.close()
            if stderr_handle is not None:
                stderr_handle.close()

        result = CommandResult(returncode=completed.returncode,stdout=completed.stdout or "",stderr=completed.stderr or "")
        if check and result.returncode != 0:
            raise PrebuiltRunnerError(f"command failed with exit code {result.returncode}: {' '.join(command)}\n stdout:\n{result.stdout[-4000:]}\n stderr:\n{result.stderr[-4000:]}")
        return result


@dataclass(slots=True, frozen=True)
class PreparedRunContext:
    session: SessionManifest
    iteration: IterationRecord
    iteration_dir: Path
    execution_rootfs: Path
    environment_tree_sha256: str
    template_run_dir: Path
    template_runtime_path: Path
    template_network_policy_path: Path | None
    host_binary: Path
    guest_binary: str
    run_dir: Path
    claim_path: Path
    execution_plan: ExecutionPlan
    attempt_contract: AttemptContract
    target_spec: TargetStateSpec | None = None
    replay_store_path: Path | None = None
    replay_store_sha256: str | None = None
    replay_store_entries: int | None = None


@dataclass(slots=True, frozen=True)
class PrebuiltRunnerResult:
    iteration_index: int
    run_dir: Path
    guest_exit_code: int
    timed_out: bool
    stop_reason: str | None
    progress: dict[str, Any]
    claim_path: Path
    attempt_id: str
    attempt_result_path: Path
    target_reached: bool = False
    target_evaluation_path: Path | None = None
    network_mode: str = "none"
    network_manifest_path: Path | None = None
    execution_backend: str = "native"
    target_arch: str = "unknown"
    execution_backend_manifest_path: Path | None = None


@dataclass(slots=True)
class PrebuiltRunnerConfig:
    session_dir: Path
    iteration_index: int
    template_run_dir: Path
    project_root: Path
    timeout_seconds: int = 60
    binary_path: Path | None = None
    target_spec_path: Path | None = None
    network_mode: str = "none"
    network_self_test: bool = False
    replay_store_path: Path | None = None
    replay_store_expected_sha256: str | None = None
    goal_reached: bool = False
    goal_reason: str | None = None
    keep_run_dir: bool = True

    def __post_init__(self) -> None:
        self.session_dir = Path(self.session_dir)
        self.template_run_dir = Path(self.template_run_dir)
        self.project_root = Path(self.project_root)
        if self.binary_path is not None:
            self.binary_path = Path(self.binary_path)
        if self.target_spec_path is not None:
            self.target_spec_path = Path(self.target_spec_path).resolve(strict=False)
        if self.replay_store_path is not None:
            self.replay_store_path = Path(self.replay_store_path).resolve(
                strict=False
            )
        if self.iteration_index < 0:
            raise PrebuiltRunnerError("iteration_index must be non-negative")
        if self.timeout_seconds < 1:
            raise PrebuiltRunnerError("timeout_seconds must be positive")
        self.network_mode = str(self.network_mode).strip().lower()
        if self.network_mode not in {"none", "controlled", "replay"}:
            raise PrebuiltRunnerError(
                "network_mode must be one of: none, controlled, replay"
            )
        if self.network_self_test and self.network_mode != "controlled":
            raise PrebuiltRunnerError("network_self_test requires network_mode=controlled")
        if self.network_mode == "replay" and self.replay_store_path is None:
            raise PrebuiltRunnerError("network_mode=replay requires replay_store_path")
        if self.network_mode != "replay" and self.replay_store_path is not None:
            raise PrebuiltRunnerError("replay_store_path is valid only for network_mode=replay")
        if (self.network_mode != "replay" and self.replay_store_expected_sha256 is not None):
            raise PrebuiltRunnerError("replay_store_expected_sha256 is valid only for network_mode=replay")
        if self.goal_reached and not self.goal_reason:
            self.goal_reason = "explicit goal marker supplied by runner caller"


class PrebuiltRootfsRunner:

    ADAPTER_VERSION = 6
    TEMPLATE_CONFIG_ALLOWLIST = ("library_plan.json","library_resolution.json","network_policy.json")

    def __init__(self,config: PrebuiltRunnerConfig,*,executor: CommandExecutor | None = None,network_backend_factory: NetworkBackendFactory | None = None) -> None:
        self.config = config
        self.executor = executor or SubprocessCommandExecutor()
        self.network_backend_factory = (network_backend_factory or (lambda backend_config, command_executor: ControlledNetworkBackend(backend_config,executor=command_executor)))
        self.controller = IterationController(self.config.session_dir)
        self.execution_resolver = ExecutionBackendResolver()

    def validate(self) -> PreparedRunContext:
        try:
            session = self.controller.verify()
        except IterationControllerError as exc:
            raise PrebuiltRunnerError(str(exc)) from exc
        if session.state != SessionState.ACTIVE:
            raise PrebuiltRunnerError(f"iteration session is not active: {session.state.value}")
        if self.config.iteration_index >= len(session.iterations):
            raise PrebuiltRunnerError("iteration index does not exist")
        iteration = session.iterations[self.config.iteration_index]
        if iteration.state != IterationState.PREPARED:
            raise PrebuiltRunnerError(f"iteration is not prepared: {iteration.state.value}")
        if self.config.iteration_index != len(session.iterations) - 1:
            raise PrebuiltRunnerError("only the latest prepared iteration may run")

        iteration_dir = _contained_path(self.config.session_dir,iteration.directory,"iteration directory")
        execution_rootfs = iteration_dir / "execution" / "rootfs"
        _validate_directory(execution_rootfs, "execution rootfs")
        if execution_rootfs.is_mount():
            raise PrebuiltRunnerError("execution rootfs contains an active mount at its root")
        try:
            store = EnvironmentSnapshotStore(session.snapshot_store)
            snapshot_manifest = store.verify(iteration.environment_snapshot_id)
            actual_digest = tree_digest(scan_environment(execution_rootfs))
        except EnvironmentSnapshotError as exc:
            raise PrebuiltRunnerError(str(exc)) from exc
        if actual_digest != snapshot_manifest.tree_sha256:
            raise PrebuiltRunnerError("prepared execution rootfs no longer matches its environment snapshot: expected {snapshot_manifest.tree_sha256}, got {actual_digest}")

        template_run_dir = self.config.template_run_dir.resolve(strict=False)
        _validate_directory(template_run_dir, "template run directory")
        template_config = template_run_dir / "config"
        _validate_directory(template_config, "template config directory")
        template_runtime_path = template_config / "runtime.json"
        runtime = _load_json_object(template_runtime_path, "template runtime")
        template_network_policy_path = template_config / "network_policy.json"
        if self.config.network_mode in {"controlled", "replay"}:
            _validate_regular_file(template_network_policy_path,"template network policy")
        elif not template_network_policy_path.is_file():
            template_network_policy_path = None

        try:
            guest_binary = resolve_runtime_guest_binary(runtime)
            host_binary = resolve_runtime_host_binary(runtime,self.config.binary_path,self.config.project_root)
            execution_plan = self.execution_resolver.resolve(runtime=runtime,host_binary=host_binary,rootfs=execution_rootfs,guest_binary=guest_binary)
        except ExecutionBackendError as exc:
            raise PrebuiltRunnerError(str(exc)) from exc
        actual_binary_sha256 = _sha256_file(host_binary)
        if actual_binary_sha256 != session.packed_binary_sha256:
            raise PrebuiltRunnerError(
                f"prepared session is bound to a different packed binary: expected {session.packed_binary_sha256}, got {actual_binary_sha256}")
        if execution_plan.target.sha256 != session.sample_sha256:
            raise PrebuiltRunnerError(
                f"prepared session is bound to a different target ELF: expected {session.sample_sha256}, got {execution_plan.target.sha256}")

        replay_store_path: Path | None = None
        replay_store_sha256: str | None = None
        replay_store_entries: int | None = None
        if self.config.network_mode == "replay":
            assert self.config.replay_store_path is not None
            try:
                replay_validation = ReplayStore(self.config.replay_store_path).validate()
            except ReplayStoreValidationError as exc:
                raise PrebuiltRunnerError(str(exc)) from exc
            replay_store_path = self.config.replay_store_path
            replay_store_sha256 = str(replay_validation["store_sha256"])
            replay_store_entries = int(replay_validation["entries"])
            if (self.config.replay_store_expected_sha256 is not None and replay_store_sha256 != self.config.replay_store_expected_sha256):
                raise PrebuiltRunnerError(f"replay store changed after the execution contract was bound: expected {self.config.replay_store_expected_sha256}, got {replay_store_sha256}")
            assert template_network_policy_path is not None
            try:
                validate_replay_policy(policy=load_network_policy(template_network_policy_path),replay_store=ReplayStore(replay_store_path)
            except (NetworkReplayError,OSError,TypeError,ValueError,json.JSONDecodeError) as exc:
                raise PrebuiltRunnerError(f"invalid deterministic replay preflight: {exc}") from exc

        try:
            attempt_contract = AttemptStore(self.config.session_dir / "attempts").load_contract(iteration.attempt_id)
            IterationController._validate_contract_binding(session,iteration,attempt_contract)
        except (AttemptValidationError, IterationControllerError) as exc:
            raise PrebuiltRunnerError(str(exc)) from exc

        proc_dir = execution_rootfs / "proc"
        _validate_directory(proc_dir, "guest /proc mountpoint")
        if proc_dir.is_mount():
            raise PrebuiltRunnerError("guest /proc is already mounted before iteration execution")

        run_dir = iteration_dir / "run"
        claim_path = iteration_dir / "execution_attempt.json"
        if run_dir.exists() or run_dir.is_symlink():
            raise PrebuiltRunnerError(f"iteration run directory already exists: {run_dir}")
        if claim_path.exists() or claim_path.is_symlink():
            raise PrebuiltRunnerError("iteration already has an execution attempt; prepared rootfs must never be executed twice")
        if _is_relative_to(execution_rootfs, run_dir) or _is_relative_to(run_dir, execution_rootfs):
            raise PrebuiltRunnerError("run directory and execution rootfs must not contain each other")

        target_spec: TargetStateSpec | None = None
        if self.config.target_spec_path is not None:
            try:
                target_spec = TargetStateSpec.load(self.config.target_spec_path)
            except TargetStateError as exc:
                raise PrebuiltRunnerError(str(exc)) from exc
            if target_spec.goal_id != attempt_contract.goal_id:
                raise PrebuiltRunnerError("target-state goal does not match the prepared attempt contract")

        return PreparedRunContext(session=session,iteration=iteration,iteration_dir=iteration_dir,execution_rootfs=execution_rootfs,environment_tree_sha256=actual_digest,template_run_dir=template_run_dir,template_runtime_path=template_runtime_path,template_network_policy_path=template_network_policy_path,host_binary=host_binary,guest_binary=guest_binary,run_dir=run_dir,claim_path=claim_path,execution_plan=execution_plan,attempt_contract=attempt_contract,target_spec=target_spec,replay_store_path=replay_store_path,replay_store_sha256=replay_store_sha256,replay_store_entries=replay_store_entries)

    def run_and_complete(self) -> PrebuiltRunnerResult:
        context = self.validate()
        claim = self._create_claim(context)
        guest_exit_code: int | None = None
        network_backend: NetworkBackendLike | None = None
        network_manifest_path: Path | None = None
        try:
            self._update_claim(context, claim, RunnerStage.VALIDATED)
            self._prepare_run_directory(context)
            self._update_claim(context, claim, RunnerStage.PREPARED)

            self._check_host_dependencies(context)
            if self.config.network_mode in {"controlled", "replay"}:
                network_backend = self._create_network_backend(context)
                network_result = network_backend.setup()
                network_manifest_path = network_result.manifest_path

            try:
                self._capture_observation(context, "before")
                self._update_claim(context,claim,RunnerStage.EXECUTING,malware_started=False,network_mode=self.config.network_mode)
                guest_exit_code = self._execute_guest(context,network_backend=network_backend)
            finally:
                if network_backend is not None:
                    network_backend.cleanup(finalize_logs=True)

            self._update_claim(context,claim,RunnerStage.POSTPROCESSING,malware_started=True,guest_exit_code=guest_exit_code)

            self._normalize_log_ownership(context)
            self._postprocess(context, guest_exit_code)
            target_evaluation = self._evaluate_target_state(context)
            self._validate_final_artifacts(context)

            goal_reached, goal_reason = self._resolve_goal(target_evaluation)

            self._update_claim(context,claim,RunnerStage.COMPLETING,guest_exit_code=guest_exit_code,target_reached=(target_evaluation.reached if target_evaluation is not None else False),target_goal_id=(target_evaluation.goal_id if target_evaluation is not None else None))

            completed = self.controller.complete_iteration(iteration_index=self.config.iteration_index,artifacts_dir=context.run_dir,goal_reached=goal_reached,goal_reason=goal_reason,guest_exit_code=guest_exit_code,timed_out=guest_exit_code == 124)

            if completed.attempt_result is None:
                raise PrebuiltRunnerError("completed iteration did not persist an attempt result")

            attempt_result_path = self.config.session_dir / completed.attempt_result
            self._update_claim(context,claim,RunnerStage.COMPLETED,guest_exit_code=guest_exit_code,stop_reason=completed.stop_reason,progress=completed.progress,attempt_result=completed.attempt_result,retry_safe=False)

            return PrebuiltRunnerResult(
                iteration_index=self.config.iteration_index,
                run_dir=context.run_dir,
                guest_exit_code=guest_exit_code,
                timed_out=guest_exit_code == 124,
                stop_reason=completed.stop_reason,
                progress=completed.progress,
                claim_path=context.claim_path,
                attempt_id=context.attempt_contract.attempt_id,
                attempt_result_path=attempt_result_path,
                target_reached=(target_evaluation.reached if target_evaluation is not None else False),
                target_evaluation_path=(context.run_dir / "config" / "target_state_evaluation.json" if target_evaluation is not None else None),
                network_mode=self.config.network_mode,
                network_manifest_path=network_manifest_path,
                execution_backend=context.execution_plan.backend.value,
                target_arch=context.execution_plan.target.arch,
                execution_backend_manifest_path=(context.run_dir/ "config" / "execution_backend_manifest.json")
            )

        except Exception as exc:
            if network_backend is not None:
                try:
                    network_backend.cleanup(finalize_logs=False)
                except Exception:
                    pass
            marker = context.run_dir / "logs" / "malware_started"
            malware_started = marker.is_file()
            retry_safe = False
            if not malware_started:
                retry_safe = self._rootfs_still_matches_snapshot(context)
            try:
                self._update_claim(context,claim,RunnerStage.FAILED,malware_started=malware_started,guest_exit_code=guest_exit_code,error=f"{type(exc).__name__}: {exc}",retry_safe=retry_safe,network_mode=self.config.network_mode)
            except Exception:
                pass
            if isinstance(exc, PrebuiltRunnerError):
                raise
            if isinstance(exc, (IterationControllerError, ControlledNetworkError)):
                raise PrebuiltRunnerError(str(exc)) from exc
            raise PrebuiltRunnerError(str(exc)) from exc

    def reset_safe_failure(self) -> None:
        lock_path = self.config.session_dir / ".session.lock"
        if not lock_path.is_file() or lock_path.is_symlink():
            raise PrebuiltRunnerError("iteration session lock is invalid")
        with lock_path.open("a+") as stream:
            try:
                fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise PrebuiltRunnerError("iteration session is locked") from exc
            try:
                session = self.controller.load()
                if session.state != SessionState.ACTIVE:
                    raise PrebuiltRunnerError("session is not active")
                if self.config.iteration_index >= len(session.iterations):
                    raise PrebuiltRunnerError("iteration index does not exist")
                record = session.iterations[self.config.iteration_index]
                if record.state != IterationState.PREPARED:
                    raise PrebuiltRunnerError("iteration is not prepared")
                if self.config.iteration_index != len(session.iterations) - 1:
                    raise PrebuiltRunnerError("only the latest prepared iteration may be reset")
                iteration_dir = _contained_path(self.config.session_dir,record.directory,"iteration directory")
                claim_path = iteration_dir / "execution_attempt.json"
                claim = _load_json_object(claim_path, "execution claim")
                if claim.get("attempt_id") != record.attempt_id:
                    raise PrebuiltRunnerError("execution claim attempt mismatch")
                if claim.get("stage") != RunnerStage.FAILED.value:
                    raise PrebuiltRunnerError("execution claim is not failed")
                if claim.get("malware_started") is not False:
                    raise PrebuiltRunnerError("cannot reset an attempt after malware started")
                if claim.get("retry_safe") is not True:
                    raise PrebuiltRunnerError("execution claim is not marked retry-safe")

                rootfs = iteration_dir / "execution" / "rootfs"
                try:
                    store = EnvironmentSnapshotStore(session.snapshot_store)
                    snapshot = store.verify(record.environment_snapshot_id)
                    actual = tree_digest(scan_environment(rootfs))
                except EnvironmentSnapshotError as exc:
                    raise PrebuiltRunnerError(str(exc)) from exc
                if actual != snapshot.tree_sha256:
                    raise PrebuiltRunnerError("execution rootfs changed; retry is unsafe")

                run_dir = iteration_dir / "run"
                if run_dir.is_symlink():
                    raise PrebuiltRunnerError("run directory must not be a symlink")
                if run_dir.exists():
                    shutil.rmtree(run_dir)
                claim_path.unlink()
            finally:
                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)

    def _prepare_run_directory(self, context: PreparedRunContext) -> None:
        temporary = Path(tempfile.mkdtemp(prefix=".prebuilt-run.",suffix=".tmp",dir=context.iteration_dir))
        try:
            config_dir = temporary / "config"
            logs_dir = temporary / "logs"
            config_dir.mkdir()
            logs_dir.mkdir()
            if context.replay_store_path is not None:
                self._copy_bound_replay_store(context,config_dir / "replay_store")

            template_config = context.template_run_dir / "config"
            for filename in self.TEMPLATE_CONFIG_ALLOWLIST:
                source = template_config / filename
                if not source.exists():
                    continue
                _validate_regular_file(source, f"template {filename}")
                shutil.copy2(source, config_dir / filename)

            runtime = _load_json_object(context.template_runtime_path,"template runtime")
            runtime["rootfs"] = str(context.execution_rootfs)
            runtime["host_binary"] = str(context.host_binary)
            runtime["host_binary_path"] = str(context.host_binary)
            runtime["guest_binary"] = context.guest_binary
            runtime["guest_binary_path"] = context.guest_binary
            runtime["qemu_required"] = context.execution_plan.qemu_required
            runtime["execution_backend"] = (context.execution_plan.backend.value)
            runtime["trace_backend"] = (context.execution_plan.trace_backend.value)
            runtime["target_arch"] = context.execution_plan.target.arch
            runtime["qemu_binary_name"] = (context.execution_plan.qemu_binary_name)
            runtime["qemu_host_path"] = (context.execution_plan.qemu_host_path)
            runtime["qemu_guest_path"] = (context.execution_plan.qemu_guest_path)
            runtime["network_mode"] = self.config.network_mode
            runtime["replay_store_source_path"] = (str(context.replay_store_path) if context.replay_store_path is not None else None)
            runtime["replay_store_path"] = (str(context.run_dir / "config" / "replay_store") if context.replay_store_path is not None else None)
            runtime["replay_store_sha256"] = context.replay_store_sha256
            runtime["replay_store_entries"] = context.replay_store_entries
            runtime["allow_internet"] = False
            runtime["prebuilt_environment"] = {
                "schema_version": 1,
                "session_id": context.session.session_id,
                "iteration_index": context.iteration.index,
                "attempt_id": context.attempt_contract.attempt_id,
                "attempt_contract_sha256": (context.attempt_contract.contract_sha256),
                "environment_manifest_id": (context.attempt_contract.environment_manifest_id),
                "environment_manifest_version": (context.attempt_contract.environment_manifest_version),
                "environment_snapshot_id": (context.iteration.environment_snapshot_id),
                "environment_tree_sha256": (context.environment_tree_sha256),
                "execution_rootfs": str(context.execution_rootfs),
                "template_run_dir": str(context.template_run_dir),
            }
            _atomic_write_json(config_dir / "runtime.json", runtime)
            backend_manifest = {
                "schema_version": 1,
                "backend_version": 1,
                "generated_at_utc": _utc_now(),
                **context.execution_plan.to_dict(),
            }
            _atomic_write_json(config_dir / "execution_backend_manifest.json",backend_manifest)

            if context.target_spec is not None:
                context.target_spec.save(config_dir / "target_state_spec.json")

            manifest = {
                "schema_version": 1,
                "adapter_version": self.ADAPTER_VERSION,
                "generated_at_utc": _utc_now(),
                "session_id": context.session.session_id,
                "iteration_index": context.iteration.index,
                "attempt_id": context.attempt_contract.attempt_id,
                "attempt_contract": context.iteration.attempt_contract,
                "attempt_contract_sha256": (context.attempt_contract.contract_sha256),
                "environment_manifest_id": (context.attempt_contract.environment_manifest_id),
                "environment_manifest_version": (context.attempt_contract.environment_manifest_version),
                "environment_snapshot_id": (context.iteration.environment_snapshot_id),
                "environment_tree_sha256": context.environment_tree_sha256,
                "execution_rootfs": str(context.execution_rootfs),
                "template_run_dir": str(context.template_run_dir),
                "template_runtime_sha256": _sha256_filecontext.template_runtime_path),
                "host_binary": str(context.host_binary),
                "host_binary_sha256": _sha256_file(context.host_binary),
                "guest_binary": context.guest_binary,
                "execution_backend": context.execution_plan.backend.value,
                "target_arch": context.execution_plan.target.arch,
                "target_elf_sha256": context.execution_plan.target.sha256,
                "trace_backend": context.execution_plan.trace_backend.value,
                "qemu_host_path": context.execution_plan.qemu_host_path,
                "qemu_host_sha256": context.execution_plan.qemu_host_sha256,
                "qemu_guest_path": context.execution_plan.qemu_guest_path,
                "network_mode": self.config.network_mode,
                "network_self_test": self.config.network_self_test,
                "replay_store_path": (str(context.replay_store_path) if context.replay_store_path is not None else None),
                "copied_replay_store_path": (str(context.run_dir / "config" / "replay_store") if context.replay_store_path is not None else None),
                "replay_store_sha256": context.replay_store_sha256,
                "replay_store_entries": context.replay_store_entries,
                "allow_internet": False,
                "timeout_seconds": self.config.timeout_seconds,
                "target_state": (
                    {
                        "goal_id": context.target_spec.goal_id,
                        "source_path": context.target_spec.source_path,
                        "source_sha256": context.target_spec.source_sha256,
                        "copied_spec": "config/target_state_spec.json",
                    } if context.target_spec is not None else None
                ),
                "isolation": {
                    "mount_namespace": True,
                    "pid_namespace": True,
                    "uts_namespace": True,
                    "ipc_namespace": True,
                    "network_namespace": True,
                    "network_connected": (self.config.network_mode in {"controlled", "replay"}),
                    "proc_private_mount": True,
                    "chroot": True,
                    "seccomp": False,
                    "user_namespace": False
                }
            }
            _atomic_write_json(config_dir / "prebuilt_runner_manifest.json",manifest)
            script_path = temporary / "run_prebuilt_sandbox.sh"
            script_path.write_text(self._build_sandbox_script(context, temporary),encoding="utf-8")
            script_path.chmod(0o700)
            os.replace(temporary, context.run_dir)
            temporary = None
        finally:
            if temporary is not None and temporary.exists():
                shutil.rmtree(temporary, ignore_errors=True)

    def _copy_bound_replay_store(self,context: PreparedRunContext,destination: Path) -> None:

        if context.replay_store_path is None or context.replay_store_sha256 is None:
            raise PrebuiltRunnerError("replay store identity is incomplete")
        source = ReplayStore(context.replay_store_path)
        destination.mkdir(parents=True, exist_ok=False)
        (destination / "requests").mkdir()
        (destination / "responses").mkdir()
        shutil.copy2(source.index_path, destination / "index.json")
        for entry in source.load_entries():
            for source_path in (source.request_blob_path(entry), source.response_blob_path(entry):
                relative = source_path.relative_to(source.root)
                target = destination / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                if target.exists():
                    if target.read_bytes() != source_path.read_bytes():
                        raise PrebuiltRunnerError(f"replay blob collision while copying: {relative}")
                    continue
                shutil.copy2(source_path, target)
        try:
            copied = ReplayStore(destination).validate()
        except ReplayStoreValidationError as exc:
            raise PrebuiltRunnerError(str(exc)) from exc
        if copied["store_sha256"] != context.replay_store_sha256:
            raise PrebuiltRunnerError("replay store changed while the bound execution copy was created")
        for path in destination.rglob("*"):
            path.chmod(0o700 if path.is_dir() else 0o400)
        destination.chmod(0o700)

    def _build_sandbox_script(self,context: PreparedRunContext,temporary_run_dir: Path) -> str:
        del temporary_run_dir
        run_dir = context.run_dir
        rootfs = shlex.quote(str(context.execution_rootfs))
        proc_dir = shlex.quote(str(context.execution_rootfs / "proc"))
        guest = shlex.quote(context.guest_binary)
        logs = run_dir / "logs"
        strace_base = shlex.quote(str(logs / "strace"))
        qemu_trace = shlex.quote(str(logs / "qemu_strace.log"))
        started = shlex.quote(str(logs / "malware_started"))
        exit_file = shlex.quote(str(logs / "guest_exit_code"))
        timeout_value = shlex.quote(str(self.config.timeout_seconds))
        hostname = shlex.quote(f"tf-iot-{context.iteration.index:04d}")

        qemu_setup = ""
        qemu_cleanup = ""
        if context.execution_plan.backend == ExecutionBackendKind.QEMU_USER:
            qemu_host = shlex.quote(str(context.execution_plan.qemu_host_path))
            qemu_guest = shlex.quote(str(context.execution_plan.qemu_guest_path))
            qemu_internal = shlex.quote(
                str(context.execution_rootfs / "__taintforge")
            )
            qemu_mount = shlex.quote(
                str(context.execution_rootfs / "__taintforge" / "qemu-user-static"))
            qemu_setup = f"""
QEMU_HOST={qemu_host}
QEMU_GUEST={qemu_guest}
QEMU_INTERNAL_DIR={qemu_internal}
QEMU_MOUNT={qemu_mount}
QEMU_TRACE={qemu_trace}
mkdir -m 0700 "$QEMU_INTERNAL_DIR"
touch "$QEMU_MOUNT"
mount --bind "$QEMU_HOST" "$QEMU_MOUNT"
mount -o remount,bind,ro "$QEMU_MOUNT"
""".rstrip()
            qemu_cleanup = """
umount -l "$QEMU_MOUNT" >/dev/null 2>&1 || true
rm -f "$QEMU_MOUNT" >/dev/null 2>&1 || true
rmdir "$QEMU_INTERNAL_DIR" >/dev/null 2>&1 || true
""".rstrip()
            execution = """timeout --signal=TERM --kill-after=2s "$TIMEOUT_SECONDS" \
    env -i PATH=/usr/bin:/bin HOME=/ LANG=C LC_ALL=C \
    chroot "$ROOTFS" "$QEMU_GUEST" -strace "$GUEST_BINARY" \
    2> >(tee "$QEMU_TRACE" >&2)"""
        else:
            execution = """timeout --signal=TERM --kill-after=2s "$TIMEOUT_SECONDS" \
    strace -ff -yy -s 4096 -o "$STRACE_BASE" \
    env -i PATH=/usr/bin:/bin HOME=/ LANG=C LC_ALL=C \
    chroot "$ROOTFS" "$GUEST_BINARY"""

        return f"""#!/usr/bin/env bash
set -euo pipefail

ROOTFS={rootfs}
PROC_DIR={proc_dir}
GUEST_BINARY={guest}
STRACE_BASE={strace_base}
STARTED_MARKER={started}
EXIT_FILE={exit_file}
TIMEOUT_SECONDS={timeout_value}
SANDBOX_HOSTNAME={hostname}
{qemu_setup}

mount --make-rprivate /
ip link set lo up
hostname "$SANDBOX_HOSTNAME"
mount -t proc proc "$PROC_DIR"
cleanup() {{
    umount -l "$PROC_DIR" >/dev/null 2>&1 || true
    {qemu_cleanup}
}}
trap cleanup EXIT INT TERM

printf '%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$STARTED_MARKER"
set +e
{execution}
status=$?
set -e
printf '%s\n' "$status" > "$EXIT_FILE"
exit "$status"
"""

    def _execute_guest(self,context: PreparedRunContext,*,network_backend: NetworkBackendLike | None = None) -> int:
        stdout_path = context.run_dir / "logs" / "runtime_stdout.log"
        stderr_path = context.run_dir / "logs" / "runtime_stderr.log"
        script_path = context.run_dir / "run_prebuilt_sandbox.sh"
        if network_backend is not None:
            command = network_backend.guest_command(script_path)
        else:
            command = [
                "sudo",
                "unshare",
                "--mount",
                "--pid",
                "--fork",
                "--uts",
                "--ipc",
                "--net",
                "--",
                "bash",
                str(script_path),
            ]
        result = self.executor.run(command,cwd=self.config.project_root,check=False,stdout_path=stdout_path,stderr_path=stderr_path)
        exit_path = context.run_dir / "logs" / "guest_exit_code"
        if not exit_path.is_file():
            raise PrebuiltRunnerError(
                f"sandbox infrastructure failed before recording the guest exit status (wrapper exit code {result.returncode})")
        try:
            guest_exit = int(exit_path.read_text(encoding="utf-8").strip())
        except (OSError, ValueError) as exc:
            raise PrebuiltRunnerError(f"invalid guest exit status artifact: {exit_path}") from exc
        if guest_exit != result.returncode:
            raise PrebuiltRunnerError(
                f"sandbox wrapper return code does not match guest exit status: wrapper={result.returncode}, guest={guest_exit}")
        return guest_exit

    def _capture_observation(self,context: PreparedRunContext,phase: str) -> None:
        self.executor.run(
            [
                "sudo",
                "env",
                f"PYTHONPATH={self.config.project_root}",
                sys.executable,
                "scripts/capture_runtime_observations.py",
                phase,
                "--run-dir",
                str(context.run_dir),
                "--rootfs",
                str(context.execution_rootfs),
                "--allow-external-rootfs",
            ],
            cwd=self.config.project_root,
            check=True,
        )

    def _postprocess(self,context: PreparedRunContext,guest_exit_code: int) -> None:
        if context.execution_plan.trace_backend == TraceBackend.QEMU_STRACE:
            parse_command = [
                sys.executable,
                "scripts/parse_qemu_strace.py",
                "--input",
                str(context.run_dir / "logs" / "qemu_strace.log"),
                "--out",
                str(context.run_dir / "logs" / "syscall_events.jsonl"),
                "--target-arch",
                context.execution_plan.target.arch,
            ]
        else:
            parse_command = [
                sys.executable,
                "scripts/parse_strace.py",
                "--log-dir",
                str(context.run_dir / "logs"),
                "--out",
                str(context.run_dir / "logs" / "syscall_events.jsonl"),
            ]
        self.executor.run(
            parse_command,
            cwd=self.config.project_root,
            check=True,
        )
        self._capture_observation(context, "finalize")
        self.executor.run(
            [
                sys.executable,
                "scripts/plan_repairs.py",
                "--requirements",
                str(context.run_dir / "config" / "runtime_requirements.json"),
                "--out",
                str(context.run_dir / "config" / "repair_plan.json"),
            ], cwd=self.config.project_root,check=True)

        execution = {
            "schema_version": 1,
            "generated_at_utc": _utc_now(),
            "guest_exit_code": guest_exit_code,
            "timed_out": guest_exit_code == 124,
            "stdout": "logs/runtime_stdout.log",
            "stderr": "logs/runtime_stderr.log",
            "strace": ("logs/qemu_strace.log" if context.execution_plan.trace_backend == TraceBackend.QEMU_STRACE else "logs/strace.*"),
            "execution_backend": context.execution_plan.backend.value,
            "trace_backend": context.execution_plan.trace_backend.value,
            "target_arch": context.execution_plan.target.arch,
        }
        _atomic_write_json(context.run_dir / "config" / "prebuilt_execution.json",execution)

        self.executor.run(
            [
                sys.executable,
                "scripts/generate_report.py",
                "--out",
                str(context.run_dir),
            ], cwd=self.config.project_root,check=True)

    def _evaluate_target_state(self,context: PreparedRunContext) -> TargetStateEvaluation | None:
        if context.target_spec is None:
            return None
        try:
            evaluation = TargetStateOracle().evaluate(context.run_dir,context.target_spec)
            evaluation.save(context.run_dir / "config" / "target_state_evaluation.json")
            return evaluation
        except TargetStateError as exc:
            raise PrebuiltRunnerError(str(exc)) from exc

    def _resolve_goal(self,evaluation: TargetStateEvaluation | None) -> tuple[bool, str | None]:
        reasons: list[str] = []
        reached = False
        if evaluation is not None and evaluation.reached:
            reached = True
            reasons.append(evaluation.reason)
        if self.config.goal_reached:
            reached = True
            reasons.append(self.config.goal_reason or "explicit goal marker supplied by runner caller")
        return reached, "; ".join(reasons) if reasons else None

    def _validate_final_artifacts(self, context: PreparedRunContext) -> None:
        required = (
            context.run_dir / "config" / "runtime.json",
            context.run_dir / "config" / "execution_backend_manifest.json",
            context.run_dir / "config" / "rootfs_before.json",
            context.run_dir / "config" / "rootfs_after.json",
            context.run_dir / "config" / "rootfs_diff.json",
            context.run_dir / "config" / "runtime_requirements.json",
            context.run_dir / "config" / "repair_plan.json",
            context.run_dir / "logs" / "syscall_events.jsonl",
            context.run_dir / "report.json",
            context.run_dir / "report.md"
            )
        if context.execution_plan.trace_backend == TraceBackend.QEMU_STRACE:
            required = (*required,context.run_dir / "logs" / "qemu_strace.log")
        if self.config.network_mode in {"controlled", "replay"}:
            required = (*required,context.run_dir / "config" / "network_policy_requested.json",context.run_dir / "config" / "network_backend_manifest.json",context.run_dir / "logs" / "network_events.jsonl")
        if self.config.network_mode == "replay":
            required = (*required,context.run_dir / "config" / "replay_store" / "index.json")
        if context.target_spec is not None:
            required = (*required,context.run_dir / "config" / "target_state_spec.json",context.run_dir / "config" / "target_state_evaluation.json")
        missing = [str(path) for path in required if not path.is_file()]
        if missing:
            raise PrebuiltRunnerError("runner did not produce required iteration artifacts:\n  - " + "\n  - ".join(missing))
        if self.config.network_mode == "replay":
            try:
                replay_validation = ReplayStore(context.run_dir / "config" / "replay_store").validate()
            except ReplayStoreValidationError as exc:
                raise PrebuiltRunnerError(str(exc)) from exc
            if (replay_validation["store_sha256"] != context.replay_store_sha256):
                raise PrebuiltRunnerError("attempt replay store was modified during execution")

    def _create_network_backend(self,context: PreparedRunContext) -> NetworkBackendLike:
        policy_path = context.run_dir / "config" / "network_policy.json"
        _validate_regular_file(policy_path, "iteration network policy")
        backend_config = ControlledNetworkConfig(
            project_root=self.config.project_root,
            run_dir=context.run_dir,
            template_policy_path=policy_path,
            session_id=context.session.session_id,
            iteration_index=context.iteration.index,
            self_test=self.config.network_self_test,
            responder_mode=("replay" if self.config.network_mode == "replay" else "emulated"),
            replay_store_path=(
                context.run_dir / "config" / "replay_store" if context.replay_store_path is not None else None),
            replay_store_expected_sha256=context.replay_store_sha256
            )
        return self.network_backend_factory(backend_config, self.executor)

    def _check_host_dependencies(self, context: PreparedRunContext) -> None:
        required = ("sudo","unshare","bash","mount","umount","ip","hostname","timeout","chroot","tee")
        if context.execution_plan.backend == ExecutionBackendKind.NATIVE:
            required = (*required, "strace")
        if self.config.network_mode in {"controlled", "replay"}:
            required = (*required, "iptables")
        missing = [name for name in required if shutil.which(name) is None]
        if missing:
            raise PrebuiltRunnerError("missing required host tools: " + ", ".join(missing))
        scripts = [
            "scripts/capture_runtime_observations.py",
            "scripts/parse_strace.py",
            "scripts/parse_qemu_strace.py",
            "scripts/plan_repairs.py",
            "scripts/generate_report.py",
        ]
        if self.config.network_mode == "controlled":
            scripts.extend(
                [
                    "scripts/start_network_emulator.py",
                    "scripts/start_transparent_logger.py",
                ]
            )
        elif self.config.network_mode == "replay":
            scripts.append("scripts/start_network_replay.py")
        for relative in scripts:
            _validate_regular_file(self.config.project_root / relative,relative)

    def _normalize_log_ownership(self, context: PreparedRunContext) -> None:
        user = os.environ.get("SUDO_USER") or os.environ.get("USER")
        if not user:
            try:
                user = pwd.getpwuid(os.getuid()).pw_name
            except KeyError as exc:
                raise PrebuiltRunnerError("cannot determine invoking user for log ownership") from exc
        self.executor.run(
            [
                "sudo",
                "chown",
                "-R",
                f"{user}:{user}",
                str(context.run_dir / "logs"),
            ],
            cwd=self.config.project_root,
            check=True)

    def _create_claim(self,context: PreparedRunContext) -> dict[str, Any]:
        payload = {
            "schema_version": 1,
            "adapter_version": self.ADAPTER_VERSION,
            "attempt_id": context.attempt_contract.attempt_id,
            "attempt_contract_sha256": (context.attempt_contract.contract_sha256),
            "session_id": context.session.session_id,
            "iteration_index": context.iteration.index,
            "environment_manifest_id": (context.attempt_contract.environment_manifest_id),
            "environment_manifest_version": (context.attempt_contract.environment_manifest_version),
            "environment_snapshot_id": (context.iteration.environment_snapshot_id),
            "environment_tree_sha256": context.environment_tree_sha256,
            "execution_rootfs": str(context.execution_rootfs),
            "run_dir": str(context.run_dir),
            "stage": RunnerStage.CLAIMED.value,
            "started_at_utc": _utc_now(),
            "updated_at_utc": _utc_now(),
            "malware_started": False,
            "retry_safe": False,
            "guest_exit_code": None,
            "execution_backend": context.execution_plan.backend.value,
            "target_arch": context.execution_plan.target.arch,
            "trace_backend": context.execution_plan.trace_backend.value,
            "qemu_host_sha256": context.execution_plan.qemu_host_sha256,
            "network_mode": self.config.network_mode,
            "network_self_test": self.config.network_self_test,
            "replay_store_path": (str(context.replay_store_path) if context.replay_store_path is not None else None),
            "replay_store_sha256": context.replay_store_sha256,
            "replay_store_entries": context.replay_store_entries,
            "error": None
        }
        serialized = json.dumps(payload, indent=2, ensure_ascii=False) + "\n"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        try:
            descriptor = os.open(context.claim_path, flags, 0o600)
        except FileExistsError as exc:
            raise PrebuiltRunnerError("iteration execution has already been claimed") from exc
        try:
            os.write(descriptor, serialized.encode("utf-8"))
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        return payload

    def _update_claim(self,context: PreparedRunContext,claim: dict[str, Any],stage: RunnerStage,**updates: Any) -> dict[str, Any]:
        updated = dict(claim)
        updated.update(updates)
        updated["stage"] = stage.value
        updated["updated_at_utc"] = _utc_now()
        if stage in {RunnerStage.COMPLETED, RunnerStage.FAILED}:
            updated["finished_at_utc"] = _utc_now()
        _atomic_write_json(context.claim_path, updated, mode=0o600)
        claim.clear()
        claim.update(updated)
        return updated

    def _rootfs_still_matches_snapshot(self,context: PreparedRunContext) -> bool:
        try:
            return (tree_digest(scan_environment(context.execution_rootfs)) == context.environment_tree_sha256)
        except EnvironmentSnapshotError:
            return False


def _load_json_object(path: Path, label: str) -> dict[str, Any]:
    _validate_regular_file(path, label)
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise PrebuiltRunnerError(f"invalid JSON in {label}: {path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise PrebuiltRunnerError(f"{label} must be a JSON object")
    return raw


def _validate_directory(path: Path, label: str) -> None:
    if path.is_symlink():
        raise PrebuiltRunnerError(f"{label} must not be a symlink: {path}")
    if not path.is_dir():
        raise PrebuiltRunnerError(f"{label} does not exist: {path}")


def _validate_regular_file(path: Path, label: str) -> None:
    if path.is_symlink():
        raise PrebuiltRunnerError(f"{label} must not be a symlink: {path}")
    if not path.is_file():
        raise PrebuiltRunnerError(f"{label} is not a regular file: {path}")


def _validate_guest_path(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise PrebuiltRunnerError(f"{label} is invalid")
    path = PurePosixPath(value)
    if not path.is_absolute() or value == "/":
        raise PrebuiltRunnerError(f"{label} must be an absolute guest path")
    if ".." in path.parts or "." in path.parts or "//" in value:
        raise PrebuiltRunnerError(f"{label} is not normalized: {value}")
    return path.as_posix()


def _guest_path_lexists(rootfs: Path, guest_path: str) -> bool:
    candidate = rootfs.joinpath(*PurePosixPath(guest_path).parts[1:])
    try:
        candidate.lstat()
    except FileNotFoundError:
        return False
    return True


def _contained_path(parent: Path, relative: str, label: str) -> Path:
    value = Path(relative)
    if value.is_absolute() or ".." in value.parts or not value.parts:
        raise PrebuiltRunnerError(f"{label} is not a contained relative path")
    candidate = (Path(parent).resolve(strict=False) / value).resolve(strict=False)
    if not _is_relative_to(candidate, Path(parent)):
        raise PrebuiltRunnerError(f"{label} escapes the session directory")
    return candidate


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.resolve(strict=False).relative_to(parent.resolve(strict=False))
        return True
    except ValueError:
        return False


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _atomic_write_json(path: Path,payload: dict[str, Any],*,mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(mode="w",encoding="utf-8",dir=path.parent,prefix=f".{path.name}.",suffix=".tmp",delete=False) as stream:
            json.dump(payload, stream, indent=2, ensure_ascii=False)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
            temporary = Path(stream.name)
        os.chmod(temporary, mode)
        os.replace(temporary, path)
        temporary = None
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink(missing_ok=True)
