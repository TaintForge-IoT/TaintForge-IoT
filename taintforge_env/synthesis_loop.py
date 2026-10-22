from __future__ import annotations

import fcntl
import hashlib
import json
import os
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import StrEnum
from pathlib import Path
from typing import Any, Callable, Iterator, Protocol

from .iteration_controller import (
    DEFAULT_DISCOVERY_GOAL_ID,
    IterationController,
    IterationControllerError,
    IterationState,
    SessionManifest,
    SessionState,
)
from .execution_backend import (
    ExecutionBackendError,
    ExecutionBackendResolver,
    resolve_runtime_guest_binary,
    resolve_runtime_host_binary,
)
from .prebuilt_runner import (
    PrebuiltRootfsRunner,
    PrebuiltRunnerConfig,
    PrebuiltRunnerError,
    PrebuiltRunnerResult,
)
from .network_policy import load_network_policy
from .network_replay import NetworkReplayError, validate_replay_policy
from .replay_store import ReplayStore, ReplayStoreValidationError
from .target_state_oracle import TargetStateError, TargetStateSpec


class SynthesisLoopError(RuntimeError):
    """Raised when the automatic synthesis loop cannot advance safely."""


class LoopOutcome(StrEnum):
    COMPLETED = "completed"
    PAUSED = "paused"
    INITIALIZED = "initialized"
    INTERVENTION_REQUIRED = "intervention_required"


class RunnerLike(Protocol):
    def run_and_complete(self) -> PrebuiltRunnerResult: ...


RunnerFactory = Callable[[PrebuiltRunnerConfig], RunnerLike]


@dataclass(slots=True)
class SynthesisLoopConfig:
    session_dir: Path
    template_run_dir: Path
    project_root: Path
    snapshot_store: Path | None = None
    seed_rootfs: Path | None = None
    binary_path: Path | None = None
    target_spec_path: Path | None = None
    network_mode: str = "none"
    network_self_test: bool = False
    replay_store_path: Path | None = None
    max_iterations: int = 5
    timeout_seconds: int = 60
    max_steps: int = 1
    adopt_existing_session: bool = False
    initialize_only: bool = False

    def __post_init__(self) -> None:
        self.session_dir = Path(self.session_dir).resolve(strict=False)
        self.template_run_dir = Path(self.template_run_dir).resolve(strict=False)
        self.project_root = Path(self.project_root).resolve(strict=False)
        if self.snapshot_store is not None:
            self.snapshot_store = Path(self.snapshot_store).resolve(strict=False)
        if self.seed_rootfs is not None:
            self.seed_rootfs = Path(self.seed_rootfs).resolve(strict=False)
        if self.binary_path is not None:
            self.binary_path = Path(self.binary_path).resolve(strict=False)
        if self.target_spec_path is not None:
            self.target_spec_path = Path(self.target_spec_path).resolve(strict=False)
        if self.replay_store_path is not None:
            self.replay_store_path = Path(self.replay_store_path).resolve(
                strict=False
            )
        self.network_mode = str(self.network_mode).strip().lower()
        if self.network_mode not in {"none", "controlled", "replay", "record"}:
            raise SynthesisLoopError(
                "network_mode must be one of: none, controlled, replay, record"
            )
        if self.network_self_test and self.network_mode != "controlled":
            raise SynthesisLoopError(
                "network_self_test requires network_mode=controlled"
            )
        if self.network_mode != "replay" and self.replay_store_path is not None:
            raise SynthesisLoopError(
                "replay_store_path is valid only for network_mode=replay"
            )
        if self.max_iterations < 1:
            raise SynthesisLoopError("max_iterations must be positive")
        if self.timeout_seconds < 1:
            raise SynthesisLoopError("timeout_seconds must be positive")
        if self.max_steps < 1:
            raise SynthesisLoopError("max_steps must be positive")


@dataclass(slots=True, frozen=True)
class SynthesisLoopResult:
    session_id: str
    outcome: LoopOutcome
    stop_reason: str | None
    executions_this_invocation: int
    total_iterations: int
    last_iteration_index: int | None
    report_json: Path
    report_markdown: Path
    event_log: Path

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "outcome": self.outcome.value,
            "stop_reason": self.stop_reason,
            "executions_this_invocation": self.executions_this_invocation,
            "total_iterations": self.total_iterations,
            "last_iteration_index": self.last_iteration_index,
            "report_json": str(self.report_json),
            "report_markdown": str(self.report_markdown),
            "event_log": str(self.event_log),
        }


class EnvironmentSynthesisLoop:
    """Thin orchestration layer over controller and prebuilt runner.

    This class deliberately owns no repair, progress, snapshot, or execution
    semantics.  It only advances the already-validated state machine:

        prepare -> execute+complete -> inspect session decision -> repeat

    A separate non-blocking loop lock prevents two automation processes from
    driving the same session concurrently.  Individual controller transitions
    continue to use the controller's own lock.
    """

    SCHEMA_VERSION = 1
    LOOP_VERSION = 6
    BINDING_FILENAME = "synthesis_loop.json"
    EVENT_FILENAME = "synthesis_events.jsonl"
    REPORT_JSON_FILENAME = "synthesis_report.json"
    REPORT_MARKDOWN_FILENAME = "synthesis_report.md"
    REQUIRED_PROJECT_SCRIPTS = (
        "scripts/capture_runtime_observations.py",
        "scripts/parse_strace.py",
        "scripts/parse_qemu_strace.py",
        "scripts/plan_repairs.py",
        "scripts/generate_report.py",
    )

    def __init__(
        self,
        config: SynthesisLoopConfig,
        *,
        runner_factory: RunnerFactory = PrebuiltRootfsRunner,
    ) -> None:
        self.config = config
        self.runner_factory = runner_factory
        self.binding_path = self.config.session_dir / self.BINDING_FILENAME
        self.event_path = self.config.session_dir / self.EVENT_FILENAME
        self.report_json_path = self.config.session_dir / self.REPORT_JSON_FILENAME
        self.report_markdown_path = (
            self.config.session_dir / self.REPORT_MARKDOWN_FILENAME
        )
        self.loop_lock_path = (
            self.config.session_dir.parent
            / f".{self.config.session_dir.name}.synthesis-loop.lock"
        )
        self.execution_resolver = ExecutionBackendResolver()

    def run(self) -> SynthesisLoopResult:
        with self._loop_locked():
            controller, session, binding = self._open_or_initialize()
            invocation_id = int(binding.get("invocations", 0)) + 1
            executions = 0
            self._append_event(
                "invocation_started",
                invocation_id=invocation_id,
                max_steps=self.config.max_steps,
                initialize_only=self.config.initialize_only,
            )

            try:
                controller.verify()

                if self.config.initialize_only:
                    result = self._finalize(
                        controller=controller,
                        binding=binding,
                        invocation_id=invocation_id,
                        outcome=LoopOutcome.INITIALIZED,
                        stop_reason="initialize_only",
                        executions=0,
                        last_error=None,
                    )
                    self._append_event(
                        "invocation_finished",
                        invocation_id=invocation_id,
                        outcome=result.outcome.value,
                        stop_reason=result.stop_reason,
                    )
                    return result

                while True:
                    session = controller.load()
                    if session.state == SessionState.COMPLETED:
                        result = self._finalize(
                            controller=controller,
                            binding=binding,
                            invocation_id=invocation_id,
                            outcome=LoopOutcome.COMPLETED,
                            stop_reason=session.stop_reason,
                            executions=executions,
                            last_error=None,
                        )
                        self._append_event(
                            "invocation_finished",
                            invocation_id=invocation_id,
                            outcome=result.outcome.value,
                            stop_reason=result.stop_reason,
                        )
                        return result
                    if session.state == SessionState.FAILED:
                        result = self._finalize(
                            controller=controller,
                            binding=binding,
                            invocation_id=invocation_id,
                            outcome=LoopOutcome.INTERVENTION_REQUIRED,
                            stop_reason=session.stop_reason,
                            executions=executions,
                            last_error=None,
                        )
                        self._append_event(
                            "invocation_finished",
                            invocation_id=invocation_id,
                            outcome=result.outcome.value,
                            stop_reason=result.stop_reason,
                        )
                        return result
                    if session.state != SessionState.ACTIVE:
                        raise SynthesisLoopError(
                            f"iteration session is not runnable: {session.state.value}"
                        )

                    if executions >= self.config.max_steps:
                        result = self._finalize(
                            controller=controller,
                            binding=binding,
                            invocation_id=invocation_id,
                            outcome=LoopOutcome.PAUSED,
                            stop_reason="invocation_step_limit",
                            executions=executions,
                            last_error=None,
                        )
                        self._append_event(
                            "invocation_finished",
                            invocation_id=invocation_id,
                            outcome=result.outcome.value,
                            stop_reason=result.stop_reason,
                        )
                        return result

                    latest = session.iterations[-1] if session.iterations else None
                    if latest is None or latest.state == IterationState.COMPLETED:
                        prepared = controller.prepare_next()
                        latest = prepared.record
                        self._append_event(
                            "iteration_prepared",
                            invocation_id=invocation_id,
                            iteration=latest.index,
                            environment_snapshot_id=(
                                latest.environment_snapshot_id
                            ),
                            environment_manifest_id=(
                                latest.environment_manifest_id
                            ),
                            environment_manifest_version=(
                                latest.environment_manifest_version
                            ),
                            attempt_id=latest.attempt_id,
                            parent_snapshot_id=latest.parent_snapshot_id,
                        )
                        controller.verify()
                    elif latest.state != IterationState.PREPARED:
                        raise SynthesisLoopError(
                            f"latest iteration has unsupported state: {latest.state.value}"
                        )

                    claim = self._load_existing_claim(latest.directory)
                    if claim is not None:
                        raise SynthesisLoopError(
                            self._claim_intervention_message(latest.index, claim)
                        )

                    runner_config = PrebuiltRunnerConfig(
                        session_dir=self.config.session_dir,
                        iteration_index=latest.index,
                        template_run_dir=self.config.template_run_dir,
                        project_root=self.config.project_root,
                        timeout_seconds=self.config.timeout_seconds,
                        binary_path=self.config.binary_path,
                        target_spec_path=self._effective_target_spec_path(),
                        network_mode=self.config.network_mode,
                        network_self_test=self.config.network_self_test,
                        replay_store_path=self._effective_replay_store_path(),
                        replay_store_expected_sha256=(
                            str(binding.get("replay_store_sha256"))
                            if self.config.network_mode == "replay"
                            else None
                        ),
                    )
                    self._append_event(
                        "iteration_execution_started",
                        invocation_id=invocation_id,
                        iteration=latest.index,
                    )
                    runner = self.runner_factory(runner_config)
                    try:
                        runner_result = runner.run_and_complete()
                    except Exception:
                        # A parser/verification failure can occur after execution.
                        # Only this newly invoked runner may contribute; a blocked
                        # resume must not count a previous attempt again.
                        if getattr(runner, "guest_execution_observed", False):
                            executions += 1
                        raise
                    executions += 1
                    self._append_event(
                        "iteration_completed",
                        invocation_id=invocation_id,
                        iteration=runner_result.iteration_index,
                        attempt_id=runner_result.attempt_id,
                        attempt_result=str(runner_result.attempt_result_path),
                        guest_exit_code=runner_result.guest_exit_code,
                        timed_out=runner_result.timed_out,
                        stop_reason=runner_result.stop_reason,
                        progress=runner_result.progress,
                        target_reached=runner_result.target_reached,
                        network_mode=runner_result.network_mode,
                        network_manifest=(
                            str(runner_result.network_manifest_path)
                            if runner_result.network_manifest_path is not None
                            else None
                        ),
                        target_evaluation=(
                            str(runner_result.target_evaluation_path)
                            if runner_result.target_evaluation_path is not None
                            else None
                        ),
                    )
                    controller.verify()
            except (IterationControllerError, PrebuiltRunnerError, OSError) as exc:
                error = f"{type(exc).__name__}: {exc}"
                self._append_event(
                    "invocation_failed",
                    invocation_id=invocation_id,
                    error=error,
                )
                self._finalize(
                    controller=controller,
                    binding=binding,
                    invocation_id=invocation_id,
                    outcome=LoopOutcome.INTERVENTION_REQUIRED,
                    stop_reason="execution_or_transition_failure",
                    executions=executions,
                    last_error=error,
                )
                raise SynthesisLoopError(str(exc)) from exc
            except SynthesisLoopError as exc:
                error = f"SynthesisLoopError: {exc}"
                self._append_event(
                    "invocation_failed",
                    invocation_id=invocation_id,
                    error=error,
                )
                self._finalize(
                    controller=controller,
                    binding=binding,
                    invocation_id=invocation_id,
                    outcome=LoopOutcome.INTERVENTION_REQUIRED,
                    stop_reason="operator_intervention_required",
                    executions=executions,
                    last_error=error,
                )
                raise

    @classmethod
    def status(cls, session_dir: str | Path) -> dict[str, Any]:
        session = Path(session_dir).resolve(strict=False)
        binding_path = session / cls.BINDING_FILENAME
        binding = _load_json_object(binding_path, "synthesis loop manifest")
        controller = IterationController(session)
        manifest = controller.load()
        return {
            "loop": binding,
            "session": manifest.to_dict(),
            "report_json": str(session / cls.REPORT_JSON_FILENAME),
            "report_markdown": str(session / cls.REPORT_MARKDOWN_FILENAME),
            "event_log": str(session / cls.EVENT_FILENAME),
        }

    @classmethod
    def verify_session(cls, session_dir: str | Path) -> dict[str, Any]:
        session = Path(session_dir).resolve(strict=False)
        binding = _load_json_object(
            session / cls.BINDING_FILENAME,
            "synthesis loop manifest",
        )
        if binding.get("schema_version") != cls.SCHEMA_VERSION:
            raise SynthesisLoopError("unsupported synthesis loop schema version")
        if binding.get("loop_version") != cls.LOOP_VERSION:
            raise SynthesisLoopError("unsupported synthesis loop version")

        controller = IterationController(session)
        manifest = controller.verify()
        if binding.get("session_id") != manifest.session_id:
            raise SynthesisLoopError("synthesis loop session_id mismatch")
        if binding.get("seed_snapshot_id") != manifest.seed_snapshot_id:
            raise SynthesisLoopError("synthesis loop seed snapshot mismatch")
        if binding.get("snapshot_store") != manifest.snapshot_store:
            raise SynthesisLoopError("synthesis loop snapshot store mismatch")
        if binding.get("max_iterations") != manifest.max_iterations:
            raise SynthesisLoopError("synthesis loop iteration budget mismatch")
        session_bindings = {
            "environment_manifest_store": manifest.environment_manifest_store,
            "seed_environment_manifest_id": (
                manifest.seed_environment_manifest_id
            ),
            "sample_sha256": manifest.sample_sha256,
            "packed_binary_sha256": manifest.packed_binary_sha256,
            "attempt_goal_id": manifest.goal_id,
        }
        drift = [
            key
            for key, expected in session_bindings.items()
            if binding.get(key) != expected
        ]
        if drift:
            raise SynthesisLoopError(
                "synthesis loop session binding mismatch: "
                + ", ".join(drift)
            )

        template_runtime = Path(str(binding.get("template_runtime")))
        _validate_regular_file(template_runtime, "bound template runtime")
        if _sha256_file(template_runtime) != binding.get("template_runtime_sha256"):
            raise SynthesisLoopError("bound template runtime was modified")

        host_binary = Path(str(binding.get("host_binary")))
        _validate_regular_file(host_binary, "bound host binary")
        if _sha256_file(host_binary) != binding.get("host_binary_sha256"):
            raise SynthesisLoopError("bound host binary was modified")
        if binding.get("host_binary_sha256") != manifest.packed_binary_sha256:
            raise SynthesisLoopError(
                "bound host binary does not match the session packed binary"
            )
        if binding.get("target_elf_sha256") != manifest.sample_sha256:
            raise SynthesisLoopError(
                "bound target ELF does not match the session sample"
            )
        bound_goal = binding.get("target_goal_id") or DEFAULT_DISCOVERY_GOAL_ID
        if bound_goal != manifest.goal_id:
            raise SynthesisLoopError(
                "bound target goal does not match the session attempt goal"
            )

        qemu_host_raw = binding.get("qemu_host_path")
        qemu_digest = binding.get("qemu_host_sha256")
        if qemu_host_raw is not None:
            if not isinstance(qemu_host_raw, str) or not isinstance(
                qemu_digest,
                str,
            ):
                raise SynthesisLoopError("bound QEMU identity is invalid")
            qemu_host = Path(qemu_host_raw)
            _validate_regular_file(qemu_host, "bound QEMU executable")
            if _sha256_file(qemu_host) != qemu_digest:
                raise SynthesisLoopError("bound QEMU executable was modified")

        if binding.get("analyzer_bundle_path") is not None:
            from .unified_runtime import verify_bundle
            try:
                verify_bundle(Path(binding["analyzer_bundle_path"]), binding["analyzer_bundle_sha256"])
            except (OSError, ValueError, RuntimeError) as exc:
                raise SynthesisLoopError(f"bound analyzer runtime changed: {exc}") from exc

        _verify_bound_file_bundle(
            binding.get("template_config_files"),
            binding.get("template_config_bundle_sha256"),
            "template config",
        )
        _verify_bound_file_bundle(
            binding.get("analysis_stack_files"),
            binding.get("analysis_stack_sha256"),
            "analysis stack",
        )

        target_spec_path = binding.get("target_spec_path")
        if target_spec_path is not None:
            try:
                target_spec = TargetStateSpec.load(Path(str(target_spec_path)))
            except TargetStateError as exc:
                raise SynthesisLoopError(str(exc)) from exc
            if target_spec.source_sha256 != binding.get("target_spec_sha256"):
                raise SynthesisLoopError("bound target-state specification was modified")
            if target_spec.goal_id != binding.get("target_goal_id"):
                raise SynthesisLoopError("bound target-state goal id mismatch")

        replay_store_path = binding.get("replay_store_path")
        replay_store_sha256 = binding.get("replay_store_sha256")
        if binding.get("network_mode") == "replay":
            if not isinstance(replay_store_path, str) or not isinstance(
                replay_store_sha256,
                str,
            ):
                raise SynthesisLoopError("bound replay store identity is invalid")
            try:
                replay_validation = validate_replay_policy(
                    policy=load_network_policy(
                        Path(str(binding.get("template_run_dir")))
                        / "config"
                        / "network_policy.json"
                    ),
                    replay_store=ReplayStore(replay_store_path),
                )
            except (
                NetworkReplayError,
                ReplayStoreValidationError,
                OSError,
                TypeError,
                ValueError,
                json.JSONDecodeError,
            ) as exc:
                raise SynthesisLoopError(
                    f"invalid deterministic replay preflight: {exc}"
                ) from exc
            if replay_validation["store_sha256"] != replay_store_sha256:
                raise SynthesisLoopError("bound replay store was modified")
            if replay_validation["entries"] != binding.get(
                "replay_store_entries"
            ):
                raise SynthesisLoopError("bound replay store entry count changed")
        elif (
            replay_store_path is not None
            or replay_store_sha256 is not None
            or binding.get("replay_store_entries") is not None
        ):
            raise SynthesisLoopError(
                "non-replay session contains an unexpected replay store binding"
            )

        return {
            "session_id": manifest.session_id,
            "session_state": manifest.state.value,
            "stop_reason": manifest.stop_reason,
            "iterations": len(manifest.iterations),
            "binding_verified": True,
            "artifacts_verified": True,
        }

    def _open_or_initialize(
        self,
    ) -> tuple[IterationController, SessionManifest, dict[str, Any]]:
        # Validate the execution target before creating any session state.
        target_identity = self._target_identity()
        manifest_path = self.config.session_dir / "session.json"
        if manifest_path.is_symlink():
            raise SynthesisLoopError("session manifest must not be a symlink")

        created_now = False
        if manifest_path.exists():
            controller = IterationController(self.config.session_dir)
            session = controller.load()
        else:
            if self.config.seed_rootfs is None or self.config.snapshot_store is None:
                raise SynthesisLoopError(
                    "new session requires --seed-rootfs and --snapshot-store"
                )
            session = IterationController.initialize(
                session_dir=self.config.session_dir,
                snapshot_store=self.config.snapshot_store,
                seed_rootfs=self.config.seed_rootfs,
                sample_sha256=target_identity["target_elf_sha256"],
                packed_binary_sha256=target_identity["host_binary_sha256"],
                goal_id=(
                    target_identity["target_goal_id"]
                    or DEFAULT_DISCOVERY_GOAL_ID
                ),
                max_iterations=self.config.max_iterations,
            )
            controller = IterationController(self.config.session_dir)
            created_now = True

        binding = self._binding_payload(session, target_identity)
        if self.binding_path.exists() or self.binding_path.is_symlink():
            stored = _load_json_object(
                self.binding_path,
                "synthesis loop manifest",
            )
            self._verify_config_binding(stored, binding)
            return controller, session, stored

        if not created_now and not self.config.adopt_existing_session:
            raise SynthesisLoopError(
                "existing session is not bound to this synthesis loop; "
                "pass --adopt-existing-session after verifying the target"
            )

        binding["created_at_utc"] = _utc_now()
        binding["updated_at_utc"] = binding["created_at_utc"]
        binding["invocations"] = 0
        binding["outcome"] = "not_started"
        binding["stop_reason"] = None
        binding["last_error"] = None
        _atomic_write_json(self.binding_path, binding)
        self._append_event(
            "loop_bound",
            session_id=session.session_id,
            adopted=not created_now,
        )
        return controller, session, binding

    def _target_identity(self) -> dict[str, Any]:
        _validate_directory(self.config.template_run_dir, "template run directory")
        _validate_directory(self.config.project_root, "project root")
        runtime_path = self.config.template_run_dir / "config" / "runtime.json"
        runtime = _load_json_object(runtime_path, "template runtime")
        if self.config.network_mode in {"controlled", "replay", "record"}:
            _validate_regular_file(
                self.config.template_run_dir / "config" / "network_policy.json",
                "template network policy",
            )
        try:
            host_binary = resolve_runtime_host_binary(
                runtime,
                self.config.binary_path,
                self.config.project_root,
            )
            guest_binary = resolve_runtime_guest_binary(runtime)
            template_rootfs = _resolve_template_rootfs(
                runtime,
                self.config.template_run_dir,
                self.config.project_root,
            )
            execution_plan = self.execution_resolver.resolve(
                runtime=runtime,
                host_binary=host_binary,
                rootfs=template_rootfs,
                guest_binary=guest_binary,
            )
        except ExecutionBackendError as exc:
            raise SynthesisLoopError(str(exc)) from exc
        template_config_files, template_config_digest = (
            self._template_config_identity()
        )
        analysis_files, analysis_digest = self._analysis_stack_identity()
        target_spec_path = self._effective_target_spec_path()
        target_spec: TargetStateSpec | None = None
        if target_spec_path is not None:
            try:
                target_spec = TargetStateSpec.load(target_spec_path)
            except TargetStateError as exc:
                raise SynthesisLoopError(str(exc)) from exc
        replay_store_path = self._effective_replay_store_path()
        replay_store_sha256: str | None = None
        replay_store_entries: int | None = None
        if self.config.network_mode == "replay":
            if replay_store_path is None:
                raise SynthesisLoopError(
                    "network_mode=replay requires --replay-store"
                )
            try:
                replay_validation = validate_replay_policy(
                    policy=load_network_policy(
                        self.config.template_run_dir
                        / "config"
                        / "network_policy.json"
                    ),
                    replay_store=ReplayStore(replay_store_path),
                )
            except (
                NetworkReplayError,
                ReplayStoreValidationError,
                OSError,
                TypeError,
                ValueError,
                json.JSONDecodeError,
            ) as exc:
                raise SynthesisLoopError(
                    f"invalid deterministic replay preflight: {exc}"
                ) from exc
            replay_store_sha256 = str(replay_validation["store_sha256"])
            replay_store_entries = int(replay_validation["entries"])
        return {
            "template_run_dir": str(self.config.template_run_dir),
            "template_runtime": str(runtime_path),
            "template_runtime_sha256": _sha256_file(runtime_path),
            "template_config_files": template_config_files,
            "template_config_bundle_sha256": template_config_digest,
            "project_root": str(self.config.project_root),
            "host_binary": str(host_binary),
            "host_binary_sha256": _sha256_file(host_binary),
            "execution_backend": execution_plan.backend.value,
            "trace_backend": execution_plan.trace_backend.value,
            "target_arch": execution_plan.target.arch,
            "target_elf_sha256": execution_plan.target.sha256,
            "target_interpreter": execution_plan.target.interpreter,
            "qemu_host_path": execution_plan.qemu_host_path,
            "qemu_host_sha256": execution_plan.qemu_host_sha256,
            "qemu_guest_path": execution_plan.qemu_guest_path,
            "analyzer_bundle_path": execution_plan.analyzer_bundle_path,
            "analyzer_bundle_sha256": execution_plan.analyzer_bundle_sha256,
            "analysis_stack_files": analysis_files,
            "analysis_stack_sha256": analysis_digest,
            "target_spec_path": (
                str(target_spec_path) if target_spec_path is not None else None
            ),
            "target_spec_sha256": (
                target_spec.source_sha256 if target_spec is not None else None
            ),
            "target_goal_id": (
                target_spec.goal_id if target_spec is not None else None
            ),
            "timeout_seconds": self.config.timeout_seconds,
            "network_mode": self.config.network_mode,
            "network_self_test": self.config.network_self_test,
            "replay_store_path": (
                str(replay_store_path) if replay_store_path is not None else None
            ),
            "replay_store_sha256": replay_store_sha256,
            "replay_store_entries": replay_store_entries,
            "allow_internet": False,
            "qemu_required_supported": True,
        }

    def _effective_target_spec_path(self) -> Path | None:
        if self.config.target_spec_path is not None:
            return self.config.target_spec_path
        if self.binding_path.is_file() and not self.binding_path.is_symlink():
            stored = _load_json_object(
                self.binding_path,
                "synthesis loop manifest",
            )
            value = stored.get("target_spec_path")
            if isinstance(value, str) and value:
                return Path(value).resolve(strict=False)
        return None

    def _effective_replay_store_path(self) -> Path | None:
        if self.config.network_mode != "replay":
            return None
        if self.config.replay_store_path is not None:
            return self.config.replay_store_path
        if self.binding_path.is_file() and not self.binding_path.is_symlink():
            stored = _load_json_object(
                self.binding_path,
                "synthesis loop manifest",
            )
            value = stored.get("replay_store_path")
            if isinstance(value, str) and value:
                return Path(value).resolve(strict=False)
        return None

    def _template_config_identity(self) -> tuple[list[dict[str, Any]], str]:
        config_dir = self.config.template_run_dir / "config"
        _validate_directory(config_dir, "template config directory")
        names = (
            "runtime.json",
            "library_plan.json",
            "library_resolution.json",
            "network_policy.json",
            "guest_runtime.json",
        )
        entries: list[dict[str, Any]] = []
        for name in names:
            path = config_dir / name
            if not path.exists():
                continue
            _validate_regular_file(path, f"template {name}")
            entries.append(
                {
                    "path": str(path),
                    "sha256": _sha256_file(path),
                }
            )
        return entries, _canonical_digest(entries)

    def _analysis_stack_identity(self) -> tuple[list[dict[str, Any]], str]:
        paths: list[Path] = []
        module_dir = Path(__file__).resolve().parent
        paths.extend(sorted(module_dir.glob("*.py")))
        # The M3 controller and mapping predicates live in experiments. Bind
        # these executable Python inputs as well, so resume cannot silently
        # replace a verifier/controller while retaining the same native bundle.
        runtime_path = self.config.template_run_dir / "config/runtime.json"
        runtime = _load_json_object(runtime_path, "template runtime")
        if runtime.get("capsule", {}).get("profile") == "input-static-i386-retirement-m3":
            paths.extend(self.config.project_root / relative for relative in (
                "experiments/retirement_observer/controller.py",
                "experiments/execution_capsule_probe/controller.py",
                "experiments/execution_capsule_retire/controller.py",
            ))
        network_scripts = {
            "none": (),
            "controlled": (
                "scripts/start_network_emulator.py",
                "scripts/start_transparent_logger.py",
            ),
            "replay": ("scripts/start_network_replay.py",),
            "record": ("scripts/start_network_record.py",),
        }[self.config.network_mode]
        for relative in (*self.REQUIRED_PROJECT_SCRIPTS, *network_scripts):
            path = self.config.project_root / relative
            _validate_regular_file(path, f"analysis script {relative}")
            paths.append(path)

        entries: list[dict[str, Any]] = []
        seen: set[Path] = set()
        for path in sorted((item.resolve(strict=False) for item in paths), key=str):
            if path in seen:
                continue
            seen.add(path)
            _validate_regular_file(path, "analysis stack file")
            entries.append(
                {
                    "path": str(path),
                    "sha256": _sha256_file(path),
                }
            )
        return entries, _canonical_digest(entries)

    def _binding_payload(
        self,
        session: SessionManifest,
        target_identity: dict[str, Any],
    ) -> dict[str, Any]:
        self._validate_session_target_identity(session, target_identity)
        return {
            "schema_version": self.SCHEMA_VERSION,
            "loop_version": self.LOOP_VERSION,
            "session_id": session.session_id,
            "session_dir": str(self.config.session_dir),
            "snapshot_store": session.snapshot_store,
            "seed_snapshot_id": session.seed_snapshot_id,
            "environment_manifest_store": session.environment_manifest_store,
            "seed_environment_manifest_id": (
                session.seed_environment_manifest_id
            ),
            "sample_sha256": session.sample_sha256,
            "packed_binary_sha256": session.packed_binary_sha256,
            "attempt_goal_id": session.goal_id,
            "max_iterations": session.max_iterations,
            **target_identity,
        }

    @staticmethod
    def _validate_session_target_identity(
        session: SessionManifest,
        target_identity: dict[str, Any],
    ) -> None:
        if session.sample_sha256 != target_identity.get("target_elf_sha256"):
            raise SynthesisLoopError(
                "session sample does not match the selected target ELF"
            )
        if session.packed_binary_sha256 != target_identity.get(
            "host_binary_sha256"
        ):
            raise SynthesisLoopError(
                "session packed binary does not match the selected host binary"
            )
        goal_id = (
            target_identity.get("target_goal_id")
            or DEFAULT_DISCOVERY_GOAL_ID
        )
        if session.goal_id != goal_id:
            raise SynthesisLoopError(
                "session goal does not match the selected target-state goal"
            )

    def _verify_config_binding(
        self,
        stored: dict[str, Any],
        current: dict[str, Any],
    ) -> None:
        if stored.get("schema_version") != self.SCHEMA_VERSION:
            raise SynthesisLoopError("unsupported synthesis loop schema version")
        if stored.get("loop_version") != self.LOOP_VERSION:
            raise SynthesisLoopError("unsupported synthesis loop version")
        keys = (
            "session_id",
            "session_dir",
            "snapshot_store",
            "seed_snapshot_id",
            "environment_manifest_store",
            "seed_environment_manifest_id",
            "sample_sha256",
            "packed_binary_sha256",
            "attempt_goal_id",
            "max_iterations",
            "template_run_dir",
            "template_runtime",
            "template_runtime_sha256",
            "template_config_files",
            "template_config_bundle_sha256",
            "project_root",
            "host_binary",
            "host_binary_sha256",
            "execution_backend",
            "trace_backend",
            "target_arch",
            "target_elf_sha256",
            "target_interpreter",
            "qemu_host_path",
            "qemu_host_sha256",
            "qemu_guest_path",
            "analyzer_bundle_path",
            "analyzer_bundle_sha256",
            "analysis_stack_files",
            "analysis_stack_sha256",
            "target_spec_path",
            "target_spec_sha256",
            "target_goal_id",
            "timeout_seconds",
            "network_mode",
            "network_self_test",
            "replay_store_path",
            "replay_store_sha256",
            "replay_store_entries",
            "allow_internet",
            "qemu_required_supported",
        )
        drift = [key for key in keys if stored.get(key) != current.get(key)]
        if drift:
            raise SynthesisLoopError(
                "synthesis-loop configuration drift detected: "
                + ", ".join(drift)
            )

    def _load_existing_claim(self, iteration_directory: str) -> dict[str, Any] | None:
        iteration_dir = self.config.session_dir / iteration_directory
        claim_path = iteration_dir / "execution_attempt.json"
        if claim_path.is_symlink():
            raise SynthesisLoopError("execution claim must not be a symlink")
        if not claim_path.exists():
            return None
        return _load_json_object(claim_path, "execution claim")

    @staticmethod
    def _claim_intervention_message(
        iteration_index: int,
        claim: dict[str, Any],
    ) -> str:
        stage = str(claim.get("stage") or "unknown")
        malware_started = claim.get("malware_started")
        retry_safe = claim.get("retry_safe")
        if stage == "failed" and malware_started is False and retry_safe is True:
            return (
                f"iteration {iteration_index} has a retry-safe failed execution "
                "claim; run reset-safe-failure explicitly before resuming"
            )
        if stage == "failed":
            return (
                f"iteration {iteration_index} has a failed execution claim and "
                "cannot reuse its execution rootfs"
            )
        return (
            f"iteration {iteration_index} already has execution claim stage "
            f"{stage!r}; inspect the runner state before resuming"
        )

    def _finalize(
        self,
        *,
        controller: IterationController,
        binding: dict[str, Any],
        invocation_id: int,
        outcome: LoopOutcome,
        stop_reason: str | None,
        executions: int,
        last_error: str | None,
    ) -> SynthesisLoopResult:
        session = controller.load()
        updated = dict(binding)
        updated.update(
            {
                "updated_at_utc": _utc_now(),
                "invocations": invocation_id,
                "outcome": outcome.value,
                "stop_reason": stop_reason,
                "last_error": last_error,
                "last_iteration_index": (
                    session.iterations[-1].index if session.iterations else None
                ),
                "executions_last_invocation": executions,
            }
        )
        _atomic_write_json(self.binding_path, updated)
        self._write_report(
            session=session,
            binding=updated,
            executions=executions,
        )
        return SynthesisLoopResult(
            session_id=session.session_id,
            outcome=outcome,
            stop_reason=stop_reason,
            executions_this_invocation=executions,
            total_iterations=len(session.iterations),
            last_iteration_index=(
                session.iterations[-1].index if session.iterations else None
            ),
            report_json=self.report_json_path,
            report_markdown=self.report_markdown_path,
            event_log=self.event_path,
        )

    def _write_report(
        self,
        *,
        session: SessionManifest,
        binding: dict[str, Any],
        executions: int,
    ) -> None:
        iterations: list[dict[str, Any]] = []
        for record in session.iterations:
            iterations.append(
                {
                    "index": record.index,
                    "state": record.state.value,
                    "environment_snapshot_id": record.environment_snapshot_id,
                    "parent_snapshot_id": record.parent_snapshot_id,
                    "environment_manifest_id": record.environment_manifest_id,
                    "environment_manifest_version": (
                        record.environment_manifest_version
                    ),
                    "attempt_id": record.attempt_id,
                    "attempt_contract": record.attempt_contract,
                    "attempt_result": record.attempt_result,
                    "progress": record.progress,
                    "stop_reason": record.stop_reason,
                    "directory": record.directory,
                }
            )
        report = {
            "schema_version": 1,
            "generated_at_utc": _utc_now(),
            "session_id": session.session_id,
            "session_state": session.state.value,
            "session_stop_reason": session.stop_reason,
            "loop_outcome": binding.get("outcome"),
            "loop_stop_reason": binding.get("stop_reason"),
            "last_error": binding.get("last_error"),
            "invocations": binding.get("invocations"),
            "executions_last_invocation": executions,
            "configuration": {
                "template_run_dir": binding.get("template_run_dir"),
                "template_runtime_sha256": binding.get(
                    "template_runtime_sha256"
                ),
                "host_binary": binding.get("host_binary"),
                "host_binary_sha256": binding.get("host_binary_sha256"),
                "execution_backend": binding.get("execution_backend"),
                "trace_backend": binding.get("trace_backend"),
                "target_arch": binding.get("target_arch"),
                "target_elf_sha256": binding.get("target_elf_sha256"),
                "qemu_host_path": binding.get("qemu_host_path"),
                "qemu_host_sha256": binding.get("qemu_host_sha256"),
                "template_config_bundle_sha256": binding.get(
                    "template_config_bundle_sha256"
                ),
                "analysis_stack_sha256": binding.get(
                    "analysis_stack_sha256"
                ),
                "target_spec_path": binding.get("target_spec_path"),
                "target_spec_sha256": binding.get("target_spec_sha256"),
                "target_goal_id": binding.get("target_goal_id"),
                "attempt_goal_id": binding.get("attempt_goal_id"),
                "sample_sha256": binding.get("sample_sha256"),
                "packed_binary_sha256": binding.get(
                    "packed_binary_sha256"
                ),
                "seed_environment_manifest_id": binding.get(
                    "seed_environment_manifest_id"
                ),
                "timeout_seconds": binding.get("timeout_seconds"),
                "max_iterations": binding.get("max_iterations"),
                "network_mode": binding.get("network_mode"),
                "replay_store_path": binding.get("replay_store_path"),
                "replay_store_sha256": binding.get("replay_store_sha256"),
                "replay_store_entries": binding.get("replay_store_entries"),
            },
            "iterations": iterations,
        }
        _atomic_write_json(self.report_json_path, report)

        lines = [
            "# TaintForge-IoT Environment Synthesis Report",
            "",
            f"- Session: `{session.session_id}`",
            f"- Session state: `{session.state.value}`",
            f"- Session stop reason: `{session.stop_reason}`",
            f"- Loop outcome: `{binding.get('outcome')}`",
            f"- Loop stop reason: `{binding.get('stop_reason')}`",
            f"- Invocations: `{binding.get('invocations')}`",
            f"- Iterations: `{len(session.iterations)}`",
            f"- Network mode: `{binding.get('network_mode')}`",
            f"- Replay store SHA-256: `{binding.get('replay_store_sha256')}`",
            f"- Last error: `{binding.get('last_error')}`",
            "",
            "## Iterations",
            "",
            (
                "| Index | State | Snapshot | Manifest | Attempt | "
                "Progress | Stop reason |"
            ),
            "|---:|---|---|---|---|---|---|",
        ]
        for item in iterations:
            progress = item["progress"] or {}
            classification = progress.get("classification", "n/a")
            lines.append(
                "| "
                f"{item['index']} | `{item['state']}` | "
                f"`{item['environment_snapshot_id']}` | "
                f"`{item['environment_manifest_id']}` | "
                f"`{item['attempt_id']}` | "
                f"`{classification}` | `{item['stop_reason']}` |"
            )
        _atomic_write_text(
            self.report_markdown_path,
            "\n".join(lines).rstrip() + "\n",
        )

    def _append_event(self, event: str, **fields: Any) -> None:
        self.config.session_dir.mkdir(parents=True, exist_ok=True)
        if self.event_path.is_symlink():
            raise SynthesisLoopError("synthesis event log must not be a symlink")
        payload = {
            "timestamp_utc": _utc_now(),
            "event": event,
            **fields,
        }
        with self.event_path.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(payload, sort_keys=True) + "\n")
            stream.flush()
            os.fsync(stream.fileno())

    @contextmanager
    def _loop_locked(self) -> Iterator[None]:
        self.loop_lock_path.parent.mkdir(parents=True, exist_ok=True)
        if self.loop_lock_path.is_symlink():
            raise SynthesisLoopError("synthesis-loop lock must not be a symlink")
        with self.loop_lock_path.open("a+") as stream:
            try:
                fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise SynthesisLoopError(
                    "another synthesis-loop process is driving this session"
                ) from exc
            try:
                yield
            finally:
                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)


def _resolve_template_rootfs(
    runtime: dict[str, Any],
    template_run_dir: Path,
    project_root: Path,
) -> Path:
    raw = runtime.get("rootfs")
    if isinstance(raw, str) and raw:
        path = Path(raw)
        if not path.is_absolute():
            path = project_root / path
    else:
        path = template_run_dir / "rootfs"
    path = path.resolve(strict=False)
    _validate_directory(path, "template rootfs")
    return path


def _validate_directory(path: Path, label: str) -> None:
    if path.is_symlink():
        raise SynthesisLoopError(f"{label} must not be a symlink: {path}")
    if not path.is_dir():
        raise SynthesisLoopError(f"{label} does not exist: {path}")


def _validate_regular_file(path: Path, label: str) -> None:
    if path.is_symlink():
        raise SynthesisLoopError(f"{label} must not be a symlink: {path}")
    if not path.is_file():
        raise SynthesisLoopError(f"{label} does not exist: {path}")


def _load_json_object(path: Path, label: str) -> dict[str, Any]:
    _validate_regular_file(path, label)
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SynthesisLoopError(f"invalid JSON in {label}: {path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise SynthesisLoopError(f"{label} must be a JSON object")
    return raw


def _verify_bound_file_bundle(
    raw_entries: Any,
    expected_digest: Any,
    label: str,
) -> None:
    if not isinstance(raw_entries, list):
        raise SynthesisLoopError(f"bound {label} file list is invalid")
    entries: list[dict[str, Any]] = []
    for raw in raw_entries:
        if not isinstance(raw, dict):
            raise SynthesisLoopError(f"bound {label} entry is invalid")
        path_raw = raw.get("path")
        digest_raw = raw.get("sha256")
        if not isinstance(path_raw, str) or not isinstance(digest_raw, str):
            raise SynthesisLoopError(f"bound {label} entry is invalid")
        path = Path(path_raw)
        _validate_regular_file(path, f"bound {label} file")
        actual = _sha256_file(path)
        if actual != digest_raw:
            raise SynthesisLoopError(f"bound {label} file was modified: {path}")
        entries.append({"path": path_raw, "sha256": actual})
    actual_bundle = _canonical_digest(entries)
    if not isinstance(expected_digest, str) or actual_bundle != expected_digest:
        raise SynthesisLoopError(f"bound {label} bundle digest mismatch")


def _canonical_digest(payload: Any) -> str:
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise SynthesisLoopError(f"refusing to replace symlink: {path}")
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        with temporary.open("w", encoding="utf-8") as stream:
            json.dump(payload, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def _atomic_write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise SynthesisLoopError(f"refusing to replace symlink: {path}")
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        with temporary.open("w", encoding="utf-8") as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()
