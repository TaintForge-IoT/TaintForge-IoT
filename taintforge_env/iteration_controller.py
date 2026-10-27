from __future__ import annotations

import fcntl
import hashlib
import json
import os
import shutil
import tempfile
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from pathlib import Path
from typing import Any, Iterator

from .attempt import (
    AttemptContract,
    AttemptOutcome,
    AttemptProgress,
    AttemptResult,
    AttemptStore,
    AttemptValidationError,
    ExecutionStage,
    RunPurpose,
    StageTransition,
    make_failure_fingerprint,
)
from .environment_manifest import (
    EnvironmentManifest,
    EnvironmentManifestError,
    EnvironmentManifestStore,
)
from .environment_manifest_builder import (
    EnvironmentManifestBuilderError,
    create_seed_environment_manifest,
    derive_environment_manifest_from_repair,
)
from .environment_snapshot import (
    EnvironmentSnapshotError,
    EnvironmentSnapshotStore,
)
from .progress_oracle import (
    IterationObservation,
    ProgressClassification,
    ProgressDecision,
    ProgressOracle,
    ProgressOracleError,
)
from .repair_applier import RepairApplicationError, RepairApplier
from .repair_plan import RepairPlan, RepairPlanValidationError


class IterationControllerError(RuntimeError):
    """Raised when an iteration session transition is invalid or unsafe."""


SESSION_SCHEMA_VERSION = 2
ITERATION_CONTROLLER_VERSION = 2
DEFAULT_DISCOVERY_GOAL_ID = "phase2.explicit_discovery_goal"


class SessionState(StrEnum):
    ACTIVE = "active"
    COMPLETED = "completed"
    FAILED = "failed"


class IterationState(StrEnum):
    PREPARED = "prepared"
    COMPLETED = "completed"


class StopReason(StrEnum):
    GOAL_REACHED = "goal_reached"
    FIXED_POINT = "fixed_point"
    CYCLE_DETECTED = "cycle_detected"
    NO_AUTOMATIC_REPAIRS = "no_automatic_repairs"
    BUDGET_EXHAUSTED = "budget_exhausted"
    EXECUTION_TIMED_OUT = "execution_timed_out"
    EXECUTION_CRASHED = "execution_crashed"
    EXECUTION_EXITED_WITHOUT_GOAL = "execution_exited_without_goal"


@dataclass(slots=True, frozen=True)
class IterationRecord:
    index: int
    state: IterationState
    directory: str
    environment_snapshot_id: str
    parent_snapshot_id: str | None
    environment_manifest_id: str
    environment_manifest_version: int
    attempt_id: str
    attempt_contract: str
    repair_application: str | None = None
    observation: str | None = None
    artifact_manifest: str | None = None
    attempt_result: str | None = None
    progress: dict[str, Any] | None = None
    stop_reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "state": self.state.value,
            "directory": self.directory,
            "environment_snapshot_id": self.environment_snapshot_id,
            "parent_snapshot_id": self.parent_snapshot_id,
            "environment_manifest_id": self.environment_manifest_id,
            "environment_manifest_version": self.environment_manifest_version,
            "attempt_id": self.attempt_id,
            "attempt_contract": self.attempt_contract,
            "repair_application": self.repair_application,
            "observation": self.observation,
            "artifact_manifest": self.artifact_manifest,
            "attempt_result": self.attempt_result,
            "progress": self.progress,
            "stop_reason": self.stop_reason,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> IterationRecord:
        if not isinstance(raw, dict):
            raise IterationControllerError("iteration record must be an object")
        index = raw.get("index")
        if not isinstance(index, int) or isinstance(index, bool) or index < 0:
            raise IterationControllerError("iteration index is invalid")
        try:
            state = IterationState(raw.get("state"))
        except ValueError as exc:
            raise IterationControllerError("iteration state is invalid") from exc
        directory = raw.get("directory")
        environment_snapshot_id = raw.get("environment_snapshot_id")
        if not isinstance(directory, str) or not directory:
            raise IterationControllerError("iteration directory is invalid")
        if (
            not isinstance(environment_snapshot_id, str)
            or not environment_snapshot_id.startswith("env_")
        ):
            raise IterationControllerError("environment snapshot id is invalid")
        parent_snapshot_id = raw.get("parent_snapshot_id")
        if parent_snapshot_id is not None and (
            not isinstance(parent_snapshot_id, str)
            or not parent_snapshot_id.startswith("env_")
        ):
            raise IterationControllerError("parent snapshot id is invalid")
        environment_manifest_id = raw.get("environment_manifest_id")
        environment_manifest_version = raw.get("environment_manifest_version")
        attempt_id = raw.get("attempt_id")
        attempt_contract = raw.get("attempt_contract")
        if not isinstance(environment_manifest_id, str) or not environment_manifest_id.startswith(
            "manifest-v"
        ):
            raise IterationControllerError("environment manifest id is invalid")
        if (
            not isinstance(environment_manifest_version, int)
            or isinstance(environment_manifest_version, bool)
            or environment_manifest_version < 0
        ):
            raise IterationControllerError("environment manifest version is invalid")
        if not isinstance(attempt_id, str) or not attempt_id.startswith("attempt-"):
            raise IterationControllerError("attempt id is invalid")
        if not isinstance(attempt_contract, str) or not attempt_contract:
            raise IterationControllerError("attempt contract path is invalid")
        _validate_relative_path(directory, "iteration directory")
        _validate_relative_path(attempt_contract, "attempt_contract")
        repair_application = _optional_string(raw.get("repair_application"))
        observation = _optional_string(raw.get("observation"))
        artifact_manifest = _optional_string(raw.get("artifact_manifest"))
        attempt_result = _optional_string(raw.get("attempt_result"))
        for label, value in (
            ("repair_application", repair_application),
            ("observation", observation),
            ("artifact_manifest", artifact_manifest),
            ("attempt_result", attempt_result),
        ):
            if value is not None:
                _validate_relative_path(value, label)
        progress = raw.get("progress")
        if progress is not None and not isinstance(progress, dict):
            raise IterationControllerError("iteration progress is invalid")
        return cls(
            index=index,
            state=state,
            directory=directory,
            environment_snapshot_id=environment_snapshot_id,
            parent_snapshot_id=parent_snapshot_id,
            environment_manifest_id=environment_manifest_id,
            environment_manifest_version=environment_manifest_version,
            attempt_id=attempt_id,
            attempt_contract=attempt_contract,
            repair_application=repair_application,
            observation=observation,
            artifact_manifest=artifact_manifest,
            attempt_result=attempt_result,
            progress=progress,
            stop_reason=_optional_string(raw.get("stop_reason")),
        )


@dataclass(slots=True, frozen=True)
class SessionManifest:
    session_id: str
    session_dir: str
    snapshot_store: str
    seed_snapshot_id: str
    environment_manifest_store: str
    seed_environment_manifest_id: str
    sample_sha256: str
    packed_binary_sha256: str
    goal_id: str
    max_iterations: int
    state: SessionState = SessionState.ACTIVE
    stop_reason: str | None = None
    iterations: tuple[IterationRecord, ...] = ()
    schema_version: int = SESSION_SCHEMA_VERSION
    controller_version: int = ITERATION_CONTROLLER_VERSION
    created_at_utc: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    updated_at_utc: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "controller_version": self.controller_version,
            "session_id": self.session_id,
            "created_at_utc": self.created_at_utc,
            "updated_at_utc": self.updated_at_utc,
            "session_dir": self.session_dir,
            "snapshot_store": self.snapshot_store,
            "seed_snapshot_id": self.seed_snapshot_id,
            "environment_manifest_store": self.environment_manifest_store,
            "seed_environment_manifest_id": self.seed_environment_manifest_id,
            "sample_sha256": self.sample_sha256,
            "packed_binary_sha256": self.packed_binary_sha256,
            "goal_id": self.goal_id,
            "max_iterations": self.max_iterations,
            "state": self.state.value,
            "stop_reason": self.stop_reason,
            "iterations": [item.to_dict() for item in self.iterations],
        }

    @classmethod
    def load(cls, path: str | Path) -> SessionManifest:
        path = Path(path)
        if path.is_symlink() or not path.is_file():
            raise IterationControllerError(
                f"session manifest is not a regular file: {path}"
            )
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except OSError as exc:
            raise IterationControllerError(
                f"cannot read session manifest {path}: {exc}"
            ) from exc
        except json.JSONDecodeError as exc:
            raise IterationControllerError(f"invalid session manifest JSON: {exc}") from exc
        if not isinstance(raw, dict):
            raise IterationControllerError("session manifest must be an object")
        if (
            raw.get("schema_version") != SESSION_SCHEMA_VERSION
            or raw.get("controller_version") != ITERATION_CONTROLLER_VERSION
        ):
            raise IterationControllerError("unsupported session manifest version")
        session_id = raw.get("session_id")
        session_dir = raw.get("session_dir")
        snapshot_store = raw.get("snapshot_store")
        seed_snapshot_id = raw.get("seed_snapshot_id")
        environment_manifest_store = raw.get("environment_manifest_store")
        seed_environment_manifest_id = raw.get("seed_environment_manifest_id")
        sample_sha256 = raw.get("sample_sha256")
        packed_binary_sha256 = raw.get("packed_binary_sha256")
        goal_id = raw.get("goal_id")
        max_iterations = raw.get("max_iterations")
        if not isinstance(session_id, str) or not session_id.startswith("session_"):
            raise IterationControllerError("session_id is invalid")
        for name, value in (
            ("session_dir", session_dir),
            ("snapshot_store", snapshot_store),
            ("environment_manifest_store", environment_manifest_store),
        ):
            if not isinstance(value, str) or not value:
                raise IterationControllerError(f"{name} is invalid")
        if not isinstance(seed_snapshot_id, str) or not seed_snapshot_id.startswith("env_"):
            raise IterationControllerError("seed_snapshot_id is invalid")
        if (
            not isinstance(seed_environment_manifest_id, str)
            or not seed_environment_manifest_id.startswith(
                "manifest-v0000-"
            )
        ):
            raise IterationControllerError("seed environment manifest id is invalid")
        _validate_sha256(sample_sha256, "sample_sha256")
        _validate_sha256(packed_binary_sha256, "packed_binary_sha256")
        _validate_goal_id(goal_id)
        if (
            not isinstance(max_iterations, int)
            or isinstance(max_iterations, bool)
            or max_iterations < 1
        ):
            raise IterationControllerError("max_iterations is invalid")
        try:
            state = SessionState(raw.get("state"))
        except ValueError as exc:
            raise IterationControllerError("session state is invalid") from exc
        iterations_raw = raw.get("iterations", [])
        if not isinstance(iterations_raw, list):
            raise IterationControllerError("iterations must be an array")
        iterations = tuple(IterationRecord.from_dict(item) for item in iterations_raw)
        if [item.index for item in iterations] != list(range(len(iterations))):
            raise IterationControllerError("iteration indexes must be contiguous")
        return cls(
            session_id=session_id,
            session_dir=session_dir,
            snapshot_store=snapshot_store,
            seed_snapshot_id=seed_snapshot_id,
            environment_manifest_store=environment_manifest_store,
            seed_environment_manifest_id=seed_environment_manifest_id,
            sample_sha256=sample_sha256,
            packed_binary_sha256=packed_binary_sha256,
            goal_id=goal_id,
            max_iterations=max_iterations,
            state=state,
            stop_reason=_optional_string(raw.get("stop_reason")),
            iterations=iterations,
            created_at_utc=str(raw.get("created_at_utc") or "unknown"),
            updated_at_utc=str(raw.get("updated_at_utc") or "unknown"),
        )

    def save(self, path: str | Path) -> None:
        _atomic_write_json(Path(path), self.to_dict())


@dataclass(slots=True, frozen=True)
class PreparedIteration:
    record: IterationRecord
    execution_rootfs: Path
    environment_snapshot_id: str
    environment_manifest_id: str
    environment_manifest_version: int
    attempt_id: str
    attempt_contract_path: Path


class IterationController:

    def __init__(self, session_dir: str | Path) -> None:
        self.session_dir = _safe_directory_path(session_dir, "session directory")
        self.session_manifest_path = self.session_dir / "session.json"
        self.lock_path = self.session_dir / ".session.lock"

    @classmethod
    def initialize(
        cls,
        *,
        session_dir: str | Path,
        snapshot_store: str | Path,
        seed_rootfs: str | Path,
        sample_sha256: str,
        packed_binary_sha256: str,
        goal_id: str = DEFAULT_DISCOVERY_GOAL_ID,
        max_iterations: int = 5,
    ) -> SessionManifest:
        if max_iterations < 1:
            raise IterationControllerError("max_iterations must be positive")
        _validate_sha256(sample_sha256, "sample_sha256")
        _validate_sha256(packed_binary_sha256, "packed_binary_sha256")
        _validate_goal_id(goal_id)
        session = _safe_directory_path(session_dir, "session directory")
        if session.exists() or session.is_symlink():
            raise IterationControllerError(f"session directory already exists: {session}")
        session.parent.mkdir(parents=True, exist_ok=True)
        if session.parent.is_symlink():
            raise IterationControllerError("session parent must not be a symlink")

        temporary = Path(
            tempfile.mkdtemp(
                prefix=f".{session.name}.",
                suffix=".tmp",
                dir=session.parent,
            )
        )
        try:
            store = EnvironmentSnapshotStore(snapshot_store)
            capture = store.capture(seed_rootfs)
            seed_environment_manifest = create_seed_environment_manifest(
                sample_sha256=sample_sha256,
                rootfs_snapshot_id=capture.manifest.snapshot_id,
            )
            EnvironmentManifestStore(temporary / "manifests").save(
                seed_environment_manifest
            )
            session_id = (
                "session_"
                + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
                + "_"
                + uuid.uuid4().hex[:8]
            )
            manifest = SessionManifest(
                session_id=session_id,
                session_dir=str(session),
                snapshot_store=str(store.store_dir),
                seed_snapshot_id=capture.manifest.snapshot_id,
                environment_manifest_store=str(session / "manifests"),
                seed_environment_manifest_id=seed_environment_manifest.manifest_id,
                sample_sha256=sample_sha256,
                packed_binary_sha256=packed_binary_sha256,
                goal_id=goal_id,
                max_iterations=max_iterations,
            )
            (temporary / "iterations").mkdir()
            (temporary / "attempts").mkdir()
            manifest.save(temporary / "session.json")
            (temporary / ".session.lock").touch()
            os.replace(temporary, session)
            temporary = None
            return manifest
        except (
            EnvironmentManifestBuilderError,
            EnvironmentManifestError,
            EnvironmentSnapshotError,
            OSError,
        ) as exc:
            if isinstance(exc, IterationControllerError):
                raise
            raise IterationControllerError(str(exc)) from exc
        finally:
            if temporary is not None and temporary.exists():
                shutil.rmtree(temporary, ignore_errors=True)

    def load(self) -> SessionManifest:
        manifest = SessionManifest.load(self.session_manifest_path)
        if Path(manifest.session_dir).resolve(strict=False) != self.session_dir:
            raise IterationControllerError("session manifest path mismatch")
        if Path(manifest.environment_manifest_store).resolve(strict=False) != (
            self.session_dir / "manifests"
        ):
            raise IterationControllerError(
                "environment manifest store path mismatch"
            )
        return manifest

    def prepare_next(self) -> PreparedIteration:
        with self._locked():
            manifest = self.load()
            if manifest.state != SessionState.ACTIVE:
                raise IterationControllerError(
                    f"session is not active: {manifest.state.value}"
                )
            if manifest.iterations and manifest.iterations[-1].state == IterationState.PREPARED:
                raise IterationControllerError("the latest iteration is still prepared")
            index = len(manifest.iterations)
            if index >= manifest.max_iterations:
                raise IterationControllerError("iteration budget is exhausted")

            store = EnvironmentSnapshotStore(manifest.snapshot_store)
            environment_manifests = EnvironmentManifestStore(
                manifest.environment_manifest_store
            )
            attempt_store = AttemptStore(self.session_dir / "attempts")
            repair_application_bytes: bytes | None = None
            if index == 0:
                parent_snapshot_id = None
                environment_snapshot_id = manifest.seed_snapshot_id
                repair_application_relative = None
                try:
                    environment_manifest = environment_manifests.load(0)
                except EnvironmentManifestError as exc:
                    raise IterationControllerError(str(exc)) from exc
                if environment_manifest.manifest_id != manifest.seed_environment_manifest_id:
                    raise IterationControllerError(
                        "seed environment manifest id does not match session"
                    )
            else:
                previous = manifest.iterations[-1]
                if previous.state != IterationState.COMPLETED:
                    raise IterationControllerError("previous iteration is incomplete")
                previous_dir = self.session_dir / previous.directory
                requirements_path = previous_dir / "artifacts" / "runtime_requirements.json"
                plan_path = previous_dir / "artifacts" / "repair_plan.json"
                if (
                    requirements_path.is_symlink()
                    or plan_path.is_symlink()
                    or not requirements_path.is_file()
                    or not plan_path.is_file()
                ):
                    raise IterationControllerError(
                        "previous iteration does not contain repair inputs"
                    )
                parent_snapshot_id = previous.environment_snapshot_id
                if previous.observation is None:
                    raise IterationControllerError(
                        "previous iteration lacks an observation"
                    )
                try:
                    previous_manifest = environment_manifests.load(
                        previous.environment_manifest_version
                    )
                    previous_contract, previous_result = (
                        attempt_store.verify_attempt(
                            previous.attempt_id,
                            require_result=True,
                        )
                    )
                except (EnvironmentManifestError, AttemptValidationError) as exc:
                    raise IterationControllerError(str(exc)) from exc
                if (
                    previous_result is None
                    or previous_result.outcome
                    != AttemptOutcome.REPAIR_REQUIRED
                ):
                    raise IterationControllerError(
                        "next environment version requires a repair-required attempt"
                    )
                self._validate_contract_binding(
                    manifest,
                    previous,
                    previous_contract,
                )
                if previous_manifest.manifest_id != previous.environment_manifest_id:
                    raise IterationControllerError(
                        "previous environment manifest id mismatch"
                    )
                if previous_manifest.rootfs_snapshot_id != previous.environment_snapshot_id:
                    raise IterationControllerError(
                        "previous manifest does not reference its execution snapshot"
                    )
                (
                    environment_snapshot_id,
                    repair_application_bytes,
                    environment_manifest,
                ) = self._build_repaired_snapshot(
                    store=store,
                    parent_snapshot_id=parent_snapshot_id,
                    plan_path=plan_path,
                    requirements_path=requirements_path,
                    iteration_index=index,
                    parent_manifest=previous_manifest,
                    source_contract=previous_contract,
                    source_result=previous_result,
                    observation_path=self.session_dir / previous.observation,
                )
                try:
                    environment_manifests.save(environment_manifest)
                except EnvironmentManifestError as exc:
                    raise IterationControllerError(str(exc)) from exc
                repair_application_relative = (
                    f"iterations/{index:04d}/repair_application.json"
                )

            if environment_manifest.rootfs_snapshot_id != environment_snapshot_id:
                raise IterationControllerError(
                    "environment manifest does not reference the execution snapshot"
                )
            try:
                contract = AttemptContract.create(
                    attempt_index=index,
                    purpose=RunPurpose.DISCOVERY,
                    sample_sha256=manifest.sample_sha256,
                    packed_binary_sha256=manifest.packed_binary_sha256,
                    environment_manifest_id=environment_manifest.manifest_id,
                    environment_manifest_version=environment_manifest.manifest_version,
                    goal_id=manifest.goal_id,
                    initial_stage=ExecutionStage.PRE_OEP_DISCOVERY,
                )
                contract_path = attempt_store.save_contract(contract)
            except AttemptValidationError as exc:
                raise IterationControllerError(str(exc)) from exc
            contract_relative = str(contract_path.relative_to(self.session_dir))

            iteration_relative = f"iterations/{index:04d}"
            iteration_dir = self.session_dir / iteration_relative
            temporary = Path(
                tempfile.mkdtemp(
                    prefix=f".{index:04d}.",
                    suffix=".tmp",
                    dir=self.session_dir / "iterations",
                )
            )
            try:
                execution_rootfs = temporary / "execution" / "rootfs"
                store.clone(environment_snapshot_id, execution_rootfs)
                if repair_application_bytes is not None:
                    (temporary / "repair_application.json").write_bytes(
                        repair_application_bytes
                    )
                record = IterationRecord(
                    index=index,
                    state=IterationState.PREPARED,
                    directory=iteration_relative,
                    environment_snapshot_id=environment_snapshot_id,
                    parent_snapshot_id=parent_snapshot_id,
                    environment_manifest_id=environment_manifest.manifest_id,
                    environment_manifest_version=environment_manifest.manifest_version,
                    attempt_id=contract.attempt_id,
                    attempt_contract=contract_relative,
                    repair_application=repair_application_relative,
                )
                _atomic_write_json(temporary / "iteration.json", record.to_dict())
                os.replace(temporary, iteration_dir)
                temporary = None
            finally:
                if temporary is not None and temporary.exists():
                    shutil.rmtree(temporary, ignore_errors=True)

            updated = _replace_session(
                manifest,
                iterations=manifest.iterations + (record,),
            )
            updated.save(self.session_manifest_path)
            return PreparedIteration(
                record=record,
                execution_rootfs=iteration_dir / "execution" / "rootfs",
                environment_snapshot_id=environment_snapshot_id,
                environment_manifest_id=environment_manifest.manifest_id,
                environment_manifest_version=environment_manifest.manifest_version,
                attempt_id=contract.attempt_id,
                attempt_contract_path=contract_path,
            )

    def complete_iteration(
        self,
        *,
        iteration_index: int,
        artifacts_dir: str | Path,
        goal_reached: bool = False,
        goal_reason: str | None = None,
        guest_exit_code: int | None = None,
        timed_out: bool = False,
        stage_transitions: tuple[StageTransition, ...] = (),
    ) -> IterationRecord:
        with self._locked():
            manifest = self.load()
            if manifest.state != SessionState.ACTIVE:
                raise IterationControllerError("cannot complete an inactive session")
            if iteration_index < 0 or iteration_index >= len(manifest.iterations):
                raise IterationControllerError("iteration index does not exist")
            record = manifest.iterations[iteration_index]
            if record.state != IterationState.PREPARED:
                raise IterationControllerError("iteration is not in prepared state")
            if iteration_index != len(manifest.iterations) - 1:
                raise IterationControllerError("only the latest iteration may be completed")

            iteration_dir = self.session_dir / record.directory
            try:
                contract = AttemptStore(
                    self.session_dir / "attempts"
                ).load_contract(record.attempt_id)
            except AttemptValidationError as exc:
                raise IterationControllerError(str(exc)) from exc
            self._validate_contract_binding(manifest, record, contract)
            stage = contract.initial_stage
            for sequence, transition in enumerate(stage_transitions):
                if not isinstance(transition, StageTransition) or transition.sequence != sequence or transition.from_stage != stage:
                    raise IterationControllerError("attempt stage transitions do not form a contiguous bound history")
                stage = transition.to_stage
            _validate_execution_claim_for_completion(
                iteration_dir,
                session_id=manifest.session_id,
                record=record,
                contract=contract,
            )
            source_artifacts_raw = Path(artifacts_dir)
            if source_artifacts_raw.is_symlink():
                raise IterationControllerError(
                    f"artifacts directory is invalid: {source_artifacts_raw}"
                )
            source_artifacts = source_artifacts_raw.resolve(strict=False)
            if not source_artifacts.is_dir():
                raise IterationControllerError(
                    f"artifacts directory is invalid: {source_artifacts}"
                )
            target_artifacts = iteration_dir / "artifacts"
            if target_artifacts.exists() or target_artifacts.is_symlink():
                raise IterationControllerError("iteration artifacts already exist")
            if _is_relative_to(target_artifacts, source_artifacts):
                raise IterationControllerError(
                    "artifacts source must not contain the iteration target"
                )

            temporary_artifacts = iteration_dir / ".artifacts.tmp"
            if temporary_artifacts.exists():
                shutil.rmtree(temporary_artifacts)
            try:
                _copy_artifacts(source_artifacts, temporary_artifacts)
                RepairPlan.load(
                    temporary_artifacts / "repair_plan.json"
                )
                oracle = ProgressOracle()
                observation = oracle.observe(
                    temporary_artifacts,
                    environment_snapshot_id=record.environment_snapshot_id,
                    goal_reached=goal_reached,
                    goal_reason=goal_reason,
                )
                previous_observation = self._previous_observation(manifest, iteration_index)
                progress = oracle.compare(previous_observation, observation)
                artifact_manifest = _build_artifact_manifest(temporary_artifacts)
                _atomic_write_json(
                    temporary_artifacts / "artifact_manifest.json",
                    artifact_manifest,
                )
                os.replace(temporary_artifacts, target_artifacts)
            except (
                ProgressOracleError,
                RepairPlanValidationError,
                OSError,
            ) as exc:
                if temporary_artifacts.exists():
                    shutil.rmtree(temporary_artifacts, ignore_errors=True)
                raise IterationControllerError(str(exc)) from exc

            observation_path = iteration_dir / "observation.json"
            observation.save(observation_path)
            stop_reason = self._decide_stop_reason(
                manifest=manifest,
                iteration_index=iteration_index,
                observation=observation,
            )
            attempt_result = _build_attempt_result(
                contract=contract,
                observation=observation,
                observation_path=observation_path,
                repair_plan_path=target_artifacts / "repair_plan.json",
                guest_exit_code=guest_exit_code,
                timed_out=timed_out,
                stage_transitions=stage_transitions,
            )
            try:
                attempt_result_path = AttemptStore(
                    self.session_dir / "attempts"
                ).save_result(attempt_result)
            except AttemptValidationError as exc:
                raise IterationControllerError(str(exc)) from exc
            session_state, stop_reason = _resolve_attempt_session_transition(
                attempt_result,
                stop_reason,
            )
            completed = IterationRecord(
                index=record.index,
                state=IterationState.COMPLETED,
                directory=record.directory,
                environment_snapshot_id=record.environment_snapshot_id,
                parent_snapshot_id=record.parent_snapshot_id,
                environment_manifest_id=record.environment_manifest_id,
                environment_manifest_version=record.environment_manifest_version,
                attempt_id=record.attempt_id,
                attempt_contract=record.attempt_contract,
                repair_application=record.repair_application,
                observation=str(observation_path.relative_to(self.session_dir)),
                artifact_manifest=str(
                    (target_artifacts / "artifact_manifest.json").relative_to(self.session_dir)
                ),
                attempt_result=str(
                    attempt_result_path.relative_to(self.session_dir)
                ),
                progress=progress.to_dict(),
                stop_reason=stop_reason.value if stop_reason else None,
            )
            _atomic_write_json(iteration_dir / "iteration.json", completed.to_dict())

            iterations = list(manifest.iterations)
            iterations[iteration_index] = completed
            updated = _replace_session(
                manifest,
                iterations=tuple(iterations),
                state=session_state,
                stop_reason=stop_reason.value if stop_reason else None,
            )
            updated.save(self.session_manifest_path)
            return completed

    def verify(self) -> SessionManifest:
        with self._locked():
            manifest = self.load()
            store = EnvironmentSnapshotStore(manifest.snapshot_store)
            store.verify(manifest.seed_snapshot_id)
            try:
                semantic_store = EnvironmentManifestStore(
                    manifest.environment_manifest_store
                )
                semantic_chain = semantic_store.verify_chain()
                attempt_store = AttemptStore(self.session_dir / "attempts")
            except (EnvironmentManifestError, AttemptValidationError) as exc:
                raise IterationControllerError(str(exc)) from exc
            if semantic_chain[0].manifest_id != manifest.seed_environment_manifest_id:
                raise IterationControllerError(
                    "seed environment manifest id mismatch"
                )
            if semantic_chain[0].rootfs_snapshot_id != manifest.seed_snapshot_id:
                raise IterationControllerError(
                    "seed environment manifest snapshot mismatch"
                )
            if semantic_chain[0].sample_sha256 != manifest.sample_sha256:
                raise IterationControllerError(
                    "seed environment manifest sample mismatch"
                )
            expected_attempt_ids = tuple(
                record.attempt_id for record in manifest.iterations
            )
            verified_results: list[AttemptResult | None] = []
            verified_observations: list[IterationObservation | None] = []
            try:
                if attempt_store.list_attempt_ids() != expected_attempt_ids:
                    raise IterationControllerError(
                        "attempt store does not match session iteration order"
                    )
            except AttemptValidationError as exc:
                raise IterationControllerError(str(exc)) from exc
            for record in manifest.iterations:
                record_observation: IterationObservation | None = None
                store.verify(record.environment_snapshot_id)
                if record.environment_manifest_version != record.index:
                    raise IterationControllerError(
                        "environment manifest version must match iteration index"
                    )
                if record.environment_manifest_version >= len(semantic_chain):
                    raise IterationControllerError(
                        "iteration references a missing environment manifest"
                    )
                semantic_manifest = semantic_chain[
                    record.environment_manifest_version
                ]
                if semantic_manifest.manifest_id != record.environment_manifest_id:
                    raise IterationControllerError(
                        "iteration environment manifest id mismatch"
                    )
                if semantic_manifest.rootfs_snapshot_id != record.environment_snapshot_id:
                    raise IterationControllerError(
                        "iteration manifest does not match its rootfs snapshot"
                    )
                if semantic_manifest.sample_sha256 != manifest.sample_sha256:
                    raise IterationControllerError(
                        "iteration environment manifest sample mismatch"
                    )
                iteration_dir = self.session_dir / record.directory
                raw_record = IterationRecord.from_dict(
                    json.loads((iteration_dir / "iteration.json").read_text(encoding="utf-8"))
                )
                if raw_record != record:
                    raise IterationControllerError(
                        f"iteration manifest mismatch for {record.index}"
                    )
                try:
                    contract, result = attempt_store.verify_attempt(
                        record.attempt_id,
                        require_result=record.state == IterationState.COMPLETED,
                    )
                except AttemptValidationError as exc:
                    raise IterationControllerError(str(exc)) from exc
                verified_results.append(result)
                self._validate_contract_binding(manifest, record, contract)
                expected_contract = str(
                    attempt_store.contract_path(record.attempt_id).relative_to(
                        self.session_dir
                    )
                )
                if record.attempt_contract != expected_contract:
                    raise IterationControllerError(
                        "iteration attempt contract path mismatch"
                    )
                if record.state == IterationState.PREPARED and result is not None:
                    raise IterationControllerError(
                        "prepared iteration already has an attempt result"
                    )
                if record.state == IterationState.COMPLETED:
                    if (
                        record.observation is None
                        or record.artifact_manifest is None
                        or record.attempt_result is None
                        or result is None
                    ):
                        raise IterationControllerError("completed iteration lacks evidence")
                    observation_path = self.session_dir / record.observation
                    observation = IterationObservation.load(observation_path)
                    record_observation = observation
                    _verify_artifact_manifest(
                        self.session_dir / record.artifact_manifest,
                        iteration_dir / "artifacts",
                    )
                    if result.progress.observation_sha256 != _sha256_file(
                        observation_path
                    ):
                        raise IterationControllerError(
                            "attempt result observation digest mismatch"
                        )
                    if (
                        result.progress.goal_reached != observation.goal_reached
                        or result.progress.oracle_reason != observation.goal_reason
                        or result.progress.guest_events_total
                        != observation.metrics.guest_events_total
                    ):
                        raise IterationControllerError(
                            "attempt result progress does not match observation"
                        )
                    expected_result = str(
                        attempt_store.result_path(record.attempt_id).relative_to(
                            self.session_dir
                        )
                    )
                    if record.attempt_result != expected_result:
                        raise IterationControllerError(
                            "iteration attempt result path mismatch"
                        )
                verified_observations.append(record_observation)
            if len(semantic_chain) != max(1, len(manifest.iterations)):
                raise IterationControllerError(
                    "environment manifest chain has orphaned versions"
                )
            oracle_stop_reason: StopReason | None = None
            if (
                manifest.iterations
                and manifest.iterations[-1].state == IterationState.COMPLETED
            ):
                latest_observation = verified_observations[-1]
                if latest_observation is None:
                    raise IterationControllerError(
                        "completed session tail lacks an observation"
                    )
                oracle_stop_reason = self._decide_stop_reason(
                    manifest=manifest,
                    iteration_index=manifest.iterations[-1].index,
                    observation=latest_observation,
                )
            _verify_session_terminal_state(
                manifest,
                verified_results,
                oracle_stop_reason,
            )
            return manifest

    @staticmethod
    def _validate_contract_binding(
        manifest: SessionManifest,
        record: IterationRecord,
        contract: AttemptContract,
    ) -> None:
        if contract.attempt_id != record.attempt_id:
            raise IterationControllerError("attempt contract id mismatch")
        if contract.attempt_index != record.index:
            raise IterationControllerError("attempt contract index mismatch")
        if contract.sample_sha256 != manifest.sample_sha256:
            raise IterationControllerError("attempt contract sample mismatch")
        if contract.packed_binary_sha256 != manifest.packed_binary_sha256:
            raise IterationControllerError("attempt contract binary mismatch")
        if contract.goal_id != manifest.goal_id:
            raise IterationControllerError("attempt contract goal mismatch")
        if contract.environment_manifest_id != record.environment_manifest_id:
            raise IterationControllerError(
                "attempt contract environment manifest id mismatch"
            )
        if (
            contract.environment_manifest_version
            != record.environment_manifest_version
        ):
            raise IterationControllerError(
                "attempt contract environment manifest version mismatch"
            )

    def _build_repaired_snapshot(
        self,
        *,
        store: EnvironmentSnapshotStore,
        parent_snapshot_id: str,
        plan_path: Path,
        requirements_path: Path,
        iteration_index: int,
        parent_manifest: EnvironmentManifest,
        source_contract: AttemptContract,
        source_result: AttemptResult,
        observation_path: Path,
    ) -> tuple[str, bytes, EnvironmentManifest]:
        staging = Path(
            tempfile.mkdtemp(
                prefix=f".repair-{iteration_index:04d}.",
                suffix=".tmp",
                dir=self.session_dir,
            )
        )
        try:
            candidate_rootfs = staging / "rootfs"
            store.clone(parent_snapshot_id, candidate_rootfs)
            application_path = staging / "repair_application.json"
            try:
                RepairApplier().apply_file(
                    plan_path=plan_path,
                    requirements_path=requirements_path,
                    rootfs=candidate_rootfs,
                    out_path=application_path,
                    dry_run=False,
                )
            except RepairApplicationError as exc:
                raise IterationControllerError(str(exc)) from exc
            capture = store.capture(candidate_rootfs)
            try:
                next_manifest = derive_environment_manifest_from_repair(
                    parent=parent_manifest,
                    rootfs_snapshot_id=capture.manifest.snapshot_id,
                    rootfs_path=candidate_rootfs,
                    source_contract=source_contract,
                    source_result=source_result,
                    repair_plan_path=plan_path,
                    repair_application_path=application_path,
                    observation_path=observation_path,
                )
            except EnvironmentManifestBuilderError as exc:
                raise IterationControllerError(str(exc)) from exc
            return (
                capture.manifest.snapshot_id,
                application_path.read_bytes(),
                next_manifest,
            )
        finally:
            shutil.rmtree(staging, ignore_errors=True)

    def _previous_observation(
        self,
        manifest: SessionManifest,
        iteration_index: int,
    ) -> IterationObservation | None:
        if iteration_index == 0:
            return None
        previous = manifest.iterations[iteration_index - 1]
        if previous.observation is None:
            raise IterationControllerError("previous iteration lacks observation")
        return IterationObservation.load(self.session_dir / previous.observation)

    def _decide_stop_reason(
        self,
        *,
        manifest: SessionManifest,
        iteration_index: int,
        observation: IterationObservation,
    ) -> StopReason | None:
        if observation.goal_reached:
            return StopReason.GOAL_REACHED

        prior: list[IterationObservation] = []
        for record in manifest.iterations[:iteration_index]:
            if record.observation is None:
                continue
            prior.append(IterationObservation.load(self.session_dir / record.observation))

        if prior and observation.state_fingerprint == prior[-1].state_fingerprint:
            return StopReason.FIXED_POINT
        if any(
            observation.state_fingerprint == item.state_fingerprint
            for item in prior[:-1]
        ):
            return StopReason.CYCLE_DETECTED
        if observation.metrics.automatic_candidates == 0:
            return StopReason.NO_AUTOMATIC_REPAIRS
        if iteration_index + 1 >= manifest.max_iterations:
            return StopReason.BUDGET_EXHAUSTED
        return None

    @contextmanager
    def _locked(self) -> Iterator[None]:
        if not self.session_dir.is_dir() or self.session_dir.is_symlink():
            raise IterationControllerError(
                f"session directory does not exist: {self.session_dir}"
            )
        with self.lock_path.open("a+") as stream:
            try:
                fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise IterationControllerError("iteration session is locked") from exc
            try:
                yield
            finally:
                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)


def _build_attempt_result(
    *,
    contract: AttemptContract,
    observation: IterationObservation,
    observation_path: Path,
    repair_plan_path: Path,
    guest_exit_code: int | None,
    timed_out: bool,
    stage_transitions: tuple[StageTransition, ...] = (),
) -> AttemptResult:
    if guest_exit_code is not None and (
        not isinstance(guest_exit_code, int) or isinstance(guest_exit_code, bool)
    ):
        raise IterationControllerError("guest_exit_code must be an integer or null")

    if observation.goal_reached:
        outcome = AttemptOutcome.GOAL_REACHED
        error_code = None
    elif timed_out or guest_exit_code == 124:
        outcome = AttemptOutcome.TIMED_OUT
        error_code = "execution_timeout"
    elif observation.metrics.fatal_signals > 0:
        outcome = AttemptOutcome.CRASHED
        error_code = "fatal_guest_signal"
    elif observation.metrics.automatic_candidates > 0:
        outcome = AttemptOutcome.REPAIR_REQUIRED
        error_code = "automatic_repair_candidate"
    else:
        outcome = AttemptOutcome.EXITED
        error_code = None

    failure_fingerprint: str | None = None
    if outcome in {
        AttemptOutcome.REPAIR_REQUIRED,
        AttemptOutcome.TIMED_OUT,
        AttemptOutcome.CRASHED,
    }:
        failure_fingerprint = make_failure_fingerprint(
            outcome=outcome,
            stage=stage_transitions[-1].to_stage if stage_transitions else contract.initial_stage,
            exit_code=guest_exit_code,
            error_code=error_code,
            blocking_resource=_first_automatic_repair_resource(
                repair_plan_path
            ),
        )

    return AttemptResult(
        attempt_id=contract.attempt_id,
        contract_sha256=contract.contract_sha256,
        outcome=outcome,
        initial_stage=contract.initial_stage,
        final_stage=stage_transitions[-1].to_stage if stage_transitions else contract.initial_stage,
        progress=AttemptProgress(
            goal_reached=observation.goal_reached,
            oracle_reason=observation.goal_reason,
            guest_events_total=observation.metrics.guest_events_total,
            observation_sha256=_sha256_file(observation_path),
        ),
        transitions=stage_transitions,
        failure_fingerprint=failure_fingerprint,
        started_at_utc=contract.created_at_utc,
        finished_at_utc=datetime.now(timezone.utc).isoformat(),
    )


def _resolve_attempt_session_transition(
    result: AttemptResult,
    oracle_stop_reason: StopReason | None,
) -> tuple[SessionState, StopReason | None]:
    """Keep the session state consistent with the persisted attempt outcome."""

    if result.outcome == AttemptOutcome.GOAL_REACHED:
        return SessionState.COMPLETED, StopReason.GOAL_REACHED
    if result.outcome == AttemptOutcome.TIMED_OUT:
        return SessionState.FAILED, StopReason.EXECUTION_TIMED_OUT
    if result.outcome == AttemptOutcome.CRASHED:
        return SessionState.FAILED, StopReason.EXECUTION_CRASHED
    if oracle_stop_reason is not None:
        return SessionState.COMPLETED, oracle_stop_reason
    if result.outcome == AttemptOutcome.REPAIR_REQUIRED:
        return SessionState.ACTIVE, None
    return (
        SessionState.FAILED,
        StopReason.EXECUTION_EXITED_WITHOUT_GOAL,
    )


def _verify_session_terminal_state(
    manifest: SessionManifest,
    results: list[AttemptResult | None],
    oracle_stop_reason: StopReason | None,
) -> None:
    if not manifest.iterations:
        if manifest.state != SessionState.ACTIVE or manifest.stop_reason is not None:
            raise IterationControllerError(
                "an empty session must be active without a stop reason"
            )
        return

    latest = manifest.iterations[-1]
    if latest.state == IterationState.PREPARED:
        if (
            manifest.state != SessionState.ACTIVE
            or manifest.stop_reason is not None
            or latest.stop_reason is not None
            or results[-1] is not None
        ):
            raise IterationControllerError(
                "prepared session tail must remain active and result-free"
            )
        return

    latest_result = results[-1]
    if latest_result is None:
        raise IterationControllerError(
            "completed session tail requires an attempt result"
        )
    expected_state, expected_reason = _resolve_attempt_session_transition(
        latest_result,
        oracle_stop_reason,
    )
    expected_reason_value = (
        expected_reason.value if expected_reason is not None else None
    )
    if (
        manifest.state != expected_state
        or manifest.stop_reason != expected_reason_value
        or latest.stop_reason != expected_reason_value
    ):
        raise IterationControllerError(
            "session state does not match its final attempt and progress oracle"
        )


def _first_automatic_repair_resource(path: Path) -> str | None:
    try:
        plan = RepairPlan.load(path)
    except RepairPlanValidationError as exc:
        raise IterationControllerError(str(exc)) from exc
    resources = sorted(
        decision.resource
        for decision in plan.decisions
        if decision.automatic_allowed
    )
    return resources[0] if resources else None


def _replace_session(
    manifest: SessionManifest,
    *,
    iterations: tuple[IterationRecord, ...] | None = None,
    state: SessionState | None = None,
    stop_reason: str | None = None,
) -> SessionManifest:
    return SessionManifest(
        session_id=manifest.session_id,
        session_dir=manifest.session_dir,
        snapshot_store=manifest.snapshot_store,
        seed_snapshot_id=manifest.seed_snapshot_id,
        environment_manifest_store=manifest.environment_manifest_store,
        seed_environment_manifest_id=manifest.seed_environment_manifest_id,
        sample_sha256=manifest.sample_sha256,
        packed_binary_sha256=manifest.packed_binary_sha256,
        goal_id=manifest.goal_id,
        max_iterations=manifest.max_iterations,
        state=state or manifest.state,
        stop_reason=stop_reason,
        iterations=iterations if iterations is not None else manifest.iterations,
        created_at_utc=manifest.created_at_utc,
        updated_at_utc=datetime.now(timezone.utc).isoformat(),
    )


def _validate_execution_claim_for_completion(
    iteration_dir: Path,
    *,
    session_id: str,
    record: IterationRecord,
    contract: AttemptContract,
) -> None:

    claim_path = iteration_dir / "execution_attempt.json"
    if not claim_path.exists() and not claim_path.is_symlink():
        return
    if claim_path.is_symlink() or not claim_path.is_file():
        raise IterationControllerError(
            f"invalid execution claim: {claim_path}"
        )
    try:
        raw = json.loads(claim_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise IterationControllerError(
            f"cannot load execution claim: {exc}"
        ) from exc
    if not isinstance(raw, dict):
        raise IterationControllerError("execution claim must be an object")
    if raw.get("session_id") != session_id:
        raise IterationControllerError("execution claim session mismatch")
    if raw.get("iteration_index") != record.index:
        raise IterationControllerError("execution claim iteration mismatch")
    if raw.get("attempt_id") != record.attempt_id:
        raise IterationControllerError("execution claim attempt mismatch")
    if raw.get("stage") != "completing":
        raise IterationControllerError(
            "iteration execution claim is not ready for completion: "
            f"stage={raw.get('stage')!r}"
        )
    if raw.get("attempt_contract_sha256") != contract.contract_sha256:
        raise IterationControllerError(
            "execution claim contract digest mismatch"
        )
    if raw.get("environment_manifest_id") != record.environment_manifest_id:
        raise IterationControllerError(
            "execution claim environment manifest id mismatch"
        )
    if (
        raw.get("environment_manifest_version")
        != record.environment_manifest_version
    ):
        raise IterationControllerError(
            "execution claim environment manifest version mismatch"
        )
    if raw.get("environment_snapshot_id") != record.environment_snapshot_id:
        raise IterationControllerError(
            "execution claim environment snapshot mismatch"
        )


def _copy_artifacts(source: Path, destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=False)
    for root, directories, files in os.walk(source, followlinks=False):
        root_path = Path(root)
        directories.sort()
        files.sort()
        relative = root_path.relative_to(source)
        target_root = destination / relative
        for directory in list(directories):
            source_dir = root_path / directory
            if source_dir.is_symlink():
                raise IterationControllerError(
                    f"artifact directory symlink is not allowed: {source_dir}"
                )
            (target_root / directory).mkdir(exist_ok=True)
        for filename in files:
            source_file = root_path / filename
            if source_file.is_symlink() or not source_file.is_file():
                raise IterationControllerError(
                    f"artifact must be a regular file: {source_file}"
                )
            target_file = target_root / filename
            target_file.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source_file, target_file)

    #promote the two required artifacts to stable top-level names so the next iteration never depends on the external runner's directory layout
    for filename in ("runtime_requirements.json", "repair_plan.json"):
        matches = [
            path for path in destination.rglob(filename)
            if path.is_file() and not path.is_symlink()
        ]
        if len(matches) != 1:
            raise IterationControllerError(
                f"expected exactly one {filename}, found {len(matches)}"
            )
        top_level = destination / filename
        if matches[0] != top_level:
            shutil.copy2(matches[0], top_level)


def _build_artifact_manifest(artifacts: Path) -> dict[str, Any]:
    files: list[dict[str, Any]] = []
    for path in sorted(item for item in artifacts.rglob("*") if item.is_file()):
        if path.name == "artifact_manifest.json":
            continue
        files.append(
            {
                "path": path.relative_to(artifacts).as_posix(),
                "size": path.stat().st_size,
                "sha256": _sha256_file(path),
            }
        )
    digest = hashlib.sha256(
        json.dumps(files, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return {
        "schema_version": 1,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "bundle_sha256": digest,
        "files": files,
    }


def _verify_artifact_manifest(manifest_path: Path, artifacts: Path) -> None:
    try:
        raw = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise IterationControllerError(f"invalid artifact manifest: {exc}") from exc
    expected = raw.get("bundle_sha256") if isinstance(raw, dict) else None
    actual = _build_artifact_manifest(artifacts).get("bundle_sha256")
    if expected != actual:
        raise IterationControllerError(
            f"artifact bundle digest mismatch: expected {expected}, got {actual}"
        )


def _validate_relative_path(value: str, label: str) -> None:
    path = Path(value)
    if path.is_absolute() or not path.parts or ".." in path.parts:
        raise IterationControllerError(
            f"{label} must be a contained relative path"
        )


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.resolve(strict=False).relative_to(parent.resolve(strict=False))
        return True
    except ValueError:
        return False


def _safe_directory_path(path: str | Path, label: str) -> Path:
    value = Path(path).expanduser().resolve(strict=False)
    if value == Path("/"):
        raise IterationControllerError(f"{label} must not be host root /")
    return value


def _optional_string(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def _validate_sha256(value: Any, label: str) -> None:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise IterationControllerError(
            f"{label} must be a lowercase SHA-256 digest"
        )


def _validate_goal_id(value: Any) -> None:
    allowed = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.:-")
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= 128
        or not value[0].isalnum()
        or any(character not in allowed for character in value)
    ):
        raise IterationControllerError("goal_id is invalid")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as stream:
            json.dump(payload, stream, indent=2, ensure_ascii=False)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
            temporary = Path(stream.name)
        os.replace(temporary, path)
        temporary = None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
