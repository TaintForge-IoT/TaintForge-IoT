from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import tempfile
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from enum import StrEnum
from pathlib import Path, PurePosixPath
from typing import Any

from . import repair_files
from .repair_plan import (
    RepairActionKind,
    RepairDecision,
    RepairDisposition,
    RepairPlan,
    RepairPlanValidationError,
)


class RepairApplicationError(RuntimeError):
    """Raised when a repair plan cannot be applied safely."""


class RepairResultStatus(StrEnum):
    NOT_SELECTED = "not_selected"
    PLANNED = "planned"
    APPLIED = "applied"
    ALREADY_SATISFIED = "already_satisfied"
    ROLLED_BACK = "rolled_back"
    REJECTED = "rejected"


class RepairApplicationState(StrEnum):
    DRY_RUN = "dry_run"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass(slots=True, frozen=True)
class RepairDecisionResult:
    decision_id: str
    requirement_id: str
    action: str
    resource: str
    status: RepairResultStatus
    reason: str
    target_path: str | None = None
    created_paths: tuple[str, ...] = ()
    network_service: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        value = {
            "decision_id": self.decision_id,
            "requirement_id": self.requirement_id,
            "action": self.action,
            "resource": self.resource,
            "status": self.status.value,
            "reason": self.reason,
            "target_path": self.target_path,
            "created_paths": list(self.created_paths),
        }
        if self.network_service is not None:
            value["network_service"] = self.network_service
        return value


@dataclass(slots=True, frozen=True)
class RepairApplicationReport:
    application_id: str
    state: RepairApplicationState
    plan_path: str
    plan_sha256: str
    requirements_path: str
    requirements_sha256: str
    rootfs: str
    dry_run: bool
    results: tuple[RepairDecisionResult, ...]
    rollback_errors: tuple[str, ...] = ()
    error: str | None = None
    schema_version: int = 1
    applier_version: int = 1
    generated_at_utc: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def summary(self) -> dict[str, Any]:
        by_status: dict[str, int] = {}
        for result in self.results:
            by_status[result.status.value] = (
                by_status.get(result.status.value, 0) + 1
            )

        return {
            "decisions_total": len(self.results),
            "selected_total": sum(
                1
                for result in self.results
                if result.status != RepairResultStatus.NOT_SELECTED
            ),
            "applied_total": sum(
                1
                for result in self.results
                if result.status == RepairResultStatus.APPLIED
            ),
            "already_satisfied_total": sum(
                1
                for result in self.results
                if result.status
                == RepairResultStatus.ALREADY_SATISFIED
            ),
            "created_paths_total": sum(
                len(result.created_paths) for result in self.results
            ),
            "rollback_errors_total": len(self.rollback_errors),
            "by_status": dict(sorted(by_status.items())),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "applier_version": self.applier_version,
            "application_id": self.application_id,
            "generated_at_utc": self.generated_at_utc,
            "state": self.state.value,
            "plan_path": self.plan_path,
            "plan_sha256": self.plan_sha256,
            "requirements_path": self.requirements_path,
            "requirements_sha256": self.requirements_sha256,
            "rootfs": self.rootfs,
            "dry_run": self.dry_run,
            "summary": self.summary(),
            "rollback_errors": list(self.rollback_errors),
            "error": self.error,
            "results": [result.to_dict() for result in self.results],
        }

    def save(self, path: str | Path) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        serialized = json.dumps(
            self.to_dict(),
            indent=2,
            ensure_ascii=False,
        ) + "\n"

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
                stream.write(serialized)
                stream.flush()
                os.fsync(stream.fileno())
                temporary = Path(stream.name)

            os.replace(temporary, path)
            os.chmod(path, 0o644)
        finally:
            if temporary is not None and temporary.exists():
                temporary.unlink(missing_ok=True)


@dataclass(slots=True, frozen=True)
class _PreparedDirectoryRepair:
    decision: RepairDecision
    guest_path: str
    target_path: Path
    mode: int
    create_paths: tuple[Path, ...]
    already_satisfied: bool


@dataclass(slots=True, frozen=True)
class _PreparedNetworkRepair:
    decision: RepairDecision
    selection: dict[str, Any]


@dataclass(slots=True, frozen=True)
class _PreparedFileRepair:
    decision: RepairDecision
    rootfs: Path
    source: repair_files.SuppliedFile


_PreparedRepair = _PreparedDirectoryRepair | _PreparedNetworkRepair | _PreparedFileRepair


@dataclass(slots=True, frozen=True)
class RepairApplierConfig:
    allowed_actions: tuple[RepairActionKind, ...] = (
        RepairActionKind.CREATE_DIRECTORY,
        RepairActionKind.PROVIDE_FILE,
    )
    denied_prefixes: tuple[str, ...] = (
        "/proc",
        "/sys",
        "/dev",
    )
    network_repair_policy: Any = None


class RepairApplier:
    """Apply only explicitly authorized low-risk repairs to a disposable rootfs.

    The applier does not infer new repairs. It validates the persisted plan,
    verifies the exact runtime-requirements input used by the planner, performs
    a complete preflight before mutation, and rolls back files and directories created by
    the current transaction when an application error occurs.
    """

    def __init__(
        self, config: RepairApplierConfig | None = None, *,
        supplied_files: dict[str, repair_files.SuppliedFile] | None = None,
    ) -> None:
        self.supplied_files = supplied_files or {}
        self.config = config or RepairApplierConfig()

    def apply_file(
        self,
        *,
        plan_path: str | Path,
        requirements_path: str | Path,
        rootfs: str | Path,
        out_path: str | Path,
        dry_run: bool = False,
    ) -> RepairApplicationReport:
        plan_path = Path(plan_path)
        requirements_path = Path(requirements_path)
        rootfs = Path(rootfs)
        out_path = Path(out_path)

        plan_bytes = self._read_file(plan_path, "repair plan")
        requirements_bytes = self._read_file(
            requirements_path,
            "runtime requirements",
        )
        plan_sha256 = hashlib.sha256(plan_bytes).hexdigest()
        requirements_sha256 = hashlib.sha256(
            requirements_bytes
        ).hexdigest()

        try:
            plan = RepairPlan.load(plan_path)
        except RepairPlanValidationError as exc:
            raise RepairApplicationError(str(exc)) from exc

        if requirements_sha256 != plan.source_sha256:
            raise RepairApplicationError(
                "runtime requirements SHA-256 does not match the repair plan: "
                f"expected {plan.source_sha256}, got {requirements_sha256}"
            )

        rootfs_resolved = self._validate_rootfs(rootfs)
        application_id = self._application_id(
            plan_sha256,
            requirements_sha256,
            rootfs_resolved,
        )

        results: list[RepairDecisionResult] = []
        prepared: list[_PreparedRepair] = []
        created_paths: list[Path] = []
        file_identities = {}
        rollback_errors: list[str] = []

        try:
            prepared, results = self._preflight(
                plan,
                rootfs_resolved,
                dry_run=dry_run,
                requirements_path=requirements_path,
            )

            if dry_run:
                report = RepairApplicationReport(
                    application_id=application_id,
                    state=RepairApplicationState.DRY_RUN,
                    plan_path=str(plan_path),
                    plan_sha256=plan_sha256,
                    requirements_path=str(requirements_path),
                    requirements_sha256=requirements_sha256,
                    rootfs=str(rootfs_resolved),
                    dry_run=True,
                    results=tuple(results),
                )
                report.save(out_path)
                return report

            results = self._apply_prepared(
                prepared,
                initial_results=results,
                created_paths=created_paths, file_identities=file_identities,
            )

            report = RepairApplicationReport(
                application_id=application_id,
                state=RepairApplicationState.COMPLETED,
                plan_path=str(plan_path),
                plan_sha256=plan_sha256,
                requirements_path=str(requirements_path),
                requirements_sha256=requirements_sha256,
                rootfs=str(rootfs_resolved),
                dry_run=False,
                results=tuple(results),
            )
            report.save(out_path)
            return report

        except Exception as exc:
            rollback_errors.extend(self._rollback(created_paths, file_identities))

            failed_results = self._mark_rolled_back(
                results,
                created_paths,
            )
            report = RepairApplicationReport(
                application_id=application_id,
                state=RepairApplicationState.FAILED,
                plan_path=str(plan_path),
                plan_sha256=plan_sha256,
                requirements_path=str(requirements_path),
                requirements_sha256=requirements_sha256,
                rootfs=str(rootfs_resolved),
                dry_run=dry_run,
                results=tuple(failed_results),
                rollback_errors=tuple(rollback_errors),
                error=str(exc),
            )
            report.save(out_path)

            if isinstance(exc, RepairApplicationError):
                raise
            raise RepairApplicationError(str(exc)) from exc

    def _preflight(
        self,
        plan: RepairPlan,
        rootfs: Path,
        *,
        dry_run: bool,
        requirements_path: Path | None = None,
    ) -> tuple[
        list[_PreparedRepair],
        list[RepairDecisionResult],
    ]:
        prepared: list[_PreparedRepair] = []
        results: list[RepairDecisionResult] = []
        virtually_created: set[Path] = set()

        for decision in plan.decisions:
            if not decision.automatic_allowed:
                results.append(
                    RepairDecisionResult(
                        decision_id=decision.decision_id,
                        requirement_id=decision.requirement_id,
                        action=decision.action.value,
                        resource=decision.resource,
                        status=RepairResultStatus.NOT_SELECTED,
                        reason=(
                            "The planner did not authorize automatic "
                            "application for this decision."
                        ),
                    )
                )
                continue

            if decision.disposition != RepairDisposition.AUTO_CANDIDATE:
                raise RepairApplicationError(
                    f"decision {decision.decision_id} is automatic but does "
                    "not have disposition=auto_candidate"
                )

            network_action = decision.action in {RepairActionKind.CONFIGURE_TCP_SERVICE,
                                                  RepairActionKind.CONFIGURE_UDP_SERVICE}
            if network_action and self.config.network_repair_policy is not None:
                from .requirements import RequirementReport
                from .network_repair import NetworkRepairError
                try:
                    requirements = RequirementReport.load(requirements_path)
                    requirement = next((item for item in requirements.requirements
                                        if item.requirement_id == decision.requirement_id), None)
                    if requirement is None or decision.requirement_kind != "network":
                        raise NetworkRepairError("network decision has no matching requirement")
                    selection = self.config.network_repair_policy.authorize(requirement)
                    transport = selection["service"]["service_type"]
                    expected_action = (RepairActionKind.CONFIGURE_TCP_SERVICE if transport == "tcp"
                                       else RepairActionKind.CONFIGURE_UDP_SERVICE)
                    if (decision.resource != requirement.resource or decision.operation != requirement.operation
                            or decision.action != expected_action
                            or dict(decision.parameters).get("network_repair") != selection):
                        raise NetworkRepairError("network decision differs from its bound authorization")
                except (OSError, ValueError, RuntimeError) as exc:
                    raise RepairApplicationError(str(exc)) from exc
                prepared.append(_PreparedNetworkRepair(decision, selection))
                results.append(RepairDecisionResult(decision.decision_id, decision.requirement_id,
                    decision.action.value, decision.resource, RepairResultStatus.PLANNED,
                    "Validated offline network configuration; requires a fresh execution attempt.",
                    network_service=selection))
                continue
            if decision.action not in self.config.allowed_actions or (
                decision.action == RepairActionKind.PROVIDE_FILE and not self.supplied_files
            ):
                raise RepairApplicationError(
                    f"automatic action {decision.action.value} is not enabled "
                    f"by this applier version ({decision.decision_id})"
                )

            if decision.action == RepairActionKind.PROVIDE_FILE:
                guest = self._validate_guest_path(decision.resource)
                source = self.supplied_files.get(guest)
                if (source is None or decision.requirement_kind != "filesystem" or decision.operation != "path_exists"
                        or dict(decision.parameters) != source.parameters()):
                    raise RepairApplicationError(f"file repair has no matching supplied content: {guest}")
                exists = repair_files.matches_or_missing(rootfs, guest, source)
                prepared.append(_PreparedFileRepair(decision, rootfs, source))
                target = rootfs / guest.lstrip("/")
                results.append(RepairDecisionResult(
                    decision_id=decision.decision_id, requirement_id=decision.requirement_id,
                    action=decision.action.value, resource=guest,
                    status=RepairResultStatus.ALREADY_SATISFIED if exists else RepairResultStatus.PLANNED,
                    target_path=str(target), created_paths=() if exists else (str(target),),
                    reason="Verified explicit content binding and guest destination."))
                continue

            if decision.action == RepairActionKind.CREATE_DIRECTORY:
                item = self._prepare_directory(
                    decision,
                    rootfs,
                    virtually_created,
                )
                prepared.append(item)
                virtually_created.update(item.create_paths)
                results.append(
                    RepairDecisionResult(
                        decision_id=decision.decision_id,
                        requirement_id=decision.requirement_id,
                        action=decision.action.value,
                        resource=decision.resource,
                        status=(
                            RepairResultStatus.ALREADY_SATISFIED
                            if item.already_satisfied
                            else RepairResultStatus.PLANNED
                        ),
                        reason=(
                            "Target already exists as a real directory."
                            if item.already_satisfied
                            else (
                                "Validated automatic directory repair; no "
                                "filesystem mutation performed in dry-run."
                                if dry_run
                                else "Validated automatic directory repair."
                            )
                        ),
                        target_path=str(item.target_path),
                        created_paths=tuple(
                            str(path) for path in item.create_paths
                        ),
                    )
                )
                continue

            raise RepairApplicationError(
                f"no implementation for automatic action "
                f"{decision.action.value}"
            )

        file_paths = {PurePosixPath(item.decision.resource) for item in prepared
                      if isinstance(item, _PreparedFileRepair)}
        if file_paths:
            for item in prepared:
                path = PurePosixPath(item.decision.resource)
                if (isinstance(item, _PreparedDirectoryRepair) and path in file_paths
                        or any(parent in file_paths for parent in path.parents)):
                    raise RepairApplicationError(f"planned directory conflicts with a supplied file: {path}")
        return prepared, results

    def _prepare_directory(
        self,
        decision: RepairDecision,
        rootfs: Path,
        virtually_created: set[Path],
    ) -> _PreparedDirectoryRepair:
        guest_path = self._validate_guest_path(decision.resource)
        parameters = dict(decision.parameters)

        parents = parameters.get("parents")
        if parents is not True:
            raise RepairApplicationError(
                f"decision {decision.decision_id} must explicitly use "
                "parameters.parents=true"
            )

        mode = self._parse_mode(
            parameters.get("mode"),
            decision.decision_id,
        )

        components = PurePosixPath(guest_path).parts[1:]
        current = rootfs
        create_paths: list[Path] = []
        already_satisfied = True

        for index, component in enumerate(components):
            current = current / component
            is_final = index == len(components) - 1

            if current in virtually_created:
                continue

            try:
                entry_stat = current.lstat()
            except FileNotFoundError:
                already_satisfied = False
                create_paths.append(current)
                continue
            except OSError as exc:
                raise RepairApplicationError(
                    f"cannot inspect repair path {current}: {exc}"
                ) from exc

            if stat.S_ISLNK(entry_stat.st_mode):
                raise RepairApplicationError(
                    f"repair path crosses a symbolic link: {current}"
                )

            if not stat.S_ISDIR(entry_stat.st_mode):
                role = "target" if is_final else "ancestor"
                raise RepairApplicationError(
                    f"repair {role} is not a directory: {current}"
                )

        target_path = rootfs.joinpath(*components)
        return _PreparedDirectoryRepair(
            decision=decision,
            guest_path=guest_path,
            target_path=target_path,
            mode=mode,
            create_paths=tuple(create_paths),
            already_satisfied=already_satisfied,
        )

    def _apply_prepared(
        self,
        prepared: list[_PreparedRepair],
        *,
        initial_results: list[RepairDecisionResult],
        created_paths: list[Path],
        file_identities: dict,
    ) -> list[RepairDecisionResult]:
        by_decision = {
            result.decision_id: result for result in initial_results
        }

        for item in prepared:
            if isinstance(item, _PreparedNetworkRepair):
                decision = item.decision
                by_decision[decision.decision_id] = RepairDecisionResult(
                    decision.decision_id, decision.requirement_id, decision.action.value,
                    decision.resource, RepairResultStatus.APPLIED,
                    "Recorded authorized offline service configuration for the next environment version; guest behavior is unvalidated.",
                    network_service=item.selection)
                continue
            if isinstance(item, _PreparedFileRepair):
                start = len(created_paths)
                repair_files.install_file(item.rootfs, item.decision.resource, item.source, created_paths, file_identities)
                paths = tuple(str(path) for path in created_paths[start:])
                result = by_decision[item.decision.decision_id]
                by_decision[item.decision.decision_id] = replace(result, created_paths=paths,
                    status=RepairResultStatus.APPLIED if paths else RepairResultStatus.ALREADY_SATISFIED,
                    reason="Verified supplied file bytes in the repaired rootfs.")
                continue
            if item.already_satisfied:
                continue

            actually_created: list[str] = []
            for path in item.create_paths:
                try:
                    path.mkdir(mode=item.mode)
                except FileExistsError:
                    entry_stat = path.lstat()
                    if stat.S_ISLNK(entry_stat.st_mode):
                        raise RepairApplicationError(
                            f"repair path became a symbolic link during "
                            f"application: {path}"
                        )
                    if not stat.S_ISDIR(entry_stat.st_mode):
                        raise RepairApplicationError(
                            f"repair path became a non-directory during "
                            f"application: {path}"
                        )
                    continue
                except OSError as exc:
                    raise RepairApplicationError(
                        f"cannot create repair directory {path}: {exc}"
                    ) from exc

                created_paths.append(path)
                os.chmod(path, item.mode)
                actually_created.append(str(path))

            by_decision[item.decision.decision_id] = RepairDecisionResult(
                decision_id=item.decision.decision_id,
                requirement_id=item.decision.requirement_id,
                action=item.decision.action.value,
                resource=item.decision.resource,
                status=(
                    RepairResultStatus.APPLIED
                    if actually_created
                    else RepairResultStatus.ALREADY_SATISFIED
                ),
                reason=(
                    "Created the authorized directory path inside rootfs."
                    if actually_created
                    else "Directory was satisfied by an earlier decision."
                ),
                target_path=str(item.target_path),
                created_paths=tuple(actually_created),
            )

        return [
            by_decision[result.decision_id]
            for result in initial_results
        ]

    @staticmethod
    def _rollback(created_paths: list[Path], file_identities: dict) -> list[str]:
        errors: list[str] = []
        for path in reversed(created_paths):
            try:
                if path in file_identities:
                    info = path.lstat()
                    if (info.st_dev, info.st_ino) != file_identities[path]:
                        raise OSError("file changed since publication")
                    path.unlink()
                else:
                    path.rmdir()
            except FileNotFoundError:
                continue
            except OSError as exc:
                errors.append(f"cannot roll back {path}: {exc}")
        return errors

    @staticmethod
    def _mark_rolled_back(
        results: list[RepairDecisionResult],
        created_paths: list[Path],
    ) -> list[RepairDecisionResult]:
        created_strings = {str(path) for path in created_paths}
        updated: list[RepairDecisionResult] = []

        for result in results:
            if created_strings.intersection(result.created_paths) or result.network_service is not None:
                updated.append(
                    RepairDecisionResult(
                        decision_id=result.decision_id,
                        requirement_id=result.requirement_id,
                        action=result.action,
                        resource=result.resource,
                        status=RepairResultStatus.ROLLED_BACK,
                        reason=(
                            "The transaction failed; its network configuration was not published "
                            "and created paths were rolled back where possible."
                        ),
                        target_path=result.target_path,
                        created_paths=result.created_paths,
                    )
                )
            else:
                updated.append(result)

        return updated

    def _validate_guest_path(self, path: str) -> str:
        if "\x00" in path:
            raise RepairApplicationError("guest path contains a NUL byte")
        if not path.startswith("/"):
            raise RepairApplicationError("guest path is not absolute")
        if path == "/":
            raise RepairApplicationError("root directory cannot be repaired")

        pure = PurePosixPath(path)
        if ".." in pure.parts:
            raise RepairApplicationError(
                "guest path contains a parent traversal component"
            )
        if pure.as_posix() != path.rstrip("/"):
            raise RepairApplicationError(
                "guest path is not in normalized POSIX form"
            )

        normalized = pure.as_posix()
        for prefix in self.config.denied_prefixes:
            if normalized == prefix or normalized.startswith(prefix + "/"):
                raise RepairApplicationError(
                    f"guest path requires pseudo-filesystem semantics: "
                    f"{normalized}"
                )

        return normalized

    @staticmethod
    def _parse_mode(value: Any, decision_id: str) -> int:
        if not isinstance(value, str) or not re.fullmatch(
            r"0?[0-7]{3}",
            value,
        ):
            raise RepairApplicationError(
                f"decision {decision_id} has invalid directory mode: "
                f"{value!r}"
            )

        mode = int(value, 8)
        if mode > 0o777:
            raise RepairApplicationError(
                f"decision {decision_id} requests special permission bits"
            )
        return mode

    @staticmethod
    def _validate_rootfs(rootfs: Path) -> Path:
        if not rootfs.exists():
            raise RepairApplicationError(f"rootfs does not exist: {rootfs}")
        if rootfs.is_symlink():
            raise RepairApplicationError(
                f"rootfs itself must not be a symbolic link: {rootfs}"
            )
        if not rootfs.is_dir():
            raise RepairApplicationError(
                f"rootfs is not a directory: {rootfs}"
            )

        resolved = rootfs.resolve(strict=True)
        if resolved == Path("/"):
            raise RepairApplicationError(
                "refusing to apply repairs to the host root directory"
            )
        return resolved

    @staticmethod
    def _read_file(path: Path, description: str) -> bytes:
        if not path.exists():
            raise RepairApplicationError(
                f"{description} file does not exist: {path}"
            )
        if not path.is_file():
            raise RepairApplicationError(
                f"{description} path is not a file: {path}"
            )
        try:
            return path.read_bytes()
        except OSError as exc:
            raise RepairApplicationError(
                f"cannot read {description} {path}: {exc}"
            ) from exc

    @staticmethod
    def _application_id(
        plan_sha256: str,
        requirements_sha256: str,
        rootfs: Path,
    ) -> str:
        canonical = (
            f"{plan_sha256}\0{requirements_sha256}\0{rootfs}"
        ).encode("utf-8")
        return "apply_" + hashlib.sha256(canonical).hexdigest()[:16]
