from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import urlsplit

from .repair_plan import (
    RepairActionKind,
    RepairDecision,
    RepairDisposition,
    RepairPlan,
    RepairPriority,
    RepairRisk,
    make_decision_id,
)
from .requirements import (
    BlockingAssessment,
    RequirementKind,
    RequirementReport,
    RequirementStatus,
    RequirementValidationError,
    RuntimeRequirement,
)


class RepairPlanningError(RuntimeError):
    """Raised when a repair plan cannot be generated safely."""


@dataclass(slots=True, frozen=True)
class RepairPlannerConfig:
    minimum_auto_confidence: float = 0.95

    def __post_init__(self) -> None:
        if not 0.0 <= self.minimum_auto_confidence <= 1.0:
            raise ValueError(
                "minimum_auto_confidence must be between 0.0 and 1.0"
            )


class RepairPlanner:
    """Convert observed requirements into a passive, auditable repair plan.

    The planner never mutates the rootfs, network namespace, or runtime.  Its
    output records what could be changed, how risky that change is, and whether
    later automation is permitted to apply it without human review.
    """

    def __init__(self, config: RepairPlannerConfig | None = None) -> None:
        self.config = config or RepairPlannerConfig()

    def plan(
        self,
        report: RequirementReport,
        *,
        source_requirements: str,
        source_sha256: str,
    ) -> RepairPlan:
        decisions = tuple(
            sorted(
                (self._plan_requirement(item) for item in report.requirements),
                key=lambda item: (
                    _priority_order(item.priority),
                    item.requirement_kind,
                    item.resource,
                    item.operation,
                    item.decision_id,
                ),
            )
        )
        return RepairPlan(
            source_requirements=source_requirements,
            source_sha256=source_sha256,
            decisions=decisions,
            warnings=report.warnings,
        )

    def plan_file(
        self,
        requirements_path: str | Path,
        out_path: str | Path,
    ) -> RepairPlan:
        requirements_path = Path(requirements_path)
        try:
            raw_bytes = requirements_path.read_bytes()
            report = RequirementReport.load(requirements_path)
        except OSError as exc:
            raise RepairPlanningError(
                f"cannot read runtime requirements {requirements_path}: {exc}"
            ) from exc
        except RequirementValidationError as exc:
            raise RepairPlanningError(str(exc)) from exc

        plan = self.plan(
            report,
            source_requirements=str(requirements_path),
            source_sha256=hashlib.sha256(raw_bytes).hexdigest(),
        )
        plan.save(out_path)
        return plan

    def _plan_requirement(
        self,
        requirement: RuntimeRequirement,
    ) -> RepairDecision:
        priority = _priority_from_blocking(requirement.blocking)

        if (
            requirement.kind == RequirementKind.NETWORK
            and dict(requirement.details).get("endpoint_resolution") == "unresolved"
        ):
            return self._decision(
                requirement,
                action=RepairActionKind.NONE,
                disposition=RepairDisposition.MANUAL_ANALYSIS,
                priority=priority,
                risk=RepairRisk.HIGH,
                automatic_allowed=False,
                reason=(
                    "The failed connect has no complete remote IP and port. "
                    "Preserve the failure and resolve its destination before "
                    "planning a network service; a sockaddr pointer is not an endpoint."
                ),
            )

        if (
            requirement.status == RequirementStatus.PROVIDED
            and not _needs_semantic_network_review(requirement)
        ):
            return self._decision(
                requirement,
                action=RepairActionKind.NONE,
                disposition=RepairDisposition.NOT_REQUIRED,
                priority=RepairPriority.LOW,
                risk=RepairRisk.LOW,
                automatic_allowed=False,
                reason=(
                    "The current execution already demonstrated that the "
                    "environment provides this capability. Preserve it during "
                    "later minimization, but do not add a repair."
                ),
            )

        if not requirement.repairable:
            return self._decision(
                requirement,
                action=RepairActionKind.NONE,
                disposition=RepairDisposition.MANUAL_ANALYSIS,
                priority=priority,
                risk=RepairRisk.HIGH,
                automatic_allowed=False,
                reason=(
                    "The observation is important but cannot be repaired by a "
                    "safe filesystem or network mutation. It requires backend, "
                    "binary, syscall, or crash analysis."
                ),
            )

        if requirement.kind == RequirementKind.FILESYSTEM:
            return self._plan_filesystem(requirement, priority)
        if requirement.kind == RequirementKind.DEVICE:
            return self._decision(
                requirement,
                action=RepairActionKind.PROVIDE_DEVICE_BACKEND,
                disposition=RepairDisposition.MANUAL_ANALYSIS,
                priority=priority,
                risk=RepairRisk.HIGH,
                automatic_allowed=False,
                reason=(
                    "A device path may require ioctl and kernel semantics; "
                    "creating a node alone is not evidence-equivalent."
                ),
                parameters={"backend_semantics_required": True},
            )
        if requirement.kind == RequirementKind.NETWORK:
            return self._plan_network(requirement, priority)
        if requirement.kind == RequirementKind.LIBRARY:
            return self._plan_library(requirement, priority)
        if requirement.kind == RequirementKind.EXECUTION:
            return self._plan_execution(requirement, priority)
        if requirement.kind == RequirementKind.SYSCALL:
            return self._decision(
                requirement,
                action=RepairActionKind.NONE,
                disposition=RepairDisposition.MANUAL_ANALYSIS,
                priority=priority,
                risk=RepairRisk.HIGH,
                automatic_allowed=False,
                reason=(
                    "Kernel or QEMU syscall support cannot be synthesized as a "
                    "rootfs repair. Select another backend or implement an "
                    "explicit syscall compatibility layer."
                ),
            )

        return self._decision(
            requirement,
            action=RepairActionKind.NONE,
            disposition=RepairDisposition.MANUAL_ANALYSIS,
            priority=priority,
            risk=RepairRisk.HIGH,
            automatic_allowed=False,
            reason="No safe planner rule exists for this requirement kind.",
        )

    def _plan_filesystem(
        self,
        requirement: RuntimeRequirement,
        priority: RepairPriority,
    ) -> RepairDecision:
        path_error = _validate_guest_path(requirement.resource)
        if path_error is not None:
            return self._decision(
                requirement,
                action=RepairActionKind.NONE,
                disposition=RepairDisposition.MANUAL_ANALYSIS,
                priority=priority,
                risk=RepairRisk.HIGH,
                automatic_allowed=False,
                reason=f"Unsafe or invalid guest path: {path_error}.",
            )

        if requirement.operation == "directory_exists":
            if requirement.resource == "/" or _is_pseudo_filesystem_path(
                requirement.resource
            ):
                return self._decision(
                    requirement,
                    action=RepairActionKind.CREATE_DIRECTORY,
                    disposition=RepairDisposition.MANUAL_ANALYSIS,
                    priority=priority,
                    risk=RepairRisk.HIGH,
                    automatic_allowed=False,
                    reason=(
                        "Pseudo-filesystem and root paths require mount or "
                        "backend semantics; mkdir is not sufficient."
                    ),
                    parameters={"mode": "0755", "parents": True},
                )

            automatic = (
                requirement.status == RequirementStatus.UNMET
                and requirement.confidence
                >= self.config.minimum_auto_confidence
            )
            return self._decision(
                requirement,
                action=RepairActionKind.CREATE_DIRECTORY,
                disposition=(
                    RepairDisposition.AUTO_CANDIDATE
                    if automatic
                    else RepairDisposition.REVIEW_REQUIRED
                ),
                priority=priority,
                risk=RepairRisk.LOW,
                automatic_allowed=automatic,
                reason=(
                    "Creating an absent directory inside a disposable rootfs is "
                    "structurally reversible and does not invent file content."
                    if automatic
                    else "The directory requirement is plausible, but the "
                    "evidence is not strong enough for automatic application."
                ),
                parameters={"mode": "0755", "parents": True},
            )

        if requirement.operation == "path_exists":
            return self._decision(
                requirement,
                action=RepairActionKind.PROVIDE_FILE,
                disposition=RepairDisposition.REVIEW_REQUIRED,
                priority=priority,
                risk=RepairRisk.MEDIUM,
                automatic_allowed=False,
                reason=(
                    "Existence alone does not reveal required content. The "
                    "planner must not create an empty file and claim semantic "
                    "satisfaction."
                ),
                parameters={
                    "content_strategy": "derive_or_supply",
                    "create_empty": False,
                },
            )

        if requirement.operation == "path_access":
            return self._decision(
                requirement,
                action=RepairActionKind.ADJUST_PATH_ACCESS,
                disposition=RepairDisposition.REVIEW_REQUIRED,
                priority=priority,
                risk=RepairRisk.HIGH,
                automatic_allowed=False,
                reason=(
                    "Changing ownership or permissions may alter malware "
                    "behavior and must be justified from the requested access "
                    "mode and sandbox identity."
                ),
                parameters={"preserve_entry_type": True},
            )

        if requirement.operation == "path_writable":
            return self._decision(
                requirement,
                action=RepairActionKind.MAKE_PATH_WRITABLE,
                disposition=RepairDisposition.REVIEW_REQUIRED,
                priority=priority,
                risk=RepairRisk.MEDIUM,
                automatic_allowed=False,
                reason=(
                    "Writable access may require an overlay, tmpfs, ownership "
                    "change, or mode change. The correct mechanism is not "
                    "inferable from one failure alone."
                ),
                parameters={"strategy": "overlay_or_permissions"},
            )

        if requirement.operation == "valid_path_layout":
            return self._decision(
                requirement,
                action=RepairActionKind.REPAIR_PATH_LAYOUT,
                disposition=RepairDisposition.MANUAL_ANALYSIS,
                priority=priority,
                risk=RepairRisk.HIGH,
                automatic_allowed=False,
                reason=(
                    "ENOTDIR indicates a type conflict in an ancestor path. "
                    "Replacing existing nodes automatically could destroy "
                    "evidence or break unrelated dependencies."
                ),
            )

        return self._decision(
            requirement,
            action=RepairActionKind.NONE,
            disposition=RepairDisposition.MANUAL_ANALYSIS,
            priority=priority,
            risk=RepairRisk.HIGH,
            automatic_allowed=False,
            reason="No safe filesystem repair rule exists for this operation.",
        )

    def _plan_network(
        self,
        requirement: RuntimeRequirement,
        priority: RepairPriority,
    ) -> RepairDecision:
        endpoint = _parse_endpoint(requirement.resource)
        if endpoint is None:
            return self._decision(
                requirement,
                action=RepairActionKind.NONE,
                disposition=RepairDisposition.MANUAL_ANALYSIS,
                priority=priority,
                risk=RepairRisk.HIGH,
                automatic_allowed=False,
                reason="The network resource is not a valid tcp:// or udp:// endpoint.",
            )

        transport, host, port = endpoint
        details = dict(requirement.details)
        parameters: dict[str, Any] = {
            "transport": transport,
            "remote_ip": host,
            "remote_port": port,
            "response_strategy": "recorded_or_protocol_specific",
        }
        if "role" in details:
            parameters["role"] = details["role"]
        if "listener_type" in details:
            parameters["listener_type"] = details["listener_type"]

        action = (
            RepairActionKind.CONFIGURE_TCP_SERVICE
            if transport == "tcp"
            else RepairActionKind.CONFIGURE_UDP_SERVICE
        )
        return self._decision(
            requirement,
            action=action,
            disposition=RepairDisposition.REVIEW_REQUIRED,
            priority=priority,
            risk=RepairRisk.MEDIUM,
            automatic_allowed=False,
            reason=(
                "Transport reachability is not equivalent to protocol "
                "satisfaction. Use a recorded response or a protocol-specific "
                "emulator rather than an arbitrary generic reply."
            ),
            parameters=parameters,
        )

    def _plan_library(
        self,
        requirement: RuntimeRequirement,
        priority: RepairPriority,
    ) -> RepairDecision:
        if requirement.operation == "interpreter_available":
            action = RepairActionKind.PROVIDE_INTERPRETER
            reason = (
                "The ELF interpreter must match the target architecture and ABI. "
                "Resolve it from a verified sysroot before copying it."
            )
        else:
            action = RepairActionKind.RESOLVE_LIBRARY
            reason = (
                "A shared object must match architecture, ABI, SONAME, and "
                "dependency closure. A filename-only stub is unsafe."
            )

        return self._decision(
            requirement,
            action=action,
            disposition=RepairDisposition.REVIEW_REQUIRED,
            priority=priority,
            risk=RepairRisk.MEDIUM,
            automatic_allowed=False,
            reason=reason,
            parameters={
                "source": "verified_sysroot_or_bundle",
                "exact_architecture_required": True,
                "dependency_closure_required": True,
            },
        )

    def _plan_execution(
        self,
        requirement: RuntimeRequirement,
        priority: RepairPriority,
    ) -> RepairDecision:
        if requirement.operation == "executable_available":
            return self._decision(
                requirement,
                action=RepairActionKind.PROVIDE_EXECUTABLE,
                disposition=RepairDisposition.REVIEW_REQUIRED,
                priority=priority,
                risk=RepairRisk.HIGH,
                automatic_allowed=False,
                reason=(
                    "An executed path may be a helper binary, shell, interpreter, "
                    "or second-stage payload. Its exact bytes and architecture "
                    "must be established before adding it."
                ),
                parameters={"source": "verified_artifact"},
            )

        return self._decision(
            requirement,
            action=RepairActionKind.NONE,
            disposition=RepairDisposition.MANUAL_ANALYSIS,
            priority=priority,
            risk=RepairRisk.HIGH,
            automatic_allowed=False,
            reason=(
                "Execution failures and fatal signals require crash, loader, or "
                "binary reconstruction analysis rather than environment mutation."
            ),
        )

    @staticmethod
    def _decision(
        requirement: RuntimeRequirement,
        *,
        action: RepairActionKind,
        disposition: RepairDisposition,
        priority: RepairPriority,
        risk: RepairRisk,
        automatic_allowed: bool,
        reason: str,
        parameters: dict[str, Any] | None = None,
    ) -> RepairDecision:
        parameters = parameters or {}
        if automatic_allowed and disposition != RepairDisposition.AUTO_CANDIDATE:
            raise RepairPlanningError(
                "automatic_allowed requires disposition=auto_candidate"
            )
        return RepairDecision(
            decision_id=make_decision_id(
                requirement.requirement_id,
                action,
                disposition,
                requirement.resource,
            ),
            requirement_id=requirement.requirement_id,
            requirement_kind=requirement.kind.value,
            resource=requirement.resource,
            operation=requirement.operation,
            action=action,
            disposition=disposition,
            priority=priority,
            risk=risk,
            automatic_allowed=automatic_allowed,
            reason=reason,
            parameters=tuple(sorted(parameters.items())),
        )


def _needs_semantic_network_review(
    requirement: RuntimeRequirement,
) -> bool:
    if requirement.kind != RequirementKind.NETWORK:
        return False
    details = dict(requirement.details)
    return details.get("semantic_satisfaction") != "confirmed"


def _priority_from_blocking(
    blocking: BlockingAssessment,
) -> RepairPriority:
    return {
        BlockingAssessment.LIKELY: RepairPriority.CRITICAL,
        BlockingAssessment.POSSIBLE: RepairPriority.HIGH,
        BlockingAssessment.UNKNOWN: RepairPriority.NORMAL,
        BlockingAssessment.UNLIKELY: RepairPriority.LOW,
    }[blocking]


def _priority_order(priority: RepairPriority) -> int:
    return {
        RepairPriority.CRITICAL: 0,
        RepairPriority.HIGH: 1,
        RepairPriority.NORMAL: 2,
        RepairPriority.LOW: 3,
    }[priority]


def _validate_guest_path(path: str) -> str | None:
    if "\x00" in path:
        return "path contains a NUL byte"
    if not path.startswith("/"):
        return "path is not absolute"
    pure = PurePosixPath(path)
    if ".." in pure.parts:
        return "path contains a parent traversal component"
    if pure.as_posix() != path.rstrip("/") and path != "/":
        return "path is not in normalized POSIX form"
    return None


def _is_pseudo_filesystem_path(path: str) -> bool:
    return any(
        path == prefix or path.startswith(prefix + "/")
        for prefix in ("/proc", "/sys", "/dev")
    )


def _parse_endpoint(resource: str) -> tuple[str, str, int] | None:
    try:
        parsed = urlsplit(resource)
        if parsed.scheme not in {"tcp", "udp"}:
            return None
        if not parsed.hostname or parsed.port is None:
            return None
        if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
            return None
        if not 1 <= parsed.port <= 65535:
            return None
        return parsed.scheme, parsed.hostname, parsed.port
    except ValueError:
        return None
