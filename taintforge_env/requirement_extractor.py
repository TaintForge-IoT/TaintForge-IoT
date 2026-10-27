from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any, Iterable

from .observations import ObservationBundle
from .requirements import (
    BlockingAssessment,
    RequirementEvidence,
    RequirementKind,
    RequirementReport,
    RequirementStatus,
    RuntimeRequirement,
    make_requirement_id,
)


OPEN_WRITE_FLAGS = {
    "O_WRONLY",
    "O_RDWR",
    "O_CREAT",
    "O_TRUNC",
    "O_APPEND",
    "O_TMPFILE",
}

PATH_EXISTS_SYSCALLS = {
    "open",
    "openat",
    "creat",
    "stat",
    "lstat",
    "newfstatat",
    "access",
    "faccessat",
    "readlink",
    "readlinkat",
    "chdir",
    "unlink",
    "unlinkat",
    "rmdir",
}

DIRECTORY_CREATE_SYSCALLS = {"mkdir", "mkdirat"}
EXEC_SYSCALLS = {"execve", "execveat"}
NETWORK_FAILURE_ERRNOS = {
    "ECONNREFUSED",
    "ETIMEDOUT",
    "ENETUNREACH",
    "EHOSTUNREACH",
    "EADDRNOTAVAIL",
}
TERMINAL_EVENTS = {"process_exit", "signal"}
LIBRARY_PATTERNS = (
    re.compile(
        r"error while loading shared libraries:\s*"
        r"(?P<name>[^:\s]+):\s*cannot open shared object file",
        re.IGNORECASE,
    ),
    re.compile(
        r"Could not open ['\"](?P<name>/[^'\"]*(?:ld[^/'\"]*\.so[^/'\"]*))['\"]",
        re.IGNORECASE,
    ),
)


@dataclass(slots=True, frozen=True)
class ExtractionConfig:
    guest_only: bool = True
    terminal_failure_window: int = 6
    maximum_evidence_per_requirement: int = 8


@dataclass(slots=True)
class _MutableRequirement:
    kind: RequirementKind
    resource: str
    operation: str
    status: RequirementStatus
    blocking: BlockingAssessment
    confidence: float
    repairable: bool
    errno: str | None
    evidence: list[RequirementEvidence]
    details: dict[str, str]


class RequirementExtractor:
    """Infer Phase 2 runtime requirements from execution evidence.

    The extractor only consumes Phase 2-owned artifacts.  It intentionally
    does not import TaintLog, MemoryRegion, or any Phase 1 JSON model.
    """

    def __init__(self, config: ExtractionConfig | None = None):
        self.config = config or ExtractionConfig()
        self._requirements: dict[
            tuple[RequirementKind, str, str], _MutableRequirement
        ] = {}

    def extract(self, bundle: ObservationBundle) -> RequirementReport:
        self._requirements.clear()
        syscall_events = self._select_syscall_events(bundle.syscall_events)

        self._extract_syscall_requirements(syscall_events)
        self._extract_network_requirements(bundle.network_events)
        self._extract_loader_requirements(bundle.iter_stderr_lines())
        self._extract_rootfs_requirements(bundle.rootfs_diff)

        requirements = tuple(
            self._freeze(requirement)
            for requirement in sorted(
                self._requirements.values(),
                key=lambda item: (
                    item.kind.value,
                    item.resource,
                    item.operation,
                ),
            )
        )
        return RequirementReport(
            requirements=requirements,
            warnings=bundle.warnings,
        )

    def _select_syscall_events(
        self,
        events: Iterable[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        selected: list[dict[str, Any]] = []
        for event in events:
            if self.config.guest_only and event.get("execution_context") != "guest":
                continue
            selected.append(event)
        return selected

    def _extract_syscall_requirements(
        self,
        events: list[dict[str, Any]],
    ) -> None:
        for index, event in enumerate(events):
            if event.get("event") == "signal":
                signal_name = str(event.get("result") or "unknown")
                self._add(
                    kind=RequirementKind.EXECUTION,
                    resource=signal_name,
                    operation="avoid_fatal_signal",
                    status=RequirementStatus.UNMET,
                    blocking=BlockingAssessment.LIKELY,
                    confidence=1.0,
                    repairable=False,
                    errno=None,
                    evidence=self._syscall_evidence(event, index),
                    details={"diagnostic": "true"},
                )
                continue

            if event.get("event") != "syscall":
                continue

            syscall = str(event.get("syscall") or "")
            errno = self._optional_string(event.get("errno"))
            path = self._optional_string(event.get("path"))
            return_value = self._optional_int(event.get("return_value"))

            if errno == "ENOSYS":
                self._add(
                    kind=RequirementKind.SYSCALL,
                    resource=syscall or "unknown",
                    operation="kernel_or_qemu_support",
                    status=RequirementStatus.UNMET,
                    blocking=self._blocking_after(events, index),
                    confidence=1.0,
                    repairable=False,
                    errno=errno,
                    evidence=self._syscall_evidence(event, index),
                    details={},
                )

            if path is not None:
                self._extract_path_event(
                    events=events,
                    index=index,
                    event=event,
                    syscall=syscall,
                    path=path,
                    errno=errno,
                    return_value=return_value,
                )

            if syscall == "connect" and errno in NETWORK_FAILURE_ERRNOS:
                remote_ip = self._optional_string(event.get("remote_ip"))
                remote_port = self._optional_int(event.get("remote_port"))
                if remote_ip is not None and remote_port is not None:
                    self._add(
                        kind=RequirementKind.NETWORK,
                        resource=f"tcp://{remote_ip}:{remote_port}",
                        operation="connect",
                        status=RequirementStatus.UNMET,
                        blocking=self._blocking_after(events, index),
                        confidence=1.0,
                        repairable=True,
                        errno=errno,
                        evidence=self._syscall_evidence(event, index),
                        details={"transport": "tcp"},
                    )
                else:
                    # QEMU may print only a sockaddr pointer. Keep the failure
                    # without inventing a destination or assuming TCP: connect
                    # is also used with datagram and Unix-domain sockets.
                    details = {
                        "endpoint_resolution": "unresolved",
                        "transport": "unknown",
                        "missing_endpoint_fields": ",".join(
                            key for key, value in (("remote_ip", remote_ip), ("remote_port", remote_port))
                            if value is None
                        ),
                    }
                    for key, value in (("remote_ip", remote_ip), ("remote_port", remote_port)):
                        if value is not None:
                            details[key] = str(value)
                    for key in ("pid", "source_file", "line_number"):
                        value = self._optional_string(event.get(key))
                        if value is not None:
                            details[key] = value
                    self._add(
                        kind=RequirementKind.NETWORK,
                        # This identifies an observation, not a network address.
                        # Do not merge unknown destinations across calls/PIDs.
                        resource=f"unresolved-connect-event-{index}",
                        operation="connect",
                        status=RequirementStatus.UNMET,
                        blocking=self._blocking_after(events, index),
                        confidence=1.0,
                        repairable=False,
                        errno=errno,
                        evidence=self._syscall_evidence(event, index),
                        details=details,
                    )

    def _extract_path_event(
        self,
        *,
        events: list[dict[str, Any]],
        index: int,
        event: dict[str, Any],
        syscall: str,
        path: str,
        errno: str | None,
        return_value: int | None,
    ) -> None:
        args = str(event.get("args") or "")
        flags = self._extract_open_flags(args)
        evidence = self._syscall_evidence(event, index)
        blocking = self._blocking_after(events, index)

        if errno == "ENOENT":
            if syscall in DIRECTORY_CREATE_SYSCALLS or (
                syscall in {"open", "openat", "creat"} and "O_CREAT" in flags
            ):
                parent = self._parent_directory(path)
                self._add(
                    kind=RequirementKind.FILESYSTEM,
                    resource=parent,
                    operation="directory_exists",
                    status=RequirementStatus.UNMET,
                    blocking=blocking,
                    confidence=1.0,
                    repairable=True,
                    errno=errno,
                    evidence=evidence,
                    details={"trigger_path": path, "syscall": syscall},
                )
                return

            if syscall in EXEC_SYSCALLS:
                self._add(
                    kind=RequirementKind.EXECUTION,
                    resource=path,
                    operation="executable_available",
                    status=RequirementStatus.UNMET,
                    blocking=BlockingAssessment.LIKELY,
                    confidence=1.0,
                    repairable=True,
                    errno=errno,
                    evidence=evidence,
                    details={"syscall": syscall},
                )
                return

            if syscall in PATH_EXISTS_SYSCALLS:
                kind = (
                    RequirementKind.DEVICE
                    if path == "/dev" or path.startswith("/dev/")
                    else RequirementKind.FILESYSTEM
                )
                self._add(
                    kind=kind,
                    resource=path,
                    operation="path_exists",
                    status=RequirementStatus.UNMET,
                    blocking=blocking,
                    confidence=1.0,
                    repairable=True,
                    errno=errno,
                    evidence=evidence,
                    details={"syscall": syscall},
                )
                return

        if errno in {"EACCES", "EPERM"}:
            self._add(
                kind=RequirementKind.FILESYSTEM,
                resource=path,
                operation="path_access",
                status=RequirementStatus.UNMET,
                blocking=blocking,
                confidence=1.0,
                repairable=True,
                errno=errno,
                evidence=evidence,
                details={
                    "syscall": syscall,
                    "requested_flags": "|".join(sorted(flags)),
                },
            )
            return

        if errno == "EROFS":
            self._add(
                kind=RequirementKind.FILESYSTEM,
                resource=path,
                operation="path_writable",
                status=RequirementStatus.UNMET,
                blocking=blocking,
                confidence=1.0,
                repairable=True,
                errno=errno,
                evidence=evidence,
                details={"syscall": syscall},
            )
            return

        if errno == "ENOTDIR":
            self._add(
                kind=RequirementKind.FILESYSTEM,
                resource=path,
                operation="valid_path_layout",
                status=RequirementStatus.UNMET,
                blocking=blocking,
                confidence=1.0,
                repairable=True,
                errno=errno,
                evidence=evidence,
                details={"syscall": syscall},
            )
            return

        if errno in {"ENODEV", "ENXIO"}:
            kind = (
                RequirementKind.DEVICE
                if path == "/dev" or path.startswith("/dev/")
                else RequirementKind.FILESYSTEM
            )
            self._add(
                kind=kind,
                resource=path,
                operation="device_or_backend_available",
                status=RequirementStatus.UNMET,
                blocking=blocking,
                confidence=1.0,
                repairable=kind == RequirementKind.DEVICE,
                errno=errno,
                evidence=evidence,
                details={"syscall": syscall},
            )
            return

        if (
            return_value is not None
            and return_value >= 0
            and syscall in {"open", "openat", "creat"}
            and flags.intersection(OPEN_WRITE_FLAGS)
        ):
            self._add(
                kind=RequirementKind.FILESYSTEM,
                resource=path,
                operation="path_writable",
                status=RequirementStatus.PROVIDED,
                blocking=BlockingAssessment.UNKNOWN,
                confidence=1.0,
                repairable=True,
                errno=None,
                evidence=evidence,
                details={
                    "syscall": syscall,
                    "requested_flags": "|".join(sorted(flags)),
                },
            )

    def _extract_network_requirements(
        self,
        events: Iterable[dict[str, Any]],
    ) -> None:
        response_connections: set[tuple[str, str, str, int]] = set()
        for event in events:
            if event.get("event") != "tcp_response":
                continue
            connection_key = self._network_connection_key(event)
            if connection_key is not None:
                response_connections.add(connection_key)

        for index, event in enumerate(events):
            event_type = str(event.get("event") or "")
            ip = self._optional_string(event.get("original_remote_ip"))
            port = self._optional_int(event.get("original_remote_port"))
            listener_type = self._optional_string(event.get("listener_type"))

            if event_type == "tcp_connection_open" and ip is not None and port is not None:
                connection_key = self._network_connection_key(event)
                has_response = (
                    connection_key is not None
                    and connection_key in response_connections
                )
                self._add(
                    kind=RequirementKind.NETWORK,
                    resource=f"tcp://{ip}:{port}",
                    operation="connect",
                    status=(
                        RequirementStatus.PROVIDED
                        if has_response
                        else RequirementStatus.UNKNOWN
                    ),
                    blocking=BlockingAssessment.UNKNOWN,
                    confidence=1.0,
                    repairable=True,
                    errno=None,
                    evidence=RequirementEvidence(
                        source="network",
                        summary=(
                            f"TCP connection intercepted by {listener_type or 'unknown'}"
                        ),
                        raw=None,
                        event_index=index,
                    ),
                    details={
                        "transport": "tcp",
                        "listener_type": listener_type or "unknown",
                        "response_observed": str(has_response).lower(),
                        "semantic_satisfaction": "unknown",
                    },
                )
                continue

            if event_type == "udp_datagram" and ip is not None and port is not None:
                role = self._optional_string(event.get("udp_role")) or "udp"
                response_sent = bool(event.get("dns_response_sent", False))
                self._add(
                    kind=RequirementKind.NETWORK,
                    resource=f"udp://{ip}:{port}",
                    operation="datagram_exchange",
                    status=(
                        RequirementStatus.PROVIDED
                        if response_sent
                        else RequirementStatus.UNKNOWN
                    ),
                    blocking=BlockingAssessment.UNKNOWN,
                    confidence=1.0,
                    repairable=True,
                    errno=None,
                    evidence=RequirementEvidence(
                        source="network",
                        summary=f"UDP datagram intercepted as role={role}",
                        raw=None,
                        event_index=index,
                    ),
                    details={
                        "transport": "udp",
                        "role": role,
                        "response_observed": str(response_sent).lower(),
                        "semantic_satisfaction": "unknown",
                    },
                )

    def _extract_loader_requirements(self, stderr_lines: Iterable[str]) -> None:
        for line_index, line in enumerate(stderr_lines):
            line = line.rstrip("\r\n")
            for pattern in LIBRARY_PATTERNS:
                match = pattern.search(line)
                if match is None:
                    continue
                name = match.group("name")
                operation = (
                    "interpreter_available"
                    if name.startswith("/") and "ld" in PurePosixPath(name).name
                    else "library_available"
                )
                self._add(
                    kind=RequirementKind.LIBRARY,
                    resource=name,
                    operation=operation,
                    status=RequirementStatus.UNMET,
                    blocking=BlockingAssessment.LIKELY,
                    confidence=1.0,
                    repairable=True,
                    errno="ENOENT",
                    evidence=RequirementEvidence(
                        source="stderr",
                        summary="dynamic loader reported a missing object",
                        raw=line,
                        event_index=line_index,
                    ),
                    details={},
                )
                break

    def _extract_rootfs_requirements(
        self,
        rootfs_diff: dict[str, Any] | None,
    ) -> None:
        if rootfs_diff is None:
            return

        for section in ("created", "modified"):
            raw_entries = rootfs_diff.get(section, [])
            if not isinstance(raw_entries, list):
                continue
            for index, entry in enumerate(raw_entries):
                if not isinstance(entry, dict):
                    continue

                if (
                    section == "modified"
                    and self._is_directory_mtime_only_change(entry)
                ):
                    continue

                path = self._optional_string(entry.get("path"))
                if path is None:
                    continue
                self._add(
                    kind=RequirementKind.FILESYSTEM,
                    resource=path,
                    operation="path_writable",
                    status=RequirementStatus.PROVIDED,
                    blocking=BlockingAssessment.UNKNOWN,
                    confidence=1.0,
                    repairable=True,
                    errno=None,
                    evidence=RequirementEvidence(
                        source="rootfs_diff",
                        summary=(
                            "path was created during execution"
                            if section == "created"
                            else "path was modified during execution"
                        ),
                        raw=None,
                        event_index=index,
                    ),
                    details={
                        "change_type": (
                            "created" if section == "created" else "modified"
                        )
                    },
                )

    @staticmethod
    def _is_directory_mtime_only_change(
        entry: dict[str, Any],
    ) -> bool:
        """Ignore parent-directory timestamp noise caused by child changes.

        Creating, deleting, or renaming a child updates the parent directory's
        mtime. That does not prove that the malware requires the directory inode
        itself to be writable as a separate environment resource; the child
        change already provides the relevant evidence.
        """
        type_before = entry.get("type_before")
        type_after = entry.get("type_after")
        changes = entry.get("changes")

        if type_before != "dir" or type_after != "dir":
            return False

        if not isinstance(changes, dict):
            return False

        return set(changes) == {"mtime_ns"}

    def _blocking_after(
        self,
        events: list[dict[str, Any]],
        index: int,
    ) -> BlockingAssessment:
        window_end = min(
            len(events),
            index + 1 + self.config.terminal_failure_window,
        )
        for event in events[index + 1 : window_end]:
            if event.get("event") == "signal":
                return BlockingAssessment.LIKELY
            if event.get("event") == "process_exit":
                exit_code = self._optional_int(event.get("return_value"))
                if exit_code is None:
                    exit_code = self._optional_int(event.get("result"))
                return (
                    BlockingAssessment.LIKELY
                    if exit_code not in {None, 0}
                    else BlockingAssessment.POSSIBLE
                )
        return BlockingAssessment.UNKNOWN

    def _add(
        self,
        *,
        kind: RequirementKind,
        resource: str,
        operation: str,
        status: RequirementStatus,
        blocking: BlockingAssessment,
        confidence: float,
        repairable: bool,
        errno: str | None,
        evidence: RequirementEvidence,
        details: dict[str, str],
    ) -> None:
        key = (kind, operation, resource)
        existing = self._requirements.get(key)
        if existing is None:
            self._requirements[key] = _MutableRequirement(
                kind=kind,
                resource=resource,
                operation=operation,
                status=status,
                blocking=blocking,
                confidence=self._bounded_confidence(confidence),
                repairable=repairable,
                errno=errno,
                evidence=[evidence],
                details=dict(details),
            )
            return

        existing.status = self._merge_status(existing.status, status)
        existing.blocking = self._merge_blocking(existing.blocking, blocking)
        existing.confidence = max(
            existing.confidence,
            self._bounded_confidence(confidence),
        )
        existing.repairable = existing.repairable or repairable
        if existing.errno is None:
            existing.errno = errno
        existing.details.update(details)
        if (
            evidence not in existing.evidence
            and len(existing.evidence) < self.config.maximum_evidence_per_requirement
        ):
            existing.evidence.append(evidence)

    @staticmethod
    def _merge_status(
        current: RequirementStatus,
        incoming: RequirementStatus,
    ) -> RequirementStatus:
        precedence = {
            RequirementStatus.UNKNOWN: 0,
            RequirementStatus.PROVIDED: 1,
            RequirementStatus.UNMET: 2,
        }
        return current if precedence[current] >= precedence[incoming] else incoming

    @staticmethod
    def _merge_blocking(
        current: BlockingAssessment,
        incoming: BlockingAssessment,
    ) -> BlockingAssessment:
        precedence = {
            BlockingAssessment.UNLIKELY: 0,
            BlockingAssessment.UNKNOWN: 1,
            BlockingAssessment.POSSIBLE: 2,
            BlockingAssessment.LIKELY: 3,
        }
        return current if precedence[current] >= precedence[incoming] else incoming

    def _freeze(self, value: _MutableRequirement) -> RuntimeRequirement:
        return RuntimeRequirement(
            requirement_id=make_requirement_id(
                value.kind,
                value.operation,
                value.resource,
            ),
            kind=value.kind,
            resource=value.resource,
            operation=value.operation,
            status=value.status,
            blocking=value.blocking,
            confidence=value.confidence,
            repairable=value.repairable,
            errno=value.errno,
            evidence=tuple(value.evidence),
            details=tuple(sorted(value.details.items())),
        )

    @classmethod
    def _network_connection_key(
        cls,
        event: dict[str, Any],
    ) -> tuple[str, str, str, int] | None:
        connection_id = event.get("connection_id")
        listener_type = cls._optional_string(event.get("listener_type"))
        remote_ip = cls._optional_string(event.get("original_remote_ip"))
        remote_port = cls._optional_int(event.get("original_remote_port"))
        if (
            connection_id is None
            or listener_type is None
            or remote_ip is None
            or remote_port is None
        ):
            return None
        return listener_type, str(connection_id), remote_ip, remote_port

    @staticmethod
    def _syscall_evidence(
        event: dict[str, Any],
        index: int,
    ) -> RequirementEvidence:
        syscall = str(event.get("syscall") or "unknown")
        errno = event.get("errno")
        summary = f"{syscall} failed with {errno}" if errno else syscall
        return RequirementEvidence(
            source="syscall",
            summary=summary,
            raw=RequirementExtractor._optional_string(event.get("raw")),
            event_index=index,
        )

    @staticmethod
    def _extract_open_flags(args: str) -> set[str]:
        return set(re.findall(r"\bO_[A-Z0-9_]+\b", args))

    @staticmethod
    def _parent_directory(path: str) -> str:
        pure = PurePosixPath(path)
        parent = str(pure.parent)
        return parent if parent not in {"", "."} else "/"

    @staticmethod
    def _optional_string(value: Any) -> str | None:
        if value is None:
            return None
        rendered = str(value)
        return rendered if rendered else None

    @staticmethod
    def _optional_int(value: Any) -> int | None:
        if value is None or isinstance(value, bool):
            return None
        try:
            return int(value)
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _bounded_confidence(value: float) -> float:
        return max(0.0, min(1.0, float(value)))
