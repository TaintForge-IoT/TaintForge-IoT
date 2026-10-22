from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .log_io import LogReadError, OBSERVATION_PREVIEW_CHARS, iter_log_lines, read_log_preview


class ObservationLoadError(RuntimeError):
    """Raised when Phase 2 runtime artifacts cannot be parsed safely."""


@dataclass(slots=True, frozen=True)
class ObservationBundle:
    """Normalized runtime artifacts produced by a single Phase 2 execution.

    This model deliberately belongs to Phase 2.  It does not import or expose
    the Phase 1 taint-log schema, so changes to unpacked.json do not propagate
    into the runtime-analysis core.
    """

    run_dir: Path
    syscall_events: tuple[dict[str, Any], ...] = ()
    network_events: tuple[dict[str, Any], ...] = ()
    runtime_status: dict[str, Any] = field(default_factory=dict)
    stdout_text: str = ""
    stderr_text: str = ""
    rootfs_diff: dict[str, Any] | None = None
    warnings: tuple[str, ...] = ()
    stderr_path: Path | None = None

    def iter_stderr_lines(self):
        """Scan the full log for requirements, even when its preview is bounded."""
        if self.stderr_path is None:
            yield from self.stderr_text.splitlines()
            return
        try:
            yield from iter_log_lines(self.stderr_path)
        except (LogReadError, OSError) as exc:
            raise ObservationLoadError(str(exc)) from exc

    def guest_syscall_events(self) -> tuple[dict[str, Any], ...]:
        return tuple(
            event
            for event in self.syscall_events
            if event.get("execution_context") == "guest"
        )


def load_observation_bundle(run_dir: str | Path) -> ObservationBundle:
    """Load all currently supported runtime artifacts from a run directory.

    Expected layout::

        <run_dir>/logs/syscall_events.jsonl
        <run_dir>/logs/network_events.jsonl
        <run_dir>/logs/runtime_stdout.log
        <run_dir>/logs/runtime_stderr.log

    runtime_status.json and rootfs_diff.json are optional and are searched in
    a small set of Phase 2-owned locations for compatibility with current and
    future orchestrator layouts.
    """

    run_dir = Path(run_dir)
    if not run_dir.exists():
        raise ObservationLoadError(f"run directory does not exist: {run_dir}")
    if not run_dir.is_dir():
        raise ObservationLoadError(f"run path is not a directory: {run_dir}")

    logs_dir = run_dir / "logs"
    warnings: list[str] = []
    runtime = _load_first_json(
        candidates=(run_dir / "config" / "runtime.json",),
        artifact_name="runtime configuration", warnings=warnings, missing_is_warning=False,
    ) or {}

    syscall_events = _load_jsonl_optional(
        logs_dir / "syscall_events.jsonl",
        artifact_name="syscall events",
        warnings=warnings,
    )
    network_events = _load_jsonl_optional(
        logs_dir / "network_events.jsonl",
        artifact_name="network events",
        warnings=warnings,
        missing_is_warning=runtime.get("network_mode") != "none",
    )

    runtime_status = _load_first_json(
        candidates=(
            run_dir / "config" / "prebuilt_execution.json",
            logs_dir / "runtime_status.json",
            run_dir / "runtime_status.json",
            run_dir / "config" / "runtime_status.json",
        ),
        artifact_name="runtime status",
        warnings=warnings,
    )

    rootfs_diff = _load_first_json(
        candidates=(
            run_dir / "config" / "rootfs_diff.json",
            logs_dir / "rootfs_diff.json",
            run_dir / "rootfs_diff.json",
        ),
        artifact_name="rootfs diff",
        warnings=warnings,
        missing_is_warning=False,
    )

    stdout_text = _read_text_optional(
        logs_dir / "runtime_stdout.log",
        artifact_name="runtime stdout",
        warnings=warnings,
    )
    stderr_text = _read_text_optional(
        logs_dir / "runtime_stderr.log",
        artifact_name="runtime stderr",
        warnings=warnings,
    )

    return ObservationBundle(
        run_dir=run_dir,
        syscall_events=tuple(syscall_events),
        network_events=tuple(network_events),
        runtime_status=runtime_status or {},
        stdout_text=stdout_text,
        stderr_text=stderr_text,
        rootfs_diff=rootfs_diff,
        warnings=tuple(warnings),
        stderr_path=(logs_dir / "runtime_stderr.log") if (logs_dir / "runtime_stderr.log").is_file() else None,
    )


def _load_jsonl_optional(
    path: Path,
    *,
    artifact_name: str,
    warnings: list[str],
    missing_is_warning: bool = True,
) -> list[dict[str, Any]]:
    if not path.exists():
        if missing_is_warning:
            warnings.append(f"{artifact_name} not found: {path}")
        return []
    if not path.is_file():
        raise ObservationLoadError(f"{artifact_name} is not a file: {path}")

    events: list[dict[str, Any]] = []
    try:
        for line_number, line in enumerate(iter_log_lines(path), start=1):
            if not line.strip():
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ObservationLoadError(
                    f"invalid JSON in {artifact_name} at {path}:{line_number}: {exc}"
                ) from exc
            if not isinstance(value, dict):
                raise ObservationLoadError(
                    f"expected JSON object in {artifact_name} at "
                    f"{path}:{line_number}, got {type(value).__name__}"
                )
            events.append(value)
    except (LogReadError, OSError) as exc:
        raise ObservationLoadError(str(exc)) from exc
    return events


def _load_first_json(
    *,
    candidates: tuple[Path, ...],
    artifact_name: str,
    warnings: list[str],
    missing_is_warning: bool = True,
) -> dict[str, Any] | None:
    for path in candidates:
        if not path.exists():
            continue
        if not path.is_file():
            raise ObservationLoadError(f"{artifact_name} is not a file: {path}")
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ObservationLoadError(
                f"invalid JSON in {artifact_name} at {path}: {exc}"
            ) from exc
        if not isinstance(value, dict):
            raise ObservationLoadError(
                f"expected JSON object in {artifact_name} at {path}, "
                f"got {type(value).__name__}"
            )
        return value

    if missing_is_warning:
        rendered = ", ".join(str(path) for path in candidates)
        warnings.append(f"{artifact_name} not found; checked: {rendered}")
    return None


def _read_text_optional(
    path: Path,
    *,
    artifact_name: str,
    warnings: list[str],
) -> str:
    if not path.exists():
        warnings.append(f"{artifact_name} not found: {path}")
        return ""
    if not path.is_file():
        raise ObservationLoadError(f"{artifact_name} is not a file: {path}")
    text, truncated = read_log_preview(path, OBSERVATION_PREVIEW_CHARS)
    if truncated:
        warnings.append(
            f"{artifact_name} preview limited to {OBSERVATION_PREVIEW_CHARS} characters: {path}; "
            "loader requirement extraction scans the complete stderr log"
        )
    return text
