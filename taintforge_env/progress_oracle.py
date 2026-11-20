from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from pathlib import Path
from typing import Any, Iterable

from .network_events import normalize_network_event


class ProgressOracleError(RuntimeError):
    """Raised when iteration artifacts are incomplete or inconsistent."""


class ProgressClassification(StrEnum):
    BASELINE = "baseline"
    PROGRESS = "progress"
    NO_PROGRESS = "no_progress"
    REGRESSION = "regression"
    GOAL_REACHED = "goal_reached"


@dataclass(slots=True, frozen=True)
class ProgressMetrics:
    guest_events_total: int
    unique_guest_events: int
    network_events_total: int
    unique_network_targets: int
    requirements_total: int
    unmet_total: int
    likely_unmet_total: int
    automatic_candidates: int
    review_required: int
    manual_analysis: int
    fatal_signals: int

    def to_dict(self) -> dict[str, int]:
        return {
            "guest_events_total": self.guest_events_total,
            "unique_guest_events": self.unique_guest_events,
            "network_events_total": self.network_events_total,
            "unique_network_targets": self.unique_network_targets,
            "requirements_total": self.requirements_total,
            "unmet_total": self.unmet_total,
            "likely_unmet_total": self.likely_unmet_total,
            "automatic_candidates": self.automatic_candidates,
            "review_required": self.review_required,
            "manual_analysis": self.manual_analysis,
            "fatal_signals": self.fatal_signals,
        }


@dataclass(slots=True, frozen=True)
class IterationObservation:
    requirements_sha256: str
    requirements_fingerprint: str
    repair_plan_sha256: str
    repair_fingerprint: str
    behavior_fingerprint: str
    state_fingerprint: str
    metrics: ProgressMetrics
    normalized_guest_events: tuple[dict[str, Any], ...]
    normalized_network_events: tuple[dict[str, Any], ...]
    goal_reached: bool = False
    goal_reason: str | None = None
    generated_at_utc: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "generated_at_utc": self.generated_at_utc,
            "requirements_sha256": self.requirements_sha256,
            "requirements_fingerprint": self.requirements_fingerprint,
            "repair_plan_sha256": self.repair_plan_sha256,
            "repair_fingerprint": self.repair_fingerprint,
            "behavior_fingerprint": self.behavior_fingerprint,
            "state_fingerprint": self.state_fingerprint,
            "goal_reached": self.goal_reached,
            "goal_reason": self.goal_reason,
            "metrics": self.metrics.to_dict(),
            "normalized_guest_events": list(self.normalized_guest_events),
            "normalized_network_events": list(self.normalized_network_events),
        }

    @classmethod
    def from_dict(cls, raw: Any) -> IterationObservation:
        if not isinstance(raw, dict):
            raise ProgressOracleError("iteration observation must be an object")
        if raw.get("schema_version") != 1:
            raise ProgressOracleError("unsupported iteration observation schema")
        metrics_raw = raw.get("metrics")
        if not isinstance(metrics_raw, dict):
            raise ProgressOracleError("observation metrics must be an object")
        try:
            metrics = ProgressMetrics(
                guest_events_total=_nonnegative_int(metrics_raw, "guest_events_total"),
                unique_guest_events=_nonnegative_int(metrics_raw, "unique_guest_events"),
                network_events_total=_nonnegative_int(metrics_raw, "network_events_total"),
                unique_network_targets=_nonnegative_int(metrics_raw, "unique_network_targets"),
                requirements_total=_nonnegative_int(metrics_raw, "requirements_total"),
                unmet_total=_nonnegative_int(metrics_raw, "unmet_total"),
                likely_unmet_total=_nonnegative_int(metrics_raw, "likely_unmet_total"),
                automatic_candidates=_nonnegative_int(metrics_raw, "automatic_candidates"),
                review_required=_nonnegative_int(metrics_raw, "review_required"),
                manual_analysis=_nonnegative_int(metrics_raw, "manual_analysis"),
                fatal_signals=_nonnegative_int(metrics_raw, "fatal_signals"),
            )
        except KeyError as exc:
            raise ProgressOracleError(f"missing observation metric: {exc}") from exc

        guest_events = raw.get("normalized_guest_events", [])
        network_events = raw.get("normalized_network_events", [])
        if not isinstance(guest_events, list) or not all(
            isinstance(item, dict) for item in guest_events
        ):
            raise ProgressOracleError("normalized_guest_events must be objects")
        if not isinstance(network_events, list) or not all(
            isinstance(item, dict) for item in network_events
        ):
            raise ProgressOracleError("normalized_network_events must be objects")

        fields: dict[str, str] = {}
        for name in (
            "requirements_sha256",
            "requirements_fingerprint",
            "repair_plan_sha256",
            "repair_fingerprint",
            "behavior_fingerprint",
            "state_fingerprint",
        ):
            value = raw.get(name)
            if not isinstance(value, str) or not _is_sha256(value):
                raise ProgressOracleError(f"invalid observation field: {name}")
            fields[name] = value

        goal_reached = raw.get("goal_reached", False)
        if not isinstance(goal_reached, bool):
            raise ProgressOracleError("goal_reached must be boolean")
        goal_reason = raw.get("goal_reason")
        if goal_reason is not None and not isinstance(goal_reason, str):
            raise ProgressOracleError("goal_reason must be string or null")

        return cls(
            **fields,
            metrics=metrics,
            normalized_guest_events=tuple(guest_events),
            normalized_network_events=tuple(network_events),
            goal_reached=goal_reached,
            goal_reason=goal_reason,
            generated_at_utc=str(raw.get("generated_at_utc") or "unknown"),
        )

    @classmethod
    def load(cls, path: str | Path) -> IterationObservation:
        try:
            raw = json.loads(Path(path).read_text(encoding="utf-8"))
        except FileNotFoundError as exc:
            raise ProgressOracleError(f"observation does not exist: {path}") from exc
        except json.JSONDecodeError as exc:
            raise ProgressOracleError(f"invalid observation JSON: {exc}") from exc
        return cls.from_dict(raw)

    def save(self, path: str | Path) -> None:
        _atomic_write_json(Path(path), self.to_dict())


@dataclass(slots=True, frozen=True)
class ProgressDecision:
    classification: ProgressClassification
    reasons: tuple[str, ...]
    new_guest_events: int
    removed_guest_events: int
    new_network_targets: int
    likely_unmet_delta: int
    unmet_delta: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "classification": self.classification.value,
            "reasons": list(self.reasons),
            "new_guest_events": self.new_guest_events,
            "removed_guest_events": self.removed_guest_events,
            "new_network_targets": self.new_network_targets,
            "likely_unmet_delta": self.likely_unmet_delta,
            "unmet_delta": self.unmet_delta,
        }


class ProgressOracle:
    """Build deterministic behavior fingerprints from Phase 2 artifacts.

    This is deliberately a progress proxy, not a correctness oracle. It never
    infers that a malware main loop has been reached. Success requires an
    explicit goal marker supplied by a higher-level analysis component.
    """

    REQUIRED_FILES = (
        "runtime_requirements.json",
        "repair_plan.json",
    )

    def observe(
        self,
        artifacts_dir: str | Path,
        *,
        environment_snapshot_id: str,
        goal_reached: bool = False,
        goal_reason: str | None = None,
    ) -> IterationObservation:
        artifacts = Path(artifacts_dir)
        if not artifacts.is_dir() or artifacts.is_symlink():
            raise ProgressOracleError(
                f"artifacts directory is invalid: {artifacts}"
            )

        requirements_path = _locate_file(artifacts, "runtime_requirements.json")
        repair_plan_path = _locate_file(artifacts, "repair_plan.json")
        requirements_bytes = _read_bytes(requirements_path)
        repair_plan_bytes = _read_bytes(repair_plan_path)
        requirements_sha256 = hashlib.sha256(requirements_bytes).hexdigest()
        repair_plan_sha256 = hashlib.sha256(repair_plan_bytes).hexdigest()

        requirements = _load_json_object(requirements_path)
        repair_plan = _load_json_object(repair_plan_path)

        source_sha256 = repair_plan.get("source_sha256")
        if source_sha256 != requirements_sha256:
            raise ProgressOracleError(
                "repair plan does not reference the exact requirements artifact: "
                f"expected {requirements_sha256}, got {source_sha256!r}"
            )

        normalized_requirements = _normalize_requirements(requirements)
        normalized_repairs = _normalize_repairs(repair_plan)

        syscall_path = _locate_optional_file(artifacts, "syscall_events.jsonl")
        network_path = _locate_optional_file(artifacts, "network_events.jsonl")
        guest_events = tuple(_normalize_guest_events(syscall_path))
        network_events = tuple(_normalize_network_events(network_path))

        requirements_fingerprint = _digest_json(normalized_requirements)
        repair_fingerprint = _digest_json(normalized_repairs)
        behavior_payload = {
            "guest_events": guest_events,
            "network_events": network_events,
        }
        behavior_fingerprint = _digest_json(behavior_payload)
        state_fingerprint = _digest_json(
            {
                "environment_snapshot_id": environment_snapshot_id,
                "requirements_fingerprint": requirements_fingerprint,
                "repair_fingerprint": repair_fingerprint,
                "behavior_fingerprint": behavior_fingerprint,
            }
        )

        metrics = _build_metrics(
            normalized_requirements,
            normalized_repairs,
            guest_events,
            network_events,
        )

        if goal_reached and not goal_reason:
            goal_reason = "explicit goal marker supplied"

        return IterationObservation(
            requirements_sha256=requirements_sha256,
            requirements_fingerprint=requirements_fingerprint,
            repair_plan_sha256=repair_plan_sha256,
            repair_fingerprint=repair_fingerprint,
            behavior_fingerprint=behavior_fingerprint,
            state_fingerprint=state_fingerprint,
            metrics=metrics,
            normalized_guest_events=guest_events,
            normalized_network_events=network_events,
            goal_reached=goal_reached,
            goal_reason=goal_reason,
        )

    def compare(
        self,
        previous: IterationObservation | None,
        current: IterationObservation,
    ) -> ProgressDecision:
        if current.goal_reached:
            return ProgressDecision(
                classification=ProgressClassification.GOAL_REACHED,
                reasons=(current.goal_reason or "explicit goal reached",),
                new_guest_events=0,
                removed_guest_events=0,
                new_network_targets=0,
                likely_unmet_delta=0,
                unmet_delta=0,
            )

        if previous is None:
            return ProgressDecision(
                classification=ProgressClassification.BASELINE,
                reasons=("first completed iteration establishes the baseline",),
                new_guest_events=current.metrics.unique_guest_events,
                removed_guest_events=0,
                new_network_targets=current.metrics.unique_network_targets,
                likely_unmet_delta=0,
                unmet_delta=0,
            )

        previous_guest = {_canonical_json(item) for item in previous.normalized_guest_events}
        current_guest = {_canonical_json(item) for item in current.normalized_guest_events}
        previous_targets = _network_targets(previous.normalized_network_events)
        current_targets = _network_targets(current.normalized_network_events)

        new_guest = len(current_guest - previous_guest)
        removed_guest = len(previous_guest - current_guest)
        new_targets = len(current_targets - previous_targets)
        new_responses = len(_network_responses(current.normalized_network_events)
                            - _network_responses(previous.normalized_network_events))
        removed_responses = len(_network_responses(previous.normalized_network_events)
                                - _network_responses(current.normalized_network_events))
        likely_delta = (
            current.metrics.likely_unmet_total
            - previous.metrics.likely_unmet_total
        )
        unmet_delta = current.metrics.unmet_total - previous.metrics.unmet_total

        positive_reasons: list[str] = []
        negative_reasons: list[str] = []

        if new_guest > 0:
            positive_reasons.append(f"observed {new_guest} new normalized guest events")
        if new_targets > 0:
            positive_reasons.append(f"observed {new_targets} new network targets")
        if new_responses > 0:
            positive_reasons.append(f"observed {new_responses} new sent network responses")
        if likely_delta < 0:
            positive_reasons.append(
                f"likely unmet requirements decreased by {-likely_delta}"
            )
        if unmet_delta < 0:
            positive_reasons.append(f"unmet requirements decreased by {-unmet_delta}")

        if current.metrics.fatal_signals > previous.metrics.fatal_signals:
            negative_reasons.append("fatal signal count increased")
        if removed_responses > 0 and new_responses == 0:
            negative_reasons.append(f"{removed_responses} previously sent network responses disappeared")
        if likely_delta > 0:
            negative_reasons.append(
                f"likely unmet requirements increased by {likely_delta}"
            )
        if removed_guest > 0 and new_guest == 0:
            negative_reasons.append(
                f"{removed_guest} previously observed guest events disappeared"
            )

        if positive_reasons and not negative_reasons:
            classification = ProgressClassification.PROGRESS
            reasons = tuple(positive_reasons)
        elif negative_reasons and not positive_reasons:
            classification = ProgressClassification.REGRESSION
            reasons = tuple(negative_reasons)
        else:
            classification = ProgressClassification.NO_PROGRESS
            reasons = tuple(positive_reasons + negative_reasons) or (
                "no conservative progress signal changed",
            )

        return ProgressDecision(
            classification=classification,
            reasons=reasons,
            new_guest_events=new_guest,
            removed_guest_events=removed_guest,
            new_network_targets=new_targets,
            likely_unmet_delta=likely_delta,
            unmet_delta=unmet_delta,
        )


def _normalize_requirements(raw: dict[str, Any]) -> list[dict[str, Any]]:
    values = raw.get("requirements")
    if not isinstance(values, list):
        raise ProgressOracleError("runtime_requirements.json lacks requirements[]")
    normalized: list[dict[str, Any]] = []
    for index, item in enumerate(values):
        if not isinstance(item, dict):
            raise ProgressOracleError(f"requirements[{index}] is not an object")
        normalized.append(
            {
                "requirement_id": _string(item, "requirement_id", index),
                "kind": _string(item, "kind", index),
                "resource": _string(item, "resource", index),
                "operation": _string(item, "operation", index),
                "status": _string(item, "status", index),
                "blocking": _string(item, "blocking", index),
                "repairable": bool(item.get("repairable", False)),
                "errno": item.get("errno") if isinstance(item.get("errno"), str) else None,
            }
        )
    return sorted(
        normalized,
        key=lambda item: (
            item["kind"],
            item["resource"],
            item["operation"],
            item["requirement_id"],
        ),
    )


def _normalize_repairs(raw: dict[str, Any]) -> list[dict[str, Any]]:
    values = raw.get("decisions")
    if not isinstance(values, list):
        raise ProgressOracleError("repair_plan.json lacks decisions[]")
    normalized: list[dict[str, Any]] = []
    for index, item in enumerate(values):
        if not isinstance(item, dict):
            raise ProgressOracleError(f"decisions[{index}] is not an object")
        normalized.append(
            {
                "decision_id": _string(item, "decision_id", index),
                "requirement_id": _string(item, "requirement_id", index),
                "resource": _string(item, "resource", index),
                "action": _string(item, "action", index),
                "disposition": _string(item, "disposition", index),
                "automatic_allowed": bool(item.get("automatic_allowed", False)),
            }
        )
    return sorted(normalized, key=lambda item: item["decision_id"])


def _normalize_guest_events(path: Path | None) -> Iterable[dict[str, Any]]:
    if path is None:
        return ()
    result: list[dict[str, Any]] = []
    for index, event in enumerate(_read_jsonl(path)):
        if event.get("execution_context") != "guest":
            continue
        event_type = str(event.get("event") or "unknown")
        if event_type == "syscall":
            return_value = event.get("return_value")
            success: bool | None = None
            if isinstance(return_value, int) and not isinstance(return_value, bool):
                success = return_value >= 0
            result.append(
                {
                    "event": "syscall",
                    "syscall": str(event.get("syscall") or "unknown"),
                    "errno": event.get("errno") if isinstance(event.get("errno"), str) else None,
                    "success": success,
                    "path": event.get("path") if isinstance(event.get("path"), str) else None,
                    "remote_ip": event.get("remote_ip") if isinstance(event.get("remote_ip"), str) else None,
                    "remote_port": event.get("remote_port") if isinstance(event.get("remote_port"), int) else None,
                    "transport": event.get("transport") if event.get("transport") in ("tcp", "udp") else None,
                }
            )
        elif event_type in {"signal", "process_exit"}:
            result.append(
                {
                    "event": event_type,
                    "result": str(event.get("result") or "unknown"),
                }
            )
        else:
            result.append({"event": event_type})
    return result


def _normalize_network_events(path: Path | None) -> Iterable[dict[str, Any]]:
    if path is None:
        return ()
    return [normalize_network_event(event) for event in _read_jsonl(path)]


def _build_metrics(
    requirements: list[dict[str, Any]],
    repairs: list[dict[str, Any]],
    guest_events: tuple[dict[str, Any], ...],
    network_events: tuple[dict[str, Any], ...],
) -> ProgressMetrics:
    unique_guest = {_canonical_json(item) for item in guest_events}
    targets = _network_targets(network_events)
    return ProgressMetrics(
        guest_events_total=len(guest_events),
        unique_guest_events=len(unique_guest),
        network_events_total=len(network_events),
        unique_network_targets=len(targets),
        requirements_total=len(requirements),
        unmet_total=sum(item["status"] == "unmet" for item in requirements),
        likely_unmet_total=sum(
            item["status"] == "unmet" and item["blocking"] == "likely"
            for item in requirements
        ),
        automatic_candidates=sum(
            item["automatic_allowed"] for item in repairs
        ),
        review_required=sum(
            item["disposition"] == "review_required" for item in repairs
        ),
        manual_analysis=sum(
            item["disposition"] == "manual_analysis" for item in repairs
        ),
        fatal_signals=sum(
            item.get("event") == "signal" for item in guest_events
        ),
    )


def _network_targets(events: Iterable[dict[str, Any]]) -> set[tuple[Any, ...]]:
    return {
        (item.get("transport"), item.get("original_remote_ip"), item.get("original_remote_port"))
        for item in events
        if item.get("original_remote_ip") is not None
        and item.get("original_remote_port") is not None
    }


def _network_responses(events: Iterable[dict[str, Any]]) -> set[tuple[Any, ...]]:
    return {
        (item.get("transport"), item.get("original_remote_ip"), item.get("original_remote_port"),
         item.get("protocol_hint"), item.get("request_sha256"), item.get("response_sha256"))
        for item in events
        if item.get("response_observed") is True and not item.get("failure")
        and item.get("replay_status") != "miss"
        and item.get("response_origin") not in {"synthetic_error", "synthetic_miss"}
        and item.get("original_remote_ip") is not None and item.get("original_remote_port") is not None
    }


def _locate_file(base: Path, filename: str) -> Path:
    result = _locate_optional_file(base, filename)
    if result is None:
        raise ProgressOracleError(
            f"required artifact {filename} was not found under {base}"
        )
    return result


def _locate_optional_file(base: Path, filename: str) -> Path | None:
    candidates = (
        base / filename,
        base / "config" / filename,
        base / "logs" / filename,
    )
    for candidate in candidates:
        if candidate.is_file() and not candidate.is_symlink():
            return candidate
    return None


def _load_json_object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ProgressOracleError(f"invalid JSON in {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ProgressOracleError(f"expected JSON object in {path}")
    return value


def _read_jsonl(path: Path) -> Iterable[dict[str, Any]]:
    for line_number, line in enumerate(
        path.read_text(encoding="utf-8", errors="replace").splitlines(),
        start=1,
    ):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ProgressOracleError(
                f"invalid JSONL in {path}:{line_number}: {exc}"
            ) from exc
        if not isinstance(value, dict):
            raise ProgressOracleError(
                f"JSONL event in {path}:{line_number} is not an object"
            )
        yield value


def _read_bytes(path: Path) -> bytes:
    try:
        return path.read_bytes()
    except OSError as exc:
        raise ProgressOracleError(f"cannot read artifact {path}: {exc}") from exc


def _string(item: dict[str, Any], field_name: str, index: int) -> str:
    value = item.get(field_name)
    if not isinstance(value, str) or not value:
        raise ProgressOracleError(
            f"item {index} has invalid {field_name}"
        )
    return value


def _digest_json(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def _is_sha256(value: str) -> bool:
    return len(value) == 64 and all(character in "0123456789abcdef" for character in value)


def _nonnegative_int(raw: dict[str, Any], name: str) -> int:
    value = raw[name]
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ProgressOracleError(f"metric {name} must be non-negative integer")
    return value


def _atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    import os
    import tempfile

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
