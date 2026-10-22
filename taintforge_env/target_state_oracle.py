from __future__ import annotations

import hashlib
import json
import os
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from pathlib import Path
from typing import Any, Iterable

from .syscall_result import normalize_syscall_event


class TargetStateError(RuntimeError):
    """Raised when a target-state specification or evidence is invalid."""


class AggregationMode(StrEnum):
    ALL = "all"
    ANY = "any"
    AT_LEAST = "at_least"


class RuleType(StrEnum):
    EVENT_COUNT = "event_count"
    REPEATED_SEQUENCE = "repeated_sequence"
    TEXT_CONTAINS = "text_contains"
    JSON_FIELD_EQUALS = "json_field_equals"


_EVENT_SOURCES = {
    "syscall": "logs/syscall_events.jsonl",
    "network": "logs/network_events.jsonl",
    "trace": "logs/trace_events.jsonl",
}
_TEXT_SOURCES = {
    "stdout": "logs/runtime_stdout.log",
    "stderr": "logs/runtime_stderr.log",
}
_JSON_ARTIFACTS = {
    "execution": "config/prebuilt_execution.json",
    "report": "report.json",
    "requirements": "config/runtime_requirements.json",
    "repair_plan": "config/repair_plan.json",
    "runtime": "config/runtime.json",
    "rootfs_diff": "config/rootfs_diff.json",
}
_MAX_SPEC_BYTES = 1024 * 1024
_MAX_EVIDENCE_FILE_BYTES = 64 * 1024 * 1024
_MAX_TEXT_BYTES = 8 * 1024 * 1024
_MAX_RULES = 64
_MAX_EVIDENCE_ITEMS = 12
_MAX_STRING = 4096


@dataclass(slots=True, frozen=True)
class TargetRule:
    rule_id: str
    rule_type: RuleType
    source: str
    parameters: dict[str, Any]
    description: str | None = None

    def to_dict(self) -> dict[str, Any]:
        payload = {
            "id": self.rule_id,
            "type": self.rule_type.value,
            "source": self.source,
            **self.parameters,
        }
        if self.description:
            payload["description"] = self.description
        return payload


@dataclass(slots=True, frozen=True)
class TargetStateSpec:
    goal_id: str
    description: str
    mode: AggregationMode
    min_satisfied: int
    rules: tuple[TargetRule, ...]
    source_sha256: str
    source_path: str | None = None

    @classmethod
    def load(cls, path: str | Path) -> "TargetStateSpec":
        source = Path(path)
        _validate_regular_file(source, "target-state specification")
        data = _read_limited(source, _MAX_SPEC_BYTES, "target-state specification")
        try:
            raw = json.loads(data)
        except json.JSONDecodeError as exc:
            raise TargetStateError(f"invalid target-state JSON: {exc}") from exc
        return cls.from_dict(
            raw,
            source_sha256=hashlib.sha256(data).hexdigest(),
            source_path=str(source.resolve(strict=False)),
        )

    @classmethod
    def from_dict(
        cls,
        raw: Any,
        *,
        source_sha256: str | None = None,
        source_path: str | None = None,
    ) -> "TargetStateSpec":
        if not isinstance(raw, dict):
            raise TargetStateError("target-state specification must be an object")
        if raw.get("schema_version") != 1:
            raise TargetStateError("unsupported target-state schema version")

        goal_id = _identifier(raw.get("goal_id"), "goal_id")
        description = _bounded_string(raw.get("description"), "description")
        try:
            mode = AggregationMode(raw.get("mode", "all"))
        except ValueError as exc:
            raise TargetStateError("invalid target-state aggregation mode") from exc

        rules_raw = raw.get("rules")
        if not isinstance(rules_raw, list) or not rules_raw:
            raise TargetStateError("target-state specification requires non-empty rules[]")
        if len(rules_raw) > _MAX_RULES:
            raise TargetStateError(f"target-state specification exceeds {_MAX_RULES} rules")

        rules: list[TargetRule] = []
        seen: set[str] = set()
        for index, item in enumerate(rules_raw):
            rule = _parse_rule(item, index)
            if rule.rule_id in seen:
                raise TargetStateError(f"duplicate target rule id: {rule.rule_id}")
            seen.add(rule.rule_id)
            rules.append(rule)

        if mode == AggregationMode.ALL:
            min_satisfied = len(rules)
        elif mode == AggregationMode.ANY:
            min_satisfied = 1
        else:
            min_satisfied = _positive_int(raw.get("min_satisfied"), "min_satisfied")
            if min_satisfied > len(rules):
                raise TargetStateError("min_satisfied exceeds number of rules")

        canonical = {
            "schema_version": 1,
            "goal_id": goal_id,
            "description": description,
            "mode": mode.value,
            "min_satisfied": min_satisfied,
            "rules": [rule.to_dict() for rule in rules],
        }
        digest = source_sha256 or _canonical_digest(canonical)
        return cls(
            goal_id=goal_id,
            description=description,
            mode=mode,
            min_satisfied=min_satisfied,
            rules=tuple(rules),
            source_sha256=digest,
            source_path=source_path,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "goal_id": self.goal_id,
            "description": self.description,
            "mode": self.mode.value,
            "min_satisfied": self.min_satisfied,
            "rules": [rule.to_dict() for rule in self.rules],
        }

    def save(self, path: str | Path) -> None:
        _atomic_write_json(Path(path), self.to_dict())


@dataclass(slots=True, frozen=True)
class RuleEvaluation:
    rule_id: str
    rule_type: str
    matched: bool
    observed_count: int
    required_count: int
    summary: str
    evidence: tuple[dict[str, Any], ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "type": self.rule_type,
            "matched": self.matched,
            "observed_count": self.observed_count,
            "required_count": self.required_count,
            "summary": self.summary,
            "evidence": list(self.evidence),
        }


@dataclass(slots=True, frozen=True)
class TargetStateEvaluation:
    goal_id: str
    description: str
    reached: bool
    reason: str
    mode: str
    min_satisfied: int
    matched_rules: int
    total_rules: int
    spec_sha256: str
    rules: tuple[RuleEvaluation, ...]
    generated_at_utc: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict[str, Any]:
        payload = {
            "schema_version": 1,
            "oracle_version": 2,
            "generated_at_utc": self.generated_at_utc,
            "goal_id": self.goal_id,
            "description": self.description,
            "reached": self.reached,
            "reason": self.reason,
            "mode": self.mode,
            "min_satisfied": self.min_satisfied,
            "matched_rules": self.matched_rules,
            "total_rules": self.total_rules,
            "spec_sha256": self.spec_sha256,
            "rules": [rule.to_dict() for rule in self.rules],
        }
        payload["evaluation_sha256"] = _canonical_digest(payload)
        return payload

    def save(self, path: str | Path) -> None:
        _atomic_write_json(Path(path), self.to_dict())


class TargetStateOracle:
    """Evaluate an explicit, analyst-defined target against iteration artifacts.

    The oracle is deliberately not a main-loop detector by default.  It only
    reports success when a versioned target specification supplied by the
    analyst is satisfied.  Heuristic rules such as repeated syscall sequences
    are therefore claims encoded in the experiment configuration, not hidden
    assumptions in the implementation.
    """

    def evaluate(
        self,
        run_dir: str | Path,
        spec: TargetStateSpec | str | Path,
    ) -> TargetStateEvaluation:
        root = Path(run_dir).resolve(strict=False)
        _validate_directory(root, "iteration run directory")
        target = TargetStateSpec.load(spec) if not isinstance(spec, TargetStateSpec) else spec

        evaluations = tuple(self._evaluate_rule(root, rule) for rule in target.rules)
        matched = sum(1 for item in evaluations if item.matched)
        reached = matched >= target.min_satisfied
        matched_ids = [item.rule_id for item in evaluations if item.matched]
        if reached:
            reason = (
                f"target {target.goal_id!r} satisfied: {matched}/"
                f"{len(evaluations)} rules matched"
            )
            if matched_ids:
                reason += " (" + ", ".join(matched_ids) + ")"
        else:
            missing = [item.rule_id for item in evaluations if not item.matched]
            reason = (
                f"target {target.goal_id!r} not satisfied: {matched}/"
                f"{len(evaluations)} rules matched; requires "
                f"{target.min_satisfied}"
            )
            if missing:
                reason += "; unmatched: " + ", ".join(missing)

        return TargetStateEvaluation(
            goal_id=target.goal_id,
            description=target.description,
            reached=reached,
            reason=reason,
            mode=target.mode.value,
            min_satisfied=target.min_satisfied,
            matched_rules=matched,
            total_rules=len(evaluations),
            spec_sha256=target.source_sha256,
            rules=evaluations,
        )

    def _evaluate_rule(self, root: Path, rule: TargetRule) -> RuleEvaluation:
        if rule.rule_type == RuleType.EVENT_COUNT:
            return self._event_count(root, rule)
        if rule.rule_type == RuleType.REPEATED_SEQUENCE:
            return self._repeated_sequence(root, rule)
        if rule.rule_type == RuleType.TEXT_CONTAINS:
            return self._text_contains(root, rule)
        if rule.rule_type == RuleType.JSON_FIELD_EQUALS:
            return self._json_field_equals(root, rule)
        raise TargetStateError(f"unsupported target rule type: {rule.rule_type}")

    def _event_count(self, root: Path, rule: TargetRule) -> RuleEvaluation:
        path = _source_path(root, _EVENT_SOURCES, rule.source)
        minimum = int(rule.parameters["min_count"])
        where = dict(rule.parameters["where"])
        events = _read_jsonl_optional(path)
        if rule.source == "syscall":
            events = [normalize_syscall_event(event) for event in events]
        if rule.source == "syscall" and "execution_context" not in where:
            where["execution_context"] = "guest"
        matches = [event for event in events if _matches(event, where)]
        evidence = tuple(
            _evidence_event(index, event)
            for index, event in enumerate(matches[:_MAX_EVIDENCE_ITEMS])
        )
        return RuleEvaluation(
            rule_id=rule.rule_id,
            rule_type=rule.rule_type.value,
            matched=len(matches) >= minimum,
            observed_count=len(matches),
            required_count=minimum,
            summary=(
                f"observed {len(matches)} matching {rule.source} events; "
                f"requires {minimum}"
            ),
            evidence=evidence,
        )

    def _repeated_sequence(self, root: Path, rule: TargetRule) -> RuleEvaluation:
        path = _source_path(root, _EVENT_SOURCES, rule.source)
        events = list(_read_jsonl_optional(path))
        if rule.source == "syscall":
            events = [normalize_syscall_event(event) for event in events
                      if event.get("execution_context") == "guest"]
        sequence = list(rule.parameters["sequence"])
        minimum = int(rule.parameters["min_repeats"])
        max_gap = int(rule.parameters["max_gap"])
        repeats, spans = _count_sequence_repeats(events, sequence, max_gap=max_gap)
        evidence = tuple(
            {
                "start_index": start,
                "end_index": end,
                "length": end - start + 1,
            }
            for start, end in spans[:_MAX_EVIDENCE_ITEMS]
        )
        return RuleEvaluation(
            rule_id=rule.rule_id,
            rule_type=rule.rule_type.value,
            matched=repeats >= minimum,
            observed_count=repeats,
            required_count=minimum,
            summary=(
                f"observed sequence {repeats} times in {rule.source} events; "
                f"requires {minimum}, max_gap={max_gap}"
            ),
            evidence=evidence,
        )

    def _text_contains(self, root: Path, rule: TargetRule) -> RuleEvaluation:
        path = _source_path(root, _TEXT_SOURCES, rule.source)
        minimum = int(rule.parameters["min_count"])
        needle = str(rule.parameters["needle"])
        if not path.exists():
            count = 0
            snippets: tuple[dict[str, Any], ...] = ()
        else:
            _validate_regular_file(path, f"target text source {rule.source}")
            data = _read_limited(path, _MAX_TEXT_BYTES, f"target text source {rule.source}")
            text = data.decode("utf-8", errors="replace")
            count = text.count(needle)
            snippets = tuple(
                {"line": number, "text": line[:512]}
                for number, line in enumerate(text.splitlines(), 1)
                if needle in line
            )[:_MAX_EVIDENCE_ITEMS]
        return RuleEvaluation(
            rule_id=rule.rule_id,
            rule_type=rule.rule_type.value,
            matched=count >= minimum,
            observed_count=count,
            required_count=minimum,
            summary=f"found text marker {count} times; requires {minimum}",
            evidence=snippets,
        )

    def _json_field_equals(self, root: Path, rule: TargetRule) -> RuleEvaluation:
        path = _source_path(root, _JSON_ARTIFACTS, rule.source)
        expected = rule.parameters["equals"]
        field_path = str(rule.parameters["field"])
        if not path.exists():
            found = False
            actual: Any = None
        else:
            raw = _load_json_object(path, f"target JSON source {rule.source}")
            found, actual = _lookup_field(raw, field_path)
        matched = found and actual == expected
        evidence = (
            {
                "artifact": str(path.relative_to(root)),
                "field": field_path,
                "actual": actual,
                "expected": expected,
                "field_present": found,
            },
        )
        return RuleEvaluation(
            rule_id=rule.rule_id,
            rule_type=rule.rule_type.value,
            matched=matched,
            observed_count=1 if matched else 0,
            required_count=1,
            summary=(
                f"JSON field {field_path!r} "
                + ("matched expected value" if matched else "did not match expected value")
            ),
            evidence=evidence,
        )


def _parse_rule(raw: Any, index: int) -> TargetRule:
    if not isinstance(raw, dict):
        raise TargetStateError(f"rules[{index}] must be an object")
    rule_id = _identifier(raw.get("id"), f"rules[{index}].id")
    description_raw = raw.get("description")
    description = None if description_raw is None else _bounded_string(
        description_raw,
        f"rules[{index}].description",
    )
    try:
        rule_type = RuleType(raw.get("type"))
    except ValueError as exc:
        raise TargetStateError(f"invalid rules[{index}].type") from exc
    source = _identifier(raw.get("source"), f"rules[{index}].source")

    if rule_type == RuleType.EVENT_COUNT:
        if source not in _EVENT_SOURCES:
            raise TargetStateError(f"rules[{index}] has invalid event source")
        where = _where(raw.get("where", {}), f"rules[{index}].where")
        minimum = _positive_int(raw.get("min_count", 1), f"rules[{index}].min_count")
        parameters = {"where": where, "min_count": minimum}
    elif rule_type == RuleType.REPEATED_SEQUENCE:
        if source not in _EVENT_SOURCES:
            raise TargetStateError(f"rules[{index}] has invalid event source")
        sequence_raw = raw.get("sequence")
        if not isinstance(sequence_raw, list) or not sequence_raw:
            raise TargetStateError(f"rules[{index}].sequence must be non-empty")
        if len(sequence_raw) > 32:
            raise TargetStateError(f"rules[{index}].sequence is too long")
        sequence = [
            _where(item, f"rules[{index}].sequence[{offset}]")
            for offset, item in enumerate(sequence_raw)
        ]
        minimum = _positive_int(raw.get("min_repeats", 2), f"rules[{index}].min_repeats")
        max_gap = _nonnegative_int(raw.get("max_gap", 0), f"rules[{index}].max_gap")
        if max_gap > 1024:
            raise TargetStateError(f"rules[{index}].max_gap is too large")
        parameters = {
            "sequence": sequence,
            "min_repeats": minimum,
            "max_gap": max_gap,
        }
    elif rule_type == RuleType.TEXT_CONTAINS:
        if source not in _TEXT_SOURCES:
            raise TargetStateError(f"rules[{index}] has invalid text source")
        needle = _bounded_string(raw.get("needle"), f"rules[{index}].needle")
        if not needle:
            raise TargetStateError(f"rules[{index}].needle must not be empty")
        minimum = _positive_int(raw.get("min_count", 1), f"rules[{index}].min_count")
        parameters = {"needle": needle, "min_count": minimum}
    else:
        if source not in _JSON_ARTIFACTS:
            raise TargetStateError(f"rules[{index}] has invalid JSON artifact source")
        field_path = _bounded_string(raw.get("field"), f"rules[{index}].field")
        _validate_field_path(field_path, f"rules[{index}].field")
        if "equals" not in raw:
            raise TargetStateError(f"rules[{index}].equals is required")
        expected = raw["equals"]
        if not _json_scalar(expected):
            raise TargetStateError(f"rules[{index}].equals must be a JSON scalar")
        parameters = {"field": field_path, "equals": expected}

    return TargetRule(
        rule_id=rule_id,
        rule_type=rule_type,
        source=source,
        parameters=parameters,
        description=description,
    )


def _count_sequence_repeats(
    events: list[dict[str, Any]],
    sequence: list[dict[str, Any]],
    *,
    max_gap: int,
) -> tuple[int, list[tuple[int, int]]]:
    repeats = 0
    spans: list[tuple[int, int]] = []
    cursor = 0
    while cursor < len(events):
        start = _find_match(events, sequence[0], cursor, len(events))
        if start is None:
            break
        previous = start
        matched = True
        for expected in sequence[1:]:
            upper = min(len(events), previous + max_gap + 2)
            found = _find_match(events, expected, previous + 1, upper)
            if found is None:
                matched = False
                break
            previous = found
        if matched:
            repeats += 1
            spans.append((start, previous))
            cursor = previous + 1
        else:
            cursor = start + 1
    return repeats, spans


def _find_match(
    events: list[dict[str, Any]],
    expected: dict[str, Any],
    start: int,
    end: int,
) -> int | None:
    for index in range(start, end):
        if _matches(events[index], expected):
            return index
    return None


def _matches(event: dict[str, Any], where: dict[str, Any]) -> bool:
    # JSON true/false must not match Python's numerically equal 1/0.
    return all(
        (event.get(key) is value if isinstance(value, bool) else event.get(key) == value)
        for key, value in where.items()
    )


def _source_path(root: Path, mapping: dict[str, str], source: str) -> Path:
    relative = mapping[source]
    path = root / relative
    resolved_parent = path.parent.resolve(strict=False)
    if not _is_relative_to(resolved_parent, root):
        raise TargetStateError("target evidence path escapes run directory")
    return path


def _read_jsonl_optional(path: Path) -> Iterable[dict[str, Any]]:
    if not path.exists():
        return ()
    _validate_regular_file(path, "target JSONL evidence")
    if path.stat().st_size > _MAX_EVIDENCE_FILE_BYTES:
        raise TargetStateError(f"target evidence file is too large: {path}")
    result: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, 1):
            if not line.strip():
                continue
            try:
                raw = json.loads(line)
            except json.JSONDecodeError as exc:
                raise TargetStateError(
                    f"invalid JSONL evidence at {path}:{line_number}: {exc}"
                ) from exc
            if not isinstance(raw, dict):
                raise TargetStateError(
                    f"JSONL evidence entry must be an object at {path}:{line_number}"
                )
            result.append(raw)
    return result


def _evidence_event(index: int, event: dict[str, Any]) -> dict[str, Any]:
    allowed = (
        "event",
        "execution_context",
        "syscall",
        "success",
        "return_value",
        "result",
        "errno",
        "source_file",
        "line_number",
        "pid",
        "path",
        "remote_ip",
        "remote_port",
        "original_remote_ip",
        "original_remote_port",
        "address",
        "pc",
        "signal",
    )
    return {"index": index, **{key: event.get(key) for key in allowed if key in event}}


def _lookup_field(raw: dict[str, Any], field_path: str) -> tuple[bool, Any]:
    value: Any = raw
    for part in field_path.split("."):
        if not isinstance(value, dict) or part not in value:
            return False, None
        value = value[part]
    return True, value


def _validate_field_path(value: str, label: str) -> None:
    parts = value.split(".")
    if not parts or any(not part or not part.replace("_", "a").isalnum() for part in parts):
        raise TargetStateError(f"{label} is invalid")


def _where(raw: Any, label: str) -> dict[str, Any]:
    if not isinstance(raw, dict) or not raw:
        raise TargetStateError(f"{label} must be a non-empty object")
    if len(raw) > 32:
        raise TargetStateError(f"{label} contains too many fields")
    result: dict[str, Any] = {}
    for key, value in raw.items():
        if not isinstance(key, str) or not key or len(key) > 128:
            raise TargetStateError(f"{label} contains an invalid field name")
        if not _json_scalar(value):
            raise TargetStateError(f"{label}.{key} must be a JSON scalar")
        result[key] = value
    return result


def _json_scalar(value: Any) -> bool:
    return value is None or isinstance(value, (str, int, float, bool))


def _identifier(value: Any, label: str) -> str:
    text = _bounded_string(value, label)
    if not text or len(text) > 128:
        raise TargetStateError(f"{label} is invalid")
    if not all(character.isalnum() or character in "_-.:" for character in text):
        raise TargetStateError(f"{label} contains unsupported characters")
    return text


def _bounded_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or "\x00" in value or len(value) > _MAX_STRING:
        raise TargetStateError(f"{label} must be a bounded string")
    return value


def _positive_int(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise TargetStateError(f"{label} must be a positive integer")
    return value


def _nonnegative_int(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise TargetStateError(f"{label} must be a non-negative integer")
    return value


def _read_limited(path: Path, limit: int, label: str) -> bytes:
    size = path.stat().st_size
    if size > limit:
        raise TargetStateError(f"{label} exceeds {limit} bytes: {path}")
    return path.read_bytes()


def _load_json_object(path: Path, label: str) -> dict[str, Any]:
    _validate_regular_file(path, label)
    data = _read_limited(path, _MAX_EVIDENCE_FILE_BYTES, label)
    try:
        raw = json.loads(data)
    except json.JSONDecodeError as exc:
        raise TargetStateError(f"invalid JSON in {label}: {exc}") from exc
    if not isinstance(raw, dict):
        raise TargetStateError(f"{label} must be an object")
    return raw


def _validate_directory(path: Path, label: str) -> None:
    if path.is_symlink() or not path.is_dir():
        raise TargetStateError(f"{label} is invalid: {path}")


def _validate_regular_file(path: Path, label: str) -> None:
    if path.is_symlink() or not path.is_file():
        raise TargetStateError(f"{label} is not a regular file: {path}")


def _canonical_digest(raw: Any) -> str:
    payload = json.dumps(
        raw,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise TargetStateError(f"refusing to replace symlink: {path}")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(payload, stream, indent=2, ensure_ascii=False, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False
