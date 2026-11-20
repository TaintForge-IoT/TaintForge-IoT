from __future__ import annotations

import hashlib
import json
import re
import stat
from dataclasses import replace
from pathlib import Path, PurePosixPath
from typing import Any

from .attempt import (
    AttemptContract,
    AttemptOutcome,
    AttemptResult,
)
from .environment_manifest import (
    EnvironmentManifest,
    EvidenceKind,
    LifecycleScope,
    ManifestConfidence,
    ManifestEntry,
    ManifestEntryStatus,
    ManifestEvidence,
    ManifestResourceKind,
)
from .progress_oracle import (
    IterationObservation,
    ProgressOracleError,
)
from .repair_plan import (
    RepairActionKind,
    RepairDisposition,
    RepairPlan,
    RepairPlanValidationError,
)


class EnvironmentManifestBuilderError(RuntimeError):
    """Raised when runtime repair evidence cannot be represented faithfully."""


def create_seed_environment_manifest(
    *,
    sample_sha256: str,
    rootfs_snapshot_id: str,
) -> EnvironmentManifest:


    return EnvironmentManifest(
        sample_sha256=sample_sha256,
        manifest_version=0,
        rootfs_snapshot_id=rootfs_snapshot_id,
        entries=(),
        created_by_attempt_id="preflight",
        change_reason=(
            "Captured the immutable sparse seed environment before the first packed execution attempt."
        ),
    )


def derive_environment_manifest_from_repair(
    *,
    parent: EnvironmentManifest,
    rootfs_snapshot_id: str,
    rootfs_path: str | Path,
    source_contract: AttemptContract,
    source_result: AttemptResult,
    repair_plan_path: str | Path,
    repair_application_path: str | Path,
    observation_path: str | Path,
) -> EnvironmentManifest:

    if source_contract.sample_sha256 != parent.sample_sha256:
        raise EnvironmentManifestBuilderError(
            "source attempt sample does not match the parent manifest"
        )
    if source_contract.environment_manifest_id != parent.manifest_id:
        raise EnvironmentManifestBuilderError(
            "source attempt does not reference the parent manifest id"
        )
    if (
        source_contract.environment_manifest_version
        != parent.manifest_version
    ):
        raise EnvironmentManifestBuilderError(
            "source attempt does not reference the parent manifest version"
        )
    if source_result.attempt_id != source_contract.attempt_id:
        raise EnvironmentManifestBuilderError(
            "source attempt result id does not match its contract"
        )
    if source_result.contract_sha256 != source_contract.contract_sha256:
        raise EnvironmentManifestBuilderError(
            "source attempt result does not reference the exact contract"
        )
    if source_result.outcome != AttemptOutcome.REPAIR_REQUIRED:
        raise EnvironmentManifestBuilderError(
            "only a repair-required attempt may derive a repaired manifest"
        )

    rootfs = _regular_directory(rootfs_path, "repaired rootfs")
    plan_path = _regular_file(repair_plan_path, "repair plan")
    application_path = _regular_file(
        repair_application_path,
        "repair application",
    )
    observation = _regular_file(observation_path, "attempt observation")
    try:
        plan = RepairPlan.load(plan_path)
    except RepairPlanValidationError as exc:
        raise EnvironmentManifestBuilderError(str(exc)) from exc
    plan_sha256 = _sha256_file(plan_path)
    observation_sha256 = _sha256_file(observation)
    if source_result.progress.observation_sha256 != observation_sha256:
        raise EnvironmentManifestBuilderError(
            "source attempt result does not reference the exact observation"
        )
    try:
        parsed_observation = IterationObservation.load(observation)
    except ProgressOracleError as exc:
        raise EnvironmentManifestBuilderError(str(exc)) from exc
    if parsed_observation.repair_plan_sha256 != plan_sha256:
        raise EnvironmentManifestBuilderError(
            "attempt observation does not reference the exact repair plan"
        )
    if parsed_observation.requirements_sha256 != plan.source_sha256:
        raise EnvironmentManifestBuilderError(
            "attempt observation requirements digest does not match the plan"
        )

    application = _load_json_object(application_path, "repair application")
    if (
        _required_int(application.get("schema_version"), "schema_version")
        != 1
    ):
        raise EnvironmentManifestBuilderError(
            "unsupported repair application schema_version"
        )
    if (
        _required_int(application.get("applier_version"), "applier_version")
        != 1
    ):
        raise EnvironmentManifestBuilderError(
            "unsupported repair application applier_version"
        )
    if (
        application.get("state") != "completed"
        or application.get("dry_run") is not False
    ):
        raise EnvironmentManifestBuilderError(
            "only a completed non-dry-run repair application may derive a "
            "manifest"
        )
    if application.get("plan_sha256") != plan_sha256:
        raise EnvironmentManifestBuilderError(
            "repair application does not reference the exact repair plan"
        )
    if application.get("requirements_sha256") != plan.source_sha256:
        raise EnvironmentManifestBuilderError(
            "repair application requirements digest does not match the plan"
        )

    results = application.get("results")
    if not isinstance(results, list) or not all(
        isinstance(item, dict) for item in results
    ):
        raise EnvironmentManifestBuilderError(
            "repair application results must be a JSON array of objects"
        )
    decisions = {item.decision_id: item for item in plan.decisions}
    application_sha256 = _sha256_file(application_path)
    entries = tuple(parent.entries)
    selected_total = 0
    seen_decisions: set[str] = set()

    for result in sorted(
        results,
        key=lambda item: str(item.get("decision_id") or ""),
    ):
        decision_id = _required_string(
            result.get("decision_id"),
            "decision_id",
        )
        if decision_id in seen_decisions:
            raise EnvironmentManifestBuilderError(
                f"repair application repeats decision {decision_id!r}"
            )
        seen_decisions.add(decision_id)
        decision = decisions.get(decision_id)
        if decision is None:
            raise EnvironmentManifestBuilderError(
                f"repair application references unknown decision {decision_id!r}"
            )
        if result.get("resource") != decision.resource:
            raise EnvironmentManifestBuilderError(
                f"repair resource mismatch for {decision_id}"
            )
        if result.get("action") != decision.action.value:
            raise EnvironmentManifestBuilderError(
                f"repair action mismatch for {decision_id}"
            )
        if result.get("requirement_id") != decision.requirement_id:
            raise EnvironmentManifestBuilderError(
                f"repair requirement mismatch for {decision_id}"
            )
        status = _required_string(result.get("status"), "status")
        if decision.automatic_allowed:
            if decision.disposition != RepairDisposition.AUTO_CANDIDATE:
                raise EnvironmentManifestBuilderError(
                    f"automatic repair {decision_id} is not an auto candidate"
                )
            if status not in {"applied", "already_satisfied"}:
                raise EnvironmentManifestBuilderError(
                    f"completed automatic repair {decision_id} has invalid "
                    "status"
                )
        elif status != "not_selected":
            raise EnvironmentManifestBuilderError(
                f"manual repair {decision_id} was reported as selected"
            )

        if status == "not_selected":
            continue
        selected_total += 1
        if decision.action in {RepairActionKind.CONFIGURE_TCP_SERVICE, RepairActionKind.CONFIGURE_UDP_SERVICE}:
            selection = dict(decision.parameters).get("network_repair")
            if not isinstance(selection, dict) or result.get("network_service") != selection:
                raise EnvironmentManifestBuilderError("network application differs from its exact repair decision")
            from .network_repair import digest, endpoint
            endpoint(decision.resource)
            if selection.get("provider") not in {"replay", "dns_records"}:
                raise EnvironmentManifestBuilderError("unknown network repair provider")
            replacement = ManifestEntry(resource_id="net:" + decision.resource,
                kind=ManifestResourceKind.NETWORK_SERVICE, lifecycle_scope=LifecycleScope.ITERATION_RUNTIME,
                first_seen_stage=source_contract.initial_stage,
                first_seen_attempt_id=source_contract.attempt_id, provider=selection["provider"],
                value_id="service-" + digest(selection)[:24], value_sha256=digest(selection),
                evidence=tuple(sorted((ManifestEvidence(
                    evidence_id=f"{source_contract.attempt_id}:observation", kind=EvidenceKind.RUNTIME_EVENT,
                    attempt_id=source_contract.attempt_id, artifact_sha256=observation_sha256),
                    ManifestEvidence(evidence_id=f"{source_contract.attempt_id}:repair:{decision_id}",
                    kind=EvidenceKind.REPAIR_APPLICATION, attempt_id=source_contract.attempt_id,
                    artifact_sha256=application_sha256)), key=lambda item: item.evidence_id)),
                confidence=ManifestConfidence.HYPOTHESIS, status=ManifestEntryStatus.ACTIVE)
            entries = _merge_entry(entries, replacement)
            continue
        if decision.action != RepairActionKind.CREATE_DIRECTORY:
            raise EnvironmentManifestBuilderError(
                "selected repair action has no manifest mapping: "
                f"{decision.action.value}"
            )

        replacement = _directory_entry(
            rootfs=rootfs,
            contract=source_contract,
            decision_id=decision_id,
            resource=decision.resource,
            parameters=dict(decision.parameters),
            observation_sha256=observation_sha256,
            application_sha256=application_sha256,
        )
        entries = _merge_entry(entries, replacement)

    if seen_decisions != set(decisions):
        missing = sorted(set(decisions) - seen_decisions)
        raise EnvironmentManifestBuilderError(
            "repair application is missing decision results: "
            + ", ".join(missing)
        )
    if selected_total == 0:
        raise EnvironmentManifestBuilderError(
            "completed repair application contains no applied or satisfied "
            "repair"
        )

    return parent.derive(
        rootfs_snapshot_id=rootfs_snapshot_id,
        entries=entries,
        created_by_attempt_id=source_contract.attempt_id,
        change_reason=(
            f"Recorded {selected_total} deterministic repair result(s) from "
            f"{source_contract.attempt_id}."
        ),
    )


def _directory_entry(
    *,
    rootfs: Path,
    contract: AttemptContract,
    decision_id: str,
    resource: str,
    parameters: dict[str, Any],
    observation_sha256: str,
    application_sha256: str,
) -> ManifestEntry:
    mode_raw = parameters.get("mode")
    parents = parameters.get("parents")
    if (
        not isinstance(mode_raw, str)
        or re.fullmatch(r"0?[0-7]{3}", mode_raw) is None
        or parents is not True
    ):
        raise EnvironmentManifestBuilderError(
            f"directory repair {decision_id} lacks exact mode/parents semantics"
        )
    mode = _observed_directory_mode(rootfs, resource, decision_id)
    value_payload = {
        "action": RepairActionKind.CREATE_DIRECTORY.value,
        "mode": mode,
        "parents": True,
        "resource": resource,
    }
    value_sha256 = _canonical_sha256(value_payload)
    evidence = tuple(
        sorted(
            (
                ManifestEvidence(
                    evidence_id=f"{contract.attempt_id}:observation",
                    kind=EvidenceKind.RUNTIME_EVENT,
                    attempt_id=contract.attempt_id,
                    artifact_sha256=observation_sha256,
                ),
                ManifestEvidence(
                    evidence_id=f"{contract.attempt_id}:repair:{decision_id}",
                    kind=EvidenceKind.REPAIR_APPLICATION,
                    attempt_id=contract.attempt_id,
                    artifact_sha256=application_sha256,
                ),
            ),
            key=lambda item: item.evidence_id,
        )
    )
    return ManifestEntry(
        resource_id=f"fs:{resource}",
        kind=ManifestResourceKind.DIRECTORY,
        lifecycle_scope=LifecycleScope.UNKNOWN,
        first_seen_stage=contract.initial_stage,
        first_seen_attempt_id=contract.attempt_id,
        provider="static_directory",
        value_id=f"directory-{mode}-{value_sha256[:12]}",
        value_sha256=value_sha256,
        evidence=evidence,
        confidence=ManifestConfidence.OBSERVED,
        status=ManifestEntryStatus.ACTIVE,
    )


def _merge_entry(
    entries: tuple[ManifestEntry, ...],
    replacement: ManifestEntry,
) -> tuple[ManifestEntry, ...]:
    by_resource = {entry.resource_id: entry for entry in entries}
    existing = by_resource.get(replacement.resource_id)
    if existing is not None:
        evidence = {item.evidence_id: item for item in existing.evidence}
        for item in replacement.evidence:
            previous = evidence.get(item.evidence_id)
            if previous is not None and previous != item:
                raise EnvironmentManifestBuilderError(
                    f"conflicting evidence id {item.evidence_id!r}"
                )
            evidence[item.evidence_id] = item
        same_value = (
            existing.kind == replacement.kind
            and existing.provider == replacement.provider
            and existing.value_sha256 == replacement.value_sha256
        )
        replacement = replace(
            replacement,
            first_seen_stage=existing.first_seen_stage,
            first_seen_attempt_id=existing.first_seen_attempt_id,
            consumer_pc=existing.consumer_pc,
            lifecycle_scope=existing.lifecycle_scope,
            confidence=(
                existing.confidence
                if same_value
                else replacement.confidence
            ),
            status=(existing.status if same_value else replacement.status),
            evidence=tuple(
                sorted(evidence.values(), key=lambda item: item.evidence_id)
            ),
        )
    by_resource[replacement.resource_id] = replacement
    return tuple(
        sorted(by_resource.values(), key=lambda item: item.resource_id)
    )


def _regular_file(path: str | Path, label: str) -> Path:
    raw = Path(path)
    if raw.is_symlink() or not raw.is_file():
        raise EnvironmentManifestBuilderError(f"{label} is invalid: {raw}")
    return raw.resolve(strict=True)


def _regular_directory(path: str | Path, label: str) -> Path:
    raw = Path(path)
    if raw.is_symlink() or not raw.is_dir():
        raise EnvironmentManifestBuilderError(f"{label} is invalid: {raw}")
    return raw.resolve(strict=True)


def _observed_directory_mode(
    rootfs: Path,
    resource: str,
    decision_id: str,
) -> str:
    pure = PurePosixPath(resource)
    if (
        not resource.startswith("/")
        or resource == "/"
        or ".." in pure.parts
        or pure.as_posix() != resource.rstrip("/")
    ):
        raise EnvironmentManifestBuilderError(
            f"directory repair {decision_id} has an invalid guest path"
        )
    current = rootfs
    observed_mode: int | None = None
    for component in pure.parts[1:]:
        current = current / component
        try:
            entry_stat = current.lstat()
        except OSError as exc:
            raise EnvironmentManifestBuilderError(
                f"cannot observe repaired directory {resource}: {exc}"
            ) from exc
        if stat.S_ISLNK(entry_stat.st_mode) or not stat.S_ISDIR(
            entry_stat.st_mode
        ):
            raise EnvironmentManifestBuilderError(
                f"repaired directory is not a real directory: {resource}"
            )
        observed_mode = stat.S_IMODE(entry_stat.st_mode)
    if observed_mode is None:
        raise EnvironmentManifestBuilderError(
            f"directory repair {decision_id} has an empty guest path"
        )
    return f"{observed_mode:04o}"


def _load_json_object(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise EnvironmentManifestBuilderError(f"invalid {label}: {exc}") from exc
    if not isinstance(value, dict):
        raise EnvironmentManifestBuilderError(f"{label} must be a JSON object")
    return value


def _required_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise EnvironmentManifestBuilderError(
            f"{label} must be a non-empty string"
        )
    return value


def _required_int(value: Any, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise EnvironmentManifestBuilderError(f"{label} must be an integer")
    return value


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _canonical_sha256(value: Any) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()
