"""File-backed concolic inputs from immutable environment snapshots.

One ordinary file, one read of at most 4096 bytes, and at most 16 mutable
offsets. The standalone adapter uses QEMU's file prefix and is not an isolation
backend. Candidate snapshots can also be consumed by an environment runner.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
import hashlib
import json
import math
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import re
from uuid import uuid4
from typing import Any, Sequence

from .attempt import ExecutionStage
from .concolic_file import (
    ConcolicError, _digest, _elf, _execute, _integer, _regular,
    validate_prefix, verify_prefixes,
)
from .environment_manifest import (
    EnvironmentManifest, EvidenceKind, LifecycleScope, ManifestConfidence,
    ManifestEntry, ManifestEntryStatus, ManifestEvidence, ManifestResourceKind,
    replace_manifest_entry,
)
from .environment_snapshot import (
    EnvironmentSnapshotManifest, EnvironmentSnapshotStore, scan_environment, tree_digest,
)
from .phase1_runtime import Phase1Runtime, read_json


MAX_FILE_BYTES = 1024 * 1024
MAX_MUTABLE_BYTES = 16
MAX_READ_BYTES = 4096


def _guest_path(value: str) -> str:
    if (not isinstance(value, str) or len(value) > 252 or
            not value.startswith("/") or value == "/" or
            str(PurePosixPath(value)) != value or ".." in PurePosixPath(value).parts or
            any(ord(c) < 32 or ord(c) > 126 or c == "," for c in value)):
        raise ConcolicError("file needs a normalized absolute guest path")
    if PurePosixPath(value).parts[1] in {"proc", "sys", "dev", "__taintforge"}:
        raise ConcolicError("special guest resources need a separate input contract")
    return value


@dataclass(frozen=True)
class EnvironmentFile:
    guest_path: str
    offsets: tuple[int, ...]
    size: int
    sha256: str
    snapshot_id: str
    tree_sha256: str

    @property
    def resource_id(self) -> str:
        return "fs:" + self.guest_path

    def to_dict(self) -> dict[str, Any]:
        return {"resource_id": self.resource_id, "guest_path": self.guest_path,
                "offsets": list(self.offsets), "size": self.size, "sha256": self.sha256,
                "snapshot_id": self.snapshot_id, "tree_sha256": self.tree_sha256}


def register_file(store: EnvironmentSnapshotStore, snapshot: str | Path, guest_path: str,
                  offsets: Sequence[int], sample_sha256: str) -> EnvironmentFile:
    guest_path = _guest_path(guest_path)
    selected = tuple(offsets)
    if (not 1 <= len(selected) <= MAX_MUTABLE_BYTES or
            any(not _integer(n, MAX_FILE_BYTES - 1) for n in selected) or
            selected != tuple(sorted(set(selected)))):
        raise ConcolicError("select 1..16 distinct, increasing file offsets")
    manifest = store.verify(snapshot)
    entry = next((e for e in manifest.entries if e.path == guest_path), None)
    if (entry is None or entry.type != "file" or entry.hardlink_group is not None or
            not 0 < entry.size <= MAX_FILE_BYTES or selected[-1] >= entry.size):
        raise ConcolicError("selected resource must be a bounded regular file without aliases")
    # Snapshot scanning never traverses symlinks, so an entry cannot be reached
    # through a symlink parent. Mutating an ELF image is a different experiment.
    source = (store.store_dir / manifest.snapshot_id / "rootfs").joinpath(
        *PurePosixPath(guest_path).parts[1:])
    with source.open("rb") as stream:
        magic = stream.read(4)
    if entry.sha256 == sample_sha256 or magic == b"\x7fELF":
        raise ConcolicError("executable images cannot be mutable file inputs")
    return EnvironmentFile(guest_path, selected, entry.size, entry.sha256,
                           manifest.snapshot_id, manifest.tree_sha256)


def _source_bytes(store: EnvironmentSnapshotStore, source: EnvironmentFile) -> bytes:
    _guest_path(source.guest_path)
    if (not re.fullmatch(r"env_[0-9a-f]{16}", source.snapshot_id) or
            not 1 <= len(source.offsets) <= MAX_MUTABLE_BYTES or
            any(not _integer(n, source.size - 1) for n in source.offsets) or
            source.offsets != tuple(sorted(set(source.offsets)))):
        raise ConcolicError("invalid registered resource")
    manifest = store.verify(source.snapshot_id)
    if manifest.tree_sha256 != source.tree_sha256:
        raise ConcolicError("registered environment changed")
    entry = next((e for e in manifest.entries if e.path == source.guest_path), None)
    if entry is None or entry.type != "file" or entry.hardlink_group is not None:
        raise ConcolicError("registered file identity missing")
    path = (store.store_dir / source.snapshot_id / "rootfs").joinpath(
        *PurePosixPath(source.guest_path).parts[1:])
    _regular(path, MAX_FILE_BYTES)
    raw = path.read_bytes()
    if len(raw) != source.size or hashlib.sha256(raw).hexdigest() != source.sha256:
        raise ConcolicError("registered resource changed")
    return raw


def materialize_environment(store: EnvironmentSnapshotStore, source: EnvironmentFile,
                            assignments: Sequence[tuple[int, int]], destination: Path
                            ) -> tuple[EnvironmentSnapshotManifest, list[dict[str, int]]]:
    """Create a full independent candidate; never mutate the seed or snapshot."""
    raw = _source_bytes(store, source)
    assignments = tuple(assignments)
    if (len(assignments) != len(source.offsets) or
            any(not isinstance(a, (tuple, list)) or len(a) != 2 for a in assignments) or
            tuple(a[0] for a in assignments) != source.offsets or
            any(not _integer(a[0], source.size - 1) or not _integer(a[1], 255)
                for a in assignments)):
        raise ConcolicError("candidate assignments do not match selected offsets")
    updated = bytearray(raw)
    changes = []
    for offset, value in assignments:
        if value != raw[offset]:
            changes.append({"offset": offset, "before": raw[offset], "after": value})
        updated[offset] = value
    if not changes:
        raise ConcolicError("candidate does not change any selected byte")
    destination = destination.absolute()
    if destination.exists() or destination.is_symlink():
        raise ConcolicError("candidate environment already exists")
    store.clone(source.snapshot_id, destination)
    try:
        path = destination.joinpath(*PurePosixPath(source.guest_path).parts[1:])
        mode = path.stat().st_mode & 0o7777
        path.chmod(mode | 0o200)
        try:
            path.write_bytes(updated)
        finally:
            path.chmod(mode)
        original = store.verify(source.snapshot_id)
        candidate = store.capture(destination).manifest
        expected = {e.path: e for e in original.entries}
        for entry in candidate.entries:
            before = expected.pop(entry.path, None)
            if before is None:
                raise ConcolicError("candidate added an unrequested resource")
            if entry.path == source.guest_path:
                if (entry.type != before.type or entry.mode != before.mode or
                        entry.size != before.size or entry.hardlink_group is not None or
                        entry.sha256 != hashlib.sha256(updated).hexdigest()):
                    raise ConcolicError("candidate resource metadata changed")
            elif entry != before:
                raise ConcolicError("candidate changed an unselected resource")
        if expected:
            raise ConcolicError("candidate removed a resource")
        _source_bytes(store, source)
        return candidate, changes
    except Exception:
        shutil.rmtree(destination)
        raise


def validate_file_observation(report: dict[str, Any], source: EnvironmentFile, raw: bytes,
                              pc: int, occurrence: int, max_steps: int) -> list[dict[str, Any]]:
    file = report.get("file")
    if (type(report.get("schema")) is not int or report["schema"] != 2 or
            report.get("relation") != "environment_file_read_identity" or
            report.get("host_identity_verified") is not True or
            not isinstance(file, dict) or type(file.get("size")) is not int or
            file != {"guest_path": source.guest_path, "size": len(raw),
                                   "sha256": hashlib.sha256(raw).hexdigest()} or
            len(raw) != source.size or not _integer(report.get("fd"), 0x7fffffff) or
            not _integer(report.get("read_offset"), len(raw)) or
            not _integer(report.get("read_size"), MAX_READ_BYTES) or not report["read_size"] or
            not _integer(report.get("requested"), MAX_READ_BYTES) or
            report["requested"] < report["read_size"] or
            report["read_offset"] + report["read_size"] > len(raw)):
        raise ConcolicError("file/read identity missing")
    trace = validate_prefix(report, pc, occurrence, max_steps)
    start, size = report["read_offset"], report["read_size"]
    address = report["address"]
    if address + size > 1 << 32:
        raise ConcolicError("read buffer wraps the address space")
    bindings = report.get("bindings")
    if not isinstance(bindings, list) or len(bindings) != len(source.offsets):
        raise ConcolicError("file input bindings missing")
    ids = set()
    for offset, row in zip(source.offsets, bindings):
        if (not isinstance(row, dict) or not _integer(row.get("offset"), len(raw) - 1) or
                row["offset"] != offset or not start <= offset < start + size or
                not _integer(row.get("address"), 0xffffffff) or
                row["address"] != address + offset - start or
                not _integer(row.get("byte"), 255) or row["byte"] != raw[offset] or
                not _integer(row.get("candidate"), 255) or
                not _integer(row.get("input_id"), 0xffffffff)):
            raise ConcolicError("file byte binding mismatch")
        if row["input_id"]:
            if row["input_id"] in ids:
                raise ConcolicError("duplicate boundary input")
            ids.add(row["input_id"])
        elif row["candidate"] != row["byte"]:
            raise ConcolicError("unused input byte changed")
        if report.get("status") == "OBSERVED" and row["candidate"] != row["byte"]:
            raise ConcolicError("observation contains an unexecuted assignment")
    if not ids:
        raise ConcolicError("no observed boundary input")
    events = report.get("syscalls")
    if not isinstance(events, list) or not 2 <= len(events) <= 32:
        raise ConcolicError("file syscall evidence missing")
    syscall_seqs = [row["instruction"]["seq"] for row in trace
                    if row["instruction"]["bytes"] == "cd80"]
    if [e.get("seq") if isinstance(e, dict) else None for e in events] != syscall_seqs:
        raise ConcolicError("file syscall sequence mismatch")
    fd = None
    cursor = 0
    for index, event in enumerate(events):
        args, result, number = event.get("args"), event.get("result"), event.get("number")
        if (not _integer(event.get("seq")) or not event["seq"] or
                not isinstance(args, list) or len(args) != 6 or
                any(not _integer(n, 0xffffffff) for n in args) or
                not _integer(result, 0x7fffffff) or not _integer(number, 0xffffffff)):
            raise ConcolicError("invalid syscall observation")
        if number in (5, 295):
            flags = args[1 if number == 5 else 2]
            if fd is not None or flags & ~0x88000 or (number == 295 and args[0] != 0xffffff9c):
                raise ConcolicError("file open contract mismatch")
            fd, cursor = result, 0
        elif number in (3, 6, 19) and fd is not None and args[0] == fd:
            if number == 6:
                if result:
                    raise ConcolicError("close result mismatch")
                fd = None
            elif number == 19:
                offset = args[1] if args[1] < 1 << 31 else args[1] - (1 << 32)
                if args[2] > 2:
                    raise ConcolicError("seek mode mismatch")
                expected = (0, cursor, len(raw))[args[2]] + offset
                if not 0 <= expected <= 0x7fffffff or expected != result:
                    raise ConcolicError("seek offset mismatch")
                cursor = result
            elif (index != len(events) - 1 or event["seq"] != report["read_seq"] or
                  cursor != start or args[1] != address or args[2] != report["requested"] or
                  result != size or fd != report["fd"]):
                raise ConcolicError("direct read contract mismatch")
        else:
            raise ConcolicError("unsupported syscall in file prefix")
    if events[-1]["number"] != 3:
        raise ConcolicError("file prefix has no completed read")
    return trace


def verify_file_rerun(baseline: dict[str, Any], rerun: dict[str, Any], source: EnvironmentFile,
                      seed: bytes, candidate: bytes, pc: int, occurrence: int,
                      max_steps: int) -> dict[str, Any]:
    if baseline.get("status") != "BOUNDARY_WITNESS" or rerun.get("status") != "OBSERVED":
        raise ConcolicError("file inversion needs a witness and an observed rerun")
    if hashlib.sha256(seed).hexdigest() != source.sha256:
        raise ConcolicError("baseline bytes do not match the registered resource")
    first = validate_file_observation(baseline, source, seed, pc, occurrence, max_steps)
    second = validate_file_observation(rerun, source, candidate, pc, occurrence, max_steps)
    expected = bytearray(seed)
    for row in baseline["bindings"]:
        expected[row["offset"]] = row["candidate"]
    if candidate != bytes(expected) or candidate == seed:
        raise ConcolicError("materialized environment does not match the model")
    if any(baseline[k] != rerun[k] for k in ("read_offset", "read_size", "requested", "fd")):
        raise ConcolicError("file read changed between runs")
    # Match syscall order by instruction ordinal, not by foreign sequence IDs.
    def calls(report, trace):
        ordinal = {row["instruction"]["seq"]: i for i, row in enumerate(trace)}
        return [(ordinal[e["seq"]], e["number"], e["args"], e["result"])
                for e in report["syscalls"]]
    if calls(baseline, first) != calls(rerun, second):
        raise ConcolicError("file syscall effects diverged")
    if [(r["offset"], r["input_id"]) for r in baseline["bindings"]] != [
            (r["offset"], r["input_id"]) for r in rerun["bindings"]]:
        raise ConcolicError("boundary catalogue changed")
    edge = verify_prefixes(baseline, rerun, first, second, pc)
    edge.update(evidence="environment_file_rerun", resource_id=source.resource_id)
    return edge


def _write(path: Path, value: Any) -> None:
    with path.open("x") as stream:
        json.dump(value, stream, indent=2)
        stream.write("\n")


def run_environment_inversion(*, qemu: Path, plugin: Path, binary: Path, rootfs: Path,
                               guest_file: str, offsets: Sequence[int], flags_receipt: Path,
                               branch_pc: int, output: Path, occurrence: int = 1,
                               max_steps: int = 256, timeout: float = 30,
                               single_step: bool = False,
                               environment_manifest: Path | None = None) -> dict[str, Any]:
    if (not _integer(branch_pc, 0xffffffff) or not _integer(occurrence, 1024) or not occurrence or
            not _integer(max_steps, 1024) or not max_steps or
            not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or
            not 0 < timeout <= 300):
        raise ConcolicError("invalid branch or execution budget")
    qemu, binary = _regular(qemu, 256 * 1024 * 1024), _regular(binary, 64 * 1024 * 1024)
    receipt = _regular(flags_receipt, 4096)
    runtime = Phase1Runtime.load(plugin)
    runtime.validate_qemu(qemu)
    _elf(binary)
    rootfs = rootfs.expanduser().absolute()
    output = output.expanduser().absolute()
    if (rootfs.resolve() in (output.resolve(), *output.resolve().parents) or
            output.resolve() in rootfs.resolve().parents):
        raise ConcolicError("output and source environment must be independent directories")
    if any("," in str(p) or "\n" in str(p) for p in (output, runtime.plugin, receipt)):
        raise ConcolicError("plugin argument paths cannot contain commas or newlines")
    output.mkdir(parents=True, exist_ok=False)
    attempt = "concolic-" + uuid4().hex[:16]
    result: dict[str, Any] = {"schema": 1, "status": "UNKNOWN",
        "scope": "one_file_one_read_environment_prefix", "branch_pc": branch_pc,
        "occurrence": occurrence, "complete_cfg": False, "successor_execution_proven": False,
        "control_channel_protection_verified": False, "isolation_verified": False,
        "execution_adapter": "qemu_file_prefix", "attempt_id": attempt}
    try:
        store = EnvironmentSnapshotStore(output / "snapshots")
        captured = store.capture(rootfs)
        sample_hash = _digest(binary)
        source = register_file(store, captured.manifest.snapshot_id, guest_file, offsets, sample_hash)
        raw = _source_bytes(store, source)
        _write(output / "resource.json", source.to_dict())
        parent = (EnvironmentManifest.load(environment_manifest) if environment_manifest else
                  EnvironmentManifest(sample_sha256=sample_hash, manifest_version=0,
                    rootfs_snapshot_id=source.snapshot_id, entries=(),
                    created_by_attempt_id=attempt + "-seed", change_reason="Captured concolic seed environment."))
        if parent.sample_sha256 != sample_hash or parent.rootfs_snapshot_id != source.snapshot_id:
            raise ConcolicError("environment manifest does not describe this sample and snapshot")
        previous = next((e for e in parent.entries if e.resource_id == source.resource_id), None)
        if previous is not None and (previous.kind != ManifestResourceKind.FILE or
                previous.value_sha256 != source.sha256 or previous.status != ManifestEntryStatus.ACTIVE):
            raise ConcolicError("manifest resource does not describe the selected file")
        parent.save(output / "seed_environment_manifest.json")
        target = output / "target"
        target.write_bytes(binary.read_bytes())
        target.chmod(0o700)
        if _digest(target) != sample_hash:
            raise ConcolicError("sample changed while copying")
        stdin = output / "stdin"
        stdin.write_bytes(b"")
        pinned = {str(p): _digest(p) for p in (qemu, runtime.plugin, runtime.manifest,
                                              receipt, target, stdin)}
        result.update(resource=source.to_dict(), artifacts=pinned)
        execution = output / "execution-rootfs"

        def intact():
            for path, expected in pinned.items():
                if _digest(Path(path)) != expected:
                    raise ConcolicError(f"pinned artifact changed: {path}")
            Phase1Runtime.load(runtime.plugin)
            _source_bytes(store, source)

        def execute(mode: str, snapshot: EnvironmentSnapshotManifest):
            intact()
            store.clone(snapshot.snapshot_id, execution)
            directory = output / mode
            resource = execution.joinpath(*PurePosixPath(source.guest_path).parts[1:])
            options = [str(runtime.plugin), "ir-check=on", "ir-flat-memory=on", "ir-ssa=on",
                       f"ir-report={directory / 'ir.jsonl'}", "runtime-log=summary",
                       f"x86-flags-receipt={receipt}", f"concolic-report={directory / 'concolic.json'}",
                       f"concolic-branch={branch_pc}", f"concolic-occurrence={occurrence}",
                       f"concolic-max-steps={max_steps}", f"concolic-mode={mode}",
                       f"concolic-file={source.guest_path}", f"concolic-seed={resource}",
                       "concolic-offsets=" + ":".join(str(n) for n in source.offsets)]
            command = [str(qemu), *(["-one-insn-per-tb"] if single_step else []),
                       "-L", str(execution), "-plugin", ",".join(options), str(target)]
            try:
                status = _execute(command, stdin, directory, timeout)
                intact()
                if tree_digest(scan_environment(execution)) != snapshot.tree_sha256:
                    raise ConcolicError("guest changed the supplied environment")
                result.setdefault("guest_exit_codes", {})[mode] = status
                if status < 0:
                    raise ConcolicError(f"{mode} guest exited with status {status}")
                return read_json(directory / "concolic.json", maximum=1024 * 1024)
            finally:
                # Preserve every executed tree under a distinct name. Each run
                # sees the same pathname, but receives a fresh full copy.
                execution.rename(output / (mode + "-rootfs"))

        baseline = execute("solve", captured.manifest)
        result["baseline"] = baseline.get("status")
        if baseline.get("status") == "UNSAT":
            validate_file_observation(baseline, source, raw, branch_pc, occurrence, max_steps)
            result.update(status="UNSAT", reason="no_witness_in_selected_model")
        elif baseline.get("status") != "BOUNDARY_WITNESS":
            result["reason"] = baseline.get("reason", "baseline_unknown")
        else:
            validate_file_observation(baseline, source, raw, branch_pc, occurrence, max_steps)
            assignments = [(r["offset"], r["candidate"]) for r in baseline["bindings"]]
            candidate, changes = materialize_environment(store, source, assignments,
                                                          output / "candidate-rootfs")
            candidate_bytes = (output / "candidate-rootfs").joinpath(
                *PurePosixPath(source.guest_path).parts[1:]).read_bytes()
            rerun = execute("observe", candidate)
            edge = verify_file_rerun(baseline, rerun, source, raw, candidate_bytes,
                                     branch_pc, occurrence, max_steps)
            intact()
            evidence = {str(output / mode / "concolic.json"): _digest(output / mode / "concolic.json")
                        for mode in ("solve", "observe")}
            edge.update(binary_sha256=sample_hash, seed_snapshot_id=source.snapshot_id,
                        candidate_snapshot_id=candidate.snapshot_id, reports=evidence)
            mutation = {"schema": 1, "resource": source.to_dict(), "changes": changes,
                        "candidate_snapshot_id": candidate.snapshot_id,
                        "candidate_tree_sha256": candidate.tree_sha256,
                        "candidate_sha256": hashlib.sha256(candidate_bytes).hexdigest(),
                        "validation": "prefix_preserved_branch_inverted", "reports": evidence}
            _write(output / "environment_changes.json", mutation)
            entry = ManifestEntry(resource_id=source.resource_id, kind=ManifestResourceKind.FILE,
                lifecycle_scope=LifecycleScope.UNKNOWN, first_seen_stage=ExecutionStage.PRE_OEP_DISCOVERY,
                first_seen_attempt_id=attempt + "-solve", provider="concolic_file",
                value_id="file-" + mutation["candidate_sha256"][:16],
                value_sha256=mutation["candidate_sha256"], confidence=ManifestConfidence.OBSERVED,
                status=ManifestEntryStatus.ACTIVE, consumer_pc=hex(branch_pc), evidence=(
                    ManifestEvidence(evidence_id=attempt + ":file-inversion",
                        kind=EvidenceKind.VALIDATION_RUN, attempt_id=attempt + "-observe",
                        artifact_sha256=_digest(output / "environment_changes.json")),))
            if previous is not None:
                evidence_by_id = {e.evidence_id: e for e in previous.evidence}
                evidence_by_id.update((e.evidence_id, e) for e in entry.evidence)
                entry = replace(entry, lifecycle_scope=previous.lifecycle_scope,
                    first_seen_stage=previous.first_seen_stage,
                    first_seen_attempt_id=previous.first_seen_attempt_id,
                    evidence=tuple(sorted(evidence_by_id.values(), key=lambda e: e.evidence_id)))
            derived = parent.derive(rootfs_snapshot_id=candidate.snapshot_id,
                entries=replace_manifest_entry(parent.entries, entry),
                created_by_attempt_id=attempt + "-observe",
                change_reason="File candidate preserved the prefix and inverted the selected branch.")
            derived.save(output / "candidate_environment_manifest.json")
            _write(output / "dcfg_observed_delta.json", {"schema": 1, "edges": [edge]})
            result.update(status="VERIFIED", reason="prefix_preserved_branch_inverted",
                          changes=changes, candidate_rootfs=str(output / "candidate-rootfs"),
                          candidate_snapshot_id=candidate.snapshot_id,
                          candidate_manifest_id=derived.manifest_id, observed_edge=edge)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        result.update(status="UNKNOWN", reason=str(exc))
    finally:
        _write(output / "result.json", result)
    return result
