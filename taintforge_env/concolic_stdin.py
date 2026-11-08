"""Invert a branch through selected bytes of regular-file stdin.

The default profile binds one completed i386 read from fd 0 to guest memory.
The opt-in sequence profile models one to four reads chronologically from the
first read boundary, including computations between reads. Taint labels cannot
establish either source relation. Only an actual second execution can promote
a boundary witness to VERIFIED.
"""
from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path
import subprocess
from typing import Any, Sequence

from .concolic_file import (
    ConcolicError, _digest, _elf, _execute, _integer, _regular, _unique,
    validate_prefix, verify_prefixes,
)
from .phase1_runtime import Phase1Runtime


MAX_FILE_BYTES = 1024 * 1024
MAX_READ_BYTES = 4096
MAX_MUTABLE_BYTES = 16
MAX_SEQUENCE_READS = 4


def _selection(offsets: Sequence[int], size: int) -> tuple[int, ...]:
    if isinstance(offsets, (str, bytes, bytearray)) or not isinstance(offsets, Sequence):
        raise ConcolicError("selected offsets must be a sequence of integers")
    selected = tuple(offsets)
    if (not 1 <= len(selected) <= MAX_MUTABLE_BYTES or
            any(not _integer(offset, size - 1) for offset in selected) or
            selected != tuple(sorted(set(selected)))):
        raise ConcolicError("select 1..16 distinct, increasing stdin file offsets")
    return selected


def _load_report(path: Path) -> dict[str, Any]:
    _regular(path, 1024 * 1024)

    def nonfinite(value: str) -> None:
        raise ConcolicError("non-finite value in concolic report: " + value)

    result = json.loads(path.read_text(), object_pairs_hook=_unique, parse_constant=nonfinite)
    if (not isinstance(result, dict) or type(result.get("schema")) is not int or
            result["schema"] not in (3, 4) or result.get("status") not in
            ("UNKNOWN", "UNSAT", "BOUNDARY_WITNESS", "OBSERVED")):
        raise ConcolicError("invalid stdin concolic report")
    return result


def validate_stdin_observation(report: dict[str, Any], raw: bytes, offsets: Sequence[int],
                               pc: int, occurrence: int, max_steps: int) -> list[dict[str, Any]]:
    """Bind the complete source file and selected offsets to one observed read."""
    selected = _selection(offsets, len(raw))
    file = report.get("stdin_file")
    if (type(report.get("schema")) is not int or report["schema"] != 3 or
            report.get("status") not in ("BOUNDARY_WITNESS", "OBSERVED", "UNSAT") or
            report.get("relation") != "stdin_read_span_identity" or
            report.get("host_identity_verified") is not True or
            not isinstance(file, dict) or type(file.get("size")) is not int or
            file != {"size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()} or
            not 0 < len(raw) <= MAX_FILE_BYTES or
            type(report.get("fd")) is not int or report["fd"] != 0 or
            type(report.get("read_offset")) is not int or report["read_offset"] != 0 or
            not _integer(report.get("read_size"), MAX_READ_BYTES) or not report["read_size"] or
            not _integer(report.get("requested"), MAX_READ_BYTES) or not report["requested"] or
            report["read_size"] > min(report["requested"], len(raw)) or
            not _integer(report.get("address"), 0xffffffff) or
            report["address"] + report["read_size"] > 1 << 32 or
            type(report.get("target_known")) is not bool):
        raise ConcolicError("stdin file/read identity missing")
    trace = validate_prefix(report, pc, occurrence, max_steps)
    bindings = report.get("bindings")
    if not isinstance(bindings, list) or len(bindings) != len(selected):
        raise ConcolicError("stdin input bindings missing")
    used = set()
    for offset, row in zip(selected, bindings):
        if (not isinstance(row, dict) or not _integer(row.get("offset"), len(raw) - 1) or
                row["offset"] != offset or offset >= report["read_size"] or
                not _integer(row.get("address"), 0xffffffff) or
                row["address"] != report["address"] + offset or
                not _integer(row.get("byte"), 255) or row["byte"] != raw[offset] or
                not _integer(row.get("candidate"), 255) or
                not _integer(row.get("input_id"), 0xffffffff)):
            raise ConcolicError("stdin byte binding mismatch")
        if row["input_id"]:
            if row["input_id"] in used:
                raise ConcolicError("duplicate stdin boundary input")
            used.add(row["input_id"])
        elif row["candidate"] != row["byte"]:
            raise ConcolicError("unused stdin input byte changed")
        if report["status"] in ("OBSERVED", "UNSAT") and row["candidate"] != row["byte"]:
            raise ConcolicError("report contains an unexecuted assignment")
    if not used:
        raise ConcolicError("no observed stdin boundary input")
    events = report.get("syscalls")
    if not isinstance(events, list) or len(events) != 1 or not isinstance(events[0], dict):
        raise ConcolicError("stdin needs exactly one observed read syscall")
    event = events[0]
    args = event.get("args")
    if (not _integer(event.get("seq")) or event["seq"] != report["read_seq"] or
            not _integer(event.get("number"), 0xffffffff) or event["number"] != 3 or
            not isinstance(args, list) or len(args) != 6 or
            any(not _integer(value, 0xffffffff) for value in args) or
            args[:3] != [0, report["address"], report["requested"]] or
            not _integer(event.get("result"), MAX_READ_BYTES) or
            event["result"] != report["read_size"] or
            [row["instruction"]["seq"] for row in trace
             if row["instruction"]["bytes"] == "cd80"] != [event["seq"]]):
        raise ConcolicError("stdin read syscall evidence differs")
    return trace


def validate_stdin_sequence_observation(report: dict[str, Any], raw: bytes,
                                        offsets: Sequence[int], pc: int,
                                        occurrence: int, max_steps: int) -> list[dict[str, Any]]:
    """Bind every read occurrence to one immutable, sequential source file.

    A selected byte denotes a file offset, rather than a guest address. Each
    positive read delivers the next source interval; overlapping guest buffers
    remain distinct chronological effects of those source values.
    """
    selected = _selection(offsets, len(raw))
    file = report.get("stdin_file")
    reads = report.get("reads")
    if (type(report.get("schema")) is not int or report["schema"] != 4 or
            report.get("status") not in ("BOUNDARY_WITNESS", "OBSERVED", "UNSAT") or
            report.get("relation") != "stdin_read_sequence_identity" or
            report.get("host_identity_verified") is not True or
            not isinstance(file, dict) or type(file.get("size")) is not int or
            file != {"size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()} or
            not 0 < len(raw) <= MAX_FILE_BYTES or
            type(report.get("fd")) is not int or report["fd"] != 0 or
            type(report.get("max_reads")) is not int or report["max_reads"] != MAX_SEQUENCE_READS or
            not _integer(report.get("read_count"), MAX_SEQUENCE_READS) or not report["read_count"] or
            not isinstance(reads, list) or len(reads) != report["read_count"] or
            type(report.get("target_known")) is not bool):
        raise ConcolicError("stdin sequence file/read identity missing")
    trace = validate_prefix(report, pc, occurrence, max_steps)
    cursor, previous = 0, 0
    for row in reads:
        if (not isinstance(row, dict) or
                not _integer(row.get("seq")) or row["seq"] <= previous or
                not _integer(row.get("read_offset"), len(raw)) or row["read_offset"] != cursor or
                not _integer(row.get("address"), 0xffffffff) or
                not _integer(row.get("requested"), MAX_READ_BYTES) or not row["requested"] or
                not _integer(row.get("read_size"), MAX_READ_BYTES) or
                row["read_size"] > min(row["requested"], len(raw) - cursor) or
                row["address"] + row["requested"] > 1 << 32):
            raise ConcolicError("stdin chronological read geometry differs")
        cursor += row["read_size"]
        previous = row["seq"]
    if report["read_seq"] != reads[0]["seq"] or report["address"] != reads[0]["address"]:
        raise ConcolicError("stdin first read boundary differs")
    bindings = report.get("bindings")
    if not isinstance(bindings, list) or len(bindings) != len(selected):
        raise ConcolicError("stdin source input bindings missing")
    used = set()
    for offset, row in zip(selected, bindings):
        if (not isinstance(row, dict) or
                not _integer(row.get("offset"), len(raw) - 1) or row["offset"] != offset or
                offset >= cursor or
                not _integer(row.get("byte"), 255) or row["byte"] != raw[offset] or
                not _integer(row.get("candidate"), 255) or
                not _integer(row.get("input_id"), 0xffffffff)):
            raise ConcolicError("stdin source byte binding mismatch")
        if row["input_id"]:
            if row["input_id"] in used:
                raise ConcolicError("duplicate stdin source input")
            used.add(row["input_id"])
        elif row["candidate"] != row["byte"]:
            raise ConcolicError("unused stdin source byte changed")
        if report["status"] in ("OBSERVED", "UNSAT") and row["candidate"] != row["byte"]:
            raise ConcolicError("report contains an unexecuted assignment")
    if not used:
        raise ConcolicError("no observed stdin source input")
    events = report.get("syscalls")
    if not isinstance(events, list) or len(events) != len(reads):
        raise ConcolicError("stdin sequence syscall ledger missing")
    for read, event in zip(reads, events):
        if not isinstance(event, dict):
            raise ConcolicError("invalid stdin read syscall")
        args = event.get("args")
        if (not _integer(event.get("seq")) or event["seq"] != read["seq"] or
                not _integer(event.get("number"), 0xffffffff) or event["number"] != 3 or
                not isinstance(args, list) or len(args) != 6 or
                any(not _integer(value, 0xffffffff) for value in args) or
                args[:3] != [0, read["address"], read["requested"]] or
                not _integer(event.get("result"), MAX_READ_BYTES) or
                event["result"] != read["read_size"]):
            raise ConcolicError("stdin sequence syscall evidence differs")
    if [row["instruction"]["seq"] for row in trace
            if row["instruction"]["bytes"] == "cd80"] != [row["seq"] for row in reads]:
        raise ConcolicError("stdin sequence does not cover every trace syscall")
    return trace


def _observed_calls(report: dict[str, Any], trace: list[dict[str, Any]]) -> list[tuple[Any, ...]]:
    ordinal = {row["instruction"]["seq"]: index for index, row in enumerate(trace)}
    # INT 80 read consumes EBX/ECX/EDX. ESI/EDI/EBP may carry symbolic
    # application values across a read and are not read arguments.
    return [(ordinal[event["seq"]], event["number"], event["args"][:3], event["result"])
            for event in report["syscalls"]]


def verify_stdin_sequence_rerun(baseline: dict[str, Any], rerun: dict[str, Any], seed: bytes,
                                candidate: bytes, offsets: Sequence[int], pc: int,
                                occurrence: int, max_steps: int) -> dict[str, Any]:
    """Accept a sequence witness only after a matching external execution."""
    if baseline.get("status") != "BOUNDARY_WITNESS" or rerun.get("status") != "OBSERVED":
        raise ConcolicError("stdin sequence requires a witness and an observed rerun")
    if len(candidate) != len(seed) or candidate == seed:
        raise ConcolicError("invalid or unchanged stdin candidate")
    first = validate_stdin_sequence_observation(baseline, seed, offsets, pc, occurrence, max_steps)
    second = validate_stdin_sequence_observation(rerun, candidate, offsets, pc, occurrence, max_steps)
    expected = bytearray(seed)
    for row in baseline["bindings"]:
        expected[row["offset"]] = row["candidate"]
    if candidate != bytes(expected):
        raise ConcolicError("materialized stdin does not match the source model")
    if any(baseline[key] != rerun[key] for key in ("fd", "read_count", "max_reads")):
        raise ConcolicError("stdin read count changed between runs")
    fields = ("address", "read_offset", "read_size", "requested")
    if [tuple(row[key] for key in fields) for row in baseline["reads"]] != [
            tuple(row[key] for key in fields) for row in rerun["reads"]]:
        raise ConcolicError("stdin read sequence geometry changed between runs")
    if [(row["offset"], row["input_id"]) for row in baseline["bindings"]] != [
            (row["offset"], row["input_id"]) for row in rerun["bindings"]]:
        raise ConcolicError("stdin source catalogue changed")
    if _observed_calls(baseline, first) != _observed_calls(rerun, second):
        raise ConcolicError("stdin sequence syscall effects changed between runs")
    edge = verify_prefixes(baseline, rerun, first, second, pc)
    edge.update(evidence="stdin_sequence_external_rerun", resource_id="stdin:regular_file")
    return edge


def materialize_stdin(seed: Path, expected_sha256: str, offsets: Sequence[int],
                      assignments: Sequence[tuple[int, int]], destination: Path) -> None:
    """Write exactly the selected assignments into an exclusive full-file copy."""
    seed = _regular(seed, MAX_FILE_BYTES)
    raw = seed.read_bytes()
    selected = _selection(offsets, len(raw))
    if not raw or hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise ConcolicError("stdin seed changed")
    assignments = tuple(assignments)
    if (len(assignments) != len(selected) or
            any(not isinstance(row, (tuple, list)) or len(row) != 2 for row in assignments) or
            tuple(row[0] for row in assignments) != selected or
            any(not _integer(row[0], len(raw) - 1) or not _integer(row[1], 255)
                for row in assignments)):
        raise ConcolicError("assignments do not match selected stdin offsets")
    updated = bytearray(raw)
    for offset, value in assignments:
        updated[offset] = value
    if updated == raw:
        raise ConcolicError("candidate does not change any selected stdin byte")
    with destination.open("xb") as stream:
        stream.write(updated)


def verify_stdin_rerun(baseline: dict[str, Any], rerun: dict[str, Any], seed: bytes,
                       candidate: bytes, offsets: Sequence[int], pc: int, occurrence: int,
                       max_steps: int) -> dict[str, Any]:
    if baseline.get("status") != "BOUNDARY_WITNESS" or rerun.get("status") != "OBSERVED":
        raise ConcolicError("stdin inversion requires a witness and an observed rerun")
    if len(candidate) != len(seed) or candidate == seed:
        raise ConcolicError("invalid or unchanged stdin candidate")
    first = validate_stdin_observation(baseline, seed, offsets, pc, occurrence, max_steps)
    second = validate_stdin_observation(rerun, candidate, offsets, pc, occurrence, max_steps)
    expected = bytearray(seed)
    for row in baseline["bindings"]:
        expected[row["offset"]] = row["candidate"]
    if candidate != bytes(expected):
        raise ConcolicError("materialized stdin does not match the model")
    if any(baseline[key] != rerun[key] for key in ("fd", "read_offset", "read_size", "requested")):
        raise ConcolicError("stdin read geometry changed between runs")
    if [(row["offset"], row["input_id"]) for row in baseline["bindings"]] != [
            (row["offset"], row["input_id"]) for row in rerun["bindings"]]:
        raise ConcolicError("stdin boundary catalogue changed")

    def calls(report: dict[str, Any], trace: list[dict[str, Any]]) -> list[tuple[Any, ...]]:
        ordinal = {row["instruction"]["seq"]: index for index, row in enumerate(trace)}
        return [(ordinal[event["seq"]], event["number"], event["args"], event["result"])
                for event in report["syscalls"]]

    if calls(baseline, first) != calls(rerun, second):
        raise ConcolicError("stdin syscall effects changed between runs")
    edge = verify_prefixes(baseline, rerun, first, second, pc)
    edge.update(evidence="stdin_span_external_rerun", resource_id="stdin:regular_file")
    return edge


def _write(path: Path, value: Any) -> None:
    with path.open("x") as stream:
        json.dump(value, stream, indent=2, allow_nan=False)
        stream.write("\n")


def run_stdin_inversion(*, qemu: Path, plugin: Path, binary: Path, input_file: Path,
                        offsets: Sequence[int], flags_receipt: Path, branch_pc: int,
                        output: Path, occurrence: int = 1, max_steps: int = 256,
                        timeout: float = 30, single_step: bool = False,
                        read_sequence: bool = False) -> dict[str, Any]:
    if (not _integer(branch_pc, 0xffffffff) or not _integer(occurrence, 1024) or not occurrence or
            not _integer(max_steps, 1024) or not max_steps or
            type(timeout) not in (int, float) or not math.isfinite(timeout) or
            not 0 < timeout <= 300 or type(single_step) is not bool or
            type(read_sequence) is not bool):
        raise ConcolicError("invalid branch or execution budget")
    qemu = _regular(qemu, 256 * 1024 * 1024)
    binary = _regular(binary, 64 * 1024 * 1024)
    input_file = _regular(input_file, MAX_FILE_BYTES)
    receipt = _regular(flags_receipt, 4096)
    runtime = Phase1Runtime.load(plugin)
    runtime.validate_qemu(qemu)
    plugin = runtime.plugin
    _elf(binary)
    raw = input_file.read_bytes()
    if not raw:
        raise ConcolicError("stdin seed must contain at least one byte")
    selected = _selection(offsets, len(raw))
    output = output.expanduser().absolute()
    if any("," in str(path) or "\n" in str(path) for path in (output, plugin, receipt)):
        raise ConcolicError("plugin argument paths cannot contain commas or newlines")
    output.mkdir(parents=True, exist_ok=False)
    seed, target = output / "seed.bin", output / "target"
    seed.write_bytes(raw)
    target.write_bytes(binary.read_bytes())
    target.chmod(0o700)
    pinned = {str(path): _digest(path) for path in
              (qemu, plugin, runtime.manifest, binary, input_file, target, seed, receipt)}
    if pinned[str(seed)] != pinned[str(input_file)] or pinned[str(target)] != pinned[str(binary)]:
        raise ConcolicError("source changed while copying the stdin experiment")
    result: dict[str, Any] = {
        "schema": 1, "report_schema": 4 if read_sequence else 3, "status": "UNKNOWN",
        "scope": ("sequential_stdin_reads_selected_file_offsets" if read_sequence else
                  "one_stdin_read_selected_file_offsets"), "artifacts": pinned,
        "branch_pc": branch_pc, "occurrence": occurrence, "offsets": list(selected),
        "complete_cfg": False, "universal_soundness_proven": False,
        "successor_execution_proven": False, "control_channel_protection_verified": False,
        "isolation_verified": False,
    }

    def intact() -> None:
        for path, expected in pinned.items():
            if _digest(Path(path)) != expected:
                raise ConcolicError("pinned artifact changed: " + path)
        Phase1Runtime.load(plugin)

    def execute(mode: str, source: Path) -> dict[str, Any]:
        intact()
        directory = output / mode
        options = [str(plugin), "ir-check=on", "ir-flat-memory=on", "ir-ssa=on",
                   f"ir-report={directory / 'ir.jsonl'}", "runtime-log=summary",
                   f"x86-flags-receipt={receipt}", f"concolic-report={directory / 'concolic.json'}",
                   f"concolic-branch={branch_pc}", f"concolic-occurrence={occurrence}",
                   f"concolic-max-steps={max_steps}", f"concolic-mode={mode}",
                   f"{'concolic-stdin-reads' if read_sequence else 'concolic-stdin'}={source}",
                   "concolic-offsets=" + ":".join(str(offset) for offset in selected)]
        command = [str(qemu), *(["-one-insn-per-tb"] if single_step else []),
                   "-plugin", ",".join(options), str(target)]
        status = _execute(command, source, directory, timeout)
        intact()
        if status != 0:
            raise ConcolicError(f"{mode} guest exited with status {status}")
        report = _load_report(directory / "concolic.json")
        if report["schema"] != (4 if read_sequence else 3):
            raise ConcolicError("stdin report profile differs from the requested mode")
        return report

    validate = validate_stdin_sequence_observation if read_sequence else validate_stdin_observation
    verify = verify_stdin_sequence_rerun if read_sequence else verify_stdin_rerun
    try:
        baseline = execute("solve", seed)
        result["baseline"] = baseline["status"]
        if baseline["status"] == "UNSAT":
            validate(baseline, raw, selected, branch_pc, occurrence, max_steps)
            result.update(status="UNSAT", reason="no_witness_in_selected_model")
        elif baseline["status"] != "BOUNDARY_WITNESS":
            result["reason"] = baseline.get("reason", "baseline_unknown")
        else:
            validate(baseline, raw, selected, branch_pc, occurrence, max_steps)
            candidate = output / "candidate.bin"
            materialize_stdin(seed, pinned[str(seed)], selected,
                              [(row["offset"], row["candidate"]) for row in baseline["bindings"]],
                              candidate)
            pinned[str(candidate)] = _digest(candidate)
            observation = execute("observe", candidate)
            candidate_bytes = candidate.read_bytes()
            edge = verify(baseline, observation, raw, candidate_bytes, selected,
                          branch_pc, occurrence, max_steps)
            intact()
            evidence = {str(output / mode / "concolic.json"):
                        _digest(output / mode / "concolic.json") for mode in ("solve", "observe")}
            edge.update(binary_sha256=pinned[str(target)], candidate_sha256=pinned[str(candidate)],
                        source_sha256=pinned[str(seed)], reports=evidence)
            _write(output / "dcfg_observed_delta.json", {"schema": 1, "edges": [edge]})
            changes = [{"offset": index, "before": before, "after": after}
                       for index, (before, after) in enumerate(zip(raw, candidate_bytes)) if before != after]
            result.update(status="VERIFIED", reason="prefix_preserved_branch_inverted",
                          changes=changes, candidate_file=str(candidate),
                          candidate_sha256=pinned[str(candidate)], observed_edge=edge)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        result.update(status="UNKNOWN", reason=str(error))
    finally:
        _write(output / "result.json", result)
    return result
