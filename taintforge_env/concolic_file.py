"""Bounded file-byte inversion followed by an actual QEMU replay.

The first guest syscall must be i386 read(0, address, 1), returning one byte.
The caller supplies a one-byte regular file, static ELF32 and verified plugin.
Provenance labels never establish the byte-to-boundary equality.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import struct
import subprocess
from typing import Any

from .phase1_runtime import Phase1Runtime


class ConcolicError(RuntimeError):
    pass


def _digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def _regular(path: Path, maximum: int) -> Path:
    path = path.expanduser().absolute()
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > maximum:
        raise ConcolicError(f"expected bounded regular file: {path}")
    return path


def _elf(path: Path) -> None:
    with path.open("rb") as stream:
        header = stream.read(52)
        if len(header) != 52 or header[:6] != b"\x7fELF\x01\x01":
            raise ConcolicError("MVP requires a little-endian ELF32")
        kind, machine = struct.unpack_from("<HH", header, 16)
        offset = struct.unpack_from("<I", header, 28)[0]
        size, count = struct.unpack_from("<HH", header, 42)
        if kind != 2 or machine != 3 or size != 32 or not 1 <= count <= 128:
            raise ConcolicError("MVP requires static i386 ET_EXEC")
        stream.seek(offset)
        entries = stream.read(size * count)
        if len(entries) != size * count or any(
            struct.unpack_from("<I", entries, i * size)[0] in (2, 3)
            for i in range(count)
        ):
            raise ConcolicError("dynamic/interpreter ELF is outside this input contract")


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ConcolicError(f"duplicate report key: {key}")
        result[key] = value
    return result


def _load(path: Path) -> dict[str, Any]:
    _regular(path, 1024 * 1024)
    result = json.loads(path.read_text(), object_pairs_hook=_unique)
    if not isinstance(result, dict) or type(result.get("schema")) is not int or result["schema"] != 1:
        raise ConcolicError("invalid concolic report")
    return result


def _integer(value: Any, maximum: int = (1 << 64) - 1) -> bool:
    return type(value) is int and 0 <= value <= maximum


def _instruction(value: Any) -> tuple[int, str, int]:
    if not isinstance(value, dict):
        raise ConcolicError("instruction identity missing")
    if (not _integer(value.get("pc"), 0xffffffff) or value.get("vcpu") != 0 or
            type(value.get("vcpu")) is not int or not _integer(value.get("seq")) or
            not value["seq"] or not _integer(value.get("generation"), 0xffffffff) or
            not _integer(value.get("descriptor")) or not value["descriptor"] or
            not isinstance(value.get("bytes"), str) or
            not re.fullmatch(r"(?:[0-9a-f]{2}){1,15}", value["bytes"])):
        raise ConcolicError("invalid instruction identity")
    # Generations/descriptors/sequences are run-local. Content and execution
    # ordinal are the cross-run key; all original identities remain in reports.
    return value["pc"], value["bytes"], value["vcpu"]


def validate_observation(report: dict[str, Any], expected_byte: int, pc: int,
                         occurrence: int, max_steps: int) -> list[dict[str, Any]]:
    if (type(report.get("schema")) is not int or report["schema"] != 1 or
            report.get("flags_verified") is not True or
            report.get("relation") != "stdin_read_byte_identity" or
            type(report.get("offset")) is not int or report["offset"] != 0 or
            not _integer(report.get("byte"), 255) or report["byte"] != expected_byte or
            not _integer(report.get("branch_pc"), 0xffffffff) or report["branch_pc"] != pc or
            not _integer(report.get("occurrence"), 1024) or report["occurrence"] != occurrence or
            not _integer(report.get("selected_seq")) or
            not _integer(report.get("read_seq")) or not report["read_seq"] or
            not _integer(report.get("address"), 0xffffffff) or
            not _integer(report.get("input_id")) or not report["input_id"] or
            type(report.get("taken")) is not bool or
            not re.fullmatch(r"[0-9a-f]{64}", str(report.get("fixed_inputs_sha256")))):
        raise ConcolicError("input/flags/branch evidence missing")
    return validate_prefix(report, pc, occurrence, max_steps)


def validate_prefix(report: dict[str, Any], pc: int, occurrence: int,
                    max_steps: int) -> list[dict[str, Any]]:
    """Validate the observed route independently of its external input adapter."""
    if (report.get("flags_verified") is not True or
            not _integer(report.get("branch_pc"), 0xffffffff) or report["branch_pc"] != pc or
            not _integer(report.get("occurrence"), 1024) or report["occurrence"] != occurrence or
            not _integer(report.get("selected_seq")) or
            not _integer(report.get("read_seq")) or not report["read_seq"] or
            not _integer(report.get("address"), 0xffffffff) or
            type(report.get("taken")) is not bool or
            not re.fullmatch(r"[0-9a-f]{64}", str(report.get("fixed_inputs_sha256")))):
        raise ConcolicError("flags/branch evidence missing")
    trace = report.get("trace")
    if not isinstance(trace, list) or not 1 <= len(trace) <= max_steps:
        raise ConcolicError("prefix missing or exceeds budget")
    successor = report.get("successor")
    _instruction(successor)
    seen = 0
    read_index = None
    for index, row in enumerate(trace):
        if not isinstance(row, dict):
            raise ConcolicError("invalid prefix row")
        instruction = row.get("instruction")
        _instruction(instruction)
        if not _integer(row.get("branch_outcome"), 2):
            raise ConcolicError("invalid branch outcome")
        if index + 1 < len(trace) and not isinstance(trace[index + 1], dict):
            raise ConcolicError("invalid prefix row")
        following = trace[index + 1].get("instruction") if index + 1 < len(trace) else successor
        _instruction(following)
        if (not _integer(row.get("next_pc"), 0xffffffff) or row["next_pc"] != following["pc"] or
                following["seq"] != instruction["seq"] + 1):
            raise ConcolicError("discontinuous prefix")
        if instruction["seq"] == report["read_seq"]:
            if instruction["bytes"] != "cd80" or read_index is not None:
                raise ConcolicError("read identity mismatch")
            read_index = index
        if instruction["seq"] > report["read_seq"] and instruction["pc"] == pc:
            seen += 1
    last = trace[-1]
    if (read_index is None or read_index == len(trace) - 1 or seen != occurrence or
            last["instruction"]["pc"] != pc or
            last["instruction"]["seq"] != report.get("selected_seq") or
            last["branch_outcome"] != (1 if report["taken"] else 2)):
        raise ConcolicError("selected branch occurrence mismatch")
    edge = report.get("dcfg_edge")
    if (not isinstance(edge, dict) or not _integer(edge.get("id")) or not edge["id"] or
            edge.get("kind") != ("jcc-taken" if report["taken"] else "jcc-fallthrough") or
            not _integer(edge.get("source_pc"), 0xffffffff) or
            edge.get("target_pc") != last["next_pc"] or
            not _integer(edge.get("source_generation"), 0xffffffff) or
            not _integer(edge.get("target_generation"), 0xffffffff)):
        raise ConcolicError("observed DCFG edge missing")
    return trace


def verify_rerun(baseline: dict[str, Any], candidate: dict[str, Any], seed: int,
                 value: int, pc: int, occurrence: int, max_steps: int) -> dict[str, Any]:
    if baseline.get("status") != "BOUNDARY_WITNESS" or candidate.get("status") != "OBSERVED":
        raise ConcolicError("both a boundary witness and an observed rerun are required")
    if (not _integer(value, 255) or value == seed or
            not _integer(baseline.get("candidate"), 255) or baseline["candidate"] != value or
            type(baseline.get("target_known")) is not bool):
        raise ConcolicError("invalid materialized byte")
    first = validate_observation(baseline, seed, pc, occurrence, max_steps)
    second = validate_observation(candidate, value, pc, occurrence, max_steps)
    return verify_prefixes(baseline, candidate, first, second, pc)


def verify_prefixes(baseline: dict[str, Any], candidate: dict[str, Any],
                    first: list[dict[str, Any]], second: list[dict[str, Any]],
                    pc: int) -> dict[str, Any]:
    """Compare validated routes. IDs and generations remain local to each run."""
    if type(baseline.get("target_known")) is not bool:
        raise ConcolicError("prediction evidence missing")
    if len(first) != len(second):
        raise ConcolicError("prefix length diverged")
    for index, (old, new) in enumerate(zip(first, second)):
        if _instruction(old["instruction"]) != _instruction(new["instruction"]):
            raise ConcolicError("prefix instruction identity diverged")
        if index + 1 < len(first) and (old["next_pc"], old["branch_outcome"]) != (
                new["next_pc"], new["branch_outcome"]):
            raise ConcolicError("earlier control flow diverged")
    if (baseline["fixed_inputs_sha256"] != candidate["fixed_inputs_sha256"] or
            baseline["address"] != candidate["address"]):
        raise ConcolicError("fixed boundary inputs diverged")
    if baseline["taken"] == candidate["taken"]:
        raise ConcolicError("selected branch was not inverted")
    if (baseline["target_known"] and
            (not _integer(baseline.get("predicted_target"), 0xffffffff) or
             baseline["predicted_target"] != candidate["successor"]["pc"])):
        raise ConcolicError("observed successor disagrees with prediction")
    return {"kind": candidate["dcfg_edge"]["kind"], "branch_pc": pc,
            "source_pc": candidate["dcfg_edge"]["source_pc"],
            "target_pc": candidate["successor"]["pc"],
            "target_bytes": candidate["successor"]["bytes"],
            "branch_bytes": second[-1]["instruction"]["bytes"],
            "run_local_edge": candidate["dcfg_edge"],
            "branch_origin": second[-1]["instruction"],
            "evidence": "external_input_rerun", "complete_cfg": False}


def materialize(seed: Path, expected_sha256: str, value: int, destination: Path) -> None:
    _regular(seed, 1)
    raw = seed.read_bytes()
    if len(raw) != 1 or hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise ConcolicError("seed file changed")
    if not _integer(value, 255) or raw[0] == value:
        raise ConcolicError("invalid or unchanged candidate byte")
    with destination.open("xb") as stream:
        stream.write(bytes([value]))


def _execute(command: list[str], stdin: Path, directory: Path, timeout: float) -> int:
    directory.mkdir()
    (directory / "command.json").write_text(json.dumps(command, indent=2) + "\n")
    with stdin.open("rb") as source, (directory / "stdout").open("xb") as stdout, (
            directory / "stderr").open("xb") as stderr:
        process = subprocess.Popen(command, stdin=source, stdout=stdout, stderr=stderr,
                                   cwd=directory.parent, start_new_session=True)
        try:
            return process.wait(timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
            raise ConcolicError("guest replay timed out") from exc


def run_file_inversion(*, qemu: Path, plugin: Path, binary: Path, input_file: Path,
                       flags_receipt: Path, branch_pc: int, output: Path,
                       occurrence: int = 1, max_steps: int = 256,
                       timeout: float = 30, single_step: bool = False) -> dict[str, Any]:
    if (not _integer(branch_pc, 0xffffffff) or not _integer(occurrence, 1024) or
            not occurrence or not _integer(max_steps, 1024) or not max_steps or
            not 0 < timeout <= 300):
        raise ConcolicError("invalid branch or execution budget")
    qemu = _regular(qemu, 256 * 1024 * 1024)
    binary = _regular(binary, 64 * 1024 * 1024)
    input_file = _regular(input_file, 1)
    flags_receipt = _regular(flags_receipt, 4096)
    runtime = Phase1Runtime.load(plugin)
    plugin = runtime.plugin
    runtime.validate_qemu(qemu)
    _elf(binary)
    raw = input_file.read_bytes()
    if len(raw) != 1:
        raise ConcolicError("MVP requires exactly one input byte")
    output = output.expanduser().absolute()
    if any("," in str(p) or "\n" in str(p) for p in (output, plugin, flags_receipt)):
        raise ConcolicError("plugin argument paths cannot contain commas or newlines")
    output.mkdir(parents=True, exist_ok=False)
    seed = output / "seed.bin"
    seed.write_bytes(raw)
    target = output / "target"
    target.write_bytes(binary.read_bytes())
    target.chmod(0o700)
    pinned = {str(p): _digest(p) for p in (qemu, plugin, runtime.manifest, target, seed, flags_receipt)}
    result: dict[str, Any] = {"schema": 1, "status": "UNKNOWN", "scope": "one_byte_stdin_prefix",
                              "artifacts": pinned, "branch_pc": branch_pc,
                              "occurrence": occurrence, "complete_cfg": False,
                              "successor_execution_proven": False,
                              "control_channel_protection_verified": False}

    def intact() -> None:
        for name, expected in pinned.items():
            if _digest(Path(name)) != expected:
                raise ConcolicError(f"pinned artifact changed: {name}")
        Phase1Runtime.load(plugin)

    def execute(mode: str, file: Path, value: int) -> dict[str, Any]:
        intact()
        directory = output / mode
        report = directory / "concolic.json"
        options = [str(plugin), "ir-check=on", "ir-flat-memory=on", "ir-ssa=on",
                   f"ir-report={directory / 'ir.jsonl'}", "runtime-log=summary",
                   f"x86-flags-receipt={flags_receipt}", f"concolic-report={report}",
                   f"concolic-branch={branch_pc}", f"concolic-occurrence={occurrence}",
                   f"concolic-max-steps={max_steps}", f"concolic-byte={value}",
                   f"concolic-mode={mode}"]
        command = [str(qemu), *( ["-one-insn-per-tb"] if single_step else []),
                   "-plugin", ",".join(options), str(target)]
        status = _execute(command, file, directory, timeout)
        intact()
        if status != 0:
            raise ConcolicError(f"{mode} guest exited with status {status}")
        return _load(report)

    try:
        baseline = execute("solve", seed, raw[0])
        result["baseline"] = baseline.get("status")
        if baseline.get("status") == "UNSAT":
            result.update(status="UNSAT", reason="no_witness_in_selected_model")
        elif baseline.get("status") != "BOUNDARY_WITNESS":
            result["reason"] = baseline.get("reason", "baseline_unknown")
        else:
            validate_observation(baseline, raw[0], branch_pc, occurrence, max_steps)
            value = baseline.get("candidate")
            candidate = output / "candidate.bin"
            materialize(seed, pinned[str(seed)], value, candidate)
            pinned[str(candidate)] = _digest(candidate)
            observation = execute("observe", candidate, value)
            edge = verify_rerun(baseline, observation, raw[0], value, branch_pc, occurrence, max_steps)
            intact()
            # The live collector has already inserted this edge from execution.
            # Persist a run-qualified delta; never import foreign provenance IDs.
            evidence = {str(output / mode / "concolic.json"):
                        _digest(output / mode / "concolic.json") for mode in ("solve", "observe")}
            edge.update(binary_sha256=pinned[str(target)], candidate_sha256=pinned[str(candidate)],
                        reports=evidence)
            with (output / "dcfg_observed_delta.json").open("x") as stream:
                json.dump({"schema": 1, "edges": [edge]}, stream, indent=2)
                stream.write("\n")
            result.update(status="VERIFIED", reason="prefix_preserved_branch_inverted",
                          original_byte=raw[0], candidate_byte=value,
                          candidate_file=str(candidate), observed_edge=edge)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        result.update(status="UNKNOWN", reason=str(exc))
    finally:
        with (output / "result.json").open("x") as stream:
            json.dump(result, stream, indent=2)
            stream.write("\n")
    return result
