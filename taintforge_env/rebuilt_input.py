"""Import a completed unpack run as the executable for environment synthesis."""
import hashlib
import json
from pathlib import Path
import re

from unpacker.mvp.ct_elf import MAX_BYTES
from unpacker.unpack import MAX_INPUT_ELF, STATUS, file_digest, regular
from unpacker.unpack_process import compare_results

from .elf_runtime import copy_file
from .elf_target import inspect_elf_target


def import_rebuilt(directory: Path, destination: Path) -> dict:
    directory = directory.expanduser().resolve(strict=True)
    receipts = {}
    digests = {}
    for name in ("summary", "rebuild", "comparisons"):
        path = regular(directory / (name + ".json"), 32 * 1024**2, name)
        data = path.read_bytes()
        receipts[name] = json.loads(data)
        digests[name] = hashlib.sha256(data).hexdigest()
    summary, rebuild, comparisons = (receipts[key] for key in ("summary", "rebuild", "comparisons"))
    if (not isinstance(summary, dict) or summary.get("schema_version") != 1
            or summary.get("status") != STATUS or summary.get("all_selected_cases_match") is not True):
        raise ValueError("a completed unpack run with matching selected cases is required")
    if not isinstance(rebuild, dict) or rebuild.get("status") != "REBUILT_IMAGE":
        raise ValueError("missing successful reconstruction receipt")
    rebuilt_hash = summary.get("rebuilt_sha256")
    if not isinstance(rebuilt_hash, str) or re.fullmatch(r"[0-9a-f]{64}", rebuilt_hash) is None or rebuild.get("elf_sha256") != rebuilt_hash:
        raise ValueError("unpack summary and reconstruction disagree on rebuilt ELF identity")
    packed_hash = summary.get("packed_sha256")
    packed = regular(directory / "inputs/packed.elf", MAX_INPUT_ELF, "packed input copy")
    if file_digest(packed) != packed_hash:
        raise ValueError("packed input identity differs from the unpack summary")

    artifacts = summary.get("compared_artifacts")
    if (artifacts not in (["packed", "rebuilt"], ["packed", "rebuilt", "original"])
            or summary.get("repetitions_per_artifact") != 2 or not isinstance(comparisons, list)
            or not 1 <= len(comparisons) <= 64 or summary.get("cases") != len(comparisons)
            or summary.get("guest_executions") != len(comparisons) * len(artifacts) * 2):
        raise ValueError("incomplete unpack comparisons")
    case_ids = set()
    for row in comparisons:
        if not isinstance(row, dict) or row.get("matched") is not True or not isinstance(row.get("id"), str) or row["id"] in case_ids:
            raise ValueError("invalid or duplicated comparison case")
        case_ids.add(row["id"])
        runs = row.get("executions")
        if (not isinstance(runs, dict) or set(runs) != set(artifacts)
                or any(not isinstance(group, list) or len(group) != 2 for group in runs.values())
                or not compare_results([item for group in runs.values() for item in group])):
            raise ValueError("cold execution results differ or are incomplete")

    for key, filename, limit in (("report_sha256", "unpacked.json", 4 * 1024**2),
                                 ("dump_sha256", "unpacked.bin", MAX_BYTES)):
        path = regular(directory / "capture" / filename, limit, filename)
        if file_digest(path) != rebuild.get(key):
            raise ValueError("unpack capture changed: " + filename)
    binary = regular(directory / "rebuilt.elf", MAX_BYTES, "rebuilt ELF")
    copy_file(binary, destination, expected=rebuilt_hash, executable=True)
    target = inspect_elf_target(destination)
    size = destination.stat().st_size
    if (target.arch != "i386" or not target.static or target.file_type_id != 2
            or rebuild.get("entry") != hex(target.entry_point) or summary.get("entry") != target.entry_point
            or rebuild.get("elf_bytes") != size or summary.get("reconstructed_elf_bytes") != size):
        raise ValueError("rebuilt ELF entry, size or static i386 profile differs from the receipts")
    return {"source": "rebuilt_elf", "packed_sha256": packed_hash, "rebuilt_sha256": rebuilt_hash,
            "entry": target.entry_point, "cases": len(case_ids), "receipt_sha256": digests,
            "report_sha256": rebuild["report_sha256"], "dump_sha256": rebuild["dump_sha256"]}
