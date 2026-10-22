"""Bind live module mappings to saved module bytes."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import stat

from experiments.execution_capsule_probe import controller as probe
from experiments.execution_capsule_retire import controller as maps
from .phase1_runtime import Phase1Runtime, read_json

SCHEMA = 1
IDENTITY = ("session_id", "attempt_id", "analysis_instance_id", "attempt_contract_sha256", "bundle_sha256")


class EvidenceInconclusive(RuntimeError):
    """A legacy run lacks the observations required for portable verification."""


def directory(binding):
    return Path(binding["run_dir"]) / "logs/capsule/phase1-retirement"


def module_paths(binding):
    root = Path(binding["run_dir"])
    phase = read_json(root / "config/phase1_binding.json")
    probe.require(all(phase.get(k) == binding[k] for k in IDENTITY), "Module binding identity mismatch")
    bundle = root / "config/analyzer_runtime"
    return {"phase1": bundle / phase["plugin"], "observer": bundle / binding["capsule"]["plugin"]}


def fingerprint(path):
    """Hash the same bounded regular file whose identity was obtained by fstat."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        probe.require(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= 512 * 1024**2,
                      "Module is not a bounded regular file")
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
        after = os.fstat(stream.fileno())
    probe.require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
                  (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
                  "Module changed while recording its identity")
    return {"device": [os.major(before.st_dev), os.minor(before.st_dev)], "inode": before.st_ino,
            "size": before.st_size, "sha256": digest}


def process_identity(text):
    try:
        prefix, fields = text.rsplit(")", 1)
        pid = int(prefix.split("(", 1)[0].strip())
        ticks = int(fields.split()[19])
    except (ValueError, IndexError) as exc:
        raise probe.ProbeError("Malformed process stat evidence") from exc
    probe.require(pid > 0 and ticks > 0, "Invalid process identity")
    return pid, ticks


def record_identity(binding, pid, ticks):
    paths = module_paths(binding)
    runtime = Phase1Runtime.load(paths["phase1"])
    modules = {role: fingerprint(path) for role, path in paths.items()}
    probe.require(modules["phase1"]["sha256"] == runtime.plugin_sha256, "Phase 1 changed during identity capture")
    return {"schema_version": SCHEMA, **{k: binding[k] for k in IDENTITY},
            "nonce": binding["lifecycle_attempt"], "qemu_pid": pid, "process_start_ticks": ticks,
            "phase1_build_id": runtime.build_id, "phase1_manifest_sha256": runtime.manifest_sha256,
            "modules": modules}


def load_identity(binding):
    path = directory(binding) / "mapping-identity.json"
    if not path.exists():
        probe.require("retirement_evidence_schema" not in binding,
                      "Missing required mapping-identity.json")
        raise EvidenceInconclusive("Legacy retirement evidence lacks mapping-identity.json; rerun is required")
    probe.require(type(binding.get("retirement_evidence_schema")) is int and
                  binding["retirement_evidence_schema"] == SCHEMA, "Missing/unsupported mapping evidence schema")
    record = read_json(path, 64 * 1024)
    probe.require(set(record) == {"schema_version", *IDENTITY, "nonce", "qemu_pid", "process_start_ticks",
                  "phase1_build_id", "phase1_manifest_sha256", "modules"} and
                  type(record["schema_version"]) is int and record["schema_version"] == SCHEMA and
                  all(record[k] == binding[k] for k in IDENTITY) and
                  record["nonce"] == binding["lifecycle_attempt"], "Invalid mapping identity binding/schema")
    for key in ("qemu_pid", "process_start_ticks"):
        probe.require(type(record[key]) is int and record[key] > 0, "Invalid recorded process identity")
    probe.require(set(record["modules"]) == {"phase1", "observer"}, "Invalid module identity inventory")
    for role, path in module_paths(binding).items():
        item = record["modules"][role]
        probe.require(set(item) == {"device", "inode", "size", "sha256"} and
                      isinstance(item["device"], list) and len(item["device"]) == 2 and
                      all(type(n) is int and n >= 0 for n in item["device"]) and
                      type(item["inode"]) is int and item["inode"] > 0 and
                      type(item["size"]) is int and item["size"] > 0, "Invalid recorded module identity")
        current = fingerprint(path)
        probe.require(all(item[k] == current[k] for k in ("size", "sha256")), "Saved module bytes changed: " + role)
    a, b = (record["modules"][role] for role in ("phase1", "observer"))
    probe.require((a["device"], a["inode"]) != (b["device"], b["inode"]), "Modules have the same recorded identity")
    runtime = Phase1Runtime.load(module_paths(binding)["phase1"])
    probe.require(record["phase1_build_id"] == runtime.build_id and
                  record["phase1_manifest_sha256"] == runtime.manifest_sha256, "Saved Phase 1 build identity changed")
    return record


def verdict(record, text, released):
    rows = maps.parse_maps(text)
    observed = {role + "_present": maps.file_mapped(rows, (tuple(item["device"]), item["inode"]))
                for role, item in record["modules"].items()}
    probe.require(observed == {"phase1_present": not released, "observer_present": True},
                  "Phase 1/observer mapping state is wrong")
    return observed


def capture(binding, pid, point):
    """Only the live observer calls this, while the guest is held."""
    output = directory(binding)
    proc = Path(binding["rootfs"]) / "proc" / str(pid)
    before = (proc / "stat").read_text()
    text = (proc / "maps").read_text()
    after = (proc / "stat").read_text()
    identity = process_identity(before)
    probe.require(identity == process_identity(after) and identity[0] == pid, "Process changed during mapping capture")
    current = record_identity(binding, *identity)
    path = output / "mapping-identity.json"
    if point == 1:
        probe.require(not path.exists(), "Refusing reuse of live mapping identity")
        probe.write_json(path, current)
    else:
        probe.require(current == load_identity(binding), "Live module/process identity changed")
    observed = verdict(current, text, point == 2)
    map_path, stat_path = output / f"maps-{point}.txt", output / f"process-{point}.stat"
    map_path.write_text(text)
    stat_path.write_text(after)
    return {"mapping_schema": SCHEMA, "mapping_identity_sha256": probe.sha(path),
            "process_start_ticks": identity[1], "process_stat_sha256": probe.sha(stat_path),
            "maps_sha256": probe.sha(map_path), "mapping_evidence": observed}


def verify_observation(binding, event, pid):
    record = load_identity(binding)
    output = directory(binding)
    point = event["point"]
    probe.require(type(event.get("mapping_schema")) is int and event["mapping_schema"] == SCHEMA and
                  event.get("mapping_identity_sha256") == probe.sha(output / "mapping-identity.json") and
                  record["qemu_pid"] == pid and record["process_start_ticks"] == event["process_start_ticks"],
                  "Saved mapping observation identity mismatch")
    stat_path = output / f"process-{point}.stat"
    map_path = output / f"maps-{point}.txt"
    probe.require(probe.sha(stat_path) == event["process_stat_sha256"] and
                  process_identity(stat_path.read_text()) == (pid, record["process_start_ticks"]),
                  "Saved process stat evidence changed")
    probe.require(probe.sha(map_path) == event["maps_sha256"] and
                  verdict(record, map_path.read_text(), point == 2) == event["mapping_evidence"],
                  "Saved retirement mapping evidence changed")
