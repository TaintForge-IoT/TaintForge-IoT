"""A portable, bounded copy of retirement evidence, never an executable checkpoint."""
from __future__ import annotations

import copy
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tempfile

from experiments.execution_capsule_probe import controller as probe
from .phase1_runtime import read_json
from . import phase1_retirement as retirement, retirement_mappings as mappings

SCHEMA = 1
MAX_FILE = 1024**3
MAX_TOTAL = 2 * 1024**3
MAX_FILES = 64
SCOPE = "phase1-retirement-evidence-only"


def verify_attempt(binding, result):
    if "observer" in binding:
        from experiments.retirement_observer.controller import verify_attempt as verify_observer
        return verify_observer(binding, result)
    return retirement.verify_attempt(binding, result)


def relative(value):
    probe.require(isinstance(value, str) and value and "\\" not in value,
                  "Invalid evidence path")
    path = PurePosixPath(value)
    probe.require(not path.is_absolute() and str(path) == value and
                  all(p not in {".", ".."} for p in path.parts), "Evidence path escapes the bundle")
    return path


def local_file(root, name):
    path = root / relative(name)
    for part in [path, *path.parents]:
        if part == root:
            break
        probe.require(not part.is_symlink(), "Symlink in evidence path")
    info = path.lstat()
    probe.require(stat.S_ISREG(info.st_mode) and info.st_size <= MAX_FILE, "Unbounded/non-regular evidence file")
    return path


def normalized_bindings(binding, phase, plugin_name):
    b, p = copy.deepcopy(binding), copy.deepcopy(phase)
    b.update(run_dir=".", recorded_phase1_directory=phase["output_directory"])
    b["capsule"]["plugin"] = "observer/plugin.so"
    p.update(plugin="phase1/" + plugin_name, output_directory="phase1")
    return b, p


def verify(root, *, expected_sha256=None):
    root = Path(root).resolve(strict=True)
    manifest_path = local_file(root, "bundle.json")
    digest = probe.sha(manifest_path)
    if expected_sha256 is not None:
        probe.require(isinstance(expected_sha256, str) and re.fullmatch(r"[0-9a-f]{64}", expected_sha256)
                      and digest == expected_sha256, "Evidence bundle digest differs from the trusted reference")
    manifest = read_json(manifest_path, 1024**2)
    probe.require(set(manifest) == {"schema_version", "kind", "scope", "identity", "files"} and
                  type(manifest["schema_version"]) is int and manifest["schema_version"] == SCHEMA and
                  manifest["kind"] == "taintforge-retirement-evidence" and manifest["scope"] == SCOPE,
                  "Unsupported evidence bundle schema")
    inventory = manifest["files"]
    probe.require(isinstance(inventory, list) and 0 < len(inventory) <= MAX_FILES, "Invalid evidence inventory")
    seen, total = set(), 0
    for item in inventory:
        probe.require(isinstance(item, dict) and set(item) == {"path", "size", "sha256"} and
                      type(item["size"]) is int and 0 <= item["size"] <= MAX_FILE and
                      isinstance(item["sha256"], str) and re.fullmatch(r"[0-9a-f]{64}", item["sha256"]),
                      "Invalid evidence file descriptor")
        name = item["path"]
        relative(name)
        probe.require(name not in seen and name != "bundle.json", "Duplicate evidence inventory entry")
        seen.add(name)
        total += item["size"]
        probe.require(total <= MAX_TOTAL, "Evidence bundle exceeds its byte budget")
        path = local_file(root, name)
        probe.require(path.stat().st_size == item["size"] and probe.sha(path) == item["sha256"],
                      "Evidence file changed: " + name)
    actual = set()
    for path in root.rglob("*"):
        probe.require(not path.is_symlink(), "Symlink in evidence bundle")
        if not path.is_dir():
            actual.add(path.relative_to(root).as_posix())
    probe.require(actual == seen | {"bundle.json"}, "Evidence inventory is incomplete or contains extra files")
    source = read_json(local_file(root, "source/capsule_binding.json"))
    phase = read_json(local_file(root, "source/phase1_binding.json"))
    probe.require(Path(phase["output_directory"]).is_absolute(), "Missing recorded Phase 1 output path")
    plugin_name = Path(phase["plugin"]).name
    expected_binding, expected_phase = normalized_bindings(source, phase, plugin_name)
    binding = read_json(local_file(root, "config/capsule_binding.json"))
    current_phase = read_json(local_file(root, "config/phase1_binding.json"))
    probe.require(binding == expected_binding and current_phase == expected_phase,
                  "Portable bindings differ from their recorded source")
    probe.require(manifest["identity"] == {k: binding[k] for k in mappings.IDENTITY},
                  "Portable evidence attempt identity mismatch")
    # Offline reads use only the verified relative paths.
    binding["run_dir"] = str(root)
    result = read_json(local_file(root, "logs/capsule/supervisor.json"))
    retirement.validate_settings(binding["settings"]["phase1_retirement"])
    checked = verify_attempt(binding, result)
    probe.require(result["status"] == checked["status"], "Saved supervisor outcome differs from verified evidence")
    return {"status": "verified", "schema_version": SCHEMA, "scope": SCOPE,
            "manifest_sha256": digest, "reference_digest_checked": expected_sha256 is not None,
            "authenticity": "not_asserted", "attempt_outcome": checked["status"],
            "identity": manifest["identity"], "phase1_retirement": checked["phase1_retirement"]}


def pack(run_dir, destination):
    run = Path(run_dir).resolve(strict=True)
    destination = Path(destination).absolute()
    probe.require(not destination.exists() and not destination.is_symlink(), "Evidence destination already exists")
    original_binding = read_json(run / "config/capsule_binding.json")
    binding = copy.deepcopy(original_binding)
    probe.require(Path(binding["run_dir"]) == run, "Pack the original attempt before moving it")
    mappings.load_identity(binding)
    phase = read_json(run / "config/phase1_binding.json")
    result = read_json(run / "logs/capsule/supervisor.json")
    verify_attempt(binding, result)
    modules = mappings.module_paths(binding)
    analyzer = retirement.analysis(binding)
    b, p = normalized_bindings(binding, phase, modules["phase1"].name)
    sources = {
        "source/capsule_binding.json": run / "config/capsule_binding.json",
        "source/phase1_binding.json": run / "config/phase1_binding.json",
        "config/analyzer_runtime/" + p["plugin"]: modules["phase1"],
        "config/analyzer_runtime/" + p["plugin"] + ".runtime.json": analyzer.runtime.manifest,
        "config/analyzer_runtime/observer/plugin.so": modules["observer"],
    }
    journal = "observer-events.json" if "observer" in binding else "observations.jsonl"
    for name in (journal, "controller.json", "supervisor.json"):
        sources["logs/capsule/" + name] = run / "logs/capsule" / name
    if 'hardening' in binding.get('settings', {}):
        for name in ('execution-context-1.json', 'execution-context-2.json', 'm4-setup.json'):
            sources['logs/capsule/' + name] = run / 'logs/capsule' / name
    if "input_retirement" not in binding:
        sources["logs/capsule/capsule-fd.txt"] = run / "logs/capsule/capsule-fd.txt"
    else:
        sources["config/input-attempt.json"] = run / "config/input-attempt.json"
    if "observer" in binding:
        sources["guest-i386"] = run / "guest-i386"
        sources["config/observer-contract.json"] = run / "config/observer-contract.json"
    for name in ("runtime_stdout.log", "qemu_strace.log"):
        sources["logs/" + name] = run / "logs" / name
    for path in analyzer.paths.values():
        if path.exists():
            sources["phase1/" + path.name] = path
    out = retirement.directory(binding)
    for name in ("mapping-identity.json", "maps-1.txt", "process-1.stat", "maps-2.txt", "process-2.stat",
                 "retirement.json", "maps-unmapped.txt", "process-unmapped.stat"):
        if (out / name).exists():
            sources["logs/capsule/phase1-retirement/" + name] = out / name
    for path in analyzer.paths.values():
        saved = out / "export" / path.name
        if saved.exists():
            sources["logs/capsule/phase1-retirement/export/" + path.name] = saved
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".tf-evidence-", dir=destination.parent) as temporary:
        stage = Path(temporary) / "bundle"
        stage.mkdir(mode=0o700)
        total = 0
        for name, source in sources.items():
            source = local_file(source.parent, source.name)
            size = source.stat().st_size
            total += size
            probe.require(total <= MAX_TOTAL, "Evidence bundle exceeds its byte budget")
            target = stage / relative(name)
            target.parent.mkdir(parents=True, exist_ok=True)
            # A concurrent change must not yield a silently accepted partial copy.
            before = probe.sha(source)
            with source.open("rb") as src, target.open("xb") as dst:
                left = size
                while left:
                    data = src.read(min(left, 1024**2))
                    probe.require(data, "Source evidence was truncated while copying")
                    dst.write(data)
                    left -= len(data)
                probe.require(not src.read(1), "Source evidence grew while copying")
                dst.flush()
                os.fsync(dst.fileno())
            probe.require(target.stat().st_size == size and probe.sha(target) == before == probe.sha(source),
                          "Source evidence changed while copying")
        probe.write_json(stage / "config/capsule_binding.json", b)
        probe.write_json(stage / "config/phase1_binding.json", p)
        files = [{"path": path.relative_to(stage).as_posix(), "size": path.stat().st_size,
                  "sha256": probe.sha(path)} for path in sorted(stage.rglob("*")) if path.is_file()]
        probe.write_json(stage / "bundle.json", {"schema_version": SCHEMA, "kind": "taintforge-retirement-evidence",
            "scope": SCOPE, "identity": {k: binding[k] for k in mappings.IDENTITY}, "files": files})
        checked = verify(stage)
        probe.require(not destination.exists(), "Evidence destination appeared while packing")
        stage.rename(destination)
    return {**checked, "directory": str(destination)}
