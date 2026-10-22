#!/usr/bin/env python3
"""Compare Phase1 sources and build receipt with the pinned lifecycle review.

Read-only inspection: never imports the target repository or loads its plugin.
Exit 0 means matching fingerprints, NOT safe live retirement or erased memory.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat

REFERENCE = Path(__file__).resolve().parents[1] / "docs/PHASE1_LIFECYCLE_REFERENCE_V1.json"
MAX_JSON = 2 * 1024 * 1024
PROFILE = {"architecture": "i386", "mode": "linux-user", "processes": 1, "threads": 1}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def regular(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        require(stat.S_ISREG(os.fstat(fd).st_mode), f"Not a regular file: {path}")
        return os.fdopen(fd, "rb")
    except BaseException:
        os.close(fd)
        raise


def fingerprint(path):
    try:
        with regular(path) as stream:
            before = os.fstat(stream.fileno())
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
            after = os.fstat(stream.fileno())
            require((before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
                    (after.st_size, after.st_mtime_ns, after.st_ctime_ns), f"File changed: {path}")
            return {"sha256": digest, "size": after.st_size}
    except FileNotFoundError:
        return None


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, f"Duplicate JSON key: {key}")
        result[key] = value
    return result


def invalid_constant(value):
    raise ValueError(f"Non-finite JSON constant: {value}")


def read_json(path):
    with regular(path) as stream:
        require(os.fstat(stream.fileno()).st_size <= MAX_JSON, f"JSON too large: {path}")
        data = stream.read(MAX_JSON + 1)
    require(len(data) <= MAX_JSON, f"JSON too large: {path}")
    value = json.loads(data, object_pairs_hook=unique_object, parse_constant=invalid_constant)
    require(isinstance(value, dict), f"Expected JSON object: {path}")
    return value


def source_map(value):
    require(isinstance(value, dict) and value, "Expected nonempty source_files object")
    for name, digest in value.items():
        require(isinstance(name, str) and re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]*", name),
                "Source filenames must be flat and relative")
        require(isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest),
                f"Invalid source SHA-256: {name}")
    return value


def inspect_sources(source, reference, built):
    expected = source_map(reference["source_files"])
    # The pinned recipe compiles its named .c files and fingerprints ALL root .h files.
    headers = {p.name for p in source.glob("*.h")}
    selected = set(expected) | set(built) | headers
    rows = {}
    for name in sorted(selected):
        actual = fingerprint(source / name)
        sha = actual["sha256"] if actual else None
        rows[name] = {"reviewed_sha256": expected.get(name), "actual_sha256": sha,
                      "build_sha256": built.get(name),
                      "matches_review": sha is not None and sha == expected.get(name),
                      "matches_build": sha is not None and sha == built.get(name)}
    return rows


def inspect_runtime(plugin, manifest, reference):
    require(type(manifest.get("schema_version")) is int and manifest["schema_version"] == 1 and
            manifest.get("runtime_kind") == "taintforge-phase1", "Unsupported runtime manifest")
    inputs = manifest.get("build_inputs")
    require(isinstance(inputs, dict), "Missing build_inputs")
    built = source_map(inputs.get("source_files"))
    for key in ("compiler", "cppflags", "ldflags", "libs", "qemu_header_sha256"):
        require(isinstance(inputs.get(key), str), f"Missing build input: {key}")
    require(type(inputs.get("plugin_api")) is int, "Missing integer plugin_api")
    identity = hashlib.sha256(json.dumps(inputs, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    require(manifest.get("build_id") == identity, "build_id does not match build_inputs")
    record = manifest.get("plugin")
    require(isinstance(record, dict), "Missing plugin record")
    requirements = manifest.get("requirements")
    require(isinstance(requirements, dict), "Missing requirements")
    profile = manifest.get("compiled_profile")
    require(isinstance(profile, dict), "Missing compiled_profile")
    actual = fingerprint(plugin)
    checks = {
        "plugin_matches_manifest": actual is not None and
            record.get("sha256") == actual["sha256"] and type(record.get("size")) is int and
            record["size"] == actual["size"] and
            record.get("filename") == plugin.name,
        "build_sources_match_review": built == reference["source_files"],
        "plugin_api_matches_review": inputs["plugin_api"] == reference["qemu"]["plugin_api"] and
            requirements.get("plugin_api") == reference["qemu"]["plugin_api"],
        "header_matches_review": inputs["qemu_header_sha256"] == reference["qemu"]["header_sha256"],
        "profile_matches_review": profile == PROFILE and
            all(type(profile.get(key)) is int for key in ("processes", "threads")) and
            requirements.get("qemu_linkage") == "dynamic" and requirements.get("plugins") is True,
    }
    return built, {"build_id": identity, "source_revision": manifest.get("source_revision"),
                   "plugin": actual, "checks": checks, "matched": all(checks.values())}


def inspect(repo, source, plugin, reference, source_only=False):
    require(source.is_dir(), f"Source directory is missing: {source}")
    source_map(reference["source_files"])
    report = {"schema_version": 1, "scope": "phase1_lifecycle_source_identity",
              "reference_revision": reference["revision"], "repo": str(repo),
              "source_directory": str(source), "source_only": source_only,
              "runtime_binding": "not_checked", "live_retirement_ready": False,
              "phase1_memory_released": False, "residue_free": False,
              "plugin_executed": False, "audit_findings": [f["id"] for f in reference["findings"]]}
    built = {}
    runtime = None
    sidecar = Path(str(plugin) + ".runtime.json")
    sidecar_before = None
    if not source_only:
        sidecar_before = fingerprint(sidecar)
        if sidecar_before is not None:
            built, runtime = inspect_runtime(plugin, read_json(sidecar), reference)
            report["runtime_binding"] = "matched" if runtime["matched"] else "mismatch"
        else:
            report["runtime_binding"] = "manifest_missing"
    rows = inspect_sources(source, reference, built)
    source_ok = all(row["matches_review"] for row in rows.values())
    build_ok = source_only or (runtime is not None and runtime["matched"] and
                              all(row["matches_build"] for row in rows.values()))
    # Detect ordinary concurrent edits across the inspection, without claiming an atomic snapshot.
    for name, row in rows.items():
        current = fingerprint(source / name)
        require((current["sha256"] if current else None) == row["actual_sha256"],
                f"Source changed during audit: {name}")
    if not source_only:
        require(fingerprint(sidecar) == sidecar_before, "Runtime manifest changed during audit")
        if runtime is not None:
            require(fingerprint(plugin) == runtime["plugin"], "Plugin changed during audit")
    report.update(status="matched" if source_ok and build_ok else "mismatch", files=rows,
                  runtime=runtime, source_matches_review=source_ok,
                  source_matches_build=not source_only and bool(built) and
                      all(row["matches_build"] for row in rows.values()))
    return report


def output_path(path, repo, source):
    # Refuse to place output in any source/build area, even when a different source root is selected.
    out = path.absolute()
    require(not out.is_symlink(), "Output must not be a symlink")
    out = out.resolve()
    forbidden = tuple(p.resolve() for p in
                      (source, repo / "unpacker", repo / "build", repo / ".git",
                       repo / "scripts", repo / "docs", repo / "tests", repo / "taintforge_env"))
    require(not any(out == p or out.is_relative_to(p) for p in forbidden),
            "Output must be outside source/build directories; use workdir/")
    require(not out.exists(), f"Output already exists: {out}")
    return out


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--source-dir", type=Path, default=Path("unpacker/test"))
    parser.add_argument("--phase1", type=Path, default=Path("build/libtaintforge_ir.so"))
    parser.add_argument("--source-only", action="store_true", help="Skip binary/receipt binding explicitly")
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args(argv)
    repo = args.repo.resolve()
    source = (repo / args.source_dir).resolve()
    plugin = repo / args.phase1
    try:
        out = output_path(repo / args.out, repo, source)
    except (OSError, ValueError) as exc:
        print(f"Phase1 lifecycle audit: {exc}")
        return 2
    try:
        reference = read_json(REFERENCE)
        require(reference.get("schema_version") == 1, "Unsupported lifecycle reference")
        report = inspect(repo, source, plugin, reference, args.source_only)
        code = 0 if report["status"] == "matched" else 1
    except (OSError, ValueError, KeyError, TypeError, RecursionError) as exc:
        report = {"schema_version": 1, "status": "error", "error": f"{type(exc).__name__}: {exc}",
                  "live_retirement_ready": False, "phase1_memory_released": False,
                  "residue_free": False, "plugin_executed": False}
        code = 2
    try:
        out.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w") as stream:
            json.dump(report, stream, indent=2, sort_keys=True)
            stream.write("\n")
    except OSError as exc:
        print(f"Cannot save audit: {exc}")
        return 2
    print(f"identity: {report['status']}; live_retirement_ready: false")
    if report.get("error"):
        print(report["error"])
    elif report["status"] == "mismatch":
        for name, row in report["files"].items():
            if not row["matches_review"] or (not args.source_only and not row["matches_build"]):
                print(f"  review/build mismatch: {name}")
        print(f"runtime_binding: {report['runtime_binding']}")
    print(out)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
