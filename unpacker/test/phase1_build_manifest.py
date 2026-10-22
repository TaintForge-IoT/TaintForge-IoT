#!/usr/bin/env python3
"""Fingerprint the inputs selected by the existing plugin build recipe."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile


def sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("identity", "write"))
    parser.add_argument("--header", required=True, type=Path)
    parser.add_argument("--plugin", required=True, type=Path)
    parser.add_argument("--compiler", required=True)
    parser.add_argument("--expected-build-id")
    parser.add_argument("sources", nargs="+", type=Path)
    args = parser.parse_args()
    root = args.sources[0].resolve().parent
    selected = set(path.resolve() for path in args.sources)
    selected.update(root.glob("*.h"))
    selected.update((root / "build_group7_4c1_plugin.sh", Path(__file__).resolve()))
    inputs = {str(path.relative_to(root)): sha256(path) for path in sorted(selected)}
    api = re.search(r"^#define QEMU_PLUGIN_VERSION\s+(\d+)", args.header.read_text(), re.M)
    if api is None:
        raise SystemExit("Selected header does not define QEMU_PLUGIN_VERSION")
    compiler = subprocess.run([args.compiler, "--version"], check=True, text=True, capture_output=True).stdout.splitlines()[0]
    identity = {
        "source_files": inputs,
        "qemu_header_sha256": sha256(args.header),
        "plugin_api": int(api[1]),
        "compiler": compiler,
        "cppflags": os.environ.get("TF_BUILD_CPPFLAGS", ""),
        "ldflags": os.environ.get("TF_BUILD_LDFLAGS", ""),
        "libs": os.environ.get("TF_BUILD_LIBS", ""),
    }
    build_id = hashlib.sha256(json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    if args.mode == "identity":
        print(build_id)
        return
    if build_id != args.expected_build_id:
        raise SystemExit("Build inputs changed while compiling; refusing runtime manifest")
    try:
        revision = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"], check=True, text=True, capture_output=True).stdout.strip()
    except subprocess.CalledProcessError:
        revision = None
    payload = {
        "schema_version": 1,
        "runtime_kind": "taintforge-phase1",
        "build_id": build_id,
        "plugin": {"filename": args.plugin.name, "sha256": sha256(args.plugin), "size": args.plugin.stat().st_size},
        "source_revision": revision,
        "build_inputs": identity,
        "compiled_profile": {"architecture": "i386", "mode": "linux-user", "processes": 1, "threads": 1},
        "requirements": {"qemu_linkage": "dynamic", "plugins": True, "plugin_api": int(api[1]), "flags_contract": "taintforge_x86_flags_v1_when_required"},
        "formats": {"events": 1, "report": 1, "capture_manifest": 1, "provenance_export": None,
                    "cooperative_retirement": 1 if int(api[1]) == 6 else None,
                    "verdict_retirement": 2 if int(api[1]) == 6 else None},
        "resource_ledger": {"schema": 1, "scope": "explicit_project_allocations",
                            "external_allocations_tracked": False},
        "runtime_verification": "not_performed_by_build",
    }
    output = Path(str(args.plugin) + ".runtime.json")
    fd, temporary = tempfile.mkstemp(prefix=output.name + ".", dir=output.parent)
    try:
        with os.fdopen(fd, "w") as stream:
            json.dump(payload, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, output)
    finally:
        Path(temporary).unlink(missing_ok=True)


if __name__ == "__main__":
    main()
