#!/usr/bin/env python3
"""Reevaluate saved target evidence into a new file outside the original session.

No guest is executed, session resumed, or Phase 1 completeness inferred.
Legacy syscall results are normalized in memory by TargetStateOracle.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from taintforge_env.target_state_oracle import TargetStateError, TargetStateOracle, TargetStateSpec


def reevaluate(run_dir: Path, out: Path, spec_path: Path | None = None) -> dict:
    source = run_dir.expanduser().resolve(strict=True)
    if not source.is_dir():
        raise ValueError(f"run directory does not exist: {source}")
    output = out.expanduser().absolute()
    if output.exists() or output.is_symlink():
        raise ValueError(f"use a new output file: {output}")
    # Protect both the run and its enclosing session/unified reports, including
    # destinations reached through a symlinked parent directory.
    protected = [source]
    for parent in source.parents:
        if (parent / "session.json").exists() or (parent / "unified_launch.json").exists():
            protected.append(parent)
    if any(output.resolve().is_relative_to(root) for root in protected):
        raise ValueError("reevaluation output must be outside the original run/session")

    specification = spec_path.expanduser() if spec_path else source / "config/target_state_spec.json"
    spec = TargetStateSpec.load(specification)
    evaluation = TargetStateOracle().evaluate(source, spec)
    result = {
        "schema_version": 1,
        "status": "reevaluated",
        "source_run_dir": str(source),
        "spec_path": str(specification.resolve()),
        "guest_executed": False,
        "session_resumed": False,
        "phase1_artifacts_verified": False,
        "fuzzing_ready": False,
        "goal_reached": evaluation.reached,
        "evaluation": evaluation.to_dict(),
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    # Exclusive creation also refuses a file/symlink created after preflight.
    with output.open("x", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2, ensure_ascii=False)
        stream.write("\n")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True, help="New JSON file outside the source run/session")
    parser.add_argument("--spec", type=Path, help="Defaults to the saved config/target_state_spec.json")
    args = parser.parse_args()
    os.umask(0o077)
    try:
        result = reevaluate(args.run_dir, args.out, args.spec)
    except (OSError, ValueError, TargetStateError) as exc:
        parser.exit(2, f"Target-state reevaluation failed: {exc}\n")
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0 if result["goal_reached"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
