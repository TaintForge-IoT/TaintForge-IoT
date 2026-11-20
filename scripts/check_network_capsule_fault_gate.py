#!/usr/bin/env python3
"""Read-only readiness check for the benign owned-responder crash fixture."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import time

from taintforge_env.network_capsule import interrupted_retirement, require, verify_runtime
from taintforge_env.network_runtime import _regular
from taintforge_env.phase1_runtime import read_json


def probe(run, attempt_id, contract_sha256):
    run = Path(run).resolve(strict=True)
    binding = read_json(run / "config/capsule_binding.json", 256 * 1024)
    require(binding.get("run_dir") == str(run) and binding.get("attempt_id") == attempt_id
            and binding.get("attempt_contract_sha256") == contract_sha256,
            "responder fault gate belongs to another attempt")
    identity = {key: binding[key] for key in ("attempt_id", "attempt_contract_sha256", "lifecycle_attempt")}
    path = run / "logs/capsule/observer-events.json"
    try:
        raw = _regular(path, 256 * 1024)
    except FileNotFoundError:
        return {"status": "pending", **identity, "observed_events": 0}
    journal = json.loads(raw)
    require(isinstance(journal, dict) and journal.get("schema") == 2
            and isinstance(journal.get("events"), list) and len(journal["events"]) <= 40
            and all(isinstance(event, dict) for event in journal["events"]),
            "invalid responder fault observer journal")
    events = journal["events"]
    require(not any(event.get("event") in {"done", "early_exit"} for event in events),
            "guest terminated before responder fault injection")
    # The controller publishes progress_window only after validating RESUME 2.
    # Traffic counters alone can advance before module_unmapped or HOLD 2.
    if not any(event.get("event") == "progress_window" for event in events):
        return {"status": "pending", **identity, "observed_events": len(events)}
    verify_runtime(binding)
    mapping = read_json(run / "logs/capsule/phase1-retirement/mapping-identity.json", 64 * 1024)
    pid = mapping["qemu_pid"]
    retirement = interrupted_retirement(binding, {"qemu_pid": pid})
    require(retirement.get("status") == "verified" and retirement.get("phase1_retired") is True
            and retirement.get("observer_completed") is False,
            "responder fault lacks verified retirement and post-unmap resume")
    digest = hashlib.sha256(raw).hexdigest()
    require(retirement.get("observer_journal_sha256") == digest
            and _regular(path, 256 * 1024) == raw,
            "observer journal changed during responder fault verification")
    return {"status": "ready", **identity, "qemu_pid": pid,
            "observed_monotonic_ns": time.monotonic_ns(), "retirement": retirement}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path, required=True)
    parser.add_argument("--attempt-id", required=True)
    parser.add_argument("--contract-sha256", required=True)
    args = parser.parse_args()
    try:
        result = probe(args.run, args.attempt_id, args.contract_sha256)
        code = 0
    except (OSError, ValueError, RuntimeError, KeyError, TypeError, StopIteration) as exc:
        result = {"status": "failed", "error": f"{type(exc).__name__}: {exc}"[:2000]}
        code = 1
    print(json.dumps(result, sort_keys=True))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
