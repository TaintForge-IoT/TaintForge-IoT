#!/usr/bin/env python3
"""Validate a recording run and publish a new replay bundle after full validation."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile

from taintforge_env.capture_importer import import_capture, _json_object, _no_symlinks, _read_file
from taintforge_env.network_policy import NetworkPolicy, NetworkServicePolicy, load_network_policy
from taintforge_env.network_record import validate_record_policy
from taintforge_env.network_replay import validate_replay_policy
from taintforge_env.replay_store import ReplayStore


def import_run(capture_dir: Path, policy_path: Path, out: Path) -> dict:
    _no_symlinks(capture_dir)
    _no_symlinks(policy_path)
    _no_symlinks(out)
    if out.exists():
        raise ValueError("replay bundle output must be new")
    policy = load_network_policy(policy_path)
    options = validate_record_policy(policy)
    endpoints = {(s.service_type, s.remote_ip, s.remote_port): s for s in policy.services}
    sessions = sorted(capture_dir.rglob("session.json"))
    if not sessions:
        raise ValueError("no completed captures found")
    out.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=".network-import-", dir=out.parent))
    try:
        store = ReplayStore(staging / "replay_store")
        receipts = []
        for session in sessions:
            raw = _json_object(_read_file(session, 65536), "session")
            key = (raw.get("transport", "tcp"), raw.get("original_ip", raw.get("original_remote_ip")),
                   raw.get("original_port", raw.get("original_remote_port")))
            service = endpoints.get(key)
            if service is None:
                raise ValueError(f"capture endpoint is outside the recording policy: {key}")
            if raw.get("run_id") != options["run_id"] or raw.get("capture_kind") != options["capture_kind"]:
                raise ValueError("capture run identity or kind does not match recording policy")
            if (raw.get("upstream_ip"), raw.get("upstream_port")) != (service.upstream_ip, service.upstream_port):
                raise ValueError("capture upstream does not match recording policy")
            receipts.append(import_capture(session.parent, store, protocol_hint=service.protocol_hint).to_dict())
        services = [NetworkServicePolicy(service_type=s.service_type, role=s.role, remote_ip=s.remote_ip,
                    remote_port=s.remote_port, domain=s.domain, bind_ip="127.0.0.1", bind_port=s.remote_port,
                    protocol_hint=s.protocol_hint) for s in policy.services]
        replay = NetworkPolicy(mode="replay", services=services)
        replay.catch_all.enabled = False
        validation = validate_replay_policy(policy=replay, replay_store=store)
        (staging / "network_policy.json").write_text(json.dumps(replay.to_dict(), indent=2) + "\n")
        report = {"schema_version": 1, "status": "ready", "capture_count": len(sessions),
                  "record_policy_sha256": hashlib.sha256(policy_path.read_bytes()).hexdigest(),
                  "store_sha256": validation["store_sha256"], "entries": validation["entries"], "receipts": receipts}
        (staging / "import_report.json").write_text(json.dumps(report, indent=2) + "\n")
        if out.exists() or out.is_symlink():
            raise ValueError("replay bundle destination appeared during import")
        os.rename(staging, out)
        return report
    finally:
        if staging.exists():
            shutil.rmtree(staging)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture-dir", type=Path, required=True)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    try:
        report = import_run(args.capture_dir.absolute(), args.policy.absolute(), args.out.absolute())
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"Network import failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps({key: value for key, value in report.items() if key != "receipts"}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
