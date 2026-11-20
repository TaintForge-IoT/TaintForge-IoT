"""Bounded external sorting and one payload alias per source artifact."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat
import tempfile

from .network_runtime import NetworkRuntimeError, NetworkRuntimeLimits, network_open


def aggregate_network_events(logs_dir, *, runtime=None):
    logs_dir = Path(logs_dir)
    limits = runtime.limits if runtime is not None else NetworkRuntimeLimits()
    client = runtime.client() if runtime is not None else None
    destination = logs_dir / "network_events.jsonl"
    temporary = logs_dir / ".network_events.pending"
    payload_root = logs_dir / "network_payloads"
    descriptor, database = tempfile.mkstemp(prefix="tf-net-sort-", suffix=".sqlite")
    os.close(descriptor)
    connection = sqlite3.connect(database)
    total = records = 0
    payloads = {}
    try:
        connection.execute("PRAGMA journal_mode=OFF")
        connection.execute("PRAGMA synchronous=OFF")
        connection.execute("PRAGMA cache_size=-1024")
        connection.execute("PRAGMA temp_store=FILE")
        connection.execute("CREATE TABLE events (stamp TEXT, source TEXT, name TEXT, sequence INTEGER, body TEXT)")
        for source_name in ("host", "loopback", "transparent"):
            source_dir = logs_dir / ("network_" + source_name)
            if not source_dir.exists():
                continue
            if source_dir.is_symlink() or not source_dir.is_dir():
                raise NetworkRuntimeError("invalid network source directory")
            event_path = source_dir / "network_events.jsonl"
            if event_path.is_symlink():
                raise NetworkRuntimeError("symlink in network event source")
            if not event_path.exists():
                continue
            if not event_path.is_file():
                raise NetworkRuntimeError("network event source is not a regular file")
            source_fd = os.open(event_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(source_fd, "rb") as source:
                if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
                    raise NetworkRuntimeError("network event source is not a regular file")
                while True:
                    line = source.readline(65537)
                    if not line:
                        break
                    total += len(line)
                    if len(line) > 65536 or total > limits.max_log_bytes or records >= 100000:
                        raise NetworkRuntimeError("network aggregation input budget exceeded")
                    if not line.strip():
                        continue
                    value = json.loads(line)
                    if not isinstance(value, dict):
                        raise NetworkRuntimeError("network event is not an object")
                    value["backend_source"] = source_name
                    payload = value.get("payload_file")
                    if isinstance(payload, str) and payload:
                        relative = Path(payload)
                        if relative.is_absolute() or ".." in relative.parts:
                            raise NetworkRuntimeError("network payload escapes its source")
                        source_payload = source_dir / relative
                        if any(path.is_symlink() for path in (source_payload, *source_payload.parents)):
                            raise NetworkRuntimeError("symlink in network payload")
                        if source_payload.is_file():
                            key = (source_name, payload)
                            if key not in payloads:
                                payload_root.mkdir(exist_ok=True)
                                if payload_root.is_symlink():
                                    raise NetworkRuntimeError("symlink in network payload destination")
                                name = source_name + "_" + hashlib.sha256(payload.encode()).hexdigest() + ".bin"
                                target = payload_root / name
                                if target.exists() or target.is_symlink():
                                    if target.is_symlink() or not os.path.samefile(source_payload, target):
                                        raise NetworkRuntimeError("network payload alias conflicts with existing data")
                                else:
                                    # Sources and aliases live on the same attempt filesystem.
                                    # Refuse a cross-filesystem copy rather than duplicate unbudgeted bytes.
                                    os.link(source_payload, target)
                                payloads[key] = "network_payloads/" + name
                            value["payload_file"] = payloads[key]
                    body = json.dumps(value, ensure_ascii=False, sort_keys=True)
                    connection.execute("INSERT INTO events VALUES (?,?,?,?,?)", (
                        str(value.get("timestamp_utc") or ""), source_name, str(value.get("event") or ""), records, body))
                    records += 1
        connection.commit()
        with network_open(temporary, "wb", runtime=client, finalizing=True) as output:
            for (body,) in connection.execute("SELECT body FROM events ORDER BY stamp,source,name,sequence"):
                output.write(body.encode() + b"\n")
        os.replace(temporary, destination)
        return {"records": records, "source_bytes": total, "unique_payloads": len(payloads)}
    finally:
        connection.close()
        Path(database).unlink(missing_ok=True)
        temporary.unlink(missing_ok=True)
