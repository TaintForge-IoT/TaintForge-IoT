"""Small broker-schema captures with explicit stream ordering for regressions."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path


CLIENT = "client_to_server"
SERVER = "server_to_client"
STAMP = "2026-09-11T00:00:00+00:00"


def write_capture(
    root: Path,
    chunks: tuple[tuple[str, bytes], ...] = ((CLIENT, b"he"), (CLIENT, b"llo"),
                                            (SERVER, b"wo"), (SERVER, b"rld")),
) -> Path:
    (root / "chunks").mkdir(parents=True)
    endpoint = {"original_remote_ip": "198.51.100.10", "original_remote_port": 48101,
                "upstream_ip": "127.0.0.1", "upstream_port": 49001}
    summary = {
        "schema_version": 1, "run_id": "fixture-run", "session_id": "fixture-session",
        "capture_kind": "local_test", "started_at_utc": STAMP, "finished_at_utc": STAMP,
        "duration_seconds": 1.0, "close_reason": "upstream_closed", "error": None,
        **endpoint,
        "limits": {"max_client_bytes": 65536, "max_server_bytes": 1048576},
    }
    events = [
        {"event": "session_started", "capture_kind": "local_test", **endpoint},
        {"event": "upstream_connected", "upstream_ip": "127.0.0.1", "upstream_port": 49001},
    ]
    payloads = {CLIENT: bytearray(), SERVER: bytearray()}
    counts = {CLIENT: 0, SERVER: 0}
    for i, (direction, data) in enumerate(chunks, 1):
        counts[direction] += 1
        payloads[direction].extend(data)
        path = f"chunks/{counts[direction]:06d}_{direction}.bin"
        (root / path).write_bytes(data)
        events.append({"event": "stream_chunk", "direction": direction,
                       "chunk_index": counts[direction], "size": len(data),
                       "sha256": hashlib.sha256(data).hexdigest(),
                       "elapsed_seconds": i / 100, "payload_file": path})
    for direction in (CLIENT, SERVER):
        events.append({"event": "stream_eof", "direction": direction})
        data = bytes(payloads[direction])
        (root / f"{direction}.bin").write_bytes(data)
        summary[direction] = {"bytes": len(data), "chunks": counts[direction],
                              "sha256": hashlib.sha256(data).hexdigest(),
                              "path": f"{direction}.bin"}
    events.append({"event": "session_finished", "close_reason": "upstream_closed",
                   "client_bytes": len(payloads[CLIENT]), "server_bytes": len(payloads[SERVER]),
                   "error": None})
    for event in events:
        event.update(session_id=summary["session_id"], timestamp_utc=STAMP)
    (root / "session.json").write_text(json.dumps(summary) + "\n", encoding="utf-8")
    write_events(root, events)
    return root


def read_events(root: Path) -> list[dict]:
    return [json.loads(line) for line in (root / "events.jsonl").read_text().splitlines()]


def write_events(root: Path, events: list[dict]) -> None:
    (root / "events.jsonl").write_text(
        "".join(json.dumps(event) + "\n" for event in events), encoding="utf-8")
