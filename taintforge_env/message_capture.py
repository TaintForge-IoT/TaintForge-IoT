"""Immutable single-message UDP/DNS captures and strict ReplayStore import."""
from __future__ import annotations

import json
import os
from pathlib import Path
import uuid

from .capture_importer import (CaptureImportError, CaptureImportResult, _check_digest,
    _integer, _json_object, _object, _read_file, _require, _string)
from .dns_protocol import DNSError, canonical_exchange
from .replay_store import (ReplayStore, ReplayEntryExistsError, normalize_ip,
                           normalize_port, normalize_protocol_hint, sha256_bytes)


FORMAT = "network-message-v1"


def _write(path: Path, content: bytes) -> None:
    with path.open("xb") as output:
        os.chmod(path, 0o600)
        output.write(content)
        output.flush()
        os.fsync(output.fileno())


def publish_capture(root: Path, *, run_id: str, transport: str, protocol_hint: str | None,
                    remote_ip: str, remote_port: int, upstream_ip: str, upstream_port: int,
                    capture_kind: str, request: bytes, response: bytes | None,
                    status: str = "completed", reason: str | None = None,
                    quiet_seconds: float = 0.05) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    session_id = uuid.uuid4().hex
    directory = root / session_id
    directory.mkdir(mode=0o700)
    files = {}
    for name, payload in (("request", request), ("response", response)):
        if payload is None:
            files[name] = None
            continue
        _write(directory / f"{name}.bin", payload)
        files[name] = {"path": f"{name}.bin", "size": len(payload), "sha256": sha256_bytes(payload)}
    events = [{"sequence": 1, "direction": "client_to_server", "payload": files["request"]}]
    if response is not None:
        events.append({"sequence": 2, "direction": "server_to_client", "payload": files["response"]})
    event_bytes = b"".join((json.dumps(event, sort_keys=True) + "\n").encode() for event in events)
    _write(directory / "events.jsonl", event_bytes)
    summary = {"schema_version": 1, "capture_format": FORMAT, "run_id": run_id,
        "session_id": session_id, "transport": transport, "protocol_hint": protocol_hint,
        "original_ip": remote_ip, "original_port": remote_port, "upstream_ip": upstream_ip,
        "upstream_port": upstream_port, "capture_kind": capture_kind, "status": status,
        "reason": reason, "profile": "one-request-one-response", "quiet_seconds": quiet_seconds,
        "files": files, "events_sha256": sha256_bytes(event_bytes), "event_count": len(events)}
    temporary = directory / "session.pending"
    _write(temporary, (json.dumps(summary, sort_keys=True, indent=2) + "\n").encode())
    os.link(temporary, directory / "session.json")
    temporary.unlink()
    return directory


def import_message_capture(directory: str | Path, store: ReplayStore, *, protocol_hint: str | None = None) -> CaptureImportResult:
    directory = Path(directory).absolute()
    raw = _read_file(directory / "session.json", 65536)
    summary = _json_object(raw, "message capture")
    _require(type(summary.get("schema_version")) is int and summary["schema_version"] == 1,
             "unsupported message capture schema")
    _require(summary.get("capture_format") == FORMAT, "unsupported message capture format")
    _require(summary.get("status") == "completed" and summary.get("reason") is None, "message capture is incomplete")
    _require(summary.get("profile") == "one-request-one-response", "unsupported datagram profile")
    run_id = _string(summary.get("run_id"), "run_id")
    session_id = _string(summary.get("session_id"), "session_id")
    transport = summary.get("transport")
    _require(transport in ("tcp", "udp"), "unsupported message transport")
    hint = normalize_protocol_hint(summary.get("protocol_hint"))
    _require(transport == "udp" or hint == "dns", "message TCP capture must be DNS")
    _require(protocol_hint is None or normalize_protocol_hint(protocol_hint) == hint,
             "cannot change the message capture protocol")
    _require(summary.get("capture_kind") in ("local_test", "live"), "invalid capture kind")
    quiet = summary.get("quiet_seconds")
    _require(type(quiet) in (int, float) and 0 < quiet <= 1, "invalid response observation window")
    remote_ip = normalize_ip(summary.get("original_ip"))
    remote_port = normalize_port(summary.get("original_port"))
    normalize_ip(summary.get("upstream_ip"))
    normalize_port(summary.get("upstream_port"))
    files = _object(summary.get("files"), "files")
    _require(set(files) == {"request", "response"}, "invalid message capture inventory")
    payloads = {}
    for name in ("request", "response"):
        item = _object(files[name], name)
        _require(item.get("path") == f"{name}.bin", "invalid message payload path")
        limit = min(65507 if transport == "udp" else 65535,
                    store.max_request_bytes if name == "request" else store.max_response_bytes)
        data = _read_file(directory / f"{name}.bin", limit)
        _integer(item.get("size"), f"{name}.size", 0, limit)
        _require(item["size"] == len(data), "message payload size mismatch")
        _check_digest(data, item.get("sha256"), name)
        payloads[name] = data
    events_raw = _read_file(directory / "events.jsonl", 8192)
    _check_digest(events_raw, summary.get("events_sha256"), "events")
    _require(events_raw.endswith(b"\n"), "truncated message events")
    events = [_json_object(line, "event") for line in events_raw.splitlines()]
    expected = [{"sequence": i, "direction": direction, "payload": files[name]}
                for i, (name, direction) in enumerate((("request", "client_to_server"), ("response", "server_to_client")), 1)]
    _require(type(summary.get("event_count")) is int and summary["event_count"] == 2 and events == expected,
             "message events do not describe one complete exchange")
    request, response = payloads["request"], payloads["response"]
    if hint == "dns":
        try:
            request, response = canonical_exchange(request, response)
        except DNSError as exc:
            raise CaptureImportError(f"invalid captured DNS: {exc}") from exc
    provenance = {"schema_version": 1, "importer": FORMAT, "run_id": run_id,
        "session_id": session_id, "capture_kind": summary["capture_kind"],
        "source_files_sha256": {"session.json": sha256_bytes(raw), "events.jsonl": sha256_bytes(events_raw),
                               "request.bin": files["request"]["sha256"], "response.bin": files["response"]["sha256"]},
        "dns_normalization": "id-and-question-case-v1" if hint == "dns" else None,
        "ttl_policy": "recorded-fixed-per-attempt" if hint == "dns" else None,
        "profile": summary["profile"], "quiet_seconds": quiet}
    if store.root.exists() or store.root.is_symlink():
        store.validate()
        existing = store.lookup(transport=transport, remote_ip=remote_ip, remote_port=remote_port,
                                request_bytes=request, protocol_hint=hint)
        if existing.hit:
            if existing.response_bytes != response or not existing.entry.response.close_after_send or existing.entry.response.delay_ms:
                raise ReplayEntryExistsError(f"message capture conflicts with existing response: {existing.entry.entry_id}")
            return CaptureImportResult(existing.entry, False, provenance)
    entry = store.add(transport=transport, remote_ip=remote_ip, remote_port=remote_port,
        request_bytes=request, response_bytes=response, protocol_hint=hint,
        source_run_id=run_id, notes=json.dumps({"capture_import": provenance}, sort_keys=True))
    return CaptureImportResult(entry, True, provenance)
