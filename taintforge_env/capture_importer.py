from __future__ import annotations

import ipaddress
import json
import math
import os
import stat
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from .replay_store import (
    DEFAULT_MAX_REQUEST_BYTES,
    DEFAULT_MAX_RESPONSE_BYTES,
    ReplayEntry,
    ReplayEntryExistsError,
    ReplayStore,
    ReplayStoreValidationError,
    normalize_protocol_hint,
    sha256_bytes
)


MAX_SESSION_BYTES = 64 * 1024
MAX_EVENTS_BYTES = 8 * 1024 * 1024
MAX_EVENTS = 16384
MAX_CHUNK_BYTES = 65536
DIRECTIONS = ("client_to_server", "server_to_client")
CLEAN_CLOSE_REASONS = ("upstream_closed", "client_closed", "completed")


class CaptureImportError(ReplayStoreValidationError):
    pass


@dataclass(frozen=True)
class CaptureTransaction:
    remote_ip: str
    remote_port: int
    request_bytes: bytes
    response_bytes: bytes
    provenance: dict[str, Any]


@dataclass(frozen=True)
class CaptureImportResult:
    entry: ReplayEntry
    created: bool
    provenance: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": "imported" if self.created else "already_present",
            "entry_id": self.entry.entry_id,
            "source": self.provenance
        }


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise CaptureImportError(message)


def _integer(value: Any, label: str, minimum: int, maximum: int) -> int:
    _require(type(value) is int and minimum <= value <= maximum,f"{label} must be an integer in [{minimum}, {maximum}]")
    return value


def _number(value: Any, label: str) -> float:
    _require(type(value) in (int, float), f"{label} must be a number")
    try:
        result = float(value)
    except OverflowError as exc:
        raise CaptureImportError(f"{label} is too large") from exc
    _require(math.isfinite(result) and result >= 0,f"{label} must be a finite non-negative number")
    return result


def _string(value: Any, label: str) -> str:
    _require(isinstance(value, str) and bool(value.strip()) and len(value) <= 256,f"{label} must be a non-empty string of at most 256 characters")
    return value


def _object(value: Any, label: str) -> dict[str, Any]:
    _require(isinstance(value, dict), f"{label} must be an object")
    return value


def _json_object(data: bytes, label: str) -> dict[str, Any]:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            _require(key not in result, f"{label}: duplicate JSON key {key!r}")
            result[key] = value
        return result

    def invalid_constant(value: str) -> None:
        raise CaptureImportError(f"{label}: invalid JSON constant {value}")

    try:
        value = json.loads(data, object_pairs_hook=pairs,
                           parse_constant=invalid_constant)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise CaptureImportError(f"{label}: invalid JSON: {exc}") from exc
    return _object(value, label)


def _no_symlinks(path: Path) -> None:
    for component in (path, *path.absolute().parents):
        _require(not component.is_symlink(),f"capture path must not contain a symlink: {component}")


def _read_file(path: Path, limit: int) -> bytes:
    _no_symlinks(path)
    # O_NONBLOCK avoids hanging on a FIFO before fstat can reject it
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as handle:
            metadata = os.fstat(handle.fileno())
            _require(stat.S_ISREG(metadata.st_mode),f"capture file must be regular: {path}")
            _require(metadata.st_size <= limit, f"capture file exceeds limit: {path}")
            data = handle.read(limit + 1)
            _require(len(data) <= limit, f"capture file exceeds limit: {path}")
            return data
    except OSError as exc:
        raise CaptureImportError(f"cannot read capture file {path}: {exc}") from exc


def _check_digest(data: bytes, expected: Any, label: str) -> None:
    _require(isinstance(expected, str) and sha256_bytes(data) == expected,f"{label}: SHA-256 mismatch")


def _timestamp(value: Any, label: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(_string(value, label))
    except ValueError as exc:
        raise CaptureImportError(f"{label}: invalid timestamp") from exc
    _require(parsed.utcoffset() is not None, f"{label}: timezone is required")
    return parsed


def load_capture_transaction(session_dir: str | Path,*,max_request_bytes: int = DEFAULT_MAX_REQUEST_BYTES,max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES) -> CaptureTransaction:
    root = Path(session_dir)
    _no_symlinks(root)
    summary_bytes = _read_file(root / "session.json", MAX_SESSION_BYTES)
    summary = _json_object(summary_bytes, "session.json")
    _integer(summary.get("schema_version"), "schema_version", 1, 1)
    run_id = _string(summary.get("run_id"), "run_id")
    session_id = _string(summary.get("session_id"), "session_id")
    _require(summary.get("capture_kind") in ("local_test", "live"),
             "unsupported capture_kind")
    _require(summary.get("transport", "tcp") == "tcp", "only TCP is supported")
    _require(summary.get("close_reason") in CLEAN_CLOSE_REASONS,
             "capture did not close cleanly (timeout, error, or incomplete session)")
    _require("error" in summary and summary["error"] is None,
             "capture contains an error")
    started = _timestamp(summary.get("started_at_utc"), "started_at_utc")
    finished = _timestamp(summary.get("finished_at_utc"), "finished_at_utc")
    _require(finished >= started, "session finishes before it starts")
    duration = _number(summary.get("duration_seconds"), "duration_seconds")
    try:
        remote_ip = str(ipaddress.IPv4Address(
            _string(summary.get("original_remote_ip"), "original_remote_ip")))
        ipaddress.ip_address(_string(summary.get("upstream_ip"), "upstream_ip"))
    except ValueError as exc:
        raise CaptureImportError("invalid endpoint; replay requires original IPv4") from exc
    remote_port = _integer(summary.get("original_remote_port"),
                           "original_remote_port", 1, 65535)
    _integer(summary.get("upstream_port"), "upstream_port", 1, 65535)

    limits = _object(summary.get("limits"), "limits")
    payloads: dict[str, bytes] = {}
    stream_metadata: dict[str, dict[str, Any]] = {}
    source_files = {"session.json": sha256_bytes(summary_bytes)}
    for direction, maximum, limit_key in ((DIRECTIONS[0], min(max_request_bytes, DEFAULT_MAX_REQUEST_BYTES), "max_client_bytes"),(DIRECTIONS[1], min(max_response_bytes, DEFAULT_MAX_RESPONSE_BYTES), "max_server_bytes")):
        metadata = _object(summary.get(direction), direction)
        expected_path = f"{direction}.bin"
        _require(metadata.get("path") == expected_path,
                 f"{direction}: non-canonical payload path")
        size = _integer(metadata.get("bytes"), f"{direction}.bytes", 1, maximum)
        limit = _integer(limits.get(limit_key), limit_key, 1, DEFAULT_MAX_RESPONSE_BYTES)
        _require(size <= limit, f"{direction}: recorded byte limit exceeded")
        _integer(metadata.get("chunks"), f"{direction}.chunks", 1, MAX_EVENTS)
        payload = _read_file(root / expected_path, maximum)
        _require(len(payload) == size, f"{direction}: size mismatch")
        _check_digest(payload, metadata.get("sha256"), direction)
        payloads[direction] = payload
        stream_metadata[direction] = metadata
        source_files[expected_path] = sha256_bytes(payload)

    events_bytes = _read_file(root / "events.jsonl", MAX_EVENTS_BYTES)
    _require(events_bytes.endswith(b"\n"), "events.jsonl is truncated")
    lines = events_bytes.splitlines()
    _require(5 <= len(lines) <= MAX_EVENTS, "events.jsonl: invalid event count")
    events = [_json_object(line, f"events.jsonl:{i}") for i, line in enumerate(lines, 1)]
    _require(events[0].get("event") == "session_started", "missing session_started")
    _require(events[1].get("event") == "upstream_connected", "missing upstream_connected")
    _require(events[-1].get("event") == "session_finished", "missing session_finished")
    for key in ("original_remote_ip", "original_remote_port", "upstream_ip","upstream_port", "capture_kind"):
        _require(type(events[0].get(key)) is type(summary[key]) and events[0][key] == summary[key], f"session_started: {key} mismatch")
    for key in ("upstream_ip", "upstream_port"):
        _require(type(events[1].get(key)) is type(summary[key]) and events[1][key] == summary[key], f"upstream_connected: {key} mismatch")
    final = events[-1]
    _require(final.get("close_reason") == summary["close_reason"] and "error" in final and final["error"] is None, "session_finished disagrees with summary")
    for key, direction in (("client_bytes", DIRECTIONS[0]), ("server_bytes", DIRECTIONS[1])):
        size = _integer(final.get(key), f"session_finished.{key}", 1, DEFAULT_MAX_RESPONSE_BYTES)
        _require(size == len(payloads[direction]), f"session_finished: {key} mismatch")
    for event in events:
        _require(event.get("session_id") == session_id, "event session_id mismatch")
        _timestamp(event.get("timestamp_utc"), "event.timestamp_utc")

    offsets = dict.fromkeys(DIRECTIONS, 0)
    counts = dict.fromkeys(DIRECTIONS, 0)
    eof: set[str] = set()
    chunk_names: set[str] = set()
    response_started = False
    last_elapsed = 0.0
    for event in events[2:-1]:
        kind = event.get("event")
        _require(kind in ("stream_chunk", "stream_eof"), f"unexpected capture event: {kind}")
        direction = event.get("direction")
        _require(direction in DIRECTIONS, "invalid stream direction")
        _require(direction not in eof, f"{direction}: data or duplicate EOF after EOF")
        if kind == "stream_eof":
            eof.add(direction)
            continue
        if direction == DIRECTIONS[0]:
            _require(not response_started, "interleaved/multi-round capture is unsupported")
        else:
            _require(offsets[DIRECTIONS[0]] > 0, "server-first capture is unsupported")
            response_started = True
        index = _integer(event.get("chunk_index"), "chunk_index", 1, MAX_EVENTS)
        _require(index == counts[direction] + 1, "missing or reordered chunk index")
        size = _integer(event.get("size"), "chunk.size", 1, MAX_CHUNK_BYTES)
        elapsed = _number(event.get("elapsed_seconds"), "elapsed_seconds")
        _require(last_elapsed <= elapsed <= duration, "chunk elapsed time is out of order/range")
        last_elapsed = elapsed
        name = f"{index:06d}_{direction}.bin"
        _require(event.get("payload_file") == f"chunks/{name}", "non-canonical chunk path")
        chunk = _read_file(root / "chunks" / name, MAX_CHUNK_BYTES)
        _require(len(chunk) == size, "chunk size mismatch")
        _check_digest(chunk, event.get("sha256"), name)
        offset = offsets[direction]
        _require(payloads[direction][offset:offset + size] == chunk,
                 f"{direction}: chunks disagree with aggregate stream")
        offsets[direction] += size
        counts[direction] += 1
        chunk_names.add(name)
    _require(DIRECTIONS[1] in eof, "response is incomplete: missing upstream EOF")
    for direction in DIRECTIONS:
        _require(offsets[direction] == len(payloads[direction]) and counts[direction] == stream_metadata[direction]["chunks"],f"{direction}: missing chunks or count mismatch")
    _no_symlinks(root / "chunks")
    with os.scandir(root / "chunks") as entries:
        for item in entries:
            _require(item.name in chunk_names, f"unreferenced capture chunk: {item.name}")
    source_files["events.jsonl"] = sha256_bytes(events_bytes)
    provenance = {
        "schema_version": 1,
        "importer": "c2-capture-single-transaction-v1",
        "run_id": run_id,
        "session_id": session_id,
        "capture_kind": summary["capture_kind"],
        "source_files_sha256": source_files,
        "close_reason": summary["close_reason"],
        "replay_policy": {"close_after_send": True, "delay_ms": 0}
    }
    return CaptureTransaction(remote_ip, remote_port, payloads[DIRECTIONS[0]],payloads[DIRECTIONS[1]], provenance)


def import_capture(session_dir: str | Path,store: ReplayStore,*,protocol_hint: str | None = None) -> CaptureImportResult:
    summary = _json_object(_read_file(Path(session_dir) / 'session.json', MAX_SESSION_BYTES), 'session')
    if summary.get('capture_format') is not None:
        from .message_capture import import_message_capture
        return import_message_capture(session_dir, store, protocol_hint=protocol_hint)
    capture = load_capture_transaction(
        session_dir, max_request_bytes=store.max_request_bytes,
        max_response_bytes=store.max_response_bytes)
    captured_hint = normalize_protocol_hint(summary.get('protocol_hint'))
    hint = captured_hint if protocol_hint is None else normalize_protocol_hint(protocol_hint)
    _require(captured_hint is None or hint == captured_hint, 'cannot change the captured protocol hint')
    if store.root.exists() or store.root.is_symlink():
        store.validate()
        exchanges = store.exchanges_for_endpoint(
            transport="tcp", remote_ip=capture.remote_ip,
            remote_port=capture.remote_port, protocol_hint=hint)
        for exchange in exchanges:
            if exchange.request_bytes == capture.request_bytes:
                response = exchange.entry.response
                if (exchange.response_bytes != capture.response_bytes
                        or not response.close_after_send or response.delay_ms != 0):
                    raise ReplayEntryExistsError(
                        f"capture conflicts with existing response/policy: {exchange.entry.entry_id}")
                return CaptureImportResult(exchange.entry, False, capture.provenance)
            if (exchange.request_bytes.startswith(capture.request_bytes)
                    or capture.request_bytes.startswith(exchange.request_bytes)):
                raise CaptureImportError("capture would introduce TCP request prefix ambiguity")
    entry = store.add(transport="tcp", remote_ip=capture.remote_ip, remote_port=capture.remote_port,request_bytes=capture.request_bytes, response_bytes=capture.response_bytes,protocol_hint=hint, close_after_send=True, delay_ms=0,source_run_id=capture.provenance["run_id"],notes=json.dumps({"capture_import": capture.provenance}, sort_keys=True))
    return CaptureImportResult(entry, True, capture.provenance)
