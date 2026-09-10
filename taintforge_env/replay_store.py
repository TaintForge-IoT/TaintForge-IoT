from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import tempfile
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA_VERSION = 1
DEFAULT_MAX_REQUEST_BYTES = 1024 * 1024
DEFAULT_MAX_RESPONSE_BYTES = 16 * 1024 * 1024
SUPPORTED_TRANSPORTS = {"tcp", "udp"}


class ReplayStoreError(RuntimeError):
    pass


class ReplayStoreValidationError(ReplayStoreError):
    pass


class ReplayEntryExistsError(ReplayStoreError):
    pass


@dataclass(slots=True, frozen=True)
class ReplayRequest:
    transport: str
    remote_ip: str
    remote_port: int
    payload_sha256: str
    payload_size: int
    protocol_hint: str | None = None

    def canonical_dict(self) -> dict[str, Any]:
        return {"transport": self.transport,"remote_ip": self.remote_ip,"remote_port": self.remote_port,"payload_sha256": self.payload_sha256,"payload_size": self.payload_size,"protocol_hint": self.protocol_hint}

    def fingerprint(self) -> str:
        canonical = json.dumps(self.canonical_dict(),sort_keys=True,separators=(",", ":"),ensure_ascii=True).encode("utf-8")
        return hashlib.sha256(canonical).hexdigest()


@dataclass(slots=True, frozen=True)
class ReplayResponse:
    blob_path: str
    sha256: str
    size: int
    close_after_send: bool = True
    delay_ms: int = 0


@dataclass(slots=True, frozen=True)
class ReplayEntry:
    entry_id: str
    created_at_utc: str
    request: ReplayRequest
    response: ReplayResponse
    source_run_id: str | None = None
    notes: str | None = None


@dataclass(slots=True, frozen=True)
class ReplayLookup:
    hit: bool
    fingerprint: str
    entry: ReplayEntry | None
    response_bytes: bytes | None


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()

    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)

    return digest.hexdigest()


def normalize_transport(value: str) -> str:
    normalized = value.strip().lower()

    if normalized not in SUPPORTED_TRANSPORTS:
        raise ReplayStoreValidationError(f"Unsupported transport: {value}. Expected one of: {sorted(SUPPORTED_TRANSPORTS)}")

    return normalized


def normalize_ip(value: str) -> str:
    try:
        return str(ipaddress.ip_address(value))
    except ValueError as exc:
        raise ReplayStoreValidationError(f"Invalid IP address: {value}") from exc


def normalize_port(value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ReplayStoreValidationError("Remote port must be an integer")

    if not 1 <= value <= 65535:
        raise ReplayStoreValidationError(f"Remote port is out of range: {value}")

    return value


def normalize_protocol_hint(value: str | None) -> str | None:
    if value is None:
        return None

    normalized = value.strip().lower()

    if not normalized:
        return None

    if len(normalized) > 64:
        raise ReplayStoreValidationError("protocol_hint is too long")

    return normalized


def safe_relative_path(value: str) -> Path:
    path = Path(value)

    if path.is_absolute():
        raise ReplayStoreValidationError(f"Replay blob path must be relative: {value}")

    if ".." in path.parts:
        raise ReplayStoreValidationError(f"Replay blob path must not contain '..': {value}")

    return path


def parse_request(raw: dict[str, Any]) -> ReplayRequest:
    try:
        payload_sha256 = str(raw["payload_sha256"])
        payload_size = int(raw["payload_size"])
    except (KeyError, TypeError, ValueError) as exc:
        raise ReplayStoreValidationError("Replay request is missing valid payload metadata") from exc

    if len(payload_sha256) != 64:
        raise ReplayStoreValidationError("Request payload_sha256 must contain 64 hex characters")

    try:
        int(payload_sha256, 16)
    except ValueError as exc:
        raise ReplayStoreValidationError("Request payload_sha256 is not hexadecimal") from exc

    if payload_size < 0:
        raise ReplayStoreValidationError("Request payload_size must not be negative")

    return ReplayRequest(transport=normalize_transport(str(raw.get("transport",""))),remote_ip=normalize_ip(str(raw.get("remote_ip",""))),remote_port=normalize_port(int(raw.get("remote_port",0))),payload_sha256=payload_sha256.lower(),payload_size=payload_size,protocol_hint=normalize_protocol_hint(raw.get("protocol_hint")))


def parse_response(raw: dict[str, Any]) -> ReplayResponse:
    try:
        blob_path = str(raw["blob_path"])
        digest = str(raw["sha256"])
        size = int(raw["size"])
        delay_ms = int(raw.get("delay_ms", 0))
    except (KeyError, TypeError, ValueError) as exc:
        raise ReplayStoreValidationError("Replay response is missing valid metadata") from exc

    safe_relative_path(blob_path)

    if len(digest) != 64:
        raise ReplayStoreValidationError("Response sha256 must contain 64 hex characters")

    try:
        int(digest, 16)
    except ValueError as exc:
        raise ReplayStoreValidationError("Response sha256 is not hexadecimal") from exc

    if size < 0:
        raise ReplayStoreValidationError("Response size must not be negative")

    if delay_ms < 0 or delay_ms > 60_000:
        raise ReplayStoreValidationError("Response delay_ms must be between 0 and 60000")

    return ReplayResponse(blob_path=blob_path,sha256=digest.lower(),size=size,close_after_send=bool(raw.get("close_after_send", True)),delay_ms=delay_ms)


def parse_entry(raw: dict[str, Any]) -> ReplayEntry:
    try:
        entry_id = str(raw["entry_id"])
        created_at_utc = str(raw["created_at_utc"])
        request_raw = raw["request"]
        response_raw = raw["response"]
    except KeyError as exc:
        raise ReplayStoreValidationError(f"Replay entry is missing field: {exc}") from exc

    if not isinstance(request_raw, dict) or not isinstance(response_raw, dict):
        raise ReplayStoreValidationError("Replay entry request/response must be objects")

    request = parse_request(request_raw)
    response = parse_response(response_raw)

    if entry_id != request.fingerprint():
        raise ReplayStoreValidationError(f"Replay entry ID does not match request fingerprint: {entry_id}")

    source_run_id = raw.get("source_run_id")
    notes = raw.get("notes")

    return ReplayEntry(entry_id=entry_id,created_at_utc=created_at_utc,request=request,response=response,source_run_id=str(source_run_id) if source_run_id is not None else None,notes=str(notes) if notes is not None else None)


class ReplayStore:
    def __init__(self,root: str | Path,*,max_request_bytes: int = DEFAULT_MAX_REQUEST_BYTES,max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES) -> None:
        self.root = Path(root)
        self.index_path = self.root / "index.json"
        self.requests_dir = self.root / "requests"
        self.responses_dir = self.root / "responses"
        self.max_request_bytes = max_request_bytes
        self.max_response_bytes = max_response_bytes

    def initialize(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        self.requests_dir.mkdir(parents=True, exist_ok=True)
        self.responses_dir.mkdir(parents=True, exist_ok=True)

        if not self.index_path.exists():
            self._atomic_write_index(
                {
                    "schema_version": SCHEMA_VERSION,
                    "entries": [],
                }
            )

        self._chmod_private(self.root, directory=True)
        self._chmod_private(self.requests_dir, directory=True)
        self._chmod_private(self.responses_dir, directory=True)
        self._chmod_private(self.index_path)

    def load_entries(self) -> list[ReplayEntry]:
        raw = self._load_index()
        entries_raw = raw.get("entries")

        if not isinstance(entries_raw, list):
            raise ReplayStoreValidationError("Replay index entries must be a list")

        return [parse_entry(item) for item in entries_raw]

    def add(self,*,transport: str,remote_ip: str,remote_port: int,request_bytes: bytes,response_bytes: bytes,protocol_hint: str | None = None,close_after_send: bool = True,delay_ms: int = 0,source_run_id: str | None = None,notes: str | None = None,replace: bool = False) -> ReplayEntry:
        self.initialize()

        if len(request_bytes) > self.max_request_bytes:
            raise ReplayStoreValidationError(
                f"Request exceeds replay limit: "
                f"{len(request_bytes)} > {self.max_request_bytes}"
            )

        if len(response_bytes) > self.max_response_bytes:
            raise ReplayStoreValidationError(f"Response exceeds replay limit: {len(response_bytes)} > {self.max_response_bytes}")

        request= ReplayRequest(transport=normalize_transport(transport),remote_ip=normalize_ip(remote_ip),remote_port=normalize_port(remote_port),payload_sha256=sha256_bytes(request_bytes),payload_size=len(request_bytes),protocol_hint=normalize_protocol_hint(protocol_hint))

        entry_id = request.fingerprint()
        entries = self.load_entries()

        if any(item.entry_id == entry_id for item in entries) and not replace:
            raise ReplayEntryExistsError(f"Replay entry already exists: {entry_id}")

        request_rel = Path("requests") / f"{entry_id}.bin"
        response_digest = sha256_bytes(response_bytes)
        response_rel = Path("responses") / f"{response_digest}.bin"

        self._write_blob(self.root / request_rel, request_bytes)
        self._write_blob(self.root / response_rel, response_bytes)

        entry = ReplayEntry(entry_id=entry_id,created_at_utc=datetime.now(timezone.utc).isoformat(),request=request,response=ReplayResponse(blob_path=str(response_rel),sha256=response_digest,size=len(response_bytes),close_after_send=close_after_send,delay_ms=delay_ms),source_run_id=source_run_id,notes=notes)

        updated = [
            current for current in entries if current.entry_id != entry_id
        ]
        updated.append(entry)
        updated.sort(key=lambda item: item.entry_id)

        self._atomic_write_index(
            {
                "schema_version": SCHEMA_VERSION,
                "entries": [asdict(item) for item in updated],
            }
        )

        return entry

    def add_from_files(self,*,transport: str,remote_ip: str,remote_port: int,request_path: str | Path,response_path: str | Path,protocol_hint: str | None = None,close_after_send: bool = True,delay_ms: int = 0,source_run_id: str | None = None,notes: str | None = None,replace: bool = False) -> ReplayEntry:
        request_path = Path(request_path)
        response_path = Path(response_path)

        if not request_path.is_file():
            raise ReplayStoreValidationError(f"Request file does not exist: {request_path}")

        if not response_path.is_file():
            raise ReplayStoreValidationError(f"Response file does not exist: {response_path}")

        return self.add(transport=transport,remote_ip=remote_ip,remote_port=remote_port,request_bytes=request_path.read_bytes(),response_bytes=response_path.read_bytes(),protocol_hint=protocol_hint,close_after_send=close_after_send,delay_ms=delay_ms,source_run_id=source_run_id,notes=notes,replace=replace)

    def lookup(self,*,transport: str,remote_ip: str,remote_port: int,request_bytes: bytes,protocol_hint: str | None = None) -> ReplayLookup:
        request = ReplayRequest(transport=normalize_transport(transport),remote_ip=normalize_ip(remote_ip),remote_port=normalize_port(remote_port),payload_sha256=sha256_bytes(request_bytes),payload_size=len(request_bytes),protocol_hint=normalize_protocol_hint(protocol_hint)
        fingerprint = request.fingerprint()

        for entry in self.load_entries():
            if entry.entry_id != fingerprint:
                continue

            blob_path = self.root / safe_relative_path(entry.response.blob_path)

            if not blob_path.is_file():
                raise ReplayStoreValidationError(f"Replay response blob is missing: {blob_path}")

            response_bytes = blob_path.read_bytes()

            if len(response_bytes) != entry.response.size:
                raise ReplayStoreValidationError(f"Replay response size mismatch: {blob_path}")

            if sha256_bytes(response_bytes) != entry.response.sha256:
                raise ReplayStoreValidationError(f"Replay response digest mismatch: {blob_path}")

            return ReplayLookup(hit=True,fingerprint=fingerprint,entry=entry,response_bytes=response_bytes)

        return ReplayLookup(hit=False,fingerprint=fingerprint,entry=None,response_bytes=None)

    def validate(self) -> dict[str, Any]:
        entries = self.load_entries()
        errors: list[str] = []

        for entry in entries:
            response_path = self.root / safe_relative_path(entry.response.blob_path)

            if not response_path.is_file():
                errors.append(f"missing response blob for {entry.entry_id}: {response_path}")
                continue

            actual_size = response_path.stat().st_size
            actual_digest = sha256_file(response_path)

            if actual_size != entry.response.size:
                errors.append(
                    f"size mismatch for {entry.entry_id}: {actual_size} != {entry.response.size}")

            if actual_digest != entry.response.sha256:
                errors.append(
                    f"sha256 mismatch for {entry.entry_id}: {actual_digest} != {entry.response.sha256}")

        if errors:
            raise ReplayStoreValidationError("Replay store validation failed:\n- " + "\n- ".join(errors))

        return {"schema_version": SCHEMA_VERSION,"entries": len(entries),"store_path": str(self.root)}

    def _load_index(self) -> dict[str, Any]:
        if not self.index_path.exists():
            raise ReplayStoreValidationError(f"Replay index does not exist: {self.index_path")

        try:
            raw = json.loads(self.index_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ReplayStoreValidationError(f"Invalid replay index JSON: {exc}") from exc

        if not isinstance(raw, dict):
            raise ReplayStoreValidationError("Replay index root must be an object")

        if raw.get("schema_version") != SCHEMA_VERSION:
            raise ReplayStoreValidationError(f"Unsupported replay schema_version: {raw.get('schema_version')}")

        return raw

    def _atomic_write_index(self, data: dict[str, Any]) -> None:
        self.root.mkdir(parents=True, exist_ok=True)

        fd, temp_name = tempfile.mkstemp(prefix=".index.",suffix=".json.tmp",dir=self.root)
        temp_path = Path(temp_name)

        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(data,handle,indent=2,ensure_ascii=False,sort_keys=True)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())

            os.chmod(temp_path, 0o600)
            temp_path.replace(self.index_path)
            self._chmod_private(self.index_path)
        finally:
            temp_path.unlink(missing_ok=True)

    def _write_blob(self, path: Path, data: bytes) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)

        if path.exists():
            if path.read_bytes() != data:
                raise ReplayStoreValidationError(f"Replay blob collision: {path}")
            return

        fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.",suffix=".tmp",dir=path.parent)
        temp_path = Path(temp_name)

        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())

            os.chmod(temp_path, 0o600)
            temp_path.replace(path)
            self._chmod_private(path)
        finally:
            temp_path.unlink(missing_ok=True)

    @staticmethod
    def _chmod_private(path: Path, *, directory: bool = False) -> None:
        try:
            path.chmod(0o700 if directory else 0o600)
        except FileNotFoundError:
            return
