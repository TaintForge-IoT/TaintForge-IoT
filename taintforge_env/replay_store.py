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
        return {
            "transport": self.transport,
            "remote_ip": self.remote_ip,
            "remote_port": self.remote_port,
            "payload_sha256": self.payload_sha256,
            "payload_size": self.payload_size,
            "protocol_hint": self.protocol_hint,
        }

    def fingerprint(self) -> str:
        canonical = json.dumps(
            self.canonical_dict(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
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


@dataclass(slots=True, frozen=True)
class ReplayExchange:
    """One integrity-checked request/response exchange ready for replay."""

    entry: ReplayEntry
    request_bytes: bytes
    response_bytes: bytes


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
        raise ReplayStoreValidationError(
            f"Unsupported transport: {value}. "
            f"Expected one of: {sorted(SUPPORTED_TRANSPORTS)}"
        )

    return normalized


def normalize_ip(value: str) -> str:
    try:
        return str(ipaddress.ip_address(value))
    except ValueError as exc:
        raise ReplayStoreValidationError(
            f"Invalid IP address: {value}"
        ) from exc


def normalize_port(value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ReplayStoreValidationError(
            "Remote port must be an integer"
        )

    if not 1 <= value <= 65535:
        raise ReplayStoreValidationError(
            f"Remote port is out of range: {value}"
        )

    return value


def normalize_protocol_hint(value: str | None) -> str | None:
    if value is None:
        return None

    normalized = value.strip().lower()

    if not normalized:
        return None

    if len(normalized) > 64:
        raise ReplayStoreValidationError(
            "protocol_hint is too long"
        )

    return normalized


def safe_relative_path(value: str) -> Path:
    path = Path(value)

    if path.is_absolute():
        raise ReplayStoreValidationError(
            f"Replay blob path must be relative: {value}"
        )

    if ".." in path.parts:
        raise ReplayStoreValidationError(
            f"Replay blob path must not contain '..': {value}"
        )

    return path


def parse_request(raw: dict[str, Any]) -> ReplayRequest:
    try:
        payload_sha256 = str(raw["payload_sha256"])
        payload_size = int(raw["payload_size"])
    except (KeyError, TypeError, ValueError) as exc:
        raise ReplayStoreValidationError(
            "Replay request is missing valid payload metadata"
        ) from exc

    if len(payload_sha256) != 64:
        raise ReplayStoreValidationError(
            "Request payload_sha256 must contain 64 hex characters"
        )

    try:
        int(payload_sha256, 16)
    except ValueError as exc:
        raise ReplayStoreValidationError(
            "Request payload_sha256 is not hexadecimal"
        ) from exc

    if payload_size < 0:
        raise ReplayStoreValidationError(
            "Request payload_size must not be negative"
        )

    return ReplayRequest(
        transport=normalize_transport(str(raw.get("transport", ""))),
        remote_ip=normalize_ip(str(raw.get("remote_ip", ""))),
        remote_port=normalize_port(int(raw.get("remote_port", 0))),
        payload_sha256=payload_sha256.lower(),
        payload_size=payload_size,
        protocol_hint=normalize_protocol_hint(raw.get("protocol_hint")),
    )


def parse_response(raw: dict[str, Any]) -> ReplayResponse:
    try:
        blob_path = str(raw["blob_path"])
        digest = str(raw["sha256"])
        size = int(raw["size"])
        delay_ms = int(raw.get("delay_ms", 0))
    except (KeyError, TypeError, ValueError) as exc:
        raise ReplayStoreValidationError(
            "Replay response is missing valid metadata"
        ) from exc

    relative_blob_path = safe_relative_path(blob_path)

    if len(digest) != 64:
        raise ReplayStoreValidationError(
            "Response sha256 must contain 64 hex characters"
        )

    try:
        int(digest, 16)
    except ValueError as exc:
        raise ReplayStoreValidationError(
            "Response sha256 is not hexadecimal"
        ) from exc

    expected_blob_path = Path("responses") / f"{digest.lower()}.bin"
    if relative_blob_path != expected_blob_path:
        raise ReplayStoreValidationError(
            "Response blob_path must match its content digest: "
            f"expected {expected_blob_path}, got {relative_blob_path}"
        )

    if size < 0:
        raise ReplayStoreValidationError(
            "Response size must not be negative"
        )

    if delay_ms < 0 or delay_ms > 60_000:
        raise ReplayStoreValidationError(
            "Response delay_ms must be between 0 and 60000"
        )

    return ReplayResponse(
        blob_path=blob_path,
        sha256=digest.lower(),
        size=size,
        close_after_send=bool(raw.get("close_after_send", True)),
        delay_ms=delay_ms,
    )


def parse_entry(raw: dict[str, Any]) -> ReplayEntry:
    try:
        entry_id = str(raw["entry_id"])
        created_at_utc = str(raw["created_at_utc"])
        request_raw = raw["request"]
        response_raw = raw["response"]
    except KeyError as exc:
        raise ReplayStoreValidationError(
            f"Replay entry is missing field: {exc}"
        ) from exc

    if not isinstance(request_raw, dict) or not isinstance(response_raw, dict):
        raise ReplayStoreValidationError(
            "Replay entry request/response must be objects"
        )

    request = parse_request(request_raw)
    response = parse_response(response_raw)

    if entry_id != request.fingerprint():
        raise ReplayStoreValidationError(
            f"Replay entry ID does not match request fingerprint: {entry_id}"
        )

    source_run_id = raw.get("source_run_id")
    notes = raw.get("notes")

    return ReplayEntry(
        entry_id=entry_id,
        created_at_utc=created_at_utc,
        request=request,
        response=response,
        source_run_id=str(source_run_id) if source_run_id is not None else None,
        notes=str(notes) if notes is not None else None,
    )


class ReplayStore:
    def __init__(
        self,
        root: str | Path,
        *,
        max_request_bytes: int = DEFAULT_MAX_REQUEST_BYTES,
        max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
    ) -> None:
        self.root = Path(root)
        self.index_path = self.root / "index.json"
        self.requests_dir = self.root / "requests"
        self.responses_dir = self.root / "responses"
        self.max_request_bytes = max_request_bytes
        self.max_response_bytes = max_response_bytes

    def initialize(self) -> None:
        self._validate_layout_symlinks(allow_missing=True)
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
            raise ReplayStoreValidationError(
                "Replay index entries must be a list"
            )

        return [parse_entry(item) for item in entries_raw]

    def add(
        self,
        *,
        transport: str,
        remote_ip: str,
        remote_port: int,
        request_bytes: bytes,
        response_bytes: bytes,
        protocol_hint: str | None = None,
        close_after_send: bool = True,
        delay_ms: int = 0,
        source_run_id: str | None = None,
        notes: str | None = None,
        replace: bool = False,
    ) -> ReplayEntry:
        self.initialize()

        if len(request_bytes) > self.max_request_bytes:
            raise ReplayStoreValidationError(
                f"Request exceeds replay limit: "
                f"{len(request_bytes)} > {self.max_request_bytes}"
            )

        if len(response_bytes) > self.max_response_bytes:
            raise ReplayStoreValidationError(
                f"Response exceeds replay limit: "
                f"{len(response_bytes)} > {self.max_response_bytes}"
            )

        request = ReplayRequest(
            transport=normalize_transport(transport),
            remote_ip=normalize_ip(remote_ip),
            remote_port=normalize_port(remote_port),
            payload_sha256=sha256_bytes(request_bytes),
            payload_size=len(request_bytes),
            protocol_hint=normalize_protocol_hint(protocol_hint),
        )

        entry_id = request.fingerprint()
        entries = self.load_entries()

        if any(item.entry_id == entry_id for item in entries) and not replace:
            raise ReplayEntryExistsError(
                f"Replay entry already exists: {entry_id}"
            )

        request_rel = Path("requests") / f"{entry_id}.bin"
        response_digest = sha256_bytes(response_bytes)
        response_rel = Path("responses") / f"{response_digest}.bin"

        self._write_blob(self.root / request_rel, request_bytes)
        self._write_blob(self.root / response_rel, response_bytes)

        entry = ReplayEntry(
            entry_id=entry_id,
            created_at_utc=datetime.now(timezone.utc).isoformat(),
            request=request,
            response=ReplayResponse(
                blob_path=str(response_rel),
                sha256=response_digest,
                size=len(response_bytes),
                close_after_send=close_after_send,
                delay_ms=delay_ms,
            ),
            source_run_id=source_run_id,
            notes=notes,
        )

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

    def add_from_files(
        self,
        *,
        transport: str,
        remote_ip: str,
        remote_port: int,
        request_path: str | Path,
        response_path: str | Path,
        protocol_hint: str | None = None,
        close_after_send: bool = True,
        delay_ms: int = 0,
        source_run_id: str | None = None,
        notes: str | None = None,
        replace: bool = False,
    ) -> ReplayEntry:
        request_path = Path(request_path)
        response_path = Path(response_path)

        if not request_path.is_file():
            raise ReplayStoreValidationError(
                f"Request file does not exist: {request_path}"
            )

        if not response_path.is_file():
            raise ReplayStoreValidationError(
                f"Response file does not exist: {response_path}"
            )

        return self.add(
            transport=transport,
            remote_ip=remote_ip,
            remote_port=remote_port,
            request_bytes=request_path.read_bytes(),
            response_bytes=response_path.read_bytes(),
            protocol_hint=protocol_hint,
            close_after_send=close_after_send,
            delay_ms=delay_ms,
            source_run_id=source_run_id,
            notes=notes,
            replace=replace,
        )

    def lookup(
        self,
        *,
        transport: str,
        remote_ip: str,
        remote_port: int,
        request_bytes: bytes,
        protocol_hint: str | None = None,
    ) -> ReplayLookup:
        request = ReplayRequest(
            transport=normalize_transport(transport),
            remote_ip=normalize_ip(remote_ip),
            remote_port=normalize_port(remote_port),
            payload_sha256=sha256_bytes(request_bytes),
            payload_size=len(request_bytes),
            protocol_hint=normalize_protocol_hint(protocol_hint),
        )
        fingerprint = request.fingerprint()

        for entry in self.load_entries():
            if entry.entry_id != fingerprint:
                continue

            exchange = self.load_exchange(entry)

            return ReplayLookup(
                hit=True,
                fingerprint=fingerprint,
                entry=entry,
                response_bytes=exchange.response_bytes,
            )

        return ReplayLookup(
            hit=False,
            fingerprint=fingerprint,
            entry=None,
            response_bytes=None,
        )

    def load_exchange(self, entry: ReplayEntry) -> ReplayExchange:
        """Load and verify both blobs referenced by one replay entry."""

        self._validate_layout_symlinks(allow_missing=False)
        request_path = self.request_blob_path(entry)
        response_path = self.response_blob_path(entry)
        self._validate_blob_path(request_path, "request")
        self._validate_blob_path(response_path, "response")
        request_bytes = self._read_verified_blob(
            request_path,
            expected_size=entry.request.payload_size,
            expected_sha256=entry.request.payload_sha256,
            label="request",
        )
        response_bytes = self._read_verified_blob(
            response_path,
            expected_size=entry.response.size,
            expected_sha256=entry.response.sha256,
            label="response",
        )
        return ReplayExchange(
            entry=entry,
            request_bytes=request_bytes,
            response_bytes=response_bytes,
        )

    def exchanges_for_endpoint(
        self,
        *,
        transport: str,
        remote_ip: str,
        remote_port: int,
        protocol_hint: str | None = None,
    ) -> list[ReplayExchange]:
        """Return verified exchanges for one exact endpoint contract."""

        normalized_transport = normalize_transport(transport)
        normalized_ip = normalize_ip(remote_ip)
        normalized_port = normalize_port(remote_port)
        normalized_hint = normalize_protocol_hint(protocol_hint)
        matches = [
            self.load_exchange(entry)
            for entry in self.load_entries()
            if entry.request.transport == normalized_transport
            and entry.request.remote_ip == normalized_ip
            and entry.request.remote_port == normalized_port
            and entry.request.protocol_hint == normalized_hint
        ]
        matches.sort(key=lambda item: item.entry.entry_id)
        if normalized_transport == "tcp":
            self._validate_tcp_framing(matches)
        return matches

    def request_blob_path(self, entry: ReplayEntry) -> Path:
        return self.root / "requests" / f"{entry.entry_id}.bin"

    def response_blob_path(self, entry: ReplayEntry) -> Path:
        return self.root / safe_relative_path(entry.response.blob_path)

    def validate(self) -> dict[str, Any]:
        self._validate_layout_symlinks(allow_missing=False)
        entries = self.load_entries()
        errors: list[str] = []

        exchanges: list[ReplayExchange] = []

        for entry in entries:
            try:
                exchanges.append(self.load_exchange(entry))
            except ReplayStoreValidationError as exc:
                errors.append(str(exc))

        groups: dict[tuple[str, str, int, str | None], list[ReplayExchange]] = {}
        for exchange in exchanges:
            request = exchange.entry.request
            key = (
                request.transport,
                request.remote_ip,
                request.remote_port,
                request.protocol_hint,
            )
            groups.setdefault(key, []).append(exchange)
        for key, group in groups.items():
            if key[0] != "tcp":
                continue
            try:
                self._validate_tcp_framing(group)
            except ReplayStoreValidationError as exc:
                errors.append(str(exc))

        if errors:
            raise ReplayStoreValidationError(
                "Replay store validation failed:\n- "
                + "\n- ".join(errors)
            )

        identity_payload = {
            "schema_version": SCHEMA_VERSION,
            "entries": [
                {
                    "entry_id": exchange.entry.entry_id,
                    "request": exchange.entry.request.canonical_dict(),
                    "response": {
                        "sha256": exchange.entry.response.sha256,
                        "size": exchange.entry.response.size,
                        "close_after_send": (
                            exchange.entry.response.close_after_send
                        ),
                        "delay_ms": exchange.entry.response.delay_ms,
                    },
                }
                for exchange in sorted(
                    exchanges,
                    key=lambda item: item.entry.entry_id,
                )
            ],
        }
        store_sha256 = sha256_bytes(
            json.dumps(
                identity_payload,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            ).encode("utf-8")
        )
        return {
            "schema_version": SCHEMA_VERSION,
            "entries": len(entries),
            "store_path": str(self.root),
            "store_sha256": store_sha256,
        }

    @staticmethod
    def _validate_tcp_framing(exchanges: list[ReplayExchange]) -> None:
        """Reject byte streams that cannot be framed without guessing."""

        ordered = sorted(exchanges, key=lambda item: item.request_bytes)
        for exchange in ordered:
            if not exchange.request_bytes:
                raise ReplayStoreValidationError(
                    "TCP replay requests must not be empty: "
                    f"{exchange.entry.entry_id}"
                )
        for index, current in enumerate(ordered):
            for candidate in ordered[index + 1 :]:
                if not candidate.request_bytes.startswith(current.request_bytes):
                    break
                raise ReplayStoreValidationError(
                    "TCP replay request prefix ambiguity for endpoint "
                    f"{current.entry.request.remote_ip}:"
                    f"{current.entry.request.remote_port}: "
                    f"{current.entry.entry_id} prefixes "
                    f"{candidate.entry.entry_id}"
                )

    @staticmethod
    def _read_verified_blob(
        path: Path,
        *,
        expected_size: int,
        expected_sha256: str,
        label: str,
    ) -> bytes:
        if path.is_symlink():
            raise ReplayStoreValidationError(
                f"Replay {label} blob must not be a symlink: {path}"
            )
        if not path.is_file():
            raise ReplayStoreValidationError(
                f"Replay {label} blob is missing: {path}"
            )
        data = path.read_bytes()
        if len(data) != expected_size:
            raise ReplayStoreValidationError(
                f"Replay {label} size mismatch: {path}"
            )
        if sha256_bytes(data) != expected_sha256:
            raise ReplayStoreValidationError(
                f"Replay {label} digest mismatch: {path}"
            )
        return data

    def _load_index(self) -> dict[str, Any]:
        self._validate_layout_symlinks(allow_missing=True)
        if not self.index_path.exists():
            raise ReplayStoreValidationError(
                f"Replay index does not exist: {self.index_path}"
            )

        try:
            raw = json.loads(self.index_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ReplayStoreValidationError(
                f"Invalid replay index JSON: {exc}"
            ) from exc

        if not isinstance(raw, dict):
            raise ReplayStoreValidationError(
                "Replay index root must be an object"
            )

        if raw.get("schema_version") != SCHEMA_VERSION:
            raise ReplayStoreValidationError(
                f"Unsupported replay schema_version: "
                f"{raw.get('schema_version')}"
            )

        return raw

    def _atomic_write_index(self, data: dict[str, Any]) -> None:
        self._validate_layout_symlinks(allow_missing=True)
        self.root.mkdir(parents=True, exist_ok=True)

        fd, temp_name = tempfile.mkstemp(
            prefix=".index.",
            suffix=".json.tmp",
            dir=self.root,
        )
        temp_path = Path(temp_name)

        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(
                    data,
                    handle,
                    indent=2,
                    ensure_ascii=False,
                    sort_keys=True,
                )
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())

            os.chmod(temp_path, 0o600)
            temp_path.replace(self.index_path)
            self._chmod_private(self.index_path)
        finally:
            temp_path.unlink(missing_ok=True)

    def _write_blob(self, path: Path, data: bytes) -> None:
        self._validate_layout_symlinks(allow_missing=True)
        self._validate_blob_path(path, "store")
        path.parent.mkdir(parents=True, exist_ok=True)

        if path.exists():
            if path.is_symlink():
                raise ReplayStoreValidationError(
                    f"Replay blob must not be a symlink: {path}"
                )
            if path.read_bytes() != data:
                raise ReplayStoreValidationError(
                    f"Replay blob collision: {path}"
                )
            return

        fd, temp_name = tempfile.mkstemp(
            prefix=f".{path.name}.",
            suffix=".tmp",
            dir=path.parent,
        )
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

    def _validate_layout_symlinks(self, *, allow_missing: bool) -> None:
        for path, label in (
            (self.root, "root"),
            (self.requests_dir, "requests directory"),
            (self.responses_dir, "responses directory"),
            (self.index_path, "index"),
        ):
            if path.is_symlink():
                raise ReplayStoreValidationError(
                    f"Replay store {label} must not be a symlink: {path}"
                )
            if not allow_missing and not path.exists():
                raise ReplayStoreValidationError(
                    f"Replay store {label} is missing: {path}"
                )

    def _validate_blob_path(self, path: Path, label: str) -> None:
        try:
            relative = path.relative_to(self.root)
        except ValueError as exc:
            raise ReplayStoreValidationError(
                f"Replay {label} blob escapes the store: {path}"
            ) from exc
        current = self.root
        for part in relative.parts:
            current = current / part
            if current.is_symlink():
                raise ReplayStoreValidationError(
                    f"Replay {label} blob path contains a symlink: {current}"
                )
