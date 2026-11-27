"""Operator-supplied file bytes for a subsequent, evidence-driven rootfs repair."""

import base64
from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import secrets
import stat


MAX_FILE = 1024**2
MAX_TOTAL = 8 * MAX_FILE
MAX_FILES = 16
CATALOG = "repair_files.json"


def check_guest_file(value: str) -> PurePosixPath:
    path = PurePosixPath(value)
    if (
        not path.is_absolute()
        or path.root != "/"
        or len(path.parts) < 2
        or len(value) > 4095
        or ".." in path.parts
        or str(path) != value
        or any(not c.isprintable() for c in value)
        or path.parts[1] in {"proc", "sys", "dev", "__taintforge", "__taintforge_capsule"}
    ):
        raise ValueError(f"invalid guest file destination: {value!r}")
    return path


def _read_regular(path, limit, *, dir_fd=None):
    before = os.stat(path, dir_fd=dir_fd, follow_symlinks=False)
    if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
        raise ValueError(f"expected a bounded regular file: {path}")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dir_fd)
    try:
        info = os.fstat(fd)
        if not os.path.samestat(before, info) or not stat.S_ISREG(info.st_mode):
            raise ValueError(f"file changed while opening: {path}")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            data = stream.read(limit + 1)
        if len(data) != before.st_size:
            raise ValueError(f"file size changed while reading: {path}")
        return data
    finally:
        os.close(fd)


@dataclass(frozen=True)
class SuppliedFile:
    data: bytes

    @property
    def sha256(self):
        return hashlib.sha256(self.data).hexdigest()

    def parameters(self):
        return {"content_strategy": "supplied_file", "sha256": self.sha256, "bytes": len(self.data)}


def _check_destinations(destinations):
    paths = {check_guest_file(name) for name in destinations}
    if any(parent in paths for path in paths for parent in path.parents):
        raise ValueError("a supplied file cannot be another supplied file's parent")


def write_catalog(path: Path, mappings: list[str]):
    records = {}
    total = 0
    if len(mappings) > MAX_FILES:
        raise ValueError("at most 16 --repair-file mappings are supported")
    for mapping in mappings:
        guest, sep, host = mapping.partition("=")
        if not sep or not host or guest in records:
            raise ValueError("--repair-file requires a distinct /guest/path=host-file")
        check_guest_file(guest)
        data = _read_regular(Path(host).expanduser(), MAX_FILE)
        total += len(data)
        if total > MAX_TOTAL:
            raise ValueError("supplied file inputs exceed 8 MiB")
        records[guest] = base64.b64encode(data).decode("ascii")
    _check_destinations(records)
    path.write_text(
        json.dumps({"version": 1, "files": records}, sort_keys=True) + "\n", encoding="utf-8"
    )


def _unique_pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError(f"duplicate supplied file catalog key: {key}")
        result[key] = value
    return result


def load_catalog(path: Path, expected_sha256: str | None = None) -> dict[str, SuppliedFile]:
    raw = _read_regular(path, 12 * MAX_FILE)
    if expected_sha256 is not None and hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise ValueError("supplied file catalog differs from the session binding")
    doc = json.loads(raw, object_pairs_hook=_unique_pairs)
    if not isinstance(doc, dict) or doc.get("version") != 1 or not isinstance(doc.get("files"), dict):
        raise ValueError("invalid supplied file catalog")
    records = doc["files"]
    if len(records) > MAX_FILES:
        raise ValueError("too many supplied files")
    _check_destinations(records)
    result = {}
    total = 0
    for guest, encoded in records.items():
        if not isinstance(encoded, str) or len(encoded) > 4 * ((MAX_FILE + 2) // 3):
            raise ValueError("invalid encoded file input")
        data = base64.b64decode(encoded, validate=True)
        total += len(data)
        if len(data) > MAX_FILE or total > MAX_TOTAL:
            raise ValueError("supplied file input exceeds its size budget")
        result[guest] = SuppliedFile(data)
    return result


@contextmanager
def _parent(root: Path, guest: str, created: list[Path] | None = None):
    parts = check_guest_file(guest).parts[1:]
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    parent = os.open(root, flags)
    current = root
    try:
        for part in parts[:-1]:
            current = current / part
            made_directory = False
            try:
                child = os.open(part, flags, dir_fd=parent)
            except FileNotFoundError:
                if created is None:
                    raise
                try:
                    os.mkdir(part, 0o755, dir_fd=parent)
                    created.append(current)
                    made_directory = True
                except FileExistsError:
                    pass
                child = os.open(part, flags, dir_fd=parent)
            os.close(parent)
            parent = child
            if made_directory:
                os.fchmod(parent, 0o755)
        yield parent, parts[-1]
    finally:
        os.close(parent)


def observe_file(root: Path, guest: str) -> SuppliedFile:
    with _parent(root, guest) as (parent, name):
        return SuppliedFile(_read_regular(name, MAX_FILE, dir_fd=parent))


def matches_or_missing(root: Path, guest: str, source: SuppliedFile) -> bool:
    try:
        observed = observe_file(root, guest)
    except FileNotFoundError:
        return False
    if observed != source:
        raise ValueError(f"existing guest file differs from the supplied content: {guest}")
    return True


def install_file(
    root: Path, guest: str, source: SuppliedFile, created: list[Path], file_identities: dict
):
    with _parent(root, guest, created) as (parent, name):
        try:
            existing = _read_regular(name, MAX_FILE, dir_fd=parent)
        except FileNotFoundError:
            existing = None
        if existing is not None:
            if existing != source.data:
                raise ValueError(f"file collision at guest path {guest}")
            return
        temporary = ".tf-input-" + secrets.token_hex(12)
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=parent)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(source.data)
                stream.flush()
                os.fchmod(stream.fileno(), 0o644)
                info = os.fstat(stream.fileno())
            try:
                os.link(temporary, name, src_dir_fd=parent, dst_dir_fd=parent, follow_symlinks=False)
                path = root / guest.lstrip("/")
                file_identities[path] = (info.st_dev, info.st_ino)
                created.append(path)
            except FileExistsError:
                if _read_regular(name, MAX_FILE, dir_fd=parent) != source.data:
                    raise ValueError(f"file collision at guest path {guest}")
        finally:
            os.unlink(temporary, dir_fd=parent)
