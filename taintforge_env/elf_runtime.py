"""Read ELF loader metadata without executing the target; provision bounded dependencies."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import struct
import subprocess

from .elf_target import ElfTargetError, inspect_elf_target


class ElfRuntimeError(ValueError):
    pass


@dataclass(frozen=True)
class Segment:
    kind: int
    flags: int
    offset: int
    address: int
    file_size: int
    memory_size: int
    alignment: int


class ElfImage:
    def __init__(self, path: Path):
        self.path = Path(path)
        if self.path.stat().st_size > 512 * 1024 * 1024:
            raise ElfRuntimeError("ELF exceeds the 512 MiB inspection limit")
        self.target = inspect_elf_target(self.path)
        self.data = self.path.read_bytes()
        self.order = "<" if self.target.endianness == "little" else ">"
        self.word = 4 if self.target.elf_class == 32 else 8
        fmt = "16sHHIIIIIHHHHHH" if self.word == 4 else "16sHHIQQQIHHHHHH"
        self.header = struct.unpack_from(self.order + fmt, self.data)
        self.header_size = 52 if self.word == 4 else 64
        self.phoff, self.phsize, self.phnum = self.header[5], self.header[9], self.header[10]
        self.segments = []
        for index in range(self.phnum):
            at = self.phoff + index * self.phsize
            if self.word == 4:
                kind, offset, address, _, file_size, memory_size, flags, alignment = struct.unpack_from(self.order + "8I", self.data, at)
            else:
                kind, flags, offset, address, _, file_size, memory_size, alignment = struct.unpack_from(self.order + "II6Q", self.data, at)
            if offset + file_size > len(self.data):
                raise ElfRuntimeError(f"ELF segment exceeds file bounds: {self.path}")
            if kind == 1 and (file_size > memory_size or (alignment > 1 and (alignment & (alignment - 1) or offset % alignment != address % alignment))):
                raise ElfRuntimeError("invalid PT_LOAD extent or alignment")
            self.segments.append(Segment(kind, flags, offset, address, file_size, memory_size, alignment))

    def offset_for(self, address: int, size: int) -> int:
        matches = {s.offset + address - s.address for s in self.segments
                   if s.kind == 1 and s.address <= address and address + size <= s.address + s.file_size}
        if len(matches) != 1:
            raise ElfRuntimeError("dynamic ELF address lacks an unambiguous file-backed PT_LOAD extent")
        return matches.pop()

    def dynamic(self) -> dict:
        segments = [s for s in self.segments if s.kind == 2]
        if not segments:
            return {"needed": [], "rpath": [], "runpath": [], "soname": None}
        if len(segments) != 1:
            raise ElfRuntimeError("multiple PT_DYNAMIC segments are unsupported")
        segment = segments[0]
        entry_size = self.word * 2
        if segment.file_size % entry_size or segment.file_size // entry_size > 16384:
            raise ElfRuntimeError("invalid or oversized PT_DYNAMIC table")
        entries = []
        for at in range(segment.offset, segment.offset + segment.file_size, entry_size):
            tag, value = struct.unpack_from(self.order + ("iI" if self.word == 4 else "qQ"), self.data, at)
            if tag == 0:
                break
            entries.append((tag, value))
        else:
            raise ElfRuntimeError("PT_DYNAMIC has no terminator")
        def one(tag):
            values = [value for key, value in entries if key == tag]
            if len(values) != 1:
                raise ElfRuntimeError(f"dynamic ELF requires exactly one tag {tag}")
            return values[0]
        strings = [item for item in entries if item[0] in (1, 14, 15, 29)]
        if not strings:
            return {"needed": [], "rpath": [], "runpath": [], "soname": None}
        size = one(10)
        if not 0 < size <= 16 * 1024 * 1024:
            raise ElfRuntimeError("invalid dynamic string-table size")
        start = self.offset_for(one(5), size)
        table = self.data[start:start + size]
        def string(offset):
            if offset >= len(table):
                raise ElfRuntimeError("dynamic string offset is out of bounds")
            end = table.find(b"\0", offset)
            if end < 0 or end - offset > 4096:
                raise ElfRuntimeError("unterminated or oversized dynamic string")
            try:
                return table[offset:end].decode("utf-8")
            except UnicodeError as exc:
                raise ElfRuntimeError("unsupported non-UTF-8 library name") from exc
        result = {"needed": [], "rpath": [], "runpath": [], "soname": None}
        for tag, value in strings:
            text = string(value)
            if tag == 1:
                if not text or "/" in text or text in (".", ".."):
                    raise ElfRuntimeError("DT_NEEDED must be a simple library name")
                result["needed"].append(text)
            elif tag == 14:
                result["soname"] = text
            else:
                result["rpath" if tag == 15 else "runpath"] = text.split(":")
        if len(result["needed"]) > 256:
            raise ElfRuntimeError("too many ELF dependencies")
        return result


def guest_path(value: str) -> str:
    path = PurePosixPath(value)
    if not path.is_absolute() or ".." in path.parts or "\0" in value or str(path) != value:
        raise ElfRuntimeError(f"invalid absolute guest path: {value!r}")
    return value


def in_sysroot(root: Path, value: str) -> Path:
    """Resolve absolute symlinks relative to the selected sysroot, never the host."""
    guest_path(value)
    pending = list(PurePosixPath(value).parts[1:])
    done = []
    links = 0
    while pending:
        part = pending.pop(0)
        if part in ("", "."):
            continue
        if part == "..":
            if not done:
                raise ElfRuntimeError("symlink escapes selected sysroot")
            done.pop()
            continue
        path = root.joinpath(*done, part)
        if path.is_symlink():
            links += 1
            if links > 40:
                raise ElfRuntimeError("too many sysroot symlinks")
            target = PurePosixPath(os.readlink(path))
            if target.is_absolute():
                done = []
                pending = list(target.parts[1:]) + pending
            else:
                pending = list(target.parts) + pending
        else:
            done.append(part)
    return root.joinpath(*done)


def copy_file(source: Path, destination: Path, *, expected: str | None = None, executable=False):
    if not source.is_file():
        raise ElfRuntimeError(f"required ELF/library is missing: {source}")
    data = source.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if expected is not None and digest != expected:
        raise ElfRuntimeError(f"runtime file changed: {source}")
    for path in (destination, *destination.parents):
        if path.is_symlink():
            raise ElfRuntimeError(f"destination contains a symlink: {path}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        if not destination.is_file() or destination.read_bytes() != data:
            raise ElfRuntimeError(f"runtime dependency collision: {destination}")
    else:
        with destination.open("xb") as stream:
            stream.write(data)
        destination.chmod(0o555 if executable else 0o444)
    return digest


class DependencyResolver:
    def __init__(self, sysroot: Path, target_arch: str, *, extra_dirs=()):
        self.root = Path(sysroot).resolve(strict=True)
        if not self.root.is_dir():
            raise ElfRuntimeError("sysroot must be a directory")
        self.arch = target_arch
        triples = {"i386": "i386-linux-gnu", "x86_64": "x86_64-linux-gnu", "arm": "arm-linux-gnueabihf",
                   "aarch64": "aarch64-linux-gnu", "mips": "mips-linux-gnu", "mipsel": "mipsel-linux-gnu"}
        triple = triples.get(target_arch)
        self.directories = list(extra_dirs)
        self.directories += ([f"/lib/{triple}", f"/usr/lib/{triple}"] if triple else [])
        self.directories += (["/lib32", "/usr/lib32"] if target_arch == "i386" else [])
        self.directories += ["/lib", "/usr/lib", "/lib64", "/usr/lib64", "/usr/local/lib"]
        for path in self.directories:
            guest_path(path)
        self.cache = {}
        if self.root == Path("/") and shutil.which("ldconfig"):
            output = subprocess.run([shutil.which("ldconfig"), "-p"], capture_output=True, text=True, timeout=10, check=True)
            for line in output.stdout.splitlines():
                if " => /" in line:
                    name, path = line.strip().split(" => ", 1)
                    self.cache.setdefault(name.split()[0], []).append(path)

    def valid(self, path: Path) -> bool:
        if not path.is_file():
            return False
        try:
            return inspect_elf_target(path).arch == self.arch
        except (ValueError, ElfTargetError):
            return False

    def resolve(self, name: str, owner: str, dynamic: dict, inherited: tuple[str, ...] = ()) -> tuple[Path, str]:
        origin = str(PurePosixPath(owner).parent)
        runtime_paths = []
        for path in dynamic["runpath"] or dynamic["rpath"]:
            path = path.replace("${ORIGIN}", origin).replace("$ORIGIN", origin)
            if "$" in path or not path.startswith("/"):
                raise ElfRuntimeError("relative or unsupported ELF search-path token; provide a compatible sysroot")
            # Normalize '..' within a loader path without allowing escape above '/'.
            normalized = os.path.normpath(path)
            runtime_paths.append(guest_path(normalized))
        candidates = [f"{directory.rstrip('/')}/{name}" for directory in (*runtime_paths, *inherited, *self.directories)]
        candidates.extend(self.cache.get(name, []))
        for virtual in dict.fromkeys(candidates):
            path = in_sysroot(self.root, virtual)
            if self.valid(path):
                return path, virtual
        raise ElfRuntimeError(f"missing {self.arch} dependency {name} required by {owner}; sysroot={self.root}")

    def closure(self, sources: list[tuple[Path, str]]) -> list[dict]:
        pending = [(path, virtual, ()) for path, virtual in sources]
        seen, result = set(), []
        while pending:
            path, virtual, inherited = pending.pop(0)
            key = str(path), virtual
            if key in seen:
                continue
            seen.add(key)
            if len(seen) > 256:
                raise ElfRuntimeError("runtime dependency closure exceeds 256 files")
            image = ElfImage(path)
            if image.target.arch != self.arch:
                raise ElfRuntimeError(f"wrong architecture in dependency closure: {path}")
            dynamic = image.dynamic()
            if image.target.interpreter:
                interpreter = in_sysroot(self.root, image.target.interpreter)
                if not self.valid(interpreter):
                    raise ElfRuntimeError(f"missing {self.arch} ELF interpreter: {image.target.interpreter}")
                pending.append((interpreter, image.target.interpreter, ()))
            result.append({"source": str(path), "guest_path": virtual, "sha256": image.target.sha256,
                           "needed": dynamic["needed"], "interpreter": image.target.interpreter})
            inherited_next = inherited
            if not dynamic["runpath"]:
                origin = str(PurePosixPath(virtual).parent)
                inherited_next = tuple(os.path.normpath(p.replace("${ORIGIN}", origin).replace("$ORIGIN", origin))
                                       for p in dynamic["rpath"]) + inherited
            for name in dynamic["needed"]:
                dependency, dependency_virtual = self.resolve(name, virtual, dynamic, inherited)
                pending.append((dependency, dependency_virtual, inherited_next))
        return result


def provision_guest(binary: Path, rootfs: Path, *, sysroot: Path, binary_guest_path="/bin/unpacked.elf", library_dirs=(), extra_libraries=()) -> dict:
    image = ElfImage(binary)
    guest_path(binary_guest_path)
    if image.target.file_type_id not in (2, 3) or not any(s.kind == 1 and s.flags & 1
            and s.address <= image.target.entry_point < s.address + s.memory_size for s in image.segments):
        raise ElfRuntimeError("target ELF has no executable entry point")
    resolver = DependencyResolver(sysroot, image.target.arch, extra_dirs=library_dirs)
    sources = [(binary, binary_guest_path)]
    dynamic = image.dynamic()
    for name in extra_libraries:
        if not isinstance(name, str) or not name or "/" in name or name in (".", ".."):
            raise ElfRuntimeError("extra libraries must be simple ELF library names")
        sources.append(resolver.resolve(name, binary_guest_path, dynamic))
    records = resolver.closure(sources)
    # Older glibc loads these NSS modules via dlopen, outside DT_NEEDED.
    # Newer glibc can implement DNS/files directly; absence is not an error.
    nss_modules = []
    if any("libc.so.6" in record["needed"] for record in records):
        for name in ("libnss_files.so.2", "libnss_dns.so.2"):
            try:
                dependency = resolver.resolve(name, binary_guest_path, dynamic)
            except ElfRuntimeError:
                continue
            sources.append(dependency)
            nss_modules.append(name)
        records = resolver.closure(sources)
    for record in records:
        copy_file(Path(record["source"]), rootfs / record["guest_path"].lstrip("/"), expected=record["sha256"], executable=True)
    library_path = list(dict.fromkeys(str(PurePosixPath(record["guest_path"]).parent)
                                     for record in records if record["guest_path"] != binary_guest_path))
    return {"schema_version": 1, "target": image.target.to_dict(), "sysroot": str(resolver.root),
            "files": records, "missing": [], "headers": "original_valid_elf", "recursive_dt_needed": True,
            "library_path": library_path, "nss_modules": nss_modules,
            "explicit_extra_libraries": list(extra_libraries), "other_dlopen_dependencies": "not_inferred"}


def canonical_hash(value: dict) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
