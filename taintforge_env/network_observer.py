"""Build and bind the independent Phase 2 i386 endpoint observer."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess

from .elf_runtime import ElfImage, canonical_hash


class NetworkObserverError(ValueError):
    pass


def _hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _regular(path: Path, maximum: int):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > maximum:
        raise NetworkObserverError(f"expected a bounded regular observer file: {path}")


def _glib_flags(kind: str) -> list[str]:
    name = "TF_NETWORK_GLIB_CFLAGS" if kind == "--cflags" else "TF_NETWORK_GLIB_LIBS"
    if name in os.environ:
        return shlex.split(os.environ[name])
    pkg = shutil.which("pkg-config") or shutil.which("pkgconf")
    if pkg is None:
        raise NetworkObserverError("pkg-config and GLib development headers are required")
    result = subprocess.run([pkg, kind, "glib-2.0"], capture_output=True, text=True)
    if result.returncode:
        raise NetworkObserverError(result.stderr.strip())
    return shlex.split(result.stdout)


def build_observer(project: Path, destination: Path, *, qemu_include: Path | None = None) -> dict:
    project = project.resolve(strict=True)
    source = project / "network/endpoint_observer.c"
    if qemu_include is None:
        configured = os.environ.get("TF_QEMU_INCLUDE")
        qemu_include = Path(configured) if configured else Path("/usr/include")
        if not (qemu_include / "qemu-plugin.h").is_file() and not configured:
            qemu_include = project / "experiments/execution_capsule_probe/vendor"
    header = (qemu_include / "qemu-plugin.h").resolve(strict=True)
    match = re.search(r"^#define QEMU_PLUGIN_VERSION ([0-9]+)$", header.read_text(), re.MULTILINE)
    if not match or int(match.group(1)) < 4:
        raise NetworkObserverError("observer requires a QEMU memory-read plugin API header")
    api = int(match.group(1))
    compiler = shutil.which("gcc")
    if compiler is None:
        raise NetworkObserverError("GCC is required to build the endpoint observer")
    flags, libraries = _glib_flags("--cflags"), _glib_flags("--libs")
    destination = destination.expanduser().absolute()
    if destination.exists() or destination.is_symlink():
        raise NetworkObserverError("use a fresh observer build directory")
    destination.mkdir(parents=True)
    plugin = destination / "libnetwork_endpoint.so"
    command = [compiler, "-std=c11", "-O2", "-shared", "-fPIC", "-fvisibility=hidden",
               "-Wall", "-Wextra", "-Werror", "-Wl,-z,relro,-z,now", "-I", str(header.parent),
               *flags, str(source), "-o", str(plugin), *libraries]
    result = subprocess.run(command, capture_output=True, text=True)
    if result.returncode:
        raise NetworkObserverError(result.stderr.strip())
    inputs = {"source_sha256": _hash(source), "header_sha256": _hash(header), "plugin_api": api,
              "compiler": compiler, "cflags": flags, "libraries": libraries}
    metadata = {"schema_version": 1, "kind": "taintforge-network-endpoints", "target_arch": "i386",
                "profile": "single-process-single-thread", "build_id": canonical_hash(inputs),
                "build_inputs": inputs, "plugin_api": api,
                "plugin": {"filename": plugin.name, "sha256": _hash(plugin), "size": plugin.stat().st_size}}
    Path(str(plugin) + ".observer.json").write_text(json.dumps(metadata, indent=2) + "\n")
    return {"plugin_path": str(plugin), **validate_observer(plugin)}


def validate_observer(plugin: Path) -> dict:
    _regular(plugin, 8 * 1024 * 1024)
    sidecar = Path(str(plugin) + ".observer.json")
    _regular(sidecar, 64 * 1024)
    data = json.loads(sidecar.read_text())
    if (not isinstance(data, dict) or data.get("schema_version") != 1
            or data.get("kind") != "taintforge-network-endpoints" or data.get("target_arch") != "i386"
            or data.get("profile") != "single-process-single-thread"
            or not isinstance(data.get("build_inputs"), dict)
            or data.get("build_id") != canonical_hash(data["build_inputs"])
            or type(data.get("plugin_api")) is not int or data["plugin_api"] < 4
            or data["build_inputs"].get("plugin_api") != data["plugin_api"]):
        raise NetworkObserverError("invalid network observer build contract")
    artifact = data.get("plugin")
    if (not isinstance(artifact, dict) or artifact.get("filename") != plugin.name
            or artifact.get("size") != plugin.stat().st_size or artifact.get("sha256") != _hash(plugin)):
        raise NetworkObserverError("network observer binary differs from its build contract")
    image = ElfImage(plugin)
    if image.target.arch not in {"x86_64", "i386"} or image.target.interpreter is not None:
        raise NetworkObserverError("network observer must be a host x86 ELF shared library")
    return data


def plugin_argument(plugin: str, events: Path, session_id: str, attempt_id: str) -> str:
    for value in (session_id, attempt_id):
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,120}", value):
            raise NetworkObserverError("invalid network observer session/attempt identity")
    parts = [plugin, f"events={events}", f"session={session_id}", f"attempt={attempt_id}"]
    if any("," in part or "\n" in part or "\r" in part for part in parts):
        raise NetworkObserverError("network observer arguments contain a comma or newline")
    if not Path(plugin).is_absolute() or not events.is_absolute():
        raise NetworkObserverError("network observer plugin and output paths must be absolute")
    return ",".join(parts)


def mount_fragments(root: Path, output: Path, planned: list[Path]) -> tuple[str, str]:
    current = root
    created = []
    for part in output.parts[1:]:
        current = current / part
        if current in planned:
            continue
        if current.is_symlink() or (current.exists() and not current.is_dir()):
            raise NetworkObserverError("network observer output mount traverses an invalid guest path")
        if not current.exists():
            created.append(current)
    if current.exists():
        raise NetworkObserverError("network observer output mount would hide a guest directory")
    quote = shlex.quote
    setup = "".join(f"mkdir -m 0755 {quote(str(path))}\n" for path in created)
    setup += f"mount --bind {quote(str(output))} {quote(str(current))}\n"
    cleanup = f"umount -l {quote(str(current))} >/dev/null 2>&1 || true\n"
    cleanup += "".join(f"rmdir {quote(str(path))} >/dev/null 2>&1 || true\n" for path in reversed(created))
    return setup, cleanup
