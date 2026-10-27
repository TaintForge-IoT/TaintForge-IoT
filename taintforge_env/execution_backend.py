from __future__ import annotations

import hashlib
import platform
import shutil
from dataclasses import asdict, dataclass
from enum import StrEnum
from pathlib import Path, PurePosixPath
from typing import Any, Callable

from .elf_target import (
    ElfTargetDescriptor,
    ElfTargetError,
    canonical_arch,
    guest_path_exists,
    inspect_elf_target,
)


class ExecutionBackendError(RuntimeError):
    """Raised when no safe execution backend can satisfy the runtime."""


class ExecutionBackendKind(StrEnum):
    NATIVE = "native"
    QEMU_USER = "qemu_user"
    QEMU_PLUGIN = "qemu_plugin"


class TraceBackend(StrEnum):
    HOST_STRACE = "host_strace"
    QEMU_STRACE = "qemu_strace"


QEMU_STATIC_BY_ARCH = {
    "i386": "qemu-i386-static",
    "x86_64": "qemu-x86_64-static",
    "arm": "qemu-arm-static",
    "aarch64": "qemu-aarch64-static",
    "mips": "qemu-mips-static",
    "mipsel": "qemu-mipsel-static",
}

_RESERVED_QEMU_GUEST_PATH = "/__taintforge/qemu-user-static"
_RESERVED_INTERNAL_DIR = "/__taintforge"


@dataclass(slots=True, frozen=True)
class ExecutionPlan:
    backend: ExecutionBackendKind
    trace_backend: TraceBackend
    host_arch: str
    target: ElfTargetDescriptor
    guest_binary: str
    guest_interpreter: str | None
    qemu_binary_name: str | None = None
    qemu_host_path: str | None = None
    qemu_host_sha256: str | None = None
    qemu_guest_path: str | None = None
    legacy_qemu_guest_path: str | None = None
    analyzer_bundle_path: str | None = None
    analyzer_bundle_sha256: str | None = None

    @property
    def qemu_required(self) -> bool:
        return self.backend in {ExecutionBackendKind.QEMU_USER, ExecutionBackendKind.QEMU_PLUGIN}

    @property
    def trace_filename(self) -> str:
        if self.trace_backend == TraceBackend.QEMU_STRACE:
            return "qemu_strace.log"
        return "strace.*"

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["backend"] = self.backend.value
        payload["trace_backend"] = self.trace_backend.value
        payload["target"] = self.target.to_dict()
        payload["qemu_required"] = self.qemu_required
        payload["reserved_internal_dir"] = (
            _RESERVED_INTERNAL_DIR if self.qemu_required else None
        )
        return payload


class ExecutionBackendResolver:
    """Select a native or QEMU user-mode backend from verified ELF metadata."""

    def __init__(
        self,
        *,
        host_arch: str | None = None,
        which: Callable[[str], str | None] = shutil.which,
    ) -> None:
        raw_host_arch = host_arch or platform.machine()
        try:
            self.host_arch = canonical_arch(raw_host_arch)
        except ElfTargetError as exc:
            raise ExecutionBackendError(
                f"unsupported host architecture: {raw_host_arch!r}"
            ) from exc
        self.which = which

    def resolve(
        self,
        *,
        runtime: dict[str, Any],
        host_binary: str | Path,
        rootfs: str | Path,
        guest_binary: str,
    ) -> ExecutionPlan:
        try:
            target = inspect_elf_target(host_binary)
        except ElfTargetError as exc:
            raise ExecutionBackendError(str(exc)) from exc

        root = Path(rootfs).resolve(strict=False)
        if root.is_symlink() or not root.is_dir():
            raise ExecutionBackendError(f"execution rootfs is invalid: {root}")
        guest_binary = _validate_guest_path(guest_binary, "guest binary")
        if not guest_path_exists(root, guest_binary):
            raise ExecutionBackendError(
                f"guest binary is absent from execution rootfs: {guest_binary}"
            )

        runtime_arch_raw = runtime.get("arch")
        if isinstance(runtime_arch_raw, str) and runtime_arch_raw.strip():
            try:
                runtime_arch = canonical_arch(runtime_arch_raw)
            except ElfTargetError as exc:
                raise ExecutionBackendError(str(exc)) from exc
            if runtime_arch != target.arch:
                raise ExecutionBackendError(
                    "runtime architecture does not match the ELF header: "
                    f"runtime={runtime_arch}, elf={target.arch}"
                )

        if target.arch not in QEMU_STATIC_BY_ARCH:
            raise ExecutionBackendError(
                f"unsupported ELF target architecture: {target.arch}"
            )

        if target.interpreter is not None and not guest_path_exists(
            root,
            target.interpreter,
        ):
            raise ExecutionBackendError(
                "guest dynamic interpreter is missing from the execution "
                f"rootfs: {target.interpreter}"
            )

        if "phase1" in runtime:
            from .elf_runtime import in_sysroot
            from .unified_runtime import verify_bundle
            try:
                config = runtime["phase1"]
                if not isinstance(config, dict) or not isinstance(config.get("bundle_path"), str) or not isinstance(config.get("bundle_sha256"), str):
                    raise ExecutionBackendError("phase1 requires a bound analyzer runtime bundle")
                bundle = Path(config["bundle_path"])
                if not bundle.is_absolute() or bundle.resolve() != bundle:
                    raise ExecutionBackendError("analyzer bundle path must be absolute and canonical")
                manifest = verify_bundle(bundle, config["bundle_sha256"])
                if target.arch != "i386" or manifest["host_arch"] != self.host_arch:
                    raise ExecutionBackendError("Phase 1 v1 requires an i386 guest and a matching host analyzer bundle")
                if _sha256_file(in_sysroot(root, guest_binary)) != target.sha256:
                    raise ExecutionBackendError("guest launch ELF differs from the bound original binary")
                if (root / _RESERVED_INTERNAL_DIR.lstrip("/")).exists() or (root / _RESERVED_INTERNAL_DIR.lstrip("/")).is_symlink():
                    raise ExecutionBackendError("execution rootfs contains reserved runner path /__taintforge")
                qemu = bundle / manifest["qemu"]
                return ExecutionPlan(backend=ExecutionBackendKind.QEMU_PLUGIN,
                    trace_backend=TraceBackend.QEMU_STRACE, host_arch=self.host_arch,
                    target=target, guest_binary=guest_binary, guest_interpreter=target.interpreter,
                    qemu_binary_name="qemu-i386", qemu_host_path=str(qemu),
                    qemu_host_sha256=_sha256_file(qemu), qemu_guest_path="/__taintforge/bin/qemu-i386",
                    analyzer_bundle_path=str(bundle), analyzer_bundle_sha256=manifest["bundle_sha256"])
            except (OSError, ValueError, RuntimeError) as exc:
                raise ExecutionBackendError(f"invalid Phase 1 execution backend: {exc}") from exc

        native_compatible = _native_compatible(
            self.host_arch,
            target.arch,
        )
        qemu_raw = runtime.get("qemu_required")
        if qemu_raw is None:
            qemu_required = not native_compatible
        elif isinstance(qemu_raw, bool):
            qemu_required = qemu_raw
        else:
            raise ExecutionBackendError("runtime qemu_required must be boolean")

        if not qemu_required and not native_compatible:
            raise ExecutionBackendError(
                "runtime declares qemu_required=false for a foreign ELF target: "
                f"host={self.host_arch}, target={target.arch}"
            )

        if not qemu_required:
            return ExecutionPlan(
                backend=ExecutionBackendKind.NATIVE,
                trace_backend=TraceBackend.HOST_STRACE,
                host_arch=self.host_arch,
                target=target,
                guest_binary=guest_binary,
                guest_interpreter=target.interpreter,
            )

        reserved = root / _RESERVED_INTERNAL_DIR.lstrip("/")
        if reserved.exists() or reserved.is_symlink():
            raise ExecutionBackendError(
                "execution rootfs already contains reserved runner path: "
                f"{_RESERVED_INTERNAL_DIR}"
            )

        qemu_name = runtime.get("qemu_binary_name")
        if qemu_name is not None and (
            not isinstance(qemu_name, str) or not qemu_name.strip()
        ):
            raise ExecutionBackendError("runtime qemu_binary_name is invalid")
        qemu_name = qemu_name or QEMU_STATIC_BY_ARCH[target.arch]
        if qemu_name != QEMU_STATIC_BY_ARCH[target.arch]:
            raise ExecutionBackendError(
                "runtime QEMU binary does not match the ELF target: "
                f"expected {QEMU_STATIC_BY_ARCH[target.arch]}, got {qemu_name}"
            )

        qemu_host = self._resolve_qemu_host(runtime, qemu_name)
        try:
            qemu_target = inspect_elf_target(qemu_host)
        except ElfTargetError as exc:
            raise ExecutionBackendError(
                f"invalid QEMU executable {qemu_host}: {exc}"
            ) from exc
        if qemu_target.interpreter is not None:
            raise ExecutionBackendError(
                "QEMU user-mode executable is dynamically linked; a static "
                f"binary is required for chroot injection: {qemu_host}"
            )

        legacy_guest = runtime.get("qemu_guest_path")
        if legacy_guest is not None and not isinstance(legacy_guest, str):
            raise ExecutionBackendError("runtime qemu_guest_path is invalid")

        return ExecutionPlan(
            backend=ExecutionBackendKind.QEMU_USER,
            trace_backend=TraceBackend.QEMU_STRACE,
            host_arch=self.host_arch,
            target=target,
            guest_binary=guest_binary,
            guest_interpreter=target.interpreter,
            qemu_binary_name=qemu_name,
            qemu_host_path=str(qemu_host),
            qemu_host_sha256=_sha256_file(qemu_host),
            qemu_guest_path=_RESERVED_QEMU_GUEST_PATH,
            legacy_qemu_guest_path=legacy_guest,
        )

    def _resolve_qemu_host(
        self,
        runtime: dict[str, Any],
        qemu_name: str,
    ) -> Path:
        raw = runtime.get("qemu_host_path")
        if raw is not None:
            if not isinstance(raw, str) or not raw.strip():
                raise ExecutionBackendError("runtime qemu_host_path is invalid")
            path = Path(raw).expanduser().resolve(strict=False)
        else:
            found = self.which(qemu_name)
            if found is None:
                raise ExecutionBackendError(
                    f"required static QEMU executable not found: {qemu_name}"
                )
            path = Path(found).resolve(strict=False)

        if not path.is_file():
            raise ExecutionBackendError(
                f"QEMU executable does not exist: {path}"
            )
        if not path.stat().st_mode & 0o111:
            raise ExecutionBackendError(
                f"QEMU executable is not executable: {path}"
            )
        return path


def resolve_runtime_host_binary(
    runtime: dict[str, Any],
    explicit: str | Path | None,
    project_root: str | Path,
) -> Path:
    raw: Any
    if explicit is not None:
        raw = str(explicit)
    else:
        raw = runtime.get("host_binary") or runtime.get("host_binary_path")
    if not isinstance(raw, str) or not raw:
        raise ExecutionBackendError(
            "host binary is missing; pass --binary or provide host_binary_path "
            "in runtime.json"
        )
    path = Path(raw)
    if not path.is_absolute():
        path = Path(project_root) / path
    path = path.resolve(strict=False)
    if path.is_symlink() or not path.is_file():
        raise ExecutionBackendError(f"host binary does not exist: {path}")
    return path


def resolve_runtime_guest_binary(runtime: dict[str, Any]) -> str:
    raw = runtime.get("guest_binary") or runtime.get("guest_binary_path")
    if raw is None:
        raw = "/bin/unpacked.elf"
    return _validate_guest_path(raw, "guest binary")


def _native_compatible(host_arch: str, target_arch: str) -> bool:
    if host_arch == target_arch:
        return True
    return host_arch == "x86_64" and target_arch == "i386"


def _validate_guest_path(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.startswith("/"):
        raise ExecutionBackendError(
            f"{label} must be an absolute POSIX path"
        )
    path = PurePosixPath(value)
    if any(part == ".." for part in path.parts):
        raise ExecutionBackendError(f"{label} must not contain '..'")
    if str(path) != value or path == PurePosixPath("/"):
        raise ExecutionBackendError(f"{label} must be normalized")
    return value


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
