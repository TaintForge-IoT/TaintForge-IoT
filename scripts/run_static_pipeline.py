#!/usr/bin/env python3
"""
Temporary end-to-end launcher for the current TaintForge-IoT MVP.

Connects the existing Phase 1 QEMU plugin and existing Phase 2 orchestrator:

    static i386 ELF
        -> Phase 1 QEMU plugin
        -> unpacked.json + unpacked.bin
        -> compatibility adapter
        -> Phase 2 scripts/run_sample.py
        -> Phase 2 report + top-level pipeline report

IMPORTANT CURRENT LIMITATION
============================
Phase 1 currently emits a raw memory dump, not a generally runnable rebuilt ELF.
This temporary bridge therefore executes the ORIGINAL STATIC ELF in Phase 2 and
uses Phase 1 output as environment metadata. It is an MVP integration wrapper,
not fixed-address snapshot replay.

SAFETY
======
By default Phase 1 runs in a new network namespace and drops to the invoking
user before QEMU starts. This blocks ordinary outbound network access, but it
is not a complete filesystem sandbox. Run malware only on a dedicated analysis
machine/VM.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import uuid
import zipfile

from taintforge_env.phase1_runtime import Phase1Run, Phase1Runtime, Phase1RuntimeError
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCRIPT_VERSION = "0.5.0"
SUPPORTED_MACHINE = "Intel 80386"


class PipelineError(RuntimeError):
    """Raised when an integration stage cannot be completed safely."""


@dataclass(frozen=True, slots=True)
class ElfInfo:
    elf_class: str
    endianness: str
    machine: str
    entry_point: str
    statically_linked: bool


@dataclass(frozen=True, slots=True)
class CommandResult:
    command: tuple[str, ...]
    returncode: int
    stdout_path: Path
    stderr_path: Path


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file_obj:
        while block := file_obj.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as file_obj:
            json.dump(payload, file_obj, indent=2, sort_keys=True)
            file_obj.write("\n")
            file_obj.flush()
            os.fsync(file_obj.fileno())
        os.replace(temporary_path, path)
    finally:
        temporary_path.unlink(missing_ok=True)


def atomic_write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as file_obj:
            file_obj.write(text)
            file_obj.flush()
            os.fsync(file_obj.fileno())
        os.replace(temporary_path, path)
    finally:
        temporary_path.unlink(missing_ok=True)


def require_program(name: str) -> str:
    resolved = shutil.which(name)
    if resolved is None:
        raise PipelineError(f"Required program is not installed or not in PATH: {name}")
    return resolved


def resolve_project_root(explicit: str | None) -> Path:
    candidates: list[Path] = []
    if explicit is not None:
        candidates.append(Path(explicit).expanduser().resolve())
    candidates.extend([Path.cwd().resolve(), Path(__file__).resolve().parent.parent])

    for candidate in candidates:
        if (
            (candidate / "scripts" / "run_sample.py").is_file()
            and (candidate / "taintforge_env").is_dir()
        ):
            return candidate

    checked = ", ".join(str(path) for path in candidates)
    raise PipelineError(
        "Could not locate the TaintForge-IoT project root. "
        f"Checked: {checked}. Use --project-root explicitly."
    )


def parse_readelf_value(output: str, label: str) -> str:
    for line in output.splitlines():
        stripped = line.strip()
        if stripped.startswith(label):
            return stripped.split(":", 1)[1].strip()
    raise PipelineError(f"readelf output does not contain {label!r}")


def inspect_elf(sample: Path) -> ElfInfo:
    readelf = require_program("readelf")
    header = subprocess.run(
        [readelf, "-hW", str(sample)],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if header.returncode != 0:
        raise PipelineError(
            f"Input is not a readable ELF file: {sample}\n{header.stderr.strip()}"
        )

    program_headers = subprocess.run(
        [readelf, "-lW", str(sample)],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if program_headers.returncode != 0:
        raise PipelineError(
            f"Could not inspect ELF program headers: {program_headers.stderr.strip()}"
        )

    elf_class = parse_readelf_value(header.stdout, "Class")
    data = parse_readelf_value(header.stdout, "Data")
    machine = parse_readelf_value(header.stdout, "Machine")
    entry_point = parse_readelf_value(header.stdout, "Entry point address")

    if "little endian" in data.lower():
        endianness = "little"
    elif "big endian" in data.lower():
        endianness = "big"
    else:
        endianness = data

    return ElfInfo(
        elf_class=elf_class,
        endianness=endianness,
        machine=machine,
        entry_point=entry_point,
        statically_linked="INTERP" not in program_headers.stdout,
    )


def validate_sample(sample: Path, elf: ElfInfo) -> None:
    if not sample.exists():
        raise PipelineError(f"Input sample does not exist: {sample}")
    if not sample.is_file():
        raise PipelineError(f"Input sample is not a regular file: {sample}")
    if not os.access(sample, os.R_OK):
        raise PipelineError(f"Input sample is not readable: {sample}")
    if not os.access(sample, os.X_OK):
        raise PipelineError(
            f"Input sample is not executable: {sample}. Run: chmod +x {sample}"
        )
    if not elf.statically_linked:
        raise PipelineError(
            "This temporary unified wrapper accepts only static ELF binaries. "
            "The input contains a PT_INTERP program header."
        )
    if elf.machine != SUPPORTED_MACHINE:
        raise PipelineError(
            "The current Phase 1 plugin is only reliable for Linux i386. "
            f"Detected machine: {elf.machine!r}; expected {SUPPORTED_MACHINE!r}."
        )
    if elf.elf_class != "ELF32":
        raise PipelineError(
            f"The current wrapper expects ELF32, detected {elf.elf_class!r}."
        )
    if elf.endianness != "little":
        raise PipelineError(
            "The current wrapper expects little-endian i386, "
            f"detected {elf.endianness!r}."
        )


def plugin_candidates(project_root: Path, explicit: str | None) -> list[Path]:
    selected = explicit or os.environ.get("TAINTFORGE_QEMU_PLUGIN")
    return [Path(selected).expanduser().resolve()] if selected else [project_root / "build" / "libtaintforge_ir.so"]


def find_system_qemu_plugin_header() -> Path | None:
    candidates = [
        Path("/usr/include/qemu-plugin.h"),
        Path("/usr/local/include/qemu-plugin.h"),
    ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return None


def qemu_source_candidates(
    project_root: Path,
    explicit: str | None,
) -> list[Path]:
    candidates: list[Path] = []

    if explicit:
        candidates.append(Path(explicit).expanduser().resolve())

    for variable in ("TAINTFORGE_QEMU_SOURCE", "QEMU_SRC"):
        value = os.environ.get(variable)
        if value:
            candidates.append(Path(value).expanduser().resolve())

    candidates.extend(
        [
            Path.home() / "qemu",
            project_root.parent / "qemu",
            project_root / "qemu",
        ]
    )

    unique: list[Path] = []
    seen: set[Path] = set()
    for candidate in candidates:
        normalized = candidate.resolve()
        if normalized not in seen:
            seen.add(normalized)
            unique.append(normalized)
    return unique


def resolve_qemu_source(
    project_root: Path,
    explicit: str | None,
) -> Path:
    checked: list[Path] = []

    for candidate in qemu_source_candidates(project_root, explicit):
        checked.append(candidate)
        plugins_header = candidate / "include" / "plugins" / "qemu-plugin.h"
        source_header = candidate / "include" / "qemu" / "qemu-plugin.h"
        installed_style_header = candidate / "include" / "qemu-plugin.h"
        build_dir = candidate / "build"

        if (
            (plugins_header.is_file() or source_header.is_file() or installed_style_header.is_file())
            and build_dir.is_dir()
        ):
            return candidate

    rendered = "\n".join(f"  - {path}" for path in checked)
    raise PipelineError(
        "The Phase 1 plugin is missing and could not be built because a "
        "configured QEMU source/build tree was not found.\n"
        "Expected a tree such as ~/qemu with include/ and build/.\n"
        "Pass --qemu-source /path/to/qemu or set TAINTFORGE_QEMU_SOURCE.\n"
        f"Checked:\n{rendered}"
    )


def build_phase1_plugin(*, project_root: Path, qemu_source: Path | None) -> Path:
    source = project_root / "unpacker" / "test"
    recipe = source / "build_group7_4c1_plugin.sh"
    if not recipe.is_file():
        raise PipelineError("Missing canonical Phase 1 build recipe")
    header = None
    explicit_header = os.environ.get("TF_QEMU_INCLUDE")
    if explicit_header:
        header = Path(explicit_header) / "qemu-plugin.h"
    elif qemu_source is not None:
        for candidate in (qemu_source / "include" / "plugins" / "qemu-plugin.h",
                          qemu_source / "include" / "qemu" / "qemu-plugin.h",
                          qemu_source / "include" / "qemu-plugin.h"):
            if candidate.is_file():
                header = candidate
                break
    else:
        header = find_system_qemu_plugin_header()
    if header is None or not header.is_file():
        raise PipelineError("Select the exact QEMU header with TF_QEMU_INCLUDE or --qemu-source")
    output = project_root / "build" / "libtaintforge_ir.so"
    output.parent.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env["TF_QEMU_INCLUDE"] = str(header.parent)
    command = ["bash", str(recipe), str(source), str(output)]
    result = subprocess.run(command, cwd=project_root, env=env, text=True, capture_output=True, check=False)
    (output.parent / "qemu_unpacker.build.log").write_text(result.stdout + result.stderr)
    if result.returncode:
        raise PipelineError("Canonical Phase 1 build failed; see build/qemu_unpacker.build.log")
    Phase1Runtime.load(output)
    return output


def resolve_or_build_plugin(
    *,
    project_root: Path,
    explicit: str | None,
    qemu_source_explicit: str | None,
    auto_build: bool,
) -> Path:
    candidates = plugin_candidates(project_root, explicit)

    for candidate in candidates:
        if candidate.is_file():
            Phase1Runtime.load(candidate)
            return candidate.resolve()
    if explicit or os.environ.get("TAINTFORGE_QEMU_PLUGIN"):
        raise PipelineError("Explicitly selected Phase 1 plugin does not exist; no fallback is permitted")

    if auto_build:
        if not qemu_source_explicit and (os.environ.get("TF_QEMU_INCLUDE") or find_system_qemu_plugin_header() is not None):
            return build_phase1_plugin(
                project_root=project_root,
                qemu_source=None,
            )

        qemu_source = resolve_qemu_source(
            project_root,
            qemu_source_explicit,
        )
        return build_phase1_plugin(
            project_root=project_root,
            qemu_source=qemu_source,
        )

    rendered = "\n".join(f"  - {path}" for path in candidates)
    raise PipelineError(
        "Could not find the compiled QEMU plugin and automatic build is disabled.\n"
        "Pass --plugin /absolute/path/to/plugin.so or remove "
        "--no-auto-build-plugin.\n"
        f"Checked:\n{rendered}"
    )


def resolve_qemu(explicit: str | None) -> str:
    if explicit:
        path = Path(explicit).expanduser()
        if path.is_file():
            return str(path.resolve())
        resolved = shutil.which(explicit)
        if resolved:
            return resolved
        raise PipelineError(f"QEMU executable not found: {explicit}")

    for name in ("qemu-i386",):
        resolved = shutil.which(name)
        if resolved:
            return resolved

    raise PipelineError(
        "Neither qemu-i386 nor qemu-i386-static was found in PATH."
    )


def prepare_output_directory(path: Path, force: bool) -> None:
    if path.exists():
        if not force:
            raise PipelineError(
                f"Output directory already exists: {path}. Use --force to replace it."
            )
        shutil.rmtree(path)

    (path / "phase1").mkdir(parents=True, exist_ok=False)
    (path / "logs").mkdir(parents=True, exist_ok=False)


def run_captured(
    command: list[str], *, cwd: Path, stdout_path: Path, stderr_path: Path
) -> CommandResult:
    stdout_path.parent.mkdir(parents=True, exist_ok=True)
    stderr_path.parent.mkdir(parents=True, exist_ok=True)

    with stdout_path.open("w", encoding="utf-8") as stdout_file, stderr_path.open(
        "w", encoding="utf-8"
    ) as stderr_file:
        result = subprocess.run(
            command,
            cwd=cwd,
            text=True,
            stdout=stdout_file,
            stderr=stderr_file,
            check=False,
        )

    return CommandResult(
        command=tuple(command),
        returncode=result.returncode,
        stdout_path=stdout_path,
        stderr_path=stderr_path,
    )


def run_phase1(
    *,
    sample: Path,
    plugin: Path,
    qemu: str,
    output_root: Path,
    timeout_seconds: int,
    isolation: str,
    flags_receipt: Path | None = None,
) -> CommandResult:
    phase1_dir = (output_root / "phase1").resolve()
    runtime = Phase1Runtime.load(plugin)
    qemu_identity = runtime.validate_qemu(Path(qemu))
    identity = uuid.uuid4().hex
    phase1_run = Phase1Run(runtime, f"pipeline-{identity}", f"attempt-000-{identity[:12]}",
                           f"analysis-{identity}", phase1_dir,
                           require_flags=flags_receipt is not None, flags_receipt=flags_receipt)
    plugin_argument = phase1_run.plugin_argument()
    atomic_write_json(phase1_dir / "run_binding.json", {
        "schema_version": 1, "session_id": phase1_run.session_id, "attempt_id": phase1_run.attempt_id,
        "analysis_instance_id": phase1_run.analysis_instance_id, "sample_sha256": sha256_file(sample),
        "qemu": qemu_identity, "build_id": runtime.build_id, "plugin_sha256": runtime.plugin_sha256,
        "runtime_manifest_sha256": runtime.manifest_sha256,
        "x86_flags_receipt_sha256": sha256_file(flags_receipt) if flags_receipt is not None else None,
    })
    timeout_program = require_program("timeout")

    qemu_command = [
        timeout_program,
        "--signal=INT",
        "--kill-after=3s",
        f"{timeout_seconds}s",
        qemu,
        "-plugin",
        plugin_argument,
        str(sample),
    ]

    if isolation == "netns":
        unshare = require_program("unshare")
        uid = os.getuid()
        gid = os.getgid()

        if os.geteuid() == 0:
            prefix: list[str] = []
        else:
            require_program("sudo")
            print("[+] Validating sudo for the isolated Phase 1 network namespace")
            sudo_check = subprocess.run(["sudo", "-v"], check=False)
            if sudo_check.returncode != 0:
                raise PipelineError("sudo validation failed")
            prefix = ["sudo"]

        command = prefix + [
            unshare,
            "--net",
            "--pid",
            "--fork",
            "--mount-proc",
            f"--setuid={uid}",
            f"--setgid={gid}",
            "--",
        ] + qemu_command
    elif isolation == "none":
        print(
            "[!] WARNING: Phase 1 network isolation is disabled. "
            "Use this only for a trusted synthetic test binary."
        )
        command = qemu_command
    else:
        raise PipelineError(f"Unknown Phase 1 isolation mode: {isolation}")

    print("[+] Phase 1: executing the sample under qemu-i386 + QEMU plugin")
    result = run_captured(
        command,
        cwd=phase1_dir,
        stdout_path=output_root / "logs" / "phase1_stdout.log",
        stderr_path=output_root / "logs" / "phase1_stderr.log",
    )

    try:
        evidence = phase1_run.verify()
    except Phase1RuntimeError as exc:
        raise PipelineError(f"Phase 1 evidence rejected (QEMU exit {result.returncode}): {exc}") from exc
    if sha256_file(Path(qemu)) != qemu_identity["sha256"]:
        raise PipelineError("QEMU executable changed during Phase 1")
    atomic_write_json(phase1_dir / "runtime_evidence.json", evidence)
    if not evidence["runtime_observed"] or evidence["analysis_status"] == "unsupported":
        raise PipelineError("Phase 1 did not complete a supported instrumented attempt")
    if evidence["stream_status"] == "error":
        raise PipelineError("Phase 1 reported an analysis or output error")
    raw_json = phase1_dir / "unpacked.json"
    raw_dump = phase1_dir / "unpacked.bin"

    if not raw_json.is_file():
        tail = ""
        if result.stderr_path.is_file():
            lines = result.stderr_path.read_text(
                encoding="utf-8", errors="replace"
            ).splitlines()
            tail = "\n".join(lines[-30:])
        raise PipelineError(
            "Phase 1 did not produce unpacked.json. "
            f"Exit code: {result.returncode}.\nLast stderr lines:\n{tail}"
        )

    if not raw_dump.is_file():
        raise PipelineError("Phase 1 produced unpacked.json but not unpacked.bin")
    if raw_json.stat().st_size == 0:
        raise PipelineError("Phase 1 produced an empty unpacked.json")
    if raw_dump.stat().st_size == 0:
        raise PipelineError("Phase 1 produced an empty unpacked.bin")

    if result.returncode != 0:
        print(
            "[!] Phase 1 exited non-zero, but expected artifacts exist. "
            f"Continuing with exit code {result.returncode}."
        )

    return result


def normalize_hex(value: Any, fallback: str) -> str:
    if isinstance(value, str):
        try:
            return hex(int(value, 0))
        except ValueError:
            pass
    if isinstance(value, int) and value >= 0:
        return hex(value)
    return hex(int(fallback, 0))


def normalize_regions(raw_regions: Any) -> list[dict[str, Any]]:
    if not isinstance(raw_regions, list):
        return []

    normalized: list[dict[str, Any]] = []
    for item in raw_regions:
        if not isinstance(item, dict):
            continue
        try:
            address = normalize_hex(item.get("addr"), "0")
            size = int(item.get("size"))
            protection = int(item.get("prot"))
            offset = int(item.get("offset"))
        except (TypeError, ValueError):
            continue
        if size <= 0 or offset < 0:
            continue
        normalized.append(
            {
                "addr": address,
                "size": size,
                "prot": protection,
                "offset": offset,
            }
        )

    normalized.sort(key=lambda region: int(region["addr"], 0))
    return normalized


def normalize_file_dependencies(raw_dependencies: Any) -> list[dict[str, Any]]:
    if not isinstance(raw_dependencies, list):
        return []

    by_path: dict[str, bool] = {}
    for item in raw_dependencies:
        if not isinstance(item, dict):
            continue
        path = item.get("path")
        if not isinstance(path, str) or not path.startswith("/"):
            continue
        write = bool(item.get("write", False))
        by_path[path] = by_path.get(path, False) or write

    return [{"path": path, "write": by_path[path]} for path in sorted(by_path)]


def classify_network_type(operation: str, raw_type: Any, port: int) -> str:
    if port == 53:
        return "dns"
    if port == 123:
        return "ntp"
    if operation == "sendto":
        return "udp"
    if isinstance(raw_type, str) and raw_type in {"tcp", "udp"}:
        return raw_type
    return "tcp"


def normalize_ip(value: Any) -> str | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def normalize_network_dependencies(
    raw_dependencies: Any,
) -> tuple[
    list[dict[str, Any]],
    list[dict[str, Any]],
    list[dict[str, Any]],
]:
    """Convert Phase 1 events into emulatable and unsupported endpoints.

    Loopback endpoints are kept out of the current host-side Phase 2 known
    service model. From inside a network namespace, 127.0.0.0/8 refers to the
    namespace itself rather than to the host-side listener at 10.10.0.1.
    """
    if not isinstance(raw_dependencies, list):
        return [], [], []

    endpoints: dict[tuple[str, int, str], dict[str, Any]] = {}
    skipped: list[dict[str, Any]] = []
    unsupported_loopback: dict[
        tuple[str, int, str],
        dict[str, Any],
    ] = {}

    for item in raw_dependencies:
        if not isinstance(item, dict):
            skipped.append({"reason": "not_an_object", "value": repr(item)})
            continue

        operation = item.get("op")
        if operation not in {"connect", "sendto"}:
            skipped.append(
                {
                    "reason": "event_has_no_remote_endpoint",
                    "op": operation,
                    "fd": item.get("fd"),
                }
            )
            continue

        ip = normalize_ip(item.get("ip"))
        try:
            port = int(item.get("port"))
        except (TypeError, ValueError):
            port = 0

        if ip is None or not (1 <= port <= 65535):
            skipped.append(
                {
                    "reason": "invalid_remote_endpoint",
                    "op": operation,
                    "ip": item.get("ip"),
                    "port": item.get("port"),
                }
            )
            continue

        network_type = classify_network_type(
            str(operation),
            item.get("type"),
            port,
        )
        key = (ip, port, network_type)
        endpoint = {
            "ip": ip,
            "port": port,
            "type": network_type,
        }

        if ipaddress.ip_address(ip).is_loopback:
            unsupported_loopback[key] = endpoint
            continue

        endpoints[key] = endpoint

    normalized = [
        endpoints[key]
        for key in sorted(
            endpoints,
            key=lambda value: (value[0], value[1], value[2]),
        )
    ]
    loopback = [
        unsupported_loopback[key]
        for key in sorted(
            unsupported_loopback,
            key=lambda value: (value[0], value[1], value[2]),
        )
    ]
    return normalized, skipped, loopback


def build_phase2_input(
    *, raw_phase1: dict[str, Any], elf: ElfInfo
) -> tuple[dict[str, Any], dict[str, Any]]:
    regions = normalize_regions(raw_phase1.get("regions"))
    files = normalize_file_dependencies(raw_phase1.get("file_dependencies"))
    (
        networks,
        skipped_network_events,
        unsupported_loopback_endpoints,
    ) = normalize_network_dependencies(
        raw_phase1.get("network_dependencies")
    )

    raw_oep = normalize_hex(raw_phase1.get("oep"), elf.entry_point)
    used_entry_fallback = int(raw_oep, 0) == 0
    oep = normalize_hex(elf.entry_point, "0") if used_entry_fallback else raw_oep

    fallback_base = regions[0]["addr"] if regions else elf.entry_point
    base = normalize_hex(raw_phase1.get("base"), fallback_base)
    if int(base, 0) == 0 and regions:
        base = regions[0]["addr"]

    phase2_input = {
        "oep": oep,
        "arch": "x86",
        "base": base,
        "regions": regions,
        "file_dependencies": files,
        "network_dependencies": networks,
        "library_dependencies": [],
        "anti_analysis": {
            "cpuinfo_check": False,
            "uname_check": False,
            "ptrace_traceme": False,
        },
    }

    adapter_audit = {
        "adapter_version": SCRIPT_VERSION,
        "mode": "original_static_elf_with_phase1_metadata",
        "oep_source": "elf_entry_fallback" if used_entry_fallback else "phase1",
        "raw_counts": {
            "regions": len(raw_phase1.get("regions", []))
            if isinstance(raw_phase1.get("regions"), list)
            else 0,
            "file_dependencies": len(raw_phase1.get("file_dependencies", []))
            if isinstance(raw_phase1.get("file_dependencies"), list)
            else 0,
            "network_events": len(raw_phase1.get("network_dependencies", []))
            if isinstance(raw_phase1.get("network_dependencies"), list)
            else 0,
            "library_events": len(raw_phase1.get("library_dependencies", []))
            if isinstance(raw_phase1.get("library_dependencies"), list)
            else 0,
        },
        "normalized_counts": {
            "regions": len(regions),
            "file_dependencies": len(files),
            "network_dependencies": len(networks),
            "library_dependencies": 0,
        },
        "skipped_network_events": skipped_network_events,
        "unsupported_loopback_endpoints": (
            unsupported_loopback_endpoints
        ),
        "limitations": [
            "Phase 2 executes the original static ELF, not unpacked.bin.",
            (
                "Loopback endpoints are retained in the bridge audit but "
                "are not promoted to host-side known services because "
                "127.0.0.0/8 inside a network namespace refers to that "
                "namespace itself."
            ),
            "unpacked.bin is retained as a Phase 1 artifact only.",
            "No register state or address-preserving snapshot replay is performed.",
            "Phase 1 event-style network records are reduced to connect/sendto endpoints.",
            "This bridge is intended for current MVP integration demonstrations.",
        ],
    }
    return phase2_input, adapter_audit


def load_json_object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise PipelineError(f"Invalid JSON in {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise PipelineError(f"Expected a JSON object in {path}")
    return value


def oep_certificate_reference(
    path: Path, *, sample_sha256: str, candidate: Any
) -> dict[str, Any]:
    """Import an offline certificate as a reference, never as this run's proof."""
    path = path.expanduser()
    if path.is_symlink() or not path.is_file():
        raise PipelineError("OEP certificate must be a regular file")
    with path.open("rb") as stream:
        raw = stream.read(1024 * 1024 + 1)
    if len(raw) > 1024 * 1024:
        raise PipelineError("OEP certificate exceeds 1 MiB")

    def object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise ValueError(f"duplicate key: {key}")
            value[key] = item
        return value

    def invalid_constant(value: str) -> None:
        raise ValueError(f"non-finite JSON number: {value}")

    try:
        certificate = json.loads(raw.decode("utf-8"), object_pairs_hook=object_pairs,
                                 parse_constant=invalid_constant)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise PipelineError(f"Invalid OEP certificate JSON: {exc}") from exc
    if (not isinstance(certificate, dict)
            or type(certificate.get("schema_version")) is not int
            or certificate["schema_version"] != 1
            or certificate.get("status") not in (
                "VERIFIED_RESTORED_ENTRY_UNDER_EXPLICIT_PREMISES",
                "CONFIRMED_REFERENCE_ENTRY_FOR_OBSERVED_RUN_UNDER_TRUSTED_MODELS")
            or certificate.get("restored_image_entry_verified_under_premises") is not True
            or certificate.get("oep_proof") != "NOT_ESTABLISHED"):
        raise PipelineError("Unsupported OEP reference certificate schema or scope")
    if (certificate["status"] == "CONFIRMED_REFERENCE_ENTRY_FOR_OBSERVED_RUN_UNDER_TRUSTED_MODELS"
            and certificate.get("oep_confirmed_for_observed_run_under_trusted_models") is not True):
        raise PipelineError("Unsupported OEP reference certificate observed-run confirmation")
    required_false = (
        "original_prepack_OEP_independently_established", "independent_OS_entry_origins_proven",
        "kernel_implementation_verified", "guest_permissions_independently_observed",
        "unconditional_oep_proven", "historical_certificates_upgraded",
        "target_instruction_executed", "checkpoint_used_as_seed",
    )
    optional_false = ("oep_proven", "whole_program_oep_proven", "fuzzing_ready", "process_checkpoint",
                      "applies_to_current_run", "current_run_binding_verified")
    if (any(certificate.get(key) is not False for key in required_false)
            or any(key in certificate and certificate[key] is not False for key in optional_false)):
        raise PipelineError("OEP reference certificate promotes unsupported proof scope")
    source = certificate.get("source_elf_sha256")
    target = certificate.get("payload_entry")
    if (not isinstance(source, str) or len(source) != 64
            or any(char not in "0123456789abcdef" for char in source)
            or type(target) is not int or not 0 <= target <= 0xffffffff
            or not isinstance(certificate.get("conditions"), list) or not certificate["conditions"]
            or not isinstance(certificate.get("open_obligations"), list) or not certificate["open_obligations"]):
        raise PipelineError("Invalid OEP reference identity or premise fields")
    try:
        current_target = int(candidate, 0) if isinstance(candidate, str) else candidate
    except ValueError:
        current_target = None
    return {
        "status": "REFERENCE_ONLY", "certificate_path": str(path.resolve()),
        "certificate_sha256": hashlib.sha256(raw).hexdigest(),
        "certificate_status": certificate["status"], "source_elf_sha256": source,
        "payload_entry": target, "sample_sha256_matches": source == sample_sha256,
        "candidate_address_matches": type(current_target) is int and current_target == target,
        "current_run_binding_verified": False, "applies_to_current_run": False,
        "oep_proven": False, "process_checkpoint": False, "fuzzing_ready": False,
        "oep_proof": "NOT_ESTABLISHED",
        "scope": "Offline reference only; this import verifies no current Phase 1 execution or snapshot binding.",
    }


def oep_proof_reference(
    path: Path, *, sample_sha256: str, candidate: Any
) -> dict[str, Any]:
    """Audit recorded proof receipts without binding a fresh pipeline execution."""
    try:
        from unpacker.oep_audit import audit_evidence

        audited = audit_evidence(path.expanduser())
    except (ImportError, ValueError, OSError, KeyError, TypeError, RecursionError,
            zipfile.BadZipFile) as exc:
        raise PipelineError(f"Invalid OEP proof evidence: {exc}") from exc
    if (not isinstance(audited, dict)
            or type(audited.get("schema_version")) is not int
            or audited["schema_version"] != 1
            or audited.get("status") != "SMT_REFERENCE_RECEIPTS_AUDITED"):
        raise PipelineError("Unsupported OEP proof audit status or schema")
    source, target = audited.get("source_elf_sha256"), audited.get("entry")
    if (not isinstance(source, str) or len(source) != 64
            or any(char not in "0123456789abcdef" for char in source)
            or type(target) is not int or not 0 <= target <= 0xffffffff
            or audited.get("certificate_status") != "SMT_PROVED_REFERENCE_OEP_FOR_SELECTED_EXECUTION"
            or audited.get("oep_proof") != "SMT_SELECTED_EXECUTION_TO_REFERENCE_OEP_UNDER_TRUSTED_MODELS"):
        raise PipelineError("Invalid OEP proof audit identity or recorded scope")
    false_scope = (
        "unconditional_oep_proven", "current_run_binding_verified", "applies_to_current_run",
        "solver_results_recomputed", "proof_results_recomputed", "fuzzing_ready",
        "oep_proven", "process_checkpoint",
    )
    if any(key in audited and audited[key] is not False for key in false_scope):
        raise PipelineError("OEP proof audit promotes unsupported current-run or proof scope")
    try:
        current_target = int(candidate, 0) if isinstance(candidate, str) else candidate
    except ValueError:
        current_target = None
    return {
        **audited,
        "proof_reference_path": str(path.expanduser().resolve()),
        "payload_entry": target,
        "sample_sha256_matches": source == sample_sha256,
        "candidate_address_matches": type(current_target) is int and current_target == target,
        "current_run_binding_verified": False, "applies_to_current_run": False,
        "oep_proven": False, "process_checkpoint": False, "fuzzing_ready": False,
        "solver_results_recomputed": False, "proof_results_recomputed": False,
        "recorded_solver_results_trusted": True,
        "reference_scope": (
            "Offline recorded SMT proof receipts; this audit verifies no current "
            "Phase 1 execution or snapshot binding."
        ),
    }


def tcp_dependency_ports(phase2_payload: dict[str, Any]) -> list[int]:
    ports: set[int] = set()

    raw_dependencies = phase2_payload.get("network_dependencies", [])
    if not isinstance(raw_dependencies, list):
        return []

    for item in raw_dependencies:
        if not isinstance(item, dict):
            continue

        network_type = item.get("type")
        if network_type in {"udp", "dns", "ntp"}:
            continue

        try:
            port = int(item.get("port"))
        except (TypeError, ValueError):
            continue

        if 1 <= port <= 65535:
            ports.add(port)

    return sorted(ports)


def read_sysctl_int(key: str) -> int:
    sysctl = require_program("sysctl")
    result = subprocess.run(
        [sysctl, "-n", key],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        raise PipelineError(
            f"Could not read sysctl {key}: {result.stderr.strip()}"
        )

    try:
        return int(result.stdout.strip())
    except ValueError as exc:
        raise PipelineError(
            f"Unexpected integer value for sysctl {key}: "
            f"{result.stdout.strip()!r}"
        ) from exc


def write_sysctl_int(key: str, value: int) -> None:
    sysctl = require_program("sysctl")
    command = [sysctl, "-q", "-w", f"{key}={value}"]

    if os.geteuid() != 0:
        require_program("sudo")
        command.insert(0, "sudo")

    result = subprocess.run(
        command,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        raise PipelineError(
            f"Could not set sysctl {key}={value}: "
            f"{result.stderr.strip()}"
        )


def enable_privileged_bind_workaround(
    *,
    phase2_payload: dict[str, Any],
    network: str,
    enabled: bool,
) -> dict[str, Any]:
    state: dict[str, Any] = {
        "enabled": enabled,
        "applied": False,
        "sysctl": "net.ipv4.ip_unprivileged_port_start",
        "original_value": None,
        "temporary_value": None,
        "tcp_ports": tcp_dependency_ports(phase2_payload),
    }

    if not enabled or network == "none" or os.geteuid() == 0:
        return state

    ports = state["tcp_ports"]
    if not ports:
        return state

    key = state["sysctl"]
    original = read_sysctl_int(key)
    state["original_value"] = original

    minimum_required_port = min(ports)
    if minimum_required_port >= original:
        return state

    print(
        "[!] Phase 2 known-service emulator needs a privileged host port: "
        f"{minimum_required_port}"
    )
    print(
        "[+] Temporarily setting "
        f"{key}={minimum_required_port}; it will be restored after Phase 2"
    )

    write_sysctl_int(key, minimum_required_port)
    state["applied"] = True
    state["temporary_value"] = minimum_required_port
    return state


def restore_privileged_bind_workaround(state: dict[str, Any]) -> None:
    if not state.get("applied"):
        return

    key = str(state["sysctl"])
    original = int(state["original_value"])
    print(f"[+] Restoring {key}={original}")
    write_sysctl_int(key, original)
    state["restored"] = True


def read_log_tail(path: Path, lines: int = 30) -> str:
    if not path.is_file():
        return ""
    content = path.read_text(encoding="utf-8", errors="replace").splitlines()
    return "\n".join(content[-lines:])


def choose_effective_phase2_network(
    *,
    requested_network: str,
    requested_self_test: bool,
    phase2_payload: dict[str, Any],
    adapter_audit: dict[str, Any],
) -> tuple[str, bool, dict[str, Any]]:
    """Choose a truthful Phase 2 network mode for the current MVP bridge."""
    emulatable_dependencies = phase2_payload.get(
        "network_dependencies",
        [],
    )
    if not isinstance(emulatable_dependencies, list):
        emulatable_dependencies = []

    loopback_dependencies = adapter_audit.get(
        "unsupported_loopback_endpoints",
        [],
    )
    if not isinstance(loopback_dependencies, list):
        loopback_dependencies = []

    effective_network = requested_network
    effective_self_test = requested_self_test
    reason: str | None = None

    if requested_network == "auto" and not emulatable_dependencies:
        effective_network = "none"
        effective_self_test = False

        if loopback_dependencies:
            reason = (
                "Only loopback endpoints were discovered. The current "
                "host-side emulator cannot intercept namespace-local "
                "127.0.0.0/8 destinations, so auto mode falls back to "
                "network=none. Runtime strace still records the malware "
                "network attempt."
            )
        else:
            reason = (
                "No emulatable network endpoints were discovered, so auto "
                "mode falls back to network=none."
            )

    decision = {
        "requested_network": requested_network,
        "effective_network": effective_network,
        "requested_self_test": requested_self_test,
        "effective_self_test": effective_self_test,
        "emulatable_dependencies": len(emulatable_dependencies),
        "unsupported_loopback_endpoints": loopback_dependencies,
        "reason": reason,
    }
    return effective_network, effective_self_test, decision


def run_phase2(
    *,
    project_root: Path,
    sample: Path,
    phase2_input: Path,
    phase2_out: Path,
    timeout_seconds: int,
    network: str,
    sysroot: Path | None,
    allow_missing_libraries: bool,
    keep_namespace: bool,
    self_test_network: bool,
    output_root: Path,
) -> CommandResult:
    command = [
        sys.executable,
        str(project_root / "scripts" / "run_sample.py"),
        "--taint",
        str(phase2_input),
        "--binary",
        str(sample),
        "--out",
        str(phase2_out),
        "--timeout",
        str(timeout_seconds),
        "--network",
        network,
    ]

    if sysroot is not None:
        command.extend(["--sysroot", str(sysroot)])
    if allow_missing_libraries:
        command.append("--allow-missing-libraries")
    if keep_namespace:
        command.append("--keep-namespace")
    if self_test_network:
        command.append("--self-test-network")

    env = os.environ.copy()
    env["PYTHONPATH"] = str(project_root)

    stdout_path = output_root / "logs" / "phase2_stdout.log"
    stderr_path = output_root / "logs" / "phase2_stderr.log"

    print("[+] Phase 2: environment reconstruction, controlled execution, and report")
    print(f"[cmd] {' '.join(command)}")

    with stdout_path.open("w", encoding="utf-8") as stdout_file, stderr_path.open(
        "w", encoding="utf-8"
    ) as stderr_file:
        result = subprocess.run(
            command,
            cwd=project_root,
            env=env,
            text=True,
            stdout=stdout_file,
            stderr=stderr_file,
            check=False,
        )

    if result.returncode != 0:
        stdout_tail = "\n".join(
            stdout_path.read_text(encoding="utf-8", errors="replace").splitlines()[-30:]
        )
        stderr_tail = "\n".join(
            stderr_path.read_text(encoding="utf-8", errors="replace").splitlines()[-30:]
        )
        service_logs: list[str] = []
        for name in (
            "network_emulator_stderr.log",
            "transparent_logger_stderr.log",
            "c2_record_broker_stderr.log",
        ):
            path = phase2_out / "logs" / name
            tail = read_log_tail(path)
            if tail:
                service_logs.append(f"Last {name} lines:\n{tail}")

        service_section = (
            "\n" + "\n".join(service_logs)
            if service_logs
            else ""
        )

        raise PipelineError(
            "Phase 2 failed.\n"
            f"Exit code: {result.returncode}\n"
            f"Last stdout lines:\n{stdout_tail}\n"
            f"Last stderr lines:\n{stderr_tail}"
            f"{service_section}"
        )

    return CommandResult(
        command=tuple(command),
        returncode=result.returncode,
        stdout_path=stdout_path,
        stderr_path=stderr_path,
    )


def relative_or_absolute(path: Path, base: Path) -> str:
    try:
        return str(path.relative_to(base))
    except ValueError:
        return str(path)


def build_markdown_report(report: dict[str, Any]) -> str:
    input_info = report["input"]
    phase1 = report["phase1"]
    bridge = report["bridge"]
    phase2 = report["phase2"]

    lines = [
        "# TaintForge-IoT Temporary Unified Pipeline Report",
        "",
        f"- **Status:** `{report['status']}`",
        f"- **Generated:** `{report['generated_at_utc']}`",
        f"- **Wrapper version:** `{report['wrapper_version']}`",
        "",
        "## Input",
        "",
        f"- File: `{input_info.get('path')}`",
        f"- SHA-256: `{input_info.get('sha256')}`",
        f"- ELF class: `{input_info.get('elf_class')}`",
        f"- Machine: `{input_info.get('machine')}`",
        f"- Endianness: `{input_info.get('endianness')}`",
        f"- Entry point: `{input_info.get('entry_point')}`",
        f"- Static: `{input_info.get('statically_linked')}`",
        "",
        "## Phase 1",
        "",
        f"- Status: `{phase1.get('status')}`",
        f"- QEMU return code: `{phase1.get('returncode')}`",
        f"- Raw metadata: `{phase1.get('unpacked_json')}`",
        f"- Raw memory dump: `{phase1.get('unpacked_bin')}`",
        f"- OEP recorded by Phase 1: `{phase1.get('oep')}`",
        f"- Imported OEP certificate: `{phase1.get('oep_verification', {}).get('status', 'not_requested')}`",
        f"- Dumped regions: `{phase1.get('regions')}`",
        f"- File dependencies: `{phase1.get('file_dependencies')}`",
        f"- Network events: `{phase1.get('network_events')}`",
        "",
        "## Compatibility Bridge",
        "",
        f"- Status: `{bridge.get('status')}`",
        f"- Mode: `{bridge.get('mode')}`",
        f"- Phase 2 input: `{bridge.get('phase2_input')}`",
        f"- OEP source: `{bridge.get('oep_source')}`",
        f"- Normalized network endpoints: `{bridge.get('network_dependencies')}`",
        (
            "- Unsupported loopback endpoints: `"
            + str(
                len(
                    bridge.get("network_decision", {}).get(
                        "unsupported_loopback_endpoints",
                        [],
                    )
                )
            )
            + "`"
        ),
        (
            "- Effective network mode: `"
            + str(
                bridge.get("network_decision", {}).get(
                    "effective_network",
                    "unknown",
                )
            )
            + "`"
        ),
        (
            "- Effective network self-test: `"
            + str(
                bridge.get("network_decision", {}).get(
                    "effective_self_test",
                    False,
                )
            )
            + "`"
        ),
        "",
        "## Phase 2",
        "",
        f"- Status: `{phase2.get('status')}`",
        f"- Output directory: `{phase2.get('output_dir')}`",
        f"- JSON report: `{phase2.get('report_json')}`",
        f"- Markdown report: `{phase2.get('report_md')}`",
        f"- Runtime requirements: `{phase2.get('runtime_requirements')}`",
        f"- Repair plan: `{phase2.get('repair_plan')}`",
        "",
        "## Current Limitations",
        "",
    ]

    imported_proof = phase1.get("oep_verification", {})
    if imported_proof.get("status") == "SMT_REFERENCE_RECEIPTS_AUDITED":
        position = lines.index("## Compatibility Bridge") - 1
        lines[position:position] = [
            f"- Recorded reference OEP: `{hex(imported_proof['payload_entry'])}`",
            f"- Recorded proof status: `{imported_proof['certificate_status']}`",
            f"- Recorded proof: `{imported_proof['oep_proof']}`",
            f"- Imported proof scope: {imported_proof['reference_scope']}",
            f"- Current Phase 1 binding verified: `{imported_proof['current_run_binding_verified']}`",
            f"- Current Phase 1 OEP proved: `{imported_proof['oep_proven']}`",
            f"- Imported solver results recomputed: `{imported_proof['solver_results_recomputed']}`",
        ]

    lines.extend(f"- {item}" for item in report["limitations"])

    if report.get("error"):
        lines.extend(["", "## Error", "", "```text", str(report["error"]), "```"])

    lines.append("")
    return "\n".join(lines)


def default_output_path(project_root: Path, sample: Path) -> Path:
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return project_root / "workdir" / f"pipeline_{sample.stem}_{timestamp}"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Temporary unified TaintForge-IoT launcher for static Linux i386 ELF files."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """
            Example:
              PYTHONPATH=. python scripts/run_static_pipeline.py \\
                samples/test_stat \\
                --out workdir/full_test_stat \\
                --network auto

            The wrapper keeps Phase 1 raw artifacts, writes a Phase 2-compatible
            metadata file, launches the existing Phase 2 orchestrator, and emits
            pipeline_report.json plus pipeline_report.md.
            """
        ),
    )

    parser.add_argument("sample", help="Path to a statically linked i386 ELF")
    parser.add_argument("--project-root", default=None)
    parser.add_argument(
        "--plugin",
        default=None,
        help=(
            "Compiled Phase 1 plugin (.so). If omitted or missing, the wrapper "
            "builds build/libtaintforge_ir.so using the canonical recipe."
        ),
    )
    parser.add_argument(
        "--qemu-source",
        default=None,
        help=(
            "Configured QEMU source tree containing include/ and build/. "
            "Defaults to TAINTFORGE_QEMU_SOURCE, QEMU_SRC, or ~/qemu."
        ),
    )
    parser.add_argument(
        "--no-auto-build-plugin",
        action="store_true",
        help="Do not build the Phase 1 plugin when no .so is found.",
    )
    parser.add_argument("--qemu", default=None, help="qemu-i386 executable or path")
    parser.add_argument("--x86-flags-receipt", type=Path,
                        help="EFLAGS probe receipt for this QEMU executable; checked by the plugin")
    parser.add_argument("--out", default=None, help="Pipeline output directory")
    parser.add_argument("--phase1-timeout", type=int, default=20)
    parser.add_argument("--phase1-only", action="store_true", help="Validate Phase 1 and its artifacts, then finish before Phase 2")
    oep_reference = parser.add_mutually_exclusive_group()
    oep_reference.add_argument("--oep-certificate", type=Path,
                               help="Offline conditional OEP certificate for reference only; never proves this Phase 1 run")
    oep_reference.add_argument("--oep-proof", type=Path,
                               help="Audit recorded SMT proof evidence (result directory or ZIP); never proves this Phase 1 run")
    parser.add_argument("--phase2-timeout", type=int, default=60)
    parser.add_argument(
        "--network",
        choices=["auto", "none", "emulated", "controlled"],
        default="auto",
    )
    parser.add_argument("--sysroot", default=None)
    parser.add_argument(
        "--phase1-isolation",
        choices=["netns", "none"],
        default="netns",
    )
    parser.add_argument("--allow-missing-libraries", action="store_true")
    parser.add_argument("--keep-namespace", action="store_true")
    parser.add_argument("--self-test-network", action="store_true")
    parser.add_argument(
        "--no-privileged-bind-workaround",
        action="store_true",
        help=(
            "Do not temporarily lower "
            "net.ipv4.ip_unprivileged_port_start when Phase 2 needs a "
            "known service on a port below the current threshold."
        ),
    )
    parser.add_argument("--force", action="store_true")

    args = parser.parse_args()
    if args.phase1_timeout <= 0:
        parser.error("--phase1-timeout must be positive")
    if args.phase2_timeout <= 0:
        parser.error("--phase2-timeout must be positive")
    if args.network == "none" and args.self_test_network:
        parser.error("--self-test-network cannot be used with --network none")
    return args


def main() -> int:
    args = parse_args()

    report: dict[str, Any] = {
        "schema_version": 1,
        "wrapper_version": SCRIPT_VERSION,
        "generated_at_utc": utc_now(),
        "status": "initializing",
        "input": {},
        "phase1": {"status": "not_started"},
        "bridge": {"status": "not_started"},
        "phase2": {"status": "not_started"},
        "limitations": [
            "This is a temporary integration wrapper, not the final execution architecture.",
            "Only statically linked Linux i386 ELF inputs are accepted.",
            "Phase 2 executes the original static ELF rather than the raw memory dump.",
            "No fixed-address memory replay or register restoration is performed.",
            "Phase 1 network isolation is not a complete filesystem sandbox.",
            "Phase 1 and Phase 2 schemas are bridged by a lossy adapter.",
            (
                "Loopback endpoints are reported but are not yet emulated "
                "by the current host-side network backend."
            ),
        ],
    }

    output_root: Path | None = None

    try:
        project_root = resolve_project_root(args.project_root)
        sample = Path(args.sample).expanduser().resolve()
        if not sample.exists():
            raise PipelineError(f"Input sample does not exist: {sample}")

        elf = inspect_elf(sample)
        validate_sample(sample, elf)
        plugin = resolve_or_build_plugin(
            project_root=project_root,
            explicit=args.plugin,
            qemu_source_explicit=args.qemu_source,
            auto_build=not args.no_auto_build_plugin,
        )
        qemu = resolve_qemu(args.qemu)
        Phase1Runtime.load(plugin).validate_qemu(Path(qemu))

        output_root = (
            Path(args.out).expanduser().resolve()
            if args.out
            else default_output_path(project_root, sample)
        )
        prepare_output_directory(output_root, args.force)

        report["input"] = {
            "path": str(sample),
            "sha256": sha256_file(sample),
            "size": sample.stat().st_size,
            "elf_class": elf.elf_class,
            "endianness": elf.endianness,
            "machine": elf.machine,
            "entry_point": elf.entry_point,
            "statically_linked": elf.statically_linked,
        }
        report["project_root"] = str(project_root)
        report["output_root"] = str(output_root)
        report["plugin"] = {"path": str(plugin), "sha256": sha256_file(plugin)}
        report["qemu"] = qemu

        print("[+] TaintForge-IoT temporary unified static pipeline")
        print(f"[+] project: {project_root}")
        print(f"[+] sample:  {sample}")
        print(f"[+] plugin:  {plugin}")
        print(f"[+] output:  {output_root}")
        print()

        report["phase1"]["status"] = "running"
        phase1_result = run_phase1(
            sample=sample,
            plugin=plugin,
            qemu=qemu,
            output_root=output_root,
            timeout_seconds=args.phase1_timeout,
            isolation=args.phase1_isolation,
            flags_receipt=args.x86_flags_receipt.expanduser().resolve() if args.x86_flags_receipt else None,
        )

        raw_json_path = output_root / "phase1" / "unpacked.json"
        raw_dump_path = output_root / "phase1" / "unpacked.bin"
        raw_phase1 = load_json_object(raw_json_path)

        report["phase1"] = {
            "status": "completed",
            "runtime_evidence": load_json_object(output_root / "phase1" / "runtime_evidence.json"),
            "returncode": phase1_result.returncode,
            "command": list(phase1_result.command),
            "stdout_log": relative_or_absolute(phase1_result.stdout_path, output_root),
            "stderr_log": relative_or_absolute(phase1_result.stderr_path, output_root),
            "unpacked_json": relative_or_absolute(raw_json_path, output_root),
            "unpacked_json_sha256": sha256_file(raw_json_path),
            "unpacked_bin": relative_or_absolute(raw_dump_path, output_root),
            "unpacked_bin_sha256": sha256_file(raw_dump_path),
            "unpacked_bin_size": raw_dump_path.stat().st_size,
            "oep": raw_phase1.get("oep"),
            "regions": len(raw_phase1.get("regions", []))
            if isinstance(raw_phase1.get("regions"), list)
            else 0,
            "file_dependencies": len(raw_phase1.get("file_dependencies", []))
            if isinstance(raw_phase1.get("file_dependencies"), list)
            else 0,
            "network_events": len(raw_phase1.get("network_dependencies", []))
            if isinstance(raw_phase1.get("network_dependencies"), list)
            else 0,
        }

        if args.oep_certificate is not None:
            report["phase1"]["oep_verification"] = oep_certificate_reference(
                args.oep_certificate, sample_sha256=report["input"]["sha256"],
                candidate=raw_phase1.get("oep"),
            )
        elif args.oep_proof is not None:
            report["phase1"]["oep_verification"] = oep_proof_reference(
                args.oep_proof, sample_sha256=report["input"]["sha256"],
                candidate=raw_phase1.get("oep"),
            )

        if args.phase1_only:
            report["status"] = "completed"
            report["phase2"]["status"] = "not_requested"
            return 0

        print("[+] Bridge: adapting Phase 1 JSON for current Phase 2")
        phase2_payload, adapter_audit = build_phase2_input(
            raw_phase1=raw_phase1, elf=elf
        )
        if "oep_verification" in report["phase1"]:
            adapter_audit["oep_verification"] = report["phase1"]["oep_verification"]
        phase2_input_path = output_root / "phase2_input.json"
        adapter_audit_path = output_root / "bridge_audit.json"
        atomic_write_json(phase2_input_path, phase2_payload)
        atomic_write_json(adapter_audit_path, adapter_audit)

        report["bridge"] = {
            "status": "completed",
            "mode": adapter_audit["mode"],
            "phase2_input": relative_or_absolute(phase2_input_path, output_root),
            "phase2_input_sha256": sha256_file(phase2_input_path),
            "audit": relative_or_absolute(adapter_audit_path, output_root),
            "oep_source": adapter_audit["oep_source"],
            "network_dependencies": adapter_audit["normalized_counts"][
                "network_dependencies"
            ],
        }
        if "oep_verification" in report["phase1"]:
            report["bridge"]["oep_verification"] = report["phase1"]["oep_verification"]

        report["phase2"]["status"] = "running"
        phase2_out = output_root / "phase2"
        sysroot = (
            Path(args.sysroot).expanduser().resolve()
            if args.sysroot is not None
            else None
        )
        (
            effective_network,
            effective_self_test,
            network_decision,
        ) = choose_effective_phase2_network(
            requested_network=args.network,
            requested_self_test=args.self_test_network,
            phase2_payload=phase2_payload,
            adapter_audit=adapter_audit,
        )
        report["bridge"]["network_decision"] = network_decision

        if network_decision["reason"]:
            print(f"[!] {network_decision['reason']}")
            print(
                "[+] Effective Phase 2 network configuration: "
                f"network={effective_network}, "
                f"self_test={effective_self_test}"
            )

        privileged_bind_state = enable_privileged_bind_workaround(
            phase2_payload=phase2_payload,
            network=effective_network,
            enabled=not args.no_privileged_bind_workaround,
        )
        report["phase2"]["privileged_bind_workaround"] = (
            privileged_bind_state
        )

        try:
            phase2_result = run_phase2(
                project_root=project_root,
                sample=sample,
                phase2_input=phase2_input_path,
                phase2_out=phase2_out,
                timeout_seconds=args.phase2_timeout,
                network=effective_network,
                sysroot=sysroot,
                allow_missing_libraries=args.allow_missing_libraries,
                keep_namespace=args.keep_namespace,
                self_test_network=effective_self_test,
                output_root=output_root,
            )
        finally:
            restore_privileged_bind_workaround(
                privileged_bind_state
            )

        phase2_report_json = phase2_out / "report.json"
        phase2_report_md = phase2_out / "report.md"
        runtime_requirements = phase2_out / "config" / "runtime_requirements.json"
        repair_plan = phase2_out / "config" / "repair_plan.json"

        report["phase2"] = {
            "status": "completed",
            "returncode": phase2_result.returncode,
            "command": list(phase2_result.command),
            "stdout_log": relative_or_absolute(phase2_result.stdout_path, output_root),
            "stderr_log": relative_or_absolute(phase2_result.stderr_path, output_root),
            "output_dir": relative_or_absolute(phase2_out, output_root),
            "report_json": relative_or_absolute(phase2_report_json, output_root)
            if phase2_report_json.exists()
            else None,
            "report_md": relative_or_absolute(phase2_report_md, output_root)
            if phase2_report_md.exists()
            else None,
            "runtime_requirements": relative_or_absolute(
                runtime_requirements, output_root
            )
            if runtime_requirements.exists()
            else None,
            "repair_plan": relative_or_absolute(repair_plan, output_root)
            if repair_plan.exists()
            else None,
            "privileged_bind_workaround": privileged_bind_state,
            "network_decision": network_decision,
        }

        report["status"] = "completed"
        print()
        print("[+] Unified pipeline completed")
        print(f"[+] Pipeline report: {output_root / 'pipeline_report.json'}")
        print(f"[+] Phase 2 report:   {phase2_report_json}")

    except (PipelineError, Phase1RuntimeError, OSError) as exc:
        report["status"] = "failed"
        report["error"] = str(exc)
        print(f"[-] Unified pipeline failed: {exc}", file=sys.stderr)

    finally:
        report["generated_at_utc"] = utc_now()
        if output_root is not None and output_root.exists():
            atomic_write_json(output_root / "pipeline_report.json", report)
            atomic_write_text(
                output_root / "pipeline_report.md", build_markdown_report(report)
            )

    return 0 if report["status"] == "completed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
