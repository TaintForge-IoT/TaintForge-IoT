"""Delivery-I runtime contract. Byte integrity is separate from guest isolation.

These helpers accept only an explicitly selected plugin and its build manifest.
They never infer checkpoint, controllable-input, OEP or fuzzing readiness from
an IR MATCH, a successful guest exit, or a self-reported capability.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
import stat
from typing import Any

from .elf_target import inspect_elf_target


class Phase1RuntimeError(RuntimeError):
    pass


def digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise Phase1RuntimeError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def _parse(text: str) -> dict[str, Any]:
    try:
        value = json.loads(text, object_pairs_hook=_object, parse_constant=lambda s: (_ for _ in ()).throw(ValueError(s)))
    except (ValueError, TypeError) as exc:
        raise Phase1RuntimeError(f"invalid runtime JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise Phase1RuntimeError("runtime JSON must be an object")
    return value


def _regular(path: Path, maximum: int) -> None:
    try:
        info = path.lstat()
    except OSError as exc:
        raise Phase1RuntimeError(f"missing runtime artifact: {path}") from exc
    if not stat.S_ISREG(info.st_mode) or info.st_size > maximum:
        raise Phase1RuntimeError(f"not a bounded regular runtime artifact: {path}")


def read_json(path: Path, maximum: int = 64 * 1024 * 1024) -> dict[str, Any]:
    _regular(path, maximum)
    return _parse(path.read_text(encoding="utf-8"))


@dataclass(frozen=True)
class Phase1Runtime:
    plugin: Path
    manifest: Path
    build_id: str
    plugin_sha256: str
    manifest_sha256: str
    plugin_api: int

    @classmethod
    def load(cls, plugin: Path) -> Phase1Runtime:
        plugin = plugin.absolute()
        _regular(plugin, 512 * 1024 * 1024)
        manifest = Path(str(plugin) + ".runtime.json")
        data = read_json(manifest)
        if data.get("schema_version") != 1 or data.get("runtime_kind") != "taintforge-phase1":
            raise Phase1RuntimeError("unsupported Phase 1 runtime manifest")
        build_id = data.get("build_id")
        if not isinstance(build_id, str) or not re.fullmatch(r"[0-9a-f]{64}", build_id):
            raise Phase1RuntimeError("invalid Phase 1 build identity")
        inputs = data.get("build_inputs")
        if not isinstance(inputs, dict) or hashlib.sha256(json.dumps(inputs, sort_keys=True, separators=(",", ":")).encode()).hexdigest() != build_id:
            raise Phase1RuntimeError("Phase 1 build identity does not match its inputs")
        claimed = data.get("plugin", {})
        actual = digest(plugin)
        if claimed.get("filename") != plugin.name or claimed.get("sha256") != actual or claimed.get("size") != plugin.stat().st_size:
            raise Phase1RuntimeError("Phase 1 plugin does not match its build manifest")
        required = data.get("requirements", {})
        if required.get("qemu_linkage") != "dynamic" or required.get("plugins") is not True:
            raise Phase1RuntimeError("incompatible Phase 1 QEMU requirements")
        api = required.get("plugin_api")
        if type(api) is not int or api != inputs.get("plugin_api"):
            raise Phase1RuntimeError("invalid plugin API requirement")
        return cls(plugin, manifest, build_id, actual, digest(manifest), api)

    def validate_qemu(self, qemu: Path) -> dict[str, Any]:
        try:
            target = inspect_elf_target(qemu)
        except (OSError, RuntimeError, ValueError) as exc:
            raise Phase1RuntimeError(f"invalid QEMU executable: {exc}") from exc
        if target.interpreter is None:
            raise Phase1RuntimeError("static QEMU cannot load TCG plugins; Phase 2 requires a dynamic-QEMU execution backend")
        return {"path": str(qemu), "sha256": digest(qemu), "linkage": "dynamic", "load_check": "pending"}


@dataclass(frozen=True)
class Phase1Run:
    runtime: Phase1Runtime
    session_id: str
    attempt_id: str
    analysis_instance_id: str
    directory: Path
    require_flags: bool = False
    flags_receipt: Path | None = None

    def __post_init__(self) -> None:
        for value in (self.session_id, self.attempt_id, self.analysis_instance_id):
            if not re.fullmatch(r"[A-Za-z0-9_.-]{1,120}", value):
                raise Phase1RuntimeError("invalid phase1 session/attempt/instance identity")
        if not self.directory.is_absolute() or self.directory.resolve() != self.directory:
            raise Phase1RuntimeError("Phase 1 output directory must be absolute and canonical")

    @property
    def paths(self) -> dict[str, Path]:
        return {"events": self.directory / "events.jsonl", "manifest": self.directory / "capture_manifest.json",
                "dump": self.directory / "unpacked.bin", "report": self.directory / "unpacked.json",
                "ir": self.directory / "ir_runtime.jsonl"}

    def plugin_argument(self, *, ir: bool = True, extra: tuple[str, ...] = ()) -> str:
        self.directory.mkdir(parents=True, exist_ok=True)
        for path in self.paths.values():
            if path.exists() or path.is_symlink():
                raise Phase1RuntimeError(f"refusing reuse of Phase 1 output: {path}")
        options = [str(self.runtime.plugin), f"tf-session-id={self.session_id}", f"tf-attempt-id={self.attempt_id}",
                   f"tf-instance-id={self.analysis_instance_id}", f"tf-require-flags={'on' if self.require_flags else 'off'}"]
        if self.flags_receipt is not None:
            receipt = self.flags_receipt.expanduser().resolve(strict=True)
            _regular(receipt, 4096)
            # The plugin checks the exact receipt and the executing QEMU's hash.
            options.append(f"x86-flags-receipt={receipt}")
        options.extend(f"tf-{'ir-report' if key == 'ir' else key}={path}" for key, path in self.paths.items())
        options.append(f"ir-check={'on' if ir else 'off'}")
        allowed = {"ir-probe", "ir-start", "ir-window", "ir-flat-memory", "ir-ssa", "tf-selection-delay", "tf-max-events", "tf-max-dump-bytes", "tf-max-candidates"}
        for option in extra:
            if option.split("=", 1)[0] not in allowed or "=" not in option:
                raise Phase1RuntimeError(f"not an allowed per-run analysis option: {option}")
        options.extend(extra)
        if any("," in value or "\n" in value for value in options):
            raise Phase1RuntimeError("QEMU plugin arguments cannot contain commas or newlines")
        return ",".join(options)

    def _identity(self, data: dict[str, Any]) -> None:
        for key in ("session_id", "attempt_id", "analysis_instance_id"):
            if data.get(key) != getattr(self, key):
                raise Phase1RuntimeError(f"Phase 1 {key} mismatch")

    def events(self, *, final: bool = True) -> list[dict[str, Any]]:
        path = self.paths["events"]
        _regular(path, 256 * 1024 * 1024)
        result: list[dict[str, Any]] = []
        with path.open("r", encoding="utf-8") as stream:
            for sequence, line in enumerate(stream, 1):
                if len(line) > 32768:
                    raise Phase1RuntimeError("oversized Phase 1 event")
                if not line.endswith("\n"):
                    if final:
                        raise Phase1RuntimeError("truncated Phase 1 event stream")
                    break
                item = _parse(line)
                self._identity(item)
                if item.get("schema_version") != 1 or type(item.get("event_seq")) is not int or item["event_seq"] != sequence or item.get("event_id") != f"{self.analysis_instance_id}:{sequence}":
                    raise Phase1RuntimeError("Phase 1 event ordering or identity mismatch")
                if result and result[-1].get("event_type") == "analysis_finished":
                    raise Phase1RuntimeError("Phase 1 event follows terminal event")
                result.append(item)
        if not result or result[0].get("event_type") != "analysis_started":
            raise Phase1RuntimeError("Phase 1 did not report runtime capabilities")
        if final and result[-1].get("event_type") != "analysis_finished":
            raise Phase1RuntimeError("Phase 1 event stream did not finish")
        return result

    def verify(self, *, require_protected_channel: bool = False,
               recorded_directory: Path | None = None) -> dict[str, Any]:
        # No opt-in flag can manufacture channel isolation from this transport.
        if require_protected_channel:
            raise Phase1RuntimeError("protected evidence channel is unsupported by the regular-file QEMU-user adapter")
        if digest(self.runtime.plugin) != self.runtime.plugin_sha256 or digest(self.runtime.manifest) != self.runtime.manifest_sha256:
            raise Phase1RuntimeError("Phase 1 runtime changed during execution")
        manifest = read_json(self.paths["manifest"])
        self._identity(manifest)
        if manifest.get("schema_version") != 1 or manifest.get("storage_status") != "ok":
            raise Phase1RuntimeError("Phase 1 capture manifest is not committed")
        artifacts = manifest.get("artifacts")
        if not isinstance(artifacts, dict) or set(artifacts) != {"dump", "report", "events", "ir"}:
            raise Phase1RuntimeError("invalid Phase 1 artifact inventory")
        for name, item in artifacts.items():
            if item is None:
                if name in {"report", "events"}:
                    raise Phase1RuntimeError(f"missing required Phase 1 artifact: {name}")
                continue
            path = self.paths[name]
            _regular(path, 1024 * 1024 * 1024)
            recorded = path if recorded_directory is None else recorded_directory / path.name
            if not recorded.is_absolute() or item.get("path") != str(recorded) or type(item.get("size")) is not int or item["size"] != path.stat().st_size or item.get("sha256") != digest(path):
                raise Phase1RuntimeError(f"Phase 1 artifact integrity mismatch: {name}")
        events = self.events()
        if manifest.get("event_count") != len(events):
            raise Phase1RuntimeError("Phase 1 event count mismatch")
        capabilities = events[0].get("data", {})
        if capabilities.get("build_id") != self.runtime.build_id or capabilities.get("plugin_api") != self.runtime.plugin_api:
            raise Phase1RuntimeError("loaded Phase 1 runtime does not match selected build")
        if self.require_flags and capabilities.get("flags_contract") != "taintforge_x86_flags_v1":
            raise Phase1RuntimeError("required flag observation contract was not observed")
        report = read_json(self.paths["report"])
        self._identity(report)
        if report.get("capture_status") != manifest.get("capture_status"):
            raise Phase1RuntimeError("capture statuses disagree")
        if artifacts["dump"] is not None:
            offset = 0
            with self.paths["dump"].open("rb") as stream:
                for region in report.get("regions", []):
                    size = region.get("size")
                    if type(size) is not int or not 0 < size <= 4096 or region.get("offset") != offset:
                        raise Phase1RuntimeError("invalid captured region extent")
                    data = stream.read(size)
                    if len(data) != size or hashlib.sha256(data).hexdigest() != region.get("sha256"):
                        raise Phase1RuntimeError("captured region bytes do not match report")
                    offset += size
                if stream.read(1) or offset != artifacts["dump"]["size"]:
                    raise Phase1RuntimeError("capture contains unreported bytes")
        observed = any(event.get("event_type") == "runtime_observation" and event.get("data", {}).get("kind") == "instruction_callback" for event in events)
        return {"schema_version": 1, "session_id": self.session_id, "attempt_id": self.attempt_id,
                "analysis_instance_id": self.analysis_instance_id, "build_id": self.runtime.build_id,
                "plugin_sha256": self.runtime.plugin_sha256, "runtime_manifest_sha256": self.runtime.manifest_sha256,
                "runtime_observed": observed, "artifact_integrity": "verified", "analysis_status": manifest.get("analysis_status"),
                "capture_status": manifest.get("capture_status"), "stream_status": events[-1].get("status"),
                "control_channel_protection": "unverified", "process_checkpoint": False,
                "oep_proven": False, "fuzzing_ready": False, "event_count": len(events)}
