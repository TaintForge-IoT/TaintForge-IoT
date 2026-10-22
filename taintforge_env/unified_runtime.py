"""Phase 2 adapter for the separately owned Phase 1 runtime v1 contract.

The bundle separates host-QEMU libraries from guest libraries. An optional
controlled capsule probe adds a handoff experiment, not a protected evidence
channel, analyzer quiescence or a checkpoint.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import shlex
import shutil

from .attempt import ExecutionStage, StageTransition
from .elf_runtime import DependencyResolver, ElfImage, canonical_hash, copy_file, guest_path
from .elf_target import canonical_arch


class UnifiedRuntimeError(RuntimeError):
    pass


GUEST_TOOL_DIR = "/__taintforge"


def phase1_api():
    # Keep all existing Phase 2 commands usable without the optional Phase 1 package.
    try:
        from .phase1_runtime import Phase1Run, Phase1Runtime, Phase1RuntimeError
    except ImportError as exc:
        raise UnifiedRuntimeError("install the developer's Phase 1 runtime v1 package first") from exc
    return Phase1Run, Phase1Runtime, Phase1RuntimeError


def write_json(path: Path, value: dict):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def check_runtime_inputs(project_root: Path, *, qemu: str | Path | None = None,
                         plugin: str | Path | None = None) -> dict:
    """Validate selected files without executing QEMU or creating output files.

    Explicit selections and TAINTFORGE_QEMU_PLUGIN never silently fall back to
    another build. Compatible-looking alternatives are only reported.
    """
    project_root = project_root.expanduser().resolve()
    qemu_name = os.path.expanduser(str(qemu)) if qemu is not None else "qemu-i386"
    qemu_path = Path(shutil.which(qemu_name) or qemu_name).resolve()
    plugin_path = Path(plugin or os.environ.get("TAINTFORGE_QEMU_PLUGIN") or
                       project_root / "build/libtaintforge_ir.so").expanduser().resolve()
    sidecar = Path(str(plugin_path) + ".runtime.json")
    missing = []
    for label, path in (("QEMU executable", qemu_path), ("Phase 1 plugin", plugin_path),
                        ("Phase 1 runtime manifest", sidecar)):
        if not path.is_file():
            missing.append(f"{label}: missing regular file: {path}")
        elif not os.access(path, os.R_OK):
            missing.append(f"{label}: file is not readable: {path}")
    if qemu_path.is_file() and not os.access(qemu_path, os.X_OK):
        missing.append(f"QEMU executable: execute permission is missing: {qemu_path}")
    if missing:
        details = ["Unified runtime prerequisites are incomplete:", *missing]
        # Report the two documented build locations; do not search captures or
        # substitute another analysis build for the selected plugin.
        for candidate in (project_root / "build/libtaintforge_ir.so",
                          project_root / "unpacker/test/libtaintforge_ir.so"):
            candidate = candidate.resolve()
            if candidate == plugin_path or not candidate.is_file():
                continue
            candidate_manifest = Path(str(candidate) + ".runtime.json")
            if not candidate_manifest.is_file():
                details.append(f"Other plugin without runtime manifest: {candidate}")
                continue
            try:
                _, Phase1Runtime, _ = phase1_api()
                Phase1Runtime.load(candidate)
            except (OSError, ValueError, RuntimeError) as exc:
                details.append(f"Other plugin is not a verified Phase 1 build: {candidate}: {exc}")
            else:
                details.append(f"Found a plugin with verified build metadata; select it explicitly with --plugin {shlex.quote(str(candidate))}")
        details += [f"Selected QEMU: {qemu_path}", f"Selected plugin: {plugin_path}",
                    "tests/run_phase1_tests.sh does not build the TCG plugin.",
                    "Build it with the Phase 1 recipe and the header of the QEMU you will use; see docs/PHASE1_RUNTIME_V1.md.",
                    "The .runtime.json must come from that build. Plugin load compatibility still requires actual QEMU execution."]
        raise UnifiedRuntimeError("\n".join(details))
    _, Phase1Runtime, _ = phase1_api()
    runtime = Phase1Runtime.load(plugin_path)
    qemu_identity = runtime.validate_qemu(qemu_path)
    if qemu_path.name != "qemu-i386":
        raise UnifiedRuntimeError(f"select a dynamically linked executable named qemu-i386: {qemu_path}")
    return {"status": "input_files_verified", "qemu": qemu_identity,
            "plugin": str(plugin_path), "runtime_manifest": str(sidecar),
            "plugin_sha256": runtime.plugin_sha256, "build_id": runtime.build_id,
            "plugin_api": runtime.plugin_api, "guest_executed": False,
            "qemu_plugin_load": "not_tested"}


def build_bundle(destination: Path, *, qemu: Path, plugin: Path, capsule_probe: dict | None = None) -> dict:
    """Copy a glibc host-QEMU/plugin DT_NEEDED closure without running the guest."""
    _, Phase1Runtime, _ = phase1_api()
    qemu, plugin = qemu.resolve(strict=True), plugin.resolve(strict=True)
    runtime = Phase1Runtime.load(plugin)
    runtime.validate_qemu(qemu)
    host_arch = canonical_arch(platform.machine())
    if host_arch not in {"x86_64", "i386"}:
        raise UnifiedRuntimeError("the initial unified runner supports x86 Linux glibc hosts")
    if qemu.name != "qemu-i386":
        raise UnifiedRuntimeError("select a dynamically linked executable named qemu-i386")
    image = ElfImage(qemu)
    interpreter = image.target.interpreter
    if not interpreter or "ld-linux" not in PurePosixPath(interpreter).name:
        raise UnifiedRuntimeError("the initial host runtime bundle requires the glibc ELF loader")
    resolver = DependencyResolver(Path("/"), host_arch)
    roots = [(qemu, str(qemu)), (plugin, str(plugin))]
    capsule_plugin = Path(capsule_probe["plugin"]).resolve(strict=True) if capsule_probe else None
    lifecycle_plugin = (Path(capsule_probe["lifecycle_plugin"]).resolve(strict=True)
                        if capsule_probe and "lifecycle_plugin" in capsule_probe else None)
    if capsule_plugin is not None:
        roots.append((capsule_plugin, str(capsule_plugin)))
    if lifecycle_plugin is not None:
        roots.append((lifecycle_plugin, str(lifecycle_plugin)))
    records = resolver.closure(roots)
    if destination.exists() or destination.is_symlink():
        raise UnifiedRuntimeError(f"runtime bundle already exists: {destination}")
    destination.mkdir(parents=True)
    inventory = {}
    for record in records:
        source = Path(record["source"])
        if ElfImage(source).dynamic()["rpath"]:
            raise UnifiedRuntimeError("analyzer DT_RPATH is unsupported; rebuild with DT_RUNPATH so bundled libraries take precedence")
        if source == qemu:
            relative = "bin/qemu-i386"
        elif source == plugin:
            relative = f"plugin/{plugin.name}"
        elif source == capsule_plugin:
            relative = "capsule/libcapsule_probe.so"
        elif source == lifecycle_plugin:
            relative = "capsule/libcapsule_lifecycle.so"
        else:
            relative = f"lib/{PurePosixPath(record['guest_path']).name}"
        digest = copy_file(source, destination / relative, expected=record["sha256"], executable=True)
        inventory[relative] = {"path": relative, "sha256": digest, "size": source.stat().st_size}
    loader = resolver.root / interpreter.lstrip("/")
    digest = copy_file(loader, destination / "bin/loader", executable=True)
    inventory["bin/loader"] = {"path": "bin/loader", "sha256": digest, "size": loader.stat().st_size}
    relative = f"plugin/{runtime.manifest.name}"
    digest = copy_file(runtime.manifest, destination / relative, expected=runtime.manifest_sha256)
    inventory[relative] = {"path": relative, "sha256": digest, "size": runtime.manifest.stat().st_size}
    manifest = {"schema_version": 1, "kind": "phase1-qemu-bundle", "host_arch": host_arch,
                "target_arch": "i386", "qemu": "bin/qemu-i386", "loader": "bin/loader",
                "plugin": f"plugin/{plugin.name}", "build_id": runtime.build_id,
                "plugin_api": runtime.plugin_api, "files": sorted(inventory.values(), key=lambda item: item["path"])}
    if capsule_probe is not None:
        from .execution_capsule import bundle_profile
        profile = bundle_profile(capsule_probe)
        fixture = Path(capsule_probe["guest"])
        digest = copy_file(fixture, destination / profile["fixture"], expected=profile["fixture_sha256"], executable=True)
        inventory[profile["fixture"]] = {"path": profile["fixture"], "sha256": digest, "size": fixture.stat().st_size}
        manifest["capsule"] = profile
        manifest["files"] = sorted(inventory.values(), key=lambda item: item["path"])
    manifest["bundle_sha256"] = canonical_hash(manifest)
    write_json(destination / "bundle.json", manifest)
    return verify_bundle(destination, manifest["bundle_sha256"])


def verify_bundle(directory: Path, expected: str | None = None) -> dict:
    if directory.is_symlink() or not directory.is_dir():
        raise UnifiedRuntimeError("analyzer runtime bundle must be a regular directory")
    manifest_path = directory / "bundle.json"
    if manifest_path.is_symlink() or not manifest_path.is_file() or manifest_path.stat().st_size > 1024 * 1024:
        raise UnifiedRuntimeError("invalid analyzer bundle manifest")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(manifest, dict):
        raise UnifiedRuntimeError("invalid analyzer bundle manifest object")
    unsigned = {key: value for key, value in manifest.items() if key != "bundle_sha256"}
    digest = canonical_hash(unsigned)
    if manifest.get("schema_version") != 1 or manifest.get("kind") != "phase1-qemu-bundle" or manifest.get("bundle_sha256") != digest or (expected is not None and expected != digest):
        raise UnifiedRuntimeError("analyzer runtime bundle identity mismatch")
    files = manifest.get("files")
    if not isinstance(files, list) or not 1 <= len(files) <= 260:
        raise UnifiedRuntimeError("invalid analyzer file inventory")
    names = set()
    for item in files:
        if not isinstance(item, dict) or not isinstance(item.get("path"), str):
            raise UnifiedRuntimeError("invalid analyzer file entry")
        name = item["path"]
        relative = PurePosixPath(name)
        if relative.is_absolute() or ".." in relative.parts or str(relative) != name or name in names:
            raise UnifiedRuntimeError("invalid or duplicate analyzer file path")
        names.add(name)
        path = directory / name
        if any(part.is_symlink() for part in [path, *list(path.parents)[:len(relative.parts)]]):
            raise UnifiedRuntimeError("analyzer bundle contains a symlink")
        if not path.is_file() or path.stat().st_size != item.get("size") or hashlib.sha256(path.read_bytes()).hexdigest() != item.get("sha256"):
            raise UnifiedRuntimeError(f"analyzer runtime file changed: {name}")
    actual = set()
    for path in directory.rglob("*"):
        if path.is_symlink() or (not path.is_file() and not path.is_dir()):
            raise UnifiedRuntimeError("unsupported analyzer bundle entry")
        if path.is_file():
            actual.add(path.relative_to(directory).as_posix())
    if actual != names | {"bundle.json"}:
        raise UnifiedRuntimeError("analyzer bundle contains unbound files")
    if manifest.get("qemu") != "bin/qemu-i386" or manifest.get("loader") != "bin/loader" or manifest.get("target_arch") != "i386":
        raise UnifiedRuntimeError("unsupported analyzer runtime profile")
    for role in ("qemu", "loader", "plugin"):
        if manifest.get(role) not in names:
            raise UnifiedRuntimeError(f"analyzer bundle lacks {role}")
    _, Phase1Runtime, _ = phase1_api()
    runtime = Phase1Runtime.load(directory / manifest["plugin"])
    if runtime.build_id != manifest.get("build_id") or runtime.plugin_api != manifest.get("plugin_api"):
        raise UnifiedRuntimeError("analyzer build contract mismatch")
    if "capsule" in manifest:
        from .execution_capsule import verify_profile
        verify_profile(manifest)
    return manifest


def prepare_attempt(context, temporary: Path) -> dict:
    """Stage artifacts without creating the final run directory before rename."""
    plan = context.execution_plan
    source = Path(plan.analyzer_bundle_path)
    manifest = verify_bundle(source, plan.analyzer_bundle_sha256)
    destination = temporary / "config" / "analyzer_runtime"
    for item in manifest["files"]:
        copy_file(source / item["path"], destination / item["path"], expected=item["sha256"], executable=True)
    copy_file(source / "bundle.json", destination / "bundle.json")
    verify_bundle(destination, plan.analyzer_bundle_sha256)
    Phase1Run, Phase1Runtime, _ = phase1_api()
    runtime = Phase1Runtime.load(destination / manifest["plugin"])
    options = json.loads(context.template_runtime_path.read_text())["phase1"].get("options", [])
    if not isinstance(options, list) or not all(isinstance(option, str) for option in options):
        raise UnifiedRuntimeError("phase1 options must be a list of strings")
    analysis = Phase1Run(runtime, context.session.session_id, context.attempt_contract.attempt_id,
                         "phase1-" + context.attempt_contract.attempt_id, temporary / "logs" / "phase1")
    argument = analysis.plugin_argument(extra=tuple(options))
    parts = argument.split(",")
    parts[0] = GUEST_TOOL_DIR + "/" + manifest["plugin"]
    # Only path-valued options produced by the Phase 1 API are relocated.
    for index, value in enumerate(parts):
        key, sep, path = value.partition("=")
        if key in {"tf-events", "tf-manifest", "tf-dump", "tf-report", "tf-ir-report"}:
            parts[index] = key + sep + str(context.run_dir / Path(path).relative_to(temporary))
    binding = {"schema_version": 1, "session_id": analysis.session_id, "attempt_id": analysis.attempt_id,
               "analysis_instance_id": analysis.analysis_instance_id,
               "attempt_contract_sha256": context.attempt_contract.contract_sha256,
               "bundle_sha256": manifest["bundle_sha256"], "plugin": manifest["plugin"],
               "plugin_argument": ",".join(parts), "output_directory": str(context.run_dir / "logs" / "phase1"),
               "control_channel_protection": "unverified", "process_checkpoint": False,
               "execution_model": "original_elf_one_qemu_process_per_attempt"}
    write_json(temporary / "config" / "phase1_binding.json", binding)
    if "capsule" in manifest:
        from .execution_capsule import prepare_binding
        prepare_binding(context, temporary, manifest, binding)
    elif "capsule" in json.loads(context.template_runtime_path.read_text()):
        raise UnifiedRuntimeError("capsule settings require a bound capsule runtime")
    return binding


def project_events(events: list[dict], initial: ExecutionStage) -> tuple[StageTransition, ...]:
    """Record candidate history, never promote a heuristic selection to proven OEP."""
    stage = initial
    transitions = []
    now = datetime.now(timezone.utc).isoformat()
    for event in events:
        kind = event.get("event_type")
        target, reason = None, None
        if kind == "oep_candidate_observed" and stage in {ExecutionStage.PRE_OEP_DISCOVERY, ExecutionStage.OEP_VALIDATION}:
            target, reason = ExecutionStage.OEP_CANDIDATE, "Phase 1 observed a heuristic OEP candidate"
        elif kind == "oep_candidate_selected" and stage == ExecutionStage.OEP_CANDIDATE:
            target, reason = ExecutionStage.OEP_VALIDATION, "Retrospective candidate selection; OEP remains unproven"
        elif kind in {"oep_candidate_invalidated", "analysis_invalidated", "profile_lost"} and stage in {ExecutionStage.OEP_CANDIDATE, ExecutionStage.OEP_VALIDATION}:
            target, reason = ExecutionStage.PRE_OEP_DISCOVERY, "Phase 1 invalidated the candidate or analysis"
        if target is not None:
            transitions.append(StageTransition(len(transitions), stage, target, reason,
                event["event_id"], now))
            stage = target
        if kind == "profile_lost":
            break
    return tuple(transitions)


def finish_attempt(context, guest_exit_code: int) -> tuple[StageTransition, ...]:
    """Validate existing Phase 1 artifacts; save adapter errors without editing them."""
    try:
        return _finish_attempt(context, guest_exit_code)
    except Exception as exc:
        from .attempt_finalization import error_text
        write_json(context.run_dir / "config/phase1_result.json", {
            "schema_version": 1, "attempt_id": context.attempt_contract.attempt_id,
            "attempt_contract_sha256": context.attempt_contract.contract_sha256,
            "guest_exit_code": guest_exit_code, "verification_status": "failed",
            "artifact_integrity": "unverified", "analysis_status": "unknown",
            "capture_status": "unknown", "reason": error_text(exc),
            "oep_proven": False, "fuzzing_ready": False, "transitions": [],
            "guest_restarted_at_oep": False, "control_channel_protection": "unverified",
        })
        raise


def _finish_attempt(context, guest_exit_code: int) -> tuple[StageTransition, ...]:
    binding = json.loads((context.run_dir / "config" / "phase1_binding.json").read_text())
    directory = context.run_dir / "config" / "analyzer_runtime"
    verify_bundle(directory, context.execution_plan.analyzer_bundle_sha256)
    Phase1Run, Phase1Runtime, Phase1RuntimeError = phase1_api()
    analysis = Phase1Run(Phase1Runtime.load(directory / binding["plugin"]), binding["session_id"],
                         binding["attempt_id"], binding["analysis_instance_id"], Path(binding["output_directory"]))
    # Failure to load the plugin is infrastructure failure, not a successful guest exit.
    try:
        events = analysis.events(final=False)
        if not events or events[0].get("data", {}).get("build_id") != analysis.runtime.build_id or events[0].get("data", {}).get("plugin_api") != analysis.runtime.plugin_api:
            raise UnifiedRuntimeError("the selected Phase 1 plugin did not report analysis_started")
        summary = analysis.verify()
    except Phase1RuntimeError as exc:
        if guest_exit_code != 124 or analysis.paths["manifest"].exists() or analysis.paths["manifest"].is_symlink() or not analysis.paths["events"].is_file():
            stderr = context.run_dir / "logs/runtime_stderr.log"
            tail = ""
            if stderr.is_file():
                with stderr.open("rb") as stream:
                    stream.seek(0, 2)
                    stream.seek(max(0, stream.tell() - 2500))
                    tail = stream.read().decode("utf-8", errors="replace")
            raise UnifiedRuntimeError(f"Phase 1 evidence validation failed: {exc}\nAnalyzer stderr: {stderr}\n{tail}") from exc
        events = analysis.events(final=False)
        if not events or events[0].get("data", {}).get("build_id") != analysis.runtime.build_id or events[0].get("data", {}).get("plugin_api") != analysis.runtime.plugin_api:
            raise UnifiedRuntimeError("timeout occurred before Phase 1 startup was observed") from exc
        summary = {"schema_version": 1, "artifact_integrity": "incomplete", "reason": str(exc),
                   "analysis_status": "interrupted", "capture_status": "incomplete", "oep_proven": False,
                   "fuzzing_ready": False,
                   "runtime_observed": any(event.get("event_type") == "runtime_observation" and event.get("data", {}).get("kind") == "instruction_callback" for event in events),
                   "control_channel_protection": "unverified"}
    transitions = project_events(events, context.attempt_contract.initial_stage)
    summary.update({"verification_status": summary["artifact_integrity"],
                    "attempt_id": binding["attempt_id"], "attempt_contract_sha256": binding["attempt_contract_sha256"],
                    "bundle_sha256": binding["bundle_sha256"], "guest_exit_code": guest_exit_code,
                    "execution_model": binding["execution_model"], "guest_restarted_at_oep": False,
                    "timestamp_semantics": "transition UTC is controller ingestion time; source sequence and monotonic time remain in events",
                    "transitions": [item.to_dict() for item in transitions]})
    write_json(context.run_dir / "config" / "phase1_result.json", summary)
    return transitions


def sandbox_fragments(context, temporary: Path) -> tuple[str, str, str]:
    """Bind outputs at their canonical host path to preserve Phase 1 artifact IDs."""
    binding = json.loads((temporary / "config" / "phase1_binding.json").read_text())
    root = context.execution_rootfs
    output = Path(binding["output_directory"])
    # Track only directories created by this wrapper; reject symlink traversal.
    created = []
    current = root
    for part in output.parts[1:]:
        current = current / part
        if current.is_symlink() or (current.exists() and not current.is_dir()):
            raise UnifiedRuntimeError(f"Phase 1 output mount collides with guest path: {current}")
        if not current.exists():
            created.append(current)
    if current.exists():
        raise UnifiedRuntimeError("Phase 1 output mount must not hide an existing guest directory")
    quote = shlex.quote
    runtime = json.loads(context.template_runtime_path.read_text())
    library_paths = runtime.get("guest_library_path", [])
    if not isinstance(library_paths, list) or any(not isinstance(path, str) or ":" in path or "," in path for path in library_paths):
        raise UnifiedRuntimeError("guest_library_path must contain absolute guest directories")
    for path in library_paths:
        guest_path(path)
    guest_env = "-E " + quote("LD_LIBRARY_PATH=" + ":".join(library_paths)) if library_paths else ""
    tool_mount = root / GUEST_TOOL_DIR.lstrip("/")
    setup = f"""
QEMU_GUEST={quote(GUEST_TOOL_DIR + '/bin/qemu-i386')}
QEMU_TRACE={quote(str(context.run_dir / 'logs/qemu_strace.log'))}
mkdir -m 0700 {quote(str(tool_mount))}
mount --bind {quote(str(context.run_dir / 'config/analyzer_runtime'))} {quote(str(tool_mount))}
mount -o remount,bind,ro {quote(str(tool_mount))}
"""
    for path in created:
        setup += f"mkdir -m 0755 {quote(str(path))}\n"
    setup += f"mount --bind {quote(str(output))} {quote(str(current))}\n"
    cleanup = f"umount -l {quote(str(current))} >/dev/null 2>&1 || true\n"
    for path in reversed(created):
        cleanup += f"rmdir {quote(str(path))} >/dev/null 2>&1 || true\n"
    cleanup += f"umount -l {quote(str(tool_mount))} >/dev/null 2>&1 || true\nrmdir {quote(str(tool_mount))} >/dev/null 2>&1 || true"
    execution = f"""timeout --signal=TERM --kill-after=2s "$TIMEOUT_SECONDS" \\
    env -i PATH=/usr/bin:/bin HOME=/ LANG=C LC_ALL=C \\
    chroot "$ROOTFS" {GUEST_TOOL_DIR}/bin/loader --inhibit-cache \\
    --library-path {GUEST_TOOL_DIR}/lib "$QEMU_GUEST" -L / -strace \\
    -plugin {quote(binding['plugin_argument'])} {guest_env} "$GUEST_BINARY" \\
    2> >(tee "$QEMU_TRACE" >&2)"""
    if (temporary / "config/capsule_binding.json").is_file():
        from .execution_capsule import sandbox_fragments as capsule_fragments
        extra_setup, extra_cleanup, execution = capsule_fragments(context)
        setup += extra_setup
        cleanup = extra_cleanup + "\n" + cleanup
    return setup, cleanup, execution
