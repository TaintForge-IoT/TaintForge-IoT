"""Integration contracts use a synthetic executor, never claim a QEMU run."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from scripts.run_unified_pipeline import parser, prepare, run_session
from taintforge_env.elf_runtime import canonical_hash
from taintforge_env.execution_backend import ExecutionBackendKind
from taintforge_env.iteration_controller import IterationController
from taintforge_env.prebuilt_runner import PrebuiltRootfsRunner, PrebuiltRunnerConfig, PrebuiltRunnerError
from taintforge_env.synthesis_loop import EnvironmentSynthesisLoop, SynthesisLoopConfig, SynthesisLoopError
from taintforge_env.unified_runtime import build_bundle, verify_bundle, write_json, UnifiedRuntimeError
from tests.elf_fixture import write_elf
from tests.test_prebuilt_runner import FakeExecutor


PROJECT = Path(__file__).resolve().parents[1]


def fake_toolchain(directory: Path):
    """Actual host ELF dependencies, synthetic plugin identity; no TCG execution."""
    directory.mkdir()
    qemu = directory / "qemu-i386"
    shutil.copyfile(shutil.which("true"), qemu)
    qemu.chmod(0o755)
    source = directory / "plugin.c"
    source.write_text("int synthetic_plugin_fixture;\n")
    plugin = directory / "fixture.so"
    subprocess.run(["gcc", "-shared", "-nostdlib", "-fPIC", str(source), "-o", str(plugin)], check=True, capture_output=True)
    inputs = {"plugin_api": 5, "test_fixture_only": True}
    write_json(Path(str(plugin) + ".runtime.json"), {
        "schema_version": 1, "runtime_kind": "taintforge-phase1", "build_id": canonical_hash(inputs),
        "build_inputs": inputs, "requirements": {"qemu_linkage": "dynamic", "plugins": True, "plugin_api": 5},
        "plugin": {"filename": plugin.name, "size": plugin.stat().st_size, "sha256": hashlib.sha256(plugin.read_bytes()).hexdigest()}})
    return qemu, plugin


def synthetic_capture(run_dir: Path, *, mode="complete"):
    binding = json.loads((run_dir / "config/phase1_binding.json").read_text())
    manifest = json.loads((run_dir / "config/analyzer_runtime/bundle.json").read_text())
    identity = {key: binding[key] for key in ("session_id", "attempt_id", "analysis_instance_id")}
    kinds = ["analysis_started", "runtime_observation", "oep_candidate_observed", "oep_candidate_selected",
             "oep_candidate_invalidated", "oep_candidate_observed", "oep_candidate_selected", "analysis_finished"]
    if mode == "incomplete":
        kinds = kinds[:4]
    events = [{"schema_version": 1, **identity, "event_type": kind, "event_seq": i,
               "event_id": f"{identity['analysis_instance_id']}:{i}", "data": {}, "status": "partial"}
              for i, kind in enumerate(kinds, 1)]
    events[0]["data"] = {"build_id": manifest["build_id"], "plugin_api": manifest["plugin_api"]}
    events[1]["data"] = {"kind": "instruction_callback"}
    output = Path(binding["output_directory"])
    (output / "events.jsonl").write_text("".join(json.dumps(event) + "\n" for event in events))
    if mode == "incomplete":
        with (output / "events.jsonl").open("a") as stream:
            stream.write('{"partial')
        return
    write_json(output / "unpacked.json", {"schema_version": 1, **identity, "capture_status": "no_candidate"})
    artifacts = {"dump": None, "ir": None}
    for name, filename in (("report", "unpacked.json"), ("events", "events.jsonl")):
        path = output / filename
        artifacts[name] = {"path": str(path), "size": path.stat().st_size, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
    write_json(output / "capture_manifest.json", {"schema_version": 1, **identity, "storage_status": "ok",
        "capture_status": "no_candidate", "analysis_status": "partial", "artifacts": artifacts, "event_count": len(events)})
    if mode == "corrupt":
        (output / "unpacked.json").write_text("{}")


class InstrumentedExecutor(FakeExecutor):
    def __init__(self, mode="complete", **kwargs):
        super().__init__(**kwargs)
        self.mode = mode

    def run(self, command, **kwargs):
        result = super().run(command, **kwargs)
        if command and str(command[-1]).endswith("run_prebuilt_sandbox.sh") and "unshare" in command and self.mode != "missing":
            synthetic_capture(Path(command[-1]).parent, mode=self.mode)
        return result


@unittest.skipUnless(shutil.which("gcc") and shutil.which("true"), "host ELF fixture compiler required")
class UnifiedPipelineTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name).resolve()
        self.qemu, self.plugin = fake_toolchain(self.base / "tools")
        self.template = self.base / "template"
        self.bundle_path = self.template / "config/analyzer_runtime"
        self.bundle = build_bundle(self.bundle_path, qemu=self.qemu, plugin=self.plugin)
        self.binary = write_elf(self.base / "sample", arch="i386")
        self.seed = self.template / "rootfs"
        (self.seed / "proc").mkdir(parents=True)
        (self.seed / "bin").mkdir()
        shutil.copyfile(self.binary, self.seed / "bin/sample.elf")
        write_json(self.template / "config/runtime.json", {"arch": "i386", "rootfs": str(self.seed),
            "host_binary": str(self.binary), "guest_binary": "/bin/sample.elf", "qemu_required": False,
            "phase1": {"bundle_path": str(self.bundle_path), "bundle_sha256": self.bundle["bundle_sha256"]}})
        self.loop_config = SynthesisLoopConfig(session_dir=self.base / "session", template_run_dir=self.template,
            project_root=PROJECT, snapshot_store=self.base / "snapshots", seed_rootfs=self.seed, initialize_only=True)
        EnvironmentSynthesisLoop(self.loop_config).run()
        IterationController(self.base / "session").prepare_next()
        self.config = PrebuiltRunnerConfig(session_dir=self.base / "session", iteration_index=0,
            template_run_dir=self.template, project_root=PROJECT)

    def execute(self, executor):
        runner = PrebuiltRootfsRunner(self.config, executor=executor)
        with patch.object(runner, "_check_host_dependencies"):
            result = runner.run_and_complete()
        return result

    def test_one_guest_execution_and_candidate_history_are_persisted(self):
        executor = InstrumentedExecutor()
        result = self.execute(executor)
        self.assertEqual(result.execution_backend, "qemu_plugin")
        self.assertEqual(sum("unshare" in command for command in executor.commands), 1)
        raw = json.loads(result.attempt_result_path.read_text())
        self.assertEqual(raw["final_stage"], "oep_validation")
        self.assertEqual(len(raw["stage_transitions"]), 5)
        summary = json.loads((result.run_dir / "config/phase1_result.json").read_text())
        self.assertFalse(summary["oep_proven"])
        self.assertFalse(summary["fuzzing_ready"])
        self.assertEqual(summary["artifact_integrity"], "verified")
        self.assertTrue(EnvironmentSynthesisLoop.verify_session(self.base / "session")["binding_verified"])
        script = (result.run_dir / "run_prebuilt_sandbox.sh").read_text()
        self.assertEqual(script.count("-plugin "), 1)
        self.assertLess(script.index("trap cleanup"), script.index("mount --bind"))
        self.assertIn("--library-path /__taintforge/lib", script)
        binding = json.loads((result.run_dir / "config/phase1_binding.json").read_text())
        self.assertNotIn(".prebuilt-run.", binding["plugin_argument"])
        self.assertIn(str(result.run_dir / "logs/phase1"), script)
        self.assertFalse((self.seed / "__taintforge").exists())

    def test_bundle_change_refuses_execution_and_session_verification(self):
        library = next((self.bundle_path / "lib").iterdir())
        library.chmod(0o644)
        library.write_bytes(b"changed")
        with self.assertRaisesRegex(PrebuiltRunnerError, "changed"):
            PrebuiltRootfsRunner(self.config).validate()
        with self.assertRaisesRegex(SynthesisLoopError, "analyzer runtime changed"):
            EnvironmentSynthesisLoop.verify_session(self.base / "session")

    def test_unknown_bundle_file_is_not_injected(self):
        (self.bundle_path / "lib/unbound.so").write_bytes(b"extra")
        with self.assertRaisesRegex(UnifiedRuntimeError, "unbound"):
            verify_bundle(self.bundle_path, self.bundle["bundle_sha256"])

    def test_timeout_preserves_partial_events_without_claiming_integrity(self):
        result = self.execute(InstrumentedExecutor(mode="incomplete", guest_exit_code=124))
        self.assertTrue(result.timed_out)
        raw = json.loads(result.attempt_result_path.read_text())
        self.assertEqual(raw["outcome"], "timed_out")
        self.assertEqual(raw["final_stage"], "oep_validation")
        summary = json.loads((result.run_dir / "config/phase1_result.json").read_text())
        self.assertEqual(summary["artifact_integrity"], "incomplete")

    def test_corrupt_committed_manifest_is_not_excused_by_timeout(self):
        with self.assertRaisesRegex(PrebuiltRunnerError, "integrity mismatch"):
            self.execute(InstrumentedExecutor(mode="corrupt", guest_exit_code=124))

    def test_timeout_cannot_excuse_wrong_plugin_api(self):
        original = synthetic_capture
        def changed_capture(run_dir, **kwargs):
            original(run_dir, **kwargs)
            path = run_dir / "logs/phase1/events.jsonl"
            lines = path.read_text().splitlines(keepends=True)
            first = json.loads(lines[0])
            first["data"]["plugin_api"] = 999
            lines[0] = json.dumps(first) + "\n"
            path.write_text("".join(lines))
        with patch(__name__ + ".synthetic_capture", side_effect=changed_capture):
            with self.assertRaisesRegex(PrebuiltRunnerError, "analysis_started"):
                self.execute(InstrumentedExecutor(mode="incomplete", guest_exit_code=124))

    def test_missing_plugin_evidence_is_not_success(self):
        with self.assertRaisesRegex(PrebuiltRunnerError, "Phase 1 evidence"):
            self.execute(InstrumentedExecutor(mode="missing"))
        claim = json.loads((self.base / "session/iterations/0000/execution_attempt.json").read_text())
        self.assertEqual(claim["stage"], "failed")
        self.assertFalse(claim["retry_safe"])

    def test_forces_plugin_backend_even_on_compatible_host(self):
        context = PrebuiltRootfsRunner(self.config).validate()
        self.assertEqual(context.execution_plan.backend, ExecutionBackendKind.QEMU_PLUGIN)

    def test_prepared_guest_must_match_original_elf(self):
        from taintforge_env.execution_backend import ExecutionBackendResolver, ExecutionBackendError
        guest = self.seed / "bin/sample.elf"
        guest.write_bytes(guest.read_bytes() + b"modified")
        with self.assertRaisesRegex(ExecutionBackendError, "differs from the bound original"):
            ExecutionBackendResolver().resolve(runtime=json.loads((self.template / "config/runtime.json").read_text()),
                host_binary=self.binary, rootfs=self.seed, guest_binary="/bin/sample.elf")

    def test_phase1_output_path_collision_is_rejected(self):
        runner = PrebuiltRootfsRunner(self.config)
        context = runner.validate()
        first = context.run_dir.parts[1]
        (context.execution_rootfs / first).symlink_to("/tmp")
        with self.assertRaisesRegex(UnifiedRuntimeError, "collides"):
            runner._prepare_run_directory(context)

    def test_guest_ld_library_path_is_set_by_qemu_not_host_loader(self):
        runtime_path = self.template / "config/runtime.json"
        runtime = json.loads(runtime_path.read_text())
        runtime["guest_library_path"] = ["/lib32", "/opt/guest/lib"]
        write_json(runtime_path, runtime)
        runner = PrebuiltRootfsRunner(self.config)
        context = runner.validate()
        runner._prepare_run_directory(context)
        script = (context.run_dir / "run_prebuilt_sandbox.sh").read_text()
        self.assertIn("-E LD_LIBRARY_PATH=/lib32:/opt/guest/lib", script)
        self.assertEqual(script.count("LD_LIBRARY_PATH="), 1)

    def test_cli_prepare_and_resume_use_bound_session(self):
        obj = self.base / "fixture.o"
        binary = self.base / "fixture"
        subprocess.run(["as", "--32", str(PROJECT / "tests/phase1_two_layers.S"), "-o", str(obj)], check=True, capture_output=True)
        subprocess.run(["ld", "-m", "elf_i386", str(obj), "-o", str(binary)], check=True, capture_output=True)
        out = self.base / "cli"
        args = parser().parse_args(["run", "--binary", str(binary), "--out", str(out), "--plugin", str(self.plugin),
                                   "--qemu", str(self.qemu), "--prepare-only"])
        launch = prepare(args)
        report, code = run_session(out, launch, max_steps=1, initialize_only=True)
        self.assertEqual(code, 0)
        self.assertEqual(report["outcome"], "initialized")
        self.assertEqual(report["executions_this_invocation"], 0)
        self.assertTrue(EnvironmentSynthesisLoop.verify_session(out / "session")["binding_verified"])
        executor = InstrumentedExecutor()
        def factory(config):
            runner = PrebuiltRootfsRunner(config, executor=executor)
            runner._check_host_dependencies = lambda context: None
            return runner
        kwargs = {key: value for key, value in launch.items() if key != "schema_version"}
        resumed = EnvironmentSynthesisLoop(SynthesisLoopConfig(**kwargs), runner_factory=factory).run()
        self.assertEqual(resumed.executions_this_invocation, 1)
        report, code = run_session(out, launch, max_steps=1)
        self.assertEqual(code, 0)
        self.assertEqual(report["executions_this_invocation"], 0)
        self.assertEqual(report["phase1"]["artifact_integrity"], "verified")

    def test_dynamic_i386_acceptance_fixture_links_and_prepares(self):
        from scripts.run_unified_local_e2e import build_fixtures
        source = self.base / "loader_source"
        (source / "lib").mkdir(parents=True)
        # This fixture supplies only ELF metadata, never acts as a real loader.
        write_elf(source / "lib/ld-linux.so.2", arch="i386")
        build = self.base / "fixtures"
        build.mkdir()
        name, binary, sysroot = build_fixtures(build, source)[1]
        args = parser().parse_args(["run", "--binary", str(binary), "--out", str(self.base / "dynamic_cli"),
                                   "--sysroot", str(sysroot), "--plugin", str(self.plugin), "--qemu", str(self.qemu), "--prepare-only"])
        launch = prepare(args)
        report, code = run_session(args.out, launch, max_steps=1, initialize_only=True)
        self.assertEqual(code, 0)
        self.assertEqual(report["executions_this_invocation"], 0)
        guest_runtime = json.loads((args.out / "template/config/guest_runtime.json").read_text())
        self.assertEqual(guest_runtime["target"]["interpreter"], "/lib/ld-linux.so.2")
        self.assertTrue(any(item["guest_path"] == "/lib/libtf_leaf.so" for item in guest_runtime["files"]))


if __name__ == "__main__":
    unittest.main()
