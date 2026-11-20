from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from scripts.run_unified_pipeline import parser, prepare
from taintforge_env.elf_runtime import canonical_hash
from taintforge_env.execution_backend import TraceBackend
from taintforge_env.network_observer import NetworkObserverError, plugin_argument, validate_observer
from taintforge_env.prebuilt_runner import PrebuiltRootfsRunner, PrebuiltRunnerError
from taintforge_env.unified_runtime import build_bundle, prepare_attempt, sandbox_fragments, verify_bundle, write_json
from tests.elf_fixture import write_elf
from tests.test_prebuilt_runner import FakeExecutor
from tests.test_unified_pipeline import fake_toolchain


PROJECT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(shutil.which("gcc") and shutil.which("true"), "host ELF fixture toolchain required")
class NetworkObserverBindingTests(unittest.TestCase):
    """Synthetic host ELF contracts; these tests do not claim a QEMU run."""
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.qemu, self.phase1 = fake_toolchain(self.root / "tools")
        self.observer = self.root / "tools/libnetwork_endpoint.so"
        shutil.copyfile(self.phase1, self.observer)
        inputs = {"plugin_api": 6, "test_fixture_only": True}
        write_json(Path(str(self.observer) + ".observer.json"), {
            "schema_version": 1, "kind": "taintforge-network-endpoints", "target_arch": "i386",
            "profile": "single-process-single-thread", "plugin_api": 6,
            "build_inputs": inputs, "build_id": canonical_hash(inputs),
            "plugin": {"filename": self.observer.name, "size": self.observer.stat().st_size,
                       "sha256": hashlib.sha256(self.observer.read_bytes()).hexdigest()},
        })

    def bundle(self):
        destination = self.root / "bundle"
        manifest = build_bundle(destination, qemu=self.qemu, plugin=self.phase1, network_observer=self.observer)
        return destination, manifest

    def context(self):
        bundle, manifest = self.bundle()
        template = self.root / "runtime.json"
        write_json(template, {"phase1": {"options": []}})
        rootfs = self.root / "rootfs"
        rootfs.mkdir()
        temporary = self.root / "temporary"
        (temporary / "logs").mkdir(parents=True)
        context = SimpleNamespace(
            execution_plan=SimpleNamespace(analyzer_bundle_path=str(bundle), analyzer_bundle_sha256=manifest["bundle_sha256"],
                trace_backend=TraceBackend.QEMU_STRACE, target=SimpleNamespace(arch="i386")),
            template_runtime_path=template, run_dir=self.root / "published-run", execution_rootfs=rootfs,
            session=SimpleNamespace(session_id="session"),
            attempt_contract=SimpleNamespace(attempt_id="attempt", contract_sha256="a" * 64),
        )
        binding = prepare_attempt(context, temporary)
        return context, temporary, binding

    def test_observer_and_manifest_are_in_the_bound_inventory(self):
        destination, manifest = self.bundle()
        self.assertIn("network_observer", manifest)
        self.assertEqual(verify_bundle(destination)["bundle_sha256"], manifest["bundle_sha256"])
        artifact = destination / manifest["network_observer"]["plugin"]
        artifact.chmod(0o644)
        artifact.write_bytes(artifact.read_bytes() + b"changed")
        with self.assertRaisesRegex(RuntimeError, "changed"):
            verify_bundle(destination)

    def test_observer_binary_change_and_missing_sidecar_are_rejected(self):
        sidecar = Path(str(self.observer) + ".observer.json")
        original = sidecar.read_bytes()
        sidecar.unlink()
        with self.assertRaises(NetworkObserverError):
            validate_observer(self.observer)
        sidecar.write_bytes(original)
        self.observer.write_bytes(self.observer.read_bytes() + b"changed")
        with self.assertRaises(NetworkObserverError):
            validate_observer(self.observer)

    def test_attempt_stages_independent_output_and_two_plugin_arguments(self):
        context, temporary, binding = self.context()
        setup, cleanup, execution = sandbox_fragments(context, temporary)
        observer = binding["network_observer"]
        self.assertEqual(observer["events"], str(context.run_dir / "logs/network_endpoints/events.jsonl"))
        self.assertNotIn(str(temporary), observer["plugin_argument"])
        self.assertEqual(execution.count("-plugin "), 2)
        self.assertIn("session=session,attempt=attempt", observer["plugin_argument"])
        self.assertIn(str(context.run_dir / "logs/network_endpoints"), setup)
        self.assertIn("network_endpoints", cleanup)
        directories = [line for line in setup.splitlines() if line.startswith("mkdir -m 0755 ")]
        self.assertEqual(len(directories), len(set(directories)))

    def test_runner_passes_bound_identity_and_sidecar_to_the_parser(self):
        context, temporary, _ = self.context()
        temporary.rename(context.run_dir)
        runner = object.__new__(PrebuiltRootfsRunner)
        runner.config = SimpleNamespace(project_root=PROJECT)
        runner.executor = FakeExecutor()
        runner._parse_logs(context)
        command = runner.executor.commands[-1]
        self.assertEqual(command[command.index("--endpoint-session") + 1], "session")
        self.assertEqual(command[command.index("--endpoint-attempt") + 1], "attempt")
        self.assertEqual(command[command.index("--endpoint-events") + 1],
                         str(context.run_dir / "logs/network_endpoints/events.jsonl"))

    def test_missing_selected_observer_fails_before_creating_output(self):
        binary = write_elf(self.root / "sample", arch="i386")
        output = self.root / "out"
        args = parser().parse_args(["run", "--binary", str(binary), "--out", str(output),
            "--qemu", str(self.qemu), "--plugin", str(self.phase1),
            "--network-observer", str(self.root / "missing.so")])
        with self.assertRaises(OSError):
            prepare(args)
        self.assertFalse(output.exists())

    def test_runner_rejects_a_binding_from_another_attempt(self):
        context, temporary, _ = self.context()
        temporary.rename(context.run_dir)
        path = context.run_dir / "config/phase1_binding.json"
        binding = json.loads(path.read_text())
        binding["attempt_id"] = "another-attempt"
        write_json(path, binding)
        runner = object.__new__(PrebuiltRootfsRunner)
        runner.config = SimpleNamespace(project_root=PROJECT)
        runner.executor = FakeExecutor()
        with self.assertRaisesRegex(PrebuiltRunnerError, "another session or attempt"):
            runner._parse_logs(context)

    def test_plugin_argument_rejects_ambiguous_options_and_identities(self):
        for path, session, attempt in [("/tmp/a,b.so", "session", "attempt"),
                                       ("/tmp/a.so", "bad identity", "attempt")]:
            with self.subTest(path=path, session=session):
                with self.assertRaises(NetworkObserverError):
                    plugin_argument(path, Path("/tmp/events"), session, attempt)


if __name__ == "__main__":
    unittest.main()
