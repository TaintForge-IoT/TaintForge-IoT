"""Read-only input checks must identify missing files before any guest run."""
import io
import json
import os
from pathlib import Path
import shutil
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from scripts.run_unified_local_e2e import run as run_e2e
from scripts.run_unified_pipeline import main
from taintforge_env.unified_runtime import check_runtime_inputs, UnifiedRuntimeError
from tests.elf_fixture import write_elf
from tests.test_unified_pipeline import fake_toolchain


@unittest.skipUnless(shutil.which("gcc") and shutil.which("true"), "host ELF fixture compiler required")
class UnifiedPreflightTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.qemu, self.plugin = fake_toolchain(self.root / "tools")

    def check(self, **kwargs):
        return check_runtime_inputs(self.root, qemu=self.qemu, plugin=self.plugin, **kwargs)

    def test_each_missing_component_is_identified_without_writes(self):
        for path, label in ((self.qemu, "QEMU executable"), (self.plugin, "Phase 1 plugin"),
                            (Path(str(self.plugin) + ".runtime.json"), "Phase 1 runtime manifest")):
            with self.subTest(component=label):
                content, mode = path.read_bytes(), path.stat().st_mode
                path.unlink()
                try:
                    with self.assertRaises(UnifiedRuntimeError) as failure:
                        self.check()
                    self.assertIn(f"{label}: missing regular file: {path}", str(failure.exception))
                    self.assertFalse(path.exists())
                finally:
                    path.write_bytes(content)
                    path.chmod(mode)

    def test_valid_files_do_not_claim_a_plugin_load_or_execute_qemu(self):
        with patch("subprocess.run", side_effect=AssertionError("QEMU must not run during this check")):
            report = self.check()
        self.assertEqual(report["status"], "input_files_verified")
        self.assertEqual(report["qemu"]["linkage"], "dynamic")
        self.assertEqual(report["qemu_plugin_load"], "not_tested")
        self.assertFalse(report["guest_executed"])

    def test_alternative_default_build_is_reported_without_silent_selection(self):
        directory = self.root / "unpacker/test"
        directory.mkdir(parents=True)
        candidate = directory / "libtaintforge_ir.so"
        candidate.write_bytes(self.plugin.read_bytes())
        metadata = json.loads(Path(str(self.plugin) + ".runtime.json").read_text())
        # Synthetic fixture identity, not a manifest for an actual TCG plugin.
        metadata["plugin"]["filename"] = candidate.name
        Path(str(candidate) + ".runtime.json").write_text(json.dumps(metadata))
        selected = self.root / "build/libtaintforge_ir.so"
        with self.assertRaises(UnifiedRuntimeError) as failure:
            check_runtime_inputs(self.root, qemu=self.qemu, plugin=selected)
        self.assertIn(f"--plugin {candidate}", str(failure.exception))
        self.assertIn(str(selected), str(failure.exception))
        self.assertFalse(selected.exists())

    def test_e2e_missing_inputs_does_not_create_output_or_build_fixtures(self):
        args = SimpleNamespace(out=self.root / "e2e", qemu=self.qemu,
                               plugin=self.root / "missing.so", dynamic_sysroot=None)
        with patch("scripts.run_unified_local_e2e.command", side_effect=AssertionError("fixtures must not build")):
            with self.assertRaises(UnifiedRuntimeError):
                run_e2e(args)
        self.assertFalse(args.out.exists())

    def test_environment_selection_and_explicit_precedence(self):
        with patch.dict(os.environ, {"TAINTFORGE_QEMU_PLUGIN": str(self.plugin)}):
            report = check_runtime_inputs(self.root, qemu=self.qemu)
            self.assertEqual(report["plugin"], str(self.plugin))
            with self.assertRaisesRegex(UnifiedRuntimeError, "explicit-missing.so"):
                check_runtime_inputs(self.root, qemu=self.qemu, plugin=self.root / "explicit-missing.so")

    def test_static_qemu_is_rejected_as_static_not_as_missing(self):
        write_elf(self.qemu, arch="x86_64")
        with self.assertRaisesRegex(RuntimeError, "static QEMU"):
            self.check()

    def test_cli_check_needs_no_binary_out_or_sudo(self):
        output = io.StringIO()
        with patch("sys.argv", ["run_unified_pipeline.py", "check-runtime", "--qemu", str(self.qemu), "--plugin", str(self.plugin)]), patch("sys.stdout", output):
            status = main()
        self.assertEqual(status, 0)
        self.assertEqual(json.loads(output.getvalue())["status"], "input_files_verified")


if __name__ == "__main__":
    unittest.main()
