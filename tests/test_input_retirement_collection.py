import hashlib
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from experiments.execution_capsule_probe import controller as p
from scripts import collect_input_retirement_evidence as collection
from scripts import run_input_retirement_e2e as acceptance
from taintforge_env.phase1_runtime import read_json
from tests import test_input_retirement as fixture


class CollectionTests(unittest.TestCase):
    def test_failed_run_is_preserved_with_complete_file_inventory(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "validation").mkdir()
            (root / "validation/preflight.log").write_text("systemd unavailable\n")
            receipt = root / "e2e/repair/session/iterations/0001/repair_application.json"
            receipt.parent.mkdir(parents=True)
            receipt.write_text("{}\n")
            result = collection.collect(root, 7)
            self.assertFalse(result["complete"])
            self.assertEqual(p.sha(result["archive"]), result["sha256"])
            with tarfile.open(result["archive"]) as archive:
                manifest = json.load(archive.extractfile("evidence/collection.json"))
                self.assertEqual(manifest["command_exit_code"], 7)
                self.assertEqual(len(manifest["files"]), 2)
                for item in manifest["files"]:
                    data = archive.extractfile("evidence/" + item["path"]).read()
                    self.assertEqual((len(data), hashlib.sha256(data).hexdigest()), (item["size"], item["sha256"]))
                self.assertEqual(len(archive.getmembers()), len(manifest["files"]) + 1)
            with self.assertRaisesRegex(p.ProbeError, "already exists"):
                collection.collect(root, 7)

    def test_symlink_and_oversize_sources_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "validation").mkdir()
            source = root / "validation/tests.log"
            source.symlink_to("/etc/passwd")
            with self.assertRaisesRegex(p.ProbeError, "Symlink"):
                collection.collect(root, 0)
            source.unlink()
            source.write_bytes(b"abcd")
            with patch.object(collection, "MAX_FILE", 3), self.assertRaisesRegex(p.ProbeError, "Invalid evidence"):
                collection.collect(root, 0)
            with patch.object(collection, "MAX_TOTAL", 3), self.assertRaisesRegex(p.ProbeError, "byte budget"):
                collection.collect(root, 0)
            self.assertFalse((root / "acceptance.tar.gz").exists())

    def test_complete_collection_and_tampered_portable_bundle(self):
        case = fixture.InputRetirementTests("test_original_input_no_fixture_oracle_and_portable_evidence")
        case.setUp()
        self.addCleanup(case.doCleanups)
        root = case.base / "collection"
        (root / "validation").mkdir(parents=True)
        for name in ("preflight", "build", "tests", "e2e"):
            (root / f"validation/{name}.log").write_text("synthetic collection test\n")
        p.write_json(root / "validation/tests.json", dict(modules=list(collection.MODULES), successful=True,
            tests_run=107, tests_expected=107, failures=0, errors=0, skipped=0, unexpected_successes=0))
        inputs = root / "e2e/inputs"
        inputs.mkdir(parents=True)
        p.write_json(inputs / "build.json", {"scope": "synthetic_collection_test"})
        names = ("normal", "repair", "missing-verdict", "fork-after")
        results = []
        for name in names:
            out, launch = case.prepare_input(name="collection/e2e/" + name)
            executor = fixture.InputExecutor(repair=name == "repair",
                fault="missing-verdict" if name in {"missing-verdict", "fork-after"} else None)
            report, code = case.invoke(out, launch, executor, steps=2)
            run = executor.runs[0][0]
            (inputs / name).write_bytes((run / "guest-i386").read_bytes())
            if name in {"missing-verdict", "fork-after"}:
                exit_code = 89 if name == "missing-verdict" else 126
                for path, key in ((run / "config/prebuilt_execution.json", "guest_exit_code"),
                                  (run / "logs/capsule/supervisor.json", "qemu_exit"),
                                  (run.parent / "execution_attempt.json", "guest_exit_code")):
                    p.write_json(path, read_json(path) | {key: exit_code})
                prefix = "CAPSULE_PHASE1_ABORT" if exit_code == 89 else "OBSERVER_ABORT"
                (run / "logs/qemu_strace.log").write_text(f"{prefix} code={exit_code} synthetic\n")
            with patch.object(acceptance, "run_session", side_effect=lambda *a, **k: case.invoke(out, launch, executor)):
                attempts = acceptance.validate_case(name, out, report, code)
            results.append(dict(name=name, status="passed", attempts=attempts))
        p.write_json(root / "e2e/report.json", dict(matrix_version=2, status="passed", acceptance_complete=True,
            scope="synthetic_collection_test", runtime_unchanged=True, cases=results,
            input_build_sha256=p.sha(inputs / "build.json")))
        with patch.object(collection, "CASES", {name: collection.CASES[name] for name in names}):
            result = collection.collect(root, 0)
            self.assertTrue(result["complete"], result)
            portable = root / "e2e/normal/session/iterations/0000/run/retirement-evidence/guest-i386"
            portable.write_bytes(b"tampered")
            with self.assertRaisesRegex(p.ProbeError, "changed"):
                collection.check_results(root)

    def test_missing_required_evidence_never_yields_complete(self):
        with tempfile.TemporaryDirectory() as temporary:
            result = collection.collect(Path(temporary), 0)
            self.assertFalse(result["complete"])
            self.assertIn("validation/tests.log", result["missing_required"])
            self.assertIn("e2e/repair/session/iterations/0001/repair_application.json", result["missing_required"])
            self.assertIn("e2e/fork-after/resume_report.json", result["missing_required"])

    def test_a_concurrent_change_aborts_collection(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "validation").mkdir()
            source = root / "validation/tests.log"
            source.write_text("before")
            real_sha = p.sha
            def changed(path):
                if Path(path) == source:
                    source.write_text("after")
                return real_sha(path)
            with patch.object(p, "sha", side_effect=changed), self.assertRaisesRegex(p.ProbeError, "changed during"):
                collection.collect(root, 0)
            self.assertFalse((root / "acceptance.tar.gz").exists())
