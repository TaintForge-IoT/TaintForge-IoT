"""Identity checks use synthetic receipts; no fixture is an executable plugin."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts import audit_phase1_lifecycle as audit


class LifecycleAuditTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.repo = Path(self.temporary.name)
        self.source = self.repo / "unpacker/test"
        self.source.mkdir(parents=True)
        contents = {"owner.c": b"int owner;\n", "owner.h": b"extern int owner;\n",
                    "build_group7_4c1_plugin.sh": b"exit 0\n", "phase1_build_manifest.py": b"pass\n"}
        for name, data in contents.items():
            (self.source / name).write_bytes(data)
        self.reference = {"schema_version": 1, "revision": "a" * 40,
                          "qemu": {"plugin_api": 6, "header_sha256": "b" * 64},
                          "source_files": {name: hashlib.sha256(data).hexdigest()
                                           for name, data in contents.items()},
                          "findings": [{"id": "TEST-ONLY"}]}
        self.plugin = self.repo / "build/libtaintforge_ir.so"
        self.plugin.parent.mkdir()
        self.plugin.write_bytes(b"Synthetic plugin identity fixture. Never loaded.\n")
        self.manifest_path = Path(str(self.plugin) + ".runtime.json")
        self.manifest = {"schema_version": 1, "runtime_kind": "taintforge-phase1",
                         "plugin": {"filename": self.plugin.name, **audit.fingerprint(self.plugin)},
                         "build_inputs": {"source_files": dict(self.reference["source_files"]),
                                          "qemu_header_sha256": "b" * 64, "plugin_api": 6,
                                          "compiler": "test compiler", "cppflags": "",
                                          "ldflags": "", "libs": ""},
                         "compiled_profile": dict(audit.PROFILE),
                         "requirements": {"qemu_linkage": "dynamic", "plugins": True, "plugin_api": 6}}
        self.save_manifest()

    def save_manifest(self):
        self.manifest["build_id"] = hashlib.sha256(json.dumps(
            self.manifest["build_inputs"], sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        self.manifest_path.write_text(json.dumps(self.manifest))

    def inspect(self, source_only=False):
        return audit.inspect(self.repo, self.source, self.plugin, self.reference, source_only)

    def test_matching_identity_never_claims_safe_retirement(self):
        before = {p: p.read_bytes() for p in self.repo.rglob("*") if p.is_file()}
        result = self.inspect()
        self.assertEqual(result["status"], "matched")
        self.assertEqual(result["runtime_binding"], "matched")
        self.assertTrue(result["source_matches_build"])
        for name in ("live_retirement_ready", "phase1_memory_released", "residue_free", "plugin_executed"):
            self.assertIs(result[name], False)
        self.assertEqual(before, {p: p.read_bytes() for p in self.repo.rglob("*") if p.is_file()})

    def test_modified_source_and_missing_source_are_mismatches(self):
        (self.source / "owner.c").write_text("int edited_owner;\n")
        (self.source / "owner.h").unlink()
        result = self.inspect()
        self.assertEqual(result["status"], "mismatch")
        self.assertFalse(result["files"]["owner.c"]["matches_build"])
        self.assertIsNone(result["files"]["owner.h"]["actual_sha256"])

    def test_unreviewed_build_and_extra_header_cannot_match(self):
        (self.source / "new.h").write_text("int new_owner;\n")
        self.manifest["build_inputs"]["source_files"]["new.h"] = audit.fingerprint(self.source / "new.h")["sha256"]
        self.save_manifest()
        result = self.inspect()
        self.assertTrue(result["source_matches_build"])
        self.assertFalse(result["source_matches_review"])
        self.assertEqual(result["status"], "mismatch")

    def test_source_only_and_missing_manifest_are_explicit(self):
        self.manifest_path.unlink()
        self.assertEqual(self.inspect()["runtime_binding"], "manifest_missing")
        self.assertEqual(self.inspect()["status"], "mismatch")
        result = self.inspect(source_only=True)
        self.assertEqual(result["status"], "matched")
        self.assertEqual(result["runtime_binding"], "not_checked")
        self.assertFalse(result["source_matches_build"])

    def test_tampered_receipt_and_different_binary(self):
        self.manifest["build_id"] = "0" * 64
        self.manifest_path.write_text(json.dumps(self.manifest))
        with self.assertRaisesRegex(ValueError, "build_id"):
            self.inspect()
        self.save_manifest()
        self.plugin.write_bytes(b"different bytes")
        self.assertEqual(self.inspect()["status"], "mismatch")
        self.assertFalse(self.inspect()["runtime"]["checks"]["plugin_matches_manifest"])

    def test_header_api_profile_and_source_set_are_checked(self):
        original = copy.deepcopy(self.manifest)
        edits = (("build_inputs", "plugin_api", 7),
                 ("build_inputs", "qemu_header_sha256", "c" * 64),
                 ("compiled_profile", "threads", 2),
                 ("compiled_profile", "threads", True),
                 ("requirements", "qemu_linkage", "static"))
        for section, key, value in edits:
            with self.subTest(section=section, key=key):
                self.manifest = copy.deepcopy(original)
                self.manifest[section][key] = value
                self.save_manifest()
                self.assertEqual(self.inspect()["status"], "mismatch")

    def test_paths_duplicates_symlinks_and_bounded_json(self):
        for name in ("../owner.c", "/owner.c", "sub/owner.c"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                audit.source_map({name: "a" * 64})
        self.manifest_path.write_text('{"schema_version":1,"schema_version":1}')
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            self.inspect()
        self.manifest_path.write_text('{"not_json": NaN}')
        with self.assertRaisesRegex(ValueError, "Non-finite"):
            audit.read_json(self.manifest_path)
        self.manifest_path.write_bytes(b" " * (audit.MAX_JSON + 1))
        with self.assertRaisesRegex(ValueError, "too large"):
            self.inspect()
        self.manifest_path.unlink()
        self.manifest_path.symlink_to(self.source / "owner.c")
        with self.assertRaises(OSError):
            self.inspect()

    def test_output_cannot_overwrite_sources_or_existing_results(self):
        for name in ("unpacker/test/owner.c", "build/new.json", "scripts/new.json"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                audit.output_path(self.repo / name, self.repo, self.source)
        out = self.repo / "workdir/audit.json"
        self.assertEqual(audit.output_path(out, self.repo, self.source), out)
        out.parent.mkdir()
        out.write_text("existing result")
        with self.assertRaisesRegex(ValueError, "already exists"):
            audit.output_path(out, self.repo, self.source)
        build = self.repo / "build"
        build.rename(self.repo / "actual-build")
        build.symlink_to(self.repo / "actual-build", target_is_directory=True)
        with self.assertRaises(ValueError):
            audit.output_path(build / "new.json", self.repo, self.source)

    def test_cli_reports_mismatch_without_importing_target_repo(self):
        (self.source / "owner.c").write_text("int changed;\n")
        with patch.object(audit, "read_json", side_effect=lambda path:
                          self.reference if path == audit.REFERENCE else self.manifest):
            code = audit.main(["--repo", str(self.repo), "--out", "workdir/audit.json"])
        self.assertEqual(code, 1)
        result = json.loads((self.repo / "workdir/audit.json").read_text())
        self.assertEqual(result["status"], "mismatch")

    def test_edit_during_inspection_is_an_error(self):
        original = audit.fingerprint
        seen = 0

        def changed(path):
            nonlocal seen
            result = original(path)
            if path == self.source / "owner.c":
                seen += 1
                if seen == 1:
                    path.write_text("int concurrent_edit;\n")
            return result

        with patch.object(audit, "fingerprint", side_effect=changed):
            with self.assertRaisesRegex(ValueError, "Source changed"):
                self.inspect()


if __name__ == "__main__":
    unittest.main()
