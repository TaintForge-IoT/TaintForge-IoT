from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from taintforge_env.phase1_runtime import Phase1Run, Phase1Runtime, Phase1RuntimeError, read_json
from tests.elf_fixture import write_elf


class Phase1RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.plugin = self.root / "plugin.so"
        self.plugin.write_bytes(b"test plugin identity")
        self.inputs = {"plugin_api": 5}
        self.build_id = hashlib.sha256(json.dumps(self.inputs, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        self.manifest = Path(str(self.plugin) + ".runtime.json")
        self.manifest.write_text(json.dumps({"schema_version": 1, "runtime_kind": "taintforge-phase1", "build_id": self.build_id,
            "build_inputs": self.inputs, "requirements": {"qemu_linkage": "dynamic", "plugins": True, "plugin_api": 5},
            "plugin": {"filename": self.plugin.name, "size": self.plugin.stat().st_size, "sha256": hashlib.sha256(self.plugin.read_bytes()).hexdigest()}}))
        self.runtime = Phase1Runtime.load(self.plugin)
        self.run = Phase1Run(self.runtime, "session", "attempt-000", "analysis", self.root / "run")

    def events(self):
        self.run.directory.mkdir(exist_ok=True)
        return [{"schema_version": 1, "session_id": "session", "attempt_id": "attempt-000", "analysis_instance_id": "analysis",
            "event_id": f"analysis:{i}", "event_seq": i, "event_type": event, "data": {}}
            for i, event in enumerate(("analysis_started", "analysis_finished"), 1)]

    def save_events(self, events):
        self.run.paths["events"].write_text("".join(json.dumps(e) + "\n" for e in events))

    def test_modified_plugin_is_not_selected(self):
        self.plugin.write_bytes(b"other build")
        with self.assertRaisesRegex(Phase1RuntimeError, "does not match"):
            Phase1Runtime.load(self.plugin)

    def test_modified_build_inputs_are_rejected(self):
        data = read_json(self.manifest)
        data["build_inputs"]["plugin_api"] = 4
        self.manifest.write_text(json.dumps(data))
        with self.assertRaisesRegex(Phase1RuntimeError, "identity does not match"):
            Phase1Runtime.load(self.plugin)

    def test_missing_manifest_cannot_fall_back(self):
        self.manifest.unlink()
        with self.assertRaises(Phase1RuntimeError):
            Phase1Runtime.load(self.plugin)

    def test_static_qemu_rejected_before_execution(self):
        qemu = write_elf(self.root / "qemu", arch="x86_64")
        with self.assertRaisesRegex(Phase1RuntimeError, "static QEMU"):
            self.runtime.validate_qemu(qemu)

    def test_output_identity_and_reuse(self):
        argument = self.run.plugin_argument(extra=("ir-probe=0x8049000",))
        self.assertIn("tf-attempt-id=attempt-000", argument)
        self.assertIn("tf-ir-report=", argument)
        self.run.paths["events"].touch()
        with self.assertRaisesRegex(Phase1RuntimeError, "reuse"):
            self.run.plugin_argument()

    def test_argument_cannot_replace_identity_or_paths(self):
        with self.assertRaises(Phase1RuntimeError):
            self.run.plugin_argument(extra=("tf-attempt-id=other",))
        with self.assertRaises(Phase1RuntimeError):
            Phase1Run(self.runtime, "bad,id", "attempt", "analysis", self.root)

    def test_event_reorder_identity_and_truncation(self):
        for change in ("reorder", "identity", "truncate", "no_finish"):
            with self.subTest(change=change):
                events = self.events()
                if change == "reorder": events.reverse()
                if change == "identity": events[-1]["attempt_id"] = "other"
                if change == "no_finish": events.pop()
                self.save_events(events)
                if change == "truncate":
                    path = self.run.paths["events"]
                    path.write_text(path.read_text()[:-1])
                with self.assertRaises(Phase1RuntimeError): self.run.events()

    def test_live_reader_accepts_only_complete_records(self):
        events = self.events()
        self.save_events(events[:1])
        with self.run.paths["events"].open("a") as out: out.write('{"event_')
        self.assertEqual(len(self.run.events(final=False)), 1)
        with self.assertRaises(Phase1RuntimeError): self.run.events()

    def test_duplicate_json_keys_rejected(self):
        path = self.root / "duplicate.json"
        path.write_text('{"schema_version":1,"schema_version":2}')
        with self.assertRaisesRegex(Phase1RuntimeError, "duplicate"):
            read_json(path)

    def test_channel_protection_cannot_be_asserted(self):
        with self.assertRaisesRegex(Phase1RuntimeError, "protected evidence channel"):
            self.run.verify(require_protected_channel=True)

    def test_events_after_finish_rejected(self):
        events = self.events()
        third = dict(events[-1], event_seq=3, event_id="analysis:3")
        self.save_events(events + [third])
        with self.assertRaisesRegex(Phase1RuntimeError, "follows terminal"):
            self.run.events()


if __name__ == "__main__":
    unittest.main()
