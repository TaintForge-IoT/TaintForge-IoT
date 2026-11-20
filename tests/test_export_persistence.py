"""NET-9 export publication, using ordinary local files."""
import errno
import hashlib
import os
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from taintforge_env import phase1_retirement as retirement


class ExportPersistenceTests(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        self.binding = {"run_dir": str(root)}
        self.parent = retirement.directory(self.binding)
        self.parent.mkdir(parents=True)
        self.export = self.parent / "export"
        self.paths = {key: root / name for key, name in (
            ("events", "events.jsonl"), ("manifest", "capture_manifest.json"),
            ("dump", "unpacked.bin"), ("report", "unpacked.json"), ("ir", "ir_runtime.jsonl"))}
        self.contents = {p.name: p.name.encode() + b"\x00\n" for p in self.paths.values()}
        for path in self.paths.values():
            path.write_bytes(self.contents[path.name])
        self.run = SimpleNamespace(paths=self.paths)

    def test_first_sync_sees_complete_batch_and_each_inode_is_synced(self):
        calls = []
        sync = os.fsync

        def observe(fd):
            if not calls:
                self.assertEqual({p.name: p.read_bytes() for p in self.export.iterdir()}, self.contents)
            calls.append(os.fstat(fd).st_ino)
            sync(fd)

        with patch.object(os, "fsync", side_effect=observe):
            hashes = retirement.preserve_export(self.binding, self.run)
        self.assertCountEqual(calls[:-2], [p.stat().st_ino for p in self.export.iterdir()])
        self.assertEqual(calls[-2:], [self.export.stat().st_ino, self.parent.stat().st_ino])
        self.assertEqual(hashes, {name: hashlib.sha256(raw).hexdigest() for name, raw in self.contents.items()})

    def test_file_and_directory_errors_propagate_and_descriptors_close(self):
        sync = os.fsync
        for target in (self.export / "unpacked.bin", self.export, self.parent):
            with self.subTest(target=target):
                def fail(fd):
                    if target.exists() and os.fstat(fd).st_ino == target.stat().st_ino:
                        raise OSError(errno.EIO, "sync failed")
                    sync(fd)

                with patch.object(os, "fsync", side_effect=fail), self.assertRaises(OSError) as error:
                    retirement.preserve_export(self.binding, self.run)
                self.assertEqual(error.exception.errno, errno.EIO)
                owned = {*self.export.iterdir(), self.export, self.parent}
                for fdpath in Path("/proc/self/fd").iterdir():
                    try:
                        destination = fdpath.readlink()
                    except FileNotFoundError:
                        continue
                    self.assertNotIn(destination, owned)
                for p in self.export.iterdir():
                    p.unlink()
                self.export.rmdir()

    def test_changed_source_detected_after_file_sync(self):
        sync = os.fsync
        source = self.paths["report"]

        def change_once(fd):
            sync(fd)
            if os.fstat(fd).st_ino == (self.export / source.name).stat().st_ino:
                source.write_bytes(b"changed")

        with patch.object(os, "fsync", side_effect=change_once), self.assertRaisesRegex(RuntimeError, "changed"):
            retirement.preserve_export(self.binding, self.run)
