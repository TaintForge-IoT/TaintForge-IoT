from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from taintforge_env.capture_importer import (
    CaptureImportError,
    import_capture,
    load_capture_transaction,
)
from taintforge_env.replay_store import ReplayEntryExistsError, ReplayStore, sha256_bytes
from tests.capture_fixture import CLIENT, SERVER, read_events, write_capture, write_events


class CaptureImporterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.capture = write_capture(self.root / "capture")
        self.store = ReplayStore(self.root / "store")

    def _summary(self, mutate) -> None:
        path = self.capture / "session.json"
        summary = json.loads(path.read_text())
        mutate(summary)
        path.write_text(json.dumps(summary) + "\n")

    def _snapshot(self) -> dict[str, bytes]:
        return {str(path.relative_to(self.store.root)): path.read_bytes()
                for path in self.store.root.rglob("*") if path.is_file()}

    def _reject(self) -> None:
        before = self._snapshot()
        existed = self.store.root.exists()
        with self.assertRaises(CaptureImportError):
            import_capture(self.capture, self.store)
        self.assertEqual(self._snapshot(), before)
        self.assertEqual(self.store.root.exists(), existed)

    def test_segmented_transaction_and_provenance(self) -> None:
        result = import_capture(self.capture, self.store, protocol_hint="C2_BINARY")
        self.assertTrue(result.created)
        self.assertEqual(result.entry.request.remote_ip, "198.51.100.10")
        self.assertEqual(result.entry.request.remote_port, 48101)
        self.assertEqual(result.entry.request.protocol_hint, "c2_binary")
        exchange = self.store.load_exchange(result.entry)
        self.assertEqual((exchange.request_bytes, exchange.response_bytes), (b"hello", b"world"))
        self.assertTrue(result.entry.response.close_after_send)
        self.assertEqual(result.entry.response.delay_ms, 0)
        self.assertEqual(result.entry.source_run_id, "fixture-run")
        stored = self.store.load_entries()[0]
        provenance = json.loads(stored.notes)["capture_import"]
        self.assertEqual(provenance, result.provenance)
        self.assertEqual(provenance["session_id"], "fixture-session")
        for name, digest in provenance["source_files_sha256"].items():
            self.assertEqual(digest, sha256_bytes((self.capture / name).read_bytes()))
        self.assertEqual(self.store.validate()["entries"], 1)

    def test_identical_import_is_byte_for_byte_noop(self) -> None:
        first = import_capture(self.capture, self.store)
        before = self._snapshot()
        digest = self.store.validate()["store_sha256"]
        second = import_capture(self.capture, self.store)
        self.assertFalse(second.created)
        self.assertEqual(first.entry, second.entry)
        self.assertEqual(second.to_dict()["status"], "already_present")
        self.assertEqual(self._snapshot(), before)
        self.assertEqual(self.store.validate()["store_sha256"], digest)

    def test_identical_exchange_from_another_source_returns_current_receipt(self) -> None:
        first = import_capture(self.capture, self.store)
        self._summary(lambda raw: raw.update(run_id="another-run"))
        before = self._snapshot()
        second = import_capture(self.capture, self.store)
        self.assertFalse(second.created)
        self.assertEqual(first.entry, second.entry)
        self.assertEqual(second.provenance["run_id"], "another-run")
        self.assertEqual(self._snapshot(), before)

    def test_conflicting_response_or_replay_policy_never_replaces(self) -> None:
        for response, close, delay in ((b"other", True, 0), (b"world", False, 0),
                                       (b"world", True, 1)):
            with self.subTest(response=response, close=close, delay=delay):
                self.store.add(transport="tcp", remote_ip="198.51.100.10", remote_port=48101,
                               request_bytes=b"hello", response_bytes=response,
                               close_after_send=close, delay_ms=delay, replace=True)
                before = self._snapshot()
                with self.assertRaises(ReplayEntryExistsError):
                    import_capture(self.capture, self.store)
                self.assertEqual(self._snapshot(), before)

    def test_both_prefix_directions_rejected_before_any_store_write(self) -> None:
        for i, request in enumerate((b"he", b"hello!")):
            with self.subTest(request=request):
                self.store = ReplayStore(self.root / f"prefix-{i}")
                self.store.add(transport="tcp", remote_ip="198.51.100.10", remote_port=48101,
                               request_bytes=request, response_bytes=b"existing")
                self._reject()

    def test_other_endpoint_and_protocol_hint_do_not_conflict(self) -> None:
        self.store.add(transport="tcp", remote_ip="198.51.100.11", remote_port=48101,
                       request_bytes=b"he", response_bytes=b"other")
        self.store.add(transport="tcp", remote_ip="198.51.100.10", remote_port=48101,
                       request_bytes=b"hello", response_bytes=b"other", protocol_hint="other")
        self.assertTrue(import_capture(self.capture, self.store).created)
        self.assertEqual(self.store.validate()["entries"], 3)

    def test_server_first_and_multiround_captures_are_rejected(self) -> None:
        for i, chunks in enumerate((((SERVER, b"banner"), (CLIENT, b"hello")),
                                    ((CLIENT, b"one"), (SERVER, b"1"),
                                     (CLIENT, b"two"), (SERVER, b"2")))):
            with self.subTest(chunks=chunks):
                self.capture = write_capture(self.root / f"ordered-{i}", chunks)
                self._reject()

    def test_unfinished_timeout_error_and_invalid_summary_rejected(self) -> None:
        original = (self.capture / "session.json").read_bytes()
        cases = [
            lambda s: s.update(close_reason="idle_timeout"),
            lambda s: s.update(close_reason="session_timeout"),
            lambda s: s.update(close_reason="client_to_server_limit_exceeded"),
            lambda s: s.update(close_reason="unknown"),
            lambda s: s.update(close_reason=[]),
            lambda s: s.update(error="ConnectionResetError"),
            lambda s: s.pop("error"),
            lambda s: s.update(schema_version=True),
            lambda s: s.update(original_remote_port=True),
            lambda s: s.update(original_remote_ip="::1"),
            lambda s: s.update(transport="udp"),
            lambda s: s.update(run_id=""),
            lambda s: s.update(finished_at_utc=None),
            lambda s: s.update(duration_seconds=float("nan")),
            lambda s: s.update(duration_seconds=10 ** 400),
            lambda s: s[CLIENT].update(bytes=True),
            lambda s: s[CLIENT].update(bytes=0),
            lambda s: s[SERVER].update(bytes=0),
            lambda s: s[CLIENT].update(bytes=6),
            lambda s: s[CLIENT].update(chunks=3),
            lambda s: s[CLIENT].update(sha256="0" * 64),
            lambda s: s["limits"].update(max_client_bytes=4),
        ]
        for i, mutate in enumerate(cases):
            with self.subTest(case=i):
                (self.capture / "session.json").write_bytes(original)
                self._summary(mutate)
                self._reject()

    def test_bad_events_rejected_without_store_mutation(self) -> None:
        original = read_events(self.capture)
        cases = [
            lambda e: e.pop(),
            lambda e: e.pop(1),
            lambda e: e.pop(2),
            lambda e: e.insert(3, e[2].copy()),
            lambda e: e[2].update(session_id="other"),
            lambda e: e[0].update(original_remote_port=80),
            lambda e: e[1].update(upstream_port=True),
            lambda e: e[-1].update(client_bytes=9),
            lambda e: e[-1].update(error="reset"),
            lambda e: e[2].update(chunk_index=True),
            lambda e: e[2].update(direction="unknown"),
            lambda e: e[2].update(size=99),
            lambda e: e[2].update(sha256="0" * 64),
            lambda e: e[2].update(elapsed_seconds=10),
            lambda e: e[3].update(elapsed_seconds=0),
            lambda e: e[2].update(event="relay_error"),
            lambda e: e.pop(-2),  # no upstream EOF
            lambda e: e.insert(2, {"event": "stream_eof", "direction": CLIENT,
                                   "session_id": "fixture-session", "timestamp_utc": e[0]["timestamp_utc"]}),
        ]
        self.store.initialize()
        for i, mutate in enumerate(cases):
            with self.subTest(case=i):
                events = json.loads(json.dumps(original))
                mutate(events)
                write_events(self.capture, events)
                self._reject()

    def test_corrupt_missing_extra_and_disagreeing_payloads_rejected(self) -> None:
        chunk = self.capture / "chunks/000001_client_to_server.bin"
        chunk.write_bytes(b"XX")
        self._reject()
        # Even mutually consistent chunk bytes and event hashes cannot override
        # a different aggregate stream with its own valid summary hash.
        events = read_events(self.capture)
        events[2]["sha256"] = sha256_bytes(b"XX")
        write_events(self.capture, events)
        self._reject()
        chunk.unlink()
        self._reject()

    def test_unreferenced_chunk_rejected(self) -> None:
        (self.capture / "chunks/extra.bin").write_bytes(b"orphan")
        self._reject()

    def test_payload_paths_cannot_escape_capture(self) -> None:
        original = (self.capture / "session.json").read_bytes()
        for path in ("../secret", "/etc/passwd", "chunks/../client_to_server.bin"):
            with self.subTest(path=path):
                (self.capture / "session.json").write_bytes(original)
                self._summary(lambda s: s[CLIENT].update(path=path))
                self._reject()
        (self.capture / "session.json").write_bytes(original)
        events = read_events(self.capture)
        events[2]["payload_file"] = "../secret"
        write_events(self.capture, events)
        self._reject()

    def test_symlinks_and_fifo_rejected(self) -> None:
        chunk = self.capture / "chunks/000001_client_to_server.bin"
        outside = self.root / "outside"
        outside.write_bytes(chunk.read_bytes())
        chunk.unlink()
        chunk.symlink_to(outside)
        self._reject()
        chunk.unlink()
        os.mkfifo(chunk)
        self._reject()

    def test_symlinked_capture_or_chunks_directory_rejected(self) -> None:
        link = self.root / "capture-link"
        link.symlink_to(self.capture, target_is_directory=True)
        with self.assertRaises(CaptureImportError):
            load_capture_transaction(link)
        (self.capture / "chunks").rename(self.root / "moved-chunks")
        (self.capture / "chunks").symlink_to(self.root / "moved-chunks", target_is_directory=True)
        self._reject()

    def test_duplicate_json_keys_and_truncated_jsonl_rejected(self) -> None:
        path = self.capture / "session.json"
        original = path.read_bytes()
        path.write_bytes(original.replace(b'"schema_version": 1',
                                         b'"schema_version": 2, "schema_version": 1'))
        self._reject()
        path.write_bytes(original)
        path = self.capture / "events.jsonl"
        path.write_bytes(path.read_bytes().rstrip(b"\n"))
        self._reject()

    def test_size_limit_applies_before_import(self) -> None:
        self.store = ReplayStore(self.root / "limited", max_request_bytes=4)
        self._reject()
        self.store = ReplayStore(self.root / "limited", max_response_bytes=4)
        self._reject()


if __name__ == "__main__":
    unittest.main()
