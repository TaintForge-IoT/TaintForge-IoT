"""Check timing/generation validation against a genuine production capture."""
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from ct_elf import CaptureError, sha256
from cu_capture import validate

SOURCE = Path(sys.argv[1]).resolve()
del sys.argv[1]


class CaptureValidation(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.path = Path(self.temporary.name)
        for name in ('capture.json', 'image.bin', 'capture-manifest.json', 'events.jsonl'):
            shutil.copyfile(SOURCE / name, self.path / name)
        self.report = json.loads((self.path / 'capture.json').read_text())

    def tearDown(self):
        self.temporary.cleanup()

    def write_report(self):
        path = self.path / 'capture.json'
        path.write_text(json.dumps(self.report))
        manifest = json.loads((self.path / 'capture-manifest.json').read_text())
        manifest['artifacts']['report'].update(sha256=sha256(path), size=path.stat().st_size)
        (self.path / 'capture-manifest.json').write_text(json.dumps(manifest))

    def reject(self, reason):
        self.write_report()
        with self.assertRaises(CaptureError) as caught:
            validate(self.path)
        self.assertEqual(reason, caught.exception.reason)

    def test_real_capture(self):
        validate(self.path)

    def test_late_timestamp_with_valid_code_and_hashes(self):
        self.report['capture_trace_seq'] += 1
        self.reject('CAPTURE_TIMING_MISMATCH')

    def test_wrong_candidate_identity(self):
        self.report['capture_candidate_id'] += 1
        self.reject('CAPTURE_TIMING_MISMATCH')

    def test_wrong_capture_pc(self):
        self.report['capture_pc'] += 1
        self.reject('CAPTURE_TIMING_MISMATCH')

    def test_unverified_mapping(self):
        self.report['main_image_verified'] = False
        self.reject('UNVERIFIED_MAIN_IMAGE')

    def test_stale_generation(self):
        chosen = next(c for c in self.report['oep_candidates'] if c['selected'])
        chosen['code_generation'] += 1
        self.reject('STALE_CANDIDATE')

    def test_stale_candidate(self):
        chosen = next(c for c in self.report['oep_candidates'] if c['selected'])
        chosen['stale'] = True
        self.reject('STALE_CANDIDATE')

    def test_corrupt_dump(self):
        path = self.path / 'image.bin'
        data = bytearray(path.read_bytes())
        data[0] ^= 1
        path.write_bytes(data)
        with self.assertRaises(CaptureError) as caught:
            validate(self.path)
        self.assertEqual('CAPTURE_HASH_MISMATCH', caught.exception.reason)

    def test_missing_commit_manifest(self):
        (self.path / 'capture-manifest.json').unlink()
        with self.assertRaises(CaptureError) as caught:
            validate(self.path)
        self.assertEqual('CAPTURE_UNAVAILABLE', caught.exception.reason)


unittest.main()
