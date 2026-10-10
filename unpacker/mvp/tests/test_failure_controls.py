"""Regressions for failed prerequisites and false-positive negative controls."""
from contextlib import redirect_stdout
from pathlib import Path
import io
import json
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import cu_capture
import cv_runner
from ct_elf import CaptureError


class FailureControls(unittest.TestCase):
    def test_missing_guest_never_launches_capture(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with patch.object(cu_capture, 'run') as launch:
                with self.assertRaises(CaptureError) as caught:
                    cu_capture.capture(Path('/bin/false'), root/'plugin.so', root/'missing.upx',
                                       {}, root/'capture', {}, root/'guard.so')
                self.assertEqual(caught.exception.reason, 'CAPTURE_INPUT_UNAVAILABLE')
                launch.assert_not_called()
                self.assertFalse((root/'capture').exists())

    def test_no_guest_failure_is_not_budget_or_collision_success(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory/'capture.json').write_text(json.dumps(dict(
                main_image_verified=False, capture_status='not_available', analysis_instance_id='no-guest')))
            (directory/'events.jsonl').write_text(json.dumps(dict(
                event_type='analysis_finished', trace_seq=0, incomplete_reasons=[]))+'\n')
            process = dict(returncode=1, timed_out=False, rss_limit_hit=False, solver_guard_active=True)
            for status,reason in (('budget_exhausted','capture_budget_exhausted'),('error','dump_open_failed')):
                with self.subTest(reason=reason), self.assertRaises(CaptureError):
                    cu_capture.validate_export_failure(directory, process, status, reason)

    def test_generic_capture_absence_does_not_establish_expected_cause(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            report = dict(main_image_verified=True, capture_status='budget_exhausted',
                          dse_check_enabled=False, trace_archive_enabled=False, analysis_instance_id='guest')
            events = [dict(event_type='oep_candidate_observed', trace_seq=10,
                           analysis_instance_id='guest', incomplete_reasons=[]),
                      dict(event_type='error', trace_seq=10, analysis_instance_id='guest',
                           incomplete_reasons=['dump_open_failed'])]
            (directory/'capture.json').write_text(json.dumps(report))
            (directory/'events.jsonl').write_text(''.join(json.dumps(e)+'\n' for e in events))
            process = dict(returncode=0, timed_out=False, rss_limit_hit=False, solver_guard_active=True)
            with self.assertRaises(CaptureError):
                cu_capture.validate_export_failure(directory, process, 'budget_exhausted', 'capture_budget_exhausted')

    def test_failed_scale_pack_does_not_rebuild_partial_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            built = []

            def build(name, optimization, directory, compiler, size):
                directory.mkdir(parents=True, exist_ok=False)
                built.append(size)
                path = directory/'original.elf'
                path.write_bytes(b'partial test input')
                return path

            def pack(original, mode, directory, upx):
                directory.mkdir(parents=True, exist_ok=False)
                raise CaptureError('UPX_PACK_FAILED', 'controlled packing failure')

            summary = dict(scale=[])
            with patch.object(cv_runner.cv_build,'build_original',side_effect=build), \
                 patch.object(cv_runner.cv_build,'pack',side_effect=pack), \
                 patch.object(cv_runner,'check_program') as capture, redirect_stdout(io.StringIO()):
                rows = cv_runner.scale(root/'scale',Path('/bin/false'),root/'plugin.so',root/'guard.so',
                                       Path('/bin/false'),Path('/bin/false'),summary,root)
            self.assertEqual(built,[65536,262144,1048576])
            self.assertEqual([r['reason'] for r in rows],
                             ['UPX_PACK_FAILED']*3+['DEPENDENCY_FAILED']*3)
            self.assertTrue(all(r['status']=='FAIL' for r in rows))
            capture.assert_not_called()


if __name__ == '__main__':
    unittest.main()
