"""Negative checks for actual process accounting and output-file validation."""
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import cv_corpus
from cv_runner import check_behavior
from cu_process import run


class RunnerControls(unittest.TestCase):
    def test_observed_rss_exhaustion(self):
        with tempfile.TemporaryDirectory() as temporary:
            child = Path(temporary) / 'run'
            command = [sys.executable, '-c', 'import time; data=bytearray(96*1024*1024); time.sleep(0.15)']
            result = run(command, {}, child, {}, rss_limit_mib=64)
            self.assertGreater(result['max_rss_kib'], 64*1024)
            self.assertTrue(result['rss_limit_hit'])
            self.assertFalse(result['timed_out'])

    def test_changed_output_file_is_rejected(self):
        case = cv_corpus.cases('filetransform')[1]
        with tempfile.TemporaryDirectory() as temporary:
            child = Path(temporary) / 'run'
            command = [sys.executable, '-c',
                'from pathlib import Path; Path("output.bin").write_bytes(b"abc"); print("n=3 hash=440920331")']
            result = run(command, case, child, {})
            self.assertTrue(check_behavior(case, child, result))
            (child / 'output.bin').write_bytes(b'abd')
            self.assertFalse(check_behavior(case, child, result))

    def test_unexpected_output_file_is_rejected(self):
        case = cv_corpus.cases('filetransform')[9]
        with tempfile.TemporaryDirectory() as temporary:
            child = Path(temporary) / 'run'
            result = run([sys.executable,'-c','import sys; print("ERR"); sys.exit(2)'],case,child,{})
            self.assertTrue(check_behavior(case, child, result))
            (child / 'output.bin').write_bytes(b'unexpected')
            self.assertFalse(check_behavior(case, child, result))


if __name__ == '__main__':
    unittest.main()
