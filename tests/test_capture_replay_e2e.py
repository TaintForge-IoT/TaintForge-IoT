from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(
    shutil.which("gcc") and platform.system() == "Linux"
    and platform.machine() in ("x86_64", "amd64"),
    "Linux x86-64 and gcc are required for the real C-client E2E",
)
class CaptureReplayE2ETests(unittest.TestCase):
    def test_real_c_client_record_import_offline_replay(self) -> None:
        import sys

        with tempfile.TemporaryDirectory() as temporary:
            out = Path(temporary) / "e2e"
            result = subprocess.run(
                [sys.executable, str(PROJECT_ROOT / "scripts/run_c2_replay_local_e2e.py"),
                 "--out", str(out)],
                cwd=PROJECT_ROOT, env=dict(os.environ, PYTHONPATH=str(PROJECT_ROOT)),
                capture_output=True, text=True, timeout=45)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            report = json.loads((out / "report.json").read_text())
            self.assertEqual(report["status"], "passed")
            self.assertTrue(report["prebuilt_validated"])
            self.assertTrue(report["synthesis_binding_verified"])
            self.assertFalse(report["sandbox_executed"])
            self.assertTrue(report["upstream_stopped_before_replay"])
            self.assertEqual(report["upstream_connections"], 1)
            self.assertEqual(report["replay_hits"], 1)
            self.assertEqual(report["replay_misses"], 1)
            self.assertGreaterEqual(report["response_capture_chunks"], 2)
            self.assertEqual((out / "record_client.stdout").read_bytes(), b"world\n")
            self.assertEqual((out / "replay_client.stdout").read_bytes(), b"world\n")


if __name__ == "__main__":
    unittest.main()
