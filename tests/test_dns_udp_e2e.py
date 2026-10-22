import json
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
import unittest


@unittest.skipUnless(shutil.which("gcc") and platform.system() == "Linux"
                    and platform.machine() in ("x86_64", "amd64"), "the domain-client scenario needs Linux x86-64 and gcc")
class DomainNetworkE2ETests(unittest.TestCase):
    def test_real_client_and_import_cli_with_upstream_stopped(self):
        with tempfile.TemporaryDirectory() as temporary:
            out = Path(temporary) / "run"
            result = subprocess.run([sys.executable, "scripts/run_dns_udp_replay_e2e.py", "--out", str(out)],
                capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            report = json.loads((out / "report.json").read_text())
            self.assertTrue(report["local"]["upstream_stopped_before_replay"])
            self.assertTrue(report["local"]["dns_tcp_fallback"])
            self.assertEqual(report["local"]["entries"], 4)
            self.assertFalse(report["sandbox_executed"])
            policy = out / "local/record_policy.json"
            captures = out / "local/record/captures"
            message = next(p.parent for p in captures.glob("*/session.json")
                           if "capture_format" in json.loads(p.read_text()))
            (message / "response.bin").write_bytes(b"damaged")
            failed = Path(temporary) / "invalid-bundle"
            rejected = subprocess.run([sys.executable, "scripts/import_network_recording.py", "--capture-dir", str(captures),
                "--policy", str(policy), "--out", str(failed)], capture_output=True, text=True, timeout=5)
            self.assertNotEqual(rejected.returncode, 0)
            self.assertFalse(failed.exists(), "invalid import published a partial replay bundle")
