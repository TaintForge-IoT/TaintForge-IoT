from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from taintforge_env.iteration_controller import IterationController
from taintforge_env.replay_store import ReplayStore
from tests.elf_fixture import write_elf


class ReplayCLITests(unittest.TestCase):
    """Exercise public replay commands without executing the synthetic ELF."""

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.project = Path(__file__).resolve().parents[1]
        self.template = self.root / "template"
        self.rootfs = self.template / "rootfs"
        (self.rootfs / "bin").mkdir(parents=True)
        (self.rootfs / "proc").mkdir()
        self.binary = write_elf(self.root / "sample", arch="x86_64")
        shutil.copyfile(self.binary, self.rootfs / "bin" / "unpacked.elf")
        (self.rootfs / "bin" / "unpacked.elf").chmod(0o755)
        config = self.template / "config"
        config.mkdir()
        (config / "runtime.json").write_text(
            json.dumps({
                "arch": "x86_64",
                "host_binary": str(self.binary),
                "guest_binary": "/bin/unpacked.elf",
                "qemu_required": False,
                "rootfs": str(self.rootfs),
            }),
            encoding="utf-8",
        )
        self.policy = config / "network_policy.json"
        self.policy.write_text(
            json.dumps({
                "mode": "replay",
                "allow_internet": False,
                "services": [{
                    "service_type": "tcp",
                    "role": "c2",
                    "remote_ip": "203.0.113.10",
                    "remote_port": 48101,
                    "domain": None,
                    "bind_ip": "127.0.0.1",
                    "bind_port": 0,
                    "protocol_hint": "c2_binary",
                }],
                "catch_all": {"enabled": False},
            }),
            encoding="utf-8",
        )
        self.store = ReplayStore(self.root / "replay-store")
        self.add_exchange(b"world")
        self.session = self.root / "session"

    def add_exchange(self, response: bytes, *, replace: bool = False) -> None:
        self.store.add(
            transport="tcp",
            remote_ip="203.0.113.10",
            remote_port=48101,
            request_bytes=b"hello",
            response_bytes=response,
            protocol_hint="c2_binary",
            replace=replace,
        )

    def cli(self, script: str, *args: str) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        env["PYTHONPATH"] = str(self.project)
        return subprocess.run(
            [sys.executable, str(self.project / "scripts" / script), *args],
            cwd=self.root,
            env=env,
            text=True,
            capture_output=True,
            timeout=15,
            check=False,
        )

    def initialize(self, *, include_store: bool = True) -> subprocess.CompletedProcess[str]:
        args = [
            "run", "--session-dir", str(self.session),
            "--template-run-dir", str(self.template),
            "--project-root", str(self.project),
            "--seed-rootfs", str(self.rootfs),
            "--snapshot-store", str(self.root / "snapshots"),
            "--network", "replay", "--initialize-only",
        ]
        if include_store:
            args.extend(["--replay-store", str(self.store.root)])
        return self.cli("run_synthesis_loop.py", *args)

    def assert_success(self, result: subprocess.CompletedProcess[str]) -> None:
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_initialize_resume_verify_and_prebuilt_validate(self) -> None:
        self.assert_success(self.initialize())
        binding = json.loads((self.session / "synthesis_loop.json").read_text())
        self.assertEqual(binding["network_mode"], "replay")
        self.assertEqual(binding["replay_store_sha256"], self.store.validate()["store_sha256"])
        self.assert_success(self.initialize(include_store=False))
        verified = self.cli("run_synthesis_loop.py", "verify", "--session-dir", str(self.session))
        self.assert_success(verified)
        self.assertTrue(json.loads(verified.stdout)["binding_verified"])

        IterationController(self.session).prepare_next()
        validated = self.cli(
            "run_prebuilt_iteration.py", "validate",
            "--session-dir", str(self.session), "--iteration", "0",
            "--template-run-dir", str(self.template),
            "--project-root", str(self.project),
            "--network", "replay", "--replay-store", str(self.store.root),
        )
        self.assert_success(validated)
        self.assertIn("Prepared iteration is valid", validated.stdout)
        self.assertFalse((self.session / "iterations/0000/execution_attempt.json").exists())

    def test_store_drift_is_reported_by_verify_and_resume(self) -> None:
        self.assert_success(self.initialize())
        self.add_exchange(b"changed", replace=True)
        verified = self.cli("run_synthesis_loop.py", "verify", "--session-dir", str(self.session))
        self.assertEqual(verified.returncode, 2, verified.stdout + verified.stderr)
        self.assertIn("modified", verified.stdout)
        resumed = self.initialize(include_store=False)
        self.assertEqual(resumed.returncode, 2, resumed.stdout + resumed.stderr)
        self.assertIn("configuration drift", resumed.stdout)
        self.assertNotIn("Traceback", verified.stderr + resumed.stderr)

    def test_replay_entrypoint_rejects_wrong_store_digest(self) -> None:
        result = self.cli(
            "start_network_replay.py",
            "--policy", str(self.policy),
            "--store", str(self.store.root),
            "--expected-store-sha256", "0" * 64,
            "--log-dir", str(self.root / "logs"),
        )
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("digest does not match", result.stdout)
        self.assertNotIn("Traceback", result.stderr)


if __name__ == "__main__":
    unittest.main()
