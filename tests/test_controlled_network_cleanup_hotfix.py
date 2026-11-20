from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from taintforge_env.controlled_network_backend import (
    ControlledNetworkBackend,
    ControlledNetworkConfig,
    ControlledNetworkError,
    ControlledNetworkPlan,
)


class FakeResult:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class SequencedExecutor:
    def __init__(self, results):
        self.results = list(results)
        self.commands = []

    def run(self, command, *, cwd, check=True, stdout_path=None, stderr_path=None):
        self.commands.append([str(value) for value in command])
        return self.results.pop(0)


class ControlledNetworkCleanupHotfixTests(unittest.TestCase):
    def make_backend(self, root, executor):
        project = root / "project"
        run_dir = root / "run"
        config = run_dir / "config"
        logs = run_dir / "logs"
        project.mkdir()
        config.mkdir(parents=True)
        logs.mkdir()
        policy = config / "policy.json"
        policy.write_text("{}\n", encoding="utf-8")
        backend = ControlledNetworkBackend(
            ControlledNetworkConfig(
                project_root=project,
                run_dir=run_dir,
                template_policy_path=policy,
                session_id="cleanup-test",
                iteration_index=0,
            ),
            executor=executor,
        )
        backend._topology_owned = {"veth": True, "namespace": True}
        return backend

    @staticmethod
    def plan():
        return ControlledNetworkPlan(
            namespace_name="tf-test",
            veth_host="tfh-test",
            veth_namespace="tfn-test",
            host_ip="10.203.1.1",
            namespace_ip="10.203.1.2",
            host_cidr="10.203.1.1/24",
            namespace_cidr="10.203.1.2/24",
            catch_all_enabled=True,
            catch_all_tcp_port=40000,
            catch_all_udp_port=40001,
        )

    def test_already_absent_veth_is_idempotent(self):
        executor = SequencedExecutor([
            FakeResult(1, stderr='Cannot find device "tfh-test"\n'),
            FakeResult(0),
        ])
        with tempfile.TemporaryDirectory() as tmp:
            backend = self.make_backend(Path(tmp), executor)
            backend._cleanup_topology(self.plan(), ignore_errors=False)
        self.assertEqual(executor.commands[0][2:5], ["ip", "link", "del"])
        self.assertEqual(executor.commands[1][2:5], ["ip", "netns", "del"])

    def test_absent_namespace_is_idempotent(self):
        executor = SequencedExecutor([
            FakeResult(0),
            FakeResult(1, stderr='Cannot remove namespace file "/var/run/netns/tf-test": No such file or directory\n'),
        ])
        with tempfile.TemporaryDirectory() as tmp:
            backend = self.make_backend(Path(tmp), executor)
            backend._cleanup_topology(self.plan(), ignore_errors=False)

    def test_real_cleanup_failure_remains_fatal(self):
        executor = SequencedExecutor([
            FakeResult(1, stderr="RTNETLINK answers: Operation not permitted\n"),
            FakeResult(0),
        ])
        with tempfile.TemporaryDirectory() as tmp:
            backend = self.make_backend(Path(tmp), executor)
            with self.assertRaisesRegex(ControlledNetworkError, "Operation not permitted"):
                backend._cleanup_topology(self.plan(), ignore_errors=False)


if __name__ == "__main__":
    unittest.main()
