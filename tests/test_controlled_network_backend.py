from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from taintforge_env.controlled_network_backend import (
    CommandResultLike,
    ControlledNetworkBackend,
    ControlledNetworkConfig,
    ControlledNetworkError,
)
from taintforge_env.replay_store import ReplayStore


class FakeResult:
    def __init__(self, returncode: int = 0, stdout: str = "", stderr: str = ""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class FakeExecutor:
    def __init__(self) -> None:
        self.commands: list[list[str]] = []

    def run(
        self,
        command,
        *,
        cwd: Path,
        check: bool = True,
        stdout_path: Path | None = None,
        stderr_path: Path | None = None,
    ) -> FakeResult:
        cmd = [str(value) for value in command]
        self.commands.append(cmd)
        if stdout_path is not None:
            stdout_path.parent.mkdir(parents=True, exist_ok=True)
            stdout_path.write_text('{"results": []}\n', encoding="utf-8")
        if stderr_path is not None:
            stderr_path.parent.mkdir(parents=True, exist_ok=True)
            stderr_path.write_text("", encoding="utf-8")
        return FakeResult(0)


class FakeProcess:
    def __init__(self, command, *, exit_code: int | None = None) -> None:
        self.command = [str(value) for value in command]
        self.exit_code = exit_code
        self.terminated = False
        self.killed = False

    def poll(self):
        if self.terminated or self.killed:
            return 0
        return self.exit_code

    def terminate(self):
        self.terminated = True

    def kill(self):
        self.killed = True

    def wait(self, timeout=None):
        return 0 if self.exit_code is None else self.exit_code


class FakeSupervisor:
    def __init__(self, *, immediate_exit: bool = False) -> None:
        self.immediate_exit = immediate_exit
        self.started: list[FakeProcess] = []

    def start(
        self,
        command,
        *,
        cwd: Path,
        stdout_path: Path,
        stderr_path: Path,
    ) -> FakeProcess:
        stdout_path.parent.mkdir(parents=True, exist_ok=True)
        stdout_path.write_text("started\n", encoding="utf-8")
        stderr_path.write_text("", encoding="utf-8")
        process = FakeProcess(
            command,
            exit_code=1 if self.immediate_exit else None,
        )
        self.started.append(process)
        return process


class FakePortAllocator:
    def __init__(self, values: list[int] | None = None) -> None:
        self.values = list(values or [25080, 25081, 25082])
        self.calls: list[tuple[str, int]] = []

    def allocate(self, host: str, preferred_start: int) -> int:
        self.calls.append((host, preferred_start))
        return self.values.pop(0)


class ControlledNetworkBackendTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.project = self.root / "project"
        self.run_dir = self.root / "run"
        (self.project / "scripts").mkdir(parents=True)
        for name in (
            "start_network_emulator.py",
            "start_network_replay.py",
            "start_transparent_logger.py",
        ):
            (self.project / "scripts" / name).write_text(
                "# placeholder\n", encoding="utf-8"
            )
        (self.run_dir / "config").mkdir(parents=True)
        (self.run_dir / "logs").mkdir()
        self.policy = self.run_dir / "config" / "template_policy.json"
        write_json(
            self.policy,
            {
                "mode": "local_test",
                "allow_internet": False,
                "services": [
                    {
                        "service_type": "tcp",
                        "role": "http",
                        "remote_ip": "203.0.113.10",
                        "remote_port": 80,
                        "bind_ip": "10.10.0.1",
                        "bind_port": 80,
                        "protocol_hint": "text",
                    },
                    {
                        "service_type": "tcp",
                        "role": "loopback-http",
                        "remote_ip": "127.0.0.1",
                        "remote_port": 80,
                        "bind_ip": "10.10.0.1",
                        "bind_port": 80,
                        "protocol_hint": "text",
                    },
                    {
                        "service_type": "udp",
                        "role": "dns",
                        "remote_ip": "8.8.8.8",
                        "remote_port": 53,
                    },
                ],
                "catch_all": {
                    "enabled": True,
                    "tcp_bind_port": 40000,
                    "udp_bind_port": 40001,
                },
            },
        )
        self.executor = FakeExecutor()
        self.supervisor = FakeSupervisor()
        self.allocator = FakePortAllocator()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def make_backend(
        self,
        *,
        self_test: bool = False,
        supervisor=None,
        responder_mode: str = "emulated",
        replay_store_path: Path | None = None,
        replay_store_expected_sha256: str | None = None,
    ):
        return ControlledNetworkBackend(
            ControlledNetworkConfig(
                project_root=self.project,
                run_dir=self.run_dir,
                template_policy_path=self.policy,
                session_id="session-test",
                iteration_index=2,
                self_test=self_test,
                responder_mode=responder_mode,
                replay_store_path=replay_store_path,
                replay_store_expected_sha256=(
                    replay_store_expected_sha256
                ),
                process_start_grace_seconds=0,
            ),
            executor=self.executor,
            process_supervisor=supervisor or self.supervisor,
            port_allocator=self.allocator,
        )

    @patch("taintforge_env.controlled_network_backend.shutil.which", return_value="/bin/tool")
    def test_plan_separates_host_and_loopback_services(self, _which) -> None:
        backend = self.make_backend()
        result = backend.setup()
        self.assertEqual(len(result.plan.host_services), 1)
        self.assertEqual(len(result.plan.loopback_services), 1)
        host = result.plan.host_services[0]
        loopback = result.plan.loopback_services[0]
        self.assertEqual(host.remote_port, 80)
        self.assertEqual(host.bind_port, 25080)
        self.assertNotEqual(host.bind_port, host.remote_port)
        self.assertEqual(loopback.bind_ip, "127.0.0.1")
        self.assertEqual(loopback.bind_port, 80)
        self.assertEqual(len(result.plan.skipped_services), 1)
        backend.cleanup()

    @patch("taintforge_env.controlled_network_backend.shutil.which", return_value="/bin/tool")
    def test_firewall_preserves_remote_endpoint_and_uses_local_mapping(self, _which) -> None:
        backend = self.make_backend()
        result = backend.setup()
        commands = [" ".join(command) for command in self.executor.commands]
        dnat = next(item for item in commands if "--to-destination" in item)
        self.assertIn("-d 203.0.113.10 --dport 80", dnat)
        self.assertIn(f"{result.plan.host_ip}:25080", dnat)
        self.assertTrue(any("TF_TCP_CATCHALL" in item for item in commands))
        self.assertTrue(any("127.0.0.0/8 -j RETURN" in item for item in commands))
        backend.cleanup()

    @patch("taintforge_env.controlled_network_backend.shutil.which", return_value="/bin/tool")
    def test_service_processes_run_on_correct_side(self, _which) -> None:
        backend = self.make_backend()
        result = backend.setup()
        commands = [process.command for process in self.supervisor.started]
        host = next(command for command in commands if command[0].endswith("python") or command[0].endswith("python3"))
        self.assertIn(str(backend.host_policy_path), host)
        namespace = [
            command
            for command in commands
            if contains_subsequence(command, ["ip", "netns", "exec"])
        ]
        self.assertEqual(len(namespace), 2)
        self.assertTrue(
            any(
                str(backend.loopback_policy_path) in command
                for command in namespace
            )
        )
        self.assertTrue(
            any(
                any(
                    "start_transparent_logger.py" in item
                    for item in command
                )
                for command in namespace
            )
        )
        guest = backend.guest_command(self.run_dir / "sandbox.sh")
        self.assertTrue(
            contains_subsequence(guest, ["ip", "netns", "exec"])
        )
        self.assertIn(result.plan.namespace_name, guest)
        self.assertNotIn("--net", guest)
        backend.cleanup()

    @patch("taintforge_env.controlled_network_backend.shutil.which", return_value="/bin/tool")
    def test_cleanup_aggregates_events_and_payloads(self, _which) -> None:
        backend = self.make_backend()
        backend.setup()
        source = self.run_dir / "logs" / "network_host"
        source.mkdir(parents=True, exist_ok=True)
        (source / "payload.bin").write_bytes(b"hello")
        (source / "network_events.jsonl").write_text(
            json.dumps(
                {
                    "timestamp_utc": "2026-01-01T00:00:00+00:00",
                    "event": "tcp_data",
                    "payload_file": "payload.bin",
                }
            )
            + "\n",
            encoding="utf-8",
        )
        backend.cleanup()
        events = [
            json.loads(line)
            for line in backend.events_path.read_text().splitlines()
            if line.strip()
        ]
        self.assertEqual(events[0]["backend_source"], "host")
        payload = self.run_dir / "logs" / events[0]["payload_file"]
        self.assertEqual(payload.read_bytes(), b"hello")
        manifest = json.loads(backend.manifest_path.read_text())
        self.assertEqual(manifest["state"], "cleaned")
        self.assertFalse(manifest["allow_internet"])

    @patch("taintforge_env.controlled_network_backend.shutil.which", return_value="/bin/tool")
    def test_self_test_is_archived_and_services_restart_clean(self, _which) -> None:
        backend = self.make_backend(self_test=True)
        backend.setup()
        self.assertEqual(len(self.supervisor.started), 6)
        self.assertTrue((self.run_dir / "logs" / "network_self_test").is_dir())
        self.assertTrue(
            (self.run_dir / "logs" / "network_self_test_stdout.log").is_file()
        )
        backend.cleanup()

    @patch("taintforge_env.controlled_network_backend.shutil.which", return_value="/bin/tool")
    def test_background_service_early_exit_fails_closed(self, _which) -> None:
        backend = self.make_backend(supervisor=FakeSupervisor(immediate_exit=True))
        with self.assertRaisesRegex(ControlledNetworkError, "exited during startup"):
            backend.setup()
        manifest = json.loads(backend.manifest_path.read_text())
        self.assertEqual(manifest["state"], "failed")

    @patch("taintforge_env.controlled_network_backend.shutil.which", return_value="/bin/tool")
    def test_replay_mode_uses_exact_responder_and_disables_catch_all(
        self,
        _which,
    ) -> None:
        write_json(
            self.policy,
            {
                "mode": "replay",
                "allow_internet": False,
                "services": [
                    {
                        "service_type": "tcp",
                        "role": "http",
                        "remote_ip": "203.0.113.10",
                        "remote_port": 80,
                        "bind_ip": "10.10.0.1",
                        "bind_port": 80,
                        "protocol_hint": "text",
                    },
                    {
                        "service_type": "tcp",
                        "role": "loopback-http",
                        "remote_ip": "127.0.0.1",
                        "remote_port": 80,
                        "bind_ip": "127.0.0.1",
                        "bind_port": 80,
                        "protocol_hint": "text",
                    },
                ],
                "catch_all": {"enabled": True},
            },
        )
        store_path = self.root / "replay-store"
        store = ReplayStore(store_path)
        for remote_ip in ("203.0.113.10", "127.0.0.1"):
            store.add(
                transport="tcp",
                remote_ip=remote_ip,
                remote_port=80,
                request_bytes=b"GET / HTTP/1.0\r\n\r\n",
                response_bytes=b"HTTP/1.0 200 OK\r\n\r\n",
                protocol_hint="text",
            )
        digest = store.validate()["store_sha256"]

        backend = self.make_backend(
            responder_mode="replay",
            replay_store_path=store_path,
            replay_store_expected_sha256=digest,
        )
        result = backend.setup()
        self.assertFalse(result.plan.catch_all_enabled)
        commands = [process.command for process in self.supervisor.started]
        self.assertEqual(len(commands), 2)
        self.assertTrue(
            all("scripts/start_network_replay.py" in command for command in commands)
        )
        self.assertTrue(all("--store" in command for command in commands))
        self.assertFalse(
            any("start_transparent_logger.py" in command for command in commands)
        )
        manifest = json.loads(backend.manifest_path.read_text())
        self.assertEqual(manifest["responder_mode"], "replay")
        self.assertEqual(manifest["replay_store_sha256"], digest)
        backend.cleanup()

    @patch("taintforge_env.controlled_network_backend.shutil.which", return_value="/bin/tool")
    def test_replay_mode_refuses_incomplete_service_coverage(self, _which) -> None:
        write_json(
            self.policy,
            {
                "mode": "replay",
                "allow_internet": False,
                "services": [
                    {
                        "service_type": "tcp",
                        "role": "http",
                        "remote_ip": "203.0.113.10",
                        "remote_port": 80,
                        "protocol_hint": "text",
                    }
                ],
                "catch_all": {"enabled": False},
            },
        )
        store = ReplayStore(self.root / "empty-replay-store")
        store.initialize()
        digest = store.validate()["store_sha256"]
        backend = self.make_backend(
            responder_mode="replay",
            replay_store_path=store.root,
            replay_store_expected_sha256=digest,
        )

        with self.assertRaisesRegex(
            ControlledNetworkError,
            "does not cover every effective TCP service",
        ):
            backend.setup()

    def test_network_names_are_deterministic_and_interface_safe(self) -> None:
        from taintforge_env.controlled_network_backend import _derive_topology

        first = _derive_topology("session-test", 2)
        second = _derive_topology("session-test", 2)
        self.assertEqual(first, second)
        self.assertLessEqual(len(first.veth_host), 15)
        self.assertLessEqual(len(first.veth_namespace), 15)
        self.assertNotEqual(first.host_ip, first.namespace_ip)


def contains_subsequence(values, expected) -> bool:
    width = len(expected)
    return any(
        values[index:index + width] == expected
        for index in range(len(values) - width + 1)
    )


def write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    unittest.main()
