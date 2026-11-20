from __future__ import annotations

import asyncio
import gc
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from taintforge_env.controlled_network_backend import ControlledNetworkBackend, ControlledNetworkConfig, ControlledNetworkError
from taintforge_env.network_aggregation import aggregate_network_events
from taintforge_env.network_process import CapturedNetworkProcess
from taintforge_env.network_runtime import (NetworkRuntimeOwner, NetworkRuntimeClient, NetworkRuntimeLimits,
                                           NetworkRuntimeError, _CURRENT, network_write, proc_self, process_start)
from taintforge_env.network_runtime_transport import start_server
from tests.test_controlled_network_backend import FakeExecutor, FakeProcess, FakeSupervisor, FakePortAllocator


PROJECT = Path(__file__).resolve().parents[1]


class NetworkLifecycleTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.logs = self.root / "logs"
        self.logs.mkdir()
        self.owners, self.processes = [], []

    def tearDown(self):
        for process in self.processes:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=3)
        for owner in self.owners:
            owner.close()

    def owner(self, **limits):
        owner = NetworkRuntimeOwner(self.root / f"control-{len(self.owners)}", self.logs,
            attempt_id="lifecycle", limits=NetworkRuntimeLimits.parse(limits))
        self.owners.append(owner)
        return owner

    def backend(self):
        run = self.root / "run"
        (run / "config").mkdir(parents=True, exist_ok=True)
        (run / "logs").mkdir(exist_ok=True)
        policy = run / "config/policy.json"
        policy.write_text('{"services":[],"catch_all":{"enabled":false}}')
        return ControlledNetworkBackend(ControlledNetworkConfig(PROJECT, run, policy, "lifecycle", 0,
            process_start_grace_seconds=0), executor=FakeExecutor(), process_supervisor=FakeSupervisor(),
            port_allocator=FakePortAllocator())

    def test_payload_alias_is_created_once_for_many_events(self):
        source = self.logs / "network_host"
        source.mkdir()
        payload = source / "payload.bin"
        payload.write_bytes(b"hello")
        events = [{"event": "tcp_data", "timestamp_utc": str(i), "payload_file": "payload.bin"} for i in range(10)]
        (source / "network_events.jsonl").write_text("".join(json.dumps(event) + "\n" for event in events))
        result = aggregate_network_events(self.logs)
        paths = list((self.logs / "network_payloads").iterdir())
        self.assertEqual(len(paths), 1)
        self.assertTrue(os.path.samefile(payload, paths[0]))
        self.assertEqual(result["unique_payloads"], 1)
        references = {json.loads(line)["payload_file"] for line in (self.logs / "network_events.jsonl").read_text().splitlines()}
        self.assertEqual(len(references), 1)
        self.assertEqual(aggregate_network_events(self.logs)["unique_payloads"], 1)

    def test_sigkill_reclaims_real_responder_leases_with_procfs_pid_identity(self):
        owner = self.owner()
        self.assertIsNotNone(process_start(proc_self()))
        ready = self.root / "ready"
        code = """import sys,time
from pathlib import Path
from taintforge_env.network_runtime import NetworkRuntimeClient
c=NetworkRuntimeClient(sys.argv[1]); c.call('listen'); c.call('slot',kind='tcp')
Path(sys.argv[2]).write_text('ready'); time.sleep(60)
"""
        process = subprocess.Popen([sys.executable, "-c", code, str(owner.client_path), str(ready)],
                                   cwd=PROJECT, env={**os.environ, "PYTHONPATH": str(PROJECT)})
        self.processes.append(process)
        deadline = time.monotonic() + 3
        while not ready.exists():
            self.assertLess(time.monotonic(), deadline)
            time.sleep(0.01)
        self.assertEqual(owner.snapshot()["ready_listeners"], 1)
        self.assertEqual(owner.snapshot()["budget_usage"]["active_jobs"], 1)
        process.kill()
        process.wait(timeout=2)
        status = owner.close()
        self.assertEqual(status["cleanup_status"], "cleaned")
        self.assertEqual(status["ready_listeners"], 0)
        self.assertEqual(status["budget_usage"]["active_jobs"], 0)

    def test_standalone_stdout_and_setup_failure_leave_no_owner_thread(self):
        from taintforge_env.network_runtime import run_network_service
        async def noisy():
            print("x" * 5000)
        with self.assertRaises(NetworkRuntimeError):
            asyncio.run(run_network_service(noisy, log_dir=self.logs,
                        limits=NetworkRuntimeLimits.parse({"max_log_bytes": 4096})))
        status = json.loads((self.logs / "network_runtime_status.json").read_text())
        self.assertEqual(status["termination_reason"], "network_log_budget_exceeded")
        self.assertEqual(status["cleanup_status"], "cleaned")
        self.assertLess(sum(p.stat().st_size for p in self.logs.iterdir() if p.is_file()), 4096)
        with self.assertRaisesRegex(ValueError, "fresh empty"):
            asyncio.run(run_network_service(noisy, log_dir=self.logs))
        empty = self.root / "setup-failed"
        with self.assertRaises(NetworkRuntimeError):
            asyncio.run(run_network_service(noisy, log_dir=empty,
                        limits=NetworkRuntimeLimits.parse({"max_log_files": 1})))
        self.assertFalse(any(p.name.startswith('.runtime-') for p in empty.iterdir()))

    def test_exited_leader_does_not_hide_a_live_owned_process_group(self):
        owner = self.owner(shutdown_timeout_ms=500)
        ready = self.root / "descendant-ready"
        child = ("import os,signal,sys,time; from pathlib import Path; "
                 "signal.signal(signal.SIGTERM,signal.SIG_IGN); "
                 "os.close(1); os.close(2); Path(sys.argv[1]).write_text('ready'); time.sleep(60)")
        code = ("import subprocess,sys,time; from pathlib import Path; "
                "subprocess.Popen([sys.executable,'-c',sys.argv[1],sys.argv[2]]); "
                "p=Path(sys.argv[2]); exec('while not p.exists(): time.sleep(.005)')")
        process = CapturedNetworkProcess([sys.executable, "-c", code, child, str(ready)], cwd=PROJECT,
            stdout_path=self.logs / "parent.stdout", stderr_path=self.logs / "parent.stderr", runtime=owner)
        self.processes.append(process)
        deadline = time.monotonic() + 3
        while not ready.exists() or process.poll() is None:
            self.assertLess(time.monotonic(), deadline)
            time.sleep(0.01)
        with self.assertRaises(subprocess.TimeoutExpired):
            process.wait(timeout=0.02)
        backend = self.backend()
        backend.runtime, backend.processes = owner, [process]
        backend._stop_services()
        self.assertFalse(process._group_alive())
        self.assertEqual(backend.processes, [])

    def test_aggregation_sorts_unsorted_sources_without_an_event_list(self):
        for name, values in [("host", ["3", "1"]), ("loopback", ["4", "2"])]:
            source = self.logs / ("network_" + name)
            source.mkdir()
            (source / "network_events.jsonl").write_text("".join(json.dumps({"timestamp_utc": value, "event": "data"}) + "\n" for value in values))
        aggregate_network_events(self.logs)
        values = [json.loads(line)["timestamp_utc"] for line in (self.logs / "network_events.jsonl").read_text().splitlines()]
        self.assertEqual(values, ["1", "2", "3", "4"])

    def test_aggregation_rejects_payload_traversal_and_symlinks(self):
        source = self.logs / "network_host"
        source.mkdir()
        events = source / "network_events.jsonl"
        for name in ("../outside", "/tmp/outside"):
            events.write_text(json.dumps({"payload_file": name}) + "\n")
            with self.assertRaises(NetworkRuntimeError):
                aggregate_network_events(self.logs)
        (source / "payload").symlink_to(self.root / "outside")
        events.write_text(json.dumps({"payload_file": "payload"}) + "\n")
        with self.assertRaises(NetworkRuntimeError):
            aggregate_network_events(self.logs)

    def test_aggregation_rejects_oversized_line_before_json_decode(self):
        source = self.logs / "network_host"
        source.mkdir()
        (source / "network_events.jsonl").write_bytes(b"x" * 65537)
        with self.assertRaisesRegex(NetworkRuntimeError, "input budget"):
            aggregate_network_events(self.logs)

    def test_aggregation_consumes_the_finalization_budget(self):
        owner = self.owner(max_log_bytes=4096)
        source = self.logs / "network_host"
        source.mkdir()
        token = _CURRENT.set(owner.client())
        try:
            network_write(source / "network_events.jsonl", b'{"event":"data"}\n')
        finally:
            _CURRENT.reset(token)
        before = owner.snapshot()["budget_usage"]["log_bytes_reserved"]
        aggregate_network_events(self.logs, runtime=owner)
        self.assertGreater(owner.snapshot()["budget_usage"]["log_bytes_reserved"], before)

    def test_failed_cleanup_retains_process_for_retry(self):
        backend = self.backend()
        class RetryProcess(FakeProcess):
            fail = True
            def wait(self, timeout=None):
                if self.fail:
                    raise OSError("injected wait failure")
                return 0
        process = RetryProcess(["owned-responder"])
        backend.processes = [process]
        with self.assertRaises(ControlledNetworkError):
            backend.cleanup(finalize_logs=False)
        self.assertEqual(backend.processes, [process])
        self.assertFalse(backend._cleaned)
        process.fail = False
        backend.cleanup(finalize_logs=False)
        self.assertTrue(backend._cleaned)
        self.assertEqual(backend.processes, [])

    def test_unowned_topology_is_never_deleted(self):
        backend = self.backend()
        from tests.test_controlled_network_cleanup_hotfix import ControlledNetworkCleanupHotfixTests
        backend._cleanup_topology(ControlledNetworkCleanupHotfixTests.plan(), ignore_errors=False)
        self.assertEqual(backend.executor.commands, [])

    @patch("taintforge_env.controlled_network_backend.shutil.which", return_value="/usr/bin/tool")
    def test_namespace_creation_failure_does_not_delete_an_existing_namespace(self, _which):
        backend = self.backend()
        original = backend.executor.run
        def run(command, **kwargs):
            if list(command)[2:5] == ["ip", "netns", "add"]:
                backend.executor.commands.append(list(command))
                raise RuntimeError("namespace already exists")
            return original(command, **kwargs)
        backend.executor.run = run
        with self.assertRaises(ControlledNetworkError):
            backend.setup()
        self.assertFalse(any(command[2:5] in (["ip", "netns", "del"], ["ip", "link", "del"])
                             for command in backend.executor.commands))

    def test_global_shutdown_deadline_escalates_two_real_processes(self):
        owner = self.owner(shutdown_timeout_ms=500)
        backend = self.backend()
        backend.runtime = owner
        for index in range(2):
            ready = self.root / f"ready-{index}"
            code = "import signal,time;from pathlib import Path;signal.signal(signal.SIGTERM,signal.SIG_IGN);Path(" + repr(str(ready)) + ").write_text('ready');time.sleep(60)"
            process = CapturedNetworkProcess([sys.executable, "-c", code], cwd=PROJECT,
                stdout_path=self.logs / f"out-{index}", stderr_path=self.logs / f"err-{index}", runtime=owner)
            self.processes.append(process)
            deadline = time.monotonic() + 2
            while not ready.exists():
                self.assertLess(time.monotonic(), deadline)
                time.sleep(0.01)
        backend.processes = list(self.processes)
        started = time.monotonic()
        backend._stop_services()
        self.assertLess(time.monotonic() - started, 1)
        self.assertEqual(backend.processes, [])
        self.assertTrue(all(process.poll() is not None for process in self.processes))

    def test_responder_stdout_cannot_exceed_the_shared_log_budget(self):
        owner = self.owner(max_log_bytes=4096)
        process = CapturedNetworkProcess([sys.executable, "-c", "import sys,time;sys.stdout.write('x'*100000);sys.stdout.flush();time.sleep(60)"],
            cwd=PROJECT, stdout_path=self.logs / "out", stderr_path=self.logs / "err", runtime=owner)
        self.processes.append(process)
        deadline = time.monotonic() + 3
        while owner.snapshot()["termination_reason"] is None:
            self.assertLess(time.monotonic(), deadline)
            time.sleep(0.01)
        process.kill()
        process.wait(timeout=2)
        self.assertLessEqual(sum(path.stat().st_size for path in self.logs.iterdir()), owner.producer_limit)
        self.assertEqual(owner.snapshot()["termination_reason"], "network_log_budget_exceeded")

    def test_guard_stops_its_real_child_when_owner_is_lost(self):
        control = self.root / "external-control"
        owner_code = "from taintforge_env.network_runtime import NetworkRuntimeOwner,NetworkRuntimeLimits;import time;from pathlib import Path;o=NetworkRuntimeOwner(" + repr(str(control)) + "," + repr(str(self.logs)) + ",attempt_id='lost',limits=NetworkRuntimeLimits(shutdown_timeout_ms=500));time.sleep(60)"
        owner = subprocess.Popen([sys.executable, "-c", owner_code], cwd=PROJECT,
                                 env={**os.environ, "PYTHONPATH": str(PROJECT)})
        ready = self.root / "guest-ready"
        result = self.root / "guard.json"
        guard = None
        try:
            deadline = time.monotonic() + 3
            while not (control / "client.json").exists():
                self.assertLess(time.monotonic(), deadline)
                time.sleep(0.01)
            guest = "from pathlib import Path;import time;Path(" + repr(str(ready)) + ").write_text('ready');time.sleep(60)"
            guard = subprocess.Popen([sys.executable, str(PROJECT / "scripts/run_network_guard.py"),
                "--runtime", str(control / "client.json"), "--result", str(result), "--",
                sys.executable, "-c", guest], cwd=PROJECT, env={**os.environ, "PYTHONPATH": str(PROJECT)})
            while not ready.exists():
                self.assertLess(time.monotonic(), deadline)
                time.sleep(0.01)
            owner.kill()
            owner.wait(timeout=2)
            self.assertNotEqual(guard.wait(timeout=3), 0)
            value = json.loads(result.read_text())
            self.assertTrue(value["guest_process_stopped"])
            self.assertEqual(value["termination_reason"], "network_runtime_owner_lost")
        finally:
            if owner.poll() is None:
                owner.kill()
                owner.wait(timeout=2)
            if guard is not None and guard.poll() is None:
                guard.terminate()
                guard.wait(timeout=3)


class RepeatedNetworkAttemptsTests(unittest.IsolatedAsyncioTestCase):
    async def test_one_hundred_attempts_release_fds_tasks_listeners_and_threads(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            baseline = len(os.listdir("/proc/self/fd"))
            for index in range(100):
                owner = NetworkRuntimeOwner(root / f"control-{index}", root / f"logs-{index}", attempt_id=str(index))
                token = _CURRENT.set(owner.client())
                async def echo(reader, writer):
                    writer.write(await reader.read(4))
                    await writer.drain()
                listener = await start_server(echo, "127.0.0.1", 0)
                reader, writer = await asyncio.open_connection("127.0.0.1", listener.sockets[0].getsockname()[1])
                writer.write(b"ping")
                await writer.drain()
                self.assertEqual(await reader.read(), b"ping")
                writer.close()
                await writer.wait_closed()
                listener.close()
                await listener.wait_closed()
                _CURRENT.reset(token)
                status = owner.close()
                self.assertEqual(status["cleanup_status"], "cleaned")
                self.assertEqual(status["budget_usage"]["active_jobs"], 0)
                self.assertEqual(status["ready_listeners"], 0)
                self.assertFalse(owner.thread.is_alive())
            await asyncio.sleep(0)
            gc.collect()
            self.assertEqual(len(os.listdir("/proc/self/fd")), baseline)


if __name__ == "__main__":
    unittest.main()
