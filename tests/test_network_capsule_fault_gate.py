"""Regression for traffic arriving before the post-unmap observer handshake."""
from __future__ import annotations

import copy
from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from scripts import check_network_capsule_fault_gate as gate
from scripts import run_network_capsule_e2e as runner
from scripts.run_network_stability_e2e import AuditedFaultRunner
from taintforge_env.prebuilt_runner import PrebuiltRootfsRunner
from taintforge_env import network_process as process_module
from taintforge_env.network_runtime import NetworkRuntimeOwner, NetworkRuntimeError
from taintforge_env.unified_runtime import write_json
from tests import test_network_capsule_pipeline as pipeline_fixtures
from tests import test_input_retirement as input_fixtures


def read(path):
    return json.loads(path.read_text())


class FaultRunnerTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.context = SimpleNamespace(run_dir=self.root, attempt_contract=SimpleNamespace(
            attempt_id="fault-attempt", contract_sha256="a" * 64))
        self.seen, self.killed = threading.Event(), threading.Event()
        self.signals = []
        self.signal_timeouts = []
        def kill(*, timeout=None):
            self.signal_timeouts.append(timeout)
            self.signals.append("SIGKILL")
            self.seen.set()
            self.killed.set()
        self.process = SimpleNamespace(command=["responder", "network_policy_loopback.json"],
            poll=lambda: None, kill=kill, process=SimpleNamespace(pid=12345), proc_pid=12345)
        self.usage = {"received_bytes": 6, "sent_bytes_reserved": 6}
        self.backend = SimpleNamespace(processes=[self.process],
            runtime=SimpleNamespace(snapshot=lambda: {"budget_usage": dict(self.usage)}),
            plan=SimpleNamespace(namespace_name="tf-fault-fixture"))
        self.instance = runner.FaultRunner.__new__(runner.FaultRunner)
        self.identity = {"attempt_id": "fault-attempt", "attempt_contract_sha256": "a" * 64}

    def pending(self):
        return {"status": "pending", **self.identity, "observed_events": 11}

    def ready(self):
        return {"status": "ready", **self.identity, "observed_monotonic_ns": time.monotonic_ns(),
                "retirement": {"status": "verified", "phase1_retired": True}}

    def invoke(self, execute, probe):
        with patch.object(PrebuiltRootfsRunner, "_execute_guest", execute), \
             patch.object(type(self.instance), "_fault_probe", side_effect=probe, create=True):
            return self.instance._execute_guest(self.context, network_backend=self.backend)

    def test_network_exchange_waits_for_post_resume_gate(self):
        released = threading.Event()
        def probe(*args, **kwargs):
            if not released.is_set():
                self.seen.set()
                return self.pending()
            return self.ready()
        def execute(*args, **kwargs):
            self.assertTrue(self.seen.wait(3), "injector did not reach traffic/gate")
            self.assertEqual(self.signals, [], "responder was killed before the post-unmap handshake")
            released.set()
            self.assertTrue(self.killed.wait(3), "verified gate did not permit the owned fault")
            return 14
        self.assertEqual(self.invoke(execute, probe), 14)
        self.assertEqual(self.signals, ["SIGKILL"])
        self.assertEqual(self.signal_timeouts, [runner.FAULT_SIGNAL_TIMEOUT_SECONDS])
        receipt = read(self.root / "logs/net6_fault.json")
        self.assertEqual(receipt["status"], "injected")
        self.assertTrue(receipt["gate"]["retirement"]["phase1_retired"])
        self.assertGreaterEqual(receipt["injected_monotonic_ns"], receipt["gate"]["observed_monotonic_ns"])

    def test_delayed_owned_signal_helper_is_allowed_to_finish(self):
        owner = NetworkRuntimeOwner(self.root / 'control', self.root / 'process-logs', attempt_id='signal-delay')
        process = process_module.CapturedNetworkProcess(
            [sys.executable, '-c', 'import time; time.sleep(60)'], cwd=runner.PROJECT,
            stdout_path=self.root / 'process-logs/out', stderr_path=self.root / 'process-logs/err', runtime=owner)
        # Simulate sudo startup latency while signalling only this test's child.
        process.command = ['sudo', 'responder', 'network_policy_loopback.json']
        self.backend.processes = [process]
        real_run = subprocess.run
        observed = []
        helper = 'import os,signal,sys,time; time.sleep(.35); os.killpg(int(sys.argv[1]), signal.SIGKILL)'

        def delayed_signal(command, **kwargs):
            self.assertEqual(command[-1], '-' + str(process.process.pid))
            self.assertEqual(command[:2], ['sudo', '-n'])
            self.assertEqual(command[-3:-1], ['9', '--'])
            observed.append(kwargs['timeout'])
            return real_run([sys.executable, '-c', helper, str(process.process.pid)], **kwargs)

        def execute(*args, **kwargs):
            deadline = time.monotonic() + 3
            while process.poll() is None and not (self.root / 'logs/net6_fault.json').exists():
                self.assertLess(time.monotonic(), deadline)
                time.sleep(.01)
            return 14

        try:
            with patch.object(process_module.subprocess, 'run', side_effect=delayed_signal):
                self.assertEqual(self.invoke(execute, lambda *a, **k: self.ready()), 14)
            self.assertEqual(observed, [2.0])
            self.assertIsNotNone(process.poll())
            self.assertEqual(read(self.root / 'logs/net6_fault.json')['status'], 'injected')
        finally:
            try:
                os.killpg(process.process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=3)
            owner.close()

    def test_signal_is_not_sent_after_the_injection_deadline(self):
        clock = iter((0, 0, 46))

        def now():
            value = next(clock)
            if value == 46:
                self.seen.set()
            return value

        def execute(*args, **kwargs):
            self.assertTrue(self.seen.wait(3))
            return 14

        with patch.object(runner, 'time', SimpleNamespace(monotonic=now)), \
             self.assertRaisesRegex(RuntimeError, 'fault signal deadline expired'):
            self.invoke(execute, lambda *a, **k: self.ready())
        self.assertEqual(self.signals, [])
        self.assertEqual(read(self.root / 'logs/net6_fault.json')['status'], 'failed')

    def test_missing_capsule_result_keeps_the_original_attempt_failure(self):
        run = self.root / 'run'
        write_json(run / 'config/capsule_binding.json', {})
        error = 'TimeoutExpired: owned SIGKILL helper timed out after 0.2 seconds'
        write_json(self.root / 'execution_attempt.json', {'stage': 'failed', 'error': error})
        with patch.object(runner, 'verify_runtime', return_value={}), \
             self.assertRaisesRegex(RuntimeError, 'original attempt failure: TimeoutExpired') as caught:
            runner.validate_attempt(run, expected_reason='network_responder_exited', goal=False)
        self.assertIn(error, str(caught.exception))
        self.assertFalse((run / 'config/capsule_result.json').exists())

    def test_missing_capsule_and_claim_remain_a_failure_without_inventing_a_cause(self):
        run = self.root / 'run'
        write_json(run / 'config/capsule_binding.json', {})
        with patch.object(runner, 'verify_runtime', return_value={}), \
             self.assertRaisesRegex(RuntimeError, 'capsule_result.json was not produced'):
            runner.validate_attempt(run, expected_reason='network_responder_exited', goal=False)
        self.assertFalse((run / 'config/capsule_result.json').exists())

    def test_both_traffic_counters_are_required_before_probing(self):
        for field in self.usage:
            with self.subTest(field=field):
                self.usage = {"received_bytes": 6, "sent_bytes_reserved": 6, field: 5}
                self.seen.clear()
                def snapshot():
                    self.seen.set()
                    return {"budget_usage": dict(self.usage)}
                self.backend.runtime.snapshot = snapshot
                def execute(*args, **kwargs):
                    self.assertTrue(self.seen.wait(3))
                    return 14
                with self.assertRaisesRegex(RuntimeError, "injection was not completed"):
                    self.invoke(execute, lambda *a, **k: self.fail("probed before real exchange"))
                self.assertEqual(self.signals, [])

    def test_verifier_error_is_preserved_and_never_injects(self):
        def probe(*args, **kwargs):
            self.seen.set()
            raise RuntimeError("saved unmap hash differs")
        def execute(*args, **kwargs):
            self.assertTrue(self.seen.wait(3))
            return 14
        with self.assertRaisesRegex(RuntimeError, "saved unmap hash differs"):
            self.invoke(execute, probe)
        self.assertEqual(self.signals, [])
        self.assertEqual(read(self.root / "logs/net6_fault.json")["status"], "failed")

    def test_cancellation_during_probe_never_sends_a_late_signal(self):
        stop = threading.Event()
        shim = SimpleNamespace(Event=lambda: stop, Lock=threading.Lock, Thread=threading.Thread)
        def probe(*args, **kwargs):
            self.seen.set()
            self.assertTrue(stop.wait(3), "guest return did not cancel injection")
            return self.ready()
        def execute(*args, **kwargs):
            self.assertTrue(self.seen.wait(3))
            return 14
        with patch.object(runner, "threading", shim), \
             self.assertRaisesRegex(RuntimeError, "injection was not completed"):
            self.invoke(execute, probe)
        self.assertEqual(self.signals, [])
        self.assertEqual(read(self.root / "logs/net6_fault.json")["status"], "cancelled")

    def test_timeout_is_bounded_and_retains_pending_gate(self):
        calls = iter((0, 40))
        def clock():
            value = next(calls)
            if value: self.seen.set()
            return value
        def execute(*args, **kwargs):
            self.assertTrue(self.seen.wait(3))
            return 14
        with patch.object(runner, "time", SimpleNamespace(monotonic=clock)), \
             self.assertRaisesRegex(RuntimeError, "did not reach verified post-unmap resume"):
            self.invoke(execute, lambda *a, **k: self.fail("deadline expired before probe"))
        self.assertEqual(self.signals, [])
        self.assertEqual(read(self.root / "logs/net6_fault.json")["gate"]["status"], "pending")

    def test_ambiguous_or_dead_owned_responder_is_not_signalled(self):
        for ambiguous in (True, False):
            with self.subTest(ambiguous=ambiguous):
                self.seen.clear()
                self.backend.processes = [self.process, self.process] if ambiguous else [self.process]
                self.process.poll = (lambda: None) if ambiguous else (lambda: 1)
                def probe(*args, **kwargs):
                    self.seen.set()
                    return self.ready()
                def execute(*args, **kwargs):
                    self.assertTrue(self.seen.wait(3))
                    return 14
                with self.assertRaises(RuntimeError): self.invoke(execute, probe)
                self.assertEqual(self.signals, [])

    def test_probe_uses_bounded_noninteractive_privilege_without_a_shell(self):
        value = self.ready()
        result = subprocess.CompletedProcess([], 0, json.dumps(value), "")
        with patch.object(runner.subprocess, "run", return_value=result) as command:
            self.assertEqual(self.instance._fault_probe(self.context, timeout=6), value)
        args, kwargs = command.call_args
        self.assertEqual(args[0][:5], ["sudo", "-n", "timeout", "--kill-after=1s", "4s"])
        self.assertIn(str(self.root), args[0])
        self.assertIn(self.context.attempt_contract.contract_sha256, args[0])
        self.assertEqual(kwargs["timeout"], 6)
        self.assertEqual(kwargs["stdin"], subprocess.DEVNULL)
        self.assertNotIn("shell", kwargs)

    def test_probe_rejects_bad_exit_foreign_result_and_malformed_output(self):
        for code, value in ((124, ""), (1, "denied"), (0, "[]"), (0, "{"),
                (0, json.dumps({**self.ready(), "attempt_id": "foreign"})),
                (0, json.dumps({**self.ready(), "status": "failed"}))):
            result = subprocess.CompletedProcess([], code, value, "")
            with self.subTest(code=code, value=value), patch.object(runner.subprocess, "run", return_value=result), \
                 self.assertRaises((ValueError, RuntimeError)):
                self.instance._fault_probe(self.context, timeout=6)

    def test_stability_reuses_the_same_fault_injector(self):
        self.assertIn(runner.FaultRunner, AuditedFaultRunner.__mro__)
        self.assertIs(AuditedFaultRunner._fault_probe, runner.FaultRunner._fault_probe)


class OwnedSignalTimeoutTests(unittest.TestCase):
    def setUp(self):
        self.process = process_module.CapturedNetworkProcess.__new__(process_module.CapturedNetworkProcess)
        self.process.command = ['sudo', '-n', 'owned-responder']
        self.process.process = SimpleNamespace(pid=12345)
        self.process.proc_pid, self.process.birth = 12345, '42'
        self.process.runtime = SimpleNamespace(limits=SimpleNamespace(shutdown_timeout_ms=5000))
        self.enterContext(patch.object(process_module, 'process_start', return_value='42'))
        self.enterContext(patch.object(self.process, '_group_alive', return_value=True))
        self.enterContext(patch.object(process_module.shutil, 'which', return_value='/usr/bin/kill'))
        self.command = self.enterContext(patch.object(process_module.subprocess, 'run',
            return_value=subprocess.CompletedProcess([], 0)))
        self.killpg = self.enterContext(patch.object(process_module.os, 'killpg'))

    def test_default_cleanup_signal_deadline_is_preserved(self):
        self.process.terminate()
        self.assertEqual(self.command.call_args.kwargs['timeout'], .2)
        self.assertEqual(self.command.call_args.args[0],
            ['sudo', '-n', '/usr/bin/kill', '-s', '15', '--', '-12345'])

    def test_explicit_fault_deadline_is_bounded_by_the_runtime_shutdown_limit(self):
        for limit, expected in ((5000, 2.0), (500, .5)):
            with self.subTest(limit=limit):
                self.process.runtime.limits.shutdown_timeout_ms = limit
                self.process.kill(timeout=2)
                self.assertEqual(self.command.call_args.kwargs['timeout'], expected)
                self.assertEqual(self.command.call_args.args[0],
                    ['sudo', '-n', '/usr/bin/kill', '-s', '9', '--', '-12345'])

    def test_invalid_signal_deadlines_never_start_a_helper(self):
        for value in (True, False, 0, -1, 31, 10**400, '2', float('nan'), float('inf')):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.process.kill(timeout=value)
        self.command.assert_not_called()
        self.killpg.assert_not_called()

    def test_changed_process_identity_is_rejected_before_any_signal(self):
        with patch.object(process_module, 'process_start', return_value='43'), \
             self.assertRaisesRegex(NetworkRuntimeError, 'identity changed'):
            self.process.kill(timeout=2)
        self.command.assert_not_called()
        self.killpg.assert_not_called()

    def test_signal_helper_timeout_is_not_recorded_as_success(self):
        self.command.side_effect = subprocess.TimeoutExpired('owned signal helper', 2)
        with self.assertRaises(subprocess.TimeoutExpired):
            self.process.kill(timeout=2)
        self.killpg.assert_not_called()

    def test_rejected_privileged_signal_to_a_live_group_is_a_failure(self):
        self.command.return_value = subprocess.CompletedProcess([], 1)
        with self.assertRaisesRegex(NetworkRuntimeError, 'did not accept its signal'):
            self.process.kill(timeout=2)
        self.killpg.assert_not_called()


class FaultGateEvidenceTests(unittest.TestCase):
    # Reuse the existing synthetic artifact generator, with real verifiers.
    setUp = pipeline_fixtures.NetworkCapsulePipelineTests.setUp
    prepare_input = pipeline_fixtures.NetworkCapsulePipelineTests.prepare_input
    prepare_network = pipeline_fixtures.NetworkCapsulePipelineTests.prepare_network
    prepare_hardened_network = pipeline_fixtures.NetworkCapsulePipelineTests.prepare_hardened_network
    invoke_network = pipeline_fixtures.NetworkCapsulePipelineTests.invoke_network

    def evidence(self, *, hardened=False):
        out, launch = self.prepare_hardened_network() if hardened else self.prepare_network()
        executor = pipeline_fixtures.NetworkExecutor()
        if hardened:
            from tests.test_capsule_hardening_integration import hardened_evidence
            with patch.object(input_fixtures, "synthetic_evidence", side_effect=hardened_evidence):
                report, code = self.invoke_network(out, launch, executor)
        else:
            report, code = self.invoke_network(out, launch, executor)
        self.assertEqual(code, 0, report.get("error"))
        run, binding, _ = executor.runs[0]
        path = run / "logs/capsule/observer-events.json"
        journal = read(path)
        self.assertEqual(journal["events"][-1]["event"], "done")
        journal["events"].pop()
        write_json(path, journal)
        self.run_dir, self.binding, self.journal = run, binding, journal
        return path

    def probe(self, **kwargs):
        return gate.probe(self.run_dir, kwargs.get("attempt_id", self.binding["attempt_id"]),
                          kwargs.get("contract_sha256", self.binding["attempt_contract_sha256"]))

    def test_all_partial_prefixes_wait_including_observed_eleven_event_failure(self):
        path = self.evidence()
        self.assertEqual(self.journal["events"][10]["event"], "released")
        for length in range(20):
            with self.subTest(length=length):
                write_json(path, {**self.journal, "events": self.journal["events"][:length]})
                with patch.object(gate, "interrupted_retirement", side_effect=AssertionError("too early")):
                    result = self.probe()
                self.assertEqual(result["status"], "pending")
                self.assertEqual(result["observed_events"], length)
        write_json(path, self.journal)
        self.assertEqual(self.probe()["status"], "ready")

    def test_complete_hardened_prefix_uses_the_existing_full_verifier(self):
        self.evidence(hardened=True)
        result = self.probe()
        self.assertEqual(result["status"], "ready")
        self.assertEqual(result["retirement"]["status"], "verified")
        self.assertTrue(result["retirement"]["phase1_retired"])
        self.assertFalse(result["retirement"]["observer_completed"])
        self.assertTrue(result["retirement"]["hardening"]["phase1_output_fds_released"])
        self.assertFalse(result["retirement"]["claims"]["hostile_sample_ready"])

    def test_standalone_probe_is_read_only_with_private_evidence(self):
        self.evidence(hardened=True)
        paths = [p for p in self.run_dir.rglob("*") if p.is_file() and not p.is_symlink()]
        before = {p: p.read_bytes() for p in paths}
        journal = self.run_dir / "logs/capsule/observer-events.json"
        journal.chmod(0o600)
        result = subprocess.run(["timeout", "--kill-after=1s", "4s", "env",
            "PYTHONPATH=" + str(runner.PROJECT), sys.executable,
            str(runner.PROJECT / "scripts/check_network_capsule_fault_gate.py"),
            "--run", str(self.run_dir), "--attempt-id", self.binding["attempt_id"],
            "--contract-sha256", self.binding["attempt_contract_sha256"]],
            stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=6)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(json.loads(result.stdout)["status"], "ready")
        self.assertEqual({p: p.read_bytes() for p in paths}, before)
        self.assertEqual(journal.stat().st_mode & 0o777, 0o600)

    def test_missing_journal_waits_but_invalid_journal_fails(self):
        path = self.evidence()
        path.unlink()
        self.assertEqual(self.probe()["observed_events"], 0)
        for value in ("{", "[]", '{"schema":2,"events":[0]}', '{"schema":1,"events":[]}'):
            with self.subTest(value=value):
                path.write_text(value)
                with self.assertRaises((ValueError, RuntimeError)): self.probe()

    def test_other_attempt_contract_and_mapping_are_rejected(self):
        self.evidence()
        for kwargs in ({"attempt_id": "foreign"}, {"contract_sha256": "0" * 64}):
            with self.subTest(kwargs=kwargs), self.assertRaisesRegex(RuntimeError, "another attempt"):
                self.probe(**kwargs)
        path = self.run_dir / "logs/capsule/phase1-retirement/mapping-identity.json"
        mapping = read(path); mapping["nonce"] = "0" * 32; write_json(path, mapping)
        with self.assertRaisesRegex(RuntimeError, "mapping identity"): self.probe()

    def test_removed_unmap_bad_resume_and_terminal_events_cannot_unlock_fault(self):
        path = self.evidence()
        for damage in ("unmap", "resume", "done", "early_exit"):
            with self.subTest(damage=damage):
                journal = copy.deepcopy(self.journal)
                if damage == "unmap": journal["events"].pop(11)
                elif damage == "resume": journal["events"][18]["seq"] += 1
                else: journal["events"].append({"event": damage})
                write_json(path, journal)
                with self.assertRaises(RuntimeError): self.probe()

    def test_tampered_unmap_file_is_not_accepted_by_the_live_gate(self):
        self.evidence()
        path = self.run_dir / "logs/capsule/phase1-retirement/maps-unmapped.txt"
        path.write_text(path.read_text() + "\n")
        with self.assertRaisesRegex(RuntimeError, "unmap observation changed"): self.probe()

    def test_journal_change_during_verification_is_not_accepted(self):
        path = self.evidence()
        original = gate.interrupted_retirement
        def changing(*args, **kwargs):
            result = original(*args, **kwargs)
            path.write_text(path.read_text() + "\n")
            return result
        with patch.object(gate, "interrupted_retirement", side_effect=changing), \
             self.assertRaisesRegex(RuntimeError, "journal changed"):
            self.probe()

    def test_cli_reports_gate_failure_as_nonzero_json(self):
        self.evidence()
        output = io.StringIO()
        with patch("sys.argv", ["gate", "--run", str(self.run_dir), "--attempt-id", "foreign",
                                "--contract-sha256", self.binding["attempt_contract_sha256"]]), redirect_stdout(output):
            self.assertEqual(gate.main(), 1)
        result = json.loads(output.getvalue())
        self.assertEqual(result["status"], "failed")
        self.assertIn("another attempt", result["error"])


if __name__ == "__main__":
    unittest.main()
