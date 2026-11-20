"""Hybrid v5.1: custom stage timing, native hooks, replay provenance, shared AFL flags.

All tests are local components, not real QEMU/afl-fuzz native acceptance.
"""
from __future__ import annotations

import ctypes
import json
import os
from pathlib import Path
import socket
import struct
import tempfile
import threading
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from experiments.hybrid_rebuilt_v1.controller import LiveRebuiltController, REQUEST, RESPONSE
from experiments.hybrid_rebuilt_v1.mutator_build import build_mutator
from experiments.hybrid_rebuilt_v1.telemetry import audit_hook_trace
from scripts import run_afl_rebuilt, run_hybrid_ablation
from taintforge_env import afl_rebuilt as backend


class StagePolicyTests(unittest.TestCase):
    def test_fast_stage_has_z_but_preserves_bridge_and_stock_command(self):
        root = Path('/tmp/taintforge-v51-commands')
        manifest = {'case_seconds': 5, 'bridge': '/tmp/taintforge-bridge'}
        kw = dict(afl=Path('/usr/bin/afl-fuzz'), root=root, manifest=manifest,
                  seconds=180, max_cases=512, afl_seed=42, peer_fd=11)
        fast = backend.build_afl_command(**kw, afl_stage_policy='fast')
        full = backend.build_afl_command(**kw, afl_stage_policy='full')
        self.assertEqual(fast[:fast.index('--')], full[:full.index('--')] + ['-z'])
        self.assertEqual(fast[-3:], ['--', '/tmp/taintforge-bridge', '11', '@@'][-3:])
        self.assertEqual(full[-4:], ['--', '/tmp/taintforge-bridge', '11', '@@'])
        self.assertIn('448', fast)
        self.assertNotIn('-z', full)
        self.assertIn('-z', fast[:fast.index('--')])
        with self.assertRaises(RuntimeError):
            backend.build_afl_command(**kw, afl_stage_policy='ignored')

    def test_auto_stage_policy_is_explicit_and_mode_specific(self):
        choose = run_afl_rebuilt.resolve_afl_stage_policy
        self.assertEqual(choose('hybrid-mixed', 'auto'), 'fast')
        self.assertEqual(choose('afl', 'auto'), 'full')
        self.assertEqual(choose('focus', 'auto'), 'full')
        self.assertEqual(choose('hybrid', 'auto'), 'full')
        self.assertEqual(choose('afl', 'fast'), 'fast')
        self.assertEqual(choose('hybrid-mixed', 'full'), 'full')
        with self.assertRaises(RuntimeError):
            choose('unknown', 'auto')

    def test_ablation_arguments_force_common_stage_policy(self):
        args = run_hybrid_ablation.arguments([
            '--binary', '/tmp/target', '--seeds', '/tmp/seeds',
            '--qemu', '/tmp/qemu', '--plugin', '/tmp/plugin',
            '--flags-receipt', '/tmp/receipt', '--out', '/tmp/ablation',
            '--replicates', '1', '--afl-stage-policy', 'fast',
            '--mixed-custom-fuzz-count', '8', '--plan-only'])
        self.assertEqual(args.afl_stage_policy, 'fast')
        self.assertEqual(args.mixed_custom_fuzz_count, 8)
        cli = run_afl_rebuilt.main
        self.assertTrue(callable(cli))


class CMutatorHooksTests(unittest.TestCase):
    def test_independent_native_C_hooks_count_stage_and_callbacks(self):
        with tempfile.TemporaryDirectory(prefix='tfh-v51-hooks-') as d:
            root = Path(d)
            sock = root / 'socket'
            listener = socket.socket(socket.AF_UNIX)
            listener.bind(str(sock))
            listener.listen(1)
            token = 'a' * 64
            trace = root / 'hooks.log'
            failures = []
            def recv_n(conn, n):
                content = bytearray()
                while len(content) < n:
                    part = conn.recv(n - len(content))
                    if not part:
                        raise EOFError('Unexpected client disconnect')
                    content.extend(part)
                return bytes(content)
            def serve():
                try:
                    conn, _ = listener.accept()
                    with conn:
                        self.assertEqual(recv_n(conn, 64).decode('ascii'), token)
                        for seq in range(1, 4):
                            magic, number, size = REQUEST.unpack(recv_n(conn, REQUEST.size))
                            self.assertEqual((magic, number, size), (b'TFH2', seq, 32))
                            parent = recv_n(conn, size)
                            self.assertEqual(parent, b'AA' + b'x' * 30)
                            updated = bytes([parent[0] ^ 1]) + parent[1:]
                            conn.sendall(RESPONSE.pack(b'TFH2', seq, 1, 4, len(updated)) +
                                         b'\x01\x00\x00\x00' + updated)
                except BaseException as exc:
                    failures.append(exc)
            worker = threading.Thread(target=serve, daemon=True)
            worker.start()
            library = ctypes.CDLL(str(build_mutator(root / 'mutator.so')))
            library.afl_custom_init.argtypes = [ctypes.c_void_p, ctypes.c_uint]
            library.afl_custom_init.restype = ctypes.c_void_p
            library.afl_custom_fuzz_count.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]
            library.afl_custom_fuzz_count.restype = ctypes.c_uint
            library.afl_custom_fuzz.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t,
                 ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p, ctypes.c_size_t, ctypes.c_size_t]
            library.afl_custom_fuzz.restype = ctypes.c_size_t
            library.afl_custom_deinit.argtypes = [ctypes.c_void_p]
            environment = {'TF_HYBRID_SOCKET': str(sock), 'TF_HYBRID_TOKEN': token,
                'TF_HYBRID_MAX_INPUT': '4096', 'TF_HYBRID_FUZZ_COUNT': '8',
                'TF_HYBRID_HOOK_TRACE': str(trace)}
            with patch.dict(os.environ, environment):
                state = library.afl_custom_init(None, 42)
                self.assertTrue(state)
                try:
                    parent = ctypes.create_string_buffer(b'AA' + b'x' * 30)
                    self.assertEqual(library.afl_custom_fuzz_count(state, parent, 32), 8)
                    for _ in range(3):
                        out = ctypes.c_void_p()
                        self.assertEqual(library.afl_custom_fuzz(state, parent, 32,
                            ctypes.byref(out), None, 0, 4096), 32)
                        self.assertEqual(ctypes.string_at(out, 32)[0], ord('A') ^ 1)
                finally:
                    library.afl_custom_deinit(state)
            worker.join(2)
            listener.close()
            self.assertFalse(worker.is_alive())
            self.assertFalse(failures, failures)
            report = audit_hook_trace(trace, expected_fuzz_callbacks=3)
            self.assertEqual(report['custom_stage_entries'], 1)
            self.assertEqual(report['custom_attempts_budgeted'], 8)
            self.assertEqual(report['custom_fuzz_callbacks'], 3)
            self.assertEqual(report['trace_status'], 'clean_deinit')
            self.assertFalse(report['stock_stage_provenance_verified'])
            trace.write_bytes(trace.read_bytes() + b'F 1\n' * 9)
            with self.assertRaises(RuntimeError):
                audit_hook_trace(trace)

    def test_hook_trace_rejects_partial_and_symlinks(self):
        with tempfile.TemporaryDirectory(prefix='tfh-v51-reject-') as d:
            root = Path(d)
            trace = root / 'trace.log'
            trace.write_bytes(b'C 8\nF 1')
            with self.assertRaises(RuntimeError):
                audit_hook_trace(trace)
            trace.write_bytes(b'C 8\nF 1\nX 1\n')
            with self.assertRaises(RuntimeError):
                audit_hook_trace(trace, expected_fuzz_callbacks=2)
            symlink = root / 'link'
            symlink.symlink_to(trace)
            with self.assertRaises(RuntimeError):
                audit_hook_trace(symlink)


class PlateauCallbackLatencyTests(unittest.TestCase):
    def test_plateau_to_DSE_callback_case_delay_is_measured(self):
        # Exercise the Python controller on synthetically signed transport
        # receipts without starting any binary. We do not claim native E2E.
        from experiments.hybrid_rebuilt_v1.tests import ControllerComponentTests
        with tempfile.TemporaryDirectory(prefix='tfh-v51-lag-') as d:
            root = Path(d)
            (root / 'cases').mkdir()
            binary, initial = ControllerComponentTests.source(root)
            seen = []
            candidate = b'AF' + b'x' * 30
            def solve(*args, **kw):
                seen.append('solved')
                from experiments.hybrid_rebuilt_v1.policy import digest
                return candidate, {'candidate_sha256': digest(candidate),
                    'target_sha256': digest(binary.read_bytes()),
                    'status': 'VERIFIED', 'replayed_and_reaudited': True}
            ctl = LiveRebuiltController(root, initial=initial, binary=binary,
                qemu=None, plugin=None, flags_receipt=None, stall_cases=4,
                max_dse_jobs=1, solve_worker=solve, mixed_mutations=True)
            server = SimpleNamespace(count=0, delivered=0, lock=threading.Lock(),
                current=None, stop=threading.Event(), error=None, delivery_error=None)
            ctl.server = server
            # First case produces new coverage, four quiet cases reach plateau,
            # and three additional deliveries wait for the next custom callback.
            for _ in range(8):
                ControllerComponentTests.fake_case(root, server, b'BB' + b'x' * 30)
            ctl.drain()
            self.assertEqual(ctl.plateau_edge['case'], 4)
            ctl.request_sequence = 1
            output = ctl.next_input(b'AA' + b'x' * 30)
            self.assertEqual(RESPONSE.unpack(output[:RESPONSE.size])[2], 2)
            self.assertEqual(seen, ['solved'])
            self.assertEqual(len(ctl.dse_callback_lags), 1)
            self.assertEqual(ctl.dse_callback_lags[0]['completed_case_lag'], 3)
            ctl.close()


class NativeReceiptAuditTests(unittest.TestCase):
    def test_readonly_audit_reconciles_command_hooks_and_delivery_ledger(self):
        from experiments.hybrid_rebuilt_v1.acceptance import audit_native_campaign
        from experiments.hybrid_rebuilt_v1.telemetry import audit_hook_trace
        with tempfile.TemporaryDirectory(prefix='tfh-v51-accept-') as d:
            root = Path(d)
            (root / 'mutator-hooks.log').write_text('C 8\nF 1\nX 1\n')
            hooks = audit_hook_trace(root / 'mutator-hooks.log')
            events = [{'event': 'case_delivered', 'case': k} for k in range(3)] + [
                      {'event': 'masked_mutation'}]
            (root / 'events.jsonl').write_text(''.join(json.dumps(e) + '\n' for e in events))
            campaign = {'status': 'completed', 'afl_exit': 0,
                'afl_stage_policy': 'fast', 'enhanced_deterministic_skipped': True,
                'command': ['/usr/bin/afl-fuzz', '-z', '--', 'bridge', '5', '@@'],
                'cases': 3, 'delivered_cases': 3, 'target_sha256': 'a'*64,
                'hybrid': {'mixed_mutations': True, 'mutator_hooks': hooks}}
            result = {'status': 'completed', 'mixed_mutations': True,
                'target_sha256': 'a'*64, 'mutator_hooks': hooks,
                'processed_cases': 3, 'mutations_generated': 1,
                'masked_mutations_delivered': 1, 'matched_DSE_deliveries': 0,
                'unattributed_deliveries': 2, 'DSE_triggers': 0}
            (root / 'campaign.json').write_text(json.dumps(campaign))
            (root / 'hybrid-result.json').write_text(json.dumps(result))
            audited = audit_native_campaign(root)
            self.assertEqual(audited['status'], 'passed_v51_native_receipt_audit')
            self.assertEqual(audited['custom_stage_entries'], 1)
            self.assertFalse(audited['stock_stage_provenance_verified'])
            campaign['command'].remove('-z')
            (root / 'campaign.json').write_text(json.dumps(campaign))
            with self.assertRaises(RuntimeError):
                audit_native_campaign(root)
            campaign['command'].insert(1, '-z')
            (root / 'campaign.json').write_text(json.dumps(campaign))
            result['mutator_hooks']['custom_fuzz_callbacks'] = 12
            (root / 'hybrid-result.json').write_text(json.dumps(result))
            with self.assertRaises(RuntimeError):
                audit_native_campaign(root)


if __name__ == '__main__':
    unittest.main(verbosity=2)
