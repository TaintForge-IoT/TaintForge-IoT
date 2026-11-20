"""Offline and native C component tests. Not a substitute for the QEMU E2E."""
from __future__ import annotations

import ctypes
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from . import controller as live
from .mutator_build import build_mutator
from .policy import (MAX_INPUT, MAP_SIZE, CoveragePlateau, checked_input, checked_mask,
                     digest, diff_offsets, eligible_requests, mask_bits, mask_from_requests,
                     masked_mutation)


def bitmap(*values):
    result = bytearray(MAP_SIZE)
    for slot in values:
        result[slot] = 1
    return bytes(result)


class PolicyTests(unittest.TestCase):
    def test_mask_allows_nonfixture_offsets_and_rejects_invalid(self):
        requests = [{'observed_site': {'offsets': [20, 1000]}},
                    {'observed_site': {'offsets': [2, 1000]}}]
        self.assertEqual(mask_from_requests(requests), (2, 20, 1000))
        self.assertEqual(mask_bits([1, 9], 10), b'\x02\x02')
        for invalid in ([True], [0, 0], [-1], [1, 0], [4096]):
            with self.subTest(invalid=invalid), self.assertRaises(RuntimeError):
                checked_mask(invalid)
        with self.assertRaises(RuntimeError):
            mask_from_requests([{'observed_site': {'offsets': [4096]}}])

    def test_mutator_preserves_length_and_tainted_positions(self):
        for length in (1, 7, 32, 1001, 4096):
            original = bytes([77]) * length
            offsets = sorted(set([0, length // 2, length - 1]))
            for ordinal in range(1, 65):
                changed, offset, operation = masked_mutation(original, offsets, ordinal)
                self.assertEqual(len(changed), length)
                self.assertTrue(set(diff_offsets(original, changed)) <= set(offsets))
                self.assertIn(offset, offsets)
                self.assertTrue(0 <= operation < 16)
        with self.assertRaises(RuntimeError):
            masked_mutation(b'aaa', [7], 1)

    def test_variable_input_bounds(self):
        self.assertEqual(checked_input(b'x' * MAX_INPUT), b'x' * MAX_INPUT)
        for invalid in (b'', b'x' * (MAX_INPUT + 1), bytearray(b'x')):
            with self.assertRaises(RuntimeError):
                checked_input(invalid)

    def test_coverage_plateau_only_counts_eligible_and_real_novelty(self):
        policy = CoveragePlateau(4)
        policy.observe(bitmap(1), eligible=False)
        for _ in range(4):
            policy.observe(bitmap(1), eligible=False)
        self.assertFalse(policy.stalled)
        for _ in range(4):
            policy.observe(bitmap(1), eligible=True)
        self.assertTrue(policy.stalled)
        self.assertEqual(policy.observe(bitmap(1, 2), eligible=True), 1)
        self.assertFalse(policy.stalled)
        with self.assertRaises(RuntimeError):
            policy.observe(bytes(5), eligible=True)

    def test_only_eligible_bounded_dse_requests(self):
        valid = {'request_id': '1' * 64, 'opposite_observed_elsewhere': False,
                 'observed_site': {'seq': 10, 'offsets': [1000]}}
        invalid = {'request_id': '2' * 64, 'opposite_observed_elsewhere': True,
                   'observed_site': {'seq': 1, 'offsets': [0]}}
        self.assertEqual(eligible_requests([invalid, valid]), [valid])
        self.assertEqual(eligible_requests([valid], {'1' * 64}), [])


class DynamicCAdapterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix='tf-hyb-v2-adapter-')
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.library = build_mutator(Path(cls.temporary.name) / 'mutator.so')

    @staticmethod
    def c_library(path):
        library = ctypes.CDLL(str(path))
        library.afl_custom_init.argtypes = [ctypes.c_void_p, ctypes.c_uint]
        library.afl_custom_init.restype = ctypes.c_void_p
        library.afl_custom_fuzz_count.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]
        library.afl_custom_fuzz_count.restype = ctypes.c_uint
        library.afl_custom_fuzz.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p, ctypes.c_size_t, ctypes.c_size_t]
        library.afl_custom_fuzz.restype = ctypes.c_size_t
        library.afl_custom_deinit.argtypes = [ctypes.c_void_p]
        return library

    def test_real_C_adapter_handles_variable_size_and_masked_changes(self):
        with tempfile.TemporaryDirectory(prefix='tf-v2-') as directory:
            path = Path(directory) / 'bridge.sock'
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.bind(str(path))
            listener.listen(1)
            errors = []
            def controller():
                try:
                    with listener.accept()[0] as connection:
                        self.assertEqual(live.receive(connection, 64), b'c' * 64)
                        for sequence, parent in enumerate([b'abcdefg', b'Z' * 4096], 1):
                            magic, index, size = live.REQUEST.unpack(live.receive(connection, live.REQUEST.size))
                            self.assertEqual((magic, index, size), (b'TFH2', sequence, len(parent)))
                            self.assertEqual(live.receive(connection, size), parent)
                            result = bytearray(parent)
                            result[-1] ^= 2
                            mask = mask_bits([len(parent) - 1], len(parent))
                            answer = live.RESPONSE.pack(b'TFH2', sequence, 1, len(mask), len(result))
                            connection.sendall(answer + mask + result)
                except BaseException as exc:
                    errors.append(exc)
            thread = threading.Thread(target=controller)
            thread.start()
            library = self.c_library(self.library)
            with patch.dict(os.environ, {'TF_HYBRID_SOCKET': str(path), 'TF_HYBRID_TOKEN': 'c' * 64,
                                          'TF_HYBRID_MAX_INPUT': '4096'}):
                state = library.afl_custom_init(None, 42)
                try:
                    for parent in (b'abcdefg', b'Z' * 4096):
                        data = ctypes.create_string_buffer(parent)
                        output = ctypes.c_void_p()
                        self.assertEqual(library.afl_custom_fuzz_count(state, data, len(parent)), 16)
                        length = library.afl_custom_fuzz(state, data, len(parent),
                            ctypes.byref(output), None, 0, MAX_INPUT)
                        changed = ctypes.string_at(output, length)
                        self.assertEqual(diff_offsets(parent, changed), [len(parent) - 1])
                finally:
                    library.afl_custom_deinit(state)
            thread.join(5)
            listener.close()
            self.assertFalse(thread.is_alive())
            self.assertEqual(errors, [])

    def test_mutator_exits_for_response_outside_mask(self):
        with tempfile.TemporaryDirectory(prefix='tf-v2-invalid-') as directory:
            path = Path(directory) / 'bridge.sock'
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.bind(str(path))
            listener.listen(1)
            code = '''import ctypes,sys
lib=ctypes.CDLL(sys.argv[1])
lib.afl_custom_init.argtypes=[ctypes.c_void_p,ctypes.c_uint]
lib.afl_custom_init.restype=ctypes.c_void_p
lib.afl_custom_fuzz.argtypes=[ctypes.c_void_p,ctypes.c_void_p,ctypes.c_size_t,ctypes.POINTER(ctypes.c_void_p),ctypes.c_void_p,ctypes.c_size_t,ctypes.c_size_t]
lib.afl_custom_fuzz.restype=ctypes.c_size_t
state=lib.afl_custom_init(None,42)
parent=ctypes.create_string_buffer(b'abcdefg')
out=ctypes.c_void_p()
lib.afl_custom_fuzz(state,parent,7,ctypes.byref(out),None,0,4096)
'''
            environment = dict(os.environ, TF_HYBRID_SOCKET=str(path), TF_HYBRID_TOKEN='d' * 64,
                               TF_HYBRID_MAX_INPUT='4096')
            process = subprocess.Popen([sys.executable, '-c', code, str(self.library)],
                                       env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                with listener.accept()[0] as connection:
                    self.assertEqual(live.receive(connection, 64), b'd' * 64)
                    live.receive(connection, live.REQUEST.size + 7)
                    # Change offset 5 while the only authorized bit is offset 0.
                    mask = mask_bits([0], 7)
                    connection.sendall(live.RESPONSE.pack(b'TFH2', 1, 1, 1, 7)
                                       + mask + b'abcdeZg')
                _, stderr = process.communicate(timeout=5)
                self.assertEqual(process.returncode, 2)
                self.assertIn(b'mutation_outside_DTA_mask', stderr)
            finally:
                listener.close()
                if process.poll() is None:
                    process.kill()
                process.wait(timeout=5)


class ControllerComponentTests(unittest.TestCase):
    @staticmethod
    def source(root):
        binary = root / 'sample.elf'
        binary.write_bytes(b'deterministic, harmless component target')
        initial = {'target_sha256': live.sha(binary), 'mask': [0, 1],
                   'directory': str(root / 'initial'),
                   'requests': [{'request_id': 'f' * 64,
                                 'input_sha256': digest(b'AA' + b'x' * 30),
                                 'opposite_observed_elsewhere': False,
                                 'observed_site': {'seq': 5, 'offsets': [1]}}]}
        return binary, initial

    @staticmethod
    def fake_case(root, server, raw, *, quarantined=False):
        index = server.delivered
        case = root / 'cases' / f'{index:08d}'
        case.mkdir(parents=True)
        code = 2 if raw.startswith(b'AF') else 1
        cov = bytes(MAP_SIZE) if quarantined else bitmap(1, 10 + code)
        (case / 'input').write_bytes(raw)
        (case / 'coverage.map').write_bytes(cov)
        report = {'input_sha256': digest(raw), 'guest_exit': code,
                  'status': 'quarantined' if quarantined else 'passed',
                  'coverage': {'status': 'unavailable', 'map_sha256': None} if quarantined else
                              {'status': 'verified', 'map_sha256': digest(cov)}}
        if quarantined:
            report['classification'] = 'unverified_abnormal_exit'
            del report['guest_exit']
        (case / 'result.json').write_text(json.dumps(report))
        (case / 'transport.json').write_text(json.dumps({
            'schema': 1, 'status': 'delivered', 'case': index,
            'input_sha256': digest(raw), 'coverage_sha256': digest(cov),
            'feedback': 'zero_unverified' if quarantined else 'verified_guest_coverage'}))
        server.delivered += 1
        server.count += 1

    def test_real_socket_C_adapter_controller_DSE_refresh_and_AFL_queue(self):
        with tempfile.TemporaryDirectory(prefix='tf-v2-controller-') as directory:
            root = Path(directory)
            (root / 'cases').mkdir()
            (root / 'afl/default/queue').mkdir(parents=True)
            binary, initial = self.source(root)
            seed = b'AA' + b'x' * 30
            dse_seed = b'AF' + b'x' * 30
            calls = []
            def solve(*args, **kwargs):
                calls.append('dse')
                return dse_seed, {'candidate_sha256': digest(dse_seed),
                    'target_sha256': live.sha(binary), 'status': 'VERIFIED',
                    'replayed_and_reaudited': True}
            def analyze(*args, **kwargs):
                calls.append('dta')
                self.assertEqual(kwargs['seed'], dse_seed)
                return dict(initial, mask=[0, 1, 2])
            controller = live.LiveRebuiltController(root, initial=initial,
                binary=binary, qemu=None, plugin=None, flags_receipt=None,
                stall_cases=4, max_dse_jobs=1, solve_worker=solve, analyze_worker=analyze)
            server = SimpleNamespace(count=0, delivered=0, lock=threading.Lock(), current=None, error=None, stop=threading.Event(), delivery_error=None)
            controller.bind(server)
            self.fake_case(root, server, seed)
            compiled = build_mutator(root / 'mutator.so')
            library = DynamicCAdapterTests.c_library(compiled)
            with patch.dict(os.environ, controller.environment(compiled)):
                state = library.afl_custom_init(None, 42)
                try:
                    # The real AFL++ calls fuzz_count before fuzzing the queue entry.
                    # Model that stage entry for native hook telemetry.
                    parent = ctypes.create_string_buffer(seed)
                    self.assertEqual(library.afl_custom_fuzz_count(state, parent, len(seed)), 16)
                    for _ in range(15):
                        parent = ctypes.create_string_buffer(seed)
                        output = ctypes.c_void_p()
                        length = library.afl_custom_fuzz(state, parent, len(seed),
                            ctypes.byref(output), None, 0, 4096)
                        generated = ctypes.string_at(output, length)
                        if generated == dse_seed:
                            (root / 'afl/default/queue/id:000001').write_bytes(generated)
                        self.fake_case(root, server, generated)
                finally:
                    library.afl_custom_deinit(state)
                    controller.close()
            results = controller.finish()
            self.assertEqual(calls, ['dse', 'dta'])
            self.assertEqual(results['DTA_mask_revisions'], [[0, 1], [0, 1, 2]])
            self.assertTrue(results['automatic_live_cycle_verified'])
            self.assertTrue(results['DSE_seed_retained_by_AFL'])
            self.assertEqual(results['DSE_jobs'][0]['status'], 'VERIFIED')
            self.assertEqual(len(results['DSE_live_executions']), 1)

    def test_quarantined_case_is_not_a_verified_DSE_seed_or_plateau_count(self):
        with tempfile.TemporaryDirectory(prefix='tf-v2-fault-') as directory:
            root = Path(directory)
            (root / 'cases').mkdir()
            (root / 'afl/default/queue').mkdir(parents=True)
            binary, initial = self.source(root)
            controller = live.LiveRebuiltController(root, initial=initial, binary=binary,
                qemu=None, plugin=None, flags_receipt=None, stall_cases=4, max_dse_jobs=1)
            server = SimpleNamespace(count=0, delivered=0, lock=threading.Lock(), current=None, error=None, stop=threading.Event(), delivery_error=None)
            controller.server = server
            raw = b'AF' + b'x' * 30
            controller.pending = {'kind': 'dse', 'raw': raw, 'sha256': digest(raw), 'delivered': False}
            self.fake_case(root, server, raw, quarantined=True)
            controller.drain()
            self.assertEqual(controller.dse_executions, [])
            self.assertEqual(controller.plateau.observations, 0)
            self.assertTrue(controller.pending['delivered'])
            controller.close()
            event = (root / 'events.jsonl').read_text()
            self.assertIn('abnormal_exit_quarantined', event)
            self.assertNotIn('DSE_seed_executed_by_live_AFL', event)


class RebuiltBackendFaultEvidenceTests(unittest.TestCase):
    def test_incomplete_guest_exit_can_only_be_quarantined_with_valid_input_evidence(self):
        from taintforge_env import afl_rebuilt as backend
        with tempfile.TemporaryDirectory(prefix='tf-hyb-fault-record-') as directory:
            path = Path(directory) / 'coverage.bin'
            backend.write_map(path)
            with path.open('r+b') as stream:
                stream.write(backend.HEADER.pack(b'TFRCOV1\0', 1, MAP_SIZE,
                    1, 0, 20, 0x8049000, 0x8049010, 0, 0, 8, 0, 0))
            evidence = backend.partial_coverage_candidate(path)
            self.assertIsNotNone(evidence)
            self.assertEqual(evidence['input_bytes_read'], 8)
            self.assertTrue(evidence['guest_exit_was_not_observed'])
            with self.assertRaises(RuntimeError):
                backend.parse_map(path, 139)
            # The QEMU plugin reported an error: never relabel as a candidate.
            with path.open('r+b') as stream:
                stream.write(backend.HEADER.pack(b'TFRCOV1\0', 1, MAP_SIZE,
                    1, 0, 20, 0x8049000, 0x8049010, 0, 0, 8, 0, 1))
            self.assertIsNone(backend.partial_coverage_candidate(path))

    def test_false_exit_claim_cannot_be_promoted(self):
        from taintforge_env import afl_rebuilt as backend
        with tempfile.TemporaryDirectory(prefix='tf-hyb-fault-record-') as directory:
            path = Path(directory) / 'coverage.bin'
            backend.write_map(path)
            with path.open('r+b') as stream:
                stream.write(backend.HEADER.pack(b'TFRCOV1\0', 1, MAP_SIZE,
                    1, 0, 20, 0x8049000, 0x8049010, 1, 0, 8, 0, 0))
            self.assertIsNone(backend.partial_coverage_candidate(path))


class ReplayFaultTests(unittest.TestCase):
    def test_repeated_abnormal_returns_remain_unverified_even_when_reproducible(self):
        from scripts.replay_hybrid_faults import replay
        from taintforge_env import afl_rebuilt as backend
        with tempfile.TemporaryDirectory(prefix='tf-hyb-replays-') as directory:
            root = Path(directory)
            (root / 'cases/00000000').mkdir(parents=True)
            raw = b'AA' + b'x' * 30
            (root / 'cases/00000000/input').write_bytes(raw)
            (root / 'cases/00000000/result.json').write_text(json.dumps({
                'status': 'quarantined', 'input_sha256': digest(raw)}))
            (root / 'campaign.json').write_text(json.dumps({
                'status': 'completed', 'profile': backend.PROFILE,
                'target_sha256': 'b' * 64, 'cases': 1}))
            (root / 'quarantined.json').write_text(json.dumps({
                'schema': 1, 'cases': [{'case': 0, 'input_sha256': digest(raw)}]}))
            def execute(campaign, data, out):
                self.assertEqual(data, raw)
                out.mkdir(parents=True, exist_ok=False)
                return {'status': 'quarantined', 'classification': 'unverified_abnormal_exit',
                        'returncode': 139}, bytes(MAP_SIZE)
            with patch.object(backend, 'execute_case', side_effect=execute) as worker:
                result = replay(root, repetitions=2)
            self.assertEqual(worker.call_count, 2)
            self.assertTrue(result['cases'][0]['reproduced_abnormal_candidate'])
            self.assertFalse(result['cases'][0]['verified_target_crash'])
            self.assertFalse(result['verified_target_hang'])
            self.assertTrue((root / 'fault-replays/replay-report.json').is_file())



class CLITests(unittest.TestCase):
    def test_cli_exposes_stock_and_live_hybrid_modes(self):
        from scripts import run_afl_rebuilt
        program = Path(run_afl_rebuilt.__file__)
        result = subprocess.run([sys.executable, str(program), 'campaign', '--help'],
            text=True, capture_output=True, check=True)
        self.assertIn('--mode {afl,focus,hybrid,hybrid-mixed}', result.stdout)
        self.assertIn('--stall-cases', result.stdout)
        self.assertIn('--max-dse-jobs', result.stdout)
        self.assertIn('--flags-receipt', result.stdout)



if __name__ == '__main__':
    unittest.main(verbosity=2)
