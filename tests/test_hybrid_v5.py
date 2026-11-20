"""Hybrid v5: mixed stock/custom accounting and controlled five-arm comparisons.

These tests exercise the actual C custom-mutator socket but use synthetic
transport receipts. They are not a native QEMU/AFL acceptance claim.
"""
from __future__ import annotations

import ctypes
import json
import os
from pathlib import Path
import tempfile
import threading
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from experiments.hybrid_rebuilt_v1 import ablation, controller, policy
from experiments.hybrid_rebuilt_v1.mutator_build import build_mutator
from experiments.hybrid_rebuilt_v1.tests import ControllerComponentTests, DynamicCAdapterTests
from scripts import run_hybrid_ablation


class AdaptiveScheduleTests(unittest.TestCase):
    def _requests(self, offsets):
        return [{'request_id': 'f' * 64, 'opposite_observed_elsewhere': False,
                 'observed_site': {'seq': 5, 'offsets': offsets}}]

    def test_collapsed_single_byte_mask_uses_at_most_quarter_focused(self):
        schedule = policy.AdaptiveBranchSchedule(tuple(range(32)), self._requests([0]))
        self.assertEqual(schedule.focus_quota, 2)
        actual = [schedule.next(i, 32) for i in range(1, 65)]
        focused = [x for x in actual if x[2] == 'branch_focus']
        self.assertEqual(len(focused), 8)
        self.assertEqual(len(actual) - len(focused), 56)
        self.assertTrue(all(mask == (0,) for mask, _, _ in focused))
        self.assertTrue(all(mask == tuple(range(32)) for mask, _, scope in actual
                            if scope == 'full_union_fallback'))
        for mask, ordinal, _ in actual:
            output, offset, _ = policy.masked_mutation(b'x' * 32, mask, ordinal)
            self.assertIn(offset, mask)
            self.assertTrue(set(policy.diff_offsets(b'x' * 32, output)) <= set(mask))

    def test_adaptive_feedback_does_not_exceed_singleton_cap(self):
        schedule = policy.AdaptiveBranchSchedule(tuple(range(32)), self._requests([0]))
        for _ in range(8):
            schedule.observe('branch_focus', 1)
        for _ in range(24):
            schedule.observe('full_union_fallback', 0)
        self.assertEqual(schedule.focus_quota, 3)
        for _ in range(8):
            schedule.observe('branch_focus', 1)
        for _ in range(24):
            schedule.observe('full_union_fallback', 0)
        self.assertEqual(schedule.focus_quota, 4)
        for _ in range(8):
            schedule.observe('branch_focus', 1)
        for _ in range(24):
            schedule.observe('full_union_fallback', 0)
        self.assertEqual(schedule.focus_quota, 4)
        for _ in range(8):
            schedule.observe('branch_focus', 0)
        for _ in range(24):
            schedule.observe('full_union_fallback', 1)
        self.assertEqual(schedule.focus_quota, 3)
        self.assertEqual(len(schedule.adjustments), 4)

    def test_no_real_focus_never_claims_focus(self):
        mask = (0, 1, 2)
        schedule = policy.AdaptiveBranchSchedule(mask, self._requests([0, 1, 2]))
        self.assertEqual(schedule.focus, ())
        self.assertEqual(schedule.focus_quota, 0)
        self.assertTrue(all(schedule.next(i, 3)[2] == 'full_union_fallback'
                            for i in range(1, 65)))
        with self.assertRaises(RuntimeError):
            schedule.observe('unknown', 0)


class MixedControllerTests(unittest.TestCase):
    def make(self, root, *, mixed=True, live_dse=True, solve=None, analyze=None):
        binary, initial = ControllerComponentTests.source(root)
        ctrl = controller.LiveRebuiltController(root, initial=initial, binary=binary,
            qemu=None, plugin=None, flags_receipt=None, stall_cases=4,
            max_dse_jobs=1 if live_dse else 0,
            mixed_mutations=mixed, live_dse=live_dse,
            solve_worker=solve or controller.solve_request,
            analyze_worker=analyze or controller.analyze_seed)
        server = SimpleNamespace(count=0, delivered=0, lock=threading.Lock(),
            current=None, error=None, stop=threading.Event(), delivery_error=None)
        return ctrl, server, initial

    def test_mixed_environment_keeps_stock_stages_and_reduces_custom_count(self):
        with tempfile.TemporaryDirectory(prefix='tf-v5-') as temporary:
            root = Path(temporary)
            ctrl, _, _ = self.make(root)
            path = build_mutator(root / 'mutator.so')
            environment = ctrl.environment(path)
            self.assertNotIn('AFL_CUSTOM_MUTATOR_ONLY', environment)
            self.assertEqual(environment['TF_HYBRID_FUZZ_COUNT'], '8')
            legacy, _, _ = self.make_fixture(temporary)
            self.assertEqual(legacy['TF_HYBRID_FUZZ_COUNT'], '16')
            self.assertEqual(legacy['AFL_CUSTOM_MUTATOR_ONLY'], '1')
            ctrl.close()

    def make_fixture(self, temporary):
        # A second controller must have its own AF_UNIX socket path.
        other = Path(temporary) / 'legacy'
        other.mkdir()
        obj, _, _ = self.make(other, mixed=False)
        env = obj.environment(build_mutator(other / 'legacy.so'))
        obj.close()
        return env, other, obj

    def test_actual_C_adapter_and_stock_cases_trigger_audited_live_DSE(self):
        with tempfile.TemporaryDirectory(prefix='tf-v5-live-') as temporary:
            root = Path(temporary)
            (root / 'cases').mkdir()
            (root / 'afl/default/queue').mkdir(parents=True)
            raw = b'AA' + b'x' * 30
            result_seed = b'AF' + b'x' * 30
            calls = []
            def solve(*a, **k):
                calls.append('dse')
                return result_seed, {'candidate_sha256': policy.digest(result_seed),
                    'target_sha256': policy.digest((root / 'sample.elf').read_bytes()),
                    'status': 'VERIFIED', 'replayed_and_reaudited': True}
            def analyze(*a, **k):
                calls.append('dta')
                self.assertEqual(k['seed'], result_seed)
                source = ControllerComponentTests.source(root)[1]
                return dict(source, mask=[0, 1, 2])
            ctrl, server, _ = self.make(root, solve=solve, analyze=analyze)
            ctrl.bind(server)
            compiled = build_mutator(root / 'mutator.so')
            library = DynamicCAdapterTests.c_library(compiled)
            with patch.dict(os.environ, ctrl.environment(compiled)):
                state = library.afl_custom_init(None, 42)
                try:
                    parent = ctypes.create_string_buffer(raw)
                    output = ctypes.c_void_p()
                    self.assertEqual(library.afl_custom_fuzz_count(state, parent, len(raw)), 8)
                    size = library.afl_custom_fuzz(state, parent, len(raw),
                        ctypes.byref(output), None, 0, 4096)
                    first = ctypes.string_at(output, size)
                    ControllerComponentTests.fake_case(root, server, first)
                    # Stock-stage payloads did not originate from the pending callback.
                    for _ in range(4):
                        ControllerComponentTests.fake_case(root, server, b'ST' + b'x' * 30)
                    size = library.afl_custom_fuzz(state, parent, len(raw),
                        ctypes.byref(output), None, 0, 4096)
                    dse = ctypes.string_at(output, size)
                    self.assertEqual(dse, result_seed)
                    ControllerComponentTests.fake_case(root, server, dse)
                    (root / 'afl/default/queue/id:000001').write_bytes(dse)
                    ControllerComponentTests.fake_case(root, server, b'ST' + b'x' * 30)
                    size = library.afl_custom_fuzz(state, parent, len(raw),
                        ctypes.byref(output), None, 0, 4096)
                    ControllerComponentTests.fake_case(root, server, ctypes.string_at(output, size))
                finally:
                    library.afl_custom_deinit(state)
                    ctrl.close()
            results = ctrl.finish()
            self.assertEqual(calls, ['dse', 'dta'])
            self.assertTrue(results['mixed_mutations'])
            self.assertEqual(results['masked_mutations_delivered'], 2)
            self.assertEqual(results['matched_DSE_deliveries'], 1)
            self.assertEqual(results['unattributed_deliveries'], 5)
            self.assertEqual(results['processed_cases'], 8)
            self.assertTrue(results['automatic_live_cycle_verified'])
            self.assertTrue(results['DSE_seed_retained_by_AFL'])
            self.assertEqual(results['DTA_mask_refresh_count'], 1)
            self.assertGreaterEqual(ctrl.plateau.eligible, 7)
            self.assertEqual(len(results['DSE_live_executions']), 1)

    def test_focus_only_never_runs_DSE_despite_a_plateau(self):
        with tempfile.TemporaryDirectory(prefix='tf-v5-focus-') as temporary:
            root = Path(temporary)
            (root / 'cases').mkdir()
            (root / 'afl/default/queue').mkdir(parents=True)
            ctrl, server, _ = self.make(root, mixed=False, live_dse=False)
            ctrl.server = server
            ctrl.plateau.quiet = 100
            self.assertEqual(ctrl.max_dse_jobs, 0)
            ctrl.request_sequence = 1
            answer = ctrl.next_input(b'AA' + b'x' * 30)
            magic, serial, kind, _, _ = controller.RESPONSE.unpack(answer[:20])
            self.assertEqual((magic, kind), (b'TFH2', 1))
            self.assertEqual(ctrl.dse_jobs, [])
            ctrl.close()

    def test_unrelated_deliveries_never_claim_DSE_execution(self):
        with tempfile.TemporaryDirectory(prefix='tf-v5-nomatch-') as temporary:
            root = Path(temporary)
            (root / 'cases').mkdir()
            (root / 'afl/default/queue').mkdir(parents=True)
            ctrl, server, _ = self.make(root)
            ctrl.server = server
            seed = b'AF' + b'x' * 30
            ctrl.pending = {'kind': 'dse', 'raw': seed, 'sha256': policy.digest(seed),
                            'scope': None, 'delivered': False}
            ControllerComponentTests.fake_case(root, server, b'BB' + b'x' * 30)
            ctrl.drain()
            self.assertFalse(ctrl.pending['delivered'])
            self.assertEqual(ctrl.dse_executions, [])
            self.assertEqual(ctrl.unattributed_deliveries, 1)
            ctrl.close()


class FiveArmStudyTests(unittest.TestCase):
    def test_five_arm_complete_pairing_and_rejection_of_missing_run(self):
        metrics = {'target_sha256': 'a' * 64, 'afl_seed': 42, 'delivered': 500,
                   'history': [{'case': i, 'branch_outcomes': i + 10, 'map_slots': i + 15}
                               for i in range(501)], 'campaign': '/tmp'}
        data = [{'replicate': 1, 'arm': arm, 'metrics': metrics,
                 'total_elapsed_seconds': 200.0} for arm in ablation.ARMS_V5]
        result = ablation.comparisons(data, required_arms=ablation.ARMS_V5)
        self.assertEqual([row['arm'] for row in result], sorted(ablation.ARMS_V5))
        self.assertTrue(all(row['branch_outcomes'] == 510 for row in result))
        self.assertEqual(len(ablation.aggregate(result)), 5)
        with self.assertRaises(ValueError):
            ablation.comparisons(data[:-1], required_arms=ablation.ARMS_V5)

    def test_rotations_cover_all_five_ordinal_positions(self):
        positions = {arm: set() for arm in ablation.ARMS_V5}
        for rep in range(5):
            order = ablation.ARMS_V5[rep:] + ablation.ARMS_V5[:rep]
            for position, arm in enumerate(order):
                positions[arm].add(position)
        self.assertTrue(all(value == set(range(5)) for value in positions.values()))



class PrepareHybridTests(unittest.TestCase):
    def test_focus_preparation_needs_no_solver_flags_and_preserves_accepted_seeds(self):
        from scripts import run_afl_rebuilt
        from taintforge_env import afl_rebuilt as backend
        with tempfile.TemporaryDirectory(prefix='tf-v5-prepare-') as temporary:
            root = Path(temporary)
            (root / 'seeds').mkdir()
            (root / 'dta').mkdir()
            (root / 'build').mkdir()
            binary = root / 'sample.elf'
            binary.write_bytes(b'reviewed static test content')
            initial_seed = b'AA' + b'x' * 30
            (root / 'seeds/initial').write_bytes(initial_seed)
            (root / 'campaign.json').write_text(json.dumps({'status': 'prepared',
                'target_sha256': backend.digest(binary)}))
            def analyze(directory, *, binary, qemu, plugin, seed, max_candidates):
                accepted = root / 'dta/accepted-seeds'
                accepted.mkdir()
                second = b'AB' + b'x' * 30
                (accepted / policy.digest(second)).write_bytes(second)
                return {'target_sha256': backend.digest(binary),
                    'mask': [0, 1], 'requests': [],
                    'source_seed_sha256': policy.digest(seed),
                    'directory': str(root / 'dta'),
                    'DTA_summary_sha256': 'a' * 64}
            with patch.object(controller, 'analyze_seed', analyze):
                ctrl, compiled = run_afl_rebuilt.prepare_hybrid(root, binary=binary,
                    qemu=None, plugin=None, flags_receipt=None, stall_cases=16,
                    max_dse_jobs=0, max_candidates=16, mixed=False, live_dse=False)
                try:
                    env = ctrl.environment(compiled)
                    self.assertIn('AFL_CUSTOM_MUTATOR_ONLY', env)
                    self.assertFalse(ctrl.live_dse)
                    self.assertIsNone(backend.read_json(root / 'campaign.json')['hybrid']['flags_receipt_sha256'])
                    self.assertTrue((root / 'seeds' / policy.digest(b'AB' + b'x' * 30)).is_file())
                finally:
                    ctrl.close()

    def test_all_five_cli_modes_are_unique_where_required(self):
        self.assertEqual(run_hybrid_ablation.ARM_MODES,
            {'A': 'afl', 'B': 'afl', 'C1': 'focus',
             'C2': 'hybrid', 'D': 'hybrid-mixed'})

if __name__ == '__main__':
    unittest.main(verbosity=2)
