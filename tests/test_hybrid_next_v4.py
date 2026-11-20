"""Offline regressions for hybrid forensics, ablation and boundary receipts."""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import tempfile
import unittest

from experiments.hybrid_rebuilt_v1 import ablation, boundary, forensics, policy
from taintforge_env import afl_rebuilt as backend, capsule_resources


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True))


def digest(raw):
    return sha256(raw).hexdigest()


class FocusMaskTests(unittest.TestCase):
    def test_per_branch_masks_keep_full_union_fallback(self):
        requests = [
            {'request_id': 'a'*64, 'opposite_observed_elsewhere': False,
             'observed_site': {'pc': 2, 'seq': 4, 'offsets': [3, 5]}},
            {'request_id': 'b'*64, 'opposite_observed_elsewhere': False,
             'observed_site': {'pc': 3, 'seq': 5, 'offsets': [1]}},
            {'request_id': 'c'*64, 'opposite_observed_elsewhere': True,
             'observed_site': {'pc': 4, 'seq': 6, 'offsets': [0, 1, 2, 3, 5]}}]
        union = (0, 1, 2, 3, 5)
        focus = policy.focused_masks(requests, union)
        self.assertEqual(focus, ((1,), (3, 5)))
        schedule = policy.BranchFocusedSchedule(union, requests)
        values = [schedule.next(i, 8) for i in range(1, 33)]
        self.assertTrue(all(set(mask) <= set(union) for mask, _, _ in values))
        self.assertEqual(set(values[i][2] for i in range(24, 32)), {'full_union_fallback'})
        self.assertEqual(schedule.focused_mutations, 24)
        self.assertEqual(schedule.fallback_mutations, 8)
        for mask, ordinal, _ in values:
            out, _, _ = policy.masked_mutation(b'abcdefgh', mask, ordinal)
            self.assertTrue(set(policy.diff_offsets(b'abcdefgh', out)) <= set(mask))

    def test_if_every_site_taints_every_byte_no_false_focus_claim(self):
        requests = [{'request_id':'a'*64, 'opposite_observed_elsewhere':False,
                     'observed_site': {'pc':1,'seq':5,'offsets':[0,1,2,3]}}]
        schedule = policy.BranchFocusedSchedule((0, 1, 2, 3), requests)
        self.assertEqual(schedule.focus, ())
        self.assertEqual(schedule.next(1, 4)[2], 'full_union_fallback')
        with self.assertRaises(RuntimeError):
            policy.focused_masks(requests, (0, 2))


class ForensicsTests(unittest.TestCase):
    def test_readonly_distinguishes_failed_audit_from_unsolved_candidate(self):
        with tempfile.TemporaryDirectory() as tmp:
            campaign = Path(tmp)
            save(campaign / 'hybrid-result.json', {'DSE_jobs': [
                {'job': 2, 'status': 'FAILED', 'request_id': 'f'*64}]})
            job = campaign / 'dse/job-02'
            (job / 'jobs/0000/recapture-0001').mkdir(parents=True)
            save(job / 'summary.json', {'status': 'passed', 'dse_status': 'UNKNOWN', 'new_seed_count': 0})
            save(job / 'jobs/0000/recapture-0001/summary.json', {'status': 'passed', 'dse_status': 'OBSERVED'})
            result = forensics.diagnose(campaign, 2)
            self.assertEqual(result['classification'], 'no_verified_new_candidate')
            self.assertEqual(len([v for v in result['evidence'] if v['present']]), 2)
            save(job / 'summary.json', {'status': 'passed', 'dse_status': 'VERIFIED', 'new_seed_count': 1})
            self.assertEqual(forensics.diagnose(campaign, 2)['classification'],
                             'post_publication_fresh_audit_or_controller_binding_failed')
            save(job / 'summary.json', {'status': 'failed', 'dse_status': 'NOT_RUN'})
            self.assertEqual(forensics.diagnose(campaign, 2)['classification'],
                             'extend_corpus_or_worker_publication_failed')
            self.assertFalse((job / 'diagnostic.json').exists())


class AblationTests(unittest.TestCase):
    @staticmethod
    def case(folder, input_bytes, bits, branches, *, with_transport=False):
        folder.mkdir(parents=True)
        raw_bitmap = bytearray(policy.MAP_SIZE)
        for index in bits:
            raw_bitmap[index] = 1
        (folder / 'input').write_bytes(input_bytes)
        (folder / 'coverage.map').write_bytes(raw_bitmap)
        receipt = {'schema': 1, 'status': 'passed',
                   'input_sha256': digest(input_bytes), 'phase1_executed': False,
                   'hostile_sample_ready': False,
                   'coverage': {'status': 'verified', 'map_sha256': digest(raw_bitmap),
                                'branch_outcomes': branches}}
        save(folder / 'result.json', receipt)
        binding = {'target_sha256': 'b'*64, 'input_sha256': digest(input_bytes),
                   'run_dir': str(folder)}
        binding['attempt_contract_sha256'] = backend.contract(binding)
        save(folder / 'config/rebuilt_binding.json', binding)
        if with_transport:
            save(folder / 'transport.json', {'status': 'delivered',
                'case': int(folder.name),
                'input_sha256': digest(input_bytes), 'coverage_sha256': digest(raw_bitmap),
                'feedback': 'verified_guest_coverage'})

    def test_coverage_is_measured_at_matching_delivered_case_budget(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.case(root / 'baseline/00-0', b'x', [1], [[100, 0]])
            self.case(root / 'baseline/00-1', b'x', [1], [[100, 0]])
            self.case(root / 'cases/00000000', b'y', [1, 2], [[100, 0], [101, 1]],
                      with_transport=True)
            self.case(root / 'cases/00000001', b'z', [3], [[102, 0]], with_transport=True)
            target = 'b' * 64
            save(root / 'campaign.json', {'status': 'completed', 'afl_exit': 0,
                 'target_sha256': target, 'phase1_executed': False,
                 'cases': 2, 'delivered_cases': 2, 'quarantined_cases': 0,
                 'afl_seed': 42})
            save(root / 'baseline.json', {'stable': True, 'branch_outcomes': [[100, 0]]})
            report = ablation.measure_campaign(root, target_sha256=target)
            self.assertEqual([i['branch_outcomes'] for i in report['history']], [1, 2, 3])
            self.assertEqual([i['map_slots'] for i in report['history']], [1, 2, 3])
            runs = [{'replicate': 1, 'arm': arm, 'metrics': report,
                     'total_elapsed_seconds': 10} for arm in ('A', 'B', 'C')]
            values = ablation.comparisons(runs)
            self.assertEqual(len(values), 3)
            self.assertEqual(values[0]['common_delivered_executions'], 2)
            save(root / 'cases/00000001/transport.json', {'status': 'delivered',
                'input_sha256': 'bad', 'coverage_sha256': 'bad', 'feedback': 'verified_guest_coverage'})
            with self.assertRaises(ValueError):
                ablation.measure_campaign(root, target_sha256=target)

    def test_incomplete_replicate_cannot_be_labeled_comparable(self):
        with self.assertRaises(ValueError):
            ablation.comparisons([{'replicate': 1, 'arm': 'A'}])


class AblationPlanTests(unittest.TestCase):
    def test_plan_has_balanced_five_arms_and_distinct_replicate_seeds(self):
        from scripts import run_hybrid_ablation as study
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'seeds').mkdir()
            (root / 'seeds/initial').write_bytes(b'AA' + b'x' * 30)
            (root / 'rebuilt.elf').write_bytes(b'reviewed fixture identity')
            (root / 'qemu').write_bytes(b'qemu stub')
            (root / 'plugin.so').write_bytes(b'plugin stub')
            (root / 'plugin.so.runtime.json').write_bytes(b'{}')
            (root / 'flags.json').write_bytes(b'{}')
            args = study.arguments([
                '--binary', str(root / 'rebuilt.elf'), '--seeds', str(root / 'seeds'),
                '--qemu', str(root / 'qemu'), '--plugin', str(root / 'plugin.so'),
                '--flags-receipt', str(root / 'flags.json'), '--out', str(root / 'study'),
                '--replicates', '5', '--seconds', '300', '--plan-only'])
            plan = study.run(args)
            self.assertEqual(len(plan['requested_runs']), 25)
            for replicate in range(1, 6):
                items = [row for row in plan['requested_runs'] if row['replicate'] == replicate]
                self.assertEqual({row['arm'] for row in items}, {'A', 'B', 'C1', 'C2', 'D'})
                self.assertEqual({row['afl_seed'] for row in items}, {41 + replicate})
            self.assertEqual(plan['maximum_reserved_disk_mib'], 25 * 2048)
            self.assertFalse((root / 'study').exists())


class BoundaryTests(unittest.TestCase):
    def test_phase1_consistency_is_not_an_oep_or_hostile_readiness_proof(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            packed, rebuilt = b'packed', b'rebuilt-test'
            (root / 'inputs').mkdir()
            (root / 'inputs/packed.elf').write_bytes(packed)
            (root / 'rebuilt.elf').write_bytes(rebuilt)
            save(root / 'summary.json', {'status': boundary.UNPACK_STATUS, 'errors': [],
                'all_selected_cases_match': True, 'rebuilt_sha256': digest(rebuilt),
                'packed_sha256': digest(packed), 'oep_proven': False,
                'fuzzing_ready': False, 'protected_channel': False})
            save(root / 'rebuild.json', {'elf_sha256': digest(rebuilt)})
            result = boundary.phase1_source(root, target_sha256=digest(rebuilt))
            self.assertTrue(result['recovered_source_consistency_verified'])
            self.assertFalse(result['OEP_proven'])
            self.assertFalse(result['phase1_executed_in_rebuilt_AFL_campaign'])
            with self.assertRaises(ValueError):
                boundary.phase1_source(root, target_sha256=digest(b'changed'))

    def test_case_capsule_receipts_bound_to_exact_input_and_namespace(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            case = root / 'cases/00000000'
            (case / 'rootfs/bin').mkdir(parents=True)
            (case / 'rootfs/etc').mkdir()
            (case / 'rootfs/etc/dta-input').write_bytes(b'A')
            (case / 'rootfs/bin/sample.elf').write_bytes(b'ELF')
            (case / 'input').write_bytes(b'A')
            parent = {name: f'host-{name}' for name in boundary.EXPECTED_NS}
            config = capsule_resources.policy(512, 30)
            binding = {'profile': backend.PROFILE, 'run_dir': str(case),
                'rootfs': str(case / 'rootfs'), 'attempt_id': 'case-1',
                'lifecycle_attempt': 'a'*32,
                'target_sha256': digest(b'ELF'), 'input_sha256': digest(b'A'),
                'bundle_sha256': 'r'*64, 'coverage_plugin_sha256': 'p'*64,
                'settings': {'resources': config},
                'input_path': '/etc/dta-input', 'host_namespaces': parent}
            binding['attempt_contract_sha256'] = backend.contract(binding)
            token = binding['attempt_contract_sha256']
            save(case / 'config/rebuilt_binding.json', binding)
            from taintforge_env.phase1_runtime import digest as file_digest
            unit = capsule_resources.unit_name(binding)
            limits = {'memory.max': str(config['memory_bytes']), 'memory.swap.max': '0',
                      'memory.oom.group': '1', 'pids.max': str(config['tasks'])}
            service = {'status': 'verified', 'tree_empty': True, 'wrapper_exit': 0,
                'attempt_id': 'case-1', 'attempt_contract_sha256': token, 'unit': unit,
                'service': {'Result': 'success'}}
            resources = {'status': 'verified', 'attempt_id': 'case-1',
                'attempt_contract_sha256': token, 'unit': unit,
                'limits': limits, 'cgroup': '/system.slice/' + unit,
                'no_new_privs': True, 'core_rlimit': [0, 0],
                'memory_isolation': False, 'hostile_sample_ready': False}
            save(case / 'logs/capsule/service.json', service)
            save(case / 'logs/capsule/resources.json', resources)
            from experiments.execution_capsule_probe import controller as probe
            checked = {'status': 'verified', 'limits': limits, 'tree_empty': True,
                'unit': unit, 'evidence_sha256': {
                    name: probe.sha(case / 'logs/capsule' / name)
                    for name in ('resources.json', 'service.json')}}
            save(case / 'result.json', {'status': 'passed', 'guest_exit': 0,
                'input_sha256': digest(b'A'), 'phase1_executed': False,
                'hostile_sample_ready': False, 'protected_control_channel': False,
                'resources': checked})
            save(case / 'logs/capsule/namespaces.json', {'request_sha256': token,
                'host': parent, 'observed': {n: f'guest-{n}' for n in parent}})
            campaign = {'target_sha256': digest(b'ELF'), 'runtime_sha256': 'r'*64,
                        'coverage_plugin_sha256': 'p'*64}
            self.assertEqual(boundary.audited_case(case, campaign)['attempt_id'], 'case-1')
            service['tree_empty'] = False
            save(case / 'logs/capsule/service.json', service)
            with self.assertRaises(ValueError):
                boundary.audited_case(case, campaign)


if __name__ == '__main__':
    unittest.main(verbosity=2)
