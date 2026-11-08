"""Offline regressions for fixture portability, semantic checks and run admission."""
from contextlib import redirect_stdout, redirect_stderr
import copy
import hashlib
from io import StringIO
import json
import os
from pathlib import Path
import shutil
import struct
import tempfile
import unittest
from unittest.mock import patch
import zipfile

import corpus
import run as runner
import support

ROOT = Path(__file__).resolve().parent
DEFINITION = support.read(ROOT / 'cases.json')


class ModelTests(unittest.TestCase):
    def test_known_independent_vectors(self):
        self.assertEqual(corpus.model(0, b'12aF'), 0x12af)
        self.assertEqual(corpus.model(1, bytes([3, 1, 2, 3])), 0x030201)
        self.assertEqual(corpus.model(2, bytes([0xe5, 0x8e, 0x26])), 624485)
        self.assertEqual(corpus.model(3, b''), 2166136261)
        self.assertEqual(corpus.model(4, b'123456789'), 0xf4)
        self.assertEqual(corpus.model(6, bytes.fromhex('78563412')), 0x78563412)

    def test_bt_index_wraps_at_32(self):
        for index in range(256):
            self.assertEqual(corpus.model(5, bytes([index])), (0x800013 >> (index % 32)) & 1)

    def test_signed_clamp_extremes(self):
        for value, expected in ((0, 1000), (0x7fffffff, 2000), (0x80000000, 0), (0xffffffff, 999)):
            self.assertEqual(corpus.model(7, value.to_bytes(4, 'little') + b'\0'), expected)

    def test_integer_normalization_uses_a_nonzero_input_divisor(self):
        self.assertEqual(corpus.model(7, bytes.fromhex('c409000002')), 666)
        self.assertEqual(corpus.model(7, bytes.fromhex('c40900000f')), 125)

    def test_invalid_and_truncated_inputs(self):
        for kind, data in ((0, b'1'), (1, b''), (1, bytes([5, 0, 0, 0, 0, 0])),
                           (2, bytes([0x80]) * 4), (5, b''), (6, b'123'), (7, b'123')):
            self.assertEqual(corpus.model(kind, data), 0xffffffff)


class FixtureTests(unittest.TestCase):
    def test_all_six_cases_have_bound_inputs_outputs_and_paths(self):
        self.assertEqual(len(DEFINITION['cases']), 6)
        for row in DEFINITION['cases']:
            expected = support.verify_case(ROOT, row)
            self.assertEqual(expected['baseline_route'][-1][0], row['pc'])
            self.assertEqual(expected['witness_route'][-1][0], row['pc'])

    def test_fixtures_survive_directory_relocation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            shutil.copytree(ROOT / 'data', root / 'data')
            for row in DEFINITION['cases']: support.verify_case(root, row)

    def test_six_witnesses_are_distinct(self):
        self.assertEqual(len({r['witness_sha256'] for r in DEFINITION['cases']}), 6)

    def test_expected_data_has_no_historical_host_paths(self):
        for row in DEFINITION['cases']:
            self.assertNotIn('/home/', (ROOT / row['data'] / 'expected.json').read_text())

    def test_semantic_regressions_accept_actual_archived_runs(self):
        workspace = os.environ.get('TF_REG_WORKSPACE')
        if not workspace: self.skipTest('Set TF_REG_WORKSPACE for archive integration checks')
        for row in DEFINITION['cases']:
            if row['pc'] in (0x8049388, 0x8049390):
                archive = 'taintforge_bt_recapture_reports_x9wk9bsf.zip'
                prefix = 'selected-' + hex(row['pc'])
            else:
                archive = 'taintforge_unknown_recheck_tfur.4_uu3fwe_reports.zip'
                index = (0x80493f9, 0x8049383, 0x8049437, 0x804943c).index(row['pc']) + 1
                prefix = 'request-%02d-%s' % (index, hex(row['pc']))
            with zipfile.ZipFile(Path(workspace) / 'upload' / archive) as z:
                worker = prefix + '/jobs/0000/inversion/'
                summary = json.loads(z.read(worker + 'summary.json'))
                solved = json.loads(z.read(worker + 'solve/logs/phase1/concolic.json'))
                observed = json.loads(z.read(worker + 'observe/logs/phase1/concolic.json'))
                expected = support.verify_case(ROOT, row)
                seed = z.read(worker + 'solve/input.bin'); candidate = z.read(worker + 'observe/input.bin')
                support.check_inversion(row, expected, summary, solved, observed, seed, candidate)
                support.check_saved_witness(row, expected, observed)
                bad = copy.deepcopy(observed); bad['taken'] = not bad['taken']
                with self.assertRaisesRegex(RuntimeError, 'invert'):
                    support.check_inversion(row, expected, summary, solved, bad, seed, candidate)
                bad = copy.deepcopy(observed); bad['trace'][0]['next_pc'] += 1
                with self.assertRaisesRegex(RuntimeError, 'prefix'):
                    support.check_inversion(row, expected, summary, solved, bad, seed, candidate)
                wrong = bytes([candidate[0] ^ 1]) + candidate[1:]
                modified = dict(summary, candidate_sha256=hashlib.sha256(wrong).hexdigest())
                with self.assertRaisesRegex(RuntimeError, 'input scope'):
                    support.check_inversion(row, expected, modified, solved, observed, seed, wrong)

    def test_incomplete_replay_cannot_pass(self):
        with self.assertRaisesRegex(RuntimeError, 'completely lifted'):
            support.ready({'replay_build': {'status': 1, 'issues': 8, 'selected_steps': 10, 'lifted_steps': 9}})

    def test_golden_seed_corruption_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); shutil.copytree(ROOT / 'data', root / 'data')
            row = DEFINITION['cases'][0]; (root / row['data'] / 'seed').write_bytes(b'drift')
            with self.assertRaisesRegex(RuntimeError, 'data changed'): support.verify_case(root, row)


class WorkflowTests(unittest.TestCase):
    def test_offline_mode_never_loads_project_runtime(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(runner, 'runtime') as runtime, \
             patch.object(corpus, 'legacy_oracle', return_value=(None, {'checks': 12})), \
             redirect_stdout(StringIO()):
            code = runner.main(['--output-dir', temporary, '--suite', 'regression', '--offline-only'])
            self.assertEqual(code, 0); runtime.assert_not_called()
            summary = support.read(next(Path(temporary).glob('tfreg.*/summary.json')))
            self.assertEqual(summary['status'], 'OFFLINE_PASS_GUESTS_NOT_RUN')
            self.assertFalse(summary['guest_execution_requested'])
            self.assertEqual(summary['regressions'], [])

    def test_final_guard_failure_invalidates_offline_success(self):
        with tempfile.TemporaryDirectory() as temporary, \
             patch.object(corpus, 'legacy_oracle', return_value=(None, {'checks': 12})), \
             patch.object(runner, 'check_guards', side_effect=RuntimeError('source drift')), \
             redirect_stdout(StringIO()), redirect_stderr(StringIO()):
            code = runner.main(['--output-dir', temporary, '--suite', 'regression', '--offline-only'])
            self.assertEqual(code, 1)
            summary = support.read(next(Path(temporary).glob('tfreg.*/summary.json')))
            self.assertEqual(summary['status'], 'INCOMPLETE')

    def test_reconstruction_mismatch_cannot_publish(self):
        class Adapter:
            def observe_file(self, **kwargs): return {'status': 'passed'}
            def audit_file_run(self, **kwargs): return {'status': 'failed'}
        with self.assertRaisesRegex(RuntimeError, 'reconstruction'):
            runner.audited(Adapter(), 'observe_file', {}, Path('/unused'))

    def test_ranking_preserves_distinct_elf_identities(self):
        rows = []
        for index in range(2):
            rows.append({'id': str(index), 'status': 'UNKNOWN', 'binary_sha256': str(index) * 64,
                'diagnostic': {'bucket': 'unsupported_instruction', 'replay_build': {
                    'stopped_origin': {'pc': 0x1000, 'bytes': '0fa3d8', 'seq': 4}}}})
        ranked = runner.rank_stops(rows)
        self.assertEqual(ranked[0]['affected_elf_count'], 2)
        self.assertEqual(len({r['binary_sha256'] for r in ranked[0]['cases']}), 2)

    def test_unknown_without_explicit_stop_is_not_ranked(self):
        value = runner.rank_stops([{'status': 'UNKNOWN', 'diagnostic': {'bucket': 'replay_unknown_without_location'}}])
        self.assertEqual(value, [])

    def test_export_includes_probe_elf_and_excludes_guest_trees(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); (root / 'corpus-build').mkdir(); (root / 'corpus-build/a.elf').write_bytes(b'fixture')
            (root / 'snapshots').mkdir(); (root / 'snapshots/private.json').write_text('{}')
            with redirect_stdout(StringIO()): support.export_reports(root)
            with zipfile.ZipFile(next(root.glob('*_reports.zip'))) as z:
                self.assertIn('corpus-build/a.elf', z.namelist()); self.assertNotIn('snapshots/private.json', z.namelist())

    def test_built_corpus_has_24_bound_branch_sites(self):
        build = os.environ.get('TF_REG_BUILD')
        if not build: self.skipTest('Set TF_REG_BUILD for compiled ELF integration checks')
        manifest = support.read(Path(build) / 'build.json')
        self.assertEqual(len(manifest['cases']), 24)
        self.assertEqual(manifest['native_model_comparisons'], 12384)
        for row in manifest['cases']:
            code = corpus.instruction_bytes(row['binary'], row['pc'], 2)
            self.assertEqual(code.hex(), row['branch_bytes'])
            self.assertEqual(code[0], 0x75)
            self.assertEqual(support.digest(row['binary']), row['binary_sha256'])


if __name__ == '__main__': unittest.main()
