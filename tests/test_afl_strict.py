"""Calibration binding and CLI failures without substituting a native acceptance."""
import contextlib
import copy
import io
import json
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from scripts import run_afl_file as cli, verify_afl_strict_e2e as native
from taintforge_env import afl_strict as a, afl_warm as w, capsule_strict as s


class PreparationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.qemu, self.plugin = self.root/'qemu', self.root/'plugin'
        self.qemu.write_bytes(b'qemu identity fixture')
        self.plugin.write_bytes(b'plugin identity fixture')
        self.out = self.root/'campaign'
        self.options = dict(binary=self.root/'sample', qemu=self.qemu, plugin=self.plugin,
                            guest_path='/etc/input', seeds=self.root/'seeds', phase2_mode='parallel')
        self.symbols = ''.join('000000 T '+name+'\n' for name in sorted(a.SYMBOLS))

    def recorded_calibration(self, qemu, plugin, out):
        out.mkdir()
        (out/'probe').mkdir()
        receipt = out/'probe/flags.receipt'
        receipt.write_bytes(s.receipt_bytes(s.digest(qemu)))
        summary = {'schema_version': 1, 'status': 'PASS_QEMU_PUSHF_BOUNDARY_PROBE',
            'artifacts_unchanged': True, 'errors': [], 'receipt_sha256': s.digest(receipt),
            'runs': {mode: {'checked': 32, 'exit': 0, 'valid': True, 'mismatches': []}
                     for mode in ('normal', 'single')}}
        s.save(out/'probe/summary.json', summary)
        s.save(out/'calibration.json', {'schema': 1, 'status': 'passed',
            'scope': 'bounded_i386_eflags_observations', 'qemu_sha256': s.digest(qemu),
            'plugin_sha256': s.digest(plugin), 'receipt_sha256': s.digest(receipt),
            'probe_summary_sha256': s.digest(out/'probe/summary.json'),
            'universal_equivalence': False, 'probe': summary})
        return receipt

    def prepared(self, out, **options):
        out.mkdir()
        if options.get('flags_receipt') is not None:
            (out/'bound.receipt').write_bytes(Path(options['flags_receipt']).read_bytes())
        return {'status': 'prepared', 'assets': {}}

    def test_strict_calibrates_before_preparation_and_retains_bound_evidence(self):
        with patch.object(a.f.p, 'command', return_value=self.symbols), \
             patch.object(s, 'calibration', side_effect=self.recorded_calibration) as calibration, \
             patch.object(w, 'prepare_campaign', side_effect=self.prepared) as prepare:
            result = a.prepare_campaign(self.out, **self.options)
        calibration.assert_called_once()
        self.assertEqual(prepare.call_args.kwargs['analysis_policy'], 'strict')
        self.assertEqual((self.out/'bound.receipt').read_bytes(), s.receipt_bytes(s.digest(self.qemu)))
        checked = a.calibration_ok(self.out/'flags-calibration', qemu=self.qemu, plugin=self.plugin)
        self.assertEqual(result['flags_calibration'], {'schema': 1, 'profile': a.PROFILE,
            'directory': 'flags-calibration', 'status': 'passed', **checked})
        self.assertGreaterEqual(len(result['assets']), 3)
        for name, digest in result['assets'].items():
            self.assertEqual(s.digest(name), digest)
        self.assertEqual(json.loads((self.out/'campaign.json').read_text()), result)

    def test_invalid_calibration_never_prepares_a_campaign(self):
        def incomplete(qemu, plugin, out):
            receipt = self.recorded_calibration(qemu, plugin, out)
            summary = a.f.read_json(out/'probe/summary.json')
            summary['runs']['normal']['checked'] = 31
            s.save(out/'probe/summary.json', summary)
            report = a.f.read_json(out/'calibration.json')
            report.update(probe=summary, probe_summary_sha256=s.digest(out/'probe/summary.json'))
            s.save(out/'calibration.json', report)
            return receipt
        with patch.object(a.f.p, 'command', return_value=self.symbols), \
             patch.object(s, 'calibration', side_effect=incomplete), \
             patch.object(w, 'prepare_campaign') as prepare:
            with self.assertRaisesRegex(RuntimeError, 'incomplete or mismatched'):
                a.prepare_campaign(self.out, **self.options)
        prepare.assert_not_called()
        self.assertTrue((self.out/'flags-calibration/calibration.json').is_file())
        self.assertFalse((self.out/'campaign.json').exists())

    def test_changed_runtime_cannot_reuse_a_receipt(self):
        self.recorded_calibration(self.qemu, self.plugin, self.root/'calibration')
        for path in (self.qemu, self.plugin):
            with self.subTest(path=path.name):
                old = path.read_bytes()
                path.write_bytes(old+b'changed')
                with self.assertRaises((ValueError, RuntimeError)):
                    a.calibration_ok(self.root/'calibration', qemu=self.qemu, plugin=self.plugin)
                path.write_bytes(old)

    def test_nonpassing_probe_and_boolean_counter_are_rejected(self):
        self.recorded_calibration(self.qemu, self.plugin, self.root/'calibration')
        root = self.root/'calibration'
        original = a.f.read_json(root/'probe/summary.json')
        for key, value in (('checked', True), ('valid', False), ('exit', 1), ('mismatches', [1])):
            with self.subTest(key=key):
                summary = copy.deepcopy(original)
                summary['runs']['single'][key] = value
                s.save(root/'probe/summary.json', summary)
                report = a.f.read_json(root/'calibration.json')
                report.update(probe=summary, probe_summary_sha256=s.digest(root/'probe/summary.json'))
                s.save(root/'calibration.json', report)
                with self.assertRaises(RuntimeError):
                    a.calibration_ok(root, qemu=self.qemu, plugin=self.plugin)

    def test_explicit_matching_receipt_is_reused_without_calibration(self):
        receipt = self.root/'receipt'
        receipt.write_bytes(s.receipt_bytes(s.digest(self.qemu)))
        with patch.object(a.f.p, 'command', return_value=self.symbols), \
             patch.object(s, 'calibration') as calibration, \
             patch.object(w, 'prepare_campaign', return_value={'status': 'prepared'}) as prepare:
            a.prepare_campaign(self.out, flags_receipt=receipt, **self.options)
        calibration.assert_not_called()
        self.assertEqual(prepare.call_args.kwargs['flags_receipt'], receipt)

    def test_wrong_explicit_receipt_fails_before_preparation(self):
        receipt = self.root/'receipt'
        receipt.write_bytes(s.receipt_bytes('0'*64))
        with patch.object(a.f.p, 'command', return_value=self.symbols), \
             patch.object(w, 'prepare_campaign') as prepare:
            with self.assertRaises(ValueError):
                a.prepare_campaign(self.out, flags_receipt=receipt, **self.options)
        prepare.assert_not_called()

    def test_research_remains_an_explicit_policy(self):
        with patch.object(a.f.p, 'command', return_value=self.symbols), \
             patch.object(s, 'calibration') as calibration, \
             patch.object(w, 'prepare_campaign', return_value={'status': 'prepared'}) as prepare:
            a.prepare_campaign(self.out, analysis_policy='research', **self.options)
        calibration.assert_not_called()
        self.assertEqual(prepare.call_args.kwargs['analysis_policy'], 'research')

    def test_abi2_is_rejected_before_calibration_or_output_creation(self):
        symbols = self.symbols.replace('000000 T qemu_plugin_tf_warm_abi3\n', '')
        with patch.object(a.f.p, 'command', return_value=symbols), \
             patch.object(s, 'calibration') as calibration, \
             patch.object(w, 'prepare_campaign') as prepare:
            with self.assertRaisesRegex(RuntimeError, 'ABI 3'):
                a.prepare_campaign(self.out, **self.options)
        calibration.assert_not_called()
        prepare.assert_not_called()
        self.assertFalse(self.out.exists())


class CliTests(unittest.TestCase):
    def arguments(self):
        return ['run_afl_file', 'campaign', '--binary', '/tmp/sample', '--qemu', '/tmp/qemu',
                '--plugin', '/tmp/plugin', '--seeds', '/tmp/seeds', '--guest-file', '/etc/input',
                '--out', '/tmp/campaign']

    def test_receipt_and_ir_boundary_reach_strict_preparation(self):
        for mode in ('parallel', 'sequential'):
            with self.subTest(mode=mode), \
                 patch.object(sys, 'argv', self.arguments()+['--phase2-mode', mode,
                     '--flags-receipt', '/tmp/flags.receipt', '--ir-start', '0x8048123']), \
                 patch.object(a, 'prepare_campaign', return_value={'status': 'prepared'}) as prepare, \
                 patch('taintforge_env.afl_transport.run_campaign', return_value={'status': 'completed'}), \
                 contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(cli.main(), 0)
                self.assertEqual(prepare.call_args.kwargs['flags_receipt'], Path('/tmp/flags.receipt'))
                self.assertEqual(prepare.call_args.kwargs['ir_start'], 0x8048123)
                self.assertEqual(prepare.call_args.kwargs['analysis_policy'], 'strict')
                self.assertEqual(prepare.call_args.kwargs['phase2_mode'], mode)

    def test_calibration_failure_never_starts_afl_and_keeps_strict(self):
        with patch.object(sys, 'argv', self.arguments()), \
             patch.object(a, 'prepare_campaign', side_effect=RuntimeError('flags mismatch')) as prepare, \
             patch('taintforge_env.afl_transport.run_campaign') as run, \
             contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(cli.main(), 2)
        self.assertEqual(prepare.call_count, 1)
        self.assertEqual(prepare.call_args.kwargs['analysis_policy'], 'strict')
        run.assert_not_called()


class AcceptanceTests(unittest.TestCase):
    def test_unavailable_native_environment_is_never_reported_as_passed(self):
        with tempfile.TemporaryDirectory() as directory:
            result = native.verify(Path(directory)/'native', qemu=Path(directory)/'missing-qemu')
            self.assertEqual(result['status'], 'blocked_environment')
            self.assertFalse(result['native_strict_positive_verified'])
            self.assertFalse(result['native_strict_negative_verified'])

    def test_invalid_limits_do_not_create_an_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)/'native'
            for options in ({'executions': True}, {'seconds': 0}, {'modes': ('off',)}):
                with self.subTest(options=options), self.assertRaises(RuntimeError):
                    native.verify(root, qemu='/missing/qemu', **options)
                self.assertFalse(root.exists())

    @unittest.skipUnless(all(shutil.which(tool) for tool in ('as', 'ld', 'nm', 'strip', 'objcopy')),
                         'GNU binutils required')
    def test_fast_fixture_uses_64_selection_iterations_instead_of_retirement_delay(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            built = s.build_fixture(root/'fixture', handoff_loops=64)
            obj = root/'fixture/guest.o'
            binary = root/'rodata'
            subprocess.run(['objcopy', '--dump-section', '.rodata='+str(binary), str(obj)], check=True)
            symbols = subprocess.check_output(['nm', '-P', str(obj)], text=True)
            address = next(int(line.split()[2], 16) for line in symbols.splitlines()
                           if line.startswith('payload_source '))
            data = binary.read_bytes()[address:]
            self.assertEqual(data[0], 0xb9)
            self.assertEqual(struct.unpack_from('<I', data, 1)[0], 64)
            self.assertEqual(built['handoff_work_iterations'], 64)
            self.assertTrue(built['input']['static'])
            for loops in (0, -1, True, s.HANDOFF_LOOPS+1):
                with self.subTest(loops=loops), self.assertRaises(ValueError):
                    s.build_fixture(root/'invalid', handoff_loops=loops)


if __name__ == '__main__':
    unittest.main()
