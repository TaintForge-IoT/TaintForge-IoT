import json
import os
from pathlib import Path
import platform
import shutil
import shlex
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from taintforge_env import capsule_strict as s, unified_runtime as u
from taintforge_env.elf_runtime import ElfImage
from tests.test_unified_pipeline import fake_toolchain


class NativeTargetProofTests(unittest.TestCase):
    def test_symbolic_main_image_target_needs_the_guard(self):
        cflags = os.environ.get('TF_PLUGIN_CPPFLAGS')
        libs = os.environ.get('TF_PLUGIN_LIBS')
        if not all(shutil.which(tool) for tool in ('gcc', 'pkg-config')):
            self.skipTest('C compiler and pkg-config required')
        if not (cflags and libs):
            if subprocess.run(['pkg-config', '--exists', 'glib-2.0', 'capstone', 'z3'],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode:
                self.skipTest('GLib/Capstone/Z3 development packages required')
            cflags = subprocess.check_output(['pkg-config', '--cflags', 'glib-2.0', 'capstone', 'z3'], text=True)
            libs = subprocess.check_output(['pkg-config', '--libs', 'glib-2.0', 'capstone', 'z3'], text=True)
        names = ('dcfg dta trace aux_trace provenance replay_input replay_sources ir ir_eval ir_opt '
                 'ir_lift_x86 ir_environment ir_replay ir_inputs ir_runtime ir_ssa ir_smt ir_branches '
                 'ir_oep runtime_diag qemu_flags_contract dse dse_lift_x86 trace_deps trace_deps_x86').split()
        source = s.PROJECT/'unpacker/test'
        flags = ['-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-I'+str(source),
                 '-I'+str(s.PROJECT/'unpacker/mvp/tests/native'), *shlex.split(cflags)]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            objects = []
            for name in names:
                obj = root/(name+'.o')
                subprocess.run(['gcc', *flags, '-c', str(source/(name+'.c')), '-o', str(obj)], check=True)
                objects.append(str(obj))
            binary = root/'target-proof'
            subprocess.run(['gcc', *flags, str(s.HERE/'target_proof_test.c'), *objects,
                            *shlex.split(libs), '-lm', '-pthread', '-o', str(binary)], check=True)
            result = subprocess.run([str(binary)], capture_output=True, text=True, check=True)
            rows = [json.loads(line) for line in result.stdout.splitlines()]
            self.assertEqual([(r['guarded'], r['verdict'], r['reason']) for r in rows],
                             [(True, 'CONFIRMED', 'NONE'), (False, 'UNKNOWN', 'NONUNIQUE_TARGET')])
            self.assertTrue(all(r['target_symbolic'] and r['replay_valid'] and r['proof_eligible'] for r in rows))


class LoadedImageTests(unittest.TestCase):
    def test_native_image_identity_direct_and_through_loader(self):
        if not shutil.which('gcc'):
            self.skipTest('gcc required')
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory)/'identity'
            subprocess.run(['gcc', '-std=gnu11', '-O2', '-Wall', '-Wextra', '-Werror', '-rdynamic',
                '-I', str(s.PROJECT/'unpacker/test'), str(s.HERE/'loaded_image_test.c'), '-ldl',
                '-o', str(binary)], check=True)
            loader = ElfImage(binary).target.interpreter
            direct = subprocess.run([str(binary), str(binary)], check=True, capture_output=True, text=True)
            indirect = subprocess.run([loader, str(binary), str(binary)], check=True, capture_output=True, text=True)
            self.assertEqual(json.loads(direct.stdout), {'image_matches': True, 'proc_exe_matches': True})
            self.assertEqual(json.loads(indirect.stdout), {'image_matches': True, 'proc_exe_matches': False})
            wrong = subprocess.run([loader, str(binary), loader], capture_output=True, text=True)
            self.assertEqual(wrong.returncode, 4)
            self.assertFalse(json.loads(wrong.stdout)['image_matches'])


class StrictFixtureTests(unittest.TestCase):
    def test_payload_finishes_bounded_work_before_the_first_input(self):
        if platform.machine() != 'x86_64' or not all(shutil.which(tool) for tool in
                                                     ('as', 'ld', 'strip', 'nm', 'objcopy', 'gcc')):
            self.skipTest('x86_64 and GNU toolchain required')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            guest = s.build_fixture(root/'fixture')
            symbols = subprocess.check_output(['nm', '-P', str(root/'fixture/guest.o')], text=True)
            addresses = {parts[0]: int(parts[2], 16) for parts in
                         (line.split() for line in symbols.splitlines()) if parts[0] in
                         {'payload_source', 'payload_input'}}
            data = root/'rodata.bin'
            subprocess.run(['objcopy', '--dump-section', '.rodata='+str(data),
                            str(root/'fixture/guest.o')], check=True)
            payload = data.read_bytes()[addresses['payload_source']:]
            size = addresses['payload_input']-addresses['payload_source']
            self.assertEqual(guest['handoff_work_iterations'], 20000000)
            self.assertEqual(payload[0], 0xb9)
            self.assertEqual(struct.unpack_from('<I', payload, 1)[0], guest['handoff_work_iterations'])
            self.assertEqual(payload[size:size+5], b'\xb8\x05\0\0\0')
            (root/'work.bin').write_bytes(payload[:size])
            assembly = root/'work.S'
            assembly.write_text('.text\n.globl handoff_work\nhandoff_work:\n'
                                '.incbin "'+str(root/'work.bin')+'"\n'
                                'movl %ecx, %eax\nret\n.section .note.GNU-stack,"",@progbits\n')
            source = root/'main.c'
            source.write_text('extern unsigned int handoff_work(void);\n'
                              'int main(void) { return handoff_work() != 0; }\n')
            binary = root/'work'
            subprocess.run(['gcc', '-Wall', '-Wextra', '-Werror', str(source), str(assembly),
                            '-o', str(binary)], check=True)
            subprocess.run([str(binary)], check=True, timeout=10)

    def test_guests_are_stripped_static_i386_with_separate_guard_paths(self):
        if not shutil.which('as') or not shutil.which('ld'):
            self.skipTest('binutils required')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            guests = [s.build_fixture(root/name, negative=negative)
                      for name, negative in [('positive', False), ('negative', True)]]
            for guest in guests:
                self.assertTrue(guest['input']['static'])
                self.assertEqual(guest['input']['arch'], 'i386')
                image = ElfImage(Path(guest['path']))
                at = image.offset_for(guest['target_word_address'], 4)
                self.assertEqual(struct.unpack_from('<I', image.data, at)[0], guest['expected_oep'])
                self.assertEqual(guest['target_source'], 'main_elf_file_bytes')
                self.assertFalse((Path(guest['path']).parent/'target-input').exists())
                self.assertGreater(guest['expected_oep'], guest['ir_start'])
            self.assertNotEqual(guests[0]['input']['sha256'], guests[1]['input']['sha256'])

    def test_only_mprotect_precedes_the_indirect_transfer(self):
        if not all(shutil.which(tool) for tool in ('as', 'ld', 'strip', 'nm', 'objdump')):
            self.skipTest('binutils required')
        with tempfile.TemporaryDirectory() as directory:
            for negative in (False, True):
                guest = s.build_fixture(Path(directory)/str(negative), negative=negative)
                decoded = subprocess.check_output(['objdump', '-d', '--no-show-raw-insn', guest['path']], text=True)
                self.assertEqual(decoded.count('int    $0x80'), 3)
                self.assertEqual(decoded.count('mov    $0x7d,%eax'), 2)
                self.assertNotIn('mov    $0x3,%eax', decoded)
                self.assertNotIn('mov    $0x5,%eax', decoded)
                self.assertNotIn('mov    $0x6,%eax', decoded)


class ReceiptTests(unittest.TestCase):
    def test_receipt_is_bound_to_exact_qemu_and_rejects_modified_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'receipt'
            data = s.receipt_bytes('a'*64)
            path.write_bytes(data)
            self.assertEqual(s.read_receipt(path, 'a'*64), data)
            with self.assertRaisesRegex(ValueError, 'selected QEMU'):
                s.read_receipt(path, 'b'*64)
            path.write_bytes(data+b'\n')
            with self.assertRaises(ValueError):
                s.read_receipt(path, 'a'*64)

    def test_receipt_rejects_symlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'real').write_bytes(s.receipt_bytes('a'*64))
            (root/'link').symlink_to(root/'real')
            with self.assertRaises((OSError, ValueError, RuntimeError)):
                s.read_receipt(root/'link', 'a'*64)


class BundleReceiptTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.qemu, self.plugin = fake_toolchain(self.root/'tools')
        self.receipt = self.root/'eflags.receipt'
        self.receipt.write_bytes(s.receipt_bytes(s.digest(self.qemu)))

    def test_receipt_is_copied_and_covered_by_bundle_identity(self):
        bundle = u.build_bundle(self.root/'bundle', qemu=self.qemu, plugin=self.plugin,
                                flags_receipt=self.receipt)
        self.assertEqual(bundle['flags_receipt'], s.RECEIPT)
        saved = self.root/'bundle'/s.RECEIPT
        self.assertEqual(saved.read_bytes(), self.receipt.read_bytes())
        saved.chmod(0o600)
        saved.write_bytes(saved.read_bytes()+b'\n')
        with self.assertRaisesRegex(u.UnifiedRuntimeError, 'changed'):
            u.verify_bundle(self.root/'bundle', bundle['bundle_sha256'])

    def test_wrong_receipt_is_rejected_before_bundle_creation(self):
        self.receipt.write_bytes(s.receipt_bytes('b'*64))
        with self.assertRaisesRegex(ValueError, 'selected QEMU'):
            u.build_bundle(self.root/'bundle', qemu=self.qemu, plugin=self.plugin,
                           flags_receipt=self.receipt)
        self.assertFalse((self.root/'bundle').exists())

    def test_phase1_argument_uses_bound_guest_receipt(self):
        from tests.test_unified_pipeline import UnifiedPipelineTests, InstrumentedExecutor
        case = UnifiedPipelineTests('test_one_guest_execution_and_candidate_history_are_persisted')
        case.setUp()
        try:
            destination = case.bundle_path
            manifest = json.loads((destination/'bundle.json').read_text())
            receipt = destination/s.RECEIPT
            receipt.parent.mkdir()
            receipt.write_bytes(s.receipt_bytes(s.digest(destination/'bin/qemu-i386')))
            manifest['flags_receipt'] = s.RECEIPT
            manifest['files'].append({'path': s.RECEIPT, 'sha256': s.digest(receipt), 'size': receipt.stat().st_size})
            manifest['bundle_sha256'] = u.canonical_hash({k:v for k,v in manifest.items() if k != 'bundle_sha256'})
            u.write_json(destination/'bundle.json', manifest)
            case.bundle = manifest
            runtime = json.loads((case.template/'config/runtime.json').read_text())
            runtime['phase1']['bundle_sha256'] = manifest['bundle_sha256']
            u.write_json(case.template/'config/runtime.json', runtime)
            from taintforge_env.synthesis_loop import EnvironmentSynthesisLoop
            from taintforge_env.iteration_controller import IterationController
            shutil.rmtree(case.base/'session')
            EnvironmentSynthesisLoop(case.loop_config).run()
            IterationController(case.base/'session').prepare_next()
            from taintforge_env.prebuilt_runner import PrebuiltRootfsRunner
            runner = PrebuiltRootfsRunner(case.config, executor=InstrumentedExecutor())
            with patch.object(runner, '_check_host_dependencies'):
                context = runner.validate()
                runner._prepare_run_directory(context)
            binding = json.loads((context.run_dir/'config/phase1_binding.json').read_text())
            argument = binding['plugin_argument']
            self.assertIn('tf-require-flags=on', argument)
            self.assertIn('x86-flags-receipt=/__taintforge/'+s.RECEIPT, argument)
            self.assertNotIn('.prebuilt-run.', argument)
        finally:
            case.doCleanups()


class StrictVerifierTests(unittest.TestCase):
    def test_native_abort_is_reported_with_the_accepted_pre_retirement_analysis(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run = root/'warm-session/iterations/0000/run'
            (run/'config').mkdir(parents=True)
            (run/'logs/capsule/phase1-retirement').mkdir(parents=True)
            secondary = 'ProbeError: Unproven/invalid early exit'
            s.save(run/'config/capsule_result.json', {'error': secondary, 'analysis_quality': None})
            quality = {'status': 'accepted', 'facts': {'candidate': {'dse_verdict': 'CONFIRMED'}}}
            s.save(run/'logs/capsule/phase1-retirement/retirement.json',
                   {'status': 'released', 'permit_sent': True, 'analysis_quality': quality})
            (run/'logs/qemu_strace.log').write_text(
                'x'*70000+'\nTF_WARM_ABORT reason=input_opened_before_retirement\n')
            result = s.failure_details(root, 'Warm bootstrap failed')
            self.assertEqual(result['reason'], 'TF_WARM_ABORT reason=input_opened_before_retirement')
            self.assertEqual(result['warm_abort'], 'input_opened_before_retirement')
            self.assertEqual(result['verification_error'], secondary)
            self.assertEqual(result['analysis_quality'], quality)
            self.assertEqual(result['retirement_status'], 'released')
            self.assertIs(result['permit_sent'], True)
            self.assertNotIn('phase1_retired', result)

    def test_abort_parsing_ignores_old_or_embedded_log_messages(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            logs = root/'warm-session/iterations/0000/run/logs'
            logs.mkdir(parents=True)
            log = logs/'qemu_strace.log'
            log.write_text('TF_WARM_ABORT reason=old\n'+'x'*70000+
                           '\noutput: TF_WARM_ABORT reason=embedded\n')
            result = s.failure_details(root, 'original failure')
            self.assertEqual(result['reason'], 'original failure')
            self.assertIsNone(result['warm_abort'])
            log.write_text('TF_WARM_ABORT reason=first\nTF_WARM_ABORT reason=last\n')
            self.assertEqual(s.failure_details(root, 'original failure')['warm_abort'], 'last')

    def test_diagnostics_do_not_read_a_symlink_or_block_on_a_fifo(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            log = root/'warm-session/iterations/0000/run/logs/qemu_strace.log'
            log.parent.mkdir(parents=True)
            outside = root/'outside'
            outside.write_text('TF_WARM_ABORT reason=outside\n')
            log.symlink_to(outside)
            for kind in ('symlink', 'fifo'):
                if kind == 'fifo':
                    log.unlink()
                    os.mkfifo(log)
                with self.subTest(kind=kind):
                    result = s.failure_details(root, 'original failure')
                    self.assertEqual(result['reason'], 'original failure')
                    self.assertIsNone(result['warm_abort'])
                    self.assertIn('qemu_log', result['read_errors'])

    def test_long_output_is_rejected_before_build_or_calibration(self):
        from scripts.verify_capsule_strict_e2e import verify
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)/('x'*100)
            with patch.object(s, 'calibration') as calibration, patch('shutil.which') as tools:
                result = verify(root, qemu=Path(directory)/'qemu')
            self.assertEqual(result['status'], 'failed')
            self.assertIn('Unix socket limit', result['error'])
            calibration.assert_not_called()
            tools.assert_not_called()

    def test_failure_details_retain_the_actual_quality_rejection(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            saved = root/'warm-session/iterations/0000/run/config/capsule_result.json'
            saved.parent.mkdir(parents=True)
            decision = {'status': 'rejected', 'rejection_reasons': ['unknown_candidate_analysis']}
            s.save(saved, {'error': 'Analysis policy rejected retirement', 'analysis_quality': decision})
            result = s.failure_details(root, 'Warm bootstrap failed')
            self.assertEqual(result['reason'], 'Analysis policy rejected retirement')
            self.assertEqual(result['analysis_quality'], decision)
            self.assertEqual(result['pipeline_error'], 'Warm bootstrap failed')
            self.assertTrue(result['qemu_log'].endswith('/logs/qemu_strace.log'))

    def test_missing_native_dependencies_never_claim_strict_success(self):
        from scripts.verify_capsule_strict_e2e import verify
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch('shutil.which', return_value=None):
                result = verify(root/'out', qemu=root/'missing-qemu')
            self.assertEqual(result['status'], 'blocked_environment')
            self.assertFalse(result['native_strict_positive_verified'])
            self.assertFalse(result['native_strict_negative_verified'])
            self.assertEqual(json.loads((root/'out/acceptance.json').read_text()), result)

    def test_rejection_cannot_contain_readiness_or_children(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'warm-ready.json').write_text('{}')
            with self.assertRaisesRegex(ValueError, 'warm readiness'):
                s.verify_negative(root)
            (root/'warm-ready.json').unlink()
            (root/'cases/00000000').mkdir(parents=True)
            with self.assertRaisesRegex(ValueError, 'child'):
                s.verify_negative(root)

    def test_rejection_cannot_start_afl(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'afl').mkdir()
            with self.assertRaisesRegex(ValueError, 'AFL started'):
                s.verify_negative(root)


if __name__ == '__main__':
    unittest.main()
