"""File binding, coverage integrity, and real unified lifecycle with synthetic execution."""
import hashlib
import os
from pathlib import Path
import tempfile
import shlex
import subprocess
import unittest
from unittest.mock import patch

from taintforge_env import afl_file as f
from taintforge_env import input_retirement as m3
from tests import test_input_retirement as old
from tests import test_capsule_hardening_integration as hard
from tests.test_capsule_hardening_integration import hardened_evidence


class FileBindingTests(unittest.TestCase):
    def test_canonical_paths_and_limits(self):
        for value in (None, 1, '/', 'etc/input', '//etc/input', '/etc/../tmp/x',
                      '/etc/./x', '/etc//x', '/etc/x/', '/proc/x', '/sys/x', '/dev/x',
                      '/__taintforge/x', '/__taintforge_capsule/x', '/tmp/a,b', '/tmp/a\nx', '/tmp/a\0x'):
            with self.subTest(value=value), self.assertRaises(RuntimeError):
                f.settings(value, b'A')
        for data in (b'', b'A'*(1024**2+1), 'A'):
            with self.assertRaises(RuntimeError): f.settings('/etc/input', data)
        self.assertEqual(f.settings('/etc/input', b'A')['input_size'], 1)

    def test_symlinks_and_hardlinks_never_change_outside_input(self):
        with tempfile.TemporaryDirectory() as td:
            root, outside = Path(td)/'root', Path(td)/'outside'
            root.mkdir(); outside.mkdir()
            (outside/'file').write_bytes(b'unchanged')
            (root/'etc').symlink_to(outside, target_is_directory=True)
            with self.assertRaises(RuntimeError): f.create_guest_file(root, '/etc/file', b'new')
            self.assertEqual((outside/'file').read_bytes(), b'unchanged')
            (root/'etc').unlink(); (root/'etc').mkdir()
            os.link(outside/'file', root/'etc/file')
            with self.assertRaises(RuntimeError): f.guest_file(root, '/etc/file')
            with self.assertRaises(RuntimeError): f.guest_file(root, '/etc/../../outside/file')

    def test_binding_rejects_changed_input_and_executable(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            path=f.create_guest_file(root, '/etc/input', b'abc')
            settings=f.settings('/etc/input', b'abc')
            self.assertEqual(f.validate_setting(settings, root, '/sample'), settings)
            with self.assertRaises(RuntimeError): f.validate_setting(settings, root, '/etc/input')
            path.write_bytes(b'abd')
            with self.assertRaises(RuntimeError): f.validate_setting(settings, root, '/sample')

    def test_coverage_partial_complete_and_tampering(self):
        with tempfile.TemporaryDirectory() as td:
            path=Path(td)/'map'; f.create_map(path)
            self.assertEqual(path.stat().st_size, 65600)
            with self.assertRaises(RuntimeError): f.inspect_map(path)
            self.assertEqual(f.inspect_map(path, complete=False)[0]['status'], 'incomplete')
            bitmap=bytearray(f.MAP_SIZE); bitmap[5]=1
            good=f.HEADER.pack(b'TFACOV1\0',1,f.MAP_SIZE,1,1,4,0x8049000,0x8049004,0)+bitmap
            path.write_bytes(good)
            self.assertEqual(f.inspect_map(path)[0]['nonzero_slots'], 1)
            for bad in (good[:-1], b'BADMAGIC'+good[8:],
                        f.HEADER.pack(b'TFACOV1\0',1,f.MAP_SIZE,2,1,4,1,1,0)+bitmap,
                        f.HEADER.pack(b'TFACOV1\0',1,f.MAP_SIZE,1,1,4,1<<40,1,0)+bitmap,
                        good[:64]+bytes(f.MAP_SIZE)):
                path.write_bytes(bad)
                with self.assertRaises(RuntimeError): f.inspect_map(path)


class NativeCoverageTests(unittest.TestCase):
    def test_gate_and_counter_with_sanitizers(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); binary=root/'native'
            flags=shlex.split(f.p.command('pkg-config','--cflags','--libs','glib-2.0'))
            f.p.command('cc','-std=c11','-O1','-g','-Wall','-Wextra','-Werror',
                '-fsanitize=address,undefined','-fno-omit-frame-pointer','-fno-pie','-no-pie',
                '-I',f.PROJECT/'experiments/execution_capsule_probe/vendor',
                f.PROJECT/'experiments/afl_file/native_test.c','-o',binary,*flags)
            coverage=root/'map'; f.create_map(coverage)
            environment=dict(os.environ, ASAN_OPTIONS='detect_leaks=0')
            executed=subprocess.run([str(binary),str(coverage)],capture_output=True,text=True,env=environment)
            self.assertEqual(executed.returncode,0,executed.stderr)
            self.assertEqual(f.inspect_map(coverage)[0]['blocks'],10000)
            # A nonzero map must not be accepted as a pristine attempt.
            executed=subprocess.run([str(binary),str(coverage)],capture_output=True,text=True,env=environment)
            self.assertEqual(executed.returncode,2)


class UnifiedAflTests(unittest.TestCase):
    setUp=hard.HardeningIntegrationTests.setUp
    prepare_input=hard.HardeningIntegrationTests.prepare_input
    prepare_m4=hard.HardeningIntegrationTests.prepare_m4
    invoke=hard.HardeningIntegrationTests.invoke

    def setup_afl(self):
        out,launch=self.prepare_m4()
        root=Path(launch['seed_rootfs'])
        f.create_guest_file(root, '/etc/afl-input', b'A')
        runtime_path=Path(launch['template_run_dir'])/'config/runtime.json'
        runtime=f.read_json(runtime_path); runtime['afl_file']=f.settings('/etc/afl-input', b'A')
        f.atomic_json(runtime_path,runtime)
        return out,launch

    def test_bound_coverage_finalizes_via_existing_m4_pipeline(self):
        out,launch=self.setup_afl()
        def evidence(run,code,fault=None):
            binding,result=hardened_evidence(run,code,fault)
            self.assertEqual(binding['afl_file'], f.settings('/etc/afl-input', b'A'))
            contract=f.read_json(run/'config/observer-contract.json')
            self.assertEqual(contract['afl_file'],binding['afl_file'])
            bitmap=bytearray(f.MAP_SIZE);bitmap[7]=1
            (run/'logs/capsule'/f.MAP_NAME).write_bytes(
                f.HEADER.pack(b'TFACOV1\0',1,f.MAP_SIZE,1,1,10,0x8049000,0x8049004,0)+bitmap)
            f.atomic_json(run/'logs/capsule/afl-coverage.json',f.inspect_map(run/'logs/capsule'/f.MAP_NAME)[0])
            return binding,result
        executor=old.InputExecutor()
        with patch.object(old,'synthetic_evidence',side_effect=evidence):
            report,code=self.invoke(out,launch,executor)
        self.assertEqual(code,0,report.get('error'))
        self.assertEqual(report['capsule']['afl_coverage']['nonzero_slots'],1)
        binding=executor.runs[0][1]
        binding['afl_file']['input_sha256']='0'*64
        with self.assertRaisesRegex(RuntimeError,'contract changed'): m3.verify_contract(binding)

    def test_missing_coverage_blocks_attempt_success(self):
        out,launch=self.setup_afl()
        with patch.object(old,'synthetic_evidence',side_effect=hardened_evidence):
            report,code=self.invoke(out,launch,old.InputExecutor())
        self.assertEqual(code,1)
        self.assertEqual(report['outcome'],'intervention_required')
        self.assertIn('afl-coverage',report['error'])


if __name__=='__main__': unittest.main()
