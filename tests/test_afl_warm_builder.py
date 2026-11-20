import os
from pathlib import Path
import subprocess
import tempfile
import unittest


class WarmBuilderTests(unittest.TestCase):
    def run_builder(self, *, abi2=True, abi3=True, commit='6e9a825c1d4e7b62d072e99a89ecd1a74c7f0d55'):
        project = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            tools, source, prefix = root/'tools', root/'qemu', root/'prefix'
            tools.mkdir()
            source.mkdir()
            log = root/'calls'
            def executable(path, data):
                path.write_text('#!/bin/sh\n'+data)
                path.chmod(0o755)
            executable(tools/'git', 'printf "%s\\n" "$TF_TEST_COMMIT"\n')
            executable(tools/'python-driver', 'printf "installer:%s\\n" "$*" >> "$TF_TEST_LOG"\n')
            executable(source/'configure', 'printf "configure:%s\\n" "$*" >> "$TF_TEST_LOG"\n')
            executable(tools/'ninja', 'printf "ninja:%s\\n" "$*" >> "$TF_TEST_LOG"\n')
            symbols = ['qemu_plugin_tf_warm_configure', 'qemu_plugin_tf_warm_arm']
            if abi2:
                symbols.append('qemu_plugin_tf_warm_abi2')
            if abi3:
                symbols.extend(('qemu_plugin_tf_warm_abi3', 'qemu_plugin_tf_warm_set_input_gate'))
            executable(tools/'nm', ''.join('printf "000000 T '+name+'\\n"\n' for name in symbols))
            environment = os.environ | {'PATH': str(tools)+os.pathsep+os.environ['PATH'],
                'TF_PYTHON': str(tools/'python-driver'), 'TF_TEST_LOG': str(log), 'TF_TEST_COMMIT': commit}
            result = subprocess.run(['bash', str(project/'scripts/build_afl_warm_qemu.sh'),
                                     str(source), str(prefix)], env=environment,
                                    capture_output=True, text=True, timeout=15)
            return result, log.read_text() if log.exists() else ''

    def test_current_source_builder_accepts_abi3_without_newer_calibration_modules(self):
        result, calls = self.run_builder()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('warm ABI 3 built', result.stdout)
        self.assertEqual(calls.count('installer:'), 2)
        self.assertIn('--check', calls)
        self.assertIn('ninja:', calls)
        self.assertNotIn('calibrate_runtime_flags', calls)

    def test_abi1_output_is_rejected(self):
        result, calls = self.run_builder(abi2=False)
        self.assertEqual(result.returncode, 1)
        self.assertIn('Required QEMU symbol missing: qemu_plugin_tf_warm_abi2', result.stderr)
        self.assertNotIn('warm ABI 3 built', result.stdout)

    def test_abi2_without_the_input_gate_is_rejected(self):
        result, calls = self.run_builder(abi3=False)
        self.assertEqual(result.returncode, 1)
        self.assertIn('Required QEMU symbol missing: qemu_plugin_tf_warm_abi3', result.stderr)
        self.assertNotIn('warm ABI 3 built', result.stdout)

    def test_unpinned_source_is_rejected_before_patch_or_build(self):
        result, calls = self.run_builder(commit='unsupported')
        self.assertEqual(result.returncode, 2)
        self.assertEqual(calls, '')
        self.assertIn('pinned v11.0.1', result.stderr)


if __name__ == '__main__':
    unittest.main()
