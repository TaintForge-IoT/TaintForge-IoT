"""Installer and public-header regression checks; no guest programs are run."""
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from experiments.afl_file.qemu import apply as installer


class WarmQemuBuildTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        source = os.environ.get('TF_WARM_QEMU_SOURCE')
        if not source:
            raise unittest.SkipTest('TF_WARM_QEMU_SOURCE with pinned QEMU git source required')
        cls.source = Path(source)
        cls.baselines = {}
        for name, expected in installer.BASELINES.items():
            data = subprocess.check_output(['git', '-C', str(cls.source), 'show', 'HEAD:' + name])
            if installer.hashlib.sha256(data).hexdigest() != expected:
                raise ValueError('Unsupported QEMU baseline: ' + name)
            cls.baselines[name] = data

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / 'VERSION').write_text('11.0.1\n')
        for name, data in self.baselines.items():
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)

    def snapshot(self):
        return {str(path.relative_to(self.root)): path.read_bytes()
                for path in self.root.rglob('*')
                if path.is_file() and '.taintforge-warm-backups' not in path.parts}

    def legacy_install(self):
        path = self.root / 'linux-user/syscall.c'
        path.write_bytes(installer.warm_syscall(path.read_bytes(), gate=False))
        path = self.root / 'include/plugins/qemu-plugin.h'
        path.write_bytes(path.read_bytes() + installer.DECLARATIONS)
        (self.root / 'linux-user/tf-warm.h').write_bytes((installer.HERE / 'tf-warm.h').read_bytes())

    def test_check_does_not_write_and_install_is_idempotent(self):
        before = self.snapshot()
        self.assertEqual(installer.install(self.root, check=True), ('compatible', None))
        self.assertEqual(self.snapshot(), before)
        status, backup = installer.install(self.root)
        self.assertEqual(status, 'installed')
        self.assertEqual((backup / 'linux-user/syscall.c').read_bytes(), before['linux-user/syscall.c'])
        self.assertEqual(installer.install(self.root), ('already installed', None))

    def test_upgrade_repairs_the_legacy_tree(self):
        self.legacy_install()
        self.assertEqual(installer.install(self.root)[0], 'installed')
        header = (self.root / 'include/plugins/qemu-plugin.h').read_bytes()
        self.assertLess(header.index(b'qemu_plugin_tf_warm_arm'), header.index(b'} /* extern "C" */'))
        self.assertEqual(installer.install(self.root), ('already installed', None))

    def test_legacy_flags_and_abi2_upgrade_to_the_same_fresh_install(self):
        expected = self.snapshot()
        for path, _, desired in installer.changes(self.root):
            expected[str(path.relative_to(self.root))] = desired
        self.legacy_install()
        (self.root/'linux-user/tf-warm.h').write_bytes((installer.HERE/'tf-warm-v2.h').read_bytes())
        for name, replacements in installer.LEGACY_EFLAGS_REPLACEMENTS.items():
            value = self.baselines[name]
            for before, after in replacements:
                value = value.replace(before, after, 1)
            (self.root/name).write_bytes(value)
        self.assertEqual(installer.install(self.root)[0], 'installed')
        self.assertEqual(self.snapshot(), expected)
        self.assertEqual(installer.install(self.root), ('already installed', None))

    def test_actual_abi1_backend_is_upgraded_with_a_backup(self):
        self.legacy_install()
        backend=self.root/'linux-user/tf-warm.h'
        legacy=(installer.HERE/'tf-warm-v1.h').read_bytes()
        backend.write_bytes(legacy)
        status,backup=installer.install(self.root)
        self.assertEqual(status,'installed')
        self.assertEqual((backup/'linux-user/tf-warm.h').read_bytes(),legacy)
        self.assertEqual(backend.read_bytes(),(installer.HERE/'tf-warm.h').read_bytes())

    def test_abi2_upgrade_places_gate_before_any_syscall_callback(self):
        self.legacy_install()
        backend = self.root/'linux-user/tf-warm.h'
        legacy = (installer.HERE/'tf-warm-v2.h').read_bytes()
        backend.write_bytes(legacy)
        status, backup = installer.install(self.root)
        self.assertEqual(status, 'installed')
        self.assertEqual((backup/'linux-user/tf-warm.h').read_bytes(), legacy)
        syscall = (self.root/'linux-user/syscall.c').read_bytes()
        hook = syscall.index(installer.PRE_HOOK)
        self.assertLess(hook, syscall.index(b'    record_syscall_start(cpu, num, arg1,', hook))
        self.assertEqual(syscall.count(installer.PRE_HOOK), 1)
        header = (self.root/'include/plugins/qemu-plugin.h').read_bytes()
        self.assertIn(installer.V3_DECLARATIONS, header)
        self.assertEqual(installer.install(self.root), ('already installed', None))

    def test_manual_patch_matches_the_installer(self):
        subprocess.run(['git', 'apply', '--check', str(installer.HERE / 'qemu-changes.patch')],
                       cwd=self.root, check=True)
        subprocess.run(['git', 'apply', str(installer.HERE / 'qemu-changes.patch')],
                       cwd=self.root, check=True)
        self.assertEqual(installer.install(self.root, check=True), ('already installed', None))

    def test_local_edit_refused_before_any_write(self):
        self.legacy_install()
        with (self.root / 'linux-user/strace.c').open('ab') as output:
            output.write(b'\n/* local change */\n')
        before = self.snapshot()
        with self.assertRaisesRegex(ValueError, 'source differs'):
            installer.install(self.root)
        self.assertEqual(self.snapshot(), before)

    def test_different_backend_refused_before_any_write(self):
        self.legacy_install()
        (self.root / 'linux-user/tf-warm.h').write_bytes(b'local backend\n')
        before = self.snapshot()
        with self.assertRaisesRegex(ValueError, 'backend differs'):
            installer.install(self.root)
        self.assertEqual(self.snapshot(), before)

    def test_modified_cpu_loop_is_refused_before_any_write(self):
        path = self.root/'linux-user/i386/cpu_loop.c'
        path.write_bytes(path.read_bytes()+b'\n/* changed CPU event ordering */\n')
        before = self.snapshot()
        with self.assertRaisesRegex(ValueError, 'source differs'):
            installer.install(self.root)
        self.assertEqual(self.snapshot(), before)

    def test_symlink_refused(self):
        path = self.root / 'linux-user/strace.c'
        path.rename(path.with_suffix('.saved'))
        path.symlink_to(path.with_suffix('.saved'))
        with self.assertRaisesRegex(ValueError, 'symlink'):
            installer.install(self.root)

    def test_failure_rolls_back_installed_sources(self):
        before = self.snapshot()
        write = installer.atomic_write
        calls = 0

        def fail_once(path, data, mode):
            nonlocal calls
            calls += 1
            if calls == 3:
                raise OSError('injected write failure')
            write(path, data, mode)

        with patch.object(installer, 'atomic_write', side_effect=fail_once):
            with self.assertRaisesRegex(OSError, 'injected write failure'):
                installer.install(self.root)
        self.assertEqual(self.snapshot(), before)

    def compile_header(self, compiler, language, standard):
        if not shutil.which(compiler) or not shutil.which('pkg-config') or not shutil.which('nm'):
            self.skipTest('C/C++ compiler, pkg-config and nm required')
        self.legacy_install()
        installer.install(self.root)
        code = '''#include "qemu-plugin.h"
#include "qemu-plugin.h"
void (*warm_arm)(void) = qemu_plugin_tf_warm_arm;
int (*warm_configure)(const char *, const char *, uint64_t, int,
                      void (*)(void), void (*)(void)) = qemu_plugin_tf_warm_configure;
unsigned int (*warm_abi3)(void) = qemu_plugin_tf_warm_abi3;
int (*warm_input_gate)(void (*)(void)) = qemu_plugin_tf_warm_set_input_gate;
'''
        flags = shlex.split(subprocess.check_output(
            ['pkg-config', '--cflags', 'glib-2.0'], text=True))
        obj = self.root / 'header.o'
        subprocess.run([compiler, '-x', language, '-std=' + standard, '-Wall', '-Wextra',
                        '-Werror', '-Wredundant-decls', '-I', str(self.root / 'include/plugins'),
                        *flags, '-c', '-o', str(obj), '-'], input=code, text=True, check=True)
        names = {line.split()[-1] for line in subprocess.check_output(['nm', '-u', str(obj)], text=True).splitlines()}
        self.assertIn('qemu_plugin_tf_warm_arm', names)
        self.assertIn('qemu_plugin_tf_warm_configure', names)
        self.assertIn('qemu_plugin_tf_warm_abi3', names)
        self.assertIn('qemu_plugin_tf_warm_set_input_gate', names)

    def test_header_can_be_included_twice_in_c(self):
        self.compile_header('cc', 'c', 'c11')

    def test_header_can_be_included_twice_with_c_linkage_in_cpp(self):
        self.compile_header('c++', 'c++', 'c++17')


if __name__ == '__main__':
    unittest.main()
