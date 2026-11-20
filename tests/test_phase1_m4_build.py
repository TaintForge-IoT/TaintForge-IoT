"""Source binding on synthetic files; no plugin or guest is executed."""
import copy
from contextlib import redirect_stderr, redirect_stdout
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest

from scripts import check_phase1_m4_build as gate


class BuildBindingTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / 'source'
        self.source.mkdir()
        for name in gate.REQUIRED | {'owner.h'}:
            (self.source / name).write_text(name + '\n')
        self.header = self.root / 'qemu-plugin.h'
        self.header.write_text('#define QEMU_PLUGIN_VERSION 6\n')
        self.plugin = self.root / 'plugin.so'
        self.plugin.write_bytes(b'synthetic plugin identity')
        self.sidecar = Path(str(self.plugin) + '.runtime.json')
        self.manifest = {'schema_version': 1, 'runtime_kind': 'taintforge-phase1',
            'plugin': {'filename': self.plugin.name, 'sha256': gate.digest(self.plugin),
                       'size': self.plugin.stat().st_size},
            'requirements': {'qemu_linkage': 'dynamic', 'plugins': True, 'plugin_api': 6},
            'formats': {'cooperative_retirement': 1, 'verdict_retirement': 2},
            'resource_ledger': {'schema': 1, 'scope': 'explicit_project_allocations',
                                'external_allocations_tracked': False},
            'compiled_profile': {'architecture': 'i386', 'mode': 'linux-user', 'processes': 1, 'threads': 1},
            'build_inputs': {'plugin_api': 6, 'qemu_header_sha256': gate.digest(self.header),
                'source_files': {path.name: gate.digest(path) for path in self.source.iterdir()}}}
        self.save()

    def save(self):
        data = json.dumps(self.manifest['build_inputs'], sort_keys=True, separators=(',', ':')).encode()
        self.manifest['build_id'] = hashlib.sha256(data).hexdigest()
        self.sidecar.write_text(json.dumps(self.manifest))

    def check(self):
        return gate.check(self.plugin, self.source, self.header)

    def test_current_build_is_bound_without_claiming_execution(self):
        result = self.check()
        self.assertEqual(result['status'], 'compatible')
        self.assertEqual(result['source_files'], self.manifest['build_inputs']['source_files'])
        self.assertIs(result['guest_executed'], False)
        self.assertIs(result['retirement_verified'], False)

    def test_changed_source_header_or_plugin_is_rejected(self):
        for path in (self.source / 'qemu_unpacker.c', self.header, self.plugin):
            with self.subTest(path=path.name):
                original = path.read_bytes()
                path.write_bytes(original + b'changed')
                with self.assertRaises(RuntimeError):
                    self.check()
                path.write_bytes(original)

    def test_missing_source_new_header_and_symlink_are_rejected(self):
        path = self.source / 'phase1_resources.c'
        original = path.read_bytes()
        path.unlink()
        with self.assertRaises(RuntimeError):
            self.check()
        target = self.root / 'owner.c'
        target.write_bytes(original)
        path.symlink_to(target)
        with self.assertRaises(RuntimeError):
            self.check()
        path.unlink()
        path.write_bytes(original)
        (self.source / 'new-owner.h').write_text('new header\n')
        with self.assertRaises(RuntimeError):
            self.check()

    def test_ledger_and_profile_cannot_be_promoted_by_metadata(self):
        original = copy.deepcopy(self.manifest)
        for section, key, value in (
            ('resource_ledger', 'schema', True),
            ('resource_ledger', 'external_allocations_tracked', True),
            ('compiled_profile', 'processes', True),
            ('compiled_profile', 'threads', 2),
            ('formats', 'verdict_retirement', 1),
        ):
            with self.subTest(section=section, key=key):
                self.manifest = copy.deepcopy(original)
                self.manifest[section][key] = value
                self.save()
                with self.assertRaises(RuntimeError):
                    self.check()

    def test_omitted_inputs_and_nonlocal_paths_are_rejected(self):
        original = copy.deepcopy(self.manifest)
        for name in ('omitted', '../outside.c', '/outside.c', '..' + chr(92) + 'outside.c'):
            with self.subTest(name=name):
                self.manifest = copy.deepcopy(original)
                sources = self.manifest['build_inputs']['source_files']
                if name == 'omitted':
                    del sources['phase1_retire.c']
                else:
                    sources[name] = 'a' * 64
                self.save()
                with self.assertRaises(RuntimeError):
                    self.check()

    def test_failed_cli_preserves_a_failure_report_and_refuses_overwrite(self):
        (self.source / 'phase1_resources.c').write_text('changed\n')
        out = self.root / 'check.json'
        arguments = ['--plugin', str(self.plugin), '--source', str(self.source),
                     '--header', str(self.header), '--out', str(out)]
        with redirect_stdout(io.StringIO()):
            self.assertEqual(gate.main(arguments), 1)
        self.assertEqual(json.loads(out.read_text())['status'], 'failed')
        before = out.read_bytes()
        with self.assertRaises(SystemExit), redirect_stderr(io.StringIO()):
            gate.main(arguments)
        self.assertEqual(out.read_bytes(), before)


if __name__ == '__main__':
    unittest.main()
