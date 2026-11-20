import copy
import errno
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from taintforge_env import afl_file as f, afl_storage as s, afl_transport as t


class StoragePermissionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.parent = Path(self.temporary.name)
        self.root = self.parent/'campaign'
        self.root.mkdir()
        self.export = self.root/'warm-session/run/logs/capsule/phase1-retirement/export'
        self.export.mkdir(parents=True, mode=0o700)
        (self.export/'payload.bin').write_bytes(b'x'*73)
        (self.export/'payload.bin').chmod(0o600)

    def budget(self, **options):
        return s.Budget(self.root, s.policy(min_free_mib=1), **options)

    def deny_export(self):
        self.addCleanup(self.export.chmod, 0o700)
        self.export.chmod(0)
        try:
            with os.scandir(self.export):
                pass
        except PermissionError:
            return
        self.skipTest('Current credentials bypass directory permissions')

    def test_real_permission_denial_is_not_silently_ignored(self):
        self.deny_export()
        before = len(list(Path('/proc/self/fd').iterdir()))
        for _ in range(3):
            with self.assertRaises(PermissionError):
                s.usage(self.root)
        self.assertEqual(len(list(Path('/proc/self/fd').iterdir())), before)

    def test_warm_budget_counts_private_export_and_preserves_its_permissions(self):
        measured = s.usage(self.root)
        self.assertEqual(measured['preparation_bytes'], 73)
        self.deny_export()
        budget = self.budget(allow_privileged=True)
        with patch.object(s, 'privileged_usage', return_value=measured) as helper:
            self.assertEqual(budget.check(force=True), measured)
            report = budget.report()
            self.assertEqual(report['usage'], measured)
            self.assertEqual(report['measurement_backend'], 'sudo_read_only')
            self.assertEqual(helper.call_count, 2)
        self.assertEqual(self.export.stat().st_mode & 0o777, 0)

    def test_private_export_still_enforces_preparation_limit(self):
        measured = s.usage(self.root)
        measured.update(preparation_bytes=2*s.MIB, total_bytes=2*s.MIB)
        policy = s.policy(preparation_mib=1, min_free_mib=1)
        budget = s.Budget(self.root, policy, allow_privileged=True)
        with patch.object(s, 'usage', side_effect=PermissionError(errno.EACCES, 'private')), \
             patch.object(s, 'privileged_usage', return_value=measured):
            with self.assertRaises(s.ResourceLimit) as caught:
                budget.check(force=True)
        self.assertEqual(caught.exception.record['reason'], 'preparation_bytes')

    def test_failed_helper_does_not_produce_a_successful_measurement(self):
        budget = self.budget(allow_privileged=True)
        with patch.object(s, 'usage', side_effect=PermissionError(errno.EACCES, 'private')), \
             patch.object(s, 'privileged_usage', side_effect=RuntimeError('sudo failed')):
            with self.assertRaisesRegex(RuntimeError, 'sudo failed'):
                budget.check(force=True)
        self.assertFalse(budget.privileged_measurement)
        self.assertIsNone(budget.sample)

    def test_local_budget_never_launches_sudo_implicitly(self):
        budget = self.budget()
        with patch.object(s, 'usage', side_effect=PermissionError(errno.EACCES, 'private')), \
             patch.object(s, 'privileged_usage') as helper:
            with self.assertRaises(PermissionError):
                budget.check(force=True)
        helper.assert_not_called()

    def test_only_warm_transport_enables_privileged_measurement(self):
        for warm in (False, True):
            manifest = {'warm': {}} if warm else {}
            s.bind(manifest, s.policy())
            f.atomic_json(self.root/'campaign.json', manifest)
            server = t.AttemptServer(self.root)
            try:
                self.assertEqual(server.storage.allow_privileged, warm)
            finally:
                server.close()

    def test_isolated_measurement_process_returns_metadata_without_changing_files(self):
        before = [(p, p.stat().st_mode & 0o777, p.stat().st_uid, p.stat().st_gid)
                  for p in (self.export, self.export/'payload.bin')]
        original = subprocess.run
        def invoke(command, **options):
            self.assertEqual(command[:3], ['sudo', '-n', '--'])
            self.assertEqual(command[3:5], [sys.executable, '-I'])
            environment = os.environ.copy()
            environment.pop('SUDO_UID', None)
            return original(command[3:], env=environment, **options)
        with patch.object(s.subprocess, 'run', side_effect=invoke):
            self.assertEqual(s.privileged_usage(self.root), s.usage(self.root))
        after = [(p, p.stat().st_mode & 0o777, p.stat().st_uid, p.stat().st_gid) for p, *_ in before]
        self.assertEqual(before, after)
        self.assertEqual((self.export/'payload.bin').read_bytes(), b'x'*73)

    def test_invalid_helper_records_are_rejected(self):
        record = s.measurement(self.root)
        bad = []
        for field, value in [('schema', True), ('root', str(self.parent)), ('identity', [1, 2])]:
            item = copy.deepcopy(record); item[field] = value; bad.append(item)
        for field, value in [('preparation_bytes', -1), ('files', True), ('total_bytes', 0)]:
            item = copy.deepcopy(record); item['usage'][field] = value; bad.append(item)
        bad.extend([{}, [], record | {'extra': 1}])
        for item in bad:
            result = subprocess.CompletedProcess([], 0, json.dumps(item), '')
            with self.subTest(item=item), patch.object(s.subprocess, 'run', return_value=result):
                with self.assertRaisesRegex(RuntimeError, 'Invalid private'):
                    s.privileged_usage(self.root)
        duplicate = json.dumps(record)[:-1]+', "schema": 1}'
        with patch.object(s.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, duplicate, '')):
            with self.assertRaisesRegex(RuntimeError, 'Duplicate'):
                s.privileged_usage(self.root)

    def test_helper_errors_and_timeouts_are_not_accepted(self):
        with patch.object(s.subprocess, 'run', return_value=subprocess.CompletedProcess([], 1, '', 'sudo denied')):
            with self.assertRaisesRegex(RuntimeError, 'sudo denied'):
                s.privileged_usage(self.root)
        for error in (FileNotFoundError('sudo missing'), subprocess.TimeoutExpired('measure', 30)):
            with self.subTest(error=error), patch.object(s.subprocess, 'run', side_effect=error):
                with self.assertRaisesRegex(RuntimeError, 'measurement failed'):
                    s.privileged_usage(self.root)

    def test_helper_refuses_another_callers_root(self):
        if os.geteuid() != 0:
            self.skipTest('Root-only helper authorization check')
        environment = os.environ | {'SUDO_UID': str(self.root.stat().st_uid+1)}
        result = subprocess.run([sys.executable, '-I', str(Path(s.__file__).resolve()), '--measure', str(self.root)],
                                env=environment, capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 2)
        self.assertIn('does not belong', result.stderr)
        self.assertEqual(result.stdout, '')

    def test_directory_replaced_with_symlink_during_scan_is_not_followed(self):
        outside = self.parent/'outside'
        outside.mkdir()
        (outside/'secret').write_bytes(b'outside'*100)
        victim = self.root/'victim'
        victim.mkdir()
        original = s._directory_fd
        def replace(root_fd, parts):
            if parts == ('victim',):
                victim.rename(self.parent/'old-victim')
                victim.symlink_to(outside, target_is_directory=True)
            return original(root_fd, parts)
        before = len(list(Path('/proc/self/fd').iterdir()))
        with patch.object(s, '_directory_fd', side_effect=replace):
            result = s.usage(self.root)
        self.assertEqual(result['total_bytes'], 73)
        self.assertEqual(len(list(Path('/proc/self/fd').iterdir())), before)


if __name__ == '__main__':
    unittest.main()
