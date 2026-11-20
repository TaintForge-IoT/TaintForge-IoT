"""Private ledger ownership across ordinary and privileged network clients."""
import json
import os
from pathlib import Path
import select
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from taintforge_env import network_runtime as runtime


PROJECT = Path(__file__).resolve().parents[1]


class NetworkRuntimeOwnershipTests(unittest.TestCase):
    def test_atomic_replacement_uses_the_existing_owner_before_publication(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'state.json'
            runtime._private_json(path, {'value': 'before'})
            existing = SimpleNamespace(st_uid=2001, st_gid=2002, st_mode=stat.S_IFREG | 0o600)
            replace = os.replace

            def set_owner(descriptor, uid, gid):
                self.assertEqual((uid, gid), (existing.st_uid, existing.st_gid))
                self.assertTrue(stat.S_ISREG(os.fstat(descriptor).st_mode))

            def publish(source, destination):
                change_owner.assert_called_once()
                self.assertEqual(stat.S_IMODE(os.stat(source).st_mode), 0o600)
                replace(source, destination)

            with patch.object(Path, 'lstat', return_value=existing), \
                 patch.object(os, 'fchown', side_effect=set_owner) as change_owner, \
                 patch.object(os, 'replace', side_effect=publish):
                runtime._private_json(path, {'value': 'after'})
            self.assertEqual(json.loads(path.read_text()), {'value': 'after'})

    def test_control_lock_exists_before_the_descriptor_is_published(self):
        with tempfile.TemporaryDirectory() as temporary, \
             patch.object(runtime.NetworkRuntimeOwner, '_heartbeat'):
            root = Path(temporary)
            owner = runtime.NetworkRuntimeOwner(root / 'control', root / 'logs', attempt_id='ownership')
            try:
                for name in ('state.json', 'client.json', 'control.lock'):
                    info = (owner.directory / name).stat()
                    self.assertEqual((info.st_uid, info.st_gid), (os.geteuid(), os.getegid()))
                    self.assertEqual(stat.S_IMODE(info.st_mode), 0o600)
            finally:
                owner.close()

    @unittest.skipUnless(os.geteuid() == 0, 'run with sudo for real root and non-root clients')
    def test_root_client_preserves_an_unprivileged_owner_and_terminal_status(self):
        script = '''import json
import os
import sys
from pathlib import Path
from taintforge_env.network_runtime import NetworkRuntimeOwner
root = Path(sys.argv[1])
os.chdir(root)
os.setgroups([])
os.setgid(65534)
os.setuid(65534)
owner = NetworkRuntimeOwner(root / 'control', root / 'logs', attempt_id='cross-uid')
print(json.dumps({'descriptor': str(owner.client_path)}), flush=True)
if sys.stdin.readline().strip() != 'verify':
    raise RuntimeError('missing verification request')
snapshot = owner.snapshot()
status = owner.close()
print(json.dumps({'reason': snapshot['termination_reason'], 'cleanup': status['cleanup_status'],
                 'status_path': str(owner.status_path)}), flush=True)
'''
        with tempfile.TemporaryDirectory(prefix='taintforge-network-ownership-') as temporary:
            root = Path(temporary)
            os.chown(root, 65534, 65534)
            process = subprocess.Popen([sys.executable, '-c', script, str(root)], cwd=PROJECT,
                env={**os.environ, 'PYTHONPATH': str(PROJECT)}, text=True,
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                ready, _, _ = select.select([process.stdout], [], [], 5)
                self.assertTrue(ready, 'unprivileged runtime owner did not become ready')
                line = process.stdout.readline()
                self.assertTrue(line, 'unprivileged runtime owner failed during startup')
                descriptor = json.loads(line)['descriptor']
                client = runtime.NetworkRuntimeClient(descriptor)
                client.call('heartbeat')
                client.fail('network_receive_budget_exceeded')
                client.fail('network_capsule_timeout')
                for name in ('state.json', 'client.json', 'control.lock'):
                    info = (root / 'control' / name).stat()
                    self.assertEqual((info.st_uid, info.st_gid), (65534, 65534), name)
                    self.assertEqual(stat.S_IMODE(info.st_mode), 0o600, name)
                stdout, stderr = process.communicate('verify\n', timeout=10)
                self.assertEqual(process.returncode, 0, stderr)
                result = json.loads(stdout)
                self.assertEqual(result['reason'], 'network_receive_budget_exceeded')
                self.assertEqual(result['cleanup'], 'cleaned')
                status_path = Path(result['status_path'])
                self.assertEqual(status_path.stat().st_uid, 65534)
                self.assertEqual(json.loads(status_path.read_text())['termination_reason'], result['reason'])
                self.assertFalse((root / 'control').exists())
            finally:
                if process.poll() is None:
                    process.kill()
                process.communicate(timeout=3)


if __name__ == '__main__':
    unittest.main()
