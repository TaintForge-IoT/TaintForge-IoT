"""Real PTY/process-group regression checks, without requiring sudo or M4."""
import fcntl
import json
import os
from pathlib import Path
import pty
import signal
import subprocess
import sys
import tempfile
import termios
import unittest
from unittest.mock import patch

from taintforge_env import afl_file as f, afl_warm as w
from taintforge_env.afl_transport import stop_case


PROBE = r'''
import json, os, sys
from pathlib import Path
root = Path(sys.argv[1])
identity = {'pid': os.getpid(), 'sid': os.getsid(0), 'pgid': os.getpgrp()}
try:
    fd = os.open('/dev/tty', os.O_RDONLY | os.O_NOCTTY)
    identity['tty_foreground_pgid'] = os.tcgetpgrp(fd)
    os.close(fd)
except OSError:
    identity['tty_foreground_pgid'] = None
(root/'worker-identity.json').write_text(json.dumps(identity))
(root/'warm-ready.json').write_text(json.dumps({'status': 'ready'}))
assert os.read(int(sys.argv[2]), 1) == b'S'
'''


def tty_probe(root, mode):
    # The outer subprocess used setsid; attach its supplied PTY as controlling tty.
    fcntl.ioctl(0, termios.TIOCSCTTY, 0)
    root = Path(root)
    f.atomic_json(root/'campaign.json', {'warm': {'bootstrap_seconds': 10}})
    popen = subprocess.Popen
    gate_read, gate_write = os.pipe()

    def launch(command, **kwargs):
        if mode == 'legacy':
            kwargs.pop('process_group', None)
            kwargs['start_new_session'] = True
        return popen([sys.executable, '-c', PROBE, str(root), str(gate_read)],
                     pass_fds=(gate_read,), **kwargs)

    server = w.WarmAttemptServer(root)
    try:
        with patch.object(w.subprocess, 'Popen', side_effect=launch):
            server.start()
        identity = json.loads((root/'worker-identity.json').read_text())
        result = {'parent_sid': os.getsid(0), 'parent_pgid': os.getpgrp(),
                  'parent_tty_foreground_pgid': os.tcgetpgrp(0), 'worker': identity}
        if mode == 'cleanup':
            stop_case(server.worker, root)
            result['cleanup_returncode'] = server.worker.returncode
            server.started = False
        else:
            os.write(gate_write, b'S')
            server.worker.wait(timeout=5)
        server.close()
        result['worker_returncode'] = server.worker.returncode
        f.atomic_json(root/'topology-result.json', result)
    finally:
        os.close(gate_read)
        os.close(gate_write)
        server.started = False
        server.close()
        if server.worker is not None and server.worker.poll() is None:
            os.killpg(server.worker.pid, signal.SIGKILL)
            server.worker.wait(timeout=5)


class WorkerProcessTests(unittest.TestCase):
    def probe(self, mode):
        with tempfile.TemporaryDirectory() as td:
            master, slave = pty.openpty()
            try:
                result = subprocess.run([sys.executable, '-m', 'tests.test_afl_warm_process',
                    '--tty-probe', td, mode], cwd=f.PROJECT, stdin=slave,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True,
                    text=True, timeout=20)
                worker_log = Path(td)/'warm-worker.log'
                diagnostics = result.stderr + (worker_log.read_text() if worker_log.exists() else '')
                self.assertEqual(result.returncode, 0, diagnostics)
                return f.read_json(Path(td)/'topology-result.json')
            finally:
                os.close(master)
                os.close(slave)

    def test_worker_keeps_terminal_and_session_in_its_own_group(self):
        result = self.probe('current')
        child = result['worker']
        self.assertEqual(child['sid'], result['parent_sid'])
        self.assertEqual(child['tty_foreground_pgid'], result['parent_tty_foreground_pgid'])
        self.assertEqual(child['pgid'], child['pid'])
        self.assertNotEqual(child['pgid'], result['parent_pgid'])
        self.assertEqual(result['worker_returncode'], 0)

    def test_legacy_setsid_loses_the_terminal_session(self):
        result = self.probe('legacy')
        self.assertNotEqual(result['worker']['sid'], result['parent_sid'])
        self.assertIsNone(result['worker']['tty_foreground_pgid'])

    def test_group_cleanup_terminates_worker_and_preserves_parent(self):
        result = self.probe('cleanup')
        self.assertEqual(result['cleanup_returncode'], -signal.SIGTERM)
        self.assertEqual(result['worker']['sid'], result['parent_sid'])
        self.assertNotEqual(result['worker']['pgid'], result['parent_pgid'])


class SessionDiagnosticTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        template = self.root/'original-template'
        (template/'config').mkdir(parents=True)
        f.atomic_json(template/'config/runtime.json', {'phase1': {'bundle_path': '/original'}})
        self.manifest = {'warm': w.configuration(self.root, bootstrap_seconds=60,
            campaign_seconds=30, timeout_ms=2000, max_rss_mib=512),
            'guest_path': '/etc/input', 'snapshot_store': str(self.root/'store'),
            'snapshot_id': 'snapshot', 'launch': {'template_run_dir': str(template)}}

    def clone(self, snapshot, rootfs):
        (rootfs/'etc').mkdir(parents=True)
        (rootfs/'etc/input').write_bytes(b'A')

    def invoke(self, report, code, *, auth_error=None):
        with patch.object(f, 'verify_campaign', return_value=self.manifest), \
             patch.object(f.p, 'command', side_effect=auth_error, return_value='') as auth, \
             patch.object(f, 'EnvironmentSnapshotStore') as store, \
             patch('scripts.run_unified_pipeline.run_session', return_value=(report, code)) as session:
            store.return_value.clone.side_effect = self.clone
            try:
                return w.execute_session(self.root)
            finally:
                auth.assert_called_once_with('sudo', '-n', 'true', timeout=15)
                if auth_error is not None:
                    session.assert_not_called()
                else:
                    session.assert_called_once()

    def test_authorization_failure_precedes_m4_execution(self):
        with self.assertRaisesRegex(RuntimeError, 'password is required'):
            self.invoke({}, 1, auth_error=RuntimeError('sudo: a password is required'))
        self.assertFalse((self.root/'warm-template').exists())

    def test_failed_session_is_saved_and_its_actual_error_is_reported(self):
        report = {'outcome': 'intervention_required', 'error': 'snapshot failed: permission denied'}
        with self.assertRaisesRegex(RuntimeError, 'snapshot failed: permission denied'):
            self.invoke(report, 1)
        self.assertEqual(f.read_json(self.root/'warm-session-result.json'), report)

    def test_executor_cause_is_not_hidden_by_missing_finalization_artifact(self):
        f.atomic_json(self.root/'warm-executor.json',
                      {'status':'failed','error':'Warm backend infrastructure failure: original cause'})
        report={'error':'missing runtime artifact: controller.json','capsule':{'status':'failed'}}
        with self.assertRaisesRegex(RuntimeError,'Warm backend infrastructure failure: original cause'):
            self.invoke(report,1)
        self.assertEqual(f.read_json(self.root/'warm-session-result.json'),report)

    def test_worker_close_reports_the_executor_cause(self):
        f.atomic_json(self.root/'warm-executor.json',
                      {'status':'failed','error':'original executor cause'})
        server=w.WarmAttemptServer(self.root)
        worker=unittest.mock.Mock()
        worker.poll.return_value=86;worker.returncode=86
        server.worker=worker;server.started=True
        with self.assertRaisesRegex(RuntimeError,'original executor cause'):
            server.close()
        self.assertEqual(server.channel.fileno(),-1)
        self.assertEqual(server.peer.fileno(),-1)

    def test_missing_capsule_result_has_actionable_diagnostic(self):
        report = {'outcome': 'intervention_required'}
        with self.assertRaisesRegex(RuntimeError, 'no verified capsule result'):
            self.invoke(report, 0)
        self.assertEqual(f.read_json(self.root/'warm-session-result.json'), report)

    def test_worker_close_reports_session_failure_after_executor_passed(self):
        f.atomic_json(self.root/'warm-executor.json', {'status': 'passed', 'children': 65})
        f.atomic_json(self.root/'warm-session-result.json',
                      {'outcome': 'intervention_required', 'stop_reason': 'execution_crashed', 'error': None})
        server = w.WarmAttemptServer(self.root)
        worker = unittest.mock.Mock()
        worker.poll.return_value = 2
        worker.returncode = 2
        server.worker, server.started = worker, True
        with self.assertRaisesRegex(RuntimeError, 'execution_crashed'):
            server.close()
        self.assertEqual(server.channel.fileno(), -1)

    def test_verified_session_is_returned_and_saved(self):
        report = {'capsule': {'status': 'passed'}}
        self.assertEqual(self.invoke(report, 0), report)
        self.assertEqual(f.read_json(self.root/'warm-session-result.json'), report)


if __name__ == '__main__':
    if len(sys.argv) == 4 and sys.argv[1] == '--tty-probe':
        tty_probe(sys.argv[2], sys.argv[3])
    else:
        unittest.main()
