"""Checkpoint invariants and real serial QEMU forks."""
import copy
import os
from pathlib import Path
import socket
import struct
import tempfile
import subprocess
import sys
import unittest
from unittest.mock import patch

from taintforge_env import afl_file as f, afl_warm as w
from experiments.afl_file.build import components
from scripts.verify_afl_warm_components import NativeSession
from taintforge_env.afl_transport import recv_exact
from tests import test_input_retirement as old
from tests import test_capsule_hardening_integration as hard


class CheckpointTests(unittest.TestCase):
    def test_configuration_rejects_unbounded_and_wrong_types(self):
        value = w.configuration('/tmp/tf-campaign', bootstrap_seconds=1200,
            campaign_seconds=3600, timeout_ms=2000, max_rss_mib=2048)
        self.assertEqual(w.validate(value), value)
        for key, bad in [('bootstrap_seconds', 0), ('campaign_seconds', 72001),
                         ('timeout_ms', 0), ('max_rss_mib', True)]:
            changed = value | {key: bad}
            with self.subTest(key=key), self.assertRaises(RuntimeError): w.validate(changed)

    def test_filesystem_restores_checkpoint_and_preserves_runtime_mounts(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)/'root'; root.mkdir(); (root/'etc').mkdir(); (root/'tmp').mkdir()
            (root/'etc/input').write_bytes(b'A'); (root/'tmp/from-phase1').write_bytes(b'prepared')
            (root/'proc').mkdir(); (root/'proc/runtime').write_bytes(b'live')
            baseline = w.FilesystemBaseline(root, Path(td)/'baseline')
            inode = root.stat().st_ino
            for _ in range(2):
                (root/'etc/input').write_bytes(b'changed'); (root/'tmp/dirty').write_bytes(b'x')
                (root/'tmp/from-phase1').unlink()
                baseline.restore()
                self.assertEqual(root.stat().st_ino, inode)
                self.assertEqual((root/'etc/input').read_bytes(), b'A')
                self.assertEqual((root/'tmp/from-phase1').read_bytes(), b'prepared')
                self.assertFalse((root/'tmp/dirty').exists())
                self.assertEqual((root/'proc/runtime').read_bytes(), b'live')
            (baseline.backup/'etc/input').write_bytes(b'changed')
            with self.assertRaisesRegex(RuntimeError, 'changed'): baseline.restore()

    def test_default_cli_prepares_warm_not_repeated_phase1(self):
        from scripts import run_afl_file as cli
        with patch('sys.argv', ['run_afl_file', 'prepare', '--binary', '/x', '--qemu', '/q',
                   '--plugin', '/p', '--seeds', '/s', '--guest-file', '/etc/input', '--out', '/out']), \
             patch.object(w, 'prepare_campaign', return_value={'status': 'prepared'}) as warm, \
             patch.object(f, 'prepare_campaign') as fresh:
            self.assertEqual(cli.main(), 0)
        warm.assert_called_once(); fresh.assert_not_called()
        self.assertEqual(warm.call_args.kwargs['analysis_mib'], 49152)

    @unittest.skipUnless(os.geteuid() == 0, 'ownership transfer requires root')
    def test_supervisor_published_readiness_is_readable_by_campaign_owner(self):
        with tempfile.TemporaryDirectory() as td:
            directory = Path(td); directory.chmod(0o755)
            campaign = directory/'campaign'; campaign.mkdir(); campaign.chmod(0o700)
            try: os.chown(campaign, 65534, 65534)
            except OSError as exc:
                if exc.errno in (1, 22): self.skipTest('Execution namespace does not map UID/GID 65534')
                raise
            broker = object.__new__(w.Broker)
            broker.owner = campaign.stat()
            broker.publish(campaign/'warm-ready.json', {'status': 'ready'})
            script = 'import json,sys;assert json.load(open(sys.argv[1]))["status"]=="ready"'
            result = subprocess.run([sys.executable, '-c', script, str(campaign/'warm-ready.json')],
                                    user=65534, group=65534, cwd='/', capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)


class WarmEvidenceTests(unittest.TestCase):
    setUp = hard.HardeningIntegrationTests.setUp
    prepare_input = hard.HardeningIntegrationTests.prepare_input
    prepare_m4 = hard.HardeningIntegrationTests.prepare_m4
    invoke = hard.HardeningIntegrationTests.invoke

    def test_warm_checkpoint_requires_retirement_order_and_is_not_guest_exit(self):
        from experiments.retirement_observer import controller
        from taintforge_env import retirement_evidence
        out, launch = self.prepare_m4()
        rootfs = Path(launch['seed_rootfs'])
        f.create_guest_file(rootfs, '/etc/afl-input', b'A')
        runtime_path = Path(launch['template_run_dir'])/'config/runtime.json'
        runtime = f.read_json(runtime_path)
        runtime['afl_file'] = f.settings('/etc/afl-input', b'A')
        runtime['afl_warm'] = w.configuration(self.base/'campaign', bootstrap_seconds=60,
            campaign_seconds=30, timeout_ms=2000, max_rss_mib=512)
        f.atomic_json(runtime_path, runtime)

        def evidence(run, code, fault=None):
            binding, result = hard.hardened_evidence(run, code, fault)
            path = run/'logs/capsule/observer-events.json'
            journal = f.read_json(path)
            events = journal['events']
            events.insert(-1, dict(event='warm_checkpoint', protocol=3, host_pid=77, seq=515))
            for index, event in enumerate(events, 1):
                event.update(controller_seq=index, controller_ns=index*1000)
            f.atomic_json(path, journal)
            result['warm'] = {'status': 'passed', 'phase1_runs': 1, 'children': 2}
            f.atomic_json(run/'logs/capsule/supervisor.json', result)
            return binding, result

        executor = old.InputExecutor()
        with patch.object(old, 'synthetic_evidence', side_effect=evidence):
            report, code = self.invoke(out, launch, executor)
        self.assertEqual(code, 0, report)
        self.assertEqual(len(executor.runs), 1)
        self.assertTrue(report['capsule']['phase1_retirement']['phase1_retired'])
        self.assertFalse(report['capsule']['guest_completed'])
        run, binding, result = executor.runs[0]
        self.assertEqual(retirement_evidence.verify(run/'retirement-evidence')['attempt_outcome'], 'passed')
        path = run/'logs/capsule/observer-events.json'
        journal = f.read_json(path)
        journal['events'] = [event for event in journal['events'] if event['event'] != 'module_unmapped']
        for index, event in enumerate(journal['events'], 1):
            event.update(controller_seq=index, controller_ns=index*1000)
        f.atomic_json(path, journal)
        with self.assertRaisesRegex(RuntimeError, 'order'):
            controller.verify_attempt(binding, result)


class NativeForkTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.qemu = os.environ.get('TF_WARM_QEMU')
        if not cls.qemu: raise unittest.SkipTest('TF_WARM_QEMU required')
        cls.directory = tempfile.TemporaryDirectory(); cls.addClassCleanup(cls.directory.cleanup)
        cls.root = Path(cls.directory.name)
        cls.built = components(cls.root/'build')

    def test_one_preparation_independent_memory_and_filesystem_stable_coverage(self):
        session = NativeSession(self.root/'serial', self.built, self.qemu)
        try:
            maps = [session.attempt(data)[1] for data in (b'A', b'B', b'AFL!', b'A', b'A')]
            self.assertEqual(maps[0], maps[3]); self.assertEqual(maps[3], maps[4])
            self.assertEqual(len(set(maps)), 3)
            self.assertEqual(session.prepared.read_bytes(), b'P')
            self.assertEqual(len(set(session.children)), 5)
        finally: session.close()
        self.assertEqual(session.process.returncode, 0)

    def test_controller_disconnect_terminates_parent(self):
        session = NativeSession(self.root/'disconnect', self.built, self.qemu)
        session.close(abort=True)
        self.assertEqual(session.process.returncode, 86)
        self.assertIn('controller_lost', (session.root/'qemu.log').read_text())

    def test_input_consumed_before_retirement_and_unreleased_rss_are_rejected(self):
        for extra, reason in [('unarmed=on', 'input_opened_before_retirement'),
                              ('rss=1', 'phase1_resident_memory_not_released')]:
            directory = self.root/extra.replace('=', '-')
            with self.subTest(extra=extra), self.assertRaises(ConnectionError):
                NativeSession(directory, self.built, self.qemu, extra=extra)
            self.assertIn(reason, (directory/'qemu.log').read_text())

    def fault_guest(self, name, insertion, needle):
        directory = self.root/name; directory.mkdir()
        source = f.PROJECT/'experiments/afl_file/guest.S'
        text = source.read_text()
        self.assertEqual(text.count(needle), 1)
        (directory/'guest.S').write_text(text.replace(needle, insertion+needle))
        f.p.command('as', '--32', '--defsym', 'WORK_LOOPS=1000', '--defsym', 'CONSTANT_PATH=0',
                    directory/'guest.S', '-o', directory/'guest.o')
        f.p.command('ld', '-m', 'elf_i386', '-z', 'noexecstack', directory/'guest.o', '-o', directory/'guest')
        return self.built | {'guest': str(directory/'guest')}

    def test_inherited_file_description_is_rejected(self):
        built = self.fault_guest('fd-fixture',
            '    movl $5, %eax\n    movl $marker_name, %ebx\n    movl $65, %ecx\n'
            '    movl $0600, %edx\n    int $0x80\n',
            '    movl $5, %eax\n    movl input_pointer, %ebx\n')
        # The fixture's fixed marker path is outside the temporary test root;
        # use an existing harmless fd instead and leave it open deliberately.
        source = self.root/'fd-fixture/guest.S'
        text = source.read_text().replace('marker_name: .asciz "/tmp/afl-marker"',
                                         'marker_name: .asciz "/dev/null"')
        source.write_text(text)
        f.p.command('as', '--32', '--defsym', 'WORK_LOOPS=1000', '--defsym', 'CONSTANT_PATH=0',
                    source, '-o', source.with_suffix('.o'))
        f.p.command('ld', '-m', 'elf_i386', source.with_suffix('.o'), '-o', self.root/'fd-fixture/guest')
        directory = self.root/'extra-fd'
        with self.assertRaises(ConnectionError): NativeSession(directory, built, self.qemu)
        self.assertIn('inherited_guest_or_unknown_fd', (directory/'qemu.log').read_text())

    def test_child_timeout_reaps_child_and_parent_accepts_next_input(self):
        built = self.fault_guest('timeout-fixture',
            '    cmpb $72, buffer\n    jne 8f\n7:  jmp 7b\n8:\n', '.if !CONSTANT_PATH\n')
        session = NativeSession(self.root/'timeout', built, self.qemu)
        try:
            session.input.write_bytes(b'H')
            session.connection.sendall(struct.pack('!3I', w.MAGIC, 1, 20))
            magic, child, status, timed_out = struct.unpack('!4I', recv_exact(session.connection, 16))
            self.assertEqual((magic, timed_out), (w.MAGIC, 1))
            self.assertTrue(os.WIFSIGNALED(status))
            session.attempt(b'A')
        finally: session.close()


if __name__ == '__main__': unittest.main()
