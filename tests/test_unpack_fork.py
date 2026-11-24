"""Process-scoped unpacking with real Linux i386 guests and the production plugin."""
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from unpacker import unpack
from unpacker import unpack_process


def read(path):
    return json.loads(path.read_text())


def events(path):
    return [json.loads(line) for line in path.read_text().splitlines()]


class ForkSupervisor(unittest.TestCase):
    def test_last_socket_release_can_follow_terminal_record(self):
        receiver, sender = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        with receiver, sender:
            receiver.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
            for kind in ('S', 'X'):
                sender.send(struct.pack('=ii', ord(kind), 0))
            release = threading.Timer(0.05, sender.close)
            release.start()
            try:
                exits = unpack_process._process_exits(receiver, os.getpid(), 0, time.monotonic() + 2)
            finally:
                release.join()
            self.assertEqual(exits['parent']['returncode'], 0)

    def test_parent_can_report_child_killed_before_its_first_callback(self):
        receiver, sender = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        with receiver, sender:
            receiver.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
            sender.send(struct.pack('=ii', ord('S'), 0))
            child = os.fork()
            if child == 0:
                signal.pause()
                os._exit(1)
            try:
                fd = os.pidfd_open(child)
                try:
                    sender.sendmsg([struct.pack('=ii', ord('F'), child)],
                                   [(socket.SOL_SOCKET, socket.SCM_RIGHTS, struct.pack('=i', fd))])
                finally:
                    os.close(fd)
            finally:
                os.kill(child, signal.SIGKILL)
                os.waitpid(child, 0)
            sender.send(struct.pack('=ii', ord('X'), 0))
            sender.close()
            exits = unpack_process._process_exits(receiver, os.getpid(), 0, time.monotonic() + 1)
            self.assertEqual(exits['child'], {'pid': child, 'returncode': -9, 'signal': 9})

    def test_zombie_with_hidden_exit_field_is_incomplete(self):
        pid = os.fork()
        if pid == 0:
            os._exit(7)
        try:
            os.waitid(os.P_PID, pid, os.WEXITED | os.WNOWAIT)
            # Simulate pidfs retaining the status only at reap, while procfs
            # still exposes the zombie. An unreadable exit field can look zero.
            def no_exit_info(fd, request, info):
                struct.pack_into('=Q', info, 0, 0)

            with patch.object(unpack_process.fcntl, 'ioctl', side_effect=no_exit_info):
                self.assertEqual(unpack_process._child_returncode(-1, pid), 7)
                with patch.object(os, 'readlink', side_effect=PermissionError):
                    with self.assertRaises(unpack.UnpackError) as raised:
                        unpack_process._child_returncode(-1, pid)
                self.assertEqual(raised.exception.reason, 'INCOMPLETE_PROCESS_EXIT')
        finally:
            os.waitpid(pid, 0)

    def test_missing_observer_cannot_pass_as_single_process(self):
        with tempfile.TemporaryDirectory() as work:
            out = Path(work) / 'case'
            result = unpack_process.run_fork_replay([shutil.which('true')], {'id': 'silent'}, out,
                                                    plugin='unused', payload_role='parent')
            self.assertEqual(result['returncode'], 0)
            self.assertEqual(result['process_exit_error']['reason'], 'INCOMPLETE_PROCESS_EXIT')
            self.assertFalse(unpack.compare_results([result]))
            self.assertEqual(result, read(out / 'result.json'))

    def test_timeout_after_root_exit(self):
        with tempfile.TemporaryDirectory() as work:
            out = Path(work) / 'case'
            script = 'import os,time\nif os.fork(): os._exit(0)\ntime.sleep(30)'
            result = unpack.run_process([sys.executable, '-c', script], {'id': 'timeout'},
                                        out, timeout=0.35, wait_for_group=True)
            self.assertEqual(result['returncode'], 0)
            self.assertTrue(result['timed_out'])
            self.assertLess(result['wall_seconds'], 5)


class ForkCapture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.work = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.work.cleanup)
        cls.root = Path(cls.work.name)
        qemu = os.environ.get('TF_QEMU_I386') or shutil.which('qemu-i386')
        plugin = os.environ.get('TF_PHASE1_PLUGIN')
        include = os.environ.get('TF_QEMU_INCLUDE')
        if not qemu or (not plugin and not include):
            raise unittest.SkipTest('set TF_QEMU_I386 and either TF_QEMU_INCLUDE or TF_PHASE1_PLUGIN')
        cls.qemu = Path(qemu).resolve(strict=True)
        cls.plugin = Path(plugin).resolve(strict=True) if plugin else unpack.build_plugin(include, cls.root / 'plugin')

    def capture(self, *defines, follow=True, stdin_base64='', cases=None):
        work = self.root / self._testMethodName
        work.mkdir()
        args = [part for value in defines for part in ('--defsym', value + '=1')]
        fixture = Path(__file__).with_name('phase1_unpack_fork.S')
        subprocess.run(['as', '--32', *args, '-o', work / 'guest.o', fixture], check=True)
        guest = work / 'guest.elf'
        subprocess.run(['ld', '-m', 'elf_i386', '-static', '-o', guest, work / 'guest.o'], check=True)
        symbols = subprocess.check_output(['nm', '-n', guest], text=True)
        self.entry = next(int(line.split()[0], 16) for line in symbols.splitlines()
                          if line.endswith(' T payload_entry'))
        self.out = work / 'out'
        return unpack.unpack_sample(guest, self.out, qemu=self.qemu, plugin=self.plugin,
                                    cases=cases or [{'id': 'fork', 'stdin_base64': stdin_base64}],
                                    timeout=10, follow_fork=follow)

    def check_child(self, summary, inherited, local):
        self.assertEqual(summary['status'], unpack.FORK_STATUS)
        self.assertEqual(summary['entry'], self.entry)
        receipt = summary['process_capture']
        self.assertEqual(receipt, read(self.out / 'process-capture.json'))
        self.assertEqual(receipt['selected_role'], 'child')
        self.assertEqual(receipt['selected_directory'], 'capture/child')
        self.assertEqual(receipt['processes']['parent']['capture_status'], 'not_available')
        self.assertEqual(receipt['processes']['child']['capture_status'], 'success')
        self.assertEqual(receipt['entry_stores'], {
            'address': self.entry, 'candidate_id': summary['selected_candidate_id'], 'entry_bytes': 5,
            'prefork_guest_store_bytes': inherited, 'child_guest_store_bytes': local})
        parent = events(self.out / 'capture/events.jsonl')
        child = events(self.out / 'capture/child/events.jsonl')
        self.assertEqual([e['data'] for e in parent if e['event_type'] == 'process_fork'], [receipt['fork']])
        self.assertEqual([e['data'] for e in child if e['event_type'] == 'process_fork_child'], [receipt['fork']])
        self.assertNotEqual(parent[0]['analysis_instance_id'], child[0]['analysis_instance_id'])
        self.assertEqual(receipt['fork']['parent_pid'], read(self.out / 'capture-process.json')['root_pid'])
        self.assertLess(receipt['fork']['fork_trace_seq'], summary['capture_trace_seq'])
        for artifact in ('packed', 'rebuilt'):
            for repeat in ('0', '1'):
                self.assertEqual((self.out / 'runs/case-000' / artifact / repeat / 'stdout').read_bytes(),
                                 b'fork-child-ok\n')

    def test_inherited_store_at_child_oep(self):
        self.check_child(self.capture(), 5, 0)

    def test_private_clone_with_child_tid(self):
        summary = self.capture('LIBC_CLONE')
        self.check_child(summary, 5, 0)
        fork = summary['process_capture']['fork']
        self.assertEqual((fork['syscall_nr'], fork['clone_flags']), (120, 0x01200011))

    def test_child_overwrites_one_entry_byte(self):
        self.check_child(self.capture('CHILD_REWRITE'), 4, 1)

    def test_kernel_copy_does_not_inherit_a_guest_store(self):
        self.check_child(self.capture('READ_ENTRY_BYTE', stdin_base64='BA=='), 4, 0)

    def test_child_unpacks_after_fork(self):
        self.check_child(self.capture('CHILD_BUILD'), 0, 5)

    def test_parent_exits_before_child_entry(self):
        self.check_child(self.capture('ROOT_FIRST'), 5, 0)

    def check_masked_replay(self, value, expected, *defines):
        cases = [{'id': 'capture'}, {'id': 'masked', 'stdin_base64': value}]
        with self.assertRaises(unpack.UnpackError) as raised:
            self.capture('REPLAY_STATUS', *defines, cases=cases)
        self.assertEqual(raised.exception.reason, 'SELECTED_CASE_MISMATCH', str(raised.exception))
        first, second = read(self.out / 'comparisons.json')
        self.assertTrue(first['matched'])
        self.assertFalse(second['matched'])
        for packed, rebuilt in zip(second['executions']['packed'], second['executions']['rebuilt'], strict=True):
            for field in ('returncode', 'stdout_sha256', 'stderr_sha256', 'output_files'):
                self.assertEqual(packed[field], rebuilt[field])
            self.assertEqual(packed['returncode'], 0)
            self.assertEqual(packed['process_exits']['child']['returncode'], expected)
            self.assertEqual(packed['process_exits']['child']['signal'], -expected if expected < 0 else None)
            self.assertEqual(set(rebuilt['process_exits']), {'parent'})
        self.assertEqual(len(second['executions']['rebuilt']), 2)

    def test_reaped_child_nonzero_on_second_input(self):
        self.check_masked_replay('Bw==', 7)

    def test_child_signaled_on_second_input(self):
        self.check_masked_replay('CQ==', -signal.SIGKILL)

    def test_orphan_signaled_on_second_input(self):
        self.check_masked_replay('CQ==', -signal.SIGKILL, 'ROOT_FIRST')

    def test_missing_kernel_exit_evidence_is_incomplete(self):
        with patch.object(unpack_process.fcntl, 'ioctl', side_effect=OSError('ioctl unavailable')):
            with self.assertRaisesRegex(unpack.UnpackError, 'PIDFD_GET_INFO') as raised:
                self.capture()
        self.assertEqual(raised.exception.reason, 'INCOMPLETE_PROCESS_EXIT')
        self.assertFalse(read(self.out / 'comparisons.json')[0]['matched'])

    def test_parent_postfork_write_is_private(self):
        with self.assertRaises(unpack.UnpackError) as raised:
            self.capture('AFTER_ONLY')
        self.assertEqual(raised.exception.reason, 'NO_PROCESS_CAPTURE')
        self.assertEqual((self.out / 'capture-process/stdout').read_bytes(), b'fork-child-ok\n')
        receipt = read(self.out / 'process-capture.json')
        self.assertEqual([r['capture_status'] for r in receipt['processes'].values()],
                         ['not_available', 'not_available'])
        self.assertFalse(any(e['event_type'] == 'oep_candidate_observed'
                             for e in events(self.out / 'capture/child/events.jsonl')))
        self.assertFalse((self.out / 'rebuilt.elf').exists())

    def test_only_parent_has_a_capture(self):
        summary = self.capture('BOTH', 'CHILD_IDLE')
        self.assertEqual((summary['entry'], summary['process_capture']['selected_role']), (self.entry, 'parent'))
        self.assertEqual(summary['process_capture']['processes']['child']['capture_status'], 'not_available')

    def test_two_images_require_disambiguation(self):
        with self.assertRaises(unpack.UnpackError) as raised:
            self.capture('BOTH')
        self.assertEqual(raised.exception.reason, 'AMBIGUOUS_PROCESS_CAPTURE')
        self.assertTrue(all(r['capture_status'] == 'success'
                            for r in read(self.out / 'process-capture.json')['processes'].values()))
        self.assertFalse((self.out / 'rebuilt.elf').exists())

    def test_abnormal_child_exit(self):
        with self.assertRaisesRegex(unpack.UnpackError, 'guest exit in child'):
            self.capture('CHILD_FAULT')
        self.assertFalse((self.out / 'rebuilt.elf').exists())

    def test_shared_memfd_still_mapped_at_fork(self):
        with self.assertRaisesRegex(unpack.UnpackError, 'unsupported_fork_memory_mapping'):
            self.capture('MEMFD_SHARED')

    def test_shared_memfd_unmapped_before_fork(self):
        self.check_child(self.capture('MEMFD_SHARED', 'RELEASE_SHARED'), 5, 0)

    def test_fork_after_observed_candidate(self):
        with self.assertRaisesRegex(unpack.UnpackError, 'fork_after_candidate'):
            self.capture('LATE_FORK')

    def test_shared_mapping_is_out_of_profile(self):
        with self.assertRaisesRegex(unpack.UnpackError, 'unsupported_fork_memory_mapping'):
            self.capture('SHARED_PAGE')

    def test_vfork_is_out_of_profile(self):
        with self.assertRaisesRegex(unpack.UnpackError, 'process_or_thread_transition_requested'):
            self.capture('VFORK')

    def test_second_fork_is_reported(self):
        with self.assertRaisesRegex(unpack.UnpackError, 'second_fork_requested'):
            self.capture('SECOND_FORK')
        self.assertFalse((self.out / 'rebuilt.elf').exists())

    def test_second_sibling_before_oep_is_reported(self):
        with self.assertRaisesRegex(unpack.UnpackError, 'second_fork_requested'):
            self.capture('SECOND_SIBLING')
        self.assertFalse((self.out / 'rebuilt.elf').exists())

    def test_single_process_upx_memfd_with_original_oracle(self):
        corpus = Path(__file__).resolve().parents[1] / 'unpacker/mvp/corpus'
        out = self.root / self._testMethodName
        summary = unpack.unpack_sample(corpus / 'jsmn.upx', out, qemu=self.qemu, plugin=self.plugin,
                                       oracle=corpus / 'jsmn.original', follow_fork=True,
                                       cases=[{'id': 'json', 'stdin_base64': 'e30K'}])
        self.assertIsNone(summary['process_capture']['fork'])
        self.assertTrue(read(out / 'oracle.json')['complete_exact_match'])
        self.assertTrue(read(out / 'oracle.json')['entry_exact'])

    def test_single_process_in_fork_profile(self):
        summary = self.capture('NO_FORK')
        self.assertEqual(summary['entry'], self.entry)
        self.assertIsNone(summary['process_capture']['fork'])
        self.assertEqual(set(summary['process_capture']['processes']), {'parent'})

    def test_single_process_in_default_profile(self):
        summary = self.capture('NO_FORK', follow=False)
        self.assertEqual((summary['status'], summary['entry']), (unpack.STATUS, self.entry))
        self.assertNotIn('process_capture', summary)

    def test_default_profile_rejects_fork(self):
        with self.assertRaises(unpack.UnpackError):
            self.capture(follow=False)
        self.assertTrue(any('process_or_thread_transition_requested' in e['incomplete_reasons']
                            for e in events(self.out / 'capture/events.jsonl')))


if __name__ == '__main__':
    unittest.main()
