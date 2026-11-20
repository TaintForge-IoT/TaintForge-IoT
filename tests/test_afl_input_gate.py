"""Native input barrier with real QEMU uninstall and the production observer.

The retirement peer is a test plugin. M4 analysis and service isolation are
covered by the host acceptance runner, not by this socketpair transport test.
"""
import os
from pathlib import Path
import select
import shlex
import socket
import struct
import subprocess
import tempfile
import time
import unittest

from experiments.afl_campaign_corpus import build as corpus
from experiments.retirement_observer import controller as observer
from taintforge_env import afl_file as f, afl_outcome
from taintforge_env.afl_transport import recv_exact
from taintforge_env.afl_warm import FilesystemBaseline, MAGIC


@unittest.skipUnless(os.environ.get('TF_WARM_QEMU'), 'TF_WARM_QEMU with ABI 3 required')
class NativeInputGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.root = Path(cls.temporary.name)
        cls.qemu = os.environ['TF_WARM_QEMU']
        flags = shlex.split(f.p.command('pkg-config', '--cflags', '--libs', 'glib-2.0'))
        cls.observer = cls.root/'observer.so'
        cls.retirement = cls.root/'retirement.so'
        common = ('cc', '-std=c11', '-O2', '-g', '-Wall', '-Wextra', '-Werror',
                  '-fPIC', '-fvisibility=hidden', '-shared', '-pthread', '-I', f.p.HERE/'vendor')
        f.p.command(*common, observer.HERE/'install_probe.c', '-o', cls.observer, *flags)
        f.p.command(*common, f.PROJECT/'experiments/afl_file/retirement_probe.c',
                    '-o', cls.retirement, *flags)
        cls.guest = corpus.build(cls.root/'fixture', 'prefix')
        source = (corpus.HERE/'guest.S').read_text()
        original = ('    movl $5, %eax\n    movl input_pointer, %ebx\n'
                    '    xorl %ecx, %ecx\n    int $0x80\n')
        if source.count(original) != 1:
            raise ValueError('Corpus input syscall changed')
        source = source.replace(original, '    movl $295, %eax\n    movl $-100, %ebx\n'
                                '    movl input_pointer, %ecx\n    xorl %edx, %edx\n    int $0x80\n')
        assembly = cls.root/'openat.S'
        assembly.write_text(source)
        obj = cls.root/'openat.o'
        cls.openat_guest = cls.root/'openat-i386'
        f.p.command('as', '--32', '--defsym', 'RECORD_PARSER=0', '--defsym', 'PREP_LOOPS=0',
                    '--defsym', 'ENABLE_FAULTS=0', '--defsym', 'LEAK_FD=0', assembly, '-o', obj)
        f.p.command('ld', '-m', 'elf_i386', '-z', 'noexecstack', '--build-id=none', obj, '-o', cls.openat_guest)

    def launch(self, *, pause_ms=5000, retirement=True, reverse=False, openat=False,
               qemu=None, bootstrap=True):
        temporary = tempfile.TemporaryDirectory(dir=self.root)
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        fs = root/'fs'
        (fs/'etc').mkdir(parents=True)
        (fs/'tmp').mkdir()
        input_file = fs/'etc/input'
        input_file.write_bytes(b'A')
        f.create_map(root/'coverage')
        control, observer_peer = socket.socketpair()
        backend, backend_peer = socket.socketpair()
        retire, retire_peer = socket.socketpair()
        for connection in (control, backend, retire):
            connection.settimeout(8)
            self.addCleanup(connection.close)
        options = [f'socket={root}/observer.sock', f'pause-ms={pause_ms}', 'total-ms=20000',
                   f'controller={os.getpid()}', f'controller-uid={os.getuid()}',
                   f'control-guard={root}/private', f'afl-coverage={root}/coverage',
                   f'afl-input={input_file}', f'afl-warm=fd:{backend_peer.fileno()}', 'afl-warm-rss=512']
        plugins = [str(self.observer)+','+','.join(options)]
        descriptors = [observer_peer.fileno(), backend_peer.fileno()]
        if retirement:
            plugins.append(f'{self.retirement},control={retire_peer.fileno()},input={input_file}')
            descriptors.append(retire_peer.fileno())
        if reverse:
            plugins.reverse()
        command = [qemu or self.qemu, '-strace']
        for plugin in plugins:
            command.extend(('-plugin', plugin))
        guest = self.openat_guest if openat else self.guest
        command.extend((str(guest), str(input_file), str(fs/'tmp/marker'), str(fs/'tmp/prepared')))
        log = (root/'qemu.log').open('wb')
        self.addCleanup(log.close)
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=log, stderr=log,
            pass_fds=tuple(descriptors), cwd='/',
            env=os.environ | {'TF_OBSERVER_TEST_FD':str(observer_peer.fileno())})
        observer_peer.close()
        backend_peer.close()
        retire_peer.close()
        def reap():
            if process.poll() is None:
                process.kill()
            process.wait(timeout=5)
        self.addCleanup(reap)
        channel = observer.Channel(control, lambda event: None, timeout=8)
        if bootstrap:
            first = channel.receive('snapshot')
            observer.snapshot_ok(first, process.pid, 1, 1, control_guard=str(root/'private'))
            channel.command('CHECK 1')
            channel.receive('snapshot')
            channel.command('RESUME 1')
            channel.receive('resumed')
        return root, fs, process, channel, backend, retire

    def release_retirement(self, process, channel, retire):
        self.assertEqual(recv_exact(retire, 1), b'R')
        coordinates = struct.unpack('!9I', recv_exact(retire, 36))
        stack = recv_exact(retire, 32)
        channel.command('STAMP')
        channel.receive('stamp')
        retire.sendall(b'G')
        self.assertEqual(recv_exact(retire, 1), b'D')
        deadline = time.monotonic()+3
        while str(self.retirement) in Path(f'/proc/{process.pid}/maps').read_text():
            self.assertLess(time.monotonic(), deadline, 'Retirement module remained mapped')
            time.sleep(.001)
        return {'regs':list(coordinates[:8]), 'pc':coordinates[8], 'stack_hex':stack.hex()}

    def test_delayed_controller_reaches_checkpoint_in_both_plugin_orders(self):
        for reverse, openat in ((False, False), (True, False), (False, True), (True, True)):
            with self.subTest(reverse=reverse, openat=openat):
                root, fs, process, channel, backend, retire = self.launch(reverse=reverse, openat=openat)
                original = self.release_retirement(process, channel, retire)
                self.assertEqual(select.select([backend, channel.connection], [], [], 3)[0], [])
                self.assertIsNone(process.poll())
                channel.command('HOLD 2')
                first = channel.receive('snapshot')
                observer.snapshot_ok(first, process.pid, 2, 1, control_guard=str(root/'private'))
                self.assertEqual({key:first[key] for key in original}, original)
                self.assertEqual(select.select([backend], [], [], 0)[0], [])
                channel.command('CHECK 2')
                second = channel.receive('snapshot')
                observer.same_hold(first, second, 0)
                self.assertEqual(select.select([backend], [], [], 0)[0], [])
                channel.command('RESUME 2')
                channel.receive('resumed')
                checkpoint = channel.receive('warm_checkpoint')
                observer.warm_checkpoint_ok(checkpoint, process.pid, first['seq'])
                self.assertEqual(checkpoint['seq'], first['seq'])
                try:
                    hello = struct.unpack('!4I', recv_exact(backend, 16))
                except (ConnectionError, OSError):
                    self.fail('Warm handshake failed: '+(root/'qemu.log').read_text())
                self.assertEqual(hello[:2], (MAGIC, 2))
                baseline = FilesystemBaseline(fs, root/'baseline')
                children = []
                for data in (b'A', b'B', b'AFL!', b'A'):
                    baseline.restore()
                    (fs/'etc/input').write_bytes(data)
                    backend.sendall(struct.pack('!3I', MAGIC, 1, 500))
                    outcome = afl_outcome.decode(recv_exact(backend, afl_outcome.RESPONSE.size))
                    self.assertEqual((outcome['kind'], outcome['guest_exit'], outcome['guest_signal']),
                                     corpus.expected('prefix', data))
                    children.append(outcome['child_namespace_pid'])
                    self.assertEqual((fs/'tmp/prepared').read_bytes(), b'P')
                    self.assertEqual((fs/'tmp/marker').read_bytes(), b'K')
                self.assertEqual(len(set(children)), len(children))
                backend.sendall(struct.pack('!3I', MAGIC, 0, 0))
                done = channel.receive('done')
                observer.continuation_ok(done, process.pid, first['seq'], checkpoint=checkpoint)
                self.assertEqual(process.wait(timeout=5), 0, (root/'qemu.log').read_text())
                self.assertNotIn('nanosleep(', (root/'qemu.log').read_text())

    def test_input_before_retirement_stamp_is_rejected(self):
        root, fs, process, channel, backend, retire = self.launch(retirement=False)
        self.assertEqual(process.wait(timeout=5), 126)
        self.assertIn('input_opened_before_retirement', (root/'qemu.log').read_text())

    def test_missing_hold_times_out(self):
        root, fs, process, channel, backend, retire = self.launch(pause_ms=500)
        self.release_retirement(process, channel, retire)
        self.assertEqual(process.wait(timeout=5), 124)
        self.assertIn('input_gate_timeout', (root/'qemu.log').read_text())

    def test_controller_disconnect_aborts_wait(self):
        root, fs, process, channel, backend, retire = self.launch()
        self.release_retirement(process, channel, retire)
        channel.connection.close()
        self.assertEqual(process.wait(timeout=5), 125)
        self.assertIn('controller_lost', (root/'qemu.log').read_text())

    def test_resume_without_check_is_rejected(self):
        root, fs, process, channel, backend, retire = self.launch()
        self.release_retirement(process, channel, retire)
        channel.command('HOLD 2')
        channel.receive('snapshot')
        channel.command('RESUME 2')
        self.assertEqual(process.wait(timeout=5), 126)
        self.assertIn('command_order', (root/'qemu.log').read_text())

    @unittest.skipUnless(os.environ.get('TF_WARM_QEMU_V2'), 'TF_WARM_QEMU_V2 required for ABI rejection')
    def test_old_backend_is_refused_before_guest_execution(self):
        root, fs, process, channel, backend, retire = self.launch(
            qemu=os.environ['TF_WARM_QEMU_V2'], bootstrap=False)
        self.assertNotEqual(process.wait(timeout=5), 0)
        self.assertIn('warm_backend_gate_abi3_required', (root/'qemu.log').read_text())
        self.assertFalse((fs/'tmp/prepared').exists())


if __name__ == '__main__':
    unittest.main()
