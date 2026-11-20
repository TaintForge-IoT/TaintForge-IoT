"""Load the production observer in real QEMU; no Phase 1/M4 claims."""
import os
from pathlib import Path
import socket
import shlex
import subprocess
import tempfile
import unittest
import struct

from experiments.afl_file.build import guest
from experiments.retirement_observer import controller as c
from taintforge_env import afl_file as f, afl_outcome
from taintforge_env.afl_transport import recv_exact
from taintforge_env.afl_warm import MAGIC


@unittest.skipUnless(os.environ.get('TF_WARM_QEMU'), 'TF_WARM_QEMU required')
class ObserverInstallTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary=tempfile.TemporaryDirectory(prefix='tf-observer-install-')
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.root=Path(cls.temporary.name)
        cls.built=c.build_plugin(cls.root/'build')
        cls.guest=guest(cls.root/'guest',loops=1000)
        source=cls.root/'guest/delayed.S'
        text=(f.PROJECT/'experiments/afl_file/guest.S').read_text()
        text=text.replace('_start:\n','_start:\n    movl $162, %eax\n    movl $install_delay, %ebx\n    xorl %ecx, %ecx\n    int $0x80\n',1)
        text=text.replace('.section .rodata\n','.section .rodata\ninstall_delay: .long 1,0\n',1)
        source.write_text(text)
        c.p.command('as','--32','--defsym','WORK_LOOPS=1000','--defsym','CONSTANT_PATH=0',
                    '--defsym','FAULT_FIXTURE=0',source,'-o',cls.root/'guest/delayed.o')
        c.p.command('ld','-m','elf_i386','-z','noexecstack',cls.root/'guest/delayed.o','-o',cls.guest)
        cls.inherited_channel=False
        try:
            with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM):pass
        except PermissionError:cls.inherited_channel=True
        if cls.inherited_channel:
            plugin=cls.root/'build/libobserver_install_probe.so'
            flags=shlex.split(c.p.command('pkg-config','--cflags','--libs','glib-2.0'))
            c.p.command('cc','-std=c11','-O2','-g','-Wall','-Wextra','-Werror','-Wshadow',
                '-fPIC','-fvisibility=hidden','-shared','-pthread','-I',c.p.HERE/'vendor',
                c.HERE/'install_probe.c','-o',plugin,*flags)
            cls.built['plugin']=str(plugin)

    def launch(self,*,afl=True,warm=True,guard=True,duplicate=False,stdin=None,bad_map=False,
               backend_fd=None,private_marker=False):
        temp=tempfile.TemporaryDirectory(dir=self.root)
        self.addCleanup(temp.cleanup)
        root=Path(temp.name)
        peer=None
        if self.inherited_channel:
            listener,peer=socket.socketpair()
            listener.settimeout(2)
        else:
            listener=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
            listener.bind(str(root/'observer.sock'));listener.listen(1);listener.settimeout(2)
        self.addCleanup(listener.close)
        f.create_map(root/'coverage')
        if bad_map:(root/'coverage').write_bytes(b'invalid')
        (root/'input').write_bytes(b'A')
        options=[f'socket={root}/observer.sock','pause-ms=5000','total-ms=15000',
                 f'controller={os.getpid()}',f'controller-uid={os.getuid()}']
        if guard:options.append(f'control-guard={root}/private')
        if afl:options.extend((f'afl-coverage={root}/coverage',f'afl-input={root}/input'))
        if warm:options.extend((f'afl-warm={root}/warm.sock' if backend_fd is None else f'afl-warm=fd:{backend_fd}',
                                'afl-warm-rss=512'))
        if duplicate:options.append('controller=1')
        log=(root/'qemu.log').open('wb');self.addCleanup(log.close)
        environment=os.environ.copy()
        if peer is not None:environment['TF_OBSERVER_TEST_FD']=str(peer.fileno())
        descriptors=[] if peer is None else [peer.fileno()]
        if backend_fd is not None:descriptors.append(backend_fd)
        marker=root/'private/marker' if private_marker else root/'marker'
        process=subprocess.Popen([os.environ['TF_WARM_QEMU'],'-plugin',
            self.built['plugin']+','+','.join(options),str(self.guest),str(root/'input'),
            str(marker),str(root/'prepared'),str(root/'state/entry')],
            stdin=subprocess.DEVNULL if stdin is None else stdin,stdout=log,stderr=log,
            pass_fds=tuple(descriptors),env=environment,cwd='/')
        if peer is not None:peer.close()
        def reap():
            if process.poll() is None:process.kill()
            process.wait(timeout=3)
            if process.stdin is not None:process.stdin.close()
        self.addCleanup(reap)
        return process,listener,root

    def assert_hold(self,**options):
        process,listener,root=self.launch(**options)
        try:
            connection=listener if self.inherited_channel else listener.accept()[0]
        except socket.timeout:
            process.wait(timeout=3)
            self.fail('Production observer never connected: '+(root/'qemu.log').read_text())
        self.addCleanup(connection.close)
        channel=c.Channel(connection,lambda event:None,timeout=2)
        try:first=channel.receive('snapshot')
        except (OSError,RuntimeError,ValueError):
            process.wait(timeout=3)
            self.fail('Production observer did not reach its first hold: '+(root/'qemu.log').read_text())
        c.snapshot_ok(first,process.pid,1,1,control_guard=str(root/'private'))
        channel.command('CHECK 1')
        second=channel.receive('snapshot')
        c.snapshot_ok(second,process.pid,1,2,control_guard=str(root/'private'))
        c.same_hold(first,second,0)
        self.assertNotIn('Could not load plugin',(root/'qemu.log').read_text())
        connection.close()
        self.assertEqual(process.wait(timeout=3),125)
        self.assertIn('controller_lost',(root/'qemu.log').read_text())

    def assert_rejected(self,reason,**options):
        process,_,root=self.launch(**options)
        self.assertNotEqual(process.wait(timeout=3),0)
        text=(root/'qemu.log').read_text()
        self.assertIn('OBSERVER_INSTALL_ERROR reason='+reason,text)
        self.assertIn('qemu_plugin_install returned error code -1',text)

    def test_full_m5_warm_profile_reaches_real_bootstrap_hold(self):
        self.assert_hold()

    def test_standalone_m5_profile_still_reaches_bootstrap_hold(self):
        self.assert_hold(afl=False,warm=False)

    def test_guarded_fresh_coverage_is_still_rejected(self):
        self.assert_rejected('guard_requires_warm_afl',warm=False)

    def test_non_dev_null_stdin_cannot_disable_guard(self):
        self.assert_rejected('control_guard_initialization',stdin=subprocess.PIPE)

    def test_bad_coverage_map_is_rejected(self):
        self.assert_rejected('afl_coverage_map',bad_map=True)

    def test_duplicate_option_is_rejected(self):
        self.assert_rejected('invalid_or_duplicate_option',afl=False,warm=False,duplicate=True)

    def test_warm_backend_requires_coverage(self):
        self.assert_rejected('warm_backend_requirements',afl=False)

    def warm_children(self,*,refused=False):
        backend,child=socket.socketpair();backend.settimeout(5)
        self.addCleanup(backend.close);self.addCleanup(child.close)
        process,listener,root=self.launch(backend_fd=child.fileno(),private_marker=refused)
        child.close()
        connection=listener if self.inherited_channel else listener.accept()[0]
        self.addCleanup(connection.close)
        channel=c.Channel(connection,lambda event:None,timeout=3)
        for point in (1,2):
            first=channel.receive('snapshot')
            c.snapshot_ok(first,process.pid,point,1,control_guard=str(root/'private'))
            channel.command('CHECK '+str(point))
            second=channel.receive('snapshot')
            c.snapshot_ok(second,process.pid,point,2,control_guard=str(root/'private'))
            c.same_hold(first,second,0)
            channel.command('RESUME '+str(point));channel.receive('resumed')
            if point==1:
                channel.command('STAMP');channel.receive('stamp');channel.command('HOLD 2')
        checkpoint=channel.receive('warm_checkpoint')
        self.assertEqual(checkpoint['host_pid'],process.pid)
        try:magic,version,pid,_=struct.unpack('!4I',recv_exact(backend,16))
        except (OSError,RuntimeError):
            process.wait(timeout=3)
            self.fail('Warm backend did not connect: '+(root/'qemu.log').read_text())
        self.assertEqual((magic,version,pid),(MAGIC,2,process.pid))
        children=[]
        for data in (b'A',b'AFL!'):
            (root/'marker').unlink(missing_ok=True)
            (root/'input').write_bytes(data)
            with (root/'coverage').open('r+b') as stream:
                stream.write(f.HEADER.pack(b'TFACOV1\0',1,f.MAP_SIZE,0,0,0,0,0,0)+bytes(f.MAP_SIZE))
            backend.sendall(struct.pack('!3I',MAGIC,1,500))
            value=afl_outcome.decode(recv_exact(backend,afl_outcome.RESPONSE.size))
            children.append(value['child_namespace_pid'])
            if refused:
                self.assertEqual(value['kind'],'infra_error')
                self.assertEqual(value['wait_status'],126<<8)
            else:
                self.assertEqual((value['kind'],value['guest_exit']),('normal',0))
                coverage,bitmap=f.inspect_map(root/'coverage',complete=True)
                self.assertGreater(coverage['blocks'],0);self.assertTrue(any(bitmap))
                self.assertTrue((root/'marker').is_file())
        self.assertEqual(len(set(children)),2)
        self.assertEqual((root/'prepared').read_bytes(),b'P')
        backend.sendall(struct.pack('!3I',MAGIC,0,0))
        done=channel.receive('done')
        self.assertGreater(done['control_guard']['checked_syscalls'],0)
        self.assertEqual(process.wait(timeout=3),0)
        if refused:self.assertEqual((root/'qemu.log').read_text().count('reason=private_path'),2)

    def test_production_observer_warm_children_keep_guard_and_coverage(self):
        self.warm_children()

    def test_production_observer_guard_refusal_is_not_a_guest_crash(self):
        self.warm_children(refused=True)


if __name__=='__main__':unittest.main()
