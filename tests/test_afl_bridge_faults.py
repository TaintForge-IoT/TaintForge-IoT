"""Exercise the real forkserver relay, including a killed infrastructure child."""
import array
import ctypes
import os
from pathlib import Path
import select
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import unittest

from taintforge_env import afl_file as f


class BridgeFaultTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(); cls.addClassCleanup(cls.tmp.cleanup)
        cls.root = Path(cls.tmp.name)
        cls.bridge = cls.root/'bridge'
        f.p.command('cc', '-std=c11', '-Wall', '-Wextra', '-Werror', '-O2',
                    f.PROJECT/'experiments/afl_file/bridge.c', '-o', cls.bridge)
        # Model the external core-handler delay without changing core_pattern.
        source = cls.root/'core_delay.c'
        source.write_text('''#define _GNU_SOURCE
#include <dlfcn.h>
#include <signal.h>
#include <sys/prctl.h>
#include <time.h>
#include <unistd.h>
int kill(pid_t pid, int sig)
{
    int (*next)(pid_t, int) = dlsym(RTLD_NEXT, "kill");
    if (!next) _exit(99);
    if (pid == getpid() && (sig == SIGSEGV || sig == SIGILL || sig == SIGABRT) &&
        prctl(PR_GET_DUMPABLE, 0L, 0L, 0L, 0L) != 0) {
        struct timespec delay = {2, 0};
        nanosleep(&delay, NULL);
    }
    return next(pid, sig);
}
''')
        cls.core_delay = cls.root/'core_delay.so'
        f.p.command('cc', '-shared', '-fPIC', '-Wall', '-Wextra', '-Werror',
                    source, '-ldl', '-o', cls.core_delay)

    def run_relay(self, *, kill=False, kind=0, sig=0, delayed_core=False):
        libc = ctypes.CDLL(None, use_errno=True)
        shm = libc.shmget(0, f.MAP_SIZE, 0o1600)
        if shm < 0: self.skipTest('System V shared memory is unavailable')
        control_read, control_write = os.pipe()
        status_read, status_write = os.pipe()
        host, peer = socket.socketpair(); host.settimeout(3)
        (self.root/'input').write_bytes(b'A')
        launcher = ('import os,sys; a,b=int(sys.argv[1]),int(sys.argv[2]); '
                    'os.dup2(a,198); os.dup2(b,199); os.close(a); os.close(b); '
                    'os.execv(sys.argv[3],sys.argv[3:])')
        env = os.environ | {'__AFL_SHM_ID': str(shm)}
        if delayed_core:
            env['LD_PRELOAD'] = str(self.core_delay)
        process = subprocess.Popen([sys.executable, '-c', launcher, str(control_read), str(status_write),
            str(self.bridge), str(peer.fileno()), str(self.root/'input')],
            pass_fds=(control_read, status_write, peer.fileno()),
            env=env, stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE, start_new_session=True)
        peer.close(); os.close(control_read); os.close(status_write)
        child = None
        attempt = None
        def word(timeout=3):
            self.assertTrue(select.select([status_read], [], [], timeout)[0], 'No forkserver response')
            data = os.read(status_read, 4)
            self.assertEqual(len(data), 4)
            return struct.unpack('=I', data)[0]
        try:
            self.assertEqual(word(), 0)
            os.write(control_write, struct.pack('=I', 0))
            marker, controls, flags, _ = host.recvmsg(1, socket.CMSG_SPACE(4))
            self.assertEqual(marker, b'C'); self.assertEqual(flags, 0)
            descriptor = array.array('i'); descriptor.frombytes(controls[0][2])
            attempt = socket.socket(fileno=descriptor[0]); attempt.settimeout(3)
            child = word()
            if kill:
                os.kill(child, signal.SIGKILL)
                _, error = process.communicate(timeout=3)
                self.assertEqual(process.returncode, 86)
                self.assertIn(b'refusing a fake target crash', error)
                self.assertEqual(os.read(status_read, 4), b'')
            else:
                from taintforge_env.afl_transport import recv_exact
                self.assertEqual(struct.unpack('!I', recv_exact(attempt,4))[0],1)
                self.assertEqual(recv_exact(attempt,1),b'A')
                attempt.sendall(struct.pack('!4I',0x54464131,kind,sig,f.MAP_SIZE)+b'\1'+bytes(f.MAP_SIZE-1))
                status=word(timeout=1 if delayed_core else 3)
                if kind==0:self.assertTrue(os.WIFEXITED(status) and os.WEXITSTATUS(status)==0)
                else:
                    self.assertTrue(os.WIFSIGNALED(status) and os.WTERMSIG(status)==sig)
                    self.assertFalse(os.WCOREDUMP(status))
                os.close(control_write);control_write=None
                process.communicate(timeout=3)
                self.assertEqual(process.returncode,0)
        finally:
            if process.poll() is None:
                os.killpg(process.pid,signal.SIGKILL);process.communicate(timeout=3)
            if attempt is not None:attempt.close()
            host.close();os.close(status_read)
            if control_write is not None:os.close(control_write)
            libc.shmctl(shm,2,None)

    def test_unattested_sigkill_is_an_infrastructure_failure(self):
        self.run_relay(kill=True)

    def test_normal_result_is_delivered(self):
        self.run_relay()

    def test_attested_guest_signal_is_delivered(self):
        self.run_relay(kind=1,sig=signal.SIGSEGV)

    def test_core_handler_delay_cannot_turn_attested_crashes_into_timeouts(self):
        for sig in (signal.SIGILL, signal.SIGSEGV, signal.SIGABRT):
            with self.subTest(signal=sig):
                self.run_relay(kind=1, sig=sig, delayed_core=True)
