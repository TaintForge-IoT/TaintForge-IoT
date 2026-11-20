import os
from pathlib import Path
import signal
import tempfile
import unittest
from unittest.mock import patch

from experiments.afl_file.build import components, guest
from scripts.verify_afl_warm_components import NativeSession
from taintforge_env import afl_outcome as o


class OutcomeTests(unittest.TestCase):
    def value(self, status=0, timeout=0, event=1, target=0, host=0, code=0):
        return o.decode(o.RESPONSE.pack(o.MAGIC, 100, status, timeout, event, target, host, code,
                                        0x804b100, 20, 18000, 0))

    def test_exit_86_and_nonzero_guest_exits_are_normal(self):
        for code in (0, 1, 86, 128, 255):
            value = self.value(status=code << 8, code=code)
            self.assertEqual(value['kind'], 'normal')
            self.assertEqual(value['guest_exit'], code)

    def test_host_signal_is_not_evidence_of_a_guest_crash(self):
        self.assertEqual(self.value(status=signal.SIGSEGV, event=0)['kind'], 'infra_error')
        self.assertEqual(self.value(status=signal.SIGABRT, event=2, target=11, host=11)['kind'], 'infra_error')
        self.assertEqual(self.value(status=86 << 8, event=0)['kind'], 'infra_error')

    def test_matching_guest_signal_and_controller_timeout(self):
        value = self.value(status=signal.SIGSEGV, event=2, target=11, host=11)
        self.assertEqual(value['kind'], 'guest_crash')
        o.check_bridge(o.bridge_header(value))
        value = self.value(status=signal.SIGKILL, event=0, timeout=1)
        self.assertEqual(value['kind'], 'timeout')
        self.assertEqual(self.value(status=signal.SIGKILL, event=0)['kind'], 'infra_error')

    def test_reported_sigsegv_racing_with_deadline_is_a_guest_crash(self):
        # Exact terminal record from fz.wnpnwvrp/cases/00000006/outcome.json.
        packet=o.RESPONSE.pack(o.MAGIC,50,139,1,2,11,11,0,134525118,51,9060,18)
        value=o.decode(packet)
        self.assertEqual(value['kind'],'guest_crash',value)
        self.assertEqual(value['guest_signal'],11)
        self.assertTrue(value['deadline_expired'])
        self.assertFalse(value['timed_out'])
        self.assertEqual(o.check_bridge(o.bridge_header(value)),1)

    def test_attested_exit_wins_a_race_with_deadline(self):
        for code in (0,86,255):
            with self.subTest(code=code):
                value=self.value(status=code << 8,timeout=1,code=code)
                self.assertEqual(value['kind'],'normal',value)
                self.assertEqual(value['guest_exit'],code)
                self.assertTrue(value['deadline_expired'])
                self.assertFalse(value['timed_out'])

    def test_expired_deadline_does_not_attest_an_unmatched_signal(self):
        for status,event,host in ((139,0,0),(139,2,6),(86 << 8,0,0)):
            with self.subTest(status=status,event=event,host=host):
                value=self.value(status=status,timeout=1,event=event,target=11 if event else 0,host=host)
                self.assertEqual(value['kind'],'infra_error',value)
        value=self.value(status=signal.SIGKILL,timeout=1,event=2,target=11,host=11)
        self.assertEqual(value['kind'],'timeout')
        self.assertTrue(value['timed_out'])
        self.assertIsNone(value['guest_signal'])


@unittest.skipUnless(os.environ.get('TF_WARM_QEMU'), 'TF_WARM_QEMU required')
class NativeOutcomeTests(unittest.TestCase):
    def test_real_child_exit_and_signal_race_with_expired_backend_deadline(self):
        # Delay WNOHANG observation in this test process only. Real children exit
        # before the parent observes its deadline, then native wait4 reaps them.
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            source=root/'wait_delay.c'
            source.write_text('''#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
pid_t wait4(pid_t pid, int *status, int options, struct rusage *usage)
{
    if (pid > 0 && (options & WNOHANG)) {
        struct timespec delay = {0, 150000000};
        while (nanosleep(&delay, &delay) && errno == EINTR) {}
        return 0;
    }
    pid_t (*next)(pid_t, int *, int, struct rusage *) = dlsym(RTLD_NEXT, "wait4");
    if (!next) _exit(99);
    return next(pid, status, options, usage);
}
''')
            library=root/'wait_delay.so'
            from taintforge_env import afl_file as f
            f.p.command('cc','-shared','-fPIC','-Wall','-Wextra','-Werror',source,'-ldl','-o',library)
            built=components(root/'build')
            built['guest']=str(guest(root/'faults',loops=1000,faults=True))
            with patch.dict(os.environ,{'LD_PRELOAD':str(library)}):
                session=NativeSession(root/'session',built,os.environ['TF_WARM_QEMU'])
            try:
                for data,kind,sig,code in ((b'S','guest_crash',11,None),(b'C','guest_crash',4,None),
                        (b'B','guest_crash',6,None),(b'A','normal',None,0),(b'E','normal',None,86),
                        (b'H','timeout',None,None)):
                    with self.subTest(data=data):
                        value,coverage,bitmap=session.attempt_outcome(data,timeout_ms=50)
                        self.assertEqual(value['kind'],kind,value)
                        self.assertTrue(value['deadline_expired'],value)
                        self.assertEqual(value['timed_out'],kind=='timeout')
                        self.assertEqual(value['guest_signal'],sig)
                        self.assertEqual(value['guest_exit'],code)
                        self.assertTrue(any(bitmap))
                        self.assertIsNone(session.process.poll())
                self.assertEqual(session.prepared.read_bytes(),b'P')
            finally:
                session.close()

    def test_guest_crashes_and_timeout_do_not_repeat_preparation_or_kill_parent(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            built = components(root/'build')
            built['guest'] = str(guest(root/'faults', loops=1000, faults=True))
            session = NativeSession(root/'session', built, os.environ['TF_WARM_QEMU'])
            try:
                first = session.attempt(b'A')[1]
                for data, expected, sig in ((b'C', 'guest_crash', 4), (b'S', 'guest_crash', 11),
                                            (b'B', 'guest_crash', 6), (b'H', 'timeout', None),
                                            (b'E', 'normal', None)):
                    with self.subTest(data=data):
                        value, coverage, bitmap = session.attempt_outcome(data, timeout_ms=30)
                        self.assertEqual(value['kind'], expected, value)
                        self.assertEqual(value['guest_signal'], sig)
                        self.assertTrue(any(bitmap))
                        self.assertEqual(coverage['started'], 1)
                        if data == b'E': self.assertEqual(value['guest_exit'], 86)
                        self.assertEqual(session.attempt(b'A')[1], first)
                        self.assertIsNone(session.process.poll())
                self.assertEqual(session.prepared.read_bytes(), b'P')
                self.assertEqual(len(set(session.children)), len(session.children))
            finally:
                session.close()


if __name__ == '__main__': unittest.main()
