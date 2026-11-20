"""Fault injection is bound to one admitted, actively fuzzed capsule process."""
from pathlib import Path
import signal
import tempfile
import unittest
from unittest.mock import patch

from scripts import inject_afl_capsule_fault as injector
from taintforge_env import afl_file as f


class WarmFaultInjectionTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup)
        self.root=Path(temp.name)
        self.run=self.root/'warm-session/iterations/0000/run'
        (self.run/'config').mkdir(parents=True);(self.run/'logs/capsule').mkdir(parents=True)
        (self.root/'cases/00000000').mkdir(parents=True)
        (self.root/'cases/00000000/result.json').write_text('{}')
        self.proof={'profile':'warm-m5-capsule-v1','status':'admitted'}
        self.binding={'run_dir':str(self.run),'afl_warm':{'campaign_root':str(self.root)}}
        self.record={'qemu_pid':77,'identity':{'attempt_id':'a'},'unit':'bound.service'}
        self.target={'pid':123,'role':'qemu','start_ticks':500}
        f.atomic_json(self.root/'campaign.json',{'status':'running'})
        f.atomic_json(self.root/'warm-ready.json',{'capsule_checkpoint':self.proof})
        f.atomic_json(self.run/'config/capsule_binding.json',self.binding)
        f.atomic_json(self.run/'logs/capsule/workers.json',self.record)

    def invoke(self,*,identities=None):
        with patch.object(injector.afl_capsule,'checkpoint',return_value=self.proof), \
             patch.object(injector,'target_identity',side_effect=identities or [self.target,self.target]), \
             patch.object(injector.os,'pidfd_open',return_value=999) as opened, \
             patch.object(injector.os,'close') as closed, \
             patch.object(injector.signal,'pidfd_send_signal') as sent:
            try:return injector.inject(self.root,'qemu',seconds=1)
            finally:self.opened,self.closed,self.sent=opened,closed,sent

    def test_kill_follows_admission_child_execution_and_rechecked_pidfd_identity(self):
        result=self.invoke()
        self.assertEqual(result['status'],'injected')
        self.sent.assert_called_once_with(999,signal.SIGKILL)
        self.closed.assert_called_once_with(999)

    def test_stale_readiness_cannot_authorize_a_signal(self):
        f.atomic_json(self.root/'warm-ready.json',{'capsule_checkpoint':{'status':'stale'}})
        with self.assertRaisesRegex(RuntimeError,'admitted M5'):self.invoke()
        self.opened.assert_not_called();self.sent.assert_not_called()

    def test_pid_reuse_or_process_replacement_is_refused_after_open(self):
        with self.assertRaisesRegex(RuntimeError,'target changed'):
            self.invoke(identities=[self.target,self.target|{'start_ticks':501}])
        self.closed.assert_called_once_with(999);self.sent.assert_not_called()

    def test_completed_campaign_is_never_killed(self):
        f.atomic_json(self.root/'campaign.json',{'status':'completed'})
        with self.assertRaisesRegex(RuntimeError,'boundary was missed'):self.invoke()
        self.opened.assert_not_called();self.sent.assert_not_called()

    def test_escaping_binding_is_never_killed(self):
        f.atomic_json(self.run/'config/capsule_binding.json',self.binding|{'run_dir':'/other/run'})
        with self.assertRaisesRegex(RuntimeError,'escapes'):self.invoke()
        self.opened.assert_not_called();self.sent.assert_not_called()


if __name__=='__main__':unittest.main()
