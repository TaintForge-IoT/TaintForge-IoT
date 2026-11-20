"""M5/warm admission uses independently verified M4 and analysis evidence."""
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
import os
from unittest.mock import patch

from taintforge_env import afl_capsule as a, afl_file as f, afl_warm as w
from taintforge_env import analysis_quality, capsule_control
from tests import test_capsule_control as control, test_input_retirement as base
from tests.test_analysis_quality import denied_evidence


class AdmissionPolicyTests(unittest.TestCase):
    def test_prepare_always_binds_m5_and_keeps_strict_default(self):
        with tempfile.TemporaryDirectory() as temporary:
            out=Path(temporary)
            with patch.object(f.p,'command',return_value=' qemu_plugin_tf_warm_configure\n qemu_plugin_tf_warm_arm\n qemu_plugin_tf_warm_abi2'), \
                 patch.object(f,'prepare_campaign',return_value={'source_sha256':{}}) as prepare:
                result=w.prepare_campaign(out,binary='/bin/sample',qemu='/qemu',plugin='/plugin',
                                          guest_path='/etc/input',seeds='/seeds')
            self.assertEqual(prepare.call_args.kwargs['analysis_policy'],'strict')
            self.assertIn('--capsule-control-guard',prepare.call_args.kwargs['pipeline_options'])
            self.assertEqual(result['warm']['capsule_profile'],a.PROFILE)
            self.assertTrue(set(a.SOURCES)<=set(result['source_sha256']))

    def test_guard_cannot_be_combined_with_legacy_or_fresh_afl(self):
        for config in ({'afl_file':{}},{'afl_warm':{}},{'afl_file':{},'afl_warm':{}}):
            with self.subTest(config=config), self.assertRaisesRegex(RuntimeError,'M5 AFL requires'):
                a.validate_binding({'settings':{'control_guard':capsule_control.policy()},**config})
        with self.assertRaises(RuntimeError):
            a.validate_binding({'settings':{},'afl_warm':{'capsule_profile':a.PROFILE}})

    def test_profile_cannot_be_misspelled_or_downgraded(self):
        value=w.configuration('/tmp/tf-m5',bootstrap_seconds=60,campaign_seconds=30,
                              timeout_ms=100,max_rss_mib=512,capsule_m5=True)
        for bad in ('off','',None,True):
            with self.subTest(profile=bad),self.assertRaises(RuntimeError):
                w.validate(value|{'capsule_profile':bad})


class CapsuleWarmIntegrationTests(unittest.TestCase):
    setUp=base.InputRetirementTests.setUp
    prepare_input=base.InputRetirementTests.prepare_input
    invoke=base.InputRetirementTests.invoke
    prepare_guarded=control.ControlIntegrationTests.prepare_guarded

    def prepare_warm(self, *, strict=False):
        out,launch=self.prepare_guarded()
        path=Path(launch['template_run_dir'])/'config/runtime.json'
        runtime=f.read_json(path)
        if strict:runtime['capsule']['analysis_policy']=analysis_quality.policy('strict')
        f.create_guest_file(Path(launch['seed_rootfs']),'/etc/afl-input',b'A')
        runtime['afl_file']=f.settings('/etc/afl-input',b'A')
        runtime['afl_warm']=w.configuration(self.base/'campaign',bootstrap_seconds=60,
            campaign_seconds=30,timeout_ms=2000,max_rss_mib=512,capsule_m5=True)
        f.atomic_json(path,runtime)
        return out,launch

    @staticmethod
    def evidence(run,code,fault=None):
        binding,result=control.guarded_evidence(run,code,fault)
        path=run/'logs/capsule/observer-events.json'
        journal=f.read_json(path)
        journal['events'].insert(-1,dict(event='warm_checkpoint',protocol=3,host_pid=77,seq=520))
        for index,event in enumerate(journal['events'],1):
            event.update(controller_seq=index,controller_ns=index*1000)
        f.atomic_json(path,journal)
        result.update(warm={'status':'passed','phase1_runs':1,'children':2},controller_failures=[])
        f.atomic_json(run/'logs/capsule/supervisor.json',result)
        f.atomic_json(run/'logs/capsule/afl-checkpoint.json',a.checkpoint(binding,77))
        return binding,result

    def test_admission_and_finalization_bind_m5_analysis_and_one_phase1(self):
        out,launch=self.prepare_warm();executor=base.InputExecutor()
        with patch.object(base,'synthetic_evidence',side_effect=self.evidence):
            report,code=self.invoke(out,launch,executor)
        self.assertEqual(code,0,report.get('error'))
        capsule=report['capsule'];admitted=capsule['afl_checkpoint']
        self.assertEqual(admitted['profile'],a.PROFILE)
        self.assertEqual(capsule['control_guard']['status'],'verified')
        self.assertEqual(admitted['analysis_quality']['policy'],analysis_quality.policy('research'))
        self.assertFalse(admitted['memory_isolation'])
        run,binding,_=executor.runs[0]
        self.assertEqual(a.checkpoint(binding,77),admitted)
        ready={'capsule_checkpoint':admitted,'pid_namespace_pid':77,'run_dir':str(run)}
        contract=SimpleNamespace(attempt_id=binding['attempt_id'],contract_sha256=binding['attempt_contract_sha256'])
        a.verify_ready(ready,analysis_quality.policy('research'),contract=contract,
                       session_id=binding['session_id'],run_dir=run)
        self.assertEqual(report['executions_this_invocation'],1)
        for key,bad in (('schema',True),('parent_namespace_pid',True),('phase1_runs',2),
                        ('phase1_output_fds_released',False),('identity',{}),('analysis_quality',{}),
                        ('control_guard',{})):
            with self.subTest(key=key),self.assertRaises((RuntimeError,ValueError,KeyError)):
                a.verify_ready(ready|{'capsule_checkpoint':admitted|{key:bad}},analysis_quality.policy('research'))
        for kwargs in ({'session_id':'stale'},{'run_dir':run/'stale'},
                       {'contract':SimpleNamespace(attempt_id='stale',contract_sha256='0'*64)}):
            with self.subTest(kwargs=kwargs),self.assertRaises(RuntimeError):
                a.verify_ready(ready,analysis_quality.policy('research'),**kwargs)
        with self.assertRaisesRegex(RuntimeError,'policy mismatch'):
            a.verify_ready(ready,analysis_quality.policy('strict'))

    def test_changed_checkpoint_blocks_completion_and_resume(self):
        out,launch=self.prepare_warm();executor=base.InputExecutor()
        def changed(run,code,fault=None):
            binding,result=self.evidence(run,code,fault)
            path=run/'logs/capsule/afl-checkpoint.json'
            value=f.read_json(path);value['control_guard']['checked_syscalls']+=1
            f.atomic_json(path,value)
            return binding,result
        with patch.object(base,'synthetic_evidence',side_effect=changed):
            report,code=self.invoke(out,launch,executor)
            self.assertEqual(code,1)
            self.assertIn('checkpoint evidence changed',str(report))
            resumed,code=self.invoke(out,launch,executor)
            self.assertEqual(code,1)
            self.assertEqual(resumed['executions_this_invocation'],0)

    def test_strict_denial_never_produces_a_checkpoint(self):
        out,launch=self.prepare_warm(strict=True);executor=base.InputExecutor(fault='analysis')
        def denied(run,code,fault=None):
            return denied_evidence(run,code,fault,builder=control.guarded_evidence)
        with patch.object(base,'synthetic_evidence',side_effect=denied):
            report,code=self.invoke(out,launch,executor)
        self.assertEqual(code,1)
        self.assertIn('rejected',str(report))
        run=executor.runs[0][0]
        self.assertFalse((run/'logs/capsule/afl-checkpoint.json').exists())
        self.assertNotIn('afl_checkpoint',report['capsule'])


@unittest.skipUnless(os.environ.get('TF_WARM_QEMU'),'TF_WARM_QEMU required')
class NativeWarmGuardTests(unittest.TestCase):
    def test_private_path_guard_remains_active_in_every_warm_child(self):
        from experiments.afl_file.build import components,guest
        from scripts.verify_afl_warm_components import NativeSession
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            built=components(root/'build')
            built['guest']=str(guest(root/'fixture',loops=1000,faults=True))
            private=root/'native/fs/state'
            session=NativeSession(root/'native',built,os.environ['TF_WARM_QEMU'],guard=private)
            try:
                for data in (b'A',b'B'):
                    value,_,_=session.attempt_outcome(data)
                    self.assertEqual(value['kind'],'infra_error')
                    self.assertEqual(value['wait_status'],126<<8)
                    self.assertIsNone(value['guest_signal'])
                diagnostic=(session.root/'qemu.log').read_text()
                self.assertEqual(diagnostic.count('CAPSULE_GUARD_ABORT code=126 reason=private_path'),2)
                self.assertEqual(session.prepared.read_bytes(),b'P')
            finally:session.close()
            self.assertEqual(session.process.returncode,0)


if __name__=='__main__':unittest.main()
