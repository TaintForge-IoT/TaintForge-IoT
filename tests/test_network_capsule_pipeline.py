"""Unified integration with synthetic QEMU/cgroup evidence, real parsers and finalizers."""
import json
import os
from pathlib import Path
import shutil
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from scripts.run_unified_pipeline import run_session
from taintforge_env import capsule_resources as resources
from taintforge_env import input_retirement
from taintforge_env import network_capsule as net
from taintforge_env.network_policy import NetworkPolicy
from taintforge_env.network_runtime import NetworkRuntimeOwner, NetworkRuntimeLimits
from taintforge_env.prebuilt_runner import PrebuiltRootfsRunner
from taintforge_env.synthesis_loop import EnvironmentSynthesisLoop
from taintforge_env.unified_runtime import canonical_hash, write_json
from tests import test_input_retirement as fixtures
from tests.test_prebuilt_runner import FakeNetworkBackend
from tests import test_prebuilt_runner as prebuilt_fixtures


def read(path):
    return json.loads(path.read_text())


class ContractBackend(FakeNetworkBackend):
    def setup(self):
        result=super().setup()
        config=self.config.run_dir/'config'
        write_json(config/'network_policy.json',read(config/'network_policy_requested.json'))
        requested=read(config/'network_policy_requested.json')
        self.runtime=NetworkRuntimeOwner(config/'network_runtime',self.config.run_dir/'logs',
            attempt_id=self.config.attempt_id,limits=NetworkRuntimeLimits.parse(requested.get('runtime_limits')))
        self.plan=type('Plan',(),{'namespace_name':'tf-00cafe00'})()
        self.executor.network_owner=self.runtime
        return result

    def guest_command(self, script):
        return ['sudo','-n','ip','netns','exec',self.plan.namespace_name,'env','PYTHONPATH='+str(self.config.project_root),
                sys.executable,str(self.config.project_root/'scripts/run_network_guard.py'),
                '--runtime',str(self.runtime.client_path),'--result',str(self.config.run_dir/'config/network_guard_result.json'),
                '--','unshare','--mount','--pid','--fork','--uts','--ipc','--','bash',str(script)]

    def cleanup(self, *, finalize_logs=True):
        super().cleanup(finalize_logs=finalize_logs)
        if hasattr(self,'runtime'):
            self.runtime.close()


class NetworkExecutor(fixtures.InputExecutor):
    def __init__(self, reason=None, damage=False):
        super().__init__(exit_code=14 if reason else 0)
        self.reason,self.damage=reason,damage
        self.service_commands=[]

    def run(self, command, **kwargs):
        result=super().run(command,**kwargs)
        if 'unshare' not in command or not str(command[-1]).endswith('run_prebuilt_sandbox.sh'):
            return result
        root=Path(command[-1]).parent
        (root/'logs/network_endpoints/events.jsonl').write_text('{"fixture":"synthetic endpoint journal"}\n')
        if self.reason:
            self.network_owner.fail(self.reason)
            root=Path(command[-1]).parent
            binding=read(root/'config/capsule_binding.json')
            path=root/'logs/capsule/supervisor.json';saved=read(path)
            saved['network_termination']={**{k:binding[k] for k in net.IDENTITY},'reason':self.reason,
                                          'observed_monotonic_ns':1}
            saved['error']='synthetic network termination fixture'
            write_json(path,saved)
            if self.damage:
                path=root/'logs/capsule/observer-events.json';journal=read(path)
                journal['events']=[e for e in journal['events'] if e['event']!='module_unmapped']
                for i,event in enumerate(journal['events'],1):event['controller_seq']=i
                write_json(path,journal)
        return result


class NetworkCapsulePipelineTests(unittest.TestCase):
    setUp=fixtures.InputRetirementTests.setUp
    prepare_input=fixtures.InputRetirementTests.prepare_input

    def prepare_network(self, *, name='network', extra=()):
        policy=self.base/'network-policy.json';write_json(policy,NetworkPolicy(mode='controlled').to_dict())
        observer=self.base/'libnetwork_endpoint.so';shutil.copyfile(self.plugin,observer)
        inputs={'plugin_api':6,'synthetic_contract_fixture':True}
        write_json(Path(str(observer)+'.observer.json'),{'schema_version':1,'kind':'taintforge-network-endpoints',
            'target_arch':'i386','profile':'single-process-single-thread','plugin_api':6,'build_inputs':inputs,
            'build_id':canonical_hash(inputs),'plugin':{'filename':observer.name,'size':observer.stat().st_size,
                                                      'sha256':fixtures.c.p.sha(observer)}})
        return self.prepare_input(name=name,extra=('--network','controlled','--network-policy',str(policy),
                                                 '--network-observer',str(observer),*extra))

    def invoke_network(self, out, launch, executor):
        current=os.stat('/proc/self/ns/net')
        def namespace(name):return {'name':name,'device':current.st_dev,'inode':current.st_ino}
        def service(binding,command,executor,**kwargs):
            executor.service_commands.append(resources.command(binding,command))
            result=executor.run(command,**kwargs)
            write_json(Path(binding['run_dir'])/'logs/capsule/service.json',{
                'status':'verified','unit':resources.unit_name(binding),'attempt_id':binding['attempt_id'],
                'attempt_contract_sha256':binding['attempt_contract_sha256'],'tree_empty':True,
                'wrapper_exit':result.returncode,'service':{'Result':'success' if result.returncode==0 else 'exit-code'}})
            return result
        with patch.object(PrebuiltRootfsRunner,'_check_host_dependencies'),patch.object(resources,'execute',service),\
             patch.object(net,'namespace_identity',side_effect=namespace):
            return run_session(out,launch,max_steps=1,runner_factory=lambda config:
                PrebuiltRootfsRunner(config,executor=executor,network_backend_factory=ContractBackend))

    def test_fresh_retirement_network_attempt_finalizes_and_remains_verifiable(self):
        out,launch=self.prepare_network();executor=NetworkExecutor()
        report,code=self.invoke_network(out,launch,executor)
        self.assertEqual(code,0,report.get('error'))
        self.assertTrue(report['capsule']['phase1_retirement']['phase1_retired'])
        run,binding,_=executor.runs[0]
        self.assertEqual(binding['network']['profile'],net.PROFILE)
        self.assertTrue(EnvironmentSynthesisLoop.verify_session(out/'session')['artifacts_verified'])
        plugins=input_retirement.plugin_arguments(binding,'phase1-options','retirement-options')
        self.assertEqual(plugins.count('-plugin'),3)
        self.assertEqual(plugins[-1],binding['network']['observer']['plugin_argument'])
        self.assertIn('--capsule-binding',executor.service_commands[0])
        self.assertEqual(read(run/'config/finalization_status.json')['status'],'completed')
        self.assertEqual(read(run/'report.json')['network']['capsule_integration']['status'],'passed')

    def test_prelaunch_failure_keeps_the_supervisor_error_in_finalization(self):
        run = self.base / 'failed-prelaunch'
        (run / 'config').mkdir(parents=True)
        (run / 'logs/capsule').mkdir(parents=True)
        identities = {name: 'a' * 64 if name.endswith('sha256') else name for name in net.IDENTITY}
        write_json(run / 'config/capsule_binding.json', {'run_dir': str(run), **identities})
        error = 'FileNotFoundError: cgroup memory.max is not visible'
        write_json(run / 'logs/capsule/supervisor.json', {
            **identities, 'status': 'failed', 'qemu_exit': None, 'error': error,
        })
        context = SimpleNamespace(run_dir=run, attempt_contract=SimpleNamespace(
            attempt_id=identities['attempt_id'], contract_sha256=identities['attempt_contract_sha256'],
        ))
        with self.assertRaisesRegex(RuntimeError, r'before QEMU launch: .*memory\.max'):
            input_retirement.finish_attempt(context, 126)
        report = read(run / 'config/capsule_result.json')
        self.assertEqual(report['status'], 'failed')
        self.assertEqual(report['supervisor_error'], error)
        self.assertEqual(report['wrapper_exit'], 126)
        self.assertIsNone(report['qemu_exit'])
        self.assertNotIn('qemu_exit_status', report)

    def test_network_failure_preserves_retirement_prefix_and_blocks_resume(self):
        out,launch=self.prepare_network();executor=NetworkExecutor('network_receive_budget_exceeded')
        report,code=self.invoke_network(out,launch,executor)
        self.assertEqual(code,1)
        run=executor.runs[0][0];capsule=read(run/'config/capsule_result.json')
        self.assertEqual(capsule['network_termination']['reason'],'network_receive_budget_exceeded')
        self.assertEqual(capsule['retirement_before_stop']['status'],'verified',capsule['retirement_before_stop'].get('error'))
        self.assertFalse(capsule['claims']['oep_proven'])
        self.assertEqual(read(run/'config/finalization_status.json')['status'],'failed')
        self.assertFalse((run/'config/repair_plan.json').exists())
        self.assertEqual(read(run/'config/network_capsule_result.json')['status'],'interrupted')
        before=(run.parent/'execution_attempt.json').read_bytes()
        resumed,status=run_session(out,launch,max_steps=1)
        self.assertEqual(status,1)
        self.assertEqual(resumed['executions_this_invocation'],0)
        self.assertEqual((run.parent/'execution_attempt.json').read_bytes(),before)

    def test_missing_unmap_prefix_cannot_be_reported_as_verified_retirement(self):
        out,launch=self.prepare_network();executor=NetworkExecutor('network_responder_exited',damage=True)
        report,code=self.invoke_network(out,launch,executor)
        self.assertEqual(code,1)
        capsule=read(executor.runs[0][0]/'config/capsule_result.json')
        self.assertEqual(capsule['retirement_before_stop']['status'],'unverified')
        self.assertNotEqual(capsule['status'],'passed')

    def test_explicit_evidence_sync_failure_rejects_an_otherwise_valid_interrupted_prefix(self):
        out,launch=self.prepare_network();executor=NetworkExecutor('network_receive_budget_exceeded')
        _,code=self.invoke_network(out,launch,executor)
        self.assertEqual(code,1)
        run=executor.runs[0][0]
        binding=read(run/'config/capsule_binding.json')
        result=read(run/'logs/capsule/supervisor.json')
        self.assertEqual(net.interrupted_retirement(binding,result)['status'],'verified')
        path=run/'logs/capsule/controller.json';controller=read(path)
        controller['evidence_persistence_error']='OSError: test deferred fsync failure'
        write_json(path,controller)
        with self.assertRaisesRegex(RuntimeError,'evidence persistence failed'):
            net.interrupted_retirement(binding,result)

    def test_network_and_fd_path_control_guard_are_rejected_before_execution(self):
        with self.assertRaisesRegex(RuntimeError,'cannot be relaxed'):
            self.prepare_network(extra=('--capsule-hardening','--capsule-control-guard'))

    def prepare_hardened_network(self):
        path=Path(str(self.plugin)+'.runtime.json');data=read(path)
        data['resource_ledger']={'schema':1,'scope':'explicit_project_allocations','external_allocations_tracked':False}
        write_json(path,data)
        return self.prepare_network(extra=('--capsule-hardening',))

    def test_hardened_network_retirement_evidence_survives_relocation(self):
        from tests.test_capsule_hardening_integration import hardened_evidence
        from taintforge_env import retirement_evidence
        out,launch=self.prepare_hardened_network();executor=NetworkExecutor()
        with patch.object(fixtures,'synthetic_evidence',side_effect=hardened_evidence):
            report,code=self.invoke_network(out,launch,executor)
        self.assertEqual(code,0,report.get('error'))
        run=executor.runs[0][0];moved=self.base/'moved-network-retirement'
        shutil.copytree(run/'retirement-evidence',moved)
        checked=retirement_evidence.verify(moved,expected_sha256=report['capsule']['portable_evidence']['manifest_sha256'])
        self.assertEqual(checked['attempt_outcome'],'passed')
        self.assertTrue((moved/'logs/network_endpoints/events.jsonl').is_file())

    def test_hardened_network_failure_keeps_verified_context_and_ledger(self):
        from tests.test_capsule_hardening_integration import hardened_evidence
        out,launch=self.prepare_hardened_network();executor=NetworkExecutor('network_capsule_timeout')
        with patch.object(fixtures,'synthetic_evidence',side_effect=hardened_evidence):
            report,code=self.invoke_network(out,launch,executor)
        self.assertEqual(code,1)
        prefix=read(executor.runs[0][0]/'config/capsule_result.json')['retirement_before_stop']
        self.assertEqual(prefix['status'],'verified',prefix.get('error'))
        self.assertEqual(prefix['hardening']['status'],'verified')


class CapsuleCleanupResetTests(unittest.TestCase):
    setUp=prebuilt_fixtures.PrebuiltRunnerTests.setUp
    tearDown=prebuilt_fixtures.PrebuiltRunnerTests.tearDown
    make_runner=prebuilt_fixtures.PrebuiltRunnerTests.make_runner

    def test_unconfirmed_capsule_tree_blocks_reset_before_the_guest_starts(self):
        class RetainedService(FakeNetworkBackend):
            def setup(self):
                result=super().setup()
                write_json(self.config.run_dir/'logs/capsule/service.json',
                    {'attempt_id':self.config.attempt_id,'tree_empty':False})
                return result
        runner=self.make_runner(prebuilt_fixtures.FakeExecutor(infrastructure_fail=True),network_mode='controlled',
                                network_backend_factory=RetainedService)
        with patch.object(runner,'_check_host_dependencies'),self.assertRaisesRegex(RuntimeError,'before recording'):
            runner.run_and_complete()
        claim_path=self.session/'iterations/0000/execution_attempt.json';claim=read(claim_path)
        self.assertFalse(claim['malware_started'])
        self.assertFalse(claim['retry_safe'])
        claim['retry_safe']=True;write_json(claim_path,claim)
        with self.assertRaisesRegex(RuntimeError,'capsule cleanup is unconfirmed'):
            runner.reset_safe_failure()


if __name__=='__main__':unittest.main()
