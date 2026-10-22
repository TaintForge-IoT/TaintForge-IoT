import copy
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from taintforge_env import capsule_hardening as m4, retirement_evidence
from tests import test_input_retirement as base
from tests import test_capsule_hardening as policy_fixture

ORIGINAL_EVIDENCE=base.synthetic_evidence


def hardened_evidence(run, code, fault=None):
    binding, result=ORIGINAL_EVIDENCE(run,code,fault)
    output=run/'logs/capsule'
    analyzer=base.r.analysis(binding)
    ledger={'schema':1,'scope':'explicit_project_allocations',
        'limit_bytes':binding['settings']['hardening']['analysis_bytes'],'ledger_reserved_bytes':1024,
        'live_allocations':0,'live_bytes':0,'peak_bytes':10000,'allocations':20,'releases':20,
        'wiped_bytes':10000,'external_allocations_tracked':False}
    report=base.c.read_json(analyzer.paths['report'])
    report['resource_inventory']=ledger|{'live_allocations':2,'live_bytes':100,'releases':18,
        'owners':[{'source':'qemu_unpacker.c','live_allocations':2,'live_bytes':100,
                   'peak_bytes':10000,'allocations':20,'releases':18}]}
    base.c.p.write_json(analyzer.paths['report'],report)
    manifest=base.c.read_json(analyzer.paths['manifest'])
    artifact=manifest['artifacts']['report']
    artifact.update(size=analyzer.paths['report'].stat().st_size,sha256=base.c.p.sha(analyzer.paths['report']))
    base.c.p.write_json(analyzer.paths['manifest'],manifest)
    directory=base.r.directory(binding)
    shutil.rmtree(directory/'export')
    hashes=base.r.preserve_export(binding,analyzer)
    saved=base.c.read_json(directory/'retirement.json')
    digest=base.c.p.sha(analyzer.paths['manifest'])
    saved['events'][1]['data']={'sha256':digest,'size':analyzer.paths['manifest'].stat().st_size}
    saved['events'][-1]['data']['resource_ledger']=ledger
    saved.update(accepted_manifest_sha256=digest,preserved_sha256=hashes,
                 permit=f"RETIRE {binding['lifecycle_attempt']} 1 {digest}\n")
    base.c.p.write_json(directory/'retirement.json',saved)
    journal=base.c.read_json(output/'observer-events.json')
    prototype=policy_fixture.HardeningPolicyTests.context(SimpleNamespace(binding=binding))
    for point in (1,2):
        item=copy.deepcopy(prototype)
        item.update(m4.identity(binding),point=point,start_ticks=12345)
        item['fds']=[{'fd':1,'target':'/runtime_stdout.log','fdinfo':'flags:\t1\n'}]
        if point==1:item['fds'].append({'fd':4,'target':str(run/'logs/phase1/events.jsonl'),'fdinfo':'flags:\t02000001\n'})
        path=output/f'execution-context-{point}.json'
        base.c.p.write_json(path,item)
        next(e for e in journal['events'] if e['event']=='maps_held' and e['point']==point)['execution_context_sha256']=base.c.p.sha(path)
    base.c.p.write_json(output/'observer-events.json',journal)
    m4.private_controls(run)
    base.c.p.write_json(output/'m4-setup.json',{'schema':1,'profile':m4.PROFILE,**m4.identity(binding),
        'setup_uid':0,'execution_uid':65534,'execution_gid':65534,'ipc_mode':'0710',
        'protected_control_channel':False,'control_files':m4.controls_record(run)})
    return binding,result


class HardeningIntegrationTests(unittest.TestCase):
    setUp=base.InputRetirementTests.setUp
    prepare_input=base.InputRetirementTests.prepare_input
    invoke=base.InputRetirementTests.invoke

    def prepare_m4(self):
        path=Path(str(self.plugin)+'.runtime.json')
        data=base.c.read_json(path)
        data['resource_ledger']={'schema':1,'scope':'explicit_project_allocations','external_allocations_tracked':False}
        base.c.p.write_json(path,data)
        return self.prepare_input(extra=('--capsule-hardening',))

    def test_hardened_attempt_finalizes_and_portable_evidence_survives_relocation(self):
        out,launch=self.prepare_m4()
        executor=base.InputExecutor()
        with patch.object(base,'synthetic_evidence',side_effect=hardened_evidence):
            report,code=self.invoke(out,launch,executor)
        self.assertEqual(code,0,report.get('error'))
        run,binding,_=executor.runs[0]
        capsule=base.c.read_json(run/'config/capsule_result.json')
        self.assertTrue(capsule['hardening']['capabilities_zero'])
        self.assertFalse(capsule['hardening']['protected_control_channel'])
        script=(run/'run_prebuilt_sandbox.sh').read_text()
        self.assertIn('remount,bind,ro,nosuid,nodev',script)
        self.assertIn('capsule_hardening prepare',script)
        with tempfile.TemporaryDirectory() as d:
            moved=Path(d)/'moved'
            shutil.copytree(run/'retirement-evidence',moved)
            checked=retirement_evidence.verify(moved,expected_sha256=capsule['portable_evidence']['manifest_sha256'])
            self.assertEqual(checked['attempt_outcome'],'passed')
            path=moved/'logs/capsule/execution-context-2.json'
            bad=json.loads(path.read_text());bad['credentials']['CapEff']='1'
            bad['status_text']=bad['status_text'].replace('CapEff:\t0','CapEff:\t1')
            base.c.p.write_json(path,bad)
            journal_path=moved/'logs/capsule/observer-events.json'
            journal=base.c.read_json(journal_path)
            next(e for e in journal['events'] if e['event']=='maps_held' and e['point']==2)['execution_context_sha256']=base.c.p.sha(path)
            base.c.p.write_json(journal_path,journal)
            inventory=base.c.read_json(moved/'bundle.json')
            for item in inventory['files']:
                f=moved/item['path'];item.update(size=f.stat().st_size,sha256=base.c.p.sha(f))
            base.c.p.write_json(moved/'bundle.json',inventory)
            with self.assertRaisesRegex(RuntimeError,'retained capabilities'):
                retirement_evidence.verify(moved,expected_sha256=base.c.p.sha(moved/'bundle.json'))

    def test_missing_context_and_ledger_residue_block_finalization_and_resume(self):
        for fault in ('context','ledger'):
            with self.subTest(fault=fault):
                self.setUp()
                out,launch=self.prepare_m4()
                executor=base.InputExecutor()
                def corrupt(run,code,ignored=None):
                    binding,result=hardened_evidence(run,code)
                    if fault=='context':(run/'logs/capsule/execution-context-2.json').unlink()
                    else:
                        path=base.r.directory(binding)/'retirement.json'
                        data=base.c.read_json(path)
                        data['events'][-1]['data']['resource_ledger']['live_allocations']=1
                        base.c.p.write_json(path,data)
                    return binding,result
                with patch.object(base,'synthetic_evidence',side_effect=corrupt):
                    report,code=self.invoke(out,launch,executor)
                    self.assertEqual(code,1)
                    self.assertEqual(report['outcome'],'intervention_required')
                    self.assertIn('execution-context-2' if fault=='context' else 'M4 release',report['error'])
                    resumed,code=self.invoke(out,launch,executor)
                    self.assertEqual(code,1)
                    self.assertEqual(resumed['executions_this_invocation'],0)

    def test_old_plugin_is_rejected_before_guest_execution(self):
        out,launch=self.prepare_input(extra=('--capsule-hardening',))
        executor=base.InputExecutor()
        report,code=self.invoke(out,launch,executor)
        self.assertEqual(code,1)
        self.assertFalse(executor.runs)

    def test_supervisor_imports_launcher_with_clean_environment_outside_guest_root(self):
        out,launch=self.prepare_m4()
        executor=base.InputExecutor()
        with patch.object(base,'synthetic_evidence',side_effect=hardened_evidence):
            report,code=self.invoke(out,launch,executor)
        self.assertEqual(code,0,report.get('error'))
        run,binding,_=executor.runs[0]
        real_popen=subprocess.Popen
        shadow=Path(binding['rootfs'])/'taintforge_env'
        for guest_package in (False,True):
            with self.subTest(guest_package=guest_package):
                if guest_package:
                    shadow.mkdir()
                    (shadow/'__init__.py').write_text("raise RuntimeError('guest directory imported')\n")
                context=Mock()
                context.Pipe.side_effect=lambda:(Mock(),Mock())
                workers=[Mock(pid=111,exitcode=0),Mock(pid=112,exitcode=0)]
                for worker in workers:worker.is_alive.return_value=False
                context.Process.side_effect=workers
                process=Mock(pid=77,returncode=0)
                process.poll.return_value=0
                probes=[]
                def start(command,**kwargs):
                    self.assertNotIn('PYTHONPATH',kwargs['env'])
                    with real_popen([*command[:3],'--help'],cwd=kwargs['cwd'],env=kwargs['env'],
                                    stdout=subprocess.PIPE,stderr=subprocess.PIPE) as probe:
                        stdout,stderr=probe.communicate(timeout=10)
                        probes.append((probe.returncode,stdout,stderr))
                    return process
                with tempfile.TemporaryDirectory() as ipc, \
                     patch.object(base.m3.mp,'get_context',return_value=context), \
                     patch.object(base.m3.p,'wait_worker_ready'), \
                     patch.object(base.resources,'inspect_self',return_value=base.resource_entry(binding)), \
                     patch.object(base.m3.subprocess,'Popen',side_effect=start):
                    code=base.m3.supervise(binding,ipc)
                self.assertEqual(len(probes),1)
                self.assertEqual(probes[0][0],0,probes[0][2].decode(errors='replace'))
                self.assertIn(b'usage:',probes[0][1])
                self.assertEqual(code,0,base.c.read_json(run/'logs/capsule/supervisor.json'))


if __name__=='__main__':unittest.main()
