from dataclasses import replace
import hashlib
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from taintforge_env import afl_file as f, afl_warm as w, afl_epochs as e, afl_phase2 as phase2
from taintforge_env.afl_replay import clone_campaign, minimize, same_fault, replay
from taintforge_env.afl_metrics import Metrics, artifact_bytes
from taintforge_env.repair_applier import RepairApplier
from tests import test_repair_applier as repairs


class ReplayEpochTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.source=self.root/'source';self.source.mkdir()
        template=self.source/'template';fs=template/'rootfs'
        (fs/'etc').mkdir(parents=True);(fs/'etc/input').write_bytes(b'A')
        (template/'config/analyzer_runtime').mkdir(parents=True)
        runtime={'network_mode':'none','allow_internet':False,'rootfs':str(fs),'phase1':{'bundle_path':str(template/'config/analyzer_runtime'),'bundle_sha256':'a'*64}}
        f.atomic_json(template/'config/runtime.json',runtime)
        store=f.EnvironmentSnapshotStore(self.source/'baseline-snapshots');snapshot=store.capture(fs)
        (self.source/'seeds').mkdir();(self.source/'seeds/A').write_bytes(b'A')
        (self.source/'afl/default/queue').mkdir(parents=True)
        (self.source/'afl/default/queue/id:0').write_bytes(b'B')
        config=w.configuration(self.source,bootstrap_seconds=30,campaign_seconds=60,timeout_ms=100,max_rss_mib=512,phase2_mode='parallel')
        self.manifest={'schema':1,'profile':f.PROFILE,'project_root':str(f.PROJECT),'status':'completed',
            'guest_path':'/etc/input','max_input':4096,'source_sha256':{},'execution_mode':w.PROFILE,
            'build':{'bridge':'/bin/true'},'protected_control_channel':False,'hostile_sample_ready':False,
            'warm':config,'launch':{'template_run_dir':str(template),'seed_rootfs':str(fs),'timeout_seconds':60},
            'snapshot_store':str(store.store_dir),'snapshot_id':snapshot.manifest.snapshot_id,
            'assets':{str(template/'config/runtime.json'):f.p.sha(template/'config/runtime.json')},'cases':0}
        f.atomic_json(self.source/'campaign.json',self.manifest)
        self.closed(self.source)
        self.bundle=patch.object(f,'verify_bundle',return_value={});self.bundle.start();self.addCleanup(self.bundle.stop)

    def closed(self,root):
        count=len(list((root/'cases').glob('*/result.json')))
        value=f.read_json(root/'campaign.json')
        value.update(cases=count,completed_cases=count,phase1_runs=1)
        f.atomic_json(root/'campaign.json',value)
        f.atomic_json(root/'warm-session-result.json',{'capsule':{'status':'passed','resources':{'tree_empty':True},
                      'phase1_retirement':{'phase1_retired':True}}})
        f.atomic_json(root/'warm-executor.json',{'status':'passed','children':count,'phase1_runs':1})
        f.atomic_json(root/'phase2-progress.json',{'status':'passed','pending':0,'submitted':count,'completed':count})

    def repair(self,index=0,mode='0755',*,root=None,unmet=True):
        root=root or self.source
        case=root/'cases'/f'{index:08d}';case.mkdir(parents=True)
        (case/'input').write_bytes(b'A')
        (case/'coverage.map').write_bytes(b'\1'+bytes(f.MAP_SIZE-1))
        parent=root/'template';(parent/'logs').mkdir(exist_ok=True)
        trace=parent/'logs/qemu_strace.log'
        if not trace.exists():trace.write_bytes(b'')
        fs=parent/'rootfs'
        capture=phase2.Capture(fs,parent,case,excluded=(),config=phase2.settings())
        capture.before()
        pid=100+index
        with trace.open('a') as stream:
            stream.write(str(pid)+' open("/var/fuzz-state/entry",O_WRONLY|O_CREAT,0600) = '+
                         ('-1 errno=2 (No such file or directory)' if unmet else '3')+'\n')
        result={'status':'passed','child_namespace_pid':pid,'guest_exit':0,'phase1_runs':1,
                'input':f.settings('/etc/input',b'A'),
                'coverage':{'map_sha256':f.p.sha(case/'coverage.map')}}
        f.atomic_json(case/'result.json',result);capture.finish(result)
        phase2.analyze(case,phase2.settings())
        if mode!='0755':
            from taintforge_env.repair_plan import RepairPlan
            plan_path=case/'phase2/config/repair_plan.json';plan=RepairPlan.load(plan_path)
            changed=tuple(replace(d,parameters=(("mode",mode),("parents",True))) if d.automatic_allowed else d for d in plan.decisions)
            replace(plan,decisions=changed).save(plan_path)
            analysis=f.read_json(case/'phase2/result.json');analysis['repair_plan_sha256']=f.p.sha(plan_path)
            f.atomic_json(case/'phase2/result.json',analysis)
        self.closed(root)

    def test_clone_preserves_corpus_bundle_and_initial_files_but_not_live_state(self):
        output=self.root/'clone'
        value=clone_campaign(self.source,output)
        self.assertEqual(value['status'],'prepared')
        self.assertEqual(value['warm']['campaign_root'],str(output))
        self.assertEqual({p.read_bytes() for p in (output/'seeds').iterdir()},{b'A',b'B'})
        self.assertEqual((output/'template/rootfs/etc/input').read_bytes(),b'A')
        self.assertFalse((output/'warm-ready.json').exists())
        self.assertEqual(f.verify_campaign(output)['snapshot_id'],value['snapshot_id'])

    def test_replay_and_repair_clone_preserve_the_m5_profile(self):
        from taintforge_env.afl_capsule import PROFILE
        self.manifest['warm']['capsule_profile']=PROFILE
        f.atomic_json(self.source/'campaign.json',self.manifest)
        cloned=clone_campaign(self.source,self.root/'m5-clone')
        self.assertEqual(cloned['warm']['capsule_profile'],PROFILE)

    def test_reduction_preserves_same_fault_and_budget(self):
        reduced,stats=minimize(b'prefixCxxxxxxxx',lambda value:b'C' in value,budget=128)
        self.assertEqual(reduced,b'C');self.assertLessEqual(stats['executions'],128)
        _,stats=minimize(b'xxxxCxxxx',lambda value:b'C' in value,budget=1)
        self.assertTrue(stats['budget_exhausted'])
        expected={'kind':'guest_crash','guest_signal':11,'guest_pc':0x8048000}
        self.assertTrue(same_fault(expected,expected))
        self.assertFalse(same_fault(expected,expected|{'guest_pc':0x8049000}))

    def test_nested_clone_and_oversized_corpus_fail_before_copying(self):
        output=self.source/'template/config/nested'
        with self.assertRaisesRegex(RuntimeError,'outside'):
            clone_campaign(self.source,output)
        self.assertFalse(output.exists())
        (self.source/'afl/default/queue/id:1').write_bytes(b'x'*4097)
        with self.assertRaisesRegex(RuntimeError,'campaign limit'):
            clone_campaign(self.source,self.root/'oversized')
        self.assertFalse((self.root/'oversized').exists())

    def test_epoch_cannot_extend_only_the_broker_lifetime(self):
        self.repair()
        with self.assertRaisesRegex(RuntimeError,'capsule lifetime'):
            e.evolve(self.source,self.root/'longer',seconds=61)
        self.assertFalse((self.root/'longer').exists())

    def test_missing_phase2_report_and_wrong_child_identity_are_refused(self):
        self.repair()
        path=self.source/'cases/00000000/phase2/result.json'
        value=f.read_json(path)
        path.unlink()
        with self.assertRaisesRegex(RuntimeError, 'missing runtime artifact'):
            e.collect(self.source,self.root/'missing')
        value['child_namespace_pid']+=1;f.atomic_json(path,value)
        with self.assertRaisesRegex(RuntimeError,'identity mismatch'):
            e.collect(self.source,self.root/'mixed')

    def test_incomplete_phase2_counts_are_refused(self):
        self.repair()
        state=f.read_json(self.source/'phase2-progress.json');state['completed']=0
        f.atomic_json(self.source/'phase2-progress.json',state)
        with self.assertRaisesRegex(RuntimeError,'Incomplete'):
            e.evolve(self.source,self.root/'partial')
        self.assertFalse((self.root/'partial').exists())

    def test_minimization_time_limit_never_calls_the_oracle_after_expiry(self):
        calls=[]
        value,stats=minimize(b'long input',lambda data:calls.append(data),can_run=lambda:False)
        self.assertEqual(value,b'long input');self.assertEqual(calls,[])
        self.assertEqual(stats['executions'],0)
        self.assertEqual(stats['stop_reason'],'time_budget')

    def test_replay_rejects_changed_provenance_before_creating_session(self):
        from taintforge_env.afl_findings import record
        self.repair()
        case=self.source/'cases/00000000'
        value=f.read_json(case/'result.json')
        value['outcome']={'kind':'guest_crash','guest_signal':4,'guest_pc':0x8048000}
        f.atomic_json(case/'result.json',value)
        finding=record(self.source,case)
        saved=f.read_json(finding/'finding.json')
        saved['assets']={};f.atomic_json(finding/'finding.json',saved)
        with self.assertRaisesRegex(RuntimeError,'provenance'):
            replay(self.source,finding,self.root/'replay')
        self.assertFalse((self.root/'replay').exists())

    def test_invalid_replay_budget_does_not_create_a_session(self):
        from taintforge_env.afl_findings import record
        self.repair()
        case=self.source/'cases/00000000'
        value=f.read_json(case/'result.json')
        value['outcome']={'kind':'timeout','guest_signal':None,'guest_pc':None}
        f.atomic_json(case/'result.json',value)
        finding=record(self.source,case)
        with self.assertRaisesRegex(RuntimeError,'minimization budget'):
            replay(self.source,finding,self.root/'invalid-replay',budget=0)
        self.assertFalse((self.root/'invalid-replay').exists())

    def test_duplicate_repairs_are_applied_once_only_to_a_new_rootfs(self):
        self.repair(0);self.repair(1)
        selected=e.collect(self.source,self.root/'selected')
        self.assertEqual(selected['automatic_resources'],1)
        self.assertEqual(len(selected['plans']),1)
        def edit(fs):
            item=selected['plans'][0]
            report=RepairApplier().apply_file(plan_path=item['plan'],requirements_path=item['requirements'],
                                             rootfs=fs,out_path=item['application'])
            self.assertEqual(report.summary()['applied_total'],1)
        clone_campaign(self.source,self.root/'changed',edit_rootfs=edit)
        self.assertTrue((self.root/'changed/template/rootfs/var/fuzz-state').is_dir())
        self.assertFalse((self.source/'template/rootfs/var').exists())

    def test_conflict_and_changed_requirements_are_refused(self):
        self.repair(0);self.repair(1,mode='0700')
        with self.assertRaisesRegex(RuntimeError,'Conflicting'):
            e.collect(self.source,self.root/'conflict')
        (self.source/'cases/00000001/phase2/config/runtime_requirements.json').write_text('changed')
        with self.assertRaisesRegex(RuntimeError,'requirements changed'):
            e.collect(self.source,self.root/'tampered')

    def test_epoch_runs_once_then_stops_without_new_repairs(self):
        self.repair()
        calls=[]
        def run(root,**kwargs):
            calls.append(Path(root));value=f.read_json(root/'campaign.json')
            value.update(status='completed',phase1_runs=1,cases=0)
            f.atomic_json(root/'campaign.json',value)
            self.repair(root=root,unmet=False)
            self.closed(root)
            return value
        with patch('taintforge_env.afl_transport.run_campaign',side_effect=run):
            result=e.evolve(self.source,self.root/'evolve',max_epochs=3,seconds=10)
        self.assertEqual(len(calls),1)
        self.assertEqual(result['new_phase1_runs'],1)
        self.assertEqual(result['stop_reason'],'no_automatic_repairs')
        self.assertTrue((calls[0]/'template/rootfs/var/fuzz-state').is_dir())

    def test_live_capsule_is_refused_before_creating_an_epoch(self):
        f.atomic_json(self.source/'warm-session-result.json',{'capsule':{'status':'passed','resources':{'tree_empty':False}}})
        with self.assertRaisesRegex(RuntimeError,'stopped'):
            e.evolve(self.source,self.root/'forbidden')
        self.assertFalse((self.root/'forbidden').exists())

    def test_repeated_repair_cycle_is_detected_before_second_preparation(self):
        self.repair()
        calls=[]
        def run(root,**kwargs):
            calls.append(root);value=f.read_json(root/'campaign.json')
            value.update(status='completed',phase1_runs=1,cases=1)
            f.atomic_json(root/'campaign.json',value)
            self.repair(root=root)
            self.closed(root)
            return value
        with patch('taintforge_env.afl_transport.run_campaign',side_effect=run):
            with self.assertRaisesRegex(RuntimeError,'Repeated repair'):
                e.evolve(self.source,self.root/'cycle',max_epochs=3,seconds=10)
        self.assertEqual(len(calls),1)

    def test_metrics_count_faults_and_skip_runtime_rootfs_and_symlinks(self):
        root=self.root/'metrics';case=root/'cases/00000000';case.mkdir(parents=True)
        (case/'input').write_bytes(b'abc');(case/'rootfs').mkdir();(case/'rootfs/ignored').write_bytes(b'ignored')
        (case/'external').symlink_to('/etc/passwd')
        self.assertEqual(artifact_bytes(root),3)
        metrics=Metrics(root)
        metrics.record({'outcome':{'kind':'guest_crash','duration_ms':20,'child_peak_rss_kib':10000}})
        value=metrics.publish(executed=1,completed=1,final=True)
        self.assertEqual(value['outcomes'],{'guest_crash':1})
        self.assertEqual(value['retained_artifact_bytes'],3)
        self.assertEqual(value['child_peak_rss_kib'],10000)


if __name__=='__main__':unittest.main()
