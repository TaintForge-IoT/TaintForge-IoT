"""Actual campaign/session/snapshot logic, synthetic guest/service execution."""
from pathlib import Path
import unittest
from unittest.mock import patch

from taintforge_env import afl_file as f
from tests import test_input_retirement as old
from tests import test_capsule_hardening_integration as hard
from taintforge_env.phase1_runtime import Phase1Runtime


class CampaignTests(unittest.TestCase):
    setUp=hard.HardeningIntegrationTests.setUp
    invoke=hard.HardeningIntegrationTests.invoke

    def prepare(self):
        sidecar=Path(str(self.plugin)+'.runtime.json')
        manifest=f.read_json(sidecar)
        manifest['formats']={'cooperative_retirement':1,'verdict_retirement':2}
        manifest['resource_ledger']={'schema':1,'scope':'explicit_project_allocations','external_allocations_tracked':False}
        f.atomic_json(sidecar,manifest)
        seeds=self.base/'seeds';seeds.mkdir();(seeds/'a').write_bytes(b'A')
        built=dict(plugin=self.built['plugin'],source_sha256={'observer.c':'a'*64,'qemu-plugin.h':'b'*64,
            'afl_coverage.h':f.p.sha(f.PROJECT/'experiments/afl_file/coverage.h')})
        root=self.base/'campaign'
        with patch.object(old.resources,'preflight'), patch.object(old.c,'build_plugin',return_value=built), \
             patch.object(old.c.p,'load_phase1',return_value=(None,Phase1Runtime.load(self.plugin),None)):
            f.prepare_campaign(root,binary=self.built['guest'],qemu=self.qemu,plugin=self.plugin,
                               guest_path='/etc/afl-input',seeds=seeds)
        return root

    def test_fresh_session_input_and_coverage_for_each_case(self):
        root=self.prepare()
        (root/'cases').mkdir()
        real_run=__import__('scripts.run_unified_pipeline',fromlist=['run_session']).run_session
        all_bindings=[]
        for index,data in enumerate((b'B',b'C')):
            case=root/'cases'/f'{index:08d}';case.mkdir();(case/'input').write_bytes(data)
            executor=old.InputExecutor()
            def evidence(run,code,fault=None):
                binding,result=hard.hardened_evidence(run,code,fault)
                self.assertEqual(f.guest_file(binding['rootfs'],'/etc/afl-input').read_bytes(),data)
                bitmap=bytearray(f.MAP_SIZE);bitmap[data[0]]=1
                path=run/'logs/capsule'/f.MAP_NAME
                path.write_bytes(f.HEADER.pack(b'TFACOV1\0',1,f.MAP_SIZE,1,1,7,0x8049000,0x8049004,0)+bitmap)
                f.atomic_json(run/'logs/capsule/afl-coverage.json',f.inspect_map(path)[0])
                all_bindings.append(binding)
                return binding,result
            # invoke() patches the service and runner, leaving the actual unified loop intact.
            def session(out,launch,*,max_steps):
                with patch('scripts.run_unified_pipeline.run_session',real_run):
                    return self.invoke(out,launch,executor,steps=max_steps)
            with patch('scripts.run_unified_pipeline.run_session',side_effect=session), \
                 patch.object(old,'synthetic_evidence',side_effect=evidence):
                result=f.execute_attempt(root,case)
            self.assertEqual(result['status'],'passed')
            self.assertEqual(result['baseline_input_sha256'],f.settings('/etc/afl-input',b'A')['input_sha256'])
        self.assertNotEqual(all_bindings[0]['attempt_id'],all_bindings[1]['attempt_id'])
        snapshot=f.EnvironmentSnapshotStore(f.read_json(root/'campaign.json')['snapshot_store'])
        saved=snapshot.verify(f.read_json(root/'campaign.json')['snapshot_id'])
        self.assertFalse(any(e.path=='/tmp/attempt-only' for e in saved.entries))
        self.assertEqual((root/'cases/00000000/coverage.map').read_bytes()[ord('B')],1)
        self.assertEqual((root/'cases/00000001/coverage.map').read_bytes()[ord('C')],1)

    def test_snapshot_and_asset_tampering_are_rejected(self):
        root=self.prepare()
        value=f.verify_campaign(root)
        target=Path(value['launch']['binary_path']); target.chmod(0o644); target.write_bytes(b'changed')
        with self.assertRaisesRegex(RuntimeError,'asset changed'):f.verify_campaign(root)


if __name__=='__main__':unittest.main()
