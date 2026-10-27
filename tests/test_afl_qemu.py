"""Real production campaign controller with a benign, explicitly component-only worker."""
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from experiments.afl_file.build import components
from scripts.verify_afl_components import fixture
from taintforge_env import afl_file as f
from taintforge_env import afl_transport as transport


class QemuCampaignTests(unittest.TestCase):
    def test_real_afl_with_campaign_controller(self):
        qemu=os.environ.get('TF_OBSERVER_QEMU')
        afl_bin=os.environ.get('TF_AFL_BIN')
        if not qemu or not afl_bin:self.skipTest('TF_OBSERVER_QEMU and TF_AFL_BIN required')
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);built=components(root/'build')
            campaign=root/'campaign';command=fixture(campaign,built,qemu)
            manifest={'schema':1,'profile':'component-only','status':'prepared','max_input':4096,
                      'launch':{'timeout_seconds':10},'build':{'bridge':built['bridge']}}
            f.atomic_json(campaign/'campaign.json',manifest)
            seeds=campaign/'seeds';seeds.mkdir();(seeds/'seed').write_bytes(b'A')
            server_type=transport.AttemptServer
            def create_server(path,**kwargs):return server_type(path,command=command,**kwargs)
            with patch.object(f,'verify_campaign',return_value=manifest), \
                 patch.object(transport,'AttemptServer',side_effect=create_server):
                result=transport.run_campaign(campaign,afl_bin=afl_bin,seconds=2,executions=12)
            self.assertEqual(result['status'],'completed')
            self.assertGreaterEqual(result['completed_cases'],2)
            self.assertEqual(result['executor_errors'],[])
            self.assertEqual(f.read_json(campaign/'campaign.json')['status'],'completed')
            for case in (campaign/'cases').iterdir():
                self.assertTrue(f.read_json(case/'transport.json')['cleanup_confirmed'])


if __name__=='__main__':unittest.main()
