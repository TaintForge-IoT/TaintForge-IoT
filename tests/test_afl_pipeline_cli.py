import contextlib
import io
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

from scripts.run_afl_file import main
from taintforge_env import afl_strict, afl_transport


class PipelineCliTests(unittest.TestCase):
    def arguments(self):
        return ['run_afl_file','campaign','--binary','/tmp/sample.elf','--qemu','/tmp/qemu-i386',
                '--plugin','/tmp/phase1.so','--seeds','/tmp/seeds','--guest-file','/etc/input','--out','/tmp/campaign',
                '--seconds','30','--executions','64']

    def test_single_command_prepares_then_runs_with_parallel_phase2(self):
        calls=[]
        def prepare(*args,**kwargs):
            self.assertEqual(kwargs['phase2_mode'],'parallel');calls.append('prepare');return {'status':'prepared'}
        def run(*args,**kwargs):
            self.assertEqual(calls,['prepare']);self.assertEqual(kwargs['executions'],64)
            calls.append('run');return {'status':'completed'}
        with patch.object(sys,'argv',self.arguments()),patch.object(afl_strict,'prepare_campaign',side_effect=prepare),\
             patch.object(afl_transport,'run_campaign',side_effect=run),contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(),0)
        self.assertEqual(calls,['prepare','run'])

    def test_sequential_phase2_choice_reaches_the_warm_binding(self):
        with patch.object(sys,'argv',self.arguments()+['--phase2-mode','sequential','--phase2-pending','2']),\
             patch.object(afl_strict,'prepare_campaign',return_value={'status':'prepared'}) as prepare,\
             patch.object(afl_transport,'run_campaign',return_value={'status':'completed'}),\
             contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(),0)
        self.assertEqual(prepare.call_args.kwargs['phase2_mode'],'sequential')
        self.assertEqual(prepare.call_args.kwargs['phase2_pending'],2)

    def test_failed_preparation_never_starts_afl(self):
        with patch.object(sys,'argv',self.arguments()),\
             patch.object(afl_strict,'prepare_campaign',side_effect=RuntimeError('retirement prerequisite failed')),\
             patch.object(afl_transport,'run_campaign') as run,contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main(),2)
            run.assert_not_called()


if __name__=='__main__':unittest.main()
