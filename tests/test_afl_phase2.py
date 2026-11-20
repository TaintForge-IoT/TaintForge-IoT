import json
from pathlib import Path
import tempfile
import threading
import unittest

from taintforge_env import afl_file as f, afl_phase2 as p, afl_warm as w


class CaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.fs = self.base/'rootfs'
        for name in ('etc', 'tmp', '__taintforge'):
            (self.fs/name).mkdir(parents=True)
        (self.fs/'__taintforge/secret').write_text('service data')
        self.parent = self.base/'parent'
        (self.parent/'config').mkdir(parents=True)
        (self.parent/'logs').mkdir()
        f.atomic_json(self.parent/'config/runtime.json', {'network_mode':'none', 'allow_internet':False})
        self.trace = self.parent/'logs/qemu_strace.log'
        self.trace.write_text('Phase 1 output before checkpoint\n')

    def capture(self, index=0, pid=101, *, mixed=False, fatal_signal=False):
        case = self.base/f'{index:08d}'
        case.mkdir()
        data = bytes([65+index])
        (case/'input').write_bytes(data)
        (self.fs/'etc/input').write_bytes(data)
        (self.fs/'tmp/marker').unlink(missing_ok=True)
        capture = p.Capture(self.fs,self.parent,case,excluded=('/__taintforge',),config=p.settings())
        capture.before()
        with self.trace.open('a') as stream:
            stream.write(f'{pid} open("/etc/needed",O_RDONLY) = -1 errno=2 (No such file or directory)\n')
            stream.write(f'{pid} read(3,0x804b000,4096) = 1\n')
            if fatal_signal: stream.write('--- SIGSEGV {si_signo=SIGSEGV, si_code=1, si_addr=NULL} ---\n')
            if mixed: stream.write(f'{pid+1} close(3) = 0\n')
        (self.fs/'tmp/marker').write_bytes(data)
        result={'status':'passed','child_namespace_pid':pid,'guest_exit':0,'phase1_runs':1,
                'input':f.settings('/etc/input',data)}
        f.atomic_json(case/'result.json',result)
        (case/'coverage.map').write_bytes(b'coverage')
        capture.finish(result)
        return case

    def test_existing_phase2_finds_missing_file_from_each_immutable_child(self):
        first = self.capture()
        second = self.capture(1,102)
        (self.fs/'etc/input').write_text('state was reset again')
        for case,pid in ((first,101),(second,102)):
            result=p.analyze(case,p.settings())
            self.assertEqual(result['status'],'passed')
            self.assertEqual(result['syscall_events'],2)
            self.assertGreaterEqual(result['requirements'],1)
            self.assertGreaterEqual(result['repair_plan']['decisions_total'],1)
            self.assertFalse(result['repairs_applied'])
            events=[json.loads(line) for line in (case/'phase2/logs/syscall_events.jsonl').read_text().splitlines()]
            self.assertEqual({event['pid'] for event in events},{pid})
            diff=f.read_json(case/'phase2/config/rootfs_diff.json')
            self.assertIn('/tmp/marker',{item['path'] for item in diff['created']})
            before=f.read_json(case/'phase2/config/rootfs_before.json')
            self.assertNotIn('/__taintforge/secret',before['entries'])
            self.assertNotIn('/tmp/marker',before['entries'])
            self.assertTrue((case/'phase2/report.md').is_file())

    def test_pidless_signal_is_bound_to_its_exclusive_child_capture(self):
        case=self.capture(fatal_signal=True)
        result=p.analyze(case,p.settings())
        self.assertEqual(result['syscall_events'],3)
        events=[json.loads(line) for line in (case/'phase2/logs/syscall_events.jsonl').read_text().splitlines()]
        self.assertEqual(events[-1]['pid'],101)
        self.assertEqual(events[-1]['pid_source'],'exclusive_child_capture')

    def test_changed_capture_is_rejected(self):
        case=self.capture()
        (case/'phase2/logs/qemu_strace.log').write_text('tampered')
        with self.assertRaisesRegex(RuntimeError,'observation changed'):
            p.analyze(case,p.settings())

    def test_mixed_child_pids_are_rejected(self):
        case=self.capture(mixed=True)
        with self.assertRaisesRegex(RuntimeError,'mixed child'):
            p.analyze(case,p.settings())

    def test_changed_input_identity_is_rejected(self):
        case=self.capture()
        (case/'input').write_bytes(b'changed')
        with self.assertRaisesRegex(RuntimeError,'case identity changed'):
            p.analyze(case,p.settings())

    def test_log_budget_does_not_silently_truncate_observations(self):
        case=self.base/'00000000';case.mkdir();(case/'input').write_bytes(b'A')
        capture=p.Capture(self.fs,self.parent,case,excluded=('/__taintforge',),config=p.settings())
        capture.before()
        with self.trace.open('ab') as stream:
            stream.write(b'x'*(1024*1024+1))
        with self.assertRaisesRegex(RuntimeError,'budget or was truncated'):
            capture.finish({'guest_exit':0,'child_namespace_pid':101})

    def test_configuration_round_trip_keeps_old_campaigns_compatible(self):
        args=dict(bootstrap_seconds=60,campaign_seconds=60,timeout_ms=1000,max_rss_mib=512)
        old=w.configuration(self.base,**args)
        self.assertNotIn('phase2',old)
        self.assertEqual(w.validate(old),old)
        value=w.configuration(self.base,**args,phase2_mode='parallel',phase2_pending=2)
        self.assertEqual(w.validate(value),value)
        value['phase2']['pending']=0
        with self.assertRaisesRegex(RuntimeError,'configuration'):
            w.validate(value)


class ProcessorTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.base=Path(self.temp.name)
        for index in range(3): (self.base/f'{index:08d}'/'phase2').mkdir(parents=True)

    def test_sequential_mode_finishes_analysis_before_next_input(self):
        calls=[]
        worker=p.Processor(self.base,p.settings('sequential'),process=lambda case,config:calls.append(case))
        worker.start();worker.submit(self.base/'00000000')
        self.assertEqual(calls,[self.base/'00000000'])
        self.assertEqual(worker.completed,1)
        worker.close()
        self.assertEqual(f.read_json(self.base/'phase2-progress.json')['status'],'passed')

    def test_parallel_mode_returns_while_analysis_is_still_running_and_drains(self):
        entered,release=threading.Event(),threading.Event()
        calls=[]
        def process(case,config):
            entered.set()
            if not release.wait(5): raise RuntimeError('Test did not release worker')
            calls.append(case)
        worker=p.Processor(self.base,p.settings('parallel',2),process=process)
        worker.start()
        try:
            worker.submit(self.base/'00000000')
            self.assertTrue(entered.wait(2))
            self.assertEqual(worker.completed,0)
            worker.submit(self.base/'00000001')
            self.assertEqual(worker.submitted,2)
        finally:
            release.set();worker.close()
        self.assertEqual(len(calls),2)
        self.assertEqual(worker.maximum_pending,2)

    def test_queue_applies_backpressure_instead_of_growing_without_bound(self):
        entered,release,submitted=threading.Event(),threading.Event(),threading.Event()
        def process(case,config):
            entered.set()
            if not release.wait(5): raise RuntimeError('Test did not release worker')
        worker=p.Processor(self.base,p.settings('parallel',1),process=process)
        worker.start();worker.submit(self.base/'00000000')
        self.assertTrue(entered.wait(2))
        def submit():
            worker.submit(self.base/'00000001');submitted.set()
        thread=threading.Thread(target=submit);thread.start()
        try: self.assertFalse(submitted.wait(.1))
        finally:
            release.set();thread.join(3);worker.close()
        self.assertTrue(submitted.is_set())
        self.assertLessEqual(worker.maximum_pending,1)

    def test_analysis_failure_blocks_a_successful_campaign(self):
        def failed(case,config): raise RuntimeError('broken phase2 parser')
        worker=p.Processor(self.base,p.settings('sequential'),process=failed)
        worker.start()
        with self.assertRaisesRegex(RuntimeError,'broken phase2 parser'):
            worker.submit(self.base/'00000000')
        with self.assertRaisesRegex(RuntimeError,'broken phase2 parser'):
            worker.close()
        self.assertEqual(f.read_json(self.base/'phase2-progress.json')['status'],'failed')


if __name__=='__main__': unittest.main()
