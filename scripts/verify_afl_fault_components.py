"""Real AFL/QEMU crash, hang, Phase 2, replay and minimization acceptance; no M4."""
import argparse
import hashlib
import json
from pathlib import Path
import shlex
import struct
import time
from unittest.mock import patch

from experiments.afl_file.build import components, guest, fault_mutator
from scripts.verify_afl_warm_components import NativeSession
from scripts import verify_afl_phase2_e2e as fixture
from taintforge_env import afl_file as f, afl_outcome as o, afl_phase2 as p, afl_transport as t
from taintforge_env.afl_findings import record
from taintforge_env.afl_replay import minimize, same_fault


def verify(out, *, qemu, afl_bin, mode='parallel', executions=32, seconds=15, test_reply_delay_ms=0,
           guard=False, guest_timeout_ms=30):
    f.p.require(type(test_reply_delay_ms) is int and 0 <= test_reply_delay_ms <= 10000,
                'Invalid test-only host reply delay')
    f.p.require(type(guest_timeout_ms) is int and 10<=guest_timeout_ms<=1000,'Invalid component guest deadline')
    out=Path(out).resolve();out.mkdir(parents=True,exist_ok=False)
    report={'status':'failed','scope':'real_afl_qemu_faults_phase2', 'm4_retirement_executed':False,
            'fixture_limits': {'guest_timeout_ms': guest_timeout_ms, 'afl_timeout_ms': fixture.FAULT_AFL_TIMEOUT_MS},
            'test_only_first_reply_delay_ms': test_reply_delay_ms}
    session=processor=None
    try:
        built=components(out/'build')
        built['guest']=str(guest(out/'fault-fixture',loops=1000,faults=True))
        private='/__taintforge_capsule' if guard else None
        session=NativeSession(out/'native',built,qemu,guard=private)
        original=session.attempt(b'A')[1]
        native=[]
        for data in (b'C',b'A',b'S',b'A',b'B',b'A',b'H',b'A',b'E',b'A'):
            value,coverage,bitmap=session.attempt_outcome(data,timeout_ms=guest_timeout_ms)
            f.p.require((value['kind'], value['guest_exit'], value['guest_signal']) == fixture.expected_fault_fixture(data),
                        'Unexpected native fixture outcome for '+repr(data)+': '+str(value))
            native.append(value)
            if data==b'A': f.p.require(bitmap==original,'State leaked across a fault')
        expected=native[0]
        def check(data):
            return same_fault(expected,session.attempt_outcome(data,timeout_ms=guest_timeout_ms)[0])
        reduced,reduction=minimize(b'C'+b'extra bytes'*8,check,budget=64)
        f.p.require(reduced==b'C' and check(reduced),'Fault minimization failed')
        session.close()
        # The deterministic mutator belongs only to this benign test.
        library=fault_mutator(out/'mutator')
        launcher=out/'afl-bin';launcher.mkdir()
        shim=launcher/'afl-fuzz'
        executable=Path(afl_bin).resolve()/'afl-fuzz'
        fixture.write_fault_launcher(shim, executable, library)
        parent=out/'parent';(parent/'config').mkdir(parents=True)
        f.atomic_json(parent/'config/runtime.json',{'network_mode':'none','allow_internet':False})
        empty=out/'empty.log';empty.write_bytes(b'')
        campaign=out/'campaign';campaign.mkdir();(campaign/'seeds').mkdir()
        (campaign/'seeds/A').write_bytes(b'A')
        manifest={'schema':1,'profile':'component-only','status':'prepared','max_input':4096,
                  'launch':{'timeout_seconds':10},'build':{'bridge':built['bridge']}}
        f.atomic_json(campaign/'campaign.json',manifest)
        session=NativeSession(out/'afl-native',built,qemu,guard=private)
        parent_fds_before=session.parent_fd_count()
        parent_rss=[]
        started=time.monotonic()
        config=p.settings(mode,4);processor=p.Processor(campaign,config);processor.start()
        class Server(t.AttemptServer):
            def execute(self,connection):
                size=struct.unpack('!I',t.recv_exact(connection,4))[0]
                f.p.require(1<=size<=4096,'Input limit')
                data=t.recv_exact(connection,size)
                case=self.root/'cases'/f'{self.executed:08d}';case.mkdir()
                self.executed+=1;(case/'input').write_bytes(data)
                capture=p.Capture(session.fs,parent,case,excluded=(),config=config,phase1_runs=0,
                    log_paths={'qemu_strace.log':session.root/'qemu.log','runtime_stdout.log':empty,'runtime_stderr.log':empty})
                outcome,coverage,bitmap=session.attempt_outcome(data,timeout_ms=guest_timeout_ms,before=capture.before)
                parent_rss.append(outcome['parent_rss_mib'])
                f.p.require(outcome['kind']!='infra_error','Infrastructure failure')
                (case/'coverage.map').write_bytes(bitmap)
                result={'schema':1,'status':'passed','child_namespace_pid':session.children[-1],
                        'guest_exit':outcome['guest_exit'],'outcome':outcome,'phase1_runs':0,
                        'input':f.settings('/etc/input',data),'coverage':coverage,'filesystem_sha256':session.baseline.digest}
                f.atomic_json(case/'result.json',result);capture.finish(result)
                record(campaign,case);self.metrics.record(result);processor.submit(case)
                if self.executed == 1 and test_reply_delay_ms:
                    time.sleep(test_reply_delay_ms/1000)
                connection.sendall(o.bridge_header(outcome)+bitmap);self.completed+=1
        with patch.object(f,'verify_campaign',return_value=manifest),patch.object(t,'AttemptServer',Server):
            result=t.run_campaign(campaign,afl_bin=launcher,seconds=seconds,executions=executions)
        processor.close()
        parent_fds_after=session.parent_fd_count()
        f.p.require(parent_fds_before==parent_fds_after,'Warm parent leaked file descriptors')
        elapsed=time.monotonic()-started
        session.close()
        if guard:
            from taintforge_env.capsule_control import verify_snapshot
            proofs=[json.loads(line.split('TF_COMPONENT_M5',1)[1]) for line in
                    (session.root/'qemu.log').read_text(errors='replace').splitlines() if 'TF_COMPONENT_M5' in line]
            f.p.require(proofs and len({item['pid'] for item in proofs})==len(proofs), 'Missing or duplicate native M5 child proof')
            for item in proofs:
                verify_snapshot(item['control_guard'],private=private)
                f.p.require(item['control_guard']['checked_syscalls']>0, 'Inactive native M5 guard')
            report['control_guard_verified']=True
            report['guarded_completed_children']=len(proofs)
        crashes=list((campaign/'afl/default/crashes').glob('id:*'))
        hangs=list((campaign/'afl/default/hangs').glob('id:*'))
        findings=list((campaign/'findings').glob('*/*/finding.json'))
        report.update(fixture.verify_saved_faults(campaign))
        cases=[]
        for path in sorted((campaign/'cases').glob('*/result.json')):
            value=f.read_json(path)
            fixture.verify_fault_fixture(path.parent,value)
            cases.append(value)
        kinds={v['outcome']['kind'] for v in cases}
        if guard:
            f.p.require({v['child_namespace_pid'] for v in cases if v['outcome']['kind']=='normal'} <=
                        {item['pid'] for item in proofs} <= {v['child_namespace_pid'] for v in cases},
                        'M5 proof does not cover every normally completed warm child')
        f.p.require(kinds=={'normal','guest_crash','timeout'},'Outcome coverage incomplete')
        f.p.require(session.prepared.read_bytes()==b'P','Preparation repeated')
        analyses=[f.read_json(x) for x in (campaign/'cases').glob('*/phase2/result.json')]
        f.p.require(len(analyses)==len(cases) and all(v['status']=='passed' for v in analyses),'Fault observations lost')
        for category,paths in (('crashes',crashes),('hangs',hangs)):
            for path in paths:
                values=[v for v in cases if v['input']['input_sha256']==hashlib.sha256(path.read_bytes()).hexdigest()]
                expected_kind='guest_crash' if category=='crashes' else 'timeout'
                f.p.require(values and all(v['outcome']['kind']==expected_kind for v in values),'False AFL finding')
        report.update(status='passed',mode=mode,children=len(cases),phase2_cases=len(analyses),
                      afl_crashes=len(crashes),afl_hangs=len(hangs),fault_groups=len(findings),
                      native_outcomes=[v['kind'] for v in native],parent_survived_faults=True,
                      original_preparations=1,minimized_input_hex=reduced.hex(),minimization=reduction)
        report.update(warm_seconds=elapsed,executions_per_second=len(cases)/max(elapsed,.001),
                      parent_fds_before=parent_fds_before,parent_fds_after=parent_fds_after,
                      parent_rss_mib_min=min(parent_rss),parent_rss_mib_max=max(parent_rss),
                      retained_artifact_bytes=f.read_json(campaign/'metrics.json')['retained_artifact_bytes'])
        return report
    except BaseException as exc:
        report['error']=str(exc);raise
    finally:
        try:
            if session is not None and session.process.poll() is None:session.close(abort=True)
        finally:
            try:
                if processor is not None and not processor.closed:processor.close()
            finally:f.atomic_json(out/'acceptance.json',report)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('out','qemu','afl-bin'):parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--phase2-mode',choices=('parallel','sequential'),default='parallel')
    parser.add_argument('--executions',type=int,default=32)
    parser.add_argument('--seconds',type=int,default=15)
    parser.add_argument('--guard',action='store_true')
    parser.add_argument('--guest-timeout-ms',type=int,default=30)
    args=parser.parse_args()
    print(json.dumps(verify(args.out,qemu=args.qemu.resolve(),afl_bin=args.afl_bin,mode=args.phase2_mode,
                           executions=args.executions,seconds=args.seconds,guard=args.guard,
                           guest_timeout_ms=args.guest_timeout_ms),indent=2))


if __name__=='__main__':main()
