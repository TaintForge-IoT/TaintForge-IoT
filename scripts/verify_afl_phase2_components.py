"""Real AFL/QEMU with per-child Phase 2; this does not execute M4 retirement."""
import argparse
import json
from pathlib import Path
import struct
from unittest.mock import patch

from experiments.afl_file.build import components
from scripts.verify_afl_warm_components import NativeSession
from taintforge_env import afl_file as f, afl_phase2 as p, afl_transport as t


def verify(out, *, qemu, afl_bin, mode='parallel', executions=32):
    out = Path(out).resolve(); out.mkdir(parents=True, exist_ok=False)
    report = {'status':'failed', 'scope':'real_afl_qemu_child_phase2', 'm4_retirement_executed':False}
    session = processor = None
    try:
        built = components(out/'build')
        session = NativeSession(out/'native',built,qemu)
        parent = out/'parent'; (parent/'config').mkdir(parents=True)
        f.atomic_json(parent/'config/runtime.json',{'network_mode':'none','allow_internet':False})
        empty = out/'empty.log'; empty.write_bytes(b'')
        campaign = out/'campaign'; campaign.mkdir(); (campaign/'seeds').mkdir()
        (campaign/'seeds/A').write_bytes(b'A')
        manifest={'schema':1,'profile':'component-only','status':'prepared','max_input':4096,
                  'launch':{'timeout_seconds':10},'build':{'bridge':built['bridge']}}
        f.atomic_json(campaign/'campaign.json',manifest)
        config = p.settings(mode,4)
        processor = p.Processor(campaign,config); processor.start()

        class Server(t.AttemptServer):
            def execute(self, connection):
                size=struct.unpack('!I',t.recv_exact(connection,4))[0]
                f.p.require(1<=size<=4096,'Input limit')
                data=t.recv_exact(connection,size)
                case=self.root/'cases'/f'{self.executed:08d}';case.mkdir()
                self.executed+=1;(case/'input').write_bytes(data)
                capture=p.Capture(session.fs,parent,case,excluded=(),config=config,phase1_runs=0,
                    log_paths={'qemu_strace.log':session.root/'qemu.log',
                               'runtime_stdout.log':empty,'runtime_stderr.log':empty})
                coverage,bitmap=session.attempt(data,before=capture.before)
                (case/'coverage.map').write_bytes(bitmap)
                result={'status':'passed','child_namespace_pid':session.children[-1],
                        'guest_exit':0,'phase1_runs':0,'input':f.settings('/etc/input',data),'coverage':coverage}
                f.atomic_json(case/'result.json',result);capture.finish(result)
                processor.submit(case)
                connection.sendall(struct.pack('!4I',0x54464131,0,0,f.MAP_SIZE)+bitmap)
                self.completed+=1

        with patch.object(f,'verify_campaign',return_value=manifest),patch.object(t,'AttemptServer',Server):
            result=t.run_campaign(campaign,afl_bin=afl_bin,seconds=10,executions=executions)
        processor.close();session.close()
        analysis=[f.read_json(path) for path in sorted((campaign/'cases').glob('*/phase2/result.json'))]
        f.p.require(result['status']=='completed' and len(analysis)==result['cases'] and
                    all(value['status']=='passed' for value in analysis),'Per-child Phase 2 failed')
        f.p.require(session.prepared.read_bytes()==b'P','Original preparation was repeated')
        overlap=sum(value['finished_ns']<result['afl_finished_ns'] for value in analysis)
        f.p.require(overlap>0,'Phase 2 did not overlap the AFL campaign')
        queue=list((campaign/'afl/default/queue').glob('id:*'))
        f.p.require(len(queue)>1,'No corpus growth')
        for path in (campaign/'cases').glob('*/phase2/config/rootfs_diff.json'):
            f.p.require('/tmp/marker' in {item['path'] for item in f.read_json(path)['created']},
                        'Per-child filesystem observation was lost')
        report.update(status='passed',mode=mode,children=len(analysis),phase2_cases=len(analysis),
                      phase2_completed_during_afl=overlap,queue_entries=len(queue),
                      original_preparations=1,phase2=f.read_json(campaign/'phase2-progress.json'))
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
    args=parser.parse_args()
    print(json.dumps(verify(args.out,qemu=args.qemu.resolve(),afl_bin=args.afl_bin,mode=args.phase2_mode),indent=2))


if __name__=='__main__':main()
