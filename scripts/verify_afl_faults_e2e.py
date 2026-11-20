"""Full M4 + AFL faults, one-session replay/minimization and a repair epoch."""
import argparse
import json
from pathlib import Path

from scripts.verify_afl_phase2_e2e import verify as pipeline, SudoLease
from taintforge_env import afl_file as f
from taintforge_env.afl_epochs import evolve
from taintforge_env.afl_replay import replay


def verify(out, *, qemu, afl_bin=None, mode='parallel', seconds=30, executions=64):
    out=Path(out).absolute();out.mkdir(parents=True,exist_ok=False)
    report={'status':'failed','scope':'real_m4_afl_faults_replay_repair_epoch'}
    try:
        first=pipeline(out/'initial',qemu=qemu,afl_bin=afl_bin,mode=mode,seconds=seconds,
                       executions=executions,faults=True)
        campaign=out/'initial/campaign'
        findings=[path.parent for path in (campaign/'findings/crashes').glob('*/finding.json')]
        finding=max(findings,key=lambda path:(path/'input').stat().st_size)
        # Each new session has one Phase 1; mutations/minimization trials reuse it.
        with SudoLease():
            print('Проверка воспроизведения и минимизации в одной новой warm-сессии.',flush=True)
            reproduced=replay(campaign,finding,out/'replay',repetitions=3,reduce=True,budget=64)
            f.p.require(reproduced['status']=='passed' and reproduced['phase1_runs']==1 and
                        (out/'replay/minimized-input').stat().st_size==1,'Replay/minimization failed')
            print('Проверка ремонта отсутствующего каталога и нового checkpoint.',flush=True)
            epochs=evolve(campaign,out/'repair-epochs',max_epochs=2,seconds=seconds,executions=16,
                          afl_bin=out/'initial/afl-bin')
            f.p.require(epochs['new_phase1_runs']==1 and epochs['stop_reason']=='no_automatic_repairs',
                        'Expected exactly one effective repair epoch')
        report.update(status='passed',initial=first,replay=reproduced,repair_epochs=epochs,
                      phase1_runs_per_session=1,new_sessions=3)
        return report
    except BaseException as exc:
        report['error']=str(exc)
        raise
    finally:
        f.atomic_json(out/'acceptance.json',report)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out',type=Path,required=True)
    parser.add_argument('--qemu',type=Path,required=True)
    parser.add_argument('--afl-bin',type=Path)
    parser.add_argument('--phase2-mode',choices=('parallel','sequential'),default='parallel')
    parser.add_argument('--seconds',type=int,default=30)
    parser.add_argument('--executions',type=int,default=64)
    args=parser.parse_args()
    print(json.dumps(verify(args.out,qemu=args.qemu,afl_bin=args.afl_bin,mode=args.phase2_mode,
                            seconds=args.seconds,executions=args.executions),indent=2))


if __name__=='__main__':main()
