"""Host acceptance: M5 + Phase 1 + warm AFL + Phase 2 + replay + controller loss."""
import argparse
import json
from pathlib import Path
import subprocess
import sys

from scripts.verify_afl_faults_e2e import verify as fault_pipeline
from scripts.verify_afl_phase2_e2e import SudoLease,verify_fault_fixture
from taintforge_env import afl_file as f,afl_capsule
from taintforge_env.afl_replay import clone_campaign


def fault_case(source,out,role,*,afl_bin,case_verifier=verify_fault_fixture):
    clone_campaign(source,out,inputs=[b'A'])
    command=[sys.executable,'-m','scripts.run_afl_file','run','--out',str(out),
             '--seconds','30','--afl-bin',str(afl_bin)]
    with (out/'fault-helper.log').open('wb') as helper_log,(out/'pipeline.log').open('wb') as log:
        helper=subprocess.Popen(['sudo','-n',sys.executable,'-m','scripts.inject_afl_capsule_fault',
            '--campaign',str(out),'--role',role],cwd=f.PROJECT,stdin=subprocess.DEVNULL,
            stdout=helper_log,stderr=subprocess.STDOUT)
        process=None
        try:
            process=subprocess.Popen(command,cwd=f.PROJECT,stdin=subprocess.DEVNULL,
                stdout=log,stderr=subprocess.STDOUT,process_group=0)
            try:code=process.wait(timeout=1300)
            except subprocess.TimeoutExpired:
                from taintforge_env.afl_transport import stop_case
                stop_case(process,out)
                raise
        finally:
            (out/'fault-cancel').touch()
            try:helper.wait(timeout=10)
            except subprocess.TimeoutExpired:helper.terminate();helper.wait(timeout=5)
    injection=f.read_json(out/'fault-injection.json')
    manifest=f.read_json(out/'campaign.json')
    session=f.read_json(out/'warm-session-result.json')
    capsule=session.get('capsule',{})
    resources=session.get('capsule_resources') or capsule.get('resources',{})
    f.p.require(code!=0 and helper.returncode==0 and injection['status']=='injected' and
                manifest['status']=='failed' and capsule.get('status')=='failed',
                'Killed warm capsule was accepted or injection missed: '+str(out))
    f.p.require(resources.get('status')=='verified' and resources.get('tree_empty') is True,
                'Failed warm capsule service cleanup was not verified')
    ready=f.read_json(out/'warm-ready.json')
    f.p.require(ready['phase1_runs']==1 and ready['capsule_checkpoint']['profile']==afl_capsule.PROFILE,
                'Warm fault did not follow one admitted Phase 1')
    cases=list((out/'cases').glob('*/result.json'))
    f.p.require(cases,'Warm fault preceded guest execution')
    for path in cases:case_verifier(path.parent,f.read_json(path))
    for path in (out/'findings').glob('*/*/finding.json'):
        value=f.read_json(path)
        relative=Path(value['first_case'])
        f.p.require(len(relative.parts)==2 and relative.parts[0]=='cases' and
                    relative.parts[1].isdecimal(),'Finding escapes its child evidence')
        case=out/relative;result=f.read_json(case/'result.json')
        from taintforge_env.afl_findings import signature
        f.p.require(value['case_result_sha256']==f.p.sha(case/'result.json') and
                    value['outcome']==result['outcome'] and value['signature']==signature(result) and
                    (path.parent/'input').read_bytes()==(case/'input').read_bytes(),
                    'Infrastructure loss was misreported as a guest finding')
    result={'schema':1,'status':'passed','role':role,'phase1_runs':1,'completed_before_loss':len(cases),
            'campaign_status':manifest['status'],'service_cleanup_verified':True,'injection':injection,
            'scope':'bound_capsule_process_loss_during_afl','capsule_error':capsule.get('error') or session.get('error'),
            'qemu_exit_status':capsule.get('qemu_exit_status'), 'wrapper_exit':capsule.get('wrapper_exit'),
            'supervisor_error':capsule.get('supervisor_error'), 'failure':capsule.get('failure'),
            'worker_exit':capsule.get('worker_exit'), 'controller_exit':capsule.get('controller_exit'),
            'controller_failures':capsule.get('controller_failures')}
    f.atomic_json(out/'fault-acceptance.json',result)
    return result


def verify(out,*,qemu,afl_bin=None,mode='parallel',seconds=30,executions=64,faults=True):
    out=Path(out).resolve();out.mkdir(parents=True,exist_ok=False)
    report={'schema':1,'status':'failed','scope':'real_m5_warm_afl_capsule',
            'capsule_profile':afl_capsule.PROFILE,'fault_cases':[],
            'afl_m5_integration_accepted':False,
            'native_strict_positive_verified':False,'memory_isolation':False,'hostile_sample_ready':False}
    try:
        report['pipeline']=fault_pipeline(out/'pipeline',qemu=qemu,afl_bin=afl_bin,mode=mode,
                                         seconds=seconds,executions=executions)
        source=out/'pipeline/initial/campaign'
        for campaign in (source,out/'pipeline/replay',out/'pipeline/repair-epochs/epoch-000'):
            session=f.read_json(campaign/'warm-session-result.json')
            f.p.require(session['capsule'].get('afl_checkpoint',{}).get('profile')==afl_capsule.PROFILE and
                        session['capsule']['control_guard']['status']=='verified',
                        'Replay or repair epoch lost the M5 capsule profile')
        if faults:
            with SudoLease():
                for role in ('observer','qemu'):
                    print('Проверка потери '+role+' во время AFL.',flush=True)
                    report['fault_cases'].append(fault_case(source,out/('kill-'+role),role,
                        afl_bin=out/'pipeline/initial/afl-bin'))
        report.update(status='passed',fault_injection_tested=faults,afl_m5_integration_accepted=faults)
        return report
    except BaseException as exc:
        report['error']=f'{type(exc).__name__}: {exc}';raise
    finally:f.atomic_json(out/'acceptance.json',report)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out',type=Path,required=True)
    parser.add_argument('--qemu',type=Path,required=True)
    parser.add_argument('--afl-bin',type=Path)
    parser.add_argument('--phase2-mode',choices=('parallel','sequential'),default='parallel')
    parser.add_argument('--seconds',type=int,default=30)
    parser.add_argument('--executions',type=int,default=64)
    parser.add_argument('--skip-fault-injection',action='store_true')
    args=parser.parse_args()
    print(json.dumps(verify(args.out,qemu=args.qemu,afl_bin=args.afl_bin,mode=args.phase2_mode,
        seconds=args.seconds,executions=args.executions,faults=not args.skip_fault_injection),indent=2))


if __name__=='__main__':main()
