"""M4 limits and concurrent attempts on the pinned systemd backend."""
import argparse
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import traceback

from experiments.execution_capsule_probe import controller as p
from experiments.input_retirement.cases import build_guests
from scripts.run_input_retirement_e2e import validate_case
from scripts.run_unified_pipeline import parser as unified_parser, prepare, run_session
from taintforge_env.phase1_runtime import read_json
from taintforge_env.input_retirement import inspect_input


def launch_case(qemu, plugin, entry, out, extra=()):
    goal=out.parent/(out.name+'-goal.json')
    p.write_json(goal,{'schema_version':1,'goal_id':'m4-complete','description':'Benign guest output',
        'mode':'all','rules':[{'id':'stdout','type':'text_contains','source':'stdout',
                             'needle':entry['expected_stdout'] or 'M3_INPUT_OK\n','min_count':1}]})
    options=unified_parser().parse_args(['run','--retire-phase1','--capsule-hardening',
        '--binary',entry['path'],'--qemu',str(qemu),'--plugin',str(plugin),'--out',str(out),
        '--target-spec',str(goal),'--max-iterations','1',*extra])
    launch=prepare(options)
    result,code=run_session(out,launch,max_steps=1)
    return launch,result,code


def budget_guests(out):
    source=Path(__file__).resolve().parents[1]/'experiments/capsule_hardening/budget_guest.S'
    results={}
    for name,export,journal in [('export-budget',1,0),('journal-budget',0,1)]:
        obj,guest=out/(name+'.o'),out/name
        p.command('as','--32','--defsym','LARGE_EXPORT='+str(export),'--defsym','LARGE_JOURNAL='+str(journal),source,'-o',obj)
        p.command('ld','-m','elf_i386','-z','noexecstack','--build-id=none',obj,'-o',guest)
        p.command('strip','--strip-all',guest)
        results[name]={'path':str(guest),'input':inspect_input(guest),'expected_stdout':'M3_INPUT_OK\n',
                       'source_sha256':p.sha(source)}
    p.write_json(out/'budget-build.json',results)
    return results


def refused(out, launch, result, code):
    p.require(code==1 and result['outcome']=='intervention_required' and
              result.get('capsule',{}).get('status')=='failed','M4 refusal was finalized as success')
    runs=sorted((out/'session/iterations').glob('*/run'))
    p.require(len(runs)==1,'M4 refusal created another attempt')
    run=runs[0]
    claim=read_json(run.parent/'execution_attempt.json')
    supervisor=read_json(run/'logs/capsule/supervisor.json')
    service=read_json(run/'logs/capsule/service.json')
    p.require(claim['stage']=='failed' and claim['retry_safe'] is False and
              service['tree_empty'] is True,'M4 failure did not clean up or retain terminal claim')
    before=p.sha(run.parent/'execution_attempt.json')
    p.write_json(out/'initial_unified_report.json',result)
    resume,code=run_session(out,launch,max_steps=1)
    p.write_json(out/'resume_report.json',resume)
    p.require(code==1 and resume['executions_this_invocation']==0 and
              p.sha(run.parent/'execution_attempt.json')==before,'M4 failed attempt resumed')
    return {'run_dir':str(run),'supervisor':supervisor,'claim_sha256':before,'tree_empty':True,'resume_executions':0}


def parallel(qemu, plugin, guests, out, *, refusal):
    out.mkdir()
    names=['missing-verdict','normal'] if refusal else ['normal','normal']
    def one(index):
        name=names[index]
        target=out/str(index)
        extra=['--retirement-max-insns','2048'] if name=='missing-verdict' else []
        launch,result,code=launch_case(qemu,plugin,guests[name],target,extra)
        attempts=validate_case(name,target,result,code,guests[name])
        run=Path(attempts[0]['run_dir'])
        binding=read_json(run/'config/capsule_binding.json')
        supervisor=read_json(run/'logs/capsule/supervisor.json')
        context=read_json(run/'logs/capsule/execution-context-1.json')
        service=read_json(run/'logs/capsule/service.json')
        return {'name':name,'run_dir':str(run),'attempt':attempts[0],'unit':service['unit'],
                'nonce':binding['lifecycle_attempt'],'pid_namespace':context['namespaces']['pid'],
                'started_ns':context['captured_monotonic_ns'],'finished_ns':supervisor['finish_monotonic_ns']}
    with ThreadPoolExecutor(max_workers=2) as executor:
        results=list(executor.map(one,(0,1)))
    for key in ('unit','nonce','pid_namespace','run_dir'):
        p.require(results[0][key]!=results[1][key],'Parallel M4 attempts share '+key)
    p.require(max(r['started_ns'] for r in results)<min(r['finished_ns'] for r in results),
              'M4 attempts did not actually overlap')
    if refusal:
        p.require(results[0]['finished_ns']<results[1]['finished_ns'],
                  'Healthy attempt did not continue after the other attempt refused')
    record={'status':'passed','refusal':refusal,'attempts':results,'overlap_verified':True}
    p.write_json(out/'report.json',record)
    return record


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qemu',type=Path,required=True)
    parser.add_argument('--plugin',type=Path,required=True)
    parser.add_argument('--out',type=Path,required=True)
    args=parser.parse_args()
    out=args.out.absolute();out.mkdir(parents=True,exist_ok=False)
    guests=build_guests(out/'inputs')
    large=budget_guests(out/'inputs')
    report={'schema':1,'profile':'capsule-hardening-m4-v1','status':'failed',
            'cases':[],'protected_control_channel':False,'hostile_sample_ready':False}
    for name,entry,extra in [
        ('memory-budget',guests['normal'],['--analysis-memory-mib','4']),
        ('export-budget',large['export-budget'],['--export-mib','1']),
        ('journal-budget',large['journal-budget'],['--journal-mib','1'])]:
        record={'name':name,'status':'failed'}
        try:
            # A positive run must not be relabelled as a budget failure.
            launch,result,code=launch_case(args.qemu,args.plugin,entry,out/name,extra)
            record.update(refused(out/name,launch,result,code))
            diagnostic=(Path(record['run_dir'])/'logs/qemu_strace.log').read_text(errors='replace')
            supervisor=record['supervisor']
            if name=='memory-budget':p.require('code=92 reason=analysis_memory_budget' in diagnostic,'Memory limit was not reached')
            else:p.require('M4 '+name.split('-')[0]+' byte budget exceeded' in supervisor.get('error',''),
                           'Requested M4 output budget was not reached')
            record['status']='passed'
        except Exception as exc:record.update(error=str(exc),traceback=traceback.format_exc())
        report['cases'].append(record);p.write_json(out/'report.json',report)
        print(name+': '+record['status'],flush=True)
        if record['status']!='passed':return 1
    for name,fault in [('parallel-positive',False),('parallel-refusal',True)]:
        record={'name':name,'status':'failed'}
        try:record.update(parallel(args.qemu,args.plugin,guests,out/name,refusal=fault))
        except Exception as exc:record.update(error=str(exc),traceback=traceback.format_exc())
        report['cases'].append(record);p.write_json(out/'report.json',report)
        print(name+': '+record['status'],flush=True)
        if record['status']!='passed':return 1
    report['status']='passed';p.write_json(out/'report.json',report)
    return 0


if __name__=='__main__':raise SystemExit(main())
