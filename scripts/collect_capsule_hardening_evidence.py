"""Collect M4 evidence without copying complete rootfs/runtime trees."""
import argparse
from pathlib import Path

from scripts import collect_input_retirement_evidence as base
from experiments.execution_capsule_probe import controller as p
from taintforge_env.phase1_runtime import read_json

EXTRA_PATTERNS = (
    'extra/*.json', 'extra/inputs/*', 'extra/*/*.json', 'extra/*/*/*.json',
    'extra/**/session/*.json', 'extra/**/session/*.jsonl',
    'extra/**/session/attempts/**/*.json', 'extra/**/session/manifests/**/*.json',
    'extra/**/session/iterations/*/*.json', 'extra/**/run/guest-i386',
    'extra/**/run/config/*.json', 'extra/**/run/config/analyzer_runtime/bundle.json',
    'extra/**/run/config/analyzer_runtime/plugin/*', 'extra/**/run/config/analyzer_runtime/capsule/*',
    'extra/**/run/logs/**/*', 'extra/**/run/retirement-evidence/**/*', 'fd-probe/*',
)


def check_budget_case(root, case):
    run=root/'extra'/case['name']/'session/iterations/0000/run'
    claim=run.parent/'execution_attempt.json'
    resume=read_json(root/'extra'/case['name']/'resume_report.json')
    supervisor=read_json(run/'logs/capsule/supervisor.json')
    binding=read_json(run/'config/capsule_binding.json')
    service=read_json(run/'logs/capsule/service.json')
    c=read_json(claim)
    native=supervisor['qemu_exit']
    p.require(type(native) is int and -64 <= native <= 255 and
              type(c['guest_exit_code']) is int, 'Invalid M4 exit status')
    expected_exit=128-native if native < 0 else native
    p.require(p.sha(claim)==case['claim_sha256'] and c['stage']=='failed' and c['retry_safe'] is False and
              supervisor==case['supervisor'] and service['tree_empty'] is True and
              expected_exit==c['guest_exit_code'] and
              resume['executions_this_invocation']==0,'M4 budget failure evidence changed')
    trace=(run/'logs/qemu_strace.log').read_text(errors='replace')
    if case['name']=='memory-budget':
        p.require('code=92 reason=analysis_memory_budget' in trace,'Native memory budget diagnostic changed')
    else:
        label=case['name'].split('-')[0]
        p.require('M4 '+label+' byte budget exceeded' in supervisor.get('error',''),'Output budget diagnosis changed')
        # Validate the saved sizes with local paths, without rewriting evidence.
        export=sum(f.stat().st_size for f in (run/'logs/phase1').iterdir() if not f.name.startswith('events.jsonl'))
        journal=sum(f.stat().st_size for f in (run/'logs/phase1').iterdir() if f.name.startswith('events.jsonl'))
        journal+=sum((run/'logs'/n).stat().st_size for n in ('runtime_stdout.log','qemu_strace.log'))
        journal+=sum(f.stat().st_size for f in (run/'logs/capsule').rglob('*') if f.is_file() and 'export' not in f.relative_to(run/'logs/capsule').parts)
        p.require((export if label=='export' else journal)>binding['settings']['hardening'][label+'_bytes'],
                  'Saved output did not exceed its requested budget')


def check_results(root):
    base.check_results(root)
    matrix=read_json(root/'e2e/report.json')
    tests=read_json(root/'validation/m4-tests.json')
    extra=read_json(root/'extra/report.json')
    fd=read_json(root/'fd-probe/report.json')
    p.require(matrix.get('m4_hardening') is True,'M4 base matrix did not enable hardening')
    p.require(tests['successful'] is True and tests['tests_run']==tests['tests_expected'] and
              tests['tests_run']>=16 and all(tests[k]==0 for k in ('skipped','failures','errors')),
              'M4 tests did not pass without skips')
    expected=['memory-budget','export-budget','journal-budget','parallel-positive','parallel-refusal']
    p.require(extra['status']=='passed' and [c['name'] for c in extra['cases']]==expected and
              all(c['status']=='passed' for c in extra['cases']),'M4 extra matrix is incomplete')
    p.require(fd['status']=='reproduced' and fd['protected_control_channel'] is False,
              'FD architectural limitation was not reproduced')
    for case in extra['cases']:
        if case['name'].endswith('budget'):
            check_budget_case(root, case)
        else:
            p.require(case['overlap_verified'] is True and len(case['attempts'])==2,'Missing parallel attempts')
            for index,attempt in enumerate(case['attempts']):
                run=root/'extra'/case['name']/str(index)/'session/iterations/0000/run'
                context=read_json(run/'logs/capsule/execution-context-1.json')
                supervisor=read_json(run/'logs/capsule/supervisor.json')
                service=read_json(run/'logs/capsule/service.json')
                p.require(attempt['started_ns']==context['captured_monotonic_ns'] and
                          attempt['finished_ns']==supervisor['finish_monotonic_ns'] and
                          attempt['unit']==service['unit'] and service['tree_empty'] is True and
                          attempt['pid_namespace']==context['namespaces']['pid'],'Parallel timing/resource evidence changed')
                if attempt['name']=='normal':
                    from taintforge_env.retirement_evidence import verify
                    verify(run/'retirement-evidence',expected_sha256=attempt['attempt']['bundle_sha256'])
            for key in ('unit','nonce','pid_namespace','run_dir'):
                p.require(case['attempts'][0][key]!=case['attempts'][1][key],'Shared parallel resource: '+key)
            p.require(max(a['started_ns'] for a in case['attempts'])<min(a['finished_ns'] for a in case['attempts']),
                      'Saved M4 attempts did not overlap')
            if case['refusal']:
                p.require(case['attempts'][0]['finished_ns']<case['attempts'][1]['finished_ns'],
                          'Healthy attempt did not continue after the other refusal')


def collect(root, code):
    required=base.required_paths()|{'validation/m4-tests.json','validation/m4-tests.log',
                                  'validation/extra.log','extra/report.json','fd-probe/report.json'}
    return base.collect(root,code,patterns=base.PATTERNS+EXTRA_PATTERNS,
                        required=required,checker=check_results,kind='m4-acceptance')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out',type=Path,required=True)
    mode=parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--exit-code',type=int)
    mode.add_argument('--verify-only',action='store_true')
    args=parser.parse_args()
    if args.verify_only:
        check_results(args.out)
        print({'status':'verified','profile':'capsule-hardening-m4-v1','out':str(args.out)})
        return 0
    result=collect(args.out,args.exit_code)
    print(result)
    return 0 if result['complete'] else 1


if __name__=='__main__':raise SystemExit(main())
