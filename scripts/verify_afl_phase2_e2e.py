"""Host test of one real Phase 1/M4 followed by AFL and per-child Phase 2."""
import argparse
from contextlib import redirect_stderr, redirect_stdout
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import threading
import time

from experiments.afl_file.build import guest, fault_mutator
from taintforge_env import afl_file as f, afl_warm as w
from taintforge_env.capsule_resources import preflight

FAULT_AFL_TIMEOUT_MS = 3000


def write_fault_launcher(shim, executable, library):
    """Allow capture/analysis overhead outside the short guest deadline."""
    shim = Path(shim)
    shim.write_text('#!/usr/bin/env python3\nimport os,sys\na=sys.argv[1:]\n'
        'a[a.index("-t")+1]='+repr(str(FAULT_AFL_TIMEOUT_MS))+'\n'
        'os.environ.update(AFL_CUSTOM_MUTATOR_LIBRARY='+repr(str(library))+',AFL_CUSTOM_MUTATOR_ONLY="1",'
        'AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES="1",AFL_HANG_TMOUT='+repr(str(FAULT_AFL_TIMEOUT_MS))+')\n'
        'os.execv('+repr(str(executable))+',['+repr(str(executable))+']+a)\n')
    shim.chmod(0o700)


class SudoLease:
    def __enter__(self):
        subprocess.run(['sudo','-v'],check=True)
        self.stop=threading.Event()
        def refresh():
            while not self.stop.wait(45):
                try:
                    subprocess.run(['sudo','-n','-v'],stdin=subprocess.DEVNULL,
                        stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=15,check=True)
                except (OSError,subprocess.SubprocessError):
                    return
        self.thread=threading.Thread(target=refresh,daemon=True);self.thread.start()
        return self
    def __exit__(self,*args):
        self.stop.set();self.thread.join(16)


class Progress:
    def __init__(self,root):
        self.root=Path(root);self.console=sys.stdout;self.stop=threading.Event()
    def log(self,message):
        print('['+time.strftime('%H:%M:%S')+'] '+message,file=self.console,flush=True)
    def __enter__(self):
        def monitor():
            ready=False;last=time.monotonic()
            while not self.stop.wait(1):
                path=self.root/'warm-ready.json'
                if path.is_file() and not ready:
                    data=f.read_json(path)
                    if data['status']=='ready':
                        ready=True;self.log('Phase 1 завершена; checkpoint RSS='+str(data['rss_mib'])+' MiB. AFL и Phase 2 работают.')
                if time.monotonic()-last>=30:
                    path=self.root/'phase2-progress.json'
                    value=f.read_json(path) if path.is_file() else {}
                    self.log('Phase 2: '+str(value.get('completed',0))+'/'+str(value.get('submitted',0))+' исполнений обработано.')
                    last=time.monotonic()
        self.thread=threading.Thread(target=monitor,daemon=True);self.thread.start();return self
    def __exit__(self,*args):
        self.stop.set();self.thread.join(2)


def expected_fault_fixture(data):
    return {b'C':('guest_crash',None,4),b'S':('guest_crash',None,11),
        b'B':('guest_crash',None,6),b'H':('timeout',None,None),b'E':('normal',86,None)}.get(data[:1],('normal',0,None))


def verify_fault_fixture(case, result):
    kind,code,sig=expected_fault_fixture((Path(case)/'input').read_bytes())
    value=result.get('outcome',{})
    f.p.require(value.get('kind')==kind and result['guest_exit']==code and value.get('guest_signal')==sig
                and result['input']['input_sha256']==f.p.sha(Path(case)/'input'),
                'Fault fixture produced an unexpected child outcome: '+str(case))


def verify_saved_faults(root):
    """Verify AFL's own saved findings, independently of our case reports."""
    saved = Path(root)/'afl/default'
    crashes = sorted((saved/'crashes').glob('id:*'))
    hangs = sorted((saved/'hangs').glob('id:*'))
    expected = {b'C': 4, b'S': 11, b'B': 6}
    seen = set()
    for path in crashes:
        key = path.read_bytes()[:1]
        fields = dict(item.split(':', 1) for item in path.name.split(',') if ':' in item)
        f.p.require(key in expected and fields.get('sig') == f'{expected[key]:02d}',
                    'AFL saved a fixture crash with the wrong input or signal: '+str(path))
        seen.add(key)
    f.p.require(seen == set(expected), 'AFL did not save all three fixture crash classes')
    f.p.require(bool(hangs) and all(path.read_bytes()[:1] == b'H' for path in hangs),
                'AFL hang findings are missing or contain a misclassified crash')
    return {'afl_crashes': len(crashes), 'afl_hangs': len(hangs),
            'afl_crash_signals': sorted(expected.values())}


def verify(out, *, qemu, afl_bin=None, mode='parallel', seconds=30, executions=64, faults=False):
    out=Path(out).resolve();out.mkdir(parents=True,exist_ok=False)
    report={'status':'failed','scope':'real_m5_capsule_afl_per_child_phase2','phase2_mode':mode,'fault_fixture':faults,
            'analysis_policy': 'research', 'analysis_policy_reason': 'benign_fixture_has_partial_analysis'}
    progress=Progress(out/'campaign');progress.log('Результаты нового прогона: '+str(out))
    try:
        w.configuration(out/'campaign',bootstrap_seconds=1200,campaign_seconds=seconds+30,
                        timeout_ms=50 if faults else 3000,max_rss_mib=512,phase2_mode=mode)
        preflight()
        qemu=Path(qemu).resolve(strict=True)
        executable=Path(afl_bin)/'afl-fuzz' if afl_bin else Path(shutil.which('afl-fuzz') or '/nonexistent/afl-fuzz')
        f.p.require(executable.is_file(),'afl-fuzz is not installed')
        executable=executable.resolve()
        launcher=out/'afl-bin';launcher.mkdir()
        core_pattern=Path('/proc/sys/kernel/core_pattern').read_text().strip()
        override=core_pattern.startswith('|')
        if override:
            f.p.require(b'AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES' in executable.read_bytes(),
                        'AFL does not support the fixture-only core-pattern override')
        shim=launcher/'afl-fuzz'
        shim.write_text('#!/bin/sh\n'+('export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1\n' if override else '')+
                        'exec '+shlex.quote(str(executable))+' "$@"\n');shim.chmod(0o700)
        if faults:
            library=fault_mutator(out/'mutator')
            write_fault_launcher(shim, executable, library)
            report['fixture_limits'] = {'guest_timeout_ms': 50, 'afl_timeout_ms': FAULT_AFL_TIMEOUT_MS}
        report['fixture_only_core_override']=override or faults
        with SudoLease():
            subprocess.run(['sudo','-n','unshare','--mount','--pid','--fork','--net','true'],check=True,timeout=15)
            progress.log('Проверка bind mounts; затем сборка настоящей Phase 1.')
            environment=os.environ.copy()
            environment.update(PYTHONPATH=str(f.PROJECT),PYTHONDONTWRITEBYTECODE='1',TF_WARM_REAL_MOUNTS='1',
                               TF_QEMU_INCLUDE=str(f.PROJECT/'experiments/execution_capsule_probe/vendor'),
                               GIT_CEILING_DIRECTORIES=str(f.PROJECT.parent))
            with (out/'mount-tests.log').open('wb') as log:
                subprocess.run(['sudo','-n','unshare','--mount','--fork','--','env',
                    'PYTHONPATH='+str(f.PROJECT),'PYTHONDONTWRITEBYTECODE=1','TF_WARM_REAL_MOUNTS=1',
                    sys.executable,'-m','unittest','-v','tests.test_afl_warm_mounts.RealMountTests'],
                    stdout=log,stderr=subprocess.STDOUT,check=True,timeout=60)
            plugin=out/'libtaintforge_ir.so'
            with (out/'phase1-build.log').open('wb') as log:
                subprocess.run(['bash','unpacker/test/build_group7_4c1_plugin.sh','unpacker/test',str(plugin)],
                    cwd=f.PROJECT,env=environment,stdout=log,stderr=subprocess.STDOUT,check=True)
            from taintforge_env.phase1_runtime import Phase1Runtime
            runtime=Phase1Runtime.load(plugin)
            report['phase1_build_id']=runtime.build_id
            binary=guest(out/'fixture',faults=faults)
            seeds=out/'seeds';seeds.mkdir();(seeds/'A').write_bytes(b'A')
            argv=['run_afl_file','campaign','--binary',str(binary),'--qemu',str(qemu),'--plugin',str(plugin),
                '--seeds',str(seeds),'--guest-file','/etc/afl-input','--out',str(out/'campaign'),
                '--phase2-mode',mode,'--phase2-pending','4','--seconds',str(seconds),'--executions',str(executions),
                '--analysis-policy','research',
                '--afl-bin',str(launcher),'--campaign-seconds',str(seconds+30),'--bootstrap-seconds','1200',
                '--timeout-ms','50' if faults else '3000','--max-rss-mib','512','--memory-mib','4096','--analysis-mib','2048']
            from scripts.run_afl_file import main as campaign_main
            original=sys.argv
            try:
                sys.argv=argv
                with progress,(out/'pipeline.log').open('w') as log,redirect_stdout(log),redirect_stderr(log):
                    code=campaign_main()
            finally:sys.argv=original
            if code != 0:
                with (out/'pipeline.log').open('rb') as log:
                    log.seek(0,2);log.seek(max(0,log.tell()-8192))
                    detail=log.read().decode('utf-8',errors='replace').strip()
                raise RuntimeError('Pipeline failed (exit '+str(code)+'): '+detail+
                                   '\nLog: '+str(out/'pipeline.log'))
        root=out/'campaign'
        manifest=f.read_json(root/'campaign.json')
        session=f.read_json(root/'warm-session-result.json')
        capsule=session['capsule']
        worker=f.read_json(root/'warm-executor.json')
        state=f.read_json(root/'phase2-progress.json')
        f.p.require(manifest['status']=='completed' and manifest['phase1_runs']==worker['phase1_runs']==1,
                    'Phase 1 was repeated or the campaign failed')
        f.p.require(capsule['status']=='passed' and capsule['phase1_retirement']['phase1_retired'] is True
                    and capsule['resources']['tree_empty'] is True,'Capsule retirement or cleanup failed')
        from taintforge_env import afl_capsule
        ready=f.read_json(root/'warm-ready.json')
        template_runtime=f.read_json(Path(manifest['launch']['template_run_dir'])/'config/runtime.json')
        admission=afl_capsule.verify_ready(ready, template_runtime['capsule']['analysis_policy'])
        f.p.require(capsule.get('afl_checkpoint')==admission and capsule.get('control_guard',{}).get('status')=='verified'
                    and capsule['analysis_quality']==admission['analysis_quality'], 'M5 AFL admission/finalization mismatch')
        f.p.require(state['status']=='passed' and state['submitted']==state['completed']==worker['children']==manifest['cases']
                    and state['maximum_pending']<=4,'Per-child Phase 2 did not finish')
        cases=sorted((root/'cases').glob('*/result.json'))
        f.p.require(len(cases)==state['completed'] and len(cases)>=2,'Not enough verified child executions')
        maps={};children=set();overlap=0
        for path in cases:
            value=f.read_json(path);analysis=f.read_json(path.parent/'phase2/result.json')
            if faults:verify_fault_fixture(path.parent,value)
            f.p.require((faults or value['guest_exit']==0) and value['phase1_runs']==1 and analysis['status']=='passed'
                        and analysis['input_sha256']==value['input']['input_sha256']
                        and analysis['child_namespace_pid']==value['child_namespace_pid'], 'Child Phase 2 identity mismatch')
            if value.get('outcome',{}).get('kind')!='timeout':
                maps.setdefault(value['input']['input_sha256'],set()).add(value['coverage']['map_sha256'])
            children.add(value['child_namespace_pid'])
            overlap+=manifest['afl_started_ns']<=analysis['finished_ns']<=manifest['afl_finished_ns']
            diff=f.read_json(path.parent/'phase2/config/rootfs_diff.json')
            f.p.require('/tmp/afl-marker' in {item['path'] for item in diff['created']},'Child filesystem observation missing')
        queue=list((root/'afl/default/queue').glob('id:*'))
        f.p.require(len(children)==len(cases) and all(len(value)==1 for value in maps.values())
                    and len(queue)>1,'Child isolation, coverage stability or corpus growth failed')
        f.p.require(overlap>0,'No Phase 2 result was produced while AFL was running')
        final=session['finalization']
        f.p.require(final['status']=='completed' and all(final['stages'][name]['status']=='completed'
                    for name in ('execution','filesystem','phase1','syscalls','requirements','repair_plan','capsule'))
                    and final['stages']['network_cleanup']['status']=='not_applicable','Unified Phase 2 finalization failed')
        if faults:
            report.update(verify_saved_faults(root))
        report.update(status='passed',phase1_runs=1,children=len(cases),phase2_cases=state['completed'],
                      phase2_completed_during_afl=overlap,queue_entries=len(queue),
                      retirement_verified=True,service_cleanup_verified=True,
                      capsule_profile=afl_capsule.PROFILE, control_guard_verified=True,
                      analysis_quality=capsule['analysis_quality'],
                      pipeline_report=str(root/'pipeline-report.json'))
        progress.log('PASS: Phase 1=1; детей='+str(len(cases))+'; отчётов Phase 2='+str(state['completed'])+
                     '; обработано во время AFL='+str(overlap)+'.')
        return report
    except BaseException as exc:
        report['error']=str(exc);progress.log('FAIL: '+str(exc));raise
    finally:f.atomic_json(out/'acceptance.json',report)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out',type=Path,required=True)
    parser.add_argument('--qemu',type=Path,default=Path.home()/'.local/opt/taintforge/qemu-11.0.1-warm-v3/bin/qemu-i386')
    parser.add_argument('--afl-bin',type=Path)
    parser.add_argument('--phase2-mode',choices=('parallel','sequential'),default='parallel')
    parser.add_argument('--seconds',type=int,default=30)
    parser.add_argument('--executions',type=int,default=64)
    parser.add_argument('--faults',action='store_true')
    args=parser.parse_args()
    print(json.dumps(verify(args.out,qemu=args.qemu,afl_bin=args.afl_bin,mode=args.phase2_mode,
                            seconds=args.seconds,executions=args.executions,faults=args.faults),indent=2))


if __name__=='__main__':main()
