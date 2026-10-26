"""Host acceptance: original benign ELF, real M4 retirement, guest-file coverage, AFL++."""
import argparse
import hashlib
from pathlib import Path
import subprocess

from experiments.afl_file.build import guest
from taintforge_env import afl_file as f
from taintforge_env.afl_transport import run_campaign
from taintforge_env.capsule_resources import preflight
from experiments.execution_capsule_probe import controller as p


def verify(out, *, qemu, plugin, afl_bin, seconds=300, executions=64):
    out=Path(out).resolve();out.mkdir(parents=True,exist_ok=False)
    report={'status':'failed','scope':'real_m4_end_to_end',
            'protected_control_channel':False,'hostile_sample_ready':False}
    try:
        preflight()
        version=p.command(qemu,'--version').splitlines()[0]
        p.require('version 11.0.1' in version,'QEMU 11.0.1 required')
        p.command('sudo','-n','true')
        # This must succeed on the host; there is no component fallback.
        p.command('sudo','-n','unshare','--mount','--pid','--fork','--net','true')
        binary=guest(out/'fixture')
        seeds=out/'seeds';seeds.mkdir();(seeds/'seed').write_bytes(b'A')
        root=out/'campaign'
        manifest=f.prepare_campaign(root,binary=binary,qemu=qemu,plugin=plugin,
                                    guest_path='/etc/afl-input',seeds=seeds)
        (root/'cases').mkdir()
        maps=[];ids=[]
        for index,data in enumerate((b'A',b'A',b'B',b'AFL!',b'A')):
            case=root/'cases'/str(90000000+index);case.mkdir();(case/'input').write_bytes(data)
            result=f.execute_attempt(root,case)
            p.require(result['guest_exit']==0,'Controlled fixture did not exit successfully')
            binding=f.read_json(Path(result['run_dir'])/'config/capsule_binding.json')
            p.require((Path(binding['rootfs'])/'tmp/afl-marker').is_file(),'Guest did not create its private marker')
            p.require(binding['afl_file']==f.settings('/etc/afl-input',data),'Input identity was lost')
            maps.append((case/'coverage.map').read_bytes());ids.append(binding['attempt_id'])
        p.require(len(set(ids))==len(ids),'Attempt identity reused')
        p.require(maps[0]==maps[1]==maps[4],'Identical input coverage is unstable after retirement')
        p.require(len(set(maps))>=3,'Guest input branches are not visible in coverage')
        campaign=run_campaign(root,afl_bin=afl_bin,seconds=seconds,executions=executions)
        p.require(campaign['status']=='completed' and campaign['cases']>=2,'Campaign did not complete')
        queue=list((root/'afl/default/queue').glob('id:*'))
        p.require(len(queue)>1,'AFL++ did not retain a new guest path')
        snapshot=f.EnvironmentSnapshotStore(manifest['snapshot_store']).verify(manifest['snapshot_id'])
        p.require(not any(e.path=='/tmp/afl-marker' for e in snapshot.entries),'Baseline was polluted')
        results=[]
        for case in sorted((root/'cases').iterdir()):
            if int(case.name) < 90000000:
                transport=f.read_json(case/'transport.json')
                p.require(transport['cleanup_confirmed'] is True,'Attempt cancellation left processes')
                if transport['status']=='cancelled':
                    results.append({'case':case.name,'status':'cancelled_by_afl_budget'})
                    continue
            result=f.read_json(case/'result.json');p.require(result['status']=='passed','Failed case in acceptance')
            binding=f.read_json(Path(result['run_dir'])/'config/capsule_binding.json')
            capsule=f.read_json(Path(result['run_dir'])/'config/capsule_result.json')
            p.require(capsule['status']=='passed' and capsule['resources']['tree_empty'] is True,
                      'Capsule cleanup was not verified')
            p.require((Path(binding['rootfs'])/'tmp/afl-marker').is_file(),'Dirty/missing guest fixture marker')
            p.require(result['baseline_input_sha256']==hashlib.sha256(b'A').hexdigest(),
                      'Input was not restored from baseline')
            results.append({'case':case.name,'attempt_id':binding['attempt_id'],
                            'input_sha256':result['input']['input_sha256'],
                            'map_sha256':result['coverage']['map_sha256']})
        report.update(status='passed',qemu_version=version,queue_entries=len(queue),
            cases=results,afl_cases=campaign['cases'],same_input_stable=True,
            fresh_snapshot_per_attempt=True,phase1_retirement_verified=True)
        return report
    except Exception as exc:
        report['error']=f'{type(exc).__name__}: {exc}'
        raise
    finally:f.atomic_json(out/'acceptance.json',report)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('out','qemu','plugin','afl-bin'):parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--seconds',type=int,default=300)
    parser.add_argument('--executions',type=int,default=64)
    args=parser.parse_args()
    import json
    print(json.dumps(verify(args.out,qemu=args.qemu,plugin=args.plugin,afl_bin=args.afl_bin,
                            seconds=args.seconds,executions=args.executions),indent=2))


if __name__=='__main__':main()
