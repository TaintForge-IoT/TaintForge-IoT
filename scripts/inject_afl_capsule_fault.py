"""Kill a bound capsule process only after real warm AFL execution has begun."""
import argparse
import os
from pathlib import Path
import signal
import time

from scripts.inject_capsule_lifecycle_fault import target_identity
from taintforge_env import afl_file as f, afl_capsule


def inject(campaign,role,*,seconds=1200):
    campaign=Path(campaign).absolute()
    f.p.require(role in ('qemu','observer') and '..' not in campaign.parts and campaign!=Path('/'),
                'Invalid warm fault target')
    run=campaign/'warm-session/iterations/0000/run'
    deadline=time.monotonic()+seconds
    while time.monotonic()<deadline:
        f.p.require(not (campaign/'fault-cancel').exists(),'Warm fault injection cancelled')
        paths=(campaign/'campaign.json',campaign/'warm-ready.json',run/'config/capsule_binding.json',
               run/'logs/capsule/workers.json')
        if not all(path.is_file() for path in paths):
            time.sleep(.02);continue
        manifest,ready,binding,record=(f.read_json(path) for path in paths)
        f.p.require(manifest['status'] in ('preparing','running'),'Warm fault boundary was missed')
        if manifest['status']!='running' or not any((campaign/'cases').glob('*/result.json')):
            time.sleep(.02);continue
        f.p.require(Path(binding['run_dir'])==run and binding['afl_warm']['campaign_root']==str(campaign),
                    'Warm fault binding escapes this campaign')
        proof=afl_capsule.checkpoint(binding,record['qemu_pid'])
        f.p.require(ready['capsule_checkpoint']==proof,'Warm fault requires admitted M5 execution')
        target=target_identity(binding,record,role)
        descriptor=os.pidfd_open(target['pid'])
        try:
            f.p.require(target_identity(binding,record,role)==target,'Warm fault target changed after pidfd open')
            f.p.require(f.read_json(campaign/'campaign.json')['status']=='running' and
                        not (campaign/'fault-cancel').exists(),'Warm AFL fault boundary was missed or cancelled')
            signal.pidfd_send_signal(descriptor,signal.SIGKILL)
        finally:os.close(descriptor)
        return {'schema':1,'status':'injected','role':role,'signal':'SIGKILL','target':target,
                'identity':record['identity'],'unit':record['unit'],'capsule_checkpoint':proof,
                'injected_monotonic_ns':time.monotonic_ns()}
    raise TimeoutError('Warm AFL fault boundary deadline')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--campaign',type=Path,required=True)
    parser.add_argument('--role',choices=('qemu','observer'),required=True)
    args=parser.parse_args()
    os.umask(0o077)
    result={'schema':1,'status':'failed','role':args.role}
    try:result.update(inject(args.campaign,args.role))
    except Exception as exc:result['error']=f'{type(exc).__name__}: {exc}'[:3000]
    path=args.campaign/'fault-injection.json';f.p.write_json(path,result)
    owner=args.campaign.stat();os.chown(path,owner.st_uid,owner.st_gid)
    return 0 if result['status']=='injected' else 1


if __name__=='__main__':raise SystemExit(main())
