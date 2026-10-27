"""Benign component fixture only. This worker does NOT perform M4 retirement."""
import argparse
from pathlib import Path
import subprocess

from taintforge_env import afl_file as f
from taintforge_env.environment_snapshot import EnvironmentSnapshotStore


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out',type=Path,required=True)
    parser.add_argument('--case',type=Path,required=True)
    args=parser.parse_args()
    root,case=args.out,args.case
    config=f.read_json(root/'component.json')
    environment=case/'rootfs'
    EnvironmentSnapshotStore(root/'snapshots').clone(config['snapshot_id'], environment)
    if (environment/'marker').exists(): raise RuntimeError('Dirty baseline')
    input_path=environment/'input'; input_path.write_bytes((case/'input').read_bytes())
    coverage=case/'coverage.bin'; f.create_map(coverage)
    command=[config['qemu'],'-plugin',config['probe']+',coverage='+str(coverage)+',input='+str(input_path),
             config['guest'],str(input_path),str(environment/'marker')]
    result=subprocess.run(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10)
    (case/'qemu.stderr').write_bytes(result.stderr)
    if result.returncode or not (environment/'marker').is_file():
        raise RuntimeError('Controlled QEMU fixture failed: '+str(result.returncode))
    report,bitmap=f.inspect_map(coverage)
    report['scope']='guest_tb_edges_after_first_input_read_component_only'
    (case/'coverage.map').write_bytes(bitmap)
    f.atomic_json(case/'result.json',{'status':'passed','coverage':report,'guest_exit':result.returncode,
                                     'component_only':True,'m4_retirement_verified':False})
    return 0


if __name__=='__main__': raise SystemExit(main())
