"""Real AFL++/QEMU coverage test; no namespaces, Phase 1, or M4 success claim."""
import argparse
import hashlib
import os
from pathlib import Path
import struct
import subprocess
import sys
import re
import time

from experiments.afl_file.build import components
from taintforge_env import afl_file as f
from taintforge_env.afl_transport import AttemptServer, recv_exact
from taintforge_env.environment_snapshot import EnvironmentSnapshotStore
from experiments.execution_capsule_probe import controller as p


def request(server,data):
    with server.connect() as connection:
        connection.settimeout(20)
        connection.sendall(struct.pack('!I',len(data))+data)
        magic,status,reserved,length=struct.unpack('!4I',recv_exact(connection,16))
        p.require((magic,status,reserved,length)==(0x54464131,0,0,f.MAP_SIZE),'Transport returned failure')
        return recv_exact(connection,length)


def fixture(root,built,qemu,constant=False):
    root.mkdir(parents=True)
    baseline=root/'baseline';baseline.mkdir();(baseline/'input').write_bytes(b'A')
    store=EnvironmentSnapshotStore(root/'snapshots')
    captured=store.capture(baseline)
    f.atomic_json(root/'campaign.json',{'max_input':4096})
    f.atomic_json(root/'component.json',{'snapshot_id':captured.manifest.snapshot_id,
        'qemu':str(qemu),'probe':built['probe'],
        'guest':built['constant_guest'] if constant else built['guest']})
    return [sys.executable,'-m','tests.afl_component_worker','--out',str(root)]


def environment():
    env=dict(os.environ)
    env.update(AFL_NO_UI='1',AFL_NO_AFFINITY='1',AFL_SKIP_CPUFREQ='1',AFL_FAST_CAL='1',AFL_MAP_SIZE='65536')
    return env


def run(root,qemu,afl_bin,seconds=15):
    p.require(type(seconds) is int and 1 <= seconds <= 3600, 'Invalid verification time')
    root=Path(root).resolve();root.mkdir(parents=True,exist_ok=False)
    qemu=Path(qemu).resolve(strict=True);afl_bin=Path(afl_bin).resolve(strict=True)
    p.require('version 11.0.1' in p.command(qemu,'--version').splitlines()[0],'Pinned QEMU 11.0.1 required')
    built=components(root/'build')
    corpus=root/'branching'
    command=fixture(corpus,built,qemu)
    server=AttemptServer(corpus,command=command,deadline=15);server.start()
    try:
        samples=[b'A',b'A',b'B',b'AFL!',b'CCCC',b'A']
        maps=[request(server,data) for data in samples]
        p.require(maps[0]==maps[1]==maps[5],'Coverage is not deterministic for identical input')
        p.require(len(set(maps))>=3,'Guest branches did not produce distinct coverage')
        direct_hashes=[hashlib.sha256(x).hexdigest() for x in maps]
        seeds=corpus/'seeds';seeds.mkdir();(seeds/'seed').write_bytes(b'A')
        before_fuzz=server.executed;before_completed=server.completed
        afl_command=[str(afl_bin/'afl-fuzz'),'-i',str(seeds),'-o',str(corpus/'afl'),'-V',str(seconds),
            '-t','15000','-m','256','-g','1','-G','4096','-s','42',
            '--',built['bridge'],str(server.control_fd),'@@']
        with (corpus/'afl.log').open('wb') as log:
            executed=subprocess.run(afl_command,env=environment(),stdout=log,stderr=log,timeout=seconds+30,pass_fds=(server.control_fd,))
        p.require(executed.returncode==0,'Real AFL++ failed; inspect '+str(corpus/'afl.log'))
        p.require(not server.errors,'Attempt errors: '+str(server.errors))
        queue=list((corpus/'afl/default/queue').glob('id:*'))
        p.require(len(queue)>1,'AFL++ queue did not grow on new guest coverage')
        count=server.executed-before_fuzz
        delivered=server.completed-before_completed
    finally:server.close()
    constant=root/'constant';command=fixture(constant,built,qemu,True)
    server=AttemptServer(constant,command=command,deadline=15);server.start()
    try:
        constant_maps=[request(server,data) for data in (b'A',b'B',b'AFL!',b'xyz'*30)]
        p.require(len(set(constant_maps))==1,'Input bytes/host harness contaminated guest coverage')
    finally:server.close()
    # Worker failures must stop the forkserver, never become target crashes.
    failed=root/'failed';failed.mkdir();f.atomic_json(failed/'campaign.json',{'max_input':4096})
    server=AttemptServer(failed,command=[sys.executable,'-c','raise SystemExit(2)'],deadline=2)
    server.start()
    try:
        seeds=failed/'seeds';seeds.mkdir();(seeds/'seed').write_bytes(b'A')
        with (failed/'afl.log').open('wb') as log:
            failure=subprocess.run([str(afl_bin/'afl-fuzz'),'-i',str(seeds),'-o',str(failed/'afl'),
                '-V','3','-t','5000','-m','256','--',built['bridge'],str(server.control_fd),'@@'],
                env=environment(),stdout=log,stderr=log,timeout=15,pass_fds=(server.control_fd,))
        p.require(failure.returncode!=0 and server.errors,'Infrastructure failure was not fatal')
        p.require(not list((failed/'afl/default/crashes').glob('id:*')),'Fake guest crash saved')
    finally:server.close()
    # Lost AFL child must cancel the worker process group.
    cancelled=root/'cancelled';cancelled.mkdir();f.atomic_json(cancelled/'campaign.json',{'max_input':4096})
    script="import os,pathlib,sys,time; pathlib.Path(sys.argv[-1],'pid').write_text(str(os.getpid())); time.sleep(20)"
    server=AttemptServer(cancelled,command=[sys.executable,'-c',script],deadline=10);server.start()
    connection=server.connect()
    connection.sendall(struct.pack('!I',1)+b'A')
    pidfile=cancelled/'cases/00000000/pid'
    until=time.monotonic()+5
    while not pidfile.exists() and time.monotonic()<until: time.sleep(.02)
    p.require(pidfile.exists(),'Cancellation worker did not start')
    pid=int(pidfile.read_text());connection.close();server.close()
    try:os.kill(pid,0)
    except ProcessLookupError:pass
    else:raise RuntimeError('Cancelled worker is still alive')
    help_text=subprocess.run([str(afl_bin/'afl-fuzz'),'-h'],capture_output=True,text=True).stdout
    help_text=re.sub(r'\x1b\[[0-9;]*m','',help_text)
    version=next((line for line in help_text.splitlines() if 'afl-fuzz++' in line), None)
    p.require(version, 'Unable to identify AFL++ version')
    report={'status':'passed','verification_scope':'components_only',
        'qemu_version':p.command(qemu,'--version').splitlines()[0],
        'afl_version':version,
        'qemu_sha256':p.sha(qemu),'direct_map_sha256':direct_hashes,
        'same_input_stable':True,'constant_path_stable_across_inputs':True,
        'direct_attempts':len(samples),'afl_attempts_started':count,'afl_attempts_delivered':delivered,
        'queue_entries':len(queue),
        'fresh_snapshot_per_attempt':True,'worker_failure_not_target_crash':True,
        'disconnected_worker_stopped':True,'m4_end_to_end_verified':False,
        'protected_control_channel':False,'hostile_sample_ready':False}
    f.atomic_json(root/'verification.json',report)
    return report


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qemu',type=Path,required=True)
    parser.add_argument('--afl-bin',type=Path,required=True)
    parser.add_argument('--out',type=Path,required=True)
    parser.add_argument('--seconds',type=int,default=15)
    args=parser.parse_args()
    import json
    print(json.dumps(run(args.out,args.qemu,args.afl_bin,args.seconds),indent=2))


if __name__=='__main__':main()
