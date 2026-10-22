"""Reproduce access to an inherited host FD with a benign i386 guest."""
import argparse
import os
from pathlib import Path
import subprocess

from experiments.execution_capsule_probe import controller as p


def probe(qemu, out, *, loader=None, libraries=None):
    qemu, out = Path(qemu).resolve(strict=True), Path(out).absolute()
    out.mkdir(parents=True, exist_ok=False)
    source = Path(__file__).resolve().parents[1]/'experiments/capsule_hardening/fd_probe.S'
    target = out/'host-only-output.bin'
    fd = os.open(target, os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_CLOEXEC, 0o600)
    try:
        p.command('as','--32','--defsym','PROBE_FD='+str(fd),source,'-o',out/'probe.o')
        p.command('ld','-m','elf_i386','-z','noexecstack',out/'probe.o','-o',out/'probe-i386')
        p.command('strip','--strip-all',out/'probe-i386')
        p.require((loader is None) == (libraries is None), 'Loader and library path must be supplied together')
        command=[str(qemu),'-strace',str(out/'probe-i386')]
        if loader is not None:command=[str(loader),'--inhibit-cache','--library-path',str(libraries),*command]
        result=subprocess.run(command,pass_fds=(fd,),
                              capture_output=True,timeout=10)
        (out/'stdout.log').write_bytes(result.stdout)
        (out/'strace.log').write_bytes(result.stderr)
        os.lseek(fd,0,os.SEEK_SET)
        observed=os.read(fd,128)
        p.require(result.returncode==0 and observed==b'M4_FD_PROBE\n', 'FD exposure experiment was not reproduced')
        record={'schema':1,'status':'reproduced','guest_exit':result.returncode,'inherited_fd':fd,
                'host_output_sha256':p.sha(target),'guest_sha256':p.sha(out/'probe-i386'),
                'source_sha256':p.sha(source),'qemu_sha256':p.sha(qemu),
                'scope':'benign_inherited_fd_linux_user_probe','protected_control_channel':False,
                'hostile_sample_ready':False}
        p.write_json(out/'report.json',record)
        return record
    finally:os.close(fd)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qemu',type=Path,required=True)
    parser.add_argument('--out',type=Path,required=True)
    parser.add_argument('--loader',type=Path)
    parser.add_argument('--library-path',type=Path)
    args=parser.parse_args()
    print(probe(args.qemu,args.out,loader=args.loader,libraries=args.library_path))


if __name__=='__main__':main()
