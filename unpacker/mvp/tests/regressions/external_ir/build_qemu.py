"""Build the i386 observation runtime from a local QEMU 11.0.1 checkout."""
import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent
PROJECT = ROOT.parents[4]
QEMU_COMMIT = '6e9a825c1d4e7b62d072e99a89ecd1a74c7f0d55'


def run(command, log, *, cwd=None, timeout=600):
    with log.open('wb') as stream:
        subprocess.run(command, cwd=cwd, stdout=stream, stderr=subprocess.STDOUT, check=True,
                       timeout=timeout, env={**os.environ, 'GIT_TERMINAL_PROMPT': '0'})


def build(checkout, output, jobs):
    output.mkdir(parents=True, exist_ok=False)
    with tempfile.TemporaryDirectory(prefix='qemu-build.', dir=output) as temporary:
        root = Path(temporary)
        source, build_dir = root / 'source', root / 'build'
        run(['git', 'clone', '--no-hardlinks', '--no-checkout', checkout, source], output / 'clone.log')
        run(['git', '-C', source, 'checkout', '--detach', QEMU_COMMIT], output / 'checkout.log')
        run([sys.executable, '-I', '-B', PROJECT / 'experiments/afl_file/qemu/apply.py',
             '--qemu-source', source], output / 'base-patch.log')
        patch = ROOT / 'qemu-observations.patch'
        run(['git', '-C', source, 'apply', '--check', patch], output / 'patch-check.log')
        run(['git', '-C', source, 'apply', patch], output / 'patch.log')
        build_dir.mkdir()
        run([source / 'configure', '--python=' + sys.executable, '--target-list=i386-linux-user',
             '--enable-plugins', '--disable-system', '--disable-docs', '--without-default-features'],
            output / 'configure.log', cwd=build_dir)
        run(['ninja', '-j', str(jobs), 'qemu-i386'], output / 'ninja.log', cwd=build_dir, timeout=2400)
        sdk = output / 'include'
        sdk.mkdir()
        shutil.copy2(source / 'include/plugins/qemu-plugin.h', sdk / 'qemu-plugin.h')
        qemu = output / 'qemu-i386'
        shutil.copy2(build_dir / 'qemu-i386', qemu)
    print(qemu)
    print(sdk)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qemu-source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--jobs', type=int, default=min(8, os.cpu_count() or 1))
    args = parser.parse_args()
    if args.jobs < 1:
        parser.error('--jobs must be positive')
    build(args.qemu_source.resolve(strict=True), args.output.resolve(), args.jobs)


if __name__ == '__main__':
    main()
