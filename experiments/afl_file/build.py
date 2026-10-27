"""Build a benign guest, bridge, and independent coverage test plugin."""
from pathlib import Path
import shlex

from experiments.execution_capsule_probe import controller as p
from taintforge_env.input_retirement import inspect_input
from taintforge_env import afl_file as f

HERE = Path(__file__).resolve().parent


def guest(directory, *, loops=20000000, constant=False):
    directory = Path(directory).resolve()
    directory.mkdir(parents=True, exist_ok=False)
    obj, binary = directory/'guest.o', directory/'guest-i386'
    p.command('as', '--32', '--defsym', 'WORK_LOOPS='+str(loops), '--defsym',
              'CONSTANT_PATH='+str(int(constant)), HERE/'guest.S', '-o', obj)
    p.command('ld', '-m', 'elf_i386', '-z', 'noexecstack', '--build-id=none', obj, '-o', binary)
    p.command('strip', '--strip-all', binary)
    inspect_input(binary)
    return binary


def components(directory):
    directory = Path(directory).resolve()
    built = f.build(directory)
    flags = shlex.split(p.command('pkg-config', '--cflags', '--libs', 'glib-2.0'))
    probe = directory/'libcoverage_probe.so'
    p.command('cc', '-std=c11', '-O2', '-g', '-Wall', '-Wextra', '-Werror', '-Wshadow',
              '-fPIC', '-fvisibility=hidden', '-shared', '-I', p.HERE/'vendor',
              HERE/'coverage_probe.c', '-o', probe, *flags)
    built.update(probe=str(probe), guest=str(guest(directory/'fixture', loops=1000)),
                 constant_guest=str(guest(directory/'constant', loops=1000, constant=True)))
    return built
