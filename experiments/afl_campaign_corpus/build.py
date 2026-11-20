"""Build the corpus and calculate results independently of guest execution."""
from pathlib import Path
from experiments.execution_capsule_probe import controller as p
from taintforge_env.input_retirement import inspect_input

HERE = Path(__file__).resolve().parent
TARGETS = ('prefix', 'record', 'slow-prefix')
ALL_TARGETS = (*TARGETS, 'fault-prefix')
FAULTS = {b'C': ('guest_crash', None, 4), b'S': ('guest_crash', None, 11),
          b'B': ('guest_crash', None, 6), b'H': ('timeout', None, None), b'E': ('normal', 86, None)}


def build(directory, target, *, leak_fd=False):
    if target not in ALL_TARGETS or type(leak_fd) is not bool:
        raise ValueError('Unknown corpus target')
    root = Path(directory).resolve()
    root.mkdir(parents=True, exist_ok=False)
    source, obj, binary = root/'guest-source.S', root/'guest.o', root/'guest-i386'
    source.write_bytes((HERE/'guest.S').read_bytes())
    p.command('as', '--32', '--defsym', 'RECORD_PARSER='+str(int(target == 'record')),
              '--defsym', 'PREP_LOOPS='+str(20000 if target == 'slow-prefix' else 0),
              '--defsym', 'ENABLE_FAULTS='+str(int(target == 'fault-prefix')),
              '--defsym', 'LEAK_FD='+str(int(leak_fd)), source, '-o', obj)
    p.command('ld', '-m', 'elf_i386', '-z', 'noexecstack', '--build-id=none', obj, '-o', binary)
    p.command('strip', '--strip-all', binary)
    inspect_input(binary)
    return binary


def expected(target, data):
    if target not in ALL_TARGETS or not isinstance(data, bytes) or not 1 <= len(data) <= 4096:
        raise ValueError('Invalid corpus oracle input')
    if target == 'fault-prefix' and data[:1] in FAULTS:
        return FAULTS[data[:1]]
    if target != 'record':
        count = 0
        for actual, wanted in zip(data, b'AFL!'):
            if actual != wanted:
                break
            count += 1
        return 'normal', count, None
    if len(data) < 2:
        code = 20
    elif data[1]+2 != len(data):
        code = 21
    elif data[0] == 1:
        code = 32+(sum(data[2:]) & 15)
    elif data[0] == 2:
        code = 49 if data[2:3] == b'X' else 48
    else:
        code = 22
    return 'normal', code, None


def seeds(target):
    if target not in ALL_TARGETS:
        raise ValueError('Unknown corpus target')
    if target == 'record':
        return (b'\x01\x00', b'\x01\x03ABC', b'\x02\x01X', b'\x02\x01Y', b'\x03\x00', b'\x01', b'\x01\x02A')
    return (b'A', b'AF', b'AFL', b'AFL!', b'Z')


def check_sequence(target):
    values = seeds(target)
    result = [values[0], *values, values[0]]
    # Retain one redundant crashing input so replay exercises real reduction.
    for data in ((b'C'+b'x'*88, b'S', b'B', b'H', b'E') if target == 'fault-prefix' else reversed(values)):
        result.extend((data, values[0]))
    return tuple(result)
