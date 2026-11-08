"""Build 24 i386 ELF probes and compare their C kernels with Python models."""
import ctypes
import hashlib
import json
import importlib.util
from pathlib import Path
import shutil
import struct
import subprocess

ROOT = Path(__file__).resolve().parent
MASK = 0xffffffff
PROBES = (
    ('hex4', b'1234', 0x1234),
    ('tlv4', bytes([3, 1, 2, 3]), 0x030201),
    ('uleb3', bytes([0xe5, 0x8e, 0x26]), 624485),
    ('fnv8', b'abcdefgh', 0x12345678),
    ('crc8', b'ABC', 0x52),
    ('bitset', bytes([23, 0, 0, 0]), 1),
    ('bswap', bytes.fromhex('78563412'), 0x78563412),
    ('clamp_norm', bytes.fromhex('c409000002'), 666),
)


def model(kind, data):
    if kind == 0:
        if len(data) < 4: return MASK
        value = 0
        for i, c in enumerate(data[:4]):
            if 48 <= c <= 57: digit = c - 48
            elif 97 <= c <= 102: digit = c - 87
            elif 65 <= c <= 70: digit = c - 55
            else: return 0xffff0000 | i
            value = value * 16 + digit
        return value
    if kind == 1:
        if not data or data[0] > 4 or len(data) < data[0] + 1: return MASK
        return int.from_bytes(data[1:1 + data[0]], 'little')
    if kind == 2:
        value = 0
        for i, c in enumerate(data[:4]):
            value |= (c & 127) << (7 * i)
            if not c & 128: return value
        return MASK
    if kind == 3:
        value = 2166136261
        for c in data: value = ((value ^ c) * 16777619) & MASK
        return value
    if kind == 4:
        value = 0
        for c in data:
            value ^= c
            for _ in range(8): value = ((value << 1) ^ (7 if value & 128 else 0)) & 255
        return value
    if kind == 5:
        return ((0x800013 >> (data[0] & 31)) & 1) if data else MASK
    if kind == 6:
        return int.from_bytes(data[:4], 'big') if len(data) >= 4 else MASK
    if kind == 7:
        if len(data) < 5: return MASK
        value = int.from_bytes(data[:4], 'little', signed=True)
        return (max(-1000, min(1000, value)) + 1000) // ((data[4] & 15) + 1)
    raise ValueError('Unknown model')


def elf_view(path):
    data = Path(path).read_bytes()
    if data[:7] != b'\x7fELF\x01\x01\x01' or struct.unpack_from('<HH', data, 16) != (2, 3):
        raise ValueError('Expected fixed-address i386 ELF')
    offset = struct.unpack_from('<I', data, 28)[0]
    size, count = struct.unpack_from('<HH', data, 42)
    if size != 32 or offset + count * size > len(data): raise ValueError('Invalid ELF program headers')
    loads = []
    for i in range(count):
        p = struct.unpack_from('<8I', data, offset + i * size)
        if p[0] in (2, 3): raise ValueError('Dynamic ELF is outside this probe corpus')
        if p[0] == 1: loads.append(p)
    return data, loads


def instruction_bytes(path, address, count):
    data, loads = elf_view(path)
    for p in loads:
        if p[2] <= address and address + count <= p[2] + p[4]:
            start = p[1] + address - p[2]
            if start + count <= len(data): return data[start:start + count]
    raise ValueError('Selected PC is not file backed')


def vectors(seed):
    values = [b'', seed, bytes(16), bytes([255]) * 16]
    for value in range(256):
        values.append(bytes([value]) + seed[1:])
        values.append(seed[:-1] + bytes([value]))
    return values


def build(out, cc='gcc'):
    out = Path(out); out.mkdir(parents=True, exist_ok=False)
    for name in ('kernels.c', 'runtime.S'):
        shutil.copyfile(ROOT / 'corpus' / name, out / name)
    compiler = shutil.which(cc)
    if not compiler: raise ValueError('C compiler is unavailable: ' + cc)
    compiler = str(Path(compiler).resolve())
    commands, rows, comparisons = [], [], 0
    base = ['-std=gnu11', '-g0', '-Wall', '-Wextra', '-Werror', '-fno-builtin', '-fno-stack-protector']
    for optimization in ('O1', 'O2', 'O3'):
        for kind, (name, seed, expected) in enumerate(PROBES):
            tag = name + '-' + optimization
            binary, oracle = out / (tag + '.elf'), out / (tag + '.so')
            host = [compiler, *base, '-' + optimization, '-DTF_KIND=' + str(kind), '-fPIC', '-shared',
                    str(ROOT / 'corpus/kernels.c'), '-o', str(oracle)]
            guest = [compiler, *base, '-' + optimization, '-DTF_KIND=' + str(kind), '-m32', '-march=i686',
                '-mno-sse', '-mno-mmx', '-fno-pic', '-fno-pie', '-ffreestanding', '-nostdlib', '-static',
                '-no-pie', '-fno-asynchronous-unwind-tables', '-fno-unwind-tables',
                '-Wl,--build-id=none,-e,_start', '-Wa,--defsym,TF_COMPARE=' + str(expected),
                str(ROOT / 'corpus/runtime.S'), str(ROOT / 'corpus/kernels.c'), '-o', str(binary)]
            for label, command in (('oracle', host), ('elf', guest)):
                commands.append(command)
                log = out / (tag + '-' + label + '.build.log')
                with log.open('wb') as stream:
                    result = subprocess.run(command, stdout=stream, stderr=subprocess.STDOUT, timeout=120)
                if result.returncode: raise RuntimeError('Compile failed: ' + str(log) + '\n' + log.read_text()[-3000:])
            function = ctypes.CDLL(str(oracle.resolve())).tf_kernel
            function.argtypes = (ctypes.c_void_p, ctypes.c_uint); function.restype = ctypes.c_uint
            tested = 0
            for data in vectors(seed):
                buffer = ctypes.create_string_buffer(data)
                actual = function(buffer, len(data))
                if actual != model(kind, data): raise ValueError('Native/model mismatch: ' + tag + ' ' + data.hex())
                tested += 1
            comparisons += tested
            text = subprocess.check_output(['nm', '-n', '--defined-only', str(binary)], text=True)
            (out / (tag + '.symbols.txt')).write_text(text)
            (out / (tag + '.disassembly.txt')).write_text(
                subprocess.check_output(['objdump', '-d', str(binary)], text=True))
            symbols = {r[2]: int(r[0], 16) for line in text.splitlines() if len(r := line.split()) == 3}
            pc = symbols['tf_probe_jcc']; code = instruction_bytes(binary, pc, 2)
            if code[0] != 0x75: raise ValueError('Probe label is not JNE rel8')
            taken = pc + 2 + int.from_bytes(code[1:], 'little', signed=True)
            if taken != symbols['tf_probe_taken'] or pc + 2 != symbols['tf_probe_fallthrough']:
                raise ValueError('Probe branch/symbol binding differs')
            seed_path = out / (tag + '.seed'); seed_path.write_bytes(seed)
            value = model(kind, seed)
            rows.append({'id': tag, 'kind': kind, 'kernel': name, 'optimization': optimization,
                'binary': str(binary.resolve()), 'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
                'seed': str(seed_path.resolve()), 'seed_sha256': hashlib.sha256(seed).hexdigest(),
                'offsets': list(range(len(seed))), 'pc': pc, 'branch_bytes': code.hex(),
                'expected_value': value, 'compare_value': expected, 'expected_taken': value != expected,
                'expected_successor': taken if value != expected else pc + 2,
                'expected_stdout_hex': (b'T\n' if value != expected else b'F\n').hex(),
                'native_model_comparisons': tested})
    record = {'schema': 1, 'status': 'BUILT_AND_NATIVE_MODELS_MATCH', 'elf_count': len(rows),
              'native_model_comparisons': comparisons, 'cases': rows, 'commands': commands,
              'compiler': subprocess.check_output([compiler, '--version'], text=True).splitlines()[0],
              'compiler_sha256': hashlib.sha256(Path(compiler).read_bytes()).hexdigest(),
              'oracle_scope': 'host C execution versus separate Python models; no i386 guest execution here',
              'scope': 'eight bounded C kernels at O1/O2/O3; one input per generated ELF',
              'source_sha256': {n: hashlib.sha256((ROOT / n).read_bytes()).hexdigest()
                                for n in ('corpus/kernels.c', 'corpus/runtime.S')}}
    (out / 'build.json').write_text(json.dumps(record, indent=2) + '\n')
    return record


def legacy_oracle(out, cases, cc='gcc'):
    out = Path(out); out.mkdir(parents=True, exist_ok=False)
    spec = importlib.util.spec_from_file_location('legacy_target_builder', ROOT / 'legacy-source/build_target.py')
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    source = module.verify_source()
    library = out / 'jsmn-oracle.so'
    command = [cc, '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-fPIC', '-shared',
               str(ROOT / 'legacy-source/oracle.c'), '-o', str(library)]
    with (out / 'build.log').open('wb') as stream:
        subprocess.run(command, check=True, stdout=stream, stderr=subprocess.STDOUT, timeout=120)
    def execute(data): return module.oracle_record(library, data)
    checks = 0
    for row in cases:
        for label in ('seed', 'witness'):
            path = ROOT / row['data']
            if execute((path / label).read_bytes()) != (path / (label + '.stdout')).read_bytes():
                raise ValueError('Archived tokenizer result differs from native oracle: ' + row['id'])
            checks += 1
    record = {'status': 'NATIVE_LEGACY_GOLDENS_MATCH', 'checks': checks, 'upstream': source,
              'command': command, 'scope': 'same pinned tokenizer source; separate host build, not independent semantics'}
    (out / 'validation.json').write_text(json.dumps(record, indent=2) + '\n')
    return execute, record
