"""Build 36 C-only i386 ELFs and two deterministic seed scenarios per ELF."""
import ctypes
import hashlib
from pathlib import Path
import shutil
import subprocess

from controls import elf_view, instruction_bytes
from support import require, save

ROOT = Path(__file__).resolve().parent
MASK = 0xffffffff
MASK64 = (1 << 64) - 1


def signed(value):
    return value if value < 1 << 31 else value - (1 << 32)


def trunc_div(value, divisor):
    q = abs(value) // abs(divisor)
    return -q if (value < 0) != (divisor < 0) else q


def model(kind, data):
    minimum = (5, 5, 6, 5, 5, 4, 4, 16, 16, 16, 5, 9)[kind]
    if len(data) < minimum: return MASK
    value = int.from_bytes(data[:4], 'little')
    if kind in (0, 1):
        value = max(-1000000, min(1000000, signed(value)))
        divisor = (data[4] & 15) + 1
        if data[4] & 128: divisor = -divisor
        quotient = trunc_div(value, divisor)
        return (quotient if kind == 0 else value - quotient * divisor) & MASK
    if kind == 2: return value % (int.from_bytes(data[4:6], 'little') | 1)
    if kind in (3, 4):
        count = data[4] % 32
        bits = f'{value:032b}'
        if not count: return value
        rotated = bits[count:] + bits[:count] if kind == 3 else bits[-count:] + bits[:-count]
        return int(rotated, 2)
    if kind == 5: return 32 - (value | 1).bit_length()
    if kind == 6:
        value |= 1 << 16
        return next(i for i in range(32) if value & (1 << i))
    if kind in (7, 8):
        a, b = int.from_bytes(data[:8], 'little'), int.from_bytes(data[8:16], 'little')
        result = (a + b if kind == 7 else a * b) & MASK64
        return ((result & MASK) ^ (result >> 32)) & MASK
    if kind == 9:
        return next(((a - b) & MASK for a, b in zip(data[:8], data[8:16]) if a != b), 0)
    if kind == 10:
        table = (0x13, 0x87, 0x55555555, 0xabcdef01, 0, 0x80000000, 0x10203, 0xdeadbeef)
        return table[data[0] % 8] ^ int.from_bytes(data[1:5], 'little')
    if kind == 11: return (int.from_bytes(data[:8], 'little') // (1 << (data[8] % 64))) & MASK
    raise ValueError('Unknown kernel')


def i32(value): return (value & MASK).to_bytes(4, 'little')
def i64(value): return (value & MASK64).to_bytes(8, 'little')


PROBES = (
    ('sdiv32', (i32(-12345) + b'\x06', i32(12345) + b'\x82')),
    ('smod32', (i32(-8) + b'\x02', i32(8) + b'\x82')),
    ('urem32', (i32(0x12345678) + b'\x10\x00', i32(MASK) + b'\xff\xff')),
    ('rol32', (bytes.fromhex('7856341200'), bytes.fromhex('7856341207'))),
    ('ror32', (bytes.fromhex('7856341200'), bytes.fromhex('785634121f'))),
    ('clz32', (i32(1), i32(0x80000000))),
    ('ctz32', (i32(0), i32(4))),
    ('add64_fold', (i64(MASK) + i64(1), i64(MASK64) + i64(1))),
    ('mul64_fold', (i64(MASK) + i64(0x100000001), i64(0x123456789abcdef0) + i64(0xfedcba9876543210))),
    ('memcmp8', (b'abcdefghabcdefgh', b'abcdefghabcdEfgh')),
    ('lookup8', (b'\x00' + i32(0), b'\x07' + i32(0x11223344))),
    ('window64', (bytes.fromhex('010203040506070800'), bytes.fromhex('010203040506070824'))),
)


def vectors(seeds):
    values = list(seeds) + [bytes(n) for n in range(17)] + [b'\xff' * 16]
    edges = (0, 1, 2, 7, 15, 16, 31, 32, 63, 64, 127, 128, 129, 254, 255)
    for seed in seeds:
        for position in range(len(seed)):
            for value in edges:
                values.append(seed[:position] + bytes([value]) + seed[position + 1:])
        for value in range(256):
            values.append(bytes([value]) + seed[1:])
            values.append(seed[:-1] + bytes([value]))
    return list(dict.fromkeys(values))


def execute(command, log):
    with log.open('wb') as stream:
        completed = subprocess.run(command, stdout=stream, stderr=subprocess.STDOUT, timeout=120)
    require(completed.returncode == 0, 'Compile failed: ' + str(log) + '\n' + log.read_text(errors='replace')[-3000:])


def build(out, cc='gcc', sanitize_oracles=False):
    out = Path(out); out.mkdir(parents=True, exist_ok=False)
    compiler = shutil.which(cc); require(compiler is not None, 'C compiler is unavailable')
    compiler = str(Path(compiler).resolve())
    for name in ('kernels.c', 'runtime.S'): shutil.copyfile(ROOT / 'corpus' / name, out / name)
    base = ['-std=gnu11', '-g0', '-Wall', '-Wextra', '-Werror', '-fno-builtin', '-fno-stack-protector']
    rows, commands, binaries = [], [], []
    comparisons = 0
    for opt in ('O1', 'O2', 'O3'):
        for kind, (name, seeds) in enumerate(PROBES):
            tag = name + '-' + opt; binary = out / (tag + '.elf'); library = out / (tag + '.so')
            expected = model(kind, seeds[0]); require(expected != model(kind, seeds[1]), 'Seed scenarios do not exercise distinct outputs')
            host = [compiler, *base, '-' + opt, '-DTF_KIND=' + str(kind), '-fPIC', '-shared',
                    *(['-fsanitize=undefined', '-fno-sanitize-recover=all'] if sanitize_oracles else []),
                    str(ROOT / 'corpus/kernels.c'), '-o', str(library)]
            guest = [compiler, *base, '-' + opt, '-DTF_KIND=' + str(kind), '-m32', '-march=i686',
                '-mno-sse', '-mno-mmx', '-fno-pic', '-fno-pie', '-ffreestanding', '-nostdlib', '-static',
                '-no-pie', '-fno-asynchronous-unwind-tables', '-fno-unwind-tables',
                '-Wl,--build-id=none,-e,_start', '-Wa,--defsym,TF_COMPARE=' + str(expected),
                str(ROOT / 'corpus/runtime.S'), str(ROOT / 'corpus/kernels.c'), '-o', str(binary)]
            for label, command in [('oracle', host), ('elf', guest)]:
                commands.append(command); execute(command, out / (tag + '-' + label + '.build.log'))
            function = ctypes.CDLL(str(library.resolve())).tf_kernel
            function.argtypes = (ctypes.c_void_p, ctypes.c_uint); function.restype = ctypes.c_uint
            samples = vectors(seeds)
            for data in samples:
                actual = function(ctypes.create_string_buffer(data), len(data))
                require(actual == model(kind, data), 'Native C/Python model mismatch: ' + tag + ' ' + data.hex())
            comparisons += len(samples)
            symbols_text = subprocess.check_output(['nm', '-n', '--defined-only', str(binary)], text=True)
            (out / (tag + '.symbols.txt')).write_text(symbols_text)
            text = subprocess.check_output(['objdump', '-d', '--insn-width=15', str(binary)], text=True)
            (out / (tag + '.disassembly.txt')).write_text(text)
            symbols = {r[2]: int(r[0], 16) for line in symbols_text.splitlines() if len(r := line.split()) == 3}
            pc = symbols['tf_probe_jcc']; code = instruction_bytes(binary, pc, 2)
            require(code[0] == 0x75 and pc + 2 == symbols['tf_probe_fallthrough'], 'Selected branch is not JNE rel8')
            target = pc + 2 + int.from_bytes(code[1:], 'little', signed=True)
            require(target == symbols['tf_probe_taken'], 'Selected branch target differs')
            elf_view(binary); binary_sha = hashlib.sha256(binary.read_bytes()).hexdigest()
            binaries.append({'id': tag, 'kernel': name, 'optimization': opt, 'sha256': binary_sha,
                             'model_comparisons': len(samples), 'scope': 'static compiler output; no execution evidence'})
            for scenario, seed in zip(('a', 'b'), seeds):
                case = tag + '-' + scenario; seed_path = out / (case + '.seed'); seed_path.write_bytes(seed)
                value = model(kind, seed); taken = value != expected
                rows.append({'id': case, 'kind': kind, 'kernel': name, 'optimization': opt, 'scenario': scenario,
                    'binary': str(binary.resolve()), 'binary_sha256': binary_sha, 'seed': str(seed_path.resolve()),
                    'seed_sha256': hashlib.sha256(seed).hexdigest(), 'offsets': list(range(len(seed))),
                    'pc': pc, 'branch_bytes': code.hex(), 'expected_value': value, 'compare_value': expected,
                    'expected_taken': taken, 'expected_successor': target if taken else pc + 2,
                    'expected_stdout_hex': ((b'T\n' if taken else b'F\n') + value.to_bytes(4, 'little')).hex()})
    record = {'status': 'BUILT_NATIVE_MODELS_MATCH', 'elf_count': len(binaries), 'observation_count': len(rows),
        'native_model_comparisons': comparisons, 'cases': rows, 'binaries': binaries, 'commands': commands,
        'compiler': subprocess.check_output([compiler, '--version'], text=True).splitlines()[0],
        'compiler_sha256': hashlib.sha256(Path(compiler).read_bytes()).hexdigest(),
        'oracle_undefined_sanitizer': sanitize_oracles,
        'source_sha256': {n: hashlib.sha256((ROOT / 'corpus' / n).read_bytes()).hexdigest() for n in ('kernels.c', 'runtime.S')},
        'scope': 'host C/Python comparisons and i386 ELF builds; no QEMU guest execution'}
    save(out / 'build.json', record); return record
