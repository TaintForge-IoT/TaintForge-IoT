"""Build an unchanged pinned jsmn tokenizer in explicit bounded file adapters."""
from __future__ import annotations

import ctypes
import hashlib
import json
from pathlib import Path
import shutil
import struct
import subprocess

ROOT = Path(__file__).resolve().parent
RECORD_BYTES = 544
SEEDS = {'string': b'"x"', 'unicode': b'"\\u0041"', 'array': b'[0,1]'}
PIN = 'fdcef3ebf886fa210d14956d3c068a653e76a24e'


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def verify_source():
    source = json.loads((ROOT / 'source.json').read_text())
    if source.get('commit') != PIN or source.get('upstream_source_unmodified') is not True:
        raise ValueError('Unrecognized upstream source pin')
    for name, expected in source['files'].items():
        if name not in ('jsmn.h', 'LICENSE') or digest(ROOT / name) != expected:
            raise ValueError('Pinned upstream source changed: ' + name)
    if set(source['files']) != {'jsmn.h', 'LICENSE'}:
        raise ValueError('Incomplete upstream source inventory')
    return source


def decode_record(raw):
    if not isinstance(raw, bytes) or len(raw) != RECORD_BYTES:
        raise ValueError('Expected exact bounded binary tokenizer record')
    fields = struct.unpack('<IIIiIIiI', raw[:32])
    if fields[0] != 0x314d534a or fields[1] != 1 or fields[7] != 32:
        raise ValueError('Unsupported tokenizer record header')
    if not 0 <= fields[2] <= 4096 or not 0 <= fields[5] <= 32:
        raise ValueError('Tokenizer record exceeds input or token budget')
    return dict(version=fields[1], input_size=fields[2], result=fields[3],
                parser_pos=fields[4], token_count=fields[5], token_super=fields[6],
                token_capacity=fields[7], tokens=[dict(zip(('type', 'start', 'end', 'size'),
                struct.unpack('<iiii', raw[32 + i * 16:48 + i * 16]))) for i in range(32)])


def oracle_record(library, data):
    if not isinstance(data, bytes) or len(data) > 4096:
        raise ValueError('Invalid bounded tokenizer input')
    function = ctypes.CDLL(str(Path(library).resolve())).tf_jsmn_oracle
    function.argtypes = (ctypes.c_void_p, ctypes.c_uint, ctypes.c_void_p)
    function.restype = ctypes.c_int
    source = ctypes.create_string_buffer(data)
    output = ctypes.create_string_buffer(RECORD_BYTES)
    if function(source, len(data), output) != 0:
        raise ValueError('Native tokenizer oracle rejected bounded transport')
    return output.raw


def build(out, cc='gcc', host_cc='gcc'):
    source = verify_source()
    out = Path(out).absolute()
    if out.exists():
        raise ValueError('Build output must be new')
    out.mkdir(parents=True)
    compiler = shutil.which(cc)
    host_compiler = shutil.which(host_cc)
    nm = shutil.which('nm')
    objdump = shutil.which('objdump')
    if not all((compiler, host_compiler, nm, objdump)):
        raise ValueError('gcc, native host C compiler and binutils are required')
    binary, oracle = out / 'jsmn-file.elf', out / 'jsmn-oracle.so'
    flags = ['-std=c11', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
        '-fno-inline', '-fno-jump-tables', '-fno-tree-switch-conversion', '-fno-if-conversion', '-fno-ipa-icf',
        '-fno-tree-loop-distribute-patterns', '-I', str(ROOT)]
    commands = [
        [compiler, *flags, '-m32', '-ffreestanding', '-fno-builtin', '-fno-pic',
         '-fno-pie', '-fno-stack-protector', '-fno-asynchronous-unwind-tables',
         '-fno-unwind-tables', '-nostdlib', '-static', '-no-pie',
         '-Wl,--build-id=none,-e,_start', str(ROOT / 'start.S'), str(ROOT / 'target.c'),
         '-o', str(binary)],
        [host_compiler, *flags, '-fPIC', '-shared', str(ROOT / 'oracle.c'), '-o', str(oracle)],
    ]
    log = out / 'build.log'
    with log.open('wb') as stream:
        for command in commands:
            subprocess.run(command, stdout=stream, stderr=subprocess.STDOUT, check=True)
    elf = binary.read_bytes()
    if elf[:7] != b'\x7fELF\x01\x01\x01' or struct.unpack('<HH', elf[16:20]) != (2, 3):
        raise ValueError('Target is not static non-PIE little-endian i386 ELF')
    phoff = struct.unpack('<I', elf[28:32])[0]
    phsize, phnum = struct.unpack('<HH', elf[42:46])
    if phsize != 32 or any(struct.unpack('<I', elf[phoff + i*32:phoff + i*32+4])[0]
                           in (2, 3) for i in range(phnum)):
        raise ValueError('Target unexpectedly requires a dynamic loader')
    symbols = subprocess.check_output([nm, '-n', '-S', '--defined-only', str(binary)], text=True)
    (out / 'symbols.txt').write_text(symbols)
    ranges = []
    for line in symbols.splitlines():
        row = line.split()
        if len(row) == 4 and row[2] in ('t', 'T'):
            start, size = int(row[0], 16), int(row[1], 16)
            ranges.append(dict(name=row[3], start=start, end=start + size,
                               upstream_parser=row[3].startswith('jsmn_')))
    if len([row for row in ranges if row['upstream_parser']]) < 5:
        raise ValueError('Compiler omitted expected separately identified upstream parser functions')
    with (out / 'disassembly.txt').open('wb') as stream:
        subprocess.run([objdump, '-d', '-l', str(binary)], stdout=stream, check=True)
    seed_dir = out / 'seeds'
    seed_dir.mkdir()
    checks = []
    for name, data in SEEDS.items():
        (seed_dir / name).write_bytes(data)
        raw = oracle_record(oracle, data)
        record = decode_record(raw)
        expected = {'string': (1, 3), 'unicode': (1, 3), 'array': (3, 2)}[name]
        if (record['result'], record['tokens'][0]['type']) != expected:
            raise ValueError('Known upstream tokenizer seed outcome changed: ' + name)
        checks.append(dict(id=name, input_hex=data.hex(), sha256=hashlib.sha256(data).hexdigest(),
                           result=record['result'], token_count=record['token_count'],
                           oracle_record_sha256=hashlib.sha256(raw).hexdigest()))
    files = ('jsmn.h', 'LICENSE', 'source.json', 'record.h', 'target.c', 'start.S', 'oracle.c', 'build_target.py')
    manifest = dict(schema=1, status='BUILT_PINNED_UPSTREAM_JSMN_ADAPTERS', upstream=source,
        scope='unchanged_upstream_tokenizer_with_bounded_file_input_harness',
        input_path='/etc/dta-input', max_input_bytes=4096, token_capacity=32,
        binary=str(binary), oracle=str(oracle), commands=commands,
        binary_sha256=digest(binary), oracle_sha256=digest(oracle),
        source_sha256={name: digest(ROOT/name) for name in files},
        tools={name: dict(path=str(Path(path).resolve()), sha256=digest(Path(path).resolve()))
               for name, path in [('cc', compiler), ('host_cc', host_compiler), ('nm', nm), ('objdump', objdump)]},
        function_ranges=ranges, seeds=checks,
        oracle_scope='same_upstream_source_separate_native_build_not_independent_semantics',
        guest_execution_performed=False)
    (out / 'manifest.json').write_text(json.dumps(manifest, indent=2)+'\n')
    return manifest


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--cc', default='gcc')
    parser.add_argument('--host-cc', default='gcc')
    args = parser.parse_args()
    print(json.dumps(build(args.out, cc=args.cc, host_cc=args.host_cc), indent=2))
