"""Static i386 programs packed with UPX; no guest capture helper or OEP hint."""
from pathlib import Path
import base64
import hashlib
import subprocess

ROOT = Path(__file__).resolve().parent
SEEDS = [b'', b'T', b'TF', b'TF2', b'TF22', b'TF\0d', b'TF\x07]',
         b'TF\xff\x01', b'TF22extra', b'XX22', b'CFG:0', b'CFG:9', b'CFG:5\n',
         b'CFG:a', b'CFG:', b'CFG:10', b'cfg:5', b'\0\xff\x01\x02',
         bytes(range(64)), b'A' * 65]
NAMES = ('stdin-echo', 'file-config', 'stateful-parser')


def cases(variant):
    return [dict(id=f'input-{i:02d}', stdin_base64='' if variant == 1 else base64.b64encode(raw).decode(),
                 argv=[], files={'input.bin': base64.b64encode(raw).decode()} if variant == 1 else {})
            for i, raw in enumerate(SEEDS)]


def expected(variant, raw):
    raw = raw[:64]
    if variant == 0:
        return 0, raw
    if len(raw) < (5 if variant == 1 else 4):
        return 2, b'SHORT\n'
    valid = (raw[:4] == b'CFG:' and 48 <= raw[4] <= 57 if variant == 1
             else raw[:2] == b'TF' and sum(raw[2:4]) == 100)
    return (0, b'ACCEPT\n') if valid else (1, b'REJECT\n')


def build(variant, directory, upx):
    directory.mkdir(parents=True, exist_ok=False)
    directory = directory.resolve()
    table = b''.join(hashlib.sha256(b'taintforge-table' + i.to_bytes(4, 'little')).digest() for i in range(256))
    (directory / 'table.bin').write_bytes(table)
    obj, original, packed = (directory / name for name in ('program.o', 'original.elf', 'packed.upx'))
    commands = [
        ['as', '--32', '--defsym', f'VARIANT={variant}', '--defsym', f'TABLE_MAGIC={int.from_bytes(table[:4], "little")}',
         str(ROOT / 'tests/program.S'), '-o', str(obj)],
        ['ld', '-m', 'elf_i386', '-T', str(ROOT / 'tests/program.ld'), str(obj), '-o', str(original)],
        [str(upx), '-q', '--no-progress', '-o', str(packed), str(original)]]
    with (directory / 'build.log').open('wb') as log:
        for command in commands:
            subprocess.run(command, cwd=directory, check=True, stdout=log, stderr=subprocess.STDOUT)
    return original.resolve(), packed.resolve()
