"""Build controlled freestanding ELF32/i386 programs with the host compiler."""
from pathlib import Path
import hashlib
import subprocess

from cu_process import save
from ct_elf import CaptureError, sha256, read_elf
from cv_corpus import scale_blob

ROOT = Path(__file__).resolve().parent
TABLE = b''.join(hashlib.sha256(b'taintforge-table' + i.to_bytes(4, 'little')).digest() for i in range(256))
TABLE += bytes(range(256)) * 128


def verify_fixture_layout(elf):
    loads = elf['loads']
    writable = [p for p in loads if p['flags'] == 6]
    if (len(writable) != 1 or any(p['filesz'] == 0 for p in loads)
            or [p['offset'] for p in loads] != sorted(p['offset'] for p in loads)
            or writable[0]['filesz'] < 4
            or elf['data'][writable[0]['offset']:writable[0]['offset']+4] != b'TFCW'):
        raise CaptureError('FIXTURE_LAYOUT_INVALID',
                           'Require ordered file-backed PT_LOAD segments and the TFCW writable anchor')


def checked_commands(commands, directory, log_name, reason):
    log_path = directory / log_name
    try:
        with log_path.open('wb') as log:
            for command in commands:
                subprocess.run(command, cwd=directory, check=True, stdout=log,
                               stderr=subprocess.STDOUT, timeout=60)
    except subprocess.SubprocessError as error:
        tail = log_path.read_text(errors='replace')[-1800:].strip()
        raise CaptureError(reason, f'{error}; log={log_path}; {tail}') from error


def build_original(name, optimization, directory, compiler, image_bytes=0):
    directory.mkdir(parents=True, exist_ok=False)
    directory = directory.resolve()
    (directory / 'table.bin').write_bytes(TABLE)
    assembly = '.section .rodata.fixture,"a"\n.balign 16\n.global fixture_table\nfixture_table:\n.incbin "table.bin"\n'
    if image_bytes:
        (directory / 'blob.bin').write_bytes(scale_blob(image_bytes))
        assembly += '.balign 16\n.global scale_blob\nscale_blob:\n.incbin "blob.bin"\n'
    assembly += '.section .note.GNU-stack,"",@progbits\n'
    (directory / 'data.S').write_text(assembly)
    flags = ['-m32', '-std=c11', f'-{optimization}', '-Wall', '-Wextra', '-Werror',
             '-ffreestanding', '-fno-builtin', '-fno-tree-loop-distribute-patterns', '-fno-pie', '-fno-pic',
             '-fno-stack-protector', '-fno-asynchronous-unwind-tables', '-fno-unwind-tables', '-fcf-protection=none',
             '-I', str(ROOT / 'fixtures'), f'-DFIXTURE_TABLE_MAGIC={int.from_bytes(TABLE[:4], "little")}u',
             f'-DFIXTURE_TABLE_TAIL={TABLE[-1]}u']
    if image_bytes:
        flags.append(f'-DCV_IMAGE_BYTES={image_bytes}')
    objects, commands = [], []
    for source in [ROOT / 'fixtures/start.S', ROOT / 'fixtures/runtime.c', ROOT / f'fixtures/{name}.c', directory / 'data.S']:
        obj = directory / (source.stem + '.o')
        objects.append(obj)
        commands.append([str(compiler), *flags, '-c', str(source), '-o', str(obj)])
    original = directory / 'original.elf'
    commands.append([str(compiler), '-m32', '-nostdlib', '-static', '-no-pie', '-Wl,--build-id=none',
                     '-Wl,-T,' + str(ROOT / 'fixtures/layout.ld'), *map(str, objects), '-o', str(original)])
    checked_commands(commands, directory, 'build.log', 'GUEST_BUILD_FAILED')
    elf = read_elf(original)
    verify_fixture_layout(elf)
    save(directory / 'build.json', dict(name=name, optimization=optimization, compiler=str(compiler),
         commands=commands, original_sha256=sha256(original), original_bytes=original.stat().st_size,
         image_blob_bytes=image_bytes, table_sha256=sha256(directory / 'table.bin'),
         inputs={str(p.relative_to(ROOT)): sha256(p) for p in (ROOT / 'fixtures').iterdir() if p.is_file()},
         entry=hex(elf['entry'])))
    return original


def pack(original, mode, directory, upx):
    original = Path(original).resolve(strict=True)
    directory.mkdir(parents=True, exist_ok=False)
    directory = directory.resolve()
    packed = directory / 'packed.upx'
    command = [str(upx), '-q', '--no-progress', *(['--lzma'] if mode == 'lzma' else []), '-o', str(packed), str(original)]
    checked_commands([command, [str(upx), '-t', str(packed)]], directory, 'pack.log', 'UPX_PACK_FAILED')
    read_elf(packed)
    save(directory / 'pack.json', dict(mode=mode, argv=command, original_sha256=sha256(original),
                                     packed_sha256=sha256(packed), packed_bytes=packed.stat().st_size))
    return packed.resolve()


def preflight(directory, compiler, upx):
    original = build_original('hexcodec', 'O2', directory / 'build', compiler)
    profiles = {}
    for mode in ('default', 'lzma'):
        packed = pack(original, mode, directory / mode, upx)
        profiles[mode] = dict(status='PASS', packed_sha256=sha256(packed),
                              log=str(directory / mode / 'pack.log'))
    return dict(status='PASS', original_sha256=sha256(original), profiles=profiles)
