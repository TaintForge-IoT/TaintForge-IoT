"""Immutable-self-file private mapping fixtures with source-defined EOF."""
import re
import struct
from pathlib import Path

from run_runtime_dse_audit import digest, require, save


OUTER = 0x08049000
ENTRY_A = 0x08100000
ENTRY_B = 0x08102000
BUFFER = 0x08070000
SOURCE_ALIAS = 0x08200000
PAGE = 4096
FIRST_BLOB_OFFSET = 0x2000
FIXTURE_FILES = ('unpacker/mvp/filemap_fixtures.py',
                 'unpacker/mvp/fixtures/core_filemap_decoder32.S')
CASES = (
    ('mmap2-offset', 2, 192, False, False, False),
    ('old-mmap-offset', 2, 90, False, False, False),
    ('close-before-use', 2, 192, True, False, False),
    ('cow-alias', 2, 192, False, True, False),
    ('eof-tail', 2, 192, True, True, False),
    ('fixed-file-remap', 3, 192, False, True, True),
)


def _symbol(text, name):
    found = re.findall(r'^([0-9a-fA-F]+) [A-Za-z] ' + re.escape(name) + r'$', text, re.M)
    require(len(found) == 1, 'Missing or duplicate file-map fixture symbol: ' + name)
    return int(found[0], 16)


def _packed_elf(text, blobs):
    """No section table: the final blob ends at the actual source-file EOF."""
    require(0 < len(text) < PAGE and blobs and all(0 < len(blob) < 0xe00 for blob in blobs),
            'File-map source geometry exceeds the controlled page profile')
    size = FIRST_BLOB_OFFSET + PAGE * (len(blobs) - 1) + len(blobs[-1])
    result = bytearray(size)
    ident = b'\x7fELF\x01\x01\x01' + bytes(9)
    result[:52] = struct.pack('<16sHHIIIIIHHHHHH', ident, 2, 3, 1, OUTER, 52, 0, 0,
                              52, 32, 3, 0, 0, 0)
    headers = ((1, 0, 0x08048000, 0x08048000, PAGE, PAGE, 4, PAGE),
               (1, PAGE, OUTER, OUTER, len(text), len(text), 5, PAGE),
               (1, 0, BUFFER, BUFFER, 0, PAGE, 6, PAGE))
    for index, row in enumerate(headers):
        struct.pack_into('<IIIIIIII', result, 52 + 32 * index, *row)
    result[PAGE:PAGE + len(text)] = text
    for index, blob in enumerate(blobs):
        start = FIRST_BLOB_OFFSET + PAGE * index
        result[start:start + len(blob)] = blob
    return bytes(result)


def build_fixture(fixtures, directory, case, command):
    fixtures, directory = Path(fixtures), Path(directory)
    name, depth, number, early_close, cow, fixed = case
    require(case in CASES and not directory.exists() and not directory.is_symlink(),
            'Unknown file-map fixture or occupied output')
    directory.mkdir()
    addresses = [OUTER, ENTRY_A, ENTRY_B] + ([ENTRY_A] if depth == 3 else [])
    payload = directory / f'stage{depth}'
    payload.mkdir()
    (payload / 'payload.ld').write_text(
        'ENTRY(_start)\nPHDRS { ro PT_LOAD FILEHDR PHDRS FLAGS(4); '
        'image PT_LOAD FLAGS(5); data PT_LOAD FLAGS(6); }\n'
        'SECTIONS { . = 0x08040000 + SIZEOF_HEADERS; .headers : { BYTE(0); } :ro\n'
        f'. = 0x{addresses[-1]:x}; .text : {{ *(.text) }} :image\n'
        f'. = 0x{BUFFER:x}; .buffer (NOLOAD) : {{ . += 4096; }} :data\n'
        '/DISCARD/ : { *(.note*) *(.comment*) } }\n')
    command(['as', '--32', '--defsym', f'BUFFER_ADDRESS={BUFFER}', '--defsym', 'HELPER_ADDRESS=0',
             fixtures / 'core_multilayer_payload32.S', '-o', payload / 'stage.o'], 'filemap-payload-assemble')
    reference = payload / 'stage.elf'
    command(['ld', '-m', 'elf_i386', '-T', payload / 'payload.ld', payload / 'stage.o',
             '-o', reference], 'filemap-payload-link')
    command(['objcopy', '-O', 'binary', '-j', '.text', reference, payload / 'stage.bin'],
            'filemap-payload-extract')
    reference.chmod(0o700)
    stages = {depth: dict(path=payload / 'stage.bin', entry=addresses[-1])}
    blobs = [None] * depth
    for index in reversed(range(depth)):
        stage = directory / f'stage{index}'
        stage.mkdir()
        raw = stages[index + 1]['path'].read_bytes()
        require(0 < len(raw) < 0xe00, 'File-map decoder exceeds target page')
        key = 0x51 + 3 * index
        encoded = bytes(value ^ key for value in raw)
        blobs[index] = encoded
        (stage / 'next.enc').write_bytes(encoded)
        defines = dict(TARGET_ADDRESS=addresses[index + 1], MMAP_NUMBER=number,
            DEST_FLAGS=0x12 if fixed and index == depth - 1 else 2,
            FILE_OFFSET=FIRST_BLOB_OFFSET + PAGE * index, BUFFER_ADDRESS=BUFFER,
            SOURCE_ALIAS=SOURCE_ALIAS, CHILD_SIZE=len(raw), XOR_KEY=key,
            ENCODED_FIRST=encoded[0], CLOSE_BEFORE_USE=int(early_close), COW_TAIL_WRITE=int(cow),
            CHECK_FD_REUSE=int(index > 0))
        args = ['as', '--32']
        for key_name, value in defines.items():
            args += ['--defsym', f'{key_name}={value}']
        command([*args, fixtures / 'core_filemap_decoder32.S', '-o', stage / 'stage.o'],
                'filemap-decoder-assemble')
        binary = stage / 'stage.elf'
        command(['ld', '-m', 'elf_i386', '-Ttext', hex(addresses[index]), '-e', '_start',
                 stage / 'stage.o', '-o', binary], 'filemap-decoder-link')
        command(['objcopy', '-O', 'binary', '-j', '.text', binary, stage / 'stage.bin'],
                'filemap-decoder-extract')
        symbols = command(['nm', '-n', binary], 'filemap-decoder-symbols').stdout.decode()
        require(_symbol(symbols, '_start') == addresses[index], 'File-map decoder entry differs')
        stages[index] = dict(path=stage / 'stage.bin', entry=addresses[index],
            transfer=_symbol(symbols, 'transfer'), eof_check=_symbol(symbols, 'eof_check'),
            cow_check=_symbol(symbols, 'cow_check'))
    packed = directory / 'packed.elf'
    packed.write_bytes(_packed_elf(stages[0]['path'].read_bytes(), blobs))
    packed.chmod(0o700)
    catalogue = [dict(index=index, entry=addresses[index], size=stages[index]['path'].stat().st_size,
        sha256=digest(stages[index]['path']), cleartext_file=str(stages[index]['path'].relative_to(directory)),
        predecessor=stages[index - 1]['transfer'] if index else 0, dynamic_mapping=index > 0,
        expected_mapping_epoch=4 * (index - 1) + 2 if index else 0,
        expected_descriptor_epoch=4 * (index - 1) + 1 if index else 0,
        expected_file_offset=FIRST_BLOB_OFFSET + PAGE * (index - 1) if index else 0,
        reused_address=index == 3) for index in range(depth + 1)]
    (directory / 'entries.txt').write_text(''.join(
        f"{row['entry']:x} {row['size']} {row['predecessor']:x}\n" for row in catalogue))
    save(directory / 'fixture.json', dict(name=name, decoding_layers=depth, payload_entry=addresses[-1],
        stage_catalogue=catalogue, mmap_syscall=number, close_before_source_read=early_close,
        private_alias_tail_write=cow, fixed_replacement=fixed, source_file_size=packed.stat().st_size,
        source_offsets=[FIRST_BLOB_OFFSET + PAGE * i for i in range(depth)],
        consumed_file_zero_offset=0xf00, source_alias=SOURCE_ALIAS,
        actual_file_EOF_without_section_table=True, source_file_immutable=True,
        closed_descriptor_number_reuse_checked=depth >= 2,
        runtime_return_used_as_copy_and_transfer_pointer=True, controlled_nonfixed_hint_guard=True,
        reference_payload_built_before_packing=True, packing='controlled_private_self_file_XOR_decoders',
        file_mapping_profile_version=4, observed_image_used_as_source=False,
        original_reference_used_by_proof=False, behavior_or_SMT_validation_performed_by_builder=False))
    return catalogue, reference


def build_past_eof_fault(directory, command):
    """A valid mapping whose first accessed byte is in a page beyond EOF."""
    directory = Path(directory)
    require(not directory.exists() and not directory.is_symlink(), 'Occupied EOF control output')
    directory.mkdir()
    source = directory / 'fault.S'
    source.write_text('''.code32
.section .text
.globl _start
_start:
 mov $path, %ebx
 mov $0, %ecx
 mov $0, %edx
 mov $5, %eax
 int $0x80
 mov %eax, %edi
 mov $0x08300000, %ebx
 mov $4096, %ecx
 mov $1, %edx
 mov $2, %esi
 mov $3, %ebp
 mov $192, %eax
 int $0x80
 cmp $0x08300000, %eax
 jne failed
 mov (%eax), %eax
failed:
 mov $1, %eax
 mov $103, %ebx
 int $0x80
path: .asciz "/proc/self/exe"
''')
    command(['as', '--32', source, '-o', directory / 'fault.o'], 'eof-control-assemble')
    command(['ld', '-m', 'elf_i386', '-Ttext', hex(OUTER), '-e', '_start',
             directory / 'fault.o', '-o', directory / 'fault-linked.elf'], 'eof-control-link')
    command(['objcopy', '-O', 'binary', '-j', '.text', directory / 'fault-linked.elf',
             directory / 'fault.bin'], 'eof-control-extract')
    binary = directory / 'fault.elf'
    binary.write_bytes(_packed_elf((directory / 'fault.bin').read_bytes(), [bytes(16)]))
    binary.chmod(0o700)
    require(binary.stat().st_size == 0x2010, 'EOF fault source-file size changed')
    return binary
