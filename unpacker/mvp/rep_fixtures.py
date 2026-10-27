"""Source-built static i386 REP fixtures with independent byte/state oracles.

The original file initializes both buffers.  Expected values are conclusions
for tests, never captured state or proof premises.  The selected target is a
computed JMP to a distinct executable page before the first syscall.
"""
from pathlib import Path
import struct

from filemap_fixtures import _symbol
from run_runtime_dse_audit import digest, require, save

ENTRY = 0x08049000
TARGET = 0x0804a000
SOURCE = 0x0804c000
DESTINATION = 0x0804d000
PAGE = 4096
GUARD = 32
ACCUMULATOR = 0x9a5c317e
FIXTURE_FILES = ('unpacker/mvp/rep_fixtures.py',
                 'unpacker/mvp/fixtures/core_rep32.S')
# name, operation, element byte width, initial ECX, initial DF
CASES = tuple((f'{operation}-{width}-n{count}-df{backward}', operation, width, count, backward)
    for operation in ('movs', 'stos')
    for width in (1, 2, 4)
    for count in (0, 1, 2, 308)
    for backward in (0, 1))


def source_bytes():
    return bytes((37 * index + 11) & 255 for index in range(PAGE))


def destination_bytes():
    return bytes((13 * index + 7) & 255 for index in range(PAGE))


def expected(case):
    """Compute every visible byte and final pointer from the fixture definition."""
    require(case in CASES, 'Unknown REP fixture')
    _, operation, width, count, backward = case
    offset = GUARD + ((count - 1) * width if backward and count else 0)
    stride = -width if backward else width
    result = bytearray(destination_bytes())
    source = source_bytes()
    value = ACCUMULATOR.to_bytes(4, 'little')[:width]
    for index in range(count):
        position = offset + index * stride
        require(GUARD <= position and position + width <= PAGE - GUARD,
                'REP fixture exceeds guarded page')
        result[position:position+width] = source[position:position+width] if operation == 'movs' else value
    source_start, destination_start = SOURCE + offset, DESTINATION + offset
    source_final = source_start + count * stride if operation == 'movs' else source_start
    destination_final = destination_start + count * stride
    registers = dict(ecx=0, esi=source_final, edi=destination_final)
    output = bytes(result) + struct.pack('<III', 0, source_final, destination_final)
    return dict(source_start=source_start, destination_start=destination_start,
                registers=registers, destination=bytes(result), stdout=output)


def build_fixture(fixtures, directory, case, command):
    fixtures, directory = Path(fixtures), Path(directory)
    require(case in CASES and not directory.exists() and not directory.is_symlink(),
            'Unknown REP fixture or occupied output')
    directory.mkdir()
    name, operation, width, count, backward = case
    wanted = expected(case)
    (directory / 'source.bin').write_bytes(source_bytes())
    (directory / 'destination.bin').write_bytes(destination_bytes())
    (directory / 'expected-stdout.bin').write_bytes(wanted['stdout'])
    linker = directory / 'fixture.ld'
    linker.write_text(
        'ENTRY(_start)\n'
        'PHDRS { headers PT_LOAD FILEHDR PHDRS FLAGS(4); '
        'code PT_LOAD FLAGS(5); data PT_LOAD FLAGS(6); }\n'
        'SECTIONS { . = 0x08048000 + SIZEOF_HEADERS; .headers : { BYTE(0); } :headers\n'
        f'. = 0x{ENTRY:x}; .text : {{ *(.text) }} :code\n'
        f'. = 0x{TARGET:x}; .payload : {{ *(.payload) }} :code\n'
        f'. = 0x{SOURCE:x}; .testdata : {{ *(.testdata) }} :data\n'
        '/DISCARD/ : { *(.note*) *(.comment*) } }\n')
    defines = dict(SOURCE_START=wanted['source_start'],
        DESTINATION_START=wanted['destination_start'], REPEAT_COUNT=count,
        BACKWARD=backward, STORE_KIND=int(operation == 'stos'), ELEMENT_BYTES=width)
    args = ['as', '--32']
    for key, value in defines.items():
        args += ['--defsym', f'{key}={value}']
    command([*args, fixtures / 'core_rep32.S', '-o', directory / 'fixture.o'],
            'rep-assemble', cwd=directory)
    elf = directory / 'fixture.elf'
    command(['ld', '-m', 'elf_i386', '-T', linker, directory / 'fixture.o', '-o', elf],
            'rep-link', cwd=directory)
    command(['objcopy', '-O', 'binary', '-j', '.text', elf, directory / 'text.bin'],
            'rep-text', cwd=directory)
    symbols = command(['nm', '-n', elf], 'rep-symbols', cwd=directory).stdout.decode()
    require(_symbol(symbols, '_start') == ENTRY and _symbol(symbols, 'payload') == TARGET and
            _symbol(symbols, 'source_buffer') == SOURCE and
            _symbol(symbols, 'destination_buffer') == DESTINATION,
            'REP fixture linker geometry differs')
    elf.chmod(0o700)
    record = dict(name=name, operation=operation, element_bytes=width,
        initial_count=count, initial_DF=backward,
        source_start=wanted['source_start'], destination_start=wanted['destination_start'],
        expected_post_REP_registers=wanted['registers'], packed_entry=ENTRY, target=TARGET,
        rep_pc=_symbol(symbols, 'rep_instruction'), after_rep_pc=_symbol(symbols, 'after_rep'),
        transfer_pc=_symbol(symbols, 'transfer'), fixture_elf='fixture.elf',
        fixture_elf_sha256=digest(elf), expected_stdout='expected-stdout.bin',
        expected_stdout_sha256=digest(directory / 'expected-stdout.bin'),
        goal_start=TARGET, goal_size=PAGE,
        source_buffer=SOURCE, destination_buffer=DESTINATION, buffer_size=PAGE,
        syscalls_before_selected_transfer=0, original_file_initializes_buffers=True,
        observed_snapshot_used_as_source=False, oracle_used_as_proof_premise=False,
        SMT_proof_performed_by_builder=False, address_size_bits=32)
    save(directory / 'fixture.json', record)
    return record
