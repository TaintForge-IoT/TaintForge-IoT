"""Rebuild a bounded static ELF32 image from a checked phase-1 capture."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import struct
import tempfile

PAGE = 4096
MAX_BYTES = 256 * 1024 * 1024
MAX_REGIONS = 4096
ELF_HEADER = struct.Struct('<16sHHIIIIIHHHHHH')
PROGRAM_HEADER = struct.Struct('<IIIIIIII')
PT_LOAD, PT_DYNAMIC, PT_INTERP, PT_PHDR, PT_TLS = 1, 2, 3, 6, 7
PT_GNU_STACK = 0x6474E551


class CaptureError(ValueError):
    def __init__(self, reason, detail):
        self.reason = reason
        super().__init__(detail)


def sha256(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def integer(value, name):
    if type(value) is int:
        return value
    if isinstance(value, str):
        try:
            return int(value, 16 if value.startswith('0x') else 10)
        except ValueError:
            pass
    raise CaptureError('INVALID_CAPTURE', f'{name}: expected an integer')


def read_elf(path):
    path = Path(path)
    if not ELF_HEADER.size <= path.stat().st_size <= MAX_BYTES:
        raise CaptureError('UNSUPPORTED_PROFILE', 'ELF size is outside the supported budget')
    data = path.read_bytes()
    header = ELF_HEADER.unpack_from(data)
    ident, kind, machine, version, entry, phoff, _, _, ehsize, phsize, phnum, _, _, _ = header
    if (ident[:7] != b'\x7fELF\x01\x01\x01' or kind != 2 or machine != 3 or version != 1
            or ehsize != ELF_HEADER.size or phsize != PROGRAM_HEADER.size):
        raise CaptureError('UNSUPPORTED_PROFILE', 'Require little-endian i386 ELF32 ET_EXEC')
    if not 1 <= phnum <= MAX_REGIONS + 3 or phoff < ehsize or phoff + phnum * phsize > len(data):
        raise CaptureError('INVALID_ELF', 'Invalid program-header table')
    programs = []
    for i in range(phnum):
        ptype, offset, address, _, filesz, memsz, flags, align = PROGRAM_HEADER.unpack_from(data, phoff + i * phsize)
        if ptype in (PT_DYNAMIC, PT_INTERP, PT_TLS):
            raise CaptureError('UNSUPPORTED_PROFILE', 'Dynamic linking and TLS are outside the first profile')
        if ptype == PT_LOAD:
            if (filesz > memsz or offset + filesz > len(data) or address + memsz > 2**32
                    or flags & ~7 or align not in (0, 1) and (align & (align - 1) or (address - offset) % align)):
                raise CaptureError('INVALID_ELF', 'Invalid PT_LOAD extent, permissions or alignment')
            programs.append(dict(address=address, offset=offset, filesz=filesz, memsz=memsz, flags=flags))
    if not programs or not any(p['flags'] & 1 and p['address'] <= entry < p['address'] + p['memsz'] for p in programs):
        raise CaptureError('INVALID_ELF', 'Entry is outside executable PT_LOAD memory')
    return dict(entry=entry, loads=programs, data=data, sha256=hashlib.sha256(data).hexdigest())


def load_capture(report_path, dump_path):
    report_path, dump_path = Path(report_path), Path(dump_path)
    if report_path.stat().st_size > 4 * 1024 * 1024:
        raise CaptureError('RESOURCE_LIMIT', 'Capture report exceeds 4 MiB')
    report = json.loads(report_path.read_text())
    if not isinstance(report, dict):
        raise CaptureError('INVALID_CAPTURE', 'Capture report must be an object')
    if report.get('schema_version') != 1 or report.get('arch') != 'x86' or report.get('byte_order') != 'little':
        raise CaptureError('UNSUPPORTED_PROFILE', 'Require the phase-1 schema-1 little-endian x86 capture')
    if report.get('capture_status') != 'success' or report.get('capture_gaps') != []:
        raise CaptureError('INCOMPLETE_CAPTURE', 'Require a successful capture without gaps')
    if (not isinstance(report.get('library_dependencies'), list)
            or not isinstance(report.get('resolved_imports'), list)):
        raise CaptureError('INVALID_CAPTURE', 'Library/import dependency observations are missing')
    if report['library_dependencies'] or report['resolved_imports']:
        raise CaptureError('UNSUPPORTED_PROFILE', 'Loaded libraries/import reconstruction are outside the first profile')
    regions = report.get('regions')
    if not isinstance(regions, list) or not 1 <= len(regions) <= MAX_REGIONS:
        raise CaptureError('INVALID_CAPTURE', 'Missing or oversized region table')
    size = dump_path.stat().st_size
    if not 0 < size <= MAX_BYTES:
        raise CaptureError('RESOURCE_LIMIT', 'Dump size is outside the 256 MiB budget')
    dump = dump_path.read_bytes()
    checked = []
    for region in regions:
        if not isinstance(region, dict):
            raise CaptureError('INVALID_CAPTURE', 'Each capture region must be an object')
        address, count, offset, prot = (integer(region.get(k), k) for k in ('addr', 'size', 'offset', 'prot'))
        if (address < 0x10000 or address % PAGE or count <= 0 or count % PAGE
                or address + count > 2**32 or offset < 0 or offset + count > size
                or not 0 <= prot <= 7 or region.get('lib') is not False):
            raise CaptureError('INVALID_CAPTURE', 'Invalid page-aligned program region')
        raw = dump[offset:offset + count]
        if hashlib.sha256(raw).hexdigest() != region.get('sha256'):
            raise CaptureError('CAPTURE_HASH_MISMATCH', f'Region at 0x{address:x} differs from its report')
        checked.append(dict(address=address, size=count, prot=prot, data=raw,
                            code_generation=region.get('code_generation'), dump_offset=offset))
    extents = sorted((r['dump_offset'], r['dump_offset'] + r['size']) for r in checked)
    cursor = 0
    for begin, end in extents:
        if begin != cursor:
            raise CaptureError('INVALID_CAPTURE', 'Dump extents overlap or leave unaccounted bytes')
        cursor = end
    if cursor != size:
        raise CaptureError('INVALID_CAPTURE', 'Trailing unaccounted dump bytes')
    checked.sort(key=lambda r: r['address'])
    for left, right in zip(checked, checked[1:]):
        if left['address'] + left['size'] > right['address']:
            raise CaptureError('INVALID_CAPTURE', 'Overlapping guest regions')
    entry = integer(report.get('oep'), 'oep')
    executable = next((r for r in checked if r['prot'] & 4 and r['address'] <= entry < r['address'] + r['size']), None)
    if executable is None:
        raise CaptureError('INVALID_CAPTURE', 'Selected entry is outside captured executable memory')
    candidates = report.get('oep_candidates', [])
    selected = [c for c in candidates if c.get('selected') is True]
    if candidates and (len(selected) != 1 or selected[0].get('stale') is not False
                       or integer(selected[0].get('addr'), 'candidate addr') != entry
                       or selected[0].get('code_generation') != executable['code_generation']):
        raise CaptureError('STALE_CANDIDATE', 'Selected candidate does not identify the captured entry generation')
    return report, checked


def captured_bytes(regions, address, count):
    parts = []
    end = address + count
    for region in regions:
        begin = max(address, region['address'])
        stop = min(end, region['address'] + region['size'])
        if begin < stop:
            if begin != address:
                raise CaptureError('INCOMPLETE_CAPTURE', 'Missing bytes in the requested guest range')
            parts.append(region['data'][begin - region['address']:stop - region['address']])
            address = stop
    if address != end:
        raise CaptureError('INCOMPLETE_CAPTURE', 'Missing bytes in the requested guest range')
    return b''.join(parts)


def code_oracle(regions, entry, reference):
    expected = equal = 0
    for load in reference['loads']:
        if not load['flags'] & 1:
            continue
        wanted = reference['data'][load['offset']:load['offset'] + load['filesz']]
        observed = captured_bytes(regions, load['address'], load['filesz'])
        expected += len(wanted)
        equal += sum(a == b for a, b in zip(wanted, observed))
    return dict(expected_bytes=expected, equal_bytes=equal, unequal_bytes=expected - equal,
                entry_exact=entry == reference['entry'], complete_exact_match=expected > 0 and equal == expected)


def rebuild(report_path, dump_path, output):
    output = Path(output)
    report, regions = load_capture(report_path, dump_path)
    entry = integer(report['oep'], 'oep')
    groups = []
    for region in regions:
        if groups and groups[-1]['address'] + groups[-1]['size'] == region['address'] and groups[-1]['prot'] == region['prot']:
            groups[-1]['parts'].append(region['data'])
            groups[-1]['size'] += region['size']
        else:
            groups.append(dict(address=region['address'], size=region['size'], prot=region['prot'], parts=[region['data']]))
    phnum = len(groups) + 3
    header_size = (ELF_HEADER.size + phnum * PROGRAM_HEADER.size + PAGE - 1) // PAGE * PAGE
    header_address = regions[0]['address'] - header_size
    if header_address < 0x10000:
        raise CaptureError('UNSUPPORTED_PROFILE', 'No space below the image for separate ELF metadata')
    ident = b'\x7fELF\x01\x01\x01' + bytes(9)
    header = ELF_HEADER.pack(ident, 2, 3, 1, entry, ELF_HEADER.size, 0, 0,
                             ELF_HEADER.size, PROGRAM_HEADER.size, phnum, 0, 0, 0)
    phdrs = [PROGRAM_HEADER.pack(PT_PHDR, ELF_HEADER.size, header_address + ELF_HEADER.size,
                                 header_address + ELF_HEADER.size, phnum * PROGRAM_HEADER.size,
                                 phnum * PROGRAM_HEADER.size, 4, 4),
             PROGRAM_HEADER.pack(PT_LOAD, 0, header_address, header_address, header_size, header_size, 4, PAGE)]
    offset = header_size
    loads = []
    for group in groups:
        prot = group['prot']
        flags = (4 if prot & 1 else 0) | (2 if prot & 2 else 0) | (1 if prot & 4 else 0)
        phdrs.append(PROGRAM_HEADER.pack(PT_LOAD, offset, group['address'], group['address'],
                                         group['size'], group['size'], flags, PAGE))
        loads.append(dict(address=group['address'], offset=offset, size=group['size'], flags=flags))
        offset += group['size']
    phdrs.append(PROGRAM_HEADER.pack(PT_GNU_STACK, 0, 0, 0, 0, 0, 6, 16))
    if output.exists():
        raise CaptureError('OUTPUT_EXISTS', f'Refusing to overwrite {output}')
    output.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=output.name + '.', dir=output.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            metadata = header + b''.join(phdrs)
            stream.write(metadata)
            stream.write(bytes(header_size - len(metadata)))
            for group in groups:
                for part in group['parts']:
                    stream.write(part)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o755)
        verified = read_elf(temporary)
        for load in loads:
            raw = verified['data'][load['offset']:load['offset'] + load['size']]
            if raw != captured_bytes(regions, load['address'], load['size']):
                raise CaptureError('REBUILD_MISMATCH', 'Rebuilt PT_LOAD bytes differ from the capture')
        os.link(temporary, output)
    finally:
        Path(temporary).unlink(missing_ok=True)
    return dict(status='REBUILT_IMAGE', entry=f'0x{entry:x}', elf_sha256=sha256(output),
                elf_bytes=output.stat().st_size, metadata_address=f'0x{header_address:x}',
                report_sha256=sha256(report_path), dump_sha256=sha256(dump_path),
                capture_consistency=report.get('capture_consistency'),
                capture_trace_seq=report.get('capture_trace_seq'), loads=loads,
                process_snapshot=False, oep_proof='NOT_ESTABLISHED')
