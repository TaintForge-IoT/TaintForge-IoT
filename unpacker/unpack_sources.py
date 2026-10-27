"""Construct a bounded static i386 loader image from authenticated ELF bytes.

These are source premises for the generic IR replay, rather than bytes copied
from its final image.  The loader, flat 32-bit mode and this supported loading
profile remain trusted models.  Stack and kernel premises are supplied by the
caller separately.
"""

import hashlib
import struct


PAGE_SIZE = 4096
MAX_PACKED_BYTES = 1024**2
MAX_LOAD_BYTES = 1024**2
MAX_IMAGE_BYTES = 16 * 1024**2
MAX_PROGRAM_HEADERS = 256
U32_END = 1 << 32
_HEADER = struct.Struct('<16sHHIIIIIHHHHHH')
_PROGRAM_HEADER = struct.Struct('<IIIIIIII')


def _require(condition, message):
    if not condition:
        raise ValueError(message)


def _round_up(value):
    return (value + PAGE_SIZE - 1) & -PAGE_SIZE


def loader_regions(packed):
    """Return source-constructed LOAD bytes and their effective permissions.

    Only static little-endian i386 ET_EXEC images with disjoint rounded LOADs
    are supported.  File mappings retain bytes after ``p_filesz`` within their
    last file page when there is no BSS.  A BSS segment instead zeroes from its
    declared file end to the rounded memory end.  This distinction matters for
    UPX images whose actual file extends beyond the last LOAD's ``p_filesz``.

    ``initial_regions`` contains ``(address, bytes)`` pairs suitable for
    ``oep_smt.source_value``.  No observed stack or final capture is accepted.
    """
    _require(type(packed) is bytes and _HEADER.size <= len(packed) <= MAX_PACKED_BYTES,
             'Packed ELF byte extent')
    fields = _HEADER.unpack_from(packed)
    (ident, kind, machine, version, entry, phoff, _shoff, flags, ehsize,
     phentsize, phnum, _shentsize, _shnum, _shstrndx) = fields
    _require(ident[:7] == b'\x7fELF\x01\x01\x01',
             'Expected little-endian ELF32 version1')
    _require(ident[7] in (0, 3) and ident[8] == 0, 'Unsupported ELF ABI')
    _require(kind == 2 and machine == 3 and version == 1,
             'Expected static i386 ET_EXEC')
    _require(flags == 0, 'Unsupported i386 ELF flags')
    _require(ehsize == _HEADER.size and phentsize == _PROGRAM_HEADER.size,
             'Unexpected ELF header sizes')
    _require(0 < phnum <= MAX_PROGRAM_HEADERS and phoff >= ehsize
             and phoff + phnum * phentsize <= len(packed),
             'Program-header table extent')

    loads = []
    stack_header = None
    for index in range(phnum):
        item = _PROGRAM_HEADER.unpack_from(packed, phoff + index * phentsize)
        kind, offset, address, _physical, filesz, memsz, protection, alignment = item
        _require(kind not in (2, 3, 7), 'Dynamic, interpreter or TLS segments unsupported')
        if kind == 0x6474e551:  # PT_GNU_STACK
            _require(stack_header is None, 'Duplicate PT_GNU_STACK unsupported')
            _require(protection <= 7, 'Unsupported PT_GNU_STACK flags')
            stack_header = {'index': index, 'flags': protection}
        if kind != 1:
            continue
        _require(filesz <= memsz and offset + filesz <= len(packed),
                 'PT_LOAD file extent')
        _require(0 < memsz and 0 < address < address + memsz <= U32_END,
                 'PT_LOAD memory extent')
        _require(0 <= protection <= 7, 'Unsupported PT_LOAD flags')
        _require(alignment in (0, 1) or alignment & (alignment - 1) == 0,
                 'Invalid PT_LOAD alignment')
        _require(address % PAGE_SIZE == offset % PAGE_SIZE
                 and (alignment <= 1 or address % alignment == offset % alignment),
                 'Incongruent PT_LOAD alignment')
        start = address & -PAGE_SIZE
        end = _round_up(address + memsz)
        _require(0 < end - start <= MAX_LOAD_BYTES and end <= U32_END,
                 'PT_LOAD mapping budget')
        file_start = offset & -PAGE_SIZE
        file_map_end = _round_up(address + filesz) if filesz else start
        # The actual mmap includes complete file pages, not merely filesz bytes.
        data = bytearray(end - start)
        if filesz:
            copied = min(file_map_end - start, max(0, len(packed) - file_start))
            data[:copied] = packed[file_start:file_start + copied]
        else:
            copied = 0
        if memsz > filesz:
            zero_start = address + filesz - start if filesz else 0
            data[zero_start:] = bytes(len(data) - zero_start)
        else:
            zero_start = None
        # ELF PF_R/PF_W/PF_X become the replay's read/write/execute bits.
        prot = ((protection >> 2) & 1) | (protection & 2) | ((protection & 1) << 2)
        loads.append({
            'index': index, 'start': start, 'end': end, 'prot': prot,
            'vaddr': address, 'offset': offset, 'filesz': filesz, 'memsz': memsz,
            'file_page_offset': file_start, 'file_bytes_copied': copied,
            'zero_from': None if zero_start is None else start + zero_start,
            'data': bytes(data),
        })

    _require(loads, 'ELF has no supported PT_LOAD')
    loads.sort(key=lambda item: item['start'])
    _require(all(left['end'] <= right['start'] for left, right in zip(loads, loads[1:])),
             'Overlapping rounded PT_LOAD mappings')
    _require(sum(item['end'] - item['start'] for item in loads) <= MAX_IMAGE_BYTES,
             'Initial image byte budget')
    _require(any(item['start'] <= entry < item['end'] and item['prot'] & 5 == 5
                 for item in loads), 'ELF entry is not readable and executable')
    return {
        'schema_version': 1,
        'source_kind': 'packed_ELF_loader_construction',
        'packed_sha256': hashlib.sha256(packed).hexdigest(),
        'entry': entry,
        # QEMU linux-user i386 gives the stack RW and uses only GNU_STACK's
        # PF_X bit.  Its i386 EXSTACK_DEFAULT is true when no header exists.
        'stack_prot': 3 | (4 if stack_header is None or stack_header['flags'] & 1 else 0),
        'stack_prot_source': 'QEMU_linux_user_i386_GNU_STACK_PF_X_or_executable_default',
        'stack_header': stack_header,
        'initial_regions': [(item['start'], item['data']) for item in loads],
        'protections': [{'start': item['start'], 'end': item['end'], 'prot': item['prot']}
                        for item in loads],
        'loads': [{**{key: value for key, value in item.items() if key != 'data'},
                   'bytes_sha256': hashlib.sha256(item['data']).hexdigest()}
                  for item in loads],
        'observed_final_bytes_used_as_sources': False,
        'loader_implementation_verified': False,
    }
