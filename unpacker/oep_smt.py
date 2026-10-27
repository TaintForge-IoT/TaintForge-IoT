#!/usr/bin/env python3
"""Prove source-derived entry producer values with the existing IR/SMT backend.

This is a selected-execution dataflow theorem. The source-built replay validates
the control, alias and instruction-fetch schedule; these are explicit premises,
not a claim that SMT explored every execution or verified the kernel.
"""
import argparse
import hashlib
import mmap
import os
from pathlib import Path
import shlex
import shutil
import struct
import subprocess
import sys
import tempfile
import time
import zipfile

sys.dont_write_bytecode = True
try:
    from . import oep_verify as verifier
    from . import oep_current_run as current
    from .oep_observations import read_capture, audit_observations
    from .oep_environment import _pairs, audit_environment
    from .oep_entry import parse_elf32
except ImportError:
    import oep_verify as verifier
    import oep_current_run as current
    from oep_observations import read_capture, audit_observations
    from oep_environment import _pairs, audit_environment
    from oep_entry import parse_elf32

ROOT = Path(__file__).resolve().parent
HEADER = b'TFPROD1\0' + struct.pack('<II', 1, 32)
RECORD = struct.Struct('<HHIIIQQ')
ARITY = {0: 0, 2: 0, 3: 1, 4: 2, 5: 2, 6: 2, 7: 2, 8: 2, 9: 2,
         10: 1, 11: 1, 12: 2, 13: 2, 14: 2, 15: 1, 16: 2, 17: 1,
         18: 1, 19: 2, 20: 2, 21: 2, 22: 3}
require = verifier.require


def file_digest(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def slice_ledger(path, roots, output, max_nodes=2_000_000):
    """Retain real producer operations; source metadata is never a dependency."""
    path, output = Path(path), Path(output)
    require(path.is_file() and not path.is_symlink(), 'Producer ledger missing or symlink')
    size = path.stat().st_size
    require(16 < size <= 16 + 268435456 * 32 and (size - 16) % 32 == 0, 'Producer ledger extent')
    require(type(max_nodes) is int and 0 < max_nodes <= 2_000_000 and roots, 'Producer slice budget or roots')
    count = (size - 16) // 32
    with path.open('rb') as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as data:
        require(data[:16] == HEADER, 'Producer ledger header')

        def read(node):
            require(type(node) is int and 0 < node <= count, 'Producer identity')
            result = RECORD.unpack_from(data, 16 + (node - 1) * 32)
            op, bits, a, b, c, immediate, _ = result
            require(0 < bits <= 64, 'Producer width')
            if 100 <= op <= 109:
                require(c == 0 and immediate < 1 << bits, 'Producer source encoding')
            else:
                require(op in ARITY, 'Unmodeled producer opcode')
                for index, argument in enumerate((a, b, c)):
                    require(0 < argument < node if index < ARITY[op] else argument == 0,
                            'Producer dependency order')
                require(op != 0 or immediate < 1 << bits, 'Producer constant encoding')
            return result

        pending = []
        for root in roots:
            require(type(root) is dict, 'Producer root object')
            node, offset, bits, expected = [root.get(k) for k in ('id', 'offset', 'bits', 'expected')]
            require(all(type(x) is int for x in (node, offset, bits, expected))
                    and offset >= 0 and 0 < bits <= 64 and 0 <= expected < 1 << bits,
                    'Producer root encoding')
            require(offset + bits <= read(node)[1], 'Producer root extent')
            pending.append(node)
        needed = set()
        while pending:
            node = pending.pop()
            if node in needed:
                continue
            require(len(needed) < max_nodes, 'Producer slice node budget')
            row = read(node)
            needed.add(node)
            if row[0] < 100:
                pending.extend(row[2:2 + ARITY[row[0]]])
        ordered = sorted(needed)
        mapping = {old: new for new, old in enumerate(ordered, 1)}
        records, source_nodes = [], []
        for old in ordered:
            row = read(old)
            if row[0] >= 100:
                source_nodes.append((mapping[old], row))
                records.append(row)
            else:
                records.append((*row[:2], *(mapping.get(x, 0) for x in row[2:5]), *row[5:]))
        goals, values = [], {}
        extracts = {}
        for root in roots:
            node, bits, offset = mapping[root['id']], root['bits'], root['offset']
            if offset or bits != read(root['id'])[1]:
                key = node, bits, offset
                if key not in extracts:
                    require(len(records) < max_nodes, 'Producer slice extraction budget')
                    records.append((15, bits, node, 0, 0, offset, 0))
                    extracts[key] = len(records)
                node = extracts[key]
            require(node not in values or values[node] == root['expected'], 'Conflicting producer goals')
            if node not in values:
                goals.append((node, root['expected']))
                values[node] = root['expected']
        with output.open('wb') as target:
            target.write(HEADER)
            for row in records:
                target.write(RECORD.pack(*row))
    return {'mapping': mapping, 'nodes': len(records), 'source_nodes': source_nodes, 'goals': goals,
            'operation_nodes': sum(row[0] in ARITY and row[0] not in (0, 2) for row in records)}


def private_file_padding_source(context, offset):
    """Bind EOF padding to an immutable source-file mapping constructor."""
    packed, calls = context['packed'], context['calls']
    require(type(packed) is bytes and 0 < len(packed) <= 1024**2 and
            type(calls) in (list, tuple) and len(calls) <= 256,
            'Private file source inventory')
    source_sha = hashlib.sha256(packed).hexdigest()
    capacity = (len(packed) + 4095) & ~4095
    descriptors, covered = {}, False
    none = dict(operation='none', address=0, size=0, prot=0,
                mapping_epoch=0, zero_fill_sha256=None)
    for ordinal, (entry, returned, post) in enumerate(calls, 1):
        require(type(entry) is dict and type(returned) is dict and type(post) is dict and
                type(entry.get('ordinal')) is int and entry['ordinal'] == ordinal and
                type(entry.get('number')) is int and
                all(key in post for key in ('file_mapping', 'file_descriptor', 'mapping_effect')),
                'Private file source call chronology')
        number, args, result = entry['number'], entry['args'], returned['result_u32']
        require(type(args) in (list, tuple) and len(args) == 6 and
                all(type(value) is int and 0 <= value <= 0xffffffff for value in args) and
                type(result) is int and 0 <= result <= 0xffffffff,
                'Private file source call scalars')
        effect = post['mapping_effect']
        require(type(effect) is dict and set(effect) == set(none) and
                effect.get('operation') in ('none', 'map', 'unmap', 'protect') and
                all(type(effect.get(key)) is int and 0 <= effect[key] <= 0xffffffff
                    for key in ('address', 'size', 'prot', 'mapping_epoch')),
                'Private file source mapping effect fields')
        descriptor, mapped = post['file_descriptor'], post['file_mapping']
        if number in (5, 6):
            fd = result if number == 5 else args[0]
            require(type(fd) is int and 3 <= fd < 64 and mapped is None and
                    post['mapping_effect'] == none,
                    'Private source descriptor effect')
            if number == 5:
                require(args[1] == 0 and entry.get('path_hex') == b'/proc/self/exe\0'.hex() and
                        fd not in descriptors, 'Private source readonly open identity')
                epoch = ordinal
                descriptors[fd] = epoch
            else:
                require(result == 0 and fd in descriptors, 'Private source close identity')
                epoch = descriptors.pop(fd)
            require(type(descriptor) is dict and all(type(descriptor.get(key)) is int
                    for key in ('fd', 'file_id', 'descriptor_epoch', 'file_size')) and
                    descriptor == dict(operation='open' if number == 5 else 'close',
                        fd=fd, file_id=0, descriptor_epoch=epoch, file_size=len(packed),
                        source_sha256=source_sha), 'Private source descriptor constructor')
        elif number in (90, 192):
            effective = entry.get('mmap_args') if number == 90 else args
            require(type(effective) in (list, tuple) and len(effective) == 6 and
                    all(type(value) is int and 0 <= value <= 0xffffffff for value in effective),
                    'Private source mmap arguments')
            if effective[3] & 32 or result >= 0xfffff001:
                require(mapped is None and descriptor is None,
                        'Failed or anonymous map cannot supply file padding')
                continue
            length = (effective[1] + 4095) & ~4095
            file_offset = effective[5] * (4096 if number == 192 else 1)
            require(0 < effective[1] <= 1024**2 and effective[2] <= 7 and effective[2] & 1 and
                    effective[3] in (2, 0x12) and effective[4] in descriptors and
                    0x10000 <= result < 0xfffff001 and result % 4096 == 0 and
                    result + length <= 2**32 and file_offset % 4096 == 0 and
                    file_offset + length <= capacity and file_offset < len(packed) and
                    (not effective[3] & 16 or effective[0] == result) and descriptor is None,
                    'Private source mapping geometry or lifetime')
            copied = min(length, len(packed) - file_offset)
            expected = packed[file_offset:file_offset + copied] + bytes(length - copied)
            require(type(mapped) is dict and all(type(mapped.get(key)) is int for key in
                    ('fd', 'file_id', 'descriptor_epoch', 'file_size', 'file_offset',
                     'file_bytes', 'zero_tail_bytes')) and mapped == dict(fd=effective[4], file_id=0,
                        descriptor_epoch=descriptors[effective[4]], file_size=len(packed),
                        file_offset=file_offset, file_bytes=copied, zero_tail_bytes=length-copied,
                        initial_bytes_sha256=hashlib.sha256(expected).hexdigest()) and
                    post['mapping_effect'] == dict(operation='map', address=result, size=length,
                        prot=effective[2], mapping_epoch=ordinal, zero_fill_sha256=None),
                    'Private source mapping constructor differs')
            covered |= file_offset + copied <= offset < file_offset + length
        else:
            require(number in (91, 125) and mapped is None and descriptor is None,
                    'Unsupported private source file mutation')
    require(covered, 'EOF zero is outside authenticated private source constructors')
    return 0


def mutable_file_source(context, *, zero=None, padding=None):
    """Authenticate V5 zero leaves against chronological file constructors.

    Pre-write observations are used here only to check constructor metadata.
    Written values remain LOAD-derived producer expressions in the native graph;
    this function admits only zero leaves and immutable-file EOF padding.
    """
    packed, calls = context['packed'], context['calls']
    require(type(packed) is bytes and 0 < len(packed) <= 1024**2 and
            type(calls) in (list, tuple) and 0 < len(calls) <= 256,
            'Mutable file source inventory')
    shared_profile = context.get('mapping_profile_version') in (6, 7)
    tail_profile = context.get('mapping_profile_version') == 7
    source_sha = hashlib.sha256(packed).hexdigest()
    none = dict(operation='none', address=0, size=0, prot=0,
                mapping_epoch=0, zero_fill_sha256=None)
    descriptors, files, live, next_file = {}, {0: dict(
        data=packed, size=len(packed), capacity=(len(packed)+4095)&~4095, epoch=0, tail_dirty=False)}, {}, 1

    live_shared, live_offsets = {}, {}
    shared_stores = context.get('shared_stores') if shared_profile else []
    require(type(shared_stores) is list and len(shared_stores) <= 1_000_000,
            'V6 requires a bounded shared-store inventory')
    previous = (-1, 0)
    for row in shared_stores:
        require(type(row) is dict and type(row.get('after_syscall_ordinal')) is int and
                0 <= row['after_syscall_ordinal'] <= len(calls) and
                type(row.get('store_ordinal')) is int and row['store_ordinal'] > previous[1] and
                row['after_syscall_ordinal'] >= previous[0],
                'Shared-store inventory chronology')
        previous = row['after_syscall_ordinal'], row['store_ordinal']

    def uint(value, label, limit=0xffffffff):
        require(type(value) is int and 0 <= value <= limit, label)
        return value

    def exact(actual, expected, label):
        require(type(actual) is dict and set(actual) == set(expected) and
                all(type(actual[key]) is type(value) and actual[key] == value
                    for key, value in expected.items()), label)

    def blob(value, label, size=None):
        require(type(value) is str and len(value) % 2 == 0 and len(value) <= 2*1024**2 and
                all(c in '0123456789abcdef' for c in value), label)
        result = bytes.fromhex(value)
        require(size is None or len(result) == size, label)
        return result

    def apply_stores(after):
        for row in shared_stores:
            if row['after_syscall_ordinal'] != after:
                continue
            address = uint(row.get('address'), 'Shared-store address')
            size = uint(row.get('size'), 'Shared-store size', 16)
            write = row.get('shared_file_write')
            require(size in (1, 2, 4, 8, 16) and address+size <= 2**32 and
                    type(write) is dict and set(write) == {'file_id', 'file_offset', 'data_hex'},
                    'Shared-store effect identity')
            file_id = uint(write.get('file_id'), 'Shared-store local file', 31)
            offset = uint(write.get('file_offset'), 'Shared-store file offset', 1024**2)
            data = blob(write.get('data_hex'), 'Shared-store observed data', size)
            limit = (((files[file_id]['size']+4095)&~4095) if tail_profile else files[file_id]['size']) if file_id in files else 0
            require(file_id > 0 and file_id in files and offset+size <= limit and
                    all(live.get((address+i)//4096*4096) == file_id and
                        live_shared.get((address+i)//4096*4096) is True and
                        live_offsets.get((address+i)//4096*4096) == offset+i-(address+i)%4096
                        for i in range(size)) and
                    all(other != file_id or live_shared.get(page) is True
                        for page, other in live.items()), 'Shared-store live backing or EOF')
            image = bytearray(files[file_id]['data'])
            image[offset:offset+size] = data
            files[file_id]['data'] = bytes(image)
            if tail_profile and offset+size > files[file_id]['size']:
                files[file_id]['tail_dirty'] = True

    for ordinal, call in enumerate(calls, 1):
        if shared_profile:
            apply_stores(ordinal-1)
        require(type(call) in (list, tuple) and len(call) == 3, 'Mutable source call triple')
        entry, returned, post = call
        require(type(entry) is dict and type(returned) is dict and type(post) is dict and
                type(entry.get('ordinal')) is int and entry['ordinal'] == ordinal and
                all(key in post for key in ('mapping_effect', 'file_mapping',
                                           'file_descriptor', 'file_mutation')),
                'Mutable source call chronology or profile')
        number = uint(entry.get('number'), 'Mutable source syscall number')
        args = entry.get('args')
        require(type(args) in (list, tuple) and len(args) == 6,
                'Mutable source call arguments')
        for arg in args: uint(arg, 'Mutable source call argument')
        result = uint(returned.get('result_u32'), 'Mutable source call result')
        mapped = descriptor = mutation = None
        effect = none.copy()
        zero_ranges, zero_file = [], None
        if number in (5, 356):
            require(3 <= result < 64 and result not in descriptors,
                    'Mutable source fresh descriptor')
            if number == 5:
                require(args[1] == 0 and entry.get('path_hex') == b'/proc/self/exe\0'.hex(),
                        'Mutable profile immutable source open')
                file_id = 0
            else:
                name = blob(entry.get('name_hex'), 'Mutable memfd name')
                require(0 < len(name) <= 64 and name[-1:] == b'\0' and b'\0' not in name[:-1] and
                        args[1] in ((0, 1, 16, 17) if shared_profile else (0, 1)) and next_file < 32,
                        'Mutable memfd creation profile')
                file_id, next_file = next_file, next_file + 1
                files[file_id] = dict(data=b'', size=0, capacity=0, epoch=ordinal, tail_dirty=False)
            descriptors[result] = dict(file=file_id, epoch=ordinal, cursor=0)
            descriptor = dict(operation='open' if number == 5 else 'memfd_create',
                fd=result, file_id=file_id, descriptor_epoch=ordinal,
                file_size=files[file_id]['size'], source_sha256=source_sha if file_id == 0 else None)
        elif number == 6:
            fd = args[0]
            require(fd in descriptors and result == 0, 'Mutable source close lifetime')
            d = descriptors.pop(fd); file_id = d['file']
            descriptor = dict(operation='close', fd=fd, file_id=file_id,
                descriptor_epoch=d['epoch'], file_size=files[file_id]['size'],
                source_sha256=source_sha if file_id == 0 else None)
        elif number in (4, 93, 19):
            fd = args[0]
            require(fd in descriptors and descriptors[fd]['file'] != 0,
                    'Mutable operation requires a local memfd')
            d = descriptors[fd]; file_id = d['file']; f = files[file_id]
            old_size, before = f['size'], d['cursor']
            old_capacity = f['capacity']
            if tail_profile and f['tail_dirty']:
                require(number != 93 and (number != 4 or before+result <= old_size),
                        'Dirty page-cache source excludes truncate and growth')
            mutation = dict(operation={4:'write',93:'truncate',19:'seek'}[number],
                fd=fd, file_id=file_id, descriptor_epoch=d['epoch'], content_epoch=f['epoch'],
                old_size=old_size, new_size=old_size, offset_before=before, offset_after=before,
                write_address=0, write_count=0, write_sha256=None, zero_start=0, zero_end=0)
            if number == 19:
                require(args[2] == 0 and args[1] <= 1024**2 and result == args[1],
                        'Mutable seek requires bounded SEEK_SET')
                d['cursor'] = result; mutation['offset_after'] = result
            else:
                require(file_id not in live.values() or shared_profile and number == 4 and
                        all(live_shared.get(page) is True for page, other in live.items() if other == file_id),
                        'Mutable source mutation has live private aliases or unsupported truncate')
                if file_id in live.values():
                    require(before+result <= old_size, 'Live shared write cannot grow a source file')
                if number == 93:
                    require(result == 0 and args[1] <= 1024**2, 'Mutable truncate contract')
                    desired = args[1]
                    if desired != old_size:
                        f['epoch'] = ordinal
                        f['capacity'] = max(old_capacity, (desired+4095)&~4095)
                        zero_ranges = [(min(old_size, desired),
                                        old_capacity if desired < old_size else (desired+4095)&~4095)]
                        zero_file = file_id
                        if tail_profile:
                            image = bytearray(f['data'] + bytes(f['capacity']-len(f['data'])))
                            low = min(old_size, desired)
                            image[low:f['capacity']] = bytes(f['capacity']-low)
                            f['data'] = bytes(image)
                        else:
                            f['data'] = f['data'][:desired] + bytes(max(0, desired-old_size))
                        if desired > old_size:
                            mutation.update(zero_start=old_size, zero_end=desired)
                    f['size'] = desired
                else:
                    require(args[2] <= 1024**2 and result <= args[2] and
                            args[1] + args[2] <= 2**32 and before + result <= 1024**2,
                            'Mutable write prefix or extent')
                    observed = entry.get('write_buffer')
                    require(type(observed) is dict and set(observed) == {'address','size','data_hex'} and
                            type(observed['address']) is int and observed['address'] == args[1] and
                            type(observed['size']) is int and observed['size'] == args[2],
                            'Mutable write observation identity')
                    data = blob(observed['data_hex'], 'Mutable write observation bytes', args[2])[:result]
                    mutation.update(write_address=args[1], write_count=result,
                                    write_sha256=hashlib.sha256(data).hexdigest())
                    if result:
                        desired = max(old_size, before+result)
                        capacity = max(old_capacity, (desired+4095)&~4095)
                        # The write interval is never an admitted zero source,
                        # even if the recorded buffer happens to contain zeros.
                        constructed_end = (desired+4095)&~4095
                        zero_ranges = ([(old_size, min(before, constructed_end)),
                                       (max(old_size, before+result), constructed_end)]
                                       if not tail_profile or desired > old_size else [])
                        zero_file = file_id
                        image = bytearray(f['data'] + bytes((capacity if tail_profile else desired)-len(f['data'])))
                        image[before:before+result] = data
                        f.update(data=bytes(image), size=desired, capacity=capacity, epoch=ordinal)
                        d['cursor'] = before+result
                        if before > old_size:
                            mutation.update(zero_start=old_size, zero_end=before)
            mutation.update(content_epoch=f['epoch'], new_size=f['size'], offset_after=d['cursor'])
        elif number == 144:
            address, size, flags = args[:3]
            length = (size+4095)&~4095
            require(tail_profile and result == 0 and address >= 0x10000 and address % 4096 == 0 and
                    0 < size <= 1024**2 and address+length <= 2**32 and flags == 4 and
                    all(live.get(page, 0) > 0 and live_shared.get(page) is True
                        for page in range(address,address+length,4096)),
                    'Only bounded local shared source MS_SYNC is admitted')
        elif number in (90, 192):
            a = entry.get('mmap_args') if number == 90 else args
            require(type(a) in (list, tuple) and len(a) == 6,
                    'Mutable source mmap arguments')
            for arg in a: uint(arg, 'Mutable source mmap argument')
            location, size, prot, flags, fd, offset = a
            length = (size+4095)&~4095
            require(size <= 1024**2 and prot <= 7 and prot & 1 and flags in ((1,0x11,2,0x12,0x22,0x32) if shared_profile else (2,0x12,0x22,0x32)),
                    'Mutable source mapping profile')
            file_map = not flags & 32
            shared = file_map and flags & 3 == 1
            byte_offset = offset*(4096 if number == 192 else 1)
            if file_map:
                require(fd in descriptors and byte_offset <= 1024**2,
                        'Mutable mapping descriptor or offset')
            else:
                require(fd == 0xffffffff and offset == 0, 'Mutable anonymous source identity')
            invalid = not size or bool(flags & 16 and location % 4096) or bool(file_map and byte_offset % 4096)
            if result >= 0xfffff001:
                require(result == 0xffffffea and invalid, 'Mutable failed-map source contract')
            else:
                require(not invalid and result >= 0x10000 and result % 4096 == 0 and
                        result+length <= 2**32 and (not flags & 16 or result == location),
                        'Mutable map result geometry')
                effect = dict(operation='map', address=result, size=length, prot=prot,
                              mapping_epoch=ordinal, zero_fill_sha256=None)
                if file_map:
                    d = descriptors[fd]; file_id = d['file']; f = files[file_id]
                    require(not shared or shared_profile and file_id > 0,
                            'Shared source mapping requires a local memfd')
                    require(byte_offset < f['size'] and byte_offset+length <= (f['size']+4095)&~4095,
                            'Mutable whole-page-past-EOF constructor')
                    copied = min(length, f['size']-byte_offset)
                    constructor = (f['data'][byte_offset:byte_offset+length] if tail_profile and file_id > 0
                                   else f['data'][byte_offset:byte_offset+copied] + bytes(length-copied))
                    mapped = dict(fd=fd, file_id=file_id, descriptor_epoch=d['epoch'],
                        file_size=f['size'], file_offset=byte_offset, file_bytes=copied,
                        zero_tail_bytes=length-copied,
                        initial_bytes_sha256=hashlib.sha256(constructor).hexdigest(), content_epoch=f['epoch'])
                    if shared_profile:
                        mapped['shared'] = shared
                    if tail_profile:
                        mapped['cache_tail_bytes'] = length-copied if file_id > 0 else 0
                        if file_id > 0:
                            mapped['zero_tail_bytes'] = 0
                else:
                    effect['zero_fill_sha256'] = hashlib.sha256(bytes(length)).hexdigest()
                for page in range(result, result+length, 4096):
                    if file_map:
                        live[page] = file_id
                        live_shared[page] = shared
                        live_offsets[page] = byte_offset+page-result
                    else:
                        live.pop(page, None)
                        live_shared.pop(page, None)
                        live_offsets.pop(page, None)
                require(len(live) <= 4096, 'Mutable source live mapping budget')
        elif number in (91, 125):
            address, size = args[:2]; length = (size+4095)&~4095
            invalid = bool(address % 4096) or number == 91 and not size
            require(length <= 1024**2 and (number != 125 or args[2] <= 7),
                    'Mutable source memory operation bound')
            if result >= 0xfffff001:
                require(result == 0xffffffea and invalid, 'Mutable source memory preflight errno')
            else:
                require(result == 0 and not invalid and size > 0 and address >= 0x10000 and
                        address+length <= 2**32, 'Mutable source memory operation geometry')
                effect = dict(operation='unmap' if number == 91 else 'protect',
                    address=address, size=length, prot=0 if number == 91 else args[2],
                    mapping_epoch=0, zero_fill_sha256=None)
                if number == 91:
                    for page in range(address, address+length, 4096):
                        live.pop(page, None)
                        live_shared.pop(page, None)
                        live_offsets.pop(page, None)
        else:
            require(False, 'Unsupported mutable file source syscall')
        exact(post['mapping_effect'], effect, 'Mutable source mapping effect differs')
        for key, expected in (('file_mapping', mapped), ('file_descriptor', descriptor),
                              ('file_mutation', mutation)):
            if expected is None:
                require(post[key] is None, 'Unexpected mutable file effect: '+key)
            else:
                exact(post[key], expected, 'Mutable source effect differs: '+key)
        if zero is not None and ordinal == zero[1]:
            require(zero_file == zero[0] and any(low <= zero[2] < high for low, high in zero_ranges),
                    'Mutable zero is not supplied by this exact file constructor')
            return 0
        if padding is not None and mapped is not None and mapped['file_id'] == 0:
            if mapped['file_offset']+mapped['file_bytes'] <= padding < mapped['file_offset']+effect['size']:
                return 0
    require(False, 'Mutable zero constructor was not found')


def source_value(record, context):
    """Authenticate each leaf against entry bytes or an explicit syscall contract."""
    op, bits, low, high, unused, recorded, _ = record
    require(100 <= op <= 109 and unused == 0, 'Unsupported producer source kind')
    profile = context.get('mapping_profile_version')
    require(profile is None or type(profile) is int and profile in (3, 4, 5, 6, 7),
            'Unsupported mapping source profile')
    key = low | high << 32
    if op in (100, 101):
        require(bits == 8, 'Byte producer width')
        blob = context['packed' if op == 100 else 'stack']
        require(key < len(blob), 'Producer source offset')
        if op == 101:
            require(len(context['mask']) == len(blob) and context['mask'][key] == 255,
                    'Producer stack byte is not an admitted known input')
        value = blob[key]
    elif op == 102:
        matches = [blob[key - address] for address, blob in context['initial_regions']
                   if address <= key < address + len(blob)]
        require(bits == 8 and matches == [0], 'Initial zero RAM source')
        value = 0
    elif op in (103, 104):
        require(key == 0 and bits == (32 if op == 103 else 1), 'Entry scalar producer identity')
        value = context['esp' if op == 103 else 'df']
    elif op in (105, 106, 107):
        ordinal, detail = key >> 32, key & 0xffffffff
        calls = context['calls']
        require(0 < ordinal <= len(calls), 'Producer syscall ordinal')
        entry, returned, post = calls[ordinal - 1]
        require(entry['ordinal'] == ordinal, 'Producer syscall order')
        if op == 105:
            require(bits == 32 and detail == entry['number'], 'Producer syscall identity')
            value = returned['result_u32']
        elif op == 106:
            reply = bytes.fromhex(returned.get('reply_hex') or '')
            require(bits == 8 and entry['number'] == 85 and detail < len(reply)
                    and len(reply) == returned['result_u32'], 'Readlink producer byte')
            value = reply[detail]
        else:
            require(bits == 8 and entry['number'] in (90, 192), 'Anonymous mapping zero producer')
            args = entry['mmap_args'] if entry['number'] == 90 else entry['args']
            start = returned['result_u32']
            require(type(args) in (list, tuple) and len(args) == 6 and
                    all(type(value) is int and 0 <= value < 2**32 for value in args) and
                    type(start) is int and 0 < start < 0xfffff001 and start % 4096 == 0 and
                    args[1] > 0, 'Anonymous mapping zero requires a successful mapping')
            length = (args[1] + 4095) & ~4095
            require(args[3] & 32 and start + length <= 2**32 and
                    start <= detail < start + length,
                    'Anonymous mapping zero extent')
            if profile in (3, 4, 5, 6, 7):
                require(type(post) is dict, 'Anonymous mapping post-state')
                effect = post.get('mapping_effect')
                require(length <= 1024**2 and args[3] in (0x22, 0x32) and
                        args[4] == 0xffffffff and args[5] == 0 and args[2] <= 7 and args[2] & 1 and
                        (not args[3] & 16 or args[0] == start) and
                        type(effect) is dict and all(type(effect.get(field)) is int for field in
                            ('address', 'size', 'prot', 'mapping_epoch')) and
                        effect == dict(operation='map', address=start,
                            size=length, prot=args[2], mapping_epoch=ordinal,
                            zero_fill_sha256=hashlib.sha256(bytes(length)).hexdigest()),
                        'Anonymous mapping zero lacks a validated current mapping constructor')
                if profile in (4, 5, 6, 7):
                    require('file_mapping' in post and 'file_descriptor' in post and
                            post['file_mapping'] is None and post['file_descriptor'] is None,
                            'Anonymous zero cannot use a private file constructor')
                if profile in (5, 6, 7):
                    require('file_mutation' in post and post['file_mutation'] is None,
                            'Anonymous zero cannot use a mutable file effect')
            value = 0
    elif op == 108:
        require(profile != 3, 'Anonymous-only mapping profile cannot admit file padding')
        require(bits == 8 and len(context['packed']) <= key < (len(context['packed']) + 4095) & ~4095,
                'Initial file padding zero producer')
        value = (mutable_file_source(context, padding=key) if profile in (5, 6, 7) else
                 private_file_padding_source(context, key) if profile == 4 else 0)
    else:
        require(profile not in (3, 4),
                'Anonymous/immutable mapping profile does not admit file growth zeros')
        file_id, ordinal, offset = key >> 56, key >> 32 & 0xffffff, key & 0xffffffff
        calls = context['calls']
        initial_capacity = (len(context['packed']) + 4095) & ~4095
        require(bits == 8 and file_id < 32 and 0 < ordinal <= len(calls)
                and offset < 1024 * 1024 and initial_capacity <= 1024 * 1024,
                'Kernel file zero identity')
        if profile in (5, 6, 7):
            value = mutable_file_source(context, zero=(file_id, ordinal, offset))
            require(recorded == value, 'Mutable zero leaf differs from constructor')
            return value
        descriptors, capacities, next_file = {}, {0: initial_capacity}, 1
        growth = None
        for index, (entry, returned, _) in enumerate(calls[:ordinal], 1):
            number, args, result = entry['number'], entry['args'], returned['result_u32']
            require(entry['ordinal'] == index and type(result) is int and 0 <= result <= 0xffffffff
                    and len(args) == 6 and all(type(a) is int and 0 <= a <= 0xffffffff for a in args),
                    'Kernel file capacity history')
            target, desired = None, None
            growth = None
            if number == 356:
                require(result < 64 and result not in descriptors and next_file < 32,
                        'Memfd capacity contract')
                descriptors[result] = next_file
                capacities[next_file] = 0
                next_file += 1
            elif number == 5:
                require(result < 64 and result not in descriptors, 'Open capacity contract')
                descriptors[result] = 0
            elif number == 6:
                require(args[0] in descriptors and result == 0, 'Close capacity contract')
                del descriptors[args[0]]
            elif number in (93, 4):
                require(args[0] in descriptors and (result == 0 if number == 93 else result == args[2]),
                        'File growth capacity contract')
                target = descriptors[args[0]]
                desired = args[1] if number == 93 else (result + 4095) & ~4095
            elif number in (90, 192):
                args = entry['mmap_args'] if number == 90 else args
                require(len(args) == 6 and all(type(a) is int and 0 <= a <= 0xffffffff for a in args)
                        and result % 4096 == 0 and 0 < args[1] <= 1024 * 1024
                        and result + ((args[1] + 4095) & ~4095) <= 0x100000000,
                        'Mapped file capacity geometry')
                if not args[3] & 32:
                    require(args[4] in descriptors, 'Mapped file capacity descriptor')
                    target = descriptors[args[4]]
                    desired = args[5] * (4096 if number == 192 else 1) + ((args[1] + 4095) & ~4095)
            if target is not None:
                require(0 <= desired <= 1024 * 1024, 'Kernel file capacity bound')
                old = capacities[target]
                if desired > old:
                    capacities[target] = desired
                    growth = target, old, desired
        require(growth is not None and growth[0] == file_id and growth[1] <= offset < growth[2],
                'Kernel file zero was not newly allocated at this ordinal')
        value = 0
    require(type(value) is int and 0 <= value < 1 << bits and recorded == value,
            'Producer leaf differs from authenticated source')
    return value


def build_solver(output):
    output.mkdir()
    source = output / 'sources'
    source.mkdir()
    names = ('ir.c', 'ir_eval.c', 'ir_inputs.c', 'ir_smt.c', 'replay_sources.c')
    headers = (*verifier.IR_HEADER_FILES, 'ir_eval.h', 'ir_inputs.h', 'ir_smt.h', 'replay_sources.h',
               'ir_smt_diagnostics.h', 'ir_smt_checks.h', 'ir_smt_ownership.h')
    hashes = {}
    for name in (*names, *headers):
        data = (ROOT / 'test' / name).read_bytes()
        (source / name).write_bytes(data)
        hashes[name] = verifier.digest(data)
    data = (ROOT / 'oep_smt.c').read_bytes()
    (source / 'oep_smt.c').write_bytes(data)
    hashes['oep_smt.c'] = verifier.digest(data)
    cpp = os.environ.get('TF_SMT_CPPFLAGS', os.environ.get('TF_PLUGIN_CPPFLAGS'))
    if cpp is None:
        cpp = subprocess.check_output(['pkg-config', '--cflags', 'capstone', 'z3'], text=True, timeout=30)
    libs = os.environ.get('TF_SMT_LIBS')
    if libs is None:
        libs = subprocess.check_output(['pkg-config', '--libs', 'z3'], text=True, timeout=30)
    binary = output / 'oep-smt'
    command = [os.environ.get('TF_IR_CC', 'gcc'), '-std=gnu11', '-O2', '-Wall', '-Wextra', '-Werror',
               '-ffunction-sections', '-fdata-sections', '-I', str(source), *shlex.split(cpp),
               str(source / 'oep_smt.c'), *[str(source / n) for n in names],
               '-Wl,--gc-sections', *shlex.split(libs), '-o', str(binary)]
    with (output / 'build.log').open('wb') as log:
        result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, timeout=180)
    require(result.returncode == 0, 'SMT build failed; inspect ' + str(output / 'build.log'))
    verifier.save(output / 'receipt.json', {'source_files_sha256': hashes, 'command': command,
                  'binary_sha256': file_digest(binary), 'existing_IR_SMT_backend': True,
                  'uploaded_native_objects_linked': False})
    return binary


def evidence_path(path):
    path = Path(path)
    if path.is_dir():
        choices = [p for p in (path / 'probe/oep-evidence.zip', path / 'oep-evidence.zip') if p.is_file()]
        require(len(choices) == 1, 'Expected one OEP evidence archive')
        return choices[0]
    return path


def producer_goals(original, root_rows, origins, catalogue, instructions, *, kernel_pcs=()):
    """Use independent ELF bytes and fresh catalogue bytes as conclusions only."""
    elf = parse_elf32(original)
    image = {}
    for segment in elf['program_headers']:
        if segment['type'] != 1:
            continue
        require(segment['memsz'] <= 1024 * 1024, 'Reference segment budget')
        data = original[segment['offset']:segment['offset'] + segment['filesz']]
        data += bytes(segment['memsz'] - segment['filesz'])
        for index, value in enumerate(data):
            address = segment['vaddr'] + index
            require(address not in image, 'Overlapping reference PT_LOAD bytes')
            image[address] = value
    selected, coverage = [], {}
    for row in root_rows:
        kind, address, bits = row['kind'], row['address'], row['bits']
        require(type(address) is int and type(bits) is int, 'Producer goal encoding')
        if kind == 'target':
            require(address == elf['entry'] and bits == 32, 'Target producer identity')
            expected = elf['entry']
        else:
            require(kind in ('elf_entry_byte', 'target_fetch_byte', 'restored_image_byte')
                    and address in image and bits == 8, 'Image producer identity')
            if kind == 'elf_entry_byte':
                require(0x08048018 <= address < 0x0804801c, 'ELF entry producer address')
            if kind == 'target_fetch_byte':
                require(elf['entry'] <= address < elf['entry'] + 15, 'Target fetch producer address')
            expected = image[address]
        addresses = coverage.setdefault(kind, set())
        require(address not in addresses and row['known'] == (1 << bits) - 1,
                'Duplicate or unknown producer goal')
        addresses.add(address)
        selected.append({'id': row['id'], 'offset': row['offset'], 'bits': bits,
                         'expected': expected, 'label': kind, 'address': address})
    require(coverage.get('target') == {elf['entry']}
            and coverage.get('elf_entry_byte') == set(range(0x08048018, 0x0804801c))
            and coverage.get('restored_image_byte') == image.keys()
            and coverage.get('target_fetch_byte'), 'Incomplete image/entry producer coverage')
    nodes = {}
    for node in catalogue:
        key = node['pc'], node['original_ir_sha256']
        modeled = node.get('ir_semantics_modeled') is True and node.get('lift_status') == 0
        explicit_kernel = (key[0] in kernel_pcs and node.get('opaque_syscall') is True
            and node.get('ir_semantics_modeled') is False and node.get('lift_status') == 1
            and node.get('bytes') == 'cd80' and node.get('size') == 2
            and node.get('ir_instructions') == 0 and node.get('instructions') == []
            and node.get('kernel_boundary_kind') == 'UNMODELED_INT80_EXPLICIT_CONTRACT_REQUIRED'
            and node.get('boundary_resume_pc') == key[0] + 2)
        require(key not in nodes and node.get('ir_validator_passed') is True
                and (modeled or explicit_kernel)
                and verifier.digest(node['original_ir_dump'].encode()) == key[1],
                'Fresh IR catalogue identity')
        nodes[key] = node
    seen, code_bytes, repeats = set(), 0, 0
    for origin in origins:
        key = origin['pc'], origin['original_ir_sha256']
        require(key in nodes and key not in seen and type(origin['first_step']) is int
                and 0 < origin['first_step'] <= instructions, 'Instruction producer identity')
        seen.add(key)
        node = nodes[key]
        encoded = bytes.fromhex(node['bytes'])
        require(origin['bytes_hex'] == node['bytes'] and len(encoded) == node['size']
                and 0 < len(encoded) <= 15 and len(origin['fetch_roots']) == len(encoded),
                'Instruction producer bytes differ from fresh catalogue')
        for index, (root, value) in enumerate(zip(origin['fetch_roots'], encoded)):
            selected.append({'id': root, 'offset': 0, 'bits': 8, 'expected': value,
                             'label': 'instruction_fetch_byte', 'address': key[0] + index})
            code_bytes += 1
        repeat = node['repeat_expansion_iterations']
        require(origin['repeat_iterations'] == (-1 if repeat is None else repeat), 'REP expansion identity')
        if repeat is not None:
            selected.append({'id': origin['repeat_root'], 'offset': 0, 'bits': 32,
                             'expected': repeat, 'label': 'REP_expansion_count', 'address': key[0]})
            repeats += 1
        else:
            require(origin['repeat_root'] == 0, 'Unexpected REP producer')
    require(seen == nodes.keys() and seen, 'Incomplete instruction producer coverage')
    return selected, {'reference_image_bytes': len(image), 'instruction_variants': len(seen),
                      'instruction_fetch_bytes': code_bytes, 'REP_expansion_counts': repeats}


def prove_chunks(solver, output, *, chunk_size=4096):
    """Prove a topological induction; evaluated values are conjectures, not axioms."""
    require(type(chunk_size) is int and 0 < chunk_size <= 4096, 'SMT chunk budget')
    started = time.monotonic()
    evaluation = output / 'evaluation.json'
    values_path = output / 'values.bin'
    with (output / 'evaluation.log').open('wb') as log:
        process = subprocess.run([str(solver), '--evaluate', str(output / 'slice.bin'),
            str(output / 'source-premises.txt'), str(values_path), str(evaluation)],
            stdout=log, stderr=subprocess.STDOUT, timeout=180)
    evaluated = verifier.strict_json(evaluation.read_bytes())
    require(process.returncode == 0 and evaluated.get('status') == 'EVALUATED',
            'Intermediate conjectures could not be evaluated with existing IR evaluator')
    data = (output / 'slice.bin').read_bytes()
    require(data[:16] == HEADER and (len(data) - 16) % 32 == 0, 'Compact producer framing')
    nodes = [RECORD.unpack_from(data, offset) for offset in range(16, len(data), 32)]
    raw = values_path.read_bytes()
    require(raw[:16] == b'TFVALUES' + struct.pack('<II', 1, len(nodes))
            and len(raw) == 16 + 8 * len(nodes), 'Intermediate conjecture framing')
    values = [0] + [v[0] for v in struct.iter_unpack('<Q', raw[16:])]
    goal_fields = [line.split() for line in (output / 'goals.txt').read_text().splitlines()]
    require(all(len(fields) == 2 for fields in goal_fields), 'Final proof goal framing')
    goals = [tuple(int(v, base) for v, base in zip(fields, (10, 16))) for fields in goal_fields]
    require(goals and all(len(g) == 2 and 0 < g[0] <= len(nodes) for g in goals), 'Final proof goals')
    source_rows = [(i, r) for i, r in enumerate(nodes, 1) if 100 <= r[0] <= 109]
    require(source_rows and all(values[i] == r[5] for i, r in source_rows), 'Evaluated original source differs')
    chain, checks, blocks, finals = '0' * 64, 0, 0, 0
    source_baseline = None
    reports = output / 'chunk-reports.jsonl'
    with tempfile.TemporaryDirectory(prefix='tf-smt-chunks-') as temporary, reports.open('w') as journal:
        work = Path(temporary)

        def query(rows, bindings, conclusions, phase, lo, hi):
            nonlocal chain, checks
            require(time.monotonic() - started < 1800, 'SMT induction time budget')
            if not bindings:
                # A constant-only block still has the authenticated input context.
                rows.append(source_rows[0][1])
                bindings = [(len(rows), source_rows[0][1][5])]
            ledger = HEADER + b''.join(RECORD.pack(*r) for r in rows)
            premises = ''.join(f'{i} {v:x} {(1 << rows[i - 1][1]) - 1:x}\n' for i, v in bindings).encode()
            expected = ''.join(f'{i} {v:x}\n' for i, v in conclusions).encode()
            (work / 'slice.bin').write_bytes(ledger)
            (work / 'inputs.txt').write_bytes(premises)
            (work / 'goals.txt').write_bytes(expected)
            (work / 'report.json').unlink(missing_ok=True)
            (work / 'solver.log').unlink(missing_ok=True)
            command = [str(solver), *(['--lemma-chunk'] if phase != 'original_sources' else []),
                       str(work / 'slice.bin'), str(work / 'inputs.txt'), str(work / 'goals.txt'),
                       str(work / 'report.json')]
            with (work / 'solver.log').open('wb') as log:
                result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, timeout=300)
            report = verifier.strict_json((work / 'report.json').read_bytes())
            receipt = {'phase': phase, 'first_node': lo, 'last_node': hi,
                       'ledger_sha256': verifier.digest(ledger), 'premises_sha256': verifier.digest(premises),
                       'goals_sha256': verifier.digest(expected), 'previous_receipt_sha256': chain, 'solver': report}
            encoded = verifier.json.dumps(receipt, sort_keys=True, separators=(',', ':'))
            chain = verifier.digest(encoded.encode())
            journal.write(encoded + '\n')
            journal.flush()
            require(result.returncode == 0 and report.get('status') == 'PROVED'
                    and report.get('baseline', {}).get('status') == 'SAT'
                    and report.get('counterexample', {}).get('status') == 'UNSAT',
                    'SMT induction failed in ' + phase + '; inspect chunk-reports.jsonl')
            checks += report['baseline']['solver_checks'] + report['counterexample']['solver_checks']
            return report

        # Establish consistency of the complete authenticated original input set.
        require(len(source_rows) <= 16384, 'Joint original-source SAT budget')
        bindings = [(i, r[5]) for i, (_, r) in enumerate(source_rows, 1)]
        source_baseline = query([r for _, r in source_rows], bindings, bindings,
                                'original_sources', source_rows[0][0], source_rows[-1][0])
        proved = 0
        for start in range(0, len(nodes), chunk_size):
            stop = min(start + chunk_size, len(nodes))
            boundary = set()
            for r in nodes[start:stop]:
                if r[0] < 100:
                    require(r[0] in ARITY, 'Unsupported induction operation')
                    boundary.update(p for p in r[2:2 + ARITY[r[0]]] if p <= start)
            require(proved == start and all(0 < p <= proved for p in boundary), 'Unproved boundary lemma')
            ordered = sorted(boundary)
            mapping = {old: new for new, old in enumerate(ordered, 1)}
            rows, bindings = [], []
            for old in ordered:
                r = nodes[old - 1]
                rows.append((110, r[1], old, 0, 0, values[old], r[6]))
                bindings.append((len(rows), values[old]))
            for old in range(start + 1, stop + 1):
                r = nodes[old - 1]
                require(0 <= values[old] < 1 << r[1], 'Intermediate conjecture width')
                if 100 <= r[0] <= 109:
                    # These exact source equalities were proved jointly above.
                    row = (110, r[1], old, 0, 0, values[old], r[6])
                else:
                    require(r[0] in ARITY, 'Unsupported induction source')
                    row = (*r[:2], *(mapping.get(p, 0) for p in r[2:5]), *r[5:])
                rows.append(row)
                mapping[old] = len(rows)
                if 100 <= r[0] <= 109:
                    bindings.append((len(rows), r[5]))
            query(rows, bindings, [(mapping[i], values[i]) for i in range(start + 1, stop + 1)],
                  'producer_induction', start + 1, stop)
            proved = stop  # Advance only after the actual SAT/UNSAT checks passed.
            blocks += 1
            if blocks % 256 == 0 or proved == len(nodes):
                print(f'SMT: proved producer nodes {proved}/{len(nodes)}', flush=True)
        for start in range(0, len(goals), chunk_size):
            part = goals[start:start + chunk_size]
            rows = [(110, nodes[old - 1][1], old, 0, 0, values[old], nodes[old - 1][6]) for old, _ in part]
            bindings = [(i, values[old]) for i, (old, _) in enumerate(part, 1)]
            conclusions = [(i, expected) for i, (_, expected) in enumerate(part, 1)]
            query(rows, bindings, conclusions, 'independent_reference_goals', start, start + len(part))
            finals += 1
    result = {'schema_version': 1, 'status': 'PROVED', 'proof_mode': 'TOPOLOGICAL_SMT_INDUCTION',
              'producer_nodes': len(nodes), 'source_premises': len(source_rows), 'goals': len(goals),
              'producer_chunks_proved': blocks, 'reference_chunks_proved': finals, 'solver_checks': checks,
              'baseline': {'status': 'SAT', 'kind': 'authenticated_original_sources'},
              'counterexample': {'status': 'UNSAT', 'kind': 'all_induction_and_reference_queries'},
              'values_sha256': file_digest(values_path), 'chunk_reports_sha256': file_digest(reports),
              'last_receipt_sha256': chain, 'intermediate_values_admitted_without_SMT_proof': False,
              'observed_checkpoint_used_as_premise': False, 'model_built_by_existing_ir_smt': True,
              'z3_version': source_baseline['z3_version'], 'duration_seconds': time.monotonic() - started}
    verifier.save(output / 'solver.json', result)
    return result


def prove_capture(capture, output, *, max_nodes=2_000_000, prove_schedule=False):
    sources = output / 'source'
    sources.mkdir()
    for name in ('oep_smt.py', 'oep_verify.py', 'oep_current_run.py', 'oep_observations.py',
                 'oep_entry.py', 'oep_environment.py', 'oep_boundary.py'):
        (sources / name).write_bytes((ROOT / name).read_bytes())
    if prove_schedule:
        (sources / 'oep_schedule.py').write_bytes((ROOT / 'oep_schedule.py').read_bytes())
    with verifier.Evidence(evidence_path(capture)) as evidence:
        certificate = evidence.json('certificate.json')
        require(certificate.get('status') == 'CONFIRMED_REFERENCE_ENTRY_FOR_OBSERVED_RUN_UNDER_TRUSTED_MODELS'
                and certificate.get('oep_confirmed_for_observed_run_under_trusted_models') is True,
                'Successful reference-entry capture required')
        launch = evidence.json('launch.json')
        raw = evidence.read('capture/events.jsonl')
        rows = read_capture(raw, launch)
        packed, original = evidence.read('inputs/source.elf'), evidence.read('inputs/original.elf')
        require(verifier.digest(packed) == verifier.ELF_SHA and verifier.digest(original) == verifier.ORIGINAL_SHA,
                'Selected original/packed ELF identity differs')
        projection = evidence.read('reduced/projection.bin')
        receipt = {'input_evidence_sha256': evidence.sha256, 'run_id': launch['run_id']}
    current.initial_elf_observations(rows, packed)
    observations = audit_observations(rows, launch, elf=packed, projection=projection)
    environment = audit_environment(rows, observations['process_profile'], observations['effect_observations'])
    verifier.save(output / 'input-evidence.json', receipt)
    verifier.save(output / 'observations.json', observations)
    verifier.save(output / 'environment.json', environment)
    (output / 'events.jsonl').write_bytes(raw)
    verifier.save(output / 'launch.json', launch)
    inputs = output / 'inputs'
    inputs.mkdir()
    initial = verifier.one(rows, 'initial')['registers']
    stack = bytes.fromhex(verifier.one(rows, 'snapshot', 'initial_stack')['bytes_hex'])
    require(len(stack) == len(projection) == verifier.STACK_SIZE, 'Producer entry stack extent')
    scalars = f"{initial['esp']:x} {(initial['eflags'] >> 10) & 1:x}\n".encode()
    values = {'source.elf': packed, 'original.elf': original, 'stack.bin': bytes(v & k for v, k in zip(stack, projection)),
              'stack-mask.bin': projection, 'scalars.txt': scalars, 'contracts.txt': current.contracts_text(rows).encode()}
    for name, value in values.items():
        (inputs / name).write_bytes(value)
    require(shutil.disk_usage(output).free >= 12 * 1024**3, 'Producer replay needs 12 GiB free scratch space')
    binary = verifier.build_replay(ROOT / 'test', output / 'native-replay')
    replay, ledger = output / 'replay', output / 'producers'
    replay.mkdir()
    command = [str(binary), *[str(inputs / n) for n in
               ('source.elf', 'stack.bin', 'stack-mask.bin', 'scalars.txt', 'contracts.txt')], str(replay)]
    print('SMT: deriving producer expressions from the original entry', flush=True)
    with (replay / 'execution.json').open('wb') as stdout, (replay / 'stderr').open('wb') as stderr:
        result = subprocess.run(command, stdout=stdout, stderr=stderr, timeout=1800,
                                env={**os.environ, 'TF_OEP_PRODUCERS': str(ledger), 'TF_OEP_PRODUCER_LIMIT': '268435456'})
    require(result.returncode == 0, 'Producer replay failed; inspect ' + str(replay / 'stderr'))
    execution, regions, comparisons = current.compare_execution(rows, replay)
    require((replay / 'projection.bin').read_bytes() == projection, 'Fresh producer input projection differs')
    current.compare_initial_reads(rows, replay / 'initial-reads.jsonl')
    kernel = current.compare_kernel(rows, replay)
    verifier.save(output / 'kernel-comparison.json', kernel)
    verifier.save(output / 'comparison.json', comparisons)
    catalogue = list(current.json_lines(replay / 'original-ir.jsonl', max_line_bytes=64 * 1024**2))
    boundary_receipt = verifier.strict_json((replay / 'boundary.json').read_bytes())
    last = [n for n in catalogue if n['pc'] == boundary_receipt['transition']['pc']
            and n['original_ir_sha256'] == boundary_receipt['transition']['original_ir_sha256']]
    require(len(last) == 1, 'Unique final transfer IR node')
    final_stack = next(r for r in regions if r['address'] == verifier.STACK_BASE)
    layout = verifier.parse_entry_table(final_stack['data'], verifier.STACK_BASE,
                                       execution['registers'][4]['value'], known_mask=final_stack['known'])
    boundary = verifier.audit_boundary(regions, execution, final_auxv=layout['auxv'], boundary=boundary_receipt,
        last_ir_node=last[0], original_elf=original, image_provenance={
            'source_kind': 'computed_IR_model', 'source_elf_sha256': verifier.ELF_SHA,
            'path_sha256': execution['path_sha256'], 'checkpoint_used_as_seed': False})
    require(boundary['restored_entry_boundary_verified'] is True
            and boundary['original_reference_image_matches'] is True, 'Original entry boundary remains open')
    observed_vmas = current.page_map(observations['payload_vmas'])
    require(all(observed_vmas.get(a) == p for a, p in current.page_map(boundary_receipt['vmas'], 'permissions').items()),
            'Final observed guest permissions differ')
    verifier.save(output / 'boundary.json', boundary)
    manifest = verifier.strict_json((ledger / 'manifest.json').read_bytes())
    require(manifest.get('source_kind') == 'computed_original_entry_IR_producers'
            and manifest.get('checkpoint_used_as_seed') is False
            and manifest.get('observed_final_state_used_as_input') is False
            and manifest.get('path_sha256') == execution['path_sha256']
            and manifest.get('instructions') == execution['instructions'], 'Producer manifest execution binding')
    require(manifest['nodes_sha256'] == file_digest(ledger / 'nodes.bin')
            and manifest['conditions_sha256'] == file_digest(ledger / 'conditions.bin'), 'Producer ledger digest')
    require(manifest['input_files_sha256'] == [verifier.digest(values[n]) for n in
            ('source.elf', 'stack.bin', 'stack-mask.bin', 'scalars.txt', 'contracts.txt')], 'Producer original input binding')
    entry = int.from_bytes(original[24:28], 'little')
    root_rows = list(current.json_lines(ledger / 'goals.jsonl'))
    selected, coverage = producer_goals(original, root_rows,
        current.json_lines(ledger / 'instruction-origins.jsonl'), catalogue, execution['instructions'],
        kernel_pcs={e['pc'] for e, _, _ in _pairs(rows, 26)})
    sliced = slice_ledger(ledger / 'nodes.bin', selected, output / 'slice.bin', max_nodes=max_nodes)
    context = {'packed': packed, 'stack': stack, 'mask': projection, 'esp': initial['esp'],
               'df': initial['eflags'] >> 10 & 1, 'calls': _pairs(rows, 26),
               'initial_regions': current.initial_elf_observations(rows, packed)}
    bindings = []
    for node, record in sliced['source_nodes']:
        value = source_value(record, context)
        bindings.append((node, value, (1 << record[1]) - 1))
    require(bindings and sliced['operation_nodes'] > 0, 'Nontrivial original producer expressions required')
    (output / 'source-premises.txt').write_text(''.join(f'{node} {value:x} {mask:x}\n' for node, value, mask in bindings))
    (output / 'goals.txt').write_text(''.join(f'{node} {value:x}\n' for node, value in sliced['goals']))
    verifier.save(output / 'slice-receipt.json', {'nodes': sliced['nodes'], 'source_leaves': len(bindings),
                  'goals': selected, 'slice_sha256': file_digest(output / 'slice.bin'),
                  'source_premises_sha256': file_digest(output / 'source-premises.txt'),
                  'goals_sha256': file_digest(output / 'goals.txt'), 'producer_ledger_sha256': manifest['nodes_sha256'],
                  'source_values_authenticated': True, 'candidate_relation_added_to_source_premises': False,
                  **coverage, 'instruction_origins_sha256': file_digest(ledger / 'instruction-origins.jsonl')})
    solver = build_solver(output / 'native-smt')
    print('SMT: checking source-premise SAT and image/entry/code counterexample UNSAT', flush=True)
    report = prove_chunks(solver, output)
    require(report.get('status') == 'PROVED'
            and report.get('baseline', {}).get('status') == 'SAT'
            and report.get('counterexample', {}).get('status') == 'UNSAT', 'SMT producer theorem not established')
    result = {'schema_version': 1, 'status': 'SMT_PROVED_ENTRY_PRODUCERS_FOR_VALIDATED_EXECUTION',
              **receipt, 'entry': entry, 'instructions': execution['instructions'], 'path_sha256': execution['path_sha256'],
              'smt_target_entry_and_fetch_proved': True, 'source_premises': len(bindings), 'producer_nodes': sliced['nodes'],
              'SMT_proof_mode': report['proof_mode'], 'SMT_solver_checks': report['solver_checks'],
              'whole_image_reference_comparison': 'SOURCE_BUILT_IR_REPLAY_AND_SMT', 'whole_image_SMT_proved': True,
              'instruction_variant_first_fetch_origins_SMT_proved': True, **coverage,
              'source_premise_query': 'SAT', 'entry_counterexample_query': 'UNSAT',
              'selected_control_alias_and_fetch_schedule_is_explicit_premise': True,
              'all_prefix_schedule_conditions_encoded_in_SMT': False,
              'checkpoint_used_as_seed': False, 'observed_final_state_used_as_input': False,
              'unconditional_oep_proven': False, 'fuzzing_ready': False, 'target_instruction_executed': False,
              'conditions': ['Trusted source-built IR frontend, producer tracking, SMT translation and host build.',
                             'Computed execution, memory-alias and instruction-fetch schedule validated against this capture.',
                             'Explicit original-entry bytes/ESP/DF and kernel contracts; source identities checked.',
                             'Provided original ELF pre-pack provenance remains external.'],
              'oep_proof': 'SMT_ENTRY_DATAFLOW_WITH_VALIDATED_EXECUTION_PREMISES'}
    if prove_schedule:
        try:
            from .oep_schedule import verify_schedule
        except ImportError:
            from oep_schedule import verify_schedule
        schedule = verify_schedule(sys.modules[__name__], ledger, selected, context, output)
        result.update(status='SMT_PROVED_REFERENCE_OEP_FOR_SELECTED_EXECUTION',
            oep_proof='SMT_SELECTED_EXECUTION_TO_REFERENCE_OEP_UNDER_TRUSTED_MODELS',
            selected_control_alias_and_fetch_schedule_is_explicit_premise=False,
            all_prefix_schedule_conditions_encoded_in_SMT=True,
            schedule_condition_count=schedule['condition_count'],
            schedule_unique_condition_goals=schedule['condition_goal_count'],
            schedule_producer_nodes=schedule['proved_nodes'],
            schedule_source_premises=schedule['source_premises'],
            SMT_solver_checks=report['solver_checks'] + schedule['solver_checks'],
            conditions=['Trusted source-built IR frontend, chronological memory model, producer tracking, SMT translation and host build.',
                        'All recorded control, memory-address, fetch, REP, computed-transfer and checked kernel-string conditions are SMT proved.',
                        'Explicit original-entry bytes/ESP/DF and kernel contracts; source identities checked.',
                        'Provided original ELF pre-pack provenance remains external.'])
    verifier.save(output / 'certificate.json', result)
    return result


def archive_results(output):
    excluded = {'nodes.bin', 'conditions.bin', 'oep-execute', 'oep-smt', 'oep-schedule',
                'compact.bin', 'needed.bitset', 'needed.rank', 'condition-goals.bin',
                'oep-evidence.zip', 'evidence-files.json'}
    paths = [p for p in sorted(output.rglob('*')) if p.is_file() and p.name not in excluded and p.suffix != '.o']
    paths = [p for p in paths if p != output / 'schedule/values.bin']
    require(not any(p.is_symlink() for p in output.rglob('*')), 'Proof evidence symlink')
    require(len(paths) <= 256 and sum(p.stat().st_size for p in paths) <= 256 * 1024**2, 'SMT evidence exceeds bound')
    verifier.save(output / 'evidence-files.json', {p.relative_to(output).as_posix(): file_digest(p) for p in paths})
    with zipfile.ZipFile(output / 'oep-evidence.zip', 'w', zipfile.ZIP_DEFLATED) as archive:
        for path in (*paths, output / 'evidence-files.json'):
            archive.write(path, path.relative_to(output).as_posix())


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--capture', required=True, type=Path)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--prove-schedule', action='store_true',
                        help='Also prove every recorded selected-execution condition with streaming SMT induction')
    args = parser.parse_args(argv)
    output = args.output.resolve() if args.output else Path(tempfile.mkdtemp(prefix='oep-smt.', dir=ROOT)) / 'probe'
    output.mkdir(parents=True, exist_ok=False)
    print('Results:', output, flush=True)
    summary = {'schema_version': 1, 'status': 'FAIL', 'errors': [], 'oep_proof': 'NOT_ESTABLISHED',
               'unconditional_oep_proven': False, 'target_instruction_executed': False}
    try:
        summary.update(prove_capture(args.capture, output, prove_schedule=args.prove_schedule))
        print(summary['status'], flush=True)
    except (ValueError, OSError, KeyError, TypeError, RecursionError, subprocess.SubprocessError,
            zipfile.BadZipFile) as error:
        summary['errors'].append(type(error).__name__ + ': ' + str(error))
        print('FAIL:', summary['errors'][-1], flush=True)
    finally:
        verifier.save(output / 'summary.json', summary)
    archive_results(output)
    print('Evidence:', output / 'oep-evidence.zip', flush=True)
    return 0 if not summary['errors'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
