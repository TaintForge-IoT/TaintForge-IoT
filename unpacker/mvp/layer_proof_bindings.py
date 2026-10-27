"""Bind fresh layered replay claims without treating observations as premises.

This module checks capture/replay identities and proof scope. Actual SMT queries
are performed by the existing source-built generic producer/schedule pipeline.
It never grants a theorem from receipt consistency alone.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

try:
    from .ct_elf import validate_stage_selection
except ImportError:
    from ct_elf import validate_stage_selection


PAGE = 4096
MAX_EVENTS = 128 * 1024**2
MAX_LINE = 5 * 1024**2
MAX_STEPS = 1_000_000
GPRS = ('eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi')
FLAG_BITS = (0, 2, 4, 6, 7, 11, 10)
SMT_STATUS = 'SMT_PROVED_SELECTED_TRANSFER_AND_OBSERVED_IMAGE_UNDER_EXPLICIT_PREMISES'


class LayerBindingError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise LayerBindingError(message)


def uint(value, label, maximum=0xffffffff):
    require(type(value) is int and 0 <= value <= maximum, label)
    return value


def sha(value, label):
    require(type(value) is str and len(value) == 64 and
            all(character in '0123456789abcdef' for character in value), label)
    return value


def strict_json(raw):
    def pairs(items):
        output = {}
        for key, value in items:
            require(key not in output, 'Duplicate JSON key: ' + key)
            output[key] = value
        return output

    def invalid(value):
        raise LayerBindingError('Noninteger or nonfinite JSON number: ' + value)

    return json.loads(raw, object_pairs_hook=pairs, parse_float=invalid, parse_constant=invalid)


def hex_bytes(value, label, maximum=MAX_LINE // 2):
    require(type(value) is str and len(value) % 2 == 0 and len(value) <= maximum * 2,
            label + ' extent')
    try:
        data = bytes.fromhex(value)
    except ValueError as error:
        raise LayerBindingError(label + ' encoding') from error
    require(data.hex() == value, label + ' noncanonical encoding')
    return data


def json_lines(path):
    path = Path(path)
    require(path.is_file() and not path.is_symlink() and 0 < path.stat().st_size <= MAX_EVENTS,
            'Missing, symlink or oversized event file')
    raw = path.read_bytes()
    lines = raw.splitlines(keepends=True)
    require(lines and all(line.endswith(b'\n') and len(line) <= MAX_LINE for line in lines),
            'Invalid event framing')
    rows = [strict_json(line) for line in lines]
    require(all(type(row) is dict for row in rows), 'Event row must be an object')
    return raw, lines, rows


def select_stage_ancestry(report):
    """Return only the selected leaf's observed ancestors, in execution order.

    The caller first validates and pins the genuine capture/dump and packed ELF.
    This relation is a selection claim for a fresh proof, never inherited proof.
    Later independent candidates, such as the helper control, are excluded.
    """
    require(type(report) is dict, 'Stage capture must be an object')
    validate_stage_selection(report)
    nodes = report.get('observed_stage_candidates')
    require(type(nodes) is list and nodes, 'Source-bound observed stage inventory required')
    by_id = {row['candidate_id']: row for row in nodes}
    selected = [row for row in nodes if row['selected']]
    require(len(selected) == 1, 'Exactly one observed selected leaf required')
    selected = selected[0]
    stages, seen, current = [], set(), selected
    while current is not None:
        ident = current['candidate_id']
        require(ident not in seen and len(seen) < 10000, 'Cyclic or oversized stage ancestry')
        stages.append(dict(current)); seen.add(ident)
        parent = current['parent_candidate_id']
        require(not parent or parent in by_id, 'Missing stage ancestor')
        current = by_id.get(parent)
    stages.reverse()
    require(stages[-1]['candidate_id'] == selected['candidate_id'] and
            all(left['entry_seq'] < right['entry_seq'] for left, right in zip(stages, stages[1:])),
            'Stage ancestry is not chronological')
    return {
        'stages': stages, 'selected_id': selected['candidate_id'],
        'selected_target': selected['address'],
        'covered_prefix_candidate_ids': [row['candidate_id'] for row in stages],
        'excluded_nonancestor_ids': [row['candidate_id'] for row in nodes if row['candidate_id'] not in seen],
        'excluded_postselected_ids': [row['candidate_id'] for row in nodes
                                     if row['entry_seq'] > selected['entry_seq']],
        'selection_only': True, 'previous_proof_status_inherited': False,
        'historical_originality_proven': False,
    }


def _loader(packed):
    require(type(packed) is bytes, 'Packed source must be immutable bytes')
    try:
        from ..unpack_sources import loader_regions
    except ImportError:
        from unpack_sources import loader_regions
    return loader_regions(packed)


def _registers(row, label):
    require(type(row) is dict and set(row) == {*GPRS, 'eflags'}, label + ' register inventory')
    for key in (*GPRS, 'eflags'):
        uint(row[key], label + ' ' + key)
    return row


def _permissions(loader, initial):
    result = {}
    for region in loader['protections']:
        for address in range(region['start'], region['end'], PAGE):
            result[address] = region['prot']
    for address in range(initial['stack_base'], initial['stack_base'] + initial['stack_size'], PAGE):
        require(address not in result, 'Entry stack overlaps source ELF')
        result[address] = loader['stack_prot']
    return result


def _protect(permissions, args):
    address, size, prot = args[:3]
    require(address % PAGE == 0 and 0 < size <= 1024**2 and prot <= 7 and
            address + size <= 2**32, 'Unsupported mprotect geometry')
    end = (address + size + PAGE - 1) // PAGE * PAGE
    for page in range(address, end, PAGE):
        require(page in permissions, 'mprotect touches an unconstructed mapping')
        permissions[page] = prot


def _mapping_transition(number, args, mmap_args, result, ordinal, permissions,
                        epochs, generations, protected_pages):
    """Apply only the explicit, bounded V3 anonymous-memory contract profile.

    A failed MAP_FIXED or mprotect need not leave Linux VMAs unchanged.  Only
    the specified EINVAL preflight failures are admitted as no-effect calls.
    """
    none = dict(operation='none', address=0, size=0, prot=0, mapping_epoch=0,
                zero_fill_sha256=None)
    effective = mmap_args if number in (90, 192) else args
    if number in (90, 192):
        require(effective[1] <= 1024**2 and effective[2] <= 7 and effective[2] & 1 and
                effective[3] in (0x22, 0x32) and effective[4] == 0xffffffff and effective[5] == 0,
                'Unsupported anonymous mapping profile, including failed requests')
    else:
        require(args[1] <= 1024**2 and (number != 125 or args[2] <= 7),
                'Unsupported memory-operation profile, including failed requests')
    if result >= 0xfffff001:
        invalid = ((number in (90, 192) and
                    (effective[1] == 0 or effective[3] & 16 and effective[0] % PAGE != 0)) or
                   (number == 91 and (args[1] == 0 or args[0] % PAGE != 0)) or
                   (number == 125 and args[0] % PAGE != 0))
        require(result == 0xffffffea and invalid,
                'Only verified EINVAL preflight failures have no modeled effects')
        return none
    if number in (90, 192):
        address, size, prot, flags, fd, offset = effective
        rounded = (size + PAGE - 1) // PAGE * PAGE
        require(0 < size <= 1024**2 and 0 < rounded <= 1024**2 and
                prot <= 7 and prot & 1 and flags in (0x22, 0x32) and
                fd == 0xffffffff and offset == 0 and result >= 0x10000 and
                result % PAGE == 0 and result + rounded <= 2**32 and
                (not flags & 16 or result == address),
                'Unsupported successful anonymous mapping contract')
        pages = range(result, result + rounded, PAGE)
        require(all(page not in protected_pages for page in pages),
                'Anonymous replacement touches protected source ELF or entry stack')
        require(flags & 16 or all(page not in permissions for page in pages),
                'Nonfixed anonymous mapping overlaps a live mapping')
        for page in pages:
            permissions[page] = prot
            epochs[page] = ordinal
            generations.pop(page, None)
        return dict(operation='map', address=result, size=rounded, prot=prot,
                    mapping_epoch=ordinal,
                    zero_fill_sha256=hashlib.sha256(bytes(rounded)).hexdigest())
    require(result == 0, 'Unexpected successful memory-operation result')
    address, size = args[:2]
    rounded = (size + PAGE - 1) // PAGE * PAGE
    require(address % PAGE == 0 and 0 < size <= 1024**2 and
            address + rounded <= 2**32, 'Unsupported successful memory-operation geometry')
    pages = range(address, address + rounded, PAGE)
    if number == 91:
        require(all(page not in protected_pages for page in pages),
                'Unmap touches protected source ELF or entry stack')
        for page in pages:
            permissions.pop(page, None)
            epochs.pop(page, None)
            generations.pop(page, None)
        return dict(operation='unmap', address=address, size=rounded, prot=0,
                    mapping_epoch=0, zero_fill_sha256=None)
    require(number == 125 and args[2] <= 7 and
            all(page in permissions for page in pages),
            'Protection change requires a complete constructed mapping')
    _protect(permissions, args)
    return dict(operation='protect', address=address, size=rounded, prot=args[2],
                mapping_epoch=0, zero_fill_sha256=None)


def _same_mapping_effect(actual, expected):
    return (type(actual) is dict and set(actual) == set(expected) and
            all(type(actual[key]) is type(value) and actual[key] == value
                for key, value in expected.items()))


def _file_transition(number, args, mmap_args, result, ordinal, permissions,
                     epochs, generations, protected_pages, descriptors, backing, packed):
    """Construct the V4 source-file effect independently of observed RAM.

    File 0 is the immutable packed ELF. A descriptor lifetime is separate
    from a mapping lifetime: closing/reusing an fd leaves older PRIVATE
    mappings and their backing metadata intact.
    """
    none = dict(operation='none', address=0, size=0, prot=0, mapping_epoch=0,
                zero_fill_sha256=None)
    require(type(packed) is bytes and 0 < len(packed) <= 1024**2,
            'Unsupported immutable packed-file size')
    source_sha = hashlib.sha256(packed).hexdigest()
    file_mapping = file_descriptor = constructor = None
    if number == 5:
        require(args[1] == 0 and 3 <= result < 64 and result not in descriptors,
                'Only a fresh read-only packed-source descriptor is admitted')
        descriptors[result] = ordinal
        file_descriptor = dict(operation='open', fd=result, file_id=0,
            descriptor_epoch=ordinal, file_size=len(packed), source_sha256=source_sha)
        return none, file_mapping, file_descriptor, constructor
    if number == 6:
        fd = args[0]
        require(fd in descriptors and result == 0, 'Unsupported close descriptor contract')
        file_descriptor = dict(operation='close', fd=fd, file_id=0,
            descriptor_epoch=descriptors[fd], file_size=len(packed), source_sha256=source_sha)
        del descriptors[fd]
        return none, file_mapping, file_descriptor, constructor
    effective = mmap_args if number in (90, 192) else args
    file_map = number in (90, 192) and not effective[3] & 32
    if file_map:
        address, size, prot, flags, fd, offset = effective
        byte_offset = offset * (PAGE if number == 192 else 1)
        rounded = (size + PAGE - 1) // PAGE * PAGE
        require(size <= 1024**2 and prot <= 7 and prot & 1 and flags in (2, 0x12) and
                fd in descriptors and byte_offset <= 0xffffffff,
                'Unsupported PRIVATE packed-source mapping profile')
        invalid = not size or flags & 16 and address % PAGE != 0 or byte_offset % PAGE != 0
        if result >= 0xfffff001:
            require(result == 0xffffffea and invalid,
                    'Only file-map EINVAL preflight failures have no modeled effects')
            return none, file_mapping, file_descriptor, constructor
        capacity = (len(packed) + PAGE - 1) // PAGE * PAGE
        require(not invalid and 0 < rounded <= 1024**2 and result >= 0x10000 and
                result % PAGE == 0 and result + rounded <= 2**32 and
                (not flags & 16 or result == address) and
                byte_offset + rounded <= capacity,
                'File-map result, offset or EOF extent is unsupported')
        pages = range(result, result + rounded, PAGE)
        require(all(page not in protected_pages for page in pages) and
                (flags & 16 or all(page not in permissions for page in pages)),
                'File mapping replaces a protected or live nonfixed mapping')
        copied = min(rounded, len(packed) - byte_offset)
        require(copied > 0, 'A whole page beyond EOF cannot supply file or zero bytes')
        constructor = packed[byte_offset:byte_offset + copied] + bytes(rounded - copied)
        file_mapping = dict(fd=fd, file_id=0, descriptor_epoch=descriptors[fd],
            file_size=len(packed), file_offset=byte_offset, file_bytes=copied,
            zero_tail_bytes=rounded - copied,
            initial_bytes_sha256=hashlib.sha256(constructor).hexdigest())
        for page in pages:
            permissions[page] = prot
            epochs[page] = ordinal
            generations.pop(page, None)
            backing[page] = (0, byte_offset + page - result, descriptors[fd])
        return dict(operation='map', address=result, size=rounded, prot=prot,
                    mapping_epoch=ordinal, zero_fill_sha256=None), file_mapping, file_descriptor, constructor
    effect = _mapping_transition(number, args, mmap_args, result, ordinal,
                                 permissions, epochs, generations, protected_pages)
    if effect['operation'] in ('map', 'unmap'):
        for page in range(effect['address'], effect['address'] + effect['size'], PAGE):
            if effect['operation'] == 'map':
                backing[page] = (-1, 0, 0)
            else:
                backing.pop(page, None)
    if effect['operation'] == 'map':
        constructor = bytes(effect['size'])
    return effect, file_mapping, file_descriptor, constructor


def _same_optional_file_effect(actual, expected):
    if expected is None:
        return actual is None
    return _same_mapping_effect(actual, expected)


def _mutable_file_state(packed, version=5):
    """An audit ledger reconstructed from source bytes and syscall observations.

    Its data never enters the original-entry interpreter or its producer graph.
    Replay has to compute independently the same constructor and write results.
    """
    require(type(packed) is bytes and 0 < len(packed) <= 1024**2,
            'Unsupported mutable-profile packed source')
    capacity = (len(packed) + PAGE - 1) // PAGE * PAGE
    return {'files': {0: dict(size=len(packed), capacity=capacity,
                             data=bytearray(packed + bytes(capacity-len(packed))),
                             content_epoch=0, guest_generations={}, tail_dirty=False)}, 'next_file': 1, 'version': version, 'shared': {}}


def _mutable_name(entry):
    name = hex_bytes(entry.get('name_hex'), 'Memfd name', 64)
    require(0 < len(name) <= 64 and name[-1] == 0 and 0 not in name[:-1],
            'Memfd name lacks a bounded unique terminator')
    return name


def _observed_write(entry):
    args, buffer = entry['args'], entry.get('write_buffer')
    require(type(buffer) is dict and set(buffer) == {'address', 'size', 'data_hex'} and
            type(buffer['address']) is int and buffer['address'] == args[1] and
            type(buffer['size']) is int and buffer['size'] == args[2] and
            args[2] <= 1024**2 and args[1] + args[2] <= 2**32,
            'Observed write buffer identity or bound differs')
    data = hex_bytes(buffer['data_hex'], 'Observed pre-write bytes', 1024**2)
    require(len(data) == args[2], 'Observed write buffer extent differs')
    return data


def _shared_generations(file_id, state, backing, generations):
    """Rebuild each shared alias generation from its file-byte last writers."""
    file = state['files'][file_id]
    for page, identity in backing.items():
        if identity[0] == file_id and state['shared'].get(page) is True:
            backing[page] = (*identity[:3], file['content_epoch'])
            low = identity[1]
            generations[page] = max((value for offset, value in file['guest_generations'].items()
                                     if low <= offset < low+PAGE), default=0)


def _mutable_store(row, state, backing, generations):
    """Reconstruct an observed shared write for comparison, never as a premise."""
    require(state['version'] >= 6 and 'shared_file_write' in row,
            'Missing V6 shared-store effect')
    address, size = row['address'], row['size']
    first_page = address // PAGE * PAGE
    shared = state['shared'].get(first_page, False)
    effect = row['shared_file_write']
    if not shared:
        require(effect is None and all(not state['shared'].get(page, False)
                for page in range(first_page, (address+size+PAGE-1)//PAGE*PAGE, PAGE)),
                'Ordinary store cannot supply a shared-file write')
        return
    require(type(effect) is dict and set(effect) == {'file_id', 'file_offset', 'data_hex'},
            'Shared store effect shape differs')
    file_id = uint(effect.get('file_id'), 'Shared store file identity', 31)
    offset = uint(effect.get('file_offset'), 'Shared store file offset', 1024**2)
    data = hex_bytes(effect.get('data_hex'), 'Shared store observed bytes', 16)
    require(file_id > 0 and file_id in state['files'] and len(data) == size and
            all(state['shared'].get((address+i)//PAGE*PAGE) is True and
                backing.get((address+i)//PAGE*PAGE, ())[:2] ==
                (file_id, offset+i-(address+i)%PAGE) for i in range(size)),
            'Shared store backing or extent differs')
    file = state['files'][file_id]
    limit = (file['size']+PAGE-1)//PAGE*PAGE if state['version'] == 7 else file['size']
    require(offset+size <= limit and
            all(identity[0] != file_id or state['shared'].get(page) is True
                for page, identity in backing.items()),
            'Shared store crosses supported cache extent or a live PRIVATE alias')
    if state['version'] == 7 and offset+size > file['size']:
        file['tail_dirty'] = True
    file['data'][offset:offset+size] = data
    file['guest_generations'].update({offset+i: row['store_ordinal'] for i in range(size)})
    _shared_generations(file_id, state, backing, generations)


def _mutable_transition(entry, result, permissions, epochs, generations,
                        protected_pages, descriptors, backing, state, packed):
    """Audit V5 effects, without admitting observed mutable bytes as sources."""
    number, args, ordinal = entry['number'], entry['args'], entry['ordinal']
    require(type(number) is int and type(ordinal) is int and 1 <= ordinal <= 256 and
            type(args) in (list, tuple) and len(args) == 6 and
            all(type(value) is int and 0 <= value <= 0xffffffff for value in args) and
            type(result) is int and 0 <= result <= 0xffffffff,
            'Mutable call scalar identity')
    none = dict(operation='none', address=0, size=0, prot=0,
                mapping_epoch=0, zero_fill_sha256=None)
    files = state['files']
    mapped = descriptor = mutation = constructor = None
    if number in (5, 356):
        require(3 <= result < 64 and result not in descriptors,
                'Mutable profile fresh descriptor identity')
        if number == 5:
            require(args[1] == 0 and entry.get('path_hex') == b'/proc/self/exe\0'.hex(),
                    'Mutable profile only opens the immutable source')
            file_id, operation = 0, 'open'
        else:
            require(args[1] in ((0, 1, 16, 17) if state['version'] >= 6 else (0, 1)),
                    'Unsupported memfd flags')
            _mutable_name(entry)
            file_id, operation = state['next_file'], 'memfd_create'
            require(1 <= file_id < 32, 'Mutable file inventory budget')
            files[file_id] = dict(size=0, capacity=0, data=bytearray(), content_epoch=ordinal,
                                  guest_generations={}, tail_dirty=False)
            state['next_file'] += 1
        descriptors[result] = dict(file_id=file_id, descriptor_epoch=ordinal, cursor=0)
        descriptor = dict(operation=operation, fd=result, file_id=file_id,
            descriptor_epoch=ordinal, file_size=files[file_id]['size'],
            source_sha256=hashlib.sha256(packed).hexdigest() if file_id == 0 else None)
        return none, mapped, descriptor, mutation, constructor
    if number == 6:
        fd = args[0]
        require(fd in descriptors and result == 0, 'Mutable close identity')
        handle = descriptors.pop(fd)
        file_id = handle['file_id']
        descriptor = dict(operation='close', fd=fd, file_id=file_id,
            descriptor_epoch=handle['descriptor_epoch'], file_size=files[file_id]['size'],
            source_sha256=hashlib.sha256(packed).hexdigest() if file_id == 0 else None)
        return none, mapped, descriptor, mutation, constructor
    if number in (4, 93, 19):
        fd = args[0]
        require(fd in descriptors and descriptors[fd]['file_id'] > 0,
                'Only created memfd objects are mutable')
        handle = descriptors[fd]
        file_id, old_cursor = handle['file_id'], handle['cursor']
        file = files[file_id]
        old_size = file['size']
        if state['version'] == 7 and file['tail_dirty']:
            require(number != 93 and (number != 4 or old_cursor+result <= old_size),
                    'Dirty page-cache tail excludes truncate and file growth')
        if number in (4, 93):
            live = [page for page, identity in backing.items() if identity[0] == file_id]
            require(not live or state['version'] >= 6 and number == 4 and
                    all(state['shared'].get(page) is True for page in live),
                    'File mutation overlaps a live PRIVATE mapping or unsupported truncate')
            if live:
                require(old_cursor + result <= old_size, 'Live shared write cannot grow a file')
        mutation = dict(operation={4: 'write', 93: 'truncate', 19: 'seek'}[number],
            fd=fd, file_id=file_id, descriptor_epoch=handle['descriptor_epoch'],
            content_epoch=file['content_epoch'], old_size=old_size, new_size=old_size,
            offset_before=old_cursor, offset_after=old_cursor,
            write_address=0, write_count=0, zero_start=0, zero_end=0, write_sha256=None)
        if number == 19:
            require(args[2] == 0 and args[1] <= 1024**2 and result == args[1],
                    'Only bounded successful SEEK_SET is admitted')
            handle['cursor'] = result
        elif number == 93:
            require(result == 0 and args[1] <= 1024**2, 'Unsupported ftruncate contract')
            new_size = args[1]
            capacity = max(file['capacity'], (new_size + PAGE - 1) // PAGE * PAGE)
            if len(file['data']) < capacity:
                file['data'].extend(bytes(capacity-len(file['data'])))
            if new_size != old_size:
                file['data'][min(old_size, new_size):capacity] = bytes(capacity-min(old_size, new_size))
                if state['version'] >= 6:
                    for offset in list(file['guest_generations']):
                        if offset >= min(old_size, new_size):
                            file['guest_generations'].pop(offset)
                file['content_epoch'] = ordinal
            file['size'], file['capacity'] = new_size, capacity
            if new_size > old_size:
                mutation.update(zero_start=old_size, zero_end=new_size)
        else:
            data = _observed_write(entry)
            require(result <= len(data) and old_cursor + result <= 1024**2,
                    'Write result exceeds requested buffer or file budget')
            written = data[:result]
            mutation.update(write_address=args[1], write_count=result,
                            write_sha256=hashlib.sha256(written).hexdigest())
            if result:
                new_size = max(old_size, old_cursor+result)
                capacity = max(file['capacity'], (new_size + PAGE - 1) // PAGE * PAGE)
                file['data'].extend(bytes(capacity-len(file['data'])))
                if old_cursor > old_size:
                    mutation.update(zero_start=old_size, zero_end=old_cursor)
                    file['data'][old_size:old_cursor] = bytes(old_cursor-old_size)
                file['data'][old_cursor:old_cursor+result] = written
                if state['version'] >= 6:
                    for offset in range(old_cursor, old_cursor+result):
                        file['guest_generations'].pop(offset, None)
                file['size'], file['capacity'], file['content_epoch'] = new_size, capacity, ordinal
                if state['version'] >= 6:
                    _shared_generations(file_id, state, backing, generations)
                handle['cursor'] += result
        mutation.update(new_size=file['size'], offset_after=handle['cursor'],
                        content_epoch=file['content_epoch'])
        return none, mapped, descriptor, mutation, constructor
    if number == 144:
        address, size, flags = args[:3]
        rounded = (size+PAGE-1)//PAGE*PAGE
        require(state['version'] == 7 and result == 0 and address >= 0x10000 and
                address % PAGE == 0 and 0 < size <= 1024**2 and address+rounded <= 2**32 and flags == 4 and
                all(page in permissions and backing.get(page, (-1,))[0] > 0 and
                    state['shared'].get(page) is True
                    for page in range(address, address+rounded, PAGE)),
                'Only bounded local shared MS_SYNC is admitted')
        return none, mapped, descriptor, mutation, constructor
    effective = entry.get('mmap_args') if number in (90, 192) else args
    file_map = number in (90, 192) and not effective[3] & 32
    if file_map:
        address, size, prot, flags, fd, offset = effective
        byte_offset = offset * (PAGE if number == 192 else 1)
        rounded = (size + PAGE - 1) // PAGE * PAGE
        require(size <= 1024**2 and prot <= 7 and prot & 1 and flags in ((1, 0x11, 2, 0x12) if state['version'] >= 6 else (2, 0x12)) and
                fd in descriptors and byte_offset <= 0xffffffff,
                'Unsupported mutable PRIVATE file mapping')
        invalid = not size or flags & 16 and address % PAGE != 0 or byte_offset % PAGE != 0
        if result >= 0xfffff001:
            require(result == 0xffffffea and invalid, 'Unsupported mutable mapping failure')
            return none, mapped, descriptor, mutation, constructor
        handle = descriptors[fd]
        file_id, file = handle['file_id'], files[handle['file_id']]
        shared = flags & 3 == 1
        require(not shared or state['version'] >= 6 and file_id > 0,
                'Shared mapping requires a local memfd')
        live_capacity = (file['size'] + PAGE - 1) // PAGE * PAGE
        require(not invalid and 0 < rounded <= 1024**2 and result >= 0x10000 and
                result % PAGE == 0 and result + rounded <= 2**32 and
                (not flags & 16 or address == result) and byte_offset < file['size'] and
                byte_offset + rounded <= live_capacity,
                'Mutable mapping offset, EOF or result geometry')
        pages = range(result, result + rounded, PAGE)
        require(all(page not in protected_pages for page in pages) and
                (flags & 16 or all(page not in permissions for page in pages)),
                'Mutable mapping replaces protected or live nonfixed mapping')
        constructor = bytes(file['data'][byte_offset:byte_offset+rounded])
        copied = min(rounded, file['size']-byte_offset)
        mapped = dict(fd=fd, file_id=file_id, descriptor_epoch=handle['descriptor_epoch'],
            content_epoch=file['content_epoch'], file_size=file['size'], file_offset=byte_offset,
            file_bytes=copied, zero_tail_bytes=rounded-copied,
            initial_bytes_sha256=hashlib.sha256(constructor).hexdigest())
        if state['version'] == 7:
            mapped['cache_tail_bytes'] = rounded-copied if file_id > 0 else 0
            if file_id > 0:
                mapped['zero_tail_bytes'] = 0
        if state['version'] >= 6:
            mapped['shared'] = shared
        for page in pages:
            permissions[page], epochs[page] = prot, ordinal
            generations.pop(page, None)
            backing[page] = (file_id, byte_offset+page-result,
                             handle['descriptor_epoch'], file['content_epoch'])
            if state['version'] >= 6:
                state['shared'][page] = shared
                generations[page] = max((value for offset, value in file['guest_generations'].items()
                    if backing[page][1] <= offset < backing[page][1]+PAGE), default=0)
        effect = dict(operation='map', address=result, size=rounded, prot=prot,
                      mapping_epoch=ordinal, zero_fill_sha256=None)
        return effect, mapped, descriptor, mutation, constructor
    effect = _mapping_transition(number, args, entry.get('mmap_args'), result, ordinal,
                                 permissions, epochs, generations, protected_pages)
    if effect['operation'] in ('map', 'unmap'):
        for page in range(effect['address'], effect['address']+effect['size'], PAGE):
            state['shared'].pop(page, None)
            if effect['operation'] == 'map':
                backing[page] = (-1, 0, 0, 0)
            else:
                backing.pop(page, None)
    if effect['operation'] == 'map':
        constructor = bytes(effect['size'])
    return effect, mapped, descriptor, mutation, constructor


def _load_report(report):
    if type(report) is dict:
        return report
    require(report is not None, 'Complete observer report required')
    path = Path(report)
    require(path.is_file() and not path.is_symlink() and 0 < path.stat().st_size <= MAX_LINE,
            'Missing, symlink or oversized observer report')
    result = strict_json(path.read_bytes())
    require(type(result) is dict, 'Observer report must be an object')
    return result


def _boundary_identity(row, label, *, stage_index=True):
    require(row.get('boundary_selector_version') in (2, 3, 4, 5, 6, 7) and
            type(row.get('boundary_selector_version')) is int,
            label + ' exact boundary selector version')
    result = {'pc': uint(row.get('stop_pc'), label + ' stop PC'),
              'instruction_ordinal': uint(row.get('stop_instruction_ordinal'),
                                          label + ' stop occurrence', MAX_STEPS + 1),
              'page_generation': uint(row.get('stop_page_generation'),
                                      label + ' stop page generation', MAX_STEPS)}
    require(result['instruction_ordinal'] > 1 and result['page_generation'] > 0,
            label + ' empty selected boundary')
    if row['boundary_selector_version'] in (3, 4, 5, 6, 7):
        result['mapping_epoch'] = uint(row.get('stop_mapping_epoch'), label + ' stop mapping epoch', 256)
        if row['boundary_selector_version'] >= 4:
            result['file_mapping_profile_version'] = row['boundary_selector_version']
    else:
        require('stop_mapping_epoch' not in row, label + ' mixed mapping selector metadata')
    if stage_index:
        result['stage_index'] = uint(row.get('stop_stage_index'), label + ' stop stage index', 7)
        require(result['stage_index'] > 0, label + ' original entry is not a selected layer')
    return result


def read_observer(events, packed, expected_target, run_id, report=None, expected_stages=None,
                  expected_boundary=None):
    """Validate the standard-API fresh-prefix observation and source constructor.

    Stack bytes in ``context`` are canonical unknown bytes. The real entry
    stack is retained only as an observation; it never initializes replay.
    V1/V2 generations count guest stores from zero with only mprotect calls.
    V3 also binds each page to its live anonymous-mapping lifetime.
    """
    uint(expected_target, 'Requested target')
    require(type(run_id) is str and len(run_id) == 32 and
            all(c in '0123456789abcdef' for c in run_id), 'Observer run identity')
    loader = _loader(packed)
    raw, lines, rows = json_lines(events)
    header, footer = rows[0], rows[-1]
    schema = header.get('schema_version')
    require(type(schema) is int and schema in (1, 2, 3, 4, 5, 6, 7), 'Unsupported observer schema')
    selected_boundary = None
    selector_keys = ('boundary_selector_version', 'stop_instruction_ordinal',
                     'stop_page_generation', 'stop_stage_index', 'stop_mapping_epoch')
    if schema in (2, 3, 4, 5, 6, 7):
        require(header.get('boundary_selector_version') == schema,
                'Observer schema and selector version differ')
        selected_boundary = _boundary_identity(header, 'Observer header')
        if expected_boundary is None and expected_stages:
            claim = expected_stages[-1]
            if type(claim) is dict:
                expected_boundary = {'pc': claim.get('address'),
                                     'instruction_ordinal': claim.get('entry_seq'),
                                     'page_generation': claim.get('guest_store_generation') if schema >= 3 else claim.get('code_generation'),
                                     'stage_index': len(expected_stages)}
                if schema >= 3:
                    expected_boundary['mapping_epoch'] = claim.get('mapping_epoch')
                if schema >= 4:
                    expected_boundary['file_mapping_profile_version'] = claim.get('file_mapping_profile_version')
        require(type(expected_boundary) is dict and
                set(expected_boundary) == set(selected_boundary) and
                all(type(value) is int for value in expected_boundary.values()) and
                expected_boundary == selected_boundary,
                'Requested exact boundary occurrence/generation differs')
    else:
        require(expected_boundary is None and not any(key in header for key in selector_keys),
                'Exact boundary request cannot use a legacy PC-only observer')
    allowed = {'header', 'initial', 'initial_load', 'stage', 'store', 'syscall_enter',
               'syscall_return', 'syscall_post', 'target_page', 'footer'}
    require(all(row.get('kind') in allowed for row in rows) and
            sum(row.get('kind') == 'header' for row in rows) == 1 and
            sum(row.get('kind') == 'footer' for row in rows) == 1,
            'Unknown event or duplicated observer framing')
    for row in rows:
        for key in ('checkpoint_used_as_seed', 'observed_final_state_used_as_input',
                    'observed_image_used_as_input', 'target_instruction_executed',
                    'historical_originality_proven', 'unconditional_oep_proven', 'oep_proven'):
            require(key not in row or row[key] is False, 'Observer scope promoted: ' + key)
    require(header.get('kind') == 'header' and
            header.get('profile') == ('controlled_static_i386_JMP_memfd_tail_prefix' if schema == 7
                                      else 'controlled_static_i386_JMP_shared_memfd_prefix' if schema == 6
                                      else 'controlled_static_i386_JMP_mutable_memfd_prefix' if schema == 5
                                      else 'controlled_static_i386_JMP_private_file_mapping_prefix' if schema == 4
                                      else 'controlled_static_i386_JMP_anonymous_mapping_prefix' if schema == 3
                                      else 'controlled_static_i386_JMP_mprotect_prefix') and
            header.get('run_id') == run_id and header.get('elf_sha256') == loader['packed_sha256'] and
            header.get('initial_pc') == loader['entry'] and
            type(header.get('initial_pc')) is int and
            header.get('stop_pc') == expected_target and type(header.get('stop_pc')) is int and
            header.get('maximum_instructions') == MAX_STEPS and
            type(header.get('maximum_instructions')) is int and
            header.get('maximum_event_bytes') == 32 * 1024**2 and
            type(header.get('maximum_event_bytes')) is int and
            header.get('custom_QEMU_APIs_used') is False,
            'Observer source, profile or entry identity differs')
    require(2 <= uint(header.get('stage_count'), 'Configured stage count', 8) and
            len(raw) <= header['maximum_event_bytes'], 'Observer stage/event budget')
    prefix = b''.join(lines[:-1])
    require(footer.get('kind') == 'footer' and footer.get('success') is True and
            footer.get('reason') == 'selected_stage_boundary' and footer.get('run_id') == run_id and
            footer.get('stop_pc') == expected_target and type(footer.get('stop_pc')) is int and
            footer.get('boundary_reached') is True and footer.get('target_instruction_executed') is False and
            footer.get('events_bytes_before_footer') == len(prefix) and
            type(footer.get('events_bytes_before_footer')) is int and
            footer.get('events_sha256_before_footer') == hashlib.sha256(prefix).hexdigest(),
            'Incomplete observer stop or event checksum')
    instructions = uint(footer.get('instructions'), 'Executed instruction count', MAX_STEPS)
    require(instructions > 0, 'Empty observed execution')
    for key in ('executed_pc_sha256', 'executed_fetch_sha256'):
        sha(footer.get(key), 'Observer ' + key)
    report = _load_report(report)
    require(report.get('schema_version') == schema and type(report.get('schema_version')) is int and
            report.get('capture_kind') == 'BOUNDED_LAYER_PREFIX_V' + str(schema) and
            report.get('success') is True and report.get('reason') == 'selected_stage_boundary' and
            report.get('run_id') == run_id and report.get('elf_sha256') == loader['packed_sha256'] and
            report.get('initial_pc') == loader['entry'] and type(report.get('initial_pc')) is int and
            report.get('stop_pc') == expected_target and type(report.get('stop_pc')) is int and
            report.get('cpus') == 1 and type(report.get('cpus')) is int and
            report.get('events_bytes') == len(raw) and type(report.get('events_bytes')) is int and
            report.get('events_sha256') == hashlib.sha256(raw).hexdigest(),
            'Observer report is not bound to this source/run/event file')
    if selected_boundary is not None:
        require(_boundary_identity(footer, 'Observer footer') == selected_boundary and
                _boundary_identity(report, 'Observer report') == selected_boundary,
                'Observer exact boundary identity differs across framing')
    else:
        require(not any(key in row for row in (footer, report) for key in selector_keys),
                'Mixed legacy and exact observer boundary metadata')
    for key in ('target_instruction_executed', 'guest_permissions_independently_observed',
                'independent_OS_entry_origins_proven', 'kernel_implementation_verified', 'oep_proven'):
        require(report.get(key) is False, 'Observer report scope promoted: ' + key)
    for key in ('instructions', 'stores', 'syscall_count', 'syscall_returns', 'entries'):
        uint(footer.get(key), 'Observer footer ' + key, MAX_STEPS)
        require(type(report.get(key)) is int and report[key] == footer[key],
                'Observer report/footer count differs: ' + key)
    for key in ('executed_pc_sha256', 'executed_fetch_sha256'):
        require(report.get(key) == footer[key], 'Observer report/footer digest differs')

    initial_rows = [row for row in rows if row['kind'] == 'initial']
    require(len(initial_rows) == 1 and rows[1] == initial_rows[0], 'Original entry snapshot is missing or late')
    initial = initial_rows[0]
    registers = _registers(initial.get('registers'), 'Initial')
    require(uint(initial.get('pc'), 'Initial PC') == loader['entry'] and
            uint(initial.get('esp'), 'Initial ESP') == registers['esp'] and
            uint(initial.get('df'), 'Initial DF', 1) == (registers['eflags'] >> 10 & 1) == 0,
            'Entry ESP/DF differs')
    base, size = uint(initial.get('stack_base'), 'Stack base'), uint(initial.get('stack_size'), 'Stack size')
    require(base % PAGE == 0 and size == 2 * PAGE and base + size <= 2**32 and
            base == (initial['esp'] // PAGE - 1) * PAGE,
            'Unsupported entry stack observation window')
    observed_stack = hex_bytes(initial.get('stack_hex'), 'Observed entry stack', 2 * PAGE)
    require(len(observed_stack) == size, 'Entry stack snapshot extent differs')
    permissions = _permissions(loader, initial)
    protected_pages = set(permissions)
    mapping_epochs = {page: 0 for page in permissions}
    descriptors = {}
    backing = {page: (-1, 0, 0, 0) if schema >= 5 else (-1, 0, 0) for page in permissions}
    mutable_state = _mutable_file_state(packed, schema) if schema >= 5 else None
    loads = [row for row in rows if row['kind'] == 'initial_load']
    by_address = {row.get('address'): row for row in loads}
    require(len(loads) == len(by_address) == len(loader['initial_regions']), 'Initial image inventory differs')
    dynamic_seen = False
    for row in rows[2:-1]:
        if row['kind'] in ('initial', 'header', 'footer'):
            raise LayerBindingError('Repeated observer initialization')
        if row['kind'] == 'initial_load':
            require(not dynamic_seen, 'Post-entry image cannot become an initial source')
        else:
            dynamic_seen = True
    for address, data in loader['initial_regions']:
        row = by_address.get(address)
        require(type(row) is dict and type(row.get('address')) is int and
                uint(row.get('size'), 'Initial LOAD size', 1024**2) == len(data) and
                uint(row.get('prot'), 'Initial LOAD protection', 7) == permissions[address] and
                hex_bytes(row.get('bytes_hex'), 'Initial LOAD bytes', 1024**2) == data and
                row.get('sha256') == hashlib.sha256(data).hexdigest(),
                'Initial LOAD observation differs from source ELF construction')

    stages, stores, calls, generations, previous_at_pc = [], [], [], {}, {}
    stage_backings, stage_shared, stage_file_generations = {}, {}, {}
    pending = returned = None
    last_store_step, latest_stage_seq = 0, 0
    for row in rows[2:-1]:
        kind = row['kind']
        if kind == 'initial_load':
            continue
        if kind == 'store':
            require(pending is None and returned is None, 'Guest store overlaps a syscall')
            step = uint(row.get('step'), 'Store step', instructions)
            pc = uint(row.get('pc'), 'Store PC')
            address, size = uint(row.get('address'), 'Store address'), uint(row.get('size'), 'Store size', 16)
            ordinal = uint(row.get('store_ordinal'), 'Store ordinal', MAX_STEPS)
            require(step > 0 and step >= last_store_step and step >= latest_stage_seq and
                    size in (1, 2, 4, 8, 16) and address + size <= 2**32 and
                    ordinal == len(stores) + 1, 'Invalid chronological guest store')
            for page in range(address // PAGE * PAGE, (address + size + PAGE - 1) // PAGE * PAGE, PAGE):
                require(permissions.get(page, 0) & 2, 'Store outside writable constructed RAM')
                generations[page] = ordinal
            stored = {'step': step, 'pc': pc, 'address': address, 'size': size, 'store_ordinal': ordinal}
            if schema >= 3:
                touched = range(address // PAGE * PAGE, (address + size + PAGE - 1) // PAGE * PAGE, PAGE)
                epoch = uint(row.get('mapping_epoch'), 'Store destination mapping epoch', 256)
                writer_epoch = uint(row.get('writer_mapping_epoch'), 'Store writer mapping epoch', 256)
                require(all(mapping_epochs.get(page) == epoch for page in touched) and
                        mapping_epochs.get(pc // PAGE * PAGE) == writer_epoch and
                        permissions.get(pc // PAGE * PAGE, 0) & 5 == 5,
                        'Guest store crosses stale or unsupported mapping lifetimes')
                stored.update(mapping_epoch=epoch, writer_mapping_epoch=writer_epoch)
            if schema >= 6:
                _mutable_store(row, mutable_state, backing, generations)
                stored['shared_file_write'] = row['shared_file_write']
            stores.append(stored)
            last_store_step = step
        elif kind == 'stage':
            require(pending is None and returned is None, 'Stage overlaps a syscall')
            index, pc = uint(row.get('index'), 'Stage index', 7), uint(row.get('pc'), 'Stage PC')
            seq = uint(row.get('seq'), 'Stage occurrence', MAX_STEPS + 1)
            preview = hex_bytes(row.get('bytes_hex'), 'Stage current bytes', PAGE)
            width = uint(row.get('instruction_size'), 'Stage instruction size', 15)
            code = hex_bytes(row.get('instruction_bytes_hex'), 'Stage instruction bytes', 15)
            require(index == len(stages) and seq > latest_stage_seq and seq > last_store_step and
                    type(row.get('instruction_ordinal')) is int and row['instruction_ordinal'] == seq and
                    0 < len(preview) == uint(row.get('size'), 'Stage preview size', PAGE) and
                    pc + len(preview) <= 2**32 and row.get('sha256') == hashlib.sha256(preview).hexdigest() and
                    0 < width == len(code) and
                    (code == preview[:width] or schema >= 3 and index == 0 and preview == code[:len(preview)]) and
                    uint(row.get('page_generation'), 'Stage generation') == generations.get(pc // PAGE * PAGE, 0) and
                    permissions.get(pc // PAGE * PAGE, 0) & 5 == 5,
                    'Stage occurrence, generation or current code differs')
            _registers(row.get('registers'), 'Stage')
            if schema >= 3:
                require(uint(row.get('mapping_epoch'), 'Stage mapping epoch', 256) ==
                        mapping_epochs.get(pc // PAGE * PAGE), 'Stage mapping lifetime differs')
            if schema >= 4:
                stage_backings[index] = backing.get(pc // PAGE * PAGE)
                require(stage_backings[index] is not None, 'Stage source backing is unconstructed')
                if schema >= 6:
                    stage_shared[index] = mutable_state['shared'].get(pc//PAGE*PAGE, False)
                    file_id = stage_backings[index][0]
                    stage_file_generations[index] = dict(mutable_state['files'][file_id]['guest_generations']) if file_id > 0 else {}
            predecessor = uint(row.get('predecessor_pc'), 'Predecessor PC')
            predecessor_step = uint(row.get('predecessor_step'), 'Predecessor occurrence', instructions)
            predecessor_code = hex_bytes(row.get('predecessor_bytes_hex'), 'Predecessor bytes', 15)
            if index == 0:
                require(pc == loader['entry'] and seq == 1 and predecessor == predecessor_step == 0 and
                        predecessor_code == b'' and row['page_generation'] == 0,
                        'Original entry is not the first observed stage')
                if schema >= 3:
                    source = {}
                    for begin, values in loader['initial_regions']:
                        for offset, value in enumerate(values):
                            if pc <= begin + offset < pc + width:
                                source[begin + offset] = value
                    require(len(source) == width and bytes(source[pc + offset] for offset in range(width)) == code,
                            'Initial complete instruction differs from source ELF constructor')
            else:
                require(predecessor_step + 1 == seq and predecessor_step > 0 and
                        0 < len(predecessor_code) <= 15,
                        'Stage lacks an adjacent predecessor transfer')
            if pc in previous_at_pc:
                previous = previous_at_pc[pc]
                require(selected_boundary is not None and seq > previous['seq'] and
                        (row['page_generation'] > previous['page_generation'] or schema >= 3 and
                         row['mapping_epoch'] > previous['mapping_epoch']),
                        'Repeated stage PC requires a later occurrence and newer generation')
            previous_at_pc[pc] = row
            stages.append(row)
            latest_stage_seq = seq
        elif kind == 'syscall_enter':
            require(pending is None and returned is None, 'Overlapping syscall entry')
            ordinal = uint(row.get('ordinal'), 'Syscall ordinal', 256)
            require(ordinal == len(calls) + 1 and type(row.get('number')) is int and
                    row['number'] in ((4, 5, 6, 19, 90, 91, 93, 125, 144, 192, 356) if schema == 7 else
                                     (4, 5, 6, 19, 90, 91, 93, 125, 192, 356) if schema >= 5 else
                                     (5, 6, 90, 91, 125, 192) if schema == 4 else
                                     (90, 91, 125, 192) if schema == 3 else (125,)),
                    'Unsupported or nonchronological memory contract')
            pc = uint(row.get('pc'), 'Syscall PC', 0xfffffffd)
            args = row.get('args')
            require(type(args) is list and len(args) == 6 and
                    all(type(a) is int and 0 <= a <= 0xffffffff for a in args),
                    'Unexpected syscall argument/effect encoding')
            regs = _registers(row.get('registers'), 'Syscall entry')
            number = row['number']
            arity = {4: 3, 5: 2, 6: 1, 19: 3, 90: 1, 91: 2, 93: 2, 125: 3, 144: 3, 192: 6, 356: 2}[number]
            require(regs['eax'] == number and
                    [regs[key] for key in ('ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp')][:arity] == args[:arity],
                    'Consumed memory-operation arguments differ from architectural registers')
            require(row.get('path_hex') == (b'/proc/self/exe\0'.hex() if number == 5 else None),
                    'Only the immutable packed-source pathname is admitted')
            if schema >= 5:
                if number == 356:
                    _mutable_name(row)
                else:
                    require(row.get('name_hex') is None, 'Unexpected memfd name')
                if number == 4:
                    _observed_write(row)
                else:
                    require(row.get('write_buffer') is None, 'Unexpected pre-write observation')
            if number in (90, 192):
                effective = row.get('mmap_args')
                require(schema >= 3 and type(effective) is list and len(effective) == 6 and
                        all(type(value) is int and 0 <= value <= 0xffffffff for value in effective) and
                        (number != 192 or effective == args), 'Unsupported mmap argument array')
            else:
                require(row.get('mmap_args') is None, 'Unexpected mmap argument array')
            if schema < 3:
                check = dict(permissions); _protect(check, args)
            pending = row
        elif kind == 'syscall_return':
            require(pending is not None and returned is None and
                    all(type(row.get(key)) is int and row[key] == pending[key]
                        for key in ('ordinal', 'pc', 'number')) and
                    type(row.get('result_u32')) is int and 0 <= row['result_u32'] <= 0xffffffff and
                    (schema >= 3 or row['result_u32'] == 0) and
                    row.get('reply_hex') is None, 'Unexpected memory-operation return')
            returned = row
        elif kind == 'syscall_post':
            require(pending is not None and returned is not None and
                    type(row.get('ordinal')) is int and row['ordinal'] == pending['ordinal'] and
                    type(row.get('number')) is int and row['number'] == pending['number'] and
                    type(row.get('pc')) is int and row['pc'] == pending['pc'] + 2,
                    'Missing or reordered mprotect post-state')
            regs = _registers(row.get('registers'), 'Syscall post')
            require(regs['eax'] == returned['result_u32'] and all(regs[key] == pending['registers'][key] for key in GPRS if key != 'eax'),
                    'Memory operation changed preserved architectural registers')
            require(regs['eflags'] == pending['registers']['eflags'],
                    'Memory operation changed observed EFLAGS')
            if schema >= 5:
                effect, file_mapping, file_descriptor, file_mutation, _ = _mutable_transition(
                    pending, returned['result_u32'], permissions, mapping_epochs, generations,
                    protected_pages, descriptors, backing, mutable_state, packed)
                require(_same_mapping_effect(row.get('mapping_effect'), effect) and
                        all(key in row for key in ('file_mapping', 'file_descriptor', 'file_mutation')) and
                        _same_optional_file_effect(row['file_mapping'], file_mapping) and
                        _same_optional_file_effect(row['file_descriptor'], file_descriptor) and
                        _same_optional_file_effect(row['file_mutation'], file_mutation),
                        'Observed mutable-file constructor or mutation differs')
            elif schema == 4:
                effect, file_mapping, file_descriptor, _ = _file_transition(
                    pending['number'], pending['args'], pending.get('mmap_args'),
                    returned['result_u32'], pending['ordinal'], permissions, mapping_epochs,
                    generations, protected_pages, descriptors, backing, packed)
                require(_same_mapping_effect(row.get('mapping_effect'), effect) and
                        'file_mapping' in row and 'file_descriptor' in row and
                        _same_optional_file_effect(row['file_mapping'], file_mapping) and
                        _same_optional_file_effect(row['file_descriptor'], file_descriptor),
                        'Observed file/descriptor effect differs from source constructor')
            elif schema == 3:
                effect = _mapping_transition(pending['number'], pending['args'], pending.get('mmap_args'),
                    returned['result_u32'], pending['ordinal'], permissions, mapping_epochs,
                    generations, protected_pages)
                require(_same_mapping_effect(row.get('mapping_effect'), effect),
                        'Observed mapping effect differs from constructor')
            else:
                _protect(permissions, pending['args'])
            calls.append((pending, returned, row)); pending = returned = None
        elif kind == 'target_page':
            require(stages and row is rows[-2], 'Target-page observation is missing or late')
    require(pending is None and returned is None and stages and
            len(stages) <= header['stage_count'] and stages[-1]['pc'] == expected_target and
            stages[-1]['seq'] == instructions + 1 and
            footer['entries'] == len(stages) and footer['stores'] == len(stores) and
            footer['syscall_count'] == footer['syscall_returns'] == len(calls),
            'Incomplete stage/store/syscall chronology')
    if selected_boundary is not None:
        require(selected_boundary['pc'] == stages[-1]['pc'] and
                selected_boundary['instruction_ordinal'] == stages[-1]['seq'] == instructions + 1 and
                selected_boundary['page_generation'] == stages[-1]['page_generation'] and
                selected_boundary['stage_index'] == stages[-1]['index'] == len(stages) - 1,
                'Selected stop is not the requested stage occurrence/generation')
        if schema >= 3:
            require(selected_boundary['mapping_epoch'] == stages[-1]['mapping_epoch'],
                    'Selected stop belongs to a different mapping lifetime')
    pages = [row for row in rows if row['kind'] == 'target_page']
    require(len(pages) == 1, 'Exactly one stop-page observation required')
    target_page = pages[0]
    address = uint(target_page.get('address'), 'Target-page address')
    data = hex_bytes(target_page.get('bytes_hex'), 'Target-page bytes', PAGE)
    require(address == expected_target // PAGE * PAGE and len(data) == PAGE and
            type(target_page.get('size')) is int and target_page['size'] == PAGE and
            target_page.get('sha256') == hashlib.sha256(data).hexdigest() and
            uint(target_page.get('prot'), 'Target-page protection', 7) == permissions[address] and
            permissions[address] & 5 == 5 and
            uint(target_page.get('page_generation'), 'Target-page generation') == generations.get(address, 0),
            'Target-page image, permission or store generation differs')
    if schema >= 3:
        require(uint(target_page.get('mapping_epoch'), 'Target-page mapping epoch', 256) ==
                mapping_epochs.get(address) == stages[-1]['mapping_epoch'],
                'Current target page belongs to a different mapping lifetime')
    offset = expected_target - address
    last_preview = bytes.fromhex(stages[-1]['bytes_hex'])
    require(offset + len(last_preview) <= PAGE and data[offset:offset+len(last_preview)] == last_preview,
            'Stop-stage current bytes differ from its target page')
    bound_edges = []
    if expected_stages is not None:
        require(type(expected_stages) in (list, tuple) and len(expected_stages) == len(stages) - 1,
                'Requested stage ancestry coverage differs')
        preceding_claims = {}
        for wanted, observed in zip(expected_stages, stages[1:]):
            if type(wanted) is int:
                require(wanted == observed['pc'], 'Requested stage target differs')
                continue
            require(type(wanted) is dict and uint(wanted.get('address'), 'Claimed stage address') == observed['pc'],
                    'Claimed stage target differs')
            if schema >= 3:
                uint(wanted.get('mapping_epoch'), 'Claimed stage mapping epoch', 256)
                uint(wanted.get('guest_store_generation'), 'Claimed guest-store generation', MAX_STEPS)
            comparisons = [('entry_seq', 'seq'),
                                  ('guest_store_generation' if schema >= 3 else 'code_generation', 'page_generation'),
                                  ('entry_size', 'instruction_size')]
            if schema >= 3:
                comparisons.append(('mapping_epoch', 'mapping_epoch'))
            for claim, actual in comparisons:
                if claim in wanted:
                    require(type(wanted[claim]) is int and wanted[claim] == observed[actual],
                            'Claimed stage occurrence/generation differs: ' + claim)
            if schema >= 4:
                require(wanted.get('file_mapping_profile_version') == schema and
                        type(wanted.get('file_mapping_profile_version')) is int,
                        'File mapping proof profile claim is missing or invalid')
                # Each claim concerns the backing at that entry occurrence,
                # not the page's eventual backing after later remappings.
                expected_backing = stage_backings.get(observed['index'])
                require(type(expected_backing) is tuple and
                        all(type(wanted.get(key)) is int and wanted[key] == value
                            for key, value in zip((('backing_file_id', 'backing_offset', 'descriptor_epoch', 'backing_content_epoch')
                                                  if schema >= 5 else ('backing_file_id', 'backing_offset',
                                                  'descriptor_epoch')), expected_backing)),
                        'Claimed source-file backing differs at stage entry')
                if schema >= 6:
                    require(type(wanted.get('backing_shared')) is bool and
                            wanted['backing_shared'] == stage_shared[observed['index']],
                            'Claimed shared backing differs at stage entry')
            for claim, actual in (('transfer_pc', 'predecessor_pc'), ('transfer_seq', 'predecessor_step')):
                if claim in wanted:
                    require(type(wanted[claim]) is int and wanted[claim] == observed[actual],
                            'Claimed adjacent predecessor differs: ' + claim)
            parent_id = uint(wanted.get('parent_candidate_id', 0), 'Claimed parent identity', 2**64 - 1)
            if parent_id:
                require(type(parent_id) is int and parent_id in preceding_claims,
                        'Fresh causal edge has no earlier ancestor')
                parent_claim, parent_stage = preceding_claims[parent_id]
                target_page_address = observed['pc'] // PAGE * PAGE
                parent_page = parent_stage['pc'] // PAGE * PAGE
                routed_stores = []
                for row in stores:
                    projected = row
                    shared_write = row.get('shared_file_write')
                    if schema >= 6 and shared_write is not None and expected_backing[0] == shared_write['file_id']:
                        projected = {**row, 'address': target_page_address + shared_write['file_offset'] - expected_backing[1],
                                     'mapping_epoch': observed['mapping_epoch']}
                    routed_stores.append(projected)
                writes = [row for row in routed_stores if parent_stage['seq'] <= row['step'] < observed['seq'] and
                          row['address'] < target_page_address + PAGE and
                          row['address'] + row['size'] > target_page_address and
                          (schema < 3 or row['mapping_epoch'] == observed['mapping_epoch'])]
                require(writes, 'Fresh causal edge has no target-page write')
                interval, byte_owners, byte_laststores = None, {}, {}
                for row in writes:
                    begin = max(row['address'], target_page_address)
                    end = min(row['address'] + row['size'], target_page_address + PAGE)
                    owned = row['pc'] // PAGE * PAGE == parent_page and (
                        schema < 3 or row['writer_mapping_epoch'] == parent_stage['mapping_epoch'])
                    for byte in range(begin, end):
                        byte_owners[byte] = parent_id if owned else 0
                        byte_laststores[byte] = row['store_ordinal']
                    # Stage6 merges only touching writes with the same active
                    # candidate owner. A foreign writer retracts that interval.
                    if not owned:
                        interval = None
                    elif interval and begin <= interval[1] and end >= interval[0]:
                        interval = (min(begin, interval[0]), max(end, interval[1]))
                    else:
                        interval = (begin, end)
                last = writes[-1]
                if schema >= 6 and expected_backing[0] > 0:
                    file_generations = stage_file_generations[observed['index']]
                    for byte in list(byte_owners):
                        if file_generations.get(expected_backing[1]+byte-target_page_address, 0) != byte_laststores[byte]:
                            byte_owners[byte] = 0
                require(interval is not None and
                        uint(wanted.get('source_write_pc'), 'Claimed causal writer PC') == last['pc'] and
                        uint(wanted.get('source_write_seq'), 'Claimed causal writer occurrence') == last['step'] and
                        uint(wanted.get('guest_store_generation') if schema >= 3 else wanted.get('source_write_generation'),
                             'Claimed causal writer generation') == last['store_ordinal'] ==
                        wanted['guest_store_generation' if schema >= 3 else 'code_generation'] == observed['page_generation'] and
                        uint(wanted.get('written_begin'), 'Claimed causal interval start') == interval[0] and
                        uint(wanted.get('written_end'), 'Claimed causal interval end', 2**32) == interval[1] and
                        interval[0] <= observed['pc'] < observed['pc'] + observed['instruction_size'] <= interval[1] and
                        all(byte_owners.get(byte) == parent_id for byte in range(*interval)),
                        'Claimed causal write identity or contiguous interval differs')
                bound_edges.append({'parent_candidate_id': parent_claim['candidate_id'],
                                    'child_candidate_id': wanted['candidate_id'],
                                    'writer_pc': last['pc'], 'write_step': last['step'],
                                    'write_store_ordinal': last['store_ordinal'],
                                    'written_begin': interval[0], 'written_end': interval[1],
                                    'transfer_pc': observed['predecessor_pc'],
                                    'transfer_step': observed['predecessor_step'],
                                    'entry_step': observed['seq'],
                                    'binding': 'fresh_guest_store_chronology_and_adjacent_JMP',
                                    'numeric_generation_SMT_proven': False})
                if schema >= 3:
                    require(wanted.get('parent_mapping_epoch') == parent_stage['mapping_epoch'] and
                            wanted.get('source_writer_mapping_epoch') == last['writer_mapping_epoch'],
                            'Claimed parent/writer mapping lifetime differs')
                    bound_edges[-1].update(mapping_epoch=observed['mapping_epoch'],
                                           writer_mapping_epoch=parent_stage['mapping_epoch'])
            if 'candidate_id' in wanted:
                ident = uint(wanted['candidate_id'], 'Claimed candidate identity', 2**64 - 1)
                require(ident and ident not in preceding_claims, 'Repeated claimed stage identity')
                preceding_claims[ident] = (wanted, observed)
    context = {'packed': packed, 'stack': bytes(initial['stack_size']),
               'mask': bytes(initial['stack_size']), 'initial_regions': loader['initial_regions'],
               'esp': initial['esp'], 'df': initial['df'], 'calls': calls}
    if schema >= 6:
        ordinal = 0
        inventory = []
        for row in rows:
            if row['kind'] == 'syscall_post':
                ordinal = row['ordinal']
            elif row['kind'] == 'store' and row.get('shared_file_write') is not None:
                inventory.append({**row, 'after_syscall_ordinal': ordinal})
        context['shared_stores'] = inventory
    if schema >= 3:
        context['mapping_profile_version'] = schema
    return {'rows': rows, 'header': header, 'footer': footer, 'initial': initial,
            'target_page': target_page, 'target_bytes': data, 'stages': stages, 'stores': stores,
            'calls': calls, 'loader': loader, 'context': context, 'observed_stack': observed_stack,
            'permissions': permissions, 'mapping_epochs': mapping_epochs if schema >= 3 else None,
            'file_backing': backing if schema >= 4 else None,
            'stage_file_backing': stage_backings if schema >= 4 else None,
            'source_descriptors': descriptors if schema >= 4 else None,
            'shared_backing': dict(mutable_state['shared']) if schema >= 6 else None,
            'run_id': run_id, 'packed_sha256': loader['packed_sha256'],
            'events_sha256': hashlib.sha256(raw).hexdigest(), 'observer_report': report,
            'boundary_selector_version': schema, 'boundary_identity': selected_boundary,
            'original_entry_stack_bytes_admitted': 0,
            'ancestry_edges_bound_to_fresh_stores': bound_edges,
            'generation_binding': ('shared_memfd_file_alias_and_mapping_lifetimes_and_guest_store_counter' if schema >= 6
                                   else 'mutable_memfd_descriptor_content_and_mapping_lifetimes_and_guest_store_counter' if schema == 5
                                   else 'private_file_and_mapping_lifetimes_and_guest_store_counter' if schema == 4
                                   else 'anonymous_mapping_lifetimes_and_guest_store_counter' if schema == 3
                                   else 'mprotect_only_guest_store_counter_from_zero'),
            'runtime_generation_numeric_values_SMT_proven': False}


def _read_json(path):
    path = Path(path)
    require(path.is_file() and not path.is_symlink() and 0 < path.stat().st_size <= MAX_EVENTS,
            'Missing, symlink or oversized replay receipt')
    value = strict_json(path.read_bytes())
    require(type(value) is dict, 'Replay receipt must be an object')
    return value


def _read_binary(path, size):
    path = Path(path)
    require(path.is_file() and not path.is_symlink() and path.stat().st_size == size,
            'Missing, symlink or wrong-size replay bytes')
    return path.read_bytes()


def _page_map(rows, *, shared=False):
    require(type(rows) is list and 0 < len(rows) <= 4096, 'Replay VMA inventory')
    output = {}
    for row in rows:
        require(type(row) is dict, 'Replay VMA object')
        start = uint(row.get('start'), 'Replay VMA start')
        end = uint(row.get('end'), 'Replay VMA end', 2**32)
        prot = uint(row.get('permissions'), 'Replay VMA permissions', 7)
        require(start % PAGE == end % PAGE == 0 and start < end and
                end - start <= 16 * 1024**2 and
                type(row.get('file_id')) is int and type(row.get('offset')) is int and
                (row['file_id'] == -1 and row['offset'] == 0 or shared and
                 1 <= row['file_id'] < 32 and row['offset'] % PAGE == 0 and
                 row.get('backing_shared') is True and
                 row['file_id'] == row.get('backing_file_id') and
                 row['offset'] == row.get('backing_offset')), 'Unsupported replay VMA')
        if shared:
            require(type(row.get('backing_shared')) is bool and
                    row['backing_shared'] == (row['file_id'] >= 1),
                    'V6 shared VMA identity differs')
        for page in range(start, end, PAGE):
            require(page not in output, 'Overlapping replay VMA')
            output[page] = prot
            require(len(output) <= 4098, 'Replay VMA aggregate page budget')
    return output


def _page_epochs(rows, *, shared=False):
    """Mapping-lifetime identity is distinct from guest-store generation."""
    _page_map(rows, shared=shared)
    output = {}
    for row in rows:
        epoch = uint(row.get('mapping_epoch'), 'Native VMA mapping epoch', 256)
        for address in range(row['start'], row['end'], PAGE):
            output[address] = epoch
    return output


def _page_backing(rows, *, mutable=False, shared=False):
    _page_map(rows, shared=shared)
    output = {}
    for row in rows:
        file_id = row.get('backing_file_id')
        require(type(file_id) is int and -1 <= file_id < (32 if mutable else 1),
                'Native private backing file identity')
        offset = uint(row.get('backing_offset'), 'Native private backing offset')
        epoch = uint(row.get('descriptor_epoch'), 'Native backing descriptor epoch', 256)
        content_epoch = uint(row.get('content_epoch'), 'Native mapped content epoch', 256) if mutable else 0
        require((file_id == -1 and offset == epoch == content_epoch == 0) or
                (file_id >= 0 and offset % PAGE == 0 and epoch > 0 and
                 (file_id == 0 and content_epoch == 0 or
                  mutable and file_id > 0 and content_epoch >= epoch)),
                'Native private backing metadata differs')
        for address in range(row['start'], row['end'], PAGE):
            identity = (file_id, offset + address - row['start'] if file_id >= 0 else 0, epoch)
            output[address] = (*identity, content_epoch) if mutable else identity
    return output


def _bind_mutable_write(entry, result, model):
    """Compare computed pre-write bits; only applied bytes must be known."""
    observed = _observed_write(entry)
    buffer = model.get('write_buffer')
    require(type(buffer) is dict and set(buffer) == {'address', 'size', 'data_hex', 'known_hex'} and
            type(buffer['address']) is int and buffer['address'] == entry['args'][1] and
            type(buffer['size']) is int and buffer['size'] == len(observed),
            'Native requested write-buffer identity differs')
    data = hex_bytes(buffer['data_hex'], 'Computed pre-write data', 1024**2)
    known = hex_bytes(buffer['known_hex'], 'Computed pre-write known bits', 1024**2)
    require(len(data) == len(known) == len(observed) and 0 <= result <= len(observed) and
            known[:result] == b'\xff' * result and
            all(value & ~mask == 0 and value == (wanted & mask)
                for value, mask, wanted in zip(data, known, observed)),
            'Native write bytes are unknown or differ from observed result prefix')


def bind_replay(capture, replay_dir, loader=None):
    """Bind a fresh original-entry replay to one observed prefix.

    This is a consistency check around the trusted native interpreter. The
    complete source-derived producer and schedule proof must still run freshly.
    Page generations are derived from independently matching chronological
    stores; observed postimages never initialize the replay or SMT model.
    """
    try:
        from ..unpack_observations import compare_scalars, compare_initial_reads
    except ImportError:
        from unpack_observations import compare_scalars, compare_initial_reads
    require(type(capture) is dict and type(capture.get('context')) is dict,
            'Checked fresh observer context required')
    context, initial = capture['context'], capture['initial']
    constructed = _loader(context.get('packed'))
    require(capture.get('packed_sha256') == constructed['packed_sha256'] and
            capture.get('loader') == constructed and
            (loader is None or loader == constructed), 'Replay source constructor changed')
    require(context.get('initial_regions') == constructed['initial_regions'] and
            context.get('stack') == bytes(initial['stack_size']) and
            context.get('mask') == bytes(initial['stack_size']) and
            context.get('esp') == initial['esp'] and context.get('df') == initial['df'] == 0 and
            capture.get('original_entry_stack_bytes_admitted') == 0,
            'Observed image or stack admitted as a replay premise')
    directory = Path(replay_dir)
    execution, boundary = _read_json(directory / 'execution.json'), _read_json(directory / 'boundary.json')
    footer, stage = capture['footer'], capture['stages'][-1]
    for key in ('schema_version', 'entry', 'pc', 'instructions', 'stores', 'syscalls',
                'initial_known_GPRs', 'initial_known_flags', 'initial_stack_base',
                'initial_stack_size', 'initial_stack_known_bytes', 'projection_bytes'):
        uint(execution.get(key), 'Native execution ' + key)
    require(execution.get('schema_version') == 1 and
            execution.get('status') == 'COMPUTED_GENERIC_ENTRY_TO_SELECTED_TRANSFER' and
            execution.get('entry') == constructed['entry'] and execution.get('pc') == stage['pc'] and
            execution.get('instructions') == footer['instructions'] and
            execution.get('stores') == footer['stores'] and
            execution.get('syscalls') == footer['syscall_count'] and
            execution.get('path_sha256') == footer['executed_pc_sha256'] and
            execution.get('fetch_sha256') == footer['executed_fetch_sha256'] and
            execution.get('fetch_hash_encoding') == 'LE32_PC_U8_SIZE_BYTES',
            'Fresh replay differs from full captured prefix/fetch chronology')
    for key in ('checkpoint_used_as_seed', 'observed_final_state_used_as_input',
                'kernel_implementation_verified', 'independent_entry_origins_proven',
                'target_instruction_executed'):
        require(execution.get(key) is False, 'Replay scope promoted: ' + key)
    require(execution.get('initial_known_GPRs') == execution.get('initial_known_flags') == 1 and
            execution.get('initial_stack_base') == initial['stack_base'] and
            execution.get('initial_stack_size') == initial['stack_size'] and
            type(execution.get('initial_stack_known_bytes')) is int and
            execution['initial_stack_known_bytes'] == 0 and
            type(execution.get('projection_bytes')) is int and execution['projection_bytes'] == 0 and
            _read_binary(directory / 'projection.bin', initial['stack_size']) == bytes(initial['stack_size']),
            'Replay depends on incoming scalar/stack values outside ESP/DF premises')
    unknown = compare_scalars(execution['registers'], execution['flags'], stage['registers'], 'Stop-stage')
    raw_stores, _, stores = json_lines(directory / 'write-origins.jsonl')
    schema = capture.get('boundary_selector_version', 1)
    store_keys = {'step', 'pc', 'address', 'size', 'store_ordinal'}
    if schema >= 3:
        store_keys |= {'mapping_epoch', 'writer_mapping_epoch'}
    if schema >= 6:
        store_keys.add('shared_file_write')
    require(all(set(row) == store_keys for row in stores),
            'Native guest-store ledger shape differs')
    for row in stores:
        for key in row:
            if key != 'shared_file_write':
                uint(row[key], 'Native store ' + key)
    require(stores == capture['stores'] and len(stores) == execution['stores'],
            'Native and observer chronological writes differ')
    require(context.get('calls') == capture['calls'],
            'Replay context syscall inventory differs from the checked capture')
    if schema >= 6:
        expected_inventory, call_ordinal = [], 0
        by_ordinal = {row['store_ordinal']: row for row in stores}
        for row in capture['rows']:
            if row['kind'] == 'syscall_post':
                call_ordinal = row['ordinal']
            elif row['kind'] == 'store':
                require({key: row[key] for key in store_keys} == by_ordinal.get(row['store_ordinal']),
                        'Shared-store source rows differ from the native chronology')
                if row['shared_file_write'] is not None:
                    expected_inventory.append({**row, 'after_syscall_ordinal': call_ordinal})
        require(context.get('shared_stores') == expected_inventory,
                'Shared-store context inventory differs from the checked capture')
    for key in ('schema_version', 'pc', 'instructions'):
        uint(boundary.get(key), 'Native boundary ' + key)
    require(boundary.get('schema_version') == 1 and boundary.get('source_kind') == 'computed_IR_model' and
            boundary.get('pc') == stage['pc'] and boundary.get('instructions') == execution['instructions'] and
            boundary.get('path_sha256') == execution['path_sha256'], 'Computed boundary identity differs')
    exact = capture.get('boundary_identity')
    if exact is not None:
        identity = {key: exact[key] for key in ('pc', 'instruction_ordinal', 'page_generation')}
        if schema >= 3:
            identity['mapping_epoch'] = exact['mapping_epoch']
        if schema >= 4:
            identity['file_mapping_profile_version'] = schema
        for label, model in (('Native execution', execution), ('Native boundary', boundary)):
            require(_boundary_identity({**model, 'stop_pc': model['pc']}, label, stage_index=False) == identity,
                    'Native exact stop occurrence/generation differs')
        require(identity['instruction_ordinal'] == execution['instructions'] + 1,
                'Native replay stopped at a different occurrence of the selected PC')
    else:
        require(not any(key in model for model in (execution, boundary)
                        for key in ('boundary_selector_version', 'stop_instruction_ordinal',
                                    'stop_page_generation', 'stop_mapping_epoch')),
                'Exact replay cannot be downgraded to a legacy observer binding')
    for key in ('guest_permissions_independently_observed', 'kernel_implementation_verified',
                'independent_entry_origins_proven', 'target_instruction_executed'):
        require(boundary.get(key) is False, 'Computed boundary scope promoted: ' + key)
    transition, fetch = boundary.get('transition'), boundary.get('fetch')
    predecessor_code = hex_bytes(stage['predecessor_bytes_hex'], 'Adjacent JMP bytes', 15)
    direct = ((len(predecessor_code) == 5 and predecessor_code[0] == 0xe9) or
              (len(predecessor_code) == 2 and predecessor_code[0] == 0xeb))
    indirect = (len(predecessor_code) == 2 and predecessor_code[0] == 0xff and
                predecessor_code[1] & 0xf8 == 0xe0)
    require(type(transition) is dict and transition.get('computed_target_known') is True and
            transition.get('computed_target') == stage['pc'] and
            transition.get('pc') == stage['predecessor_pc'] and
            transition.get('instruction_ordinal') == stage['predecessor_step'] == execution['instructions'] and
            transition.get('bytes_hex') == stage['predecessor_bytes_hex'] and
            transition.get('size') == len(bytes.fromhex(stage['predecessor_bytes_hex'])) and
            type(transition.get('control')) is int and
            ((direct and transition['control'] == 1) or (indirect and transition['control'] == 3)),
            'Computed final adjacent JMP differs from observed predecessor')
    if direct:
        displacement = int.from_bytes(predecessor_code[1:], 'little', signed=True)
        require((transition['pc'] + len(predecessor_code) + displacement) & 0xffffffff == stage['pc'],
                'Direct adjacent JMP displacement differs from stage target')
    require(type(fetch) is dict and fetch.get('pc') == stage['pc'] and
            fetch.get('size') == stage['instruction_size'] and
            fetch.get('bytes_hex') == stage['instruction_bytes_hex'] and
            fetch.get('known_hex') == 'ff' * stage['instruction_size'] and
            fetch.get('ir_validator_passed') is True and fetch.get('lift_status') == 0 and
            fetch.get('ir_semantics_modeled') is True and fetch.get('target_instruction_executed') is False,
            'Computed current code fetch differs from stage occurrence')
    _, _, catalogue = json_lines(directory / 'original-ir.jsonl')
    for descriptor, byte_key in ((transition, 'bytes_hex'), (fetch, 'bytes_hex')):
        digest = sha(descriptor.get('original_ir_sha256'), 'Boundary source-IR digest')
        matches = [row for row in catalogue if row.get('pc') == descriptor['pc'] and
                   row.get('original_ir_sha256') == digest]
        # The native catalogue excludes the unexecuted target fetch.
        if descriptor is fetch:
            dump = fetch.get('original_ir_dump')
            require(type(dump) is str and hashlib.sha256(dump.encode()).hexdigest() == digest,
                    'Unexecuted fetch source-IR digest differs')
        else:
            require(len(matches) == 1 and matches[0].get('bytes') == descriptor[byte_key] and
                    matches[0].get('size') == descriptor['size'] and
                    type(matches[0].get('original_ir_dump')) is str and
                    hashlib.sha256(matches[0]['original_ir_dump'].encode()).hexdigest() == digest,
                    'Executed transfer source-IR catalogue differs')
    permissions = _permissions(constructed, initial)
    mapping_epochs = {page: 0 for page in permissions}
    descriptors = {}
    backing = {page: (-1, 0, 0, 0) if schema >= 5 else (-1, 0, 0) for page in permissions}
    mutable_state = _mutable_file_state(context['packed'], schema) if schema >= 5 else None
    protected_pages = set(permissions)
    _, _, kernels = json_lines(directory / 'kernel.jsonl')
    require(len(kernels) == len(capture['calls']) + 1, 'Native kernel timeline extent differs')
    kernel_unknown = []
    shared_inventory = context.get('shared_stores', []) if schema >= 6 else []
    def apply_stores_after(call_ordinal):
        for row in shared_inventory:
            if row['after_syscall_ordinal'] == call_ordinal:
                _mutable_store(row, mutable_state, backing, {})
    for ordinal, model in enumerate(kernels):
        require(model.get('schema_version') == 1 and model.get('source_kind') == 'computed_IR_model' and
                type(model.get('ordinal')) is int and model['ordinal'] == ordinal,
                'Native kernel model identity/order differs')
        if ordinal == 0:
            require(model.get('kind') == 'initial_model', 'Native initial constructor receipt absent')
        else:
            if schema >= 6:
                apply_stores_after(ordinal-1)
            entry, returned, post = capture['calls'][ordinal - 1]
            require(model.get('kind') == 'kernel_model' and model.get('number') == entry['number'] and
                    model.get('pc_before') == entry['pc'] and model.get('pc_after') == post['pc'] and
                    model.get('kernel_implementation_verified') is False and model.get('files') == [] and
                    (schema >= 5 and entry['number'] == 4 or model.get('write_buffer') is None),
                    'Native memory-operation boundary differs')
            constructor = None
            if schema >= 5:
                if entry['number'] == 4:
                    _bind_mutable_write(entry, returned['result_u32'], model)
                effect, file_mapping, file_descriptor, file_mutation, constructor = _mutable_transition(
                    entry, returned['result_u32'], permissions, mapping_epochs, {}, protected_pages,
                    descriptors, backing, mutable_state, context['packed'])
                require(_same_mapping_effect(model.get('mapping_effect'), effect) and
                        _same_mapping_effect(post.get('mapping_effect'), effect) and
                        all(key in model and key in post for key in
                            ('file_mapping', 'file_descriptor', 'file_mutation')) and
                        all(_same_optional_file_effect(row[key], expected)
                            for row in (model, post) for key, expected in (
                                ('file_mapping', file_mapping), ('file_descriptor', file_descriptor),
                                ('file_mutation', file_mutation))),
                        'Native/observer mutable-file constructors or effects differ')
                expected_fds = [dict(fd=fd, model_file_id=descriptors[fd]['file_id'])
                                for fd in sorted(descriptors)]
                require(type(model.get('descriptors')) is list and
                        all(type(row) is dict and set(row) == {'fd', 'model_file_id'} and
                            type(row['fd']) is int and type(row['model_file_id']) is int
                            for row in model['descriptors']) and model['descriptors'] == expected_fds,
                        'Native mutable descriptor timeline differs')
            elif schema == 4:
                effect, file_mapping, file_descriptor, constructor = _file_transition(
                    entry['number'], entry['args'], entry.get('mmap_args'), returned['result_u32'],
                    ordinal, permissions, mapping_epochs, {}, protected_pages, descriptors, backing,
                    context['packed'])
                require(_same_mapping_effect(model.get('mapping_effect'), effect) and
                        _same_mapping_effect(post.get('mapping_effect'), effect) and
                        all(key in model and key in post for key in ('file_mapping', 'file_descriptor')) and
                        _same_optional_file_effect(model['file_mapping'], file_mapping) and
                        _same_optional_file_effect(post['file_mapping'], file_mapping) and
                        _same_optional_file_effect(model['file_descriptor'], file_descriptor) and
                        _same_optional_file_effect(post['file_descriptor'], file_descriptor),
                        'Native/observer file and descriptor constructors differ')
                expected_fds = [dict(fd=fd, model_file_id=0) for fd in sorted(descriptors)]
                require(type(model.get('descriptors')) is list and
                        all(type(row) is dict and set(row) == {'fd', 'model_file_id'} and
                            type(row['fd']) is int and type(row['model_file_id']) is int
                            for row in model['descriptors']) and model['descriptors'] == expected_fds,
                        'Native source descriptor timeline differs')
            elif schema == 3:
                require(model.get('descriptors') == [], 'Unexpected anonymous-profile descriptors')
                effect = _mapping_transition(entry['number'], entry['args'], entry.get('mmap_args'),
                    returned['result_u32'], ordinal, permissions, mapping_epochs, {}, protected_pages)
                require(_same_mapping_effect(model.get('mapping_effect'), effect) and
                        _same_mapping_effect(post.get('mapping_effect'), effect),
                        'Native and observer mapping-lifetime effects differ')
            else:
                require(model.get('descriptors') == [], 'Unexpected protection-profile descriptors')
                _protect(permissions, entry['args'])
                effect = dict(operation='protect', address=entry['args'][0],
                              size=(entry['args'][1] + PAGE - 1) // PAGE * PAGE)
            kernel_unknown.extend({'ordinal': ordinal, **row} for row in compare_scalars(
                model['registers'], model['flags'], post['registers'], 'Post-memory-operation'))
            # This serializer calls protection-only coverage "changed_memory";
            # it remains computed output, never an observer-derived input.
            changed = model.get('changed_memory')
            live_write = schema >= 6 and entry['number'] == 4
            if live_write:
                file_id = file_mutation['file_id']
                pages = sorted(page for page, identity in backing.items()
                               if identity[0] == file_id and mutable_state['shared'].get(page) is True)
                chunks = []
                for page in pages:
                    if chunks and chunks[-1][-1]+PAGE == page and len(chunks[-1]) < 32:
                        chunks[-1].append(page)
                    else:
                        chunks.append([page])
                require(type(changed) is list and len(changed) == len(chunks),
                        'Native shared-write alias coverage differs')
                for actual, chunk in zip(changed, chunks):
                    wanted = b''.join(bytes(mutable_state['files'][file_id]['data'][
                        backing[page][1]:backing[page][1]+PAGE]) for page in chunk)
                    require(type(actual) is dict and actual.get('address') == chunk[0] and
                            type(actual.get('address')) is int and actual.get('size') == len(chunk)*PAGE and
                            type(actual.get('size')) is int and
                            hex_bytes(actual.get('data_hex'), 'Computed shared alias bytes', 32*PAGE) == wanted and
                            hex_bytes(actual.get('known_hex'), 'Computed shared alias bits', 32*PAGE) == b'\xff'*len(wanted),
                            'Native shared-write alias bytes differ or remain UNKNOWN')
            else:
                require(type(changed) is list and len(changed) ==
                        (1 if effect['operation'] in ('map', 'protect') else 0),
                        'Unexpected modeled mapping-memory effect count')
                if changed:
                    require(changed[0].get('address') == effect['address'] and
                            changed[0].get('size') == effect['size'],
                            'Unexpected modeled mapping-memory extent')
                    data = hex_bytes(changed[0].get('data_hex'), 'Computed mapped RAM', 1024**2)
                    known = hex_bytes(changed[0].get('known_hex'), 'Computed mapped mask', 1024**2)
                    require(len(data) == len(known) == changed[0]['size'] and
                            all(value & ~mask == 0 for value, mask in zip(data, known)),
                            'Noncanonical computed mapped RAM')
                    if effect['operation'] == 'map':
                        wanted = constructor if schema >= 4 else bytes(effect['size'])
                        require(data == wanted and known == b'\xff' * effect['size'],
                                'Map is not the fully known source-derived constructor')
        require(_page_map(model.get('vmas'), shared=schema >= 6) == permissions, 'Native constructed permission timeline differs')
        if schema >= 3:
            require(_page_epochs(model.get('vmas'), shared=schema >= 6) == mapping_epochs,
                    'Native constructed mapping-lifetime timeline differs')
        if schema >= 4:
            require(_page_backing(model.get('vmas'), mutable=schema >= 5, shared=schema >= 6) == backing,
                    'Native PRIVATE source-backing timeline differs')
    if schema >= 6:
        apply_stores_after(len(capture['calls']))
        require(mutable_state['shared'] == capture['shared_backing'],
                'Final shared mapping identities differ')
    require(permissions == capture['permissions'] and _page_map(boundary.get('vmas'), shared=schema >= 6) == permissions,
            'Final source-derived permissions differ')
    if schema >= 3:
        require(mapping_epochs == capture['mapping_epochs'] and
                _page_epochs(boundary.get('vmas'), shared=schema >= 6) == mapping_epochs,
                'Final source-derived mapping lifetimes differ')
    if schema >= 4:
        require(backing == capture['file_backing'] and
                descriptors == capture['source_descriptors'] and
                _page_backing(boundary.get('vmas'), mutable=schema >= 5, shared=schema >= 6) == backing,
                'Final PRIVATE file backing or descriptor identity differs')
    address = capture['target_page']['address']
    data = _read_binary(directory / 'final' / f'ram-{address:08x}.bin', PAGE)
    known = _read_binary(directory / 'final' / f'known-{address:08x}.bin', PAGE)
    require(known == b'\xff' * PAGE and data == capture['target_bytes'],
            'Current stage goal page differs or contains UNKNOWN bytes')
    initial_reads = compare_initial_reads(constructed['initial_regions'], directory / 'initial-reads.jsonl')
    return {'execution': execution, 'source_constructor_bound': True,
            'packed_sha256': constructed['packed_sha256'], 'observer_run_id': capture['run_id'],
            'observer_events_sha256': capture['events_sha256'],
            'native_store_ledger_sha256': hashlib.sha256(raw_stores).hexdigest(),
            'native_observer_store_chronology_equal': True, 'store_events_compared': len(stores),
            'current_target': stage['pc'], 'instruction_ordinal': stage['seq'],
            'boundary_selector_version': capture.get('boundary_selector_version', 1),
            'boundary_identity': exact,
            'earlier_same_PC_stage_occurrences': sum(
                earlier['pc'] == stage['pc'] for earlier in capture['stages'][:-1]),
            'derived_page_generation': capture['target_page']['page_generation'],
            'derived_mapping_epoch': capture['target_page'].get('mapping_epoch') if schema >= 3 else None,
            'current_page_sha256': hashlib.sha256(data).hexdigest(), 'current_page_bytes_compared': PAGE,
            'full_executed_PC_and_fetch_prefix_equal': True,
            'source_constructor_permissions_compared': True,
            'original_entry_stack_bytes_admitted': 0, 'initial_reads': initial_reads,
            'stop_unknown_scalars': unknown, 'post_kernel_unknown_scalars': kernel_unknown,
            'generation_binding': capture['generation_binding'],
            'ancestry_edges_bound_to_fresh_stores': capture['ancestry_edges_bound_to_fresh_stores'],
            'runtime_generation_numeric_values_SMT_proven': False,
            'observed_image_admitted_as_source_premise': False,
            'SMT_proof_performed_by_this_binding_check': False,
            'historical_originality_proven': False}


def validate_smt_certificate(certificate, *, target=None, packed_sha256=None, path_sha256=None):
    """Check the scope of an actual generic-pipeline result, not its SMT proof.

    The host must call ``unpack_smt.prove_generic`` freshly and bind its journal,
    source inputs and producer ledger. This consistency check prevents promoting
    UNKNOWN, a schedule-only theorem, or an image-as-input result afterwards.
    """
    require(type(certificate) is dict and certificate.get('status') == SMT_STATUS,
            'Fresh complete generic SMT result required')
    require(certificate.get('source_premise_query') == 'SAT' and
            certificate.get('image_and_transfer_counterexample_query') == 'UNSAT',
            'SMT source SAT and counterexample UNSAT required')
    for key in ('selected_execution_proved', 'all_prefix_schedule_conditions_encoded_in_SMT',
                'all_observed_image_bytes_SMT_proved', 'computed_transfer_and_fetch_SMT_proved'):
        require(certificate.get(key) is True, 'Incomplete SMT result: ' + key)
    for key in ('candidate_relation_added_to_source_premises',
                'intermediate_values_admitted_without_SMT_proof', 'checkpoint_used_as_seed',
                'observed_final_state_used_as_input', 'original_elf_used_as_input',
                'historical_originality_proven', 'unconditional_oep_proven',
                'target_instruction_executed', 'fuzzing_ready'):
        require(certificate.get(key) is False, 'Promoted or invalid SMT scope: ' + key)
    require(certificate.get('SMT_proof_mode') == 'TOPOLOGICAL_SMT_INDUCTION',
            'Unexpected SMT proof mode')
    for key in ('SMT_solver_checks', 'instructions', 'schedule_producer_nodes',
                'schedule_source_premises', 'schedule_condition_count',
                'schedule_unique_condition_goals'):
        require(uint(certificate.get(key), key, 2**64 - 1) > 0, 'Empty SMT proof: ' + key)
    for key in ('path_sha256', 'packed_sha256', 'producer_ledger_sha256'):
        sha(certificate.get(key), 'SMT ' + key)
    uint(certificate.get('selected_transfer'), 'SMT selected transfer')
    if target is not None:
        require(certificate['selected_transfer'] == target, 'SMT target differs from bound boundary')
    if packed_sha256 is not None:
        require(certificate['packed_sha256'] == packed_sha256, 'SMT source ELF differs')
    if path_sha256 is not None:
        require(certificate['path_sha256'] == path_sha256, 'SMT executed path differs')
    return {'source_premise_query': 'SAT', 'counterexample_query': 'UNSAT',
            'scope_consistent': True, 'independent_SMT_reverification_performed': False,
            'historical_originality_proven': False}
