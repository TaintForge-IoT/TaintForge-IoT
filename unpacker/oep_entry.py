"""Check the selected i386 entry table without treating a snapshot as OS proof.

The launch profile is an explicit premise.  ELF-dependent auxv fields are
reconstructed from the authenticated ELF; pointer values, layout, page size,
other auxv values and ESP/DF remain named external admissions.
"""

import hashlib
import json
import struct


_U32_END = 1 << 32
_CRITICAL_AUX = {3, 4, 5, 6, 9}
_PROFILE_FIELDS = {
    'schema_version', 'provenance', 'elf_sha256', 'esp', 'df', 'page_size',
    'phdr_load_index', 'argv_pointers', 'envp_pointers', 'auxv', 'stack_mapping',
}


def _require(condition, message):
    if not condition:
        raise ValueError(message)


def _uint(value, label):
    _require(type(value) is int and 0 <= value < _U32_END, label + ' must be uint32')
    return value


def _bytes(value, label):
    _require(isinstance(value, (bytes, bytearray)), label + ' must be bytes')
    return bytes(value)


def parse_elf32(data, *, require_file_bytes=True):
    """Read i386 ET_EXEC headers; header-only mode supports computed RAM images."""
    data = _bytes(data, 'ELF')
    _require(type(require_file_bytes) is bool, 'require_file_bytes must be boolean')
    _require(len(data) >= 52, 'Truncated ELF header')
    fields = struct.unpack_from('<16sHHIIIIIHHHHHH', data)
    ident, kind, machine, version, entry, phoff, shoff, flags, ehsize, phsize, count, shsize, shcount, shstr = fields
    _require(ident[:7] == b'\x7fELF\x01\x01\x01', 'Expected little-endian ELF32 version1')
    _require(ident[7] in (0, 3) and ident[8] == 0, 'Unsupported ELF ABI')
    _require(kind == 2 and machine == 3 and version == 1, 'Expected i386 ET_EXEC')
    _require(ehsize == 52 and phsize == 32, 'Unexpected ELF header sizes')
    _require(0 < count <= 4096, 'Unsupported program-header count')
    _require(phoff >= ehsize and phoff + count * phsize <= len(data), 'Truncated program-header table')
    headers = []
    for index in range(count):
        values = struct.unpack_from('<IIIIIIII', data, phoff + index * phsize)
        h = dict(zip(('type', 'offset', 'vaddr', 'paddr', 'filesz', 'memsz', 'flags', 'align'), values))
        h['index'] = index
        _require(h['offset'] + h['filesz'] <= _U32_END, 'Segment file range wraps')
        _require(h['vaddr'] + h['memsz'] <= _U32_END, 'Segment virtual range wraps')
        if require_file_bytes and h['filesz']:
            _require(h['offset'] + h['filesz'] <= len(data), 'Truncated segment file bytes')
        if h['type'] == 1:
            _require(h['filesz'] <= h['memsz'], 'PT_LOAD filesz exceeds memsz')
            alignment = h['align']
            _require(alignment in (0, 1) or alignment & (alignment - 1) == 0, 'Invalid PT_LOAD alignment')
            if alignment > 1:
                _require(h['vaddr'] % alignment == h['offset'] % alignment, 'Incongruent PT_LOAD alignment')
        headers.append(h)
    _require(any(h['type'] == 1 for h in headers), 'ELF has no PT_LOAD')
    return {
        'elf_type': kind, 'machine': machine, 'entry': entry, 'phoff': phoff,
        'phentsize': phsize, 'phnum': count, 'ehsize': ehsize, 'flags': flags,
        'program_headers': headers, 'full_segment_file_extent_checked': require_file_bytes,
    }


def parse_entry_table(stack, base, esp, max_bytes=None, *, known_mask=None):
    """Parse a bounded argc/argv/envp/auxv table; do not dereference its pointers."""
    stack = _bytes(stack, 'Stack snapshot')
    _uint(base, 'Stack base')
    _uint(esp, 'ESP')
    _require(base + len(stack) <= _U32_END, 'Stack snapshot wraps')
    _require(esp % 4 == 0 and base <= esp < base + len(stack), 'Invalid entry-table ESP')
    offset = esp - base
    if max_bytes is None:
        max_bytes = len(stack) - offset
    _require(type(max_bytes) is int and 4 <= max_bytes <= len(stack) - offset, 'Invalid entry-table bound')
    limit = offset + max_bytes
    if known_mask is not None:
        known_mask = _bytes(known_mask, 'Known mask')
        _require(len(known_mask) == len(stack) and all(k in (0, 255) for k in known_mask), 'Invalid byte known mask')
    cursor = offset

    def word():
        nonlocal cursor
        _require(cursor + 4 <= limit, 'Unterminated or truncated entry table')
        if known_mask is not None:
            _require(known_mask[cursor:cursor + 4] == b'\xff' * 4, 'Entry-table field is UNKNOWN')
        value = struct.unpack_from('<I', stack, cursor)[0]
        cursor += 4
        return value

    argc = word()
    _require(argc <= (limit - cursor) // 4, 'argc exceeds entry-table bound')
    argv_start = cursor
    argv = [word() for _ in range(argc)]
    _require(all(argv) and word() == 0, 'Invalid argv pointers or terminator')
    env_start = cursor
    envp = []
    while True:
        value = word()
        if value == 0:
            break
        envp.append(value)
    aux_start = cursor
    auxv = []
    seen = set()
    while True:
        tag, value = word(), word()
        _require(tag not in _CRITICAL_AUX or tag not in seen, 'Duplicate critical auxv field')
        seen.add(tag)
        auxv.append([tag, value])
        if tag == 0:
            break
    return {
        'argc': argc, 'argv_pointers': argv, 'envp_pointers': envp, 'auxv': auxv,
        'address': esp, 'end': base + cursor, 'size': cursor - offset,
        'table_sha256': hashlib.sha256(stack[offset:cursor]).hexdigest(),
        'regions': [
            {'kind': 'argc', 'address': esp, 'size': 4},
            {'kind': 'argv', 'address': base + argv_start, 'size': env_start - argv_start},
            {'kind': 'envp', 'address': base + env_start, 'size': aux_start - env_start},
            {'kind': 'auxv', 'address': base + aux_start, 'size': cursor - aux_start},
        ],
        'pointer_target_contents_checked': False,
    }


def _phdr_candidates(elf):
    start = elf['phoff']
    end = start + elf['phentsize'] * elf['phnum']
    return [
        {'load_index': h['index'], 'address': h['vaddr'] + start - h['offset']}
        for h in elf['program_headers']
        if h['type'] == 1 and h['offset'] <= start and end <= h['offset'] + h['filesz']
    ]


def _aux_map(pairs):
    result = {}
    for tag, value in pairs:
        if tag in _CRITICAL_AUX:
            _require(tag not in result, 'Duplicate critical auxv field')
            result[tag] = value
    _require(_CRITICAL_AUX <= result.keys(), 'Missing critical auxv field')
    return result


def _mapping(value, esp, end, page_size):
    _require(isinstance(value, dict) and set(value) == {'start', 'end', 'read', 'write'}, 'Invalid stack_mapping fields')
    start = _uint(value['start'], 'Stack mapping start')
    stop = value['end']
    _require(type(stop) is int and start < stop <= _U32_END, 'Invalid stack mapping end')
    _require(value['read'] is True and value['write'] is True, 'Entry stack must be admitted readable/writable')
    _require(start % page_size == stop % page_size == 0, 'Unaligned stack mapping')
    _require(start <= esp < end <= stop, 'Entry table outside admitted stack mapping')
    return dict(value)


def _profile_from_observation(elf_data, elf, layout, esp, df, stack_mapping):
    aux = _aux_map(layout['auxv'])
    candidates = _phdr_candidates(elf)
    matches = [c for c in candidates if c['address'] == aux[3]]
    _require(matches, 'Observed AT_PHDR is not a file-backed ELF program-header address')
    return {
        'schema_version': 1, 'provenance': 'observed_entry_table',
        'elf_sha256': hashlib.sha256(elf_data).hexdigest(), 'esp': esp, 'df': df,
        'page_size': aux[6], 'phdr_load_index': matches[0]['load_index'],
        'argv_pointers': list(layout['argv_pointers']), 'envp_pointers': list(layout['envp_pointers']),
        'auxv': [[tag, None if tag in (3, 4, 5, 6, 9) else value] for tag, value in layout['auxv']],
        'stack_mapping': stack_mapping,
    }


def _reconstruct(profile, elf):
    _require(isinstance(profile, dict) and set(profile) == _PROFILE_FIELDS, 'Invalid launch-profile fields')
    _require(type(profile['schema_version']) is int and profile['schema_version'] == 1, 'Unsupported launch-profile schema')
    _require(profile['provenance'] in ('observed_entry_table', 'external_launch_profile'), 'Unsupported profile provenance')
    esp = _uint(profile['esp'], 'Profile ESP')
    _require(type(profile['df']) is int and profile['df'] == 0, 'Selected entry model requires DF=0')
    page_size = _uint(profile['page_size'], 'Profile page_size')
    _require(page_size >= 4 and page_size & (page_size - 1) == 0, 'Invalid profile page size')
    index = profile['phdr_load_index']
    _require(type(index) is int, 'phdr_load_index must be integer')
    candidates = _phdr_candidates(elf)
    selected = [c for c in candidates if c['load_index'] == index]
    _require(len(selected) == 1, 'Profile selects no file-backed program-header mapping')
    derived = {3: selected[0]['address'], 4: elf['phentsize'], 5: elf['phnum'], 6: page_size, 9: elf['entry']}
    pointers = []
    for label in ('argv_pointers', 'envp_pointers'):
        values = profile[label]
        _require(isinstance(values, list) and len(values) <= 8192, label + ' must be a bounded list')
        pointers.append([_uint(v, label) for v in values])
        _require(all(values), label + ' contains NULL')
    pairs = profile['auxv']
    _require(isinstance(pairs, list) and 0 < len(pairs) <= 4096, 'Invalid profile auxv')
    auxv = []
    for i, pair in enumerate(pairs):
        _require(isinstance(pair, (list, tuple)) and len(pair) == 2, 'Invalid profile auxv pair')
        tag, value = pair
        _uint(tag, 'Auxv type')
        _require((tag == 0) == (i == len(pairs) - 1), 'Profile auxv must end at its only AT_NULL')
        if tag in derived:
            _require(value is None or type(value) is int and value == derived[tag], 'Profile conflicts with derived auxv value')
            value = derived[tag]
        else:
            _uint(value, 'Auxv value')
        auxv.append([tag, value])
    _aux_map(auxv)
    argv, envp = pointers
    words = [len(argv), *argv, 0, *envp, 0, *(v for pair in auxv for v in pair)]
    _require(len(words) <= 16384 and esp + len(words) * 4 <= _U32_END, 'Launch table exceeds supported extent')
    mapping = _mapping(profile['stack_mapping'], esp, esp + len(words) * 4, page_size)
    _require(all(mapping['start'] <= ptr < mapping['end'] for ptr in argv + envp), 'Argument/environment pointer outside admitted stack mapping')
    return struct.pack('<' + 'I' * len(words), *words), derived, candidates


def _origin_fields(layout):
    fields = []

    def field(name, address, size, source):
        if size:
            fields.append({'field': name, 'address': address, 'size': size, 'source': source})

    field('argc', layout['address'], 4, 'length of admitted launch_profile.argv_pointers')
    argv, envp, auxv = layout['regions'][1:]
    field('argv pointers', argv['address'], argv['size'] - 4, 'launch_profile.argv_pointers')
    field('argv NULL', argv['address'] + argv['size'] - 4, 4, 'entry-table structural zero')
    field('envp pointers', envp['address'], envp['size'] - 4, 'launch_profile.envp_pointers')
    field('envp NULL', envp['address'] + envp['size'] - 4, 4, 'entry-table structural zero')
    sources = {3: 'ELF program-header mapping plus admitted phdr_load_index',
               4: 'ELF.e_phentsize', 5: 'ELF.e_phnum', 6: 'launch_profile.page_size',
               9: 'ELF.e_entry'}
    for index, (tag, value) in enumerate(layout['auxv']):
        address = auxv['address'] + index * 8
        field(f'auxv[{index}].type', address, 4, 'launch_profile.auxv tag order')
        source = sources.get(tag, 'launch_profile.auxv external value')
        if tag == 0:
            source = 'launch_profile.auxv ignored AT_NULL value'
        field(f'auxv[{index}].value', address + 4, 4, source)
    _require(sum(f['size'] for f in fields) == layout['size'], 'Entry provenance extent mismatch')
    _require(all(a['address'] + a['size'] == b['address'] for a, b in zip(fields, fields[1:])),
             'Entry provenance has an overlap or gap')
    return fields


def verify_entry_contract(elf, stack, base, esp, known_mask, profile=None, *, df=0, stack_mapping=None):
    """Classify and check a table-only projection under named launch premises.

    A supplied profile can reconstruct the selected bytes without reading them
    as values.  Matching such a profile still is not independent OS evidence.
    Missing profiles produce an explicitly observation-derived template only.
    """
    elf = _bytes(elf, 'ELF')
    stack = _bytes(stack, 'Stack snapshot')
    known_mask = _bytes(known_mask, 'Known mask')
    _require(type(df) is int and df == 0, 'Selected entry model requires observed DF=0')
    parsed_elf = parse_elf32(elf)
    layout = parse_entry_table(stack, base, esp, known_mask=known_mask)
    start, stop = esp - base, layout['end'] - base
    _require(not any(known_mask[:start]) and not any(known_mask[stop:]), 'Projection contains bytes outside the entry table')
    supplied = profile is not None
    if profile is None:
        if stack_mapping is None:
            stack_mapping = {'start': base, 'end': base + len(stack), 'read': True, 'write': True}
        profile = _profile_from_observation(elf, parsed_elf, layout, esp, df, stack_mapping)
    _require(isinstance(profile, dict), 'Launch profile must be an object')
    _require(profile.get('elf_sha256') == hashlib.sha256(elf).hexdigest(), 'Launch profile is bound to another ELF')
    reconstructed, derived, candidates = _reconstruct(profile, parsed_elf)
    _require(profile['esp'] == esp and profile['df'] == df, 'Launch scalar mismatch')
    _require(len(reconstructed) == stop - start, 'Launch table extent mismatch')
    _require(reconstructed == stack[start:stop], 'Reconstructed entry table differs from known observation')
    canonical = json.dumps(profile, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()
    external_profile = supplied and profile['provenance'] == 'external_launch_profile'
    return {
        'schema_version': 1,
        'status': 'VERIFIED_ENTRY_TABLE_UNDER_EXPLICIT_PROFILE' if external_profile else 'OBSERVED_ENTRY_LAYOUT_ONLY',
        'layout': layout, 'profile': profile, 'profile_supplied': supplied,
        'profile_provenance': profile['provenance'], 'profile_sha256': hashlib.sha256(canonical).hexdigest(),
        'ELF_derived_auxv_values': {str(k): v for k, v in derived.items() if k != 6},
        'profile_derived_auxv_values': {'6': derived[6]},
        'field_origins_under_explicit_profile': _origin_fields(layout),
        'origin_fields_cover_known_projection': True,
        'ELF_phdr_address_candidates': candidates,
        'phdr_mapping_selection_is_profile_premise': len(candidates) != 1,
        'reconstructed_known_bytes': len(reconstructed), 'known_projection_completely_classified': True,
        'independent_OS_entry_origins_proven': False,
        'stack_mapping_permissions_independently_verified': False,
        'argv_envp_string_contents_verified': False,
        'external_admissions': [
            'ESP and DF=0 for this launch.',
            'argc is reconstructed from the admitted argv pointer list; argv/envp pointer values and layout remain profile inputs.',
            'Initial stack mapping, permissions and pointer-target contents are not established by parsing the table.',
            'Page size, non-ELF auxv values, auxv order and any ambiguous AT_PHDR mapping selection remain profile inputs.',
            'A matching supplied profile is not authenticated OS-entry evidence; observation-derived templates remain observations.',
        ],
        'oep_proof': 'NOT_ESTABLISHED',
    }
