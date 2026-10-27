"""Bind a fresh generic capture to source constructors and a chronological replay.

The observer, ELF loader, decoder, IR semantics and syscall model remain trusted.
Observed final bytes are conclusions to compare, never replay premises.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import struct

try:
    from . import oep_verify as verifier
    from .oep_entry import parse_elf32, parse_entry_table
    from .oep_environment import syscall_arity
except ImportError:
    import oep_verify as verifier
    from oep_entry import parse_elf32, parse_entry_table
    from oep_environment import syscall_arity


MAX_CAPTURE = 256 * 1024**2
MAX_SIDE = 64 * 1024**2
MAX_STACK = 1024 * 1024
SUPPORTED_SYSCALLS = {4, 5, 6, 45, 85, 90, 91, 93, 125, 144, 192, 356}
GPRS = verifier.GPRS
FLAG_BITS = verifier.FLAG_BITS
require = verifier.require


def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'Duplicate JSON key: ' + key)
            result[key] = value
        return result

    def invalid(value):
        raise ValueError('Noninteger JSON number: ' + value)

    return json.loads(raw, object_pairs_hook=pairs, parse_float=invalid, parse_constant=invalid)


def uint(value, label, maximum=0xffffffff):
    require(type(value) is int and 0 <= value <= maximum, label)
    return value


def hex_bytes(value, label, limit=16 * 1024**2):
    require(type(value) is str and len(value) % 2 == 0 and len(value) <= limit * 2, label)
    try:
        result = bytes.fromhex(value)
    except ValueError as error:
        raise ValueError(label) from error
    require(len(result) * 2 == len(value), label + ' contains whitespace')
    return result


def one(rows, kind, **fields):
    selected = [row for row in rows if row.get('kind') == kind
                and all(row.get(key) == value for key, value in fields.items())]
    require(len(selected) == 1, 'Unique ' + kind + ' observation required: ' + str(fields))
    return selected[0]


def json_lines(path, *, max_bytes=MAX_SIDE, max_line_bytes=4 * 1024**2):
    path = Path(path)
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= max_bytes,
            'Replay sidecar absent, symlink or oversized')
    with path.open('rb') as stream:
        for line in stream:
            require(line.endswith(b'\n') and len(line) <= max_line_bytes, 'Replay sidecar framing')
            row = strict_json(line)
            require(type(row) is dict, 'Replay sidecar object')
            yield row


def calls(rows):
    """Validate all int80 boundaries, returning entry/return/post triples."""
    result, pending, returned = [], None, None
    arg_registers = ('ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp')
    for row in rows:
        kind = row.get('kind')
        if kind == 'syscall_enter':
            require(pending is None and returned is None and len(result) < 256, 'Overlapping syscall or syscall budget')
            require(type(row.get('ordinal')) is int and row['ordinal'] == len(result) + 1, 'Syscall ordinal order')
            number = uint(row.get('number'), 'Syscall number')
            uint(row.get('pc'), 'Syscall PC', 0xfffffffd)
            require(number in SUPPORTED_SYSCALLS, 'Unsupported captured syscall')
            args = row.get('args')
            require(type(args) is list and len(args) == 6, 'Six captured ABI arguments required')
            for value in args:
                uint(value, 'Syscall argument')
            registers = row.get('registers')
            require(type(registers) is dict, 'Syscall entry registers missing')
            for name in (*GPRS, 'eflags'):
                uint(registers.get(name), 'Syscall entry ' + name)
            require(registers['eax'] == number, 'Captured syscall number differs from EAX')
            arity = syscall_arity(number, args[1] if number == 5 else 0)
            require(all(registers[name] == value for name, value in zip(arg_registers[:arity], args[:arity])),
                    'Consumed syscall argument differs from register')
            if number in (90, 192):
                array = row.get('mmap_args') if number == 90 else args
                require(type(array) is list and len(array) == 6, 'Mapping argument array')
                for value in array:
                    uint(value, 'Mapping argument')
            pending = row
        elif kind == 'syscall_return':
            require(pending is not None and returned is None, 'Unexpected or duplicate syscall return')
            require(all(row.get(key) == pending[key] for key in ('ordinal', 'number', 'pc')), 'Syscall return identity differs')
            outcome = uint(row.get('result_u32'), 'Syscall result')
            require(outcome < 0xfffff001, 'Failed syscall outside supported model')
            if pending['number'] == 85:
                reply = hex_bytes(row.get('reply_hex'), 'Readlink reply', 4096)
                require(len(reply) == outcome <= pending['args'][2], 'Readlink result extent')
            else:
                require(row.get('reply_hex') in (None, ''), 'Unexpected syscall reply bytes')
            returned = row
        elif kind == 'syscall_post':
            require(pending is not None and returned is not None, 'Unexpected syscall post')
            require(all(row.get(key) == pending[key] for key in ('ordinal', 'number'))
                    and row.get('pc') == pending['pc'] + 2, 'Syscall post identity differs')
            registers = row.get('registers')
            require(type(registers) is dict, 'Syscall post registers missing')
            for name in (*GPRS, 'eflags'):
                uint(registers.get(name), 'Syscall post ' + name)
            require(registers['eax'] == returned['result_u32'], 'Syscall post EAX differs from return')
            require(all(registers[name] == pending['registers'][name] for name in (*arg_registers, 'esp')),
                    'Observed syscall GPR clobber')
            require(registers['eflags'] == pending['registers']['eflags'],
                    'Observed int80 EFLAGS clobber; inspect the live flag provider')
            # The profile preserves flags across int80. Native-known flag bits
            # are independently checked later; observations never fill UNKNOWN.
            result.append((pending, returned, row))
            pending = returned = None
        elif kind in ('payload_entry', 'footer'):
            require(pending is None and returned is None, 'Incomplete syscall at capture boundary')
    require(pending is None and returned is None, 'Incomplete syscall chain')
    return result


def read_capture(raw, launch):
    """Read strict bounded JSONL and check its exact serialized prefix binding."""
    require(isinstance(raw, bytes) and 0 < len(raw) <= MAX_CAPTURE, 'Capture byte budget')
    lines = raw.splitlines(keepends=True)
    require(2 <= len(lines) <= 65536 and all(line.endswith(b'\n') and len(line) <= 4 * 1024**2
                                           for line in lines), 'Capture line framing')
    rows = [strict_json(line) for line in lines]
    require(all(type(row) is dict for row in rows), 'Capture row object')
    header, footer = rows[0], rows[-1]
    require(header.get('kind') == 'header' and footer.get('kind') == 'footer'
            and sum(row.get('kind') == 'header' for row in rows) == 1
            and sum(row.get('kind') == 'footer' for row in rows) == 1, 'Capture header/footer framing')
    require(type(launch) is dict and launch.get('schema_version') == 1, 'Launch manifest schema')
    run = launch.get('run_id')
    require(type(run) is str and re.fullmatch('[0-9a-f]{32}', run), 'Capture run identity')
    require(header.get('capture_kind') == 'GENERIC_UNPACK_CAPTURE_V1'
            and type(header.get('schema_version')) is int and header['schema_version'] == 1
            and header.get('run_id') == footer.get('run_id') == run
            and header.get('elf_sha256') == launch.get('source_elf_sha256'), 'Capture launch identity')
    require(all(row.get('run_id', run) == run for row in rows), 'Mixed capture run identity')
    require(type(header.get('elf_sha256')) is str
            and re.fullmatch('[0-9a-f]{64}', header['elf_sha256']), 'Capture source digest')
    for key in ('guest_vma_api_version', 'entry_construction_api_version', 'brk_api_version'):
        require(type(header.get(key)) is int and header[key] == 1, 'Missing observer capability: ' + key)
    require(header.get('binary_path_matches') is True and header.get('captured_execution_only') is True,
            'Capture binary identity or scope')
    require(header.get('executed_pc_hash_encoding') == 'LE32_EXECUTED_PC'
            and header.get('executed_fetch_hash_encoding') == 'LE32_PC_U8_SIZE_BYTES', 'Capture hash encoding')
    prefix = b''.join(lines[:-1])
    require(footer.get('events_bytes_before_footer') == len(prefix)
            and footer.get('events_sha256_before_footer') == hashlib.sha256(prefix).hexdigest(),
            'Capture footer prefix binding differs')
    require(footer.get('success') is True and footer.get('reason') == 'selected_candidate_boundary'
            and footer.get('target_instruction_executed') is False
            and footer.get('stopped_before_instruction') is True, 'Capture completion boundary')
    for key in ('executed_pc_sha256', 'executed_fetch_sha256'):
        require(type(footer.get(key)) is str and re.fullmatch('[0-9a-f]{64}', footer[key]), 'Capture digest: ' + key)
    uint(footer.get('instructions'), 'Capture instruction budget', 30000000)
    count = uint(footer.get('syscall_count'), 'Capture syscall count', 256)
    require(type(footer.get('syscall_returns')) is int and footer['syscall_returns'] == count,
            'Capture syscall returns differ')
    triples = calls(rows)
    require(len(triples) == count, 'Captured syscall timeline differs')
    boundary = one(rows, 'payload_entry')
    target = uint(header.get('target_pc'), 'Capture target')
    require(target == boundary.get('pc') and boundary.get('stopped_before_instruction') is True
            and boundary.get('target_instruction_executed') is False
            and boundary.get('instructions') == footer['instructions']
            and boundary.get('syscall_count') == count, 'Capture boundary identity')
    if 'target_pc' in launch:
        require(target == launch['target_pc'], 'Capture selected target changed')
    for row in (header, footer):
        require(row.get('oep_proof', 'NOT_ESTABLISHED') == 'NOT_ESTABLISHED', 'Capture proof scope promoted')
        for key in ('kernel_implementation_verified', 'independent_OS_entry_origins_proven',
                    'unconditional_oep_proven', 'historical_certificates_upgraded', 'fuzzing_ready'):
            require(row.get(key, False) is False, 'Capture scope promoted: ' + key)
    return rows


def snapshots(rows, prefix):
    """Join indexed snapshot chunks, rejecting gaps, duplicates and overlap."""
    pattern = re.compile(re.escape(prefix) + r'_(\d+)_(\d+)\Z')
    groups = {}
    for row in rows:
        if row.get('kind') != 'snapshot':
            continue
        label = row.get('label')
        if type(label) is not str or not label.startswith(prefix + '_'):
            continue
        match = pattern.fullmatch(label)
        require(match is not None, 'Snapshot chunk label')
        index, chunk = map(int, match.groups())
        require(index <= 4095 and chunk <= 8191, 'Snapshot chunk index budget')
        group = groups.setdefault(index, {})
        require(chunk not in group, 'Duplicate snapshot chunk')
        address = uint(row.get('address'), 'Snapshot chunk address')
        size = uint(row.get('size'), 'Snapshot chunk size', 131072)
        require(size > 0 and address + size <= 2**32, 'Snapshot chunk extent')
        data = hex_bytes(row.get('bytes_hex'), 'Snapshot chunk bytes', 131072)
        require(len(data) == size, 'Snapshot chunk byte extent')
        group[chunk] = (address, data)
    require(groups and set(groups) == set(range(len(groups))), 'Snapshot group index gap')
    result = []
    for index in range(len(groups)):
        group = groups[index]
        require(set(group) == set(range(len(group))), 'Snapshot chunk index gap')
        address = group[0][0]
        parts, cursor = [], address
        for chunk in range(len(group)):
            begin, data = group[chunk]
            require(begin == cursor, 'Snapshot chunks overlap or leave gaps')
            parts.append(data)
            cursor += len(data)
        result.append({'address': address, 'data': b''.join(parts)})
    require(sum(len(row['data']) for row in result) <= 32 * 1024**2, 'Snapshot aggregate budget')
    ordered = sorted(result, key=lambda row: row['address'])
    require(all(left['address'] + len(left['data']) <= right['address']
                for left, right in zip(ordered, ordered[1:])), 'Snapshot groups overlap')
    return result


def page_map(regions, key='prot'):
    result = {}
    previous = 0
    require(type(regions) is list and len(regions) <= 4096, 'VMA region budget')
    for region in regions:
        require(type(region) is dict, 'VMA object')
        start, end, protection = region.get('start'), region.get('end'), region.get(key)
        uint(start, 'VMA start')
        uint(end, 'VMA end', 2**32)
        uint(protection, 'VMA protection', 7)
        require(start < end and start % 4096 == end % 4096 == 0 and start >= previous,
                'VMA overlap, order or alignment')
        previous = end
        for address in range(start, end, 4096):
            require(len(result) < 65536, 'VMA page budget')
            result[address] = protection
    return result


def _observed_vmas(row):
    require(row.get('page_size') == 4096 and type(row.get('page_size')) is int, 'Observed page size')
    pages = page_map(row.get('regions'))
    for item in row['regions']:
        flags = uint(item.get('raw_flags'), 'Observed raw VMA flags')
        require(flags & 8 and item['prot'] == (flags & 5) | (2 if flags & 16 else 0),
                'Observed VMA raw flags differ')
    return pages


def _region_bytes(regions, address, size, label):
    end = address + size
    parts = []
    for row in sorted(regions, key=lambda item: item['address']):
        begin = max(address, row['address'])
        stop = min(end, row['address'] + len(row['data']))
        if begin < stop:
            require(begin == address, label + ' coverage gap or overlap')
            parts.append(row['data'][begin - row['address']:stop - row['address']])
            address = stop
    require(address == end, label + ' coverage missing')
    return b''.join(parts)


def _entry_origins(rows, launch, packed, stack, base, esp, df):
    """Check loader words and launch strings, leaving their origin trusted."""
    require(df == 0, 'Generic entry requires observed DF=0')
    constructor = one(rows, 'entry_construction')
    metadata = constructor.get('metadata')
    require(type(metadata) is list and len(metadata) == 8, 'Entry constructor metadata extent')
    for value in metadata:
        uint(value, 'Entry constructor metadata')
    version, width, constructed_sp, argc, envc, entry, phdr, interpreter = metadata
    parsed = parse_elf32(packed)
    require(version == 1 and width == 4 and not interpreter and constructed_sp == esp
            and entry == parsed['entry'], 'Entry constructor identity')
    layout = parse_entry_table(stack, base, esp)
    require(argc == layout['argc'] and envc == len(layout['envp_pointers']), 'Entry constructor argc/envc')
    table_end = parsed['phoff'] + parsed['phentsize'] * parsed['phnum']
    phdrs = [item for item in parsed['program_headers'] if item['type'] == 1
             and item['offset'] <= parsed['phoff'] and table_end <= item['offset'] + item['filesz']
             and item['vaddr'] + parsed['phoff'] - item['offset'] == phdr]
    require(len(phdrs) == 1, 'Constructor PHDR differs from source ELF')
    aux = {}
    for tag, value in layout['auxv']:
        if tag in (3, 4, 5, 6, 9):
            require(tag not in aux, 'Duplicate ELF-bound auxv field')
            aux[tag] = value
    require(aux == {3: phdr, 4: parsed['phentsize'], 5: parsed['phnum'], 6: 4096, 9: entry},
            'Entry auxv differs from ELF constructor')
    words = constructor.get('words')
    require(type(words) is list and 0 < len(words) <= 1024, 'Constructor word budget')
    origins = {}
    mask = bytearray(len(stack))
    for record in words:
        require(type(record) is list and len(record) == 3, 'Constructor word')
        address, value, kind = record
        uint(address, 'Constructor word address')
        uint(value, 'Constructor word value')
        require(type(kind) is int and kind in (1, 2, 3, 4) and address % 4 == 0
                and esp <= address < layout['end'] and address not in origins, 'Constructor word geometry')
        expected_kind = next(index + 1 for index, region in enumerate(layout['regions'])
                             if region['address'] <= address < region['address'] + region['size'])
        offset = address - base
        require(kind == expected_kind and stack[offset:offset + 4] == struct.pack('<I', value),
                'Constructor word differs from initial RAM')
        origins[address] = kind
        mask[offset:offset + 4] = b'\xff' * 4
    require(set(origins) == set(range(esp, layout['end'], 4)), 'Constructor table coverage gap')
    string_count = 0
    if launch is not None:
        all_ranges = []
        for key, pointers in (('guest_argv', layout['argv_pointers']), ('guest_environ', layout['envp_pointers'])):
            values = launch.get(key)
            require(type(values) is list and len(values) == len(pointers) <= 256, 'Launch string count')
            previous = None
            for pointer, value in zip(pointers, values):
                require(type(value) is str and '\0' not in value, 'Launch string')
                data = value.encode('utf-8') + b'\0'
                require(len(data) <= 4096 and base <= pointer and pointer + len(data) <= base + len(stack),
                        'Launch string outside captured stack')
                require(pointer >= layout['end'] or pointer + len(data) <= esp, 'Launch string overlaps table')
                require(previous is None or pointer == previous, 'Launch string order/progression differs')
                offset = pointer - base
                require(stack[offset:offset + len(data)] == data, 'Launch string differs from manifest')
                mask[offset:offset + len(data)] = b'\xff' * len(data)
                previous = pointer + len(data)
                all_ranges.append((pointer, previous))
                string_count += len(data)
        all_ranges.sort()
        require(all(left[1] <= right[0] for left, right in zip(all_ranges, all_ranges[1:])), 'Launch string overlap')
    return bytes(mask), {'constructor_table_bytes': len(words) * 4, 'launch_string_bytes': string_count,
                         'entry_table_matches_constructor': True,
                         'launch_strings_bound': launch is not None,
                         'independent_OS_entry_origins_proven': False,
                         'initial_ESP_DF_and_other_auxv_values_are_explicit_premises': True}


def initial_context(rows, packed, loader, launch=None):
    require(isinstance(packed, bytes) and hashlib.sha256(packed).hexdigest() == rows[0]['elf_sha256'],
            'Capture source bytes differ')
    require(rows[0].get('elf_size') == len(packed), 'Capture source size differs')
    initial = one(rows, 'initial')
    geometry = one(rows, 'initial_geometry')
    registers = initial.get('registers')
    require(type(registers) is dict, 'Initial registers missing')
    for name in (*GPRS, 'eflags'):
        uint(registers.get(name), 'Initial ' + name)
    esp, df = registers['esp'], registers['eflags'] >> 10 & 1
    require(initial.get('pc') == rows[0].get('initial_pc') == loader['entry']
            and rows[0].get('initial_sp') == esp and rows[0].get('initial_df') == df, 'Initial scalar binding')
    base = uint(geometry.get('stack_base'), 'Initial stack base')
    size = uint(geometry.get('stack_size'), 'Initial stack size', MAX_STACK)
    require(size > 0 and base % 4096 == size % 4096 == 0 and base <= esp < base + size <= 2**32,
            'Initial stack geometry')
    stack_rows = snapshots(rows, 'initial_stack')
    require(len(stack_rows) == 1 and stack_rows[0]['address'] == base
            and len(stack_rows[0]['data']) == size, 'Initial stack snapshot geometry differs')
    observed = snapshots(rows, 'initial_load')
    initial_regions = loader['initial_regions']
    loads = geometry.get('loads')
    require(type(loads) is list and len(loads) == len(loader['protections']), 'Observed initial LOAD table extent')
    load_pages = []
    for item in loads:
        require(type(item) is dict, 'Observed initial LOAD geometry')
        start = uint(item.get('base'), 'Observed initial LOAD base')
        count = uint(item.get('size'), 'Observed initial LOAD size', 1024 * 1024)
        flags = uint(item.get('elf_flags'), 'Observed initial LOAD ELF flags', 7)
        load_pages.append({'start': start, 'end': start + count,
                           'prot': (flags >> 2 & 1) | (flags & 2) | (flags & 1) << 2})
    require(sorted(load_pages, key=lambda item: item['start']) == loader['protections'],
            'Observed initial LOAD table differs from source ELF')
    require(sum(len(data) for _, data in initial_regions) == sum(len(row['data']) for row in observed),
            'Initial ELF observed/source extent differs')
    for address, data in initial_regions:
        require(_region_bytes(observed, address, len(data), 'Initial ELF') == data,
                'Initial ELF RAM differs from source constructor')
    initial_vmas = _observed_vmas(one(rows, 'vma_snapshot', phase='initial', ordinal=0))
    for region in loader['protections']:
        for address in range(region['start'], region['end'], 4096):
            require(initial_vmas.get(address) == region['prot'], 'Source ELF initial permissions differ')
    require(all(initial_vmas.get(address) == loader['stack_prot'] for address in range(base, base + size, 4096)),
            'Initial stack permissions differ from source ELF loader policy')
    initial_brk = max(region['end'] for region in loader['protections'])
    brk = one(rows, 'brk', phase='initial', ordinal=0)
    require(brk.get('initial') == brk.get('current') == initial_brk,
            'Initial program break differs from source ELF constructor')
    stack = stack_rows[0]['data']
    origin_mask, receipt = _entry_origins(rows, launch, packed, stack, base, esp, df)
    receipt.update(source_elf_initial_bytes_compared=sum(len(data) for _, data in initial_regions),
                   source_ELF_loader_constructor_independently_compared=True,
                   observed_initial_stack_bytes=size)
    return {'packed': packed, 'stack_base': base, 'stack': stack, 'esp': esp, 'df': df, 'initial_brk': initial_brk,
            'initial_regions': initial_regions, 'calls': calls(rows), 'origin_mask': origin_mask,
            'source_receipt': receipt}


def validate_projection(context, projection):
    require(isinstance(projection, bytes) and len(projection) == len(context['stack'])
            and all(value in (0, 255) for value in projection), 'Initial read projection encoding')
    require(all(not selected or origin == 255 for selected, origin in zip(projection, context['origin_mask'])),
            'Consumed initial byte lacks constructor/launch origin')
    return dict(context['source_receipt'], consumed_initial_stack_bytes=projection.count(255),
                all_consumed_initial_stack_bytes_classified=True)


def contracts_text(rows):
    lines = []
    for entry, returned, _ in calls(rows):
        reply = returned.get('reply_hex') or '-'
        lines.append(' '.join([f"{entry['pc']:x}", str(entry['number']),
                               *[f'{value:x}' for value in entry['args']],
                               f"{returned['result_u32']:x}", reply]))
        if entry['number'] in (90, 192):
            values = entry['mmap_args'] if entry['number'] == 90 else entry['args']
            lines.append(' '.join(f'{value:x}' for value in values))
    return '\n'.join(lines) + ('\n' if lines else '')


def compare_known(value, known, observed, label):
    require(len(value) == len(known) == len(observed), label + ' extent differs')
    require(all(v & ~k == 0 and (v ^ o) & k == 0 for v, k, o in zip(value, known, observed)),
            label + ' known bytes differ')
    return sum(k == 255 for k in known)


def compare_scalars(model, flags, observed, label):
    require(type(model) is list and len(model) == 8 and type(flags) is list and len(flags) == 7,
            label + ' scalar extent')
    unknown = []
    for name, item in zip(GPRS, model):
        require(type(item) is dict and set(item) == {'value', 'known'}, label + ' register encoding')
        value, known = uint(item['value'], label + ' register value'), uint(item['known'], label + ' known mask')
        actual = uint(observed.get(name), label + ' observed register')
        require(value & ~known == 0 and (value ^ actual) & known == 0, label + ' register differs: ' + name)
        if known != 0xffffffff:
            unknown.append({'register': name, 'unknown_mask': known ^ 0xffffffff})
    for bit, item in zip(FLAG_BITS, flags):
        require(type(item) is dict and set(item) == {'value', 'known'} and type(item['value']) is int
                and type(item['known']) is int and item['known'] in (0, 1)
                and 0 <= item['value'] <= item['known'], label + ' flag encoding')
        actual = uint(observed.get('eflags'), label + ' observed EFLAGS')
        require(not item['known'] or item['value'] == actual >> bit & 1, label + ' modeled flag differs')
        if not item['known']:
            unknown.append({'flag_bit': bit})
    return unknown


def _snapshot_range(rows, address, size, ordinal, prefixes, low, high):
    regions = []
    for index in range(low + 1, high):
        row = rows[index]
        if row.get('kind') != 'snapshot' or row.get('syscall_ordinal') != ordinal:
            continue
        label = row.get('label', '')
        if not any(label == prefix or label.startswith(prefix + '_') for prefix in prefixes):
            continue
        data = hex_bytes(row.get('bytes_hex'), 'Kernel effect observation', 131072)
        require(row.get('size') == len(data), 'Kernel effect observation size')
        regions.append({'address': uint(row.get('address'), 'Kernel effect observation address'), 'data': data})
    return _region_bytes(regions, address, size, 'Kernel effect observation')


def compare_kernel(rows, directory):
    triples = calls(rows)
    models = list(json_lines(Path(directory) / 'kernel.jsonl'))
    require(len(models) == len(triples) + 1 and models[0].get('kind') == 'initial_model',
            'Kernel model timeline extent')
    observations = [row for row in rows if row.get('kind') == 'vma_snapshot'
                    and row.get('phase') in ('initial', 'syscall_return')]
    require(len(observations) == len(models), 'Kernel VMA timeline extent')
    indexed = {}
    for row in observations:
        ordinal = uint(row.get('ordinal'), 'Observed VMA ordinal', len(triples))
        require(ordinal not in indexed, 'Duplicate observed VMA ordinal')
        require(row['phase'] == ('initial' if ordinal == 0 else 'syscall_return'), 'VMA observation phase')
        indexed[ordinal] = row
    require(set(indexed) == set(range(len(models))), 'Kernel VMA observation ordinal gap')
    tracked, file_identity, unknown = set(), {}, []
    memory_bytes = file_bytes = 0
    initial_break = one(rows, 'brk', phase='initial', ordinal=0)
    break_value = uint(initial_break.get('initial'), 'Initial program break')
    require(initial_break.get('current') == break_value, 'Initial program break observation changed')
    for ordinal, model in enumerate(models):
        require(model.get('source_kind') == 'computed_IR_model' and model.get('ordinal') == ordinal,
                'Kernel model provenance/order')
        current, observed = page_map(model['vmas'], 'permissions'), _observed_vmas(indexed[ordinal])
        tracked.update(current)
        require(all(observed.get(address) == prot for address, prot in current.items()), 'Kernel VMA permission mismatch')
        require(not (tracked - current.keys()).intersection(observed), 'Kernel unmap observation mismatch')
        if ordinal == 0:
            continue
        entry, returned, post = triples[ordinal - 1]
        require(model.get('kind') == 'kernel_model' and model.get('number') == entry['number']
                and model.get('pc_before') == entry['pc'] and model.get('pc_after') == entry['pc'] + 2,
                'Kernel model syscall identity')
        unknown.extend({'ordinal': ordinal, **item} for item in compare_scalars(
            model['registers'], model['flags'], post['registers'], 'Post-syscall'))
        enter_index, return_index, post_index = rows.index(entry), rows.index(returned), rows.index(post)
        require(return_index < rows.index(indexed[ordinal]) < post_index, 'Kernel VMA observation outside boundary')
        brk = one(rows, 'brk', phase='syscall_return', ordinal=ordinal)
        require(brk.get('initial') == brk.get('current') == break_value
                and return_index < rows.index(brk) < post_index, 'Unsupported changing program break')
        if entry['number'] == 45:
            require(returned['result_u32'] == break_value, 'Program break result differs from unchanged model')
        changed = model.get('changed_memory')
        require(type(changed) is list and len(changed) <= 4096, 'Kernel changed-memory budget')
        for cell in changed:
            address, size = uint(cell.get('address'), 'Kernel RAM address'), uint(cell.get('size'), 'Kernel RAM size', 131072)
            value = hex_bytes(cell.get('data_hex'), 'Kernel RAM value', 131072)
            known = hex_bytes(cell.get('known_hex'), 'Kernel RAM known mask', 131072)
            require(len(value) == len(known) == size and address + size <= 2**32, 'Kernel RAM model extent')
            if entry['number'] == 85:
                require(address == entry['args'][1] and size == returned['result_u32'], 'Readlink modeled extent')
                actual = hex_bytes(returned['reply_hex'], 'Readlink bytes', 4096)
            else:
                actual = _snapshot_range(rows, address, size, ordinal,
                    ('syscall_mapping_' + str(ordinal), 'syscall_memory_' + str(ordinal)), return_index, post_index)
            memory_bytes += compare_known(value, known, actual, 'Post-syscall RAM')
        cell = model.get('write_buffer')
        require((cell is not None) == (entry['number'] == 4), 'Kernel write-buffer model presence')
        if cell is not None:
            require(cell.get('address') == entry['args'][1] and cell.get('size') == entry['args'][2],
                    'Write-buffer model identity')
            actual = _snapshot_range(rows, cell['address'], cell['size'], ordinal,
                ('write_buffer_' + str(ordinal),), enter_index, return_index)
            compare_known(hex_bytes(cell['data_hex'], 'Write-buffer bytes', 131072),
                          hex_bytes(cell['known_hex'], 'Write-buffer mask', 131072), actual, 'Write buffer')
        files = model.get('files')
        require(type(files) is list and len(files) <= 32, 'Kernel file budget')
        for item in files:
            phase = 'syscall_enter' if entry['number'] == 6 else 'syscall_return'
            actual = one(rows, 'file_snapshot', phase=phase, ordinal=ordinal, fd=item['fd'])
            index = rows.index(actual)
            require((enter_index < index < return_index) if phase == 'syscall_enter'
                    else (return_index < index < post_index), 'File observation outside kernel boundary')
            key = item['model_file_id']
            require(key not in file_identity or file_identity[key] == actual['file_id'], 'Modeled backing file identity changed')
            file_identity[key] = actual['file_id']
            size = uint(item.get('size'), 'Modeled file size', 1024 * 1024)
            require(actual.get('size') == size, 'Actual file size differs')
            value = hex_bytes(item.get('data_hex'), 'Modeled file bytes', 1024 * 1024)
            known = hex_bytes(item.get('known_hex'), 'Modeled file known', 1024 * 1024)
            require(len(value) == len(known) == size, 'Modeled file extent')
            file_bytes += compare_known(value, known, hex_bytes(actual.get('bytes_hex'), 'Actual file bytes', 1024 * 1024),
                                        'Actual file contents')
    return {'syscalls': len(triples), 'modeled_VMA_presence_and_permissions_compared': True,
            'post_syscall_unknown_scalars': unknown, 'post_syscall_RAM_known_bytes_compared': memory_bytes,
            'actual_file_known_bytes_compared': file_bytes, 'kernel_implementation_verified': False}


def compare_initial_reads(initial_regions, path):
    seen = set()
    for row in json_lines(path, max_bytes=16 * 1024**2):
        address = uint(row.get('address'), 'Initial read address')
        value = uint(row.get('value'), 'Initial read value', 255)
        require(row.get('known') == 255 and type(row.get('known')) is int
                and address not in seen and len(seen) < 1048576, 'Initial read receipt encoding/order')
        candidates = [data[address - start] for start, data in initial_regions if start <= address < start + len(data)]
        require(candidates == [value], 'Consumed initial ELF RAM byte lacks source constructor binding')
        seen.add(address)
    return {'unique_initial_data_bytes': len(seen), 'all_initial_data_reads_source_bound': True}


def compare_replay(rows, directory, goals, *, initial_regions=None):
    directory = Path(directory)
    execution = strict_json((directory / 'execution.json').read_bytes())
    boundary = strict_json((directory / 'boundary.json').read_bytes())
    observed = one(rows, 'payload_entry')
    footer = rows[-1]
    require(execution.get('status') == 'COMPUTED_GENERIC_ENTRY_TO_SELECTED_TRANSFER'
            and execution.get('pc') == observed['pc'] and execution.get('entry') == rows[0]['initial_pc']
            and execution.get('instructions') == footer['instructions']
            and execution.get('path_sha256') == footer['executed_pc_sha256']
            and execution.get('fetch_sha256') == footer['executed_fetch_sha256']
            and execution.get('fetch_hash_encoding') == 'LE32_PC_U8_SIZE_BYTES'
            and execution.get('syscalls') == footer['syscall_count'], 'Replay differs from captured executed path/fetches')
    for key in ('checkpoint_used_as_seed', 'observed_final_state_used_as_input', 'kernel_implementation_verified',
                'independent_entry_origins_proven', 'target_instruction_executed'):
        require(execution.get(key) is False, 'Replay scope promoted: ' + key)
    unknown = compare_scalars(execution['registers'], execution['flags'], observed['registers'], 'Final')
    require(boundary.get('source_kind') == 'computed_IR_model' and boundary.get('pc') == observed['pc']
            and boundary.get('instructions') == execution['instructions']
            and boundary.get('path_sha256') == execution['path_sha256']
            and boundary.get('target_instruction_executed') is False, 'Boundary replay identity')
    transition, fetch = boundary.get('transition'), boundary.get('fetch')
    require(type(transition) is dict and transition.get('computed_target') == observed['pc']
            and transition.get('computed_target_known') is True
            and transition.get('pc') == observed.get('previous_pc')
            and transition.get('instruction_ordinal') == execution['instructions'], 'Computed final transfer differs')
    size = uint(observed.get('instruction_size'), 'Observed target instruction size', 15)
    require(size > 0 and type(fetch) is dict and fetch.get('pc') == observed['pc'] and fetch.get('size') == size
            and fetch.get('bytes_hex') == observed.get('bytes_hex')
            and fetch.get('known_hex') == 'ff' * size and fetch.get('ir_validator_passed') is True
            and fetch.get('target_instruction_executed') is False, 'Computed target fetch differs')
    catalogue = list(json_lines(directory / 'original-ir.jsonl', max_line_bytes=64 * 1024**2))
    last = [node for node in catalogue if node.get('pc') == transition['pc']
            and node.get('original_ir_sha256') == transition.get('original_ir_sha256')]
    require(len(last) == 1 and last[0].get('bytes') == transition.get('bytes_hex'), 'Final transfer source IR identity')
    current = _observed_vmas(one(rows, 'vma_snapshot', phase='payload_entry', ordinal=execution['syscalls']))
    modeled = page_map(boundary['vmas'], 'permissions')
    require(all(current.get(address) == prot for address, prot in modeled.items()), 'Final observed permissions differ')
    require(current.get(observed['pc'] & ~4095, 0) & 4, 'Observed target is not executable')
    final = snapshots(rows, 'final_goal')
    require(len(final) == len(goals), 'Final goal extent count differs')
    comparisons = []
    for goal, snapshot in zip(goals, final):
        address, data = goal['address'], goal['data']
        require(snapshot == {'address': address, 'data': data}, 'Fresh captured goal image differs from selected image')
        value = (directory / 'final' / f'ram-{address:08x}.bin').read_bytes()
        known = (directory / 'final' / f'known-{address:08x}.bin').read_bytes()
        count = compare_known(value, known, data, 'Final image')
        require(count == len(data), 'Final image contains unknown bytes')
        if 'prot' in goal:
            require(all(current.get(page) == goal['prot'] for page in range(address, address + len(data), 4096)),
                    'Fresh captured goal permissions differ from selected image')
        comparisons.append({'address': address, 'bytes': len(data), 'known_bytes': count})
    stack = snapshots(rows, 'final_stack')
    geometry = one(rows, 'initial_geometry')
    require(len(stack) == 1 and stack[0]['address'] == geometry['stack_base']
            and len(stack[0]['data']) == geometry['stack_size'], 'Final stack geometry differs')
    address, actual = stack[0]['address'], stack[0]['data']
    value = (directory / 'final' / f'ram-{address:08x}.bin').read_bytes()
    known = (directory / 'final' / f'known-{address:08x}.bin').read_bytes()
    count = compare_known(value, known, actual, 'Final stack')
    require(execution.get('initial_stack_base') == address and execution.get('initial_stack_size') == len(actual),
            'Replay initial stack geometry differs')
    result = {'execution': execution, 'comparisons': comparisons, 'final_unknown_scalars': unknown,
              'final_stack_known_bytes_compared': count, 'kernel': compare_kernel(rows, directory)}
    if initial_regions is not None:
        result['initial_reads'] = compare_initial_reads(initial_regions, directory / 'initial-reads.jsonl')
    return result
