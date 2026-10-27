"""Check fresh QEMU observations against a launch manifest and loader writes.

The observer, QEMU backend and their build bindings are a caller trust boundary.
These checks do not prove the Linux implementation or promote historical runs.
"""

import hashlib
import json
import struct

try:
    from .oep_entry import parse_elf32, parse_entry_table
    from .oep_environment import _pairs
except ImportError:
    from oep_entry import parse_elf32, parse_entry_table
    from oep_environment import _pairs


U32_END = 1 << 32
PAGE_SIZE = 4096
MAX_CAPTURE_BYTES = 32 * 1024**2


def _require(condition, message):
    if not condition:
        raise ValueError(message)


def _uint(value, label, maximum=U32_END - 1):
    _require(type(value) is int and 0 <= value <= maximum, label)
    return value


def _hex(value, label, limit=MAX_CAPTURE_BYTES):
    _require(type(value) is str and len(value) <= limit * 2 and len(value) % 2 == 0, label)
    try:
        result = bytes.fromhex(value)
    except ValueError as error:
        raise ValueError(label) from error
    _require(len(result) * 2 == len(value), label + ' contains whitespace')
    return result


def _one(rows, kind, **fields):
    selected = [(index, row) for index, row in enumerate(rows)
                if row.get('kind') == kind and all(row.get(k) == v for k, v in fields.items())]
    _require(len(selected) == 1, 'Unique ' + kind + ' observation required: ' + str(fields))
    return selected[0]


def _identity(rows, launch, expected_syscall_count):
    _require(type(expected_syscall_count) is int and 0 <= expected_syscall_count <= 26, 'Expected syscall count')
    _require(type(launch) is dict and type(launch.get('schema_version')) is int
             and launch['schema_version'] == 1, 'Launch manifest schema')
    run = launch.get('run_id')
    _require(type(run) is str and len(run) == 32 and all(c in '0123456789abcdef' for c in run), 'Launch run_id')
    source = launch.get('source_elf_sha256')
    _require(type(source) is str and len(source) == 64 and all(c in '0123456789abcdef' for c in source), 'Launch ELF digest')
    _require(type(rows) is list and 2 <= len(rows) <= 65536 and all(type(r) is dict for r in rows), 'Capture row extent')
    _require(rows[0].get('kind') == 'header' and rows[-1].get('kind') == 'footer'
             and sum(r.get('kind') == 'header' for r in rows) == 1
             and sum(r.get('kind') == 'footer' for r in rows) == 1, 'Capture header/footer framing')
    header, footer = rows[0], rows[-1]
    _require(header.get('capture_kind') == 'OEP_ENVIRONMENT_CAPTURE_V1'
             and type(header.get('schema_version')) is int and header['schema_version'] == 1
             and header.get('run_id') == run and header.get('elf_sha256') == source, 'Capture launch identity differs')
    for key in ('guest_vma_api_version', 'entry_construction_api_version', 'brk_api_version'):
        _require(type(header.get(key)) is int and header[key] == 1, 'Missing observer capability: ' + key)
    _require(all(r.get('run_id', run) == run for r in rows), 'Mixed capture run_id')
    _require(type(footer.get('syscall_count')) is int and type(footer.get('syscall_returns')) is int, 'Capture syscall count types')
    _require(footer.get('success') is True and footer.get('reason') == 'payload_entry_boundary'
             and footer.get('target_instruction_executed') is False
             and footer.get('syscall_count') == footer.get('syscall_returns') == expected_syscall_count,
             'Capture completion scope')
    path = footer.get('executed_pc_sha256')
    _require(header.get('executed_pc_hash_encoding') == 'LE32_EXECUTED_PC'
             and type(path) is str and len(path) == 64 and all(c in '0123456789abcdef' for c in path),
             'Executed PC observation digest/encoding')
    _uint(footer.get('instructions'), 'Observed instruction budget', 30000000)
    _require(header.get('binary_path_matches') is True and header.get('captured_execution_only') is True,
             'Capture binary observation identity/scope')
    for row in (header, footer):
        _require(row.get('oep_proof', 'NOT_ESTABLISHED') == 'NOT_ESTABLISHED', 'Capture promotes unsupported OEP proof')
        for key in ('kernel_implementation_verified', 'independent_OS_entry_origins_proven',
                    'unconditional_oep_proven', 'historical_certificates_upgraded', 'fuzzing_ready'):
            _require(key not in row or row[key] is False, 'Capture promotes unsupported proof scope: ' + key)
    return run, source


def read_capture(raw, launch, *, expected_syscall_count=26):
    """Read bounded strict JSONL and authenticate its exact footer prefix bytes."""
    _require(isinstance(raw, bytes) and len(raw) <= MAX_CAPTURE_BYTES, 'Capture byte budget')
    lines = raw.splitlines(keepends=True)
    _require(lines and all(line.endswith(b'\n') and len(line) <= 4 * 1024**2 for line in lines), 'Capture line framing')

    def pairs(values):
        result = {}
        for key, value in values:
            _require(key not in result, 'Duplicate JSON key: ' + key)
            result[key] = value
        return result

    def invalid(value):
        raise ValueError('Noninteger capture JSON number: ' + value)

    try:
        rows = [json.loads(line.decode('utf-8'), object_pairs_hook=pairs, parse_constant=invalid, parse_float=invalid) for line in lines]
    except (UnicodeError, RecursionError) as error:
        raise ValueError('Invalid capture JSON') from error
    _identity(rows, launch, expected_syscall_count)
    prefix = b''.join(lines[:-1])
    _require(rows[-1].get('events_bytes_before_footer') == len(prefix)
             and rows[-1].get('events_sha256_before_footer') == hashlib.sha256(prefix).hexdigest(),
             'Capture footer prefix binding differs')
    return rows


def _vmas(row):
    _require(type(row.get('page_size')) is int and row['page_size'] == PAGE_SIZE, 'Observed page size')
    regions = row.get('regions')
    _require(type(regions) is list and 0 < len(regions) <= 4096, 'Observed VMA count')
    result, previous, pages = [], 0, 0
    for item in regions:
        _require(type(item) is dict, 'Observed VMA object')
        start = _uint(item.get('start'), 'Observed VMA start')
        end = _uint(item.get('end'), 'Observed VMA end', U32_END)
        flags = _uint(item.get('raw_flags'), 'Observed raw page flags')
        prot = _uint(item.get('prot'), 'Observed VMA protection', 7)
        _require(start < end and start % PAGE_SIZE == end % PAGE_SIZE == 0
                 and start >= previous, 'Observed VMA overlap or alignment')
        _require(flags & 8 and prot == (flags & 5) | (2 if flags & 16 else 0),
                 'Observed VMA raw flags/protection differ')
        previous = end
        pages += (end - start) // PAGE_SIZE
        _require(pages <= 65536, 'Observed VMA page budget')
        if result and result[-1]['end'] == start and result[-1]['prot'] == prot:
            result[-1]['end'] = end
        else:
            result.append({'start': start, 'end': end, 'prot': prot})
    return result


def _manifest_strings(value, label):
    _require(type(value) is list and len(value) <= 256, label + ' count')
    result = []
    for item in value:
        _require(type(item) is str and '\0' not in item, label + ' string')
        encoded = item.encode('utf-8') + b'\0'
        _require(len(encoded) <= 4096, label + ' string budget')
        result.append(encoded)
    _require(sum(map(len, result)) <= 16384, label + ' byte budget')
    return result


def _entry(rows, launch, elf, initial_vmas, projection):
    _, initial = _one(rows, 'initial')
    _, snapshot = _one(rows, 'snapshot', label='initial_stack')
    _, constructor = _one(rows, 'entry_construction')
    stack = _hex(snapshot.get('bytes_hex'), 'Initial stack bytes', 131072)
    base = _uint(snapshot.get('address'), 'Initial stack address')
    _require(snapshot.get('size') == len(stack) and base + len(stack) <= U32_END, 'Initial stack extent')
    registers = initial.get('registers')
    _require(type(registers) is dict, 'Initial registers')
    esp = _uint(registers.get('esp'), 'Initial ESP')
    eflags = _uint(registers.get('eflags'), 'Initial EFLAGS')
    _require(not eflags & (1 << 10), 'Selected replay requires observed DF=0')
    _require(rows[0].get('initial_pc') == initial.get('pc') and rows[0].get('initial_sp') == esp
             and type(rows[0].get('initial_df')) is int and rows[0]['initial_df'] == 0,
             'Header initial-state observation differs')
    metadata = constructor.get('metadata')
    _require(type(metadata) is list and len(metadata) == 8, 'Entry construction metadata extent')
    for value in metadata:
        _uint(value, 'Entry construction metadata scalar')
    version, width, constructed_sp, argc, envc, entry, phdr, interpreter = metadata
    _require(version == 1 and width == 4 and not interpreter, 'Unsupported entry construction receipt')
    parsed = parse_elf32(elf)
    _require(not any(p['type'] == 3 for p in parsed['program_headers']), 'Selected replay requires static ELF')
    _require(entry == parsed['entry'] == initial.get('pc') and constructed_sp == esp,
             'Loader entry/ESP differs from initial observation')
    layout = parse_entry_table(stack, base, esp)
    argv = _manifest_strings(launch.get('guest_argv'), 'Launch argv')
    envp = _manifest_strings(launch.get('guest_environ'), 'Launch environ')
    _require(argc == layout['argc'] == len(argv) and envc == len(layout['envp_pointers']) == len(envp),
             'Launch argc/envc differs from constructor')
    table_end = parsed['phoff'] + parsed['phentsize'] * parsed['phnum']
    candidates = [p for p in parsed['program_headers'] if p['type'] == 1
                  and p['offset'] <= parsed['phoff'] and table_end <= p['offset'] + p['filesz']
                  and p['vaddr'] + parsed['phoff'] - p['offset'] == phdr]
    _require(len(candidates) == 1, 'Loader PHDR address differs from ELF')
    aux = {tag: value for tag, value in layout['auxv'] if tag in (3, 4, 5, 6, 9)}
    _require(aux == {3: phdr, 4: parsed['phentsize'], 5: parsed['phnum'], 6: PAGE_SIZE, 9: entry},
             'Entry auxv differs from ELF/constructor')
    words = constructor.get('words')
    _require(type(words) is list and 0 < len(words) <= 1024, 'Entry construction word budget')
    origins = {}
    known = bytearray(len(stack))
    for record in words:
        _require(type(record) is list and len(record) == 3, 'Entry construction word')
        address, value, kind = record
        _uint(address, 'Constructed word address')
        _uint(value, 'Constructed word value')
        _require(type(kind) is int and kind in (1, 2, 3, 4), 'Constructed word kind')
        _require(address % 4 == 0 and esp <= address < layout['end'] and address not in origins,
                 'Constructed word outside table or duplicate')
        expected_kind = next(index + 1 for index, region in enumerate(layout['regions'])
                             if region['address'] <= address < region['address'] + region['size'])
        offset = address - base
        _require(kind == expected_kind and stack[offset:offset + 4] == struct.pack('<I', value),
                 'Entry table differs from constructor write')
        origins[address] = kind
        known[offset:offset + 4] = b'\xff' * 4
    _require(set(origins) == set(range(esp, layout['end'], 4)), 'Constructor does not cover complete entry table')
    string_ranges = []
    for label, pointers, strings in (('argv', layout['argv_pointers'], argv), ('environ', layout['envp_pointers'], envp)):
        for index, (pointer, data) in enumerate(zip(pointers, strings)):
            _require(base <= pointer and pointer + len(data) <= base + len(stack), 'Launch string outside stack snapshot')
            _require(pointer >= layout['end'] or pointer + len(data) <= esp, 'Launch string overlaps entry table')
            offset = pointer - base
            _require(stack[offset:offset + len(data)] == data, 'Launch ' + label + ' string/order differs')
            if index:
                _require(pointer == pointers[index - 1] + len(strings[index - 1]), 'Launch string pointer progression differs')
            string_ranges.append((pointer, pointer + len(data)))
            known[offset:offset + len(data)] = b'\xff' * len(data)
    ordered = sorted(string_ranges)
    _require(all(a[1] <= b[0] for a, b in zip(ordered, ordered[1:])), 'Launch string ranges overlap')
    table_mapping = [m for m in initial_vmas if m['start'] <= esp < layout['end'] <= m['end'] and m['prot'] & 3 == 3]
    _require(len(table_mapping) == 1, 'Entry table lacks observed readable/writable mapping')
    selected_count = None
    if projection is not None:
        _require(isinstance(projection, bytes) and len(projection) == len(stack)
                 and all(v in (0, 255) for v in projection), 'Entry projection byte masks')
        _require(all(not selected or origin for selected, origin in zip(projection, known)),
                 'Selected initial byte lacks constructor/launch origin')
        selected_count = projection.count(255)
    mapping = table_mapping[0]
    profile = {'schema_version': 1, 'provenance': 'external_launch_profile',
               'elf_sha256': hashlib.sha256(elf).hexdigest(), 'esp': esp, 'df': 0,
               'page_size': PAGE_SIZE, 'phdr_load_index': candidates[0]['index'],
               'argv_pointers': layout['argv_pointers'], 'envp_pointers': layout['envp_pointers'],
               'auxv': [[tag, None if tag in (3, 4, 5, 6, 9) else value] for tag, value in layout['auxv']],
               'stack_mapping': {'start': mapping['start'], 'end': mapping['end'], 'read': True, 'write': True}}
    return {'status': 'VERIFIED_ENTRY_TABLE_AGAINST_LOADER_CONSTRUCTION_AND_LAUNCH_MANIFEST',
            'layout': layout, 'profile': profile, 'constructor_words': len(words),
            'constructor_table_bytes': len(words) * 4, 'launch_string_bytes': sum(b - a for a, b in string_ranges),
            'entry_origins_observed_in_loader': True, 'entry_table_matches_construction_receipt': True,
            'argv_envp_string_contents_verified': True, 'stack_mapping_permissions_observed': True,
            'DF_observed_zero': True, 'selected_projection_bytes': selected_count,
            'classified_initial_bytes_mask_hex': bytes(known).hex(),
            'independent_OS_entry_origins_proven': False,
            'external_admissions': ['Trusted QEMU loader/observer source and build binding.',
                                    'DF=0 is a live initial-register observation; no CPU reset implementation proof is claimed.'],
            'oep_proof': 'NOT_ESTABLISHED'}


def audit_observations(rows, launch, *, elf, projection=None, expected_syscall_count=26):
    """Normalize fresh entry, fd, brk and complete guest-VMA observations.

    Call read_capture first to check the exact serialized footer binding. The
    caller must bind the manifest, plugin and QEMU build to the launched run.
    """
    run, source = _identity(rows, launch, expected_syscall_count)
    _require(isinstance(elf, bytes) and hashlib.sha256(elf).hexdigest() == source, 'Capture packed ELF bytes differ')
    _require(all(type(row.get('ordinal')) is int for row in rows
                 if row.get('kind') in ('syscall_enter', 'syscall_return', 'syscall_post')), 'Syscall ordinal types')
    calls = _pairs(rows, expected_syscall_count)
    first_call = next((i for i, row in enumerate(rows) if row.get('kind') == 'syscall_enter'), len(rows) - 1)
    timeline = {}
    for index, row in enumerate(rows):
        if row.get('kind') != 'vma_snapshot':
            continue
        phase, ordinal = row.get('phase'), row.get('ordinal')
        _require(phase in ('initial', 'syscall_return', 'payload_entry') and type(ordinal) is int,
                 'VMA observation phase/ordinal')
        key = phase, ordinal
        _require(key not in timeline, 'Duplicate VMA observation')
        timeline[key] = (index, _vmas(row))
    expected = {('initial', 0), ('payload_entry', expected_syscall_count)} | {
        ('syscall_return', i) for i in range(1, expected_syscall_count + 1)}
    _require(set(timeline) == expected, 'Incomplete or unexpected VMA observation timeline')
    _require(timeline['initial', 0][0] < first_call, 'Initial VMA observation follows guest syscall')
    for entry, returned, _ in calls:
        ordinal = entry['ordinal']
        _, post = _one(rows, 'syscall_post', ordinal=ordinal)
        _require(rows.index(returned) < timeline['syscall_return', ordinal][0] < rows.index(post),
                 'VMA observation is outside syscall-return boundary')
    last_post = max((i for i, row in enumerate(rows) if row.get('kind') == 'syscall_post'), default=_one(rows, 'initial')[0])
    _require(last_post < timeline['payload_entry', expected_syscall_count][0] < len(rows) - 1,
             'Final VMA observation is outside payload boundary')
    prior_key = ('syscall_return', expected_syscall_count) if calls else ('initial', 0)
    _require(timeline['payload_entry', expected_syscall_count][1] == timeline[prior_key][1],
             'Guest mapping/protection changed after final syscall observation')
    for kind in ('initial', 'entry_construction', 'fd_initial'):
        _require(_one(rows, kind)[0] < first_call, 'Initial observation follows guest syscall: ' + kind)
    initial_vmas = timeline['initial', 0][1]
    entry_report = _entry(rows, launch, elf, initial_vmas, projection)
    _, fds = _one(rows, 'fd_initial')
    limit = _uint(fds.get('limit'), 'FD scan limit', 4096)
    _require(limit > 0, 'FD scan limit is empty')
    observer = _uint(fds.get('observer_fd'), 'Observer fd', limit - 1)
    descriptors = fds.get('descriptors')
    _require(type(descriptors) is list and len(descriptors) <= limit, 'Initial fd descriptor extent')
    profile_fds, occupied, identities = [], set(), {}
    for fd in descriptors:
        _require(type(fd) is dict, 'Initial fd descriptor object')
        number = _uint(fd.get('fd'), 'Initial fd number', limit - 1)
        _require(number not in occupied, 'Duplicate initial fd')
        occupied.add(number)
        device = _uint(fd.get('dev'), 'Initial fd device', 2**64 - 1)
        inode = _uint(fd.get('ino'), 'Initial fd inode', 2**64 - 1)
        key = fd.get('file_id')
        _require(key == 'stat:' + str(device) + ':' + str(inode), 'Initial fd stat identity differs')
        mode = _uint(fd.get('mode'), 'Initial fd mode')
        size = _uint(fd.get('size'), 'Initial fd size')
        _require(key not in identities or identities[key] == (device, inode, mode, size), 'Inconsistent initial file identity')
        identities[key] = device, inode, mode, size
        access = fd.get('access')
        _require(access in ('read', 'write', 'read_write'), 'Initial fd access')
        _require(type(fd.get('seekable')) is bool and type(fd.get('cloexec')) is bool, 'Initial fd state booleans')
        position = fd.get('position')
        if fd['seekable']:
            position = _uint(position, 'Initial fd position')
        else:
            _require(position is None, 'Nonseekable fd has an invented file position')
            position = 0
        profile_fds.append({'fd': number, 'file_id': key, 'size': size, 'access': access, 'position': position})
    _require(observer in occupied, 'Observer fd omitted from allocation occupancy')
    brks = {}
    for index, row in enumerate(rows):
        if row.get('kind') != 'brk':
            continue
        key = row.get('phase'), row.get('ordinal')
        _require(key in expected and key not in brks, 'Unexpected or duplicate brk observation')
        initial = _uint(row.get('initial'), 'Initial brk')
        current = _uint(row.get('current'), 'Current brk')
        _require(initial % PAGE_SIZE == 0 and current >= initial, 'Observed brk extent')
        brks[key] = index, initial, current
    _require(set(brks) == expected, 'Incomplete brk observation timeline')
    initial_brk = brks['initial', 0][1]
    _require(brks['initial', 0][2] == initial_brk and brks['initial', 0][0] < first_call, 'Initial brk state differs')
    for key, (_, initial, _) in brks.items():
        _require(initial == initial_brk, 'Initial brk origin changed')
    current = initial_brk
    for entry, returned, _ in calls:
        ordinal = entry['ordinal']
        index, _, observed = brks['syscall_return', ordinal]
        _, post = _one(rows, 'syscall_post', ordinal=ordinal)
        _require(rows.index(returned) < index < rows.index(post), 'brk observation is outside syscall-return boundary')
        if entry['number'] == 45:
            _require(returned['result_u32'] == observed, 'Observed brk differs from syscall result')
        else:
            _require(observed == current, 'brk changed outside brk syscall')
        current = observed
    _require(brks['payload_entry', expected_syscall_count][2] == current
             and last_post < brks['payload_entry', expected_syscall_count][0] < len(rows) - 1,
             'Final brk observation differs')
    canonical = hashlib.sha256(json.dumps(rows, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    effects = {'capture_rows_sha256': canonical, 'vma_snapshots': [
        {'ordinal': ordinal, 'vmas': timeline[('initial' if ordinal == 0 else 'syscall_return', ordinal)][1]}
        for ordinal in range(expected_syscall_count + 1)]}
    for index, row in enumerate(rows):
        if row.get('kind') == 'file_snapshot':
            ordinal = _uint(row.get('ordinal'), 'File observation ordinal', expected_syscall_count)
            _require(ordinal > 0 and row.get('phase') in ('syscall_enter', 'syscall_return'), 'File observation phase')
            call, returned, _ = calls[ordinal - 1]
            _, post = _one(rows, 'syscall_post', ordinal=ordinal)
            if row['phase'] == 'syscall_enter':
                _require(call['number'] == 6 and row.get('fd') == call['args'][0]
                         and rows.index(call) < index < rows.index(returned), 'Pre-close file observation boundary')
            else:
                _require(call['number'] in (356, 5, 93, 4, 90, 192, 144)
                         and rows.index(returned) < index < rows.index(post), 'File observation outside selected syscall-return boundary')
                if call['number'] in (356, 5):
                    _require(row.get('fd') == returned['result_u32'], 'Created file observation fd differs')
                elif call['number'] in (93, 4):
                    _require(row.get('fd') == call['args'][0], 'Consumed file observation fd differs')
            _uint(row.get('fd'), 'File observation fd', 4095)
            device = _uint(row.get('dev'), 'File observation device', 2**64 - 1)
            inode = _uint(row.get('ino'), 'File observation inode', 2**64 - 1)
            _require(row.get('file_id') == 'stat:' + str(device) + ':' + str(inode), 'Observed file stat identity differs')
            mode = _uint(row.get('mode'), 'File observation mode')
            _require(mode & 0o170000 == 0o100000, 'Observed file is not regular')
            size = _uint(row.get('size'), 'File observation size', 1024**2)
            _require(len(_hex(row.get('bytes_hex'), 'Observed file bytes', 1024**2)) == size, 'Observed file byte extent')
            if row.get('position') is not None:
                _uint(row['position'], 'Observed file position')
    return {'schema_version': 1, 'status': 'VERIFIED_FRESH_ENTRY_AND_ENVIRONMENT_OBSERVATIONS',
            'capture_identity': {'run_id': run, 'source_elf_sha256': source, 'capture_rows_sha256': canonical,
                                 'executed_pc_sha256': rows[-1]['executed_pc_sha256'],
                                 'instructions': rows[-1]['instructions']},
            'entry': entry_report,
            'process_profile': {'page_size': PAGE_SIZE, 'fds': profile_fds, 'vmas': initial_vmas, 'brk': initial_brk},
            'effect_observations': effects,
            'payload_vmas': timeline['payload_entry', expected_syscall_count][1],
            'observer_fd_in_occupied_set': True, 'initial_fd_occupancy_observed': True,
            'guest_permissions_observed': True, 'brk_timeline_observed': True,
            'capture_source_authentication_required': True,
            'independent_OS_entry_origins_proven': False, 'kernel_implementation_verified': False,
            'unconditional_oep_proven': False, 'historical_certificates_upgraded': False,
            'open_obligations': ['TRUSTED_OBSERVER_AND_QEMU_BUILD_BINDING_REQUIRED',
                                 'NO_OUTSIDE_MUTATION_OR_SIGNAL_EFFECTS',
                                 'REPLAY_AND_MEMORY_FILE_EFFECT_COMPARISONS_REQUIRED'],
            'oep_proof': 'NOT_ESTABLISHED'}
