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


def validate_stage_selection(report):
    """Check the bounded observed-stage graph without inferring originality.

    Legacy captures have no stage inventory. New-policy captures must retain
    the whole bounded inventory and an eligible selected leaf, even when the
    detailed scoring table contains only three candidates.
    """
    policy = 'observed_write_transfer_leaf_semantic_evidence_v2'
    stage_fields = ('observed_stage_candidates', 'observed_stage_edges',
                    'observed_stage_history_status', 'selection_scope',
                    'historical_originality_proven', 'complete_stage_chain')
    if (not any(key in report for key in stage_fields) and
            report.get('oep_selection_policy') != policy):
        return

    def reject(message):
        raise CaptureError('INVALID_STAGE_SELECTION', message)

    def number(row, key, maximum=2**64 - 1):
        value = row.get(key)
        if type(value) is not int or not 0 <= value <= maximum:
            reject('Invalid stage integer: ' + key)
        return value

    if (report.get('oep_selection_policy') != policy or
            report.get('observed_stage_history_status') != 'complete' or
            report.get('selection_scope') != 'observed_stage_leaf_candidate' or
            report.get('oep_proven') is not False or
            report.get('historical_originality_proven') is not False or
            report.get('complete_stage_chain') is not False):
        reject('Incomplete inventory or promoted stage-selection scope')
    nodes = report.get('observed_stage_candidates')
    edges = report.get('observed_stage_edges')
    if (not isinstance(nodes, list) or not 1 <= len(nodes) <= 10000 or
            not isinstance(edges, list) or len(edges) > len(nodes) - 1):
        reject('Missing or oversized stage inventory')
    mapping_version = report.get('observed_stage_mapping_identity_version')
    mapping_keys = ('mapping_epoch', 'guest_store_generation', 'parent_mapping_epoch',
                    'source_writer_mapping_epoch')
    has_mapping = any(isinstance(row, dict) and any(key in row for key in mapping_keys)
                      for row in nodes)
    if (mapping_version is not None or has_mapping) and (
            type(mapping_version) is not int or mapping_version != 1):
        reject('Missing or unsupported stage mapping identity version')
    mapping_identity = mapping_version == 1
    file_version = report.get('file_mapping_profile_version')
    file_keys = ('file_mapping_profile_version', 'backing_file_id',
                 'backing_offset', 'descriptor_epoch')
    if file_version in (5, 6, 7):
        file_keys += ('backing_content_epoch',)
    if file_version in (6, 7):
        file_keys += ('backing_shared',)
    if file_version == 7:
        file_keys += ('write_origin',)
    file_rows = nodes + (report.get('oep_candidates') if isinstance(report.get('oep_candidates'), list) else [])
    has_file = any(isinstance(row, dict) and any(key in row for key in (*file_keys, 'backing_content_epoch', 'backing_shared', 'write_origin'))
                   for row in file_rows)
    if (file_version is not None or has_file) and (
            type(file_version) is not int or file_version not in (4, 5, 6, 7) or not mapping_identity):
        reject('Missing or unsupported file mapping profile version')
    file_identity = file_version in (4, 5, 6, 7)
    for row in file_rows:
        if not isinstance(row, dict):
            continue
        if file_version == 7:
            if row.get('write_origin') not in ('observed_guest_store_page', 'kernel_or_unknown_page'):
                reject('Missing or unknown V7 page-write origin')
        elif 'write_origin' in row:
            reject('Page-write origin classification requires V7')
    by_id, children, previous_id, previous_seq = {}, {}, 0, 0
    last_generation_at_pc = {}
    last_store_at_pc = {}
    for row in nodes:
        if not isinstance(row, dict):
            reject('Invalid stage row')
        ident, seq = number(row, 'candidate_id'), number(row, 'entry_seq')
        address = number(row, 'address', 2**32 - 1)
        size = number(row, 'entry_size', 15)
        generation = number(row, 'code_generation', 2**32 - 1)
        number(row, 'epoch')
        number(row, 'vcpu', 2**32 - 1)
        parent = number(row, 'parent_candidate_id')
        number(row, 'superseded_by_candidate_id')
        if (ident <= previous_id or seq <= previous_seq or not size or
                generation in (0, 2**32 - 1) or
                address + size > 2**32 or parent >= ident or
                any(type(row.get(key)) is not bool for key in
                    ('stale', 'superseded', 'selected', 'selection_eligible'))):
            reject('Invalid stage order, identity or state')
        if address in last_generation_at_pc and generation <= last_generation_at_pc[address]:
            reject('Repeated stage PC lacks a later code generation')
        last_generation_at_pc[address] = generation
        if mapping_identity:
            for key in mapping_keys:
                number(row, key)
            observation_only = file_version == 7 and row['write_origin'] == 'kernel_or_unknown_page'
            if ((not row['guest_store_generation'] and not observation_only) or
                    (not parent and (row['parent_mapping_epoch'] or
                                     row['source_writer_mapping_epoch']))):
                reject('Invalid stage mapping or STORE identity')
            if observation_only:
                if (row['guest_store_generation'] or parent or row['selected'] or row['selection_eligible'] or
                        any(number(row,key) for key in ('source_write_pc','source_write_seq',
                            'source_write_generation','written_begin','written_end'))):
                    reject('Kernel or unknown page cannot supply guest STORE evidence')
            if (not observation_only and address in last_store_at_pc and
                    row['guest_store_generation'] <= last_store_at_pc[address]):
                reject('Repeated stage PC lacks a later guest STORE')
            if not observation_only:
                last_store_at_pc[address] = row['guest_store_generation']
        if file_identity:
            if (type(row.get('file_mapping_profile_version')) is not int or
                    row['file_mapping_profile_version'] != file_version):
                reject('Incomplete file mapping stage profile')
            file_id = row.get('backing_file_id')
            offset = number(row, 'backing_offset')
            descriptor = number(row, 'descriptor_epoch')
            if (type(file_id) is not int or file_id not in range(-2, 32 if file_version in (5, 6, 7) else 1) or
                    offset % PAGE or offset > 2**64 - PAGE or
                    (file_id >= 0 and not 0 < descriptor < row['mapping_epoch']) or
                    (file_id < 0 and descriptor) or
                    (file_id == -1 and offset)):
                reject('Invalid file mapping source or descriptor lifetime')
            if file_version in (5, 6, 7):
                content_epoch = number(row, 'backing_content_epoch')
                # V6 permits a kernel write while a shared map remains live.
                # Its constructor ordinal may therefore follow the map ordinal.
                # Exact chronology is checked by the fresh-prefix bindings.
                content_limit = row['entry_seq'] if file_version in (6, 7) else row['mapping_epoch']
                if (file_id <= 0 and content_epoch or
                        file_id > 0 and not descriptor <= content_epoch < content_limit):
                    reject('Invalid mutable file content lifetime')
            elif 'backing_content_epoch' in row:
                reject('Mutable content lifetime requires the V5 profile')
            if file_version in (6, 7):
                if (type(row.get('backing_shared')) is not bool or
                        row['backing_shared'] and file_id <= 0):
                    reject('Shared backing requires a local mutable file')
            elif 'backing_shared' in row:
                reject('Shared backing requires the V6 profile')
        by_id[ident], children[ident] = row, set()
        previous_id, previous_seq = ident, seq
    incoming = {}
    for edge in edges:
        if not isinstance(edge, dict):
            reject('Invalid stage edge')
        parent_id, child_id = (number(edge, key) for key in
                              ('parent_candidate_id', 'child_candidate_id'))
        parent, child = by_id.get(parent_id), by_id.get(child_id)
        if file_version == 7 and any(node is not None and node['write_origin'] != 'observed_guest_store_page'
                                     for node in (parent, child)):
            reject('Observed guest-STORE edges cannot use a kernel or unknown page')
        if (parent is None or child is None or parent_id >= child_id or child_id in incoming or
                child['parent_candidate_id'] != parent_id or
                edge.get('relation') != 'observed_contiguous_write_then_adjacent_transfer'):
            reject('Orphan, duplicate or inconsistent stage edge')
        writer = number(edge, 'writer_pc', 2**32 - 1)
        transfer = number(edge, 'transfer_pc', 2**32 - 1)
        write_seq, transfer_seq, entry_seq = (number(edge, key) for key in
                                             ('write_seq', 'transfer_seq', 'entry_seq'))
        begin = number(edge, 'written_begin', 2**32 - 1)
        end = number(edge, 'written_end', 2**32)
        page_begin = child['address'] // PAGE * PAGE
        if (not parent['entry_seq'] <= write_seq < transfer_seq or
                transfer_seq == 2**64 - 1 or transfer_seq + 1 != entry_seq or
                entry_seq != child['entry_seq'] or
                not page_begin <= begin < end <= page_begin + PAGE or
                not begin <= child['address'] < child['address'] + child['entry_size'] <= end or
                writer // PAGE != parent['address'] // PAGE or
                transfer // PAGE != parent['address'] // PAGE or
                number(edge, 'vcpu', 2**32 - 1) != parent['vcpu'] or
                parent['vcpu'] != child['vcpu'] or
                number(edge, 'write_generation', 2**32 - 1) != child['code_generation'] or
                number(edge, 'target_code_generation', 2**32 - 1) != child['code_generation']):
            reject('Stage producer, byte interval or transfer boundary differs')
        for key, edge_key in (('source_write_pc', 'writer_pc'), ('source_write_seq', 'write_seq'),
                              ('source_write_generation', 'write_generation'),
                              ('transfer_seq', 'transfer_seq'), ('transfer_pc', 'transfer_pc'),
                              ('written_begin', 'written_begin'), ('written_end', 'written_end')):
            if number(child, key) != edge[edge_key]:
                reject('Stage row differs from its causal edge')
        if mapping_identity:
            bindings = (('target_mapping_epoch', child['mapping_epoch']),
                        ('parent_mapping_epoch', parent['mapping_epoch']),
                        ('writer_mapping_epoch', parent['mapping_epoch']),
                        ('guest_store_generation', child['guest_store_generation']))
            if (any(number(edge, key) != wanted for key, wanted in bindings) or
                    child['parent_mapping_epoch'] != parent['mapping_epoch'] or
                    child['source_writer_mapping_epoch'] != parent['mapping_epoch']):
                reject('Stage edge crosses a stale or different mapping lifetime')
        incoming[child_id] = parent_id
        children[parent_id].add(child_id)
    selected = []
    for ident, row in by_id.items():
        if (bool(row['parent_candidate_id']) != (ident in incoming) or
                row['superseded'] != bool(children[ident]) or
                (row['superseded_by_candidate_id'] not in children[ident]
                 if children[ident] else row['superseded_by_candidate_id'] != 0) or
                row['selection_eligible'] != (not row['stale'] and not row['superseded'] and
                    (file_version != 7 or row['write_origin'] == 'observed_guest_store_page'))):
            reject('Stage eligibility or supersession differs from observed edges')
        if row['selected']:
            if not row['selection_eligible']:
                reject('Selected stage is stale or has an observed successor')
            selected.append(row)
    details = report.get('oep_candidates')
    if len(selected) != 1 or not isinstance(details, list):
        reject('A successful capture requires one selected stage')
    detail = [row for row in details if isinstance(row, dict) and row.get('selected') is True]
    row = selected[0]
    if (len(detail) != 1 or
            integer(report.get('oep'), 'oep') != row['address'] or
            number(detail[0], 'candidate_id') != row['candidate_id'] or
            integer(detail[0].get('addr'), 'candidate addr') != row['address'] or
            number(detail[0], 'code_generation', 2**32 - 1) != row['code_generation'] or
            detail[0].get('stale') is not False or
            ('superseded' in detail[0] and detail[0]['superseded'] is not False)):
        reject('Selected stage is absent from or differs from detailed capture metadata')
    if mapping_identity and any(number(detail[0], key) != row[key]
                                for key in ('mapping_epoch', 'guest_store_generation')):
        reject('Selected stage mapping differs from detailed capture metadata')
    if file_version == 4 and 'backing_content_epoch' in detail[0]:
        reject('Mutable detailed lifetime requires the V5 profile')
    if file_version not in (6, 7) and 'backing_shared' in detail[0]:
        reject('Shared detailed backing requires the V6 profile')
    if file_identity and any(type(detail[0].get(key)) is not type(row[key]) or detail[0][key] != row[key]
                             for key in file_keys):
        reject('Selected stage file backing differs from detailed capture metadata')


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
    validate_stage_selection(report)
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
