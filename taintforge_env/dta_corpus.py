"""Bounded file-byte mutation proposals from existing DTA root diagnostics.

No guest, solver, coverage replay or branch inversion is performed here.
The caller supplies the association between a seed, executable and trace.
"""
from __future__ import annotations

from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import stat


class DtaCorpusError(RuntimeError):
    pass


_DEC = r"[0-9]+"
_HEX = r"0x[0-9a-f]+"
_PROV = re.compile(
    rf"\[BRANCH-PROV\] event=({_DEC}) edge=({_DEC}) seq=({_DEC}) vcpu=({_DEC}) "
    rf"pc=({_HEX}) next=({_HEX}) outcome=(taken|not-taken|unknown) cc=({_DEC}) "
    rf"label=({_DEC}) complete=({_HEX}) reasons=({_HEX})")
_ROOT = re.compile(
    rf"\[BRANCH-ROOT\] event=({_DEC}) channel=(data|address) root=({_DEC}) "
    rf"resource=({_DEC}) path=(.+) offset=({_DEC})")
_OTHER_ROOT = re.compile(
    rf"\[BRANCH-ROOT\] event=({_DEC}) channel=(data|address) root=({_DEC}) "
    rf"kind=({_DEC}) source=({_DEC}) discriminator=({_DEC}) offset=({_DEC}) instance=({_DEC})")
_DCFG = re.compile(
    rf"\[DCFG-JCC\] event=({_DEC}) edge=({_DEC}) src-node=({_DEC}) dst-node=({_DEC}) "
    rf"src=({_HEX}) dst=({_HEX}) pc=({_HEX}) src-gen=({_DEC}) dst-gen=({_DEC}) "
    rf"kind=(jcc-taken|jcc-fallthrough|jcc-unknown) count=({_DEC}) seq=({_DEC}) label=({_DEC})")
_HEADER = re.compile(rf"\[RUNTIME\] log=roots profile=(on|off) progress=({_DEC})")
_PALETTE = (0, 1, 0x20, 0x30, 0x41, 0x7f, 0x80, 0xff)


def _require(value, message):
    if not value:
        raise DtaCorpusError(message)


def _limit(value, maximum, name):
    _require(type(value) is int and 1 <= value <= maximum, f"Invalid {name} budget")


def _canonical(path):
    path = Path(path).expanduser().absolute()
    _require('..' not in path.parts, "Parent traversal in local path")
    for component in (path, *path.parents):
        _require(not component.is_symlink(), f"Symlink in local path: {component}")
    return path


def _regular(path, maximum):
    path = _canonical(path)
    info = path.lstat()
    _require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= maximum,
             f"Expected bounded private regular file: {path}")
    return path


def _pin(path, maximum):
    path = _regular(path, maximum)
    digest, size = hashlib.sha256(), 0
    with path.open('rb') as stream:
        while chunk := stream.read(1024 * 1024):
            size += len(chunk)
            _require(size <= maximum, f"Input exceeds byte budget: {path}")
            digest.update(chunk)
    _require(path.stat().st_size == size, f"Input changed while reading: {path}")
    return path, {'path': str(path), 'sha256': digest.hexdigest(), 'size': size}


def _number(value, bits=64):
    result = int(value, 16 if value.startswith('0x') else 10)
    _require(0 <= result < 1 << bits, "Diagnostic integer exceeds its native width")
    return result


def parse_trace(trace, input_path, input_size, *, max_groups=64, max_offsets=16,
                max_trace_bytes=64 * 1024**2):
    """Read the exact native stderr records; reject ambiguous or partial groups."""
    _limit(max_groups, 4096, 'groups')
    _limit(max_offsets, 4096, 'offsets')
    _limit(max_trace_bytes, 64 * 1024**2, 'trace bytes')
    _require(type(input_size) is int and 1 <= input_size <= 4096, 'Invalid seed size')
    _require(isinstance(input_path, str) and input_path.startswith('/') and
             not input_path.startswith('//') and len(input_path.encode()) <= 4095 and
             str(Path(input_path)) == input_path and '..' not in Path(input_path).parts and
             not any(ord(c) < 32 or ord(c) == 127 for c in input_path), 'Invalid input path')
    trace = _regular(trace, max_trace_bytes)
    groups, skipped, occurrences, definitions, resources = [], Counter(), Counter(), {}, {}
    current, last_event, last_seq, event_count, root_count, headers, size = None, 0, 0, 0, 0, 0, 0
    digest = hashlib.sha256()

    def finish():
        if current is None:
            return
        roots = current['data']
        if not current['complete'] & 1 or current['reasons']:
            reason = 'incomplete_data'
        elif current['outcome'] == 'unknown':
            reason = 'unknown_outcome'
        elif not roots:
            reason = 'no_data_roots'
        elif any(root[0] != 'resource' or root[2] != input_path for root in roots):
            reason = 'foreign_data_roots'
        else:
            _require(current['dcfg'] is not None, 'Selected data branch lacks matching DCFG evidence')
            _require(all(root[3] < input_size for root in roots), 'Selected source offset outside seed')
            _require(len({root[1] for root in roots}) == 1, 'Selected input has conflicting resource IDs')
            offsets = sorted({root[3] for root in roots})
            _require(len(offsets) <= max_offsets, 'Source offset budget exceeded')
            _require(len(groups) < max_groups, 'Branch group budget exceeded')
            groups.append({key: current[key] for key in
                           ('event', 'edge', 'seq', 'vcpu', 'pc', 'next', 'outcome', 'occurrence')} |
                          {'source_block_generation': current['dcfg']['generation'], 'offsets': offsets,
                           'resource_id': roots[0][1], 'address_roots_ignored': len(current['address']),
                           'dse_status': 'NOT_RUN', 'dse_eligible': False})
            return
        skipped[reason] += 1

    with trace.open('rb') as stream:
        while raw := stream.readline(65537):
            size += len(raw)
            _require(size <= max_trace_bytes and len(raw) <= 65536, 'Trace or line byte budget exceeded')
            digest.update(raw)
            _require(raw.endswith(b'\n'), 'Truncated diagnostic line')
            try:
                line = raw[:-1].decode('utf-8')
            except UnicodeDecodeError as exc:
                raise DtaCorpusError('Diagnostic log is not UTF-8') from exc
            if '[RUNTIME] log=' in line:
                match = _HEADER.fullmatch(line)
                _require(match is not None and not headers and not event_count,
                         'Missing roots profile, repeated run header or malformed runtime header')
                _number(match[2]); headers += 1
            elif '[BRANCH-PROV]' in line:
                match = _PROV.fullmatch(line)
                _require(headers == 1 and match is not None, 'Malformed or unbound branch record')
                finish()
                event, edge, seq, vcpu = (_number(match[i], 32 if i in (2, 4) else 64) for i in range(1, 5))
                _require(event > last_event and seq > last_seq, 'Duplicate or nonchronological branch identity')
                event_count += 1
                _require(event_count <= 100000, 'Branch event budget exceeded')
                pc, next_pc, cc, label, complete, reasons = (_number(match[i], bits) for i, bits in
                    ((5, 64), (6, 64), (8, 16), (9, 32), (10, 8), (11, 64)))
                _require(complete <= 3, 'Invalid completeness mask')
                occurrences[(vcpu, pc)] += 1
                current = dict(event=event, edge=edge, seq=seq, vcpu=vcpu, pc=pc, next=next_pc,
                    outcome=match[7], cc=cc, label=label, complete=complete, reasons=reasons,
                    occurrence=occurrences[(vcpu, pc)], data=[], address=[], dcfg=None, root_ids=set())
                last_event, last_seq = event, seq
            elif '[BRANCH-ROOT]' in line:
                match, other = _ROOT.fullmatch(line), _OTHER_ROOT.fullmatch(line)
                _require(current is not None and (match is not None or other is not None), 'Malformed or orphan root')
                record = match or other
                _require(_number(record[1]) == current['event'] and current['dcfg'] is None,
                         'Root belongs to another or completed branch')
                root_id = _number(record[3], 32)
                _require(root_id > 0 and (record[2], root_id) not in current['root_ids'], 'Duplicate root record')
                current['root_ids'].add((record[2], root_id))
                if match:
                    root = ('resource', _number(match[4], 32), match[5], _number(match[6]))
                    _require(root[1] > 0, 'Invalid resource identity')
                    _require(root[1] not in resources or resources[root[1]] == root[2],
                             'Conflicting resource identity')
                    resources[root[1]] = root[2]
                    if root[2] == input_path:
                        _require(root[3] < input_size, 'Selected source offset outside seed')
                else:
                    root = ('other', *(_number(other[i], 32 if i in (4, 6) else 64) for i in range(4, 9)))
                    _require(2 <= root[1] <= 7, 'Invalid non-resource root kind')
                _require(root_id not in definitions or definitions[root_id] == root, 'Conflicting root identity')
                definitions[root_id] = root
                current[record[2]].append(root)
                root_count += 1
                _require(root_count <= 1000000, 'Source root budget exceeded')
            elif '[DCFG-JCC]' in line:
                match = _DCFG.fullmatch(line)
                _require(current is not None and match is not None and current['dcfg'] is None,
                         'Malformed, orphan or duplicate DCFG record')
                values = [_number(match[i], 32 if i in (2, 3, 4, 8, 9, 13) else 64)
                          for i in (1, 2, 3, 4, 5, 6, 7, 8, 9, 11, 12, 13)]
                event, edge, src_node, dst_node, src, dst, pc, generation, dst_gen, count, seq, label = values
                expected_kind = {'taken': 'jcc-taken', 'not-taken': 'jcc-fallthrough', 'unknown': 'jcc-unknown'}
                _require((event, edge, seq, pc, dst, label) == tuple(current[key] for key in
                         ('event', 'edge', 'seq', 'pc', 'next', 'label')) and
                         min(edge, src_node, dst_node, count) > 0 and
                         match[10] == expected_kind[current['outcome']], 'DCFG/branch identity mismatch')
                current['dcfg'] = {'generation': generation}
    _require(headers == 1, 'Roots diagnostic header missing')
    finish()
    _require(trace.stat().st_size == size, 'Trace changed while reading')
    return {'groups': groups, 'skipped': dict(sorted(skipped.items())), 'events': event_count,
            'roots': root_count, 'trace_sha256': digest.hexdigest(), 'trace_size': size}


def _variants(seed, group):
    offsets = group['offsets']
    for value in _PALETTE:
        yield 'group-fill', {offset: value for offset in offsets}
    for offset in offsets:
        original = seed[offset]
        for value in dict.fromkeys((*_PALETTE, (original - 1) & 255, (original + 1) & 255,
                                   *(original ^ (1 << bit) for bit in range(8)))):
            yield 'byte-value', {offset: value}


def generate_corpus(*, seed, binary, trace, input_path, out, max_candidates=128,
                    max_groups=64, max_offsets=16, max_trace_bytes=64 * 1024**2):
    """Plan all bounded candidates before publishing a new corpus directory."""
    _limit(max_candidates, 4096, 'candidates')
    seed, seed_record = _pin(seed, 4096)
    binary, binary_record = _pin(binary, 512 * 1024**2)
    _require(seed_record['size'] > 0, 'AFL file seed must be nonempty')
    raw = seed.read_bytes()
    _require(hashlib.sha256(raw).hexdigest() == seed_record['sha256'], 'Seed changed')
    trace = _regular(trace, max_trace_bytes)
    parsed = parse_trace(trace, input_path, len(raw), max_groups=max_groups,
                         max_offsets=max_offsets, max_trace_bytes=max_trace_bytes)
    trace_record = {'path': str(trace), 'sha256': parsed['trace_sha256'], 'size': parsed['trace_size']}
    out = _canonical(out)
    _require(not out.exists() and all(not path.is_relative_to(out) and not out.is_relative_to(path)
             for path in (seed, binary, trace)), 'Output must be new and outside all inputs')
    candidates, blobs = [], {}

    def admit(data, group, operation):
        sha = hashlib.sha256(data).hexdigest()
        if sha in blobs:
            return
        _require((len(blobs) + 1) * len(raw) <= 64 * 1024**2, 'Generated corpus byte budget exceeded')
        blobs[sha] = data
        candidates.append({'sha256': sha, 'size': len(data), 'baseline': group is None,
            'operation': operation, 'site': group, 'mutations': [
                {'offset': offset, 'before': raw[offset], 'after': data[offset]}
                for offset in (group['offsets'] if group else ()) if raw[offset] != data[offset]]})

    admit(raw, None, 'baseline')
    sites = {}
    for group in parsed['groups']:
        sites.setdefault(tuple(group['offsets']), group)
    active = [(group, iter(_variants(raw, group))) for group in sites.values()]
    while active and len(candidates) < max_candidates:
        remaining = []
        for group, iterator in active:
            try:
                operation, edits = next(iterator)
            except StopIteration:
                continue
            data = bytearray(raw)
            for offset, value in edits.items():
                data[offset] = value
            admit(bytes(data), group, operation)
            remaining.append((group, iterator))
            if len(candidates) == max_candidates:
                break
        active = remaining
    manifest = {'schema': 1, 'status': 'DTA_GUIDED_CANDIDATES_UNVALIDATED',
        'inputs': {'seed': seed_record, 'binary': binary_record, 'trace': trace_record},
        'input_path': input_path, 'input_binding': 'caller_supplied_not_independently_verified',
        'coverage_replay': 'NOT_RUN', 'dse': 'NOT_RUN', 'branch_inversion_proven': False,
        'groups': parsed['groups'], 'skipped': parsed['skipped'], 'events': parsed['events'],
        'roots': parsed['roots'], 'candidates': candidates,
        'budgets': {'max_candidates': max_candidates, 'max_groups': max_groups,
                    'max_offsets': max_offsets, 'max_trace_bytes': max_trace_bytes,
                    'max_generated_bytes': 64 * 1024**2}}
    for path, expected, maximum in ((seed, seed_record, 4096), (binary, binary_record, 512 * 1024**2),
                                    (trace, trace_record, max_trace_bytes)):
        _require(_pin(path, maximum)[1] == expected, f'Input changed before publication: {path}')
    out.mkdir(parents=True, exist_ok=False)
    (out / 'seeds').mkdir()
    for sha, data in blobs.items():
        with (out / 'seeds' / sha).open('xb') as stream:
            stream.write(data)
    with (out / 'manifest.json').open('x') as stream:
        json.dump(manifest, stream, indent=2, sort_keys=True, allow_nan=False)
        stream.write('\n')
    return manifest
