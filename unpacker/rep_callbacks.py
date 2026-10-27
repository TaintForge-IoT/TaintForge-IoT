"""Bounded REP callback profiles, explicit config, and calibration bindings.

Calibration records runtime observations. It never supplies ECX or memory to
the native machine and is not an SMT proof or a substitute for full path hashes.
"""
import hashlib
import json
from pathlib import Path
import re
import struct

MODES = ('terminal_zero', 'body_only', 'macro_once')
SEMANTICS = {'terminal_zero': 'rep_terminal_zero_v1', 'body_only': 'rep_body_only_v1',
             'macro_once': 'rep_macro_once_v1'}
STATUS = 'CALIBRATED_REP_CALLBACK_PROFILES'
MAX_COUNT = 4096
CASES = tuple((f'{operation}-{width}-n{count}-df{backward}', operation, width, count, backward)
    for operation in ('movs', 'stos') for width in (1, 2, 4)
    for count in (0, 1, 2, 308) for backward in (0, 1))
HEX = re.compile(r'[0-9a-f]{64}\Z')
SOURCE_FILES = (
    'unpacker/rep_callbacks.py', 'unpacker/replay_trace.py', 'unpacker/unpack_sources.py',
    'unpacker/unpack_proof.py', 'unpacker/unpack_capture.c', 'unpacker/test/qemu_plugin_compat.h',
    'unpacker/mvp/run_rep_audit.py', 'unpacker/mvp/rep_fixtures.py',
    'unpacker/mvp/fixtures/core_rep32.S', 'unpacker/mvp/filemap_fixtures.py',
    'unpacker/mvp/run_runtime_dse_audit.py')


def require(valid, message):
    if not valid:
        raise ValueError(message)


def integer(value, label, low=0, high=0xffffffff):
    require(type(value) is int and low <= value <= high, 'Invalid '+label)
    return value


def semantics(mode):
    require(type(mode) is str and mode in MODES, 'Unsupported REP callback profile')
    return SEMANTICS[mode]


def sequence(mode, count):
    semantics(mode)
    integer(count, 'REP count', high=MAX_COUNT)
    if mode == 'terminal_zero':
        return list(range(count, -1, -1))
    if mode == 'macro_once':
        return [count]
    return list(range(count, 0, -1)) if count else [0]


def callbacks(mode, count):
    semantics(mode)
    integer(count, 'REP count', high=MAX_COUNT)
    return count + 1 if mode == 'terminal_zero' else 1 if mode == 'macro_once' else max(1, count)


def classify(count, observed_sequence):
    integer(count, 'REP count', high=MAX_COUNT)
    require(type(observed_sequence) is list and 0 < len(observed_sequence) <= MAX_COUNT + 1,
            'REP ECX sequence absent or oversized')
    for value in observed_sequence:
        integer(value, 'observed REP ECX', high=MAX_COUNT)
    return tuple(mode for mode in MODES if observed_sequence == sequence(mode, count))


def select_profile(records, mode):
    require(mode in ('normal', 'single') and type(records) is list and len(records) == len(CASES),
            'Complete REP calibration inventory required')
    candidates = set(MODES)
    for row, expected in zip(records, CASES):
        require(type(row) is dict and row.get('name') == expected[0] and
                type(row.get('initial_count')) is int and row['initial_count'] == expected[3],
                'REP calibration order/count differs')
        observation = row.get(mode)
        require(type(observation) is dict, 'Missing REP '+mode+' observation')
        found = classify(expected[3], observation.get('ECX_sequence'))
        require(found, 'Unsupported REP '+mode+' sequence for '+expected[0]+': '+
                repr(observation.get('ECX_sequence')))
        candidates.intersection_update(found)
        require(candidates, 'Mixed REP '+mode+' callback profiles at '+expected[0])
    require(len(candidates) == 1, 'REP '+mode+' calibration does not identify a unique profile')
    return next(iter(candidates))


def config_text(stop, stack_base, limit, ranges, mode):
    """Mode is a checked model selector, never an observed-register premise."""
    semantics(mode)
    integer(stop, 'REP config target')
    integer(stack_base, 'REP config stack')
    require(stack_base % 4096 == 0, 'REP config stack alignment')
    integer(limit, 'REP config callback budget', 1, 30000000)
    require(type(ranges) in (list, tuple) and 1 <= len(ranges) <= 256,
            'REP config range inventory')
    lines, end, total = [], 0, 0
    for row in ranges:
        require(type(row) is dict, 'REP config range must be an object')
        start = integer(row.get('address'), 'REP config range address')
        size = integer(row.get('size'), 'REP config range size', 1)
        require(not ((start | size) & 4095) and start >= end and
                start + size <= 1 << 32 and total + size <= 16 * 1024**2,
                'REP config range geometry')
        lines.append(f'{start:x} {size}\n')
        end, total = start + size, total + size
    return f'TFOEPGEN1C\n{stop:x} {stack_base:x} {limit}\n{mode}\n{len(lines)}\n'+''.join(lines)


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'Duplicate REP calibration JSON key')
            result[key] = value
        return result
    def invalid(value):
        raise ValueError('Noninteger REP calibration JSON number: '+value)
    return json.loads(raw, object_pairs_hook=pairs, parse_float=invalid, parse_constant=invalid)


def validate_calibration(document, *, qemu_sha256, observer_sha256, sdk_sha256):
    require(type(document) is dict and type(document.get('schema_version')) is int and
            document['schema_version'] == 1 and document.get('status') == STATUS,
            'Unsupported REP calibration receipt')
    expected_runtime = dict(qemu_sha256=qemu_sha256, observer_sha256=observer_sha256,
                            sdk_sha256=sdk_sha256)
    require(all(type(value) is str and HEX.fullmatch(value) for value in expected_runtime.values()) and
            document.get('runtime') == expected_runtime, 'REP calibration runtime identity differs')
    for key in ('calibration_not_SMT_proof', 'source_derived_fixture_only',
                'complete_raw_callback_hashes_checked', 'all_inputs_unchanged',
                'event_snapshots_not_used_as_profile_premises'):
        require(document.get(key) is True, 'REP calibration scope differs: '+key)
    for key in ('proof_authorized', 'observed_ECX_admitted_as_source',
                'historical_originality_proven', 'universal_equivalence'):
        require(document.get(key) is False, 'REP calibration scope promoted: '+key)
    require(type(document.get('fixture_count')) is int and document['fixture_count'] == 48 and
            type(document.get('observer_calibrations')) is int and document['observer_calibrations'] == 96,
            'Incomplete REP calibration denominator')
    profiles = document.get('profiles')
    require(type(profiles) is dict and set(profiles) == {'normal','single'},
            'REP calibration modes differ')
    for value in profiles.values():
        semantics(value)
    sources = document.get('source_sha256')
    require(type(sources) is dict and set(sources) == set(SOURCE_FILES),
            'REP calibration source inventory incomplete')
    require(all(type(name) is str and not Path(name).is_absolute() and
                '..' not in Path(name).parts and '\\' not in name and
                type(value) is str and HEX.fullmatch(value) for name,value in sources.items()),
            'Invalid REP calibration source identity')
    evidence_root = document.get('evidence_root')
    require(type(evidence_root) is str and Path(evidence_root).is_absolute(),
            'REP calibration evidence root must be absolute')
    evidence = document.get('evidence_files')
    wanted_evidence = set()
    for name, *_ in CASES:
        wanted_evidence.update((f'fixtures/{name}/fixture.json', f'fixtures/{name}/fixture.elf'))
        for folder in ('capture','single-capture'):
            wanted_evidence.update(f'cases/{name}/{folder}/{file}'
                                  for file in ('trace.jsonl','report.json','launch.json'))
    require(type(evidence) is dict and set(evidence) == wanted_evidence and
            all(type(value) is str and HEX.fullmatch(value) for value in evidence.values()),
            'REP calibration thin evidence inventory differs')
    records = document.get('records')
    require(type(records) is list and len(records) == len(CASES), 'Incomplete REP calibration records')
    for row, expected in zip(records, CASES):
        name, operation, width, count, backward = expected
        require(type(row) is dict and row.get('name') == name and row.get('operation') == operation and
                type(row.get('element_bytes')) is int and row['element_bytes'] == width and
                type(row.get('initial_count')) is int and row['initial_count'] == count and
                type(row.get('initial_DF')) is int and row['initial_DF'] == backward,
                'REP calibration fixture identity differs: '+name)
        for key in ('fixture_elf_sha256','fixture_record_sha256'):
            require(type(row.get(key)) is str and HEX.fullmatch(row[key]),
                    'Missing REP fixture identity: '+key)
        for mode in ('normal','single'):
            observation = row.get(mode)
            require(type(observation) is dict and observation.get('mode') == mode and
                    observation.get('execution_mode') == ('normal' if mode=='normal' else 'one_insn_per_tb'),
                    'REP calibration launch mode differs')
            candidates = classify(count, observation.get('ECX_sequence'))
            require(observation.get('callback_candidates') == list(candidates) and
                    profiles[mode] in candidates and observation.get('callback_profile') == profiles[mode],
                    'REP calibration profile/sequence differs: '+name+' '+mode)
            wanted = callbacks(profiles[mode], count)
            require(type(observation.get('REP_callbacks')) is int and observation['REP_callbacks'] == wanted and
                    type(observation.get('expected_REP_callbacks')) is int and
                    observation['expected_REP_callbacks'] == wanted and
                    type(observation.get('instruction_callbacks')) is int and
                    observation['instruction_callbacks'] == 14 + wanted,
                    'REP calibration callback inventory differs')
            for key in ('trace_sha256','raw_PC_sha256','raw_fetch_sha256','events_sha256',
                        'report_sha256','launch_sha256'):
                require(type(observation.get(key)) is str and HEX.fullmatch(observation[key]),
                        'REP calibration evidence identity missing: '+key)
            for key in ('source_pointer_destination_pointer_DF_checked',
                        'complete_diagnostic_trace_reconstructs_raw_hashes','calibration_not_SMT_proof'):
                require(observation.get(key) is True, 'Incomplete REP observation relation')
            require(observation.get('native_equivalence_claimed') is False,
                    'REP calibration promoted to native equivalence')
    for mode in ('normal','single'):
        require(select_profile(records, mode) == profiles[mode], 'REP calibration selected profile differs')
    return document


def _plain_file(root, relative, maximum=8 * 1024**2):
    root = Path(root)
    require(root.is_absolute() and root.is_dir() and root == root.resolve(strict=True) and
            not any(p.is_symlink() for p in (root,*root.parents)),
            'REP evidence root absent or traverses a symlink')
    rel = Path(relative)
    require(type(relative) is str and relative and not rel.is_absolute() and
            '..' not in rel.parts and '\\' not in relative and rel.as_posix() == relative,
            'Invalid REP relative evidence path')
    path = root
    for part in rel.parts:
        path /= part
        require(not path.is_symlink(), 'REP evidence path contains a symlink')
    require(path.is_file() and path.stat().st_size <= maximum, 'REP evidence absent or oversized')
    return path


def inspect_observation(directory, fixture, case, rows, mode, *, trace_limit=8192, events_digest=None):
    """Check a full observed route against an independently defined fixture."""
    try:
        from .replay_trace import read_trace
    except ImportError:
        from replay_trace import read_trace
    require(mode in ('normal','single') and case in CASES, 'Invalid REP observation mode/case')
    directory = Path(directory)
    trace, pin = read_trace(directory/'trace.jsonl')
    report = strict_json((directory/'report.json').read_bytes())
    metadata = report.get('instruction_trace')
    require(type(metadata) is dict and metadata.get('diagnostic_only') is True and
            metadata.get('start') == 1 and metadata.get('limit') == trace_limit and
            metadata.get('records') == len(trace) == report.get('instructions') == rows[-1]['instructions'] and
            metadata.get('sha256') == pin['sha256'] and metadata.get('complete_execution') is True and
            metadata.get('tail_truncated') is False and
            [row['ordinal'] for row in trace] == list(range(1,len(trace)+1)),
            'REP calibration requires a complete hash-bound occurrence trace')
    pc_hash, fetch_hash = hashlib.sha256(), hashlib.sha256()
    for row in trace:
        pc = struct.pack('<I',row['pc'])
        pc_hash.update(pc)
        fetch_hash.update(pc+bytes([row['size']])+bytes.fromhex(row['bytes_hex']))
    require(pc_hash.hexdigest() == rows[-1]['executed_pc_sha256'] == report['executed_pc_sha256'] and
            fetch_hash.hexdigest() == rows[-1]['executed_fetch_sha256'] == report['executed_fetch_sha256'],
            'Complete REP occurrence trace differs from raw callback hashes')
    name, operation, width, count, backward = case
    repeated = [row for row in trace if row['pc'] == fixture['rep_pc']]
    observed = [row.get('ecx') for row in repeated]
    found = classify(count,observed)
    require(found and len(trace) == 14 + len(repeated),
            f'Unsupported REP callbacks: case={name} mode={mode} count={count} '
            f'callbacks={len(repeated)} total={len(trace)} ECX={observed!r} candidates={list(found)!r}')
    require([row['ordinal'] for row in repeated] == list(range(9,9+len(repeated))),
            f'Noncontiguous REP callbacks: case={name} mode={mode}')
    offset = 32 + ((count-1)*width if backward and count else 0)
    source_start, destination_start = 0x0804c000 + offset, 0x0804d000 + offset
    stride = -width if backward else width
    require(fixture.get('source_start') == source_start and fixture.get('destination_start') == destination_start,
            'REP fixture pointer constructor differs')
    for index,row in enumerate(repeated):
        delta = index * stride
        require(row['size'] == fixture['after_rep_pc'] - fixture['rep_pc'] and
                all(row.get(key+'_known') == 0xffffffff for key in ('ecx','esi','edi','eflags')) and
                row['esi'] == source_start + (delta if operation=='movs' else 0) and
                row['edi'] == destination_start + delta and row['eflags'] >> 10 & 1 == backward,
                f'REP pointer/DF relation differs: case={name} mode={mode} callback={index}')
    expected_post = dict(ecx=0,esi=source_start+(count*stride if operation=='movs' else 0),
                         edi=destination_start+count*stride)
    require(fixture.get('expected_post_REP_registers') == expected_post,
            'REP fixture poststate constructor differs')
    post = [row for row in trace if row['pc'] == fixture['after_rep_pc']]
    require(len(post) == 1 and all(post[0].get(key) == value and
            post[0].get(key+'_known') == 0xffffffff for key,value in expected_post.items()),
            f'REP poststate differs: case={name} mode={mode}')
    return dict(mode=mode,execution_mode='normal' if mode=='normal' else 'one_insn_per_tb',
                instruction_callbacks=len(trace),REP_callbacks=len(repeated),expected_REP_callbacks=len(repeated),
                ECX_sequence=observed,callback_candidates=list(found),
                source_pointer_destination_pointer_DF_checked=True,trace_sha256=pin['sha256'],
                raw_PC_sha256=pc_hash.hexdigest(),raw_fetch_sha256=fetch_hash.hexdigest(),
                events_sha256=digest(directory/'events.jsonl') if events_digest is None else events_digest,
                report_sha256=digest(directory/'report.json'),launch_sha256=digest(directory/'launch.json'),
                complete_diagnostic_trace_reconstructs_raw_hashes=True,
                calibration_not_SMT_proof=True,native_equivalence_claimed=False)


def _audit_thin_evidence(document):
    """Recheck persisted observations; this does not reexecute QEMU or prove SMT."""
    try:
        from .unpack_sources import loader_regions
        from .replay_trace import read_trace
    except ImportError:
        from unpack_sources import loader_regions
        from replay_trace import read_trace
    root = Path(document['evidence_root'])
    for relative,wanted in document['evidence_files'].items():
        require(digest(_plain_file(root,relative)) == wanted, 'REP calibration evidence changed: '+relative)
    for row,case in zip(document['records'],CASES):
        name = case[0]
        fixture_path = _plain_file(root,f'fixtures/{name}/fixture.json')
        fixture = strict_json(fixture_path.read_bytes())
        elf_path = _plain_file(root,f'fixtures/{name}/fixture.elf')
        require(digest(fixture_path) == row['fixture_record_sha256'] and
                digest(elf_path) == row['fixture_elf_sha256'] == fixture.get('fixture_elf_sha256'),
                'REP fixture evidence identity differs')
        loader = loader_regions(elf_path.read_bytes())
        require(loader['entry'] == 0x08049000 and fixture.get('target') == 0x0804a000,
                'REP fixture ELF/target constructor differs')
        for mode,folder in (('normal','capture'),('single','single-capture')):
            directory = root/f'cases/{name}/{folder}'
            report = strict_json((directory/'report.json').read_bytes())
            launch = strict_json((directory/'launch.json').read_bytes())
            require(launch.get('returncode') == 0 and
                    launch.get('qemu_sha256') == document['runtime']['qemu_sha256'] and
                    launch.get('plugin_sha256') == document['runtime']['observer_sha256'] and
                    launch.get('source_elf_sha256') == row['fixture_elf_sha256'] and
                    launch.get('target') == 0x0804a000 and launch.get('stdin_empty') is True and
                    launch.get('payload_instruction_execution_allowed') is False and
                    launch.get('guest_argv') == ['target.elf'] and
                    launch.get('controlled_host_environment') == {'LC_ALL':'C','TZ':'UTC'},
                    'REP calibration launch identity or scope differs')
            argv = launch.get('argv')
            require(type(argv) is list and all(type(value) is str for value in argv) and
                    argv.count('-one-insn-per-tb') == (1 if mode=='single' else 0),
                    'REP calibration launch execution mode differs')
            require(report.get('success') is True, 'REP calibration observer report failed')
            footer = dict(instructions=report['instructions'],executed_pc_sha256=report['executed_pc_sha256'],
                          executed_fetch_sha256=report['executed_fetch_sha256'])
            observed = inspect_observation(directory,fixture,case,[footer],mode,
                                           events_digest=row[mode]['events_sha256'])
            for key,value in observed.items():
                require(row[mode].get(key) == value,
                        'REP calibration observation changed: '+name+' '+mode+' '+key)
            trace,_ = read_trace(directory/'trace.jsonl')
            for event in trace:
                source = [data[event['pc']-start:event['pc']-start+event['size']]
                          for start,data in loader['initial_regions']
                          if start <= event['pc'] and event['pc']+event['size'] <= start+len(data)]
                require(source == [bytes.fromhex(event['bytes_hex'])],
                        'REP calibration fetch lacks original ELF-byte constructor')


def load_calibration(path, *, qemu, observer, sdk, project=None):
    path = Path(path)
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= 8 * 1024**2,
            'REP calibration receipt absent, symlink or oversized')
    raw = path.read_bytes()
    require(len(raw) <= 8 * 1024**2, 'REP calibration receipt grew beyond budget')
    for filename in (qemu, observer, sdk):
        require(Path(filename).is_file() and not Path(filename).is_symlink(),
                'REP calibration runtime must be a regular file')
    document = validate_calibration(strict_json(raw), qemu_sha256=digest(qemu),
                                    observer_sha256=digest(observer), sdk_sha256=digest(sdk))
    project = Path(project).resolve(strict=True) if project is not None else Path(__file__).resolve().parents[1]
    for relative,wanted in document['source_sha256'].items():
        require(digest(_plain_file(project,relative,16*1024**2)) == wanted,
                'REP calibration source changed: '+relative)
    _audit_thin_evidence(document)
    return document
