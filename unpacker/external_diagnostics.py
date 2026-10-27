"""Classify bounded external-evaluation failures without promoting evidence.

This is a diagnostic classifier, not a proof verifier. Even a success-looking
receipt is never returned as PASS or PROVED; the benchmark's evidence gate owns
positive results. Resource stops take precedence over incidental error text.
"""
import json
import math
from pathlib import Path
import re
import signal
import stat


PHASES = frozenset(('capture', 'reference', 'behavior', 'baseline', 'proof',
                    'build-native', 'build-plugin'))
MAX_JSON = 4 * 1024**2
MAX_TAIL = 64 * 1024


def _answer(category, phase, detail, source=None):
    result = dict(category=category, stage=phase, detail=str(detail)[:4096])
    if source is not None:
        result['diagnostic_file'] = str(source)
    return result


def _plain(path):
    path = Path(path).absolute()
    if any(part.is_symlink() for part in (path, *path.parents)):
        raise ValueError('Diagnostic path contains a symlink')
    return path


def _json(path):
    path = _plain(path)
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= MAX_JSON:
        raise ValueError('Diagnostic JSON is missing, empty or oversized')
    return _decode_json(path.read_bytes())


def _decode_json(data):
    def pairs(items):
        row = {}
        for key, value in items:
            if key in row:
                raise ValueError('Duplicate diagnostic JSON key: ' + key)
            row[key] = value
        return row
    def number(text):
        value = float(text)
        if not math.isfinite(value):
            raise ValueError('Nonfinite diagnostic JSON number')
        return value
    def constant(_):
        raise ValueError('Nonfinite diagnostic JSON constant')
    row = json.loads(data, object_pairs_hook=pairs,
                     parse_float=number, parse_constant=constant)
    if type(row) is not dict:
        raise ValueError('Diagnostic JSON must be an object')
    return row


def _resource(phase, measured, source=None):
    if type(measured) is not dict:
        raise ValueError('Phase measurement must be an object')
    flags = ('timed_out', 'rss_limit_hit', 'file_limit_hit', 'cpu_limit_hit',
             'output_limit_exceeded')
    if any(key in measured and type(measured[key]) is not bool for key in flags):
        raise ValueError('Resource measurement flags must be booleans')
    code = measured.get('returncode')
    if code is not None and type(code) is not int:
        raise ValueError('Resource measurement returncode must be an integer or null')
    status = measured.get('status')
    if status is not None and type(status) is not str:
        raise ValueError('Resource measurement status must be text')
    if measured.get('timed_out') is True or status == 'TIMEOUT':
        return _answer('RESOURCE_TIMEOUT', phase, 'The measured process exceeded its wall-time budget', source)
    if measured.get('rss_limit_hit') is True or status == 'RSS_LIMIT':
        return _answer('RESOURCE_MEMORY', phase, 'The measured process exceeded its resident-memory budget', source)
    if (measured.get('file_limit_hit') is True or measured.get('output_limit_exceeded') is True or
            code == -signal.SIGXFSZ or status == 'FILE_LIMIT'):
        return _answer('RESOURCE_BUDGET', phase, 'A file or output-size budget was reached', source)
    if measured.get('cpu_limit_hit') is True or code == -signal.SIGXCPU or status == 'CPU_LIMIT':
        return _answer('RESOURCE_BUDGET', phase, 'The measured process reached its CPU-time budget', source)
    return None


def _errors(row):
    errors = row.get('errors', [])
    if type(errors) is not list or len(errors) > 128:
        raise ValueError('Diagnostic errors must be a bounded list')
    result = []
    for error in errors:
        if type(error) is str:
            text = error
        elif type(error) is dict:
            if (not {'message'} <= error.keys() or
                    any(type(error[key]) is not str for key in ('message', 'reason', 'type') if key in error)):
                raise ValueError('Malformed structured diagnostic error')
            text = ': '.join(error[key] for key in ('reason', 'type', 'message') if error.get(key))
        else:
            raise ValueError('Malformed diagnostic error value')
        if len(text) > MAX_TAIL:
            raise ValueError('Diagnostic error text exceeds its bound')
        result.append(text)
    reason = row.get('reason')
    if reason is not None:
        if type(reason) is not str or len(reason) > 4096:
            raise ValueError('Invalid diagnostic reason')
        result.insert(0, reason)
    if row.get('success') is False and row.get('status') in (
            'REFERENCE_ENTRY_OR_CODE_MISMATCH', 'SELECTED_BEHAVIOR_MISMATCH',
            'ORIGINAL_PACKED_BASELINE_MISMATCH'):
        result.insert(0, row['status'])
    return result


def _last_query(path):
    """Read one bounded diagnostic row; this does not audit the query chain."""
    path = _plain(path)
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= 128 * 1024**2:
        raise ValueError('SMT diagnostic journal is missing or exceeds its bound')
    with path.open('rb') as stream:
        if info.st_size > MAX_JSON + 1:
            stream.seek(-(MAX_JSON + 1), 2)
        raw = stream.read(MAX_JSON + 2)
    if len(raw) > MAX_JSON + 1 or not raw.endswith(b'\n'):
        raise ValueError('SMT diagnostic journal has an oversized or incomplete final row')
    row = raw[:-1].rsplit(b'\n', 1)[-1]
    if not row or len(row) > MAX_JSON:
        raise ValueError('SMT diagnostic final row exceeds its bound')
    result = _decode_json(row)
    solver = result.get('solver')
    if type(solver) is not dict or type(solver.get('status')) is not str:
        raise ValueError('SMT diagnostic query has no solver result')
    return solver


def _tail(path):
    path = _plain(path)
    info = path.stat()
    if not stat.S_ISREG(info.st_mode):
        raise ValueError('Native diagnostic must be a regular file')
    with path.open('rb') as stream:
        if info.st_size > MAX_TAIL:
            stream.seek(-MAX_TAIL, 2)
            stream.readline()  # Do not interpret an incomplete first line.
        data = stream.read(MAX_TAIL + 1)
    if len(data) > MAX_TAIL:
        raise ValueError('Native diagnostic grew beyond its bounded tail')
    return data.decode('utf-8', errors='replace')


def _capture_profile_loss(path, phase):
    """Inspect a bounded diagnostic event tail, without claiming a full audit."""
    path = _plain(path)
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= 128 * 1024**2:
        raise ValueError('Capture diagnostic events are missing or exceed their bound')
    with path.open('rb') as stream:
        if info.st_size > MAX_TAIL:
            stream.seek(-MAX_TAIL, 2)
            stream.readline()
        raw = stream.read(MAX_TAIL + 1)
    if len(raw) > MAX_TAIL or not raw.endswith(b'\n'):
        raise ValueError('Capture diagnostic event tail has an incomplete or oversized row')
    rows = [_decode_json(line) for line in raw.splitlines()]
    previous = -1
    for row in rows:
        if (type(row.get('schema_version')) is not int or row['schema_version'] != 1 or
                type(row.get('event_type')) is not str):
            raise ValueError('Capture diagnostic event schema differs')
        if 'event_seq' in row:
            sequence = row['event_seq']
            if type(sequence) is not int or not previous < sequence < 2**64:
                raise ValueError('Capture diagnostic event sequence differs')
            previous = sequence
    for kind in ('profile_lost', 'analysis_finished'):
        for row in rows:
            if row['event_type'] != kind:
                continue
            data = row.get('data', {})
            if type(data) is not dict:
                raise ValueError('Capture diagnostic event data must be an object')
            unsupported = (row.get('status') == 'unsupported' if kind == 'profile_lost'
                           else data.get('capture_status') == 'unsupported')
            if not unsupported:
                continue
            reasons, pc, trace = (row.get(key) for key in
                                  ('incomplete_reasons', 'current_pc', 'trace_seq'))
            if (type(reasons) is not list or not 0 < len(reasons) <= 64 or
                    any(type(reason) is not str or not 0 < len(reason) <= 1024 for reason in reasons) or
                    type(pc) is not int or not 0 <= pc < 2**32 or
                    type(trace) is not int or not 0 <= trace < 2**64):
                raise ValueError('Capture profile-loss reason or occurrence is invalid')
            detail = (f'{kind} at pc=0x{pc:08x} trace_seq={trace}: ' + ', '.join(reasons))
            reason_category = _classify_text(phase, ' '.join(reasons), path)
            category = (reason_category['category'] if reason_category and
                        reason_category['category'].startswith('RESOURCE_') else 'UNSUPPORTED_PROFILE')
            return _answer(category, phase, detail, path)
    return None


def _classify_text(phase, text, source):
    """Specific native causes precede generic outer Python failure messages."""
    patterns = (
        ('RESOURCE_MEMORY', r'out of memory|cannot allocate memory|allocation failed|failed to allocate|memoryerror|std::bad_alloc'),
        ('RESOURCE_BUDGET', r'\bbudget\b|exceeds? (?:the )?(?:bound|limit)|too many (?:producer|source|instruction|node)|producer node (?:bound|limit)'),
        ('RESOURCE_TIMEOUT', r'\btimed out\b|\btimeoutexpired\b|\btimeout (?:exceeded|expired)\b'),
        ('UNSUPPORTED_SYSCALL', r'unsupported (?:syscall|kernel contract)|(?:syscall|kernel contract)[^\n]{0,100}unsupported'),
        ('UNSUPPORTED_INSTRUCTION', r'unsupported (?:x86 |ir )?(?:instruction|opcode)|unmodeled (?:x86 |ir )?(?:instruction|opcode)|frontend lift failed|frontend.*unsupported'),
        ('UNSUPPORTED_PROFILE', r'unsupported_profile|outside (?:the |this )?(?:first |supported )?profile|unsupported.*(?:profile|tls|elf|mapping)|(?:dynamic linking|tls) (?:are|is) outside|unmodeled.*flags|unsupported.*flag|unknown or non-scalar operand'),
        ('SMT_UNKNOWN', r'\bsolver[^\n]{0,100}\bunknown\b|\bsmt[^\n]{0,100}\bunknown\b'),
        ('SMT_COUNTEREXAMPLE', r'\bcounterexample(?:_query)?\s*[:=]\s*sat\b|\bstatus\s*[:=]\s*counterexample\b'),
        ('STATE_MISMATCH', r'computed (?:syscall|mmap)[^\n]{0,100}differ|post-syscall[^\n]{0,100}differ|(?:replay|checkpoint|register|eflags|flags|poststate|post-state)[^\n]{0,100}(?:mismatch|differ)|environment_or_state_mismatch'),
        ('INVALID_EVIDENCE', r'identity_changed|invalid_(?:capture|stage_selection|input)|checksum|digest[^\n]{0,80}differs|hash[^\n]{0,80}differs|duplicate json|scope promoted|pinned[^\n]{0,80}changed'),
        ('REFERENCE_MISMATCH', r'reference_image_mismatch|reference[^\n]{0,80}(?:mismatch|differs)|original[^\n]{0,80}(?:entry|code|bytes)[^\n]{0,80}(?:mismatch|differ)'),
        ('BEHAVIOR_MISMATCH', r'selected_case_mismatch|case_execution_failed|original_packed_baseline_mismatch|behavior[^\n]{0,80}(?:mismatch|differs)|repetition determinism differs'),
    )
    for category, pattern in patterns:
        match = re.search(pattern, text, re.I)
        if match:
            # Keep the complete bounded causal line rather than only a regexp fragment.
            line = text[text.rfind('\n', 0, match.start()) + 1:text.find('\n', match.end()) if '\n' in text[match.end():] else len(text)]
            return _answer(category, phase, line.strip(), source)
    return None


def diagnose(phase, output, measurement):
    """Return a nonproof stop category for one failed benchmark phase.

    Terminal PASS/UNSAT text is never positive evidence. The caller must run its
    separate capture/reference/behavior/proof evidence checks before admitting
    success. This function deliberately has no success return category.
    """
    if phase not in PHASES:
        raise ValueError('Unknown external evaluation phase')
    try:
        stopped = _resource(phase, measurement)
        if stopped:
            return stopped
        if measurement.get('spawn_error') is not None or measurement.get('status') == 'SPAWN_ERROR':
            return _answer('BUILD_FAILURE' if phase.startswith('build-') else 'FAILED', phase,
                           measurement.get('spawn_error') or 'Phase process could not be started')
        root = _plain(output)
        if not root.exists():
            return _answer('FAILED', phase, 'The phase did not create an output directory')
        if not root.is_dir():
            raise ValueError('Phase diagnostic output must be a directory')
        messages = []
        for filename in ('worker-summary.json', 'summary.json'):
            path = root / filename
            if path.exists() or path.is_symlink():
                row = _json(path)
                if filename == 'worker-summary.json':
                    if (type(row.get('schema_version')) is not int or row['schema_version'] != 1 or
                            row.get('phase') != phase or type(row.get('success')) is not bool):
                        raise ValueError('Worker diagnostic phase/schema differs')
                messages.extend((message, path) for message in _errors(row))
        # A guest can exhaust its own smaller budget while the enclosing phase
        # completes normally. Preserve that cause instead of reporting a mismatch.
        guest_results = []
        capture = root / 'capture-process.json'
        if capture.exists() or capture.is_symlink():
            guest_results.append(capture)
        if phase in ('capture', 'behavior', 'baseline'):
            guest_results.extend(root.glob('runs/*/*/*/result.json'))
        if len(guest_results) > 512:
            raise ValueError('Too many guest diagnostic result files')
        for path in guest_results:
            stopped = _resource(phase, _json(path), path)
            if stopped:
                return stopped
        if phase == 'capture':
            path = root / 'capture/events.jsonl'
            if path.exists() or path.is_symlink():
                found = _capture_profile_loss(path, phase)
                if found:
                    return found
        native_paths = {
            'proof': ('reduced/stderr', 'discovery/stderr', 'capture/stderr'),
            'build-native': ('build.log', 'calibration-tools/build.log'),
            'build-plugin': ('build.log',),
            'capture': ('capture-process/stderr',),
        }.get(phase, ())
        for name in native_paths:
            path = root / name
            if path.exists() or path.is_symlink():
                text = _tail(path)
                found = _classify_text(phase, text, path)
                if found:
                    return found
        if phase == 'proof':
            for name in ('smt/goal-proof/schedule-queries.jsonl', 'smt/schedule-queries.jsonl'):
                path = root / name
                if path.exists() or path.is_symlink():
                    solver = _last_query(path)
                    if solver['status'] == 'UNKNOWN':
                        return _answer('SMT_UNKNOWN', phase,
                            'The last recorded SMT query returned UNKNOWN; no proof was admitted', path)
                    if solver['status'] == 'COUNTEREXAMPLE':
                        return _answer('SMT_COUNTEREXAMPLE', phase,
                            'The last recorded SMT query reported a counterexample', path)
        for text, path in messages:
            found = _classify_text(phase, text, path)
            if found:
                return found
        if phase.startswith('build-'):
            return _answer('BUILD_FAILURE', phase,
                messages[0][0] if messages else 'Native build or runtime calibration did not complete',
                messages[0][1] if messages else None)
        return _answer('FAILED', phase,
            messages[0][0] if messages else 'No authenticated success was admitted; inspect the retained phase outputs',
            messages[0][1] if messages else None)
    except (ValueError, OSError, UnicodeError, json.JSONDecodeError, RecursionError) as error:
        return _answer('INVALID_EVIDENCE', phase, type(error).__name__ + ': ' + str(error))
