#!/usr/bin/env python3
"""Retain timeout diagnostics and repeat bounded automatic capture; no SMT."""
import argparse
from itertools import islice
import json
import os
from pathlib import Path
import stat
import sys
import tempfile

try:
    from . import external_eval as external
    from .external_diagnostics import diagnose
except ImportError:
    import external_eval as external
    from external_diagnostics import diagnose


ROOT = Path(__file__).resolve().parent
STATUS = 'PASS_BOUNDED_REPEATED_AUTOMATIC_CAPTURE'
JSON_LIMIT = 4 * 1024**2
LOG_LIMIT = 64 * 1024**2
TAIL_LIMIT = 16384


def require(value, message):
    if not value:
        raise ValueError(message)


def plain(path):
    path = Path(os.path.abspath(os.fspath(path)))
    require(all(not part.is_symlink() for part in (path, *path.parents)),
            'Capture audit path contains a symlink: ' + str(path))
    return path


def _snapshot(root, relative, pins):
    path = plain(root / relative)
    if not path.exists():
        return dict(path=relative, present=False)
    info = path.stat()
    require(stat.S_ISREG(info.st_mode), 'Diagnostic input is not a regular file: ' + relative)
    result = dict(path=relative, present=True, bytes=info.st_size)
    maximum = (16 * 1024**2 if path.suffix == '.bin' else
               JSON_LIMIT if path.suffix == '.json' else LOG_LIMIT)
    if info.st_size > maximum:
        result.update(read=False, reason='OVERSIZED_DIAGNOSTIC_FILE')
        return result
    sha = external.digest(path)
    pins[str(path)] = sha
    result['sha256'] = sha
    if path.suffix == '.bin':
        return result
    if path.suffix == '.json':
        try:
            data = external.strict_json(path, JSON_LIMIT)
            encoded = json.dumps(data, allow_nan=False)
            if len(encoded.encode()) <= 65536:
                result['json'] = data
            else:
                # Keep the full-file identity and pointer without copying a
                # potentially large capture manifest into this diagnostic.
                result['json_truncated'] = True
                result['json'] = {key: value for key, value in list(data.items())[:32]
                    if len(key) <= 128 and type(value) in (str, int, bool, type(None))
                    and len(str(value)) <= 1024} if type(data) is dict else None
        except (ValueError, UnicodeError, RecursionError) as error:
            result['parse_error'] = type(error).__name__ + ': ' + str(error)
    elif info.st_size:
        with path.open('rb') as stream:
            stream.seek(max(0, info.st_size - TAIL_LIMIT))
            raw = stream.read(TAIL_LIMIT)
        result['tail'] = raw.decode(errors='replace')
        result['tail_truncated'] = info.st_size > TAIL_LIMIT
        if path.name == 'events.jsonl':
            lines = raw.splitlines()
            if result['tail_truncated']:
                lines = lines[1:]
            events = []
            for line in lines[-40:]:
                try:
                    row = json.loads(line)
                    if type(row) is dict:
                        events.append({key: row[key] for key in
                            ('event_type', 'status', 'event_seq', 'current_pc', 'trace_seq') if key in row})
                except (ValueError, UnicodeError):
                    continue
            result['event_tail'] = events
            result['event_tail_is_incomplete'] = True
    return result


def collect_prior(prior, sample, pins):
    """Read a bounded snapshot; presence localizes progress, not the root cause."""
    prior = plain(prior)
    summary_path = plain(prior / 'summary.json')
    summary = external.strict_json(summary_path, 16 * 1024**2)
    pins[str(summary_path)] = external.digest(summary_path)
    require(type(summary) is dict, 'Prior evaluation summary must be an object')
    rows = summary.get('samples')
    require(type(rows) is list, 'Prior evaluation has no sample inventory')
    selected = [row for row in rows if type(row) is dict and row.get('id') == sample['id']]
    require(len(selected) == 1 and selected[0].get('packed_sha256') == sample['packed_sha256'],
            'Prior capture belongs to another packed sample')
    phases = selected[0].get('phases')
    require(type(phases) is dict, 'Prior evaluation has no phase inventory')
    part = phases.get('capture')
    require(type(part) is dict, 'Prior evaluation has no capture phase')
    require(part.get('status') == 'NONPROOF' and type(part.get('measurement')) is dict,
        'Prior capture is not a recorded NONPROOF phase')
    case = prior / 'samples' / sample['id']
    names = (
        'process/capture/command.json', 'process/capture/result.json',
        'process/capture/stdout', 'process/capture/stderr',
        'capture/summary.json', 'capture/worker-summary.json',
        'capture/capture-process.json', 'capture/capture-process/command.json',
        'capture/capture-process/result.json', 'capture/capture-process/stdout',
        'capture/capture-process/stderr', 'capture/capture-verification.json',
        'capture/rebuild.json', 'capture/comparisons.json',
        'capture/capture/unpacked.json', 'capture/capture/unpacked.bin',
        'capture/capture/capture_manifest.json',
        'capture/capture/events.jsonl')
    runs = plain(case / 'capture/runs')
    guest_results = sorted(islice(runs.glob('*/*/*/result.json'), 513))
    require(len(guest_results) <= 512, 'Too many prior guest diagnostic result files')
    names += tuple(str(path.relative_to(case)) for path in guest_results)
    files = [_snapshot(case, name, pins) for name in names]
    # The evaluation diagnosis may describe the guest's smaller wall budget,
    # while the enclosing Python worker simply exits nonzero. Preserve these
    # different boundaries rather than inventing an outer-process timeout.
    measurements = [_timeout_record(part['measurement'], 'summary.json:capture.measurement')]
    for row in files:
        if (row['path'] in ('process/capture/result.json', 'capture/capture-process.json',
                           'capture/capture-process/result.json') or
                row['path'].startswith('capture/runs/') and row['path'].endswith('/result.json')) and 'json' in row:
            measurements.append(_timeout_record(row['json'], row['path']))
    diagnosis = part.get('diagnosis')
    reported = type(diagnosis) is dict and diagnosis.get('category') == 'RESOURCE_TIMEOUT'
    measured = [row['source'] for row in measurements if row['wall_timeout_recorded']]
    require(reported or measured, 'Prior capture has no recorded or reported timeout')
    present = {row['path'] for row in files if row['present']}
    milestones = dict(
        guest_launch_recorded='capture/capture-process/command.json' in present,
        guest_result_recorded='capture/capture-process/result.json' in present,
        capture_process_return_recorded='capture/capture-process.json' in present,
        capture_validation_recorded='capture/capture-verification.json' in present,
        reconstruction_recorded='capture/rebuild.json' in present,
        smoke_comparisons_recorded='capture/comparisons.json' in present)
    return dict(status='CAPTURE_DIAGNOSTIC_SNAPSHOT', sample=sample['id'],
        prior_evaluation=str(prior), packed_sha256=sample['packed_sha256'],
        recorded_phase=part, milestones=milestones, files=files,
        timeout_diagnosis_reported=reported,
        wall_timeout_recorded=bool(measured), measured_timeout_sources=measured,
        timeout_measurements=measurements,
        timeout_evidence_scope='MEASURED_STOP_RECORD' if measured else 'REPORTED_DIAGNOSIS_ONLY',
        timeout_records_independently_reverified=False,
        root_cause='UNKNOWN', root_cause_established=False,
        diagnostic_only=True, prior_timeout_retracted=False, SMT_proof=False)


def _timeout_record(record, source):
    """Describe a retained process record, without promoting diagnostic text."""
    result = dict(source=source, wall_timeout_recorded=False,
                  measurement_state='NO_RECORDED_WALL_TIMEOUT')
    if type(record) is not dict:
        result['measurement_state'] = 'MALFORMED_MEASUREMENT'
        return result
    result['observed_fields'] = {key: record[key] for key in
        ('status', 'returncode', 'timed_out', 'wall_seconds') if key in record}
    flags = ('timed_out', 'rss_limit_hit', 'file_limit_hit', 'cpu_limit_hit', 'output_limit_exceeded')
    malformed = (any(key in record and type(record[key]) is not bool for key in flags) or
        'status' in record and type(record['status']) is not str or
        'returncode' in record and record['returncode'] is not None and type(record['returncode']) is not int)
    if malformed:
        result['measurement_state'] = 'MALFORMED_MEASUREMENT'
        return result
    timeout = record.get('timed_out') is True or record.get('status') == 'TIMEOUT'
    contradictory = (record.get('status') == 'TIMEOUT' and record.get('timed_out') is False or
        record.get('timed_out') is True and 'status' in record and record['status'] != 'TIMEOUT' or
        timeout and record.get('returncode') == 0)
    if contradictory:
        result['measurement_state'] = 'CONFLICTING_MEASUREMENT'
    elif timeout:
        result.update(measurement_state='MEASURED_WALL_TIMEOUT', wall_timeout_recorded=True)
    return result


def _capture_result(receipt, selection, sample):
    require(receipt.get('packed_sha256') == sample['packed_sha256'] and
        receipt.get('target') == selection['target'] and receipt.get('smoke_cases') == 1 and
        receipt.get('capture_guest_executions') == 1 and receipt.get('smoke_guest_executions') == 4 and
        receipt.get('original_used_as_reconstruction_input') is False and
        receipt.get('SMT_proof_recomputed') is False, 'Capture/smoke identity or coverage differs')


def _reference_result(receipt, selection, sample):
    oracle = receipt.get('oracle')
    require(type(oracle) is dict and oracle.get('entry_exact') is True and
        oracle.get('complete_exact_match') is True and
        receipt.get('packed_sha256') == sample['packed_sha256'] and
        receipt.get('original_sha256') == sample['original_sha256'] and
        receipt.get('target') == selection['target'] and
        receipt.get('original_read_after_capture') is True and
        receipt.get('original_used_as_reconstruction_input') is False and
        receipt.get('historical_originality_proven') is False and receipt.get('formal_proof') is False,
        'Reference entry/code or scope differs')


def audit_capture(corpus, prior, output, *, qemu, qemu_include, repetitions=3,
                  sample_id='bzip2-lzma', collect_only=False):
    require(type(repetitions) is int and 1 <= repetitions <= 5,
            'Repetition denominator must be in 1..5')
    require(sample_id == 'bzip2-lzma' and type(collect_only) is bool,
            'This bounded capture audit selects bzip2-lzma')
    _, samples, pins = external.load_corpus(corpus)
    matches = [sample for sample in samples if sample['id'] == sample_id]
    require(len(matches) == 1, 'Missing unique capture audit sample')
    sample = matches[0]
    require(sample.get('program') == 'bzip2' and sample.get('packing') == 'lzma',
            'Capture audit sample label does not identify bzip2/lzma')
    prior = plain(prior)
    qemu, include = plain(qemu), plain(qemu_include)
    input_paths = [plain(path) for path in (qemu, include / 'qemu-plugin.h', ROOT / 'capture_audit.py',
                 ROOT / 'external_worker.py', ROOT / 'external_eval.py', ROOT / 'external_process.py',
                 ROOT / 'unpack.py', ROOT / 'unpack_process.py', ROOT / 'mvp/ct_elf.py',
                 ROOT.parent / 'taintforge_env/phase1_runtime.py')]
    output = plain(output)
    require(not output.exists() and all(not output.is_relative_to(Path(name)) and
        not Path(name).is_relative_to(output) for name in (*pins, *input_paths)),
        'Capture audit output must be new and separate from inputs')
    require(not output.is_relative_to(prior) and not prior.is_relative_to(output),
            'Capture audit output overlaps the prior evaluation')
    output.mkdir(parents=True)
    result = dict(schema_version=1, status='NONPROOF_REPEATED_AUTOMATIC_CAPTURE', errors=[],
        sample=sample_id, packed_sha256=sample['packed_sha256'], original_sha256=sample['original_sha256'],
        requested_repetitions=repetitions, completed_repetitions=0, successful_repetitions=0,
        attempts=[], budgets=dict(guest_timeout=30, capture_timeout=600, reference_timeout=60,
            guest_rss_limit_mib=4096, rss_limit_mib=8192, address_space_mib=16384,
            file_limit_mib=2048), prior_diagnostics_sha256=None,
        prior_timeout_retracted=False, root_cause='UNKNOWN', root_cause_established=False,
        SMT_run=False, SMT_proof=False, universal_equivalence=False, historical_originality_proven=False,
        behavior_scope='One retained case; two packed and two rebuilt fresh executions per capture',
        all_pinned_inputs_unchanged=False)

    def phase(name, destination, process, extra, timeout):
        command = [sys.executable, '-B', str(external.WORKER), '--phase', name,
            '--output', str(destination), '--qemu', str(qemu), '--qemu-include', str(include),
            '--guest-timeout', '30', '--guest-rss-mib', '4096', *map(str, extra)]
        measured = external.run_phase(command, process, cwd=ROOT.parent, timeout=timeout,
            rss_limit_mib=8192, address_space_mib=16384, file_limit_mib=2048)
        try:
            receipt = external._positive(name, destination, measured)
            return dict(status='PASS', measurement=measured, receipt=receipt)
        except (OSError, ValueError, KeyError, TypeError) as error:
            return dict(status='NONPROOF', measurement=measured,
                diagnosis=diagnose(name, destination, measured), error=str(error))

    try:
        diagnostic = collect_prior(prior, sample, pins)
        external.save(output / 'prior-diagnostics.json', diagnostic)
        result['prior_diagnostics_sha256'] = external.digest(output / 'prior-diagnostics.json')
        result['prior_wall_timeout_recorded'] = diagnostic['wall_timeout_recorded']
        result['prior_timeout_evidence_scope'] = diagnostic['timeout_evidence_scope']
        require(qemu.is_file() and os.access(qemu, os.X_OK) and
            (include / 'qemu-plugin.h').is_file(), 'QEMU runtime and matching SDK are required')
        for path in input_paths:
            pins[str(path)] = external.digest(path)
        external.check_pins(pins)
        if collect_only:
            result['status'] = 'COLLECTED_CAPTURE_TIMEOUT_DIAGNOSTICS'
        else:
            print('capture-audit: build-plugin', flush=True)
            built = phase('build-plugin', output / 'plugin', output / 'process/build-plugin', [], 600)
            result['build'] = built
            require(built['status'] == 'PASS', 'Fresh production plugin build failed')
            plugin = plain(output / 'plugin/libtaintforge_ir.so')
            manifest = plain(Path(str(plugin) + '.runtime.json'))
            build_receipt = external.strict_json(output / 'plugin/build-receipt.json', JSON_LIMIT)
            require(built['receipt'].get('plugin_sha256') == external.digest(plugin) ==
                build_receipt.get('plugin_sha256') and
                build_receipt.get('manifest_sha256') == external.digest(manifest) and
                built['receipt'].get('receipt_sha256') == external.digest(output / 'plugin/build-receipt.json') and
                build_receipt.get('qemu_header_sha256') == external.digest(include / 'qemu-plugin.h'),
                'Fresh production build/runtime identity differs')
            pins[str(plugin)] = external.digest(plugin)
            pins[str(manifest)] = external.digest(manifest)
            pins[str(output / 'plugin/build-receipt.json')] = external.digest(output / 'plugin/build-receipt.json')
            common = ['--packed', sample['packed'], '--original', sample['original'], '--cases', sample['cases']]
            for index in range(repetitions):
                external.check_pins(pins)
                attempt = output / f'attempt-{index + 1:02d}'
                attempt.mkdir()
                row = dict(index=index + 1, status='NONPROOF', reference=dict(status='NOT_RUN_NO_CAPTURE'))
                result['attempts'].append(row)
                print(f'capture-audit: {index + 1}/{repetitions}', flush=True)
                row['capture'] = phase('capture', attempt / 'capture', attempt / 'process/capture',
                    [*common, '--plugin', plugin], 600)
                if row['capture']['status'] == 'PASS':
                    try:
                        selection = external._capture_view(attempt / 'capture', sample['packed_sha256'])
                        _capture_result(row['capture']['receipt'], selection, sample)
                        row['selection'] = selection
                        row['reference'] = phase('reference', attempt / 'reference', attempt / 'process/reference',
                            [*common, '--unpack', attempt / 'capture'], 60)
                        if row['reference']['status'] == 'PASS':
                            _reference_result(row['reference']['receipt'], selection, sample)
                            row['status'] = 'PASS'
                    except (OSError, ValueError, KeyError, TypeError) as error:
                        row['errors'] = [type(error).__name__ + ': ' + str(error)]
                result['completed_repetitions'] += 1
                result['successful_repetitions'] += row['status'] == 'PASS'
                external.check_pins(pins)
                external.save(output / 'summary.json', result)
            require(result['completed_repetitions'] == result['successful_repetitions'] == repetitions,
                    'Not every declared fresh capture/reference/smoke attempt passed')
            targets = {row['selection']['target'] for row in result['attempts']}
            require(len(targets) == 1, 'Repeated automatic entry selection differs')
            result.update(status=STATUS, target=targets.pop(),
                observed_whole_image_hashes_equal=len({row['selection']['dump_sha256'] for row in result['attempts']}) == 1,
                whole_image_hash_comparison_is_diagnostic_only=True,
                selected_entry_and_reference_code_match_in_every_attempt=True)
        external.check_pins(pins)
        result['all_pinned_inputs_unchanged'] = True
    except (OSError, ValueError, KeyError, TypeError) as error:
        result['status'] = 'NONPROOF_REPEATED_AUTOMATIC_CAPTURE'
        result['errors'].append(type(error).__name__ + ': ' + str(error))
    finally:
        external.save(output / 'input-pins.json', pins)
        external.save(output / 'summary.json', result)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--corpus', type=Path, required=True)
    parser.add_argument('--prior-evaluation', type=Path, required=True)
    parser.add_argument('--qemu', type=Path, required=True)
    parser.add_argument('--qemu-include', type=Path, required=True)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--sample', default='bzip2-lzma')
    parser.add_argument('--repetitions', type=int, default=3)
    parser.add_argument('--collect-only', action='store_true')
    args = parser.parse_args(argv)
    output = args.output or Path(tempfile.mkdtemp(prefix='unpack-proof.capture-audit-', dir=ROOT)) / 'probe'
    print('Results:', output, flush=True)
    try:
        result = audit_capture(args.corpus, args.prior_evaluation, output, qemu=args.qemu,
            qemu_include=args.qemu_include, repetitions=args.repetitions,
            sample_id=args.sample, collect_only=args.collect_only)
    except (OSError, ValueError, KeyError, TypeError) as error:
        print('FAIL:', type(error).__name__ + ': ' + str(error), file=sys.stderr)
        return 1
    print(result['status'], flush=True)
    print('Capture attempts:', result['successful_repetitions'], '/', result['requested_repetitions'], flush=True)
    if result['errors']:
        print(result['errors'], file=sys.stderr)
    return 0 if result['status'] in (STATUS, 'COLLECTED_CAPTURE_TIMEOUT_DIAGNOSTICS') else 1


if __name__ == '__main__':
    raise SystemExit(main())
