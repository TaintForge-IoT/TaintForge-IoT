"""Run the production detector and validate the saved candidate image."""
from pathlib import Path
import json
import os
import uuid

from ct_elf import CaptureError, integer, load_capture, read_elf, sha256
from cu_process import run, save


def capture(qemu, plugin, packed, case, directory, environment, guard, method='entry',
            max_capture_bytes=64 * 1024**2, max_dump_bytes=16 * 1024**2,
            collect_metrics=False, rss_limit_mib=None, timeout=120):
    packed = Path(packed).resolve()
    if not packed.is_file():
        raise CaptureError('CAPTURE_INPUT_UNAVAILABLE', f'Packed guest does not exist: {packed}')
    packed_identity = read_elf(packed)['sha256']
    directory = directory.resolve()
    instance = 'cu-' + uuid.uuid4().hex
    options = [str(plugin), 'dse-check=off', 'ir-check=off', 'ir-trace-capacity=4096',
               f'tf-capture={method}', 'tf-session-id=cu-corpus', 'tf-attempt-id=run',
               f'tf-instance-id={instance}', 'tf-require-flags=off', 'runtime-log=summary',
               'tf-max-candidates=64', f'tf-max-dump-bytes={max_dump_bytes}',
               f'tf-max-capture-bytes={max_capture_bytes}']
    if collect_metrics:
        options.append('dta-shadow-stats=on')
    paths = {'events': 'events.jsonl', 'manifest': 'capture-manifest.json', 'dump': 'image.bin',
             'report': 'capture.json', 'ir-report': 'ir.jsonl'}
    for key, name in paths.items():
        options.append(f'tf-{key}={directory / name}')
    if any(',' in str(p) for p in (directory, plugin)):
        raise CaptureError('UNSUPPORTED_PATH', 'QEMU plugin paths cannot contain commas')
    env = dict(environment)
    env['LD_PRELOAD'] = str(guard) + (':' + os.environ['LD_PRELOAD'] if os.environ.get('LD_PRELOAD') else '')
    result = run([str(qemu), '-plugin', ','.join(options), '-0', 'target.elf', str(packed),
                  *case.get('argv', [])], case, directory, env, timeout=timeout,
                 file_size_mib=64, plugin=True, rss_limit_mib=rss_limit_mib)
    log = (directory / 'stderr').read_bytes()
    if result['rss_limit_hit']:
        raise CaptureError('CAPTURE_RSS_LIMIT', f"Capture exceeded {rss_limit_mib} MiB RSS; peak={result['max_rss_kib']} KiB")
    if result['timed_out'] or result['returncode'] < 0:
        raise CaptureError('CAPTURE_PROCESS_FAILED', f"Capture exit={result['returncode']}; timeout={result['timed_out']}")
    if b'[CU-GUARD] solver checks forbidden' not in log or b'[CU-GUARD] FORBIDDEN' in log:
        raise CaptureError('SOLVER_GUARD_FAILED', 'Capture did not keep the solver-check guard active')
    if sha256(packed) != packed_identity:
        raise CaptureError('IDENTITY_CHANGED', 'Packed guest changed during capture')
    result.update(solver_guard_active=True, solver_guard_sha256=sha256(guard),
                  packed_sha256=packed_identity)
    save(directory / 'result.json', result)
    return result


def validate_export_failure(directory, process, expected_status, expected_reason):
    required = (directory / 'capture.json', directory / 'events.jsonl')
    if not all(p.is_file() for p in required):
        raise CaptureError('NEGATIVE_CONTROL_FAILED', 'Missing producer report or failure events')
    report = json.loads(required[0].read_text())
    events = [json.loads(line) for line in required[1].read_text().splitlines()]
    candidates = [e for e in events if e.get('event_type') == 'oep_candidate_observed'
                  and e.get('trace_seq', 0) > 0]
    failures = [e for e in events if expected_reason in e.get('incomplete_reasons', [])
                and e.get('trace_seq', 0) > 0]
    if (process['returncode'] != 0 or process['timed_out'] or process['rss_limit_hit']
            or process.get('solver_guard_active') is not True
            or report.get('main_image_verified') is not True
            or report.get('capture_status') != expected_status
            or report.get('dse_check_enabled') is not False
            or report.get('trace_archive_enabled') is not False
            or not candidates or not failures
            or any(e.get('analysis_instance_id') != report.get('analysis_instance_id')
                   for e in candidates + failures)):
        raise CaptureError('NEGATIVE_CONTROL_FAILED',
                           f'Guest execution and producer cause {expected_reason} were not established')
    return dict(producer_status=expected_status, producer_reason=expected_reason,
                candidate_trace_seq=candidates[0]['trace_seq'], failure_trace_seq=failures[0]['trace_seq'],
                main_image_verified=True)


def validate(directory, method='entry'):
    report_path, dump_path = directory / 'capture.json', directory / 'image.bin'
    required = (report_path, dump_path, directory / 'capture-manifest.json', directory / 'events.jsonl')
    if not all(path.is_file() for path in required):
        raise CaptureError('CAPTURE_UNAVAILABLE', 'Production detector did not export an image')
    report, regions = load_capture(report_path, dump_path)
    if report.get('main_image_verified') is not True:
        raise CaptureError('UNVERIFIED_MAIN_IMAGE', 'Require the file/guest/auxv-verified main ELF mapping')
    if report.get('dse_check_enabled') is not False or report.get('trace_archive_enabled') is not False:
        raise CaptureError('UNEXPECTED_ANALYSIS_MODE', 'Capture requires DSE/IR checks and full trace archive to be disabled')
    manifest = json.loads((directory / 'capture-manifest.json').read_text())
    for key, path in (('dump', dump_path), ('report', report_path), ('events', directory / 'events.jsonl')):
        item = manifest.get('artifacts', {}).get(key)
        if not item or item['sha256'] != sha256(path) or item['size'] != path.stat().st_size:
            raise CaptureError('CAPTURE_HASH_MISMATCH', f'Export manifest mismatch: {key}')
    if manifest.get('capture_status') != 'success' or manifest.get('storage_status') != 'ok':
        raise CaptureError('INCOMPLETE_CAPTURE', 'Production export did not complete')
    chosen = [c for c in report.get('oep_candidates', []) if c.get('selected')]
    if len(chosen) != 1 or any(c.get('candidate_query') != 'NOT_RUN' or c.get('alternative_query') != 'NOT_RUN'
                               for c in report.get('oep_candidates', [])):
        raise CaptureError('INVALID_CAPTURE', 'Candidate selection or disabled-query record is invalid')
    if method == 'entry' and (report.get('capture_method') != 'candidate_entry_before_instruction'
            or report.get('capture_candidate_id') != chosen[0].get('candidate_id')
            or report.get('capture_trace_seq') != chosen[0].get('observed_trace_seq')
            or report.get('capture_pc') != integer(report['oep'], 'oep')):
        raise CaptureError('CAPTURE_TIMING_MISMATCH', 'Saved image is not from the selected candidate entry')
    return report, regions
