"""Observe Python boundaries of an unchanged isolated DTA/DSE evaluation."""
from __future__ import annotations

import argparse
from contextlib import ExitStack, contextmanager
import csv
import functools
import hashlib
import inspect
import io
import json
import math
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import threading
import time
from unittest.mock import patch

from taintforge_env import dse_analysis, dta_analysis, dta_dse, dta_dse_eval, dta_dse_queue
from taintforge_env.dta_corpus import _canonical, _limit, _require


PROFILE = 'dta-dse-python-boundary-profile-v1'
MAX_EVENTS = 32768
MAX_OUTPUT_BYTES = 64 * 1024**2
PROJECT = Path(__file__).resolve().parents[1]
_ACTIVE_PROFILE = None


class ProfileBudgetError(RuntimeError):
    """Profiling stopped before invoking another original function."""


def _context(arguments, inherited):
    result = dict(inherited)
    for name in ('out', 'directory', 'queue'):
        value = arguments.get(name)
        if isinstance(value, (str, Path)):
            value = str(value)
            if len(value) <= 4096:
                result['argument_' + name] = value
                parts = Path(value).parts
                matches = [parts[index + 1] for index, part in enumerate(parts[:-2])
                           if part == 'attempts' and re.fullmatch('[0-9a-f]{64}', parts[index + 1])
                           and parts[index + 2] == '0001']
                if len(matches) == 1:
                    result['job_id'] = matches[0]
    for name in ('branch_pc', 'occurrence', 'max_steps'):
        value = arguments.get(name)
        if type(value) is int and 0 <= value < 2**64:
            result['argument_' + name] = value
    concolic = arguments.get('concolic')
    if isinstance(concolic, dict):
        for name in ('mode', 'branch_pc', 'occurrence', 'max_steps'):
            value = concolic.get(name)
            if isinstance(value, str) and len(value) <= 64 or type(value) is int and 0 <= value < 2**64:
                result['concolic_' + name] = value
    return result


class SpanProfiler:
    """Bounded single-threaded call tree; durations are observational metrics."""

    def __init__(self, *, max_events=MAX_EVENTS, clock=time.monotonic_ns):
        _limit(max_events, MAX_EVENTS, 'profiler events')
        self.max_events = max_events
        self.clock = clock
        self.thread = threading.get_ident()
        self.started_ns = clock()
        self.ended_ns = None
        self.events = []
        self.stack = []

    @contextmanager
    def span(self, category, metadata=None):
        if threading.get_ident() != self.thread:
            raise RuntimeError('The profiling driver supports one Python control thread')
        if self.ended_ns is not None:
            raise RuntimeError('The profiling session has ended')
        if len(self.events) == self.max_events:
            raise ProfileBudgetError('Profiler event budget exhausted before the next original call')
        if not isinstance(category, str) or not 1 <= len(category) <= 128:
            raise ValueError('Invalid profiling category')
        parent = self.stack[-1] if self.stack else None
        event = {'id': len(self.events) + 1, 'parent_id': parent['id'] if parent else None,
                 'depth': len(self.stack), 'category': category, 'metadata': metadata or {},
                 'start_ns': self.clock(), 'end_ns': None, 'status': 'RUNNING',
                 'child_wall_ns': 0}
        self.events.append(event)
        self.stack.append(event)
        try:
            yield event
        except BaseException as exc:
            event['status'] = 'ERROR'
            event['exception_type'] = type(exc).__name__
            raise
        else:
            event['status'] = 'RETURNED'
        finally:
            event['end_ns'] = self.clock()
            elapsed = event['end_ns'] - event['start_ns']
            _require(elapsed >= event['child_wall_ns'] >= 0, 'Profiler clock or nesting is invalid')
            event['inclusive_ns'] = elapsed
            event['exclusive_ns'] = elapsed - event['child_wall_ns']
            _require(self.stack.pop() is event, 'Profiler call stack changed')
            if parent:
                parent['child_wall_ns'] += elapsed

    def wrap(self, original, category):
        signature = inspect.signature(original)

        @functools.wraps(original)
        def observed(*args, **kwargs):
            try:
                arguments = signature.bind_partial(*args, **kwargs).arguments
            except TypeError:
                # Preserve the original callable's own argument error.
                arguments = {}
            inherited = self.stack[-1]['metadata'] if self.stack else {}
            metadata = _context(arguments, inherited)
            label = category(arguments) if callable(category) else category
            with self.span(label, metadata):
                return original(*args, **kwargs)

        return observed

    def finish(self):
        _require(not self.stack, 'Cannot finish profiling with an active call')
        if self.ended_ns is None:
            self.ended_ns = self.clock()
        return self.summary()

    def summary(self):
        _require(self.ended_ns is not None and not self.stack, 'Profiling has not finished')
        grouped = {}
        for event in self.events:
            _require(event['status'] in ('RETURNED', 'ERROR'), 'Incomplete profiling event')
            grouped.setdefault(event['category'], []).append(event)
        rows = []
        for category, events in sorted(grouped.items()):
            durations = sorted(event['inclusive_ns'] for event in events)
            count = len(events)
            rows.append({'category': category, 'calls': count,
                'errors': sum(event['status'] == 'ERROR' for event in events),
                'inclusive_ns': sum(event['inclusive_ns'] for event in events),
                'exclusive_ns': sum(event['exclusive_ns'] for event in events),
                'min_inclusive_ns': durations[0], 'p50_inclusive_ns': durations[math.ceil(count * .50) - 1],
                'p95_inclusive_ns': durations[math.ceil(count * .95) - 1],
                'max_inclusive_ns': durations[-1]})
        wall = self.ended_ns - self.started_ns
        root_wall = sum(event['inclusive_ns'] for event in self.events if event['parent_id'] is None)
        exclusive = sum(event['exclusive_ns'] for event in self.events)
        _require(0 <= root_wall == exclusive <= wall, 'Profiling partition is inconsistent')
        return {'profiled_wall_ns': wall, 'instrumented_root_wall_ns': root_wall,
                'outside_spans_wall_ns': wall - root_wall, 'exclusive_partition_ns': exclusive,
                'span_count': len(self.events), 'error_span_count': sum(row['errors'] for row in rows),
                'max_events': self.max_events, 'categories': rows}


def _native_category(arguments):
    mode = arguments.get('concolic', {}).get('mode') if isinstance(arguments.get('concolic'), dict) else None
    if mode == 'solve':
        return 'guest.native_solve_case_wall'
    if mode == 'observe':
        return 'guest.native_observe_case_wall'
    return 'guest.native_other_case_wall'


def _bindings():
    return (
        (dta_analysis, 'analyze_file', 'DTA.full_analysis'),
        (dta_analysis, 'run_case', 'guest.DTA_case_wall'),
        (dse_analysis.dta_capsule, 'run_case', _native_category),
        (dse_analysis, 'observe_file', 'DSE.recapture_worker'),
        (dse_analysis, 'invert_file', 'DSE.inversion_worker'),
        (dse_analysis, 'audit_file_run', 'audit.native_worker'),
        (dta_dse, 'extend_corpus', 'controller.extend_corpus'),
        (dta_dse, 'audit_selected_corpus', 'audit.selected_controller'),
        (dta_dse_queue, '_configuration', 'audit.runtime_and_code_inventory'),
        (dta_dse_queue, '_sources', 'audit.all_DTA_sources'),
        (dta_dse_queue, '_collect', 'audit.completed_queue_results'),
        (dta_dse_queue, '_commit', 'publication.queue_commit'),
        (dta_dse_queue, '_publish', 'publication.queue_corpus'),
        (dta_dse_queue, 'export_handoff', 'audit.handoff.queue'),
        (dta_dse, 'export_handoff', 'audit.handoff.controller'),
        (dta_dse_eval, 'export_handoff', 'audit.handoff.evaluator'),
    )


@contextmanager
def instrument(profiler, bindings=None):
    """Restore every binding even if the original evaluation raises."""
    global _ACTIVE_PROFILE
    _require(_ACTIVE_PROFILE is None, 'Nested profiling installation is unsupported')
    bindings = tuple(_bindings() if bindings is None else bindings)
    keys = [(id(owner), name) for owner, name, _ in bindings]
    _require(len(keys) == len(set(keys)), 'Profiling binding inventory contains duplicates')
    # Capture all aliases before installing anything, so equal function objects
    # in several modules do not accidentally wrap one another.
    originals = [(owner, name, getattr(owner, name), category) for owner, name, category in bindings]
    _ACTIVE_PROFILE = profiler
    try:
        with ExitStack() as stack:
            for owner, name, original, category in originals:
                stack.enter_context(patch.object(owner, name, profiler.wrap(original, category)))
            yield
    finally:
        _ACTIVE_PROFILE = None


def _source_pins():
    paths = [PROJECT / 'scripts' / name for name in ('profile_dta_dse.py', 'dta_dse_diagnostics.py')]
    return {str(_canonical(path)): hashlib.sha256(path.read_bytes()).hexdigest() for path in paths}


def _intact(pins):
    _require(all(hashlib.sha256(_canonical(path).read_bytes()).hexdigest() == expected
                 for path, expected in pins.items()), 'Profiling implementation changed during measurement')


def _atomic_bytes(path, value):
    _require(len(value) <= MAX_OUTPUT_BYTES, 'Profiling output byte budget exceeded')
    descriptor, temporary = tempfile.mkstemp(prefix='.profile-', dir=path.parent)
    try:
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def _write_metrics(out, profiler, report):
    lines = []
    size = 0
    for event in profiler.events:
        encoded = (json.dumps(event, sort_keys=True, allow_nan=False) + '\n').encode()
        size += len(encoded)
        _require(size <= MAX_OUTPUT_BYTES, 'Profiling span byte budget exceeded')
        lines.append(encoded)
    _atomic_bytes(out / 'spans.jsonl', b''.join(lines))
    table = io.StringIO(newline='')
    fields = ('category', 'calls', 'errors', 'inclusive_ns', 'exclusive_ns', 'min_inclusive_ns',
              'p50_inclusive_ns', 'p95_inclusive_ns', 'max_inclusive_ns')
    writer = csv.DictWriter(table, fieldnames=fields)
    writer.writeheader()
    writer.writerows(report['categories'])
    _atomic_bytes(out / 'timings.csv', table.getvalue().encode())
    _atomic_bytes(out / 'profile.json', (json.dumps(report, indent=2, sort_keys=True, allow_nan=False) + '\n').encode())


def profile_evaluation(*, out, max_events=MAX_EVENTS, **parameters):
    """Run the original evaluator and retain a separate observational profile."""
    out = _canonical(out)
    _require(not out.exists() and not out.is_relative_to(PROJECT) and not PROJECT.is_relative_to(out),
             'Profiling output must be new and outside the project')
    inputs = [parameters.get(name) for name in ('binary', 'qemu', 'plugin', 'flags_receipt')]
    inputs.extend(parameters.get('seeds', ()))
    for value in inputs:
        if value is not None:
            path = _canonical(value)
            _require(not out.is_relative_to(path) and not path.is_relative_to(out), 'Profiling output overlaps an input')
    _require('out' not in parameters, 'The profiling driver owns the fresh evaluation output')
    pins = _source_pins()
    profiler = SpanProfiler(max_events=max_events)
    out.mkdir(parents=True, mode=0o700)
    report = {'schema': 1, 'profile': PROFILE, 'status': 'FAILED_DTA_DSE_PROFILE',
        'metrics_scope': 'single_threaded_Python_boundary_wall_time_not_a_proof',
        'evaluation': str(out / 'evaluation'), 'diagnostics': str(out / 'diagnostics'),
        'implementation_sha256': pins, 'SMT_only_time': 'NOT_MEASURED',
        'native_solve_case_scope': 'isolated_case_startup_IR_replay_SMT_output_and_cleanup',
        'exclusive_time_scope': 'function_self_work_plus_uninstrumented_work_and_profiling_overhead',
        'percentile_method': 'nearest_rank_of_inclusive_call_wall_time',
        'proof_reports_modified': False, 'existing_queue_resumed': False,
        'evaluation_measurement_completed': False, 'afl_campaign_executed': False,
        'universal_equivalence': False, 'protected_control_channel': False,
        'diagnostic_wall_ns': None}
    primary_error = None
    try:
        with instrument(profiler):
            with profiler.span('evaluation.total'):
                evaluated = dta_dse_eval.evaluate_file(out=out / 'evaluation', **parameters)
        report.update(profiler.finish())
        _require(evaluated.get('measurement_completed') is True, 'Original evaluation did not complete')
        report['evaluation_measurement_completed'] = True
        _intact(pins)
        from scripts.dta_dse_diagnostics import inspect_evaluation
        started = time.monotonic_ns()
        diagnostic = inspect_evaluation(evaluation=out / 'evaluation', out=out / 'diagnostics')
        report['diagnostic_wall_ns'] = time.monotonic_ns() - started
        _require(diagnostic.get('status') == 'AUDITED_DTA_DSE_DIAGNOSTICS',
                 'Fresh evaluation diagnostics did not complete their original evidence audit')
        _intact(pins)
        report.update(status='COMPLETED_DTA_DSE_PROFILE', evaluation_measurement_completed=True,
            gain_status=evaluated['gain_status'], dse_status=evaluated['dse_status'],
            verified_jobs=evaluated['verified_jobs'], nonproof_jobs=evaluated['nonproof_jobs'],
            pending_jobs=evaluated['pending_jobs'], new_seed_count=evaluated['new_seed_count'],
            new_branch_outcomes=len(evaluated['new_full_run_outcomes']),
            corpus=evaluated['seeds'], diagnostics_status=diagnostic['status'])
        return report
    except BaseException as exc:
        primary_error = exc
        report['error'] = type(exc).__name__ + ': ' + str(exc)[:4096]
        raise
    finally:
        try:
            report.update(profiler.finish())
            _write_metrics(out, profiler, report)
        except BaseException as metrics_error:
            report['status'] = 'FAILED_DTA_DSE_PROFILE'
            report['metric_publication_error'] = type(metrics_error).__name__ + ': ' + str(metrics_error)[:4096]
            # Best effort only: a full filesystem may prevent even this small
            # failure report. It must never replace an original worker error.
            try:
                _atomic_bytes(out / 'profile.json',
                    (json.dumps(report, indent=2, sort_keys=True, allow_nan=False) + '\n').encode())
            except BaseException as fallback_error:
                report['failure_report_publication_error'] = type(fallback_error).__name__ + ': ' + str(fallback_error)[:4096]
            if primary_error is not None:
                BaseException.add_note(primary_error, 'Profiling metric publication also failed: ' +
                    report['metric_publication_error'])
                if 'failure_report_publication_error' in report:
                    BaseException.add_note(primary_error, 'Profiling failure report could not be saved: ' +
                        report['failure_report_publication_error'])
            else:
                raise


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    audit = sub.add_parser('audit', help='audit saved evidence and diagnose recorded nonproof results')
    audit.add_argument('--evaluation', type=Path, required=True)
    audit.add_argument('--out', type=Path, required=True)
    run = sub.add_parser('run', help='profile a fresh unchanged DTA/DSE evaluation')
    for name in ('binary', 'qemu', 'plugin', 'flags-receipt', 'out'):
        run.add_argument('--' + name, type=Path, required=True)
    run.add_argument('--seed', action='append', dest='seeds', type=Path, required=True)
    run.add_argument('--input-path', required=True)
    run.add_argument('--arg', action='append', dest='argv', default=[])
    for name, default in (('max-candidates', 24), ('max-jobs', 16), ('max-occurrences', 4),
                          ('max-steps', 1024), ('max-sites', 4096), ('seconds', 30),
                          ('memory-mib', 1024), ('wall-seconds', 5400), ('max-events', MAX_EVENTS)):
        run.add_argument('--' + name, type=int, default=default)
    values = vars(parser.parse_args(argv))
    command = values.pop('command')
    try:
        if command == 'audit':
            from scripts.dta_dse_diagnostics import inspect_evaluation
            report = inspect_evaluation(**values)
        else:
            report = profile_evaluation(**values)
    except KeyboardInterrupt:
        print('DTA_DSE_PROFILE_INTERRUPTED: inspect original queue evidence before resuming', file=sys.stderr)
        return 130
    except (OSError, ValueError, RuntimeError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        print('DTA_DSE_PROFILE_FAILED: ' + str(exc), file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2, sort_keys=True, allow_nan=False))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
