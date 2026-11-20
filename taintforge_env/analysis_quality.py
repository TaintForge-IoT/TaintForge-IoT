"""Analysis admission before a cooperative retirement permit."""
from collections import Counter
import json

from experiments.execution_capsule_probe import controller as p
from .phase1_runtime import _parse, _regular, read_json

PROFILE = 'pre-retirement-analysis-v1'
MODES = ('strict', 'research')
COUNTERS = ('trace_dropped', 'trace_incomplete', 'ir_matches', 'ir_mismatches',
            'ir_unknown', 'ir_errors', 'ir_skipped_budget')
IR_COUNTERS = ('matches', 'mismatches', 'unknown', 'errors', 'skipped_budget')
DSE_REASONS = {'NONE', 'INVALID_INPUT', 'NO_SLICE', 'TRIGGER_MISSING', 'SLICE_TRUNCATED',
    'META_MISSING', 'AUX_MISSING', 'UNSUPPORTED_INSN', 'UNRESOLVED_DEPENDENCY',
    'SYMBOLIC_ADDRESS', 'MEM_ACCESS_UNMODELED', 'TARGET_UNAVAILABLE', 'CONTEXT_INIT_FAILED',
    'SOLVER_UNKNOWN', 'NONUNIQUE_TARGET', 'CONCRETE_REPLAY', 'REPLAY_MISMATCH',
    'MODEL_INCOMPLETE', 'PATH_MODEL_INCOMPLETE', 'RESOURCE_LIMIT', 'DISABLED'}


def policy(mode='strict'):
    p.require(type(mode) is str and mode in MODES, 'Unknown analysis policy')
    return {'schema': 1, 'profile': PROFILE, 'mode': mode,
            'scope': 'observed_pre_retirement_trace', 'oep_policy': 'heuristic_candidate'}


def validate(value):
    p.require(isinstance(value, dict) and value == policy(value.get('mode')) and
              type(value.get('schema')) is int, 'Invalid analysis policy')
    return value


def uint(value):
    return type(value) is int and 0 <= value < 2**64


def ir_summary(path):
    _regular(path, 256 * 1024**2)
    counts, summary = Counter(), None
    with path.open('rb') as stream:
        for index in range(4097):
            line = stream.readline(4 * 1024**2 + 1)
            if not line:
                break
            p.require(index < 4096 and len(line) <= 4 * 1024**2 and line.endswith(b'\n') and
                      summary is None, 'Invalid or unbounded IR stream')
            item = _parse(line.decode('utf-8'))
            p.require(type(item.get('schema')) is int and item['schema'] == 1,
                      'Unsupported IR schema')
            if item.get('event') == 'summary':
                summary = item
            else:
                p.require(item.get('event') == 'check' and
                          item.get('status') in ('MATCH', 'MISMATCH', 'UNKNOWN', 'ERROR'),
                          'Invalid IR check')
                counts[item['status']] += 1
    p.require(summary is not None and all(uint(summary.get(k)) for k in ('checks', *IR_COUNTERS)),
              'Missing or invalid IR summary')
    p.require(summary['checks'] == sum(counts.values()) and
              all(summary[k] == counts[s] for k, s in zip(IR_COUNTERS[:4],
                  ('MATCH', 'MISMATCH', 'UNKNOWN', 'ERROR'))), 'IR checks disagree with summary')
    return {k: summary[k] for k in ('checks', *IR_COUNTERS)}


def facts(run, verified, stream):
    manifest = read_json(run.paths['manifest'])
    p.require(manifest['artifacts'].get('ir') is not None and
              manifest['analysis_status'] == verified['analysis_status'], 'Unbound IR evidence')
    capabilities, terminal = stream[0]['data'], stream[-1]['data']
    p.require(stream[0]['status'] == 'observing' and
              sum(e['event_type'] == 'analysis_started' for e in stream) == 1 and
              capabilities.get('profile') == 'linux-i386-single-thread-v1' and
              capabilities.get('ir_enabled') is True and
              capabilities.get('flags_contract') in ('unverified', 'taintforge_x86_flags_v1'),
              'Missing analysis capabilities')
    summaries = [e for e in stream if e['event_type'] == 'analysis_summary']
    p.require(len(summaries) == 1, 'Missing or duplicate analysis summary')
    summary, event = summaries[0]['data'], summaries[0]
    verdict_index = next(i for i, e in enumerate(stream) if e['event_type'] == 'oep_verdict')
    p.require(verdict_index < stream.index(event) < len(stream)-1, 'Analysis summary order changed')
    p.require(set(summary) == set(COUNTERS) | {'shadow_knowledge_valid', 'flags_verified'} and
              all(uint(summary[k]) for k in COUNTERS) and
              all(type(summary[k]) is bool for k in ('shadow_knowledge_valid', 'flags_verified')),
              'Invalid analysis summary')
    p.require(uint(terminal.get('dropped_events')) and terminal.get('storage_status') == 'ok' and
              terminal.get('capture_status') == verified['capture_status'] == 'success',
              'Incomplete terminal storage evidence')
    p.require(summary['flags_verified'] is (capabilities['flags_contract'] == 'taintforge_x86_flags_v1'),
              'Flag observations disagree')
    ir = ir_summary(run.paths['ir'])
    p.require(all(summary['ir_'+k] == ir[k] for k in IR_COUNTERS),
              'Analysis and IR summaries disagree')
    selected = [e for e in stream if e['event_type'] == 'oep_candidate_selected'][-1]
    candidate = selected['data']
    p.require(uint(candidate.get('candidate_id')) and candidate['candidate_id'] > 0 and
              candidate.get('dse_verdict') in ('CONFIRMED', 'UNKNOWN', 'REFUTED') and
              type(candidate.get('dse_reason')) is str and candidate['dse_reason'] in DSE_REASONS and
              (candidate['dse_verdict'] != 'CONFIRMED' or candidate['dse_reason'] == 'NONE') and
              isinstance(selected.get('incomplete_reasons'), list) and
              len(selected['incomplete_reasons']) <= 128 and
              all(type(r) is str and 0 < len(r) <= 128 for r in selected['incomplete_reasons']),
              'Missing selected candidate analysis')
    return {**summary, 'analysis_status': verified['analysis_status'],
        'stream_status': verified['stream_status'], 'summary_status': event['status'],
        'flags_contract': capabilities['flags_contract'], 'ir': ir,
        'dropped_events': terminal['dropped_events'],
        'fatal_events': sorted({e['event_type'] for e in stream
                               if e['event_type'] in ('profile_lost', 'data_loss', 'error', 'analysis_invalidated')}),
        'observation_incomplete': any(e['event_type'] == 'runtime_observation' and
                                    e['status'] != 'observed' for e in stream),
        'candidate': {k: candidate[k] for k in ('candidate_id', 'dse_verdict', 'dse_reason')} |
                     {'incomplete_reasons': selected['incomplete_reasons']}}


def assess(binding, run, verified, stream):
    config = validate(binding['settings']['analysis_policy'])
    decision = {'schema': 1, 'profile': PROFILE, 'policy': config, 'status': 'rejected',
        'identity': {k: binding[k] for k in ('session_id', 'attempt_id', 'analysis_instance_id', 'lifecycle_attempt')},
        'build_id': run.runtime.build_id, 'plugin_sha256': run.runtime.plugin_sha256,
        'runtime_manifest_sha256': run.runtime.manifest_sha256,
        'export_manifest_sha256': p.sha(run.paths['manifest']),
        'oep_proven': False, 'complete_program_analysis': False,
        'ir_scope': 'selected_trace_window_only', 'limitations': [], 'rejection_reasons': []}
    try:
        observed = facts(run, verified, stream)
    except (OSError, ValueError, RuntimeError, KeyError, TypeError, IndexError, AttributeError, StopIteration) as exc:
        detail = str(exc)
        for name, path in run.paths.items():
            detail = detail.replace(str(path), '<'+name+'>')
        return decision | {'facts': None, 'rejection_reasons': ['invalid_quality_evidence'],
                           'validation_error': f'{type(exc).__name__}: {detail}'[:512]}
    reasons, limits = [], []
    status = observed['analysis_status']
    if status not in ('observed', 'partial'):
        reasons.append('unsupported_analysis_status')
    elif observed['stream_status'] != ('completed' if status == 'observed' else 'partial') or observed['summary_status'] != status:
        reasons.append('inconsistent_analysis_status')
    if status == 'observed' and (not observed['flags_verified'] or observed['trace_incomplete']):
        reasons.append('inconsistent_analysis_status')
    if observed['fatal_events'] or observed['dropped_events'] or observed['trace_dropped']:
        reasons.append('analysis_evidence_lost')
    if not observed['shadow_knowledge_valid']:
        reasons.append('invalid_shadow_knowledge')
    if observed['ir_mismatches'] or observed['ir_errors']:
        reasons.append('ir_failure')
    if observed['candidate']['dse_verdict'] == 'REFUTED':
        reasons.append('candidate_refuted')
    if observed['candidate']['dse_reason'] in {'REPLAY_MISMATCH', 'INVALID_INPUT', 'CONTEXT_INIT_FAILED'}:
        reasons.append('candidate_analysis_failure')
    for condition, name in (
        (status == 'partial', 'partial_analysis'),
        (not observed['flags_verified'], 'unverified_flags'),
        (observed['trace_incomplete'] > 0, 'incomplete_trace'),
        (observed['observation_incomplete'], 'incomplete_runtime_observation'),
        (observed['ir_unknown'] > 0, 'unknown_ir'),
        (observed['ir_skipped_budget'] > 0, 'ir_budget_skipped'),
        (observed['ir']['checks'] == 0, 'no_ir_checks'),
        (observed['candidate']['dse_verdict'] == 'UNKNOWN', 'unknown_candidate_analysis'),
        (bool(observed['candidate']['incomplete_reasons']), 'incomplete_candidate_analysis')):
        if condition:
            limits.append(name)
    if config['mode'] == 'strict':
        reasons.extend(limits)
    return decision | {'status': 'rejected' if reasons else 'accepted', 'facts': observed,
                       'limitations': sorted(limits), 'rejection_reasons': sorted(set(reasons))}


def require_accepted(value):
    p.require(value['status'] == 'accepted',
              'Analysis policy rejected retirement: ' + ', '.join(value['rejection_reasons']))


def match_saved(binding, verified, result):
    expected = verified['analysis_quality']
    validate(binding['settings']['analysis_policy'])
    canonical = lambda v: json.dumps(v, sort_keys=True, separators=(',', ':'))
    p.require(canonical(result.get('analysis_quality')) == canonical(expected) and
              canonical(result.get('export_verification', {}).get('analysis_quality')) == canonical(expected),
              'Saved analysis decision differs from the export or policy')
    return expected


def verify_saved(binding, verified, result):
    expected = match_saved(binding, verified, result)
    require_accepted(expected)
    return expected


def verify_denial(binding, result, events, controller):
    from pathlib import Path
    from . import phase1_retirement as retirement
    root = Path(binding['run_dir'])
    saved = read_json(retirement.directory(binding)/'retirement.json')
    p.require(saved['status'] == 'analysis_rejected' and saved['nonce'] == binding['lifecycle_attempt'] and
              saved['qemu_pid'] == result['qemu_pid'] and saved['claims'] == retirement.CLAIMS and
              saved['permit_sent'] is False and saved['permit'] == 'DENY\n' and
              saved['stream_closed'] is True and len(saved['events']) == 2 and
              controller['status'] == 'failed', 'Invalid analysis denial record')
    retirement.check_packets(binding, saved['events'], result['qemu_pid'], complete=False)
    _, verified = retirement.verify_export(binding, saved['events'])
    decision = match_saved(binding, verified, saved)
    p.require(decision['status'] == 'rejected' and decision['rejection_reasons'], 'Denial has no policy rejection')
    diagnostic = (root/'logs/qemu_strace.log').read_text(errors='replace')
    p.require('CAPSULE_PHASE1_ABORT code=88 reason=invalid_permit\n' in diagnostic,
              'Phase 1 did not abort the denied permit')
    if 'hardening' in binding['settings']:
        from .capsule_hardening import verify_context
        observation = next(e for e in events if e['event'] == 'maps_held')
        path = root/'logs/capsule/execution-context-1.json'
        p.require(p.sha(path) == observation['execution_context_sha256'], 'Denial bootstrap context changed')
        verify_context(binding, read_json(path), result['qemu_pid'], 1, observation['process_start_ticks'])
    return decision
