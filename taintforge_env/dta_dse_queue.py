"""Durable single-controller scheduling of audited DTA-to-DSE requests."""
from __future__ import annotations

from contextlib import contextmanager
import fcntl
import hashlib
import os
from pathlib import Path
import re
import stat
import tempfile
import time
from uuid import uuid4

from . import dta_dse
from .dta_corpus import _canonical, _limit, _pin, _require
from .dta_handoff import export_handoff
from .elf_runtime import canonical_hash
from .environment_snapshot import EnvironmentSnapshotStore
from .phase1_runtime import read_json


PROFILE = 'dta-dse-durable-queue-v1'
MAX_ANALYSES = 64
MAX_METADATA = 8 * 1024**2
PROJECT = Path(__file__).resolve().parents[1]
STATES = {'PENDING', 'RUNNING', 'VERIFIED', 'NONPROOF', 'BLOCKED_RECOVERY'}
RUNTIME_LIMITS = {'qemu': 512 * 1024**2, 'plugin': 512 * 1024**2,
                  'runtime_manifest': 16 * 1024**2, 'flags_receipt': 4096}
CODE = ('dta_dse_queue.py', 'dta_dse.py', 'dse_analysis.py', 'dta_handoff.py',
        'dta_corpus.py', 'dta_capsule.py', 'phase1_runtime.py',
        'concolic_environment.py', 'environment_snapshot.py', 'capsule_resources.py')


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _id(value):
    return isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value) is not None


def _read(path):
    path, identity = _pin(path, 8 * 1024**2)
    value = read_json(path, maximum=8 * 1024**2)
    _require(_pin(path, 8 * 1024**2)[1] == identity, 'Queue metadata changed while reading')
    return value


def _atomic(path, raw, *, staging=None):
    path = _canonical(path)
    if path.exists():
        _pin(path, 8 * 1024**2)
    directory = _canonical(staging) if staging is not None else path.parent
    temporary_parent = directory
    descriptor, temporary = tempfile.mkstemp(prefix='.queue-write-', dir=directory)
    try:
        with os.fdopen(descriptor, 'wb') as output:
            output.write(raw)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        for parent in {path.parent, temporary_parent}:
            descriptor = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
    finally:
        Path(temporary).unlink(missing_ok=True)


def _encoded(value):
    import json
    raw = (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + '\n').encode()
    _require(len(raw) <= MAX_METADATA, 'Queue metadata byte budget exceeded')
    return raw


def _json(path, value):
    _atomic(path, _encoded(value))


@contextmanager
def _lock(queue):
    queue = _canonical(queue)
    _require(queue.is_dir(), 'Queue directory does not exist')
    path = _canonical(queue / 'controller.lock')
    descriptor = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(descriptor)
        _require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, 'Unsafe queue lock file')
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise RuntimeError('Another queue controller holds the lock') from exc
        yield queue
    finally:
        os.close(descriptor)


def _limits(**values):
    for name, maximum in (('max_total_starts', 4096), ('max_queue_jobs', 4096),
                          ('max_occurrences', 32), ('max_steps', 1024), ('max_sites', 4096), ('seconds', 120)):
        _limit(values[name], maximum, name)
    _require(type(values['memory_mib']) is int and 256 <= values['memory_mib'] <= 4096,
             'Invalid DSE queue memory budget')
    return values


def _configuration(queue, paths, limits):
    runtime = {name: _pin(paths[name], maximum)[1] for name, maximum in RUNTIME_LIMITS.items()}
    _require(all(not queue.is_relative_to(Path(row['path'])) and
                 not Path(row['path']).is_relative_to(queue) for row in runtime.values()),
             'Queue overlaps a runtime input')
    files = set((PROJECT / 'taintforge_env').glob('*.py'))
    files.update((PROJECT / 'experiments/execution_capsule_probe').rglob('*.py'))
    _require(all(PROJECT / 'taintforge_env' / name in files for name in CODE) and len(files) <= 1024,
             'Project Python implementation inventory is missing or oversized')
    code = {path.relative_to(PROJECT).as_posix(): _pin(path, 4 * 1024**2)[1] for path in sorted(files)}
    return {'profile': PROFILE, 'directory': str(queue), 'runtime': runtime,
            'limits': _limits(**limits), 'code': code}


def _binding(config):
    return canonical_hash({key: value for key, value in config.items() if key != 'directory'})


def _save_state(queue, state):
    state['revision'] += 1
    state['state_sha256'] = canonical_hash({key: value for key, value in state.items() if key != 'state_sha256'})
    _json(queue / 'state.json', state)


def _load(queue, *, verify=True):
    state = _read(queue / 'state.json')
    _require(state.get('schema') == 1 and type(state.get('revision')) is int and state['revision'] > 0 and
             state.get('state_sha256') == canonical_hash({k: v for k, v in state.items() if k != 'state_sha256'}),
             'Queue journal integrity failed')
    config = state['config']
    _require(config.get('directory') == str(queue) and config.get('profile') == PROFILE and
             state.get('binding_id') == _binding(config), 'Queue runtime/policy binding changed')
    _limits(**config['limits'])
    if verify:
        paths = {name: row['path'] for name, row in config['runtime'].items()}
        _require(_configuration(queue, paths, config['limits']) == config,
                 'Queue runtime or implementation changed; create a new queue')
    _require(isinstance(state['analyses'], dict) and isinstance(state['jobs'], dict) and
             isinstance(state['order'], list) and len(state['order']) == len(set(state['order'])) and
             set(state['order']) == set(state['jobs']) and len(state['jobs']) <= config['limits']['max_queue_jobs'],
             'Queue job inventory is invalid')
    _require(len(state['analyses']) <= MAX_ANALYSES and
             (state.get('acknowledged_stop_nonce') is None or isinstance(state['acknowledged_stop_nonce'], str) and
              re.fullmatch('[0-9a-f]{32}', state['acknowledged_stop_nonce']) is not None),
             'Queue analysis inventory or stop acknowledgment is invalid')
    scope_id = canonical_hash(state['scope']) if state['scope'] is not None else None
    for identifier, row in state['analyses'].items():
        _require(_id(identifier) and identifier == canonical_hash({k: row[k] for k in
                 ('handoff_sha256', 'requests_sha256')}) and isinstance(row['path'], str),
                 'Queue source-analysis identity changed')
    starts = 0
    for identifier, row in state['jobs'].items():
        body = {key: row[key] for key in ('analysis_id', 'request_id', 'binding_id', 'scope_id')}
        _require(_id(identifier) and identifier == canonical_hash(body) and
                 body['analysis_id'] in state['analyses'] and _id(body['request_id']) and
                 body['binding_id'] == state['binding_id'] and body['scope_id'] == scope_id and
                 row['status'] in STATES and isinstance(row['attempts'], list) and len(row['attempts']) <= 1,
                 'Queue task identity or state changed')
        if row['status'] == 'PENDING':
            _require(row['attempts'] == [] and row.get('result') is None, 'Pending task contains an attempt')
        else:
            _require(len(row['attempts']) == 1 and row['attempts'][0]['number'] == 1 and
                     row['attempts'][0]['directory'] == str(queue / 'attempts' / identifier / '0001'),
                     'Queue attempt inventory changed')
        starts += len(row['attempts'])
    _require(starts <= config['limits']['max_total_starts'], 'Persisted queue start budget exceeded')
    return state


def _source_audit(analysis, max_sites):
    analysis = _canonical(analysis)
    with tempfile.TemporaryDirectory(prefix='tf-dse-queue-source-') as temporary:
        directory = Path(temporary) / 'handoff'
        handoff = export_handoff(analysis=analysis, out=directory, max_sites=max_sites)
        _require(canonical_hash(handoff) == canonical_hash(_read(directory / 'manifest.json')),
                 'Source auditor returned a different manifest')
        requests = _read(directory / 'recapture-requests.json')['requests']
        seeds = {}
        for row in handoff['accepted_seeds']:
            path, identity = _pin(directory / 'seeds' / row['sha256'], 4096)
            _require(identity['sha256'] == row['sha256'], 'Audited source seed changed')
            seeds[row['sha256']] = path.read_bytes()
    snapshot = EnvironmentSnapshotStore(analysis / 'snapshots').verify(handoff['snapshot']['snapshot_id'])
    environment = []
    for entry in snapshot.entries:
        row = entry.to_dict()
        if row['path'] == handoff['input_path']:
            _require(row['type'] == 'file', 'Queue input is not a regular environment file')
            row = dict(row, size=None, sha256=None)
        environment.append(row)
    scope = {'target_sha256': handoff['target_sha256'], 'input_path': handoff['input_path'],
             'argv': handoff['argv'], 'environment': environment}
    return {'handoff': handoff, 'requests': requests, 'seeds': seeds, 'scope': scope}


def _admission(data):
    handoff, requests = data['handoff'], data['requests']
    _require(handoff.get('status') == 'AUDITED_DTA_CORPUS_AND_RECAPTURE_HINTS' and
             isinstance(requests, list) and data['seeds'], 'Invalid audited queue source')
    identifiers = set()
    for request in requests:
        identifier = request.get('request_id')
        _require(_id(identifier) and identifier not in identifiers and identifier == canonical_hash(
                 {key: value for key, value in request.items() if key != 'request_id'}),
                 'Invalid or duplicate audited hint identity')
        identifiers.add(identifier)
    for sha, raw in data['seeds'].items():
        _require(_id(sha) and isinstance(raw, bytes) and 0 < len(raw) <= 4096 and _sha(raw) == sha,
                 'Invalid audited source seed bytes')
    identity = {'handoff_sha256': canonical_hash(handoff), 'requests_sha256': canonical_hash(requests)}
    return canonical_hash(identity), identity


def _sources(queue, state):
    result = {}
    for identifier, row in state['analyses'].items():
        path = _canonical(row['path'])
        _require(not path.is_relative_to(queue) and not queue.is_relative_to(path),
                 'Queue overlaps its source analysis')
        data = _source_audit(path, state['config']['limits']['max_sites'])
        actual, identity = _admission(data)
        _require(identifier == actual and all(row[key] == value for key, value in identity.items()) and
                 data['scope'] == state['scope'], 'Audited DTA source changed after admission')
        result[identifier] = data
    return result


def _controller_arguments(state):
    runtime, limits = state['config']['runtime'], state['config']['limits']
    return {**{name: runtime[name]['path'] for name in ('qemu', 'plugin', 'flags_receipt')},
            **{name: limits[name] for name in ('max_occurrences', 'max_steps', 'max_sites', 'seconds', 'memory_mib')}}


def _collect(queue, state, sources):
    seeds, origins, changed, adopted = {}, {}, False, 0

    def add(raw_seeds, origin):
        for sha, raw in raw_seeds.items():
            _require(_id(sha) and isinstance(raw, bytes) and 0 < len(raw) <= 4096 and _sha(raw) == sha,
                     'Invalid seed returned by evidence audit')
            _require(sha not in seeds or seeds[sha] == raw, 'Conflicting content-addressed seed')
            seeds[sha] = raw
            origins.setdefault(sha, set()).add(origin)

    for identifier, data in sources.items():
        add(data['seeds'], 'DTA:' + identifier)
    arguments = _controller_arguments(state)
    for identifier in state['order']:
        row = state['jobs'][identifier]
        data = sources[row['analysis_id']]
        requests = {item['request_id']: item for item in data['requests']}
        _require(row['request_id'] in requests, 'Queue hint is no longer present in its audited source')
        request = requests[row['request_id']]
        _require(request['opposite_observed_elsewhere'] is False and request['observed_site']['vcpu'] == 0,
                 'Queue contains an ineligible source hint')
        if row['status'] == 'PENDING':
            continue
        attempt = row['attempts'][0]
        try:
            audited = dta_dse.audit_selected_corpus(directory=attempt['directory'],
                analysis=state['analyses'][row['analysis_id']]['path'], request_id=row['request_id'], **arguments)
        except (OSError, RuntimeError, ValueError, KeyError, TypeError) as exc:
            if row['status'] in ('VERIFIED', 'NONPROOF'):
                raise RuntimeError('Previously completed queue evidence no longer audits') from exc
            reason = f'{type(exc).__name__}: {exc}'[:2000]
            if row['status'] != 'BLOCKED_RECOVERY' or row.get('error') != reason:
                row.update(status='BLOCKED_RECOVERY', error=reason)
                attempt['status'] = 'BLOCKED_RECOVERY'
                changed = True
            continue
        report = audited['report']
        _require(report.get('status') == 'passed' and audited['request'] == request and
                 canonical_hash(audited['handoff']) == canonical_hash(data['handoff']),
                 'Saved controller result does not fulfil its exact audited queue request')
        identities = {name: _pin(Path(attempt['directory']) / name, 8 * 1024**2)[1]['sha256']
                      for name in ('summary.json', 'manifest.json')}
        status = 'VERIFIED' if report['dse_status'] == 'VERIFIED' else 'NONPROOF'
        _require(report['dse_status'] in ('VERIFIED', 'NOT_ESTABLISHED') and
                 set(data['seeds']) <= set(audited['seeds']) and
                 len(set(audited['seeds']) - set(data['seeds'])) <= (1 if status == 'VERIFIED' else 0),
                 'Controller promoted a nonproof result or unexpected corpus growth')
        if row['status'] in ('VERIFIED', 'NONPROOF'):
            _require(row['status'] == status and row.get('result') == identities,
                     'Completed result metadata changed after commitment')
        else:
            row.update(status=status, result=identities)
            row.pop('error', None)
            attempt['status'] = 'COMPLETED'
            changed, adopted = True, adopted + 1
        for sha, raw in audited['seeds'].items():
            _require(isinstance(raw, bytes) and _sha(raw) == sha, 'Audited controller seed bytes changed')
            if sha in data['seeds']:
                _require(data['seeds'][sha] == raw, 'Controller changed an admitted baseline seed')
        add({sha: raw for sha, raw in audited['seeds'].items() if sha not in data['seeds']}, 'DSE:' + identifier)
    return seeds, origins, changed, adopted


def _corpus_manifest(state, seeds, origins, *, revision=None):
    return {'schema': 1, 'profile': PROFILE, 'binding_id': state['binding_id'], 'scope': state['scope'],
        'revision': state['revision'] if revision is None else revision,
        'seeds': [{'sha256': sha, 'origins': sorted(origins[sha])} for sha in sorted(seeds)],
        'scope_description': 'audited_DTA_and_verified_selected_execution_corpus',
        'protected_control_channel': False, 'universal_equivalence': False, 'successor_execution_proven': False}


def _intact(queue, state):
    paths = {name: row['path'] for name, row in state['config']['runtime'].items()}
    _require(_configuration(queue, paths, state['config']['limits']) == state['config'],
             'Queue runtime or implementation changed before publication')


def _commit(queue, state, seeds, origins):
    _encoded(_corpus_manifest(state, seeds, origins, revision=state['revision'] + 1))
    _intact(queue, state)
    _save_state(queue, state)
    _publish(queue, state, seeds, origins)


def _publish(queue, state, seeds, origins):
    manifest = _corpus_manifest(state, seeds, origins)
    _encoded(manifest)
    previous = _read(queue / 'corpus.json') if (queue / 'corpus.json').exists() else None
    published = set()
    if previous is not None:
        _require(previous.get('schema') == 1 and previous.get('profile') == PROFILE and
                 previous.get('binding_id') == state['binding_id'] and
                 set(previous) == set(manifest) and
                 all(previous.get(name) == manifest[name] for name in
                     ('scope_description', 'protected_control_channel', 'universal_equivalence', 'successor_execution_proven')) and
                 type(previous.get('revision')) is int and previous['revision'] <= state['revision'] and
                 (previous.get('scope') == state['scope'] or previous.get('scope') is None and previous.get('seeds') == []),
                 'Published corpus scope or revision changed')
        for row in previous['seeds']:
            sha = row['sha256']
            _require(sha not in published and sha in seeds and set(row['origins']) <= origins[sha],
                     'Published corpus contains an unaudited seed or origin')
            published.add(sha)
        if previous['revision'] == state['revision']:
            _require(previous == manifest, 'Published corpus metadata changed at the committed revision')
    directory = _canonical(queue / 'seeds')
    _require(directory.is_dir(), 'Queue corpus directory is missing')
    present = set()
    for path in directory.iterdir():
        path, identity = _pin(path, 4096)
        _require(path.name in seeds and identity['sha256'] == path.name and path.read_bytes() == seeds[path.name],
                 'Published corpus seed is altered or unaudited')
        present.add(path.name)
    _require(published <= present, 'A previously published corpus seed is missing')
    for sha, raw in seeds.items():
        if sha not in present:
            staging = _canonical(queue / 'staging')
            staging.mkdir(mode=0o700, exist_ok=True)
            _atomic(directory / sha, raw, staging=staging)
    _intact(queue, state)
    _json(queue / 'corpus.json', manifest)
    return manifest


def _summary(queue, state, *, audited=False, stopped=None, action='status', **extra):
    if stopped is None:
        stopped = _stopped(queue, state)
    counts = {name: sum(row['status'] == name for row in state['jobs'].values()) for name in sorted(STATES)}
    starts = sum(len(row['attempts']) for row in state['jobs'].values())
    remaining = state['config']['limits']['max_total_starts'] - starts
    if counts['BLOCKED_RECOVERY']:
        status = 'QUEUE_BLOCKED'
    elif counts['PENDING'] and remaining == 0:
        status = 'QUEUE_BUDGET_EXHAUSTED'
    elif stopped and counts['PENDING']:
        status = 'QUEUE_STOPPED'
    else:
        status = 'QUEUE_PAUSED' if counts['PENDING'] or counts['RUNNING'] else 'QUEUE_COMPLETE'
    corpus = _read(queue / 'corpus.json')
    return {'schema': 1, 'profile': PROFILE, 'status': status, 'action': action, 'queue': str(queue),
        'scope': 'audited_selected_file_branch_requests_with_persistent_scheduling',
        'proof_scope': 'per_completed_selected_execution',
        'counts': counts, 'started_attempts': starts, 'remaining_start_budget': remaining,
        'corpus_seed_count': len(corpus['seeds']), 'seeds': str(queue / 'seeds'),
        'corpus_manifest': str(queue / 'corpus.json'), 'evidence_audited': audited,
        'dse_status': 'VERIFIED' if audited and counts['VERIFIED'] else 'NOT_ESTABLISHED',
        'afl_campaign_executed': False, 'protected_control_channel': False,
        'universal_equivalence': False, 'successor_execution_proven': False, **extra}


def create_queue(*, queue, qemu, plugin, flags_receipt, max_total_starts=128, max_queue_jobs=512,
                 max_occurrences=8, max_steps=128, max_sites=256, seconds=30, memory_mib=1024):
    queue = _canonical(queue)
    _require(not queue.exists(), 'Queue output must be new')
    limits = _limits(max_total_starts=max_total_starts, max_queue_jobs=max_queue_jobs,
        max_occurrences=max_occurrences, max_steps=max_steps, max_sites=max_sites, seconds=seconds, memory_mib=memory_mib)
    paths = {'qemu': qemu, 'plugin': plugin, 'runtime_manifest': str(plugin) + '.runtime.json', 'flags_receipt': flags_receipt}
    config = _configuration(queue, paths, limits)
    queue.mkdir(parents=True, mode=0o700)
    with _lock(queue):
        (queue / 'seeds').mkdir(mode=0o700)
        (queue / 'attempts').mkdir(mode=0o700)
        state = {'schema': 1, 'revision': 0, 'config': config, 'binding_id': _binding(config),
                 'scope': None, 'analyses': {}, 'jobs': {}, 'order': [], 'acknowledged_stop_nonce': None}
        _commit(queue, state, {}, {})
        return _summary(queue, state, audited=True, action='created')


def enqueue_analyses(*, queue, analyses):
    _require(isinstance(analyses, (list, tuple)) and 1 <= len(analyses) <= 64,
             'Enqueue between one and 64 completed analyses')
    with _lock(queue) as queue:
        state = _load(queue)
        sources = _sources(queue, state)
        admitted, duplicates = 0, 0
        for analysis in analyses:
            path = _canonical(analysis)
            _require(not path.is_relative_to(queue) and not queue.is_relative_to(path), 'Queue overlaps source analysis')
            data = _source_audit(path, state['config']['limits']['max_sites'])
            identifier, identity = _admission(data)
            _require(data['handoff']['analysis'] == str(path), 'Audited analysis path differs')
            _require(state['scope'] is None or data['scope'] == state['scope'],
                     'Analysis target, launch or environment is incompatible with this queue')
            state['scope'] = data['scope']
            record = dict(identity, path=str(path))
            _require(identifier not in state['analyses'] or state['analyses'][identifier] == record,
                     'Analysis identity conflicts with an existing source')
            _require(identifier in state['analyses'] or len(state['analyses']) < MAX_ANALYSES,
                     'Queue source-analysis budget exceeded')
            state['analyses'][identifier] = record
            sources[identifier] = data
            for request in data['requests']:
                if request['opposite_observed_elsewhere'] is not False or request['observed_site']['vcpu'] != 0:
                    continue
                body = {'analysis_id': identifier, 'request_id': request['request_id'],
                        'binding_id': state['binding_id'], 'scope_id': canonical_hash(state['scope'])}
                job = canonical_hash(body)
                if job in state['jobs']:
                    duplicates += 1
                    continue
                _require(len(state['jobs']) < state['config']['limits']['max_queue_jobs'], 'Queue job budget exceeded')
                state['jobs'][job] = dict(body, status='PENDING', attempts=[], result=None)
                state['order'].append(job)
                admitted += 1
        seeds, origins, changed, recovered = _collect(queue, state, sources)
        _commit(queue, state, seeds, origins)
        return _summary(queue, state, audited=True, action='enqueued',
                        admitted_jobs=admitted, duplicate_jobs=duplicates, adopted_completed_attempts=recovered)


def _audit_locked(queue, state):
    sources = _sources(queue, state)
    seeds, origins, changed, adopted = _collect(queue, state, sources)
    if changed:
        _commit(queue, state, seeds, origins)
    else:
        _publish(queue, state, seeds, origins)
    return sources, adopted


def audit_queue(*, queue):
    with _lock(queue) as queue:
        state = _load(queue)
        _, adopted = _audit_locked(queue, state)
        return _summary(queue, state, audited=True, action='audited', adopted_completed_attempts=adopted)


def queue_status(*, queue):
    queue = _canonical(queue)
    return _summary(queue, _load(queue, verify=False), action='snapshot')


def request_stop(*, queue):
    queue = _canonical(queue)
    state = _load(queue, verify=False)
    _json(queue / 'stop.json', {'schema': 1, 'binding_id': state['binding_id'], 'stop': True, 'nonce': uuid4().hex})
    return _summary(queue, state, stopped=True, action='stop_requested')


def _stop_record(queue, state):
    path = queue / 'stop.json'
    if not path.exists():
        return None
    record = _read(path)
    _require(set(record) == {'schema', 'binding_id', 'stop', 'nonce'} and record.get('schema') == 1 and
             record.get('binding_id') == state['binding_id'] and record.get('stop') is True and
             isinstance(record.get('nonce'), str) and re.fullmatch('[0-9a-f]{32}', record['nonce']) is not None,
             'Stop request is invalid')
    return record


def _stopped(queue, state):
    record = _stop_record(queue, state)
    return record is not None and record['nonce'] != state.get('acknowledged_stop_nonce')


def run_queue(*, queue, max_jobs=1, wall_seconds=900):
    _limit(max_jobs, 4096, 'jobs per queue invocation')
    _limit(wall_seconds, 172800, 'soft between-job wall time')
    with _lock(queue) as queue:
        start = time.monotonic()
        state = _load(queue)
        previous_stop = _stop_record(queue, state)
        if previous_stop is not None and previous_stop['nonce'] != state.get('acknowledged_stop_nonce'):
            state['acknowledged_stop_nonce'] = previous_stop['nonce']
            _save_state(queue, state)
        sources, adopted = _audit_locked(queue, state)
        launched, stopped = 0, False
        for identifier in state['order']:
            if any(row['status'] == 'BLOCKED_RECOVERY' for row in state['jobs'].values()):
                break
            if _stopped(queue, state):
                stopped = True
                break
            row = state['jobs'][identifier]
            if row['status'] != 'PENDING':
                continue
            starts = sum(len(item['attempts']) for item in state['jobs'].values())
            if launched == max_jobs or starts == state['config']['limits']['max_total_starts'] or time.monotonic() - start >= wall_seconds:
                break
            directory = queue / 'attempts' / identifier / '0001'
            _canonical(directory)
            _require(not directory.exists(), 'Unrecorded attempt output already exists')
            directory.parent.mkdir(parents=True, exist_ok=True)
            row['status'] = 'RUNNING'
            row['attempts'].append({'number': 1, 'directory': str(directory), 'status': 'RUNNING'})
            _save_state(queue, state)
            launched += 1
            try:
                returned = dta_dse.extend_corpus(analysis=state['analyses'][row['analysis_id']]['path'],
                    out=directory, max_jobs=1, request_ids=[row['request_id']], **_controller_arguments(state))
                _require(canonical_hash(returned) == canonical_hash(_read(directory / 'summary.json')),
                         'Controller return differs from its saved result')
                sources = _sources(queue, state)
                seeds, origins, changed, recovered = _collect(queue, state, sources)
                adopted += recovered
                _require(row['status'] in ('VERIFIED', 'NONPROOF'), 'Fresh attempt did not pass its saved evidence audit')
                _load(queue)  # Recheck source code/runtime and the committed pre-execution journal.
                _commit(queue, state, seeds, origins)
            except BaseException as exc:
                if row['status'] in ('RUNNING', 'BLOCKED_RECOVERY'):
                    row['status'] = 'BLOCKED_RECOVERY'
                    row['attempts'][0]['status'] = 'BLOCKED_RECOVERY'
                    row['error'] = f'{type(exc).__name__}: {exc}'[:2000]
                    _save_state(queue, state)
                raise
        _load(queue)
        return _summary(queue, state, audited=True, stopped=stopped or _stopped(queue, state), action='run',
                        started_this_run=launched, adopted_completed_attempts=adopted,
                        soft_wall_seconds=wall_seconds, wall_seconds=time.monotonic() - start)
