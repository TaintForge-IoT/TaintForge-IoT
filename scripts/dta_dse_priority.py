"""Opt-in static diversity scheduling for one newly created DTA/DSE queue.

Only initial queue order changes. The original admission, execution, selected
proof audits, limits and publication functions remain responsible for evidence.
The policy journal is a consistency record, not a protected authority or proof.
"""
from __future__ import annotations

import copy
from collections import deque
import hashlib
import json
from pathlib import Path
import threading

from taintforge_env import dta_dse_queue as queue_module
from taintforge_env.dta_corpus import _canonical, _pin, _require
from taintforge_env.elf_runtime import canonical_hash


PROFILE = 'static-diverse-dta-dse-priority-session-v1'
POLICY = 'globally-unseen-goals-first-source-round-robin-v1'
COMMITTED = 'COMMITTED_STATIC_DTA_DSE_PRIORITY_PLAN'
AUDITED = 'AUDITED_STATIC_DTA_DSE_PRIORITY_PLAN'
MAX_PLAN_BYTES = 8 * 1024**2
_ACTIVE_SESSION = None
_SCOPE = dict(heuristic_only=True, proof_scope_promoted=False,
    historical_instruction_identity_proven=False, protected_control_channel=False,
    universal_equivalence=False, successor_execution_proven=False,
    exact_request_identities_preserved=True, all_jobs_retained=True,
    existing_queue_resumed=False, adaptive_feedback_used=False)


def _hash_state(state):
    return canonical_hash({key: value for key, value in state.items() if key != 'state_sha256'})


def _self_identity():
    return _pin(Path(__file__).resolve(), 4 * 1024**2)[1]


def _fresh(state):
    _require(state.get('acknowledged_stop_nonce') is None and
        all(row.get('status') == 'PENDING' and row.get('attempts') == [] and
            row.get('result') is None and 'error' not in row for row in state['jobs'].values()),
        'Priority scheduling requires an unstarted queue without stop acknowledgments')


def _site(request):
    site = request['observed_site']
    _require(isinstance(site, dict) and type(site.get('vcpu')) is int and 0 <= site['vcpu'] < 2**32 and
        type(site.get('pc')) is int and 0 <= site['pc'] < 2**64 and
        type(site.get('occurrence')) is int and 1 <= site['occurrence'] < 2**64 and
        type(site.get('seq')) is int and 0 <= site['seq'] < 2**64 and
        site.get('outcome') in ('taken', 'not-taken') and
        request.get('desired_outcome') == ('not-taken' if site['outcome'] == 'taken' else 'taken'),
        'Priority source has an invalid diagnostic site or desired outcome')
    return site


def plan_priority(state, sources):
    """Return a deterministic full permutation from already-audited sources.

``state['order']`` is the original FIFO admission order. Status and attempt
fields do not affect ranking. A goal is a diagnostic heuristic, never an exact
instruction, path, generation or proof identity. No request is removed.
"""
    order, jobs = state['order'], state['jobs']
    _require(isinstance(order, list) and isinstance(jobs, dict) and len(order) <= 4096 and
        len(order) == len(set(order)) and set(order) == set(jobs) and
        isinstance(sources, dict) and set(sources) == set(state['analyses']) and len(sources) <= 64,
        'Priority planner received an invalid queue or source inventory')
    observed, requests = set(), {}
    for analysis_id, data in sources.items():
        _require(queue_module._id(analysis_id) and isinstance(data.get('requests'), list) and
            len(data['requests']) <= 4096, 'Invalid priority source request inventory')
        by_id = {}
        for request in data['requests']:
            identifier = request.get('request_id')
            _require(queue_module._id(identifier) and identifier not in by_id and
                identifier == canonical_hash({k: v for k, v in request.items() if k != 'request_id'}),
                'Priority request identity is invalid or duplicated')
            site = _site(request)
            observed.add((site['vcpu'], site['pc'], site['outcome']))
            by_id[identifier] = request
        requests[analysis_id] = by_id
    source_order, rows = [], []
    for index, identifier in enumerate(order):
        item = jobs[identifier]
        _require(queue_module._id(identifier) and item['analysis_id'] in sources and
            item['request_id'] in requests[item['analysis_id']], 'Priority job has no audited source request')
        body = {key: item[key] for key in ('analysis_id', 'request_id', 'binding_id', 'scope_id')}
        _require(identifier == canonical_hash(body) and body['binding_id'] == state['binding_id'] and
            body['scope_id'] == (canonical_hash(state['scope']) if state['scope'] is not None else None),
            'Priority job identity or queue binding changed')
        request = requests[item['analysis_id']][item['request_id']]
        site = _site(request)
        _require(request.get('opposite_observed_elsewhere') is False and site['vcpu'] == 0,
            'Priority planner cannot admit an ineligible queue request')
        if item['analysis_id'] not in source_order:
            source_order.append(item['analysis_id'])
        goal = (site['vcpu'], site['pc'], request['desired_outcome'])
        rows.append(dict(job_id=identifier, analysis_id=item['analysis_id'], request_id=item['request_id'],
            goal=list(goal), tier=int(goal in observed), original_index=index,
            source_index=source_order.index(item['analysis_id']),
            diagnostic_occurrence=site['occurrence'], diagnostic_seq=site['seq']))
    ranked, next_source = [], 0
    for tier in (0, 1):
        # Preserve first-admitted goal order, but choose different sources in a
        # round-robin walk. Every remaining goal gets one representative before
        # another round may choose a duplicate goal.
        buckets = {}
        for row in rows:
            if row['tier'] == tier:
                buckets.setdefault(tuple(row['goal']), []).append(row)
        round_number = 0
        while buckets:
            pending = set(buckets)
            choices_by_source = {index: deque(goal for goal, items in buckets.items()
                if any(row['source_index'] == index for row in items))
                for index in range(len(source_order))}
            while pending:
                advanced = False
                for offset in range(len(source_order)):
                    source_index = (next_source + offset) % len(source_order)
                    candidates = choices_by_source[source_index]
                    while candidates and candidates[0] not in pending:
                        candidates.popleft()
                    if not candidates:
                        continue
                    goal = candidates.popleft()
                    choices = [row for row in buckets[goal] if row['source_index'] == source_index]
                    selected = min(choices, key=lambda row: (row['diagnostic_occurrence'],
                        row['diagnostic_seq'], row['original_index']))
                    result = dict(selected, goal_round=round_number, rank=len(ranked) + 1)
                    ranked.append(result)
                    buckets[goal].remove(selected)
                    if not buckets[goal]:
                        del buckets[goal]
                    pending.remove(goal)
                    next_source = (source_index + 1) % len(source_order)
                    advanced = True
                    break
                _require(advanced, 'Priority source round made no progress')
            round_number += 1
    planned_order = [row['job_id'] for row in ranked]
    _require(len(planned_order) == len(order) and set(planned_order) == set(order),
        'Priority plan is not a full job permutation')
    return dict(policy=POLICY, order=planned_order, rows=ranked,
        observed_goals=[list(goal) for goal in sorted(observed)],
        source_order=source_order)


def _encode(value):
    raw = (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + '\n').encode()
    _require(len(raw) <= MAX_PLAN_BYTES, 'Priority plan metadata byte budget exceeded')
    return raw


def _read_plan(path):
    path, identity = _pin(path, MAX_PLAN_BYTES)
    raw = path.read_bytes()
    _require(hashlib.sha256(raw).hexdigest() == identity['sha256'], 'Priority plan changed during read')

    def pairs(items):
        result = {}
        for key, value in items:
            _require(key not in result, 'Duplicate JSON field in priority plan')
            result[key] = value
        return result

    def nonfinite(value):
        raise ValueError('Non-finite JSON number in priority plan: ' + value)

    value = json.loads(raw, object_pairs_hook=pairs, parse_constant=nonfinite)
    _require(isinstance(value, dict) and value.get('plan_sha256') ==
        canonical_hash({k: v for k, v in value.items() if k != 'plan_sha256'}),
        'Priority plan integrity failed')
    _require(_pin(path, MAX_PLAN_BYTES)[1] == identity, 'Priority plan changed during read')
    return value, identity


def _write_plan(path, value, *, previous=None):
    _require(not path.exists() if previous is None else _pin(path, MAX_PLAN_BYTES)[1] == previous,
        'Priority plan destination appeared or changed')
    value['plan_sha256'] = canonical_hash({k: v for k, v in value.items() if k != 'plan_sha256'})
    raw = _encode(value)
    queue_module._atomic(path, raw)
    parsed, identity = _read_plan(path)
    _require(parsed == value, 'Priority plan publication changed its contents')
    return identity


def _admission_order(state, sources, paths):
    _require(isinstance(paths, list) and 1 <= len(paths) <= 64 and len(paths) == len(set(paths)),
        'Priority plan analysis admission paths are invalid or duplicated')
    by_path = {row['path']: identifier for identifier, row in state['analyses'].items()}
    _require(len(by_path) == len(state['analyses']) and set(paths) == set(by_path),
        'Priority plan source admission inventory changed')
    order = []
    for path in paths:
        analysis_id = by_path[path]
        for request in sources[analysis_id]['requests']:
            if request['opposite_observed_elsewhere'] is not False or request['observed_site']['vcpu'] != 0:
                continue
            body = dict(analysis_id=analysis_id, request_id=request['request_id'],
                binding_id=state['binding_id'], scope_id=canonical_hash(state['scope']))
            order.append(canonical_hash(body))
    _require(len(order) == len(set(order)) and set(order) == set(state['jobs']),
        'Priority original admission order does not cover the exact queue jobs')
    return order


class PrioritySession:
    """Install one explicit policy for exactly one fresh queue and admission."""

    def __init__(self, *, queue, plan):
        self.queue, self.plan = _canonical(queue), _canonical(plan)
        _require(not self.plan.is_relative_to(self.queue) and not self.queue.is_relative_to(self.plan),
            'Priority policy journal must be outside its queue')
        self.active = self._used = self._created = self._admitted = False
        self._admission_started = False
        self._record = None

    def __enter__(self):
        global _ACTIVE_SESSION
        _require(_ACTIVE_SESSION is None and not self._used and not self.active and
            not self.queue.exists() and not self.plan.exists(),
            'Priority session requires a new queue, a new plan, and no active session')
        self._thread = threading.get_ident()
        self._identity = _self_identity()
        self._original_create, self._original_enqueue = queue_module.create_queue, queue_module.enqueue_analyses
        self._installed_create, self._installed_enqueue = self._create, self._enqueue
        self._original_codes = (getattr(self._original_create, '__code__', None),
            getattr(self._original_enqueue, '__code__', None))
        _require(all(self._original_codes), 'Priority scheduling requires original Python queue entry points')
        queue_module.create_queue, queue_module.enqueue_analyses = self._installed_create, self._installed_enqueue
        self.active = self._used = True
        _ACTIVE_SESSION = self
        return self

    def _check(self):
        _require(self.active and _ACTIVE_SESSION is self and threading.get_ident() == self._thread,
            'Priority session is inactive or used by a different control thread')
        _require(queue_module.create_queue is self._installed_create and
            queue_module.enqueue_analyses is self._installed_enqueue and
            (self._original_create.__code__, self._original_enqueue.__code__) == self._original_codes,
            'Priority queue entry point bindings changed')
        _require(_self_identity() == self._identity, 'Priority scheduling implementation changed')

    def _create(self, *args, **kwargs):
        self._check()
        _require(not args and _canonical(kwargs.get('queue')) == self.queue and not self._created and
            not self.queue.exists(), 'Priority context can create only its own new queue once')
        returned = self._original_create(**kwargs)
        with queue_module._lock(self.queue):
            state = queue_module._load(self.queue)
            _require(not state['jobs'] and not state['analyses'] and not state['order'] and
                state['scope'] is None and state['revision'] == 1,
                'New priority queue is not empty')
            _fresh(state)
            self._created_state = copy.deepcopy(state)
        self._created = True
        self._check()
        return returned

    def _enqueue(self, *args, **kwargs):
        self._check()
        _require(not args and _canonical(kwargs.get('queue')) == self.queue and self._created and
            not self._admission_started and not self._admitted,
            'Priority context accepts exactly one admission into its own new queue')
        analyses = kwargs.get('analyses')
        _require(isinstance(analyses, (list, tuple)) and 1 <= len(analyses) <= 64,
            'Priority context requires one bounded analysis admission')
        paths = [str(_canonical(path)) for path in analyses]
        _require(len(paths) == len(set(paths)), 'Priority source admission paths must be distinct')
        _require(all(not self.plan.is_relative_to(Path(path)) and not Path(path).is_relative_to(self.plan)
            for path in paths), 'Priority plan overlaps an admitted source analysis')
        with queue_module._lock(self.queue):
            _require(queue_module._load(self.queue) == self._created_state,
                'Priority queue changed before its initial admission')
        self._admission_started = True
        returned = self._original_enqueue(**kwargs)
        self._check()
        with queue_module._lock(self.queue):
            state = queue_module._load(self.queue)
            _fresh(state)
            _require(state['revision'] == 2 and state['binding_id'] == self._created_state['binding_id'],
                'Priority queue was changed outside its single initial admission')
            sources = queue_module._sources(self.queue, state)
            seeds, origins, changed, adopted = queue_module._collect(self.queue, state, sources)
            _require(not changed and adopted == 0 and state['order'] == _admission_order(state, sources, paths),
                'Priority admission needs recovery or differs from its original FIFO order')
            before = copy.deepcopy(state)
            schedule = plan_priority(before, sources)
            record = dict(schema=1, profile=PROFILE, status='PREPARED_STATIC_DTA_DSE_PRIORITY_PLAN',
                policy=POLICY, queue=str(self.queue), plan=str(self.plan),
                implementation=self._identity, created_state_sha256=self._created_state['state_sha256'],
                binding_id=state['binding_id'], before_state=before, source_identities=copy.deepcopy(state['analyses']),
                analyses_order=paths, schedule=schedule, committed_state_sha256=None,
                committed_revision=None, **_SCOPE)
            self.plan.parent.mkdir(parents=True, exist_ok=True)
            prepared_identity = _write_plan(self.plan, record)
            self._check()
            state['order'] = list(schedule['order'])
            queue_module._commit(self.queue, state, seeds, origins)
            committed = queue_module._load(self.queue)
            expected = copy.deepcopy(before)
            expected.update(order=list(schedule['order']), revision=before['revision'] + 1)
            expected['state_sha256'] = _hash_state(expected)
            _require(committed == expected, 'Priority publication changed more than initial order and revision')
            self._check()
            record.update(status=COMMITTED, committed_state_sha256=committed['state_sha256'],
                committed_revision=committed['revision'])
            _write_plan(self.plan, record, previous=prepared_identity)
            self._record = copy.deepcopy(record)
            self._admitted = True
            return queue_module._summary(self.queue, committed, audited=True, action='enqueued',
                admitted_jobs=returned['admitted_jobs'], duplicate_jobs=returned['duplicate_jobs'],
                adopted_completed_attempts=returned['adopted_completed_attempts'])

    def summary(self):
        return dict(profile=PROFILE, policy=POLICY, active=self.active,
            created=self._created, admitted=self._admitted, queue=str(self.queue), plan=str(self.plan),
            job_count=len(self._record['schedule']['order']) if self._record is not None else 0,
            **_SCOPE)

    def __exit__(self, kind, exception, traceback):
        global _ACTIVE_SESSION
        changed = queue_module.create_queue is not self._installed_create or \
            queue_module.enqueue_analyses is not self._installed_enqueue
        queue_module.create_queue, queue_module.enqueue_analyses = self._original_create, self._original_enqueue
        self.active = False
        _ACTIVE_SESSION = None
        if kind is None:
            _require(not changed and self._admitted, 'Priority session ended without its complete initial plan')
            _require(_self_identity() == self._identity, 'Priority implementation changed before context close')
        return False


def audit_priority_plan(*, queue, plan):
    """Read-only consistency audit after the priority context has closed.

Recompute admission and ranking from freshly audited DTA sources; re-audit all
completed exact selected requests using unchanged core functions. This does not
prove instruction chronology or independently rerun a native SMT solver.
"""
    _require(_ACTIVE_SESSION is None, 'Close the priority context before its final plan audit')
    queue, plan = _canonical(queue), _canonical(plan)
    _require(not plan.is_relative_to(queue) and not queue.is_relative_to(plan), 'Priority plan overlaps its queue')
    record, plan_identity = _read_plan(plan)
    _require(record.get('schema') == 1 and record.get('profile') == PROFILE and
        record.get('status') == COMMITTED and record.get('policy') == POLICY and
        record.get('queue') == str(queue) and record.get('plan') == str(plan) and
        record.get('implementation') == _self_identity() and
        all(record.get(key) == value for key, value in _SCOPE.items()),
        'Priority plan is incomplete, changed, or has promoted its scope')
    # Do not allow _lock to create a missing file during a read-only audit.
    _pin(queue / 'controller.lock', 1024)
    with queue_module._lock(queue):
        state = queue_module._load(queue)
        state_identity = _pin(queue / 'state.json', queue_module.MAX_METADATA)[1]
        _require(all(item['status'] in ('PENDING', 'VERIFIED', 'NONPROOF') for item in state['jobs'].values()),
            'Priority audit requires completed or pending jobs, without recovery')
        sources = queue_module._sources(queue, state)
        seeds, origins, changed, adopted = queue_module._collect(queue, state, sources)
        _require(not changed and adopted == 0, 'Priority queue requires recovery before plan auditing')
        before = record['before_state']
        _fresh(before)
        _require(before.get('state_sha256') == _hash_state(before) and before.get('revision') == 2 and
            record.get('binding_id') == state['binding_id'] == before['binding_id'] and
            record.get('source_identities') == before['analyses'] == state['analyses'] and
            record.get('committed_revision') == 3,
            'Priority initial source, revision, or state identity changed')
        normalized = copy.deepcopy(state)
        normalized.update(order=before['order'], revision=before['revision'], acknowledged_stop_nonce=None)
        normalized['jobs'] = {identifier: dict(
            {key: row[key] for key in ('analysis_id', 'request_id', 'binding_id', 'scope_id')},
            status='PENDING', attempts=[], result=None) for identifier, row in state['jobs'].items()}
        normalized['state_sha256'] = _hash_state(normalized)
        _require(normalized == before and before['order'] ==
            _admission_order(before, sources, record['analyses_order']),
            'Priority initial queue differs from the original admitted jobs')
        created = copy.deepcopy(before)
        created.update(revision=1, scope=None, analyses={}, jobs={}, order=[])
        created['state_sha256'] = _hash_state(created)
        _require(record.get('created_state_sha256') == created['state_sha256'],
            'Priority plan did not begin with this exact empty queue')
        schedule = plan_priority(before, sources)
        _require(record['schedule'] == schedule and state['order'] == schedule['order'],
            'Priority order or ranking differs from its audited deterministic policy')
        committed = copy.deepcopy(before)
        committed.update(order=schedule['order'], revision=3)
        committed['state_sha256'] = _hash_state(committed)
        _require(record.get('committed_state_sha256') == committed['state_sha256'],
            'Priority committed initial journal identity changed')
        executed = [identifier for identifier in state['order'] if state['jobs'][identifier]['attempts']]
        _require(executed == state['order'][:len(executed)] and state['revision'] >= 3 + 2 * len(executed),
            'Priority execution is not a prefix of its complete initial plan')
        corpus = queue_module._read(queue / 'corpus.json')
        _require(corpus == queue_module._corpus_manifest(state, seeds, origins) and
            sorted(path.name for path in (queue / 'seeds').iterdir()) == sorted(seeds),
            'Priority queue corpus differs from its original exact request audits')
        for name, raw in seeds.items():
            path, identity = _pin(queue / 'seeds' / name, 4096)
            _require(identity['sha256'] == name and path.read_bytes() == raw, 'Priority queue seed changed')
        _require(queue_module._load(queue) == state and
            _pin(queue / 'state.json', queue_module.MAX_METADATA)[1] == state_identity,
            'Priority queue journal changed during its final audit')
    _require(_pin(plan, MAX_PLAN_BYTES)[1] == plan_identity and record['implementation'] == _self_identity(),
        'Priority plan or implementation changed during its final audit')
    goals = {tuple(row['goal']) for row in schedule['rows']}
    unseen = {tuple(row['goal']) for row in schedule['rows'] if row['tier'] == 0}
    return dict(schema=1, status=AUDITED, profile=PROFILE, policy=POLICY, queue=str(queue), plan=str(plan),
        job_count=len(schedule['order']), started_attempts=len(executed), executed_job_ids=executed,
        goal_count=len(goals), globally_unseen_goal_count=len(unseen),
        plan_sha256=plan_identity['sha256'], readonly_queue_audit=True,
        independently_rerun_solver=False, historical_instruction_chronology_proven=False, **_SCOPE)
