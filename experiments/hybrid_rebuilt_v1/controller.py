"""Bounded live AFL -> audited DSE -> AFL -> DTA loop for recovered i386 ELFs.

DTA/DSE workers use separate fresh isolated executions. The AFL process stays
alive while its custom-mutator callback waits for the audited DSE seed. The
controller never attributes a child failure to the target without evidence.
"""
from __future__ import annotations

import hmac
import json
import os
from pathlib import Path
import secrets
import socket
import struct
import subprocess
import threading
import time

from .receipts import read_delivery, verify_case_target
from .telemetry import audit_hook_trace
from .policy import (MAX_INPUT, AdaptiveBranchSchedule, BranchFocusedSchedule, CoveragePlateau, checked_input,
                     checked_mask, digest, diff_offsets, eligible_requests,
                     mask_bits, mask_from_requests, masked_mutation, require)
from experiments.hybrid_prefix_v1.runtime import save, sha

REQUEST = struct.Struct('!4sII')
RESPONSE = struct.Struct('!4sIIII')
INPUT_PATH = '/etc/dta-input'


def receive(stream, length):
    data = bytearray()
    while len(data) < length:
        piece = stream.recv(length - len(data))
        if not piece:
            raise ConnectionError('Live hybrid peer disconnected')
        data.extend(piece)
    return bytes(data)


def analyze_seed(root, *, binary, qemu, plugin, seed, max_candidates=16):
    """Run real fresh DTA; fail closed if target/seed/handoff identities diverge."""
    from taintforge_env.dta_analysis import analyze_file
    from taintforge_env.dta_handoff import export_handoff
    root = Path(root)
    root.mkdir(parents=True, exist_ok=False)
    seed = checked_input(seed)
    target = sha(binary)
    seed_path = root / 'seed'
    seed_path.write_bytes(seed)
    directory = root / 'analysis'
    result = analyze_file(binary=binary, qemu=qemu, plugin=plugin, seed=seed_path,
        input_path=INPUT_PATH, out=directory, max_candidates=max_candidates,
        seconds=15, memory_mib=1024, wall_seconds=900)
    require(result.get('status') == 'passed' and
            result['inputs']['binary']['sha256'] == target and
            result['inputs']['seed']['sha256'] == digest(seed), 'Initial DTA source binding failed')
    handoff = export_handoff(analysis=directory, out=root / 'handoff')
    require(handoff.get('target_sha256') == target and
            handoff.get('input_path') == INPUT_PATH and not handoff.get('argv'),
            'DTA handoff target/input/argv does not match the rebuilt AFL backend')
    requests = json.loads((root / 'handoff/recapture-requests.json').read_bytes())['requests']
    mask = mask_from_requests(requests)
    report = {'root': str(root), 'directory': str(directory), 'target_sha256': target,
              'source_seed_sha256': digest(seed), 'mask': list(mask), 'requests': requests,
              'DTA_summary_sha256': sha(directory / 'summary.json'),
              'handoff_manifest_sha256': sha(root / 'handoff/manifest.json')}
    save(root / 'hybrid-dta.json', report)
    return report


def solve_request(root, *, analysis, request, qemu, plugin, flags_receipt):
    """One independently audited DSE request, never a guessed mutation."""
    from taintforge_env.dta_dse import extend_corpus, audit_selected_corpus
    root = Path(root)
    seq = request['observed_site']['seq']
    require(type(seq) is int and 0 < seq <= 1024, 'Unbounded DSE prefix')
    steps = max(128, min(1024, 1 << (seq + 15).bit_length()))
    output = extend_corpus(analysis=Path(analysis['directory']), qemu=qemu,
        plugin=plugin, flags_receipt=flags_receipt, out=root,
        max_jobs=1, max_occurrences=1, max_steps=steps, seconds=30,
        memory_mib=1024, request_ids=[request['request_id']])
    # Distinguish solver/replay failure, publication and independent re-audit.
    # Every failed phase remains FAILED; none is counted as a live seed.
    if output.get('dse_status') != 'VERIFIED':
        job_states = [job.get('status') for job in output.get('jobs', [])]
        raise RuntimeError(f'DSE_NO_VERIFIED_SEED: dse_status={output.get("dse_status")}; jobs={job_states}')
    if output.get('new_seed_count') != 1:
        raise RuntimeError('DSE_NEW_SEED_COUNT_MISMATCH: expected exactly one verified new seed')
    try:
        checked = audit_selected_corpus(directory=root, analysis=Path(analysis['directory']),
            qemu=qemu, plugin=plugin, flags_receipt=flags_receipt,
            request_id=request['request_id'], max_occurrences=1,
            max_steps=steps, seconds=30, memory_mib=1024)
    except (OSError, ValueError, RuntimeError, KeyError, TypeError) as exc:
        raise RuntimeError(f'DSE_FRESH_AUDIT_FAILED: {type(exc).__name__}: {exc}') from exc
    require(checked['report'] == output, 'DSE_FRESH_AUDIT_REPORT_MISMATCH')
    require(checked['manifest']['target_sha256'] == analysis['target_sha256'],
            'DSE_FRESH_AUDIT_TARGET_MISMATCH')
    verified = [job for job in output['jobs'] if job['status'] == 'VERIFIED']
    require(len(verified) == 1, 'DSE verification inventory is ambiguous')
    identity = verified[0]['candidate_sha256']
    candidate = checked_input(checked['seeds'][identity])
    require(digest(candidate) == identity, 'DSE seed hash mismatch')
    return candidate, {'status': 'VERIFIED', 'request_id': request['request_id'],
        'candidate_sha256': identity, 'steps': steps,
        'summary_sha256': sha(root / 'summary.json'),
        'target_sha256': analysis['target_sha256'], 'replayed_and_reaudited': True}


class LiveRebuiltController:
    """One socket-connected, budgeted controller with verifiable case receipts.

    ``server`` is the existing isolated ``afl_rebuilt.Server``. Its ``count``
    advances only after a case receipt is written; ``delivered`` advances only
    after the coverage was actually handed to AFL. This avoids inventing an
    AFL execution when custom-mutator output is ignored.
    """
    def __init__(self, root, *, initial, binary, qemu, plugin, flags_receipt,
                 max_input=MAX_INPUT, stall_cases=16, max_dse_jobs=2,
                 solve_worker=solve_request, analyze_worker=analyze_seed,
                 mixed_mutations=False, live_dse=True, custom_fuzz_count=None):
        self.root = Path(root)
        self.initial = initial
        self.current_analysis = initial
        self.target_sha256 = sha(binary)
        require(self.target_sha256 == initial['target_sha256'], 'Changed target identity')
        self.binary, self.qemu, self.plugin, self.flags_receipt = binary, qemu, plugin, flags_receipt
        require(type(max_input) is int and 1 <= max_input <= MAX_INPUT, 'Invalid input limit')
        require(type(mixed_mutations) is bool and type(live_dse) is bool, 'Invalid hybrid profile')
        require(type(max_dse_jobs) is int and
                (1 <= max_dse_jobs <= 8 if live_dse else max_dse_jobs == 0),
                'Invalid DSE job bound')
        self.mixed, self.live_dse = mixed_mutations, live_dse
        if custom_fuzz_count is None:
            custom_fuzz_count = 8 if mixed_mutations else 16
        require(type(custom_fuzz_count) is int and 1 <= custom_fuzz_count <= 16,
                'Invalid custom fuzz count')
        self.custom_fuzz_count = custom_fuzz_count
        self.max_input, self.max_dse_jobs = max_input, max_dse_jobs
        self.mask = checked_mask(initial['mask'], max_input)
        require(self.mask, 'No DTA-observed byte offsets: choose AFL-only mode')
        self.schedule_type = AdaptiveBranchSchedule if mixed_mutations else BranchFocusedSchedule
        self.mask_schedule = self.schedule_type(self.mask, initial['requests'], limit=max_input)
        self.focus_mask_revisions = [[list(x) for x in self.mask_schedule.focus]]
        self.skipped_mutations = 0
        self.total_focused_mutations = 0
        self.total_fallback_mutations = 0
        self.adaptive_feedback_history = []
        self.unattributed_deliveries = 0
        self.matched_dse_deliveries = 0
        self.matched_quarantined_dse_deliveries = 0
        self.dse_offers = {}
        self.plateau_edge = None
        self.dse_callback_lags = []
        self.plateau = CoveragePlateau(stall_cases)
        self.solve_worker, self.analyze_worker = solve_worker, analyze_worker
        self.token = secrets.token_hex(32)
        self.socket_path = self.root / 'hybrid.sock'
        require(len(os.fsencode(self.socket_path)) < 108, 'Hybrid socket path too long')
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.listener.bind(str(self.socket_path))
        os.chmod(self.socket_path, 0o600)
        self.listener.listen(1)
        self.listener.settimeout(.2)
        self.connection = None
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self.serve, name='tf-rebuilt-hybrid', daemon=True)
        self.server = None
        self.processed = self.generated = self.delivered_mutations = 0
        self.pending = None
        self.attempted = set()
        self.dse_jobs = []
        self.dse_executions = []
        self.mask_revisions = [list(self.mask)]
        self.trigger_count = 0
        self.refresh_count = 0
        self.error = None
        self.sequence = 0
        self.request_sequence = 0
        self._receipt_lock = threading.Lock()
        self._deliveries = []
        self._attempt_ids = set()
        self._receipt_error = None
        self._events_lock = threading.Lock()
        self.event('controller_created', target_sha256=self.target_sha256,
                   max_input=max_input, stall_cases=stall_cases, max_dse_jobs=max_dse_jobs,
                   mixed_mutations=mixed_mutations, live_dse=live_dse,
                   custom_fuzz_count=custom_fuzz_count)

    def event(self, name, **fields):
        with self._events_lock:
            self.sequence += 1
            event = {'seq': self.sequence, 'monotonic_ns': time.monotonic_ns(),
                     'event': name, **fields}
            with (self.root / 'events.jsonl').open('a') as output:
                output.write(json.dumps(event, sort_keys=True, allow_nan=False) + '\n')
        return event

    def bind(self, server):
        require(self.server is None and server.count == server.delivered == 0,
                'Controller can attach only before the first AFL child')
        self.server = server
        server.receipt_observer = self.observe_delivery
        self.thread.start()
        self.event('live_AFL_bound', initial_mask=list(self.mask),
                   focused_site_masks=[list(x) for x in self.mask_schedule.focus])

    def environment(self, library):
        env = {'AFL_CUSTOM_MUTATOR_LIBRARY': str(Path(library).resolve(strict=True)),
               'AFL_DISABLE_TRIM': '1', 'TF_HYBRID_SOCKET': str(self.socket_path),
               'TF_HYBRID_TOKEN': self.token,
               'TF_HYBRID_MAX_INPUT': str(self.max_input),
               'TF_HYBRID_FUZZ_COUNT': str(self.custom_fuzz_count),
               'TF_HYBRID_HOOK_TRACE': str(self.root / 'mutator-hooks.log')}
        if not self.mixed:
            env['AFL_CUSTOM_MUTATOR_ONLY'] = '1'
        # Without ONLY AFL++ invokes both the custom stage and built-in havoc.
        return env

    def drain(self, observed_by='catch_up'):
        require(self.server is not None, 'Unbound AFL server')
        deadline = time.monotonic() + 30
        while self.server.delivered < self.server.count:
            if self.server.stop.is_set() and self.server.delivery_error:
                self.event('AFL_delivery_cancelled', executed=self.server.count,
                           delivered=self.server.delivered, diagnostic=self.server.delivery_error)
                break
            require(not self.server.error and time.monotonic() < deadline,
                    'AFL transport acknowledgement was not committed')
            time.sleep(.005)
        with self._receipt_lock:
            require(self._receipt_error is None, self._receipt_error)
            for index in range(self.processed, self.server.delivered):
                self._read_case(index, observed_by)

    def observe_delivery(self, index):
        """Consume the published receipt before the server exposes its next delivery count."""
        with self._receipt_lock:
            require(self._receipt_error is None, self._receipt_error)
            self._read_case(index, 'transport')

    def _read_case(self, index, observed_by):
        try:
            require(type(index) is int and 0 <= index <= self.processed, 'Gap in case receipts')
            case = self.root / 'cases' / f'{index:08d}'
            receipt, bitmap = read_delivery(case, index, max_input=self.max_input)
            binding_sha = None
            campaign_id = getattr(self.server, 'campaign_id', None)
            if campaign_id is not None:
                require(receipt.sent_ns is not None and receipt.campaign_id == campaign_id,
                        'Receipt belongs to another campaign or lacks current timing evidence')
            if receipt.sent_ns is not None:
                require(receipt.sent_ns <= time.monotonic_ns(), 'Transport timestamp is in the future')
                binding_sha = verify_case_target(case, self.target_sha256, receipt)
            identity = (receipt, binding_sha)
            if index < self.processed:
                require(self._deliveries[index] == identity, f'Committed receipt changed for case {index}')
                return
            if receipt.attempt_id is not None:
                require(receipt.attempt_id not in self._attempt_ids, 'Reused execution attempt ID')
                self._attempt_ids.add(receipt.attempt_id)
            self._record_case(index, receipt, bitmap, observed_by, binding_sha)
            self._deliveries.append(identity)
            self.processed += 1
        except Exception as exc:
            # Do not retry a partially written ledger or publish a successful summary.
            self._receipt_error = f'Case {index} receipt error: {exc}'
            raise

    def _record_case(self, index, receipt, bitmap, observed_by, binding_sha):
        sha = receipt.input_sha256
        pending = self.pending
        same_bytes = pending is not None and pending['sha256'] == sha
        pending_dse = same_bytes and pending['kind'] == 'dse'
        already_verified = any(row['sha256'] == sha for row in self.dse_executions)
        matched = same_bytes and (not pending['delivered'] or
                                  (pending_dse and not receipt.quarantined and not already_verified))
        is_dse = matched and pending_dse
        eligible = not is_dse and (self.mixed or (matched and pending['kind'] == 'masked'))
        was_stalled = self.plateau.stalled
        fresh = 0 if receipt.quarantined else self.plateau.observe(bitmap, eligible=eligible)
        if not was_stalled and self.plateau.stalled:
            edge = self.event('coverage_plateau_reached', case=index, observed_by=observed_by,
                              transport_sent_ns=receipt.sent_ns, threshold=self.plateau.threshold,
                              eligible_cases=self.plateau.eligible)
            self.plateau_edge = {'case': index, 'monotonic_ns': edge['monotonic_ns'],
                                 'transport_sent_ns': receipt.sent_ns}
        elif not self.plateau.stalled:
            self.plateau_edge = None
        if receipt.quarantined:
            self.event('abnormal_exit_quarantined', case=index, input_sha256=sha,
                       classification='unverified_abnormal_exit',
                       verified_target_crash=False, verified_hang=False)
        self.event('case_delivered', case=index, input_sha256=sha,
                   campaign_id=receipt.campaign_id, attempt_id=receipt.attempt_id,
                   result_sha256=receipt.result_sha256, binding_sha256=binding_sha,
                   transport_sha256=receipt.transport_sha256,
                   execution_started_ns=receipt.started_ns, execution_finished_ns=receipt.finished_ns,
                   coverage_sha256=receipt.coverage_sha256, fresh_hitcount_slots=fresh,
                   observed_by=observed_by, transport_sent_ns=receipt.sent_ns,
                   guest_exit=receipt.guest_exit, quarantined=receipt.quarantined,
                   matched_kind=pending['kind'] if matched else None, matched_mutator_output=matched,
                   mutation_origin='custom_payload_match' if matched else 'unattributed',
                   plateau_eligible=eligible and not receipt.quarantined)
        if matched:
            pending['delivered'] = True
            if is_dse:
                self.matched_dse_deliveries += 1
                self.matched_quarantined_dse_deliveries += int(receipt.quarantined)
            else:
                self.delivered_mutations += 1
                if not receipt.quarantined and isinstance(self.mask_schedule, AdaptiveBranchSchedule):
                    self.mask_schedule.observe(pending['scope'], fresh)
        else:
            self.unattributed_deliveries += 1

        # Later executions can have the same bytes even after another callback.
        # Preserve the first verified case separately from delivery attribution.
        offer = self.dse_offers.get(sha)
        # Legacy receipts do not carry host execution clocks.
        offered_in_time = (offer is not None and
                           (receipt.started_ns is None or offer['offered_ns'] <= receipt.started_ns))
        if not receipt.quarantined and not already_verified and (offered_in_time or
                                                                  (receipt.sent_ns is None and pending_dse)):
            execution = {'case': index, 'sha256': sha, 'coverage_sha256': receipt.coverage_sha256,
                         'fresh_hitcount_slots': fresh, 'guest_exit': receipt.guest_exit,
                         'job': offer['job'] if offered_in_time else None,
                         'match_basis': 'input_sha256_after_offer' if offered_in_time else 'pending_payload_match'}
            self.dse_executions.append(execution)
            self.event('DSE_seed_executed_by_live_AFL', **execution)

    def refresh(self, raw):
        root = self.root / 'dta' / f'refresh-{self.refresh_count + 1:02d}'
        self.event('DTA_refresh_started', seed_sha256=digest(raw))
        try:
            analysis = self.analyze_worker(root, binary=self.binary, qemu=self.qemu,
                                           plugin=self.plugin, seed=raw)
            require(analysis['target_sha256'] == self.target_sha256,
                    'DTA refresh target identity mismatch')
            mask = checked_mask(analysis['mask'], self.max_input)
            require(mask, 'DTA refresh returned no tainted offsets')
            schedule = self.schedule_type(mask, analysis['requests'], limit=self.max_input)
            if isinstance(self.mask_schedule, AdaptiveBranchSchedule):
                self.adaptive_feedback_history.extend(self.mask_schedule.adjustments)
            self.current_analysis = analysis
            self.mask = mask
            self.mask_schedule = schedule
            self.mask_revisions.append(list(mask))
            self.focus_mask_revisions.append([list(x) for x in self.mask_schedule.focus])
            self.refresh_count += 1
            self.event('DTA_mask_refreshed', mask=list(mask),
                       focused_site_masks=[list(x) for x in self.mask_schedule.focus],
                       seed_sha256=digest(raw))
        except (OSError, ValueError, RuntimeError, KeyError, subprocess.SubprocessError) as exc:
            self.event('DTA_refresh_failed', error=f'{type(exc).__name__}: {exc}')
            # Preserve the last audited mask; never forge a DTA revision.

    def solve(self):
        """One scheduled DSE job after a measured plateau; errors remain evidence."""
        if len(self.dse_jobs) >= self.max_dse_jobs:
            return None
        requests = eligible_requests(self.current_analysis['requests'], self.attempted)
        if not requests:
            return None
        request = requests[0]
        self.attempted.add(request['request_id'])
        number = len(self.dse_jobs) + 1
        root = self.root / 'dse' / f'job-{number:02d}'
        self.trigger_count += 1
        # This measures latency *to the next mutator callback*. It is not
        # solver runtime or a scheduler-independent DSE dispatch latency.
        lag = None
        if self.plateau_edge is not None:
            sent_ns = self.plateau_edge.get('transport_sent_ns')
            reference_ns = sent_ns if sent_ns is not None else self.plateau_edge['monotonic_ns']
            lag = {'job': number, 'plateau_case': self.plateau_edge['case'],
                   'time_reference': 'transport_send' if sent_ns is not None else 'observation',
                   'completed_cases_at_DSE_trigger': self.processed,
                   'completed_case_lag': max(0, self.processed - self.plateau_edge['case'] - 1),
                   'callback_wait_ms': round((time.monotonic_ns() -
                       reference_ns) / 1_000_000, 3)}
            self.dse_callback_lags.append(lag)
        self.event('DSE_trigger', job=number, request_id=request['request_id'],
                   dispatch_source='mutator_callback',
                   plateau_quiet=self.plateau.quiet, threshold=self.plateau.threshold,
                   completed_cases=self.processed, plateau_callback_lag=lag)
        record = {'job': number, 'request_id': request['request_id'], 'status': 'FAILED'}
        try:
            record['worker_call_started_ns'] = time.monotonic_ns()
            candidate, evidence = self.solve_worker(root, analysis=self.current_analysis,
                request=request, qemu=self.qemu, plugin=self.plugin,
                flags_receipt=self.flags_receipt)
            record['worker_call_finished_ns'] = time.monotonic_ns()
            checked_input(candidate, self.max_input)
            require(evidence['candidate_sha256'] == digest(candidate) and
                    evidence['target_sha256'] == self.target_sha256 and
                    evidence['status'] == 'VERIFIED' and evidence['replayed_and_reaudited'] is True,
                    'DSE worker supplied a seed without matching audit evidence')
            # Do not repeatedly enqueue the same result from different branches.
            if any(job.get('candidate_sha256') == digest(candidate) for job in self.dse_jobs):
                raise RuntimeError('DSE returned an already scheduled seed')
            root_seeds = self.root / 'verified-dse-seeds'
            root_seeds.mkdir(exist_ok=True)
            (root_seeds / digest(candidate)).write_bytes(candidate)
            record.update(status='VERIFIED', candidate_sha256=digest(candidate),
                          evidence=evidence)
            self.event('DSE_candidate_verified', **record)
            return candidate
        except (OSError, ValueError, RuntimeError, KeyError, subprocess.SubprocessError) as exc:
            record['error'] = f'{type(exc).__name__}: {exc}'
            self.event('DSE_job_failed', **record)
            return None
        finally:
            self.dse_jobs.append(record)
            # Avoid triggering a new DSE job on every subsequent callback.
            self.plateau.quiet = 0
            self.plateau_edge = None

    def next_input(self, parent, *, send=None):
        parent = checked_input(parent, self.max_input)
        self.drain('callback')
        with self._receipt_lock:
            response = self._prepare_reply(parent)
            if send is not None:
                try:
                    send(response)
                except OSError:
                    self.pending = None
                    raise
                if self.pending is not None and self.pending['kind'] == 'dse':
                    job = self.dse_jobs[-1]
                    event = self.event('DSE_seed_returned_to_live_AFL', callback=self.request_sequence, **job)
                    self.dse_offers[job['candidate_sha256']] = {'job': job['job'], 'offered_ns': event['monotonic_ns']}
            return response

    def _skip_mutation(self, parent, reason):
        self.pending = None
        self.skipped_mutations += 1
        self.event('mutation_skipped', callback=self.request_sequence, reason=reason,
                   parent_sha256=digest(parent), parent_length=len(parent))
        return RESPONSE.pack(b'TFH2', self.request_sequence, 0, 0, 0)

    def _prepare_reply(self, parent):
        if self.pending is not None:
            if self.pending['delivered'] and self.pending['kind'] == 'dse' and any(
                row['sha256'] == self.pending['sha256'] for row in self.dse_executions):
                self.refresh(self.pending['raw'])
            elif not self.pending['delivered']:
                self.event('mutator_output_not_observed', input_sha256=self.pending['sha256'],
                           kind=self.pending['kind'])
        output = None
        active_mask = self.mask
        kind = 'masked'
        scope = None
        if self.live_dse and self.plateau.stalled:
            # At the callback boundary no AFL child should still be executing.
            with self.server.lock:
                current = self.server.current
            require(current is None, 'DSE cannot run concurrently with an AFL child')
            output = self.solve()
            if output is not None:
                kind = 'dse'
        if output is None:
            choice = self.mask_schedule.next(self.generated + self.skipped_mutations + 1, len(parent))
            if choice is None:
                return self._skip_mutation(parent, 'no_applicable_offsets')
            active_mask, ordinal, scope = choice
            output, offset, operation = masked_mutation(parent, active_mask, ordinal, self.max_input)
            parent_sha = digest(parent)
            reason = self.mask_schedule.skip_reason(parent, parent_sha, offset, output[offset])
            if reason is not None:
                return self._skip_mutation(parent, reason)
            self.generated += 1
            if scope == 'branch_focus':
                self.total_focused_mutations += 1
            else:
                self.total_fallback_mutations += 1
            self.event('masked_mutation', input_sha256=digest(output),
                       parent_sha256=parent_sha, offset=offset, operation=operation,
                       active_mask=list(active_mask), scheduling_scope=scope)
        if kind == 'masked':
            require(set(diff_offsets(parent, output)) <= set(active_mask),
                    'Masked mutation changed an untainted byte')
        self.pending = {'kind': kind, 'raw': output, 'sha256': digest(output),
                        'scope': scope, 'delivered': False}
        header = RESPONSE.pack(b'TFH2', self.request_sequence, 2 if kind == 'dse' else 1,
                               (len(parent) + 7) // 8, len(output))
        return header + mask_bits(active_mask, len(parent)) + output

    def serve(self):
        connection = None
        try:
            while not self.stop.is_set():
                try:
                    connection, _ = self.listener.accept()
                    break
                except socket.timeout:
                    continue
            if connection is None:
                return
            self.connection = connection
            with connection:
                connection.settimeout(600)
                peer = struct.unpack('3i', connection.getsockopt(socket.SOL_SOCKET,
                                                                  socket.SO_PEERCRED, 12))
                require(peer[1] == os.getuid(), 'Mutator socket UID mismatch')
                require(hmac.compare_digest(receive(connection, 64).decode('ascii'), self.token),
                        'Mutator token mismatch')
                sequence = 0
                while not self.stop.is_set():
                    try:
                        packet = receive(connection, REQUEST.size)
                    except ConnectionError:
                        break
                    magic, number, size = REQUEST.unpack(packet)
                    require(magic == b'TFH2' and number == sequence + 1 and
                            1 <= size <= self.max_input, 'Malformed hybrid request')
                    sequence = number
                    self.request_sequence = number
                    parent = receive(connection, size)
                    self.next_input(parent, send=connection.sendall)
        except BaseException as exc:
            if not self.stop.is_set():
                self.error = f'{type(exc).__name__}: {exc}'
                self.event('controller_failed', error=self.error)
        finally:
            self.connection = None

    def close(self):
        self.stop.set()
        if self.connection is not None:
            try:
                self.connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        if self.thread.ident is not None:
            self.thread.join(10)
        self.listener.close()
        self.socket_path.unlink(missing_ok=True)
        require(not self.thread.is_alive(), 'Hybrid sidecar is still running; DTA/DSE did not stop')

    def finish(self):
        self.drain('finalize')
        require(self.error is None, 'Hybrid sidecar failed: ' + str(self.error))
        executed = [row for row in self.dse_executions if any(
            job.get('candidate_sha256') == row['sha256'] for job in self.dse_jobs)]
        queue = self.root / 'afl/default/queue'
        retained = {digest(path.read_bytes()) for path in queue.glob('id:*')
                    if path.is_file() and not path.is_symlink() and path.stat().st_size <= self.max_input}
        retained_executions = [row for row in executed if row['sha256'] in retained]
        require(self.processed == self.delivered_mutations + self.matched_dse_deliveries +
                self.unattributed_deliveries, 'Hybrid delivery provenance accounting diverged')
        trace_path = self.root / 'mutator-hooks.log'
        hook_telemetry = (audit_hook_trace(trace_path, expected_fuzz_callbacks=self.request_sequence)
                          if trace_path.exists() or trace_path.is_symlink() else None)
        result = {'schema': 4, 'profile': 'rebuilt-i386-live-hybrid-v4',
                  'target_sha256': self.target_sha256,
                  'campaign_id': getattr(self.server, 'campaign_id', None),
                  'status': 'completed', 'processed_cases': self.processed,
                  'mutations_generated': self.generated, 'mutations_skipped': self.skipped_mutations,
                  'masked_mutations_delivered': self.delivered_mutations,
                  'matched_DSE_deliveries': self.matched_dse_deliveries,
                  'matched_quarantined_DSE_deliveries': self.matched_quarantined_dse_deliveries,
                  'verified_DSE_payloads': len(executed),
                  'receipt_observer_version': 1,
                  'unattributed_deliveries': self.unattributed_deliveries,
                  'mutator_hooks': hook_telemetry,
                  'dse_callback_lags': self.dse_callback_lags,
                  'mixed_mutations': self.mixed, 'live_dse_enabled': self.live_dse,
                  'adaptive_quota_adjustments': (self.adaptive_feedback_history +
                      self.mask_schedule.adjustments if isinstance(self.mask_schedule,
                          AdaptiveBranchSchedule) else []),
                  'adaptive_focus_quota_per_16': (self.mask_schedule.focus_quota
                      if isinstance(self.mask_schedule, AdaptiveBranchSchedule) else None),
                  'AFL_unacknowledged_cases': self.server.count - self.server.delivered,
                  'plateau_observations': self.plateau.observations,
                  'DSE_triggers': self.trigger_count, 'DSE_jobs': self.dse_jobs,
                  'DSE_live_executions': executed,
                  'DSE_queue_membership': retained_executions,
                  'DTA_mask_revisions': self.mask_revisions,
                  'focused_site_mask_revisions': self.focus_mask_revisions,
                  'focused_mutations_generated': self.total_focused_mutations,
                  'full_union_fallback_mutations_generated': self.total_fallback_mutations,
                  'DTA_mask_refresh_count': self.refresh_count,
                  'automatic_live_cycle_verified': bool(executed and self.refresh_count > 0),
                  'DSE_seed_retained_by_AFL': bool(retained_executions),
                  'phase1_executed_in_rebuilt_campaign': False,
                  'hostile_sample_ready': False,
                  'scope': 'recovered_static_i386_file_input_only'}
        save(self.root / 'hybrid-result.json', result)
        return result
