"""One live, bounded DTA/AFL/DSE cycle for the bundled prefix parser."""
from __future__ import annotations

import hmac
import json
import os
from pathlib import Path
import secrets
import socket
import struct
import threading
import time

from .policy import SEED, INPUT_PATH, MAP_SIZE, CoveragePlateau, checked_input, checked_mask
from .policy import changed_offsets, digest, masked_mutation
from .runtime import require, save, sha


def receive(connection, size):
    result = bytearray()
    while len(result) < size:
        part = connection.recv(size - len(result))
        if not part:
            raise ConnectionError('Hybrid adapter disconnected')
        result.extend(part)
    return bytes(result)


def analyze(root, *, binary, metadata, qemu, plugin, seed):
    from taintforge_env.dta_analysis import analyze_file
    from taintforge_env.dta_handoff import export_handoff
    root = Path(root)
    root.mkdir(parents=True, exist_ok=False)
    seed_file = root / 'seed'
    seed_file.write_bytes(checked_input(seed))
    directory = root / 'analysis'
    result = analyze_file(binary=binary, qemu=qemu, plugin=plugin, seed=seed_file,
        input_path=INPUT_PATH, out=directory, max_candidates=17,
        seconds=10, memory_mib=1024, wall_seconds=300)
    require(result['status'] == 'passed' and result['inputs']['binary']['sha256'] == metadata['binary_sha256']
            and result['inputs']['seed']['sha256'] == digest(seed), 'DTA source binding mismatch')
    handoff = export_handoff(analysis=directory, out=root / 'handoff')
    require(handoff['target_sha256'] == metadata['binary_sha256'] and handoff['input_path'] == INPUT_PATH
            and handoff['argv'] == [], 'DTA handoff uses another target or launch')
    requests = json.loads((root / 'handoff/recapture-requests.json').read_bytes())['requests']
    offsets = sorted({offset for request in requests for offset in request['observed_site']['offsets']})
    mask = checked_mask(offsets)
    save(root / 'mask.json', {'offsets': list(mask), 'target_sha256': metadata['binary_sha256'],
        'source_seed_sha256': digest(seed), 'source_summary_sha256': sha(directory / 'summary.json'),
        'handoff_manifest_sha256': sha(root / 'handoff/manifest.json')})
    return {'root': root, 'directory': directory, 'report': result, 'requests': requests, 'mask': mask}


def selected_request(analysis, metadata):
    matches = [row for row in analysis['requests'] if row['input_sha256'] == digest(SEED)
        and row['observed_site']['pc'] == metadata['second_branch_pc']
        and row['observed_site']['offsets'] == [1] and row['opposite_observed_elsewhere'] is False]
    require(len(matches) == 1, 'The fixed second-byte branch is no longer an unseen DTA site')
    return matches[0]


def solve(directory, *, analysis, request, qemu, plugin, receipt, metadata):
    from taintforge_env.dta_dse import extend_corpus, audit_selected_corpus
    seq = request['observed_site']['seq']
    require(type(seq) is int and 0 < seq < 1008, 'Invalid fixed-prefix instruction sequence')
    budget = max(128, 1 << (seq + 15).bit_length())
    result = extend_corpus(analysis=analysis['directory'], qemu=qemu, plugin=plugin,
        flags_receipt=receipt, out=directory, max_jobs=1, max_occurrences=1,
        max_steps=budget, seconds=30, memory_mib=1024, request_ids=[request['request_id']])
    checked = audit_selected_corpus(directory=directory, analysis=analysis['directory'],
        qemu=qemu, plugin=plugin, flags_receipt=receipt, request_id=request['request_id'],
        max_occurrences=1, max_steps=budget, seconds=30, memory_mib=1024)
    require(checked['report'] == result and checked['manifest']['target_sha256'] == metadata['binary_sha256']
            and result['dse_status'] == 'VERIFIED' and result['new_seed_count'] == 1,
            'DSE did not produce one fully audited new seed')
    verified = [job for job in result['jobs'] if job['status'] == 'VERIFIED']
    require(len(verified) == 1, 'DSE job inventory is ambiguous')
    identity = verified[0]['candidate_sha256']
    raw = checked_input(checked['seeds'][identity])
    require(digest(raw) == identity and changed_offsets(SEED, raw) == [1],
            'Verified DSE seed changed bytes beyond its selected source offset')
    return raw, {'status': 'VERIFIED', 'candidate_sha256': identity,
        'selected_request_id': request['request_id'], 'max_steps': budget,
        'summary_sha256': sha(Path(directory) / 'summary.json'),
        'source_and_worker_evidence_reaudited': True, 'changed_source_offsets': [1]}


class LiveController:
    def __init__(self, root, *, analysis, metadata, binary, qemu, plugin, receipt, threshold=16,
                 solve_worker=solve, analyze_worker=analyze):
        self.root = Path(root)
        self.analysis = analysis
        self.metadata = metadata
        self.binary, self.qemu, self.plugin, self.receipt = binary, qemu, plugin, receipt
        self.request = selected_request(analysis, metadata)
        self.mask = checked_mask(list(analysis['mask']))
        self.plateau = CoveragePlateau(threshold)
        self.solve_worker, self.analyze_worker = solve_worker, analyze_worker
        self.token = secrets.token_hex(32)
        self.socket_path = self.root / 'control.sock'
        require(len(os.fsencode(self.socket_path)) < 108, 'Hybrid socket path is too long')
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.listener.bind(str(self.socket_path))
        os.chmod(self.socket_path, 0o600)
        self.listener.listen(1)
        self.listener.settimeout(.2)
        self.stop = threading.Event()
        self.connection = None
        self.thread = threading.Thread(target=self.serve, name='tf-prefix-hybrid', daemon=True)
        self.server = None
        self.processed = self.ordinal = self.event_sequence = 0
        self.pending = None
        self.errors = []
        self.dse = self.dse_case = self.trigger = None
        self.refreshed = False
        self.mutations = self.delivered_mutations = 0
        self.mask_revisions = [list(self.mask)]

    def event(self, kind, **fields):
        self.event_sequence += 1
        value = {'sequence': self.event_sequence, 'monotonic_ns': time.monotonic_ns(),
                 'event': kind, **fields}
        with (self.root / 'events.jsonl').open('a') as stream:
            stream.write(json.dumps(value, sort_keys=True, allow_nan=False) + '\n')
        return value

    def bind(self, server, stage):
        if stage == 'before_afl':
            require(self.server is None and server.executed == server.completed == 0,
                    'Hybrid controller must bind before the first AFL child')
            self.server = server
            self.event('afl_ready', mask=list(self.mask))
        else:
            self.drain()
        return {'status': 'passed', 'scope': 'fixed_prefix_hybrid_session_binding',
                'stage': stage, 'processed_cases': self.processed}

    def start(self):
        self.thread.start()

    def close(self):
        self.stop.set()
        connection = self.connection
        if connection is not None:
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        if self.thread.ident is not None:
            self.thread.join(610)
        self.listener.close()
        self.socket_path.unlink(missing_ok=True)
        require(not self.thread.is_alive(), 'Hybrid sidecar did not finish')

    def drain(self):
        require(self.server is not None, 'AFL server is not bound')
        deadline = time.monotonic() + 5
        expected = self.server.executed
        while self.processed < expected:
            case = self.root / 'campaign/cases' / f'{self.processed:08d}'
            receipt = case / 'transport.json'
            while not receipt.is_file():
                require(time.monotonic() < deadline and not self.server.errors,
                        'AFL case delivery was not committed before the next mutation')
                time.sleep(.005)
            transport = json.loads(receipt.read_bytes())
            result = json.loads((case / 'result.json').read_bytes())
            raw = checked_input((case / 'input').read_bytes())
            bitmap = (case / 'coverage.map').read_bytes()
            require(transport.get('status') == 'delivered' and result.get('status') == 'passed'
                    and result['input']['input_sha256'] == digest(raw)
                    and result['coverage']['map_sha256'] == digest(bitmap)
                    and result['outcome']['kind'] == 'normal'
                    and type(result['guest_exit']) is int and 0 <= result['guest_exit'] <= 4,
                    'Hybrid coverage is not bound to a delivered fixed-parser case')
            matched = self.pending is not None and raw == self.pending['raw'] and not self.pending['delivered']
            fresh = self.plateau.observe(bitmap, eligible=matched and self.pending['kind'] == 'masked')
            self.event('coverage', case=case.name, input_sha256=digest(raw),
                coverage_sha256=digest(bitmap), new_bucket_slots=fresh,
                counted_for_plateau=bool(matched and self.pending['kind'] == 'masked'),
                stagnant_mutations=self.plateau.quiet, guest_exit=result['guest_exit'])
            if matched:
                self.pending['delivered'] = True
                if self.pending['kind'] == 'masked':
                    self.delivered_mutations += 1
                else:
                    require(result['guest_exit'] == 2 and fresh > 0,
                            'DSE seed did not produce its expected parser result and new live coverage')
                    self.dse_case = {'case': case.name, 'guest_exit': 2,
                        'input_sha256': digest(raw), 'new_bucket_slots': fresh,
                        'coverage_sha256': digest(bitmap)}
                    self.event('DSE_seed_executed', **self.dse_case)
            self.processed += 1

    def next_input(self, parent):
        checked_input(parent)
        self.drain()
        if self.pending is not None:
            require(self.pending['delivered'], 'AFL requested another mutation before executing its prior output')
        if self.dse_case is not None and not self.refreshed:
            self.event('DTA_refresh_started', source_seed_sha256=self.dse_case['input_sha256'])
            refreshed = self.analyze_worker(self.root / 'refreshed-dta', binary=self.binary,
                metadata=self.metadata, qemu=self.qemu, plugin=self.plugin, seed=self.pending['raw'])
            self.mask = checked_mask(list(refreshed['mask']))
            require(2 in self.mask, 'DTA refresh did not observe the newly reached third-byte dependency')
            self.mask_revisions.append(list(self.mask))
            self.refreshed = True
            self.event('DTA_mask_refreshed', mask=list(self.mask))
        if self.plateau.stalled and self.dse is None:
            deadline = time.monotonic() + 5
            while self.server.active_attempt.is_set():
                require(time.monotonic() < deadline and not self.server.errors,
                        'DSE started while a warm child was active')
                time.sleep(.005)
            self.trigger = self.event('DSE_trigger', metric='live_guest_edge_hitcount_buckets',
                stagnant_mutations=self.plateau.quiet, threshold=self.plateau.threshold,
                last_completed_case=self.processed - 1, coverage_observations=self.plateau.observations)
            raw, self.dse = self.solve_worker(self.root / 'dse', analysis=self.analysis,
                request=self.request, qemu=self.qemu, plugin=self.plugin, receipt=self.receipt,
                metadata=self.metadata)
            checked_input(raw)
            require(changed_offsets(SEED, raw) == [1], 'DSE returned an invalid fixed-parser seed')
            seeds = self.root / 'verified-seeds'
            seeds.mkdir(exist_ok=True)
            (seeds / digest(raw)).write_bytes(raw)
            self.event('DSE_seed_returned_to_live_AFL', **self.dse)
            kind, opcode = 'dse', 2
        else:
            self.ordinal += 1
            raw, offset, bit = masked_mutation(parent, list(self.mask), self.ordinal)
            self.mutations += 1
            kind, opcode = 'masked', 1
            self.event('masked_mutation', ordinal=self.ordinal, selected_offset=offset,
                       selected_bit=bit, parent_sha256=digest(parent), input_sha256=digest(raw),
                       mask=list(self.mask), changed_offsets=changed_offsets(parent, raw))
        require(set(changed_offsets(parent, raw)) <= set(self.mask), 'Response escapes the active DTA mask')
        self.pending = {'kind': kind, 'raw': raw, 'delivered': False}
        mask = sum(1 << offset for offset in self.mask)
        return struct.pack('!BBH32s', opcode, mask, 32, raw)

    def serve(self):
        try:
            while not self.stop.is_set():
                try:
                    connection, _ = self.listener.accept()
                    break
                except socket.timeout:
                    continue
            else:
                return
            self.connection = connection
            with connection:
                connection.settimeout(600)
                peer = struct.unpack('3i', connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                require(peer[1] == os.getuid(), 'Wrong hybrid adapter UID')
                require(hmac.compare_digest(receive(connection, 64).decode('ascii'), self.token),
                        'Hybrid adapter token mismatch')
                sequence = 0
                while not self.stop.is_set():
                    try:
                        header = receive(connection, 8)
                    except ConnectionError:
                        break
                    magic, current = struct.unpack('!4sI', header)
                    require(magic == b'TFH1' and current == sequence + 1, 'Invalid hybrid request ordering')
                    sequence = current
                    parent = receive(connection, 32)
                    response = self.next_input(parent)
                    connection.sendall(response)
        except BaseException as exc:
            if not self.stop.is_set():
                self.errors.append(f'{type(exc).__name__}: {exc}')
                self.event('controller_failed', error=self.errors[-1])
        finally:
            self.connection = None

    def finish(self):
        self.drain()
        require(not self.errors, 'Hybrid sidecar failed: ' + '; '.join(self.errors))
        require(self.trigger is not None and self.dse is not None and self.dse_case is not None
                and self.refreshed and self.delivered_mutations >= self.plateau.threshold,
                'The live masked-AFL / plateau / DSE / renewed-DTA cycle did not complete')
        value = {'status': 'passed', 'same_binary_sha256': self.metadata['binary_sha256'],
            'metric': 'post_input_guest_edge_hitcount_bucket_novelty',
            'metric_scope': 'the exact guest bitmap delivered to AFL; not AFL internal queue accounting',
            'masked_mutations_generated': self.mutations,
            'masked_mutations_concretely_delivered': self.delivered_mutations,
            'processed_cases': self.processed, 'DSE_jobs': 1,
            'DSE_trigger': self.trigger, 'DSE': self.dse, 'DSE_seed_execution': self.dse_case,
            'DTA_mask_revisions': self.mask_revisions,
            'DSE_seed_return': 'custom_mutator_response_into_the_same_live_AFL_process',
            'DSE_executed_while_AFL_waited_in_custom_callback': True,
            'queue_membership_verified_separately': False}
        save(self.root / 'hybrid-result.json', value)
        return value
