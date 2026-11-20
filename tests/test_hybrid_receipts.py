"""Receipt publication, observation and offline audit on fixed case data."""
import array
from contextlib import redirect_stderr, redirect_stdout
import io
import json
import socket
import struct
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from experiments.hybrid_rebuilt_v1 import controller, telemetry
from experiments.hybrid_rebuilt_v1.acceptance import audit_native_campaign
from experiments.hybrid_rebuilt_v1.policy import MAP_SIZE, digest
from experiments.hybrid_rebuilt_v1.receipt_audit import mutation_counts
from scripts.audit_hybrid_v51 import main as audit_cli
from taintforge_env import afl_rebuilt as backend


def put(path, record):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(record) + '\n')


class ReceiptFixture(unittest.TestCase):
    mixed = True

    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix='tf-receipts-')
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.binary = self.root / 'sample'
        self.binary.write_bytes(b'receipt fixture')
        self.target = digest(self.binary.read_bytes())
        self.server = backend.Server(self.root, 128, campaign_id='1' * 32)
        self.addCleanup(self.server.channel.close)
        self.addCleanup(self.server.peer.close)
        self.start_ns = time.monotonic_ns()
        self.initial = {'target_sha256': self.target, 'mask': [0],
                        'requests': [{'request_id': 'f' * 64, 'opposite_observed_elsewhere': False,
                                      'observed_site': {'seq': 5, 'offsets': [0]}}]}
        # No AFL listener or solver is needed to exercise the transport publisher.
        with patch.object(controller.socket, 'socket'), patch.object(controller.os, 'chmod'):
            self.ctl = controller.LiveRebuiltController(
                self.root, initial=self.initial, binary=self.binary, qemu=None, plugin=None,
                flags_receipt=None, mixed_mutations=self.mixed, live_dse=True, max_dse_jobs=1,
                solve_worker=self.unexpected_worker, analyze_worker=self.unexpected_worker, stall_cases=4)
        self.addCleanup(self.ctl.close)
        with patch.object(self.ctl.thread, 'start'):
            self.ctl.bind(self.server)

    def unexpected_worker(self, *args, **kwargs):
        self.fail('Receipt observation invoked an analysis worker')

    def case_files(self, folder, raw, quarantine=False):
        index = int(folder.name)
        folder.mkdir(parents=True)
        bitmap = bytes(MAP_SIZE) if quarantine else b'\x01' + bytes(MAP_SIZE - 1)
        (folder / 'input').write_bytes(raw)
        (folder / 'coverage.map').write_bytes(bitmap)
        result = {'status': 'quarantined' if quarantine else 'passed',
                  'campaign_id': self.server.campaign_id, 'attempt_id': f'fixture-{index}',
                  'input_sha256': digest(raw), 'phase1_executed': False,
                  'hostile_sample_ready': False}
        if quarantine:
            result.update(classification='unverified_abnormal_exit',
                          coverage={'status': 'unavailable', 'map_sha256': None})
        else:
            output = folder / 'output/coverage.bin'
            output.parent.mkdir()
            header = backend.HEADER.pack(b'TFRCOV1\0', 1, MAP_SIZE, 1, 1, 4, 8, 16, 1, 0, len(raw), 0, 0)
            output.write_bytes(header + bitmap + bytes(backend.MAX_BRANCHES * backend.BRANCH.size))
            coverage, _ = backend.parse_map(output, 0)
            result.update(guest_exit=0, returncode=0, coverage=coverage)
        put(folder / 'result.json', result)
        binding = {'target_sha256': self.target, 'input_sha256': digest(raw),
                   'campaign_id': self.server.campaign_id, 'attempt_id': result['attempt_id']}
        binding['attempt_contract_sha256'] = backend.contract(binding)
        put(folder / 'config/rebuilt_binding.json', binding)
        return result, bitmap

    def case(self, raw=b'a', *, quarantine=False):
        folder = self.root / 'cases' / f'{self.server.count:08d}'
        started_ns = time.monotonic_ns()
        result, bitmap = self.case_files(folder, raw, quarantine)
        self.server.count += 1
        self.server.publish_delivery(folder, result, bitmap, started_ns=started_ns, finished_ns=time.monotonic_ns())
        return folder

    def events(self, label):
        rows = (json.loads(s) for s in (self.root / 'events.jsonl').read_text().splitlines())
        return [row for row in rows if row['event'] == label]

    def finish_campaign(self, hooks=None):
        if hooks is None:
            hooks = 'C 1\nF 1\n' * self.ctl.request_sequence + 'X 1\n'
        (self.root / 'mutator-hooks.log').write_text(hooks)
        hybrid = self.ctl.finish()
        campaign = {'status': 'completed', 'profile': backend.PROFILE, 'afl_exit': 0,
                    'afl_executable_sha256': digest(b'fixture process'),
                    'campaign_id': self.server.campaign_id, 'target_sha256': self.target,
                    'afl_stage_policy': 'fast', 'enhanced_deterministic_skipped': True,
                    'command': ['afl-fuzz', '-z', '--', 'bridge'],
                    'cases': self.server.count, 'delivered_cases': self.server.delivered,
                    'quarantined_cases': len(self.events('abnormal_exit_quarantined')),
                    'final_delivery_error': self.server.delivery_error,
                    'hybrid': {'mixed_mutations': self.mixed, 'mutator_hooks': hybrid['mutator_hooks'],
                               'stall_cases': 4},
                    'afl_process_window': {'clock': 'host_monotonic_ns', 'pid': 7,
                                           'started_ns': self.start_ns, 'last_alive_ns': time.monotonic_ns(),
                                           'exit_observed_ns': time.monotonic_ns()}}
        put(self.root / 'campaign.json', campaign)
        return campaign

    def fixed_worker(self, directory, *, request, **kwargs):
        raw = b'fixed replay'
        sha, req = digest(raw), request['request_id']
        jobs = [{'status': 'VERIFIED', 'candidate_sha256': sha, 'request_id': req}]
        seed_dir = directory / 'seeds'
        seed_dir.mkdir(parents=True)
        (seed_dir / sha).write_bytes(raw)
        put(directory / 'manifest.json', {'target_sha256': self.target, 'selected_request_ids': [req],
            'jobs': jobs, 'seeds': [{'sha256': sha, 'origin': 'verified_isolated_DSE'}]})
        summary = directory / 'summary.json'
        put(summary, {'status': 'passed', 'dse_status': 'VERIFIED', 'new_seed_count': 1,
                      'source_and_worker_evidence_reaudited': True, 'jobs': jobs, 'selected_request_ids': [req]})
        return raw, {'status': 'VERIFIED', 'replayed_and_reaudited': True, 'request_id': req,
                     'candidate_sha256': sha, 'summary_sha256': digest(summary.read_bytes()),
                     'target_sha256': self.target}

    def offer(self, send):
        for _ in range(6):
            self.case()
        self.ctl.solve_worker = self.fixed_worker
        self.ctl.request_sequence = 1
        self.ctl.next_input(b'a', send=send)

    def strict_status(self):
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            return audit_cli(['--campaign', str(self.root), '--require-live-cycle',
                              '--target-sha256', self.target])


class ReceiptTests(ReceiptFixture):
    def test_plateau_is_visible_on_receipt_with_zero_callbacks(self):
        for _ in range(8):
            self.case()
        self.assertEqual(self.ctl.processed, 8)
        edges = self.events('coverage_plateau_reached')
        self.assertEqual([(r['case'], r['observed_by']) for r in edges], [(4, 'transport')])
        self.assertLessEqual(edges[0]['transport_sent_ns'], edges[0]['monotonic_ns'])
        self.assertEqual(self.events('DSE_trigger'), [])
        self.assertEqual(self.ctl.finish()['processed_cases'], 8)
        self.assertEqual([r['case'] for r in self.events('case_delivered')], list(range(8)))

    def test_clean_deinit_without_a_request(self):
        (self.root / 'mutator-hooks.log').write_text('X 1\n')
        result = self.ctl.finish()
        self.assertEqual(result['mutator_hooks']['custom_fuzz_callbacks'], 0)
        self.assertTrue(result['mutator_hooks']['clean_deinit_observed'])

    def test_repeated_observation_and_catchup_are_idempotent(self):
        with patch.object(self.server, 'receipt_observer', None):
            folder = self.case()
        barrier = threading.Barrier(3)
        errors = []
        def repeat(call):
            try:
                barrier.wait(timeout=2)
                call()
            except Exception as exc:
                errors.append(exc)
        readers = [threading.Thread(target=repeat, args=(call,)) for call in
                   (lambda: self.ctl.observe_delivery(0), self.ctl.drain)]
        for t in readers:
            t.start()
        barrier.wait(timeout=2)
        for t in readers:
            t.join(2)
            self.assertFalse(t.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(len(self.events('case_delivered')), 1)
        second = self.case()
        self.assertNotEqual(second, folder)
        self.assertEqual(len(self.events('case_delivered')), 2)
        record = json.loads((folder / 'result.json').read_text())
        record['guest_exit'] = 1
        put(folder / 'result.json', record)
        with self.assertRaisesRegex((RuntimeError, ValueError), 'changed|conflict'):
            self.ctl.observe_delivery(0)

    def test_quarantine_then_verified_delivery_of_the_same_bytes(self):
        self.offer(lambda response: None)
        data = b'fixed replay'
        observations = self.ctl.plateau.observations
        self.case(data, quarantine=True)
        self.assertEqual(self.ctl.dse_executions, [])
        self.assertEqual(self.ctl.plateau.observations, observations)
        self.case(data)
        self.case(data)
        self.assertEqual([row['case'] for row in self.ctl.dse_executions], [7])
        self.assertEqual(len(self.events('abnormal_exit_quarantined')), 1)
        self.assertEqual(self.ctl.matched_quarantined_dse_deliveries, 1)

    def test_real_transport_publishes_only_after_coverage_send(self):
        seen = threading.Event()
        def observed(index):
            self.ctl.observe_delivery(index)
            seen.set()
        self.server.receipt_observer = observed
        def execute(root, raw, case, active):
            return self.case_files(case, raw)
        with patch.object(backend, 'execute_case', side_effect=execute):
            client, endpoint = socket.socketpair()
            with client, endpoint:
                client.settimeout(3)
                self.server.thread.start()
                try:
                    self.server.peer.sendmsg([b'C'], [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
                                                       array.array('i', [endpoint.fileno()]))])
                    client.sendall(struct.pack('!I', 1) + b'a')
                    reply = backend.receive(client, 16 + MAP_SIZE)
                    self.assertEqual(struct.unpack('!4I', reply[:16]), (0x54464131, 0, 0, MAP_SIZE))
                    self.assertTrue(seen.wait(3), self.server.error)
                    self.assertEqual(self.events('case_delivered')[0]['coverage_sha256'], digest(reply[16:]))
                finally:
                    self.server.stop.set()
                    self.server.thread.join(3)
        self.assertFalse(self.server.thread.is_alive())
        self.assertIsNone(self.server.error)

    def test_offline_zero_callbacks_does_not_establish_a_cycle(self):
        for _ in range(5):
            self.case()
        self.finish_campaign()
        report = audit_native_campaign(self.root, expected_target_sha256=self.target)
        self.assertEqual(report['evidence_level'], 'primary_case_receipts')
        self.assertEqual(report['custom_fuzz_callbacks'], 0)
        self.assertEqual(report['witnessed_cycles'], [])
        self.assertEqual(report['plateau_cases_while_afl_alive'], [4])
        self.assertEqual(report['dse_jobs_started_while_afl_alive'], [])
        self.assertEqual(self.strict_status(), 1)
        with self.assertRaisesRegex(RuntimeError, 'expected SHA-256'):
            audit_native_campaign(self.root, expected_target_sha256='0' * 64)

    def test_verified_bytes_after_quarantine_and_another_callback(self):
        sent = []
        self.offer(sent.append)
        raw = b'fixed replay'
        self.assertTrue(sent[0].endswith(raw))
        self.case(raw, quarantine=True)
        self.ctl.request_sequence = 2
        self.ctl.next_input(b'a', send=sent.append)
        folder = self.case(raw)
        self.finish_campaign()
        report = audit_native_campaign(self.root)
        cycle, = report['witnessed_cycles']
        self.assertEqual((cycle['plateau_case'], cycle['case'], cycle['dispatch_source']), (4, 7, 'mutator_callback'))
        self.assertEqual(cycle['seed_sha256'], digest(raw))
        self.assertEqual(report['dse_jobs_started_while_afl_alive'], [1])
        self.assertEqual(cycle['coverage_sha256'], digest((folder / 'coverage.map').read_bytes()))
        self.assertFalse(report['independent_dse_dispatch_verified'])
        self.assertIsNone(self.events('case_delivered')[-1]['matched_kind'])
        self.assertEqual(self.strict_status(), 0)
        (self.root / 'dse/job-01/seeds' / digest(raw)).write_bytes(b'different seed')
        self.assertEqual(self.strict_status(), 2)

    def test_offer_without_verified_execution_is_inconclusive(self):
        self.offer(lambda reply: None)
        self.case(b'fixed replay', quarantine=True)
        self.finish_campaign()
        self.assertFalse(audit_native_campaign(self.root)['live_cycle_observed'])
        self.assertEqual(self.strict_status(), 1)

    def test_failed_send_does_not_publish_an_offer(self):
        def disconnected(reply):
            raise BrokenPipeError('fixture transport closed')
        with self.assertRaises(BrokenPipeError):
            self.offer(disconnected)
        self.assertEqual(len(self.events('DSE_candidate_verified')), 1)
        self.assertEqual(self.events('DSE_seed_returned_to_live_AFL'), [])
        self.case(b'fixed replay')
        self.assertEqual(self.events('DSE_seed_executed_by_live_AFL'), [])

    def test_late_execution_does_not_prove_an_in_campaign_cycle(self):
        self.offer(lambda reply: None)
        self.case(b'fixed replay')
        campaign = self.finish_campaign()
        campaign['afl_process_window']['last_alive_ns'] = self.events('DSE_candidate_verified')[0]['monotonic_ns']
        put(self.root / 'campaign.json', campaign)
        self.assertEqual(self.strict_status(), 1)

    def test_cases_first_seen_at_finalize_are_identified(self):
        with patch.object(self.server, 'receipt_observer', None):
            for _ in range(5):
                self.case()
            self.assertEqual(self.ctl.processed, 0)
        self.finish_campaign()
        self.assertEqual(self.events('coverage_plateau_reached')[0]['observed_by'], 'finalize')
        self.assertEqual(audit_native_campaign(self.root)['plateau_cases_while_afl_alive'], [])
        self.assertEqual(self.strict_status(), 1)

    def test_rejects_corrupt_or_foreign_receipts(self):
        folder = self.case()
        self.finish_campaign()
        for rel in ('coverage.map', 'output/coverage.bin', 'input', 'result.json',
                    'transport.json', 'config/rebuilt_binding.json'):
            path = folder / rel
            raw = path.read_bytes()
            with self.subTest(file=rel):
                path.write_bytes(raw[:-1] + bytes([raw[-1] ^ 1]) if not rel.endswith('.json') else raw + b' ')
                self.assertEqual(self.strict_status(), 2)
                path.write_bytes(raw)
        receipt = json.loads((folder / 'transport.json').read_text())
        receipt['campaign_id'] = '2' * 32
        put(folder / 'transport.json', receipt)
        self.assertEqual(self.strict_status(), 2)

    def test_rejects_torn_and_ambiguous_event_records(self):
        self.case()
        self.finish_campaign()
        path = self.root / 'events.jsonl'
        raw = path.read_bytes()
        for damaged in (raw.rstrip(), raw.replace(b'"event":', b'"event": "ignored", "event":', 1)):
            path.write_bytes(damaged)
            self.assertEqual(self.strict_status(), 2)

    def test_balanced_counters_cannot_invent_a_mutator_match(self):
        self.case()
        self.finish_campaign()
        ledger = self.root / 'events.jsonl'
        rows = [json.loads(line) for line in ledger.read_bytes().splitlines()]
        delivered = next(row for row in rows if row['event'] == 'case_delivered')
        delivered.update(matched_kind='masked', matched_mutator_output=True, mutation_origin='custom_payload_match')
        ledger.write_text(''.join(json.dumps(row) + '\n' for row in rows))
        path = self.root / 'hybrid-result.json'
        hybrid = json.loads(path.read_bytes())
        hybrid.update(masked_mutations_delivered=1, unattributed_deliveries=0)
        put(path, hybrid)
        self.assertEqual(self.strict_status(), 2)

    def test_previous_attempt_id_cannot_identify_a_new_case(self):
        self.case()
        with patch.object(self.server, 'receipt_observer', None):
            path = self.case()
        for rel in ('result.json', 'transport.json', 'config/rebuilt_binding.json'):
            artifact = path / rel
            record = json.loads(artifact.read_bytes())
            record['attempt_id'] = 'fixture-0'
            if 'attempt_contract_sha256' in record:
                record['attempt_contract_sha256'] = backend.contract(record)
            put(artifact, record)
        with self.assertRaisesRegex(RuntimeError, 'Reused execution attempt'):
            self.ctl.drain()
        self.assertEqual(self.ctl.processed, 1)

    def test_one_cancelled_terminal_case_has_no_delivery(self):
        self.case()
        self.case_files(self.root / 'cases/00000001', b'last')
        self.server.count += 1
        self.server.delivery_error = 'fixture child closed the socket'
        self.server.stop.set()
        self.finish_campaign()
        report = audit_native_campaign(self.root)
        self.assertEqual(report['delivered_cases'], 1)
        self.assertFalse(report['live_cycle_observed'])
        put(self.root / 'cases/00000001/transport.json', {'status': 'delivered'})
        self.assertEqual(self.strict_status(), 2)


class CustomOnlyTests(ReceiptFixture):
    mixed = False

    def test_native_fixture_profile_counts_only_eligible_custom_cases(self):
        self.case()
        outputs = []
        for n in range(1, 5):
            self.ctl.request_sequence = n
            self.ctl.next_input(b'a', send=outputs.append)
            self.case(self.ctl.pending['raw'])
        self.ctl.solve_worker = self.fixed_worker
        self.ctl.request_sequence = 5
        self.ctl.next_input(b'a', send=outputs.append)
        self.case(b'fixed replay')
        self.finish_campaign()
        report = audit_native_campaign(self.root)
        self.assertFalse(report['mixed_mutations'])
        self.assertEqual(report['witnessed_cycles'][0]['plateau_case'], 4)
        self.assertEqual(self.strict_status(), 0)


class HookOrderTests(unittest.TestCase):
    def test_diversity_is_scoped_to_parent_and_dta_revision(self):
        a, b = digest(b'a'), digest(b'b')
        focus = {'event': 'masked_mutation', 'parent_sha256': a, 'input_sha256': b, 'offset': 0,
                 'scheduling_scope': 'branch_focus', 'active_mask': [0]}
        fallback = dict(focus, scheduling_scope='full_union_fallback', active_mask=[0, 1])
        initial = {'event': 'live_AFL_bound', 'initial_mask': [0, 1], 'focused_site_masks': [[0]]}
        refresh = {'event': 'DTA_mask_refreshed', 'mask': [0, 1], 'focused_site_masks': [[0]]}
        rows = [initial, focus, fallback, dict(fallback, parent_sha256=b), refresh, fallback]
        counts = mutation_counts(rows)
        self.assertEqual(counts, {'attempts': 4, 'unique_per_parent_and_revision': 3, 'duplicate_attempts': 1,
                                  'unchanged_attempts': 1, 'outputs_seen_in_both_scopes': 1})
        with self.assertRaisesRegex(RuntimeError, 'masked-mutation'):
            mutation_counts([initial, dict(focus, active_mask=[1], offset=1)])

    def test_each_callback_consumes_a_slot_in_its_own_stage(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / 'hooks'
            for raw in ('F 1\nC 2\nX 1\n', 'C 8\nC 1\nF 1\nF 1\nX 1\n'):
                with self.subTest(raw=raw):
                    log.write_text(raw)
                    with self.assertRaises(RuntimeError):
                        telemetry.audit_hook_trace(log)
