import json
from unittest import TestCase
from .test_hybrid_receipts import ReceiptFixture
from experiments.hybrid_rebuilt_v1 import controller
from experiments.hybrid_rebuilt_v1.policy import AdaptiveBranchSchedule, BranchFocusedSchedule


class ShortMaskTests(TestCase):
    def test_empty_intersection_consumes_no_ordinal(self):
        for schedule_type in (AdaptiveBranchSchedule, BranchFocusedSchedule):
            with self.subTest(schedule=schedule_type.__name__):
                schedule = schedule_type([7], [])
                self.assertIsNone(schedule.next(1, 1))
                self.assertEqual(schedule.next(2, 8), ((7,), 1, 'full_union_fallback'))


class CallbackTests(ReceiptFixture):
    def test_short_parent_then_valid_parent(self):
        self.ctl.analyze_worker = lambda *args, **kwargs: {
            'target_sha256': self.target, 'mask': [7], 'requests': []}
        self.ctl.refresh(b'x')
        self.ctl.request_sequence = 1
        replies = []
        self.ctl.next_input(b'x', send=replies.append)
        self.assertEqual(replies, [controller.RESPONSE.pack(b'TFH2', 1, 0, 0, 0)])
        self.assertIsNone(self.ctl.pending)
        self.assertEqual(self.ctl.generated, 0)
        self.ctl.request_sequence = 2
        self.ctl.next_input(b'x' * 8, send=replies.append)
        self.assertEqual(replies[-1][-8:], b'x' * 7 + b'y')
        self.assertEqual(self.ctl.generated, 1)
        self.assertEqual(self.events('mutation_skipped')[0]['reason'], 'no_applicable_offsets')

    def test_offline_audit_reconciles_native_skip(self):
        from experiments.hybrid_rebuilt_v1.acceptance import audit_native_campaign
        self.ctl.analyze_worker = lambda *args, **kwargs: {
            'target_sha256': self.target, 'mask': [7], 'requests': []}
        self.ctl.refresh(b'x')
        self.ctl.request_sequence = 1
        self.ctl.next_input(b'x', send=lambda reply: None)
        self.ctl.request_sequence = 2
        self.ctl.next_input(b'x' * 8, send=lambda reply: None)
        self.case(b'unrelated')
        self.finish_campaign(hooks='C 2\nS 1\nF 1\nX 1\n')
        report = audit_native_campaign(self.root)
        self.assertEqual(report['mutations_skipped'], 1)
        self.assertEqual(report['custom_fuzz_callbacks'], 2)
        path = self.root / 'events.jsonl'
        rows = [json.loads(line) for line in path.read_text().splitlines()]
        next(row for row in rows if row['event'] == 'mutation_skipped')['callback'] = 3
        path.write_text(''.join(json.dumps(row) + '\n' for row in rows))
        with self.assertRaisesRegex(RuntimeError, 'Invalid skipped callback receipt'):
            audit_native_campaign(self.root)

    def test_attempt_three_does_not_repeat_first_output(self):
        self.ctl.mask = tuple(range(32))
        self.ctl.mask_schedule = AdaptiveBranchSchedule(self.ctl.mask, self.initial['requests'])
        parent = b'A' * 32
        replies = [self.ctl.next_input(parent) for _ in range(16)]
        kinds = [controller.RESPONSE.unpack_from(reply)[2] for reply in replies]
        self.assertEqual(kinds[:3], [1, 1, 0])
        outputs = [reply[-32:] for kind, reply in zip(kinds, replies) if kind == 1]
        self.assertEqual(len(set(outputs)), len(outputs))
        self.assertNotIn(parent, outputs)
        self.assertEqual(self.ctl.generated, len(outputs))
        self.assertEqual(self.events('mutation_skipped')[0]['reason'], 'duplicate_output')

    def test_exhaustion_is_local_to_parent_and_mask_revision(self):
        parent = bytes(1)
        for _ in range(33):
            self.ctl.next_input(parent)
        reasons = [row['reason'] for row in self.events('mutation_skipped')]
        self.assertIn('unchanged_input', reasons)
        self.assertEqual(reasons[-1], 'options_exhausted')
        self.assertEqual(controller.RESPONSE.unpack_from(self.ctl.next_input(b'b'))[2], 1)
        self.ctl.analyze_worker = lambda *args, **kwargs: self.initial
        self.ctl.refresh(parent)
        self.assertEqual(controller.RESPONSE.unpack_from(self.ctl.next_input(parent))[2], 1)

    def test_audit_keeps_attempts_after_a_later_callback(self):
        from experiments.hybrid_rebuilt_v1.acceptance import audit_native_campaign
        self.offer(lambda reply: None)
        self.case(b'fixed replay', quarantine=True)
        self.ctl.request_sequence = 2
        self.ctl.next_input(b'a', send=lambda reply: None)
        self.case(b'fixed replay')
        self.case(b'fixed replay')
        self.finish_campaign()
        report = audit_native_campaign(self.root)
        candidate, = report['candidate_history']
        self.assertLess(candidate['verified_ns'], candidate['offered_ns'])
        self.assertEqual([(row['case'], row['attempt_id'], row['quarantined'])
                          for row in candidate['matching_attempts']],
                         [(6, 'fixture-6', True), (7, 'fixture-7', False), (8, 'fixture-8', False)])
        self.assertFalse(report['independent_dse_dispatch_verified'])


class MaskRefreshTests(ReceiptFixture):
    def test_rejected_site_keeps_previous_revision(self):
        previous_schedule = self.ctl.mask_schedule
        self.ctl.analyze_worker = lambda *args, **kwargs: dict(self.initial, mask=[7])
        self.ctl.refresh(b'x')
        self.assertEqual(len(self.events('DTA_refresh_failed')), 1)
        self.assertEqual(self.events('DTA_mask_refreshed'), [])
        self.assertEqual(self.ctl.mask, (0,))
        self.assertIs(self.ctl.current_analysis, self.initial)
        self.assertIs(self.ctl.mask_schedule, previous_schedule)
        self.assertEqual(self.ctl.mask_revisions, [[0]])
        self.assertEqual(self.ctl.refresh_count, 0)
        response = self.ctl.next_input(b'x')
        self.assertEqual(response[controller.RESPONSE.size:], b'\x01y')


class SkipLimitAuditTests(ReceiptFixture):
    mixed = False

    def test_stop_needs_matching_callbacks_and_separate_live_evidence(self):
        from experiments.hybrid_rebuilt_v1.acceptance import audit_native_campaign
        self.ctl.analyze_worker = lambda *args, **kwargs: dict(self.initial, mask=[7], requests=[])
        self.ctl.refresh(b'AAAAAAAA')
        self.ctl.request_sequence = 1
        self.ctl.next_input(b'AAAAAAAA')
        self.case(self.ctl.pending['raw'])
        for seq in range(2, 1026):
            self.ctl.request_sequence = seq
            self.ctl.next_input(b'A')
        hooks = 'C 1\nF 1\n' + ('C 16\n' + 'S 1\n' * 16) * 64 + 'L 1024\nX 1\n'
        self.finish_campaign(hooks=hooks)
        report = audit_native_campaign(self.root)
        self.assertEqual(report['skip_limit_request'], {'callback': 1025, 'consecutive_skips': 1024})
        self.assertEqual(self.strict_status(), 1)
        ledger = self.root / 'events.jsonl'
        rows = [json.loads(line) for line in ledger.read_text().splitlines()]
        next(row for row in rows if row['event'] == 'mutation_skipped')['callback'] = 1
        ledger.write_text(''.join(json.dumps(row) + '\n' for row in rows))
        with self.assertRaisesRegex(RuntimeError, 'Skip-limit stop differs'):
            audit_native_campaign(self.root)
