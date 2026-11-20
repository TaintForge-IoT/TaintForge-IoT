"""Warm checkpoint ordering through the live controller and saved M5 evidence."""
import copy
import unittest
from unittest.mock import patch

from experiments.retirement_observer import controller as c
from taintforge_env import afl_file as f
from tests import test_afl_capsule as capsule
from tests import test_input_retirement as base
from tests import test_retirement_observer_handoff as handoff


class BoundaryPeer(handoff.Peer):
    def sendall(self, data):
        super().sendall(data)
        if data != b'RESUME 2\n':
            return
        self.frames.pop()  # Replace the ordinary guest-exit fixture.
        if self.harness.checkpoint is not None:
            self.queue(self.harness.checkpoint)
        self.queue(dict(event='done', protocol=c.PROTOCOL, host_pid=77,
                        seq=self.harness.done_seq))


class LiveBoundaryTests(unittest.TestCase):
    setUp = handoff.HandoffTests.setUp

    def run_boundary(self, *, seq=500, done_seq=500, changes=None, warm=True):
        self.checkpoint = dict(event='warm_checkpoint', protocol=c.PROTOCOL,
                               host_pid=77, seq=seq)
        self.done_seq = done_seq
        if warm:
            self.binding['afl_warm'] = {'bootstrap_seconds': 60}
        else:
            self.checkpoint = None
        self.checkpoint = (self.checkpoint | (changes or {})) if warm else None
        with patch.object(handoff, 'Peer', BoundaryPeer):
            return handoff.HandoffTests.run_controller(self)

    def test_checkpoint_and_parent_exit_at_the_held_instruction(self):
        result = self.run_boundary()
        self.assertEqual(result['status'], 'passed', result)

    def test_hold_before_the_input_still_allows_guest_progress_to_checkpoint(self):
        self.assertEqual(self.run_boundary(seq=515, done_seq=515)['status'], 'passed')

    def test_checkpoint_cannot_regress(self):
        result = self.run_boundary(seq=499)
        self.assertEqual(result['status'], 'failed')
        self.assertEqual(result['failure']['stage'], 'warm_checkpoint')

    def test_parent_cannot_execute_guest_instructions_after_checkpoint(self):
        result = self.run_boundary(done_seq=501)
        self.assertEqual(result['status'], 'failed')
        self.assertEqual(result['failure']['stage'], 'guest_exit')

    def test_checkpoint_requires_matching_identity_protocol_and_integer_counter(self):
        for changes in ({'host_pid': 78}, {'protocol': 2}, {'seq': 500.0}, {'seq': True}):
            with self.subTest(changes=changes):
                self.setUp()
                result = self.run_boundary(changes=changes)
                self.assertEqual(result['status'], 'failed')
                self.assertEqual(result['failure']['stage'], 'warm_checkpoint')

    def test_nonwarm_guest_still_requires_progress_after_resume(self):
        result = self.run_boundary(warm=False)
        self.assertEqual(result['status'], 'failed')
        self.assertIn('No progress after final resume', result['error'])


class SavedBoundaryTests(unittest.TestCase):
    setUp = capsule.CapsuleWarmIntegrationTests.setUp
    prepare_input = capsule.CapsuleWarmIntegrationTests.prepare_input
    prepare_guarded = capsule.CapsuleWarmIntegrationTests.prepare_guarded
    prepare_warm = capsule.CapsuleWarmIntegrationTests.prepare_warm
    invoke = capsule.CapsuleWarmIntegrationTests.invoke

    def make_session(self):
        out, launch = self.prepare_warm()
        executor = base.InputExecutor()

        def evidence(run, code, fault=None):
            binding, result = capsule.CapsuleWarmIntegrationTests.evidence(run, code, fault)
            path = run/'logs/capsule/observer-events.json'
            journal = f.read_json(path)
            held = next(event for event in journal['events']
                        if event['event'] == 'snapshot' and event['point'] == 2)
            for event in journal['events']:
                if event['event'] in {'warm_checkpoint', 'done'}:
                    event['seq'] = held['seq']
            f.atomic_json(path, journal)
            return binding, result

        with patch.object(base, 'synthetic_evidence', side_effect=evidence):
            report, code = self.invoke(out, launch, executor)
        self.assertEqual(code, 0, report.get('error'))
        self.assertEqual(report['capsule']['status'], 'passed')
        self.assertFalse(report['capsule']['guest_completed'])
        self.assertEqual(report['executions_this_invocation'], 1)
        return executor.runs[0]

    def test_same_instruction_checkpoint_survives_full_m5_finalization(self):
        run, binding, result = self.make_session()
        self.assertEqual(c.verify_attempt(binding, result)['status'], 'passed')

    def test_saved_checkpoint_and_final_counter_are_independently_checked(self):
        run, binding, result = self.make_session()
        path = run/'logs/capsule/observer-events.json'
        saved = f.read_json(path)
        mutations = (
            ('warm_checkpoint', 'seq', 499),
            ('warm_checkpoint', 'seq', 500.0),
            ('warm_checkpoint', 'host_pid', 78),
            ('warm_checkpoint', 'protocol', 2),
            ('done', 'seq', 499),
            ('done', 'seq', 501),
        )
        for kind, key, value in mutations:
            with self.subTest(kind=kind, key=key, value=value):
                changed = copy.deepcopy(saved)
                event = next(event for event in changed['events'] if event['event'] == kind)
                event[key] = value
                f.atomic_json(path, changed)
                with self.assertRaises(RuntimeError):
                    c.verify_attempt(binding, result)
        f.atomic_json(path, saved)

    def test_missing_or_misordered_checkpoint_is_rejected(self):
        run, binding, result = self.make_session()
        path = run/'logs/capsule/observer-events.json'
        saved = f.read_json(path)
        for mode in ('missing', 'duplicate', 'before_resume'):
            with self.subTest(mode=mode):
                changed = copy.deepcopy(saved)
                events = changed['events']
                index = next(i for i, event in enumerate(events) if event['event'] == 'warm_checkpoint')
                checkpoint = events.pop(index)
                if mode == 'duplicate':
                    events[index:index] = [copy.deepcopy(checkpoint), checkpoint]
                elif mode == 'before_resume':
                    index = next(i for i, event in enumerate(events) if event.get('command') == 'RESUME 2')
                    events.insert(index, checkpoint)
                for index, event in enumerate(events, 1):
                    event.update(controller_seq=index, controller_ns=index*1000)
                f.atomic_json(path, changed)
                with self.assertRaises(RuntimeError):
                    c.verify_attempt(binding, result)
        f.atomic_json(path, saved)


if __name__ == '__main__':
    unittest.main()
