"""Virtual slow-fsync reproduction. No QEMU execution is claimed."""
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from experiments.retirement_observer import controller as c
from tests import test_retirement_observer_handoff as fixture


class HoldBudgetPeer(fixture.Peer):
    """Apply the existing native five-second HOLD deadline to the scripted peer."""
    def __init__(self,harness):
        super().__init__(harness)
        self.hold_since = harness.clock.now
        self.hold_timeout = False

    def expire_if_needed(self):
        super().expire_if_needed()
        if self.held and self.harness.clock.now-self.hold_since >= 5:
            self.hold_timeout = True
            self.expired = True

    def sendall(self,data):
        super().sendall(data)
        if data==b'HOLD 2\n':
            self.hold_since = self.harness.clock.now


class ObserverBarrierTests(unittest.TestCase):
    setUp = fixture.HandoffTests.setUp

    def run_controller(self,*,fail_sync=False):
        barriers = []
        failed_once = False
        original = os.fsync

        def slow_sync(descriptor):
            nonlocal failed_once
            live = not self.peer.closed
            barriers.append({'live_channel':live,'held':self.peer.held})
            self.clock.advance(1.3)
            if fail_sync and not live and not failed_once:
                failed_once = True
                raise OSError('scripted deferred sync failure')
            return original(descriptor)

        with patch.object(fixture,'Peer',HoldBudgetPeer),patch.object(c.os,'fsync',side_effect=slow_sync):
            result = fixture.HandoffTests.run_controller(self)
        return result,barriers

    def test_slow_barriers_do_not_consume_native_hold_budget(self):
        result,barriers = self.run_controller()
        self.assertEqual(result['status'],'passed',result)
        self.assertFalse(self.peer.hold_timeout)
        self.assertTrue(barriers)
        self.assertFalse(any(row['live_channel'] for row in barriers))
        self.assertEqual(result['evidence_persistence']['status'],'synced')
        for command in ('CHECK 1','RESUME 1','CHECK 2','RESUME 2'):
            self.assertIn(command,self.peer.commands)

    def test_deferred_sync_failure_cannot_be_a_success(self):
        result,_ = self.run_controller(fail_sync=True)
        self.assertEqual(result['status'],'failed',result)
        self.assertIn('scripted deferred sync failure',result['evidence_persistence_error'])
        journal = c.read_json(self.output/'observer-events.json')
        self.assertTrue(any(row['event']=='done' for row in journal['events']))

    def test_complete_prefix_is_readable_before_deferred_sync(self):
        original = c.sync_observation_evidence
        prefixes = []

        def inspect(binding):
            events = c.read_json(self.output/'observer-events.json')['events']
            prefixes.append([event.get('command',event['event']) for event in events])
            self.assertTrue((self.evidence/'maps-unmapped.txt').is_file())
            original(binding)

        with patch.object(c,'sync_observation_evidence',side_effect=inspect):
            result,_ = self.run_controller()
        self.assertEqual(result['status'],'passed',result)
        self.assertEqual(len(prefixes),1)
        self.assertIn('RESUME 2',prefixes[0])
        self.assertEqual(prefixes[0][-1],'done')


class AtomicEvidenceTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def test_buffered_json_keeps_exact_bytes_atomicity_and_default_durability(self):
        value = {'schema':1,'text':'наблюдение'}
        a,b = self.root/'a.json',self.root/'b.json'
        with patch.object(c.p.os,'fsync',wraps=os.fsync) as sync:
            c.p.write_json(a,value,durable=False)
            self.assertEqual(sync.call_count,0)
            c.p.write_json(b,value)
            self.assertEqual(sync.call_count,1)
        self.assertEqual(a.read_bytes(),b.read_bytes())
        self.assertEqual(json.loads(a.read_text()),value)
        self.assertFalse(list(self.root.glob('*.tmp')))

    def test_failed_buffered_publish_retains_previous_complete_json(self):
        path = self.root/'journal.json'
        c.p.write_json(path,{'seq':1})
        before = path.read_bytes()
        with patch.object(Path,'replace',side_effect=OSError('test publish failure')):
            with self.assertRaisesRegex(OSError,'publish failure'):
                c.p.write_json(path,{'seq':2},durable=False)
        self.assertEqual(path.read_bytes(),before)

    def test_final_sync_rejects_symlink_and_keeps_saved_bytes(self):
        binding = {'run_dir':str(self.root)}
        output = self.root/'logs/capsule'
        retirement = output/'phase1-retirement'
        retirement.mkdir(parents=True)
        target = self.root/'outside.json'
        target.write_text('{}\n')
        (output/'observer-events.json').symlink_to(target)
        before = hashlib.sha256(target.read_bytes()).hexdigest()
        with self.assertRaises(OSError):
            c.sync_observation_evidence(binding)
        self.assertEqual(hashlib.sha256(target.read_bytes()).hexdigest(),before)


if __name__=='__main__':
    unittest.main()
