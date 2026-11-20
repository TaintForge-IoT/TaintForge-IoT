"""Continuation orchestration with real snapshots and child/Phase 2 evidence."""
import contextlib
import fcntl
import hashlib
import io
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from taintforge_env import afl_continue as c, afl_file as f, afl_transport
from taintforge_env.afl_capsule import PROFILE as CAPSULE
from tests import test_afl_replay_epochs as fixtures


class ContinuationTests(unittest.TestCase):
    def setUp(self):
        fixture = fixtures.ReplayEpochTests('test_reduction_preserves_same_fault_and_budget')
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.fixture, self.root, self.source = fixture, fixture.root, fixture.source
        fixture.repair()
        (self.source/'afl/default/queue/id:0').write_bytes(b'A')
        (self.source/'seeds/B').write_bytes(b'B')
        self.change(evidence_complete=True)
        manifest = f.read_json(self.source/'campaign.json')
        manifest['warm']['capsule_profile'] = CAPSULE
        for path in (self.source/'seeds').iterdir():
            manifest['assets'][str(path)] = f.p.sha(path)
        f.atomic_json(self.source/'campaign.json', manifest)
        (self.source/'.campaign.lock').touch()
        f.atomic_json(self.source/'warm-ready.json', {'status': 'ready'})
        self.admission = patch.object(c, 'verify_admission', return_value={
            'analysis_policy': {'mode': 'strict'}, 'analysis_quality': {'status': 'accepted'},
            'retirement_manifest_sha256': 'a'*64})
        self.admission.start()
        self.addCleanup(self.admission.stop)

    def change(self, **values):
        value = f.read_json(self.source/'campaign.json')
        f.atomic_json(self.source/'campaign.json', value | values)

    def inventory(self):
        return {str(path.relative_to(self.source)): f.p.sha(path)
                for path in self.source.rglob('*') if path.is_file()}

    def test_preparation_preserves_source_deduplicates_and_binds_provenance(self):
        before = self.inventory()
        out = self.root/'continued'
        value = c.prepare_continuation(self.source, out)
        self.assertEqual(before, self.inventory())
        self.assertEqual(value['status'], 'prepared')
        self.assertEqual(value['warm']['capsule_profile'], CAPSULE)
        self.assertEqual(value['warm']['phase2']['mode'], 'parallel')
        self.assertEqual({p.read_bytes() for p in (out/'seeds').iterdir()}, {b'A', b'B'})
        report = f.read_json(out/'continuation.json')
        self.assertEqual(report['source_campaign_sha256'], before['campaign.json'])
        self.assertEqual(report['corpus']['files'], 3)
        self.assertEqual(report['corpus']['unique_inputs'], 2)
        self.assertFalse(report['cpu_checkpoint_restored'])
        self.assertFalse(report['afl_scheduler_restored'])
        self.assertFalse((out/'warm-ready.json').exists())
        f.verify_campaign(out)
        (out/'continuation.json').write_text('{}')
        with self.assertRaisesRegex(RuntimeError, 'asset changed'):
            f.verify_campaign(out)

    def test_unfinalized_and_failed_states_are_refused_before_copy(self):
        for status in ('prepared', 'preparing', 'running', 'failed', 'interrupted', 'incomplete'):
            with self.subTest(status=status):
                self.change(status=status)
                out = self.root/status
                with self.assertRaisesRegex(RuntimeError, 'completed or fully drained'):
                    c.prepare_continuation(self.source, out)
                self.assertFalse(out.exists())

    def test_live_capsule_and_incomplete_evidence_are_refused(self):
        path = self.source/'warm-session-result.json'
        session = f.read_json(path)
        session['capsule']['resources']['tree_empty'] = False
        f.atomic_json(path, session)
        with self.assertRaisesRegex(RuntimeError, 'verified stopped'):
            c.prepare_continuation(self.source, self.root/'live')
        session['capsule']['resources']['tree_empty'] = True
        f.atomic_json(path, session)
        self.change(evidence_complete=False)
        with self.assertRaises(RuntimeError):
            c.prepare_continuation(self.source, self.root/'incomplete')

    def test_pending_phase2_and_changed_capture_are_refused(self):
        path = self.source/'phase2-progress.json'
        state = f.read_json(path)
        f.atomic_json(path, state | {'pending': 1})
        with self.assertRaisesRegex(RuntimeError, 'Incomplete'):
            c.prepare_continuation(self.source, self.root/'pending')
        f.atomic_json(path, state)
        (self.source/'cases/00000000/phase2/capture.json').write_text('{}')
        with self.assertRaises((RuntimeError, KeyError)):
            c.prepare_continuation(self.source, self.root/'capture')

    def test_queue_requires_executed_input_and_seed_requires_asset_binding(self):
        queue = self.source/'afl/default/queue/id:0'
        queue.write_bytes(b'unobserved')
        with self.assertRaisesRegex(RuntimeError, 'no verified child'):
            c.prepare_continuation(self.source, self.root/'unobserved')
        queue.write_bytes(b'A')
        (self.source/'seeds/injected').write_bytes(b'X')
        with self.assertRaisesRegex(RuntimeError, 'not bound'):
            c.prepare_continuation(self.source, self.root/'injected')

    def test_queue_symlink_fifo_and_linked_parent_are_refused(self):
        queue = self.source/'afl/default/queue/id:0'
        queue.unlink()
        queue.symlink_to(self.source/'seeds/A')
        with self.assertRaises(OSError):
            c.prepare_continuation(self.source, self.root/'symlink')
        queue.unlink()
        os.mkfifo(queue)
        with self.assertRaisesRegex(RuntimeError, 'regular file'):
            c.prepare_continuation(self.source, self.root/'fifo')
        queue.unlink()
        directory = queue.parent
        directory.rename(directory.with_name('saved'))
        directory.symlink_to(directory.with_name('saved'), target_is_directory=True)
        with self.assertRaisesRegex(RuntimeError, 'linked corpus'):
            c.prepare_continuation(self.source, self.root/'linked-parent')

    def test_corpus_limits_fail_without_creating_destination(self):
        for options in ({'max_corpus_files': 1}, {'max_corpus_bytes': 1},
                        {'max_corpus_files': True}, {'max_corpus_bytes': 0}):
            with self.subTest(options=options):
                out = self.root/'limited'
                with self.assertRaises(RuntimeError):
                    c.prepare_continuation(self.source, out, **options)
                self.assertFalse(out.exists())

    def test_exclusive_campaign_lock_refuses_a_concurrent_reader(self):
        with (self.source/'.campaign.lock').open('r') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaises(BlockingIOError):
                c.prepare_continuation(self.source, self.root/'locked')
        self.assertFalse((self.root/'locked').exists())

    def test_nested_and_existing_destinations_are_preserved(self):
        with self.assertRaisesRegex(RuntimeError, 'outside'):
            c.prepare_continuation(self.source, self.source/'nested')
        path = self.root/'existing'
        path.mkdir()
        (path/'keep').write_bytes(b'keep')
        with self.assertRaisesRegex(RuntimeError, 'new continuation'):
            c.prepare_continuation(self.source, path)
        self.assertEqual((path/'keep').read_bytes(), b'keep')

    def test_cleanup_errors_and_non_m5_campaigns_cannot_be_imported(self):
        self.change(cleanup_error='unit has processes')
        with self.assertRaisesRegex(RuntimeError, 'unresolved'):
            c.prepare_continuation(self.source, self.root/'cleanup')
        self.change(cleanup_error=None)
        value = f.read_json(self.source/'campaign.json')
        del value['warm']['capsule_profile']
        f.atomic_json(self.source/'campaign.json', value)
        with self.assertRaisesRegex(RuntimeError, 'M5 campaign'):
            c.prepare_continuation(self.source, self.root/'no-m5')

    def test_source_change_after_copy_marks_new_campaign_failed(self):
        clone = c.clone_campaign
        def changed(*args, **kwargs):
            result = clone(*args, **kwargs)
            (self.source/'afl/default/queue/id:0').write_bytes(b'changed')
            return result
        out = self.root/'changed'
        with patch.object(c, 'clone_campaign', side_effect=changed):
            with self.assertRaisesRegex(RuntimeError, 'corpus changed'):
                c.prepare_continuation(self.source, out)
        self.assertEqual(f.read_json(out/'campaign.json')['status'], 'failed')

    def test_metadata_change_while_verifying_is_refused_before_copy(self):
        verify = c.verify_stopped
        def changed(root):
            result = verify(root)
            f.atomic_json(root/'warm-ready.json', {'status': 'changed'})
            return result
        out = self.root/'metadata-race'
        with patch.object(c, 'verify_stopped', side_effect=changed):
            with self.assertRaisesRegex(RuntimeError, 'changed during continuation verification'):
                c.prepare_continuation(self.source, out)
        self.assertFalse(out.exists())

    def test_broken_output_link_is_preserved(self):
        path = self.root/'linked-output'
        path.symlink_to(self.root/'absent-output')
        with self.assertRaisesRegex(RuntimeError, 'new continuation'):
            c.prepare_continuation(self.source, path)
        self.assertTrue(path.is_symlink())
        self.assertFalse((self.root/'absent-output').exists())

    def test_drained_storage_stop_is_accepted_and_pending_reservations_are_not(self):
        from taintforge_env import afl_storage as storage
        manifest = f.read_json(self.source/'campaign.json')
        policy = storage.policy()
        budget = storage.Budget(self.source, policy)
        self.addCleanup(budget.release_reserve)
        reason = storage.ResourceLimit('case_reservation').record
        budget.stop(reason)
        storage.bind(manifest, policy)
        manifest.update(status='resource_limited', stop_reason='storage_limit',
                        storage_stop=reason, storage_result=budget.report())
        f.atomic_json(self.source/'campaign.json', manifest)
        value = c.prepare_continuation(self.source, self.root/'after-limit')
        self.assertEqual(value['status'], 'prepared')
        self.assertEqual(value['storage'], manifest['storage'])
        manifest['storage_result']['pending_reservations'] = 1
        f.atomic_json(self.source/'campaign.json', manifest)
        with self.assertRaisesRegex(RuntimeError, 'fully drained'):
            c.prepare_continuation(self.source, self.root/'undrained-limit')

    def test_prepare_only_never_starts_a_worker(self):
        out = self.root/'prepare-only'
        with patch.object(afl_transport, 'run_campaign') as run:
            result = c.resume(self.source, out, seconds=10, prepare_only=True)
        run.assert_not_called()
        self.assertEqual(result['status'], 'prepared')
        self.assertEqual(result['phase1_runs'], 0)

    def test_invalid_time_and_missing_afl_fail_before_copy(self):
        for seconds in (True, 0, 61):
            with self.subTest(seconds=seconds):
                with self.assertRaises(RuntimeError):
                    c.resume(self.source, self.root/'time', seconds=seconds, prepare_only=True)
        with self.assertRaisesRegex(RuntimeError, 'not installed'):
            c.resume(self.source, self.root/'no-afl', seconds=10, afl_bin=self.root/'absent')
        self.assertFalse((self.root/'no-afl').exists())

    def test_run_uses_new_directory_and_records_failure_without_changing_source(self):
        before = self.inventory()
        binary = self.root/'afl-bin'
        binary.mkdir()
        (binary/'afl-fuzz').write_bytes(b'#!/bin/sh\nexit 0\n')
        (binary/'afl-fuzz').chmod(0o700)
        out = self.root/'failed-run'
        with patch.object(afl_transport, 'run_campaign', side_effect=RuntimeError('bootstrap failed')) as run:
            with self.assertRaisesRegex(RuntimeError, 'bootstrap failed'):
                c.resume(self.source, out, seconds=10, executions=64, afl_bin=binary)
        self.assertEqual(run.call_args.args, (out,))
        self.assertEqual(run.call_args.kwargs['executions'], 64)
        self.assertEqual(f.read_json(out/'continuation-result.json')['status'], 'failed')
        self.assertEqual(before, self.inventory())


class ContinuationCliTests(unittest.TestCase):
    def test_resume_options_and_exit_codes(self):
        from scripts.run_afl_file import main
        args = ['run_afl_file', 'resume', '--campaign', '/tmp/source', '--out', '/tmp/new',
                '--seconds', '60', '--executions', '100', '--max-corpus-mib', '8', '--prepare-only']
        for status, code in (('prepared', 0), ('completed', 0), ('resource_limited', 3), ('failed', 2)):
            with self.subTest(status=status), patch.object(sys, 'argv', args), \
                 patch.object(c, 'resume', return_value={'status': status}) as resume, \
                 contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(), code)
                self.assertEqual(resume.call_args.kwargs['max_corpus_bytes'], 8*c.MIB)
                self.assertTrue(resume.call_args.kwargs['prepare_only'])


class AdmissionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.template = self.root/'template'
        (self.template/'config').mkdir(parents=True)
        self.policy = {'mode': 'strict'}
        f.atomic_json(self.template/'config/runtime.json', {'capsule': {'analysis_policy': self.policy}})
        f.atomic_json(self.root/'warm-ready.json', {'status': 'ready'})
        self.manifest = {'launch': {'template_run_dir': str(self.template)}}
        self.decision = {'status': 'accepted', 'policy': self.policy}
        self.admitted = {'analysis_quality': self.decision}
        self.capsule = {'afl_checkpoint': self.admitted, 'analysis_quality': self.decision,
                        'portable_evidence': {'manifest_sha256': 'a'*64}}

    def check(self, exported=None):
        from taintforge_env import afl_capsule, retirement_evidence
        exported = exported or {'attempt_outcome': 'passed', 'analysis_quality': self.decision}
        with patch.object(afl_capsule, 'verify_ready', return_value=self.admitted) as ready, \
             patch.object(retirement_evidence, 'verify', return_value=exported) as evidence:
            result = c.verify_admission(self.root, self.manifest, self.capsule)
        self.assertEqual(ready.call_args.args[1], self.policy)
        self.assertEqual(evidence.call_args.kwargs['expected_sha256'], 'a'*64)
        return result

    def test_readiness_and_independent_export_must_agree(self):
        result = self.check()
        self.assertEqual(result['analysis_policy'], self.policy)
        with self.assertRaisesRegex(RuntimeError, 'independent retirement'):
            self.check({'attempt_outcome': 'failed', 'analysis_quality': self.decision})
        with self.assertRaisesRegex(RuntimeError, 'independent retirement'):
            self.check({'attempt_outcome': 'passed', 'analysis_quality': {'status': 'changed'}})

    def test_checkpoint_and_final_capsule_must_agree(self):
        self.capsule['analysis_quality'] = {'status': 'changed'}
        with self.assertRaisesRegex(RuntimeError, 'finalized capsule evidence'):
            self.check()

    def test_research_policy_is_preserved_explicitly(self):
        self.policy['mode'] = 'research'
        f.atomic_json(self.template/'config/runtime.json', {'capsule': {'analysis_policy': self.policy}})
        self.assertEqual(self.check()['analysis_policy'], {'mode': 'research'})

    def test_unavailable_native_prerequisites_never_claim_acceptance(self):
        from scripts import verify_afl_continue_e2e as native
        with patch.object(native.initial, 'verify', return_value={
                'status': 'blocked_environment', 'missing': ['native fixture']}):
            result = native.verify(self.root/'native', qemu=self.root/'missing')
        self.assertEqual(result['status'], 'blocked_environment')
        self.assertFalse(result['native_continuation_verified'])


if __name__ == '__main__':
    unittest.main()
