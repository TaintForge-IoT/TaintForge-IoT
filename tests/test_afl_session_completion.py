"""Keep child findings without failing a verified warm coordinator session."""
import copy
import json
from pathlib import Path
import tempfile
import unittest

from taintforge_env.attempt import AttemptOutcome, AttemptStore
from taintforge_env.iteration_controller import (
    IterationController, IterationControllerError, SessionState, StopReason,
)
from taintforge_env.qemu_strace_parser import parse_qemu_strace
from tests.test_iteration_controller import make_seed, write_artifacts, SAMPLE_SHA256, GOAL_ID


class WarmSessionCompletionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.session = self.root/'session'
        IterationController.initialize(session_dir=self.session, snapshot_store=self.root/'store',
            seed_rootfs=make_seed(self.root), sample_sha256=SAMPLE_SHA256,
            packed_binary_sha256=SAMPLE_SHA256, goal_id=GOAL_ID, max_iterations=1)
        self.controller = IterationController(self.session)
        self.prepared = self.controller.prepare_next()
        self.contract = AttemptStore(self.session/'attempts').load_contract(self.prepared.attempt_id)
        self.artifacts = self.root/'run'
        write_artifacts(self.artifacts, automatic=True, resource='/var/fuzz-state')
        trace = self.artifacts/'logs/qemu_strace.log'
        trace.write_text('35 mprotect(0x804b000,4096,PROT_READ|PROT_WRITE) = 0\n'
                         '--- SIGILL {si_signo=SIGILL, si_code=ILL_ILLOPN, si_addr=0x804b100} ---\n'
                         '--- SIGSEGV {si_signo=SIGSEGV, si_code=SEGV_MAPERR, si_addr=NULL} ---\n'
                         '--- SIGABRT {si_signo=SIGABRT, si_code=SI_TKILL, si_pid=52} ---\n'
                         '166 exit(0)\n')
        parse_qemu_strace(trace, self.artifacts/'logs/syscall_events.jsonl', target_arch='i386')

    def save(self, name, value):
        path = self.artifacts/name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value)+'\n')

    def warm_evidence(self):
        from taintforge_env.afl_warm import configuration
        config = configuration(self.root/'campaign', bootstrap_seconds=60, campaign_seconds=30,
                               timeout_ms=50, max_rss_mib=512)
        identity = {'attempt_id': self.contract.attempt_id,
                    'attempt_contract_sha256': self.contract.contract_sha256}
        self.save('config/runtime.json', {'afl_warm': config})
        self.save('config/capsule_binding.json', dict(identity, afl_warm=config,
            session_id='session', analysis_instance_id='instance', bundle_sha256='a'*64))
        self.capsule = dict(identity, status='passed', restart='live_post_retirement_fork',
            session_id='session', analysis_instance_id='instance', bundle_sha256='a'*64,
            qemu_exit=0, controller_exit=0, supervisor_kill=False, controller_failures=[],
            warm={'status': 'passed', 'phase1_runs': 1, 'children': 65},
            phase1_retirement={'status': 'verified', 'phase1_retired': True},
            resources={'status': 'verified', 'tree_empty': True},
            hardening={'status': 'verified'})
        self.save('config/capsule_result.json', self.capsule)
        self.save('config/prebuilt_execution.json', {'guest_exit_code': 0, 'timed_out': False})
        self.finalization = dict(identity, status='completed', guest_stop_confirmed=True,
            stages={name: {'status': 'completed'} for name in (
                'execution', 'filesystem', 'phase1', 'syscalls', 'requirements', 'repair_plan', 'capsule')})
        self.finalization['stages']['network_cleanup'] = {'status': 'not_applicable'}
        self.save('config/finalization_status.json', self.finalization)

    def complete(self, **kwargs):
        return self.controller.complete_iteration(iteration_index=0, artifacts_dir=self.artifacts,
                                                  guest_exit_code=0, **kwargs)

    def test_warm_child_crashes_are_retained_but_parent_attempt_completes(self):
        self.warm_evidence()
        record = self.complete()
        self.assertEqual(self.controller.load().state, SessionState.COMPLETED)
        self.assertEqual(record.stop_reason, StopReason.BUDGET_EXHAUSTED)
        result = AttemptStore(self.session/'attempts').load_result(record.attempt_id)
        self.assertEqual(result.outcome, AttemptOutcome.REPAIR_REQUIRED)
        observation = json.loads((self.session/record.observation).read_text())
        self.assertEqual(observation['metrics']['fatal_signals'], 3)
        self.assertFalse(observation['goal_reached'])
        self.controller.verify()

    def test_fresh_attempt_still_fails_on_guest_signal(self):
        self.complete()
        self.assertEqual(self.controller.load().state, SessionState.FAILED)
        self.assertEqual(self.controller.load().stop_reason, StopReason.EXECUTION_CRASHED)

    def test_individual_case_cannot_inherit_parent_success(self):
        self.warm_evidence()
        runtime = json.loads((self.artifacts/'config/runtime.json').read_text())
        runtime['afl_case'] = {'case': '00000000'}
        self.save('config/runtime.json', runtime)
        self.complete()
        self.assertEqual(self.controller.load().stop_reason, StopReason.EXECUTION_CRASHED)

    def test_unverified_or_failed_capsule_cannot_hide_child_or_parent_failure(self):
        self.warm_evidence()
        for key, bad in (
            ('status', 'failed'), ('qemu_exit', 86), ('qemu_exit', False),
            ('controller_exit', 1), ('supervisor_kill', True),
            ('controller_failures', [{'message': 'lost'}]),
            ('attempt_id', 'stale'), ('attempt_contract_sha256', '0'*64),
            ('bundle_sha256', '0'*64), ('restart', 'new_original_elf_attempt'),
            ('warm', {'status': 'failed', 'phase1_runs': 1, 'children': 65}),
            ('warm', {'status': 'passed', 'phase1_runs': 2, 'children': 65}),
            ('warm', {'status': 'passed', 'phase1_runs': 1, 'children': True}),
            ('phase1_retirement', {'status': 'verified', 'phase1_retired': False}),
            ('resources', {'status': 'verified', 'tree_empty': False}),
            ('hardening', {'status': 'failed'}),
            ('hardening', None), ('warm', []), ('resources', 'verified'),
        ):
            with self.subTest(key=key, bad=bad):
                self.save('config/capsule_result.json', self.capsule | {key: bad})
                with self.assertRaisesRegex(IterationControllerError, 'warm coordinator'):
                    self.complete()
                self.assertFalse((self.session/'iterations/0000/artifacts').exists())

    def test_incomplete_finalization_is_not_treated_as_success(self):
        self.warm_evidence()
        bad = copy.deepcopy(self.finalization)
        bad['stages']['syscalls']['status'] = 'failed'
        self.save('config/finalization_status.json', bad)
        with self.assertRaisesRegex(IterationControllerError, 'warm coordinator'):
            self.complete()

    def test_missing_capsule_evidence_is_not_treated_as_success(self):
        self.warm_evidence()
        (self.artifacts/'config/capsule_result.json').unlink()
        with self.assertRaises(IterationControllerError):
            self.complete()

    def test_m5_profile_cannot_inherit_a_legacy_completion_record(self):
        from taintforge_env.afl_capsule import PROFILE
        self.warm_evidence()
        runtime=json.loads((self.artifacts/'config/runtime.json').read_text())
        runtime['afl_warm']['capsule_profile']=PROFILE
        self.save('config/runtime.json',runtime)
        binding=json.loads((self.artifacts/'config/capsule_binding.json').read_text())
        binding['afl_warm']=runtime['afl_warm']
        self.save('config/capsule_binding.json',binding)
        with self.assertRaises(IterationControllerError):self.complete()

    def test_malformed_warm_configuration_is_rejected_and_temporary_copy_removed(self):
        self.warm_evidence()
        runtime = json.loads((self.artifacts/'config/runtime.json').read_text())
        good = runtime['afl_warm']
        for bad in (None, [], {}, good | {'campaign_root': 1}, good | {'extra': True},
                    good | {'phase2': {'mode': [], 'pending': 4}}):
            with self.subTest(config=bad):
                self.save('config/runtime.json', runtime | {'afl_warm': bad})
                with self.assertRaises(IterationControllerError):
                    self.complete()
                self.assertFalse((self.session/'iterations/0000/.artifacts.tmp').exists())
                self.assertFalse((self.session/'iterations/0000/artifacts').exists())

    def test_missing_or_malformed_controller_failures_cannot_prove_completion(self):
        self.warm_evidence()
        for bad in (None, False, 0, {}, ''):
            with self.subTest(controller_failures=bad):
                self.save('config/capsule_result.json', self.capsule | {'controller_failures': bad})
                with self.assertRaises(IterationControllerError):
                    self.complete()

    def test_missing_controller_failures_cannot_prove_completion(self):
        self.warm_evidence()
        self.capsule.pop('controller_failures')
        self.save('config/capsule_result.json', self.capsule)
        with self.assertRaises(IterationControllerError):
            self.complete()


if __name__ == '__main__':
    unittest.main()
