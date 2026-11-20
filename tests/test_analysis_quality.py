"""Admission, permit ordering and independent finalization checks."""
import copy
import json
import os
from pathlib import Path
import shutil
import struct
import sys
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from scripts.run_unified_pipeline import parser, prepare
from taintforge_env import analysis_quality as q, input_retirement as m3
from taintforge_env import phase1_retirement as r, retirement_evidence
from taintforge_env.phase1_runtime import read_json
from tests import test_input_retirement as base

ORIGINAL_EVIDENCE = base.synthetic_evidence


def denied_evidence(run, code, fault=None, *, builder=ORIGINAL_EVIDENCE):
    binding, result = builder(run, code, fault)
    directory = r.directory(binding)
    path = directory/'retirement.json'
    saved = read_json(path)
    saved.update(status='analysis_rejected', events=saved['events'][:2], permit_sent=False,
                 permit='DENY\n', stream_closed=True)
    for key in ('preserved_sha256', 'accepted_manifest_sha256', 'permit_after_verified_export'):
        del saved[key]
    r.probe.write_json(path, saved)
    shutil.rmtree(directory/'export')
    for name in ('maps-2.txt', 'process-2.stat', 'maps-unmapped.txt', 'process-unmapped.stat'):
        (directory/name).unlink()
    (run/'logs/capsule/execution-context-2.json').unlink(missing_ok=True)
    journal_path = run/'logs/capsule/observer-events.json'
    journal = read_json(journal_path); journal['events'] = journal['events'][:6]
    r.probe.write_json(journal_path, journal)
    r.probe.write_json(run/'logs/capsule/controller.json', {'status': 'failed'})
    result['status'] = 'failed'
    r.probe.write_json(run/'logs/capsule/supervisor.json', result)
    return binding, result


class AnalysisPolicyTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.run = SimpleNamespace(paths={'ir': self.root/'ir.jsonl', 'manifest': self.root/'manifest.json'},
            runtime=SimpleNamespace(build_id='a'*64, plugin_sha256='b'*64, manifest_sha256='c'*64))
        self.binding = dict(session_id='s', attempt_id='a', analysis_instance_id='i',
            lifecycle_attempt='1'*32, run_dir=str(self.root), settings={'analysis_policy': q.policy()})
        self.verified = {'analysis_status': 'observed', 'stream_status': 'completed', 'capture_status': 'success'}
        self.summary = dict(trace_dropped=0, trace_incomplete=0, flags_verified=True,
            shadow_knowledge_valid=True, ir_matches=1, ir_mismatches=0, ir_unknown=0,
            ir_errors=0, ir_skipped_budget=0)
        self.stream = [
            {'event_type': 'analysis_started', 'status': 'observing', 'data': {
                'profile': 'linux-i386-single-thread-v1', 'ir_enabled': True,
                'flags_contract': 'taintforge_x86_flags_v1'}},
            {'event_type': 'runtime_observation', 'status': 'observed', 'data': {'kind': 'instruction_callback'}},
            {'event_type': 'oep_candidate_selected', 'status': 'candidate', 'incomplete_reasons': [],
             'data': {'candidate_id': 1, 'dse_verdict': 'CONFIRMED', 'dse_reason': 'NONE'}},
            {'event_type': 'oep_verdict', 'status': 'selected_candidate', 'data': {}},
            {'event_type': 'analysis_summary', 'status': 'observed', 'data': self.summary},
            {'event_type': 'analysis_finished', 'status': 'completed', 'data': {
                'capture_status': 'success', 'storage_status': 'ok', 'dropped_events': 0}}]
        self.write_ir()

    def write_ir(self, status='MATCH'):
        key = {'MATCH': 'matches', 'MISMATCH': 'mismatches', 'UNKNOWN': 'unknown', 'ERROR': 'errors'}[status]
        ir = {'schema': 1, 'event': 'summary', 'checks': 1, **dict.fromkeys(q.IR_COUNTERS, 0)}
        ir[key] = 1
        ir['skipped_budget'] = self.summary['ir_skipped_budget']
        self.run.paths['ir'].write_text(json.dumps({'schema': 1, 'event': 'check', 'status': status})+'\n'+json.dumps(ir)+'\n')
        r.probe.write_json(self.run.paths['manifest'], {'analysis_status': self.verified['analysis_status'],
            'artifacts': {'ir': {'sha256': r.probe.sha(self.run.paths['ir'])}}})

    def partial(self):
        self.verified.update(analysis_status='partial', stream_status='partial')
        self.stream[0]['data']['flags_contract'] = 'unverified'
        self.stream[-2]['status'] = self.stream[-1]['status'] = 'partial'
        self.summary.update(flags_verified=False, trace_incomplete=1, ir_matches=0, ir_unknown=1)
        self.stream[2]['data'].update(dse_verdict='UNKNOWN', dse_reason='UNSUPPORTED_INSN')
        self.stream[2]['incomplete_reasons'] = ['dse_incomplete']
        self.write_ir('UNKNOWN')

    def assess(self, mode='strict'):
        self.binding['settings']['analysis_policy'] = q.policy(mode)
        return q.assess(self.binding, self.run, self.verified, self.stream)

    def test_strict_acceptance_never_promotes_global_proof(self):
        result = self.assess()
        self.assertEqual(result['status'], 'accepted')
        self.assertEqual(result['limitations'], [])
        self.assertFalse(result['oep_proven'])
        self.assertFalse(result['complete_program_analysis'])
        self.assertEqual(result['ir_scope'], 'selected_trace_window_only')

    def test_partial_is_explicitly_research_only(self):
        self.partial()
        strict, research = self.assess(), self.assess('research')
        self.assertEqual(strict['status'], 'rejected')
        self.assertEqual(research['status'], 'accepted')
        self.assertEqual(strict['facts'], research['facts'])
        self.assertIn('unverified_flags', research['limitations'])
        self.assertIn('unknown_candidate_analysis', research['limitations'])

    def test_both_modes_reject_loss_invalid_shadow_and_refutation(self):
        for target, key, value, reason in (
            (self.summary, 'trace_dropped', 1, 'analysis_evidence_lost'),
            (self.stream[-1]['data'], 'dropped_events', 1, 'analysis_evidence_lost'),
            (self.summary, 'shadow_knowledge_valid', False, 'invalid_shadow_knowledge'),
            (self.stream[2]['data'], 'dse_verdict', 'REFUTED', 'candidate_refuted')):
            original = target[key]
            for mode in q.MODES:
                with self.subTest(key=key, mode=mode):
                    target[key] = value
                    self.assertIn(reason, self.assess(mode)['rejection_reasons'])
            target[key] = original
        for kind in ('profile_lost', 'data_loss', 'error', 'analysis_invalidated'):
            self.stream.insert(1, {'event_type': kind, 'data': {}, 'status': 'error'})
            for mode in q.MODES:
                self.assertIn('analysis_evidence_lost', self.assess(mode)['rejection_reasons'])
            self.stream.pop(1)

    def test_ir_mismatch_and_error_cannot_be_accepted_as_research(self):
        for status, key in (('MISMATCH', 'ir_mismatches'), ('ERROR', 'ir_errors')):
            self.summary.update(ir_matches=0)
            self.summary[key] = 1
            self.write_ir(status)
            for mode in q.MODES:
                self.assertIn('ir_failure', self.assess(mode)['rejection_reasons'])
            self.summary[key] = 0

    def test_dse_replay_failure_is_not_an_allowed_unknown(self):
        self.partial()
        self.stream[2]['data']['dse_reason'] = 'REPLAY_MISMATCH'
        for mode in q.MODES:
            self.assertIn('candidate_analysis_failure', self.assess(mode)['rejection_reasons'])

    def test_unknown_and_skipped_checks_are_not_strict(self):
        self.summary.update(ir_matches=0, ir_unknown=1, ir_skipped_budget=2)
        self.write_ir('UNKNOWN')
        self.assertEqual(self.assess('research')['status'], 'accepted')
        strict = self.assess()
        self.assertIn('unknown_ir', strict['rejection_reasons'])
        self.assertIn('ir_budget_skipped', strict['rejection_reasons'])

    def test_missing_malformed_and_disagreeing_ir_are_rejected(self):
        original = self.run.paths['ir'].read_bytes()
        for value in (b'', original.rstrip(), original+original, b'{"schema":1,"schema":1}\n',
                      original.replace(b'"matches": 1', b'"matches": true'),
                      original.replace(b'"checks": 1', b'"checks": 2')):
            with self.subTest(value=value[:50]):
                self.run.paths['ir'].write_bytes(value)
                self.assertEqual(self.assess('research')['rejection_reasons'], ['invalid_quality_evidence'])
        self.run.paths['ir'].unlink()
        self.assertEqual(self.assess('research')['status'], 'rejected')

    def test_summary_types_flags_and_order_cannot_silently_downgrade(self):
        self.summary['trace_incomplete'] = True
        self.assertEqual(self.assess('research')['rejection_reasons'], ['invalid_quality_evidence'])
        self.summary['trace_incomplete'] = 0
        self.summary['flags_verified'] = False
        self.assertEqual(self.assess('research')['rejection_reasons'], ['invalid_quality_evidence'])
        self.summary['flags_verified'] = True
        self.stream[3], self.stream[4] = self.stream[4], self.stream[3]
        self.assertEqual(self.assess('research')['rejection_reasons'], ['invalid_quality_evidence'])

    def test_policy_and_saved_decision_have_exact_types_and_binding(self):
        for config in (q.policy()|{'schema': True}, q.policy()|{'mode': 'allow-any'}, q.policy()|{'extra': True}):
            with self.assertRaises(RuntimeError): q.validate(config)
        expected = self.assess()
        saved = {'analysis_quality': expected, 'export_verification': {'analysis_quality': expected}}
        q.verify_saved(self.binding, {'analysis_quality': expected}, saved)
        for changes in ({'oep_proven': 0}, {'identity': expected['identity']|{'attempt_id': 'old'}},
                        {'export_manifest_sha256': '0'*64}, {'policy': q.policy('research')},
                        {'facts': expected['facts']|{'flags_verified': 1}}):
            bad = copy.deepcopy(saved)
            bad['analysis_quality'].update(changes)
            with self.assertRaisesRegex(RuntimeError, 'Saved analysis decision'):
                q.verify_saved(self.binding, {'analysis_quality': expected}, bad)

    def test_cli_rejects_policy_without_retirement_before_creating_output(self):
        out = self.root/'new'
        args = parser().parse_args(['run', '--out', str(out), '--analysis-policy', 'research'])
        with self.assertRaisesRegex(ValueError, '--analysis-policy requires'):
            prepare(args)
        self.assertFalse(out.exists())
        old = m3.settings()
        self.assertNotIn('analysis_policy', old)
        m3.validate_settings(old)
        m3.validate_settings(m3.settings(analysis_policy=q.policy()))

    def test_afl_cli_forwards_explicit_policy_without_weakening_default(self):
        from scripts.run_afl_file import main
        for mode in ('fresh', 'warm'):
            target = 'taintforge_env.afl_file.prepare_campaign' if mode == 'fresh' else 'taintforge_env.afl_strict.prepare_campaign'
            for requested in (None, 'research'):
                argv = ['run_afl_file', 'prepare', '--mode', mode, '--out', str(self.root/'campaign'),
                        '--binary', 'guest', '--qemu', 'qemu', '--plugin', 'plugin', '--seeds', 'seeds',
                        '--guest-file', '/etc/input']
                if requested: argv += ['--analysis-policy', requested]
                with patch.object(sys, 'argv', argv), patch(target, return_value={}) as prepare_campaign, \
                     patch('builtins.print'):
                    self.assertEqual(main(), 0)
                    self.assertEqual(prepare_campaign.call_args.kwargs['analysis_policy'], requested or 'strict')

    def worker(self, *, reject=False, change_after_copy=False):
        if reject: self.partial()
        decision = self.assess()
        self.binding['settings'].update(total_ms=30000, phase1_retirement={'fault': 'none'})
        output = r.directory(self.binding); output.mkdir(parents=True)
        payloads = [{'candidate_id': 1}, {}, {}, {}, dict(pages_released=1, bitmaps_released=1,
            register_buffers_released=1, explicitly_wiped_bytes=1, owner_roots_remaining=0,
            all_bytes_zeroed=False, allocator_residue_verified=False, guest_memory_modified=False)]
        packets = [dict(protocol=1, event=name, nonce=self.binding['lifecycle_attempt'], host_pid=77,
                   **{k: self.binding[k] for k in ('session_id', 'attempt_id', 'analysis_instance_id')}, data=data)
                   for name, data in zip(r.EVENTS, payloads)]
        connection, listener, pipe, progress = Mock(), Mock(), Mock(), Mock()
        connection.recv.side_effect = [json.dumps(item).encode() for item in packets[:2 if reject else 5]]+[b'']
        connection.getsockopt.return_value = struct.pack('3i', 77, os.geteuid(), 0)
        listener.accept.return_value = (connection, None)
        pipe.recv.return_value = 77
        progress.recv.return_value = 'grant'
        verified = {'analysis_quality': decision}
        responses = [(self.run, verified)]
        if not reject:
            second = copy.deepcopy(verified)
            if change_after_copy: second['analysis_quality']['facts']['trace_incomplete'] = 1
            responses.append((self.run, second))
        def send(command):
            saved = read_json(output/'retirement.json')
            self.assertEqual(saved['analysis_quality'], decision)
            self.assertEqual(saved['permit_sent'], False)
        connection.sendall.side_effect = send
        with patch.object(r.socket, 'socket', return_value=listener), patch.object(r.os, 'chmod'), \
             patch.object(r, 'verify_export', side_effect=responses), \
             patch.object(r, 'preserve_export', return_value={}) as preserve:
            r.permit_worker(self.root/'socket', pipe, self.binding, progress_pipe=progress)
        return read_json(output/'retirement.json'), connection, progress, preserve

    def test_rejection_is_saved_before_deny_and_never_grants_progress(self):
        saved, connection, progress, preserve = self.worker(reject=True)
        self.assertEqual(saved['status'], 'analysis_rejected')
        self.assertFalse(saved['permit_sent'])
        connection.sendall.assert_called_once_with(b'DENY\n')
        progress.send.assert_not_called()
        preserve.assert_not_called()
        self.assertEqual(len(saved['events']), 2)

    def test_accepted_decision_precedes_real_permit_path(self):
        saved, connection, progress, preserve = self.worker()
        self.assertEqual(saved['status'], 'released', saved.get('error'))
        self.assertTrue(saved['permit_sent'])
        self.assertTrue(connection.sendall.call_args.args[0].startswith(b'RETIRE '))
        self.assertEqual([call.args[0] for call in progress.send.call_args_list], ['export_ready', 'released'])
        preserve.assert_called_once()

    def test_changed_decision_after_copy_never_receives_permit(self):
        saved, connection, progress, _ = self.worker(change_after_copy=True)
        self.assertEqual(saved['status'], 'failed')
        self.assertFalse(saved['permit_sent'])
        connection.sendall.assert_not_called()
        progress.send.assert_not_called()


class QualityIntegrationTests(unittest.TestCase):
    setUp = base.InputRetirementTests.setUp
    prepare_input = base.InputRetirementTests.prepare_input
    invoke = base.InputRetirementTests.invoke

    def test_new_cli_default_is_strict_and_refusal_blocks_resume(self):
        out, launch = self.prepare_input(analysis_policy=None)
        runtime = read_json(Path(launch['template_run_dir'])/'config/runtime.json')
        self.assertEqual(runtime['capsule']['analysis_policy'], q.policy('strict'))
        executor = base.InputExecutor(fault='analysis')
        with patch.object(base, 'synthetic_evidence', side_effect=denied_evidence):
            report, code = self.invoke(out, launch, executor)
        self.assertEqual(code, 1)
        self.assertEqual(report['analysis_quality']['status'], 'rejected')
        self.assertIn('partial_analysis', report['analysis_quality']['rejection_reasons'])
        checked = retirement_evidence.verify(executor.runs[0][0]/'retirement-evidence')
        self.assertEqual(checked['attempt_outcome'], 'failed')
        self.assertEqual(checked['phase1_retirement']['status'], 'denied')
        resumed, code = self.invoke(out, launch, executor)
        self.assertEqual(code, 1)
        self.assertEqual(resumed['executions_this_invocation'], 0)
        self.assertEqual(len(executor.runs), 1)

    def test_research_repair_has_fresh_decisions_and_relocated_proof(self):
        out, launch = self.prepare_input()
        executor = base.InputExecutor(repair=True)
        report, code = self.invoke(out, launch, executor, steps=2)
        self.assertEqual(code, 0, report.get('error'))
        self.assertEqual(len(executor.runs), 2)
        decisions = []
        for run, binding, _ in executor.runs:
            with tempfile.TemporaryDirectory() as tmp:
                moved = Path(tmp)/'moved'
                shutil.copytree(run/'retirement-evidence', moved)
                checked = retirement_evidence.verify(moved)
                decisions.append(checked['analysis_quality'])
                self.assertEqual(checked['analysis_quality']['status'], 'accepted')
                self.assertFalse(checked['analysis_quality']['oep_proven'])
        self.assertNotEqual(decisions[0]['identity'], decisions[1]['identity'])
        self.assertNotEqual(decisions[0]['export_manifest_sha256'], decisions[1]['export_manifest_sha256'])

    def test_guest_exit_88_after_retirement_is_not_an_analysis_denial(self):
        out, launch = self.prepare_input()
        executor = base.InputExecutor(exit_code=88)
        report, _ = self.invoke(out, launch, executor)
        self.assertEqual(report['capsule']['status'], 'passed', report.get('error'))
        self.assertTrue(report['capsule']['phase1_retirement']['phase1_retired'])
        self.assertEqual(report['analysis_quality']['status'], 'accepted')
        self.assertEqual(retirement_evidence.verify(executor.runs[0][0]/'retirement-evidence')['attempt_outcome'], 'passed')

    def test_portable_tamper_is_rejected_after_inventory_rehash(self):
        out, launch = self.prepare_input()
        executor = base.InputExecutor()
        report, code = self.invoke(out, launch, executor)
        self.assertEqual(code, 0, report.get('error'))
        run = executor.runs[0][0]
        with tempfile.TemporaryDirectory() as tmp:
            moved = Path(tmp)/'moved'; shutil.copytree(run/'retirement-evidence', moved)
            saved_path = moved/'logs/capsule/phase1-retirement/retirement.json'
            saved = read_json(saved_path)
            saved['analysis_quality']['facts']['flags_verified'] = True
            r.probe.write_json(saved_path, saved)
            inventory = read_json(moved/'bundle.json')
            for item in inventory['files']:
                path = moved/item['path']; item.update(size=path.stat().st_size, sha256=r.probe.sha(path))
            r.probe.write_json(moved/'bundle.json', inventory)
            with self.assertRaisesRegex(RuntimeError, 'Saved analysis decision'):
                retirement_evidence.verify(moved, expected_sha256=r.probe.sha(moved/'bundle.json'))

    def test_bound_policy_cannot_change_on_resume(self):
        out, launch = self.prepare_input()
        executor = base.InputExecutor(repair=True)
        report, code = self.invoke(out, launch, executor)
        self.assertEqual(code, 0, report.get('error'))
        binding = read_json(out/'session/synthesis_loop.json')
        self.assertIn(str(Path(q.__file__).resolve()), {item['path'] for item in binding['analysis_stack_files']})
        path = out/'template/config/runtime.json'
        runtime = read_json(path)
        runtime['capsule']['analysis_policy'] = q.policy('strict')
        r.probe.write_json(path, runtime)
        resumed, code = self.invoke(out, launch, executor)
        self.assertEqual(code, 1)
        self.assertIsNone(resumed['executions_this_invocation'])
        self.assertEqual(len(executor.runs), 1)

    def test_collector_replays_relocated_success_and_denial(self):
        from scripts import collect_capsule_analysis_evidence as collector
        from scripts.run_capsule_analysis_e2e import CASES
        from scripts.run_capsule_analysis_tests import SOURCES
        from tests import test_capsule_control as control
        root = self.base
        sidecar = Path(str(self.plugin)+'.runtime.json')
        data = read_json(sidecar)
        data['resource_ledger'] = {'schema': 1, 'scope': 'explicit_project_allocations',
                                  'external_allocations_tracked': False}
        r.probe.write_json(sidecar, data)
        profile = m3.bundle_profile
        def built(value):
            value = copy.deepcopy(value); value['source_sha256']['control_guard.h'] = 'c'*64
            return profile(value)
        cases = []
        for name in CASES:
            denied, repair = name == 'strict-reject', name == 'research-repair'
            with patch.object(m3, 'bundle_profile', side_effect=built):
                out, launch = self.prepare_input(name='e2e/'+name,
                    extra=('--capsule-hardening', '--capsule-control-guard'),
                    analysis_policy='strict' if denied else 'research')
            executor = base.InputExecutor(fault='analysis' if denied else None, repair=repair)
            builder = (lambda *a: denied_evidence(*a, builder=control.guarded_evidence)) if denied else control.guarded_evidence
            with patch.object(base, 'synthetic_evidence', side_effect=builder):
                report, code = self.invoke(out, launch, executor, steps=2 if repair else 1)
            self.assertEqual(code, 1 if denied else 0, report.get('error'))
            attempts = []
            for run, _, _ in executor.runs:
                capsule = read_json(run/'config/capsule_result.json')
                attempts.append({'bundle_sha256': capsule['portable_evidence']['manifest_sha256'],
                    'analysis_quality': capsule['analysis_quality'],
                    'execution_claim_sha256': r.probe.sha(run.parent/'execution_attempt.json')})
            if denied:
                resumed, _ = self.invoke(out, launch, executor)
                r.probe.write_json(out/'resume_report.json', resumed)
                cases.append({'name': name, 'status': 'passed', **attempts[0],
                              'claim_sha256': attempts[0]['execution_claim_sha256']})
            else:
                cases.append({'name': name, 'status': 'passed', 'attempts': attempts})
        project = Path(__file__).resolve().parents[1]
        (root/'validation').mkdir()
        r.probe.write_json(root/'validation/analysis-tests.json', {'successful': True,
            'tests_run': 22, 'tests_expected': 22, 'skipped': 0, 'failures': 0, 'errors': 0,
            'source_sha256': {name: r.probe.sha(project/name) for name in SOURCES}})
        for name in ('analysis-tests.log', 'm5.log', 'e2e.log'):
            (root/'validation'/name).write_text('synthetic test fixture\n')
        (root/'e2e/inputs').mkdir()
        r.probe.write_json(root/'e2e/inputs/build.json', {})
        hashes = {'qemu_sha256': r.probe.sha(self.qemu), 'phase1_sha256': r.probe.sha(self.plugin)}
        (root/'m5/e2e').mkdir(parents=True)
        r.probe.write_json(root/'m5/e2e/report.json', hashes)
        r.probe.write_json(root/'e2e/report.json', {'profile': q.PROFILE, 'status': 'passed',
            'runtime_unchanged': True, 'oep_proven': False, 'complete_program_analysis': False,
            'hostile_sample_ready': False, 'cases': cases, **hashes,
            'input_build_sha256': r.probe.sha(root/'e2e/inputs/build.json')})
        with patch.object(collector.m5, 'check_results'):
            collected = collector.collect(root, 0)
            self.assertTrue(collected['complete'], collected)
            with tempfile.TemporaryDirectory() as tmp:
                with tarfile.open(collected['archive']) as stream:
                    stream.extractall(tmp, filter='data')
                moved = Path(tmp)/'evidence'
                collector.check_results(moved)
                report = read_json(moved/'e2e/report.json')
                report['cases'][-1]['analysis_quality']['status'] = 'accepted'
                r.probe.write_json(moved/'e2e/report.json', report)
                with self.assertRaisesRegex(RuntimeError, 'policy or outcome changed'):
                    collector.check_results(moved)


class CollectionTests(unittest.TestCase):
    def test_incomplete_run_preserves_exit_and_inventory(self):
        from scripts.collect_capsule_analysis_evidence import collect
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); (root/'validation').mkdir()
            (root/'validation/failure.log').write_text('controlled refusal\n')
            result = collect(root, 42)
            self.assertFalse(result['complete'])
            with tarfile.open(result['archive']) as stream:
                record = json.load(stream.extractfile('evidence/collection.json'))
            self.assertEqual(record['command_exit_code'], 42)
            self.assertFalse(record['complete'])
            self.assertTrue(record['missing_required'])

    def test_archive_cannot_follow_a_nested_symlink(self):
        from scripts.collect_capsule_analysis_evidence import collect
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); (root/'validation').mkdir()
            (root/'validation/failure.log').symlink_to('/etc/passwd')
            with self.assertRaisesRegex(RuntimeError, 'Symlink'):
                collect(root, 42)


if __name__ == '__main__':
    unittest.main()
