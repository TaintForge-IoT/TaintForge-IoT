"""Exercise FIFO batching with real queue journals and controlled DSE results."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from taintforge_env import dta_dse_eval as evaluator, dta_dse_queue as queue
from taintforge_env.elf_runtime import canonical_hash


class QueueBatchTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.runtime = {name: self.root / name for name in ('qemu', 'plugin', 'flags_receipt')}
        for path in (*self.runtime.values(), self.root / 'plugin.runtime.json'):
            path.write_bytes(path.name.encode())
        self.analysis = self.root / 'analysis'
        self.analysis.mkdir()
        requests = []
        for index in range(1, 19):
            request = {'index': index, 'observed_site': {'vcpu': 0, 'pc': 0x8049000 + index,
                                                        'occurrence': 1, 'offsets': [0]},
                       'desired_outcome': 'taken',
                       'opposite_observed_elsewhere': False}
            requests.append(dict(request, request_id=canonical_hash(request)))
        self.requests = {request['request_id']: request for request in requests}
        self.source = {
            'handoff': {'analysis': str(self.analysis), 'status': 'AUDITED_DTA_CORPUS_AND_RECAPTURE_HINTS'},
            'requests': requests, 'seeds': {queue._sha(b'initial'): b'initial'},
            'scope': {'target_sha256': queue._sha(b'target')},
        }
        self.started = []
        self.produce_candidates = True
        self.enterContext(patch.object(queue, '_source_audit', return_value=self.source))
        self.worker = self.enterContext(patch.object(queue.dta_dse, 'extend_corpus',
                                                     side_effect=self.extend))
        self.auditor = self.enterContext(patch.object(queue.dta_dse, 'audit_selected_corpus',
                                                      side_effect=self.audit))

    def extend(self, *, out, request_ids, **kwargs):
        request_id, = request_ids
        self.started.append(request_id)
        index = self.requests[request_id]['index']
        report = {'status': 'passed', 'request_id': request_id, 'jobs': [],
                  'dse_status': 'VERIFIED' if self.produce_candidates and index % 3 == 0 else 'NOT_ESTABLISHED'}
        out.mkdir()
        queue._json(out / 'summary.json', report)
        queue._json(out / 'manifest.json', {'index': index})
        (out / 'evidence.bin').write_bytes(bytes([index]))
        return report

    def audit(self, *, directory, request_id, **kwargs):
        directory = Path(directory)
        report = queue._read(directory / 'summary.json')
        request = self.requests[request_id]
        if (directory / 'evidence.bin').read_bytes() != bytes([request['index']]):
            raise ValueError('Attempt evidence changed')
        self.assertEqual(report['request_id'], request_id)
        self.assertEqual(queue._read(directory / 'manifest.json'), {'index': request['index']})
        seeds = dict(self.source['seeds'])
        if report['dse_status'] == 'VERIFIED':
            seed = bytes([request['index']])
            seeds[queue._sha(seed)] = seed
        handoff = dict(self.source['handoff'], analysis=str(kwargs.get('analysis', self.analysis)))
        return {'report': report, 'seeds': seeds, 'request': request, 'handoff': handoff}

    def new_queue(self, name):
        path = self.root / name
        queue.create_queue(queue=path, max_total_starts=16, **self.runtime)
        queue.enqueue_analyses(queue=path, analyses=[self.analysis])
        return path

    def test_batch_preserves_fifo_and_committed_results(self):
        results = []
        for batch_size in (1, 16):
            with self.subTest(batch_size=batch_size):
                path = self.new_queue(f'queue-{batch_size}')
                self.started.clear()
                completed = []

                def record(identifier, duration):
                    row = queue._read(path / 'state.json')['jobs'][identifier]
                    self.assertIn(row['status'], ('VERIFIED', 'NONPROOF'))
                    self.assertEqual(row['attempts'][0]['status'], 'COMPLETED')
                    self.assertGreaterEqual(duration, 0)
                    completed.append(row['request_id'])

                audit_count = self.auditor.call_count
                with patch.object(queue, '_audit_locked', wraps=queue._audit_locked) as boundary_audit:
                    for _ in range(16 // batch_size):
                        result = queue.run_queue(queue=path, max_jobs=batch_size, on_job_complete=record)
                    self.assertEqual(boundary_audit.call_count, 16 if batch_size == 1 else 2)
                self.assertEqual(self.auditor.call_count - audit_count, 256 if batch_size == 1 else 32)
                self.assertEqual(completed, list(self.requests)[:16])
                self.assertEqual(self.started, completed)
                self.assertEqual(result['counts']['PENDING'], 2)
                final = queue.audit_queue(queue=path)
                self.assertTrue(final['evidence_audited'])
                self.assertEqual(final['counts']['VERIFIED'], 5)
                self.assertEqual(final['counts']['NONPROOF'], 11)
                journal = queue._read(path / 'state.json')
                outcomes = [(journal['jobs'][job]['request_id'], journal['jobs'][job]['status'])
                            for job in journal['order']]
                corpus = queue._read(path / 'corpus.json')['seeds']
                results.append((outcomes, corpus))
        self.assertEqual(*results)

    def test_batch_exit_and_resume_check_changed_attempt_evidence(self):
        path = self.new_queue('changed-history')
        completed = []

        def tamper_after_first_job(identifier, _duration):
            completed.append(identifier)
            if len(completed) == 1:
                state = queue._read(path / 'state.json')
                attempt = Path(state['jobs'][identifier]['attempts'][0]['directory'])
                (attempt / 'evidence.bin').write_bytes(b'changed')

        with self.assertRaisesRegex(RuntimeError, 'Previously completed queue evidence no longer audits'):
            queue._run_queue(queue=path, max_jobs=3, on_job_complete=tamper_after_first_job, include_exit_audit=True)
        self.assertEqual(len(completed), 3)
        for audit in (queue.audit_queue, lambda **kw: queue.run_queue(max_jobs=3, **kw)):
            with self.assertRaisesRegex(RuntimeError, 'Previously completed queue evidence no longer audits'):
                audit(queue=path)
        self.assertEqual(self.started, list(self.requests)[:3])

    def test_evaluator_uses_the_full_batch_by_default(self):
        binary, seed = self.root / 'target', self.root / 'initial'
        binary.write_bytes(b'target')
        seed.write_bytes(b'initial')
        self.produce_candidates = False

        def analyze(*, binary, seed, input_path, argv, out, **kwargs):
            saved = dict(inputs={name: queue._pin(path, 4096)[1]
                                 for name, path in (('binary', binary), ('seed', seed))},
                         input_path=input_path, argv=argv, runs=[{'observed_branch_outcomes': []}],
                         concrete_runs=2, candidate_count=1, new_branch_outcomes=0)
            out.mkdir(parents=True)
            queue._json(out / 'summary.json', saved)
            return saved

        def source_audit(analysis, max_sites):
            return dict(self.source, handoff=dict(self.source['handoff'], analysis=str(analysis)))

        handoff = {'accepted_seeds': [{'sha256': seed_hash} for seed_hash in self.source['seeds']]}
        with (patch.object(evaluator.dta_analysis, 'analyze_file', side_effect=analyze),
              patch.object(queue, '_audit_queue', wraps=queue._audit_queue) as audits,
              patch.object(evaluator, '_saved_analysis', side_effect=lambda _, saved, **kw: (saved, handoff, (b'', 0))),
              patch.object(queue, '_source_audit', side_effect=source_audit),
              patch('builtins.print')):
            scenarios = (
                ('single', {'queue_batch_size': 1}, 16, 288, [True, False]),
                ('batch', {}, 1, 48, [False]),
                ('two-batches', {'queue_batch_size': 8}, 2, 64, [False]),
                ('short-tail', {'queue_batch_size': 5}, 4, 123, [True, False]),
            )
            for name, options, calls, attempt_audits, details in scenarios:
                with self.subTest(mode=name):
                    audits.reset_mock()
                    self.auditor.reset_mock()
                    out = self.root / name
                    report = evaluator.evaluate_file(binary=binary, seeds=[seed], input_path='/etc/dta-input',
                                                     out=out, max_jobs=16, **self.runtime, **options)
                    self.assertTrue(report['measurement_completed'])
                    self.assertEqual(report['queue_invocations'], calls)
                    self.assertEqual(report['nonproof_jobs'], 16)
                    self.assertEqual(len(queue._read(out / 'job-timings.json')), 16)
                    self.assertEqual({file.name for file in (out / 'seeds').iterdir()}, set(self.source['seeds']))
                    self.assertEqual([call.kwargs['include_attempts'] for call in audits.call_args_list],
                                     details)
                    self.assertEqual(self.auditor.call_count, attempt_audits)

    def test_evaluator_audits_empty_queue_when_no_jobs_are_run(self):
        binary, seed = self.root / 'target', self.root / 'initial'
        binary.write_bytes(b'target')
        seed.write_bytes(b'initial')
        out = self.root / 'no-jobs'
        self.source['requests'] = []
        handoff = {'accepted_seeds': [{'sha256': queue._sha(b'initial')}]}

        def analyze(*, binary, seed, input_path, argv, out, **kwargs):
            saved = dict(inputs={name: queue._pin(path, 4096)[1]
                                 for name, path in (('binary', binary), ('seed', seed))},
                         input_path=input_path, argv=argv, runs=[{'observed_branch_outcomes': []}],
                         concrete_runs=2, candidate_count=1, new_branch_outcomes=0)
            out.mkdir(parents=True)
            queue._json(out / 'summary.json', saved)
            return saved

        def source_audit(analysis, max_sites):
            return dict(self.source, handoff=dict(self.source['handoff'], analysis=str(analysis)))

        with (patch.object(evaluator.dta_analysis, 'analyze_file', side_effect=analyze),
              patch.object(evaluator, '_saved_analysis', side_effect=lambda _, saved, **kw: (saved, handoff, (b'', 0))),
              patch.object(queue, '_source_audit', side_effect=source_audit),
              patch.object(queue, '_audit_queue', wraps=queue._audit_queue) as audits,
              patch('builtins.print')):
            report = evaluator.evaluate_file(binary=binary, seeds=[seed], input_path='/etc/dta-input',
                                             out=out, max_jobs=16, **self.runtime)
        self.assertTrue(report['measurement_completed'])
        self.assertEqual(report['queue_invocations'], 0)
        self.assertEqual(report['jobs'], [])
        self.assertEqual([call.kwargs['include_attempts'] for call in audits.call_args_list], [True, False])
        self.assertEqual((out / 'seeds' / queue._sha(b'initial')).read_bytes(), b'initial')

    def _evaluate_with_candidate(self, *, change_attempt):
        binary, seed = self.root / 'target', self.root / 'initial'
        binary.write_bytes(b'target')
        seed.write_bytes(b'initial')
        out = self.root / 'candidate-evaluation'
        candidate = bytes([3])
        candidate_sha = queue._sha(candidate)
        handoff = {'accepted_seeds': [{'sha256': queue._sha(b'initial')}]}
        launches = []

        def analyze(*, binary, seed, input_path, argv, out, **kwargs):
            raw = seed.read_bytes()
            launches.append(raw)
            pairs = [[0x8049003, 'taken']] if raw == candidate else []
            saved = dict(inputs={name: queue._pin(path, 4096)[1]
                                 for name, path in (('binary', binary), ('seed', seed))},
                         input_path=input_path, argv=argv,
                         runs=[{'observed_branch_outcomes': pairs}, {'observed_branch_outcomes': pairs}],
                         concrete_runs=2, candidate_count=1, new_branch_outcomes=0)
            out.mkdir(parents=True)
            queue._json(out / 'summary.json', saved)
            return saved

        def source_audit(analysis, max_sites):
            return dict(self.source, handoff=dict(self.source['handoff'], analysis=str(analysis)))

        def check(**kwargs):
            checked = self.audit(**kwargs)
            if checked['report']['dse_status'] == 'VERIFIED':
                checked['report']['jobs'] = [dict(status='VERIFIED', candidate_sha256=candidate_sha, attempts=[])]
            return checked

        self.auditor.side_effect = check
        replay = out / 'candidate-replays' / candidate_sha

        def change_evidence(*_):
            if not change_attempt:
                return
            state = queue._read(out / 'queue/state.json')
            last = state['jobs'][state['order'][2]]['attempts'][0]
            (Path(last['directory']) / 'evidence.bin').write_bytes(b'changed')

        with (patch.object(evaluator.dta_analysis, 'analyze_file', side_effect=analyze),
              patch.object(evaluator, '_saved_analysis', side_effect=lambda _, saved, **kw: (saved, handoff, (b'', 0))),
              patch.object(queue, '_source_audit', side_effect=source_audit),
              patch.object(evaluator, '_full_environment', side_effect=change_evidence),
              patch.object(evaluator, 'parse_trace', return_value={'groups': [
                  {'vcpu': 0, 'pc': 0x8049003, 'occurrence': 1, 'offsets': [0], 'outcome': 'taken'}]}),
              patch('builtins.print')):
            options = dict(binary=binary, seeds=[seed], input_path='/etc/dta-input', out=out, max_jobs=3, **self.runtime)
            if change_attempt:
                with self.assertRaisesRegex(RuntimeError, 'Previously completed queue evidence no longer audits'):
                    evaluator.evaluate_file(**options)
            else:
                evaluator.evaluate_file(**options)
        self.assertEqual(launches, [b'initial', candidate])
        self.assertTrue((replay / 'summary.json').is_file())
        summary = queue._read(out / 'summary.json')
        self.assertEqual(summary['candidate_replays'][0]['sha256'], candidate_sha)
        self.assertEqual(summary['candidate_replays'][0]['new_outcomes_vs_all_DTA'], [[0x8049003, 'taken']])
        return out, summary, candidate_sha

    def test_evaluator_publishes_audited_candidate_after_reruns(self):
        out, summary, candidate_sha = self._evaluate_with_candidate(change_attempt=False)
        self.assertTrue(summary['measurement_completed'])
        self.assertEqual(summary['full_validation_runs'], 2)
        self.assertEqual(summary['new_full_run_outcomes'], [[0x8049003, 'taken']])
        self.assertEqual((out / 'seeds' / candidate_sha).read_bytes(), bytes([3]))

    def test_final_evaluator_audit_rejects_changed_candidate_evidence(self):
        out, summary, _ = self._evaluate_with_candidate(change_attempt=True)
        self.assertFalse(summary['measurement_completed'])
        self.assertFalse((out / 'seeds').exists())

    def test_stop_between_jobs(self):
        path = self.new_queue('stop')
        result, (reported, state, details) = queue._run_queue(queue=path, max_jobs=16, include_exit_audit=True,
                                     on_job_complete=lambda *_: queue.request_stop(queue=path))
        self.assertEqual(result['status'], 'QUEUE_STOPPED')
        self.assertEqual(result['started_this_run'], 1)
        self.assertEqual(reported, queue.audit_queue(queue=path))
        self.assertEqual(state, queue._load(path))
        self.assertEqual(list(details), state['order'][:1])
        self.auditor.reset_mock()
        result, (reported, state, details) = queue._run_queue(queue=path, max_jobs=2, include_exit_audit=True)
        self.assertEqual(result['started_this_run'], 2)
        self.assertTrue(result['evidence_audited'])
        self.assertEqual(reported['status'], 'QUEUE_PAUSED')
        self.assertEqual(list(details), state['order'][:3])
        expected = list(self.requests)[:3]
        self.assertEqual(self.started, expected)
        self.assertEqual([call.kwargs['request_id'] for call in self.auditor.call_args_list], expected * 2)
        self.assertEqual(reported, queue.audit_queue(queue=path))

    def test_worker_failure_keeps_previous_job_committed(self):
        path = self.new_queue('worker-error')
        completed = []

        def extend(**kwargs):
            if completed:
                raise InterruptedError('worker interrupted')
            return self.extend(**kwargs)

        self.worker.side_effect = extend
        with self.assertRaisesRegex(InterruptedError, 'worker interrupted'):
            queue.run_queue(queue=path, max_jobs=16, on_job_complete=lambda job, _: completed.append(job))
        state = queue.queue_status(queue=path)
        self.assertEqual(len(completed), 1)
        self.assertEqual(state['status'], 'QUEUE_BLOCKED')
        self.assertEqual(state['counts']['NONPROOF'], 1)
        self.assertEqual(state['counts']['BLOCKED_RECOVERY'], 1)
        self.assertEqual(state['started_attempts'], 2)

    def test_progress_error_keeps_committed_job_resumable(self):
        path = self.new_queue('progress-error')

        def fail(*_):
            raise OSError('timing write failed')

        with self.assertRaisesRegex(OSError, 'timing write failed'):
            queue.run_queue(queue=path, max_jobs=16, on_job_complete=fail)
        self.assertEqual(queue.audit_queue(queue=path)['counts']['NONPROOF'], 1)
        self.assertEqual(queue.run_queue(queue=path)['started_this_run'], 1)
        self.assertEqual(self.started, list(self.requests)[:2])
