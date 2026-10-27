"""Mocked external orchestration; concrete stdin/command bindings use real files.

These tests do not execute guest ELF code or claim to rerun SMT.
"""
import base64
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from unpacker import input_case_eval as e


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value) + '\n')


def binding(case):
    data = e.unpack_launch.stdin_bytes(case)
    return dict(schema_version=1, profile=e.unpack_launch.PROFILE,
        case_id=case['id'], case_sha256=e.unpack_launch.case_sha256(case),
        stdin_sha256=hashlib.sha256(data).hexdigest(), stdin_bytes=len(data),
        argv=case['argv'], guest_argv=['target.elf', *case['argv']], fixed_case_only=True,
        stdin_consumed_before_selected_boundary=False,
        stdin_unconsumed_before_selected_boundary=True, stdin_admitted_as_initial_memory=False,
        new_independent_execution=True, input_domain_universally_proved=False,
        payload_behavior_proved=False)


def audit_binding(case):
    return dict(binding(case), receipt_audit_only=True, solver_not_rerun=True,
        entry_constructor_and_launch_strings_reaudited=True,
        consumed_stack_projection_reaudited=True)


class InputCaseEvaluationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / 'project/unpacker'
        self.source.mkdir(parents=True)
        for name in e.SOURCES:
            (self.source / name).write_text('# source identity fixture\n')
        self.qemu = self.root / 'qemu'
        self.qemu.write_bytes(b'not executed')
        self.qemu.chmod(0o700)
        self.sdk = self.root / 'sdk'
        self.sdk.mkdir()
        (self.sdk / 'qemu-plugin.h').write_text('SDK')
        self.samples, self.selections, self.pins = [], {}, {}
        self.cases = {}
        for name in e.DEFAULT_SELECTIONS:
            directory = self.root / 'corpus' / name
            directory.mkdir(parents=True)
            program, packing = name.split('-', 1)
            for artifact in ('packed', 'original'):
                path = directory / (artifact + '.elf')
                path.write_bytes((name + artifact).encode())
                self.pins[str(path)] = e.external.digest(path)
            case = dict(id='input-06', argv=['-'] if program == 'xxhsum' else ['-c'],
                stdin_base64=base64.b64encode(b'\x00\xffabc').decode())
            cases = directory / 'cases.json'
            write(cases, [dict(id='empty', argv=case['argv'], stdin_base64=''), case])
            self.pins[str(cases)] = e.external.digest(cases)
            sample = dict(id=name, program=program, packing=packing, cases=str(cases),
                packed=str(directory / 'packed.elf'), original=str(directory / 'original.elf'),
                packed_sha256=self.pins[str(directory / 'packed.elf')],
                original_sha256=self.pins[str(directory / 'original.elf')])
            self.samples.append(sample)
            selection = self.root / 'selection' / name
            for relative, data in (('inputs/packed.elf', (directory / 'packed.elf').read_bytes()),
                    ('capture/unpacked.json', b'{}'), ('capture/unpacked.bin', b'conclusion'),
                    ('rebuilt.elf', b'rebuilt ELF')):
                path = selection / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
            self.selections[name] = selection
            self.cases[name] = case
        self.commands = []
        self.failures = set()
        self.corrupt_stdin = set()
        self.proof_wrong_case = set()
        self.repeated_targets = set()
        self.mutate_source = False
        self.native_build_probe = None

    def measurement(self, failure=False):
        return dict(returncode=1 if failure else 0, timed_out=False,
            rss_limit_hit=False, file_limit_hit=False, cpu_limit_hit=False)

    def selection(self, directory, packed):
        return dict(status='VALIDATED_AUTOMATIC_SELECTION', target=0x8049000,
            packed_sha256=packed, repeated_target_in_stage_history=directory.name in self.repeated_targets,
            report_sha256=e.external.digest(directory / 'capture/unpacked.json'),
            dump_sha256=e.external.digest(directory / 'capture/unpacked.bin'))

    def concrete(self, output, phase, sample, case):
        names = ['packed', 'original'] + (['rebuilt'] if phase == 'behavior' else [])
        expected = {name: sample[name + '_sha256'] if name != 'rebuilt' else
            e.external.digest(self.selections[sample['id']] / 'rebuilt.elf') for name in names}
        paths, executions = {}, {}
        data = e.unpack_launch.stdin_bytes(case)
        for name in names:
            executable = output / 'inputs' / (name + '.elf')
            executable.parent.mkdir(parents=True, exist_ok=True)
            source = Path(sample[name]) if name != 'rebuilt' else self.selections[sample['id']] / 'rebuilt.elf'
            executable.write_bytes(source.read_bytes())
            paths[name] = str(executable)
            executions[name] = []
            for repeat in range(2):
                run = output / 'runs/case-000' / name / str(repeat)
                run.mkdir(parents=True)
                (run / 'stdin.bin').write_bytes(data + (b'changed' if sample['id'] in self.corrupt_stdin else b''))
                result = dict(returncode=0, timed_out=False, rss_limit_hit=False,
                    output_limit_exceeded=False, output_files={})
                for stream in ('stdout', 'stderr'):
                    raw = b'fixed observable' if stream == 'stdout' else b''
                    (run / stream).write_bytes(raw)
                    result[stream + '_bytes'] = len(raw)
                    result[stream + '_sha256'] = hashlib.sha256(raw).hexdigest()
                write(run / 'result.json', result)
                write(run / 'command.json', dict(argv=[str(self.qemu), '-0', 'target.elf',
                    str(executable), *case['argv']], case=e.validate_cases([case])[0],
                    cwd=str(run), close_fds=True, fresh_session=True))
                executions[name].append(result)
        write(output / 'comparisons.json', [dict(id=case['id'], matched=True,
            errors=[], executions=executions)])
        count = len(names) * 2
        return dict(artifact_names=names, artifact_sha256=expected, artifact_execution_paths=paths,
            cases=1, matched_cases=1, all_selected_cases_match=True, repetitions_per_artifact=2,
            executions=count, expected_executions=count, completed_concrete_executions=count,
            resource_or_signal_stopped_executions=0, execution_errors=0,
            formal_proof=False, universal_equivalence=False)

    def run_phase(self, command, directory, **budgets):
        phase = command[command.index('--phase') + 1]
        output = Path(command[command.index('--output') + 1])
        if phase == 'build-native' and self.native_build_probe is not None:
            self.native_build_probe(output)
        else:
            # The actual native builder creates only its fresh leaf directory.
            # A recursive mock would hide a missing caller-owned build parent.
            output.mkdir(parents=phase != 'build-native')
        self.commands.append((phase, command, budgets))
        if phase == 'build-native':
            name, sample, case = None, None, None
        else:
            packed = command[command.index('--packed') + 1]
            sample = next(row for row in self.samples if row['packed'] == packed)
            name = sample['id']
            case_file = Path(command[command.index('--cases') + 1])
            case = e.unpack_launch.normalize_case(e.external.strict_json(case_file)[0])
            self.assertEqual(case, self.cases[name])
        failed = (name, phase) in self.failures
        receipt = dict(schema_version=1, phase=phase, errors=[], success=not failed,
            status=e.external.WORKER_PASS[phase] if not failed else 'FAIL_WORKER_PHASE')
        if sample is not None:
            receipt['packed_sha256'] = sample['packed_sha256']
        if phase in ('baseline', 'behavior'):
            receipt.update(self.concrete(output, phase, sample, case))
        elif phase == 'reference':
            receipt.update(original_sha256=sample['original_sha256'], target=0x8049000,
                oracle=dict(entry_exact=True, complete_exact_match=True), formal_proof=False)
        elif phase == 'proof':
            self.assertEqual(e.unpack_launch.load_case(command[command.index('--proof-case') + 1]), case)
            chosen = copy.deepcopy(case)
            if name in self.proof_wrong_case:
                chosen['argv'] = ['changed']
            report = binding(chosen)
            write(output / 'summary.json', dict(launch_input_binding=report))
            write(output / 'receipt-audit.json', dict(status=e.unpack_audit.STATUS))
            receipt.update(target=0x8049000, launch_case_sha256=report['case_sha256'],
                proof_launch_profile=e.unpack_launch.PROFILE, proof_fresh_stdin='retained_file',
                proof_fresh_stdin_bytes=report['stdin_bytes'], proof_fresh_stdin_sha256=report['stdin_sha256'],
                proof_fresh_argv=chosen['argv'], same_execution_as_behavior=False,
                launch_input_binding=audit_binding(chosen))
        write(output / 'worker-summary.json', receipt)
        if self.mutate_source and phase == 'baseline':
            (self.source / 'unpack_launch.py').write_text('changed\n')
        return self.measurement(failed)

    def audit(self, directory, expected_launch_case):
        case = expected_launch_case
        name = Path(directory).parent.name
        chosen = copy.deepcopy(case)
        if name in self.proof_wrong_case:
            chosen['argv'] = ['changed']
        return dict(status=e.unpack_audit.STATUS, packed_sha256=next(row['packed_sha256']
            for row in self.samples if row['id'] == name), target=0x8049000,
            launch_input_binding=audit_binding(chosen), fixed_launch_case_audited=True,
            audited_file_sha256={})

    def invoke(self, **options):
        with patch.object(e, 'ROOT', self.source), \
             patch.object(e.external, 'load_corpus', return_value=(None, self.samples, copy.deepcopy(self.pins))), \
             patch.object(e.external, 'run_phase', side_effect=self.run_phase), \
             patch.object(e.external, '_capture_view', side_effect=self.selection), \
             patch.object(e.external, '_proof_view', return_value=dict(instructions=100)), \
             patch.object(e.unpack_audit, 'audit_sample', side_effect=self.audit):
            return e.evaluate(self.root / 'corpus.json', self.root / 'output', qemu=self.qemu,
                qemu_include=self.sdk, selections=self.selections, **options)

    def test_four_fresh_case_proofs_use_binary_stdin_argv_and_current_native_build(self):
        result = self.invoke()
        self.assertEqual(result['status'], e.STATUS)
        self.assertEqual(result['counts'], dict(baseline=4, reference=4, behavior=4, proof=4))
        self.assertEqual(result['completed_samples'], 4)
        self.assertEqual([phase for phase, _, _ in self.commands].count('build-native'), 1)
        self.assertEqual([phase for phase, _, _ in self.commands].count('proof'), 4)
        for row in result['samples']:
            self.assertEqual(row['launch_case']['stdin_bytes'], 5)
            self.assertEqual(row['phases']['baseline']['concrete_case_binding']['executions'], 4)
            self.assertEqual(row['phases']['behavior']['concrete_case_binding']['executions'], 6)
            self.assertTrue(row['phases']['proof']['proof_case_binding']['launch_input_binding']['stdin_unconsumed_before_selected_boundary'])
            audited = row['phases']['proof']['proof_case_binding']['launch_input_binding']
            self.assertTrue(audited['entry_constructor_and_launch_strings_reaudited'])
            # A real receipt audit adds evidence-check flags to the proof's
            # base launch binding; those two objects must not be compared as
            # though they had identical schemas.
            self.assertEqual(set(audited) - set(binding(self.cases[row['id']])),
                {'receipt_audit_only', 'solver_not_rerun',
                 'entry_constructor_and_launch_strings_reaudited', 'consumed_stack_projection_reaudited'})
        self.assertTrue(result['all_pinned_inputs_unchanged'])
        self.assertFalse(result['proof_scope']['identical_to_behavior_execution_established'])
        self.assertFalse(result['proof_scope']['universal_equivalence'])

    def test_real_native_builder_reaches_compiler_under_caller_created_parent(self):
        from unpacker import unpack_proof
        reached = []

        def probe(output):
            self.assertFalse(output.exists())
            with patch.object(unpack_proof, 'flags', return_value=([], [])), \
                 patch.object(unpack_proof.subprocess, 'run',
                              side_effect=RuntimeError('compiler boundary reached')) as compiler:
                with self.assertRaisesRegex(RuntimeError, 'compiler boundary reached'):
                    unpack_proof.build_native(self.sdk, output)
            compiler.assert_called_once()
            self.assertTrue(output.parent.is_dir())
            self.assertIn('-c', compiler.call_args.args[0])
            self.assertEqual((output / 'source/oep_execute.c').read_bytes(),
                             (unpack_proof.ROOT / 'oep_execute.c').read_bytes())
            self.assertFalse((output / 'unpack-execute').exists())
            reached.append(output)

        self.native_build_probe = probe
        result = self.invoke(samples=['xxhsum-default'])
        self.assertEqual(result['status'], e.STATUS, result['errors'])
        self.assertEqual(reached, [self.root / 'output/build/native'])

    def test_real_native_builder_missing_parent_reproduces_original_failure(self):
        from unpacker import unpack_proof
        output = self.root / 'missing-build/native'
        with patch.object(unpack_proof.subprocess, 'run') as compiler:
            with self.assertRaises(FileNotFoundError):
                unpack_proof.build_native(self.sdk, output)
        compiler.assert_not_called()
        self.assertFalse(output.exists())

    def test_real_native_builder_preserves_an_occupied_leaf_before_compilation(self):
        from unpacker import unpack_proof
        output = self.root / 'occupied-build/native'
        output.mkdir(parents=True)
        marker = output / 'keep'
        marker.write_bytes(b'existing native run')
        with patch.object(unpack_proof.subprocess, 'run') as compiler:
            with self.assertRaises(FileExistsError):
                unpack_proof.build_native(self.sdk, output)
        compiler.assert_not_called()
        self.assertEqual(marker.read_bytes(), b'existing native run')

    def test_large_ledger_budget_applies_only_to_proof(self):
        self.invoke(samples=['xxhsum-lzma'])
        for phase, command, budgets in self.commands:
            self.assertEqual(command[command.index('--max-producer-nodes') + 1], str(e.MAX_NODES))
            self.assertEqual(budgets['file_limit_mib'], 8193 if phase == 'proof' else 2048)
            self.assertEqual(budgets['timeout'], 3600 if phase == 'proof' else 60 if phase == 'reference' else 600)
            self.assertEqual(budgets['rss_limit_mib'], 16384)
            self.assertEqual(budgets['address_space_mib'], 32768)

    def test_failed_case_stays_in_declared_denominator_and_later_proofs_run(self):
        self.failures = {('xxhsum-default', 'proof')}
        result = self.invoke()
        self.assertEqual(result['status'], e.FAIL)
        self.assertEqual(result['completed_samples'], 4)
        self.assertEqual(result['counts']['proof'], 3)
        self.assertEqual([phase for phase, _, _ in self.commands].count('proof'), 4)

    def test_failed_baseline_does_not_skip_independent_reference_behavior_or_proof(self):
        self.failures = {('xxhsum-default', 'baseline')}
        result = self.invoke(samples=['xxhsum-default'])
        self.assertEqual(result['status'], e.FAIL)
        self.assertEqual(result['counts'], dict(baseline=0, reference=1, behavior=1, proof=1))

    def test_failed_fresh_build_never_reuses_an_old_native_bundle(self):
        self.failures = {(None, 'build-native')}
        result = self.invoke()
        self.assertEqual(result['status'], e.FAIL)
        self.assertEqual(result['counts']['proof'], 0)
        self.assertEqual(result['completed_samples'], 4)
        self.assertNotIn('proof', [phase for phase, _, _ in self.commands])

    def test_repeated_PC_does_not_silently_use_PC_only_proof_selector(self):
        self.repeated_targets = {'xxhsum-default'}
        result = self.invoke()
        self.assertEqual(result['status'], e.FAIL)
        self.assertEqual(result['counts']['proof'], 3)
        self.assertEqual(result['samples'][0]['phases']['proof']['diagnosis']['category'], 'UNSUPPORTED_PROFILE')

    def test_actual_retained_stdin_tampering_cannot_keep_behavior_PASS(self):
        self.corrupt_stdin = {'xxhsum-default'}
        result = self.invoke(samples=['xxhsum-default'])
        self.assertEqual(result['status'], e.FAIL)
        self.assertEqual(result['counts']['baseline'], 0)
        self.assertEqual(result['counts']['behavior'], 0)
        self.assertEqual(result['counts']['proof'], 1)

    def test_rehashed_different_proof_case_cannot_supply_declared_case(self):
        self.proof_wrong_case = {'xxhsum-default'}
        result = self.invoke(samples=['xxhsum-default'])
        self.assertEqual(result['status'], e.FAIL)
        self.assertEqual(result['counts']['proof'], 0)

    def test_missing_nonempty_case_fails_before_build_or_output_creation(self):
        for sample in self.samples:
            write(Path(sample['cases']), [dict(id='input-06', argv=['-'], stdin_base64='')])
        with self.assertRaisesRegex(ValueError, 'nonempty'):
            self.invoke()
        self.assertEqual(self.commands, [])
        self.assertFalse((self.root / 'output').exists())

    def test_unknown_duplicate_or_empty_sample_selection_never_runs_a_worker(self):
        for values in ([], ['other'], ['xxhsum-default', 'xxhsum-default']):
            with self.subTest(values=values), self.assertRaises(ValueError):
                self.invoke(samples=values)
        self.assertEqual(self.commands, [])

    def test_retained_selection_output_overlap_and_occupied_output_are_preserved(self):
        output = self.root / 'output'
        output.mkdir()
        (output / 'keep').write_bytes(b'old')
        with self.assertRaises(ValueError):
            self.invoke()
        self.assertEqual((output / 'keep').read_bytes(), b'old')
        self.assertEqual(self.commands, [])

    def test_source_identity_mutation_stops_before_later_phases(self):
        self.mutate_source = True
        result = self.invoke()
        self.assertEqual(result['status'], e.FAIL)
        self.assertFalse(result['all_pinned_inputs_unchanged'])
        self.assertIn('changed', result['errors'][0])
        self.assertEqual([phase for phase, _, _ in self.commands], ['build-native', 'baseline'])

    def test_binding_flags_cannot_claim_input_domain_or_payload_proof(self):
        case = self.cases['xxhsum-default']
        for key, value in (('stdin_unconsumed_before_selected_boundary', False),
                ('input_domain_universally_proved', True), ('payload_behavior_proved', True),
                ('stdin_consumed_before_selected_boundary', True), ('stdin_admitted_as_initial_memory', True)):
            row = binding(case)
            row[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                e.binding_matches(row, case)


if __name__ == '__main__':
    unittest.main()
