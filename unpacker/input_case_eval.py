#!/usr/bin/env python3
"""Fresh selected-execution proofs for explicit nonempty stdin/argv cases.

Retained captures select conclusions only. A new observer run, entry replay,
SMT proof and receipt audit use the exact chosen concrete launch case. The
stdin stream is retained but must remain unconsumed before the selected entry;
input-dependent decoder reads remain outside this profile.
"""
from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import sys
import tempfile

try:
    from . import external_eval as external
    from . import unpack_audit, unpack_launch
    from .external_diagnostics import diagnose
    from .unpack_process import compare_results, validate_cases
except ImportError:
    import external_eval as external
    import unpack_audit
    import unpack_launch
    from external_diagnostics import diagnose
    from unpack_process import compare_results, validate_cases


ROOT = Path(__file__).resolve().parent
STATUS = 'PASS_NONEMPTY_LAUNCH_SELECTED_EXECUTION_SMT_AND_BEHAVIOR'
FAIL = 'NONPROOF_NONEMPTY_LAUNCH_EVALUATION'
DEFAULT_SELECTIONS = {
    'xxhsum-default': 'unpack-proof.source-budget-sus19nml/probe/external/samples/xxhsum-default/capture',
    'xxhsum-lzma': 'unpack-proof.large-ledger-zk3wm5q0/probe/external/samples/xxhsum-lzma/capture',
    'bzip2-default': 'unpack-proof.source-budget-htv6a6hc/probe/external/samples/bzip2-default/capture',
    'bzip2-lzma': 'unpack-proof.source-budget-htv6a6hc/probe/external/samples/bzip2-lzma/capture',
}
PHASES = ('baseline', 'reference', 'behavior', 'proof')
SOURCES = ('input_case_eval.py', 'unpack_launch.py', 'external_worker.py', 'external_eval.py',
    'external_process.py', 'unpack_proof.py', 'unpack_observations.py', 'unpack_audit.py',
    'unpack_smt.py', 'oep_schedule.py', 'rep_callbacks.py', 'unpack_process.py')
MAX_NODES = 268435456
MIB = 1024**2


def require(value, message):
    if not value:
        raise ValueError(message)


def plain(path):
    path = Path(os.path.abspath(os.fspath(path)))
    require(not any(part.is_symlink() for part in (path, *path.parents)),
            'Input-case path traverses a symlink: ' + str(path))
    return path


def file(path, maximum=16 * MIB, *, nonempty=True):
    path = plain(path)
    require(path.is_file() and (0 if nonempty else -1) < path.stat().st_size <= maximum,
            'Missing or oversized input-case file: ' + str(path))
    return path


def pin(pins, path, expected=None, maximum=16 * MIB, *, nonempty=True):
    path = file(path, maximum, nonempty=nonempty)
    value = external.digest(path)
    require(expected is None or value == expected, 'Input-case file identity differs: ' + str(path))
    require(str(path) not in pins or pins[str(path)] == value,
            'Input-case file changed: ' + str(path))
    pins[str(path)] = value
    return value


def select_case(sample, case_id):
    rows = validate_cases(external.strict_json(sample['cases']))
    matches = [row for row in rows if row['id'] == case_id]
    require(len(matches) == 1, 'Missing unique declared launch case: ' + case_id)
    case = unpack_launch.normalize_case(matches[0])
    require(case['argv'] and unpack_launch.stdin_bytes(case),
            'This evaluation requires both nonempty stdin and nonempty argv')
    return case


def binding_matches(binding, case):
    require(type(binding) is dict and binding.get('profile') == unpack_launch.PROFILE and
        binding.get('case_id') == case['id'] and
        binding.get('case_sha256') == unpack_launch.case_sha256(case) and
        binding.get('stdin_sha256') == hashlib.sha256(unpack_launch.stdin_bytes(case)).hexdigest() and
        type(binding.get('stdin_bytes')) is int and
        binding['stdin_bytes'] == len(unpack_launch.stdin_bytes(case)) and
        binding.get('argv') == case['argv'] and binding.get('guest_argv') == ['target.elf', *case['argv']] and
        binding.get('fixed_case_only') is True and
        binding.get('stdin_unconsumed_before_selected_boundary') is True and
        binding.get('stdin_consumed_before_selected_boundary') is False and
        binding.get('stdin_admitted_as_initial_memory') is False and
        binding.get('input_domain_universally_proved') is False and
        binding.get('payload_behavior_proved') is False,
        'Proof launch binding differs from the declared concrete case')


def behavior_binding(directory, receipt, case, artifacts, qemu, pins):
    """Bind every actual concrete run's command/stdin/result to the chosen case."""
    directory = plain(directory)
    names = list(artifacts)
    count = 2 * len(names)
    require(receipt.get('artifact_names') == names and
        receipt.get('artifact_sha256') == artifacts and receipt.get('cases') == 1 and
        receipt.get('matched_cases') == 1 and receipt.get('all_selected_cases_match') is True and
        receipt.get('repetitions_per_artifact') == 2 and
        receipt.get('executions') == receipt.get('expected_executions') ==
        receipt.get('completed_concrete_executions') == count and
        receipt.get('resource_or_signal_stopped_executions') == 0 and
        receipt.get('execution_errors') == 0 and receipt.get('formal_proof') is False and
        receipt.get('universal_equivalence') is False,
        'Concrete behavior receipt has incomplete coverage or promoted scope')
    comparisons_path = file(directory / 'comparisons.json')
    comparisons = external.strict_json(comparisons_path)
    pin(pins, comparisons_path)
    require(type(comparisons) is list and len(comparisons) == 1 and
        comparisons[0].get('id') == case['id'] and comparisons[0].get('matched') is True and
        comparisons[0].get('errors') == [], 'Concrete comparison case differs')
    executions = comparisons[0].get('executions')
    require(type(executions) is dict and set(executions) == set(names),
            'Concrete behavior artifact inventory differs')
    results = []
    normalized = validate_cases([case])[0]
    data = unpack_launch.stdin_bytes(case)
    for name in names:
        require(type(executions[name]) is list and len(executions[name]) == 2,
                'Concrete behavior repetition inventory differs')
        executable = file(directory / 'inputs' / (name + '.elf'))
        require(receipt.get('artifact_execution_paths', {}).get(name) == str(executable),
                'Concrete behavior executable path differs')
        pin(pins, executable, artifacts[name])
        for repeat in range(2):
            run = directory / 'runs/case-000' / name / str(repeat)
            command = external.strict_json(file(run / 'command.json'))
            result = external.strict_json(file(run / 'result.json'))
            require(command.get('argv') == [str(qemu), '-0', 'target.elf', str(executable), *case['argv']] and
                command.get('case') == normalized and command.get('cwd') == str(run) and
                command.get('close_fds') is True and command.get('fresh_session') is True,
                'Concrete behavior command does not pass the declared case')
            require(file(run / 'stdin.bin', MIB, nonempty=False).read_bytes() == data and
                result == executions[name][repeat] and compare_results([result]),
                'Concrete behavior input/result binding differs')
            for stream in ('stdout', 'stderr'):
                path = file(run / stream, MIB, nonempty=False)
                require(path.stat().st_size == result.get(stream + '_bytes'),
                        'Concrete behavior stream size differs')
                pin(pins, path, result.get(stream + '_sha256'), MIB, nonempty=False)
            for relative in ('stdin.bin', 'command.json', 'result.json'):
                pin(pins, run / relative, maximum=2 * MIB, nonempty=False)
            results.append(result)
    require(compare_results(results), 'Concrete behavior observables differ')
    return dict(case_sha256=unpack_launch.case_sha256(case), executions=count,
        every_launch_command_stdin_and_result_checked=True,
        separate_executions_from_formal_proof=True, formal_proof=False)


def proof_binding(directory, receipt, sample, selection, case, pins):
    metrics = external._proof_view(directory, receipt, sample['packed_sha256'], selection['target'])
    audited = unpack_audit.audit_sample(directory, expected_launch_case=case)
    proof = external.strict_json(directory / 'summary.json')
    binding = audited.get('launch_input_binding')
    base_binding = proof.get('launch_input_binding')
    binding_matches(base_binding, case)
    binding_matches(binding, case)
    audit_flags = dict(receipt_audit_only=True, solver_not_rerun=True,
        entry_constructor_and_launch_strings_reaudited=True,
        consumed_stack_projection_reaudited=True)
    require(binding == {**base_binding, **audit_flags} and
        audited.get('fixed_launch_case_audited') is True and
        receipt.get('launch_input_binding') == binding and
        receipt.get('proof_launch_profile') == unpack_launch.PROFILE and
        receipt.get('launch_case_sha256') == unpack_launch.case_sha256(case) and
        receipt.get('proof_fresh_stdin') == 'retained_file' and
        receipt.get('proof_fresh_stdin_bytes') == len(unpack_launch.stdin_bytes(case)) and
        receipt.get('proof_fresh_stdin_sha256') == binding['stdin_sha256'] and
        receipt.get('proof_fresh_argv') == case['argv'] and
        receipt.get('same_execution_as_behavior') is False and
        audited.get('status') == unpack_audit.STATUS and
        audited.get('target') == selection['target'] and
        audited.get('packed_sha256') == sample['packed_sha256'],
        'Worker/proof/audit launch input binding differs')
    for relative, value in audited['audited_file_sha256'].items():
        pin(pins, directory / relative, value, maximum=256 * MIB, nonempty=False)
    for name in ('summary.json', 'receipt-audit.json', 'worker-summary.json'):
        pin(pins, directory / name)
    return dict(metrics=metrics, launch_input_binding=binding,
        fresh_receipt_audit=audited, receipt_audit_only=True, solver_not_rerun_by_auditor=True)


def evaluate(corpus, output, *, qemu, qemu_include, selections=None, samples=None,
             case_id='input-06', max_nodes=MAX_NODES):
    require(type(case_id) is str and external.ID.fullmatch(case_id), 'Invalid concrete case ID')
    proof_limit = external.proof_file_limit_mib(max_nodes)
    _, inventory, pins = external.load_corpus(corpus)
    for name in pins:
        plain(name)
    require({row['id'] for row in inventory} == set(DEFAULT_SELECTIONS) and len(inventory) == 4,
            'Require the complete four-sample external corpus')
    requested = list(DEFAULT_SELECTIONS) if samples is None else list(samples)
    require(requested and len(requested) == len(set(requested)) and
        set(requested) <= set(DEFAULT_SELECTIONS), 'Unknown, duplicate or empty sample selection')
    rows = {row['id']: row for row in inventory}
    cases = {name: select_case(rows[name], case_id) for name in requested}
    choices = {name: ROOT / path for name, path in DEFAULT_SELECTIONS.items()}
    if selections is not None:
        require(type(selections) is dict and set(selections) <= set(DEFAULT_SELECTIONS),
                'Unknown candidate selection override')
        choices.update(selections)
    choices = {name: plain(choices[name]) for name in requested}
    require(all(path.is_dir() for path in choices.values()), 'Candidate selection directory is missing')
    qemu, include = file(qemu, 512 * MIB), plain(qemu_include)
    require(os.access(qemu, os.X_OK), 'QEMU must be executable')
    pin(pins, qemu, maximum=512 * MIB)
    pin(pins, include / 'qemu-plugin.h', maximum=MIB)
    for relative in SOURCES:
        pin(pins, ROOT / relative)
    selected = {}
    for name in requested:
        directory = choices[name]
        for relative in ('inputs/packed.elf', 'capture/unpacked.json', 'capture/unpacked.bin', 'rebuilt.elf'):
            pin(pins, directory / relative)
        selected[name] = external._capture_view(directory, rows[name]['packed_sha256'])
    output = plain(output)
    require(not output.exists() and all(not output.is_relative_to(Path(path)) and
        not Path(path).is_relative_to(output) for path in pins) and
        all(not output.is_relative_to(path) and not path.is_relative_to(output) for path in choices.values()),
        'Input-case output must be new and separate from all retained inputs')
    output.mkdir(parents=True)
    result = dict(schema_version=1, status=FAIL, errors=[], requested_samples=requested,
        sample_count=len(requested), completed_samples=0, samples=[], builds={},
        declared_case_id=case_id, fixed_concrete_launch_cases_only=True,
        proof_scope=dict(profile=unpack_launch.PROFILE, fresh_original_entry_run=True,
            proof_stdin_empty=False, proof_argv_empty=False,
            stdin_unconsumed_before_selected_boundary=True,
            input_dependent_decoder_reads_supported=False, kernel_contracts_explicit=True,
            selected_target_PC_only=True, historical_originality_proven=False,
            identical_to_behavior_execution_established=False, universal_equivalence=False,
            concrete_behavior_is_separate_from_formal_proof=True),
        budgets=dict(guest_timeout=30, build_native_timeout=600, baseline_timeout=600,
            reference_timeout=60, behavior_timeout=600, proof_timeout=3600,
            rss_limit_mib=16384, address_space_mib=32768,
            max_producer_nodes=max_nodes, proof_file_limit_mib=proof_limit),
        reused_old_proof_status=False, inherited_capture_used_as_initial_state=False,
        all_pinned_inputs_unchanged=False, all_selected_cases_passed=False)

    def phase(name, destination, process, extra, timeout):
        command = [sys.executable, '-B', str(external.WORKER), '--phase', name,
            '--output', str(destination), '--qemu', str(qemu), '--qemu-include', str(include),
            '--guest-timeout', '30', '--guest-rss-mib', '4096',
            '--max-producer-nodes', str(max_nodes), *map(str, extra)]
        measured = external.run_phase(command, process, cwd=ROOT.parent, timeout=timeout,
            rss_limit_mib=16384, address_space_mib=32768,
            file_limit_mib=proof_limit if name == 'proof' else 2048)
        try:
            receipt = external._positive(name, destination, measured)
            pin(pins, destination / 'worker-summary.json')
            return dict(status='PASS', measurement=measured, receipt=receipt)
        except (OSError, ValueError, KeyError, TypeError) as error:
            return dict(status='NONPROOF', measurement=measured,
                diagnosis=diagnose(name, destination, measured), error=str(error))

    try:
        external.check_pins(pins)
        print('input-case: build-native', flush=True)
        native = output / 'build/native'
        native.parent.mkdir()
        result['builds']['native'] = phase('build-native', native, output / 'process/build-native', [], 600)
        for name in requested:
            external.check_pins(pins)
            sample, case, selection = rows[name], cases[name], selected[name]
            directory = output / 'samples' / name
            directory.mkdir(parents=True)
            case_file = directory / 'launch-case.json'
            case_file.write_bytes(unpack_launch.case_bytes(case))
            cases_file = directory / 'behavior-cases.json'
            external.save(cases_file, [case])
            pin(pins, case_file)
            pin(pins, cases_file)
            row = dict(id=name, packed_sha256=sample['packed_sha256'],
                original_sha256=sample['original_sha256'], target=selection['target'],
                selection_directory=str(choices[name]), selection=selection,
                launch_case=dict(id=case['id'], argv=case['argv'],
                    case_sha256=unpack_launch.case_sha256(case),
                    stdin_sha256=hashlib.sha256(unpack_launch.stdin_bytes(case)).hexdigest(),
                    stdin_bytes=len(unpack_launch.stdin_bytes(case))), phases={})
            result['samples'].append(row)
            common = ['--packed', sample['packed'], '--original', sample['original'], '--cases', cases_file]
            for name_phase, timeout in (('baseline', 600), ('reference', 60), ('behavior', 600), ('proof', 3600)):
                print('input-case:', name, name_phase, flush=True)
                extra = list(common)
                if name_phase != 'baseline':
                    extra += ['--unpack', choices[name]]
                if name_phase == 'proof':
                    if result['builds']['native']['status'] != 'PASS':
                        row['phases'][name_phase] = dict(status='NOT_RUN',
                            diagnosis=dict(category='BUILD_FAILURE', stage='proof', detail='Fresh native build failed'))
                        continue
                    if selection.get('repeated_target_in_stage_history') is True:
                        row['phases'][name_phase] = dict(status='NOT_RUN', diagnosis=dict(
                            category='UNSUPPORTED_PROFILE', stage='proof', detail='Exact occurrence selector required'))
                        continue
                    extra += ['--native', native, '--proof-case', case_file]
                part = phase(name_phase, directory / name_phase,
                    directory / 'process' / name_phase, extra, timeout)
                row['phases'][name_phase] = part
                if part['status'] == 'PASS':
                    try:
                        receipt = part['receipt']
                        require(receipt.get('packed_sha256') == sample['packed_sha256'],
                                'Phase packed input identity differs')
                        if name_phase in ('baseline', 'behavior'):
                            artifacts = dict(packed=sample['packed_sha256'], original=sample['original_sha256'])
                            if name_phase == 'behavior':
                                artifacts['rebuilt'] = external.digest(choices[name] / 'rebuilt.elf')
                            part['concrete_case_binding'] = behavior_binding(directory / name_phase,
                                receipt, case, artifacts, qemu, pins)
                        elif name_phase == 'reference':
                            oracle = receipt.get('oracle')
                            require(type(oracle) is dict and oracle.get('entry_exact') is True and
                                oracle.get('complete_exact_match') is True and
                                receipt.get('original_sha256') == sample['original_sha256'] and
                                receipt.get('target') == selection['target'] and receipt.get('formal_proof') is False,
                                'Reference entry/code identity or scope differs')
                        else:
                            part['proof_case_binding'] = proof_binding(directory / 'proof', receipt,
                                sample, selection, case, pins)
                    except (OSError, ValueError, KeyError, TypeError) as error:
                        part.update(status='NONPROOF', diagnosis=dict(category='INVALID_EVIDENCE',
                            stage=name_phase, detail=str(error)))
                external.check_pins(pins)
                external.save(output / 'progress.json', result)
            result['completed_samples'] += 1
            external.save(directory / 'sample-summary.json', row)
            external.save(output / 'progress.json', result)
        external.check_pins(pins)
        result['all_pinned_inputs_unchanged'] = True
        result['counts'] = {phase_name: sum(row['phases'][phase_name]['status'] == 'PASS'
            for row in result['samples']) for phase_name in PHASES}
        result['all_selected_cases_passed'] = all(value == len(requested) for value in result['counts'].values())
        if result['completed_samples'] == len(requested) and result['all_selected_cases_passed']:
            result['status'] = STATUS
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as error:
        result['errors'].append(type(error).__name__ + ': ' + str(error))
    finally:
        external.save(output / 'input-pins.json', pins)
        external.save(output / 'summary.json', result)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--corpus', required=True, type=Path)
    parser.add_argument('--qemu', required=True, type=Path)
    parser.add_argument('--qemu-include', required=True, type=Path)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--sample', action='append')
    parser.add_argument('--case-id', default='input-06')
    parser.add_argument('--selection', action='append', default=[])
    parser.add_argument('--max-producer-nodes', type=int, default=MAX_NODES)
    args = parser.parse_args(argv)
    output = args.output or Path(tempfile.mkdtemp(prefix='unpack-proof.input-case-', dir=ROOT)) / 'probe'
    print('Results:', output, flush=True)
    try:
        choices = {}
        for value in args.selection:
            name, separator, directory = value.partition('=')
            require(separator and name not in choices and name in DEFAULT_SELECTIONS and directory,
                    'Unknown or duplicate selection override')
            choices[name] = Path(directory)
        result = evaluate(args.corpus, output, qemu=args.qemu, qemu_include=args.qemu_include,
            selections=choices, samples=args.sample, case_id=args.case_id,
            max_nodes=args.max_producer_nodes)
    except (OSError, ValueError, KeyError, TypeError) as error:
        print('FAIL:', type(error).__name__ + ': ' + str(error), file=sys.stderr)
        return 1
    print(result['status'], result.get('counts', {}), flush=True)
    print('Summary:', output / 'summary.json', flush=True)
    return 0 if result['status'] == STATUS else 1


if __name__ == '__main__':
    raise SystemExit(main())
