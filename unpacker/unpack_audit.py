#!/usr/bin/env python3
"""Audit and consolidate generic selected-execution proof receipts.

No solver or guest is run. This checks receipt consistency, hash chains,
coverage and input identity; recorded solver answers and trusted models are
not independently proved by this audit. Raw producer graphs are not replayed.
The final-goal audit supports direct SOURCE110 values with zero bit offsets;
bundles requiring additional extraction operations are rejected.
"""
import argparse
import hashlib
import json
import math
from pathlib import Path
import re
import stat
import sys
import tempfile


# Keep the aggregate bound aligned with oep_schedule.SOURCE_LIMIT.
SOURCE_LIMIT = 262144


STATUS = 'GENERIC_SELECTED_EXECUTION_RECEIPTS_AUDITED'
PROOF_STATUS = 'SMT_PROVED_SELECTED_TRANSFER_AND_OBSERVED_IMAGE_UNDER_EXPLICIT_PREMISES'
INPUT_NAMES = ('source.elf', 'stack.bin', 'stack-mask.bin', 'scalars.txt', 'contracts.txt', 'config.txt')
FALSE_FLAGS = ('candidate_relation_added_to_source_premises', 'intermediate_values_admitted_without_SMT_proof',
               'checkpoint_used_as_seed', 'observed_final_state_used_as_input', 'original_elf_used_as_input',
               'historical_originality_proven', 'unconditional_oep_proven', 'target_instruction_executed',
               'fuzzing_ready', 'rebuilt_ELF_metadata_in_proved_image')
TRUE_FLAGS = ('selected_execution_proved', 'all_prefix_schedule_conditions_encoded_in_SMT',
              'all_observed_image_bytes_SMT_proved', 'computed_transfer_and_fetch_SMT_proved')


def require(value, message):
    if not value:
        raise ValueError(message)


def _integer(value, minimum=0, maximum=0xffffffff):
    require(type(value) is int and minimum <= value <= maximum, 'Invalid receipt integer')
    return value


def _sha(value):
    require(type(value) is str and re.fullmatch('[0-9a-f]{64}', value), 'Invalid receipt SHA256')
    return value


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def _json(data):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'Duplicate JSON key: ' + key)
            result[key] = value
        return result

    def floating(value):
        result = float(value)
        require(math.isfinite(result), 'Nonfinite JSON number')
        return result

    def constant(value):
        raise ValueError('Nonfinite JSON number: ' + value)

    try:
        return json.loads(data, object_pairs_hook=pairs, parse_float=floating, parse_constant=constant)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise ValueError('Invalid receipt JSON') from error


def _normalize(directory):
    path = Path(directory).expanduser().absolute()
    require(path.is_dir() and not path.is_symlink(), 'Proof directory missing or symlink: ' + str(path))
    if not (path / 'summary.json').is_file() and (path / 'probe/summary.json').is_file():
        path = path / 'probe'
    require(not path.is_symlink(), 'Proof directory is a symlink')
    return path.resolve()


class _Reader:
    def __init__(self, directory):
        self.root = _normalize(directory)
        self.hashes = {}

    def path(self, relative, limit):
        relative = Path(relative)
        require(not relative.is_absolute() and '..' not in relative.parts, 'Unsafe receipt path')
        path = self.root
        for part in relative.parts:
            path = path / part
            require(not path.is_symlink(), 'Receipt path is a symlink: ' + str(path))
        require(path.is_file() and stat.S_ISREG(path.stat().st_mode)
                and path.stat().st_size <= limit, 'Receipt missing or exceeds bound: ' + str(path))
        return path

    def blob(self, relative, limit=4 * 1024**2):
        path = self.path(relative, limit)
        with path.open('rb') as stream:
            data = stream.read(limit + 1)
        require(len(data) <= limit, 'Receipt grew beyond bound')
        self.hashes[str(relative)] = hashlib.sha256(data).hexdigest()
        return data

    def document(self, relative, limit=4 * 1024**2):
        result = _json(self.blob(relative, limit))
        require(type(result) is dict, 'Receipt must be a JSON object: ' + str(relative))
        return result


def _solver(report, phase, span):
    require(type(report) is dict and report.get('status') == 'PROVED', 'Unproved SMT query')
    require(report.get('goals') == span and type(report.get('goals')) is int, 'SMT goal coverage differs')
    for key in ('candidate_only_in_goals', 'model_built_by_existing_ir_smt',
                'original_source_inputs_symbolic_before_premises'):
        require(report.get(key) is True, 'SMT trust/provenance flag differs: ' + key)
    require(report.get('observed_checkpoint_used_as_premise') is False
            and report.get('lemma_inputs_symbolic') is False, 'Invalid SMT premise mode')
    original = _integer(report.get('original_source_premises'))
    lemmas = _integer(report.get('previously_proved_lemma_premises'))
    symbolic = _integer(report.get('smt_build', {}).get('symbolic_parameters'))
    require(report.get('source_premises') == original + lemmas, 'SMT source inventory differs')
    if phase == 'original_sources':
        require(report.get('proof_mode') == 'source_dag' and original == span and lemmas == 0
                and symbolic == span and report.get('proved_lemma_values_substituted') is False,
                'Original sources were not symbolic')
    else:
        require(report.get('proof_mode') == 'lemma_chunk'
                and report.get('proved_lemma_values_substituted') is True
                and symbolic == original, 'Invalid proved-lemma mode')
        require(original <= (1 if phase == 'schedule_producers' else 0), 'Unproved original source in goal query')
        if original:
            require(lemmas == 0 and original == 1, 'Invalid constant-block source fallback')
    checks = 0
    for name, expected in (('baseline', 'SAT'), ('counterexample', 'UNSAT')):
        answer = report.get(name)
        require(type(answer) is dict and answer.get('status') == expected, 'SMT answer is not ' + expected)
        entries = answer.get('checks')
        require(type(entries) is list and 0 < len(entries) <= 4
                and _integer(answer.get('solver_checks'), 1) == len(entries), 'SMT check count differs')
        require(all(type(entry) is dict and entry.get('returned') is True
                    and entry.get('result') == expected for entry in entries), 'Incomplete or UNKNOWN solver check')
        checks += len(entries)
    return checks


def _journal(reader, relative, plans, proof, *, goal_roots=None):
    path = reader.path(relative, 256 * 1024**2)
    chain, checks, queries, group, consumed = '0' * 64, 0, 0, 0, 0
    require(type(proof.get('z3_version')) is str and proof['z3_version'], 'Missing SMT solver version')
    position = plans[0][1]
    blocks = {phase: 0 for phase, _, _, _ in plans}
    raw_hash = hashlib.sha256()
    with path.open('rb') as stream:
        while True:
            line = stream.readline(1024**2 + 1)
            if not line:
                break
            consumed += len(line)
            require(consumed <= 256 * 1024**2, 'SMT journal grew beyond bound')
            require(len(line) <= 1024**2 and line.endswith(b'\n') and queries < 1000000,
                    'Truncated or oversized SMT journal line')
            raw_hash.update(line)
            row = _json(line)
            require(type(row) is dict and group < len(plans), 'Unexpected extra SMT query')
            phase, first, end, inclusive = plans[group]
            lo, hi = _integer(row.get('first')), _integer(row.get('last'))
            require(row.get('phase') == phase and lo == position and lo <= hi <= end,
                    'SMT phase/range coverage differs')
            span = hi - lo + inclusive
            require(span > 0 and (phase == 'original_sources' or span <= 4096), 'Invalid SMT block extent')
            if phase == 'original_sources' and 'source_blocks' in proof:
                require(span <= _integer(proof.get('source_chunk_size'), 1, 4096), 'Original source block exceeds bound')
            require(row.get('previous_receipt_sha256') == chain, 'Broken SMT receipt hash chain')
            for key in ('ledger_sha256', 'premises_sha256', 'goals_sha256'):
                _sha(row.get(key))
            report = row.get('solver')
            checks += _solver(report, phase, span)
            if goal_roots is not None:
                require(report.get('producer_nodes') == span
                        and report.get('opcode_counts') == {'110': span}
                        and report.get('previously_proved_lemma_premises') == span,
                        'Unsupported final-goal extraction audit profile')
                batch = goal_roots[lo:hi]
                require(len(batch) == span and all(root['offset'] == 0 for root in batch),
                        'Unsupported final-goal bit offset')
                conclusions = ''.join(f"{i} {root['expected']:x}\n" for i, root in enumerate(batch, 1)).encode()
                premises = ''.join(f"{i} {root['expected']:x} {(1 << root['bits']) - 1:x}\n"
                                   for i, root in enumerate(batch, 1)).encode()
                require(hashlib.sha256(conclusions).hexdigest() == row['goals_sha256']
                        and hashlib.sha256(premises).hexdigest() == row['premises_sha256'],
                        'Final goal values differ from recorded SMT query')
            require(report.get('z3_version') == proof['z3_version'],
                    'SMT solver version differs')
            chain = hashlib.sha256(_canonical(row)).hexdigest()
            queries += 1
            blocks[phase] += 1
            position = hi + inclusive
            if position == end + inclusive:
                group += 1
                if group < len(plans):
                    position = plans[group][1]
    require(group == len(plans), 'Incomplete SMT journal coverage')
    require(_integer(proof.get('queries'), 1) == queries
            and _integer(proof.get('solver_checks'), 1) == checks
            and proof.get('last_receipt_sha256') == chain, 'SMT journal totals/digest differ')
    reader.hashes[relative] = raw_hash.hexdigest()
    if 'queries_sha256' in proof:
        require(proof['queries_sha256'] == raw_hash.hexdigest(), 'SMT journal file digest differs')
    return blocks, checks


def _native_sources(reader, name, flag):
    receipt = reader.document('smt/' + name + '/receipt.json')
    require(receipt.get('uploaded_native_objects_linked') is False and receipt.get(flag) is True,
            'Native source-build receipt differs')
    sources = receipt.get('source_files_sha256')
    require(type(sources) is dict and 0 < len(sources) <= 128, 'Native source inventory missing')
    for filename, expected in sources.items():
        require(type(filename) is str and Path(filename).name == filename, 'Unsafe native source name')
        require(hashlib.sha256(reader.blob('smt/' + name + '/sources/' + filename)).hexdigest() == _sha(expected),
                'Native source digest differs: ' + filename)


def _rep_retained_calibration(document, *, project=None):
    """Reaudit retained thin evidence and current source identities only."""
    try:
        from . import rep_callbacks
    except ImportError:
        import rep_callbacks
    project = Path(project).resolve(strict=True) if project is not None else Path(__file__).resolve().parents[1]
    for relative in rep_callbacks.SOURCE_FILES:
        path = rep_callbacks._plain_file(project,relative,16*1024**2)
        require(rep_callbacks.digest(path) == document['source_sha256'][relative],
                'Retained REP calibration source changed: '+relative)
    # This shared read-only helper authenticates trace/report/launch/fixture
    # files and source-bound observed fetches; no guest or solver is rerun.
    rep_callbacks._audit_thin_evidence(document)


def _rep_runtime_binding(reader, certificate, summary, execution, launch, *, calibration_project=None):
    """Bind a new explicit callback model to its retained calibration receipt.

    This is a persisted-receipt audit. Retained thin evidence and current
    calibration source identities are reaudited; neither the guest calibration
    nor the solver is rerun, and this does not prove the runtime implementation.
    """
    try:
        from . import rep_callbacks
    except ImportError:
        import rep_callbacks
    raw = reader.blob('inputs/config.txt', 1024**2)
    try:
        tokens = raw.decode('ascii').split()
    except UnicodeError as error:
        raise ValueError('Non-ASCII replay config') from error
    explicit = bool(tokens and tokens[0] == 'TFOEPGEN1C')
    binding = certificate.get('rep_runtime_binding')
    if not explicit:
        flag = execution.get('rep_callback_profile_explicit')
        require(binding is None and summary.get('rep_runtime_binding') is None and
                (flag is None or flag is False),
                'Legacy replay cannot inherit an explicit REP callback profile')
        if 'rep_callback_mode' in execution:
            require(execution.get('rep_callback_mode') == 'terminal_zero' and
                    execution.get('instruction_count_semantics') ==
                    'qemu_i386_normal_rep_n_plus_one_v1',
                    'Legacy replay callback interpretation differs')
        return None
    require(type(binding) is dict and set(binding) == {
        'mode','semantics','calibration_sha256','qemu_sha256','observer_sha256','sdk_sha256'},
        'Explicit replay lacks a complete REP runtime binding')
    require(summary.get('rep_runtime_binding') == binding,
            'Summary REP runtime binding differs')
    mode = binding.get('mode')
    expected_semantics = rep_callbacks.semantics(mode)
    require(binding.get('semantics') == expected_semantics and
            execution.get('rep_callback_profile_explicit') is True and
            execution.get('rep_callback_mode') == mode and
            execution.get('instruction_count_semantics') == expected_semantics,
            'Replay REP callback profile differs from certificate')
    try:
        require(len(tokens) >= 6, 'Incomplete explicit REP replay configuration')
        target, stack, limit = int(tokens[1],16), int(tokens[2],16), int(tokens[3],10)
        count = int(tokens[5],10)
        require(1 <= count <= 256 and len(tokens) == 6 + count * 2,
                'Explicit REP replay range inventory differs')
        ranges = [dict(address=int(tokens[6+2*i],16),size=int(tokens[7+2*i],10))
                  for i in range(count)]
    except (ValueError, OverflowError) as error:
        raise ValueError('Malformed explicit REP replay configuration') from error
    require(tokens[4] == mode and target == certificate.get('selected_transfer') and
            raw == rep_callbacks.config_text(target,stack,limit,ranges,mode).encode('ascii'),
            'Callback profile is not bound by the canonical replay configuration')
    require(launch.get('execution_mode') == 'normal',
            'Calibrated GEN1 proof requires the recorded normal launch mode')
    argv = launch.get('argv')
    require(type(argv) is list and 2 <= len(argv) <= 64 and
            all(type(word) is str and '\0' not in word for word in argv) and
            not any(word.startswith(('-one-insn-per-tb','--one-insn-per-tb',
                                     '-singlestep','--singlestep')) for word in argv),
            'GEN1 launch arguments select an uncalibrated instruction mode')
    native = summary.get('native_build')
    require(type(native) is dict, 'Explicit REP proof lacks its native build binding')
    for key in ('qemu_sha256','observer_sha256','sdk_sha256','calibration_sha256'):
        _sha(binding.get(key))
    require(binding['qemu_sha256'] == launch.get('qemu_sha256') and
            binding['observer_sha256'] == launch.get('plugin_sha256') == native.get('observer_sha256') and
            binding['sdk_sha256'] == native.get('sdk_sha256'),
            'REP calibration and proof runtime identities differ')
    document = reader.document('rep-calibration.json',8 * 1024**2)
    require(reader.hashes['rep-calibration.json'] == binding['calibration_sha256'],
            'Retained REP calibration receipt digest differs')
    rep_callbacks.validate_calibration(document,qemu_sha256=binding['qemu_sha256'],
        observer_sha256=binding['observer_sha256'],sdk_sha256=binding['sdk_sha256'])
    require(document['profiles']['normal'] == mode,
            'Replay callback profile was not selected by normal-mode calibration')
    if calibration_project is None:
        _rep_retained_calibration(document)
    else:
        _rep_retained_calibration(document, project=calibration_project)
    return dict(binding)


def _launch_input_binding(reader, summary, certificate, launch, *, expected_launch_case=None):
    """Bind a fixed launch case to retained observations and replay premises.

    This rechecks serialized launch/constructor evidence. It does not rerun
    QEMU or SMT, prove the kernel, or admit stdin bytes as replay memory.
    """
    artifacts = ('capture/launch-case.json', 'capture/stdin.bin')
    marked = (launch.get('launch_input_profile') is not None or
              summary.get('launch_input_profile') is not None or
              summary.get('launch_input_binding') is not None or
              any((reader.root / name).exists() or (reader.root / name).is_symlink()
                  for name in artifacts))
    if not marked:
        require(expected_launch_case is None, 'Expected launch case is absent from proof')
        return None
    try:
        from . import unpack_launch, unpack_observations, unpack_sources
    except ImportError:
        import unpack_launch, unpack_observations, unpack_sources
    require(launch.get('launch_input_profile') == summary.get('launch_input_profile') ==
            unpack_launch.PROFILE, 'Fixed launch input profile differs')
    raw_case = reader.blob('capture/launch-case.json', 2 * 1024**2)
    case = _json(raw_case)
    case = unpack_launch.normalize_case(case)
    require(raw_case == unpack_launch.case_bytes(case), 'Launch case is not canonical')
    if expected_launch_case is not None:
        require(unpack_launch.case_bytes(expected_launch_case) == raw_case,
                'Proof launch case differs from requested case')
    incoming = reader.blob('capture/stdin.bin', 1024**2)
    binding = unpack_launch.validate_launch(launch, case, incoming,
                                           capture_directory=reader.root / 'capture')
    require(summary.get('launch_input_binding') == binding,
            'Summary launch input binding differs')
    if 'launch_input_binding' in certificate:
        require(certificate['launch_input_binding'] == binding,
                'Certificate launch input binding differs')
    # Only recognized source versions are admitted. Retained source is read as
    # data and is never imported or executed by the receipt audit.
    source_receipt = reader.document('source-receipt.json')
    for name in ('unpack_launch.py', 'unpack_process.py'):
        retained = reader.blob('source/' + name, 1024**2)
        current = (Path(__file__).resolve().parent / name).read_bytes()
        require(hashlib.sha256(retained).hexdigest() == _sha(source_receipt.get(name))
                and retained == current, 'Fixed launch validator source differs: ' + name)
    packed = reader.blob('inputs/source.elf', 16 * 1024**2)
    events = reader.blob('capture/events.jsonl', 128 * 1024**2)
    require(hashlib.sha256(events).hexdigest() == summary.get('capture_events_sha256'),
            'Fixed launch capture event identity differs')
    rows = unpack_observations.read_capture(events, launch)
    context = unpack_observations.initial_context(rows, packed,
        unpack_sources.loader_regions(packed), launch=launch)
    projection = reader.blob('inputs/stack-mask.bin', 1024**2)
    premises = unpack_observations.validate_projection(context, projection)
    require(reader.document('initial-premises.json') == premises,
            'Fixed launch entry origin receipt differs')
    reduced_stack = bytes(value & known for value, known in zip(context['stack'], projection))
    require(reader.blob('inputs/stack.bin', 1024**2) == reduced_stack,
            'Fixed launch replay stack differs from constructor projection')
    require(reader.blob('inputs/scalars.txt') ==
            f"{context['esp']:x} {context['df']:x}\n".encode('ascii'),
            'Fixed launch entry scalars differ')
    require(reader.blob('inputs/contracts.txt') ==
            unpack_observations.contracts_text(rows).encode('ascii'),
            'Fixed launch syscall contracts differ')
    # Successful observations permit only the existing bounded syscall model,
    # which deliberately excludes read/readv and other stdin consumers.
    require(all(entry['number'] in unpack_observations.SUPPORTED_SYSCALLS and
                entry['number'] != 3 for entry, _, _ in context['calls']),
            'Fixed launch prefix consumes unsupported input')
    try:
        config = reader.blob('inputs/config.txt').decode('ascii').split()
        require(len(config) >= 4 and config[0] == 'TFOEPGEN1C' and
                int(config[1], 16) == certificate.get('selected_transfer') and
                int(config[2], 16) == context['stack_base'],
                'Fixed launch replay configuration differs')
    except (UnicodeError, OverflowError) as error:
        raise ValueError('Malformed fixed launch replay configuration') from error
    return dict(binding, receipt_audit_only=True, solver_not_rerun=True,
                entry_constructor_and_launch_strings_reaudited=True,
                consumed_stack_projection_reaudited=True)


def audit_sample(directory, *, calibration_project=None, expected_launch_case=None):
    """Check one completed receipt bundle, without rerunning its solver."""
    reader = _Reader(directory)
    summary = reader.document('summary.json')
    certificate = reader.document('smt/certificate.json')
    require(certificate.get('status') == PROOF_STATUS and summary.get('errors') == [], 'Sample proof failed')
    for key, value in certificate.items():
        require(key in summary and type(summary[key]) is type(value) and summary[key] == value,
                'Summary/certificate differs: ' + key)
    require(all(certificate.get(k) is True for k in TRUE_FLAGS)
            and all(certificate.get(k) is False for k in FALSE_FLAGS), 'Unsupported proof scope or premise flags')
    for key in ('universal_equivalence', 'original_required', 'original_prepack_OEP_independently_established',
                'process_snapshot', 'output_bytes_used_as_initial_premises'):
        require(key not in summary or summary[key] is False, 'Unsupported summary scope: ' + key)
    premises = certificate.get('conditions')
    require(type(premises) is list and 0 < len(premises) <= 64
            and all(type(item) is str and 0 < len(item) <= 8192 for item in premises), 'Explicit proof premises missing')
    require(certificate.get('source_premise_query') == 'SAT'
            and certificate.get('image_and_transfer_counterexample_query') == 'UNSAT'
            and certificate.get('SMT_proof_mode') == 'TOPOLOGICAL_SMT_INDUCTION', 'Incomplete theorem receipt')
    target = _integer(certificate.get('selected_transfer'))
    instructions = _integer(certificate.get('instructions'), 1)
    require(summary.get('target') == target, 'Summary transfer differs')
    packed = hashlib.sha256(reader.blob('inputs/source.elf')).hexdigest()
    hashes = [hashlib.sha256(reader.blob('inputs/' + n)).hexdigest() for n in INPUT_NAMES]
    require(certificate.get('packed_sha256') == packed
            and certificate.get('replay_input_files_sha256') == hashes, 'Replay input identity differs')
    selection = reader.document('selection.json')
    require(selection.get('packed_sha256') == packed and selection.get('target') == target
            and selection.get('observations_used_as_replay_initial_state') is False
            and selection.get('previous_proof_status_inherited') is False
            and summary.get('selection_receipt_sha256') == reader.hashes['selection.json'], 'Selection binding differs')
    launch = reader.document('capture/launch.json')
    require(hashlib.sha256(reader.blob('capture/packed.elf')).hexdigest() == packed
            and launch.get('source_elf_sha256') == packed and launch.get('target') == target
            and launch.get('target_pc') == target and launch.get('run_id') == summary.get('run_id')
            and launch.get('new_independent_execution') is True and launch.get('returncode') == 0
            and launch.get('payload_instruction_execution_allowed') is False, 'Capture run binding differs')
    capture = reader.document('capture/report.json')
    require(capture.get('success') is True and capture.get('boundary_reached') is True
            and capture.get('target_instruction_executed') is False and capture.get('target_pc') == target
            and capture.get('elf_sha256') == packed and capture.get('run_id') == summary.get('run_id')
            and capture.get('instructions') == instructions
            and capture.get('executed_pc_sha256') == certificate.get('path_sha256')
            and capture.get('events_sha256') == _sha(summary.get('capture_events_sha256')),
            'Capture boundary/report binding differs')
    execution = reader.document('reduced/execution.json')
    launch_binding = _launch_input_binding(reader, summary, certificate, launch,
                                          expected_launch_case=expected_launch_case)
    rep_binding = _rep_runtime_binding(reader,certificate,summary,execution,launch,
                                      calibration_project=calibration_project)
    manifest = reader.document('reduced/producers/manifest.json')
    require(execution.get('pc') == target and execution.get('instructions') == instructions
            and execution.get('path_sha256') == certificate.get('path_sha256')
            and manifest.get('instructions') == instructions
            and manifest.get('path_sha256') == certificate.get('path_sha256')
            and manifest.get('nodes_sha256') == certificate.get('producer_ledger_sha256')
            and manifest.get('input_files_sha256') == hashes
            and manifest.get('source_kind') == 'computed_generic_entry_IR_producers'
            and manifest.get('condition_schema_version') == 1
            and manifest.get('computed_transfer_targets_recorded') is True
            and manifest.get('kernel_checked_path_bytes_recorded') is True
            and execution.get('checkpoint_used_as_seed') is False
            and execution.get('observed_final_state_used_as_input') is False
            and execution.get('target_instruction_executed') is False
            and manifest.get('checkpoint_used_as_seed') is False
            and manifest.get('observed_final_state_used_as_input') is False, 'Replay/producer manifest binding differs')
    schedule = reader.document('smt/schedule-proof.json')
    goals = reader.document('smt/goals-proof.json')
    prepared = reader.document('smt/schedule/receipt.json')
    evaluation = reader.document('smt/schedule/evaluation.json')
    checked = reader.document('smt/schedule/condition-check.json')
    require(schedule.get('status') == goals.get('status') == 'PROVED'
            and prepared.get('status') == 'PREPARED' and evaluation.get('status') == 'EVALUATED'
            and checked.get('status') == 'MATCHED_PROVED_VALUES'
            and evaluation.get('values_are_proposed_lemmas_only') is True
            and evaluation.get('observed_checkpoint_used_as_premise') is False,
            'Incomplete schedule/goal receipts')
    nodes = _integer(certificate.get('schedule_producer_nodes'), 1)
    sources = _integer(certificate.get('schedule_source_premises'), 1, SOURCE_LIMIT)
    conditions = _integer(certificate.get('schedule_unique_condition_goals'), 1)
    occurrences = _integer(certificate.get('schedule_condition_count'), 1)
    require(schedule.get('proved_nodes') == prepared.get('compact_nodes') == evaluation.get('producer_nodes') == nodes
            and evaluation.get('fully_known_nodes') == nodes
            and schedule.get('source_premises') == prepared.get('source_leaves') == sources
            and evaluation.get('source_premises') == sources
            and schedule.get('condition_goal_count') == prepared.get('condition_goal_count') == conditions
            and schedule.get('condition_count') == manifest.get('condition_count') == prepared.get('condition_count') == occurrences
            and checked.get('condition_count') == checked.get('checked_occurrences') == occurrences
            and checked.get('first_mismatching_occurrence') == 0
            and schedule.get('all_condition_occurrences_checked') is True
            and schedule.get('all_condition_goals_encoded_in_SMT') is True, 'Incomplete producer/condition coverage')
    require(schedule.get('compact_sha256') == _sha(prepared.get('compact_sha256'))
            and schedule.get('values_sha256') == goals.get('schedule_values_sha256') == _sha(evaluation.get('values_sha256'))
            and prepared.get('nodes') == manifest.get('node_count')
            and checked.get('kind_counts') == prepared.get('kind_counts')
            and prepared.get('kind_counts') == [0] + [manifest.get('condition_kind_counts', {}).get(str(k)) for k in range(1, 10)],
            'Schedule artifact identity differs')
    kinds = prepared['kind_counts']
    require(len(kinds) == 10 and all(type(value) is int and value >= 0 for value in kinds)
            and kinds[0] == 0 and kinds[8] > 0 and sum(kinds) == occurrences,
            'Condition kind counts differ from recorded occurrences')
    blocks, first_checks = _journal(reader, 'smt/schedule-queries.jsonl',
        [('original_sources', 1, sources, 1), ('schedule_producers', 1, nodes, 1),
         ('schedule_conditions', 0, conditions, 0)], schedule)
    require(blocks['schedule_producers'] == schedule.get('producer_blocks')
            and blocks['schedule_conditions'] == schedule.get('condition_blocks')
            and blocks['original_sources'] == schedule.get('source_blocks', 1), 'Schedule block totals differ')
    if 'source_blocks' in schedule:
        require(schedule.get('source_proof_mode') == 'DISJOINT_AUTHENTICATED_SOURCE_EQUALITIES',
                'Unsupported source partition mode')
        _sha(schedule.get('source_inventory_sha256'))
    goal_receipt = reader.document('smt/goal-receipt.json', 32 * 1024**2)
    roots = goal_receipt.get('goals')
    require(type(roots) is list and 0 < len(roots) <= 262144 and len(roots) == goals.get('goals')
            and goal_receipt.get('producer_ledger_sha256') == manifest.get('nodes_sha256')
            and goal_receipt.get('candidate_relation_added_to_source_premises') is False
            and goal_receipt.get('source_values_authenticated_by_schedule_proof') is True,
            'Final goal inventory differs')
    targets = [r for r in roots if type(r) is dict and r.get('label') == 'target']
    require(len(targets) == 1 and targets[0].get('expected') == target
            and targets[0].get('address') == target and targets[0].get('id') == manifest.get('target_root'),
            'Computed transfer goal differs')
    labels = {'target': (32, 1), 'observed_image_byte': (8, certificate.get('observed_image_bytes')),
              'target_fetch_byte': (8, certificate.get('target_fetch_bytes')),
              'instruction_fetch_byte': (8, certificate.get('instruction_fetch_bytes')),
              'REP_expansion_count': (32, certificate.get('REP_expansion_counts'))}
    counts, unique, image_values = {label: 0 for label in labels}, {}, {}
    for root in roots:
        require(type(root) is dict and root.get('label') in labels, 'Unknown final goal kind')
        label = root['label']
        bits, _ = labels[label]
        _integer(root.get('id'), 1, _integer(manifest.get('node_count'), 1))
        address = _integer(root.get('address'))
        require(root.get('bits') == bits and type(root.get('bits')) is int, 'Invalid final goal width')
        _integer(root.get('expected'), 0, (1 << bits) - 1)
        _integer(root.get('offset'), 0, 64 - bits)
        counts[label] += 1
        if label in ('target', 'observed_image_byte', 'target_fetch_byte'):
            addresses = unique.setdefault(label, set())
            require(address not in addresses, 'Duplicate final image/transfer address')
            addresses.add(address)
        if label == 'observed_image_byte':
            image_values[address] = root['expected']
    require(all(counts[label] == _integer(count) for label, (_, count) in labels.items()),
            'Final goal kind coverage differs')
    require(unique.get('target_fetch_byte') == set(range(target, target + counts['target_fetch_byte']))
            and 0 < counts['target_fetch_byte'] <= 15, 'Target fetch byte coverage differs')
    regions = selection.get('goals')
    require(type(regions) is list and 0 < len(regions) <= 4096, 'Observed image selection missing')
    extents, total = [], 0
    for region in regions:
        require(type(region) is dict, 'Invalid image region')
        start = _integer(region.get('address'))
        size = _integer(region.get('size'), 1, 16 * 1024**2)
        _integer(region.get('prot'), 0, 7)
        require(start + size <= 1 << 32 and total + size <= 16 * 1024**2,
                'Observed image region exceeds bound')
        require(all(address in image_values for address in range(start, start + size)),
                'Missing selected observed image byte')
        image = bytes(image_values[address] for address in range(start, start + size))
        require(hashlib.sha256(image).hexdigest() == _sha(region.get('sha256')), 'Observed image goal bytes differ')
        extents.append((start, start + size))
        total += size
    extents.sort()
    require(total == len(image_values) and all(a[1] <= b[0] for a, b in zip(extents, extents[1:])),
            'Observed image selection coverage differs')
    require(all(root['expected'] == image_values.get(root['address'])
                for root in roots if root['label'] == 'target_fetch_byte'), 'Target fetch/image byte differs')
    for key in ('observed_image_bytes', 'instruction_variants', 'instruction_fetch_bytes', 'REP_expansion_counts', 'target_fetch_bytes'):
        require(goal_receipt.get(key) == certificate.get(key), 'Goal coverage receipt differs: ' + key)
    require(goals.get('baseline') == 'SAT' and goals.get('counterexample') == 'UNSAT'
            and goals.get('only_schedule_proved_values_used_as_lemmas') is True, 'Incomplete final goals')
    _, last_checks = _journal(reader, 'smt/goal-proof/schedule-queries.jsonl',
                             [('observed_image_and_transfer', 0, len(roots), 0)],
                             {**goals, 'z3_version': schedule.get('z3_version')}, goal_roots=roots)
    require(_integer(certificate.get('SMT_solver_checks'), 1) == first_checks + last_checks,
            'Certificate SMT check total differs')
    _native_sources(reader, 'native-smt', 'existing_IR_SMT_backend')
    _native_sources(reader, 'native-schedule', 'helper_produces_conjectures_only')
    return {'status': STATUS, 'proof_directory': str(reader.root), 'packed_sha256': packed,
            'target': target, 'instructions': instructions, 'SMT_solver_checks': first_checks + last_checks,
            'receipt_audit_only': True, 'solver_not_rerun': True,
            'historical_originality_proven': False, 'universal_equivalence': False, 'fuzzing_ready': False,
            'explicit_premises': certificate.get('conditions'), 'audited_file_sha256': reader.hashes,
            **({'launch_input_binding': launch_binding, 'fixed_launch_case_audited': True}
               if launch_binding is not None else {}),
            **({'rep_runtime_binding':rep_binding,'REP_runtime_binding_audited':True}
               if rep_binding is not None else {})}


def audit_matrix(matrix, overrides, output):
    """Consolidate successful receipts into a new report; preserve old runs."""
    reader = _Reader(matrix)
    prior = reader.document('summary.json')
    rows = prior.get('samples')
    require(type(rows) is list and 0 < len(rows) <= 64 and type(overrides) is dict, 'Matrix sample inventory missing')
    names = [row.get('sample') for row in rows if type(row) is dict]
    require(len(names) == len(rows) and all(type(n) is str and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', n) for n in names)
            and len(set(names)) == len(names) and set(overrides) <= set(names), 'Invalid matrix sample/override inventory')
    destination = Path(output).expanduser().absolute()
    require(not destination.is_symlink(), 'Audit output is a symlink')
    destination = destination.resolve()
    inputs = [reader.root] + [_normalize(p) for p in overrides.values()]
    require(not destination.exists() and all(p != destination and p not in destination.parents for p in inputs),
            'Audit output must be new and outside input runs')
    results = []
    for row in rows:
        name = row['sample']
        original = _Reader(reader.root / name)
        selection = original.document('selection.json')
        packed = hashlib.sha256(original.blob('inputs/source.elf')).hexdigest()
        require(selection.get('packed_sha256') == packed
                and (row.get('packed_sha256') is None or row['packed_sha256'] == packed), 'Original matrix packed identity differs')
        result = audit_sample(overrides.get(name, original.root))
        require(result['packed_sha256'] == packed and result['target'] == selection.get('target'),
                'Replacement proof belongs to a different packed sample/selection')
        if name not in overrides:
            require(row.get('status') == PROOF_STATUS and row.get('selected_execution_proved') is True
                    and row.get('errors') == [] and row.get('target') == result['target']
                    and row.get('instructions') == result['instructions']
                    and row.get('SMT_solver_checks') == result['SMT_solver_checks'], 'Original matrix row differs from proof')
        result.update(sample=name, replacement_used=name in overrides,
                      original_proof_directory=str(original.root), original_binding_sha256=original.hashes)
        results.append(result)
    result = {'schema_version': 1, 'status': STATUS, 'errors': [], 'samples': results,
              'matrix_directory': str(reader.root), 'matrix_summary_sha256': reader.hashes['summary.json'],
              'sample_count': len(results), 'SMT_solver_checks': sum(r['SMT_solver_checks'] for r in results),
              'all_selected_execution_proof_receipts_audited': True,
              'receipt_audit_only': True, 'solver_not_rerun': True, 'historical_originality_proven': False,
              'universal_equivalence': False, 'fuzzing_ready': False}
    destination.mkdir(parents=True)
    (destination / 'summary.json').write_text(json.dumps(result, indent=2, sort_keys=True, allow_nan=False) + '\n')
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--matrix', type=Path, required=True)
    parser.add_argument('--sample-proof', action='append', default=[], metavar='NAME=PATH')
    parser.add_argument('--output', type=Path)
    args = parser.parse_args(argv)
    output = args.output
    try:
        overrides = {}
        for item in args.sample_proof:
            name, separator, value = item.partition('=')
            require(separator and name and value and name not in overrides, 'Duplicate or invalid --sample-proof')
            overrides[name] = Path(value)
        if output is None:
            output = Path(tempfile.mkdtemp(prefix='unpack-proof.audit-', dir=Path(__file__).resolve().parent)) / 'probe'
        print('Results:', output, flush=True)
        result = audit_matrix(args.matrix, overrides, output)
        print(result['status'], flush=True)
        print('Audited selected-execution receipts:', result['sample_count'], flush=True)
        return 0
    except (OSError, ValueError, KeyError, TypeError, RecursionError) as error:
        print('FAIL: ' + type(error).__name__ + ': ' + str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
