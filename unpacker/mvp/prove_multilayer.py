#!/usr/bin/env python3
"""Fresh original-entry IR/SMT proofs for observed layer transfers and code."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import shlex
import subprocess
import sys
import tempfile
import uuid

from check_runtime_flags import check_flags
from run_runtime_dse_audit import build_flags
from ct_elf import captured_bytes, load_capture

STATUS = 'SMT_PROVED_OBSERVED_LAYER_TRANSFERS_AND_CODE_UNDER_EXPLICIT_PREMISES'
INPUT_NAMES = ('source.elf', 'stack.bin', 'stack-mask.bin', 'scalars.txt', 'contracts.txt', 'config.txt')
IR_SOURCES = ('ir.c', 'ir_environment.c', 'trace.c', 'ir_lift_x86.c')
SOLVER_SOURCES = ('ir.c', 'ir_eval.c', 'ir_inputs.c', 'ir_smt.c', 'replay_sources.c')
NATIVE_HELPERS = ('oep_execute.c', 'oep_generic_execute.h', 'oep_producers.h')
PYTHON_HELPERS = ('unpack_smt.py', 'unpack_sources.py', 'unpack_observations.py', 'oep_smt.py',
                  'oep_schedule.py', 'oep_verify.py', 'oep_entry.py', 'oep_environment.py',
                  'oep_boundary.py', 'oep_current_run.py', 'oep_observations.py')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def save(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + '\n')


def read_json(path, maximum=16 * 1024**2):
    path = Path(path)
    require(path.is_file() and not path.is_symlink() and 0 < path.stat().st_size <= maximum,
            'Missing, symlink or oversized JSON: ' + str(path))
    def pairs(rows):
        result = {}
        for key, value in rows:
            require(key not in result, 'Duplicate JSON key: ' + key)
            result[key] = value
        return result
    def invalid(value):
        raise ValueError('Nonfinite JSON value: ' + value)
    return json.loads(path.read_bytes(), object_pairs_hook=pairs, parse_constant=invalid)


def regular(path, maximum):
    path = Path(path).expanduser().absolute()
    require(path.is_file() and not path.is_symlink() and 0 < path.stat().st_size <= maximum,
            'Missing, symlink or oversized input: ' + str(path))
    return path.resolve(strict=True)


def pin(paths):
    return {str(path): digest(path) for path in paths}


def check_pins(inventory):
    require(all(Path(path).is_file() and not Path(path).is_symlink() and digest(path) == wanted
                for path, wanted in inventory.items()), 'Pinned input/runtime/source changed')


def artifact_pins(directory):
    entries = list(directory.rglob('*'))
    require(len(entries) <= 2048 and all(not path.is_symlink() for path in entries),
            'Invalid or oversized stage artifact tree')
    return pin(path for path in entries if path.is_file())


def check_SMT_query_receipts(directory, certificate):
    """Check persisted query completeness; this does not rerun the solver."""
    directory = Path(directory)
    schedule = read_json(directory / 'schedule-proof.json')
    goals = read_json(directory / 'goals-proof.json')

    def integer(value, label, minimum=0):
        require(type(value) is int and minimum <= value <= 2**32 - 1, label)
        return value

    def journal(path, record, phases):
        regular(path, 128 * 1024**2)
        raw = path.read_bytes()
        lines = raw.splitlines(keepends=True)
        require(lines and len(lines) <= 100000 and
                all(line.endswith(b'\n') and len(line) <= 4 * 1024**2 for line in lines),
                'Invalid SMT query journal framing')
        chain, checks = '0' * 64, 0
        positions = {name: start for name, start, _ in phases}
        blocks = {name: 0 for name, _, _ in phases}
        last_phase = 0
        def pairs(items):
            result = {}
            for key, value in items:
                require(key not in result, 'Duplicate SMT query JSON key')
                result[key] = value
            return result
        def invalid(value):
            raise ValueError('Nonfinite SMT query JSON value: ' + value)
        for line in lines:
            row = json.loads(line, object_pairs_hook=pairs, parse_constant=invalid)
            require(type(row) is dict, 'SMT query row must be an object')
            encoded = json.dumps(row, sort_keys=True, separators=(',', ':')).encode()
            require(line == encoded + b'\n' and row.get('previous_receipt_sha256') == chain,
                    'SMT query checksum chain or canonical encoding differs')
            chain = hashlib.sha256(encoded).hexdigest()
            require(all(type(row.get(key)) is str and re.fullmatch('[0-9a-f]{64}', row[key])
                        for key in ('ledger_sha256', 'premises_sha256', 'goals_sha256')),
                    'SMT query input digests are missing or invalid')
            phase = row.get('phase')
            index = next((i for i, item in enumerate(phases) if item[0] == phase), None)
            require(index is not None and index >= last_phase,
                    'Missing, unknown or reordered SMT query phase')
            last_phase = index
            first = integer(row.get('first'), 'SMT query range start')
            last = integer(row.get('last'), 'SMT query range end')
            inclusive = phases[index][1] == 1
            length = last - first + int(inclusive)
            require(first == positions[phase] and 0 < length <= 4096,
                    'SMT query phase coverage gap or overlapping range')
            positions[phase] = last + int(inclusive)
            blocks[phase] += 1
            solver = row.get('solver')
            require(type(solver) is dict and solver.get('status') == 'PROVED' and
                    solver.get('candidate_only_in_goals') is True and
                    solver.get('observed_checkpoint_used_as_premise') is False and
                    integer(solver.get('goals'), 'SMT query goal count', 1) == length,
                    'Incomplete or promoted SMT query result')
            for part, wanted in (('baseline', 'SAT'), ('counterexample', 'UNSAT')):
                answer = solver.get(part)
                require(type(answer) is dict and answer.get('status') == wanted,
                        'SMT query is UNKNOWN or not a proved SAT/UNSAT result')
                count = integer(answer.get('solver_checks'), 'SMT query solver checks', 1)
                detailed = answer.get('checks')
                require(type(detailed) is list and len(detailed) == count and
                        all(type(check) is dict and check.get('returned') is True and
                            check.get('result') == wanted for check in detailed),
                        'SMT solver-check inventory differs')
                checks += count
        for phase, start, expected in phases:
            require(blocks[phase] > 0 and positions[phase] == expected + start,
                    'Incomplete persisted SMT query phase: ' + phase)
        require(record.get('status') == 'PROVED' and
                integer(record.get('queries'), 'SMT proof query count', 1) == len(lines) and
                integer(record.get('solver_checks'), 'SMT proof solver checks', 1) == checks and
                record.get('last_receipt_sha256') == chain,
                'Persisted SMT query count/checksum differs from proof receipt')
        return {'queries': len(lines), 'solver_checks': checks,
                'sha256': hashlib.sha256(raw).hexdigest(), 'blocks': blocks}

    source_count = integer(certificate.get('schedule_source_premises'), 'SMT source count', 1)
    producer_count = integer(certificate.get('schedule_producer_nodes'), 'SMT producer count', 1)
    condition_count = integer(certificate.get('schedule_unique_condition_goals'), 'SMT condition goals', 1)
    require(schedule.get('source_premises') == source_count and
            schedule.get('proved_nodes') == producer_count and
            schedule.get('condition_goal_count') == condition_count and
            schedule.get('condition_count') == certificate.get('schedule_condition_count') and
            schedule.get('all_condition_occurrences_checked') is True and
            schedule.get('all_condition_goals_encoded_in_SMT') is True,
            'Schedule proof coverage differs from generic certificate')
    checked_schedule = journal(directory / 'schedule-queries.jsonl', schedule,
        [('original_sources', 1, source_count), ('schedule_producers', 1, producer_count),
         ('schedule_conditions', 0, condition_count)])
    for phase, key in (('original_sources', 'source_blocks'),
                       ('schedule_producers', 'producer_blocks'),
                       ('schedule_conditions', 'condition_blocks')):
        require(schedule.get(key) == checked_schedule['blocks'][phase],
                'Persisted SMT query block count differs: ' + phase)
    goal_count = 1 + sum(integer(certificate.get(key), 'SMT final goal coverage ' + key) for key in
                         ('observed_image_bytes', 'instruction_fetch_bytes',
                          'target_fetch_bytes', 'REP_expansion_counts'))
    require(goals.get('goals') == goal_count and
            goals.get('only_schedule_proved_values_used_as_lemmas') is True,
            'SMT final goal coverage differs from generic certificate')
    checked_goals = journal(directory / 'goal-proof/schedule-queries.jsonl', goals,
                            [('observed_image_and_transfer', 0, goal_count)])
    require(goals.get('queries_sha256') == checked_goals['sha256'] and
            checked_schedule['solver_checks'] + checked_goals['solver_checks'] ==
            certificate.get('SMT_solver_checks'),
            'Persisted SMT query checks/hash differ from generic certificate')
    return {'status': 'PASS_COMPLETE_PERSISTED_SMT_QUERY_RECEIPTS',
            'schedule': checked_schedule, 'goals': checked_goals,
            'schedule_proof_sha256': digest(directory / 'schedule-proof.json'),
            'goals_proof_sha256': digest(directory / 'goals-proof.json'),
            'generic_certificate_sha256': digest(directory / 'certificate.json'),
            'independent_solver_rerun_performed': False}


def source_inventory(project):
    test = project / 'unpacker/test'
    paths = [test / name for name in dict.fromkeys((*IR_SOURCES, *SOLVER_SOURCES))]
    paths += sorted(test.glob('*.h'))
    paths += [project / 'unpacker' / name for name in
              (*NATIVE_HELPERS, *PYTHON_HELPERS, 'oep_smt.c', 'oep_schedule.c')]
    paths += [project / 'unpacker/mvp' / name for name in
              ('prove_multilayer.py', 'layer_proof_bindings.py', 'ct_elf.py',
               'check_runtime_flags.py', 'run_runtime_dse_audit.py')]
    paths += [project / 'unpacker/mvp/fixtures' / name for name in
              ('core_layer_proof_observer.c', 'core_flags_observer.c',
               'core_flags32.S', 'core_stdin_span32.ld')]
    return [regular(path, 16 * 1024**2) for path in dict.fromkeys(paths)]


def dependency_build_flags(cpp, libs, ld, library):
    """Preserve explicit dependency links; otherwise use pkg-config or -l."""
    tokens = [part for token in (*ld, *libs)
              for part in (token[4:].split(',') if token.startswith('-Wl,') else [token])]
    filename = r'lib' + re.escape(library) + r'\.(?:a|so(?:\.\d+)*)'
    linked = any(token == '-l' + library or
                 re.fullmatch(r'-l:' + filename, token) or
                 (not token.startswith('-') and
                  re.fullmatch(filename, Path(token).name))
                 for token in tokens)
    linked |= any(left == '-l' and right == library
                  for left, right in zip(tokens, tokens[1:]))
    if linked:
        return list(cpp), list(libs), list(ld)
    try:
        dep_cpp = shlex.split(subprocess.check_output(
            ['pkg-config', '--cflags', library], text=True, stderr=subprocess.DEVNULL, timeout=30))
        dep_libs = shlex.split(subprocess.check_output(
            ['pkg-config', '--libs', library], text=True, stderr=subprocess.DEVNULL, timeout=30))
        require(dep_libs, 'pkg-config returned no ' + library + ' link flags')
    except (FileNotFoundError, subprocess.CalledProcessError):
        dep_cpp, dep_libs = [], ['-l' + library]
    return [*cpp, *dep_cpp], [*libs, *dep_libs], list(ld)


def replay_build_flags(cpp, libs, ld):
    """Add the x86 frontend's Capstone dependency to the native replay only."""
    return dependency_build_flags(cpp, libs, ld, 'capstone')


def configure_solver_build_flags(cpp, libs, ld):
    """Default the SMT backend's headers/Z3 link without replacing overrides."""
    if 'TF_SMT_CPPFLAGS' in os.environ and 'TF_SMT_LIBS' in os.environ:
        return
    solver_cpp, solver_libs, solver_ld = dependency_build_flags(cpp, libs, ld, 'z3')
    os.environ.setdefault('TF_SMT_CPPFLAGS', shlex.join(solver_cpp))
    os.environ.setdefault('TF_SMT_LIBS', shlex.join([*solver_ld, *solver_libs]))


def build_tools(project, header, output):
    output.mkdir()
    source = output / 'source'
    source.mkdir()
    paths = [project / 'unpacker/test' / name for name in IR_SOURCES]
    paths += sorted((project / 'unpacker/test').glob('*.h'))
    paths += [project / 'unpacker' / name for name in NATIVE_HELPERS]
    paths += [project / 'unpacker/mvp/fixtures' / name for name in
              ('core_layer_proof_observer.c', 'core_flags_observer.c',
               'core_flags32.S', 'core_stdin_span32.ld')]
    for path in paths:
        shutil.copyfile(path, source / path.name)
    sdk = output / 'include'
    sdk.mkdir()
    shutil.copyfile(header, sdk / 'qemu-plugin.h')
    cpp, libs, ld = build_flags()
    replay_cpp, replay_libs, replay_ld = replay_build_flags(cpp, libs, ld)
    configure_solver_build_flags(replay_cpp, libs, ld)
    cc = os.environ.get('TF_IR_CC', 'gcc')
    common = [cc, '-std=gnu11', '-O2', '-g', '-Wall', '-Wextra', '-Werror',
              '-Wno-misleading-indentation', '-ffunction-sections', '-fdata-sections',
              '-I', str(source), *replay_cpp]
    commands, objects = [], []
    for name in IR_SOURCES:
        obj = output / (Path(name).stem + '.o')
        commands.append([*common, '-c', str(source / name), '-o', str(obj)])
        objects.append(str(obj))
    replay = output / 'generic-execute'
    commands.append([*common, '-DTF_GENERIC_REPLAY=1', str(source / 'oep_execute.c'),
                     *objects, '-Wl,--gc-sections', *replay_ld, *replay_libs, '-lm', '-pthread',
                     '-o', str(replay)])
    observer, flags_observer = output / 'observer.so', output / 'flags-observer.so'
    for name, destination in [('core_layer_proof_observer.c', observer),
                              ('core_flags_observer.c', flags_observer)]:
        commands.append([cc, '-std=gnu11', '-O2', '-g', '-Wall', '-Wextra', '-Werror',
                         '-fPIC', '-shared', '-I', str(sdk), '-I', str(source), *cpp,
                         str(source / name), *ld, *libs, '-o', str(destination)])
    flags = output / 'flags.elf'
    commands += [['as', '--32', '-o', str(output / 'flags.o'), str(source / 'core_flags32.S')],
                 ['ld', '-m', 'elf_i386', '-T', str(source / 'core_stdin_span32.ld'),
                  '-o', str(flags), str(output / 'flags.o')]]
    save(output / 'build-commands.json', {'commands': commands})
    with (output / 'build.log').open('wb') as log:
        for command in commands:
            try:
                subprocess.run(command, check=True, stdout=log, stderr=log, timeout=180)
            except subprocess.CalledProcessError as error:
                raise ValueError('Native tool build failed; inspect ' + str(output / 'build.log')) from error
    receipt = output / 'receipt.json'
    save(receipt, {'commands': commands, 'source_files_sha256': pin(sorted(source.iterdir())),
                   'qemu_header_sha256': digest(header),
                   'binaries_sha256': pin((replay, observer, flags_observer, flags)),
                   'all_binaries_built_from_current_sources': True})
    return {'replay': replay, 'observer': observer, 'flags_observer': flags_observer,
            'flags_fixture': flags, 'receipt': receipt}


def boundary_identity(stage, stage_index):
    """Select one occurrence, including a later generation at the same PC."""
    mapping_epoch = stage.get('mapping_epoch')
    if mapping_epoch is not None:
        require(type(mapping_epoch) is int and 0 <= mapping_epoch <= 256,
                'Invalid claimed mapping lifetime')
    file_profile = stage.get('file_mapping_profile_version')
    require(file_profile is None or type(file_profile) is int and file_profile in (4, 5, 6, 7),
            'Invalid claimed file-mapping profile')
    mapping_profile = mapping_epoch is not None and (mapping_epoch > 0 or file_profile in (4, 5, 6, 7))
    result = {'pc': stage.get('address'),
              'instruction_ordinal': stage.get('entry_seq'),
              'page_generation': stage.get('guest_store_generation') if mapping_profile else stage.get('code_generation'),
              'stage_index': stage_index}
    require(all(type(value) is int for value in result.values()) and
            0 <= result['pc'] <= 0xffffffff and
            1 < result['instruction_ordinal'] <= 1_000_001 and
            0 < result['page_generation'] <= 1_000_000 and
            1 <= result['stage_index'] <= 7, 'Invalid exact stage boundary')
    if mapping_profile:
        result['mapping_epoch'] = mapping_epoch
    if file_profile in (4, 5, 6, 7):
        require(mapping_profile, 'File-mapping boundary lacks a mapping lifetime')
        result['file_mapping_profile_version'] = file_profile
    return result


def selector_version(target):
    return target['file_mapping_profile_version'] if target.get('file_mapping_profile_version') in (4, 5, 6, 7) else 3 if 'mapping_epoch' in target else 2


def replay_config_text(target, stack_base, page_address):
    require(type(stack_base) is int and type(page_address) is int and
            0 <= stack_base <= 0xffffe000 and stack_base % 4096 == 0 and
            0 <= page_address <= 0xfffff000 and page_address % 4096 == 0 and
            target['pc'] // 4096 * 4096 == page_address, 'Invalid exact replay geometry')
    version = selector_version(target)
    epoch = f" {target['mapping_epoch']}" if version >= 3 else ''
    return (f"TFOEPGEN{version}\n{target['pc']:x} {stack_base:x} 1000000\n"
            f"{target['instruction_ordinal']} {target['page_generation']}{epoch}\n"
            f"1\n{page_address:x} 4096\n")


def run_capture(qemu, observer, packed, stages, target, output, single_step):
    output.mkdir()
    guest = output / 'source.elf'
    shutil.copyfile(packed, guest)
    guest.chmod(0o700)
    stagefile = output / 'stages.txt'
    version = selector_version(target)
    if version >= 3:
        require(all(type(row.get('mapping_epoch')) is int and 0 <= row['mapping_epoch'] <= 256 and
                    type(row.get('guest_store_generation')) is int for row in stages),
                'Every mapping-profile stage needs a mapping lifetime and guest-store generation')
    if version in (4, 5, 6, 7):
        require(all(type(row.get('file_mapping_profile_version')) is int and
                    row['file_mapping_profile_version'] == version for row in stages),
                'Every file-profile ancestry occurrence must declare the same version')
    stagefile.write_text(f'TFLAYERSTAGES{version}\n' + ''.join(
        f"{row['address']:x} {row['entry_size']} {row['transfer_pc']:x} "
        f"{row['entry_seq']} {row['guest_store_generation'] if version >= 3 else row['code_generation']}" +
        (f" {row['mapping_epoch']}" if version >= 3 else '') + '\n' for row in stages))
    events, report = output / 'events.jsonl', output / 'report.json'
    token = uuid.uuid4().hex
    require(all(',' not in str(path) and '\n' not in str(path)
                for path in (observer, guest, events, report, stagefile)), 'Unsafe plugin path')
    options = (f'{observer},guest={guest},events={events},report={report},run-id={token},'
               f"stop=0x{target['pc']:x},stages={stagefile},stop-index={target['stage_index']}")
    command = [str(qemu), *(['-one-insn-per-tb'] if single_step else []),
               '-s', '1044480', '-plugin', options, '-0', 'target.elf', str(guest)]
    environment = {'PATH': os.environ.get('PATH', '/usr/bin:/bin'), 'LC_ALL': 'C', 'TZ': 'UTC'}
    with (output / 'stdout').open('wb') as stdout, (output / 'stderr').open('wb') as stderr:
        process = subprocess.run(command, cwd=output, env=environment, stdin=subprocess.DEVNULL,
                                 stdout=stdout, stderr=stderr, timeout=180)
    save(output / 'launch.json', {'command': command, 'run_id': token,
                                  'qemu_sha256': digest(qemu), 'observer_sha256': digest(observer),
                                  'packed_sha256': digest(packed), 'single_step': single_step,
                                  'boundary_selector_version': version, 'boundary_identity': target,
                                  'returncode': process.returncode})
    require(process.returncode == 0, 'Fresh observer failed; inspect capture/stderr')
    require((output / 'stdout').stat().st_size == 0, 'Guest ran past the requested payload boundary')
    regular(events, 32 * 1024**2)
    return events, read_json(report), token


def run_replay(native, inputs, output, max_nodes):
    require(len(str(output)) < 4096, 'Replay output path exceeds native path budget')
    output.mkdir()
    environment = dict(os.environ, TF_OEP_PRODUCERS=str(output / 'producers'),
                       TF_OEP_PRODUCER_LIMIT=str(max_nodes))
    command = [str(native), *(str(inputs / name) for name in INPUT_NAMES), str(output)]
    with (output / 'execution.json').open('wb') as stdout, (output / 'stderr').open('wb') as stderr:
        process = subprocess.run(command, env=environment, stdout=stdout, stderr=stderr, timeout=900)
    save(output / 'launch.json', {'command': command, 'returncode': process.returncode})
    require(process.returncode == 0, 'Original-entry native replay failed; inspect replay/stderr')


def mapping_contracts_text(capture):
    """Serialize only V3 calls already checked by the mapping-lifetime binder."""
    require(capture.get('boundary_selector_version') in (3, 4, 5, 6, 7) and
            capture.get('context', {}).get('mapping_profile_version') == capture['boundary_selector_version'],
            'Validated mapping-profile calls required')
    lines = []
    for entry, returned, post in capture['context']['calls']:
        require(type(post.get('mapping_effect')) is dict, 'Missing validated V3 mapping effect')
        lines.append(' '.join([f"{entry['pc']:x}", str(entry['number']),
                               *[f'{value:x}' for value in entry['args']],
                               f"{returned['result_u32']:x}", '-']))
        if entry['number'] in (90, 192):
            lines.append(' '.join(f'{value:x}' for value in entry['mmap_args']))
    return '\n'.join(lines) + ('\n' if lines else '')


def prove_stage(qemu, tools, packed, loader, stages, index, output, single_step, max_nodes):
    from layer_proof_bindings import read_observer, bind_replay, validate_smt_certificate
    from unpack_observations import contracts_text
    from unpack_smt import prove_generic
    output.mkdir()
    stage = stages[index]
    target = boundary_identity(stage, index + 1)
    configured = [{'address': loader['entry'], 'entry_size': 1, 'transfer_pc': 0,
                   'entry_seq': 1, 'code_generation': 0}, *stages]
    if 'mapping_epoch' in target:
        configured[0].update(mapping_epoch=0, guest_store_generation=0)
    if target.get('file_mapping_profile_version') in (4, 5, 6, 7):
        configured[0]['file_mapping_profile_version'] = target['file_mapping_profile_version']
    events, report, token = run_capture(qemu, tools['observer'], packed, configured,
                                       target, output / 'capture', single_step)
    stage_pins = artifact_pins(output / 'capture')
    report = read_json(output / 'capture/report.json')
    capture = read_observer(events, packed.read_bytes(), stage['address'], token, report=report,
                            expected_stages=stages[:index + 1], expected_boundary=target)
    check_pins(stage_pins)
    require(digest(events) == capture['events_sha256'], 'Parsed observer event identity changed')
    context = capture['context']
    require(context['stack'] == bytes(len(context['stack'])) and
            context['mask'] == bytes(len(context['mask'])), 'Observed stack cannot become a premise')
    page = capture['target_page']
    page_data = bytes.fromhex(page['bytes_hex'])
    inputs = output / 'inputs'
    inputs.mkdir()
    shutil.copyfile(packed, inputs / 'source.elf')
    (inputs / 'stack.bin').write_bytes(context['stack'])
    (inputs / 'stack-mask.bin').write_bytes(context['mask'])
    (inputs / 'scalars.txt').write_text(f"{context['esp']:x} {context['df']:x}\n")
    (inputs / 'contracts.txt').write_text(mapping_contracts_text(capture)
        if capture['boundary_selector_version'] >= 3 else contracts_text(capture['rows']))
    initial = capture['initial']
    (inputs / 'config.txt').write_text(replay_config_text(target, initial['stack_base'], page['address']))
    input_hashes = [digest(inputs / name) for name in INPUT_NAMES]
    run_replay(tools['replay'], inputs, output / 'replay', max_nodes)
    stage_pins.update(artifact_pins(output / 'replay'))
    stage_pins.update(pin(inputs / name for name in INPUT_NAMES))
    save(output / 'stage-input-pins.json', stage_pins)
    check_pins(stage_pins)
    binding = bind_replay(capture, output / 'replay', loader=loader)
    check_pins(stage_pins)
    save(output / 'binding.json', binding)
    goal = [{'address': page['address'], 'data': page_data, 'prot': page['prot']}]
    proof = prove_generic(output / 'replay', context, goal, output / 'smt',
                          target=stage['address'], execution=binding['execution'],
                          input_files_sha256=input_hashes, max_nodes=max_nodes)
    validate_smt_certificate(proof, target=stage['address'], packed_sha256=digest(packed),
                             path_sha256=binding['execution']['path_sha256'])
    require(proof['instructions'] + 1 == target['instruction_ordinal'],
            'SMT certificate belongs to a different selected-PC occurrence')
    check_pins(stage_pins)
    require(digest(events) == capture['events_sha256'], 'Observer events changed during proof')
    require(read_json(output / 'stage-input-pins.json') == stage_pins,
            'Stored stage input inventory changed')
    require(read_json(output / 'smt/certificate.json') == proof, 'Stored SMT certificate differs')
    require(input_hashes == [digest(inputs / name) for name in INPUT_NAMES],
            'Native replay inputs changed during proof')
    receipt_check = check_SMT_query_receipts(output / 'smt', proof)
    save(output / 'smt-receipt-check.json', receipt_check)
    certificate = {'schema_version': 1, 'status': STATUS, 'candidate_id': stage['candidate_id'],
                   'target': stage['address'], 'packed_sha256': digest(packed), 'run_id': token,
                   'proof_execution_mode': 'one_insn_per_tb' if single_step else 'normal_tb',
                   'boundary_selector_version': capture['boundary_selector_version'], 'boundary_identity': target,
                   'earlier_same_PC_stage_occurrences': binding['earlier_same_PC_stage_occurrences'],
                   'explicit_initial_ESP': context['esp'], 'explicit_initial_DF': context['df'],
                   'initial_stack_bytes_admitted': 0, 'kernel_contract_count': len(context['calls']),
                   'kernel_contracts_sha256': digest(inputs / 'contracts.txt'),
                   'observed_page_generation': page['page_generation'],
                   'observed_mapping_epoch': page.get('mapping_epoch'),
                   'selection_entry_seq': stage['entry_seq'],
                   'selection_code_generation': stage['code_generation'],
                   'selection_guest_store_generation': stage.get('guest_store_generation'),
                   'selection_mapping_epoch': stage.get('mapping_epoch'),
                   'selection_epoch': stage['epoch'],
                   'proved_code_page_address': page['address'],
                   'proved_code_page_sha256': hashlib.sha256(page_data).hexdigest(),
                   'generation_binding': binding['generation_binding'],
                   'generation_counter_proved_as_machine_state': False,
                   'guest_permissions_independently_observed': False,
                   'source_premise_query': 'SAT', 'counterexample_query': 'UNSAT',
                   'SMT_solver_checks': proof['SMT_solver_checks'],
                   'path_sha256': binding['execution']['path_sha256'],
                   'fetch_sha256': binding['execution']['fetch_sha256'],
                   'input_files_sha256': input_hashes, 'proved_current_code_bytes': len(page_data),
                   'native_binding_sha256': digest(output / 'binding.json'),
                   'capture_events_sha256': capture['events_sha256'],
                   'stage_input_pins_sha256': digest(output / 'stage-input-pins.json'),
                   'generic_certificate_sha256': digest(output / 'smt' / 'certificate.json'),
                   'SMT_receipt_check_sha256': digest(output / 'smt-receipt-check.json'),
                   'all_prefix_conditions_proved': True, 'original_entry_replayed': True,
                   'target_instruction_executed': False,
                   'target_instruction_execution_scope': 'selected_boundary_occurrence',
                   'observed_checkpoint_used_as_input': False,
                   'observed_image_used_as_source': False, 'historical_originality_proven': False,
                   'universal_oep_proven': False, 'kernel_semantics_proven': False,
                   'independent_initial_state_proven': False}
    save(output / 'certificate.json', certificate)
    return certificate, page_data, page['address']


def prove_matrix(project, matrix, qemu, include, output, samples, single_step, max_nodes):
    require(not output.exists() and not output.is_symlink(), 'Proof output must be a new path')
    output.mkdir(parents=True)
    summary = {'schema_version': 1, 'status': 'FAIL_MULTILAYER_SMT_PROOF', 'samples': [],
               'stage_proofs': 0, 'SMT_solver_checks': 0, 'errors': [],
               'historical_originality_proven': False, 'universal_oep_proven': False,
               'arbitrary_multilayer_unpacking_proven': False, 'kernel_semantics_proven': False,
               'independent_initial_state_proven': False, 'fuzzing_ready': False,
               'proof_execution_mode': 'one_insn_per_tb' if single_step else 'normal_tb',
               'conditions': [
                   'Trusted source-built IR frontend, producer tracking, SMT translation, solver and host build.',
                   'Packed ELF loader construction and observed initial ESP/DF are explicit premises; other incoming registers and stack bytes remain unknown.',
                   'Observed supported memory-operation result/effect contracts and derived page permissions are explicit environment premises.',
                   'Each theorem covers the fresh selected original-entry prefix and current target page; earlier receipt statuses are not inherited.']}
    try:
        require(project == Path(__file__).resolve().parents[2],
                'Driver and imported proof helpers must belong to the selected project')
        from layer_proof_bindings import select_stage_ancestry
        from unpack_sources import loader_regions
        matrix_summary = regular(matrix / 'summary.json', 16 * 1024**2)
        source_summary = read_json(matrix_summary)
        require(source_summary.get('status') == 'PASS_BOUNDED_MULTILAYER_SELECTION_REGRESSION',
                'Successful source-pinned production capture matrix required')
        available = sorted(path.name for path in (matrix / 'fixtures').iterdir()
                           if path.is_dir() and (path / 'packed.elf').is_file())
        require(available and len(available) <= 64 and
                all(re.fullmatch('[a-z0-9][a-z0-9-]{0,80}', name) for name in available),
                'Invalid or oversized fixture inventory')
        source_runs = source_summary.get('runs')
        require(type(source_runs) is list and 1 <= len(source_runs) <= 1024 and
                all(type(row) is dict and type(row.get('fixture')) is str for row in source_runs) and
                set(available) == {row['fixture'] for row in source_runs},
                'Matrix fixture inventory differs from successful production runs')
        chosen = samples or available
        require(len(chosen) == len(set(chosen)) and set(chosen) <= set(available),
                'Unknown or duplicate sample selection')
        paths = source_inventory(project) + [matrix_summary, qemu, include / 'qemu-plugin.h']
        plans = []
        for name in chosen:
            packed = regular(matrix / 'fixtures' / name / 'packed.elf', 64 * 1024**2)
            mode = 'single' if single_step else 'normal'
            directory = matrix / f'{name}-heuristic_delay64-{mode}'
            report_file = regular(directory / 'unpacked.json', 16 * 1024**2)
            dump = regular(directory / 'unpacked.bin', 64 * 1024**2)
            output_hashes = source_summary.get('output_files_sha256', {})
            require(all(output_hashes.get(str(path.relative_to(matrix))) == digest(path)
                        for path in (report_file, dump)),
                    'Selection capture is not bound to the production matrix')
            report = read_json(report_file)
            require(report.get('main_image_verified') is True, 'Source capture image is not verified')
            image, regions = load_capture(report_file, dump)
            require(image == report, 'Capture parser changed report interpretation')
            matches = [value for key, value in source_summary.get('built_artifacts_sha256', {}).items()
                       if key.endswith('/fixtures/' + name + '/packed.elf')]
            require(matches == [digest(packed)], 'Packed source is not bound to the production matrix')
            ancestry = select_stage_ancestry(report)
            require(1 <= len(ancestry['stages']) <= 7, 'Stage ancestry exceeds observer proof budget')
            paths += [packed, report_file, dump]
            plans.append((name, packed, loader_regions(packed.read_bytes()), ancestry, regions, report_file))
        inventory = pin(paths)
        save(output / 'input-pins.json', inventory)
        snapshot = output / 'source-python'
        for path in paths:
            if path.is_relative_to(project) and path.suffix == '.py':
                destination = snapshot / path.relative_to(project)
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(path, destination)
                require(digest(destination) == inventory[str(path)], 'Source changed while copying')
        check_pins(inventory)
        tools = build_tools(project, include / 'qemu-plugin.h', output / 'runtime')
        inventory.update(pin(tools.values()))
        flags = check_flags(qemu, tools['flags_observer'], tools['flags_fixture'], output / 'flags-probe')
        require(flags.get('status') == 'PASS_QEMU_PUSHF_BOUNDARY_PROBE', 'QEMU flag calibration failed')
        inventory.update(pin((output / 'flags-probe/flags.receipt',)))
        save(output / 'input-pins.json', inventory)
        for name, packed, loader, ancestry, regions, report_file in plans:
            case = output / name
            case.mkdir()
            production_report = read_json(report_file)
            save(case / 'selection-claims.json', {**ancestry,
                'production_report_sha256': digest(report_file), 'packed_sha256': digest(packed),
                'production_capture_id': production_report.get('capture_id'),
                'production_session_id': production_report.get('session_id'),
                'production_analysis_instance_id': production_report.get('analysis_instance_id'),
                'observed_image_used_as_source': False, 'original_elf_used_as_input': False})
            row = {'name': name, 'status': 'IN_PROGRESS', 'stages': [],
                   'excluded_postselected_ids': ancestry['excluded_postselected_ids']}
            summary['samples'].append(row)
            for index, stage in enumerate(ancestry['stages']):
                check_pins(inventory)
                print(f"layer SMT: {name} stage {index + 1}/{len(ancestry['stages'])} "
                      f"fresh original-entry prefix -> 0x{stage['address']:08x} "
                      f"occurrence={stage['entry_seq']} generation={stage['code_generation']}", flush=True)
                cert, page, address = prove_stage(qemu, tools, packed, loader, ancestry['stages'],
                    index, case / f'stage-{index + 1}', single_step, max_nodes)
                cert['selection_claims_sha256'] = digest(case / 'selection-claims.json')
                save(case / f'stage-{index + 1}' / 'certificate.json', cert)
                if index + 1 == len(ancestry['stages']):
                    require(captured_bytes(regions, address, len(page)) == page,
                            'Fresh selected page differs from automatic production capture')
                check_pins(inventory)
                row['stages'].append(cert)
                summary['stage_proofs'] += 1
                summary['SMT_solver_checks'] += cert['SMT_solver_checks']
                save(output / 'summary.json', summary)
            row['status'] = STATUS
        check_pins(inventory)
        for row in summary['samples']:
            for index, stage in enumerate(row['stages'], 1):
                directory = output / row['name'] / f'stage-{index}'
                generic = read_json(directory / 'smt/certificate.json')
                checked = check_SMT_query_receipts(directory / 'smt', generic)
                require(checked == read_json(directory / 'smt-receipt-check.json') and
                        digest(directory / 'smt-receipt-check.json') == stage['SMT_receipt_check_sha256'] and
                        read_json(directory / 'certificate.json') == stage,
                        'Completed stage SMT evidence changed before aggregate certification')
        fresh_ids = [stage['run_id'] for row in summary['samples'] for stage in row['stages']]
        require(len(fresh_ids) == summary['stage_proofs'] == len(set(fresh_ids)),
                'Fresh prefix run identity reused')
        require(read_json(output / 'input-pins.json') == inventory, 'Stored input inventory changed')
        summary.update(status=STATUS, all_selected_ancestry_stages_proved=True,
                       all_matrix_samples_processed=len(chosen) == len(available),
                       selected_samples=len(chosen), available_samples=len(available),
                       source_premise_queries='SAT', counterexample_queries='UNSAT',
                       fresh_prefix_runs=len(fresh_ids), each_prefix_has_own_ESP_DF_and_contracts=True,
                       boundary_selector_version=max(stage['boundary_selector_version']
                           for row in summary['samples'] for stage in row['stages']),
                       boundary_selector_versions=sorted({stage['boundary_selector_version']
                           for row in summary['samples'] for stage in row['stages']}),
                       mapping_lifetime_stage_proofs=sum(stage['boundary_selector_version'] >= 3
                           for row in summary['samples'] for stage in row['stages']),
                       file_mapping_stage_proofs=sum(stage['boundary_selector_version'] >= 4
                           for row in summary['samples'] for stage in row['stages']),
                       mutable_memfd_stage_proofs=sum(stage['boundary_selector_version'] >= 5
                           for row in summary['samples'] for stage in row['stages']),
                       same_PC_reentry_stage_proofs=sum(
                           stage['earlier_same_PC_stage_occurrences'] > 0
                           for row in summary['samples'] for stage in row['stages']),
                       input_pins_sha256=digest(output / 'input-pins.json'),
                       original_entry_replayed_for_every_stage=True,
                       observed_checkpoint_used_as_input=False, observed_image_used_as_source=False,
                       source_runtime_and_input_pins_unchanged=True)
        save(output / 'certificate.json', summary)
    except (OSError, ValueError, KeyError, TypeError, AttributeError, ImportError,
            UnicodeError, RecursionError, subprocess.SubprocessError) as error:
        summary['status'] = 'FAIL_MULTILAYER_SMT_PROOF'
        summary['all_selected_ancestry_stages_proved'] = False
        summary['errors'].append(type(error).__name__ + ': ' + str(error))
        for path in output.rglob('certificate.json'):
            path.rename(path.with_name('invalidated-certificate.json'))
    save(output / 'summary.json', summary)
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--project', type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument('--matrix', type=Path, required=True)
    parser.add_argument('--qemu', type=Path, default=os.environ.get('TF_QEMU'))
    parser.add_argument('--qemu-include', type=Path, default=os.environ.get('TF_QEMU_INCLUDE'))
    parser.add_argument('--sample', action='append')
    parser.add_argument('--normal-tb', action='store_true',
                        help='Require exact normal-TB/native binding; default uses one instruction per TB')
    parser.add_argument('--max-producer-nodes', type=int, default=4_000_000)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    require(1 <= args.max_producer_nodes <= 8_000_000, 'Invalid producer budget')
    project, matrix = args.project.resolve(strict=True), args.matrix.resolve(strict=True)
    if not (matrix / 'summary.json').is_file():
        matrix = next((matrix / child for child in ('probe/multilayer', 'multilayer')
                       if (matrix / child / 'summary.json').is_file()), matrix)
    require(args.qemu is not None and args.qemu_include is not None, 'QEMU and matching SDK required')
    qemu = regular(args.qemu, 512 * 1024**2)
    include = args.qemu_include.resolve(strict=True)
    output = args.output.absolute() if args.output else Path(tempfile.mkdtemp(
        prefix='unpack-proof.multilayer-smt-', dir=project / 'unpacker')) / 'probe'
    sys.path.insert(0, str(project / 'unpacker'))
    print('Results:', output, flush=True)
    result = prove_matrix(project, matrix, qemu, include, output, args.sample,
                          not args.normal_tb, args.max_producer_nodes)
    print(result['status'], flush=True)
    for error in result['errors']:
        print(error, file=sys.stderr)
    return 0 if result['status'] == STATUS else 1


if __name__ == '__main__':
    raise SystemExit(main())
