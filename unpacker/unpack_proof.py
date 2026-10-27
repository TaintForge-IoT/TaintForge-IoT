#!/usr/bin/env python3
"""Prove a selected unpacking transfer and image for a fresh static i386 run.

The earlier automatic capture selects the conclusion. Its output bytes never
initialize the IR machine. Replay starts at the packed ELF entry, using a source
loader construction and explicit initial-stack/kernel premises for a new run.
"""
from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import resource
import shlex
import signal
import subprocess
import sys
import tempfile
import time
import uuid

try:
    from . import oep_verify as v
    from . import unpack_observations as observations
    from . import unpack_smt
    from .unpack_sources import loader_regions
    from .mvp import ct_elf
    from . import rep_callbacks
    from . import unpack_launch
except ImportError:
    import oep_verify as v
    import unpack_observations as observations
    import unpack_smt
    from unpack_sources import loader_regions
    from mvp import ct_elf
    import rep_callbacks
    import unpack_launch

ROOT = Path(__file__).resolve().parent
PROJECT = ROOT.parent
INPUT_NAMES = ('source.elf', 'stack.bin', 'stack-mask.bin', 'scalars.txt',
               'contracts.txt', 'config.txt')
APIS = tuple('qemu_plugin_taintforge_user_' + name + '_v1'
             for name in ('vmas', 'entry', 'brk'))
MAX_CAPTURE = 128 * 1024**2
TIMEOUT = 900
MAX_PRODUCER_NODES = unpack_smt.RAW_NODE_LIMIT


def producer_node_budget(value):
    """Validate the shared native/SMT raw-ledger bound before side effects."""
    v.require(type(value) is int and 1 <= value <= MAX_PRODUCER_NODES,
              f'Producer budget must be in 1..{MAX_PRODUCER_NODES}')
    return value


def digest_file(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def snapshot_sources(output):
    names = ('unpack_proof.py', 'unpack_observations.py', 'unpack_sources.py', 'unpack_smt.py',
             'oep_verify.py', 'oep_entry.py', 'oep_environment.py', 'oep_smt.py', 'oep_schedule.py',
             'mvp/ct_elf.py', 'replay_trace.py', 'rep_callbacks.py', 'unpack_launch.py',
             'unpack_process.py')
    hashes = {}
    for name in names:
        data = (ROOT / name).read_bytes()
        target = output / 'source' / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        hashes[name] = v.digest(data)
    v.save(output / 'source-receipt.json', hashes)
    return hashes


def bounded(path, limit, label):
    path = Path(path).expanduser().absolute()
    v.require(path.is_file() and not path.is_symlink()
              and 0 < path.stat().st_size <= limit, label + ' missing or exceeds bound')
    return path.resolve()


def flags():
    cpp, libraries = os.environ.get('TF_PLUGIN_CPPFLAGS'), os.environ.get('TF_PLUGIN_LIBS')
    if cpp is None:
        cpp = subprocess.check_output(['pkg-config', '--cflags', 'glib-2.0', 'capstone'],
                                      text=True, timeout=30)
    if libraries is None:
        libraries = subprocess.check_output(['pkg-config', '--libs', 'glib-2.0', 'capstone'],
                                            text=True, timeout=30)
    v.require('TF_PROV_FASTPATH' not in cpp and 'TF_CAPTURE_FASTPATH' not in cpp,
              'Fast-path build flags cannot establish the generic proof')
    return shlex.split(cpp), [*shlex.split(libraries),
                              *shlex.split(os.environ.get('TF_PLUGIN_LDFLAGS', ''))]


def build_native(include, output):
    """Build both observers and IR objects from current source, then bind hashes."""
    output = Path(output)
    output.mkdir()
    sources = output / 'source'
    sources.mkdir()
    include = Path(include).expanduser().resolve(strict=True)
    bounded(include / 'qemu-plugin.h', 1024**2, 'Matching QEMU SDK')
    names = list(v.IR_SOURCE_FILES) + list(v.IR_HEADER_FILES)
    source_map = {name: ROOT / 'test' / name for name in names}
    source_map.update({name: ROOT / name for name in
                       ('oep_execute.c', 'oep_producers.h', 'unpack_capture.c')})
    # Generic mode may split its bounded loader constructor into a private header.
    for path in sorted(ROOT.glob('oep_generic_*.h')):
        source_map[path.name] = path
    source_map['test/qemu_plugin_compat.h'] = ROOT / 'test/qemu_plugin_compat.h'
    hashes = {}
    for name, path in source_map.items():
        bounded(path, 16 * 1024**2, 'Native source')
        target = sources / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(path.read_bytes())
        hashes[name] = digest_file(target)
    cpp, libraries = flags()
    common = [os.environ.get('TF_IR_CC', 'gcc'), '-std=gnu11', '-O2', '-Wall', '-Wextra',
              '-Werror', '-Wno-misleading-indentation', '-ffunction-sections', '-fdata-sections',
              '-I', str(sources), *cpp]
    objects = [output / (Path(name).stem + '.o') for name in v.IR_SOURCE_FILES]
    commands = [[*common, '-c', str(sources / name), '-o', str(obj)]
                for name, obj in zip(v.IR_SOURCE_FILES, objects)]
    replay = output / 'unpack-execute'
    commands.append([*common, '-DTF_GENERIC_REPLAY=1', '-Wl,--gc-sections',
                     str(sources / 'oep_execute.c'), *map(str, objects), *libraries,
                     '-lm', '-pthread', '-o', str(replay)])
    plugin = output / 'unpack-capture.so'
    commands.append([*common, '-fPIC', '-shared', '-fvisibility=hidden', '-I', str(include),
                     str(sources / 'unpack_capture.c'), *libraries, '-o', str(plugin)])
    with (output / 'build.log').open('wb') as log:
        for command in commands:
            result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, timeout=180)
            v.require(result.returncode == 0, 'Native build failed; inspect ' + str(log.name))
    receipt = dict(schema_version=1, commands=commands, sources_sha256=hashes,
        replay_sha256=digest_file(replay), observer_sha256=digest_file(plugin),
        sdk_sha256=digest_file(include / 'qemu-plugin.h'),
        all_project_IR_objects_built_from_source=True, uploaded_native_binaries_executed=False,
        generic_replay_mode=True, compiler_and_linker_configuration_trusted=True)
    v.save(output / 'receipt.json', receipt)
    return replay, plugin, receipt


def calibrate_native(qemu, include, native, output):
    """Measure a callback representation before it is used by a GEN1 proof."""
    try:
        from .mvp.run_rep_audit import calibrate_runtime
    except ImportError:
        location = str(ROOT / 'mvp')
        if location not in sys.path:
            sys.path.insert(0, location)
        from run_rep_audit import calibrate_runtime
    output = Path(output)
    calibrate_runtime(PROJECT, qemu, include, output, native=native)
    return output / 'calibration.json'


def resolve_callback_profile(qemu, include, native, output):
    """Bind an explicit model selector to this runtime and independent fixtures."""
    binary, plugin, _ = native
    calibration = Path(binary).parent / 'rep-calibration/calibration.json'
    if not calibration.exists():
        calibration = calibrate_native(qemu, include, native, Path(output) / 'rep-calibration')
    document = rep_callbacks.load_calibration(calibration, qemu=qemu,
        observer=plugin, sdk=Path(include) / 'qemu-plugin.h')
    mode = document['profiles']['normal']
    binding = dict(mode=mode, semantics=rep_callbacks.semantics(mode),
        calibration_sha256=digest_file(calibration), **document['runtime'])
    destination = Path(output) / 'rep-calibration.json'
    with destination.open('xb') as stream:
        stream.write(calibration.read_bytes())
    v.require(digest_file(destination) == binding['calibration_sha256'],
              'REP calibration copy changed')
    return binding


def candidate_inputs(directory):
    """Read a selection as claims; no inherited proof status is consumed."""
    directory = Path(directory).expanduser().resolve(strict=True)
    packed = bounded(directory / 'inputs/packed.elf', 16 * 1024**2, 'Packed ELF')
    report_path = bounded(directory / 'capture/unpacked.json', 4 * 1024**2, 'Candidate report')
    dump_path = bounded(directory / 'capture/unpacked.bin', 16 * 1024**2, 'Candidate dump')
    # Detector confidence scores are finite JSON decimals; strict duplicate-key
    # and nonfinite checks still apply. Machine geometry is checked by ct_elf.
    strict_report = v.strict_json(report_path.read_bytes())
    v.require(type(strict_report) is dict and type(strict_report.get('oep_candidates')) is list
              and 0 < len(strict_report['oep_candidates']) <= 64
              and all(type(row) is dict for row in strict_report['oep_candidates']),
              'Require a bounded production candidate table')
    # ct_elf performs bounded geometry, byte-digest, executable-entry and generation checks.
    report, goals = ct_elf.load_capture(report_path, dump_path)
    v.require(report == strict_report, 'Candidate report changed while reading')
    target = ct_elf.integer(report['oep'], 'candidate entry')
    v.require(report.get('main_image_verified') is True
              and report.get('capture_method') == 'candidate_entry_before_instruction'
              and report.get('capture_scope') == 'tracked_program_pages',
              'Require a production candidate-entry capture')
    packed_bytes = packed.read_bytes()
    image = loader_regions(packed_bytes)
    receipt = dict(packed_sha256=v.digest(packed_bytes), target=target,
        report_sha256=digest_file(report_path), dump_sha256=digest_file(dump_path),
        selection_only=True, observations_used_as_replay_initial_state=False,
        previous_proof_status_inherited=False,
        goals=[dict(address=r['address'], size=r['size'], prot=r['prot'],
                    sha256=v.digest(r['data'])) for r in goals])
    return packed_bytes, image, target, goals, receipt


def child_limits():
    requested = {
        resource.RLIMIT_CORE: (0, 0),
        resource.RLIMIT_AS: (8 * 1024**3, 8 * 1024**3),
        resource.RLIMIT_FSIZE: (MAX_CAPTURE, MAX_CAPTURE),
        resource.RLIMIT_CPU: (TIMEOUT, TIMEOUT + 5),
        resource.RLIMIT_NOFILE: (1024, 1024),
    }
    for which, (soft, hard) in requested.items():
        # The external evaluator can run this proof inside an already bounded
        # worker. A child may tighten, but cannot raise an inherited hard limit.
        inherited_hard = resource.getrlimit(which)[1]
        if inherited_hard != resource.RLIM_INFINITY:
            hard = min(hard, inherited_hard)
        resource.setrlimit(which, (min(soft, hard), hard))


def capture(qemu, plugin, packed, target, goals, output, *, trace_prefix=0, launch_case=None):
    v.require(type(trace_prefix) is int and 0 <= trace_prefix <= 262144,
              'Diagnostic trace prefix must be in 0..262144')
    case = unpack_launch.normalize_case(launch_case) if launch_case is not None else None
    output.mkdir()
    guest = output / 'packed.elf'
    guest.write_bytes(packed)
    guest.chmod(0o700)
    goal_file = output / 'goals.txt'
    goal_file.write_text(''.join(f"{r['address']:x} {r['size']:x}\n" for r in goals))
    events, report = output / 'events.jsonl', output / 'report.json'
    for path in (plugin, guest, goal_file, events, report):
        v.require(not any(c in str(path) for c in ',\n\r'), 'Unsupported capture path delimiter')
    token = uuid.uuid4().hex
    option = (f'{plugin},guest={guest},events={events},report={report},run-id={token}'
              f',target=0x{target:x},goals={goal_file}')
    if trace_prefix:
        option += f',trace={output / "trace.jsonl"},trace-start=1,trace-limit={trace_prefix}'
    command = [str(qemu), '-s', '1044480', '-plugin', option, '-0', 'target.elf', str(guest)]
    if case is not None:
        command.extend(case['argv'])
    environment = {'LC_ALL': 'C', 'TZ': 'UTC'}
    launch = dict(schema_version=1, run_id=token, source_elf_sha256=v.digest(packed),
        qemu_sha256=digest_file(qemu), plugin_sha256=digest_file(plugin),
        target=target, target_pc=target, argv=command, guest_argv=['target.elf'],
        guest_environ=[k + '=' + value for k, value in environment.items()],
        controlled_host_environment=environment, cwd=str(output),
        stdin_empty=True, timeout_seconds=TIMEOUT, payload_instruction_execution_allowed=False,
        new_independent_execution=True, runtime_and_observer_trusted=True)
    launch['execution_mode'] = 'normal'
    if case is not None:
        stdin_data = unpack_launch.stdin_bytes(case)
        (output / unpack_launch.CASE_FILE).write_bytes(unpack_launch.case_bytes(case))
        (output / unpack_launch.STDIN_FILE).write_bytes(stdin_data)
        launch.update(launch_input_profile=unpack_launch.PROFILE,
            launch_case_file=unpack_launch.CASE_FILE, launch_case_id=case['id'],
            launch_case_sha256=unpack_launch.case_sha256(case),
            stdin_file=unpack_launch.STDIN_FILE, stdin_size=len(stdin_data),
            stdin_sha256=v.digest(stdin_data), stdin_empty=not stdin_data,
            guest_argv=['target.elf', *case['argv']])
    v.save(output / 'launch.json', launch)
    print(f'capture: fresh original-entry run; stop before 0x{target:08x}', flush=True)
    stdin_path = output / unpack_launch.STDIN_FILE if case is not None else Path(os.devnull)
    with stdin_path.open('rb') as stdin, (output / 'stdout').open('wb') as stdout, \
            (output / 'stderr').open('wb') as stderr:
        process = subprocess.Popen(command, cwd=output, env=environment, stdin=stdin,
            stdout=stdout, stderr=stderr, close_fds=True, start_new_session=True, preexec_fn=child_limits)
        deadline = time.monotonic() + TIMEOUT
        try:
            while process.poll() is None:
                v.require(time.monotonic() < deadline, 'Observer capture timed out')
                try:
                    process.wait(timeout=min(30, max(0.1, deadline - time.monotonic())))
                except subprocess.TimeoutExpired:
                    print('capture: still running', flush=True)
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=10)
        if case is not None:
            launch['stdin_offset_after_capture'] = stdin.tell()
    launch['returncode'] = process.returncode
    v.save(output / 'launch.json', launch)
    v.require(process.returncode == 0, 'Observer capture failed; inspect ' + str(output / 'stderr'))
    if case is not None:
        retained_case = unpack_launch.load_case(output / unpack_launch.CASE_FILE)
        v.require(unpack_launch.case_bytes(retained_case) == unpack_launch.case_bytes(case),
                  'Fixed launch case changed during capture')
        unpack_launch.validate_launch(launch, retained_case,
            (output / unpack_launch.STDIN_FILE).read_bytes(), capture_directory=output)
    result = v.strict_json(bounded(report, 4 * 1024**2, 'Observer report').read_bytes())
    v.require(result.get('success') is True, 'Observer did not stop successfully')
    rows = observations.read_capture(bounded(events, MAX_CAPTURE, 'Observer events').read_bytes(), launch)
    return rows, launch


def replay(binary, inputs, output, *, producers=False, max_nodes=67000000, trace_prefix=0):
    producer_node_budget(max_nodes)
    v.require(type(trace_prefix) is int and 0 <= trace_prefix <= 262144,
              'Diagnostic trace prefix must be in 0..262144')
    output.mkdir()
    command = [str(binary), *[str(inputs / name) for name in INPUT_NAMES], str(output)]
    environment = dict(os.environ)
    environment.pop('TF_OEP_PRODUCERS', None)
    environment.pop('TF_OEP_PRODUCER_LIMIT', None)
    for key in ('TF_OEP_TRACE_PATH', 'TF_OEP_TRACE_START', 'TF_OEP_TRACE_LIMIT'):
        environment.pop(key, None)
    if trace_prefix:
        environment.update(TF_OEP_TRACE_PATH=str(output / 'trace.jsonl'),
                           TF_OEP_TRACE_START='1', TF_OEP_TRACE_LIMIT=str(trace_prefix))
    if producers:
        environment['TF_OEP_PRODUCERS'] = str(output / 'producers')
        environment['TF_OEP_PRODUCER_LIMIT'] = str(max_nodes)
    with (output / 'execution.json').open('wb') as stdout, (output / 'stderr').open('wb') as stderr:
        result = subprocess.run(command, stdout=stdout, stderr=stderr, env=environment, timeout=TIMEOUT)
    v.require(result.returncode == 0, 'Original-entry IR replay failed; inspect ' + str(output / 'stderr'))


def prove_unpack(directory, output, *, qemu, qemu_include, native=None, max_nodes=67000000,
                 trace_prefix=0, launch_case=None):
    producer_node_budget(max_nodes)
    v.require(type(trace_prefix) is int and 0 <= trace_prefix <= 262144,
              'Diagnostic trace prefix must be in 0..262144')
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    summary = dict(schema_version=1, status='FAIL', errors=[], oep_proof='NOT_ESTABLISHED',
        original_prepack_OEP_independently_established=False, universal_equivalence=False,
        target_instruction_executed=False, selected_execution_proved=False,
        all_observed_image_bytes_SMT_proved=False, computed_transfer_and_fetch_SMT_proved=False,
        original_required=False, output_bytes_used_as_initial_premises=False,
        process_snapshot=False, fuzzing_ready=False)
    try:
        case = unpack_launch.normalize_case(launch_case) if launch_case is not None else None
        source_hashes = snapshot_sources(output)
        packed, image, target, goals, selection = candidate_inputs(directory)
        v.save(output / 'selection.json', selection)
        qemu = bounded(qemu, 512 * 1024**2, 'QEMU executable')
        exported = subprocess.check_output(['nm', '-D', '--defined-only', str(qemu)],
                                           text=True, timeout=30)
        symbols = {line.split()[-1].split('@')[0] for line in exported.splitlines() if line.split()}
        v.require(set(APIS) <= symbols, 'QEMU observer APIs are missing; use the separate observer build')
        if native is None:
            native = build_native(qemu_include, output / 'native')
        binary, plugin, receipt = native
        v.require(digest_file(binary) == receipt['replay_sha256']
                  and digest_file(plugin) == receipt['observer_sha256'], 'Native build identity changed')
        callback_binding = resolve_callback_profile(qemu, qemu_include, native, output)
        diagnostic = dict(trace_prefix=trace_prefix) if trace_prefix else {}
        capture_options = dict(diagnostic)
        if case is not None:
            capture_options['launch_case'] = case
        rows, launch = capture(qemu, plugin, packed, target, goals, output / 'capture', **capture_options)
        context = observations.initial_context(rows, packed, image, launch=launch)
        if case is not None:
            binding = unpack_launch.validate_launch(launch,
                unpack_launch.load_case(output / 'capture' / unpack_launch.CASE_FILE),
                (output / 'capture' / unpack_launch.STDIN_FILE).read_bytes(),
                capture_directory=output / 'capture')
            v.require(binding['case_sha256'] == unpack_launch.case_sha256(case),
                      'Fixed launch case differs from the requested case')
            summary.update(launch_input_profile=unpack_launch.PROFILE, launch_input_binding=binding)
            launch_input_hashes = {name: digest_file(output / 'capture' / name)
                for name in ('launch.json', unpack_launch.CASE_FILE, unpack_launch.STDIN_FILE)}
        context['packed'] = packed
        context['rep_runtime_binding'] = callback_binding
        inputs = output / 'inputs'
        inputs.mkdir()
        config = rep_callbacks.config_text(target, context['stack_base'], 30000000,
            goals, callback_binding['mode']).encode('ascii')
        values = {'source.elf': packed, 'stack.bin': context['stack'],
                  'stack-mask.bin': bytes([255]) * len(context['stack']),
                  'scalars.txt': f"{context['esp']:x} {context['df']:x}\n".encode('ascii'),
                  'contracts.txt': observations.contracts_text(rows).encode('ascii'), 'config.txt': config}
        for name, blob in values.items():
            (inputs / name).write_bytes(blob)
        print('IR: discovering consumed initial stack bytes from the packed entry', flush=True)
        replay(binary, inputs, output / 'discovery', **diagnostic)
        if trace_prefix:
            try:
                from .replay_trace import compare as compare_trace
            except ImportError:
                from replay_trace import compare as compare_trace
            v.save(output / 'diagnostic-prefix.json', compare_trace(
                output / 'capture/trace.jsonl', output / 'discovery/trace.jsonl'))
        discovery = observations.compare_replay(rows, output / 'discovery', goals,
                                               initial_regions=image['initial_regions'])
        projection = (output / 'discovery/projection.bin').read_bytes()
        v.require(len(projection) == len(context['stack']) and all(b in (0, 255) for b in projection),
                  'Invalid consumed-byte projection')
        v.save(output / 'initial-premises.json', observations.validate_projection(context, projection))
        context['stack'] = bytes(b & k for b, k in zip(context['stack'], projection))
        context['mask'] = projection
        (inputs / 'stack.bin').write_bytes(context['stack'])
        (inputs / 'stack-mask.bin').write_bytes(projection)
        print('IR: fresh reduced-premise replay and chronological producer derivation', flush=True)
        replay(binary, inputs, output / 'reduced', producers=True, max_nodes=max_nodes)
        comparison = observations.compare_replay(rows, output / 'reduced', goals,
                                                initial_regions=image['initial_regions'])
        execution = comparison['execution']
        v.require((output / 'reduced/projection.bin').read_bytes() == projection,
                  'Reduced replay consumed a different initial stack projection')
        v.require(execution['path_sha256'] == discovery['execution']['path_sha256'], 'Reduced replay path changed')
        v.save(output / 'comparison.json', comparison)
        input_hashes = [digest_file(inputs / name) for name in INPUT_NAMES]
        proof = unpack_smt.prove_generic(output / 'reduced', context, goals, output / 'smt',
            target=target, execution=execution, input_files_sha256=input_hashes, max_nodes=max_nodes)
        v.require(digest_file(output / 'rep-calibration.json') == callback_binding['calibration_sha256'],
                  'REP calibration binding changed during proof')
        rep_callbacks.load_calibration(output / 'rep-calibration.json', qemu=qemu,
            observer=plugin, sdk=Path(qemu_include) / 'qemu-plugin.h')
        v.require(all(digest_file(ROOT / name) == value for name, value in source_hashes.items()),
                  'Python proof source changed during verification')
        v.require(digest_file(qemu) == launch['qemu_sha256']
                  and digest_file(plugin) == receipt['observer_sha256']
                  and digest_file(binary) == receipt['replay_sha256'], 'Trusted runtime identity changed')
        if case is not None:
            v.require(all(digest_file(output / 'capture' / name) == value
                          for name, value in launch_input_hashes.items()),
                      'Fixed launch input changed during proof')
        summary.update(proof)
        summary.update(errors=[], target=target, packed_sha256=v.digest(packed),
            selected_execution_proved=proof.get('status') == unpack_smt.STATUS,
            run_id=launch['run_id'], consumed_initial_stack_bytes=projection.count(255),
            capture_events_sha256=digest_file(output / 'capture/events.jsonl'),
            native_build=receipt, selection_receipt_sha256=digest_file(output / 'selection.json'))
        v.require(summary.get('selected_execution_proved') is True, 'Generic SMT theorem was not completed')
        print(summary['status'], flush=True)
    except (ValueError, OSError, KeyError, TypeError, AttributeError, UnicodeError,
            RecursionError, ImportError, subprocess.SubprocessError) as error:
        summary['status'] = 'FAIL'
        summary['selected_execution_proved'] = False
        summary['oep_proof'] = 'NOT_ESTABLISHED'
        summary['errors'] = [type(error).__name__ + ': ' + str(error)]
        certificate = output / 'smt/certificate.json'
        if certificate.is_file():
            certificate.rename(output / 'smt/invalidated-certificate.json')
        print('FAIL: ' + summary['errors'][0], flush=True)
    finally:
        v.save(output / 'summary.json', summary)
    return summary


def prove_matrix(matrix, output, *, qemu, qemu_include, max_nodes=67000000, trace_prefix=0):
    """Prove each retained automatic selection; build native tools once."""
    producer_node_budget(max_nodes)
    matrix, output = Path(matrix).resolve(), Path(output).resolve()
    if (matrix / 'probe/samples').is_dir():
        matrix = matrix / 'probe'
    output.mkdir(parents=True, exist_ok=False)
    result = dict(schema_version=1, status='FAIL', errors=[], samples=[],
                  original_required=False, selected_execution_proved=False,
                  historical_originality_proven=False, universal_equivalence=False,
                  fuzzing_ready=False)
    try:
        samples = sorted((matrix / 'samples').iterdir())
        v.require(0 < len(samples) <= 64 and all(p.is_dir() and not p.is_symlink() for p in samples),
                  'Require a bounded unpack matrix samples directory')
        native = build_native(qemu_include, output / 'native')
        calibrate_native(qemu, qemu_include, native, output / 'native/rep-calibration')
        for sample in samples:
            print('proof matrix: ' + sample.name, flush=True)
            proof = prove_unpack(sample / 'unpack', output / sample.name, qemu=qemu,
                qemu_include=qemu_include, native=native, max_nodes=max_nodes,
                **(dict(trace_prefix=trace_prefix) if trace_prefix else {}))
            result['samples'].append(dict(sample=sample.name, status=proof['status'],
                target=proof.get('target'), instructions=proof.get('instructions'),
                packed_sha256=proof.get('packed_sha256'),
                selected_execution_proved=proof.get('selected_execution_proved'),
                SMT_solver_checks=proof.get('SMT_solver_checks'), errors=proof['errors']))
            v.save(output / 'summary.json', result)
            v.require(proof['selected_execution_proved'] is True and not proof['errors'],
                      'Selected-execution proof failed: ' + sample.name)
        result.update(status='PASS_WITH_GENERIC_SELECTED_EXECUTION_SMT_PROOFS',
                      selected_execution_proved=True)
    except (ValueError, OSError, KeyError, TypeError, ImportError, subprocess.SubprocessError) as error:
        result['errors'].append(type(error).__name__ + ': ' + str(error))
        print('FAIL: ' + result['errors'][-1], flush=True)
    finally:
        v.save(output / 'summary.json', result)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    inputs = parser.add_mutually_exclusive_group(required=True)
    inputs.add_argument('--unpack', type=Path, help='Successful unpack.py result directory')
    inputs.add_argument('--matrix', type=Path, help='Successful unpack_matrix.py result directory')
    parser.add_argument('--qemu', type=Path, default=os.environ.get('TF_QEMU_I386'))
    parser.add_argument('--qemu-include', type=Path, default=os.environ.get('TF_QEMU_INCLUDE'))
    parser.add_argument('--max-producer-nodes', type=int, default=67000000)
    parser.add_argument('--trace-prefix', type=int, default=0,
                        help='Retain bounded diagnostic fetch prefixes; never a proof premise')
    parser.add_argument('--output', type=Path)
    parser.add_argument('--launch-case', type=Path,
                        help='One concrete stdin/argv case; unsupported prefix input reads fail closed')
    args = parser.parse_args(argv)
    if args.qemu is None or args.qemu_include is None:
        parser.error('--qemu and --qemu-include are required')
    if not 1 <= args.max_producer_nodes <= MAX_PRODUCER_NODES:
        parser.error(f'Producer budget must be in 1..{MAX_PRODUCER_NODES}')
    if not 0 <= args.trace_prefix <= 262144:
        parser.error('Diagnostic trace prefix must be in 0..262144')
    if args.launch_case is not None and args.matrix is not None:
        parser.error('--launch-case requires --unpack')
    prefix = 'unpack-proof.' if args.unpack else 'unpack-proof-matrix.'
    output = args.output.resolve() if args.output else Path(tempfile.mkdtemp(prefix=prefix, dir=ROOT)) / 'probe'
    print('Results:', output, flush=True)
    function = prove_unpack if args.unpack else prove_matrix
    options = dict(trace_prefix=args.trace_prefix) if args.trace_prefix else {}
    if args.launch_case is not None:
        options['launch_case'] = unpack_launch.load_case(args.launch_case)
    summary = function(args.unpack or args.matrix, output, qemu=args.qemu, qemu_include=args.qemu_include,
                       max_nodes=args.max_producer_nodes,
                       **options)
    return 0 if not summary['errors'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
