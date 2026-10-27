#!/usr/bin/env python3
"""Run one bounded external-corpus phase in a separately measured process.

This adapter reuses capture, replay and receipt-audit services.  Reference and
behavior comparisons do not grant a formal proof. The generic proof service
uses a fresh run with either the legacy empty launch or an explicit fixed
stdin/argv case, retaining its PC-only boundary profile.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
from pathlib import Path
import shutil
import stat
import sys


ROOT = Path(__file__).resolve().parent
PROJECT = ROOT.parent
for location in (ROOT, ROOT / 'mvp', PROJECT):
    if str(location) not in sys.path:
        sys.path.insert(0, str(location))

try:
    from . import unpack, unpack_proof, unpack_audit, oep_entry, unpack_launch
    from .mvp import ct_elf
    from .unpack_process import compare_results, run_process, validate_cases
except ImportError:
    import unpack
    import unpack_proof
    import unpack_audit
    import oep_entry
    import unpack_launch
    from mvp import ct_elf
    from unpack_process import compare_results, run_process, validate_cases


PHASES = ('build-plugin', 'build-native', 'baseline', 'capture', 'reference', 'behavior', 'proof')


def require(value, message):
    if not value:
        raise ValueError(message)


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def save(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + '\n')


def checked(path, *, directory=False, maximum=512 * 1024**2):
    require(path is not None, 'Required phase input is missing')
    path = Path(path).expanduser().absolute()
    require(not any(part.is_symlink() for part in (path, *path.parents)),
            'Phase input traverses a symlink: ' + str(path))
    if directory:
        require(path.is_dir(), 'Missing phase directory: ' + str(path))
    else:
        require(path.is_file() and 0 < path.stat().st_size <= maximum,
                'Missing or oversized phase input: ' + str(path))
    return path.resolve(strict=True)


def document(path, maximum=16 * 1024**2):
    path = checked(path, maximum=maximum)
    def pairs(rows):
        result = {}
        for key, value in rows:
            require(key not in result, 'Duplicate phase JSON field: ' + key)
            result[key] = value
        return result
    def invalid(value):
        raise ValueError('Nonfinite phase JSON value: ' + value)
    return json.loads(path.read_bytes(), object_pairs_hook=pairs, parse_constant=invalid)


def _output(path):
    path = Path(path).expanduser().absolute()
    require(not path.exists() and not path.is_symlink() and
            not any(parent.is_symlink() for parent in path.parents),
            'Phase output must be new and cannot traverse symlinks')
    return path


def _required(args, name, *, directory=False, maximum=512 * 1024**2):
    return checked(getattr(args, name, None), directory=directory, maximum=maximum)


def _capture_inputs(args):
    directory = _required(args, 'unpack', directory=True)
    packed = _required(args, 'packed', maximum=unpack.MAX_INPUT_ELF)
    copied = checked(directory / 'inputs/packed.elf', maximum=unpack.MAX_INPUT_ELF)
    require(digest(copied) == digest(packed), 'Capture belongs to another packed input')
    report = checked(directory / 'capture/unpacked.json', maximum=4 * 1024**2)
    dump = checked(directory / 'capture/unpacked.bin', maximum=64 * 1024**2)
    strict = document(report, maximum=4 * 1024**2)
    captured, regions = ct_elf.load_capture(report, dump)
    require(captured == strict, 'Capture report changed while validating')
    return directory, packed, captured, regions


def reference_image(original):
    """TLS headers are metadata here; the image is never a loader premise."""
    original = checked(original, maximum=unpack.MAX_INPUT_ELF)
    data = original.read_bytes()
    image = oep_entry.parse_elf32(data)
    headers = image['program_headers']
    require(not any(row['type'] in (ct_elf.PT_DYNAMIC, ct_elf.PT_INTERP) for row in headers),
            'Reference requires a static i386 ET_EXEC image')
    loads = [dict(address=row['vaddr'], offset=row['offset'], filesz=row['filesz'],
                  memsz=row['memsz'], flags=row['flags']) for row in headers
             if row['type'] == ct_elf.PT_LOAD]
    require(all(not row['flags'] & ~7 for row in loads), 'Unsupported reference LOAD permissions')
    require(any(row['flags'] & 1 and row['address'] <= image['entry'] < row['address'] + row['memsz']
                for row in loads), 'Reference entry is not in executable LOAD memory')
    return dict(entry=image['entry'], loads=loads, data=data, sha256=hashlib.sha256(data).hexdigest(),
                TLS_metadata_present=any(row['type'] == ct_elf.PT_TLS for row in headers))


def _build_plugin(args, output):
    include = _required(args, 'qemu_include', directory=True)
    plugin = unpack.build_plugin(include, output)
    return dict(status='PASS_PLUGIN_BUILD', success=True, plugin=str(plugin),
                plugin_sha256=digest(plugin), receipt_sha256=digest(output / 'build-receipt.json'))


def _build_native(args, output):
    include = _required(args, 'qemu_include', directory=True)
    qemu = _required(args, 'qemu')
    binary, plugin, receipt = unpack_proof.build_native(include, output)
    # Reuse the existing source-built 64-boundary calibration, including both
    # normal blocks and one-instruction blocks.  Its replay binary is not used
    # by this generic proof path.
    import prove_multilayer
    tools = prove_multilayer.build_tools(PROJECT, include / 'qemu-plugin.h', output / 'calibration-tools')
    flags = prove_multilayer.check_flags(qemu, tools['flags_observer'], tools['flags_fixture'],
                                        output / 'flags-probe')
    require(flags['status'] == 'PASS_QEMU_PUSHF_BOUNDARY_PROBE', 'Runtime flag calibration failed')
    calibration = unpack_proof.calibrate_native(qemu, include, (binary, plugin, receipt),
                                               output / 'rep-calibration')
    return dict(status='PASS_NATIVE_BUILD_AND_FLAGS', success=True,
                replay=str(binary), observer=str(plugin), qemu_sha256=digest(qemu),
                replay_sha256=receipt['replay_sha256'], observer_sha256=receipt['observer_sha256'],
                receipt_sha256=digest(output / 'receipt.json'),
                flags_receipt_sha256=digest(output / 'flags-probe/summary.json'),
                rep_calibration_sha256=digest(calibration))


def _capture(args, output):
    packed = _required(args, 'packed', maximum=unpack.MAX_INPUT_ELF)
    qemu, plugin = _required(args, 'qemu'), _required(args, 'plugin')
    cases = unpack.read_cases(_required(args, 'cases', maximum=16 * 1024**2))
    result = unpack.unpack_sample(packed, output, qemu=qemu, plugin=plugin, cases=cases[:1],
        oracle=None, timeout=args.guest_timeout, rss_limit_mib=args.guest_rss_mib)
    require(result['status'] == unpack.STATUS, 'Capture and one-case smoke did not complete')
    return dict(status='PASS_CAPTURE_AND_SMOKE', success=True, unpack_status=result['status'],
                packed_sha256=result['packed_sha256'], target=result['entry'],
                selected_candidate_id=result['selected_candidate_id'], smoke_cases=1,
                capture_guest_executions=result['capture_guest_executions'],
                smoke_guest_executions=result['guest_executions'],
                original_used_as_reconstruction_input=False, SMT_proof_recomputed=False)


def _reference(args, output):
    _, packed, report, regions = _capture_inputs(args)
    # The original is first opened only after capture geometry/identity checks.
    original = reference_image(_required(args, 'original', maximum=unpack.MAX_INPUT_ELF))
    target = ct_elf.integer(report['oep'], 'candidate entry')
    oracle = ct_elf.code_oracle(regions, target, original)
    success = oracle['entry_exact'] is True and oracle['complete_exact_match'] is True
    output.mkdir(parents=True)
    return dict(status='PASS_REFERENCE_ENTRY_AND_CODE_MATCH' if success else
                'REFERENCE_ENTRY_OR_CODE_MISMATCH', success=success, oracle=oracle,
                packed_sha256=digest(packed), original_sha256=original['sha256'], target=target,
                reference_TLS_metadata_only=original['TLS_metadata_present'],
                original_read_after_capture=True, original_used_as_reconstruction_input=False,
                historical_originality_proven=False, formal_proof=False)


def _compare_behavior(args, output, artifacts, *, rebuilt_compared):
    qemu = _required(args, 'qemu')
    cases = validate_cases(unpack.read_cases(_required(args, 'cases', maximum=16 * 1024**2)))
    output.mkdir(parents=True)
    pins = {name: digest(path) for name, path in artifacts.items()}
    source_modes = {name: stat.S_IMODE(path.stat().st_mode) for name, path in artifacts.items()}
    inputs = output / 'inputs'
    inputs.mkdir()
    executable = {}
    for name, source in artifacts.items():
        copied = inputs / (name+'.elf')
        shutil.copyfile(source, copied)
        require(digest(copied) == pins[name], 'Copied behavior input differs from retained bytes')
        copied.chmod(0o700)
        executable[name] = copied
    rows, executed, completed = [], 0, 0
    per_case = len(artifacts)*2
    for index, case in enumerate(cases):
        row = dict(id=case['id'], matched=False, executions={}, errors=[])
        results = []
        for name, binary in executable.items():
            row['executions'][name] = []
            for repeat in range(2):
                try:
                    result = run_process([str(qemu), '-0', 'target.elf', str(binary), *case['argv']],
                        case, output / 'runs' / f'case-{index:03d}' / name / str(repeat),
                        timeout=args.guest_timeout, rss_limit_mib=args.guest_rss_mib,
                        file_limit=1024**2, environment=unpack.controlled_environment())
                    row['executions'][name].append(result)
                    results.append(result)
                    executed += 1
                    completed += compare_results([result])
                except (OSError, ValueError) as error:
                    row['errors'].append(dict(artifact=name, repeat=repeat,
                        type=type(error).__name__, message=str(error)))
        row['matched'] = len(results) == per_case and not row['errors'] and compare_results(results)
        rows.append(row)
        save(output / 'comparisons.json', rows)
        print('external behavior:' if rebuilt_compared else 'external baseline:',
              case['id'], 'MATCH' if row['matched'] else 'MISMATCH', flush=True)
    require(all(digest(path) == pins[name] for name, path in artifacts.items()),
            'Behavior artifact changed during comparison')
    require(all(digest(path) == pins[name] for name, path in executable.items()),
            'Copied behavior executable changed during comparison')
    success = all(row['matched'] for row in rows)
    positive = 'PASS_SELECTED_BEHAVIOR_EQUIVALENCE' if rebuilt_compared else 'PASS_ORIGINAL_PACKED_BASELINE'
    negative = 'SELECTED_BEHAVIOR_MISMATCH' if rebuilt_compared else 'ORIGINAL_PACKED_BASELINE_MISMATCH'
    return dict(status=positive if success else negative,
                success=success, packed_sha256=pins['packed'], artifact_sha256=pins,
                artifact_source_paths={name: str(path) for name, path in artifacts.items()},
                artifact_execution_paths={name: str(path) for name, path in executable.items()},
                source_modes_before=source_modes,
                source_modes_after={name: stat.S_IMODE(path.stat().st_mode)
                                    for name, path in artifacts.items()},
                execution_modes={name: stat.S_IMODE(path.stat().st_mode)
                                 for name, path in executable.items()},
                inputs_copied_for_execution=True, retained_artifact_byte_hashes_preserved=True,
                artifact_names=list(artifacts), rebuilt_compared=rebuilt_compared,
                cases=len(cases), repetitions_per_artifact=2, executions=executed,
                expected_executions=len(cases)*per_case,
                completed_concrete_executions=completed,
                resource_or_signal_stopped_executions=executed-completed,
                execution_errors=sum(len(row['errors']) for row in rows),
                matched_cases=sum(row['matched'] for row in rows),
                all_selected_cases_match=success, comparison_fields=['returncode', 'stdout_sha256',
                    'stderr_sha256', 'output_files'], fresh_process_per_execution=True,
                universal_equivalence=False, formal_proof=False)


def _baseline(args, output):
    packed = _required(args, 'packed', maximum=unpack.MAX_INPUT_ELF)
    original = _required(args, 'original', maximum=unpack.MAX_INPUT_ELF)
    # A loader error shared by two non-ELF files is not a program baseline.
    # This checks static i386 headers without imposing the capture/IR profile.
    reference_image(packed)
    reference_image(original)
    return _compare_behavior(args, output, {'packed': packed, 'original': original},
                             rebuilt_compared=False)


def _behavior(args, output):
    directory, packed, _, _ = _capture_inputs(args)
    original = _required(args, 'original', maximum=unpack.MAX_INPUT_ELF)
    rebuilt = checked(directory / 'rebuilt.elf', maximum=unpack.MAX_INPUT_ELF)
    return _compare_behavior(args, output, {'packed': packed, 'original': original, 'rebuilt': rebuilt},
                             rebuilt_compared=True)


def _proof(args, output):
    directory, packed, _, _ = _capture_inputs(args)
    launch_case = None
    case_path = case_file_sha256 = None
    if getattr(args, 'proof_case', None) is not None:
        case_path = _required(args, 'proof_case', maximum=4 * 1024**2)
        case_file_sha256 = digest(case_path)
        launch_case = unpack_launch.normalize_case(document(case_path, maximum=4 * 1024**2))
    native = _required(args, 'native', directory=True)
    receipt = document(native / 'receipt.json')
    binary = checked(native / 'unpack-execute')
    plugin = checked(native / 'unpack-capture.so')
    require(digest(binary) == receipt.get('replay_sha256') and
            digest(plugin) == receipt.get('observer_sha256'), 'Native proof build identity differs')
    qemu = _required(args, 'qemu')
    include = _required(args, 'qemu_include', directory=True)
    require(digest(checked(include / 'qemu-plugin.h', maximum=1024**2)) == receipt.get('sdk_sha256'),
            'Native proof SDK identity differs')
    build = document(native / 'worker-summary.json')
    flags = document(native / 'flags-probe/summary.json')
    require(flags.get('status') == 'PASS_QEMU_PUSHF_BOUNDARY_PROBE' and
            flags.get('qemu_sha256') == digest(qemu) and
            all(type(flags.get('runs', {}).get(mode)) is dict and
                flags['runs'][mode].get('valid') is True and
                flags['runs'][mode].get('checked') == 32 and
                flags['runs'][mode].get('exit') == 0 for mode in ('normal', 'single')),
            'Native proof flags calibration is incomplete')
    require(build.get('status') == 'PASS_NATIVE_BUILD_AND_FLAGS' and build.get('success') is True and
            build.get('qemu_sha256') == digest(qemu) and
            build.get('receipt_sha256') == digest(native / 'receipt.json') and
            build.get('flags_receipt_sha256') == digest(native / 'flags-probe/summary.json'),
            'Proof requires the exact calibrated native/runtime build')
    calibration = checked(native / 'rep-calibration/calibration.json', maximum=8*1024**2)
    require(build.get('rep_calibration_sha256') == digest(calibration),
            'REP callback calibration differs from the source-built runtime bundle')
    launch_options = {'launch_case': launch_case} if launch_case is not None else {}
    result = unpack_proof.prove_unpack(directory, output, qemu=qemu,
        qemu_include=include,
        native=(binary, plugin, receipt), max_nodes=args.max_producer_nodes, **launch_options)
    if case_path is not None:
        require(digest(case_path) == case_file_sha256, 'Proof launch case changed during execution')
    success = result.get('status') == unpack_audit.PROOF_STATUS
    summary = dict(status='FAIL_SELECTED_EXECUTION_PROOF', success=False,
        proof_status=result.get('status'), packed_sha256=digest(packed), target=result.get('target'),
        boundary_selector_version=1, proof_fresh_stdin='empty', proof_fresh_argv=[],
        same_execution_as_behavior=False, selected_execution_proved=False,
        original_elf_used_as_input=False, historical_originality_proven=False,
        universal_equivalence=False, kernel_implementation_verified=False,
        proof_errors=result.get('errors', []))
    if launch_case is not None:
        stdin_data = unpack_launch.stdin_bytes(launch_case)
        summary.update(proof_launch_profile=unpack_launch.PROFILE,
            launch_case_sha256=unpack_launch.case_sha256(launch_case),
            proof_case_file_sha256=case_file_sha256,
            proof_fresh_stdin='retained_file', proof_fresh_stdin_bytes=len(stdin_data),
            proof_fresh_stdin_sha256=hashlib.sha256(stdin_data).hexdigest(),
            proof_fresh_argv=list(launch_case['argv']))
    if success:
        audit_options = {'expected_launch_case': launch_case} if launch_case is not None else {}
        audit = unpack_audit.audit_sample(output, **audit_options)
        require(audit.get('status') == unpack_audit.STATUS and audit.get('packed_sha256') == digest(packed)
                and audit.get('target') == result.get('target'), 'Proof receipt audit identity differs')
        if launch_case is not None:
            binding = audit.get('launch_input_binding')
            require(audit.get('fixed_launch_case_audited') is True and type(binding) is dict and
                binding.get('profile') == unpack_launch.PROFILE and
                binding.get('case_sha256') == unpack_launch.case_sha256(launch_case) and
                binding.get('stdin_sha256') == summary['proof_fresh_stdin_sha256'] and
                binding.get('stdin_bytes') == summary['proof_fresh_stdin_bytes'] and
                binding.get('argv') == launch_case['argv'] and
                binding.get('stdin_unconsumed_before_selected_boundary') is True and
                binding.get('input_domain_universally_proved') is False and
                binding.get('payload_behavior_proved') is False,
                'Proof receipt audit does not bind the requested fixed launch case')
            summary['launch_input_binding'] = binding
        save(output / 'receipt-audit.json', audit)
        summary.update(status='PASS_AUDITED_SELECTED_EXECUTION_PROOF', success=True,
            selected_execution_proved=True, audit_status=audit['status'],
            receipt_audit_sha256=digest(output / 'receipt-audit.json'),
            SMT_solver_checks=audit['SMT_solver_checks'], instructions=audit['instructions'])
    return summary


HANDLERS = {'build-plugin': _build_plugin, 'build-native': _build_native, 'baseline': _baseline, 'capture': _capture,
            'reference': _reference, 'behavior': _behavior, 'proof': _proof}


def run(args):
    output = _output(args.output)
    result = dict(schema_version=1, phase=args.phase, status='FAIL_WORKER_PHASE', success=False, errors=[])
    try:
        require(args.phase in HANDLERS, 'Unknown external phase')
        require(getattr(args, 'proof_case', None) is None or args.phase == 'proof',
                '--proof-case applies only to the proof phase')
        require(type(args.guest_timeout) in (int, float) and math.isfinite(args.guest_timeout) and
                0 < args.guest_timeout <= 300 and type(args.guest_rss_mib) is int and
                32 <= args.guest_rss_mib <= 4096 and type(args.max_producer_nodes) is int and
                1 <= args.max_producer_nodes <= unpack_proof.MAX_PRODUCER_NODES,
                'Invalid external worker budget')
        result.update(HANDLERS[args.phase](args, output))
    except Exception as error:
        result['errors'].append(dict(type=type(error).__name__, message=str(error),
                                    **({'reason': error.reason} if hasattr(error, 'reason') else {})))
    output.mkdir(parents=True, exist_ok=True)
    save(output / 'worker-summary.json', result)
    print(result['status'], flush=True)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--phase', required=True, choices=PHASES)
    parser.add_argument('--output', required=True, type=Path)
    for name in ('qemu', 'qemu-include', 'plugin', 'packed', 'original', 'cases', 'unpack', 'native'):
        parser.add_argument('--'+name, type=Path)
    parser.add_argument('--proof-case', type=Path,
                        help='One explicit fixed stdin/argv launch case for a fresh proof run')
    parser.add_argument('--guest-timeout', type=float, default=120)
    parser.add_argument('--guest-rss-mib', type=int, default=2048)
    parser.add_argument('--max-producer-nodes', type=int, default=32_000_000)
    args = parser.parse_args(argv)
    try:
        result = run(args)
    except (OSError, ValueError) as error:
        print(type(error).__name__ + ': ' + str(error), file=sys.stderr)
        return 2
    return 0 if result['success'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
