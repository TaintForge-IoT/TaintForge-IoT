#!/usr/bin/env python3
"""Capture a new static i386 sample and check its reconstructed observed image.

This path uses the production candidate detector without historical milestones
or an original ELF. It does not inherit the separate reference SMT theorem.
An optional original is first read after the observed image has been rebuilt.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import uuid

ROOT = Path(__file__).resolve().parent
PROJECT = ROOT.parent
if str(PROJECT) not in sys.path:
    sys.path.insert(0, str(PROJECT))

from taintforge_env.phase1_runtime import Phase1Run, Phase1Runtime, Phase1RuntimeError

try:
    from .mvp import ct_elf
    from .unpack_process import UnpackError, compare_results, run_process, save, validate_cases
except ImportError:
    from mvp import ct_elf
    from unpack_process import UnpackError, compare_results, run_process, save, validate_cases


STATUS = 'PASS_WITH_OBSERVED_IMAGE_AND_SELECTED_CASE_EQUIVALENCE'
MAX_INPUT_ELF = 16 * 1024**2
CAPTURE_EXTRAS = ('tf-capture=entry', 'tf-max-capture-bytes=67108864',
    'dse-check=off', 'ir-trace-capacity=4096', 'runtime-log=summary',
    'tf-max-dump-bytes=16777216', 'tf-max-candidates=64', 'tf-max-events=100000')
SCOPE = dict(oep_proven=False, oep_proof='NOT_ESTABLISHED', process_snapshot=False,
    protected_channel=False, universal_equivalence=False, fuzzing_ready=False,
    historical_proof_reused=False, SMT_proof_recomputed=False,
    capture_scope='tracked_program_pages',
    capture_consistency='best_effort_no_backend_safepoint',
    reconstruction_scope='Fresh static ELF with new metadata and observed RAM pages.')


def require(condition, reason, detail):
    if not condition:
        raise UnpackError(reason, detail)


def file_digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def regular(path, maximum, label):
    path = Path(path).expanduser().absolute()
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= maximum,
            'INVALID_INPUT', label + ' must be a bounded regular file')
    return path.resolve()


def controlled_environment():
    # Private Capstone/Z3 runtime libraries may be needed by the selected plugin.
    value = os.environ.get('LD_LIBRARY_PATH')
    return {'LD_LIBRARY_PATH': value} if value else {}


def read_cases(path):
    path = regular(path, 16 * 1024**2, 'Cases JSON')
    def pairs(rows):
        result = {}
        for key, value in rows:
            require(key not in result, 'INVALID_CASES', 'Duplicate JSON field: ' + key)
            result[key] = value
        return result
    def nonfinite(value):
        raise UnpackError('INVALID_CASES', 'Non-finite JSON value: ' + value)
    try:
        cases = json.loads(path.read_text(encoding='utf-8'), object_pairs_hook=pairs,
                           parse_constant=nonfinite)
        return validate_cases(cases)
    except (ValueError, TypeError, RecursionError) as error:
        if isinstance(error, UnpackError):
            raise
        raise UnpackError('INVALID_CASES', str(error)) from error


def build_plugin(qemu_include, output):
    """Build the canonical production plugin and its runtime manifest."""
    require(qemu_include is not None, 'BUILD_CONFIGURATION',
            'Select the matching QEMU SDK with --qemu-include or TF_QEMU_INCLUDE')
    include = Path(qemu_include).expanduser().resolve(strict=True)
    regular(include / 'qemu-plugin.h', 1024**2, 'QEMU plugin header')
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    plugin = output / 'libtaintforge_ir.so'
    source = ROOT / 'test'
    command = ['bash', str(source / 'build_group7_4c1_plugin.sh'), str(source), str(plugin)]
    environment = {**os.environ, 'TF_QEMU_INCLUDE': str(include)}
    with (output / 'build.log').open('wb') as log:
        try:
            result = subprocess.run(command, env=environment, stdout=log,
                                    stderr=subprocess.STDOUT, timeout=300)
        except subprocess.SubprocessError as error:
            raise UnpackError('PLUGIN_BUILD_FAILED',
                              str(error) + '; inspect ' + str(output / 'build.log')) from error
    require(result.returncode == 0, 'PLUGIN_BUILD_FAILED',
            'Production plugin build failed; inspect ' + str(output / 'build.log'))
    runtime = Phase1Runtime.load(plugin)
    save(output / 'build-receipt.json', dict(schema_version=1, command=command,
        qemu_header_sha256=file_digest(include / 'qemu-plugin.h'),
        build_id=runtime.build_id, plugin_sha256=runtime.plugin_sha256,
        manifest_sha256=runtime.manifest_sha256, historical_package_used=False))
    return plugin


def validate_capture(run):
    """Bind a successful candidate-entry image to the selected runtime/run."""
    verification = run.verify()
    require(verification.get('capture_status') != 'budget_exhausted',
            'CAPTURE_BUDGET_EXHAUSTED', 'Production candidate capture exhausted its byte budget')
    require(verification.get('runtime_observed') is True
            and verification.get('analysis_status') in ('observed', 'partial')
            and verification.get('stream_status') in ('completed', 'partial')
            and verification.get('capture_status') == 'success',
            'INCOMPLETE_CAPTURE', 'Runtime, event stream or selected capture is incomplete')
    events = run.events()
    capabilities = events[0].get('data', {})
    require(capabilities.get('target') == 'i386' and capabilities.get('mode') == 'linux-user'
            and capabilities.get('profile') == 'linux-i386-single-thread-v1'
            and capabilities.get('ir_enabled') is False
            and type(capabilities.get('max_guest_processes')) is int
            and capabilities['max_guest_processes'] == 1
            and type(capabilities.get('max_guest_threads')) is int
            and capabilities['max_guest_threads'] == 1,
            'UNSUPPORTED_PROFILE', 'Require observed single-process/single-thread i386 Linux capture')
    require(not any(e.get('event_type') in ('profile_lost', 'data_loss') for e in events),
            'INCOMPLETE_CAPTURE', 'The supported execution profile or event stream was lost')
    analyses = [e.get('data', {}) for e in events if e.get('event_type') == 'analysis_summary']
    # Disabling semantic proof/flag checks can mark analysis partial. Successful
    # page capture is still usable, provided this is not lost trace/shadow data.
    require(len(analyses) == 1 and analyses[0].get('shadow_knowledge_valid') is True
            and all(type(analyses[0].get(k)) is int and analyses[0][k] == 0
                    for k in ('trace_dropped', 'trace_incomplete', 'ir_errors', 'ir_mismatches')),
            'INCOMPLETE_CAPTURE', 'Trace/shadow integrity or analysis error checks are incomplete')
    try:
        report, regions = ct_elf.load_capture(run.paths['report'], run.paths['dump'])
    except (KeyError, TypeError, AttributeError, OverflowError, RecursionError) as error:
        raise UnpackError('INVALID_CAPTURE', 'Malformed capture record: ' + str(error)) from error
    require(report.get('main_image_verified') is True
            and report.get('dse_check_enabled') is False
            and report.get('trace_archive_enabled') is False,
            'INVALID_CAPTURE', 'Require verified initial main image and bounded detector mode')
    require(report.get('capture_method') == 'candidate_entry_before_instruction'
            and report.get('capture_consistency') == SCOPE['capture_consistency']
            and report.get('capture_scope') == SCOPE['capture_scope']
            and report.get('process_snapshot') is False,
            'CAPTURE_TIMING_MISMATCH', 'Capture is not the declared observed candidate-entry image')
    candidates = report.get('oep_candidates')
    require(type(candidates) is list and 0 < len(candidates) <= 64,
            'INVALID_CAPTURE', 'Require a bounded candidate table')
    chosen = [c for c in candidates if c.get('selected') is True]
    require(len(chosen) == 1 and chosen[0].get('stale') is False
            and all(c.get('candidate_query') == 'NOT_RUN'
                    and c.get('alternative_query') == 'NOT_RUN' for c in candidates),
            'STALE_CANDIDATE', 'Require one current selected candidate without inherited solver results')
    candidate = chosen[0]
    candidate_id, sequence = candidate.get('candidate_id'), candidate.get('observed_trace_seq')
    require(type(candidate_id) is int and candidate_id > 0 and type(sequence) is int and sequence > 0,
            'INVALID_CAPTURE', 'Candidate identity/trace sequence is absent')
    entry = ct_elf.integer(report['oep'], 'oep')
    coordinates = (report.get('capture_candidate_id'), report.get('capture_trace_seq'),
        report.get('capture_pc'), report.get('capture_generation'), report.get('capture_epoch'),
        candidate.get('code_generation'), candidate.get('analysis_epoch'))
    require(all(type(value) is int and 0 <= value < 2**64 for value in coordinates),
            'INVALID_CAPTURE', 'Candidate/capture coordinates must be unsigned integers')
    require(report.get('capture_candidate_id') == candidate_id
            and report.get('capture_trace_seq') == sequence and report.get('capture_pc') == entry
            and report.get('capture_generation') == candidate.get('code_generation')
            and report.get('capture_epoch') == candidate.get('analysis_epoch'),
            'CAPTURE_TIMING_MISMATCH', 'Captured bytes and selected candidate coordinates differ')
    observed = [e for e in events if e.get('event_type') == 'oep_candidate_observed'
                and e.get('data', {}).get('candidate_id') == candidate_id]
    captured = [e for e in events if e.get('event_type') == 'candidate_image_captured'
                and e.get('data', {}).get('candidate_id') == candidate_id]
    selected = [e for e in events if e.get('event_type') == 'oep_candidate_selected']
    require(len(observed) == len(captured) == 1 and bool(selected),
            'INVALID_CAPTURE', 'Selected candidate lacks its observed/captured/selected event chain')
    for event in (observed[0], selected[-1]):
        data = event['data']
        require(data.get('candidate_id') == candidate_id and data.get('address') == entry
                and data.get('observed_trace_seq') == sequence
                and data.get('observed_code_generation') == candidate.get('code_generation')
                and data.get('observed_epoch') == candidate.get('analysis_epoch'),
                'INVALID_CAPTURE', 'Candidate event coordinates differ from the exported image')
    require(captured[0].get('status') == 'success'
            and captured[0]['data'].get('capture_trace_seq') == sequence
            and captured[0]['data'].get('bytes') == run.paths['dump'].stat().st_size,
            'INVALID_CAPTURE', 'Candidate capture event does not identify the retained image')
    return report, regions, verification


def _failure(error):
    return dict(schema_version=1, status='FAIL', reason=getattr(error, 'reason', type(error).__name__),
                errors=[str(error)], **SCOPE)


def unpack_sample(packed, output, *, qemu, plugin, cases, oracle=None, timeout=120,
                  rss_limit_mib=2048, capture_bytes=64 * 1024**2):
    """Fresh capture/rebuild and selected-case differential runs; no OEP proof."""
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    try:
        require(type(timeout) in (int, float) and math.isfinite(timeout) and 0 < timeout <= 300,
                'INVALID_BUDGET', 'Timeout must be positive and at most 300 seconds')
        require(type(capture_bytes) is int and 1 <= capture_bytes <= 64 * 1024**2,
                'INVALID_BUDGET', 'Capture byte budget must be between one byte and 64 MiB')
        cases = validate_cases(cases)
        packed = regular(packed, MAX_INPUT_ELF, 'Packed ELF')
        ct_elf.read_elf(packed)
        qemu = regular(qemu, 512 * 1024**2, 'QEMU executable')
        require(os.access(qemu, os.X_OK), 'INVALID_RUNTIME', 'Selected QEMU is not executable')
        runtime = Phase1Runtime.load(Path(plugin))
        identity = runtime.validate_qemu(qemu)
        environment = controlled_environment()
        save(output / 'cases.json', cases)
        inputs = output / 'inputs'
        inputs.mkdir()
        copied = inputs / 'packed.elf'
        copied.write_bytes(packed.read_bytes())
        copied.chmod(0o700)
        packed_sha256 = file_digest(copied)
        require(packed_sha256 == file_digest(packed), 'IDENTITY_CHANGED', 'Packed input changed while copying')
        shutil.copyfile(runtime.manifest, output / 'runtime-manifest.json')
        save(output / 'runtime.json', dict(qemu=identity, plugin_path=str(runtime.plugin),
            plugin_sha256=runtime.plugin_sha256, plugin_build_id=runtime.build_id,
            plugin_manifest_sha256=runtime.manifest_sha256, environment_additions=environment,
            host_runtime_trusted=True, control_channel_protection='unverified'))
        sources = output / 'source'
        sources.mkdir()
        source_files = (ROOT / 'unpack.py', ROOT / 'unpack_process.py',
                        ROOT / 'mvp/ct_elf.py', PROJECT / 'taintforge_env/phase1_runtime.py')
        source_hashes = {}
        for path in source_files:
            name = str(path.relative_to(PROJECT))
            target = sources / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(path.read_bytes())
            source_hashes[name] = file_digest(target)
        token = uuid.uuid4().hex
        run = Phase1Run(runtime, 'unpack-' + token, 'attempt-1', 'analysis-' + token,
                        output / 'capture')
        extras = (CAPTURE_EXTRAS if capture_bytes == 64 * 1024**2 else
                  tuple('tf-max-capture-bytes=' + str(capture_bytes)
                        if value.startswith('tf-max-capture-bytes=') else value
                        for value in CAPTURE_EXTRAS))
        option = run.plugin_argument(ir=False, extra=extras)
        command = [str(qemu), '-plugin', option, '-0', 'target.elf', str(copied), *cases[0]['argv']]
        print('capture: new packed-ELF run; automatic candidate selection', flush=True)
        captured_process = run_process(command, cases[0], output / 'capture-process',
            timeout=timeout, file_limit=64 * 1024**2, rss_limit_mib=rss_limit_mib,
            environment=environment)
        save(output / 'capture-process.json', captured_process)
        require(compare_results([captured_process]), 'CAPTURE_PROCESS_FAILED',
                'Capture run signaled, timed out or exceeded a resource budget')
        report, regions, verification = validate_capture(run)
        save(output / 'capture-verification.json', verification)
        rebuilt = output / 'rebuilt.elf'
        reconstruction = ct_elf.rebuild(run.paths['report'], run.paths['dump'], rebuilt)
        save(output / 'rebuild.json', reconstruction)
        artifacts = {'packed': copied, 'rebuilt': rebuilt}
        artifact_hashes = {'packed': packed_sha256, 'rebuilt': reconstruction['elf_sha256']}
        require(file_digest(rebuilt) == artifact_hashes['rebuilt'],
                'IDENTITY_CHANGED', 'Rebuilt ELF differs from its reconstruction receipt')
        capture_hashes = {name: file_digest(path) for name, path in run.paths.items() if path.is_file()}
        oracle_receipt = None
        # No original ELF is examined until after reconstruction from observed RAM.
        if oracle is not None:
            original = regular(oracle, MAX_INPUT_ELF, 'Original comparison oracle')
            reference = ct_elf.read_elf(original)
            oracle_receipt = ct_elf.code_oracle(regions, ct_elf.integer(report['oep'], 'oep'), reference)
            oracle_receipt.update(original_sha256=reference['sha256'],
                original_read_after_reconstruction=True, original_used_as_reconstruction_input=False,
                original_prepack_history_authenticated=False)
            save(output / 'oracle.json', oracle_receipt)
            require(oracle_receipt['entry_exact'] and oracle_receipt['complete_exact_match'],
                    'REFERENCE_IMAGE_MISMATCH', 'Observed entry/executable bytes differ from the optional original')
            oracle_copy = inputs / 'original.elf'
            oracle_copy.write_bytes(reference['data'])
            oracle_copy.chmod(0o700)
            artifacts['original'] = oracle_copy
            artifact_hashes['original'] = reference['sha256']
            require(file_digest(oracle_copy) == artifact_hashes['original'],
                    'IDENTITY_CHANGED', 'Copied original differs from its oracle identity')
        comparisons = []
        for index, case in enumerate(cases):
            row = {'id': case['id'], 'executions': {}, 'matched': False}
            comparisons.append(row)
            save(output / 'comparisons.json', comparisons)
            results = []
            for name, path in artifacts.items():
                executions = []
                row['executions'][name] = executions
                for repeat in range(2):
                    result = run_process([str(qemu), '-0', 'target.elf', str(path), *case['argv']],
                        case, output / 'runs' / f'case-{index:03d}' / name / str(repeat),
                        timeout=timeout, file_limit=1024**2, rss_limit_mib=rss_limit_mib,
                        environment=environment)
                    executions.append(result)
                    results.append(result)
                    save(output / 'comparisons.json', comparisons)
                    require(compare_results([result]), 'CASE_EXECUTION_FAILED',
                            'Execution signaled, timed out or exceeded a resource budget on case ' + case['id'])
            require(compare_results(results), 'SELECTED_CASE_MISMATCH',
                    'Behavior or repetition determinism differs on case ' + case['id'])
            row['matched'] = True
            save(output / 'comparisons.json', comparisons)
            print('unpack: matched ' + case['id'], flush=True)
        require(file_digest(copied) == packed_sha256 and file_digest(packed) == packed_sha256,
                'IDENTITY_CHANGED', 'Packed input changed during execution')
        require(all(file_digest(path) == artifact_hashes[name] for name, path in artifacts.items()),
                'IDENTITY_CHANGED', 'Reconstructed or original ELF changed during execution')
        require(all(file_digest(run.paths[name]) == digest for name, digest in capture_hashes.items()),
                'IDENTITY_CHANGED', 'Captured evidence changed during differential execution')
        require(file_digest(qemu) == identity['sha256']
                and file_digest(runtime.plugin) == runtime.plugin_sha256
                and file_digest(runtime.manifest) == runtime.manifest_sha256,
                'IDENTITY_CHANGED', 'Selected host runtime changed during execution')
        summary = dict(schema_version=1, status=STATUS, errors=[], **SCOPE,
            packed_sha256=packed_sha256, rebuilt_sha256=artifact_hashes['rebuilt'],
            entry=ct_elf.integer(report['oep'], 'oep'), selected_candidate_id=report['capture_candidate_id'],
            capture_trace_seq=report['capture_trace_seq'], capture_case_id=cases[0]['id'],
            source_files_sha256=source_hashes, cases=len(cases), repetitions_per_artifact=2,
            guest_executions=len(cases) * len(artifacts) * 2,
            capture_guest_executions=1, compared_artifacts=list(artifacts),
            capture_budget_bytes=capture_bytes,
            comparison_fields=['returncode', 'stdout_sha256', 'stderr_sha256', 'output_files'],
            all_selected_cases_match=True, historical_milestones_required=False,
            original_required=False, original_used_as_reconstruction_input=False,
            optional_original_compared=oracle is not None,
            original_sha256=oracle_receipt['original_sha256'] if oracle_receipt else None,
            observed_capture_bytes=run.paths['dump'].stat().st_size,
            reconstructed_elf_bytes=rebuilt.stat().st_size,
            original_program_headers_recovered=False, original_section_table_recovered=False,
            fresh_process_per_execution=True,
            scope='Observed selected candidate image and equivalence on the supplied finite case set under the selected trusted QEMU/plugin. No formal OEP theorem is established.')
        save(output / 'summary.json', summary)
        return summary
    except (UnpackError, ct_elf.CaptureError, Phase1RuntimeError, OSError, ValueError,
            KeyError, TypeError, subprocess.SubprocessError) as error:
        save(output / 'summary.json', _failure(error))
        raise


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('packed', type=Path)
    parser.add_argument('--cases', required=True, type=Path)
    parser.add_argument('--qemu', required=True, type=Path)
    parser.add_argument('--plugin', type=Path)
    parser.add_argument('--qemu-include', type=Path)
    parser.add_argument('--oracle', type=Path)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--timeout', type=float, default=120)
    parser.add_argument('--rss-limit-mib', type=int, default=2048)
    parser.add_argument('--capture-bytes', type=int, default=64 * 1024**2)
    args = parser.parse_args(argv)
    output = args.output.resolve() if args.output else Path(tempfile.mkdtemp(prefix='unpack-new.', dir=ROOT)) / 'probe'
    if output.exists() or output.is_symlink():
        print('FAIL: OUTPUT_EXISTS: Refusing to overwrite ' + str(output))
        return 1
    print('Results:', output, flush=True)
    try:
        cases = read_cases(args.cases)
        plugin = args.plugin
        if plugin is None:
            output.parent.mkdir(parents=True, exist_ok=True)
            build_base = Path(tempfile.mkdtemp(prefix='unpack-build.', dir=output.parent))
            plugin = build_plugin(args.qemu_include or os.environ.get('TF_QEMU_INCLUDE'), build_base / 'plugin')
        report = unpack_sample(args.packed, output, qemu=args.qemu, plugin=plugin,
            cases=cases, oracle=args.oracle, timeout=args.timeout,
            rss_limit_mib=args.rss_limit_mib, capture_bytes=args.capture_bytes)
        print(report['status'])
        return 0
    except (UnpackError, ct_elf.CaptureError, Phase1RuntimeError, OSError, ValueError,
            KeyError, TypeError, subprocess.SubprocessError) as error:
        output.mkdir(parents=True, exist_ok=True)
        save(output / 'summary.json', _failure(error))
        print('FAIL:', getattr(error, 'reason', type(error).__name__) + ':', error)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
