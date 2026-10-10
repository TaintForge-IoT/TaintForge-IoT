"""Production candidate capture -> ELF rebuild -> independent cold corpus."""
from pathlib import Path
import argparse
import base64
import json
import os
import shutil
import subprocess
import sys
import zipfile

from ct_elf import CaptureError, code_oracle, read_elf, rebuild, sha256
import cu_capture
import cu_fixtures
from cu_process import cold_check, run, save

ROOT = Path(__file__).resolve().parent
VERSION = '7.4f.3cu'


def verify_package():
    manifest = json.loads((ROOT / 'manifest.json').read_text())
    for name, digest in manifest['files'].items():
        path = ROOT / name
        if Path(name).is_absolute() or '..' in Path(name).parts or sha256(path) != digest:
            raise CaptureError('PACKAGE_HASH_MISMATCH', f'Package input changed: {name}')
    return sha256(ROOT / 'manifest.json')


def build_plugin(header, output):
    output.mkdir()
    plugin, guard = output / 'libtaintforge_cu.so', output / 'no_solver.so'
    env = os.environ.copy()
    env['TF_QEMU_INCLUDE'] = str(header)
    commands = [
        ['bash', str(ROOT / 'source/build_group7_4c1_plugin.sh'), str(ROOT / 'source'), str(plugin)],
        [os.environ.get('TF_IR_CC', 'gcc'), '-std=c11', '-Wall', '-Wextra', '-O2', '-fPIC', '-shared',
         str(ROOT / 'tests/no_solver.c'), '-o', str(guard)]]
    with (output / 'build.log').open('wb') as log:
        for command in commands:
            child = subprocess.run(command, env=env, stdout=log, stderr=subprocess.STDOUT)
            if child.returncode:
                raise CaptureError('BUILD_FAILED', f"Build exited {child.returncode}; see {output / 'build.log'}")
    return plugin, guard


def copy_inputs(original, packed, directory):
    inputs = directory / 'inputs'
    inputs.mkdir()
    for source, filename in ((original, 'original.elf'), (packed, 'packed.upx')):
        target = inputs / filename
        target.write_bytes(source.read_bytes())
        target.chmod(0o755)
        if sha256(source) != sha256(target):
            raise CaptureError('IDENTITY_CHANGED', 'ELF input changed while copying')
    return inputs / 'original.elf', inputs / 'packed.upx'


def check_program(name, original, packed, cases, directory, qemu, plugin, guard, env, variant=None, rss_limit_mib=None):
    directory.mkdir()
    original, packed = copy_inputs(original, packed, directory)
    case_index = 12 if variant == 1 else 4 if variant is not None else 0
    record = dict(name=name, status='RUNNING', original_sha256=sha256(original), packed_sha256=sha256(packed))
    record['capture'] = cu_capture.capture(qemu, plugin, packed, cases[case_index], directory / 'capture', env, guard, rss_limit_mib=rss_limit_mib)
    report, regions = cu_capture.validate(directory / 'capture')
    reference = read_elf(original)
    oracle = code_oracle(regions, int(report['oep'], 16), reference)
    record['code_oracle'] = oracle
    if not oracle['complete_exact_match'] or not oracle['entry_exact']:
        raise CaptureError('CODE_ORACLE_MISMATCH', f'{name}: entry or executable bytes differ from the original')
    record['rebuild'] = rebuild(directory / 'capture/capture.json', directory / 'capture/image.bin', directory / 'restored.elf')
    record['cold_run'] = cold_check(qemu, original, directory / 'restored.elf', cases, directory / 'cold', env)
    if record['cold_run']['status'] != 'RUNNABLE_ON_TESTED_CASES':
        raise CaptureError('COLD_RUN_MISMATCH', f'{name}: independent cold executions differ')
    for i, comparison in enumerate(record['cold_run']['comparisons']):
        expected = cu_fixtures.expected(variant, cu_fixtures.SEEDS[i]) if variant is not None else (0, b'tokens=9 device=sensor ports=2\n')
        for kind in ('original', 'restored'):
            if (comparison[kind]['returncode'] != expected[0]
                    or (directory / f'cold/case-{i:03d}/{kind}/stdout').read_bytes() != expected[1]
                    or comparison[kind]['stderr_bytes'] != 0):
                raise CaptureError('BEHAVIOR_ORACLE_MISMATCH', f'{name}: independent behavior oracle failed on {cases[i]["id"]}')
    record.update(status='PASS', selected_candidate_id=report['capture_candidate_id'],
                  capture_trace_seq=report['capture_trace_seq'], entry=report['oep'])
    save(directory / 'result.json', record)
    print(f"PASS {name}: candidate entry capture; {record['cold_run']['distinct_inputs']} distinct inputs; capture RSS={record['capture']['max_rss_kib']} KiB", flush=True)
    return record


def timing_control(corpus, output, qemu, plugin, guard, env):
    directory = output / 'negative-late-capture'
    directory.mkdir()
    record = cu_capture.capture(qemu, plugin, corpus / 'packed.upx', cu_fixtures.cases(2)[4],
                                directory / 'capture', env, guard, method='exit')
    report, regions = cu_capture.validate(directory / 'capture', method='exit')
    reference = read_elf(corpus / 'original.elf')
    oracle = code_oracle(regions, int(report['oep'], 16), reference)
    rebuild(directory / 'capture/capture.json', directory / 'capture/image.bin', directory / 'restored.elf')
    result = cold_check(qemu, corpus / 'original.elf', directory / 'restored.elf', [cu_fixtures.cases(2)[4]], directory / 'cold', env)
    if (not oracle['complete_exact_match'] or not oracle['entry_exact']
            or result['status'] != 'COLD_RUN_MISMATCH'
            or result['comparisons'][0]['original']['returncode'] != 0
            or result['comparisons'][0]['restored']['returncode'] != 4):
        raise CaptureError('NEGATIVE_CONTROL_FAILED', 'Late mutable-state capture was not detected')
    record = dict(status='PASS', expected_failure='COLD_RUN_MISMATCH', code_oracle=oracle,
                  capture=record, cold_run=result, capture_trace_seq=report['capture_trace_seq'])
    save(directory / 'result.json', record)
    print('PASS negative control: late capture has identical code but cannot restart with the expected writable state', flush=True)
    return record


def budget_control(corpus, output, qemu, plugin, guard, env, rss_limit_mib=None, case=None, behavior_check=None):
    directory = output / 'negative-capture-budget'
    case = case if case is not None else cu_fixtures.cases(2)[4]
    record = cu_capture.capture(qemu, plugin, corpus / 'packed.upx', case,
                                directory, env, guard, max_capture_bytes=1, rss_limit_mib=rss_limit_mib)
    cause = cu_capture.validate_export_failure(directory, record, 'budget_exhausted', 'capture_budget_exhausted')
    if behavior_check and not behavior_check(case, directory, record, check_stderr=False):
        raise CaptureError('NEGATIVE_CONTROL_FAILED', 'Budget-control guest failed its behavior oracle')
    try:
        cu_capture.validate(directory)
    except CaptureError as error:
        if error.reason not in ('CAPTURE_UNAVAILABLE', 'INCOMPLETE_CAPTURE'):
            raise
        result = dict(status='PASS', expected_failure='CAPTURE_BUDGET_EXHAUSTED',
                      validator_rejection=error.reason, cause=cause, capture=record)
    else:
        raise CaptureError('NEGATIVE_CONTROL_FAILED', 'An exhausted capture budget was accepted')
    save(directory / 'control.json', result)
    print('PASS negative control: capture budget exhaustion rejects the artifact', flush=True)
    return result


def collision_control(corpus, output, qemu, plugin, guard, env, rss_limit_mib=None, case=None, behavior_check=None):
    directory = output / 'negative-existing-image'
    case = dict(case if case is not None else cu_fixtures.cases(2)[4])
    sentinel = b'pre-existing input; preserve these bytes\n'
    case['files'] = {**case.get('files', {}), 'image.bin.candidate-1': base64.b64encode(sentinel).decode()}
    process = cu_capture.capture(qemu, plugin, corpus / 'packed.upx', case, directory, env, guard, rss_limit_mib=rss_limit_mib)
    cause = cu_capture.validate_export_failure(directory, process, 'error', 'dump_open_failed')
    if behavior_check and not behavior_check(case, directory, process, check_stderr=False):
        raise CaptureError('NEGATIVE_CONTROL_FAILED', 'Collision-control guest failed its behavior oracle')
    try:
        cu_capture.validate(directory)
    except CaptureError as error:
        if (error.reason not in ('CAPTURE_UNAVAILABLE', 'INCOMPLETE_CAPTURE')
                or (directory / 'image.bin.candidate-1').read_bytes() != sentinel):
            raise CaptureError('NEGATIVE_CONTROL_FAILED', 'Existing image was replaced or removed')
        result = dict(status='PASS', expected_failure='DUMP_OPEN_FAILED_WITH_EXISTING_IMAGE',
                      validator_rejection=error.reason, cause=cause, existing_file_preserved=True, capture=process)
    else:
        raise CaptureError('NEGATIVE_CONTROL_FAILED', 'An image destination collision was accepted')
    save(directory / 'control.json', result)
    print('PASS negative control: destination collision preserves the existing file and rejects export', flush=True)
    return result


def evidence(output):
    files = [p for p in sorted(output.rglob('*')) if p.is_file() and p.suffix != '.zip']
    save(output / 'evidence-files.json', {str(p.relative_to(output)): sha256(p) for p in files})
    with zipfile.ZipFile(output / 'mvp-entry-evidence.zip', 'w', zipfile.ZIP_DEFLATED) as archive:
        for path in files + [output / 'evidence-files.json']:
            archive.write(path, str(path.relative_to(output)))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--project', type=Path)
    parser.add_argument('--qemu', type=Path, default=os.environ.get('TF_QEMU_I386'))
    parser.add_argument('--qemu-include', type=Path, default=os.environ.get('TF_QEMU_INCLUDE'))
    parser.add_argument('--upx', type=Path, default=shutil.which('upx') or shutil.which('upx-ucl'))
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    summary = dict(package_version=VERSION, status='RUNNING', stage='preflight', errors=[], programs=[],
                   oep_proof='NOT_ESTABLISHED', production_oep_detector_exercised=False,
                   full_solver_checks=0, project_sources_modified=False,
                   scope='i386 linux-user; single process/thread; static non-PIE ELF; three controlled UPX programs and the pinned jsmn regression',
                   limits=dict(capture_timeout_seconds=120, cold_timeout_seconds=10,
                               address_space_mib=8192, trace_ring_entries=4096,
                               per_capture_bytes=16*1024**2, total_capture_bytes=64*1024**2))
    save(output / 'summary.json', summary)
    try:
        summary['package_manifest_sha256'] = verify_package()
        if not args.qemu or not args.qemu_include or not args.upx:
            raise CaptureError('MISSING_ENVIRONMENT', 'Source environment.sh; require TF_QEMU_I386, TF_QEMU_INCLUDE and upx/upx-ucl')
        qemu, header, upx = (p.resolve(strict=True) for p in (args.qemu, args.qemu_include, args.upx))
        if not (header / 'qemu-plugin.h').is_file():
            raise CaptureError('MISSING_ENVIRONMENT', 'Matching qemu-plugin.h not found')
        summary['identity'] = dict(qemu_sha256=sha256(qemu), qemu_header_sha256=sha256(header / 'qemu-plugin.h'),
                                   upx_sha256=sha256(upx), qemu_version=subprocess.check_output([str(qemu), '--version'], text=True).splitlines()[0])
        summary['stage'] = 'build'
        save(output / 'summary.json', summary)
        plugin, guard = build_plugin(header, output / 'build')
        summary['identity'].update(plugin_sha256=sha256(plugin), solver_guard_sha256=sha256(guard))
        summary['stage'] = 'corpus'
        env = dict(LC_ALL='C', TZ='UTC')
        for variant, name in enumerate(cu_fixtures.NAMES):
            directory = output / name
            original, packed = cu_fixtures.build(variant, directory / 'corpus', upx)
            save(directory / 'cases.json', cu_fixtures.cases(variant))
            row = check_program(name, original, packed, cu_fixtures.cases(variant), directory / 'probe',
                                qemu, plugin, guard, env, variant)
            summary['programs'].append(row)
            summary['production_oep_detector_exercised'] = True
            save(output / 'summary.json', summary)
        summary['stage'] = 'jsmn-regression'
        summary['jsmn'] = check_program('jsmn', ROOT / 'corpus/jsmn.original', ROOT / 'corpus/jsmn.upx',
            [dict(id='recorded-input', stdin_base64='', argv=[], files={})], output / 'jsmn', qemu, plugin, guard, env)
        summary['stage'] = 'negative-controls'
        corpus = output / 'stateful-parser/corpus'
        summary['late_capture_control'] = timing_control(corpus, output, qemu, plugin, guard, env)
        summary['budget_control'] = budget_control(corpus, output, qemu, plugin, guard, env)
        summary['collision_control'] = collision_control(corpus, output, qemu, plugin, guard, env)
        if sha256(qemu) != summary['identity']['qemu_sha256'] or sha256(plugin) != summary['identity']['plugin_sha256']:
            raise CaptureError('IDENTITY_CHANGED', 'QEMU or plugin changed during the corpus run')
        summary.update(status='PASS', stage='complete', corpus_programs=3, corpus_input_comparisons=60,
                       per_program_distinct_inputs=20,
                       milestone='M1 controlled production-capture corpus',
                       capture_peak_rss_kib=max(p['capture']['max_rss_kib'] for p in summary['programs'] + [summary['jsmn']]))
    except (CaptureError, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        summary.update(status='FAIL')
        summary['errors'].append(dict(reason=getattr(error, 'reason', type(error).__name__), detail=str(error)))
    save(output / 'summary.json', summary)
    evidence(output)
    print(f"{summary['status']}: {output / 'summary.json'}", flush=True)
    print('OEP proof: NOT_ESTABLISHED; full solver checks: 0; production capture: '
          + ('VALIDATED' if summary['production_oep_detector_exercised'] else 'NOT_VALIDATED'), flush=True)
    for error in summary['errors']:
        print(f"{error['reason']}: {error['detail']}", file=sys.stderr)
    print(f"Evidence: {output / 'mvp-entry-evidence.zip'}", flush=True)
    return 0 if summary['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
