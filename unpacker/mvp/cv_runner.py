"""Controlled C corpus built locally, production capture, restart and scale gates."""
from pathlib import Path
import argparse
import base64
import csv
import json
import os
import shutil
import subprocess
import sys

import cu_capture
import cu_fixtures
import cu_runner
import cv_build
import cv_corpus
from ct_elf import CaptureError, code_oracle, read_elf, rebuild, sha256
from cu_process import run, save, compare_runs

ROOT = Path(__file__).resolve().parent
VERSION = '7.4f.3cw'
RSS_LIMIT_MIB = 2048


def check_behavior(case, directory, result, check_stderr=True):
    expected = case['expected']
    if (result['timed_out'] or result['rss_limit_hit']
            or result['returncode'] != expected['returncode']
            or (directory / 'stdout').read_bytes() != base64.b64decode(expected['stdout_base64'])
            or (check_stderr and (directory / 'stderr').read_bytes() != base64.b64decode(expected['stderr_base64']))):
        return False
    return (all((directory / name).is_file() and (directory / name).read_bytes() == base64.b64decode(value)
                for name, value in expected['files'].items())
            and all(not (directory / name).exists() for name in expected['absent_files']))


def cold_check(qemu, original, restored, cases, directory):
    comparisons = []
    for i, case in enumerate(cases):
        pair = dict(id=case['id'])
        valid = True
        for kind, binary in (('original', original), ('restored', restored)):
            path = directory / f'case-{i:03d}' / kind
            result = run([str(qemu), '-0', 'target.elf', str(binary), *case['argv']],
                         case, path, dict(LC_ALL='C', TZ='UTC'), rss_limit_mib=RSS_LIMIT_MIB)
            result['behavior_oracle_match'] = check_behavior(case, path, result)
            result['output_files'] = {name: sha256(path / name) if (path / name).is_file() else None
                                      for name in case['expected']['files']}
            save(path / 'result.json', result)
            pair[kind] = result
            valid &= result['behavior_oracle_match']
        pair['status'] = 'MATCH' if valid and compare_runs(pair['original'], pair['restored']) else 'MISMATCH'
        comparisons.append(pair)
    return dict(status='RUNNABLE_ON_TESTED_CASES' if all(p['status'] == 'MATCH' for p in comparisons) else 'COLD_RUN_MISMATCH',
                cases=len(cases), comparisons=comparisons,
                distinct_inputs=len({json.dumps({k:c[k] for k in ('stdin_base64','argv','files')},sort_keys=True) for c in cases}),
                observation_scope='fresh processes; exit/stdout/stderr and expected output file bytes; independent Python oracle')


def metrics(directory):
    samples = [json.loads(line[len('[TF-SCALE] '):]) for line in (directory / 'stderr').read_text().splitlines()
               if line.startswith('[TF-SCALE] ')]
    if (not samples or samples[-1]['stage'] != 'final'
            or any(row['trace_archive_records'] != 0 or row['trace_ring_records'] > 4096 for row in samples)
            or any(not row['shadow_knowledge_valid'] for row in samples)
            or any(left['instructions'] > right['instructions'] for left, right in zip(samples,samples[1:]))):
        raise CaptureError('INVALID_RESOURCE_METRICS', 'Missing final sample, lost shadow knowledge or unexpected trace retention')
    maxima = {key:max(row[key] for row in samples) for key in samples[0]
              if key != 'stage' and isinstance(samples[0][key], int) and not isinstance(samples[0][key], bool)}
    result = dict(samples=samples, sampled_maxima=maxima, final=samples[-1],
                  scope='periodic 100000-instruction samples, candidate entries and finalization; payload sizes exclude allocator/hash overhead')
    save(directory / 'resource-metrics.json', result)
    return result


def check_program(original, packed, cases, directory, qemu, plugin, guard):
    directory.mkdir(parents=True)
    original, packed = cu_runner.copy_inputs(original, packed, directory)
    save(directory / 'cases.json', cases)
    chosen = next((i for i,c in enumerate(cases) if c['expected']['returncode'] == 0 and
                   (c['stdin_base64'] or c['argv'] or c['files'])), 0)
    capture = cu_capture.capture(qemu, plugin, packed, cases[chosen], directory / 'capture',
                                 dict(LC_ALL='C', TZ='UTC'), guard,
                                 collect_metrics=True, rss_limit_mib=RSS_LIMIT_MIB)
    if not check_behavior(cases[chosen], directory / 'capture', capture, check_stderr=False):
        raise CaptureError('PACKED_BEHAVIOR_MISMATCH', 'Instrumented packed program failed its independent oracle')
    report, regions = cu_capture.validate(directory / 'capture')
    oracle = code_oracle(regions, int(report['oep'],16), read_elf(original))
    if not oracle['complete_exact_match'] or not oracle['entry_exact']:
        raise CaptureError('CODE_ORACLE_MISMATCH', 'Selected entry or executable bytes differ from the original')
    resources = metrics(directory / 'capture')
    rebuilt = rebuild(directory / 'capture/capture.json', directory / 'capture/image.bin', directory / 'restored.elf')
    cold = cold_check(qemu, original, directory / 'restored.elf', cases, directory / 'cold')
    return dict(status='PASS' if cold['status'] == 'RUNNABLE_ON_TESTED_CASES' else 'FAIL',
                reason=None if cold['status'] == 'RUNNABLE_ON_TESTED_CASES' else 'COLD_RUN_MISMATCH',
                original_sha256=sha256(original), packed_sha256=sha256(packed), capture=capture,
                capture_trace_seq=report['capture_trace_seq'], entry=report['oep'],
                candidate_capture_bytes=report['candidate_capture_bytes'], code_oracle=oracle,
                rebuild=rebuilt, cold_run=cold, resource_metrics=resources)


def failure(error, directory):
    row = dict(status='FAIL', reason=getattr(error,'reason',type(error).__name__), detail=str(error))
    if (directory / 'capture/result.json').is_file():
        row['capture'] = json.loads((directory / 'capture/result.json').read_text())
    return row


def matrix(directory, qemu, plugin, guard, compiler, upx, summary, output):
    rows = []
    for name in cv_corpus.NAMES:
        cases = cv_corpus.cases(name)
        if len(cases) != 20 or len({json.dumps({k:c[k] for k in ('stdin_base64','argv','files')},sort_keys=True) for c in cases}) != 20:
            raise CaptureError('INVALID_CORPUS', 'Each C program must have 20 distinct cases')
        for optimization in ('O1','O2'):
            base = directory / name / optimization
            try:
                original = cv_build.build_original(name, optimization, base / 'build', compiler)
                build_error = None
            except (OSError, ValueError, subprocess.SubprocessError) as error:
                build_error = error
            for packing in ('default','lzma'):
                target = base / packing
                print(f'RUN {name}/{optimization}/{packing}', flush=True)
                try:
                    if build_error: raise build_error
                    packed = cv_build.pack(original, packing, target, upx)
                    row = check_program(original, packed, cases, target / 'probe', qemu, plugin, guard)
                except (CaptureError, OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
                    target.mkdir(parents=True,exist_ok=True)
                    row = failure(error, target / 'probe')
                row.update(program=name, optimization=optimization, packing=packing,
                           result_path=str(target.relative_to(output)))
                save(target / 'result.json', row)
                rows.append(row)
                summary['matrix'] = rows
                save(output / 'summary.json', summary)
                peak = row.get('capture',{}).get('max_rss_kib')
                print(f"{row['status']} {name}/{optimization}/{packing}: RSS={peak} KiB; reason={row.get('reason')}",flush=True)
    return rows


def scale(directory, qemu, plugin, guard, compiler, upx, summary, output):
    rows, builds = [], {}
    points = [('image',size,1000) for size in (65536,262144,1048576)]
    points += [('iterations',65536,count) for count in (1000,10000,100000)]
    for axis,size,count in points:
        target = directory / f'{axis}-{size}-{count}'
        print(f'RUN scale/{axis}: image={size}; iterations={count}',flush=True)
        try:
            if size not in builds:
                try:
                    original = cv_build.build_original('scale','O2',directory / f'build-{size}',compiler,size)
                    packed = cv_build.pack(original,'default',directory / f'pack-{size}',upx)
                    builds[size] = (original,packed)
                except (CaptureError,OSError,ValueError,subprocess.SubprocessError) as error:
                    builds[size] = error
                    raise
            if isinstance(builds[size], Exception):
                prior = builds[size]
                raise CaptureError('DEPENDENCY_FAILED',
                                   f'Scale input build-{size}/pack-{size} failed earlier: '
                                   f'{getattr(prior,"reason",type(prior).__name__)}: {prior}')
            original,packed = builds[size]
            cases = [cv_corpus.scale_case(size,count,seed,i) for i,seed in enumerate((0,1,4294967295))]
            row = check_program(original,packed,cases,target,qemu,plugin,guard)
        except (CaptureError,OSError,ValueError,KeyError,subprocess.SubprocessError) as error:
            target.mkdir(parents=True,exist_ok=True)
            row = failure(error,target)
        row.update(axis=axis,image_bytes=size,iterations=count,result_path=str(target.relative_to(output)))
        save(target / 'result.json',row)
        rows.append(row)
        summary['scale'] = rows
        save(output / 'summary.json',summary)
        print(f"{row['status']} scale/{axis}/{size}/{count}: RSS={row.get('capture',{}).get('max_rss_kib')} KiB; reason={row.get('reason')}",flush=True)
    return rows


def late_control(original,packed,case,directory,qemu,plugin,guard):
    directory.mkdir()
    capture = cu_capture.capture(qemu,plugin,packed,case,directory/'capture',dict(LC_ALL='C',TZ='UTC'),guard,method='exit',rss_limit_mib=RSS_LIMIT_MIB)
    report,regions = cu_capture.validate(directory/'capture',method='exit')
    oracle = code_oracle(regions,int(report['oep'],16),read_elf(original))
    if not oracle['complete_exact_match'] or not oracle['entry_exact']:
        raise CaptureError('NEGATIVE_CONTROL_FAILED','Late control did not preserve exact code and entry')
    rebuild(directory/'capture/capture.json',directory/'capture/image.bin',directory/'restored.elf')
    pair = {}
    for name,binary in (('original',original),('restored',directory/'restored.elf')):
        pair[name] = run([str(qemu),'-0','target.elf',str(binary),*case['argv']],case,directory/name,dict(LC_ALL='C',TZ='UTC'),rss_limit_mib=RSS_LIMIT_MIB)
    if (not check_behavior(case,directory/'original',pair['original']) or pair['restored']['returncode'] != 4
            or (directory/'restored/stdout').read_bytes() != b'BADSTATE\n' or (directory/'restored/stderr').read_bytes()):
        raise CaptureError('NEGATIVE_CONTROL_FAILED','Late writable-state mismatch was not detected')
    return dict(status='PASS',expected_failure='LATE_WRITABLE_STATE',code_oracle=oracle,capture=capture,cold_runs=pair)


def legacy_control(variant,output,qemu,plugin,guard,upx):
    name = cu_fixtures.NAMES[variant]
    directory = output/'legacy'/name
    original,packed = cu_fixtures.build(variant,directory/'corpus',upx)
    return cu_runner.check_program(name,original,packed,cu_fixtures.cases(variant),directory/'probe',
                                   qemu,plugin,guard,dict(LC_ALL='C',TZ='UTC'),variant,rss_limit_mib=RSS_LIMIT_MIB)


def write_report(output,summary):
    lines = [f"# TaintForge {VERSION}: {summary['status']}",'',
             'Controlled freestanding C corpus; static non-PIE ELF32/i386. OEP proof: NOT_ESTABLISHED. Full solver checks: 0.','',
             '| Program | Build | UPX | Status | Cold pairs | Capture RSS (MiB) | Capture seconds | Reason |',
             '| --- | --- | --- | --- | ---: | ---: | ---: | --- |']
    for row in summary.get('matrix',[]):
        capture = row.get('capture',{}); cold = row.get('cold_run',{})
        rss = f"{capture['max_rss_kib']/1024:.1f}" if 'max_rss_kib' in capture else '-'
        seconds = f"{capture['wall_seconds']:.3f}" if 'wall_seconds' in capture else '-'
        lines.append(f"| {row['program']} | {row['optimization']} | {row['packing']} | {row['status']} | {cold.get('cases',0)} | {rss} | {seconds} | {row.get('reason') or ''} |")
    lines += ['','## Scale','',
              'Image size and iteration count vary separately. All size points share the same deterministic byte pattern; compression ratio is not varied.','',
              '| Axis | Image bytes | Iterations | Status | RSS (MiB) | Seconds | Shadow pages* | Labels* | DCFG nodes* | Instruction contexts* |',
              '| --- | ---: | ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |']
    fields = ['axis','image_bytes','iterations','status','max_rss_kib','wall_seconds','shadow_pages','provenance_labels','dcfg_nodes','instruction_contexts']
    with (output/'scale.csv').open('w',newline='') as stream:
        writer = csv.DictWriter(stream,fieldnames=fields); writer.writeheader()
        for row in summary.get('scale',[]):
            capture = row.get('capture',{}); counters = row.get('resource_metrics',{}).get('sampled_maxima',{})
            flat = {key:row.get(key,capture.get(key,counters.get(key))) for key in fields}
            writer.writerow(flat)
            rss = f"{flat['max_rss_kib']/1024:.1f}" if flat['max_rss_kib'] is not None else '-'
            seconds = f"{flat['wall_seconds']:.3f}" if flat['wall_seconds'] is not None else '-'
            lines.append(f"| {row['axis']} | {row['image_bytes']} | {row['iterations']} | {row['status']} | {rss} | {seconds} | {flat['shadow_pages']} | {flat['provenance_labels']} | {flat['dcfg_nodes']} | {flat['instruction_contexts']} |")
    lines += ['','*Internal counters are sampled maxima, not exact allocation high-water marks. DCFG branch occurrences count executions, not stored occurrence objects.',
              'Peak RSS uses wait4 for the QEMU process. The 2 GiB acceptance gate applies to observed RSS; a 20 ms monitor can stop a process with overshoot. The separate 8 GiB virtual-address limit is inherited from 7cu.',
              '','## Controls','']
    for name,row in summary.get('controls',{}).items(): lines.append(f"- {name}: {row['status']} ({row.get('reason') or row.get('expected_failure','')})")
    lines += ['','## Scope','',
              'These are 10 owned controlled C programs, not 10 external real applications. Forty packed variants and twenty cases per variant are tested. A PASS does not prove every input/path, arbitrary UPX settings, dynamic linking, PIE, TLS, threads, fork or other architectures.',
              '','## Errors','']
    for error in summary.get('errors',[]): lines.append(f"- {error['reason']}: {error['detail']}")
    (output/'report.md').write_text('\n'.join(lines)+'\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--project',type=Path)
    parser.add_argument('--qemu',type=Path,default=os.environ.get('TF_QEMU_I386'))
    parser.add_argument('--qemu-include',type=Path,default=os.environ.get('TF_QEMU_INCLUDE'))
    parser.add_argument('--upx',type=Path,default=shutil.which('upx') or shutil.which('upx-ucl'))
    parser.add_argument('--guest-cc',type=Path,default=shutil.which(os.environ.get('TF_CV_GUEST_CC','gcc')))
    parser.add_argument('--output',type=Path,required=True)
    args = parser.parse_args()
    output = args.output.resolve(); output.mkdir(parents=True,exist_ok=False)
    summary = dict(package_version=VERSION,status='RUNNING',stage='preflight',errors=[],matrix=[],scale=[],controls={},
                   oep_proof='NOT_ESTABLISHED',full_solver_checks=0,project_sources_modified=False,
                   limits=dict(capture_rss_mib=RSS_LIMIT_MIB,capture_timeout_seconds=120,cold_timeout_seconds=10,
                               address_space_mib=8192,trace_ring_entries=4096,per_image_bytes=16777216,total_capture_bytes=67108864),
                   expected=dict(programs=10,packed_variants=40,inputs_per_variant=20,matrix_pairs=800,
                                 scale_points=6,scale_pairs=18,legacy_pairs=60,jsmn_pairs=1))
    save(output/'summary.json',summary)
    try:
        summary['package_manifest_sha256'] = cu_runner.verify_package()
        if not all((args.qemu,args.qemu_include,args.upx,args.guest_cc)):
            raise CaptureError('MISSING_ENVIRONMENT','Source verified environment.sh; require matching QEMU/header, gcc, binutils and upx/upx-ucl')
        qemu,header,upx,compiler = (p.resolve(strict=True) for p in (args.qemu,args.qemu_include,args.upx,args.guest_cc))
        identity = dict(qemu_sha256=sha256(qemu),qemu_header_sha256=sha256(header/'qemu-plugin.h'),upx_sha256=sha256(upx),
                        guest_compiler_sha256=sha256(compiler),qemu_version=subprocess.check_output([str(qemu),'--version'],text=True).splitlines()[0],
                        upx_version=subprocess.check_output([str(upx),'--version'],text=True).splitlines()[0],
                        compiler_version=subprocess.check_output([str(compiler),'--version'],text=True).splitlines()[0])
        summary['identity'] = identity
        summary['stage'] = 'toolchain-preflight'; save(output/'summary.json',summary)
        summary['toolchain_preflight'] = cv_build.preflight(output/'toolchain-preflight',compiler,upx)
        print('PASS toolchain preflight: ELF writable anchor, gcc/linker and both UPX profiles',flush=True)
        summary['stage'] = 'runner-controls'
        with (output/'runner-controls.log').open('wb') as log:
            subprocess.run([sys.executable,str(ROOT/'tests/test_runner.py')],stdout=log,stderr=subprocess.STDOUT,check=True,timeout=30)
        summary['harness_controls_pass'] = 3
        with (output/'failure-controls.log').open('wb') as log:
            subprocess.run([sys.executable,str(ROOT/'tests/test_failure_controls.py')],stdout=log,stderr=subprocess.STDOUT,check=True,timeout=60)
        summary['failure_harness_controls_pass'] = 4
        summary['stage'] = 'plugin-build'; save(output/'summary.json',summary)
        plugin,guard = cu_runner.build_plugin(header,output/'plugin-build')
        identity.update(plugin_sha256=sha256(plugin),solver_guard_sha256=sha256(guard))
        summary['stage'] = 'matrix'
        matrix(output/'matrix',qemu,plugin,guard,compiler,upx,summary,output)
        good = next((row for row in summary['matrix'] if row['status']=='PASS'),None)
        if good:
            with (output/'capture-validator.log').open('wb') as log:
                subprocess.run([sys.executable,str(ROOT/'tests/test_capture.py'),
                                str(output/good['result_path']/'probe/capture')],
                               stdout=log,stderr=subprocess.STDOUT,check=True,timeout=30)
            summary['capture_validator_controls_pass'] = 9
        summary['stage'] = 'scale'
        scale(output/'scale',qemu,plugin,guard,compiler,upx,summary,output)
        summary['stage'] = 'controls'
        packed_dir = output/'matrix/uintcalc/O2/default'
        original = output/'matrix/uintcalc/O2/build/original.elf'
        control_functions = {
            'late-capture':lambda:late_control(original,packed_dir/'packed.upx',cv_corpus.cases('uintcalc')[1],output/'negative-late-capture',qemu,plugin,guard),
            'budget':lambda:cu_runner.budget_control(packed_dir,output,qemu,plugin,guard,dict(LC_ALL='C',TZ='UTC'),rss_limit_mib=RSS_LIMIT_MIB,case=cv_corpus.cases('uintcalc')[1],behavior_check=check_behavior),
            'collision':lambda:cu_runner.collision_control(packed_dir,output,qemu,plugin,guard,dict(LC_ALL='C',TZ='UTC'),rss_limit_mib=RSS_LIMIT_MIB,case=cv_corpus.cases('uintcalc')[1],behavior_check=check_behavior),
            'jsmn':lambda:cu_runner.check_program('jsmn',ROOT/'corpus/jsmn.original',ROOT/'corpus/jsmn.upx',
                      [dict(id='recorded-input',stdin_base64='',argv=[],files={})],output/'jsmn',qemu,plugin,guard,dict(LC_ALL='C',TZ='UTC'),rss_limit_mib=RSS_LIMIT_MIB)}
        for variant,name in enumerate(cu_fixtures.NAMES):
            control_functions['legacy-'+name] = lambda variant=variant:legacy_control(variant,output,qemu,plugin,guard,upx)
        for name,function in control_functions.items():
            try:
                if name in ('late-capture','budget','collision') and not any(
                        r.get('program')=='uintcalc' and r.get('optimization')=='O2'
                        and r.get('packing')=='default' and r['status']=='PASS' for r in summary['matrix']):
                    raise CaptureError('DEPENDENCY_FAILED', 'Control requires PASS uintcalc/O2/default')
                row = function()
            except (CaptureError,OSError,ValueError,KeyError,subprocess.SubprocessError) as error: row = failure(error,output/name)
            summary['controls'][name] = row; save(output/'summary.json',summary)
            print(f"{row['status']} control/{name}: {row.get('reason') or row.get('expected_failure','')}",flush=True)
        if sha256(qemu) != identity['qemu_sha256'] or sha256(plugin) != identity['plugin_sha256'] or sha256(compiler) != identity['guest_compiler_sha256']:
            raise CaptureError('IDENTITY_CHANGED','QEMU, plugin or guest compiler changed during the run')
        rows = summary['matrix']+summary['scale']+list(summary['controls'].values())
        summary['completed'] = dict(matrix_pass=sum(r['status']=='PASS' for r in summary['matrix']),
            matrix_fail=sum(r['status']!='PASS' for r in summary['matrix']),scale_pass=sum(r['status']=='PASS' for r in summary['scale']),
            scale_fail=sum(r['status']!='PASS' for r in summary['scale']),controls_pass=sum(r['status']=='PASS' for r in summary['controls'].values()),
            matrix_pairs=sum(r.get('cold_run',{}).get('cases',0) for r in summary['matrix']),
            matrix_pairs_matched=sum(sum(p['status']=='MATCH' for p in r.get('cold_run',{}).get('comparisons',[])) for r in summary['matrix']),
            scale_pairs_matched=sum(sum(p['status']=='MATCH' for p in r.get('cold_run',{}).get('comparisons',[])) for r in summary['scale']),
            legacy_pairs_matched=sum(sum(p['status']=='MATCH' for p in r.get('cold_run',{}).get('comparisons',[]))
                                     for name,r in summary['controls'].items() if name.startswith('legacy-')))
        summary.update(status='PASS' if len(summary['matrix'])==40 and len(summary['scale'])==6 and all(r['status']=='PASS' for r in rows) else 'FAIL',stage='complete')
    except (CaptureError,OSError,ValueError,KeyError,TypeError,subprocess.SubprocessError) as error:
        summary['status'] = 'FAIL'
        summary['errors'].append(dict(reason=getattr(error,'reason',type(error).__name__),detail=str(error)))
    save(output/'summary.json',summary)
    write_report(output,summary)
    cu_runner.evidence(output)
    old = output/'mvp-entry-evidence.zip'; evidence = output/'controlled-corpus-evidence.zip'; old.rename(evidence)
    print(f"{summary['status']}: {output/'summary.json'}",flush=True)
    print('OEP proof: NOT_ESTABLISHED; full solver checks: 0',flush=True)
    print(f"Report: {output/'report.md'}\nEvidence: {evidence}",flush=True)
    return 0 if summary['status']=='PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
