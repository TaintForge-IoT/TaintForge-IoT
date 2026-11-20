"""Run the fixed i386 IR windows and compare observed ELF reconstructions."""
import argparse
import json
from pathlib import Path
import shutil
import subprocess
import sys
import uuid

ROOT = Path(__file__).resolve().parent
PROJECT = ROOT.parents[4]
sys.path.insert(0, str(PROJECT))

from taintforge_env.phase1_runtime import Phase1Run, Phase1Runtime, Phase1RuntimeError, read_json
from taintforge_env.runtime_flags import calibrate_flags
from unpacker import unpack
from unpacker.external_worker import reference_image, require
from unpacker.mvp import ct_elf
from unpacker.mvp.tests.regressions.external_ir import fixtures
from unpacker.unpack_process import compare_results, run_process, save, validate_cases

PASS = 'PASS_EXTERNAL_I386_IR_REGRESSIONS'
PROGRAMS = ('minigzip', 'bzip2', 'lua')
MIB = 1024**2
RESULT_FIELDS = ('returncode', 'stdout_bytes', 'stdout_sha256', 'stderr_bytes', 'stderr_sha256', 'output_files')
IR_OPTIONS = ('ir-window=512', 'ir-flat-memory=on', 'ir-tls32=on',
              'ir-observed-munmap=on', 'ir-observed-mprotect=on', 'ir-observed-files=on',
              'ir-observed-proc-exe-boundary=on', 'ir-observed-memfd-boundary=on',
              'ir-observed-set-thread-area=on', 'ir-observed-mov-gs=on', 'ir-observed-set-tid-address=on',
              'ir-xmm-movq=on', 'ir-lock-or32=on', 'ir-observed-sigprocmask=on',
              'ir-observed-sigaction=on', 'ir-observed-stdio=on', 'ir-sse2-dwords=on')


def corpus_file(corpus, spec):
    path = corpus / Path(spec['path']).relative_to('corpus')
    require(path.resolve() == path and path.is_relative_to(corpus), 'Invalid corpus path: ' + str(path))
    unpack.regular(path, 16 * MIB, 'Corpus ELF')
    require(path.stat().st_size == spec['bytes'] and unpack.file_digest(path) == spec['sha256'],
            'Corpus ELF differs from the fixed input: ' + str(path))
    return path


def copy_executable(source, destination, expected_sha):
    shutil.copyfile(source, destination)
    destination.chmod(0o700)
    require(unpack.file_digest(destination) == expected_sha, 'ELF copy differs: ' + str(destination))
    return destination


def check_windows(path, analysis, program, expected):
    raw = unpack.regular(path, 2 * MIB, 'IR journal').read_bytes()
    require(raw.endswith(b'\n'), 'Unsealed IR journal')
    *rows, summary = (json.loads(line) for line in raw.splitlines())
    keys = []
    for row in rows:
        trigger = row['trigger']
        require(row['schema'] == 1 and row['event'] == 'check' and row['kind'] == 'candidate'
                and row['status'] == 'MATCH' and row['selected_steps'] == row['lifted_steps'] == 512
                and row['unknown_observations'] == 0 and trigger['identity_valid'] is True
                and trigger['flags_trusted'] is True and row['vcpu'] == 0
                and trigger['seq'] == row['trigger_seq'] == row['first_seq'] + 512,
                'Incomplete IR window at ' + hex(row['candidate_address']))
        keys.append([hex(row['candidate_address']), hex(trigger['pc']), trigger['target_gpr'], trigger['bytes']])
    require(keys == expected, 'Captured IR window inventory differs: ' + program)
    require(summary['schema'] == 1 and summary['event'] == 'summary' and summary['window_limit'] == 512
            and summary['checks'] == summary['matches'] == analysis['ir_matches'] == len(rows)
            and summary['selected_steps'] == summary['lifted_steps'] == 512 * len(rows)
            and summary['skipped_budget'] == analysis['ir_skipped_budget']
            and all(summary[key] == analysis['ir_' + key] == 0 for key in ('mismatches', 'unknown', 'errors')),
            'IR journal totals differ from Phase 1 events: ' + program)
    if program == 'minigzip':
        by_pc = {row['candidate_address']: row for row in rows}
        mm = by_pc[0x8056fd0]['environment']['files']
        read = by_pc[0x8051148]['environment']
        io, sse2 = read['stdio'], read['sse2_dwords']
        close = by_pc[0x804f360]['environment']['stdio']
        require(mm['anonymous_maps'] == 1 and
                (io['read_count'], io['read_requested'], io['read_returned'], io['read_bytes']) == (2, 8192, 20, 20)
                and (sse2['first_pc'], sse2['movd_count'], sse2['punpckldq_count']) == (0x805067f, 2, 1)
                and close['close_pc'] == io['read_pc'] == 0x40801554 and close['close_seq'] > 0,
                'The recovered minigzip environment transitions differ')
    return summary


def check_program(sample, inputs, qemu, runtime, flags, work, expected, cases, result):
    work.mkdir()
    program = sample['program']
    packed = copy_executable(inputs['packed'], work / 'packed.elf', sample['packed']['sha256'])
    environment = unpack.controlled_environment()
    token = uuid.uuid4().hex
    run = Phase1Run(runtime, 'external-ir-' + token, 'attempt-1', token, work / 'capture',
                    require_flags=True, flags_receipt=flags)
    argument = run.plugin_argument(extra=unpack.CAPTURE_EXTRAS + IR_OPTIONS)
    case, = validate_cases([sample['case']])
    measured = run_process([str(qemu), '-plugin', argument, '-0', 'target.elf', str(packed), *case['argv']],
                           case, work / 'instrumented', timeout=180, file_limit=64 * MIB,
                           rss_limit_mib=3072, environment=environment)
    result['instrumented'] = measured
    require(compare_results([measured]) and all(measured[key] == sample['m22_case_' + key]
            for key in ('returncode', 'stdout_bytes', 'stdout_sha256')), 'Packed execution differs: ' + program)
    phase = run.verify()
    events = run.events()
    capability = events[0]['data']
    analyses = [event['data'] for event in events if event['event_type'] == 'analysis_summary']
    require(phase['runtime_observed'] is True and phase['capture_status'] == 'success'
            and capability['target'] == 'i386' and capability['mode'] == 'linux-user'
            and capability['profile'] == 'linux-i386-single-thread-v1' and capability['ir_enabled'] is True
            and len(analyses) == 1 and analyses[0]['flags_verified'] is True
            and analyses[0]['shadow_knowledge_valid'] is True and analyses[0]['trace_dropped'] == 0
            and not any(event['event_type'] in ('profile_lost', 'data_loss') for event in events),
            'Capture profile or flags evidence differs: ' + program)
    report, regions = unpack.validate_candidate_image(run, events, trace_archive=True)
    result['ir_summary'] = check_windows(run.paths['ir'], analyses[0], program, expected)
    result['phase1'] = phase
    result['phase1_analysis'] = analyses[0]
    rebuilt = work / 'rebuilt.elf'
    result['rebuild'] = ct_elf.rebuild(run.paths['report'], run.paths['dump'], rebuilt)
    entry = ct_elf.integer(report['oep'], 'oep')
    original = copy_executable(inputs['original'], work / 'original.elf', sample['original']['sha256'])
    oracle = ct_elf.code_oracle(regions, entry, reference_image(original))
    result['entry_observation'] = dict(pc=hex(entry), **oracle)
    require(entry == sample['m22_entry'] and oracle['entry_exact'] and oracle['complete_exact_match'],
            'OEP or executable bytes differ: ' + program)
    print(f"{program}: {result['ir_summary']['matches']} MATCH, OEP {hex(entry)}, "
          f"{result['ir_summary']['skipped_budget']} skipped by the check budget", flush=True)
    for fixed in cases:
        case = fixed['case']
        executions = {}
        for role, binary in (('original', original), ('rebuilt', rebuilt)):
            executions[role] = run_process([str(qemu), '-0', 'target.elf', str(binary), *case['argv']],
                                           case, work / 'replay' / case['id'] / role, timeout=30,
                                           file_limit=MIB, environment=environment)
        original_run, replayed = executions['original'], executions['rebuilt']
        passed = (compare_results([original_run, replayed])
                  and {key: original_run[key] for key in RESULT_FIELDS} == fixed['m22_original'])
        result['replays'].append(dict(id=case['id'], match=passed, executions=executions))
        require(passed, f"Reconstructed ELF behavior differs for {program} {case['id']}")
        print(f"{program} {case['id']}: MATCH exit={original_run['returncode']}/{replayed['returncode']}", flush=True)
    require(unpack.file_digest(original) == sample['original']['sha256']
            and unpack.file_digest(rebuilt) == result['rebuild']['elf_sha256'],
            'An executed ELF changed: ' + program)


def execute(qemu, sdk, corpus, output, result):
    definition = read_json(ROOT / 'corpus-pins.json')
    cases = read_json(ROOT / 'replay-cases.json')
    expected = read_json(ROOT / 'windows.json')
    require(tuple(row['program'] for row in definition['cases']) == PROGRAMS
            and cases['source_m22_evidence_sha256'] == definition['source_m22_evidence_sha256']
            and set(expected) == set(cases['samples']) == set(PROGRAMS), 'Unexpected corpus inventory')
    inputs = {row['program']: {role: corpus_file(corpus, row[role]) for role in ('packed', 'original')}
              for row in definition['cases']}
    guards = {path: unpack.file_digest(path) for path in (qemu, sdk / 'qemu-plugin.h')}
    for row in definition['cases']:
        for role, path in inputs[row['program']].items():
            guards[path] = row[role]['sha256']
    plugin = unpack.build_plugin(sdk, output / 'plugin')
    calibration = calibrate_flags(qemu=qemu, qemu_include=sdk, plugin=plugin, out=output / 'calibration')
    require(calibration['status'] == 'READY_X86_FLAGS_RUNTIME', 'EFLAGS calibration failed')
    runtime = Phase1Runtime.load(plugin)
    flags = Path(calibration['flags_receipt'])
    result['runtime'] = dict(qemu=str(qemu), qemu_sha256=guards[qemu], sdk_sha256=guards[sdk / 'qemu-plugin.h'],
                             plugin=str(plugin), plugin_sha256=runtime.plugin_sha256,
                             runtime_manifest_sha256=runtime.manifest_sha256, flags_receipt=str(flags),
                             flags_receipt_sha256=unpack.file_digest(flags))
    print('PASS: exact plugin and 64 EFLAGS comparisons', flush=True)
    native = ROOT.parent / 'imul32/run_native.py'
    with (output / 'native.log').open('wb') as log:
        subprocess.run([sys.executable, '-I', '-B', native, '--project', PROJECT, '--results', output / 'native'],
                       check=True, stdout=log, stderr=subprocess.STDOUT, timeout=1200)
    validation = read_json(output / 'native/validation.json')
    require(validation['status'] == 'PASS' and validation['native_suites'] == 15, 'Native suite incomplete')
    result['native_suites'] = validation['native_suites']
    result['fixtures'] = fixtures.check(qemu, runtime, flags, output / 'fixtures')
    print(f"PASS: {result['native_suites']} native suites and {len(result['fixtures'])} focused guest fixtures", flush=True)
    for sample in definition['cases']:
        program = sample['program']
        fixed = cases['samples'][program]
        require(len(fixed) == 3 and validate_cases([row['case'] for row in fixed]) ==
                [row['case'] for row in fixed], 'Replay case inventory differs: ' + program)
        row = dict(program=program, replays=[])
        result['samples'].append(row)
        check_program(sample, inputs[program], qemu, runtime, flags, output / program, expected[program], fixed, row)
        save(output / 'summary.json', result)
    for path, digest in guards.items():
        require(unpack.file_digest(path) == digest, 'Regression input changed: ' + str(path))
    result['matched_windows'] = sum(row['ir_summary']['matches'] for row in result['samples'])
    result['rebuild_comparisons'] = sum(case['match'] for row in result['samples'] for case in row['replays'])
    require((result['matched_windows'], result['rebuild_comparisons']) == (26, 9), 'Regression cohort incomplete')
    result['status'] = PASS


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('qemu', 'qemu-include', 'corpus', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    qemu, sdk, corpus = (path.resolve(strict=True) for path in (args.qemu, args.qemu_include, args.corpus))
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    result = dict(schema=1, status='INCOMPLETE', samples=[])
    try:
        execute(qemu, sdk, corpus, output, result)
    except (OSError, ValueError, RuntimeError, KeyError, TypeError, Phase1RuntimeError,
            subprocess.SubprocessError) as error:
        result['error'] = f'{type(error).__name__}: {error}'
        print(result['error'], file=sys.stderr, flush=True)
    finally:
        save(output / 'summary.json', result)
    print('Summary: ' + str(output / 'summary.json'), flush=True)
    print(result['status'], flush=True)
    return 0 if result['status'] == PASS else 1


if __name__ == '__main__':
    raise SystemExit(main())
