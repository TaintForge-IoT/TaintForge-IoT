"""Build the real IR backend and run focused native regressions."""
from __future__ import annotations
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess

SOURCES = ('dta provenance dcfg trace aux_trace trace_deps trace_deps_x86 replay_input '
           'replay_sources dse dse_lift_x86 ir ir_eval ir_opt ir_lift_x86 ir_environment '
           'ir_replay ir_inputs ir_runtime ir_ssa ir_smt ir_branches ir_concolic ir_oep '
           'phase1_io phase1_retire phase1_resources').split()
RETAINED = ['test_ir_oep', 'test_ir_oep_legacy', 'test_ir_oep_inputs',
            'test_ir_oep_lifetime', 'test_dse_control']
ADDED = ['test_ir_bt', 'test_ir_bt_diagnostics', 'test_ir_div32', 'test_ir_signed_div32', 'test_ir_bitscan32', 'test_ir_rotate32', 'test_ir_shrd32', 'test_ir_mul32']
POSIX_SOURCES = frozenset(('ir_smt', 'ir_concolic'))


def source_feature_flags(name):
    # These two pinned sources explicitly select POSIX.1-2008. A forced
    # phase1_alloc.h loads libc before their first line, so enabling GNU
    # features here lets newer glibc upgrade _POSIX_C_SOURCE underneath them.
    # Keep their requested API and keep -Werror for every translation unit.
    return ['-U_GNU_SOURCE'] if name in POSIX_SOURCES else ['-D_GNU_SOURCE=']


def run(command, log, timeout=180):
    with Path(log).open('wb') as stream:
        result = subprocess.run(list(map(str, command)), stdout=stream,
                                stderr=subprocess.STDOUT, timeout=timeout)
    if result.returncode:
        raise RuntimeError(f'Command failed ({result.returncode}); see {log}\n' +
                           Path(log).read_text(errors='replace')[-4000:])


def diagnostic_checks(directory):
    log = (directory / 'test_ir_bt_diagnostics.log').read_text()
    assert 'replay_build_diagnostics=2/2' in log and 'BT_DIAGNOSTICS_PASS' in log
    collector = json.loads((directory / 'collector.json').read_text())
    assert collector['status'] == 'UNKNOWN' and collector['reason'] == 'unsupported_syscall_prefix'
    assert collector.get('replay_build') is None
    c = collector['collector']
    assert c == {'branch_pc': 0x2000, 'requested_occurrence': 2, 'observed_occurrences': 1,
                 'armed': True, 'last_syscall': {'seq': 3, 'number': 4}}
    missing = json.loads((directory / 'collector-missing.json').read_text())
    assert missing['status'] == 'UNKNOWN' and missing['reason'] == 'selected_branch_not_reached'
    assert missing['collector'] == {'branch_pc': 0x2000, 'requested_occurrence': 2,
        'observed_occurrences': 1, 'armed': True, 'last_syscall': {'seq': 1, 'number': 3}}


def build_and_test(project, results, sanitize=False):
    project, results = Path(project).resolve(), Path(results).resolve()
    results.mkdir(parents=True, exist_ok=False)
    source, tests = project / 'unpacker/test', Path(__file__).resolve().parent / 'native'
    cc = shlex.split(os.environ.get('TF_IR_CC', 'gcc'))
    cflags = shlex.split(os.environ.get('TF_PLUGIN_CPPFLAGS') or
        subprocess.check_output(['pkg-config', '--cflags', 'glib-2.0', 'capstone', 'z3'], text=True))
    libs = shlex.split(os.environ.get('TF_PLUGIN_LIBS') or
        subprocess.check_output(['pkg-config', '--libs', 'glib-2.0', 'capstone', 'z3'], text=True) + ' -lm -pthread')
    flags = ['-std=gnu11', '-O1' if sanitize else '-O2', '-g', '-Wall', '-Wextra', '-Werror',
        '-D_POSIX_C_SOURCE=200809L', '-DTF_IR_TRACE_SSA',
        '-I' + str(source), '-I' + str(tests), *cflags,
        '-ffunction-sections', '-fdata-sections', '-mno-red-zone']
    if sanitize:
        flags += ['-fsanitize=address,undefined', '-fno-omit-frame-pointer']
    objects = [results / (name + '.o') for name in SOURCES]
    (results / 'build-options.json').write_text(json.dumps({
        'compiler': cc, 'common_flags': flags,
        'source_feature_flags': {name + '.c': source_feature_flags(name) for name in SOURCES},
        'test_feature_flags': ['-D_GNU_SOURCE='],
        'allocation_header': str(source / 'phase1_alloc.h'),
    }, indent=2) + '\n')

    def compile_one(name):
        run([*cc, *flags, *source_feature_flags(name),
            '-include', source / 'phase1_alloc.h', '-c', source / (name + '.c'),
            '-o', results / (name + '.o')], results / (name + '.compile.log'))

    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(compile_one, SOURCES))
    rows = []
    for name in ([] if sanitize else RETAINED) + ADDED:
        used = objects
        executable = results / name
        run([*cc, *flags, '-D_GNU_SOURCE=', tests / (name + '.c'), *used, *libs, '-Wl,--gc-sections',
             '-o', executable], results / (name + '.build.log'))
        arguments = ([results / 'collector.json', results / 'collector-missing.json'] if name.endswith('diagnostics') else
                     [] if name in ('test_ir_bt', 'test_ir_div32', 'test_ir_signed_div32', 'test_ir_bitscan32', 'test_ir_rotate32', 'test_ir_shrd32', 'test_ir_mul32') else [results / (name + '.jsonl')])
        print('Running ' + name, flush=True)
        run([executable, *arguments], results / (name + '.log'))
        rows.append({'suite': name, 'status': 'PASS',
            'log_sha256': hashlib.sha256((results / (name + '.log')).read_bytes()).hexdigest()})
    diagnostic_checks(results)
    run([results / 'test_ir_div32', tests / 'clamp-prefix-forms.txt'], results / 'clamp-prefix-forms.log')
    record = {'status': 'PASS', 'sanitizers': ['address', 'undefined'] if sanitize else [],
              'native_suites': len(rows), 'suites': rows, 'diagnostic_json_checks': 'PASS',
              'saved_instruction_forms': '3 prefixes / 90 forms; not historical register or memory replay', 'hardware_BT_comparisons': 4096, 'division_suite': 'test_ir_div32', 'signed_division_suite': 'test_ir_signed_div32',
              'bitscan_suite': 'test_ir_bitscan32', 'rotate_suite': 'test_ir_rotate32', 'shrd_suite': 'test_ir_shrd32', 'mul_suite': 'test_ir_mul32',
              'bitscan_profile': 'bare r32 register forms; exact nonzero result and ZF, legacy conservative zero destination/other flags',
              'scope': 'native regression fixtures; no QEMU or historical recapture executed',
              'compiler': subprocess.check_output([*cc, '--version'], text=True).splitlines()[0]}
    (results / 'validation.json').write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps(record), flush=True)
    return record


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--project', type=Path, required=True)
    parser.add_argument('--results', type=Path, required=True)
    parser.add_argument('--sanitize', action='store_true')
    args = parser.parse_args()
    build_and_test(args.project, args.results, args.sanitize)
