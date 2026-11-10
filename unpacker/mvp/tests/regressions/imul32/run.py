"""Fixed integer regressions in one process with an inherited disk budget."""
import argparse
from collections import Counter
import hashlib
import os
from pathlib import Path
import shutil
import sys
import tempfile
import traceback

sys.dont_write_bytecode = True
import fixtures
import reporting
import runtime
import storage
from support import check_guards, check_inversion, check_saved_witness, digest, read, require, save

ROOT = Path(__file__).resolve().parent
SUCCESS = 'PASS_INTEGER_CORE_THROUGH_IMUL32_REGRESSIONS'
COHORTS = {
    'imul32': ('integer-core-through-imul32-v1', SUCCESS),
    'bt-imm32': (fixtures.CARRY_PROFILE, 'PASS_BT_IMM32_REGRESSIONS'),
    'all': ('integer-core-through-bt-imm32-v1', 'PASS_INTEGER_CORE_THROUGH_BT_IMM32_REGRESSIONS'),
}
LEGACY_COUNTS = {'bt32': 6, 'div32': 3, 'signed_div32': 6, 'bitscan32': 6, 'rotate32': 6,
                 'shrd32': 3, 'mul32': 3, 'shld32': 6, 'imul32': 3}


def secondary_role(suite):
    if suite in ('bt32', 'div32', 'bt_imm32'):
        return None
    return 'negative-divisor' if suite == 'signed_div32' else 'secondary'


def expected_requests(cases, work):
    result = set()
    for case in cases:
        directory = work / 'cases' / case['suite'] / case['row']['id']
        result.update(directory / name for name in ('inversion', 'saved-witness'))
        role = secondary_role(case['suite'])
        if role:
            result.add(directory / role)
    return result


def run_cases(cases, work, params, requests, oracle, record, cohort='imul32'):
    for case in cases:
        row, expected = case['row'], case['expected']
        directory = work / 'cases' / case['suite'] / row['id']
        binary = fixtures.materialize(case, work / 'binaries' / case['suite'])
        arguments = dict(params, binary=binary, seed=fixtures.fixed(case, 'seed'), branch_pc=row['pc'],
                         offsets=row['offsets'], occurrence=row.get('occurrence', 1))
        if case['suite'] == 'bt_imm32':
            arguments.update(argv=[params['input_path']], seconds=40, memory_mib=512)
        record['guest_execution_requested'] |= not (directory / 'inversion').exists()
        save(work / 'summary.json', record)
        result = requests.execute('invert_file', arguments, directory / 'inversion')
        solved = read(directory / 'inversion/solve/logs/phase1/concolic.json')
        observed = read(directory / 'inversion/observe/logs/phase1/concolic.json')
        seed = (directory / 'inversion/solve/input.bin').read_bytes()
        candidate = (directory / 'inversion/observe/input.bin').read_bytes()
        require(seed == fixtures.fixed(case, 'seed').read_bytes(), 'Fresh inversion seed differs from the fixed seed')
        check_inversion(row, expected, result, solved, observed, seed, candidate)
        for mode, raw in (('solve', seed), ('observe', candidate)):
            require((directory / 'inversion' / mode / 'logs/runtime_stdout.log').read_bytes() ==
                    fixtures.stdout_model(case, raw, oracle), 'Fresh candidate numeric/tokenizer output differs')
        secondary = secondary_role(case['suite'])
        observations = [('witness', 'saved-witness')]
        if secondary:
            observations.append(('secondary', secondary))
        for label, role in observations:
            target = directory / role
            record['guest_execution_requested'] |= not target.exists()
            save(work / 'summary.json', record)
            known = requests.execute('observe_file', dict(arguments, seed=fixtures.fixed(case, label)), target)
            require(known['dse_status'] == 'OBSERVED' and
                    (target / 'observe/input.bin').read_bytes() == fixtures.fixed(case, label).read_bytes(),
                    'Saved witness/secondary execution did not use the fixed input')
            native = read(target / 'observe/logs/phase1/concolic.json')
            if label == 'witness':
                check_saved_witness(row, expected, native)
            else:
                fixtures.secondary_check(case, native)
            raw = (target / 'observe/input.bin').read_bytes()
            require((target / 'observe/logs/runtime_stdout.log').read_bytes() == fixtures.fixed(case, label + '.stdout').read_bytes() ==
                    fixtures.stdout_model(case, raw, oracle), 'Fixed witness/secondary numeric output differs')
        record['results'].append({'suite': case['suite'], 'id': row['id'], 'status': 'VERIFIED',
                                  'saved_witness_reproduced': True, 'secondary_reproduced': secondary is not None,
                                  'fresh_candidate_sha256': result['candidate_sha256'], 'audit': 'PASS'})
        record['guest_executions_with_completed_receipts'] = requests.receipts
        save(work / 'summary.json', record)
        print(case['suite'] + ' ' + row['id'] + ': VERIFIED; saved witness and numeric checks PASS', flush=True)
    counts = Counter(item['suite'] for item in record['results'])
    expected = dict(LEGACY_COUNTS) if cohort != 'bt-imm32' else {}
    if cohort != 'imul32':
        expected['bt_imm32'] = len(fixtures.CARRY_CASES)
    total = sum(expected.values())
    secondary_count = sum(n for name, n in expected.items() if secondary_role(name))
    analyses = 2 * total + secondary_count
    require(counts == expected and requests.receipts == analyses + total and
            requests.fresh + requests.reused == analyses, 'Permanent regression cohort is incomplete')
    record.update(status=COHORTS[cohort][1], verified_inversions=total, saved_witnesses=total,
                  secondary_observations=secondary_count, negative_divisor_observations=expected.get('signed_div32', 0),
                  suite_counts=dict(counts), api_analyses=analyses,
                  guest_executions_with_completed_receipts=requests.receipts, fresh_api_requests=requests.fresh,
                  reused_api_requests=requests.reused)


def verify_payload():
    expected = read(ROOT / 'suite-files.json')
    actual = {str(p.relative_to(ROOT)): digest(p) for p in ROOT.rglob('*')
              if p.is_file() and '__pycache__' not in p.parts and p != ROOT / 'suite-files.json'}
    require(actual == expected, 'Installed integer regression payload differs')


def verify_runtime(cohort, identity, manifest):
    previous = read(ROOT / 'runtime-identity.json')
    if cohort == 'imul32':
        require(identity == previous, 'Permanent runtime differs from the accepted IMUL32 plugin')
        return
    sources = {name.removeprefix('unpacker/test/'): expected
               for name, expected in read(ROOT / 'project-pins.json').items() if name.startswith('unpacker/test/')}
    inputs = manifest['build_inputs']
    require(all(identity[key] == previous[key] for key in ('qemu_sha256', 'flags_receipt_sha256')) and
            inputs['source_files'] == sources and inputs['qemu_header_sha256'] == digest(ROOT / 'sdk/qemu-plugin.h'),
            'Expected the pinned QEMU and flags with a plugin built from the BT immediate sources')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('project', 'qemu', 'plugin', 'flags-receipt', 'storage-baseline', 'resume-work'):
        parser.add_argument('--' + name, type=Path)
    parser.add_argument('--output-dir', type=Path, required=True)
    parser.add_argument('--offline-only', action='store_true')
    parser.add_argument('--cohort', choices=COHORTS, default='imul32',
                        help='original IMUL32 fixtures, BT immediate fixtures, or both with the BT immediate plugin')
    args = parser.parse_args(argv)
    profile, success = COHORTS[args.cohort]
    verify_payload()
    parent = args.output_dir.expanduser().resolve(strict=True)
    require(parent.is_dir() and not parent.is_relative_to(ROOT), 'Keep output outside the permanent suite')
    project = args.project.expanduser().resolve(strict=True) if args.project else None
    if project:
        require(not parent.is_relative_to(project), 'Keep output outside the project')
    if args.resume_work:
        work = args.resume_work.expanduser().resolve(strict=True)
        require(work.parent == parent and work.name.startswith('tfimulreg.') and not args.offline_only,
                'Invalid permanent continuation directory')
        old = read(work / 'summary.json')
        require(old['profile'] == profile and old['status'] in ('INCOMPLETE', success),
                'Only a recognised permanent run of the selected cohort can be continued')
        reporting.preserve(work / 'summary.json')
        reporting.preserve(work / 'disk-admission.json')
    else:
        work = Path(tempfile.mkdtemp(prefix='tfimulreg.', dir=parent))
    name = 'IMUL32' if args.cohort == 'imul32' else args.cohort
    print('Permanent ' + name + ' regression run: ' + str(work), flush=True)
    guards = {p: digest(p) for p in ROOT.rglob('*') if p.is_file() and '__pycache__' not in p.parts}
    record = {'status': 'INCOMPLETE', 'profile': profile, 'results': [],
              'guest_execution_requested': False, 'guest_executions_with_completed_receipts': 0,
              'afl_campaign_executed': False, 'universal_equivalence': False, 'successor_execution_proven': False,
              'scope': 'fixed inversions, saved witnesses and secondary observations of the selected integer cohort'}
    code, requests = 1, None
    try:
        cases = fixtures.load_cases(project, args.cohort)
        for case in cases:
            binary = fixtures.materialize(case, work / 'binaries' / case['suite'])
            guards[binary] = case['row']['elf_sha256']
            if case['suite'] == 'bt_imm32':
                for label in case['row']['fixed']:
                    path = fixtures.fixed(case, label)
                    guards[path] = digest(path)
        save(work / 'suite-definition.json', [{k: v for k, v in case.items() if k not in ('elf_bytes', 'folder', 'elf_hex')}
                                               for case in cases])
        if args.offline_only:
            record.update(status='OFFLINE_PASS_GUESTS_NOT_RUN', fixed_elf_cases=len(cases))
            code = 0
        else:
            require(project and args.qemu and args.plugin and args.flags_receipt and os.getuid() != 0 and os.geteuid() != 0,
                    'Specify project/runtime and run as the original non-root user')
            runtime.verify_project(project, guards)
            qemu, plugin, flags = (p.expanduser().resolve(strict=True) for p in (args.qemu, args.plugin, args.flags_receipt))
            api, unified = runtime.load(project, guards)
            record['runtime_preflight'] = unified.check_runtime_inputs(project, qemu=qemu, plugin=plugin)
            manifest_path = Path(str(plugin) + '.runtime.json')
            manifest = read(manifest_path)
            for path in (qemu, plugin, flags, manifest_path):
                guards[path] = digest(path)
            identity = {'plugin_sha256': digest(plugin), 'manifest_sha256': digest(manifest_path), 'build_id': manifest['build_id'],
                        'qemu_sha256': digest(qemu), 'flags_receipt_sha256': digest(flags)}
            verify_runtime(args.cohort, identity, manifest)
            record['runtime_identity'] = identity
            baseline = None
            if args.storage_baseline:
                path = args.storage_baseline.expanduser().resolve(strict=True)
                require(path == parent / 'disk-preflight.json', 'Use the calling integration storage baseline')
                baseline = read(path)
                guards[path] = digest(path)
            admission = storage.Admission(work, initial=baseline)
            reference = None
            if args.cohort != 'bt-imm32':
                reference, record['legacy_oracle'] = fixtures.tokenizer_oracle(project, work, cases)
            params = dict(qemu=qemu, plugin=plugin, flags_receipt=flags, input_path='/etc/dta-input',
                          max_steps=1024, seconds=30, memory_mib=1024, argv=[])
            requests = runtime.Requests(api, unified, work, admission, identity, expected_requests(cases, work))
            if args.resume_work:
                requests.recover()
                runtime.archive_closed_journal(work)
            from sudo_session import SudoSession
            require(Path(sys.modules['sudo_session'].__file__).resolve() == ROOT / 'sudo_session.py', 'Wrong sudo session helper imported')
            with SudoSession(out=work / 'sudo-session.json'):
                run_cases(cases, work, params, requests, reference, record, args.cohort)
            admission.before_case('suite-exit')
            code = 0
    except BaseException as exc:
        code = 130 if isinstance(exc, KeyboardInterrupt) else 1
        record.update(status='INCOMPLETE', error=type(exc).__name__ + ': ' + str(exc))
        (work / 'driver-error.log').write_text(traceback.format_exc())
        print(record['error'], flush=True)
    finally:
        try:
            check_guards(guards)
            record['guarded_inputs_unchanged'] = True
        except Exception as exc:
            code = 1
            record.update(status='INCOMPLETE', guard_error=str(exc))
        if requests:
            record.update(fresh_api_requests=requests.fresh, reused_api_requests=requests.reused,
                          guest_executions_with_completed_receipts=requests.receipts,
                          fresh_execution_receipts=requests.fresh_receipts, reused_execution_receipts=requests.reused_receipts)
        save(work / 'summary.json', record)
        save(work / 'input-inventory.json', {str(p): h for p, h in guards.items()})
        reporting.export(work)
    print(record['status'], flush=True)
    return code


if __name__ == '__main__':
    raise SystemExit(main())
