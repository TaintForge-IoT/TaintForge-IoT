"""Permanent fixed-ELF DIV32 regressions, optionally with the six BT32 cases."""
import argparse
import importlib.util
import hashlib
import os
from pathlib import Path
import shutil
import sys
import tempfile
import traceback

import corpus
from support import (check_guards, check_inversion, check_saved_witness, digest,
                     export_reports, read, require, save)

ROOT = Path(__file__).resolve().parent
MIB = 1024 ** 2


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def verify_cases():
    definition = read(ROOT / 'cases.json')
    require(len(definition['cases']) == 3, 'Expected three fixed-ELF DIV32 cases')
    for row in definition['cases']:
        folder = ROOT / row['data']
        require(folder.resolve().is_relative_to(ROOT), 'Invalid fixture path')
        for key, name in [('seed', 'seed'), ('witness', 'witness'), ('expected', 'expected.json'),
                          ('elf_hex', 'elf.hex'), ('seed_stdout', 'seed.stdout'), ('witness_stdout', 'witness.stdout')]:
            require(digest(folder / name) == row[key + '_sha256'], 'Fixture changed: ' + row['id'] + '/' + name)
        seed, witness = (folder / 'seed').read_bytes(), (folder / 'witness').read_bytes()
        require(len(seed) == len(witness) == 5 and
                [i for i, (a, b) in enumerate(zip(seed, witness)) if a != b] == row['changed_offsets'] and
                set(row['changed_offsets']) <= set(row['offsets']), 'Invalid saved DIV32 witness')
        expected = read(folder / 'expected.json')
        require(expected['branch_pc'] == row['pc'] and
                expected['baseline_route'][:-1] == expected['witness_route'][:-1] and
                expected['baseline_taken'] is False and expected['witness_taken'] is True,
                'Saved branch or route differs')
        require(corpus.model(7, seed) == row['expected_seed_value'] == row['compare_value'] and
                corpus.model(7, witness) == row['expected_witness_value'] != row['compare_value'],
                'Saved DIV32 input differs from its independent Python model')
        require((folder / 'seed.stdout').read_bytes() == b'F\n' and
                (folder / 'witness.stdout').read_bytes() == b'T\n', 'Invalid saved stdout')
    return definition


def materialize(row, output):
    raw = bytes.fromhex((ROOT / row['data'] / 'elf.hex').read_text())
    require(hashlib.sha256(raw).hexdigest() == row['elf_sha256'], 'Fixed ELF differs')
    output.write_bytes(raw); output.chmod(0o755); corpus.elf_view(output)
    expected = read(ROOT / row['data'] / 'expected.json')
    require(corpus.instruction_bytes(output, row['pc'], len(expected['branch_bytes']) // 2).hex() ==
            expected['branch_bytes'], 'Selected branch bytes differ from the fixed ELF')


def _continuation():
    sys.path.insert(0, str(ROOT.parent / 'continuation_support'))
    import continuation
    return continuation


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--project', type=Path)
    parser.add_argument('--qemu', type=Path)
    parser.add_argument('--plugin', type=Path)
    parser.add_argument('--flags-receipt', type=Path)
    parser.add_argument('--output-dir', type=Path, required=True)
    parser.add_argument('--suite', choices=('div32', 'all'), default='all')
    parser.add_argument('--offline-only', action='store_true')
    parser.add_argument('--resume-work', type=Path)
    args = parser.parse_args(argv)
    parent = args.output_dir.expanduser().resolve(strict=True)
    require(not parent.is_relative_to(ROOT), 'Keep output outside the regression directory')
    project = args.project.expanduser().resolve(strict=True) if args.project else None
    if not args.offline_only:
        require(project and args.qemu and args.plugin and args.flags_receipt, 'Specify project, QEMU, plugin and flags receipt')
        require(not parent.is_relative_to(project), 'Keep run output outside the project')
    continuation = _continuation()
    work = continuation.work_directory(args.resume_work, parent, 'tfdivreg.')
    print('Permanent DIV32 regression run: ' + str(work), flush=True)
    guards = {p: digest(p) for p in ROOT.rglob('*') if p.is_file() and '__pycache__' not in p.parts}
    record = {'status': 'INCOMPLETE', 'profile': 'bt32-div32-permanent-regressions-v1',
        'regressions': [], 'div32_regressions': [], 'guest_execution_requested': False,
        'guest_executions_with_completed_receipts': 0, 'afl_campaign_executed': False,
        'universal_equivalence': False, 'successor_execution_proven': False,
        'scope': 'three DIV32 cases and optionally six BT32 cases; bounded inversions and saved witness reruns'}
    code = 1
    disk_admission = None
    try:
        definition = verify_cases(); save(work / 'suite-definition.json', definition)
        binaries = {}
        for row in definition['cases']:
            binary = work / (row['id'] + '.elf'); continuation.materialize(materialize, row, binary, preserve=bool(args.resume_work)); binaries[row['id']] = binary
            folder = work / 'definition' / row['id']; folder.mkdir(parents=True, exist_ok=bool(args.resume_work))
            for name in ('seed', 'witness', 'expected.json', 'seed.stdout', 'witness.stdout'):
                continuation.copyfile(ROOT / row['data'] / name, folder / name, preserve=bool(args.resume_work))
        if args.offline_only:
            record.update(status='OFFLINE_PASS_GUESTS_NOT_RUN', offline_div32_fixture_cases=3); code = 0
        else:
            require(os.getuid() != 0 and os.geteuid() != 0, 'Run as the original non-root user')
            sys.dont_write_bytecode = True; sys.path.insert(0, str(project))
            btroot = ROOT.parent / 'bt32'; sys.path.append(str(btroot))
            driver = load('accepted_bt32_regressions', btroot / 'run.py')
            api, runtime = driver.runtime(project, args.qemu.resolve(), args.plugin.resolve(), args.flags_receipt.resolve(), guards)
            record['runtime_preflight'] = runtime
            for name, module in tuple(sys.modules.items()):
                path = getattr(module, '__file__', None)
                if path and name.split('.')[0] in ('taintforge_env', 'experiments', 'scripts'):
                    path = Path(path).resolve(); require(path.is_relative_to(project), 'Foreign project module imported')
                    if path in guards: require(digest(path) == guards[path], 'Project source changed during import')
                    guards[path] = digest(path)
            sys.path.insert(0, str(ROOT.parent / 'shared_storage'))
            from regression_disk import Admission
            disk_admission = Admission(work)
            record['storage_initial'] = disk_admission.value['initial']
            def admission():
                disk_admission.before_case('next-api-request-or-legacy-run')
            params = dict(qemu=args.qemu.resolve(), plugin=args.plugin.resolve(), flags_receipt=args.flags_receipt.resolve(),
                          input_path=definition['input_path'], max_steps=1024, seconds=30, memory_mib=1024, argv=[])
            from sudo_session import SudoSession
            record['guest_execution_requested'] = True
            with SudoSession(out=work / 'sudo-session.json'):
                if args.suite == 'all':
                    for p in btroot.rglob('*'):
                        if p.is_file() and '__pycache__' not in p.parts: guards[p] = digest(p)
                    olddef = read(btroot / 'cases.json'); oldbinary = work / 'legacy-target.elf'
                    continuation.materialize(driver.materialize_legacy, olddef, oldbinary, preserve=bool(args.resume_work))
                    btcorpus = load('accepted_bt32_corpus', btroot / 'corpus.py')
                    reference, record['legacy_oracle'] = btcorpus.legacy_oracle(continuation.oracle_directory(work / 'legacy-oracle', bool(args.resume_work)), olddef['cases'], 'gcc')
                    driver.regressions(api, olddef, oldbinary, work, params, reference, record, admission)
                for row in definition['cases']:
                    admission(); folder = ROOT / row['data']; expected = read(folder / 'expected.json')
                    dest = work / 'div32' / row['id']; dest.mkdir(parents=True, exist_ok=bool(args.resume_work))
                    arguments = dict(params, binary=binaries[row['id']], seed=folder / 'seed',
                                     branch_pc=row['pc'], offsets=row['offsets'], occurrence=1)
                    result = driver.audited(api, 'invert_file', arguments, dest / 'inversion')
                    solved = read(dest / 'inversion/solve/logs/phase1/concolic.json')
                    observed = read(dest / 'inversion/observe/logs/phase1/concolic.json')
                    seed = (dest / 'inversion/solve/input.bin').read_bytes()
                    candidate = (dest / 'inversion/observe/input.bin').read_bytes()
                    check_inversion(row, expected, result, solved, observed, seed, candidate)
                    for mode in ('solve', 'observe'):
                        raw = (dest / 'inversion' / mode / 'input.bin').read_bytes()
                        stdout = b'F\n' if corpus.model(7, raw) == row['compare_value'] else b'T\n'
                        require((dest / 'inversion' / mode / 'logs/runtime_stdout.log').read_bytes() == stdout,
                                'Fresh DIV32 stdout differs from its Python model')
                    admission()
                    saved = driver.audited(api, 'observe_file', dict(arguments, seed=folder / 'witness'), dest / 'saved-witness')
                    require(saved['dse_status'] == 'OBSERVED', 'Saved DIV32 witness is not observed')
                    check_saved_witness(row, expected, read(dest / 'saved-witness/observe/logs/phase1/concolic.json'))
                    require((dest / 'saved-witness/observe/input.bin').read_bytes() == (folder / 'witness').read_bytes() and
                            (dest / 'saved-witness/observe/logs/runtime_stdout.log').read_bytes() == (folder / 'witness.stdout').read_bytes(),
                            'Saved DIV32 witness input/output differs')
                    record['div32_regressions'].append({'id': row['id'], 'status': 'VERIFIED', 'audit': 'PASS',
                        'saved_witness_reproduced': True, 'fresh_candidate_sha256': result['candidate_sha256'],
                        'fresh_candidate_value': corpus.model(7, candidate)})
                    save(work / 'summary.json', record)
                    print(row['id'] + ': VERIFIED; saved witness PASS', flush=True)
            require(len(record['div32_regressions']) == 3 and len(record['regressions']) == (6 if args.suite == 'all' else 0), 'Regression inventory incomplete')
            record['status'] = 'PASS_BT32_DIV32_REGRESSIONS'; code = 0
    except BaseException as exc:
        code = 130 if isinstance(exc, KeyboardInterrupt) else 1
        record.update(status='INCOMPLETE', error=type(exc).__name__ + ': ' + str(exc))
        (work / 'driver-error.log').write_text(traceback.format_exc()); print(record['error'], file=sys.stderr, flush=True)
    finally:
        if disk_admission is not None:
            try: disk_admission.before_case('suite-exit')
            except Exception as exc:
                code = 1; record.update(status='INCOMPLETE', disk_error=str(exc))
        try: check_guards(guards); record['guarded_inputs_unchanged'] = True
        except Exception as exc: code = 1; record.update(status='INCOMPLETE', guard_error=str(exc))
        for pattern in ('regressions/*/inversion/*/receipt.json', 'regressions/*/saved-witness/observe/receipt.json',
                        'div32/*/inversion/*/receipt.json', 'div32/*/saved-witness/observe/receipt.json'):
            for path in work.glob(pattern):
                try: record['guest_executions_with_completed_receipts'] += read(path).get('status') == 'passed'
                except Exception: code = 1; record['status'] = 'INCOMPLETE'
        expected_count = 27 if args.suite == 'all' else 9
        if record['status'] == 'PASS_BT32_DIV32_REGRESSIONS' and record['guest_executions_with_completed_receipts'] != expected_count:
            code = 1; record.update(status='INCOMPLETE', error='Completed execution receipt count differs')
        save(work / 'summary.json', record); save(work / 'input-inventory.json', {str(p): h for p, h in guards.items()})
        continuation.export_reports(export_reports, work, bool(args.resume_work))
    print(record['status'], flush=True); return code


if __name__ == '__main__': raise SystemExit(main())
