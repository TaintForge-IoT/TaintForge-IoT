"""Permanent BSF/BSR cases, saved witnesses and secondary corpus observations."""
import argparse
import hashlib
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import traceback

import probes
from support import (check_guards, check_inversion, check_saved_witness, digest,
                     export_reports, read, ready, require, route, save)

ROOT = Path(__file__).resolve().parent
MIB = 1024 ** 2


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def stdout_model(row, raw):
    value = probes.model(row['kind'], raw)
    return (b'F\n' if value == row['compare_value'] else b'T\n') + value.to_bytes(4, 'little')


def verify_cases():
    definition = read(ROOT / 'cases.json')
    require(definition['profile'] == 'bitscan32-fixed-elf-regressions-v1' and len(definition['cases']) == 6,
            'Expected six BSF/BSR cases')
    require({(r['kernel'], r['optimization']) for r in definition['cases']} ==
            {(k, o) for k in ('clz32', 'ctz32') for o in ('O1', 'O2', 'O3')}, 'Bit-scan fixture inventory differs')
    for row in definition['cases']:
        folder = ROOT / row['data']; require(folder.resolve().is_relative_to(ROOT), 'Invalid fixture path')
        for key, name in [('seed','seed'), ('witness','witness'), ('secondary','secondary'), ('expected','expected.json'),
                          ('elf_hex','elf.hex'), ('seed_stdout','seed.stdout'), ('witness_stdout','witness.stdout'),
                          ('secondary_stdout','secondary.stdout')]:
            require(digest(folder / name) == row[key + '_sha256'], 'Fixture changed: ' + row['id'] + '/' + name)
        seed, witness, secondary = ((folder / n).read_bytes() for n in ('seed', 'witness', 'secondary'))
        changes = [i for i, (a, b) in enumerate(zip(seed, witness)) if a != b]
        require(len(seed) == len(witness) == len(secondary) == 4 and changes == row['changed_offsets'] and
                changes and set(changes) <= set(row['offsets']) and secondary != seed,
                'Invalid bit-scan witness or secondary input')
        expected = read(folder / 'expected.json')
        require(expected['branch_pc'] == row['pc'] and expected['branch_bytes'] == row['branch_bytes'] and
                expected['baseline_route'][:-1] == expected['witness_route'][:-1] and
                expected['baseline_taken'] is False and expected['witness_taken'] is True,
                'Saved selected branch or prefix differs')
        for name in ('seed', 'witness', 'secondary'):
            raw = (folder / name).read_bytes()
            require(probes.model(row['kind'], raw) == row['expected_' + name + '_value'] and
                    (folder / (name + '.stdout')).read_bytes() == stdout_model(row, raw),
                    'Saved bit-scan input/output differs from the independent model')
        require(row['expected_seed_value'] == row['compare_value'] != row['expected_witness_value'], 'Saved witness does not invert the comparison')
    return definition


def materialize(row, output):
    raw = bytes.fromhex((ROOT / row['data'] / 'elf.hex').read_text())
    require(hashlib.sha256(raw).hexdigest() == row['elf_sha256'], 'Fixed bit-scan ELF differs')
    output.write_bytes(raw); output.chmod(0o755); probes.elf_view(output)
    require(probes.instruction_bytes(output, row['pc'], len(row['branch_bytes']) // 2).hex() == row['branch_bytes'],
            'Selected branch bytes differ from the fixed ELF')


def secondary_check(row, expected, native):
    ready(native)
    require(native['status'] == 'OBSERVED' and native['branch_pc'] == row['pc'] and
            native['taken'] == expected['secondary_taken'] and route(native) == expected['secondary_route'] and
            native['successor']['pc'] == expected['secondary_successor'], 'Secondary bit-scan observation differs')


def legacy_result(work):
    paths = list((work / 'older-regressions').glob('tfsignedreg.*/summary.json'))
    require(len(paths) == 1, 'Legacy regression run identity is ambiguous')
    return paths[0], read(paths[0])


def receipt_paths(work):
    child = 'older-regressions/tfsignedreg.*/'
    nested = child + 'older-regressions/tfdivreg.*/'
    patterns = ['bitscan32/*/inversion/*/receipt.json', 'bitscan32/*/saved-witness/observe/receipt.json',
        'bitscan32/*/secondary/observe/receipt.json', child + 'signed-div32/*/inversion/*/receipt.json',
        child + 'signed-div32/*/saved-witness/observe/receipt.json', child + 'signed-div32/*/negative-divisor/observe/receipt.json',
        nested + 'regressions/*/inversion/*/receipt.json', nested + 'regressions/*/saved-witness/observe/receipt.json',
        nested + 'div32/*/inversion/*/receipt.json', nested + 'div32/*/saved-witness/observe/receipt.json']
    return sorted({p for pattern in patterns for p in work.glob(pattern)})


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
    parser.add_argument('--offline-only', action='store_true')
    parser.add_argument('--resume-work', type=Path)
    args = parser.parse_args(argv)
    parent = args.output_dir.expanduser().resolve(strict=True)
    require(not parent.is_relative_to(ROOT), 'Keep output outside the regression directory')
    project = args.project.expanduser().resolve(strict=True) if args.project else None
    if not args.offline_only:
        require(project and args.qemu and args.plugin and args.flags_receipt, 'Specify project, QEMU, plugin and flags receipt')
        require(not parent.is_relative_to(project), 'Keep output outside the project')
    continuation = _continuation()
    work = continuation.work_directory(args.resume_work, parent, 'tfscanreg.')
    print('Permanent BITSCAN32 regression run: ' + str(work), flush=True)
    guards = {p: digest(p) for p in ROOT.rglob('*') if p.is_file() and '__pycache__' not in p.parts}
    record = {'status': 'INCOMPLETE', 'profile': 'bt32-div32-signed-div32-bitscan32-permanent-regressions-v1',
        'bitscan32_regressions': [], 'secondary_observations': [],
        'guest_execution_requested': False, 'guest_executions_with_completed_receipts': 0,
        'afl_campaign_executed': False, 'universal_equivalence': False, 'successor_execution_proven': False,
        'scope': '21 BT32/DIV32/signed-DIV32/BSF/BSR inversions with saved witnesses and 12 secondary observations'}
    code = 1
    disk_admission = None
    try:
        definition = verify_cases(); save(work / 'suite-definition.json', definition)
        binaries = {}
        for row in definition['cases']:
            binary = work / (row['id'] + '.elf'); continuation.materialize(materialize, row, binary, preserve=bool(args.resume_work)); binaries[row['id']] = binary
            folder = work / 'definition' / row['id']; folder.mkdir(parents=True, exist_ok=bool(args.resume_work))
            for name in ('seed', 'witness', 'secondary', 'expected.json', 'seed.stdout', 'witness.stdout', 'secondary.stdout'):
                continuation.copyfile(ROOT / row['data'] / name, folder / name, preserve=bool(args.resume_work))
        if args.offline_only:
            record.update(status='OFFLINE_PASS_GUESTS_NOT_RUN', fixed_elf_cases=6, secondary_inputs=6); code = 0
        else:
            require(os.getuid() != 0 and os.geteuid() != 0, 'Run as the original non-root user')
            sys.dont_write_bytecode = True; btroot = ROOT.parent / 'bt32'; previous_root = ROOT.parent / 'signed_div32'
            for root in (btroot, ROOT.parent / 'div32', previous_root):
                require(root.is_dir() and not root.is_symlink(), 'Previous permanent suite missing')
                for p in root.rglob('*'):
                    if p.is_file() and '__pycache__' not in p.parts: guards[p] = digest(p)
            sys.path.append(str(btroot))
            driver = load('accepted_bt32_runtime', btroot / 'run.py')
            api, runtime = driver.runtime(project, args.qemu.resolve(), args.plugin.resolve(), args.flags_receipt.resolve(), guards)
            from sudo_session import SudoSession
            record['runtime_preflight'] = runtime
            for name, module in tuple(sys.modules.items()):
                path = getattr(module, '__file__', None)
                if path and name.split('.')[0] in ('taintforge_env', 'experiments', 'scripts'):
                    path = Path(path).resolve(); require(path.is_relative_to(project), 'Foreign project module imported')
                    require(path not in guards or guards[path] == digest(path), 'Project changed during import'); guards[path] = digest(path)
            sys.path.insert(0, str(ROOT.parent / 'shared_storage'))
            from regression_disk import Admission
            disk_admission = Admission(work)
            record['storage_initial'] = disk_admission.value['initial']
            def admission():
                disk_admission.before_case('next-api-request-or-legacy-run')
            params = dict(qemu=args.qemu.resolve(), plugin=args.plugin.resolve(), flags_receipt=args.flags_receipt.resolve(),
                input_path=definition['input_path'], max_steps=1024, seconds=30, memory_mib=1024, argv=[])
            record['guest_execution_requested'] = True
            with SudoSession(out=work / 'sudo-session.json'):
                older = work / 'older-regressions'; older.mkdir(exist_ok=bool(args.resume_work)); admission()
                with (work / 'older-regressions.log').open('wb') as log:
                    completed = subprocess.run((list(map(str, [sys.executable, '-B', previous_root / 'run.py', '--project', project,
                        '--qemu', args.qemu.resolve(), '--plugin', args.plugin.resolve(), '--flags-receipt', args.flags_receipt.resolve(),
                        '--output-dir', older]))) + continuation.child_arguments(older, bool(args.resume_work)), stdout=log, stderr=subprocess.STDOUT)
                require(completed.returncode == 0, 'Previous regressions failed; see ' + str(work / 'older-regressions.log') + '\n' + (work / 'older-regressions.log').read_text(errors='replace')[-4000:])
                previous_path, previous = legacy_result(work)
                require(previous['status'] == 'PASS_BT32_DIV32_SIGNED_DIV32_REGRESSIONS' and
                        previous['guest_executions_with_completed_receipts'] == 51, 'Previous regression acceptance failed')
                record.update(legacy_regressions=str(previous_path), bt32_verified=6, div32_verified=3, signed_div32_verified=6, negative_divisor_observations=6)
                print('BT32/DIV32/IDIV32: 15 VERIFIED; saved witnesses and negative divisors PASS', flush=True)
                for row in definition['cases']:
                    admission(); folder = ROOT / row['data']; expected = read(folder / 'expected.json')
                    dest = work / 'bitscan32' / row['id']; dest.mkdir(parents=True, exist_ok=bool(args.resume_work))
                    arguments = dict(params, binary=binaries[row['id']], seed=folder / 'seed',
                                     branch_pc=row['pc'], offsets=row['offsets'], occurrence=1)
                    result = driver.audited(api, 'invert_file', arguments, dest / 'inversion')
                    solved = read(dest / 'inversion/solve/logs/phase1/concolic.json')
                    observed = read(dest / 'inversion/observe/logs/phase1/concolic.json')
                    seed = (dest / 'inversion/solve/input.bin').read_bytes(); candidate = (dest / 'inversion/observe/input.bin').read_bytes()
                    check_inversion(row, expected, result, solved, observed, seed, candidate)
                    for mode in ('solve', 'observe'):
                        raw = (dest / 'inversion' / mode / 'input.bin').read_bytes()
                        require((dest / 'inversion' / mode / 'logs/runtime_stdout.log').read_bytes() == stdout_model(row, raw),
                                'Fresh bit-scan numeric output differs from Python model')
                    for name in ('witness', 'secondary'):
                        admission(); destination = dest / ('saved-witness' if name == 'witness' else 'secondary')
                        checked = driver.audited(api, 'observe_file', dict(arguments, seed=folder / name), destination)
                        native = read(destination / 'observe/logs/phase1/concolic.json')
                        require(checked['dse_status'] == 'OBSERVED', 'Saved input is not observed')
                        if name == 'witness': check_saved_witness(row, expected, native)
                        else: secondary_check(row, expected, native)
                        require((destination / 'observe/input.bin').read_bytes() == (folder / name).read_bytes() and
                                (destination / 'observe/logs/runtime_stdout.log').read_bytes() == (folder / (name + '.stdout')).read_bytes(),
                                'Saved input/output differs')
                    record['bitscan32_regressions'].append({'id': row['id'], 'status': 'VERIFIED', 'audit': 'PASS',
                        'saved_witness_reproduced': True, 'fresh_candidate_sha256': result['candidate_sha256'],
                        'fresh_candidate_uint32': probes.model(row['kind'], candidate)})
                    record['secondary_observations'].append({'id': row['id'], 'status': 'OBSERVED', 'audit': 'PASS'})
                    save(work / 'summary.json', record); print(row['id'] + ': VERIFIED; saved witness and secondary input PASS', flush=True)
            require(len(record['bitscan32_regressions']) == len(record['secondary_observations']) == 6, 'Bit-scan regression inventory incomplete')
            record['status'] = 'PASS_BT32_DIV32_SIGNED_DIV32_BITSCAN32_REGRESSIONS'; code = 0
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
        for path in receipt_paths(work):
            try: record['guest_executions_with_completed_receipts'] += read(path).get('status') == 'passed'
            except Exception: code = 1; record['status'] = 'INCOMPLETE'
        if record['status'] == 'PASS_BT32_DIV32_SIGNED_DIV32_BITSCAN32_REGRESSIONS' and record['guest_executions_with_completed_receipts'] != 75:
            code = 1; record.update(status='INCOMPLETE', error='Expected exactly 75 completed execution receipts')
        save(work / 'summary.json', record); save(work / 'input-inventory.json', {str(p): h for p, h in guards.items()})
        continuation.export_reports(export_reports, work, bool(args.resume_work))
    print(record['status'], flush=True); return code


if __name__ == '__main__': raise SystemExit(main())
