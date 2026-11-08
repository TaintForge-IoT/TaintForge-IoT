"""Permanent six-case BT32 regressions and a bounded 24-ELF coverage corpus."""
import argparse
from collections import Counter
import importlib
import hashlib
import os
from pathlib import Path
import shutil
import sys
import tempfile
import traceback

import corpus
from diagnostics import classify
from support import (MIB, check_guards, check_inversion, check_saved_witness, digest,
                     export_reports, read, ready, require, save, verify_case)

ROOT = Path(__file__).resolve().parent


def materialize_legacy(definition, destination):
    path = ROOT / definition['legacy_binary']['hex_file']
    require(path.is_file() and not path.is_symlink(), 'Import the golden ELF with install.py first')
    raw = bytes.fromhex(path.read_text())
    require(len(raw) == definition['legacy_binary']['size'] and
            hashlib.sha256(raw).hexdigest() == definition['legacy_binary']['sha256'],
            'Golden ELF bytes differ from the accepted six-case target')
    destination.write_bytes(raw); destination.chmod(0o755)
    corpus.elf_view(destination)
    for row in definition['cases']:
        expected = read(ROOT / row['data'] / 'expected.json')
        require(corpus.instruction_bytes(destination, row['pc'], len(expected['branch_bytes']) // 2).hex() ==
                expected['branch_bytes'], 'Golden ELF selected branch differs: ' + row['id'])


def runtime(project, qemu, plugin, flags, guards):
    sys.path.insert(0, str(project)); sys.path.insert(0, str(ROOT))
    for file in (project / 'taintforge_env').rglob('*.py'):
        guards[file] = digest(file)
    api = importlib.import_module('taintforge_env.dse_analysis')
    require(Path(api.__file__).resolve().is_relative_to(project), 'Wrong project module imported')
    unified = importlib.import_module('taintforge_env.unified_runtime')
    checked = unified.check_runtime_inputs(project, qemu=qemu, plugin=plugin)
    manifest = read(Path(str(plugin) + '.runtime.json'))
    for name, expected in manifest['build_inputs']['source_files'].items():
        require(Path(name).name == name, 'Invalid native build input name')
        path = project / 'unpacker/test' / name
        require(digest(path) == expected, 'Plugin is not built from the current core: ' + name)
        guards[path] = expected
    for path in (qemu, plugin, Path(str(plugin) + '.runtime.json'), flags): guards[path] = digest(path)
    return api, checked


def audited(api, kind, params, destination):
    hook = _continuation()
    cached = hook.cached(api, kind, params, destination)
    if cached is not None: return cached
    result = getattr(api, kind)(**params, out=destination)
    require(api.audit_file_run(directory=destination) == result, 'Saved execution reconstruction differs')
    hook.completed(api, kind, params, destination, result)
    return result


def regressions(api, definition, binary, work, runtime_args, reference, record, admission):
    for row in definition['cases']:
        admission()
        expected = verify_case(ROOT, row)
        directory = work / 'regressions' / row['id']; directory.mkdir(parents=True, exist_ok=_continuation().is_resuming(work))
        params = dict(runtime_args, binary=binary, seed=ROOT / row['data'] / 'seed',
                      branch_pc=row['pc'], offsets=row['offsets'], occurrence=row['occurrence'])
        inversion = directory / 'inversion'
        result = audited(api, 'invert_file', params, inversion)
        require(result['dse_status'] == 'VERIFIED', 'Regression inversion failed: ' + row['id'])
        solved = read(inversion / 'solve/logs/phase1/concolic.json')
        observed = read(inversion / 'observe/logs/phase1/concolic.json')
        check_inversion(row, expected, result, solved, observed,
                        (inversion / 'solve/input.bin').read_bytes(), (inversion / 'observe/input.bin').read_bytes())
        for mode in ('solve', 'observe'):
            raw = (inversion / mode / 'input.bin').read_bytes()
            require((inversion / mode / 'logs/runtime_stdout.log').read_bytes() == reference(raw),
                    'Fresh jsmn output differs from the pinned native oracle')
        admission()
        known = directory / 'saved-witness'
        known_params = dict(params, seed=ROOT / row['data'] / 'witness')
        known_result = audited(api, 'observe_file', known_params, known)
        require(known_result['dse_status'] == 'OBSERVED', 'Saved witness is no longer observed')
        require((known / 'observe/input.bin').read_bytes() == (ROOT / row['data'] / 'witness').read_bytes(),
                'Saved witness input binding changed')
        native = read(known / 'observe/logs/phase1/concolic.json')
        check_saved_witness(row, expected, native)
        require((known / 'observe/logs/runtime_stdout.log').read_bytes() ==
                (ROOT / row['data'] / 'witness.stdout').read_bytes(), 'Saved witness output changed')
        record['regressions'].append({'id': row['id'], 'pc': row['pc'], 'status': 'VERIFIED',
            'fresh_candidate_sha256': result['candidate_sha256'], 'saved_witness_reproduced': True,
            'native_oracle_outputs_match': True, 'prefix_route_preserved': True,
            'prefix_branches': solved['prefix_branches'], 'audit': 'PASS'})
        save(work / 'summary.json', record)
        print('Regression %s: VERIFIED; saved witness PASS' % row['id'], flush=True)


def coverage(api, probes, work, runtime_args, record, admission):
    for row in probes:
        admission()
        directory = work / 'coverage' / row['id']
        params = dict(runtime_args, binary=Path(row['binary']), seed=Path(row['seed']),
                      branch_pc=row['pc'], offsets=row['offsets'], occurrence=1)
        result = audited(api, 'observe_file', params, directory)
        native = read(directory / 'observe/logs/phase1/concolic.json')
        output = (directory / 'observe/logs/runtime_stdout.log').read_bytes()
        require(output.hex() == row['expected_stdout_hex'], 'Probe stdout differs from its native/Python oracle: ' + row['id'])
        require(result['dse_status'] in ('OBSERVED', 'UNKNOWN'), 'Unexpected probe proof status')
        if result['dse_status'] == 'OBSERVED':
            ready(native)
            require(native['branch_pc'] == row['pc'] and native['taken'] == row['expected_taken'] and
                    native['successor']['pc'] == row['expected_successor'] and
                    native['trace'][-1]['instruction']['bytes'] == row['branch_bytes'],
                    'Probe observation differs from its branch/ELF/oracle identity')
        record['coverage'].append({**row, 'status': result['dse_status'], 'audit': 'PASS',
            'stdout_matches_oracle': True, 'diagnostic': classify(native)})
        save(work / 'summary.json', record)
        print('Coverage %s: %s' % (row['id'], result['dse_status']), flush=True)


def rank_stops(rows):
    grouped = {}
    for row in rows:
        diagnostic = row['diagnostic']
        if row['status'] != 'UNKNOWN' or diagnostic['bucket'] != 'unsupported_instruction': continue
        stop = diagnostic['replay_build']['stopped_origin']
        values = grouped.setdefault(stop['bytes'], [])
        values.append({'id': row['id'], 'binary_sha256': row['binary_sha256'], 'pc': stop['pc'], 'seq': stop['seq']})
    return sorted([{'bytes': code, 'affected_elf_count': len(values), 'cases': values}
                   for code, values in grouped.items()], key=lambda r: (-r['affected_elf_count'], r['bytes']))


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
    parser.add_argument('--suite', choices=('regression', 'coverage', 'all'), default='all')
    parser.add_argument('--offline-only', action='store_true')
    parser.add_argument('--cc', default='gcc')
    parser.add_argument('--resume-work', type=Path)
    args = parser.parse_args(argv)
    parent = args.output_dir.expanduser().resolve(strict=True)
    require(parent.is_dir() and not parent.is_relative_to(ROOT), 'Choose an output directory outside the suite')
    if not args.offline_only:
        require(all((args.project, args.qemu, args.plugin, args.flags_receipt)), 'Specify project, QEMU, plugin and flags receipt')
        args.project = args.project.expanduser().resolve(strict=True)
        require(not parent.is_relative_to(args.project), 'Keep run output outside the project')
    continuation = _continuation()
    work = continuation.work_directory(args.resume_work, parent, 'tfreg.')
    print('Regression/coverage run: ' + str(work), flush=True)
    guards = {p: digest(p) for p in ROOT.rglob('*') if p.is_file() and '__pycache__' not in p.parts}
    record = {'schema': 1, 'profile': 'bt32-portable-regression-corpus-v1', 'status': 'INCOMPLETE',
        'regressions': [], 'coverage': [], 'suite': args.suite, 'guest_execution_requested': False,
        'guest_executions_with_completed_receipts': 0, 'afl_campaign_executed': False,
        'universal_equivalence': False, 'successor_execution_proven': False,
        'scope': 'six accepted fixed-ELF cases plus eight bounded kernels at three optimization levels',
        'budgets': {'case_seconds': 30, 'memory_mib': 1024, 'max_steps': 1024,
                    'reserve_mib': 4096, 'growth_admission_mib': 12288},
        'disk_scope': 'admission before each inversion or observation; not a filesystem quota'}
    code = 0
    disk_admission = None
    try:
        definition = read(ROOT / 'cases.json')
        for row in definition['cases']: verify_case(ROOT, row)
        save(work / 'suite-definition.json', definition)
        for row in definition['cases']:
            snapshot = work / 'definition' / row['id']; snapshot.mkdir(parents=True, exist_ok=bool(args.resume_work))
            continuation.copyfile(ROOT / row['data'] / 'expected.json', snapshot / 'expected.json', preserve=bool(args.resume_work))
            for label in ('seed', 'witness'):
                case = snapshot / label; case.mkdir(exist_ok=bool(args.resume_work))
                continuation.copyfile(ROOT / row['data'] / label, case / 'input.bin', preserve=bool(args.resume_work))
                continuation.copyfile(ROOT / row['data'] / (label + '.stdout'), case / 'stdout.log', preserve=bool(args.resume_work))
        reference = None; probes = []
        if args.suite in ('regression', 'all'):
            reference, oracle_record = corpus.legacy_oracle(continuation.oracle_directory(work / 'legacy-oracle', bool(args.resume_work)), definition['cases'], args.cc)
            record['legacy_oracle'] = oracle_record
        if args.suite in ('coverage', 'all'):
            built = corpus.build(work / 'corpus-build', args.cc)
            probes = built['cases']; record['corpus_build'] = {k: v for k, v in built.items() if k not in ('cases', 'commands')}
        if args.offline_only:
            record.update(status='OFFLINE_PASS_GUESTS_NOT_RUN', legacy_elf_imported=(ROOT / definition['legacy_binary']['hex_file']).is_file())
        else:
            require(os.getuid() != 0 and os.geteuid() != 0, 'Run as the original non-root user')
            qemu, plugin, flags = (p.expanduser().resolve(strict=True) for p in (args.qemu, args.plugin, args.flags_receipt))
            api, runtime_record = runtime(args.project, qemu, plugin, flags, guards)
            record['runtime'] = runtime_record
            sys.path.insert(0, str(ROOT.parent / 'shared_storage'))
            from regression_disk import Admission
            disk_admission = Admission(work)
            record['storage_initial'] = disk_admission.value['initial']
            def admission():
                disk_admission.before_case('next-api-request-or-legacy-run')
            params = dict(qemu=qemu, plugin=plugin, flags_receipt=flags, input_path=definition['input_path'],
                          max_steps=1024, seconds=30, memory_mib=1024, argv=[])
            from sudo_session import SudoSession
            record['guest_execution_requested'] = True
            with SudoSession(out=work / 'sudo-session.json'):
                if args.suite in ('regression', 'all'):
                    binary = work / 'legacy-target.elf'; continuation.materialize(materialize_legacy, definition, binary, preserve=bool(args.resume_work))
                    regressions(api, definition, binary, work, params, reference, record, admission)
                if args.suite in ('coverage', 'all'):
                    coverage(api, probes, work, params, record, admission)
            require(len(record['regressions']) == (len(definition['cases']) if args.suite in ('regression', 'all') else 0), 'Regression inventory incomplete')
            require(len(record['coverage']) == len(probes), 'Coverage inventory incomplete')
            record['coverage_status_counts'] = dict(Counter(r['status'] for r in record['coverage']))
            record['ranked_unsupported_encodings'] = rank_stops(record['coverage'])
            record['ranking_scope'] = 'encoding groups across distinct ELF identities, explicit native stopped_origin only'
            record['status'] = ('COMPLETED_WITH_COVERAGE_FINDINGS' if any(r['status'] == 'UNKNOWN' for r in record['coverage']) else 'PASS_BT32_REGRESSION_AND_COVERAGE')
    except BaseException as exc:
        code = 130 if isinstance(exc, KeyboardInterrupt) else 1
        record.update(status='INCOMPLETE', error=type(exc).__name__ + ': ' + str(exc))
        (work / 'driver-error.log').write_text(traceback.format_exc())
        print(record['error'], file=sys.stderr, flush=True)
    finally:
        if disk_admission is not None:
            try: disk_admission.before_case('suite-exit')
            except Exception as exc:
                code = 1; record.update(status='INCOMPLETE', disk_error=str(exc))
        try:
            check_guards(guards); record['guarded_inputs_unchanged'] = True
        except Exception as exc:
            code = 1; record.update(status='INCOMPLETE', guarded_inputs_unchanged=False, final_guard_error=str(exc))
        receipt_paths = [p for pattern in ('regressions/*/inversion/*/receipt.json',
            'regressions/*/saved-witness/observe/receipt.json', 'coverage/*/observe/receipt.json')
            for p in work.glob(pattern)]
        for path in receipt_paths:
            if path.is_file() and not path.is_symlink():
                try: record['guest_executions_with_completed_receipts'] += read(path).get('status') == 'passed'
                except Exception: code = 1; record['status'] = 'INCOMPLETE'
        save(work / 'input-inventory.json', {str(p): v for p, v in guards.items()})
        save(work / 'summary.json', record); continuation.export_reports(export_reports, work, bool(args.resume_work))
    print(record['status'], flush=True)
    print('Regressions VERIFIED: %d; coverage observations: %d' % (len(record['regressions']), len(record['coverage'])), flush=True)
    return code


if __name__ == '__main__':
    raise SystemExit(main())
