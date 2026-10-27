#!/usr/bin/env python3
"""Measure external ELF reconstruction, behavior and selected-execution proof."""
import argparse
import base64
import csv
import hashlib
import json
import math
import os
from pathlib import Path
import re
import sys
import tempfile

try:
    from .external_process import run_phase
    from .external_diagnostics import diagnose
    from .unpack_process import validate_cases
except ImportError:
    from external_process import run_phase
    from external_diagnostics import diagnose
    from unpack_process import validate_cases


ROOT = Path(__file__).resolve().parent
WORKER = ROOT / 'external_worker.py'
# Match the existing native producer writer and generic SMT raw-ledger bounds.
MAX_PRODUCER_NODES = 268435456
ID = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,95}\Z')
PROOF_STATUS = 'SMT_PROVED_SELECTED_TRANSFER_AND_OBSERVED_IMAGE_UNDER_EXPLICIT_PREMISES'
WORKER_PASS = dict(capture='PASS_CAPTURE_AND_SMOKE',
    baseline='PASS_ORIGINAL_PACKED_BASELINE',
    reference='PASS_REFERENCE_ENTRY_AND_CODE_MATCH',
    behavior='PASS_SELECTED_BEHAVIOR_EQUIVALENCE',
    proof='PASS_AUDITED_SELECTED_EXECUTION_PROOF',
    **{'build-plugin': 'PASS_PLUGIN_BUILD', 'build-native': 'PASS_NATIVE_BUILD_AND_FLAGS'})
PROOF_SCOPE = dict(profile='TFOEPGEN1', selected_target_PC_only=True,
    fresh_original_entry_run=True, proof_stdin_empty=True, proof_argv_empty=True,
    identical_to_behavior_execution_established=False, kernel_contracts_explicit=True,
    historical_originality_proven=False, universal_equivalence=False)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def proof_file_limit_mib(max_producer_nodes):
    """Keep the raw ledger's 16-byte header inside its per-file byte limit."""
    require(type(max_producer_nodes) is int and 1 <= max_producer_nodes <= MAX_PRODUCER_NODES,
            'External producer budget is invalid')
    raw_bytes = 16 + 32 * max_producer_nodes
    return max(2048, (raw_bytes + 1024**2 - 1) // 1024**2)


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def strict_json(path, maximum=16*1024**2):
    path = Path(path)
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= maximum,
            'Missing, symlink or oversized JSON: '+str(path))
    def unique(items):
        result = {}
        for key, value in items:
            require(key not in result, 'Duplicate JSON key: '+key)
            result[key] = value
        return result
    def invalid(value):
        raise ValueError('Nonfinite JSON number: '+value)
    def floating(value):
        result=float(value)
        require(math.isfinite(result),'Nonfinite JSON number: '+value)
        return result
    raw = path.read_bytes()
    require(len(raw) <= maximum, 'JSON grew beyond its byte budget')
    return json.loads(raw, object_pairs_hook=unique, parse_constant=invalid, parse_float=floating)


def safe_file(root, relative, maximum):
    require(type(relative) is str and relative and '\\' not in relative,
            'Corpus path must be a nonempty relative POSIX path')
    rel = Path(relative)
    require(not rel.is_absolute() and '..' not in rel.parts and str(rel) == relative,
            'Corpus path escapes its manifest directory')
    path = root
    for part in rel.parts:
        path /= part
        require(not path.is_symlink(), 'Corpus path contains a symlink')
    require(path.is_file() and 0 < path.stat().st_size <= maximum,
            'Missing or oversized corpus file: '+relative)
    return path


def load_corpus(manifest):
    manifest = Path(manifest).absolute()
    require(not manifest.is_symlink(), 'Corpus manifest must not be a symlink')
    root = manifest.parent.resolve(strict=True)
    document = strict_json(manifest, 4*1024**2)
    require(type(document) is dict and type(document.get('schema_version')) is int and
            document['schema_version'] == 1 and document.get('corpus_kind') == 'upstream_static_i386_UPX',
            'Unsupported external corpus schema')
    samples = document.get('samples')
    require(type(samples) is list and 0 < len(samples) <= 64, 'External sample inventory bound')
    rows, names, pins, total = [], set(), {str(manifest): digest(manifest)}, 0
    for sample in samples:
        require(type(sample) is dict and type(sample.get('id')) is str and
                ID.fullmatch(sample['id']) and sample['id'] not in names,
                'External sample IDs must be unique simple names')
        names.add(sample['id'])
        require(sample.get('program') in ('xxhsum', 'bzip2') and
                sample.get('packing') in ('default', 'lzma'), 'Unrecognized upstream sample profile')
        row = dict(sample)
        for key in ('original', 'packed', 'cases', 'build_receipt', 'pack_receipt', 'prepack'):
            limit = 16*1024**2 if key in ('original', 'packed', 'cases') else 4*1024**2
            path = safe_file(root, sample.get(key), limit)
            row[key] = str(path)
            if str(path) not in pins:
                total += path.stat().st_size
                require(total <= 128*1024**2, 'External corpus input byte budget')
                pins[str(path)] = digest(path)
        for key in ('original', 'packed'):
            wanted = sample.get(key+'_sha256')
            require(type(wanted) is str and re.fullmatch('[0-9a-f]{64}', wanted) and
                    pins[row[key]] == wanted, 'External '+key+' bytes differ from manifest')
        cases = validate_cases(strict_json(row['cases']))
        require(sample.get('cases_sha256') == pins[row['cases']], 'External cases differ from manifest')
        row['case_count'] = len(cases)
        # Packing receipts bind the independently built original before UPX.
        receipt = strict_json(row['pack_receipt'], 4*1024**2)
        require(type(receipt) is dict and receipt.get('original_sha256') == sample['original_sha256'] and
                receipt.get('packed_sha256') == sample['packed_sha256'] and
                receipt.get('original_unchanged') is True and receipt.get('upx_test_succeeded') is True and
                receipt.get('prepack_sha256') == pins[row['prepack']],
                'External packing lineage is not bound to original and packed bytes')
        prepack = strict_json(row['prepack'],4*1024**2)
        require(type(prepack) is dict and prepack.get('original_sha256') == sample['original_sha256'] and
                prepack.get('recorded_before_packer_invocation') is True and
                prepack.get('build_receipt_sha256') == pins[row['build_receipt']] and
                prepack.get('program') == sample['program'] and prepack.get('packing') == sample['packing'],
                'Missing independently recorded pre-pack original identity')
        built = strict_json(row['build_receipt'],4*1024**2)
        require(type(built) is dict and built.get('original_sha256') == sample['original_sha256'] and
                built.get('original_built_before_packing') is True and
                built.get('upstream_standalone_CLI') is True and
                built.get('source_edited_before_build') is False and
                built.get('original_supplies_unpacking_or_SMT_state') is False and
                built.get('cases_sha256') == pins[row['cases']] and
                prepack.get('source_archive_sha256') == built.get('source_archive_sha256'),
                'Independent upstream build provenance or case identity differs')
        rows.append(row)
    return document, rows, pins


def check_pins(pins):
    for name, wanted in pins.items():
        path = Path(name)
        require(path.is_file() and not path.is_symlink() and digest(path) == wanted,
                'Pinned external input/runtime/source changed: '+name)


def save(path, data):
    path = Path(path)
    encoded = (json.dumps(data, indent=2, sort_keys=True, allow_nan=False)+'\n').encode()
    fd, temporary = tempfile.mkstemp(prefix=path.name+'.', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(encoded); stream.flush(); os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def _positive(phase, output, measurement):
    """A process exit or a printed PASS is insufficient to accept a phase."""
    require(measurement.get('returncode') == 0 and
            all(measurement.get(k) is False for k in
                ('timed_out', 'rss_limit_hit', 'file_limit_hit', 'cpu_limit_hit')),
            'Phase process did not complete within its explicit budgets')
    row = strict_json(output/'worker-summary.json')
    require(type(row) is dict and row.get('phase') == phase and row.get('success') is True and
            row.get('status') == WORKER_PASS[phase] and row.get('errors') == [],
            'Phase has no complete successful worker receipt')
    return row


def _capture_view(directory, packed_sha256):
    try:
        from .mvp import ct_elf
    except ImportError:
        from mvp import ct_elf
    packed = safe_file(directory,'inputs/packed.elf',16*1024**2)
    require(digest(packed) == packed_sha256, 'Selected capture belongs to another packed ELF')
    report_path,dump_path = directory/'capture/unpacked.json',directory/'capture/unpacked.bin'
    expected = strict_json(report_path,4*1024**2)
    report,_ = ct_elf.load_capture(report_path,dump_path)
    require(report == expected and report.get('main_image_verified') is True and
            report.get('capture_method') == 'candidate_entry_before_instruction' and
            report.get('capture_scope') == 'tracked_program_pages',
            'Require a validated production candidate-entry capture')
    target = ct_elf.integer(report['oep'],'candidate entry')
    history = report.get('observed_stage_candidates', [])
    repeated = sum(type(n) is dict and n.get('address') == target for n in history) > 1
    return dict(status='VALIDATED_AUTOMATIC_SELECTION', target=target,
        packed_sha256=packed_sha256, repeated_target_in_stage_history=repeated,
        report_sha256=digest(report_path), dump_sha256=digest(dump_path))


def _proof_view(directory, worker, packed_sha256, target):
    proof = strict_json(directory/'summary.json')
    audit = strict_json(directory/'receipt-audit.json')
    require(proof.get('status') == PROOF_STATUS and proof.get('selected_execution_proved') is True and
            proof.get('packed_sha256') == packed_sha256 and proof.get('target') == target and
            audit.get('status') == 'GENERIC_SELECTED_EXECUTION_RECEIPTS_AUDITED' and
            audit.get('packed_sha256') == packed_sha256 and audit.get('target') == target and
            worker.get('packed_sha256') == packed_sha256 and worker.get('target') == target and
            worker.get('receipt_audit_sha256') == digest(directory/'receipt-audit.json'),
            'Successful external proof is not bound to the selected input and complete receipts')
    hashed = audit.get('audited_file_sha256')
    require(type(hashed) is dict and hashed, 'External proof lacks audited file identities')
    for relative, wanted in hashed.items():
        require(type(wanted) is str and re.fullmatch('[0-9a-f]{64}',wanted), 'Invalid audited file identity')
        path = safe_file(directory,relative,2048*1024**2)
        require(digest(path) == wanted, 'Audited proof file changed: '+relative)
    return {k: proof.get(k) for k in ('instructions','producer_nodes','schedule_producer_nodes',
        'schedule_condition_count','SMT_solver_checks','consumed_initial_stack_bytes')}


def _trace_view(qemu, sample, case, first_case, timeout, rss_limit_mib):
    """An independent raw syscall observation supplies diagnostics, not proof."""
    work=case/'trace-work';work.mkdir()
    stdin=case/'trace-stdin.bin'
    stdin.write_bytes(base64.b64decode(first_case['stdin_base64'],validate=True))
    for name,data in first_case['files'].items():
        (work/name).write_bytes(base64.b64decode(data,validate=True))
    executable=case/'trace-packed.elf'
    executable.write_bytes(Path(sample['packed']).read_bytes());executable.chmod(0o700)
    require(digest(executable)==sample['packed_sha256'],'Raw syscall trace input copy differs')
    trace=run_phase([str(qemu),'-strace','-0','target.elf',str(executable),*first_case['argv']],
        case/'process/syscall-trace',cwd=work,stdin_path=stdin,timeout=timeout,
        rss_limit_mib=rss_limit_mib,address_space_mib=max(8192,rss_limit_mib*2),file_limit_mib=16)
    path=case/'process/syscall-trace/stderr'
    parsed=path.stat().st_size<=1024**2
    text=path.read_text(errors='replace') if parsed else ''
    return dict(measurement=trace,trace_sha256=digest(path),trace_parsed_within_budget=parsed,
        packed_execution_copy_sha256=digest(executable),packed_execution_mode='0700',
        observed_memfd_flags=[int(v) for v in re.findall(r'memfd_create\([^,\n]+,(\d+),',text)],
        MAP_SHARED_lines=[line for line in text.splitlines() if 'MAP_SHARED' in line][:32],
        independent_run=True,kernel_effects_proved=False,selected_case=first_case['id'])


def evaluate(manifest, output, *, qemu, qemu_include, guest_timeout=30,
             capture_timeout=180, behavior_timeout=600, proof_timeout=900,
             rss_limit_mib=4096, max_producer_nodes=32000000, samples=None):
    proof_file_limit = proof_file_limit_mib(max_producer_nodes)
    _, corpus, pins = load_corpus(manifest)
    requested = set(samples or [row['id'] for row in corpus])
    require(requested and requested <= {row['id'] for row in corpus}, 'Unknown or empty external sample selection')
    corpus = [row for row in corpus if row['id'] in requested]
    require(type(guest_timeout) in (int,float) and math.isfinite(guest_timeout) and
            0 < guest_timeout <= 300,'Guest timeout must be finite and <=300 seconds')
    for value in (capture_timeout, behavior_timeout, proof_timeout):
        require(type(value) in (int, float) and math.isfinite(value) and 0 < value <= 3600,
                'External phase time budget must be finite and <=3600 seconds')
    require(type(rss_limit_mib) is int and 128 <= rss_limit_mib <= 32768 and
            type(max_producer_nodes) is int and 1 <= max_producer_nodes <= MAX_PRODUCER_NODES,
            'External memory or producer budget is invalid')
    qemu, qemu_include = Path(qemu).resolve(strict=True), Path(qemu_include).resolve(strict=True)
    require(qemu.is_file() and os.access(qemu, os.X_OK) and qemu.stat().st_size <= 512*1024**2 and
            (qemu_include/'qemu-plugin.h').is_file(), 'QEMU executable and matching SDK are required')
    pins.update({str(qemu): digest(qemu), str(qemu_include/'qemu-plugin.h'): digest(qemu_include/'qemu-plugin.h')})
    for path in [*ROOT.glob('external_*.py'), ROOT/'unpack.py', ROOT/'unpack_proof.py',
                 ROOT/'unpack_audit.py', ROOT/'unpack_smt.py', ROOT/'oep_smt.py',
                 ROOT/'oep_schedule.py', ROOT/'mvp/ct_elf.py', ROOT/'rep_callbacks.py',
                 ROOT/'mvp/run_rep_audit.py', ROOT/'mvp/rep_fixtures.py',
                 ROOT/'mvp/fixtures/core_rep32.S']:
        pins[str(path)] = digest(path)
    output = Path(output).absolute()
    require(not output.exists() and not output.is_symlink(), 'External evaluation output must be new')
    require(all(not parent.is_symlink() for parent in (output, *output.parents)),
            'External evaluation output contains a symlink ancestor')
    require(all(not Path(name).is_relative_to(output) and not output.is_relative_to(Path(name))
                for name in pins), 'Evaluation output must be separate from corpus/runtime inputs')
    output.mkdir(parents=True)
    save(output/'input-pins.json', pins)
    result = dict(schema_version=1, status='RUNNING_EXTERNAL_EVALUATION', errors=[],
        corpus_manifest=str(Path(manifest).absolute()), requested_samples=[r['id'] for r in corpus],
        sample_count=len(corpus), completed_samples=0, samples=[], builds={},
        proof_scope=PROOF_SCOPE, all_samples_smt_proved_and_reference_matched=False,
        fuzzing_performed=False, budgets=dict(guest_timeout=guest_timeout,
            capture_timeout=capture_timeout, behavior_timeout=behavior_timeout,
            proof_timeout=proof_timeout, rss_limit_mib=rss_limit_mib,
            max_producer_nodes=max_producer_nodes, proof_file_limit_mib=proof_file_limit),
        memory_metric='Per-phase wait4 max_rss_kib: largest process peak, not simultaneous process-tree peak; '
                      'sampled_group_peak_rss_kib is a separate conservative process-group RSS sample.')

    def phase(name, destination, logdir, extra, timeout):
        command = [sys.executable, '-B', str(WORKER), '--phase', name, '--output', str(destination),
                   '--qemu', str(qemu), '--qemu-include', str(qemu_include),
                   '--guest-timeout', str(guest_timeout), '--guest-rss-mib', str(min(rss_limit_mib,4096)),
                   '--max-producer-nodes', str(max_producer_nodes), *map(str, extra)]
        measurement = run_phase(command, logdir, cwd=ROOT.parent, timeout=timeout,
            rss_limit_mib=rss_limit_mib, address_space_mib=max(8192,rss_limit_mib*2),
            file_limit_mib=proof_file_limit if name == 'proof' else 2048)
        try:
            receipt = _positive(name, destination, measurement)
            return dict(status='PASS', measurement=measurement, receipt=receipt)
        except (OSError, ValueError, KeyError, TypeError) as error:
            diagnosis = diagnose(name, destination, measurement)
            return dict(status='NONPROOF', measurement=measurement, diagnosis=diagnosis,
                        validation_error=str(error))

    try:
        plugin_dir, native_dir = output/'build/plugin', output/'build/native'
        result['builds']['plugin'] = phase('build-plugin', plugin_dir, output/'process/build-plugin', [], 600)
        result['builds']['native'] = phase('build-native', native_dir, output/'process/build-native', [], 600)
        plugin = plugin_dir/'libtaintforge_ir.so'
        for sample in corpus:
            check_pins(pins)
            case = output/'samples'/sample['id'];case.mkdir(parents=True)
            row = dict(id=sample['id'], program=sample['program'], packing=sample['packing'],
                original_sha256=sample['original_sha256'], packed_sha256=sample['packed_sha256'],
                case_count=sample['case_count'], phases={}, proof_scope=PROOF_SCOPE)
            result['samples'].append(row)
            common = ['--packed',sample['packed'],'--original',sample['original'],'--cases',sample['cases']]
            row['phases']['baseline'] = phase('baseline',case/'baseline',case/'process/baseline',common,behavior_timeout)
            first_case=validate_cases(strict_json(sample['cases']))[0]
            row['raw_syscall_observation']=_trace_view(qemu,sample,case,first_case,guest_timeout,rss_limit_mib)
            if result['builds']['plugin']['status'] != 'PASS':
                row['phases']['capture'] = dict(status='NOT_RUN', diagnosis=dict(category='BUILD_FAILURE',
                    stage='capture',detail='Production plugin build was not successful'))
                for name in ('reference','behavior','proof'):
                    row['phases'][name] = dict(status='NOT_RUN', diagnosis=dict(category='NO_CAPTURE',stage=name,
                        detail='No validated automatic selection'))
            else:
                row['phases']['capture'] = phase('capture',case/'capture',case/'process/capture',
                    [*common,'--plugin',plugin],capture_timeout)
                try:
                    row['selection'] = _capture_view(case/'capture',sample['packed_sha256'])
                except (OSError, ValueError, KeyError, TypeError) as error:
                    row['selection'] = dict(status='NO_VALIDATED_SELECTION',detail=str(error))
                    if row['phases']['capture']['status'] == 'PASS':
                        row['phases']['capture'].update(status='NONPROOF',diagnosis=dict(
                            category='INVALID_EVIDENCE',stage='capture',detail=str(error)))
                if row['selection']['status'] != 'VALIDATED_AUTOMATIC_SELECTION':
                    for name in ('reference','behavior','proof'):
                        row['phases'][name] = dict(status='NOT_RUN', diagnosis=dict(category='NO_CAPTURE',stage=name,
                            detail=row['selection']['detail']))
                else:
                    for name,timeout in (('reference',60),('behavior',behavior_timeout)):
                        row['phases'][name] = phase(name,case/name,case/'process'/name,
                            [*common,'--unpack',case/'capture'],timeout)
                    if result['builds']['native']['status'] != 'PASS':
                        row['phases']['proof'] = dict(status='NOT_RUN',diagnosis=dict(category='BUILD_FAILURE',
                            stage='proof',detail='Native tools or QEMU EFLAGS calibration failed'))
                    elif row['selection']['repeated_target_in_stage_history']:
                        row['phases']['proof'] = dict(status='NOT_RUN',diagnosis=dict(category='UNSUPPORTED_PROFILE',
                            stage='proof',detail='Repeated target PC requires an exact occurrence selector; '
                            'the generic external service still uses TFOEPGEN1'))
                    else:
                        row['phases']['proof'] = phase('proof',case/'proof',case/'process/proof',
                            [*common,'--unpack',case/'capture','--native',native_dir],proof_timeout)
                        if row['phases']['proof']['status'] == 'PASS':
                            try:
                                row['proof_metrics'] = _proof_view(case/'proof',row['phases']['proof']['receipt'],
                                    sample['packed_sha256'],row['selection']['target'])
                            except (OSError,ValueError,KeyError,TypeError) as error:
                                row['phases']['proof'].update(status='NONPROOF',diagnosis=dict(
                                    category='INVALID_EVIDENCE',stage='proof',detail=str(error)))
            result['completed_samples'] += 1
            save(case/'summary.json',row);save(output/'progress.json',result)
            print('external:',row['id'],' '.join(name+'='+part['status']+
                (':'+part['diagnosis']['category'] if 'diagnosis' in part else '')
                for name,part in row['phases'].items()),flush=True)
        check_pins(pins)
        result['status'] = 'EXTERNAL_EVALUATION_COMPLETED'
        result['counts'] = {name: sum(row['phases'][name]['status']=='PASS' for row in result['samples'])
                            for name in ('baseline','capture','reference','behavior','proof')}
        result['counts']['validated_selections'] = sum(row.get('selection',{}).get('status') ==
            'VALIDATED_AUTOMATIC_SELECTION' for row in result['samples'])
        result['all_samples_smt_proved_and_reference_matched'] = all(
            row['phases']['proof']['status']=='PASS' and row['phases']['reference']['status']=='PASS'
            for row in result['samples'])
        result['all_samples_behavior_match'] = all(row['phases']['behavior']['status']=='PASS' for row in result['samples'])
        result['all_samples_original_packed_baseline_match'] = all(
            row['phases']['baseline']['status']=='PASS' for row in result['samples'])
    except (OSError,ValueError,KeyError,TypeError) as error:
        result.update(status='INCOMPLETE_EXTERNAL_EVALUATION',errors=[type(error).__name__+': '+str(error)])
    finally:
        result['input_pins_sha256'] = digest(output/'input-pins.json')
        save(output/'summary.json',result)
        with (output/'results.csv').open('w',newline='') as stream:
            fields=['id','program','packing','phase','status','category','wall_seconds','max_rss_kib',
                    'sampled_group_peak_rss_kib']
            writer=csv.DictWriter(stream,fieldnames=fields);writer.writeheader()
            for row in result['samples']:
                for name,part in row['phases'].items():
                    m=part.get('measurement',{})
                    writer.writerow(dict(id=row['id'],program=row['program'],packing=row['packing'],phase=name,
                        status=part['status'],category=part.get('diagnosis',{}).get('category',''),
                        **{k:m.get(k,'') for k in fields[-3:]}))
    return result


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--corpus',type=Path,required=True)
    parser.add_argument('--qemu',type=Path,required=True)
    parser.add_argument('--qemu-include',type=Path,required=True)
    parser.add_argument('--output',type=Path)
    parser.add_argument('--sample',action='append')
    parser.add_argument('--guest-timeout',type=float,default=30)
    parser.add_argument('--capture-timeout',type=float,default=180)
    parser.add_argument('--behavior-timeout',type=float,default=600)
    parser.add_argument('--proof-timeout',type=float,default=900)
    parser.add_argument('--rss-limit-mib',type=int,default=4096)
    parser.add_argument('--max-producer-nodes',type=int,default=32000000)
    args=parser.parse_args(argv)
    output=args.output or Path(tempfile.mkdtemp(prefix='unpack-proof.external-',dir=ROOT))/'probe'
    print('Results:',output,flush=True)
    try:
        result=evaluate(args.corpus,output,qemu=args.qemu,qemu_include=args.qemu_include,
            guest_timeout=args.guest_timeout,capture_timeout=args.capture_timeout,
            behavior_timeout=args.behavior_timeout,proof_timeout=args.proof_timeout,
            rss_limit_mib=args.rss_limit_mib,max_producer_nodes=args.max_producer_nodes,samples=args.sample)
    except (OSError,ValueError,KeyError,TypeError) as error:
        print('FAIL:',type(error).__name__+': '+str(error),file=sys.stderr);return 1
    print(result['status'],result.get('counts',{}),flush=True)
    return 0 if result['status']=='EXTERNAL_EVALUATION_COMPLETED' else 1


if __name__=='__main__': raise SystemExit(main())
