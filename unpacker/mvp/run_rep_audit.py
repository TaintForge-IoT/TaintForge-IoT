#!/usr/bin/env python3
"""Fresh bounded REP callback calibration and source-derived GEN1 replay.

Normal QEMU callbacks are compared exactly with native replay: no callback is
dropped and the existing count/PC/fetch comparison remains unchanged.  The
single-instruction-per-TB runs calibrate a distinct callback convention only.
They never authorize a native equivalence or SMT claim.  Optional SMT covers
three explicitly selected fresh normal-mode executions, not the whole corpus.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import struct
import subprocess
import sys
import uuid

PROJECT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT / 'unpacker'))
import unpack_proof as proof
import unpack_observations as observations
from unpack_sources import loader_regions
from replay_trace import read_trace, compare as compare_trace
import rep_fixtures as fixtures
import rep_callbacks as callbacks

STATUS = 'PASS_BOUNDED_REP_CALLBACK_AND_NATIVE_AUDIT'
SMT_CASES = ('movs-1-n2-df0', 'stos-4-n2-df1', 'movs-1-n0-df0')
TRACE_LIMIT = 8192
require = proof.v.require
save = proof.v.save
digest = proof.digest_file


def _source_range(loader, address, size):
    choices = [data[address-start:address-start+size]
        for start, data in loader['initial_regions']
        if start <= address and address + size <= start + len(data)]
    require(len(choices) == 1 and len(choices[0]) == size,
            'REP conclusion lacks a unique original ELF LOAD range')
    return choices[0]


def expected_goals(packed, case):
    """Construct conclusions independently, including real file-page padding."""
    loader = loader_regions(packed)
    data = bytearray(_source_range(loader, fixtures.SOURCE, 3 * fixtures.PAGE))
    wanted = fixtures.expected(case)
    destination = fixtures.DESTINATION - fixtures.SOURCE
    data[destination:destination+fixtures.PAGE] = wanted['destination']
    data[destination+fixtures.PAGE:destination+fixtures.PAGE+12] = wanted['stdout'][-12:]
    return loader, [
        dict(address=fixtures.TARGET, size=fixtures.PAGE, prot=5,
             data=_source_range(loader, fixtures.TARGET, fixtures.PAGE)),
        dict(address=fixtures.SOURCE, size=3 * fixtures.PAGE, prot=3, data=bytes(data))]


def _capture_single(qemu, plugin, packed, goals, output):
    """Use the same strict observer protocol in a separately labeled mode."""
    output.mkdir()
    guest = output / 'packed.elf'
    guest.write_bytes(packed)
    guest.chmod(0o700)
    goal_file = output / 'goals.txt'
    goal_file.write_text(''.join(f"{row['address']:x} {row['size']:x}\n" for row in goals))
    events, report, trace = (output / name for name in
                             ('events.jsonl', 'report.json', 'trace.jsonl'))
    for path in (qemu, plugin, guest, goal_file, events, report, trace):
        require(not any(char in str(path) for char in ',\n\r'), 'Unsupported REP capture path delimiter')
    token = uuid.uuid4().hex
    option = (f'{plugin},guest={guest},events={events},report={report},run-id={token}'
        f',target=0x{fixtures.TARGET:x},goals={goal_file},trace={trace},trace-start=1,trace-limit={TRACE_LIMIT}')
    command = [str(qemu), '-one-insn-per-tb', '-s', '1044480', '-plugin', option,
               '-0', 'target.elf', str(guest)]
    environment = {'LC_ALL': 'C', 'TZ': 'UTC'}
    launch = dict(schema_version=1, run_id=token, source_elf_sha256=proof.v.digest(packed),
        qemu_sha256=digest(qemu), plugin_sha256=digest(plugin), target=fixtures.TARGET,
        target_pc=fixtures.TARGET, argv=command, guest_argv=['target.elf'],
        guest_environ=[key + '=' + value for key, value in environment.items()],
        controlled_host_environment=environment, cwd=str(output), stdin_empty=True,
        timeout_seconds=proof.TIMEOUT, payload_instruction_execution_allowed=False,
        new_independent_execution=True, runtime_and_observer_trusted=True,
        execution_mode='one_insn_per_tb_calibration_only', proof_authorized_by_calibration=False)
    save(output / 'launch.json', launch)
    with (output / 'stdout').open('xb') as stdout, (output / 'stderr').open('xb') as stderr:
        process = subprocess.Popen(command, cwd=output, env=environment,
            stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr, close_fds=True,
            start_new_session=True, preexec_fn=proof.child_limits)
        try:
            process.wait(timeout=proof.TIMEOUT)
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=10)
    launch['returncode'] = process.returncode
    save(output / 'launch.json', launch)
    require(process.returncode == 0, 'Single-TB REP capture failed; inspect ' + str(output / 'stderr'))
    require(proof.v.strict_json(proof.bounded(report, 4 * 1024**2, 'REP report').read_bytes()).get('success') is True,
            'Single-TB REP capture did not stop before target')
    return observations.read_capture(proof.bounded(events, proof.MAX_CAPTURE, 'REP capture').read_bytes(), launch), launch


def _calibrate(directory, case, record, rows, mode):
    return callbacks.inspect_observation(directory, record, case, rows, mode, trace_limit=TRACE_LIMIT)


def _write_inputs(context, packed, goals, inputs, profile):
    inputs.mkdir()
    config = callbacks.config_text(fixtures.TARGET, context['stack_base'], 30000000,
                                   goals, profile).encode('ascii')
    values = {'source.elf': packed, 'stack.bin': context['stack'],
        'stack-mask.bin': bytes([255]) * len(context['stack']),
        'scalars.txt': f"{context['esp']:x} {context['df']:x}\n".encode('ascii'),
        'contracts.txt': observations.contracts_text(context['rows']).encode('ascii'), 'config.txt': config}
    for name, value in values.items():
        (inputs / name).write_bytes(value)


CALIBRATION_SOURCE_NAMES = callbacks.SOURCE_FILES


def _binding(document, path):
    return dict(mode=document['profiles']['normal'],
        semantics=callbacks.semantics(document['profiles']['normal']),
        calibration_sha256=digest(path), **document['runtime'])


def _run(project, qemu, include, output, *, prove=False, max_nodes=2000000,
         calibration_only=False, native=None):
    project, qemu, include = (Path(path).resolve(strict=True) for path in (project, qemu, include))
    output = Path(os.path.abspath(os.fspath(output)))
    require(project == PROJECT and qemu.is_file() and os.access(qemu, os.X_OK) and
            (include/'qemu-plugin.h').is_file(), 'Run this driver from its own project with a matching QEMU SDK')
    require(os.sysconf('SC_PAGE_SIZE') == 4096, 'Bounded REP audit requires 4096-byte host pages')
    require(type(prove) is bool and type(calibration_only) is bool and
            type(max_nodes) is int and 1 <= max_nodes <= 67000000,
            'REP proof option or producer budget')
    require(not os.path.lexists(output) and not any(path.is_symlink() for path in output.parents),
            'REP output is occupied or traverses a symlink')
    output.mkdir(parents=True)
    result = dict(schema_version=1,status='FAIL_BOUNDED_REP_CALLBACK_AND_NATIVE_AUDIT',
        fixture_count=0,calibrated_fixture_count=0,observer_calibrations=0,native_route_comparisons=0,
        SMT_selected_case_proofs=0,SMT_requested=prove,SMT_case_inventory=list(SMT_CASES) if prove else [],
        phase='calibration',records=[],errors=[],calibration_not_SMT_proof=True,
        normal_GEN1_raw_callback_identity_required=True,single_TB_native_equivalence_claimed=False,
        source_derived_initial_memory_only=True,observed_final_state_used_as_input=False,
        historical_originality_proven=False,universal_equivalence=False,
        initial_ESP_DF_and_runtime_IR_solver_models_remain_explicit=True,commands=[])
    pins = {}
    def pin(path):
        path = Path(path).resolve(strict=True)
        require(path.is_file() and not path.is_symlink(), 'REP pin must be a regular source/runtime file')
        pins[str(path)] = digest(path)
    def check_pins():
        require(all(Path(path).is_file() and not Path(path).is_symlink() and digest(path)==value
                    for path,value in pins.items()), 'REP pinned source/runtime/artifact changed')
    def command(argv,label,*,cwd=None):
        argv = list(map(str,argv))
        result['commands'].append(dict(label=label,argv=argv,cwd=str(cwd or output)))
        completed = subprocess.run(argv,cwd=cwd or output,capture_output=True,timeout=60)
        require(completed.returncode==0,label+': '+completed.stderr.decode(errors='replace'))
        return completed
    try:
        require(tuple(fixtures.CASES)==callbacks.CASES, 'REP calibration fixture inventory differs')
        for path in [*sorted((project/'unpacker').glob('*.py')),
                     *[project/name for name in CALIBRATION_SOURCE_NAMES], qemu, include/'qemu-plugin.h']:
            pin(path)
        exported = subprocess.check_output(['nm','-D','--defined-only',str(qemu)],text=True,timeout=30)
        require(set(proof.APIS)<={line.split()[-1].split('@')[0] for line in exported.splitlines() if line.split()},
                'QEMU lacks required existing observer APIs')
        if native is None:
            print('REP: source-building native replay and exact observer',flush=True)
            native = proof.build_native(include,output/'runtime')
        binary,plugin,receipt = native
        binary,plugin = Path(binary).resolve(strict=True),Path(plugin).resolve(strict=True)
        require(digest(binary)==receipt['replay_sha256'] and digest(plugin)==receipt['observer_sha256'] and
                digest(include/'qemu-plugin.h')==receipt['sdk_sha256'], 'REP native build identity differs')
        for name,wanted in receipt['sources_sha256'].items():
            original = project/'unpacker'/('test/'+name if name in (*proof.v.IR_SOURCE_FILES,*proof.v.IR_HEADER_FILES) else name)
            require(digest(original)==wanted,'REP native source differs: '+name)
            pin(original)
        pin(binary);pin(plugin)
        fixture_root,cases = output/'fixtures',output/'cases'
        fixture_root.mkdir();cases.mkdir()
        calibration_records,evidence = [],{}
        # Measure every mode/case before any native equivalence or SMT query.
        for case in fixtures.CASES:
            name = case[0]
            print('REP calibration:',name,flush=True)
            record = fixtures.build_fixture(project/'unpacker/mvp/fixtures',fixture_root/name,case,command)
            packed_path = fixture_root/name/record['fixture_elf']
            packed = packed_path.read_bytes()
            pin(packed_path);pin(fixture_root/name/'fixture.json')
            _,goals = expected_goals(packed,case)
            work = cases/name;work.mkdir()
            rows,launch = proof.capture(qemu,plugin,packed,fixtures.TARGET,goals,
                                       work/'capture',trace_prefix=TRACE_LIMIT)
            normal = _calibrate(work/'capture',case,record,rows,'normal')
            normal_image = observations.snapshots(rows,'final_goal')
            require(normal_image==[dict(address=g['address'],data=g['data']) for g in goals],
                    'Normal REP observed memory differs from independent conclusions: '+name)
            single_rows,_ = _capture_single(qemu,plugin,packed,goals,work/'single-capture')
            single = _calibrate(work/'single-capture',case,record,single_rows,'single')
            require(observations.snapshots(single_rows,'final_goal')==
                    [dict(address=g['address'],data=g['data']) for g in goals],
                    'Single-TB REP observed memory differs from independent conclusions: '+name)
            for item in (normal,single):
                item['independent_final_goal_bytes_compared'] = sum(goal['size'] for goal in goals)
            calibration_records.append(dict(name=name,operation=case[1],element_bytes=case[2],
                initial_count=case[3],initial_DF=case[4],fixture_elf_sha256=digest(packed_path),
                fixture_record_sha256=digest(fixture_root/name/'fixture.json'),normal=normal,single=single))
            thin = [fixture_root/name/'fixture.json',packed_path]
            for folder in ('capture','single-capture'):
                thin.extend(work/folder/file for file in ('trace.jsonl','report.json','launch.json'))
            for path in thin:
                pin(path);evidence[path.relative_to(output).as_posix()] = digest(path)
            result['calibrated_fixture_count'] += 1;result['observer_calibrations'] += 2
            save(output/'progress.json',result)
        profiles = {mode:callbacks.select_profile(calibration_records,mode) for mode in ('normal','single')}
        for row in calibration_records:
            for mode in ('normal','single'):
                row[mode]['callback_profile'] = profiles[mode]
                row[mode]['expected_REP_callbacks'] = callbacks.callbacks(profiles[mode],row['initial_count'])
        check_pins()
        calibration = dict(schema_version=1,status=callbacks.STATUS,
            runtime=dict(qemu_sha256=digest(qemu),observer_sha256=digest(plugin),
                         sdk_sha256=digest(include/'qemu-plugin.h')),
            profiles=profiles,fixture_count=48,observer_calibrations=96,records=calibration_records,
            source_sha256={name:digest(project/name) for name in CALIBRATION_SOURCE_NAMES},
            evidence_root=str(output),evidence_files=evidence,calibration_not_SMT_proof=True,
            source_derived_fixture_only=True,complete_raw_callback_hashes_checked=True,
            all_inputs_unchanged=True,event_snapshots_not_used_as_profile_premises=True,
            proof_authorized=False,observed_ECX_admitted_as_source=False,
            historical_originality_proven=False,universal_equivalence=False)
        callbacks.validate_calibration(calibration,**calibration['runtime'])
        save(output/'calibration.json',calibration);pin(output/'calibration.json')
        # The reusable loader independently checks the small trace/report/ELF
        # evidence and current sources before any native or solver invocation.
        callbacks.load_calibration(output/'calibration.json',qemu=qemu,observer=plugin,
                                   sdk=include/'qemu-plugin.h',project=project)
        binding = _binding(calibration,output/'calibration.json')
        result.update(calibration_receipt_sha256=binding['calibration_sha256'],
            callback_profiles=profiles,rep_runtime_binding=binding,calibration_completed_before_native=True)
        if calibration_only:
            check_pins()
            result.update(status=callbacks.STATUS,phase='calibrated',all_pinned_sources_runtime_and_fixture_inputs_unchanged=True,
                          raw_callback_hash_check_weakened=False)
            return result
        result['phase']='native_and_SMT'
        proof_root = output/'proofs'
        if prove:proof_root.mkdir()
        profile=profiles['normal']
        for case,calibrated in zip(fixtures.CASES,calibration_records):
            name=case[0]
            print('REP native:',name,'profile='+profile,flush=True)
            work=cases/name;packed_path=fixture_root/name/'fixture.elf'
            packed=packed_path.read_bytes();loader,goals=expected_goals(packed,case)
            launch=proof.v.strict_json((work/'capture/launch.json').read_bytes())
            require(digest(work/'capture/events.jsonl')==calibrated['normal']['events_sha256'],
                    'REP normal capture events changed')
            rows=observations.read_capture((work/'capture/events.jsonl').read_bytes(),launch)
            context=observations.initial_context(rows,packed,loader,launch=launch)
            require(context['calls']==[],'REP fixture unexpectedly consumed a kernel contract')
            context['rows']=rows;context['rep_runtime_binding']=dict(binding)
            inputs=work/'inputs';_write_inputs(context,packed,goals,inputs,profile)
            save(work/'rep-runtime-binding.json',binding)
            proof.replay(binary,inputs,work/'discovery',trace_prefix=TRACE_LIMIT)
            discovered=observations.compare_replay(rows,work/'discovery',goals,initial_regions=loader['initial_regions'])
            compared_trace=compare_trace(work/'capture/trace.jsonl',work/'discovery/trace.jsonl')
            require(compared_trace['status']=='MATCHED_DIAGNOSTIC_PREFIX' and
                    compared_trace['observed']['rows']==calibrated['normal']['instruction_callbacks'],
                    'REP native full route differs from calibrated raw callbacks')
            save(work/'diagnostic-comparison.json',compared_trace)
            projection=(work/'discovery/projection.bin').read_bytes()
            save(work/'initial-premises.json',observations.validate_projection(context,projection))
            require(projection.count(255)==0,'REP fixture unexpectedly depends on initial stack bytes')
            context['stack']=bytes(value&mask for value,mask in zip(context['stack'],projection));context['mask']=projection
            (inputs/'stack.bin').write_bytes(context['stack']);(inputs/'stack-mask.bin').write_bytes(projection)
            selected=prove and name in SMT_CASES
            proof.replay(binary,inputs,work/'reduced',producers=selected,max_nodes=max_nodes,trace_prefix=TRACE_LIMIT)
            compared=observations.compare_replay(rows,work/'reduced',goals,initial_regions=loader['initial_regions'])
            require((work/'reduced/projection.bin').read_bytes()==projection and
                    compared['execution']['path_sha256']==discovered['execution']['path_sha256'],
                    'Reduced REP replay changed source projection or exact route')
            execution=compared['execution']
            require(execution.get('instruction_count_semantics')==callbacks.semantics(profile) and
                    execution.get('rep_callback_mode')==profile and
                    execution.get('rep_callback_profile_explicit') is True and
                    execution.get('macro_instructions')==15 and execution.get('rep_macros')==1 and
                    execution.get('rep_extra_callbacks')==callbacks.callbacks(profile,case[3])-1,
                    'REP replay does not declare its calibrated explicit callback convention')
            save(work/'comparison.json',compared)
            item=dict(calibrated,normal_native_count_path_fetch_and_full_goal_image_match=True,
                initial_known_stack_bytes=0,no_kernel_contracts=True,compared_goal_bytes=sum(g['size'] for g in goals),
                normal_instructions=execution['instructions'],normal_macro_instructions=execution['macro_instructions'],
                normal_REP_extra_callbacks=execution['rep_extra_callbacks'],
                native_instruction_count_semantics=execution['instruction_count_semantics'],
                normal_PC_sha256=execution['path_sha256'],normal_fetch_sha256=execution['fetch_sha256'],
                native_callback_profile=profile,rep_runtime_binding=dict(binding),
                SMT_status='NOT_RUN',SMT_proof_directory=None)
            if selected:
                smt_dir=proof_root/name
                theorem=proof.unpack_smt.prove_generic(work/'reduced',context,goals,smt_dir,
                    target=fixtures.TARGET,execution=execution,
                    input_files_sha256=[digest(inputs/filename) for filename in proof.INPUT_NAMES],max_nodes=max_nodes)
                require(theorem.get('status')==proof.unpack_smt.STATUS and theorem.get('source_premise_query')=='SAT' and
                        theorem.get('image_and_transfer_counterexample_query')=='UNSAT',
                        'Selected REP SMT theorem did not complete')
                save(smt_dir/'rep-runtime-binding.json',binding)
                save(smt_dir/'rep-calibration.json',calibration)
                item.update(SMT_status=theorem['status'],SMT_proof_directory=str(smt_dir.relative_to(output)),
                            SMT_solver_checks=theorem['SMT_solver_checks'])
                result['SMT_selected_case_proofs']+=1
            result['records'].append(item);result['fixture_count']+=1;result['native_route_comparisons']+=1
            check_pins();save(output/'progress.json',result)
        require(result['fixture_count']==result['native_route_comparisons']==48 and result['observer_calibrations']==96 and
                result['SMT_selected_case_proofs']==(len(SMT_CASES) if prove else 0), 'Incomplete bounded REP audit inventory')
        check_pins()
        result.update(status=STATUS,phase='complete',all_pinned_sources_runtime_and_fixture_inputs_unchanged=True,
                      raw_callback_hash_check_weakened=False)
    except (OSError,ValueError,KeyError,TypeError,subprocess.SubprocessError) as error:
        result['errors'].append(type(error).__name__+': '+str(error))
        print('FAIL:',result['errors'][-1],file=sys.stderr,flush=True)
    finally:
        save(output/'input-pins.json',pins);save(output/'summary.json',result)
    print(result['status'],flush=True)
    return result


def run(project,qemu,include,output,*,prove=False,max_nodes=2000000):
    return _run(project,qemu,include,output,prove=prove,max_nodes=max_nodes)


def calibrate_runtime(project,qemu,include,output,*,native=None):
    """Measure all48×2 modes before selecting one profile; no replay or SMT."""
    result=_run(project,qemu,include,output,calibration_only=True,native=native)
    require(result['status']==callbacks.STATUS,'REP runtime calibration failed: '+repr(result['errors']))
    return callbacks.load_calibration(Path(output)/'calibration.json',qemu=qemu,
        observer=(native[1] if native is not None else Path(output)/'runtime/unpack-capture.so'),
        sdk=Path(include)/'qemu-plugin.h',project=project)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--project', type=Path, default=PROJECT)
    parser.add_argument('--qemu', type=Path, required=True)
    parser.add_argument('--qemu-include', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--prove', action='store_true')
    parser.add_argument('--max-nodes', type=int, default=2000000)
    args = parser.parse_args()
    try:
        result = run(args.project, args.qemu, args.qemu_include, args.output,
                     prove=args.prove, max_nodes=args.max_nodes)
        return 0 if result['status'] == STATUS else 1
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        print('FAIL:', type(error).__name__ + ': ' + str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
