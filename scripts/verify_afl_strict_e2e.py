"""Real strict admission followed by ABI 3 warm AFL and per-child Phase 2."""
import argparse
from contextlib import redirect_stderr, redirect_stdout
import json
import os
from pathlib import Path
import re
import shutil
import subprocess

from scripts.verify_afl_corpus_components import stock_launcher
from scripts.verify_afl_phase2_e2e import SudoLease
from taintforge_env import afl_file as f, afl_strict, capsule_strict as strict
from taintforge_env.afl_transport import run_campaign


def validate(executions, seconds, modes):
    f.p.require(type(executions) is int and 2 <= executions <= 1000000 and
                type(seconds) is int and 1 <= seconds <= 3600 and
                isinstance(modes, tuple) and modes and len(set(modes)) == len(modes) and
                set(modes) <= {'parallel', 'sequential'}, 'Invalid strict AFL acceptance limits')


def launch_case(out, fixture, *, qemu, plugin, afl_bin, executions, seconds, mode):
    out = Path(out)
    seeds = out/'seeds'
    seeds.mkdir()
    for name in ('A', 'B'):
        (seeds/name).write_bytes(name.encode())
    root = out/'campaign'
    error = None
    with (out/'pipeline.log').open('w') as log, redirect_stdout(log), redirect_stderr(log):
        try:
            afl_strict.prepare_campaign(root, binary=fixture['path'], qemu=qemu, plugin=plugin,
                guest_path='/etc/afl-input', seeds=seeds, analysis_policy='strict',
                ir_start=fixture['ir_start'], phase2_mode=mode, phase2_pending=4,
                bootstrap_seconds=180, campaign_seconds=seconds+60, timeout_ms=3000,
                max_rss_mib=512, memory_mib=4096, analysis_mib=2048)
            run_campaign(root, afl_bin=afl_bin, seconds=seconds, executions=executions)
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
            error = type(exc).__name__+': '+str(exc)
    if error is not None:
        strict.save(out/'diagnostics.json', strict.failure_details(root, error))
    if fixture['negative']:
        f.p.require(error is not None, 'Rejected strict fixture unexpectedly completed')
        return strict.verify_negative(root) | {'pipeline_error': error, 'phase2_mode': mode}
    f.p.require(error is None, 'Strict AFL failed: '+str(error)+'; log: '+str(out/'pipeline.log'))
    result = strict.verify_positive(root, minimum=executions, expected_oep=fixture['expected_oep'])
    manifest = f.verify_campaign(root)
    calibration = afl_strict.calibration_ok(root/'flags-calibration', qemu=qemu, plugin=plugin)
    f.p.require(manifest.get('flags_calibration') == {
        'schema': 1, 'profile': afl_strict.PROFILE, 'directory': 'flags-calibration',
        'status': 'passed', **calibration}, 'Strict AFL calibration record changed')
    f.p.require(manifest['afl_exit'] == 0 and manifest['evidence_complete'] is True and
                manifest['completed_cases'] == manifest['cases'] >= executions and
                manifest['warm']['phase2']['mode'] == mode and manifest['phase2']['pending'] == 0,
                'Strict AFL execution or Phase 2 accounting failed')
    overlap = sum(manifest['afl_started_ns'] <= f.read_json(case/'phase2/result.json')['finished_ns']
                  <= manifest['afl_finished_ns'] for case in sorted((root/'cases').iterdir()))
    f.p.require(overlap > 0, 'Phase 2 did not process any cases while AFL was running')
    run = root/'warm-session/iterations/0000/run'
    events = f.read_json(run/'logs/capsule/observer-events.json')['events']
    held = next(e for e in events if e['event'] == 'snapshot' and e['point'] == 2)
    checkpoint = next(e for e in events if e['event'] == 'warm_checkpoint')
    done = next(e for e in events if e['event'] == 'done')
    from experiments.retirement_observer import controller
    controller.warm_checkpoint_ok(checkpoint, held['host_pid'], held['seq'])
    controller.continuation_ok(done, held['host_pid'], held['seq'], checkpoint=checkpoint)
    return result | {'phase2_mode': mode, 'phase2_cases': manifest['phase2']['completed'],
        'phase2_completed_during_afl': overlap,
        'input_gate_abi': 3, 'outcome_wire_abi': 2,
        'checkpoint_at_held_instruction': checkpoint['seq'] == held['seq'],
        'fixture_work_iterations': fixture['handoff_work_iterations'],
        'flags_calibration': calibration}


def verify(out, *, qemu, afl_bin=None, executions=64, seconds=60,
           modes=('parallel', 'sequential')):
    validate(executions, seconds, modes)
    out = Path(out).expanduser().absolute()
    f.p.require(not out.exists() and not out.is_symlink(), 'Use a new strict AFL output directory')
    out.mkdir(parents=True)
    report = {'schema': 1, 'status': 'failed', 'scope': 'native_strict_abi3_afl_phase2',
        'analysis_policy': 'strict', 'modes': {}, 'native_strict_positive_verified': False,
        'native_strict_negative_verified': False, 'oep_proven': False,
        'memory_isolation': False, 'hostile_sample_ready': False, 'memory_40gib_tested': False}
    try:
        from taintforge_env.afl_warm import configuration
        for mode in modes:
            for name in ('positive', 'negative'):
                configuration(out/(mode+'-'+name)/'campaign', bootstrap_seconds=180,
                    campaign_seconds=seconds+60, timeout_ms=3000, max_rss_mib=512,
                    phase2_mode=mode, capsule_m5=True)
        missing = [tool for tool in ('gcc', 'as', 'ld', 'strip', 'nm', 'pkg-config', 'sudo',
            'systemd-run', 'systemctl', 'unshare', 'mount', 'umount', 'ip', 'hostname', 'chroot',
            'bash', 'timeout', 'tee')
            if not shutil.which(tool)]
        qemu = Path(qemu).expanduser().resolve()
        executable = Path(afl_bin)/'afl-fuzz' if afl_bin else Path(shutil.which('afl-fuzz') or '/missing/afl-fuzz')
        if not qemu.is_file():
            missing.append(str(qemu))
        if not executable.is_file():
            missing.append(str(executable))
        if not Path('/run/systemd/system').is_dir():
            missing.append('running systemd system manager')
        if shutil.which('pkg-config') and subprocess.run(
                ['pkg-config', '--exists', 'glib-2.0', 'capstone', 'z3'],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode:
            missing.append('GLib/Capstone/Z3 development packages')
        if missing:
            report.update(status='blocked_environment', missing=missing)
            return report
        version = f.p.command(qemu, '--version')
        f.p.require(re.search(r'\bversion 11\.0\.1(?:[\s(]|$)', version), 'QEMU 11.0.1 required')
        afl_strict.require_backend(qemu)
        plugin = out/'libtaintforge_ir.so'
        environment = os.environ | {
            'TF_QEMU_INCLUDE': str(f.PROJECT/'experiments/execution_capsule_probe/vendor'),
            'GIT_CEILING_DIRECTORIES': str(f.PROJECT.parent)}
        print('Сборка Phase 1 для strict AFL ABI 3.', flush=True)
        with (out/'phase1-build.log').open('wb') as log:
            subprocess.run(['bash', 'unpacker/test/build_group7_4c1_plugin.sh', 'unpacker/test', str(plugin)],
                           cwd=f.PROJECT, env=environment, stdout=log, stderr=subprocess.STDOUT, check=True)
        before = {str(path): strict.digest(path) for path in (qemu, plugin, executable)}
        launcher = stock_launcher(out/'afl-bin', executable)
        with SudoLease():
            for mode in modes:
                results = {}
                for name, negative in (('positive', False), ('negative', True)):
                    case = out/(mode+'-'+name)
                    case.mkdir()
                    # Enough callbacks for candidate selection; retirement is gated by the backend.
                    fixture = strict.build_fixture(case/'fixture', negative=negative, handoff_loops=64)
                    print('Strict ABI 3: '+mode+' '+name+'.', flush=True)
                    results[name] = launch_case(case, fixture, qemu=qemu, plugin=plugin,
                        afl_bin=launcher, executions=executions, seconds=seconds, mode=mode)
                    report['modes'][mode] = results
                    strict.save(out/'acceptance.json', report)
        f.p.require(all(strict.digest(Path(path)) == digest for path, digest in before.items()),
                    'Strict AFL runtime changed during acceptance')
        report.update(status='passed', native_strict_positive_verified=True,
                      native_strict_negative_verified=True, phase1_runs_per_session=1,
                      runtime_sha256=before)
        return report
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError, KeyError) as exc:
        report['error'] = type(exc).__name__+': '+str(exc)
        return report
    finally:
        strict.save(out/'acceptance.json', report)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qemu', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--afl-bin', type=Path)
    parser.add_argument('--executions', type=int, default=64)
    parser.add_argument('--seconds', type=int, default=60)
    parser.add_argument('--phase2-mode', choices=('parallel', 'sequential', 'both'), default='both')
    args = parser.parse_args()
    modes = ('parallel', 'sequential') if args.phase2_mode == 'both' else (args.phase2_mode,)
    report = verify(args.out, qemu=args.qemu, afl_bin=args.afl_bin,
                    executions=args.executions, seconds=args.seconds, modes=modes)
    print(json.dumps(report, indent=2))
    return 0 if report['status'] == 'passed' else 2 if report['status'] == 'blocked_environment' else 1


if __name__ == '__main__':
    raise SystemExit(main())
