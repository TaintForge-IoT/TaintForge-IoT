"""Native strict campaigns, real group signals, drain verification and continuation."""
import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

from scripts import verify_afl_strict_e2e as baseline
from scripts.verify_afl_phase2_e2e import SudoLease
from taintforge_env import afl_file as f, afl_continue as continuation, capsule_strict as strict
from taintforge_env.afl_stop import verify_receipt


def interrupted_run(root, *, qemu, afl_bin, number, seconds):
    command = [sys.executable, '-m', 'scripts.run_afl_file', 'run', '--out', str(root),
               '--afl-bin', str(afl_bin), '--seconds', str(seconds), '--stop-timeout', '60']
    environment = os.environ | {'PYTHONPATH': str(f.PROJECT), 'TF_WARM_QEMU': str(qemu),
        'TF_OBSERVER_QEMU': str(qemu), 'PYTHONDONTWRITEBYTECODE': '1',
        'GIT_CEILING_DIRECTORIES': str(f.PROJECT.parent)}
    with (root/'signal-test.log').open('wb') as log:
        # Retain the authenticated terminal session, but signal only this coordinator group.
        process = subprocess.Popen(command, cwd=f.PROJECT, env=environment,
                                   stdin=subprocess.DEVNULL, stdout=log, stderr=log, process_group=0)
        sent = False
        try:
            deadline = time.monotonic()+240
            while process.poll() is None and time.monotonic() < deadline:
                state = f.read_json(root/'campaign.json')
                delivered = sum(f.read_json(path).get('status') == 'delivered'
                                for path in (root/'cases').glob('*/transport.json'))
                if state['status'] == 'running' and delivered >= 4:
                    os.killpg(process.pid, number)
                    sent = True
                    break
                time.sleep(.05)
            f.p.require(sent, 'Campaign did not reach the native signal point; inspect '+str(root/'signal-test.log'))
            code = process.wait(timeout=150)
            f.p.require(code == 130, 'Signal campaign did not finish with the interrupted CLI status: '+str(code))
        finally:
            if process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                    process.wait(timeout=90)
                except subprocess.TimeoutExpired:
                    from taintforge_env.afl_transport import stop_case
                    stop_case(process, root)
    manifest, executed, admission = continuation.verify_stopped(root)
    verify_receipt(root, manifest)
    f.p.require(manifest['interruption']['signals'] == [number] and
                manifest['interruption']['status'] == 'drained' and
                manifest['cases'] == manifest['completed_cases'] >= 4,
                'Native interruption lost accepted work')
    return manifest, executed, admission


def verify(out, *, qemu, afl_bin=None, executions=64, seconds=60, modes=('parallel', 'sequential')):
    baseline.validate(executions, seconds, modes)
    f.p.require(seconds >= 10, 'Signal acceptance requires at least 10 seconds of prepared AFL lifetime')
    out = Path(out).expanduser().absolute()
    f.p.require(not out.exists() and not out.is_symlink(), 'Use a new graceful-stop acceptance directory')
    out.mkdir(parents=True)
    report = {'schema': 1, 'status': 'failed', 'scope': 'native_strict_signal_drain_and_continue',
              'native_graceful_stop_verified': False, 'scenarios': {},
              'cpu_checkpoint_restored': False, 'afl_scheduler_restored': False,
              'memory_40gib_tested': False, 'hostile_sample_ready': False}
    try:
        # Check every planned socket before a native build or any capsule is started.
        from taintforge_env.afl_warm import configuration
        for mode in modes:
            paths = [out/'baseline'/(mode+'-'+name)/'campaign' for name in ('positive', 'negative')]
            paths += [out/(mode+'-'+name+'-'+kind) for name in ('int', 'term') for kind in ('stop', 'resume')]
            for path in paths:
                configuration(path, bootstrap_seconds=180, campaign_seconds=seconds+60,
                              timeout_ms=3000, max_rss_mib=512, phase2_mode=mode, capsule_m5=True)
        first = baseline.verify(out/'baseline', qemu=qemu, afl_bin=afl_bin,
                                executions=executions, seconds=seconds, modes=modes)
        report['baseline'] = first
        if first['status'] != 'passed':
            report['status'] = first['status']
            if 'missing' in first:
                report['missing'] = first['missing']
            return report
        launcher = out/'baseline/afl-bin'
        with SudoLease():
            for mode in modes:
                source = out/'baseline'/(mode+'-positive')/'campaign'
                expected_oep = f.read_json(source/'warm-session-result.json')['capsule']['phase1_retirement']['verdict']['oep']
                for name, number in (('int', signal.SIGINT), ('term', signal.SIGTERM)):
                    key = mode+'-'+name
                    root, target = out/(key+'-stop'), out/(key+'-resume')
                    continuation.prepare_continuation(source, root)
                    print('Настоящий '+signal.Signals(number).name+', Phase 2='+mode+'.', flush=True)
                    stopped, _, admitted = interrupted_run(root, qemu=qemu, afl_bin=launcher,
                                                           number=number, seconds=seconds)
                    source_hash = f.p.sha(root/'campaign.json')
                    result = continuation.resume(root, target, afl_bin=launcher,
                                                  seconds=seconds, executions=executions)
                    f.p.require(result['status'] == 'completed', 'Continuation after a signal did not complete')
                    checked = strict.verify_positive(target, minimum=executions, expected_oep=expected_oep)
                    resumed, executed, _ = continuation.verify_stopped(target)
                    imported = {p.name for p in (target/'seeds').iterdir()}
                    f.p.require(imported <= executed and f.p.sha(root/'campaign.json') == source_hash and
                                admitted['analysis_quality']['policy']['mode'] == 'strict' and
                                resumed['warm']['phase2']['mode'] == mode,
                                'Continuation lost imported inputs, strict policy or source identity')
                    # A forced-stop flag must deny continuation before a new capsule is created.
                    manifest_path = root/'campaign.json'
                    original = manifest_path.read_bytes()
                    changed = json.loads(original)
                    changed['interruption']['forced'] = True
                    strict.save(manifest_path, changed)
                    refused = out/(key+'-refused')
                    try:
                        try:
                            continuation.prepare_continuation(root, refused)
                        except RuntimeError:
                            pass
                        else:
                            raise RuntimeError('Forced-stop evidence was accepted')
                        f.p.require(not refused.exists(), 'Rejected source created a continuation')
                    finally:
                        manifest_path.write_bytes(original)
                    report['scenarios'][key] = {'status': 'passed', 'signal': signal.Signals(number).name,
                        'phase2_mode': mode, 'stopped_campaign': str(root), 'resumed_campaign': str(target),
                        'stopped_cases': stopped['cases'], 'phase2_cases': stopped['phase2']['completed'],
                        'interruption': stopped['interruption'], 'resume': checked,
                        'source_manifest_unchanged': True, 'imported_inputs_executed': True,
                        'forced_stop_evidence_refused': True}
                    strict.save(out/'acceptance.json', report)
        report.update(status='passed', native_graceful_stop_verified=True,
                      phase1_runs_per_new_session=1)
        return report
    except (OSError, RuntimeError, ValueError, KeyError, subprocess.SubprocessError) as exc:
        report.update(status='failed', error=type(exc).__name__+': '+str(exc))
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
