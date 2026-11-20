"""Native strict admission followed by a second independent corpus campaign."""
import argparse
import json
from pathlib import Path
import subprocess

from scripts import verify_afl_strict_e2e as initial
from scripts.verify_afl_phase2_e2e import SudoLease
from taintforge_env import afl_file as f, capsule_strict as strict
from taintforge_env.afl_continue import prepare_continuation, resume, verify_stopped


def verify(out, *, qemu, afl_bin=None, executions=64, seconds=60, modes=('parallel', 'sequential')):
    initial.validate(executions, seconds, modes)
    out = Path(out).expanduser().absolute()
    f.p.require(not out.exists() and not out.is_symlink(), 'Use a new continuation acceptance directory')
    out.mkdir(parents=True)
    report = {'schema': 1, 'status': 'failed', 'scope': 'native_strict_corpus_continuation',
              'native_continuation_verified': False, 'continuations': {},
              'cpu_checkpoint_restored': False, 'afl_scheduler_restored': False,
              'memory_40gib_tested': False, 'hostile_sample_ready': False}
    try:
        first = initial.verify(out/'initial', qemu=qemu, afl_bin=afl_bin,
                               executions=executions, seconds=seconds, modes=modes)
        report['initial'] = first
        if first['status'] != 'passed':
            report['status'] = first['status']
            if 'missing' in first:
                report['missing'] = first['missing']
            return report
        with SudoLease():
            for mode in modes:
                source = out/'initial'/(mode+'-positive')/'campaign'
                source_manifest, _, _ = verify_stopped(source)
                source_hash = f.p.sha(source/'campaign.json')
                expected_oep = f.read_json(source/'warm-session-result.json')['capsule']['phase1_retirement']['verdict']['oep']
                target = out/(mode+'-continued')
                print('Продолжение корпуса в новой strict-сессии: '+mode+'.', flush=True)
                result = resume(source, target, seconds=seconds, executions=executions,
                                afl_bin=out/'initial/afl-bin')
                f.p.require(result['status'] == 'completed' and result['phase1_runs'] == 1,
                            'Continuation did not complete exactly one Phase 1 session')
                positive = strict.verify_positive(target, minimum=executions, expected_oep=expected_oep)
                resumed, executed, admitted = verify_stopped(target)
                provenance = f.read_json(target/'continuation.json')
                imported = {path.name for path in (target/'seeds').iterdir()}
                f.p.require(imported == {item['sha256'] for item in provenance['corpus']['inputs']} and
                            imported <= executed and
                            provenance['source_campaign_sha256'] == source_hash == f.p.sha(source/'campaign.json') and
                            resumed['warm']['phase2']['mode'] == mode and
                            admitted['analysis_quality']['policy']['mode'] == 'strict' and
                            resumed['cases'] == resumed['completed_cases'] >= executions,
                            'Continuation lost corpus, strict policy or child evidence')
                original_environment = f.EnvironmentSnapshotStore(source_manifest['snapshot_store']).verify(source_manifest['snapshot_id'])
                new_environment = f.EnvironmentSnapshotStore(resumed['snapshot_store']).verify(resumed['snapshot_id'])
                f.p.require(original_environment.tree_sha256 == new_environment.tree_sha256 == provenance['environment_sha256'],
                            'Continuation changed the initial environment')
                # A completed manifest alone cannot authorize a capsule with live processes.
                session_path = target/'warm-session-result.json'
                session_bytes = session_path.read_bytes()
                session = json.loads(session_bytes)
                session['capsule']['resources']['tree_empty'] = False
                strict.save(session_path, session)
                refused = out/(mode+'-must-not-start')
                try:
                    try:
                        prepare_continuation(target, refused)
                    except RuntimeError:
                        pass
                    else:
                        raise RuntimeError('Live capsule evidence was accepted for continuation')
                    f.p.require(not refused.exists(), 'Rejected continuation created a new campaign')
                finally:
                    session_path.write_bytes(session_bytes)
                report['continuations'][mode] = positive | {
                    'source_campaign': str(source), 'campaign': str(target),
                    'imported_inputs': len(imported), 'imported_inputs_executed': True,
                    'source_manifest_unchanged': True, 'environment_unchanged': True,
                    'live_capsule_refused': True, 'phase2_cases': resumed['phase2']['completed']}
                strict.save(out/'acceptance.json', report)
        report.update(status='passed', native_continuation_verified=True,
                      phase1_runs_per_new_session=1)
        return report
    except (OSError, ValueError, RuntimeError, KeyError, subprocess.SubprocessError) as exc:
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
    report = verify(args.out, qemu=args.qemu, afl_bin=args.afl_bin, executions=args.executions,
                    seconds=args.seconds, modes=modes)
    print(json.dumps(report, indent=2))
    return 0 if report['status'] == 'passed' else 2 if report['status'] == 'blocked_environment' else 1


if __name__ == '__main__':
    raise SystemExit(main())
