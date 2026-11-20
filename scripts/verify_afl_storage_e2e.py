import argparse
import json
from pathlib import Path

from taintforge_env import afl_file as f, afl_storage as storage
from taintforge_env.afl_evidence import completed_cases, child_report, reusable
from taintforge_env.afl_replay import clone_campaign, replay
from taintforge_env.afl_transport import run_campaign
from scripts.verify_afl_capsule_e2e import verify as capsule_acceptance
from scripts.verify_afl_phase2_e2e import SudoLease


def verify(out, *, qemu, afl_bin=None, executions=10000, seconds=1800, mode='parallel'):
    out = Path(out).resolve()
    if out.exists() or executions < 10000:
        raise ValueError('Use a new result directory and at least 10000 executions')
    out.mkdir(parents=True)
    report = {'schema': 1, 'status': 'failed', 'scope': 'real_m5_storage_acceptance',
              'memory_40gib_tested': False, 'filesystem_quota_tested': False}
    try:
        full = capsule_acceptance(out/'full', qemu=qemu, afl_bin=afl_bin, mode=mode,
                                  seconds=seconds, executions=executions)
        source = out/'full/pipeline/initial/campaign'
        original = f.verify_campaign(source)
        if original['cases'] < executions or full['status'] != 'passed':
            raise RuntimeError('The long M5 campaign did not finish its execution budget')
        limited = out/'limited'
        clone_campaign(source, limited, inputs=[b'A'])
        with SudoLease():
            result = run_campaign(limited, afl_bin=out/'full/pipeline/initial/afl-bin',
                                  seconds=60, max_artifact_mib=16, max_case_mib=15)
        if not reusable(result) or result['status'] != 'resource_limited' or result['cases'] < 1:
            raise RuntimeError('Storage limit did not produce a complete, bounded campaign')
        session = f.read_json(limited/'warm-session-result.json')
        capsule = session.get('capsule', {})
        if (capsule.get('status') != 'passed' or result.get('phase1_runs') != 1 or
                capsule.get('resources', {}).get('tree_empty') is not True):
            raise RuntimeError('Limited campaign cleanup or retirement was not verified')
        for case in completed_cases(limited, result):
            child_report(case, result['max_input'])
        if (limited/storage.RESERVE).exists():
            raise RuntimeError('Storage reserve leaked')
        findings = sorted((source/'findings/crashes').glob('*/finding.json'))
        if not findings: raise RuntimeError('Long campaign retained no crash fixture')
        clone = out/'replay'
        with SudoLease():
            reproduced = replay(source, findings[0].parent, clone, repetitions=3)
        if reproduced['status'] != 'passed': raise RuntimeError('Saved finding was not reproduced')
        report.update(status='passed', full=full, long_cases=original['cases'],
                      limited_cases=result['cases'], limited_storage=result['storage_result'],
                      limited_capsule=capsule, replay=reproduced)
        return report
    finally:
        f.atomic_json(out/'acceptance.json', report)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--qemu', type=Path, required=True)
    parser.add_argument('--afl-bin', type=Path)
    parser.add_argument('--executions', type=int, default=10000)
    parser.add_argument('--seconds', type=int, default=1800)
    parser.add_argument('--phase2-mode', choices=('parallel', 'sequential'), default='parallel')
    args = parser.parse_args()
    result = verify(args.out, qemu=args.qemu, afl_bin=args.afl_bin, executions=args.executions,
                    seconds=args.seconds, mode=args.phase2_mode)
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
