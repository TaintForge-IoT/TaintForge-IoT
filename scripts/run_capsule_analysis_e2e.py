"""Research retirement and strict denial on benign M5 inputs."""
import argparse
from pathlib import Path
import traceback

from experiments.execution_capsule_probe import controller as p
from experiments.input_retirement.cases import build_guests
from scripts.run_capsule_control_e2e import launch
from scripts.run_capsule_hardening_e2e import refused
from scripts.run_input_retirement_e2e import validate_case
from taintforge_env.analysis_quality import PROFILE
from taintforge_env.phase1_runtime import read_json
from taintforge_env.retirement_evidence import verify

CASES = ('research-normal', 'research-repair', 'strict-reject')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qemu', type=Path, required=True)
    parser.add_argument('--plugin', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    out = args.out.absolute(); out.mkdir(parents=True, exist_ok=False)
    report = {'schema': 1, 'profile': PROFILE, 'status': 'failed', 'cases': [],
        'scope': 'benign_static_i386_unified_systemd', 'oep_proven': False,
        'complete_program_analysis': False, 'hostile_sample_ready': False,
        'qemu_sha256': p.sha(args.qemu), 'phase1_sha256': p.sha(args.plugin)}
    try:
        guests = build_guests(out/'inputs')
        report['input_build_sha256'] = p.sha(out/'inputs/build.json')
        for name in CASES[:2]:
            original = name.removeprefix('research-')
            directory = out/name
            _, result, code = launch(args.qemu, args.plugin, guests[original]['path'], directory,
                                     repair=original == 'repair', analysis_policy='research')
            attempts = validate_case(original, directory, result, code, guests[original])
            for index, attempt in enumerate(attempts):
                run = directory/f'session/iterations/{index:04d}/run'
                checked = verify(run/'retirement-evidence', expected_sha256=attempt['bundle_sha256'])
                decision = checked['analysis_quality']
                p.require(decision['status'] == 'accepted' and decision['policy']['mode'] == 'research' and
                          'unverified_flags' in decision['limitations'], 'Research decision lost its observed limitations')
                attempt['analysis_quality'] = decision
            report['cases'].append({'name': name, 'status': 'passed', 'attempts': attempts})
            p.write_json(out/'report.json', report)
            print(name+': passed', flush=True)
        directory = out/'strict-reject'
        prepared, result, code = launch(args.qemu, args.plugin, guests['normal']['path'], directory,
                                        analysis_policy='strict')
        record = refused(directory, prepared, result, code)
        run = Path(record['run_dir'])
        capsule = read_json(run/'config/capsule_result.json')
        digest = capsule['portable_evidence']['manifest_sha256']
        checked = verify(run/'retirement-evidence', expected_sha256=digest)
        decision = checked['analysis_quality']
        p.require(record['supervisor']['qemu_exit'] == 88 and checked['attempt_outcome'] == 'failed' and
                  checked['phase1_retirement']['phase1_retired'] is False and
                  decision['status'] == 'rejected' and decision['policy']['mode'] == 'strict' and
                  'unverified_flags' in decision['rejection_reasons'], 'Strict policy did not deny retirement')
        record.update(name='strict-reject', status='passed', bundle_sha256=digest, analysis_quality=decision)
        report['cases'].append(record)
        print('strict-reject: passed', flush=True)
        report['status'] = 'passed'
    except Exception as exc:
        report.update(error=f'{type(exc).__name__}: {exc}', traceback=traceback.format_exc())
    report['runtime_unchanged'] = p.sha(args.qemu) == report['qemu_sha256'] and p.sha(args.plugin) == report['phase1_sha256']
    if not report['runtime_unchanged']: report['status'] = 'failed'
    p.write_json(out/'report.json', report)
    return 0 if report['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
