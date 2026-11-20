"""Collect M4 and strict control-guard acceptance evidence."""
import argparse
import json
from pathlib import Path

from experiments.capsule_control.check import CASES
from experiments.execution_capsule_probe import controller as p
from scripts import collect_input_retirement_evidence as base
from scripts import collect_capsule_hardening_evidence as m4
from scripts.run_capsule_control_e2e import ATTACKS
from taintforge_env.capsule_control import PROFILE, private_prefix, verify_snapshot
from taintforge_env.phase1_runtime import read_json
from taintforge_env.retirement_evidence import verify

PATTERNS = base.PATTERNS+tuple('m4/'+v for v in base.PATTERNS+m4.EXTRA_PATTERNS)+(
    'components/report.json', 'components/build/*', 'components/*/*.log', 'components/*/guest-i386',
    'components/*/*.S', 'components/*/*.inc', 'e2e/probes/**/*')


def check_results(root):
    m4.check_results(root/'m4')
    tests = read_json(root/'validation/control-tests.json')
    p.require(tests['successful'] is True and tests['tests_run'] == tests['tests_expected'] >= 8 and
              all(tests[k] == 0 for k in ('skipped', 'failures', 'errors')), 'Control tests are incomplete')
    components = read_json(root/'components/report.json')
    expected = [('write', False)]+[(name, True) for name in CASES]
    p.require(components['status'] == 'passed' and components['profile'] == PROFILE and
              components['unsafe_stdin_rejected'] is True and
              [(c['name'], c['guarded']) for c in components['cases']] == expected and
              all(c['status'] == 'passed' for c in components['cases']), 'Control component matrix is incomplete')
    report = read_json(root/'e2e/report.json')
    p.require(report['profile'] == PROFILE and report['status'] == 'passed' and
              report['runtime_unchanged'] is True and report['m4_end_to_end_verified'] is True and
              [c['name'] for c in report['cases']] == ['normal', 'repair']+[a[0] for a in ATTACKS],
              'Guarded E2E matrix is incomplete')
    for case in report['cases']:
        p.require(case['status'] == 'passed', 'Guarded E2E case did not pass')
        if case['name'] in {'normal', 'repair'}:
            p.require(len(case['attempts']) == (2 if case['name'] == 'repair' else 1), 'Guarded attempt count changed')
            for index, attempt in enumerate(case['attempts']):
                run = root/f'e2e/{case["name"]}/session/iterations/{index:04d}/run'
                checked = verify(run/'retirement-evidence', expected_sha256=attempt['bundle_sha256'])
                p.require(checked['attempt_outcome'] == 'passed', 'Guarded portable proof did not pass')
                binding = read_json(run/'retirement-evidence/source/capsule_binding.json')
                p.require('control_guard' in binding['settings'], 'Guard was disabled in portable proof')
        else:
            directory = root/'e2e'/case['name']
            run = directory/'session/iterations/0000/run'
            claim = read_json(run.parent/'execution_attempt.json')
            service = read_json(run/'logs/capsule/service.json')
            supervisor = read_json(run/'logs/capsule/supervisor.json')
            resume = read_json(directory/'resume_report.json')
            binding = read_json(run/'config/capsule_binding.json')
            p.require(p.sha(run.parent/'execution_attempt.json') == case['claim_sha256'] and
                      claim['stage'] == 'failed' and claim['retry_safe'] is False and
                      claim['guest_exit_code'] == supervisor['qemu_exit'] == 126 and
                      service['tree_empty'] is True and resume['executions_this_invocation'] == 0,
                      'Guard refusal is not terminal or was not cleaned up')
            journal = read_json(run/'logs/capsule/observer-events.json')['events']
            p.require(journal and any(e['event'] == 'module_unmapped' for e in journal) is case['after_retirement'],
                      'Guard refusal retirement boundary changed')
            p.require(not case['after_retirement'] or
                      any(e['event'] == 'resumed' and e['point'] == 2 for e in journal),
                      'Guard refusal has no post-retirement resume')
            for item in journal:
                if item['event'] == 'snapshot':
                    verify_snapshot(item.get('control_guard'), private=private_prefix(binding))
            trace = (run/'logs/qemu_strace.log').read_text(errors='replace')
            p.require('CAPSULE_GUARD_ABORT code=126 reason='+case['reason']+'\n' in trace, 'Guard refusal diagnosis changed')


def collect(root, code):
    return base.collect(root, code, patterns=PATTERNS,
        required={'validation/control-tests.json', 'validation/control-tests.log', 'components/report.json',
                  'e2e/report.json', 'm4/e2e/report.json', 'm4/extra/report.json'},
        checker=check_results, kind='m5-control-acceptance')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--exit-code', type=int)
    parser.add_argument('--verify-only', action='store_true')
    args = parser.parse_args()
    if args.verify_only:
        if args.exit_code is not None: parser.error('--verify-only does not take --exit-code')
        check_results(args.out.absolute())
        print({'status': 'verified', 'profile': PROFILE})
        return 0
    if args.exit_code is None: parser.error('--exit-code is required for collection')
    result = collect(args.out, args.exit_code)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result['complete'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
