"""Collect M5 and analysis admission evidence without accepting partial runs."""
import argparse
import json
from pathlib import Path

from experiments.execution_capsule_probe import controller as p
from scripts import collect_input_retirement_evidence as base
from scripts import collect_capsule_control_evidence as m5
from scripts.run_capsule_analysis_e2e import CASES
from scripts.run_capsule_analysis_tests import SOURCES
from taintforge_env.analysis_quality import PROFILE
from taintforge_env.phase1_runtime import read_json
from taintforge_env.retirement_evidence import verify

PATTERNS = base.PATTERNS + tuple('m5/'+name for name in m5.PATTERNS)


def check_results(root):
    m5.check_results(root/'m5')
    tests = read_json(root/'validation/analysis-tests.json')
    p.require(tests['successful'] is True and tests['tests_run'] == tests['tests_expected'] >= 22 and
              all(tests[k] == 0 for k in ('skipped', 'failures', 'errors')), 'Analysis tests are incomplete')
    project = Path(__file__).resolve().parents[1]
    p.require(tests['source_sha256'] == {name: p.sha(project/name) for name in SOURCES},
              'Analysis verifier sources differ from the tested package')
    report = read_json(root/'e2e/report.json')
    control = read_json(root/'m5/e2e/report.json')
    p.require(report['profile'] == PROFILE and report['status'] == 'passed' and
              all(report[k] == control[k] for k in ('qemu_sha256', 'phase1_sha256')) and
              report['runtime_unchanged'] is True and [c['name'] for c in report['cases']] == list(CASES) and
              all(report[k] is False for k in ('oep_proven', 'complete_program_analysis', 'hostile_sample_ready')) and
              report['input_build_sha256'] == p.sha(root/'e2e/inputs/build.json'), 'Analysis E2E matrix is incomplete')
    for case in report['cases']:
        p.require(case['status'] == 'passed', 'Analysis E2E case did not pass')
        denied = case['name'] == 'strict-reject'
        attempts = [case] if denied else case['attempts']
        p.require(len(attempts) == (2 if case['name'] == 'research-repair' else 1), 'Analysis attempt count changed')
        for index, attempt in enumerate(attempts):
            run = root/f'e2e/{case["name"]}/session/iterations/{index:04d}/run'
            checked = verify(run/'retirement-evidence', expected_sha256=attempt['bundle_sha256'])
            binding = read_json(run/'retirement-evidence/source/capsule_binding.json')
            decision = checked['analysis_quality']
            p.require('control_guard' in binding['settings'] and 'hardening' in binding['settings'] and
                      decision['plugin_sha256'] == report['phase1_sha256'] and
                      json.dumps(decision, sort_keys=True) == json.dumps(attempt['analysis_quality'], sort_keys=True) and
                      decision['policy']['mode'] == ('strict' if denied else 'research') and
                      decision['status'] == ('rejected' if denied else 'accepted') and
                      checked['attempt_outcome'] == ('failed' if denied else 'passed'), 'Analysis policy or outcome changed')
            claim_path = run.parent/'execution_attempt.json'
            claim = read_json(claim_path)
            service = read_json(run/'logs/capsule/service.json')
            p.require(service['tree_empty'] is True and service['attempt_id'] == binding['attempt_id'] and
                      service['attempt_contract_sha256'] == binding['attempt_contract_sha256'] and
                      claim['attempt_id'] == binding['attempt_id'] and claim['retry_safe'] is False,
                      'Analysis attempt identity or cleanup changed')
            if denied:
                resume = read_json(root/f'e2e/{case["name"]}/resume_report.json')
                p.require(p.sha(claim_path) == case['claim_sha256'] and claim['stage'] == 'failed' and
                          claim['guest_exit_code'] == 88 and resume['executions_this_invocation'] == 0 and
                          checked['phase1_retirement']['status'] == 'denied' and
                          checked['phase1_retirement']['phase1_retired'] is False,
                          'Analysis refusal was resumed or claimed as retirement')
            else:
                p.require(p.sha(claim_path) == attempt['execution_claim_sha256'], 'Research execution claim changed')


def collect(root, code):
    return base.collect(root, code, patterns=PATTERNS,
        required={'validation/analysis-tests.json', 'validation/analysis-tests.log',
                  'validation/m5.log', 'validation/e2e.log', 'm5/e2e/report.json', 'e2e/report.json'},
        checker=check_results, kind='capsule-analysis-acceptance')


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
    result = collect(args.out.absolute(), args.exit_code)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result['complete'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
