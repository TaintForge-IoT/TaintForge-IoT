import argparse
import json
from pathlib import Path

from experiments.execution_capsule_probe import controller as p
from scripts import collect_input_retirement_evidence as base
from scripts import collect_capsule_analysis_evidence as analysis
from scripts.audit_capsule_strict_evidence import audit
from scripts.inject_capsule_lifecycle_fault import CASES, at_boundary
from scripts.run_capsule_lifecycle_e2e import PROFILE
from scripts.run_capsule_lifecycle_tests import SOURCES
from taintforge_env import capsule_resources as resources, retirement_mappings as mappings, phase1_retirement as retirement
from taintforge_env.phase1_runtime import read_json

PATTERNS = base.PATTERNS + ('e2e/*/fault-helper.log',) + tuple('analysis/'+name for name in analysis.PATTERNS)


def check_results(root):
    analysis.check_results(root/'analysis')
    tests = read_json(root/'validation/lifecycle-tests.json')
    project = Path(__file__).resolve().parents[1]
    p.require(tests['successful'] is True and tests['tests_run'] == tests['tests_expected'] >= 25 and
              all(tests[k] == 0 for k in ('skipped', 'failures', 'errors')) and
              tests['native_qemu_faults_tested_by_this_suite'] is False and
              tests['source_sha256'] == {name: p.sha(project/name) for name in SOURCES},
              'Lifecycle component tests or sources are incomplete')
    report = read_json(root/'e2e/report.json')
    previous = read_json(root/'analysis/e2e/report.json')
    p.require(report['profile'] == PROFILE and report['status'] == 'passed' and
              report['runtime_unchanged'] is True and list(CASES) == [c['name'] for c in report['cases']] and
              all(report[k] == previous[k] for k in ('qemu_sha256', 'phase1_sha256')) and
              report['native_cleanup_interruption_tested'] is False and
              report['native_strict_positive_verified'] is False, 'Native lifecycle matrix is incomplete')
    for case in report['cases']:
        name = case['name']
        directory = root/'e2e'/name
        run = directory/'session/iterations/0000/run'
        binding = read_json(run/'config/capsule_binding.json')
        workers = read_json(run/'logs/capsule/workers.json')
        injection = read_json(directory/'fault-injection.json')
        role, point = CASES[name]
        identity = {k: binding[k] for k in mappings.IDENTITY}
        journal = read_json(run/'logs/capsule/observer-events.json')
        before = injection['pre_signal_journal']['events']
        p.require(case['status'] == 'passed' and case['injection'] == injection and
                  injection['status'] == 'injected' and injection['signal'] == 'SIGKILL' and
                  injection['case'] == name and injection['identity'] == workers['identity'] == identity and
                  injection['unit'] == workers['unit'] == resources.unit_name(binding) and
                  injection['point'] == point and injection['target']['role'] == role and
                  at_boundary(injection['pre_signal_journal'], point) and
                  journal['events'][:len(before)] == before, 'Lifecycle fault identity or boundary changed')
        target = injection['target']
        p.require(target['namespace_pid'] == (workers['qemu_pid'] if role == 'qemu' else workers['workers'][role]) and
                  target['pid_namespace'] == workers['pid_namespace'] and
                  target['parent_pid'] == target['supervisor_host_pid'] and
                  target['cgroup'] == '0::/system.slice/'+resources.unit_name(binding) and
                  type(target['pid']) is int and target['pid'] > 0 and
                  type(target['start_ticks']) is int and target['start_ticks'] > 0,
                  'Injected process was not a bound capsule child')
        supervisor = read_json(run/'logs/capsule/supervisor.json')
        claim_path = run.parent/'execution_attempt.json'
        claim = read_json(claim_path)
        resume = read_json(directory/'resume_report.json')
        summary = read_json(run/'config/capsule_result.json')
        exit_code = supervisor['qemu_exit']
        p.require(type(exit_code) is int and supervisor['status'] == summary['status'] == 'failed' and
                  supervisor == case['supervisor'] and all(supervisor[k] == binding[k] for k in mappings.IDENTITY) and
                  claim['stage'] == 'failed' and claim['retry_safe'] is False and
                  claim['attempt_id'] == binding['attempt_id'] and p.sha(claim_path) == case['claim_sha256'] and
                  claim['guest_exit_code'] == (128-exit_code if exit_code < 0 else exit_code) and
                  resume['executions_this_invocation'] == case['resume_executions'] == 0,
                  'Failed lifecycle attempt was completed, changed or resumed')
        relocated = binding | {'run_dir': str(run)}
        resources.verify_saved(relocated, claim['guest_exit_code'])
        bundle = read_json(run/'config/analyzer_runtime/bundle.json')
        p.require(p.sha(run/'config/analyzer_runtime'/bundle['plugin']) == report['phase1_sha256'],
                  'Fault case used a different Phase 1 plugin')
        diagnostic = (run/'logs/qemu_strace.log').read_text(errors='replace')
        if point == 2:
            saved = read_json(run/'logs/capsule/phase1-retirement/retirement.json')
            retirement.check_packets(relocated, saved['events'], supervisor['qemu_pid'], complete=True)
            evidence = run/'logs/capsule/phase1-retirement'
            identity_record = read_json(evidence/'mapping-identity.json')
            maps = (evidence/'maps-unmapped.txt').read_text()
            mappings.verdict(identity_record, maps, True)
            unmap = next(e for e in journal['events'] if e['event'] == 'module_unmapped')
            p.require(unmap['maps_sha256'] == p.sha(evidence/'maps-unmapped.txt') and
                      unmap['process_stat_sha256'] == p.sha(evidence/'process-unmapped.stat') and
                      mappings.process_identity((evidence/'process-unmapped.stat').read_text()) ==
                      (supervisor['qemu_pid'], identity_record['process_start_ticks']),
                      'Post-unmap mapping evidence changed')
            p.require(saved['status'] == 'released' and saved['permit_sent'] is True and
                      saved['stream_closed'] is True and
                      [e['event'] for e in saved['events']] == ['verdict', 'export_complete',
                          'uninstall_requested', 'callbacks_removed', 'resources_released'] and
                      not any(e.get('command') == 'RESUME 2' for e in journal['events']) and
                      ('OBSERVER_ABORT code=125 reason=controller_lost' in diagnostic or
                       supervisor.get('worker_exit', {}).get('component') == 'observer'),
                      'Post-unmap observer fault did not stop continuation')
        else:
            p.require(not any(e.get('command') == 'RESUME 1' for e in journal['events']),
                      'Bootstrap fault was injected after continuation')
            saved_path = run/'logs/capsule/phase1-retirement/retirement.json'
            if saved_path.exists():
                p.require(read_json(saved_path)['permit_sent'] is False, 'Bootstrap fault received a permit')
            if role == 'qemu':
                p.require(exit_code == -9, 'QEMU did not receive the injected signal')
    first = previous['cases'][0]['attempts'][0]
    proof = root/'analysis/e2e/research-normal/session/iterations/0000/run/retirement-evidence'
    p.require(read_json(root/'validation/strict-audit.json') == audit(proof, first['bundle_sha256']),
              'Strict capability assessment differs from the verified export')


def collect(root, code):
    return base.collect(root, code, patterns=PATTERNS,
        required={'validation/lifecycle-tests.json', 'validation/lifecycle-tests.log',
                  'validation/analysis.log', 'validation/e2e.log', 'validation/strict-audit.json',
                  'analysis/e2e/report.json', 'e2e/report.json'},
        checker=check_results, kind='capsule-lifecycle-failure-acceptance')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--exit-code', type=int)
    parser.add_argument('--verify-only', action='store_true')
    args = parser.parse_args()
    if args.verify_only:
        if args.exit_code is not None:
            parser.error('--verify-only does not take --exit-code')
        check_results(args.out.absolute())
        print({'status': 'verified', 'profile': PROFILE})
        return 0
    if args.exit_code is None:
        parser.error('--exit-code is required')
    result = collect(args.out.absolute(), args.exit_code)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result['complete'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
