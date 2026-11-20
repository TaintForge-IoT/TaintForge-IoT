import argparse
from pathlib import Path
import subprocess
import sys
import traceback

from experiments.execution_capsule_probe import controller as p
from experiments.input_retirement.cases import build_guests
from scripts.inject_capsule_lifecycle_fault import CASES, at_boundary
from scripts.run_capsule_hardening_e2e import refused
from scripts.run_unified_pipeline import parser as unified_parser, prepare, run_session
from taintforge_env.phase1_runtime import read_json

PROFILE = 'capsule-lifecycle-failures-v1'


def launch_fault(qemu, plugin, binary, directory, name):
    goal = directory.parent/(directory.name+'-goal.json')
    p.write_json(goal, {'schema_version': 1, 'goal_id': 'capsule-lifecycle',
        'description': 'Benign guest completes', 'mode': 'all', 'rules': [{
            'id': 'stdout', 'type': 'text_contains', 'source': 'stdout',
            'needle': 'M3_INPUT_OK\n', 'min_count': 1}]})
    args = unified_parser().parse_args(['run', '--retire-phase1', '--capsule-hardening',
        '--capsule-control-guard', '--analysis-policy', 'research', '--capsule-hold-ms', '1000',
        '--binary', str(binary), '--qemu', str(qemu), '--plugin', str(plugin),
        '--out', str(directory), '--target-spec', str(goal), '--max-iterations', '1'])
    prepared = prepare(args)
    with (directory/'fault-helper.log').open('wb') as log:
        process = subprocess.Popen(['sudo', '-n', sys.executable, '-m',
            'scripts.inject_capsule_lifecycle_fault', '--case-dir', str(directory), '--case', name],
            cwd=Path(__file__).resolve().parents[1], stdin=subprocess.DEVNULL,
            stdout=log, stderr=subprocess.STDOUT)
        try:
            result, code = run_session(directory, prepared, max_steps=1)
        finally:
            (directory/'fault-cancel').touch()
            process.wait(timeout=40)
    injection = read_json(directory/'fault-injection.json')
    p.require(process.returncode == 0 and injection['status'] == 'injected' and
              at_boundary(injection['pre_signal_journal'], CASES[name][1]),
              'Requested lifecycle fault was not injected: '+str(injection.get('error')))
    record = refused(directory, prepared, result, code)
    run = Path(record['run_dir'])
    supervisor = record['supervisor']
    journal = read_json(run/'logs/capsule/observer-events.json')
    p.require(supervisor['status'] == 'failed', 'Killed lifecycle attempt was accepted')
    diagnostic = (run/'logs/qemu_strace.log').read_text(errors='replace')
    if name == 'kill-observer-after-unmap':
        p.require(not any(e.get('command') == 'RESUME 2' for e in journal['events']) and
                  ('OBSERVER_ABORT code=125 reason=controller_lost' in diagnostic or
                   supervisor.get('worker_exit', {}).get('component') == 'observer'),
                  'Observer loss did not stop the post-unmap hold')
        saved = read_json(run/'logs/capsule/phase1-retirement/retirement.json')
        p.require(saved['status'] == 'released', 'Observer fault preceded real resource release')
    else:
        p.require(not any(e.get('command') == 'RESUME 1' for e in journal['events']),
                  'Before-permit fault missed the bootstrap hold')
        saved_path = run/'logs/capsule/phase1-retirement/retirement.json'
        if saved_path.exists():
            p.require(read_json(saved_path)['permit_sent'] is False, 'Killed bootstrap attempt received a permit')
        if name == 'kill-qemu-before-permit':
            p.require(supervisor['qemu_exit'] == -9, 'QEMU was not terminated by the injected signal')
    return record | {'name': name, 'status': 'passed', 'injection': injection}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--qemu', type=Path, required=True)
    parser.add_argument('--plugin', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    out = args.out.absolute(); out.mkdir(parents=True, exist_ok=False)
    report = {'schema': 1, 'profile': PROFILE, 'status': 'failed', 'cases': [],
        'qemu_sha256': p.sha(args.qemu), 'phase1_sha256': p.sha(args.plugin),
        'scope': 'benign_static_i386_systemd_controller_and_process_failure',
        'native_cleanup_interruption_tested': False, 'native_strict_positive_verified': False}
    try:
        guests = build_guests(out/'inputs')
        for name in CASES:
            report['cases'].append(launch_fault(args.qemu, args.plugin, guests['normal']['path'], out/name, name))
            p.write_json(out/'report.json', report)
            print(name+': passed', flush=True)
        report['status'] = 'passed'
    except Exception as exc:
        report.update(error=f'{type(exc).__name__}: {exc}', traceback=traceback.format_exc())
    report['runtime_unchanged'] = p.sha(args.qemu) == report['qemu_sha256'] and p.sha(args.plugin) == report['phase1_sha256']
    if not report['runtime_unchanged']:
        report['status'] = 'failed'
    p.write_json(out/'report.json', report)
    return 0 if report['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
