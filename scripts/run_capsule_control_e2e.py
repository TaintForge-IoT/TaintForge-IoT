"""Guarded M4 attempts with benign static i386 inputs."""
import argparse
from pathlib import Path
import traceback

from experiments.capsule_control.check import CASES, build_guest
from experiments.execution_capsule_probe import controller as p
from experiments.input_retirement.cases import build_guests
from scripts.run_capsule_hardening_e2e import refused
from scripts.run_input_retirement_e2e import validate_case
from scripts.run_unified_pipeline import parser as unified_parser, prepare, run_session
from taintforge_env.capsule_control import PROFILE, private_prefix, verify_snapshot
from taintforge_env.phase1_runtime import read_json

ATTACKS = [('write-before', 'write', False), ('write-after', 'write', True),
           ('dup2-after', 'dup2-target', True), ('proc-after', 'proc-fd', True),
           ('control-path-after', 'control-path', True), ('export-path-after', 'export-path', True),
           ('socket-after', 'socketcall', True)]


def launch(qemu, plugin, binary, out, *, repair=False, analysis_policy='research'):
    goal = out.parent/(out.name+'-goal.json')
    p.write_json(goal, {'schema_version': 1, 'goal_id': 'capsule-control', 'description': 'Benign guest output',
        'mode': 'all', 'rules': [{'id': 'stdout', 'type': 'text_contains', 'source': 'stdout',
                                'needle': 'M3_INPUT_OK\n', 'min_count': 1}]})
    args = unified_parser().parse_args(['run', '--retire-phase1', '--analysis-policy', analysis_policy, '--capsule-hardening',
        '--capsule-control-guard', '--binary', str(binary), '--qemu', str(qemu), '--plugin', str(plugin),
        '--out', str(out), '--target-spec', str(goal), '--max-iterations', '3' if repair else '1'])
    prepared = prepare(args)
    result, code = run_session(out, prepared, max_steps=2 if repair else 1)
    return prepared, result, code


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qemu', required=True, type=Path)
    parser.add_argument('--plugin', required=True, type=Path)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    out = args.out.absolute(); out.mkdir(parents=True, exist_ok=False)
    report = {'schema': 1, 'profile': PROFILE, 'status': 'failed', 'cases': [],
              'm4_end_to_end_verified': False, 'memory_isolation': False,
              'protected_control_channel': False, 'hostile_sample_ready': False,
              'qemu_sha256': p.sha(args.qemu), 'phase1_sha256': p.sha(args.plugin)}
    try:
        guests = build_guests(out/'inputs')
        for name in ('normal', 'repair'):
            directory = out/name
            prepared, result, code = launch(args.qemu, args.plugin, guests[name]['path'], directory, repair=name == 'repair')
            attempts = validate_case(name, directory, result, code, guests[name])
            for attempt in attempts:
                capsule = read_json(Path(attempt['run_dir'])/'config/capsule_result.json')
                p.require(capsule['control_guard']['status'] == 'verified', 'Native control guard was not finalized')
            report['cases'].append({'name': name, 'status': 'passed', 'attempts': attempts})
            p.write_json(out/'report.json', report)
            print(name+': passed', flush=True)
        normal = Path(report['cases'][0]['attempts'][0]['run_dir'])
        context = read_json(normal/'logs/capsule/execution-context-2.json')
        descriptors = [f['fd'] for f in context['fds'] if f['fd'] > 2]
        p.require(descriptors, 'No actual native descriptor observed after retirement')
        probe_fd = min(descriptors)
        for name, probe, unpack in ATTACKS:
            directory = out/name
            target = directory/'session/iterations/0000/run'
            paths = {'private_path': target/'logs/phase1/events.jsonl', 'public_path': '/tmp/control-input',
                     'symlink_path': '/tmp/control-link', 'hardlink_path': '/tmp/control-hardlink',
                     'traversal_path': '/tmp/../__taintforge_capsule/observer.sock'}
            binary = build_guest(out/'probes'/name, probe, paths, fd=probe_fd, unpack=unpack)
            prepared, result, code = launch(args.qemu, args.plugin, binary, directory)
            record = refused(directory, prepared, result, code)
            run = Path(record['run_dir'])
            binding = read_json(run/'config/capsule_binding.json')
            diagnostic = (run/'logs/qemu_strace.log').read_text(errors='replace')
            p.require(record['supervisor']['qemu_exit'] == 126 and
                      'CAPSULE_GUARD_ABORT code=126 reason='+CASES[probe][1]+'\n' in diagnostic,
                      'Expected native guard refusal was not observed')
            journal = read_json(run/'logs/capsule/observer-events.json')['events']
            snapshots = [e for e in journal if e['event'] == 'snapshot']
            p.require(snapshots, 'Guard refusal has no verified bootstrap')
            for item in snapshots:
                verify_snapshot(item.get('control_guard'), private=private_prefix(binding))
            p.require(any(e['event'] == 'module_unmapped' for e in journal) is unpack,
                      'Guard refusal happened on the wrong side of retirement')
            p.require(not unpack or (any(e['point'] == 2 for e in snapshots) and
                      any(e['event'] == 'resumed' and e['point'] == 2 for e in journal)),
                      'Guard refusal preceded the verified second resume')
            point = 2 if unpack else 1
            observed = read_json(run/f'logs/capsule/execution-context-{point}.json')
            record.update(name=name, status='passed', reason=CASES[probe][1], after_retirement=unpack,
                          probe_fd=probe_fd, target_fd_observed=any(f['fd'] == probe_fd for f in observed['fds']))
            report['cases'].append(record)
            p.write_json(out/'report.json', report)
            print(name+': passed', flush=True)
        report.update(status='passed', m4_end_to_end_verified=True)
    except Exception as exc:
        report.update(error=f'{type(exc).__name__}: {exc}', traceback=traceback.format_exc())
    report['runtime_unchanged'] = (p.sha(args.qemu) == report['qemu_sha256'] and p.sha(args.plugin) == report['phase1_sha256'])
    if not report['runtime_unchanged']: report.update(status='failed', m4_end_to_end_verified=False)
    p.write_json(out/'report.json', report)
    return 0 if report['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
