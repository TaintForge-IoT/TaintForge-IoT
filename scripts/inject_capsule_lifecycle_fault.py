import argparse
import os
from pathlib import Path
import signal
import time

from experiments.execution_capsule_probe import controller as p
from taintforge_env import capsule_resources as resources, retirement_mappings as mappings
from taintforge_env.phase1_runtime import read_json

CASES = {'kill-permit-before-permit': ('permit', 1),
         'kill-qemu-before-permit': ('qemu', 1),
         'kill-observer-after-unmap': ('observer', 2)}


def at_boundary(journal, point):
    events = journal['events']
    return (any(e.get('event') == 'maps_held' and e.get('point') == point for e in events) and
            not any(e.get('command') == 'RESUME '+str(point) for e in events) and
            (point != 2 or any(e.get('event') == 'module_unmapped' for e in events)))


def target_identity(binding, record, role, *, proc=Path('/proc'), cgroup=resources.CGROUP):
    unit = resources.unit_name(binding)
    p.require(type(record['schema']) is int and record['schema'] == 1 and record['pid_scope'] == 'sandbox_pid_namespace' and
              record['unit'] == unit and record['identity'] == {k: binding[k] for k in mappings.IDENTITY},
              'Fault target belongs to another attempt')
    expected = record['qemu_pid'] if role == 'qemu' else record['workers'][role]
    p.require(all(type(value) is int and value > 0 for value in
                  (expected, record['supervisor_pid'], record['supervisor_start_ticks'])),
              'Invalid fault process coordinates')
    expected_group = '0::/system.slice/'+unit
    members = (cgroup/'system.slice'/unit/'cgroup.procs').read_text().splitlines()
    processes = []
    for value in members:
        p.require(value.isdecimal(), 'Invalid cgroup process identity')
        pid = int(value)
        directory = proc/value
        try:
            status = dict(line.split(':', 1) for line in (directory/'status').read_text().splitlines())
            stat_pid, start = mappings.process_identity((directory/'stat').read_text())
            group = (directory/'cgroup').read_text().splitlines()
            namespace = os.readlink(directory/'ns/pid')
        except FileNotFoundError:
            continue
        p.require(stat_pid == pid, 'Process identity changed')
        if group == [expected_group] and namespace == record['pid_namespace']:
            processes.append({'pid': pid, 'namespace_pid': int(status['NSpid'].split()[-1]),
                'parent_pid': int(status['PPid']), 'start_ticks': start, 'pid_namespace': namespace,
                'cgroup': expected_group})
    supervisors = [item for item in processes if item['namespace_pid'] == record['supervisor_pid'] and
                   item['start_ticks'] == record['supervisor_start_ticks']]
    p.require(len(supervisors) == 1, 'Bound capsule supervisor not found')
    targets = [item for item in processes if item['namespace_pid'] == expected and
               item['parent_pid'] == supervisors[0]['pid']]
    p.require(len(targets) == 1, 'Bound capsule child not found')
    return targets[0] | {'supervisor_host_pid': supervisors[0]['pid'], 'role': role}


def inject(case_dir, name):
    role, point = CASES[name]
    case_dir = Path(case_dir).absolute()
    p.require('..' not in case_dir.parts and case_dir != Path('/'), 'Invalid fault case path')
    run = case_dir/'session/iterations/0000/run'
    deadline = time.monotonic()+35
    while time.monotonic() < deadline:
        p.require(not (case_dir/'fault-cancel').exists(), 'Fault injection cancelled')
        paths = (run/'config/capsule_binding.json', run/'logs/capsule/workers.json',
                 run/'logs/capsule/observer-events.json')
        if not all(path.exists() for path in paths):
            time.sleep(.005)
            continue
        binding, record, journal = (read_json(path, 256*1024) for path in paths)
        p.require(Path(binding['run_dir']) == run and
                  'analysis_policy' in binding['settings'] and 'control_guard' in binding['settings'],
                  'Fault case requires its bound analysis and control profile')
        if not at_boundary(journal, point):
            time.sleep(.005)
            continue
        target = target_identity(binding, record, role)
        descriptor = os.pidfd_open(target['pid'])
        try:
            p.require(target_identity(binding, record, role) == target, 'Fault target changed after pidfd open')
            journal = read_json(run/'logs/capsule/observer-events.json', 256*1024)
            p.require(not (case_dir/'fault-cancel').exists() and at_boundary(journal, point),
                      'Requested fault boundary was missed or cancelled')
            signal.pidfd_send_signal(descriptor, signal.SIGKILL)
        finally:
            os.close(descriptor)
        return {'schema': 1, 'case': name, 'status': 'injected', 'signal': 'SIGKILL',
            'identity': record['identity'], 'unit': record['unit'], 'point': point,
            'target': target, 'pre_signal_journal': journal, 'injected_monotonic_ns': time.monotonic_ns()}
    raise TimeoutError('Capsule fault boundary deadline')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--case-dir', type=Path, required=True)
    parser.add_argument('--case', choices=CASES, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    result = {'schema': 1, 'case': args.case, 'status': 'failed'}
    try:
        result.update(inject(args.case_dir, args.case))
    except Exception as exc:
        result['error'] = f'{type(exc).__name__}: {exc}'[:3000]
    path = args.case_dir/'fault-injection.json'
    p.write_json(path, result)
    owner = args.case_dir.stat()
    os.chown(path, owner.st_uid, owner.st_gid)
    return 0 if result['status'] == 'injected' else 1


if __name__ == '__main__':
    raise SystemExit(main())
