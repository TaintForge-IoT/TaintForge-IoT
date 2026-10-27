"""M4 budgets, execution credentials and saved resource evidence."""
from __future__ import annotations

import argparse
import ctypes
import json
import os
from pathlib import Path
import resource
import stat
import sys
import time

from experiments.execution_capsule_probe import controller as p
from . import retirement_mappings as mappings
from .phase1_runtime import read_json

PROFILE = 'capsule-hardening-m4-v1'
CONTEXT_KEYS = ('Uid', 'Gid', 'Groups', 'CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb', 'NoNewPrivs')


def policy(*, analysis_mib=512, export_mib=256, journal_mib=32, uid=65534, gid=65534):
    for value, maximum in ((analysis_mib, 131072), (export_mib, 512), (journal_mib, 256)):
        p.require(type(value) is int and 1 <= value <= maximum, 'Invalid M4 byte budget')
    p.require(type(uid) is int and type(gid) is int and 1 <= uid <= 2**31-1 and 1 <= gid <= 2**31-1,
              'M4 execution requires explicit non-root UID/GID')
    return {'profile': PROFILE, 'analysis_bytes': analysis_mib * 1024**2,
            'export_bytes': export_mib * 1024**2, 'journal_bytes': journal_mib * 1024**2,
            'uid': uid, 'gid': gid, 'poll_ms': 10, 'protected_control_channel': False}


def validate(config):
    expected = policy(analysis_mib=config['analysis_bytes']//1024**2,
        export_mib=config['export_bytes']//1024**2, journal_mib=config['journal_bytes']//1024**2,
        uid=config['uid'], gid=config['gid'])
    p.require(config == expected, 'Unsupported M4 policy')
    return config


def config(binding):
    return validate(binding['settings']['hardening'])


def private_controls(root):
    directory = Path(root) / 'config'
    for name in ('capsule_binding.json', 'phase1_binding.json', 'observer-contract.json', 'input-attempt.json'):
        path = directory / name
        info = path.lstat()
        p.require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, 'Unsafe control file: ' + name)
        path.chmod(0o600)
    directory.chmod(0o700)


def controls_record(run):
    result = {}
    for name in ('capsule_binding.json','phase1_binding.json','observer-contract.json','input-attempt.json'):
        path = Path(run) / 'config' / name
        info = path.lstat()
        p.require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o600,
                  'M4 control file is not private: ' + name)
        result[name] = {'sha256':p.sha(path), 'uid':info.st_uid, 'gid':info.st_gid, 'mode':'0600', 'links':1}
    return result


def prepare(binding, ipc):
    c = config(binding)
    root, run, ipc = Path(binding['rootfs']), Path(binding['run_dir']), Path(ipc)
    p.require(os.geteuid() == 0, 'M4 setup requires the privileged wrapper')
    p.require(not root.is_symlink() and root.is_dir() and not ipc.is_symlink() and ipc.is_dir(),
              'M4 setup requires real rootfs and IPC directories')
    for directory, names, files in os.walk(root, followlinks=False):
        if Path(directory) == root:
            names[:] = [n for n in names if n not in {'__taintforge', 'proc'}]
        os.chown(directory, c['uid'], c['gid'], follow_symlinks=False)
        for name in files:
            os.chown(Path(directory) / name, c['uid'], c['gid'], follow_symlinks=False)
        for name in names:
            path = Path(directory) / name
            if path.is_symlink(): os.chown(path, c['uid'], c['gid'], follow_symlinks=False)
    runtime = run / 'config/analyzer_runtime'
    for directory, names, files in os.walk(runtime, followlinks=False):
        Path(directory).chmod(0o555)
        for name in files:
            path = Path(directory) / name
            p.require(not path.is_symlink(), 'Symlink in analyzer runtime')
            path.chmod(0o555 if path.stat().st_mode & 0o111 else 0o444)
    phase = Path(read_json(run / 'config/phase1_binding.json')['output_directory'])
    p.require(phase == run / 'logs/phase1' and phase.is_dir() and not phase.is_symlink(),
              'Unbound M4 Phase 1 output directory')
    os.chown(phase, c['uid'], c['gid']); phase.chmod(0o700)
    os.chown(ipc, 0, c['gid']); ipc.chmod(0o710)
    private_controls(run)
    p.write_json(run / 'logs/capsule/m4-setup.json', {
        'schema': 1, 'profile': PROFILE, **identity(binding), 'setup_uid': os.geteuid(),
        'execution_uid': c['uid'], 'execution_gid': c['gid'], 'ipc_mode': '0710',
        'protected_control_channel': False, 'control_files': controls_record(run)})


def identity(binding):
    return {key: binding[key] for key in mappings.IDENTITY} | {'nonce': binding['lifecycle_attempt']}


def socket_permissions(path, binding):
    c = config(binding)
    os.chown(path, os.geteuid(), c['gid']); os.chmod(path, 0o660)


def peer_uid(binding):
    return config(binding)['uid'] if 'hardening' in binding.get('settings', {}) else os.geteuid()


def budget_usage(binding):
    c = config(binding)
    run = Path(binding['run_dir'])
    phase = (run / read_json(run / 'config/phase1_binding.json')['output_directory']).resolve()
    p.require(phase.is_relative_to(run.resolve()), 'M4 output directory escapes the attempt')
    export = journal = 0
    seen = set()
    for path in phase.iterdir():
        try: info = path.lstat()
        except FileNotFoundError: continue
        p.require(stat.S_ISREG(info.st_mode) and 1 <= info.st_nlink <= 2,
                  'Unsafe Phase 1 output during M4 budget check')
        key = (info.st_dev, info.st_ino)
        if key in seen: continue
        seen.add(key)
        if path.name.startswith('events.jsonl'): journal += info.st_size
        else: export += info.st_size
    for name in ('runtime_stdout.log', 'qemu_strace.log'):
        path = run / 'logs' / name
        if path.exists():
            info = path.lstat()
            p.require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, 'Unsafe runtime journal')
            journal += info.st_size
    controls = run / 'logs/capsule'
    for path in controls.rglob('*'):
        if 'export' in path.relative_to(controls).parts: continue
        try: info = path.lstat()
        except FileNotFoundError: continue
        if stat.S_ISDIR(info.st_mode): continue
        p.require(stat.S_ISREG(info.st_mode), 'Unsafe M4 controller journal')
        journal += info.st_size
    p.require(export <= c['export_bytes'], 'M4 export byte budget exceeded')
    p.require(journal <= c['journal_bytes'], 'M4 journal byte budget exceeded')
    return {'export_bytes': export, 'journal_bytes': journal}


def capture_context(binding, pid, point):
    c = config(binding)
    proc = Path(binding['rootfs']) / 'proc' / str(pid)
    before = (proc / 'stat').read_text()
    _, start = mappings.process_identity(before)
    status = (proc / 'status').read_text()
    mountinfo = (proc / 'mountinfo').read_text()
    namespaces = {name: os.readlink(proc / 'ns' / name) for name in ('mnt', 'pid', 'net', 'uts', 'ipc', 'user')}
    descriptors = []
    for path in sorted((proc / 'fd').iterdir(), key=lambda path: int(path.name)):
        try:
            descriptors.append({'fd': int(path.name), 'target': os.readlink(path),
                                'fdinfo': (proc / 'fdinfo' / path.name).read_text()})
        except FileNotFoundError:
            continue
    p.require(mappings.process_identity((proc / 'stat').read_text()) == (pid, start), 'QEMU identity changed during M4 snapshot')
    fields = dict(line.split(':', 1) for line in status.splitlines())
    values = {key: fields[key].strip() for key in CONTEXT_KEYS}
    item = {'schema': 1, 'profile': PROFILE, **identity(binding), 'pid': pid, 'start_ticks': start,
            'captured_monotonic_ns': time.monotonic_ns(),
            'point': point, 'credentials': values, 'status_text': status,
            'mountinfo': mountinfo, 'namespaces': namespaces, 'fds': descriptors,
            'protected_control_channel': False, 'fd_table_scope': 'shared_linux_user_host_process'}
    p.require(len(json.dumps(item).encode()) <= 1024**2, 'M4 execution context exceeds its byte budget')
    verify_context(binding, item, pid, point, start)
    path = Path(binding['run_dir']) / f'logs/capsule/execution-context-{point}.json'
    p.write_json(path, item)
    return {'execution_context_sha256': p.sha(path)}


def verify_context(binding, item, pid, point, start):
    c = config(binding)
    p.require(item['schema'] == 1 and item['profile'] == PROFILE and
              all(item[key] == value for key, value in identity(binding).items()) and
              item['pid'] == pid and item['point'] == point and item['start_ticks'] == start,
              'M4 context identity mismatch')
    p.require(type(item.get('captured_monotonic_ns')) is int and item['captured_monotonic_ns'] > 0,
              'Missing M4 context timestamp')
    values = item['credentials']
    fields = dict(line.split(':', 1) for line in item['status_text'].splitlines())
    p.require(values == {key: fields[key].strip() for key in CONTEXT_KEYS}, 'M4 credentials differ from raw status')
    p.require([int(n) for n in values['Uid'].split()] == [c['uid']]*4 and
              [int(n) for n in values['Gid'].split()] == [c['gid']]*4 and
              not values['Groups'].split() and values['NoNewPrivs'] == '1',
              'QEMU retained privileged credentials')
    p.require(all(int(values[key], 16) == 0 for key in ('CapInh','CapPrm','CapEff','CapBnd','CapAmb')),
              'QEMU retained capabilities')
    mounts = [line.split() for line in item['mountinfo'].splitlines()]
    tools = [line for line in mounts if line[4].endswith('/__taintforge')]
    p.require(tools and all({'ro','nosuid','nodev'} <= set(line[5].split(',')) for line in tools),
              'Analyzer runtime mount lacks required restrictions')
    p.require(item['protected_control_channel'] is False and
              item['fd_table_scope'] == 'shared_linux_user_host_process', 'M4 context overstates FD isolation')
    p.require(set(item['namespaces']) == {'mnt','pid','net','uts','ipc','user'} and
              all(isinstance(value,str) and value for value in item['namespaces'].values()), 'Missing M4 namespace identities')
    p.require(type(item['fds']) is list and len(item['fds']) <= 1024 and
              len({f['fd'] for f in item['fds']}) == len(item['fds']) and
              all(type(f['fd']) is int and f['fd'] >= 0 and isinstance(f['target'], str) and
                  isinstance(f['fdinfo'], str) for f in item['fds']), 'Invalid M4 FD inventory')


def verify_saved(binding, events, pid):
    c = config(binding)
    root = Path(binding['run_dir'])
    observations = []
    for point in (1, 2):
        event = next(e for e in events if e['event'] == 'maps_held' and e['point'] == point)
        path = root / f'logs/capsule/execution-context-{point}.json'
        p.require(p.sha(path) == event['execution_context_sha256'], 'M4 execution context changed')
        item = read_json(path, 1024**2)
        verify_context(binding, item, pid, point, event['process_start_ticks'])
        observations.append(item)
    p.require(observations[0]['namespaces'] == observations[1]['namespaces'], 'QEMU namespaces changed during retirement')
    setup = read_json(root / 'logs/capsule/m4-setup.json')
    p.require(setup['schema'] == 1 and setup['profile'] == PROFILE and
              all(setup[key] == value for key, value in identity(binding).items()) and
              setup['setup_uid'] == 0 and setup['execution_uid'] == c['uid'] and
              setup['execution_gid'] == c['gid'] and setup['ipc_mode'] == '0710' and
              setup['protected_control_channel'] is False, 'M4 setup differs from its contract')
    for name, item in setup['control_files'].items():
        p.require(name in {'capsule_binding.json','phase1_binding.json','observer-contract.json','input-attempt.json'} and
                  item['mode'] == '0600' and item['links'] == 1, 'Invalid M4 control file record')
        source = root / 'source' / name if name in {'capsule_binding.json','phase1_binding.json'} and (root/'source').is_dir() else root / 'config' / name
        p.require(p.sha(source) == item['sha256'], 'M4 control file changed since setup')
    p.require(len(setup['control_files']) == 4, 'Missing M4 control file records')
    phase = read_json(root/'source/phase1_binding.json' if (root/'source').is_dir() else root/'config/phase1_binding.json')
    prefix = phase['output_directory'].rstrip('/') + '/'
    def phase_fds(snapshot):
        return [f for f in snapshot['fds'] if prefix in f['target']]
    p.require(phase_fds(observations[0]) and not phase_fds(observations[1]),
              'Phase 1 output descriptors were not observed and released')
    usage = budget_usage(binding)
    return {'status': 'verified', 'profile': PROFILE, 'policy': c, 'usage': usage,
            'execution_uid': c['uid'], 'execution_gid': c['gid'], 'capabilities_zero': True,
            'contexts': [p.sha(root / f'logs/capsule/execution-context-{i}.json') for i in (1,2)],
            'phase1_output_fds_released': True,
            'protected_control_channel': False}


def verify_ledger(binding, release, report=None):
    c = config(binding)
    expected = {'schema','scope','limit_bytes','ledger_reserved_bytes','live_allocations','live_bytes',
                'peak_bytes','allocations','releases','wiped_bytes','external_allocations_tracked'}
    item = release.get('resource_ledger')
    p.require(isinstance(item, dict) and set(item) == expected and item['schema'] == 1 and
              item['scope'] == 'explicit_project_allocations' and item['external_allocations_tracked'] is False,
              'Missing M4 allocation ledger')
    for key in expected - {'scope','external_allocations_tracked'}:
        p.require(type(item[key]) is int and item[key] >= 0, 'Invalid M4 allocation counter')
    p.require(item['limit_bytes'] == c['analysis_bytes'] and item['live_allocations'] == item['live_bytes'] == 0 and
              item['allocations'] == item['releases'] > 0 and item['ledger_reserved_bytes'] > 0 and
              item['peak_bytes'] + item['ledger_reserved_bytes'] <= c['analysis_bytes'] and item['wiped_bytes'] > 0,
              'M4 release is incomplete or over budget')
    if report is not None:
        inventory = report.get('resource_inventory')
        p.require(isinstance(inventory, dict) and inventory['scope'] == item['scope'] and
                  inventory['limit_bytes'] == item['limit_bytes'] and inventory['external_allocations_tracked'] is False and
                  0 < inventory['allocations'] <= item['allocations'] and
                  inventory['peak_bytes'] <= item['peak_bytes'], 'M4 export lacks its allocation inventory')
        owners = inventory['owners']
        p.require(isinstance(owners, list) and 0 < len(owners) <= 64 and
                  len({o['source'] for o in owners}) == len(owners), 'Invalid M4 allocation owners')
        for key in ('live_allocations','live_bytes','allocations','releases'):
            p.require(all(type(o[key]) is int and o[key] >= 0 for o in owners) and
                      sum(o[key] for o in owners) == inventory[key], 'M4 owner totals disagree')
    return item


def launch(binding, argv, *, direct_qemu=False):
    p.require(type(direct_qemu) is bool, 'Invalid M4 direct-QEMU mode')
    p.require(not direct_qemu or binding.get('profile') == 'dse-file-analysis-v1',
              'Direct QEMU launch requires the isolated DSE profile')
    c = config(binding)
    p.require(os.geteuid() == 0, 'M4 launcher must enter the chroot before dropping privileges')
    root = Path(binding['rootfs'])
    executable = '/__taintforge/bin/qemu-i386' if direct_qemu else '/__taintforge/bin/loader'
    p.require(root.is_dir() and not root.is_symlink() and argv[0] == executable, 'Invalid M4 launch root/loader')
    libc = ctypes.CDLL(None, use_errno=True)
    prctl_call, capset = libc.prctl, libc.capset
    class Header(ctypes.Structure):
        _fields_ = [('version',ctypes.c_uint32),('pid',ctypes.c_int)]
    class Caps(ctypes.Structure):
        _fields_ = [('effective',ctypes.c_uint32),('permitted',ctypes.c_uint32),('inheritable',ctypes.c_uint32)]
    header, caps = Header(0x20080522,0), (Caps*2)()
    capset_args = ctypes.byref(header), ctypes.byref(caps)
    def prctl(option, value=0):
        if prctl_call(ctypes.c_int(option), ctypes.c_ulong(value), ctypes.c_ulong(0), ctypes.c_ulong(0), ctypes.c_ulong(0)) < 0:
            raise OSError(ctypes.get_errno(), 'M4 prctl failed')
    os.chroot(root); os.chdir('/')
    resource.setrlimit(resource.RLIMIT_CORE, (0,0))
    maximum = max(c['export_bytes'], c['journal_bytes'])
    resource.setrlimit(resource.RLIMIT_FSIZE, (maximum, maximum))
    resource.setrlimit(resource.RLIMIT_NOFILE, (1024,1024))
    prctl(38, 1)
    for cap in range(64):
        result = prctl_call(ctypes.c_int(23), ctypes.c_ulong(cap), ctypes.c_ulong(0), ctypes.c_ulong(0), ctypes.c_ulong(0))
        if result < 0:
            p.require(ctypes.get_errno() == 22, 'Cannot inspect capability bounding set')
            break
        if result: prctl(24, cap)
    prctl(47, 4)
    os.setgroups([]); os.setresgid(c['gid'], c['gid'], c['gid']); os.setresuid(c['uid'], c['uid'], c['uid'])
    if capset(*capset_args) < 0:
        raise OSError(ctypes.get_errno(), 'M4 capability clear failed')
    p.require(os.getresuid() == (c['uid'],)*3 and os.getresgid() == (c['gid'],)*3 and not os.getgroups(),
              'M4 credential drop failed')
    env = {'PATH':'/usr/bin:/bin','HOME':'/','LANG':'C','LC_ALL':'C'}
    if direct_qemu:
        env['LD_LIBRARY_PATH'] = '/__taintforge/lib'
    os.execve(argv[0], argv, env)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('prepare','launch'))
    parser.add_argument('--binding', type=Path, required=True)
    parser.add_argument('--ipc', type=Path)
    values = sys.argv[1:]
    index = values.index('--') if '--' in values else len(values)
    args = parser.parse_args(values[:index])
    command = values[index+1:]
    binding = read_json(args.binding)
    if args.action == 'prepare':
        p.require(args.ipc is not None and not command, 'Invalid M4 setup arguments')
        prepare(binding, args.ipc)
    else:
        p.require(command, 'Missing M4 command')
        launch(binding, command)


if __name__ == '__main__':
    main()
