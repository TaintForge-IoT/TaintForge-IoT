"""Build and run benign control-resource probes with QEMU."""
import json
import os
from pathlib import Path
import shlex
import subprocess

from experiments.execution_capsule_probe import controller as p
from taintforge_env.capsule_control import PROFILE, verify_snapshot

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
CASES = {
    'write': (0, 'non_guest_fd'), 'read': (1, 'non_guest_fd'),
    'close': (2, 'non_guest_fd'), 'dup': (3, 'non_guest_fd'),
    'dup2-target': (4, 'non_guest_fd'), 'fcntl': (5, 'non_guest_fd'),
    'fcntl64-dup': (6, 'non_guest_fd'), 'mmap2-fd': (7, 'non_guest_fd'),
    'mmap-fd': (8, 'non_guest_fd'), 'writev': (9, 'non_guest_fd'),
    'pwrite64': (10, 'non_guest_fd'), 'sendfile': (11, 'unsupported_syscall'),
    'socketcall': (12, 'unsupported_syscall'), 'close-range': (13, 'unsupported_syscall'),
    'proc-fd': (14, 'private_path'), 'control-path': (15, 'private_path'),
    'export-path': (16, 'private_path'), 'symlink': (17, 'symlink_path'),
    'traversal': (18, 'noncanonical_path'), 'relative-path': (19, 'noncanonical_path'),
    'unknown-syscall': (20, 'unsupported_syscall'), 'guest-open-write': (21, None),
    'closed-guest-fd': (22, 'non_guest_fd'), 'guest-dup': (23, None),
    'guest-dup2': (24, None), 'invalid-pointer': (25, 'guest_pointer'),
    'unterminated-path': (26, 'path_too_long'), 'hardlink': (27, 'hardlinked_path'),
    'guest-openat': (28, None), 'service-dirfd': (29, 'unsupported_dirfd'),
    'immediate-path-write': (30, 'private_path'), 'guest-stdout': (31, None),
    'anonymous-mmap': (32, None), 'guest-file-mmap': (33, None),
}


def build_plugin(out):
    out = Path(out).absolute()
    out.mkdir(parents=True, exist_ok=False)
    header = ROOT/'experiments/execution_capsule_probe/vendor/qemu-plugin.h'
    flags = shlex.split(p.command('pkg-config', '--cflags', '--libs', 'glib-2.0'))
    plugin = out/'control-probe.so'
    p.command('cc', '-std=c11', '-O2', '-g', '-Wall', '-Wextra', '-Werror', '-Wshadow',
              '-Wformat=2', '-fPIC', '-fvisibility=hidden', '-shared', '-Wl,-z,relro,-z,now',
              '-I', header.parent, HERE/'probe.c', '-o', plugin, *flags)
    return plugin


def build_guest(out, name, paths, *, fd=200, unpack=False):
    out = Path(out).absolute()
    out.mkdir(parents=True, exist_ok=False)
    declarations = '\n'.join(k+': .asciz '+json.dumps(str(v)) for k, v in paths.items())+'\n'
    (out/'paths.inc').write_text(declarations)
    source = out/'guest.S'
    if unpack:
        text = (ROOT/'experiments/input_retirement/guest.S').read_text()
        anchor = '.endif\n.if FORK_AFTER\n'
        p.require(text.count(anchor) == 1, 'Unexpected M3 guest body')
        text = text.replace(anchor, '.endif\n    call control_probe\n.if FORK_AFTER\n')
    else:
        text = '.section .text\n.global _start\n_start:\n    jmp control_probe\n'
    source.write_text(text+'\n.include "'+str(HERE/'payload.S')+'"\n')
    binary = out/'guest-i386'
    p.command('as', '--32', '-I', out, '--defsym', 'CASE_ID='+str(CASES[name][0]),
              '--defsym', 'PROBE_FD='+str(fd), '--defsym', 'NEED_DIRECTORY=0',
              '--defsym', 'NO_VERDICT=0', '--defsym', 'FORK_AFTER=0', source, '-o', out/'guest.o')
    p.command('ld', '-m', 'elf_i386', '-z', 'noexecstack', '--build-id=none', out/'guest.o', '-o', binary)
    p.command('strip', '--strip-all', binary)
    return binary


def components(qemu, out):
    qemu, out = Path(qemu).resolve(strict=True), Path(out).absolute()
    out.mkdir(parents=True, exist_ok=False)
    plugin = build_plugin(out/'build')
    private = out/'private'
    private.mkdir()
    sentinel = b'CAPSULE_SERVICE_SECRET\n'
    service = private/'service'
    service.write_bytes(sentinel)
    public = out/'public'
    public.mkdir()
    (public/'symlink').symlink_to(service)
    os.link(service, public/'hardlink')
    paths = {'private_path': service, 'public_path': public/'input',
             'symlink_path': public/'symlink', 'hardlink_path': public/'hardlink',
             'traversal_path': str(public)+'/../private/service'}
    report = {'schema': 1, 'profile': PROFILE, 'status': 'failed', 'scope': 'real_qemu_guard_components',
              'qemu_sha256': p.sha(qemu), 'probe_plugin_sha256': p.sha(plugin), 'cases': [],
              'source_sha256': {str(path.relative_to(ROOT)): p.sha(path) for path in
                  (HERE/'probe.c', HERE/'payload.S', Path(__file__),
                   ROOT/'experiments/retirement_observer/control_guard.h')},
              'm4_end_to_end_verified': False, 'memory_isolation': False,
              'protected_control_channel': False, 'hostile_sample_ready': False}
    def run(name, guarded):
        directory = out/(name if guarded else 'unguarded-'+name)
        guest = build_guest(directory, name, paths)
        service.write_bytes(sentinel)
        arg = ','.join([str(plugin), 'private='+str(private), 'service='+str(service),
                        'guard='+('on' if guarded else 'off')])
        command = [str(qemu), '-strace', '-plugin', arg, str(guest)]
        result = subprocess.run(command, stdin=subprocess.DEVNULL, capture_output=True, timeout=15)
        (directory/'stdout.log').write_bytes(result.stdout)
        (directory/'stderr.log').write_bytes(result.stderr)
        reason = CASES[name][1]
        expected = 126 if guarded and reason else 0
        p.require(result.returncode == expected, 'Unexpected probe exit: '+name+': '+result.stderr.decode(errors='replace'))
        if guarded:
            p.require(service.read_bytes() == sentinel, 'Guarded guest changed the service file: '+name)
            if reason:
                p.require(('CAPSULE_GUARD_ABORT code=126 reason='+reason+'\n').encode() in result.stderr and
                          b'CONTROL_GUEST_OK' not in result.stdout and b'CONTROL_PROBE_DONE' not in result.stderr,
                          'Guard refusal did not precede guest continuation: '+name)
            else:
                expected_stdout = (b'CONTROL_FD_WRITE\n' if name == 'guest-dup2' else b'')+b'CONTROL_GUEST_OK\n'
                p.require(result.stdout == expected_stdout, 'Guest continuation missing: '+name)
                frames = [line.partition(b'CONTROL_PROBE_DONE')[2] for line in result.stderr.splitlines()
                          if line.startswith(b'CONTROL_PROBE_DONE')]
                p.require(len(frames) == 1, 'Missing native guard completion')
                frame = json.loads(frames[0])
                p.require(frame['service_fd_open'] is True, 'Guest closed the service descriptor')
                verify_snapshot(frame.get('control_guard'), private=str(private))
                p.require(frame['control_guard']['checked_syscalls'] > 0, 'No guest syscalls checked')
        else:
            p.require(service.read_bytes().startswith(b'CONTROL_FD_WRITE\n'), 'Unprotected native FD exposure not reproduced')
        item = {'name': name, 'guarded': guarded, 'status': 'passed', 'exit_code': result.returncode,
                'expected_refusal': bool(guarded and reason), 'reason': reason if guarded else None,
                'guest_sha256': p.sha(guest), 'service_unchanged': service.read_bytes() == sentinel}
        report['cases'].append(item)
        p.write_json(out/'report.json', report)
    run('write', False)
    for name in CASES:
        run(name, True)
    directory = out/'invalid-stdin'
    guest = build_guest(directory, 'guest-stdout', paths)
    arg = ','.join([str(plugin), 'private='+str(private), 'service='+str(service), 'guard=on'])
    with service.open('rb') as input_file:
        result = subprocess.run([str(qemu), '-plugin', arg, str(guest)], stdin=input_file,
                                capture_output=True, timeout=15)
    (directory/'stdout.log').write_bytes(result.stdout)
    (directory/'stderr.log').write_bytes(result.stderr)
    p.require(result.returncode != 0 and result.stdout == b'' and service.read_bytes() == sentinel,
              'Unsafe initial stdin was accepted')
    report['unsafe_stdin_rejected'] = True
    report['status'] = 'passed'
    p.write_json(out/'report.json', report)
    return report
