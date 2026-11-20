"""Preserve the kernel executable identity for strict M3 flags receipts."""
from __future__ import annotations

import os
from pathlib import Path, PurePosixPath
import stat
import subprocess

from .capsule_strict import digest, read_receipt
from .elf_runtime import ElfImage
from .phase1_runtime import read_json
from .unified_runtime import verify_bundle, write_json

PROFILE = 'input-static-i386-retirement-m3'
PREFIX = ['/__taintforge/bin/loader', '--inhibit-cache', '--library-path',
          '/__taintforge/lib', '/__taintforge/bin/qemu-i386']


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def selected_receipt(binding, argv):
    """Only convert the existing strict M3 launcher; other profiles keep their path."""
    if binding.get('profile') != PROFILE:
        return None
    require(isinstance(argv, list) and all(isinstance(value, str) for value in argv),
            'Invalid M3 command')
    # Non-receipt launches, including the network endpoint observer, retain
    # their existing loader command. The shape below applies to strict setup.
    receipt_requested = any(
        option.startswith('x86-flags-receipt=')
        for value in argv for option in value.split(',')[1:])
    if not receipt_requested:
        return None
    require(len(argv) == 13 and argv[:5] == PREFIX and argv[5:9] == ['-L', '/', '-strace', '-plugin']
            and argv[10] == '-plugin' and argv[12] == binding['guest_binary'],
            'Unrecognized M3 loader command; executable identity was not changed')
    options = argv[9].split(',')[1:]
    receipts = [part.split('=', 1)[1] for part in options if part.startswith('x86-flags-receipt=')]
    if not receipts:
        return None
    require(len(receipts) == 1 and receipts[0] == '/__taintforge/flags/eflags.receipt'
            and options.count('tf-require-flags=on') == 1,
            'Strict M3 flags arguments are incomplete or ambiguous')
    return receipts[0]


def guest_slot(root, name, *, create=False):
    path = PurePosixPath(name)
    require(path.is_absolute() and len(path.parts) > 1 and '..' not in path.parts,
            'Invalid native interpreter path')
    current = root
    for part in path.parts[1:-1]:
        current /= part
        require(not current.is_symlink() and (not current.exists() or current.is_dir()),
                'Native interpreter traverses a guest symlink or non-directory')
        if create and not current.exists():
            current.mkdir(mode=0o755)
            # The supervisor uses umask 0077; the dropped UID must traverse these directories.
            current.chmod(0o755)
    destination = current / path.name
    require(not destination.is_symlink(), 'Native interpreter destination is a symlink')
    if destination.exists():
        info = destination.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size == 0,
                'Native interpreter or loader control would hide an existing guest file: ' + name)
    elif create:
        fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o444)
        os.close(fd)
    return destination


def readonly_bind(source, destination):
    subprocess.run(['mount', '--bind', str(source), str(destination)], check=True)
    subprocess.run(['mount', '-o', 'remount,bind,ro,nosuid,nodev', str(destination)], check=True)


def prepare_launch(binding, argv):
    receipt_name = selected_receipt(binding, argv)
    if receipt_name is None:
        return None
    require(os.geteuid() == 0, 'Native M3 setup requires the namespace supervisor')
    from .input_retirement import inspect_input, verify_contract
    verify_contract(binding)
    run, root = Path(binding['run_dir']), Path(binding['rootfs'])
    require(root.is_absolute() and not root.is_symlink() and root.is_dir(), 'Invalid M3 rootfs')
    require(inspect_input(root / binding['guest_binary'].lstrip('/')) == binding['input_retirement'],
            'M3 target changed before native launch')
    bundle = root / '__taintforge'
    manifest = verify_bundle(bundle, binding['bundle_sha256'])
    require(manifest.get('capsule') == binding['capsule'], 'M3 observer identity changed')
    require(argv[9].split(',', 1)[0] == '/__taintforge/' + manifest['plugin']
            and argv[11].split(',', 1)[0] == '/__taintforge/' + binding['capsule']['plugin'],
            'M3 plugin selection changed')
    qemu = bundle / manifest['qemu']
    loader = bundle / manifest['loader']
    qemu_sha, loader_sha = digest(qemu), digest(loader)
    receipt = root / receipt_name.lstrip('/')
    read_receipt(receipt, qemu_sha)
    interpreter = ElfImage(qemu).target.interpreter
    require(interpreter in ('/lib64/ld-linux-x86-64.so.2', '/lib/ld-linux.so.2'),
            'Unsupported QEMU kernel interpreter')
    slots = (interpreter, '/etc/ld.so.preload', '/etc/ld.so.cache')
    # Inspect all destinations before creating or mounting anything.
    for name in slots:
        guest_slot(root, name)
    empty = run / 'config/native-loader-empty'
    require(not empty.exists() and not empty.is_symlink(), 'Native loader setup was already attempted')
    with empty.open('xb'):
        pass
    empty.chmod(0o444)
    for name in slots:
        destination = guest_slot(root, name, create=True)
        readonly_bind(loader if name == interpreter else empty, destination)
    require(digest(root / interpreter.lstrip('/')) == loader_sha, 'Mounted kernel loader identity changed')
    require(digest(qemu) == qemu_sha, 'QEMU changed during native launch setup')
    read_receipt(receipt, qemu_sha)
    command = ['/__taintforge/bin/qemu-i386', '-U', 'LD_LIBRARY_PATH', *argv[5:]]
    write_json(run / 'logs/capsule/native-exec.json', {
        'schema': 1, 'profile': 'strict-m3-native-exec-v1', 'status': 'prepared',
        'attempt_id': binding['attempt_id'], 'attempt_contract_sha256': binding['attempt_contract_sha256'],
        'bundle_sha256': binding['bundle_sha256'], 'qemu_sha256': qemu_sha,
        'kernel_interpreter': interpreter, 'loader_sha256': loader_sha,
        'flags_receipt_sha256': digest(receipt), 'requested_command': argv, 'exec_command': command,
        'receipt_check_disabled': False, 'execution_verified': False})
    return command


def warm_mounts(binding, pid):
    """Admit only the identity-checked loader mounts into the warm checkpoint."""
    run, root = Path(binding['run_dir']), Path(binding['rootfs'])
    evidence = run / 'logs/capsule/native-exec.json'
    if not evidence.exists():
        return ()
    require(binding.get('profile') == PROFILE and not evidence.is_symlink(), 'Unexpected native execution evidence')
    record = read_json(evidence)
    require(record.get('schema') == 1 and record.get('profile') == 'strict-m3-native-exec-v1'
            and record.get('status') == 'prepared' and record.get('receipt_check_disabled') is False
            and all(record.get(key) == binding[key] for key in ('attempt_id', 'attempt_contract_sha256', 'bundle_sha256')),
            'Native execution evidence belongs to another attempt')
    bundle = root / '__taintforge'
    manifest = verify_bundle(bundle, binding['bundle_sha256'])
    qemu, loader = bundle / manifest['qemu'], bundle / manifest['loader']
    require(digest(qemu) == record['qemu_sha256'] and digest(loader) == record['loader_sha256'],
            'Native runtime changed before checkpoint')
    require(type(pid) is int and pid > 0, 'Invalid native process identity')
    executable = root / 'proc' / str(pid) / 'exe'
    actual, expected = executable.stat(), qemu.stat()
    require((actual.st_dev, actual.st_ino) == (expected.st_dev, expected.st_ino)
            and digest(executable) == record['qemu_sha256'],
            'Warm process executable is not the calibrated QEMU')
    interpreter = ElfImage(qemu).target.interpreter
    require(interpreter == record['kernel_interpreter'] and interpreter in
            ('/lib64/ld-linux-x86-64.so.2', '/lib/ld-linux.so.2'), 'Native interpreter changed')
    receipt = bundle / 'flags/eflags.receipt'
    read_receipt(receipt, record['qemu_sha256'])
    require(digest(receipt) == record['flags_receipt_sha256'], 'Native flags receipt changed')
    empty = run / 'config/native-loader-empty'
    require(not empty.is_symlink() and empty.is_file() and empty.stat().st_size == 0,
            'Native loader controls changed')
    from .afl_warm import rootfs_mounts
    mounts = rootfs_mounts(root)
    destinations = []
    for name, source in ((interpreter, loader), ('/etc/ld.so.preload', empty), ('/etc/ld.so.cache', empty)):
        destination = root / name.lstrip('/')
        rows = mounts.get(destination.relative_to(root), ())
        require(len(rows) == 1 and {'ro', 'nosuid', 'nodev'} <= set(rows[0][5].split(',')),
                'Native loader mount is missing or writable: ' + name)
        left, right = destination.stat(), source.stat()
        require((left.st_dev, left.st_ino) == (right.st_dev, right.st_ino),
                'Native loader mount points to another file: ' + name)
        destinations.append(destination)
    write_json(run / 'logs/capsule/native-exec-verified.json', {
        'schema': 1, 'status': 'verified', 'attempt_id': binding['attempt_id'],
        'attempt_contract_sha256': binding['attempt_contract_sha256'], 'pid': pid,
        'qemu_sha256': record['qemu_sha256'], 'launch_evidence_sha256': digest(evidence),
        'preserved_mounts': [str(path) for path in destinations]})
    return tuple(destinations)
