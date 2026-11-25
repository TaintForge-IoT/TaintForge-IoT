"""Observe one fixed input in a fresh snapshot for a trusted recovered i386 ELF."""
import hashlib
import os
from pathlib import Path
import stat
import struct

from taintforge_env import afl_file, afl_rebuilt as coverage
from taintforge_env.phase1_runtime import digest
from taintforge_env.unified_runtime import write_json
from unpacker.unpack_process import run_observed_process

MAX_PROCESSES = 8
OWNER = struct.Struct('<iI')
EMPTY_RECORD = coverage.HEADER.pack(b'TFRCOV1\0', 1, coverage.MAP_SIZE, *([0] * 10)) + bytes(
    coverage.RECORD_SIZE - coverage.HEADER.size)
SLOT_SIZE = OWNER.size + coverage.RECORD_SIZE


def write_tree_map(path):
    with path.open('xb') as stream:
        stream.write((OWNER.pack(0, 0) + EMPTY_RECORD) * MAX_PROCESSES)


def collect_maps(path, process_tree):
    info = path.lstat()
    coverage.require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and
                     info.st_size == SLOT_SIZE * MAX_PROCESSES, 'Invalid tree coverage file')
    data = path.read_bytes()
    coverage.require(len(data) == info.st_size, 'Tree coverage length changed')
    exits = {row['pid']: row for row in process_tree}
    bitmap = bytearray(coverage.MAP_SIZE)
    rows = []
    seen = set()
    for slot in range(MAX_PROCESSES):
        offset = slot * SLOT_SIZE
        pid, inherited = OWNER.unpack_from(data, offset)
        record = data[offset + OWNER.size:offset + SLOT_SIZE]
        if pid == 0:
            coverage.require(slot > 0 and not inherited and record == EMPTY_RECORD, 'Dirty unused coverage slot')
            continue
        coverage.require(pid in exits and pid not in seen and inherited in (0, 1)
                         and (slot == 0) == (exits[pid]['parent_pid'] is None)
                         and (slot != 0 or not inherited), 'Coverage PID differs from the observed fork tree')
        seen.add(pid)
        report, local = coverage.parse_coverage_record(record, exits[pid]['returncode'], tree=True,
                                                       inherited_input=bool(inherited))
        rows.append({**exits[pid], 'inherited_input': bool(inherited), 'coverage': report})
        for i, value in enumerate(local):
            if value:
                bitmap[i] = min(255, bitmap[i] + value)
    coverage.require(seen == exits.keys() and any(bitmap) and
                     sum(row['coverage']['input_bytes_read'] for row in rows) > 0,
                     'Incomplete tree or no coverage from this input')
    return rows, bytes(bitmap)


def send_fixed_feedback(connection, receipt, bitmap, *, data, target_sha256, known_faults):
    """Deliver this fixed input. Only a known guest trap for the pinned fixture confirms a signal."""
    coverage.require(receipt['status'] == 'observed' and receipt['target_sha256'] == target_sha256
                     and receipt['input_sha256'] == hashlib.sha256(data).hexdigest()
                     and receipt['coverage_sha256'] == hashlib.sha256(bitmap).hexdigest(),
                     'Feedback belongs to a different input, image or coverage map')
    signals = set()
    for row in receipt['processes']:
        sig = row['signal']
        if sig is not None:
            coverage.require(known_faults.get(row['coverage']['last_pc']) == sig,
                             'Observed signal lacks a matching guest trap in the fixture')
            signals.add(sig)
    coverage.require(len(signals) <= 1, 'One AFL result cannot encode distinct terminal signals')
    coverage.send_feedback(connection, bitmap, signal_number=next(iter(signals), 0))


def replay_case(store, snapshot_id, out, data, *, qemu, plugin, argv=(), timeout=10):
    """Fixed-input QEMU linux-user replay. -L resolves the fixture's guest file paths."""
    coverage.require(1 <= len(data) <= 4096, 'Input must contain 1..4096 bytes')
    out = coverage.private_path(out)
    out.mkdir(parents=True, exist_ok=False)
    root = out / 'rootfs'
    store.clone(snapshot_id, root)
    target = afl_file.guest_file(root, '/bin/sample.elf')
    input_path = afl_file.guest_file(root, '/etc/dta-input')
    input_path.chmod(0o600)
    input_path.write_bytes(data)
    input_path.chmod(0o444)
    record = out / 'coverage.bin'
    write_tree_map(record)
    plugin = Path(plugin).resolve(strict=True)
    coverage.require(not any(',' in str(p) for p in (record, plugin)), 'Comma in QEMU plugin argument')
    receipt = {'input_sha256': hashlib.sha256(data).hexdigest(), 'target_sha256': digest(target),
               'snapshot_id': snapshot_id, 'guest_isolation_established': False, 'status': 'incomplete'}
    try:
        option = f'{plugin},output={record},input=/etc/dta-input,tree-fd='
        result = run_observed_process([os.fspath(qemu), '-L', str(root), str(target), *argv],
            {'id': 'fixed-input'}, out / 'run', plugin_option=option, max_processes=MAX_PROCESSES,
            timeout=timeout)
        receipt['root_returncode'] = result['returncode']
        coverage.require(not any(result[key] for key in ('timed_out', 'rss_limit_hit', 'output_limit_exceeded')),
                         'Fixed-input replay exceeded its resource budget')
        if 'process_exit_error' in result:
            receipt['process_exit_error'] = result['process_exit_error']
            raise RuntimeError(result['process_exit_error']['detail'])
        rows, bitmap = collect_maps(record, result['process_tree'])
        coverage.require(digest(input_path) == receipt['input_sha256'] and digest(target) == receipt['target_sha256'],
                         'Input or target changed during tree replay')
        receipt.update(status='observed', processes=rows, coverage_sha256=hashlib.sha256(bitmap).hexdigest())
        (out / 'coverage.map').write_bytes(bitmap)
        return receipt, bitmap
    except Exception as exc:
        receipt['error'] = str(exc)
        raise
    finally:
        write_json(out / 'result.json', receipt)
