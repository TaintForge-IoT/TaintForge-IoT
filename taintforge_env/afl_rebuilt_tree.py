"""Bounded fixed-input replay through the rebuilt campaign's namespace and AFL server."""
import fcntl
import hashlib
import os
from pathlib import Path
import re
import signal
import socket
import stat
import subprocess
import time

from experiments.afl_rebuilt import fork_replay
from unpacker.unpack_process import _process_tree, UnpackError
from . import afl_rebuilt as backend, capsule_hardening
from .phase1_runtime import read_json
from .unified_runtime import write_json

EVENTS = ('user_queue_signal', 'user_handle_signal', 'user_dump_core_and_abort')
LINE = re.compile(rb'(user_queue_signal|user_handle_signal|user_dump_core_and_abort) env=(0x[0-9a-f]+) signal ([0-9]+)(?: \(host ([0-9]+)\))?')


def reap_tree(root, deadline):
    statuses = {}
    while time.monotonic() < deadline:
        try:
            pid, status = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            backend.require(root in statuses, 'Missing root wait status')
            return statuses
        if pid:
            statuses[pid] = os.waitstatus_to_exitcode(status)
        else:
            time.sleep(0.005)
    raise UnpackError('TREE_TIMEOUT', 'Tree exceeded the case deadline')


def supervise(binding, command):
    backend.require(os.getpid() == 1, 'Tree supervisor requires a private PID namespace')
    receiver, sender = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    report = {k: binding[k] for k in ('attempt_contract_sha256', 'target_sha256', 'input_sha256')}
    with receiver, sender:
        receiver.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        root = os.fork()
        if root == 0:
            try:
                receiver.close()
                fd = fcntl.fcntl(sender.fileno(), fcntl.F_DUPFD, 256)
                os.set_inheritable(fd, True)
                sender.close()
                i = command.index('-plugin')
                command[i + 1] += f',tree-fd={fd},fixed-input=on'
                options = ['-d', 'tid', '-D', '/__tf_output/qemu.%d.log']
                for event in EVENTS:
                    options.extend(['-trace', 'enable=' + event])
                command[i:i] = options
                command.append('/etc/dta-input')
                capsule_hardening.launch(binding, command)
            except BaseException as exc:
                os.write(2, (str(exc) + '\n').encode(errors='replace'))
            finally:
                os._exit(125)
        sender.close()
        deadline = time.monotonic() + binding['seconds']
        try:
            statuses = reap_tree(root, deadline)
            traps = {}
            rows = _process_tree(receiver, root, statuses[root], deadline, fork_replay.MAX_PROCESSES, traps=traps)
            codes = {r['pid']: r['returncode'] for r in rows}
            backend.require(all(codes.get(pid) == rc for pid, rc in statuses.items()), 'Conflicting wait status')
            report.update(status='observed', root_pid=root, root_returncode=statuses[root], processes=rows, traps=traps)
        except (UnpackError, RuntimeError, OSError) as exc:
            report.update(status='incomplete', reason=getattr(exc, 'reason', 'INCOMPLETE_PROCESS_EXIT'), detail=str(exc))
    write_json(Path(binding['run_dir']) / 'logs/capsule/tree.json', report)
    # On timeout exiting PID 1 tears down its namespace. The service must still
    # verify cgroup cleanup before the outer worker can deliver any results.
    return 0


def verify_signals(directory, processes, traps):
    known = {r['pid']: r['signal'] for r in processes}
    signaled = {pid: sig for pid, sig in known.items() if sig is not None}
    fatal = {}
    for path in directory.iterdir():
        if path.name == 'coverage.bin':
            continue
        match = re.fullmatch(r'qemu\.([1-9][0-9]*)\.log', path.name)
        backend.require(match and int(match[1]) in known, 'Native trace from an unknown process')
        pid = int(match[1])
        st = path.lstat()
        backend.require(stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and st.st_size <= 65536, 'Invalid native trace')
        events = []
        for line in path.read_bytes().splitlines():
            event = LINE.fullmatch(line)
            backend.require(event is not None, 'Malformed QEMU signal trace')
            name, env, guest, host = event.groups()
            if name == b'user_dump_core_and_abort':
                backend.require(pid not in fatal and int(guest) == signal.SIGILL and host == guest and
                                events[-2:] == [(b'user_queue_signal', env, guest), (b'user_handle_signal', env, guest)],
                                'Missing synchronous guest signal delivery')
                fatal[pid] = int(guest)
            events.append((name, env, guest))
    backend.require(signaled == fatal and set(traps) == set(signaled), 'Guest trap, trace and kernel status disagree')
    return [{'pid': pid, 'guest_pc': traps[pid], 'signal': sig} for pid, sig in sorted(signaled.items())]


def collect(binding, out):
    tree = read_json(out / 'logs/capsule/tree.json')
    backend.require(all(tree.get(k) == binding[k] for k in ('attempt_contract_sha256', 'target_sha256', 'input_sha256')),
                    'Process tree belongs to another execution')
    if tree.get('status') == 'incomplete':
        raise UnpackError(tree['reason'], tree['detail'])
    backend.require(tree.get('status') == 'observed', 'No complete process tree')
    rows, bitmap = fork_replay.collect_maps(out / 'output/coverage.bin', tree['processes'])
    signals = verify_signals(out / 'output', rows, {int(k): v for k, v in tree['traps'].items()})
    return {'guest_exit': tree['root_returncode'], 'root_pid': tree['root_pid'], 'processes': rows,
            'guest_signals': signals, 'feedback_signal': signals[0]['signal'] if signals else 0,
            'coverage': {'status': 'verified', 'scope': 'process_tree_after_input_read',
                         'map_sha256': hashlib.sha256(bitmap).hexdigest(),
                         'branch_outcomes': sorted({tuple(b) for row in rows for b in row['coverage']['branch_outcomes']})}}, bitmap


def replay_corpus(root, manifest, showmap):
    inputs = manifest['fixed_inputs']
    backend.require(inputs and backend.digest(Path(manifest['bridge'])) == manifest['bridge_sha256'], 'Invalid bridge or corpus')
    server = backend.Server(root, len(inputs), campaign_id=manifest['campaign_id'])
    server.thread.start()
    runs = []
    timeout = manifest['case_seconds'] + 35
    try:
        for index, digest in enumerate(inputs):
            dest = root / 'proof' / f'{index:08d}'
            seeds = dest / 'input'
            seeds.mkdir(parents=True)
            seed = seeds / 'case'
            seed.write_bytes((root / 'seeds' / digest).read_bytes())
            backend.require(backend.digest(seed) == digest, 'Input changed')
            maps = dest / 'maps'
            fd = server.peer.fileno()
            cmd = [showmap, '-q', '-e', '-i', seeds, '-o', maps, '-t', str(timeout * 1000),
                   '--', manifest['bridge'], str(fd), '@@']
            with (dest / 'showmap.log').open('wb') as log:
                result = subprocess.run(cmd, pass_fds=(fd,), timeout=timeout + 10, stdout=log, stderr=log,
                    env={**os.environ, 'AFL_QUIET':'1', 'AFL_NO_AFFINITY':'1', 'AFL_MAP_SIZE':'4194304'})
            backend.require(not server.error and result.returncode in (0, 2), server.error or 'afl-showmap failed, see ' + str(dest))
            runs.append((result.returncode, maps / 'case'))
    finally:
        server.peer.close()
        server.thread.join(timeout)
        if server.thread.is_alive():
            server.cancel()
            server.thread.join(20)
        server.channel.close()
    backend.require(not server.thread.is_alive() and not server.error and server.delivered == len(inputs),
                    server.error or 'Incomplete fixed-corpus delivery')
    observations = []
    for index, (code, path) in enumerate(runs):
        case = root / 'cases' / f'{index:08d}'
        result = read_json(case / 'result.json')
        transport = read_json(case / 'transport.json')
        bitmap = (case / 'coverage.map').read_bytes()
        indices = {int(line.split(':', 1)[0]) for line in path.read_text().splitlines()}
        backend.require(transport['input_sha256'] == inputs[index] == result['input_sha256'] and
                        transport['coverage_sha256'] == hashlib.sha256(bitmap).hexdigest() and
                        code == (2 if result.get('feedback_signal') else 0) and
                        indices == {i for i, value in enumerate(bitmap) if value}, 'AFL and isolated worker disagree')
        observations.append({'case': index, 'input_sha256': inputs[index], 'status': result['status'],
                             'afl_showmap_returncode': code, 'reported_edges': len(indices)})
    manifest.update(status='replayed', cases=len(runs), observations=observations)
    write_json(root / 'campaign.json', manifest)
    return observations
