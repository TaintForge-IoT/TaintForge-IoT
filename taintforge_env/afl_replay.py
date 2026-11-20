"""Replay and bounded delta reduction using one fresh warm session."""
from __future__ import annotations

import hashlib
from pathlib import Path
import shutil
import signal
import time
import struct

from . import afl_file as f, afl_outcome as o
from .afl_evidence import read_input, reusable
from . import afl_storage as storage


def corpus(root, maximum=4096):
    root = Path(root)
    paths = [*sorted((root/'seeds').glob('*')), *sorted((root/'afl/default/queue').glob('id:*'))]
    inputs = {}
    for path in paths:
        data = read_input(path, maximum)
        digest = hashlib.sha256(data).hexdigest()
        if len(path.name) == 64 and all(c in '0123456789abcdef' for c in path.name):
            f.p.require(path.name == digest, 'Corpus filename/content hash mismatch: '+str(path))
        inputs[digest] = data
    return inputs


def clone_campaign(source, output, *, inputs=None, edit_rootfs=None):
    """Clone only the prepared filesystem/bundle; no live CPU checkpoint is persisted."""
    from .afl_warm import configuration
    source, output = Path(source).expanduser().resolve(strict=True), Path(output).expanduser().resolve()
    original = f.verify_campaign(source)
    f.p.require('warm' in original and (original['status'] == 'prepared' or reusable(original)),
                'Cloning requires a prepared or completed warm campaign')
    if original['status'] == 'interrupted':
        from .afl_stop import verify_receipt
        verify_receipt(source, original)
    protected = (source, Path(original['snapshot_store']).resolve(),
                 Path(original['launch']['seed_rootfs']).resolve(),
                 Path(original['launch']['template_run_dir']).resolve())
    f.p.require(not any(output.is_relative_to(path) or path.is_relative_to(output) for path in protected),
                'New campaign must be outside the source campaign and its snapshot/template trees')
    data_inputs = list(inputs) if inputs is not None else list(corpus(source, original['max_input']).values())
    f.p.require(data_inputs and all(isinstance(data, bytes) and 1 <= len(data) <= original['max_input'] for data in data_inputs),
                'Replay corpus is empty or exceeds campaign limits')
    output.mkdir(parents=True, exist_ok=False)
    template = output/'template'
    template.mkdir()
    fs = template/'rootfs'
    f.EnvironmentSnapshotStore(original['snapshot_store']).clone(original['snapshot_id'], fs)
    shutil.copytree(Path(original['launch']['template_run_dir'])/'config', template/'config')
    if edit_rootfs is not None:
        edit_rootfs(fs)
    snapshot_store = f.EnvironmentSnapshotStore(output/'baseline-snapshots')
    snapshot = snapshot_store.capture(fs)
    runtime = f.read_json(template/'config/runtime.json')
    runtime['rootfs'] = str(fs)
    runtime['phase1']['bundle_path'] = str(template/'config/analyzer_runtime')
    f.atomic_json(template/'config/runtime.json', runtime)
    launch = original['launch'] | {'session_dir': str(output/'unused-session'),
        'template_run_dir': str(template), 'seed_rootfs': str(fs),
        'snapshot_store': str(output/'unused-snapshots'), 'max_iterations': 1}
    value = {key: original[key] for key in ('schema', 'profile', 'project_root', 'guest_path',
        'max_input', 'build', 'protected_control_channel', 'hostile_sample_ready', 'source_sha256', 'execution_mode')}
    config = original['warm']
    warm = configuration(output, **{name: config[name] for name in
        ('bootstrap_seconds', 'campaign_seconds', 'timeout_ms', 'max_rss_mib')},
        phase2_mode=config.get('phase2', {}).get('mode', 'off'),
        phase2_pending=config.get('phase2', {}).get('pending', 4),
        capsule_m5='capsule_profile' in config, storage=config.get('storage'))
    value.update(status='prepared', cases=0, launch=launch, warm=warm,
                 snapshot_store=str(snapshot_store.store_dir), snapshot_id=snapshot.manifest.snapshot_id,
                 assets={name: sha for name, sha in original['assets'].items()
                         if name != str(Path(original['launch']['template_run_dir'])/'config/runtime.json')
                         and not Path(name).is_relative_to(source/'seeds')},
                 parent_campaign=str(source))
    value['assets'][str(template/'config/runtime.json')] = f.p.sha(template/'config/runtime.json')
    if 'storage' in original:
        storage.bind(value, storage.verify_manifest(original))
    (output/'seeds').mkdir()
    for data in data_inputs:
        f.p.require(1 <= len(data) <= value['max_input'], 'Replay input exceeds campaign limits')
        path = output/'seeds'/hashlib.sha256(data).hexdigest()
        path.write_bytes(data)
        value['assets'][str(path)] = f.p.sha(path)
    f.p.require(any((output/'seeds').iterdir()), 'Replay corpus is empty')
    f.atomic_json(output/'campaign.json', value)
    f.verify_campaign(output)
    return value


def same_fault(expected, actual):
    return (expected['kind'] == actual['kind'] and
            expected.get('guest_signal') == actual.get('guest_signal') and
            (expected['kind'] != 'guest_crash' or expected.get('guest_pc') == actual.get('guest_pc')))


def minimize(data, check, *, budget=128, repetitions=2, can_run=None):
    """Delete chunks; preserve at least one byte and require repeated same-fault results."""
    f.p.require(isinstance(data, bytes) and data and type(budget) is int and 1 <= budget <= 10000
                and type(repetitions) is int and 1 <= repetitions <= 10,
                'Invalid minimization budget')
    current, calls, parts = data, 0, 2
    exhausted = False
    stop_reason = 'completed'
    while len(current) > 1:
        width = (len(current)+parts-1)//parts
        accepted = False
        for start in range(0, len(current), width):
            candidate = current[:start]+current[start+width:]
            if not candidate:
                continue
            if calls+repetitions > budget:
                exhausted = True
                stop_reason = 'execution_budget'
                break
            matched = True
            for _ in range(repetitions):
                if can_run is not None and not can_run():
                    exhausted, matched, stop_reason = True, False, 'time_budget'
                    break
                calls += 1
                if not check(candidate):
                    matched = False
                    break
            if exhausted:
                break
            if matched:
                current, parts, accepted = candidate, max(2, parts-1), True
                break
        if exhausted or (not accepted and parts >= len(current)):
            break
        if not accepted:
            parts = min(len(current), parts*2)
    return current, {'executions': calls, 'budget_exhausted': exhausted,
                     'original_bytes': len(data), 'minimized_bytes': len(current),
                     'repetitions': repetitions, 'stop_reason': stop_reason, 'method': 'bounded_chunk_deletion'}


def direct_attempt(server, data):
    with server.connect() as connection:
        connection.settimeout(server.deadline+5)
        index = server.executed
        connection.sendall(struct.pack('!I', len(data))+data)
        from .afl_transport import recv_exact
        import select
        deadline = time.monotonic()+server.deadline+5
        while not select.select([connection], [], [], .1)[0]:
            if server.admission_closed.is_set():
                reason = server.budget_reason or {}
                raise storage.ResourceLimit(reason.get('reason', 'admission_closed'))
            if server.stop.is_set():
                raise InterruptedError('Replay executor stopped')
            if time.monotonic() >= deadline:
                raise TimeoutError('Replay executor response deadline exceeded')
        header = recv_exact(connection, 16)
        o.check_bridge(header)
        bitmap = recv_exact(connection, f.MAP_SIZE)
    case = server.root/'cases'/f'{index:08d}'
    value = f.read_json(case/'result.json')
    f.p.require(value['status'] == 'passed' and value['input']['input_sha256'] == hashlib.sha256(data).hexdigest()
                and header == o.bridge_header(value['outcome'])
                and value['coverage']['map_sha256'] == hashlib.sha256(bitmap).hexdigest(),
                'Replay coverage identity mismatch')
    return value


def replay(source, finding, output, *, repetitions=3, reduce=False, budget=128):
    import fcntl
    from .afl_warm import WarmAttemptServer
    source, finding, output = Path(source).resolve(strict=True), Path(finding).resolve(strict=True), Path(output).resolve()
    f.p.require(finding.is_relative_to(source/'findings'), 'Finding belongs to another campaign')
    saved = f.read_json(finding/'finding.json')
    original = f.verify_campaign(source)
    f.p.require(reusable(original), 'Replay requires a completed source campaign')
    data = read_input(finding/'input', original['max_input'])
    first_case = (source/saved['first_case']).resolve()
    f.p.require(first_case.parent == source/'cases', 'Finding case escapes its source campaign')
    executed = f.read_json(first_case/'result.json')
    f.p.require(saved['outcome'] == executed['outcome'] and saved['input_sha256'] == executed['input']['input_sha256']
                and saved.get('snapshot_id') == original['snapshot_id']
                and saved.get('assets') == original['assets']
                and saved.get('source_sha256') == original['source_sha256'],
                'Finding provenance does not match its original campaign/child')
    if 'case_result_sha256' in saved:
        f.p.require(saved['case_result_sha256'] == f.p.sha(first_case/'result.json'), 'Finding child result changed')
    f.p.require(saved['input_sha256'] == hashlib.sha256(data).hexdigest(), 'Finding input changed')
    f.p.require(type(repetitions) is int and 1 <= repetitions <= 10, 'Invalid replay count')
    f.p.require(type(budget) is int and 1 <= budget <= 10000, 'Invalid minimization budget')
    manifest = clone_campaign(source, output, inputs=[data])
    report = {'schema': 1, 'status': 'failed', 'source_campaign': str(source),
              'finding': str(finding), 'repetitions': repetitions, 'preparation': 'one_new_phase1_session',
              'signature_policy': 'same_kind_guest_signal_and_guest_pc', 'trials': []}
    server = WarmAttemptServer(output, deadline=manifest['warm']['timeout_ms']/1000+30)
    def interrupted(number, frame):
        server.stop.set()
        raise InterruptedError('Replay interrupted')
    handlers = {number: signal.signal(number, interrupted) for number in (signal.SIGINT, signal.SIGTERM)}
    try:
        with (output/'.campaign.lock').open('a+') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            manifest['status'] = 'preparing'; f.atomic_json(output/'campaign.json', manifest)
            if server.storage is not None:
                server.storage.open()
            server.start()
            deadline = time.monotonic()+manifest['warm']['campaign_seconds']
            def can_run():
                return not server.stop.is_set() and time.monotonic()+manifest['warm']['timeout_ms']/1000+3 < deadline
            matched, complete = True, True
            for _ in range(repetitions):
                if not can_run():
                    complete = False
                    break
                result = direct_attempt(server, data)
                report['trials'].append(result['outcome'])
                matched &= same_fault(saved['outcome'], result['outcome'])
            if matched and complete and reduce:
                def check(candidate):
                    return same_fault(saved['outcome'], direct_attempt(server, candidate)['outcome'])
                data, report['minimization'] = minimize(data, check, budget=budget, can_run=can_run)
                (output/'minimized-input').write_bytes(data)
            server.close()
            f.p.require(not server.errors and server.executed == server.completed, 'Replay left undelivered children')
            report.update(status='incomplete' if not complete else 'passed' if matched else 'not_reproduced',
                          phase1_runs=1, children=server.executed, input_sha256=hashlib.sha256(data).hexdigest())
            manifest.update(status='completed', phase1_runs=1, cases=server.executed, completed_cases=server.completed,
                            execution_purpose='finding_replay', executor_errors=server.errors)
    except storage.ResourceLimit as exc:
        server.stop_admission(exc.record)
        report.update(status='incomplete', stop_reason='storage_limit', storage_stop=exc.record)
        manifest.update(status='incomplete', stop_reason='storage_limit', evidence_complete=False)
    except BaseException as exc:
        report.update(status='interrupted' if isinstance(exc, InterruptedError) else 'failed', error=str(exc))
        manifest.update(status=report['status'], error=str(exc))
        raise
    finally:
        for number in handlers:signal.signal(number, signal.SIG_IGN)
        try:
            if server.storage is not None:
                server.storage.release_reserve()
            server.close()
        except Exception as exc:
            report.update(status='failed', cleanup_error=str(exc))
            manifest.update(status='failed', cleanup_error=str(exc))
            raise
        finally:
            for number, handler in handlers.items(): signal.signal(number, handler)
            if server.storage is not None:
                manifest['storage_result'] = server.storage.report()
                if server.storage.reason is not None:
                    report.update(status='incomplete', stop_reason='storage_limit', storage_stop=server.storage.reason)
                    manifest.update(status='incomplete', stop_reason='storage_limit', evidence_complete=False)
            manifest.update(cases=server.executed, completed_cases=server.completed,
                            executor_errors=server.errors)
            f.atomic_json(output/'campaign.json', manifest)
            f.atomic_json(output/'replay.json', report)
    return report
