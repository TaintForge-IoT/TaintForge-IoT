"""Continue a verified, stopped M5 campaign with its corpus in a new session."""
from __future__ import annotations

import fcntl
import hashlib
import os
from pathlib import Path
import stat

from . import afl_file as f
from .afl_evidence import child_report, completed_cases, read_input, reusable
from .afl_replay import clone_campaign

PROFILE = 'afl-corpus-continuation-v1'
MIB = 1024**2


def verify_stopped(root):
    """Require finalized children, retirement and independently checked M5 evidence."""
    root = Path(root)
    manifest = f.verify_campaign(root)
    from . import afl_capsule
    f.p.require(reusable(manifest) and manifest.get('evidence_complete') is True and
                afl_capsule.enabled(manifest.get('warm', {})) and
                'phase2' in manifest['warm'],
                'Continuation requires a completed or fully drained M5 campaign with Phase 2')
    if manifest.get('status') == 'interrupted':
        from .afl_stop import verify_receipt
        verify_receipt(root, manifest)
    f.p.require(not any(manifest.get(key) for key in
                ('error', 'cleanup_error', 'report_error', 'metrics_error', 'executor_errors')),
                'Source campaign has unresolved execution or cleanup errors')
    session = f.read_json(root/'warm-session-result.json')
    capsule = session.get('capsule', {})
    f.p.require(capsule.get('status') == 'passed' and
                capsule.get('resources', {}).get('tree_empty') is True and
                capsule.get('phase1_retirement', {}).get('phase1_retired') is True and
                type(manifest.get('phase1_runs')) is int and manifest['phase1_runs'] == 1,
                'Source capsule has not been verified stopped and retired')
    admission = verify_admission(root, manifest, capsule)
    cases = completed_cases(root, manifest)
    executed = set()
    for case in cases:
        analysis = child_report(case, manifest['max_input'])
        executed.add(analysis['input_sha256'])
    return manifest, executed, admission


def verify_admission(root, manifest, capsule):
    from . import afl_capsule
    from .retirement_evidence import verify
    runtime = f.read_json(Path(manifest['launch']['template_run_dir'])/'config/runtime.json')
    policy = runtime['capsule']['analysis_policy']
    admitted = afl_capsule.verify_ready(f.read_json(root/'warm-ready.json'), policy)
    decision = admitted['analysis_quality']
    f.p.require(capsule.get('afl_checkpoint') == admitted and capsule.get('analysis_quality') == decision,
                'Source readiness does not match finalized capsule evidence')
    checked = verify(root/'warm-session/iterations/0000/run/retirement-evidence',
                     expected_sha256=capsule['portable_evidence']['manifest_sha256'])
    f.p.require(checked['attempt_outcome'] == 'passed' and checked['analysis_quality'] == decision,
                'Source admission does not match independent retirement evidence')
    return {'analysis_policy': policy, 'analysis_quality': decision,
            'retirement_manifest_sha256': capsule['portable_evidence']['manifest_sha256']}


def retained_corpus(root, manifest, executed, *, max_files=100000, max_bytes=64*MIB):
    """Bound every read and accept queue entries only when a verified child ran them."""
    f.p.require(type(max_files) is int and 1 <= max_files <= 1000000 and
                type(max_bytes) is int and 1 <= max_bytes <= 1024*MIB,
                'Invalid continuation corpus limits')
    root = Path(root)
    inputs, records, total = {}, [], 0
    for relative in ('seeds', 'afl/default/queue'):
        directory = root
        queue_root = root/relative
        if (relative != 'seeds' and manifest.get('status') == 'interrupted' and manifest.get('cases') == 0 and
                not queue_root.exists() and not queue_root.is_symlink()):
            continue
        for part in Path(relative).parts:
            directory /= part
            f.p.require(directory.is_dir() and not directory.is_symlink(),
                        'Missing or linked corpus directory: '+str(directory))
        with os.scandir(directory) as entries:
            for entry in entries:
                if relative != 'seeds' and not entry.name.startswith('id:'):
                    continue
                f.p.require(len(records) < max_files, 'Continuation corpus file limit exceeded')
                path = directory/entry.name
                f.p.require(total < max_bytes, 'Continuation corpus byte limit exceeded')
                data = read_input(path, min(manifest['max_input'], max_bytes-total))
                total += len(data)
                f.p.require(total <= max_bytes, 'Continuation corpus byte limit exceeded')
                digest = hashlib.sha256(data).hexdigest()
                if relative == 'seeds':
                    f.p.require(manifest['assets'].get(str(path)) == digest,
                                'Seed is not bound to the source campaign: '+str(path))
                else:
                    # AFL copies seeds into queue before its first dry-run execution.
                    # A duplicate of an asset-bound seed adds no new input to the corpus.
                    f.p.require(digest in executed or digest in inputs,
                                'Queue input has no verified child evidence: '+str(path))
                inputs[digest] = data
                records.append({'path': str(path.relative_to(root)), 'sha256': digest, 'bytes': len(data)})
    f.p.require(inputs, 'Continuation corpus is empty')
    return inputs, {'files': len(records), 'unique_inputs': len(inputs), 'read_bytes': total,
                    'unique_bytes': sum(map(len, inputs.values())),
                    'inputs': sorted(records, key=lambda item: item['path'])}


def prepare_continuation(source, output, *, max_corpus_files=100000, max_corpus_bytes=64*MIB):
    source = Path(source).expanduser().resolve(strict=True)
    output = Path(output).expanduser().absolute()
    f.p.require(not output.exists() and not output.is_symlink(), 'Use a new continuation output directory')
    output = output.resolve()
    # The same lock is held exclusively by run_campaign. Never create or edit source files.
    fd = os.open(source/'.campaign.lock', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        f.p.require(stat.S_ISREG(os.fstat(fd).st_mode), 'Invalid source campaign lock')
        fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
        source_digest = f.p.sha(source/'campaign.json')
        evidence_paths = ('warm-session-result.json', 'warm-ready.json', 'warm-executor.json', 'phase2-progress.json')
        if (source/'interruption.json').is_file():
            evidence_paths += ('interruption.json',)
        evidence = {name: f.p.sha(source/name) for name in evidence_paths}
        original, executed, admission = verify_stopped(source)
        inputs, corpus = retained_corpus(source, original, executed,
            max_files=max_corpus_files, max_bytes=max_corpus_bytes)
        f.p.require(f.p.sha(source/'campaign.json') == source_digest and
                    all(f.p.sha(source/name) == digest for name, digest in evidence.items()),
                    'Source campaign changed during continuation verification')
        snapshot = f.EnvironmentSnapshotStore(original['snapshot_store']).verify(original['snapshot_id'])
        record = {'schema': 1, 'profile': PROFILE, 'source_campaign': str(source),
            'source_campaign_sha256': source_digest, 'source_evidence_sha256': evidence,
            'environment_sha256': snapshot.tree_sha256, 'corpus': corpus, **admission,
            'strategy': 'corpus_in_new_warm_session', 'phase1_runs_per_new_session': 1,
            'cpu_checkpoint_restored': False, 'afl_scheduler_restored': False,
            'preparation_assets': 'verified_source_assets_retained_by_path'}
        value = clone_campaign(source, output, inputs=[inputs[key] for key in sorted(inputs)])
        try:
            cloned = f.EnvironmentSnapshotStore(value['snapshot_store']).verify(value['snapshot_id'])
            f.p.require(cloned.tree_sha256 == snapshot.tree_sha256,
                        'Continuation changed the prepared filesystem')
            f.p.require(f.p.sha(source/'campaign.json') == source_digest and
                        all(f.p.sha(source/name) == digest for name, digest in evidence.items()),
                        'Source campaign changed during continuation preparation')
            f.verify_campaign(source)
            # Do not accept a corpus changed after selection, even by an uncooperative writer.
            for item in corpus['inputs']:
                data = read_input(source/item['path'], original['max_input'])
                f.p.require(hashlib.sha256(data).hexdigest() == item['sha256'],
                            'Source corpus changed during continuation preparation')
            f.atomic_json(output/'continuation.json', record)
            value['continuation'] = {'profile': PROFILE, 'source_campaign': str(source),
                'source_campaign_sha256': source_digest, 'corpus_inputs': len(inputs)}
            value['assets'][str(output/'continuation.json')] = f.p.sha(output/'continuation.json')
            if original.get('status') == 'interrupted':
                value['assets'][str(source/'interruption.json')] = evidence['interruption.json']
            value['source_sha256']['taintforge_env/afl_continue.py'] = f.p.sha(Path(__file__))
            f.atomic_json(output/'campaign.json', value)
            f.verify_campaign(output)
            return value
        except BaseException as exc:
            value.update(status='failed', error='Continuation preparation failed: '+str(exc))
            f.atomic_json(output/'campaign.json', value)
            raise
    finally:
        os.close(fd)


def resume(source, output, *, seconds=300, executions=None, afl_bin=None, max_artifact_mib=None,
           max_corpus_files=100000, max_corpus_bytes=64*MIB, prepare_only=False, stop_timeout=120):
    from .afl_transport import run_campaign
    from .afl_stop import validate_timeout
    validate_timeout(stop_timeout)
    source = Path(source).expanduser().resolve(strict=True)
    original = f.verify_campaign(source)
    f.p.require(type(seconds) is int and 1 <= seconds <= original.get('warm', {}).get('campaign_seconds', 0),
                'Continuation exceeds the prepared capsule lifetime')
    f.p.require(executions is None or type(executions) is int and executions >= 1,
                'Invalid continuation execution budget')
    f.p.require(max_artifact_mib is None or type(max_artifact_mib) is int and 16 <= max_artifact_mib <= 1048576,
                'Invalid continuation artifact budget')
    if not prepare_only:
        import shutil
        binary = Path(afl_bin).expanduser().resolve()/'afl-fuzz' if afl_bin else Path(shutil.which('afl-fuzz') or '/missing/afl-fuzz')
        f.p.require(binary.is_file() and os.access(binary, os.X_OK), 'afl-fuzz is not installed')
        f.p.sha(binary)
    value = prepare_continuation(source, output, max_corpus_files=max_corpus_files,
                                 max_corpus_bytes=max_corpus_bytes)
    output = Path(output).expanduser().resolve(strict=True)
    report = {'schema': 1, 'profile': PROFILE, 'status': 'prepared',
              'campaign': str(output), 'source_campaign': str(source),
              'strategy': 'corpus_in_new_warm_session', 'phase1_runs': 0,
              'corpus_inputs': value['continuation']['corpus_inputs']}
    try:
        if not prepare_only:
            result = run_campaign(output, seconds=seconds, executions=executions, afl_bin=afl_bin,
                                  max_artifact_mib=max_artifact_mib, stop_timeout=stop_timeout)
            report.update(status=result['status'], phase1_runs=result.get('phase1_runs', 0),
                          cases=result.get('cases', 0), completed_cases=result.get('completed_cases', 0))
        return report
    except BaseException as exc:
        report.update(status='interrupted' if isinstance(exc, InterruptedError) else 'failed',
                      error=type(exc).__name__+': '+str(exc))
        raise
    finally:
        f.atomic_json(output/'continuation-result.json', report)
