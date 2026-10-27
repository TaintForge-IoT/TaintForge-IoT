"""Fresh isolated file-seed analysis; candidates remain independent of AFL/DSE."""
from __future__ import annotations

import hashlib
from pathlib import Path
import time

from .afl_file import atomic_json, create_guest_file, validate_guest_path
from .dta_capsule import run_case
from .dta_corpus import DtaCorpusError, _canonical, _limit, _pin, _require, generate_corpus, parse_trace
from .elf_runtime import provision_guest
from .environment_snapshot import EnvironmentSnapshotStore
from .input_retirement import inspect_input
from .unified_runtime import build_bundle, check_runtime_inputs


PROJECT = Path(__file__).resolve().parents[1]


def _arguments(argv):
    _require(isinstance(argv, (list, tuple)) and len(argv) <= 32 and
             all(isinstance(arg, str) and '\0' not in arg and len(arg.encode()) <= 4096 for arg in argv) and
             sum(len(arg.encode()) for arg in argv) <= 16384, 'Invalid bounded guest argv')
    return list(argv)


def analyze_file(*, binary, qemu, plugin, seed, input_path, argv=(), out,
                 max_candidates=40, seconds=10, memory_mib=1024, wall_seconds=900):
    _limit(max_candidates, 128, 'analysis candidates')
    _limit(seconds, 120, 'case seconds')
    _limit(wall_seconds, 7200, 'worker seconds')
    _require(type(memory_mib) is int and 256 <= memory_mib <= 4096, 'Invalid worker memory budget')
    argv = _arguments(argv)
    validate_guest_path(input_path)
    _require(input_path != '/bin/sample.elf', 'The executable cannot be the mutable input')
    seed, seed_identity = _pin(seed, 4096)
    _require(seed_identity['size'] > 0, 'Seed must be nonempty')
    binary, binary_identity = _pin(binary, 64 * 1024**2)
    inspect_input(binary)
    qemu, qemu_identity = _pin(qemu, 512 * 1024**2)
    plugin, plugin_identity = _pin(plugin, 512 * 1024**2)
    sidecar, sidecar_identity = _pin(Path(str(plugin) + '.runtime.json'), 16 * 1024**2)
    check_runtime_inputs(PROJECT, qemu=qemu, plugin=plugin)
    sources = [(seed, seed_identity, 4096), (binary, binary_identity, 64 * 1024**2),
               (qemu, qemu_identity, 512 * 1024**2), (plugin, plugin_identity, 512 * 1024**2),
               (sidecar, sidecar_identity, 16 * 1024**2)]
    out = _canonical(out)
    _require(not out.exists() and all(not path.is_relative_to(out) and not out.is_relative_to(path)
             for path, _, _ in sources), 'Worker output must be new and outside its inputs')
    data = seed.read_bytes()
    _require(hashlib.sha256(data).hexdigest() == seed_identity['sha256'], 'Seed changed before capture')
    out.mkdir(parents=True)
    deadline = time.monotonic() + wall_seconds
    report = {'schema': 1, 'status': 'failed', 'profile': 'dta-file-analysis-v1',
        'dse_status': 'NOT_RUN', 'afl_campaign_executed': False,
        'novelty_scope': 'observed_diagnostic_branch_outcomes',
        'protected_diagnostic_channel': False, 'universal_equivalence': False,
        'input_path': input_path, 'argv': argv,
        'inputs': {'seed': seed_identity, 'binary': binary_identity, 'qemu': qemu_identity,
                   'plugin': plugin_identity, 'runtime_manifest': sidecar_identity},
        'budgets': {'max_candidates': max_candidates, 'case_cpu_seconds': seconds,
                    'memory_mib': memory_mib, 'worker_wall_seconds': wall_seconds},
        'runs': []}
    try:
        runtime = build_bundle(out / 'runtime', qemu=qemu, plugin=plugin)
        rootfs = out / 'template-rootfs'
        for name in ('proc', 'dev', 'sys', 'tmp', 'bin', 'etc'):
            (rootfs / name).mkdir(parents=True, exist_ok=True)
        (rootfs / 'tmp').chmod(0o1777)
        provision_guest(binary, rootfs, sysroot=Path('/'), binary_guest_path='/bin/sample.elf')
        create_guest_file(rootfs, input_path, data)
        snapshots = EnvironmentSnapshotStore(out / 'snapshots')
        snapshot = snapshots.capture(rootfs).manifest
        report['snapshot'] = {'snapshot_id': snapshot.snapshot_id, 'tree_sha256': snapshot.tree_sha256}

        def observe(raw, directory):
            remaining = int(deadline - time.monotonic())
            _require(remaining >= 1, 'Analysis worker wall-time budget exceeded')
            receipt = run_case(project=PROJECT, bundle=out / 'runtime',
                bundle_sha256=runtime['bundle_sha256'], store=snapshots.store_dir,
                snapshot_id=snapshot.snapshot_id, input_path=input_path, data=raw,
                argv=argv, out=directory, seconds=min(seconds, remaining), memory_mib=memory_mib)
            _require(receipt.get('status') == 'passed' and
                     receipt.get('resources', {}).get('status') == 'verified' and
                     receipt['resources'].get('tree_empty') is True and
                     receipt.get('phase1', {}).get('runtime_observed') is True and
                     receipt['phase1'].get('artifact_integrity') == 'verified' and
                     receipt['phase1'].get('dta_diagnostics_accepted') is True,
                     'Analysis case lacks complete runtime and cleanup evidence')
            _require(receipt.get('input_sha256') == hashlib.sha256(raw).hexdigest() and
                     receipt.get('target_sha256') == binary_identity['sha256'] and
                     receipt.get('input_path') == input_path, 'Analysis case source binding mismatch')
            trace = _canonical(receipt['trace'])
            _require(trace.is_relative_to(directory), 'Analysis trace escapes its case')
            parsed = parse_trace(trace, input_path, len(raw))
            _require(parsed['trace_sha256'] == receipt.get('trace_sha256'), 'Recorded analysis trace changed')
            stdout, stdout_identity = _pin(receipt['stdout'], 16 * 1024**2)
            _require(stdout.is_relative_to(directory) and stdout_identity['sha256'] == receipt.get('stdout_sha256'),
                     'Recorded analysis stdout changed or escaped its case')
            signature = {(group['pc'], group['outcome']) for group in parsed['groups']}
            _require(time.monotonic() < deadline, 'Analysis worker wall-time budget exceeded')
            report['runs'].append({'case': str(directory.relative_to(out)),
                'input_sha256': hashlib.sha256(raw).hexdigest(), 'guest_exit': receipt['guest_exit'],
                'trace_sha256': parsed['trace_sha256'], 'observed_branch_outcomes': sorted(signature)})
            return receipt, signature

        baseline, known = observe(data, out / 'baseline')
        repeat, repeated = observe(data, out / 'repeat')
        _require(known == repeated and baseline['guest_exit'] == repeat['guest_exit'],
                 'Repeated baseline input has unstable observed branch outcomes or exit status')
        corpus = generate_corpus(seed=seed, binary=binary, trace=Path(baseline['trace']),
            input_path=input_path, out=out / 'corpus', max_candidates=max_candidates)
        accepted = []
        new_outcomes = set()
        replays = out / 'replays'
        replays.mkdir()
        for index, candidate in enumerate(corpus['candidates']):
            raw = (out / 'corpus/seeds' / candidate['sha256']).read_bytes()
            _require(hashlib.sha256(raw).hexdigest() == candidate['sha256'], 'Corpus candidate changed')
            if candidate['baseline']:
                accepted.append({'sha256': candidate['sha256'], 'case': 'baseline', 'new_outcomes': []})
                continue
            _, signature = observe(raw, replays / f'{index:04d}')
            fresh = signature - known
            if fresh:
                accepted.append({'sha256': candidate['sha256'], 'case': f'replays/{index:04d}',
                                 'new_outcomes': sorted(fresh)})
            known.update(signature)
            new_outcomes.update(fresh)
        _require(snapshots.verify(snapshot.snapshot_id).tree_sha256 == snapshot.tree_sha256,
                 'Baseline snapshot changed')
        for path, identity, maximum in sources:
            _require(_pin(path, maximum)[1] == identity, f'Analysis source changed: {path}')
        _require(time.monotonic() < deadline, 'Analysis worker wall-time budget exceeded')
        destination = out / '.accepted-seeds.pending'
        destination.mkdir()
        for candidate in accepted:
            raw = (out / 'corpus/seeds' / candidate['sha256']).read_bytes()
            _require(hashlib.sha256(raw).hexdigest() == candidate['sha256'], 'Accepted seed changed')
            (destination / candidate['sha256']).write_bytes(raw)
        destination.rename(out / 'accepted-seeds')
        report.update(status='passed', candidate_count=len(corpus['candidates']),
            concrete_runs=len(report['runs']), baseline_repetitions=2,
            new_branch_outcomes=len(new_outcomes), accepted_seed_count=len(accepted),
            accepted=accepted, input_execution_binding='fresh_snapshot_bound_launch',
            original_inputs_unchanged=True, baseline_snapshot_unchanged=True)
        return report
    except Exception as exc:
        report['error'] = f'{type(exc).__name__}: {exc}'
        raise
    finally:
        atomic_json(out / 'summary.json', report)
