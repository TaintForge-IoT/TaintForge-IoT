import argparse
import hashlib
import json
from pathlib import Path
import resource
import threading
import time

from taintforge_env import afl_file as f, afl_phase2 as phase2, afl_storage as storage


def verify(out, *, cases=10000, mode='parallel'):
    out = Path(out).resolve()
    if not 1 <= cases <= 100000 or out.exists():
        raise ValueError('Use a new result directory and 1..100000 cases')
    out.mkdir(parents=True)
    rootfs, parent = out/'fixture/rootfs', out/'fixture/parent'
    (rootfs/'etc').mkdir(parents=True); (parent/'config').mkdir(parents=True); (parent/'logs').mkdir()
    f.atomic_json(parent/'config/runtime.json', {'network_mode': 'none', 'allow_internet': False})
    (rootfs/'etc/input').write_bytes(b'A')
    (out/'cases').mkdir()
    manifest = {'profile': 'synthetic-storage-phase2-components', 'status': 'running'}
    storage.bind(manifest, storage.policy(artifact_mib=2048, case_mib=1, reserve_mib=1,
                                        rootfs_mib=64, min_free_mib=64))
    f.atomic_json(out/'campaign.json', manifest)
    budget = storage.Budget(out, manifest['storage'])
    config = phase2.settings(mode, 4)
    processor = phase2.Processor(out, config, on_complete=budget.complete)
    stop = threading.Event()
    started = time.monotonic()
    fd_before = len(list(Path('/proc/self/fd').iterdir()))
    report = {'schema': 1, 'status': 'failed', 'scope': 'synthetic_child_captures_real_phase2_and_storage',
              'native_qemu_executed': False, 'phase1_executed': False, 'full_m5_acceptance': False,
              'mode': mode, 'requested_cases': cases,
              'source_sha256': {name: f.p.sha(f.PROJECT/name) for name in
                  ('taintforge_env/afl_storage.py', 'taintforge_env/afl_phase2.py',
                   'taintforge_env/afl_file.py', 'scripts/verify_afl_storage_components.py')}}
    try:
        budget.open(); processor.start()
        bitmap = b'\1'+bytes(f.MAP_SIZE-1)
        for index in range(cases):
            budget.admit(index, stop=stop)
            case = out/'cases'/f'{index:08d}'; case.mkdir()
            data = bytes([65+index%26])
            (case/'input').write_bytes(data); (rootfs/'etc/input').write_bytes(data)
            capture = phase2.Capture(rootfs, parent, case, excluded=(), config=config, phase1_runs=0)
            capture.before()
            pid = 100+index
            with (parent/'logs/qemu_strace.log').open('a') as log:
                log.write(str(pid)+' open("/var/component/state",O_RDONLY) = -1 errno=2 (No such file or directory)\n')
            result = {'schema': 1, 'status': 'passed', 'child_namespace_pid': pid,
                      'guest_exit': 0, 'phase1_runs': 0, 'input': f.settings('/etc/input', data),
                      'coverage': {'map_sha256': hashlib.sha256(bitmap).hexdigest()},
                      'outcome': {'kind': 'normal', 'guest_signal': None, 'guest_exit': 0, 'timed_out': False}}
            f.atomic_json(case/'result.json', result); (case/'coverage.map').write_bytes(bitmap)
            capture.finish(result); processor.submit(case)
            if (index+1)%1000 == 0:
                print(str(index+1)+' captures; '+str(processor.completed)+' Phase 2 reports', flush=True)
        processor.close()
        if processor.completed != cases or processor.errors:
            raise RuntimeError('Phase 2 did not finish every capture')
        budget.check(force=True)
        report.update(status='passed', completed=processor.completed,
                      maximum_pending=processor.maximum_pending)
    finally:
        stop.set()
        budget.release_reserve()
        try: processor.close()
        finally:
            report.update(elapsed_seconds=round(time.monotonic()-started, 3), storage=budget.report(),
                          fd_before=fd_before, fd_after=len(list(Path('/proc/self/fd').iterdir())),
                          process_peak_rss_kib=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
            if report['fd_before'] != report['fd_after']:
                report.update(status='failed', error='Descriptor count changed')
            f.atomic_json(out/'acceptance.json', report)
    return report


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--cases', type=int, default=10000)
    parser.add_argument('--mode', choices=('parallel', 'sequential'), default='parallel')
    args = parser.parse_args()
    result = verify(args.out, cases=args.cases, mode=args.mode)
    print(json.dumps(result, indent=2))
    return 0 if result['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
