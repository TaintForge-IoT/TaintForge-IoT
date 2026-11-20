"""Validate retained inputs and the chain from a child to its Phase 2 report."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import stat

from . import afl_file as f


def reusable(manifest):
    if manifest.get('status') == 'interrupted':
        from .afl_stop import resumable
        return resumable(manifest)
    if manifest.get('status') == 'completed':
        return True
    if manifest.get('status') != 'resource_limited' or manifest.get('evidence_complete') is not True:
        return False
    from .afl_storage import verify_manifest
    value = verify_manifest(manifest)
    result = manifest.get('storage_result', {})
    count = manifest.get('cases')
    return (type(count) is int and count >= 0 and type(manifest.get('completed_cases')) is int and
            manifest['completed_cases'] == count and
            manifest.get('stop_reason') == 'storage_limit' and
            value is not None and result.get('profile') == 'afl-storage-v1' and result.get('policy') == value and
            result.get('policy_sha256') == manifest['storage_policy_sha256'] and
            type(result.get('pending_reservations')) is int and result['pending_reservations'] == 0 and
            result.get('reserve_released') is True and
            isinstance(result.get('stop'), dict) and result['stop'].get('category') == 'storage_limit' and
            isinstance(result['stop'].get('reason'), str) and bool(result['stop']['reason']) and
            manifest.get('storage_stop') == result['stop'])


def read_input(path, maximum):
    path = Path(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        f.p.require(stat.S_ISREG(before.st_mode) and 1 <= before.st_size <= maximum,
                    'Input must be a nonempty regular file within the campaign limit: '+str(path))
        data = stream.read(maximum+1)
        after = os.fstat(stream.fileno())
    f.p.require(len(data) == before.st_size and
                (before.st_size, before.st_mtime_ns) == (after.st_size, after.st_mtime_ns),
                'Input changed while reading: '+str(path))
    return data


def child_report(case, maximum):
    case = Path(case)
    f.p.require(case.is_dir() and not case.is_symlink() and re.fullmatch(r'[0-9]{8}', case.name),
                'Invalid child evidence directory')
    result = f.read_json(case/'result.json')
    analysis = f.read_json(case/'phase2/result.json')
    capture = f.read_json(case/'phase2/capture.json')
    digest = hashlib.sha256(read_input(case/'input', maximum)).hexdigest()
    f.p.require(result['status'] == analysis['status'] == 'passed' and
                analysis['capture_sha256'] == f.p.sha(case/'phase2/capture.json') and
                capture['case'] == case.name and
                capture['result_sha256'] == f.p.sha(case/'result.json') and
                capture['coverage_sha256'] == f.p.sha(case/'coverage.map') and
                digest == result['input']['input_sha256'] == capture['input_sha256'] == analysis['input_sha256'] and
                result['child_namespace_pid'] == analysis['child_namespace_pid'] == capture['child_namespace_pid'] and
                result['phase1_runs'] == analysis['phase1_runs'] == capture['phase1_runs'] == 1,
                'Child/Phase 2 evidence identity mismatch: '+str(case))
    for name, key in (('runtime_requirements.json', 'requirements_sha256'), ('repair_plan.json', 'repair_plan_sha256')):
        f.p.require(analysis.get(key) == f.p.sha(case/'phase2/config'/name),
                    'Repair requirements changed or repair plan changed: '+str(case))
    return analysis


def completed_cases(root, manifest):
    root = Path(root)
    count = manifest.get('cases')
    state = f.read_json(root/'phase2-progress.json')
    worker = f.read_json(root/'warm-executor.json')
    f.p.require(type(count) is int and count >= 0 and
                manifest.get('completed_cases') == worker.get('children') == state.get('submitted') == state.get('completed') == count and
                state.get('status') == worker.get('status') == 'passed' and state.get('pending') == 0,
                'Incomplete child/Phase 2 execution counts')
    cases = sorted((root/'cases').iterdir()) if (root/'cases').exists() else []
    f.p.require(len(cases) == count and all(case.name == f'{index:08d}' for index, case in enumerate(cases)),
                'Missing or unexpected child evidence directories')
    return cases
