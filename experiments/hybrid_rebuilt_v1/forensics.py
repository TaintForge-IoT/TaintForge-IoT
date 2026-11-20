"""Read-only, bounded triage of an existing live-hybrid DSE attempt.

No guest, solver, AFL or plugin is executed. Evidence not present in the
provided campaign is explicitly reported as absent, never reconstructed.
"""
from __future__ import annotations

from contextlib import contextmanager
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import stat


MAX_JSON = 4 * 1024 * 1024
DETAIL_KEYS = ('profile', 'status', 'dse_status', 'reason', 'error', 'new_seed_count',
               'selected_request_ids', 'attempts', 'worker', 'mapping',
               'candidate_sha256', 'source_and_worker_evidence_reaudited',
               'successor_boundary_observed', 'fresh_runtime_inputs')


@contextmanager
def evidence_file(path, limit):
    """Keep one bounded regular file open and check it across the entire read."""
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    with os.fdopen(os.open(path, flags), 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or not 0 < info.st_size <= limit:
            raise ValueError(f'Invalid evidence file: {path}')
        yield stream, info.st_size
        after = os.fstat(stream.fileno())
        if after.st_size != info.st_size or after.st_ctime_ns != info.st_ctime_ns:
            raise ValueError(f'Evidence changed during read: {path}')


def read_bytes(path, limit):
    with evidence_file(path, limit) as (stream, size):
        raw = stream.read(size + 1)
        if len(raw) != size:
            raise ValueError(f'Incomplete evidence file: {path}')
        return raw


def json_object(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('Duplicate DSE evidence JSON key')
            result[key] = value
        return result
    def invalid(value):
        raise ValueError('Non-finite DSE evidence number: ' + value)
    value = json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid)
    if not isinstance(value, dict):
        raise ValueError('Evidence JSON must be an object')
    return value


def safe_json(path):
    raw = read_bytes(path, MAX_JSON)
    return json_object(raw), sha256(raw).hexdigest()


def diagnose(campaign, job_number=2):
    """Summarize raw worker evidence without interpreting failed jobs as SAT."""
    root = Path(campaign).expanduser().resolve(strict=True)
    if type(job_number) is not int or not 1 <= job_number <= 8:
        raise ValueError('DSE job number outside 1..8')
    hybrid, hybrid_hash = safe_json(root / 'hybrid-result.json')
    summary = next((row for row in hybrid.get('DSE_jobs', [])
                    if isinstance(row, dict) and row.get('job') == job_number), None)
    if summary is None:
        raise ValueError('DSE job is not present in the recorded live-hybrid results')
    name = f'job-{job_number:02d}'
    directory = root / 'dse' / name
    if not directory.is_dir() or directory.is_symlink():
        raise ValueError('DSE job evidence directory is missing or invalid')
    requested = summary.get('request_id')
    files = []
    candidates = [directory / 'summary.json', directory / 'manifest.json']
    jobs = directory / 'jobs'
    if jobs.is_dir() and not jobs.is_symlink():
        for worker in sorted(jobs.iterdir()):
            if worker.is_symlink() or not worker.is_dir() or not re.fullmatch(r'\d{4}', worker.name):
                continue
            for attempt in sorted(worker.iterdir()):
                if attempt.is_symlink() or not attempt.is_dir():
                    continue
                if re.fullmatch(r'recapture-\d{4}', attempt.name) or attempt.name == 'inversion':
                    candidates.append(attempt / 'summary.json')
    if len(candidates) > 100:
        raise ValueError('DSE job evidence exceeds triage file budget')
    for path in candidates:
        if not path.exists():
            files.append({'path': path.relative_to(root).as_posix(), 'present': False})
            continue
        doc, identity = safe_json(path)
        details = {key: doc[key] for key in DETAIL_KEYS if key in doc and key != 'fresh_runtime_inputs'}
        files.append({'path': path.relative_to(root).as_posix(),
                      'present': True, 'sha256': identity, 'selected_fields': details})
    controller_summary = dict(summary)
    primary = next((f for f in files if f['path'] == f'dse/{name}/summary.json'), None)
    stage = 'unresolved_requires_worker_evidence'
    if primary is not None and primary.get('present'):
        details = primary['selected_fields']
        if details.get('status') == 'failed':
            stage = 'extend_corpus_or_worker_publication_failed'
        elif details.get('status') == 'passed':
            if details.get('dse_status') != 'VERIFIED' or details.get('new_seed_count') != 1:
                stage = 'no_verified_new_candidate'
            elif summary.get('status') != 'VERIFIED':
                stage = 'post_publication_fresh_audit_or_controller_binding_failed'
    return {'schema': 1, 'profile': 'read_only_dse_forensics_v1',
            'campaign': str(root), 'hybrid_result_sha256': hybrid_hash,
            'job': job_number, 'request_id': requested, 'controller_job': controller_summary,
            'classification': stage, 'evidence': files,
            'limitations': ['No fresh guest/solver replay was performed',
                'A controller FAILED state alone does not identify an SMT failure',
                'Auditing failures require their original, complete worker artifacts']}
