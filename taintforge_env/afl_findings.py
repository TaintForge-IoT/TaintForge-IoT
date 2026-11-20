"""Record reproducible inputs and heuristic fault groups independently of AFL."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil

from . import afl_file as f


def signature(result):
    value = result['outcome']
    identity = {'schema': 1, 'kind': value['kind'], 'signal': value['guest_signal'],
                'pc': value['guest_pc'] if value['kind'] == 'guest_crash' else None,
                'filesystem': result.get('filesystem_sha256'),
                'coverage': result['coverage']['map_sha256'] if value['kind'] == 'timeout' else None}
    return hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()


def record(root, case):
    root, case = Path(root), Path(case)
    result = f.read_json(case/'result.json')
    value = result.get('outcome', {})
    if value.get('kind') not in {'guest_crash', 'timeout'}:
        return None
    data = (case/'input').read_bytes()
    f.p.require(hashlib.sha256(data).hexdigest() == result['input']['input_sha256'],
                'Finding input does not match the executed child')
    key = signature(result)
    category = 'crashes' if value['kind'] == 'guest_crash' else 'hangs'
    directory = root/'findings'/category/key
    directory.mkdir(parents=True, exist_ok=True)
    relative = str(case.relative_to(root))
    manifest = f.read_json(root/'campaign.json')
    if not (directory/'finding.json').exists():
        (directory/'input').write_bytes(data)
        f.atomic_json(directory/'finding.json', {
            'schema': 1, 'signature': key, 'grouping': 'heuristic_not_unique_bug_proof',
            'kind': value['kind'], 'input_sha256': hashlib.sha256(data).hexdigest(),
            'first_case': relative, 'outcome': value,
            'case_result_sha256': f.p.sha(case/'result.json'),
            'filesystem_sha256': result.get('filesystem_sha256'),
            'source_sha256': manifest.get('source_sha256'),
            'assets': manifest.get('assets'), 'launch': manifest.get('launch'),
            'warm': manifest.get('warm'), 'snapshot_id': manifest.get('snapshot_id'),
            'phase1_runs': result.get('phase1_runs')})
        shutil.copyfile(case/'coverage.map', directory/'coverage.map')
    event = {'case': relative, 'input_sha256': result['input']['input_sha256'],
             'signature': key, 'kind': value['kind'], 'outcome': value}
    with (directory/'occurrences.jsonl').open('a') as stream:
        stream.write(json.dumps(event, sort_keys=True)+'\n')
    f.atomic_json(case/'finding.json', {'schema': 1, 'signature': key,
                                      'finding': str(directory.relative_to(root))})
    return directory
