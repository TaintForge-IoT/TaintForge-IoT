"""Common file guards and portable regression assertions."""
import hashlib
import json
import os
from pathlib import Path
import stat
import zipfile

MIB = 1024 ** 2


def require(condition, message):
    if not condition: raise RuntimeError(message)


def digest(path):
    path = Path(path)
    require(path.is_file() and not path.is_symlink(), 'Missing regular file: ' + str(path))
    with path.open('rb') as stream: return hashlib.file_digest(stream, 'sha256').hexdigest()


def read(path):
    path = Path(path)
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= 16 * MIB,
            'Missing or oversized JSON: ' + str(path))
    return json.loads(path.read_text())


def save(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def route(native):
    return [[r['instruction']['pc'], r['instruction']['bytes'], r['instruction']['vcpu'],
             r['next_pc'], r['branch_outcome']] for r in native['trace']]


def ready(native):
    value = native.get('replay_build') or {}
    require(value.get('status') == 0 and value.get('issues') == 0 and
            value.get('stopped_origin') is None and
            value.get('selected_steps') == value.get('lifted_steps') and value.get('selected_steps', 0) > 0,
            'Regression prefix is not completely lifted')


def verify_case(root, row):
    path = root / row['data']
    require(path.resolve().is_relative_to(root.resolve()), 'Case data escapes suite')
    for label in ('seed', 'witness', 'expected', 'seed_stdout', 'witness_stdout'):
        filename = {'expected': 'expected.json', 'seed_stdout': 'seed.stdout',
                    'witness_stdout': 'witness.stdout'}.get(label, label)
        require(digest(path / filename) == row[label + '_sha256'], 'Regression data changed: ' + str(path / filename))
    expected = read(path / 'expected.json')
    require(expected['branch_pc'] == row['pc'] and expected['baseline_taken'] != expected['witness_taken'],
            'Regression branch identity or inversion changed')
    seed, witness = (path / 'seed').read_bytes(), (path / 'witness').read_bytes()
    require(len(seed) == len(witness) and [i for i, (a, b) in enumerate(zip(seed, witness)) if a != b] == row['offsets'],
            'Regression witness does not change exactly its selected bytes')
    require(expected['baseline_route'][:-1] == expected['witness_route'][:-1],
            'Saved witness changed an earlier path')
    return expected


def check_inversion(row, expected, result, solved, observed, seed, candidate):
    require(result['dse_status'] == 'VERIFIED' and result['reason'] == 'prefix_preserved_branch_inverted',
            'Regression inversion did not produce a verified candidate: ' + row['id'])
    ready(solved); ready(observed)
    require(solved['status'] == 'BOUNDARY_WITNESS' and observed['status'] == 'OBSERVED',
            'Regression lacks solve or observed candidate evidence')
    require(route(solved) == expected['baseline_route'] and solved['taken'] == expected['baseline_taken'],
            'Regression baseline diverged from its accepted path')
    require(route(solved)[:-1] == route(observed)[:-1] and observed['taken'] == expected['witness_taken'] and
            observed['successor']['pc'] == solved['predicted_target'] == expected['witness_successor'],
            'Fresh candidate did not preserve the accepted prefix and invert its target')
    require(solved['branch_pc'] == observed['branch_pc'] == row['pc'], 'Regression PC changed')
    changed = {i for i, (a, b) in enumerate(zip(seed, candidate)) if a != b}
    require(len(seed) == len(candidate) and changed and changed <= set(row['offsets']),
            'Fresh candidate changed bytes outside the selected input scope')
    require(hashlib.sha256(seed).hexdigest() == row['seed_sha256'] and
            hashlib.sha256(candidate).hexdigest() == result['candidate_sha256'], 'Fresh input byte identity differs')


def check_saved_witness(row, expected, native):
    ready(native)
    require(native['status'] == 'OBSERVED' and route(native) == expected['witness_route'] and
            native['taken'] == expected['witness_taken'], 'Previously accepted witness no longer reproduces: ' + row['id'])


def check_guards(inventory):
    for path, expected in inventory.items():
        require(digest(path) == expected, 'Guarded file changed: ' + str(path))


def export_reports(work):
    excluded = {'runtime', 'rootfs', 'template-rootfs', 'snapshots', 'seeds', 'accepted-seeds', '__pycache__'}
    files, omitted = [], []
    for root, dirs, names in os.walk(work, followlinks=False):
        dirs[:] = [n for n in dirs if n not in excluded and not (Path(root) / n).is_symlink()]
        for name in names:
            p = Path(root) / name
            allowed = p.suffix in ('.json', '.jsonl', '.log', '.txt', '.receipt', '.elf', '.c', '.S') or name == 'input.bin'
            if not allowed: continue
            if p.is_symlink() or not stat.S_ISREG(p.lstat().st_mode): omitted.append(str(p.relative_to(work)))
            else: files.append(p)
    destination = work / ('taintforge_regression_' + work.name + '_reports.zip')
    total = 0
    with zipfile.ZipFile(destination, 'x', compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(files, key=lambda p: (p.suffix != '.json', str(p))):
            size = path.stat().st_size
            if size > 32 * MIB or total + size > 256 * MIB:
                omitted.append(str(path.relative_to(work))); continue
            archive.write(path, str(path.relative_to(work))); total += size
        archive.writestr('export_inventory.json', json.dumps({'omitted': omitted, 'uncompressed_bytes': total,
            'scope': 'reports, generated probe ELFs and source; excludes guest filesystems and analyzer libraries'}, indent=2) + '\n')
    print('Reports: ' + str(destination), flush=True)
