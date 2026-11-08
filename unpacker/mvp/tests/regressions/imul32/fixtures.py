"""Use the existing 39 accepted fixed cases and three new IMUL32 cases."""
import hashlib
import importlib.util
from pathlib import Path

import controls
import models
import probes
from support import digest, read, require, route, ready

ROOT = Path(__file__).resolve().parent
ORDER = ('bt32', 'div32', 'signed_div32', 'bitscan32', 'rotate32', 'shrd32', 'mul32', 'shld32')


def stdout_model(case, raw, oracle=None):
    row = case['row']
    if case['suite'] == 'bt32':
        require(oracle is not None, 'The pinned native tokenizer oracle is required')
        return oracle(raw)
    value = (controls.model(7, raw) if case['suite'] == 'div32' else
             models.model(row['kind'], raw) if case['suite'] in ('shld32', 'imul32') else probes.model(row['kind'], raw))
    output = b'F\n' if value == row['compare_value'] else b'T\n'
    return output + (b'' if case['suite'] == 'div32' else value.to_bytes(4, 'little'))


def fixed(case, label):
    return case['folder'] / label


def load_cases(project=None):
    cases = []
    catalog = read(ROOT / 'legacy-catalog.json') if project is not None else {}
    for name in ORDER if project is not None else ():
        folder = project / 'unpacker/mvp/tests/regressions' / name
        definition = read(folder / 'cases.json')
        require(definition == catalog[name]['definition'], 'Existing fixed suite definition changed: ' + name)
        for saved in catalog[name]['cases']:
            row = dict(saved['row'])
            data = folder / row['data']
            require(data.resolve(strict=True).is_relative_to(folder.resolve(strict=True)), 'Invalid legacy fixture path')
            expected = read(data / 'expected.json')
            require(expected == saved['expected'] and digest(data / 'expected.json') == row['expected_sha256'],
                    'Existing expected route changed')
            for label, encoded in saved['fixed'].items():
                path = data / label
                require(path.read_bytes() == bytes.fromhex(encoded) and
                        digest(path) == row[label.replace('.', '_') + '_sha256'], 'Existing fixed input/output changed')
            source = folder / (definition['legacy_binary']['hex_file'] if name == 'bt32' else row['data'] + '/elf.hex')
            row['elf_sha256'] = definition['legacy_binary']['sha256'] if name == 'bt32' else row['elf_sha256']
            if name != 'bt32':
                require(digest(source) == row['elf_hex_sha256'], 'Existing fixed ELF text changed')
            cases.append({'suite': name, 'row': row, 'expected': expected, 'folder': data, 'elf_hex': source})
    definition = read(ROOT / 'cases.json')
    require(definition['profile'] == 'imul32-fixed-elf-regressions-v1' and len(definition['cases']) == 3 and
            {(r['kernel'], r['optimization']) for r in definition['cases']} ==
            {('smul_hi32', o) for o in ('O1', 'O2', 'O3')}, 'Expected exactly three IMUL32 compiler fixtures')
    for row in definition['cases']:
        folder = ROOT / row['data']
        require(folder.resolve(strict=True).is_relative_to(ROOT), 'Invalid IMUL32 fixture path')
        for key, filename in (('seed', 'seed'), ('witness', 'witness'), ('secondary', 'secondary'),
                              ('expected', 'expected.json'), ('elf_hex', 'elf.hex'),
                              ('seed_stdout', 'seed.stdout'), ('witness_stdout', 'witness.stdout'),
                              ('secondary_stdout', 'secondary.stdout')):
            require(digest(folder / filename) == row[key + '_sha256'], 'IMUL32 fixture changed: ' + filename)
        require(row['kind'] == 3 and row['offsets'] == list(range(8)), 'IMUL32 fixture input scope differs')
        values = [(folder / label).read_bytes() for label in ('seed', 'witness', 'secondary')]
        changes = [i for i, (a, b) in enumerate(zip(values[0], values[1])) if a != b]
        require(all(len(v) == 8 for v in values) and len(set(values)) == 3 and changes == row['changed_offsets'] and
                changes and set(changes) <= set(row['offsets']), 'IMUL32 fixed input identities differ')
        expected = read(folder / 'expected.json')
        case = {'suite': 'imul32', 'row': row, 'expected': expected, 'folder': folder, 'elf_hex': folder / 'elf.hex'}
        for label, value in zip(('seed', 'witness', 'secondary'), values):
            require(models.model(row['kind'], value) == row['expected_' + label + '_value'] and
                    (folder / (label + '.stdout')).read_bytes() == stdout_model(case, value),
                    'IMUL32 fixed result differs from independent signed multiplication model')
        require(row['expected_seed_value'] == row['compare_value'] != row['expected_witness_value'] and
                expected['baseline_taken'] is False and expected['witness_taken'] is True and
                expected['baseline_route'][:-1] == expected['witness_route'][:-1], 'IMUL32 witness does not invert the selected branch')
        cases.append(case)
    require(len(cases) == (42 if project is not None else 3), 'Permanent fixed-case inventory differs')
    for case in cases:
        row, expected = case['row'], case['expected']
        require(expected['branch_pc'] == row['pc'] and expected['baseline_taken'] != expected['witness_taken'],
                'Selected branch identity differs')
        row.setdefault('branch_bytes', expected['branch_bytes'])
        raw = bytes.fromhex(case['elf_hex'].read_text())
        require(hashlib.sha256(raw).hexdigest() == row['elf_sha256'], 'Fixed ELF bytes differ')
        case['elf_bytes'] = raw
    return cases


def materialize(case, directory):
    directory.mkdir(parents=True, exist_ok=True)
    binary = directory / (case['row']['id'] + '.elf')
    if binary.exists():
        require(digest(binary) == case['row']['elf_sha256'], 'Existing materialized ELF differs')
    else:
        binary.write_bytes(case['elf_bytes'])
        binary.chmod(0o755)
    probes.elf_view(binary)
    row = case['row']
    require(probes.instruction_bytes(binary, row['pc'], len(row['branch_bytes']) // 2).hex() == row['branch_bytes'],
            'Selected branch does not match its fixed ELF')
    return binary


def secondary_check(case, native):
    row, expected = case['row'], case['expected']
    ready(native)
    require(native['status'] == 'OBSERVED' and native['branch_pc'] == row['pc'] and
            route(native) == expected['secondary_route'] and native['taken'] == expected['secondary_taken'] and
            native['successor']['pc'] == expected['secondary_successor'], 'Fixed secondary route changed')


def tokenizer_oracle(project, work, cases):
    folder = project / 'unpacker/mvp/tests/regressions/bt32'
    spec = importlib.util.spec_from_file_location('accepted_bt32_corpus_oracle', folder / 'corpus.py')
    corpus = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(corpus)
    destination = work / 'legacy-oracle'
    if destination.exists():
        import tempfile
        destination = Path(tempfile.mkdtemp(prefix='legacy-oracle-resume.', dir=work))
        destination.rmdir()
    return corpus.legacy_oracle(destination, [case['row'] for case in cases if case['suite'] == 'bt32'])
