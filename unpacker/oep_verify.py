#!/usr/bin/env python3
"""Verify the restored entry boundary of the authenticated M366 sample.

This command builds its own IR replay executable. Uploaded executables are
never invoked. A conditional restored-entry certificate does not establish
independent Linux entry origins, kernel implementation correctness or the
identity of a pre-pack reference that was not supplied.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shlex
import subprocess
import sys
import tempfile
import zipfile

sys.dont_write_bytecode = True
try:
    from .oep_entry import parse_entry_table, verify_entry_contract
    from .oep_environment import audit_environment, compare_contracts
    from .oep_boundary import audit_boundary
except ImportError:
    from oep_entry import parse_entry_table, verify_entry_contract
    from oep_environment import audit_environment, compare_contracts
    from oep_boundary import audit_boundary

ROOT = Path(__file__).resolve().parent
ELF_SHA = '7daac7415a92362184996750d19e878c49b9d5e866690e62851f4589a115bf2e'
ORIGINAL_SHA = 'ae7c5a6e46ba540af679ae282239d159fe9b8161cb39e9707760be39db79500a'
M362_SHA = 'b8f4c9842c12616006517c904009cda91f971ce4b2c2bdf944ae74a8aff9f0df'
FRONTEND_SHA = '054c3768e510d24e1799773f0a90163f5513fed078a8c8b4489a64df5d5bb9f1'
M366_DRIVER_SHA = '26cfcb471b68df459f6aee6c991850c8a4a87fe2d136cfee4bbdfe1ce28ce700'
M366_SOURCE_MANIFESTS = {
    'dee595e39c88b62ef7253a970122a6a535b9b1212c4c7c5aba6b6ae1ce3b78ac',
    # Same implementation, locally tested before documentation was finalized.
    '7d2323ff190fb1f64070236f9e3fc85ba33ead1035b12e237eea3bc8958e2ccd',
}
HEADER_PINS = {
    'dcfg.h': '873ee2d17784d4bdd11dac3c4b60c434dc60f79b5bd4359911ee28e590a1d5c5',
    'dta.h': 'ec4e45f4703cad0bd79ee8ddd9e6479a95270efad21b856dd275052bb850b874',
    'ir.h': '3cf38b32d758340606a34e9da6cebf490fd37431e79b41c3fc345950c5bfa4a0',
    'ir_environment.h': '94dc2bd22941cad333da1397c666d22b7cd8c35e8f18fda5c2a5eef2ac75a2bf',
    'ir_lift_x86.h': '7f91c35f62adbe8e87d38d9d0e99bab743b1b8c477b23b8134c833115655ad14',
    'provenance.h': 'c7c776c74dcc0b8d18eb3ce44ba20407d688368b14b75269944a17be2c4eaa2d',
    'trace.h': '6f630c87e87163f8473b26e963b1cbc32d97318cc1dcff50e10b0d66581f3bd3',
}
OBJECT_PINS = {
    'ir.o': 'd191b88d5db99865001508577d2bfdb2285510330face1d50abcb1abd653f943',
    'ir_environment.o': '4aae7136f1e3f9b310691ffd75697b39efe1808809f00fc2522b220001f3ac55',
    'trace.o': '4b55760574193e3488ddf1cfda797bbee116e31e03bf5bdb7f5e7dd8828fb3a4',
}
GPRS = ('eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi')
FLAG_BITS = (0, 2, 4, 6, 7, 11, 10)
STACK_BASE, STACK_SIZE = 0x407fc000, 20480
PATH_SHA = 'faa031c96d7f56b4def43f3123c467f23eae1c50261cd5f9f842e05a9c50242c'


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def strict_json(data):
    def object_pairs(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'Duplicate JSON key: ' + key)
            result[key] = value
        return result

    def invalid_constant(value):
        raise ValueError('Non-finite JSON number: ' + value)

    return json.loads(data, object_pairs_hook=object_pairs, parse_constant=invalid_constant)


def read_original_reference(path):
    path = Path(path)
    require(path.is_file() and not path.is_symlink(), 'Original reference missing or symlink')
    with path.open('rb') as stream:
        data = stream.read(16 * 1024**2 + 1)
    require(len(data) <= 16 * 1024**2, 'Original reference exceeds bound')
    return data, {'sha256': digest(data), 'bytes': len(data),
                  'matches_historical_M312_original_sha256': digest(data) == ORIGINAL_SHA,
                  'historical_pin_source': 'M312 xxhsum/lzma/capture/certificate.json metadata',
                  'prepack_history_authenticated': False}


def save(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def resolve_evidence(path):
    path = Path(path)
    if path.is_dir():
        candidates = [p for p in (path / 'probe/m3-evidence.zip', path / 'm3-evidence.zip') if p.is_file()]
        require(len(candidates) == 1, 'Expected one evidence ZIP: ' + str(path))
        path = candidates[0]
    require(path.is_file() and not path.is_symlink(), 'Evidence file missing or symlink: ' + str(path))
    return path


class Evidence:
    """Bounded, inventory-checked data access; never extract or execute files."""

    def __init__(self, path, expected_sha=None, max_size=256 * 1024**2):
        self.path = resolve_evidence(path)
        require(self.path.stat().st_size <= max_size, 'Evidence ZIP exceeds bound')
        self.sha256 = digest(self.path.read_bytes())
        require(expected_sha is None or self.sha256 == expected_sha, 'Evidence ZIP identity differs')
        self.archive = zipfile.ZipFile(self.path)
        try:
            entries = self.archive.infolist()
            names = [item.filename for item in entries]
            require(len(names) <= 256 and len(names) == len(set(names)), 'Evidence names or count')
            for item in entries:
                parts = PurePosixPath(item.filename)
                require(not parts.is_absolute() and '..' not in parts.parts and '\\' not in item.filename
                        and parts.as_posix() == item.filename and not item.is_dir(), 'Unsafe evidence name')
                require(item.flag_bits & 1 == 0 and item.external_attr >> 28 != 0xa, 'Encrypted or symlink evidence')
            require(sum(item.file_size for item in entries) <= max_size, 'Expanded evidence exceeds bound')
            require(self.archive.testzip() is None, 'Evidence CRC mismatch')
            self.inventory = self.json('evidence-files.json')
            require(type(self.inventory) is dict and set(names) == set(self.inventory) | {'evidence-files.json'},
                    'Evidence inventory extent')
            for name, pin in self.inventory.items():
                require(type(pin) is str and len(pin) == 64 and digest(self.read(name)) == pin,
                        'Evidence inventory hash: ' + name)
        except BaseException:
            self.archive.close()
            raise

    def read(self, name):
        return self.archive.read(name)

    def json(self, name):
        return strict_json(self.read(name))

    def close(self):
        self.archive.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def capture_rows(evidence):
    raw = evidence.read('capture/events.jsonl')
    lines = raw.splitlines(keepends=True)
    require(lines and all(line.endswith(b'\n') and len(line) <= 1024 * 1024 for line in lines), 'Capture line framing')
    rows = [strict_json(line) for line in lines]
    require(all(type(row) is dict for row in rows), 'Capture row objects')
    require(rows[0].get('kind') == 'header' and rows[-1].get('kind') == 'footer', 'Capture boundary rows')
    footer, prefix = rows[-1], b''.join(lines[:-1])
    require(footer.get('events_sha256_before_footer') == digest(prefix)
            and footer.get('events_bytes_before_footer') == len(prefix), 'Capture prefix binding')
    require(footer.get('success') is True and footer.get('target_instruction_executed') is False
            and footer.get('syscall_count') == footer.get('syscall_returns') == 26
            and footer.get('reason') == 'payload_entry_boundary', 'Capture completion scope')
    require(rows[0].get('elf_sha256') == ELF_SHA and rows[0].get('initial_pc') == 0x08070300,
            'Capture packed ELF identity')
    return rows


def one(rows, kind=None, label=None):
    selected = [row for row in rows if (kind is None or row.get('kind') == kind)
                and (label is None or row.get('label') == label)]
    require(len(selected) == 1, 'Unique capture row required: ' + str(kind or label))
    return selected[0]


def authenticate(m366, m362, output):
    summary, receipt = m366.json('summary.json'), m366.json('native-build/receipt.json')
    require(summary.get('status') == 'PASS_WITH_REDUCED_INITIAL_PREMISES_AND_CONDITIONAL_PAYLOAD_TRANSFER'
            and summary.get('source_manifest_sha256') in M366_SOURCE_MANIFESTS
            and summary.get('errors') == [] and summary.get('oep_proof') == 'NOT_ESTABLISHED', 'M366 source and scope')
    require(receipt.get('driver_sha256') == M366_DRIVER_SHA and receipt.get('frontend_sha256') == FRONTEND_SHA
            and receipt.get('baseline_headers') == HEADER_PINS and receipt.get('linked_objects') == OBJECT_PINS,
            'M366 native source/input bindings')
    require(digest(m366.read('native-build/ir_lift_x86.c')) == FRONTEND_SHA, 'Production frontend source')
    for name, key in (('ir_lift_x86.o', 'frontend_object_sha256'), ('m366-execute', 'binary_sha256')):
        require(digest(m366.read('native-build/' + name)) == receipt.get(key), 'M366 native artifact binding')
    rows = capture_rows(m362)
    initial = one(rows, 'initial')
    stack = one(rows, 'snapshot', 'initial_stack')
    original = bytes.fromhex(stack['bytes_hex'])
    require(stack['address'] == STACK_BASE and stack['size'] == len(original) == STACK_SIZE, 'Initial stack extent')
    elf = m366.read('reduced-inputs/source.elf')
    require(digest(elf) == ELF_SHA and elf == m366.read('discovery-inputs/source.elf'), 'Packed ELF bytes')
    require(m366.read('discovery-inputs/stack.bin') == original, 'M366/M362 initial stack binding')
    require(m366.read('discovery-inputs/stack-mask.bin') == bytes([255]) * STACK_SIZE, 'Discovery input masks')
    scalars = f"{initial['registers']['esp']:x} 0\n".encode()
    require(initial['registers']['eflags'] >> 10 & 1 == 0
            and m366.read('reduced-inputs/scalars.txt') == m366.read('discovery-inputs/scalars.txt') == scalars,
            'Observed ESP/DF binding')
    projection = m366.read('reduced/projection.bin')
    require(len(projection) == STACK_SIZE and all(k in (0, 255) for k in projection)
            and sum(k == 255 for k in projection) == 372
            and projection == m366.read('discovery/projection.bin')
            == m366.read('reduced-inputs/stack-mask.bin'), 'Reduced projection binding')
    reduced = bytes(v & k for v, k in zip(original, projection))
    require(m366.read('reduced-inputs/stack.bin') == reduced, 'Unknown input cells are not canonical')
    contracts = m366.read('reduced-inputs/contracts.txt')
    require(contracts == m366.read('discovery-inputs/contracts.txt'), 'Kernel contract inputs differ')
    compare_contracts(rows, contracts.decode('ascii'))
    inputs = output / 'inputs'
    inputs.mkdir()
    for name, value in {'source.elf': elf, 'stack.bin': reduced, 'stack-mask.bin': projection,
                        'scalars.txt': scalars, 'contracts.txt': contracts}.items():
        (inputs / name).write_bytes(value)
    report = {'schema_version': 1, 'M366_evidence_sha256': m366.sha256, 'M362_evidence_sha256': m362.sha256,
              'M366_source_manifest_sha256': summary['source_manifest_sha256'],
              'uploaded_native_binaries_executed': False, 'historical_certificates_upgraded': False,
              'source_elf_sha256': ELF_SHA, 'capture_bytes_sha256': digest(m362.read('capture/events.jsonl')),
              # The pinned M362 observer reads this buffer directly from guest RAM
              # in its syscall-return callback; reply_hex is an observation.
              'readlink_guest_RAM_observation_ordinals': [row['ordinal'] for row in rows
                  if row.get('kind') == 'syscall_return' and row.get('number') == 85]}
    save(output / 'authentication.json', report)
    return rows, inputs, original, projection, report


IR_SOURCE_FILES = ('ir.c', 'ir_environment.c', 'trace.c', 'ir_lift_x86.c')
IR_HEADER_FILES = ('ir.h', 'ir_internal.h', 'ir_environment.h', 'ir_lift_x86.h',
                   'trace.h', 'dcfg.h', 'dta.h', 'provenance.h')


def build_replay(ir_source, output):
    """Compile the current project IR sources, without linking uploaded objects."""
    ir_source = Path(ir_source)
    output.mkdir()
    sources = output / 'sources'
    sources.mkdir()
    source_hashes = {}
    for name in (*IR_SOURCE_FILES, *IR_HEADER_FILES):
        path = ir_source / name
        require(path.is_file() and not path.is_symlink(), 'Project IR source missing or symlink: ' + str(path))
        data = path.read_bytes()
        source_hashes[name] = digest(data)
        (sources / name).write_bytes(data)
    driver = (ROOT / 'oep_execute.c').read_bytes()
    (sources / 'oep_execute.c').write_bytes(driver)
    source_hashes['oep_execute.c'] = digest(driver)
    producer_header = (ROOT / 'oep_producers.h').read_bytes()
    (sources / 'oep_producers.h').write_bytes(producer_header)
    source_hashes['oep_producers.h'] = digest(producer_header)
    cpp, libs = os.environ.get('TF_PLUGIN_CPPFLAGS'), os.environ.get('TF_PLUGIN_LIBS')
    if cpp is None:
        cpp = subprocess.check_output(['pkg-config', '--cflags', 'glib-2.0', 'capstone'], text=True, timeout=30)
    if libs is None:
        libs = subprocess.check_output(['pkg-config', '--libs', 'glib-2.0', 'capstone'], text=True, timeout=30)
    require('TF_PROV_FASTPATH' not in cpp and 'TF_CAPTURE_FASTPATH' not in cpp, 'Ambiguous build flags')
    common = [os.environ.get('TF_IR_CC', 'gcc'), '-std=gnu11', '-O2', '-Wall', '-Wextra', '-Werror',
              '-Wno-misleading-indentation', '-ffunction-sections', '-fdata-sections',
              '-I', str(sources), *shlex.split(cpp)]
    binary = output / 'oep-execute'
    objects = [output / (Path(name).stem + '.o') for name in IR_SOURCE_FILES]
    commands = [[*common, '-c', str(sources / name), '-o', str(obj)]
                for name, obj in zip(IR_SOURCE_FILES, objects)]
    commands.append([*common, '-Wl,--gc-sections', str(sources / 'oep_execute.c'),
                     *map(str, objects), *shlex.split(libs), '-lm', '-pthread', '-o', str(binary)])
    with (output / 'build.log').open('wb') as log:
        for command in commands:
            result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, timeout=120)
            require(result.returncode == 0, 'Native build failed: ' + str(output / 'build.log'))
    save(output / 'receipt.json', {'schema_version': 1, 'commands': commands,
                                  'source_tree': str(ir_source.resolve()), 'sources_sha256': source_hashes,
                                  'linked_objects': {obj.name: digest(obj.read_bytes()) for obj in objects},
                                  'driver_sha256': digest(driver), 'all_project_IR_objects_built_from_source': True,
                                  'compiler_and_linker_configuration_trusted': True,
                                  'binary_sha256': digest(binary.read_bytes()),
                                  'uploaded_native_binaries_executed': False,
                                  'historical_native_objects_selected_by_verifier': False, 'guest_executions': 0})
    return binary


def run_replay(binary, inputs, output):
    output.mkdir()
    command = [str(binary), *[str(inputs / name) for name in
               ('source.elf', 'stack.bin', 'stack-mask.bin', 'scalars.txt', 'contracts.txt')], str(output)]
    with (output / 'execution.json').open('wb') as stdout, (output / 'stderr').open('wb') as stderr:
        result = subprocess.run(command, stdout=stdout, stderr=stderr, timeout=900)
    require(result.returncode == 0, 'Fresh IR replay failed: ' + str(output / 'stderr'))


def compare_replay(rows, directory, baseline):
    execution = strict_json((directory / 'execution.json').read_bytes())
    require(execution.get('status') == 'COMPUTED_REDUCED_PREMISE_ORIGINAL_ENTRY_TO_PAYLOAD_TRANSFER'
            and execution.get('schema_version') == 1 and execution.get('pc') == 0x08049096
            and execution.get('instructions') == 13144778 and execution.get('path_sha256') == PATH_SHA
            and execution.get('checkpoint_instructions') == 13144307
            and execution.get('syscalls') == 26 and execution.get('fresh_ir_nodes') == 1870,
            'Fresh replay selected-path identity')
    for key in ('checkpoint_used_as_seed', 'kernel_implementation_verified', 'independent_entry_origins_proven', 'target_instruction_executed'):
        require(execution.get(key) is False, 'Fresh replay scope promoted: ' + key)
    require(execution.get('source_private_unmapped') is True and execution.get('oep_proof') == 'NOT_ESTABLISHED', 'Fresh replay scope')
    require(execution == baseline.json('reduced/execution.json'), 'Fresh execution differs from authenticated M366')
    require((directory / 'projection.bin').read_bytes() == baseline.read('reduced/projection.bin'), 'Fresh projection differs')
    require(digest((directory / 'original-ir.jsonl').read_bytes()) == digest(baseline.read('reduced/original-ir.jsonl')),
            'Fresh original IR differs')
    comparisons, regions = [], []
    for phase, kind, prefix, reg_key, flag_key in (
        ('checkpoint', 'checkpoint', 'checkpoint_', 'checkpoint_registers', 'checkpoint_flags'),
        ('final', 'payload_entry', 'payload_', 'registers', 'flags')):
        event = one(rows, kind)
        require(execution['checkpoint_instructions' if phase == 'checkpoint' else 'instructions'] == event['instructions'], 'Capture instruction count')
        require(len(execution[reg_key]) == 8 and len(execution[flag_key]) == 7, 'Scalar extent')
        for name, state in zip(GPRS, execution[reg_key]):
            require(state == {'value': event['registers'][name], 'known': 0xffffffff}, 'Computed register differs: ' + phase + '/' + name)
        for bit, state in zip(FLAG_BITS, execution[flag_key]):
            require(state == {'value': event['registers']['eflags'] >> bit & 1, 'known': 1}, 'Computed modeled flag differs')
        snapshots = [r for r in rows if r.get('kind') == 'snapshot' and r.get('label', '').startswith(prefix)]
        require(len(snapshots) == (7 if phase == 'checkpoint' else 5), 'Capture snapshot extent')
        for snapshot in snapshots:
            address = snapshot['address']
            value = (directory / phase / f'ram-{address:08x}.bin').read_bytes()
            known = (directory / phase / f'known-{address:08x}.bin').read_bytes()
            observed = bytes.fromhex(snapshot['bytes_hex'])
            require(len(value) == len(known) == len(observed) == snapshot['size'], 'Snapshot size')
            require(all(v & ~k == 0 and (v ^ o) & k == 0 for v, k, o in zip(value, known, observed)),
                    'Unknown canonicality or known RAM mismatch: ' + snapshot['label'])
            if address != STACK_BASE:
                require(all(k == 255 for k in known), 'Unknown payload image byte')
            comparisons.append({'phase': phase, 'label': snapshot['label'], 'address': address, 'bytes': len(value),
                                'known_bytes': sum(k == 255 for k in known), 'sha256': digest(value)})
            if phase == 'final':
                regions.append({'address': address, 'data': value, 'known': known})
    return execution, regions, comparisons


def compare_vma_models(environment, boundary):
    def pages(regions, prot_key):
        result = {}
        for region in regions:
            start, end, prot = region['start'], region['end'], region[prot_key]
            require(type(start) is int and type(end) is int and type(prot) is int
                    and 0 <= start < end <= 1 << 32 and start % 4096 == end % 4096 == 0
                    and 0 <= prot <= 7, 'VMA model extent/protection')
            for address in range(start, end, 4096):
                require(address not in result, 'Overlapping model VMAs')
                result[address] = prot
        return result
    expected, computed = pages(environment['modeled_final_vmas'], 'prot'), pages(boundary['vmas'], 'permissions')
    require(expected == computed, 'Syscall and IR model final VMA maps differ')
    for region in environment['modeled_final_unmapped_ranges']:
        require(not any(address in computed for address in range(region['start'], region['end'], 4096)), 'Unmapped page remains in IR model')
    return {'pages': len(computed), 'presence_and_protection_match': True,
            'independent_guest_permissions_observed': False, 'scope': 'CONSISTENCY_OF_CONDITIONAL_MODELS'}


def make_certificate(authentication, entry, environment, boundary, execution, vmas):
    require(boundary.get('restored_entry_boundary_verified') is True, 'Restored entry boundary obligations remain open')
    conditions = [
        {'id': 'trusted_IR_and_loader_model', 'detail': 'Recorded project IR sources, decoder, host compiler/linker configuration, dependency libraries and bounded interpreter are trusted; the fresh IR catalogue matches M366.'},
        {'id': 'observed_initial_state', 'detail': 'ESP, DF=0, selected stack values, flat32 and initial mappings remain stated entry/profile premises.'},
        {'id': 'kernel_effect_contracts', 'detail': 'All 26 syscall results and modeled memory, fd, mapping and cache effects remain explicit contracts.'},
        {'id': 'execution_scope', 'detail': 'Single thread, no asynchronous outside mutation; only this authenticated selected path is covered.'},
    ]
    open_items = [{'id': 'independent_initial_state_origin', 'details': entry['external_admissions']}]
    observed_readlink = set(authentication.get('readlink_guest_RAM_observation_ordinals', []))
    for item in environment['open_obligations']:
        if item.get('id') == 'observations_are_bound_to_actual_execution_by_caller':
            continue
        if (item.get('id') == 'readlink_reply_written_to_guest_RAM'
                and authentication.get('M362_evidence_sha256') == M362_SHA
                and item.get('ordinal') in observed_readlink):
            continue
        open_items.append(item)
    open_items.extend({'id': item} if isinstance(item, str) else item
                      for item in boundary.get('open_originality_obligations', []))
    return {
        'schema_version': 1, 'status': 'VERIFIED_RESTORED_ENTRY_UNDER_EXPLICIT_PREMISES',
        'statement': 'Under the listed premises, this packed ELF computes a restored ELF and transfers to its known executable e_entry.',
        'payload_entry': execution['pc'], 'source_elf_sha256': ELF_SHA, 'instructions': execution['instructions'],
        'path_sha256': execution['path_sha256'], 'checkpoint_used_as_seed': False,
        'restored_image_entry_verified_under_premises': True,
        'original_prepack_OEP_independently_established': False,
        'independent_OS_entry_origins_proven': False, 'kernel_implementation_verified': False,
        'guest_permissions_independently_observed': False, 'unconditional_oep_proven': False,
        'historical_certificates_upgraded': False, 'target_instruction_executed': False,
        'original_reference_compared': boundary.get('original_reference_image_matches') is True,
        'original_reference': boundary.get('original_reference'),
        'original_reference_identity': authentication.get('original_reference'),
        'authentication': authentication, 'entry_contract_status': entry['status'],
        'capture_authentication_checked_by_caller': True,
        'boundary_status': boundary['status'], 'VMA_model_consistency': vmas,
        'conditions': conditions, 'open_obligations': open_items,
        'oep_proof': 'NOT_ESTABLISHED',
    }


def archive_results(output):
    files = [path for path in sorted(output.rglob('*')) if path.is_file()
             and path.name not in ('oep-evidence.zip', 'evidence-files.json')]
    require(not any(path.is_symlink() for path in output.rglob('*')), 'Result symlink')
    require(sum(path.stat().st_size for path in files) <= 128 * 1024**2, 'Result evidence exceeds bound')
    save(output / 'evidence-files.json', {path.relative_to(output).as_posix(): digest(path.read_bytes()) for path in files})
    with zipfile.ZipFile(output / 'oep-evidence.zip', 'w', zipfile.ZIP_DEFLATED) as archive:
        for path in [*files, output / 'evidence-files.json']:
            archive.write(path, path.relative_to(output).as_posix())


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--m366', required=True, type=Path, help='Successful M366 evidence ZIP or result directory')
    parser.add_argument('--m362', required=True, type=Path, help='Exact original M362 evidence ZIP or result directory')
    parser.add_argument('--entry-profile', type=Path)
    parser.add_argument('--process-profile', type=Path)
    parser.add_argument('--effect-observations', type=Path)
    parser.add_argument('--original-elf', type=Path)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args(argv)
    output = args.output.resolve() if args.output else Path(tempfile.mkdtemp(prefix='oep-verification.', dir=ROOT)) / 'probe'
    output.mkdir(parents=True, exist_ok=False)
    print('Results:', output, flush=True)
    summary = {'schema_version': 1, 'status': 'FAIL', 'errors': [], 'oep_proof': 'NOT_ESTABLISHED',
               'guest_executions': 0, 'target_instruction_executed': False, 'unconditional_oep_proven': False}
    try:
        sources = output / 'source'
        sources.mkdir()
        for name in ('oep_verify.py', 'oep_entry.py', 'oep_environment.py', 'oep_boundary.py', 'oep_execute.c'):
            (sources / name).write_bytes((ROOT / name).read_bytes())
        with Evidence(args.m366) as baseline, Evidence(args.m362, M362_SHA, 32 * 1024**2) as captured:
            rows, inputs, initial_stack, projection, authentication = authenticate(baseline, captured, output)
            original_reference = None
            if args.original_elf is not None:
                original_reference, identity = read_original_reference(args.original_elf)
                (inputs / 'original.elf').write_bytes(original_reference)
                authentication['original_reference'] = identity
                save(output / 'authentication.json', authentication)
            print('entry: classifying all 372 initial bytes and checking ELF-bound relations', flush=True)
            profile = strict_json(args.entry_profile.read_bytes()) if args.entry_profile else None
            esp = one(rows, 'initial')['registers']['esp']
            stack_mapping = {'start': 0x40700000, 'end': 0x40801000, 'read': True, 'write': True}
            entry = verify_entry_contract((inputs / 'source.elf').read_bytes(), initial_stack,
                                          STACK_BASE, esp, projection, profile, df=0, stack_mapping=stack_mapping)
            save(output / 'entry.json', entry)
            save(output / 'entry-profile-template.json', entry['profile'])
            process_profile = strict_json(args.process_profile.read_bytes()) if args.process_profile else {
                'vmas': [{'start': stack_mapping['start'], 'end': stack_mapping['end'], 'prot': 3}],
            }
            effects = strict_json(args.effect_observations.read_bytes()) if args.effect_observations else None
            save(output / 'process-profile.json', process_profile)
            if effects is not None:
                save(output / 'effect-observations.json', effects)
            print('environment: auditing 26 observed syscall boundaries and explicit effect premises', flush=True)
            environment = audit_environment(rows, process_profile, effects)
            save(output / 'environment.json', environment)
            print('native-ir: source-building and freshly replaying the original path', flush=True)
            binary = build_replay(ROOT / 'test', output / 'native-build')
            run_replay(binary, inputs, output / 'replay')
            execution, regions, comparison = compare_replay(rows, output / 'replay', baseline)
            save(output / 'comparison.json', comparison)
            boundary_receipt = strict_json((output / 'replay/boundary.json').read_bytes())
            node_pc = boundary_receipt['transition']['pc']
            candidates = []
            with (output / 'replay/original-ir.jsonl').open('rb') as stream:
                for line in stream:
                    node = strict_json(line)
                    if node.get('pc') == node_pc and node.get('original_ir_sha256') == boundary_receipt['transition']['original_ir_sha256']:
                        candidates.append(node)
            require(len(candidates) == 1, 'Unique final transition IR node')
            stack_region = next(region for region in regions if region['address'] == STACK_BASE)
            final_layout = parse_entry_table(stack_region['data'], STACK_BASE, execution['registers'][4]['value'], known_mask=stack_region['known'])
            lineage = {'source_kind': 'computed_IR_model', 'source_elf_sha256': ELF_SHA,
                       'path_sha256': execution['path_sha256'], 'checkpoint_used_as_seed': False}
            print('boundary: binding restored ELF entry, executed transfer, current permissions and fetch bytes', flush=True)
            boundary = audit_boundary(regions, execution, final_auxv=final_layout['auxv'], boundary=boundary_receipt,
                                      last_ir_node=candidates[0], original_elf=original_reference,
                                      image_provenance=lineage)
            save(output / 'boundary.json', boundary)
            if original_reference is not None:
                print('reference: ELF entry, headers, all PT_LOAD bytes and BSS match; SHA256=' + digest(original_reference), flush=True)
            vmas = compare_vma_models(environment, boundary_receipt)
            certificate = make_certificate(authentication, entry, environment, boundary, execution, vmas)
            save(output / 'certificate.json', certificate)
            summary.update(status=certificate['status'], completed_native_IR_replays=1,
                           restored_image_entry_verified_under_premises=True, payload_entry=execution['pc'],
                           original_instructions=execution['instructions'], initial_stack_known_bytes=372,
                           retained_kernel_contracts=26, open_obligations=len(certificate['open_obligations']),
                           original_reference_compared=certificate['original_reference_compared'],
                           original_reference_identity=certificate['original_reference_identity'])
            print(summary['status'], flush=True)
    except (ValueError, OSError, KeyError, TypeError, RecursionError, subprocess.SubprocessError, zipfile.BadZipFile) as error:
        summary['errors'].append(type(error).__name__ + ': ' + str(error))
        print('FAIL:', summary['errors'][-1], flush=True)
    finally:
        save(output / 'summary.json', summary)
    try:
        archive_results(output)
        print('Evidence:', output / 'oep-evidence.zip', flush=True)
    except (ValueError, OSError, zipfile.BadZipFile) as error:
        summary['status'] = 'FAIL'
        summary['errors'].append('Evidence archive: ' + str(error))
        save(output / 'summary.json', summary)
        print('FAIL:', summary['errors'][-1], flush=True)
    print('OEP: NOT_ESTABLISHED; restored entry is verified conditionally; independent entry/environment/pre-pack origins remain explicit.', flush=True)
    return 0 if not summary['errors'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
