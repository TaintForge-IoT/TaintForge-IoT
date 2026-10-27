"""Bind a fresh selected-run capture to source-built IR and an original ELF.

QEMU, the observer, the IR semantics and the host build remain trusted.  Every
comparison uses this run's observations; historical execution is not reused.
"""

from pathlib import Path

try:
    from . import oep_verify as verifier
    from .oep_observations import audit_observations
    from .oep_environment import _pairs, audit_environment, compare_contracts
except ImportError:
    import oep_verify as verifier
    from oep_observations import audit_observations
    from oep_environment import _pairs, audit_environment, compare_contracts


require = verifier.require
ROOT = Path(__file__).resolve().parent


def json_lines(path, *, max_bytes=64 * 1024**2, max_line_bytes=4 * 1024**2):
    require(path.stat().st_size <= max_bytes, 'Replay sidecar exceeds bound')
    with path.open('rb') as stream:
        for line in stream:
            require(line.endswith(b'\n') and len(line) <= max_line_bytes, 'Replay sidecar line framing')
            row = verifier.strict_json(line)
            require(type(row) is dict, 'Replay sidecar object')
            yield row


def page_map(regions, key='prot'):
    result = {}
    for region in regions:
        start, end, protection = region.get('start'), region.get('end'), region.get(key)
        require(type(start) is int and type(end) is int and type(protection) is int
                and 0 <= start < end <= 2**32 and start % 4096 == end % 4096 == 0
                and 0 <= protection <= 7, 'Replay VMA geometry')
        require((end - start) // 4096 <= 65536, 'Replay VMA budget')
        for address in range(start, end, 4096):
            require(address not in result and len(result) < 65536, 'Replay VMA overlap or budget')
            result[address] = protection
    return result


def compare_known(value, known, observed, label):
    require(len(value) == len(known) == len(observed), label + ' extent')
    require(all(v & ~k == 0 and (v ^ o) & k == 0 for v, k, o in zip(value, known, observed)),
            label + ' known bytes differ')
    return sum(k == 255 for k in known)


def compare_scalars(model, flags, observed, label, *, allow_unknown_flags=False):
    require(type(model) is list and len(model) == 8 and type(flags) is list and len(flags) == 7,
            label + ' scalar extent')
    for name, item in zip(verifier.GPRS, model):
        require(type(item) is dict and item == {'value': observed[name], 'known': 0xffffffff},
                label + ' register differs: ' + name)
    unknown = []
    for bit, item in zip(verifier.FLAG_BITS, flags):
        require(type(item) is dict and set(item) == {'value', 'known'}
                and type(item['value']) is int and type(item['known']) is int
                and item['known'] in (0, 1) and 0 <= item['value'] <= item['known'],
                label + ' modeled flag encoding: bit ' + str(bit))
        if item['known']:
            require(item['value'] == observed['eflags'] >> bit & 1,
                    label + ' modeled flag differs: bit ' + str(bit))
        else:
            require(allow_unknown_flags, label + ' modeled flag is unknown: bit ' + str(bit))
            unknown.append(bit)
    return unknown


def contracts_text(rows):
    lines = []
    for entry, returned, _ in _pairs(rows, 26):
        reply = returned.get('reply_hex') or '-'
        lines.append(' '.join([f"{entry['pc']:x}", str(entry['number']),
                               *[f'{a:x}' for a in entry['args']],
                               f"{returned['result_u32']:x}", reply]))
        if entry['number'] in (90, 192):
            array = entry['mmap_args'] if entry['number'] == 90 else entry['args']
            lines.append(' '.join(f'{a:x}' for a in array))
    text = '\n'.join(lines) + '\n'
    compare_contracts(rows, text)
    return text


def initial_elf_observations(rows, packed_bytes=None):
    result = []
    for label, address, size in (('initial_image', 0x08048000, 118784),
                                 ('initial_source', 0x08065000, 51072)):
        snapshot = verifier.one(rows, 'snapshot', label)
        require(snapshot.get('address') == address and snapshot.get('size') == size,
                'Initial ELF RAM observation geometry differs: ' + label)
        data = bytes.fromhex(snapshot['bytes_hex'])
        require(len(data) == size, 'Initial ELF RAM observation extent differs: ' + label)
        if label == 'initial_source' and packed_bytes is not None:
            require(len(packed_bytes) >= size and data == packed_bytes[:size],
                    'Initial executable source bytes differ from packed ELF')
        result.append((address, data))
    return result


def compare_initial_reads(rows, path):
    data = initial_elf_observations(rows)
    seen = set()
    for row in json_lines(path, max_bytes=16 * 1024**2):
        address, value, known = row.get('address'), row.get('value'), row.get('known')
        require(type(address) is int and address not in seen and len(seen) < 262144,
                'Initial read receipt duplicate or budget')
        require(type(value) is int and type(known) is int and 0 <= value <= 255 and known == 255,
                'Initial data read must be known')
        matches = [blob[address - start] for start, blob in data if start <= address < start + len(blob)]
        require(len(matches) == 1 and matches[0] == value, 'Consumed initial ELF RAM byte differs')
        seen.add(address)
    return {'unique_initial_data_bytes': len(seen), 'all_consumed_initial_data_bytes_observed': True}


def compare_kernel(rows, directory):
    models = list(json_lines(directory / 'kernel.jsonl'))
    require(len(models) == 27 and models[0].get('kind') == 'initial_model'
            and models[0].get('ordinal') == 0, 'Kernel model sidecar extent')
    observations = {r['ordinal']: r for r in rows if r.get('kind') == 'vma_snapshot'
                    and r.get('phase') in ('initial', 'syscall_return')}
    require(set(observations) == set(range(27)), 'Kernel VMA observation timeline')
    tracked = set()
    memory_bytes = file_bytes = 0
    file_identity = {}
    unknown_flags = []
    for ordinal, model in enumerate(models):
        require(model.get('source_kind') == 'computed_IR_model' and model.get('ordinal') == ordinal,
                'Kernel model order or provenance')
        current = page_map(model['vmas'], 'permissions')
        observed = page_map(observations[ordinal]['regions'])
        tracked.update(current)
        require(all(observed.get(address) == prot for address, prot in current.items()),
                'Observed guest mapping/protection differs from replay')
        require(not any(address in observed for address in tracked - current.keys()),
                'Observed guest mapping survived modeled unmap')
        if not ordinal:
            continue
        entry, returned, _ = _pairs(rows, 26)[ordinal - 1]
        require(model.get('kind') == 'kernel_model' and model.get('number') == entry['number']
                and model.get('pc_before') == entry['pc'] and model.get('pc_after') == entry['pc'] + 2,
                'Kernel model syscall identity')
        post = verifier.one([r for r in rows if r.get('ordinal') == ordinal], 'syscall_post')
        # Undefined intermediate flags remain UNKNOWN; observations never fill
        # them. Checkpoint and payload-entry comparisons still require all flags.
        unknown_flags.extend({'ordinal': ordinal, 'bit': bit} for bit in compare_scalars(
            model['registers'], model['flags'], post['registers'], 'Post-syscall', allow_unknown_flags=True))
        enter_index, return_index, post_index = rows.index(entry), rows.index(returned), rows.index(post)
        for cell in model['changed_memory']:
            address, size = cell['address'], cell['size']
            require(type(size) is int and 0 <= size <= 131072
                    and len(bytes.fromhex(cell['data_hex'])) == len(bytes.fromhex(cell['known_hex'])) == size,
                    'Kernel RAM model byte extent')
            candidates = [r for r in rows if r.get('kind') == 'snapshot'
                          and r.get('syscall_ordinal') == ordinal and r.get('address') == address
                          and r.get('size') == size and r.get('label') in
                          ('syscall_mapping_' + str(ordinal), 'syscall_memory_' + str(ordinal))]
            if entry['number'] == 85:
                require(address == entry['args'][1] and size == returned['result_u32'], 'Readlink effect geometry')
                actual = bytes.fromhex(returned['reply_hex'])
            else:
                require(len(candidates) == 1, 'Immediate kernel RAM observation missing or ambiguous')
                require(return_index < rows.index(candidates[0]) < post_index, 'Kernel RAM observation outside syscall-return boundary')
                actual = bytes.fromhex(candidates[0]['bytes_hex'])
            memory_bytes += compare_known(bytes.fromhex(cell['data_hex']), bytes.fromhex(cell['known_hex']),
                                          actual, 'Post-syscall RAM')
        cell = model.get('write_buffer')
        require((cell is not None) == (entry['number'] == 4), 'Write buffer model missing or unexpected')
        if cell is not None:
            snapshot = verifier.one(rows, 'snapshot', 'write_buffer_' + str(ordinal))
            require(snapshot['syscall_ordinal'] == ordinal and snapshot['address'] == cell['address'] == entry['args'][1]
                    and snapshot['size'] == cell['size'] == entry['args'][2]
                    and len(bytes.fromhex(cell['data_hex'])) == len(bytes.fromhex(cell['known_hex'])) == cell['size'],
                    'Write buffer observation identity')
            require(enter_index < rows.index(snapshot) < return_index, 'Write buffer observation must precede kernel effects')
            compare_known(bytes.fromhex(cell['data_hex']), bytes.fromhex(cell['known_hex']),
                          bytes.fromhex(snapshot['bytes_hex']), 'Write buffer')
        for item in model['files']:
            phase = 'syscall_enter' if entry['number'] == 6 else 'syscall_return'
            candidates = [r for r in rows if r.get('kind') == 'file_snapshot' and r.get('phase') == phase
                          and r.get('ordinal') == ordinal and r.get('fd') == item['fd']]
            require(len(candidates) == 1, 'Actual file observation missing or ambiguous')
            actual = candidates[0]
            key = item['model_file_id']
            require(key not in file_identity or file_identity[key] == actual['file_id'], 'Observed backing file identity changed')
            file_identity[key] = actual['file_id']
            require(actual['size'] == item['size']
                    and len(bytes.fromhex(item['data_hex'])) == len(bytes.fromhex(item['known_hex'])) == item['size']
                    and len(bytes.fromhex(actual['bytes_hex'])) == actual['size'], 'Observed file size or byte extent differs')
            file_bytes += compare_known(bytes.fromhex(item['data_hex']), bytes.fromhex(item['known_hex']),
                                        bytes.fromhex(actual['bytes_hex']), 'Actual file contents')
    return {'syscalls': 26, 'all_modeled_guest_VMA_presence_and_permissions_observed': True,
            'post_syscall_known_flag_bits_compared': 26 * len(verifier.FLAG_BITS) - len(unknown_flags),
            'post_syscall_unknown_flag_bits': unknown_flags,
            'post_syscall_RAM_known_bytes_compared': memory_bytes,
            'actual_file_known_bytes_compared': file_bytes,
            'unmodeled_initial_mappings_executed_or_read_by_replay': False,
            'kernel_implementation_verified': False}


def compare_execution(rows, directory):
    execution = verifier.strict_json((directory / 'execution.json').read_bytes())
    footer = rows[-1]
    require(execution.get('status') == 'COMPUTED_REDUCED_PREMISE_ORIGINAL_ENTRY_TO_PAYLOAD_TRANSFER'
            and execution.get('instructions') == footer['instructions']
            and execution.get('path_sha256') == footer['executed_pc_sha256']
            and execution.get('syscalls') == 26 and execution.get('pc') == 0x08049096,
            'Fresh replay differs from observed executed instruction path')
    for key in ('checkpoint_used_as_seed', 'kernel_implementation_verified',
                'independent_entry_origins_proven', 'target_instruction_executed'):
        require(execution.get(key) is False, 'Fresh replay scope promoted: ' + key)
    regions, comparisons = [], []
    for phase, kind, prefix, reg_key, flag_key in (
        ('checkpoint', 'checkpoint', 'checkpoint_', 'checkpoint_registers', 'checkpoint_flags'),
        ('final', 'payload_entry', 'payload_', 'registers', 'flags')):
        event = verifier.one(rows, kind)
        require(execution['checkpoint_instructions' if phase == 'checkpoint' else 'instructions'] == event['instructions'],
                'Observed checkpoint/final instruction count differs')
        compare_scalars(execution[reg_key], execution[flag_key], event['registers'], phase)
        snapshots = [r for r in rows if r.get('kind') == 'snapshot' and r.get('label', '').startswith(prefix)]
        require(len(snapshots) == (7 if phase == 'checkpoint' else 5), 'Observed checkpoint/final RAM extent')
        for row in snapshots:
            address = row['address']
            value = (directory / phase / f'ram-{address:08x}.bin').read_bytes()
            known = (directory / phase / f'known-{address:08x}.bin').read_bytes()
            count = compare_known(value, known, bytes.fromhex(row['bytes_hex']), phase + ' RAM')
            require(len(value) == row['size'], 'Observed RAM size differs')
            if address != verifier.STACK_BASE:
                require(count == len(value), 'Unknown restored image byte')
            comparisons.append({'phase': phase, 'address': address, 'bytes': len(value), 'known_bytes': count})
            if phase == 'final':
                regions.append({'address': address, 'data': value, 'known': known})
    return execution, regions, comparisons


def verify_capture(rows, launch, packed_bytes, original_bytes, output):
    output = Path(output)
    require(verifier.digest(packed_bytes) == verifier.ELF_SHA, 'Selected packed ELF identity differs')
    require(verifier.digest(original_bytes) == verifier.ORIGINAL_SHA, 'Historical original reference identity differs')
    initial_elf_observations(rows, packed_bytes)
    observations = audit_observations(rows, launch, elf=packed_bytes)
    verifier.save(output / 'observations.json', observations)
    environment = audit_environment(rows, observations['process_profile'], observations['effect_observations'])
    verifier.save(output / 'environment.json', environment)
    sources = output / 'source'
    sources.mkdir()
    for name in ('oep_current_run.py', 'oep_observations.py', 'oep_capture.py', 'oep_capture.c',
                 'oep_verify.py', 'oep_entry.py', 'oep_boundary.py', 'oep_environment.py', 'oep_execute.c'):
        (sources / name).write_bytes((ROOT / name).read_bytes())
    binary = verifier.build_replay(ROOT / 'test', output / 'native-build')
    initial = verifier.one(rows, 'initial')
    stack = verifier.one(rows, 'snapshot', 'initial_stack')
    require(stack['address'] == verifier.STACK_BASE and stack['size'] == verifier.STACK_SIZE, 'Initial stack geometry')
    stack_bytes = bytes.fromhex(stack['bytes_hex'])
    scalars = f"{initial['registers']['esp']:x} {(initial['registers']['eflags'] >> 10) & 1:x}\n".encode()
    contracts = contracts_text(rows).encode('ascii')
    inputs = output / 'inputs'
    inputs.mkdir()
    for name, value in {'source.elf': packed_bytes, 'original.elf': original_bytes,
                        'scalars.txt': scalars, 'contracts.txt': contracts}.items():
        (inputs / name).write_bytes(value)
    (inputs / 'stack.bin').write_bytes(stack_bytes)
    (inputs / 'stack-mask.bin').write_bytes(bytes([255]) * len(stack_bytes))
    print('IR: discovering initial read-before-write bytes for this run', flush=True)
    verifier.run_replay(binary, inputs, output / 'discovery')
    discovered, _, _ = compare_execution(rows, output / 'discovery')
    projection = (output / 'discovery/projection.bin').read_bytes()
    require(len(projection) == len(stack_bytes) and all(k in (0, 255) for k in projection), 'Fresh projection mask')
    observations = audit_observations(rows, launch, elf=packed_bytes, projection=projection)
    verifier.save(output / 'observations.json', observations)
    (inputs / 'stack.bin').write_bytes(bytes(v & k for v, k in zip(stack_bytes, projection)))
    (inputs / 'stack-mask.bin').write_bytes(projection)
    print('IR: replaying with only constructor-bound consumed initial bytes', flush=True)
    verifier.run_replay(binary, inputs, output / 'reduced')
    execution, regions, comparisons = compare_execution(rows, output / 'reduced')
    require((output / 'reduced/projection.bin').read_bytes() == projection, 'Reduced projection changed')
    require(execution['path_sha256'] == discovered['path_sha256'], 'Reduced executed path changed')
    initial_reads = compare_initial_reads(rows, output / 'reduced/initial-reads.jsonl')
    kernel = compare_kernel(rows, output / 'reduced')
    verifier.save(output / 'kernel-comparison.json', kernel)
    verifier.save(output / 'comparison.json', comparisons)
    receipt = verifier.strict_json((output / 'reduced/boundary.json').read_bytes())
    node = [n for n in json_lines(output / 'reduced/original-ir.jsonl', max_line_bytes=64 * 1024**2)
            if n.get('pc') == receipt['transition']['pc']
            and n.get('original_ir_sha256') == receipt['transition']['original_ir_sha256']]
    require(len(node) == 1, 'Unique final transfer IR node')
    stack = next(r for r in regions if r['address'] == verifier.STACK_BASE)
    layout = verifier.parse_entry_table(stack['data'], verifier.STACK_BASE, execution['registers'][4]['value'], known_mask=stack['known'])
    boundary = verifier.audit_boundary(regions, execution, final_auxv=layout['auxv'], boundary=receipt,
                                      last_ir_node=node[0], original_elf=original_bytes,
                                      image_provenance={'source_kind': 'computed_IR_model',
                                                        'source_elf_sha256': verifier.ELF_SHA,
                                                        'path_sha256': execution['path_sha256'], 'checkpoint_used_as_seed': False})
    require(boundary['restored_entry_boundary_verified'] is True and boundary['original_reference_image_matches'] is True,
            'Original entry boundary remains open')
    final_observed = page_map(observations['payload_vmas'])
    final_model = page_map(receipt['vmas'], 'permissions')
    require(all(final_observed.get(a) == p for a, p in final_model.items()), 'Final observed guest permissions differ')
    verifier.save(output / 'boundary.json', boundary)
    certificate = {
        'schema_version': 1, 'status': 'CONFIRMED_REFERENCE_ENTRY_FOR_OBSERVED_RUN_UNDER_TRUSTED_MODELS',
        'run_id': launch['run_id'], 'source_elf_sha256': verifier.ELF_SHA,
        'original_elf_sha256': verifier.ORIGINAL_SHA, 'payload_entry': execution['pc'],
        'instructions': execution['instructions'], 'path_sha256': execution['path_sha256'],
        'oep_confirmed_for_observed_run_under_trusted_models': True,
        'restored_image_entry_verified_under_premises': True,
        'original_prepack_OEP_independently_established': False,
        'guest_permissions_independently_observed': False,
        'executed_path_matches_capture': True, 'entry_table_matches_construction_receipt': True,
        'consumed_initial_stack_bytes': projection.count(255), 'initial_RAM_reads': initial_reads,
        'kernel_comparison': kernel, 'original_reference_compared': True,
        'guest_permissions_observed_in_QEMU': True, 'historical_certificates_upgraded': False,
        'checkpoint_used_as_seed': False, 'target_instruction_executed': False,
        'independent_OS_entry_origins_proven': False, 'kernel_implementation_verified': False,
        'unconditional_oep_proven': False, 'fuzzing_ready': False,
        'conditions': ['Trusted QEMU backend, observer, IR/decoder semantics, compiler and linked libraries.',
                       'One selected single-threaded run; no asynchronous outside mutation or signal effects.',
                       'Supplied original ELF pre-pack provenance is an external assertion; its historical hash and declared PT_LOAD bytes are checked.',
                       'Only declared PT_LOAD file bytes/BSS are compared; page padding and whole-program equivalence are outside the claim.',
                       'Observed initial ESP/DF and flat32 machine mode are explicit execution-scope inputs.'],
        'open_obligations': [
            {'id': 'TRUSTED_QEMU_OBSERVER_IR_AND_HOST_BUILD'},
            {'id': 'EXTERNAL_ORIGINAL_PREPACK_PROVENANCE'},
            {'id': 'NO_ASYNCHRONOUS_OUTSIDE_MUTATION_OR_SIGNAL_EFFECTS'},
        ],
        'oep_proof': 'NOT_ESTABLISHED',
    }
    verifier.save(output / 'certificate.json', certificate)
    return certificate
