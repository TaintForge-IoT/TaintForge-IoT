"""SMT proof of one source-derived unpacking path and its observed RAM image.

The packed ELF, admitted entry bytes/scalars and explicit kernel contracts are
the source premises.  Observed image bytes and the selected transfer address are
conclusions only.  This does not establish historical pre-pack originality.
The caller must freshly build/replay the source IR and validate its observations;
this module checks the resulting producer graph with actual SAT/UNSAT queries.
"""
from contextlib import ExitStack
import mmap
from pathlib import Path
import struct

try:
    from . import oep_smt as smt
    from . import oep_schedule as schedule
    from . import rep_callbacks
except ImportError:
    import oep_smt as smt
    import oep_schedule as schedule
    import rep_callbacks

require = smt.require
STATUS = 'SMT_PROVED_SELECTED_TRANSFER_AND_OBSERVED_IMAGE_UNDER_EXPLICIT_PREMISES'
PROOF = 'SMT_SELECTED_EXECUTION_TO_OBSERVED_IMAGE_UNDER_TRUSTED_MODELS'
RAW_NODE_LIMIT = 268435456
GOAL_LIMIT = 262144


def _catalogue_rows(path):
    # A bounded REP expansion can place millions of IR operations in one row.
    # Keep the same 64 MiB total bound while allowing that bounded row size.
    return list(smt.current.json_lines(path, max_line_bytes=64 * 1024**2))


def _integer(value, low, high, label):
    require(type(value) is int and low <= value <= high, label)
    return value


def _sha(value, label):
    require(type(value) is str and len(value) == 64
            and all(c in '0123456789abcdef' for c in value), label)
    return value


def _image(expected_image_rows):
    """Return exactly the captured RAM bytes, including observed page padding."""
    image = {}
    require(type(expected_image_rows) in (list, tuple) and expected_image_rows,
            'Observed image ranges required')
    for row in expected_image_rows:
        require(type(row) is dict and set(row) >= {'address', 'data'}, 'Observed image row')
        address, data = row['address'], row['data']
        _integer(address, 0, 0xffffffff, 'Observed image address')
        require(type(data) is bytes and data and len(data) <= 1024 * 1024
                and address + len(data) <= 1 << 32, 'Observed image range extent')
        for offset, value in enumerate(data):
            require(address + offset not in image, 'Overlapping observed image ranges')
            image[address + offset] = value
        require(len(image) <= GOAL_LIMIT - 32, 'Observed image goal budget')
    return image


def producer_goals(target, expected_image_rows, root_rows, origins, catalogue,
                   instructions, *, kernel_pcs=()):
    """Bind complete image/transfer roots and all fresh instruction variants."""
    _integer(target, 0, 0xffffffff, 'Selected transfer address')
    _integer(instructions, 1, 0xffffffff, 'Replay instruction count')
    image = _image(expected_image_rows)
    require(target in image, 'Transfer outside observed image')
    selected, coverage = [], {}
    for row in root_rows:
        require(type(row) is dict, 'Producer goal row')
        kind, address, bits = row.get('kind'), row.get('address'), row.get('bits')
        _integer(address, 0, 0xffffffff, 'Producer goal address')
        if kind == 'target':
            require(address == target and bits == 32, 'Computed transfer goal identity')
            expected = target
        else:
            require(kind in ('target_fetch_byte', 'observed_image_byte')
                    and bits == 8 and address in image, 'Observed image producer identity')
            if kind == 'target_fetch_byte':
                require(target <= address < target + 15, 'Target fetch goal address')
            expected = image[address]
        addresses = coverage.setdefault(kind, set())
        require(address not in addresses and row.get('known') == (1 << bits) - 1,
                'Duplicate or unknown producer goal')
        _integer(row.get('id'), 1, RAW_NODE_LIMIT, 'Producer goal ID')
        _integer(row.get('offset'), 0, 63, 'Producer goal bit offset')
        require(row.get('value') == expected, 'Computed replay goal differs from observation')
        addresses.add(address)
        selected.append({'id': row['id'], 'offset': row['offset'], 'bits': bits,
                         'expected': expected, 'label': kind, 'address': address})
    fetch = coverage.get('target_fetch_byte', set())
    require(coverage.get('target') == {target}
            and coverage.get('observed_image_byte') == image.keys()
            and fetch and fetch == set(range(target, target + len(fetch))),
            'Incomplete observed image/transfer producer coverage')

    nodes = {}
    for node in catalogue:
        require(type(node) is dict, 'Fresh IR catalogue row')
        key = node.get('pc'), node.get('original_ir_sha256')
        _integer(key[0], 0, 0xffffffff, 'Catalogue PC')
        _sha(key[1], 'Catalogue IR digest')
        modeled = node.get('ir_semantics_modeled') is True and node.get('lift_status') == 0
        explicit_kernel = (key[0] in kernel_pcs and node.get('opaque_syscall') is True
            and node.get('ir_semantics_modeled') is False and node.get('lift_status') == 1
            and node.get('bytes') == 'cd80' and node.get('size') == 2
            and node.get('ir_instructions') == 0 and node.get('instructions') == []
            and node.get('kernel_boundary_kind') == 'UNMODELED_INT80_EXPLICIT_CONTRACT_REQUIRED'
            and node.get('boundary_resume_pc') == key[0] + 2)
        require(key not in nodes and node.get('ir_validator_passed') is True
                and (modeled or explicit_kernel)
                and type(node.get('original_ir_dump')) is str
                and smt.verifier.digest(node['original_ir_dump'].encode()) == key[1],
                'Fresh IR catalogue identity')
        nodes[key] = node
    seen, code_bytes, repeats = set(), 0, 0
    for origin in origins:
        require(type(origin) is dict, 'Instruction origin row')
        key = origin.get('pc'), origin.get('original_ir_sha256')
        require(key in nodes and key not in seen, 'Instruction producer identity')
        _integer(origin.get('first_step'), 1, instructions, 'Instruction first occurrence')
        seen.add(key)
        node = nodes[key]
        encoded = bytes.fromhex(node['bytes'])
        roots = origin.get('fetch_roots')
        require(origin.get('bytes_hex') == node['bytes'] and len(encoded) == node['size']
                and 0 < len(encoded) <= 15 and type(roots) is list and len(roots) == len(encoded),
                'Instruction producer bytes differ from fresh catalogue')
        for index, (root, value) in enumerate(zip(roots, encoded)):
            _integer(root, 1, RAW_NODE_LIMIT, 'Instruction fetch producer ID')
            selected.append({'id': root, 'offset': 0, 'bits': 8, 'expected': value,
                             'label': 'instruction_fetch_byte', 'address': key[0] + index})
            code_bytes += 1
        repeat = node['repeat_expansion_iterations']
        require(origin.get('repeat_iterations') == (-1 if repeat is None else repeat),
                'REP expansion identity')
        if repeat is not None:
            _integer(repeat, 0, 4096, 'REP expansion bound')
            _integer(origin.get('repeat_root'), 1, RAW_NODE_LIMIT, 'REP count producer ID')
            selected.append({'id': origin['repeat_root'], 'offset': 0, 'bits': 32,
                             'expected': repeat, 'label': 'REP_expansion_count', 'address': key[0]})
            repeats += 1
        else:
            require(origin.get('repeat_root') == 0, 'Unexpected REP producer')
    require(seen == nodes.keys() and seen, 'Incomplete instruction producer coverage')
    require(len(selected) <= GOAL_LIMIT, 'Selected image/instruction goal budget')
    return selected, {'observed_image_bytes': len(image), 'instruction_variants': len(seen),
                      'instruction_fetch_bytes': code_bytes, 'REP_expansion_counts': repeats,
                      'target_fetch_bytes': len(fetch)}


def _final_goals(ledger, selected, output, schedule_proof):
    """Use only schedule-proved values as lemmas for independent conclusions."""
    prepared_dir = output / 'schedule'
    prepared = smt.verifier.strict_json((prepared_dir / 'receipt.json').read_bytes())
    evaluation = smt.verifier.strict_json((prepared_dir / 'evaluation.json').read_bytes())
    schedule.require_complete(smt, schedule_proof, prepared, evaluation)
    checks = queries = 0
    goal_output = output / 'goal-proof'
    goal_output.mkdir()
    journal = schedule._Journal(smt, output / 'native-smt/oep-smt', goal_output)
    with ExitStack() as stack:
        mapped = {}
        for name in ('needed.bitset', 'needed.rank', 'compact.bin', 'values.bin'):
            path = prepared_dir / name
            expected = evaluation['values_sha256'] if name == 'values.bin' else prepared[
                'compact_sha256' if name == 'compact.bin' else name + '_sha256']
            require(smt.file_digest(path) == expected, 'Changed schedule proof input: ' + name)
            stream = stack.enter_context(path.open('rb'))
            mapped[name] = stack.enter_context(mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ))
        count, compact_count = prepared['nodes'], prepared['compact_nodes']
        bitset, ranks, graph, values = (mapped[n] for n in
            ('needed.bitset', 'needed.rank', 'compact.bin', 'values.bin'))
        words = (count + 64) // 64
        require(bitset[:16] == b'TFNEED1\0' + struct.pack('<II', 1, count)
                and ranks[:16] == b'TFRANK1\0' + struct.pack('<II', 1, count)
                and len(bitset) == 16 + 8 * words and len(ranks) == 16 + 4 * (words + 1)
                and struct.unpack_from('<I', ranks, len(ranks) - 4)[0] == compact_count
                and graph[:16] == smt.HEADER and len(graph) == 16 + 32 * compact_count
                and values[:16] == b'TFVALUES' + struct.pack('<II', 1, compact_count)
                and len(values) == 16 + 8 * compact_count, 'Schedule closure framing')
        try:
            for start in range(0, len(selected), 4096):
                part = selected[start:start + 4096]
                rows, bindings, goals = [], [], []
                for root in part:
                    old = _integer(root['id'], 1, count, 'Final producer ID')
                    word = struct.unpack_from('<Q', bitset, 16 + 8 * (old // 64))[0]
                    bit = old % 64
                    require(word & (1 << bit), 'Final producer missing from proved closure')
                    compact = struct.unpack_from('<I', ranks, 16 + 4 * (old // 64))[0]
                    compact += (word & ((1 << (bit + 1)) - 1)).bit_count()
                    _integer(compact, 1, compact_count, 'Compact final producer ID')
                    record = smt.RECORD.unpack_from(graph, 16 + 32 * (compact - 1))
                    value = struct.unpack_from('<Q', values, 16 + 8 * (compact - 1))[0]
                    bits, offset = root['bits'], root['offset']
                    require(0 <= value < 1 << record[1] and offset + bits <= record[1],
                            'Final producer width')
                    rows.append((110, record[1], compact, 0, 0, value, record[6]))
                    bindings.append((len(rows), value))
                    if offset or bits != record[1]:
                        rows.append((15, bits, len(rows), 0, 0, offset, record[6]))
                    goals.append((len(rows), root['expected']))
                journal.query(rows, bindings, goals, 'observed_image_and_transfer',
                              start, start + len(part))
                queries += 1
            checks, chain = journal.checks, journal.chain
        finally:
            journal.close()
    for name, key in (('needed.bitset', 'needed.bitset_sha256'), ('needed.rank', 'needed.rank_sha256'),
                      ('compact.bin', 'compact_sha256')):
        require(smt.file_digest(prepared_dir / name) == prepared[key], 'Schedule proof input changed')
    require(smt.file_digest(prepared_dir / 'values.bin') == evaluation['values_sha256'],
            'Proved schedule values changed')
    result = {'schema_version': 1, 'status': 'PROVED', 'goals': len(selected),
              'queries': queries, 'solver_checks': checks, 'baseline': 'SAT',
              'counterexample': 'UNSAT', 'only_schedule_proved_values_used_as_lemmas': True,
              'schedule_values_sha256': evaluation['values_sha256'],
              'last_receipt_sha256': chain,
              'queries_sha256': smt.file_digest(goal_output / 'schedule-queries.jsonl')}
    smt.verifier.save(output / 'goals-proof.json', result)
    return result


def prove_generic(replay_dir, context, expected_image_rows, output, *, target,
                  execution=None, catalogue=None, input_files_sha256=None,
                  max_nodes=RAW_NODE_LIMIT):
    """Prove a freshly replayed generic transfer/image, with complete path proof.

    ``context`` uses source_value's packed/stack/mask/initial_regions/esp/df/calls
    fields.  Initial mappings must be reconstructed from the packed ELF loader
    recipe by the caller.  The six input hashes bind ELF, stack, mask, scalars,
    contracts and generic replay config, in the native interpreter's order.
    At most 262144 image/transfer/catalogue goals can be admitted in one proof;
    this is a theorem resource bound, independent of the capture byte budget.
    """
    replay_dir, output = Path(replay_dir), Path(output)
    output.mkdir(parents=True, exist_ok=True)
    require(not any(output.iterdir()), 'SMT output directory must be empty')
    _integer(max_nodes, 1, RAW_NODE_LIMIT, 'Generic producer node budget')
    _integer(target, 0, 0xffffffff, 'Selected transfer address')
    if execution is None:
        execution = smt.verifier.strict_json((replay_dir / 'execution.json').read_bytes())
    require(type(execution) is dict and execution.get('pc') == target
            and execution.get('checkpoint_used_as_seed') is False
            and execution.get('target_instruction_executed') is False,
            'Fresh original-entry transfer replay required')
    _integer(execution.get('instructions'), 1, 0xffffffff, 'Replay instruction count')
    _sha(execution.get('path_sha256'), 'Replay path digest')
    require(type(context) is dict and set(context) >=
            {'packed', 'stack', 'mask', 'initial_regions', 'esp', 'df', 'calls'}, 'Generic source context')
    callback_binding = context.get('rep_runtime_binding')
    if callback_binding is not None:
        require(type(callback_binding) is dict and set(callback_binding) == {
            'mode','semantics','calibration_sha256','qemu_sha256','observer_sha256','sdk_sha256'},
            'REP runtime binding inventory differs')
        mode = callback_binding['mode']
        require(callback_binding['semantics'] == rep_callbacks.semantics(mode) and
            execution.get('rep_callback_profile_explicit') is True and
            execution.get('rep_callback_mode') == mode and
            execution.get('instruction_count_semantics') == callback_binding['semantics'],
            'REP replay callback profile differs from calibrated runtime')
        for key in ('calibration_sha256','qemu_sha256','observer_sha256','sdk_sha256'):
            _sha(callback_binding[key], 'REP runtime binding '+key)
    else:
        require(execution.get('rep_callback_profile_explicit') is not True,
                'Explicit REP callback replay lacks calibrated runtime binding')
    require(type(context['packed']) is bytes and type(context['stack']) is bytes
            and type(context['mask']) is bytes and len(context['stack']) == len(context['mask'])
            and all(v in (0, 255) for v in context['mask']), 'Entry stack source projection')
    _integer(context['esp'], 0, 0xffffffff, 'Initial ESP')
    _integer(context['df'], 0, 1, 'Initial DF')
    require(type(input_files_sha256) in (list, tuple) and len(input_files_sha256) == 6,
            'Six authenticated replay input hashes required')
    for value in input_files_sha256:
        _sha(value, 'Replay input SHA256')
    require(list(input_files_sha256[:3]) == [smt.verifier.digest(context[k]) for k in ('packed', 'stack', 'mask')],
            'Replay source context differs from bound inputs')
    ledger = replay_dir / 'producers'
    manifest = smt.verifier.strict_json((ledger / 'manifest.json').read_bytes())
    require(manifest.get('source_kind') == 'computed_generic_entry_IR_producers'
            and manifest.get('checkpoint_used_as_seed') is False
            and manifest.get('observed_final_state_used_as_input') is False
            and manifest.get('path_sha256') == execution['path_sha256']
            and manifest.get('instructions') == execution['instructions']
            and manifest.get('input_files_sha256') == list(input_files_sha256),
            'Generic producer manifest execution/input binding')
    _integer(manifest.get('node_count'), 1, max_nodes, 'Generic producer ledger node count')
    require((ledger / 'nodes.bin').stat().st_size == 16 + manifest['node_count'] * 32
            and manifest.get('nodes_sha256') == smt.file_digest(ledger / 'nodes.bin')
            and manifest.get('conditions_sha256') == smt.file_digest(ledger / 'conditions.bin'),
            'Generic producer ledger digest or extent')
    if catalogue is None:
        catalogue = _catalogue_rows(replay_dir / 'original-ir.jsonl')
    kernel_pcs = {entry['pc'] for entry, _, _ in context['calls']}
    selected, coverage = producer_goals(target, expected_image_rows,
        smt.current.json_lines(ledger / 'goals.jsonl'),
        smt.current.json_lines(ledger / 'instruction-origins.jsonl'), catalogue,
        execution['instructions'], kernel_pcs=kernel_pcs)
    require(sum(row['label'] == 'target' and row['id'] == manifest.get('target_root')
                for row in selected) == 1, 'Final computed target root binding')
    smt.verifier.save(output / 'goal-receipt.json', {'schema_version': 1, 'goals': selected, **coverage,
        'producer_ledger_sha256': manifest['nodes_sha256'],
        'instruction_origins_sha256': smt.file_digest(ledger / 'instruction-origins.jsonl'),
        'candidate_relation_added_to_source_premises': False,
        'source_values_authenticated_by_schedule_proof': True})
    source_dir = output / 'source'
    source_dir.mkdir()
    source_names = ('unpack_smt.py', 'oep_smt.py', 'oep_schedule.py')
    if callback_binding is not None:
        source_names += ('rep_callbacks.py',)
    for name in source_names:
        (source_dir / name).write_bytes((smt.ROOT / name).read_bytes())
    smt.build_solver(output / 'native-smt')
    print('SMT: proving every source-derived producer and selected path condition', flush=True)
    path_proof = schedule.verify_schedule(smt, ledger, selected, context, output, require_pathname=False)
    print('SMT: checking observed image and computed transfer counterexample UNSAT', flush=True)
    goal_proof = _final_goals(ledger, selected, output, path_proof)
    result = {'schema_version': 1, 'status': STATUS, 'oep_proof': PROOF,
        'selected_transfer': target, 'instructions': execution['instructions'],
        'path_sha256': execution['path_sha256'], 'packed_sha256': smt.verifier.digest(context['packed']),
        'producer_ledger_sha256': manifest['nodes_sha256'], 'replay_input_files_sha256': list(input_files_sha256),
        'SMT_proof_mode': 'TOPOLOGICAL_SMT_INDUCTION',
        'source_premise_query': 'SAT', 'image_and_transfer_counterexample_query': 'UNSAT',
        'SMT_solver_checks': path_proof['solver_checks'] + goal_proof['solver_checks'],
        'schedule_producer_nodes': path_proof['proved_nodes'],
        'schedule_source_premises': path_proof['source_premises'],
        'schedule_condition_count': path_proof['condition_count'],
        'schedule_unique_condition_goals': path_proof['condition_goal_count'], **coverage,
        'selected_execution_proved': True, 'all_prefix_schedule_conditions_encoded_in_SMT': True,
        'all_observed_image_bytes_SMT_proved': True, 'computed_transfer_and_fetch_SMT_proved': True,
        'candidate_relation_added_to_source_premises': False,
        'intermediate_values_admitted_without_SMT_proof': False,
        'checkpoint_used_as_seed': False, 'observed_final_state_used_as_input': False,
        'original_elf_used_as_input': False, 'historical_originality_proven': False,
        'unconditional_oep_proven': False, 'target_instruction_executed': False, 'fuzzing_ready': False,
        'rebuilt_ELF_metadata_in_proved_image': False,
        'conditions': ['Trusted source-built IR frontend, chronological memory model, producer tracking, SMT translation and host build.',
            'Explicit consumed original-entry bytes, ESP/DF and kernel result/effect contracts; source identities checked.',
            'All recorded control, address, fetch, REP, computed-transfer and checked kernel-string conditions are SMT proved.',
            'Observed captured RAM image identity and selected transfer are conclusions; pre-pack historical originality is not established.']}
    if callback_binding is not None:
        result.update(rep_runtime_binding=dict(callback_binding),
            rep_callback_profile_explicit=True,
            instruction_count_semantics=callback_binding['semantics'])
    smt.verifier.save(output / 'certificate.json', result)
    return result
