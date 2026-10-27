"""Streaming SMT induction for every recorded selected-execution condition."""
import hashlib
import json
import mmap
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import time


# Aggregate source inventory; each actual SMT query remains capped at 4096.
# Native evaluation admits up to 1048576 sources with 32-bit identities.
SOURCE_LIMIT = 262144


def build_helper(core, output):
    output.mkdir()
    source = output / 'sources'
    shutil.copytree(output.parent / 'native-smt/sources', source)
    (source / 'oep_schedule.c').write_bytes((core.ROOT / 'oep_schedule.c').read_bytes())
    prior = core.verifier.strict_json((output.parent / 'native-smt/receipt.json').read_bytes())
    old_source = str(output.parent / 'native-smt/sources')
    binary = output / 'oep-schedule'
    command = [arg.replace(old_source, str(source)) for arg in prior['command']]
    command = [arg.replace(str(source / 'oep_smt.c'), str(source / 'oep_schedule.c')) for arg in command]
    command[-1] = str(binary)
    with (output / 'build.log').open('wb') as log:
        result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, timeout=180)
    core.require(result.returncode == 0, 'Schedule helper build failed; inspect native-schedule/build.log')
    core.verifier.save(output / 'receipt.json', {
        'command': command, 'binary_sha256': core.file_digest(binary),
        'source_files_sha256': {p.name: core.file_digest(p) for p in source.iterdir() if p.is_file()},
        'uploaded_native_objects_linked': False, 'helper_produces_conjectures_only': True})
    return binary


def require_complete(core, proof, prepared, evaluation):
    def digest(value):
        return isinstance(value, str) and len(value) == 64 and all(c in '0123456789abcdef' for c in value)
    core.require(type(prepared.get('compact_nodes')) is int and prepared['compact_nodes'] > 0
        and type(proof.get('proved_nodes')) is int
        and digest(prepared.get('compact_sha256')) and digest(evaluation.get('values_sha256'))
        and proof.get('status') == 'PROVED'
        and proof.get('proved_nodes') == prepared.get('compact_nodes')
        and proof.get('compact_sha256') == prepared.get('compact_sha256')
        and proof.get('values_sha256') == evaluation.get('values_sha256')
        and evaluation.get('status') == 'EVALUATED', 'Incomplete schedule producer proof')


class _Journal:
    def __init__(self, core, solver, output):
        self.core, self.solver, self.output = core, solver, output
        self.temporary = tempfile.TemporaryDirectory(prefix='tf-schedule-query-')
        self.work = Path(self.temporary.name)
        self.path = output / 'schedule-queries.jsonl'
        self.partial = output / 'schedule-queries.partial.jsonl'
        self.stream = self.partial.open('x')
        self.receipts, self.receipt_bytes, self.closed = [], 0, False
        self.chain, self.checks, self.queries = '0' * 64, 0, 0
        self.started = time.monotonic()

    def close(self):
        if self.closed:
            return
        self.closed = True
        temporary = None
        try:
            self.stream.close()
            # Publish only the complete sequence captured from this very run.
            # The progress file may have been detached/replaced while its
            # descriptor was open; it is never read as proof input here.
            expected = hashlib.sha256()
            with tempfile.NamedTemporaryFile(prefix='.schedule-queries-', suffix='.tmp',
                                              dir=self.output, delete=False) as stream:
                temporary = Path(stream.name)
                for row in self.receipts:
                    stream.write(row)
                    expected.update(row)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)
            temporary = None
            descriptor = os.open(self.output, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            with self.path.open('rb') as stream:
                actual = hashlib.file_digest(stream, 'sha256').hexdigest()
            self.core.require(self.path.stat().st_size == self.receipt_bytes and
                              actual == expected.hexdigest(),
                              'Published SMT query journal differs from this run')
            self.partial.unlink(missing_ok=True)
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
            self.temporary.cleanup()

    def query(self, rows, bindings, goals, phase, first, last):
        core = self.core
        core.require(not self.closed, 'SMT query journal is already closed')
        core.require(time.monotonic() - self.started < 7200, 'Schedule proof time budget')
        ledger = core.HEADER + b''.join(core.RECORD.pack(*r) for r in rows)
        premises = ''.join(f'{i} {v:x} {(1 << rows[i - 1][1]) - 1:x}\n' for i, v in bindings).encode()
        conclusions = ''.join(f'{i} {v:x}\n' for i, v in goals).encode()
        for name, data in [('slice.bin', ledger), ('inputs.txt', premises), ('goals.txt', conclusions)]:
            (self.work / name).write_bytes(data)
        (self.work / 'report.json').unlink(missing_ok=True)
        command = [str(self.solver), *([] if phase == 'original_sources' else ['--lemma-chunk']),
            str(self.work / 'slice.bin'), str(self.work / 'inputs.txt'), str(self.work / 'goals.txt'),
            str(self.work / 'report.json')]
        with (self.work / 'solver.log').open('wb') as log:
            result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, timeout=300)
        report = core.verifier.strict_json((self.work / 'report.json').read_bytes())
        row = {'phase': phase, 'first': first, 'last': last,
            'ledger_sha256': core.verifier.digest(ledger), 'premises_sha256': core.verifier.digest(premises),
            'goals_sha256': core.verifier.digest(conclusions), 'previous_receipt_sha256': self.chain,
            'solver': report}
        encoded = json.dumps(row, sort_keys=True, separators=(',', ':'))
        durable = (encoded + '\n').encode()
        core.require(len(durable) <= 4 * 1024**2 and len(self.receipts) < 100000 and
                     self.receipt_bytes + len(durable) <= 128 * 1024**2,
                     'Persisted SMT query journal budget')
        self.receipts.append(durable)
        self.receipt_bytes += len(durable)
        self.chain = core.verifier.digest(encoded.encode())
        self.stream.write(encoded + '\n')
        self.stream.flush()
        core.require(result.returncode == 0 and report.get('status') == 'PROVED'
            and report.get('baseline', {}).get('status') == 'SAT'
            and report.get('counterexample', {}).get('status') == 'UNSAT',
            'Schedule SMT query failed in ' + phase + '; inspect schedule-queries.jsonl')
        self.checks += report['baseline']['solver_checks'] + report['counterexample']['solver_checks']
        self.queries += 1
        return report


def _prove_sources(core, journal, sources, *, chunk_size=4096):
    """Prove disjoint source equalities without one oversized SMT query.

    The source-only encoding in oep_smt.c gives each inventory row its own
    fresh symbolic INPUT; its only premise is equality to the authenticated
    value. Thus models of disjoint blocks can be united into one joint model.
    This rule applies only to original leaves, before any SOURCE110 lemma is
    admitted. Authentication against entry bytes/contracts remains mandatory
    in verify_schedule, before this function is called.
    """
    core.require(type(chunk_size) is int and 0 < chunk_size <= 4096, 'Schedule source block budget')
    core.require(0 < len(sources) <= SOURCE_LIMIT, 'Joint schedule source budget')
    seen, identities = set(), {}
    inventory = hashlib.sha256()
    # Validate the complete inventory before admitting even the first block.
    for old, row in sources:
        core.require(type(old) is int and 0 < old <= 0xffffffff and old not in seen,
                     'Schedule source identity')
        core.require(len(row) == 7 and all(type(value) is int for value in row)
            and 100 <= row[0] <= 109 and 1 <= row[1] <= 64
            and 0 <= row[2] <= 0xffffffff and 0 <= row[3] <= 0xffffffff
            and row[4] == 0 and 0 <= row[5] < 1 << row[1]
            and 0 <= row[6] <= 0xffffffffffffffff, 'Independent original schedule source required')
        identity, assignment = (row[0], row[2], row[3]), (row[1], row[5])
        core.require(identity not in identities or identities[identity] == assignment,
                     'Conflicting original schedule source assignments')
        identities[identity] = assignment
        seen.add(old)
        inventory.update(struct.pack('<I', old) + core.RECORD.pack(*row))
    blocks, proved, version = 0, 0, None
    for start in range(0, len(sources), chunk_size):
        stop = min(len(sources), start + chunk_size)
        rows = [row for _, row in sources[start:stop]]
        bindings = [(index, row[5]) for index, row in enumerate(rows, 1)]
        report = journal.query(rows, bindings, bindings, 'original_sources', start + 1, stop)
        core.require(report.get('original_source_premises') == len(rows)
            and report.get('previously_proved_lemma_premises') == 0
            and report.get('proof_mode') == 'source_dag'
            and report.get('smt_build', {}).get('symbolic_parameters') == len(rows),
            'Original schedule sources must remain symbolic')
        core.require(version is None or version == report['z3_version'], 'Schedule source solver changed')
        version = report['z3_version']
        proved, blocks = stop, blocks + 1
    core.require(proved == len(sources), 'Incomplete original schedule source proof')
    return {'source_blocks': blocks, 'source_chunk_size': chunk_size,
            'source_inventory_sha256': inventory.hexdigest(),
            'source_proof_mode': 'DISJOINT_AUTHENTICATED_SOURCE_EQUALITIES', 'z3_version': version}


def _induct(core, solver, prepared_dir, prepared, evaluation, sources, output, *, chunk_size=4096):
    """Bound memory to one block; no evaluated value is admitted before proof."""
    core.require(type(chunk_size) is int and 0 < chunk_size <= 4096, 'Schedule SMT block budget')
    core.require(0 < len(sources) <= SOURCE_LIMIT, 'Joint schedule source budget')
    graph = prepared_dir / 'compact.bin'
    values_path = prepared_dir / 'values.bin'
    core.require(core.file_digest(graph) == prepared['compact_sha256']
        and core.file_digest(values_path) == evaluation['values_sha256'], 'Schedule graph/value digest')
    n = prepared['compact_nodes']
    core.require(graph.stat().st_size == 16 + n * 32 and values_path.stat().st_size == 16 + n * 8,
                 'Schedule graph/value extent')
    journal = _Journal(core, solver, output)
    proved, blocks = 0, 0
    try:
        source_report = _prove_sources(core, journal, sources, chunk_size=chunk_size)
        with graph.open('rb') as g, values_path.open('rb') as v, \
                mmap.mmap(g.fileno(), 0, access=mmap.ACCESS_READ) as records, \
                mmap.mmap(v.fileno(), 0, access=mmap.ACCESS_READ) as values:
            core.require(records[:16] == core.HEADER
                and values[:16] == b'TFVALUES' + struct.pack('<II', 1, n), 'Schedule graph/value framing')

            def node(i):
                core.require(type(i) is int and 0 < i <= n, 'Schedule producer identity')
                return core.RECORD.unpack_from(records, 16 + (i - 1) * 32)

            def value(i):
                return struct.unpack_from('<Q', values, 16 + (i - 1) * 8)[0]

            core.require(all(node(i) == r and value(i) == r[5] for i, r in sources),
                         'Authenticated schedule sources differ from compact producers')
            admitted_sources = {i for i, _ in sources}
            for start in range(0, n, chunk_size):
                stop = min(n, start + chunk_size)
                batch = [node(i) for i in range(start + 1, stop + 1)]
                boundary = set()
                for row in batch:
                    if row[0] < 100:
                        core.require(row[0] in core.ARITY, 'Unsupported schedule producer')
                        boundary.update(p for p in row[2:2 + core.ARITY[row[0]]] if p <= start)
                core.require(proved == start and all(0 < p <= proved for p in boundary),
                             'Schedule uses an unproved boundary')
                rows, bindings, mapping = [], [], {}
                for old in sorted(boundary):
                    row = node(old)
                    rows.append((110, row[1], old, 0, 0, value(old), row[6]))
                    mapping[old] = len(rows)
                    bindings.append((len(rows), value(old)))
                for old, row in enumerate(batch, start + 1):
                    core.require(0 <= value(old) < 1 << row[1], 'Schedule conjecture width')
                    if 100 <= row[0] <= 109:
                        core.require(old in admitted_sources and value(old) == row[5], 'Unproved schedule source')
                        record = (110, row[1], old, 0, 0, value(old), row[6])
                    else:
                        core.require(row[0] in core.ARITY, 'Unknown schedule source')
                        record = (*row[:2], *(mapping.get(p, 0) for p in row[2:5]), *row[5:])
                    rows.append(record)
                    mapping[old] = len(rows)
                    if 100 <= row[0] <= 109:
                        bindings.append((len(rows), row[5]))
                if not bindings:
                    source = sources[0][1]
                    rows.append(source)
                    bindings = [(len(rows), source[5])]
                journal.query(rows, bindings, [(mapping[i], value(i)) for i in range(start + 1, stop + 1)],
                              'schedule_producers', start + 1, stop)
                proved = stop
                blocks += 1
                if blocks % 256 == 0 or proved == n:
                    print(f'SMT schedule: proved producers {proved}/{n}', flush=True)
            proof = {'status': 'PROVED', 'proved_nodes': proved, 'producer_blocks': blocks,
                'compact_sha256': prepared['compact_sha256'], 'values_sha256': evaluation['values_sha256']}
            require_complete(core, proof, prepared, evaluation)
            goals_path = prepared_dir / 'condition-goals.bin'
            goal_count, goal_blocks = 0, 0
            with goals_path.open('rb') as stream:
                core.require(stream.read(16) == b'TFCND1\0\0' + struct.pack('<II', 1, 16),
                             'Schedule condition goal framing')
                while True:
                    block = stream.read(chunk_size * 16)
                    if not block:
                        break
                    core.require(len(block) % 16 == 0, 'Truncated schedule condition goal')
                    goals = list(struct.iter_unpack('<IIQ', block))
                    rows, bindings, conclusions = [], [], []
                    for i, (old, kinds, expected) in enumerate(goals, 1):
                        row = node(old)
                        core.require(0 < kinds < 1 << 10 and not kinds & 1, 'Schedule condition kind mask')
                        rows.append((110, row[1], old, 0, 0, value(old), row[6]))
                        bindings.append((i, value(old)))
                        conclusions.append((i, expected))
                    journal.query(rows, bindings, conclusions, 'schedule_conditions', goal_count, goal_count + len(goals))
                    goal_count += len(goals)
                    goal_blocks += 1
                    if goal_blocks % 256 == 0:
                        print(f'SMT schedule: proved unique conditions {goal_count}', flush=True)
            core.require(goal_count == prepared['condition_goal_count'], 'Schedule condition goal count')
        return {**proof, 'source_premises': len(sources), 'condition_goal_count': goal_count,
            'condition_blocks': goal_blocks, 'solver_checks': journal.checks, 'queries': journal.queries,
            'last_receipt_sha256': journal.chain, 'source_premise_query': 'SAT',
            'condition_counterexample_query': 'UNSAT', **source_report,
            'duration_seconds': time.monotonic() - journal.started}
    finally:
        journal.close()


def verify_schedule(core, ledger, selected, context, output, *, require_pathname=True):
    manifest = core.verifier.strict_json((ledger / 'manifest.json').read_bytes())
    core.require(manifest.get('condition_schema_version') == 1
        and manifest.get('computed_transfer_targets_recorded') is True
        and manifest.get('kernel_checked_path_bytes_recorded') is True,
        'Fresh complete schedule-condition capture required')
    helper = build_helper(core, output / 'native-schedule')
    prepared_dir = output / 'schedule'
    prepared_dir.mkdir()
    roots = prepared_dir / 'roots.txt'
    roots.write_text(''.join(f"{r['id']}\n" for r in selected))
    command = [str(helper), 'prepare', str(ledger / 'nodes.bin'), str(ledger / 'conditions.bin'),
               str(roots), str(prepared_dir)]
    with (prepared_dir / 'prepare.log').open('wb') as log:
        result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, timeout=600)
    core.require(result.returncode == 0, 'Schedule preparation failed; inspect schedule/prepare.log')
    prepared = core.verifier.strict_json((prepared_dir / 'receipt.json').read_bytes())
    core.require(type(prepared.get('source_leaves')) is int
        and 0 < prepared['source_leaves'] <= SOURCE_LIMIT, 'Joint schedule source budget')
    core.require(prepared.get('status') == 'PREPARED'
        and prepared['condition_count'] == manifest['condition_count']
        and prepared.get('kind_counts') == [0] + [manifest['condition_kind_counts'][str(k)] for k in range(1, 10)]
        and prepared['kind_counts'][8] > 0
        and (not require_pathname or prepared['kind_counts'][9] > 0),
        'Schedule preparation receipt or coverage')
    prepared['compact_sha256'] = core.file_digest(prepared_dir / 'compact.bin')
    for name in ('condition-goals.bin', 'needed.bitset', 'needed.rank', 'source-map.jsonl'):
        if (prepared_dir / name).is_file():
            prepared[name + '_sha256'] = core.file_digest(prepared_dir / name)
    core.verifier.save(prepared_dir / 'receipt.json', prepared)
    sources = []
    for row in core.current.json_lines(prepared_dir / 'source-map.jsonl'):
        record = tuple(row['record'])
        core.require(len(record) == 7, 'Schedule source record')
        value = core.source_value(record, context)
        core.require(value == record[5], 'Schedule source value')
        sources.append((row['id'], record))
    core.require(len(sources) == prepared['source_leaves'] and len({i for i, _ in sources}) == len(sources),
                 'Schedule source inventory')
    premises = prepared_dir / 'source-premises.txt'
    premises.write_text(''.join(f'{i} {r[5]:x} {(1 << r[1]) - 1:x}\n' for i, r in sources))
    evaluation_path = prepared_dir / 'evaluation.json'
    command = [str(helper), 'evaluate', str(prepared_dir / 'compact.bin'), str(premises),
               str(prepared_dir / 'values.bin'), str(evaluation_path)]
    with (prepared_dir / 'evaluation.log').open('wb') as log:
        result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, timeout=1800)
    evaluation = core.verifier.strict_json(evaluation_path.read_bytes())
    core.require(result.returncode == 0 and evaluation.get('status') == 'EVALUATED',
                 'Schedule conjectures contain unknown or unsupported values')
    evaluation['values_sha256'] = core.file_digest(prepared_dir / 'values.bin')
    core.verifier.save(evaluation_path, evaluation)
    proof = _induct(core, output / 'native-smt/oep-smt', prepared_dir, prepared, evaluation, sources, output)
    require_complete(core, proof, prepared, evaluation)
    core.require(core.file_digest(prepared_dir / 'compact.bin') == prepared['compact_sha256']
        and core.file_digest(prepared_dir / 'values.bin') == evaluation['values_sha256']
        and core.file_digest(prepared_dir / 'condition-goals.bin') == prepared['condition-goals.bin_sha256'],
        'Schedule query inputs changed during proof')
    check_path = prepared_dir / 'condition-check.json'
    command = [str(helper), 'check', str(ledger / 'nodes.bin'), str(ledger / 'conditions.bin'),
               str(prepared_dir / 'needed.bitset'), str(prepared_dir / 'values.bin'), str(check_path)]
    with (prepared_dir / 'check.log').open('wb') as log:
        checked = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, timeout=600)
    check = core.verifier.strict_json(check_path.read_bytes())
    core.require(checked.returncode == 0 and check.get('status') == 'MATCHED_PROVED_VALUES'
        and check['condition_count'] == manifest['condition_count']
        and check.get('kind_counts') == prepared['kind_counts'], 'Not all schedule occurrences match proved values')
    proof.update(condition_count=manifest['condition_count'], all_condition_occurrences_checked=True,
                 all_condition_goals_encoded_in_SMT=True,
                 proof_mode='TOPOLOGICAL_SMT_INDUCTION_OF_SELECTED_EXECUTION_CONDITIONS')
    core.verifier.save(output / 'schedule-proof.json', proof)
    return proof
