#!/usr/bin/env python3
"""Consolidate four external selected-execution proof receipts without execution.

Each proof retains its own source context and explicit premises. Recorded solver
answers are audited, not independently reproved; earlier failed runs are kept.
"""
import argparse
from contextlib import contextmanager
import hashlib
import json
from pathlib import Path
import sys
import tempfile

try:
    from . import external_eval as evaluator
    from . import external_worker as worker
    from . import rep_callbacks as callbacks
    from . import unpack_audit as audit
except ImportError:
    import external_eval as evaluator
    import external_worker as worker
    import rep_callbacks as callbacks
    import unpack_audit as audit


ROOT = Path(__file__).resolve().parent
STATUS = 'EXTERNAL_SELECTED_EXECUTION_RECEIPTS_AUDITED'
SAMPLES = frozenset(('xxhsum-default', 'xxhsum-lzma', 'bzip2-default', 'bzip2-lzma'))
require = audit.require


def _directory(path):
    path = Path(path).expanduser().absolute()
    require(path.is_dir() and not any(p.is_symlink() for p in (path, *path.parents)),
            'Audit input directory is missing or traverses a symlink: ' + str(path))
    return path.resolve(strict=True)


def _pin(pins, path, expected=None):
    path = Path(path).absolute()
    require(path.is_file() and not any(p.is_symlink() for p in (path, *path.parents)),
            'Audit input is missing or traverses a symlink: ' + str(path))
    value = evaluator.digest(path)
    require(expected is None or value == expected, 'Audit input digest differs: ' + str(path))
    require(str(path) not in pins or pins[str(path)] == value, 'Conflicting audit input identity')
    pins[str(path)] = value
    return value


@contextmanager
def calibration_source_context(proof, project):
    """Hash-bound read-only source context; historical Python is never imported."""
    proof, project = _directory(proof), _directory(project)
    reader = audit._Reader(proof)
    document = reader.document('rep-calibration.json', 8 * 1024**2)
    runtime = document.get('runtime')
    require(type(runtime) is dict, 'Calibration runtime identity missing')
    callbacks.validate_calibration(document, **runtime)
    pins = {str(proof / 'rep-calibration.json'): reader.hashes['rep-calibration.json']}
    evidence = _directory(document['evidence_root'])
    for relative, wanted in document['evidence_files'].items():
        _pin(pins, callbacks._plain_file(evidence, relative), wanted)
    resolved, receipt = {}, None
    with tempfile.TemporaryDirectory(prefix='tf-audit-source-context-') as temporary:
        context = Path(temporary).resolve(strict=True)
        for relative in callbacks.SOURCE_FILES:
            wanted = document['source_sha256'][relative]
            current = callbacks._plain_file(project, relative, 16 * 1024**2)
            current_sha = evaluator.digest(current)
            if current_sha == wanted:
                path, origin = current, 'current_project'
                data = current.read_bytes()
            else:
                require(relative == 'unpacker/unpack_proof.py',
                        'Unsupported historical calibration helper version: ' + relative)
                if receipt is None:
                    receipt = reader.document('source-receipt.json')
                    require(type(receipt) is dict and 0 < len(receipt) <= 128,
                            'Retained Python source receipt missing')
                    pins[str(proof / 'source-receipt.json')] = reader.hashes['source-receipt.json']
                name = relative[len('unpacker/'):]
                require(receipt.get(name) == wanted,
                        'Retained Python source is not bound to calibration: ' + relative)
                local = 'source/' + name
                data = reader.blob(local, 16 * 1024**2)
                require(reader.hashes[local] == wanted,
                        'Retained Python source digest differs: ' + relative)
                path, origin = proof / local, 'retained_snapshot'
            require(hashlib.sha256(data).hexdigest() == wanted,
                    'Calibration source changed while reading: ' + relative)
            _pin(pins, path, wanted)
            target = context / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            resolved[relative] = dict(origin=origin, path=str(path), sha256=wanted)
        version = hashlib.sha256(audit._canonical(document['source_sha256'])).hexdigest()
        report = dict(source_version_sha256=version, resolved_sources=resolved,
            compatibility_policy='known_orchestrator_snapshot_only',
            calibration_evidence_root=str(evidence), calibration_evidence_files=len(document['evidence_files']),
            historical_source_executed=False, all_calibration_source_digests_checked=True)
        if receipt is not None:
            report['snapshot_receipt_sha256'] = reader.hashes['source-receipt.json']
        evaluator.check_pins(pins)
        yield context, report, pins
        evaluator.check_pins(pins)


def _output_path(output, inputs):
    destination = Path(output).expanduser().absolute()
    require(not destination.exists() and
            not any(path.is_symlink() for path in (destination, *destination.parents)),
            'Audit output must be new and cannot traverse symlinks')
    destination = destination.resolve()
    require(all(destination != path and path not in destination.parents and
                destination not in path.parents for path in inputs),
            'Audit output must be separate from all input files and proof runs')
    return destination


def audit_external(corpus, proofs, output, *, project=None):
    """Audit one explicitly selected proof per packed corpus sample."""
    require(type(proofs) is dict and set(proofs) == SAMPLES,
            'Exactly one proof is required for each of the four external samples')
    project = _directory(project if project is not None else ROOT.parent)
    _, rows, pins = evaluator.load_corpus(corpus)
    require(len(rows) == 4 and {row['id'] for row in rows} == SAMPLES,
            'External corpus must contain exactly the four expected samples')
    directories = {name: _directory(path) for name, path in proofs.items()}
    require(len(set(directories.values())) == 4, 'A proof directory cannot represent two samples')
    input_roots = [*directories.values(), *(Path(path) for path in pins)]
    destination = _output_path(output, input_roots)
    for module in (audit, callbacks, evaluator, worker, worker.oep_entry, worker.ct_elf, worker.unpack):
        _pin(pins, Path(module.__file__).resolve(strict=True))
    _pin(pins, Path(evaluator.validate_cases.__code__.co_filename).resolve(strict=True))
    _pin(pins, Path(__file__).resolve(strict=True))
    results, evidence_roots = [], set()
    for row in rows:
        proof = directories[row['id']]
        with calibration_source_context(proof, project) as (context, sources, context_pins):
            result = audit.audit_sample(proof, calibration_project=context)
        evidence_roots.add(Path(sources['calibration_evidence_root']))
        require(result.get('status') == audit.STATUS and result.get('packed_sha256') == row['packed_sha256']
                and result.get('REP_runtime_binding_audited') is True,
                'External proof does not bind the selected packed sample and calibration')
        reference = worker.reference_image(Path(row['original']))
        require(reference.get('sha256') == row['original_sha256'] and
                result['target'] == reference.get('entry'), 'External reference entry differs from proved target')
        reader = audit._Reader(proof)
        manifest = reader.document('reduced/producers/manifest.json')
        certificate = reader.document('smt/certificate.json')
        raw_nodes = audit._integer(manifest.get('node_count'), 1, 268435456)
        for relative, value in {**result['audited_file_sha256'], **reader.hashes}.items():
            _pin(pins, proof / relative, value)
        for path, value in context_pins.items():
            _pin(pins, Path(path), value)
        results.append(dict(sample=row['id'], proof_directory=str(proof),
            packed_sha256=result['packed_sha256'], original_sha256=row['original_sha256'],
            target=result['target'], reference_entry=reference['entry'], instructions=result['instructions'],
            raw_producer_nodes=raw_nodes,
            schedule_producer_nodes=certificate['schedule_producer_nodes'],
            condition_occurrences=certificate['schedule_condition_count'],
            SMT_solver_checks=result['SMT_solver_checks'], source_context=sources,
            explicit_premises=result['explicit_premises'],
            proof_audit=result, receipt_audit_only=True, solver_not_rerun=True,
            same_execution_as_behavior=False, historical_originality_proven=False,
            universal_equivalence=False))
    evaluator.check_pins(pins)
    destination = _output_path(destination, [*input_roots, *evidence_roots])
    result = dict(schema_version=1, status=STATUS, errors=[], sample_count=4,
        corpus_manifest=str(Path(corpus).absolute()), samples=results,
        source_version_count=len({row['source_context']['source_version_sha256'] for row in results}),
        SMT_solver_checks=sum(row['SMT_solver_checks'] for row in results),
        all_selected_execution_proof_receipts_audited=True, receipt_audit_only=True,
        solver_not_rerun=True, guest_execution=False, old_runs_modified=False,
        unified_fresh_pipeline_run=False, capture_stability_established=False,
        same_execution_as_behavior=False, historical_originality_proven=False,
        universal_equivalence=False, fuzzing_ready=False, input_sha256=pins)
    destination.mkdir(parents=True, exist_ok=False)
    evaluator.save(destination / 'summary.json', result)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--corpus', type=Path, required=True)
    parser.add_argument('--sample-proof', action='append', default=[], metavar='NAME=PATH')
    parser.add_argument('--project', type=Path)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args(argv)
    try:
        proofs = {}
        for value in args.sample_proof:
            name, separator, path = value.partition('=')
            require(separator and name and path and name not in proofs, 'Duplicate or invalid --sample-proof')
            proofs[name] = Path(path)
        output = args.output or Path(tempfile.mkdtemp(prefix='unpack-proof.external-audit-', dir=ROOT)) / 'probe'
        print('Results:', output, flush=True)
        result = audit_external(args.corpus, proofs, output, project=args.project)
    except (OSError, ValueError, KeyError, TypeError, RecursionError) as error:
        print('FAIL:', type(error).__name__ + ': ' + str(error), file=sys.stderr)
        return 1
    print(result['status'], flush=True)
    print('Audited selected executions:', result['sample_count'], flush=True)
    print('Source versions:', result['source_version_count'], flush=True)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
