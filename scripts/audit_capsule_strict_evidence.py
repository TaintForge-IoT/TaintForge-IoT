import argparse
import copy
from pathlib import Path

from experiments.execution_capsule_probe import controller as p
from taintforge_env import analysis_quality as quality, phase1_retirement as retirement
from taintforge_env.phase1_runtime import read_json
from taintforge_env.retirement_evidence import verify


def audit(proof, digest):
    proof = Path(proof).resolve(strict=True)
    checked = verify(proof, expected_sha256=digest)
    binding = read_json(proof/'config/capsule_binding.json')
    binding['run_dir'] = str(proof)
    saved = read_json(proof/'logs/capsule/phase1-retirement/retirement.json')
    run, verified = retirement.verify_export(binding, saved['events'])
    strict_binding = copy.deepcopy(binding)
    strict_binding['settings']['analysis_policy'] = quality.policy('strict')
    strict = quality.assess(strict_binding, run, verified, run.events())
    return {'schema': 1, 'scope': 'offline_reassessment_of_one_verified_export',
        'source_bundle_sha256': digest, 'source_decision': checked['analysis_quality'],
        'strict_assessment': strict,
        'status': 'offline_eligible' if strict['status'] == 'accepted' else 'blocked_by_export_quality',
        'native_strict_positive_verified': False, 'oep_proven': False,
        'permit_sent_by_audit': False}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--proof', type=Path, required=True)
    parser.add_argument('--sha256', required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    p.require(not args.out.exists(), 'Strict assessment already exists')
    p.write_json(args.out, audit(args.proof, args.sha256))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
