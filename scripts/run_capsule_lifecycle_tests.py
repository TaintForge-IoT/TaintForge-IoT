import argparse
from pathlib import Path
import time
import unittest

from experiments.execution_capsule_probe import controller as p

SOURCES = ('taintforge_env/capsule_supervision.py', 'taintforge_env/input_retirement.py',
    'taintforge_env/phase1_retirement.py', 'taintforge_env/analysis_quality.py',
    'taintforge_env/capsule_resources.py', 'taintforge_env/retirement_evidence.py',
    'experiments/retirement_observer/controller.py', 'tests/test_capsule_lifecycle.py',
    'tests/test_input_retirement.py', 'tests/test_analysis_quality.py',
    'tests/test_capsule_control.py', 'tests/test_capsule_hardening_integration.py',
    'scripts/inject_capsule_lifecycle_fault.py', 'scripts/audit_capsule_strict_evidence.py',
    'scripts/run_capsule_lifecycle_e2e.py', 'scripts/collect_capsule_lifecycle_evidence.py',
    'scripts/run_capsule_lifecycle_tests.py', 'scripts/build_run_capsule_lifecycle.sh')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    p.require(not args.out.exists(), 'Lifecycle test result already exists')
    args.out.parent.mkdir(parents=True, exist_ok=True)
    suite = unittest.defaultTestLoader.loadTestsFromName('tests.test_capsule_lifecycle')
    expected, started = suite.countTestCases(), time.monotonic()
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    root = Path(__file__).resolve().parents[1]
    success = result.wasSuccessful() and not result.skipped and result.testsRun == expected
    p.write_json(args.out, {'schema': 1, 'tests_run': result.testsRun, 'tests_expected': expected,
        'successful': success, 'skipped': len(result.skipped), 'failures': len(result.failures),
        'errors': len(result.errors), 'elapsed_seconds': round(time.monotonic()-started, 3),
        'source_sha256': {name: p.sha(root/name) for name in SOURCES},
        'scope': 'real_child_processes_and_seqpacket_pairs_with_synthetic_exports_and_guest_execution',
        'native_qemu_faults_tested_by_this_suite': False})
    return 0 if success else 1


if __name__ == '__main__':
    raise SystemExit(main())
