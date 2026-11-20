"""Run control-guard contract and native handoff tests."""
import argparse
from pathlib import Path
import time
import unittest

from experiments.execution_capsule_probe import controller as p


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    p.require(not args.out.exists(), 'Control test result already exists')
    suite = unittest.defaultTestLoader.loadTestsFromName('tests.test_capsule_control')
    expected, started = suite.countTestCases(), time.monotonic()
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    success = result.wasSuccessful() and not result.skipped and result.testsRun == expected
    root = Path(__file__).resolve().parents[1]
    paths = ('tests/test_capsule_control.py', 'taintforge_env/capsule_control.py',
             'experiments/retirement_observer/control_guard.h',
             'experiments/retirement_observer/observer.c', 'experiments/retirement_observer/controller.py')
    p.write_json(args.out, {'schema': 1, 'tests_run': result.testsRun, 'tests_expected': expected,
        'successful': success, 'skipped': len(result.skipped), 'failures': len(result.failures),
        'errors': len(result.errors), 'elapsed_seconds': round(time.monotonic()-started, 3),
        'source_sha256': {name: p.sha(root/name) for name in paths}})
    return 0 if success else 1


if __name__ == '__main__':
    raise SystemExit(main())
