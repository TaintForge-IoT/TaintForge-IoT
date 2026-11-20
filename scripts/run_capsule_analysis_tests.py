"""Run analysis admission and evidence tests."""
import argparse
from pathlib import Path
import time
import unittest

from experiments.execution_capsule_probe import controller as p

SOURCES = ('taintforge_env/analysis_quality.py', 'taintforge_env/phase1_retirement.py',
    'taintforge_env/input_retirement.py', 'taintforge_env/retirement_evidence.py',
    'experiments/retirement_observer/controller.py', 'scripts/run_unified_pipeline.py',
    'scripts/run_afl_file.py', 'taintforge_env/afl_file.py', 'taintforge_env/afl_warm.py',
    'scripts/run_capsule_control_e2e.py',
    'scripts/run_capsule_analysis_e2e.py', 'scripts/collect_capsule_analysis_evidence.py',
    'tests/test_analysis_quality.py')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    p.require(not args.out.exists(), 'Analysis test result already exists')
    suite = unittest.defaultTestLoader.loadTestsFromName('tests.test_analysis_quality')
    expected, started = suite.countTestCases(), time.monotonic()
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    success = result.wasSuccessful() and not result.skipped and result.testsRun == expected
    root = Path(__file__).resolve().parents[1]
    p.write_json(args.out, {'schema': 1, 'tests_run': result.testsRun, 'tests_expected': expected,
        'successful': success, 'skipped': len(result.skipped), 'failures': len(result.failures),
        'errors': len(result.errors), 'elapsed_seconds': round(time.monotonic()-started, 3),
        'source_sha256': {name: p.sha(root/name) for name in SOURCES}})
    return 0 if success else 1


if __name__ == '__main__':
    raise SystemExit(main())
