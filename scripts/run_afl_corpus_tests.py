"""Run AFL integration regressions; record unavailable native checks explicitly."""
import argparse
import json
from pathlib import Path
import time
import unittest
from scripts.run_afl_storage_tests import MODULES, Result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    if args.out.exists(): parser.error('Result already exists')
    started = time.monotonic()
    suite = unittest.defaultTestLoader.loadTestsFromNames((*MODULES, 'tests.test_afl_corpus', 'tests.test_afl_corpus_ledger',
                                                        'tests.test_afl_continue', 'tests.test_afl_strict',
                                                        'tests.test_afl_stop'))
    result = unittest.TextTestRunner(verbosity=2, resultclass=Result).run(suite)
    value = {'schema': 1, 'tests_run': result.testsRun, 'passed': result.successes,
        'failures': len(result.failures), 'errors': len(result.errors),
        'skipped': [{'test': str(test), 'reason': reason} for test, reason in result.skipped],
        'successful': result.wasSuccessful(), 'elapsed_seconds': round(time.monotonic()-started, 3),
        'full_native_m5_acceptance': False}
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(value, indent=2)+'\n')
    return 0 if result.wasSuccessful() else 1


if __name__ == '__main__':
    raise SystemExit(main())
