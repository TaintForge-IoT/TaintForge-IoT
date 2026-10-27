"""Run the M4 tests and retain their source hashes."""
import argparse
from pathlib import Path
import time
import unittest

from experiments.execution_capsule_probe import controller as p

MODULES=('tests.test_capsule_hardening','tests.test_capsule_hardening_integration')
NATIVE_INPUTS=('experiments/capsule_hardening/budget_guest.S',
    'experiments/capsule_hardening/seed_budget_test.c', 'experiments/capsule_hardening/ledger_test.c',
    'unpacker/test/phase1_resources.c', 'unpacker/test/phase1_resources.h',
    'unpacker/test/provenance.c', 'unpacker/test/provenance.h',
    'unpacker/test/phase1_alloc.h', 'unpacker/test/dta.h')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out',type=Path,required=True)
    args=parser.parse_args()
    p.require(not args.out.exists(), 'M4 test result already exists')
    suite=unittest.defaultTestLoader.loadTestsFromNames(MODULES)
    expected=suite.countTestCases()
    started=time.monotonic()
    result=unittest.TextTestRunner(verbosity=2).run(suite)
    success=result.wasSuccessful() and not result.skipped and result.testsRun==expected
    root=Path(__file__).resolve().parents[1]
    sources=tuple(name.replace('.','/')+'.py' for name in MODULES)+NATIVE_INPUTS
    p.write_json(args.out, {'schema':1,'modules':list(MODULES),'tests_run':result.testsRun,
        'tests_expected':expected,'successful':success,'skipped':len(result.skipped),
        'failures':len(result.failures),'errors':len(result.errors),
        'elapsed_seconds':round(time.monotonic()-started,3),
        'source_sha256':{name:p.sha(root/name) for name in sources}})
    return 0 if success else 1


if __name__=='__main__':raise SystemExit(main())
