"""Run the M3 regression suite and save its result."""
import argparse
from pathlib import Path
import time
import unittest

from experiments.execution_capsule_probe.controller import sha, write_json

MODULES = (
    "tests.test_phase1_retirement", "tests.test_phase1_retirement_integration",
    "tests.test_phase1_verdict_retirement", "tests.test_phase1_runtime",
    "tests.test_execution_capsule", "tests.test_capsule_unified_lifecycle",
    "tests.test_phase1_retirement_evidence", "tests.test_retirement_observer",
    "tests.test_retirement_observer_launch", "tests.test_retirement_observer_pc",
    "tests.test_retirement_observer_handoff", "tests.test_input_retirement",
    "tests.test_input_retirement_matrix", "tests.test_input_retirement_collection",
)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    if args.out.exists() or args.out.is_symlink():
        parser.error("Test result already exists")
    suite = unittest.defaultTestLoader.loadTestsFromNames(MODULES)
    expected = suite.countTestCases()
    started = time.monotonic()
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    passed = result.wasSuccessful() and not result.skipped and result.testsRun == expected
    root = Path(__file__).resolve().parents[1]
    sources = [name.replace(".", "/") + ".py" for name in MODULES]
    write_json(args.out, dict(schema=1, modules=list(MODULES), tests_expected=expected,
        tests_run=result.testsRun, failures=len(result.failures), errors=len(result.errors),
        skipped=len(result.skipped), unexpected_successes=len(result.unexpectedSuccesses),
        successful=passed, elapsed_seconds=round(time.monotonic()-started, 3),
        source_sha256={name: sha(root / name) for name in sources}))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
