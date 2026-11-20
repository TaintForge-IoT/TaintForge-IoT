#!/usr/bin/env python3
"""Run named unittest suites with explicit counts, skips and invocation identity."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import unittest

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT))


def test_ids(suite):
    for test in suite:
        if isinstance(test, unittest.TestSuite):
            yield from test_ids(test)
        else:
            yield test.id()


def execute(names, run_id):
    suite = unittest.defaultTestLoader.loadTestsFromNames(names)
    discovered = list(test_ids(suite))
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    pairs = lambda entries: [{"test": test.id(), "detail": str(detail)} for test, detail in entries]
    complete = result.wasSuccessful() and bool(discovered) and not result.skipped and not result.expectedFailures
    return {"schema_version": 1, "kind": "network_unittest_result", "run_id": run_id,
            "status": "passed" if complete else "incomplete" if result.wasSuccessful() else "failed",
            "requested": names, "discovered": discovered, "tests_run": result.testsRun,
            "skipped": pairs(result.skipped), "expected_failures": pairs(result.expectedFailures),
            "failures": pairs(result.failures), "errors": pairs(result.errors),
            "unexpected_successes": [test.id() for test in result.unexpectedSuccesses],
            "execution_uid": os.geteuid(), "python_executable": sys.executable}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--test", action="append", required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--run-id", required=True)
    args = parser.parse_args()
    report = execute(args.test, args.run_id)
    # The parent precreates this file as the invoking user, including for sudo workers.
    if args.report.is_symlink():
        raise ValueError("report must not be a symlink")
    with args.report.open("w") as stream:
        json.dump(report, stream, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    return 1 if report["status"] == "failed" else 0


if __name__ == "__main__":
    raise SystemExit(main())
