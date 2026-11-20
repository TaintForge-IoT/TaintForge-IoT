import argparse
import json
from pathlib import Path
import time
import unittest

MODULES = (
    'tests.test_afl_storage', 'tests.test_afl_storage_permissions',
    'tests.test_afl_lifecycle', 'tests.test_afl_review_regressions',
    'tests.test_afl_observer_install',
    'tests.test_afl_capsule', 'tests.test_afl_capsule_faults', 'tests.test_afl_phase2',
    'tests.test_afl_pipeline_cli', 'tests.test_afl_replay_epochs', 'tests.test_afl_session_completion',
    'tests.test_afl_transport', 'tests.test_afl_warm', 'tests.test_afl_warm_mounts',
    'tests.test_afl_warm_process', 'tests.test_afl_campaign', 'tests.test_afl_outcomes',
    'tests.test_afl_bridge_faults', 'tests.test_afl_file.FileBindingTests',
    'tests.test_afl_file.UnifiedAflTests', 'tests.test_capsule_lifecycle',
    'tests.test_input_retirement', 'tests.test_analysis_quality',
    'tests.test_capsule_hardening_integration', 'tests.test_phase1_retirement_integration',
    'tests.test_phase1_m4_build', 'tests.test_capsule_control.ControlPolicyTests',
    'tests.test_capsule_control.ControlIntegrationTests', 'tests.test_capsule_control.CollectionTests',
    'tests.test_capsule_hardening.HardeningPolicyTests', 'tests.test_capsule_hardening.LauncherTests',
    'tests.test_capsule_hardening.CollectionTests', 'tests.test_phase1_retirement_evidence',
    'tests.test_retirement_observer_handoff', 'tests.test_retirement_observer.ObserverEvidenceTests',
)


class Result(unittest.TextTestResult):
    successes = 0

    def addSuccess(self, test):
        self.successes += 1
        super().addSuccess(test)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    if args.out.exists(): parser.error('Result already exists')
    started = time.monotonic()
    suite = unittest.defaultTestLoader.loadTestsFromNames(MODULES)
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
