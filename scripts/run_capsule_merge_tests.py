import argparse
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import unittest
import xml.etree.ElementTree as ET


class Result(unittest.TextTestResult):
    successes = 0

    def addSuccess(self, test):
        self.successes += 1
        super().addSuccess(test)


def cases(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite): yield from cases(item)
        else: yield item


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    if args.out.exists(): parser.error('Result already exists')
    root = Path(__file__).resolve().parents[1]
    os.environ['PYTHONPATH'] = str(root)+os.pathsep+os.environ.get('PYTHONPATH', '')
    unavailable = {}
    if not shutil.which('pkg-config'):
        unavailable = {'tests.test_afl_file.NativeCoverageTests': 'pkg-config and GLib development files required',
                       'tests.test_retirement_observer.NativeObserverTests': 'pkg-config and GLib development files required',
                       'tests.test_capsule_control.NativeControlTests': 'pkg-config and GLib development files required'}
    names = ['tests.'+path.stem for path in sorted((root/'tests').glob('test_*.py'))
             if path.stem != 'test_runtime_modules']
    discovered = unittest.defaultTestLoader.loadTestsFromNames(names)
    suite, excluded = unittest.TestSuite(), []
    for test in cases(discovered):
        kind = test.__class__.__module__+'.'+test.__class__.__name__
        if kind in unavailable:
            excluded.append({'test': test.id(), 'reason': unavailable[kind]})
        else:
            suite.addTest(test)
    started = time.monotonic()
    result = unittest.TextTestRunner(verbosity=2, resultclass=Result).run(suite)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    pytest = {'status': 'unavailable', 'reason': 'pytest required for tests/test_runtime_modules.py'}
    if importlib.util.find_spec('pytest') is not None:
        xml = args.out.with_suffix('.pytest.xml')
        process = subprocess.run([sys.executable, '-m', 'pytest', '-q', 'tests/test_runtime_modules.py',
                                  '--junitxml='+str(xml.resolve())], cwd=root, capture_output=True, text=True)
        args.out.with_suffix('.pytest.log').write_text(process.stdout+process.stderr)
        pytest = {'status': 'failed', 'returncode': process.returncode}
        try:
            tree = ET.parse(xml).getroot()
            counts = {name: sum(int(node.get(name, 0)) for node in tree.iter('testsuite'))
                      for name in ('tests', 'failures', 'errors', 'skipped')}
            pytest.update(counts)
            if process.returncode == 0 and not counts['failures'] and not counts['errors']:
                pytest['status'] = 'passed'
        except (OSError, ET.ParseError, ValueError) as exc:
            pytest['reason'] = str(exc)
    value = {'schema': 1, 'tests_run': result.testsRun, 'passed': result.successes,
             'failures': len(result.failures), 'errors': len(result.errors),
             'skipped': [{'test': str(test), 'reason': reason} for test, reason in result.skipped],
             'unavailable': excluded, 'pytest': pytest,
             'successful': result.wasSuccessful() and pytest['status'] != 'failed',
             'elapsed_seconds': round(time.monotonic()-started, 3),
             'native_capsule_acceptance': False, 'network_namespace_acceptance': False}
    args.out.write_text(json.dumps(value, indent=2)+'\n')
    return 0 if value['successful'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
