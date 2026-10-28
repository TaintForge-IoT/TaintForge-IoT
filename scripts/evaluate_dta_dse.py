"""Measure fresh file DTA/DSE and fully rerun all generated DSE candidates."""
import argparse
import json
from pathlib import Path
import sys
import subprocess

from taintforge_env.dta_dse_eval import evaluate_file


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('binary', 'qemu', 'plugin', 'flags-receipt', 'out'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--seed', action='append', dest='seeds', type=Path, required=True)
    parser.add_argument('--input-path', required=True)
    parser.add_argument('--arg', dest='argv', action='append', default=[])
    for name, default in (('max-candidates', 24), ('max-jobs', 8), ('max-occurrences', 4),
                          ('max-steps', 1024), ('max-sites', 4096), ('seconds', 30),
                          ('memory-mib', 1024), ('wall-seconds', 3600)):
        parser.add_argument('--' + name, type=int, default=default)
    args = parser.parse_args(argv)
    try:
        report = evaluate_file(**vars(args))
    except KeyboardInterrupt:
        print('FILE_DTA_DSE_EVALUATION_INTERRUPTED', file=sys.stderr)
        return 130
    except (OSError, ValueError, RuntimeError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        print('FILE_DTA_DSE_EVALUATION_FAILED: ' + str(exc), file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report['measurement_completed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
