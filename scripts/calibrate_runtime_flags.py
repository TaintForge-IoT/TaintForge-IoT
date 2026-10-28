"""Build a matching observer and calibrate one exact QEMU/Phase 1 runtime."""
import argparse
import json
from pathlib import Path
import subprocess
import sys

from taintforge_env.runtime_flags import calibrate_flags


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('qemu', 'qemu-include', 'plugin', 'out'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        result = calibrate_flags(**vars(args))
    except (OSError, ValueError, RuntimeError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        print(f'RUNTIME_FLAGS_CALIBRATION_FAILED: {exc}', file=sys.stderr)
        return 1
    print(json.dumps({key: result[key] for key in ('status', 'qemu', 'qemu_sha256', 'plugin',
        'plugin_api', 'flags_receipt', 'flags_receipt_sha256')}, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
