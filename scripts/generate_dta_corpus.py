"""Create bounded file-input mutation candidates from existing DTA root logs."""
import argparse
import json
from pathlib import Path
import sys

from taintforge_env.dta_corpus import DtaCorpusError, generate_corpus


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('seed', 'binary', 'trace', 'out'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--input-path', required=True)
    parser.add_argument('--max-candidates', type=int, default=128)
    parser.add_argument('--max-groups', type=int, default=64)
    parser.add_argument('--max-offsets', type=int, default=16)
    parser.add_argument('--max-trace-bytes', type=int, default=64 * 1024**2)
    args = parser.parse_args(argv)
    try:
        report = generate_corpus(**vars(args))
    except (DtaCorpusError, OSError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print(json.dumps(report, indent=2, ensure_ascii=False))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
