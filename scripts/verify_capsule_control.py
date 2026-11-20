"""Exercise the strict control guard with benign i386 guests."""
import argparse
from pathlib import Path

from experiments.capsule_control.check import components


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qemu', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    report = components(args.qemu, args.out)
    print('Capsule control components:', report['status'], 'cases:', len(report['cases']))


if __name__ == '__main__':
    main()
