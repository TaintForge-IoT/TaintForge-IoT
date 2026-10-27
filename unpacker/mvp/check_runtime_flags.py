#!/usr/bin/env python3
"""Calibrate one QEMU's EFLAGS observations against 64 guest PUSHFL results.

This is a bounded observation probe. It does not assert correctness of the
whole x86 emulator or grant a flag-observation contract to another executable.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import sys


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def require(value, message):
    if not value:
        raise ValueError(message)


def save(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + '\n')


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'Duplicate observer JSON field')
        result[key] = value
    return result


def check_flags(qemu, plugin, binary, output):
    qemu, plugin, binary = (Path(p).resolve(strict=True) for p in (qemu, plugin, binary))
    output = Path(output).absolute()
    require(not output.exists() and not output.is_symlink(), 'Flags output must be new')
    require(all(',' not in str(p) and '\n' not in str(p) for p in (plugin, output)),
            'Plugin argument paths cannot contain commas/newlines')
    output.mkdir(parents=True)
    pinned = {str(p): digest(p) for p in (qemu, plugin, binary)}
    summary = {'schema_version': 1, 'status': 'FAIL_QEMU_PUSHF_BOUNDARY_PROBE',
               'bounded_probe_only': True, 'qemu_sha256': pinned[str(qemu)],
               'artifacts': pinned, 'runs': {}, 'errors': []}
    try:
        symbols = subprocess.run(['nm', '-n', str(binary)], check=True, text=True,
                                 capture_output=True, timeout=30).stdout
        (output / 'symbols.txt').write_text(symbols)
        boundaries = {}
        for line in symbols.splitlines():
            match = re.fullmatch(r'([0-9a-fA-F]+) [A-Za-z] flag_boundary_([0-9]+)', line)
            if match:
                index = int(match[2])
                require(index not in boundaries, 'Duplicate flags boundary symbol')
                boundaries[index] = int(match[1], 16)
        require(set(boundaries) == set(range(32)) and len(set(boundaries.values())) == 32,
                'Expected exactly 32 unique PUSHFL boundaries')
        summary['boundary_pcs'] = [boundaries[i] for i in range(32)]
        for mode in ('normal', 'single'):
            report = output / (mode + '.jsonl')
            command = [str(qemu), *(['-one-insn-per-tb'] if mode == 'single' else []),
                       '-plugin', f'{plugin},report={report}', str(binary)]
            save(output / (mode + '-command.json'), command)
            process = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                     timeout=30)
            (output / (mode + '.stdout')).write_bytes(process.stdout)
            (output / (mode + '.stderr')).write_bytes(process.stderr)
            rows = []
            if report.is_file():
                require(report.stat().st_size <= 32768, 'Oversized flags observer report')
                rows = [json.loads(line, object_pairs_hook=unique)
                        for line in report.read_text().splitlines()]
            valid = process.returncode == 0 and len(process.stdout) == 128 and len(rows) == 33
            mismatches = []
            if valid:
                tail = rows[-1]
                valid = (isinstance(tail, dict) and
                         tail == {'summary': True, 'checks': 32, 'cpus': 1, 'failed': False} and
                         tail['summary'] is True and tail['failed'] is False and
                         type(tail['checks']) is int and type(tail['cpus']) is int)
                guest_flags = struct.unpack('<32I', process.stdout)
                for index, (row, guest) in enumerate(zip(rows[:-1], guest_flags)):
                    match = (isinstance(row, dict) and type(row.get('index')) is int and
                             row['index'] == index + 1 and type(row.get('pc')) is int and
                             row['pc'] == boundaries[index] and row.get('valid') is True and
                             type(row.get('flags')) is int and row['flags'] == guest)
                    if not match:
                        mismatches.append({'index': index + 1, 'observed': row, 'pushfl': guest})
            summary['runs'][mode] = {'checked': 32 if valid else 0, 'exit': process.returncode,
                                     'valid': valid, 'mismatches': mismatches}
        unchanged = all(digest(Path(path)) == value for path, value in pinned.items())
        summary['artifacts_unchanged'] = unchanged
        success = unchanged and all(row['valid'] and not row['mismatches']
                                    for row in summary['runs'].values())
        if success:
            receipt = ('TAINTFORGE_X86_FLAGS_V1\nqemu_sha256=' + pinned[str(qemu)] +
                       '\nprobe=pushf-boundary-v1\ntarget=i386-linux-user\nnormal_checked=32\n'
                       'single_checked=32\nmismatches=0\n')
            with (output / 'flags.receipt').open('x') as stream:
                stream.write(receipt)
            summary['receipt_sha256'] = digest(output / 'flags.receipt')
            summary['status'] = 'PASS_QEMU_PUSHF_BOUNDARY_PROBE'
        return summary
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        summary['errors'].append(type(error).__name__ + ': ' + str(error))
        raise
    finally:
        save(output / 'summary.json', summary)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('qemu', 'plugin', 'binary', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    try:
        result = check_flags(args.qemu, args.plugin, args.binary, args.output)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print('FAIL:', error, file=sys.stderr)
        return 1
    print(result['status'])
    return 0 if result['status'] == 'PASS_QEMU_PUSHF_BOUNDARY_PROBE' else 1


if __name__ == '__main__':
    raise SystemExit(main())
