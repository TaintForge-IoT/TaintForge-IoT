"""Compare bounded diagnostic fetch prefixes; this module never authorizes proof."""
import argparse
import hashlib
import json
from pathlib import Path

MAX_ROWS = 262144
MAX_BYTES = 128 * 1024**2


def require(condition, message):
    if not condition:
        raise ValueError(message)


def read_trace(path):
    path = Path(path)
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= MAX_BYTES,
            'Diagnostic trace absent, symlink or oversized')
    raw = path.read_bytes()
    require(len(raw) <= MAX_BYTES, 'Diagnostic trace grew beyond budget')
    def pairs(items):
        row = {}
        for key, value in items:
            require(key not in row, 'Duplicate diagnostic trace key')
            row[key] = value
        return row
    def invalid(value):
        raise ValueError('Noninteger diagnostic trace number: '+value)
    rows = []
    for line in raw.splitlines(keepends=True):
        require(line.endswith(b'\n') and len(line) <= 8192 and len(rows) < MAX_ROWS,
                'Diagnostic trace framing or row budget')
        row = json.loads(line, object_pairs_hook=pairs, parse_float=invalid, parse_constant=invalid)
        require(type(row) is dict, 'Diagnostic trace row must be an object')
        for key, maximum, minimum in (('ordinal', 30000000, 1), ('pc', 0xffffffff, 0), ('size', 15, 1)):
            value = row.get(key)
            require(type(value) is int and minimum <= value <= maximum,
                    'Invalid diagnostic trace '+key)
        require(not rows or row['ordinal'] == rows[-1]['ordinal'] + 1,
                'Diagnostic instruction ordinal gap')
        value = row.get('bytes_hex')
        require(type(value) is str and len(value) == row['size'] * 2 and
                all(c in '0123456789abcdef' for c in value), 'Noncanonical diagnostic bytes')
        for register in ('ecx', 'esi', 'edi', 'eflags'):
            if register in row:
                value, known = row[register], row.get(register+'_known')
                require(type(known) is int and 0 <= known <= 0xffffffff and
                        (value is None or type(value) is int and 0 <= value <= 0xffffffff),
                        'Invalid diagnostic register or known mask')
                require(value is not None or known != 0xffffffff,
                        'Fully known diagnostic register lacks value')
        rows.append(row)
    require(rows, 'Empty diagnostic trace')
    return rows, dict(path=str(path.absolute()), sha256=hashlib.sha256(raw).hexdigest(),
                      bytes=len(raw), rows=len(rows), first_ordinal=rows[0]['ordinal'],
                      last_ordinal=rows[-1]['ordinal'])


def compare(observed, replay):
    left, left_pin = read_trace(observed)
    right, right_pin = read_trace(replay)
    require(left[0]['ordinal'] == right[0]['ordinal'], 'Diagnostic trace starts differ')
    key = lambda row: (row['ordinal'], row['pc'], row['size'], row['bytes_hex'])
    same = 0
    while same < min(len(left), len(right)) and key(left[same]) == key(right[same]):
        same += 1
    mismatch = None
    if same < min(len(left), len(right)):
        mismatch = dict(observed=left[same], replay=right[same],
                        previous_observed=left[max(0, same-2):same],
                        previous_replay=right[max(0, same-2):same])
        status = 'DIAGNOSTIC_FETCH_DIVERGENCE'
    elif len(left) != len(right):
        status = 'DIAGNOSTIC_PREFIX_LENGTH_DIFFERENCE'
    else:
        status = 'MATCHED_DIAGNOSTIC_PREFIX'
    return dict(schema_version=1, status=status, compared_equal_rows=same,
                first_difference=mismatch, observed=left_pin, replay=right_pin,
                comparison_keys=['ordinal','pc','size','bytes_hex'],
                register_values_are_diagnostics_only=True,
                full_path_equivalence_established=False, proof_authorized=False,
                truncated_prefix_cannot_establish_full_execution=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--observed', type=Path, required=True)
    parser.add_argument('--replay', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = compare(args.observed, args.replay)
    require(not args.output.is_symlink(), 'Diagnostic output must not be a symlink')
    with args.output.open('x') as stream:
        json.dump(result, stream, indent=2, sort_keys=True)
        stream.write('\n')
    print(result['status'])


if __name__ == '__main__':
    main()
