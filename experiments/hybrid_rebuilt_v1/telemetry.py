"""Independent AFL++ custom-mutator hook accounting (never stock-origin proof)."""
from __future__ import annotations

from pathlib import Path
import stat


def audit_hook_trace(path, *, expected_fuzz_callbacks=None, limit_bytes=1_048_576):
    """Audit C hook trace recorded outside the guest execution boundary.

    ``C N`` is one AFL stage-entry callback asking for N custom attempts;
    ``F 1`` records a returned, validated custom output; ``X 1`` denotes a
    clean AFL mutator deinit. A skipped callback writes ``S 1``. A callback
    may not become an AFL child; only per-case SHA receipts establish delivery.
    These counters do not prove
    that an unmatched child originated from a particular stock AFL stage.
    """
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise RuntimeError('Missing or unsafe AFL custom mutator hook trace')
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > limit_bytes:
        raise RuntimeError('Invalid mutator hook trace file identity or size')
    raw = path.read_bytes()
    if len(raw) != info.st_size or not raw.endswith(b'\n'):
        raise RuntimeError('Partial or changed AFL mutator hook trace')
    counters = {'custom_stage_entries': 0, 'custom_attempts_budgeted': 0,
                'custom_fuzz_callbacks': 0, 'clean_deinit_observed': False}
    remaining = consecutive_skips = 0
    rows = raw.decode('ascii').splitlines()
    for i, row in enumerate(rows):
        if row.startswith('C '):
            if counters['clean_deinit_observed'] or not row[2:].isdigit():
                raise RuntimeError(f'Invalid hook stage-entry record {i}')
            n = int(row[2:])
            if not 0 <= n <= 16:
                raise RuntimeError(f'Invalid custom stage-entry budget {i}')
            counters['custom_stage_entries'] += 1
            counters['custom_attempts_budgeted'] += n
            remaining = n
        elif row in ('F 1', 'S 1'):
            if counters['clean_deinit_observed']:
                raise RuntimeError('Hook callback after clean deinit')
            if not remaining:
                raise RuntimeError('Custom fuzz callback outside its AFL stage-entry budget')
            if row == 'S 1':
                counters['custom_skips'] = counters.get('custom_skips', 0) + 1
                consecutive_skips += 1
            else:
                consecutive_skips = 0
            remaining -= 1
            counters['custom_fuzz_callbacks'] += 1
        elif row == 'L 1024':
            if (i == 0 or rows[i - 1] != 'S 1' or consecutive_skips != 1024 or
                    'skip_limit_request' in counters):
                raise RuntimeError('Invalid consecutive-skip stop request')
            counters['skip_limit_request'] = {'callback': counters['custom_fuzz_callbacks'],
                                              'consecutive_skips': consecutive_skips}
        elif row == 'X 1':
            if counters['clean_deinit_observed']:
                raise RuntimeError('Repeated custom mutator deinit')
            counters['clean_deinit_observed'] = True
        else:
            raise RuntimeError(f'Invalid hook trace record at line {i}')
    if (expected_fuzz_callbacks is not None and
            counters['custom_fuzz_callbacks'] != expected_fuzz_callbacks):
        raise RuntimeError('C mutator callbacks disagree with Python controller requests')
    return {'profile': 'afl_native_custom_stage_hooks_v1', **counters,
            'trace_status': ('clean_deinit' if counters['clean_deinit_observed']
                             else 'process_exit_without_deinit'),
            'stock_stage_provenance_verified': False}
