"""Backend-attested guest outcomes; a host wait signal alone is insufficient."""
from __future__ import annotations

import os
import signal
import struct

from . import afl_file as f

MAGIC = 0x54465731
VERSION = 2
RESPONSE = struct.Struct('!12I')
BRIDGE_MAGIC = 0x54464131
KINDS = {'normal': 0, 'guest_crash': 1, 'timeout': 2, 'infra_error': 3}


def decode(data):
    f.p.require(len(data) == RESPONSE.size, 'Incomplete warm outcome')
    magic, child, status, timeout, event, target_sig, host_sig, code, pc, ms, rss, parent_rss = RESPONSE.unpack(data)
    f.p.require(magic == MAGIC and child > 0 and timeout in (0, 1) and
                event in (0, 1, 2) and parent_rss <= 131072 and code <= 255,
                'Invalid warm outcome protocol')
    result = {'schema': 1, 'backend_abi': VERSION, 'kind': 'infra_error',
              'child_namespace_pid': child, 'wait_status': status, 'timed_out': False,
              'deadline_expired': bool(timeout),
              'backend_event': event, 'guest_signal': target_sig or None,
              'host_signal': host_sig or None, 'guest_exit': None,
              'guest_pc': pc if event else None, 'duration_ms': ms,
              'child_peak_rss_kib': rss, 'parent_rss_mib': parent_rss, 'reason': 'unattested_or_inconsistent_child_exit'}
    # ABI 2's timeout word records entering the deadline/kill branch. The child
    # can exit or crash between WNOHANG and kill(); wait4 still returns its real
    # terminal status. Require SIGKILL for a timeout, and retain matching backend
    # attestations when an exit or fatal signal won that race.
    if timeout and os.WIFSIGNALED(status) and os.WTERMSIG(status) == signal.SIGKILL:
        result.update(kind='timeout', timed_out=True, reason='backend_deadline', guest_signal=None, host_signal=None)
    elif event == 1 and not target_sig and not host_sig and os.WIFEXITED(status) and os.WEXITSTATUS(status) == code:
        result.update(kind='normal', reason='guest_exit', guest_exit=code)
    elif event == 2 and 1 <= target_sig <= 64 and 1 <= host_sig < signal.NSIG and os.WIFSIGNALED(status) and os.WTERMSIG(status) == host_sig:
        result.update(kind='guest_crash', reason='guest_fatal_signal')
    return result


def bridge_header(outcome):
    kind = KINDS[outcome['kind']]
    return struct.pack('!4I', BRIDGE_MAGIC, kind,
                       outcome['host_signal'] if kind == 1 else 0, f.MAP_SIZE)


def check_bridge(data):
    magic, kind, sig, size = struct.unpack('!4I', data)
    f.p.require(magic == BRIDGE_MAGIC and kind in (0, 1, 2) and size == f.MAP_SIZE and
                ((kind == 1 and 1 <= sig < signal.NSIG) or (kind != 1 and sig == 0)),
                'Invalid warm response')
    return kind
