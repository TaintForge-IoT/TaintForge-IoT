"""Bind FD samples to the live warm parent's namespace and start time."""
import hashlib
import json
import os
from pathlib import Path


def _identity(directory, namespace, pid):
    if os.readlink(directory/'ns/pid') != namespace:
        return None
    status = dict(line.split(':', 1) for line in (directory/'status').read_text().splitlines())
    if int(status['NSpid'].split()[-1]) != pid:
        return None
    text = (directory/'stat').read_text()
    fields = text[text.rindex(')')+2:].split()
    if fields[0] == 'Z':
        raise RuntimeError('Warm parent is a zombie')
    return int(fields[19])


def sample_parent(pid, *, expected=None, proc=Path('/proc')):
    if type(pid) is not int or pid <= 0:
        raise ValueError('Invalid warm parent PID')
    proc = Path(proc)
    namespace = os.readlink(proc/'self/ns/pid')
    direct = proc/str(pid)
    matches = []
    try:
        start = _identity(direct, namespace, pid)
        if start is not None:
            matches.append((direct, start))
    except (FileNotFoundError, ProcessLookupError):
        pass
    if not matches:
        for directory in proc.iterdir():
            if not directory.name.isdecimal() or directory == direct:
                continue
            try:
                start = _identity(directory, namespace, pid)
                if start is not None:
                    matches.append((directory, start))
            except (FileNotFoundError, ProcessLookupError, PermissionError):
                continue
    if len(matches) != 1:
        raise RuntimeError('Warm parent not uniquely identified in procfs')
    directory, start = matches[0]
    identity = {'namespace_pid': pid, 'pid_namespace': namespace, 'start_ticks': start}
    if expected is not None and any(identity[key] != expected[key] for key in identity):
        raise RuntimeError('Warm parent process identity changed')
    try:
        entries = sorted((int(path.name), os.readlink(path)) for path in (directory/'fd').iterdir())
    except (FileNotFoundError, ProcessLookupError) as exc:
        raise RuntimeError('Warm parent FD inventory changed during sampling') from exc
    if _identity(directory, namespace, pid) != start:
        raise RuntimeError('Warm parent changed during resource sampling')
    return identity | {'fd_count': len(entries), 'fd_sha256': hashlib.sha256(json.dumps(entries).encode()).hexdigest()}
