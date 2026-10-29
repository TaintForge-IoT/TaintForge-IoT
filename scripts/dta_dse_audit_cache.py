"""Reuse completed native worker audits after fresh whole-closure byte checks.

The cache exists only inside one explicit, single-threaded context. It is an
optional controlled-run performance experiment, not a protected evidence store.
An accepting driver must run the original full audit again after this context
has closed. UNKNOWN and UNSAT remain exactly the original auditor's results.
"""
from __future__ import annotations

import copy
import hashlib
import inspect
import json
import os
from pathlib import Path
import stat
import threading
import time

from taintforge_env import dse_analysis


PROFILE = 'content-checked-native-worker-audit-session-v1'
PROJECT = Path(__file__).resolve().parents[1]
_ACTIVE_SESSION = None


def _require(value, message):
    if not value:
        raise RuntimeError(message)


def _path(value):
    path = Path(value).expanduser().absolute()
    _require('..' not in path.parts, 'Audit cache path contains parent traversal')
    for parent in path.parents:
        info = parent.lstat()
        _require(stat.S_ISDIR(info.st_mode), 'Audit cache parent is not a real directory: ' + str(parent))
    return path


def _metadata(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_uid,
            info.st_gid, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _parent_identity(path):
    # Temporary audit siblings legitimately change a parent's timestamps and
    # link count. Its identity, type, ownership and permissions must stay fixed.
    return tuple((str(parent), info.st_dev, info.st_ino, info.st_mode,
                  info.st_uid, info.st_gid)
                 for parent in path.parents for info in (parent.lstat(),)
                 if stat.S_ISDIR(info.st_mode))


def _object(pairs):
    result = {}
    for name, value in pairs:
        _require(name not in result, 'Duplicate JSON field in cached worker summary')
        result[name] = value
    return result


def _nonfinite(value):
    raise ValueError('Non-finite JSON number in cached worker summary: ' + value)


class NativeAuditSession:
    """Install bounded in-memory reuse of ``dse_analysis.audit_file_run`` only.

    Every hit reopens and hashes every regular file in the complete worker
    subtree and the six original source files. File identities and directory
    inventories are checked as well. A changed closure raises instead of
    silently replacing an earlier successful admission with new evidence.
    """

    def __init__(self, *, max_entries=512, max_files=65536, max_bytes=4 * 1024**3):
        for value, maximum, label in ((max_entries, 4096, 'entries'),
                (max_files, 1048576, 'files'), (max_bytes, 64 * 1024**3, 'bytes')):
            _require(type(value) is int and 1 <= value <= maximum,
                     'Invalid native audit cache ' + label + ' budget')
        self.budgets = dict(max_entries=max_entries, max_files=max_files, max_bytes=max_bytes)
        self.active = False
        self._used = False
        self._entries = {}
        self._original = None
        self._installed = None
        self._code = None
        self._thread = None
        self._limits = None
        self._credentials = None
        self._metrics = dict(audit_calls=0, full_audit_calls=0, full_audits=0,
            reuse_hits=0, failures=0, changed_closures=0, seal_calls=0,
            seal_wall_ns=0, rehashed_bytes=0, code_check_wall_ns=0, peak_entries=0)

    def __enter__(self):
        global _ACTIVE_SESSION
        _require(_ACTIVE_SESSION is None and not self.active and not self._used,
                 'Nested or reused native audit sessions are unsupported')
        self._thread = threading.get_ident()
        self._credentials = self._credential_identity()
        self._original = dse_analysis.audit_file_run
        self._original_code = getattr(self._original, '__code__', None)
        _require(self._original_code is not None, 'Native audit cache requires a Python auditor')
        self._limits = dict(dse_analysis.SOURCE_LIMITS)
        self._code = self._code_identity()
        self._installed = self.audit
        self.active = self._used = True
        _ACTIVE_SESSION = self
        dse_analysis.audit_file_run = self._installed
        return self

    def __exit__(self, kind, exception, traceback):
        global _ACTIVE_SESSION
        # Restore even when the caller or a profiler has altered the binding.
        dse_analysis.audit_file_run = self._original
        self.active = False
        _ACTIVE_SESSION = None
        self._entries.clear()
        return False

    def _code_identity(self):
        paths = set((PROJECT / 'taintforge_env').glob('*.py'))
        paths.update((PROJECT / 'experiments/execution_capsule_probe').rglob('*.py'))
        paths.add(Path(__file__))
        _require(0 < len(paths) <= 1024, 'Native audit implementation inventory is missing or oversized')
        result = {}
        for value in sorted(paths):
            path = _path(value)
            info = path.lstat()
            _require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= 4 * 1024**2,
                     'Unsafe native audit implementation source')
            with path.open('rb') as stream:
                digest = hashlib.file_digest(stream, 'sha256').hexdigest()
            _require(_metadata(path.lstat()) == _metadata(info), 'Audit implementation changed while hashing')
            result[str(path)] = (_metadata(info), digest)
        _require(all(_metadata(_path(path).lstat()) == identity[0] for path, identity in result.items()),
                 'Audit implementation changed before its complete inventory was sealed')
        return result

    def _check(self):
        _require(self.active and _ACTIVE_SESSION is self and threading.get_ident() == self._thread,
                 'Native audit reuse requires its active original control thread')
        _require(self._credential_identity() == self._credentials, 'Native audit control credentials changed')
        _require(inspect.unwrap(dse_analysis.audit_file_run) == self._installed and
                 getattr(self._original, '__code__', None) is self._original_code and
                 dse_analysis.SOURCE_LIMITS == self._limits,
                 'Native auditor binding, implementation or source policy changed')
        started = time.monotonic_ns()
        try:
            _require(self._code_identity() == self._code, 'Native audit implementation inventory changed')
        finally:
            self._metrics['code_check_wall_ns'] += time.monotonic_ns() - started

    @staticmethod
    def _credential_identity():
        return (os.getuid(), os.geteuid(), os.getgid(), os.getegid(), tuple(sorted(os.getgroups())))

    def _seal(self, directory):
        started = time.monotonic_ns()
        self._metrics['seal_calls'] += 1
        fingerprint, checked_entries, summary_raw = hashlib.sha256(), [], None
        count, total = 0, 0

        def record(value):
            raw = json.dumps(value, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode()
            fingerprint.update(len(raw).to_bytes(8, 'big'))
            fingerprint.update(raw)

        def names(path, maximum):
            result = []
            for item in path.iterdir():
                _require(len(result) < maximum, 'Native audit closure file budget exceeded')
                result.append(item.name)
            return sorted(result)

        def reserve(info):
            nonlocal count, total
            count += 1
            _require(count <= self.budgets['max_files'], 'Native audit closure file budget exceeded')
            if stat.S_ISREG(info.st_mode):
                total += info.st_size
                _require(0 <= info.st_size <= self.budgets['max_bytes'] and
                         total <= self.budgets['max_bytes'], 'Native audit closure byte budget exceeded')

        def file(path, info, maximum=None, retain=False):
            _require(maximum is None or info.st_size <= maximum, 'Native audit source exceeds its role budget')
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            try:
                with os.fdopen(descriptor, 'rb') as stream:
                    descriptor = None
                    opened = os.fstat(stream.fileno())
                    _require(stat.S_ISREG(opened.st_mode) and _metadata(opened) == _metadata(info),
                             'Native audit file changed before reading')
                    digest, consumed, retained = hashlib.sha256(), 0, []
                    while chunk := stream.read(1024 * 1024):
                        consumed += len(chunk)
                        self._metrics['rehashed_bytes'] += len(chunk)
                        _require(consumed <= info.st_size, 'Native audit file grew while hashing')
                        digest.update(chunk)
                        if retain:
                            retained.append(chunk)
                    _require(consumed == info.st_size and _metadata(os.fstat(stream.fileno())) == _metadata(info),
                             'Native audit file changed while hashing')
                _require(_metadata(path.lstat()) == _metadata(info), 'Native audit file was replaced while hashing')
                return digest.hexdigest(), b''.join(retained) if retain else None
            finally:
                if descriptor is not None:
                    os.close(descriptor)

        def visit(path):
            nonlocal summary_raw
            info = path.lstat()
            reserve(info)
            checked_entries.append((path, _metadata(info)))
            name = path.relative_to(directory).as_posix()
            row = (name, _metadata(info))
            if stat.S_ISDIR(info.st_mode):
                children = names(path, self.budgets['max_files'] - count)
                record(row + ('directory', children, path.is_mount()))
                for name in children:
                    visit(path / name)
                _require(names(path, len(children)) == children and
                         _metadata(path.lstat()) == _metadata(info), 'Native audit directory changed while sealing')
            elif stat.S_ISREG(info.st_mode):
                retain = path == directory / 'summary.json'
                digest, raw = file(path, info, maximum=1024 * 1024 if retain else None, retain=retain)
                record(row + ('file', digest))
                if retain:
                    summary_raw = raw
            elif stat.S_ISLNK(info.st_mode):
                target = os.readlink(path)
                _require(_metadata(path.lstat()) == _metadata(info), 'Native audit symlink changed while sealing')
                record(row + ('symlink', target))
            else:
                raise RuntimeError('Unsupported native audit closure file type: ' + str(path))

        try:
            directory = _path(directory)
            _require(stat.S_ISDIR(directory.lstat().st_mode), 'Native audit worker is not a real directory')
            parents = _parent_identity(directory)
            visit(directory)
            _require(summary_raw is not None, 'Native audit worker lacks a regular summary')
            summary = json.loads(summary_raw, object_pairs_hook=_object, parse_constant=_nonfinite)
            _require(isinstance(summary, dict) and isinstance(summary.get('inputs'), dict) and
                     set(summary['inputs']) == set(self._limits), 'Native audit worker source inventory changed')
            parent_checks = [(directory, parents)]
            for role, maximum in sorted(self._limits.items()):
                identity = summary['inputs'][role]
                _require(isinstance(identity, dict) and set(identity) == {'path', 'sha256', 'size'} and
                         isinstance(identity['path'], str) and type(identity['size']) is int and
                         isinstance(identity['sha256'], str), 'Malformed native audit external source')
                path = _path(identity['path'])
                _require(not path.is_relative_to(directory) and not directory.is_relative_to(path),
                         'Native audit source overlaps its worker')
                parent_identity = _parent_identity(path)
                info = path.lstat()
                _require(stat.S_ISREG(info.st_mode), 'Native audit external source is not regular')
                reserve(info)
                checked_entries.append((path, _metadata(info)))
                digest, _ = file(path, info, maximum=maximum)
                _require(_parent_identity(_path(path)) == parent_identity,
                         'Native audit source parent identity changed while sealing')
                _require(identity['size'] == info.st_size and identity['sha256'] == digest,
                         'Native audit source differs from its recorded identity')
                access = (os.access(path, os.R_OK), os.access(path, os.X_OK))
                record(('external', role, str(path), _metadata(info), digest, parent_identity, access))
                parent_checks.append((path, parent_identity))
            # A file hashed early must remain the same through the complete
            # seal, including later source reads. ctime/inode checks detect
            # ordinary writes even when size and mtime are restored.
            _require(all(_metadata(path.lstat()) == identity for path, identity in checked_entries),
                     'Native audit closure changed before its complete seal finished')
            _require(all(_parent_identity(_path(path)) == identity for path, identity in parent_checks),
                     'Native audit parent identity changed while sealing')
            record(('parents', parents))
            return fingerprint.hexdigest()
        finally:
            self._metrics['seal_wall_ns'] += time.monotonic_ns() - started

    def audit(self, *, directory):
        self._metrics['audit_calls'] += 1
        try:
            self._check()
            path = _path(directory)
            key = str(path)
            entry = self._entries.get(key)
            if entry is None:
                _require(len(self._entries) < self.budgets['max_entries'], 'Native audit cache entry budget exceeded')
            before = self._seal(path)
            self._check()
            if entry is not None:
                if before != entry[0]:
                    self._metrics['changed_closures'] += 1
                    raise RuntimeError('Previously audited native worker closure changed')
                self._metrics['reuse_hits'] += 1
                return copy.deepcopy(entry[1])
            self._metrics['full_audit_calls'] += 1
            result = self._original(directory=directory)
            self._check()
            after = self._seal(path)
            self._check()
            if before != after:
                self._metrics['changed_closures'] += 1
                raise RuntimeError('Native worker closure changed during its first complete audit')
            _require(isinstance(result, dict) and result.get('status') == 'passed',
                     'Native auditor did not return a completed admitted worker')
            retained = copy.deepcopy(result)
            self._entries[key] = (after, retained)
            self._metrics['peak_entries'] = max(self._metrics['peak_entries'], len(self._entries))
            self._metrics['full_audits'] += 1
            return copy.deepcopy(retained)
        except BaseException:
            self._metrics['failures'] += 1
            raise

    def summary(self):
        return dict(schema=1, profile=PROFILE, active=self.active,
            entries=len(self._entries), budgets=dict(self.budgets), **self._metrics,
            reuse_scope='single_control_thread_fresh_complete_content_and_metadata_seals',
            persistence='NONE', stat_only_reuse=False, guest_execution=False,
            SMT_execution=False, protected_control_channel=False,
            independent_final_full_audit_required=True,
            code_sources={path: value[1] for path, value in (self._code or {}).items()})
