"""Optional content-checked reuse of completed DTA handoff publications.

Every reuse freshly hashes the complete saved analysis. This is a bounded,
single-threaded controlled-run optimization, not an atomic evidence snapshot.
An accepting caller must close all audit sessions and run a full uncached audit.
"""
from __future__ import annotations

import copy
import hashlib
import inspect
import json
import os
from pathlib import Path
import shutil
import stat
import tempfile
import threading
import time

from scripts import dta_dse_audit_cache as native
from taintforge_env import dta_handoff, dta_dse, dta_dse_queue, dta_dse_eval
from taintforge_env.dta_corpus import _canonical, _limit
from taintforge_env.elf_runtime import canonical_hash


PROFILE = 'content-checked-DTA-handoff-session-v1'
PROJECT = Path(__file__).resolve().parents[1]
_ACTIVE_HANDOFF_SESSION = None
_require = native._require
_metadata = native._metadata
_path = native._path
_parent_identity = native._parent_identity


def _bindings():
    return tuple((owner, 'export_handoff') for owner in
                 (dta_handoff, dta_dse, dta_dse_queue, dta_dse_eval))


def _parse(raw):
    value = json.loads(raw, object_pairs_hook=native._object, parse_constant=native._nonfinite)
    _require(isinstance(value, dict), 'Handoff publication must contain a JSON object')
    return value


class DtaHandoffSession(native.NativeAuditSession):
    """Recheck complete analysis bytes before copying an admitted publication.

    The original handoff auditor reads only the saved analysis. Historical
    external input paths are deliberately not reopened by this cache.
    """

    def __init__(self, *, max_entries=128, max_files=65536, max_bytes=4 * 1024**3,
                 max_output_bytes=32 * 1024**2, max_entry_bytes=8 * 1024**2):
        super().__init__(max_entries=max_entries, max_files=max_files, max_bytes=max_bytes)
        for value, maximum in ((max_output_bytes, 256 * 1024**2), (max_entry_bytes, 32 * 1024**2)):
            _require(type(value) is int and 1 <= value <= maximum, 'Invalid retained handoff byte budget')
        self.budgets.update(max_output_bytes=max_output_bytes, max_entry_bytes=max_entry_bytes)
        self._originals = None
        self._metrics.update(publication_wall_ns=0, retained_output_bytes=0, admitted_entries=0)

    def _code_identity(self):
        # Reuse the tested code-inventory checker without its native auditor
        # binding or session installation. Both session types may coexist.
        result = super()._code_identity()
        path = _path(Path(__file__))
        info = path.lstat()
        _require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= 4 * 1024**2,
                 'Unsafe handoff cache implementation source')
        raw = path.read_bytes()
        _require(_metadata(path.lstat()) == _metadata(info), 'Handoff implementation changed while reading')
        result[str(path)] = (_metadata(info), hashlib.sha256(raw).hexdigest())
        _require(all(_metadata(_path(source).lstat()) == identity[0] for source, identity in result.items()),
                 'Handoff implementation changed before its complete inventory was sealed')
        return result

    def __enter__(self):
        global _ACTIVE_HANDOFF_SESSION
        _require(_ACTIVE_HANDOFF_SESSION is None and not self.active and not self._used,
                 'Nested or reused handoff sessions are unsupported')
        self._thread = threading.get_ident()
        self._credentials = self._credential_identity()
        originals = [(owner, name, getattr(owner, name)) for owner, name in _bindings()]
        self._original = originals[0][2]
        self._original_code = getattr(self._original, '__code__', None)
        _require(self._original_code is not None and all(function is self._original for _, _, function in originals),
                 'Handoff aliases must share the original Python auditor before installation')
        self._originals = originals
        self._code = self._code_identity()
        self._installed = self.export
        self.active = self._used = True
        _ACTIVE_HANDOFF_SESSION = self
        for owner, name, _ in originals:
            setattr(owner, name, self._installed)
        return self

    def __exit__(self, kind, exception, traceback):
        global _ACTIVE_HANDOFF_SESSION
        for owner, name, original in self._originals:
            setattr(owner, name, original)
        self.active = False
        _ACTIVE_HANDOFF_SESSION = None
        self._entries.clear()
        return False

    def _check(self):
        _require(self.active and _ACTIVE_HANDOFF_SESSION is self and threading.get_ident() == self._thread,
                 'Handoff reuse requires its active original control thread')
        _require(self._credential_identity() == self._credentials, 'Handoff control credentials changed')
        _require(getattr(self._original, '__code__', None) is self._original_code and
                 all(inspect.unwrap(getattr(owner, name)) == self._installed for owner, name, _ in self._originals),
                 'Handoff auditor binding or implementation changed')
        started = time.monotonic_ns()
        try:
            _require(self._code_identity() == self._code, 'Handoff analysis implementation inventory changed')
        finally:
            self._metrics['code_check_wall_ns'] += time.monotonic_ns() - started

    def _seal(self, directory):
        started = time.monotonic_ns()
        self._metrics['seal_calls'] += 1
        fingerprint, checked = hashlib.sha256(), []
        count, total = 0, 0

        def record(value):
            raw = json.dumps(value, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode()
            fingerprint.update(len(raw).to_bytes(8, 'big'))
            fingerprint.update(raw)

        def names(path, maximum):
            values = []
            for item in path.iterdir():
                _require(len(values) < maximum, 'Handoff analysis file budget exceeded')
                values.append(item.name)
            return sorted(values)

        def visit(path):
            nonlocal count, total
            info = path.lstat()
            count += 1
            _require(count <= self.budgets['max_files'], 'Handoff analysis file budget exceeded')
            checked.append((path, _metadata(info)))
            row = (path.relative_to(directory).as_posix(), _metadata(info),
                   os.access(path, os.R_OK), os.access(path, os.X_OK))
            if stat.S_ISDIR(info.st_mode):
                children = names(path, self.budgets['max_files'] - count)
                record(row + ('directory', children, path.is_mount()))
                for name in children:
                    visit(path / name)
                _require(names(path, len(children)) == children and _metadata(path.lstat()) == _metadata(info),
                         'Handoff directory changed while sealing')
            elif stat.S_ISREG(info.st_mode):
                total += info.st_size
                _require(0 <= info.st_size <= self.budgets['max_bytes'] and total <= self.budgets['max_bytes'],
                         'Handoff analysis byte budget exceeded')
                descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                try:
                    with os.fdopen(descriptor, 'rb') as stream:
                        descriptor = None
                        _require(_metadata(os.fstat(stream.fileno())) == _metadata(info),
                                 'Handoff file changed before reading')
                        digest, consumed = hashlib.sha256(), 0
                        while chunk := stream.read(1024 * 1024):
                            consumed += len(chunk)
                            self._metrics['rehashed_bytes'] += len(chunk)
                            _require(consumed <= info.st_size, 'Handoff file grew while hashing')
                            digest.update(chunk)
                        _require(consumed == info.st_size and _metadata(os.fstat(stream.fileno())) == _metadata(info),
                                 'Handoff file changed while hashing')
                    _require(_metadata(path.lstat()) == _metadata(info), 'Handoff file was replaced while hashing')
                    record(row + ('file', digest.hexdigest()))
                finally:
                    if descriptor is not None:
                        os.close(descriptor)
            elif stat.S_ISLNK(info.st_mode):
                target = os.readlink(path)
                _require(_metadata(path.lstat()) == _metadata(info), 'Handoff symlink changed while sealing')
                record(row + ('symlink', target))
            else:
                raise RuntimeError('Unsupported handoff analysis file type: ' + str(path))

        try:
            directory = _path(directory)
            _require(stat.S_ISDIR(directory.lstat().st_mode), 'Saved DTA analysis is not a real directory')
            parents = _parent_identity(directory)
            visit(directory)
            _require(all(_metadata(path.lstat()) == identity for path, identity in checked),
                     'Handoff analysis changed before its complete seal finished')
            _require(_parent_identity(_path(directory)) == parents, 'Handoff analysis parent identity changed')
            record(('parents', parents))
            return fingerprint.hexdigest()
        finally:
            self._metrics['seal_wall_ns'] += time.monotonic_ns() - started

    def _publication(self, out, result, max_sites):
        def names(path, maximum):
            values = []
            for item in path.iterdir():
                _require(len(values) < maximum, 'Original handoff publication inventory is oversized')
                values.append(item.name)
            return sorted(values)

        _require(names(out, 3) == ['manifest.json', 'recapture-requests.json', 'seeds'],
                 'Unexpected original handoff publication inventory')
        _require(isinstance(result, dict) and result.get('status') == 'AUDITED_DTA_CORPUS_AND_RECAPTURE_HINTS' and
                 result.get('dse_status') == 'NOT_RUN' and result.get('afl_campaign_executed') is False and
                 result.get('universal_equivalence') is False and result.get('protected_diagnostic_channel') is False and
                 result.get('historical_isolation_independently_reexecuted') is False and
                 result.get('audit_scope') == 'offline_artifact_consistency_not_independent_runtime_reverification',
                 'Original handoff audit is incomplete or promoted its scope')
        files, total = {}, 0

        def read(path):
            nonlocal total
            path = _canonical(path)
            info = path.lstat()
            _require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and
                     0 <= info.st_size <= self.budgets['max_entry_bytes'], 'Unsafe handoff publication file')
            total += info.st_size
            _require(total <= self.budgets['max_entry_bytes'], 'Retained handoff entry byte budget exceeded')
            raw = path.read_bytes()
            _require(len(raw) == info.st_size and _metadata(path.lstat()) == _metadata(info),
                     'Original handoff publication changed while reading')
            files[path.relative_to(out).as_posix()] = raw
            return raw

        manifest = _parse(read(out / 'manifest.json'))
        requests = _parse(read(out / 'recapture-requests.json'))
        _require(canonical_hash(manifest) == canonical_hash(result) and
                 type(requests.get('schema')) is int and requests['schema'] == 1 and isinstance(requests.get('requests'), list) and
                 len(requests['requests']) <= max_sites, 'Original handoff documents differ from their admission')
        _require(type(result.get('recapture_sites')) is int and result['recapture_sites'] == len(requests['requests']) and
                 type(result.get('sites_with_unseen_opposite')) is int and result['sites_with_unseen_opposite'] ==
                 sum(request.get('opposite_observed_elsewhere') is False for request in requests['requests']),
                 'Original handoff request counts differ from their inventory')
        identifiers = set()
        for request in requests['requests']:
            _require(isinstance(request, dict) and request.get('kind') == 'DTA_SITE_RECAPTURE_REQUEST' and
                     request.get('status') == 'NEEDS_FRESH_IR_AND_FLAGS' and request.get('dse_eligible') is False and
                     request.get('solver_executed') is False and request.get('executable_selector') is None and
                     request.get('ir_origin') is None and request.get('instruction_bytes') is None and
                     request.get('exact_instruction_generation') is None and
                     request.get('protected_diagnostic_channel') is False and
                     type(request.get('opposite_observed_elsewhere')) is bool,
                     'Original handoff hint promoted its authority')
            identifier = request.get('request_id')
            _require(isinstance(identifier, str) and identifier not in identifiers and identifier == canonical_hash(
                     {key: value for key, value in request.items() if key != 'request_id'}),
                     'Original handoff request identity changed')
            identifiers.add(identifier)
        seeds = _canonical(out / 'seeds')
        accepted = result.get('accepted_seeds')
        _require(seeds.is_dir() and isinstance(accepted, list) and len(accepted) <= 128,
                 'Malformed original handoff accepted seed inventory')
        expected = [row['sha256'] for row in accepted]
        _require(len(expected) == len(set(expected)) and names(seeds, 128) == sorted(expected),
                 'Original handoff seed inventory changed')
        for name in expected:
            _require(isinstance(name, str) and len(name) == 64 and all(c in '0123456789abcdef' for c in name),
                     'Malformed original handoff seed identity')
            raw = read(seeds / name)
            _require(0 < len(raw) <= 4096 and hashlib.sha256(raw).hexdigest() == name,
                     'Original handoff accepted seed changed')
        return files, total

    def _publish(self, *, analysis, out, expected, files):
        started = time.monotonic_ns()
        staging = None
        try:
            _canonical(out)
            _require(not out.exists(), 'Handoff output is already occupied')
            out.parent.mkdir(parents=True, exist_ok=True)
            _path(out.parent)
            staging = Path(tempfile.mkdtemp(prefix='.tf-dta-handoff-', dir=out.parent))
            (staging / 'seeds').mkdir()
            for name, raw in sorted(files.items()):
                (staging / name).write_bytes(raw)
            self._check()
            _require(self._seal(analysis) == expected, 'DTA analysis changed during handoff publication')
            _canonical(out)
            _require(not out.exists(), 'Handoff output appeared during publication')
            staging.rename(out)
            staging = None
        finally:
            if staging is not None and staging.exists():
                shutil.rmtree(staging)
            self._metrics['publication_wall_ns'] += time.monotonic_ns() - started

    def export(self, *, analysis, out, max_sites=256):
        self._metrics['audit_calls'] += 1
        try:
            _limit(max_sites, 4096, 'handoff sites')
            self._check()
            analysis, out = _canonical(analysis), _canonical(out)
            _require(analysis.is_dir() and not out.exists() and not out.is_relative_to(analysis) and
                     not analysis.is_relative_to(out), 'Handoff output must be new and outside the analysis')
            key = (str(analysis), max_sites)
            entry = self._entries.get(key)
            if entry is None:
                _require(len(self._entries) < self.budgets['max_entries'], 'Handoff cache entry budget exceeded')
            before = self._seal(analysis)
            self._check()
            if entry is not None:
                if before != entry['seal']:
                    self._metrics['changed_closures'] += 1
                    raise RuntimeError('Previously audited DTA analysis changed')
                self._publish(analysis=analysis, out=out, expected=before, files=entry['files'])
                self._metrics['reuse_hits'] += 1
                return copy.deepcopy(entry['result'])
            publications = []
            out.parent.mkdir(parents=True, exist_ok=True)
            _path(out.parent)
            with tempfile.TemporaryDirectory(prefix='.tf-handoff-cache-audit-', dir=out.parent) as temporary:
                for name in ('first', 'recheck'):
                    destination = Path(temporary) / name
                    self._metrics['full_audit_calls'] += 1
                    returned = self._original(analysis=analysis, out=destination, max_sites=max_sites)
                    _require(returned.get('analysis') == str(analysis), 'Original handoff described a foreign analysis')
                    files, retained_bytes = self._publication(destination, returned, max_sites)
                    self._metrics['full_audits'] += 1
                    publications.append((copy.deepcopy(returned), files, retained_bytes))
            result, files, retained_bytes = publications[0]
            _require(canonical_hash(result) == canonical_hash(publications[1][0]) and files == publications[1][1],
                     'Independent original handoff regenerations differ')
            self._check()
            after = self._seal(analysis)
            self._check()
            if before != after:
                self._metrics['changed_closures'] += 1
                raise RuntimeError('DTA analysis changed during its first complete handoff audit')
            _require(self._metrics['retained_output_bytes'] + retained_bytes <= self.budgets['max_output_bytes'],
                     'Retained handoff cache byte budget exceeded')
            self._publish(analysis=analysis, out=out, expected=after, files=files)
            self._entries[key] = dict(seal=after, files=files, result=copy.deepcopy(result))
            self._metrics['retained_output_bytes'] += retained_bytes
            self._metrics['peak_entries'] = max(self._metrics['peak_entries'], len(self._entries))
            self._metrics['admitted_entries'] += 1
            return copy.deepcopy(result)
        except BaseException:
            self._metrics['failures'] += 1
            raise

    def summary(self):
        return dict(schema=1, profile=PROFILE, active=self.active, entries=len(self._entries),
            budgets=dict(self.budgets), **self._metrics,
            reuse_scope='single_control_thread_fresh_complete_saved_DTA_analysis_content_seals',
            historical_external_input_paths_required=False, output_bytes_republished_exactly=True,
            persistence='NONE', stat_only_reuse=False, guest_execution=False, SMT_execution=False,
            protected_control_channel=False, independent_final_full_audit_required=True,
            code_sources={path: value[1] for path, value in (self._code or {}).items()})
