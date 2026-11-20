import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import struct
import subprocess
import sys
import threading
import time

PROFILE = 'afl-storage-v1'
MIB = 1024**2
RESERVE = '.storage-reserve'
NOTICE = struct.Struct('!8sI32s')
NOTICE_MAGIC = b'TFSTORE1'
USAGE_CATEGORIES = ('artifact_bytes', 'log_bytes', 'rootfs_bytes', 'preparation_bytes')
USAGE_KEYS = {*USAGE_CATEGORIES, 'allocated_bytes', 'files', 'skipped_mounts', 'total_bytes'}


def notify(root, record):
    data = json.dumps(record, sort_keys=True).encode()
    if len(data) > 3000 or record.get('category') != 'storage_limit':
        raise ValueError('Invalid storage failure notice')
    fd = os.open(Path(root)/RESERVE, os.O_WRONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size < 4096:
            raise ValueError('Invalid storage reserve')
        fcntl.flock(fd, fcntl.LOCK_EX)
        if os.pwrite(fd, data, NOTICE.size) != len(data):
            raise OSError(errno.EIO, 'Incomplete storage notice')
        header = NOTICE.pack(NOTICE_MAGIC, len(data), hashlib.sha256(data).digest())
        if os.pwrite(fd, header, 0) != len(header):
            raise OSError(errno.EIO, 'Incomplete storage notice header')
        os.fsync(fd)
    finally:
        os.close(fd)


def read_notice(fd):
    fcntl.flock(fd, fcntl.LOCK_SH)
    try:
        header = os.pread(fd, NOTICE.size, 0)
        if len(header) != NOTICE.size or not header.startswith(NOTICE_MAGIC):
            return None
        _, size, expected = NOTICE.unpack(header)
        if not 0 < size <= 3000:
            raise ValueError('Invalid storage notice size')
        data = os.pread(fd, size, NOTICE.size)
        if hashlib.sha256(data).digest() != expected:
            raise ValueError('Storage notice changed')
        value = json.loads(data)
        if not isinstance(value, dict) or value.get('category') != 'storage_limit' or not isinstance(value.get('reason'), str):
            raise ValueError('Invalid storage notice')
        return value
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)


class ResourceLimit(RuntimeError):
    def __init__(self, reason, **details):
        self.record = {'category': 'storage_limit', 'reason': reason, **details}
        super().__init__('Storage limit: '+reason)


def policy(artifact_mib=10240, log_mib=256, rootfs_mib=10240,
           case_mib=32, reserve_mib=16, min_free_mib=64, preparation_mib=4096):
    values = dict(artifact_bytes=artifact_mib, log_bytes=log_mib, rootfs_bytes=rootfs_mib,
                  case_bytes=case_mib, reserve_bytes=reserve_mib, min_free_bytes=min_free_mib,
                  preparation_bytes=preparation_mib)
    if any(type(n) is not int or not 1 <= n <= 1048576 for n in values.values()):
        raise ValueError('Invalid storage budget')
    return {'profile': PROFILE, **{key: n*MIB for key, n in values.items()}}


def validate(value):
    keys = set(policy())
    if not isinstance(value, dict) or set(value) != keys or value.get('profile') != PROFILE:
        raise ValueError('Invalid storage policy')
    for name in keys-{'profile'}:
        n = value[name]
        if type(n) is not int or n % MIB or not MIB <= n <= 1048576*MIB:
            raise ValueError('Invalid storage budget: '+name)
    return dict(value)


def digest(value):
    return hashlib.sha256(json.dumps(validate(value), sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def verify_manifest(manifest):
    if 'storage' not in manifest:
        if 'storage' in manifest.get('warm', {}):
            raise ValueError('Missing campaign storage policy')
        return None
    value = validate(manifest['storage'])
    if manifest.get('storage_policy_sha256') != digest(value):
        raise ValueError('Campaign storage policy changed')
    if 'warm' in manifest and manifest['warm'].get('storage') != value:
        raise ValueError('Warm storage policy differs from its campaign')
    return value


def bind(manifest, value):
    value = validate(value)
    manifest.update(storage=value, storage_policy_sha256=digest(value))
    if 'warm' in manifest:
        manifest['warm'] = manifest['warm'] | {'storage': value}


def limits(manifest, **overrides):
    value = verify_manifest(manifest) or policy()
    for name, number in overrides.items():
        if number is not None:
            if type(number) is not int or not 1 <= number <= 1048576:
                raise ValueError('Invalid storage budget: '+name)
            value[name] = number*MIB
    return validate(value)


def _mounts(root):
    result = set()
    for line in Path('/proc/self/mountinfo').read_text().splitlines():
        fields = line.split()
        import re
        point = Path(re.sub(r'\\([0-7]{3})', lambda m: chr(int(m[1], 8)), fields[4]))
        if point != root and point.is_relative_to(root):
            result.add(point)
    return result


def _directory_fd(root_fd, parts):
    fd = os.dup(root_fd)
    try:
        for part in parts:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def usage(root, *, heartbeat=None):
    root = Path(root).resolve(strict=True)
    mounts = {os.fspath(p) for p in _mounts(root)}
    directories, hardlinks = set(), set()
    totals = dict(artifact_bytes=0, log_bytes=0, rootfs_bytes=0, preparation_bytes=0,
                  allocated_bytes=0, files=0, skipped_mounts=0)
    entries_seen = 0
    stack = [()]
    root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        while stack:
            if heartbeat is not None:
                heartbeat()
            prefix = stack.pop()
            if os.fspath(root.joinpath(*prefix)) in mounts:
                totals['skipped_mounts'] += 1
                continue
            try:
                fd = _directory_fd(root_fd, prefix)
            except OSError as exc:
                if exc.errno in {errno.ENOENT, errno.ENOTDIR, errno.ELOOP}:
                    continue
                raise
            try:
                with os.scandir(fd) as items:
                    for item in items:
                        entries_seen += 1
                        if heartbeat is not None and entries_seen % 128 == 0:
                            heartbeat()
                        if not prefix and item.name == RESERVE:
                            continue
                        try:
                            info = item.stat(follow_symlinks=False)
                        except FileNotFoundError:
                            continue
                        identity = (info.st_dev, info.st_ino)
                        if stat.S_ISDIR(info.st_mode):
                            if identity in directories:
                                continue
                            directories.add(identity)
                            stack.append(prefix+(item.name,))
                            continue
                        if not stat.S_ISREG(info.st_mode):
                            continue
                        if info.st_nlink > 1:
                            if identity in hardlinks:
                                continue
                            hardlinks.add(identity)
                        if 'rootfs' in prefix or (prefix and prefix[0] in {'baseline-snapshots', 'warm-snapshots', 'checkpoint-rootfs'}):
                            category = 'rootfs_bytes'
                        elif prefix and prefix[0] in {'cases', 'findings', 'afl', 'objects'}:
                            category = 'artifact_bytes'
                        elif 'phase1' in prefix or 'retirement-evidence' in prefix or ('phase1-retirement' in prefix and 'export' in prefix):
                            category = 'preparation_bytes'
                        elif 'logs' in prefix or item.name.endswith(('.log', '.jsonl')):
                            category = 'log_bytes'
                        else:
                            category = 'preparation_bytes'
                        totals[category] += info.st_size
                        totals['allocated_bytes'] += info.st_blocks*512
                        totals['files'] += 1
            finally:
                os.close(fd)
    finally:
        os.close(root_fd)
    totals['total_bytes'] = sum(totals[name] for name in USAGE_CATEGORIES)
    return totals


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate storage measurement key: '+key)
        result[key] = value
    return result


def privileged_usage(root):
    root = Path(root).resolve(strict=True)
    identity = root.stat()
    command = ['sudo', '-n', '--', sys.executable, '-I', str(Path(__file__).resolve()), '--measure', str(root)]
    try:
        process = subprocess.run(command, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError('Private campaign storage measurement failed: '+str(exc)) from exc
    if process.returncode != 0:
        raise RuntimeError('Private campaign storage measurement failed: '+process.stderr[-1024:].strip())
    try:
        if len(process.stdout) > 8192:
            raise ValueError('Oversized storage measurement')
        record = json.loads(process.stdout, object_pairs_hook=_unique_pairs)
        if not isinstance(record, dict) or set(record) != {'schema', 'root', 'identity', 'usage'}:
            raise ValueError('Invalid storage measurement fields')
        current = root.stat()
        expected = [identity.st_dev, identity.st_ino]
        if (type(record['schema']) is not int or record['schema'] != 1 or record['root'] != str(root)
                or type(record['identity']) is not list or any(type(n) is not int for n in record['identity'])
                or record['identity'] != expected or [current.st_dev, current.st_ino] != expected):
            raise ValueError('Storage measurement root changed')
        value = record['usage']
        if (not isinstance(value, dict) or set(value) != USAGE_KEYS
                or any(type(n) is not int or n < 0 for n in value.values())
                or value['total_bytes'] != sum(value[name] for name in USAGE_CATEGORIES)):
            raise ValueError('Invalid storage measurement totals')
        return value
    except (ValueError, TypeError, KeyError) as exc:
        raise RuntimeError('Invalid private campaign storage measurement: '+str(exc)) from exc


def case_bytes(case):
    total = 0
    for directory, names, files in os.walk(case, followlinks=False):
        names[:] = [n for n in names if not (Path(directory)/n).is_symlink() and n != 'rootfs']
        for name in files:
            try:
                info = (Path(directory)/name).lstat()
            except FileNotFoundError:
                continue
            if stat.S_ISREG(info.st_mode):
                total += info.st_size
    return total


def check_project_write(path, size):
    path = Path(path).absolute()
    for case in path.parents:
        if case.parent.name == 'cases' and len(case.name) == 8 and case.name.isdecimal():
            manifest = case.parent.parent/'campaign.json'
            if not manifest.is_file():
                return
            from .phase1_runtime import read_json
            value = verify_manifest(read_json(manifest))
            if value is not None and case_bytes(case)+size > value['case_bytes']:
                raise ResourceLimit('case_bytes', case=case.name, limit=value['case_bytes'])
            return


class _ScanCancelled(Exception):
    pass


class Budget:
    def __init__(self, root, value, *, allow_privileged=False):
        self.root = Path(root).resolve(strict=True)
        self.policy = validate(value)
        self.lock = threading.RLock()
        self.changed = threading.Condition(self.lock)
        self.pending = set()
        self.reason = None
        self.last_sample = float('-inf')
        self.sample = None
        self.extra_artifact_bytes = 0
        self.reserve_fd = None
        self.reserve_identity = None
        self.completed_bytes_total = 0
        self.monitor = None
        self.monitor_stop = threading.Event()
        self.monitor_error = None
        self.monitor_used = False
        self.maximum_scan_seconds = 0.0
        self.last_progress = time.monotonic()
        self.cancelled_scans = 0
        self.allow_privileged = allow_privileged
        self.privileged_measurement = False

    def measure(self, *, heartbeat=None):
        if not self.privileged_measurement:
            try:
                return usage(self.root, heartbeat=heartbeat) if heartbeat is not None else usage(self.root)
            except PermissionError:
                if not self.allow_privileged:
                    raise
        if heartbeat is not None:
            heartbeat()
        value = privileged_usage(self.root)
        self.privileged_measurement = True
        if heartbeat is not None:
            heartbeat()
        return value

    def open(self):
        self.check(force=True)
        fd = os.open(self.root/RESERVE, os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        self.reserve_fd = fd
        info = os.fstat(fd)
        self.reserve_identity = info.st_dev, info.st_ino
        try:
            os.posix_fallocate(fd, 0, self.policy['reserve_bytes'])
            os.fsync(fd)
            self.check(force=True)
        except BaseException:
            self.release_reserve()
            raise

    def release_reserve(self):
        with self.lock:
            if self.reserve_fd is None:
                return
            fd = self.reserve_fd
            notice_error = None
            try:
                try:
                    notice = read_notice(fd)
                    if self.reason is None and notice is not None:
                        self.reason = notice
                except (OSError, ValueError) as exc:
                    notice_error = exc
                info = (self.root/RESERVE).lstat()
                if (info.st_dev, info.st_ino) != self.reserve_identity:
                    raise RuntimeError('Storage reserve was replaced')
                (self.root/RESERVE).unlink()
                if notice_error is not None:
                    raise notice_error
            finally:
                self.reserve_fd = None
                os.close(fd)

    def stop(self, record):
        with self.lock:
            if self.reason is None:
                self.reason = dict(record)
            self.release_reserve()
            self.changed.notify_all()
            return self.reason

    def start_monitor(self, *, interval=1.0):
        if not 0 < interval <= 1:
            raise ValueError('Invalid storage monitoring interval')
        with self.lock:
            if self.monitor is not None or self.sample is None:
                raise RuntimeError('Storage monitor requires one initialized budget')
            self.monitor_stop.clear()
            self.last_progress = time.monotonic()
            self.monitor_used = True
            self.monitor = threading.Thread(target=self._monitor, args=(interval,),
                                            name='tf-storage-monitor', daemon=True)
            try:
                self.monitor.start()
            except BaseException:
                self.monitor = None
                raise

    def _heartbeat(self):
        if self.monitor_stop.is_set():
            raise _ScanCancelled()
        with self.lock:
            self.last_progress = time.monotonic()

    def _monitor(self, interval):
        while not self.monitor_stop.wait(interval):
            try:
                with self.lock:
                    watermark = self.completed_bytes_total
                started = time.monotonic()
                sampled = self.measure(heartbeat=self._heartbeat)
                with self.lock:
                    self.sample = sampled
                    self.last_sample = time.monotonic()
                    self.maximum_scan_seconds = max(self.maximum_scan_seconds, self.last_sample-started)
                    # A completion may already be included in sampled; overlap
                    # remains conservative until the next reconciliation.
                    self.extra_artifact_bytes = self.completed_bytes_total-watermark
                    self.changed.notify_all()
                self.check()
            except _ScanCancelled:
                with self.lock:
                    self.cancelled_scans += 1
                return
            except Exception as exc:
                limited = exc if isinstance(exc, ResourceLimit) else from_oserror(exc)
                try:
                    if limited is not None:
                        self.stop(limited.record)
                    else:
                        with self.lock:
                            self.monitor_error = exc
                            self.changed.notify_all()
                except Exception as error:
                    with self.lock:
                        self.monitor_error = error
                        self.changed.notify_all()
                return

    def stop_monitor(self):
        self.monitor_stop.set()
        thread = self.monitor
        if thread is not None:
            thread.join(35 if self.allow_privileged else 30)
            if thread.is_alive():
                raise RuntimeError('Storage monitor did not stop')
            self.monitor = None

    def check(self, *, force=False):
        with self.lock:
            if self.reserve_fd is not None:
                notice = read_notice(self.reserve_fd)
                if notice is not None:
                    self.stop(notice)
            if self.monitor_error is not None:
                raise RuntimeError('Storage monitor failed: '+str(self.monitor_error)) from self.monitor_error
            if self.reason is not None:
                raise ResourceLimit(self.reason['reason'], **{k: v for k, v in self.reason.items()
                                                             if k not in {'reason', 'category'}})
            now = time.monotonic()
            # A sudo scan has its own 30-second subprocess deadline; allow
            # a small margin for timeout handling before the progress watchdog.
            watchdog = 35 if self.allow_privileged else 30
            if self.monitor is not None and now-self.last_progress > watchdog:
                raise RuntimeError('Storage monitor made no progress within '+str(watchdog)+' seconds')
            if force or (self.monitor is None and now-self.last_sample >= 1):
                self.sample = self.measure()
                self.last_sample = time.monotonic()
                self.extra_artifact_bytes = 0
            space = os.statvfs(self.root)
            free = space.f_bavail*space.f_frsize
            sample = self.sample | {'artifact_bytes': self.sample['artifact_bytes']+self.extra_artifact_bytes}
            for name in ('artifact_bytes', 'log_bytes', 'rootfs_bytes', 'preparation_bytes'):
                if sample[name] >= self.policy[name]:
                    raise ResourceLimit(name, observed=sample[name], limit=self.policy[name])
            if free < self.policy['min_free_bytes']:
                raise ResourceLimit('free_space', available=free, minimum=self.policy['min_free_bytes'])
            return sample

    def admit(self, index, *, stop=None):
        with self.lock:
            while True:
                if stop is not None and stop.is_set():
                    raise ConnectionError('Campaign stopped while reserving storage')
                current = self.check()
                amount = self.policy['case_bytes']
                reserved = (len(self.pending)+1)*amount
                space = os.statvfs(self.root)
                free = space.f_bavail*space.f_frsize
                if current['artifact_bytes']+reserved <= self.policy['artifact_bytes'] and free >= self.policy['min_free_bytes']+reserved:
                    break
                if (stop is not None and self.pending and current['artifact_bytes']+amount <= self.policy['artifact_bytes']
                        and free >= self.policy['min_free_bytes']+amount):
                    self.changed.wait(.1)
                    continue
                if current['artifact_bytes']+reserved > self.policy['artifact_bytes']:
                    raise ResourceLimit('case_reservation', observed=current['artifact_bytes'],
                                        reserved=reserved, limit=self.policy['artifact_bytes'])
                raise ResourceLimit('free_space_reservation', available=free, reserved=reserved,
                                    minimum=self.policy['min_free_bytes'])
            self.pending.add(index)

    def complete(self, case):
        with self.lock:
            size = case_bytes(case)
            index = int(Path(case).name)
            if index in self.pending:
                self.extra_artifact_bytes += size
                self.completed_bytes_total += size
                self.pending.remove(index)
            self.changed.notify_all()
            if size > self.policy['case_bytes']:
                self.stop(ResourceLimit('case_bytes', case=Path(case).name, observed=size,
                                        limit=self.policy['case_bytes']).record)

    def report(self):
        self.stop_monitor()
        with self.lock:
            return {'profile': PROFILE, 'policy': self.policy, 'policy_sha256': digest(self.policy),
                    'usage': self.measure(), 'stop': self.reason,
                    'pending_reservations': len(self.pending),
                    'enforcement': 'case_admission_and_monitoring', 'filesystem_quota': False,
                    'asynchronous_campaign_monitor': self.monitor_used,
                    'maximum_scan_seconds': self.maximum_scan_seconds, 'cancelled_scans': self.cancelled_scans,
                    'monitor_error': str(self.monitor_error) if self.monitor_error is not None else None,
                    'measurement_backend': 'sudo_read_only' if self.privileged_measurement else 'local',
                    'poll_seconds': 1, 'reserve_released': self.reserve_fd is None and not (self.root/RESERVE).exists()}


def from_oserror(exc):
    if isinstance(exc, OSError) and exc.errno in {errno.ENOSPC, errno.EDQUOT, errno.EFBIG}:
        return ResourceLimit('write_failed', errno=exc.errno)
    return None


def copy_file(source, destination):
    source, destination = Path(source), Path(destination)
    created = False
    try:
        with source.open('rb') as src, destination.open('xb') as dst:
            created = True
            try:
                fcntl.ioctl(dst.fileno(), 0x40049409, src.fileno())
            except OSError as exc:
                if exc.errno not in {errno.EOPNOTSUPP, errno.ENOTTY, errno.EXDEV, errno.EINVAL, errno.ENOSYS}:
                    raise
                shutil.copyfileobj(src, dst, length=MIB)
        shutil.copystat(source, destination, follow_symlinks=False)
    except BaseException:
        if created and destination.is_file() and not destination.is_symlink():
            destination.unlink()
        raise


def measurement(root):
    root = Path(root).resolve(strict=True)
    before = root.stat()
    caller = os.environ.get('SUDO_UID')
    if os.geteuid() == 0 and caller is not None and before.st_uid != int(caller):
        raise ValueError('Campaign root does not belong to the invoking user')
    value = usage(root)
    after = root.stat()
    if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
        raise ValueError('Campaign root changed during measurement')
    return {'schema': 1, 'root': str(root), 'identity': [before.st_dev, before.st_ino], 'usage': value}


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--measure', type=Path, required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(measurement(args.measure), sort_keys=True))
    except (OSError, ValueError) as exc:
        parser.exit(2, str(exc)+'\n')


if __name__ == '__main__':
    main()
