"""One attempt-wide network budget shared by local and namespace responders."""
from __future__ import annotations

import asyncio
from contextvars import ContextVar
from contextlib import contextmanager, nullcontext
import fcntl
from dataclasses import asdict, dataclass
import hashlib
import json
import math
import os
from pathlib import Path
import secrets
import signal
import stat
import sys
import tempfile
import threading
import time

from .network_owner_diagnostics import OwnerHeartbeatDiagnostics, OWNER_DIAGNOSTIC_FILE, bounded_record


class NetworkRuntimeError(RuntimeError):
    def __init__(self, *args, details=None):
        super().__init__(*args)
        self.details = details


@dataclass(frozen=True, slots=True)
class NetworkRuntimeLimits:
    max_received_bytes: int = 16 * 1024 * 1024
    max_sent_bytes: int = 16 * 1024 * 1024
    max_log_bytes: int = 8 * 1024 * 1024
    max_log_files: int = 4096
    max_connections: int = 32
    max_total_connections: int = 128
    max_pending: int = 64
    max_messages: int = 4096
    max_listeners: int = 128
    idle_timeout_ms: int = 5000
    connection_timeout_ms: int = 30000
    shutdown_timeout_ms: int = 5000

    @classmethod
    def parse(cls, raw=None):
        bounds = {"max_received_bytes": (1, 1024**3), "max_sent_bytes": (1, 1024**3),
                  "max_log_bytes": (4096, 32 * 1024**2), "max_log_files": (1, 65536),
                  "max_connections": (1, 256), "max_total_connections": (1, 65536),
                  "max_pending": (1, 256), "max_messages": (1, 100000),
                  "max_listeners": (1, 1024),
                  "idle_timeout_ms": (1, 60000), "connection_timeout_ms": (1, 300000),
                  "shutdown_timeout_ms": (100, 30000)}
        raw = {} if raw is None else raw
        if not isinstance(raw, dict) or set(raw) - bounds.keys():
            raise ValueError("invalid network runtime limit fields")
        values = {**asdict(cls()), **raw}
        for key, value in values.items():
            low, high = bounds[key]
            if type(value) is not int or not low <= value <= high:
                raise ValueError(f"network runtime {key} must be an integer in {low}..{high}")
        return cls(**values)

    @property
    def sha256(self):
        return hashlib.sha256(json.dumps(asdict(self), sort_keys=True, separators=(",", ":")).encode()).hexdigest()


_CURRENT = ContextVar("taintforge_network_runtime", default=None)
OWNER_HEARTBEAT_PROFILE = "owner-heartbeat-v1"
CONTROLLED_HEARTBEAT_PROFILE = "owner-heartbeat-v2"
OWNER_HEARTBEAT_PROFILES = {
    OWNER_HEARTBEAT_PROFILE: (1, 2),
    CONTROLLED_HEARTBEAT_PROFILE: (5, 5),
}
OWNER_HEARTBEAT_FILE = "owner-heartbeat.json"
OWNER_IDENTITY = ("owner_pid", "owner_start", "token", "attempt_id", "limits_sha256")
OWNER_STATUS_RECHECK_SECONDS = 0.05
OWNER_STATUS_CONFIRM_SECONDS = 0.15


def _confirmed_owner_status(descriptor):
    """Require a fresh status transaction after a transient stale observation."""
    started = first_age = None
    last_error = None
    attempts = 0
    for attempt in range(3):
        if started is not None and time.monotonic() - started >= OWNER_STATUS_CONFIRM_SECONDS:
            break
        attempts += 1
        try:
            result = ledger_transaction(descriptor, "status")
        except NetworkRuntimeError as exc:
            if (exc.details or {}).get("check") != "owner_heartbeat_stale":
                raise
            last_error = exc
            if started is None:
                started = time.monotonic()
                first_age = exc.details["age_seconds"]
        else:
            if (started is None or result["termination_reason"] is not None
                    or time.monotonic() - started < OWNER_STATUS_CONFIRM_SECONDS):
                return result
            break
        remaining = started + OWNER_STATUS_CONFIRM_SECONDS - time.monotonic()
        if attempt == 2 or remaining <= 0:
            break
        # Yield one publication interval. A second immediate read can see
        # the same pulse; it does not independently confirm owner failure.
        time.sleep(min(OWNER_STATUS_RECHECK_SECONDS, remaining))
        # Each retry rechecks PID/start, token, attempt and limits. No
        # cached snapshot or quota mutation is allowed during confirmation.
    last_error.details = {**last_error.details, "status_confirmation": {
        "attempts": attempts, "first_age_seconds": first_age,
        "elapsed_seconds": time.monotonic() - started,
        "max_seconds": OWNER_STATUS_CONFIRM_SECONDS}}
    raise last_error


def current_runtime():
    return _CURRENT.get()


def payload_scope(service):
    runtime = current_runtime()
    if runtime is None:
        return ""
    fields = [runtime.attempt_id, service.service_type, service.remote_ip, service.remote_port,
              service.bind_ip, service.bind_port, service.protocol_hint,
              proc_self(), process_start(proc_self())]
    return "_" + hashlib.sha256(json.dumps(fields, separators=(",", ":")).encode()).hexdigest()


def _regular(path, maximum=16384):
    path = Path(path).absolute()
    if any(item.is_symlink() for item in (path, *path.parents)):
        raise NetworkRuntimeError("network runtime path contains a symlink")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > maximum:
            raise NetworkRuntimeError("network runtime input must be a bounded regular file")
        data = stream.read(maximum + 1)
    if len(data) > maximum:
        raise NetworkRuntimeError("network runtime input is too large")
    return data


def _private_json(path, value, *, durable=True):
    """Publish private JSON while retaining an existing file's UID and GID."""
    path = Path(path)
    try:
        previous = path.lstat()
    except FileNotFoundError:
        previous = None
    if previous is not None and not stat.S_ISREG(previous.st_mode):
        raise NetworkRuntimeError("network runtime output must be a regular file")
    descriptor, temporary = tempfile.mkstemp(prefix=".network-state.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w") as stream:
            if previous is not None:
                os.fchown(stream.fileno(), previous.st_uid, previous.st_gid)
            os.fchmod(stream.fileno(), 0o600)
            json.dump(value, stream, sort_keys=True)
            stream.write("\n")
            stream.flush()
            if durable:
                os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


class NetworkRuntimeOwner:
    """Attempt-wide allocation ledger serialized with a private file lock."""
    def __init__(self, directory, logs_root, *, attempt_id, limits=None,
                 heartbeat_profile=OWNER_HEARTBEAT_PROFILE):
        if not isinstance(attempt_id, str) or not 1 <= len(attempt_id) <= 160:
            raise ValueError("invalid network runtime attempt identity")
        if type(heartbeat_profile) is not str or heartbeat_profile not in OWNER_HEARTBEAT_PROFILES:
            raise ValueError("unsupported network owner heartbeat profile")
        self.heartbeat_profile = heartbeat_profile
        self.directory, self.logs_root = Path(directory).absolute(), Path(logs_root).absolute()
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=False)
        self.logs_root.mkdir(parents=True, exist_ok=True)
        self.limits = limits or NetworkRuntimeLimits()
        self.attempt_id = attempt_id
        self.token = secrets.token_hex(32)
        self.client_path = self.directory / "client.json"
        self.status_path = self.logs_root / "network_runtime_status.json"
        self.lock = threading.RLock()
        self.reason = None
        self.closed = False
        self.peers, self.leases, self.files, self.listeners = {}, {}, set(), {}
        self.usage = dict(received_bytes=0, received_reserved=0, sent_bytes_reserved=0,
                          log_bytes_reserved=0, producer_log_bytes=0, log_files=0,
                          active_connections=0, peak_connections=0, total_connections=0,
                          active_jobs=0, peak_jobs=0, messages=0, rejected_connections=0, dropped_messages=0)
        self.footer_reserve = min(65536, max(2048, self.limits.max_log_bytes // 4))
        self.producer_limit = (self.limits.max_log_bytes - self.footer_reserve) // 2
        self.descriptor = {"schema_version": 1, "owner_pid": proc_self(),
            "owner_start": process_start(proc_self()), "token": self.token,
            "heartbeat_profile": self.heartbeat_profile,
            "attempt_id": self.attempt_id, "logs_root": str(self.logs_root),
            "directory": str(self.directory), "limits": asdict(self.limits), "limits_sha256": self.limits.sha256}
        self.owner_diagnostics = OwnerHeartbeatDiagnostics(attempt_id=self.attempt_id,
            owner_pid=self.descriptor["owner_pid"], owner_start=self.descriptor["owner_start"])
        # Create the owner's lock before privileged clients can read the descriptor.
        with ledger_lock(self.directory):
            _private_json(self.directory / "state.json", self._export(), durable=False)
            self._publish_heartbeat()
            _private_json(self.client_path, self.descriptor)
        self.stop_event = threading.Event()
        self.thread = threading.Thread(target=self._heartbeat, name="network-budget-owner", daemon=True)
        self.thread.start()

    def _export(self):
        value = {"token": self.token, "attempt_id": self.attempt_id, "reason": self.reason,
                "limits_sha256": self.limits.sha256,
                "peers": self.peers, "leases": self.leases, "files": sorted(self.files),
                "listeners": self.listeners,
                "usage": self.usage, "owner_last_seen": time.monotonic()}
        if getattr(self, "heartbeat_profile", OWNER_HEARTBEAT_PROFILE) != OWNER_HEARTBEAT_PROFILE:
            value["heartbeat_profile"] = self.heartbeat_profile
        return value

    def _snapshot(self):
        value = {"schema_version": 1, "attempt_id": self.attempt_id,
                "limits": asdict(self.limits), "limits_sha256": self.limits.sha256,
                "budget_usage": dict(self.usage), "producer_log_limit": self.producer_limit,
                "termination_reason": self.reason, "evidence_complete": self.reason is None,
                "owner_closed": self.closed,
                "ready_listeners": sum(process_alive(pid, birth) for pid, birth in self.listeners.values())}
        profile = getattr(self, "heartbeat_profile", OWNER_HEARTBEAT_PROFILE)
        if profile != OWNER_HEARTBEAT_PROFILE:
            owner_timeout, peer_timeout = OWNER_HEARTBEAT_PROFILES[profile]
            value["heartbeat"] = {"profile": profile, "owner_timeout_seconds": owner_timeout,
                                  "peer_timeout_seconds": peer_timeout}
        return value

    def _publish_heartbeat(self):
        self.owner_diagnostics.step("publishing")
        value = {"schema_version": 1, **{key: self.descriptor[key] for key in OWNER_IDENTITY},
                 "owner_last_seen": time.monotonic()}
        if self.heartbeat_profile != OWNER_HEARTBEAT_PROFILE:
            value["heartbeat_profile"] = self.heartbeat_profile
        _private_json(self.directory / OWNER_HEARTBEAT_FILE, value, durable=False)
        self.owner_diagnostics.last_pulse_timestamp = value["owner_last_seen"]
        self.owner_diagnostics.step("published")

    def _heartbeat(self):
        try:
            while True:
                self.owner_diagnostics.step("waiting")
                if self.stop_event.wait(0.05):
                    return
                try:
                    self.owner_diagnostics.step("checking_services")
                    callback = getattr(self, "health_check", None)
                    if callback is not None:
                        callback()
                    # Liveness must not wait behind quota transactions. Only this
                    # owner loop publishes the pulse, after checking its services.
                    self._publish_heartbeat()
                except (NetworkRuntimeError, OSError, ValueError) as error:
                    self.owner_diagnostics.failure(error)
                    self.owner_diagnostics.step("committing_failure")
                    try:
                        self.fail("network_runtime_owner_failed")
                    except (NetworkRuntimeError, OSError, ValueError) as error:
                        self.owner_diagnostics.failure(error)
                    return
        except BaseException as error:
            self.owner_diagnostics.failure(error)
            raise
        finally:
            self.owner_diagnostics.step("thread_exited")

    def fail(self, reason):
        ledger_transaction(self.descriptor, "fail", reason=str(reason), owner=True)

    def snapshot(self):
        if self.closed and not self.directory.exists():
            return dict(self.final_value)
        return ledger_transaction(self.descriptor, "status", owner=True)

    def _amount(self, raw):
        value = raw.get("size")
        if type(value) is not int or not 0 <= value <= 16 * 1024 * 1024:
            raise ValueError("invalid network allocation size")
        return value

    def _fatal(self, reason):
        self.reason = self.reason or reason
        raise NetworkRuntimeError(self.reason)

    def apply(self, raw, pid):
        operation = raw.get("op")
        if operation == "unlisten":
            self.listeners.pop(raw.get("key"), None)
            return None
        if operation in {"status", "owner_tick"}:
            return self._snapshot()
        if operation == "heartbeat":
            if pid not in self.peers and len(self.peers) >= 32:
                self._fatal("network_runtime_peer_limit")
            self.peers[pid] = time.monotonic(), process_start(pid)
            return self._snapshot()
        if operation == "release":
            identity = raw.get("lease")
            lease = self.leases.get(identity)
            if lease is not None:
                kind, count, owner_pid, birth = lease
                if owner_pid != pid or process_start(pid) != birth:
                    raise NetworkRuntimeError("network lease belongs to another process")
                used = raw.get("used", 0)
                if type(used) is not int or not 0 <= used <= count:
                    self._fatal("invalid_network_receive_commit")
                del self.leases[identity]
                if kind == "rx":
                    self.usage["received_reserved"] -= count
                    self.usage["received_bytes"] += used
                else:
                    self.usage["active_jobs"] -= 1
                    if kind == "tcp":
                        self.usage["active_connections"] -= 1
            return None
        if operation == "fail":
            self.reason = self.reason or str(raw.get("reason", "network_service_failed"))[:200]
            return None
        finalizing = operation == "log" and raw.get("finalizing") is True
        if self.reason is not None and not finalizing:
            raise NetworkRuntimeError(self.reason)
        if operation == "listen":
            live = {key: value for key, value in self.listeners.items() if process_alive(*value)}
            self.listeners = live
            if len(live) >= self.limits.max_listeners:
                self._fatal("network_listener_budget_exceeded")
            key = secrets.token_hex(12)
            self.listeners[key] = pid, process_start(pid)
            return key
        if operation == "message":
            if self.usage["messages"] >= self.limits.max_messages:
                self._fatal("network_message_budget_exceeded")
            self.usage["messages"] += 1
            return None
        if operation == "slot":
            kind = raw.get("kind")
            if kind not in {"tcp", "message"}:
                raise ValueError("invalid network slot kind")
            if kind == "tcp":
                if self.usage["total_connections"] >= self.limits.max_total_connections:
                    self._fatal("network_connection_budget_exceeded")
                self.usage["total_connections"] += 1
            else:
                if self.usage["messages"] >= self.limits.max_messages:
                    self._fatal("network_message_budget_exceeded")
                self.usage["messages"] += 1
            if (self.usage["active_jobs"] >= self.limits.max_pending
                    or kind == "tcp" and self.usage["active_connections"] >= self.limits.max_connections):
                self.usage["rejected_connections" if kind == "tcp" else "dropped_messages"] += 1
                return None
            lease = secrets.token_hex(12)
            self.leases[lease] = kind, 1, pid, process_start(pid)
            self.usage["active_jobs"] += 1
            self.usage["peak_jobs"] = max(self.usage["peak_jobs"], self.usage["active_jobs"])
            if kind == "tcp":
                self.usage["active_connections"] += 1
                self.usage["peak_connections"] = max(self.usage["peak_connections"], self.usage["active_connections"])
            return lease
        if operation == "receive":
            amount = self._amount(raw)
            remaining = self.limits.max_received_bytes - self.usage["received_bytes"] - self.usage["received_reserved"]
            granted = min(amount, remaining)
            if granted <= 0 or raw.get("exact") is True and granted != amount:
                self._fatal("network_receive_budget_exceeded")
            lease = secrets.token_hex(12)
            self.leases[lease] = "rx", granted, pid, process_start(pid)
            self.usage["received_reserved"] += granted
            return {"lease": lease, "size": granted}
        if operation == "send":
            amount = self._amount(raw)
            if self.usage["sent_bytes_reserved"] + amount > self.limits.max_sent_bytes:
                self._fatal("network_send_budget_exceeded")
            self.usage["sent_bytes_reserved"] += amount
            return None
        if operation == "log":
            amount = self._amount(raw)
            name = raw.get("file")
            path = Path(name) if isinstance(name, str) else None
            if path is None or len(name) > 1024 or path.is_absolute() or ".." in path.parts:
                raise ValueError("invalid network log identity")
            identity = hashlib.sha256(name.encode()).hexdigest()
            if identity not in self.files and len(self.files) >= self.limits.max_log_files + (4 if finalizing else 0):
                self._fatal("network_log_file_budget_exceeded")
            if (self.usage["log_bytes_reserved"] + amount > self.limits.max_log_bytes - self.footer_reserve
                    or not finalizing and self.usage["producer_log_bytes"] + amount > self.producer_limit):
                self._fatal("network_log_budget_exceeded")
            self.files.add(identity)
            self.usage["log_files"] = len(self.files)
            self.usage["log_bytes_reserved"] += amount
            if not finalizing:
                self.usage["producer_log_bytes"] += amount
            return None
        raise ValueError("unsupported network runtime operation")

    def check_peers(self):
        # Published state files are immutable; replacement publishes a whole
        # transaction. A health read must not contend with budget writers.
        state = json.loads(_regular(self.directory / "state.json", 8 * 1024 * 1024))
        now = time.monotonic()
        peer_timeout = OWNER_HEARTBEAT_PROFILES[self.heartbeat_profile][1]
        if any(int(pid) != proc_self() and process_alive(pid, birth) and now - last > peer_timeout
               for pid, (last, birth) in state["peers"].items()):
            self.fail("network_service_heartbeat_lost")

    def client(self):
        return NetworkRuntimeClient(self.client_path, owner_access=True)

    def reclaim_reaped(self):
        with ledger_lock(self.directory):
            path = self.directory / "state.json"
            value = json.loads(_regular(path, 8 * 1024 * 1024))
            for identity, (kind, count, pid, birth) in list(value["leases"].items()):
                if not process_alive(pid, birth):
                    del value["leases"][identity]
                    if kind == "rx":
                        value["usage"]["received_reserved"] -= count
                    else:
                        value["usage"]["active_jobs"] -= 1
                        if kind == "tcp":
                            value["usage"]["active_connections"] -= 1
            _private_json(path, value, durable=False)

    def close(self, *, cleanup_status="cleaned", remaining_resources=()):
        if self.closed and not self.directory.exists():
            return dict(self.final_value)
        if not self.closed:
            try:
                self.owner_close_diagnostic = self.owner_diagnostics.capture(self.thread)
            except Exception:
                self.owner_close_diagnostic = {"schema_version": 1, "attempt_id": self.attempt_id,
                                               "status": "capture_unavailable"}
            self.stop_event.set()
            self.thread.join(timeout=2)
            self.closed = True
        self.reclaim_reaped()
        value = self.snapshot()
        try:
            diagnostic = {**self.owner_close_diagnostic,
                          "after_join": self.owner_diagnostics.summary(self.thread)}
            _private_json(self.directory.parent / OWNER_DIAGNOSTIC_FILE,
                          bounded_record(diagnostic), durable=False)
            value["owner_diagnostic"] = {"status": "saved", "file": OWNER_DIAGNOSTIC_FILE}
        except Exception as error:
            value["owner_diagnostic"] = {"status": "unavailable", "exception_type": type(error).__name__}
        remaining = list(remaining_resources)
        if value["budget_usage"]["active_jobs"] or value["ready_listeners"] or self.thread.is_alive():
            cleanup_status = "cleanup_failed"
            remaining.append("network_tasks_or_owner_thread")
        value.update(owner_closed=True, cleanup_status=cleanup_status,
                     remaining_resources=[str(item)[:80] for item in remaining[:4]],
                     remaining_resources_total=len(remaining))
        value["evidence_complete"] = value["evidence_complete"] and cleanup_status == "cleaned"
        self.final_value = value
        if len(json.dumps(value).encode()) > self.footer_reserve:
            raise NetworkRuntimeError("network runtime terminal status exceeds its reserve")
        _private_json(self.status_path, value)
        if cleanup_status == "cleaned":
            for name in ("client.json", "state.json", "control.lock", OWNER_HEARTBEAT_FILE):
                (self.directory / name).unlink(missing_ok=True)
            for path in self.directory.glob('.network-state.*'):
                path.unlink()
            self.directory.rmdir()
        return value


def proc_self():
    """PID as seen by the mounted procfs, including nested PID namespaces."""
    return int(os.readlink("/proc/self"))


def process_alive(pid, birth):
    return birth is not None and process_start(pid) == birth


def child_proc_pid(pid):
    """Map a direct Popen child PID to the mounted procfs without scanning other namespaces."""
    own = proc_self()
    if own == os.getpid():
        return pid
    depth = len(next(line.split()[1:] for line in Path("/proc/self/status").read_text().splitlines()
                     if line.startswith("NSpid:"))) - 1
    # Some kernels omit task/children. Restrict procfs candidates by PPid before
    # comparing the PID at our namespace depth, so another namespace cannot match.
    with os.scandir("/proc") as entries:
        for entry in entries:
            if not entry.name.isdecimal():
                continue
            try:
                status = dict(line.split(":", 1) for line in Path(entry.path, "status").read_text().splitlines())
                if int(status["PPid"]) != own:
                    continue
                identifiers = status["NSpid"].split()
                if len(identifiers) > depth and int(identifiers[depth]) == pid:
                    return int(entry.name)
            except (OSError, KeyError, ValueError):
                continue
    return None


def process_start(pid):
    try:
        text = Path(f"/proc/{int(pid)}/stat").read_text()
        fields = text[text.rfind(")") + 2:].split()
        return fields[19] if fields[0] != "Z" else None
    except (OSError, TypeError, ValueError, IndexError):
        return None


@contextmanager
def ledger_lock(directory):
    path = Path(directory) / "control.lock"
    if any(parent.is_symlink() for parent in (path, *path.parents)):
        raise NetworkRuntimeError("symlink in network runtime ledger")
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise NetworkRuntimeError("network control lock must be a regular file")
        started = time.monotonic()
        deadline = started + 0.5
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise NetworkRuntimeError("network_runtime_lock_timeout", details={
                        "check": "ledger_lock_timeout", "wait_seconds": time.monotonic() - started,
                        "timeout_seconds": 0.5,
                    })
                time.sleep(0.002)
        yield
    finally:
        os.close(fd)


def _owner_profile(descriptor, value):
    profile = descriptor.get("heartbeat_profile")
    if profile is None:
        profile = OWNER_HEARTBEAT_PROFILE
    if type(profile) is not str or profile not in OWNER_HEARTBEAT_PROFILES:
        raise NetworkRuntimeError("unsupported network owner heartbeat profile")
    if value.get("heartbeat_profile", OWNER_HEARTBEAT_PROFILE) != profile:
        raise NetworkRuntimeError("network owner heartbeat profile binding changed", details={
            "check": "owner_heartbeat_profile", "owner_pid": descriptor["owner_pid"],
        })
    return profile


def _owner_last_seen(descriptor, value):
    profile = descriptor.get("heartbeat_profile")
    if profile is None:
        return value["owner_last_seen"]
    if type(profile) is not str or profile not in OWNER_HEARTBEAT_PROFILES:
        raise NetworkRuntimeError("unsupported network owner heartbeat profile")
    pulse = json.loads(_regular(Path(descriptor["directory"]) / OWNER_HEARTBEAT_FILE))
    if (not isinstance(pulse, dict) or type(pulse.get("schema_version")) is not int
            or pulse["schema_version"] != 1
            or any(pulse.get(key) != descriptor[key] for key in OWNER_IDENTITY)
            or (profile != OWNER_HEARTBEAT_PROFILE and pulse.get("heartbeat_profile") != profile)):
        raise NetworkRuntimeError("network owner heartbeat belongs to another runtime", details={
            "check": "owner_heartbeat_binding", "owner_pid": descriptor["owner_pid"],
        })
    seen = pulse.get("owner_last_seen")
    if (type(seen) not in (int, float) or seen < 0
            or seen > sys.float_info.max or not math.isfinite(seen)):
        raise NetworkRuntimeError("invalid network owner heartbeat timestamp", details={
            "check": "owner_heartbeat_data", "owner_pid": descriptor["owner_pid"],
        })
    return seen


def ledger_transaction(descriptor, operation, *, owner=False, **fields):
    directory = Path(descriptor["directory"])
    observed_start = process_start(descriptor["owner_pid"])
    if descriptor["owner_start"] is None or observed_start != descriptor["owner_start"]:
        raise NetworkRuntimeError("network_runtime_owner_lost", details={
            "check": "owner_process_identity", "owner_pid": descriptor["owner_pid"],
            "expected_start": descriptor["owner_start"], "observed_start": observed_start,
            "caller_pid": os.getpid(), "caller_uid": os.geteuid(),
        })
    # _private_json publishes complete state through atomic replacement. Status
    # observes that committed snapshot without taking the writers' lock. Every
    # mutation still serializes its read/modify/publish transaction below.
    guard = nullcontext() if operation == "status" else ledger_lock(directory)
    with guard:
        path = directory / "state.json"
        value = json.loads(_regular(path, 8 * 1024 * 1024))
        if value["token"] != descriptor["token"] or value["attempt_id"] != descriptor["attempt_id"]:
            raise NetworkRuntimeError("network runtime belongs to another attempt")
        if NetworkRuntimeLimits.parse(descriptor["limits"]).sha256 != value["limits_sha256"]:
            raise NetworkRuntimeError("network runtime limits binding changed")
        profile = _owner_profile(descriptor, value)
        owner_timeout = OWNER_HEARTBEAT_PROFILES[profile][0]
        terminal_status = operation == "status" and value["reason"] is not None
        if not owner and operation != "fail" and not terminal_status:
            for _ in range(2):
                seen = _owner_last_seen(descriptor, value)
                heartbeat_age = time.monotonic() - seen
                if heartbeat_age <= owner_timeout:
                    break
                # A reader may have been descheduled after opening a pulse.
                # Re-read the latest publication once before declaring loss.
            if heartbeat_age < 0:
                raise NetworkRuntimeError("network owner heartbeat is in the future", details={
                    "check": "owner_heartbeat_data", "owner_pid": descriptor["owner_pid"],
                })
            if heartbeat_age > owner_timeout:
                raise NetworkRuntimeError("network_runtime_owner_lost", details={
                    "check": "owner_heartbeat_stale", "owner_pid": descriptor["owner_pid"],
                    "age_seconds": heartbeat_age, "timeout_seconds": owner_timeout,
                    "heartbeat_profile": profile,
                    "caller_pid": os.getpid(), "caller_uid": os.geteuid(),
                })
        account = NetworkRuntimeOwner.__new__(NetworkRuntimeOwner)
        account.limits = NetworkRuntimeLimits.parse(descriptor["limits"])
        account.heartbeat_profile = profile
        account.attempt_id, account.token = value["attempt_id"], value["token"]
        account.reason, account.closed = value["reason"], False
        account.peers = {int(pid): seen for pid, seen in value["peers"].items()}
        account.leases = value["leases"]
        account.listeners = value.get("listeners", {})
        account.files, account.usage = set(value["files"]), value["usage"]
        account.footer_reserve = min(65536, max(2048, account.limits.max_log_bytes // 4))
        account.producer_limit = (account.limits.max_log_bytes - account.footer_reserve) // 2
        error = None
        try:
            result = account.apply({"op": operation, **fields}, proc_self())
        except (ValueError, NetworkRuntimeError) as exc:
            error = exc
        if operation != "status":
            updated = account._export()
            updated["owner_last_seen"] = time.monotonic() if owner else value["owner_last_seen"]
            _private_json(path, updated, durable=False)
        if error is not None:
            raise error
        return result


class NetworkRuntimeClient:
    def __init__(self, descriptor, *, owner_access=False):
        raw = json.loads(_regular(descriptor))
        if raw.get("schema_version") != 1:
            raise NetworkRuntimeError("unsupported network runtime descriptor")
        if raw.get("heartbeat_profile") not in (None, OWNER_HEARTBEAT_PROFILE, CONTROLLED_HEARTBEAT_PROFILE):
            raise NetworkRuntimeError("unsupported network owner heartbeat profile")
        self.path, self.descriptor = Path(descriptor), raw
        self.owner_access = owner_access
        if owner_access and (raw["owner_pid"] != proc_self() or not process_alive(proc_self(), raw["owner_start"])):
            raise NetworkRuntimeError("network runtime owner identity differs")
        self.attempt_id = raw["attempt_id"]
        self.logs_root = Path(raw["logs_root"])
        self.limits = NetworkRuntimeLimits.parse(raw["limits"])
        if raw["limits_sha256"] != self.limits.sha256:
            raise NetworkRuntimeError("network runtime limits digest differs")

    def call(self, operation, **fields):
        try:
            if (operation == "status" and not self.owner_access
                    and self.descriptor.get("heartbeat_profile") in (OWNER_HEARTBEAT_PROFILE, CONTROLLED_HEARTBEAT_PROFILE)):
                return _confirmed_owner_status(self.descriptor)
            return ledger_transaction(self.descriptor, operation, owner=self.owner_access, **fields)
        except NetworkRuntimeError as exc:
            exc.details = {"operation": operation, **(exc.details or {})}
            raise
        except (OSError, ValueError) as exc:
            raise NetworkRuntimeError("network_runtime_owner_lost", details={
                "check": "ledger_io" if isinstance(exc, OSError) else "ledger_data",
                "operation": operation, "exception_type": type(exc).__name__,
                "errno": getattr(exc, "errno", None),
                "path": str(exc.filename) if isinstance(exc, OSError) and exc.filename is not None else None,
                "ledger_directory": self.descriptor["directory"], "owner_pid": self.descriptor["owner_pid"],
                "message": str(exc)[:1000], "caller_pid": os.getpid(), "caller_uid": os.geteuid(),
            }) from exc

    def fail(self, reason):
        try:
            self.call("fail", reason=str(reason))
        except NetworkRuntimeError:
            pass

    def reserve_log(self, path, size, *, finalizing=False):
        path = Path(path).absolute()
        try:
            name = path.relative_to(self.logs_root).as_posix()
        except ValueError as exc:
            raise NetworkRuntimeError("network log escapes its attempt root") from exc
        self.call("log", file=name, size=size, finalizing=finalizing)


class NetworkFile:
    def __init__(self, path, mode, runtime, *, finalizing=False):
        self.path, self.runtime, self.finalizing = Path(path).absolute(), runtime, finalizing
        if any(item.is_symlink() for item in (self.path, *self.path.parents)):
            raise NetworkRuntimeError("symlink in network log path")
        if runtime is not None:
            runtime.reserve_log(self.path, 0, finalizing=finalizing)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        flags = os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK
        flags |= os.O_EXCL if "x" in mode else os.O_APPEND if "a" in mode else os.O_TRUNC
        try:
            self.fd = os.open(self.path, flags, 0o600)
            if not stat.S_ISREG(os.fstat(self.fd).st_mode):
                os.close(self.fd)
                raise OSError("network log must be a regular file")
        except OSError:
            if runtime is not None:
                runtime.fail("network_log_open_failed")
            raise

    def write(self, data):
        data = data.encode() if isinstance(data, str) else data
        if self.runtime is not None:
            self.runtime.reserve_log(self.path, len(data), finalizing=self.finalizing)
        view = memoryview(data)
        written = 0
        try:
            while written < len(view):
                count = os.write(self.fd, view[written:])
                if count <= 0:
                    raise OSError("short network log write")
                written += count
        except OSError:
            if self.runtime is not None:
                self.runtime.fail("network_log_write_failed")
            raise
        return written

    def flush(self):
        return None

    def fileno(self):
        return self.fd

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


def network_open(path, mode="ab", *, runtime=None, finalizing=False):
    return NetworkFile(path, mode, runtime if runtime is not None else current_runtime(), finalizing=finalizing)


def network_write(path, data):
    with network_open(path, "wb") as output:
        output.write(data)


def network_json(path, value):
    path = Path(path)
    temporary = path.with_suffix(path.suffix + ".pending")
    try:
        network_write(temporary, json.dumps(value, indent=2, ensure_ascii=False).encode() + b"\n")
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


async def run_network_service(operation, *, log_dir, runtime_path=None, limits=None):
    """Activate a shared budget and stop the service if its owner disappears."""
    owner = None
    if runtime_path is None:
        root = Path(log_dir)
        root.mkdir(parents=True, exist_ok=True)
        if any(root.iterdir()):
            raise ValueError("standalone network services require a fresh empty log directory")
        directory = Path(log_dir) / (".runtime-" + secrets.token_hex(6))
        owner = NetworkRuntimeOwner(directory, log_dir, attempt_id="standalone-" + secrets.token_hex(8), limits=limits)
        runtime_path = owner.client_path
    runtime, token = None, None
    saved_streams, outputs, tasks, signals = (sys.stdout, sys.stderr), [], [], []
    loop = asyncio.get_running_loop()
    try:
        runtime = NetworkRuntimeClient(runtime_path)
        if limits is not None and limits.sha256 != runtime.limits.sha256:
            raise NetworkRuntimeError("network policy and shared runtime limits differ")
        token = _CURRENT.set(runtime)
        if owner is not None:
            for name in ("stdout.log", "stderr.log"):
                outputs.append(NetworkTextOutput(Path(log_dir) / name, runtime))
            sys.stdout, sys.stderr = outputs
        stop = asyncio.Event()
        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(sig, stop.set)
            signals.append(sig)

        async def monitor():
            while not stop.is_set():
                status = runtime.call("heartbeat")
                if status["termination_reason"]:
                    raise NetworkRuntimeError(status["termination_reason"])
                await asyncio.sleep(0.05)

        service = asyncio.create_task(operation())
        watcher = asyncio.create_task(monitor())
        stopper = asyncio.create_task(stop.wait())
        tasks = [service, watcher, stopper]
        done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        if watcher in done:
            await watcher
        if service in done:
            await service
    except BaseException as exc:
        if runtime is not None and not isinstance(exc, asyncio.CancelledError):
            runtime.fail(str(exc) if isinstance(exc, NetworkRuntimeError) else "network_service_failed")
        raise
    finally:
        for task in tasks:
            task.cancel()
        try:
            if tasks:
                async with asyncio.timeout(runtime.limits.shutdown_timeout_ms / 1000):
                    await asyncio.gather(*tasks, return_exceptions=True)
        finally:
            for sig in signals:
                loop.remove_signal_handler(sig)
            if token is not None:
                _CURRENT.reset(token)
            sys.stdout, sys.stderr = saved_streams
            for output in outputs:
                output.close()
            if owner is not None:
                owner.close()


class NetworkTextOutput:
    """Bound standalone CLI output without duplicating backend-captured pipes."""
    encoding = "utf-8"
    def __init__(self, path, runtime):
        self.output = network_open(path, "wb", runtime=runtime)

    def write(self, text):
        self.output.write(text.encode(self.encoding, errors="backslashreplace"))
        return len(text)

    def flush(self):
        self.output.flush()

    def close(self):
        self.output.close()
