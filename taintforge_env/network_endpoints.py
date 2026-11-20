"""Observed socket endpoints and bounded correlation with a QEMU sidecar."""
from __future__ import annotations

from dataclasses import dataclass
import errno
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
from typing import Any, Iterable


OUTBOUND = {"connect", "send", "sendto", "sendmsg"}
CAPTURED = OUTBOUND | {"socket"}
MAX_RECORDS = 16384
MAX_BYTES = 16 * 1024 * 1024
MAX_TRACKED_FDS = 4096


def arguments(text: str) -> list[str]:
    result, start, depth, quote, escaped = [], 0, 0, None, False
    for index, char in enumerate(text):
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
        elif char in "\"'":
            quote = char
        elif char in "{[(":
            depth += 1
        elif char in "}])":
            depth -= 1
        elif char == "," and depth == 0:
            result.append(text[start:index].strip())
            start = index + 1
    result.append(text[start:].strip())
    return result


def integer(value: str) -> int | None:
    value = value.split("<", 1)[0].strip()
    if re.fullmatch(r"-?[0-9]{1,20}", value):
        return int(value, 10)
    if re.fullmatch(r"0[xX][0-9a-fA-F]{1,16}", value):
        return int(value, 16)
    return None


def printed_endpoint(syscall: str, text: str) -> tuple[str | None, int | None]:
    parts = arguments(text)
    position = 4 if syscall == "sendto" else 1
    if syscall not in OUTBOUND or len(parts) <= position:
        return None, None
    target = parts[position]
    if not target.startswith("{"):
        return None, None
    if syscall == "sendmsg":
        match = re.search(r"\bmsg_name\s*=\s*(\{.*)", target)
        if not match:
            return None, None
        target = arguments(match.group(1))[0]
    if not re.match(r"\{\s*(?:sa_family|sin_family)\s*=\s*(?:AF_INET|PF_INET|2)\s*,", target):
        return None, None
    ip = re.search(r'\bsin_addr\s*=\s*inet_addr\("([^"]+)"\)', target)
    port = re.search(r"\bhtons\(([0-9]{1,5})\)", target)
    if not ip or not port:
        return None, None
    try:
        host = str(ipaddress.IPv4Address(ip.group(1)))
    except ValueError:
        return None, None
    number = int(port.group(1))
    return (host, number) if 0 <= number <= 65535 else (None, None)


@dataclass
class _Socket:
    transport: str
    peer: tuple[str, int] | None = None


class SocketTraceTracker:
    """Use observed socket/dup/close results; never infer TCP from connect."""
    def __init__(self, target_arch: str | None = None):
        self.fds: dict[tuple[Any, int], _Socket] = {}
        self.numeric_socket_types = target_arch in {None, "i386", "x86_64", "arm", "aarch64"}

    def reset(self):
        self.fds.clear()

    def _store(self, key, value):
        if key not in self.fds and len(self.fds) >= MAX_TRACKED_FDS:
            self.reset()
        self.fds[key] = value

    def apply(self, event):
        if event.event != "syscall":
            return
        parts = arguments(event.args)
        pid = event.pid if event.pid is not None else event.source_file
        fd = integer(parts[0]) if parts else None
        key = (pid, fd)
        result = event.return_value
        succeeded = event.success is True
        if event.syscall == "socket" and succeeded and result is not None:
            domain = parts[0] if parts else ""
            kind = parts[1] if len(parts) > 1 else ""
            protocol = parts[2] if len(parts) > 2 else ""
            numeric = integer(kind) if self.numeric_socket_types else None
            inet = domain in {"AF_INET", "PF_INET", "2"}
            stream = "SOCK_STREAM" in kind or (numeric is not None and numeric & 15 == 1)
            datagram = "SOCK_DGRAM" in kind or (numeric is not None and numeric & 15 == 2)
            tcp = protocol in {"0", "6", "IPPROTO_IP", "IPPROTO_TCP"}
            udp = protocol in {"0", "17", "IPPROTO_IP", "IPPROTO_UDP"}
            transport = "tcp" if inet and stream and tcp else "udp" if inet and datagram and udp else "unknown"
            self._store((pid, result), _Socket(transport))
            event.socket_fd, event.transport = result, transport
            return
        if event.syscall in {"close", "close_range"}:
            if event.syscall == "close_range":
                self.reset()
            else:
                self.fds.pop(key, None)
        if event.syscall in {"execve", "execveat", "fork", "vfork", "clone", "clone3"} and succeeded:
            self.reset()
        if event.syscall in {"dup", "dup2", "dup3", "fcntl", "fcntl64"} and succeeded and result is not None:
            duplicate = event.syscall.startswith("dup") or (len(parts) > 1 and
                (parts[1].startswith("F_DUPFD") or integer(parts[1]) in {0, 1030}))
            if duplicate:
                if key in self.fds:
                    self._store((pid, result), self.fds[key])
                else:
                    self.fds.pop((pid, result), None)
        if event.syscall not in OUTBOUND:
            return
        event.socket_fd = fd
        socket = self.fds.get(key)
        event.transport = socket.transport if socket else "unknown"
        if event.remote_ip is None and event.syscall != "connect" and socket and socket.peer:
            position = 4 if event.syscall == "sendto" else 1
            target = parts[position] if len(parts) > position else ""
            if (event.syscall == "send" or target in {"NULL", "0", "0x0"}
                    or re.match(r"\{\s*msg_name\s*=\s*NULL\s*[,}]", target)):
                event.remote_ip, event.remote_port = socket.peer
                event.endpoint_source = "observed_socket_peer"
        event.endpoint_resolution = "observed" if event.remote_ip is not None and event.remote_port is not None else "unresolved"
        if event.remote_ip is not None and event.endpoint_source is None:
            event.endpoint_source = "printed_sockaddr"
        if event.syscall == "connect" and socket:
            socket.peer = (event.remote_ip, event.remote_port) if succeeded and event.remote_ip is not None else None


class EndpointCaptureError(ValueError):
    pass


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise EndpointCaptureError("duplicate endpoint capture field")
        result[key] = value
    return result


class EndpointCapture:
    def __init__(self, path: Path, *, session_id: str, attempt_id: str, target_arch: str):
        self.path = path
        self.records: list[dict] = []
        self.by_line: dict[int, dict] = {}
        self.trace_hashes: dict[int, str] = {}
        self.status: dict[str, Any] = {"status": "unavailable", "matched": 0, "source_file": path.name}
        if any(re.fullmatch(r"[A-Za-z0-9_.-]{1,120}", value or "") is None for value in (session_id, attempt_id)):
            raise EndpointCaptureError("endpoint capture requires session and attempt identities")
        if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_BYTES:
            raise EndpointCaptureError("endpoint capture must be a bounded regular file")
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, "rb") as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                raise EndpointCaptureError("endpoint capture is not a regular file")
            data = stream.read(MAX_BYTES + 1)
        if len(data) > MAX_BYTES:
            raise EndpointCaptureError("endpoint capture exceeds byte limit")
        self.status["sha256"] = hashlib.sha256(data).hexdigest()
        try:
            rows = []
            for line in data.splitlines():
                if len(line) > 2048 or len(rows) >= MAX_RECORDS + 3:
                    raise EndpointCaptureError("endpoint capture exceeds record bounds")
                row = json.loads(line, object_pairs_hook=_object)
                if not isinstance(row, dict) or type(row.get("schema_version")) is not int or row["schema_version"] != 1:
                    raise EndpointCaptureError("invalid endpoint capture record")
                rows.append(row)
        except (UnicodeError, json.JSONDecodeError) as error:
            raise EndpointCaptureError("invalid endpoint capture JSONL") from error
        if not rows or rows[0].get("event") != "observer_started":
            self.status.update(status="incomplete", reason="missing observer start")
            return
        if any(row.get("session_id") != session_id or row.get("attempt_id") != attempt_id for row in rows):
            self.status.update(status="identity_mismatch")
            return
        header = rows[0]
        if target_arch != "i386" or header.get("target_arch") != target_arch or header.get("profile") != "single-process-single-thread":
            self.status.update(status="unsupported_profile")
            return
        pid = header.get("pid")
        if type(pid) is not int or pid <= 0:
            raise EndpointCaptureError("invalid endpoint capture PID")
        if (type(header.get("plugin_api")) is not int or header["plugin_api"] < 4
                or type(header.get("max_records")) is not int or header["max_records"] != MAX_RECORDS):
            raise EndpointCaptureError("invalid endpoint observer limits or API")
        if any(row.get("event") == "observer_error" for row in rows):
            self.status.update(status="unsupported_profile", reason="observer reported lost evidence")
            return
        footer = rows[-1]
        if footer.get("event") != "observer_finished" or footer.get("complete") is not True:
            self.status.update(status="incomplete", reason="missing complete observer footer")
            return
        records = rows[1:-1]
        if type(footer.get("record_count")) is not int or footer["record_count"] != len(records):
            raise EndpointCaptureError("endpoint capture record count mismatch")
        for sequence, row in enumerate(records, 1):
            if (row.get("event") != "network_syscall" or type(row.get("seq")) is not int
                    or row["seq"] != sequence or type(row.get("pid")) is not int or row["pid"] != pid
                    or type(row.get("vcpu")) is not int or row["vcpu"] != 0
                    or not isinstance(row.get("syscall"), str) or row["syscall"] not in CAPTURED
                    or type(row.get("result")) is not int or not -(2**31) <= row["result"] < 2**31
                    or type(row.get("fd")) is not int or row["fd"] < -1
                    or not isinstance(row.get("transport"), str) or row["transport"] not in {"tcp", "udp", "unknown"}):
                raise EndpointCaptureError("invalid or out-of-order endpoint observation")
            direct = {"socket": 359, "connect": 362, "sendto": 369, "sendmsg": 370}
            multiplexed = {"socket": 1, "connect": 3, "send": 9, "sendto": 11, "sendmsg": 16}
            if (type(row.get("number")) is not int or type(row.get("subcall")) is not int
                    or not ((row["number"] == direct.get(row["syscall"]) and row["subcall"] == 0)
                            or (row["number"] == 102 and row["subcall"] == multiplexed[row["syscall"]]))):
                raise EndpointCaptureError("endpoint observation ABI/syscall mismatch")
            for key in ("sockaddr_address", "sockaddr_length"):
                if type(row.get(key)) is not int or not 0 <= row[key] < 2**32:
                    raise EndpointCaptureError("invalid guest sockaddr geometry")
            ip, port = row.get("remote_ip"), row.get("remote_port")
            if type(port) is not int or not 0 <= port <= 65535:
                raise EndpointCaptureError("invalid observed remote port")
            resolution = row.get("endpoint_resolution")
            if (not isinstance(resolution, str) or resolution not in {
                    "not_applicable", "observed_sockaddr", "observed_connected_peer", "null_sockaddr",
                    "invalid_sockaddr_length", "unreadable_sockaddr", "unsupported_address_family", "unreadable_msghdr"}
                    or ((ip is not None) != resolution.startswith("observed_"))
                    or (ip is None and port != 0)):
                raise EndpointCaptureError("inconsistent observed endpoint resolution")
            if ip is not None:
                try:
                    if not isinstance(ip, str) or str(ipaddress.IPv4Address(ip)) != ip:
                        raise ValueError("noncanonical address")
                except ValueError as error:
                    raise EndpointCaptureError("invalid observed IPv4 address") from error
        self.records = records
        self.status.update(status="validated", records=len(records))

    def correlate(self, events: Iterable[Any]):
        if self.status["status"] != "validated":
            return
        pairs = {}
        hashes = {}
        count = 0
        reverse_errno = {name: number for number, name in errno.errorcode.items()}
        for event in events:
            if event.event != "syscall" or event.syscall not in CAPTURED:
                continue
            if count >= len(self.records):
                self.status.update(status="uncorrelated", reason="more trace calls than observations")
                return
            row = self.records[count]
            count += 1
            result = event.return_value
            if event.errno:
                code = reverse_errno.get(event.errno)
                if code is None and event.errno.startswith("ERRNO_"):
                    code = int(event.errno[6:])
                result = -code if code is not None else None
            parts = arguments(event.args)
            fd = integer(parts[0]) if parts else None
            if (row["syscall"] != event.syscall or row["pid"] != event.pid or row["result"] != result
                    or (event.syscall != "socket" and row["fd"] != fd)):
                self.status.update(status="uncorrelated", reason="PID/syscall/FD/result mismatch")
                return
            if event.transport in {"tcp", "udp"} and row["transport"] in {"tcp", "udp"} and event.transport != row["transport"]:
                self.status.update(status="uncorrelated", reason="printed and observed socket types differ")
                return
            if event.remote_ip is not None and (event.remote_ip, event.remote_port) != (row["remote_ip"], row["remote_port"]):
                self.status.update(status="uncorrelated", reason="printed and observed sockaddr differ")
                return
            pairs[event.line_number] = row
            hashes[event.line_number] = hashlib.sha256(event.raw.encode()).hexdigest()
        if count != len(self.records):
            self.status.update(status="uncorrelated", reason="unmatched endpoint observations")
            return
        self.by_line = pairs
        self.trace_hashes = hashes
        self.status.update(status="correlated", matched=count)

    def enrich(self, event):
        event.endpoint_observer_status = self.status["status"]
        row = self.by_line.get(event.line_number)
        if row is None:
            if self.status["status"] == "correlated" and event.syscall in CAPTURED:
                raise EndpointCaptureError("QEMU trace changed after endpoint correlation")
            return
        if hashlib.sha256(event.raw.encode()).hexdigest() != self.trace_hashes[event.line_number]:
            raise EndpointCaptureError("QEMU trace changed after endpoint correlation")
        event.transport = row["transport"]
        event.socket_fd = row["result"] if event.syscall == "socket" and row["result"] >= 0 else row["fd"]
        if event.syscall not in OUTBOUND:
            return
        event.remote_ip = row["remote_ip"]
        event.remote_port = row["remote_port"] if row["remote_ip"] is not None else None
        event.endpoint_resolution = "observed" if row["remote_ip"] is not None else "unresolved"
        event.endpoint_source = "qemu_network_observer"
        event.endpoint_reason = row.get("endpoint_resolution")
        event.endpoint_observation_seq = row["seq"]
