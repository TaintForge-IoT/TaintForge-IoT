"""Bounded, data-only contracts for ordered TCP replay sessions."""
from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import ipaddress
import json
import re


class ReplaySessionError(ValueError):
    pass


def canonical_digest(value: dict) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=True).encode()).hexdigest()


@dataclass(frozen=True, slots=True)
class SessionLimits:
    max_steps: int = 32
    max_message_bytes: int = 65536
    max_received_bytes: int = 1048576
    max_sent_bytes: int = 1048576
    idle_timeout_ms: int = 5000
    session_timeout_ms: int = 30000
    max_connections: int = 16
    max_total_connections: int = 128

    @classmethod
    def parse(cls, raw):
        bounds = {"max_steps": (1, 32), "max_message_bytes": (1, 65536),
                  "max_received_bytes": (1, 1048576), "max_sent_bytes": (0, 1048576),
                  "idle_timeout_ms": (1, 60000), "session_timeout_ms": (1, 300000),
                  "max_connections": (1, 32), "max_total_connections": (1, 1024)}
        if not isinstance(raw, dict) or set(raw) - bounds.keys():
            raise ReplaySessionError("invalid session limit fields")
        values = {**asdict(cls()), **raw}
        for key, value in values.items():
            low, high = bounds[key]
            if type(value) is not int or not low <= value <= high:
                raise ReplaySessionError(f"session {key} must be an integer in {low}..{high}")
        return cls(**values)


@dataclass(frozen=True, slots=True)
class SessionStep:
    request: bytes
    response: bytes
    delay_ms: int = 0

    def to_dict(self):
        return {"request_hex": self.request.hex(), "response_hex": self.response.hex(),
                "delay_ms": self.delay_ms}


@dataclass(frozen=True, slots=True)
class ReplaySession:
    remote_ip: str
    remote_port: int
    protocol_hint: str | None
    steps: tuple[SessionStep, ...]
    limits: SessionLimits

    def to_dict(self):
        return {"schema_version": 1, "transport": "tcp", "remote_ip": self.remote_ip,
                "remote_port": self.remote_port, "protocol_hint": self.protocol_hint,
                "framing": "exact_bytes", "steps": [step.to_dict() for step in self.steps],
                "limits": asdict(self.limits)}

    @property
    def session_id(self):
        return canonical_digest(self.to_dict())

    @classmethod
    def parse(cls, raw):
        fields = {"schema_version", "transport", "remote_ip", "remote_port", "protocol_hint",
                  "framing", "steps", "limits"}
        if not isinstance(raw, dict) or set(raw) - fields:
            raise ReplaySessionError("invalid session fields; only data contracts are accepted")
        if (type(raw.get("schema_version")) is not int or raw["schema_version"] != 1
                or raw.get("transport") != "tcp" or raw.get("framing") != "exact_bytes"):
            raise ReplaySessionError("sessions require schema 1, TCP and exact_bytes framing")
        try:
            host = raw.get("remote_ip")
            address = ipaddress.IPv4Address(host) if isinstance(host, str) else None
            if (address is None or str(address) != host or address.is_unspecified
                    or address.is_multicast or host == "255.255.255.255"):
                raise ValueError("invalid session address")
        except (ValueError, TypeError) as exc:
            raise ReplaySessionError("session endpoint requires a canonical unicast IPv4 address") from exc
        port = raw.get("remote_port")
        if type(port) is not int or not 1 <= port <= 65535:
            raise ReplaySessionError("invalid session remote_port")
        hint = raw.get("protocol_hint")
        if hint is not None and (not isinstance(hint, str) or hint == "dns"
                                 or not re.fullmatch(r"[a-z0-9_.-]{1,64}", hint)):
            raise ReplaySessionError("invalid session protocol_hint; DNS uses its existing replay provider")
        limits = SessionLimits.parse(raw.get("limits", {}))
        steps = raw.get("steps")
        if not isinstance(steps, list) or not 1 <= len(steps) <= limits.max_steps:
            raise ReplaySessionError("session steps exceed the configured limit")
        parsed = []
        for step in steps:
            if (not isinstance(step, dict) or set(step) - {"request_hex", "response_hex", "delay_ms"}
                    or "request_hex" not in step or "response_hex" not in step):
                raise ReplaySessionError("invalid session step fields")
            payloads = []
            for key in ("request_hex", "response_hex"):
                value = step[key]
                if (not isinstance(value, str) or len(value) > 2 * limits.max_message_bytes
                        or not re.fullmatch(r"(?:[0-9a-f]{2})*", value)):
                    raise ReplaySessionError("session payloads require bounded canonical hexadecimal bytes")
                payloads.append(bytes.fromhex(value))
            if not payloads[0]:
                raise ReplaySessionError("session requests must not be empty")
            delay = step.get("delay_ms", 0)
            if type(delay) is not int or not 0 <= delay <= 60000:
                raise ReplaySessionError("session delay_ms must be an integer in 0..60000")
            parsed.append(SessionStep(*payloads, delay))
        if (sum(len(step.request) for step in parsed) > limits.max_received_bytes
                or sum(len(step.response) for step in parsed) > limits.max_sent_bytes):
            raise ReplaySessionError("session transcript exceeds its receive/send byte budget")
        return cls(host, port, hint, tuple(parsed), limits)
