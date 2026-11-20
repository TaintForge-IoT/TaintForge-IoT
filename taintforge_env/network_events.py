"""Shared network evidence contract; a sent reply is not a protocol goal.

Delivery means sendto completed or StreamWriter.drain completed. It does not
prove that the guest consumed the bytes. Old event names remain readable.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path
from typing import Any

from .dns_protocol import DNSError, canonical_exchange, canonical_query
from .event_logger import append_jsonl_event


@dataclass(frozen=True, slots=True)
class ObservedReply:
    payload: bytes
    event_path: Path
    event: dict[str, Any]

    def delivery(self, *, sent: bool, error: str | None = None) -> None:
        append_jsonl_event(self.event_path, {
            **self.event,
            "event": "network_response_sent" if sent else "network_response_failed",
            "source_event": self.event["event"],
            "response_sent": sent,
            **({"error": error} if error is not None else {}),
        })


def payload_fingerprints(request: bytes, response: bytes | None, *, dns: bool = False) -> dict[str, Any]:
    result: dict[str, Any] = {"request_sha256": hashlib.sha256(request).hexdigest()}
    if response is not None:
        result.update(response_sha256=hashlib.sha256(response).hexdigest(), response_size=len(response))
    if dns:
        try:
            normalized = canonical_query(request)
            result["canonical_request_sha256"] = hashlib.sha256(normalized).hexdigest()
            if response is not None:
                _, answer = canonical_exchange(request, response)
                result["canonical_response_sha256"] = hashlib.sha256(answer).hexdigest()
        except DNSError:
            pass  # A malformed query stays observable without inventing a DNS key.
    return result


def prepared_reply(
    event_path: Path,
    event: dict[str, Any],
    request: bytes,
    response: bytes | None,
    *,
    dns: bool = False,
) -> ObservedReply | None:
    """Log selection before transport delivery, retaining per-request context."""
    event = {
        **{key: value for key, value in event.items() if key != "timestamp_utc"},
        **payload_fingerprints(request, response, dns=dns),
        "network_event_version": 1,
        "response_prepared": response is not None,
        "response_sent": False,
        "semantic_satisfaction": "unknown",
    }
    append_jsonl_event(event_path, event)
    return ObservedReply(response, event_path, event) if response is not None else None


def normalize_network_event(event: dict[str, Any]) -> dict[str, Any]:
    """Remove run-local identities and conservatively interpret delivery evidence."""
    name = str(event.get("event") or "unknown")
    source = str(event.get("source_event") or name)
    transport = _text(event.get("transport"))
    if transport not in {"tcp", "udp"}:
        if name.startswith(("tcp_", "broker_")) or event.get("connection_id") is not None:
            transport = "tcp"
        else:
            transport = "udp" if name in {"udp_datagram", "udp_record"} else None
    dns = source.startswith("dns_") or event.get("protocol_hint") == "dns" or event.get("udp_role") == "dns"
    replay = _text(event.get("replay_status"))
    if replay not in {"hit", "miss"}:
        if source in {"replay_hit", "dns_replay_hit"}:
            replay = "hit"
        else:
            replay = "miss" if source in {"replay_miss", "dns_replay_miss"} else None
    if "response_sent" in event:
        sent = event["response_sent"] is True
    else:
        sent = (name == "tcp_response"
                or (name == "replay_hit" and transport == "tcp" and _size(event.get("response_size")) > 0)
                or (name == "udp_datagram" and event.get("dns_response_sent") is True))
    if name == "network_response_failed":
        sent = False
    if "response_prepared" in event:
        prepared = event["response_prepared"] is True
    else:
        prepared = event.get("dns_response_prepared") is True or source in {"replay_hit", "dns_replay_hit"}
    prepared = prepared or sent
    failed = (replay == "miss" or name in {"network_response_failed", "tcp_connection_error"}
              or _text(event.get("status")) in {"failed", "cancelled"}
              or (name == "broker_session_finished" and bool(event.get("error"))))
    origin = event.get("response_origin")
    if not isinstance(origin, str):
        origin = ("replay" if replay == "hit" else "synthetic_miss" if dns and replay == "miss"
                  else "upstream" if name.startswith("broker_") or source in {"udp_record", "dns_record"}
                  else "synthetic" if source in {"tcp_response", "udp_datagram", "dns_emulated"} else None)
    port = event.get("original_remote_port")
    port = port if type(port) is int and 0 < port <= 65535 else None
    ip = event.get("original_remote_ip")
    return {
        "schema_version": 1,
        "event": name,
        "transport": transport,
        "listener_type": _text(event.get("listener_type")),
        "original_remote_ip": _text(ip),
        "original_remote_port": port,
        "protocol_hint": "dns" if dns else _text(event.get("protocol_hint")),
        "udp_role": _text(event.get("udp_role")),
        "response_prepared": prepared,
        "response_observed": sent,
        "response_origin": origin,
        "replay_status": replay,
        "failure": failed,
        "request_sha256": _digest(event.get("canonical_request_sha256") if dns else None)
            or _digest(event.get("request_sha256")) or _digest(event.get("observed_request_sha256")),
        "response_sha256": _digest(event.get("canonical_response_sha256") if dns else None)
            or _digest(event.get("response_sha256")),
        "semantic_satisfaction": "unknown",
    }


def network_flow_key(event: dict[str, Any]) -> tuple[Any, ...] | None:
    """Correlate delivery within a responder and exchange, never by ID alone."""
    normalized = normalize_network_event(event)
    identity = next(((key, str(event[key])) for key in
                     ("connection_id", "session_id", "exchange_id", "datagram_id")
                     if type(event.get(key)) in {str, int}), None)
    if identity is not None and type(event.get("step_index")) is int and event["step_index"] >= 0:
        identity = (identity, ("step_index", str(event["step_index"])))
    if identity is None:
        return None
    return (
        normalized["transport"], normalized["original_remote_ip"], normalized["original_remote_port"],
        _text(event.get("backend_source")), normalized["listener_type"],
        _text(event.get("bind_ip")), _integer(event.get("bind_port")),
        _text(event.get("peer_host")), _integer(event.get("peer_port")), identity,
    )


def _text(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def _size(value: Any) -> int:
    return value if type(value) is int and value >= 0 else 0


def _integer(value: Any) -> int | None:
    return value if type(value) is int else None


def _digest(value: Any) -> str | None:
    if isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdefABCDEF" for c in value):
        return value.lower()
    return None
