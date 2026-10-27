"""Bounded DNS wire handling for recorded queries, never a recursive resolver.

Profile: standard IN queries, one uncompressed question, optional EDNS(0)
without options. Answers retain their original RDATA, flags and TTLs. Replay
changes only the ID and question case; compression offsets remain unchanged.
"""
from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import struct


class DNSError(ValueError):
    pass


@dataclass(frozen=True)
class Question:
    labels: tuple[bytes, ...]
    qtype: int
    qclass: int
    end: int

    @property
    def name(self) -> str:
        return b".".join(self.labels).decode("ascii", errors="backslashreplace")

    @property
    def key(self) -> tuple:
        return tuple(label.lower() for label in self.labels), self.qtype, self.qclass


def _header(packet: bytes) -> tuple[int, ...]:
    if not 12 <= len(packet) <= 65535:
        raise DNSError("DNS packet size is outside 12..65535")
    return struct.unpack("!6H", packet[:12])


def _name(packet: bytes, offset: int, *, compressed: bool = True) -> tuple[tuple[bytes, ...], int]:
    labels: list[bytes] = []
    end = None
    visited: set[int] = set()
    total = 1
    while True:
        if offset >= len(packet) or offset in visited:
            raise DNSError("truncated or cyclic DNS name")
        visited.add(offset)
        size = packet[offset]
        if size & 0xC0 == 0xC0:
            if not compressed or offset + 1 >= len(packet):
                raise DNSError("compressed question or truncated pointer is unsupported")
            pointer = ((size & 63) << 8) | packet[offset + 1]
            if pointer < 12 or pointer >= offset:
                raise DNSError("invalid DNS compression pointer")
            if end is None:
                end = offset + 2
            offset = pointer
            continue
        if size & 0xC0:
            raise DNSError("unsupported DNS label encoding")
        offset += 1
        if size == 0:
            return tuple(labels), end if end is not None else offset
        if offset + size > len(packet):
            raise DNSError("truncated DNS label")
        total += size + 1
        if total > 255 or len(labels) >= 127:
            raise DNSError("DNS name exceeds bounds")
        labels.append(packet[offset:offset + size])
        offset += size


def question(packet: bytes) -> Question:
    if _header(packet)[2] != 1:
        raise DNSError("exactly one DNS question is required")
    labels, end = _name(packet, 12, compressed=False)
    if end + 4 > len(packet):
        raise DNSError("truncated DNS question")
    qtype, qclass = struct.unpack("!HH", packet[end:end + 4])
    if qclass != 1:
        raise DNSError("only the DNS IN class is supported")
    return Question(labels, qtype, qclass, end + 4)


def canonical_query(packet: bytes) -> bytes:
    _, flags, _, answers, authority, additional = _header(packet)
    if flags & ~0x0130 or answers or authority or additional > 1:
        raise DNSError("unsupported DNS query flags or sections")
    query = question(packet)
    if query.qtype in (0, 249, 250, 251, 252):
        raise DNSError("DNS transfers and key negotiation are outside the replay profile")
    tail = packet[query.end:]
    if additional:
        if len(tail) != 11 or tail[0] != 0:
            raise DNSError("only empty EDNS(0) options are supported")
        kind, payload, ttl, size = struct.unpack("!HHIH", tail[1:])
        if kind != 41 or payload < 512 or ttl & ~0x8000 or size:
            raise DNSError("unsupported EDNS version, flags or options")
    elif tail:
        raise DNSError("unreported DNS query bytes")
    name = b"".join(bytes([len(label)]) + label.lower() for label in query.labels) + b"\0"
    return b"\0\0" + packet[2:12] + name + struct.pack("!HH", query.qtype, query.qclass) + tail


def validate_response(query_packet: bytes, response: bytes) -> dict:
    canonical_query(query_packet)
    query = question(query_packet)
    rid, flags, _, answers, authority, additional = _header(response)
    actual = question(response)
    if rid != int.from_bytes(query_packet[:2], "big") or not flags & 0x8000 or flags & 0x7800:
        raise DNSError("DNS response ID, QR or opcode mismatch")
    if actual.key != query.key or actual.end != query.end:
        raise DNSError("DNS response question mismatch")
    if flags & 0x0100 != int.from_bytes(query_packet[2:4], "big") & 0x0100:
        raise DNSError("DNS response RD flag mismatch")
    if answers + authority + additional > 4096:
        raise DNSError("DNS record count exceeds bounds")
    records: list[dict] = []
    offset = actual.end
    for index in range(answers + authority + additional):
        labels, offset = _name(response, offset)
        if offset + 10 > len(response):
            raise DNSError("truncated DNS resource record")
        kind, cls, ttl, size = struct.unpack("!HHIH", response[offset:offset + 10])
        offset += 10
        end = offset + size
        if end > len(response):
            raise DNSError("truncated DNS RDATA")
        item = {"name": b".".join(labels).decode("ascii", errors="backslashreplace"),
                "type": kind, "class": cls, "ttl": ttl,
                "section": "answer" if index < answers else "authority" if index < answers + authority else "additional"}
        if cls == 1 and kind in (1, 28):
            if size != (4 if kind == 1 else 16):
                raise DNSError("invalid DNS address size")
            item["address"] = str(ipaddress.ip_address(response[offset:end]))
        if cls == 1 and kind == 5:
            alias, consumed = _name(response, offset)
            if consumed != end:
                raise DNSError("invalid CNAME extent")
            item["target"] = b".".join(alias).decode("ascii", errors="backslashreplace")
        records.append(item)
        offset = end
    if offset != len(response):
        raise DNSError("unreported DNS response bytes")
    return {"name": query.name, "qtype": query.qtype, "qclass": query.qclass,
            "rcode": flags & 15, "truncated": bool(flags & 0x0200), "records": records}


def canonical_exchange(query: bytes, response: bytes) -> tuple[bytes, bytes]:
    validate_response(query, response)
    normalized = canonical_query(query)
    end = question(query).end
    return normalized, b"\0\0" + response[2:12] + normalized[12:end] + response[end:]


def replay_response(query: bytes, recorded_query: bytes, response: bytes) -> bytes:
    if canonical_query(query) != recorded_query:
        raise DNSError("DNS query does not match the recorded contract")
    validate_response(recorded_query, response)
    end = question(query).end
    return query[:2] + response[2:12] + query[12:end] + response[end:]


def answer_addresses(reports: list[dict], domain: str) -> set[str]:
    """Follow recorded answer CNAMEs; unrelated additional records grant no route."""
    reachable = {domain.rstrip(".").lower()}
    records = [item for report in reports if report["rcode"] == 0 and not report["truncated"]
               for item in report["records"] if item["section"] == "answer"]
    for _ in range(64):
        aliases = {r["target"].rstrip(".").lower() for r in records
                   if r["type"] == 5 and r["name"].rstrip(".").lower() in reachable}
        if aliases <= reachable:
            break
        reachable |= aliases
    return {r["address"] for r in records if "address" in r and r["name"].rstrip(".").lower() in reachable}


def error_response(query: bytes, rcode: int = 2) -> bytes:
    canonical_query(query)
    end = question(query).end
    flags = 0x8080 | (int.from_bytes(query[2:4], "big") & 0x0110) | rcode
    return query[:2] + struct.pack("!5H", flags, 1, 0, 0, 0) + query[12:end]


def build_query(name: str, *, transaction_id: int = 1, qtype: int = 1) -> bytes:
    labels = name.rstrip(".").encode("ascii").split(b".")
    if any(not 1 <= len(label) <= 63 for label in labels):
        raise DNSError("invalid DNS name")
    packet = struct.pack("!6H", transaction_id, 0x0100, 1, 0, 0, 0)
    packet += b"".join(bytes([len(label)]) + label for label in labels) + b"\0" + struct.pack("!HH", qtype, 1)
    canonical_query(packet)
    return packet
