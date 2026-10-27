"""Explicit synthetic DNS records for controlled experiments, with no upstream."""
from __future__ import annotations

from datetime import datetime, timezone
import ipaddress
import json
from pathlib import Path
import struct

from .dns_protocol import canonical_query, error_response, question
from .message_transport import MessageServer


class DNSStaticService:
    def __init__(self, service, log_dir):
        self.service = service
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        if not isinstance(service.dns_records, dict):
            raise ValueError("synthetic DNS requires explicit dns_records")
        self.records = {}
        for name, values in service.dns_records.items():
            if not isinstance(name, str) or not isinstance(values, list) or len(values) > 64:
                raise ValueError("invalid synthetic DNS records")
            self.records[name.rstrip(".").lower()] = [ipaddress.ip_address(value) for value in values]

    async def start(self):
        return await MessageServer(self.handle).start(self.service.bind_ip, self.service.bind_port, self.service.service_type)

    async def handle(self, query, peer):
        canonical_query(query)
        q = question(query)
        values = self.records.get(q.name.lower())
        if values is None:
            response = error_response(query, 3)
        else:
            addresses = [a for a in values if (q.qtype == 1 and a.version == 4) or (q.qtype == 28 and a.version == 6)]
            flags = 0x8080 | (int.from_bytes(query[2:4], "big") & 0x0100)
            response = query[:2] + struct.pack("!5H", flags, 1, len(addresses), 0, 0) + query[12:q.end]
            for address in addresses:
                response += b"\xc0\x0c" + struct.pack("!HHIH", q.qtype, 1, 60, len(address.packed)) + address.packed
            if self.service.service_type == "udp" and len(response) > 512:
                response = query[:2] + struct.pack("!5H", flags | 0x0200, 1, 0, 0, 0) + query[12:q.end]
        event = {"timestamp_utc": datetime.now(timezone.utc).isoformat(), "event": "dns_emulated",
            "listener_type": "dns_emulated", "response_origin": "synthetic", "dns_query": q.name,
            "dns_qtype": q.qtype, "dns_response_prepared": True, "transport": self.service.service_type,
            "original_remote_ip": self.service.remote_ip, "original_remote_port": self.service.remote_port}
        with (self.log_dir / "network_events.jsonl").open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(event, sort_keys=True) + "\n")
        return response
