from __future__ import annotations

import json
import socket 
from dataclasses import asdict, dataclass, field, replace
from pathlib import Path
from typing import Optional

from .models import NetworkDependency, TaintLog

@dataclass(slots=True)
class CatchAllPolicy:
    enabled: bool = True
    tcp_bind_ip: str = "127.0.0.1"
    tcp_bind_port: int = 40000
    udp_enabled: bool = True
    udp_bind_ip: str = "127.0.0.1"
    udp_bind_port: int = 40001
    unknown_policy: str = "transparent_redirect_and_log"

@dataclass(slots=True)
class NetworkServicePolicy:
    service_type: str
    role: str

    remote_ip: Optional[str]
    remote_port: Optional[int]
    domain: Optional[str]

    bind_ip: str
    bind_port: int
    protocol_hint: Optional[str] = None
    upstream_ip: Optional[str] = None
    upstream_port: Optional[int] = None
    dns_records: dict[str, list[str]] | None = None




@dataclass(slots=True)
class NetworkPolicy:
    mode: str = "local_test"
    allow_internet: bool = False
    services: list[NetworkServicePolicy] = field(default_factory=list)
    catch_all: CatchAllPolicy = field(default_factory=CatchAllPolicy)
    recording: dict | None = None

    def to_dict(self) -> dict:
        result = {
            "mode": self.mode,
            "allow_internet": self.allow_internet,
            "services": [asdict(service) for service in self.services],
            "catch_all": asdict(self.catch_all),
        }
        if self.recording is not None:
            result["recording"] = self.recording
        return result


def is_tcp_port_available(host: str, port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            sock.bind((host,port))
        except OSError:
            return False
        return True

def choose_tcp_bind_port(host: str, preferred_port: Optional[int], check_availability: bool = True) -> int:
    if preferred_port is not None:
        if not check_availability:
            return preferred_port

        if is_tcp_port_available(host, preferred_port):
            return preferred_port

    if not check_availability:
        if preferred_port is None:
            raise ValueError("preferred_port is required when check_availability = False")
        return preferred_port

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((host, 0))
        return int(sock.getsockname()[1])


def choose_udp_bind_port(host: str, preferred_port: Optional[int], check_availability: bool = True) -> int:
    if not check_availability:
        if preferred_port is None:
            raise ValueError("preferred_port is required when check_availability = False")
        return preferred_port
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        if preferred_port is not None:
            try:
                sock.bind((host, preferred_port))
                return int(sock.getsockname()[1])
            except OSError:
                pass
        sock.bind((host, 0))
        return int(sock.getsockname()[1])

def build_network_policy(
    taint: TaintLog,
    mode: str = "local_test",
    default_bind_ip: str = "127.0.0.1",
    check_bind_availability: bool = True,
    enable_catch_all: bool = True,
    catch_all_port: int = 40000,
) -> NetworkPolicy:
    policy = NetworkPolicy(mode=mode, allow_internet=False, catch_all=CatchAllPolicy(
    enabled=enable_catch_all,
    tcp_bind_ip="127.0.0.1",
    tcp_bind_port=catch_all_port,
    udp_enabled=True,
    udp_bind_ip="127.0.0.1",
    udp_bind_port=40001,
    unknown_policy="transparent_redirect_and_log",)
    )

    seen = set()
    for dep in taint.network_dependencies:
        service = build_service_policy(dep=dep, default_bind_ip=default_bind_ip, check_bind_availability=check_bind_availability)

        if service is not None:
            transports = ("udp", "tcp") if service.protocol_hint == "dns" else (service.service_type,)
            for transport in transports:
                key = transport, service.remote_ip, service.remote_port
                if key in seen:
                    continue
                seen.add(key)
                candidate = replace(service, service_type=transport)
                if transport != service.service_type:
                    chooser = choose_udp_bind_port if transport == "udp" else choose_tcp_bind_port
                    candidate.bind_port = chooser(default_bind_ip, service.remote_port, check_bind_availability)
                policy.services.append(candidate)

    return policy


def build_service_policy(dep: NetworkDependency, default_bind_ip: str, check_bind_availability: bool = True) -> Optional[NetworkServicePolicy]:
    if dep.transport() not in {"tcp", "udp"}:
        return None

    remote_port = dep.effective_remote_port()

    chooser = choose_udp_bind_port if dep.transport() == "udp" else choose_tcp_bind_port
    bind_port = chooser(host=default_bind_ip, preferred_port=remote_port, check_availability=check_bind_availability)

    return NetworkServicePolicy(
        service_type=dep.transport(),
        role=dep.type,
        remote_ip=dep.effective_remote_ip(),
        remote_port=remote_port,
        domain=None,
        bind_ip=default_bind_ip,
        bind_port=bind_port,
        protocol_hint="dns" if dep.is_dns() else dep.type,
    )

def save_network_policy(policy: NetworkPolicy, path: str | Path) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(policy.to_dict(), indent=2), encoding = "utf-8")

def load_network_policy(path: str | Path) -> NetworkPolicy:
    path = Path(path)
    raw = json.loads(path.read_text(encoding="utf-8"))
    
    services = [
        NetworkServicePolicy(**item)
        for item in raw.get("services", [])
    ]

    catch_all_raw = raw.get("catch_all", {})

    catch_all = CatchAllPolicy(
    enabled=bool(catch_all_raw.get("enabled", True)),
    tcp_bind_ip=catch_all_raw.get("tcp_bind_ip", "127.0.0.1"),
    tcp_bind_port=int(catch_all_raw.get("tcp_bind_port", 40000)),
    udp_enabled=bool(catch_all_raw.get("udp_enabled", True)),
    udp_bind_ip=catch_all_raw.get("udp_bind_ip", "127.0.0.1"),
    udp_bind_port=int(catch_all_raw.get("udp_bind_port", 40001)),
    unknown_policy=catch_all_raw.get(
        "unknown_policy",
        "transparent_redirect_and_log",
    )
    )

    return NetworkPolicy(mode=raw.get("mode", "local_test"), allow_internet=bool(raw.get("allow_internet", False)), services=services, catch_all=catch_all, recording=raw.get("recording"))
