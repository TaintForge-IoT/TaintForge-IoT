from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol, Sequence

from .replay_store import ReplayStore, ReplayStoreValidationError


class ControlledNetworkError(RuntimeError):
    """Raised when a controlled network environment cannot be built safely."""


class CommandResultLike(Protocol):
    returncode: int
    stdout: str
    stderr: str


class CommandExecutorLike(Protocol):
    def run(self,command: Sequence[str],*,cwd: Path,check: bool = True,stdout_path: Path | None = None,stderr_path: Path | None = None) -> CommandResultLike: ...


class BackgroundProcessLike(Protocol):
    command: list[str]

    def poll(self) -> int | None: ...

    def terminate(self) -> None: ...

    def kill(self) -> None: ...

    def wait(self, timeout: float | None = None) -> int: ...


class ProcessSupervisorLike(Protocol):
    def start(self,command: Sequence[str],*,cwd: Path,stdout_path: Path,stderr_path: Path) -> BackgroundProcessLike: ...


@dataclass(slots=True)
class PopenBackgroundProcess:
    process: subprocess.Popen[str]
    command: list[str]
    stdout_handle: Any
    stderr_handle: Any

    def poll(self) -> int | None:
        return self.process.poll()

    def terminate(self) -> None:
        if self.process.poll() is not None:
            return
        try:
            os.killpg(self.process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass

    def kill(self) -> None:
        if self.process.poll() is not None:
            return
        try:
            os.killpg(self.process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass

    def wait(self, timeout: float | None = None) -> int:
        try:
            return self.process.wait(timeout=timeout)
        finally:
            self.stdout_handle.close()
            self.stderr_handle.close()


class SubprocessProcessSupervisor:
    def start(self,command: Sequence[str],*,cwd: Path,stdout_path: Path,stderr_path: Path) -> PopenBackgroundProcess:
        stdout_path.parent.mkdir(parents=True, exist_ok=True)
        stderr_path.parent.mkdir(parents=True, exist_ok=True)
        stdout_handle = stdout_path.open("w", encoding="utf-8")
        stderr_handle = stderr_path.open("w", encoding="utf-8")
        env = os.environ.copy()
        env["PYTHONPATH"] = str(cwd)
        try:
            process = subprocess.Popen(
                [str(value) for value in command],
                cwd=cwd,
                env=env,
                text=True,
                stdin=subprocess.DEVNULL,
                stdout=stdout_handle,
                stderr=stderr_handle,
                #keep the caller's controlling terminal so a foreground sudo validation ticket remains usable, dedicated process group still lets cleanup terminate the entire service tree
                process_group=0,
            )
        except Exception:
            stdout_handle.close()
            stderr_handle.close()
            raise
        return PopenBackgroundProcess(process=process,command=[str(value) for value in command],stdout_handle=stdout_handle,stderr_handle=stderr_handle)


class PortAllocatorLike(Protocol):
    def allocate(self, host: str, preferred_start: int) -> int: ...


class SocketPortAllocator:

    MIN_PORT = 20000
    MAX_PORT = 39999

    def allocate(self, host: str, preferred_start: int) -> int:
        start = min(max(preferred_start, self.MIN_PORT), self.MAX_PORT)
        candidates = list(range(start, self.MAX_PORT + 1)) + list(range(self.MIN_PORT, start))
        for port in candidates:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                try:
                    sock.bind((host, port))
                except OSError:
                    continue
                return port
        raise ControlledNetworkError(f"no free TCP port available on {host} in {self.MIN_PORT}-{self.MAX_PORT}")


@dataclass(slots=True, frozen=True)
class NetworkServiceMapping:
    service_type: str
    role: str
    remote_ip: str
    remote_port: int
    protocol_hint: str | None
    placement: str
    bind_ip: str
    bind_port: int

    def to_policy_dict(self) -> dict[str, Any]:
        return {
            "service_type": self.service_type,
            "role": self.role,
            "remote_ip": self.remote_ip,
            "remote_port": self.remote_port,
            "domain": None,
            "bind_ip": self.bind_ip,
            "bind_port": self.bind_port,
            "protocol_hint": self.protocol_hint
        }


@dataclass(slots=True, frozen=True)
class ControlledNetworkPlan:
    namespace_name: str
    veth_host: str
    veth_namespace: str
    host_ip: str
    namespace_ip: str
    host_cidr: str
    namespace_cidr: str
    catch_all_enabled: bool
    catch_all_tcp_port: int
    catch_all_udp_port: int
    host_services: tuple[NetworkServiceMapping, ...] = ()
    loopback_services: tuple[NetworkServiceMapping, ...] = ()
    skipped_services: tuple[dict[str, Any], ...] = ()

    @property
    def all_services(self) -> tuple[NetworkServiceMapping, ...]:
        return self.host_services + self.loopback_services

    def to_dict(self) -> dict[str, Any]:
        return {
            "namespace_name": self.namespace_name,
            "veth_host": self.veth_host,
            "veth_namespace": self.veth_namespace,
            "host_ip": self.host_ip,
            "namespace_ip": self.namespace_ip,
            "host_cidr": self.host_cidr,
            "namespace_cidr": self.namespace_cidr,
            "catch_all_enabled": self.catch_all_enabled,
            "catch_all_tcp_port": self.catch_all_tcp_port,
            "catch_all_udp_port": self.catch_all_udp_port,
            "host_services": [asdict(item) for item in self.host_services],
            "loopback_services": [asdict(item) for item in self.loopback_services],
            "skipped_services": list(self.skipped_services)
        }


@dataclass(slots=True)
class ControlledNetworkConfig:
    project_root: Path
    run_dir: Path
    template_policy_path: Path
    session_id: str
    iteration_index: int
    self_test: bool = False
    responder_mode: str = "emulated"
    replay_store_path: Path | None = None
    replay_store_expected_sha256: str | None = None
    process_start_grace_seconds: float = 0.50

    def __post_init__(self) -> None:
        self.project_root = Path(self.project_root).resolve(strict=False)
        self.run_dir = Path(self.run_dir).resolve(strict=False)
        self.template_policy_path = Path(self.template_policy_path).resolve(strict=False)
        self.responder_mode = str(self.responder_mode).strip().lower()
        if self.responder_mode not in {"emulated", "replay"}:
            raise ControlledNetworkError("responder_mode must be one of: emulated, replay")
        if self.replay_store_path is not None:
            self.replay_store_path = Path(self.replay_store_path).resolve(strict=False)
        if self.responder_mode == "replay" and self.replay_store_path is None:
            raise ControlledNetworkError("replay responder mode requires replay_store_path")
        if (self.responder_mode == "replay" and self.replay_store_expected_sha256 is None):
            raise ControlledNetworkError("replay responder mode requires replay_store_expected_sha256")
        if self.responder_mode != "replay" and self.replay_store_path is not None:
            raise ControlledNetworkError("replay_store_path is valid only for responder_mode=replay")
        if (self.responder_mode != "replay" and self.replay_store_expected_sha256 is not None):
            raise ControlledNetworkError("replay_store_expected_sha256 is valid only for responder_mode=replay")
        if self.self_test and self.responder_mode != "emulated":
            raise ControlledNetworkError("network self-test is not supported for deterministic replay")
        if not self.session_id:
            raise ControlledNetworkError("session_id is required")
        if self.iteration_index < 0:
            raise ControlledNetworkError("iteration_index must be non-negative")
        if self.process_start_grace_seconds < 0:
            raise ControlledNetworkError("process_start_grace_seconds must be non-negative")


@dataclass(slots=True)
class ControlledNetworkResult:
    plan: ControlledNetworkPlan
    manifest_path: Path
    effective_policy_path: Path
    network_events_path: Path


class ControlledNetworkBackend:

    SCHEMA_VERSION = 1
    BACKEND_VERSION = 2

    def __init__(self,config: ControlledNetworkConfig,*,executor: CommandExecutorLike,process_supervisor: ProcessSupervisorLike | None = None,port_allocator: PortAllocatorLike | None = None) -> None:
        self.config = config
        self.executor = executor
        self.process_supervisor = (process_supervisor or SubprocessProcessSupervisor())
        self.port_allocator = port_allocator or SocketPortAllocator()
        self.processes: list[BackgroundProcessLike] = []
        self.plan: ControlledNetworkPlan | None = None
        self._setup_started = False
        self._cleaned = False
        self.replay_store_validation: dict[str, Any] | None = None

        self.config_dir = self.config.run_dir / "config"
        self.logs_dir = self.config.run_dir / "logs"
        self.requested_policy_path = (self.config_dir / "network_policy_requested.json")
        self.effective_policy_path = self.config_dir / "network_policy.json"
        self.host_policy_path = self.config_dir / "network_policy_host.json"
        self.loopback_policy_path = (self.config_dir / "network_policy_loopback.json")
        self.manifest_path = self.config_dir / "network_backend_manifest.json"
        self.events_path = self.logs_dir / "network_events.jsonl"

    def setup(self) -> ControlledNetworkResult:
        if self._setup_started:
            raise ControlledNetworkError("network backend setup called twice")
        self._setup_started = True
        self._validate_inputs()
        requested = _load_json_object(self.config.template_policy_path,"template network policy")
        _atomic_write_json(self.requested_policy_path, requested)

        topology = _derive_topology(self.config.session_id,self.config.iteration_index)
        self._cleanup_topology(topology, ignore_errors=True)

        try:
            self._create_topology(topology)
            self.plan = self._build_plan(requested, topology)
            self._validate_replay_plan(self.plan)
            self._write_policies(requested, self.plan)
            self._configure_firewall(self.plan)
            self._configure_namespace_service_privileges(self.plan)
            self._prepare_service_log_directories()
            self._start_services(self.plan)
            self._wait_for_services()
            if self.config.self_test:
                self._run_self_test(self.plan)
                self._archive_self_test_and_restart(self.plan)
            self._write_manifest("ready")
            return ControlledNetworkResult(plan=self.plan,manifest_path=self.manifest_path,effective_policy_path=self.effective_policy_path,network_events_path=self.events_path)
        except Exception as exc:
            try:
                self._stop_services()
                self._cleanup_topology(topology, ignore_errors=True)
                self._write_manifest("failed",error=f"{type(exc).__name__}: {exc}")
            except Exception:
                pass
            if isinstance(exc, ControlledNetworkError):
                raise
            raise ControlledNetworkError(str(exc)) from exc

    def guest_command(self, sandbox_script: Path) -> list[str]:
        if self.plan is None:
            raise ControlledNetworkError("network backend is not ready")
        return ["sudo","-n","ip","netns","exec",self.plan.namespace_name,"unshare","--mount","--pid","--fork","--uts","--ipc","--","bash",str(sandbox_script)]

    def cleanup(self, *, finalize_logs: bool = True) -> None:
        if self._cleaned:
            return
        self._cleaned = True
        errors: list[str] = []
        try:
            self._stop_services()
        except Exception as exc:
            errors.append(f"service cleanup: {exc}")
        if finalize_logs:
            try:
                self._aggregate_network_events()
            except Exception as exc:
                errors.append(f"network log aggregation: {exc}")
        if self.plan is not None:
            try:
                self._cleanup_topology(self.plan, ignore_errors=False)
            except Exception as exc:
                errors.append(f"topology cleanup: {exc}")
        try:
            self._write_manifest("cleaned" if not errors else "cleanup_failed",cleanup_errors=errors)
        except Exception as exc:
            errors.append(f"manifest update: {exc}")
        if errors:
            raise ControlledNetworkError("; ".join(errors))

    def _validate_inputs(self) -> None:
        _validate_directory(self.config.project_root, "project root")
        _validate_directory(self.config.run_dir, "run directory")
        _validate_directory(self.config_dir, "run config directory")
        _validate_directory(self.logs_dir, "run logs directory")
        _validate_regular_file(self.config.template_policy_path,"template network policy")
        service_scripts = (("scripts/start_network_replay.py") if self.config.responder_mode == "replay" else ("scripts/start_network_emulator.py","scripts/start_transparent_logger.py"))
        for relative in service_scripts:
            _validate_regular_file(self.config.project_root / relative,relative)
        if self.config.responder_mode == "replay":
            assert self.config.replay_store_path is not None
            try:
                self.replay_store_validation = ReplayStore(self.config.replay_store_path).validate()
            except ReplayStoreValidationError as exc:
                raise ControlledNetworkError(str(exc)) from exc
            actual_digest = str(self.replay_store_validation.get("store_sha256"))
            if (self.config.replay_store_expected_sha256 is not None and actual_digest != self.config.replay_store_expected_sha256):
                raise ControlledNetworkError(
                    f"replay store digest does not match the bound execution contract: expected {self.config.replay_store_expected_sha256}, got {actual_digest}")
        for tool in ("sudo", "ip", "iptables", "setpriv", "sysctl"):
            if shutil.which(tool) is None:
                raise ControlledNetworkError(f"required network tool is missing: {tool}")

        self._validate_sudo_access()

    def _validate_sudo_access(self) -> None:
        validation = self.executor.run(["sudo", "-v"],cwd=self.config.project_root,check=False)
        if validation.returncode != 0:
            raise ControlledNetworkError("sudo credential validation failed before controlled network setup")

        noninteractive = self.executor.run(["sudo", "-n", "true"],cwd=self.config.project_root,check=False)
        if noninteractive.returncode != 0:
            raise ControlledNetworkError("sudo credentials are not available non-interactively after validation; check sudo timestamp policy")

    def _create_topology(self, topology: ControlledNetworkPlan) -> None:
        commands = [
            ["sudo", "-n", "ip", "netns", "add", topology.namespace_name],
            ["sudo","-n","ip","link","add",topology.veth_host,"type","veth","peer","name",topology.veth_namespace],
            ["sudo","-n","ip","link","set",topology.veth_namespace,"netns",topology.namespace_name],
            ["sudo","-n","ip","addr","add",topology.host_cidr,"dev",topology.veth_host],
            ["sudo", "-n", "ip", "link", "set", topology.veth_host, "up"],
            self._ns_command(topology,"ip","addr","add",topology.namespace_cidr,"dev",topology.veth_namespace),
            self._ns_command(topology,"ip","link","set",topology.veth_namespace,"up"),
            self._ns_command(topology, "ip", "link", "set", "lo", "up"),
            self._ns_command(topology,"ip","route","add","default","via",topology.host_ip)
        ]
        for command in commands:
            self.executor.run(command, cwd=self.config.project_root, check=True)

    def _build_plan(self,requested: dict[str, Any],topology: ControlledNetworkPlan) -> ControlledNetworkPlan:
        services_raw = requested.get("services", [])
        if not isinstance(services_raw, list):
            raise ControlledNetworkError("network policy services must be a JSON array")
        host_services: list[NetworkServiceMapping] = []
        loopback_services: list[NetworkServiceMapping] = []
        skipped: list[dict[str, Any]] = []
        port_seed = 20000 + int(
            hashlib.sha256(f"{self.config.session_id}:{self.config.iteration_index}".encode()).hexdigest()[:4],16) % 15000

        for index, item in enumerate(services_raw):
            if not isinstance(item, dict):
                skipped.append({"index": index, "reason": "service is not an object"})
                continue
            service_type = str(item.get("service_type") or "tcp").lower()
            if service_type != "tcp":
                skipped.append(
                    {
                        "index": index,
                        "reason": "controlled backend v1 supports known TCP services only",
                        "service_type": service_type
                    }
                )
                continue
            remote_ip_raw = item.get("remote_ip")
            remote_port_raw = item.get("remote_port")
            if not isinstance(remote_ip_raw, str) or not remote_ip_raw:
                skipped.append({"index": index, "reason": "remote_ip is missing"})
                continue
            try:
                remote_ip = ipaddress.ip_address(remote_ip_raw)
            except ValueError:
                skipped.append(
                    {
                        "index": index,
                        "reason": "remote_ip is invalid",
                        "remote_ip": remote_ip_raw
                    }
                )
                continue
            if remote_ip.version != 4:
                skipped.append(
                    {
                        "index": index,
                        "reason": "controlled backend v1 supports IPv4 only",
                        "remote_ip": remote_ip_raw
                    }
                )
                continue
            try:
                remote_port = int(remote_port_raw)
            except (TypeError, ValueError):
                skipped.append({"index": index, "reason": "remote_port is invalid"})
                continue
            if not 1 <= remote_port <= 65535:
                skipped.append(
                    {
                        "index": index,
                        "reason": "remote_port is out of range",
                        "remote_port": remote_port
                    }
                )
                continue
            role = str(item.get("role") or "tcp")
            protocol_hint_raw = item.get("protocol_hint")
            protocol_hint = (str(protocol_hint_raw) if protocol_hint_raw is not None else None)
            if remote_ip.is_loopback:
                loopback_services.append(NetworkServiceMapping(service_type="tcp",role=role,remote_ip=str(remote_ip),remote_port=remote_port,protocol_hint=protocol_hint,placement="namespace_loopback",bind_ip=str(remote_ip),bind_port=remote_port))
            else:
                bind_port = self.port_allocator.allocate(topology.host_ip,port_seed + len(host_services))
                host_services.append(NetworkServiceMapping(service_type="tcp",role=role,remote_ip=str(remote_ip),remote_port=remote_port,protocol_hint=protocol_hint,placement="host_gateway",bind_ip=topology.host_ip,bind_port=bind_port))

        catch_all_raw = requested.get("catch_all", {})
        if not isinstance(catch_all_raw, dict):
            raise ControlledNetworkError("network policy catch_all must be a JSON object")
        catch_all_enabled = bool(catch_all_raw.get("enabled", True))
        if self.config.responder_mode == "replay":
            catch_all_enabled = False
        tcp_port = _validated_port(catch_all_raw.get("tcp_bind_port", 40000),"catch_all.tcp_bind_port")
        udp_port = _validated_port(catch_all_raw.get("udp_bind_port", 40001),"catch_all.udp_bind_port")
        if tcp_port == udp_port:
            raise ControlledNetworkError("TCP and UDP catch-all ports must be different")

        return ControlledNetworkPlan(namespace_name=topology.namespace_name,veth_host=topology.veth_host,veth_namespace=topology.veth_namespace,host_ip=topology.host_ip,namespace_ip=topology.namespace_ip,host_cidr=topology.host_cidr,namespace_cidr=topology.namespace_cidr,catch_all_enabled=catch_all_enabled,catch_all_tcp_port=tcp_port,catch_all_udp_port=udp_port,host_services=tuple(host_services),loopback_services=tuple(loopback_services),skipped_services=tuple(skipped))

    def _validate_replay_plan(self, plan: ControlledNetworkPlan) -> None:
        if self.config.responder_mode != "replay":
            return
        if plan.skipped_services:
            reasons = "; ".join(str(item.get("reason") or "unsupported service") for item in plan.skipped_services)
            raise ControlledNetworkError("deterministic replay refuses a partially supported policy: " + reasons)
        if not plan.all_services:
            raise ControlledNetworkError("deterministic replay policy contains no supported TCP services")
        assert self.config.replay_store_path is not None
        store = ReplayStore(self.config.replay_store_path)
        missing: list[str] = []
        for service in plan.all_services:
            try:
                exchanges = store.exchanges_for_endpoint(transport="tcp",remote_ip=service.remote_ip,remote_port=service.remote_port,protocol_hint=service.protocol_hint)
            except ReplayStoreValidationError as exc:
                raise ControlledNetworkError(str(exc)) from exc
            if not exchanges:
                missing.append(f"{service.remote_ip}:{service.remote_port} protocol_hint={service.protocol_hint!r}")
        if missing:
            raise ControlledNetworkError("replay store does not cover every effective TCP service: " + ", ".join(missing))

    def _write_policies(self,requested: dict[str, Any],plan: ControlledNetworkPlan) -> None:
        mode = self.config.responder_mode
        catch_all = {
            "enabled": plan.catch_all_enabled,
            "tcp_bind_ip": "127.0.0.1",
            "tcp_bind_port": plan.catch_all_tcp_port,
            "udp_enabled": plan.catch_all_enabled,
            "udp_bind_ip": "127.0.0.1",
            "udp_bind_port": plan.catch_all_udp_port,
            "unknown_policy": ("drop" if mode == "replay" else "transparent_redirect_and_log")
        }
        host_policy = {
            "mode": mode,
            "allow_internet": False,
            "services": [item.to_policy_dict() for item in plan.host_services],
            "catch_all": {**catch_all, "enabled": False}
        }
        loopback_policy = {
            "mode": mode,
            "allow_internet": False,
            "services": [item.to_policy_dict() for item in plan.loopback_services],
            "catch_all": {**catch_all, "enabled": False}
        }
        effective = {
            "schema_version": 1,
            "mode": mode,
            "allow_internet": False,
            "services": [item.to_policy_dict() for item in plan.all_services],
            "catch_all": catch_all,
            "backend": plan.to_dict(),
            "requested_policy_sha256": _sha256_file(self.requested_policy_path),
            "requested_mode": requested.get("mode")
        }
        _atomic_write_json(self.host_policy_path, host_policy)
        _atomic_write_json(self.loopback_policy_path, loopback_policy)
        _atomic_write_json(self.effective_policy_path, effective)

    def _configure_firewall(self, plan: ControlledNetworkPlan) -> None:
        commands: list[list[str]] = [
            self._ns_command(plan, "iptables", "-F"),
            self._ns_command(plan, "iptables", "-t", "nat", "-F"),
            self._ns_command(plan, "iptables", "-P", "OUTPUT", "DROP"),
            self._ns_command(plan, "iptables", "-P", "INPUT", "DROP"),
            self._ns_command(plan, "iptables", "-P", "FORWARD", "DROP"),
            self._ns_command(plan, "iptables", "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"),
            self._ns_command(plan, "iptables", "-A", "INPUT", "-i", "lo", "-j", "ACCEPT"),
            self._ns_command(plan,"iptables","-A","OUTPUT","-m","conntrack","--ctstate","ESTABLISHED,RELATED","-j","ACCEPT"),
            self._ns_command(plan,"iptables","-A","INPUT","-m","conntrack","--ctstate","ESTABLISHED,RELATED","-j","ACCEPT")
        ]
        for mapping in plan.host_services:
            commands.extend(
                [
                    self._ns_command(plan,"iptables","-t","nat","-A","OUTPUT","-p","tcp","-d",mapping.remote_ip,"--dport",str(mapping.remote_port),"-j","DNAT","--to-destination",f"{mapping.bind_ip}:{mapping.bind_port}"),
                    self._ns_command(plan,"iptables","-A","OUTPUT","-p","tcp","-d",mapping.bind_ip,"--dport",str(mapping.bind_port),"-j","ACCEPT"),
                    self._ns_command(plan,"iptables","-A","INPUT","-p","tcp","-s",mapping.bind_ip,"--sport",str(mapping.bind_port),"-j","ACCEPT")
                ]
            )

        if plan.catch_all_enabled:
            commands.extend(self._catch_all_commands(plan))
        for command in commands:
            self.executor.run(command, cwd=self.config.project_root, check=True)

    def _catch_all_commands(self,plan: ControlledNetworkPlan) -> list[list[str]]:
        ns = lambda *args: self._ns_command(plan, *args)
        return [
            ns("iptables", "-t", "nat", "-N", "TF_TCP_CATCHALL"),
            ns("iptables", "-t", "nat", "-N", "TF_UDP_CATCHALL"),
            ns("iptables", "-t", "nat", "-A", "TF_TCP_CATCHALL", "-d", plan.host_ip, "-j", "RETURN"),
            ns("iptables", "-t", "nat", "-A", "TF_UDP_CATCHALL", "-d", plan.host_ip, "-j", "RETURN"),
            ns("iptables", "-t", "nat", "-A", "TF_TCP_CATCHALL", "-d", "127.0.0.0/8", "-j", "RETURN"),
            ns("iptables", "-t", "nat", "-A", "TF_UDP_CATCHALL", "-d", "127.0.0.0/8", "-j", "RETURN"),
            ns("iptables", "-t", "nat", "-A", "TF_TCP_CATCHALL", "-p", "tcp", "-j", "REDIRECT", "--to-ports", str(plan.catch_all_tcp_port)),
            ns("iptables", "-t", "nat", "-A", "TF_UDP_CATCHALL", "-p", "udp", "-j", "REDIRECT", "--to-ports", str(plan.catch_all_udp_port)),
            ns("iptables", "-t", "nat", "-A", "OUTPUT", "-p", "tcp", "-j", "TF_TCP_CATCHALL"),
            ns("iptables", "-t", "nat", "-A", "OUTPUT", "-p", "udp", "-j", "TF_UDP_CATCHALL"),
            ns("iptables", "-A", "OUTPUT", "-p", "tcp", "--dport", str(plan.catch_all_tcp_port), "-j", "ACCEPT"),
            ns("iptables", "-A", "INPUT", "-p", "tcp", "--sport", str(plan.catch_all_tcp_port), "-j", "ACCEPT"),
            ns("iptables", "-A", "OUTPUT", "-p", "udp", "--dport", str(plan.catch_all_udp_port), "-j", "ACCEPT"),
            ns("iptables", "-A", "INPUT", "-p", "udp", "--sport", str(plan.catch_all_udp_port), "-j", "ACCEPT")
        ]

    def _configure_namespace_service_privileges(self,plan: ControlledNetworkPlan) -> None:
        if not plan.loopback_services:
            return

        minimum_loopback_port = min(service.bind_port for service in plan.loopback_services)
        if minimum_loopback_port >= 1024:
            return

        self.executor.run(
            self._ns_command(plan,"sysctl","-q","-w",(f"net.ipv4.ip_unprivileged_port_start={minimum_loopback_port}"),),cwd=self.config.project_root,check=True)

    def _prepare_service_log_directories(self) -> None:
        for path in (self.logs_dir / "network_host",self.logs_dir / "network_loopback",self.logs_dir / "network_transparent"):
            if path.is_symlink():
                raise ControlledNetworkError(f"network log directory must not be a symlink: {path}")
            if path.exists() and not path.is_dir():
                raise ControlledNetworkError(f"network log path is not a directory: {path}")
            path.mkdir(parents=True, exist_ok=True)
            path.chmod(0o700)

    @staticmethod
    def _drop_privileges_command() -> list[str]:
        return ["setpriv","--reuid",str(os.getuid()),"--regid",str(os.getgid()),"--clear-groups"]

    def _start_services(self, plan: ControlledNetworkPlan) -> None:
        self.processes = []
        service_script = ("scripts/start_network_replay.py" if self.config.responder_mode == "replay" else "scripts/start_network_emulator.py")
        replay_arguments = (["--store", str(self.config.replay_store_path), "--expected-store-sha256", str(self.config.replay_store_expected_sha256)] if self.config.responder_mode == "replay" else [])
        if plan.host_services:
            self.processes.append(
                self.process_supervisor.start([sys.executable,service_script,"--policy",str(self.host_policy_path),"--log-dir",str(self.logs_dir / "network_host"),*replay_arguments],cwd=self.config.project_root,stdout_path=self.logs_dir / "network_host_stdout.log",stderr_path=self.logs_dir / "network_host_stderr.log"))
        if plan.loopback_services:
            self.processes.append(
                self.process_supervisor.start(
                    ["sudo","-n","ip","netns","exec",plan.namespace_name,*self._drop_privileges_command(),"env",f"PYTHONPATH={self.config.project_root}",sys.executable,service_script,"--policy",str(self.loopback_policy_path),"--log-dir",str(self.logs_dir / "network_loopback"),*replay_arguments],cwd=self.config.project_root,stdout_path=self.logs_dir / "network_loopback_stdout.log",stderr_path=self.logs_dir / "network_loopback_stderr.log"))
        if plan.catch_all_enabled:
            self.processes.append(
                self.process_supervisor.start(
                    ["sudo","-n","ip","netns","exec",plan.namespace_name,*self._drop_privileges_command(),"env",f"PYTHONPATH={self.config.project_root}",sys.executable,"scripts/start_transparent_logger.py","--log-dir",str(self.logs_dir / "network_transparent"),"--tcp-bind-ip","127.0.0.1","--tcp-port",str(plan.catch_all_tcp_port),"--udp-bind-ip","127.0.0.1","--udp-port",str(plan.catch_all_udp_port)],cwd=self.config.project_root,stdout_path=self.logs_dir / "network_transparent_stdout.log",stderr_path=self.logs_dir / "network_transparent_stderr.log"))

    def _wait_for_services(self) -> None:
        deadline = time.monotonic() + self.config.process_start_grace_seconds
        while time.monotonic() < deadline:
            for process in self.processes:
                code = process.poll()
                if code is not None:
                    raise ControlledNetworkError(f"network background service exited during startup with code {code}: {' '.join(process.command)}")
            time.sleep(0.02)
        for process in self.processes:
            code = process.poll()
            if code is not None:
                raise ControlledNetworkError(f"network background service exited during startup with code {code}: {' '.join(process.command)}")

    def _run_self_test(self, plan: ControlledNetworkPlan) -> None:
        probes: list[dict[str, Any]] = []
        if plan.host_services:
            first = plan.host_services[0]
            probes.append(
                {
                    "kind": "tcp",
                    "label": "known_host",
                    "host": first.remote_ip,
                    "port": first.remote_port,
                    "required": True
                }
            )
        if plan.loopback_services:
            first = plan.loopback_services[0]
            probes.append(
                {
                    "kind": "tcp",
                    "label": "known_loopback",
                    "host": first.remote_ip,
                    "port": first.remote_port,
                    "required": True
                }
            )
        if plan.catch_all_enabled:
            probes.extend(
                [
                    {
                        "kind": "tcp",
                        "label": "unknown_tcp",
                        "host": "198.18.0.1",
                        "port": 5555,
                        "required": True
                    },
                    {
                        "kind": "udp",
                        "label": "unknown_udp",
                        "host": "198.18.0.2",
                        "port": 9999,
                        "required": True
                    }
                ]
            )

        stdout_path = self.logs_dir / "network_self_test_stdout.log"
        stderr_path = self.logs_dir / "network_self_test_stderr.log"
        code = _self_test_code(probes,retry_timeout_seconds=5.0,retry_interval_seconds=0.10)
        result = self.executor.run(
            ["sudo","-n","ip","netns","exec",plan.namespace_name,sys.executable,"-c",code],cwd=self.config.project_root,check=False,stdout_path=stdout_path,stderr_path=stderr_path)
        if result.returncode != 0:
            stdout_tail = _tail_text(stdout_path)
            stderr_tail = _tail_text(stderr_path)
            raise ControlledNetworkError("controlled network self-test failed" + (f"\nSelf-test stdout:\n{stdout_tail}" if stdout_tail else "")+ (f"\nSelf-test stderr:\n{stderr_tail}" if stderr_tail else ""))
        self._wait_for_services()

    def _archive_self_test_and_restart(self,plan: ControlledNetworkPlan) -> None:
        self._stop_services()
        archive = self.logs_dir / "network_self_test"
        archive.mkdir(parents=True, exist_ok=False)
        names = (
            "network_host",
            "network_loopback",
            "network_transparent",
            "network_host_stdout.log",
            "network_host_stderr.log",
            "network_loopback_stdout.log",
            "network_loopback_stderr.log",
            "network_transparent_stdout.log",
            "network_transparent_stderr.log"
        )
        for name in names:
            source = self.logs_dir / name
            if source.exists() or source.is_symlink():
                if source.is_symlink():
                    raise ControlledNetworkError(f"network log path must not be a symlink: {source}")
                shutil.move(str(source), archive / name)
        self._prepare_service_log_directories()
        self._start_services(plan)
        self._wait_for_services()

    def _stop_services(self) -> None:
        errors: list[str] = []
        for process in reversed(self.processes):
            try:
                process.terminate()
            except Exception as exc:
                errors.append(f"terminate {' '.join(process.command)}: {exc}")
        for process in reversed(self.processes):
            try:
                process.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                try:
                    process.kill()
                    process.wait(timeout=2.0)
                except Exception as exc:
                    errors.append(f"kill {' '.join(process.command)}: {exc}")
            except Exception as exc:
                errors.append(f"wait {' '.join(process.command)}: {exc}")
        self.processes = []
        if errors:
            raise ControlledNetworkError("; ".join(errors))

    def _aggregate_network_events(self) -> None:
        sources = (("host", self.logs_dir / "network_host"),("loopback", self.logs_dir / "network_loopback"),("transparent", self.logs_dir / "network_transparent"))
        payload_root = self.logs_dir / "network_payloads"
        events: list[dict[str, Any]] = []
        for source_name, source_dir in sources:
            if not source_dir.exists():
                continue
            if source_dir.is_symlink() or not source_dir.is_dir():
                raise ControlledNetworkError(f"network source log directory is invalid: {source_dir}")
            event_path = source_dir / "network_events.jsonl"
            if event_path.is_symlink():
                raise ControlledNetworkError(f"network event log must not be a symlink: {event_path}")
            if not event_path.exists():
                continue
            for line_number, line in enumerate(event_path.read_text(encoding="utf-8").splitlines(),start=1):
                if not line.strip():
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise ControlledNetworkError(f"invalid network JSONL at {event_path}:{line_number}") from exc
                if not isinstance(event, dict):
                    raise ControlledNetworkError(f"network event is not an object at {event_path}:{line_number}")
                normalized = dict(event)
                normalized["backend_source"] = source_name
                payload = normalized.get("payload_file")
                if isinstance(payload, str) and payload:
                    payload_path = source_dir / payload
                    if payload_path.is_file() and not payload_path.is_symlink():
                        payload_root.mkdir(parents=True, exist_ok=True)
                        destination_name = f"{source_name}_{payload_path.name}"
                        destination = payload_root / destination_name
                        counter = 1
                        while destination.exists():
                            destination_name = (f"{source_name}_{counter}_{payload_path.name}")
                            destination = payload_root / destination_name
                            counter += 1
                        shutil.copy2(payload_path, destination)
                        normalized["payload_file"] = (f"network_payloads/{destination_name}")
                events.append(normalized)
        events.sort(
            key=lambda item: (str(item.get("timestamp_utc") or ""),str(item.get("backend_source") or ""),str(item.get("event") or "")))
        self.events_path.parent.mkdir(parents=True, exist_ok=True)
        with self.events_path.open("w", encoding="utf-8") as stream:
            for event in events:
                stream.write(json.dumps(event, ensure_ascii=False, sort_keys=True) + "\n")

    def _cleanup_topology(self,topology: ControlledNetworkPlan,*,ignore_errors: bool) -> None:
        commands = [["sudo", "-n", "ip", "link", "del", topology.veth_host],["sudo", "-n", "ip", "netns", "del", topology.namespace_name]]
        failures: list[str] = []
        for command in commands:
            result = self.executor.run(command,cwd=self.config.project_root,check=False)
            if result.returncode == 0:
                continue
            if ignore_errors or _network_resource_is_absent(command,result.stderr):
                continue
            failures.append(f"{' '.join(command)}: {result.stderr.strip()}")
        if failures:
            raise ControlledNetworkError("; ".join(failures))

    def _write_manifest(self,state: str,*,error: str | None = None,cleanup_errors: list[str] | None = None) -> None:
        payload = {
            "schema_version": self.SCHEMA_VERSION,
            "backend_version": self.BACKEND_VERSION,
            "generated_at_utc": _utc_now(),
            "state": state,
            "session_id": self.config.session_id,
            "iteration_index": self.config.iteration_index,
            "self_test": self.config.self_test,
            "responder_mode": self.config.responder_mode,
            "replay_store_path": (str(self.config.replay_store_path) if self.config.replay_store_path is not None else None),
            "replay_store_sha256": (self.replay_store_validation.get("store_sha256") if self.replay_store_validation is not None else None),
            "replay_store_entries": (self.replay_store_validation.get("entries") if self.replay_store_validation is not None else None),
            "requested_policy": str(self.requested_policy_path),
            "effective_policy": str(self.effective_policy_path),
            "requested_policy_sha256": (_sha256_file(self.requested_policy_path) if self.requested_policy_path.is_file() else None),
            "effective_policy_sha256": (_sha256_file(self.effective_policy_path) if self.effective_policy_path.is_file() else None),
            "plan": self.plan.to_dict() if self.plan is not None else None,
            "allow_internet": False,
            "host_ip_forwarding_modified": False,
            "error": error,
            "cleanup_errors": cleanup_errors or []
        }
        _atomic_write_json(self.manifest_path, payload)

    @staticmethod
    def _ns_command(topology: ControlledNetworkPlan,*command: str) -> list[str]:
        return ["sudo","-n","ip","netns","exec",topology.namespace_name,*command]


def _derive_topology(session_id: str, iteration_index: int) -> ControlledNetworkPlan:
    digest = hashlib.sha256(f"{session_id}:{iteration_index}".encode("utf-8")).hexdigest()
    suffix = digest[:8]
    octet = 20 + (int(digest[8:10], 16) % 220)
    host_ip = f"10.203.{octet}.1"
    namespace_ip = f"10.203.{octet}.2"
    return ControlledNetworkPlan(namespace_name=f"tf-{suffix}",veth_host=f"tfh{suffix}",veth_namespace=f"tfn{suffix}",host_ip=host_ip,namespace_ip=namespace_ip,host_cidr=f"{host_ip}/24",namespace_cidr=f"{namespace_ip}/24",catch_all_enabled=True,catch_all_tcp_port=40000,catch_all_udp_port=40001)


def _self_test_code(probes: list[dict[str, Any]],*,retry_timeout_seconds: float = 5.0,retry_interval_seconds: float = 0.10) -> str:
    payload = json.dumps(probes, sort_keys=True)
    return f"""
import json
import socket
import sys
import time

probes = json.loads({payload!r})
retry_timeout = {retry_timeout_seconds!r}
retry_interval = {retry_interval_seconds!r}
results = []
failed = False

for probe in probes:
    result = dict(probe)
    started = time.monotonic()
    attempts = 0
    last_error = None

    if probe['kind'] == 'tcp':
        deadline = started + retry_timeout
        while True:
            attempts += 1
            try:
                with socket.create_connection(
                    (probe['host'], int(probe['port'])),
                    timeout=min(1.0, retry_timeout),
                ) as sock:
                    sock.settimeout(1.0)
                    sock.sendall(
                        ('tf-self-test:' + probe['label']).encode()
                    )
                    try:
                        result['response_hex'] = sock.recv(64).hex()
                    except socket.timeout:
                        result['response_hex'] = ''
                result['ok'] = True
                break
            except Exception as exc:
                last_error = f'{{type(exc).__name__}}: {{exc}}'
                if time.monotonic() >= deadline:
                    result['ok'] = False
                    result['error'] = last_error
                    break
                time.sleep(retry_interval)
    else:
        deadline = started + retry_timeout
        while True:
            attempts += 1
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                    sock.settimeout(1.0)
                    sock.sendto(
                        ('tf-self-test:' + probe['label']).encode(),
                        (probe['host'], int(probe['port'])),
                    )
                result['ok'] = True
                break
            except Exception as exc:
                last_error = f'{{type(exc).__name__}}: {{exc}}'
                if time.monotonic() >= deadline:
                    result['ok'] = False
                    result['error'] = last_error
                    break
                time.sleep(retry_interval)

    result['attempts'] = attempts
    result['elapsed_ms'] = round(
        (time.monotonic() - started) * 1000,
        3,
    )
    if not result.get('ok') and probe.get('required', True):
        failed = True
    results.append(result)

print(json.dumps({{'results': results}}, sort_keys=True))
sys.exit(1 if failed else 0)
""".strip()


def _network_resource_is_absent(command: Sequence[str],stderr: str) -> bool:

    lowered = (stderr or "").strip().lower()
    if not lowered:
        return False

    tokens = [str(value) for value in command]
    is_link_delete = _contains_subsequence(tokens, ["ip", "link", "del"])
    is_netns_delete = _contains_subsequence(tokens, ["ip", "netns", "del"])

    if is_link_delete:
        return any(
            marker in lowered
            for marker in ("cannot find device","no such device","device does not exist","rtnetlink answers: no such device"))

    if is_netns_delete:
        return any(
            marker in lowered
            for marker in ("no such file or directory","cannot open network namespace","network namespace does not exist"))

    return False


def _contains_subsequence(values: Sequence[str],expected: Sequence[str]) -> bool:
    width = len(expected)
    if width == 0:
        return True
    return any(list(values[index:index + width]) == list(expected)for index in range(len(values) - width + 1))


def _tail_text(path: Path, lines: int = 40) -> str:
    if not path.is_file() or path.is_symlink():
        return ""
    try:
        content = path.read_text(encoding="utf-8",errors="replace").splitlines()
    except OSError:
        return ""
    return "\n".join(content[-lines:])


def _validated_port(value: Any, label: str) -> int:
    try:
        port = int(value)
    except (TypeError, ValueError) as exc:
        raise ControlledNetworkError(f"{label} must be an integer") from exc
    if not 1 <= port <= 65535:
        raise ControlledNetworkError(f"{label} is out of range")
    return port


def _load_json_object(path: Path, label: str) -> dict[str, Any]:
    _validate_regular_file(path, label)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ControlledNetworkError(f"invalid {label}: {path}") from exc
    if not isinstance(payload, dict):
        raise ControlledNetworkError(f"{label} must be a JSON object")
    return payload


def _validate_directory(path: Path, label: str) -> None:
    if path.is_symlink():
        raise ControlledNetworkError(f"{label} must not be a symlink: {path}")
    if not path.is_dir():
        raise ControlledNetworkError(f"{label} is not a directory: {path}")


def _validate_regular_file(path: Path, label: str) -> None:
    if path.is_symlink():
        raise ControlledNetworkError(f"{label} must not be a symlink: {path}")
    if not path.is_file():
        raise ControlledNetworkError(f"{label} is not a regular file: {path}")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    if temporary.exists() or temporary.is_symlink():
        temporary.unlink()
    try:
        temporary.write_text(json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True) + "\n",encoding="utf-8")
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        if temporary.exists() or temporary.is_symlink():
            temporary.unlink()


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()
