"""Explicit offline network authorizations and immutable service selections."""
from __future__ import annotations

from dataclasses import asdict, replace
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
from urllib.parse import urlsplit

from .network_policy import CatchAllPolicy, NetworkPolicy, NetworkServicePolicy
from .network_replay import validate_replay_policy
from .replay_store import ReplayStore


class NetworkRepairError(ValueError):
    pass


def digest(value) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=True).encode()).hexdigest()


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise NetworkRepairError("duplicate network repair field")
        result[key] = value
    return result


def read_object(path: Path, maximum: int = 256 * 1024) -> tuple[dict, str]:
    path = Path(path).absolute()
    if any(parent.is_symlink() for parent in (path, *path.parents)):
        raise NetworkRepairError("network repair input traverses a symlink")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > maximum:
            raise NetworkRepairError("network repair input must be a bounded regular file")
        data = stream.read(maximum + 1)
    if len(data) > maximum:
        raise NetworkRepairError("network repair input exceeds its byte limit")
    try:
        value = json.loads(data, object_pairs_hook=_object)
    except (ValueError, UnicodeError) as exc:
        raise NetworkRepairError(f"invalid network repair JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise NetworkRepairError("network repair input must be an object")
    return value, hashlib.sha256(data).hexdigest()


def endpoint(resource: str) -> tuple[str, str, int]:
    try:
        parsed = urlsplit(resource)
        port = parsed.port
        address = ipaddress.IPv4Address(parsed.hostname or "")
        host = str(address)
        if (parsed.scheme not in {"tcp", "udp"} or parsed.username is not None
                or parsed.password is not None or parsed.path or parsed.query or parsed.fragment
                or type(port) is not int or not 1 <= port <= 65535
                or resource != f"{parsed.scheme}://{host}:{port}"
                or address.is_unspecified or address.is_multicast or host == "255.255.255.255"):
            raise ValueError("noncanonical endpoint")
    except (ValueError, AttributeError, TypeError) as exc:
        raise NetworkRepairError("network repairs require a canonical IPv4 TCP/UDP endpoint") from exc
    return parsed.scheme, host, port


class NetworkRepairPolicy:
    def __init__(self, path: Path, value: dict, sha256: str):
        self.path, self.sha256 = Path(path).absolute(), sha256
        if set(value) - {"schema_version", "network_mode", "replay_store", "rules"}:
            raise NetworkRepairError("unknown network repair policy field")
        if type(value.get("schema_version")) is not int or value["schema_version"] != 1:
            raise NetworkRepairError("unsupported network repair policy schema")
        self.mode = value.get("network_mode")
        if not isinstance(self.mode, str) or self.mode not in {"replay", "controlled"}:
            raise NetworkRepairError("network repair mode must be replay or controlled")
        rules = value.get("rules")
        if not isinstance(rules, list) or not 1 <= len(rules) <= 128:
            raise NetworkRepairError("network repair policy needs 1..128 explicit rules")
        self.rules = {}
        for rule in rules:
            if not isinstance(rule, dict) or set(rule) - {"resource", "provider", "protocol_hint", "dns_records", "replay_session_id"}:
                raise NetworkRepairError("invalid network repair rule fields")
            transport, host, port = endpoint(rule.get("resource"))
            resource = rule["resource"]
            if resource in self.rules:
                raise NetworkRepairError("duplicate network repair endpoint")
            provider = rule.get("provider")
            if not isinstance(provider, str) or (self.mode, provider) not in {("replay", "replay"), ("controlled", "dns_records")}:
                raise NetworkRepairError("provider is incompatible with the fixed network mode")
            hint = rule.get("protocol_hint")
            if hint is not None and (not isinstance(hint, str) or not re.fullmatch(r"[a-z0-9_.-]{1,64}", hint)):
                raise NetworkRepairError("invalid network repair protocol hint")
            records = rule.get("dns_records")
            if provider == "dns_records":
                if hint not in {None, "dns"} or not isinstance(records, dict) or not 1 <= len(records) <= 128:
                    raise NetworkRepairError("DNS provider requires explicit bounded records")
                hint = "dns"
                from .dns_protocol import build_query, question
                normalized = {}
                for name, addresses in records.items():
                    if not isinstance(name, str) or name != question(build_query(name)).name.lower():
                        raise NetworkRepairError("DNS record names must be canonical")
                    if not isinstance(addresses, list) or not 1 <= len(addresses) <= 16:
                        raise NetworkRepairError("DNS records require 1..16 addresses")
                    try:
                        if any(not isinstance(address, str) for address in addresses):
                            raise ValueError("DNS addresses must be strings")
                        normalized[name] = [str(ipaddress.ip_address(address)) for address in addresses]
                    except (ValueError, TypeError) as exc:
                        raise NetworkRepairError("invalid explicit DNS address") from exc
                records = normalized
            elif records is not None:
                raise NetworkRepairError("replay rules must not define synthetic DNS records")
            session_id = rule.get("replay_session_id")
            if session_id is not None and (provider != "replay" or transport != "tcp" or hint == "dns"
                    or not isinstance(session_id, str) or not re.fullmatch(r"[0-9a-f]{64}", session_id)):
                raise NetworkRepairError("session repairs require an exact TCP replay session identity")
            service = NetworkServicePolicy(service_type=transport, role="net4_session" if session_id else "net3_" + provider,
                remote_ip=host, remote_port=port, domain=None, bind_ip="127.0.0.1",
                bind_port=port, protocol_hint=hint, dns_records=records, replay_session_id=session_id)
            self.rules[resource] = (provider, service)
        self.store_path = None
        self.store_sha256 = None
        store = value.get("replay_store")
        if self.mode == "replay":
            if (not isinstance(store, dict) or set(store) != {"path", "sha256"}
                    or not isinstance(store["path"], str) or not Path(store["path"]).is_absolute()
                    or not isinstance(store["sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", store["sha256"])):
                raise NetworkRepairError("replay repairs require an absolute store path and exact digest")
            store_path = Path(store["path"])
            if any(parent.is_symlink() for parent in (store_path, *store_path.parents)):
                raise NetworkRepairError("authorized replay store traverses a symlink")
            self.store_path, self.store_sha256 = store_path.resolve(strict=False), store["sha256"]
        elif store is not None:
            raise NetworkRepairError("controlled DNS repairs must not contain a replay store")

    @classmethod
    def load(cls, path: Path, expected_sha256: str | None = None):
        value, sha256 = read_object(path)
        if expected_sha256 is not None and sha256 != expected_sha256:
            raise NetworkRepairError("bound network repair policy changed")
        try:
            return cls(path, value, sha256)
        except (ValueError, TypeError, KeyError) as exc:
            raise NetworkRepairError(str(exc)) from exc

    def verify_store(self):
        if self.store_path is None:
            return
        try:
            index, _ = read_object(self.store_path / "index.json", 16 * 1024 * 1024)
            entries = index.get("entries")
            if (type(index.get("schema_version")) is not int or index["schema_version"] != 1
                    or not isinstance(entries, list) or len(entries) > 4096):
                raise NetworkRepairError("authorized store has an invalid schema or entry budget")
            seen = set()
            total = 0
            for entry in entries:
                if not isinstance(entry, dict) or not isinstance(entry.get("entry_id"), str) or entry["entry_id"] in seen:
                    raise NetworkRepairError("authorized store has duplicate or invalid entry identities")
                seen.add(entry["entry_id"])
                request, response = entry.get("request"), entry.get("response")
                if not isinstance(request, dict) or not isinstance(response, dict):
                    raise NetworkRepairError("authorized store has malformed exchange metadata")
                if (not isinstance(request.get("transport"), str) or not isinstance(request.get("remote_ip"), str)
                        or not isinstance(request.get("payload_sha256"), str)
                        or (request.get("protocol_hint") is not None and not isinstance(request["protocol_hint"], str))
                        or not isinstance(response.get("sha256"), str)
                        or not isinstance(response.get("blob_path"), str)):
                    raise NetworkRepairError("authorized store has invalid request/response identities")
                for item, key in ((request, "remote_port"), (request, "payload_size"), (response, "size")):
                    if type(item.get(key)) is not int or item[key] < 0:
                        raise NetworkRepairError("authorized store numeric metadata must be integer values")
                if (type(response.get("close_after_send", True)) is not bool
                        or type(response.get("delay_ms", 0)) is not int):
                    raise NetworkRepairError("authorized store has invalid response controls")
                total += request["payload_size"] + response["size"]
                if total > 64 * 1024 * 1024:
                    raise NetworkRepairError("authorized replay content exceeds the NET-3 64 MiB budget")
            actual = ReplayStore(self.store_path).validate()
        except (OSError, ValueError, RuntimeError) as exc:
            raise NetworkRepairError(f"invalid authorized replay store: {exc}") from exc
        if actual["store_sha256"] != self.store_sha256:
            raise NetworkRepairError("authorized replay store digest changed")

    def selection(self, resource: str) -> dict:
        _, current_sha256 = read_object(self.path)
        if current_sha256 != self.sha256:
            raise NetworkRepairError("network repair policy changed after selection")
        if resource not in self.rules:
            raise NetworkRepairError("no explicit network repair rule for this endpoint")
        provider, service = self.rules[resource]
        entry_ids = []
        selected_session = None
        if provider == "replay":
            self.verify_store()
            store = ReplayStore(self.store_path)
            try:
                validate_replay_policy(policy=NetworkPolicy(services=[service],
                    catch_all=CatchAllPolicy(enabled=False, udp_enabled=False)), replay_store=store)
                if service.replay_session_id is not None:
                    session = store.load_session(service.replay_session_id)
                    selected_session = {"session_id": session.session_id, "steps": len(session.steps),
                                        "limits": asdict(session.limits)}
                    exchanges = []
                else:
                    exchanges = store.exchanges_for_endpoint(transport=service.service_type,
                        remote_ip=service.remote_ip, remote_port=service.remote_port,
                        protocol_hint=service.protocol_hint)
            except (OSError, ValueError, RuntimeError) as exc:
                raise NetworkRepairError(f"authorized replay does not cover this endpoint: {exc}") from exc
            entry_ids = [item.entry.entry_id for item in exchanges]
        return {"policy_sha256": self.sha256, "provider": provider, "service": asdict(service),
                "replay_store_sha256": self.store_sha256, "entry_ids": entry_ids,
                **({"replay_session": selected_session} if selected_session is not None else {})}

    def authorize(self, requirement) -> dict:
        transport, _, _ = endpoint(requirement.resource)
        if (requirement.kind.value != "network" or requirement.status.value != "unmet"
                or not requirement.repairable or requirement.confidence < 0.95
                or dict(requirement.details).get("transport") != transport
                or dict(requirement.details).get("endpoint_resolution") == "unresolved"):
            raise NetworkRepairError("network repair needs an unmet, observed, typed endpoint")
        return self.selection(requirement.resource)


def bound_policy(session_dir: Path) -> NetworkRepairPolicy | None:
    binding = Path(session_dir) / "synthesis_loop.json"
    if not binding.exists() and not binding.is_symlink():
        return None
    value, _ = read_object(binding, 4 * 1024 * 1024)
    path = value.get("network_repair_policy_path")
    sha256 = value.get("network_repair_policy_sha256")
    if path is None and sha256 is None:
        return None
    if not isinstance(path, str) or not isinstance(sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", sha256):
        raise NetworkRepairError("invalid session network repair binding")
    policy = NetworkRepairPolicy.load(Path(path), sha256)
    if policy.mode != value.get("network_mode"):
        raise NetworkRepairError("network repair policy mode differs from the session")
    policy.verify_store()
    return policy


def effective_policy(base: NetworkPolicy, manifest, authorization: NetworkRepairPolicy | None) -> NetworkPolicy:
    if authorization is not None and base.allow_internet:
        raise NetworkRepairError("offline repairs require Internet access to remain disabled")
    services = list(base.services)
    by_endpoint = {(item.service_type, item.remote_ip, item.remote_port): item for item in services}
    for entry in manifest.entries:
        if entry.kind.value != "network_service" or entry.status.value != "active":
            continue
        if authorization is None or not entry.resource_id.startswith("net:"):
            raise NetworkRepairError("active network service has no bound authorization")
        selection = authorization.selection(entry.resource_id[4:])
        if entry.provider != selection["provider"] or entry.value_sha256 != digest(selection):
            raise NetworkRepairError("manifest network service differs from its authorization")
        service = NetworkServicePolicy(**selection["service"])
        key = service.service_type, service.remote_ip, service.remote_port
        if key in by_endpoint:
            if asdict(by_endpoint[key]) != asdict(service):
                raise NetworkRepairError("network repair would replace an existing service")
        else:
            services.append(service)
            by_endpoint[key] = service
    return replace(base, services=services)


def verify_applied_services(session_dir: Path, chain, records):
    """Check that manifest service values still reference the exact application and source plan."""
    if not any(entry.kind.value == "network_service" for manifest in chain for entry in manifest.entries):
        return
    authorization = bound_policy(session_dir)
    by_attempt = {record.attempt_id: record for record in records}
    from .repair_plan import RepairPlan
    for manifest in chain:
        effective_policy(NetworkPolicy(), manifest, authorization)
        for entry in manifest.entries:
            if entry.kind.value != "network_service":
                continue
            selected = authorization.selection(entry.resource_id[4:])
            application_evidence = [item for item in entry.evidence if item.kind.value == "repair_application"]
            if not application_evidence:
                raise NetworkRepairError("network service lacks application evidence")
            for evidence in application_evidence:
                source = by_attempt.get(evidence.attempt_id)
                if source is None or source.index + 1 > manifest.manifest_version:
                    raise NetworkRepairError("network service references another attempt history")
                application_path = Path(session_dir) / f"iterations/{source.index + 1:04d}/repair_application.json"
                application, application_sha256 = read_object(application_path, 4 * 1024 * 1024)
                if application_sha256 != evidence.artifact_sha256:
                    raise NetworkRepairError("network repair application changed")
                plan_path = Path(session_dir) / source.directory / "artifacts/repair_plan.json"
                _, plan_sha256 = read_object(plan_path, 4 * 1024 * 1024)
                plan = RepairPlan.load(plan_path)
                if (application.get("state") != "completed" or application.get("dry_run") is not False
                        or application.get("plan_sha256") != plan_sha256
                        or application.get("requirements_sha256") != plan.source_sha256):
                    raise NetworkRepairError("network repair application is not bound to its source plan")
                decision_id = evidence.evidence_id.removeprefix(evidence.attempt_id + ":repair:")
                decision = next((item for item in plan.decisions if item.decision_id == decision_id), None)
                results = application.get("results")
                if not isinstance(results, list) or not all(isinstance(item, dict) for item in results):
                    raise NetworkRepairError("malformed network application results")
                matches = [item for item in results if item.get("decision_id") == decision_id]
                if (decision is None or not decision.automatic_allowed or len(matches) != 1
                        or matches[0].get("status") not in {"applied", "already_satisfied"}
                        or matches[0].get("network_service") != selected
                        or dict(decision.parameters).get("network_repair") != selected
                        or decision.resource != entry.resource_id[4:]):
                    raise NetworkRepairError("network manifest differs from the selected application")
