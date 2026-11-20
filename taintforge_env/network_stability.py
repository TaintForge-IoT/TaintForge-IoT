"""NET-9 repeated native evidence and read-only, attempt-bound cleanup audits."""
from __future__ import annotations

from collections import Counter
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import subprocess

from .network_acceptance import read_json, require, validate_capsule
from .network_capsule_sessions import validate_result as validate_sessions
from .network_namespace import namespace_exists, namespace_identity


SCOPE = "repeated_native_network_capsules"
DEFAULT_ROUNDS = 3
MAX_ROUNDS = 10
ATTEMPTS_PER_ROUND = 22
IDENTITIES = ("attempt_id", "analysis_instance_id", "lifecycle_attempt")
SUITES = ("capsule", "capsule_sessions")
PROC = Path("/proc")
CGROUP = Path("/sys/fs/cgroup")


def fingerprint(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _rows(*args):
    result = subprocess.run(["ip", "-j", *args], stdin=subprocess.DEVNULL,
                            capture_output=True, text=True, timeout=5)
    require(result.returncode == 0, "network inspection failed: " + result.stderr[:1000])
    require(len(result.stdout) <= 8 * 1024 * 1024, "network inspection exceeds 8 MiB")
    rows = json.loads(result.stdout)
    require(isinstance(rows, list) and all(isinstance(row, dict) for row in rows), "invalid ip JSON")
    return rows


def host_snapshot():
    identity = (PROC / "self/ns/net").stat()
    return {"namespace": {"device": identity.st_dev, "inode": identity.st_ino},
            "rules": _rows("-4", "rule", "show"),
            "routes": _rows("-4", "route", "show", "table", "all"),
            "links": _rows("link", "show")}


def process_groups(groups):
    """Inspect exact recorded groups; unreadable procfs is not an empty group."""
    result = {group: [] for group in groups}
    for entry in PROC.iterdir():
        if not entry.name.isdecimal():
            continue
        try:
            raw = (entry / "stat").read_text()
        except (FileNotFoundError, ProcessLookupError):
            continue
        fields = raw[raw.rfind(")") + 2:].split()
        require(len(fields) >= 20, "truncated procfs stat")
        group = int(fields[2])
        if group in result and fields[0] != "Z":
            result[group].append({"pid": int(entry.name), "start": fields[19]})
    return result


def cgroup_empty(unit):
    require(isinstance(unit, str) and re.fullmatch(r"taintforge-capsule-[0-9a-f]{32}\.service", unit),
            "invalid owned capsule unit")
    path = CGROUP / "system.slice" / unit / "cgroup.events"
    try:
        lines = path.read_text().splitlines()
    except FileNotFoundError:
        return True
    values = dict(line.split() for line in lines)
    require(values.get("populated") in {"0", "1"}, "missing cgroup population evidence")
    return values["populated"] == "0"


def capture_ownership(context, backend):
    """Called by the test runner after setup and before the original guest runner."""
    require(backend is not None and backend.plan is not None and backend.runtime is not None,
            "NET-9 needs a prepared controlled backend")
    binding = read_json(context.run_dir / "config/capsule_binding.json")
    require(binding["attempt_id"] == backend.runtime.attempt_id == context.attempt_contract.attempt_id,
            "ownership belongs to another attempt")
    processes = []
    for process in backend.processes:
        require(type(process.proc_pid) is int and process.proc_pid > 0
                and isinstance(process.birth, str) and process.birth.isdecimal()
                and process.poll() is None, "owned responder identity is unavailable")
        processes.append({"group": process.proc_pid, "start": process.birth})
    # A repair's first attempt may have no listeners: the endpoint is not authorized yet.
    plan = backend.plan.to_dict()
    require(len(processes) == sum(bool(plan[key]) for key in ("host_services", "loopback_services", "catch_all_enabled")),
            "responder inventory differs from the prepared policy")
    return {"schema_version": 1, **{key: binding[key] for key in IDENTITIES},
            "namespace": namespace_identity(plan["namespace_name"]), "plan": plan,
            "processes": processes, "unit": "taintforge-capsule-" + binding["lifecycle_attempt"] + ".service"}


def _multiset(rows):
    return Counter(json.dumps(row, sort_keys=True, separators=(",", ":")) for row in rows)


def _owned_routes(rows, plan):
    def matches(row):
        if row.get("dev") == plan["veth_host"]:
            return True
        if row.get("prefsrc") == plan["host_ip"]:
            try:
                return ipaddress.ip_network(row.get("dst", "default"), strict=False) == ipaddress.ip_network(
                    plan["namespace_ip"] + "/32")
            except ValueError:
                return False
        return False
    return [row for row in rows if matches(row)]


def audit_run(run, before, after):
    """Read only. Never delete discovered resources, signal processes or alter rules."""
    ownership = read_json(run / "logs/net9_ownership.json")
    binding = read_json(run / "config/capsule_binding.json")
    backend = read_json(run / "config/network_backend_manifest.json")
    runtime = read_json(run / "logs/network_runtime_status.json")
    contract = read_json(run / "config/network_capsule_runtime.json")
    service = read_json(run / "logs/capsule/service.json")
    require(all(ownership.get(key) == binding.get(key) for key in IDENTITIES), "audit identity differs")
    plan = ownership["plan"]
    require(plan == backend.get("plan"), "audit topology differs from the backend")
    namespace = plan["namespace_name"]
    require(re.fullmatch(r"tf-[0-9a-f]{8}", namespace) and plan["veth_host"] == "tfh" + namespace[3:]
            and plan["veth_namespace"] == "tfn" + namespace[3:], "invalid owned network names")
    require(ownership["namespace"]["name"] == namespace and ownership["namespace"] == contract.get("namespace")
            and contract.get("attempt_id") == binding["attempt_id"], "audit namespace differs from the live contract")
    require(ownership["unit"] == service.get("unit") == "taintforge-capsule-" + binding["lifecycle_attempt"] + ".service"
            and service.get("attempt_id") == runtime.get("attempt_id") == binding["attempt_id"],
            "audit service or runtime identity differs")
    processes = ownership["processes"]
    require(isinstance(processes, list) and all(isinstance(p, dict) and type(p.get("group")) is int
            and p["group"] > 0 and isinstance(p.get("start"), str) and p["start"].isdecimal() for p in processes),
            "invalid responder group evidence")
    groups = [p["group"] for p in processes]
    require(len(groups) == len(set(groups)) == sum(bool(plan[key]) for key in
            ("host_services", "loopback_services", "catch_all_enabled")), "incomplete or duplicate responder group inventory")
    remaining = process_groups(groups) if groups else {}
    route = backend.get("host_reply_routing")
    ledger = run / "config/network_runtime"
    try:
        ledger.lstat()
        ledger_removed = False
    except FileNotFoundError:
        ledger_removed = True
    usage = runtime.get("budget_usage", {})
    checks = {
        "host_namespace_unchanged": before["namespace"] == after["namespace"],
        "host_rules_unchanged": _multiset(before["rules"]) == _multiset(after["rules"]),
        "owned_routes_restored": _multiset(_owned_routes(before["routes"], plan)) == _multiset(_owned_routes(after["routes"], plan)),
        "namespace_removed": not namespace_exists(namespace),
        "veth_removed": not any(row.get("ifname") in {plan["veth_host"], plan["veth_namespace"]} for row in after["links"]),
        "responder_groups_empty": all(not members for members in remaining.values()),
        "capsule_cgroup_empty": cgroup_empty(ownership["unit"]),
        "runtime_ledger_removed": ledger_removed,
        "runtime_closed": runtime.get("owner_closed") is True and runtime.get("cleanup_status") == "cleaned"
            and runtime.get("remaining_resources") == [] and type(runtime.get("remaining_resources_total")) is int
            and runtime["remaining_resources_total"] == 0 and type(runtime.get("ready_listeners")) is int
            and runtime["ready_listeners"] == 0 and type(usage.get("active_jobs")) is int and usage["active_jobs"] == 0,
        "backend_cleaned": backend.get("state") == "cleaned" and backend.get("cleanup_errors") == []
            and (route is None or (isinstance(route, dict) and route.get("status") in {"cleaned", "verified"}
                                  and route.get("remaining_resources") == [])),
    }
    return {"status": "passed" if all(checks.values()) else "failed", **{key: binding[key] for key in IDENTITIES},
            "namespace": namespace, "veth": plan["veth_host"], "unit": ownership["unit"],
            "checks": checks, "responder_groups": processes, "remaining_processes": remaining,
            "ownership_sha256": fingerprint(ownership)}


AUDIT_CHECKS = {"host_namespace_unchanged", "host_rules_unchanged", "owned_routes_restored", "namespace_removed",
                "veth_removed", "responder_groups_empty", "capsule_cgroup_empty", "runtime_ledger_removed",
                "runtime_closed", "backend_cleaned"}


def attempts(suite, case):
    return case["attempts"] if suite == "capsule" else [case["attempt"]]


def validate_round(row, runtime, seen):
    require(isinstance(row, dict) and row.get("status") == "passed", "round did not pass")
    require(type(row.get("index")) is int and 1 <= row["index"] <= MAX_ROUNDS, "invalid round index")
    suites = row.get("suites")
    require(isinstance(suites, dict) and set(suites) == set(SUITES), "missing native suite")
    semantic = {}
    for suite in SUITES:
        data = suites[suite]
        require(isinstance(data, dict) and data.get("status") == "passed" and not data.get("artifact_errors"),
                "native evidence did not pass")
        count = 9 if suite == "capsule" else 13
        require(all(type(data.get(key)) is int for key in ("guest_executions", "qemu_launch_attempts", "plugin_api"))
                and data["guest_executions"] == data["qemu_launch_attempts"] == count and data["plugin_api"] == 6,
                "wrong native execution counts")
        try:
            (validate_capsule if suite == "capsule" else validate_sessions)(data, runtime)
        except (KeyError, TypeError, AttributeError) as exc:
            raise ValueError("malformed native evidence") from exc
        semantic[suite] = []
        for case in data["cases"]:
            require(case.get("audit_errors") == [], "cleanup inspection contains errors")
            native = attempts(suite, case)
            audits = case.get("cleanup_audit")
            require(isinstance(audits, list) and len(audits) == len(native), "missing independent cleanup audit")
            outcomes = []
            for attempt, audit in zip(native, audits):
                require(isinstance(attempt, dict) and isinstance(audit, dict), "malformed attempt or audit")
                for key in IDENTITIES:
                    value = attempt.get(key)
                    message = f"reused or missing {key}: round {row['index']} {suite}/{case['case']}"
                    require(isinstance(value, str) and bool(value), message)
                    # Logical IDs are deterministic within a case's synthesis
                    # session. The lifecycle nonce identifies a fresh execution.
                    identity = value if key == "lifecycle_attempt" else (row["index"], suite, case["case"], value)
                    require(identity not in seen[key], message)
                    require(audit.get(key) == value, "cleanup audit belongs to another attempt")
                    seen[key].add(identity)
                checks = audit.get("checks")
                require(audit.get("status") == "passed" and isinstance(checks, dict) and set(checks) == AUDIT_CHECKS
                        and all(value is True for value in checks.values()), "cleanup audit did not pass")
                namespace = audit.get("namespace")
                require(isinstance(namespace, str) and re.fullmatch(r"tf-[0-9a-f]{8}", namespace)
                        and audit.get("veth") == "tfh" + namespace[3:]
                        and audit.get("unit") == "taintforge-capsule-" + attempt["lifecycle_attempt"] + ".service"
                        and re.fullmatch(r"[0-9a-f]{64}", str(audit.get("ownership_sha256"))), "invalid audit resources")
                groups = audit.get("responder_groups")
                remaining = audit.get("remaining_processes")
                require(isinstance(groups, list) and all(isinstance(p, dict) and type(p.get("group")) is int
                        and p["group"] > 0 and isinstance(p.get("start"), str) and p["start"].isdecimal() for p in groups),
                        "invalid responder process inventory")
                require(len({p["group"] for p in groups}) == len(groups) and isinstance(remaining, dict)
                        and {str(key) for key in remaining} == {str(p["group"]) for p in groups}
                        and all(value == [] for value in remaining.values()), "responder processes remain")
                outcomes.append({key: attempt.get(key) for key in ("goal_reached", "termination_reason", "guest_exit")})
            if suite == "capsule" and case["case"] == "responder_crash":
                fault = case.get("fault")
                require(isinstance(fault, dict) and fault.get("status") == "injected" and fault.get("signal") == "SIGKILL"
                        and fault.get("attempt_id") == native[0]["attempt_id"]
                        and fault.get("namespace") == audits[0].get("namespace")
                        and type(fault.get("procfs_pid")) is int
                        and fault["procfs_pid"] in {p["group"] for p in audits[0].get("responder_groups", [])},
                        "responder crash lacks an owned fault injection receipt")
            summary = {"case": case["case"], "outcomes": outcomes}
            if suite == "capsule_sessions":
                # NET-8 permits a shorter valid prefix when a read crosses the byte budget.
                # TCP chunk boundaries must not turn that expected rejection into flakiness.
                fields = ("terminal", "reason") if case["case"] == "receive_budget" else ("steps", "terminal", "reason")
                summary["connections"] = [{key: connection[key] for key in fields}
                                           for connection in case["transcript"]["connections"]]
            semantic[suite].append(summary)
        semantic[suite].sort(key=lambda item: item["case"])
    return fingerprint(semantic)


def validate_result(data, runtime):
    require(isinstance(data, dict) and data.get("status") == "passed" and data.get("scope") == SCOPE,
            "wrong NET-9 status or scope")
    rounds = data.get("rounds_requested")
    require(type(rounds) is int and DEFAULT_ROUNDS <= rounds <= MAX_ROUNDS, "NET-9 needs at least three rounds")
    require(data.get("full_stability") is True and data.get("source_unchanged") is True
            and data.get("runtime_unchanged") is True, "NET-9 is incomplete or its inputs changed")
    require(data.get("oep_proven") is False and data.get("hostile_sample_ready") is False, "unsupported NET-9 claims")
    expected = {runtime[k]["resolved_path"]: runtime[k]["sha256"] for k in ("qemu", "plugin", "observer")}
    require(data.get("runtime_sha256") == expected, "NET-9 used different runtime binaries")
    for key in ("guest_executions", "qemu_launch_attempts"):
        require(type(data.get(key)) is int and data[key] == rounds * ATTEMPTS_PER_ROUND, "wrong NET-9 execution count")
    require(all(data.get(key) is True for key in ("phase1_executed", "capsule_executed", "namespace_executed")),
            "NET-9 lacks native execution evidence")
    rows = data.get("rounds")
    require(isinstance(rows, list) and len(rows) == rounds, "missing NET-9 rounds")
    seen = {key: set() for key in IDENTITIES}
    signatures = []
    for index, row in enumerate(rows, 1):
        require(isinstance(row, dict) and type(row.get("index")) is int and row["index"] == index, "reordered NET-9 rounds")
        signatures.append(validate_round(row, runtime, seen))
        require(row.get("semantic_sha256") == signatures[-1], "NET-9 semantic signature differs")
    require(len(set(signatures)) == 1, "native outcomes changed between rounds")
