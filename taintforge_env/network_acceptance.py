"""Run the existing network acceptance suites and retain their evidence boundaries."""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import uuid


UNIT_TESTS = tuple("tests." + name for name in (
    "test_network_acceptance", "test_network_capsule_sessions", "test_network_stability", "test_network_modes", "test_network_evidence",
    "test_network_delivery", "test_network_replay", "test_replay_store", "test_replay_cli",
    "test_dns_udp_replay", "test_unresolved_network_requirements",
    "test_network_endpoints", "test_network_observer_binding", "test_network_repairs",
    "test_network_sessions", "test_network_runtime", "test_network_runtime_lifecycle",
    "test_network_runtime_runner", "test_network_runtime_diagnostics", "test_network_runtime_acceptance",
    "test_network_owner_status_confirmation",
    "test_network_owner_diagnostics",
    "test_network_liveness_profile",
    "test_network_host_route", "test_network_namespace", "test_controlled_network_backend",
    "test_controlled_network_cleanup_hotfix", "test_controlled_network_ownership_hotfix",
    "test_controlled_network_selftest_retry", "test_controlled_network_sudo_hotfix",
    "test_network_capsule", "test_network_capsule_bootstrap", "test_network_capsule_pipeline",
    "test_network_capsule_fault_gate", "test_network_capsule_exec_identity",
    "test_network_capsule_repair_fixture.NetworkCapsuleRepairFixtureTests",
    "test_network_capsule_observation_window.ObservationWindowFixtureTests",
)) + (
    "tests.test_network_runtime_ownership.NetworkRuntimeOwnershipTests."
    "test_atomic_replacement_uses_the_existing_owner_before_publication",
    "tests.test_network_runtime_ownership.NetworkRuntimeOwnershipTests."
    "test_control_lock_exists_before_the_descriptor_is_published",
)

CAPSULE_CASES = ("tcp", "udp", "dns_udp", "dns_tcp", "receive_budget", "responder_crash", "timeout", "repair")
SESSION_CASES = ("ordered", "fragmented", "coalesced", "reconnect", "interleaved_connections",
    "wrong_order", "unknown_step", "premature_eof", "idle_timeout", "session_timeout",
    "wrong_response", "trailing_bytes", "receive_budget")
RUNTIME_CASES = ("mixed_protocols", "shared_receive", "shared_send", "log_budget",
    "total_connections", "concurrent_capacity", "responder_crash", "real_host_and_namespace_quota")
REPAIR_CASES = ("tcp", "udp", "dns", "unlisted_endpoint", "wrong_transport",
    "missing_exchange", "wrong_response", "unknown_request")
BASELINE_PATH = "examples/network_acceptance_baseline.json"


@dataclass(frozen=True)
class Check:
    name: str
    coverage: str
    kind: str
    script: str = ""
    tests: tuple[str, ...] = ()
    tools: tuple[str, ...] = ()
    component: bool = False
    qemu: bool = False
    root: bool = False
    namespace: bool = False


CHECKS = (
    Check("unit", "NET-1..NET-9", "component", tests=UNIT_TESTS, component=True),
    Check("record_replay", "record/import/replay", "host_fixture",
          "run_c2_replay_local_e2e.py", tools=("gcc",), component=True, namespace=True),
    Check("dns_udp_replay", "DNS/UDP replay", "host_fixture",
          "run_dns_udp_replay_e2e.py", tools=("gcc",), component=True, namespace=True),
    Check("ownership", "NET-6 UID regression", "native_root", tests=(
          "tests.test_network_runtime_ownership.NetworkRuntimeOwnershipTests."
          "test_root_client_preserves_an_unprivileged_owner_and_terminal_status",), root=True),
    Check("host_route", "NET-6 policy routing", "native_namespace",
          tests=("tests.test_network_host_route_privileged",), root=True, namespace=True),
    Check("qemu_protocols", "NET-6 guest fixtures", "qemu_component",
          tests=("tests.test_network_capsule_guest",
                 "tests.test_network_capsule_repair_fixture.NetworkCapsuleRepairGuestTests",
                 "tests.test_network_capsule_observation_window.ObservationWindowGuestTests"),
          tools=("as", "ld"), qemu=True),
    Check("endpoints", "NET-2", "qemu_loopback", "run_network_endpoint_e2e.py",
          tools=("as", "ld"), qemu=True),
    Check("repairs", "NET-3", "qemu_loopback", "run_network_repair_e2e.py",
          tools=("as", "ld"), qemu=True),
    Check("sessions", "NET-4", "qemu_loopback", "run_network_session_e2e.py",
          tools=("as", "ld"), qemu=True),
    Check("runtime", "NET-5", "qemu_namespace", "run_network_runtime_e2e.py",
          tools=("as", "ld"), qemu=True, namespace=True),
    Check("capsule", "NET-6", "native_phase1_retirement_capsule_network",
          "run_network_capsule_e2e.py", tools=("as", "ld"), qemu=True, namespace=True),
    Check("capsule_sessions", "NET-8", "native_phase1_retirement_capsule_sessions",
          "run_network_capsule_sessions_e2e.py", tools=("as", "ld"), qemu=True, namespace=True),
    Check("stability", "NET-9", "repeated_native_network_capsules",
          "run_network_stability_e2e.py", tools=("as", "ld"), qemu=True, namespace=True),
)


class AcceptanceError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise AcceptanceError(message)


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def read_json(path):
    path = Path(path)
    require(not path.is_symlink() and path.is_file(), f"missing regular JSON report: {path}")
    require(path.stat().st_size <= 16 * 1024 * 1024, f"JSON report exceeds 16 MiB: {path}")
    value = json.loads(path.read_text())
    require(isinstance(value, dict), f"expected JSON object: {path}")
    return value


def write_json(path, value):
    path = Path(path)
    fd, temporary = tempfile.mkstemp(prefix=".report-", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as stream:
            json.dump(value, stream, indent=2, ensure_ascii=False)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def source_identity(project):
    files = {}
    for folder in ("taintforge_env", "scripts", "tests", "samples", "network", "examples", "experiments"):
        for path in sorted((project / folder).rglob("*")):
            if "__pycache__" in path.parts or path.suffix not in {".py", ".c", ".h", ".S", ".sh", ".json"}:
                continue
            require(not path.is_symlink(), f"source inventory contains a symlink: {path}")
            if path.is_file():
                files[path.relative_to(project).as_posix()] = digest(path)
    if (project / "makefile").is_file():
        files["makefile"] = digest(project / "makefile")
    encoded = json.dumps(files, sort_keys=True, separators=(",", ":")).encode()
    return {"sha256": hashlib.sha256(encoded).hexdigest(), "files": files}


def baseline_identity(project):
    baseline = read_json(project / BASELINE_PATH)
    require(baseline.get("schema_version") == 1 and baseline.get("reference") == "NET-6 routecheck 2026-11-11",
            "unsupported network baseline")
    expected = baseline.get("files")
    require(isinstance(expected, dict) and bool(expected), "empty network baseline")
    missing, modified = [], []
    for name, expected_hash in expected.items():
        relative = Path(name)
        require(not relative.is_absolute() and ".." not in relative.parts, "invalid baseline path")
        path = project / relative
        if not path.is_file() or path.is_symlink():
            missing.append(name)
        elif digest(path) != expected_hash:
            modified.append(name)
    return {"reference": baseline["reference"], "manifest_sha256": digest(project / BASELINE_PATH),
            "status": "missing" if missing else "modified" if modified else "matched",
            "missing": missing, "modified": modified,
            "accepted_runtime_reference": baseline.get("accepted_runtime_reference", {})}


def runtime_identity(paths):
    result = {}
    for name, value in paths.items():
        if value is None:
            result[name] = {"status": "not_supplied"}
            continue
        path = Path(value).expanduser().absolute()
        try:
            require(path.is_file(), f"missing {name}: {path}")
            item = {"status": "recorded", "path": str(path), "resolved_path": str(path.resolve()),
                    "sha256": digest(path), "size": path.stat().st_size}
            if name == "qemu":
                version = subprocess.run([str(path), "--version"], capture_output=True, text=True, timeout=5)
                require(version.returncode == 0 and bool(version.stdout.strip()), "QEMU --version failed")
                item["version"] = version.stdout.splitlines()[0]
            elif name == "observer":
                from .network_observer import validate_observer
                metadata = validate_observer(path)
                item.update(plugin_api=metadata["plugin_api"], build_id=metadata["build_id"],
                            metadata_sha256=digest(Path(str(path) + ".observer.json")))
            result[name] = item
        except (OSError, ValueError, subprocess.SubprocessError) as exc:
            result[name] = {"status": "unavailable", "path": str(path), "error": str(exc)}
    return result


def prerequisites(check, profile, runtime):
    problems = []
    if platform.system() != "Linux":
        problems.append("Linux is required")
    if check.name in {"record_replay", "dns_udp_replay"} and platform.machine() not in {"x86_64", "amd64"}:
        problems.append("the static host client requires x86-64")
    tools = set(check.tools)
    namespace = check.namespace and profile == "full"
    if namespace:
        tools.update(("sudo", "ip", "iptables"))
    if check.root and os.geteuid() != 0:
        tools.add("sudo")
    if check.name in {"record_replay", "dns_udp_replay"} and namespace:
        tools.update(("unshare", "mount", "umount", "chroot", "strace"))
    if check.name in {"capsule", "capsule_sessions", "stability"}:
        tools.update(("systemd-run", "systemctl", "unshare", "mount", "umount", "chroot"))
        if not Path("/run/systemd/system").is_dir() or not Path("/sys/fs/cgroup/cgroup.controllers").is_file():
            problems.append("systemd system manager and cgroup v2 are required")
    problems.extend("missing executable: " + name for name in sorted(tools) if not shutil.which(name))
    if (namespace or check.root) and "sudo" in tools and shutil.which("sudo"):
        try:
            ready = subprocess.run(["sudo", "-n", "true"], stdin=subprocess.DEVNULL,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=5)
            if ready.returncode:
                problems.append("sudo -n is unavailable; authenticate with sudo -v before the run")
        except (OSError, subprocess.SubprocessError) as exc:
            problems.append("sudo preflight: " + str(exc))
    names = ("qemu", "observer", "plugin") if check.name in {"capsule", "capsule_sessions", "stability"} else ("qemu", "observer") if check.qemu else ()
    problems.extend(name + ": " + runtime.get(name, {}).get("status", "not_supplied")
                    for name in names if runtime.get(name, {}).get("status") != "recorded")
    return problems


def command_for(check, project, directory, profile, runtime, run_id):
    env = {**os.environ, "PYTHONPATH": str(project), "PYTHONUNBUFFERED": "1", "LC_ALL": "C"}
    for name in ("TF_NET6_QEMU", "TF_NET6_OBSERVER", "TF_NET6_COMPONENT_REPORT"):
        env.pop(name, None)
    if check.tests:
        report = directory / "tests.json"
        report.touch(mode=0o600, exist_ok=False)
        command = [sys.executable, str(project / "scripts/run_network_acceptance_tests.py"),
                   "--report", str(report), "--run-id", run_id]
        for name in check.tests:
            command.extend(("--test", name))
        if check.qemu:
            env.update(TF_NET6_QEMU=runtime["qemu"]["path"], TF_NET6_OBSERVER=runtime["observer"]["path"],
                       TF_NET6_COMPONENT_REPORT=str(directory / "qemu-components.json"))
        if check.root and os.geteuid() != 0:
            command = ["sudo", "-n", "env", "PYTHONPATH=" + str(project), "LC_ALL=C", *command]
    else:
        output = directory / "result"
        report = output / "report.json"
        command = [sys.executable, str(project / "scripts" / check.script), "--out", str(output)]
        if check.qemu:
            command.extend(("--qemu", runtime["qemu"]["path"], "--observer", runtime["observer"]["path"]))
        if check.name in {"capsule", "capsule_sessions", "stability"}:
            command.extend(("--plugin", runtime["plugin"]["path"]))
        if check.name in {"record_replay", "dns_udp_replay"} and profile == "full":
            command.append("--sandbox")
        if check.name == "runtime":
            command.append("--privileged")
    return command, env, report


def case_map(data, names, key="case"):
    cases = data.get("cases")
    require(isinstance(cases, list), "missing cases list")
    require(all(isinstance(case, dict) for case in cases), "malformed case")
    actual = [case.get(key) for case in cases]
    require(Counter(actual) == Counter(names), "missing, duplicate or unexpected cases")
    require(all(case.get("status") == "passed" for case in cases), "a child case did not pass")
    return {case[key]: case for case in cases}


def validate_unittest(data, check, run_id):
    require(data.get("schema_version") == 1 and data.get("kind") == "network_unittest_result",
            "invalid unittest report contract")
    require(data.get("run_id") == run_id and data.get("requested") == list(check.tests),
            "unittest report belongs to another invocation")
    require(type(data.get("tests_run")) is int and data["tests_run"] >= 0, "invalid unittest count")
    require(isinstance(data.get("discovered"), list) and bool(data["discovered"]), "no tests discovered")
    require(data.get("failures") == [] and data.get("errors") == [] and data.get("unexpected_successes") == [],
            "unittest errors, failures or unexpected successes")
    require(type(data.get("execution_uid")) is int, "missing unittest execution UID")
    if check.root:
        require(data["execution_uid"] == 0, "privileged check did not execute as root")
    require(isinstance(data.get("skipped"), list) and isinstance(data.get("expected_failures"), list),
            "missing unittest skip accounting")
    if data["skipped"] or data["expected_failures"]:
        return "skipped"
    require(data.get("status") == "passed" and data["tests_run"] == len(data["discovered"]),
            "unittest execution is incomplete")
    return "passed"


def validate_capsule(data, runtime):
    require(data.get("scope") == "native_phase1_retirement_capsule_network", "wrong NET-6 evidence scope")
    require(data.get("plugin_api") == 6, "missing or incompatible NET-6 plugin API")
    require(all(data.get(name) is True for name in ("phase1_executed", "capsule_executed", "namespace_executed")),
            "NET-6 did not execute all required components")
    require(data.get("oep_proven") is False and data.get("hostile_sample_ready") is False,
            "unsupported NET-6 claims")
    require(data.get("guest_executions") == 9 and data.get("qemu_launch_attempts") == 9, "NET-6 requires nine guest executions")
    expected = {runtime[name]["resolved_path"]: runtime[name]["sha256"] for name in ("qemu", "plugin", "observer")}
    require(data.get("runtime_sha256") == expected, "NET-6 used different runtime binaries")
    cases = case_map(data, CAPSULE_CASES)
    reasons = {"receive_budget": "network_receive_budget_exceeded", "responder_crash": "network_responder_exited",
               "timeout": "network_capsule_timeout"}
    for name, case in cases.items():
        attempts = case.get("attempts")
        count = 2 if name == "repair" else 1
        require(isinstance(attempts, list) and len(attempts) == count and case.get("guest_executions") == count,
                "wrong NET-6 attempt count: " + name)
        require(case.get("store_unchanged") is True and case.get("resume_blocked") is (name in reasons),
                "NET-6 store or resume invariant failed: " + name)
        for index, attempt in enumerate(attempts):
            require(all(attempt.get(field) is True for field in ("phase1_executed", "capsule_executed",
                    "namespace_executed", "phase1_retired", "capsule_tree_empty", "namespace_removed", "veth_removed")),
                    "NET-6 execution or cleanup evidence is incomplete: " + name)
            require(attempt.get("network_cleanup") == "cleaned", "NET-6 network was not cleaned: " + name)
            require(attempt.get("termination_reason") == reasons.get(name), "unexpected NET-6 stop reason: " + name)
            goal = name not in reasons and (name != "repair" or index == 1)
            require(attempt.get("goal_reached") is goal, "unexpected NET-6 application outcome: " + name)
            observer = attempt.get("observer", {}).get("status")
            require(observer == "correlated" or (name in {"responder_crash", "timeout"} and observer == "incomplete"),
                    "missing NET-6 observer result: " + name)


def validate_qemu_components(data, runtime):
    cases = case_map(data, CAPSULE_CASES[:4])
    require(data.get("scope") == "actual_qemu_components" and all(data.get(key) is False for key in
            ("phase1_executed", "capsule_executed", "namespace_executed")), "wrong QEMU component scope")
    for name, case in cases.items():
        require(case.get("guest_executed") is True and case.get("observer_status") == "correlated"
                and case.get("cleanup_status") == "cleaned"
                and case.get("plugin_api") == runtime["observer"]["plugin_api"],
                "incomplete QEMU protocol evidence: " + name)


def validate_report(check, data, profile, run_id, runtime):
    if check.tests:
        return validate_unittest(data, check, run_id)
    require(data.get("status") == "passed", "child report did not pass")
    if check.name == "stability":
        from .network_stability import validate_result
        validate_result(data, runtime)
    elif check.name == "capsule_sessions":
        from .network_capsule_sessions import validate_result
        validate_result(data, runtime)
    elif check.name == "capsule":
        validate_capsule(data, runtime)
    elif check.name in {"repairs", "sessions", "runtime"}:
        require(data.get("phase1_executed") is False and data.get("capsule_executed") is False,
                "component test claims a capsule execution")
        require(data.get("namespace_executed") is (check.name == "runtime"), "wrong namespace evidence scope")
        if check.name == "repairs":
            cases = data.get("cases", [])
            require(all(isinstance(case, dict) for case in cases), "invalid repair cases")
            identified = {**data, "cases": [{**case, "case": case.get("fault") or case.get("transport_case")} for case in cases]}
            case_map(identified, REPAIR_CASES)
        else:
            cases = case_map(data, SESSION_CASES if check.name == "sessions" else RUNTIME_CASES)
            if check.name == "sessions":
                require(data.get("guest_executions") == 26, "NET-4 requires twenty-six guest executions")
                require(all(case.get("store_unchanged") is True for case in cases.values()), "NET-4 changed a replay store")
    elif check.name == "endpoints":
        require(data.get("guest_executed") is True and data.get("phase1_executed") is False
                and data.get("namespace_executed") is False, "wrong endpoint execution evidence")
        require(data.get("observer_status", {}).get("status") == "correlated" and data.get("udp_packets") == 5,
                "endpoint observer did not correlate all messages")
    elif check.name == "record_replay":
        require(all(data.get(key) is True for key in ("prebuilt_validated", "synthesis_binding_verified",
                "upstream_stopped_before_replay", "corrupt_capture_rejected")), "incomplete capture/replay evidence")
        require(data.get("sandbox_executed") is (profile == "full"), "wrong capture/replay namespace scope")
    elif check.name == "dns_udp_replay":
        local = data.get("local", {})
        require(local.get("recording_client") == local.get("offline_client") == "passed", "DNS/UDP client failed")
        require(local.get("upstream_stopped_before_replay") is True and local.get("unknown_dns_rejected") is True,
                "missing offline DNS evidence")
        require(data.get("sandbox_executed") is (profile == "full"), "wrong DNS namespace scope")
        if profile == "full":
            require(all(data.get("sandbox", {}).get(key) is True for key in
                    ("record_executed", "replay_executed", "tcp_udp_dnat", "dns_tcp_fallback")),
                    "incomplete native DNS/UDP evidence")
    return "passed"


def run_child(command, env, project, stdout, stderr):
    with stdout.open("wb") as out, stderr.open("wb") as err:
        # Keep the caller's terminal session so sudo can use its timestamp ticket.
        process = subprocess.Popen(command, cwd=project, env=env, stdin=subprocess.DEVNULL,
                                   stdout=out, stderr=err, process_group=0)
        try:
            return process.wait()
        except BaseException:
            # Give the existing fixture's finally blocks time to close owned resources.
            for sig, seconds in ((signal.SIGINT, 15), (signal.SIGTERM, 5), (signal.SIGKILL, 5)):
                if process.poll() is not None:
                    break
                try:
                    os.killpg(process.pid, sig)
                    process.wait(timeout=seconds)
                    break
                except ProcessLookupError:
                    break
                except subprocess.TimeoutExpired:
                    continue
            raise


def child_failure(code, data):
    messages = []
    if isinstance(data.get("error"), str) and data["error"]:
        messages.append(data["error"][:2000])
    cases = data.get("cases")
    if isinstance(cases, list):
        for case in cases:
            if isinstance(case, dict) and case.get("status") not in {None, "passed"}:
                name = str(case.get("case", "case"))[:120]
                error = case.get("error", case.get("reason", case.get("status")))
                messages.append(name + ": " + str(error)[:2000])
                if len(messages) == 4:
                    break
    suffix = "; ".join(messages)
    return f"child exited with status {code}" + (": " + suffix if suffix else "")


def aggregate(checks, profile, *, stable=True, interrupted=False, fatal=None):
    statuses = [check["status"] for check in checks]
    matrix_complete = Counter(check["name"] for check in checks) == Counter(check.name for check in CHECKS)
    if interrupted:
        status = "interrupted"
    elif fatal or not stable or "failed" in statuses:
        status = "failed"
    elif "blocked" in statuses:
        status = "blocked"
    elif profile != "full" or not matrix_complete or any(status != "passed" for status in statuses):
        status = "incomplete"
    else:
        status = "passed"
    return {"status": status, "full_acceptance": status == "passed", "matrix_complete": matrix_complete,
            "counts": dict(Counter(statuses)),
            "exit_code": 130 if interrupted else 1 if status == "failed" else 0 if status == "passed" else 2}


def publish(out, report):
    write_json(out / "report.json", report)
    lines = ["# Network acceptance", "", f"Status: **{report['status']}**", "",
             f"Profile: `{report['profile']}`. Full acceptance: `{str(report['full_acceptance']).lower()}`.", "",
             "| Check | Coverage | Execution scope | Status | Evidence |", "|---|---|---|---|---|"]
    for item in report["checks"]:
        evidence = "[report](" + item["report"] + ")" if "report" in item else ""
        lines.append(f"| {item['name']} | {item['coverage']} | {item['kind']} | {item['status']} | {evidence} |")
    for item in report["checks"]:
        if item.get("reason"):
            lines.extend(("", item["name"] + ": " + item["reason"].replace("\n", " ")))
    lines += ["", "Component and loopback checks do not establish Phase 1 retirement or namespace execution.",
              "The NET-6 report retains application outcomes, expected interruptions and incomplete observer evidence.",
              "Claims: `oep_proven=false`, `hostile_sample_ready=false`.", ""]
    (out / "report.md").write_text("\n".join(lines))


def run_acceptance(project, out, *, profile="full", qemu=None, plugin=None, observer=None):
    require(profile in {"full", "component"}, "unknown acceptance profile")
    project = Path(project).resolve(strict=True)
    out = Path(out).expanduser().absolute()
    require(not out.is_symlink(), "output cannot be a symlink")
    out.mkdir(parents=True, exist_ok=False, mode=0o700)
    run_id = uuid.uuid4().hex
    paths = {"qemu": qemu, "plugin": plugin, "observer": observer}
    checks = [{"name": check.name, "coverage": check.coverage,
               "kind": "host_namespace" if check.component and check.namespace and profile == "full"
                       else "host_loopback" if check.kind == "host_fixture" else check.kind,
               "required": True, "status": "not_run"} for check in CHECKS]
    report = {"schema_version": 1, "run_id": run_id, "profile": profile, "status": "running",
              "full_acceptance": False, "project": str(project), "checks": checks,
              "claims": {"oep_proven": False, "hostile_sample_ready": False},
              "environment": {"python": sys.version, "python_executable": sys.executable,
                              "kernel": platform.release(), "machine": platform.machine(), "uid": os.geteuid()}}
    publish(out, report)
    started = time.monotonic()
    source_before = runtime_before = None
    stable, interrupted, fatal = True, False, None
    current = None
    try:
        report["baseline"] = baseline_identity(project)
        require(not report["baseline"]["missing"], "missing baseline files: " + ", ".join(report["baseline"]["missing"]))
        source_before = source_identity(project)
        write_json(out / "source.json", source_before)
        report["source"] = {"manifest": "source.json", "sha256": source_before["sha256"], "files": len(source_before["files"])}
        runtime_before = runtime_identity(paths)
        report["runtime"] = runtime_before
        for check, current in zip(CHECKS, checks):
            if profile == "component" and not check.component:
                current["reason"] = "not selected by the component profile"
                continue
            problems = prerequisites(check, profile, runtime_before)
            if problems:
                current.update(status="blocked", reason="; ".join(problems))
                publish(out, report)
                print(check.name + ": blocked — " + current["reason"], flush=True)
                continue
            directory = out / check.name
            directory.mkdir(mode=0o700)
            command, env, result_path = command_for(check, project, directory, profile, runtime_before, run_id)
            current.update(status="running", command=command,
                           stdout=(directory / "stdout.log").relative_to(out).as_posix(),
                           stderr=(directory / "stderr.log").relative_to(out).as_posix())
            publish(out, report)
            print(check.name + ": running", flush=True)
            step_start = time.monotonic()
            try:
                code = run_child(command, env, project, directory / "stdout.log", directory / "stderr.log")
                current["returncode"] = code
                data = read_json(result_path)
                current.update(report=result_path.relative_to(out).as_posix(), report_sha256=digest(result_path))
                if code == 2 and check.name in {"capsule", "capsule_sessions", "stability"} and data.get("status") == "blocked":
                    current.update(status="blocked", reason=str(data.get("error", "native capsule preflight blocked")))
                else:
                    require(code == 0, child_failure(code, data))
                    current["status"] = validate_report(check, data, profile, run_id, runtime_before)
                    if check.tests:
                        current.update(tests_run=data["tests_run"], skipped=data["skipped"], expected_failures=data["expected_failures"])
                        if current["status"] == "skipped":
                            current["reason"] = "mandatory tests were skipped or reported expected failures"
                    if check.name == "qemu_protocols" and current["status"] == "passed":
                        component_path = directory / "qemu-components.json"
                        components = read_json(component_path)
                        validate_qemu_components(components, runtime_before)
                        current.update(component_report=component_path.relative_to(out).as_posix(),
                                       component_report_sha256=digest(component_path))
            except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as exc:
                current.update(status="failed", reason=f"{type(exc).__name__}: {exc}")
            finally:
                current["elapsed_seconds"] = round(time.monotonic() - step_start, 3)
            publish(out, report)
            print(check.name + ": " + current["status"], flush=True)
            if current["status"] == "failed":
                for remaining in checks:
                    if remaining["status"] == "not_run":
                        remaining["reason"] = "stopped after " + check.name + " failed"
                break
    except KeyboardInterrupt:
        interrupted = True
        if current is not None and current["status"] == "running":
            current.update(status="interrupted", reason="interrupted; cleanup is not certified by this runner")
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        fatal = f"{type(exc).__name__}: {exc}"
        report["error"] = fatal
    finally:
        try:
            if source_before is not None:
                source_after = source_identity(project)
                report["source"]["unchanged"] = source_before == source_after
                stable = stable and report["source"]["unchanged"]
                if not stable:
                    write_json(out / "source-after.json", source_after)
            if runtime_before is not None:
                runtime_after = runtime_identity(paths)
                report["runtime_unchanged"] = runtime_before == runtime_after
                stable = stable and report["runtime_unchanged"]
                if not report["runtime_unchanged"]:
                    report["runtime_after"] = runtime_after
        except (OSError, ValueError) as exc:
            stable = False
            report["identity_error"] = str(exc)
        report.update(aggregate(checks, profile, stable=stable, interrupted=interrupted, fatal=fatal))
        report["elapsed_seconds"] = round(time.monotonic() - started, 3)
        publish(out, report)
    return report
