"""Resource limits for the unified sandbox."""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import resource
import shutil
import subprocess

from experiments.execution_capsule_probe import controller as probe

CGROUP = Path("/sys/fs/cgroup")
PROPERTIES = "LoadState,ActiveState,Result,ExecMainCode,ExecMainStatus,ControlGroup,MemoryPeak"


def policy(memory_mib=1024, seconds=70):
    probe.require(type(memory_mib) is int and 256 <= memory_mib <= 4096,
                  "Capsule memory limit must be an integer between 256 and 4096 MiB")
    probe.require(type(seconds) is int and 20 <= seconds <= 900, "Invalid capsule service lifetime")
    return {"backend": "systemd-system-service-v1", "memory_bytes": memory_mib * 1024 * 1024,
            "swap_bytes": 0, "tasks": 64, "seconds": seconds}


def validate(config):
    expected = policy(config["memory_bytes"] // (1024 * 1024), config["seconds"])
    probe.require(config == expected, "Unsupported capsule resource policy")


def preflight():
    for name in ("systemd-run", "systemctl", "sudo"):
        probe.require(shutil.which(name), "Missing lifecycle runtime dependency: " + name)
    probe.require((CGROUP / "cgroup.controllers").is_file() and Path("/run/systemd/system").is_dir(),
                  "Unified lifecycle requires systemd and cgroup v2")


def unit_name(binding):
    nonce = binding["lifecycle_attempt"]
    probe.require(isinstance(nonce, str) and re.fullmatch(r"[0-9a-f]{32}", nonce), "Invalid capsule service identity")
    return "taintforge-capsule-" + nonce + ".service"


def command(binding, sandbox_command):
    config = binding["settings"]["resources"]
    validate(config)
    probe.require(sandbox_command[:2] == ["sudo", "unshare"], "Resource service requires the isolated unified wrapper")
    properties = {"MemoryMax": config["memory_bytes"], "MemorySwapMax": 0, "OOMPolicy": "kill",
                  "TasksMax": config["tasks"], "KillMode": "control-group", "TimeoutStopSec": "5s",
                  "RuntimeMaxSec": f"{config['seconds']}s", "LimitCORE": 0, "CoredumpFilter": "0x0",
                  "NoNewPrivileges": "yes", "UMask": "0077", "Slice": "system.slice"}
    return ["sudo", "systemd-run", "--quiet", "--wait", "--pipe", "--service-type=exec",
            "--expand-environment=no", "--unit=" + unit_name(binding),
            *[f"--property={key}={value}" for key, value in properties.items()], *sandbox_command[1:]]


def inspect_self(binding):
    """Executed before forking the controller or starting QEMU, inside the service."""
    config = binding["settings"]["resources"]
    validate(config)
    expected_group = "/system.slice/" + unit_name(binding)
    probe.require(Path("/proc/self/cgroup").read_text().splitlines() == ["0::" + expected_group],
                  "Capsule supervisor is outside its bound service cgroup")
    directory = CGROUP / expected_group.lstrip("/")
    expected = {"memory.max": str(config["memory_bytes"]), "memory.swap.max": "0",
                "memory.oom.group": "1", "pids.max": str(config["tasks"])}
    actual = {name: (directory / name).read_text().strip() for name in expected}
    probe.require(actual == expected, "Kernel resource limits differ from the bound policy")
    status = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines())
    probe.require(status["NoNewPrivs"].strip() == "1" and resource.getrlimit(resource.RLIMIT_CORE) == (0, 0),
                  "Required process restrictions are not active")
    result = {"status": "verified", "attempt_id": binding["attempt_id"],
              "attempt_contract_sha256": binding["attempt_contract_sha256"],
              "unit": unit_name(binding), "cgroup": expected_group, "limits": actual,
              "no_new_privs": True, "core_rlimit": [0, 0],
              "memory_isolation": False, "hostile_sample_ready": False}
    probe.write_json(Path(binding["run_dir"]) / "logs/capsule/resources.json", result)
    return result


def control(*args):
    result = subprocess.run(list(args), stdin=subprocess.DEVNULL, capture_output=True,
                            text=True, timeout=15, check=False)
    return result


def status(unit):
    result = control("systemctl", "show", unit, "--property=" + PROPERTIES)
    return dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)


def execute(binding, sandbox_command, executor, **kwargs):
    """Always stop only this attempt's unit; a missing exit file remains a failure."""
    unit = unit_name(binding)
    destination = Path(binding["run_dir"]) / "logs/capsule/service.json"
    report = {"status": "failed", "unit": unit, "attempt_id": binding["attempt_id"],
              "attempt_contract_sha256": binding["attempt_contract_sha256"], "tree_empty": False}
    try:
        argv = command(binding, sandbox_command)
        report["command"] = argv
        result = executor.run(argv, **kwargs)
        report.update(wrapper_exit=result.returncode, service=status(unit))
        return result
    except BaseException as exc:
        report["error"] = f"{type(exc).__name__}: {exc}"[-3000:]
        raise
    finally:
        try:
            stop = control("sudo", "-n", "systemctl", "stop", unit)
            after = status(unit)
            probe.require(after.get("LoadState") == "not-found" or after.get("ActiveState") in {"inactive", "failed"},
                          "Capsule service cleanup was not confirmed: " + stop.stderr[-1000:])
            path = CGROUP / "system.slice" / unit / "cgroup.events"
            probe.require(not path.exists() or "populated 0" in path.read_text().splitlines(),
                          "Capsule cgroup still contains processes")
            report.update(tree_empty=True, after_cleanup=after,
                          status="failed" if "error" in report else "verified")
            control("sudo", "-n", "systemctl", "reset-failed", unit)
        except (OSError, RuntimeError, subprocess.TimeoutExpired) as exc:
            report.update(status="failed", cleanup_error=f"{type(exc).__name__}: {exc}")
        probe.write_json(destination, report)


def verify_saved(binding, guest_exit):
    output = Path(binding["run_dir"]) / "logs/capsule"
    actual = json.loads((output / "resources.json").read_text())
    service = json.loads((output / "service.json").read_text())
    config = binding["settings"]["resources"]
    validate(config)
    for record in (actual, service):
        probe.require(record["status"] == "verified" and record["unit"] == unit_name(binding)
            and record["attempt_id"] == binding["attempt_id"]
            and record["attempt_contract_sha256"] == binding["attempt_contract_sha256"],
            "Resource evidence identity or verification failed")
    probe.require(service["tree_empty"] is True and service.get("wrapper_exit") == guest_exit
                  and "error" not in service and "cleanup_error" not in service,
                  "Service failed or process-tree cleanup was not confirmed")
    expected = {"memory.max": str(config["memory_bytes"]), "memory.swap.max": "0",
                "memory.oom.group": "1", "pids.max": str(config["tasks"])}
    probe.require(actual["limits"] == expected and actual["cgroup"] == "/system.slice/" + unit_name(binding)
                  and actual["no_new_privs"] is True and actual["core_rlimit"] == [0, 0]
                  and actual["memory_isolation"] is False and actual["hostile_sample_ready"] is False,
                  "Saved resource restrictions differ from the policy")
    outcome = service["service"].get("Result")
    probe.require(outcome not in {"oom-kill", "timeout", "watchdog", "signal", "core-dump"},
                  "Capsule service terminated abnormally: " + str(outcome))
    probe.require(outcome == ("success" if guest_exit == 0 else "exit-code")
                  or (guest_exit == 0 and service["service"].get("LoadState") == "not-found"),
                  "Service result does not match the observed exit")
    return {"status": "verified", "limits": expected, "tree_empty": True, "unit": unit_name(binding),
            "evidence_sha256": {name: probe.sha(output / name) for name in ("resources.json", "service.json")}}
