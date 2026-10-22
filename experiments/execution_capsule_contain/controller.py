#!/usr/bin/env python3
"""Linux containment acceptance for the fixed capsule fixture, never an arbitrary ELF.

One external supervisor, one transient user service, one bubblewrap sandbox.
The existing retirement suite remains responsible for guest/retirement evidence.
"""
from __future__ import annotations

import argparse
import errno
import hashlib
import json
import mmap
import os
from pathlib import Path, PurePosixPath
import resource
import shutil
import stat
import subprocess
import sys
import time
import uuid

HERE = Path(__file__).resolve().parent
NAMESPACES = ("user", "mnt", "pid", "net", "ipc", "uts")
MIB = 1024 * 1024
CGROUP = Path("/sys/fs/cgroup")
PYTHON = "/usr/bin/python3"
CLAIMS = {"phase1_memory_released": False, "guest_analyzer_memory_separated": False,
          "residue_free": False, "hostile_sample_ready": False,
          "evidence_channel_protected_from_guest": False,
          "seccomp_policy_installed": False, "complete_core_dump_prevention": False}


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def write_json(path, value):
    path = Path(path)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w") as stream:
        json.dump(value, stream, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(path)


def read_json(path):
    fd = os.open(Path(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_size <= MIB, f"Not a bounded regular JSON: {path}")
        data = stream.read(MIB + 1)
    require(len(data) <= MIB, f"JSON grew beyond limit: {path}")
    return json.loads(data)


def run(*argv, check=True, timeout=15):
    result = subprocess.run(list(map(str, argv)), capture_output=True, text=True,
                            stdin=subprocess.DEVNULL, timeout=timeout, check=False)
    require(not check or result.returncode == 0,
            f"Command failed: {argv[0]} ({result.returncode}): {result.stderr[-2000:]}")
    return result


def namespaces():
    return {name: os.readlink(f"/proc/self/ns/{name}") for name in NAMESPACES}


def membership(text):
    lines = text.splitlines()
    require(len(lines) == 1 and lines[0].startswith("0::/"), "Unified cgroup v2 is required")
    path = PurePosixPath(lines[0][3:])
    require(".." not in path.parts and path != PurePosixPath("/"), "A dedicated service cgroup is required")
    return path


def limits(directory, config):
    expected = {"memory.max": config["memory_bytes"], "memory.swap.max": 0,
                "memory.oom.group": 1, "pids.max": 64}
    actual = {key: (Path(directory) / key).read_text().strip() for key in expected}
    require(all(actual[key] == str(value) for key, value in expected.items()),
            f"Kernel limits do not match requested policy: {actual}")
    return actual


def systemd_command(config, script):
    properties = {"MemoryMax": config["memory_bytes"], "MemorySwapMax": 0,
                  "OOMPolicy": "kill", "TasksMax": 64,
                  "LimitCORE": 0, "CoredumpFilter": "0x0", "NoNewPrivileges": "yes",
                  "KillMode": "control-group", "TimeoutStopSec": "5s",
                  "RuntimeMaxSec": f"{config['seconds']}s", "UMask": "0077"}
    command = ["systemd-run", "--user", "--no-ask-password", "--wait", "--pipe",
               "--service-type=exec", "--expand-environment=no", f"--unit={config['unit']}"]
    command += [f"--property={key}={value}" for key, value in properties.items()]
    # No shell, inherited Python path, loader variables, or user startup files.
    return command + ["/usr/bin/env", "-i", "PATH=/usr/bin:/bin", "LC_ALL=C",
                      PYTHON, "-I", "-B", str(script), "_enter", config["config_path"]]


def bubblewrap_command(config, directory):
    command = ["bwrap", "--unshare-user", "--unshare-pid", "--unshare-net",
               "--unshare-ipc", "--unshare-uts", "--disable-userns", "--assert-userns-disabled",
               "--die-with-parent", "--new-session", "--cap-drop", "ALL",
               "--hostname", "capsule", "--clearenv", "--setenv", "PATH", "/usr/bin:/bin",
               "--setenv", "LC_ALL", "C", "--setenv", "HOME", "/tmp",
               "--setenv", "PYTHONDONTWRITEBYTECODE", "1",
               "--ro-bind", "/usr", "/usr"]
    # Support Arch's merged /usr and distributions with real /lib directories.
    for name in ("bin", "sbin", "lib", "lib64"):
        path = Path("/") / name
        if path.is_symlink():
            target = path.resolve(strict=True)
            require(target.is_relative_to("/usr"), f"Unsupported system link: {path}")
            command += ["--symlink", str(target), str(path)]
        elif path.is_dir():
            command += ["--ro-bind", str(path), str(path)]
    command += ["--dir", "/etc"]
    if Path("/etc/ld.so.cache").is_file():
        command += ["--ro-bind", "/etc/ld.so.cache", "/etc/ld.so.cache"]
    return command + ["--proc", "/proc", "--dev", "/dev", "--perms", "1777", "--tmpfs", "/tmp",
                      "--dir", "/run", "--ro-bind", config["stage"], "/repo",
                      "--bind", config["data"], "/out",
                      "--ro-bind", str(directory), "/cgroup", "--chdir", "/repo",
                      PYTHON, "-I", "-B", "/repo/contain.py", "_inside", "/repo/config.json"]


def enter(config):
    """Runs under systemd limits, before namespaces; never runs guest code."""
    group = membership(Path("/proc/self/cgroup").read_text())
    require(group.name == config["unit"], "Unexpected service cgroup")
    directory = CGROUP / str(group).lstrip("/")
    evidence = {"nonce": config["nonce"], "cgroup": str(group), "limits": limits(directory, config)}
    write_json(Path(config["data"]) / "entry.json", evidence)
    command = bubblewrap_command(config, directory)
    os.execvp(command[0], command)


def inspect_inside(config):
    """Read kernel state before any controlled guest or memory pressure starts."""
    current = namespaces()
    require(all(current[key] != config["host_namespaces"][key] for key in NAMESPACES),
            "A required namespace is shared with the host")
    entry = read_json("/out/entry.json")
    require(entry["nonce"] == config["nonce"] and
            str(membership(Path("/proc/self/cgroup").read_text())) == entry["cgroup"],
            "Cgroup membership changed during entry")
    actual = limits("/cgroup", config)
    status = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines())
    require(status["NoNewPrivs"].strip() == "1", "no_new_privs is not set")
    require(all(int(status[key], 16) == 0 for key in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")),
            "Capabilities remain in the sandbox")
    require(resource.getrlimit(resource.RLIMIT_CORE) == (0, 0), "Core size limit is not zero")
    core_filter = int(Path("/proc/self/coredump_filter").read_text().strip(), 16)
    require(core_filter == 0, "Core mapping filter is not empty")
    for path in ("/usr", "/repo", "/cgroup"):
        require(os.statvfs(path).f_flag & os.ST_RDONLY, f"Writable input mount: {path}")
    canary = Path("/repo/readonly-canary")
    try:
        fd = os.open(canary, os.O_WRONLY)
    except OSError as exc:
        require(exc.errno == errno.EROFS, f"Unexpected readonly rejection: {exc}")
    else:
        os.close(fd)
        raise RuntimeError("Input copy is writable")
    require(not Path(config["host_canary"]).exists(), "Host-only canary is visible")
    require(not Path("/run/user").exists() and not Path("/home").exists(), "Host session paths exposed")
    interfaces = [line.split(":", 1)[0].strip() for line in Path("/proc/net/dev").read_text().splitlines()[2:]]
    require(set(interfaces) <= {"lo"}, f"Unexpected network interfaces: {interfaces}")
    # The command must actually fail, not merely omit --share-net in its argv.
    userns = run("unshare", "--user", "--", "true", check=False)
    require(userns.returncode != 0, "Nested user namespace creation succeeded")
    scratch = Path("/tmp/write-canary")
    scratch.write_bytes(b"private\n")
    scratch.unlink()
    # A piped core handler can ignore RLIMIT_CORE. Never claim full suppression.
    pattern = Path("/proc/sys/kernel/core_pattern").read_text().strip()
    return {"nonce": config["nonce"], "status": "passed", "namespaces": current,
            "pid_scope": "bubblewrap_pid_namespace",
            "cgroup": entry["cgroup"], "limits": actual, "no_new_privs": True,
            "capabilities_empty": True, "inputs_readonly": True, "host_paths_hidden": True,
            "network_interfaces": interfaces, "nested_userns_rejected": True,
            "core_rlimit": [0, 0], "coredump_filter": core_filter, "core_pattern": pattern,
            **CLAIMS}


def inside(config):
    evidence = inspect_inside(config)
    write_json("/out/containment.json", evidence)
    if config["mode"] == "check":
        return 0
    if config["mode"] == "oom-check":
        # Fixed 128 MiB cgroup; bounded 256 MiB pressure, all pages actually touched.
        require(config["memory_bytes"] == 128 * MIB, "Invalid OOM test budget")
        write_json("/out/pressure.json", {"nonce": config["nonce"], "started": True,
                                        "maximum_bytes": 256 * MIB})
        chunks = []
        for _ in range(64):
            chunk = mmap.mmap(-1, 4 * MIB, flags=mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS)
            for offset in range(0, len(chunk), mmap.PAGESIZE):
                chunk[offset] = 0xA7
            chunks.append(chunk)
        raise RuntimeError("Memory pressure survived the hard limit")
    # Isolated Python mode excludes cwd. Import only the reviewed readonly tree.
    sys.path.insert(0, "/repo")
    from experiments.execution_capsule_retire import controller as retirement
    return retirement.suite(argparse.Namespace(repo=Path("/repo"), qemu=Path("/usr/bin/qemu-i386"),
        phase1=Path("/repo/build/libtaintforge_ir.so"), out=Path("/out/retirement"), case=config["case"]))


def prepare(args, out):
    """Snapshot only reviewed inputs. Existing checkout is never mounted inside."""
    require(os.getuid() != 0, "Run as your ordinary user, without sudo")
    require(256 <= args.memory_mib <= 4096, "--memory-mib must be between 256 and 4096")
    repo = args.repo.resolve(strict=True)
    baseline = read_json(HERE / "BASELINE.json")
    checked = {}
    for name, accepted in baseline["read_only_guards"].items():
        path = repo / name
        require(path.is_file() and not path.is_symlink(), f"Missing regular input: {path}")
        checked[name] = digest(path)
        require(checked[name] in accepted, f"Source version changed: {name}; reconcile before running")
    for tool in ("systemd-run", "systemctl", "bwrap", "unshare"):
        require(shutil.which(tool), f"Missing dependency: {tool}")
    run("systemctl", "--user", "show-environment")
    help_text = run("bwrap", "--help").stdout
    require("--disable-userns" in help_text and "--assert-userns-disabled" in help_text,
            "bubblewrap lacks required user namespace restrictions")
    require((CGROUP / "cgroup.controllers").is_file(), "cgroup v2 is unavailable")
    stage, data = out / "inputs", out / "data"
    stage.mkdir(mode=0o700)
    data.mkdir(mode=0o700)
    for name in checked:
        dest = stage / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(repo / name, dest)
        require(digest(dest) == checked[name], f"Input changed while copying: {name}")
    shutil.copyfile(HERE / "controller.py", stage / "contain.py")
    (stage / "readonly-canary").write_text("read only\n")
    canary = out / "host-only-canary"
    canary.write_bytes(os.urandom(32))
    runtime = {}
    if args.mode == "suite":
        sys.path.insert(0, str(repo))
        from experiments.execution_capsule_probe import controller as probe
        plugin = args.phase1 if args.phase1.is_absolute() else repo / args.phase1
        _, selected, qemu = probe.load_phase1(repo, plugin, Path("/usr/bin/qemu-i386"))
        require(selected.plugin.name == "libtaintforge_ir.so", "Expected Phase 1 plugin filename")
        build = stage / "build"
        build.mkdir()
        for source in (selected.plugin, selected.manifest):
            shutil.copyfile(source, build / source.name)
        require(digest(build / selected.plugin.name) == selected.plugin_sha256 and
                digest(build / selected.manifest.name) == selected.manifest_sha256, "Runtime changed while copying")
        runtime = {"qemu": qemu, "phase1_sha256": selected.plugin_sha256,
                   "manifest_sha256": selected.manifest_sha256}
    config = {"schema": 1, "nonce": uuid.uuid4().hex, "mode": args.mode, "case": args.case,
              "memory_bytes": (128 if args.mode == "oom-check" else args.memory_mib) * MIB,
              "seconds": 600 if args.mode == "suite" else 60,
              "stage": str(stage), "data": str(data), "config_path": str(stage / "config.json"),
              "host_namespaces": namespaces(), "host_canary": str(canary), "host_canary_sha256": digest(canary),
              "source_hashes": checked, "runtime": runtime,
              "tools": {tool: run(tool, "--version").stdout.splitlines()[0] for tool in ("bwrap", "systemd-run")}}
    config["unit"] = "taintforge-capsule-" + config["nonce"] + ".service"
    write_json(config["config_path"], config)
    return config


def unit_status(unit):
    result = run("systemctl", "--user", "show", unit, "--property=LoadState,ActiveState,Result,ExecMainCode,ExecMainStatus,ControlGroup,MemoryPeak",
                 check=False)
    return dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)


def verify(config, exit_code, status):
    data = Path(config["data"])
    evidence = read_json(data / "containment.json")
    require(evidence["nonce"] == config["nonce"] and evidence["status"] == "passed", "Missing containment acceptance")
    require(evidence["limits"] == {"memory.max": str(config["memory_bytes"]), "memory.swap.max": "0",
            "memory.oom.group": "1", "pids.max": "64"}, "Saved memory policy mismatch")
    require(all(evidence.get(key) is True for key in ("no_new_privs", "capabilities_empty",
            "inputs_readonly", "host_paths_hidden", "nested_userns_rejected")) and
            all(evidence.get(key) is False for key in CLAIMS), "Saved containment claims mismatch")
    require(all(evidence["namespaces"][key] != config["host_namespaces"][key] for key in NAMESPACES) and
            set(evidence["network_interfaces"]) <= {"lo"} and evidence["core_rlimit"] == [0, 0] and
            evidence["coredump_filter"] == 0, "Saved isolation evidence mismatch")
    require(Path(evidence["cgroup"]).name == config["unit"], "Saved service identity mismatch")
    require(digest(config["host_canary"]) == config["host_canary_sha256"], "Host canary changed")
    if config["mode"] == "oom-check":
        pressure = read_json(data / "pressure.json")
        require(pressure == {"nonce": config["nonce"], "started": True, "maximum_bytes": 256 * MIB},
                "Pressure test did not start")
        require(exit_code != 0 and status.get("Result") == "oom-kill",
                f"Expected systemd OOM attribution, got exit={exit_code}, unit={status}")
    else:
        require(exit_code == 0, f"Contained service failed with exit {exit_code}")
        if config["mode"] == "suite":
            report = read_json(data / "retirement/report.json")
            require(report["status"] == "passed" and report["cases"], "Retirement suite failed")
            require(report["qemu"]["sha256"] == config["runtime"]["qemu"]["sha256"],
                    "QEMU changed between outer and inner checks")
    return evidence


def supervise(args):
    out = args.out.resolve()
    out.mkdir(parents=True, mode=0o700, exist_ok=False)
    report = {"schema": 1, "status": "failed", "scope": "controlled_fixture_linux_containment",
              "mode": args.mode, **CLAIMS}
    config = None
    process = None
    try:
        config = prepare(args, out)
        report["configuration"] = config
        command = systemd_command(config, Path(config["stage"]) / "contain.py")
        write_json(out / "command.json", command)
        print(f"Starting {config['unit']}; memory={config['memory_bytes'] // MIB} MiB, swap=0, tasks=64", flush=True)
        with (out / "service.log").open("w") as log:
            process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT)
            deadline = time.monotonic() + config["seconds"] + 20
            while process.poll() is None:
                require(time.monotonic() < deadline, "External service deadline expired")
                time.sleep(0.2)
        status = unit_status(config["unit"])
        report.update(service_exit=process.returncode, unit_result=status)
        report["containment"] = verify(config, process.returncode, status)
        require(all(digest(args.repo.resolve() / name) == expected for name, expected in config["source_hashes"].items()),
                "Original inputs changed during execution")
        report["status"] = "passed"
    except (OSError, ValueError, RuntimeError, KeyError, subprocess.TimeoutExpired, KeyboardInterrupt) as exc:
        report["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        if config is not None:
            try:
                # Only this invocation's random unit. No broad pkill or cgroup sweep.
                stopped = run("systemctl", "--user", "stop", config["unit"], check=False)
                after = unit_status(config["unit"])
                require(after.get("LoadState") == "not-found" or after.get("ActiveState") in {"inactive", "failed"},
                        f"Service cleanup was not confirmed: {after}; stop={stopped.stderr}")
                entry_path = Path(config["data"]) / "entry.json"
                if entry_path.is_file():
                    group = membership("0::" + read_json(entry_path)["cgroup"])
                    require(group.name == config["unit"], "Unexpected cleanup cgroup")
                    events = CGROUP / str(group).lstrip("/") / "cgroup.events"
                    if events.exists():
                        require("populated 0" in events.read_text().splitlines(), "Service cgroup still populated")
                report["unit_stopped"] = True
                run("systemctl", "--user", "reset-failed", config["unit"], check=False)
            except (OSError, RuntimeError, subprocess.TimeoutExpired) as exc:
                report.update(status="failed", cleanup_error=str(exc), unit_stopped=False)
        if process is not None and process.poll() is None:
            process.kill()  # Client only; unit stop above owns service cleanup.
            process.wait(timeout=5)
        write_json(out / "report.json", report)
    error = report.get("error", report.get("cleanup_error"))
    print(f"{args.mode}: {report['status']}" + (f" — {error}" if error else ""))
    print(out / "report.json")
    return 0 if report["status"] == "passed" else 1


def main():
    if len(sys.argv) == 3 and sys.argv[1] in {"_enter", "_inside"}:
        config = read_json(sys.argv[2])
        return enter(config) if sys.argv[1] == "_enter" else inside(config)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("check", "oom-check", "suite"))
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--phase1", type=Path, default=Path("build/libtaintforge_ir.so"))
    parser.add_argument("--memory-mib", type=int, default=1024)
    parser.add_argument("--case", default="all", choices=("all", "owner-first", "observer-first", "phase1-first",
        "owner-phase1-first", "keep-control", "timeout-1", "timeout-2", "disconnect-1", "disconnect-2",
        "kill-controller-1", "kill-controller-2"))
    return supervise(parser.parse_args())


if __name__ == "__main__":
    raise SystemExit(main())
