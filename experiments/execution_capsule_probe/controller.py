#!/usr/bin/env python3
"""Controller and supervisor for the benign capsule probe."""
from __future__ import annotations

import argparse
import hashlib
import json
import multiprocessing as mp
import os
from pathlib import Path
import re
import select
import shlex
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time

HERE = Path(__file__).resolve().parent
BEFORE = b"0123456789ABCDEF"
AFTER = b"fedcba9876543210"
FILE_BYTES = b"before\nbetween\nafter\n"
CASES = (
    "alone", "phase1-first", "capsule-first", "timeout-1", "timeout-2",
    "disconnect-1", "disconnect-2", "kill-controller-1", "kill-controller-2",
    "bad-command", "slow-command", "total-timeout",
)


class ProbeError(RuntimeError):
    pass


class WorkerStartupError(ProbeError):
    def __init__(self, failure):
        self.failure = failure
        super().__init__(f"{failure['component']} startup at {failure['stage']}: "
                         f"{failure['exception_type']}: {failure['message']}")


def worker_failure(exc, component, stage, ready=False):
    return {"category": "controller_failure" if ready else "startup_failure",
            "component": component, "stage": stage, "exception_type": type(exc).__name__,
            "errno": exc.errno if isinstance(exc, OSError) else None, "message": str(exc)[:3000]}


def send_startup_failure(pipe, failure):
    try:
        pipe.send({"status": "startup_failed", "failure": failure})
    except (OSError, EOFError):
        pass  # The parent may already have terminated; the worker report remains.


def wait_worker_ready(pipe, component, timeout=5):
    try:
        if not pipe.poll(timeout):
            raise TimeoutError("Controller readiness deadline expired")
        message = pipe.recv()
    except (EOFError, OSError) as exc:
        raise WorkerStartupError(worker_failure(exc, component, "readiness")) from exc
    if isinstance(message, dict) and message.get("status") == "startup_failed":
        raise WorkerStartupError(message["failure"])
    require(message == "ready", component + " returned an invalid readiness message")


def execution_failure(exc, result, stage):
    if isinstance(exc, WorkerStartupError):
        return exc.failure
    if result.get("supervisor_kill") or isinstance(exc, subprocess.TimeoutExpired):
        category = "execution_timeout"
    elif result.get("qemu_pid") is None:
        category = "startup_failure"
    elif result.get("qemu_exit") not in {None, result.get("expected_qemu_exit", 0)}:
        category = "guest_failure"
    else:
        category = "evidence_failure" if stage == "verification" else "controller_failure"
    return {**worker_failure(exc, "supervisor", stage), "category": category}


def saved_worker_failures(directory):
    failures = []
    for name in ("controller.json", "phase1-retirement/retirement.json"):
        path = Path(directory) / name
        try:
            if path.stat().st_size > 256 * 1024:
                continue
            record = json.loads(path.read_text())
            if isinstance(record, dict) and isinstance(record.get("failure"), dict):
                failures.append(record["failure"])
        except (OSError, ValueError):
            pass
    return failures


def require(condition, message):
    if not condition:
        raise ProbeError(message)


def sha(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def write_json(path, obj):
    path = Path(path)
    temporary = path.with_name(path.name + ".tmp")
    with temporary.open("w", encoding="utf-8") as stream:
        json.dump(obj, stream, indent=2, ensure_ascii=False)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(path)


def command(*args, cwd=None, timeout=60):
    result = subprocess.run([str(x) for x in args], cwd=cwd, capture_output=True,
                            text=True, timeout=timeout, check=False)
    require(result.returncode == 0,
            f"command failed ({result.returncode}): {shlex.join(map(str, args))}\n{result.stderr[-5000:]}")
    return result.stdout


def audit(repo):
    repo = Path(repo).resolve(strict=True)
    baseline = json.loads((HERE / "BASELINE.json").read_text())
    files = {}
    for relative, expected in baseline["source_files"].items():
        path = repo / relative
        actual = sha(path) if path.is_file() else None
        allowed = [expected, *baseline.get("compatible_source_variants", {}).get(relative, [])]
        files[relative] = {"expected_sha256": expected, "actual_sha256": actual,
                           "accepted_sha256": allowed, "matches": actual in allowed}
    revision = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"],
                              capture_output=True, text=True, check=False)
    return {"repo": str(repo), "revision": revision.stdout.strip() or None,
            "reference_local_revision": baseline["local_revision"],
            "reference_github_revision": baseline["github_revision"],
            "files": files, "compatible": all(x["matches"] for x in files.values())}


def checked_audit(repo):
    result = audit(repo)
    mismatches = [k for k, v in result["files"].items() if not v["matches"]]
    require(result["compatible"], "Integration source differs from the reviewed local packages: " +
            ", ".join(mismatches) + ". Run audit and reconcile sources; nothing was overwritten.")
    return result


def install(repo):
    provenance = checked_audit(repo)
    destination = Path(repo).resolve() / "experiments/execution_capsule_probe"
    require(not destination.exists() and not destination.is_symlink(),
            f"Refusing to overwrite {destination}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(HERE, destination, ignore=shutil.ignore_patterns("__pycache__", "build", "*.pyc"))
    write_json(destination / "installation.json", provenance)
    print(destination)


def build(out, *, guest_source=None, extra_symbols=()):
    out = Path(out).resolve()
    out.mkdir(parents=True, exist_ok=False)
    baseline = json.loads((HERE / "BASELINE.json").read_text())
    header = HERE / "vendor/qemu-plugin.h"
    require(sha(header) == baseline["qemu_header_sha256"], "Pinned QEMU header hash mismatch")
    flags = shlex.split(command("pkg-config", "--cflags", "--libs", "glib-2.0"))
    plugin = out / "libcapsule_probe.so"
    command("cc", "-std=c11", "-O2", "-g", "-Wall", "-Wextra", "-Werror", "-Wformat=2",
            "-Wshadow", "-fPIC", "-fvisibility=hidden", "-shared", "-pthread",
            "-Wl,-z,relro,-z,now", "-I", HERE / "vendor", HERE / "probe.c", "-o", plugin, *flags)
    guest_source = Path(guest_source) if guest_source is not None else HERE / "guest.S"
    command("as", "--32", guest_source, "-o", out / "guest.o")
    guest = out / "capsule_guest_i386"
    command("ld", "-m", "elf_i386", "-z", "noexecstack", "--build-id=none",
            out / "guest.o", "-o", guest)
    symbols = {}
    for line in command("nm", "-P", "--defined-only", guest).splitlines():
        fields = line.split()
        if fields[0] in {"capsule_point_one", "capsule_point_two", "capsule_buffer", *extra_symbols}:
            symbols[fields[0]] = int(fields[2], 16)
    require(len(symbols) == 3 + len(extra_symbols), "Missing fixture symbols")
    elf = guest.read_bytes()
    require(elf[:7] == b"\x7fELF\x01\x01\x01" and struct.unpack_from("<HH", elf, 16) == (2, 3),
            "Fixture must be little-endian i386 ET_EXEC")
    require("INTERP" not in command("readelf", "-lW", guest), "Fixture unexpectedly uses a loader")
    result = {"plugin": str(plugin), "guest": str(guest), "symbols": symbols,
              "hashes": {p.name: sha(p) for p in (plugin, guest, HERE / "probe.c", guest_source, header)},
              "compiler": command("cc", "--version").splitlines()[0],
              "glib": command("pkg-config", "--modversion", "glib-2.0").strip(),
              "qemu_source_revision": baseline["qemu_revision"], "plugin_api": 6}
    write_json(out / "build.json", result)
    return result


class Frames:
    """Bounded newline JSON framing; keeps bytes after the first frame."""
    def __init__(self, connection, deadline):
        self.connection = connection
        self.deadline = deadline
        self.buffer = bytearray()

    def receive(self):
        while b"\n" not in self.buffer:
            remaining = self.deadline - time.monotonic()
            require(remaining > 0, "controller deadline")
            self.connection.settimeout(remaining)
            part = self.connection.recv(4096)
            if not part:
                raise EOFError("QEMU closed the control channel")
            self.buffer.extend(part)
            require(len(self.buffer) <= 8192, "Oversized IPC frame")
        line, _, rest = self.buffer.partition(b"\n")
        require(len(line) <= 4096, "Oversized IPC frame")
        self.buffer = bytearray(rest)
        value = json.loads(line)
        require(isinstance(value, dict) and value.get("protocol") == 1, "Invalid IPC version/frame")
        return value


def validate_snapshot(event, point, sample, symbols, qpid, previous=None):
    require(event.get("event") == "snapshot" and event.get("point") == point and
            event.get("sample") == sample and event.get("vcpu") == 0 and
            event.get("host_pid") == qpid, "Snapshot identity/order mismatch")
    regs = event["regs"]
    require(set(regs) == {"eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "eip"},
            "Unexpected register inventory")
    require(all(type(v) is int and 0 <= v <= 0xffffffff for v in regs.values()), "Invalid registers")
    pc = symbols["capsule_point_one" if point == 1 else "capsule_point_two"]
    require(regs["eip"] == pc and regs["eax"] == point * 0x11111111 and
            regs["ecx"] == symbols["capsule_buffer"] and regs["edx"] == 16,
            "Known register values disagree")
    require(regs["edi"] >= 3 and regs["ebx"] == regs["edi"] and regs["esi"] == qpid and
            regs["ebp"] == regs["esp"], "PID, FD or stack register mismatch")
    require(bytes.fromhex(event["buffer_hex"]) == (BEFORE if point == 1 else AFTER),
            "Guest buffer did not contain expected bytes")
    stack = struct.pack("<8I", 0x11223344, 0x55667788, 0x99aabbcc, regs["edi"],
                        qpid, regs["esp"], 0xdeadbeef, 0xcafebabe)
    require(bytes.fromhex(event["stack_hex"]) == stack, "Stack canaries/locals changed")
    if previous:
        for key in ("esp", "ebp", "esi", "edi"):
            require(regs[key] == previous["regs"][key], f"{key} changed across resume")
        require(event["stack_hex"] == previous["stack_hex"], "Stack changed across resume")


def control_worker(endpoint, pipe, directory, symbols, case, hold_ms, total_ms,
                   *, fd_path=None, transition=None):
    """This process owns the only listening/accepted control sockets."""
    directory = Path(directory)
    result = {"case": case, "status": "failed"}
    connection = listener = None
    ready = False
    stage = "socket"
    try:
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        stage = "bind"
        listener.bind(endpoint)
        os.chmod(endpoint, 0o600)
        listener.listen(1)
        listener.settimeout(total_ms / 1000 + 3)
        pipe.send("ready")
        ready = True
        stage = "qemu_pid"
        require(pipe.poll(total_ms / 1000 + 3), "Missing QEMU PID")
        qpid = pipe.recv()
        stage = "accept"
        connection, _ = listener.accept()
        listener.close()
        stage = "peer_identity"
        peer_pid, peer_uid, _ = struct.unpack("3i", connection.getsockopt(
            socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))
        require((peer_pid, peer_uid) == (qpid, os.getuid()), "Unexpected QEMU peer")
        stage = "observations"
        frames = Frames(connection, time.monotonic() + total_ms / 1000 + 4)
        first = None
        with (directory / "observations.jsonl").open("w") as journal:
            def record(event):
                journal.write(json.dumps(event, sort_keys=True) + "\n")
                journal.flush()
                os.fsync(journal.fileno())

            for point in (1, 2):
                snapshot = frames.receive()
                record(snapshot)
                validate_snapshot(snapshot, point, 1, symbols, qpid, first)
                if first is None:
                    first = snapshot
                expected_file = b"before\n" if point == 1 else b"before\nbetween\n"
                observed_file = Path(fd_path) if fd_path is not None else directory / "capsule-fd.txt"
                require(observed_file.read_bytes() == expected_file, "Guest ran past observation point")
                start = time.monotonic()
                require(not frames.buffer and not select.select([connection], [], [], hold_ms / 1000)[0],
                        "Guest/channel advanced while held")
                require(observed_file.read_bytes() == expected_file, "Guest file changed during hold")
                connection.sendall(f"CHECK {point}\n".encode())
                repeated = frames.receive()
                record(repeated)
                validate_snapshot(repeated, point, 2, symbols, qpid, snapshot)
                require(repeated["regs"] == snapshot["regs"] and
                        repeated["buffer_hex"] == snapshot["buffer_hex"], "State changed during hold")
                require(repeated["monotonic_ms"] >= snapshot["monotonic_ms"] + hold_ms - 2,
                        "Plugin timestamps do not confirm the requested hold")
                record({"event": "hold_verified", "point": point,
                        "elapsed_ms": round((time.monotonic() - start) * 1000, 3)})
                if transition is not None:
                    transition("held", point, repeated, record)
                selected = case.endswith(f"-{point}") or (point == 1 and case in {
                    "bad-command", "slow-command", "total-timeout"})
                if selected and case.startswith("disconnect"):
                    connection.close()
                    connection = None
                    result.update(status="passed", action="connection_closed", point=point)
                    return
                if selected and case.startswith("kill-controller"):
                    record({"event": "controller_kill", "point": point})
                    os.kill(os.getpid(), signal.SIGKILL)
                    raise ProbeError("SIGKILL unexpectedly returned")
                if selected and (case.startswith("timeout") or case == "total-timeout"):
                    try:
                        frames.receive()
                    except EOFError:
                        result.update(status="passed", action="timeout_eof", point=point)
                        return
                    raise ProbeError("Unexpected frame during timeout")
                if selected and case in {"bad-command", "slow-command"}:
                    if case == "bad-command":
                        connection.sendall(b"CONTINUE 99\n")
                    else:
                        # Partial bytes must not renew the plugin's absolute deadline.
                        for byte in b"CONTINUE 1":
                            try:
                                connection.sendall(bytes([byte]))
                            except (BrokenPipeError, ConnectionResetError):
                                break
                            time.sleep(0.2)
                    try:
                        frames.receive()
                    except (EOFError, ConnectionResetError):
                        result.update(status="passed", action=case, point=point)
                        return
                    raise ProbeError("Unexpected frame after bad/slow command")
                # Intentionally fragmented to exercise stream framing.
                if transition is not None:
                    transition("resuming", point, repeated, record)
                connection.sendall(b"CON")
                connection.sendall(f"TINUE {point}\n".encode())
            done = frames.receive()
            record(done)
            require(done == {"event": "done", "protocol": 1, "points": 2}, "Invalid completion")
            if transition is not None:
                transition("done", 2, repeated, record)
            result.update(status="passed", action="two_resumes")
    except BaseException as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
        result["failure"] = worker_failure(exc, "observer", stage, ready)
        if not ready:
            try:
                write_json(directory / "controller.json", result)
            finally:
                send_startup_failure(pipe, result["failure"])
    finally:
        if connection:
            connection.close()
        if listener is not None:
            listener.close()
        pipe.close()
        write_json(directory / "controller.json", result)


def load_phase1(repo, plugin, qemu):
    sys.path.insert(0, str(repo))
    from taintforge_env.phase1_runtime import Phase1Run, Phase1Runtime
    runtime = Phase1Runtime.load(Path(plugin).resolve(strict=True))
    require(runtime.plugin_api == 6, "Phase 1 runtime manifest must require API 6")
    qemu_info = runtime.validate_qemu(qemu)
    version = command(qemu, "--version").splitlines()[0]
    require(re.search(r"\bversion 11\.0\.1(?:\s|$)", version),
            f"Expected QEMU 11.0.1 exactly; got {version}")
    qemu_info["version"] = version
    return Phase1Run, runtime, qemu_info


def run_case(case, directory, built, qemu, runtime, phase1_cls, hold_ms, pause_ms, total_ms,
             *, plugins_before=(), plugins_after=(), transition=None):
    directory.mkdir(parents=True, exist_ok=False)
    negative = case not in {"alone", "phase1-first", "capsule-first"}
    expected = (124 if case.startswith("timeout") or case in {"slow-command", "total-timeout"}
                else 125 if case.startswith(("disconnect", "kill-controller"))
                else 126 if case == "bad-command" else 0)
    effective_total = 5000 if case == "total-timeout" else total_ms
    effective_pause = 60000 if case == "total-timeout" else pause_ms
    result = {"case": case, "status": "failed", "expected_qemu_exit": expected,
              "scope": "single_guest_vcpu_callback", "global_quiescence": "not_asserted",
              "analyzer_quiescence": "not_asserted", "supervisor_kill": False}
    analysis = None
    if case != "alone":
        analysis = phase1_cls(runtime, "capsule-probe", case, "analysis-" + case,
                              (directory / "phase1").resolve())
        phase_arg = analysis.plugin_argument(extra=("tf-selection-delay=8",))
    worker = None
    process = None
    parent_pipe = None
    started = time.monotonic()
    try:
        with tempfile.TemporaryDirectory(prefix="tfc-", dir="/tmp") as ipc:
            endpoint = str(Path(ipc) / "control.sock")
            ctx = mp.get_context("fork")
            parent_pipe, child_pipe = ctx.Pipe()
            worker = ctx.Process(target=control_worker, args=(endpoint, child_pipe, str(directory),
                built["symbols"], case, hold_ms, effective_total), kwargs={"transition": transition})
            worker.start()
            child_pipe.close()
            wait_worker_ready(parent_pipe, "observer")
            capsule_arg = ",".join([
                built["plugin"], "socket=" + endpoint,
                "p1=" + hex(built["symbols"]["capsule_point_one"]),
                "p2=" + hex(built["symbols"]["capsule_point_two"]),
                "buffer=" + hex(built["symbols"]["capsule_buffer"]),
                "pause-ms=" + str(effective_pause), "total-ms=" + str(effective_total),
                "controller=" + str(worker.pid)])
            require(all("," not in p and "\n" not in p for p in (str(qemu), built["plugin"], endpoint)),
                    "Invalid comma/newline in plugin path")
            arguments = [str(qemu)]
            for plugin in plugins_before:
                arguments += ["-plugin", plugin]
            if analysis and case != "capsule-first":
                arguments += ["-plugin", phase_arg]
            arguments += ["-plugin", capsule_arg]
            if analysis and case == "capsule-first":
                arguments += ["-plugin", phase_arg]
            for plugin in plugins_after:
                arguments += ["-plugin", plugin]
            arguments += [built["guest"]]
            result["command"] = arguments
            env = {k: v for k, v in os.environ.items() if not k.startswith("QEMU_")}
            for key in ("LD_PRELOAD", "LD_AUDIT", "LD_LIBRARY_PATH"):
                env.pop(key, None)
            with (directory / "stdout.log").open("wb") as stdout, (directory / "stderr.log").open("wb") as stderr:
                process = subprocess.Popen(arguments, cwd=directory, env=env, stdout=stdout,
                                           stderr=stderr, start_new_session=True, close_fds=True)
                result["qemu_pid"] = process.pid
                result["controller_pid"] = worker.pid
                parent_pipe.send(process.pid)
                try:
                    result["qemu_exit"] = process.wait(timeout=effective_total / 1000 + 5)
                except subprocess.TimeoutExpired:
                    result["supervisor_kill"] = True
                    os.killpg(process.pid, signal.SIGKILL)
                    result["qemu_exit"] = process.wait(timeout=3)
            worker.join(timeout=4)
            result["controller_exit"] = worker.exitcode
            require(not worker.is_alive(), "Controller did not terminate")
            require(not result["supervisor_kill"], "QEMU required supervisor fallback kill")
            require(result["qemu_exit"] == expected, f"Unexpected QEMU exit: {result['qemu_exit']}")
            journal = directory / "observations.jsonl"
            events = [json.loads(line) for line in journal.read_text().splitlines()] if journal.exists() else []
            result["snapshots"] = sum(e.get("event") == "snapshot" for e in events)
            if case.startswith("kill-controller"):
                require(worker.exitcode == -signal.SIGKILL and events and
                        events[-1].get("event") == "controller_kill", "Controller death was not exercised")
            else:
                control = json.loads((directory / "controller.json").read_text())
                result["controller"] = control
                require(control["status"] == "passed", control.get("error", "Controller failed"))
            if negative:
                diagnostics = (directory / "stderr.log").read_text(errors="replace")
                require(f"CAPSULE_ABORT code={expected} " in diagnostics, "Missing plugin abort evidence")
                target = 2 if case.endswith("-2") else 1
                prefix = b"before\nbetween\n" if target == 2 else b"before\n"
                require((directory / "capsule-fd.txt").read_bytes() == prefix, "Guest continued after abort")
                require((directory / "stdout.log").read_bytes() == b"", "Guest reached success after abort")
            else:
                require(result["snapshots"] == 4, "Expected two reads at each of two points")
                require((directory / "stdout.log").read_bytes() == b"CAPSULE_OK\n", "Guest oracle failed")
                require((directory / "capsule-fd.txt").read_bytes() == FILE_BYTES, "FD continuity failed")
                result["guest_oracle"] = "stack_pid_fd_offset_readback_passed"
            if analysis:
                if negative:
                    ev = analysis.events(final=False)
                    capabilities = ev[0].get("data", {})
                    require(capabilities.get("build_id") == runtime.build_id and
                            capabilities.get("plugin_api") == 6, "Wrong loaded Phase 1 identity")
                    require(any(e.get("event_type") == "runtime_observation" and
                                e.get("data", {}).get("kind") == "instruction_callback" for e in ev),
                            "Phase 1 instruction callback was not observed")
                    result["phase1"] = {"runtime_observed": True, "build_id": runtime.build_id,
                        "finalization": "not_expected_after_forced_abort"}
                else:
                    result["phase1"] = analysis.verify()
                    require(result["phase1"]["runtime_observed"], "Phase 1 did not observe instructions")
                require(sha(runtime.plugin) == runtime.plugin_sha256 and
                        sha(runtime.manifest) == runtime.manifest_sha256, "Phase 1 runtime changed")
            result["status"] = "passed"
    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        if process and process.poll() is None:
            result["supervisor_kill"] = True
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=3)
        if worker:
            if worker.is_alive():
                worker.kill()
            worker.join(timeout=3)
        if parent_pipe:
            parent_pipe.close()
        result["elapsed_seconds"] = round(time.monotonic() - started, 3)
        write_json(directory / "result.json", result)
    return result


def suite(args):
    provenance = checked_audit(args.repo)
    repo = Path(args.repo).resolve()
    qemu = Path(args.qemu).resolve(strict=True)
    phase1_cls, runtime, qemu_info = load_phase1(repo, args.phase1, qemu)
    out = Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=False)
    report = {"schema": 1, "status": "failed", "source_audit": provenance,
              "qemu": qemu_info, "phase1_build_id": runtime.build_id,
              "phase1_sha256": runtime.plugin_sha256, "plugin_api": 6, "cases": [],
              "limitations": {"single_thread_only": True, "whole_qemu_stop": False,
                  "analyzer_quiescence": False, "memory_isolation": False,
                  "checkpoint": False, "fuzzing_ready": False,
                  "untrusted_guest_supported": False, "protected_control_channel": False}}
    try:
        built = build(out / "build")
        report["build"] = built
        cases = CASES if args.case == "all" else (args.case,)
        for case in cases:
            result = run_case(case, out / case, built, qemu, runtime, phase1_cls,
                              args.hold_ms, args.pause_ms, args.total_ms)
            report["cases"].append(result)
            write_json(out / "report.json", report)
            print(f"{case}: {result['status']}" + (" — " + result["error"] if "error" in result else ""), flush=True)
        require(sha(qemu) == qemu_info["sha256"], "QEMU binary changed during suite")
        report["source_unchanged"] = audit(repo)["compatible"]
        require(report["source_unchanged"], "Integration source changed during suite")
        report["status"] = "passed" if all(x["status"] == "passed" for x in report["cases"]) else "failed"
    except Exception as exc:
        report["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        write_json(out / "report.json", report)
    print(out / "report.json")
    return 0 if report["status"] == "passed" else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    subs = parser.add_subparsers(dest="action", required=True)
    for action in ("audit", "install"):
        p = subs.add_parser(action)
        p.add_argument("--repo", type=Path, default=Path.cwd())
    p = subs.add_parser("build")
    p.add_argument("--out", type=Path, required=True)
    p = subs.add_parser("suite")
    p.add_argument("--repo", type=Path, default=Path.cwd())
    p.add_argument("--qemu", type=Path, default=Path("/usr/bin/qemu-i386"))
    p.add_argument("--phase1", type=Path, default=Path("build/libtaintforge_ir.so"))
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--case", choices=("all", *CASES), default="all")
    p.add_argument("--hold-ms", type=int, default=200)
    p.add_argument("--pause-ms", type=int, default=1500)
    p.add_argument("--total-ms", type=int, default=30000)
    args = parser.parse_args()
    try:
        if args.action == "audit":
            result = audit(args.repo)
            print(json.dumps(result, indent=2, ensure_ascii=False))
            return 0 if result["compatible"] else 1
        if args.action == "install":
            install(args.repo)
        elif args.action == "build":
            print(json.dumps(build(args.out), indent=2))
        else:
            require(50 <= args.hold_ms <= 1000 and args.hold_ms + 500 <= args.pause_ms <= 60000 and
                    10000 <= args.total_ms <= 600000, "Invalid hold/pause/total timing budgets")
            return suite(args)
        return 0
    except (ProbeError, OSError, ValueError, subprocess.TimeoutExpired) as exc:
        print(f"capsule probe: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
