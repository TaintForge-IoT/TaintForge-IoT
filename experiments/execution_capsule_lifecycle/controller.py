#!/usr/bin/env python3
"""External retirement evidence for a fixed i386 fixture, not real Phase 1 retirement."""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
from pathlib import Path
import re
import select
import shlex
import socket
import stat
import struct
import tempfile
import time
import uuid

from experiments.execution_capsule_retire import controller as retirement

probe = retirement.probe
HERE = Path(__file__).resolve().parent
EVENTS = ("hello", "export_complete", "uninstall_requested", "callbacks_removed", "resources_released")
CLAIMS = {"subject": "capsule-fixture-v1", "phase1_retired": False,
          "all_phase1_allocations_released": False, "whole_qemu_stop": False,
          "exact_oep_cutover": False, "residue_free": False,
          "guest_analyzer_memory_separated": False, "hostile_sample_ready": False}
CASES = {
    "owner-first": ("alone", True, "remove", None),
    "observer-first": ("alone", False, "remove", None),
    "phase1-first": ("phase1-first", False, "remove", None),
    "owner-phase1-first": ("phase1-first", True, "remove", None),
    "keep-control": ("alone", False, "keep", "missing_stage"),
    "leak-arena": ("alone", False, "leak-arena", "arena_still_mapped"),
    "bad-export": ("alone", False, "bad-export", "export_digest"),
}


class EvidenceError(probe.ProbeError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def require(condition, code):
    if not condition:
        raise EvidenceError(code)


def integer(value, minimum=0):
    return type(value) is int and minimum <= value <= (1 << 64) - 1


def pairs(items):
    result = {}
    for key, value in items:
        require(key not in result, "duplicate_key")
        result[key] = value
    return result


def invalid_constant(_):
    raise EvidenceError("invalid_number")


def payload(attempt):
    return f"CAPSULE_EXPORT_V1\nattempt={attempt}\n".encode("ascii")


class Evidence:
    """Strict ordered producer claims. Only the fixture export has a known oracle."""
    def __init__(self, attempt, pid, artifact):
        require(bool(re.fullmatch(r"[0-9a-f]{32}", attempt)), "invalid_attempt")
        self.attempt, self.pid, self.artifact = attempt, pid, Path(artifact)
        self.events = []
        self.eof = False
        self.last_packet = None

    def feed(self, packet):
        require(0 < len(packet) <= 1024, "packet_size")
        self.last_packet = packet.decode("utf-8", errors="replace")
        try:
            event = json.loads(packet.decode("utf-8"), object_pairs_hook=pairs,
                               parse_constant=invalid_constant)
        except (ValueError, UnicodeError, RecursionError) as exc:
            raise EvidenceError("invalid_json") from exc
        require(type(event) is dict and set(event) == {"protocol", "attempt", "seq", "pid", "event", "data"},
                "envelope")
        require(type(event["protocol"]) is int and event["protocol"] == 1, "protocol")
        require(event["attempt"] == self.attempt and type(event["pid"]) is int and event["pid"] == self.pid,
                "identity")
        index = len(self.events)
        require(index < len(EVENTS) and type(event["seq"]) is int and event["seq"] == index
                and event["event"] == EVENTS[index], "event_order")
        data = event["data"]
        require(type(data) is dict, "event_data")
        if index == 0:
            require(set(data) == {"producer", "api", "mapping_start", "mapping_size", "page_size",
                                  "arena_start", "arena_size"}, "hello_fields")
            require(data["producer"] == "capsule-fixture-v1" and type(data["api"]) is int and data["api"] == 6,
                    "producer")
            require(all(integer(data[k], 1) for k in ("mapping_start", "mapping_size", "page_size",
                                                      "arena_start", "arena_size")), "arena_fields")
            page = os.sysconf("SC_PAGE_SIZE")
            require(data["page_size"] == page and data["arena_size"] == retirement.ARENA_SIZE
                    and data["mapping_start"] % page == 0
                    and data["arena_start"] == data["mapping_start"] + page
                    and data["mapping_size"] == retirement.ARENA_SIZE + 2 * page
                    and data["mapping_start"] + data["mapping_size"] < 1 << 64, "arena_layout")
        elif index == 1:
            require(set(data) == {"size", "sha256"} and integer(data["size"], 1)
                    and type(data["sha256"]) is str and bool(re.fullmatch(r"[0-9a-f]{64}", data["sha256"])),
                    "export_fields")
            self.verify_export(data)
        elif index == 2:
            require(set(data) == {"callbacks"} and integer(data["callbacks"], 1), "request_fields")
        elif index == 3:
            require(set(data) == {"callbacks", "pending"} and all(integer(x) for x in data.values()),
                    "completion_fields")
            require(data["callbacks"] >= self.events[2]["data"]["callbacks"]
                    and data["pending"] == data["callbacks"] - self.events[2]["data"]["callbacks"],
                    "callback_counters")
        else:
            expected = {"owned_mappings": 0, "owned_bytes": 0, "zeroed_bytes": retirement.ARENA_SIZE}
            require(data == expected and all(type(x) is int for x in data.values()), "release_fields")
        self.events.append(event)
        return event

    def verify_export(self, declared):
        expected = payload(self.attempt)
        require(declared["size"] == len(expected), "export_size")
        try:
            fd = os.open(self.artifact, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
            with os.fdopen(fd, "rb") as stream:
                before = os.fstat(stream.fileno())
                require(stat.S_ISREG(before.st_mode) and before.st_size == len(expected), "export_file")
                data = stream.read(len(expected) + 1)
                after = os.fstat(stream.fileno())
            require((before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
                    (after.st_size, after.st_mtime_ns, after.st_ctime_ns), "export_changed")
        except OSError as exc:
            raise EvidenceError("export_open") from exc
        require(hashlib.sha256(data).hexdigest() == declared["sha256"], "export_digest")
        require(data == expected, "export_content")

    def finish(self):
        require(len(self.events) == len(EVENTS), "missing_stage")
        require(self.eof, "missing_eof")
        self.verify_export(self.events[1]["data"])


def start_time(pid, proc_root=Path("/proc")):
    # comm may itself contain spaces and ')'; the numeric suffix starts after the last ')'.
    return int((Path(proc_root) / str(pid) / "stat").read_text().rsplit(")", 1)[1].split()[19])


def receive(conn, evidence, deadline, complete):
    """At point 1 drain available events; at point 2 require the whole stream and EOF."""
    while not evidence.eof:
        waiting = complete or not evidence.events
        remaining = deadline - time.monotonic()
        require(not waiting or remaining > 0, "event_timeout")
        ready = select.select([conn], [], [], max(0, remaining) if waiting else 0)[0]
        if not ready:
            require(not waiting, "event_timeout")
            return
        packet, ancillary, flags, _ = conn.recvmsg(1024)
        require(not ancillary and not flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC), "packet_truncated")
        if not packet:
            poller = select.poll()
            poller.register(conn, select.POLLHUP | select.POLLRDHUP)
            require(any(flags & (select.POLLHUP | select.POLLRDHUP) for _, flags in poller.poll(0)),
                    "empty_packet")
            evidence.eof = True
            break
        evidence.feed(packet)
    if complete or evidence.eof:
        evidence.finish()


class LifecycleGate:
    """Runs in the existing observer's controller process, never in a QEMU callback."""
    def __init__(self, endpoint, directory, owner, observer, phase1, attempt, *, listener=None,
                 artifact=None, proc_root=Path("/proc")):
        self.directory, self.attempt = Path(directory), attempt
        self.artifact = Path(artifact) if artifact is not None else self.directory / "export.bin"
        self.proc_root = Path(proc_root)
        self.owner = retirement.file_identity(owner)
        self.observer = retirement.file_identity(observer)
        self.phase1 = retirement.file_identity(phase1) if phase1 else None
        self.listener = listener
        if self.listener is None:
            self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
            self.listener.bind(str(endpoint))
            os.chmod(endpoint, 0o600)
            self.listener.listen(1)
        self.conn, self.evidence, self.started = None, None, None

    def close(self):
        if self.conn is not None:
            self.conn.close()
        self.listener.close()

    def __call__(self, action, point, snapshot, record):
        if action != "held":
            return
        verdict = {"status": "rejected", "point": point, "claims": CLAIMS}
        try:
            pid = snapshot["host_pid"]
            deadline = time.monotonic() + 1.0
            if self.conn is None:
                require(bool(select.select([self.listener], [], [], 1.0)[0]), "peer_timeout")
                self.conn, _ = self.listener.accept()
                peer = struct.unpack("3i", self.conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                require(peer[0] == pid and peer[1] == os.getuid(), "peer_identity")
                self.conn.setblocking(False)
                self.started = start_time(pid, self.proc_root)
                self.evidence = Evidence(self.attempt, pid, self.artifact)
            require(pid == self.evidence.pid and start_time(pid, self.proc_root) == self.started, "process_identity")
            receive(self.conn, self.evidence, deadline, complete=point == 2)
            if point == 1:
                require(1 <= len(self.evidence.events) <= 3, "early_completion")
            memory = (self.proc_root / str(pid) / "maps").read_text()
            require(start_time(pid, self.proc_root) == self.started, "process_identity")
            rows = retirement.parse_maps(memory)
            arena = self.evidence.events[0]["data"]
            (self.directory / f"maps-point-{point}.txt").write_text(memory)
            low, high = arena["mapping_start"], arena["mapping_start"] + arena["mapping_size"]
            mapped = {"owner_library_absent": not retirement.file_mapped(rows, self.owner),
                      "arena_range_absent": not any(a < high and b > low for a, b, *_ in rows)}
            verdict.update(qemu_pid=pid, process_start_ticks=self.started, mapping_evidence=mapped,
                           maps_sha256=hashlib.sha256(memory.encode()).hexdigest())
            if point == 2:
                require(mapped["owner_library_absent"], "module_still_mapped")
                require(mapped["arena_range_absent"], "arena_still_mapped")
            mapped.update(retirement.inspect_memory(rows, arena, self.owner, self.observer, self.phase1,
                                                     released=point == 2))
            verdict["status"] = "verified" if point == 2 else "observed"
        except Exception as exc:
            verdict["error"] = exc.code if isinstance(exc, EvidenceError) else f"{type(exc).__name__}: {exc}"
            raise
        finally:
            verdict["producer_events"] = self.evidence.events if self.evidence else []
            count = len(verdict["producer_events"])
            verdict.update(export_verified_on_receipt=count >= 2, callbacks_removed_reported=count >= 4,
                           resources_released_reported=count == 5,
                           stream_closed=bool(self.evidence and self.evidence.eof))
            if self.evidence and verdict["status"] == "rejected":
                verdict["last_packet"] = self.evidence.last_packet
            record({"event": "lifecycle_rejected" if verdict["status"] == "rejected" else "lifecycle_observed",
                    **verdict})
            probe.write_json(self.directory / f"evidence-point-{point}.json", verdict)
            if point == 2 or verdict["status"] == "rejected":
                self.close()


def audit(repo):
    repo = Path(repo).resolve()
    baseline = json.loads((HERE / "BASELINE.json").read_text())
    checked = {}
    for name, accepted in baseline["read_only_guards"].items():
        path = repo / name
        require(path.is_file() and not path.is_symlink(), f"missing_input:{name}")
        checked[name] = probe.sha(path)
        require(checked[name] in accepted, f"source_changed:{name}")
    return {"compatible": True, "repo": str(repo), "source_hashes": checked,
            "reference_revision": baseline["reference_revision"]}


def build(out):
    built = probe.build(out)
    plugin = Path(out) / "libcapsule_lifecycle.so"
    flags = shlex.split(probe.command("pkg-config", "--cflags", "--libs", "glib-2.0"))
    probe.command("cc", "-std=c11", "-O2", "-g", "-Wall", "-Wextra", "-Werror", "-Wformat=2",
                  "-Wshadow", "-fPIC", "-fvisibility=hidden", "-shared", "-Wl,-z,relro,-z,now",
                  "-I", probe.HERE / "vendor", HERE / "owner.c", "-o", plugin, *flags)
    built.update(lifecycle_plugin=str(plugin), lifecycle_sha256=probe.sha(plugin))
    probe.write_json(Path(out) / "build.json", built)
    return built


def suite(args):
    provenance = audit(args.repo)
    # The Python modules were imported from this installation, not from an unrelated --repo.
    require(HERE.parents[1] == args.repo.resolve(), "repo_module_mismatch")
    qemu = args.qemu.resolve(strict=True)
    phase1 = args.phase1 if args.phase1.is_absolute() else args.repo.resolve() / args.phase1
    phase1_cls, runtime, qemu_info = probe.load_phase1(args.repo.resolve(), phase1, qemu)
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    report = {"schema": 1, "status": "failed", "claims": CLAIMS, "source_audit": provenance,
              "qemu": qemu_info, "phase1_sha256": runtime.plugin_sha256,
              "phase1_build_id": runtime.build_id, "plugin_api": 6, "cases": []}
    try:
        built = build(out / "build")
        report["build"] = built
        selected = CASES if args.case == "all" else (args.case,)
        for name in selected:
            probe_case, first, mode, rejection = CASES[name]
            directory, attempt = out / name, uuid.uuid4().hex
            with tempfile.TemporaryDirectory(prefix="tfl-", dir="/tmp") as ipc:
                endpoint = Path(ipc) / "events.sock"
                with contextlib.closing(LifecycleGate(endpoint, directory, built["lifecycle_plugin"],
                        built["plugin"], runtime.plugin if probe_case != "alone" else None, attempt)) as gate:
                    options = [built["lifecycle_plugin"], f"p1={built['symbols']['capsule_point_one']:#x}",
                               f"socket={endpoint}", f"export={directory / 'export.bin'}",
                               f"attempt={attempt}", f"mode={mode}"]
                    require(all("," not in value and "\n" not in value for value in options), "plugin_arguments")
                    result = probe.run_case(probe_case, directory, built, qemu, runtime, phase1_cls,
                        200, 5000, 30000, plugins_before=(",".join(options),) if first else (),
                        plugins_after=() if first else (",".join(options),), transition=gate)
            evidence_path = directory / "evidence-point-2.json"
            if not evidence_path.exists():
                evidence_path = directory / "evidence-point-1.json"
            evidence = json.loads(evidence_path.read_text()) if evidence_path.exists() else {}
            entry = {"case": name, "status": "failed", "attempt": attempt,
                     "expected_rejection": rejection, "run": result, "evidence": evidence}
            if rejection:
                control_path = directory / "controller.json"
                control = json.loads(control_path.read_text()) if control_path.exists() else {}
                prefix = {1: b"before\n", 2: b"before\nbetween\n"}.get(evidence.get("point"))
                entry["status"] = "passed" if (
                    evidence.get("status") == "rejected" and evidence.get("error") == rejection
                    and result.get("qemu_exit") == 125 and not result["supervisor_kill"]
                    and result.get("controller_exit") == 0 and control.get("status") == "failed"
                    and control.get("error") == f"EvidenceError: {rejection}"
                    and prefix is not None and (directory / "capsule-fd.txt").read_bytes() == prefix
                    and (directory / "stdout.log").read_bytes() == b""
                    and "CAPSULE_ABORT code=125 " in (directory / "stderr.log").read_text()
                ) else "failed"
            elif result["status"] == "passed" and evidence.get("status") == "verified":
                entry["status"] = "passed"
            report["cases"].append(entry)
            probe.write_json(out / "report.json", report)
            print(f"{name}: {entry['status']}" + (f" (expected rejection: {rejection})" if rejection else ""), flush=True)
        require(audit(args.repo) == provenance, "sources_changed_during_suite")
        require(probe.sha(qemu) == qemu_info["sha256"] and probe.sha(runtime.plugin) == runtime.plugin_sha256
                and probe.sha(runtime.manifest) == runtime.manifest_sha256, "runtime_changed_during_suite")
        require(probe.sha(built["lifecycle_plugin"]) == built["lifecycle_sha256"], "owner_binary_changed")
        report["status"] = "passed" if all(case["status"] == "passed" for case in report["cases"]) else "failed"
    except Exception as exc:
        report["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        probe.write_json(out / "report.json", report)
    print(out / "report.json")
    return 0 if report["status"] == "passed" else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    subs = parser.add_subparsers(dest="action", required=True)
    check = subs.add_parser("audit")
    check.add_argument("--repo", type=Path, default=Path.cwd())
    run = subs.add_parser("suite")
    run.add_argument("--repo", type=Path, default=Path.cwd())
    run.add_argument("--qemu", type=Path, default=Path("/usr/bin/qemu-i386"))
    run.add_argument("--phase1", type=Path, default=Path("build/libtaintforge_ir.so"))
    run.add_argument("--case", choices=("all", *CASES), default="all")
    run.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.action == "audit":
            print(json.dumps(audit(args.repo), indent=2))
            return 0
        return suite(args)
    except (OSError, probe.ProbeError) as exc:
        parser.exit(1, f"{type(exc).__name__}: {exc}\n")


if __name__ == "__main__":
    raise SystemExit(main())
