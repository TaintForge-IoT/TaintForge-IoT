#!/usr/bin/env python3
"""Owned-arena retirement experiment. Reuse the capsule transport and ELF oracle."""
import argparse
import json
import os
from pathlib import Path
import shlex

from experiments.execution_capsule_probe import controller as probe

HERE = Path(__file__).resolve().parent
ARENA_SIZE = 4 * 1024 * 1024
REMOVED = ["arena_allocated", "uninstall_requested", "callbacks_removed", "arena_zeroed", "arena_unmapped"]
RETAINED = ["arena_allocated", "retirement_skipped", "still_active", "exit_retained"]
# (existing capsule case, owner before other plugins, keep arena)
CASES = {"owner-first": ("alone", True, False), "observer-first": ("alone", False, False),
         "phase1-first": ("phase1-first", False, False),
         "owner-phase1-first": ("phase1-first", True, False),
         "keep-control": ("alone", False, True),
         **{name: (name, False, False) for name in (
             "timeout-1", "timeout-2", "disconnect-1", "disconnect-2",
             "kill-controller-1", "kill-controller-2")}}


def read_events(path):
    data = Path(path).read_bytes()
    probe.require(len(data) <= 65536 and data.endswith(b"\n"), "Invalid lifecycle journal length/framing")
    return [json.loads(line) for line in data.splitlines()]


def validate_lifecycle(events, pid, mode, point, final=False):
    expected = RETAINED if mode == "keep" else REMOVED
    names = [event.get("event") for event in events]
    probe.require(names and names == expected[:len(names)], "Unexpected retirement event order")
    if point == 1:
        probe.require(len(names) <= 2, "Arena released before CONTINUE 1")
    elif mode == "uninstall":
        probe.require(names == REMOVED, "Uninstall/zero/munmap did not complete before point 2")
    else:
        probe.require(len(names) >= (4 if final else 2), "Keep control did not reach its boundary")
    first = events[0]
    fields = ("mapping_start", "mapping_size", "arena_start", "arena_size", "page_size")
    for event in events:
        probe.require(event.get("schema") == 1 and event.get("host_pid") == pid and event.get("mode") == mode,
                      "Lifecycle identity mismatch")
        probe.require(all(type(event.get(key)) is int and event[key] > 0 and event[key] == first[key]
                          for key in fields), "Arena identity changed")
        probe.require(all(type(event.get(key)) is int and event[key] >= 0
                          for key in ("callbacks", "pending_callbacks")), "Invalid callback counts")
    page = first["page_size"]
    probe.require(page & (page - 1) == 0 and first["mapping_start"] % page == 0 and
                  first["arena_size"] == ARENA_SIZE and ARENA_SIZE % page == 0 and
                  first["arena_start"] == first["mapping_start"] + page and
                  first["mapping_size"] == ARENA_SIZE + 2 * page, "Invalid guarded arena")
    probe.require(first["callbacks"] == first["pending_callbacks"] == 0, "Invalid initial counters")
    if len(events) >= 2:
        probe.require(events[1]["callbacks"] > 0 and events[1]["pending_callbacks"] == 0,
                      "Test plugin did not observe guest execution")
    if mode == "uninstall" and len(events) >= 3:
        complete = events[2]
        probe.require(complete["callbacks"] >= events[1]["callbacks"] and
                      complete["pending_callbacks"] == complete["callbacks"] - events[1]["callbacks"],
                      "Pending callback accounting mismatch")
        probe.require(all(event["callbacks"] == complete["callbacks"] and
                          event["pending_callbacks"] == complete["pending_callbacks"] for event in events[2:]),
                      "Callbacks changed during release")
    if mode == "keep":
        probe.require(all(event["pending_callbacks"] == 0 for event in events) and
                      all(b["callbacks"] >= a["callbacks"] for a, b in zip(events, events[1:])),
                      "Invalid retained counters")
        if len(events) >= 3:
            probe.require(events[2]["callbacks"] > events[1]["callbacks"], "Keep control stopped observing")
    return first


def parse_maps(text):
    result = []
    for line in text.splitlines():
        fields = line.split(maxsplit=5)
        probe.require(len(fields) >= 5, "Malformed /proc maps line")
        start, end = (int(value, 16) for value in fields[0].split("-"))
        device = tuple(int(value, 16) for value in fields[3].split(":"))
        probe.require(start < end and len(device) == 2, "Invalid /proc maps interval")
        result.append((start, end, fields[1], device, int(fields[4])))
    probe.require(result and all(a[1] <= b[0] for a, b in zip(result, result[1:])), "Invalid maps ordering")
    return result


def file_identity(path):
    info = Path(path).stat()
    return ((os.major(info.st_dev), os.minor(info.st_dev)), info.st_ino)


def file_mapped(rows, identity):
    return any((row[3], row[4]) == identity for row in rows)


def covered(rows, start, end, permissions):
    cursor = start
    for lo, hi, perms, *_ in rows:
        if hi <= cursor or lo >= end:
            continue
        if lo > cursor or perms != permissions:
            return False
        cursor = min(hi, end)
    return cursor == end


def inspect_memory(rows, arena, owner, observer, phase1, released):
    lo = arena["mapping_start"]
    hi = lo + arena["mapping_size"]
    start = arena["arena_start"]
    end = start + arena["arena_size"]
    present = file_mapped(rows, owner)
    overlap = any(a < hi and b > lo for a, b, *_ in rows)
    probe.require(file_mapped(rows, observer), "Capsule observer disappeared")
    if phase1 is not None:
        probe.require(file_mapped(rows, phase1), "Phase 1 disappeared")
    if released:
        # Deliberately conservative: address reuse fails this controlled test.
        # Do not mistake RSS changes or a self-reported event for unmapping.
        probe.require(not overlap, "Owned address range is still mapped or was reused")
        probe.require(not present, "Retired .so is still mapped")
    else:
        probe.require(present and covered(rows, lo, start, "---p") and
                      covered(rows, start, end, "rw-p") and covered(rows, end, hi, "---p"),
                      "Live arena/guard pages/plugin are missing")
    return {"arena_range_absent": not overlap, "owner_library_absent": not present,
            "observer_present": True, "phase1_present": phase1 is not None}


class RetirementGate:
    def __init__(self, directory, owner, observer, phase1, mode):
        self.directory = Path(directory)
        # Capture identities before exec; do not follow replacement files later.
        self.owner, self.observer = file_identity(owner), file_identity(observer)
        self.phase1 = file_identity(phase1) if phase1 is not None else None
        self.mode = mode

    def __call__(self, action, point, snapshot, record):
        if action != "held":
            return
        events = read_events(self.directory / "retirement.jsonl")
        arena = validate_lifecycle(events, snapshot["host_pid"], self.mode, point)
        text = Path(f"/proc/{snapshot['host_pid']}/maps").read_text()
        rows = parse_maps(text)
        memory = inspect_memory(rows, arena, self.owner, self.observer, self.phase1,
                                released=point == 2 and self.mode == "uninstall")
        maps_path = self.directory / f"maps-point-{point}.txt"
        maps_path.write_text(text)
        record({"event": "retirement_observed", "point": point, "mode": self.mode,
                "host_pid": snapshot["host_pid"], "maps_sha256": probe.sha(maps_path),
                "lifecycle_prefix": events, **memory})


def verify_result(directory, result, gate, built, case):
    point = 2 if result["expected_qemu_exit"] == 0 or case.endswith("-2") else 1
    events = read_events(directory / "retirement.jsonl")
    arena = validate_lifecycle(events, result["qemu_pid"], gate.mode, point, final=True)
    journal = [json.loads(line) for line in (directory / "observations.jsonl").read_text().splitlines()]
    snapshots = [event for event in journal if event["event"] == "snapshot"]
    probe.require(len(snapshots) == point * 2, "Incomplete retirement observations")
    for i, event in enumerate(snapshots):
        probe.validate_snapshot(event, i // 2 + 1, i % 2 + 1, built["symbols"], result["qemu_pid"], snapshots[0])
    order = [name for _ in range(point) for name in
             ("snapshot", "snapshot", "hold_verified", "retirement_observed")]
    if result["expected_qemu_exit"] == 0:
        order.append("done")
    elif case.startswith("kill-controller"):
        order.append("controller_kill")
    probe.require([event["event"] for event in journal] == order, "Unexpected overall retirement event order")
    for number, event in enumerate((e for e in journal if e["event"] == "retirement_observed"), 1):
        prefix = event["lifecycle_prefix"]
        validate_lifecycle(prefix, result["qemu_pid"], gate.mode, number)
        probe.require(events[:len(prefix)] == prefix and event["point"] == number and
                      event["mode"] == gate.mode and event["host_pid"] == result["qemu_pid"],
                      "Retirement evidence belongs to another boundary")
        path = directory / f"maps-point-{number}.txt"
        probe.require(probe.sha(path) == event["maps_sha256"], "Saved maps changed")
        memory = inspect_memory(parse_maps(path.read_text()), arena, gate.owner, gate.observer, gate.phase1,
                                released=number == 2 and gate.mode == "uninstall")
        probe.require(all(event[key] == value for key, value in memory.items()), "Memory result mismatch")
    released = point == 2 and gate.mode == "uninstall"
    return {"owned_arena_released": released, "test_plugin_unloaded": released,
            "arena_bytes": ARENA_SIZE, "phase1_detached": False, "phase1_memory_released": False,
            "memory_isolation": False, "residue_free": False, "whole_qemu_stop": False,
            "release_before_abort": released and result["expected_qemu_exit"] != 0}


def build(out):
    built = probe.build(out)
    plugin = Path(out) / "libcapsule_retire.so"
    flags = shlex.split(probe.command("pkg-config", "--cflags", "glib-2.0"))
    probe.command("cc", "-std=c11", "-O2", "-g", "-Wall", "-Wextra", "-Werror", "-Wformat=2",
                  "-Wshadow", "-fPIC", "-fvisibility=hidden", "-shared", "-Wl,-z,relro,-z,now",
                  "-I", probe.HERE / "vendor", HERE / "retire.c", "-o", plugin, *flags)
    built["retirement_plugin"] = str(plugin)
    built["hashes"].update({"retire.c": probe.sha(HERE / "retire.c"), plugin.name: probe.sha(plugin)})
    probe.write_json(Path(out) / "build.json", built)
    return built


def suite(args):
    audit = probe.checked_audit(args.repo)
    qemu = args.qemu.resolve(strict=True)
    phase1_cls, runtime, qemu_info = probe.load_phase1(args.repo.resolve(), args.phase1, qemu)
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    report = {"schema": 1, "status": "failed", "scope": "controlled_owned_arena_retirement",
              "source_audit": audit, "qemu": qemu_info, "cases": []}
    try:
        built = build(out / "build")
        report["build"] = built
        for name in CASES if args.case == "all" else (args.case,):
            case, before, keep = CASES[name]
            directory = out / name
            mode = "keep" if keep else "uninstall"
            owner = built["retirement_plugin"]
            log = directory / "retirement.jsonl"
            probe.require(all("," not in str(p) and "\n" not in str(p) for p in (owner, log)),
                          "Invalid retirement plugin path")
            argument = ",".join((owner, f"p1={built['symbols']['capsule_point_one']:#x}",
                                 f"p2={built['symbols']['capsule_point_two']:#x}", f"log={log}", f"mode={mode}"))
            gate = RetirementGate(directory, owner, built["plugin"],
                                  runtime.plugin if case != "alone" else None, mode)
            result = probe.run_case(case, directory, built, qemu, runtime, phase1_cls, 200, 5000, 30000,
                                    plugins_before=(argument,) if before else (),
                                    plugins_after=() if before else (argument,), transition=gate)
            result["retirement_case"] = name
            if result["status"] == "passed":
                try:
                    for artifact in (built["plugin"], built["guest"], owner):
                        probe.require(probe.sha(artifact) == built["hashes"][Path(artifact).name],
                                      "Built runtime artifact changed during execution")
                    result["retirement"] = verify_result(directory, result, gate, built, case)
                except Exception as exc:
                    result.update(status="failed", error=f"{type(exc).__name__}: {exc}")
            probe.write_json(directory / "result.json", result)
            report["cases"].append(result)
            probe.write_json(out / "report.json", report)
            print(f"{name}: {result['status']}" + (" — " + result["error"] if "error" in result else ""), flush=True)
        probe.require(probe.sha(qemu) == qemu_info["sha256"] and probe.audit(args.repo)["compatible"],
                      "QEMU or integration source changed during suite")
        report["status"] = "passed" if all(case["status"] == "passed" for case in report["cases"]) else "failed"
    except Exception as exc:
        report["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        probe.write_json(out / "report.json", report)
    print(out / "report.json")
    return 0 if report["status"] == "passed" else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--qemu", type=Path, default=Path("/usr/bin/qemu-i386"))
    parser.add_argument("--phase1", type=Path, default=Path("build/libtaintforge_ir.so"))
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--case", choices=("all", *CASES), default="all")
    args = parser.parse_args()
    try:
        return suite(args)
    except (OSError, ValueError, probe.ProbeError) as exc:
        print(f"Retirement experiment: {type(exc).__name__}: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
