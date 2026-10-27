"""Address-independent observation prototype; trusted benign i386 inputs only."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import select
import shlex
import socket
import struct
import time

from experiments.execution_capsule_probe import controller as p
from taintforge_env import phase1_retirement as retirement, retirement_mappings as mappings
from taintforge_env.phase1_runtime import _parse, read_json

HERE = Path(__file__).resolve().parent
PROFILE = "independent-observer-m2"
PROTOCOL = 3
PC_SOURCE = "qemu_plugin_insn_vaddr"
FAULTS = {"none": 0, "disconnect-before": 125, "timeout-before": 124,
          "disconnect-after": 125, "timeout-after": 124}
WINDOW = "observer_callback_entries_from_pre_permit_stamp_to_post_unmap_hold"


def build_plugin(out):
    out = Path(out).resolve()
    out.mkdir(parents=True, exist_ok=False)
    header = p.HERE / "vendor/qemu-plugin.h"
    p.require(p.sha(header) == read_json(p.HERE / "BASELINE.json")["qemu_header_sha256"],
              "Pinned API header changed")
    flags = shlex.split(p.command("pkg-config", "--cflags", "--libs", "glib-2.0"))
    plugin = out / "libretirement_observer.so"
    p.command("cc", "-std=c11", "-O2", "-g", "-Wall", "-Wextra", "-Werror", "-Wshadow",
              "-Wformat=2", "-fPIC", "-fvisibility=hidden", "-shared", "-pthread",
              "-Wl,-z,relro,-z,now", "-I", header.parent, HERE / "observer.c", "-o", plugin, *flags)
    result = dict(plugin=str(plugin), plugin_sha256=p.sha(plugin),
                  source_sha256={"observer.c": p.sha(HERE / "observer.c"), "qemu-plugin.h": p.sha(header),
                                 "afl_coverage.h": p.sha(HERE.parent / "afl_file/coverage.h")})
    p.write_json(out / "build.json", result)
    return result


def build(out):
    result = build_plugin(out)
    out = Path(out).resolve()
    plugin = Path(result["plugin"])
    guests = {}
    for variant, base, loops in (("long", 0x08048000, 20000000),
                                 ("relocated", 0x09048000, 20000000),
                                 ("short", 0x0a048000, 128)):
        obj, guest = out / (variant + ".o"), out / variant
        p.command("as", "--32", "--defsym", "WORK_LOOPS=" + str(loops), HERE / "guest.S", "-o", obj)
        p.command("ld", "-m", "elf_i386", "-Ttext-segment=" + hex(base), "-z", "noexecstack",
                  "--build-id=none", obj, "-o", guest)
        # This known OEP is the Phase-1 TEST ORACLE, never an observer option.
        expected = [int(line.split()[2], 16) for line in p.command("nm", "-P", guest).splitlines()
                    if line.startswith("phase1_payload_entry ")]
        p.require(len(expected) == 1, "Missing test oracle")
        p.command("strip", "--strip-all", guest)
        p.require(".symtab" not in p.command("readelf", "-S", guest), "Guest was not stripped")
        guests[variant] = dict(path=str(guest), sha256=p.sha(guest), expected_oep=expected[0],
                               work_loops=loops, stripped=True, load_base=base)
    result = dict(plugin=str(plugin), plugin_sha256=p.sha(plugin), guests=guests,
                  source_sha256={name: p.sha(HERE / name) for name in ("observer.c", "guest.S")})
    p.write_json(out / "build.json", result)
    return result


def observation_protocol(config):
    if "protocol" not in config:
        p.require("pc_source" not in config, "Unversioned PC observation contract")
        return 2  # Saved pre-fix evidence retains its original strict meaning.
    p.require(type(config["protocol"]) is int and config["protocol"] == PROTOCOL and
              config.get("pc_source") == PC_SOURCE, "Unsupported PC observation contract")
    return PROTOCOL


class Channel:
    def __init__(self, connection, record, timeout=6, protocol=PROTOCOL):
        self.connection, self.record, self.timeout = connection, record, timeout
        self.protocol = protocol
        self.buffer = b""

    def command(self, value):
        self.connection.sendall((value + "\n").encode("ascii"))
        self.record({"event": "command", "command": value})

    def receive(self, expected=None):
        deadline = time.monotonic() + self.timeout
        while b"\n" not in self.buffer:
            remaining = deadline - time.monotonic()
            p.require(remaining > 0, "Observer message deadline")
            self.connection.settimeout(remaining)
            data = self.connection.recv(2048)
            p.require(data, "Observer channel closed")
            self.buffer += data
            p.require(len(self.buffer) <= 4096, "Oversized observer frame")
        line, self.buffer = self.buffer.split(b"\n", 1)
        item = _parse(line.decode("ascii"))
        p.require(isinstance(item, dict) and type(item.get("protocol")) is int and
                  item["protocol"] == self.protocol, "Wrong observer protocol")
        self.record(item)
        if item.get("event") == "early_exit":
            raise EarlyExit("Guest exited before a post-unmap observation")
        p.require(expected is None or item.get("event") == expected, "Unexpected observer event")
        return item

    def wait_gate(self, gate, expected):
        deadline = time.monotonic() + self.timeout
        while time.monotonic() < deadline:
            # Drain a guest exit before considering a permit/completion ready.
            if self.buffer or select.select([self.connection], [], [], 0)[0]:
                self.receive("no_unsolicited_event_expected")
            if gate.poll(.01):
                p.require(gate.recv() == expected, "Wrong permit gate event")
                self.record({"event": expected})
                return
        raise TimeoutError("Permit gate deadline: " + expected)


class EarlyExit(p.ProbeError):
    pass


def snapshot_ok(item, pid, point, sample, protocol=PROTOCOL):
    p.require(protocol in (2, PROTOCOL), "Unsupported snapshot protocol")
    keys = {"event", "protocol", "host_pid", "point", "sample", "seq", "pc",
            "monotonic_ms", "regs", "stack_readable", "stack_hex"}
    if protocol == PROTOCOL:
        keys |= {"pc_source", "qemu_eip"}
    p.require(set(item) == keys and
              item["event"] == "snapshot" and type(item["protocol"]) is int and
              item["protocol"] == protocol and item["host_pid"] == pid and
              item["point"] == point and item["sample"] == sample, "Invalid observer snapshot identity")
    p.require(all(type(item[k]) is int and item[k] > 0 for k in ("seq", "pc", "monotonic_ms")) and
              item["pc"] <= 0xffffffff and type(item["regs"]) is list and
              len(item["regs"]) == (9 if protocol == 2 else 8) and
              all(type(n) is int and 0 <= n <= 0xffffffff for n in item["regs"]),
              "Invalid observer coordinates")
    if protocol == 2:
        p.require(item["pc"] == item["regs"][8], "Invalid legacy observer PC")
    else:
        p.require(item["pc_source"] == PC_SOURCE and type(item["qemu_eip"]) is int and
                  0 <= item["qemu_eip"] <= 0xffffffff, "Invalid raw EIP/source observation")
    # This benign profile requires a readable stack.
    p.require(item["stack_readable"] is True and isinstance(item["stack_hex"], str) and
              len(item["stack_hex"]) == 64 and all(c in "0123456789abcdef" for c in item["stack_hex"]),
              "Missing fixture stack observation")


def same_hold(first, second, hold_ms):
    keys = ["protocol", "host_pid", "seq", "pc", "regs", "stack_hex"]
    if first["protocol"] == PROTOCOL:
        keys += ["pc_source", "qemu_eip"]
    p.require(all(first[k] == second[k] for k in keys) and
              second["monotonic_ms"] >= first["monotonic_ms"] + hold_ms - 2,
              "Guest changed while held")


@dataclass(frozen=True)
class UnmapObservation:
    """Exact live evidence retained in memory until HOLD has been acknowledged."""
    maps_bytes: bytes
    stat_bytes: bytes

    def event(self):
        return dict(event="module_unmapped", maps_sha256=hashlib.sha256(self.maps_bytes).hexdigest(),
                    process_stat_sha256=hashlib.sha256(self.stat_bytes).hexdigest())

    def save(self, binding):
        output = retirement.directory(binding)
        (output / "maps-unmapped.txt").write_bytes(self.maps_bytes)
        (output / "process-unmapped.stat").write_bytes(self.stat_bytes)


def live_unmapped(binding, pid):
    """Read while the guest RUNS; do not write evidence before requesting HOLD."""
    identity = mappings.load_identity(binding)
    proc = Path(binding["rootfs"]) / "proc" / str(pid)
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        before = (proc / "stat").read_text()
        maps_bytes = (proc / "maps").read_bytes()
        stat_bytes = (proc / "stat").read_bytes()
        text, after = maps_bytes.decode(), stat_bytes.decode()
        p.require(mappings.process_identity(before) == mappings.process_identity(after) ==
                  (pid, identity["process_start_ticks"]), "Process changed during removal observation")
        rows = retirement.maps.parse_maps(text)
        module = identity["modules"]["phase1"]
        if not retirement.maps.file_mapped(rows, (tuple(module["device"]), module["inode"])):
            mappings.verdict(identity, text, True)
            return UnmapObservation(maps_bytes, stat_bytes)
        time.sleep(.001)  # Bounded polling, never substitutes for the maps predicate.
    raise TimeoutError("Phase 1 module still mapped after release")


def control_worker(endpoint, pipe, gate, binding):
    output = Path(binding["run_dir"]) / "logs/capsule"
    result = {"status": "failed", "profile": PROFILE}
    listener = connection = channel = None
    stage, ready = "socket", False
    journal = []
    deferred = False
    unmap_observation = None

    def save_journal():
        # Atomic bounded journal: at most a few dozen records in this protocol.
        p.write_json(output / "observer-events.json", {"schema": 2, "events": journal})

    def record(event):
        journal.append(event | {"controller_seq": len(journal)+1, "controller_ns": time.monotonic_ns()})
        if not deferred:
            save_journal()

    def save_pending():
        nonlocal unmap_observation, deferred
        if unmap_observation is not None:
            unmap_observation.save(binding)
            unmap_observation = None
        if deferred:
            save_journal()
            deferred = False

    try:
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        stage = "bind"
        listener.bind(str(endpoint)); os.chmod(endpoint, 0o600); listener.listen(1)
        if 'hardening' in binding.get('settings', {}):
            from taintforge_env.capsule_hardening import socket_permissions
            socket_permissions(endpoint, binding)
        listener.settimeout(6)
        pipe.send("ready"); ready = True
        stage = "qemu_pid"
        p.require(pipe.poll(5), "Missing QEMU PID")
        pid = pipe.recv()
        stage = "accept"
        connection, _ = listener.accept()
        listener.close(); listener = None
        peer = struct.unpack("3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        from taintforge_env.capsule_hardening import peer_uid
        p.require(peer[:2] == (pid, peer_uid(binding)), "Wrong observer peer")
        config = binding["observer"]
        protocol = observation_protocol(config)
        channel = Channel(connection, record, protocol=protocol)
        stage = "bootstrap"
        for point in (1, 2):
            first = channel.receive("snapshot")
            snapshot_ok(first, pid, point, 1, protocol)
            if point == 2:
                # Persist after HOLD; disk latency consumes the hold budget.
                stage = "post_unmap_evidence"
                save_pending()
                stage = "post_unmap_hold"
            mapping = mappings.capture(binding, pid, point)
            if 'hardening' in binding.get('settings', {}):
                from taintforge_env.capsule_hardening import capture_context
                mapping.update(capture_context(binding, pid, point))
            record(dict(event="maps_held", point=point, **mapping))
            time.sleep(config["hold_ms"] / 1000)
            channel.command("CHECK " + str(point))
            second = channel.receive("snapshot")
            snapshot_ok(second, pid, point, 2, protocol)
            same_hold(first, second, config["hold_ms"])
            fault_point = "before" if point == 1 else "after"
            if config["fault"].endswith("-" + fault_point):
                record({"event": "fault_injected", "fault": config["fault"]})
                if config["fault"].startswith("timeout"):
                    connection.settimeout(6)
                    p.require(connection.recv(2048) == b"", "Observer failed to abort hold timeout")
                result.update(status="fault_injected", fault=config["fault"])
                return
            channel.command("RESUME " + str(point))
            resumed = channel.receive("resumed")
            p.require(resumed["point"] == point and resumed["seq"] == first["seq"], "Invalid resume acknowledgement")
            if point == 1:
                stage = "pre_permit_stamp"
                if "input_retirement" in binding:
                    channel.timeout = config["total_ms"] / 1000 + 1
                channel.wait_gate(gate, "export_ready")
                channel.timeout = 6
                channel.command("STAMP")
                stamp = channel.receive("stamp")
                p.require(stamp["host_pid"] == pid and type(stamp["seq"]) is int and stamp["seq"] >= 1,
                          "Invalid progress stamp")
                record({"event": "permit_grant", "pre_permit_seq": stamp["seq"]})
                gate.send("grant")
                stage = "removal"
                channel.wait_gate(gate, "released")
                retirement.verify_retirement(binding, pid)
                time.sleep(config["after_release_delay_ms"] / 1000)
                # Detect already-buffered early exit before requesting any hold.
                if channel.buffer or select.select([connection], [], [], 0)[0]:
                    channel.receive("no_unsolicited_event_expected")
                # No evidence writes/fsync until HOLD is acknowledged.
                deferred = True
                unmap_observation = live_unmapped(binding, pid)
                record(unmap_observation.event())
                channel.command("HOLD 2")
                stage = "post_unmap_hold"
            else:
                p.require(first["seq"] >= stamp["seq"], "Observer sequence regressed")
                record(dict(event="progress_window", scope=WINDOW, lower_seq=stamp["seq"],
                            upper_seq=first["seq"], entries=first["seq"]-stamp["seq"],
                            exact_uninstall_interval=False, exact_oep_cutover=False))
        if 'afl_warm' in binding:
            stage = 'warm_checkpoint'
            channel.timeout = binding['afl_warm']['bootstrap_seconds'] + 1
            checkpoint = channel.receive('warm_checkpoint')
            p.require(checkpoint['host_pid'] == pid and checkpoint['seq'] > first['seq'],
                      'Warm checkpoint precedes retirement continuation')
        stage = "guest_exit"
        channel.timeout = config["total_ms"] / 1000 + 1
        done = channel.receive("done")
        p.require(done["host_pid"] == pid and done["seq"] > first["seq"], "No progress after final resume")
        # Wait for QEMU to close the socket so its watchdog cannot race us.
        connection.settimeout(2)
        p.require(not channel.buffer and connection.recv(1) == b"", "Trailing observer events")
        result["status"] = "passed"
    except EarlyExit as exc:
        result.update(status="inconclusive", error=str(exc), stage=stage)
    except Exception as exc:
        result.update(error=f"{type(exc).__name__}: {exc}", failure=p.worker_failure(exc, "observer", stage, ready))
        # Only a native early_exit frame permits an inconclusive result.
        if channel is not None and stage in {"pre_permit_stamp", "removal", "post_unmap_hold"}:
            try:
                if channel.buffer or select.select([connection], [], [], .1)[0]:
                    channel.receive("no_unsolicited_event_expected")
            except EarlyExit as early:
                result = dict(status="inconclusive", profile=PROFILE, error=str(early), stage=stage)
            except Exception:
                pass
        if not ready:
            p.send_startup_failure(pipe, result["failure"])
    finally:
        if connection is not None: connection.close()
        if listener is not None: listener.close()
        pipe.close(); gate.close()
        # Preserve partial evidence; persistence failure cannot pass.
        try:
            save_pending()
        except Exception as exc:
            result.update(status="failed", evidence_persistence_error=f"{type(exc).__name__}: {exc}",
                          failure=p.worker_failure(exc, "observer", "persist_evidence", ready))
        p.write_json(output / "controller.json", result)


def verify_attempt(binding, result):
    """Replay the saved ordering; no live /proc paths or fixture stop symbols."""
    input_mode = "input_retirement" in binding
    if input_mode:
        from taintforge_env.input_retirement import verify_contract
        verify_contract(binding)
    else:
        p.require(binding.get("observer", {}).get("profile") == PROFILE, "Unsupported observer profile")
    config = binding["observer"]
    protocol = observation_protocol(config)
    p.require(config["fault"] in FAULTS, "Unknown observer fault")
    root = Path(binding["run_dir"])
    contract = root / "config/observer-contract.json"
    module_paths = mappings.module_paths(binding)
    p.require(input_mode or (read_json(contract) == config | {
        "selection_delay": binding["settings"]["phase1_retirement"]["selection_delay"],
        "phase1_sha256": p.sha(module_paths["phase1"]), "observer_sha256": p.sha(module_paths["observer"])} and
        p.sha(contract) == binding["attempt_contract_sha256"] and
        p.sha(root / "guest-i386") == config["guest_sha256"]), "Observer contract/input changed")
    output = Path(binding["run_dir"]) / "logs/capsule"
    journal = read_json(output / "observer-events.json", 256*1024)
    p.require(set(journal) == {"schema", "events"} and journal["schema"] == 2, "Invalid observer journal schema")
    events = journal["events"]
    p.require(isinstance(events, list) and 0 < len(events) <= 40, "Invalid observer journal")
    for index, event in enumerate(events, 1):
        p.require(event["controller_seq"] == index and type(event["controller_ns"]) is int and
                  event["controller_ns"] > 0 and (index == 1 or
                  event["controller_ns"] >= events[index-2]["controller_ns"]), "Invalid controller ordering")
    stripped = [{k:v for k,v in e.items() if k not in {"controller_seq", "controller_ns"}} for e in events]
    kinds = [e["event"] if e["event"] != "command" else e["command"] for e in stripped]
    first_order = ["snapshot", "maps_held", "CHECK 1", "snapshot"]
    prefix = first_order + ["RESUME 1", "resumed", "export_ready", "STAMP", "stamp", "permit_grant", "released"]
    second_order = ["module_unmapped", "HOLD 2", "snapshot", "maps_held", "CHECK 2", "snapshot"]
    success_order = prefix + second_order + ["RESUME 2", "resumed", "progress_window", "done"]
    if 'afl_warm' in binding:
        success_order.insert(-1, 'warm_checkpoint')
    controller = read_json(output / "controller.json")
    fault, code = config["fault"], result["qemu_exit"]
    if fault == "none" and (code == 0 or (input_mode and type(code) is int and
                                         0 <= code <= 255 and kinds == success_order)):
        p.require(kinds == success_order and controller["status"] == "passed", "Invalid successful observer order")
        status = "passed"
    elif fault != "none":
        expected = first_order if fault.endswith("-before") else prefix + second_order
        p.require(kinds == expected + ["fault_injected"] and code == FAULTS[fault] and
                  controller["status"] == "fault_injected" and stripped[-1]["fault"] == fault,
                  "Expected observer fault was not exercised")
        status = "aborted"
    else:
        # Honest early exit: only a valid prefix plus the explicit native event.
        n = len(kinds)-1
        p.require(code == 123 and controller["status"] == "inconclusive" and
                  kinds[-1] == "early_exit" and kinds[:-1] == success_order[:n] and
                  "snapshot" not in kinds[len(prefix)+len(second_order):], "Unproven/invalid early exit")
        status = "inconclusive"
    p.require(not result["supervisor_kill"] and result["controller_exit"] == 0 and
              all(result[k] == binding[k] for k in mappings.IDENTITY), "Observer attempt identity/finalization mismatch")
    pid = result["qemu_pid"]
    identity = mappings.load_identity(binding)
    for event in stripped:
        if event["event"] in {"snapshot", "resumed", "stamp", "done", "early_exit", "warm_checkpoint"}:
            p.require(type(event.get("protocol")) is int and event["protocol"] == protocol,
                      "Mixed/downgraded observer protocol")
        if event["event"] in {"stamp", "done", "early_exit", "warm_checkpoint"}:
            p.require(event.get("host_pid") == pid and
                      type(event.get("seq")) is int and event["seq"] >= 1, "Invalid counter event identity")
    for point in (1, 2):
        snapshots = [e for e in stripped if e["event"] == "snapshot" and e["point"] == point]
        p.require(len(snapshots) in (0,2), "Incomplete hold observation")
        if snapshots:
            for sample, snap in enumerate(snapshots, 1): snapshot_ok(snap, pid, point, sample, protocol)
            same_hold(*snapshots, config["hold_ms"])
            if point == 1:
                p.require(snapshots[0]["seq"] == 1, "Bootstrap was not at the first observer boundary")
                if input_mode:
                    p.require(snapshots[0]["pc"] == binding["input_retirement"]["entry_point"],
                              "M3 bootstrap differs from the bound ELF entry point")
            maps = [e for e in stripped if e["event"] == "maps_held" and e["point"] == point]
            p.require(len(maps) == 1, "Missing/duplicate mapping observation")
            mappings.verify_observation(binding, maps[0], pid)
            for resumed in [e for e in stripped if e["event"] == "resumed" and e["point"] == point]:
                p.require(resumed["seq"] == snapshots[0]["seq"], "Resume/snapshot sequence mismatch")
    pre = [e for e in stripped if e["event"] == "stamp"]
    if pre:
        stamp = pre[0]
        p.require(stamp["host_pid"] == pid and type(stamp["seq"]) is int and stamp["seq"] >= 1 and
                  next(e for e in stripped if e["event"] == "permit_grant")["pre_permit_seq"] == stamp["seq"],
                  "Invalid saved pre-permit stamp")
        p.require(type(stamp.get("monotonic_ms")) is int and stamp["monotonic_ms"] >= stripped[0]["monotonic_ms"],
                  "Progress stamp predates bootstrap")
        for event in stripped:
            if event["event"] == "snapshot" and event["point"] == 2:
                p.require(event["seq"] >= stamp["seq"] and event["monotonic_ms"] >= stamp["monotonic_ms"],
                          "Post-unmap snapshot predates the pre-permit stamp")
    unmapped = [e for e in stripped if e["event"] == "module_unmapped"]
    accepted = None
    if "released" in kinds:
        retirement.verify_retirement(binding, pid)
    if unmapped:
        accepted = retirement.verify_retirement(binding, pid)
        event = unmapped[0]
        for name, key in (("maps-unmapped.txt", "maps_sha256"), ("process-unmapped.stat", "process_stat_sha256")):
            p.require(p.sha(retirement.directory(binding) / name) == event[key], "Unmap evidence changed")
        p.require(mappings.process_identity((retirement.directory(binding) / "process-unmapped.stat").read_text()) ==
                  (pid, identity["process_start_ticks"]), "Unmap process changed")
        mappings.verdict(identity, (retirement.directory(binding) / "maps-unmapped.txt").read_text(), True)
    stdout = (Path(binding["run_dir"]) / "logs/runtime_stdout.log").read_bytes()
    diagnostic = (Path(binding["run_dir"]) / "logs/qemu_strace.log").read_text(errors="replace")
    if status == "passed":
        held = next(e for e in stripped if e["event"] == "snapshot" and e["point"] == 2)
        window = next(e for e in stripped if e["event"] == "progress_window")
        p.require(window == dict(event="progress_window", scope=WINDOW, lower_seq=pre[0]["seq"],
                  upper_seq=held["seq"], entries=held["seq"]-pre[0]["seq"],
                  exact_uninstall_interval=False, exact_oep_cutover=False) and window["entries"] >= 0,
                  "Invalid measured progress window")
        p.require(stripped[-1]["seq"] > held["seq"] and stripped[-1]["host_pid"] == pid and
                  (input_mode or (stdout == b"CAPSULE_OK\n" and
                  (output / "capsule-fd.txt").read_bytes() == p.FILE_BYTES)),
                  "Guest continuation oracle failed")
    else:
        p.require(f"OBSERVER_ABORT code={code} " in diagnostic, "Missing native terminal diagnosis")
    hardening = {}
    if 'hardening' in binding.get('settings', {}) and status == 'passed':
        from taintforge_env.capsule_hardening import verify_saved, verify_ledger
        hardening['hardening'] = verify_saved(binding, stripped, pid)
        report = read_json(retirement.analysis(binding).paths['report'])
        verify_ledger(binding, accepted['events'][-1]['data'], report)
    return dict(status=status, **hardening, continuation_observed=status == "passed", guest_completed=status == "passed" and "afl_warm" not in binding,
                phase1_retirement=dict(status="verified" if accepted else "unproven", phase1_retired=bool(accepted),
                    claims=retirement.CLAIMS, verdict=accepted["events"][0]["data"] if accepted else None))
