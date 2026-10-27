"""Bind fixture retirement to a unified attempt."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat

from experiments.execution_capsule_lifecycle import controller as lifecycle

probe = lifecycle.probe
retirement = lifecycle.retirement
OWNER_PATH = "capsule/libcapsule_lifecycle.so"
MODES = {"remove": None, "keep": "missing_stage", "leak-arena": "arena_still_mapped",
         "bad-export": "export_digest"}


def settings(mode="remove", order="after"):
    probe.require(mode in MODES and order in {"before", "after"}, "Invalid lifecycle mode or owner order")
    return {"protocol": 1, "producer": "capsule-fixture-v1", "mode": mode, "owner_order": order}


def bundle_profile(built):
    return {"protocol": 1, "producer": "capsule-fixture-v1", "plugin": OWNER_PATH,
            "sha256": probe.sha(built["lifecycle_plugin"]),
            "source_sha256": probe.sha(lifecycle.HERE / "owner.c")}


def verify_profile(profile, inventory):
    probe.require(set(profile) == {"protocol", "producer", "plugin", "sha256", "source_sha256"}
                  and type(profile["protocol"]) is int and profile["protocol"] == 1
                  and profile["producer"] == "capsule-fixture-v1" and profile["plugin"] == OWNER_PATH
                  and OWNER_PATH in inventory and inventory[OWNER_PATH]["sha256"] == profile["sha256"]
                  and profile["source_sha256"] == probe.sha(lifecycle.HERE / "owner.c"),
                  "Unbound or unsupported capsule lifecycle owner")


def output_directory(binding):
    return Path(binding["run_dir"]) / "logs/capsule/lifecycle"


def gate(binding, ipc):
    run = Path(binding["run_dir"])
    bundle = run / "config/analyzer_runtime"
    phase1 = json.loads((run / "config/phase1_binding.json").read_text())
    return lifecycle.LifecycleGate(Path(ipc) / "events.sock", output_directory(binding),
        bundle / OWNER_PATH, bundle / binding["capsule"]["plugin"], bundle / phase1["plugin"],
        binding["lifecycle_attempt"], artifact=Path(ipc) / "export.bin",
        proc_root=Path(binding["rootfs"]) / "proc")


def plugin_argument(binding, ipc_guest):
    config = binding["settings"]["lifecycle"]
    return ",".join(["/__taintforge/" + OWNER_PATH,
        f"p1={binding['capsule']['symbols']['capsule_point_one']:#x}",
        f"socket={ipc_guest}/events.sock", f"export={ipc_guest}/export.bin",
        "attempt=" + binding["lifecycle_attempt"], "mode=" + config["mode"]])


class Transition:
    def __init__(self, handoff, owner_gate):
        self.handoff, self.owner_gate = handoff, owner_gate

    def __call__(self, action, point, snapshot, record):
        self.handoff(action, point, snapshot, record)
        self.owner_gate(action, point, snapshot, record)


def capture_export(binding, ipc):
    source = Path(ipc) / "export.bin"
    try:
        fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except FileNotFoundError:
        return
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        probe.require(stat.S_ISREG(info.st_mode) and info.st_size <= 1024, "Invalid lifecycle export artifact")
        data = stream.read(1025)
        probe.require(len(data) <= 1024, "Lifecycle export grew beyond its bound")
    (output_directory(binding) / "export.bin").write_bytes(data)


def verify_saved(binding, result, journal):
    """Recheck the recorded protocol, export, maps and links to the observer journal."""
    directory = output_directory(binding)
    records = [event for event in journal if event.get("event") in {"lifecycle_observed", "lifecycle_rejected"}]
    expected_reason = MODES[binding["settings"]["lifecycle"]["mode"]]
    probe.require(records and len(records) <= 2, "Missing or duplicate lifecycle observations")
    bundle = Path(binding["run_dir"]) / "config/analyzer_runtime"
    phase1 = json.loads((Path(binding["run_dir"]) / "config/phase1_binding.json").read_text())
    identities = [retirement.file_identity(bundle / path) for path in
                  (OWNER_PATH, binding["capsule"]["plugin"], phase1["plugin"])]
    previous = []
    started = None
    verified_release = False
    rejection = None
    hashes = {}
    for point, recorded in enumerate(records, 1):
        path = directory / f"evidence-point-{point}.json"
        saved = json.loads(path.read_text())
        probe.require(recorded == {"event": "lifecycle_rejected" if saved["status"] == "rejected"
                                  else "lifecycle_observed", **saved}, "Lifecycle journal/artifact mismatch")
        probe.require(saved["point"] == point and saved["claims"] == lifecycle.CLAIMS,
                      "Lifecycle point or claims mismatch")
        hashes[path.name] = probe.sha(path)
        evidence = lifecycle.Evidence(binding["lifecycle_attempt"], result["qemu_pid"], directory / "export.bin")
        events = saved["producer_events"]
        probe.require(events[:len(previous)] == previous, "Lifecycle prefix changed between observations")
        for event in events:
            evidence.feed(json.dumps(event).encode())
        previous = events
        probe.require(type(saved["stream_closed"]) is bool, "Invalid lifecycle EOF flag")
        evidence.eof = saved["stream_closed"]
        probe.require(saved["export_verified_on_receipt"] is (len(events) >= 2)
                      and saved["callbacks_removed_reported"] is (len(events) >= 4)
                      and saved["resources_released_reported"] is (len(events) == 5),
                      "Lifecycle stage flags disagree with the protocol")
        if saved["status"] == "rejected":
            rejection = saved.get("error")
            probe.require(rejection == expected_reason and point == len(records), "Unexpected lifecycle rejection")
            try:
                if rejection == "export_digest":
                    evidence.feed(saved["last_packet"].encode())
                elif rejection == "missing_stage":
                    evidence.finish()
                elif rejection == "arena_still_mapped":
                    evidence.finish()
                    rows = _maps(directory, point, saved, result, hashes)
                    arena = events[0]["data"]
                    probe.require(point == 2 and saved["process_start_ticks"] == started,
                                  "Rejected lifecycle maps belong to a different process")
                    mapped = {"owner_library_absent": not retirement.file_mapped(rows, identities[0]),
                              "arena_range_absent": not any(lo < arena["mapping_start"] + arena["mapping_size"]
                                  and hi > arena["mapping_start"] for lo, hi, *_ in rows)}
                    probe.require(mapped == saved["mapping_evidence"], "Rejected mapping verdict mismatch")
                    lifecycle.require(mapped["owner_library_absent"], "module_still_mapped")
                    lifecycle.require(mapped["arena_range_absent"], "arena_still_mapped")
                else:
                    raise RuntimeError("Unsupported lifecycle rejection")
            except lifecycle.EvidenceError as exc:
                probe.require(exc.code == rejection, "Lifecycle rejection was not reproduced")
            else:
                raise probe.ProbeError("Lifecycle rejection has no supporting evidence")
            continue
        probe.require(saved["status"] == ("observed" if point == 1 else "verified"), "Invalid lifecycle status")
        if point == 1:
            probe.require(1 <= len(events) <= 3 and not evidence.eof, "Invalid first lifecycle observation")
        else:
            evidence.finish()
        rows = _maps(directory, point, saved, result, hashes)
        ticks = saved["process_start_ticks"]
        probe.require(type(ticks) is int and ticks >= 0 and (started is None or ticks == started),
                      "Lifecycle process changed between points")
        started = ticks
        mapped = retirement.inspect_memory(rows, events[0]["data"], *identities, released=point == 2)
        probe.require(mapped == saved["mapping_evidence"], "Saved lifecycle mapping verdict mismatch")
        verified_release = point == 2
    if (directory / "export.bin").exists():
        hashes["export.bin"] = probe.sha(directory / "export.bin")
    return {"status": "rejected" if rejection else "verified" if verified_release else "incomplete",
            "rejection": rejection, "points": len(records), "owner_retired": verified_release,
            "attempt": binding["lifecycle_attempt"], "claims": lifecycle.CLAIMS, "evidence_sha256": hashes}


def _maps(directory, point, saved, result, hashes):
    path = directory / f"maps-point-{point}.txt"
    text = path.read_text()
    digest = hashlib.sha256(text.encode()).hexdigest()
    probe.require(saved["qemu_pid"] == result["qemu_pid"] and digest == saved["maps_sha256"],
                  "Lifecycle maps identity or digest mismatch")
    hashes[path.name] = digest
    return retirement.parse_maps(text)
