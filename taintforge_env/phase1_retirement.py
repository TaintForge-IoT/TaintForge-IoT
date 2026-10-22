"""Cooperative Phase 1 retirement for controlled inputs."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import socket
import stat
import struct
import time

from experiments.execution_capsule_probe import controller as probe
from experiments.execution_capsule_retire import controller as maps
from .phase1_runtime import Phase1Run, Phase1Runtime, _parse
from . import retirement_mappings

HERE = Path(__file__).resolve().parents[1] / "experiments/phase1_retirement"
EXTRA_SYMBOLS = ("phase1_payload_entry", "phase1_retire_boundary")
VERDICT_SYMBOLS = ("phase1_payload_entry",)
VERDICT_TRIGGER = "next_instruction_after_selection"
EVENTS = ("verdict", "export_complete", "uninstall_requested", "callbacks_removed", "resources_released")
FAULTS = {"none": 0, "deny": 88, "stale-permit": 88, "bad-digest": 88,
          "disconnect": 88, "timeout": 87, "missing-verdict": 89}
CLAIMS = {"whole_qemu_stop": False, "memory_isolation": False, "oep_proven": False,
          "exact_oep_cutover": False, "residue_free": False, "fuzzing_ready": False,
          "hostile_sample_ready": False, "protected_control_channel": False,
          "all_phase1_allocations_released": False}


def settings(fault="none", *, trigger="boundary", selection_delay=16):
    probe.require(fault in FAULTS, "Unsupported Phase 1 retirement fault")
    probe.require(trigger in {"boundary", "verdict"}, "Unsupported retirement trigger")
    probe.require(type(selection_delay) is int and 1 <= selection_delay <= 256,
                  "Controlled retirement selection delay must be in 1..256")
    if trigger == "verdict":
        return {"protocol": 2, "profile": "phase1-verdict-retirement-v2", "fault": fault,
                "selection_delay": selection_delay, "max_instructions": 2048}
    probe.require(selection_delay == 16, "The v1 boundary fixture fixes the selection delay")
    return {"protocol": 1, "profile": "phase1-controlled-retirement-v1", "fault": fault}


def validate_settings(config):
    if config.get("profile") == "input-static-i386-retirement-m3":
        from .input_retirement import retirement_settings
        probe.require(config == retirement_settings(selection_delay=config["selection_delay"],
                      max_instructions=config["max_instructions"]), "Invalid M3 retirement policy")
        return
    fixture(config["protocol"])
    probe.require(config == settings(config["fault"],
        trigger="verdict" if config["protocol"] == 2 else "boundary",
        selection_delay=config.get("selection_delay", 16)), "Unsupported Phase 1 retirement settings")


def fixture(protocol):
    probe.require(type(protocol) is int and protocol in {1, 2}, "Unsupported retirement protocol")
    return (HERE / "guest_verdict.S", VERDICT_SYMBOLS) if protocol == 2 else (HERE / "guest.S", EXTRA_SYMBOLS)


def build(out, *, trigger="boundary"):
    protocol = settings(trigger=trigger)["protocol"]
    source, symbols = fixture(protocol)
    result = probe.build(out, guest_source=source, extra_symbols=symbols)
    if source.name != "guest.S":
        result["hashes"]["guest.S"] = result["hashes"].pop(source.name)
    result["phase1_retirement"] = {"protocol": protocol, "guest_source_sha256": probe.sha(source)}
    probe.write_json(Path(out) / "build.json", result)
    return result


def directory(binding):
    return Path(binding["run_dir"]) / "logs/capsule/phase1-retirement"


def analysis(binding):
    run = Path(binding["run_dir"])
    config = json.loads((run / "config/phase1_binding.json").read_text())
    probe.require(all(config[k] == binding[k] for k in ("session_id", "attempt_id", "analysis_instance_id",
                  "attempt_contract_sha256", "bundle_sha256")), "Phase 1 retirement binding mismatch")
    return Phase1Run(Phase1Runtime.load(run / "config/analyzer_runtime" / config["plugin"]),
                     config["session_id"], config["attempt_id"], config["analysis_instance_id"],
                     (run / config["output_directory"]).resolve())


def check_runtime(runtime, *, trigger="boundary"):
    sidecar = json.loads(runtime.manifest.read_text())
    probe.require(sidecar.get("formats", {}).get("cooperative_retirement") == 1 and runtime.plugin_api == 6,
                  "Selected Phase 1 build does not support cooperative retirement v1/API 6")
    if trigger == "verdict":
        probe.require(sidecar.get("formats", {}).get("verdict_retirement") == 2,
                      "Selected Phase 1 build does not support verdict retirement v2")


def plugin_options(binding, ipc_guest, controller_pid):
    config = binding["settings"]["phase1_retirement"]
    validate_settings(config)
    trigger = (["retire-trigger=verdict", "retire-max-insns=" + str(config["max_instructions"])]
               if config["protocol"] == 2 else
               ["retire-boundary=" + hex(binding["capsule"]["symbols"]["phase1_retire_boundary"])])
    return ["retire-socket=" + ipc_guest + "/phase1.sock", "retire-nonce=" + binding["lifecycle_attempt"],
            *trigger,
            "retire-controller=" + str(controller_pid), "retire-timeout-ms=5000"]


def check_verdict(binding, event, stream):
    """Check current selection; the legacy fixture additionally binds its OEP."""
    data = event["data"]
    input_mode = "input_retirement" in binding
    if input_mode:
        from .input_retirement import verify_contract
        verify_contract(binding)
    symbols = binding["capsule"].get("symbols", {})
    expected_keys = {"candidate_id", "oep", "decision_pc", "decision_trace_seq", "continuation_pc",
                     "epoch", "generation", "policy", "oep_proven"}
    automatic = binding.get("settings", {}).get("phase1_retirement", {}).get("protocol", 1) == 2
    if automatic:
        expected_keys.add("trigger")
        probe.require(data.get("trigger") == VERDICT_TRIGGER, "Unsupported retirement trigger")
    probe.require(set(data) == expected_keys and data["policy"] == "heuristic_candidate" and
                  data["oep_proven"] is False, "Unsupported OEP verdict policy")
    for key in expected_keys - {"policy", "oep_proven", "trigger"}:
        probe.require(type(data[key]) is int and data[key] >= 0, "Invalid verdict coordinate")
    probe.require(data["candidate_id"] > 0 and data["decision_trace_seq"] > 0 and
                  (0 < data["oep"] <= 0xffffffff if input_mode else data["oep"] == symbols["phase1_payload_entry"]) and
                  0 < data["decision_pc"] <= 0xffffffff and
                  0 < data["continuation_pc"] <= 0xffffffff, "Fixture OEP/continuation mismatch")
    if not automatic:
        probe.require(data["continuation_pc"] == symbols["phase1_retire_boundary"] and
                      data["oep"] != data["continuation_pc"], "Fixture continuation mismatch")
    verdicts = [e for e in stream if e["event_type"] == "oep_verdict"]
    probe.require(verdicts, "No Phase 1 OEP verdict before export")
    v = verdicts[-1]
    committed = {k: data[k] for k in expected_keys - {"epoch", "generation"}} | {"rewind": False}
    probe.require(v["status"] == "selected_candidate" and v["analysis_epoch"] == data["epoch"] and
                  v["code_generation"] == data["generation"] and
                  v["data"] == committed,
                  "Socket verdict differs from committed Phase 1 verdict")
    selected = [e for e in stream[:v["event_seq"]-1] if e["event_type"] == "oep_candidate_selected"]
    probe.require(selected and selected[-1]["data"]["candidate_id"] == data["candidate_id"] and
                  selected[-1]["data"]["address"] == data["oep"], "Verdict has no selected candidate")
    if automatic:
        choice = selected[-1]
        probe.require(len(verdicts) == 1 and choice["status"] == "candidate" and
                      choice["analysis_epoch"] == data["epoch"] and
                      choice["code_generation"] == data["generation"] and
                      choice["current_pc"] == data["decision_pc"] and
                      choice["trace_seq"] == choice["data"]["decision_trace_seq"] == data["decision_trace_seq"] and
                      v["trace_seq"] == data["decision_trace_seq"] and
                      v["current_pc"] == data["continuation_pc"], "Verdict did not retire at the next instruction")
        probe.require(not any(e["event_type"] in {"oep_candidate_invalidated", "code_generation_changed",
                          "profile_lost", "data_loss", "error"} for e in stream[choice["event_seq"]:]),
                      "Selected candidate became stale before retirement")
    probe.require(not any(e["event_type"] in {"oep_candidate_invalidated", "code_generation_changed",
                      "profile_lost", "data_loss", "error"} for e in stream[v["event_seq"]:]),
                  "Verdict invalidated before retirement")
    return v


def check_packets(binding, packets, qpid, *, complete):
    probe.require(0 < len(packets) <= len(EVENTS), "Missing/extra retirement packet")
    for index, item in enumerate(packets):
        probe.require(set(item) == {"protocol", "event", "session_id", "attempt_id", "analysis_instance_id",
                      "nonce", "host_pid", "data"} and type(item["protocol"]) is int and item["protocol"] ==
                      binding.get("settings", {}).get("phase1_retirement", {}).get("protocol", 1) and
                      item["event"] == EVENTS[index] and item["nonce"] == binding["lifecycle_attempt"] and
                      type(item["host_pid"]) is int and item["host_pid"] == qpid and
                      all(item[k] == binding[k] for k in ("session_id", "attempt_id", "analysis_instance_id")),
                      "Retirement packet order/identity mismatch")
        probe.require(isinstance(item["data"], dict), "Invalid retirement packet data")
        if 2 <= index <= 3:
            probe.require(item["data"] == {}, "Unexpected removal payload")
    if complete:
        probe.require(len(packets) == 5, "Incomplete retirement protocol")
        release = packets[-1]["data"]
        expected = {"pages_released", "bitmaps_released", "register_buffers_released",
                      "explicitly_wiped_bytes", "owner_roots_remaining", "all_bytes_zeroed",
                      "allocator_residue_verified", "guest_memory_modified"}
        if 'hardening' in binding.get('settings', {}):
            from .capsule_hardening import verify_ledger
            expected.add('resource_ledger')
            verify_ledger(binding, release)
        probe.require(set(release) == expected, "Unexpected release inventory")
        for name in ("pages_released", "bitmaps_released", "register_buffers_released", "explicitly_wiped_bytes"):
            probe.require(type(release[name]) is int and release[name] > 0, "Missing real Phase 1 release evidence")
        probe.require(type(release["owner_roots_remaining"]) is int and release["owner_roots_remaining"] == 0 and
                      all(release[k] is False for k in ("all_bytes_zeroed", "allocator_residue_verified",
                          "guest_memory_modified")), "Invalid release scope")


def verify_export(binding, packets):
    run = analysis(binding)
    recorded = binding.get("recorded_phase1_directory")
    verified = run.verify(recorded_directory=Path(recorded) if recorded is not None else None)
    probe.require(verified["artifact_integrity"] == "verified" and verified["runtime_observed"] and
                  verified["capture_status"] == "success", "Phase 1 export is incomplete")
    stream = run.events()
    probe.require(stream[0]["data"].get("analysis_detach") == "cooperative-controlled-v1",
                  "Loaded Phase 1 did not enable retirement")
    check_verdict(binding, packets[0], stream)
    manifest = run.paths["manifest"]
    probe.require(packets[1]["data"] == {"sha256": probe.sha(manifest), "size": manifest.stat().st_size},
                  "Retirement manifest digest mismatch")
    report = json.loads(run.paths["report"].read_text())
    if 'hardening' in binding.get('settings', {}):
        from .capsule_hardening import budget_usage
        budget_usage(binding)
    probe.require(run.paths["dump"].is_file() and run.paths["dump"].stat().st_size > 0 and
                  any(int(region["addr"], 16) <= packets[0]["data"]["oep"] <
                      int(region["addr"], 16) + region["size"] and region["prot"] & 4
                      for region in report.get("regions", [])), "Selected code is absent from the export")
    probe.require(report["capture_pc"] == packets[0]["data"]["continuation_pc"] and
                  report["capture_epoch"] == packets[0]["data"]["epoch"] and
                  int(report["oep"], 16) == packets[0]["data"]["oep"], "Capture/verdict coordinates differ")
    if packets[0]["protocol"] == 2:
        probe.require(report["capture_trace_seq"] == packets[0]["data"]["decision_trace_seq"] and
                      report["capture_generation"] == packets[0]["data"]["generation"],
                      "Capture was delayed after the selected verdict")
    return run, verified


def preserve_export(binding, run):
    """Copy and fsync the accepted bytes before granting the permit."""
    destination = directory(binding) / "export"
    destination.mkdir(exist_ok=False)
    hashes = {}
    for name, path in run.paths.items():
        if not path.exists():
            continue
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        with os.fdopen(fd, "rb") as source, (destination / path.name).open("xb") as target:
            st = os.fstat(source.fileno())
            probe.require(stat.S_ISREG(st.st_mode) and st.st_size <= 1024**3, "Unbounded export")
            left = st.st_size
            while left:
                data = source.read(min(left, 1024**2))
                probe.require(data, "Export truncated while preserving")
                target.write(data)
                left -= len(data)
            probe.require(not source.read(1), "Export grew while preserving")
            target.flush()
            os.fsync(target.fileno())
        hashes[path.name] = probe.sha(destination / path.name)
        probe.require(hashes[path.name] == probe.sha(path), "Export changed while preserving")
    for path in (destination, destination.parent):
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    return hashes


def permit_worker(endpoint, pipe, binding, *, progress_pipe=None):
    output = directory(binding)
    result = {"status": "failed", "events": [], "permit_sent": False, "stream_closed": False,
              "nonce": binding["lifecycle_attempt"], "claims": CLAIMS}
    listener = connection = None
    ready = False
    stage = "socket"
    try:
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        stage = "bind"
        listener.bind(str(endpoint))
        os.chmod(endpoint, 0o600)
        if 'hardening' in binding.get('settings', {}):
            from .capsule_hardening import socket_permissions
            socket_permissions(endpoint, binding)
        listener.listen(1)
        listener.settimeout(binding["settings"]["total_ms"] / 1000 + 3)
        pipe.send("ready")
        ready = True
        stage = "qemu_pid"
        probe.require(pipe.poll(5), "Missing QEMU PID for retirement")
        qpid = pipe.recv()
        result["qemu_pid"] = qpid
        stage = "accept"
        connection, _ = listener.accept()
        listener.close()
        connection.settimeout(6)
        stage = "peer_identity"
        peer = struct.unpack("3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        from .capsule_hardening import peer_uid
        probe.require(peer[:2] == (qpid, peer_uid(binding)), "Wrong Phase 1 socket peer")
        fault = binding["settings"]["phase1_retirement"]["fault"]
        for index in range(5):
            stage = "protocol"
            data = connection.recv(2049)
            probe.require(0 < len(data) <= 2048, "Truncated/oversized retirement packet")
            result["events"].append(_parse(data.decode("utf-8")))
            check_packets(binding, result["events"], qpid, complete=False)
            if index == 1:
                stage = "export_verification"
                run, result["export_verification"] = verify_export(binding, result["events"])
                result["preserved_sha256"] = preserve_export(binding, run)
                # Recheck the full manifest after copying, before acknowledging it.
                verify_export(binding, result["events"])
                result["accepted_manifest_sha256"] = probe.sha(run.paths["manifest"])
                if progress_pipe is not None:
                    # STAMP runs on the host thread; a vCPU HOLD here would deadlock.
                    progress_pipe.send("export_ready")
                    probe.require(progress_pipe.poll(3) and progress_pipe.recv() == "grant",
                                  "Observer did not authorize the pre-permit progress stamp")
                if fault in {"disconnect", "timeout"}:
                    result.update(status="fault_injected", fault=fault)
                    probe.write_json(output / "retirement.json", result)
                    if fault == "timeout":
                        probe.require(connection.recv(2049) == b"", "Guest did not abort permit timeout")
                    return
                candidate = result["events"][0]["data"]["candidate_id"]
                nonce = binding["lifecycle_attempt"]
                digest = result["accepted_manifest_sha256"]
                if fault == "stale-permit":
                    nonce = ("1" if nonce[0] == "0" else "0") + nonce[1:]
                if fault == "bad-digest":
                    digest = ("1" if digest[0] == "0" else "0") + digest[1:]
                command = f"RETIRE {nonce} {candidate} {digest}\n" if fault != "deny" else "DENY\n"
                connection.sendall(command.encode("ascii"))
                result.update(permit_sent=fault == "none", permit=command,
                              permit_after_verified_export=True, fault=fault)
                probe.write_json(output / "retirement.json", result)
                if fault != "none":
                    probe.require(connection.recv(2049) == b"", "Invalid permit did not abort Phase 1")
                    result["status"] = "fault_injected"
                    return
        check_packets(binding, result["events"], qpid, complete=True)
        probe.require(connection.recv(2049) == b"", "Extra retirement packet")
        result.update(status="released", stream_closed=True)
        if progress_pipe is not None:
            # Release/EOF precede module close; the observer must check live maps.
            probe.write_json(output / "retirement.json", result)
            progress_pipe.send("released")
    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
        result["failure"] = probe.worker_failure(exc, "permit", stage, ready)
        if not ready:
            try:
                probe.write_json(output / "retirement.json", result)
            finally:
                probe.send_startup_failure(pipe, result["failure"])
    finally:
        if progress_pipe is not None:
            progress_pipe.close()
        if connection is not None:
            connection.close()
        if listener is not None:
            listener.close()
        pipe.close()
        probe.write_json(output / "retirement.json", result)


def mapping_verdict(binding, text, released):
    return retirement_mappings.verdict(retirement_mappings.load_identity(binding), text, released)


class Transition:
    def __init__(self, binding):
        self.binding = binding
        self.sequence = 0

    def __call__(self, action, point, snapshot, record):
        b = self.binding
        self.sequence += 1
        from .execution_capsule import IDENTITY, live_phase1_evidence
        evidence = {}
        if action == "held":
            if point == 1:
                evidence = live_phase1_evidence(analysis(b))
            else:
                deadline = time.monotonic() + 3
                path = directory(b) / "retirement.json"
                while not path.exists() or json.loads(path.read_text()).get("status") != "released":
                    probe.require(time.monotonic() < deadline, "Retirement completion was not observed")
                    time.sleep(.005)
                verify_retirement(b, snapshot["host_pid"])
            evidence.update(retirement_mappings.capture(b, snapshot["host_pid"], point))
        state = ("handoff_ready" if point == 1 else "continuation_observed") if action == "held" else (
            "resume_requested" if action == "resuming" else "guest_completed")
        record({"event": "handoff", "state": state, "handoff_seq": self.sequence,
                **{k: b[k] for k in IDENTITY}, **evidence, "point": point, "qemu_pid": snapshot["host_pid"],
                "phase1_retired": point == 2, "claims": CLAIMS, "monotonic_ns": time.monotonic_ns()})


def verify_retirement(binding, qpid):
    result = _parse((directory(binding) / "retirement.json").read_text())
    probe.require(result["status"] == "released" and result["permit_sent"] is True and
                  result["stream_closed"] is True and result["nonce"] == binding["lifecycle_attempt"] and
                  result["qemu_pid"] == qpid and result["claims"] == CLAIMS and
                  result["permit_after_verified_export"] is True, "Incomplete retirement evidence")
    packets = result["events"]
    check_packets(binding, packets, qpid, complete=True)
    run, _ = verify_export(binding, packets)
    digest = probe.sha(run.paths["manifest"])
    candidate = packets[0]["data"]["candidate_id"]
    probe.require(result["accepted_manifest_sha256"] == digest and
                  result["permit"] == f"RETIRE {binding['lifecycle_attempt']} {candidate} {digest}\n",
                  "Permit/export identity mismatch")
    expected = {p.name: probe.sha(p) for p in run.paths.values() if p.exists()}
    probe.require(result["preserved_sha256"] == expected, "Preserved export inventory mismatch")
    for name, value in expected.items():
        probe.require(probe.sha(directory(binding) / "export" / name) == value, "Preserved export changed")
    return result


def verify_attempt(binding, result):
    from .execution_capsule import IDENTITY, LIMITS
    retirement_mappings.load_identity(binding)
    output = Path(binding["run_dir"]) / "logs/capsule"
    fault = binding["settings"]["phase1_retirement"]["fault"]
    code = FAULTS[fault]
    probe.require(result["qemu_exit"] == code and not result["supervisor_kill"] and
                  all(result[k] == binding[k] for k in IDENTITY), "Retirement attempt/exit mismatch")
    events = [_parse(line) for line in (output / "observations.jsonl").read_text().splitlines()]
    snapshots = [e for e in events if e.get("event") == "snapshot"]
    points = 2 if code == 0 else 1
    probe.require(len(snapshots) == points * 2, "Missing retirement observer snapshots")
    for index, event in enumerate(snapshots):
        probe.validate_snapshot(event, index // 2 + 1, index % 2 + 1, binding["capsule"]["symbols"],
                                result["qemu_pid"], snapshots[0])
        if index % 2:
            previous = snapshots[index-1]
            probe.require(event["regs"] == previous["regs"] and event["stack_hex"] == previous["stack_hex"] and
                          event["buffer_hex"] == previous["buffer_hex"] and
                          event["monotonic_ms"] >= previous["monotonic_ms"] + binding["settings"]["hold_ms"] - 2,
                          "Guest changed during retirement observer hold")
    order = []
    for point in range(1, points+1):
        order += [("snapshot", point, 1), ("snapshot", point, 2), ("hold_verified", point, None),
                  ("handoff", point, "handoff_ready" if point == 1 else "continuation_observed"),
                  ("handoff", point, "resume_requested")]
    if code == 0:
        order += [("done", None, None), ("handoff", 2, "guest_completed")]
    actual = [(e.get("event"), e.get("point"), e.get("state", e.get("sample"))) for e in events]
    probe.require(actual == order, "Invalid retirement handoff order")
    handoffs = [e for e in events if e.get("event") == "handoff"]
    ticks = None
    for seq, e in enumerate(handoffs, 1):
        probe.require(e["handoff_seq"] == seq and e["qemu_pid"] == result["qemu_pid"] and
                      all(e[k] == binding[k] for k in IDENTITY) and e["claims"] == CLAIMS and
                      e["phase1_retired"] is (e["point"] == 2), "Invalid retirement handoff identity")
        if e["state"] in {"handoff_ready", "continuation_observed"}:
            point = e["point"]
            retirement_mappings.verify_observation(binding, e, result["qemu_pid"])
            probe.require(type(e["process_start_ticks"]) is int and
                          (ticks is None or ticks == e["process_start_ticks"]), "Process identity changed")
            ticks = e["process_start_ticks"]
            if point == 1:
                from .execution_capsule import live_phase1_evidence
                prefix = live_phase1_evidence(analysis(binding), e["phase1_last_event"])
                probe.require(all(e[k] == v for k, v in prefix.items()), "Invalid pre-retirement evidence")
    stdout = (Path(binding["run_dir"]) / "logs/runtime_stdout.log").read_bytes()
    controller = json.loads((output / "controller.json").read_text())
    probe.require(result["controller_exit"] == 0, "Observer controller did not terminate normally")
    if code == 0:
        accepted = verify_retirement(binding, result["qemu_pid"])
        probe.require(controller["status"] == "passed" and stdout == b"CAPSULE_OK\n" and
                      (output / "capsule-fd.txt").read_bytes() == probe.FILE_BYTES, "Guest continuation failed")
    else:
        diagnostic = (Path(binding["run_dir"]) / "logs/qemu_strace.log").read_text(errors="replace")
        probe.require(f"CAPSULE_PHASE1_ABORT code={code} " in diagnostic and stdout == b"" and
                      (output / "capsule-fd.txt").read_bytes() == b"before\n" and
                      controller["status"] == "failed", "Guest continued after retirement refusal")
        if fault != "missing-verdict":
            retirement = json.loads((directory(binding) / "retirement.json").read_text())
            probe.require(retirement["status"] == "fault_injected" and retirement["fault"] == fault and
                          retirement["permit_sent"] is False and len(retirement["events"]) == 2,
                          "Retirement fault was not exercised")
            check_packets(binding, retirement["events"], result["qemu_pid"], complete=False)
            verify_export(binding, retirement["events"])
    return {"status": "passed" if code == 0 else "aborted", "snapshots": len(snapshots),
            "limitations": {**LIMITS, "phase1_detached": code == 0},
            "handoff_ready": True, "continuation_observed": code == 0, "guest_completed": code == 0,
            "phase1_retirement": {"status": "verified" if code == 0 else "rejected",
                "phase1_retired": code == 0, "fault": fault, "claims": CLAIMS,
                "verdict": accepted["events"][0]["data"] if code == 0 else None}}
