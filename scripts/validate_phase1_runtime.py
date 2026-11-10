#!/usr/bin/env python3
"""Run only the bundled benign ELF fixtures; never accepts an arbitrary sample."""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import subprocess
import time

from taintforge_env.phase1_runtime import Phase1Run, Phase1Runtime, Phase1RuntimeError, digest, read_json


CLEANUP_CASES = (
    ("cleanup-ret", 0, "ret"),
    ("failed-munmap", 1, None),
    ("unrelated-munmap", 2, None),
    ("unbound-jump", 3, None),
    ("partial-target-write", 4, None),
    ("cleanup-jmp-eax", 5, "jmp_eax"),
    ("interrupted-return", 6, None),
    ("overlapping-target", 7, None),
)


def validate_cleanup(attempt, binary, expected_transfer):
    symbols = {}
    for line in subprocess.check_output(["nm", "-n", str(binary)], text=True).splitlines():
        address, _, symbol = line.split()
        if symbol in ("cleanup", "target"):
            symbols[symbol] = int(address, 16)
    cleanup_pc, target_pc = symbols["cleanup"], symbols["target"]
    assert cleanup_pc // 4096 == target_pc // 4096
    assert (attempt.directory / "guest_stdout.log").read_bytes() == b"S37_SYNTHETIC_TARGET_REACHED\n"
    capture = attempt.verify()
    report = read_json(attempt.paths["report"])
    events = attempt.events()
    assert capture["runtime_observed"] and report["main_image_verified"]
    assert not any(event["event_type"] in ("data_loss", "profile_lost") for event in events)
    observed = [event for event in events if event["event_type"] == "oep_candidate_observed"]
    cleanups = [event for event in observed if event["data"]["address"] == cleanup_pc]
    targets = [event for event in observed if event["data"]["address"] == target_pc]
    transfers = [event for event in events if event["event_type"] == "oep_cleanup_transfer_observed"]
    unmappings = [event for event in events if event["event_type"] == "code_generation_changed"
                  and "executed_mapping_unmapped" in event["incomplete_reasons"]]
    assert len(cleanups) == 1
    cleanup = cleanups[0]
    failed_unmap = attempt.attempt_id == "attempt-failed-munmap"
    if failed_unmap:
        assert not unmappings
        assert b"memory operation failed: num=91" in (attempt.directory / "analyzer_stderr.log").read_bytes()
    else:
        assert len(unmappings) == 1 and cleanup["event_seq"] < unmappings[0]["event_seq"]
    if expected_transfer is None:
        assert not transfers and not targets, "cleanup false positive"
        assert capture["capture_status"] == ("success" if failed_unmap else "not_available")
        return

    assert len(transfers) == len(targets) == 1
    transfer, target = transfers[0], targets[0]
    assert transfer["data"] == {
        "source_candidate_id": cleanup["data"]["candidate_id"],
        "unmap_seq": cleanup["trace_seq"],
        "unmapped_page": unmappings[0]["data"]["address"],
        "transfer_seq": target["trace_seq"] - 1,
        "address": target_pc,
        "transfer": expected_transfer,
    }
    assert unmappings[0]["event_seq"] < transfer["event_seq"] < target["event_seq"]
    assert target["analysis_epoch"] == cleanup["analysis_epoch"] + 1
    assert target["data"]["observed_code_generation"] == cleanup["data"]["observed_code_generation"]
    assert target["data"]["parent_candidate_id"] == 0
    assert capture["capture_status"] == "success"
    assert int(report["oep"], 16) == target_pc
    assert report["capture_candidate_id"] == target["data"]["candidate_id"]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--plugin", required=True, type=Path)
    parser.add_argument("--qemu", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    output = args.out.resolve()
    output.mkdir(parents=True, exist_ok=False)
    root = Path(__file__).resolve().parents[1]
    runtime = Phase1Runtime.load(args.plugin.resolve())
    qemu = args.qemu.resolve()
    qemu_identity = runtime.validate_qemu(qemu)
    results = []
    binaries = {}
    fixtures = [("layers", "phase1_two_layers.S", ()),
                ("live", "phase1_two_layers.S", ("--defsym", "WAIT_FOR_INPUT=1")),
                ("pages", "phase1_two_layers.S", ("--defsym", "SECOND_PAGE=1")),
                ("fork", "phase1_two_layers.S", ("--defsym", "WITH_FORK=1"))]
    fixtures.extend((name, "phase1_cleanup_tail.S", ("--defsym", f"SCENARIO={variant}"))
                    for name, variant, _ in CLEANUP_CASES)
    for name, source, definitions in fixtures:
        obj, binary = output / f"{name}.o", output / name
        subprocess.run(["as", "--32", *definitions, str(root / "tests" / source), "-o", str(obj)], check=True)
        subprocess.run(["ld", "-m", "elf_i386", str(obj), "-o", str(binary)], check=True)
        binaries[name] = binary

    def run(name, *, extra=(), binary=None, flags=False, live=False, terminate=False, ir=True):
        attempt = Phase1Run(runtime, "phase1-validation", name, name, output / name.replace("attempt", "run"), flags)
        argument = attempt.plugin_argument(ir=ir, extra=extra)
        with (attempt.directory / "guest_stdout.log").open("wb") as stdout, (attempt.directory / "analyzer_stderr.log").open("wb") as stderr:
            proc = subprocess.Popen([str(qemu), "-plugin", argument, str(binary or binaries["layers"])], stdin=subprocess.PIPE, stdout=stdout, stderr=stderr)
            try:
                if live:
                    deadline = time.monotonic() + 10
                    found = False
                    while time.monotonic() < deadline and proc.poll() is None:
                        try:
                            found = any(e["event_type"] == "oep_candidate_selected" for e in attempt.events(final=False))
                        except Phase1RuntimeError:
                            pass
                        if found: break
                        time.sleep(0.02)
                    assert found and proc.poll() is None, "OEP event was not visible before guest exit"
                if terminate:
                    proc.kill()
                proc.communicate(input=None if terminate else b"x", timeout=30)
            except BaseException:
                proc.kill(); proc.wait()
                raise
        return attempt, proc.returncode

    # Two simultaneous, independent analyses must retain separate identities.
    with ThreadPoolExecutor(max_workers=2) as pool:
        runs = list(pool.map(lambda n: run(n, extra=("tf-selection-delay=8",)), ("attempt-000", "attempt-001")))
    for attempt, code in runs:
        assert code == 0
        evidence = attempt.verify()
        assert evidence["runtime_observed"] and evidence["capture_status"] == "success"
        observed = [e for e in attempt.events() if e["event_type"] == "oep_candidate_observed"]
        assert len(observed) == 2
        assert observed[0]["data"]["address"] == observed[1]["data"]["address"]
        assert observed[0]["data"]["candidate_id"] != observed[1]["data"]["candidate_id"]
        assert observed[0]["data"]["observed_code_generation"] != observed[1]["data"]["observed_code_generation"]
        assert any(e["event_type"] == "oep_candidate_invalidated" for e in attempt.events())
        assert "PHASE1_TWO_LAYERS_OK" in (attempt.directory / "guest_stdout.log").read_text()
        assert all(e.get("status") != "guest_fake" for e in attempt.events())
        results.append({"test": attempt.attempt_id, "status": "PASS", "evidence": evidence})

    for name, _, expected_transfer in CLEANUP_CASES:
        # The binary and attempt directory need separate names.
        binary = binaries[name]
        attempt, code = run("attempt-" + name, binary=binary, ir=False,
                            extra=("tf-capture=entry", "dse-check=off", "ir-trace-capacity=4096",
                                   "tf-max-candidates=16", "tf-max-events=512", "runtime-log=summary"))
        assert code == 0, name
        validate_cleanup(attempt, binary, expected_transfer)
        results.append({"test": name, "status": "PASS"})
    attempt, code = run("attempt-live", binary=binaries["live"], extra=("tf-selection-delay=8",), live=True)
    assert code == 0 and attempt.verify()["runtime_observed"]
    results.append({"test": "OEP event before exit; natural continuation; preserved stack", "status": "PASS"})

    attempt, code = run("attempt-budget", extra=("tf-max-events=2",))
    assert code == 0 and attempt.verify()["analysis_status"] == "partial"
    assert any(e["event_type"] == "data_loss" for e in attempt.events())
    results.append({"test": "bounded event stream reports loss", "status": "PASS"})

    attempt, code = run("attempt-partial", binary=binaries["pages"], extra=("tf-max-dump-bytes=4096",))
    assert code == 0 and attempt.verify()["capture_status"] == "partial"
    results.append({"test": "partial capture retains exact byte offsets", "status": "PASS"})

    # The checked-in QEMU may carry the verified-flags extension. Both outcomes
    # are tested according to observed capability, never by faking its marker.
    attempt, code = run("attempt-flags", flags=True)
    events = attempt.events()
    advertised = events[0]["data"]["flags_contract"]
    if advertised == "unverified":
        assert code != 0 and not attempt.paths["manifest"].exists()
    else:
        assert code == 0 and attempt.verify()["runtime_observed"]
    results.append({"test": "required EFLAGS capability", "status": "PASS", "observed": advertised})

    attempt, code = run("attempt-fork", binary=binaries["fork"])
    assert code == 0 and attempt.verify()["analysis_status"] == "unsupported"
    assert any(e["event_type"] == "profile_lost" for e in attempt.events())
    results.append({"test": "fork invalidates single-process analysis; child cannot finalize parent stream", "status": "PASS"})

    attempt, code = run("attempt-killed", binary=binaries["live"], extra=("tf-selection-delay=8",), live=True, terminate=True)
    assert code < 0 and not attempt.paths["manifest"].exists()
    try:
        attempt.events()
        raise AssertionError("killed analysis accepted as finished")
    except Phase1RuntimeError:
        pass
    results.append({"test": "SIGKILL leaves an explicitly incomplete stream", "status": "PASS"})

    attempt = runs[0][0]
    before = attempt.paths["dump"].read_bytes()
    attempt.paths["dump"].write_bytes(bytes([before[0] ^ 1]) + before[1:])
    try:
        attempt.verify()
        raise AssertionError("tampered dump accepted")
    except Phase1RuntimeError:
        pass
    finally:
        attempt.paths["dump"].write_bytes(before)
    results.append({"test": "tampered runtime artifact rejected", "status": "PASS"})
    report_path, manifest_path = attempt.paths["report"], attempt.paths["manifest"]
    original_report, original_manifest = report_path.read_bytes(), manifest_path.read_bytes()
    changed_report, changed_manifest = json.loads(original_report), json.loads(original_manifest)
    changed_report["regions"][0]["offset"] = 1
    report_path.write_text(json.dumps(changed_report))
    changed_manifest["artifacts"]["report"].update(size=report_path.stat().st_size, sha256=digest(report_path))
    manifest_path.write_text(json.dumps(changed_manifest))
    try:
        attempt.verify()
        raise AssertionError("incorrect region offset accepted")
    except Phase1RuntimeError:
        pass
    finally:
        report_path.write_bytes(original_report)
        manifest_path.write_bytes(original_manifest)
    results.append({"test": "region extent checked independently of artifact digest", "status": "PASS"})
    assert digest(qemu) == qemu_identity["sha256"]
    (output / "results.json").write_text(json.dumps({"qemu": qemu_identity, "runtime_build": runtime.build_id, "tests": results}, indent=2) + "\n")
    for item in results: print(f"PASS: {item['test']}")


if __name__ == "__main__":
    main()
