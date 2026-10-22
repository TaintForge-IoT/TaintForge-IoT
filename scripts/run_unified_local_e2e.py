#!/usr/bin/env python3
"""VM acceptance of the unified runner using only compiled benign fixtures.

Pass --dynamic-sysroot to additionally test an i386 PT_INTERP/DT_NEEDED target.
The default acceptance covers a static i386 program with two unpacking layers.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

from taintforge_env.elf_runtime import in_sysroot, copy_file
from taintforge_env.elf_target import inspect_elf_target
from taintforge_env.synthesis_loop import EnvironmentSynthesisLoop
from taintforge_env.unified_runtime import check_runtime_inputs, write_json


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def command(*arguments):
    result = subprocess.run([str(arg) for arg in arguments], cwd=PROJECT_ROOT, capture_output=True, text=True, timeout=180)
    if result.returncode != 0:
        raise RuntimeError(f"command failed ({result.returncode}): {arguments}\n{result.stderr[-6000:]}\n{result.stdout[-2000:]}")
    return result.stdout


def check(condition, message):
    if not condition:
        raise RuntimeError(message)


def build_fixtures(out: Path, dynamic_sysroot: Path | None):
    obj, binary = out / "two_layers.o", out / "two_layers"
    command("as", "--32", PROJECT_ROOT / "tests/phase1_two_layers.S", "-o", obj)
    command("ld", "-m", "elf_i386", obj, "-o", binary)
    fixtures = [("static", binary, Path("/"))]
    if dynamic_sysroot is None:
        return fixtures
    sysroot = out / "dynamic_sysroot"
    libraries = sysroot / "lib"
    libraries.mkdir(parents=True)
    loader_guest = "/lib/ld-linux.so.2"
    loader = in_sysroot(dynamic_sysroot.resolve(strict=True), loader_guest)
    check(loader.is_file() and inspect_elf_target(loader).arch == "i386",
          "dynamic acceptance needs an i386 /lib/ld-linux.so.2 inside --dynamic-sysroot")
    copy_file(loader, sysroot / loader_guest.lstrip("/"), executable=True)
    (out / "leaf.c").write_text("int tf_leaf(void) { return 17; }\n")
    (out / "dependency.c").write_text("int tf_leaf(void); int tf_dependency_value(void) { return tf_leaf()+25; }\n")
    command("gcc", "-m32", "-shared", "-nostdlib", "-fPIC", "-Wl,-soname,libtf_leaf.so", out / "leaf.c", "-o", libraries / "libtf_leaf.so")
    command("gcc", "-m32", "-shared", "-nostdlib", "-fPIC", "-Wl,-soname,libtf_dependency.so", out / "dependency.c",
            "-L", libraries, "-ltf_leaf", "-o", libraries / "libtf_dependency.so")
    # Call through a real PLT and a transitive shared library before the unchanged
    # two-layer fixture. Headers and the ELF loader remain in their original roles.
    entry = out / "dynamic_entry.S"
    entry.write_text(".text\n.global integration_entry\nintegration_entry:\ncall tf_dependency_value@PLT\ncmp $42,%eax\njne dependency_failed\njmp _start\ndependency_failed:\nmov $1,%eax\nmov $78,%ebx\nint $0x80\n.section .note.GNU-stack,\"\",@progbits\n")
    command("as", "--32", entry, "-o", out / "dynamic_entry.o")
    dynamic = out / "two_layers_dynamic"
    command("ld", "-m", "elf_i386", "--dynamic-linker", loader_guest, "-e", "integration_entry",
            out / "dynamic_entry.o", obj, "-L", libraries, "-ltf_dependency", "-rpath-link", libraries, "-o", dynamic)
    fixtures.append(("dynamic", dynamic, sysroot))
    return fixtures


def run(args):
    selected = check_runtime_inputs(PROJECT_ROOT, qemu=args.qemu, plugin=args.plugin)
    args.qemu, args.plugin = Path(selected["qemu"]["path"]), Path(selected["plugin"])
    out = args.out.expanduser().resolve()
    out.mkdir(parents=True, exist_ok=False)
    fixtures = build_fixtures(out, args.dynamic_sysroot)
    results = []
    identities = set()
    # Two fresh static sessions check that IDs/artifacts cannot carry over.
    for name, binary, sysroot in [fixtures[0], ("static_repeat", *fixtures[0][1:]), *fixtures[1:]]:
        destination = out / name
        stdout = command(sys.executable, PROJECT_ROOT / "scripts/run_unified_pipeline.py", "run",
                         "--binary", binary, "--out", destination, "--plugin", args.plugin.resolve(),
                         "--qemu", args.qemu.resolve(), "--sysroot", sysroot, "--network", "none",
                         "--timeout", "30", "--max-steps", "1", "--phase1-option", "tf-selection-delay=8")
        (out / f"{name}.stdout").write_text(stdout)
        report = json.loads((destination / "unified_report.json").read_text())
        phase1 = report["phase1"]
        check(report["executions_this_invocation"] == 1, "unexpected number of attempts")
        check(report["execution"]["guest_exit_code"] == 0, "fixture did not exit successfully")
        check(phase1["artifact_integrity"] == "verified" and phase1["runtime_observed"], "Phase 1 plugin did not run and publish verified evidence")
        check(not phase1["oep_proven"] and not phase1["fuzzing_ready"], "heuristic candidate was incorrectly promoted")
        run_dir = Path(report["run_dir"])
        finalization = report["finalization"]
        check(finalization["status"] == "completed" and finalization["guest_stop_confirmed"], "attempt finalization did not finish")
        for operation in ("execution", "filesystem", "phase1", "syscalls", "requirements", "repair_plan"):
            check(finalization["stages"][operation]["status"] == "completed", f"{operation} was not completed")
        phase2_report = json.loads((run_dir / "report.json").read_text())
        check(phase2_report["filesystem"]["observation_available"], "post-run filesystem observation is missing")
        check(phase2_report["syscalls"]["observation_available"], "syscall processing is incomplete")
        check("PHASE1_TWO_LAYERS_OK" in (run_dir / "logs/runtime_stdout.log").read_text(), "post-unpacking continuation or stack marker failed")
        events = [json.loads(line) for line in (run_dir / "logs/phase1/events.jsonl").read_text().splitlines()]
        check(sum(event["event_type"] == "analysis_started" for event in events) == 1, "multiple plugin analysis starts in one attempt")
        check(any(event["event_type"] == "oep_candidate_selected" for event in events), "no selected candidate observed")
        check(any(event["event_type"] == "oep_candidate_invalidated" for event in events), "second unpacking layer did not invalidate the candidate")
        check(all(event.get("status") != "guest_fake" for event in events), "guest stdout was accepted as analyzer evidence")
        identity = (phase1["session_id"], phase1["attempt_id"], phase1["analysis_instance_id"])
        check(identity not in identities, "Phase 1 analysis identity was reused")
        identities.add(identity)
        EnvironmentSynthesisLoop.verify_session(destination / "session")
        controller = json.loads((destination / "session/session.json").read_text())
        attempt = destination / "session" / controller["iterations"][0]["attempt_result"]
        check(bool(json.loads(attempt.read_text())["stage_transitions"]), "Phase 1 history was not persisted in AttemptResult")
        execution_rootfs = destination / "session/iterations/0000/execution/rootfs"
        check(not (execution_rootfs / "__taintforge").exists(), "analyzer runtime mountpoint was not removed")
        check(not (execution_rootfs / str(run_dir / "logs/phase1").lstrip("/")).exists(), "Phase 1 output mountpoint was not removed")
        check(not (execution_rootfs / "proc").is_mount(), "private proc mount survived execution")
        guest_runtime = json.loads((run_dir / "config/guest_runtime.json").read_text())
        if name == "dynamic":
            check(guest_runtime["target"]["interpreter"] == "/lib/ld-linux.so.2", "dynamic fixture lacks PT_INTERP")
            check(any(item["guest_path"].endswith("libtf_leaf.so") for item in guest_runtime["files"]), "transitive dependency missing")
        results.append({"fixture": name, "status": "passed", "guest_exit_code": 0,
                        "phase1_artifacts": "verified", "continuation_and_stack": "passed",
                        "attempt_stage_history": "passed", "session_verified": True,
                        "finalization": "completed", "filesystem_observation": True})
    report = {"status": "passed", "scope": "unified_i386_static_and_dynamic" if args.dynamic_sysroot else "unified_i386_static",
              "dynamic_executed": args.dynamic_sysroot is not None, "network_mode": "none",
              "memory_isolation": "not_implemented", "fuzzing_ready": False, "results": results}
    write_json(out / "report.json", report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--plugin", type=Path, help="Phase 1 plugin; defaults to TAINTFORGE_QEMU_PLUGIN or build/libtaintforge_ir.so")
    parser.add_argument("--qemu", type=Path, default=Path(shutil.which("qemu-i386") or "/missing/qemu-i386"))
    parser.add_argument("--dynamic-sysroot", type=Path, help="also test dynamic i386; source must provide /lib/ld-linux.so.2")
    args = parser.parse_args()
    args.qemu = Path(shutil.which(str(args.qemu)) or args.qemu).expanduser()
    os.umask(0o077)
    try:
        report = run(args)
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as exc:
        print(f"Unified VM acceptance failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
