#!/usr/bin/env python3
"""Run one i386 implicit-control-flow case through the file DTA/DSE queue."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile


GUEST_INPUT = "/etc/dta-input"
SEED = b"B"
TRACE_PC = re.compile(r"^Trace \d+:\s+\S+\s+\[[0-9a-fA-F]+/([0-9a-fA-F]+)/")

FIXTURE = r"""
    .section .text
    .globl _start
_start:
    movl 8(%esp), %ebx
    xorl %ecx, %ecx
    xorl %edx, %edx
    movl $5, %eax
    int $0x80
    movl %eax, %ebx
    movl $input_byte, %ecx
    movl $1, %edx
    movl $3, %eax
    int $0x80

    movzbl input_byte, %eax
    cmpl $0x41, %eax
first_jcc:
    je first_taken
first_fallthrough:
    movl $0, %esi
    jmp .Ljoin
first_taken:
    movl $1, %esi
.Ljoin:
    cmpl $1, %esi
second_jcc:
    je second_taken
second_fallthrough:
    xorl %ebx, %ebx
    jmp .Lexit
second_taken:
    movl $0, %ebx
.Lexit:
    movl $1, %eax
    int $0x80

    .section .bss
    .lcomm input_byte, 1
    .section .note.GNU-stack,"",@progbits
"""


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def load_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def build_fixture(directory):
    assembly = directory / "implicit-flow.S"
    obj = directory / "implicit-flow.o"
    binary = directory / "implicit-flow.elf"
    assembly.write_text(FIXTURE, encoding="ascii")
    subprocess.run(["as", "--32", str(assembly), "-o", str(obj)], check=True)
    subprocess.run(
        ["ld", "-m", "elf_i386", "-z", "noexecstack", str(obj), "-o", str(binary)],
        check=True,
    )
    listing = subprocess.check_output(["nm", "--defined-only", str(binary)], text=True)
    symbols = {}
    for line in listing.splitlines():
        address, _, name = line.split()
        symbols[name] = int(address, 16)
    return binary, symbols


def observe_branch_successors(qemu, binary, seed, log, symbols):
    command = [
        str(qemu), "-one-insn-per-tb", "-d", "exec,nochain", "-D", str(log),
        str(binary), str(seed),
    ]
    subprocess.run(command, check=True, timeout=30)
    pcs = []
    with log.open(encoding="ascii") as trace:
        for line in trace:
            match = TRACE_PC.match(line)
            if match:
                pcs.append(int(match[1], 16))

    outcomes = {}
    positions = []
    for name in ("first", "second"):
        pc = symbols[f"{name}_jcc"]
        hits = [index for index, value in enumerate(pcs) if value == pc]
        require(len(hits) == 1 and hits[0] + 1 < len(pcs),
                f"Expected one executed {name} Jcc with its successor in {log}")
        positions.append(hits[0])
        successor = pcs[hits[0] + 1]
        if successor == symbols[f"{name}_taken"]:
            outcomes[name] = "taken"
        else:
            require(successor == symbols[f"{name}_fallthrough"],
                    f"Unexpected {name} Jcc successor {successor:#x} in {log}")
            outcomes[name] = "not-taken"
    require(positions[0] < positions[1], f"Jcc execution order changed in {log}")
    return outcomes


def prepare_runtime(args, project, qemu, output):
    if args.plugin is not None:
        return args.plugin.resolve(strict=True), args.flags_receipt.resolve(strict=True)

    from taintforge_env.runtime_flags import calibrate_flags

    plugin_source = project / "unpacker/test"
    include = args.qemu_include or project / "unpacker/mvp/tests/regressions/imul32/sdk"
    include = include.expanduser().resolve(strict=True)
    require((include / "qemu-plugin.h").is_file(), f"Missing QEMU plugin header in {include}")
    plugin = output / "libtaintforge_ir.so"
    env = dict(os.environ, TF_QEMU_INCLUDE=str(include), TF_PYTHON=sys.executable)
    with (output / "plugin-build.log").open("wb") as log:
        try:
            subprocess.run(
                ["bash", str(plugin_source / "build_group7_4c1_plugin.sh"),
                 str(plugin_source), str(plugin)],
                cwd=project, env=env, check=True, stdout=log, stderr=subprocess.STDOUT,
            )
        except subprocess.CalledProcessError as exc:
            raise RuntimeError(f"Plugin build failed. See {log.name}") from exc
    calibrated = calibrate_flags(
        qemu=qemu, qemu_include=include, plugin=plugin, out=output / "flags-calibration",
    )
    return plugin, Path(calibrated["flags_receipt"])


def run_test(args, project, qemu, output):
    from taintforge_env import capsule_resources, dta_analysis, dta_dse_queue

    capsule_resources.preflight()
    binary, symbols = build_fixture(output)
    seed = output / "seed.bin"
    seed.write_bytes(SEED)
    plugin, flags_receipt = prepare_runtime(args, project, qemu, output)
    subprocess.run(["sudo", "-v"], check=True)

    print("Capturing the original seed with DTA", flush=True)
    analysis = output / "dta"
    # The corpus budget includes the baseline. One slot prevents DTA mutations.
    baseline = dta_analysis.analyze_file(
        binary=binary, qemu=qemu, plugin=plugin, seed=seed, input_path=GUEST_INPUT,
        argv=[GUEST_INPUT], out=analysis, max_candidates=1,
    )
    require(baseline["status"] == "passed" and baseline["accepted_seed_count"] == 1,
            "DTA did not accept exactly the original seed")
    sites = load_json(analysis / "corpus/manifest.json")["groups"]
    require(len(sites) == 1, f"Expected one file-dependent DTA site, found {len(sites)}")
    site = sites[0]
    require((site["pc"], site["occurrence"], site["outcome"], site["offsets"])
            == (symbols["first_jcc"], 1, "not-taken", [0]),
            f"Unexpected DTA site: {site}")

    print("Running one DSE job selected by the project queue", flush=True)
    queue = output / "queue"
    dta_dse_queue.create_queue(
        queue=queue, qemu=qemu, plugin=plugin, flags_receipt=flags_receipt,
        max_total_starts=1, max_queue_jobs=1, max_occurrences=1,
        max_steps=128, max_sites=8,
    )
    enqueued = dta_dse_queue.enqueue_analyses(queue=queue, analyses=[analysis])
    require(enqueued["admitted_jobs"] == 1, "The DSE queue did not admit one DTA request")
    result = dta_dse_queue.run_queue(queue=queue, max_jobs=1)
    require(result["started_this_run"] == 1 and result["counts"]["VERIFIED"] == 1
            and result["dse_status"] == "VERIFIED", f"DSE job failed: {result}")
    rows = load_json(Path(result["corpus_manifest"]))["seeds"]
    produced = [row for row in rows if any(origin.startswith("DSE:") for origin in row["origins"])]
    require(len(produced) == 1, "The queue did not publish exactly one DSE seed")
    candidate = queue / "seeds" / produced[0]["sha256"]
    raw = candidate.read_bytes()
    require(hashlib.sha256(raw).hexdigest() == produced[0]["sha256"] and raw == b"A",
            f"Expected the verified one-byte witness 41, got {raw.hex()}")

    print("Checking both branch successors in the raw QEMU trace", flush=True)
    before = observe_branch_successors(qemu, binary, seed, output / "before.exec.log", symbols)
    after = observe_branch_successors(qemu, binary, candidate, output / "after.exec.log", symbols)
    require(before == {"first": "not-taken", "second": "not-taken"}
            and after == {"first": "taken", "second": "taken"},
            f"Unexpected branch outcomes: {before} -> {after}")
    return {
        "status": "PASS_IMPLICIT_CONTROL_FLOW",
        "dse_jobs_started": result["started_this_run"],
        "dse_status": result["dse_status"],
        "dta_file_offsets": site["offsets"],
        "seed_hex": SEED.hex(),
        "dse_seed_hex": raw.hex(),
        "first_jcc": {"pc": hex(symbols["first_jcc"]), "before": before["first"], "after": after["first"]},
        "second_jcc": {"pc": hex(symbols["second_jcc"]), "before": before["second"], "after": after["second"]},
    }


def main():
    home = Path.home()
    downloads = home / "Downloads"
    admitted_qemu = downloads / "tfprefix.6pbwecxc/admitted-runtime/qemu-i386"
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", type=Path, default=Path(__file__).resolve().parents[5])
    parser.add_argument("--qemu", type=Path,
                        default=admitted_qemu if admitted_qemu.is_file() else shutil.which("qemu-i386"))
    parser.add_argument("--qemu-include", type=Path, help="directory containing the matching qemu-plugin.h")
    parser.add_argument("--out-dir", type=Path, default=downloads, help="parent for the new run directory")
    parser.add_argument("--plugin", type=Path, help="reuse an existing Phase 1 plugin with its runtime manifest")
    parser.add_argument("--flags-receipt", type=Path, help="reuse a calibrated receipt with --plugin")
    args = parser.parse_args()
    if args.qemu is None:
        parser.error("qemu-i386 was not found. Supply --qemu.")
    if (args.plugin is None) != (args.flags_receipt is None):
        parser.error("--plugin and --flags-receipt must be supplied together.")
    if args.plugin is not None and args.qemu_include is not None:
        parser.error("--qemu-include is used only when building the plugin.")

    output = None
    try:
        project = args.project.expanduser().resolve(strict=True)
        qemu = Path(args.qemu).expanduser().resolve(strict=True)
        require(qemu.name == "qemu-i386" and os.access(qemu, os.X_OK),
                f"Expected an executable named qemu-i386, got {qemu}")
        require((project / "taintforge_env/dta_dse_queue.py").is_file(),
                f"TaintForge-IoT DSE queue not found in {project}")
        parent = args.out_dir.expanduser().resolve()
        parent.mkdir(parents=True, exist_ok=True)
        output = Path(tempfile.mkdtemp(prefix="tf-implicit-flow.", dir=parent))
        print(f"Run directory {output}", flush=True)
        sys.path.insert(0, str(project))
        result = run_test(args, project, qemu, output)
        report = json.dumps(result, indent=2) + "\n"
        (output / "result.json").write_text(report, encoding="utf-8")
        print(report, end="")
        return 0
    except (OSError, ValueError, RuntimeError, KeyError, subprocess.SubprocessError) as exc:
        print(f"FAIL_IMPLICIT_CONTROL_FLOW: {exc}", file=sys.stderr)
        if output is not None:
            print(f"Details in {output}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
