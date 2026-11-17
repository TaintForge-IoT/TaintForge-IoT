#!/usr/bin/env python3
"""Verify one counted-loop request through the project DTA/DSE queue."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import tempfile


ITERATIONS = 4096
MAX_STEPS = 1024
ADDEND = 7
SEED = b"B"
EXPECTED_WITNESS = b"A"
GUEST_INPUT = "/etc/taintforge-junk-loop.in"
TRACE_PC = re.compile(r"^Trace \d+:\s+\S+\s+\[[0-9a-fA-F]+/([0-9a-fA-F]+)/")
ASSEMBLY = rf"""
    .section .text
    .globl _start
_start:
    movl $5, %eax
    movl $input_path, %ebx
    xorl %ecx, %ecx
    xorl %edx, %edx
    int $0x80

    movl %eax, %ebx
    movl $3, %eax
    movl $input_byte, %ecx
    movl $1, %edx
    int $0x80

    movzbl input_byte, %edx
    call long_loop
flags_jcc:
    jnz bad_flags
compare_result:
    cmpl $(ITERATIONS * {ADDEND} + {EXPECTED_WITNESS[0]}), %edx
target_jcc:
    je target_taken
target_fallthrough:
    nop
    jmp publish
target_taken:
    nop
publish:
    movl %edx, observed
    movl %ecx, observed+4
    movl $4, %eax
    movl $1, %ebx
    movl $observed, %ecx
    movl $8, %edx
    int $0x80
    movl $1, %eax
    xorl %ebx, %ebx
    int $0x80
bad_flags:
    movl $1, %eax
    movl $77, %ebx
    int $0x80

long_loop:
    movl $ITERATIONS, %ecx
loop_iteration:
    addl ${ADDEND}, %edx
    decl %ecx
    jnz loop_iteration
    ret

    .section .rodata
input_path:
    .asciz "{GUEST_INPUT}"
    .section .bss
    .lcomm input_byte, 1
    .lcomm observed, 8
    .section .note.GNU-stack,"",@progbits
"""


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def prepare_runtime(args, project, qemu, output):
    from taintforge_env.phase1_runtime import Phase1Runtime
    from taintforge_env.runtime_flags import calibrate_flags

    if args.plugin is not None:
        plugin = args.plugin.expanduser().resolve(strict=True)
        receipt = args.flags_receipt.expanduser().resolve(strict=True)
    else:
        source = project / "unpacker/test"
        sdk = args.qemu_include or project / "unpacker/mvp/tests/regressions/imul32/sdk"
        sdk = sdk.expanduser().resolve(strict=True)
        require((sdk / "qemu-plugin.h").is_file(), f"Missing qemu-plugin.h in {sdk}")
        plugin = output / "libtaintforge_ir.so"
        build_log = output / "plugin-build.log"
        print("Building the Phase 1 plugin and calibrating EFLAGS", flush=True)
        env = dict(os.environ, TF_QEMU_INCLUDE=str(sdk), TF_PYTHON=sys.executable)
        with build_log.open("wb") as log:
            build = subprocess.run(
                ["bash", str(source / "build_group7_4c1_plugin.sh"), str(source), str(plugin)],
                cwd=project, env=env, stdout=log, stderr=subprocess.STDOUT, timeout=300,
            )
        require(build.returncode == 0, f"Plugin build failed. See {build_log}")
        calibration = calibrate_flags(
            qemu=qemu, qemu_include=sdk, plugin=plugin, out=output / "flags-calibration",
        )
        receipt = Path(calibration["flags_receipt"])
    runtime = Phase1Runtime.load(plugin)
    runtime.validate_qemu(qemu)
    return runtime, receipt


def assemble_fixture(output):
    source = output / "junk-loop.S"
    obj = output / "junk-loop.o"
    binary = output / "junk-loop.elf"
    source.write_text(ASSEMBLY, encoding="ascii")
    subprocess.run(
        ["as", "--32", "--defsym", f"ITERATIONS={ITERATIONS}", str(source), "-o", str(obj)],
        check=True, timeout=30,
    )
    subprocess.run(
        ["ld", "-m", "elf_i386", "-z", "noexecstack", str(obj), "-o", str(binary)],
        check=True, timeout=30,
    )
    listing = subprocess.check_output(["nm", "--defined-only", str(binary)], text=True, timeout=30)
    symbols = {}
    for line in listing.splitlines():
        address, _, name = line.split()
        symbols[name] = int(address, 16)
    return binary, symbols


def observe_guest(qemu, binary, rootfs, directory, symbols, seed, plugin_argument=None):
    directory.mkdir(parents=True, exist_ok=True)
    trace = directory / "exec.log"
    command = [
        str(qemu), "-L", str(rootfs), "-one-insn-per-tb", "-d", "exec,nochain", "-D", str(trace),
    ]
    if plugin_argument is not None:
        command.extend(("-plugin", plugin_argument))
    command.append(str(binary))
    with (directory / "stdout.bin").open("wb") as stdout, (directory / "stderr.log").open("wb") as stderr:
        run = subprocess.run(command, stdout=stdout, stderr=stderr, timeout=30)
    require(run.returncode == 0, f"Guest exit {run.returncode}. See {directory}")
    state = (directory / "stdout.bin").read_bytes()
    require(len(state) == 8, f"Expected EDX and ECX in guest stdout. See {directory}")
    edx, ecx = struct.unpack("<II", state)
    expected_edx = (seed[0] + ITERATIONS * ADDEND) & 0xffffffff
    require((edx, ecx) == (expected_edx, 0),
            f"Unexpected loop exit state EDX={edx:#x} ECX={ecx:#x}. See {directory}")

    with trace.open(encoding="ascii") as lines:
        pcs = [int(match[1], 16) for line in lines if (match := TRACE_PC.match(line))]
    iterations = pcs.count(symbols["loop_iteration"])
    require(iterations == ITERATIONS, f"Raw QEMU trace shows {iterations} loop iterations")
    flags_pc = symbols["flags_jcc"]
    target_pc = symbols["target_jcc"]
    require(pcs.count(flags_pc) == 1 and pcs.count(target_pc) == 1,
            "Expected both post-loop branches exactly once")
    flags_index = pcs.index(flags_pc)
    target_index = pcs.index(target_pc)
    require(flags_index < target_index and pcs[flags_index + 1] == symbols["compare_result"],
            "ZF from the final DEC did not survive the return")
    require(target_index + 1 < len(pcs), "Target Jcc successor is missing")
    successor = pcs[target_index + 1]
    require(successor in {symbols["target_taken"], symbols["target_fallthrough"]},
            f"Unexpected target successor {successor:#x}")
    return {
        "outcome": "taken" if successor == symbols["target_taken"] else "not-taken",
        "loop_iterations": iterations,
        "guest_instructions_through_jcc": target_index + 1,
        "edx_after_loop": hex(edx),
        "ecx_after_loop": ecx,
        "zf_at_return": 1,
    }


def run_regression(args, project, qemu, output, result):
    from taintforge_env import capsule_resources, dta_analysis, dta_dse_queue

    capsule_resources.preflight()
    subprocess.run(["sudo", "-v"], check=True)
    runtime, receipt = prepare_runtime(args, project, qemu, output)
    binary, symbols = assemble_fixture(output)
    seed = output / "seed.bin"
    seed.write_bytes(SEED)
    pc = symbols["target_jcc"]
    result["branch_pc"] = hex(pc)

    print("Capturing the original seed through isolated project DTA", flush=True)
    analysis = output / "dta"
    captured = dta_analysis.analyze_file(
        binary=binary, qemu=qemu, plugin=runtime.plugin, seed=seed,
        input_path=GUEST_INPUT, argv=[], out=analysis, max_candidates=1,
    )
    require(captured["status"] == "passed" and captured["accepted_seed_count"] == 1,
            f"Expected exactly the original DTA seed. See {analysis / 'summary.json'}")
    manifest = json.loads((analysis / "corpus/manifest.json").read_text())
    sites = manifest["groups"]
    require(len(sites) == 1, f"Expected one file-dependent DTA branch, found {sites}")
    site = sites[0]
    require((site["pc"], site["occurrence"], site["outcome"], site["offsets"])
            == (pc, 1, "not-taken", [0]), f"Unexpected DTA hint {site}")
    result["dta_file_offsets"] = site["offsets"]

    queue = output / "queue"
    dta_dse_queue.create_queue(
        queue=queue, qemu=qemu, plugin=runtime.plugin, flags_receipt=receipt,
        max_total_starts=1, max_queue_jobs=1, max_occurrences=1,
        max_steps=MAX_STEPS, max_sites=8,
    )
    enqueued = dta_dse_queue.enqueue_analyses(queue=queue, analyses=[analysis])
    require(enqueued["admitted_jobs"] == 1,
            f"Expected exactly one admitted DTA request. Got {enqueued}")
    print(f"Running one project queue job with max_steps={MAX_STEPS}", flush=True)
    outcome = dta_dse_queue.run_queue(queue=queue, max_jobs=1)
    result["queue_summary"] = outcome
    require(outcome["started_this_run"] == 1 and outcome["counts"]["VERIFIED"] == 1
            and outcome["dse_status"] == "VERIFIED",
            f"The queue did not verify its single job. See {queue / 'summary.json'}")

    print("Auditing the completed queue and its published corpus", flush=True)
    audited = dta_dse_queue.audit_queue(queue=queue)
    require(audited["evidence_audited"] is True and audited["counts"]["VERIFIED"] == 1
            and audited["started_attempts"] == 1 and audited["dse_status"] == "VERIFIED",
            f"Completed queue evidence did not pass its independent audit. Got {audited}")
    corpus = json.loads(Path(audited["corpus_manifest"]).read_text())
    produced = [row for row in corpus["seeds"]
                if any(origin.startswith("DSE:") for origin in row["origins"])]
    require(len(produced) == 1,
            f"Expected exactly one published DSE seed. Got {produced}")
    candidate = queue / "seeds" / produced[0]["sha256"]
    witness = candidate.read_bytes()
    require(witness == EXPECTED_WITNESS
            and hashlib.sha256(witness).hexdigest() == produced[0]["sha256"],
            f"Unexpected published queue seed {witness.hex()}")

    compressed = []
    for path in sorted(queue.rglob("concolic.json")):
        report = json.loads(path.read_text())
        loop = report.get("counted_loop")
        require(isinstance(loop, dict), f"Queue prefix lacks its counted loop in {path}")
        rows = report["trace"]
        require(loop["iterations"] == ITERATIONS
                and loop["resume_seq"] - loop["head_seq"] == 3 * (ITERATIONS - 1)
                and 0 < len(rows) + 1 <= MAX_STEPS,
                f"Unexpected compressed prefix in {path}")
        compressed.append({"path": str(path.relative_to(queue)), "status": report["status"],
                           "trace_rows": len(rows), "omitted_steps": 3 * (ITERATIONS - 1)})
    require(any(row["status"] == "OBSERVED" for row in compressed)
            and any(row["status"] == "BOUNDARY_WITNESS" for row in compressed),
            "The queue lacks fresh observation and solver reports for its counted loop")

    print("Checking the published seed in fresh raw QEMU traces", flush=True)
    observed = {}
    for label, raw in (("baseline", SEED), ("witness", witness)):
        directory = output / label
        rootfs = directory / "rootfs"
        guest_file = rootfs / GUEST_INPUT.lstrip("/")
        guest_file.parent.mkdir(parents=True)
        guest_file.write_bytes(raw)
        observed[label] = observe_guest(qemu, binary, rootfs, directory / "raw", symbols, raw)
    require(observed["baseline"]["outcome"] == "not-taken"
            and observed["witness"]["outcome"] == "taken",
            f"Published queue seed did not invert the raw Jcc. Got {observed}")
    result.pop("queue_summary")
    result.update(status="PASS_LOOP_SUMMARY_QUEUE", dse_jobs_started=outcome["started_this_run"],
                  dse_status=audited["dse_status"], queue_evidence_audited=True,
                  dse_seed_hex=witness.hex(), baseline=observed["baseline"],
                  witness=observed["witness"], compressed_reports=compressed,
                  queue_directory=str(queue))


def main():
    downloads = Path.home() / "Downloads"
    admitted_qemu = downloads / "tfprefix.6pbwecxc/admitted-runtime/qemu-i386"
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", type=Path,
                        default=Path(__file__).resolve().parents[5])
    parser.add_argument("--qemu", type=Path,
                        default=admitted_qemu if admitted_qemu.is_file() else shutil.which("qemu-i386"))
    parser.add_argument("--qemu-include", type=Path, help="matching SDK directory for a fresh plugin build")
    parser.add_argument("--out-dir", type=Path, default=downloads, help="parent for a fresh run directory")
    parser.add_argument("--plugin", type=Path, help="reuse a plugin built from the selected checkout")
    parser.add_argument("--flags-receipt", type=Path, help="calibration for --plugin and this QEMU")
    args = parser.parse_args()
    if args.qemu is None:
        parser.error("Supply --qemu with the calibrated i386 runtime.")
    if (args.plugin is None) != (args.flags_receipt is None):
        parser.error("--plugin and --flags-receipt must be supplied together.")
    if args.plugin is not None and args.qemu_include is not None:
        parser.error("--qemu-include applies to a fresh plugin build.")

    output = None
    result = {"status": "FAIL_LOOP_SUMMARY_QUEUE", "max_steps": MAX_STEPS,
              "requested_loop_iterations": ITERATIONS, "seed_hex": SEED.hex()}
    code = 1
    try:
        project = args.project.expanduser().resolve(strict=True)
        qemu = Path(args.qemu).expanduser().resolve(strict=True)
        require((project / "taintforge_env/concolic_environment.py").is_file(),
                f"TaintForge-IoT checkout not found at {project}")
        require(os.access(qemu, os.X_OK), f"QEMU is not executable at {qemu}")
        parent = args.out_dir.expanduser().resolve()
        parent.mkdir(parents=True, exist_ok=True)
        output = Path(tempfile.mkdtemp(prefix="tf-junk-loop-queue.", dir=parent))
        print(f"Run directory {output}", flush=True)
        sys.path.insert(0, str(project))
        run_regression(args, project, qemu, output, result)
        code = 0
    except (OSError, ValueError, RuntimeError, KeyError, subprocess.SubprocessError) as exc:
        result["error"] = str(exc)
    report = json.dumps(result, indent=2) + "\n"
    if output is not None:
        (output / "result.json").write_text(report, encoding="utf-8")
    print(report, end="")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
