#!/usr/bin/env python3
"""One i386 regression for concolic capture across a long arithmetic loop."""

import argparse
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
    from taintforge_env.concolic_environment import run_environment_inversion
    from taintforge_env.dta_capsule import verify_dta_diagnostics
    from taintforge_env.dta_corpus import parse_trace
    from taintforge_env.phase1_runtime import Phase1Run

    runtime, receipt = prepare_runtime(args, project, qemu, output)
    binary, symbols = assemble_fixture(output)
    rootfs = output / "seed-rootfs"
    input_file = rootfs / GUEST_INPUT.lstrip("/")
    input_file.parent.mkdir(parents=True)
    input_file.write_bytes(SEED)
    pc = symbols["target_jcc"]
    result["branch_pc"] = hex(pc)

    print("Checking the baseline in DTA and in the raw QEMU trace", flush=True)
    directory = output / "baseline"
    phase = Phase1Run(runtime, "junk-loop-test", "baseline", "dta", directory / "phase1")
    plugin_argument = phase.plugin_argument(
        ir=False, diagnostic_roots=True,
        extra=("runtime-log=roots", "dse-check=off", "tf-capture=exit",
               "tf-max-capture-bytes=1048576", "ir-trace-capacity=32768", "tf-max-events=4096"),
    )
    before = observe_guest(qemu, binary, rootfs, directory, symbols, SEED, plugin_argument)
    verify_dta_diagnostics(phase)
    sites = parse_trace(directory / "stderr.log", GUEST_INPUT, len(SEED))["groups"]
    require(len(sites) == 1, f"Expected one DTA site with file data roots, found {len(sites)}")
    site = sites[0]
    require((site["pc"], site["occurrence"], site["offsets"], site["outcome"])
            == (pc, 1, [0], before["outcome"]), f"Unexpected DTA source or branch: {site}")
    require(before["outcome"] == "not-taken", "Baseline seed should take the fall-through")
    result.update(baseline=before, dta_file_offsets=site["offsets"])

    print(f"Running one DSE inversion with max_steps={MAX_STEPS}", flush=True)
    dse_dir = output / "dse"
    outcome = run_environment_inversion(
        qemu=qemu, plugin=runtime.plugin, binary=binary, rootfs=rootfs,
        guest_file=GUEST_INPUT, offsets=site["offsets"], flags_receipt=receipt,
        branch_pc=pc, occurrence=site["occurrence"], max_steps=MAX_STEPS,
        output=dse_dir, single_step=True,
    )
    result["dse"] = {key: outcome.get(key) for key in ("status", "reason", "baseline", "guest_exit_codes")}
    require(outcome.get("guest_exit_codes", {}).get("solve") == 0,
            f"DSE solve guest did not exit normally. See {dse_dir / 'result.json'}")
    if args.expect == "budget":
        require(outcome["status"] == "UNKNOWN" and outcome.get("reason") == "instruction_budget",
                f"Expected UNKNOWN/instruction_budget. Got {outcome['status']}/{outcome.get('reason')}")
        require(before["guest_instructions_through_jcc"] > MAX_STEPS,
                "The reachable target must lie beyond the instruction budget")
        result["status"] = "PASS_REPRODUCED_INSTRUCTION_BUDGET"
        return

    require(outcome["status"] == "VERIFIED" and outcome.get("baseline") == "BOUNDARY_WITNESS",
            f"Expected one verified DSE witness. Got {outcome['status']}/{outcome.get('reason')}")
    require(outcome["changes"] == [{"offset": 0, "before": SEED[0], "after": EXPECTED_WITNESS[0]}],
            f"Unexpected DSE mutation: {outcome['changes']}")
    candidate_rootfs = Path(outcome["candidate_rootfs"])
    witness = (candidate_rootfs / GUEST_INPUT.lstrip("/")).read_bytes()
    require(witness == EXPECTED_WITNESS, f"Unexpected DSE witness {witness.hex()}")
    print("Checking the solver-generated input in a fresh raw QEMU trace", flush=True)
    after = observe_guest(qemu, binary, candidate_rootfs, output / "witness", symbols, witness)
    require(after["outcome"] == "taken", "The generated input did not invert the target Jcc")
    result.update(status="PASS_LOOP_SUMMARY_REGRESSION", dse_seed_hex=witness.hex(), witness=after)


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
    parser.add_argument("--expect", choices=("budget", "verified"), default="budget",
                        help="reproduce current capture limit or require an inverted branch")
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
    result = {"status": "FAIL_JUNK_LOOP_TEST", "expect": args.expect, "max_steps": MAX_STEPS,
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
        output = Path(tempfile.mkdtemp(prefix="tf-junk-loop.", dir=parent))
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
