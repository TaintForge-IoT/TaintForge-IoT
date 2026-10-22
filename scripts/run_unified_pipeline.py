#!/usr/bin/env python3
"""Run the original i386 ELF with Phase 1 instrumentation in a Phase 2 attempt."""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
from pathlib import Path
import sys

from taintforge_env.elf_runtime import provision_guest
from taintforge_env.attempt_finalization import error_text
from taintforge_env.network_policy import load_network_policy
from taintforge_env.synthesis_loop import EnvironmentSynthesisLoop, LoopOutcome, SynthesisLoopConfig
from taintforge_env.unified_runtime import build_bundle, check_runtime_inputs, write_json


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def prepare(args) -> dict:
    out = args.out.expanduser().resolve()
    if out.exists() or out.is_symlink():
        raise ValueError(f"output directory already exists; use resume or a new --out: {out}")
    if args.network != "none" and args.network_policy is None:
        raise ValueError("--network-policy is required for controlled, record and replay")
    if (args.network == "replay") != (args.replay_store is not None):
        raise ValueError("--replay-store is required only with --network replay")
    if min(args.timeout, args.max_iterations, args.max_steps) < 1:
        raise ValueError("timeout and iteration limits must be positive")
    input_config = None
    if args.retire_phase1:
        from taintforge_env import input_retirement
        from taintforge_env.capsule_resources import preflight
        if not args.binary or args.capsule_probe or args.capsule_lifecycle or args.capsule_phase1_retirement:
            raise ValueError("--retire-phase1 requires --binary and cannot select a built-in capsule fixture")
        if args.network != "none" or args.phase1_option or args.extra_library or args.library_dir:
            raise ValueError("M3 requires network=none, no extra libraries and bound Phase 1 selection settings")
        if (args.capsule_case is not None or args.capsule_owner_mode != "remove" or
            args.capsule_owner_order != "after" or args.capsule_retirement_fault != "none" or
            args.capsule_retirement_trigger != "boundary" or args.capsule_selection_delay != 16):
            raise ValueError("Built-in fixture options cannot be combined with --retire-phase1")
        input_retirement.inspect_input(args.binary.expanduser())
        input_config = input_retirement.settings(hold_ms=args.capsule_hold_ms,
            pause_ms=args.capsule_pause_ms, total_ms=args.capsule_total_ms, timeout=args.timeout,
            memory_mib=args.capsule_memory_mib, selection_delay=args.retirement_selection_delay,
            max_instructions=args.retirement_max_insns)
        if args.capsule_hardening:
            from taintforge_env.capsule_hardening import policy
            input_config = input_retirement.settings(hold_ms=args.capsule_hold_ms,
                pause_ms=args.capsule_pause_ms, total_ms=args.capsule_total_ms, timeout=args.timeout,
                memory_mib=args.capsule_memory_mib, selection_delay=args.retirement_selection_delay,
                max_instructions=args.retirement_max_insns, hardening=policy(analysis_mib=args.analysis_memory_mib,
                    export_mib=args.export_mib, journal_mib=args.journal_mib, uid=args.execution_uid, gid=args.execution_gid))
        preflight()
        args.phase1_option = ["tf-selection-delay=" + str(args.retirement_selection_delay)]
    elif args.retirement_selection_delay != 16 or args.retirement_max_insns != 10000000:
        raise ValueError("M3 retirement settings require --retire-phase1")
    if not args.retire_phase1 and (args.capsule_hardening or args.analysis_memory_mib != 512 or
        args.export_mib != 256 or args.journal_mib != 32 or args.execution_uid != 65534 or args.execution_gid != 65534):
        raise ValueError('M4 hardening requires --retire-phase1')
    if not args.capsule_hardening and (args.analysis_memory_mib != 512 or args.export_mib != 256 or
        args.journal_mib != 32 or args.execution_uid != 65534 or args.execution_gid != 65534):
        raise ValueError('M4 budget and credential options require --capsule-hardening')
    if args.capsule_phase1_retirement:
        if args.capsule_lifecycle:
            raise ValueError("Select real Phase 1 retirement or fixture-owner lifecycle")
        args.capsule_probe = True
    elif (args.capsule_retirement_fault != "none" or args.capsule_retirement_trigger != "boundary" or
          args.capsule_selection_delay != 16):
        raise ValueError("retirement options require --capsule-phase1-retirement")
    if args.capsule_lifecycle:
        args.capsule_probe = True
    elif args.capsule_owner_mode != "remove" or args.capsule_owner_order != "after" or (args.capsule_memory_mib != 1024 and not (args.capsule_phase1_retirement or args.retire_phase1)):
        raise ValueError("owner and resource options require --capsule-lifecycle")
    if bool(args.binary) == bool(args.capsule_probe):
        raise ValueError("select exactly one of --binary or --capsule-probe")
    capsule_config = input_config
    if args.capsule_probe:
        from taintforge_env.execution_capsule import settings
        if args.network != "none" or args.max_iterations != 1 or args.max_steps != 1:
            raise ValueError("--capsule-probe requires --network none --max-iterations 1 --max-steps 1")
        capsule_config = settings(args.capsule_case or "phase1-first", hold_ms=args.capsule_hold_ms,
                                  pause_ms=args.capsule_pause_ms, total_ms=args.capsule_total_ms, timeout=args.timeout)
        if args.capsule_phase1_retirement:
            from taintforge_env.phase1_retirement import settings as retirement_settings
            from taintforge_env.capsule_resources import policy, preflight
            if capsule_config["case"] not in {"phase1-first", "capsule-first"}:
                raise ValueError("Phase 1 retirement has its own fault suite")
            if args.phase1_option:
                raise ValueError("The first Phase 1 retirement profile fixes its analysis options")
            capsule_config["phase1_retirement"] = retirement_settings(args.capsule_retirement_fault,
                trigger=args.capsule_retirement_trigger, selection_delay=args.capsule_selection_delay)
            args.phase1_option = ["tf-selection-delay=" + ("100000000" if args.capsule_retirement_fault == "missing-verdict"
                                                         else str(args.capsule_selection_delay))]
            capsule_config["resources"] = policy(args.capsule_memory_mib, args.timeout + 10)
            preflight()
        if args.capsule_lifecycle:
            from taintforge_env.capsule_lifecycle import settings as owner_settings
            from taintforge_env.capsule_resources import policy, preflight
            if args.capsule_owner_mode != "remove" and capsule_config["case"] not in {"phase1-first", "capsule-first"}:
                raise ValueError("owner fault injection cannot be combined with a controller fault")
            capsule_config["lifecycle"] = owner_settings(args.capsule_owner_mode, args.capsule_owner_order)
            capsule_config["resources"] = policy(args.capsule_memory_mib, args.timeout + 10)
            preflight()
    elif args.capsule_case is not None:
        raise ValueError("--capsule-case requires --capsule-probe")
    selected = check_runtime_inputs(PROJECT_ROOT, qemu=args.qemu, plugin=args.plugin)
    qemu, plugin = Path(selected["qemu"]["path"]), Path(selected["plugin"])
    binary = args.binary.expanduser().resolve(strict=True) if args.binary else None
    if capsule_config is not None:
        from experiments.execution_capsule_probe import controller as probe
        loaded = probe.load_phase1(PROJECT_ROOT, plugin, qemu)
        if args.capsule_phase1_retirement or args.retire_phase1:
            from taintforge_env.phase1_retirement import check_runtime
            _, selected_runtime, _ = loaded
            check_runtime(selected_runtime, trigger="verdict" if args.retire_phase1 else args.capsule_retirement_trigger)
    policy = load_network_policy(args.network_policy) if args.network_policy else None
    dns_server = args.dns_server
    if dns_server is None and policy is not None:
        dns_server = next((s.remote_ip for s in policy.services if s.protocol_hint == "dns" and s.remote_ip), None)
    if dns_server is not None:
        dns_server = str(ipaddress.IPv4Address(dns_server))
        if policy is not None and not any(s.protocol_hint == "dns" and s.remote_ip == dns_server and s.remote_port == 53 for s in policy.services):
            raise ValueError("guest DNS server must match a port-53 DNS endpoint in --network-policy")
    out.mkdir(parents=True)
    capsule_build = None
    if capsule_config is not None:
        if args.retire_phase1:
            from experiments.retirement_observer.controller import build_plugin
            capsule_build = build_plugin(out / "capsule_build")
            capsule_build["profile"] = input_retirement.PROFILE
        elif args.capsule_phase1_retirement:
            from taintforge_env.phase1_retirement import build
            capsule_build = build(out / "capsule_build", trigger=args.capsule_retirement_trigger)
        elif args.capsule_lifecycle:
            from experiments.execution_capsule_lifecycle import controller as lifecycle
            lifecycle.audit(PROJECT_ROOT)
            capsule_build = lifecycle.build(out / "capsule_build")
        else:
            capsule_build = probe.build(out / "capsule_build")
        if not args.retire_phase1:
            binary = Path(capsule_build["guest"])
    template = out / "template"
    rootfs = template / "rootfs"
    for name in ("proc", "dev", "tmp", "bin", "etc", "var/tmp", "run", "root"):
        (rootfs / name).mkdir(parents=True, exist_ok=True)
    (rootfs / "tmp").chmod(0o1777)
    (rootfs / "var/tmp").chmod(0o1777)
    guest = "/bin/sample.elf"
    guest_runtime = provision_guest(binary, rootfs, sysroot=args.sysroot.expanduser(),
                                     binary_guest_path=guest, library_dirs=args.library_dir, extra_libraries=args.extra_library)
    if args.retire_phase1:
        # Keep a stable original input for every fresh attempt and later resume.
        # The caller may move the source after preparation; captured memory is
        # never used as the next executable.
        from taintforge_env.elf_runtime import copy_file
        saved_input = out / "input/sample.elf"
        copy_file(rootfs / guest.lstrip("/"), saved_input,
                  expected=guest_runtime["target"]["sha256"], executable=True)
        binary = saved_input
    if guest_runtime["target"]["arch"] != "i386":
        raise ValueError("the Phase 1 v1 integration profile supports Linux i386 ELF only")
    config = template / "config"
    bundle_path = config / "analyzer_runtime"
    bundle = build_bundle(bundle_path, qemu=qemu, plugin=plugin, capsule_probe=capsule_build)
    if capsule_config is not None:
        bundled_qemu = next(item for item in bundle["files"] if item["path"] == bundle["qemu"])
        if bundled_qemu["sha256"] != selected["qemu"]["sha256"]:
            raise ValueError("selected QEMU changed while preparing the capsule bundle")
    write_json(config / "guest_runtime.json", guest_runtime)
    if policy is not None:
        write_json(config / "network_policy.json", policy.to_dict())
    (rootfs / "etc/resolv.conf").write_text(f"nameserver {dns_server}\noptions timeout:2 attempts:1\n" if dns_server else "# No DNS endpoint configured\n")
    (rootfs / "etc/nsswitch.conf").write_text("hosts: files dns\n")
    (rootfs / "etc/hosts").write_text("127.0.0.1 localhost\n")
    # The copied original ELF, its interpreter and libraries form the seed.
    # A raw Phase 1 memory capture is never passed to exec as an ELF file.
    runtime = {"schema_version": 1, "arch": "i386", "rootfs": str(rootfs),
               "host_binary": str(binary), "host_binary_path": str(binary),
               "guest_binary": guest, "guest_binary_path": guest, "qemu_required": True,
               "guest_library_path": guest_runtime["library_path"],
               "network_mode": args.network, "allow_internet": False,
               "phase1": {"bundle_path": str(bundle_path), "bundle_sha256": bundle["bundle_sha256"],
                          "options": args.phase1_option}}
    if capsule_config is not None:
        runtime["capsule"] = capsule_config
    write_json(config / "runtime.json", runtime)
    launch = {"schema_version": 1, "session_dir": str(out / "session"), "template_run_dir": str(template),
              "project_root": str(PROJECT_ROOT), "snapshot_store": str(out / "snapshots"), "seed_rootfs": str(rootfs),
              "binary_path": str(binary), "network_mode": args.network,
              "target_spec_path": str(args.target_spec.expanduser().resolve()) if args.target_spec else None,
              "replay_store_path": str(args.replay_store.expanduser().resolve()) if args.replay_store else None,
              "timeout_seconds": args.timeout, "max_iterations": args.max_iterations}
    write_json(out / "unified_launch.json", launch)
    return launch


def run_session(out: Path, launch: dict, *, max_steps: int, initialize_only=False) -> tuple[dict, int]:
    if launch.get("schema_version") != 1:
        raise ValueError("unsupported unified launch manifest")
    kwargs = {key: value for key, value in launch.items() if key != "schema_version"}
    session_dir = Path(launch["session_dir"])
    before = _saved_result(session_dir / "synthesis_loop.json")
    try:
        result = EnvironmentSynthesisLoop(SynthesisLoopConfig(**kwargs, max_steps=max_steps,
                                                            initialize_only=initialize_only)).run()
        result_data = result.to_dict()
        error = None
    except (OSError, ValueError, RuntimeError) as exc:
        # The loop retains its failed claim and does not complete/retry it.
        # Reporting that state is independent of returning a successful result.
        error = error_text(exc)
        binding = _saved_result(session_dir / "synthesis_loop.json")
        session = _saved_result(session_dir / "session.json")
        iterations = session.get("iterations", [])
        if not isinstance(iterations, list) or not all(isinstance(item, dict) for item in iterations):
            iterations = []
        previous_invocations = before.get("invocations", 0)
        if not isinstance(previous_invocations, int):
            previous_invocations = 0
        current_invocation_saved = (isinstance(binding.get("invocations"), int)
            and binding["invocations"] > previous_invocations)
        result_data = {
            "session_id": session.get("session_id"), "outcome": "intervention_required",
            "stop_reason": binding.get("stop_reason") if current_invocation_saved else "invocation_failed",
            "executions_this_invocation": binding.get("executions_last_invocation") if current_invocation_saved else None,
            "total_iterations": len(iterations),
            "last_iteration_index": iterations[-1].get("index") if iterations else None,
            "report_json": str(session_dir / "synthesis_report.json"),
            "report_markdown": str(session_dir / "synthesis_report.md"),
            "event_log": str(session_dir / "synthesis_events.jsonl"),
        }
    report = {"schema_version": 1, **result_data, "execution_model": "one_qemu_process_per_attempt",
              "launch_source": "original_elf", "memory_isolation": "not_implemented", "fuzzing_ready": False}
    index = result_data["last_iteration_index"]
    if isinstance(index, int) and index >= 0:
        directory = session_dir / f"iterations/{index:04d}/run"
        for name, relative in (("phase1", "config/phase1_result.json"), ("execution", "config/prebuilt_execution.json"),
                               ("finalization", "config/finalization_status.json")):
            report[name] = _saved_result(directory / relative)
        if (directory / "config/capsule_binding.json").is_file():
            report["capsule"] = _saved_result(directory / "config/capsule_result.json")
            if (directory / "logs/capsule/service.json").is_file():
                report["capsule_resources"] = _saved_result(directory / "logs/capsule/service.json")
        report["run_dir"] = str(directory)
    if report["outcome"] == LoopOutcome.INTERVENTION_REQUIRED:
        binding = _saved_result(session_dir / "synthesis_loop.json")
        report["error"] = error or binding.get("last_error")
    write_json(out / "unified_report.json", report)
    return report, 1 if report["outcome"] == LoopOutcome.INTERVENTION_REQUIRED else 0


def _saved_result(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(value, dict):
            raise ValueError("saved result must be a JSON object")
        return value
    except (OSError, ValueError) as exc:
        return {"status": "unavailable", "error": error_text(exc), "path": str(path)}


def parser():
    result = argparse.ArgumentParser(description=__doc__)
    commands = result.add_subparsers(dest="command", required=True)
    run = commands.add_parser("run", help="prepare a fresh environment and run the original ELF")
    run.add_argument("--binary", type=Path)
    run.add_argument("--retire-phase1", action="store_true",
        help="M3: static i386 input, current heuristic verdict, independent observer and fresh repair attempts")
    run.add_argument("--retirement-selection-delay", type=int, default=16)
    run.add_argument("--retirement-max-insns", type=int, default=10000000)
    run.add_argument("--capsule-probe", action="store_true", help="experimental handoff with the built-in controlled i386 ELF")
    run.add_argument("--capsule-lifecycle", action="store_true", help="run the controlled ELF with verified owner retirement and cgroup limits")
    run.add_argument("--capsule-phase1-retirement", action="store_true", help="retire the real Phase 1 after a verified export, on the controlled ELF")
    run.add_argument("--capsule-retirement-trigger", choices=("boundary", "verdict"), default="boundary",
                     help="v1 fixed fixture boundary or v2 next instruction after live OEP selection")
    run.add_argument("--capsule-selection-delay", type=int, default=16,
                     help="controlled verdict fixture selection delay (1..256)")
    run.add_argument("--capsule-retirement-fault", choices=("none", "deny", "stale-permit", "bad-digest", "disconnect", "timeout", "missing-verdict"), default="none")
    run.add_argument("--capsule-owner-mode", choices=("remove", "keep", "leak-arena", "bad-export"), default="remove")
    run.add_argument("--capsule-owner-order", choices=("before", "after"), default="after")
    run.add_argument("--capsule-memory-mib", type=int, default=1024)
    run.add_argument('--capsule-hardening', action='store_true')
    run.add_argument('--analysis-memory-mib', type=int, default=512)
    run.add_argument('--export-mib', type=int, default=256)
    run.add_argument('--journal-mib', type=int, default=32)
    run.add_argument('--execution-uid', type=int, default=65534)
    run.add_argument('--execution-gid', type=int, default=65534)
    run.add_argument("--capsule-case", choices=("phase1-first", "capsule-first", "timeout-1", "timeout-2",
        "disconnect-1", "disconnect-2", "kill-controller-1", "kill-controller-2", "bad-command", "slow-command", "total-timeout"))
    run.add_argument("--capsule-hold-ms", type=int, default=200)
    run.add_argument("--capsule-pause-ms", type=int, default=5000)
    run.add_argument("--capsule-total-ms", type=int, default=30000)
    run.add_argument("--out", type=Path, required=True)
    run.add_argument("--plugin", type=Path, help="Phase 1 plugin; defaults to TAINTFORGE_QEMU_PLUGIN or build/libtaintforge_ir.so")
    run.add_argument("--qemu", help="dynamic qemu-i386 path; defaults to PATH")
    run.add_argument("--sysroot", type=Path, default=Path("/"), help="source of matching guest loader/libraries; never executed")
    run.add_argument("--library-dir", action="append", default=[], help="additional absolute search path inside --sysroot")
    run.add_argument("--extra-library", action="append", default=[], help="explicit dlopen dependency, e.g. libvendor.so")
    run.add_argument("--network", choices=("none", "controlled", "record", "replay"), default="none")
    run.add_argument("--network-policy", type=Path)
    run.add_argument("--replay-store", type=Path)
    run.add_argument("--dns-server", help="guest IPv4 resolver; defaults to first DNS endpoint in policy")
    run.add_argument("--target-spec", type=Path)
    run.add_argument("--timeout", type=int, default=60)
    run.add_argument("--max-iterations", type=int, default=5)
    run.add_argument("--max-steps", type=int, default=1)
    run.add_argument("--phase1-option", action="append", default=[], help="repeatable Phase 1 v1 key=value analysis option")
    run.add_argument("--prepare-only", action="store_true", help="bind the session without executing the guest")
    resume = commands.add_parser("resume", help="advance using the bound settings and hashes")
    resume.add_argument("--out", type=Path, required=True)
    resume.add_argument("--max-steps", type=int, default=1)
    for name in ("status", "verify"):
        commands.add_parser(name).add_argument("--out", type=Path, required=True)
    check = commands.add_parser("check-runtime", help="verify QEMU/plugin input files without executing the guest or creating a session")
    check.add_argument("--plugin", type=Path)
    check.add_argument("--qemu")
    return result


def main():
    args = parser().parse_args()
    os.umask(0o077)
    try:
        if args.command == "check-runtime":
            print(json.dumps(check_runtime_inputs(PROJECT_ROOT, qemu=args.qemu, plugin=args.plugin), indent=2))
            return 0
        out = args.out.expanduser().resolve()
        if args.command in {"status", "verify"}:
            action = EnvironmentSynthesisLoop.status if args.command == "status" else EnvironmentSynthesisLoop.verify_session
            report, status = action(out / "session"), 0
        else:
            launch = prepare(args) if args.command == "run" else json.loads((out / "unified_launch.json").read_text())
            report, status = run_session(out, launch, max_steps=args.max_steps,
                                         initialize_only=getattr(args, "prepare_only", False))
        print(json.dumps(report, indent=2, ensure_ascii=False))
        return status
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"Unified pipeline failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
