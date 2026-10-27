"""Static i386 input retirement and fresh unified attempts."""
from __future__ import annotations

import multiprocessing as mp
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time
import uuid

from experiments.retirement_observer import controller as observer
from . import capsule_resources, phase1_retirement as retirement, retirement_mappings
from .attempt import AttemptContract
from .elf_runtime import ElfImage, copy_file
from .phase1_runtime import read_json

p = retirement.probe
PROFILE = "input-static-i386-retirement-m3"
POLICY = "selected-current-heuristic-v1"
OBSERVER_PATH = "capsule/libretirement_observer.so"
MAX_INPUT_BYTES = 64 * 1024**2


def inspect_input(path):
    path = Path(path)
    info = path.lstat()
    p.require(stat.S_ISREG(info.st_mode) and 52 <= info.st_size <= MAX_INPUT_BYTES,
              "M3 input must be a regular ELF file of at most 64 MiB")
    image = ElfImage(path)
    t = image.target
    p.require(t.elf_class == 32 and t.arch == "i386" and t.endianness == "little" and
              t.file_type_id == 2 and t.static and not t.pie and t.interpreter is None and
              not any(s.kind == 2 for s in image.segments),
              "M3 accepts static little-endian i386 ET_EXEC without PT_INTERP/PT_DYNAMIC only")
    loads = [s for s in image.segments if s.kind == 1]
    p.require(loads and all(0 < s.address and s.address+s.memory_size <= 2**32 for s in loads) and
              any(s.flags & 1 and s.address <= t.entry_point < s.address+s.file_size for s in loads),
              "M3 requires a file-backed executable entry point and valid i386 load extents")
    return {"profile": PROFILE, "sha256": t.sha256, "size": info.st_size,
            "elf_class": 32, "arch": "i386", "file_type": "ET_EXEC", "static": True,
            "entry_point": t.entry_point, "single_process_vcpu_required": True}


def retirement_settings(*, selection_delay=16, max_instructions=10000000):
    p.require(type(selection_delay) is int and 1 <= selection_delay <= 100000000,
              "M3 selection delay must be in 1..100000000")
    p.require(type(max_instructions) is int and selection_delay < max_instructions <= 1000000000,
              "M3 instruction budget must exceed selection delay and be at most 1000000000")
    return {"profile": PROFILE, "protocol": 2, "fault": "none", "policy": POLICY,
            "selection_delay": selection_delay, "max_instructions": max_instructions}


def settings(*, hold_ms=200, pause_ms=5000, total_ms=30000, timeout=60,
             memory_mib=1024, selection_delay=16, max_instructions=10000000, hardening=None):
    # Native observer/permit deadlines are fixed to the M2 five-second hold.
    p.require(type(hold_ms) is int and 20 <= hold_ms <= 1000 and pause_ms == 5000 and
              type(total_ms) is int and 10000 <= total_ms <= 86400000 and
              timeout * 1000 >= total_ms + 12000, "Invalid M3 hold/total/wrapper deadlines")
    result = {"profile": PROFILE, "hold_ms": hold_ms, "pause_ms": pause_ms,
            "total_ms": total_ms, "plugin_order": "phase1-first",
            "phase1_retirement": retirement_settings(selection_delay=selection_delay,
                                                       max_instructions=max_instructions),
            "resources": capsule_resources.policy(memory_mib, timeout+10)}
    if hardening is not None:
        from .capsule_hardening import validate
        validate(hardening)
        p.require(hardening['analysis_bytes'] < result['resources']['memory_bytes'], 'M4 analysis budget requires cgroup headroom')
        result['hardening'] = hardening
    return result


def validate_settings(config):
    r = config["phase1_retirement"]
    expected = settings(hold_ms=config["hold_ms"], pause_ms=config["pause_ms"],
        total_ms=config["total_ms"], timeout=config["resources"]["seconds"]-10,
        memory_mib=config["resources"]["memory_bytes"] // 1024**2,
        selection_delay=r["selection_delay"], max_instructions=r["max_instructions"], hardening=config.get('hardening'))
    p.require(config == expected, "Unsupported M3 settings")


def bundle_profile(built):
    return {"profile": PROFILE, "plugin": OBSERVER_PATH, "protocol": observer.PROTOCOL,
            "pc_source": observer.PC_SOURCE, "qemu_version": "11.0.1",
            "source_sha256": built["source_sha256"]}


def verify_profile(manifest):
    profile = manifest["capsule"]
    inventory = {item["path"]: item for item in manifest["files"]}
    p.require(set(profile) == {"profile", "plugin", "protocol", "pc_source", "qemu_version", "source_sha256"}
              and profile["profile"] == PROFILE and profile["plugin"] == OBSERVER_PATH and
              OBSERVER_PATH in inventory and profile["protocol"] == observer.PROTOCOL and
              profile["pc_source"] == observer.PC_SOURCE and profile["qemu_version"] == "11.0.1"
              and manifest["plugin_api"] == 6, "Invalid M3 observer bundle profile")


def prepare_binding(context, temporary, manifest, phase1):
    config = read_json(context.template_runtime_path)
    p.require(config["network_mode"] == "none", "M3 input retirement requires network=none")
    config = config["capsule"]
    validate_settings(config)
    verify_profile(manifest)
    target = context.execution_rootfs / context.guest_binary.lstrip("/")
    descriptor = inspect_input(target)
    p.require(descriptor["sha256"] == context.execution_plan.target.sha256 ==
              context.attempt_contract.packed_binary_sha256, "M3 staged input/attempt mismatch")
    reserved = context.execution_rootfs / "__taintforge_capsule"
    p.require(not reserved.exists() and not reserved.is_symlink(), "M3 IPC mount collides with guest path")
    copy_file(target, temporary / "guest-i386", expected=descriptor["sha256"], executable=True)
    context.attempt_contract.save(temporary / "config/input-attempt.json")
    binding = {key: phase1[key] for key in retirement_mappings.IDENTITY}
    binding.update(schema_version=1, profile=PROFILE, run_dir=str(context.run_dir),
        rootfs=str(context.execution_rootfs), guest_binary=context.guest_binary,
        lifecycle_attempt=uuid.uuid4().hex, retirement_evidence_schema=1,
        settings=config, capsule=manifest["capsule"], input_retirement=descriptor)
    binding["observer"] = {"profile": PROFILE, "protocol": observer.PROTOCOL,
        "pc_source": observer.PC_SOURCE, "fault": "none", "plugin_order": config["plugin_order"],
        "hold_ms": config["hold_ms"], "pause_ms": config["pause_ms"], "total_ms": config["total_ms"],
        "after_release_delay_ms": 0, "guest_sha256": descriptor["sha256"]}
    if 'afl_file' in read_json(context.template_runtime_path):
        from .afl_file import validate_setting
        binding['afl_file'] = validate_setting(read_json(context.template_runtime_path)['afl_file'],
                                              context.execution_rootfs, context.guest_binary)
    if 'afl_warm' in read_json(context.template_runtime_path):
        from .afl_warm import validate
        p.require('afl_file' in binding, 'Warm execution requires a file input')
        binding['afl_warm'] = validate(read_json(context.template_runtime_path)['afl_warm'])
    (temporary / "logs/capsule/phase1-retirement").mkdir(parents=True)
    # Paths will change during the atomic staging rename; contract data does not.
    modules = {"phase1": temporary / "config/analyzer_runtime" / phase1["plugin"],
               "observer": temporary / "config/analyzer_runtime" / manifest["capsule"]["plugin"]}
    contract = contract_data(binding, context.attempt_contract.to_dict(), modules)
    p.write_json(temporary / "config/observer-contract.json", contract)
    binding["observer_contract_sha256"] = p.sha(temporary / "config/observer-contract.json")
    p.write_json(temporary / "config/capsule_binding.json", binding)
    if 'hardening' in config:
        from .capsule_hardening import private_controls
        sidecar = read_json(modules['phase1'].with_name(modules['phase1'].name + '.runtime.json'))
        p.require(sidecar.get('resource_ledger') == {'schema':1,'scope':'explicit_project_allocations',
                  'external_allocations_tracked':False}, 'M4 requires a rebuilt Phase 1 resource ledger')
        private_controls(temporary)


def contract_data(binding, attempt, modules):
    result = {"schema": 1, "profile": PROFILE, "attempt": attempt,
            **{k: binding[k] for k in retirement_mappings.IDENTITY},
            "nonce": binding["lifecycle_attempt"], "input": binding["input_retirement"],
            "observer": binding["observer"], "settings": binding["settings"],
            "phase1_sha256": p.sha(modules["phase1"]), "observer_sha256": p.sha(modules["observer"])}
    if 'afl_file' in binding:
        result['afl_file'] = binding['afl_file']
    if 'afl_warm' in binding: result['afl_warm'] = binding['afl_warm']
    return result


def verify_contract(binding):
    root = Path(binding["run_dir"])
    validate_settings(binding["settings"])
    p.require(binding.get("profile") == PROFILE and
              re.fullmatch(r"[0-9a-f]{32}", binding["lifecycle_attempt"]), "Invalid M3 identity")
    attempt = AttemptContract.load(root / "config/input-attempt.json")
    p.require(attempt.attempt_id == binding["attempt_id"] and
              attempt.contract_sha256 == binding["attempt_contract_sha256"], "M3 attempt contract changed")
    descriptor = inspect_input(root / "guest-i386")
    p.require(descriptor == binding["input_retirement"] and
              descriptor["sha256"] == attempt.packed_binary_sha256 == attempt.sample_sha256,
              "M3 input identity changed")
    config = binding["observer"]
    s = binding["settings"]
    p.require(config == {"profile": PROFILE, "protocol": observer.PROTOCOL,
        "pc_source": observer.PC_SOURCE, "fault": "none", "plugin_order": s["plugin_order"],
        "hold_ms": s["hold_ms"], "pause_ms": s["pause_ms"], "total_ms": s["total_ms"],
        "after_release_delay_ms": 0, "guest_sha256": descriptor["sha256"]}, "Invalid M3 observer settings")
    contract = root / "config/observer-contract.json"
    p.require(read_json(contract) == contract_data(binding, attempt.to_dict(), retirement_mappings.module_paths(binding))
              and p.sha(contract) == binding["observer_contract_sha256"], "M3 observer contract changed")
    return attempt


def supervise(binding, ipc):
    """Bounded supervisor inside the existing systemd/namespace wrapper."""
    from .unified_runtime import verify_bundle
    run, ipc = Path(binding["run_dir"]), Path(ipc)
    output = run / "logs/capsule"
    result = {"schema_version": 1, "profile": PROFILE, "status": "failed",
        **{k: binding[k] for k in retirement_mappings.IDENTITY}, "qemu_exit": None,
        "supervisor_kill": False, "pid_scope": "sandbox_pid_namespace", "claims": retirement.CLAIMS}
    workers, pipes = [], []
    process = None
    warm = None
    stage, started = "preflight", time.monotonic()
    try:
        verify_contract(binding)
        manifest = verify_bundle(run / "config/analyzer_runtime", binding["bundle_sha256"])
        p.require(manifest["capsule"] == binding["capsule"], "M3 observer bundle changed")
        p.require(inspect_input(Path(binding["rootfs"]) / binding["guest_binary"].lstrip("/")) ==
                  binding["input_retirement"], "M3 guest changed before launch")
        result["resource_entry"] = capsule_resources.inspect_self(binding)
        ctx = mp.get_context("spawn")
        permit_gate, observer_gate = ctx.Pipe()
        pp, pc = ctx.Pipe()
        op, oc = ctx.Pipe()
        pipes = [permit_gate, observer_gate, pp, pc, op, oc]
        permit = ctx.Process(target=retirement.permit_worker, args=(ipc / "phase1.sock", pc, binding),
                             kwargs={"progress_pipe": permit_gate})
        permit.start(); workers.append(permit); pc.close(); permit_gate.close()
        p.wait_worker_ready(pp, "permit")
        worker = ctx.Process(target=observer.control_worker, args=(ipc / "observer.sock", oc, observer_gate, binding))
        worker.start(); workers.append(worker); oc.close(); observer_gate.close()
        p.wait_worker_ready(op, "observer")
        phase = read_json(run / "config/phase1_binding.json")["plugin_argument"]
        phase += "," + ",".join(retirement.plugin_options(binding, "/__taintforge_capsule", permit.pid))
        arg = ",".join(["/__taintforge/" + binding["capsule"]["plugin"],
            "socket=/__taintforge_capsule/observer.sock", "pause-ms=5000",
            "total-ms=" + str(binding["settings"]["total_ms"]), "controller=" + str(worker.pid)])
        hardened = 'hardening' in binding['settings']
        if hardened:
            from . import capsule_hardening as m4
            limits = m4.config(binding)
            phase += ',m4-memory-bytes=' + str(limits['analysis_bytes'])
            phase += ',retire-controller-uid=' + str(os.geteuid())
            arg += ',controller-uid=' + str(os.geteuid())
        if 'afl_file' in binding:
            from .afl_file import prepare_map
            arg += ',' + ','.join(prepare_map(binding, ipc))
        if 'afl_warm' in binding:
            from .afl_warm import Broker
            warm = Broker(binding, ipc)
            warm.start()
            arg += ',afl-warm=/__taintforge_capsule/afl-warm.sock,afl-warm-rss=' + str(binding['afl_warm']['max_rss_mib'])
        command = ["chroot", binding["rootfs"], "/__taintforge/bin/loader", "--inhibit-cache",
            "--library-path", "/__taintforge/lib", "/__taintforge/bin/qemu-i386", "-L", "/", "-strace",
            "-plugin", phase, "-plugin", arg, binding["guest_binary"]]
        result["command"] = command
        if hardened:
            command = [sys.executable, '-m', 'taintforge_env.capsule_hardening', 'launch',
                       '--binding', str(run / 'config/capsule_binding.json'), '--', *command[2:]]
            result['command'] = command
        stage = "qemu_start"
        launch_cwd = Path(__file__).resolve().parents[1] if hardened else binding["rootfs"]
        # Own stdout directly: offline verification cannot race the wrapper's tee.
        with (run / "logs/runtime_stdout.log").open("wb") as stdout, (run / "logs/qemu_strace.log").open("wb") as stderr:
            process = subprocess.Popen(command, cwd=launch_cwd, stdout=stdout, stderr=stderr,
                close_fds=True, env={"PATH": "/usr/bin:/bin", "HOME": "/", "LANG": "C", "LC_ALL": "C"})
            result.update(qemu_pid=process.pid, controller_pid=worker.pid)
            result['launch_monotonic_ns'] = time.monotonic_ns()
            pp.send(process.pid); op.send(process.pid)
            stage = "qemu_wait"
            if hardened:
                deadline = time.monotonic() + binding['settings']['total_ms']/1000 + 5
                while process.poll() is None:
                    result['m4_usage'] = m4.budget_usage(binding)
                    if time.monotonic() >= deadline: raise TimeoutError('M4 QEMU total deadline')
                    time.sleep(limits['poll_ms']/1000)
                result['m4_usage'] = m4.budget_usage(binding)
                result['qemu_exit'] = process.returncode
            else:
                result["qemu_exit"] = process.wait(timeout=binding["settings"]["total_ms"] / 1000 + 5)
            result['finish_monotonic_ns'] = time.monotonic_ns()
        if warm is not None:
            warm.close()
            p.require(not warm.errors, 'Warm executor failed: '+str(warm.errors))
            result['warm'] = read_json(Path(binding['afl_warm']['campaign_root'])/'warm-executor.json')
        worker.join(4)
        p.require(not worker.is_alive(), "M3 observer controller did not finish")
        result["controller_exit"] = worker.exitcode
        permit.join(1)
        p.require(not permit.is_alive() and permit.exitcode == 0, "M3 permit controller did not finish")
        stage = "verification"
        result.update(observer.verify_attempt(binding, result))
    except Exception as exc:
        result.update(error=f"{type(exc).__name__}: {exc}"[-6000:], failure=p.execution_failure(exc, result, stage))
    finally:
        if process is not None and process.poll() is None:
            process.kill(); result["qemu_exit"] = process.wait(timeout=3); result["supervisor_kill"] = True
        if process is not None:
            if result['qemu_exit'] is None: result['qemu_exit'] = process.wait(timeout=3)
            result.setdefault('finish_monotonic_ns',time.monotonic_ns())
        if warm is not None:
            try: warm.close()
            except Exception as exc: result.update(status='failed', warm_error=str(exc))
        for worker in workers:
            if worker.is_alive(): worker.kill()
            worker.join(3)
        for pipe in pipes: pipe.close()
        if 'afl_file' in binding:
            try:
                from .afl_file import save_map
                save_map(binding, ipc)
            except Exception as exc:
                result.update(status='failed', coverage_error=str(exc))
        for name in ("phase1.sock", "observer.sock"): (ipc / name).unlink(missing_ok=True)
        result["controller_failures"] = p.saved_worker_failures(output)
        result["elapsed_seconds"] = round(time.monotonic()-started, 3)
        p.write_json(output / "supervisor.json", result)
    code = result["qemu_exit"]
    return (128-code if code < 0 else code) if code is not None else 126


def finish_attempt(context, guest_exit_code):
    run = context.run_dir
    binding = read_json(run / "config/capsule_binding.json")
    summary = {"profile": PROFILE, "status": "failed", "claims": retirement.CLAIMS}
    try:
        p.require(binding["attempt_id"] == context.attempt_contract.attempt_id and
                  binding["attempt_contract_sha256"] == context.attempt_contract.contract_sha256,
                  "M3 finalization belongs to another attempt")
        result = read_json(run / "logs/capsule/supervisor.json")
        p.require(result["qemu_exit"] == guest_exit_code, "M3 recorded exit differs from wrapper exit")
        summary.update(result)
        checked = observer.verify_attempt(binding, result)
        p.require(result["status"] == checked["status"], "M3 saved supervisor result changed")
        summary.update(checked)
        summary["resources"] = capsule_resources.verify_saved(binding, guest_exit_code)
        from .retirement_evidence import pack
        summary["portable_evidence"] = pack(run, run / "retirement-evidence")
        p.require(summary["status"] == "passed", "M3 retirement/continuation not proven; attempt cannot be reused")
        if 'afl_file' in binding and 'afl_warm' not in binding:
            from .afl_file import verify_map
            summary['afl_coverage'] = verify_map(binding)
        if 'afl_warm' in binding:
            p.require(result.get('warm', {}).get('status') == 'passed' and result['warm']['children'] >= 0,
                      'Invalid warm completion record')
            summary['warm'] = result['warm']
        summary.update(application_success="evaluated_separately_by_phase2", restart="live_post_retirement_fork" if "afl_warm" in binding else "new_original_elf_attempt")
    except Exception as exc:
        summary.update(status="failed", error=f"{type(exc).__name__}: {exc}"[-6000:])
        raise
    finally:
        p.write_json(run / "config/capsule_result.json", summary)
    return summary
