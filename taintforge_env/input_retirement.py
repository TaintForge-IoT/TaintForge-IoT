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
from .capsule_supervision import ControllerExitError, wait_qemu

p = retirement.probe
PROFILE = "input-static-i386-retirement-m3"
POLICY = "selected-current-heuristic-v1"
OBSERVER_PATH = "capsule/libretirement_observer.so"
MAX_INPUT_BYTES = 64 * 1024**2
OBSERVER_EVIDENCE_JOIN_SECONDS = 10


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
             memory_mib=1024, selection_delay=16, max_instructions=10000000, hardening=None,
             control_guard=None, analysis_policy=None):
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
    if control_guard is not None:
        from .capsule_control import validate
        p.require(hardening is not None, 'Capsule control guard requires M4 hardening')
        result['control_guard'] = validate(control_guard)
    if analysis_policy is not None:
        from .analysis_quality import validate
        result['analysis_policy'] = validate(analysis_policy)
    return result


def validate_settings(config):
    r = config["phase1_retirement"]
    expected = settings(hold_ms=config["hold_ms"], pause_ms=config["pause_ms"],
        total_ms=config["total_ms"], timeout=config["resources"]["seconds"]-10,
        memory_mib=config["resources"]["memory_bytes"] // 1024**2,
        selection_delay=r["selection_delay"], max_instructions=r["max_instructions"], hardening=config.get('hardening'),
        control_guard=config.get('control_guard'), analysis_policy=config.get('analysis_policy'))
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
    runtime_config = config
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
    from .network_capsule import staged_profile
    network = staged_profile(context, runtime_config, phase1)
    if network is not None:
        p.require(manifest.get('network_observer', {}).get('plugin_api') == manifest['plugin_api'],
                  'Network retirement requires a matching endpoint observer plugin API')
        binding['network'] = network
    binding["observer"] = {"profile": PROFILE, "protocol": observer.PROTOCOL,
        "pc_source": observer.PC_SOURCE, "fault": "none", "plugin_order": config["plugin_order"],
        "hold_ms": config["hold_ms"], "pause_ms": config["pause_ms"], "total_ms": config["total_ms"],
        "after_release_delay_ms": 0, "guest_sha256": descriptor["sha256"]}
    if 'control_guard' in config:
        from .capsule_control import private_prefix, verify_bundle
        binding['control_guard_private_path'] = binding['run_dir']
        private_prefix(binding)
        verify_bundle(manifest['capsule'])
    if 'afl_file' in read_json(context.template_runtime_path):
        from .afl_file import validate_setting
        binding['afl_file'] = validate_setting(read_json(context.template_runtime_path)['afl_file'],
                                              context.execution_rootfs, context.guest_binary)
    if 'afl_warm' in read_json(context.template_runtime_path):
        from .afl_warm import validate
        p.require('afl_file' in binding, 'Warm execution requires a file input')
        binding['afl_warm'] = validate(read_json(context.template_runtime_path)['afl_warm'])
    from .afl_capsule import validate_binding
    validate_binding(binding)
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
    if 'control_guard' in binding['settings']:
        from .capsule_control import private_prefix
        result['control_guard_private_path'] = private_prefix(binding)
    if 'afl_file' in binding:
        result['afl_file'] = binding['afl_file']
    if 'afl_warm' in binding: result['afl_warm'] = binding['afl_warm']
    if 'network' in binding: result['network'] = binding['network']
    return result


def verify_contract(binding):
    root = Path(binding["run_dir"])
    validate_settings(binding["settings"])
    if 'network' in binding:
        from .network_capsule import validate_mode, PROFILE as network_profile
        network = binding['network']
        phase = read_json(root / 'config/phase1_binding.json')
        validate_mode(network.get('mode'), binding['settings'], observer='network_observer' in phase,
                      warm=any(key in binding for key in ('afl_file', 'afl_warm')))
        p.require(set(network) == {'profile','mode','policy_sha256','observer','execution_timeout_ms'}
                  and network['profile'] == network_profile and network['mode'] != 'none'
                  and network['observer'] == phase['network_observer']
                  and type(network['execution_timeout_ms']) is int
                  and network['execution_timeout_ms'] == binding['settings']['total_ms'] - 1000,
                  'Invalid M3 network retirement profile')
    if 'control_guard' in binding['settings']:
        from .capsule_control import private_prefix, verify_bundle
        private_prefix(binding)
        verify_bundle(binding['capsule'])
    from .afl_capsule import validate_binding
    validate_binding(binding)
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


def plugin_arguments(binding, phase1_argument, observer_argument):
    phase = read_json(Path(binding['run_dir']) / 'config/phase1_binding.json')
    result = ['-plugin', phase1_argument, '-plugin', observer_argument]
    endpoint = phase.get('network_observer')
    if 'network' in binding:
        p.require(endpoint == binding['network']['observer'], 'Capsule endpoint observer binding changed')
    if endpoint is not None:
        result += ['-plugin', endpoint['plugin_argument']]
    return result


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
    network_monitor = None
    stage, started = "preflight", time.monotonic()
    try:
        verify_contract(binding)
        if 'network' in binding:
            from .network_capsule import Monitor
            network_monitor = Monitor(binding)
            result['network_namespace'] = {'status': 'verified', 'namespace': network_monitor.record['namespace']}
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
        if 'control_guard' in binding['settings']:
            from .capsule_control import private_prefix
            arg += ',control-guard=' + private_prefix(binding)
        if 'afl_file' in binding:
            from .afl_file import prepare_map
            arg += ',' + ','.join(prepare_map(binding, ipc))
        if 'afl_warm' in binding:
            from .afl_warm import Broker
            warm = Broker(binding, ipc)
            warm.start()
            arg += ',afl-warm=/__taintforge_capsule/afl-warm.sock,afl-warm-rss=' + str(binding['afl_warm']['max_rss_mib'])
        plugins = plugin_arguments(binding, phase, arg)
        command = ["chroot", binding["rootfs"], "/__taintforge/bin/loader", "--inhibit-cache",
            "--library-path", "/__taintforge/lib", "/__taintforge/bin/qemu-i386", "-L", "/", "-strace",
            *plugins, binding["guest_binary"]]
        result["command"] = command
        if hardened:
            command = [sys.executable, '-m', 'taintforge_env.capsule_hardening', 'launch',
                       '--binding', str(run / 'config/capsule_binding.json'), '--', *command[2:]]
            result['command'] = command
        stage = "qemu_start"
        launch_cwd = Path(__file__).resolve().parents[1] if hardened else binding["rootfs"]
        # Own stdout directly: offline verification cannot race the wrapper's tee.
        with (run / "logs/runtime_stdout.log").open("wb") as stdout, (run / "logs/qemu_strace.log").open("wb") as stderr:
            standard_input = {'stdin': subprocess.DEVNULL} if 'control_guard' in binding['settings'] else {}
            process = subprocess.Popen(command, cwd=launch_cwd, stdout=stdout, stderr=stderr,
                close_fds=True, env={"PATH": "/usr/bin:/bin", "HOME": "/", "LANG": "C", "LC_ALL": "C"},
                **standard_input)
            result.update(qemu_pid=process.pid, controller_pid=worker.pid)
            result['launch_monotonic_ns'] = time.monotonic_ns()
            if network_monitor is not None:
                network_monitor.arm()
            p.write_json(output/'workers.json', {
                'schema': 1, 'identity': {k: binding[k] for k in retirement_mappings.IDENTITY},
                'unit': capsule_resources.unit_name(binding), 'pid_scope': 'sandbox_pid_namespace',
                'pid_namespace': os.readlink('/proc/self/ns/pid'), 'supervisor_pid': os.getpid(),
                'supervisor_start_ticks': retirement_mappings.process_identity(Path('/proc/self/stat').read_text())[1],
                'workers': {'permit': permit.pid, 'observer': worker.pid}, 'qemu_pid': process.pid,
            })
            pp.send(process.pid); op.send(process.pid)
            stage = "qemu_wait"
            if hardened:
                def sample():
                    result['m4_usage'] = m4.budget_usage(binding)
                poll_seconds = limits['poll_ms']/1000
            else:
                sample, poll_seconds = None, .01
            if network_monitor is not None:
                resource_sample = sample
                def sample():
                    network_monitor.check()
                    if resource_sample is not None:
                        resource_sample()
            result['qemu_exit'] = wait_qemu(process, (('permit', permit), ('observer', worker)),
                output, binding['settings']['total_ms']/1000 + 5,
                poll_seconds=poll_seconds, sample=sample)
            if network_monitor is not None:
                network_monitor.check()
            if hardened:
                result['m4_usage'] = m4.budget_usage(binding)
            result['finish_monotonic_ns'] = time.monotonic_ns()
        if warm is not None:
            warm.close()
            p.require(not warm.errors, 'Warm executor failed: '+str(warm.errors))
            result['warm'] = read_json(Path(binding['afl_warm']['campaign_root'])/'warm-executor.json')
        # QEMU has exited. The observer can now sync its buffered evidence
        # without consuming either native HOLD deadline.
        worker.join(OBSERVER_EVIDENCE_JOIN_SECONDS)
        p.require(not worker.is_alive(), "M3 observer controller did not finish")
        result["controller_exit"] = worker.exitcode
        permit.join(1)
        p.require(not permit.is_alive() and permit.exitcode == 0, "M3 permit controller did not finish")
        stage = "verification"
        result.update(observer.verify_attempt(binding, result))
    except Exception as exc:
        from .network_capsule import NetworkCapsuleStopped
        failure = exc.failure if isinstance(exc, (ControllerExitError, NetworkCapsuleStopped)) else p.execution_failure(exc, result, stage)
        result.update(error=f"{type(exc).__name__}: {exc}"[-6000:], failure=failure)
        if isinstance(exc, NetworkCapsuleStopped):
            result['network_termination'] = {**{key: binding[key] for key in retirement_mappings.IDENTITY},
                'reason': exc.reason, 'observed_monotonic_ns': time.monotonic_ns()}
        if isinstance(exc, ControllerExitError):
            result['worker_exit'] = exc.record
    finally:
        if process is not None and 'network_termination' in result:
            from .network_capsule import stop_qemu
            result['qemu_exit'] = stop_qemu(process, 1)
        if process is not None and process.poll() is None:
            process.kill(); result["qemu_exit"] = process.wait(timeout=3); result["supervisor_kill"] = True
        if process is not None:
            if result['qemu_exit'] is None: result['qemu_exit'] = process.wait(timeout=3)
            result.setdefault('finish_monotonic_ns',time.monotonic_ns())
        if warm is not None:
            try: warm.close()
            except Exception as exc: result.update(status='failed', warm_error=str(exc))
        # Record failures before supervisor cleanup can itself send SIGKILL.
        # QEMU may observe controller loss and exit before wait_qemu sees it.
        exited_workers = [{'component': name, 'pid': item.pid, 'exitcode': item.exitcode}
                          for name, item in zip(('permit', 'observer'), workers)
                          if item.exitcode not in (None, 0)]
        for worker in workers:
            if 'network_termination' in result:
                worker.join(.5)
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
        result["controller_failures"] = p.saved_worker_failures(output) + exited_workers
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
        summary.update(result)
        if result.get('error'):
            summary['supervisor_error'] = result['error']
        summary['wrapper_exit'] = guest_exit_code
        if result['qemu_exit'] is None:
            p.require(result.get('qemu_pid') is None and result['status'] == 'failed'
                      and all(result.get(key) == binding[key] for key in retirement_mappings.IDENTITY),
                      'M3 missing QEMU exit without a matching supervisor launch failure')
            raise RuntimeError('M3 supervisor failed before QEMU launch: ' +
                               summary.get('supervisor_error', 'no failure detail'))
        from .capsule_supervision import exit_status
        summary['qemu_exit_status'] = exit_status(result['qemu_exit'])
        p.require(type(guest_exit_code) is int and
                  summary['qemu_exit_status']['wrapper_exit'] == guest_exit_code,
                  'M3 recorded exit differs from wrapper exit')
        if 'network_termination' in result:
            from .network_capsule import finalize_interrupted
            summary.update(finalize_interrupted(binding, result, guest_exit_code))
            p.write_json(run / 'config/capsule_result.json', summary)
            raise RuntimeError('Capsule interrupted by network runtime: ' + result['network_termination']['reason'])
        checked = observer.verify_attempt(binding, result)
        p.require(result["status"] == checked["status"], "M3 saved supervisor result changed")
        summary.update(checked)
        summary["resources"] = capsule_resources.verify_saved(binding, guest_exit_code)
        from .retirement_evidence import pack
        summary["portable_evidence"] = pack(run, run / "retirement-evidence")
        if summary.get('analysis_quality', {}).get('status') == 'rejected':
            from .analysis_quality import require_accepted
            require_accepted(summary['analysis_quality'])
        p.require(summary["status"] == "passed", "M3 retirement/continuation not proven; attempt cannot be reused")
        if 'afl_file' in binding and 'afl_warm' not in binding:
            from .afl_file import verify_map
            summary['afl_coverage'] = verify_map(binding)
        if 'afl_warm' in binding:
            p.require(result.get('warm', {}).get('status') == 'passed' and result['warm']['children'] >= 0,
                      'Invalid warm completion record')
            summary['warm'] = result['warm']
            from . import afl_capsule
            if afl_capsule.enabled(binding['afl_warm']):
                summary['afl_checkpoint'] = afl_capsule.verify_completion(binding, summary)
        summary.update(application_success="evaluated_separately_by_phase2", restart="live_post_retirement_fork" if "afl_warm" in binding else "new_original_elf_attempt")
    except Exception as exc:
        summary.update(status="failed", error=f"{type(exc).__name__}: {exc}"[-6000:])
        raise
    finally:
        p.write_json(run / "config/capsule_result.json", summary)
    return summary
