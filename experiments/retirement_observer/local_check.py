"""M2 acceptance on built benign stripped ELFs; no generic --binary or sandbox."""
from __future__ import annotations
import argparse
import multiprocessing as mp
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import uuid

from experiments.retirement_observer import controller as c
from taintforge_env import phase1_retirement as r
from taintforge_env.phase1_runtime import Phase1Run, Phase1Runtime


class QemuLoadError(r.probe.ProbeError):
    """QEMU started but rejected the guest before its execution."""


def stage_guest(source, destination, expected_sha256):
    """Copy verified fixture bytes with mode 0700."""
    source, destination = Path(source), Path(destination)
    r.probe.require(not source.is_symlink() and stat.S_ISREG(source.stat().st_mode),
                    "Guest fixture must be a regular file")
    with source.open("rb") as src, destination.open("xb") as dst:
        shutil.copyfileobj(src, dst)
    destination.chmod(0o700)
    r.probe.require(stat.S_IMODE(destination.stat().st_mode) == 0o700 and
                    r.probe.sha(destination) == expected_sha256,
                    "Staged guest permissions or bytes differ from the fixture")
    return destination


def runtime_diagnostics(out, limit=4096):
    result = {}
    for key, filename in (("stdout_tail", "runtime_stdout.log"), ("stderr_tail", "qemu_strace.log")):
        path = Path(out) / "logs" / filename
        try:
            with path.open("rb") as stream:
                stream.seek(0, 2)
                stream.seek(max(0, stream.tell() - limit))
                result[key] = stream.read(limit).decode("utf-8", errors="replace")
        except FileNotFoundError:
            result[key] = ""
    return result


def check_qemu_exit(code, allowed, diagnostic):
    if code in allowed:
        return
    detail = "\n".join(value.strip() for value in diagnostic.values() if value.strip())
    error_type = QemuLoadError if "Error while loading " in detail else r.probe.ProbeError
    raise error_type(f"QEMU exited with code {code}: {detail or 'no stdout/stderr diagnostic'}")


def run_case(out, built, qemu, runtime, order, variant, delay, fault="none", after_release_delay_ms=0):
    out.mkdir()
    logs = out / "logs/capsule"
    (logs / "phase1-retirement").mkdir(parents=True)
    bundle = out / "config/analyzer_runtime"
    (bundle / "phase1").mkdir(parents=True)
    (bundle / "observer").mkdir()
    plugin = bundle / "phase1" / runtime.plugin.name
    shutil.copyfile(runtime.plugin, plugin)
    shutil.copyfile(runtime.manifest, Path(str(plugin)+".runtime.json"))
    shutil.copyfile(built["plugin"], bundle / "observer/plugin.so")
    guest = stage_guest(built["guests"][variant]["path"], out / "guest-i386",
                        built["guests"][variant]["sha256"])
    runtime = Phase1Runtime.load(plugin)
    config = dict(profile=c.PROFILE, protocol=c.PROTOCOL, pc_source=c.PC_SOURCE,
                  fault=fault, variant=variant, plugin_order=order,
                  hold_ms=20, pause_ms=5000, total_ms=30000, after_release_delay_ms=after_release_delay_ms,
                  guest_sha256=r.probe.sha(guest), stripped=True)
    contract = out / "config/observer-contract.json"
    r.probe.write_json(contract, config | {"selection_delay": delay, "phase1_sha256": runtime.plugin_sha256,
                                         "observer_sha256": built["plugin_sha256"]})
    identity = dict(session_id="m2-benign", attempt_id=out.name, analysis_instance_id="phase1",
                    attempt_contract_sha256=r.probe.sha(contract), bundle_sha256=runtime.plugin_sha256)
    binding = dict(identity, run_dir=str(out), rootfs="/", lifecycle_attempt=uuid.uuid4().hex,
                   retirement_evidence_schema=1, observer=config,
                   settings=dict(total_ms=30000, phase1_retirement=r.settings(trigger="verdict", selection_delay=delay)),
                   capsule=dict(symbols={"phase1_payload_entry": built["guests"][variant]["expected_oep"]},
                                plugin="observer/plugin.so"))
    analyzer = Phase1Run(runtime, identity["session_id"], identity["attempt_id"], "phase1", out / "phase1")
    r.probe.write_json(out / "config/phase1_binding.json", dict(identity, plugin="phase1/"+plugin.name,
                       output_directory=str(analyzer.directory)))
    r.probe.write_json(out / "config/capsule_binding.json", binding)
    result = dict(identity, status="failed", check_passed=False, observer=config, selection_delay=delay,
                  supervisor_kill=False, expected_qemu_exit=c.FAULTS[fault], scope="benign_local_no_cgroup")
    ctx = mp.get_context("spawn")
    workers, pipes = [], []
    process = None
    stage = "controllers"
    with tempfile.TemporaryDirectory(prefix="tf-m2-") as ipc:
        try:
            permit_gate, observer_gate = ctx.Pipe()
            pipes.extend([permit_gate, observer_gate])
            pp, pc = ctx.Pipe()
            pipes.extend([pp, pc])
            permit = ctx.Process(target=r.permit_worker, args=(Path(ipc)/"phase1.sock", pc, binding),
                                 kwargs={"progress_pipe": permit_gate})
            permit.start(); pc.close(); permit_gate.close()
            workers.append(permit)
            r.probe.wait_worker_ready(pp, "permit")
            op, oc = ctx.Pipe()
            pipes.extend([op, oc])
            observer = ctx.Process(target=c.control_worker,
                args=(Path(ipc)/"observer.sock", oc, observer_gate, binding))
            observer.start(); oc.close(); observer_gate.close()
            workers.append(observer)
            r.probe.wait_worker_ready(op, "observer")
            phase = analyzer.plugin_argument(extra=(f"tf-selection-delay={delay}",))
            phase += "," + ",".join(r.plugin_options(binding, ipc, permit.pid))
            observer_arg = ",".join([str(bundle / "observer/plugin.so"), "socket="+ipc+"/observer.sock",
                           "pause-ms=5000", "total-ms=30000", "controller="+str(observer.pid)])
            plugins = [phase, observer_arg] if order == "phase1-first" else [observer_arg, phase]
            command = [str(qemu), "-strace"]
            for value in plugins: command += ["-plugin", value]
            command.append(str(guest))
            result["command"] = command
            stage = "qemu_start"
            with (out / "logs/runtime_stdout.log").open("wb") as stdout, (out / "logs/qemu_strace.log").open("wb") as stderr:
                process = subprocess.Popen(command, cwd=out, stdout=stdout, stderr=stderr)
                result["qemu_pid"] = process.pid
                pp.send(process.pid); op.send(process.pid)
                stage = "qemu_wait"
                result["qemu_exit"] = process.wait(timeout=35)
            # Preserve QEMU startup errors before checking its waiting workers.
            result["qemu_diagnostics"] = runtime_diagnostics(out)
            check_qemu_exit(result["qemu_exit"], {0, 123} if fault == "none" else {c.FAULTS[fault]},
                            result["qemu_diagnostics"])
            observer.join(4)
            r.probe.require(not observer.is_alive(), "Observer controller did not finish")
            result["controller_exit"] = observer.exitcode
            permit.join(1)
            if fault.endswith("-before"):
                # It was never connected: bootstrap abort preceded any verdict.
                if permit.is_alive(): permit.terminate(); permit.join(3)
            else:
                r.probe.require(not permit.is_alive() and permit.exitcode == 0, "Permit worker did not finish")
            fd = out / "capsule-fd.txt"
            (logs / "capsule-fd.txt").write_bytes(fd.read_bytes() if fd.exists() else b"")
            stage = "verification"
            result.update(c.verify_attempt(binding, result))
            expected = {"aborted"} if fault != "none" else {"passed", "inconclusive"} if variant == "short" else {"passed"}
            if variant == "short" and after_release_delay_ms:
                expected = {"inconclusive"}
            r.probe.require(result["status"] in expected, "Scenario did not reach its required outcome")
            result["check_passed"] = True
        except Exception as exc:
            result.update(check_passed=False, error=f"{type(exc).__name__}: {exc}",
                          failure=r.probe.execution_failure(exc, result, stage),
                          controller_failures=r.probe.saved_worker_failures(logs))
            if isinstance(exc, QemuLoadError):
                result["failure"].update(category="startup_failure", component="qemu", stage="guest_load")
        finally:
            if process is not None and process.poll() is None:
                process.kill(); process.wait(timeout=3); result["supervisor_kill"] = True
            for worker in workers:
                if worker.is_alive(): worker.terminate()
                worker.join(3)
            for pipe in pipes: pipe.close()
            result["qemu_diagnostics"] = runtime_diagnostics(out)
            result["controller_failures"] = r.probe.saved_worker_failures(logs)
    r.probe.write_json(logs / "supervisor.json", result)
    if result["check_passed"]:
        from taintforge_env.retirement_evidence import pack
        try:
            result["portable_evidence"] = pack(out, out / "retirement-evidence")
        except Exception as exc:
            result.update(check_passed=False, error=f"{type(exc).__name__}: {exc}",
                          failure=r.probe.execution_failure(exc, result, "verification"))
    r.probe.write_json(out / "result.json", result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--qemu", type=Path, required=True)
    parser.add_argument("--plugin", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--startup-probe", action="store_true", help="Run just the first real case; report failures honestly")
    parser.add_argument("--fail-fast", action="store_true", help="Stop at the first unexpected case failure")
    args = parser.parse_args()
    qemu, out = args.qemu.resolve(strict=True), args.out.resolve()
    runtime = Phase1Runtime.load(args.plugin.resolve(strict=True))
    r.check_runtime(runtime, trigger="verdict")
    r.probe.load_phase1(Path(__file__).resolve().parents[2], runtime.plugin, qemu)
    out.mkdir(parents=True, exist_ok=False)
    built = c.build(out / "build")
    report = dict(schema=2, profile=c.PROFILE, scope="benign_local_no_cgroup", cases=[],
                  claims=r.CLAIMS, qemu_sha256=r.probe.sha(qemu), plugin_sha256=runtime.plugin_sha256,
                  sidecar_sha256=runtime.manifest_sha256, build=built)
    scenarios = [(order, variant, delay, "none", 0) for order in ("phase1-first", "observer-first")
                 for variant in ("long", "relocated") for delay in (16, 17, 64)]
    scenarios += [(order, "long", 16, fault, 0) for order in ("phase1-first", "observer-first")
                  for fault in c.FAULTS if fault != "none"]
    scenarios += [(order, "short", 16, "none", delay) for order in ("phase1-first", "observer-first")
                  for delay in (0, 500)]
    scenarios += [(order, "long", 16, "none", 100) for order in ("phase1-first", "observer-first")]
    if args.startup_probe: scenarios = scenarios[:1]
    for order, variant, delay, fault, lag in scenarios:
        name = f"{order}-{variant}-{delay}-{fault}-lag{lag}"
        result = run_case(out / name, built, qemu, runtime, order, variant, delay, fault, lag)
        report["cases"].append(result)
        print(name + ": " + (result["status"] if result["check_passed"] else result.get("error", "failed")), flush=True)
        r.probe.write_json(out / "report.json", report)
        if result.get("failure", {}).get("category") == "startup_failure":
            report["stopped_after_startup_failure"] = True
            break
        if args.fail_fast and not result["check_passed"]:
            report["stopped_after_failed_case"] = name
            break
    report["runtime_unchanged"] = (r.probe.sha(qemu) == report["qemu_sha256"] and
        r.probe.sha(runtime.plugin) == runtime.plugin_sha256 and r.probe.sha(runtime.manifest) == runtime.manifest_sha256)
    report["status"] = "passed" if report["runtime_unchanged"] and len(report["cases"]) == len(scenarios) and all(
        x["check_passed"] for x in report["cases"]) else "failed"
    report["acceptance_complete"] = report["status"] == "passed" and not args.startup_probe
    r.probe.write_json(out / "report.json", report)
    print(out / "report.json")
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
