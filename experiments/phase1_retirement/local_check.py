"""Real-QEMU check on bundled benign ELFs only; no sandbox/cgroup acceptance.

Run with python3 -m experiments.phase1_retirement.local_check. Uses the real
permit worker, observer, export verifier and independent /proc mapping check.
The unified systemd/cgroup route is tested by run_phase1_retirement_e2e instead.
"""
import argparse
import json
import multiprocessing as mp
from pathlib import Path
import shutil
import subprocess
import tempfile
import uuid

from taintforge_env import execution_capsule as capsule, phase1_retirement as r
from taintforge_env.phase1_runtime import Phase1Run, Phase1Runtime


def run_case(out, built, qemu, runtime, trigger, case, fault, delay):
    out.mkdir()
    logs = out / "logs/capsule"
    (logs / "phase1-retirement").mkdir(parents=True)
    (out / "config").mkdir()
    # Keep the exact loaded module bytes inside the attempt for later packing.
    bundle = out / "config/analyzer_runtime"
    (bundle / "phase1").mkdir(parents=True)
    (bundle / "capsule").mkdir()
    plugin = bundle / "phase1" / runtime.plugin.name
    shutil.copyfile(runtime.plugin, plugin)
    shutil.copyfile(runtime.manifest, Path(str(plugin) + ".runtime.json"))
    shutil.copyfile(built["plugin"], bundle / "capsule/libcapsule_probe.so")
    runtime = Phase1Runtime.load(plugin)
    identity = dict(session_id="local-benign", attempt_id=out.name, analysis_instance_id="phase1",
                    attempt_contract_sha256=r.probe.sha(built["guest"]), bundle_sha256=runtime.plugin_sha256)
    settings = capsule.settings(case, hold_ms=50)
    settings["phase1_retirement"] = r.settings(fault, trigger=trigger, selection_delay=delay)
    binding = dict(identity, run_dir=str(out), rootfs="/", lifecycle_attempt=uuid.uuid4().hex,
                   retirement_evidence_schema=1,
                   settings=settings, capsule={"symbols": built["symbols"], "plugin": "capsule/libcapsule_probe.so"})
    analyzer = Phase1Run(runtime, identity["session_id"], identity["attempt_id"], "phase1", out / "phase1")
    r.probe.write_json(out / "config/phase1_binding.json",
        dict(identity, plugin="phase1/" + runtime.plugin.name, output_directory=str(analyzer.directory)))
    r.probe.write_json(out / "config/capsule_binding.json", binding)
    result = dict(identity, status="failed", trigger=trigger, case=case, fault=fault, delay=delay,
                  supervisor_kill=False, expected_qemu_exit=r.FAULTS[fault])
    ctx = mp.get_context("fork")
    workers, pipes = [], []
    process = None
    stage = "controllers"
    with tempfile.TemporaryDirectory(prefix="tf-verdict-") as ipc:
        try:
            pp, pc = ctx.Pipe()
            permit = ctx.Process(target=r.permit_worker, args=(Path(ipc) / "phase1.sock", pc, binding))
            permit.start(); pc.close()
            workers.append(permit); pipes.append(pp)
            r.probe.wait_worker_ready(pp, "permit")
            op, oc = ctx.Pipe()
            observer = ctx.Process(target=r.probe.control_worker,
                args=(str(Path(ipc) / "control.sock"), oc, str(logs), built["symbols"], case, 50, 30000),
                kwargs={"fd_path": str(out / "capsule-fd.txt"), "transition": r.Transition(binding)})
            observer.start(); oc.close()
            workers.append(observer); pipes.append(op)
            r.probe.wait_worker_ready(op, "observer")
            actual_delay = 100000000 if fault == "missing-verdict" else delay
            phase = analyzer.plugin_argument(extra=(f"tf-selection-delay={actual_delay}",))
            phase += "," + ",".join(r.plugin_options(binding, ipc, permit.pid))
            symbols = built["symbols"]
            observer_arg = ",".join([str(bundle / binding["capsule"]["plugin"]), "socket="+ipc+"/control.sock",
                "p1="+hex(symbols["capsule_point_one"]), "p2="+hex(symbols["capsule_point_two"]),
                "buffer="+hex(symbols["capsule_buffer"]), "pause-ms=5000", "total-ms=30000",
                "controller="+str(observer.pid)])
            plugins = [phase, observer_arg] if case == "phase1-first" else [observer_arg, phase]
            command = [str(qemu), "-strace"]
            for value in plugins:
                command += ["-plugin", value]
            command.append(built["guest"])
            result["command"] = command
            stage = "qemu_start"
            with (out / "logs/runtime_stdout.log").open("wb") as stdout, (out / "logs/qemu_strace.log").open("wb") as stderr:
                process = subprocess.Popen(command, cwd=out, stdout=stdout, stderr=stderr)
                result["qemu_pid"] = process.pid
                pp.send(process.pid); op.send(process.pid)
                stage = "qemu_wait"
                result["qemu_exit"] = process.wait(timeout=35)
            observer.join(4)
            r.probe.require(not observer.is_alive(), "Observer did not terminate")
            result["controller_exit"] = observer.exitcode
            permit.join(1)
            if fault != "missing-verdict":
                r.probe.require(not permit.is_alive() and permit.exitcode == 0, "Permit worker did not terminate")
            (logs / "capsule-fd.txt").write_bytes((out / "capsule-fd.txt").read_bytes())
            stage = "verification"
            result.update(r.verify_attempt(binding, result))
            result["check_passed"] = True
        except Exception as exc:
            result.update(error=f"{type(exc).__name__}: {exc}", check_passed=False,
                          failure=r.probe.execution_failure(exc, result, stage))
            result["controller_failures"] = r.probe.saved_worker_failures(logs)
        finally:
            if process is not None and process.poll() is None:
                process.kill(); process.wait(timeout=3)
                result["supervisor_kill"] = True
            for worker in workers:
                if worker.is_alive(): worker.terminate()
                worker.join(3)
            for pipe in pipes: pipe.close()
    r.probe.write_json(logs / "supervisor.json", result)
    r.probe.write_json(out / "result.json", result)
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
    args = parser.parse_args()
    qemu, out = args.qemu.resolve(strict=True), args.out.resolve()
    runtime = Phase1Runtime.load(args.plugin.resolve(strict=True))
    r.check_runtime(runtime, trigger="verdict")
    # The same version validation as the unified route, without launching a guest.
    r.probe.load_phase1(Path(__file__).resolve().parents[2], runtime.plugin, qemu)
    out.mkdir(parents=True, exist_ok=False)
    built = {trigger: r.build(out / ("build-"+trigger), trigger=trigger) for trigger in ("boundary", "verdict")}
    report = {"scope": "real_qemu_benign_fixture_without_unified_sandbox_or_cgroup", "cases": [],
              "qemu_sha256": r.probe.sha(qemu), "plugin_sha256": runtime.plugin_sha256,
              "sidecar_sha256": runtime.manifest_sha256, "claims": r.CLAIMS}
    scenarios = [("boundary", case, "none", 16) for case in ("phase1-first", "capsule-first")]
    scenarios += [("verdict", case, "none", delay) for delay in (16, 17, 64) for case in ("phase1-first", "capsule-first")]
    scenarios += [("verdict", "phase1-first", fault, 16) for fault in r.FAULTS if fault != "none"]
    for trigger, case, fault, delay in scenarios:
        name = f"{trigger}-{case}-{fault}-{delay}"
        result = run_case(out / name, built[trigger], qemu, runtime, trigger, case, fault, delay)
        report["cases"].append(result)
        print(name+": "+("passed" if result["check_passed"] else result["error"]), flush=True)
        r.probe.write_json(out / "report.json", report)
    verdicts = [x["phase1_retirement"]["verdict"] for x in report["cases"]
                if x["check_passed"] and x["trigger"] == "verdict" and x["fault"] == "none"]
    report["dynamic_trigger_verified"] = (len(verdicts) == 6 and
        len({v["decision_trace_seq"] for v in verdicts}) == 3 and len({v["continuation_pc"] for v in verdicts}) > 1)
    report["runtime_unchanged"] = (r.probe.sha(qemu) == report["qemu_sha256"] and
        r.probe.sha(runtime.plugin) == runtime.plugin_sha256 and r.probe.sha(runtime.manifest) == runtime.manifest_sha256)
    report["status"] = "passed" if report["runtime_unchanged"] and report["dynamic_trigger_verified"] and all(
        x["check_passed"] for x in report["cases"]) else "failed"
    r.probe.write_json(out / "report.json", report)
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
