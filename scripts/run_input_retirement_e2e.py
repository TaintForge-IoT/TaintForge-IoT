"""M3 acceptance with benign static i386 inputs."""
from __future__ import annotations
import argparse
from pathlib import Path
import traceback

from experiments.execution_capsule_probe import controller as p
from experiments.input_retirement.cases import CASES, build_guests
from scripts.run_unified_pipeline import parser as unified_parser, prepare, run_session
from taintforge_env.retirement_evidence import verify
from taintforge_env.phase1_runtime import read_json
from taintforge_env.synthesis_loop import EnvironmentSynthesisLoop

def verify_repair(runs):
    path = runs[1].parent / "repair_application.json"
    receipt = read_json(path)
    p.require(receipt["state"] == "completed" and receipt["dry_run"] is False and
              not receipt["error"] and not receipt["rollback_errors"], "Repair did not complete")
    for key, filename in (("plan", "repair_plan.json"), ("requirements", "runtime_requirements.json")):
        p.require(receipt[key + "_sha256"] == p.sha(runs[0].parent / "artifacts" / filename),
                  "Repair receipt differs from first-attempt artifacts")
    p.require(any(item["action"] == "create_directory" and item["status"] == "applied" and
                  item["target_path"] == str(Path(receipt["rootfs"]) / "var/lib/taintforge-m3")
                  for item in receipt["results"]),
              "Repair receipt has no applied directory creation")
    return {"path": str(path), "sha256": p.sha(path), "application_id": receipt["application_id"]}


def validate_case(name, out, report, code, entry=None):
    expected = CASES[name]
    status, exits = int(expected["stdout"] is None), expected["exits"]
    p.require(code == status, "Unexpected unified command outcome")
    runs = sorted((out / "session/iterations").glob("*/run"))
    p.require(len(runs) == len(exits), "Unexpected number of fresh attempts")
    summaries = []
    for run, expected_exit in zip(runs, exits):
        binding = read_json(run / "config/capsule_binding.json")
        execution = read_json(run / "config/prebuilt_execution.json")
        supervisor = read_json(run / "logs/capsule/supervisor.json")
        service = read_json(run / "logs/capsule/service.json")
        claim_path = run.parent / "execution_attempt.json"
        claim = read_json(claim_path)
        p.require(execution["guest_exit_code"] == supervisor["qemu_exit"] == expected_exit and
                  supervisor["supervisor_kill"] is False and service["tree_empty"] is True,
                  "Unexpected exit, fallback kill or incomplete process cleanup")
        p.require(claim["attempt_id"] == binding["attempt_id"] and
                  claim["attempt_contract_sha256"] == binding["attempt_contract_sha256"] and
                  claim["guest_exit_code"] == expected_exit and claim["malware_started"] is True and
                  claim["retry_safe"] is False and claim["stage"] == ("completed" if status == 0 else "failed"),
                  "Execution claim does not match the finalized attempt")
        summary = {"attempt_id":binding["attempt_id"],"nonce":binding["lifecycle_attempt"],
            "analysis_instance_id":binding["analysis_instance_id"],
            "attempt_contract_sha256":binding["attempt_contract_sha256"],
            "input_sha256":binding["input_retirement"]["sha256"], "qemu_exit":expected_exit,
            "run_dir":str(run), "supervisor_kill":False, "tree_empty":True,
            "execution_claim_sha256":p.sha(claim_path),
            "environment_manifest_version":claim["environment_manifest_version"]}
        if entry is not None:
            p.require(binding["input_retirement"] == entry["input"] and
                      p.sha(run / "guest-i386") == entry["input"]["sha256"], "Staged test input changed")
        if status == 0:
            capsule = read_json(run / "config/capsule_result.json")
            p.require(capsule["status"] == "passed" and capsule["phase1_retirement"]["phase1_retired"],
                      "Retirement was not independently finalized")
            digest = capsule["portable_evidence"]["manifest_sha256"]
            summary["portable_evidence"] = verify(run / "retirement-evidence",expected_sha256=digest)
            summary["bundle_sha256"] = digest
            if entry is not None:
                journal = read_json(run / "logs/capsule/phase1-retirement/retirement.json")
                selected = journal["events"][0]["data"]["oep"]
                p.require(selected == entry["expected_oep"], "Selected candidate differs from the test oracle")
                summary["observed_oep"] = selected
                stdout = (run / "logs/runtime_stdout.log").read_text()
                p.require(stdout == (entry["expected_stdout"] if expected_exit == 0 else ""),
                          "Unexpected benign guest output")
        summaries.append(summary)
    if status == 0:
        p.require(report["outcome"] == "completed" and report["stop_reason"] == "goal_reached",
                  "The benign application goal was not reached")
        EnvironmentSynthesisLoop.verify_session(out / "session")
    else:
        p.require(report["outcome"] == "intervention_required" and report["capsule"]["status"] == "failed",
                  "Invalid retirement must not finalize successfully")
        diagnostic = (runs[0]/"logs/qemu_strace.log").read_text(errors="replace")
        needle = "CAPSULE_PHASE1_ABORT code=89 " if name=="missing-verdict" else "OBSERVER_ABORT code=126 "
        p.require(needle in diagnostic, "Missing native refusal diagnosis")
        p.write_json(out / "initial_unified_report.json", report)
        resumed, resumed_code = run_session(out,read_json(out/"unified_launch.json"),max_steps=1)
        p.write_json(out / "resume_report.json", resumed)
        p.require(resumed_code == 1 and resumed["executions_this_invocation"] == 0,
                  "Refused attempt was improperly resumed")
        p.require(sorted((out / "session/iterations").glob("*/run")) == runs and
                  p.sha(runs[0].parent / "execution_attempt.json") == summaries[0]["execution_claim_sha256"],
                  "Resume changed the refused attempt")
    if name == "repair":
        for key in ("attempt_id","nonce","analysis_instance_id","attempt_contract_sha256"):
            p.require(summaries[0][key] != summaries[1][key], "Repaired attempt reused " + key)
        p.require(summaries[0]["input_sha256"] == summaries[1]["input_sha256"], "Restart changed original input")
        second = read_json(runs[1]/"config/capsule_binding.json")
        p.require((Path(second["rootfs"])/"var/lib/taintforge-m3").is_dir(), "Directory repair absent")
        p.require(summaries[1]["environment_manifest_version"] > summaries[0]["environment_manifest_version"],
                  "Repair did not advance the environment manifest")
        summaries[1]["repair_application"] = verify_repair(runs)
    return summaries


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--qemu",required=True,type=Path)
    parser.add_argument("--plugin",required=True,type=Path)
    parser.add_argument("--out",required=True,type=Path)
    parser.add_argument('--hardening',action='store_true')
    args=parser.parse_args()
    out=args.out.resolve();out.mkdir(parents=True,exist_ok=False)
    guests=build_guests(out/"inputs")
    report={"schema":1,"matrix_version":2,"profile":"input-static-i386-retirement-m3","status":"failed","acceptance_complete":False,
            "scope":"benign_static_i386_unified_systemd","qemu_sha256":p.sha(args.qemu),
            "phase1_sha256":p.sha(args.plugin),"cases":[],"hostile_sample_ready":False,
            "input_build_sha256":p.sha(out/"inputs/build.json")}
    report['m4_hardening'] = args.hardening
    for name, entry in guests.items():
        case_out=out/name
        case={"name":name,"status":"failed","input":entry}
        try:
            goal=out/(name+"-goal.json")
            p.write_json(goal,dict(schema_version=1,goal_id="m3-input-complete",description="Benign M3 input completion",
                mode="all",rules=[dict(id="stdout",type="text_contains",source="stdout",
                                      needle=entry["expected_stdout"] or "M3_INPUT_OK\n",min_count=1)]))
            argv=["run","--retire-phase1","--binary",entry["path"],
                "--qemu",str(args.qemu),"--plugin",str(args.plugin),"--out",str(case_out),
                "--target-spec",str(goal),"--max-iterations","3","--max-steps","2",
                "--retirement-max-insns","2048" if name=="missing-verdict" else "10000000"]
            if args.hardening:argv.append('--capsule-hardening')
            options=unified_parser().parse_args(argv)
            launch=prepare(options)
            result,code=run_session(case_out,launch,max_steps=2)
            case["attempts"]=validate_case(name,case_out,result,code,entry)
            case.update(status="passed",expected_refusal=name in {"missing-verdict","fork-after"})
        except Exception as exc:
            case.update(error=f"{type(exc).__name__}: {exc}",traceback=traceback.format_exc())
        report["cases"].append(case)
        p.write_json(out/"report.json",report)
        print(name+": "+case["status"],flush=True)
        if case["status"] != "passed":break
    report["runtime_unchanged"]=(p.sha(args.qemu)==report["qemu_sha256"] and p.sha(args.plugin)==report["phase1_sha256"])
    report["acceptance_complete"]=(len(report["cases"])==len(CASES) and all(x["status"]=="passed" for x in report["cases"])
                                   and report["runtime_unchanged"])
    report["status"]="passed" if report["acceptance_complete"] else "failed"
    p.write_json(out/"report.json",report);print(out/"report.json")
    return 0 if report["acceptance_complete"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
