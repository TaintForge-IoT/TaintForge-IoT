"""Collect bounded M3 acceptance evidence, including failed runs."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import tarfile
import tempfile

from experiments.execution_capsule_probe import controller as p
from experiments.input_retirement.cases import CASES
from scripts.run_input_retirement_tests import MODULES
from taintforge_env.phase1_runtime import read_json
from taintforge_env.retirement_evidence import verify

MAX_FILES = 4096
MAX_FILE = 256 * 1024**2
MAX_TOTAL = 512 * 1024**2
PATTERNS = (
    "validation/*", "e2e/*.json", "e2e/inputs/*", "e2e/*/*.json",
    "e2e/*/session/*.json", "e2e/*/session/*.jsonl",
    "e2e/*/session/attempts/**/*.json", "e2e/*/session/manifests/**/*.json",
    "e2e/*/session/iterations/*/*.json", "e2e/*/session/iterations/*/run/guest-i386",
    "e2e/*/session/iterations/*/run/config/*.json",
    "e2e/*/session/iterations/*/run/config/analyzer_runtime/bundle.json",
    "e2e/*/session/iterations/*/run/config/analyzer_runtime/plugin/*",
    "e2e/*/session/iterations/*/run/config/analyzer_runtime/capsule/*",
    "e2e/*/session/iterations/*/run/logs/**/*",
    "e2e/*/session/iterations/*/run/retirement-evidence/**/*",
    "e2e/*/session/iterations/*/artifacts/runtime_requirements.json",
    "e2e/*/session/iterations/*/artifacts/repair_plan.json",
)


def required_paths():
    required = {"validation/preflight.log", "validation/build.log", "validation/tests.log",
                "validation/tests.json", "validation/e2e.log", "e2e/report.json", "e2e/inputs/build.json"}
    for name, case in CASES.items():
        base = "e2e/" + name
        required.update({"e2e/inputs/" + name, base + "/unified_report.json", base + "/unified_launch.json"})
        for index in range(len(case["exits"])):
            iteration = f"{base}/session/iterations/{index:04d}"
            required.add(iteration + "/execution_attempt.json")
            for tail in ("guest-i386", "config/input-attempt.json", "config/observer-contract.json",
                         "config/capsule_binding.json", "config/phase1_binding.json", "config/capsule_result.json",
                         "config/prebuilt_execution.json", "config/analyzer_runtime/bundle.json",
                         "logs/runtime_stdout.log", "logs/qemu_strace.log", "logs/capsule/service.json",
                         "logs/capsule/resources.json", "logs/capsule/supervisor.json"):
                required.add(iteration + "/run/" + tail)
            if case["stdout"] is not None:
                required.add(iteration + "/run/retirement-evidence/bundle.json")
        if case["stdout"] is None:
            required.update({base + "/initial_unified_report.json", base + "/resume_report.json"})
    required.update({"e2e/repair/session/iterations/0001/repair_application.json",
                     "e2e/repair/session/iterations/0000/artifacts/repair_plan.json",
                     "e2e/repair/session/iterations/0000/artifacts/runtime_requirements.json"})
    return required


def regular(root, path):
    p.require(path.is_relative_to(root), "Evidence path escapes output")
    for part in (path, *path.parents):
        if part == root:
            break
        p.require(not part.is_symlink(), "Symlink in acceptance evidence: " + str(part))
    info = path.lstat()
    p.require(stat.S_ISREG(info.st_mode) and info.st_size <= MAX_FILE, "Invalid evidence file: " + str(path))
    return info


def check_results(root):
    tests = read_json(root / "validation/tests.json")
    report = read_json(root / "e2e/report.json")
    p.require(tests["modules"] == list(MODULES) and tests["successful"] is True and
              tests["tests_run"] == tests["tests_expected"] and tests["tests_run"] >= 98 and
              all(tests[k] == 0 for k in ("failures", "errors", "skipped", "unexpected_successes")),
              "Full regression suite did not pass without skips")
    p.require(report["matrix_version"] == 2 and report["status"] == "passed" and
              report["acceptance_complete"] is True and report["runtime_unchanged"] is True and
              [case["name"] for case in report["cases"]] == list(CASES) and
              all(case["status"] == "passed" for case in report["cases"]), "M3 matrix is incomplete")
    p.require(report["input_build_sha256"] == p.sha(root / "e2e/inputs/build.json"), "Input build record changed")
    for case in report["cases"]:
        base = root / "e2e" / case["name"]
        expected = CASES[case["name"]]
        p.require(len(case["attempts"]) == len(expected["exits"]), "Attempt count changed")
        for index, summary in enumerate(case["attempts"]):
            iteration = base / "session/iterations" / f"{index:04d}"
            claim_path = iteration / "execution_attempt.json"
            claim = read_json(claim_path)
            p.require(p.sha(claim_path) == summary["execution_claim_sha256"] and
                      claim["guest_exit_code"] == expected["exits"][index] and
                      claim["attempt_id"] == summary["attempt_id"] and claim["retry_safe"] is False,
                      "Saved execution claim changed")
            if expected["stdout"] is not None:
                checked = verify(iteration / "run/retirement-evidence", expected_sha256=summary["bundle_sha256"])
                p.require(checked["attempt_outcome"] == "passed", "Portable evidence did not pass")
        if expected["stdout"] is None:
            initial = read_json(base / "initial_unified_report.json")
            resumed = read_json(base / "resume_report.json")
            p.require(initial["capsule"]["status"] == "failed" and
                      resumed["outcome"] == "intervention_required" and
                      resumed["executions_this_invocation"] == 0, "Refused attempt was resumed")
    from scripts.run_input_retirement_e2e import verify_repair
    runs = [root / f"e2e/repair/session/iterations/{i:04d}/run" for i in range(2)]
    receipt = verify_repair(runs)
    repair = next(case for case in report["cases"] if case["name"] == "repair")
    p.require(receipt["sha256"] == repair["attempts"][1]["repair_application"]["sha256"], "Repair receipt changed")


def collect(root, exit_code, *, patterns=PATTERNS, required=None, checker=check_results, kind='m3-acceptance'):
    root = Path(root).resolve(strict=True)
    destination = root / "acceptance.tar.gz"
    checksum = root / "acceptance.tar.gz.sha256"
    p.require(not any(path.exists() or path.is_symlink() for path in (destination, checksum)),
              "Acceptance archive already exists")
    candidates = set()
    for pattern in patterns:
        for path in root.glob(pattern):
            p.require(not path.is_symlink(), "Symlink in acceptance evidence: " + str(path))
            if not path.is_dir():
                candidates.add(path)
    p.require(len(candidates) <= MAX_FILES, "Too many evidence files")
    inventory, total = [], 0
    with tempfile.TemporaryDirectory(prefix=".acceptance-", dir=root) as temporary:
        stage = Path(temporary) / "evidence"
        stage.mkdir()
        for source in sorted(candidates):
            info = regular(root, source)
            total += info.st_size
            p.require(total <= MAX_TOTAL, "Acceptance evidence exceeds its byte budget")
            name = source.relative_to(root).as_posix()
            target = stage / name
            target.parent.mkdir(parents=True, exist_ok=True)
            digest = hashlib.sha256()
            with source.open("rb") as src, target.open("xb") as dst:
                p.require(os.fstat(src.fileno()) == info, "Evidence changed before collection: " + name)
                left = info.st_size
                while left:
                    data = src.read(min(left, 1024**2))
                    p.require(data, "Evidence truncated during collection: " + name)
                    left -= len(data)
                    digest.update(data)
                    dst.write(data)
                p.require(not src.read(1), "Evidence grew during collection: " + name)
            p.require(regular(root, source).st_mtime_ns == info.st_mtime_ns and
                      p.sha(source) == digest.hexdigest(), "Evidence changed during collection: " + name)
            inventory.append(dict(path=name, size=info.st_size, sha256=digest.hexdigest()))
        needed = required_paths() if required is None else required
        missing = sorted(needed - {item["path"] for item in inventory})
        error = None
        try:
            checker(stage)
        except Exception as exc:
            error = f"{type(exc).__name__}: {exc}"
        manifest = dict(schema=1, kind=kind, matrix_version=2,
            scope="selected_evidence_not_a_full_session_backup", authenticity="not_asserted",
            command_exit_code=exit_code, complete=exit_code == 0 and not missing and error is None,
            missing_required=missing, result_error=error, files=inventory, total_bytes=total)
        p.write_json(stage / "collection.json", manifest)
        archive = Path(temporary) / "acceptance.tar.gz"
        with tarfile.open(archive, "w:gz") as stream:
            for name in ["collection.json", *(item["path"] for item in inventory)]:
                stream.add(stage / name, arcname="evidence/" + name, recursive=False)
        digest = p.sha(archive)
        os.link(archive, destination)
        with checksum.open("x") as stream:
            stream.write(digest + "  acceptance.tar.gz\n")
    return dict(archive=str(destination), sha256=digest, complete=manifest["complete"],
                files=len(inventory), missing_required=missing, result_error=error)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--exit-code", type=int, required=True)
    args = parser.parse_args()
    result = collect(args.out, args.exit_code)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["complete"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
