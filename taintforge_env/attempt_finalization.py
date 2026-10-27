"""Phase 2 journal of independent work after the sandbox wrapper has stopped."""
from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
from datetime import datetime, timezone


def write_json(path: Path, value: dict) -> None:
    """Publish a complete private document; leave the previous version on error."""
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(value, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def error_text(exc: Exception) -> str:
    return f"{type(exc).__name__}: {exc}"[-6000:]


class AttemptFinalization:
    """Record failures without preventing collection of independent evidence.

    A completed step means its operation finished, not that the guest succeeded
    or Phase 1 proved an OEP. Those conclusions live in their own artifacts.
    """

    def __init__(self, context):
        self.path = context.run_dir / "config/finalization_status.json"
        self.value = {
            "schema_version": 1, "attempt_id": context.attempt_contract.attempt_id,
            "attempt_contract_sha256": context.attempt_contract.contract_sha256,
            "guest_stop_confirmed": True, "status": "running",
            "stages": {name: {"status": "pending"} for name in (
                "execution", "network_cleanup", "filesystem", "phase1", "syscalls",
                "requirements", "repair_plan",
            )},
        }
        self.errors: list[str] = []

    def update(self, name: str, status: str, **details) -> None:
        self.value["stages"][name] = {"status": status, **details}
        self.save()

    def save(self) -> None:
        self.value["updated_at_utc"] = datetime.now(timezone.utc).isoformat()
        write_json(self.path, self.value)

    def run(self, name: str, operation):
        self.update(name, "running")
        try:
            result = operation()
        except Exception as exc:
            self.fail(name, exc)
            return None
        self.update(name, "completed")
        return result

    def fail(self, name: str, exc: Exception) -> None:
        error = error_text(exc)
        self.errors.append(f"{name}: {error}")
        self.value["status"] = "failed"
        self.update(name, "failed", error=error)

    def completed(self, name: str) -> bool:
        return self.value["stages"][name]["status"] == "completed"

    def finish(self) -> None:
        self.value["status"] = "failed" if self.errors else "completed"
        self.save()


def write_failure_report(run_dir: Path, finalization: AttemptFinalization) -> None:
    """Small fallback if the full report generator itself fails; never read logs."""
    report = {"schema_version": 1, "report_status": "diagnostic_only",
              "finalization": finalization.value, "fuzzing_ready": False}
    for key, filename in (("execution", "prebuilt_execution.json"), ("phase1", "phase1_result.json")):
        try:
            report[key] = json.loads((run_dir / "config" / filename).read_text())
        except (OSError, ValueError) as exc:
            report[key] = {"status": "unavailable", "error": error_text(exc)}
    write_json(run_dir / "report.json", report)
    (run_dir / "report.md").write_text(
        "# Attempt diagnostics\n\nThe full report could not be generated. "
        "See report.json and config/finalization_status.json for saved results.\n\n"
        + "\n".join(f"- {error}" for error in finalization.errors) + "\n", encoding="utf-8")
