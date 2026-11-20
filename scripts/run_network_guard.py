#!/usr/bin/env python3
"""Stop the owned guest command if its network owner or responders fail."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

from taintforge_env.network_runtime import NetworkRuntimeClient, NetworkRuntimeError, _private_json


def run(runtime_path, command, *, result_path=None, capsule_binding=None):
    runtime = NetworkRuntimeClient(runtime_path)
    binding = None
    if capsule_binding is not None:
        from taintforge_env.network_capsule import verify_runtime
        binding = json.loads(capsule_binding.read_text())
        record = verify_runtime(binding, live=True, inside_namespace=True)
        if record['descriptor']['path'] != str(runtime_path) or binding['attempt_id'] != runtime.attempt_id:
            raise NetworkRuntimeError('capsule guard uses another network runtime')
    process = subprocess.Popen(command, start_new_session=True)
    reason = None
    runtime_error = None
    interrupted = []
    def stop(sig, frame):
        interrupted.append(sig)
    previous = {sig: signal.signal(sig, stop) for sig in (signal.SIGTERM, signal.SIGINT)}
    try:
        if result_path is not None:
            _private_json(Path(result_path), {"schema_version": 1, "attempt_id": runtime.attempt_id,
                "guest_pid": process.pid, "guest_process_stopped": False})
        while process.poll() is None:
            if interrupted:
                reason = "network_guard_cancelled"
                break
            try:
                status = runtime.call("status")
                reason = status["termination_reason"]
            except NetworkRuntimeError as exc:
                reason = "network_runtime_owner_lost"
                runtime_error = {"error": str(exc), "details": exc.details}
            if reason:
                break
            time.sleep(0.05)
        if reason and process.poll() is None:
            deadline = time.monotonic() + runtime.limits.shutdown_timeout_ms / 1000
            if binding is not None:
                from taintforge_env.network_capsule import request_cancel
                request_cancel(binding, reason, runtime_error=runtime_error)
                try:
                    process.wait(timeout=max(.01, (deadline - time.monotonic()) * .6))
                except subprocess.TimeoutExpired:
                    pass
            try:
                if process.poll() is None:
                    os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=max(0.01, (deadline - time.monotonic()) * 0.6))
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=max(0.01, deadline - time.monotonic()))
        result = process.wait()
        if reason is None:
            try:
                reason = runtime.call("status")["termination_reason"]
            except NetworkRuntimeError as exc:
                reason = "network_runtime_owner_lost"
                runtime_error = {"error": str(exc), "details": exc.details}
        if reason:
            # Stop the child before waiting for the ledger writer lock. A stale
            # pulse can close a runtime, but cannot authorize new work.
            runtime.fail(reason)
            try:
                reason = runtime.call("status")["termination_reason"] or reason
            except NetworkRuntimeError:
                pass
        if result_path is not None:
            record = {"schema_version": 1, "attempt_id": runtime.attempt_id,
                "termination_reason": reason, "guest_process_stopped": True,
                "command_exit_code": result}
            if runtime_error is not None:
                record["runtime_error"] = runtime_error
            _private_json(Path(result_path), record)
            identity = Path(runtime_path).stat()
            if os.geteuid() == 0:
                os.chown(result_path, identity.st_uid, identity.st_gid)
        return result if result >= 0 else 128 - result
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=2)
        for sig, handler in previous.items():
            signal.signal(sig, handler)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--result", type=Path)
    parser.add_argument("--capsule-binding", type=Path)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command:
        parser.error("a guest command is required")
    try:
        return run(args.runtime, command, result_path=args.result, capsule_binding=args.capsule_binding)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        print(f"network guard failed: {exc}", file=sys.stderr)
        return 125


if __name__ == "__main__":
    raise SystemExit(main())
