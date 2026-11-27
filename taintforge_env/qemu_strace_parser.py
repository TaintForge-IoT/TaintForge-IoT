from __future__ import annotations

import json
import os
import re
import tempfile
from dataclasses import asdict
from pathlib import Path
from typing import Any

from .guest_paths import GuestPaths
from .log_io import LogReadError, MAX_LOG_LINE_BYTES, iter_log_lines
from .syscall_result import parse_result
from .network_endpoints import CAPTURED, EndpointCapture, EndpointCaptureError, SocketTraceTracker, printed_endpoint

from .strace_parser import (
    StraceParserError,
    SYSCALL_RE,
    build_summary,
    parse_strace_line,
)


class QemuStraceParserError(RuntimeError):
    """Raised when QEMU user-mode syscall output cannot be normalized."""


def parse_qemu_strace(
    input_path: str | Path,
    out_path: str | Path,
    *,
    target_arch: str,
    endpoint_events: str | Path | None = None,
    session_id: str | None = None,
    attempt_id: str | None = None,
    initial_guest_cwd: str | None = None,
) -> dict[str, Any]:
    source = Path(input_path)
    destination = Path(out_path)
    if source.is_symlink() or not source.is_file():
        raise QemuStraceParserError(
            f"QEMU strace input does not exist: {source}"
        )

    destination.parent.mkdir(parents=True, exist_ok=True)
    summary_path = destination.with_suffix(".summary.json")
    for path in (destination, summary_path):
        if path.is_symlink() or (path.exists() and not path.is_file()):
            raise QemuStraceParserError(f"QEMU output must be a regular file: {path}")
        if path.resolve() == source.resolve() or (path.exists() and path.samefile(source)):
            raise QemuStraceParserError(f"QEMU output would replace its input: {path}")
    if destination == summary_path:
        raise QemuStraceParserError("QEMU event and summary outputs must be distinct")

    capture = None
    def parsed_lines():
        state = SocketTraceTracker(target_arch=target_arch)
        for number, raw in enumerate(iter_log_lines(source), 1):
            line = raw.strip()
            if not line or "<unfinished ...>" in line or ("<... " in line and " resumed>" in line):
                if line:
                    state.reset()
                continue
            event = parse_strace_line(line, source.name, number, "guest")
            if event is not None:
                # QEMU's legacy socketcall printer uses uppercase operation names.
                if event.syscall.lower() in CAPTURED:
                    event.syscall = event.syscall.lower()
                    event.category = "network"
                    event.remote_ip, event.remote_port = printed_endpoint(event.syscall, event.args)
                state.apply(event)
                yield event
    if endpoint_events is not None:
        if not session_id or not attempt_id:
            raise QemuStraceParserError("endpoint events require session_id and attempt_id")
        try:
            capture = EndpointCapture(Path(endpoint_events), session_id=session_id,
                                      attempt_id=attempt_id, target_arch=target_arch)
            capture.correlate(parsed_lines())
        except (EndpointCaptureError, LogReadError, OSError) as error:
            raise QemuStraceParserError(str(error)) from error

    statistics = {"lines_total": 0, "ignored_lines": 0, "skipped_unfinished_lines": 0,
                  "max_line_bytes": MAX_LOG_LINE_BYTES}
    locations = GuestPaths(initial_guest_cwd)
    temporary_paths = []
    try:
        sockets = SocketTraceTracker(target_arch=target_arch)
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=destination.parent,
                                         prefix=f".{destination.name}.", delete=False) as stream:
            temporary_paths.append(Path(stream.name))

            def events():
                for line_number, raw_line in enumerate(iter_log_lines(source), start=1):
                    statistics["lines_total"] = line_number
                    line = raw_line.strip()
                    if "<unfinished ...>" in line or ("<... " in line and " resumed>" in line):
                        locations.lose_context()
                        statistics["skipped_unfinished_lines"] += 1
                        sockets.reset()
                        continue
                    event = parse_strace_line(line, source.name, line_number, "guest") if line else None
                    if event is None:
                        ended = re.match(r"^(\d{1,10}) (?:exit|exit_group)\(-?\d+\)$", line)
                        if ended:
                            locations.exit(int(ended[1]))
                        elif re.match(r"^\d+ (?:[a-z_]+\(|Unknown syscall)", line):
                            locations.lose_context()
                        statistics["ignored_lines"] += 1
                        continue
                    if event.syscall.lower() in CAPTURED:
                        event.syscall = event.syscall.lower()
                        event.category = "network"
                        event.remote_ip, event.remote_port = printed_endpoint(event.syscall, event.args)
                    sockets.apply(event)
                    if capture is not None:
                        capture.enrich(event)
                    locations.observe(event)
                    payload = asdict(event)
                    payload.update(trace_backend="qemu_strace", target_arch=target_arch)
                    stream.write(json.dumps(payload, ensure_ascii=False) + "\n")
                    yield event

            summary = build_summary(events())
            summary.update(trace_backend="qemu_strace", target_arch=target_arch,
                           source_file=source.name, input_statistics=statistics)
            summary["network_endpoint_observer"] = capture.status if capture is not None else {"status": "not_configured", "matched": 0}
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=destination.parent,
                                         prefix=f".{summary_path.name}.", delete=False) as stream:
            temporary_paths.append(Path(stream.name))
            json.dump(summary, stream, indent=2, ensure_ascii=False)
            stream.write("\n")
        # Neither output is replaced until the complete input has been parsed.
        os.replace(temporary_paths[0], destination)
        os.replace(temporary_paths[1], summary_path)
        return summary
    except (LogReadError, StraceParserError, EndpointCaptureError, OSError) as exc:
        raise QemuStraceParserError(str(exc)) from exc
    finally:
        for path in temporary_paths:
            path.unlink(missing_ok=True)


def _extract_qemu_errno(line: str) -> str | None:
    """Compatibility helper; errno must come from the return, never arguments."""
    match = SYSCALL_RE.match(line)
    return parse_result(match.group("result"))[1] if match else None
