"""Shared return-value contract for native strace, QEMU and legacy JSONL.

``success`` describes an observed syscall return, not application-level success:
a short write can succeed, and a nonnegative brk return need not grant a request.
Negative returns without an explicit errno remain unknown (some syscalls can
return negative data). An absent errno alone never proves success.
"""
from __future__ import annotations

import errno as errno_module
import re
from typing import Any


_RETURN = re.compile(r"^(?P<value>[+-]?(?:0[xX][0-9a-fA-F]+|[0-9]+))(?=\s|<|$)")
_ERRNO = re.compile(r"^\s+(?:errno=(?P<number>[0-9]+)|(?P<symbol>E[A-Z0-9_]+))(?=\s|\(|$)")


def parse_result(result: str) -> tuple[int | None, str | None]:
    """Keep numeric returns and errno together, including QEMU errno=N syntax."""
    match = _RETURN.match(result.strip())
    if match is None:
        return None, None
    token = match.group("value")
    # A syscall return fits in a machine word. Bound conversion of corrupt logs.
    if len(token) > 128:
        return None, None
    value = int(token, 16 if "x" in token.lower() else 10)
    error = None
    if value == -1:
        error_match = _ERRNO.match(result.strip()[match.end():])
        if error_match is not None:
            number = error_match.group("number")
            if number is not None and len(number) <= 10:
                code = int(number)
                if code:
                    error = errno_module.errorcode.get(code, f"ERRNO_{code}")
            elif number is None:
                error = error_match.group("symbol")
    return value, error


def syscall_success(return_value: Any, errno: Any) -> bool | None:
    """True: nonnegative numeric return; False: errno; None: no known outcome."""
    if errno:
        return False
    if type(return_value) is int and return_value >= 0:
        return True
    return None


def normalize_syscall_event(event: dict[str, Any]) -> dict[str, Any]:
    """Enrich a legacy event in memory without changing its source artifact.

    Explicit success/null values are authoritative; only an absent field is
    derived. Process exit codes and signals are not syscall return values.
    """
    normalized = dict(event)
    if event.get("event", "syscall") != "syscall" or not event.get("syscall"):
        return normalized
    result = event.get("result")
    if isinstance(result, str):
        value, error = parse_result(result)
        if event.get("return_value") is None and value is not None:
            normalized["return_value"] = value
        if not event.get("errno") and error is not None:
            normalized["errno"] = error
    if "success" not in event:
        normalized["success"] = syscall_success(
            normalized.get("return_value"), normalized.get("errno")
        )
    return normalized
