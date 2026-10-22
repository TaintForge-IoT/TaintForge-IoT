"""Read runtime text without allocating memory proportional to the log size."""
from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path


MAX_LOG_LINE_BYTES = 1024 * 1024
OBSERVATION_PREVIEW_CHARS = 64 * 1024


class LogReadError(RuntimeError):
    pass


def iter_log_lines(path: Path) -> Iterator[str]:
    """Preserve physical line numbers; fail explicitly on an oversized record."""
    with path.open("rb") as stream:
        line_number = 0
        while raw := stream.readline(MAX_LOG_LINE_BYTES + 1):
            line_number += 1
            if len(raw) > MAX_LOG_LINE_BYTES:
                raise LogReadError(
                    f"log line exceeds {MAX_LOG_LINE_BYTES} bytes at {path}:{line_number}; "
                    "record was not truncated or accepted as complete"
                )
            yield raw.decode("utf-8", errors="replace")


def read_log_preview(path: Path, limit: int) -> tuple[str, bool]:
    if limit < 0:
        raise ValueError("preview limit must be nonnegative")
    with path.open(encoding="utf-8", errors="replace") as stream:
        text = stream.read(limit + 1)
    return text[:limit], len(text) > limit
