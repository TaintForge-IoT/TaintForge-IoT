from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path


def append_jsonl_event(path: str | Path, event: dict) -> None:
    from .network_runtime import current_runtime, network_open
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    event_with_time = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        **event,
    }

    line = json.dumps(event_with_time, ensure_ascii=False) + "\n"

    if current_runtime() is not None:
        event_with_time.setdefault("attempt_id", current_runtime().attempt_id)
        line = json.dumps(event_with_time, ensure_ascii=False) + "\n"
        with network_open(path, "ab") as stream:
            stream.write(line.encode("utf-8"))
        return

    fd = os.open(
        path,
        os.O_APPEND | os.O_CREAT | os.O_WRONLY,
        0o644,
    )

    try:
        os.write(fd, line.encode("utf-8"))
    finally:
        os.close(fd)
