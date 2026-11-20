"""Bounded diagnostics for the network owner's existing heartbeat thread."""
from collections import deque
import json
from pathlib import Path
import sys
import threading
import time


OWNER_DIAGNOSTIC_FILE = "network_runtime_owner_diagnostic.json"
MAX_BYTES = 16384
MAX_FRAMES = 8
SLOW_NS = 200_000_000


def _frame(frame):
    return {"file": Path(frame.f_code.co_filename).name[:64],
            "function": frame.f_code.co_name[:64], "line": frame.f_lineno}


def _stack(frame):
    result = []
    while frame is not None and len(result) < MAX_FRAMES:
        result.append(_frame(frame))
        frame = frame.f_back
    return result


def bounded_record(value):
    """Bound the optional control artifact; never collect locals or source text."""
    if len(json.dumps(value, sort_keys=True).encode()) + 1 <= MAX_BYTES:
        return value

    def shrink(item):
        if isinstance(item, dict):
            return {key: shrink((child[:4] if key in {"stack", "thread_stack", "main_stack"}
                                 else child[-4:] if key == "long_spans" else child))
                    for key, child in item.items()}
        if isinstance(item, list):
            return [shrink(child) for child in item]
        return item

    result = shrink(value)
    result["truncated"] = True
    if len(json.dumps(result, sort_keys=True).encode()) + 1 <= MAX_BYTES:
        return result
    return {"schema_version": 1, "scope": "network_owner_thread_diagnostics",
            "status": "oversized", "attempt_id": str(value.get("attempt_id", ""))[:160]}


class OwnerHeartbeatDiagnostics:
    def __init__(self, *, attempt_id, owner_pid, owner_start, clock=None):
        self.clock = clock or time.monotonic_ns
        self.identity = {"attempt_id": attempt_id, "owner_pid": owner_pid,
                         "owner_start": owner_start}
        self.phase = ("initializing", self.clock())
        self.long_spans = deque(maxlen=8)
        self.exceptions = deque(maxlen=2)
        self.published_pulses = 0
        self.last_published_ns = None
        self.last_pulse_timestamp = None

    def step(self, phase):
        now = self.clock()
        previous, since = self.phase
        elapsed = now - since
        if elapsed >= SLOW_NS:
            span = {"phase": previous, "begin_ns": since, "end_ns": now, "elapsed_ns": elapsed}
            try:
                span["main_stack"] = _stack(sys._current_frames().get(threading.main_thread().ident))
            except Exception:
                span["main_stack"] = []
            self.long_spans.append(span)
        self.phase = (phase, now)
        if phase == "published":
            self.published_pulses += 1
            self.last_published_ns = now

    def failure(self, error):
        trace = []
        current = error.__traceback__
        while current is not None and len(trace) < MAX_FRAMES:
            item = _frame(current.tb_frame)
            item["line"] = current.tb_lineno
            trace.append(item)
            current = current.tb_next
        code = getattr(error, "errno", None)
        self.exceptions.append({"phase": self.phase[0], "type": type(error).__name__[:64],
                                "errno": code if type(code) is int else None, "stack": trace})

    def summary(self, thread):
        now = self.clock()
        phase, since = self.phase
        return {"observed_ns": now, "phase": phase, "phase_since_ns": since,
                "phase_elapsed_ns": max(0, now - since),
                "published_pulses": self.published_pulses,
                "last_published_ns": self.last_published_ns,
                "last_pulse_timestamp": self.last_pulse_timestamp,
                "thread_alive": thread is not None and thread.is_alive(),
                "native_thread_id": getattr(thread, "native_id", None),
                "long_spans": list(self.long_spans), "exceptions": list(self.exceptions)}

    def capture(self, thread):
        frames = sys._current_frames()
        return {"schema_version": 1, "scope": "network_owner_thread_diagnostics",
                "clock": "monotonic_ns", **self.identity, **self.summary(thread),
                "thread_stack": _stack(frames.get(getattr(thread, "ident", None))),
                "main_stack": _stack(frames.get(threading.main_thread().ident))}
