"""Contracts for ordered replay exercised through fresh retirement capsules."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import re


SCOPE = "native_phase1_retirement_capsule_sessions"
MARKER = b"NET8_OK\n"


@dataclass(frozen=True)
class SessionCase:
    name: str
    mode: int
    reason: str | None = None
    wrong_response: bool = False
    limits: tuple = ()

    @property
    def goal(self):
        return self.reason is None and not self.wrong_response

    @property
    def connections(self):
        return 2 if self.mode in (9, 10) else 1

    @property
    def guest_exit(self):
        return 14 if self.wrong_response else 20 if self.reason else 0


CASES = (
    SessionCase("ordered", 0), SessionCase("fragmented", 1), SessionCase("coalesced", 2),
    SessionCase("reconnect", 9), SessionCase("interleaved_connections", 10),
    SessionCase("wrong_order", 3, "unexpected_request_at_step"),
    SessionCase("unknown_step", 4, "unexpected_request_at_step"),
    SessionCase("premature_eof", 5, "connection_closed_before_complete_session"),
    SessionCase("idle_timeout", 6, "idle_timeout", limits=(("idle_timeout_ms", 100),)),
    SessionCase("session_timeout", 6, "session_timeout",
                limits=(("idle_timeout_ms", 1000), ("session_timeout_ms", 100))),
    SessionCase("wrong_response", 0, wrong_response=True),
    SessionCase("trailing_bytes", 7, "trailing_bytes_after_final_request"),
    SessionCase("receive_budget", 8, "receive_byte_limit", limits=(("max_received_bytes", 27),)),
)
BY_NAME = {case.name: case for case in CASES}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def specification(case, port):
    pairs = ((b"HELLO\n", b"READY\n"), (b"AUTH test\n", b"OK\n"),
             (b"GET CONFIG\n", b"interval=99\n" if case.wrong_response else b"interval=30\n"))
    return {"schema_version": 1, "transport": "tcp", "remote_ip": "127.0.0.1",
            "remote_port": port, "protocol_hint": "net4_test", "framing": "exact_bytes",
            "limits": dict(case.limits),
            "steps": [{"request_hex": request.hex(), "response_hex": response.hex()} for request, response in pairs]}


def validate_transcript(case, events, session, *, attempt_id=None):
    require(isinstance(events, list) and all(isinstance(e, dict) for e in events), "invalid session events")
    selected = [e for e in events if e.get("listener_type") == "deterministic_session"]
    require(selected, "missing session transcript")
    connections = {}
    for position, event in enumerate(selected):
        require(event.get("replay_session_id") == session.session_id
                and event.get("original_remote_ip") == session.remote_ip
                and event.get("original_remote_port") == session.remote_port,
                "transcript belongs to another replay session")
        if attempt_id is not None:
            require(event.get("attempt_id") == attempt_id, "transcript belongs to another attempt")
        cid = event.get("connection_id")
        require(type(cid) is int and cid > 0, "invalid session connection identity")
        row = connections.setdefault(cid, {"started": False, "hits": [], "terminal": None})
        kind = event.get("event")
        require(row["terminal"] is None, "event after terminal session outcome")
        if kind == "session_start":
            require(not row["started"] and event.get("steps") == 3, "duplicate or invalid session start")
            row["started"] = True
            row["start_index"] = position
            continue
        require(row["started"], "session event precedes its start")
        if kind == "replay_hit":
            index = event.get("step_index")
            require(type(index) is int and index == len(row["hits"]) and index < 3,
                    "session skipped, reordered or repeated a step")
            step = session.steps[index]
            require(event.get("response_sent") is True and event.get("response_origin") == "replay"
                    and event.get("request_sha256") == hashlib.sha256(step.request).hexdigest()
                    and event.get("response_sha256") == hashlib.sha256(step.response).hexdigest(),
                    "session step payload or delivery differs")
            row["hits"].append(index)
        elif kind in {"session_complete", "session_abort"}:
            require(event.get("completed_steps") == len(row["hits"]), "terminal step count differs")
            row["terminal"] = kind
            row["reason"] = event.get("reason")
            row["terminal_index"] = position
    rows = [{"connection_id": cid, "steps": row["hits"], "terminal": row["terminal"],
             "reason": row.get("reason"), "start_index": row.get("start_index"),
             "terminal_index": row.get("terminal_index")} for cid, row in connections.items()]
    validate_connections(case, rows)
    return {"replay_session_id": session.session_id, "connections": rows,
            "completed": sum(row["terminal"] == "session_complete" for row in rows),
            "aborted": sum(row["terminal"] == "session_abort" for row in rows)}


def validate_connections(case, rows):
    require(isinstance(rows, list) and len(rows) == case.connections, "wrong session connection count")
    identities = []
    for row in rows:
        require(isinstance(row, dict), "invalid session connection")
        cid = row.get("connection_id")
        require(type(cid) is int and cid > 0 and cid not in identities, "reused connection identity")
        identities.append(cid)
        start, end = row.get("start_index"), row.get("terminal_index")
        require(type(start) is int and type(end) is int and 0 <= start < end,
                "missing session lifetime ordering")
        steps = row.get("steps")
        require(isinstance(steps, list) and all(type(i) is int for i in steps)
                and steps == list(range(len(steps))) and len(steps) <= 3, "invalid ordered steps")
        if case.reason is None:
            require(steps == [0, 1, 2] and row.get("terminal") == "session_complete"
                    and row.get("reason") is None, "session did not complete its dialogue")
        else:
            require(row.get("terminal") == "session_abort" and row.get("reason") == case.reason,
                    "session stopped for another reason")
            expected = {"wrong_order": 0, "unknown_step": 1, "premature_eof": 0,
                        "idle_timeout": 0, "session_timeout": 0, "trailing_bytes": 2}
            require(len(steps) == expected[case.name] if case.name in expected else len(steps) < 3,
                    "unexpected progress before session rejection")
    if case.mode in (9, 10):
        first, second = sorted(rows, key=lambda row: row["start_index"])
        if case.mode == 9:
            require(first["terminal_index"] < second["start_index"], "reconnect sessions overlapped")
        else:
            require(first["start_index"] < second["start_index"] < second["terminal_index"] < first["terminal_index"],
                    "the two connections were not exercised in interleaved order")


def validate_result(data, runtime):
    require(data.get("status") == "passed" and data.get("scope") == SCOPE, "wrong NET-8 status or scope")
    require(all(type(data.get(k)) is int for k in ("plugin_api", "guest_executions", "qemu_launch_attempts"))
            and data.get("plugin_api") == 6 and data.get("guest_executions") == len(CASES)
            and data.get("qemu_launch_attempts") == len(CASES), "NET-8 needs thirteen guest executions")
    require(all(data.get(k) is True for k in ("phase1_executed", "capsule_executed", "namespace_executed")),
            "missing native NET-8 execution")
    require(data.get("oep_proven") is False and data.get("hostile_sample_ready") is False,
            "unsupported NET-8 claims")
    expected = {runtime[k]["resolved_path"]: runtime[k]["sha256"] for k in ("qemu", "plugin", "observer")}
    require(data.get("runtime_sha256") == expected, "NET-8 used different runtime binaries")
    cases = data.get("cases")
    require(isinstance(cases, list) and len(cases) == len(CASES)
            and all(isinstance(c, dict) and isinstance(c.get("case"), str) for c in cases)
            and {c["case"] for c in cases} == set(BY_NAME), "missing or duplicate NET-8 cases")
    seen = {key: set() for key in ("attempt_id", "analysis_instance_id", "lifecycle_attempt")}
    for row in cases:
        case = BY_NAME[row["case"]]
        require(row.get("status") == "passed" and type(row.get("guest_executions")) is int and row["guest_executions"] == 1
                and row.get("store_unchanged") is True, "incomplete NET-8 case")
        attempt = row.get("attempt", {})
        require(isinstance(attempt, dict), "invalid NET-8 attempt")
        observer = attempt.get("observer")
        require(isinstance(observer, dict), "invalid NET-8 observer result")
        for key, previous in seen.items():
            value = attempt.get(key)
            require(isinstance(value, str) and value and value not in previous, "reused or missing " + key)
            previous.add(value)
        require(all(attempt.get(k) is True for k in ("phase1_executed", "capsule_executed", "namespace_executed",
                "phase1_retired", "capsule_tree_empty", "namespace_removed", "veth_removed")),
                "NET-8 retirement or cleanup evidence is incomplete")
        require(attempt.get("network_cleanup") == "cleaned" and attempt.get("termination_reason") is None
                and attempt.get("goal_reached") is case.goal and type(attempt.get("guest_exit")) is int
                and attempt["guest_exit"] == case.guest_exit
                and observer.get("status") == "correlated", "wrong NET-8 application outcome")
        transcript = row.get("transcript", {})
        require(isinstance(transcript, dict)
                and re.fullmatch(r"[0-9a-f]{64}", str(transcript.get("replay_session_id"))), "invalid session digest")
        validate_connections(case, transcript.get("connections"))
        require(type(transcript.get("completed")) is int and type(transcript.get("aborted")) is int
                and transcript.get("completed") == (case.connections if case.reason is None else 0)
                and transcript.get("aborted") == (case.connections if case.reason else 0), "wrong transcript totals")
