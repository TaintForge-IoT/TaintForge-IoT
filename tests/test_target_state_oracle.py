from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from taintforge_env.target_state_oracle import (
    TargetStateError,
    TargetStateOracle,
    TargetStateSpec,
)


class TargetStateOracleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        (self.root / "logs").mkdir()
        (self.root / "config").mkdir()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def spec(self, rules: list[dict], **overrides) -> TargetStateSpec:
        raw = {
            "schema_version": 1,
            "goal_id": "goal_test",
            "description": "test target",
            "mode": "all",
            "rules": rules,
        }
        raw.update(overrides)
        return TargetStateSpec.from_dict(raw)

    def write_jsonl(self, name: str, events: list[dict]) -> None:
        path = self.root / "logs" / name
        path.write_text(
            "".join(json.dumps(event) + "\n" for event in events),
            encoding="utf-8",
        )

    def test_event_count_defaults_to_guest_context(self) -> None:
        self.write_jsonl(
            "syscall_events.jsonl",
            [
                {"execution_context": "host_wrapper", "syscall": "write", "success": True},
                {"execution_context": "guest", "syscall": "write", "success": True},
            ],
        )
        spec = self.spec(
            [
                {
                    "id": "guest_write",
                    "type": "event_count",
                    "source": "syscall",
                    "where": {"syscall": "write", "success": True},
                    "min_count": 1,
                }
            ]
        )
        result = TargetStateOracle().evaluate(self.root, spec)
        self.assertTrue(result.reached)
        self.assertEqual(result.rules[0].observed_count, 1)

    def test_repeated_sequence_with_bounded_gaps(self) -> None:
        events: list[dict] = []
        for _ in range(3):
            events.extend(
                [
                    {"execution_context": "guest", "syscall": "poll"},
                    {"execution_context": "guest", "syscall": "clock_gettime"},
                    {"execution_context": "guest", "syscall": "recvfrom"},
                ]
            )
        self.write_jsonl("syscall_events.jsonl", events)
        spec = self.spec(
            [
                {
                    "id": "loop",
                    "type": "repeated_sequence",
                    "source": "syscall",
                    "sequence": [{"syscall": "poll"}, {"syscall": "recvfrom"}],
                    "min_repeats": 3,
                    "max_gap": 1,
                }
            ]
        )
        result = TargetStateOracle().evaluate(self.root, spec)
        self.assertTrue(result.reached)
        self.assertEqual(result.rules[0].observed_count, 3)

    def test_legacy_success_inference_is_conservative_and_read_only(self) -> None:
        cases = [
            ({"return_value": 13, "errno": None}, True),
            ({"return_value": 0, "errno": None}, True),
            ({"result": "0x40805000", "return_value": None}, True),
            ({"result": "-1 ENOSYS (Function not implemented)", "return_value": -1}, False),
            ({"result": "-1 errno=111 (Connection refused)"}, False),
            ({"return_value": -1, "errno": "EIO"}, False),
            ({"return_value": -1, "errno": None}, None),
            ({"return_value": None, "errno": None}, None),
            ({"result": "?"}, None), ({}, None),
            ({"return_value": True}, None), ({"return_value": "13"}, None),
            ({"return_value": 13.0}, None),
            ({"return_value": 13, "success": None}, None),
            ({"return_value": 13, "success": False}, False),
            ({"success": 1}, 1), ({"success": 0}, 0),
            ({"event": "process_exit", "return_value": 0}, None),
        ]
        for fields, expected in cases:
            with self.subTest(fields=fields):
                event = {"event": "syscall", "syscall": "write", "execution_context": "guest", **fields}
                self.write_jsonl("syscall_events.jsonl", [event])
                source = self.root / "logs/syscall_events.jsonl"
                before = source.read_bytes()
                for success in (True, False):
                    spec = self.spec([{"id": "write", "type": "event_count", "source": "syscall",
                                       "where": {"syscall": "write", "success": success}}])
                    result = TargetStateOracle().evaluate(self.root, spec)
                    self.assertEqual(result.reached, expected is success)
                self.assertEqual(source.read_bytes(), before)

    def test_repeated_sequence_normalizes_legacy_results(self) -> None:
        self.write_jsonl("syscall_events.jsonl", [
            {"execution_context": "guest", "syscall": "write", "result": "13"},
            {"execution_context": "host_wrapper", "syscall": "write", "result": "13"},
            {"execution_context": "guest", "syscall": "close", "return_value": 0},
        ])
        spec = self.spec([{"id": "sequence", "type": "repeated_sequence", "source": "syscall",
                           "sequence": [{"syscall": "write", "success": True},
                                        {"syscall": "close", "success": True}],
                           "min_repeats": 1, "max_gap": 0}])
        self.assertTrue(TargetStateOracle().evaluate(self.root, spec).reached)

    def test_sequence_does_not_match_when_gap_exceeds_limit(self) -> None:
        self.write_jsonl(
            "syscall_events.jsonl",
            [
                {"execution_context": "guest", "syscall": "poll"},
                {"execution_context": "guest", "syscall": "a"},
                {"execution_context": "guest", "syscall": "b"},
                {"execution_context": "guest", "syscall": "recvfrom"},
            ],
        )
        spec = self.spec(
            [
                {
                    "id": "loop",
                    "type": "repeated_sequence",
                    "source": "syscall",
                    "sequence": [{"syscall": "poll"}, {"syscall": "recvfrom"}],
                    "min_repeats": 1,
                    "max_gap": 1,
                }
            ]
        )
        self.assertFalse(TargetStateOracle().evaluate(self.root, spec).reached)

    def test_text_marker_and_json_field(self) -> None:
        (self.root / "logs" / "runtime_stdout.log").write_text(
            "ready\ncommand loop ready\n",
            encoding="utf-8",
        )
        (self.root / "config" / "prebuilt_execution.json").write_text(
            json.dumps({"timed_out": True, "guest_exit_code": 124}),
            encoding="utf-8",
        )
        spec = self.spec(
            [
                {
                    "id": "marker",
                    "type": "text_contains",
                    "source": "stdout",
                    "needle": "command loop ready",
                },
                {
                    "id": "timeout",
                    "type": "json_field_equals",
                    "source": "execution",
                    "field": "timed_out",
                    "equals": True,
                },
            ]
        )
        result = TargetStateOracle().evaluate(self.root, spec)
        self.assertTrue(result.reached)
        self.assertEqual(result.matched_rules, 2)

    def test_at_least_aggregation(self) -> None:
        (self.root / "logs" / "runtime_stdout.log").write_text("one\n", encoding="utf-8")
        spec = self.spec(
            [
                {"id": "one", "type": "text_contains", "source": "stdout", "needle": "one"},
                {"id": "two", "type": "text_contains", "source": "stdout", "needle": "two"},
                {"id": "three", "type": "text_contains", "source": "stdout", "needle": "three"},
            ],
            mode="at_least",
            min_satisfied=1,
        )
        self.assertTrue(TargetStateOracle().evaluate(self.root, spec).reached)

    def test_any_aggregation_fails_when_no_rules_match(self) -> None:
        spec = self.spec(
            [
                {"id": "one", "type": "text_contains", "source": "stdout", "needle": "one"},
                {"id": "two", "type": "text_contains", "source": "stderr", "needle": "two"},
            ],
            mode="any",
        )
        result = TargetStateOracle().evaluate(self.root, spec)
        self.assertFalse(result.reached)
        self.assertIn("unmatched", result.reason)

    def test_missing_evidence_is_unmatched_not_goal(self) -> None:
        spec = self.spec(
            [
                {
                    "id": "connect",
                    "type": "event_count",
                    "source": "network",
                    "where": {"event": "tcp_connection_open"},
                }
            ]
        )
        result = TargetStateOracle().evaluate(self.root, spec)
        self.assertFalse(result.reached)
        self.assertEqual(result.rules[0].observed_count, 0)

    def test_malformed_existing_jsonl_is_rejected(self) -> None:
        (self.root / "logs" / "syscall_events.jsonl").write_text("{broken\n")
        spec = self.spec(
            [
                {
                    "id": "write",
                    "type": "event_count",
                    "source": "syscall",
                    "where": {"syscall": "write"},
                }
            ]
        )
        with self.assertRaisesRegex(TargetStateError, "invalid JSONL"):
            TargetStateOracle().evaluate(self.root, spec)

    def test_duplicate_rule_id_is_rejected(self) -> None:
        with self.assertRaisesRegex(TargetStateError, "duplicate"):
            self.spec(
                [
                    {"id": "same", "type": "text_contains", "source": "stdout", "needle": "a"},
                    {"id": "same", "type": "text_contains", "source": "stdout", "needle": "b"},
                ]
            )

    def test_spec_file_symlink_is_rejected(self) -> None:
        real = self.root / "real.json"
        real.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "goal_id": "x",
                    "description": "x",
                    "mode": "all",
                    "rules": [
                        {"id": "x", "type": "text_contains", "source": "stdout", "needle": "x"}
                    ],
                }
            )
        )
        link = self.root / "link.json"
        link.symlink_to(real)
        with self.assertRaisesRegex(TargetStateError, "regular file"):
            TargetStateSpec.load(link)

    def test_evaluation_serialization_is_deterministic_except_timestamp(self) -> None:
        (self.root / "logs" / "runtime_stdout.log").write_text("ready\n", encoding="utf-8")
        spec = self.spec(
            [{"id": "ready", "type": "text_contains", "source": "stdout", "needle": "ready"}]
        )
        first = TargetStateOracle().evaluate(self.root, spec).to_dict()
        second = TargetStateOracle().evaluate(self.root, spec).to_dict()
        first.pop("generated_at_utc")
        second.pop("generated_at_utc")
        first.pop("evaluation_sha256")
        second.pop("evaluation_sha256")
        self.assertEqual(first, second)


if __name__ == "__main__":
    unittest.main()
