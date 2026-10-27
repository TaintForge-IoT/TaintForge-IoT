"""Controller policy checks for a live verdict rather than a fixed code address."""
import copy
import unittest

from taintforge_env import phase1_retirement as r
from tests import test_phase1_retirement as baseline


class VerdictRetirementTests(unittest.TestCase):
    def setUp(self):
        baseline.RetirementEvidenceTests.setUp(self)
        self.binding["settings"] = {"phase1_retirement": r.settings(trigger="verdict")}
        del self.binding["capsule"]["symbols"]["phase1_retire_boundary"]
        for packet in self.packets:
            packet["protocol"] = 2
        self.packets[0]["data"]["trigger"] = r.VERDICT_TRIGGER
        self.stream[1]["data"]["trigger"] = r.VERDICT_TRIGGER
        self.stream[0].update(status="candidate", analysis_epoch=0, code_generation=1,
                              current_pc=4100, trace_seq=23)
        self.stream[0]["data"]["decision_trace_seq"] = 23
        self.stream[1].update(trace_seq=23, current_pc=8192)

    def test_continuation_is_observed_and_needs_no_fixed_symbol(self):
        for pc in (4101, 4100, 4096, 12288):
            # Branches may loop back to the same PC, even to the candidate OEP.
            self.packets[0]["data"]["continuation_pc"] = pc
            self.stream[1]["data"]["continuation_pc"] = pc
            self.stream[1]["current_pc"] = pc
            r.check_verdict(self.binding, self.packets[0], self.stream)
        r.check_packets(self.binding, self.packets, 77, complete=True)
        options = r.plugin_options(self.binding, "/ipc", 12)
        self.assertIn("retire-trigger=verdict", options)
        self.assertFalse(any(x.startswith("retire-boundary=") for x in options))

    def test_mixed_protocols_and_stale_or_delayed_verdicts_are_rejected(self):
        for change in ({"trace_seq": 24}, {"current_pc": 8193}, {"analysis_epoch": 1}, {"code_generation": 2}):
            stream = copy.deepcopy(self.stream)
            stream[1].update(change)
            with self.assertRaises(RuntimeError):
                r.check_verdict(self.binding, self.packets[0], stream)
        for change in ({"status": "stale"}, {"trace_seq": 22}, {"current_pc": 4101}, {"analysis_epoch": 1}):
            stream = copy.deepcopy(self.stream)
            stream[0].update(change)
            with self.assertRaises(RuntimeError):
                r.check_verdict(self.binding, self.packets[0], stream)
        for event in ("oep_candidate_invalidated", "code_generation_changed", "data_loss", "profile_lost", "error"):
            stream = copy.deepcopy(self.stream)
            stream.insert(1, {"event_type": event, "event_seq": 2})
            stream[2]["event_seq"] = 3
            with self.assertRaises(RuntimeError):
                r.check_verdict(self.binding, self.packets[0], stream)
        self.packets[0]["protocol"] = 1
        with self.assertRaises(RuntimeError):
            r.check_packets(self.binding, self.packets, 77, complete=True)

    def test_configuration_does_not_silently_change_the_bound_policy(self):
        for delay in (True, 0, 257):
            with self.assertRaises(RuntimeError):
                r.settings(trigger="verdict", selection_delay=delay)
        config = r.settings(trigger="verdict")
        config["max_instructions"] += 1
        with self.assertRaises(RuntimeError):
            r.validate_settings(config)


if __name__ == "__main__":
    unittest.main()
