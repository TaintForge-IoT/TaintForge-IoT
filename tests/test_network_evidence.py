from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from taintforge_env.observations import ObservationBundle
from taintforge_env.network_events import normalize_network_event
from taintforge_env.progress_oracle import ProgressClassification, ProgressOracle
from taintforge_env.requirement_extractor import RequirementExtractor
from taintforge_env.requirements import RequirementStatus
from tests.test_progress_oracle import write_artifacts


def event(name, **fields):
    return {
        "event": name,
        "listener_type": "deterministic_replay",
        "transport": "udp",
        "original_remote_ip": "192.0.2.10",
        "original_remote_port": 4444,
        "exchange_id": 1,
        **fields,
    }


class NetworkRequirementEvidenceTests(unittest.TestCase):
    def extract(self, *events):
        return RequirementExtractor().extract(ObservationBundle(
            run_dir=Path("/tmp/network-evidence"), network_events=tuple(events)))

    def only(self, *events):
        requirements = self.extract(*events).requirements
        self.assertEqual(len(requirements), 1)
        return requirements[0]

    def test_successful_tcp_replay_is_provided_without_claiming_semantic_success(self):
        common = dict(transport="tcp", connection_id=1)
        requirement = self.only(
            event("tcp_connection_open", **common),
            event("replay_hit", response_size=5, **common))
        self.assertEqual(requirement.status, RequirementStatus.PROVIDED)
        self.assertEqual(dict(requirement.details)["response_observed"], "true")
        self.assertEqual(dict(requirement.details)["semantic_satisfaction"], "unknown")

    def test_udp_prepared_reply_is_not_a_sent_reply(self):
        requirement = self.only(event("replay_hit", response_prepared=True, response_size=5))
        self.assertEqual(requirement.status, RequirementStatus.UNKNOWN)
        self.assertEqual(dict(requirement.details)["response_observed"], "false")

    def test_udp_delivery_is_provided(self):
        requirement = self.only(
            event("replay_hit", response_prepared=True),
            event("network_response_sent", source_event="replay_hit", response_sent=True))
        self.assertEqual(requirement.status, RequirementStatus.PROVIDED)

    def test_dns_miss_remains_unmet_when_a_synthetic_error_was_sent(self):
        common = dict(protocol_hint="dns", replay_status="miss", response_origin="synthetic_miss")
        requirement = self.only(
            event("dns_replay_miss", response_prepared=True, **common),
            event("network_response_sent", source_event="dns_replay_miss", response_sent=True, **common))
        self.assertEqual(requirement.status, RequirementStatus.UNMET)
        self.assertEqual(dict(requirement.details)["response_observed"], "true")

    def test_udp_miss_and_record_timeout_are_not_silently_ignored(self):
        for failure in (event("replay_miss"), event("udp_record", status="failed", reason="TimeoutError")):
            with self.subTest(event=failure["event"]):
                self.assertEqual(self.only(failure).status, RequirementStatus.UNMET)

    def test_send_failure_does_not_promote_a_prepared_dns_reply(self):
        requirement = self.only(
            event("dns_replay_hit", protocol_hint="dns", response_prepared=True),
            event("network_response_failed", protocol_hint="dns", source_event="dns_replay_hit",
                  response_sent=False, error="OSError: send failed"))
        self.assertEqual(requirement.status, RequirementStatus.UNMET)
        self.assertEqual(dict(requirement.details)["response_observed"], "false")

    def test_legacy_udp_sent_flag_must_be_a_boolean(self):
        requirement = self.only(event("udp_datagram", dns_response_sent="false"))
        self.assertEqual(requirement.status, RequirementStatus.UNKNOWN)

    def test_tcp_response_from_another_backend_does_not_satisfy_open_connection(self):
        common = dict(transport="tcp", connection_id=7, listener_type="known")
        requirement = self.only(
            event("tcp_connection_open", backend_source="loopback", **common),
            event("tcp_response", backend_source="host", **common))
        self.assertEqual(requirement.status, RequirementStatus.UNKNOWN)

    def test_different_udp_requests_keep_separate_delivery_evidence(self):
        requirement = self.only(
            event("replay_hit", exchange_id=1, response_prepared=True),
            event("replay_hit", exchange_id=2, response_prepared=True),
            event("network_response_sent", exchange_id=2, source_event="replay_hit", response_sent=True))
        self.assertEqual(requirement.status, RequirementStatus.UNKNOWN)

    def test_malformed_optional_metadata_does_not_invent_delivery(self):
        malformed = event("udp_datagram", transport=[], replay_status={}, status=[],
                          response_sent="true", bind_port={}, peer_port=[])
        self.assertFalse(normalize_network_event(malformed)["response_observed"])
        self.assertEqual(self.only(malformed).status, RequirementStatus.UNKNOWN)

    def test_failure_evidence_survives_the_per_requirement_evidence_cap(self):
        common = dict(transport="tcp", connection_id=1)
        events = [event("tcp_connection_open", **common)]
        events.extend(event("tcp_data", **common) for _ in range(20))
        events.append(event("tcp_connection_error", error="injected send failure", **common))
        requirement = self.only(*events)
        self.assertEqual(requirement.status, RequirementStatus.UNMET)
        self.assertEqual(requirement.evidence[0].summary, "tcp_connection_error")
        self.assertEqual(requirement.evidence[0].event_index, len(events) - 1)
        self.assertLessEqual(len(requirement.evidence), 8)


class NetworkProgressEvidenceTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def observe(self, name, events):
        root = self.root / name
        write_artifacts(root, automatic=False)
        (root / "logs/network_events.jsonl").write_text(
            "".join(json.dumps(e) + "\n" for e in events))
        return ProgressOracle().observe(root, environment_snapshot_id="same-environment")

    def test_first_sent_response_at_known_endpoint_is_progress_but_not_goal(self):
        prepared = event("replay_hit", response_prepared=True, request_sha256="1" * 64)
        before = self.observe("before", [prepared])
        after = self.observe("after", [prepared, event("network_response_sent", response_sent=True,
            source_event="replay_hit", request_sha256="1" * 64, response_sha256="2" * 64)])
        decision = ProgressOracle().compare(before, after)
        self.assertEqual(decision.classification, ProgressClassification.PROGRESS)
        self.assertFalse(after.goal_reached)

    def test_request_and_response_content_participate_in_behavior_fingerprint(self):
        first = self.observe("first", [event("network_response_sent", response_sent=True,
            source_event="replay_hit", request_sha256="1" * 64, response_sha256="2" * 64)])
        second = self.observe("second", [event("network_response_sent", response_sent=True,
            source_event="replay_hit", request_sha256="3" * 64, response_sha256="4" * 64)])
        self.assertNotEqual(first.behavior_fingerprint, second.behavior_fingerprint)

    def test_ephemeral_ids_and_peer_ports_do_not_create_progress(self):
        first = self.observe("first", [event("network_response_sent", response_sent=True,
            peer_port=12345, exchange_id=1, request_sha256="1" * 64, response_sha256="2" * 64)])
        second = self.observe("second", [event("network_response_sent", response_sent=True,
            peer_port=54321, exchange_id=72, request_sha256="1" * 64, response_sha256="2" * 64)])
        self.assertEqual(first.behavior_fingerprint, second.behavior_fingerprint)
        self.assertEqual(ProgressOracle().compare(first, second).classification, ProgressClassification.NO_PROGRESS)

    def test_losing_the_only_sent_response_is_regression(self):
        before = self.observe("before", [event("network_response_sent", response_sent=True,
            source_event="replay_hit", request_sha256="1" * 64, response_sha256="2" * 64)])
        after = self.observe("after", [event("replay_hit", response_prepared=True,
            request_sha256="1" * 64, response_sha256="2" * 64)])
        self.assertEqual(ProgressOracle().compare(before, after).classification, ProgressClassification.REGRESSION)

    def test_tcp_and_udp_at_the_same_address_are_distinct_targets(self):
        observation = self.observe("transports", [event("tcp_connection_open", transport="tcp"),
                                                  event("replay_hit", transport="udp")])
        self.assertEqual(observation.metrics.unique_network_targets, 2)


if __name__ == "__main__":
    unittest.main()
