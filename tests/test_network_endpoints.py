from __future__ import annotations

from dataclasses import asdict
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from taintforge_env.network_endpoints import EndpointCapture, SocketTraceTracker, printed_endpoint
from scripts.reprocess_prebuilt_logs import reprocess
from taintforge_env.qemu_strace_parser import parse_qemu_strace, QemuStraceParserError
from taintforge_env.strace_parser import parse_strace_line
from taintforge_env.observations import ObservationBundle
from taintforge_env.requirement_extractor import RequirementExtractor
from taintforge_env.requirements import RequirementStatus


def capture_rows(*, transport="tcp"):
    identity = {"schema_version": 1, "session_id": "session", "attempt_id": "attempt"}
    common = {**identity, "event": "network_syscall", "pid": 24, "vcpu": 0,
              "remote_ip": None, "remote_port": 0, "transport": transport,
              "sockaddr_address": 0, "sockaddr_length": 0, "endpoint_resolution": "not_applicable"}
    return [
        {**identity, "event": "observer_started", "pid": 24, "target_arch": "i386",
         "profile": "single-process-single-thread", "plugin_api": 6, "max_records": 16384},
        {**common, "seq": 1, "syscall": "socket", "number": 359, "subcall": 0, "fd": -1, "result": 4},
        {**common, "seq": 2, "syscall": "connect", "number": 362, "subcall": 0, "fd": 4,
         "result": -111, "remote_ip": "192.0.2.10", "remote_port": 4444,
         "sockaddr_address": 0x804A000, "sockaddr_length": 16, "endpoint_resolution": "observed_sockaddr"},
        {**identity, "event": "observer_finished", "record_count": 2, "complete": True},
    ]


class NetworkEndpointCaptureTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source = self.root / "qemu_strace.log"
        self.source.write_text("24 socket(PF_INET,SOCK_STREAM,IPPROTO_IP) = 4\n"
                               "24 connect(4,0x804a000,16) = -1 errno=111 (Connection refused)\n")
        self.sidecar = self.root / "endpoints.jsonl"
        self.output = self.root / "events.jsonl"

    def parse(self, rows, **options):
        self.sidecar.write_text("".join(json.dumps(row) + "\n" for row in rows))
        summary = parse_qemu_strace(self.source, self.output, target_arch="i386",
            endpoint_events=self.sidecar, session_id="session", attempt_id="attempt", **options)
        return summary, [json.loads(line) for line in self.output.read_text().splitlines()]

    def test_pointer_endpoint_is_recovered_and_errno_preserved(self):
        summary, events = self.parse(capture_rows())
        self.assertEqual(summary["network_endpoint_observer"]["status"], "correlated")
        self.assertEqual(summary["network_targets"], ["192.0.2.10:4444"])
        call = events[1]
        self.assertEqual((call["remote_ip"], call["remote_port"], call["transport"]), ("192.0.2.10", 4444, "tcp"))
        self.assertEqual(call["errno"], "ECONNREFUSED")
        self.assertFalse(call["success"])
        self.assertEqual(call["endpoint_source"], "qemu_network_observer")

    def test_observed_udp_connect_does_not_become_tcp_requirement(self):
        self.source.write_text(self.source.read_text().replace("SOCK_STREAM", "SOCK_DGRAM"))
        _, events = self.parse(capture_rows(transport="udp"))
        requirements = RequirementExtractor().extract(ObservationBundle(
            run_dir=self.root, syscall_events=tuple(events))).requirements
        self.assertEqual(len(requirements), 1)
        self.assertEqual(requirements[0].resource, "udp://192.0.2.10:4444")
        self.assertEqual(requirements[0].status, RequirementStatus.UNMET)

    def test_identity_mismatch_does_not_enrich_the_pointer(self):
        rows = capture_rows()
        for row in rows:
            row["attempt_id"] = "another-attempt"
        summary, events = self.parse(rows)
        self.assertEqual(summary["network_endpoint_observer"]["status"], "identity_mismatch")
        self.assertIsNone(events[1]["remote_ip"])

    def test_pid_fd_result_and_missing_rows_do_not_shift_correlation(self):
        cases = [("pid", 25), ("fd", 7), ("result", -110)]
        for field, value in cases:
            with self.subTest(field=field):
                rows = capture_rows()
                rows[2][field] = value
                if field == "pid":
                    with self.assertRaises(QemuStraceParserError):
                        self.parse(rows)
                else:
                    summary, events = self.parse(rows)
                    self.assertEqual(summary["network_endpoint_observer"]["status"], "uncorrelated")
                    self.assertIsNone(events[1]["remote_ip"])

    def test_incomplete_and_lost_profiles_keep_endpoints_unknown(self):
        for mode in ("incomplete", "lost"):
            with self.subTest(mode=mode):
                rows = capture_rows()
                if mode == "incomplete":
                    rows.pop()
                else:
                    rows.insert(-1, {**rows[0], "event": "observer_error", "reason": "multiple_guest_tasks_unsupported"})
                summary, events = self.parse(rows)
                self.assertNotEqual(summary["network_endpoint_observer"]["status"], "correlated")
                self.assertIsNone(events[1]["remote_ip"])

    def test_bad_capture_leaves_existing_outputs_untouched(self):
        self.output.write_text("old events\n")
        summary = self.output.with_suffix(".summary.json")
        summary.write_text("old summary\n")
        rows = capture_rows()
        rows[2]["seq"] = 9
        with self.assertRaises(QemuStraceParserError):
            self.parse(rows)
        self.assertEqual(self.output.read_text(), "old events\n")
        self.assertEqual(summary.read_text(), "old summary\n")

    def test_reused_sockaddr_pointer_preserves_each_observed_value(self):
        rows = capture_rows()
        row = {**rows[2], "seq": 3, "remote_ip": "192.0.2.20", "remote_port": 5555}
        rows.insert(-1, row)
        rows[-1]["record_count"] = 3
        with self.source.open("a") as stream:
            stream.write("24 connect(4,0x804a000,16) = -1 errno=111 (Connection refused)\n")
        _, events = self.parse(rows)
        self.assertEqual([(e["remote_ip"], e["remote_port"]) for e in events[1:]],
                         [("192.0.2.10", 4444), ("192.0.2.20", 5555)])

    def test_mismatched_socket_types_do_not_enrich_the_trace(self):
        summary, events = self.parse(capture_rows(transport="udp"))
        self.assertEqual(summary["network_endpoint_observer"]["status"], "uncorrelated")
        self.assertIsNone(events[1]["remote_ip"])

    def test_sendto_failure_uses_observed_udp_transport(self):
        self.source.write_text('24 socket(PF_INET,SOCK_DGRAM,IPPROTO_UDP) = 4\n'
            '24 sendto(4,0x8000,4,0,0x804a000,16) = -1 errno=113 (No route to host)\n')
        rows = capture_rows(transport="udp")
        rows[2].update(syscall="sendto", number=369, result=-113)
        _, events = self.parse(rows)
        requirement = RequirementExtractor().extract(ObservationBundle(
            run_dir=self.root, syscall_events=tuple(events))).requirements[0]
        self.assertEqual(requirement.resource, "udp://192.0.2.10:4444")
        self.assertEqual(requirement.operation, "datagram_exchange")

    def test_complete_address_without_transport_stays_manual(self):
        call = {"event": "syscall", "syscall": "connect", "execution_context": "guest",
                "errno": "ECONNREFUSED", "return_value": -1, "remote_ip": "192.0.2.10",
                "remote_port": 4444, "transport": "unknown"}
        requirement = RequirementExtractor().extract(ObservationBundle(
            run_dir=self.root, syscall_events=(call,))).requirements[0]
        self.assertFalse(requirement.repairable)
        self.assertTrue(requirement.resource.startswith("unresolved-connect"))

    def test_trace_changes_between_correlation_and_output_are_rejected(self):
        original = EndpointCapture.correlate
        def changed(capture, events):
            original(capture, events)
            self.source.write_text(self.source.read_text().replace("0x804a000", "0x804b000"))
        with patch.object(EndpointCapture, "correlate", changed):
            with self.assertRaises(QemuStraceParserError):
                self.parse(capture_rows())
        self.assertFalse(self.output.exists())

    def test_malformed_metadata_is_rejected_without_a_boolean_or_abi_guess(self):
        for field, value in [("vcpu", False), ("transport", {}), ("number", 999),
                             ("sockaddr_length", -1), ("remote_port", True), ("seq", 1.5)]:
            with self.subTest(field=field):
                rows = capture_rows()
                rows[2][field] = value
                with self.assertRaises(QemuStraceParserError):
                    self.parse(rows)

    def test_reprocessing_uses_the_bound_endpoint_artifact_without_running_guest(self):
        source = self.root / "original"
        (source / "logs/network_endpoints").mkdir(parents=True)
        (source / "config").mkdir()
        (source / "logs/qemu_strace.log").write_bytes(self.source.read_bytes())
        events = source / "logs/network_endpoints/events.jsonl"
        events.write_text("".join(json.dumps(row) + "\n" for row in capture_rows()))
        (source / "config/runtime.json").write_text('{"arch":"i386","network_mode":"none"}')
        (source / "config/phase1_binding.json").write_text(json.dumps({"session_id": "session", "attempt_id": "attempt",
            "network_observer": {"events": str(events)}}))
        before = {str(path.relative_to(source)): path.read_bytes() for path in source.rglob("*") if path.is_file()}
        result = reprocess(source, self.root / "reprocessed")
        self.assertFalse(result["guest_executed"])
        self.assertEqual(result["status"], "reprocessed")
        output = [json.loads(line) for line in (self.root / "reprocessed/logs/syscall_events.jsonl").read_text().splitlines()]
        self.assertEqual(output[1]["remote_ip"], "192.0.2.10")
        self.assertEqual(before, {str(path.relative_to(source)): path.read_bytes() for path in source.rglob("*") if path.is_file()})


class SocketTraceStateTests(unittest.TestCase):
    def setUp(self):
        self.state = SocketTraceTracker()

    def call(self, text):
        event = parse_strace_line("24 " + text, "strace.24", 1, "guest")
        self.state.apply(event)
        return event

    def test_udp_connected_peer_follows_dup_alias_and_is_cleared_on_reconnect(self):
        self.call("socket(PF_INET,SOCK_DGRAM|SOCK_CLOEXEC,IPPROTO_IP) = 4")
        self.call("dup(4) = 7")
        self.call('connect(7,{sa_family=AF_INET,sin_port=htons(4444),sin_addr=inet_addr("192.0.2.10")},16) = 0')
        sent = self.call('sendto(4,"hello",5,0,NULL,0) = 5')
        self.assertEqual((sent.transport, sent.remote_ip, sent.remote_port), ("udp", "192.0.2.10", 4444))
        self.call("connect(7,0x1,16) = -1 EFAULT (Bad address)")
        self.assertIsNone(self.call('sendto(4,"hello",5,0,NULL,0) = -1 ENOTCONN').remote_ip)

    def test_closed_fd_and_reuse_do_not_inherit_a_udp_peer(self):
        self.call("socket(2,524290,17) = 4")
        self.call('connect(4,{sa_family=AF_INET,sin_port=htons(4444),sin_addr=inet_addr("192.0.2.10")},16) = 0')
        self.call("close(4) = 0")
        self.call("socket(2,1,6) = 4")
        sent = self.call('sendto(4,"hello",5,0,NULL,0) = -1 ENOTCONN')
        self.assertEqual(sent.transport, "tcp")
        self.assertIsNone(sent.remote_ip)

    def test_bind_receive_and_buffer_text_are_not_remote_destinations(self):
        for name in ("bind", "recvfrom", "write"):
            with self.subTest(name=name):
                call = self.call(f'{name}(4,{{sa_family=AF_INET,sin_port=htons(4444),sin_addr=inet_addr("192.0.2.10")}},16) = 0')
                self.assertIsNone(call.remote_ip)
        self.assertEqual(printed_endpoint("sendto", '4,"inet_addr(\\\"192.0.2.99\\\")",20,0,NULL,0'), (None, None))

    def test_unknown_socket_type_and_unix_paths_do_not_imply_tcp(self):
        self.call("socket(PF_UNIX,SOCK_STREAM,0) = 4")
        call = self.call('connect(4,{sa_family=AF_UNIX,sun_path="inet_addr(\\\"192.0.2.10\\\")"},16) = -1 ECONNREFUSED')
        self.assertEqual(call.transport, "unknown")
        self.assertIsNone(call.remote_ip)

    def test_numeric_socket_types_from_an_unverified_abi_stay_unknown(self):
        self.state = SocketTraceTracker(target_arch="mipsel")
        self.call("socket(2,1,0) = 4")
        call = self.call('connect(4,{sa_family=AF_INET,sin_port=htons(4444),sin_addr=inet_addr("192.0.2.10")},16) = -1 ECONNREFUSED')
        self.assertEqual(call.transport, "unknown")


if __name__ == "__main__":
    unittest.main()
