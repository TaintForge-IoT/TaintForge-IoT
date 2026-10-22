import json
from pathlib import Path
import socket
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from taintforge_env.controlled_network_backend import ControlledNetworkBackend, ControlledNetworkConfig
from taintforge_env.models import NetworkDependency
from taintforge_env.network_policy import NetworkPolicy, NetworkServicePolicy, build_network_policy, build_service_policy
from taintforge_env.network_record import validate_record_policy
from taintforge_env.replay_store import ReplayStore
from tests.test_controlled_network_backend import FakeExecutor, FakePortAllocator, FakeSupervisor


class DatagramBackendTests(unittest.TestCase):
    def test_dns_observed_over_both_transports_has_one_service_each(self):
        taint = SimpleNamespace(network_dependencies=[NetworkDependency("127.0.0.1", 53, kind)
                                for kind in ("tcp", "dns", "udp")])
        policy = build_network_policy(taint, check_bind_availability=False)
        self.assertEqual(len(policy.services), 2)
        self.assertEqual({s.service_type for s in policy.services}, {"tcp", "udp"})
        self.assertTrue(all(s.protocol_hint == "dns" for s in policy.services))

    def test_udp_policy_avoids_an_occupied_udp_port(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as occupied:
            occupied.bind(("127.0.0.1", 0))
            port = occupied.getsockname()[1]
            service = build_service_policy(NetworkDependency("198.51.100.10", port, "udp"), "127.0.0.1")
            self.assertNotEqual(service.bind_port, port)

    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        (self.root / "scripts").mkdir()
        for name in ("start_network_replay.py", "start_network_record.py"):
            (self.root / "scripts" / name).write_text("pass\n")
        self.run = self.root / "run"
        (self.run / "config").mkdir(parents=True)
        (self.run / "logs").mkdir()
        self.policy = self.run / "config/template.json"
        self.executor, self.supervisor = FakeExecutor(), FakeSupervisor()

    @patch("taintforge_env.controlled_network_backend.shutil.which", return_value="/usr/bin/tool")
    def test_udp_replay_is_mapped_and_has_no_fallback(self, _which):
        service = NetworkServicePolicy("udp", "c2", "198.51.100.10", 48102, None, "127.0.0.1", 48102, "udp")
        self.policy.write_text(json.dumps(NetworkPolicy(services=[service]).to_dict()))
        store = ReplayStore(self.root / "store")
        store.add(transport="udp", remote_ip=service.remote_ip, remote_port=service.remote_port,
                  request_bytes=b"hello", response_bytes=b"world", protocol_hint="udp")
        backend = ControlledNetworkBackend(ControlledNetworkConfig(self.root, self.run, self.policy, "test", 0,
            responder_mode="replay", replay_store_path=store.root,
            replay_store_expected_sha256=store.validate()["store_sha256"], process_start_grace_seconds=0),
            executor=self.executor, process_supervisor=self.supervisor, port_allocator=FakePortAllocator())
        result = backend.setup()
        try:
            commands = [" ".join(command) for command in self.executor.commands]
            self.assertTrue(any("-p udp -d 198.51.100.10 --dport 48102 -j DNAT" in c for c in commands))
            self.assertFalse(result.plan.catch_all_enabled)
            self.assertTrue(all(any(arg.endswith("start_network_replay.py") for arg in p.command) for p in self.supervisor.started))
            self.assertFalse(any(any(arg.endswith("start_network_record.py") for arg in p.command) for p in self.supervisor.started))
        finally:
            backend.cleanup()
        self.assertTrue(all(p.terminated for p in self.supervisor.started))

    @patch("taintforge_env.controlled_network_backend.shutil.which", return_value="/usr/bin/tool")
    def test_loopback_dns_record_forwarding_stays_policy_bound(self, _which):
        services = [NetworkServicePolicy(t, "dns", "127.0.0.1", 53, None, "127.0.0.1", 53,
                    "dns", "127.0.0.1", 5353) for t in ("udp", "tcp")]
        policy = NetworkPolicy(services=services, recording={"capture_kind": "local_test", "run_id": "test"})
        self.policy.write_text(json.dumps(policy.to_dict()))
        backend = ControlledNetworkBackend(ControlledNetworkConfig(self.root, self.run, self.policy, "test", 0,
            responder_mode="record", process_start_grace_seconds=0), executor=self.executor,
            process_supervisor=self.supervisor, port_allocator=FakePortAllocator())
        result = backend.setup()
        try:
            self.assertEqual(len(result.plan.host_services), 2)
            self.assertFalse(result.plan.loopback_services)
            self.assertFalse(result.plan.catch_all_enabled)
            commands = [" ".join(command) for command in self.executor.commands]
            for transport in ("udp", "tcp"):
                self.assertTrue(any(f"-p {transport} -d 127.0.0.1 --dport 53 -j DNAT" in c for c in commands))
                self.assertTrue(any(f"POSTROUTING -p {transport} -s 127.0.0.0/8" in c and "-j SNAT" in c for c in commands))
            self.assertTrue(any("route_localnet=1" in c for c in commands))
            effective = json.loads(result.effective_policy_path.read_text())
            self.assertFalse(effective["allow_internet"])
            self.assertEqual(effective["recording"]["run_id"], "test")
            self.assertEqual(effective["services"][0]["upstream_ip"], "127.0.0.1")
        finally:
            backend.cleanup()

    def test_live_dns_requires_explicit_policy(self):
        service = NetworkServicePolicy("udp", "dns", "127.0.0.1", 53, None, "127.0.0.1", 5353,
                                       "dns", "9.9.9.9", 53)
        policy = NetworkPolicy(services=[service], recording={"capture_kind": "live", "run_id": "test"})
        with self.assertRaisesRegex(ValueError, "acknowledged"):
            validate_record_policy(policy)
        policy.recording["live_capture_acknowledged"] = True
        self.assertEqual(validate_record_policy(policy)["capture_kind"], "live")
        service.upstream_ip = "dns.example"
        with self.assertRaisesRegex(ValueError, "IP literals"):
            validate_record_policy(policy)
