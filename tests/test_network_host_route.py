"""Regression coverage for replies diverted into a host VPN routing table."""
import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch

from taintforge_env.network_host_route import HostReplyRoute, NetworkHostRouteError
from taintforge_env.controlled_network_backend import ControlledNetworkError
from tests import test_controlled_network_backend as fixtures
from tests.test_controlled_network_backend import FakeExecutor, FakeResult, FakeSupervisor


class RouteExecutor(FakeExecutor):
    def __init__(self):
        super().__init__()
        self.rules = [{"priority": 0, "table": "local"},
                      {"priority": 9001, "table": 2022, "suppress_prefixlength": 0},
                      {"priority": 9002, "table": 2022},
                      {"priority": 32766, "table": "main"}]
        self.route = []
        self.rule_added = False
        self.current_dev = "tun0"
        self.keep_tunnel = False
        self.fail_rule_add = False
        self.fail_rule_delete = False
        self.already_absent = False

    def run(self, command, **kwargs):
        command = list(map(str, command))
        if command[:5] == ["ip", "-j", "-4", "route", "get"]:
            self.commands.append(command)
            dev = (self.route[0]["dev"] if self.rule_added and not self.keep_tunnel
                   else self.current_dev)
            return FakeResult(stdout=json.dumps([{"dev": dev, "dst": command[5]}]))
        if command == ["ip", "-j", "-4", "rule", "show"]:
            self.commands.append(command)
            return FakeResult(stdout=json.dumps(self.rules))
        if command[:8] == ["ip", "-j", "-4", "route", "show", "table", "main", "exact"]:
            self.commands.append(command)
            return FakeResult(stdout=json.dumps(self.route))
        if command[:5] in (["sudo", "-n", "ip", "-4", "route"],
                           ["sudo", "-n", "ip", "-4", "rule"]):
            self.commands.append(command)
            kind, operation = command[4:6]
            if kind == "rule" and operation == "add":
                if self.fail_rule_add:
                    return FakeResult(2, stderr="RTNETLINK answers: Operation not permitted")
                self.rule_added = True
            elif kind == "rule":
                if self.fail_rule_delete:
                    return FakeResult(2, stderr="RTNETLINK answers: Operation not permitted")
                self.rule_added = False
            elif operation == "add":
                self.route = [{"dst": command[6], "dev": command[8]}]
            else:
                self.route = []
            if self.already_absent and operation == "del":
                return FakeResult(2, stderr="RTNETLINK answers: No such file or directory")
            return FakeResult()
        return super().run(command, **kwargs)


class HostReplyRouteTests(unittest.TestCase):
    def setUp(self):
        self.executor = RouteExecutor()
        self.guard = HostReplyRoute(executor=self.executor, project_root=Path.cwd(),
            host_ip="10.203.25.1", namespace_ip="10.203.25.2", interface="tfhb224dc23")

    def mutations(self):
        return [command for command in self.executor.commands if command[:2] == ["sudo", "-n"]]

    def test_vpn_report_is_repaired_with_an_exact_address_pair(self):
        self.guard.ensure()
        self.assertEqual(self.guard.snapshot()["before"]["dev"], "tun0")
        self.assertEqual(self.guard.snapshot()["verified_route"]["dev"], "tfhb224dc23")
        self.assertEqual(self.mutations(), [
            ["sudo", "-n", "ip", "-4", "route", "add", "10.203.25.2/32", "dev", "tfhb224dc23",
             "src", "10.203.25.1", "table", "main"],
            ["sudo", "-n", "ip", "-4", "rule", "add", "priority", "1", "from", "10.203.25.1/32",
             "to", "10.203.25.2/32", "lookup", "main"],
        ])
        self.assertEqual(self.executor.commands[-1][-2:], ["uid", str(os.geteuid())])
        self.guard.cleanup()
        self.assertEqual(self.guard.remaining_resources(), [])
        self.assertEqual(self.guard.snapshot()["status"], "cleaned")
        self.assertEqual(self.executor.rules[1]["table"], 2022)

    def test_correct_existing_route_requires_no_host_mutation(self):
        self.executor.current_dev = "tfhb224dc23"
        self.guard.ensure()
        self.guard.cleanup()
        self.assertEqual(self.mutations(), [])

    def test_existing_exact_veth_route_is_reused_and_preserved(self):
        self.executor.route = [{"dst": "10.203.25.2/32", "dev": "tfhb224dc23"}]
        self.guard.ensure()
        self.guard.cleanup()
        self.assertEqual(len(self.executor.route), 1)
        self.assertTrue(all(command[4] == "rule" for command in self.mutations()))

    def test_foreign_exact_route_is_not_replaced(self):
        self.executor.route = [{"dst": "10.203.25.2/32", "dev": "other-veth"}]
        with self.assertRaisesRegex(NetworkHostRouteError, "foreign host route"):
            self.guard.ensure()
        self.guard.cleanup()
        self.assertEqual(self.mutations(), [])

    def test_another_scoped_rule_keeps_its_priority(self):
        self.executor.rules.insert(1, {"priority": 1, "table": "main", "src": "10.203.26.1"})
        self.guard.ensure()
        self.assertEqual(self.guard.priority, 2)
        self.guard.cleanup()

    def test_priority_zero_policy_cannot_be_overridden(self):
        self.executor.rules.insert(1, {"priority": 0, "table": 2022})
        with self.assertRaisesRegex(NetworkHostRouteError, "no free rule priority"):
            self.guard.ensure()
        self.assertEqual(self.mutations(), [])

    def test_route_is_verified_after_rule_insertion(self):
        self.executor.keep_tunnel = True
        with self.assertRaisesRegex(NetworkHostRouteError, "still bypasses"):
            self.guard.ensure()
        self.guard.cleanup()
        self.assertEqual(self.guard.remaining_resources(), [])

    def test_failed_rule_insertion_rolls_back_only_the_added_route(self):
        self.executor.fail_rule_add = True
        with self.assertRaisesRegex(NetworkHostRouteError, "Operation not permitted"):
            self.guard.ensure()
        self.assertEqual(self.guard.remaining_resources(), ["host_reply_route"])
        self.guard.cleanup()
        self.assertEqual(len([command for command in self.mutations() if command[5] == "del"]), 1)
        self.assertEqual(self.guard.remaining_resources(), [])

    def test_cleanup_failure_retains_resource_evidence_and_can_be_retried(self):
        self.guard.ensure()
        self.executor.fail_rule_delete = True
        with self.assertRaisesRegex(NetworkHostRouteError, "Operation not permitted"):
            self.guard.cleanup()
        self.assertEqual(self.guard.remaining_resources(), ["host_reply_rule"])
        self.assertEqual(self.guard.snapshot()["status"], "cleanup_failed")
        self.executor.fail_rule_delete = False
        self.guard.cleanup()
        self.assertEqual(self.guard.remaining_resources(), [])

    def test_already_removed_resources_are_idempotent(self):
        self.guard.ensure()
        self.executor.already_absent = True
        self.guard.cleanup()
        count = len(self.mutations())
        self.guard.cleanup()
        self.assertEqual(len(self.mutations()), count)

    def test_invalid_route_json_is_not_treated_as_success(self):
        with patch.object(self.executor, "run", return_value=FakeResult(stdout="")):
            with self.assertRaisesRegex(NetworkHostRouteError, "invalid JSON"):
                self.guard.ensure()
        self.assertEqual(self.guard.remaining_resources(), [])


class HostReplyRouteBackendTests(unittest.TestCase):
    setUp = fixtures.ControlledNetworkBackendTests.setUp
    tearDown = fixtures.ControlledNetworkBackendTests.tearDown
    make_backend = fixtures.ControlledNetworkBackendTests.make_backend

    @patch("taintforge_env.controlled_network_backend.shutil.which", return_value="/bin/tool")
    def test_backend_verifies_routing_and_records_cleanup(self, _which):
        self.executor = RouteExecutor()
        backend = self.make_backend()
        backend.setup()
        backend.cleanup()
        manifest = json.loads(backend.manifest_path.read_text())
        routing = manifest["host_reply_routing"]
        self.assertEqual(routing["before"]["dev"], "tun0")
        self.assertEqual(routing["verified_route"]["dev"], backend.plan.veth_host)
        self.assertEqual(routing["status"], "cleaned")
        self.assertEqual(backend._remaining_resources(), [])

    @patch("taintforge_env.controlled_network_backend.shutil.which", return_value="/bin/tool")
    def test_later_setup_failure_cleans_the_owned_host_rule(self, _which):
        self.executor = RouteExecutor()
        backend = self.make_backend(supervisor=FakeSupervisor(immediate_exit=True))
        with self.assertRaisesRegex(ControlledNetworkError, "exited during startup"):
            backend.setup()
        self.assertEqual(backend._remaining_resources(), [])
        self.assertFalse(self.executor.rule_added)

    @patch("taintforge_env.controlled_network_backend.shutil.which", return_value="/bin/tool")
    def test_retained_host_rule_prevents_clean_runtime_status(self, _which):
        self.executor = RouteExecutor()
        backend = self.make_backend()
        backend.setup()
        self.executor.fail_rule_delete = True
        with self.assertRaisesRegex(ControlledNetworkError, "host reply routing"):
            backend.cleanup()
        status = json.loads((backend.logs_dir / "network_runtime_status.json").read_text())
        self.assertEqual(status["cleanup_status"], "cleanup_failed")
        self.assertIn("host_reply_rule", status["remaining_resources"])
        self.executor.fail_rule_delete = False
        backend.cleanup()


if __name__ == "__main__":
    unittest.main()
