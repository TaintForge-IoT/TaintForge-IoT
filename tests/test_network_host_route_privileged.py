"""Exercise VPN policy routing and UDP DNAT entirely in disposable namespaces."""
import json
import os
from pathlib import Path
import select
import shutil
import subprocess
import sys
import unittest
import uuid

from taintforge_env.network_host_route import HostReplyRoute


class NamespaceExecutor:
    def __init__(self, namespace):
        self.namespace = namespace

    def run(self, command, *, cwd, check=True):
        command = list(command)
        if command[:2] == ["sudo", "-n"]:
            command = command[2:]
        return subprocess.run(["ip", "netns", "exec", self.namespace, *command],
                              capture_output=True, text=True, timeout=5, check=check)


SERVER = r'''
import os, socket
os.setgroups([])
os.setgid(65534)
os.setuid(65534)
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as stream:
    stream.bind(("10.203.25.1", 20604))
    stream.settimeout(10)
    print("ready", flush=True)
    for index in range(2):
        payload, peer = stream.recvfrom(64)
        if payload != b"ping":
            raise RuntimeError("unexpected UDP request")
        stream.sendto(b"pong", peer)
'''

CLIENT = r'''
import json, os, socket
os.setgroups([])
os.setgid(65534)
os.setuid(65534)
result = {"received": False}
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as stream:
    stream.settimeout(.5)
    stream.connect(("192.0.2.10", 54750))
    stream.send(b"ping")
    try:
        payload, peer = stream.recvfrom(64)
        result = {"received": True, "payload": payload.hex(), "peer": list(peer)}
    except TimeoutError:
        pass
print(json.dumps(result))
'''


@unittest.skipUnless(os.geteuid() == 0, "requires root and network namespace privileges")
class HostReplyRoutePrivilegedTests(unittest.TestCase):
    def setUp(self):
        if not all(shutil.which(tool) for tool in ("ip", "iptables")):
            self.skipTest("requires ip and iptables")
        suffix = uuid.uuid4().hex[:8]
        self.host = "tf-route-h-" + suffix
        self.guest = "tf-route-g-" + suffix
        self.interface = "tfh" + suffix
        self.peer = "tfn" + suffix
        self.owned_namespaces = []
        self.server = None
        self.route = None
        self.addCleanup(self.cleanup)
        self.host_rules_before = self.run_command("ip", "-j", "-4", "rule", "show").stdout
        for namespace in (self.host, self.guest):
            self.run_command("ip", "netns", "add", namespace)
            self.owned_namespaces.append(namespace)
        self.run_command("ip", "-n", self.host, "link", "add", self.interface,
                         "type", "veth", "peer", "name", self.peer)
        self.run_command("ip", "-n", self.host, "link", "set", self.peer, "netns", self.guest)
        for namespace, interface, address in ((self.host, self.interface, "10.203.25.1/24"),
                                               (self.guest, self.peer, "10.203.25.2/24")):
            self.run_command("ip", "-n", namespace, "addr", "add", address, "dev", interface)
            self.run_command("ip", "-n", namespace, "link", "set", interface, "up")
            self.run_command("ip", "-n", namespace, "link", "set", "lo", "up")
            self.run_command("ip", "netns", "exec", namespace, "sysctl", "-q", "-w",
                             "net.ipv4.conf.all.rp_filter=0", f"net.ipv4.conf.{interface}.rp_filter=0")
        self.run_command("ip", "-n", self.guest, "route", "add", "default", "via", "10.203.25.1")
        self.run_command("ip", "-n", self.host, "link", "add", "tun0", "type", "dummy")
        self.run_command("ip", "-n", self.host, "link", "set", "tun0", "up")
        self.run_command("ip", "-n", self.host, "route", "add", "default", "dev", "tun0", "table", "2022")
        self.run_command("ip", "-n", self.host, "rule", "add", "priority", "9002", "lookup", "2022")
        self.run_command("ip", "netns", "exec", self.guest, "iptables", "-t", "nat", "-A", "OUTPUT",
                         "-p", "udp", "-d", "192.0.2.10", "--dport", "54750", "-j", "DNAT",
                         "--to-destination", "10.203.25.1:20604")
        self.route = HostReplyRoute(executor=NamespaceExecutor(self.host), project_root=Path.cwd(),
            host_ip="10.203.25.1", namespace_ip="10.203.25.2", interface=self.interface)

    @staticmethod
    def run_command(*command):
        return subprocess.run(command, capture_output=True, text=True, timeout=5, check=True)

    def client(self):
        result = self.run_command("ip", "netns", "exec", self.guest, sys.executable, "-c", CLIENT)
        return json.loads(result.stdout)

    def test_connected_udp_reply_avoids_policy_tunnel_and_cleanup_restores_policy(self):
        original_rules = json.loads(self.run_command(
            "ip", "-n", self.host, "-j", "-4", "rule", "show").stdout)
        self.assertTrue(any(rule.get("priority") == 9002 for rule in original_rules),
                        "baseline policy rule was not installed")
        self.server = subprocess.Popen(["ip", "netns", "exec", self.host, sys.executable, "-u", "-c", SERVER],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.assertTrue(select.select([self.server.stdout], [], [], 5)[0], "UDP responder did not start")
        self.assertEqual(self.server.stdout.readline().strip(), "ready")
        self.assertFalse(self.client()["received"], "baseline should divert replies into the dummy tunnel")
        self.route.ensure()
        self.assertEqual(self.route.before["dev"], "tun0")
        self.assertEqual(self.route.after["dev"], self.interface)
        reply = self.client()
        self.assertEqual(reply, {"received": True, "payload": b"pong".hex(), "peer": ["192.0.2.10", 54750]})
        self.server.wait(timeout=5)
        self.assertEqual(self.server.returncode, 0, self.server.stderr.read())
        self.route.cleanup()
        self.assertEqual(self.route._lookup()["dev"], "tun0")
        self.assertEqual(self.route.remaining_resources(), [])
        rules = json.loads(self.run_command("ip", "-n", self.host, "-j", "-4", "rule", "show").stdout)
        self.assertEqual(rules, original_rules,
                         "isolated host policy rules changed after route cleanup")
        self.assertFalse(any(rule.get("priority") == self.route.priority for rule in rules))

    def cleanup(self):
        errors = []
        if self.server is not None:
            if self.server.poll() is None:
                self.server.kill()
            self.server.communicate(timeout=5)
        if self.route is not None:
            try:
                self.route.cleanup()
            except Exception as error:
                errors.append(str(error))
        for namespace in reversed(self.owned_namespaces):
            try:
                self.run_command("ip", "netns", "del", namespace)
            except Exception as error:
                errors.append(str(error))
        after = self.run_command("ip", "-j", "-4", "rule", "show").stdout
        self.assertEqual(after, self.host_rules_before, "real host policy rules changed")
        self.assertEqual(errors, [], "disposable namespace cleanup failed")


if __name__ == "__main__":
    unittest.main()
