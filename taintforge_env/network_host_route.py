"""Keep emulator replies on the owned veth when host policy routing uses a VPN."""
from __future__ import annotations

import ipaddress
import json
import os
import re


class NetworkHostRouteError(RuntimeError):
    pass


class HostReplyRoute:
    def __init__(self, *, executor, project_root, host_ip, namespace_ip, interface):
        self.executor = executor
        self.project_root = project_root
        self.host_ip = str(ipaddress.IPv4Address(host_ip))
        self.namespace_ip = str(ipaddress.IPv4Address(namespace_ip))
        if not re.fullmatch(r"tfh[0-9a-f]{8}", interface):
            raise NetworkHostRouteError("invalid owned host veth name")
        self.interface = interface
        self.uid = os.geteuid()
        self.priority = None
        self.rule_owned = False
        self.route_owned = False
        self.before = None
        self.after = None
        self.status = "unverified"

    def _run(self, command):
        result = self.executor.run(command, cwd=self.project_root, check=False)
        if result.returncode:
            raise NetworkHostRouteError(
                f"{' '.join(command)}: {result.stderr.strip() or 'exit ' + str(result.returncode)}")
        return result

    def _rows(self, command):
        result = self._run(command)
        try:
            rows = json.loads(result.stdout)
        except (ValueError, TypeError) as error:
            raise NetworkHostRouteError("invalid JSON from " + " ".join(command)) from error
        if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
            raise NetworkHostRouteError("invalid objects from " + " ".join(command))
        return rows

    def _lookup(self):
        rows = self._rows(["ip", "-j", "-4", "route", "get", self.namespace_ip,
                           "from", self.host_ip, "uid", str(self.uid)])
        if len(rows) != 1:
            raise NetworkHostRouteError("host reply route lookup did not return one route")
        return rows[0]

    def _direct(self, route):
        return route.get("dev") == self.interface and not route.get("gateway")

    def _rule_command(self, operation):
        return ["sudo", "-n", "ip", "-4", "rule", operation,
                "priority", str(self.priority), "from", self.host_ip + "/32",
                "to", self.namespace_ip + "/32", "lookup", "main"]

    def _route_command(self, operation):
        return ["sudo", "-n", "ip", "-4", "route", operation, self.namespace_ip + "/32",
                "dev", self.interface, "src", self.host_ip, "table", "main"]

    def ensure(self):
        self.before = self._lookup()
        if self._direct(self.before):
            self.after = self.before
            self.status = "verified"
            return

        rules = self._rows(["ip", "-j", "-4", "rule", "show"])
        priorities = []
        for rule in rules:
            priority = rule.get("priority")
            if type(priority) is not int or priority < 0:
                raise NetworkHostRouteError("host policy rule has no valid priority")
            if priority == 0 and rule.get("table") not in ("local", 255):
                raise NetworkHostRouteError("no free rule priority before host policy routing")
            priorities.append(priority)
        used = set(priorities)
        self.priority = next(priority for priority in range(1, len(used) + 2)
                             if priority not in used)

        routes = self._rows(["ip", "-j", "-4", "route", "show", "table", "main",
                             "exact", self.namespace_ip + "/32"])
        if routes and (len(routes) != 1 or not self._direct(routes[0])):
            raise NetworkHostRouteError("foreign host route already targets the guest address")
        if not routes:
            self._run(self._route_command("add"))
            self.route_owned = True
        self._run(self._rule_command("add"))
        self.rule_owned = True
        self.after = self._lookup()
        if not self._direct(self.after):
            raise NetworkHostRouteError(
                f"host reply route still bypasses {self.interface}: {self.after}")
        self.status = "verified"

    def remaining_resources(self):
        return (["host_reply_rule"] if self.rule_owned else []) + (
            ["host_reply_route"] if self.route_owned else [])

    def cleanup(self):
        failures = []
        for attribute, command in (("rule_owned", self._rule_command("del")),
                                   ("route_owned", self._route_command("del"))):
            if not getattr(self, attribute):
                continue
            try:
                result = self.executor.run(command, cwd=self.project_root, check=False)
                absent = any(marker in result.stderr.lower() for marker in (
                    "rtnetlink answers: no such file or directory",
                    "rtnetlink answers: no such process", "cannot find device"))
                if result.returncode == 0 or absent:
                    setattr(self, attribute, False)
                else:
                    failures.append(f"{' '.join(command)}: {result.stderr.strip()}")
            except Exception as error:
                failures.append(f"{' '.join(command)}: {type(error).__name__}: {error}")
        self.status = "cleanup_failed" if failures else "cleaned"
        if failures:
            raise NetworkHostRouteError("; ".join(failures))

    def snapshot(self):
        return {"status": self.status, "from": self.host_ip + "/32",
                "to": self.namespace_ip + "/32", "interface": self.interface,
                "lookup_uid": self.uid, "rule_priority": self.priority, "table": "main",
                "before": self.before, "verified_route": self.after,
                "remaining_resources": self.remaining_resources()}
