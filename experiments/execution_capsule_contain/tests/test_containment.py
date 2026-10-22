"""Host tests of admission, evidence and failure handling; not kernel sandbox acceptance."""
import argparse
import errno
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from experiments.execution_capsule_contain import controller as c

REPO = Path(__file__).resolve().parents[3]


class ContainmentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.data = self.root / "data"
        self.data.mkdir()
        self.canary = self.root / "host-only"
        self.canary.write_bytes(b"host canary")
        self.config = {"nonce": "test", "unit": "taintforge-capsule-test.service", "mode": "check",
            "memory_bytes": 1024 * c.MIB, "seconds": 60, "stage": str(self.root / "stage"),
            "data": str(self.data), "config_path": str(self.root / "stage/config.json"),
            "host_canary": str(self.canary), "host_canary_sha256": c.digest(self.canary),
            "host_namespaces": {name: f"{name}:[10]" for name in c.NAMESPACES}}
        self.group = "/user.slice/" + self.config["unit"]
        self.evidence = {"nonce": "test", "status": "passed", "cgroup": self.group,
            "namespaces": {name: f"{name}:[20]" for name in c.NAMESPACES},
            "limits": {"memory.max": str(1024*c.MIB), "memory.swap.max": "0", "memory.oom.group": "1", "pids.max": "64"},
            "no_new_privs": True, "capabilities_empty": True, "inputs_readonly": True,
            "host_paths_hidden": True, "nested_userns_rejected": True, "network_interfaces": ["lo"],
            "core_rlimit": [0, 0], "coredump_filter": 0, "core_pattern": "|/usr/bin/handler", **c.CLAIMS}

    def save_evidence(self, evidence=None):
        c.write_json(self.data / "containment.json", evidence or self.evidence)

    def test_cgroup_membership_rejects_root_legacy_and_traversal(self):
        self.assertEqual(c.membership("0::" + self.group + "\n"), Path(self.group))
        for value in ("0::/\n", "4:memory:/x\n", "0::/../outside\n", "0::/unit\n1:cpu:/x\n"):
            with self.subTest(value=value), self.assertRaises(RuntimeError):
                c.membership(value)

    def test_limits_are_read_from_kernel_files_and_fail_closed(self):
        for key, value in self.evidence["limits"].items():
            (self.root / key).write_text(value + "\n")
        self.assertEqual(c.limits(self.root, self.config), self.evidence["limits"])
        for key in self.evidence["limits"]:
            with self.subTest(key=key):
                (self.root / key).write_text("max\n")
                with self.assertRaises(RuntimeError):
                    c.limits(self.root, self.config)
                (self.root / key).write_text(self.evidence["limits"][key])
        (self.root / "memory.swap.max").unlink()
        with self.assertRaises(FileNotFoundError):
            c.limits(self.root, self.config)

    def test_launcher_has_no_unbounded_or_privileged_fallback(self):
        command = c.systemd_command(self.config, Path("/safe input/contain.py"))
        self.assertIn("--property=MemoryMax=1073741824", command)
        for arg in ("--user", "--wait", "--pipe", "--expand-environment=no", "--property=MemorySwapMax=0",
                    "--property=OOMPolicy=kill", "--property=KillMode=control-group", "--property=LimitCORE=0"):
            self.assertIn(arg, command)
        self.assertNotIn("--collect", command)  # OOM evidence must remain available.
        self.assertNotIn("sudo", command)
        self.assertEqual(command[-3:], ["/safe input/contain.py", "_enter", self.config["config_path"]])
        wrapped = c.bubblewrap_command(self.config, Path("/sys/fs/cgroup/owned"))
        for arg in ("--unshare-user", "--unshare-pid", "--unshare-net", "--disable-userns", "--clearenv"):
            self.assertIn(arg, wrapped)
        self.assertFalse(any(arg in wrapped for arg in ("--unshare-user-try", "--share-net", "--bind-try")))
        binds = [wrapped[i+1:i+3] for i, arg in enumerate(wrapped) if arg == "--bind"]
        self.assertEqual(binds, [[self.config["data"], "/out"]])
        self.assertNotIn(str(REPO), wrapped)

    def test_saved_evidence_does_not_promote_false_guarantees(self):
        self.save_evidence()
        self.assertFalse(c.verify(self.config, 0, {})["residue_free"])
        mutations = [dict(nonce="old"), dict(status="failed"), dict(inputs_readonly=False),
                     dict(residue_free=True), dict(core_rlimit=[0, -1]), dict(coredump_filter=51),
                     dict(network_interfaces=["eth0"]), dict(cgroup="/different.service"),
                     dict(namespaces=self.config["host_namespaces"])]
        for change in mutations:
            with self.subTest(change=change), self.assertRaises(RuntimeError):
                self.save_evidence({**self.evidence, **change})
                c.verify(self.config, 0, {})
        self.save_evidence()
        with self.assertRaises(RuntimeError):
            c.verify(self.config, 1, {})

    def test_canary_changes_are_rejected(self):
        self.save_evidence()
        self.canary.write_bytes(b"changed")
        with self.assertRaises(RuntimeError):
            c.verify(self.config, 0, {})

    def test_oom_requires_kernel_manager_attribution_and_started_marker(self):
        self.config.update(mode="oom-check", memory_bytes=128*c.MIB)
        self.evidence["limits"]["memory.max"] = str(128*c.MIB)
        self.save_evidence()
        marker = self.data / "pressure.json"
        with self.assertRaises(FileNotFoundError):
            c.verify(self.config, 137, {"Result": "oom-kill"})
        c.write_json(marker, {"nonce": "test", "started": True, "maximum_bytes": 256*c.MIB})
        self.assertEqual(c.verify(self.config, 137, {"Result": "oom-kill"})["status"], "passed")
        for code, reason in ((0, "oom-kill"), (137, "signal"), (1, "exit-code"), (1, "timeout")):
            with self.subTest(code=code, reason=reason), self.assertRaises(RuntimeError):
                c.verify(self.config, code, {"Result": reason})

    def test_suite_requires_real_retirement_success_and_same_qemu(self):
        self.save_evidence()
        self.config.update(mode="suite", runtime={"qemu": {"sha256": "expected"}})
        target = self.data / "retirement/report.json"
        target.parent.mkdir()
        for report in ({"status": "failed", "cases": [1]}, {"status": "passed", "cases": []},
                       {"status": "passed", "cases": [1], "qemu": {"sha256": "other"}}):
            c.write_json(target, report)
            with self.assertRaises(RuntimeError):
                c.verify(self.config, 0, {})
        c.write_json(target, {"status": "passed", "cases": [1], "qemu": {"sha256": "expected"}})
        c.verify(self.config, 0, {})

    def kernel_fixture(self):
        kernel = self.root / "kernel"
        files = {"/proc/self/cgroup": "0::" + self.group + "\n",
                 "/proc/self/status": "NoNewPrivs:\t1\n" + "".join(f"{k}:\t0000\n" for k in
                     ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")),
                 "/proc/self/coredump_filter": "00000000\n", "/proc/sys/kernel/core_pattern": "|/handler\n",
                 "/proc/net/dev": "header\nheader\n lo: 0 0 0\n", "/repo/readonly-canary": "readonly",
                 "/out/entry.json": json.dumps({"nonce": "test", "cgroup": self.group})}
        files.update({"/cgroup/" + k: v for k, v in self.evidence["limits"].items()})
        for name, text in files.items():
            path = kernel / name.lstrip("/")
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
        (kernel / "tmp").mkdir()
        def mapped(value):
            value = Path(value)
            return kernel / str(value).lstrip("/") if value.is_absolute() else value
        return kernel, mapped

    def test_live_inspection_checks_kernel_state_before_execution(self):
        kernel, mapped = self.kernel_fixture()
        original_open = os.open
        def checked_open(path, *args, **kwargs):
            if str(path).endswith("/repo/readonly-canary"):
                raise OSError(errno.EROFS, "readonly")
            return original_open(path, *args, **kwargs)
        with patch.object(c, "Path", side_effect=mapped), patch.object(c, "namespaces", return_value=self.evidence["namespaces"]), \
             patch.object(c.os, "statvfs", return_value=argparse.Namespace(f_flag=os.ST_RDONLY)), \
             patch.object(c.os, "open", side_effect=checked_open), \
             patch.object(c.resource, "getrlimit", return_value=(0, 0)), \
             patch.object(c, "run", return_value=argparse.Namespace(returncode=1)):
            result = c.inspect_inside(self.config)
            self.assertEqual(result["core_pattern"], "|/handler")
            self.assertFalse(result["complete_core_dump_prevention"])
            tests = (("/proc/self/status", "NoNewPrivs:\t0\n"),
                     ("/proc/net/dev", "h\nh\n eth0: 0\n"),
                     ("/cgroup/memory.max", "max\n"))
            for name, value in tests:
                target = kernel / name.lstrip("/")
                old = target.read_text()
                target.write_text(value)
                with self.subTest(name=name), self.assertRaises(RuntimeError):
                    c.inspect_inside(self.config)
                target.write_text(old)

    def test_inner_failure_never_enters_pressure_or_suite(self):
        with patch.object(c, "inspect_inside", side_effect=RuntimeError("not contained")), \
             patch.object(c.mmap, "mmap") as allocation:
            for mode in ("check", "oom-check", "suite"):
                with self.subTest(mode=mode), self.assertRaises(RuntimeError):
                    c.inside({**self.config, "mode": mode})
            allocation.assert_not_called()

    def test_prepare_rejects_root_and_unknown_source_before_launch(self):
        args = argparse.Namespace(repo=REPO, memory_mib=1024, mode="check", case="all")
        with patch.object(c.os, "getuid", return_value=0), patch.object(c, "run") as launch:
            with self.assertRaisesRegex(RuntimeError, "without sudo"):
                c.prepare(args, self.root)
            launch.assert_not_called()
        with patch.object(c.os, "getuid", return_value=1000), patch.object(c, "digest", return_value="changed"), \
             patch.object(c, "run") as launch:
            with self.assertRaisesRegex(RuntimeError, "Source version changed"):
                c.prepare(args, self.root)
            launch.assert_not_called()

    def test_prepare_snapshots_only_reviewed_files(self):
        args = argparse.Namespace(repo=REPO, memory_mib=1024, mode="check", case="all")
        def commands(*argv, **kwargs):
            return argparse.Namespace(returncode=0, stdout="--disable-userns --assert-userns-disabled\n", stderr="")
        out = self.root / "prepared"
        out.mkdir()
        with patch.object(c.os, "getuid", return_value=1000), patch.object(c, "run", side_effect=commands):
            config = c.prepare(args, out)
        copied = Path(config["stage"])
        for name, expected in config["source_hashes"].items():
            self.assertEqual(c.digest(copied / name), expected)
        self.assertFalse((copied / ".git").exists())
        self.assertFalse((copied / "workdir").exists())
        self.assertFalse((copied / "unpacker").exists())

    def test_external_error_does_not_retry_without_service(self):
        args = argparse.Namespace(out=self.root / "outer", mode="check", repo=REPO)
        with patch.object(c, "prepare", side_effect=RuntimeError("no user manager")), \
             patch.object(c.subprocess, "Popen") as launch:
            self.assertEqual(c.supervise(args), 1)
            launch.assert_not_called()
        report = c.read_json(args.out / "report.json")
        self.assertEqual(report["status"], "failed")
        self.assertFalse(report["hostile_sample_ready"])

    def test_unit_failure_is_preserved_and_cleanup_targets_own_unit(self):
        args = argparse.Namespace(out=self.root / "outer", mode="check", repo=REPO)
        process = Mock(returncode=1)
        process.poll.return_value = 1
        manager = Mock(return_value=argparse.Namespace(returncode=0, stdout="", stderr=""))
        with patch.object(c, "prepare", return_value=self.config), patch.object(c.subprocess, "Popen", return_value=process), \
             patch.object(c, "unit_status", side_effect=[{"Result": "exit-code"}, {"LoadState": "not-found"}]), \
             patch.object(c, "run", manager):
            self.assertEqual(c.supervise(args), 1)
        self.assertTrue(c.read_json(args.out / "report.json")["unit_stopped"])
        for call in manager.call_args_list:
            self.assertEqual(call.args[-1], self.config["unit"])

    def test_cleanup_failure_cannot_leave_passed_report(self):
        self.save_evidence()
        self.config["source_hashes"] = {}
        args = argparse.Namespace(out=self.root / "outer", mode="check", repo=REPO)
        process = Mock(returncode=0)
        process.poll.return_value = 0
        with patch.object(c, "prepare", return_value=self.config), patch.object(c.subprocess, "Popen", return_value=process), \
             patch.object(c, "unit_status", side_effect=[{}, {"ActiveState": "active"}]), \
             patch.object(c, "run", return_value=argparse.Namespace(returncode=1, stderr="stop failed")):
            self.assertEqual(c.supervise(args), 1)
        report = c.read_json(args.out / "report.json")
        self.assertFalse(report["unit_stopped"])
        self.assertIn("cleanup_error", report)

    def test_deadline_stops_service_and_reaps_client(self):
        args = argparse.Namespace(out=self.root / "outer", mode="check", repo=REPO)
        process = Mock()
        process.poll.return_value = None
        with patch.object(c, "prepare", return_value=self.config), patch.object(c.subprocess, "Popen", return_value=process), \
             patch.object(c.time, "monotonic", side_effect=[0, 1000]), \
             patch.object(c, "unit_status", return_value={"LoadState": "not-found"}), \
             patch.object(c, "run", return_value=argparse.Namespace(returncode=0, stderr="")) as manager:
            self.assertEqual(c.supervise(args), 1)
        process.kill.assert_called_once()
        process.wait.assert_called_once()
        self.assertEqual(manager.call_args_list[0].args, ("systemctl", "--user", "stop", self.config["unit"]))
        self.assertIn("deadline", c.read_json(args.out / "report.json")["error"])

    def test_inactive_unit_with_remaining_processes_is_a_failure(self):
        self.save_evidence()
        self.config["source_hashes"] = {}
        c.write_json(self.data / "entry.json", {"cgroup": self.group})
        events = self.root / "cgroups" / self.group.lstrip("/") / "cgroup.events"
        events.parent.mkdir(parents=True)
        events.write_text("populated 1\nfrozen 0\n")
        args = argparse.Namespace(out=self.root / "outer", mode="check", repo=REPO)
        process = Mock(returncode=0)
        process.poll.return_value = 0
        with patch.object(c, "prepare", return_value=self.config), patch.object(c, "CGROUP", self.root / "cgroups"), \
             patch.object(c.subprocess, "Popen", return_value=process), \
             patch.object(c, "unit_status", return_value={"ActiveState": "inactive"}), \
             patch.object(c, "run", return_value=argparse.Namespace(returncode=0, stderr="")):
            self.assertEqual(c.supervise(args), 1)
        self.assertIn("still populated", c.read_json(args.out / "report.json")["cleanup_error"])

    def test_report_reader_rejects_symlink_fifo_and_oversized_file(self):
        target = self.root / "report.json"
        target.symlink_to(self.canary)
        with self.assertRaises(OSError):
            c.read_json(target)
        target.unlink()
        os.mkfifo(target)
        with self.assertRaises(RuntimeError):
            c.read_json(target)
        target.unlink()
        target.write_bytes(b" " * (c.MIB + 1))
        with self.assertRaises(RuntimeError):
            c.read_json(target)


if __name__ == "__main__":
    unittest.main()
