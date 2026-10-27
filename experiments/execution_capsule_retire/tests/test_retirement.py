"""Real host memory lifecycle + mocked QEMU scheduling; no QEMU acceptance claim."""
import copy
import json
import os
from pathlib import Path
import select
import shlex
import signal
import struct
import subprocess
import tempfile
import unittest

from experiments.execution_capsule_retire import controller as retirement

probe = retirement.probe


class HostRetirement(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="tfc-retire-tests-")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.build = Path(cls.temporary.name)
        cls.plugin = cls.build / "libcapsule_retire.so"
        cls.harness = cls.build / "host_harness"
        # Override only for constrained development hosts with saved GLib headers.
        extra = os.environ.get("RETIRE_TEST_CFLAGS")
        flags = shlex.split(extra if extra is not None else probe.command("pkg-config", "--cflags", "glib-2.0"))
        sanitizer = shlex.split(os.environ.get("RETIRE_TEST_SANITIZER_FLAGS", ""))
        common = ["cc", "-std=c11", "-O2", "-g", "-Wall", "-Wextra", "-Werror", "-Wformat=2",
                  "-Wshadow", "-I", str(probe.HERE / "vendor"), *flags, *sanitizer]
        subprocess.run([*common, "-fPIC", "-fvisibility=hidden", "-shared", "-Wl,-z,relro,-z,now",
                        str(retirement.HERE / "retire.c"), "-o", str(cls.plugin)], check=True)
        subprocess.run([*common, "-rdynamic", str(Path(__file__).with_name("host_harness.c")),
                        "-o", str(cls.harness), "-ldl"], check=True)

    def start(self, mode="uninstall", **env):
        temporary = tempfile.TemporaryDirectory(dir=self.build)
        self.addCleanup(temporary.cleanup)
        directory = Path(temporary.name)
        stderr = (directory / "stderr.log").open("w")
        self.addCleanup(stderr.close)
        process = subprocess.Popen([str(self.harness), str(self.plugin), str(directory / "retirement.jsonl"), mode],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=stderr, text=True, bufsize=1,
            env={**os.environ, **env})
        def cleanup():
            if process.poll() is None:
                process.kill()
            process.wait(timeout=3)
            process.stdin.close()
            process.stdout.close()
        self.addCleanup(cleanup)
        return process, directory

    def response(self, process, expected, command=None):
        if command:
            process.stdin.write(command + "\n")
            process.stdin.flush()
        self.assertTrue(select.select([process.stdout], [], [], 5)[0], "Harness did not respond")
        self.assertEqual(process.stdout.readline().strip(), expected)

    def lifecycle(self, process, directory, mode="uninstall", point=1, final=False):
        events = retirement.read_events(directory / "retirement.jsonl")
        arena = retirement.validate_lifecycle(events, process.pid, mode, point, final)
        return events, arena

    def memory(self, process, arena, released=False):
        rows = retirement.parse_maps(Path(f"/proc/{process.pid}/maps").read_text())
        return retirement.inspect_memory(rows, arena, retirement.file_identity(self.plugin),
                                         retirement.file_identity(self.harness), None, released)

    def test_deferred_release_real_mapping_zero_and_dlopen_lifetime(self):
        process, directory = self.start()
        self.response(process, "ready")
        _, arena = self.lifecycle(process, directory)
        self.assertFalse(self.memory(process, arena)["arena_range_absent"])
        self.response(process, "boundary", "boundary")
        events, _ = self.lifecycle(process, directory)
        self.assertEqual([event["event"] for event in events], retirement.REMOVED[:2])
        self.memory(process, arena)  # still live after the request and extra callbacks
        self.response(process, "completed", "complete")
        events, _ = self.lifecycle(process, directory, point=2)
        self.assertEqual(events[2]["pending_callbacks"], 2)
        with self.assertRaisesRegex(probe.ProbeError, "still mapped"):
            self.memory(process, arena, released=True)  # callback completion is not dlclose
        self.response(process, "unloaded", "unload")
        self.assertTrue(self.memory(process, arena, released=True)["owner_library_absent"])
        self.response(process, "second", "second")
        self.assertEqual(retirement.read_events(directory / "retirement.jsonl"), events)
        process.stdin.write("finish\n"); process.stdin.flush()
        self.assertEqual(process.wait(timeout=3), 0)

    def test_keep_control_continues_callbacks_and_retains_mapping(self):
        process, directory = self.start("keep")
        self.response(process, "ready")
        self.response(process, "boundary", "boundary")
        self.response(process, "second", "second")
        events, arena = self.lifecycle(process, directory, "keep", 2)
        self.assertGreater(events[2]["callbacks"], events[1]["callbacks"])
        self.memory(process, arena)
        with self.assertRaises(probe.ProbeError):
            self.memory(process, arena, released=True)
        process.stdin.write("finish\n"); process.stdin.flush()
        self.assertEqual(process.wait(timeout=3), 0)
        self.lifecycle(process, directory, "keep", 2, final=True)

    def test_munmap_failure_is_not_reported_as_release(self):
        process, directory = self.start(RETIRE_FAIL_MUNMAP="1")
        self.response(process, "ready")
        self.response(process, "boundary", "boundary")
        process.stdin.write("complete\n"); process.stdin.flush()
        self.assertEqual(process.wait(timeout=3), 127)
        self.assertEqual(retirement.read_events(directory / "retirement.jsonl")[-1]["event"], "arena_zeroed")
        self.assertIn("reason=munmap", (directory / "stderr.log").read_text())
        with self.assertRaises(probe.ProbeError):
            self.lifecycle(process, directory, point=2)

    def test_missing_completion_is_rejected_while_process_is_alive(self):
        process, directory = self.start()
        self.response(process, "ready")
        self.response(process, "boundary", "boundary")
        events, arena = self.lifecycle(process, directory)
        self.memory(process, arena)
        with self.assertRaises(probe.ProbeError):
            retirement.validate_lifecycle(events, process.pid, "uninstall", 2)
        process.stdin.write("finish\n"); process.stdin.flush()
        self.assertEqual(process.wait(timeout=3), 127)

    def test_invalid_api_options_and_second_vcpu_fail_closed(self):
        for variable, expected in (("RETIRE_BAD_API", 1), ("RETIRE_BAD_OPTIONS", 1), ("RETIRE_SECOND_VCPU", 127)):
            with self.subTest(variable=variable):
                process, directory = self.start(**{variable: "1"})
                self.assertEqual(process.wait(timeout=3), expected)
                if expected == 127:
                    self.assertIn("only_one_vcpu_supported", (directory / "stderr.log").read_text())

    def test_abort_before_and_after_release_has_distinct_evidence(self):
        for released in (False, True):
            with self.subTest(released=released):
                process, directory = self.start()
                self.response(process, "ready")
                self.response(process, "boundary", "boundary")
                if released:
                    self.response(process, "completed", "complete")
                    self.response(process, "unloaded", "unload")
                process.send_signal(signal.SIGKILL)
                self.assertEqual(process.wait(timeout=3), -signal.SIGKILL)
                events = retirement.read_events(directory / "retirement.jsonl")
                self.assertEqual(events[-1]["event"], "arena_unmapped" if released else "uninstall_requested")

    def test_saved_evidence_tampering_rejected(self):
        process, directory = self.start()
        self.response(process, "ready")
        self.response(process, "boundary", "boundary")
        self.response(process, "completed", "complete")
        events, _ = self.lifecycle(process, directory, point=2)
        modifications = [
            lambda items: items.reverse(),
            lambda items: items.pop(3),
            lambda items: items[2].update(host_pid=process.pid + 1),
            lambda items: items[3].update(arena_start=4096),
            lambda items: items[4].update(callbacks=items[4]["callbacks"] + 1),
            lambda items: items[2].update(pending_callbacks=0),
            lambda items: items[0].update(callbacks=True),
        ]
        for mutate in modifications:
            with self.subTest(mutate=mutate):
                corrupted = copy.deepcopy(events)
                mutate(corrupted)
                with self.assertRaises(probe.ProbeError):
                    retirement.validate_lifecycle(corrupted, process.pid, "uninstall", 2)

    def test_live_gate_saved_maps_and_final_validation_agree(self):
        process, directory = self.start()
        self.response(process, "ready")
        symbols = {"capsule_point_one": 0x1000, "capsule_point_two": 0x2000, "capsule_buffer": 0x3000}
        gate = retirement.RetirementGate(directory, self.plugin, self.harness, None, "uninstall")
        journal = []
        for point in (1, 2):
            if point == 2:
                self.response(process, "boundary", "boundary")
                self.response(process, "completed", "complete")
                self.response(process, "unloaded", "unload")
            for sample in (1, 2):
                snapshot = {"event": "snapshot", "protocol": 1, "point": point, "sample": sample,
                    "host_pid": process.pid, "vcpu": 0, "monotonic_ms": point * 1000 + sample * 200,
                    "regs": {"eax": point * 0x11111111, "ebx": 7, "ecx": 0x3000, "edx": 16,
                             "esi": process.pid, "edi": 7, "ebp": 0x4000, "esp": 0x4000, "eip": point * 0x1000},
                    "buffer_hex": (b"0123456789ABCDEF" if point == 1 else b"fedcba9876543210").hex(),
                    "stack_hex": struct.pack("<8I", 0x11223344, 0x55667788, 0x99aabbcc,
                                             7, process.pid, 0x4000, 0xdeadbeef, 0xcafebabe).hex()}
                journal.append(snapshot)
            journal.append({"event": "hold_verified", "point": point, "elapsed_ms": 200})
            gate("held", point, snapshot, journal.append)
        journal.append({"event": "done", "protocol": 1, "points": 2})
        path = directory / "observations.jsonl"
        def save():
            path.write_text("".join(json.dumps(event) + "\n" for event in journal))
        save()
        result = {"qemu_pid": process.pid, "expected_qemu_exit": 0}
        verified = retirement.verify_result(directory, result, gate, {"symbols": symbols}, "alone")
        self.assertTrue(verified["owned_arena_released"])
        self.assertFalse(verified["phase1_memory_released"])
        maps = directory / "maps-point-2.txt"
        original = maps.read_text()
        maps.write_text(original + "\n")
        with self.assertRaisesRegex(probe.ProbeError, "Saved maps changed"):
            retirement.verify_result(directory, result, gate, {"symbols": symbols}, "alone")
        maps.write_text(original)
        journal[7]["owner_library_absent"] = False
        save()
        with self.assertRaisesRegex(probe.ProbeError, "Memory result mismatch"):
            retirement.verify_result(directory, result, gate, {"symbols": symbols}, "alone")


class MapsValidation(unittest.TestCase):
    def test_library_identity_is_captured_before_path_replacement(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "owner.so"
            path.write_bytes(b"original")
            identity = retirement.file_identity(path)
            device, inode = identity
            rows = [(0x1000, 0x2000, "r-xp", device, inode)]
            replacement = path.with_name("replacement.so")
            replacement.write_bytes(b"replacement")
            replacement.replace(path)
            self.assertTrue(retirement.file_mapped(rows, identity))
            self.assertFalse(retirement.file_mapped(rows, retirement.file_identity(path)))

    def test_guards_may_be_merged_with_neighbor_mapping(self):
        rows = retirement.parse_maps("1000-3000 ---p 00000000 00:00 0\n3000-4000 rw-p 00000000 00:00 0\n")
        self.assertTrue(retirement.covered(rows, 0x2000, 0x3000, "---p"))
        self.assertFalse(retirement.covered(rows, 0x2000, 0x4000, "---p"))
        self.assertFalse(retirement.covered(rows, 0, 0x3000, "---p"))

    def test_truncated_unordered_and_missing_maps_rejected(self):
        for text in ("", "1000-2000 rw-p", "2000-3000 rw-p 0 00:00 0\n1000-2000 rw-p 0 00:00 0\n"):
            with self.subTest(text=text), self.assertRaises(probe.ProbeError):
                retirement.parse_maps(text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
