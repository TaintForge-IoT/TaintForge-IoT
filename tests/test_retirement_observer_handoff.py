"""Controller regression with a scripted peer and virtual disk latency, not QEMU."""
import hashlib
import json
import os
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

from experiments.retirement_observer import controller as c


class Clock:
    def __init__(self):
        self.now = 10.0

    def advance(self, seconds):
        self.now += seconds

    def monotonic(self):
        return self.now

    def monotonic_ns(self):
        return round(self.now * 1e9)


class Pipe:
    def __init__(self, *replies):
        self.replies, self.sent = list(replies), []

    def poll(self, timeout):
        return bool(self.replies)

    def recv(self):
        return self.replies.pop(0)

    def send(self, value):
        self.sent.append(value)

    def close(self):
        pass


class Peer:
    """Finite guest: 150 ms remain after unmap; writes can consume 200 ms."""
    def __init__(self, harness):
        self.harness = harness
        self.commands, self.frames = [], []
        self.held, self.closed, self.second_hold = True, False, False
        self.expired = False
        self.queue(self.snapshot(1, 1))

    def queue(self, event):
        self.frames.append((json.dumps(event) + "\n").encode())

    def snapshot(self, point, sample):
        return dict(event="snapshot", protocol=c.PROTOCOL, host_pid=77, point=point, sample=sample,
                    seq=1 if point == 1 else 500, pc=0x1000*point, pc_source=c.PC_SOURCE,
                    qemu_eip=0x1000*point-4, monotonic_ms=round(self.harness.clock.now*1000),
                    regs=list(range(8)), stack_readable=True, stack_hex="00"*32)

    def early_exit(self):
        self.expired = True
        self.frames.clear()
        self.queue(dict(event="early_exit", protocol=c.PROTOCOL, host_pid=77, seq=70000199))

    def expire_if_needed(self):
        start = self.harness.unmap_time
        if start is not None and not self.second_hold and self.harness.clock.now-start >= .15:
            self.early_exit()

    def sendall(self, data):
        command = data.decode().strip()
        self.expire_if_needed()
        if command == "HOLD 2" and self.harness.mode == "exit-before-send":
            self.early_exit()
        if self.expired:
            raise BrokenPipeError("scripted guest already exited")
        self.commands.append(command)
        self.harness.operations.append(command)
        if command.startswith("CHECK "):
            self.queue(self.snapshot(int(command[-1]), 2))
        elif command.startswith("RESUME "):
            point = int(command[-1])
            self.held = False
            self.queue(dict(event="resumed", protocol=c.PROTOCOL, point=point, seq=1 if point == 1 else 500))
            if point == 2:
                self.queue(dict(event="done", protocol=c.PROTOCOL, host_pid=77, seq=520))
        elif command == "STAMP":
            self.queue(dict(event="stamp", protocol=c.PROTOCOL, host_pid=77, seq=80,
                            monotonic_ms=round(self.harness.clock.now*1000)))
        elif command == "HOLD 2":
            if self.harness.mode == "exit-before-ack":
                self.early_exit()
            elif self.harness.mode != "disconnect":
                self.held = self.second_hold = True
                event = self.snapshot(2, 1)
                if self.harness.mode == "invalid-snapshot":
                    event["host_pid"] += 1
                self.queue(event)
            # /proc may change after capture. Saved evidence must use the bytes
            # already observed, never a later reread when the guest is held.
            self.harness.proc.joinpath("maps").write_text("later maps, not the captured observation\n")
            self.harness.proc.joinpath("stat").write_text("later stat\n")

    def recv(self, limit):
        self.expire_if_needed()
        if self.frames:
            frame = self.frames.pop(0)
            self.harness.operations.append("receive:" + json.loads(frame)["event"])
            return frame
        return b""

    def settimeout(self, timeout):
        pass

    def getsockopt(self, *args):
        return struct.pack("3i", 77, os.geteuid(), os.getegid())

    def close(self):
        self.closed = True


class Listener:
    def __init__(self, peer):
        self.peer = peer

    def bind(self, endpoint):
        Path(endpoint).touch()

    def listen(self, backlog):
        pass

    def settimeout(self, timeout):
        pass

    def accept(self):
        return self.peer, None

    def close(self):
        pass


class HandoffTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.output = self.root / "logs/capsule"
        self.evidence = self.output / "phase1-retirement"
        self.evidence.mkdir(parents=True)
        self.proc = self.root / "rootfs/proc/77"
        self.proc.mkdir(parents=True)
        self.map_bytes = b"1000-2000 r-xp 00000000 00:01 22 /observer.so\n"
        self.stat_bytes = ("77 (qemu fixture) S " + "0 "*18 + "1234\n").encode()
        (self.proc / "maps").write_bytes(self.map_bytes)
        (self.proc / "stat").write_bytes(self.stat_bytes)
        self.identity = dict(qemu_pid=77, process_start_ticks=1234, modules={
            "phase1": dict(device=[0, 1], inode=11), "observer": dict(device=[0, 1], inode=22)})
        self.binding = dict(run_dir=str(self.root), rootfs=str(self.root / "rootfs"), observer=dict(
            protocol=c.PROTOCOL, pc_source=c.PC_SOURCE, hold_ms=20, total_ms=30000,
            after_release_delay_ms=100, fault="none"))
        self.clock = Clock()
        self.mode, self.storage_error = "normal", None
        self.unmap_time = None
        self.injected_delay = False
        self.operations, self.disk_states = [], []

    def run_controller(self):
        self.peer = Peer(self)
        pipe, gate = Pipe(77), Pipe("export_ready", "released")
        original_verdict = c.mappings.verdict
        original_json, original_bytes = c.p.write_json, Path.write_bytes

        def verdict(*args):
            result = original_verdict(*args)
            self.unmap_time = self.clock.now
            self.operations.append("unmap")
            return result

        def save_json(path, value):
            if path.name == "observer-events.json" and any(
                    e["event"] == "module_unmapped" for e in value["events"]):
                self.operations.append("save:journal")
                if self.storage_error == "journal":
                    raise OSError("scripted journal write failure")
                if not self.injected_delay:
                    self.disk_states.append(self.peer.held)
                    self.clock.advance(.2)
                    self.injected_delay = True
            return original_json(path, value)

        def save_bytes(path, value):
            if path.name in {"maps-unmapped.txt", "process-unmapped.stat"}:
                self.operations.append("save:" + path.name)
                self.disk_states.append(self.peer.held)
                if self.storage_error == path.name:
                    raise OSError("scripted evidence write failure")
            return original_bytes(path, value)

        with patch.object(c.socket, "socket", return_value=Listener(self.peer)), \
             patch.object(c.select, "select", side_effect=lambda *a: ([self.peer] if self.peer.frames else [], [], [])), \
             patch.object(c.time, "monotonic", self.clock.monotonic), \
             patch.object(c.time, "monotonic_ns", self.clock.monotonic_ns), \
             patch.object(c.time, "sleep", self.clock.advance), \
             patch.object(c.mappings, "load_identity", return_value=self.identity), \
             patch.object(c.mappings, "verdict", side_effect=verdict), \
             patch.object(c.mappings, "capture", return_value={}), \
             patch.object(c.retirement, "verify_retirement"), \
             patch.object(c.p, "write_json", side_effect=save_json), \
             patch.object(Path, "write_bytes", save_bytes):
            c.control_worker(self.root / "observer.sock", pipe, gate, self.binding)
        self.assertTrue(self.peer.closed)
        self.assertEqual(pipe.sent, ["ready"])
        self.assertEqual(gate.sent, ["grant"])
        return c.read_json(self.output / "controller.json")

    def events(self):
        return c.read_json(self.output / "observer-events.json")["events"]

    def assert_saved_capture(self):
        self.assertEqual((self.evidence / "maps-unmapped.txt").read_bytes(), self.map_bytes)
        self.assertEqual((self.evidence / "process-unmapped.stat").read_bytes(), self.stat_bytes)
        event = next(e for e in self.events() if e["event"] == "module_unmapped")
        self.assertEqual(event["maps_sha256"], hashlib.sha256(self.map_bytes).hexdigest())
        self.assertEqual(event["process_stat_sha256"], hashlib.sha256(self.stat_bytes).hexdigest())

    def test_slow_persistence_waits_for_hold_and_preserves_original_live_bytes(self):
        result = self.run_controller()
        self.assertEqual(result["status"], "passed", result)
        self.assertTrue(self.injected_delay)
        self.assertTrue(all(self.disk_states))
        hold = self.operations.index("HOLD 2")
        self.assertEqual(self.operations[hold+1], "receive:snapshot")
        self.assertLess(hold+1, self.operations.index("save:maps-unmapped.txt"))
        self.assertLess(self.operations.index("save:journal"), self.operations.index("RESUME 2"))
        self.assert_saved_capture()
        events = self.events()
        self.assertEqual([e["controller_seq"] for e in events], list(range(1, len(events)+1)))
        self.assertEqual([e["controller_ns"] for e in events], sorted(e["controller_ns"] for e in events))

    def test_evidence_or_journal_failure_after_hold_never_resumes_guest(self):
        for failure in ("maps-unmapped.txt", "process-unmapped.stat", "journal"):
            with self.subTest(failure=failure):
                self.setUp()
                self.storage_error = failure
                result = self.run_controller()
                self.assertEqual(result["status"], "failed", result)
                self.assertIn("write failure", result["error"])
                self.assertIn("HOLD 2", self.peer.commands)
                self.assertNotIn("CHECK 2", self.peer.commands)
                self.assertNotIn("RESUME 2", self.peer.commands)

    def test_exit_racing_hold_send_preserves_unmap_and_explicit_early_exit(self):
        self.mode = "exit-before-send"
        result = self.run_controller()
        self.assertEqual(result["status"], "inconclusive", result)
        self.assertNotIn("HOLD 2", self.peer.commands)
        self.assertEqual([e["event"] for e in self.events()[-2:]], ["module_unmapped", "early_exit"])
        self.assert_saved_capture()

    def test_exit_after_hold_request_before_snapshot_preserves_prefix(self):
        self.mode = "exit-before-ack"
        result = self.run_controller()
        self.assertEqual(result["status"], "inconclusive", result)
        self.assertEqual([e.get("command", e["event"]) for e in self.events()[-3:]],
                         ["module_unmapped", "HOLD 2", "early_exit"])
        self.assertNotIn("RESUME 2", self.peer.commands)
        self.assert_saved_capture()

    def test_disconnect_without_native_exit_is_failure_and_retains_capture(self):
        self.mode = "disconnect"
        result = self.run_controller()
        self.assertEqual(result["status"], "failed", result)
        self.assertNotIn("RESUME 2", self.peer.commands)
        self.assert_saved_capture()

    def test_invalid_second_snapshot_cannot_resume(self):
        self.mode = "invalid-snapshot"
        result = self.run_controller()
        self.assertEqual(result["status"], "failed", result)
        self.assertNotIn("RESUME 2", self.peer.commands)
        self.assert_saved_capture()

    def test_early_exit_with_failed_evidence_save_is_failure(self):
        self.mode, self.storage_error = "exit-before-ack", "maps-unmapped.txt"
        result = self.run_controller()
        self.assertEqual(result["status"], "failed", result)
        self.assertIn("evidence_persistence_error", result)
        self.assertNotIn("RESUME 2", self.peer.commands)

    def test_still_mapped_module_never_receives_hold(self):
        (self.proc / "maps").write_bytes(self.map_bytes + b"3000-4000 r-xp 00000000 00:01 11 /phase1.so\n")
        result = self.run_controller()
        self.assertEqual(result["status"], "failed", result)
        self.assertIn("still mapped", result["error"])
        self.assertNotIn("HOLD 2", self.peer.commands)
        self.assertFalse((self.evidence / "maps-unmapped.txt").exists())

    def test_changed_process_identity_never_receives_hold(self):
        (self.proc / "stat").write_bytes(self.stat_bytes.replace(b"1234", b"1235"))
        result = self.run_controller()
        self.assertEqual(result["status"], "failed", result)
        self.assertIn("Process changed", result["error"])
        self.assertNotIn("HOLD 2", self.peer.commands)

    def test_missing_observer_mapping_never_receives_hold(self):
        (self.proc / "maps").write_bytes(b"1000-2000 rw-p 00000000 00:00 0 [stack]\n")
        result = self.run_controller()
        self.assertEqual(result["status"], "failed", result)
        self.assertIn("mapping state is wrong", result["error"])
        self.assertNotIn("HOLD 2", self.peer.commands)


if __name__ == "__main__":
    unittest.main()
