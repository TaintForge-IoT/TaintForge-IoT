"""Real IPC, mappings, export and dlclose; only QEMU scheduling is simulated."""
import copy
import json
import os
from pathlib import Path
import select
import shlex
import socket
import struct
import subprocess
import tempfile
import time
import unittest
from unittest import mock

from experiments.execution_capsule_lifecycle import controller as lifecycle

probe = lifecycle.probe
retirement = lifecycle.retirement


class PairListener:
    """Test setup only: the harness passes a socket created in its own process."""
    def __init__(self, transfer):
        self.transfer = transfer

    def fileno(self):
        return self.transfer.fileno()

    def accept(self):
        data, control, flags, _ = self.transfer.recvmsg(1, socket.CMSG_SPACE(4), socket.MSG_CMSG_CLOEXEC)
        if data != b"s" or flags & socket.MSG_CTRUNC or len(control) != 1:
            raise RuntimeError("Invalid test socket transfer")
        level, kind, value = control[0]
        if (level, kind, len(value)) != (socket.SOL_SOCKET, socket.SCM_RIGHTS, 4):
            raise RuntimeError("Missing test socket descriptor")
        return socket.socket(fileno=struct.unpack("i", value)[0]), None

    def close(self):
        self.transfer.close()


class HostLifecycle(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="tfl-tests-", dir="/tmp")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.build = Path(cls.temporary.name)
        cls.proc_ids = {}
        if os.environ.get("LIFECYCLE_TEST_PROC_TRANSLATE") == "1":
            original = Path.read_text
            def read_child_proc(path, *args, **kwargs):
                parts = path.parts
                if len(parts) == 4 and parts[1] == "proc" and parts[2] in cls.proc_ids:
                    path = Path("/proc") / cls.proc_ids[parts[2]] / parts[3]
                return original(path, *args, **kwargs)
            patch = mock.patch.object(Path, "read_text", read_child_proc)
            patch.start()
            cls.addClassCleanup(patch.stop)
        cls.plugin, cls.harness = cls.build / "owner.so", cls.build / "harness"
        extra = os.environ.get("LIFECYCLE_TEST_CFLAGS")
        flags = shlex.split(extra if extra is not None else probe.command("pkg-config", "--cflags", "glib-2.0"))
        extra_libs = os.environ.get("LIFECYCLE_TEST_LIBS")
        libs = shlex.split(extra_libs if extra_libs is not None else probe.command("pkg-config", "--libs", "glib-2.0"))
        sanitizer = shlex.split(os.environ.get("LIFECYCLE_TEST_SANITIZER_FLAGS", ""))
        common = ["cc", "-std=c11", "-O2", "-g", "-Wall", "-Wextra", "-Werror", "-Wformat=2",
                  "-Wshadow", "-I", str(probe.HERE / "vendor"), *flags, *sanitizer]
        subprocess.run([*common, "-fPIC", "-fvisibility=hidden", "-shared", "-Wl,-z,relro,-z,now",
                        str(lifecycle.HERE / "owner.c"), "-o", str(cls.plugin), *libs], check=True)
        subprocess.run([*common, "-rdynamic", str(Path(__file__).with_name("host_harness.c")),
                        "-o", str(cls.harness), "-ldl"], check=True)

    def start(self, mode="remove", **environment):
        temporary = tempfile.TemporaryDirectory(dir=self.build)
        self.addCleanup(temporary.cleanup)
        directory = Path(temporary.name)
        attempt = "a3" * 16
        if os.environ.get("LIFECYCLE_TEST_PROC_TRANSLATE") == "1":
            environment["EVIDENCE_TEST_PROC_ID"] = str(directory / "proc-id")
        listener, inherited = None, ()
        if os.environ.get("LIFECYCLE_TEST_SOCKETPAIR") == "1":
            left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
            self.addCleanup(right.close)
            listener, inherited = PairListener(left), (right.fileno(),)
            environment["EVIDENCE_TEST_SOCKET"] = str(right.fileno())
        gate = lifecycle.LifecycleGate(directory / "s", directory, self.plugin, self.harness, None, attempt,
                                       listener=listener)
        self.addCleanup(gate.close)
        stderr = (directory / "stderr.log").open("w")
        self.addCleanup(stderr.close)
        options = ["p1=0x1000", f"socket={directory / 's'}", f"export={directory / 'export.bin'}",
                   f"attempt={attempt}", f"mode={mode}"]
        process = subprocess.Popen([str(self.harness), str(self.plugin), *options], stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=stderr, text=True, bufsize=1, env={**os.environ, **environment},
            pass_fds=inherited)
        process.evidence_directory = directory
        def cleanup():
            if process.poll() is None:
                process.kill()
            process.wait(timeout=3)
            process.stdin.close()
            process.stdout.close()
        self.addCleanup(cleanup)
        return process, directory, gate

    def response(self, process, expected, command=None):
        if command:
            self.send(process, command)
        self.assertTrue(select.select([process.stdout], [], [], 3)[0], "Harness stalled")
        self.assertEqual(process.stdout.readline().strip(), expected)
        if expected == "ready" and os.environ.get("LIFECYCLE_TEST_PROC_TRANSLATE") == "1":
            self.proc_ids[str(process.pid)] = (process.evidence_directory / "proc-id").read_text().strip()

    def send(self, process, command):
        process.stdin.write(command + "\n")
        process.stdin.flush()

    def held(self, gate, process, point):
        recorded = []
        gate("held", point, {"host_pid": process.pid}, recorded.append)
        return recorded[-1]

    def complete(self, process):
        self.response(process, "boundary", "boundary")
        self.response(process, "completed", "complete")

    def success(self):
        process, directory, gate = self.start()
        self.response(process, "ready")
        self.held(gate, process, 1)
        self.complete(process)
        self.response(process, "unloaded", "unload")
        result = self.held(gate, process, 2)
        return process, directory, gate, result

    def test_full_protocol_real_peer_export_zeroing_maps_and_unload(self):
        process, directory, gate, result = self.success()
        self.assertEqual(result["status"], "verified")
        self.assertTrue(result["mapping_evidence"]["owner_library_absent"])
        self.assertTrue(result["mapping_evidence"]["arena_range_absent"])
        self.assertFalse(result["claims"]["phase1_retired"])
        self.assertEqual([e["event"] for e in gate.evidence.events], list(lifecycle.EVENTS))
        self.assertEqual(gate.evidence.events[3]["data"]["pending"], 2)
        self.assertEqual((directory / "export.bin").read_bytes(), lifecycle.payload(gate.attempt))
        self.response(process, "second", "second")
        self.send(process, "finish")
        self.assertEqual(process.wait(timeout=3), 0)

    def test_gate_reads_the_selected_proc_mount(self):
        process, directory, gate = self.start()
        self.response(process, "ready")
        gate.proc_root = directory / "private-proc"
        target = gate.proc_root / str(process.pid)
        target.mkdir(parents=True)
        def snapshot_proc():
            for name in ("stat", "maps"):
                (target / name).write_text((Path("/proc") / str(process.pid) / name).read_text())
        snapshot_proc()
        self.held(gate, process, 1)
        self.complete(process)
        self.response(process, "unloaded", "unload")
        snapshot_proc()
        self.assertEqual(self.held(gate, process, 2)["status"], "verified")

    def test_completion_and_eof_do_not_prove_module_unloaded(self):
        process, _, gate = self.start()
        self.response(process, "ready")
        self.held(gate, process, 1)
        self.complete(process)
        with self.assertRaisesRegex(lifecycle.EvidenceError, "module_still_mapped"):
            self.held(gate, process, 2)
        self.assertTrue(gate.evidence.eof)
        self.assertEqual(len(gate.evidence.events), 5)

    def test_retained_arena_is_rejected_despite_release_message_and_dlclose(self):
        process, _, gate = self.start("leak-arena")
        self.response(process, "ready")
        self.held(gate, process, 1)
        self.complete(process)
        self.response(process, "unloaded", "unload")
        with self.assertRaisesRegex(lifecycle.EvidenceError, "arena_still_mapped"):
            self.held(gate, process, 2)

    def test_missing_stage_and_wrong_export_are_rejected(self):
        for mode, reason in (("keep", "missing_stage"), ("bad-export", "export_digest")):
            with self.subTest(mode=mode):
                process, _, gate = self.start(mode)
                self.response(process, "ready")
                self.held(gate, process, 1)
                self.response(process, "boundary", "boundary")
                if mode != "keep":
                    self.response(process, "completed", "complete")
                    self.response(process, "unloaded", "unload")
                with self.assertRaisesRegex(lifecycle.EvidenceError, reason):
                    self.held(gate, process, 2)

    def test_export_or_early_close_can_fail_at_first_hold(self):
        for mode, reason in (("keep", "missing_stage"), ("bad-export", "export_digest")):
            with self.subTest(mode=mode):
                process, directory, gate = self.start(mode)
                self.response(process, "ready")
                self.response(process, "boundary", "boundary")
                with self.assertRaisesRegex(lifecycle.EvidenceError, reason):
                    self.held(gate, process, 1)
                evidence = json.loads((directory / "evidence-point-1.json").read_text())
                self.assertEqual(evidence["point"], 1)
                self.assertEqual(evidence["error"], reason)

    def test_munmap_error_never_emits_resources_released(self):
        process, _, gate = self.start(EVIDENCE_FAIL_MUNMAP="1")
        self.response(process, "ready")
        self.held(gate, process, 1)
        self.response(process, "boundary", "boundary")
        self.send(process, "complete")
        self.assertEqual(process.wait(timeout=3), 127)
        with self.assertRaisesRegex(lifecycle.EvidenceError, "missing_stage"):
            lifecycle.receive(gate.conn, gate.evidence, time.monotonic() + 1, complete=True)
        self.assertEqual(gate.evidence.events[-1]["event"], "callbacks_removed")

    def test_disconnected_receiver_and_completion_backpressure_fail_promptly(self):
        for failure in ("disconnect", "backpressure"):
            with self.subTest(failure=failure):
                env = {"EVIDENCE_SEND_FAIL": "callbacks_removed"} if failure == "backpressure" else {}
                process, directory, gate = self.start(**env)
                self.response(process, "ready")
                self.held(gate, process, 1)
                if failure == "disconnect":
                    gate.conn.close()
                    self.send(process, "boundary")
                else:
                    self.response(process, "boundary", "boundary")
                    self.send(process, "complete")
                self.assertEqual(process.wait(timeout=3), 127)
                self.assertIn("reason=event_send", (directory / "stderr.log").read_text())

    def test_strict_order_identity_types_and_duplicate_json_keys(self):
        _, directory, gate, _ = self.success()
        originals = gate.evidence.events
        mutations = [(0, "protocol", 2), (0, "attempt", "b4" * 16), (0, "pid", os.getpid()),
                     (0, "seq", False), (2, "event", "resources_released"), (4, "seq", 3),
                     (3, "data", {"callbacks": 4, "pending": 100}),
                     (4, "data", {"owned_mappings": False, "owned_bytes": 0, "zeroed_bytes": 4194304})]
        for index, field, value in mutations:
            with self.subTest(index=index, field=field):
                verifier = lifecycle.Evidence(gate.attempt, gate.evidence.pid, directory / "export.bin")
                changed = copy.deepcopy(originals)
                changed[index][field] = value
                with self.assertRaises(lifecycle.EvidenceError):
                    for event in changed:
                        verifier.feed(json.dumps(event).encode())
        for invalid in (b'{"protocol":1,"protocol":1}', b'[]', b'NaN', b'\xff', b'{}' * 600):
            with self.subTest(invalid=invalid[:30]):
                with self.assertRaises(lifecycle.EvidenceError):
                    lifecycle.Evidence(gate.attempt, gate.evidence.pid, directory / "export.bin").feed(invalid)
        with self.assertRaisesRegex(lifecycle.EvidenceError, "event_order"):
            gate.evidence.feed(json.dumps(originals[-1]).encode())

    def test_final_message_without_end_of_stream_times_out(self):
        _, directory, gate, _ = self.success()
        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        with left, right:
            for event in gate.evidence.events:
                right.send(json.dumps(event).encode())
            evidence = lifecycle.Evidence(gate.attempt, gate.evidence.pid, directory / "export.bin")
            with self.assertRaisesRegex(lifecycle.EvidenceError, "event_timeout"):
                lifecycle.receive(left, evidence, time.monotonic() + 0.05, complete=True)
            self.assertEqual(len(evidence.events), 5)
            self.assertFalse(evidence.eof)

    def test_export_rechecked_and_symlink_or_fifo_rejected(self):
        _, directory, gate, _ = self.success()
        path = directory / "export.bin"
        path.write_bytes(b"x" * len(lifecycle.payload(gate.attempt)))
        with self.assertRaisesRegex(lifecycle.EvidenceError, "export_digest"):
            gate.evidence.finish()
        path.unlink()
        path.symlink_to(directory / "stderr.log")
        with self.assertRaisesRegex(lifecycle.EvidenceError, "export_open"):
            gate.evidence.finish()
        path.unlink()
        os.mkfifo(path)
        with self.assertRaisesRegex(lifecycle.EvidenceError, "export_file"):
            gate.evidence.finish()

    def test_silent_peer_deadline_and_truncated_packet(self):
        for packet, reason in ((None, "event_timeout"), (b"x" * 1025, "packet_truncated"), (b"", "empty_packet")):
            with self.subTest(reason=reason):
                left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
                with left, right:
                    left.setblocking(False)
                    evidence = lifecycle.Evidence("a3" * 16, os.getpid(), self.build / "unused")
                    if packet is not None:
                        right.send(packet)
                    before = time.monotonic()
                    with self.assertRaisesRegex(lifecycle.EvidenceError, reason):
                        lifecycle.receive(left, evidence, before + 0.05, complete=True)
                    self.assertLess(time.monotonic() - before, 1)

    def test_socket_peer_must_be_expected_process(self):
        process, _, gate = self.start()
        self.response(process, "ready")
        with self.assertRaisesRegex(lifecycle.EvidenceError, "peer_identity"):
            gate("held", 1, {"host_pid": os.getpid()}, lambda _: None)

    def test_invalid_api_options_and_second_vcpu_fail_closed(self):
        for variable, expected in (("EVIDENCE_BAD_API", 1), ("EVIDENCE_BAD_OPTIONS", 1),
                                   ("EVIDENCE_SECOND_VCPU", 127)):
            with self.subTest(variable=variable):
                process, _, _ = self.start(**{variable: "1"})
                self.assertEqual(process.wait(timeout=3), expected)

    def test_request_can_precede_first_observer_hold_without_freeing_userdata(self):
        process, _, gate = self.start()
        self.response(process, "ready")
        self.response(process, "boundary", "boundary")
        observed = self.held(gate, process, 1)
        self.assertEqual(observed["status"], "observed")
        self.assertEqual(len(gate.evidence.events), 3)
        self.assertFalse(observed["mapping_evidence"]["owner_library_absent"])
        self.response(process, "completed", "complete")
        self.response(process, "unloaded", "unload")
        self.assertEqual(self.held(gate, process, 2)["status"], "verified")


if __name__ == "__main__":
    unittest.main()
