"""Protocol/ownership checks. Native tests simulate scheduling, not a VM run."""
import copy
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import socket
import subprocess
import tempfile
import unittest

from taintforge_env import phase1_retirement as r
from taintforge_env.phase1_runtime import Phase1Runtime, _parse

ROOT = Path(__file__).resolve().parents[1]


class RetirementEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.binding = {"session_id": "s", "attempt_id": "a", "analysis_instance_id": "i",
            "attempt_contract_sha256": "contract", "bundle_sha256": "bundle", "lifecycle_attempt": "1" * 32,
            "run_dir": str(self.root), "capsule": {"symbols": {"phase1_payload_entry": 4096,
                "phase1_retire_boundary": 8192}}}
        data = {"candidate_id": 1, "oep": 4096, "decision_pc": 4100, "decision_trace_seq": 23,
                "continuation_pc": 8192, "epoch": 0, "generation": 1,
                "policy": "heuristic_candidate", "oep_proven": False}
        payloads = [data, {"sha256": "a" * 64, "size": 3}, {}, {},
                    {"pages_released": 1, "bitmaps_released": 1, "register_buffers_released": 2,
                     "explicitly_wiped_bytes": 1024, "owner_roots_remaining": 0,
                     "all_bytes_zeroed": False, "allocator_residue_verified": False,
                     "guest_memory_modified": False}]
        self.packets = [{"protocol": 1, "event": name,
            **{k: self.binding[k] for k in ("session_id", "attempt_id", "analysis_instance_id")},
            "nonce": "1" * 32, "host_pid": 77, "data": payload} for name, payload in zip(r.EVENTS, payloads)]
        self.stream = [
            {"event_type": "oep_candidate_selected", "event_seq": 1,
             "data": {"candidate_id": 1, "address": 4096}},
            {"event_type": "oep_verdict", "event_seq": 2, "status": "selected_candidate",
             "analysis_epoch": 0, "code_generation": 1,
             "data": {k: v for k, v in data.items() if k not in {"epoch", "generation"}} | {"rewind": False}},
            {"event_type": "analysis_finished", "event_seq": 3}]

    def test_packet_order_identity_and_release_scope(self):
        r.check_packets(self.binding, self.packets, 77, complete=True)
        for mutate in (
            lambda p: p.reverse(), lambda p: p[0].update(nonce="2" * 32),
            lambda p: p[1].update(attempt_id="old"), lambda p: p[0].update(host_pid=78),
            lambda p: p[-1]["data"].update(owner_roots_remaining=1),
            lambda p: p[-1]["data"].update(all_bytes_zeroed=True),
            lambda p: p[-1]["data"].update(register_buffers_released=0),
            lambda p: p[-1]["data"].update(owner_roots_remaining=False),
            lambda p: p[2]["data"].update(extra=True),
        ):
            value = copy.deepcopy(self.packets)
            mutate(value)
            with self.assertRaises(RuntimeError):
                r.check_packets(self.binding, value, 77, complete=True)
        with self.assertRaises(RuntimeError):
            r.check_packets(self.binding, self.packets[:-1], 77, complete=True)

    def test_verdict_requires_selected_current_fixture_candidate(self):
        r.check_verdict(self.binding, self.packets[0], self.stream)
        for change in ({"oep": 8192}, {"policy": "write_exec_only"}, {"oep_proven": True},
                       {"decision_trace_seq": 0}, {"candidate_id": True}):
            packet = copy.deepcopy(self.packets[0])
            packet["data"].update(change)
            with self.assertRaises(RuntimeError):
                r.check_verdict(self.binding, packet, self.stream)
        for suffix in ("oep_candidate_invalidated", "code_generation_changed", "error", "data_loss", "profile_lost"):
            with self.assertRaises(RuntimeError):
                r.check_verdict(self.binding, self.packets[0], self.stream + [{"event_type": suffix}])
        with self.assertRaises(RuntimeError):
            r.check_verdict(self.binding, self.packets[0], self.stream[1:])

    def test_duplicate_json_keys_and_unsupported_fault_are_rejected(self):
        with self.assertRaises(RuntimeError):
            _parse('{"protocol":1,"protocol":1}')
        with self.assertRaises(RuntimeError):
            r.settings("continue_anyway")

    def test_runtime_capability_is_bound_to_build(self):
        plugin = self.root / "plugin.so"
        plugin.write_bytes(b"test plugin")
        inputs = {"plugin_api": 6}
        sidecar = {"schema_version": 1, "runtime_kind": "taintforge-phase1", "build_inputs": inputs,
            "build_id": hashlib.sha256(json.dumps(inputs, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
            "plugin": {"filename": plugin.name, "sha256": r.probe.sha(plugin), "size": plugin.stat().st_size},
            "requirements": {"plugins": True, "plugin_api": 6, "qemu_linkage": "dynamic"}}
        manifest = Path(str(plugin) + ".runtime.json")
        manifest.write_text(json.dumps(sidecar))
        with self.assertRaises(RuntimeError):
            r.check_runtime(Phase1Runtime.load(plugin))
        sidecar["formats"] = {"cooperative_retirement": 1}
        manifest.write_text(json.dumps(sidecar))
        r.check_runtime(Phase1Runtime.load(plugin))


class NativeRetirementTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        override = os.environ.get("TF_RETIRE_TEST_BIN_DIR")
        if override:
            cls.out = Path(override)
            return
        if not shutil.which("gcc"):
            raise unittest.SkipTest("gcc is required for the native ownership tests")
        flags = os.environ.get("TF_PLUGIN_CPPFLAGS")
        libs = os.environ.get("TF_PLUGIN_LIBS")
        if not (flags and libs):
            try:
                flags = subprocess.check_output(["pkg-config", "--cflags", "glib-2.0", "capstone", "z3"], text=True)
                libs = subprocess.check_output(["pkg-config", "--libs", "glib-2.0", "capstone", "z3"], text=True)
            except (OSError, subprocess.CalledProcessError) as exc:
                raise unittest.SkipTest("GLib/Capstone/Z3 development packages are required") from exc
        cls.temp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temp.cleanup)
        cls.out = Path(cls.temp.name)
        src = ROOT / "unpacker/test"
        recipe = (src / "build_group7_4c1_plugin.sh").read_text().split("for tf_runtime_name in ", 1)[1].split("; do", 1)[0]
        sources = [str(src / n) for n in recipe.replace("\\", "").split() if n != "qemu_unpacker.c"]
        common = ["gcc", "-std=gnu11", "-O1", "-g", "-I" + str(ROOT / "experiments/execution_capsule_probe/vendor"),
                  "-I" + str(src), *shlex.split(flags)]
        linked = [*shlex.split(libs), "-lm", "-pthread"]
        probe = '''#include <sys/ucontext.h>
#include "dta.h"
_Static_assert(DTA_REG_RAX == 0 && DTA_REG_R15 == 15, "register order");
void check(void *p, const char *s) {
    p = g_malloc(1); p = g_realloc(p, 2); g_free(p);
    p = g_strdup(s); g_free(p);
}
'''
        subprocess.run([*common, '-D_GNU_SOURCE=', '-include', str(src/'phase1_alloc.h'),
            '-Wall', '-Wextra', '-Werror', '-fsyntax-only', '-x', 'c', '-'], input=probe,
            check=True, capture_output=True, text=True, timeout=30)
        subprocess.run([*common, "-fno-omit-frame-pointer", "-fsanitize=address,undefined",
            '-D_GNU_SOURCE=', '-include', str(src/'phase1_alloc.h'),
            "-ffunction-sections", "-fdata-sections", "-Wl,--gc-sections",
            str(r.HERE / "release_test.c"), *sources, *linked, "-o", str(cls.out / "release_test")],
            check=True, capture_output=True, text=True, timeout=180)
        subprocess.run([*common, str(r.HERE / "protocol_test.c"), str(src / "phase1_io.c"),
            str(src / "phase1_resources.c"), *linked, "-o", str(cls.out / "protocol_test")], check=True, capture_output=True, text=True, timeout=30)
        subprocess.run([*common, str(r.HERE / "verdict_test.c"), str(src / "phase1_io.c"),
            str(src / "phase1_retire.c"), str(src / "phase1_resources.c"), *linked, "-o", str(cls.out / "verdict_test")],
            check=True, capture_output=True, text=True, timeout=30)

    def test_native_verdict_latches_then_binds_the_next_pc_and_rejects_stale_state(self):
        for case in ("none", "other-pc", "budget", "epoch", "generation", "trace", "replaced"):
            with self.subTest(case=case):
                result = subprocess.run([str(self.out / "verdict_test"), case],
                    capture_output=True, text=True, timeout=3)
                self.assertEqual(result.returncode, 0 if case in {"none", "other-pc"} else 89, result.stderr)
                if result.returncode == 0:
                    event = json.loads(result.stdout)
                    self.assertEqual(event["data"]["continuation_pc"], 12288 if case == "other-pc" else 8192)
                    self.assertEqual(event["data"]["decision_trace_seq"], 23)

    def test_real_owner_cleanup_full_partial_and_repeated_under_sanitizers(self):
        for arg in ("full", "partial", "m4-full", "m4-partial"):
            with self.subTest(arg=arg):
                result = subprocess.run([str(self.out / "release_test"), arg], capture_output=True, text=True,
                    env={**os.environ, "ASAN_OPTIONS": "detect_leaks=" + os.environ.get("TF_RETIRE_LSAN", "1") + ":halt_on_error=1",
                         "UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=1"}, timeout=20)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("release OK", result.stdout)

    def run_protocol(self, fault):
        with tempfile.TemporaryDirectory() as d:
            manifest = Path(d) / "manifest.json"
            manifest.write_text('{"export":"unit-test"}\n')
            parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
            parent.settimeout(3)
            process = subprocess.Popen([str(self.out / "protocol_test"), str(child.fileno()), str(manifest), fault],
                pass_fds=(child.fileno(),), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            child.close()
            try:
                if fault == "wrong-peer":
                    packets = []
                else:
                    packets = [_parse(parent.recv(2048).decode()) for _ in range(2)]
                    self.assertEqual([p["event"] for p in packets], ["verdict", "export_complete"])
                    nonce = packets[0]["nonce"]
                    digest = packets[1]["data"]["sha256"]
                    self.assertEqual(digest, r.probe.sha(manifest))
                    if fault == "timeout":
                        pass
                    elif fault == "disconnect":
                        parent.close()
                    else:
                        command = f"RETIRE {nonce} 1 {digest}\n".encode()
                        if fault == "bad-digest": command = command.replace(digest.encode(), b"0"*64)
                        if fault == "stale-permit": command = command.replace(nonce.encode(), b"0"*32)
                        if fault == "oversized": command += b"x"*4096
                        if fault == "deny": command = b"DENY\n"
                        if fault == "wrong-candidate": command = command.replace(b" 1 ", b" 2 ")
                        parent.sendall(command)
                    if fault == "none":
                        packets += [_parse(parent.recv(2048).decode()) for _ in range(3)]
                        self.assertEqual([p["event"] for p in packets], list(r.EVENTS))
                        self.assertEqual(parent.recv(2048), b"")
                _, stderr = process.communicate(timeout=3)
                expected = 0 if fault == "none" else 87 if fault == "timeout" else 88
                self.assertEqual(process.returncode, expected, stderr.decode())
                if expected:
                    self.assertIn(f"CAPSULE_PHASE1_ABORT code={expected}".encode(), stderr)
            finally:
                parent.close()
                if process.poll() is None:
                    process.kill()
                process.communicate(timeout=3)

    def test_native_permit_requires_exact_nonce_candidate_digest_and_order(self):
        for fault in ("none", "bad-digest", "stale-permit", "wrong-candidate", "oversized", "deny", "wrong-peer"):
            with self.subTest(fault=fault):
                self.run_protocol(fault)

    def test_native_disconnect_and_deadline_are_terminal(self):
        for fault in ("disconnect", "timeout"):
            with self.subTest(fault=fault):
                self.run_protocol(fault)


if __name__ == "__main__":
    unittest.main()
