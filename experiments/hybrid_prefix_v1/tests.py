"""Local policy, evidence, C ABI and controller tests; no QEMU/AFL acceptance claim."""
from pathlib import Path
import copy
import ctypes
from contextlib import redirect_stdout
import io
import json
import os
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from . import controller as live
from .policy import SEED, INPUT_PATH, MAP_SIZE, CoveragePlateau, checked_mask, checked_input
from .policy import count_class, digest, masked_mutation, changed_offsets
from .runtime import HERE, PROJECT, build_fixture, patched_source, patched_concolic_source
from .run import launcher, check_afl_only_outcome
from . import run as runner
from taintforge_env import concolic_environment as ce


def bitmap(*slots):
    result = bytearray(MAP_SIZE)
    for slot in slots:
        result[slot] = 1
    return bytes(result)


class PolicyTests(unittest.TestCase):
    def test_all_count_classes(self):
        for value in range(256):
            expected = (0 if value == 0 else 1 if value == 1 else 2 if value == 2 else
                4 if value == 3 else 8 if value <= 7 else 16 if value <= 15 else
                32 if value <= 31 else 64 if value <= 127 else 128)
            self.assertEqual(count_class(value), expected)

    def test_single_bit_mutations_preserve_the_DTA_mask_and_length(self):
        for mask in ([0], [1], [0, 1], [0, 1, 2, 3]):
            for ordinal in range(1, 129):
                output, offset, bit = masked_mutation(SEED, mask, ordinal)
                self.assertEqual(changed_offsets(SEED, output), [offset])
                self.assertIn(offset, mask)
                self.assertEqual(output[offset] ^ SEED[offset], 1 << bit)
                self.assertEqual(len(output), len(SEED))

    def test_invalid_masks_are_rejected(self):
        for mask in ([], [True], [-1], [4], [1, 0], [1, 1], '01'):
            with self.subTest(mask=mask), self.assertRaises(RuntimeError):
                checked_mask(mask)

    def test_arbitrary_length_and_changed_padding_are_rejected(self):
        for data in (SEED[:-1], SEED + b'x', SEED[:8] + b'y' + SEED[9:]):
            with self.assertRaises(RuntimeError):
                checked_input(data)

    def test_coverage_plateau_counts_only_delivered_mutations(self):
        state = CoveragePlateau(4)
        self.assertGreater(state.observe(bitmap(2), eligible=False), 0)
        for _ in range(12):
            state.observe(bitmap(2), eligible=False)
        self.assertEqual(state.quiet, 0)
        for _ in range(4):
            state.observe(bitmap(2), eligible=True)
        self.assertTrue(state.stalled)

    def test_new_coverage_resets_a_plateau(self):
        state = CoveragePlateau(4)
        for _ in range(7):
            state.observe(bitmap(1), eligible=True)
        self.assertTrue(state.stalled)
        state.observe(bitmap(1, 2), eligible=True)
        self.assertFalse(state.stalled)
        self.assertEqual(state.quiet, 0)

    def test_hitcount_bucket_changes_are_novel_even_at_an_existing_edge(self):
        state = CoveragePlateau(4)
        data = bytearray(bitmap(2))
        state.observe(bytes(data), eligible=False)
        data[2] = 2
        self.assertEqual(state.observe(bytes(data), eligible=True), 1)
        self.assertEqual(state.observe(bytes(data), eligible=True), 0)

    def test_empty_and_truncated_coverage_are_rejected(self):
        for data in (bytes(MAP_SIZE), b'\x01', b'\x01' * (MAP_SIZE + 1)):
            with self.assertRaises(RuntimeError):
                CoveragePlateau(4).observe(data, eligible=True)


class ModeTests(unittest.TestCase):
    def test_afl_only_rejects_incomplete_or_failed_campaigns(self):
        complete = {'status': 'completed', 'evidence_complete': True, 'afl_exit': 0}
        self.assertEqual(check_afl_only_outcome(complete, Path('/tmp/campaign'))['status'], 'completed')
        for change in ({'status': 'incomplete'}, {'evidence_complete': False},
                       {'afl_exit': 1}, {'status': 'resource_limited'}):
            with self.subTest(change=change), self.assertRaises(RuntimeError):
                check_afl_only_outcome(dict(complete, **change), Path('/tmp/campaign'))
        with self.assertRaises(RuntimeError):
            check_afl_only_outcome(None, Path('/tmp/campaign'))

    def test_mode_routes_to_only_its_selected_runner(self):
        common = ['--out', '/tmp/unused-fixture-output', '--qemu', '/tmp/unused-qemu',
                  '--qemu-include', '/tmp/unused-headers', '--flags-receipt', '/tmp/unused-receipt']
        for mode in ('afl', 'hybrid'):
            with self.subTest(mode=mode), patch.object(runner, 'verify_afl_only') as afl, \
                    patch.object(runner, 'verify') as hybrid, redirect_stdout(io.StringIO()):
                selected = afl if mode == 'afl' else hybrid
                selected.return_value = {'mode': mode, 'status': 'passed'}
                self.assertEqual(runner.main(['--mode', mode, *common]), 0)
                selected.assert_called_once()
                (hybrid if mode == 'afl' else afl).assert_not_called()


class StartupEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.source = ce.EnvironmentFile(INPUT_PATH, (1,), 32, digest(SEED), 'snapshot', 'tree')
        self.report = {'schema': 2, 'relation': 'environment_file_read_identity',
            'host_identity_verified': True, 'file': {'guest_path': INPUT_PATH, 'size': 32, 'sha256': digest(SEED)},
            'fd': 3, 'read_offset': 0, 'read_size': 32, 'requested': 4096, 'address': 0x804c000,
            'status': 'OBSERVED', 'read_seq': 3,
            'bindings': [{'offset': 1, 'address': 0x804c001, 'byte': 65, 'candidate': 65, 'input_id': 1}],
            'syscalls': [
                {'seq': 1, 'number': 125, 'args': [0x804b000, 4096, 7, 0, 0, 0], 'result': 0},
                {'seq': 2, 'number': 5, 'args': [0x804a004, 0, 0, 0, 0, 0], 'result': 3},
                {'seq': 3, 'number': 3, 'args': [3, 0x804c000, 4096, 0, 0, 0], 'result': 32}]}
        self.trace = [{'instruction': {'seq': index, 'bytes': 'cd80'}} for index in (1, 2, 3)]
        mocked = patch.object(ce, 'validate_prefix', return_value=self.trace)
        mocked.start()
        self.addCleanup(mocked.stop)

    def validate(self):
        return ce.validate_file_observation(self.report, self.source, SEED, 0x804b051, 1, 512)

    def test_one_successful_startup_mprotect_is_recorded_and_accepted(self):
        self.assertEqual(self.validate(), self.trace)

    def test_existing_open_read_contract_remains_accepted(self):
        self.report['syscalls'].pop(0)
        self.trace.pop(0)
        self.assertEqual(self.validate(), self.trace)

    def test_failed_mprotect_is_rejected(self):
        self.report['syscalls'][0]['result'] = 1
        with self.assertRaises(ce.ConcolicError):
            self.validate()

    def test_unaligned_zero_wrapping_or_invalid_protection_is_rejected(self):
        for args in ([0x804b001, 4096, 7, 0, 0, 0], [0x804b000, 0, 7, 0, 0, 0],
                     [0xfffff000, 8192, 7, 0, 0, 0], [0x804b000, 4096, 8, 0, 0, 0]):
            self.report['syscalls'][0]['args'] = args
            with self.subTest(args=args), self.assertRaises(ce.ConcolicError):
                self.validate()

    def test_mprotect_after_open_is_rejected(self):
        self.report['syscalls'][0], self.report['syscalls'][1] = self.report['syscalls'][1], self.report['syscalls'][0]
        for index, event in enumerate(self.report['syscalls'], 1):
            event['seq'] = index
        with self.assertRaises(ce.ConcolicError):
            self.validate()

    def test_omitting_the_observed_syscall_from_evidence_is_rejected(self):
        self.report['syscalls'].pop(0)
        with self.assertRaises(ce.ConcolicError):
            self.validate()

    def test_changed_startup_effects_between_baseline_and_rerun_are_rejected(self):
        baseline = copy.deepcopy(self.report)
        baseline['status'] = 'BOUNDARY_WITNESS'
        baseline['bindings'][0]['candidate'] = 70
        candidate = SEED[:1] + b'F' + SEED[2:]
        rerun = copy.deepcopy(self.report)
        rerun['file']['sha256'] = digest(candidate)
        rerun['bindings'][0].update(byte=70, candidate=70)
        rerun['syscalls'][0]['args'][2] = 5
        with self.assertRaisesRegex(ce.ConcolicError, 'effects diverged'):
            ce.verify_file_rerun(baseline, rerun, self.source, SEED, candidate, 0x804b051, 1, 512)


class BuildTests(unittest.TestCase):
    def test_native_source_hooks_are_unique_and_keep_retirement_checks(self):
        original = (PROJECT / 'unpacker/test/qemu_unpacker.c').read_text()
        changed = patched_source(original)
        self.assertIn('tf_hybrid_initial_pages(&image, effective_page_size', changed)
        self.assertIn('retirement_boundary_not_reached', changed)
        self.assertIn('qemu_plugin_uninstall', changed)
        with self.assertRaises(RuntimeError):
            patched_source(changed)

    def test_native_concolic_hook_records_setup_instead_of_skipping_it(self):
        original = (PROJECT / 'unpacker/test/ir_concolic.c').read_text()
        changed = patched_concolic_source(original)
        self.assertIn('startup_mprotect_contract', changed)
        self.assertIn('startup_mprotect_failed', changed)
        self.assertEqual(changed.count('ConcolicSyscall *event = &run->syscalls[run->syscall_count++];'),
                         original.count('ConcolicSyscall *event = &run->syscalls[run->syscall_count++];'))

    def test_fixture_build_is_deterministic_and_has_one_shared_binary(self):
        with tempfile.TemporaryDirectory() as directory:
            first, metadata = build_fixture(Path(directory) / 'one')
            second, second_metadata = build_fixture(Path(directory) / 'two')
            self.assertEqual(first.read_bytes(), second.read_bytes())
            self.assertEqual(metadata['binary_sha256'], second_metadata['binary_sha256'])
            self.assertIn('int $0x80', (HERE / 'fixture.S').read_text())

    def test_initial_page_callback_uses_ELF_permissions_and_bounds_before_writes(self):
        code = r'''
#include <assert.h>
#include <stdio.h>
#include "initial_pages.h"
static unsigned calls, observed;
static bool install(void *context, uint64_t address, unsigned prot) {
    (void)context; assert(address == 0x804b000); ++calls; observed = prot; return true;
}
int main(void) {
    TfElfImage image = {.load_count=1};
    image.loads[0] = (TfElfLoad){.address=0x804b000, .memory_size=4096};
    for (unsigned flags=0; flags<8; ++flags) {
        image.loads[0].flags = flags; calls=0;
        assert(tf_hybrid_initial_pages(&image,4096,NULL,install));
        assert(calls==1 && observed==(((flags&4)?1:0)|((flags&2)?2:0)|((flags&1)?4:0)));
    }
    calls=0; image.loads[0].memory_size = (uint64_t)4097*4096;
    assert(!tf_hybrid_initial_pages(&image,4096,NULL,install) && calls==0);
    image.loads[0].memory_size=4096; image.load_count=2; image.loads[1]=image.loads[0];
    assert(!tf_hybrid_initial_pages(&image,4096,NULL,install) && calls==0);
    puts("INITIAL_PAGE_RULES_OK"); return 0;
}
'''
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'test.c'
            path.write_text(code)
            executable = Path(directory) / 'test'
            subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror', '-I', str(HERE),
                '-I', str(PROJECT / 'unpacker/test'), str(path), '-o', str(executable)],
                check=True, capture_output=True)
            result = subprocess.run([str(executable)], capture_output=True, text=True, check=True)
            self.assertIn('INITIAL_PAGE_RULES_OK', result.stdout)


class NativeAdapterControllerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.production_library = Path(cls.temporary.name) / 'adapter.so'
        subprocess.run(['cc', '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-fPIC', '-shared',
                        str(HERE / 'mutator.c'), '-o', str(cls.production_library)], check=True, capture_output=True)
        # The executor permits socketpair but not socket creation/listen. Only
        # connection establishment is replaced; send/recv and C guards are real.
        component = Path(cls.temporary.name) / 'component.c'
        component.write_text('#define socket tf_component_socket\n#define connect tf_component_connect\n'
            '#include ' + json.dumps(str(HERE / 'mutator.c')) + '\n'
            '#undef socket\n#undef connect\n'
            'int tf_component_socket(int domain,int type,int protocol) {\n'
            ' (void)domain;(void)type;(void)protocol;\n'
            ' const char *value=getenv("TF_HYBRID_TEST_FD"); return value?dup(atoi(value)):-1;\n}\n'
            'int tf_component_connect(int fd,const struct sockaddr *address,socklen_t size) {\n'
            ' (void)fd;(void)address;(void)size;return 0;\n}\n')
        cls.library = Path(cls.temporary.name) / 'component.so'
        subprocess.run(['cc', '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-fPIC', '-shared',
                        str(component), '-o', str(cls.library)], check=True, capture_output=True)

    def test_compiled_C_adapter_completes_one_controller_cycle_with_synthetic_case_receipts(self):
        with tempfile.TemporaryDirectory(prefix='tf-hyb-') as directory:
            root = Path(directory)
            request = {'input_sha256': digest(SEED), 'opposite_observed_elsewhere': False,
                       'observed_site': {'pc': 0x804b051, 'offsets': [1]}}
            analysis = {'requests': [request], 'mask': [0, 1]}
            metadata = {'second_branch_pc': 0x804b051, 'binary_sha256': 'fixed-test-fixture'}
            witness = SEED[:1] + b'F' + SEED[2:]
            workers = {'DSE': 0, 'DTA': 0}

            def fake_solve(*args, **kwargs):
                workers['DSE'] += 1
                return witness, {'candidate_sha256': digest(witness), 'status': 'VERIFIED'}

            def fake_analyze(*args, **kwargs):
                workers['DTA'] += 1
                self.assertEqual(kwargs['seed'], witness)
                return {'mask': [0, 1, 2]}

            peer, adapter_peer = socket.socketpair()
            self.addCleanup(adapter_peer.close)
            class Listener:
                def bind(self, path): pass
                def listen(self, count): pass
                def settimeout(self, seconds): pass
                def accept(self): return peer, None
                def close(self): peer.close()
            with patch.object(live.socket, 'socket', return_value=Listener()), patch.object(live.os, 'chmod'):
                controller = live.LiveController(root, analysis=analysis, metadata=metadata,
                    binary=None, qemu=None, plugin=None, receipt=None, threshold=4,
                    solve_worker=fake_solve, analyze_worker=fake_analyze)
            server = SimpleNamespace(executed=0, completed=0, errors=[], active_attempt=threading.Event())
            controller.bind(server, 'before_afl')

            def completed_case(raw):
                number = server.executed
                case = root / 'campaign/cases' / f'{number:08d}'
                case.mkdir(parents=True)
                code = 0
                for actual, wanted in zip(raw, b'AFL!'):
                    if actual != wanted:
                        break
                    code += 1
                cover = bitmap(1, 10 + code)
                (case / 'input').write_bytes(raw)
                (case / 'coverage.map').write_bytes(cover)
                (case / 'result.json').write_text(json.dumps({'status': 'passed', 'guest_exit': code,
                    'input': {'input_sha256': digest(raw)}, 'coverage': {'map_sha256': digest(cover)},
                    'outcome': {'kind': 'normal'}}))
                (case / 'transport.json').write_text(json.dumps({'status': 'delivered'}))
                server.executed += 1
                server.completed += 1

            completed_case(SEED)
            controller.start()
            library = ctypes.CDLL(str(self.library))
            library.afl_custom_init.argtypes = [ctypes.c_void_p, ctypes.c_uint]
            library.afl_custom_init.restype = ctypes.c_void_p
            library.afl_custom_fuzz.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t,
                ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p, ctypes.c_size_t, ctypes.c_size_t]
            library.afl_custom_fuzz.restype = ctypes.c_size_t
            library.afl_custom_deinit.argtypes = [ctypes.c_void_p]
            with patch.dict(os.environ, TF_HYBRID_SOCKET=str(controller.socket_path),
                            TF_HYBRID_TOKEN=controller.token, TF_HYBRID_TEST_FD=str(adapter_peer.fileno())):
                state = library.afl_custom_init(None, 42)
                adapter_peer.close()
                try:
                    for _ in range(12):
                        parent = ctypes.create_string_buffer(SEED)
                        output = ctypes.c_void_p()
                        size = library.afl_custom_fuzz(state, parent, 32, ctypes.byref(output), None, 0, 32)
                        self.assertEqual(size, 32)
                        raw = ctypes.string_at(output, size)
                        self.assertTrue(set(changed_offsets(SEED, raw)) <= set(controller.mask))
                        completed_case(raw)
                finally:
                    library.afl_custom_deinit(state)
                    controller.close()
            result = controller.finish()
            self.assertEqual(workers, {'DSE': 1, 'DTA': 1})
            self.assertEqual(result['DTA_mask_revisions'], [[0, 1], [0, 1, 2]])
            self.assertEqual(result['DSE_seed_execution']['guest_exit'], 2)
            self.assertFalse(result['queue_membership_verified_separately'])
            events = [json.loads(line) for line in (root / 'events.jsonl').read_text().splitlines()]
            kinds = [event['event'] for event in events]
            self.assertLess(kinds.index('DSE_trigger'), kinds.index('DSE_seed_executed'))
            self.assertLess(kinds.index('DSE_seed_executed'), kinds.index('DTA_mask_refreshed'))

    def test_native_adapter_rejects_a_controller_response_outside_the_mask(self):
        with tempfile.TemporaryDirectory(prefix='tf-hyb-bad-') as directory:
            path = Path(directory) / 'control.sock'
            connection, child = socket.socketpair()
            self.addCleanup(connection.close)
            self.addCleanup(child.close)
            connection.settimeout(5)
            code = '''import ctypes,sys
library=ctypes.CDLL(sys.argv[1])
library.afl_custom_init.argtypes=[ctypes.c_void_p,ctypes.c_uint]
library.afl_custom_init.restype=ctypes.c_void_p
library.afl_custom_fuzz.argtypes=[ctypes.c_void_p,ctypes.c_void_p,ctypes.c_size_t,ctypes.POINTER(ctypes.c_void_p),ctypes.c_void_p,ctypes.c_size_t,ctypes.c_size_t]
library.afl_custom_fuzz.restype=ctypes.c_size_t
state=library.afl_custom_init(None,42)
parent=ctypes.create_string_buffer(b"AA"+b"x"*30)
output=ctypes.c_void_p()
library.afl_custom_fuzz(state,parent,32,ctypes.byref(output),None,0,32)
'''
            process = subprocess.Popen([sys.executable, '-c', code, str(self.library)],
                env=dict(os.environ, TF_HYBRID_SOCKET=str(path), TF_HYBRID_TOKEN='a' * 64,
                         TF_HYBRID_TEST_FD=str(child.fileno())), pass_fds=(child.fileno(),),
                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            child.close()
            try:
                with connection:
                    self.assertEqual(live.receive(connection, 64), b'a' * 64)
                    live.receive(connection, 40)
                    invalid = SEED[:5] + b'y' + SEED[6:]
                    connection.sendall(struct.pack('!BBH32s', 1, 3, 32, invalid))
                stdout, stderr = process.communicate(timeout=5)
                self.assertEqual(process.returncode, 2)
                self.assertIn(b'mutation_outside_DTA_mask', stderr)
            finally:
                if process.poll() is None:
                    process.kill()
                process.wait(timeout=5)


if __name__ == '__main__':
    unittest.main(verbosity=2)
