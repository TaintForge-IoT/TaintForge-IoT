"""Compile and exercise a benign fixture; no Phase 1, retirement or namespaces."""
import errno
import json
import os
from pathlib import Path
import platform
import shutil
import socket
import subprocess
import struct
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from scripts import run_network_capsule_e2e as runner
from taintforge_env.elf_runtime import ElfImage


class RepairFixtureSetup:
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def native(self, binary):
        qemu = os.environ.get('TF_NET6_QEMU')
        if not qemu and (platform.system() != 'Linux' or platform.machine() not in ('x86_64', 'i386', 'i686')):
            self.skipTest('Linux kernel with i386 ELF support required')
        command = [str(Path(qemu).resolve(strict=True)), str(binary)] if qemu else [str(binary)]
        try:
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except OSError as exc:
            if exc.errno == errno.ENOEXEC:
                self.skipTest('kernel does not execute i386 ELF')
            raise

        def cleanup():
            if process.poll() is None:
                process.kill()
            process.communicate(timeout=3)

        self.addCleanup(cleanup)
        return process


@unittest.skipUnless(all(shutil.which(tool) for tool in ('as', 'ld', 'nm')), 'binutils required')
class NetworkCapsuleRepairFixtureTests(RepairFixtureSetup, unittest.TestCase):
    def test_failure_grace_is_validated_before_creating_an_output(self):
        for index, value in enumerate((True, 10.0, -10, 1, 10001, 10010)):
            path = self.root / str(index)
            with self.subTest(value=value), self.assertRaisesRegex(RuntimeError, 'fixture failure grace'):
                runner.build_guest(path, port=4444, work=16, failure_grace_ms=value)
            self.assertFalse(path.exists())

    def test_assembler_also_rejects_invalid_failure_bounds(self):
        for value in (-10, 1, 10010):
            with self.subTest(value=value):
                result = subprocess.run(['as', '--32', '--defsym', 'NET6_FAILURE_GRACE_MS=' + str(value),
                    str(runner.PROJECT / 'samples/network_capsule_i386.S'), '-o', str(self.root / 'bad.o')],
                    capture_output=True, text=True, timeout=5)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('must be 0..10000', result.stderr)

    def test_build_records_the_bound_and_only_emits_the_enabled_wait(self):
        enabled = runner.build_guest(self.root / 'enabled', port=4444, work=16, failure_grace_ms=5000)
        disabled = runner.build_guest(self.root / 'disabled', port=4444, work=16)
        for binary, bound in ((enabled, 5000), (disabled, 0)):
            with self.subTest(bound=bound):
                build = json.loads((binary.parent / 'build.json').read_text())
                self.assertEqual(build['definitions']['NET6_FAILURE_GRACE_MS'], bound)
                symbols = subprocess.check_output(['nm', '--defined-only', str(binary)], text=True)
                self.assertEqual('failure_pause' in symbols, bool(bound))

    def test_built_failure_path_has_a_finite_counter_and_valid_sleep_arguments(self):
        if not shutil.which('objdump'):
            self.skipTest('objdump required')
        binary = runner.build_guest(self.root / 'input', port=4444, work=16, failure_grace_ms=500)
        symbols = subprocess.check_output(['nm', '--defined-only', '--format=posix', str(binary)], text=True)
        addresses = {parts[0]: int(parts[2], 16) for parts in (line.split() for line in symbols.splitlines())}
        data = ElfImage(binary)
        offset = data.offset_for(addresses['failure_pause'], 8)
        self.assertEqual(struct.unpack_from('<II', data.data, offset), (0, 10000000))
        disassembly = subprocess.check_output(['objdump', '-d', '--no-show-raw-insn', str(binary)], text=True)
        failed = disassembly.split('<failed>:', 1)[1].split('<quit>:', 1)[0]
        self.assertRegex(failed, r'mov\s+\$0x32,%edi')
        self.assertRegex(failed, r'mov\s+\$0xa2,%eax')
        self.assertRegex(failed, r'dec\s+%edi')
        self.assertRegex(failed, r'jne\s+[0-9a-f]+\s+<failed\+0x5>')
        self.assertRegex(failed, r'mov\s+\$0xe,%ebx')

    def test_only_repair_selects_the_failure_observation_window(self):
        class CapturedBuild(Exception):
            pass

        for case in runner.CASES:
            with self.subTest(case=case), patch.object(runner, 'build_guest', side_effect=CapturedBuild) as build:
                with self.assertRaises(CapturedBuild):
                    runner.run_case(self.root / case, case, self.root / 'qemu', self.root / 'phase1.so',
                                    self.root / 'endpoint.so')
                expected = runner.REPAIR_FAILURE_GRACE_MS if case == 'repair' else 0
                self.assertEqual(build.call_args.kwargs['failure_grace_ms'], expected)

    def test_acceptance_runs_execution_checks_in_the_qemu_group(self):
        from taintforge_env import network_acceptance as acceptance
        static = 'tests.test_network_capsule_repair_fixture.NetworkCapsuleRepairFixtureTests'
        guests = 'tests.test_network_capsule_repair_fixture.NetworkCapsuleRepairGuestTests'
        self.assertIn(static, acceptance.UNIT_TESTS)
        self.assertNotIn(guests, acceptance.UNIT_TESTS)
        check = next(item for item in acceptance.CHECKS if item.name == 'qemu_protocols')
        self.assertTrue(check.qemu)
        self.assertIn(guests, check.tests)
        output = self.root / 'qemu-check'
        output.mkdir()
        qemu, observer = self.root / 'selected-qemu', self.root / 'selected-observer'
        _, env, _ = acceptance.command_for(check, runner.PROJECT, output, 'full',
            {'qemu': {'path': str(qemu)}, 'observer': {'path': str(observer)}}, 'repair-check')
        self.assertEqual(env['TF_NET6_QEMU'], str(qemu))
        self.assertEqual(env['TF_NET6_OBSERVER'], str(observer))


@unittest.skipUnless(all(shutil.which(tool) for tool in ('as', 'ld', 'nm')), 'binutils required')
class NetworkCapsuleRepairGuestTests(RepairFixtureSetup, unittest.TestCase):
    def test_missing_service_keeps_a_live_failure_window_then_returns_the_error(self):
        # A bound, non-listening socket reserves the port while connect fails.
        with socket.socket() as reserved:
            reserved.bind(('127.0.0.1', 0))
            binary = runner.build_guest(self.root / 'input', port=reserved.getsockname()[1], work=16,
                                        failure_grace_ms=500)
            started = time.monotonic()
            process = self.native(binary)
            time.sleep(.1)
            self.assertIsNone(process.poll(), 'fixture exited before the observation window')
            stdout, stderr = process.communicate(timeout=3)
            self.assertGreaterEqual(time.monotonic() - started, .45)
        self.assertEqual(process.returncode, 14, stderr.decode(errors='replace'))
        self.assertEqual(stdout, b'')

    def test_default_failure_still_returns_without_the_repair_wait(self):
        with socket.socket() as reserved:
            reserved.bind(('127.0.0.1', 0))
            binary = runner.build_guest(self.root / 'input', port=reserved.getsockname()[1], work=16)
            process = self.native(binary)
            stdout, stderr = process.communicate(timeout=3)
        self.assertEqual(process.returncode, 14, stderr.decode(errors='replace'))
        self.assertEqual(stdout, b'')

    def test_successful_dialogue_does_not_take_the_failure_wait(self):
        errors = []
        listener = socket.socket()
        self.addCleanup(listener.close)
        listener.bind(('127.0.0.1', 0))
        listener.listen(1)
        listener.settimeout(3)

        def serve():
            try:
                connection, _ = listener.accept()
                with connection:
                    connection.settimeout(3)
                    for request, response in ((b'HELLO\n', b'READY\n'),
                                              (b'AUTH test\n', b'OK\n'),
                                              (b'GET CONFIG\n', b'interval=30\n')):
                        observed = b''
                        while len(observed) < len(request):
                            chunk = connection.recv(len(request) - len(observed))
                            if not chunk:
                                raise RuntimeError('fixture closed before completing its request')
                            observed += chunk
                        if observed != request:
                            raise RuntimeError('fixture sent an unexpected request')
                        connection.sendall(response)
            except Exception as exc:
                errors.append(exc)

        worker = threading.Thread(target=serve, daemon=True)
        worker.start()
        try:
            binary = runner.build_guest(self.root / 'input', port=listener.getsockname()[1], work=16,
                                        failure_grace_ms=5000)
            process = self.native(binary)
            stdout, stderr = process.communicate(timeout=3)
        finally:
            listener.close()
            worker.join(4)
        self.assertFalse(worker.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(process.returncode, 0, stderr.decode(errors='replace'))
        self.assertEqual(stdout, b'NET6_OK\n')


if __name__ == '__main__':
    unittest.main()
