"""Bounded observation time in the fixed NET-6/NET-8 guest fixtures."""
import asyncio
import json
import os
from pathlib import Path
import shutil
import socket
import struct
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch

from scripts import run_network_capsule_e2e as net6
from scripts import run_network_capsule_sessions_e2e as net8
from taintforge_env.elf_runtime import ElfImage
from taintforge_env.network_capsule_sessions import BY_NAME, MARKER
from taintforge_env.network_policy import load_network_policy
from taintforge_env.network_replay import replay_service


@unittest.skipUnless(all(shutil.which(tool) for tool in ('as', 'ld', 'nm', 'objdump')), 'binutils required')
class ObservationWindowFixtureTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def test_grace_arguments_are_checked_before_writing(self):
        for index, value in enumerate((True, 10.0, -10, 1, 10001, 10010)):
            for module, arguments, keyword in ((net6, {'port':4444}, 'success_grace_ms'),
                                               (net8, {'port':4444, 'mode':0}, 'exit_grace_ms')):
                path = self.root / (keyword + str(index))
                with self.subTest(value=value, keyword=keyword), self.assertRaises((ValueError,RuntimeError)):
                    module.build_guest(path, work=1, **arguments, **{keyword:value})
                self.assertFalse(path.exists())

    def test_assembler_rejects_invalid_window_bounds(self):
        for source, definition in (('network_capsule_i386.S','NET6_SUCCESS_GRACE_MS'),
                                    ('network_capsule_session_i386.S','NET8_EXIT_GRACE_MS')):
            for value in (-10, 1, 10010):
                with self.subTest(source=source, value=value):
                    result = subprocess.run(['as','--32','--defsym',f'{definition}={value}',
                        str(net6.PROJECT/'samples'/source),'-o',str(self.root/'bad.o')],capture_output=True,text=True)
                    self.assertNotEqual(result.returncode, 0)

    def test_build_inventory_binds_the_selected_grace_and_default_stays_zero(self):
        for label, module, arguments, keyword, definition in (
            ('net6',net6,{'port':4444},'success_grace_ms','NET6_SUCCESS_GRACE_MS'),
            ('net8',net8,{'port':4444,'mode':0},'exit_grace_ms','NET8_EXIT_GRACE_MS')):
            for bound in (0, 500, 10000):
                with self.subTest(label=label, bound=bound):
                    binary=module.build_guest(self.root/f'{label}-{bound}',work=1,**arguments,**{keyword:bound})
                    build=json.loads((binary.parent/'build.json').read_text())
                    self.assertEqual(build['definitions'][definition],bound)
                    self.assertEqual(build['binary_sha256'],net6.sha(binary))
                    symbols=subprocess.check_output(['nm','--defined-only',str(binary)],text=True)
                    self.assertEqual('observation_pause' in symbols,bool(bound))

    def test_net6_success_window_is_finite_and_preserves_exit_zero(self):
        binary=net6.build_guest(self.root/'net6',port=4444,work=1,success_grace_ms=500)
        text=subprocess.check_output(['objdump','-d','--no-show-raw-insn',str(binary)],text=True)
        success=text.split('<success_wait>:',1)[1].split('<failed>:',1)[0]
        self.assertRegex(success,r'mov\s+\$0x32,%edi')
        self.assertRegex(success,r'mov\s+\$0xa2,%eax')
        self.assertRegex(success,r'dec\s+%edi')
        self.assertRegex(success,r'xor\s+%ebx,%ebx')
        self.assertIn('<quit>',success)
        self.check_timespec(binary)

    def test_net8_common_exit_preserves_the_application_code_across_wait(self):
        binary=net8.build_guest(self.root/'net8',port=4444,mode=0,work=1,exit_grace_ms=500)
        text=subprocess.check_output(['objdump','-d','--no-show-raw-insn',str(binary)],text=True)
        exit_path=text.split('<exit>:',1)[1].split('<payload_source>:',1)[0]
        self.assertRegex(exit_path,r'mov\s+%ebx,%ebp')
        self.assertRegex(exit_path,r'mov\s+\$0x32,%edi')
        self.assertRegex(exit_path,r'mov\s+\$0xa2,%eax')
        self.assertRegex(exit_path,r'dec\s+%edi')
        self.assertRegex(exit_path,r'mov\s+%ebp,%ebx')
        self.assertRegex(exit_path,r'mov\s+\$0x1,%eax')
        self.check_timespec(binary)

    def check_timespec(self,binary):
        symbols=subprocess.check_output(['nm','--defined-only','--format=posix',str(binary)],text=True)
        addresses={p[0]:int(p[2],16) for p in (line.split() for line in symbols.splitlines())}
        elf=ElfImage(binary)
        offset=elf.offset_for(addresses['observation_pause'],8)
        self.assertEqual(struct.unpack_from('<II',elf.data,offset),(0,10000000))

    def test_native_net6_cases_select_a_window_for_successful_completion(self):
        class Captured(Exception):
            pass
        for name in net6.CASES:
            with self.subTest(name=name), patch.object(net6,'build_guest',side_effect=Captured) as build:
                with self.assertRaises(Captured):
                    net6.run_case(self.root/name,name,self.root/'qemu',self.root/'phase1',self.root/'observer')
                self.assertEqual(build.call_args.kwargs['success_grace_ms'],5000)
                self.assertEqual(build.call_args.kwargs['failure_grace_ms'],5000 if name=='repair' else 0)

    def test_native_net8_cases_select_a_window_for_every_exit(self):
        class Captured(Exception):
            pass
        for case in net8.CASES:
            with self.subTest(name=case.name), patch.object(net8,'build_guest',side_effect=Captured) as build:
                with self.assertRaises(Captured):
                    net8.run_case(self.root/case.name,case,self.root/'qemu',self.root/'phase1',self.root/'observer')
                self.assertEqual(build.call_args.kwargs['exit_grace_ms'],5000)

    def test_checks_run_in_the_correct_acceptance_groups(self):
        from taintforge_env import network_acceptance as acceptance
        self.assertIn('tests.test_network_capsule_observation_window.ObservationWindowFixtureTests',acceptance.UNIT_TESTS)
        check=next(check for check in acceptance.CHECKS if check.name=='qemu_protocols')
        self.assertIn('tests.test_network_capsule_observation_window.ObservationWindowGuestTests',check.tests)


@unittest.skipUnless(os.environ.get('TF_NET6_QEMU'), 'selected QEMU required')
class ObservationWindowGuestTests(unittest.IsolatedAsyncioTestCase):
    async def exercise(self, *, version, case_name='ordered', bound=500, expected_exit=0):
        qemu=Path(os.environ['TF_NET6_QEMU']).resolve(strict=True)
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            with socket.socket() as guard:
                guard.bind(('127.0.0.1',0))
                port=guard.getsockname()[1]
            if version==6:
                binary=net6.build_guest(root/'input',port=port,work=1,success_grace_ms=bound)
                store=net6.policy_and_store(root,'tcp',port=port,remote='127.0.0.1')
                marker=b'NET6_OK\n'
            else:
                case=BY_NAME[case_name]
                binary=net8.build_guest(root/'input',port=port,mode=case.mode,work=1,exit_grace_ms=bound)
                store,_=net8.prepare_policy(root,case,port)
                marker=MARKER if case.goal else b''
            responder=replay_service(service=load_network_policy(root/'policy.json').services[0],store=store,log_dir=root/'logs')
            listener=await responder.start()
            process=None
            try:
                started=time.monotonic()
                process=await asyncio.create_subprocess_exec(str(qemu),str(binary),stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.PIPE)
                if marker:
                    self.assertEqual(await asyncio.wait_for(process.stdout.readexactly(len(marker)),3),marker)
                    await asyncio.sleep(.1)
                    self.assertIsNone(process.returncode,'fixture exited before its observation window')
                rest,stderr=await asyncio.wait_for(process.communicate(),4)
                self.assertEqual(rest,b'')
                self.assertEqual(process.returncode,expected_exit,stderr.decode(errors='replace'))
                self.assertGreaterEqual(time.monotonic()-started,.45)
            finally:
                if process is not None and process.returncode is None:
                    process.kill()
                    await process.communicate()
                listener.close()
                await listener.wait_closed()

    async def test_net6_success_preserves_marker_and_exit_after_observation_window(self):
        await self.exercise(version=6)

    async def test_net8_success_preserves_marker_and_exit_after_observation_window(self):
        await self.exercise(version=8)

    async def test_net8_negative_dialogue_keeps_its_exit_and_no_success_marker(self):
        await self.exercise(version=8,case_name='wrong_order',expected_exit=20)


if __name__=='__main__':
    unittest.main()
