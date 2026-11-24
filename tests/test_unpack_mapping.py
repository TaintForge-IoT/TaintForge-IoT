import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from unpacker import unpack, unpack_mapping as mapping


START, SIZE = 0x24000000, 0x2345


def allocation(start=START, size=SIZE, prot='PROT_READ|PROT_WRITE', flags='MAP_PRIVATE|MAP_ANONYMOUS'):
    return ('call', ('mmap2', f'NULL,{size},{prot},{flags},-1,0', hex(start)))


class MappingEvidence(unittest.TestCase):
    def test_rebuilt_reader_accepts_both_elf_parser_signatures(self):
        path = Path('rebuilt.elf')
        image = {'entry': 0x8048000}

        def legacy_reader(source):
            self.assertEqual(source, path)
            return image

        def tls_reader(source, *, allow_tls=False):
            self.assertTrue(allow_tls)
            return legacy_reader(source)

        for reader in (legacy_reader, tls_reader):
            with self.subTest(reader=reader.__name__), patch.object(mapping.ct_elf, 'read_elf', reader):
                self.assertIs(mapping.read_rebuilt_elf(path), image)

    def test_uses_returned_base_and_byte_length(self):
        events = [allocation(), allocation(0x31000000, 4096), ('pc', 128)]
        kept = mapping.mapping_history(events, 2, START + SIZE - 1)
        self.assertEqual((kept['start'], kept['length'], kept['allocation']['returned']), (START, SIZE, hex(START)))
        with self.assertRaises(ValueError):
            mapping.mapping_history(events, 2, START + SIZE)

    def test_stale_allocation_and_page_overlap(self):
        for call in [('munmap', hex(START) + ',4096', '0'),
                     ('mprotect', hex(START + 8192) + ',4096,PROT_NONE', '0'),
                     ('mremap', hex(START) + ',4096,8192,0', '0x31000000'),
                     ('mmap2', 'NULL,4096,PROT_READ,MAP_PRIVATE,7,0', hex(START + 8192))]:
            with self.subTest(call=call), self.assertRaises(ValueError):
                mapping.mapping_history([allocation(), ('pc', 128), ('call', call)], 1, START + 4)

    def test_failed_unmap_and_post_entry_allocation(self):
        failed = ('call', ('munmap', hex(START) + ',4096', '-1 errno=22 (Invalid argument)'))
        self.assertEqual(mapping.mapping_history([allocation(), failed], 1, START)['length'], SIZE)
        with self.assertRaises(ValueError):
            mapping.mapping_history([('pc', 128), allocation()], 0, START)

    def test_file_backed_shared_and_executable_do_not_qualify(self):
        for call in [allocation(flags='MAP_PRIVATE'), allocation(flags='MAP_SHARED|MAP_ANONYMOUS'),
                     allocation(prot='PROT_READ|PROT_WRITE|PROT_EXEC')]:
            with self.subTest(call=call), self.assertRaises(ValueError):
                mapping.mapping_history([call], 1, START)

    def test_earlier_control_or_syscall_difference(self):
        entry, access = ('pc', 128), ('pc', 160)
        original = [allocation(), entry, ('pc', 132), access, ('exit', 0)]
        for difference in [('pc', 136), ('call', ('close', '6', '0'))]:
            with self.subTest(difference=difference), self.assertRaises(ValueError):
                mapping.correlate(original, [entry, difference, access, ('fault', START)], 128)

    def test_page_table_at_dynamic_occurrence(self):
        marker = 'Trace 0: 0xabc [0000/00000080/00/00]\n'
        table = 'start    end      size     prot\n'
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'trace'
            path.write_text(table + '24000000-24003000 00003000 rw-\n' + marker + table
                            + '25000000-25001000 00001000 r--\n' + marker)
            self.assertEqual(mapping.maps_at_site(path, 128, 128, 2), [(0x25000000, 0x25001000, 'r--')])

    def test_reject_signal_permissions_incomplete_and_process_boundaries(self):
        for record in ({'payload_role': 'parent', 'process_exits': {'parent': {}, 'child': {}}},
                       {'payload_role': 'parent', 'process_exit_error': {'reason': 'INCOMPLETE_PROCESS_EXIT'}}):
            with self.subTest(record=record), self.assertRaises(ValueError):
                mapping.check_single_process(record)
        for record in ('--- SIGSEGV {si_signo=SIGSEGV, si_code=2, si_addr=0x24000000} ---',
                       '9 mmap2(NULL,4096,', '9 clone(17,0,0) = 10',
                       '9 read(0,0,0) = 0\n10 exit(0)'):
            with self.subTest(record=record), tempfile.TemporaryDirectory() as directory:
                p = Path(directory) / 'trace'
                p.write_text(record + '\n')
                with self.assertRaises(ValueError):
                    mapping.events(p)


class MappingUnpack(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        qemu = os.environ.get('TF_QEMU_I386') or shutil.which('qemu-i386')
        plugin, include = os.environ.get('TF_PHASE1_PLUGIN'), os.environ.get('TF_QEMU_INCLUDE')
        if not qemu or not (plugin or include):
            raise unittest.SkipTest('set TF_QEMU_I386 and TF_PHASE1_PLUGIN or TF_QEMU_INCLUDE')
        cls.work = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.work.cleanup)
        cls.root = Path(cls.work.name)
        cls.qemu = Path(qemu).resolve(strict=True)
        cls.plugin = Path(plugin).resolve(strict=True) if plugin else unpack.build_plugin(include, cls.root/'plugin')

    def capture(self, *defines, enabled=True, follow=False):
        d = self.root / self._testMethodName
        d.mkdir()
        args = [arg for name in defines for arg in ('--defsym', name + '=1')]
        assembly = Path(__file__).with_name('phase1_unpack_mapping.S')
        subprocess.run(['as', '--32', *args, '-o', d/'guest.o', assembly], check=True)
        subprocess.run(['ld', '-m', 'elf_i386', '-static', '-o', d/'guest', d/'guest.o'], check=True)
        self.out = d / 'out'
        return unpack.unpack_sample(d/'guest', self.out, qemu=self.qemu, plugin=self.plugin,
                                    cases=[{'id': 'indirect-load', 'stdin_base64': 'Kg=='}], timeout=10,
                                    follow_fork=follow, diagnose_mappings=enabled)

    def test_missing_mapping_after_first_payload_syscall(self):
        with self.assertRaises(unpack.UnpackError) as caught:
            self.capture()
        self.assertEqual(caught.exception.reason, 'CASE_EXECUTION_FAILED')
        summary = json.loads((self.out/'summary.json').read_text())
        self.assertEqual(summary['status'], 'FAIL')
        report = json.loads((self.out / summary['mapping_diagnosis']['report']).read_text())
        self.assertEqual(report['status'], 'MAPPING_RESTORES_CASE', report)
        info = report['mapping']
        self.assertEqual((info['start'], info['length'], info['fault_address']), (START, SIZE, START + 0x2008))
        self.assertEqual(info['prior_payload_syscalls'], 1)
        self.assertTrue(report['trial']['matches_packed_syscalls'])
        self.assertEqual(unpack.file_digest(self.out/'rebuilt.elf'), report['rebuilt_sha256'])
        self.assertNotEqual(report['rebuilt_sha256'], report['trial_sha256'])

    def test_healthy_workload(self):
        self.assertEqual(self.capture('HEALTHY')['status'], unpack.STATUS)
        self.assertFalse((self.out/'mapping-diagnosis').exists())

    def test_stack_syscall_arguments_and_single_process_in_fork_profile(self):
        with self.assertRaises(unpack.UnpackError):
            self.capture('STACK_IO', follow=True)
        report = json.loads((self.out/'mapping-diagnosis/report.json').read_text())
        self.assertEqual(report['status'], 'MAPPING_RESTORES_CASE', report)
        self.assertEqual(report['trial']['post_entry_syscalls'], 3)
        trial = json.loads((self.out/'mapping-diagnosis/t/trial-0/result.json').read_text())
        self.assertEqual(set(trial['process_exits']), {'parent'})
        self.assertEqual(trial['process_exits']['parent']['returncode'], trial['returncode'])

    def test_zeros_do_not_reproduce_initialized_data(self):
        with self.assertRaises(unpack.UnpackError):
            self.capture('SEEDED')
        report = json.loads((self.out/'mapping-diagnosis/report.json').read_text())
        self.assertEqual(report['status'], 'MAPPING_CANDIDATE', report)
        self.assertFalse(report['trial']['matches_packed_observations'])

    def test_ordinary_failure_without_option(self):
        with self.assertRaises(unpack.UnpackError) as caught:
            self.capture(enabled=False)
        self.assertEqual(caught.exception.reason, 'CASE_EXECUTION_FAILED')
        self.assertFalse((self.out/'mapping-diagnosis').exists())
