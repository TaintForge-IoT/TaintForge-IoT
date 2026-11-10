import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from unpacker.mvp import ct_elf


PAGE = ct_elf.PAGE
BASE = 0x8048000
ENTRY = BASE + PAGE
DATA = BASE + 3 * PAGE
TLS_ADDRESS = DATA + 64
TLS_FILE_OFFSET = 2 * PAGE + 64
TEMPLATE = b'\x00\x8a\x14\xf2'
TLS = (ct_elf.PT_TLS, TLS_FILE_OFFSET, TLS_ADDRESS, TLS_ADDRESS,
       len(TEMPLATE), 0x2040, 4, 64)


def changed_header(header, index, value):
    values = list(header)
    values[index] = value
    return tuple(values)


class CaptureTLSTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.report = self.directory / 'capture.json'
        self.dump = self.directory / 'capture.bin'
        self.output = self.directory / 'rebuilt.elf'

    def write_capture(self, tls_headers=(TLS,), *, source_entry=ENTRY, extra_loads=(),
                      report_fields=None, header_prot=1, data_prot=3, capture_data=True):
        load_headers = (
            (ct_elf.PT_LOAD, 0, BASE, BASE, PAGE, PAGE, 4, PAGE),
            (ct_elf.PT_LOAD, PAGE, ENTRY, ENTRY, 32, 32, 5, PAGE),
            (ct_elf.PT_LOAD, 2 * PAGE, DATA, DATA, 256, 256, 6, PAGE),
        )
        headers = load_headers + extra_loads + tls_headers
        ident = b'\x7fELF\x01\x01\x01' + bytes(9)
        header = ct_elf.ELF_HEADER.pack(
            ident, 2, 3, 1, source_entry, ct_elf.ELF_HEADER.size, 0, 0,
            ct_elf.ELF_HEADER.size, ct_elf.PROGRAM_HEADER.size, len(headers), 0, 0, 0)
        header_page = (header + b''.join(ct_elf.PROGRAM_HEADER.pack(*p) for p in headers))
        data_page = bytes([0xa5]) * 64 + TEMPLATE + bytes([0xa5]) * (PAGE - 64 - len(TEMPLATE))
        pages = [(BASE, header_prot, header_page.ljust(PAGE, b'\0')),
                 (ENTRY, 5, b'\x90' * PAGE)]
        if capture_data:
            pages.append((DATA, data_prot, data_page))
        regions = [
            dict(addr=address, size=PAGE, offset=index * PAGE, prot=prot, lib=False,
                 sha256=hashlib.sha256(data).hexdigest())
            for index, (address, prot, data) in enumerate(pages)
        ]
        report = dict(schema_version=1, arch='x86', byte_order='little',
                      main_image_verified=True, base=BASE, oep=ENTRY,
                      capture_status='success', capture_gaps=[], library_dependencies=[],
                      resolved_imports=[], regions=regions)
        report.update(report_fields or {})
        self.report.write_text(json.dumps(report), encoding='utf-8')
        self.dump.write_bytes(b''.join(data for _, _, data in pages))

    def rebuild(self):
        return ct_elf.rebuild(self.report, self.dump, self.output)

    def test_initialized_template_preserves_bytes_beyond_filesz(self):
        self.write_capture()
        receipt = self.rebuild()
        self.assertIsNotNone(receipt.get('tls'))
        with self.assertRaises(ct_elf.CaptureError):
            ct_elf.read_elf(self.output)
        elf = ct_elf.read_elf(self.output, allow_tls=True)
        tls = elf['tls']
        self.assertEqual(
            {name: tls[name] for name in ('address', 'filesz', 'memsz', 'flags', 'align')},
            dict(address=TLS_ADDRESS, filesz=len(TEMPLATE), memsz=0x2040, flags=4, align=64))
        data_load = next(load for load in elf['loads'] if load['address'] == DATA)
        self.assertEqual(tls['offset'], data_load['offset'] + 64)
        self.assertGreater(tls['memsz'], data_load['memsz'])
        offset = tls['offset']
        self.assertEqual(elf['data'][offset:offset + len(TEMPLATE) + 4], TEMPLATE + b'\xa5' * 4)
        header = ct_elf.ELF_HEADER.unpack_from(elf['data'])
        phdr = ct_elf.PROGRAM_HEADER.unpack_from(elf['data'], header[5])
        self.assertEqual(phdr[0], ct_elf.PT_PHDR)
        self.assertEqual(phdr[4:6], (header[10] * ct_elf.PROGRAM_HEADER.size,) * 2)

    def test_pure_tbss_does_not_require_a_captured_initializer(self):
        address = DATA + PAGE
        self.write_capture(((ct_elf.PT_TLS, 3 * PAGE, address, address, 0, 0x2000, 4, 64),),
                           capture_data=False)
        self.rebuild()
        tls = ct_elf.read_elf(self.output, allow_tls=True)['tls']
        self.assertEqual((tls['address'], tls['filesz'], tls['memsz'], tls['align']),
                         (address, 0, 0x2000, 64))
        self.assertEqual(tls['offset'] % tls['align'], address % tls['align'])

    def test_unbound_headers_are_not_used_for_tls(self):
        for options in (
            dict(source_entry=ENTRY + 1),
            dict(report_fields={'base': DATA}),
            dict(report_fields={'main_image_verified': False}),
            dict(header_prot=0),
        ):
            with self.subTest(options=options):
                self.write_capture(**options)
                self.assertIsNone(self.rebuild().get('tls'))
                self.assertIsNone(ct_elf.read_elf(self.output, allow_tls=True).get('tls'))
                self.output.unlink()

    def test_malformed_tls_claims_do_not_publish_an_elf(self):
        for headers in (
            (TLS, TLS),
            (changed_header(TLS, 5, 1),),
            (changed_header(TLS, 7, 3),),
            (changed_header(TLS, 7, 2 * PAGE),),
            (changed_header(TLS, 1, TLS_FILE_OFFSET + 64),),
            ((ct_elf.PT_TLS, 0, 0xfffffff0, 0xfffffff0, 0, 32, 4, 4),),
        ):
            with self.subTest(headers=headers):
                self.write_capture(headers)
                with self.assertRaises(ct_elf.CaptureError):
                    self.rebuild()
                self.assertEqual(list(self.directory.glob('rebuilt.elf*')), [])

    def test_initializer_must_be_captured_and_readable(self):
        for options in (dict(capture_data=False), dict(data_prot=2)):
            with self.subTest(options=options):
                self.write_capture(**options)
                with self.assertRaises(ct_elf.CaptureError):
                    self.rebuild()
                self.assertFalse(self.output.exists())

    def test_partially_overlapping_loads_are_ambiguous(self):
        for address, size in ((TLS_ADDRESS + 1, 1), (BASE + 64, 64)):
            with self.subTest(address=address):
                extra_load = (ct_elf.PT_LOAD, 3 * PAGE + address % PAGE,
                              address, address, size, size, 4, PAGE)
                self.write_capture(extra_loads=(extra_load,))
                output = self.directory / f'overlap-{address:x}.elf'
                with self.assertRaises(ct_elf.CaptureError):
                    ct_elf.rebuild(self.report, self.dump, output)
                self.assertFalse(output.exists())


if __name__ == '__main__':
    unittest.main()
