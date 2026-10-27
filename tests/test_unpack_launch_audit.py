"""Fixed launch receipt binding on synthetic observations; no guest or SMT."""
import base64
import copy
import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT))
from unpacker import unpack_audit as audit
from unpacker import unpack_launch as launch_cases
from unpacker import unpack_observations as observations
from unpacker.unpack_sources import loader_regions
from test_unpack_audit import sample as receipt_sample


def digest(value):
    return hashlib.sha256(value).hexdigest()


def fixture(case):
    """Construct a valid static ELF and its explicit argc/argv/envp table."""
    base, entry, stack_base, esp = 0x8048000, 0x8048100, 0x40000000, 0x40000100
    target, run = 0x8054000, 'a' * 32
    header = struct.pack('<16sHHIIIIIHHHHHH', b'\x7fELF\x01\x01\x01' + bytes(9),
                         2, 3, 1, entry, 52, 0, 0, 52, 32, 1, 0, 0, 0)
    phdr = struct.pack('<IIIIIIII', 1, 0, base, base, 4096, 4096, 5, 4096)
    packed = header + phdr + bytes(4096 - len(header) - len(phdr))
    stack, cursor = bytearray(4096), 0x400
    pointers = []
    values = [['target.elf', *case['argv']], ['LC_ALL=C', 'TZ=UTC']]
    for strings in values:
        group = []
        for value in strings:
            encoded = value.encode('utf-8') + b'\0'
            group.append(stack_base + cursor)
            stack[cursor:cursor + len(encoded)] = encoded
            cursor += len(encoded)
        pointers.append(group)
    argv, envp = pointers
    words = [len(argv), *argv, 0, *envp, 0,
             3, base + 52, 4, 32, 5, 1, 6, 4096, 9, entry, 0, 0]
    stack[0x100:0x100 + len(words) * 4] = struct.pack('<' + 'I' * len(words), *words)
    layout = observations.parse_entry_table(bytes(stack), stack_base, esp)
    constructed = []
    for index, value in enumerate(words):
        address = esp + index * 4
        kind = next(i + 1 for i, region in enumerate(layout['regions'])
                    if region['address'] <= address < region['address'] + region['size'])
        constructed.append([address, value, kind])
    registers = {name: 0 for name in (*observations.GPRS, 'eflags')}
    registers.update(esp=esp, eflags=0x202)
    rows = [dict(kind='header', capture_kind='GENERIC_UNPACK_CAPTURE_V1', schema_version=1,
                 run_id=run, elf_sha256=digest(packed), elf_size=len(packed), initial_pc=entry,
                 initial_sp=esp, initial_df=0, target_pc=target,
                 guest_vma_api_version=1, entry_construction_api_version=1, brk_api_version=1,
                 binary_path_matches=True, captured_execution_only=True,
                 executed_pc_hash_encoding='LE32_EXECUTED_PC',
                 executed_fetch_hash_encoding='LE32_PC_U8_SIZE_BYTES'),
            dict(kind='initial', pc=entry, registers=registers),
            dict(kind='initial_geometry', stack_base=stack_base, stack_size=4096,
                 loads=[dict(base=base, size=4096, elf_flags=5)]),
            dict(kind='entry_construction', metadata=[1, 4, esp, len(argv), len(envp), entry, base + 52, 0],
                 words=constructed),
            dict(kind='vma_snapshot', phase='initial', ordinal=0, page_size=4096,
                 regions=[dict(start=base, end=base + 4096, prot=5, raw_flags=13),
                          dict(start=stack_base, end=stack_base + 4096, prot=7, raw_flags=31)]),
            dict(kind='brk', phase='initial', ordinal=0, initial=base + 4096, current=base + 4096)]
    for label, address, value in (('initial_load_0_0', base, packed),
                                  ('initial_stack_0_0', stack_base, bytes(stack))):
        rows.append(dict(kind='snapshot', label=label, address=address, size=len(value),
                         bytes_hex=value.hex(), syscall_ordinal=0))
    rows.append(dict(kind='payload_entry', pc=target, previous_pc=entry,
                     registers=registers, instruction_size=1, bytes_hex='00',
                     instructions=9, syscall_count=0, stopped_before_instruction=True,
                     target_instruction_executed=False))
    return packed, rows


class FixedLaunchAuditTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / 'proof'
        self.case = dict(id='binary-argv', argv=['word two', 'данные'],
                         stdin_base64=base64.b64encode(b'\0abc\xff\n').decode())
        self.packed, self.rows = fixture(self.case)
        receipt_sample(self.root, packed=self.packed)
        self.summary = self.read('summary.json')
        self.certificate = self.read('smt/certificate.json')
        directory = self.root / 'capture'
        self.launch = dict(schema_version=1, run_id='a' * 32, source_elf_sha256=digest(self.packed),
            target=0x8054000, target_pc=0x8054000, launch_input_profile=launch_cases.PROFILE,
            launch_case_file='launch-case.json', stdin_file='stdin.bin',
            new_independent_execution=True, returncode=0, payload_instruction_execution_allowed=False,
            execution_mode='normal', guest_environ=['LC_ALL=C', 'TZ=UTC'],
            controlled_host_environment={'LC_ALL': 'C', 'TZ': 'UTC'}, cwd=str(directory))
        self.apply_case(self.case)
        self.write_events()
        context = observations.initial_context(self.rows, self.packed,
            loader_regions(self.packed), launch=self.launch)
        projection = context['origin_mask']
        self.write_bytes('inputs/stack-mask.bin', projection)
        self.write_bytes('inputs/stack.bin', bytes(v & k for v, k in zip(context['stack'], projection)))
        self.write_bytes('inputs/scalars.txt', f"{context['esp']:x} {context['df']:x}\n".encode())
        self.write_bytes('inputs/contracts.txt', b'')
        self.write_bytes('inputs/config.txt', b'TFOEPGEN1C\n8054000 40000000 100\nmacro_once\n1\n8054000 4096\n')
        self.write('initial-premises.json', observations.validate_projection(context, projection))
        source_receipt = {}
        for name in ('unpack_launch.py', 'unpack_process.py'):
            source = PROJECT / 'unpacker' / name
            self.write_bytes('source/' + name, source.read_bytes())
            source_receipt[name] = digest(source.read_bytes())
        self.write('source-receipt.json', source_receipt)
        hashes = [digest((self.root / 'inputs' / name).read_bytes()) for name in audit.INPUT_NAMES]
        self.certificate['replay_input_files_sha256'] = hashes
        manifest = self.read('reduced/producers/manifest.json')
        manifest['input_files_sha256'] = hashes
        self.write('reduced/producers/manifest.json', manifest)
        self.summary.update(self.certificate)
        self.summary.update(run_id=self.launch['run_id'], launch_input_profile=launch_cases.PROFILE,
                            capture_events_sha256=digest((directory / 'events.jsonl').read_bytes()))
        report = self.read('capture/report.json')
        report.update(run_id=self.launch['run_id'], events_sha256=self.summary['capture_events_sha256'])
        self.write('capture/report.json', report)
        self.sync()

    def read(self, name):
        return json.loads((self.root / name).read_bytes())

    def write(self, name, value):
        self.write_bytes(name, (json.dumps(value, sort_keys=True) + '\n').encode())

    def write_bytes(self, name, value):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(value)

    def apply_case(self, case):
        case = launch_cases.normalize_case(case)
        incoming = launch_cases.stdin_bytes(case)
        self.write_bytes('capture/launch-case.json', launch_cases.case_bytes(case))
        self.write_bytes('capture/stdin.bin', incoming)
        self.launch.update(launch_case_id=case['id'], launch_case_sha256=launch_cases.case_sha256(case),
            stdin_sha256=digest(incoming), stdin_size=len(incoming), stdin_empty=not incoming,
            stdin_offset_after_capture=0, guest_argv=['target.elf', *case['argv']],
            argv=['/trusted/qemu', '-s', '1044480', '-plugin', '/trusted/observer.so',
                  '-0', 'target.elf', str(self.root / 'capture/packed.elf'), *case['argv']])
        self.summary['launch_input_binding'] = launch_cases.validate_launch(self.launch, case, incoming,
            capture_directory=self.root / 'capture')

    def sync(self):
        self.write('summary.json', self.summary)
        self.write('smt/certificate.json', self.certificate)
        self.write('capture/launch.json', self.launch)

    def write_events(self):
        prefix = b''.join(json.dumps(row, separators=(',', ':')).encode() + b'\n' for row in self.rows)
        footer = dict(kind='footer', success=True, reason='selected_candidate_boundary',
            instructions=9, syscall_count=0, syscall_returns=0, stopped_before_instruction=True,
            target_instruction_executed=False, executed_pc_sha256='4' * 64,
            executed_fetch_sha256='4' * 64, run_id='a' * 32,
            events_bytes_before_footer=len(prefix), events_sha256_before_footer=digest(prefix))
        self.write_bytes('capture/events.jsonl', prefix + json.dumps(footer).encode() + b'\n')

    def binding(self, expected=None):
        return audit._launch_input_binding(audit._Reader(self.root), self.summary, self.certificate,
            self.launch, expected_launch_case=self.case if expected is None else expected)

    def test_nonempty_binary_stdin_and_unicode_argv_are_bound_with_original_entry_premises(self):
        result = self.binding()
        self.assertTrue(result['fixed_case_only'])
        self.assertTrue(result['entry_constructor_and_launch_strings_reaudited'])
        self.assertTrue(result['consumed_stack_projection_reaudited'])
        self.assertTrue(result['stdin_unconsumed_before_selected_boundary'])
        self.assertFalse(result['input_domain_universally_proved'])
        self.assertFalse(result['payload_behavior_proved'])

    def test_complete_receipt_audit_invokes_fixed_launch_binding(self):
        with patch.object(audit, '_rep_runtime_binding', return_value=None):
            result = audit.audit_sample(self.root, expected_launch_case=self.case)
        self.assertEqual(result['status'], audit.STATUS)
        self.assertTrue(result['fixed_launch_case_audited'])
        self.assertIn('capture/stdin.bin', result['audited_file_sha256'])
        self.assertIn('capture/events.jsonl', result['audited_file_sha256'])
        self.assertIn('source/unpack_launch.py', result['audited_file_sha256'])

    def test_changed_stdin_byte_is_rejected(self):
        self.write_bytes('capture/stdin.bin', b'changed')
        with self.assertRaisesRegex(ValueError, 'stdin differs'):
            self.binding()

    def test_coherently_rehashed_case_still_must_match_external_request(self):
        changed = dict(self.case, stdin_base64=base64.b64encode(b'other').decode())
        self.apply_case(changed)
        with self.assertRaisesRegex(ValueError, 'requested case'):
            self.binding()

    def test_coherently_rehashed_argv_still_requires_observed_constructor_strings(self):
        changed = dict(self.case, argv=['different', 'данные'])
        self.apply_case(changed)
        with self.assertRaisesRegex(ValueError, 'Launch string'):
            self.binding(expected=changed)

    def test_changed_command_argument_order_or_argv0_is_rejected(self):
        for index, value in ((6, 'other.elf'), (-1, 'changed')):
            with self.subTest(index=index):
                original = self.launch['argv'][index]
                self.launch['argv'][index] = value
                with self.assertRaisesRegex(ValueError, 'command'):
                    self.binding()
                self.launch['argv'][index] = original

    def test_reduced_stack_and_projection_cannot_introduce_unobserved_bytes(self):
        path = self.root / 'inputs/stack.bin'
        original = path.read_bytes()
        changed = bytearray(original)
        changed[0x400] ^= 1
        path.write_bytes(changed)
        with self.assertRaisesRegex(ValueError, 'stack differs'):
            self.binding()
        path.write_bytes(original)
        path = self.root / 'inputs/stack-mask.bin'
        mask = bytearray(path.read_bytes())
        mask[0x800] = 255
        path.write_bytes(mask)
        with self.assertRaisesRegex(ValueError, 'lacks constructor'):
            self.binding()

    def test_changed_scalar_contract_and_config_are_rejected(self):
        for name, value, message in (
                ('scalars.txt', b'40000104 0\n', 'scalars'),
                ('contracts.txt', b'1000 3 0 0 0 0 0 0 0 -\n', 'contracts'),
                ('config.txt', b'TFOEPGEN1C 8054000 40001000 100 macro_once 1 8054000 4096', 'configuration')):
            with self.subTest(name=name):
                path = self.root / 'inputs' / name
                original = path.read_bytes()
                path.write_bytes(value)
                with self.assertRaisesRegex(ValueError, message):
                    self.binding()
                path.write_bytes(original)

    def test_retained_event_digest_cannot_be_replaced(self):
        self.write_bytes('capture/events.jsonl', b'{}\n')
        with self.assertRaisesRegex(ValueError, 'event identity'):
            self.binding()

    def test_rehashed_input_read_before_boundary_still_fails_the_supported_prefix(self):
        # A declared stdin file is not a license to replace unsupported read
        # effects with observed bytes in the replay source premises.
        registers = {name: 0 for name in (*observations.GPRS, 'eflags')}
        registers.update(eax=3, esp=0x40000100, eflags=0x202)
        self.rows.insert(-1, dict(kind='syscall_enter', ordinal=1, pc=0x8048100,
                                 number=3, args=[0, 0x40000800, 1, 0, 0, 0], registers=registers))
        self.write_events()
        self.summary['capture_events_sha256'] = digest((self.root / 'capture/events.jsonl').read_bytes())
        with self.assertRaisesRegex(ValueError, 'Unsupported captured syscall'):
            self.binding()

    def test_rehashed_validator_source_is_not_a_recognized_implementation(self):
        data = b'# changed validator\n'
        self.write_bytes('source/unpack_launch.py', data)
        receipt = self.read('source-receipt.json')
        receipt['unpack_launch.py'] = digest(data)
        self.write('source-receipt.json', receipt)
        with self.assertRaisesRegex(ValueError, 'validator source'):
            self.binding()

    def test_scope_promotion_and_positive_stdin_offset_are_rejected(self):
        self.summary['launch_input_binding']['input_domain_universally_proved'] = True
        with self.assertRaisesRegex(ValueError, 'Summary launch'):
            self.binding()
        self.apply_case(self.case)
        self.launch['stdin_offset_after_capture'] = 1
        with self.assertRaisesRegex(ValueError, 'unconsumed'):
            self.binding()

    def test_erasing_profile_metadata_cannot_silently_downgrade_case_artifacts(self):
        del self.launch['launch_input_profile']
        del self.summary['launch_input_profile']
        del self.summary['launch_input_binding']
        with self.assertRaisesRegex(ValueError, 'profile differs'):
            self.binding()

    def test_legacy_bundle_cannot_satisfy_an_explicit_case_request(self):
        root = Path(self.temp.name) / 'legacy'
        receipt_sample(root)
        with self.assertRaisesRegex(ValueError, 'Expected launch case'):
            audit.audit_sample(root, expected_launch_case=self.case)
        result = audit.audit_sample(root)
        self.assertEqual(result['status'], audit.STATUS)
        self.assertNotIn('fixed_launch_case_audited', result)


if __name__ == '__main__':
    unittest.main()
