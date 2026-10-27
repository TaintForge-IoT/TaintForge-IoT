"""Concrete launch identity and real Python child I/O; no QEMU or SMT substitute."""
import base64
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from unpacker import unpack_launch as launch
from unpacker import unpack_proof as proof

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_unpack_proof as flow_fixture


def case(data=b'\x00input\xff\n', argv=None):
    return dict(id='binary-input', argv=['-c', 'two words', '\u043f\u0443\u0442\u044c'] if argv is None else argv,
                stdin_base64=base64.b64encode(data).decode('ascii'))


def manifest(directory, value):
    normalized = launch.normalize_case(value)
    data = launch.stdin_bytes(value)
    return dict(schema_version=1, launch_input_profile=launch.PROFILE,
        launch_case_file=launch.CASE_FILE, stdin_file=launch.STDIN_FILE,
        launch_case_id=normalized['id'], launch_case_sha256=launch.case_sha256(value),
        stdin_sha256=hashlib.sha256(data).hexdigest(), stdin_size=len(data),
        stdin_empty=not data, stdin_offset_after_capture=0,
        guest_argv=['target.elf', *normalized['argv']],
        guest_environ=['LC_ALL=C', 'TZ=UTC'], controlled_host_environment={'LC_ALL': 'C', 'TZ': 'UTC'},
        cwd=str(directory), new_independent_execution=True, returncode=0,
        payload_instruction_execution_allowed=False, execution_mode='normal',
        argv=['/trusted/qemu', '-s', '1044480', '-plugin', '/trusted/plugin,fixture=true',
              '-0', 'target.elf', str(directory / 'packed.elf'), *normalized['argv']])


class FixedCaseTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def test_binary_stdin_and_argv_have_one_canonical_detached_case(self):
        value = case()
        normalized = launch.normalize_case(value)
        encoded = launch.case_bytes(value)
        self.assertEqual(json.loads(encoded), normalized)
        self.assertEqual(launch.case_sha256(value), hashlib.sha256(encoded).hexdigest())
        self.assertEqual(launch.stdin_bytes(normalized), b'\x00input\xff\n')
        value['argv'][0] = 'changed'
        self.assertEqual(normalized['argv'][0], '-c')
        self.assertEqual(encoded, launch.case_bytes(normalized))

    def test_empty_case_is_explicit_and_empty_artifact_is_valid(self):
        value = case(b'', [])
        record = manifest(self.root, value)
        receipt = launch.validate_launch(record, value, b'', capture_directory=self.root)
        self.assertEqual(receipt['stdin_bytes'], 0)
        self.assertEqual(receipt['stdin_sha256'], hashlib.sha256(b'').hexdigest())
        self.assertEqual(receipt['argv'], [])

    def test_empty_file_fields_from_existing_cases_are_normalized(self):
        value = dict(case(), files={}, output_files=[])
        self.assertEqual(set(launch.normalize_case(value)), {'id', 'argv', 'stdin_base64'})

    def test_unknown_file_inputs_and_malformed_cases_are_rejected(self):
        invalid = [dict(case(), files={'input': ''}), dict(case(), output_files=['output']),
            dict(case(), extra=True), dict(case(), id='../escape'),
            dict(case(), argv=['\0bad']), dict(case(), argv=['x' * 4097]),
            dict(case(), argv=['x'] * 33), dict(case(), stdin_base64='!!!!'),
            dict(case(), stdin_base64='YR=='), dict(case(), stdin_base64='YQ==\n')]
        for value in invalid:
            with self.subTest(value=str(value)[:200]), self.assertRaises(ValueError):
                launch.normalize_case(value)

    def test_exact_input_and_argument_limits_are_enforced(self):
        value = case(b'x' * 1024**2, ['x' * 4096] * 4)
        self.assertEqual(len(launch.stdin_bytes(value)), 1024**2)
        for oversized in (case(b'x' * (1024**2 + 1)), case(b'', ['x' * 4096] * 5)):
            with self.assertRaises(ValueError):
                launch.normalize_case(oversized)

    def test_case_reader_rejects_duplicate_nonfinite_and_symlink_inputs(self):
        path = self.root / 'case.json'
        for raw in ('{"id":"one","id":"two"}', '{"id":NaN}', '{"argv":[Infinity]}'):
            path.write_text(raw)
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                launch.load_case(path)
        path.write_bytes(launch.case_bytes(case()))
        self.assertEqual(launch.load_case(path), launch.normalize_case(case()))
        link = self.root / 'link.json'
        link.symlink_to(path)
        with self.assertRaises(ValueError):
            launch.load_case(link)

    def test_receipt_keeps_fixed_case_and_unconsumed_prefix_scope(self):
        value = case()
        receipt = launch.validate_launch(manifest(self.root, value), value,
            launch.stdin_bytes(value), capture_directory=self.root)
        self.assertTrue(receipt['fixed_case_only'])
        self.assertTrue(receipt['stdin_unconsumed_before_selected_boundary'])
        for field in ('stdin_consumed_before_selected_boundary', 'stdin_admitted_as_initial_memory',
                      'input_domain_universally_proved', 'payload_behavior_proved'):
            self.assertFalse(receipt[field])
        self.assertEqual(receipt['argv'], value['argv'])

    def test_changed_bytes_case_identity_metadata_or_offset_cannot_be_bound(self):
        value = case()
        record = manifest(self.root, value)
        changes = dict(launch_case_sha256='0' * 64, launch_case_id='other',
            stdin_sha256='0' * 64, stdin_size=True, stdin_empty=True,
            stdin_offset_after_capture=1, stdin_file='../stdin.bin', launch_case_file='other.json',
            guest_argv=['target.elf'], launch_input_profile='UNIVERSAL')
        for field, replacement in changes.items():
            changed = dict(record, **{field: replacement})
            with self.subTest(field=field), self.assertRaises(ValueError):
                launch.validate_launch(changed, value, launch.stdin_bytes(value), capture_directory=self.root)
        with self.assertRaisesRegex(ValueError, 'Retained stdin differs'):
            launch.validate_launch(record, value, b'wrong', capture_directory=self.root)

    def test_changed_command_environment_or_execution_scope_is_rejected(self):
        value = case()
        record = manifest(self.root, value)
        changes = dict(argv=record['argv'][:-1], controlled_host_environment={'LC_ALL': 'C'},
            guest_environ=['TZ=UTC', 'LC_ALL=C'], cwd='/wrong', returncode=7,
            new_independent_execution=False, payload_instruction_execution_allowed=True,
            execution_mode='single')
        for field, replacement in changes.items():
            with self.subTest(field=field), self.assertRaises(ValueError):
                launch.validate_launch(dict(record, **{field: replacement}), value,
                    launch.stdin_bytes(value), capture_directory=self.root)


class CaptureForwardingTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.plugin = self.root / 'observer.so'
        self.plugin.write_bytes(b'not loaded by the Python I/O fixture')
        self.runtime = self.root / 'python-io-fixture'

    def python_runtime(self, *, consume=False, mutate=False):
        # This subprocess checks fd/argv forwarding only. It never impersonates
        # actual observer chronology or SMT; read_capture is explicitly mocked.
        source = (f'#!{sys.executable}\n'
            'import json, os, pathlib, sys\n'
            'args = sys.argv[1:]\n'
            "options = dict(part.split('=', 1) for part in args[args.index('-plugin') + 1].split(',')[1:])\n"
            + ('data = sys.stdin.buffer.read()\n' if consume else 'data = os.pread(0, 1048576, 0)\n') +
            "pathlib.Path('forwarded.json').write_text(json.dumps({'argv': args, 'stdin_hex': data.hex()}))\n"
            + ("pathlib.Path('stdin.bin').write_bytes(b'changed')\n" if mutate else '') +
            "pathlib.Path(options['report']).write_text(json.dumps({'success': True}))\n"
            "pathlib.Path(options['events']).write_text('fixture-only\\n')\n")
        self.runtime.write_text(source)
        self.runtime.chmod(0o700)

    def run_capture(self, value):
        output = self.root / 'capture'
        with patch.object(proof.observations, 'read_capture', return_value=[]) as parse:
            rows, record = proof.capture(self.runtime, self.plugin, b'fixture ELF bytes',
                0x8049000, [dict(address=0x8049000, size=4096)], output, launch_case=value)
        self.assertEqual(rows, [])
        self.assertEqual(parse.call_count, 1)
        return output, record

    def test_real_python_child_gets_exact_binary_fd_and_literal_unicode_argv(self):
        self.python_runtime()
        value = case(argv=['-c', 'two words', '\u043f\u0443\u0442\u044c', '$HOME;must-stay-literal'])
        output, record = self.run_capture(value)
        forwarded = json.loads((output / 'forwarded.json').read_text())
        self.assertEqual(bytes.fromhex(forwarded['stdin_hex']), launch.stdin_bytes(value))
        self.assertEqual(forwarded['argv'][-4:], value['argv'])
        self.assertEqual(record['guest_argv'], ['target.elf', *value['argv']])
        self.assertEqual(record['stdin_offset_after_capture'], 0)
        self.assertEqual((output / launch.CASE_FILE).read_bytes(), launch.case_bytes(value))
        self.assertEqual((output / launch.STDIN_FILE).read_bytes(), launch.stdin_bytes(value))
        self.assertEqual(json.loads((output / 'launch.json').read_bytes()), record)

    def test_real_python_child_can_receive_an_explicit_empty_stdin_file(self):
        self.python_runtime()
        output, record = self.run_capture(case(b'', []))
        self.assertEqual((output / launch.STDIN_FILE).stat().st_size, 0)
        self.assertEqual(record['guest_argv'], ['target.elf'])
        self.assertTrue(record['stdin_empty'])

    def test_consumed_input_fails_this_unconsumed_prefix_profile(self):
        self.python_runtime(consume=True)
        with patch.object(proof.observations, 'read_capture') as parse:
            with self.assertRaisesRegex(ValueError, 'unconsumed boundary differs'):
                proof.capture(self.runtime, self.plugin, b'fixture', 0x8049000,
                    [dict(address=0x8049000, size=4096)], self.root / 'capture', launch_case=case())
        parse.assert_not_called()
        record = json.loads((self.root / 'capture/launch.json').read_text())
        self.assertEqual(record['stdin_offset_after_capture'], len(launch.stdin_bytes(case())))

    def test_stdin_mutation_cannot_keep_a_positive_launch_binding(self):
        self.python_runtime(mutate=True)
        with patch.object(proof.observations, 'read_capture') as parse:
            with self.assertRaisesRegex(ValueError, 'Retained stdin differs'):
                proof.capture(self.runtime, self.plugin, b'fixture', 0x8049000,
                    [dict(address=0x8049000, size=4096)], self.root / 'capture', launch_case=case())
        parse.assert_not_called()

    def test_invalid_case_fails_before_output_or_process_creation(self):
        with patch.object(proof.subprocess, 'Popen') as spawn:
            with self.assertRaises(ValueError):
                proof.capture(self.runtime, self.plugin, b'fixture', 0x8049000, [],
                    self.root / 'capture', launch_case=dict(case(), files={'input': ''}))
        spawn.assert_not_called()
        self.assertFalse((self.root / 'capture').exists())


class FixedProofFlowTests(unittest.TestCase):
    """Reuse the existing explicit mocked-proof fixture, without solver claims."""
    def setUp(self):
        self.flow = flow_fixture.GenericProofOrchestrationTests(
            'test_candidate_image_is_a_conclusion_and_never_a_replay_seed')
        self.flow.setUp()
        self.addCleanup(self.flow.doCleanups)
        self.proof = flow_fixture.proof
        self.value = case()

    def capture(self, qemu, plugin, packed, target, goals, output, *, launch_case):
        self.assertEqual(launch_case, launch.normalize_case(self.value))
        output.mkdir()
        (output / 'events.jsonl').write_bytes(b'{"mock_capture":true}\n')
        (output / launch.CASE_FILE).write_bytes(launch.case_bytes(launch_case))
        (output / launch.STDIN_FILE).write_bytes(launch.stdin_bytes(launch_case))
        record = manifest(output, launch_case)
        record.update(run_id='b' * 32, qemu_sha256=self.proof.digest_file(qemu))
        record['argv'][0] = str(qemu)
        (output / 'launch.json').write_text(json.dumps(record))
        return [], record

    def test_fixed_case_reaches_capture_and_source_bound_summary(self):
        environment, mocks = self.flow.environment()
        with environment:
            mocks['capture'].side_effect = self.capture
            summary = self.proof.prove_unpack(self.flow.selection, self.flow.output,
                qemu=self.flow.qemu, qemu_include=self.flow.root / 'sdk', launch_case=self.value)
        self.assertEqual(summary['status'], self.proof.unpack_smt.STATUS)
        binding = summary['launch_input_binding']
        self.assertEqual(binding['case_sha256'], launch.case_sha256(self.value))
        self.assertEqual(binding['stdin_sha256'], hashlib.sha256(launch.stdin_bytes(self.value)).hexdigest())
        self.assertEqual(binding['argv'], self.value['argv'])
        self.assertEqual(summary['launch_input_profile'], launch.PROFILE)
        self.assertTrue(binding['stdin_unconsumed_before_selected_boundary'])
        self.assertEqual(mocks['replay'].call_count, 2)
        self.assertNotIn('launch_case', mocks['replay'].call_args.kwargs)
        self.assertEqual(len(mocks['smt'].call_args.kwargs['input_files_sha256']), 6)

    def test_retained_input_mutation_during_solver_invalidates_certificate(self):
        environment, mocks = self.flow.environment()
        def mutate(*args, **kwargs):
            (self.flow.output / 'capture/stdin.bin').write_bytes(b'changed after launch')
            folder = self.flow.output / 'smt'
            folder.mkdir()
            (folder / 'certificate.json').write_text('{"mock_solver":true}')
            return self.flow.theorem
        with environment:
            mocks['capture'].side_effect = self.capture
            mocks['smt'].side_effect = mutate
            summary = self.proof.prove_unpack(self.flow.selection, self.flow.output,
                qemu=self.flow.qemu, qemu_include=self.flow.root / 'sdk', launch_case=self.value)
        self.flow.assert_failed(summary)
        self.assertIn('Fixed launch input changed during proof', summary['errors'][0])
        self.assertFalse((self.flow.output / 'smt/certificate.json').exists())
        self.assertTrue((self.flow.output / 'smt/invalidated-certificate.json').is_file())

    def test_invalid_input_case_never_reaches_capture_replay_or_solver(self):
        environment, mocks = self.flow.environment()
        with environment:
            summary = self.proof.prove_unpack(self.flow.selection, self.flow.output,
                qemu=self.flow.qemu, qemu_include=self.flow.root / 'sdk',
                launch_case=dict(self.value, files={'unsupported': ''}))
        self.flow.assert_failed(summary)
        for name in ('capture', 'replay', 'smt'):
            mocks[name].assert_not_called()

    def test_prefix_stdin_read_remains_unsupported(self):
        with self.assertRaisesRegex(ValueError, 'Unsupported captured syscall'):
            self.proof.observations.calls([
                dict(kind='syscall_enter', ordinal=1, number=3, pc=0x8048100)])


if __name__ == '__main__':
    unittest.main()
