"""Fixed-case worker forwarding and audit gates; proof/solver are mocked."""
import base64
import hashlib
import unittest
from unittest.mock import patch

from unpacker import external_worker as worker


class FixedLaunchWorkerTests(unittest.TestCase):
    def setUp(self):
        from test_external_worker import ExternalWorkerTests
        self.fixture = ExternalWorkerTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.root = self.fixture.root
        self.case = dict(id='input-06', argv=['-c'],
            stdin_base64=base64.b64encode(bytes(range(256))).decode('ascii'))
        self.case_path = self.root / 'fixed-case.json'
        worker.save(self.case_path, self.case)
        self.args = self.fixture.args('proof')
        self.args.proof_case = self.case_path
        self.fixture.native()

    def proof(self, directory, output, **options):
        output.mkdir()
        return dict(status=worker.unpack_audit.PROOF_STATUS, errors=[], target=0x8049000)

    def audit(self):
        incoming = worker.unpack_launch.stdin_bytes(self.case)
        return dict(status=worker.unpack_audit.STATUS,
            packed_sha256=worker.digest(self.root / 'packed'), target=0x8049000,
            SMT_solver_checks=12, instructions=100, fixed_launch_case_audited=True,
            launch_input_binding=dict(profile=worker.unpack_launch.PROFILE,
                case_sha256=worker.unpack_launch.case_sha256(self.case),
                stdin_sha256=hashlib.sha256(incoming).hexdigest(), stdin_bytes=len(incoming),
                argv=self.case['argv'], stdin_unconsumed_before_selected_boundary=True,
                input_domain_universally_proved=False, payload_behavior_proved=False))

    def invoke(self, *, proof=None, audit=None):
        with patch.object(worker, '_capture_inputs', return_value=self.fixture.capture_inputs()), \
             patch.object(worker.unpack_proof, 'prove_unpack', side_effect=proof or self.proof) as replay, \
             patch.object(worker.unpack_audit, 'audit_sample', return_value=audit or self.audit()) as checked:
            result = worker.run(self.args)
        return result, replay, checked

    def test_exact_binary_case_reaches_fresh_proof_and_expected_case_audit(self):
        result, replay, checked = self.invoke()
        self.assertTrue(result['success'])
        self.assertEqual(replay.call_args.kwargs['launch_case'], self.case)
        checked.assert_called_once_with(self.args.output, expected_launch_case=self.case)
        self.assertEqual(result['proof_fresh_stdin_bytes'], 256)
        self.assertEqual(result['proof_fresh_stdin_sha256'],
                         hashlib.sha256(bytes(range(256))).hexdigest())
        self.assertEqual(result['proof_fresh_argv'], ['-c'])
        self.assertEqual(result['launch_case_sha256'], worker.unpack_launch.case_sha256(self.case))
        self.assertFalse(result['same_execution_as_behavior'])
        self.assertFalse(result['universal_equivalence'])

    def test_file_inputs_are_rejected_before_replay(self):
        worker.save(self.case_path, dict(self.case, files={'data': 'YQ=='}))
        result, replay, checked = self.invoke()
        self.assertFalse(result['success'])
        replay.assert_not_called()
        checked.assert_not_called()

    def test_case_mutation_during_proof_never_reaches_receipt_audit(self):
        def changed(directory, output, **options):
            result = self.proof(directory, output, **options)
            worker.save(self.case_path, dict(self.case, argv=['-d']))
            return result
        result, _, checked = self.invoke(proof=changed)
        self.assertFalse(result['success'])
        self.assertIn('changed during execution', result['errors'][0]['message'])
        checked.assert_not_called()

    def test_legacy_only_audit_cannot_authorize_fixed_case_success(self):
        audit = self.audit()
        audit.pop('fixed_launch_case_audited')
        audit.pop('launch_input_binding')
        result, _, _ = self.invoke(audit=audit)
        self.assertFalse(result['success'])
        self.assertFalse((self.args.output / 'receipt-audit.json').exists())

    def test_changed_case_or_promoted_input_domain_in_audit_is_rejected(self):
        for index, (key, value) in enumerate((('case_sha256', 'f' * 64),
                ('argv', ['-d']), ('stdin_bytes', 255),
                ('stdin_unconsumed_before_selected_boundary', False),
                ('input_domain_universally_proved', True), ('payload_behavior_proved', True))):
            with self.subTest(key=key):
                self.args.output = self.root / f'changed-audit-{index}'
                audit = self.audit()
                audit['launch_input_binding'][key] = value
                result, _, _ = self.invoke(audit=audit)
                self.assertFalse(result['success'])

    def test_unsupported_input_read_remains_nonproof_without_audit(self):
        def failed(directory, output, **options):
            output.mkdir()
            return dict(status='FAIL', errors=['Unsupported captured syscall: read'], target=0x8049000)
        result, _, checked = self.invoke(proof=failed)
        self.assertFalse(result['success'])
        self.assertFalse(result['selected_execution_proved'])
        self.assertEqual(result['proof_fresh_stdin'], 'retained_file')
        checked.assert_not_called()

    def test_proof_case_cannot_silently_apply_to_another_phase(self):
        self.args.phase = 'capture'
        with patch.object(worker.unpack, 'unpack_sample') as capture:
            result = worker.run(self.args)
        capture.assert_not_called()
        self.assertFalse(result['success'])

    def test_duplicate_case_keys_are_rejected_before_replay(self):
        self.case_path.write_text('{"id":"first","id":"second"}')
        result, replay, _ = self.invoke()
        self.assertFalse(result['success'])
        replay.assert_not_called()

    def test_case_symlink_does_not_supply_launch_input(self):
        alias = self.root / 'case-alias.json'
        alias.symlink_to(self.case_path)
        self.args.proof_case = alias
        result, replay, _ = self.invoke()
        self.assertFalse(result['success'])
        replay.assert_not_called()


if __name__ == '__main__':
    unittest.main()
