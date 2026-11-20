import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from taintforge_env import capsule_exec_identity as identity, input_retirement


RECEIPT = '/__taintforge/flags/eflags.receipt'


class NetworkCapsuleExecIdentityTests(unittest.TestCase):
    def setUp(self):
        self.binding = {'profile': identity.PROFILE, 'guest_binary': '/bin/sample.elf'}
        self.phase1 = '/__taintforge/plugin/libtaintforge_ir.so,tf-require-flags=off'
        self.strict_phase1 = ('/__taintforge/plugin/libtaintforge_ir.so,tf-require-flags=on,'
                              'x86-flags-receipt=' + RECEIPT)
        self.observer = '/__taintforge/capsule/libretirement_observer.so,socket=/__taintforge_capsule/observer.sock'
        self.endpoint = '/__taintforge/network/libnetwork_endpoint.so,events=/logs/events.jsonl'

    def command(self, *, strict=False, network=False):
        plugins = ['-plugin', self.strict_phase1 if strict else self.phase1, '-plugin', self.observer]
        if network:
            plugins += ['-plugin', self.endpoint]
        return [*identity.PREFIX, '-L', '/', '-strace', *plugins, self.binding['guest_binary']]

    def test_actual_network_plugin_builder_keeps_the_existing_loader_command(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'config').mkdir()
            endpoint = {'plugin_argument': self.endpoint}
            (root / 'config/phase1_binding.json').write_text(json.dumps({'network_observer': endpoint}))
            binding = {**self.binding, 'run_dir': str(root), 'network': {'observer': endpoint}}
            plugins = input_retirement.plugin_arguments(binding, self.phase1, self.observer)
            command = [*identity.PREFIX, '-L', '/', '-strace', *plugins, binding['guest_binary']]
            before = copy.deepcopy(command)
            self.assertEqual(len(command), 15)
            self.assertIsNone(identity.prepare_launch(binding, command))
            self.assertEqual(command, before)

    def test_nonreceipt_launches_do_not_enter_native_setup(self):
        for network in (False, True):
            with self.subTest(network=network), \
                 patch.object(identity.os, 'geteuid', side_effect=AssertionError('native setup entered')), \
                 patch.object(identity, 'verify_bundle') as verify_bundle, \
                 patch.object(identity, 'read_receipt') as read_receipt, \
                 patch.object(identity, 'readonly_bind') as mount:
                command = self.command(network=network)
                self.assertIsNone(identity.prepare_launch(self.binding, command))
                verify_bundle.assert_not_called()
                read_receipt.assert_not_called()
                mount.assert_not_called()

    def test_strict_two_plugin_launch_still_selects_its_receipt(self):
        command = self.command(strict=True)
        before = copy.deepcopy(command)
        self.assertEqual(identity.selected_receipt(self.binding, command), RECEIPT)
        self.assertEqual(command, before)

    def test_strict_native_setup_still_requires_contract_verification(self):
        with patch.object(identity.os, 'geteuid', return_value=0), \
             patch.object(input_retirement, 'verify_contract', side_effect=RuntimeError('contract verification reached')) as verify, \
             patch.object(identity, 'readonly_bind') as mount:
            with self.assertRaisesRegex(RuntimeError, 'contract verification reached'):
                identity.prepare_launch(self.binding, self.command(strict=True))
            verify.assert_called_once_with(self.binding)
            mount.assert_not_called()

    def test_strict_native_setup_still_requires_the_supervisor_uid(self):
        with patch.object(identity.os, 'geteuid', return_value=65534), \
             patch.object(input_retirement, 'verify_contract') as verify:
            with self.assertRaisesRegex(RuntimeError, 'namespace supervisor'):
                identity.prepare_launch(self.binding, self.command(strict=True))
            verify.assert_not_called()

    def test_strict_launch_with_an_extra_plugin_remains_rejected(self):
        with self.assertRaisesRegex(RuntimeError, 'Unrecognized M3 loader command'):
            identity.selected_receipt(self.binding, self.command(strict=True, network=True))

    def test_strict_command_prefix_option_positions_and_guest_remain_bound(self):
        for index, value in ((0, '/bin/other-loader'), (4, '/bin/other-qemu'),
                             (5, '-other-L'), (6, '/other-root'), (7, '-other-strace'),
                             (8, '-other-plugin'), (10, '-other-plugin'), (12, '/bin/other-guest')):
            with self.subTest(index=index):
                command = self.command(strict=True)
                command[index] = value
                with self.assertRaisesRegex(RuntimeError, 'Unrecognized M3 loader command'):
                    identity.selected_receipt(self.binding, command)

    def test_strict_command_with_extra_arguments_remains_rejected(self):
        command = self.command(strict=True) + ['extra']
        with self.assertRaisesRegex(RuntimeError, 'Unrecognized M3 loader command'):
            identity.selected_receipt(self.binding, command)

    def test_strict_receipt_options_remain_unambiguous_and_bound(self):
        options = (
            ',tf-require-flags=on,x86-flags-receipt=/wrong.receipt',
            ',tf-require-flags=off,x86-flags-receipt=' + RECEIPT,
            ',x86-flags-receipt=' + RECEIPT,
            ',tf-require-flags=on,tf-require-flags=on,x86-flags-receipt=' + RECEIPT,
            ',tf-require-flags=on,x86-flags-receipt=' + RECEIPT + ',x86-flags-receipt=' + RECEIPT,
        )
        for suffix in options:
            with self.subTest(suffix=suffix):
                command = self.command(strict=True)
                command[9] = '/__taintforge/plugin/libtaintforge_ir.so' + suffix
                with self.assertRaisesRegex(RuntimeError, 'incomplete or ambiguous'):
                    identity.selected_receipt(self.binding, command)

    def test_receipt_option_in_a_malformed_strict_command_is_not_skipped(self):
        command = self.command(strict=True)
        command.pop(8)
        with self.assertRaisesRegex(RuntimeError, 'Unrecognized M3 loader command'):
            identity.selected_receipt(self.binding, command)

    def test_invalid_m3_argument_types_remain_rejected(self):
        for command in (None, 'qemu', tuple(self.command()), [*self.command(), None]):
            with self.subTest(command=command), self.assertRaisesRegex(RuntimeError, 'Invalid M3 command'):
                identity.selected_receipt(self.binding, command)

    def test_other_profiles_do_not_select_the_m3_converter(self):
        self.assertIsNone(identity.prepare_launch({'profile': 'other'}, self.command(strict=True, network=True)))


if __name__ == '__main__':
    unittest.main()
