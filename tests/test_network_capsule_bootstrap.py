"""Check the built NET-6 client's entry into its unpacked page."""
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

from scripts.run_network_capsule_e2e import build_guest
from taintforge_env.input_retirement import inspect_input


class NetworkCapsuleBootstrapTests(unittest.TestCase):
    def test_client_enters_the_unpacked_page_through_a_register(self):
        with tempfile.TemporaryDirectory() as temporary:
            binary = build_guest(Path(temporary) / 'input', port=4444, work=1000)
            self.assertEqual(inspect_input(binary)['arch'], 'i386')
            symbols = subprocess.check_output(
                ['nm', '--defined-only', '--format=posix', str(binary)], text=True,
            )
            payload = next(int(line.split()[2], 16) for line in symbols.splitlines()
                           if line.split()[0] == 'payload_page')
            disassembly = subprocess.check_output(
                ['objdump', '-d', '--no-show-raw-insn', str(binary)], text=True,
            )
            entry = disassembly.split('<_start>:', 1)[1].split('\n\n', 1)[0]
            instructions = []
            for line in entry.splitlines():
                match = re.fullmatch(r'\s*[0-9a-f]+:\s+([a-z]+)\s*(.*?)\s*', line)
                if match:
                    instructions.append((match[1], match[2]))
            call_index = next(index for index, item in enumerate(instructions) if item[0] == 'call')
            self.assertEqual(instructions[call_index], ('call', '*%eax'))
            self.assertEqual(instructions[call_index - 1], ('mov', f'$0x{payload:x},%eax'))


if __name__ == '__main__':
    unittest.main()
