"""Corrupt independently captured evidence; acceptance must reject every mutation."""
import hashlib
from pathlib import Path
import tempfile
import unittest

from taintforge_env import afl_file as f, afl_phase2 as phase2
from taintforge_env.afl_validation import CaseLedger


class LedgerTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.fs = self.root/'fs'
        (self.fs/'tmp').mkdir(parents=True)
        (self.fs/'etc').mkdir()
        self.parent = self.root/'parent'
        (self.parent/'config').mkdir(parents=True)
        f.atomic_json(self.parent/'config/runtime.json', {'network_mode': 'none'})
        self.resources = {'namespace_pid': 1, 'start_ticks': 100, 'fd_count': 4, 'fd_sha256': 'a'*64}
        self.ledger = CaseLedger('prefix', parent={'resources': self.resources, 'rss_mib': 18})

    def case(self, index, *, bitmap=None, stdout=b'\x01', prepared=b'P', dirty=False, resources=None, rss=18):
        case = self.root/f'{index:08d}'; case.mkdir()
        (case/'input').write_bytes(b'A')
        (self.fs/'etc/afl-input').write_bytes(b'A')
        (self.fs/'tmp/afl-prepared').write_bytes(prepared)
        marker = self.fs/'tmp/afl-marker'
        marker.unlink(missing_ok=True)
        if dirty: marker.write_bytes(b'K')
        log = self.root/'stdout'; log.write_bytes(b'')
        trace = self.root/'trace'; trace.write_bytes(b'')
        capture = phase2.Capture(self.fs, self.parent, case, excluded=(), config=phase2.settings('parallel', 4),
            log_paths={'runtime_stdout.log': log, 'qemu_strace.log': trace})
        capture.before()
        marker.write_bytes(b'K')
        log.write_bytes(stdout)
        bitmap = bitmap if bitmap is not None else b'\x01'+bytes(f.MAP_SIZE-1)
        (case/'coverage.map').write_bytes(bitmap)
        resources = resources or dict(self.resources)
        result = {'status': 'passed', 'phase1_runs': 1, 'guest_exit': 1, 'child_namespace_pid': 100+index,
            'input': {'input_sha256': f.p.sha(case/'input')}, 'parent_resources': resources,
            'coverage': {'map_sha256': hashlib.sha256(bitmap).hexdigest()},
            'outcome': {'kind': 'normal', 'guest_exit': 1, 'guest_signal': None, 'guest_pc': 1000,
                'child_namespace_pid': 100+index, 'parent_rss_mib': rss, 'parent_fd_count': resources['fd_count']}}
        f.atomic_json(case/'result.json', result)
        capture.finish(result)
        return case

    def test_repeated_input_requires_same_coverage_outcome_and_private_state(self):
        self.ledger.observe(self.case(0))
        self.ledger.observe(self.case(1))
        self.assertEqual(self.ledger.report()['same_input_comparisons'], 1)

    def test_coverage_instability_is_rejected_even_with_matching_saved_hashes(self):
        self.ledger.observe(self.case(0))
        with self.assertRaisesRegex(RuntimeError, 'Same input changed'):
            self.ledger.observe(self.case(1, bitmap=b'\x02'+bytes(f.MAP_SIZE-1)))

    def test_wrong_stdout_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError, 'Guest output'): self.ledger.observe(self.case(0, stdout=b'bad'))

    def test_preparation_repetition_and_dirty_filesystem_are_rejected(self):
        with self.assertRaisesRegex(RuntimeError, 'Filesystem reset'):
            self.ledger.observe(self.case(0, prepared=b'PP'))
        with self.assertRaisesRegex(RuntimeError, 'Filesystem reset'):
            self.ledger.observe(self.case(1, dirty=True))

    def test_parent_fd_replacement_and_rss_growth_are_rejected(self):
        with self.assertRaisesRegex(RuntimeError, 'FD inventory'):
            self.ledger.observe(self.case(0, resources=self.resources | {'fd_sha256': 'b'*64}))
        with self.assertRaisesRegex(RuntimeError, 'RSS'):
            self.ledger.observe(self.case(1, rss=35))

    def test_tampered_captured_source_is_rejected_before_interpretation(self):
        case = self.case(0)
        (case/'phase2/config/rootfs_after.json').write_text('{}')
        with self.assertRaisesRegex(RuntimeError, 'observation changed'): self.ledger.observe(case)

    def test_mismatched_capture_identity_is_rejected(self):
        case = self.case(0)
        value = f.read_json(case/'phase2/capture.json'); value['child_namespace_pid'] += 1
        f.atomic_json(case/'phase2/capture.json', value)
        with self.assertRaisesRegex(RuntimeError, 'capture identity'): self.ledger.observe(case)

    def test_reused_child_pid_is_rejected(self):
        case = self.case(0); self.ledger.observe(case)
        with self.assertRaisesRegex(RuntimeError, 'Child identity reused'): self.ledger.observe(case)


if __name__ == '__main__': unittest.main()
