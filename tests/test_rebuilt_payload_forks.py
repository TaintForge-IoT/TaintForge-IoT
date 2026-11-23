"""A fixed benign ELF is rebuilt, run from fresh snapshots and observed by AFL++."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import struct
import subprocess
import tempfile
import unittest

from experiments.afl_rebuilt import fork_replay
from taintforge_env import afl_rebuilt
from taintforge_env.afl_transport import recv_exact
from taintforge_env.elf_runtime import provision_guest
from taintforge_env.environment_snapshot import EnvironmentSnapshotStore
from unpacker import unpack


class RebuiltPayloadForks(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        qemu = os.environ.get('TF_QEMU_I386') or shutil.which('qemu-i386')
        include = os.environ.get('TF_QEMU_INCLUDE')
        phase1 = os.environ.get('TF_PHASE1_PLUGIN')
        if not qemu or not (phase1 or include):
            raise unittest.SkipTest('requires TF_QEMU_I386 and TF_QEMU_INCLUDE or TF_PHASE1_PLUGIN')
        cls.qemu = Path(qemu).resolve(strict=True)
        evidence = os.environ.get('TF_PAYLOAD_FORK_OUTPUT')
        if evidence:
            cls.root = Path(evidence).resolve()
            cls.root.mkdir(parents=True, exist_ok=False)
        else:
            temporary = tempfile.TemporaryDirectory(prefix='tf-rebuilt-payload-forks-')
            cls.addClassCleanup(temporary.cleanup)
            cls.root = Path(temporary.name)
        packed = cls.root / 'packed.elf'
        source = Path(__file__).with_name('rebuilt_payload_forks.S')
        obj = cls.root / 'fixture.o'
        subprocess.run(['as', '--32', '-o', obj, source], check=True)
        subprocess.run(['ld', '-m', 'elf_i386', '-static', '-o', packed, obj], check=True)
        symbols = subprocess.check_output(['nm', '-n', packed], text=True).splitlines()
        cls.pc = {name: int(address, 16) for address, _, name in (line.split() for line in symbols)}
        if not phase1:
            phase1 = unpack.build_plugin(include, cls.root / 'phase1')
        output = cls.root / 'unpacked'
        result = unpack.unpack_sample(packed, output, qemu=cls.qemu, plugin=Path(phase1),
                                      cases=[{'id': 'capture'}], timeout=10)
        if result['status'] != unpack.STATUS or result['entry'] != cls.pc['payload_entry']:
            raise AssertionError(result)
        cls.target_sha256 = afl_rebuilt.digest(output / 'rebuilt.elf')
        cls.traps = {cls.pc[name]: signal.SIGILL for name in ('leaf_fault', 'sibling_fault')}
        cls.plugin = cls.root / 'coverage.so'
        afl_rebuilt.build_coverage_plugin(cls.plugin)
        template = cls.root / 'template'
        (template / 'etc').mkdir(parents=True)
        provision_guest(output / 'rebuilt.elf', template, sysroot=Path('/'), binary_guest_path='/bin/sample.elf')
        (template / 'etc/dta-input').write_bytes(b'initial')
        cls.store = EnvironmentSnapshotStore(cls.root / 'snapshots')
        cls.snapshot_id = cls.store.capture(template).manifest.snapshot_id

    def setUp(self):
        self.work = self.root / self._testMethodName
        self.work.mkdir()

    def replay(self, name, data, argv=('/etc/dta-input',)):
        result, bitmap = fork_replay.replay_case(self.store, self.snapshot_id, self.work / name, data,
            qemu=self.qemu, plugin=self.plugin, argv=argv)
        self.assertEqual(result['root_returncode'], 0)
        self.assertEqual(result['input_sha256'], hashlib.sha256(data).hexdigest())
        self.assertEqual(result['coverage_sha256'], hashlib.sha256(bitmap).hexdigest())
        self.assertEqual((self.work / name / 'coverage.map').read_bytes(), bitmap)
        self.assertEqual(json.loads((self.work / name / 'result.json').read_text())['input_sha256'],
                         result['input_sha256'])
        return result, bitmap

    def roles(self, result):
        rows = result['processes']
        self.assertEqual(len(rows), 4)
        root, = (row for row in rows if row['parent_pid'] is None)
        children = [row for row in rows if row['parent_pid'] == root['pid']]
        self.assertEqual(len(children), 2)
        leaf, = (row for row in rows if row['parent_pid'] in {c['pid'] for c in children})
        sibling, = (row for row in children if row['pid'] != leaf['parent_pid'])
        self.assertEqual(root['coverage']['input_bytes_read'], 1)
        for row in [*children, leaf]:
            self.assertTrue(row['inherited_input'])
            self.assertEqual(row['coverage']['input_bytes_read'], 0)
        return sibling, leaf

    def leaf_edge(self):
        def location(pc):
            return (pc >> 4) ^ (pc << 8)
        return (location(self.pc['leaf_extra']) ^ (location(self.pc['leaf_choice_block']) >> 1)) & 65535

    def test_only_worker_reads_input(self):
        result, _ = self.replay('worker-read', bytes([3]), argv=('/etc/dta-input', 'worker-reads'))
        self.assertEqual(len(result['processes']), 5)
        root, = (r for r in result['processes'] if r['parent_pid'] is None)
        reader, = (r for r in result['processes'] if r['coverage']['input_bytes_read'])
        self.assertEqual(root['coverage']['blocks'], 0)
        self.assertEqual(reader['parent_pid'], root['pid'])
        self.assertFalse(reader['inherited_input'])
        fault, = (r for r in result['processes'] if r['signal'] is not None)
        self.assertEqual((fault['signal'], fault['coverage']['last_pc']), (signal.SIGILL, self.pc['leaf_fault']))

    def test_exact_process_budget(self):
        result, _ = self.replay('eight', bytes([32 | 64]))
        rows = result['processes']
        self.assertEqual(len(rows), 8)
        root, = (row for row in rows if row['parent_pid'] is None)
        self.assertEqual(sum(row['parent_pid'] == root['pid'] for row in rows), 7)
        self.assertTrue(all(row['returncode'] == 0 for row in rows))

    def test_own_branch_for_each_descendant(self):
        normal, before = self.replay('plain', bytes([0]))
        extra, after = self.replay('extra', bytes([1]))
        for result, direction in ((normal, 0), (extra, 1)):
            sibling, leaf = self.roles(result)
            for symbol, owner, taken in (('leaf_choice', leaf, direction), ('sibling_choice', sibling, 1)):
                matches = [(row['pid'], bit) for row in result['processes']
                           for pc, bit in row['coverage']['branch_outcomes'] if pc == self.pc[symbol]]
                self.assertEqual(matches, [(owner['pid'], taken)])
        edge = self.leaf_edge()
        self.assertEqual(before[edge], 0)
        self.assertGreater(after[edge], 0)
        raw = (self.work / 'extra/coverage.bin').read_bytes()
        owners = set()
        for start in range(0, len(raw), fork_replay.SLOT_SIZE):
            if raw[start + fork_replay.OWNER.size + afl_rebuilt.HEADER.size + edge]:
                owners.add(fork_replay.OWNER.unpack_from(raw, start)[0])
        self.assertEqual(owners, {self.roles(extra)[1]['pid']})
        _, again = self.replay('repeat', bytes([0]))
        self.assertEqual(before, again)

    def test_signal_even_after_root_exits(self):
        for name, mode in (('reaped', 3), ('root-first', 7), ('two-signals', 11)):
            with self.subTest(name=name):
                result, _ = self.replay(name, bytes([mode]))
                sibling, leaf = self.roles(result)
                self.assertEqual(leaf['signal'], signal.SIGILL)
                self.assertEqual(leaf['coverage']['last_pc'], self.pc['leaf_fault'])
                self.assertEqual(sibling['signal'], signal.SIGILL if mode == 11 else None)
                if mode == 11:
                    self.assertEqual(sibling['coverage']['last_pc'], self.pc['sibling_fault'])

    def test_exit_132_is_normal(self):
        result, _ = self.replay('exit132', bytes([16]))
        _, leaf = self.roles(result)
        self.assertEqual(leaf['returncode'], 132)
        self.assertIsNone(leaf['signal'])

    def test_afl_feedback_refuses_mismatched_or_unconfirmed_observations(self):
        data = bytes([3])
        result, bitmap = self.replay('leaf', data)
        host, peer = socket.socketpair()
        with host, peer:
            for candidate, digest, coverage_map, traps in (
                    (bytes([0]), self.target_sha256, bitmap, self.traps),
                    (data, '0' * 64, bitmap, self.traps),
                    (data, self.target_sha256, bytes(len(bitmap)), self.traps),
                    (data, self.target_sha256, bitmap, {})):
                with self.assertRaises(RuntimeError):
                    fork_replay.send_fixed_feedback(host, result, coverage_map, data=candidate,
                                                    target_sha256=digest, known_faults=traps)
            peer.setblocking(False)
            with self.assertRaises(BlockingIOError):
                peer.recv(1)

    def test_regular_campaign_plugin_rejects_payload_fork(self):
        root = self.work / 'rootfs'
        self.store.clone(self.snapshot_id, root)
        (root / 'etc/dta-input').write_bytes(bytes([1]))
        record = self.work / 'coverage.bin'
        afl_rebuilt.write_map(record)
        argument = f'{self.plugin},output={record},input=/etc/dta-input'
        run = subprocess.run([self.qemu, '-L', root, '-plugin', argument,
                              root / 'bin/sample.elf', '/etc/dta-input'], timeout=10)
        self.assertEqual(run.returncode, 86)
        with self.assertRaises(RuntimeError):
            afl_rebuilt.parse_map(record, run.returncode)
        self.assertIsNone(afl_rebuilt.partial_coverage_candidate(record))

    def test_tree_budget_discards_partial_feedback(self):
        with self.assertRaisesRegex(RuntimeError, 'limit of 8 processes'):
            self.replay('over-limit', bytes([32]))
        out = self.work / 'over-limit'
        result = json.loads((out / 'result.json').read_text())
        self.assertEqual(result['process_exit_error']['reason'], 'PROCESS_LIMIT')
        self.assertEqual(result['status'], 'incomplete')
        self.assertFalse((out / 'coverage.map').exists())

    def showmap(self, binary, bridge, name, data):
        # A single known input goes through the real forkserver and its SysV map.
        # Only the fixture's two known UD2 sites attest a guest signal here.
        inputs = self.work / (name + '-inputs')
        inputs.mkdir()
        (inputs / 'case').write_bytes(data)
        maps = self.work / (name + '-maps')
        with tempfile.TemporaryFile() as log:
            host, peer = socket.socketpair()
            with host, peer:
                host.settimeout(10)
                command = [binary, '-e', '-i', inputs, '-o', maps, '-t', '10000', '--',
                           bridge, str(peer.fileno()), '@@']
                # showmap 4.21 probes legacy forkservers with a 4 MiB segment.
                # The bridge writes its 64 KiB map; compare every reported index below.
                env = {**os.environ, 'AFL_QUIET': '1', 'AFL_NO_AFFINITY': '1', 'AFL_MAP_SIZE': '4194304'}
                proc = subprocess.Popen(command, pass_fds=(peer.fileno(),), stdout=log, stderr=log,
                                        env=env, start_new_session=True)
                peer.close()
                try:
                    marker, fds, flags, _ = socket.recv_fds(host, 1, 1)
                    if len(fds) != 1:
                        log.seek(0)
                        self.fail('AFL did not send a case: ' + log.read().decode(errors='replace'))
                    with socket.socket(fileno=fds[0]) as case:
                        self.assertEqual((marker, flags), (b'C', 0))
                        case.settimeout(10)
                        size, = struct.unpack('!I', recv_exact(case, 4))
                        self.assertEqual(size, len(data))
                        delivered = recv_exact(case, size)
                        self.assertEqual(delivered, data)
                        result, bitmap = self.replay(name, delivered)
                        signaled = [r for r in result['processes'] if r['signal'] is not None]
                        fork_replay.send_fixed_feedback(case, result, bitmap, data=delivered,
                                                        target_sha256=self.target_sha256, known_faults=self.traps)
                    code = proc.wait(timeout=15)
                finally:
                    if proc.poll() is None:
                        os.killpg(proc.pid, signal.SIGKILL)
                        proc.wait()
        observations = (maps / 'case').read_text().splitlines()
        indices = {int(line.split(':')[0]) for line in observations}
        self.assertEqual(indices, {i for i, value in enumerate(bitmap) if value})
        afl_rebuilt.write_json(self.work / name / 'showmap.json', {
            'input_sha256': result['input_sha256'], 'root_returncode': result['root_returncode'],
            'afl_showmap_returncode': code, 'reported_edge_count': len(indices),
            'leaf_edge': self.leaf_edge(), 'leaf_edge_present': self.leaf_edge() in indices,
            'signaled_pids': [row['pid'] for row in signaled],
        })
        return code, indices

    def test_afl_showmap_observes_leaf_edge_and_signal_for_the_same_input(self):
        binary = os.environ.get('TF_AFL_SHOWMAP') or shutil.which('afl-showmap')
        if not binary:
            self.skipTest('set TF_AFL_SHOWMAP to run the AFL++ integration')
        bridge = self.work / 'tf-afl-bridge'
        subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror', '-O2',
                        afl_rebuilt.PROJECT / 'experiments/afl_file/bridge.c', '-o', bridge], check=True)
        normal, baseline = self.showmap(binary, bridge, 'normal', bytes([0]))
        extra, with_edge = self.showmap(binary, bridge, 'extra', bytes([1]))
        crash, with_signal = self.showmap(binary, bridge, 'leaf-signal', bytes([3]))
        early, late_signal = self.showmap(binary, bridge, 'root-first-signal', bytes([7]))
        regular, _ = self.showmap(binary, bridge, 'exit132', bytes([16]))
        final, clean = self.showmap(binary, bridge, 'normal-again', bytes([0]))
        self.assertEqual([normal, extra, crash, early, regular, final], [0, 0, 2, 2, 0, 0])
        self.assertIn(self.leaf_edge(), (with_edge - baseline) & with_signal & late_signal)
        self.assertEqual(baseline, clean)


if __name__ == '__main__':
    unittest.main()
