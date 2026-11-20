"""Control contracts and synthetic/native handoff checks; no M4 execution claims."""
import copy
import hashlib
from pathlib import Path
import shutil
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from experiments.retirement_observer import controller as c
from scripts.run_unified_pipeline import parser, prepare
from taintforge_env import capsule_control as guard, capsule_hardening as m4
from taintforge_env import input_retirement as m3, retirement_evidence
from tests import test_input_retirement as base
from tests import test_capsule_hardening_integration as hardened
from tests import test_retirement_observer as native


def proof(private, calls=0):
    return {'profile': guard.PROFILE, 'checked_syscalls': calls, 'guest_fds': 3,
            'private_path_sha256': hashlib.sha256(private.encode()).hexdigest()}


def guarded_evidence(run, code, fault=None):
    binding, result = hardened.hardened_evidence(run, code, fault)
    path = run/'logs/capsule/observer-events.json'
    journal = c.read_json(path)
    for point in (1, 2):
        context = run/f'logs/capsule/execution-context-{point}.json'
        data = c.read_json(context)
        data['fds'].append({'fd': 0, 'target': '/dev/null', 'fdinfo': 'flags:\t0100000\n'})
        c.p.write_json(context, data)
        next(e for e in journal['events'] if e['event'] == 'maps_held' and e['point'] == point)['execution_context_sha256'] = c.p.sha(context)
    for item in journal['events']:
        if item['event'] == 'snapshot':
            item['control_guard'] = proof(binding['run_dir'], 0 if item['point'] == 1 else 2)
        elif item['event'] == 'done':
            item['control_guard'] = proof(binding['run_dir'], 3)
    c.p.write_json(path, journal)
    return binding, result


class ControlPolicyTests(unittest.TestCase):
    def test_guard_requires_m4_and_invalid_cli_never_creates_output(self):
        with self.assertRaisesRegex(RuntimeError, 'requires M4'):
            m3.settings(control_guard=guard.policy())
        config = m3.settings(hardening=m4.policy(), control_guard=guard.policy())
        m3.validate_settings(config)
        with tempfile.TemporaryDirectory() as tmp:
            for i, flags in enumerate(([], ['--retire-phase1'], ['--capsule-hardening'])):
                out = Path(tmp)/str(i)
                args = parser().parse_args(['run', '--capsule-control-guard', '--out', str(out), *flags])
                with self.assertRaisesRegex(ValueError, '--capsule-control-guard requires'):
                    prepare(args)
                self.assertFalse(out.exists())

    def test_private_prefix_is_bound_and_cannot_inject_plugin_options(self):
        for value in ('/', '//a', '/a/../b', '/a//b', '/a/./b', '/a,guard=off', '/a\nb', '/a\x00b', '/a\tb'):
            with self.subTest(value=value), self.assertRaises(RuntimeError):
                guard.private_prefix({'run_dir': value, 'control_guard_private_path': value})
        binding = {'run_dir': '/a/run', 'control_guard_private_path': '/a/run'}
        self.assertEqual(guard.private_prefix(binding), '/a/run')
        binding['run_dir'] = '/moved/bundle'
        with self.assertRaises(RuntimeError): guard.private_prefix(binding)
        binding['recorded_phase1_directory'] = '/a/run/logs/phase1'
        self.assertEqual(guard.private_prefix(binding), '/a/run')

    def test_missing_downgraded_and_wrong_native_proof_are_rejected(self):
        good = proof('/a/run')
        guard.verify_snapshot(good, private='/a/run')
        bad_values = [None, {}, good|{'checked_syscalls': True}, good|{'guest_fds': 4097},
                      good|{'profile': 'off'}, good|{'private_path_sha256': '0'*64}]
        for value in bad_values:
            with self.subTest(value=value), self.assertRaises(RuntimeError):
                guard.verify_snapshot(value, private='/a/run')
        with self.assertRaises(RuntimeError): guard.validate(guard.policy()|{'guest_fd_limit': True})


class NativeControlTests(unittest.TestCase):
    setUpClass = classmethod(native.NativeObserverTests.setUpClass.__func__)
    tearDownClass = classmethod(native.NativeObserverTests.tearDownClass.__func__)
    start = native.NativeObserverTests.start
    resume = native.NativeObserverTests.resume

    def hold_guarded(self, channel, point):
        first = channel.receive('snapshot')
        c.snapshot_ok(first, first['host_pid'], point, 1, control_guard='/capsule/run')
        channel.command('CHECK '+str(point))
        second = channel.receive('snapshot')
        c.snapshot_ok(second, first['host_pid'], point, 2, control_guard='/capsule/run')
        c.same_hold(first, second, 0)
        return first

    def test_guard_remains_active_across_both_native_holds(self):
        process, _, channel = self.start('guarded')
        first = self.hold_guarded(channel, 1)
        self.assertEqual(first['control_guard']['checked_syscalls'], 0)
        self.resume(channel, 1)
        channel.command('STAMP'); channel.receive('stamp')
        channel.command('HOLD 2')
        second = self.hold_guarded(channel, 2)
        self.assertEqual(second['control_guard']['checked_syscalls'], 1)
        self.resume(channel, 2)
        done = channel.receive('done')
        guard.verify_snapshot(done['control_guard'], private='/capsule/run')
        self.assertEqual(process.wait(timeout=2), 0)

    def test_non_guest_fd_after_second_resume_is_terminal(self):
        process, _, channel = self.start('guard-after')
        self.hold_guarded(channel, 1); self.resume(channel, 1)
        channel.command('STAMP'); channel.receive('stamp'); channel.command('HOLD 2')
        self.hold_guarded(channel, 2); self.resume(channel, 2)
        self.assertEqual(process.wait(timeout=2), 126)
        self.assertIn(b'CAPSULE_GUARD_ABORT code=126 reason=non_guest_fd', process.stderr.read())

    def test_self_abort_exception_cannot_signal_another_process_or_group(self):
        for mode in ('guard-signal-other','guard-signal-group','guard-signal-otherkind'):
            with self.subTest(mode=mode):
                process,_,channel=self.start(mode)
                self.hold_guarded(channel,1);self.resume(channel,1)
                channel.command('STAMP');channel.receive('stamp');channel.command('HOLD 2')
                self.hold_guarded(channel,2);self.resume(channel,2)
                self.assertEqual(process.wait(timeout=2),126)
                self.assertIn(b'reason=unsupported_signal_target',process.stderr.read())


class ControlIntegrationTests(unittest.TestCase):
    setUp = base.InputRetirementTests.setUp
    prepare_input = base.InputRetirementTests.prepare_input
    invoke = base.InputRetirementTests.invoke

    def prepare_guarded(self, *, old_observer=False):
        sidecar = Path(str(self.plugin)+'.runtime.json')
        data = c.read_json(sidecar)
        data['resource_ledger'] = {'schema': 1, 'scope': 'explicit_project_allocations',
                                   'external_allocations_tracked': False}
        c.p.write_json(sidecar, data)
        original = m3.bundle_profile
        def built_profile(built):
            built = copy.deepcopy(built)
            if not old_observer: built['source_sha256']['control_guard.h'] = 'c'*64
            return original(built)
        with patch.object(m3, 'bundle_profile', side_effect=built_profile):
            return self.prepare_input(extra=('--capsule-hardening', '--capsule-control-guard'))

    def test_guarded_finalization_and_portable_proof_survive_relocation(self):
        out, launch = self.prepare_guarded()
        executor = base.InputExecutor()
        with patch.object(base, 'synthetic_evidence', side_effect=guarded_evidence):
            report, code = self.invoke(out, launch, executor)
        self.assertEqual(code, 0, report.get('error'))
        self.assertEqual(report['capsule']['control_guard']['status'], 'verified')
        self.assertFalse(report['capsule']['hardening']['protected_control_channel'])
        run = executor.runs[0][0]
        with tempfile.TemporaryDirectory() as tmp:
            moved = Path(tmp)/'moved'
            shutil.copytree(run/'retirement-evidence', moved)
            result = retirement_evidence.verify(moved, expected_sha256=report['capsule']['portable_evidence']['manifest_sha256'])
            self.assertEqual(result['attempt_outcome'], 'passed')
            path = moved/'logs/capsule/observer-events.json'
            journal = c.read_json(path)
            journal['events'][0]['control_guard']['private_path_sha256'] = '0'*64
            c.p.write_json(path, journal)
            inventory = c.read_json(moved/'bundle.json')
            for item in inventory['files']:
                f = moved/item['path']; item.update(size=f.stat().st_size, sha256=c.p.sha(f))
            c.p.write_json(moved/'bundle.json', inventory)
            with self.assertRaisesRegex(RuntimeError, 'different private path'):
                retirement_evidence.verify(moved, expected_sha256=c.p.sha(moved/'bundle.json'))

    def test_old_observer_is_rejected_before_any_guest_execution(self):
        out, launch = self.prepare_guarded(old_observer=True)
        executor = base.InputExecutor()
        report, code = self.invoke(out, launch, executor)
        self.assertEqual(code, 1)
        self.assertFalse(executor.runs)
        self.assertIn('lacks the capsule control guard', str(report))

    def test_missing_native_proof_blocks_success_and_resume(self):
        out, launch = self.prepare_guarded()
        executor = base.InputExecutor()
        def missing(run, code, fault=None):
            binding, result = guarded_evidence(run, code, fault)
            path = run/'logs/capsule/observer-events.json'
            journal = c.read_json(path)
            del journal['events'][-1]['control_guard']
            c.p.write_json(path, journal)
            return binding, result
        with patch.object(base, 'synthetic_evidence', side_effect=missing):
            report, code = self.invoke(out, launch, executor)
            self.assertEqual(code, 1)
            self.assertEqual(report['outcome'], 'intervention_required')
            self.assertIn('native control guard evidence', str(report))
            resumed, code = self.invoke(out, launch, executor)
            self.assertEqual(code, 1)
            self.assertEqual(resumed['executions_this_invocation'], 0)
            self.assertEqual(len(executor.runs), 1)


class CollectionTests(unittest.TestCase):
    def test_partial_archive_preserves_exit_and_does_not_claim_complete(self):
        from scripts.collect_capsule_control_evidence import collect
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root/'validation').mkdir()
            (root/'validation/failure.log').write_text('controlled host preflight refusal\n')
            result = collect(root, 42)
            self.assertFalse(result['complete'])
            with tarfile.open(result['archive']) as stream:
                import json
                record = json.load(stream.extractfile('evidence/collection.json'))
            self.assertEqual(record['command_exit_code'], 42)
            self.assertFalse(record['complete'])
            self.assertTrue(record['missing_required'])

    def test_component_public_aliases_are_excluded_but_probe_symlinks_are_rejected(self):
        from scripts.collect_capsule_control_evidence import collect
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            public = root/'components/public'
            public.mkdir(parents=True)
            (public/'symlink').symlink_to('/does/not/exist')
            self.assertFalse(collect(root, 1)['complete'])
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            probe = root/'components/write'
            probe.mkdir(parents=True)
            (probe/'guest-i386').symlink_to('/etc/passwd')
            with self.assertRaisesRegex(RuntimeError, 'Symlink'):
                collect(root, 1)


if __name__ == '__main__':
    unittest.main()
