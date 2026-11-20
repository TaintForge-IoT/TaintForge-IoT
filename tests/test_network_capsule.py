"""Contract/fault tests use synthetic namespace handles; they do not assert native retirement."""
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from scripts import run_network_guard
from taintforge_env import capsule_resources
from taintforge_env import network_capsule as net
from taintforge_env.network_policy import NetworkPolicy
from taintforge_env.network_runtime import NetworkRuntimeOwner, NetworkRuntimeError
from taintforge_env.unified_runtime import write_json, canonical_hash


PROJECT = Path(__file__).resolve().parents[1]


class NetworkCapsuleContractTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        (self.root / 'config').mkdir()
        (self.root / 'logs/capsule').mkdir(parents=True)
        self.owner = NetworkRuntimeOwner(self.root / 'config/network_runtime', self.root / 'logs', attempt_id='attempt_net6')
        self.addCleanup(self.owner.close)
        self.policy = NetworkPolicy(mode='controlled').to_dict()
        for name in ('network_policy_requested.json', 'network_policy.json'):
            write_json(self.root / 'config' / name, self.policy)
        current = os.stat('/proc/self/ns/net')
        self.namespace = {'name': 'tf-0123abcd', 'device': current.st_dev, 'inode': current.st_ino}
        self.enterContext(patch.object(net, 'namespace_identity', return_value=self.namespace))
        self.binding = {'profile': 'input-static-i386-retirement-m3', 'run_dir': str(self.root),
            'lifecycle_attempt': 'a' * 32, 'settings': {'total_ms': 10000, 'resources': capsule_resources.policy()},
            **{key: ('attempt_net6' if key == 'attempt_id' else 'b' * 64 if key.endswith('sha256') else key) for key in net.IDENTITY},
            'network': {'profile': net.PROFILE, 'mode': 'controlled', 'policy_sha256': canonical_hash(self.policy),
                        'observer': {'build_id': 'c' * 64}, 'execution_timeout_ms': 9000}}
        write_json(self.root / 'config/capsule_binding.json', self.binding)
        self.backend = SimpleNamespace(runtime=self.owner, plan=SimpleNamespace(namespace_name=self.namespace['name']),
                                       config=SimpleNamespace(project_root=PROJECT))
        self.command = ['sudo','-n','ip','netns','exec',self.namespace['name'],'env','PYTHONPATH='+str(PROJECT),sys.executable,
            str(PROJECT / 'scripts/run_network_guard.py'), '--runtime',str(self.owner.client_path), '--result',
            str(self.root / 'config/network_guard_result.json'),'--','unshare','--mount','--pid','--fork','--uts','--ipc',
            '--','bash',str(self.root / 'run_prebuilt_sandbox.sh')]

    def bind(self):
        return net.bind_runtime(self.binding, self.command, self.backend)

    def test_runtime_contract_binds_shared_limits_and_omits_private_token(self):
        command = self.bind()
        self.assertIn('--capsule-binding', command)
        record = net.verify_runtime(self.binding, live=True, inside_namespace=True)
        self.assertEqual(record['descriptor']['limits_sha256'], self.owner.limits.sha256)
        self.assertNotIn(self.owner.token, json.dumps(record))
        with self.assertRaisesRegex(NetworkRuntimeError, 'already bound'):
            self.bind()

    def test_systemd_command_joins_only_the_bound_network_namespace(self):
        command = self.bind()
        service = capsule_resources.command(self.binding, command)
        self.assertEqual(service[:2], ['sudo','systemd-run'])
        expected = [
            'nsenter', '--net=/run/netns/' + self.namespace['name'], '--', *command[6:],
        ]
        self.assertEqual(service[-len(expected):], expected)
        self.assertIn('--property=KillMode=control-group', service)
        altered = command.copy(); altered[-1] = '/tmp/another.sh'
        with self.assertRaisesRegex(NetworkRuntimeError, 'command differs'):
            capsule_resources.command(self.binding, altered)

    def test_policy_change_after_setup_is_rejected(self):
        self.bind()
        write_json(self.root / 'config/network_policy.json', {'allow_internet': True})
        with self.assertRaisesRegex(NetworkRuntimeError, 'policy changed'):
            net.verify_runtime(self.binding)

    def test_another_attempt_or_capsule_binding_is_rejected(self):
        self.bind()
        foreign = copy.deepcopy(self.binding); foreign['attempt_id'] = 'foreign'
        with self.assertRaisesRegex(NetworkRuntimeError, 'identities differ'):
            net.verify_runtime(foreign)
        write_json(self.root / 'config/capsule_binding.json', foreign)
        with self.assertRaisesRegex(NetworkRuntimeError, 'binding changed'):
            net.verify_runtime(self.binding)

    def test_replaced_descriptor_and_namespace_are_rejected(self):
        self.bind()
        with patch.object(net, 'namespace_identity', return_value={**self.namespace, 'inode': 1}):
            with self.assertRaisesRegex(NetworkRuntimeError, 'namespace was replaced'):
                net.verify_runtime(self.binding, live=True)
        raw = json.loads(self.owner.client_path.read_text());raw['attempt_id']='another'
        self.owner.client_path.write_text(json.dumps(raw))
        try:
            with self.assertRaisesRegex(NetworkRuntimeError, 'descriptor changed'):
                net.verify_runtime(self.binding, live=True)
        finally:
            raw['attempt_id']='attempt_net6';self.owner.client_path.write_text(json.dumps(raw))

    def test_live_monitor_preserves_the_runtime_failure_reason(self):
        self.bind();monitor=net.Monitor(self.binding);monitor.arm()
        monitor.check()
        self.owner.fail('network_send_budget_exceeded')
        with self.assertRaisesRegex(net.NetworkCapsuleStopped, 'network_send_budget_exceeded'):
            monitor.check()

    def test_monitor_timeout_is_a_sticky_shared_runtime_failure(self):
        self.bind();monitor=net.Monitor(self.binding);monitor.arm();monitor.deadline=time.monotonic()-.01
        with self.assertRaisesRegex(net.NetworkCapsuleStopped, 'network_capsule_timeout'):
            monitor.check()
        self.assertEqual(self.owner.snapshot()['termination_reason'],'network_capsule_timeout')

    def test_cancellation_is_bound_to_the_same_attempt(self):
        self.bind();monitor=net.Monitor(self.binding)
        net.request_cancel(self.binding,'network_guard_cancelled')
        with self.assertRaisesRegex(net.NetworkCapsuleStopped, 'network_guard_cancelled'):
            monitor.check()
        write_json(self.root / 'logs/capsule/network_cancel.json', {'attempt_id':'foreign','reason':'network_guard_cancelled'})
        with self.assertRaisesRegex(NetworkRuntimeError, 'another attempt'):
            monitor.check()

    def test_first_runtime_failure_keeps_priority_over_later_cancellation(self):
        self.bind();monitor=net.Monitor(self.binding)
        self.owner.fail('network_send_budget_exceeded')
        net.request_cancel(self.binding,'network_guard_cancelled')
        with self.assertRaisesRegex(net.NetworkCapsuleStopped,'network_send_budget_exceeded'):
            monitor.check()

    def test_endpoint_observer_output_counts_toward_the_m4_journal_budget(self):
        from taintforge_env import capsule_hardening as m4
        phase=self.root/'logs/phase1';phase.mkdir()
        endpoint=self.root/'logs/network_endpoints';endpoint.mkdir()
        write_json(self.root/'config/phase1_binding.json',{'output_directory':str(phase),
                   'network_observer':{'output_directory':str(endpoint)}})
        binding=copy.deepcopy(self.binding);binding['settings']['hardening']=m4.policy(journal_mib=1)
        output=endpoint/'events.jsonl';output.write_bytes(b'x'*64)
        self.assertEqual(m4.budget_usage(binding)['journal_bytes'],64)
        output.write_bytes(b'x'*(1024*1024+1))
        with self.assertRaisesRegex(RuntimeError,'journal byte budget'):
            m4.budget_usage(binding)

    def test_owned_qemu_cleanup_escalates_when_term_is_ignored(self):
        ready=self.root/'ready'
        command=[sys.executable,'-c',"import signal,sys,time;from pathlib import Path;"
            "signal.signal(signal.SIGTERM,signal.SIG_IGN);Path(sys.argv[1]).write_text('ready');time.sleep(60)",str(ready)]
        process=subprocess.Popen(command)
        try:
            deadline=time.monotonic()+3
            while not ready.exists():
                self.assertLess(time.monotonic(),deadline);time.sleep(.005)
            started=time.monotonic()
            self.assertEqual(net.stop_qemu(process,.2),-9)
            self.assertLess(time.monotonic()-started,1)
        finally:
            if process.poll() is None:process.kill()
            process.wait(timeout=2)

    def test_offline_contract_remains_verifiable_after_the_owner_closes(self):
        self.bind();self.owner.close()
        self.assertEqual(net.verify_runtime(self.binding)['namespace'],self.namespace)
        with self.assertRaises(OSError):
            net.verify_runtime(self.binding,live=True)

    def test_network_does_not_silently_relax_warm_or_fd_path_guards(self):
        for mode in net.MODES:
            net.validate_mode(mode,{},observer=True)
            with self.assertRaisesRegex(NetworkRuntimeError,'network-observer'):
                net.validate_mode(mode,{},observer=False)
            with self.assertRaisesRegex(NetworkRuntimeError,'warm/file'):
                net.validate_mode(mode,{},observer=True,warm=True)
            with self.assertRaisesRegex(NetworkRuntimeError,'cannot be relaxed'):
                net.validate_mode(mode,{'control_guard':{}},observer=True)

    def test_guard_allows_cooperative_capsule_cleanup_before_signalling(self):
        command=self.bind()
        record=net.verify_runtime(self.binding)
        stopped=self.root/'cooperated';result=self.root/'guard.json'
        code="""import json,sys,time
from pathlib import Path
cancel=Path(sys.argv[1]); stopped=Path(sys.argv[2])
while not cancel.exists():time.sleep(.005)
stopped.write_text(json.loads(cancel.read_text())['reason'])
raise SystemExit(14)
"""
        timer=threading.Timer(.15,lambda:self.owner.fail('network_send_budget_exceeded'))
        timer.start()
        try:
            with patch.object(net,'verify_runtime',return_value=record):
                exit_code=run_network_guard.run(self.owner.client_path,
                    [sys.executable,'-c',code,str(self.root/'logs/capsule/network_cancel.json'),str(stopped)],
                    result_path=result,capsule_binding=self.root/'config/capsule_binding.json')
        finally:
            timer.join()
        self.assertEqual(exit_code,14)
        self.assertEqual(stopped.read_text(),'network_send_budget_exceeded')
        self.assertTrue(read_json(result)['guest_process_stopped'])


def read_json(path):
    return json.loads(path.read_text())


if __name__=='__main__':
    unittest.main()
