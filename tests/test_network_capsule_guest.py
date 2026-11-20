"""Actual ELF/QEMU/replay components; Phase 1, capsule and namespaces are not executed here."""
import asyncio
import json
import os
from pathlib import Path
import tempfile
import unittest

from scripts.run_network_capsule_e2e import build_guest, policy_and_store
from taintforge_env.input_retirement import inspect_input
from taintforge_env.network_observer import plugin_argument, validate_observer
from taintforge_env.network_policy import load_network_policy
from taintforge_env.network_replay import replay_service
from taintforge_env.network_runtime import NetworkRuntimeOwner, _CURRENT
from taintforge_env.qemu_strace_parser import parse_qemu_strace


@unittest.skipUnless(os.environ.get('TF_NET6_QEMU') and os.environ.get('TF_NET6_OBSERVER'),
                     'set TF_NET6_QEMU and TF_NET6_OBSERVER for actual QEMU component checks')
class NetworkCapsuleGuestTests(unittest.IsolatedAsyncioTestCase):
    async def exercise(self, transport):
        qemu=Path(os.environ['TF_NET6_QEMU']).resolve(strict=True)
        observer=Path(os.environ['TF_NET6_OBSERVER']).resolve(strict=True)
        metadata=validate_observer(observer)
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            import socket
            with socket.socket(socket.AF_INET,socket.SOCK_DGRAM if transport in (1,2) else socket.SOCK_STREAM) as guard:
                guard.bind(('127.0.0.1',0));port=guard.getsockname()[1]
            name=('tcp','udp','dns_udp','dns_tcp')[transport]
            binary=build_guest(root/'input',port=port,transport=transport,work=1000)
            self.assertEqual(inspect_input(binary)['arch'],'i386')
            store=policy_and_store(root,name,port=port,remote='127.0.0.1')
            policy=load_network_policy(root/'policy.json')
            logs=root/'logs';logs.mkdir()
            owner=NetworkRuntimeOwner(root/'control',logs,attempt_id='net6-component')
            token=_CURRENT.set(owner.client())
            responder=replay_service(service=policy.services[0],store=store,log_dir=logs/'network_host')
            listener=process=None
            try:
                listener=await responder.start()
                argument=plugin_argument(str(observer),root/'endpoints.jsonl','net6-component','net6-component')
                process=await asyncio.create_subprocess_exec(str(qemu),'-plugin',argument,'-strace',str(binary),
                    stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.PIPE)
                stdout,stderr=await asyncio.wait_for(process.communicate(),5)
                self.assertEqual(process.returncode,0,stderr.decode(errors='replace'))
                self.assertEqual(stdout,b'NET6_OK\n')
                (root/'strace.log').write_bytes(stderr)
                summary=parse_qemu_strace(root/'strace.log',root/'syscalls.jsonl',target_arch='i386',
                    endpoint_events=root/'endpoints.jsonl',session_id='net6-component',attempt_id='net6-component')
                self.assertEqual(summary['network_endpoint_observer']['status'],'correlated')
            finally:
                if process is not None and process.returncode is None:
                    process.kill();await process.communicate()
                if listener is not None:
                    listener.close();await listener.wait_closed()
                _CURRENT.reset(token)
                status=owner.close()
            self.assertEqual(status['cleanup_status'],'cleaned')
            self.assertEqual(status['budget_usage']['active_jobs'],0)
            report_path=os.environ.get('TF_NET6_COMPONENT_REPORT')
            if report_path:
                destination=Path(report_path)
                report=json.loads(destination.read_text()) if destination.exists() else {'scope':'actual_qemu_components',
                    'phase1_executed':False,'capsule_executed':False,'namespace_executed':False,'cases':[]}
                report['cases'].append({'case':name,'status':'passed','guest_executed':True,'plugin_api':metadata['plugin_api'],
                    'observer_status':'correlated','cleanup_status':status['cleanup_status']})
                destination.write_text(json.dumps(report,indent=2)+'\n')

    async def test_ordered_tcp_fixture(self):await self.exercise(0)
    async def test_udp_fixture(self):await self.exercise(1)
    async def test_dns_udp_fixture(self):await self.exercise(2)
    async def test_dns_tcp_fixture(self):await self.exercise(3)


if __name__=='__main__':unittest.main()
