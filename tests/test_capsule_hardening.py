import copy
import io
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import Mock, patch

from taintforge_env import capsule_hardening as m4, input_retirement
from scripts.run_unified_pipeline import parser

ROOT = Path(__file__).resolve().parents[1]


class NativeLedgerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not shutil.which('gcc'): raise unittest.SkipTest('gcc required')
        cls.temp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temp.cleanup)
        cls.exe = Path(cls.temp.name)/'ledger'
        common = ['gcc','-std=gnu11','-O1','-g','-Wall','-Wextra','-Werror','-pthread',
                  '-I'+str(ROOT/'unpacker/test'), str(ROOT/'experiments/capsule_hardening/ledger_test.c'),
                  str(ROOT/'unpacker/test/phase1_resources.c'), '-Wl,--wrap=free']
        subprocess.run([*common,'-o',str(cls.exe)],check=True,capture_output=True,timeout=30)
        cls.small = Path(cls.temp.name)/'small-ledger'
        subprocess.run([*common,'-DTF_RESOURCE_SLOTS=128','-o',str(cls.small)],check=True,capture_output=True,timeout=30)

    def run_ledger(self, mode, exe=None):
        return subprocess.run([str(exe or self.exe),mode],capture_output=True,text=True,timeout=10)

    def test_boundary_and_actual_zeroing_before_free(self):
        for mode in ('below','exact','realloc','zero'):
            with self.subTest(mode=mode):
                result=self.run_ledger(mode)
                self.assertEqual(result.returncode,0,result.stderr)
                item=json.loads(result.stdout)
                self.assertEqual(item['live_allocations'],0)
                self.assertEqual(item['allocations'],item['releases'])
                self.assertLessEqual(item['peak_bytes']+item['ledger_reserved_bytes'],item['limit_bytes'])
                self.assertGreater(item['wiped_bytes'],0)

    def test_above_limit_overflow_capacity_and_invalid_owner_are_terminal(self):
        for mode,reason,exe in [('above','analysis_memory_budget',self.exe),
                              ('overflow','analysis_allocation_overflow',self.exe),
                              ('capacity','allocation_ledger_capacity',self.small),
                              ('invalid-owner','invalid_allocation_owner',self.exe)]:
            with self.subTest(mode=mode):
                result=self.run_ledger(mode,exe)
                self.assertEqual(result.returncode,92,result.stderr)
                self.assertIn(reason,result.stderr)
                self.assertEqual(result.stdout,'')

    def test_partial_release_and_reset_refuse_a_live_owner(self):
        partial=self.run_ledger('partial')
        self.assertEqual(partial.returncode,0,partial.stderr)
        self.assertEqual(json.loads(partial.stdout)['live_allocations'],0)
        leaked=self.run_ledger('leak')
        self.assertEqual(leaked.returncode,0,leaked.stderr)
        self.assertEqual(json.loads(leaked.stdout)['live_allocations'],1)

    def test_threads_and_two_independent_processes(self):
        with ThreadPoolExecutor(max_workers=2) as pool:
            first,second=list(pool.map(self.run_ledger,['threads','threads']))
        for result in (first,second):
            self.assertEqual(result.returncode,0,result.stderr)
            item=json.loads(result.stdout)
            self.assertEqual(item['live_allocations'],0)
            self.assertEqual(item['allocations'],4000)
            self.assertEqual({o['source'] for o in item['owners']},{'trace.c','provenance.c'})

    def test_all_allocator_macros_parse_with_their_actual_argument_counts(self):
        definitions='\n'.join(line for line in (ROOT/'unpacker/test/phase1_alloc.h').read_text().splitlines()
                              if line.startswith(('#define ', '#undef ')))
        declarations='''#include <stdlib.h>
#include <string.h>
#include "phase1_resources.h"
void *g_malloc(size_t); void *g_malloc0(size_t);
void *g_malloc_n(size_t,size_t); void *g_malloc0_n(size_t,size_t);
void *g_try_malloc(size_t); void *g_try_malloc0(size_t);
void *g_try_malloc_n(size_t,size_t); void *g_try_malloc0_n(size_t,size_t);
void *g_realloc(void *,size_t); void *g_try_realloc(void *,size_t);
void *g_realloc_n(void *,size_t,size_t);
char *g_strdup(const char *); char *g_strndup(const char *,size_t);
char *g_strdup_printf(const char *,...);
#define g_free(p) (g_free)(p)
#define g_strdup(s) (g_strdup)(s)
'''
        calls='''
void check(void *p,const char *s) {
    p=malloc(1); p=calloc(1,2); p=realloc(p,3); free(p);
    p=g_malloc(1); p=g_malloc0(1); p=g_malloc_n(1,2); p=g_malloc0_n(1,2);
    p=g_try_malloc(1); p=g_try_malloc0(1); p=g_try_malloc_n(1,2); p=g_try_malloc0_n(1,2);
    p=g_realloc(p,1); p=g_try_realloc(p,1); p=g_realloc_n(p,1,2); g_free(p);
    p=g_strdup(s); p=g_strndup(s,1); p=g_strdup_printf("%s",s); g_free(p);
}
'''
        result=subprocess.run(['gcc','-std=gnu11','-Wall','-Wextra','-Werror','-fsyntax-only',
            '-I'+str(ROOT/'unpacker/test'),'-x','c','-'],input=declarations+definitions+calls,
            capture_output=True,text=True,timeout=10)
        self.assertEqual(result.returncode,0,result.stderr)

    def test_register_ids_coexist_with_gnu_ucontext_and_keep_their_values(self):
        header=(ROOT/'unpacker/test/dta.h').read_text()
        declaration=re.search(r'typedef enum \{[^}]+\} RegId;',header).group()
        names=('RAX','RCX','RDX','RBX','RSP','RBP','RSI','RDI',
               'R8','R9','R10','R11','R12','R13','R14','R15')
        checks='\n'.join('_Static_assert(DTA_REG_'+name+' == '+str(index)+', "register order");'
                         for index,name in enumerate(names))
        checks+='\n_Static_assert(REG_COUNT == 16 && REG_INVALID == -1, "register bounds");'
        for before,after in (('#include <sys/ucontext.h>\n',''),('', '#include <sys/ucontext.h>\n')):
            source=before+declaration+'\n'+after+checks+'\n'
            result=subprocess.run(['gcc','-D_GNU_SOURCE=','-std=gnu11','-Wall','-Wextra','-Werror',
                                   '-fsyntax-only','-x','c','-'],input=source,capture_output=True,
                                  text=True,timeout=10)
            self.assertEqual(result.returncode,0,result.stderr)


class BudgetGuestTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not all(shutil.which(tool) for tool in ('gcc', 'as', 'ld', 'strip')):
            raise unittest.SkipTest('gcc and binutils required')
        from scripts.run_capsule_hardening_e2e import budget_guests
        cls.temp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temp.cleanup)
        root = Path(cls.temp.name)
        (root/'inputs').mkdir()
        cls.guests = budget_guests(root/'inputs')
        shim = root/'alloc.h'
        shim.write_text('#include <stdlib.h>\n#include "phase1_resources.h"\n'
            '#define malloc(n) tf_alloc_malloc((n), __FILE__)\n'
            '#define calloc(n,s) tf_alloc_calloc((n), (s), __FILE__)\n'
            '#define realloc(p,n) tf_alloc_realloc((p), (n), __FILE__)\n'
            '#define free tf_alloc_free\n')
        cls.seed = root/'seed'
        subprocess.run(['gcc', '-std=gnu11', '-O1', '-g', '-Wall', '-Wextra', '-Werror', '-pthread',
            '-I'+str(ROOT/'unpacker/test'), '-include', str(shim),
            str(ROOT/'experiments/capsule_hardening/seed_budget_test.c'),
            str(ROOT/'unpacker/test/provenance.c'), str(ROOT/'unpacker/test/phase1_resources.c'),
            '-o', str(cls.seed)], check=True, capture_output=True, timeout=30)

    def test_large_budget_buffers_use_zero_fill_load_segments(self):
        for name, entry in self.guests.items():
            with self.subTest(name=name):
                data = Path(entry['path']).read_bytes()
                offset = struct.unpack_from('<I', data, 28)[0]
                size, count = struct.unpack_from('<HH', data, 42)
                loads = [struct.unpack_from('<8I', data, offset+i*size) for i in range(count)]
                loads = [load for load in loads if load[0] == 1]
                self.assertLess(len(data), 16384)
                self.assertLess(sum(load[4] for load in loads), 8192)
                self.assertGreaterEqual(sum(load[5]-load[4] for load in loads), 2*1024**2)
                self.assertTrue(all(load[4] <= load[5] for load in loads))

    def test_initial_file_provenance_fits_the_actual_ledger_and_releases_it(self):
        for name, entry in self.guests.items():
            with self.subTest(name=name):
                result = subprocess.run([str(self.seed), entry['path']], capture_output=True,
                                        text=True, timeout=20)
                self.assertEqual(result.returncode, 0, result.stderr)
                item = json.loads(result.stdout)
                before, after = item['before'], item['after']
                self.assertGreater(before['live_allocations'], 0)
                self.assertLess(before['live_allocations'], 8192)
                self.assertLessEqual(before['peak_bytes']+before['ledger_reserved_bytes'], before['limit_bytes'])
                self.assertEqual(after['live_allocations'], 0)
                self.assertEqual(after['live_bytes'], 0)
                self.assertEqual(after['allocations'], after['releases'])
                self.assertGreater(after['wiped_bytes'], 0)


class LauncherTests(unittest.TestCase):
    def run_launcher(self, failure=None):
        entered = False
        layouts, lookups, calls = [], [], []
        structure = m4.ctypes.Structure

        class LayoutMeta(type(structure)):
            def __new__(cls, name, bases, namespace, **kwargs):
                if '_fields_' in namespace:
                    if entered:
                        raise ModuleNotFoundError("No module named 'ctypes._layout'")
                    layouts.append(name)
                return super().__new__(cls, name, bases, namespace, **kwargs)

        class CheckedStructure(structure, metaclass=LayoutMeta):
            pass

        def chroot(root):
            nonlocal entered
            entered = True
            calls.append('chroot')

        def prctl(option, value, *unused):
            calls.append(('prctl', option.value, value.value))
            if failure == 'prctl' and option.value == 38:
                return -1
            return int(value.value < 2) if option.value == 23 else 0

        def capset(header, caps):
            self.assertEqual(m4.ctypes.string_at(header, 8), b'\x22\x05\x08\x20\0\0\0\0')
            self.assertEqual(m4.ctypes.string_at(caps, 24), bytes(24))
            calls.append('capset')
            return -1 if failure == 'capset' else 0

        class Libc:
            def __getattr__(self, name):
                lookups.append((name, entered))
                return {'prctl': prctl, 'capset': capset}[name]

        def record(name):
            return Mock(side_effect=lambda *args: calls.append((name, *args)))

        system = {name: record(name) for name in ('chdir', 'setgroups', 'setresgid', 'setresuid', 'execve')}
        system.update(chroot=chroot, geteuid=Mock(return_value=0), getresuid=Mock(return_value=(65534,)*3),
                      getresgid=Mock(return_value=(65534,)*3), getgroups=Mock(return_value=[]))
        with tempfile.TemporaryDirectory() as root, \
             patch.multiple(m4.os, **system), \
             patch.object(m4.resource, 'setrlimit', side_effect=record('rlimit')), \
             patch.object(m4.ctypes, 'Structure', CheckedStructure), \
             patch.object(m4.ctypes, 'CDLL', return_value=Libc()), \
             patch.object(m4.ctypes, 'get_errno', return_value=1):
            binding = {'rootfs': root, 'settings': {'hardening': m4.policy()}}
            command = ['/__taintforge/bin/loader', '/__taintforge/bin/qemu-i386']
            if failure:
                with self.assertRaisesRegex(OSError, 'M4 ' + ('prctl' if failure == 'prctl' else 'capability clear')):
                    m4.launch(binding, command)
                system['execve'].assert_not_called()
            else:
                m4.launch(binding, command)
                system['execve'].assert_called_once_with(command[0], command,
                    {'PATH':'/usr/bin:/bin', 'HOME':'/', 'LANG':'C', 'LC_ALL':'C'})
        return layouts, lookups, calls

    def test_native_dependencies_are_prepared_before_chroot(self):
        layouts, lookups, calls = self.run_launcher()
        self.assertEqual(len(layouts), 2)
        self.assertEqual(lookups, [('prctl', False), ('capset', False)])
        self.assertLess(calls.index(('setgroups', [])), calls.index(('setresgid', 65534, 65534, 65534)))
        self.assertLess(calls.index(('setresgid', 65534, 65534, 65534)), calls.index(('setresuid', 65534, 65534, 65534)))
        self.assertLess(calls.index(('setresuid', 65534, 65534, 65534)), calls.index('capset'))
        self.assertEqual([c for c in calls if isinstance(c, tuple) and c[:2] == ('prctl', 24)],
                         [('prctl', 24, 0), ('prctl', 24, 1)])

    def test_native_failure_never_executes_target(self):
        for failure in ('prctl', 'capset'):
            with self.subTest(failure=failure):
                self.run_launcher(failure)


class HardeningPolicyTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.run=Path(self.temp.name)
        (self.run/'config').mkdir()
        (self.run/'logs/phase1').mkdir(parents=True)
        (self.run/'logs/capsule').mkdir()
        self.policy=m4.policy(analysis_mib=8,export_mib=1,journal_mib=1)
        self.binding={key:key for key in m4.mappings.IDENTITY}
        self.binding.update(run_dir=str(self.run),lifecycle_attempt='1'*32,
                            settings={'hardening':self.policy})
        (self.run/'config/phase1_binding.json').write_text(json.dumps({'output_directory':str(self.run/'logs/phase1')}))

    def test_policy_is_strict_and_requires_unprivileged_ids(self):
        m4.validate(self.policy)
        for key,value in [('analysis_bytes',True),('analysis_bytes',1),('uid',0),('gid',True),
                          ('poll_ms',11),('protected_control_channel',True)]:
            with self.subTest(key=key):
                c=self.policy|{key:value}
                with self.assertRaises((RuntimeError,TypeError)):m4.validate(c)

    def test_policy_is_bound_into_m3_settings_without_changing_legacy_settings(self):
        legacy=input_retirement.settings()
        self.assertNotIn('hardening',legacy)
        config=input_retirement.settings(hardening=self.policy)
        input_retirement.validate_settings(config)
        config['hardening']['analysis_bytes']+=1
        with self.assertRaises(RuntimeError):input_retirement.validate_settings(config)

    def test_export_and_journal_budgets_at_below_and_above_the_boundary(self):
        for folder,name,key in [('logs/phase1','unpacked.bin','export_bytes'),
                               ('logs/phase1','events.jsonl','journal_bytes'),
                               ('logs','qemu_strace.log','journal_bytes')]:
            with self.subTest(name=name):
                path=self.run/folder/name
                for size in (2**20-1,2**20):
                    with path.open('wb') as stream: stream.truncate(size)
                    self.assertEqual(m4.budget_usage(self.binding)[key],size)
                with path.open('wb') as stream:stream.truncate(2**20+1)
                with self.assertRaises(RuntimeError):m4.budget_usage(self.binding)
                path.unlink()

    def test_total_journal_size_and_atomic_publication_are_counted_once(self):
        source=self.run/'logs/phase1/unpacked.bin.part.test'
        source.write_bytes(b'a'*100)
        os.link(source,self.run/'logs/phase1/unpacked.bin')
        self.assertEqual(m4.budget_usage(self.binding)['export_bytes'],100)
        (self.run/'logs/phase1/events.jsonl').write_bytes(b'a'*(2**19))
        (self.run/'logs/runtime_stdout.log').write_bytes(b'a'*(2**19))
        self.assertEqual(m4.budget_usage(self.binding)['journal_bytes'],2**20)
        with (self.run/'logs/qemu_strace.log').open('wb') as f:f.write(b'x')
        with self.assertRaises(RuntimeError):m4.budget_usage(self.binding)

    def test_symlink_outputs_and_escape_are_rejected(self):
        (self.run/'logs/phase1/x').symlink_to('/dev/null')
        with self.assertRaises(RuntimeError):m4.budget_usage(self.binding)
        (self.run/'logs/phase1/x').unlink()
        (self.run/'config/phase1_binding.json').write_text(json.dumps({'output_directory':'/tmp'}))
        with self.assertRaises(RuntimeError):m4.budget_usage(self.binding)

    def test_private_controls_reject_links_and_restrict_modes(self):
        for name in ('capsule_binding.json','observer-contract.json','input-attempt.json'):
            (self.run/'config'/name).write_text('{}')
        m4.private_controls(self.run)
        self.assertEqual((self.run/'config').stat().st_mode&0o777,0o700)
        self.assertTrue(all(item['mode']=='0600' for item in m4.controls_record(self.run).values()))
        (self.run/'duplicate').hardlink_to(self.run/'config/input-attempt.json')
        with self.assertRaises(RuntimeError):m4.private_controls(self.run)

    def context(self):
        credentials={'Uid':'65534 65534 65534 65534','Gid':'65534 65534 65534 65534','Groups':'',
                     **{k:'0' for k in ('CapInh','CapPrm','CapEff','CapBnd','CapAmb')},'NoNewPrivs':'1'}
        return {'schema':1,'profile':m4.PROFILE,**m4.identity(self.binding),'pid':77,'point':1,'start_ticks':100,
                'captured_monotonic_ns':1000000,
                'credentials':credentials,'status_text':'\n'.join(k+':\t'+v for k,v in credentials.items()),
                'mountinfo':'1 0 0:1 / /root/__taintforge ro,nosuid,nodev - tmpfs tmpfs ro\n',
                'fds':[{'fd':1,'target':'/log','fdinfo':'flags:\t0100001\n'}],
                'namespaces':{name:name for name in ('mnt','pid','net','uts','ipc','user')},
                'protected_control_channel':False,'fd_table_scope':'shared_linux_user_host_process'}

    def test_context_requires_actual_ids_empty_caps_and_restricted_runtime_mount(self):
        item=self.context()
        m4.verify_context(self.binding,item,77,1,100)
        for key,value in [('Uid','0 0 0 0'),('CapEff','1'),('CapBnd','1'),('Groups','1000'),('NoNewPrivs','0')]:
            changed=copy.deepcopy(item);changed['credentials'][key]=value
            changed['status_text']='\n'.join(k+':\t'+v for k,v in changed['credentials'].items())
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                m4.verify_context(self.binding,changed,77,1,100)
        for change in ({'pid':78},{'nonce':'2'*32},{'mountinfo':item['mountinfo'].replace('ro,nosuid,nodev','rw')},
                       {'protected_control_channel':True},{'fds':item['fds']*2}):
            with self.assertRaises(RuntimeError):m4.verify_context(self.binding,item|change,77,1,100)

    def test_release_ledger_refuses_residue_and_budget_or_scope_tampering(self):
        ledger={'schema':1,'scope':'explicit_project_allocations','limit_bytes':8*1024**2,
                'ledger_reserved_bytes':1024,'live_allocations':0,'live_bytes':0,'peak_bytes':100,
                'allocations':2,'releases':2,'wiped_bytes':100,'external_allocations_tracked':False}
        m4.verify_ledger(self.binding,{'resource_ledger':ledger})
        for change in ({'live_allocations':1},{'live_bytes':1},{'releases':1},{'peak_bytes':8*1024**2},
                       {'limit_bytes':4*1024**2},{'external_allocations_tracked':True},{'allocations':True}):
            with self.assertRaises(RuntimeError):m4.verify_ledger(self.binding,{'resource_ledger':ledger|change})

    def test_cli_keeps_m4_explicit(self):
        args=parser().parse_args(['run','--out',str(self.run/'new'),'--retire-phase1','--capsule-hardening',
                                  '--binary',str(ROOT/'experiments/input_retirement/guest.S')])
        self.assertTrue(args.capsule_hardening)
        self.assertEqual((args.execution_uid,args.execution_gid),(65534,65534))


class CollectionTests(unittest.TestCase):
    def budget_case(self, root, native=-9, shell=137):
        from experiments.execution_capsule_probe import controller as p
        name = 'export-budget'
        run = root/'extra'/name/'session/iterations/0000/run'
        (run/'logs/phase1').mkdir(parents=True)
        (run/'logs/capsule').mkdir()
        (run/'config').mkdir()
        p.write_json(run.parent/'execution_attempt.json',
                     {'stage':'failed', 'retry_safe':False, 'guest_exit_code':shell})
        supervisor = {'qemu_exit':native, 'supervisor_kill':True,
                      'error':'ProbeError: M4 export byte budget exceeded'}
        p.write_json(run/'logs/capsule/supervisor.json', supervisor)
        p.write_json(run/'logs/capsule/service.json', {'tree_empty':True})
        p.write_json(run/'config/capsule_binding.json',
                     {'settings':{'hardening':{'export_bytes':1024**2}}})
        p.write_json(root/'extra'/name/'resume_report.json', {'executions_this_invocation':0})
        for name in ('runtime_stdout.log', 'qemu_strace.log'):
            (run/'logs'/name).write_bytes(b'')
        with (run/'logs/phase1/unpacked.bin').open('wb') as stream:
            stream.truncate(1024**2+1)
        case = {'name':'export-budget', 'supervisor':supervisor,
                'claim_sha256':p.sha(run.parent/'execution_attempt.json')}
        return case, run

    def test_budget_collection_accepts_real_signal_and_normal_exit_statuses(self):
        from scripts.collect_capsule_hardening_evidence import check_budget_case
        killed = subprocess.run([sys.executable, '-c',
            'import os,signal;os.kill(os.getpid(),signal.SIGKILL)'], capture_output=True, timeout=10)
        self.assertEqual(killed.returncode, -9)
        for native, shell in ((killed.returncode, 137), (92, 92), (0, 0)):
            with self.subTest(native=native), tempfile.TemporaryDirectory() as d:
                case, run = self.budget_case(Path(d), native, shell)
                check_budget_case(Path(d), case)

    def test_budget_collection_rejects_mismatched_statuses_and_changed_evidence(self):
        from experiments.execution_capsule_probe import controller as p
        from scripts.collect_capsule_hardening_evidence import check_budget_case
        for native, shell in ((-9, -9), (-9, 139), (92, 137), (True, 1), (0, False),
                              (None, 137), (-65, 193), (256, 256)):
            with self.subTest(native=native, shell=shell), tempfile.TemporaryDirectory() as d:
                case, run = self.budget_case(Path(d), native, shell)
                with self.assertRaises(RuntimeError):
                    check_budget_case(Path(d), case)
        for fault in ('claim', 'supervisor', 'cleanup', 'resume', 'size'):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as d:
                root = Path(d)
                case, run = self.budget_case(root)
                if fault == 'claim':
                    path = run.parent/'execution_attempt.json'
                    item = json.loads(path.read_text()); item['retry_safe'] = True
                    p.write_json(path, item); case['claim_sha256'] = p.sha(path)
                elif fault == 'supervisor':
                    p.write_json(run/'logs/capsule/supervisor.json', case['supervisor']|{'changed':True})
                elif fault == 'cleanup':
                    p.write_json(run/'logs/capsule/service.json', {'tree_empty':False})
                elif fault == 'resume':
                    p.write_json(root/'extra/export-budget/resume_report.json', {'executions_this_invocation':1})
                else:
                    (run/'logs/phase1/unpacked.bin').write_bytes(b'')
                with self.assertRaises(RuntimeError):
                    check_budget_case(root, case)

    def test_verify_only_checks_results_without_collecting_or_writing(self):
        from scripts import collect_capsule_hardening_evidence as collection
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            source = root/'preserved.txt'; source.write_bytes(b'original')
            with patch.object(sys, 'argv', ['collect', '--out', str(root), '--verify-only']), \
                 patch.object(collection, 'check_results') as check, \
                 patch.object(collection, 'collect') as collect, \
                 patch('sys.stdout', new_callable=io.StringIO) as output:
                self.assertEqual(collection.main(), 0)
                check.assert_called_once_with(root)
                collect.assert_not_called()
                self.assertIn('verified', output.getvalue())
            self.assertEqual(list(root.iterdir()), [source])
            self.assertEqual(source.read_bytes(), b'original')

    def test_partial_m4_archive_keeps_original_exit_and_never_claims_complete(self):
        from scripts.collect_capsule_hardening_evidence import collect
        import tarfile
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);(root/'validation').mkdir()
            (root/'validation/preflight.log').write_text('systemd unavailable\n')
            result=collect(root,7)
            self.assertFalse(result['complete'])
            with tarfile.open(result['archive']) as archive:
                manifest=json.load(archive.extractfile('evidence/collection.json'))
                self.assertEqual(manifest['kind'],'m4-acceptance')
                self.assertEqual(manifest['command_exit_code'],7)
                self.assertEqual(len(manifest['files']),1)
                self.assertIn('extra/report.json',manifest['missing_required'])

    def test_collection_refuses_a_symlink_in_extra_evidence(self):
        from scripts.collect_capsule_hardening_evidence import collect
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);(root/'extra').mkdir()
            (root/'extra/report.json').symlink_to('/etc/passwd')
            with self.assertRaisesRegex(RuntimeError,'Symlink'):collect(root,0)


if __name__ == '__main__':unittest.main()
