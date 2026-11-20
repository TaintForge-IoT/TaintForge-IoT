"""Check retained observations against the independent benign parser oracle."""
from collections import Counter
import hashlib
from pathlib import Path
import time
from experiments.afl_campaign_corpus.build import expected, check_sequence
from . import afl_file as f


class CaseLedger:
    def __init__(self, target, *, phase1_runs=1, marker='/tmp/afl-marker',
                 prepared='/tmp/afl-prepared', parent=None, max_rss_growth_mib=16):
        expected(target, b'A')
        self.target, self.phase1_runs = target, phase1_runs
        self.marker, self.prepared, self.parent = marker, prepared, parent
        self.max_rss_growth_mib = max_rss_growth_mib
        self.inputs, self.maps, self.children = {}, set(), set()
        self.counts = Counter()
        self.cases = self.repeated = 0
        self.rss, self.fds = [], []

    def observe(self, case, result=None):
        from .afl_evidence import read_input
        from .afl_phase2 import regular
        case = Path(case)
        result = f.read_json(case/'result.json') if result is None else result
        data = read_input(case/'input', 4096)
        digest = hashlib.sha256(data).hexdigest()
        value = result['outcome']
        wanted = expected(self.target, data)
        actual = value['kind'], value['guest_exit'], value['guest_signal']
        f.p.require(actual == wanted, 'Corpus semantics mismatch: '+str(case)+' '+str(actual))
        f.p.require(result['status'] == 'passed' and result['phase1_runs'] == self.phase1_runs and
                    result['input']['input_sha256'] == digest and result['guest_exit'] == wanted[1],
                    'Corpus child identity mismatch')
        regular(case/'coverage.map', f.MAP_SIZE)
        bitmap = (case/'coverage.map').read_bytes()
        coverage = hashlib.sha256(bitmap).hexdigest()
        f.p.require(len(bitmap) == f.MAP_SIZE and any(bitmap) and coverage == result['coverage']['map_sha256'],
                    'Corpus coverage changed')
        capture = f.read_json(case/'phase2/capture.json')
        f.p.require(capture['case'] == case.name and capture['input_sha256'] == digest and
                    capture['result_sha256'] == f.p.sha(case/'result.json') and capture['coverage_sha256'] == coverage and
                    capture['child_namespace_pid'] == result['child_namespace_pid'] and capture['phase1_runs'] == self.phase1_runs,
                    'Corpus capture identity mismatch')
        required = {'config/rootfs_before.json', 'config/rootfs_after.json', 'logs/runtime_stdout.log'}
        f.p.require(required <= capture['source_files'].keys(), 'Missing corpus observations')
        for name, sha in capture['source_files'].items():
            relative = Path(name)
            f.p.require(not relative.is_absolute() and '..' not in relative.parts, 'Observation escapes its case')
            path = case/'phase2'/relative
            regular(path, 16*1024**2)
            f.p.require(f.p.sha(path) == sha, 'Corpus observation changed: '+name)
        before = f.read_json(case/'phase2/config/rootfs_before.json')['entries']
        after = f.read_json(case/'phase2/config/rootfs_after.json')['entries']
        f.p.require(self.marker not in before and
                    after.get(self.marker, {}).get('sha256') == hashlib.sha256(b'K').hexdigest() and
                    before.get(self.prepared, {}).get('sha256') == hashlib.sha256(b'P').hexdigest() and
                    after.get(self.prepared, {}).get('sha256') == hashlib.sha256(b'P').hexdigest(),
                    'Filesystem reset or single-preparation oracle failed')
        stdout = (case/'phase2/logs/runtime_stdout.log').read_bytes()
        f.p.require(stdout == (bytes([wanted[1]]) if wanted[0] == 'normal' else b''), 'Guest output differs from oracle')
        child = result['child_namespace_pid']
        f.p.require(child not in self.children and child == value['child_namespace_pid'], 'Child identity reused')
        self.children.add(child)
        resources = result['parent_resources']
        if self.parent is not None:
            f.p.require(resources == self.parent['resources'], 'Warm parent identity or FD inventory changed')
            f.p.require(value['parent_rss_mib'] <= self.parent['rss_mib']+self.max_rss_growth_mib,
                        'Warm parent RSS exceeded allowed growth')
        f.p.require(value['parent_fd_count'] == resources['fd_count'], 'Parent FD metric mismatch')
        self.rss.append(value['parent_rss_mib'])
        self.fds.append(resources['fd_count'])
        if wanted[0] != 'timeout':
            identity = wanted, value['guest_pc'], coverage, hashlib.sha256(stdout).hexdigest()
            if digest in self.inputs:
                f.p.require(self.inputs[digest] == identity, 'Same input changed its outcome or coverage')
                self.repeated += 1
            else:
                self.inputs[digest] = identity
            self.maps.add(coverage)
        self.cases += 1
        self.counts[wanted[0]] += 1
        return digest

    def report(self):
        return {'target': self.target, 'cases': self.cases, 'outcomes': dict(self.counts),
            'distinct_non_timeout_inputs': len(self.inputs), 'distinct_non_timeout_maps': len(self.maps),
            'same_input_comparisons': self.repeated, 'unique_children': len(self.children),
            'parent_fd_min': min(self.fds) if self.fds else None, 'parent_fd_max': max(self.fds) if self.fds else None,
            'parent_rss_min_mib': min(self.rss) if self.rss else None,
            'parent_rss_max_mib': max(self.rss) if self.rss else None, 'timeout_coverage_compared': False}


class SessionChecks:
    def __init__(self, target, *, phase1_runs=1, marker='/tmp/afl-marker',
                 prepared='/tmp/afl-prepared', max_rss_growth_mib=16):
        self.target = target
        self.options = dict(phase1_runs=phase1_runs, marker=marker, prepared=prepared,
                            max_rss_growth_mib=max_rss_growth_mib)
        self.ledger = None

    def __call__(self, server, stage):
        from .afl_replay import direct_attempt
        f.p.require(stage in {'before_afl', 'after_afl'}, 'Unknown session check stage')
        ready = f.read_json(server.root/'warm-ready.json')
        if self.ledger is None:
            self.ledger = CaseLedger(self.target, parent={'resources': ready['parent_resources'],
                                                          'rss_mib': ready['rss_mib']}, **self.options)
        start = server.executed
        for data in check_sequence(self.target):
            index = server.executed
            result = direct_attempt(server, data)
            case = server.root/'cases'/f'{index:08d}'
            deadline = time.monotonic()+5
            while not (case/'transport.json').exists():
                f.p.require(not server.errors and not server.stop.is_set() and time.monotonic() < deadline,
                            'Checked child was not delivered')
                server.stop.wait(.01)
            f.p.require(f.read_json(case/'transport.json').get('status') == 'delivered', 'Checked child delivery cancelled')
            self.ledger.observe(case, result)
        return {'status': 'passed', 'stage': stage, 'cases_before': start,
                'cases_after': server.executed, 'checks': self.ledger.report()}


def verify_loss_diagnostic(result):
    from .capsule_supervision import exit_status
    role, status = result['role'], result.get('qemu_exit_status') or {}
    f.p.require(role in {'observer', 'qemu'} and type(status.get('returncode')) is int and
                status == exit_status(status['returncode']) and status['wrapper_exit'] == result.get('wrapper_exit'),
                'Injected loss lost its QEMU/wrapper exit identity')
    if role == 'qemu':
        f.p.require(status['returncode'] == -9, 'Injected QEMU SIGKILL was not preserved')
    f.p.require(isinstance(result.get('supervisor_error'), str) and result['supervisor_error'] and
                'M3 recorded exit differs from wrapper exit' not in str(result.get('capsule_error')),
                'Injected loss lost its primary supervisor diagnostic')
    if role == 'observer':
        records = [result.get('failure') or {}, result.get('worker_exit') or {}, *(result.get('controller_failures') or [])]
        f.p.require(result.get('controller_exit') == -9 or
                    any(r.get('component') == role and r.get('exitcode') == -9 for r in records),
                    'Observer loss was not retained as controller failure')
    return {'status': 'passed', 'role': role, 'qemu_exit_status': status, 'supervisor_error': result['supervisor_error']}
