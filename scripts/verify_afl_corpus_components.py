"""Real QEMU, stock AFL and Phase 2; this does not execute Phase 1/M4."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
from unittest.mock import patch
from experiments.afl_campaign_corpus import build as corpus
from experiments.afl_file.build import components, fault_mutator
from scripts.verify_afl_warm_components import NativeSession
from taintforge_env import afl_file as f, afl_outcome as o, afl_phase2 as p, afl_transport as t
from taintforge_env.afl_findings import record
from taintforge_env.afl_resources import sample_parent
from taintforge_env.afl_validation import CaseLedger, SessionChecks


def stock_launcher(directory, executable, *, timeout_ms=None):
    directory = Path(directory)
    directory.mkdir()
    executable = Path(executable).resolve(strict=True)
    code = '#!/usr/bin/env python3\nimport os,sys\na=sys.argv[1:]\n'
    if timeout_ms is not None:
        code += 'a[a.index("-t")+1]='+repr(str(timeout_ms))+'\n'
    code += 'os.environ["AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES"]="1"\n'
    code += 'os.execv('+repr(str(executable))+',['+repr(str(executable))+']+a)\n'
    script = directory/'afl-fuzz'
    script.write_text(code)
    script.chmod(0o700)
    return directory


def inspect_cases(root, target, parent, *, phase1_runs, marker, prepared, executions,
                  max_rss_growth_mib=16, verify_phase2_identity=False):
    root = Path(root)
    manifest = f.read_json(root/'campaign.json')
    f.p.require(manifest['status'] == 'completed' and manifest.get('evidence_complete') is True,
                'Corpus campaign did not complete with full evidence')
    checks = manifest['session_checks']
    f.p.require(set(checks) == {'before_afl', 'after_afl'} and
                all(v['status'] == 'passed' for v in checks.values()), 'Missing session checks')
    first, last = checks['before_afl']['cases_after'], checks['after_afl']['cases_before']
    f.p.require(last-first >= executions, 'AFL stopped before its execution budget')
    ledger = CaseLedger(target, phase1_runs=phase1_runs, marker=marker, prepared=prepared,
                        parent=parent, max_rss_growth_mib=max_rss_growth_mib)
    seed_hashes = {hashlib.sha256(data).hexdigest() for data in corpus.seeds(target)}
    mutations, overlap, restore_retries = set(), 0, None
    cases = sorted((root/'cases').iterdir())
    f.p.require(len(cases) == manifest['cases'] == manifest['completed_cases'] and first <= last and
                checks['before_afl']['cases_before'] == 0 and checks['after_afl']['cases_after'] == len(cases),
                'Corpus execution accounting mismatch')
    for index, case in enumerate(cases):
        f.p.require(case.name == f'{index:08d}', 'Corpus case index mismatch')
        digest = ledger.observe(case)
        value = f.read_json(case/'result.json').get('filesystem_restore_retries')
        if value is not None:
            f.p.require(type(value) is int and value >= (restore_retries or 0), 'Invalid filesystem retry accounting')
            restore_retries = value
        analysis = f.read_json(case/'phase2/result.json')
        f.p.require(analysis['status'] == 'passed' and
                    f.read_json(case/'transport.json').get('status') == 'delivered', 'Case delivery/analysis failed')
        if verify_phase2_identity:
            from taintforge_env.afl_evidence import child_report
            child_report(case, manifest['max_input'])
        if first <= index < last and digest not in seed_hashes:
            mutations.add(digest)
        overlap += manifest['afl_started_ns'] <= analysis['finished_ns'] <= manifest['afl_finished_ns']
    state = f.read_json(root/'phase2-progress.json')
    f.p.require(state['status'] == 'passed' and state['pending'] == 0 and state['maximum_pending'] <= 4 and
                state['submitted'] == state['completed'] == len(cases), 'Phase 2 queue did not drain')
    f.p.require(mutations and overlap and len(ledger.maps) >= 3 and ledger.repeated,
                'Missing mutations, coverage diversity, repetition checks or Phase 2 overlap')
    return ledger.report() | {'status': 'passed', 'afl_executions': last-first, 'afl_nonseed_inputs': len(mutations),
        'phase2_completed_during_afl': overlap, 'maximum_pending': state['maximum_pending'],
        'mutator': 'stock_afl', 'control_checks_before_and_after_afl': True,
        'filesystem_restore_retries': restore_retries}


def verify(out, *, qemu, afl_bin, executions=1000, seconds=300, mode='parallel', targets=corpus.TARGETS):
    if (type(executions) is not int or executions < 1 or type(seconds) is not int or
            not 1 <= seconds <= 604800 or mode not in {'parallel', 'sequential'} or
            not targets or len(set(targets)) != len(targets) or not set(targets) <= set(corpus.ALL_TARGETS)):
        raise ValueError('Invalid native component campaign limits')
    out = Path(out).resolve()
    out.mkdir(parents=True, exist_ok=False)
    report = {'schema': 1, 'status': 'failed', 'scope': 'native_qemu_stock_afl_corpus_components',
              'phase1_m4_executed': False, 'full_m5_admission_executed': False, 'targets': {}}
    session = None
    try:
        built = components(out/'build')
        launcher = stock_launcher(out/'afl-bin', Path(afl_bin)/'afl-fuzz',
                                  timeout_ms=3000 if targets == ('fault-prefix',) else None)
        if targets == ('fault-prefix',):
            from scripts.verify_afl_phase2_e2e import write_fault_launcher
            write_fault_launcher(launcher/'afl-fuzz', (Path(afl_bin)/'afl-fuzz').resolve(), fault_mutator(out/'mutator'))
        for target in targets:
            directory = out/target
            directory.mkdir()
            selected = built | {'guest': str(corpus.build(directory/'fixture', target))}
            campaign = directory/'campaign'
            (campaign/'seeds').mkdir(parents=True)
            for data in corpus.seeds(target):
                (campaign/'seeds'/hashlib.sha256(data).hexdigest()).write_bytes(data)
            parent = directory/'parent'
            (parent/'config').mkdir(parents=True)
            f.atomic_json(parent/'config/runtime.json', {'network_mode': 'none', 'allow_internet': False})
            empty = directory/'empty.log'
            empty.write_bytes(b'')
            with (directory/'stdout.log').open('wb') as stdout:
                session = NativeSession(directory/'native', selected, qemu, guard='/__taintforge_capsule', stdout=stdout)
                initial = sample_parent(session.pid)
                parent_state = {'resources': initial, 'rss_mib': session.rss}
                f.atomic_json(campaign/'warm-ready.json', {'parent_resources': initial, 'rss_mib': session.rss,
                                                         'run_dir': str(parent)})
                f.atomic_json(campaign/'campaign.json', {'schema': 1, 'profile': 'component-only',
                    'status': 'prepared', 'max_input': 4096, 'phase1_runs': 0,
                    'launch': {'timeout_seconds': 10}, 'build': {'bridge': built['bridge']}})

                class Server(t.AttemptServer):
                    def __init__(self, *args, **kwargs):
                        super().__init__(*args, **kwargs)
                        self.processor = p.Processor(self.root, p.settings(mode, 4), on_complete=self.storage.complete)

                    def start(self):
                        self.processor.start()
                        super().start()

                    def close(self):
                        try:
                            super().close()
                        finally:
                            self.processor.close()

                    def execute(self, connection):
                        size = struct.unpack('!I', t.recv_exact(connection, 4))[0]
                        f.p.require(1 <= size <= 4096, 'Corpus input limit')
                        data = t.recv_exact(connection, size)
                        index = self.executed
                        self.admit_case(index)
                        case = self.root/'cases'/f'{index:08d}'
                        case.mkdir()
                        self.executed += 1
                        (case/'input').write_bytes(data)
                        capture = p.Capture(session.fs, parent, case, excluded=(), config=p.settings(mode, 4),
                            phase1_runs=0, log_paths={'qemu_strace.log': session.root/'qemu.log',
                            'runtime_stdout.log': directory/'stdout.log', 'runtime_stderr.log': empty})
                        outcome, coverage, bitmap = session.attempt_outcome(data, timeout_ms=500, before=capture.before)
                        resources = sample_parent(session.pid, expected=initial)
                        outcome['parent_fd_count'] = resources['fd_count']
                        f.p.require(outcome['kind'] != 'infra_error', 'Corpus infrastructure failure: '+str(outcome))
                        result = {'schema': 1, 'status': 'passed', 'phase1_runs': 0,
                            'child_namespace_pid': outcome['child_namespace_pid'], 'guest_exit': outcome['guest_exit'],
                            'outcome': outcome, 'parent_resources': resources, 'input': f.settings('/etc/input', data),
                            'coverage': coverage, 'filesystem_sha256': session.baseline.digest,
                            'filesystem_restore_retries': session.baseline.restore_retries}
                        (case/'coverage.map').write_bytes(bitmap)
                        f.atomic_json(case/'result.json', result)
                        capture.finish(result)
                        record(self.root, case)
                        self.metrics.record(result)
                        self.processor.submit(case)
                        connection.sendall(o.bridge_header(outcome)+bitmap)
                        self.completed += 1
                        f.atomic_json(case/'transport.json', {'status': 'delivered', 'cleanup_confirmed': True})

                checks = SessionChecks(target, phase1_runs=0, marker='/tmp/marker', prepared='/tmp/prepared')
                with patch.object(f, 'verify_campaign', side_effect=lambda path: f.read_json(Path(path)/'campaign.json')), \
                     patch.object(t, 'AttemptServer', Server):
                    t.run_campaign(campaign, afl_bin=launcher, seconds=seconds, executions=executions, session_check=checks)
                report['targets'][target] = inspect_cases(campaign, target, parent_state, phase1_runs=0,
                    marker='/tmp/marker', prepared='/tmp/prepared', executions=executions)
                if targets == ('fault-prefix',):
                    from scripts.verify_afl_phase2_e2e import verify_saved_faults
                    report['targets'][target].update(verify_saved_faults(campaign), mutator='deliberate_fault_control')
                session.close()
                f.p.require(session.process.returncode == 0, 'Warm parent did not stop')
                f.atomic_json(out/'acceptance.json', report)
        report['status'] = 'passed'
        return report
    except BaseException as exc:
        report['error'] = f'{type(exc).__name__}: {exc}'
        raise
    finally:
        if session is not None and session.process.poll() is None:
            session.close(abort=True)
        f.atomic_json(out/'acceptance.json', report)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('out', 'qemu', 'afl-bin'):
        parser.add_argument('--'+name, type=Path, required=True)
    parser.add_argument('--executions', type=int, default=1000)
    parser.add_argument('--seconds', type=int, default=300)
    parser.add_argument('--phase2-mode', choices=('parallel', 'sequential'), default='parallel')
    parser.add_argument('--target', action='append', choices=corpus.ALL_TARGETS)
    args = parser.parse_args()
    print(json.dumps(verify(args.out, qemu=args.qemu, afl_bin=args.afl_bin,
        executions=args.executions, seconds=args.seconds, mode=args.phase2_mode,
        targets=tuple(args.target) if args.target else corpus.TARGETS), indent=2))


if __name__ == '__main__':
    main()
