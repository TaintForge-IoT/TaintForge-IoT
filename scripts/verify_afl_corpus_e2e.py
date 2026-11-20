"""Host acceptance for stock AFL on several benign parsers after real M4/M5 retirement."""
import argparse
from contextlib import redirect_stderr, redirect_stdout
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

from experiments.afl_campaign_corpus import build as corpus
from experiments.afl_file.build import fault_mutator
from scripts.verify_afl_corpus_components import inspect_cases, stock_launcher
from scripts.verify_afl_capsule_e2e import fault_case
from scripts.verify_afl_phase2_e2e import Progress, SudoLease, write_fault_launcher, verify_saved_faults
from taintforge_env import afl_capsule, afl_file as f, afl_warm as w
from taintforge_env.afl_replay import replay
from taintforge_env.afl_transport import run_campaign
from taintforge_env.afl_validation import SessionChecks, verify_loss_diagnostic
from taintforge_env.capsule_resources import preflight


def validate_limits(executions, seconds, growth, mode):
    if (type(executions) is not int or executions < 10000 or type(seconds) is not int or
            not 60 <= seconds <= 71880 or type(growth) is not int or not 0 <= growth <= 512 or
            mode not in {'parallel', 'sequential'}):
        raise ValueError('Use >=10000 executions, 60..71880 seconds and 0..512 MiB RSS growth')


def prepare(root, target, *, plugin, qemu, seconds, mode, leak_fd=False):
    root = Path(root)
    root.mkdir()
    binary = corpus.build(root/'fixture', target, leak_fd=leak_fd)
    seeds = root/'seeds'
    seeds.mkdir()
    for data in corpus.seeds(target):
        (seeds/hashlib.sha256(data).hexdigest()).write_bytes(data)
    campaign = root/'campaign'
    manifest = w.prepare_campaign(campaign, binary=binary, qemu=qemu, plugin=plugin,
        guest_path='/etc/afl-input', seeds=seeds, max_input=4096, bootstrap_seconds=1200,
        campaign_seconds=seconds+120, timeout_ms=500, max_rss_mib=512,
        memory_mib=4096, analysis_mib=2048, phase2_mode=mode, phase2_pending=4,
        analysis_policy='research')
    for name in ('experiments/afl_campaign_corpus/build.py', 'experiments/afl_campaign_corpus/guest.S',
                 'scripts/verify_afl_corpus_e2e.py', 'scripts/verify_afl_corpus_components.py'):
        manifest['source_sha256'][name] = f.p.sha(f.PROJECT/name)
    f.atomic_json(campaign/'campaign.json', manifest)
    return campaign


def capsule_result(campaign):
    manifest = f.verify_campaign(campaign)
    session = f.read_json(campaign/'warm-session-result.json')
    capsule = session['capsule']
    worker = f.read_json(campaign/'warm-executor.json')
    ready = f.read_json(campaign/'warm-ready.json')
    runtime = f.read_json(Path(manifest['launch']['template_run_dir'])/'config/runtime.json')
    admission = afl_capsule.verify_ready(ready, runtime['capsule']['analysis_policy'])
    f.p.require(manifest['phase1_runs'] == worker['phase1_runs'] == ready['phase1_runs'] == 1 and
        worker['status'] == 'passed' and worker['children'] == manifest['completed_cases'],
        'Phase 1 repetition or child accounting mismatch')
    f.p.require(capsule['status'] == 'passed' and capsule['phase1_retirement']['phase1_retired'] is True and
        capsule['resources']['tree_empty'] is True and capsule['control_guard']['status'] == 'verified' and
        capsule['afl_checkpoint'] == admission and capsule['analysis_quality'] == admission['analysis_quality'],
        'M5 admission, retirement or service cleanup was not verified')
    final = session['finalization']
    f.p.require(final['status'] == 'completed' and all(final['stages'][name]['status'] == 'completed'
        for name in ('execution', 'filesystem', 'phase1', 'syscalls', 'requirements', 'repair_plan', 'capsule')) and
        final['stages']['network_cleanup']['status'] == 'not_applicable', 'Unified finalization failed')
    return {'phase1_runs': 1, 'retirement_verified': True, 'service_cleanup_verified': True,
        'control_guard_verified': True, 'analysis_quality': capsule['analysis_quality']}


def verify_rejection(campaign, launcher):
    failure = None
    try:
        run_campaign(campaign, afl_bin=launcher, seconds=30, executions=1)
    except Exception as exc:
        failure = f'{type(exc).__name__}: {exc}'
    manifest = f.read_json(campaign/'campaign.json')
    f.p.require(failure is not None and manifest['status'] == 'failed' and
                not (campaign/'warm-ready.json').exists() and not (campaign/'afl').exists(),
                'Leaked guest FD was admitted or AFL started before the checkpoint')
    run = campaign/'warm-session/iterations/0000/run'
    stderr = (run/'logs/qemu_strace.log').read_text(errors='replace')
    f.p.require('inherited_guest_or_unknown_fd' in stderr, 'Checkpoint failed for an unrelated reason')
    session = f.read_json(campaign/'warm-session-result.json')
    resources = session.get('capsule_resources') or session.get('capsule', {}).get('resources', {})
    if not resources:
        resources = f.read_json(run/'logs/capsule/service.json')
    f.p.require(resources.get('status') == 'verified' and resources.get('tree_empty') is True,
                'Rejected checkpoint did not clean its service')
    return {'status': 'passed', 'reason': 'inherited_guest_or_unknown_fd',
            'afl_started': False, 'service_cleanup_verified': True, 'error': failure}


def verify(out, *, qemu, afl_bin=None, executions=10000, seconds=1800, mode='parallel',
           max_rss_growth_mib=16, faults=True):
    validate_limits(executions, seconds, max_rss_growth_mib, mode)
    if type(faults) is not bool:
        raise ValueError('Invalid fault injection flag')
    out = Path(out).resolve()
    out.mkdir(parents=True, exist_ok=False)
    report = {'schema': 1, 'status': 'failed', 'scope': 'real_m4_m5_stock_afl_multi_elf_corpus',
        'analysis_policy': 'research', 'targets': {}, 'full_native_acceptance': False,
        'memory_40gib_tested': False, 'native_strict_positive_verified': False,
        'memory_isolation': False, 'hostile_sample_ready': False, 'fault_cases': []}
    progress = Progress(out)
    try:
        preflight()
        qemu = Path(qemu).resolve(strict=True)
        executable = Path(afl_bin)/'afl-fuzz' if afl_bin else Path(shutil.which('afl-fuzz') or '/missing/afl-fuzz')
        launcher = stock_launcher(out/'afl-bin', executable)
        environment = os.environ | {'PYTHONPATH': str(f.PROJECT), 'PYTHONDONTWRITEBYTECODE': '1',
            'TF_QEMU_INCLUDE': str(f.PROJECT/'experiments/execution_capsule_probe/vendor')}
        with SudoLease():
            subprocess.run(['sudo', '-n', 'unshare', '--mount', '--pid', '--fork', '--net', 'true'],
                           check=True, timeout=15)
            with (out/'mount-tests.log').open('wb') as log:
                subprocess.run(['sudo', '-n', 'unshare', '--mount', '--fork', '--', 'env',
                    'PYTHONPATH='+str(f.PROJECT), 'PYTHONDONTWRITEBYTECODE=1', 'TF_WARM_REAL_MOUNTS=1',
                    sys.executable, '-m', 'unittest', '-v', 'tests.test_afl_warm_mounts.RealMountTests'],
                    stdout=log, stderr=subprocess.STDOUT, check=True, timeout=60)
            progress.log('Сборка текущей Phase 1; затем три длинные кампании stock AFL.')
            plugin = out/'libtaintforge_ir.so'
            with (out/'phase1-build.log').open('wb') as log:
                subprocess.run(['bash', 'unpacker/test/build_group7_4c1_plugin.sh', 'unpacker/test', str(plugin)],
                    cwd=f.PROJECT, env=environment, stdout=log, stderr=subprocess.STDOUT, check=True)
            from taintforge_env.phase1_runtime import Phase1Runtime
            report['phase1_build_id'] = Phase1Runtime.load(plugin).build_id
            for target in corpus.ALL_TARGETS:
                positive = target in corpus.TARGETS
                duration, count = (seconds, executions) if positive else (180, 128)
                selected_launcher = launcher
                if not positive:
                    selected_launcher = out/'fault-afl-bin'
                    selected_launcher.mkdir()
                    write_fault_launcher(selected_launcher/'afl-fuzz', executable.resolve(), fault_mutator(out/'mutator'))
                campaign = prepare(out/target, target, plugin=plugin, qemu=qemu, seconds=duration, mode=mode)
                # The real AFL executable is an immutable campaign asset, including when a shim is used.
                manifest = f.read_json(campaign/'campaign.json')
                manifest['assets'][str(executable.resolve())] = f.p.sha(executable)
                f.atomic_json(campaign/'campaign.json', manifest)
                progress.log(target+': '+str(count)+' исполнений AFL плюс контрольные входы.')
                with Progress(campaign), (out/target/'pipeline.log').open('w') as log, \
                        redirect_stdout(log), redirect_stderr(log):
                    result = run_campaign(campaign, afl_bin=selected_launcher, seconds=duration, executions=count,
                        session_check=SessionChecks(target, max_rss_growth_mib=max_rss_growth_mib))
                f.p.require(result['status'] == 'completed', 'Campaign stopped before acceptance: '+target)
                capsule = capsule_result(campaign)
                ready = f.read_json(campaign/'warm-ready.json')
                checked = inspect_cases(campaign, target, {'resources': ready['parent_resources'], 'rss_mib': ready['rss_mib']},
                    phase1_runs=1, marker='/tmp/afl-marker', prepared='/tmp/afl-prepared', executions=count,
                    max_rss_growth_mib=max_rss_growth_mib, verify_phase2_identity=True)
                if not positive:
                    checked.update(verify_saved_faults(campaign), mutator='deliberate_fault_control')
                report['targets'][target] = capsule | checked
                f.atomic_json(out/'acceptance.json', report)
            rejected = prepare(out/'leaked-fd', 'prefix', plugin=plugin, qemu=qemu, seconds=30, mode=mode, leak_fd=True)
            report['leaked_fd'] = verify_rejection(rejected, launcher)
            source = out/'fault-prefix/campaign'
            findings = sorted((source/'findings/crashes').glob('*/finding.json'))
            f.p.require(findings, 'No retained control crash for replay')
            finding = max(findings, key=lambda path: (path.parent/'input').stat().st_size)
            report['replay'] = replay(source, finding.parent, out/'replay', repetitions=3, reduce=True, budget=64)
            f.p.require(report['replay']['status'] == 'passed' and report['replay']['phase1_runs'] == 1,
                        'Control crash replay failed')
            reduction = report['replay']['minimization']
            f.p.require(reduction['original_bytes'] > reduction['minimized_bytes'] == 1 and
                        reduction['executions'] > 0 and not reduction['budget_exhausted'],
                        'Control crash minimization was not exercised')
            if faults:
                def check_case(case, result):
                    expected = corpus.expected('prefix', (case/'input').read_bytes())
                    f.p.require((result['outcome']['kind'], result['guest_exit'], result['outcome']['guest_signal']) == expected,
                                'Infrastructure loss was misclassified as a guest fault')
                for role in ('observer', 'qemu'):
                    loss = fault_case(out/'prefix/campaign', out/('kill-'+role), role,
                                      afl_bin=launcher, case_verifier=check_case)
                    loss['diagnostic'] = verify_loss_diagnostic(loss)
                    report['fault_cases'].append(loss)
        report.update(status='passed', full_native_acceptance=faults,
                      fault_injection_tested=faults, phase1_runs_per_session=1)
        return report
    except BaseException as exc:
        report['error'] = f'{type(exc).__name__}: {exc}'
        raise
    finally:
        f.atomic_json(out/'acceptance.json', report)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--qemu', type=Path, required=True)
    parser.add_argument('--afl-bin', type=Path)
    parser.add_argument('--executions', type=int, default=10000)
    parser.add_argument('--seconds', type=int, default=1800)
    parser.add_argument('--phase2-mode', choices=('parallel', 'sequential'), default='parallel')
    parser.add_argument('--max-rss-growth-mib', type=int, default=16)
    parser.add_argument('--skip-fault-injection', action='store_true')
    args = parser.parse_args()
    print(json.dumps(verify(args.out, qemu=args.qemu, afl_bin=args.afl_bin, executions=args.executions,
        seconds=args.seconds, mode=args.phase2_mode, max_rss_growth_mib=args.max_rss_growth_mib,
        faults=not args.skip_fault_injection), indent=2))


if __name__ == '__main__':
    main()
