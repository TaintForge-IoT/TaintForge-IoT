"""Run AFL or the automatic hybrid cycle on the bundled harmless prefix parser."""
from __future__ import annotations

import argparse
from contextlib import redirect_stderr, redirect_stdout
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import traceback

from .controller import LiveController, analyze
from .policy import SEED, INPUT_PATH, digest
from .runtime import HERE, PROJECT, build_fixture, build_plugin, require, save, sha


def launcher(directory, executable, library, controller):
    directory.mkdir(parents=True, exist_ok=False)
    options = {'AFL_CUSTOM_MUTATOR_LIBRARY': str(library), 'AFL_CUSTOM_MUTATOR_ONLY': '1',
        'AFL_DISABLE_TRIM': '1', 'TF_HYBRID_SOCKET': str(controller.socket_path),
        'TF_HYBRID_TOKEN': controller.token, 'AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES': '1'}
    script = directory / 'afl-fuzz'
    script.write_text('#!/usr/bin/env python3\nimport os, sys\n'
        'os.environ.update(' + repr(options) + ')\n'
        'os.execv(' + repr(str(executable)) + ', [' + repr(str(executable)) + '] + sys.argv[1:])\n')
    script.chmod(0o700)
    return directory



HYBRID_STARTUP_FIX_REVISION = 1


def campaign_diagnostics(campaign):
    campaign = Path(campaign)
    fields = ('status', 'stage', 'error', 'cleanup_error', 'outcome', 'stop_reason',
              'storage_stop', 'afl_exit', 'cases', 'completed_cases', 'evidence_complete',
              'phase1_runs', 'children', 'failure', 'controller_errors')
    result = {'campaign': str(campaign)}
    for name in ('campaign.json', 'warm-ready.json', 'warm-executor.json', 'warm-session-result.json'):
        path = campaign / name
        if not path.is_file():
            result[name] = {'present': False}
            continue
        try:
            if path.stat().st_size > 4 * 1024 * 1024:
                raise ValueError('diagnostic JSON exceeds the size limit')
            value = json.loads(path.read_bytes())
            if not isinstance(value, dict):
                raise ValueError('diagnostic JSON is not an object')
            selected = {key: value[key] for key in fields if key in value}
            selected['present'] = True
            if name == 'campaign.json':
                selected['afl_launch_recorded'] = 'afl_started_ns' in value
                selected['session_check_stages'] = sorted(value.get('session_checks', {}))
                storage = value.get('storage_result')
                if isinstance(storage, dict):
                    selected['storage_result'] = {key: storage[key] for key in
                        ('status', 'reason', 'stop', 'usage', 'policy', 'reserve_released') if key in storage}
            capsule = value.get('capsule')
            if isinstance(capsule, dict):
                selected['capsule'] = {key: capsule[key] for key in fields if key in capsule}
            result[name] = selected
        except (OSError, ValueError, TypeError) as exc:
            result[name] = {'diagnostic_error': f'{type(exc).__name__}: {exc}'}
    tails = {}
    for name in ('warm-worker.log', 'afl.log',
                 'warm-session/iterations/0000/run/logs/qemu_strace.log',
                 'warm-session/iterations/0000/run/logs/runtime_stderr.log',
                 'warm-session/iterations/0000/run/logs/capsule/supervisor.json'):
        path = campaign / name
        if not path.is_file():
            continue
        try:
            with path.open('rb') as stream:
                stream.seek(0, 2)
                size = stream.tell()
                stream.seek(max(0, size - 16000))
                text = stream.read().decode('utf-8', errors='replace')
            tails[name] = {'size_bytes': size, 'last_lines': text.splitlines()[-60:]}
        except OSError as exc:
            tails[name] = {'diagnostic_error': str(exc)}
    result['log_tails'] = tails
    return result


def check_campaign_outcome(value, campaign, controller):
    if not isinstance(value, dict):
        raise RuntimeError('Warm/AFL returned no campaign result; inspect ' + str(Path(campaign) / 'campaign.json'))
    selected = {key: value[key] for key in
        ('status', 'error', 'cleanup_error', 'stop_reason', 'storage_stop',
         'evidence_complete', 'afl_exit', 'cases', 'completed_cases') if key in value}
    if value.get('status') != 'completed':
        raise RuntimeError('Warm/AFL campaign stopped before hybrid finalization: ' +
                           json.dumps(selected, sort_keys=True))
    if value.get('evidence_complete') is not True:
        raise RuntimeError('Warm/AFL campaign returned incomplete evidence: ' +
                           json.dumps(selected, sort_keys=True))
    if controller.server is None:
        raise RuntimeError('Warm/AFL returned completed without invoking before_afl; inspect ' +
                           str(Path(campaign) / 'campaign.json'))
    return selected


def check_afl_only_outcome(value, campaign):
    if not isinstance(value, dict):
        raise RuntimeError('Warm/AFL returned no campaign result; inspect ' + str(Path(campaign) / 'campaign.json'))
    selected = {key: value[key] for key in
        ('status', 'error', 'cleanup_error', 'stop_reason', 'storage_stop',
         'evidence_complete', 'afl_exit', 'cases', 'completed_cases') if key in value}
    if (value.get('status') != 'completed' or value.get('evidence_complete') is not True
            or value.get('afl_exit') != 0):
        raise RuntimeError('Warm/AFL campaign stopped before AFL-only finalization: ' +
                           json.dumps(selected, sort_keys=True))
    return selected


def verify(args):
    from scripts.verify_afl_phase2_e2e import SudoLease
    from taintforge_env import afl_file as f, afl_warm
    from taintforge_env.afl_evidence import completed_cases, child_report
    from taintforge_env.afl_transport import run_campaign
    from taintforge_env.phase1_runtime import Phase1Runtime
    root = args.out.expanduser().absolute()
    require(not root.exists() and not root.is_symlink(), 'Choose a new short output directory')
    require(64 <= args.executions <= 1000 and 120 <= args.seconds <= 1200
            and 4 <= args.stall_cases <= 64, 'Invalid bounded fixture limits')
    qemu = args.qemu.expanduser().resolve(strict=True)
    receipt = args.flags_receipt.expanduser().resolve(strict=True)
    qemu_include = args.qemu_include.expanduser().resolve(strict=True)
    executable = args.afl_bin / 'afl-fuzz' if args.afl_bin else Path(shutil.which('afl-fuzz') or '/missing/afl-fuzz')
    executable = executable.expanduser().resolve(strict=True)
    require(os.access(executable, os.X_OK), 'AFL is not executable')
    afl_warm.configuration(root / 'campaign', bootstrap_seconds=180,
        campaign_seconds=args.seconds + 60, timeout_ms=3000, max_rss_mib=512,
        phase2_mode='parallel', capsule_m5=True)
    root.mkdir(parents=True, mode=0o700)
    report = {'schema': 1, 'status': 'failed', 'stage': 'build', 'mode': 'hybrid',
        'profile': 'fixed_prefix_live_hybrid_v1', 'fixture_only': True,
        'automatic_cycle_verified': False, 'same_binary_chain_verified': False,
        'hostile_sample_ready': False, 'maximum_DSE_jobs': 1,
        'source_sha256': {path.name: sha(path) for path in sorted(HERE.iterdir())
                          if path.is_file() and path.suffix in ('.py', '.c', '.h', '.S')}}
    controller = None
    print('Results: ' + str(root), flush=True)

    def stage(name):
        report['stage'] = name
        save(root / 'acceptance.json', report)
        print('Stage: ' + name, flush=True)

    try:
        stage('build_one_fixture_and_separate_Phase1_runtime')
        binary, metadata = build_fixture(root / 'fixture')
        plugin = build_plugin(root / 'runtime', qemu_include)
        Phase1Runtime.load(plugin).validate_qemu(qemu)
        report['fixture'] = metadata
        report['plugin'] = str(plugin)
        library = root / 'masked_adapter.so'
        subprocess.run(['cc', '-std=c11', '-O2', '-g', '-Wall', '-Wextra', '-Werror',
                        '-fPIC', '-shared', str(HERE / 'mutator.c'), '-o', str(library)],
                       check=True, capture_output=True)
        with SudoLease():
            stage('DTA_analysis_and_audited_live_mask')
            with (root / 'initial-dta.log').open('w') as log, redirect_stdout(log), redirect_stderr(log):
                initial = analyze(root / 'initial-dta', binary=binary, metadata=metadata,
                                  qemu=qemu, plugin=plugin, seed=SEED)
            require(set(initial['mask']) == {0, 1}
                    and all(row['guest_exit'] < 2 for row in initial['report']['runs']),
                    'The initial DTA fixture already passed the branch reserved for DSE')
            stage('prepare_one_warm_campaign')
            controller = LiveController(root, analysis=initial, metadata=metadata, binary=binary,
                qemu=qemu, plugin=plugin, receipt=receipt, threshold=args.stall_cases)
            shim = launcher(root / 'afl-bin', executable, library, controller)
            campaign = root / 'campaign'
            with (root / 'prepare.log').open('w') as log, redirect_stdout(log), redirect_stderr(log):
                afl_warm.prepare_campaign(campaign, binary=binary, qemu=qemu, plugin=plugin,
                    guest_path=INPUT_PATH, seeds=initial['directory'] / 'accepted-seeds',
                    max_input=32, bootstrap_seconds=180, campaign_seconds=args.seconds + 60,
                    timeout_ms=3000, max_rss_mib=512, memory_mib=4096, analysis_mib=2048,
                    phase2_mode='parallel', analysis_policy='research', flags_receipt=receipt,
                    ir_start=metadata['ir_start'])
            controller.start()
            stage('live_masked_AFL_plateau_DSE_and_DTA_refresh')
            with (root / 'campaign.log').open('w') as log, redirect_stdout(log), redirect_stderr(log):
                campaign_result = run_campaign(campaign, afl_bin=shim, seconds=args.seconds, executions=args.executions,
                             session_check=controller.bind)
            report['campaign_outcome'] = check_campaign_outcome(campaign_result, campaign, controller)
            controller.close()
            stage('verify_live_case_queue_and_capsule_evidence')
            hybrid = controller.finish()
            manifest = f.verify_campaign(campaign)
            require(manifest['status'] == 'completed' and manifest.get('evidence_complete') is True
                    and manifest.get('phase1_runs') == 1
                    and sha(Path(manifest['launch']['binary_path'])) == metadata['binary_sha256'],
                    'Warm campaign failed or used another ELF or Phase 1 run count')
            cases = completed_cases(campaign, manifest)
            for case in cases:
                child_report(case, 32)
            candidate_sha = hybrid['DSE']['candidate_sha256']
            queued = [path.name for path in sorted((campaign / 'afl/default/queue').glob('id:*'))
                      if path.is_file() and not path.is_symlink() and sha(path) == candidate_sha]
            require(queued, 'AFL did not retain the concretely verified DSE seed in its own queue')
            hybrid['AFL_queue_entries_for_DSE_seed'] = queued
            hybrid['queue_membership_verified_separately'] = True
            save(root / 'hybrid-result.json', hybrid)
            report.update(status='passed_fixed_fixture_live_hybrid', stage='completed',
                automatic_cycle_verified=True, same_binary_chain_verified=True,
                live_AFL_DTA_mask_verified=True, live_coverage_plateau_trigger_verified=True,
                DSE_seed_executed_and_retained_by_AFL=True, DTA_mask_refresh_verified=True,
                campaign_Phase1_runs=1, cases=len(cases), hybrid=hybrid,
                analysis_runs_scope='DTA and DSE use separate fresh analysis executions; one Phase1 run belongs to the live warm campaign')
            return report
    except BaseException as exc:
        report['error'] = f'{type(exc).__name__}: {exc}'
        (root / 'failure.log').write_text(traceback.format_exc())
        if controller is not None:
            report['controller_errors'] = list(controller.errors)
        if (root / 'campaign').is_dir():
            try:
                report['campaign_diagnostics'] = campaign_diagnostics(root / 'campaign')
                print('CAMPAIGN_DIAGNOSTICS: ' + json.dumps(report['campaign_diagnostics'], sort_keys=True),
                      file=sys.stderr, flush=True)
            except (OSError, ValueError, TypeError) as diagnostic_error:
                report['diagnostic_error'] = str(diagnostic_error)
        raise
    finally:
        try:
            if controller is not None:
                controller.close()
        except BaseException as cleanup:
            report.update(status='failed', cleanup_error=f'{type(cleanup).__name__}: {cleanup}')
            raise
        finally:
            save(root / 'acceptance.json', report)


def verify_afl_only(args):
    from scripts.verify_afl_phase2_e2e import SudoLease
    from taintforge_env import afl_file as f, afl_warm
    from taintforge_env.afl_evidence import completed_cases, child_report
    from taintforge_env.afl_transport import run_campaign
    from taintforge_env.phase1_runtime import Phase1Runtime
    root = args.out.expanduser().absolute()
    require(not root.exists() and not root.is_symlink(), 'Choose a new short output directory')
    require(64 <= args.executions <= 1000 and 120 <= args.seconds <= 1200,
            'Invalid bounded fixture limits')
    qemu = args.qemu.expanduser().resolve(strict=True)
    receipt = args.flags_receipt.expanduser().resolve(strict=True)
    qemu_include = args.qemu_include.expanduser().resolve(strict=True)
    executable = args.afl_bin / 'afl-fuzz' if args.afl_bin else Path(shutil.which('afl-fuzz') or '/missing/afl-fuzz')
    executable = executable.expanduser().resolve(strict=True)
    require(os.access(executable, os.X_OK), 'AFL is not executable')
    afl_warm.configuration(root / 'campaign', bootstrap_seconds=180,
        campaign_seconds=args.seconds + 60, timeout_ms=3000, max_rss_mib=512,
        phase2_mode='parallel', capsule_m5=True)
    root.mkdir(parents=True, mode=0o700)
    report = {'schema': 1, 'status': 'failed', 'stage': 'build', 'mode': 'afl',
        'profile': 'fixed_prefix_afl_only_v1', 'fixture_only': True,
        'automatic_cycle_verified': False, 'same_binary_chain_verified': False,
        'hostile_sample_ready': False, 'DTA_executed': False, 'DSE_executed': False,
        'source_sha256': {path.name: sha(path) for path in sorted(HERE.iterdir())
                          if path.is_file() and path.suffix in ('.py', '.c', '.h', '.S')}}
    print('Results: ' + str(root), flush=True)

    def stage(name):
        report['stage'] = name
        save(root / 'acceptance.json', report)
        print('Stage: ' + name, flush=True)

    try:
        stage('build_one_fixture_and_separate_Phase1_runtime')
        binary, metadata = build_fixture(root / 'fixture')
        plugin = build_plugin(root / 'runtime', qemu_include)
        Phase1Runtime.load(plugin).validate_qemu(qemu)
        report['fixture'] = metadata
        report['plugin'] = str(plugin)
        seeds = root / 'initial-seeds'
        seeds.mkdir(mode=0o700)
        (seeds / digest(SEED)).write_bytes(SEED)
        with SudoLease():
            stage('prepare_one_warm_campaign')
            campaign = root / 'campaign'
            with (root / 'prepare.log').open('w') as log, redirect_stdout(log), redirect_stderr(log):
                afl_warm.prepare_campaign(campaign, binary=binary, qemu=qemu, plugin=plugin,
                    guest_path=INPUT_PATH, seeds=seeds, max_input=32,
                    bootstrap_seconds=180, campaign_seconds=args.seconds + 60,
                    timeout_ms=3000, max_rss_mib=512, memory_mib=4096, analysis_mib=2048,
                    phase2_mode='parallel', analysis_policy='research', flags_receipt=receipt,
                    ir_start=metadata['ir_start'])
            stage('stock_AFL_without_DTA_or_DSE')
            with (root / 'campaign.log').open('w') as log, redirect_stdout(log), redirect_stderr(log):
                outcome = run_campaign(campaign, afl_bin=executable, seconds=args.seconds,
                                       executions=args.executions)
            report['campaign_outcome'] = check_afl_only_outcome(outcome, campaign)
            stage('verify_AFL_case_and_capsule_evidence')
            manifest = f.verify_campaign(campaign)
            require(manifest['status'] == 'completed' and manifest.get('evidence_complete') is True
                    and manifest.get('phase1_runs') == 1
                    and sha(Path(manifest['launch']['binary_path'])) == metadata['binary_sha256'],
                    'Warm campaign failed or used another ELF or Phase 1 run count')
            cases = completed_cases(campaign, manifest)
            require(cases, 'AFL-only fixture campaign delivered no cases')
            for case in cases:
                child_report(case, 32)
            require(any(sha(case / 'input') == digest(SEED) for case in cases),
                    'AFL-only campaign did not execute its initial seed')
            report.update(status='passed_fixed_fixture_afl_only', stage='completed',
                same_binary_chain_verified=True, campaign_Phase1_runs=1, cases=len(cases))
            return report
    except BaseException as exc:
        report['error'] = f'{type(exc).__name__}: {exc}'
        (root / 'failure.log').write_text(traceback.format_exc())
        if (root / 'campaign').is_dir():
            try:
                report['campaign_diagnostics'] = campaign_diagnostics(root / 'campaign')
            except (OSError, ValueError, TypeError) as diagnostic_error:
                report['diagnostic_error'] = str(diagnostic_error)
        raise
    finally:
        save(root / 'acceptance.json', report)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode', choices=('afl', 'hybrid'), default='hybrid')
    parser.add_argument('--out', type=Path, required=True)
    for name, variable in (('qemu', 'TF_WARM_QEMU'), ('qemu-include', 'TF_QEMU_INCLUDE'),
                           ('flags-receipt', 'TF_X86_FLAGS_RECEIPT')):
        value = os.environ.get(variable)
        parser.add_argument('--' + name, type=Path, default=Path(value) if value else None,
                            required=not bool(value))
    parser.add_argument('--afl-bin', type=Path)
    parser.add_argument('--seconds', type=int, default=600)
    parser.add_argument('--executions', type=int, default=128)
    parser.add_argument('--stall-cases', type=int, default=16)
    args = parser.parse_args(argv)
    try:
        result = verify_afl_only(args) if args.mode == 'afl' else verify(args)
    except (OSError, RuntimeError, ValueError, KeyError, subprocess.SubprocessError) as exc:
        print(args.mode.upper() + '_FAILED: ' + str(exc), file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
