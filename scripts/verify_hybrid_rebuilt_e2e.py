"""Native acceptance: one bundled benign i386 fixture through rebuilt live hybrid.

Requires the user's Linux host, matching warm QEMU 11.0.1, Phase 1 plugin
headers, AFL++, sudo namespaces and systemd cgroups. This does NOT certify
arbitrary recovered or hostile samples. Every success claim follows real
re-execution and artifact inspection; failures leave acceptance.json='failed'.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import traceback

from experiments.hybrid_prefix_v1.runtime import build_plugin, require, save, sha
from experiments.hybrid_rebuilt_v1.acceptance import audit_native_campaign
from experiments.hybrid_rebuilt_v1.policy import digest
from scripts.run_afl_rebuilt import prepare_hybrid
from taintforge_env import afl_rebuilt as backend
from taintforge_env.input_retirement import inspect_input
from taintforge_env.phase1_runtime import Phase1Runtime


def build_input_fixture(out):
    """Use the original harmless fixture with the rebuilt backend's input path."""
    out.mkdir(parents=True, exist_ok=False)
    original = Path(__file__).resolve().parents[1] / 'experiments/hybrid_prefix_v1/fixture.S'
    text = original.read_text()
    require(text.count('/etc/afl-input') == 1, 'Fixture input contract changed')
    source = out / 'fixture.S'
    source.write_text(text.replace('/etc/afl-input', '/etc/dta-input'))
    object_file = out / 'fixture.o'
    binary = out / 'fixture-i386'
    with (out / 'build.log').open('wb') as log:
        subprocess.run(['as', '--32', str(source), '-o', str(object_file)],
                       check=True, stdout=log, stderr=subprocess.STDOUT)
        subprocess.run(['ld', '-m', 'elf_i386', '-z', 'noexecstack', '--build-id=none',
                        str(object_file), '-o', str(binary)],
                       check=True, stdout=log, stderr=subprocess.STDOUT)
        subprocess.run(['strip', '--strip-all', str(binary)],
                       check=True, stdout=log, stderr=subprocess.STDOUT)
    info = inspect_input(binary)
    require(info['arch'] == 'i386' and info['static'] is True,
            'Native acceptance fixture is not a static i386 ELF')
    return binary


def acceptance(root, *, qemu, qemu_include, flags_receipt, afl_bin,
               seconds=900, max_cases=512, stall_cases=16):
    from scripts.verify_afl_phase2_e2e import SudoLease
    root = backend.private_path(root)
    require(not root.exists(), 'Use a fresh directory for native acceptance')
    require(300 <= seconds <= 3600 and 128 <= max_cases <= 4096,
            'Native acceptance campaign outside bounded budgets')
    qemu = Path(qemu).expanduser().resolve(strict=True)
    qemu_include = Path(qemu_include).expanduser().resolve(strict=True)
    flags_receipt = Path(flags_receipt).expanduser().resolve(strict=True)
    afl_bin = Path(afl_bin).expanduser().resolve(strict=True)
    require(os.access(afl_bin, os.X_OK), 'afl-fuzz is not executable')
    root.mkdir(parents=True, mode=0o700)
    report = {'schema': 1, 'status': 'failed', 'stage': 'initialization',
              'profile': 'fixed_benign_rebuilt_live_hybrid_native_e2e_v1',
              'native_e2e_verified': False, 'fixture_only': True,
              'hostile_sample_ready': False}

    def stage(name):
        report['stage'] = name
        save(root / 'acceptance.json', report)
        print('NATIVE_E2E_STAGE ' + name, flush=True)

    try:
        stage('build_benign_fixture_and_DTA_plugin')
        target = build_input_fixture(root / 'fixture')
        plugin = build_plugin(root / 'plugin', qemu_include)
        Phase1Runtime.load(plugin).validate_qemu(qemu)
        seeds = root / 'seeds'
        seeds.mkdir(mode=0o700)
        original = b'AA' + b'x' * 30
        (seeds / digest(original)).write_bytes(original)
        report['target_sha256'] = sha(target)
        report['plugin_sha256'] = sha(plugin)
        with SudoLease():
            stage('prepare_isolated_rebuilt_AFL')
            campaign = root / 'campaign'
            backend.prepare(campaign, target, seeds, qemu, plugin, case_seconds=5)
            stage('DTA_and_audited_initial_mask')
            controller, library = prepare_hybrid(campaign, binary=target,
                qemu=qemu, plugin=plugin, flags_receipt=flags_receipt,
                stall_cases=stall_cases, max_dse_jobs=2, max_candidates=16)
            stage('live_AFL_plateau_DSE_and_DTA_refresh')
            outcome = backend.campaign(campaign, afl_bin, seconds=seconds,
                max_cases=max_cases, disk_mib=2048,
                hybrid=controller, hybrid_library=library)
            require(outcome['status'] == 'completed' and outcome.get('hybrid_result', {}).get(
                'automatic_live_cycle_verified') is True,
                'Native live DSE->AFL->DTA cycle was not observed')
            stage('independent_artifact_and_replay_audit')
            receipts = audit_native_campaign(campaign, expected_target_sha256=report['target_sha256'])
            require(receipts['live_cycle_observed'], 'Missing in-campaign plateau, worker and guest execution')
            hybrid = backend.read_json(campaign / 'hybrid-result.json')
            require(hybrid['target_sha256'] == report['target_sha256'] and
                    hybrid['automatic_live_cycle_verified'] is True and
                    hybrid['DSE_seed_retained_by_AFL'] is True,
                    'Live seed, queue, or target binding is incomplete')
            witnessed = {row['seed_sha256'] for row in receipts['witnessed_cycles']}
            retained = [row['sha256'] for row in hybrid['DSE_queue_membership'] if row['sha256'] in witnessed]
            require(retained, 'No retained seed has a witnessed in-campaign execution')
            identity = retained[0]
            raw = (campaign / 'verified-dse-seeds' / identity).read_bytes()
            require(digest(raw) == identity, 'Native DSE seed changed')
            evidence = [job for job in hybrid['DSE_jobs'] if
                        job.get('candidate_sha256') == identity and job['status'] == 'VERIFIED']
            require(len(evidence) == 1, 'DSE concrete evidence does not match retained seed')
            queue = [p for p in (campaign / 'afl/default/queue').glob('id:*')
                     if p.is_file() and not p.is_symlink() and digest(p.read_bytes()) == identity]
            require(queue, 'AFL queue does not contain the verified DSE seed')
            replays = []
            for repetition in range(2):
                receipt, bitmap = backend.execute_case(campaign, raw,
                    root / f'DSE-independent-replay-{repetition}')
                require(receipt['status'] == 'passed' and digest(bitmap) ==
                        receipt['coverage']['map_sha256'], 'Native replay lacks verified coverage')
                replays.append((receipt['guest_exit'], receipt['coverage']['map_sha256'],
                                receipt['coverage']['branch_outcomes']))
            require(replays[0] == replays[1], 'DSE seed is not stable across fresh isolated replays')
            report.update(status='passed_native_rebuilt_fixture_hybrid', stage='completed',
                          native_e2e_verified=True, phase1_executed_in_rebuilt_campaign=False,
                          DSE_seed_sha256=identity,
                          witnessed_cycles=receipts['witnessed_cycles'],
                          skip_limit_request=receipts['skip_limit_request'],
                          DSE_seed_independent_replays=2,
                          AFL_queue_membership=True,
                          DTA_mask_refresh_count=hybrid['DTA_mask_refresh_count'],
                          isolated_AFL_cases=outcome['cases'],
                          source_scope='one bundled benign i386 parser')
            return report
    except BaseException as exc:
        report['error'] = f'{type(exc).__name__}: {exc}'
        (root / 'failure.log').write_text(traceback.format_exc())
        raise
    finally:
        save(root / 'acceptance.json', report)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    for name, environment in [('qemu', 'TF_WARM_QEMU'),
                              ('qemu-include', 'TF_QEMU_INCLUDE'),
                              ('flags-receipt', 'TF_X86_FLAGS_RECEIPT')]:
        default = os.environ.get(environment)
        parser.add_argument('--' + name, type=Path, default=Path(default) if default else None,
                            required=not bool(default))
    parser.add_argument('--afl-bin', type=Path,
                        default=Path(shutil.which('afl-fuzz')) if shutil.which('afl-fuzz') else None)
    parser.add_argument('--seconds', type=int, default=900)
    parser.add_argument('--max-cases', type=int, default=512)
    parser.add_argument('--stall-cases', type=int, default=16)
    args = parser.parse_args(argv)
    try:
        require(args.afl_bin is not None, 'afl-fuzz is not installed')
        result = acceptance(args.out, qemu=args.qemu, qemu_include=args.qemu_include,
                            flags_receipt=args.flags_receipt, afl_bin=args.afl_bin,
                            seconds=args.seconds, max_cases=args.max_cases,
                            stall_cases=args.stall_cases)
    except (OSError, RuntimeError, ValueError, KeyError, subprocess.SubprocessError) as exc:
        print('NATIVE_HYBRID_E2E_FAILED: ' + str(exc), file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
