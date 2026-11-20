import argparse
from contextlib import redirect_stderr, redirect_stdout
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess

from taintforge_env import capsule_strict as s, afl_warm as w
from taintforge_env.afl_transport import run_campaign
from scripts.verify_afl_phase2_e2e import SudoLease

WARM_LIMITS = dict(bootstrap_seconds=180, campaign_seconds=90, timeout_ms=3000,
                   max_rss_mib=512, phase2_mode='parallel')


def launch_case(out, fixture, *, qemu, plugin, receipt, afl_bin, executions):
    root = out/'campaign'
    seeds = out/'seeds'
    seeds.mkdir()
    (seeds/'A').write_bytes(b'A')
    (seeds/'B').write_bytes(b'B')
    w.prepare_campaign(root, binary=fixture['path'], qemu=qemu, plugin=plugin,
        guest_path='/etc/afl-input', seeds=seeds, analysis_policy='strict',
        flags_receipt=receipt, ir_start=fixture['ir_start'], **WARM_LIMITS,
        memory_mib=4096, analysis_mib=2048)
    error = None
    with (out/'pipeline.log').open('w') as log, redirect_stdout(log), redirect_stderr(log):
        try:
            run_campaign(root, afl_bin=afl_bin, seconds=60, executions=executions)
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
            error = type(exc).__name__+': '+str(exc)
    if error is not None:
        details = s.failure_details(root, error)
        s.save(out/'diagnostics.json', details)
        error = details['reason']+'; diagnostics: '+str(out/'diagnostics.json')
    if fixture['negative']:
        s.require(error is not None, 'Negative strict case unexpectedly completed')
        return s.verify_negative(root) | {'pipeline_error': error}
    s.require(error is None, 'Positive strict case failed: '+str(error)+'; log: '+str(out/'pipeline.log'))
    return s.verify_positive(root, minimum=executions, expected_oep=fixture['expected_oep'])


def verify(out, *, qemu, afl_bin=None, executions=32):
    out = Path(out).expanduser().absolute()
    s.require(not out.exists() and executions >= 2, 'Use a new output directory and at least 2 executions')
    out.mkdir(parents=True)
    report = {'schema': 1, 'status': 'failed', 'scope': 'native_warm_m5_strict_admission_and_denial',
              'native_strict_positive_verified': False, 'native_strict_negative_verified': False,
              'oep_proven': False, 'memory_isolation': False, 'hostile_sample_ready': False}
    try:
        for name in ('positive', 'negative'):
            w.configuration(out/name/'campaign', **WARM_LIMITS, capsule_m5=True)
        missing = [tool for tool in ('gcc', 'as', 'ld', 'strip', 'nm', 'pkg-config', 'sudo', 'systemd-run',
                                     'systemctl', 'bash', 'unshare', 'mount', 'umount', 'ip', 'hostname',
                                     'timeout', 'chroot', 'tee')
                   if not shutil.which(tool)]
        if shutil.which('pkg-config') and subprocess.run(
                ['pkg-config', '--exists', 'glib-2.0', 'capstone', 'z3'],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode:
            missing.append('GLib/Capstone/Z3 development packages')
        qemu = Path(qemu).expanduser().resolve()
        if not qemu.is_file():
            missing.append(str(qemu))
        executable = Path(afl_bin)/'afl-fuzz' if afl_bin else Path(shutil.which('afl-fuzz') or '/nonexistent/afl-fuzz')
        if not executable.is_file():
            missing.append(str(executable))
        if not Path('/run/systemd/system').is_dir():
            missing.append('running systemd system manager')
        if missing:
            report.update(status='blocked_environment', missing=missing)
            return report
        version = subprocess.check_output([str(qemu), '--version'], text=True, timeout=15)
        s.require(re.search(r'\bversion 11\.0\.1(?:[\s(]|$)', version), 'QEMU 11.0.1 required')
        symbols = subprocess.check_output(['nm', '-D', '--defined-only', str(qemu)], text=True)
        exported = {line.split()[-1] for line in symbols.splitlines() if line.split()}
        s.require({'qemu_plugin_tf_warm_configure', 'qemu_plugin_tf_warm_arm', 'qemu_plugin_tf_warm_abi2'} <= exported,
                  'QEMU warm ABI 2 required')
        plugin = out/'libtaintforge_ir.so'
        environment = os.environ | {'TF_QEMU_INCLUDE': str(s.PROJECT/'experiments/execution_capsule_probe/vendor'),
                                    'GIT_CEILING_DIRECTORIES': str(s.PROJECT.parent)}
        print('Сборка Phase 1 для strict-проверки.', flush=True)
        with (out/'phase1-build.log').open('wb') as log:
            subprocess.run(['bash', 'unpacker/test/build_group7_4c1_plugin.sh', 'unpacker/test', str(plugin)],
                           cwd=s.PROJECT, env=environment, stdout=log, stderr=subprocess.STDOUT, check=True)
        print('Проверка EFLAGS на выбранном QEMU.', flush=True)
        receipt = s.calibration(qemu, plugin, out/'calibration')
        launcher = out/'afl-bin'
        launcher.mkdir()
        core = Path('/proc/sys/kernel/core_pattern').read_text().strip()
        override = core.startswith('|')
        if override:
            s.require(b'AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES' in executable.read_bytes(),
                      'AFL does not support the fixture core-pattern override')
        shim = launcher/'afl-fuzz'
        shim.write_text('#!/bin/sh\n'+('export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1\n' if override else '')+
                        'exec '+shlex.quote(str(executable.resolve()))+' "$@"\n')
        shim.chmod(0o700)
        report.update(qemu_sha256=s.digest(qemu), plugin_sha256=s.digest(plugin),
                      calibration_sha256=s.digest(out/'calibration/calibration.json'),
                      flags_receipt_sha256=s.digest(receipt), fixture_only_core_override=override)
        with SudoLease():
            for name, negative in [('positive', False), ('negative', True)]:
                case = out/name
                case.mkdir()
                fixture = s.build_fixture(case/'fixture', negative=negative)
                print('Strict '+name+': запуск.', flush=True)
                result = launch_case(case, fixture, qemu=qemu, plugin=plugin, receipt=receipt,
                                     afl_bin=launcher, executions=executions)
                report[name] = result
                report['native_strict_'+name+'_verified'] = True
                s.save(out/'acceptance.json', report)
                print('Strict '+name+': passed.', flush=True)
        s.require(s.digest(qemu) == report['qemu_sha256'] and s.digest(plugin) == report['plugin_sha256']
                  and s.digest(receipt) == report['flags_receipt_sha256'], 'Strict runtime changed')
        report['status'] = 'passed'
        return report
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError, KeyError) as exc:
        report['error'] = type(exc).__name__+': '+str(exc)
        return report
    finally:
        s.save(out/'acceptance.json', report)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--qemu', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--afl-bin', type=Path)
    parser.add_argument('--executions', type=int, default=32)
    args = parser.parse_args()
    result = verify(**vars(args))
    print(json.dumps(result, indent=2))
    return 0 if result['status'] == 'passed' else 2 if result['status'] == 'blocked_environment' else 1


if __name__ == '__main__':
    raise SystemExit(main())
