"""Bind a bounded native flags calibration to a warm AFL preparation."""
from pathlib import Path
import shutil
import tempfile

from . import afl_file as f, capsule_strict as strict

SYMBOLS = {'qemu_plugin_tf_warm_configure', 'qemu_plugin_tf_warm_arm',
           'qemu_plugin_tf_warm_abi2', 'qemu_plugin_tf_warm_abi3',
           'qemu_plugin_tf_warm_set_input_gate'}
PROFILE = 'warm-afl-flags-preparation-v1'


def require_backend(qemu):
    symbols = f.p.command('nm', '-D', '--defined-only', Path(qemu))
    exported = {line.split()[-1] for line in symbols.splitlines() if line.split()}
    f.p.require(SYMBOLS <= exported, 'Warm AFL requires QEMU ABI 3 with the input gate')


def calibration_ok(directory, *, qemu, plugin):
    """Check copied evidence by content; original temporary paths are diagnostic."""
    directory = Path(directory)
    report = f.read_json(directory/'calibration.json')
    summary = f.read_json(directory/'probe/summary.json')
    f.p.require(isinstance(report, dict) and isinstance(summary, dict), 'Invalid flags calibration records')
    receipt = directory/'probe/flags.receipt'
    qemu_sha, plugin_sha = strict.digest(qemu), strict.digest(plugin)
    strict.read_receipt(receipt, qemu_sha)
    f.p.require(type(report.get('schema')) is int and report['schema'] == 1 and
                report.get('status') == 'passed' and
                report.get('scope') == 'bounded_i386_eflags_observations' and
                report.get('qemu_sha256') == qemu_sha and report.get('plugin_sha256') == plugin_sha and
                report.get('receipt_sha256') == strict.digest(receipt) and
                report.get('probe_summary_sha256') == strict.digest(directory/'probe/summary.json') and
                report.get('universal_equivalence') is False and report.get('probe') == summary,
                'Flags calibration does not match the selected runtime')
    f.p.require(type(summary.get('schema_version')) is int and summary['schema_version'] == 1 and
                summary.get('status') == 'PASS_QEMU_PUSHF_BOUNDARY_PROBE' and
                summary.get('artifacts_unchanged') is True and summary.get('errors') == [] and
                summary.get('receipt_sha256') == strict.digest(receipt) and
                isinstance(summary.get('runs'), dict) and set(summary['runs']) == {'normal', 'single'},
                'Incomplete flags calibration evidence')
    for run in summary['runs'].values():
        f.p.require(isinstance(run, dict) and type(run.get('checked')) is int and run['checked'] == 32 and
                    type(run.get('exit')) is int and run['exit'] == 0 and
                    run.get('valid') is True and run.get('mismatches') == [],
                    'Flags calibration has incomplete or mismatched observations')
    return {'qemu_sha256': qemu_sha, 'plugin_sha256': plugin_sha,
            'receipt_sha256': strict.digest(receipt),
            'calibration_sha256': strict.digest(directory/'calibration.json'),
            'probe_summary_sha256': strict.digest(directory/'probe/summary.json'),
            'normal_checked': 32, 'single_checked': 32, 'universal_equivalence': False}


def prepare_campaign(out, *, binary, qemu, plugin, guest_path, seeds, max_input=4096,
                     analysis_policy='strict', flags_receipt=None, ir_start=None, **limits):
    """Strict CLI preparations calibrate when no matching receipt was supplied."""
    from . import afl_warm
    from .analysis_quality import policy
    policy(analysis_policy)
    out = Path(out).expanduser().absolute()
    f.p.require(not out.exists() and not out.is_symlink(), 'A new campaign directory is required')
    require_backend(qemu)
    options = dict(binary=binary, qemu=qemu, plugin=plugin, guest_path=guest_path,
                   seeds=seeds, max_input=max_input, analysis_policy=analysis_policy,
                   ir_start=ir_start, **limits)
    if flags_receipt is not None:
        strict.read_receipt(flags_receipt, strict.digest(qemu))
        return afl_warm.prepare_campaign(out, flags_receipt=flags_receipt, **options)
    if analysis_policy == 'research':
        return afl_warm.prepare_campaign(out, **options)
    out.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='tf-flags-', dir=out.parent) as temporary:
        calibration = Path(temporary)/'calibration'
        try:
            receipt = strict.calibration(qemu, plugin, calibration)
            checked = calibration_ok(calibration, qemu=qemu, plugin=plugin)
            manifest = afl_warm.prepare_campaign(out, flags_receipt=receipt, **options)
        except BaseException as error:
            # Retain bounded calibration diagnostics even if preparation failed.
            if calibration.is_dir():
                try:
                    out.mkdir(parents=True, exist_ok=True)
                    shutil.copytree(calibration, out/'flags-calibration', dirs_exist_ok=True)
                except OSError as diagnostic_error:
                    error.add_note('Could not retain calibration diagnostics: '+str(diagnostic_error))
            raise
        destination = out/'flags-calibration'
        shutil.copytree(calibration, destination)
        copied = calibration_ok(destination, qemu=qemu, plugin=plugin)
        f.p.require(copied == checked, 'Flags calibration changed during preparation')
        manifest['flags_calibration'] = {'schema': 1, 'profile': PROFILE,
            'directory': 'flags-calibration', 'status': 'passed', **checked}
        for path in sorted(destination.rglob('*')):
            if path.is_file():
                f.p.require(not path.is_symlink(), 'Symlink in flags calibration evidence')
                manifest['assets'][str(path)] = strict.digest(path)
        f.atomic_json(out/'campaign.json', manifest)
        return manifest
