import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import stat
import subprocess

PROJECT = Path(__file__).resolve().parents[1]
HERE = PROJECT/'experiments/strict_capsule'
RECEIPT = 'flags/eflags.receipt'
HANDOFF_LOOPS = 20000000


def require(value, message):
    if not value:
        raise ValueError(message)


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def receipt_bytes(qemu_sha256):
    return ('TAINTFORGE_X86_FLAGS_V1\nqemu_sha256='+qemu_sha256+
            '\nprobe=pushf-boundary-v1\ntarget=i386-linux-user\nnormal_checked=32\n'
            'single_checked=32\nmismatches=0\n').encode()


def read_receipt(path, qemu_sha256):
    from .phase1_runtime import _regular
    path = Path(path)
    _regular(path, 4096)
    data = path.read_bytes()
    require(data == receipt_bytes(qemu_sha256), 'EFLAGS receipt does not match the selected QEMU')
    return data


def save(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True)+'\n')


def calibration(qemu, plugin, out):
    from .phase1_runtime import Phase1Runtime
    from experiments.strict_capsule.flags_probe import check_flags
    qemu, plugin = (Path(p).expanduser().resolve(strict=True) for p in (qemu, plugin))
    out = Path(out).absolute()
    require(not out.exists(), 'Calibration output must be new')
    out.mkdir(parents=True)
    runtime = Phase1Runtime.load(plugin)
    runtime.validate_qemu(qemu)
    header = PROJECT/'experiments/execution_capsule_probe/vendor/qemu-plugin.h'
    manifest = json.loads(runtime.manifest.read_text())
    require(manifest['build_inputs']['qemu_header_sha256'] == digest(header),
            'Phase 1 build and calibration SDK differ')
    identities = {str(p): digest(p) for p in (qemu, plugin, runtime.manifest, header,
        HERE/'flags.S', HERE/'flags_observer.c', HERE/'flags_probe.py',
        PROJECT/'unpacker/test/qemu_plugin_compat.h')}
    report = {'schema': 1, 'status': 'failed', 'scope': 'bounded_i386_eflags_observations',
              'sources': identities, 'qemu_sha256': digest(qemu), 'plugin_sha256': digest(plugin),
              'universal_equivalence': False}
    try:
        cflags = shlex.split(subprocess.check_output(['pkg-config', '--cflags', 'glib-2.0'], text=True))
        libs = shlex.split(subprocess.check_output(['pkg-config', '--libs', 'glib-2.0'], text=True))
        observer, obj, binary = out/'flags.so', out/'flags.o', out/'flags-i386'
        commands = [
            [os.environ.get('TF_IR_CC', 'gcc'), '-std=gnu11', '-O2', '-Wall', '-Wextra', '-Werror',
             '-fPIC', '-shared', '-I', str(header.parent), '-I', str(PROJECT/'unpacker/test'),
             *cflags, str(HERE/'flags_observer.c'), '-o', str(observer), *libs],
            ['as', '--32', str(HERE/'flags.S'), '-o', str(obj)],
            ['ld', '-m', 'elf_i386', '-z', 'noexecstack', str(obj), '-o', str(binary)]]
        save(out/'commands.json', commands)
        with (out/'build.log').open('wb') as log:
            for command in commands:
                subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, check=True, timeout=120)
        checked = check_flags(qemu, observer, binary, out/'probe')
        require(checked['status'] == 'PASS_QEMU_PUSHF_BOUNDARY_PROBE' and
                checked['artifacts_unchanged'] is True, 'Native EFLAGS calibration failed')
        receipt = out/'probe/flags.receipt'
        read_receipt(receipt, report['qemu_sha256'])
        require(all(digest(path) == sha for path, sha in identities.items()),
                'Calibration source or runtime changed')
        report.update(status='passed', receipt=str(receipt), receipt_sha256=digest(receipt),
                      probe_summary_sha256=digest(out/'probe/summary.json'), probe=checked)
        return receipt
    except BaseException as exc:
        (out/'probe/flags.receipt').unlink(missing_ok=True)
        report['error'] = type(exc).__name__+': '+str(exc)
        raise
    finally:
        save(out/'calibration.json', report)


def build_fixture(out, *, negative=False, handoff_loops=HANDOFF_LOOPS):
    from .input_retirement import inspect_input
    require(type(handoff_loops) is int and 1 <= handoff_loops <= HANDOFF_LOOPS,
            'Invalid strict fixture work limit')
    out = Path(out).absolute()
    out.mkdir(parents=True, exist_ok=False)
    obj, binary = out/'guest.o', out/'guest-i386'
    subprocess.run(['as', '--32', '--defsym', 'STRICT_NEGATIVE='+str(int(negative)),
                    '--defsym', 'STRICT_HANDOFF_LOOPS='+str(handoff_loops),
                    str(HERE/'guest.S'), '-o', str(obj)], check=True)
    subprocess.run(['ld', '-m', 'elf_i386', '-z', 'noexecstack', '--build-id=none',
                    str(obj), '-o', str(binary)], check=True)
    symbols = subprocess.check_output(['nm', '-P', str(binary)], text=True)
    addresses = {}
    for line in symbols.splitlines():
        name, kind, *rest = line.split()
        if name in {'strict_ir_start', 'payload_page', 'payload_source', 'payload_end', 'target_word'}:
            addresses[name] = int(rest[0], 16)
    require(set(addresses) == {'strict_ir_start', 'payload_page', 'payload_source', 'payload_end', 'target_word'},
            'Missing strict fixture symbols')
    require(0 < addresses['payload_end']-addresses['payload_source'] <= 512, 'Strict payload exceeds copied bytes')
    subprocess.run(['strip', '--strip-all', str(binary)], check=True)
    result = {'path': str(binary), 'input': inspect_input(binary), 'negative': negative,
              'ir_start': addresses['strict_ir_start'], 'expected_oep': addresses['payload_page'],
              'target_source': 'main_elf_file_bytes', 'target_word_address': addresses['target_word'],
              'handoff_work_iterations': handoff_loops,
              'source_sha256': digest(HERE/'guest.S')}
    save(out/'fixture.json', result)
    return result


def failure_details(root, error):
    from .phase1_runtime import read_json
    root = Path(root)
    run = root/'warm-session/iterations/0000/run'
    records, read_errors = {}, {}
    for name, path in [('session', root/'warm-session-result.json'),
                       ('capsule', run/'config/capsule_result.json'),
                       ('executor', root/'warm-executor.json'),
                       ('retirement', run/'logs/capsule/phase1-retirement/retirement.json')]:
        try:
            records[name] = read_json(path, 1024*1024)
        except (OSError, ValueError, RuntimeError) as exc:
            read_errors[name] = type(exc).__name__+': '+str(exc)
    capsule, session = records.get('capsule', {}), records.get('session', {})
    retirement = records.get('retirement', {})
    verification_error = capsule.get('error') or session.get('error') or records.get('executor', {}).get('error')
    abort = None
    qemu_log = run/'logs/qemu_strace.log'
    try:
        fd = os.open(qemu_log, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as stream:
            info = os.fstat(stream.fileno())
            require(stat.S_ISREG(info.st_mode), 'QEMU log must be a regular file')
            offset = max(0, info.st_size-64*1024)
            stream.seek(offset)
            tail = stream.read(64*1024)
        if offset:
            tail = tail.partition(b'\n')[2]
        matches = re.findall(rb'^TF_WARM_ABORT reason=([a-z0-9_]{1,128})$', tail, re.MULTILINE)
        if matches:
            abort = matches[-1].decode('ascii')
    except (OSError, ValueError) as exc:
        read_errors['qemu_log'] = type(exc).__name__+': '+str(exc)
    quality = next((value for value in (capsule.get('analysis_quality'), session.get('analysis_quality'),
                                        retirement.get('analysis_quality')) if value is not None), None)
    reason = 'TF_WARM_ABORT reason='+abort if abort else verification_error or error
    return {'pipeline_error': error, 'reason': str(reason), 'verification_error': verification_error,
            'warm_abort': abort, 'read_errors': read_errors, 'analysis_quality': quality,
            'retirement_status': retirement.get('status'), 'permit_sent': retirement.get('permit_sent'),
            'worker_log': str(root/'warm-worker.log'), 'qemu_log': str(qemu_log)}


def verify_positive(root, *, minimum, expected_oep):
    from . import afl_file as f, afl_capsule
    from .afl_evidence import completed_cases, child_report
    from .retirement_evidence import verify
    manifest = f.verify_campaign(root)
    session = f.read_json(root/'warm-session-result.json')
    capsule = session['capsule']
    require(manifest['status'] == 'completed' and capsule['status'] == 'passed',
            'Strict campaign did not complete')
    ready = f.read_json(root/'warm-ready.json')
    runtime = f.read_json(Path(manifest['launch']['template_run_dir'])/'config/runtime.json')
    admitted = afl_capsule.verify_ready(ready, runtime['capsule']['analysis_policy'])
    decision = admitted['analysis_quality']
    require(capsule.get('afl_checkpoint') == admitted and capsule.get('analysis_quality') == decision,
            'Warm readiness does not match final capsule evidence')
    run = root/'warm-session/iterations/0000/run'
    checked = verify(run/'retirement-evidence',
                     expected_sha256=capsule['portable_evidence']['manifest_sha256'])
    require(checked['attempt_outcome'] == 'passed' and checked['analysis_quality'] == decision,
            'Strict decision does not match independently verified export')
    require(decision['status'] == 'accepted' and decision['policy']['mode'] == 'strict' and
            not decision['limitations'] and not decision['rejection_reasons'], 'Strict quality admission failed')
    require(decision['facts']['flags_verified'] is True and
            decision['facts']['candidate']['dse_verdict'] == 'CONFIRMED', 'Missing strict native evidence')
    retirement = capsule['phase1_retirement']
    require(retirement['phase1_retired'] is True and retirement['verdict']['oep'] == expected_oep and
            capsule['resources']['tree_empty'] is True and manifest['phase1_runs'] == 1,
            'Strict retirement, OEP oracle or service cleanup failed')
    cases = completed_cases(root, manifest)
    require(len(cases) >= minimum, 'Too few strict warm executions')
    children = set()
    for case in cases:
        analysis = child_report(case, manifest['max_input'])
        result = f.read_json(case/'result.json')
        require(result['guest_exit'] == 0 and result['outcome']['kind'] == 'normal',
                'Strict fixture child did not complete normally')
        require(analysis['phase1_runs'] == 1, 'Strict child repeated Phase 1')
        children.add(analysis['child_namespace_pid'])
    require(len(children) == len(cases), 'Strict children reused a process identity')
    return {'status': 'passed', 'policy': 'strict', 'children': len(cases), 'phase1_runs': 1,
            'analysis_quality': decision, 'retirement_verified': True, 'tree_empty': True}


def verify_negative(root):
    from .phase1_runtime import read_json
    from .retirement_evidence import verify
    require(not (root/'warm-ready.json').exists() and not list((root/'cases').glob('*')),
            'Rejected analysis reached warm readiness or a child')
    require(not (root/'afl').exists(), 'AFL started before strict rejection')
    from .afl_file import verify_campaign
    campaign = verify_campaign(root)
    require('afl_started_ns' not in campaign and campaign.get('cases', 0) == 0,
            'Rejected strict campaign admitted AFL work')
    run = root/'warm-session/iterations/0000/run'
    capsule = read_json(run/'config/capsule_result.json')
    require(capsule['status'] == 'failed' and capsule['resources']['tree_empty'] is True,
            'Strict rejection did not fail the attempt or clean the service')
    proof = capsule['portable_evidence']
    checked = verify(run/'retirement-evidence', expected_sha256=proof['manifest_sha256'])
    decision = checked['analysis_quality']
    require(checked['attempt_outcome'] == 'failed' and decision['status'] == 'rejected' and
            decision['policy']['mode'] == 'strict' and decision['facts']['flags_verified'] is True and
            decision['facts']['candidate']['dse_verdict'] == 'UNKNOWN' and
            'unknown_candidate_analysis' in decision['rejection_reasons'], 'Unexpected strict rejection reason')
    facts = decision['facts']
    require(facts['candidate']['dse_reason'] == 'NONUNIQUE_TARGET' and
            facts['trace_incomplete'] == facts['trace_dropped'] == facts['ir_unknown'] == 0 and
            facts['ir_errors'] == facts['ir_mismatches'] == 0 and facts['ir']['checks'] > 0,
            'Negative fixture failed for a reason other than its nonunique target')
    permit = read_json(run/'logs/capsule/phase1-retirement/retirement.json')
    require(permit['status'] == 'analysis_rejected' and permit['permit_sent'] is False and
            permit['permit'] == 'DENY\n' and capsule['phase1_retirement']['phase1_retired'] is False,
            'Strict rejection crossed the retirement permit boundary')
    return {'status': 'passed', 'analysis_quality': decision, 'afl_started': False,
            'warm_ready': False, 'permit_sent': False, 'tree_empty': True}
