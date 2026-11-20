"""Exercise the SHRD, stdio, mmap2 and SSE2 forms in the corpus."""
from base64 import b64encode
import json
from pathlib import Path
import subprocess

from taintforge_env.phase1_runtime import Phase1Run
from unpacker import unpack
from unpacker.external_worker import require
from unpacker.unpack_process import compare_results, run_process

ROOT = Path(__file__).resolve().parent


def observe(qemu, runtime, flags, binary, work, start, stop, case, extra):
    work.mkdir()
    run = Phase1Run(runtime, 'external-ir-fixture', 'attempt-1', case['id'], work / 'capture',
                    require_flags=True, flags_receipt=flags)
    options = ('tf-capture=exit', 'tf-max-capture-bytes=1048576', 'dse-check=off', 'runtime-log=summary',
               'ir-flat-memory=on', 'ir-observed-munmap=on', 'ir-observed-files=on',
               'ir-window=128', f'ir-start={start:#x}', f'ir-probe={stop:#x}')
    result = run_process([str(qemu), '-plugin', run.plugin_argument(extra=options + extra),
                          str(binary), *case['argv']], case, work / 'guest',
                         timeout=30, file_limit=8 * 1024**2, environment=unpack.controlled_environment())
    require(compare_results([result]) and result['returncode'] == 0 and result['stdout_bytes'] == 0,
            'Fixture guest behavior differs: ' + case['id'])
    phase = run.verify()
    events = run.events()
    analysis, = (event['data'] for event in events if event['event_type'] == 'analysis_summary')
    require(phase['runtime_observed'] is True and analysis['flags_verified'] is True
            and not any(event['event_type'] in ('profile_lost', 'data_loss') for event in events),
            'Fixture capture is incomplete: ' + case['id'])
    raw = unpack.regular(run.paths['ir'], 1024**2, 'Fixture IR journal').read_bytes()
    check, summary = (json.loads(line) for line in raw.splitlines())
    require(raw.endswith(b'\n') and check['event'] == 'check' and check['kind'] == 'probe'
            and check['trigger']['pc'] == stop and check['trigger']['flags_trusted'] is True
            and check['requested_first_seq'] == check['first_seq']
            and summary['checks'] == 1 and summary['observed_files'] is True
            and summary['observed_stdio'] is ('ir-observed-stdio=on' in extra)
            and summary['sse2_dwords'] is ('ir-sse2-dwords=on' in extra),
            'Unexpected fixture IR profile: ' + case['id'])
    return check


def check(qemu, runtime, flags, work):
    work.mkdir()
    binary, obj = work / 'external-ir.elf', work / 'external-ir.o'
    subprocess.run(['as', '--32', ROOT / 'fixtures.S', '-o', obj], check=True, timeout=30)
    subprocess.run(['ld', '-m', 'elf_i386', '-z', 'noexecstack', obj, '-o', binary], check=True, timeout=30)
    symbols = subprocess.check_output(['nm', '-n', binary], text=True, timeout=15)
    labels = {name: int(address, 16) for address, _, name in map(str.split, symbols.splitlines())}
    data = bytes(range(20))
    stdio = ('ir-observed-stdio=on',)
    movq = ('ir-xmm-movq=on',)
    sse2 = movq + ('ir-sse2-dwords=on',)
    cases = (
        ('shrd', 's', 'shift_start', 'shift_done', b'', ()),
        ('read', 'r', 'read_start', 'read_done', data, stdio),
        ('read-disabled', 'r', 'read_start', 'read_done', data, ()),
        ('read-over-limit', 'l', 'read_start', 'read_done', data + b'\xee' * 237, stdio),
        ('close', 'c', 'close_start', 'close_done', b'', stdio),
        ('close-disabled', 'c', 'close_start', 'close_done', b'', ()),
        ('close-failed', 'c', 'close_again', 'close_again_done', b'', stdio),
        ('mmap', 'm', 'mmap_start', 'mmap_done', b'', ()),
        ('xmm', 'x', 'xmm_start', 'xmm_done', b'', sse2),
        ('xmm-disabled', 'x', 'xmm_start', 'xmm_done', b'', movq),
        ('xmm-unbound', 'x', 'xmm_unpack', 'xmm_done', b'', sse2),
    )
    results = {
        name: observe(qemu, runtime, flags, binary, work / name, labels[start], labels[stop],
                      dict(id=name, argv=[arg], stdin_base64=b64encode(payload).decode()), options)
        for name, arg, start, stop, payload, options in cases
    }
    for name in ('shrd', 'read', 'close', 'mmap', 'xmm'):
        row = results[name]
        require(row['status'] == 'MATCH' and row['selected_steps'] == row['lifted_steps']
                and row['unknown_observations'] == 0, 'Complete fixture did not match: ' + name)
    for name, label, reason in (
        ('read-disabled', 'read_start', None),
        ('read-over-limit', 'read_start', 'regular_stdio_transition_unverified'),
        ('close-disabled', 'close_start', 'close_file_object_missing'),
        ('close-failed', 'close_again', 'close_not_successful'),
        ('xmm-disabled', 'xmm_start', None),
        ('xmm-unbound', 'xmm_unpack', 'punpckldq_xmm_source_before_window'),
    ):
        row = results[name]
        require(row['status'] == 'UNKNOWN' and row['stop']['pc'] == labels[label]
                and row['environment']['reason'] == reason,
                'Unsupported fixture stopped elsewhere: ' + name)
    row = results['read']
    io = row['environment']['stdio']
    require((io['read_count'], io['read_bytes'], io['read_requested'], io['read_returned']) == (2, 20, 8192, 20)
            and io['read_seq'] == row['first_seq'] and io['read_pc'] == labels['read_start']
            and io['read_address'] == labels['buffer'], 'Regular stdin and EOF evidence differs')
    row = results['close']
    io = row['environment']['stdio']
    require(io['close_seq'] == row['first_seq'] and io['close_pc'] == labels['close_start'],
            'Regular stdout close evidence differs')
    require(results['mmap']['environment']['files']['anonymous_maps'] == 1,
            'Anonymous mmap2 did not map one zero-initialized range')
    row = results['xmm']
    xmm = row['environment']['sse2_dwords']
    require(xmm['first_seq'] == row['first_seq'] and xmm['first_pc'] == labels['xmm_start']
            and xmm['movd_count'] == xmm['punpckldq_count'] == row['environment']['movq']['stores'] == 2,
            'SSE2 fixture evidence differs')
    return results
