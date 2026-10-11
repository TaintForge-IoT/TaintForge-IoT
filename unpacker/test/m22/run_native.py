"""Independent native regression checks for the committed M2.2 capture path."""
from pathlib import Path
import json
import os
import shlex
import subprocess
import sys


def main(output):
    tests = Path(__file__).resolve().parent
    source = tests.parent
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    cc = os.environ.get('TF_IR_CC', 'gcc')
    rows = {}
    with (output / 'build.log').open('wb') as log:
        for name in ('provenance_differential', 'provenance_publication'):
            results = []
            for union, capture in ((0, 0), (1, 0), (1, 1)):
                executable = output / f'{name}-{union}-{capture}'
                subprocess.run([cc, '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-pthread',
                    f'-DTF_PROV_FASTPATH={union}', f'-DTF_CAPTURE_FASTPATH={capture}', '-I', str(source),
                    str(source / 'provenance.c'), str(tests / (name + '.c')), '-o', str(executable)],
                    check=True, stdout=log, stderr=subprocess.STDOUT)
                data = subprocess.check_output([str(executable)], timeout=60, text=True)
                (output / f'{name}-{union}-{capture}.jsonl').write_text(data)
                results.append([json.loads(line) for line in data.splitlines()])
            fields = ('cap', 'digest', 'sets', 'labels', 'truncations', 'registry_digest')
            if any(len(r) != len(results[0]) for r in results):
                raise RuntimeError('Native oracle row count differs: ' + name)
            for a, b, c in zip(*results):
                keys = fields if name == 'provenance_differential' else tuple(a)
                if any(a[k] != b[k] or b[k] != c[k] for k in keys):
                    raise RuntimeError('Native semantics differ: ' + name)
            rows[name] = dict(status='PASS', runs=results)
        flags = shlex.split(os.environ.get('TF_PLUGIN_CPPFLAGS') or
                            subprocess.check_output(['pkg-config', '--cflags', 'glib-2.0', 'capstone'], text=True))
        executable = output / 'aux-slot-ownership'
        subprocess.run([cc, '-std=gnu11', '-O2', '-Wall', '-Wextra', '-Werror',
            '-ffunction-sections', '-fdata-sections', '-Wl,--gc-sections', '-I', str(source), *flags,
            str(source / 'aux_trace.c'), str(tests / 'aux_slot_ownership.c'), '-o', str(executable)],
            check=True, stdout=log, stderr=subprocess.STDOUT)
        rows['aux_slot_ownership'] = json.loads(subprocess.check_output([str(executable)], timeout=30, text=True))
        executable = output / 'runtime-periodic'
        libs = shlex.split(os.environ.get('TF_PLUGIN_LIBS') or
                          subprocess.check_output(['pkg-config', '--libs', 'glib-2.0'], text=True))
        subprocess.run([cc, '-std=gnu11', '-O2', '-Wall', '-Wextra', '-Werror', '-I', str(source), *flags,
            str(source / 'runtime_diag.c'), str(tests / 'runtime_periodic.c'), *libs, '-o', str(executable)],
            check=True, stdout=log, stderr=subprocess.STDOUT)
        rows['runtime_periodic'] = json.loads(subprocess.check_output([str(executable)], timeout=10, text=True))
        with subprocess.Popen([str(executable), 'killed'], stdout=subprocess.PIPE, stderr=subprocess.PIPE) as child:
            try:
                child.communicate(timeout=.25)
                raise RuntimeError('Periodic profile control exited early')
            except subprocess.TimeoutExpired:
                child.kill()
                out, err = child.communicate(timeout=10)
                (output / 'killed.stderr').write_bytes(err)
                profiles = [line for line in err.splitlines() if b'[RUNTIME-PROFILE]' in line]
                if child.returncode != -9 or len(profiles) < 2:
                    raise RuntimeError('Periodic profile did not survive SIGKILL')
    (output / 'result.json').write_text(json.dumps(dict(status='PASS', controls=rows), indent=2, sort_keys=True) + '\n')
    print('PASS M2.2 native: exact root members/IDs/PARTIAL flags, concurrent publication, auxiliary ownership and periodic profile')


if __name__ == '__main__':
    if len(sys.argv) != 2:
        raise SystemExit('Usage: run_native.py OUTPUT_DIRECTORY')
    main(sys.argv[1])
