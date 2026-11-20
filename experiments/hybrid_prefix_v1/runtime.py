"""Build an experiment-specific Phase 1 without replacing the installed runtime."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

HERE = Path(__file__).resolve().parent
PROJECT = HERE.parents[1]


def require(value, message):
    if not value:
        raise RuntimeError(message)


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def save(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name('.' + path.name + '.pending')
    with temporary.open('w') as stream:
        json.dump(value, stream, indent=2, sort_keys=True, allow_nan=False)
        stream.write('\n')
    os.replace(temporary, path)


INSTALL_PAGE = '''static bool tf_hybrid_install_initial_page(void *context, uint64_t address, unsigned prot) {
    (void)context;
    gpointer key = (gpointer)(uintptr_t)address;
    if (g_hash_table_lookup(pages, key)) return false;
    page_t *page = g_new0(page_t, 1);
    page->prot = (int)prot;
    g_hash_table_insert(pages, key, page);
    return true;
}

'''


def patched_source(source):
    include = '#include "elf_image.h"'
    function = 'static bool seed_main_file_taint(const TfElfImage *image) {'
    call = '    if (!seed_main_file_taint(&image))\n'
    require(all(source.count(anchor) == 1 for anchor in (include, function, call)),
            'Phase 1 source differs at the initial-ELF mapping hooks; refusing an ambiguous patch')
    require('tf_hybrid_initial_pages' not in source, 'The experiment hook is already present')
    result = source.replace(include, include + '\n#include "hybrid_initial_pages.h"', 1)
    result = result.replace(function, INSTALL_PAGE + function, 1)
    result = result.replace(call,
        '    if (!tf_hybrid_initial_pages(&image, effective_page_size, NULL, tf_hybrid_install_initial_page))\n'
        '        return false;\n'
        '    fprintf(stderr, "[HYBRID-ELF-PAGES] initial PT_LOAD protections registered\\n");\n' + call, 1)
    return result


def patched_concolic_source(source):
    opening = '    if (num == 5 || num == 295) {\n        uint32_t flags ='
    returned = '    if (num == 5 || num == 295) {\n        struct stat st;'
    require(source.count(opening) == 1 and source.count(returned) == 1,
            'Concolic source differs at the file startup syscall hooks')
    source = source.replace(opening,
        '    if (num == 125) {\n'
        '        if (run->syscall_count || run->opened || args[0] > UINT32_MAX ||\n'
        '            args[1] > UINT32_MAX || (args[0] & 4095) || !args[1] ||\n'
        '            (args[1] & 4095) || args[0] + args[1] > (UINT64_C(1) << 32) ||\n'
        '            (args[2] & ~UINT64_C(7))) {\n'
        '            fail(run, "startup_mprotect_contract");\n'
        '            return;\n'
        '        }\n'
        '    } else if (num == 5 || num == 295) {\n        uint32_t flags =', 1)
    return source.replace(returned,
        '    if (num == 125) {\n'
        '        if (returned != 0) fail(run, "startup_mprotect_failed");\n'
        '    } else if (num == 5 || num == 295) {\n        struct stat st;', 1)


def build_plugin(directory, qemu_include):
    from taintforge_env.phase1_runtime import Phase1Runtime
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=False)
    source = directory / 'source'
    source.mkdir()
    original = PROJECT / 'unpacker/test'
    identities = {}
    for path in sorted(original.iterdir()):
        if path.is_file() and not path.is_symlink() and path.suffix in ('.c', '.h', '.py', '.sh'):
            identities[path.name] = sha(path)
            shutil.copy2(path, source / path.name)
    target = source / 'qemu_unpacker.c'
    target.write_text(patched_source(target.read_text()))
    concolic = source / 'ir_concolic.c'
    concolic.write_text(patched_concolic_source(concolic.read_text()))
    shutil.copy2(HERE / 'initial_pages.h', source / 'hybrid_initial_pages.h')
    include = Path(qemu_include).expanduser().resolve(strict=True)
    require((include / 'qemu-plugin.h').is_file(), 'The matching QEMU plugin header is missing')
    plugin = directory / 'libtaintforge_ir.so'
    command = ['bash', str(source / 'build_group7_4c1_plugin.sh'), str(source), str(plugin)]
    try:
        with (directory / 'build.log').open('wb') as log:
            subprocess.run(command, cwd=PROJECT, check=True, stdout=log, stderr=subprocess.STDOUT,
                           env=dict(os.environ, TF_QEMU_INCLUDE=str(include)))
    except subprocess.CalledProcessError as exc:
        tail = (directory / 'build.log').read_bytes()[-12000:].decode('utf-8', errors='replace')
        raise RuntimeError('Experiment plugin build failed; log: ' + str(directory / 'build.log') + '\n' + tail) from exc
    require(all(sha(original / name) == value for name, value in identities.items()),
            'The original Phase 1 sources changed during the experiment build')
    runtime = Phase1Runtime.load(plugin)
    save(directory / 'build.json', {'scope': 'experiment_copy_with_initial_PT_LOAD_page_protections',
        'plugin': str(plugin), 'plugin_sha256': runtime.plugin_sha256,
        'runtime_build_id': runtime.build_id, 'original_source_sha256': identities,
        'patched_source_sha256': sha(target), 'hook_sha256': sha(source / 'hybrid_initial_pages.h'),
        'patched_concolic_sha256': sha(concolic),
        'installed_runtime_replaced': False, 'project_Phase1_sources_modified': False})
    return plugin


def build_fixture(directory):
    from taintforge_env.input_retirement import inspect_input
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=False)
    source, obj, binary = (directory / name for name in ('guest.S', 'guest.o', 'guest-i386'))
    shutil.copy2(HERE / 'fixture.S', source)
    with (directory / 'build.log').open('wb') as log:
        subprocess.run(['as', '--32', str(source), '-o', str(obj)], check=True, stdout=log, stderr=log)
        subprocess.run(['ld', '-m', 'elf_i386', '-z', 'noexecstack', '--build-id=none',
                        str(obj), '-o', str(binary)], check=True, stdout=log, stderr=log)
    wanted = {'payload_source', 'payload_page', 'payload_end', 'branch_one', 'branch_two', 'hybrid_ir_start'}
    symbols = {}
    for line in subprocess.check_output(['nm', '-P', str(binary)], text=True).splitlines():
        name, kind, *values = line.split()
        if name in wanted:
            symbols[name] = int(values[0], 16)
    require(set(symbols) == wanted, 'The bundled fixture symbol layout changed')
    subprocess.run(['strip', '--strip-all', str(binary)], check=True, capture_output=True)
    metadata = {'binary_sha256': sha(binary), 'input': inspect_input(binary),
        'source_sha256': sha(HERE / 'fixture.S'), 'payload_page': symbols['payload_page'],
        'ir_start': symbols['hybrid_ir_start'],
        'second_branch_pc': symbols['payload_page'] + symbols['branch_two'] - symbols['payload_source']}
    save(directory / 'fixture.json', metadata)
    return binary, metadata
