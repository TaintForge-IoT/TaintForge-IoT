#!/usr/bin/env python3
"""Install the warm-fork ABI and x86 plugin EFLAGS fix in pinned QEMU 11.0.1."""
import argparse
import hashlib
import os
from pathlib import Path
import shutil
import tempfile

HERE = Path(__file__).resolve().parent
BASELINES = {
    'linux-user/syscall.c': 'c327a29ff382a1ee10528a9354b3fded934f9497f565c92d620ab5546da4fbe8',
    'linux-user/syscall_defs.h': '850be5489422d063ea1d213f9a31b66130b4f72445b1bc893b01d750fccbb359',
    'linux-user/strace.c': '8c470c56124e23606edd089606d69d778d7d1db10db2e91e9c82e602f50bd592',
    'include/plugins/qemu-plugin.h': '9592f519d7344b1e38b0123b92c28c4e688faedf41263984910353736bb0b7be',
    'target/i386/cpu.h': 'e4161376ce7f839b51aac81abb6b01830593d0729dfd7a7e27a4789259c72c63',
    'target/i386/gdbstub.c': '19e432e4fdaf50212a8c66c0cc3770960380b80d364bc165d1c6d55a4da9f4b2',
    'target/i386/tcg/tcg-cpu.c': '7ae34b79e3d7d0f6448cfc213830b31a0d5a33adf975c41e9bcac913658d568e',
    'target/i386/tcg/translate.c': '491e6023ddaf370a0428b44558ec6a50977d756fda0837fac9bc092970a25c5a',
}
# Backport of upstream e7ae490e0cf8c712fad6e39984a57a14e9cc400f.
# Keep this host execution marker outside migratable CPUX86State.
EFLAGS_REPLACEMENTS = {
    'target/i386/cpu.h': ((b'    CPUX86State env;\n',
        b'    CPUX86State env;\n    bool eflags_in_tcg;\n'),),
    'target/i386/gdbstub.c': ((b'        case IDX_FLAGS_REG:\n'
        b'            return gdb_get_reg32(mem_buf, env->eflags);\n',
        b'        case IDX_FLAGS_REG:\n'
        b'            if (cpu->eflags_in_tcg) {\n'
        b'                return gdb_get_reg32(mem_buf, cpu_compute_eflags(env));\n'
        b'            }\n'
        b'            return gdb_get_reg32(mem_buf, env->eflags);\n'),),
    'target/i386/tcg/tcg-cpu.c': (
        (b'    env->eflags &= ~(DF_MASK | CC_O | CC_S | CC_Z | CC_A | CC_P | CC_C);\n',
         b'    env->eflags &= ~(DF_MASK | CC_O | CC_S | CC_Z | CC_A | CC_P | CC_C);\n'
         b'    cpu->eflags_in_tcg = true;\n'),
        (b'    env->eflags = cpu_compute_eflags(env);\n',
         b'    env->eflags = cpu_compute_eflags(env);\n    cpu->eflags_in_tcg = false;\n')),
    'target/i386/tcg/translate.c': ((b'    dc->prev_insn_start = dc->base.insn_start;\n',
        b'    if (dcbase->plugin_enabled) {\n'
        b'        gen_update_cc_op(dc);\n'
        b'    }\n'
        b'    dc->prev_insn_start = dc->base.insn_start;\n'),),
}
# The previously delivered standalone flags patch is admitted exactly, then
# upgraded to the upstream placement and callback ordering above.
LEGACY_EFLAGS_REPLACEMENTS = {
    'target/i386/cpu.h': ((b'                        stored elsewhere */\n',
        b'                        stored elsewhere */\n'
        b'    bool eflags_in_tcg; /* CC and DF currently use the TCG representation. */\n'),),
    'target/i386/gdbstub.c': ((b'            return gdb_get_reg32(mem_buf, env->eflags);\n',
        b'            return gdb_get_reg32(mem_buf, env->eflags_in_tcg ?\n'
        b'                                 cpu_compute_eflags(env) : env->eflags);\n'),),
    'target/i386/tcg/tcg-cpu.c': (
        (b'    env->eflags &= ~(DF_MASK | CC_O | CC_S | CC_Z | CC_A | CC_P | CC_C);\n',
         b'    env->eflags &= ~(DF_MASK | CC_O | CC_S | CC_Z | CC_A | CC_P | CC_C);\n'
         b'    env->eflags_in_tcg = true;\n'),
        (b'    env->eflags = cpu_compute_eflags(env);\n',
         b'    env->eflags = cpu_compute_eflags(env);\n    env->eflags_in_tcg = false;\n')),
    'target/i386/tcg/translate.c': ((b'    tcg_gen_insn_start(pc_arg, dc->cc_op, 0);\n',
        b'    if (dc->base.plugin_enabled) {\n'
        b'        gen_update_cc_op(dc);\n'
        b'    }\n'
        b'    tcg_gen_insn_start(pc_arg, dc->cc_op, 0);\n'),),
}
INCLUDE = b'#include "tf-warm.h"\n\n'
HOOK = b'    tf_warm_syscall(num, arg1, arg2);\n'
DECLARATIONS = b'''
/* Private TaintForge warm-fork ABI 1, linux-user only. */
QEMU_PLUGIN_API
int qemu_plugin_tf_warm_configure(const char *input, const char *endpoint,
 uint64_t max_rss_mib, int observer_fd, void (*prepare)(void), void (*on_child)(void));
QEMU_PLUGIN_API
void qemu_plugin_tf_warm_arm(void);
'''
API_END = b'#ifdef __cplusplus\n} /* extern "C" */\n#endif\n\n#endif /* QEMU_QEMU_PLUGIN_H */\n'


def target_mask(source):
    # Preserve QEMU's guest command mask independently of newer host flags.
    return source.replace(b'FUTEX_CMD_MASK', b'TARGET_FUTEX_CMD_MASK')


def warm_syscall(source):
    anchor = b'static void record_syscall_start(CPUState *cpu, int num,'
    needle = b'                         arg2, arg3, arg4, arg5, arg6, arg7, arg8);\n\n    if (unlikely(qemu_loglevel_mask(LOG_STRACE)))'
    if source.count(anchor) != 1 or source.count(needle) != 1:
        raise ValueError('Syscall insertion point changed')
    source = source.replace(anchor, INCLUDE + anchor, 1)
    return source.replace(needle, needle.replace(b'\n\n    if', b'\n' + HOOK + b'\n    if'), 1)


def read_regular(root, name):
    path = root
    for part in Path(name).parts:
        path = path / part
        if path.is_symlink():
            raise ValueError('Refusing symlink: ' + str(path))
    if path.exists() and not path.is_file():
        raise ValueError('Not a regular file: ' + str(path))
    return path.read_bytes() if path.exists() else None


def flags_source(name, original):
    baseline = original
    for replacements in (EFLAGS_REPLACEMENTS[name], LEGACY_EFLAGS_REPLACEMENTS[name]):
        for before, after in reversed(replacements):
            baseline = baseline.replace(after, before)
    variants = []
    for replacements in (EFLAGS_REPLACEMENTS[name], LEGACY_EFLAGS_REPLACEMENTS[name]):
        variant = baseline
        for before, after in replacements:
            if variant.count(before) != 1:
                raise ValueError('EFLAGS insertion point changed: ' + name)
            variant = variant.replace(before, after, 1)
        variants.append(variant)
    return baseline, variants[0], (baseline, *variants)


def changes(root):
    root = Path(root).resolve(strict=True)
    version = read_regular(root, 'VERSION')
    if version is None or version.strip() != b'11.0.1':
        raise ValueError('QEMU 11.0.1 source required')
    pending = []
    for name, expected in BASELINES.items():
        original = read_regular(root, name)
        if original is None:
            raise ValueError('Missing QEMU source: ' + name)
        if name in EFLAGS_REPLACEMENTS:
            baseline, desired, accepted = flags_source(name, original)
        elif name == 'include/plugins/qemu-plugin.h':
            baseline = original.replace(DECLARATIONS, b'')
            if baseline.count(API_END) != 1:
                raise ValueError('Plugin API insertion point changed')
            desired = baseline.replace(API_END, DECLARATIONS + API_END, 1)
            accepted = (baseline, baseline + DECLARATIONS, desired)
        else:
            baseline = original.replace(b'TARGET_FUTEX_CMD_MASK', b'FUTEX_CMD_MASK')
            if name == 'linux-user/syscall.c':
                baseline = baseline.replace(INCLUDE, b'').replace(HOOK, b'')
                legacy = warm_syscall(baseline)
                desired = target_mask(legacy)
                accepted = (baseline, legacy, desired)
            else:
                desired = target_mask(baseline)
                accepted = (baseline, desired)
        if hashlib.sha256(baseline).hexdigest() != expected or original not in accepted:
            raise ValueError('QEMU source differs from the supported baseline: ' + name)
        if original != desired:
            pending.append((root / name, original, desired))
    backend = 'linux-user/tf-warm.h'
    original = read_regular(root, backend)
    desired = (HERE / 'tf-warm.h').read_bytes()
    if original is not None and original != desired:
        raise ValueError('Existing warm backend differs; refusing to overwrite')
    if original != desired:
        pending.append((root / backend, original, desired))
    return pending


def atomic_write(path, data, mode):
    fd, temporary = tempfile.mkstemp(prefix='.' + path.name, dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def install(root, check=False):
    root = Path(root).resolve(strict=True)
    pending = changes(root)
    if check or not pending:
        return ('compatible' if pending else 'already installed'), None
    backup_root = root / '.taintforge-warm-backups'
    if backup_root.is_symlink():
        raise ValueError('Refusing symlink: ' + str(backup_root))
    backup_root.mkdir(exist_ok=True)
    backup = Path(tempfile.mkdtemp(prefix='buildfix-', dir=backup_root))
    modes = {}
    for path, original, desired in pending:
        modes[path] = path.stat().st_mode & 0o777 if original is not None else 0o644
        if original is not None:
            saved = backup / path.relative_to(root)
            saved.parent.mkdir(parents=True, exist_ok=True)
            saved.write_bytes(original)
            shutil.copymode(path, saved)
    done = []
    try:
        for path, original, desired in pending:
            if read_regular(root, path.relative_to(root)) != original:
                raise ValueError('Concurrent modification: ' + str(path))
            atomic_write(path, desired, modes[path])
            done.append((path, original))
    except BaseException:
        for path, original in reversed(done):
            if original is None:
                path.unlink(missing_ok=True)
            else:
                atomic_write(path, original, modes[path])
        raise
    return 'installed', backup


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qemu-source', type=Path, required=True)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    try:
        status, backup = install(args.qemu_source, args.check)
    except (OSError, ValueError) as exc:
        parser.exit(2, str(exc) + '\n')
    print(status)
    if backup is not None:
        print('QEMU source backup: ' + str(backup))


if __name__ == '__main__':
    main()
