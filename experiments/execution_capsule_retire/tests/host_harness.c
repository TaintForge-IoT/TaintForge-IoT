/* SPDX-License-Identifier: GPL-2.0-or-later
 * Mock scheduling only. dlopen/dlclose, mmap/mprotect/munmap and /proc are real.
 * This is NOT a QEMU safe-work or TCG cache-flush acceptance test.
 */
#define _GNU_SOURCE
#include <qemu-plugin.h>
#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

struct callback { qemu_plugin_vcpu_udata_cb_t fn; void *data; };
struct qemu_plugin_insn { uint64_t pc; unsigned int count; struct callback callbacks[2]; };
struct qemu_plugin_tb { struct qemu_plugin_insn insns[3]; };
static struct qemu_plugin_tb block = { .insns = {{.pc=0x800}, {.pc=0x1000}, {.pc=0x2000}} };
static qemu_plugin_vcpu_simple_cb_t init;
static qemu_plugin_vcpu_tb_trans_cb_t translate;
static qemu_plugin_udata_cb_t exiting;
static qemu_plugin_simple_cb_t pending;
static bool in_callback;

static void check(bool condition)
{
    if (!condition) { _exit(90); }
}

/* Deterministic failure before release, without weakening the shipped plugin. */
int munmap(void *address, size_t size)
{
    size_t page = (size_t)sysconf(_SC_PAGESIZE);
    if (size == 4 * 1024 * 1024 + 2 * page) {
        /* Independently inspect all payload bytes BEFORE the real unmap. */
        const volatile unsigned char *bytes = (const volatile unsigned char *)address + page;
        for (size_t i = 0; i < 4 * 1024 * 1024; i++) {
            if (bytes[i]) { _exit(94); }
        }
        if (getenv("RETIRE_FAIL_MUNMAP")) {
            errno = EINVAL;
            return -1;
        }
    }
    return (int)syscall(SYS_munmap, address, size);
}

void qemu_plugin_register_vcpu_init_cb(qemu_plugin_id_t id, qemu_plugin_vcpu_simple_cb_t cb)
{
    check(id == 42); init = cb;
}
void qemu_plugin_register_vcpu_tb_trans_cb(qemu_plugin_id_t id, qemu_plugin_vcpu_tb_trans_cb_t cb)
{
    check(id == 42); translate = cb;
}
void qemu_plugin_register_atexit_cb(qemu_plugin_id_t id, qemu_plugin_udata_cb_t cb, void *userdata)
{
    check(id == 42 && !userdata); exiting = cb;
}
size_t qemu_plugin_tb_n_insns(const struct qemu_plugin_tb *tb)
{
    check(tb == &block); return 3;
}
struct qemu_plugin_insn *qemu_plugin_tb_get_insn(const struct qemu_plugin_tb *tb, size_t index)
{
    check(tb == &block && index < 3); return &block.insns[index];
}
uint64_t qemu_plugin_insn_vaddr(const struct qemu_plugin_insn *insn) { return insn->pc; }
void qemu_plugin_register_vcpu_insn_exec_cb(struct qemu_plugin_insn *insn,
    qemu_plugin_vcpu_udata_cb_t cb, enum qemu_plugin_cb_flags flags, void *userdata)
{
    check(insn->count < 2 && flags == QEMU_PLUGIN_CB_NO_REGS);
    insn->callbacks[insn->count++] = (struct callback){cb, userdata};
}
void qemu_plugin_uninstall(qemu_plugin_id_t id, qemu_plugin_simple_cb_t cb)
{
    check(id == 42 && in_callback && !pending);
    pending = cb; /* Do not complete synchronously. */
}

static void execute(size_t index)
{
    in_callback = true;
    for (unsigned int i = 0; i < block.insns[index].count; i++) {
        struct callback cb = block.insns[index].callbacks[i];
        cb.fn(0, cb.data);
    }
    in_callback = false;
}

int main(int argc, char **argv)
{
    check(argc == 4);
    void *library = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!library) { fprintf(stderr, "%s\n", dlerror()); return 91; }
    int (*install)(qemu_plugin_id_t, const qemu_info_t *, int, char **) = dlsym(library, "qemu_plugin_install");
    int *version = dlsym(library, "qemu_plugin_version");
    check(install && version && *version == 6);
    qemu_info_t info = {.target_name="i386", .version={.min=6, .cur=6}, .system_emulation=false};
    if (getenv("RETIRE_BAD_API")) { info.version.cur = 5; }
    char log[4096], mode[64];
    check(snprintf(log, sizeof(log), "log=%s", argv[2]) < (int)sizeof(log));
    check(snprintf(mode, sizeof(mode), "mode=%s", argv[3]) < (int)sizeof(mode));
    char *options[] = {"p1=0x1000", "p2=0x2000", log, mode};
    if (getenv("RETIRE_BAD_OPTIONS")) { options[1] = "p1=0x2000"; }
    if (install(42, &info, 4, options)) { return 1; }
    check(init && translate && exiting);
    init(42, 0);
    if (getenv("RETIRE_SECOND_VCPU")) { init(42, 1); }
    translate(42, &block);
    execute(0);
    puts("ready"); fflush(stdout);
    char command[32];
    while (fgets(command, sizeof(command), stdin)) {
        if (!strcmp(command, "boundary\n")) {
            execute(1);
            execute(0); execute(0); /* Pending callbacks must still have live userdata. */
            puts("boundary");
        } else if (!strcmp(command, "complete\n")) {
            check(pending && !in_callback);
            for (size_t i = 0; i < 3; i++) { block.insns[i].count = 0; }
            init = NULL; translate = NULL; exiting = NULL;
            pending(42); pending = NULL;
            puts("completed");
        } else if (!strcmp(command, "unload\n")) {
            check(!pending && !exiting && library && dlclose(library) == 0);
            library = NULL;
            puts("unloaded");
        } else if (!strcmp(command, "second\n")) {
            execute(2);
            puts("second");
        } else if (!strcmp(command, "finish\n")) {
            if (exiting) { exiting(42, NULL); }
            return 0;
        } else { return 92; }
        fflush(stdout);
    }
    return 93;
}
