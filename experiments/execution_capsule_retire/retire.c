/* SPDX-License-Identifier: GPL-2.0-or-later
 * QEMU 11.0.1/API 6, controlled single-thread i386 ELF only.
 * This plugin owns its mmap arena. It never frees Phase 1 or guest memory.
 * No private threads: uninstall completion covers all of our callbacks.
 */
#define _GNU_SOURCE
#include <qemu-plugin.h>
#include <errno.h>
#include <fcntl.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

_Static_assert(QEMU_PLUGIN_VERSION == 6, "requires QEMU plugin API 6");
QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;
enum { ARENA_SIZE = 4 * 1024 * 1024 };
enum lifecycle { ACTIVE, REQUESTED, CLEARED };
struct owned_state { uint64_t callbacks, pending_callbacks; };
static qemu_plugin_id_t owner_id;
static struct owned_state *owned;
static void *mapping;
static size_t mapping_size, page_size;
static uint64_t first_pc, second_pc, final_callbacks, final_pending;
static enum lifecycle state;
static atomic_uint initialized;
static bool keep, boundary_seen;
static int journal = -1;

static _Noreturn void fail(const char *reason)
{
    dprintf(STDERR_FILENO, "RETIRE_ABORT reason=%s\n", reason);
    _exit(127);
}

static void record(const char *event)
{
    struct owned_state counters = {final_callbacks, final_pending};
    if (state != CLEARED) {
        if (!owned) { fail("missing_live_arena"); }
        counters = *owned;
    }
    char line[768];
    int length = snprintf(line, sizeof(line),
        "{\"schema\":1,\"event\":\"%s\",\"host_pid\":%ld,\"mode\":\"%s\","
        "\"mapping_start\":%" PRIuPTR ",\"mapping_size\":%zu,"
        "\"arena_start\":%" PRIuPTR ",\"arena_size\":%u,\"page_size\":%zu,"
        "\"callbacks\":%" PRIu64 ",\"pending_callbacks\":%" PRIu64 "}\n",
        event, (long)getpid(), keep ? "keep" : "uninstall",
        (uintptr_t)mapping, mapping_size, (uintptr_t)mapping + page_size,
        (unsigned int)ARENA_SIZE, page_size, counters.callbacks, counters.pending_callbacks);
    if (length < 0 || (size_t)length >= sizeof(line)) {
        fail("journal_overflow");
    }
    ssize_t written;
    do {
        written = write(journal, line, (size_t)length);
    } while (written < 0 && errno == EINTR);
    if (written != length) {
        fail("journal_write");
    }
}

static void removed(qemu_plugin_id_t id)
{
    if (id != owner_id || state != REQUESTED) {
        fail("unexpected_completion");
    }
    record("callbacks_removed");
    final_callbacks = owned->callbacks;
    final_pending = owned->pending_callbacks;
    /* Volatile stores prevent dead-store elimination before munmap.
     * This only erases our dedicated mapping, not all traces of analysis.
     */
    volatile unsigned char *bytes = (volatile unsigned char *)owned;
    for (size_t i = 0; i < ARENA_SIZE; i++) {
        bytes[i] = 0;
    }
    for (size_t i = 0; i < ARENA_SIZE; i++) {
        if (bytes[i] != 0) {
            fail("zero_verification");
        }
    }
    state = CLEARED; /* record must no longer dereference the erased counters. */
    record("arena_zeroed");
    if (munmap(mapping, mapping_size) != 0) {
        fail("munmap");
    }
    owned = NULL;
    record("arena_unmapped");
    if (close(journal) != 0) {
        fail("journal_close");
    }
    journal = -1;
    /* Return to QEMU. QEMU closes this .so AFTER this callback returns. */
}

static void count_exec(unsigned int vcpu, void *userdata)
{
    if (vcpu != 0 || state == CLEARED || userdata != owned) {
        fail("callback_after_release_or_wrong_cpu");
    }
    owned->callbacks++;
    if (state == REQUESTED) {
        owned->pending_callbacks++;
    }
}

static void boundary(unsigned int vcpu, void *userdata)
{
    if (vcpu != 0 || state != ACTIVE || boundary_seen || userdata != owned) {
        fail("unexpected_boundary");
    }
    boundary_seen = true;
    if (keep) {
        record("retirement_skipped");
        return;
    }
    state = REQUESTED;
    record("uninstall_requested");
    qemu_plugin_uninstall(owner_id, removed);
    /* Never wait here. Pending callbacks may still use owned until removed(). */
}

static void second_point(unsigned int vcpu, void *userdata)
{
    if (vcpu != 0 || userdata != owned || state == CLEARED) {
        fail("unexpected_second_point");
    }
    record("still_active"); /* Expected only in the keep control. */
}

static void translate(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
    if (id != owner_id || state == CLEARED) {
        fail("translation_after_release");
    }
    for (size_t i = 0; i < qemu_plugin_tb_n_insns(tb); i++) {
        struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);
        uint64_t pc = qemu_plugin_insn_vaddr(insn);
        qemu_plugin_register_vcpu_insn_exec_cb(insn, count_exec, QEMU_PLUGIN_CB_NO_REGS, owned);
        if (pc == first_pc || pc == second_pc) {
            qemu_plugin_register_vcpu_insn_exec_cb(insn,
                pc == first_pc ? boundary : second_point, QEMU_PLUGIN_CB_NO_REGS, owned);
        }
    }
}

static void init_vcpu(qemu_plugin_id_t id, unsigned int vcpu)
{
    if (id != owner_id || vcpu != 0 || atomic_fetch_add(&initialized, 1) != 0) {
        fail("only_one_vcpu_supported");
    }
}

static void retained_exit(qemu_plugin_id_t id, void *userdata)
{
    (void)userdata;
    if (id != owner_id || !keep || !boundary_seen || state != ACTIVE) {
        fail("uninstall_not_completed");
    }
    record("exit_retained");
    close(journal);
    journal = -1; /* keep control intentionally leaves the arena to process exit. */
}

static bool address(const char *text, uint64_t *value)
{
    char *end;
    errno = 0;
    if (!*text || *text == '-' || *text == '+') {
        return false;
    }
    *value = strtoull(text, &end, 0);
    return !errno && !*end && *value > 0 && *value <= UINT32_MAX;
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id, const qemu_info_t *info,
                                         int argc, char **argv)
{
    if (info->system_emulation || strcmp(info->target_name, "i386") ||
        info->version.cur != 6 || info->version.min > 6 || argc != 4) {
        return 1;
    }
    const char *path = NULL;
    unsigned int seen = 0;
    for (int i = 0; i < argc; i++) {
        unsigned int bit;
        if (!strncmp(argv[i], "p1=", 3)) {
            bit = 1;
            if (!address(argv[i] + 3, &first_pc)) { return 1; }
        } else if (!strncmp(argv[i], "p2=", 3)) {
            bit = 2;
            if (!address(argv[i] + 3, &second_pc)) { return 1; }
        } else if (!strncmp(argv[i], "log=", 4) && argv[i][4]) {
            bit = 4;
            path = argv[i] + 4;
        } else if (!strcmp(argv[i], "mode=keep") || !strcmp(argv[i], "mode=uninstall")) {
            bit = 8;
            keep = !strcmp(argv[i], "mode=keep");
        } else {
            return 1;
        }
        if (seen & bit) { return 1; }
        seen |= bit;
    }
    long pages = sysconf(_SC_PAGESIZE);
    if (seen != 15 || first_pc == second_pc || pages <= 0 ||
        (size_t)pages > ARENA_SIZE || ARENA_SIZE % (size_t)pages) {
        return 1;
    }
    page_size = (size_t)pages;
    mapping_size = ARENA_SIZE + 2 * page_size;
    journal = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (journal < 0) { return 1; }
    mapping = mmap(NULL, mapping_size, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mapping == MAP_FAILED) {
        close(journal);
        return 1;
    }
    owned = (struct owned_state *)((unsigned char *)mapping + page_size);
    if (mprotect(owned, ARENA_SIZE, PROT_READ | PROT_WRITE) != 0) {
        munmap(mapping, mapping_size);
        close(journal);
        return 1;
    }
    memset(owned, 0xa7, ARENA_SIZE); /* Touch every page; do not infer release from RSS. */
    owned->callbacks = owned->pending_callbacks = 0;
    owner_id = id;
    record("arena_allocated");
    qemu_plugin_register_vcpu_init_cb(id, init_vcpu);
    qemu_plugin_register_vcpu_tb_trans_cb(id, translate);
    qemu_plugin_register_atexit_cb(id, retained_exit, NULL);
    return 0;
}
