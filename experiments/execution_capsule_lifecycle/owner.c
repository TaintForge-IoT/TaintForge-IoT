/* SPDX-License-Identifier: GPL-2.0-or-later
 * Retirement evidence fixture. No Phase 1 or guest allocations are released.
 */
#define _GNU_SOURCE
#include <qemu-plugin.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

_Static_assert(QEMU_PLUGIN_VERSION == 6, "requires plugin API 6");
QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;
enum { ARENA_SIZE = 4 * 1024 * 1024 };
enum mode { REMOVE, KEEP, LEAK_ARENA, BAD_EXPORT };
enum state { ACTIVE, REQUESTED, RELEASED };
struct counters { uint64_t total, pending; };
static qemu_plugin_id_t owner;
static struct counters *arena;
static void *mapping;
static size_t mapping_size, page_size;
static uint64_t first_pc;
static enum mode mode;
static enum state state;
static atomic_uint initialized;
static int channel = -1;
static unsigned int sequence;
static char attempt[33], export_path[PATH_MAX];

static _Noreturn void fail(const char *reason)
{
    dprintf(STDERR_FILENO, "LIFECYCLE_ABORT reason=%s\n", reason);
    _exit(127);
}

static void emit(const char *event, const char *fields)
{
    char packet[1024];
    int length = snprintf(packet, sizeof(packet),
        "{\"protocol\":1,\"attempt\":\"%s\",\"seq\":%u,\"pid\":%ld,"
        "\"event\":\"%s\",\"data\":{%s}}", attempt, sequence,
        (long)getpid(), event, fields);
    if (length < 0 || (size_t)length >= sizeof(packet)) { fail("packet_size"); }
    /* Completion runs under QEMU's plugin lock. Never wait for the receiver.
     * SOCK_SEQPACKET preserves one JSON object per send, including its boundary.
     * Even EINTR is a failed attempt; there is no unbounded retry loop here.
     */
    if (send(channel, packet, (size_t)length, MSG_DONTWAIT | MSG_NOSIGNAL) != length) {
        fail("event_send");
    }
    sequence++;
}

static void close_channel(void)
{
    if (close(channel) != 0) { fail("channel_close"); }
    channel = -1;
}

static void export_result(void)
{
    char payload[96], fields[192];
    int length = snprintf(payload, sizeof(payload), "CAPSULE_EXPORT_V1\nattempt=%s\n", attempt);
    if (length < 0 || (size_t)length >= sizeof(payload)) { fail("export_size"); }
    int fd = open(export_path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) { fail("export_open"); }
    if (write(fd, payload, (size_t)length) != length || fsync(fd) != 0 || close(fd) != 0) {
        fail("export_write");
    }
    GChecksum *checksum = g_checksum_new(G_CHECKSUM_SHA256);
    if (!checksum) { fail("export_digest"); }
    g_checksum_update(checksum, (const guchar *)payload, length);
    char digest[65];
    strcpy(digest, g_checksum_get_string(checksum));
    g_checksum_free(checksum);
    if (mode == BAD_EXPORT) { digest[0] = digest[0] == '0' ? '1' : '0'; }
    snprintf(fields, sizeof(fields), "\"size\":%d,\"sha256\":\"%s\"", length, digest);
    emit("export_complete", fields);
}

static void removed(qemu_plugin_id_t id)
{
    if (id != owner || state != REQUESTED) { fail("unexpected_completion"); }
    char fields[192];
    snprintf(fields, sizeof(fields), "\"callbacks\":%" PRIu64 ",\"pending\":%" PRIu64,
             arena->total, arena->pending);
    emit("callbacks_removed", fields);
    /* All userdata users are gone; this fixture has no private worker threads. */
    volatile unsigned char *bytes = (volatile unsigned char *)arena;
    for (size_t i = 0; i < ARENA_SIZE; i++) { bytes[i] = 0; }
    if (mode != LEAK_ARENA && munmap(mapping, mapping_size) != 0) { fail("munmap"); }
    arena = NULL;
    mapping = NULL;
    state = RELEASED;
    /* LEAK_ARENA deliberately lies here. The external maps check must reject it. */
    emit("resources_released", "\"owned_mappings\":0,\"owned_bytes\":0,\"zeroed_bytes\":4194304");
    close_channel();
    /* EOF is NOT module-unloaded evidence. QEMU calls g_module_close after return. */
}

static void count_exec(unsigned int vcpu, void *userdata)
{
    if (vcpu || state == RELEASED || userdata != arena) { fail("invalid_callback"); }
    arena->total++;
    if (state == REQUESTED) { arena->pending++; }
}

static void boundary(unsigned int vcpu, void *userdata)
{
    if (vcpu || state != ACTIVE || userdata != arena) { fail("unexpected_boundary"); }
    export_result();
    state = REQUESTED;
    if (mode == KEEP) { close_channel(); return; }
    char fields[96];
    snprintf(fields, sizeof(fields), "\"callbacks\":%" PRIu64, arena->total);
    emit("uninstall_requested", fields);
    qemu_plugin_uninstall(owner, removed);
    /* Return: safe work cannot complete while this callback waits for it. */
}

static void translate(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
    if (id != owner || state == RELEASED) { fail("invalid_translation"); }
    for (size_t i = 0; i < qemu_plugin_tb_n_insns(tb); i++) {
        struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);
        qemu_plugin_register_vcpu_insn_exec_cb(insn, count_exec, QEMU_PLUGIN_CB_NO_REGS, arena);
        if (qemu_plugin_insn_vaddr(insn) == first_pc) {
            qemu_plugin_register_vcpu_insn_exec_cb(insn, boundary, QEMU_PLUGIN_CB_NO_REGS, arena);
        }
    }
}

static void init_vcpu(qemu_plugin_id_t id, unsigned int vcpu)
{
    if (id != owner || vcpu || atomic_fetch_add(&initialized, 1)) { fail("only_one_vcpu_supported"); }
}

static void retained_exit(qemu_plugin_id_t id, void *userdata)
{
    (void)userdata;
    if (id != owner || mode != KEEP || state != REQUESTED) { fail("missing_completion"); }
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id, const qemu_info_t *info,
                                         int argc, char **argv)
{
    if (info->system_emulation || strcmp(info->target_name, "i386") ||
        info->version.cur != 6 || info->version.min > 6 || argc != 5) { return 1; }
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    unsigned int seen = 0;
    for (int i = 0; i < argc; i++) {
        unsigned int bit;
        const char *value = strchr(argv[i], '=');
        if (!value || !*++value) { return 1; }
        if (!strncmp(argv[i], "p1=", 3)) {
            bit = 1;
            char *end;
            errno = 0;
            first_pc = strtoull(value, &end, 0);
            if (errno || *end || !first_pc || first_pc > UINT32_MAX || *value == '-' || *value == '+') {
                return 1;
            }
        } else if (!strncmp(argv[i], "socket=", 7)) {
            bit = 2;
            if (strlen(value) >= sizeof(address.sun_path)) { return 1; }
            strcpy(address.sun_path, value);
        } else if (!strncmp(argv[i], "export=", 7)) {
            bit = 4;
            if (strlen(value) >= sizeof(export_path)) { return 1; }
            strcpy(export_path, value);
        } else if (!strncmp(argv[i], "attempt=", 8)) {
            bit = 8;
            if (strlen(value) != 32 || strspn(value, "0123456789abcdef") != 32) { return 1; }
            strcpy(attempt, value);
        } else if (!strncmp(argv[i], "mode=", 5)) {
            bit = 16;
            if (!strcmp(value, "remove")) { mode = REMOVE; }
            else if (!strcmp(value, "keep")) { mode = KEEP; }
            else if (!strcmp(value, "leak-arena")) { mode = LEAK_ARENA; }
            else if (!strcmp(value, "bad-export")) { mode = BAD_EXPORT; }
            else { return 1; }
        } else { return 1; }
        if (seen & bit) { return 1; }
        seen |= bit;
    }
    long pages = sysconf(_SC_PAGESIZE);
    if (seen != 31 || pages <= 0 || pages > ARENA_SIZE || ARENA_SIZE % pages) { return 1; }
    page_size = (size_t)pages;
    mapping_size = ARENA_SIZE + 2 * page_size;
    channel = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (channel < 0) { return 1; }
    if (connect(channel, (struct sockaddr *)&address, sizeof(address)) != 0) {
        close(channel); return 1;
    }
    mapping = mmap(NULL, mapping_size, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mapping == MAP_FAILED) { close(channel); return 1; }
    arena = (struct counters *)((unsigned char *)mapping + page_size);
    if (mprotect(arena, ARENA_SIZE, PROT_READ | PROT_WRITE) != 0) {
        munmap(mapping, mapping_size); close(channel); return 1;
    }
    memset(arena, 0xa7, ARENA_SIZE);
    arena->total = arena->pending = 0;
    owner = id;
    char fields[320];
    snprintf(fields, sizeof(fields), "\"producer\":\"capsule-fixture-v1\",\"api\":6,"
        "\"mapping_start\":%" PRIuPTR ",\"mapping_size\":%zu,\"page_size\":%zu,"
        "\"arena_start\":%" PRIuPTR ",\"arena_size\":%u",
        (uintptr_t)mapping, mapping_size, page_size, (uintptr_t)arena, (unsigned int)ARENA_SIZE);
    emit("hello", fields);
    qemu_plugin_register_vcpu_init_cb(id, init_vcpu);
    qemu_plugin_register_vcpu_tb_trans_cb(id, translate);
    qemu_plugin_register_atexit_cb(id, retained_exit, NULL);
    return 0;
}
