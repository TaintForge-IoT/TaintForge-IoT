/* SPDX-License-Identifier: GPL-2.0-or-later
 * QEMU 11.0.1 / plugin API 6 only. This is a one-vCPU experiment.
 * All CPU/memory APIs run in vCPU callbacks. The watchdog uses host APIs only.
 * A bounded wait inside a callback is NOT a QEMU/Phase-1 quiescence barrier.
 */
#define _GNU_SOURCE
#include <qemu-plugin.h>
#include <errno.h>
#include <limits.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

_Static_assert(QEMU_PLUGIN_VERSION == 6, "requires the pinned API 6 header");
QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;
static const char *const reg_names[] = {
    "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "eip"
};
enum { NREG = 9, SP = 7, PC = 8 };
static struct qemu_plugin_register *reg_handles[NREG];
static bool reg_found[NREG]; /* EAX's valid opaque handle may be NULL. */
static uint64_t points[2], buffer_addr, pause_ms, total_ms, total_deadline;
static int channel = -1;
static unsigned int stops;
static atomic_uint vcpu_count;
static atomic_bool finished;
static pthread_t watchdog;

static uint64_t now_ms(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        _exit(126);
    }
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

static _Noreturn void abort_run(int code, const char *reason)
{
    /* Bounded best-effort diagnostic; do not run analyzer atexit on failure.
     * stderr is a private regular file supplied by the supervisor, not a pipe.
     */
    char line[160];
    int n = snprintf(line, sizeof(line), "CAPSULE_ABORT code=%d reason=%s\n", code, reason);
    if (n > 0 && (size_t)n < sizeof(line)) {
        ssize_t written = write(STDERR_FILENO, line, (size_t)n);
        (void)written;
    }
    _exit(code);
}

static void wait_io(short events, uint64_t deadline)
{
    for (;;) {
        uint64_t now = now_ms();
        if (now >= deadline) {
            abort_run(124, "deadline");
        }
        struct pollfd p = { .fd = channel, .events = events | POLLRDHUP };
        int n = poll(&p, 1, (int)(deadline - now));
        if (n < 0 && errno == EINTR) {
            continue;
        }
        if (n < 0) {
            abort_run(126, "poll_error");
        }
        if (p.revents & (POLLHUP | POLLRDHUP | POLLERR | POLLNVAL)) {
            abort_run(125, "controller_lost");
        }
        if (p.revents & events) {
            return;
        }
    }
}

static void send_frame(const char *frame, uint64_t deadline)
{
    size_t len = strlen(frame), off = 0;
    while (off < len) {
        wait_io(POLLOUT, deadline);
        ssize_t n = send(channel, frame + off, len - off, MSG_NOSIGNAL | MSG_DONTWAIT);
        if (n < 0 && (errno == EAGAIN || errno == EINTR)) {
            continue;
        }
        if (n <= 0) {
            abort_run(125, "send_failed");
        }
        off += (size_t)n;
    }
}

static void read_command(char *out, size_t capacity, uint64_t deadline)
{
    size_t used = 0;
    while (used + 1 < capacity) {
        wait_io(POLLIN, deadline);
        ssize_t n = recv(channel, out + used, 1, MSG_DONTWAIT);
        if (n < 0 && (errno == EAGAIN || errno == EINTR)) {
            continue;
        }
        if (n <= 0) {
            abort_run(125, "controller_lost");
        }
        if (out[used] == '\n') {
            out[used + 1] = 0;
            return;
        }
        if (out[used] < 32 || out[used] > 126) {
            abort_run(126, "invalid_command_byte");
        }
        used++;
    }
    abort_run(126, "command_too_long");
}

static void *watch_connection(void *unused)
{
    (void)unused;
    while (!atomic_load(&finished)) {
        if (now_ms() >= total_deadline) {
            abort_run(124, "total_timeout");
        }
        /* Never receive bytes and never call any QEMU API here. */
        struct pollfd p = { .fd = channel, .events = POLLRDHUP };
        int result = poll(&p, 1, 25);
        if (atomic_load(&finished)) {
            break;
        }
        if (result < 0 && errno != EINTR) {
            abort_run(126, "watchdog_poll");
        }
        if (p.revents & (POLLHUP | POLLRDHUP | POLLERR | POLLNVAL)) {
            abort_run(125, "controller_lost");
        }
    }
    return NULL;
}

static void hex_bytes(const unsigned char *data, size_t len, char *out)
{
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[2*i] = hex[data[i] >> 4];
        out[2*i+1] = hex[data[i] & 15];
    }
    out[2*len] = 0;
}

static void snapshot(unsigned int index, unsigned int sample, uint64_t deadline)
{
    uint32_t values[NREG];
    GByteArray *bytes = g_byte_array_new();
    for (unsigned int r = 0; r < NREG; r++) {
        g_byte_array_set_size(bytes, 0); /* read_register appends */
        if (!reg_found[r] || !qemu_plugin_read_register(reg_handles[r], bytes) || bytes->len != 4) {
            abort_run(126, "register_read_failed");
        }
        values[r] = (uint32_t)bytes->data[0] | ((uint32_t)bytes->data[1] << 8) |
            ((uint32_t)bytes->data[2] << 16) | ((uint32_t)bytes->data[3] << 24);
    }
    if (values[PC] != points[index]) {
        abort_run(126, "pc_not_at_observation_point");
    }
    char buffer[33], stack[65];
    if (!qemu_plugin_read_memory_vaddr(buffer_addr, bytes, 16) || bytes->len != 16) {
        abort_run(126, "buffer_read_failed");
    }
    hex_bytes(bytes->data, 16, buffer);
    if (!qemu_plugin_read_memory_vaddr(values[SP], bytes, 32) || bytes->len != 32) {
        abort_run(126, "stack_read_failed");
    }
    hex_bytes(bytes->data, 32, stack);
    g_byte_array_unref(bytes);
    char json[2048];
    int n = snprintf(json, sizeof(json),
        "{\"event\":\"snapshot\",\"protocol\":1,\"point\":%u,\"sample\":%u,"
        "\"host_pid\":%ld,\"vcpu\":0,\"monotonic_ms\":%" PRIu64 ","
        "\"regs\":{\"eax\":%u,\"ebx\":%u,\"ecx\":%u,\"edx\":%u,\"esi\":%u,"
        "\"edi\":%u,\"ebp\":%u,\"esp\":%u,\"eip\":%u},"
        "\"buffer_hex\":\"%s\",\"stack_hex\":\"%s\"}\n",
        index + 1, sample, (long)getpid(), now_ms(), values[0], values[1], values[2],
        values[3], values[4], values[5], values[6], values[7], values[8], buffer, stack);
    if (n < 0 || (size_t)n >= sizeof(json)) {
        abort_run(126, "snapshot_overflow");
    }
    send_frame(json, deadline);
}

static void observe(unsigned int vcpu, void *userdata)
{
    unsigned int index = (unsigned int)(uintptr_t)userdata;
    if (vcpu != 0 || index != stops || index > 1) {
        abort_run(126, "unexpected_vcpu_or_point");
    }
    uint64_t deadline = now_ms() + pause_ms;
    if (deadline > total_deadline) {
        deadline = total_deadline;
    }
    snapshot(index, 1, deadline);
    char command[32], expected[32];
    read_command(command, sizeof(command), deadline);
    snprintf(expected, sizeof(expected), "CHECK %u\n", index + 1);
    if (strcmp(command, expected) != 0) {
        abort_run(126, "expected_check");
    }
    snapshot(index, 2, deadline);
    read_command(command, sizeof(command), deadline);
    snprintf(expected, sizeof(expected), "CONTINUE %u\n", index + 1);
    if (strcmp(command, expected) != 0) {
        abort_run(126, "expected_continue");
    }
    stops++;
    /* Returning from this callback resumes this same vCPU. */
}

static void init_vcpu(qemu_plugin_id_t id, unsigned int vcpu)
{
    (void)id;
    if (vcpu != 0 || atomic_fetch_add(&vcpu_count, 1) != 0) {
        abort_run(126, "only_one_vcpu_supported");
    }
    GArray *regs = qemu_plugin_get_registers();
    if (!regs) {
        abort_run(126, "no_registers");
    }
    for (unsigned int i = 0; i < regs->len; i++) {
        qemu_plugin_reg_descriptor *r = &g_array_index(regs, qemu_plugin_reg_descriptor, i);
        for (unsigned int k = 0; k < NREG; k++) {
            if (r->name && strcmp(r->name, reg_names[k]) == 0) {
                reg_handles[k] = r->handle;
                reg_found[k] = true;
            }
        }
    }
    g_array_free(regs, true);
    for (unsigned int k = 0; k < NREG; k++) {
        if (!reg_found[k]) {
            abort_run(126, "missing_i386_register");
        }
    }
}

static void translate(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
    (void)id;
    for (size_t i = 0; i < qemu_plugin_tb_n_insns(tb); i++) {
        struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);
        uint64_t pc = qemu_plugin_insn_vaddr(insn);
        for (unsigned int p = 0; p < 2; p++) {
            if (pc == points[p]) {
                qemu_plugin_register_vcpu_insn_exec_cb(insn, observe,
                    QEMU_PLUGIN_CB_R_REGS, (void *)(uintptr_t)p);
            }
        }
    }
}

static void capsule_exit(qemu_plugin_id_t id, void *unused)
{
    (void)id;
    (void)unused;
    if (stops != 2) {
        abort_run(126, "missing_observation_points");
    }
    /* No guest API in atexit. Do not claim analyzer callbacks finished. */
    atomic_store(&finished, true);
    pthread_join(watchdog, NULL);
    send_frame("{\"event\":\"done\",\"protocol\":1,\"points\":2}\n", now_ms() + 1000);
    close(channel);
}

static bool parse_num(const char *s, uint64_t *value)
{
    char *end;
    errno = 0;
    if (!*s || *s == '-' || *s == '+') {
        return false;
    }
    unsigned long long n = strtoull(s, &end, 0);
    if (errno || *end) {
        return false;
    }
    *value = n;
    return true;
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id, const qemu_info_t *info,
                                          int argc, char **argv)
{
    if (info->system_emulation || strcmp(info->target_name, "i386") != 0 ||
        info->version.cur != 6 || info->version.min > 6 || argc != 7) {
        return -1;
    }
    const char *socket_path = NULL;
    uint64_t controller = 0;
    unsigned int seen = 0;
    const char *keys[] = {"p1=", "p2=", "buffer=", "pause-ms=", "total-ms=", "controller="};
    uint64_t *dest[] = {&points[0], &points[1], &buffer_addr, &pause_ms, &total_ms, &controller};
    for (int i = 0; i < argc; i++) {
        unsigned int bit = 0;
        if (strncmp(argv[i], "socket=", 7) == 0) {
            socket_path = argv[i] + 7;
            bit = 1U << 6;
        } else {
            for (unsigned int k = 0; k < 6; k++) {
                size_t len = strlen(keys[k]);
                if (strncmp(argv[i], keys[k], len) == 0 && parse_num(argv[i] + len, dest[k])) {
                    bit = 1U << k;
                    break;
                }
            }
        }
        if (!bit || (seen & bit)) {
            return -1;
        }
        seen |= bit;
    }
    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    if (seen != 127 || !socket_path || strlen(socket_path) >= sizeof(addr.sun_path) ||
        !points[0] || !points[1] || points[0] == points[1] || !buffer_addr ||
        points[0] > UINT32_MAX || points[1] > UINT32_MAX || buffer_addr > UINT32_MAX - 15 ||
        pause_ms < 100 || pause_ms > 60000 || total_ms < 100 || total_ms > 600000 ||
        !controller || controller > INT_MAX) {
        return -1;
    }
    total_deadline = now_ms() + total_ms;
    channel = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (channel < 0) {
        return -1;
    }
    strcpy(addr.sun_path, socket_path);
    /* Listener is already bound and listening before QEMU starts. */
    if (connect(channel, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(channel);
        return -1;
    }
    struct ucred peer;
    socklen_t len = sizeof(peer);
    if (getsockopt(channel, SOL_SOCKET, SO_PEERCRED, &peer, &len) != 0 ||
        peer.uid != getuid() || peer.pid != (pid_t)controller) {
        close(channel);
        return -1;
    }
    if (pthread_create(&watchdog, NULL, watch_connection, NULL) != 0) {
        close(channel);
        return -1;
    }
    qemu_plugin_register_vcpu_init_cb(id, init_vcpu);
    qemu_plugin_register_vcpu_tb_trans_cb(id, translate);
    qemu_plugin_register_atexit_cb(id, capsule_exit, NULL);
    return 0;
}
