#define _GNU_SOURCE
#include "phase1_retire.h"
#include "phase1_resources.h"
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

void tf_retire_wipe(void *data, size_t size) {
    volatile unsigned char *p = data;
    while (size--)
        *p++ = 0;
}

_Noreturn void tf_retire_abort(int code, const char *reason) {
    /* No atexit export after a protocol failure: the attempt is terminal. */
    dprintf(STDERR_FILENO, "CAPSULE_PHASE1_ABORT code=%d reason=%s\n", code, reason);
    _exit(code);
}

static bool number(const char *value, uint64_t *out, uint64_t max) {
    if (!value[0] || value[0] == '-' || value[0] == '+' || g_ascii_isspace(value[0]))
        return false;
    char *end;
    errno = 0;
    unsigned long long n = strtoull(value, &end, 0);
    if (errno || *end || !n || n > max)
        return false;
    *out = n;
    return true;
}

bool tf_retire_configure(TfRetire *r, TfPhase1Io *io, int argc, char **argv,
                         unsigned api, const char *target, bool system) {
    memset(r, 0, sizeof(*r));
    r->fd = -1;
    r->controller_uid = geteuid();
    r->timeout_ms = 5000;
    unsigned seen = 0;
    for (int i = 0; i < argc; i++) {
        if (!g_str_has_prefix(argv[i], "retire-"))
            continue;
        const char *eq = strchr(argv[i], '=');
        if (!eq || !eq[1])
            return false;
        size_t len = (size_t)(eq - argv[i]);
        const char *v = eq + 1;
        unsigned bit;
        uint64_t n;
#define OPT(s) (len == sizeof(s)-1 && !memcmp(argv[i], s, len))
        if (OPT("retire-socket")) {
            bit = 1;
            if (v[0] != '/' || strlen(v) >= sizeof(r->socket_path)) return false;
            strcpy(r->socket_path, v);
        } else if (OPT("retire-nonce")) {
            bit = 2;
            if (strlen(v) != 32 || strspn(v, "0123456789abcdef") != 32) return false;
            strcpy(r->nonce, v);
        } else if (OPT("retire-boundary")) {
            bit = 4;
            if (!number(v, &r->boundary, UINT32_MAX)) return false;
        } else if (OPT("retire-trigger")) {
            bit = 4; /* Mutually exclusive with a fixed boundary. */
            if (strcmp(v, "verdict")) return false;
            r->on_verdict = true;
        } else if (OPT("retire-controller")) {
            bit = 8;
            if (!number(v, &n, INT_MAX)) return false;
            r->controller = (pid_t)n;
        } else if (OPT("retire-timeout-ms")) {
            bit = 16;
            if (!number(v, &n, 60000) || n < 100) return false;
            r->timeout_ms = (unsigned)n;
        } else if (OPT("retire-max-insns")) {
            bit = 32;
            if (!number(v, &r->instruction_limit, UINT64_MAX)) return false;
        } else if (OPT("retire-controller-uid")) {
            bit = 64;
            if (!strcmp(v, "0")) n = 0;
            else if (!number(v, &n, INT_MAX)) return false;
            r->controller_uid = (uid_t)n;
        } else return false;
#undef OPT
        if (seen & bit) return false;
        seen |= bit;
    }
    if (!seen) return true;
    /* Historical candidate bytes cannot describe the current continuation. */
    if ((seen & 15) != 15 || !io->enabled || io->capture_at_entry || api != 6 || !target ||
        strcmp(target, "i386") || system) return false;
    if (r->on_verdict != !!(seen & 32)) return false;
    strcpy(r->session, io->session);
    strcpy(r->attempt, io->attempt);
    strcpy(r->instance, io->instance);
    r->state = TF_RETIRE_ACTIVE;
    io->retirement_enabled = true;
    return true;
}

static void publish_verdict(TfRetire *r, TfPhase1Io *io) {
    char data[768];
    snprintf(data, sizeof(data),
        "{\"candidate_id\":%" PRIu64 ",\"oep\":%" PRIu64
        ",\"decision_pc\":%" PRIu64 ",\"decision_trace_seq\":%" PRIu64
        ",\"continuation_pc\":%" PRIu64 ",\"policy\":\"heuristic_candidate\","
        "\"oep_proven\":false,\"rewind\":false%s}",
        r->candidate, r->oep, r->decision_pc, r->decision_seq, r->boundary,
        r->on_verdict ? ",\"trigger\":\"next_instruction_after_selection\"" : "");
    if (!tf_phase1_event(io, "oep_verdict", "selected_candidate", NULL, data))
        tf_retire_abort(90, "verdict_write_failed");
}

void tf_retire_verdict(TfRetire *r, TfPhase1Io *io, uint64_t candidate, uint64_t oep) {
    if (r->state != TF_RETIRE_ACTIVE) return;
    if (r->on_verdict && r->candidate) tf_retire_abort(89, "verdict_replaced_before_retirement");
    r->candidate = candidate;
    r->oep = oep;
    r->decision_pc = io->pc;
    r->decision_seq = io->trace_seq;
    r->epoch = io->epoch;
    r->generation = io->generation;
    /* Latch now; the next instruction callback supplies the continuation PC. */
    if (!r->on_verdict) publish_verdict(r, io);
}

bool tf_retire_due(TfRetire *r) {
    if (r->state != TF_RETIRE_ACTIVE || !r->on_verdict) return false;
    if (r->candidate) return true;
    if (r->instructions_seen >= r->instruction_limit)
        tf_retire_abort(89, "oep_verdict_instruction_limit");
    ++r->instructions_seen;
    return false;
}

void tf_retire_bind_continuation(TfRetire *r, TfPhase1Io *io, uint64_t pc) {
    if (!r->on_verdict) return;
    if (r->state != TF_RETIRE_ACTIVE || !r->candidate || !pc || pc > UINT32_MAX ||
        io->epoch != r->epoch || io->generation != r->generation ||
        io->trace_seq != r->decision_seq)
        tf_retire_abort(89, "verdict_changed_before_retirement");
    r->boundary = pc;
    io->pc = pc;
    publish_verdict(r, io);
}

static void wait_fd(int fd, short events, int64_t deadline) {
    for (;;) {
        int64_t remaining = deadline - g_get_monotonic_time();
        if (remaining <= 0) tf_retire_abort(87, "permit_deadline");
        struct pollfd p = {.fd = fd, .events = events};
        int rc = poll(&p, 1, (int)((remaining + 999) / 1000));
        if (rc < 0 && errno == EINTR) continue;
        if (rc == 0) tf_retire_abort(87, "permit_deadline");
        if (rc < 0 || !(p.revents & events)) tf_retire_abort(88, "controller_disconnected");
        return;
    }
}

static void event(TfRetire *r, const char *kind, const char *data, int64_t deadline) {
    char packet[2048];
    int len = snprintf(packet, sizeof(packet),
        "{\"protocol\":%u,\"event\":\"%s\",\"session_id\":\"%s\","
        "\"attempt_id\":\"%s\",\"analysis_instance_id\":\"%s\",\"nonce\":\"%s\","
        "\"host_pid\":%ld,\"data\":%s}", r->on_verdict ? 2U : 1U, kind, r->session, r->attempt, r->instance,
        r->nonce, (long)getpid(), data);
    if (len < 0 || (size_t)len >= sizeof(packet)) tf_retire_abort(88, "oversized_event");
    for (;;) {
        ssize_t n = send(r->fd, packet, (size_t)len, MSG_DONTWAIT | MSG_NOSIGNAL);
        if (n == len) return;
        if (n < 0 && (errno == EAGAIN || errno == EINTR) && deadline) {
            wait_fd(r->fd, POLLOUT, deadline);
            continue;
        }
        tf_retire_abort(88, "event_send_failed");
    }
}

void tf_retire_permit(TfRetire *r, TfPhase1Io *io) {
    if (r->state != TF_RETIRE_PREPARING || !r->candidate || !io->finished ||
        io->storage_failed || io->profile_lost || io->dropped_events)
        tf_retire_abort(90, "export_not_committed");
    uint64_t size;
    if (!tf_file_digest(io->manifest_path, r->manifest_sha256, &size))
        tf_retire_abort(90, "manifest_digest_failed");
    int64_t deadline = g_get_monotonic_time() + (int64_t)r->timeout_ms * 1000;
    r->fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    strcpy(address.sun_path, r->socket_path);
    if (r->fd < 0 || connect(r->fd, (struct sockaddr *)&address, sizeof(address)))
        tf_retire_abort(88, "controller_connect_failed");
    struct ucred peer;
    socklen_t length = sizeof(peer);
    if (getsockopt(r->fd, SOL_SOCKET, SO_PEERCRED, &peer, &length) ||
        length != sizeof(peer) || peer.pid != r->controller || peer.uid != r->controller_uid)
        tf_retire_abort(88, "controller_identity");
    char data[1024];
    snprintf(data, sizeof(data), "{\"candidate_id\":%" PRIu64 ",\"oep\":%" PRIu64
        ",\"decision_pc\":%" PRIu64 ",\"decision_trace_seq\":%" PRIu64
        ",\"continuation_pc\":%" PRIu64 ",\"epoch\":%" PRIu64 ",\"generation\":%u,"
        "\"policy\":\"heuristic_candidate\",\"oep_proven\":false%s}",
        r->candidate, r->oep, r->decision_pc, r->decision_seq, r->boundary, r->epoch, r->generation,
        r->on_verdict ? ",\"trigger\":\"next_instruction_after_selection\"" : "");
    event(r, "verdict", data, deadline);
    snprintf(data, sizeof(data), "{\"sha256\":\"%s\",\"size\":%" PRIu64 "}",
             r->manifest_sha256, size);
    event(r, "export_complete", data, deadline);
    char expected[256], reply[256];
    int n = snprintf(expected, sizeof(expected), "RETIRE %s %" PRIu64 " %s\n",
                     r->nonce, r->candidate, r->manifest_sha256);
    wait_fd(r->fd, POLLIN, deadline);
    ssize_t got = recv(r->fd, reply, sizeof(reply), MSG_DONTWAIT | MSG_TRUNC);
    if (got != n || memcmp(reply, expected, (size_t)n)) tf_retire_abort(88, "invalid_permit");
    r->state = TF_RETIRE_REQUESTED;
    event(r, "uninstall_requested", "{}", deadline);
}

void tf_retire_removed(TfRetire *r) {
    if (r->state != TF_RETIRE_REQUESTED) tf_retire_abort(88, "removal_order");
    r->state = TF_RETIRE_REMOVED;
    event(r, "callbacks_removed", "{}", 0);
}

void tf_retire_released(TfRetire *r, uint64_t pages, uint64_t bitmaps,
                        uint64_t buffers, uint64_t wiped, unsigned remaining) {
    if (r->state != TF_RETIRE_REMOVED || remaining) tf_retire_abort(88, "release_incomplete");
    char data[1536];
    int length = snprintf(data, sizeof(data),
        "{\"pages_released\":%" PRIu64 ",\"bitmaps_released\":%" PRIu64
        ",\"register_buffers_released\":%" PRIu64 ",\"explicitly_wiped_bytes\":%" PRIu64
        ",\"owner_roots_remaining\":%u,\"all_bytes_zeroed\":false,"
        "\"allocator_residue_verified\":false,\"guest_memory_modified\":false}",
        pages, bitmaps, buffers, wiped, remaining);
    if (tf_resources_enabled()) {
        if (tf_resources_remaining()) tf_retire_abort(92, "tracked_allocations_remaining");
        char summary[768];
        int size = tf_resources_summary(summary, sizeof(summary));
        if (size < 1 || (size_t)size >= sizeof(summary) || length < 1 ||
            (size_t)length + (size_t)size + 22 >= sizeof(data))
            tf_retire_abort(92, "resource_summary_failed");
        snprintf(data + length - 1, sizeof(data) - (size_t)length + 1,
                 ",\"resource_ledger\":%s}", summary);
    }
    event(r, "resources_released", data, 0);
    r->state = TF_RETIRE_RELEASED;
    tf_retire_close(r);
}

void tf_retire_close(TfRetire *r) {
    if (r->fd >= 0) close(r->fd);
    r->fd = -1;
}
