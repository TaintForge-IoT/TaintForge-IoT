/* SPDX-License-Identifier: GPL-2.0-or-later */
#define _GNU_SOURCE
#include <qemu-plugin.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

#if QEMU_PLUGIN_VERSION < 4
#error "Endpoint observation requires QEMU plugin memory-read API (version 4 or newer)"
#endif

enum { MAX_RECORDS = 16384, MAX_FDS = 4096 };
typedef struct SocketInfo {
    unsigned refs;
    const char *transport;
    bool connected;
    unsigned char ip[4];
    unsigned port;
} SocketInfo;

typedef struct Pending {
    int64_t number;
    uint32_t args[6];
    unsigned subcall;
    const char *name;
    const char *resolution;
    const char *transport;
    int fd;
    int action;
    bool observed;
    unsigned char ip[4];
    unsigned port;
    uint32_t address, length;
    SocketInfo *socket;
} Pending;

enum { NONE, CREATE, CONNECT, CLOSE, DUP, FCNTL_DUP, INVALIDATE };
static GMutex mutex;
static GHashTable *sockets;
static Pending pending;
static int output = -1;
static pid_t owner;
static unsigned sequence;
static bool lost, write_failed;
static char session[121], attempt[121];

static SocketInfo *socket_ref(SocketInfo *value) {
    if (value) value->refs++;
    return value;
}

static void socket_unref(gpointer pointer) {
    SocketInfo *value = pointer;
    if (value && --value->refs == 0) g_free(value);
}

static void emit(const char *line) {
    size_t remaining = strlen(line);
    while (remaining && !write_failed) {
        ssize_t size = write(output, line, remaining);
        if (size < 0 && errno == EINTR) continue;
        if (size <= 0) { write_failed = true; return; }
        line += size;
        remaining -= (size_t)size;
    }
}

static void lose_profile(const char *reason) {
    if (lost) return;
    lost = true;
    char line[512];
    snprintf(line, sizeof(line), "{\"schema_version\":1,\"event\":\"observer_error\","
        "\"reason\":\"%s\",\"session_id\":\"%s\",\"attempt_id\":\"%s\"}\n",
        reason, session, attempt);
    emit(line);
}

static bool memory(uint32_t address, size_t length, unsigned char *result) {
    if (!address || !length || length > 32 || (uint64_t)address + length > UINT64_C(0x100000000))
        return false;
    GByteArray *data = g_byte_array_new();
    bool ok = qemu_plugin_read_memory_vaddr(address, data, length) && data->len == length;
    if (ok) memcpy(result, data->data, length);
    g_byte_array_free(data, true);
    return ok;
}

static uint32_t little32(const unsigned char *bytes) {
    return (uint32_t)bytes[0] | (uint32_t)bytes[1] << 8 |
           (uint32_t)bytes[2] << 16 | (uint32_t)bytes[3] << 24;
}

static bool words(uint32_t address, unsigned count, uint32_t *result) {
    unsigned char bytes[24];
    if (count > 6 || !memory(address, count * 4, bytes)) return false;
    for (unsigned i = 0; i < count; i++) result[i] = little32(bytes + i * 4);
    return true;
}

static void put_socket(int fd, SocketInfo *value) {
    if (fd < 0) return;
    gpointer key = GINT_TO_POINTER(fd);
    if (!g_hash_table_contains(sockets, key) && g_hash_table_size(sockets) >= MAX_FDS) {
        lose_profile("socket_tracking_limit");
        return;
    }
    g_hash_table_replace(sockets, key, socket_ref(value));
}

static void address(Pending *call, uint32_t pointer, uint32_t length, bool connected_allowed) {
    call->address = pointer;
    call->length = length;
    if (!pointer && connected_allowed && call->socket && call->socket->connected) {
        memcpy(call->ip, call->socket->ip, 4);
        call->port = call->socket->port;
        call->observed = true;
        call->resolution = "observed_connected_peer";
        return;
    }
    call->resolution = !pointer ? "null_sockaddr" : "invalid_sockaddr_length";
    if (!pointer || length < 16 || length > 128) return;
    unsigned char bytes[16];
    call->resolution = "unreadable_sockaddr";
    if (!memory(pointer, sizeof(bytes), bytes)) return;
    call->resolution = "unsupported_address_family";
    if ((bytes[0] | (unsigned)bytes[1] << 8) != 2) return;
    memcpy(call->ip, bytes + 4, 4);
    call->port = (unsigned)bytes[2] << 8 | bytes[3];
    call->observed = true;
    call->resolution = "observed_sockaddr";
}

static void enter_impl(unsigned cpu, int64_t number, const uint64_t *arguments) {
    g_mutex_lock(&mutex);
    socket_unref(pending.socket);
    memset(&pending, 0, sizeof(pending));
    pending.fd = -1;
    pending.number = number;
    pending.transport = "unknown";
    pending.resolution = "not_applicable";
    if (getpid() != owner || cpu || syscall(SYS_gettid) != owner) {
        lose_profile("multiple_guest_tasks_unsupported");
    }
    if (lost) { g_mutex_unlock(&mutex); return; }
    for (unsigned i = 0; i < 6; i++) pending.args[i] = (uint32_t)arguments[i];
    if (number == 11 || number == 358) lose_profile("guest_exec_transition_unsupported");
    if (number == 436) g_hash_table_remove_all(sockets); /* close_range: conservative invalidation */
    if (number == 6) { pending.action = CLOSE; pending.fd = (int)pending.args[0]; }
    if (number == 41 || number == 63 || number == 330) pending.action = DUP;
    if ((number == 55 || number == 221) && (pending.args[1] == 0 || pending.args[1] == 1030))
        pending.action = FCNTL_DUP;
    if (number == 359) { pending.name = "socket"; pending.action = CREATE; }
    if (number == 362) { pending.name = "connect"; pending.action = CONNECT; }
    if (number == 369) pending.name = "sendto";
    if (number == 370) pending.name = "sendmsg";
    if (number == 364 || number == 360) pending.action = INVALIDATE;
    if (number == 102) {
        unsigned subcall = pending.args[0];
        unsigned count = 0;
        pending.subcall = subcall;
        switch (subcall) {
        case 1: pending.name = "socket"; pending.action = CREATE; count = 3; break;
        case 3: pending.name = "connect"; pending.action = CONNECT; count = 3; break;
        case 9: pending.name = "send"; count = 4; break;
        case 11: pending.name = "sendto"; count = 6; break;
        case 16: pending.name = "sendmsg"; count = 3; break;
        case 5: case 8: case 18: pending.action = INVALIDATE; break;
        default: break;
        }
        if (count && !words(pending.args[1], count, pending.args)) {
            lose_profile("unreadable_socketcall_arguments");
        }
    }
    if ((pending.name && pending.action != CREATE) || pending.action == DUP || pending.action == FCNTL_DUP) {
        pending.fd = (int)pending.args[0];
        pending.socket = socket_ref(g_hash_table_lookup(sockets, GINT_TO_POINTER(pending.fd)));
        if (pending.socket) pending.transport = pending.socket->transport;
    }
    if (pending.name && !strcmp(pending.name, "connect")) {
        address(&pending, pending.args[1], pending.args[2], false);
    } else if (pending.name && !strcmp(pending.name, "sendto")) {
        address(&pending, pending.args[4], pending.args[5], true);
    } else if (pending.name && !strcmp(pending.name, "send")) {
        address(&pending, 0, 0, true);
    } else if (pending.name && !strcmp(pending.name, "sendmsg")) {
        uint32_t header[2];
        if (words(pending.args[1], 2, header)) address(&pending, header[0], header[1], true);
        else pending.resolution = "unreadable_msghdr";
    }
    g_mutex_unlock(&mutex);
}

static void return_impl(unsigned cpu, int64_t number, int64_t raw_result) {
    g_mutex_lock(&mutex);
    if (getpid() != owner || cpu || syscall(SYS_gettid) != owner) lose_profile("multiple_guest_tasks_unsupported");
    int32_t result = (int32_t)raw_result;
    if (number != pending.number) lose_profile("syscall_entry_return_mismatch");
    if ((number == 2 || number == 120 || number == 190 || number == 435) && result >= 0)
        lose_profile("multiple_guest_tasks_unsupported");
    if (!lost) {
        if (pending.action == CLOSE) g_hash_table_remove(sockets, GINT_TO_POINTER(pending.fd));
        if (pending.action == INVALIDATE && result >= 0) g_hash_table_remove_all(sockets);
        if ((pending.action == DUP || pending.action == FCNTL_DUP) && result >= 0) {
            if (pending.socket) put_socket(result, pending.socket);
            else g_hash_table_remove(sockets, GINT_TO_POINTER(result));
        }
        if (pending.action == CREATE && result >= 0) {
            SocketInfo *value = g_new0(SocketInfo, 1);
            value->refs = 1;
            unsigned type = pending.args[1] & 15;
            unsigned protocol = pending.args[2];
            value->transport = pending.args[0] == 2 && type == 1 && (protocol == 0 || protocol == 6) ? "tcp" :
                               pending.args[0] == 2 && type == 2 && (protocol == 0 || protocol == 17) ? "udp" : "unknown";
            pending.transport = value->transport;
            put_socket(result, value);
            socket_unref(value);
        }
        if (pending.action == CONNECT && pending.socket) {
            pending.socket->connected = result == 0 && pending.observed;
            if (pending.socket->connected) {
                memcpy(pending.socket->ip, pending.ip, 4);
                pending.socket->port = pending.port;
            }
        }
        if (pending.name) {
            if (sequence >= MAX_RECORDS) lose_profile("observation_record_limit");
            else {
                char ip[40] = "null", line[1024];
                if (pending.observed) snprintf(ip, sizeof(ip), "\"%u.%u.%u.%u\"",
                    pending.ip[0], pending.ip[1], pending.ip[2], pending.ip[3]);
                sequence++;
                int size = snprintf(line, sizeof(line), "{\"schema_version\":1,\"event\":\"network_syscall\","
                    "\"session_id\":\"%s\",\"attempt_id\":\"%s\",\"seq\":%u,\"pid\":%d,\"vcpu\":0,"
                    "\"syscall\":\"%s\",\"number\":%lld,\"subcall\":%u,\"fd\":%d,\"result\":%d,"
                    "\"sockaddr_address\":%u,\"sockaddr_length\":%u,\"remote_ip\":%s,\"remote_port\":%u,"
                    "\"transport\":\"%s\",\"endpoint_resolution\":\"%s\"}\n",
                    session, attempt, sequence, (int)syscall(SYS_gettid), pending.name,
                    (long long)number, pending.subcall, pending.fd, result,
                    pending.address, pending.length, ip, pending.port, pending.transport, pending.resolution);
                if (size < 0 || (size_t)size >= sizeof(line)) lose_profile("observation_encoding_limit");
                else emit(line);
            }
        }
    }
    socket_unref(pending.socket);
    pending.socket = NULL;
    g_mutex_unlock(&mutex);
}

#if QEMU_PLUGIN_VERSION >= 7
static void enter(unsigned cpu, int64_t nr, uint64_t a1, uint64_t a2, uint64_t a3,
                  uint64_t a4, uint64_t a5, uint64_t a6, uint64_t a7, uint64_t a8, void *data) {
    (void)a7; (void)a8; (void)data;
    const uint64_t args[6] = {a1, a2, a3, a4, a5, a6}; enter_impl(cpu, nr, args);
}
static void returned(unsigned cpu, int64_t nr, int64_t result, void *data) {
    (void)data; return_impl(cpu, nr, result);
}
static void finish(void *data) {
    (void)data;
#else
static void enter(qemu_plugin_id_t id, unsigned cpu, int64_t nr, uint64_t a1, uint64_t a2,
                  uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6, uint64_t a7, uint64_t a8) {
    (void)id; (void)a7; (void)a8;
    const uint64_t args[6] = {a1, a2, a3, a4, a5, a6}; enter_impl(cpu, nr, args);
}
static void returned(qemu_plugin_id_t id, unsigned cpu, int64_t nr, int64_t result) {
    (void)id; return_impl(cpu, nr, result);
}
static void finish(qemu_plugin_id_t id, void *data) {
    (void)id; (void)data;
#endif
    if (getpid() != owner) return;
    g_mutex_lock(&mutex);
    char line[512];
    snprintf(line, sizeof(line), "{\"schema_version\":1,\"event\":\"observer_finished\","
        "\"session_id\":\"%s\",\"attempt_id\":\"%s\",\"record_count\":%u,\"complete\":%s}\n",
        session, attempt, sequence, !lost && !write_failed ? "true" : "false");
    emit(line);
    socket_unref(pending.socket);
    pending.socket = NULL;
    g_hash_table_destroy(sockets);
    sockets = NULL;
    close(output);
    output = -1;
    g_mutex_unlock(&mutex);
}

static bool identity(const char *value) {
    size_t length = strlen(value);
    if (!length || length > 120) return false;
    for (size_t i = 0; i < length; i++)
        if (!g_ascii_isalnum(value[i]) && value[i] != '-' && value[i] != '_' && value[i] != '.') return false;
    return true;
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id, const qemu_info_t *info,
                                         int argc, char **argv) {
    const char *path = NULL, *session_arg = NULL, *attempt_arg = NULL;
    if (info->system_emulation || strcmp(info->target_name, "i386")) return -1;
    for (int i = 0; i < argc; i++) {
        if (!strncmp(argv[i], "events=", 7) && !path) path = argv[i] + 7;
        else if (!strncmp(argv[i], "session=", 8) && !session_arg) session_arg = argv[i] + 8;
        else if (!strncmp(argv[i], "attempt=", 8) && !attempt_arg) attempt_arg = argv[i] + 8;
        else return -1;
    }
    if (!path || path[0] != '/' || !session_arg || !attempt_arg ||
        !identity(session_arg) || !identity(attempt_arg)) return -1;
    output = open(path, O_WRONLY | O_CREAT | O_EXCL | O_APPEND | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (output < 0) return -1;
    strcpy(session, session_arg);
    strcpy(attempt, attempt_arg);
    owner = getpid();
    sockets = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, socket_unref);
    char line[512];
    snprintf(line, sizeof(line), "{\"schema_version\":1,\"event\":\"observer_started\","
        "\"session_id\":\"%s\",\"attempt_id\":\"%s\",\"pid\":%d,\"target_arch\":\"i386\","
        "\"plugin_api\":%d,\"max_records\":%d,\"profile\":\"single-process-single-thread\"}\n",
        session, attempt, (int)syscall(SYS_gettid), QEMU_PLUGIN_VERSION, MAX_RECORDS);
    emit(line);
#if QEMU_PLUGIN_VERSION >= 7
    qemu_plugin_register_vcpu_syscall_cb(id, enter, NULL);
    qemu_plugin_register_vcpu_syscall_ret_cb(id, returned, NULL);
    qemu_plugin_register_atexit_cb(id, finish, NULL);
#else
    qemu_plugin_register_vcpu_syscall_cb(id, enter);
    qemu_plugin_register_vcpu_syscall_ret_cb(id, returned);
    qemu_plugin_register_atexit_cb(id, finish, NULL);
#endif
    return write_failed ? -1 : 0;
}
