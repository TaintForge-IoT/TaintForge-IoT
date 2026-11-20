#ifndef TF_CONTROL_GUARD_H
#define TF_CONTROL_GUARD_H

#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <signal.h>
#include <stdio.h>

#define TF_CONTROL_GUARD_PROFILE "static-i386-fd-path-v1"
#define TF_CONTROL_GUARD_FDS 4096
#define TF_CONTROL_GUARD_PATH 4096

static bool cg_enabled;
static bool cg_fds[TF_CONTROL_GUARD_FDS];
static char cg_private[TF_CONTROL_GUARD_PATH];
static char cg_private_digest[65];
static uint64_t cg_calls;
static int64_t cg_pending = -1;
static int cg_action, cg_closing;

static _Noreturn void cg_fail(const char *reason)
{
    char line[160];
    int n = snprintf(line, sizeof(line), "CAPSULE_GUARD_ABORT code=126 reason=%s\n", reason);
    if (n > 0 && (size_t)n < sizeof(line)) {
        ssize_t ignored = write(STDERR_FILENO, line, (size_t)n);
        (void)ignored;
    }
    _exit(126);
}

static bool cg_prefix(const char *path, const char *prefix)
{
    size_t n = strlen(prefix);
    return !strncmp(path, prefix, n) && (!path[n] || path[n] == '/');
}

static bool cg_canonical(const char *path)
{
    if (path[0] != '/') return false;
    if (!path[1]) return true;
    const char *part = path + 1;
    for (const char *p = part; ; ++p) {
        if (*p && *p != '/') continue;
        size_t n = (size_t)(p - part);
        if (!n || (n == 1 && part[0] == '.') ||
            (n == 2 && part[0] == '.' && part[1] == '.')) return false;
        if (!*p) return true;
        part = p + 1;
    }
}

static int cg_enable(const char *private_path)
{
    if (!private_path || strlen(private_path) >= sizeof(cg_private) ||
        !cg_canonical(private_path) || !private_path[1]) return -1;
    struct stat input;
    if (fstat(STDIN_FILENO, &input) || !S_ISCHR(input.st_mode) ||
        major(input.st_rdev) != 1 || minor(input.st_rdev) != 3 ||
        fcntl(STDOUT_FILENO, F_GETFD) < 0 || fcntl(STDERR_FILENO, F_GETFD) < 0) return -1;
    strcpy(cg_private, private_path);
    char *digest = g_compute_checksum_for_string(G_CHECKSUM_SHA256, private_path, -1);
    if (!digest) return -1;
    strcpy(cg_private_digest, digest);
    g_free(digest);
    memset(cg_fds, 0, sizeof(cg_fds));
    cg_fds[0] = cg_fds[1] = cg_fds[2] = true;
    cg_calls = 0;
    cg_pending = -1;
    cg_enabled = true;
    return 0;
}

static unsigned cg_fd(uint64_t arg)
{
    uint32_t fd = (uint32_t)arg;
    if (fd >= TF_CONTROL_GUARD_FDS || !cg_fds[fd]) cg_fail("non_guest_fd");
    return fd;
}

static void cg_read(uint64_t address, void *destination, size_t size)
{
    if (!address || address > UINT32_MAX || size > UINT32_MAX - address + 1)
        cg_fail("guest_pointer");
    GByteArray *bytes = g_byte_array_new();
    if (!qemu_plugin_read_memory_vaddr(address, bytes, size) || bytes->len != size)
        cg_fail("guest_pointer");
    memcpy(destination, bytes->data, size);
    g_byte_array_free(bytes, true);
}

static void cg_path(uint64_t address)
{
    char path[TF_CONTROL_GUARD_PATH];
    GByteArray *bytes = g_byte_array_new();
    size_t used;
    for (used = 0; used < sizeof(path); ++used) {
        if (!address || address > UINT32_MAX || used > UINT32_MAX - address)
            cg_fail("guest_pointer");
        g_byte_array_set_size(bytes, 0);
        if (!qemu_plugin_read_memory_vaddr(address + used, bytes, 1) || bytes->len != 1)
            cg_fail("guest_pointer");
        path[used] = (char)bytes->data[0];
        if (!path[used]) break;
    }
    g_byte_array_free(bytes, true);
    if (used == sizeof(path)) cg_fail("path_too_long");
    if (!cg_canonical(path)) cg_fail("noncanonical_path");
    if (cg_prefix(path, "/proc") || cg_prefix(path, "/sys") || cg_prefix(path, "/dev") ||
        !strncmp(path, "/__taintforge", sizeof("/__taintforge") - 1) ||
        cg_prefix(path, cg_private)) cg_fail("private_path");
    for (size_t i = 1; i <= used; ++i) {
        if (path[i] && path[i] != '/') continue;
        char saved = path[i];
        path[i] = 0;
        struct stat info;
        int rc = lstat(path, &info);
        path[i] = saved;
        if (rc) {
            if (errno == ENOENT || errno == ENOTDIR) break;
            cg_fail("path_lookup");
        }
        if (S_ISLNK(info.st_mode)) cg_fail("symlink_path");
        if (!S_ISREG(info.st_mode) && !S_ISDIR(info.st_mode)) cg_fail("special_path");
        if (S_ISREG(info.st_mode) && info.st_nlink != 1) cg_fail("hardlinked_path");
    }
}

static void cg_mapping(uint32_t flags, uint32_t fd)
{
    if (!(flags & 2) || (flags & (1 | 16))) cg_fail("unsupported_mapping");
    if (flags & 32) {
        if (fd != UINT32_MAX) cg_fail("anonymous_mapping_fd");
    } else cg_fd(fd);
}

static void cg_before(unsigned vcpu, int64_t num, uint64_t a1, uint64_t a2,
                      uint64_t a3, uint64_t a4, uint64_t a5)
{
    if (!cg_enabled) return;
    if (vcpu || cg_pending != -1) cg_fail("syscall_state");
    if (++cg_calls == 0) cg_fail("syscall_counter");
    cg_pending = num;
    cg_action = 0;
    switch (num) {
    case 3: case 4: case 19: case 108: case 140: case 145: case 146:
    case 180: case 181: case 197: case 118: case 148:
        cg_fd(a1);
        break;
    case 6:
        cg_closing = (int)cg_fd(a1);
        cg_action = 2;
        break;
    case 5: case 8:
        cg_path(a1);
        cg_action = 1;
        break;
    case 295:
        if ((int32_t)a1 != -100) cg_fail("unsupported_dirfd");
        cg_path(a2);
        cg_action = 1;
        break;
    case 41:
        cg_fd(a1);
        cg_action = 1;
        break;
    case 63: case 330:
        cg_fd(a1);
        cg_fd(a2);
        cg_action = 1;
        break;
    case 55: case 221:
        cg_fd(a1);
        if (a2 == 0 || a2 == 1030) cg_action = 1;
        else if (a2 < 1 || a2 > 4) cg_fail("unsupported_fcntl");
        break;
    case 10: case 15: case 33: case 39: case 40: case 106: case 107:
    case 195: case 196:
        cg_path(a1);
        break;
    case 90: {
        unsigned char args[24];
        cg_read(a1, args, sizeof(args));
        uint32_t flags = (uint32_t)args[12] | (uint32_t)args[13] << 8 |
                         (uint32_t)args[14] << 16 | (uint32_t)args[15] << 24;
        uint32_t fd = (uint32_t)args[16] | (uint32_t)args[17] << 8 |
                      (uint32_t)args[18] << 16 | (uint32_t)args[19] << 24;
        cg_mapping(flags, fd);
        break;
    }
    case 192:
        cg_mapping((uint32_t)a4, (uint32_t)a5);
        break;
    case 37:
        /* A single-threaded guest may abort itself, never signal a controller. */
        if (a1 != (uint32_t)getpid() || a2 != SIGABRT) cg_fail("unsupported_signal_target");
        break;
    case 1: case 13: case 20: case 24: case 47: case 49: case 50:
    case 45: case 78: case 91: case 122: case 125: case 162: case 183:
    case 191: case 199: case 200: case 201: case 202: case 252: case 265: case 355:
        break;
    default:
        cg_fail("unsupported_syscall");
    }
    (void)a3;
}

static void cg_after(int64_t num, int64_t ret)
{
    if (!cg_enabled) return;
    if (num != cg_pending) cg_fail("syscall_return_order");
    if (cg_action == 1 && ret >= 0) {
        if (ret >= TF_CONTROL_GUARD_FDS) cg_fail("guest_fd_capacity");
        cg_fds[ret] = true;
    } else if (cg_action == 2 && ret == 0) cg_fds[cg_closing] = false;
    cg_pending = -1;
}

static void cg_snapshot(char *text, size_t size)
{
    text[0] = 0;
    if (!cg_enabled) return;
    unsigned fds = 0;
    for (unsigned i = 0; i < TF_CONTROL_GUARD_FDS; ++i) fds += cg_fds[i];
    int n = snprintf(text, size, ",\"control_guard\":{\"profile\":\"%s\","
        "\"checked_syscalls\":%llu,\"guest_fds\":%u,\"private_path_sha256\":\"%s\"}",
        TF_CONTROL_GUARD_PROFILE, (unsigned long long)cg_calls, fds, cg_private_digest);
    if (n < 0 || (size_t)n >= size) cg_fail("guard_snapshot");
}

#endif
