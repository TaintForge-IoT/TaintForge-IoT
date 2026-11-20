#define _GNU_SOURCE
#include <qemu-plugin.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "../retirement_observer/control_guard.h"

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

static void before(qemu_plugin_id_t id, unsigned vcpu, int64_t num, uint64_t a1,
                   uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5,
                   uint64_t a6, uint64_t a7, uint64_t a8)
{
    (void)id; (void)a6; (void)a7; (void)a8;
    cg_before(vcpu, num, a1, a2, a3, a4, a5);
}

static void after(qemu_plugin_id_t id, unsigned vcpu, int64_t num, int64_t ret)
{
    (void)id; (void)vcpu;
    cg_after(num, ret);
}

static void done(qemu_plugin_id_t id, void *unused)
{
    (void)id; (void)unused;
    char text[320];
    cg_snapshot(text, sizeof(text));
    fprintf(stderr, "CONTROL_PROBE_DONE{\"service_fd_open\":%s%s}\n",
            fcntl(200, F_GETFD) >= 0 ? "true" : "false", text);
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id, const qemu_info_t *info,
                                          int argc, char **argv)
{
    if (info->system_emulation || strcmp(info->target_name, "i386") ||
        info->version.cur != 6 || info->version.min > 6 || argc != 3 ||
        strncmp(argv[0], "private=", 8) || strncmp(argv[1], "service=", 8) ||
        (strcmp(argv[2], "guard=on") && strcmp(argv[2], "guard=off"))) return -1;
    if (fcntl(200, F_GETFD) >= 0 || errno != EBADF) return -1;
    int fd = open(argv[1] + 8, O_RDWR | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0 || dup3(fd, 200, O_CLOEXEC) < 0) return -1;
    close(fd);
    if (!strcmp(argv[2], "guard=on") && cg_enable(argv[0] + 8)) return -1;
    qemu_plugin_register_vcpu_syscall_cb(id, before);
    qemu_plugin_register_vcpu_syscall_ret_cb(id, after);
    qemu_plugin_register_atexit_cb(id, done, NULL);
    return 0;
}
