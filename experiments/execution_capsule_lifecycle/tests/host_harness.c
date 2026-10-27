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
#include <sys/socket.h>
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
static int paired_channel = -1;

static void check(bool condition)
{
    if (!condition) { _exit(90); }
}

/* Development hosts may forbid bind/listen. This optional test setup creates
 * a real socketpair IN THE CHILD, preserving the child's SO_PEERCRED identity,
 * and transfers the receiver to Python. It does not test named-socket setup.
 */
int socket(int domain, int type, int protocol)
{
    const char *transfer = getenv("EVIDENCE_TEST_SOCKET");
    if (!transfer) { return (int)syscall(SYS_socket, domain, type, protocol); }
    int ends[2];
    check(domain == AF_UNIX && socketpair(domain, type, protocol, ends) == 0);
    char byte = 's';
    struct iovec vector = {.iov_base = &byte, .iov_len = 1};
    union { struct cmsghdr alignment; char bytes[CMSG_SPACE(sizeof(int))]; } control = {0};
    struct msghdr message = {.msg_iov = &vector, .msg_iovlen = 1,
                            .msg_control = control.bytes, .msg_controllen = sizeof(control.bytes)};
    struct cmsghdr *header = CMSG_FIRSTHDR(&message);
    header->cmsg_level = SOL_SOCKET;
    header->cmsg_type = SCM_RIGHTS;
    header->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(header), &ends[1], sizeof(int));
    check(sendmsg(atoi(transfer), &message, MSG_NOSIGNAL) == 1);
    close(ends[1]);
    paired_channel = ends[0];
    return ends[0];
}

int connect(int fd, const struct sockaddr *address, socklen_t length)
{
    if (fd == paired_channel) { return 0; }
    return (int)syscall(SYS_connect, fd, address, length);
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
        if (getenv("EVIDENCE_FAIL_MUNMAP")) {
            errno = EINVAL;
            return -1;
        }
    }
    return (int)syscall(SYS_munmap, address, size);
}

/* Inject backpressure at an exact stage; successful sends use the real socket. */
ssize_t send(int fd, const void *data, size_t length, int flags)
{
    const char *event = getenv("EVIDENCE_SEND_FAIL");
    if (event && memmem(data, length, event, strlen(event))) {
        errno = EAGAIN;
        return -1;
    }
    return syscall(SYS_sendto, fd, data, length, flags, NULL, 0);
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
    check(argc >= 3);
    /* Some test runners virtualize getpid but expose host PID numbers in /proc.
     * Expose ONLY this child's real proc ID to the optional Python test adapter.
     */
    const char *proc_path = getenv("EVIDENCE_TEST_PROC_ID");
    if (proc_path) {
        FILE *source = fopen("/proc/self/stat", "r"), *dest = fopen(proc_path, "wx");
        long proc_id;
        check(source && dest && fscanf(source, "%ld", &proc_id) == 1);
        check(fprintf(dest, "%ld\n", proc_id) > 0);
        check(fclose(source) == 0 && fclose(dest) == 0);
    }
    void *library = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!library) { fprintf(stderr, "%s\n", dlerror()); return 91; }
    int (*install)(qemu_plugin_id_t, const qemu_info_t *, int, char **) = dlsym(library, "qemu_plugin_install");
    int *version = dlsym(library, "qemu_plugin_version");
    check(install && version && *version == 6);
    qemu_info_t info = {.target_name="i386", .version={.min=6, .cur=6}, .system_emulation=false};
    if (getenv("EVIDENCE_BAD_API")) { info.version.cur = 5; }
    if (getenv("EVIDENCE_BAD_OPTIONS")) { argv[2] = "p1=0"; }
    if (install(42, &info, argc - 2, argv + 2)) { return 1; }
    check(init && translate && exiting);
    init(42, 0);
    if (getenv("EVIDENCE_SECOND_VCPU")) { init(42, 1); }
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
