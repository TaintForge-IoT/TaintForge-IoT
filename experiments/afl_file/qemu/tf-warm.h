/* SPDX-License-Identifier: GPL-2.0-or-later
 * Included by linux-user/syscall.c, after plugin callbacks have returned.
 * Private TaintForge ABI 1; Linux i386, one guest task, serial children.
 */
#include <arpa/inet.h>
#include <dirent.h>
#include <poll.h>
#include <sys/prctl.h>
#include <sys/un.h>
#include <malloc.h>

#define TF_WARM_MAGIC 0x54465731U
static struct {
    char *input, *endpoint;
    uint64_t max_rss_mib;
    bool armed, child, entered;
    int observer_fd;
    void (*prepare)(void);
    void (*on_child)(void);
} tf_warm;

static G_NORETURN void tf_warm_fail(const char *reason)
{
    dprintf(2, "TF_WARM_ABORT reason=%s\n", reason);
    _exit(86);
}

int qemu_plugin_tf_warm_configure(const char *input, const char *endpoint,
                                uint64_t max_rss_mib, int observer_fd,
                                void (*prepare)(void), void (*on_child)(void))
{
    if (tf_warm.input || !input || input[0] != '/' || !endpoint ||
        strlen(endpoint) >= sizeof(((struct sockaddr_un *)0)->sun_path) ||
        !max_rss_mib || !prepare || !on_child) {
        return -1;
    }
    tf_warm.input = g_strdup(input);
    tf_warm.endpoint = g_strdup(endpoint);
    tf_warm.max_rss_mib = max_rss_mib;
    tf_warm.observer_fd = observer_fd;
    tf_warm.prepare = prepare;
    tf_warm.on_child = on_child;
    return 0;
}

void qemu_plugin_tf_warm_arm(void)
{
    tf_warm.armed = true;
}

static int tf_warm_io(int fd, void *data, size_t length, bool sending)
{
    char *bytes = data;
    while (length) {
        ssize_t n = sending ? send(fd, bytes, length, MSG_NOSIGNAL) :
                              recv(fd, bytes, length, 0);
        if (n < 0 && errno == EINTR) {
            continue;
        }
        if (n <= 0) {
            return -1;
        }
        bytes += n;
        length -= n;
    }
    return 0;
}

/* Inherited open-file descriptions and writable shared mappings do not roll
 * back with fork. Reject guest resources this MVP cannot reset faithfully. */
static uint32_t tf_warm_validate(int control)
{
    char buffer[8192], path[80], target[PATH_MAX];
    FILE *file = fopen("/proc/self/maps", "r");
    if (!file) {
        tf_warm_fail("proc_maps_required");
    }
    while (fgets(buffer, sizeof(buffer), file)) {
        unsigned long low, high;
        char perms[5];
        if (sscanf(buffer, "%lx-%lx %4s", &low, &high, perms) == 3 &&
            perms[1] == 'w' && perms[3] == 's' &&
            low >= guest_base && low - guest_base < (1ULL << 32)) {
            tf_warm_fail("guest_shared_writable_mapping");
        }
    }
    fclose(file);
    DIR *directory = opendir("/proc/self/fd");
    if (!directory) {
        tf_warm_fail("proc_fds_required");
    }
    struct dirent *entry;
    while ((entry = readdir(directory))) {
        char *end;
        long fd = strtol(entry->d_name, &end, 10);
        if (*end || fd <= 2 || fd == dirfd(directory) || fd == control ||
            fd == tf_warm.observer_fd) {
            continue;
        }
        snprintf(path, sizeof(path), "/proc/self/fd/%ld", fd);
        ssize_t n = readlink(path, target, sizeof(target) - 1);
        if (n < 0) {
            tf_warm_fail("fd_inventory_changed");
        }
        target[n] = 0;
        if (strncmp(target, "anon_inode:", 11) &&
            strncmp(target, "/memfd:tcg", 10)) {
            dprintf(2, "TF_WARM unsupported fd=%ld target=%s\n", fd, target);
            tf_warm_fail("inherited_guest_or_unknown_fd");
        }
    }
    closedir(directory);
    if (!getcwd(target, sizeof(target)) || strcmp(target, "/")) {
        tf_warm_fail("checkpoint_requires_root_cwd");
    }
    /* Release free glibc arenas after the explicit Phase-1 retirement. This
     * cannot free live/untracked allocations; the RSS gate remains mandatory. */
    malloc_trim(0);
    file = fopen("/proc/self/statm", "r");
    unsigned long pages, resident;
    if (!file || fscanf(file, "%lu %lu", &pages, &resident) != 2) {
        tf_warm_fail("rss_unavailable");
    }
    fclose(file);
    uint64_t bytes = (uint64_t)resident * sysconf(_SC_PAGESIZE);
    if (bytes > tf_warm.max_rss_mib * 1024 * 1024) {
        tf_warm_fail("phase1_resident_memory_not_released");
    }
    return (bytes + 1024 * 1024 - 1) / (1024 * 1024);
}

static void tf_warm_checkpoint(void)
{
    tf_warm.entered = true;
    tf_warm.prepare();  /* join observer host thread before fork_start */
    int control;
    if (g_str_has_prefix(tf_warm.endpoint, "fd:")) {
        char *end;
        long value = strtol(tf_warm.endpoint + 3, &end, 10);
        if (*end || value < 3 || value > INT_MAX) {
            tf_warm_fail("component_control_fd");
        }
        control = value;
    } else {
        control = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    }
    struct sockaddr_un address = { .sun_family = AF_UNIX };
    strcpy(address.sun_path, tf_warm.endpoint);
    if (control < 0 || (!g_str_has_prefix(tf_warm.endpoint, "fd:") &&
        connect(control, (struct sockaddr *)&address, sizeof(address)))) {
        tf_warm_fail("controller_connect");
    }
    uint32_t hello[] = {htonl(TF_WARM_MAGIC), htonl(1), htonl(getpid()),
                       htonl(tf_warm_validate(control))};
    if (tf_warm_io(control, hello, sizeof(hello), true)) {
        tf_warm_fail("hello");
    }
    for (;;) {
        uint32_t command[3];
        if (tf_warm_io(control, command, sizeof(command), false) ||
            ntohl(command[0]) != TF_WARM_MAGIC) {
            tf_warm_fail("controller_lost");
        }
        unsigned operation = ntohl(command[1]), timeout = ntohl(command[2]);
        if (operation == 0) {
            close(control);
            qemu_plugin_user_exit();
            _exit(0);
        }
        if (operation != 1 || timeout < 10 || timeout > 600000) {
            tf_warm_fail("command");
        }
        fork_start();
        pid_t child = fork();
        fork_end(child);
        if (child < 0) {
            tf_warm_fail("fork");
        }
        if (!child) {
            tf_warm.child = true;
            close(control);
            pid_t owner = getppid();
            if (prctl(PR_SET_PDEATHSIG, SIGKILL) || getppid() != owner || owner == 1) {
                tf_warm_fail("parent_lost");
            }
            tf_warm.on_child();
            return; /* same syscall and guest registers, no clone return value */
        }
        uint64_t start = g_get_monotonic_time();
        int status = 0;
        bool timed_out = false;
        for (;;) {
            pid_t done = waitpid(child, &status, WNOHANG);
            if (done == child) {
                break;
            }
            if (done < 0 && errno != EINTR) {
                tf_warm_fail("waitpid");
            }
            struct pollfd poller = { .fd = control, .events = POLLIN | POLLRDHUP };
            int n = poll(&poller, 1, 2);
            bool lost = n > 0 && poller.revents;
            if (lost || g_get_monotonic_time() - start > (uint64_t)timeout * 1000) {
                kill(child, SIGKILL);
                while (waitpid(child, &status, 0) < 0 && errno == EINTR) {}
                if (lost) {
                    tf_warm_fail("controller_lost_during_child");
                }
                timed_out = true;
                break;
            }
        }
        uint32_t response[] = {htonl(TF_WARM_MAGIC), htonl(child),
                               htonl(status), htonl(timed_out)};
        if (tf_warm_io(control, response, sizeof(response), true)) {
            tf_warm_fail("result");
        }
    }
}

static void tf_warm_syscall(int num, abi_long arg1, abi_long arg2)
{
#if defined(TARGET_I386) && !defined(TARGET_X86_64)
    if (!tf_warm.input || tf_warm.entered) {
        return;
    }
    abi_ulong address = num == TARGET_NR_open ? arg1 :
                        num == TARGET_NR_openat ? arg2 : 0;
    if (address) {
        char *path = lock_user_string(address);
        bool matches = path && !strcmp(path, tf_warm.input);
        if (path) {
            unlock_user(path, address, 0);
        }
        if (matches) {
            if (!tf_warm.armed) {
                tf_warm_fail("input_opened_before_retirement");
            }
            tf_warm_checkpoint();
        }
    }
#endif
}
