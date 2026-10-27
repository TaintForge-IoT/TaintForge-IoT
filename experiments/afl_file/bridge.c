/* SPDX-License-Identifier: GPL-2.0-or-later
 * AFL forkserver and bitmap transport. No host-code instrumentation.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/shm.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#define MAP_SIZE 65536U
#define TF_MAX_INPUT (1024U * 1024U)
#define INFRA_FAILURE 86

static int transfer(int fd, void *buffer, size_t size, int sending)
{
    unsigned char *bytes = buffer;
    while (size) {
        ssize_t n = sending ? send(fd, bytes, size, MSG_NOSIGNAL) : read(fd, bytes, size);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return -1;
        bytes += n; size -= (size_t)n;
    }
    return 0;
}

static int pipe_write(int fd, const void *buffer, size_t size)
{
    const unsigned char *bytes = buffer;
    while (size) {
        ssize_t n = write(fd, bytes, size);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return -1;
        bytes += n; size -= (size_t)n;
    }
    return 0;
}

static int execute(int fd, const char *filename, unsigned char *map)
{
    int input = open(filename, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    struct stat st;
    if (input < 0) return INFRA_FAILURE;
    if (fstat(input, &st) || !S_ISREG(st.st_mode) || st.st_size < 1 ||
        st.st_size > TF_MAX_INPUT) { close(input); return INFRA_FAILURE; }
    size_t size = (size_t)st.st_size;
    unsigned char *bytes = malloc(size);
    if (!bytes) { close(input); return INFRA_FAILURE; }
    if (transfer(input, bytes, size, 0)) { close(input); free(bytes); return INFRA_FAILURE; }
    close(input);
    uint32_t length = htonl((uint32_t)size);
    int failed = transfer(fd, &length, sizeof(length), 1) || transfer(fd, bytes, size, 1);
    free(bytes);
    uint32_t header[4];
    if (failed || transfer(fd, header, sizeof(header), 0) ||
        ntohl(header[0]) != 0x54464131 || ntohl(header[1]) != 0 ||
        ntohl(header[2]) != 0 || ntohl(header[3]) != MAP_SIZE ||
        transfer(fd, map, MAP_SIZE, 0)) { close(fd); return INFRA_FAILURE; }
    close(fd);
    return 0;
}

static int send_connection(int control, int connection)
{
    char marker = 'C';
    struct iovec vector = {.iov_base = &marker, .iov_len = 1};
    union { struct cmsghdr align; unsigned char data[CMSG_SPACE(sizeof(int))]; } buffer;
    memset(&buffer, 0, sizeof(buffer));
    struct msghdr message = {.msg_iov = &vector, .msg_iovlen = 1,
        .msg_control = buffer.data, .msg_controllen = sizeof(buffer.data)};
    struct cmsghdr *header = CMSG_FIRSTHDR(&message);
    header->cmsg_level = SOL_SOCKET; header->cmsg_type = SCM_RIGHTS;
    header->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(header), &connection, sizeof(connection));
    ssize_t result;
    do { result = sendmsg(control, &message, MSG_NOSIGNAL); } while (result < 0 && errno == EINTR);
    return result == 1 ? 0 : -1;
}

int main(int argc, char **argv)
{
    if (argc != 3) { fprintf(stderr, "usage: tf-afl-bridge CONTROL_FD INPUT\n"); return 2; }
    char *descriptor_end = NULL;
    long descriptor = strtol(argv[1], &descriptor_end, 10);
    if (!*argv[1] || *descriptor_end || descriptor < 3 || descriptor > INT_MAX ||
        descriptor == 198 || descriptor == 199) return 2;
    int control = (int)descriptor;
    /* This marker also lets AFL++ identify the uninstrumented custom executor. */
    const char *id = getenv("__AFL_SHM_ID");
    if (!id || !*id) { fprintf(stderr, "requires AFL++ or afl-showmap\n"); return 2; }
    char *end = NULL;
    unsigned long number = strtoul(id, &end, 10);
    struct shmid_ds info;
    if (*end || number > INT_MAX || shmctl((int)number, IPC_STAT, &info) ||
        info.shm_segsz < MAP_SIZE) return 2;
    unsigned char *map = shmat((int)number, NULL, 0);
    if (map == (void *)-1) return 2;
    struct rlimit no_core = {0, 0};
    if (setrlimit(RLIMIT_CORE, &no_core)) return 2;
    uint32_t hello = 0;
    if (pipe_write(199, &hello, sizeof(hello))) {
        shmdt(map); return 2;
    }
    for (;;) {
        uint32_t command;
        if (transfer(198, &command, sizeof(command), 0)) break;
        int pair[2];
        if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, pair)) return 2;
        pid_t child = fork();
        if (child < 0) { close(pair[0]); close(pair[1]); return 2; }
        if (!child) {
            close(198); close(199); close(control); close(pair[1]);
            _exit(execute(pair[0], argv[2], map));
        }
        close(pair[0]);
        int sent = send_connection(control, pair[1]);
        close(pair[1]);
        if (sent) { kill(child, SIGKILL); waitpid(child, NULL, 0); return INFRA_FAILURE; }
        uint32_t pid = (uint32_t)child;
        if (pipe_write(199, &pid, sizeof(pid))) { kill(child, SIGKILL); waitpid(child, NULL, 0); break; }
        int status;
        while (waitpid(child, &status, 0) < 0) if (errno != EINTR) return 2;
        if (WIFSIGNALED(status) || (WIFEXITED(status) && WEXITSTATUS(status) == INFRA_FAILURE)) {
            fprintf(stderr, "TaintForge executor failed; refusing a fake target crash\n");
            shmdt(map); return INFRA_FAILURE;
        }
        uint32_t result = (uint32_t)status;
        if (pipe_write(199, &result, sizeof(result))) break;
    }
    shmdt(map);
    return 0;
}
