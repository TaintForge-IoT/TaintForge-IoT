/* Transport entry is injected for a unit test; packets, deadlines, peer
 * credentials and native protocol validation use a real inherited socketpair.
 * This does not test AF_UNIX listener/connect or QEMU's uninstall scheduler. */
#define _GNU_SOURCE
#include <sys/socket.h>
#include <stdlib.h>
static int test_fd;
static int test_socket(int domain, int type, int protocol) {
    (void)domain; (void)type; (void)protocol;
    return test_fd;
}
static int test_connect(int fd, const struct sockaddr *address, socklen_t length) {
    (void)fd; (void)address; (void)length;
    return 0;
}
#define socket test_socket
#define connect test_connect
#include "../../unpacker/test/phase1_retire.c"
#undef socket
#undef connect

int main(int argc, char **argv) {
    if (argc != 4) return 2;
    test_fd = atoi(argv[1]);
    TfPhase1Io io = {.enabled = true, .finished = true, .owner = getpid(),
                    .manifest_path = argv[2], .session = "s", .attempt = "a", .instance = "i"};
    TfRetire r = {.state = TF_RETIRE_PREPARING, .fd = -1, .controller = getppid(),
        .controller_uid = geteuid(),
        .timeout_ms = 150, .candidate = 1, .oep = 4096, .decision_pc = 4100,
        .decision_seq = 23, .boundary = 8192};
    strcpy(r.nonce, "12345678901234567890123456789012");
    strcpy(r.session, "s"); strcpy(r.attempt, "a"); strcpy(r.instance, "i");
    strcpy(r.socket_path, "/unit-test-entry");
    if (!strcmp(argv[3], "wrong-peer")) r.controller++;
    tf_retire_permit(&r, &io);
    tf_retire_removed(&r);
    tf_retire_released(&r, 1, 1, 1, 512, 0);
    return 0;
}
