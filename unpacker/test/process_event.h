/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef TF_PROCESS_EVENT_H
#define TF_PROCESS_EVENT_H

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#ifdef __linux__
#include <sys/syscall.h>
#endif
#include <sys/wait.h>
#include <unistd.h>

#define I386_SIGCHLD 17U
#define I386_CLONE_CHILD_CLEARTID 0x00200000U
#define I386_CLONE_CHILD_SETTID   0x01000000U

static inline bool process_transition_i386(int64_t num) {
    return num == 2 || num == 11 || num == 120 || num == 190 || num == 358 || num == 435;
}

static inline bool private_fork_i386(int64_t num, uint32_t flags, uint32_t stack) {
    uint32_t tid_flags = I386_CLONE_CHILD_SETTID | I386_CLONE_CHILD_CLEARTID;
    return num == 2 || (num == 120 && !stack && (flags & ~tid_flags) == I386_SIGCHLD);
}

static inline bool tf_process_event(int channel, char kind, int32_t value, pid_t observe) {
    int32_t packet[2] = {kind, value};
    struct iovec vec = {.iov_base = packet, .iov_len = sizeof(packet)};
    struct msghdr msg = {.msg_iov = &vec, .msg_iovlen = 1};
    union { struct cmsghdr align; char buf[CMSG_SPACE(sizeof(int))]; } control = {0};
    int pidfd = -1;
#ifdef SYS_pidfd_open
    if (observe > 0)
        pidfd = syscall(SYS_pidfd_open, observe, 0);
#endif
    if (pidfd >= 0 && kind == 'F') {
        /* With SIGCHLD ignored the numeric PID could already have been
         * recycled. Only pass a pidfd for a child we can still wait on. */
        siginfo_t info = {0};
        int rc;
        do {
            rc = waitid(P_PID, (id_t)observe, &info, WEXITED | WNOHANG | WNOWAIT);
        } while (rc < 0 && errno == EINTR);
        if (rc < 0) {
            close(pidfd);
            pidfd = -1;
        }
    }
    if (pidfd >= 0) {
        msg.msg_control = control.buf;
        msg.msg_controllen = sizeof(control.buf);
        struct cmsghdr *header = CMSG_FIRSTHDR(&msg);
        header->cmsg_level = SOL_SOCKET;
        header->cmsg_type = SCM_RIGHTS;
        header->cmsg_len = CMSG_LEN(sizeof(pidfd));
        memcpy(CMSG_DATA(header), &pidfd, sizeof(pidfd));
    }
    ssize_t n;
    do {
        n = sendmsg(channel, &msg, MSG_DONTWAIT | MSG_NOSIGNAL);
    } while (n < 0 && errno == EINTR);
    if (pidfd >= 0)
        close(pidfd);
    return n == sizeof(packet);
}

#endif
