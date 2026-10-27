#define _POSIX_C_SOURCE 200809L

#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#define TARGET_IP "198.51.100.10"
#define TARGET_PORT 48101
#define EXPECTED_RESPONSE "world"

static int send_all(
    int fd,
    const unsigned char *buffer,
    size_t size
) {
    size_t offset = 0;

    while (offset < size) {
        ssize_t written = send(
            fd,
            buffer + offset,
            size - offset,
            0
        );

        if (written < 0) {
            if (errno == EINTR) {
                continue;
            }

            perror("send");
            return -1;
        }

        if (written == 0) {
            fprintf(stderr, "send returned zero\n");
            return -1;
        }

        offset += (size_t)written;
    }

    return 0;
}

int main(int argc, char **argv) {
    const unsigned char request[] = "hello";
    /* One extra byte detects overlong responses as well as short reads. */
    unsigned char response[sizeof(EXPECTED_RESPONSE)];
    const char *target_ip = TARGET_IP;
    long target_port = TARGET_PORT;

    if (argc == 3) {
        char *end = NULL;
        errno = 0;
        target_ip = argv[1];
        target_port = strtol(argv[2], &end, 10);
        if (errno != 0 || end == argv[2] || *end != '\0'
            || target_port < 1 || target_port > 65535) {
            fprintf(stderr, "invalid port\n");
            return 2;
        }
    } else if (argc != 1) {
        fprintf(stderr, "usage: %s [IPv4 PORT]\n", argv[0]);
        return 2;
    }

    int fd = socket(AF_INET, SOCK_STREAM, 0);

    if (fd < 0) {
        perror("socket");
        return 10;
    }

    struct timeval timeout = {.tv_sec = 5, .tv_usec = 0};
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0
        || setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) < 0) {
        perror("setsockopt");
        close(fd);
        return 10;
    }

    struct sockaddr_in address;
    memset(&address, 0, sizeof(address));

    address.sin_family = AF_INET;
    address.sin_port = htons((unsigned short)target_port);

    if (
        inet_pton(
            AF_INET,
            target_ip,
            &address.sin_addr
        )
        != 1
    ) {
        fprintf(stderr, "inet_pton failed\n");
        close(fd);
        return 11;
    }

    if (
        connect(
            fd,
            (struct sockaddr *)&address,
            sizeof(address)
        )
        < 0
    ) {
        perror("connect");
        close(fd);
        return 12;
    }

    if (
        send_all(
            fd,
            request,
            sizeof(request) - 1
        )
        != 0
    ) {
        close(fd);
        return 13;
    }

    /*
     * Mark the complete request while keeping the read half open for the reply.
     */
    if (shutdown(fd, SHUT_WR) < 0) {
        perror("shutdown");
        close(fd);
        return 14;
    }

    size_t received = 0;
    while (received < sizeof(response)) {
        ssize_t chunk = recv(fd, response + received, sizeof(response) - received, 0);
        if (chunk < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("recv");
            close(fd);
            return 15;
        }
        if (chunk == 0) {
            break;
        }
        received += (size_t)chunk;
    }

    close(fd);

    if (
        received != sizeof(EXPECTED_RESPONSE) - 1
        || memcmp(
            response,
            EXPECTED_RESPONSE,
            sizeof(EXPECTED_RESPONSE) - 1
        )
        != 0
    ) {
        fprintf(stderr, "unexpected response\n");
        return 17;
    }

    if (fwrite(response, 1, received, stdout) != received
        || fputc('\n', stdout) == EOF || fflush(stdout) == EOF) {
        perror("write");
        return 16;
    }

    return 0;
}
