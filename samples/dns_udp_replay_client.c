/* Benign integration client: DNS (including TCP fallback), TCP and UDP C2.
 * With no arguments, also exercise libc getaddrinfo inside the prepared rootfs.
 */
#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

static unsigned u16(const unsigned char *p) { return ((unsigned)p[0] << 8) | p[1]; }
static void put16(unsigned char *p, unsigned n) { p[0] = n >> 8; p[1] = n; }

static int endpoint(const char *ip, int port, int type) {
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_port = htons((uint16_t)port)};
    if (port < 1 || port > 65535 || inet_pton(AF_INET, ip, &address.sin_addr) != 1) return -1;
    int fd = socket(AF_INET, type, 0);
    if (fd < 0) return -1;
    struct timeval timeout = {.tv_sec = 3};
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) ||
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) ||
        connect(fd, (struct sockaddr *)&address, sizeof(address))) { close(fd); return -1; }
    return fd;
}

static int write_all(int fd, const unsigned char *data, size_t size) {
    while (size) {
        ssize_t n = send(fd, data, size, MSG_NOSIGNAL);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return -1;
        data += n; size -= (size_t)n;
    }
    return 0;
}

static int read_all(int fd, unsigned char *data, size_t size) {
    while (size) {
        ssize_t n = recv(fd, data, size, 0);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return -1;
        data += n; size -= (size_t)n;
    }
    return 0;
}

static size_t skip_name(const unsigned char *packet, size_t size, size_t pos) {
    for (unsigned labels = 0; labels < 128 && pos < size; labels++) {
        unsigned len = packet[pos++];
        if (!len) return pos;
        if ((len & 0xc0) == 0xc0) return pos < size ? pos + 1 : 0;
        if (len > 63 || pos + len > size) return 0;
        pos += len;
    }
    return 0;
}

static int dns_lookup(const char *server, int udp_port, int tcp_port, const char *name,
                      int force_tcp, unsigned id, char output[INET_ADDRSTRLEN]) {
    unsigned char query[512] = {0}, answer[65535], prefix[2];
    size_t length = 12;
    put16(query, id); put16(query + 2, 0x0100); put16(query + 4, 1);
    const char *part = name;
    while (*part) {
        const char *dot = strchr(part, '.');
        size_t n = dot ? (size_t)(dot - part) : strlen(part);
        if (!n || n > 63 || length + n + 6 > sizeof(query)) return -1;
        query[length++] = (unsigned char)n;
        memcpy(query + length, part, n); length += n;
        if (!dot) break;
        part = dot + 1;
    }
    query[length++] = 0; put16(query + length, 1); put16(query + length + 2, 1); length += 4;
    for (int tcp = force_tcp; tcp <= 1; tcp++) {
        int fd = endpoint(server, tcp ? tcp_port : udp_port, tcp ? SOCK_STREAM : SOCK_DGRAM);
        if (fd < 0) return -1;
        ssize_t count = -1;
        if (tcp) {
            put16(prefix, (unsigned)length);
            if (!write_all(fd, prefix, 2) && !write_all(fd, query, length) && !read_all(fd, prefix, 2)) {
                count = (ssize_t)u16(prefix);
                if (count < 12 || read_all(fd, answer, (size_t)count)) count = -1;
            }
        } else if (send(fd, query, length, 0) == (ssize_t)length) {
            count = recv(fd, answer, sizeof(answer), 0);
        }
        close(fd);
        if (count < 12 || u16(answer) != id || !(u16(answer + 2) & 0x8000) || (u16(answer + 2) & 15)) return -1;
        if ((u16(answer + 2) & 0x0200) && !tcp) continue;
        size_t pos = skip_name(answer, (size_t)count, 12);
        if (!pos || pos + 4 > (size_t)count) return -1;
        pos += 4;
        for (unsigned i = 0; i < u16(answer + 6); i++) {
            pos = skip_name(answer, (size_t)count, pos);
            if (!pos || pos + 10 > (size_t)count) return -1;
            unsigned kind = u16(answer + pos), cls = u16(answer + pos + 2), n = u16(answer + pos + 8);
            pos += 10;
            if (pos + n > (size_t)count) return -1;
            if (kind == 1 && cls == 1 && n == 4) return inet_ntop(AF_INET, answer + pos, output, INET_ADDRSTRLEN) ? 0 : -1;
            pos += n;
        }
        return -1;
    }
    return -1;
}

int main(int argc, char **argv) {
    char dns_ip[INET_ADDRSTRLEN], domain[254];
    int dns_udp, dns_tcp, c2_tcp, c2_udp;
    if (argc == 7) {
        if (strlen(argv[1]) >= sizeof(dns_ip) || strlen(argv[6]) >= sizeof(domain)) return 2;
        strcpy(dns_ip, argv[1]); strcpy(domain, argv[6]);
        dns_udp = atoi(argv[2]); dns_tcp = atoi(argv[3]); c2_tcp = atoi(argv[4]); c2_udp = atoi(argv[5]);
    } else if (argc == 1) {
        FILE *config = fopen("/etc/taintforge-network-probe.conf", "r");
        if (!config) { perror("probe config"); return 2; }
        int fields = fscanf(config, "%15s %d %d %d %d %253s", dns_ip, &dns_udp, &dns_tcp, &c2_tcp, &c2_udp, domain);
        fclose(config);
        if (fields != 6) return 2;
    } else return 2;
    char resolved[INET_ADDRSTRLEN], explicit_ip[INET_ADDRSTRLEN];
    if (argc == 1) {
        struct addrinfo hints = {.ai_family = AF_INET, .ai_socktype = SOCK_STREAM}, *addresses = NULL;
        int error = getaddrinfo(domain, NULL, &hints, &addresses);
        if (error) { fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(error)); return 10; }
        const struct sockaddr_in *address = (const struct sockaddr_in *)addresses->ai_addr;
        int ok = inet_ntop(AF_INET, &address->sin_addr, resolved, sizeof(resolved)) != NULL;
        freeaddrinfo(addresses);
        if (!ok) return 10;
    } else if (dns_lookup(dns_ip, dns_udp, dns_tcp, domain, 0, 0x1234, resolved)) return 11;
    if (dns_lookup(dns_ip, dns_udp, dns_tcp, domain, 0, 0x4321, explicit_ip) || strcmp(resolved, explicit_ip)) return 12;
    if (dns_lookup(dns_ip, dns_udp, dns_tcp, domain, 1, 0xabcd, explicit_ip) || strcmp(resolved, explicit_ip)) return 13;
    int tcp = endpoint(resolved, c2_tcp, SOCK_STREAM);
    unsigned char response[64];
    if (tcp < 0) { perror("TCP connect"); return 20; }
    int tcp_ok = !write_all(tcp, (const unsigned char *)"hello", 5) && !shutdown(tcp, SHUT_WR) && !read_all(tcp, response, 5) && !memcmp(response, "world", 5);
    close(tcp);
    if (!tcp_ok) return 21;
    int udp = endpoint(resolved, c2_udp, SOCK_DGRAM);
    if (udp < 0) return 30;
    int udp_ok = send(udp, "hello", 5, 0) == 5 && recv(udp, response, sizeof(response), 0) == 5 && !memcmp(response, "world", 5);
    close(udp);
    if (!udp_ok) return 31;
    puts("dns tcp udp ok");
    return 0;
}
