/* Test-only transport adapter for runners that forbid socket(AF_UNIX).
 * qemu_plugin_install and all guest callbacks come from the production source.
 * Only socket/connect use an inherited socketpair; peer credentials stay real.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

static int install_test_socket(int domain, int type, int protocol)
{
    const char *text = getenv("TF_OBSERVER_TEST_FD");
    if (!text || domain != AF_UNIX || protocol || !(type & SOCK_STREAM)) {
        errno = EINVAL;
        return -1;
    }
    char *end;
    long value = strtol(text, &end, 10);
    if (*end || value < 3 || value > 65535) {
        errno = EINVAL;
        return -1;
    }
    int result = dup((int)value);
    close((int)value);
    return result;
}

static int install_test_connect(int descriptor, const struct sockaddr *address, socklen_t length)
{
    (void)descriptor;
    if (!address || length < sizeof(address->sa_family) || address->sa_family != AF_UNIX) {
        errno = EINVAL;
        return -1;
    }
    return 0;
}

#define socket install_test_socket
#define connect install_test_connect
#include "observer.c"
