/* Fixed-parser acceptance adapter. No external target or variable-size input. */
#define _GNU_SOURCE
#include <errno.h>
#include <arpa/inet.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>

enum { INPUT_SIZE = 32 };
struct adapter { int fd; uint32_t sequence; unsigned char output[INPUT_SIZE]; };

static void fail(const char *reason)
{
    dprintf(2, "TF_HYBRID_MUTATOR_ERROR %s\n", reason);
    _exit(2);
}

static void transfer(int fd, void *buffer, size_t size, int sending)
{
    unsigned char *bytes = buffer;
    while (size) {
        ssize_t done = sending ? send(fd, bytes, size, MSG_NOSIGNAL) : recv(fd, bytes, size, 0);
        if (done < 0 && errno == EINTR) continue;
        if (done <= 0) fail(sending ? "controller_send" : "controller_receive");
        bytes += done;
        size -= (size_t)done;
    }
}

void *afl_custom_init(void *afl, unsigned int seed)
{
    (void)afl; (void)seed;
    const char *path = getenv("TF_HYBRID_SOCKET");
    const char *token = getenv("TF_HYBRID_TOKEN");
    struct sockaddr_un address = {.sun_family=AF_UNIX};
    if (!path || !token || strlen(token) != 64 || strlen(path) >= sizeof(address.sun_path))
        fail("configuration");
    struct adapter *state = calloc(1, sizeof(*state));
    if (!state) fail("allocation");
    state->fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (state->fd < 0) fail("socket");
    struct timeval timeout = {.tv_sec=600};
    if (setsockopt(state->fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) ||
        setsockopt(state->fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)))
        fail("socket_timeout");
    strcpy(address.sun_path, path);
    if (connect(state->fd, (struct sockaddr *)&address, sizeof(address))) fail("controller_connect");
    transfer(state->fd, (void *)token, 64, 1);
    return state;
}

unsigned int afl_custom_fuzz_count(void *data, const unsigned char *input, size_t size)
{ (void)data; (void)input; return size == INPUT_SIZE ? 16 : 0; }

void afl_custom_splice_optout(void *data) { (void)data; }

size_t afl_custom_fuzz(void *data, unsigned char *input, size_t size, unsigned char **output,
                       unsigned char *other, size_t other_size, size_t maximum)
{
    (void)other; (void)other_size;
    struct adapter *state = data;
    if (!state || size != INPUT_SIZE || maximum < INPUT_SIZE || ++state->sequence == 0)
        fail("input_contract");
    unsigned char request[8 + INPUT_SIZE] = {'T','F','H','1'};
    uint32_t sequence = htonl(state->sequence);
    memcpy(request + 4, &sequence, 4);
    memcpy(request + 8, input, INPUT_SIZE);
    transfer(state->fd, request, sizeof(request), 1);
    unsigned char response[4 + INPUT_SIZE];
    transfer(state->fd, response, sizeof(response), 0);
    unsigned mask = response[1];
    if ((response[0] != 1 && response[0] != 2) || !mask || (mask & ~15U) ||
        response[2] || response[3] != INPUT_SIZE)
        fail("response_contract");
    for (size_t index = 0; index < INPUT_SIZE; ++index)
        if (input[index] != response[4 + index] && (index >= 4 || !(mask & (1U << index))))
            fail("mutation_outside_DTA_mask");
    memcpy(state->output, response + 4, INPUT_SIZE);
    *output = state->output;
    return INPUT_SIZE;
}

int afl_custom_init_trim(void *data, unsigned char *input, size_t size)
{ (void)data; (void)input; (void)size; return 0; }
size_t afl_custom_trim(void *data, unsigned char **output)
{ struct adapter *state = data; *output = state->output; return INPUT_SIZE; }
int afl_custom_post_trim(void *data, unsigned char success)
{ (void)data; (void)success; return 0; }

void afl_custom_deinit(void *data)
{ struct adapter *state = data; if (state) { close(state->fd); free(state); } }
