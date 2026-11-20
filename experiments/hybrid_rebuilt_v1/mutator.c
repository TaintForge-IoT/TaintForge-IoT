/* Live, variable-size AFL++ custom mutator for isolated recovered i386 ELFs.
 * The controller verifies DTA/DSE evidence; the adapter enforces transport,
 * bounds, ordering and that normal mutations stay within the DTA mask.
 * No guest code ever receives the control socket, token or AFL shared memory.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>

enum { TF_MAX_INPUT = 4096, TF_HEADER = 20, TF_REQUEST = 12,
       TF_SKIP_LIMIT = 1024, TF_STOP_GRACE_HOOKS = 32 };
struct adapter {
    int fd;
    int trace_fd;
    uint32_t sequence;
    size_t limit;
    unsigned int fuzz_count;
    unsigned int consecutive_skips;
    unsigned int shutdown_hooks_left;
    unsigned char output[TF_MAX_INPUT];
};

/* Per-run hook trace: C <planned fuzzes>, F <returned output>,
 * S <skipped callback>, L <consecutive skips at stop request>, X <clean deinit>.
 * One write is used per record; the private parent directory prevents guest
 * access. A partial trace is reported as such, never silently filled in.
 */
static void die(const char *reason);

static void hook_trace(struct adapter *state, const char *code, unsigned int value)
{
    if (state->trace_fd < 0) return;
    char row[48];
    int len = snprintf(row, sizeof(row), "%s %u\n", code, value);
    if (len <= 0 || (size_t)len >= sizeof(row) ||
        write(state->trace_fd, row, (size_t)len) != len)
        die("hook_trace_write");
}


static void die(const char *reason)
{
    dprintf(2, "TF_HYBRID_V2_MUTATOR_ERROR %s\n", reason);
    _exit(2);
}

/* AFL may finish its current custom stage after receiving SIGINT. Bound the
 * number of further calls even if the host ignores the shutdown request. */
static void check_shutdown_grace(struct adapter *state)
{
    if (state && state->shutdown_hooks_left) {
        if (state->shutdown_hooks_left == 1) die("skip_limit_stop_ignored");
        state->shutdown_hooks_left--;
    }
}

static void transfer(int fd, void *buffer, size_t length, int sending)
{
    unsigned char *pointer = buffer;
    while (length) {
        ssize_t count = sending ? send(fd, pointer, length, MSG_NOSIGNAL) : recv(fd, pointer, length, 0);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) die(sending ? "send_failed" : "receive_failed");
        pointer += count;
        length -= (size_t)count;
    }
}

static void put_u32(unsigned char *at, uint32_t value)
{
    value = htonl(value);
    memcpy(at, &value, 4);
}

static uint32_t get_u32(const unsigned char *at)
{
    uint32_t value;
    memcpy(&value, at, 4);
    return ntohl(value);
}

void *afl_custom_init(void *afl, unsigned int seed)
{
    (void)afl; (void)seed;
    const char *path = getenv("TF_HYBRID_SOCKET");
    const char *token = getenv("TF_HYBRID_TOKEN");
    const char *maximum = getenv("TF_HYBRID_MAX_INPUT");
    const char *fuzz_count = getenv("TF_HYBRID_FUZZ_COUNT");
    const char *trace_path = getenv("TF_HYBRID_HOOK_TRACE");
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    char *end = NULL;
    if (!path || !token || !maximum || strlen(token) != 64 ||
        strlen(path) >= sizeof(address.sun_path)) die("configuration");
    unsigned long limit = strtoul(maximum, &end, 10);
    if (!*maximum || !end || *end || limit < 1 || limit > TF_MAX_INPUT)
        die("invalid_max_input");
    struct adapter *state = calloc(1, sizeof(*state));
    if (!state) die("allocation");
    state->limit = (size_t)limit;
    state->trace_fd = -1;
    /* Keep the custom stage short in mixed mode so havoc can execute too. */
    state->fuzz_count = 16;
    if (fuzz_count) {
        end = NULL; errno = 0;
        unsigned long count = strtoul(fuzz_count, &end, 10);
        if (errno || !*fuzz_count || !end || *end || count < 1 || count > 16)
            die("invalid_custom_fuzz_count");
        state->fuzz_count = (unsigned int)count;
    }
    state->fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (state->fd < 0) die("socket");
    struct timeval timeout = {.tv_sec = 600};
    if (setsockopt(state->fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) ||
        setsockopt(state->fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)))
        die("socket_timeout");
    strcpy(address.sun_path, path);
    if (connect(state->fd, (struct sockaddr *)&address, sizeof(address))) die("connect");
    transfer(state->fd, (void *)token, 64, 1);
    if (trace_path) {
        if (!*trace_path) die("empty_hook_trace_path");
        state->trace_fd = open(trace_path,
            O_WRONLY | O_APPEND | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
            0600);
        if (state->trace_fd < 0) die("hook_trace_open");
    }
    return state;
}

unsigned int afl_custom_fuzz_count(void *data, const unsigned char *input, size_t size)
{
    struct adapter *state = data;
    (void)input;
    check_shutdown_grace(state);
    unsigned int count = state && size && size <= state->limit ? state->fuzz_count : 0U;
    if (state) hook_trace(state, "C", count);
    return count;
}

void afl_custom_splice_optout(void *data) { (void)data; }

size_t afl_custom_fuzz(void *data, unsigned char *input, size_t size,
                       unsigned char **output, unsigned char *other,
                       size_t other_size, size_t maximum)
{
    (void)other; (void)other_size;
    struct adapter *state = data;
    if (!state || !input || !output || !size || size > state->limit ||
        !maximum || ++state->sequence == 0) die("input_contract");
    check_shutdown_grace(state);
    unsigned char header[TF_REQUEST] = {'T', 'F', 'H', '2'};
    put_u32(header + 4, state->sequence);
    put_u32(header + 8, (uint32_t)size);
    transfer(state->fd, header, sizeof(header), 1);
    transfer(state->fd, input, size, 1);
    unsigned char answer[TF_HEADER];
    transfer(state->fd, answer, sizeof(answer), 0);
    if (memcmp(answer, "TFH2", 4) || get_u32(answer + 4) != state->sequence)
        die("response_sequence");
    uint32_t kind = get_u32(answer + 8);
    uint32_t mask_size = get_u32(answer + 12);
    uint32_t result_size = get_u32(answer + 16);
    if (kind == 0) {
        if (mask_size || result_size) die("invalid_skip_frame");
        *output = state->output;
        hook_trace(state, "S", 1);
        if (++state->consecutive_skips == TF_SKIP_LIMIT) {
            const char *only = getenv("AFL_CUSTOM_MUTATOR_ONLY");
            if (only && strcmp(only, "1") == 0) {
                state->shutdown_hooks_left = TF_STOP_GRACE_HOOKS + 1;
                hook_trace(state, "L", TF_SKIP_LIMIT);
                if (raise(SIGINT) != 0) die("skip_limit_signal");
            }
        }
        return 0;
    }
    if ((kind != 1 && kind != 2) || !result_size || result_size > state->limit ||
        result_size > maximum || mask_size != (size + 7U) / 8U)
        die("response_bounds");
    unsigned char mask[(TF_MAX_INPUT + 7) / 8];
    transfer(state->fd, mask, mask_size, 0);
    transfer(state->fd, state->output, result_size, 0);
    if (kind == 1) {
        if (result_size != size) die("masked_size_change");
        for (size_t i = 0; i < size; i++) {
            if (input[i] != state->output[i] && !(mask[i / 8] & (1U << (i % 8))))
                die("mutation_outside_DTA_mask");
        }
    }
    /* Kind=2 is already verified against an audited DSE job on the host;
       its length may differ from the parent selected by AFL. */
    *output = state->output;
    state->consecutive_skips = 0;
    hook_trace(state, "F", 1);
    return result_size;
}

int afl_custom_init_trim(void *data, unsigned char *input, size_t size)
{ (void)data; (void)input; (void)size; return 0; }
size_t afl_custom_trim(void *data, unsigned char **output)
{ struct adapter *state = data; if (state) *output = state->output; return 0; }
int afl_custom_post_trim(void *data, unsigned char success)
{ (void)data; (void)success; return 0; }
void afl_custom_deinit(void *data)
{
    struct adapter *state = data;
    if (state) {
        hook_trace(state, "X", 1);
        if (state->trace_fd >= 0) close(state->trace_fd);
        close(state->fd);
        free(state);
    }
}
