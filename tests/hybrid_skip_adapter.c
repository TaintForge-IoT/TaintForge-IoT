#include "../experiments/hybrid_rebuilt_v1/mutator.c"
#include <signal.h>

static volatile sig_atomic_t stopped;

static void on_stop(int sig)
{
    (void)sig;
    stopped = 1;
}

static int run_skip_stages(struct adapter *state, int ignore_signal)
{
    struct sigaction action = {0};
    action.sa_handler = ignore_signal ? SIG_IGN : on_stop;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGINT, &action, NULL) != 0) return 1;
    unsigned char parent = 'A';
    unsigned char *out = NULL;
    unsigned int calls = 0;
    state->fuzz_count = 16;
    while (!stopped && calls < 2100) {
        unsigned int budget = afl_custom_fuzz_count(state, &parent, 1);
        if (budget == 0) return 1;
        for (unsigned int i = 0; i < budget && calls < 2100 && !stopped; i++) {
            afl_custom_fuzz(state, &parent, 1, &out, NULL, 0, 1);
            calls++;
        }
    }
    return 0;
}

int main(int argc, char **argv)
{
    struct adapter *state = calloc(1, sizeof(*state));
    unsigned char parent[] = {'A'};
    unsigned char *output = NULL;
    if (!state) return 1;
    state->fd = STDIN_FILENO;
    state->trace_fd = STDOUT_FILENO;
    state->limit = sizeof(parent);
    state->fuzz_count = 2;
    if (argc == 2) {
        int result = run_skip_stages(state, strcmp(argv[1], "ignore-signal") == 0);
        afl_custom_deinit(state);
        return result;
    }

    if (afl_custom_fuzz_count(state, parent, sizeof(parent)) != 2) return 1;
    size_t skipped = afl_custom_fuzz(state, parent, 1, &output, NULL, 0, 1);
    if (skipped != 0) return 1;
    size_t size = afl_custom_fuzz(state, parent, 1, &output, NULL, 0, 1);
    if (size != 1 || !output || *output != '@') return 1;
    afl_custom_deinit(state);
    return 0;
}
