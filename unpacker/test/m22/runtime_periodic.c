#define _POSIX_C_SOURCE 200809L
#include "runtime_diag.h"
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

int main(int argc, char **argv) {
    TfRuntimeDiag diag;
    tf_runtime_diag_init(&diag);
    assert(!tf_runtime_profile_due(&diag, 1));
    char *options[] = {"runtime-profile=on", "runtime-profile-interval=10"};
    assert(tf_runtime_diag_options(&diag, 2, options, stderr));
    assert(tf_runtime_profile_due(&diag, 1));
    assert(!tf_runtime_profile_due(&diag, 1));
    assert(!tf_runtime_profile_due(&diag, 10));
    assert(tf_runtime_profile_due(&diag, 11));
    TfRuntimeDiagOptions before = diag.options;
    char *invalid[] = {"runtime-profile=off", "runtime-profile-interval=18446744073709551616"};
    assert(!tf_runtime_diag_options(&diag, 2, invalid, NULL));
    assert(!memcmp(&before, &diag.options, sizeof(before)));
    assert(tf_runtime_profile_due(&diag, UINT64_MAX));
    assert(!tf_runtime_profile_due(&diag, UINT64_MAX));
    assert(tf_runtime_diag_options(&diag, 2, options, stderr));
    if (argc > 1 && !strcmp(argv[1], "killed")) {
        for (uint64_t instructions = 1;; instructions++) {
            {
                TF_RUNTIME_SCOPE(&diag, TF_PHASE_INSTRUCTION);
                struct timespec delay = {.tv_nsec = 1000000};
                nanosleep(&delay, NULL);
            }
            if (tf_runtime_profile_due(&diag, instructions)) {
                fputs("[RUNTIME-PROFILE] ", stderr);
                assert(tf_runtime_profile_snapshot_json(stderr, &diag, "periodic", instructions));
                fflush(stderr);
            }
        }
    }
    {
        TF_RUNTIME_SCOPE(&diag, TF_PHASE_INSTRUCTION);
        { TF_RUNTIME_SCOPE(&diag, TF_PHASE_REG_SNAPSHOT); }
    }
    assert(diag.phases[TF_PHASE_INSTRUCTION].calls == 1);
    assert(diag.phases[TF_PHASE_REG_SNAPSHOT].calls == 1);
    assert(tf_runtime_profile_snapshot_json(stdout, &diag, "exit", 12));
    return 0;
}
