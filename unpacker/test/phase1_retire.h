#ifndef TAINTFORGE_PHASE1_RETIRE_H
#define TAINTFORGE_PHASE1_RETIRE_H

#include "phase1_io.h"

/* Single-vCPU retirement for controlled guests; no hostile-guest authentication. */
typedef enum {
    TF_RETIRE_OFF, TF_RETIRE_ACTIVE, TF_RETIRE_PREPARING,
    TF_RETIRE_REQUESTED, TF_RETIRE_REMOVED, TF_RETIRE_RELEASED
} TfRetireState;

typedef struct {
    TfRetireState state;
    int fd;
    pid_t controller;
    uid_t controller_uid;
    unsigned timeout_ms;
    char socket_path[108], nonce[33];
    char session[121], attempt[121], instance[121];
    uint64_t boundary, candidate, oep, decision_pc, decision_seq, epoch;
    uint32_t generation;
    bool on_verdict;
    uint64_t instruction_limit, instructions_seen;
    char manifest_sha256[65];
} TfRetire;

bool tf_retire_configure(TfRetire *r, TfPhase1Io *io, int argc, char **argv,
                         unsigned api, const char *target, bool system);
void tf_retire_verdict(TfRetire *r, TfPhase1Io *io, uint64_t candidate, uint64_t oep);
/* Check after finalizing the previous instruction; no uninstall/free here. */
bool tf_retire_due(TfRetire *r);
void tf_retire_bind_continuation(TfRetire *r, TfPhase1Io *io, uint64_t pc);
/* After capture commits, wait for a digest-bound permit in an instruction callback. */
void tf_retire_permit(TfRetire *r, TfPhase1Io *io);
/* Completion callbacks must never wait for the controller or read the guest. */
void tf_retire_removed(TfRetire *r);
void tf_retire_released(TfRetire *r, uint64_t pages, uint64_t bitmaps,
                        uint64_t register_buffers, uint64_t wiped_bytes,
                        unsigned owners_remaining);
void tf_retire_close(TfRetire *r);
_Noreturn void tf_retire_abort(int code, const char *reason);
void tf_retire_wipe(void *data, size_t size);

#endif
