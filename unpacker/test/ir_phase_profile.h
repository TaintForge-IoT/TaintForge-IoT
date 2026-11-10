#ifndef IR_PHASE_PROFILE_H
#define IR_PHASE_PROFILE_H

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>

typedef enum {
    IR_PHASE_CAPTURE,
    IR_PHASE_LIFT,
    IR_PHASE_REPLAY_CHECK,
    IR_PHASE_SSA_OPTIMIZE,
    IR_PHASE_BRANCH_CATALOG,
    IR_PHASE_SMT_ENCODE,
    IR_PHASE_QUERY,
    IR_PHASE_QUERY_CONSTRAINTS,
    IR_PHASE_VERIFY_PREFIX,
    IR_PHASE_VERIFY_WITNESS,
    IR_PHASE_COUNT
} IrPhase;

typedef struct {
    uint64_t ns;
    bool measured;
} IrPhaseTime;

typedef struct {
    IrPhaseTime phases[IR_PHASE_COUNT];
    struct {
        IrPhaseTime time;
        int result;
        bool recorded, returned, api_ok;
    } checks[2];
    uint32_t solver_checks, prefix_constraints, encoded_values;
} IrPhaseProfile;

/* Set only while the plugin prepares one selected-prefix report. */
extern _Thread_local IrPhaseProfile *ir_phase_profile;

static inline uint64_t ir_phase_clock(void) {
    int saved = errno;
    struct timespec value;
    int status = clock_gettime(CLOCK_MONOTONIC, &value);
    errno = saved;
    return status ? UINT64_MAX
                  : (uint64_t)value.tv_sec * UINT64_C(1000000000) + (uint64_t)value.tv_nsec;
}

static inline IrPhaseTime ir_phase_elapsed(uint64_t start) {
    if (start == UINT64_MAX)
        return (IrPhaseTime){0};
    uint64_t stop = ir_phase_clock();
    if (stop == UINT64_MAX || stop < start)
        return (IrPhaseTime){0};
    return (IrPhaseTime){.ns = stop - start, .measured = true};
}

static inline uint64_t ir_phase_start(void) {
    return ir_phase_profile ? ir_phase_clock() : UINT64_MAX;
}

static inline void ir_phase_stop(IrPhase phase, uint64_t start) {
    if (ir_phase_profile)
        ir_phase_profile->phases[phase] = ir_phase_elapsed(start);
}

#endif
