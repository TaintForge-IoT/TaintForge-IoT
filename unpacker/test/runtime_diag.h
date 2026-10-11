#ifndef TAINTFORGE_RUNTIME_DIAG_H
#define TAINTFORGE_RUNTIME_DIAG_H

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <glib.h>

typedef enum {
    TF_LOG_SUMMARY,
    TF_LOG_EVENTS,
    TF_LOG_ROOTS
} TfRuntimeLog;

typedef enum {
    TF_PHASE_INSTRUCTION,
    TF_PHASE_MEMORY,
    TF_PHASE_CODE_WRITE,
    TF_PHASE_TRANSLATION,
    TF_PHASE_SYSCALL,
    TF_PHASE_SYSCALL_RETURN,
    TF_PHASE_CONTROL_FLOW,
    TF_PHASE_REG_SNAPSHOT,
    TF_PHASE_ES_SNAPSHOT,
    TF_PHASE_AUX_RECORD,
    TF_PHASE_ARCHIVE,
    TF_PHASE_TRACE_CAPTURE,
    TF_PHASE_REGISTER_DTA,
    TF_PHASE_SEED,
    TF_PHASE_IR,
    TF_PHASE_DSE,
    TF_PHASE_DUMP,
    TF_PHASE_EVENT_LOG,
    TF_PHASE_SHUTDOWN,
    TF_PHASE_COUNT
} TfRuntimePhase;

typedef struct {
    uint64_t calls;
    uint64_t total_us;
    uint64_t max_us;
} TfRuntimeMetric;

typedef struct {
    TfRuntimeLog log;
    bool profile;
    uint64_t progress_interval;
    uint64_t profile_interval;
} TfRuntimeDiagOptions;

typedef struct {
    TfRuntimeDiagOptions options;
    uint64_t start_us;
    uint64_t next_progress;
    uint64_t next_profile;
    TfRuntimeMetric phases[TF_PHASE_COUNT];
} TfRuntimeDiag;

typedef struct {
    TfRuntimeDiag *diag;
    TfRuntimePhase phase;
    uint64_t start_us;
} TfRuntimeScope;

void tf_runtime_diag_init(TfRuntimeDiag *diag);
/* Call before callbacks start. Failure leaves the options unchanged. */
bool tf_runtime_diag_options(TfRuntimeDiag *diag, int argc, char **argv, FILE *errors);
const char *tf_runtime_log_name(TfRuntimeLog level);
const char *tf_runtime_phase_name(TfRuntimePhase phase);
void tf_runtime_scope_end(TfRuntimeScope *scope);
/* Metrics are inclusive wall times; nested phases must not be added together. */
bool tf_runtime_profile_json(FILE *out, const TfRuntimeDiag *diag);
bool tf_runtime_profile_snapshot_json(FILE *out, const TfRuntimeDiag *diag,
                                      const char *stage, uint64_t instructions);
bool tf_runtime_profile_due(TfRuntimeDiag *diag, uint64_t instructions);
/* Claims one progress interval atomically; zero disables progress. */
bool tf_runtime_progress_due(TfRuntimeDiag *diag, uint64_t instructions);

static inline bool tf_runtime_log_enabled(const TfRuntimeDiag *diag, TfRuntimeLog level) {
    return diag && diag->options.log >= level;
}

static inline TfRuntimeScope tf_runtime_scope_begin(TfRuntimeDiag *diag, TfRuntimePhase phase) {
    if (!diag || !diag->options.profile || (unsigned)phase >= TF_PHASE_COUNT)
        return (TfRuntimeScope){0};
    return (TfRuntimeScope){diag, phase, (uint64_t)g_get_monotonic_time()};
}

static inline void tf_runtime_scope_cleanup(TfRuntimeScope *scope) {
    if (scope->diag)
        tf_runtime_scope_end(scope);
}

/* The plugin is built with GNU C. Cleanup covers every early return. */
#define TF_RUNTIME_SCOPE_NAME_(a, b) a##b
#define TF_RUNTIME_SCOPE_NAME(a, b) TF_RUNTIME_SCOPE_NAME_(a, b)
#define TF_RUNTIME_SCOPE(diag, phase)                                                              \
    TfRuntimeScope TF_RUNTIME_SCOPE_NAME(tf_runtime_scope_, __LINE__)                              \
        __attribute__((cleanup(tf_runtime_scope_cleanup))) = tf_runtime_scope_begin(diag, phase)

#endif
