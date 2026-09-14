#ifndef TAINTFORGE_IR_RUNTIME_H
#define TAINTFORGE_IR_RUNTIME_H

#include "ir_replay.h"
#include "ir_ssa.h"

#define IR_RUNTIME_MAX_WINDOW 4096U
#define IR_RUNTIME_MAX_CHECKS 1024U

typedef struct {
    uint32_t window_steps, max_checks;
    size_t capture_bytes;
    IrReplayOptions replay;
    IrEvalLimits eval;
    bool trace_ssa;
    IrAnalysisLimits analysis;
    ReplaySourceLimits sources;
} IrRuntimeOptions;

typedef enum {
    IR_RUNTIME_PROBE,
    IR_RUNTIME_CANDIDATE
} IrRuntimeKind;

typedef struct {
    IrRuntimeKind kind;
    uint64_t trigger_seq;
    /* Optional exact lower bound. A budget clips its prefix and records that
     * fact. Zero requests the most recent window before the trigger. */
    uint64_t first_seq;
    bool require_first_seq;
    uint32_t vcpu_index;
    uint64_t candidate_address;
    /* Optional full-GPR hint, checked against the decoded operand. Use -1 for
     * memory/RET targets or to select the target solely from the instruction. */
    int target_gpr;
    bool collector_serialized;
    bool flag_observations_trusted;
} IrRuntimeRequest;

enum {
    IR_RUNTIME_WINDOW_CLIPPED = 1U << 0,
    IR_RUNTIME_CAPTURE_FAILED = 1U << 1,
    IR_RUNTIME_EMPTY_WINDOW = 1U << 2,
    IR_RUNTIME_TARGET_UNSUPPORTED = 1U << 3,
    IR_RUNTIME_TARGET_EVIDENCE = 1U << 4,
    IR_RUNTIME_CONCURRENCY = 1U << 5,
    IR_RUNTIME_CHECK_BUDGET = 1U << 6,
    IR_RUNTIME_BAD_REQUEST = 1U << 7,
    IR_RUNTIME_START_MISSING = 1U << 8,
    IR_RUNTIME_FLAGS_UNVERIFIED = 1U << 9,
    IR_RUNTIME_SSA_FAILED = 1U << 10
};

typedef struct {
    IrRuntimeRequest request;
    IrReplayCheckStatus status;
    uint32_t issues;
    uint64_t first_seq;
    uint32_t selected_steps;
    ReplayInputStatus capture_status;
    uint32_t capture_issues;
    uint64_t initial_gpr[IR_X86_GPR_COUNT];
    uint32_t initial_gpr_mask, initial_eflags;
    bool initial_eflags_valid;
    IrReplayBuildInfo build;
    IrReplayCheckResult check;
    bool ssa_attempted;
    IrTraceSsaResult ssa;
    uint32_t active_before_ssa, active_after_ssa;
    uint64_t ssa_us;
    ReplaySourceInfo sources;
    IrInputInfo inputs;
    bool inputs_available;
    bool build_attempted, check_attempted;
    bool stopped_identity_valid;
    TraceEntry stopped;
    uint16_t stopped_native_id;
    bool trigger_identity_valid;
    TraceEntry trigger;
    size_t capture_bytes, replay_bytes;
    uint32_t ir_instructions, ir_values, ir_blocks, observations;
    uint64_t capture_us, build_us, check_us, total_us;
} IrRuntimeReport;

typedef struct {
    IrRuntimeOptions options;
    uint32_t checks, matches, mismatches, unknown, errors;
    uint64_t skipped_budget, selected_steps, lifted_steps, total_us;
    size_t peak_capture_bytes, peak_replay_bytes, peak_evaluator_bytes;
} IrRuntime;

IrRuntimeOptions ir_runtime_default_options(void);
bool ir_runtime_init(IrRuntime *runtime, const IrRuntimeOptions *options);
/* Must run while trace/aux/meta owners are serialized. No live guest reads,
 * borrowed objects, retained IR or solver calls. Runs at most max_checks;
 * returns false on an exhausted check budget (an UNKNOWN report is filled).
 * MATCH covers exactly [first_seq, trigger_seq), never the omitted prefix,
 * complete program, missing paths, or OEP validity. */
bool ir_runtime_check(IrRuntime *runtime, const TraceBuffer *trace, const DseAuxRing *aux,
                      const IrRuntimeRequest *request, IrRuntimeReport *report);
/* Same registry as collector labels. Captured records are owned and no registry
 * pointer enters the report. Source uncertainty is separate from concrete
 * consistency; MATCH does not assert an externally controllable input model. */
bool ir_runtime_check_sources(IrRuntime *runtime, const TraceBuffer *trace, const DseAuxRing *aux,
                              ProvRegistry *registry, const IrRuntimeRequest *request,
                              IrRuntimeReport *report);
const char *ir_runtime_status_name(IrReplayCheckStatus status);
bool ir_runtime_report_json(FILE *stream, const IrRuntimeReport *report);
bool ir_runtime_summary_json(FILE *stream, const IrRuntime *runtime);

#endif
