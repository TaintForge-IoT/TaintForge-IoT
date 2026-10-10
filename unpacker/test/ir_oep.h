#ifndef TAINTFORGE_IR_OEP_H
#define TAINTFORGE_IR_OEP_H

#include "ir_branches.h"
#include "ir_replay.h"
#include "ir_ssa.h"

/* Explicit boundary cells. Register bytes use a state key and bit offset;
 * memory uses a state key and byte address. These are NOT provenance labels
 * or promises that a file/network input can realize this boundary state. */
typedef struct {
    IrInputKind kind;
    uint64_t state_key, address;
    uint8_t bit_offset, width;
    uint32_t same_as; /* 1-based earlier selector, zero means independent.
                      * The referenced selector must itself be independent. */
} IrOepInput;

/* Explicit caller policy, invoked once after construction. Selectors remain
 * caller-owned and valid until verify returns. It may inspect the immutable
 * catalogue, but must not mutate it. False/empty selection is not a proof. */
typedef bool (*IrOepSelectInputs)(void *user, const IrInputs *catalogue, uint32_t limit,
                                const IrOepInput **selectors, uint32_t *count);

typedef struct {
    uint64_t first_seq, trigger_seq, candidate_address;
    uint32_t vcpu;
    bool flags_verified;
    const IrOepInput *symbolic_inputs;
    uint32_t symbolic_count; /* Must be nonzero; no implicit all-fixed proof. */
    IrOepSelectInputs select_inputs; /* Alternative to the explicit array, never both. */
    void *selection_user;
} IrOepRequest;

typedef struct {
    IrReplayOptions replay;
    IrAnalysisLimits ssa;
    bool target_slice; /* Default true; false is the full-IR comparison path. */
    IrAnalysisLimits slice; /* Additional clone/scratch. */
    bool rebuild_replay; /* Opt-in: requires target_slice. Free original before SMT;
                         * destroy SMT/slice before deterministic witness rebuild. */
    bool legacy_smt_context; /* Diagnostic A/B only. Default false uses RC and
                             * retains only value roots needed by the two queries. */
    IrBranchLimits branches;
    IrSmtLimits smt;
    IrSmtQueryLimits query;
    IrEvalLimits evaluation;
    IrInputLimits bindings;
    uint32_t symbolic_inputs, prefix_branches;
    uint64_t work; /* Wrapper scans and concrete binding lookups. */
    size_t bytes; /* Wrapper arrays + one evaluator; other stages have own limits. */
    void (*progress)(void *user, const char *phase); /* Optional synchronous stage observer. */
    void *progress_user;
} IrOepOptions;

typedef enum {
    IR_OEP_UNKNOWN,
    IR_OEP_UNIQUE,
    IR_OEP_NONUNIQUE,
    IR_OEP_REFUTED,
    IR_OEP_MISMATCH,
    IR_OEP_RESOURCE_LIMIT,
    IR_OEP_INVALID,
    IR_OEP_OUT_OF_MEMORY
} IrOepStatus;

typedef struct {
    IrOepStatus status;
    uint64_t first_seq, trigger_seq, candidate_address, observed_target;
    uint32_t vcpu, selected_steps, symbolic_count, input_aliases, prefix_count, reasons;
    uint64_t work;
    size_t bytes, evaluator_bytes;
    IrOrigin trigger, failure_origin;
    IrReplayBuildInfo replay_build;
    IrReplayCheckResult baseline;
    IrTraceSsaResult ssa;
    bool slice_attempted;
    IrTargetSliceInfo slice;
    IrSmtInfo smt;
    bool baseline_verified, candidate_attempted, alternative_attempted;
    bool candidate_verified, alternative_verified;
    IrBits candidate_target, alternative_target;
    IrEvalResult candidate_replay, alternative_replay;
    IrSmtAnswer candidate, alternative; /* Owned, only checked SAT models are exposed. */
    bool replay_released, smt_released, rebuild_attempted, rebuild_verified;
    size_t released_replay_bytes, retained_input_bytes;
    char replay_sha256[65], rebuilt_sha256[65];
    IrReplayBuildInfo rebuilt_build;
    IrTraceSsaResult rebuilt_ssa;
    char diagnostic[160];
    const char *phase; /* Static stage name, including on failure. */
} IrOepResult;

IrOepOptions ir_oep_default_options(void);
/* Owned ReplayInput -> x86 IR -> baseline replay -> trace SSA -> two SMT
 * relations at the exact pre-transfer boundary. Requires a nonempty adjacent
 * same-vCPU fragment, verified flags, complete trigger evidence and explicit
 * symbolic boundary cells. Every observed Jcc outcome is constrained,
 * including identical successors. Observations validate baseline execution;
 * post-state checkpoints never become SMT equalities.
 *
 * UNIQUE means P(prefix) AND target==candidate is SAT, while the alternative
 * is UNSAT for these selected cells and fixed remaining boundary values.
 * It is NOT an OEP verdict, program-entry reachability or complete DCFG proof.
 * All SAT witnesses are independently evaluated to the same boundary and
 * checked against every prefix outcome. CALL/RET post-transfer effects are
 * outside this query. No live guest/trace reads, legacy DSE fallback, source
 * mutation or candidate scoring. The result survives input destruction.
 * With rebuild_replay, SAT models are kept unverified until both queries have
 * finished and the original SSA IR has been reconstructed from this same
 * immutable ReplayInput. Structural SHA-256 and exact input-catalogue equality
 * must match before witness execution. Rebuild failure is never a proof.
 * Destroy every owned result; calls must serialize mutation of the input. */
IrOepResult ir_oep_verify(const ReplayInput *input, const IrOepRequest *request,
                          const IrOepOptions *options);
void ir_oep_result_destroy(IrOepResult *result);
const char *ir_oep_status_name(IrOepStatus status);
bool ir_oep_report_json(FILE *stream, const IrOepResult *result);

#endif
