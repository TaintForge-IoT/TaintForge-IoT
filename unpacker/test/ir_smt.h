#ifndef TAINTFORGE_IR_SMT_H
#define TAINTFORGE_IR_SMT_H

#include "ir_inputs.h"

/* Z3 stays behind this API; ir.h and the x86 frontend remain solver-free. */
typedef struct IrSmt IrSmt;

typedef struct {
    uint64_t work;
    uint64_t constructors; /* Cumulative Z3 term/sort construction requests. */
    size_t bytes;          /* Adapter-owned arrays; excludes Z3 internals/shared inputs. */
} IrSmtLimits;

typedef struct {
    uint64_t key; /* IR_OP_INPUT binding namespace, separate from state keys. */
    uint8_t width;
    IrBits observed;
    bool symbolic; /* Explicitly controllable boundary parameter. */
} IrSmtParameter;

typedef struct {
    IrInputId input, canonical; /* Both selected, same width and observed bits. */
} IrSmtInputAlias;

typedef struct {
    IrSmtLimits limits;
    const IrInputId *symbolic_inputs;
    uint32_t symbolic_count;
    const IrSmtParameter *parameters;
    uint32_t parameter_count;
    const IrSmtInputAlias *aliases;
    uint32_t alias_count; /* Explicit one-level equality groups; no inferred provenance. */
    bool legacy_context; /* Diagnostic comparison: retain all ASTs until destruction. */
    bool retained_values_only; /* Opt-in last-use release; requires the RC context. */
    const IrValueId *retained_values;
    uint32_t retained_value_count; /* Only these value IDs remain queryable after build.
                                   * CJUMP queries remain available in either mode. */
} IrSmtOptions;

/* Bounded, owned diagnostics. Missing /proc metrics are UINT64_MAX. Statistics
 * are copied before destroying the solver; no AST text or borrowed pointers. */
#define IR_SMT_STATS_CAPACITY 64
typedef struct {
    uint64_t vm_size_kib, vm_peak_kib, vm_rss_kib, vm_hwm_kib, vm_swap_kib;
    uint64_t z3_estimated_alloc_bytes;
} IrSmtMemory;
typedef struct {
    char key[80];
    bool key_truncated, is_uint;
    uint64_t uint_value;
    double double_value;
} IrSmtStatistic;
typedef struct {
    bool available, truncated;
    uint32_t count, total;
    IrSmtStatistic entries[IR_SMT_STATS_CAPACITY];
} IrSmtStatistics;
typedef struct {
    bool recorded, returned, api_ok, clock_available, reason_truncated;
    uint32_t pass, timeout_ms, rlimit; /* pass 0 = certain, 1 = possible. */
    int result; /* Raw Z3_lbool: -1 UNSAT, 0 UNKNOWN, 1 SAT. */
    uint64_t elapsed_ns;
    char reason_unknown[160];
    IrSmtMemory before, after;
    IrSmtStatistics statistics_before, statistics_after;
    bool rlimit_delta_available, timeout_elapsed, rlimit_delta_reached;
    uint64_t rlimit_delta; /* Context counter delta, not a count of guest instructions.
                           * Threshold observations are not definitive cancellation causes. */
} IrSmtCheck;

/* First Z3 API failure, copied before backend destruction. No borrowed Z3
 * pointers, AST printing or heap allocation is needed to retain this record.
 * Numeric error codes are Z3_error_code values; Z3 remains a private dependency.
 * Message/version buffers report truncation explicitly. UINT64_MAX denotes
 * unavailable /proc metrics; RLIMIT_AS availability/infinity are explicit. */
typedef struct {
    bool present, message_truncated, version_truncated, null_result;
    uint32_t code;
    char api[64], message[1024], version[160], stage[32];
    uint32_t version_major, version_minor, version_build, version_revision;
    IrInstId instruction;
    IrValueId result;
    IrBlockId block;
    IrInstSpec spec;
    IrOrigin origin;
    bool has_instruction;
    uint64_t work, constructors, lowered_values, z3_estimated_alloc_bytes;
    int errno_at_api_return;
    uint64_t vm_size_kib, vm_peak_kib, vm_rss_kib, vm_hwm_kib, vm_swap_kib;
    bool rlimit_as_available, rlimit_as_soft_unlimited, rlimit_as_hard_unlimited;
    uint64_t rlimit_as_soft_bytes, rlimit_as_hard_bytes;
} IrSmtZ3Error;

typedef struct {
    IrStatus status;
    uint64_t work, constructors;
    size_t bytes;
    uint32_t lowered_values, symbolic_inputs, symbolic_parameters, input_aliases;
    IrOrigin origin;
    const char *message; /* Static string. */
    IrSmtZ3Error z3_error;
    bool reference_counted, retained_values_only;
    uint64_t references_acquired, references_released, temporary_peak;
    uint64_t values_live, values_peak, values_released;
    bool values_compacted;
    uint64_t value_table_bytes, value_index_bytes; /* Requested storage, not RSS.
                                                   * bytes above remains a peak bound. */
} IrSmtInfo;

typedef struct {
    IrValueId value;
    uint64_t expected, mask;
} IrSmtConstraint;

typedef struct {
    IrBlockId block; /* CJUMP occurrence, independent of its condition's definition. */
    bool taken;
} IrSmtBranchConstraint;

typedef struct {
    uint64_t work;
    size_t bytes; /* New result/scratch arrays, excluding backend/Z3. */
    uint32_t constraints, samples;
    uint32_t timeout_ms; /* Per solver check; zero prohibits solver calls. */
    uint32_t rlimit;     /* Z3 work limit per check; zero prohibits calls. */
} IrSmtQueryLimits;

typedef enum {
    IR_SMT_SAT,
    IR_SMT_UNSAT,
    IR_SMT_UNKNOWN,
    IR_SMT_RESOURCE_LIMIT,
    IR_SMT_INVALID,
    IR_SMT_OUT_OF_MEMORY
} IrSmtStatus;

typedef struct {
    IrValueId value;
    IrBits bits;
} IrSmtSample;

typedef struct {
    uint64_t key;
    uint8_t width;
    uint64_t value;
} IrSmtParameterValue;

typedef struct {
    IrSmtStatus status;
    uint32_t reasons, solver_checks;
    uint64_t work;
    size_t bytes;
    IrOrigin origin; /* Last constraint's origin; not a first-failure claim. */
    char diagnostic[160];
    IrInputAssignment *inputs;
    uint32_t input_count;
    IrSmtParameterValue *parameters;
    uint32_t parameter_count;
    IrSmtSample *samples;
    uint32_t sample_count;
    IrInputs *catalogue; /* Retained for the lifetime/identity of InputIds. */
    IrSmtCheck checks[2]; /* Exact check timing excludes query setup and cleanup. */
} IrSmtAnswer;

IrSmtLimits ir_smt_default_limits(void);
IrSmtOptions ir_smt_default_options(void);
IrSmtQueryLimits ir_smt_default_query_limits(void);
/* Requires a validated, acyclic trace chain (stateful or trace SSA). No CFG
 * joins/loops/phi inference. Source module must stay alive and unchanged;
 * mutation invalidates this backend. Input catalogue is retained; options are
 * copied. Unselected inputs retain observed bits; missing bits remain unknown.
 * The default RC context releases construction temporaries. By default all
 * value IDs remain queryable. retained_values_only explicitly narrows this
 * contract: unlisted value constraints/samples are INVALID, never guessed or
 * reconstructed. Operands, states, branch conditions, masks, reachability and
 * model inputs stay owned while needed. Duplicate retained IDs are harmless.
 * Calls on one backend/context must be serialized; no global Z3 parameters are
 * changed. Unknown IR/MEM values are not controllable parameters. No provenance-derived
 * equalities or external-input reachability claims are introduced. */
IrSmt *ir_smt_build(const IrModule *module, const IrInputs *inputs, const IrSmtOptions *options,
                    IrSmtInfo *info);
void ir_smt_destroy(IrSmt *smt);
bool ir_smt_current(const IrSmt *smt);
IrSmtInfo ir_smt_info(const IrSmt *smt);
/* JSON object for a captured API failure, or null when no API failure occurred.
 * Safe after backend/module destruction. Does not imply solver satisfiability. */
bool ir_smt_z3_error_report_json(FILE *out, const IrSmtZ3Error *error);
bool ir_smt_checks_report_json(FILE *out, const IrSmtAnswer *answer);
bool ir_smt_lifetime_report_json(FILE *out, const IrSmtInfo *info);
/* Query conjunction: every constraint requests a nonempty mask of one active
 * BV value AT ITS DEFINITION. Reachability includes preceding branches/guards;
 * no later branch or checkpoint observation is asserted. Samples do not add
 * constraints and can report NOT_EXECUTED/partially known bits.
 *
 * SAT has a witness using fully defined requested bits and known reachability.
 * If no such witness exists, a second, conservative possible-value query can
 * prove UNSAT; otherwise return UNKNOWN. UNKNOWN is never reported as UNSAT.
 * At most two solver checks. Result arrays contain no Z3 pointers and survive
 * backend/module destruction. Call ir_smt_answer_destroy exactly once per
 * owned answer (it is safe to call again after it clears the same object).
 * Query term construction also spends the backend's cumulative limits. */
IrSmtAnswer ir_smt_query(IrSmt *smt, const IrSmtConstraint *constraints, uint32_t constraint_count,
                         const IrValueId *samples, uint32_t sample_count,
                         const IrSmtQueryLimits *limits);
/* Conjunction at CJUMP terminators, after preceding instructions/effects and
 * before choosing successors. This includes guards after the condition's
 * definition. Observed outcomes are not added implicitly: pass every required
 * prefix outcome explicitly, including branches with identical successors.
 * Uses the same SAT/UNSAT/UNKNOWN, budgets and ownership contract as value
 * queries. A known condition can select an external/UNKNOWN successor; SAT
 * does not establish that successor's behavior or full-program reachability. */
IrSmtAnswer ir_smt_query_branches(IrSmt *smt, const IrSmtBranchConstraint *constraints,
                                  uint32_t constraint_count, const IrSmtQueryLimits *limits);
void ir_smt_answer_destroy(IrSmtAnswer *answer);

#endif
