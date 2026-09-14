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
    IrSmtLimits limits;
    const IrInputId *symbolic_inputs;
    uint32_t symbolic_count;
    const IrSmtParameter *parameters;
    uint32_t parameter_count;
} IrSmtOptions;

typedef struct {
    IrStatus status;
    uint64_t work, constructors;
    size_t bytes;
    uint32_t lowered_values, symbolic_inputs, symbolic_parameters;
    IrOrigin origin;
    const char *message; /* Static string. */
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
} IrSmtAnswer;

IrSmtLimits ir_smt_default_limits(void);
IrSmtOptions ir_smt_default_options(void);
IrSmtQueryLimits ir_smt_default_query_limits(void);
/* Requires a validated, acyclic trace chain (stateful or trace SSA). No CFG
 * joins/loops/phi inference. Source module must stay alive and unchanged;
 * mutation invalidates this backend. Input catalogue is retained; options are
 * copied. Unselected inputs retain observed bits; missing bits remain unknown.
 * Calls on one backend/context must be serialized; no global Z3 parameters are
 * changed. Unknown IR/MEM values are not controllable parameters. No provenance-derived
 * equalities or external-input reachability claims are introduced. */
IrSmt *ir_smt_build(const IrModule *module, const IrInputs *inputs, const IrSmtOptions *options,
                    IrSmtInfo *info);
void ir_smt_destroy(IrSmt *smt);
bool ir_smt_current(const IrSmt *smt);
IrSmtInfo ir_smt_info(const IrSmt *smt);
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
