#ifndef TAINTFORGE_IR_BRANCHES_H
#define TAINTFORGE_IR_BRANCHES_H

#include "ir_smt.h"

typedef struct IrBranches IrBranches;
typedef uint32_t IrBranchId; /* Catalogue-local, one-based execution order. */

enum {
    IR_BRANCH_IDENTITY_MISSING = 1U << 0,
    IR_BRANCH_OBSERVATION_MISSING = 1U << 1,
    IR_BRANCH_ORDER_CONFLICT = 1U << 2,
    IR_BRANCH_ROUTE_CONFLICT = 1U << 3,
    IR_BRANCH_TARGET_CONFLICT = 1U << 4,
    IR_BRANCH_TARGET_UNVERIFIED = 1U << 5
};

typedef struct {
    IrBranchId id;
    IrBlockId block;
    IrValueId condition;
    IrOrigin origin;
    IrTarget successors[2];
    bool has_observation, observed_taken;
    uint64_t observed_target;
    uint32_t issues;
} IrBranch;

typedef struct {
    uint32_t branches;
    uint64_t work;
    size_t bytes; /* Catalogue + temporary rank array, excluding borrowed IR. */
} IrBranchLimits;

typedef struct {
    IrStatus status;
    uint32_t count, issues;
    uint64_t work;
    size_t bytes;
    const char *message; /* Static string. */
} IrBranchInfo;

IrBranchLimits ir_branch_default_limits(void);
/* One validated acyclic trace chain, stateful or trace SSA. Every CJUMP gets
 * an entry, including incomplete evidence. Trace identity is the full tuple
 * (seq, PC, code generation, descriptor, vCPU); repeated PCs are distinct.
 * A module must outlive the catalogue and remain unchanged. Inputs, if any,
 * are retained. Build failure publishes no partial catalogue. Entries describe
 * only this modeled prefix, never all branches of a DCFG/program. */
IrBranches *ir_branches_build(const IrModule *module, const IrInputs *inputs,
                              const IrBranchLimits *limits, IrBranchInfo *info);
void ir_branches_destroy(IrBranches *branches);
bool ir_branches_current(const IrBranches *branches);
IrBranchInfo ir_branches_info(const IrBranches *branches);
const IrBranch *ir_branches_at(const IrBranches *branches, IrBranchId id);
/* Bounded linear lookup in this catalogue; zero for absent/ambiguous/stale
 * identity. Provenance labels do not participate in identity. */
IrBranchId ir_branches_find(const IrBranches *branches, IrOrigin origin);

typedef enum {
    IR_INVERT_VERIFIED, /* Boundary witness passed concrete prefix execution. */
    IR_INVERT_UNSAT,    /* No witness within the chosen inputs/model/prefix. */
    IR_INVERT_UNKNOWN,
    IR_INVERT_RESOURCE_LIMIT,
    IR_INVERT_INVALID,
    IR_INVERT_OUT_OF_MEMORY,
    IR_INVERT_MISMATCH /* Baseline evidence or solver witness disagreed with evaluation. */
} IrInvertStatus;

typedef struct {
    IrSmtOptions smt; /* Explicit InputIds/parameters; no provenance-derived selection. */
    IrSmtQueryLimits query;
    IrInputLimits bindings;  /* Per immutable binding owner. */
    IrEvalLimits evaluation; /* Per baseline/candidate execution. */
    uint32_t prefix_branches;
    uint64_t work; /* Wrapper scans, validation and binding callback lookups. */
    size_t
        bytes; /* Prefix arrays + evaluator upper bound; excludes separately budgeted SMT/bindings. */
} IrInvertOptions;

typedef struct {
    IrInvertStatus status;
    uint32_t reasons, prefix_count;
    uint64_t work;
    size_t bytes, evaluator_bytes;
    IrBranch branch;
    IrOrigin failure_origin;
    bool baseline_verified, candidate_verified;
    IrEvalResult baseline, candidate;
    IrSmtInfo build;
    IrSmtAnswer model; /* Owned assignments only for VERIFIED; no Z3 pointers. */
    char diagnostic[160];
} IrInvertResult;

IrInvertOptions ir_invert_default_options(void);
/* Check the observed prefix using unchanged boundary bindings. Then constrain
 * all earlier observed outcomes and invert exactly the selected CJUMP at its
 * terminator. Validate a SAT witness with independent concrete execution,
 * stopping before the selected successor, even for identical successors.
 * Future checkpoints/exports do not constrain or validate this query.
 *
 * VERIFIED means a branch direction changed in this IR from assigned boundary
 * state. It does not prove a new external input, actual process replay, OEP,
 * successor semantics or DCFG completeness. Unknown flags/effects/evidence
 * remain UNKNOWN. No source, observation, IR, DCFG or input is mutated.
 * Result data survives catalogue/backend/module destruction. Calls must be
 * serialized with mutation; destroy each owned result exactly once. */
IrInvertResult ir_branch_invert(const IrBranches *branches, IrBranchId id,
                                const IrInvertOptions *options);
void ir_invert_result_destroy(IrInvertResult *result);

#endif
