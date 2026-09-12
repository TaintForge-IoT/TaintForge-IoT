#ifndef TAINTFORGE_IR_SSA_H
#define TAINTFORGE_IR_SSA_H

#include "ir.h"

typedef struct {
    uint64_t work;
    size_t bytes;
} IrAnalysisLimits;

typedef struct {
    IrStatus status;
    uint64_t work;
    size_t bytes; /* Peak owned + scratch allocation estimate, not RSS. */
    const char *message;
} IrAnalysisInfo;

typedef struct {
    bool keep_outputs;
    bool all_exit_states;
    const IrValueId *values;
    uint32_t value_count;
    const IrStateId *states;
    uint32_t state_count;
} IrSsaRoots;

typedef struct {
    IrAnalysisLimits limits;
    IrSsaRoots roots;
    bool dce;
} IrTraceSsaOptions;

typedef struct {
    IrAnalysisInfo analysis;
    uint32_t renamed_reads, initial_reads, removed, removed_writes;
} IrTraceSsaResult;

IrAnalysisLimits ir_analysis_default_limits(void);
IrTraceSsaOptions ir_trace_ssa_default_options(void);
/* Transactional: failure leaves module, IDs, revision and builder status
 * unchanged. Requires one acyclic chain covering every block, with at most
 * one distinct internal successor at each terminator. ADDRESS/UNKNOWN exits
 * remain intact; no observed condition is substituted. General CFG/phi is
 * deliberately rejected. Uses may cross blocks only along this chain.
 *
 * Each first READ_STATE is an immutable boundary input; subsequent reads are
 * COPY of the last state version (a ValueId). WRITE_STATE materializes exit
 * state; dead intermediate writes may be removed. MEM versions preserve the
 * entire functional STORE chain, with no alias-sensitive pruning.
 *
 * Default roots preserve every output/checkpoint and all exit state. Analysis
 * clients may select normal-exit state/outputs on a separate module clone.
 * GUARD/BARRIER, CJUMP and unknown/external exits always preserve all current
 * state, even with a narrower normal-exit contract. Budget interruption points
 * are not semantic checkpoints; optimized step counts can differ.
 *
 * Successful conversion seals the structural builder. Optimization and adding
 * outputs remain allowed. Existing evaluators and analyses become stale. */
IrTraceSsaResult ir_trace_ssa(IrModule *module, const IrTraceSsaOptions *options);

typedef enum {
    IR_USE_INSTRUCTION,
    IR_USE_CONDITION,
    IR_USE_INDIRECT,
    IR_USE_OUTPUT
} IrUseKind;

typedef struct {
    IrUseKind kind;
    IrInstId instruction;
    IrBlockId block;
    uint32_t operand; /* Argument slot, or output index. */
} IrUse;
typedef struct IrUseDef IrUseDef;
/* Owned CSR use lists. Source module must outlive the index. This index only
 * accepts trace SSA: implicit reaching definitions are not invented. */
IrUseDef *ir_use_def_build(const IrModule *module, const IrAnalysisLimits *limits,
                           IrAnalysisInfo *info);
void ir_use_def_destroy(IrUseDef *index);
bool ir_use_def_current(const IrUseDef *index);
IrInstId ir_use_def_definition(const IrUseDef *index, IrValueId value);
uint32_t ir_use_def_count(const IrUseDef *index, IrValueId value);
const IrUse *ir_use_def_use(const IrUseDef *index, IrValueId value, uint32_t use);

typedef struct IrLiveness IrLiveness;
/* Fixed-point backwards traversal of scalar/address/MEM operands, seeded by
 * explicit outputs, boundary state producers and control/effect operands.
 * No postdominator-based control pruning. Failure returns no partial result. */
IrLiveness *ir_liveness_build(const IrModule *module, const IrSsaRoots *roots,
                              const IrAnalysisLimits *limits, IrAnalysisInfo *info);
void ir_liveness_destroy(IrLiveness *live);
bool ir_liveness_current(const IrLiveness *live);
bool ir_liveness_inst(const IrLiveness *live, IrInstId instruction);
bool ir_liveness_value(const IrLiveness *live, IrValueId value);

#endif
