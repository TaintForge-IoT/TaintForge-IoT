#ifndef TAINTFORGE_IR_EVAL_H
#define TAINTFORGE_IR_EVAL_H

#include "ir.h"

typedef struct IrEval IrEval;

typedef struct {
    uint64_t value;
    uint64_t known_mask;
    uint32_t reasons;
} IrBits;

typedef struct {
    IrType type;
    IrBits bits;
    uint32_t memory; /* Persistent memory handle, local to this evaluator/run. */
} IrEvalValue;

typedef enum {
    IR_BIND_INPUT,
    IR_BIND_STATE
} IrBindingKind;

typedef struct {
    void *user;
    IrBits (*read_bv)(void *user, IrBindingKind kind, uint64_t key, uint8_t width);
    IrBits (*read_byte)(void *user, IrBindingKind kind, uint64_t key, uint64_t address);
} IrBindings;

/* Bindings describe an immutable snapshot for one run, not a live process or
 * device. Repeated reads of a byte must agree. INPUT BV values are cached by
 * key; READ_STATE observes this run's current mutable state. Different binding
 * keys are independent even if their concrete values/provenance happen to match.
 * Returned unknown bits are masked out; callers can provide partial validity. */
typedef struct {
    uint64_t steps;          /* Active instructions + terminators. */
    uint64_t memory_queries; /* Persistent-chain nodes examined by loads. */
    uint32_t memory_nodes;   /* BASE, STORE and opaque memory versions. */
} IrEvalLimits;

typedef enum {
    IR_EVAL_FRAGMENT_END,
    IR_EVAL_PROGRAM_EXIT,
    IR_EVAL_UNKNOWN,
    IR_EVAL_RESOURCE_LIMIT,
    IR_EVAL_INVALID,
    IR_EVAL_OUT_OF_MEMORY,
    IR_EVAL_BRANCH /* Only run_to_branch: known condition at the requested terminator. */
} IrEvalStatus;

typedef struct {
    IrBlockId block;
    IrOrigin origin;
    IrBits condition;
    IrTarget target; /* Meaningful only for a complete condition. */
} IrEvalBranch;

typedef struct {
    IrEvalStatus status;
    uint32_t reasons;
    IrQuality quality;
    uint64_t steps;
    uint64_t memory_queries;
    IrBlockId block;
    IrInstId instruction;
    IrOrigin origin;
    bool target_known;
    uint64_t target_address;
} IrEvalResult;

IrBits ir_bits_known(uint64_t value, uint32_t width);
IrBits ir_bits_unknown(uint32_t reasons);
bool ir_bits_complete(IrBits bits, uint32_t width);
IrEvalLimits ir_eval_default_limits(void);
/* The validated module must outlive the evaluator and stay unchanged. A
 * revision mismatch produces INVALID. Create a new evaluator after any pass. */
IrEval *ir_eval_create(const IrModule *module, const IrBindings *bindings,
                       const IrEvalLimits *limits);
void ir_eval_destroy(IrEval *eval);
/* Each run resets all dynamic state and memory versions. FRAGMENT_END only
 * means evaluation reached that boundary; it is not a full-program/CFG proof.
 * Exports mean their last executed definition in this run; an export never
 * executed is UNKNOWN. Exported/live-out BV unknowns affect the final status.
 * A MEM handle describes a persistent map; inspect bytes explicitly. A base
 * callback's presence alone does not certify completeness of its entire map. */
IrEvalResult ir_eval_run(IrEval *eval);
/* Reset and execute up to a CJUMP occurrence. Record each encountered CJUMP
 * in caller-owned storage, including an unknown condition. On IR_EVAL_BRANCH
 * the selected successor has not executed; no future exports/live-outs are
 * checked. An external or unknown successor does not prevent reaching this
 * boundary. Earlier exits/effects and resource limits still stop execution.
 * Target block must be a CJUMP; count is required and reset on entry. Capacity
 * exhaustion is RESOURCE_LIMIT, never a truncated successful prefix. */
IrEvalResult ir_eval_run_to_branch(IrEval *eval, IrBlockId block, IrEvalBranch *events,
                                   uint32_t capacity, uint32_t *count);
IrEvalResult ir_eval_result(const IrEval *eval);
/* Owned allocations including capacities, excluding the borrowed module and
 * bindings. After a run this is its allocation high-water mark. */
size_t ir_eval_allocated_bytes(const IrEval *eval);
/* Conservative owned-allocation bound for create + a run with these limits.
 * Excludes module/bindings/allocator overhead; rejects size overflow. */
bool ir_eval_allocation_bound(const IrModule *module, const IrEvalLimits *limits, size_t *bytes);
IrEvalValue ir_eval_value(const IrEval *eval, IrValueId id);
IrEvalValue ir_eval_state(const IrEval *eval, IrStateId id);
/* Inspection shares the memory query budget, reports UNKNOWN/BUDGET rather
 * than walking an unbounded STORE chain, and never writes the base snapshot. */
IrBits ir_eval_load(IrEval *eval, IrEvalValue memory, uint64_t address, uint32_t width,
                    IrEndian endian);

#endif
