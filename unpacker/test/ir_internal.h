#ifndef TAINTFORGE_IR_INTERNAL_H
#define TAINTFORGE_IR_INTERNAL_H

#include "ir.h"

struct IrModule {
    IrInst *insts;
    IrValue *values;
    IrBlock *blocks;
    IrState *states;
    IrValueId *outputs;
    uint32_t inst_count, value_count, block_count, state_count, output_count;
    uint32_t inst_capacity, value_capacity, block_capacity, state_capacity, output_capacity;
    IrLimits limits;
    IrBlockId entry;
    IrStatus status;
    const char *error;
    uint64_t revision;
    IrQuality quality;
    uint32_t *trace_rank; /* NULL before trace SSA, otherwise block_count entries. */
};

bool ir_trace_shape(const IrModule *m, uint32_t *rank, bool verify);
IrBlockId ir_trace_next(const IrTerminator *term, bool *valid);
bool ir_fail(IrModule *m, IrStatus status, const char *message);
bool ir_compute_bv(const IrInstSpec *spec, const IrType types[3], const uint64_t args[3],
                   uint64_t *result);
bool ir_constant(const IrModule *m, IrValueId id, uint64_t *bits);
/* Return an equivalent existing operand, or zero. Constants are inspected
 * from IR only: observed runtime bindings are deliberately unavailable here. */
IrValueId ir_identity_operand(const IrModule *m, const IrInstSpec *spec);

#endif
