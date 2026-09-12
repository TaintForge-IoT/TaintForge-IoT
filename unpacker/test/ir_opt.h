#ifndef TAINTFORGE_IR_OPT_H
#define TAINTFORGE_IR_OPT_H

#include "ir.h"

typedef struct {
    bool fold;
    bool dce;
    uint64_t max_work;
} IrOptOptions;

typedef struct {
    IrStatus status;
    uint64_t work;
    uint32_t constants_folded;
    uint32_t identities_folded;
    uint32_t copies_propagated;
    uint32_t removed;
} IrOptResult;

IrOptOptions ir_opt_default_options(void);
/* In-place, identity-preserving, no CFG pruning, no runtime bindings, no
 * alias-sensitive memory rewrites. All state writes, guards, barriers,
 * terminator operands and explicit exports are roots. Tombstones retain IDs.
 * Budget exhaustion may leave valid partial folding; DCE publishes deletions
 * only after its complete liveness traversal. A pass failure does not poison
 * the module's builder status. Consumers must invalidate cached analyses. */
IrOptResult ir_optimize(IrModule *module, const IrOptOptions *options);

#endif
