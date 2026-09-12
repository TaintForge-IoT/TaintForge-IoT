#ifndef TAINTFORGE_IR_INPUTS_H
#define TAINTFORGE_IR_INPUTS_H

#include "ir_eval.h"
#include "replay_sources.h"

/* Source adapter outside the ISA-independent IR core. InputId is catalogue-
 * local, one-based, and unrelated to ValueId, RootId or a provenance label. */
typedef uint32_t IrInputId;
typedef struct IrInputs IrInputs;
typedef struct IrInputBindings IrInputBindings;

typedef struct {
    uint32_t inputs;
    size_t bytes;
    uint64_t work;
} IrInputLimits;

typedef enum {
    IR_INPUT_STATE_SLICE,
    IR_INPUT_MEMORY_BYTE
} IrInputKind;

enum {
    IR_INPUT_OBSERVATION_MISSING = 1U << 0,
    IR_INPUT_PROVENANCE_MISSING = 1U << 1,
    IR_INPUT_PROVENANCE_INCOMPLETE = 1U << 2,
    IR_INPUT_SOURCE_UNRESOLVED = 1U << 3,
    IR_INPUT_DERIVATION_MISSING = 1U << 4,
    IR_INPUT_PROVENANCE_CONFLICT = 1U << 5
};

typedef struct {
    IrStateId state;
    IrType type;
    uint64_t key;
    IrInputId first; /* BV slices form a contiguous, complete partition. */
    uint32_t count;  /* MEM uses sparse lookup; first/count are zero. */
} IrInputState;

typedef struct {
    IrInputKind kind;
    IrStateId state;
    uint64_t address; /* MEM address; zero for state slices. */
    uint8_t bit_offset, width;
    IrBits observed;
    IrOrigin observation_origin; /* First read for memory; boundary for BV. */
    ProvLabelId label;
    bool label_present;
    uint32_t issues;
} IrInputCell;

typedef struct {
    IrStatus status;
    uint32_t count, missing_observations, missing_provenance;
    uint32_t incomplete_provenance, unresolved_sources, dependent_inputs;
    uint64_t work;
    size_t bytes;
} IrInputInfo;

typedef struct {
    IrInputId input;
    IrBits bits;
} IrInputAssignment;

IrInputLimits ir_input_default_limits(void);
/* Bounded builder: capacity is the exact upper bound for this catalogue.
 * Source snapshot is retained. Duplicate state keys, overlapping slices and
 * duplicate memory addresses are rejected. Failure is sticky. Publish only
 * after seal succeeds. The complete owner can outlive ReplayInput/registry. */
IrInputs *ir_inputs_create(IrOrigin boundary, const IrInputState *states, uint32_t state_count,
                           uint32_t capacity, const ReplaySources *sources,
                           const IrInputLimits *limits, IrInputInfo *info);
IrInputId ir_inputs_add(IrInputs *inputs, IrInputCell cell);
bool ir_inputs_seal(IrInputs *inputs);
IrInputs *ir_inputs_retain(const IrInputs *inputs);
void ir_inputs_release(IrInputs *inputs);
IrInputInfo ir_inputs_info(const IrInputs *inputs);
/* Constant-time sealed-state enumeration for bounded downstream adapters. */
bool ir_inputs_ready(const IrInputs *inputs);
uint32_t ir_inputs_state_count(const IrInputs *inputs);
const IrInputState *ir_inputs_state_at(const IrInputs *inputs, uint32_t index);
size_t ir_inputs_bytes(const IrInputs *inputs); /* Includes shared sources. */
IrOrigin ir_inputs_boundary(const IrInputs *inputs);
const IrInputState *ir_inputs_state(const IrInputs *inputs, IrStateId state);
const IrInputCell *ir_inputs_cell(const IrInputs *inputs, IrInputId input);
IrInputId ir_inputs_find_byte(const IrInputs *inputs, IrStateId state, uint64_t address);
const ReplaySources *ir_inputs_sources(const IrInputs *inputs);
const ReplaySourceLabel *ir_inputs_label(const IrInputs *inputs, IrInputId input);

/* Immutable assignment of BOUNDARY values, not a materialized file/network
 * input or a proof that this state is reachable from program entry. Each
 * InputId changes independently, even with equal labels or observations.
 * Unassigned cells retain observed (possibly unknown) bits. Unknown/unlisted
 * memory stays UNKNOWN. Assignments are copied; duplicate/out-of-range IDs and
 * malformed masks fail transactionally. Budgets cover this new binding owner. */
IrInputBindings *ir_inputs_bindings_create(const IrInputs *inputs,
                                           const IrInputAssignment *assignments, uint32_t count,
                                           const IrInputLimits *limits, IrInputInfo *info);
void ir_inputs_bindings_destroy(IrInputBindings *bindings);
IrBindings ir_inputs_bindings(IrInputBindings *bindings);

#endif
