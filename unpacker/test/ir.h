#ifndef TAINTFORGE_IR_H
#define TAINTFORGE_IR_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

/* IDs are module-local, start at one, and never change during optimization.
 * Zero is invalid. All returned pointers are borrowed and may be invalidated
 * by any module mutation. The module owns every record; no Capstone/QEMU/Z3
 * object is retained. Builder failures are sticky and must be checked. */
typedef uint32_t IrValueId;
typedef uint32_t IrInstId;
typedef uint32_t IrBlockId;
typedef uint32_t IrStateId;
typedef struct IrModule IrModule;

typedef enum {
    IR_TYPE_VOID,
    IR_TYPE_BV,
    IR_TYPE_MEM
} IrTypeKind;

typedef struct {
    IrTypeKind kind;
    uint8_t bits;
} IrType;

/* BV supports every width 1..64; MEM(bits) is BV(bits) -> BV8. */
IrType ir_type_void(void);
IrType ir_type_bv(uint32_t bits);
IrType ir_type_mem(uint32_t address_bits);
bool ir_type_equal(IrType a, IrType b);
bool ir_type_valid(IrType type);
uint64_t ir_width_mask(uint32_t bits);

typedef enum {
    IR_OK,
    IR_INVALID,
    IR_RESOURCE_LIMIT,
    IR_OUT_OF_MEMORY
} IrStatus;

enum {
    IR_REASON_UNBOUND_INPUT = 1U << 0,
    IR_REASON_UNBOUND_STATE = 1U << 1,
    IR_REASON_UNDEFINED = 1U << 2,
    IR_REASON_UNSUPPORTED = 1U << 3,
    IR_REASON_MEMORY = 1U << 4,
    IR_REASON_TARGET = 1U << 5,
    IR_REASON_TRACE_GAP = 1U << 6,
    IR_REASON_BUDGET = 1U << 7,
    IR_REASON_GUARD = 1U << 8,
    IR_REASON_NOT_EXECUTED = 1U << 9
};

typedef struct {
    uint64_t seq_id;
    uint64_t descriptor_id;
    uint64_t pc;
    uint64_t code_generation;
    uint32_t vcpu_id;
    bool has_trace_identity;
    /* Metadata only: a provenance label is not a semantic value identity. */
    uint64_t provenance_label;
} IrOrigin;

typedef struct {
    uint32_t semantic;
    uint32_t control;
    uint32_t observation;
} IrQuality;

typedef enum {
    IR_ENDIAN_LE,
    IR_ENDIAN_BE
} IrEndian;

typedef enum {
    IR_OP_CONST,
    IR_OP_INPUT,
    IR_OP_UNKNOWN,
    IR_OP_COPY,
    IR_OP_ADD,
    IR_OP_SUB,
    IR_OP_MUL,
    IR_OP_AND,
    IR_OP_OR,
    IR_OP_XOR,
    IR_OP_NOT,
    IR_OP_NEG,
    IR_OP_SHL,
    IR_OP_LSHR,
    IR_OP_ASHR,
    IR_OP_EXTRACT,
    IR_OP_CONCAT,
    IR_OP_ZEXT,
    IR_OP_SEXT,
    IR_OP_EQ,
    IR_OP_ULT,
    IR_OP_SLT,
    IR_OP_ITE,
    IR_OP_READ_STATE,
    IR_OP_WRITE_STATE,
    IR_OP_LOAD,
    IR_OP_STORE,
    /* GUARD requires BV1(true); BARRIER stops at unmodeled effects. Neither
     * is removable. Guest traps/volatile I/O need explicit effects; pure
     * mathematical LOAD/STORE do not model those effects themselves. */
    IR_OP_GUARD,
    IR_OP_BARRIER,
    /* A fully defined, immutable zero byte array over the whole MEM domain. */
    IR_OP_ZERO_MEMORY,
    IR_OP_COUNT
} IrOpcode;

typedef struct {
    IrOpcode op;
    IrType type;
    IrValueId args[3];
    /* CONST: bits; INPUT: stable binding key; UNKNOWN/GUARD/BARRIER:
     * nonzero reason bits; EXTRACT: least significant bit offset. */
    uint64_t immediate;
    IrStateId state;
    IrEndian endian;
    IrOrigin origin;
} IrInstSpec;

typedef struct {
    IrInstSpec spec;
    IrValueId result;
    IrBlockId block;
    IrInstId next;
    /* DCE keeps tombstones and origins, so external IDs remain meaningful. */
    bool removed;
} IrInst;

typedef struct {
    IrType type;
    IrInstId definition;
} IrValue;

typedef struct {
    IrType type;
    uint64_t key;
    /* Required at fragment exit. This does not license dropping state writes
     * inside the fragment: a later READ_STATE may still need them. */
    bool live_out;
} IrState;

typedef enum {
    IR_TARGET_BLOCK,
    IR_TARGET_ADDRESS,
    IR_TARGET_UNKNOWN
} IrTargetKind;

typedef struct {
    IrTargetKind kind;
    IrBlockId block;
    uint64_t address;
    uint32_t reasons;
} IrTarget;

typedef enum {
    IR_TERM_NONE,
    IR_TERM_FRAGMENT_END,
    IR_TERM_PROGRAM_EXIT,
    IR_TERM_JUMP,
    IR_TERM_CJUMP,
    IR_TERM_INDIRECT,
    IR_TERM_UNKNOWN
} IrTermKind;

typedef struct {
    IrTermKind kind;
    IrValueId condition;
    IrValueId indirect_target;
    /* CJUMP: [0] true, [1] false. ADDRESS is known but not lifted here. */
    IrTarget successors[2];
    uint32_t reasons;
    IrOrigin origin;
    /* Evidence only. Execution and optimization never substitute these for
     * the semantic condition or target. */
    bool has_observation;
    bool observed_taken;
    uint64_t observed_target;
} IrTerminator;

typedef struct {
    IrInstId first;
    IrInstId last;
    IrTerminator terminator;
} IrBlock;

typedef struct {
    uint32_t instructions, values, blocks, states, outputs;
} IrLimits;

typedef struct {
    IrStatus status;
    IrBlockId block;
    IrInstId instruction;
    const char *message; /* Static string. */
} IrDiagnostic;

/* Construction counters are emission history, not active post-SSA counts.
 * Phases are exclusive; nested helpers restore their caller's phase. */
typedef enum {
    IR_BUILD_OTHER, IR_BUILD_SETUP, IR_BUILD_X86, IR_BUILD_REGISTERS,
    IR_BUILD_ARITHMETIC_FLAGS, IR_BUILD_MEMORY, IR_BUILD_ENVIRONMENT,
    IR_BUILD_OBSERVATIONS, IR_BUILD_CONTROL, IR_BUILD_FLAG_DEFINEDNESS,
    IR_BUILD_FETCH, IR_BUILD_PHASE_COUNT
} IrBuildPhase;
typedef enum {
    IR_BUDGET_NONE, IR_BUDGET_INSTRUCTIONS, IR_BUDGET_VALUES, IR_BUDGET_BLOCKS,
    IR_BUDGET_STATES, IR_BUDGET_OUTPUTS, IR_BUDGET_STEPS, IR_BUDGET_OBSERVATIONS,
    IR_BUDGET_MEMORY_BYTES, IR_BUDGET_REPEAT_ITERATIONS
} IrBudgetKind;
typedef struct {
    IrBudgetKind kind;
    uint64_t used, limit, requested; /* requested is the required total. */
    IrOrigin origin;
    IrBuildPhase phase;
} IrBudgetFailure;
typedef struct {
    IrLimits records, limits;
    size_t allocated_bytes;
    IrStatus status;
    IrBudgetFailure failure;
    uint64_t opcodes[IR_OP_COUNT], phases[IR_BUILD_PHASE_COUNT];
} IrBuildMetrics;
IrBuildPhase ir_module_build_phase(IrModule *module, IrBuildPhase phase);
void ir_module_build_origin(IrModule *module, IrOrigin origin);
IrBuildMetrics ir_module_build_metrics(const IrModule *module);
const char *ir_budget_kind_name(IrBudgetKind kind);
const char *ir_build_phase_name(IrBuildPhase phase);
bool ir_budget_report_json(FILE *stream, const IrBudgetFailure *failure);
bool ir_build_report_json(FILE *stream, const IrBuildMetrics *metrics);

IrLimits ir_default_limits(void);
IrModule *ir_module_create(const IrLimits *limits);
void ir_module_destroy(IrModule *module);
/* Deep copy with identical IDs/origins, no shared owned storage. */
IrModule *ir_module_clone(const IrModule *module);
bool ir_module_is_trace_ssa(const IrModule *module);
IrStatus ir_module_status(const IrModule *module);
const char *ir_module_error(const IrModule *module);
uint64_t ir_module_revision(const IrModule *module);
void ir_module_note_quality(IrModule *module, IrQuality quality);
IrQuality ir_module_quality(const IrModule *module);
IrBlockId ir_block_add(IrModule *module);
bool ir_module_set_entry(IrModule *module, IrBlockId block);
IrBlockId ir_module_entry(const IrModule *module);
IrStateId ir_state_add(IrModule *module, IrType type, uint64_t key, bool live_out);
IrValueId ir_emit_value(IrModule *module, IrBlockId block, IrInstSpec spec);
bool ir_emit_effect(IrModule *module, IrBlockId block, IrInstSpec spec);
bool ir_block_terminate(IrModule *module, IrBlockId block, IrTerminator term);
bool ir_module_add_output(IrModule *module, IrValueId value);

/* Stateful IR requires temporary definitions before their uses in the same
 * block; state slots carry values across blocks. Repeated block execution
 * redefines its temporaries. Trace SSA permits cross-block uses along the
 * validated acyclic chain, and READ_STATE reads initial boundary bindings.
 * General CFG joins and phi nodes are not supported. */
bool ir_validate(const IrModule *module, IrDiagnostic *diagnostic);
bool ir_dump(const IrModule *module, FILE *stream);
const char *ir_opcode_name(IrOpcode opcode);
unsigned ir_opcode_arity(IrOpcode opcode);
bool ir_opcode_is_effect(IrOpcode opcode);
const IrInst *ir_module_inst(const IrModule *module, IrInstId id);
const IrValue *ir_module_value(const IrModule *module, IrValueId id);
const IrBlock *ir_module_block(const IrModule *module, IrBlockId id);
const IrState *ir_module_state(const IrModule *module, IrStateId id);
uint32_t ir_module_inst_count(const IrModule *module);
uint32_t ir_module_value_count(const IrModule *module);
uint32_t ir_module_block_count(const IrModule *module);
uint32_t ir_module_state_count(const IrModule *module);
uint32_t ir_module_output_count(const IrModule *module);
IrValueId ir_module_output(const IrModule *module, uint32_t index);
uint32_t ir_module_active_inst_count(const IrModule *module);
/* Owned allocations, including unused array capacity. Excludes allocator
 * overhead and temporary allocations inside passes; this is not process RSS. */
size_t ir_module_allocated_bytes(const IrModule *module);

#endif
