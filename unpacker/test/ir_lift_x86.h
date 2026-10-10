#ifndef TAINTFORGE_IR_LIFT_X86_H
#define TAINTFORGE_IR_LIFT_X86_H

#include "ir.h"
#include "ir_environment.h"
#include "trace.h"

/* IA-32 data movement, arithmetic, shifts, stack, flags, SETcc/CMOVcc and near transfers.
 * These keys belong to the x86 frontend, not the generic IR.
 * GPR order is the existing RegId order 0..7;
 * flag order is CF/PF/AF/ZF/SF/OF/DF (X86SpecialStateId). */
#define IR_X86_GPR_COUNT 8U
#define IR_X86_FLAG_COUNT 7U
#define IR_X86_GPR_KEY_BASE UINT64_C(0x100)
#define IR_X86_FLAG_KEY_BASE UINT64_C(0x200)
#define IR_X86_MEMORY_KEY UINT64_C(0x300)
#define IR_X86_TLS_COUNT 2U /* FS, GS */
#define IR_X86_TLS_KEY_BASE UINT64_C(0x500)
#define IR_X86_REPEAT_API 1
#define IR_X86_MAX_UNMAPPED_RANGES 16U
#define IR_X86_MAX_PROTECTED_RANGES 16U

enum {
    IR_X86_ACCESS_READ = 1U,
    IR_X86_ACCESS_WRITE = 2U,
    IR_X86_ACCESS_EXEC = 4U,
    IR_X86_ACCESS_ALL = 7U
};

typedef struct {
    IrStateId gpr[IR_X86_GPR_COUNT];
    IrStateId flags[IR_X86_FLAG_COUNT];
    IrStateId memory;
    IrStateId tls_base[IR_X86_TLS_COUNT];
} IrX86State;

typedef struct {
    /* Explicit model contract: normal RAM, zero CS/DS/ES/SS bases, no modeled
     * faults/MMIO/concurrent writes, a 32-bit stack segment (SS.B=1), and
     * CET disabled.
     * false permits register operations, LEA and direct branches, but no memory access. */
    bool flat32_ram;
    /* Additional explicit contract: FS/GS are present ordinary user data
     * segments with 4 GiB limits. Bases come from separate BV32 state.
     * Requires flat32_ram; does not model descriptor changes or faults. */
    bool tls32_ram;
} IrX86Options;

typedef enum {
    IR_X86_LIFT_OK,
    IR_X86_LIFT_UNSUPPORTED,
    IR_X86_LIFT_IDENTITY,
    IR_X86_LIFT_MODE,
    IR_X86_LIFT_MEMORY_MODEL,
    IR_X86_LIFT_ERROR,
    IR_X86_LIFT_REPEAT, /* Supported REP body; requires explicit bounded expansion. */
    IR_X86_LIFT_LIMIT,
    IR_X86_LIFT_CALLBACK
} IrX86LiftStatus;

typedef enum {
    IR_X86_FALLTHROUGH,
    IR_X86_DIRECT_JUMP,
    IR_X86_CONDITIONAL,
    IR_X86_INDIRECT
} IrX86Control;

typedef struct {
    bool write;
    uint8_t bytes;
    IrValueId address, data;
} IrX86MemoryEffect;

typedef struct {
    IrX86LiftStatus status;
    uint32_t gpr_writes;
    /* Masks use X86_SPECIAL_STATE_* indices, not EFLAGS bit positions. */
    uint32_t flags_written, flags_undefined;
    bool reads_memory, writes_memory;
    uint8_t memory_bytes;
    /* data is retained for compatibility: write value if present, else read.
     * RMW consumers must use the separate read_data / write_data values. */
    IrValueId address, data;
    IrValueId read_data, write_data;
    IrX86Control control;
    IrValueId condition; /* BV1 for a conditional transfer. */
    uint32_t direct_target, fallthrough;
    IrValueId target; /* Semantic BV32 destination of an indirect transfer. */
    int target_gpr;   /* -1 unless a full GPR supplies the target. */
    bool call;
    uint8_t segment_reads; /* FS/GS base state used by this instruction. */
    /* Ordered effects: operand read precedes a stack write; POP destination
     * addressing uses the incremented stack pointer. POPAD has seven reads. */
    uint8_t memory_count;
    IrX86MemoryEffect memory[8];
    /* Optional BV1 conditions for conditional flag preservation/definedness.
     * Zero IDs mean no preservation / statically defined, respectively. */
    IrValueId flags_preserved_when;
    IrValueId flags_defined[IR_X86_FLAG_COUNT];
    bool repeated, string_move;
    uint8_t string_bytes, string_address_bytes;
} IrX86LiftResult;

typedef struct IrX86Frontend IrX86Frontend;
/* Module is borrowed and must outlive frontend. No live QEMU/trace pointers
 * are retained. Decoder configuration is owned, fixed to x86-32/Intel syntax.
 * Unsupported instructions are rejected before any instruction is emitted.
 * A lift returns semantic control information; the caller installs the block
 * terminator. Near 32-bit CALL/JMP/RET and the 16 ordinary Jcc are supported.
 * Operand-size prefix 66 on transfers, far transfers and LOOPcc/JCXZ remain
 * unsupported. LOOP supports CX/ECX selected by address size and preserves flags.
 * PUSH/POP accept 16/32-bit operands; LEAVE requires 32 bits.
 * SCAS accepts 8/16/32-bit operands and 16/32-bit addresses, without REP.
 * LODS accepts 8/16/32-bit operands and 16/32-bit addresses, without REP;
 * source segments obey the ordinary RAM/TLS contracts. All flags are preserved.
 * Exact F3 C3 (REPZ RET) uses the near RET model, including target projection.
 * Other F2/F3-prefixed returns and additional prefixes remain unsupported.
 * NEG/INC/DEC accept 8/16/32-bit register or ordinary RAM operands, without
 * LOCK/REP. INC/DEC preserve CF (including unknown CF); all three preserve DF.
 * ADC/SBB accept 8/16/32-bit register, immediate and ordinary RAM operands.
 * NOT/XCHG preserve flags; BSWAP requires a 32-bit GPR. Memory XCHG uses the
 * explicit serialized ordinary-RAM contract (no competing writes or MMIO).
 * MOVS/STOS support 8/16/32-bit data and 16/32-bit addresses. F3 requires the
 * separate guarded expansion API; F2/LOCK and repeated prefix groups reject.
 * SETcc writes one byte (0 or 1), preserves flags and is not a control transfer.
 * CMOVcc selects a 16/32-bit register value, preserves flags and creates no control edge.
 * Its register/memory source is read unconditionally, even when the condition is false.
 * Exact F3 0F 1E FB ENDBR32 is a no-op under flat32_ram's CET-disabled contract;
 * other ENDBR encodings remain unsupported. Replay checkpoints retain its origin.
 * Lifting never consults an observed branch outcome. */
IrX86Frontend *ir_x86_frontend_create(IrModule *module, const IrX86Options *options);
void ir_x86_frontend_destroy(IrX86Frontend *frontend);
const IrX86State *ir_x86_frontend_state(const IrX86Frontend *frontend);
/* Borrow a shared environment lowering. Its guest-memory state must be this
 * frontend's memory. Kernel copy-in uses the same guarded memory semantics. */
void ir_x86_attach_environment(IrX86Frontend *frontend, IrEnvironment *environment);
bool ir_x86_memory_write(IrX86Frontend *frontend, IrBlockId block, IrOrigin origin,
                           IrValueId address, unsigned bytes, IrValueId value);
IrValueId ir_x86_memory_read(IrX86Frontend *frontend, IrBlockId block, IrOrigin origin,
                             IrValueId address, unsigned bytes);
/* For an observed unmap, guard every subsequent data access before LOAD/STORE
 * and reject instruction fetches in the range. End is exclusive, at most 2^32.
 * Never re-enable a range implicitly; mapping syscalls need their own model. */
IrStatus ir_x86_exclude_memory(IrX86Frontend *frontend, uint32_t start, uint64_t end);
/* A successful modeled mapping restores exactly this interval and replaces
 * its access rights. The caller must supply fresh anonymous/file contents.
 * Both exclusion and permission updates are transactional on budget failure. */
IrStatus ir_x86_map_memory(IrX86Frontend *frontend, uint32_t start, uint64_t end,
                           unsigned access);
bool ir_x86_range_excluded(const IrX86Frontend *frontend, uint32_t start, unsigned bytes);
/* Bounded, disjoint intervals with the latest observed permissions. Updates
 * are transactional and cannot restore an unmapped range. Outside these
 * intervals the existing flat RAM contract applies. Contents are unchanged. */
IrStatus ir_x86_protect_memory(IrX86Frontend *frontend, uint32_t start, uint64_t end,
                               unsigned access);
bool ir_x86_range_permitted(const IrX86Frontend *frontend, uint32_t start, unsigned bytes,
                            unsigned access);
IrX86LiftResult ir_x86_lift(IrX86Frontend *frontend, IrBlockId block, const InsnDesc *descriptor,
                            IrOrigin origin);
/* Trace specialization of REP MOVS/STOS. The IR guards CX/ECX == iterations
 * before all effects, then lowers ordered LOAD/STORE/index/count updates.
 * No observed data/post-state enters semantics. Zero count performs no memory
 * access. Callback sees each iteration's semantic effects and can add exports;
 * false returns CALLBACK with a partial module which the caller must not run
 * as a complete instruction. LIMIT rejects before emitting any instruction.
 * A changed/unknown count fails the guard instead of reusing an old schedule. */
typedef bool (*IrX86RepeatObserver)(void *user, uint32_t iteration,
                                   const IrX86LiftResult *effects);
IrX86LiftResult ir_x86_lift_repeat(IrX86Frontend *frontend, IrBlockId block,
    const InsnDesc *descriptor, IrOrigin origin, uint32_t iterations, uint32_t max_iterations,
    IrX86RepeatObserver observer, void *user);
/* Project a near JMP/CALL/RET destination from the pre-transfer state. Does
 * not push a return address, pop the stack, execute the transfer or its target. */
IrX86LiftResult ir_x86_lift_target(IrX86Frontend *frontend, IrBlockId block,
                                   const InsnDesc *descriptor, IrOrigin origin);
/* Identity/mode/encoding preflight only; emits no IR and returns no ValueId. */
IrX86LiftResult ir_x86_describe_target(IrX86Frontend *frontend, IrBlockId block,
                                       const InsnDesc *descriptor, IrOrigin origin);

#endif
