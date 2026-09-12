#ifndef TAINTFORGE_IR_LIFT_X86_H
#define TAINTFORGE_IR_LIFT_X86_H

#include "ir.h"
#include "trace.h"

/* IA-32 data movement, arithmetic, flags and direct branches. These keys belong to the x86
 * frontend, not the generic IR. GPR order is the existing RegId order 0..7;
 * flag order is CF/PF/AF/ZF/SF/OF/DF (X86SpecialStateId). */
#define IR_X86_GPR_COUNT 8U
#define IR_X86_FLAG_COUNT 7U
#define IR_X86_GPR_KEY_BASE UINT64_C(0x100)
#define IR_X86_FLAG_KEY_BASE UINT64_C(0x200)
#define IR_X86_MEMORY_KEY UINT64_C(0x300)

typedef struct {
    IrStateId gpr[IR_X86_GPR_COUNT];
    IrStateId flags[IR_X86_FLAG_COUNT];
    IrStateId memory;
} IrX86State;

typedef struct {
    /* Explicit model contract: normal RAM, zero CS/DS/ES/SS bases, no modeled
     * faults/MMIO/concurrent writes. FS/GS accesses remain unsupported.
     * false permits register operations, LEA and direct branches, but no memory access. */
    bool flat32_ram;
} IrX86Options;

typedef enum {
    IR_X86_LIFT_OK,
    IR_X86_LIFT_UNSUPPORTED,
    IR_X86_LIFT_IDENTITY,
    IR_X86_LIFT_MODE,
    IR_X86_LIFT_MEMORY_MODEL,
    IR_X86_LIFT_ERROR
} IrX86LiftStatus;

typedef enum {
    IR_X86_FALLTHROUGH,
    IR_X86_DIRECT_JUMP,
    IR_X86_CONDITIONAL
} IrX86Control;

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
} IrX86LiftResult;

typedef struct IrX86Frontend IrX86Frontend;
/* Module is borrowed and must outlive frontend. No live QEMU/trace pointers
 * are retained. Decoder configuration is owned, fixed to x86-32/Intel syntax.
 * Unsupported instructions are rejected before any instruction is emitted.
 * A lift returns semantic control information; the caller installs the block
 * terminator. Direct rel8/rel32 JMP and the 16 ordinary Jcc are supported.
 * Operand-size prefix 66 on transfers, indirect/far transfers and LOOP/JCXZ
 * remain unsupported. Lifting never consults an observed branch outcome. */
IrX86Frontend *ir_x86_frontend_create(IrModule *module, const IrX86Options *options);
void ir_x86_frontend_destroy(IrX86Frontend *frontend);
const IrX86State *ir_x86_frontend_state(const IrX86Frontend *frontend);
IrX86LiftResult ir_x86_lift(IrX86Frontend *frontend, IrBlockId block, const InsnDesc *descriptor,
                            IrOrigin origin);

#endif
