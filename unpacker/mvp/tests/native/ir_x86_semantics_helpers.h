#ifndef TAINTFORGE_IR_X86_SEMANTICS_HELPERS_H
#define TAINTFORGE_IR_X86_SEMANTICS_HELPERS_H
#include "ir_frontend_test_helpers.h"

enum { ALU_ADD, ALU_SUB, ALU_AND, ALU_OR, ALU_XOR, ALU_CMP, ALU_TEST, ALU_COUNT };
static const unsigned alu_flag_bits[7] = {0, 2, 4, 6, 7, 11, 10};
typedef struct { uint32_t value, flags, defined; } AluExpected;
/* Independent oracle: widened signed ranges, nibble carry/borrow and bit
 * counting, rather than the frontend's XOR/sign-bit/parity expressions. */
static inline AluExpected alu_reference(unsigned op, unsigned width, uint32_t a, uint32_t b) {
    uint64_t modulus = UINT64_C(1) << width, mask = modulus - 1U, full;
    a &= (uint32_t)mask; b &= (uint32_t)mask;
    bool add = op == ALU_ADD, sub = op == ALU_SUB || op == ALU_CMP;
    if (add) full = (uint64_t)a + b;
    else if (sub) full = (uint64_t)a - b;
    else if (op == ALU_OR) full = a | b;
    else if (op == ALU_XOR) full = a ^ b;
    else full = a & b;
    uint32_t result = (uint32_t)(full & mask), flags = 0;
    unsigned ones = 0;
    for (unsigned i = 0; i < 8; ++i) if (result & (1U << i)) ++ones;
    flags |= (ones % 2 == 0) << 2;
    flags |= (result == 0) << 6;
    flags |= (result >> (width - 1U)) << 7;
    if (add || sub) {
        int64_t sa = (a & (modulus >> 1)) ? (int64_t)a - (int64_t)modulus : a;
        int64_t sb = (b & (modulus >> 1)) ? (int64_t)b - (int64_t)modulus : b;
        int64_t sr = add ? sa + sb : sa - sb;
        flags |= add ? full >= modulus : a < b;
        flags |= (add ? (a % 16U + b % 16U >= 16U) : a % 16U < b % 16U) << 4;
        flags |= (sr < -(int64_t)(modulus >> 1) || sr >= (int64_t)(modulus >> 1)) << 11;
    }
    return (AluExpected){.value = (op == ALU_CMP || op == ALU_TEST) ? a : result,
        .flags = flags, .defined = (add || sub) ? 0x8d5 : 0x8c5};
}
static inline InsnAux alu_after(InsnAux before, unsigned op, unsigned width, uint32_t a, uint32_t b,
                                 unsigned reg, unsigned offset, bool write_reg) {
    AluExpected e = alu_reference(op, width, a, b);
    InsnAux after = before;
    after.eflags_before = (before.eflags_before & ~e.defined) | e.flags;
    if (write_reg && op != ALU_CMP && op != ALU_TEST) {
        uint32_t mask = (uint32_t)ir_width_mask(width) << offset;
        after.reg_vals[reg] = (before.reg_vals[reg] & ~mask) | (e.value << offset);
    }
    return after;
}
typedef struct { uint32_t gpr[8], eflags, unknown_gpr, unknown_flags; } AluInputs;
static inline IrBits alu_binding(void *user, IrBindingKind kind, uint64_t key, uint8_t width) {
    AluInputs *in = user;
    if (kind == IR_BIND_STATE && key >= IR_X86_GPR_KEY_BASE && key < IR_X86_GPR_KEY_BASE + 8 && width == 32) {
        unsigned i = (unsigned)(key - IR_X86_GPR_KEY_BASE);
        return in->unknown_gpr & (1U << i) ? ir_bits_unknown(IR_REASON_UNBOUND_STATE) : ir_bits_known(in->gpr[i], 32);
    }
    if (kind == IR_BIND_STATE && key >= IR_X86_FLAG_KEY_BASE && key < IR_X86_FLAG_KEY_BASE + 7 && width == 1) {
        unsigned i = (unsigned)(key - IR_X86_FLAG_KEY_BASE);
        return in->unknown_flags & (1U << i) ? ir_bits_unknown(IR_REASON_UNBOUND_STATE)
            : ir_bits_known((in->eflags >> alu_flag_bits[i]) & 1U, 1);
    }
    return ir_bits_unknown(IR_REASON_UNBOUND_STATE);
}
typedef struct { IrModule *module; IrX86State state; IrX86LiftResult lift; IrBlockId block; } AluProgram;
static inline AluProgram alu_program(const uint8_t *code, size_t size, uint32_t pc) {
    FrontFixture f = ff_new(8); InsnAux a = ff_registers();
    uint64_t seq = ff_emit(&f, pc, code, size, 9, 1, &a);
    const TraceEntry *entry = trace_find_seq(f.trace, seq, NULL); CHECK(entry);
    const InsnDesc *d = trace_insn_desc_get(f.trace, entry->insn_desc_id); CHECK(d);
    AluProgram p = {.module = ir_module_create(NULL)}; CHECK(p.module);
    IrX86Options options = {.flat32_ram = true};
    IrX86Frontend *front = ir_x86_frontend_create(p.module, &options); CHECK(front);
    p.state = *ir_x86_frontend_state(front); p.block = ir_block_add(p.module); CHECK(p.block);
    p.lift = ir_x86_lift(front, p.block, d, (IrOrigin){.seq_id = seq, .pc = pc,
        .descriptor_id = d->desc_id, .code_generation = 9, .vcpu_id = 1, .has_trace_identity = true});
    ir_x86_frontend_destroy(front); ff_free(&f); return p;
}
static inline void alu_observe_flags(AluProgram *p) {
    for (unsigned i = 0; i < IR_X86_FLAG_COUNT; ++i) {
        if (p->lift.flags_undefined & (1U << i)) continue;
        IrValueId v = ir_emit_value(p->module,p->block,(IrInstSpec){.op = IR_OP_READ_STATE,
            .type = ir_type_bv(1),.state = p->state.flags[i]});
        CHECK(v && ir_module_add_output(p->module,v));
    }
}
static inline void alu_end(AluProgram *p) {
    alu_observe_flags(p);
    CHECK(ir_block_terminate(p->module, p->block, (IrTerminator){.kind = IR_TERM_FRAGMENT_END}));
    CHECK(ir_validate(p->module, NULL));
}
static inline uint32_t alu_state(IrEval *eval, IrStateId state, unsigned width) {
    IrBits b = ir_eval_state(eval, state).bits; CHECK(ir_bits_complete(b, width)); return (uint32_t)b.value;
}
/* Supply an exact event before archiving, as the production collector does. */
static inline void ff_finish_branch(FrontFixture *f, uint64_t seq, uint32_t next_pc, bool taken) {
    const TraceEntry *e = trace_find_seq(f->trace, seq, NULL); CHECK(e);
    InsnAux *a = (InsnAux *)dse_aux_for(f->aux, f->trace, e); CHECK(a);
    dse_aux_finalize(a, next_pc, NULL, 0);
    BranchEventBuffer *events = branch_event_buffer_create(8); CHECK(events);
    CHECK(branch_event_append(events, &(BranchEvent){.branch_seq_id = seq, .vcpu_index = e->vcpu_index,
        .meta_id = e->meta_id, .pc = e->pc, .fallthrough = (uint32_t)(e->pc + e->size),
        .observed_next_pc = next_pc, .outcome = taken ? BRANCH_OUTCOME_TAKEN : BRANCH_OUTCOME_NOT_TAKEN}));
    CHECK(dse_aux_archive_occurrence(f->aux, f->trace, events, seq));
    branch_event_buffer_destroy(events);
}
#endif
