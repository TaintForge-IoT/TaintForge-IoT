#ifndef TAINTFORGE_IR_OEP_TEST_HELPERS_H
#define TAINTFORGE_IR_OEP_TEST_HELPERS_H

#include "ir_oep.h"
#include "ir_x86_semantics_helpers.h"

enum { OF_EQUAL, OF_NOT_EQUAL, OF_SAME_SUCCESSOR, OF_LINEAR, OF_MEMORY, OF_RET,
       OF_CALL, OF_STORE, OF_LATE_GUARD, OF_GAP, OF_UNSUPPORTED, OF_SYSCALL,
       OF_BAD_BASELINE, OF_BAD_BRANCH };

typedef struct {
    ReplayInput *input;
    IrOepInput variables[4];
    uint32_t variable_count, target_address, target_memory;
    int target_register;
} OepFixture;

static inline InsnAux of_registers(void) {
    InsnAux a = {0};
    a.reg_value_valid_mask = 0xff;
    dse_aux_set_eflags(&a, 0x202, true, true);
    a.reg_vals[DTA_REG_RAX] = 8;
    a.reg_vals[DTA_REG_RSP] = 0x3000;
    /* The legacy comparison imports the exact selected cells itself. Keep
     * later normalization from concretizing those expressions via DTA. */
    memset(a.reg_taint, 0x0f, sizeof(a.reg_taint));
    return a;
}

static inline IrOepInput of_register_byte(unsigned reg, unsigned byte) {
    return (IrOepInput){.kind = IR_INPUT_STATE_SLICE,
        .state_key = IR_X86_GPR_KEY_BASE + reg, .bit_offset = (uint8_t)(byte * 8), .width = 8};
}

static inline void of_read(InsnAux *a, uint32_t address, uint32_t value) {
    ff_read(a, address, value, 4, true);
    a->mem_read_taint = a->mem_read_effective_taint = 0x0f;
    a->mem_reads[0].taint = a->mem_reads[0].effective_taint = 0x0f;
}

static inline uint64_t of_emit(FrontFixture *f, uint32_t pc, const uint8_t *bytes, size_t size,
                                InsnAux a, uint32_t next) {
    uint64_t seq = ff_emit(f, pc, bytes, size, 9, 0, &a);
    ff_finish(f, seq, next);
    return seq;
}

static inline OepFixture of_fixture(unsigned kind) {
    FrontFixture f = ff_new(32);
    OepFixture out = {.variable_count = 1, .target_register = DTA_REG_RAX, .target_address = 9};
    out.variables[0] = of_register_byte(DTA_REG_RAX, 0);
    InsnAux a = of_registers();
    uint64_t seqs[8], trigger;
    unsigned count = 0;
    uint32_t pc = 0x1000;
    const uint8_t nop[] = {0x90}, add[] = {0x83, 0xc0, 1}, jump[] = {0xff, 0xe0};
    if (kind <= OF_SAME_SUCCESSOR || kind == OF_BAD_BRANCH) {
        uint8_t compare[] = {0x83, 0xf8, kind == OF_NOT_EQUAL ? 7 : 8};
        seqs[count++] = of_emit(&f, pc, compare, sizeof(compare), a, pc + 3);
        a = alu_after(a, ALU_CMP, 32, 8, compare[2], DTA_REG_RAX, 0, false);
        pc += 3;
        uint8_t branch[] = {0x74, kind == OF_SAME_SUCCESSOR ? 0 : 0x10};
        bool taken = kind != OF_NOT_EQUAL;
        uint32_t next = pc + 2 + (taken ? branch[1] : 0);
        seqs[count] = ff_emit(&f, pc, branch, sizeof(branch), 9, 0, &a);
        ff_finish_branch(&f, seqs[count++], next, kind == OF_BAD_BRANCH ? !taken : taken);
        pc = next;
    }
    if (kind <= OF_LINEAR || kind == OF_CALL || kind == OF_BAD_BASELINE || kind == OF_BAD_BRANCH) {
        seqs[count++] = of_emit(&f, pc, add, sizeof(add), a, pc + 3);
        a = alu_after(a, ALU_ADD, 32, 8, 1, DTA_REG_RAX, 0, true);
        pc += 3;
        if (kind == OF_BAD_BASELINE) a.reg_vals[DTA_REG_RAX] = 10;
    } else if (kind == OF_MEMORY || kind == OF_RET) {
        seqs[count++] = of_emit(&f, pc, nop, 1, a, pc + 1);
        ++pc;
        out.target_register = -1; out.target_memory = 0x3000;
        out.variables[0] = (IrOepInput){.kind = IR_INPUT_MEMORY_BYTE,
            .state_key = IR_X86_MEMORY_KEY, .address = 0x3000, .width = 8};
        of_read(&a, 0x3000, 9);
    } else if (kind == OF_STORE) {
        const uint8_t store[] = {0xa3, 0x00, 0x30, 0x00, 0x00};
        InsnAux before = a;
        ff_write(&before, 0x3000, 8, 4, true);
        seqs[count++] = of_emit(&f, pc, store, sizeof(store), before, pc + 5);
        pc += 5;
        out.target_address = 8; out.target_register = -1; out.target_memory = 0x3000;
        of_read(&a, 0x3000, 8);
    } else if (kind == OF_LATE_GUARD) {
        a.reg_vals[DTA_REG_RDX] = 0x1200;
        out.variables[0] = of_register_byte(DTA_REG_RDX, 0);
        out.target_address = 0x1200;
        const uint8_t move[] = {0x89, 0xd0}, indirect[] = {0xff, 0xe2};
        seqs[count++] = of_emit(&f, pc, move, 2, a, pc + 2);
        a.reg_vals[DTA_REG_RAX] = 0x1200; pc += 2;
        seqs[count++] = of_emit(&f, pc, indirect, 2, a, 0x1200);
        pc = 0x1200;
        seqs[count++] = of_emit(&f, pc, nop, 1, a, pc + 1);
        ++pc;
    } else if (kind == OF_GAP) {
        seqs[count++] = of_emit(&f, pc, nop, 1, a, pc + 1);
        ++pc;
        (void)of_emit(&f, pc, nop, 1, a, pc + 1);
        ++pc;
        seqs[count++] = of_emit(&f, pc, nop, 1, a, pc + 1);
        ++pc; out.target_address = 8;
    } else if (kind == OF_UNSUPPORTED) {
        const uint8_t divide[] = {0xf7, 0xf1};
        seqs[count++] = of_emit(&f, pc, divide, 2, a, pc + 2);
        a.reg_vals[DTA_REG_RAX] = ~a.reg_vals[DTA_REG_RAX];
        pc += 2; out.target_address = 0xfffffff7;
    } else if (kind == OF_SYSCALL) {
        const uint8_t call[] = {0xcd, 0x80};
        a.reg_vals[DTA_REG_RAX] = 5; a.reg_vals[DTA_REG_RBX] = 0x2000;
        uint64_t seq = ff_emit(&f, pc, call, 2, 9, 0, &a);
        const TraceEntry *e = trace_find_seq(f.trace, seq, NULL);
        InsnAux *aux = (InsnAux *)dse_aux_for(f.aux, f.trace, e);
        const uint32_t args[6] = {0x2000, 0, 0, 0, 0, 0};
        CHECK(dse_aux_syscall_enter(f.aux, aux, e, 5, args));
        CHECK(dse_aux_syscall_return(aux, seq, 0, 5, 4));
        ff_finish(&f, seq, pc + 2);
        seqs[count++] = seq; pc += 2; a.reg_vals[DTA_REG_RAX] = 4;
        out.target_address = 4;
    }
    if (kind == OF_MEMORY || kind == OF_STORE) {
        const uint8_t memjump[] = {0xff, 0x25, 0x00, 0x30, 0x00, 0x00};
        trigger = of_emit(&f, pc, memjump, sizeof(memjump), a, out.target_address);
    } else if (kind == OF_RET) {
        const uint8_t ret[] = {0xc3};
        trigger = of_emit(&f, pc, ret, 1, a, out.target_address);
    } else if (kind == OF_CALL) {
        const uint8_t call[] = {0xff, 0xd0};
        ff_write(&a, 0x2ffc, pc + 2, 4, true);
        trigger = of_emit(&f, pc, call, 2, a, out.target_address);
    } else {
        trigger = of_emit(&f, pc, jump, 2, a, out.target_address);
    }
    out.input = ff_capture(&f, seqs, count, trigger);
    ff_free(&f); /* All consumers below use the same owned snapshot. */
    return out;
}

static inline IrOepRequest of_request(const OepFixture *f) {
    return (IrOepRequest){.first_seq = replay_input_step(f->input, 0)->entry.seq_id,
        .trigger_seq = replay_input_trigger(f->input)->entry.seq_id,
        .candidate_address = f->target_address, .vcpu = 0, .flags_verified = true,
        .symbolic_inputs = f->variables, .symbolic_count = f->variable_count};
}

static inline IrOepOptions of_options(void) {
    IrOepOptions o = ir_oep_default_options();
    o.replay.x86.flat32_ram = true;
    return o;
}

static inline void of_status(const IrOepResult *r, IrOepStatus expected) {
    if (r->status != expected) {
        fprintf(stderr, "expected %s: ", ir_oep_status_name(expected));
        (void)ir_oep_report_json(stderr, r);
        fprintf(stderr, "baseline status=%u eval=%u mismatch=%u build=%u stop=%llu\n",
                r->baseline.status, r->baseline.execution.status, r->baseline.mismatches,
                r->replay_build.status, (unsigned long long)r->replay_build.stopped_seq);
    }
    CHECK(r->status == expected);
}

#endif
