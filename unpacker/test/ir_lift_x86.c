#include "ir_lift_x86.h"

#include <stdlib.h>
#include <string.h>

struct IrX86Frontend {
    IrModule *module;
    csh decoder;
    IrX86Options options;
    IrX86State state;
};

/* Decode register identity AND natural width. Do not infer an alias's width
 * solely from cs_x86_op.size (segment/control/SIMD registers are not GPRs). */
static RegSlice register_slice(unsigned reg) {
    static const unsigned r32[IR_X86_GPR_COUNT] = {X86_REG_EAX, X86_REG_ECX, X86_REG_EDX,
                                                   X86_REG_EBX, X86_REG_ESP, X86_REG_EBP,
                                                   X86_REG_ESI, X86_REG_EDI};
    static const unsigned r16[IR_X86_GPR_COUNT] = {X86_REG_AX, X86_REG_CX, X86_REG_DX, X86_REG_BX,
                                                   X86_REG_SP, X86_REG_BP, X86_REG_SI, X86_REG_DI};
    static const unsigned low[4] = {X86_REG_AL, X86_REG_CL, X86_REG_DL, X86_REG_BL};
    static const unsigned high[4] = {X86_REG_AH, X86_REG_CH, X86_REG_DH, X86_REG_BH};
    for (unsigned i = 0; i < IR_X86_GPR_COUNT; ++i) {
        if (reg == r32[i])
            return (RegSlice){(RegId)i, 0, 4, 15};
        if (reg == r16[i])
            return (RegSlice){(RegId)i, 0, 2, 3};
        if (i < 4 && reg == low[i])
            return (RegSlice){(RegId)i, 0, 1, 1};
        if (i < 4 && reg == high[i])
            return (RegSlice){(RegId)i, 1, 1, 2};
    }
    return (RegSlice){.reg_id = REG_INVALID};
}

IrX86Frontend *ir_x86_frontend_create(IrModule *m, const IrX86Options *options) {
    if (!m || ir_module_status(m) != IR_OK)
        return NULL;
    IrX86Frontend *f = calloc(1, sizeof(*f));
    if (!f)
        return NULL;
    f->module = m;
    if (options)
        f->options = *options;
    if (cs_open(CS_ARCH_X86, CS_MODE_32, &f->decoder) != CS_ERR_OK ||
        cs_option(f->decoder, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK ||
        cs_option(f->decoder, CS_OPT_SYNTAX, CS_OPT_SYNTAX_INTEL) != CS_ERR_OK) {
        ir_x86_frontend_destroy(f);
        return NULL;
    }
    for (unsigned i = 0; i < IR_X86_GPR_COUNT; ++i)
        f->state.gpr[i] = ir_state_add(m, ir_type_bv(32), IR_X86_GPR_KEY_BASE + i, false);
    for (unsigned i = 0; i < IR_X86_FLAG_COUNT; ++i)
        f->state.flags[i] = ir_state_add(m, ir_type_bv(1), IR_X86_FLAG_KEY_BASE + i, false);
    f->state.memory = ir_state_add(m, ir_type_mem(32), IR_X86_MEMORY_KEY, false);
    if (ir_module_status(m) != IR_OK) {
        ir_x86_frontend_destroy(f);
        return NULL;
    }
    return f;
}

void ir_x86_frontend_destroy(IrX86Frontend *f) {
    if (!f)
        return;
    if (f->decoder)
        cs_close(&f->decoder);
    free(f);
}

const IrX86State *ir_x86_frontend_state(const IrX86Frontend *f) {
    return f ? &f->state : NULL;
}

static bool width_ok(unsigned bytes) {
    return bytes == 1 || bytes == 2 || bytes == 4;
}

static bool register_ok(const cs_x86_op *op) {
    RegSlice s = register_slice(op->reg);
    return op->type == X86_OP_REG && s.reg_id != REG_INVALID && s.width == op->size;
}

static bool address_ok(const cs_x86 *x, const cs_x86_op *op) {
    if (op->type != X86_OP_MEM || (x->addr_size != 2 && x->addr_size != 4))
        return false;
    const x86_op_mem *mem = &op->mem;
    if (mem->base != X86_REG_INVALID && register_slice(mem->base).width != x->addr_size)
        return false;
    if (mem->index != X86_REG_INVALID && register_slice(mem->index).width != x->addr_size)
        return false;
    return mem->scale == 1 ||
           (x->addr_size == 4 && (mem->scale == 2 || mem->scale == 4 || mem->scale == 8));
}

static bool ram_segment(unsigned segment) {
    return segment == X86_REG_INVALID || segment == X86_REG_DS || segment == X86_REG_ES ||
           segment == X86_REG_SS || segment == X86_REG_CS;
}

static bool supported_prefixes(const InsnDesc *d) {
    for (unsigned i = 0; i < d->size; ++i) {
        switch (d->bytes[i]) {
        case 0xf0:
        case 0xf2:
        case 0xf3:
            return false;
        case 0x66:
        case 0x67:
        case 0x26:
        case 0x2e:
        case 0x36:
        case 0x3e:
        case 0x64:
        case 0x65:
            break;
        default:
            return true;
        }
    }
    return false;
}

/* Intel condition encoding order, expressed only in the ISA frontend. */
static int condition_code(unsigned id) {
    switch (id) {
    case X86_INS_JO:
        return 0;
    case X86_INS_JNO:
        return 1;
    case X86_INS_JB:
        return 2;
    case X86_INS_JAE:
        return 3;
    case X86_INS_JE:
        return 4;
    case X86_INS_JNE:
        return 5;
    case X86_INS_JBE:
        return 6;
    case X86_INS_JA:
        return 7;
    case X86_INS_JS:
        return 8;
    case X86_INS_JNS:
        return 9;
    case X86_INS_JP:
        return 10;
    case X86_INS_JNP:
        return 11;
    case X86_INS_JL:
        return 12;
    case X86_INS_JGE:
        return 13;
    case X86_INS_JLE:
        return 14;
    case X86_INS_JG:
        return 15;
    default:
        return -1;
    }
}

static bool arithmetic(unsigned id) {
    return id == X86_INS_ADD || id == X86_INS_SUB || id == X86_INS_CMP || id == X86_INS_AND ||
           id == X86_INS_OR || id == X86_INS_XOR || id == X86_INS_TEST;
}

static IrX86LiftStatus preflight(const IrX86Frontend *f, const cs_insn *insn) {
    const cs_x86 *x = &insn->detail->x86;
    if (insn->id == X86_INS_NOP)
        return IR_X86_LIFT_OK;
    if (insn->id == X86_INS_JMP || condition_code(insn->id) >= 0) {
        /* Operand-size override on control transfers is unsupported. */
        return x->prefix[2] != 0x66 && x->op_count == 1 && x->operands[0].type == X86_OP_IMM
                   ? IR_X86_LIFT_OK
                   : IR_X86_LIFT_UNSUPPORTED;
    }
    bool extend = insn->id == X86_INS_MOVZX || insn->id == X86_INS_MOVSX;
    bool lea = insn->id == X86_INS_LEA;
    if (insn->id != X86_INS_MOV && !extend && !lea && !arithmetic(insn->id))
        return IR_X86_LIFT_UNSUPPORTED;
    if (x->op_count != 2)
        return IR_X86_LIFT_UNSUPPORTED;
    const cs_x86_op *dst = &x->operands[0], *src = &x->operands[1];
    if (!width_ok(dst->size) || !width_ok(src->size))
        return IR_X86_LIFT_UNSUPPORTED;
    if (lea) {
        return register_ok(dst) && dst->size >= 2 && address_ok(x, src) ? IR_X86_LIFT_OK
                                                                        : IR_X86_LIFT_UNSUPPORTED;
    }
    if (extend) {
        if (!register_ok(dst) || dst->size <= src->size ||
            (src->type != X86_OP_REG && src->type != X86_OP_MEM))
            return IR_X86_LIFT_UNSUPPORTED;
    } else if (dst->size != src->size || (dst->type != X86_OP_REG && dst->type != X86_OP_MEM) ||
               (src->type != X86_OP_REG && src->type != X86_OP_MEM && src->type != X86_OP_IMM)) {
        return IR_X86_LIFT_UNSUPPORTED;
    }
    if (dst->type == X86_OP_MEM && src->type == X86_OP_MEM)
        return IR_X86_LIFT_UNSUPPORTED;
    for (unsigned i = 0; i < 2; ++i) {
        const cs_x86_op *op = &x->operands[i];
        if (op->type == X86_OP_REG && !register_ok(op))
            return IR_X86_LIFT_UNSUPPORTED;
        if (op->type == X86_OP_MEM) {
            if (!address_ok(x, op))
                return IR_X86_LIFT_UNSUPPORTED;
            if (!f->options.flat32_ram || !ram_segment(op->mem.segment))
                return IR_X86_LIFT_MEMORY_MODEL;
        }
    }
    return IR_X86_LIFT_OK;
}

typedef struct {
    IrX86Frontend *f;
    IrBlockId block;
    IrOrigin origin;
} Lift;

static IrValueId emit(Lift *l, IrInstSpec s) {
    s.origin = l->origin;
    return ir_emit_value(l->f->module, l->block, s);
}

static IrValueId constant(Lift *l, unsigned width, uint64_t bits) {
    return emit(l, (IrInstSpec){.op = IR_OP_CONST, .type = ir_type_bv(width), .immediate = bits});
}

static IrValueId unary(Lift *l, IrOpcode op, unsigned width, IrValueId a, uint64_t offset) {
    return emit(
        l, (IrInstSpec){.op = op, .type = ir_type_bv(width), .args = {a}, .immediate = offset});
}

static IrValueId binary(Lift *l, IrOpcode op, unsigned width, IrValueId a, IrValueId b) {
    return emit(l, (IrInstSpec){.op = op, .type = ir_type_bv(width), .args = {a, b}});
}

static IrValueId read_state(Lift *l, IrStateId id, IrType type) {
    return emit(l, (IrInstSpec){.op = IR_OP_READ_STATE, .type = type, .state = id});
}

static void write_state(Lift *l, IrStateId id, IrValueId v) {
    (void)ir_emit_effect(l->f->module, l->block,
                         (IrInstSpec){.op = IR_OP_WRITE_STATE,
                                      .type = ir_type_void(),
                                      .args = {v},
                                      .state = id,
                                      .origin = l->origin});
}

static IrValueId read_register(Lift *l, unsigned reg) {
    RegSlice s = register_slice(reg);
    IrValueId full = read_state(l, l->f->state.gpr[s.reg_id], ir_type_bv(32));
    return s.width == 4 ? full : unary(l, IR_OP_EXTRACT, s.width * 8U, full, s.byte_offset * 8U);
}

static void write_register(Lift *l, unsigned reg, IrValueId value) {
    RegSlice s = register_slice(reg);
    IrStateId state = l->f->state.gpr[s.reg_id];
    if (s.width < 4) {
        unsigned bits = s.width * 8U, offset = s.byte_offset * 8U;
        /* Assemble preserved slices explicitly. Unlike (old & mask) | new,
         * this also preserves useful known bits when old is partly UNKNOWN. */
        IrValueId old = read_state(l, state, ir_type_bv(32));
        if (offset) {
            IrValueId low = unary(l, IR_OP_EXTRACT, offset, old, 0);
            value = binary(l, IR_OP_CONCAT, bits + offset, value, low);
        }
        unsigned upper = 32U - bits - offset;
        IrValueId high = unary(l, IR_OP_EXTRACT, upper, old, bits + offset);
        value = binary(l, IR_OP_CONCAT, 32, high, value);
    }
    write_state(l, state, value);
}

static IrValueId effective_address(Lift *l, const cs_x86 *x, const cs_x86_op *op) {
    unsigned bits = x->addr_size * 8U;
    IrValueId value = constant(l, bits, (uint64_t)op->mem.disp);
    if (op->mem.base != X86_REG_INVALID) {
        IrValueId base = read_register(l, op->mem.base);
        value = binary(l, IR_OP_ADD, bits, value, base);
    }
    if (op->mem.index != X86_REG_INVALID) {
        IrValueId index = read_register(l, op->mem.index);
        if (op->mem.scale != 1) {
            IrValueId scale = constant(l, bits, (unsigned)op->mem.scale);
            index = binary(l, IR_OP_MUL, bits, index, scale);
        }
        value = binary(l, IR_OP_ADD, bits, value, index);
    }
    return value;
}

static IrValueId linear_address(Lift *l, const cs_x86 *x, const cs_x86_op *op) {
    IrValueId value = effective_address(l, x, op);
    return x->addr_size == 4 ? value : unary(l, IR_OP_ZEXT, 32, value, 0);
}

static IrValueId read_operand(Lift *l, const cs_x86 *x, const cs_x86_op *op, IrX86LiftResult *r) {
    if (op->type == X86_OP_REG)
        return read_register(l, op->reg);
    if (op->type == X86_OP_IMM)
        return constant(l, op->size * 8U, (uint64_t)op->imm);
    r->reads_memory = true;
    r->memory_bytes = op->size;
    r->address = linear_address(l, x, op);
    IrValueId memory = read_state(l, l->f->state.memory, ir_type_mem(32));
    r->read_data = emit(l, (IrInstSpec){.op = IR_OP_LOAD,
                                        .type = ir_type_bv(op->size * 8U),
                                        .args = {memory, r->address},
                                        .endian = IR_ENDIAN_LE});
    r->data = r->read_data;
    return r->read_data;
}

static void write_operand(Lift *l, const cs_x86 *x, const cs_x86_op *op, IrValueId value,
                          IrX86LiftResult *r) {
    if (op->type == X86_OP_REG) {
        r->gpr_writes = UINT32_C(1) << register_slice(op->reg).reg_id;
        write_register(l, op->reg, value);
    } else {
        r->writes_memory = true;
        r->memory_bytes = op->size;
        r->data = r->write_data = value;
        if (!r->reads_memory)
            r->address = linear_address(l, x, op);
        IrValueId memory = read_state(l, l->f->state.memory, ir_type_mem(32));
        IrValueId updated = emit(l, (IrInstSpec){.op = IR_OP_STORE,
                                                 .type = ir_type_mem(32),
                                                 .args = {memory, r->address, value},
                                                 .endian = IR_ENDIAN_LE});
        write_state(l, l->f->state.memory, updated);
    }
}

static IrValueId bit(Lift *l, IrValueId a, unsigned index) {
    return unary(l, IR_OP_EXTRACT, 1, a, index);
}

static void arithmetic_flags(Lift *l, unsigned id, unsigned width, IrValueId a, IrValueId b,
                             IrValueId result, IrX86LiftResult *r) {
    IrValueId flags[6];
    bool add = id == X86_INS_ADD;
    bool sub = id == X86_INS_SUB || id == X86_INS_CMP;
    flags[X86_SPECIAL_STATE_ZF] = binary(l, IR_OP_EQ, 1, result, constant(l, width, 0));
    flags[X86_SPECIAL_STATE_SF] = bit(l, result, width - 1U);
    IrValueId parity = bit(l, result, 0);
    for (unsigned i = 1; i < 8; ++i)
        parity = binary(l, IR_OP_XOR, 1, parity, bit(l, result, i));
    flags[X86_SPECIAL_STATE_PF] = unary(l, IR_OP_NOT, 1, parity, 0);
    if (add || sub) {
        IrValueId different = binary(l, IR_OP_XOR, width, a, b);
        IrValueId changed = binary(l, IR_OP_XOR, width, a, result);
        flags[X86_SPECIAL_STATE_CF] = binary(l, IR_OP_ULT, 1, add ? result : a, add ? a : b);
        flags[X86_SPECIAL_STATE_AF] = bit(l, binary(l, IR_OP_XOR, width, different, result), 4);
        IrValueId sign_mask = add ? unary(l, IR_OP_NOT, width, different, 0) : different;
        flags[X86_SPECIAL_STATE_OF] =
            bit(l, binary(l, IR_OP_AND, width, sign_mask, changed), width - 1U);
    } else {
        flags[X86_SPECIAL_STATE_CF] = constant(l, 1, 0);
        flags[X86_SPECIAL_STATE_OF] = constant(l, 1, 0);
        flags[X86_SPECIAL_STATE_AF] = emit(l, (IrInstSpec){.op = IR_OP_UNKNOWN,
                                                           .type = ir_type_bv(1),
                                                           .immediate = IR_REASON_UNDEFINED});
        r->flags_undefined = UINT32_C(1) << X86_SPECIAL_STATE_AF;
    }
    r->flags_written = 0x3f;
    for (unsigned i = 0; i < 6; ++i)
        write_state(l, l->f->state.flags[i], flags[i]);
    /* DF is preserved. No flags are copied from replay observations. */
}

static IrValueId branch_condition(Lift *l, unsigned cc) {
    IrValueId value;
    unsigned flag;
    switch (cc >> 1U) {
    case 0:
        flag = X86_SPECIAL_STATE_OF;
        break;
    case 1:
        flag = X86_SPECIAL_STATE_CF;
        break;
    case 2:
        flag = X86_SPECIAL_STATE_ZF;
        break;
    case 4:
        flag = X86_SPECIAL_STATE_SF;
        break;
    case 5:
        flag = X86_SPECIAL_STATE_PF;
        break;
    default:
        flag = IR_X86_FLAG_COUNT;
        break;
    }
    if (flag < IR_X86_FLAG_COUNT)
        value = read_state(l, l->f->state.flags[flag], ir_type_bv(1));
    else if ((cc >> 1U) == 3) {
        IrValueId cf = read_state(l, l->f->state.flags[X86_SPECIAL_STATE_CF], ir_type_bv(1));
        IrValueId zf = read_state(l, l->f->state.flags[X86_SPECIAL_STATE_ZF], ir_type_bv(1));
        value = binary(l, IR_OP_OR, 1, cf, zf);
    } else {
        IrValueId sf = read_state(l, l->f->state.flags[X86_SPECIAL_STATE_SF], ir_type_bv(1));
        IrValueId of = read_state(l, l->f->state.flags[X86_SPECIAL_STATE_OF], ir_type_bv(1));
        value = binary(l, IR_OP_XOR, 1, sf, of);
        if ((cc >> 1U) == 7) {
            IrValueId zf = read_state(l, l->f->state.flags[X86_SPECIAL_STATE_ZF], ir_type_bv(1));
            value = binary(l, IR_OP_OR, 1, value, zf);
        }
    }
    return cc & 1U ? unary(l, IR_OP_NOT, 1, value, 0) : value;
}

IrX86LiftResult ir_x86_lift(IrX86Frontend *f, IrBlockId block, const InsnDesc *d, IrOrigin origin) {
    IrX86LiftResult r = {.status = IR_X86_LIFT_ERROR};
    if (!f || !d || !ir_module_block(f->module, block) || ir_module_status(f->module) != IR_OK)
        return r;
    if (d->arch != TRACE_ARCH_X86 || d->mode != TRACE_MODE_32) {
        r.status = IR_X86_LIFT_MODE;
        return r;
    }
    if (!d->desc_id || !origin.seq_id || !d->size || d->size > MAX_INSN_BYTES ||
        d->pc > UINT32_MAX || d->bytes_hash != trace_instruction_bytes_hash(d->bytes, d->size) ||
        !origin.has_trace_identity || origin.descriptor_id != d->desc_id || origin.pc != d->pc ||
        origin.code_generation != d->code_generation) {
        r.status = IR_X86_LIFT_IDENTITY;
        return r;
    }
    cs_insn *insn = NULL;
    size_t n = cs_disasm(f->decoder, d->bytes, d->size, d->pc, 1, &insn);
    if (n != 1 || !insn->detail || insn->size != d->size || insn->id != d->native_insn_id) {
        if (n)
            cs_free(insn, n);
        r.status = IR_X86_LIFT_IDENTITY;
        return r;
    }
    r.status = supported_prefixes(d) ? preflight(f, insn) : IR_X86_LIFT_UNSUPPORTED;
    r.fallthrough = (uint32_t)(d->pc + d->size);
    if (r.status != IR_X86_LIFT_OK || insn->id == X86_INS_NOP) {
        cs_free(insn, n);
        return r;
    }
    Lift l = {f, block, origin};
    const cs_x86 *x = &insn->detail->x86;
    int cc = condition_code(insn->id);
    if (cc >= 0 || insn->id == X86_INS_JMP) {
        r.control = cc >= 0 ? IR_X86_CONDITIONAL : IR_X86_DIRECT_JUMP;
        r.direct_target = (uint32_t)x->operands[0].imm;
        if (cc >= 0)
            r.condition = branch_condition(&l, (unsigned)cc);
    } else {
        const cs_x86_op *dst = &x->operands[0], *src = &x->operands[1];
        IrValueId value;
        if (arithmetic(insn->id)) {
            IrValueId a = read_operand(&l, x, dst, &r);
            /* Identical aliases are one semantic read (self-XOR/CMP included). */
            IrValueId b = dst->type == X86_OP_REG && src->type == X86_OP_REG && dst->reg == src->reg
                              ? a
                              : read_operand(&l, x, src, &r);
            IrOpcode op = IR_OP_AND;
            switch (insn->id) {
            case X86_INS_ADD:
                op = IR_OP_ADD;
                break;
            case X86_INS_SUB:
            case X86_INS_CMP:
                op = IR_OP_SUB;
                break;
            case X86_INS_OR:
                op = IR_OP_OR;
                break;
            case X86_INS_XOR:
                op = IR_OP_XOR;
                break;
            default:
                break;
            }
            value = binary(&l, op, dst->size * 8U, a, b);
            arithmetic_flags(&l, insn->id, dst->size * 8U, a, b, value, &r);
        } else if (insn->id == X86_INS_LEA) {
            value = effective_address(&l, x, src);
            if (x->addr_size < dst->size)
                value = unary(&l, IR_OP_ZEXT, dst->size * 8U, value, 0);
            if (x->addr_size > dst->size)
                value = unary(&l, IR_OP_EXTRACT, dst->size * 8U, value, 0);
        } else {
            value = read_operand(&l, x, src, &r);
            if (insn->id == X86_INS_MOVZX || insn->id == X86_INS_MOVSX)
                value = unary(&l, insn->id == X86_INS_MOVZX ? IR_OP_ZEXT : IR_OP_SEXT,
                              dst->size * 8U, value, 0);
        }
        if (insn->id != X86_INS_CMP && insn->id != X86_INS_TEST)
            write_operand(&l, x, dst, value, &r);
    }
    if (ir_module_status(f->module) != IR_OK)
        r.status = IR_X86_LIFT_ERROR;
    cs_free(insn, n);
    return r;
}
