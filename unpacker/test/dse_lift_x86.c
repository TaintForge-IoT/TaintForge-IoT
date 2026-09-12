#include <stdint.h>
#include <stdbool.h>
#include <capstone/capstone.h>
#include "dta.h"
#include "trace.h"
#include "dse.h"

static bool is_high_byte(x86_reg r) {
    return r == X86_REG_AH || r == X86_REG_BH || r == X86_REG_CH || r == X86_REG_DH;
}

static bool x86_has_address_size_override(const cs_x86 *x86) {
    if (!x86)
        return true;
    for (unsigned i = 0; i < (sizeof(x86->prefix) / sizeof(x86->prefix[0])); i++) {
        if (x86->prefix[i] == 0x67) {
            return true;
        }
    }
    return false;
}

static bool x86_has_segment_override(const cs_x86 *x86) {
    if (!x86)
        return true;
    for (unsigned i = 0; i < (sizeof(x86->prefix) / sizeof(x86->prefix[0])); i++) {
        switch (x86->prefix[i]) {
        case 0x26:
        case 0x2e:
        case 0x36:
        case 0x3e:
        case 0x64:
        case 0x65:
            return true;
        default:
            break;
        }
    }
    return false;
}

static uint8_t x86_string_element_size(unsigned int instruction_id) {
    switch (instruction_id) {
    case X86_INS_MOVSB:
    case X86_INS_STOSB:
    case X86_INS_LODSB:
        return 1;
    case X86_INS_MOVSW:
    case X86_INS_STOSW:
    case X86_INS_LODSW:
        return 2;
    case X86_INS_MOVSD:
    case X86_INS_STOSD:
    case X86_INS_LODSD:
        return 4;
    case X86_INS_MOVSQ:
    case X86_INS_STOSQ:
    case X86_INS_LODSQ:
        return 8;
    default:
        return 0;
    }
}

static uint64_t x86_string_event_byte_address(uint64_t first, int8_t direction,
                                              uint8_t element_size, uint32_t event_index,
                                              uint8_t byte_index) {
    int64_t displacement =
        (int64_t)direction * (int64_t)event_index * (int64_t)element_size + (int64_t)byte_index;
    return (uint64_t)(uint32_t)((uint32_t)first + (uint32_t)displacement);
}

static SymExpr *x86_effective_address_expr(DSECtx *ctx, const cs_x86 *x86, const cs_x86_op *operand,
                                           const InsnAux *aux, const DseArch *arch,
                                           bool observed_roots) {
    if (!ctx || !x86 || !operand || !aux || !arch || !arch->reg_to_rid ||
        operand->type != X86_OP_MEM || arch->natural_width != 32 ||
        x86_has_address_size_override(x86) || operand->mem.segment != X86_REG_INVALID) {
        return NULL;
    }
    uint32_t width = arch->natural_width;
    SymExpr *address = sym_expr_const(0, width);
    if (!address)
        return NULL;
    if (operand->mem.base != X86_REG_INVALID) {
        int base_rid = arch->reg_to_rid(operand->mem.base);
        if (base_rid < 0) {
            sym_expr_free(address);
            return NULL;
        }
        SymExpr *base = observed_roots
                            ? dse_read_rid_observed_root(ctx, aux, base_rid, width, width)
                            : dse_read_rid_fit(ctx, aux, base_rid, width, width);
        if (!base) {
            sym_expr_free(address);
            return NULL;
        }
        address = sym_expr_add(address, base);
        if (!address)
            return NULL;
    }
    if (operand->mem.index != X86_REG_INVALID) {
        int index_rid = arch->reg_to_rid(operand->mem.index);
        if (index_rid < 0 || (operand->mem.scale != 1 && operand->mem.scale != 2 &&
                              operand->mem.scale != 4 && operand->mem.scale != 8)) {
            sym_expr_free(address);
            return NULL;
        }
        SymExpr *index = observed_roots
                             ? dse_read_rid_observed_root(ctx, aux, index_rid, width, width)
                             : dse_read_rid_fit(ctx, aux, index_rid, width, width);
        if (!index) {
            sym_expr_free(address);
            return NULL;
        }
        index = sym_expr_mul(index, sym_expr_const((uint64_t)operand->mem.scale, width));
        if (!index) {
            sym_expr_free(address);
            return NULL;
        }
        address = sym_expr_add(address, index);
        if (!address)
            return NULL;
    }
    if (operand->mem.disp != 0) {
        address =
            sym_expr_add(address, sym_expr_const((uint64_t)(int64_t)operand->mem.disp, width));
    }
    return address;
}

static bool x86_constrain_mem_operand(DSECtx *ctx, const cs_x86 *x86, const cs_x86_op *operand,
                                      const InsnAux *aux, const DseArch *arch,
                                      DseAddressAccess access) {
    if (!aux || !operand || operand->type != X86_OP_MEM) {
        return false;
    }
    uint64_t observed_address;
    if (access == DSE_ADDRESS_READ) {
        if (!aux->has_mem_read)
            return false;
        observed_address = aux->mem_read_addr;
    } else if (access == DSE_ADDRESS_WRITE) {
        if (!aux->has_mem_write)
            return false;
        observed_address = aux->mem_write_addr;
    } else {
        return false;
    }
    SymExpr *address = x86_effective_address_expr(ctx, x86, operand, aux, arch, true);
    return dse_constrain_observed_address(ctx, address, observed_address, access);
}

static SymExpr *x86_flag_not(SymExpr *value) {
    if (!value)
        return NULL;
    return sym_expr_xor(value, sym_expr_const(1, 1));
}

static SymExpr *x86_even_parity(SymExpr *value) {
    if (!value)
        return NULL;
    if (value->width < 8) {
        value = sym_expr_zext(value, 8);
    } else if (value->width > 8) {
        value = sym_expr_extract(value, 0, 8);
    }
    if (!value)
        return NULL;
    SymExpr *parity = sym_expr_extract(sym_expr_clone(value), 0, 1);
    for (uint32_t bit = 1; bit < 8 && parity; bit++) {
        parity = sym_expr_xor(parity, sym_expr_extract(sym_expr_clone(value), bit, 1));
    }
    sym_expr_free(value);
    return x86_flag_not(parity);
}

static void x86_set_zsp_flags(DSECtx *ctx, const SymExpr *result) {
    if (!ctx || !result || result->width == 0) {
        if (ctx) {
            dse_invalidate_x86_flags(ctx, X86_FLAG_ZF | X86_FLAG_SF | X86_FLAG_PF);
        }
        return;
    }
    dse_set_x86_flag(ctx, X86_FLAG_ZF,
                     sym_expr_eq(sym_expr_clone(result), sym_expr_const(0, result->width)));
    dse_set_x86_flag(ctx, X86_FLAG_SF,
                     sym_expr_extract(sym_expr_clone(result), (result->width - 1U), 1));
    dse_set_x86_flag(ctx, X86_FLAG_PF, x86_even_parity(sym_expr_clone(result)));
}

static void x86_set_arithmetic_flags(DSECtx *ctx, const SymExpr *left, const SymExpr *right,
                                     const SymExpr *result, bool subtraction, bool preserve_cf) {
    if (!ctx || !left || !right || !result || left->width == 0 || left->width != right->width ||
        left->width != result->width) {
        if (ctx) {
            dse_invalidate_x86_flags(ctx, X86_FLAG_TRACKED);
        }
        return;
    }
    uint32_t msb = left->width - 1U;
    SymExpr *left_sign = sym_expr_extract(sym_expr_clone(left), msb, 1);
    SymExpr *right_sign = sym_expr_extract(sym_expr_clone(right), msb, 1);
    SymExpr *result_sign = sym_expr_extract(sym_expr_clone(result), msb, 1);
    SymExpr *left_xor_right = sym_expr_xor(sym_expr_clone(left_sign), sym_expr_clone(right_sign));
    SymExpr *left_xor_result = sym_expr_xor(sym_expr_clone(left_sign), sym_expr_clone(result_sign));
    SymExpr *overflow = subtraction ? sym_expr_and(left_xor_right, left_xor_result)
                                    : sym_expr_and(x86_flag_not(left_xor_right), left_xor_result);
    dse_set_x86_flag(ctx, X86_FLAG_OF, overflow);
    SymExpr *auxiliary = sym_expr_xor(sym_expr_xor(sym_expr_clone(left), sym_expr_clone(right)),
                                      sym_expr_clone(result));
    dse_set_x86_flag(ctx, X86_FLAG_AF, sym_expr_extract(auxiliary, 4, 1));

    if (!preserve_cf) {
        SymExpr *carry = subtraction ? sym_expr_ult(sym_expr_clone(left), sym_expr_clone(right))
                                     : sym_expr_ult(sym_expr_clone(result), sym_expr_clone(left));
        dse_set_x86_flag(ctx, X86_FLAG_CF, carry);
    }
    x86_set_zsp_flags(ctx, result);
    sym_expr_free(left_sign);
    sym_expr_free(right_sign);
    sym_expr_free(result_sign);
}

static void x86_set_logical_flags(DSECtx *ctx, const SymExpr *result) {
    if (!ctx || !result) {
        if (ctx) {
            dse_invalidate_x86_flags(ctx, X86_FLAG_TRACKED);
        }

        return;
    }

    dse_set_x86_flag(ctx, X86_FLAG_CF, sym_expr_const(0, 1));

    dse_set_x86_flag(ctx, X86_FLAG_OF, sym_expr_const(0, 1));

    dse_invalidate_x86_flags(ctx, X86_FLAG_AF);

    x86_set_zsp_flags(ctx, result);
}

static X86ConditionCode x86_condition_code_from_id(unsigned int id) {
    switch (id) {
    case X86_INS_JO:
        return X86_CC_O;

    case X86_INS_JNO:
        return X86_CC_NO;

    case X86_INS_JB:
        return X86_CC_B;

    case X86_INS_JAE:
        return X86_CC_AE;

    case X86_INS_JE:
        return X86_CC_E;

    case X86_INS_JNE:
        return X86_CC_NE;

    case X86_INS_JBE:
        return X86_CC_BE;

    case X86_INS_JA:
        return X86_CC_A;

    case X86_INS_JS:
        return X86_CC_S;

    case X86_INS_JNS:
        return X86_CC_NS;

    case X86_INS_JP:
        return X86_CC_P;

    case X86_INS_JNP:
        return X86_CC_NP;

    case X86_INS_JL:
        return X86_CC_L;

    case X86_INS_JGE:
        return X86_CC_GE;

    case X86_INS_JLE:
        return X86_CC_LE;

    case X86_INS_JG:
        return X86_CC_G;

    default:
        return X86_CC_NONE;
    }
}

static SymExpr *x86_condition_expr(DSECtx *ctx, const InsnAux *aux, X86ConditionCode condition) {
    SymExpr *cf = NULL;
    SymExpr *zf = NULL;
    SymExpr *sf = NULL;
    SymExpr *of = NULL;
    SymExpr *different = NULL;

    switch (condition) {
    case X86_CC_O:
        return dse_get_x86_flag(ctx, aux, X86_FLAG_OF);

    case X86_CC_NO:
        return x86_flag_not(dse_get_x86_flag(ctx, aux, X86_FLAG_OF));

    case X86_CC_B:
        return dse_get_x86_flag(ctx, aux, X86_FLAG_CF);

    case X86_CC_AE:
        return x86_flag_not(dse_get_x86_flag(ctx, aux, X86_FLAG_CF));

    case X86_CC_E:
        return dse_get_x86_flag(ctx, aux, X86_FLAG_ZF);

    case X86_CC_NE:
        return x86_flag_not(dse_get_x86_flag(ctx, aux, X86_FLAG_ZF));

    case X86_CC_BE:
        cf = dse_get_x86_flag(ctx, aux, X86_FLAG_CF);

        zf = dse_get_x86_flag(ctx, aux, X86_FLAG_ZF);

        return sym_expr_or(cf, zf);

    case X86_CC_A:
        cf = dse_get_x86_flag(ctx, aux, X86_FLAG_CF);

        zf = dse_get_x86_flag(ctx, aux, X86_FLAG_ZF);

        return x86_flag_not(sym_expr_or(cf, zf));

    case X86_CC_S:
        return dse_get_x86_flag(ctx, aux, X86_FLAG_SF);

    case X86_CC_NS:
        return x86_flag_not(dse_get_x86_flag(ctx, aux, X86_FLAG_SF));

    case X86_CC_P:
        return dse_get_x86_flag(ctx, aux, X86_FLAG_PF);

    case X86_CC_NP:
        return x86_flag_not(dse_get_x86_flag(ctx, aux, X86_FLAG_PF));

    case X86_CC_L:
        sf = dse_get_x86_flag(ctx, aux, X86_FLAG_SF);

        of = dse_get_x86_flag(ctx, aux, X86_FLAG_OF);

        return sym_expr_xor(sf, of);

    case X86_CC_GE:
        sf = dse_get_x86_flag(ctx, aux, X86_FLAG_SF);

        of = dse_get_x86_flag(ctx, aux, X86_FLAG_OF);

        return x86_flag_not(sym_expr_xor(sf, of));

    case X86_CC_LE:
        zf = dse_get_x86_flag(ctx, aux, X86_FLAG_ZF);

        sf = dse_get_x86_flag(ctx, aux, X86_FLAG_SF);

        of = dse_get_x86_flag(ctx, aux, X86_FLAG_OF);

        different = sym_expr_xor(sf, of);

        return sym_expr_or(zf, different);

    case X86_CC_G:
        zf = dse_get_x86_flag(ctx, aux, X86_FLAG_ZF);

        sf = dse_get_x86_flag(ctx, aux, X86_FLAG_SF);

        of = dse_get_x86_flag(ctx, aux, X86_FLAG_OF);

        different = sym_expr_xor(sf, of);

        return x86_flag_not(sym_expr_or(zf, different));

    case X86_CC_NONE:
    default:
        return NULL;
    }
}

//processing of all types from the disassembler
static SymExpr *get_operand_expr(DSECtx *ctx, const cs_x86 *x86, const cs_x86_op *op,
                                 uint32_t want_w, const InsnAux *aux, const DseArch *arch) {
    if (op->type == X86_OP_REG) {
        int rid = x86_reg_to_rid(op->reg);
        if (rid < 0)
            return NULL;
        uint32_t operand_width = op->size != 0 ? (uint32_t)op->size * 8 : want_w;
        uint32_t low_bit = is_high_byte(op->reg) ? 8 : 0;
        SymExpr *value =
            dse_read_rid_slice(ctx, aux, rid, low_bit, operand_width, arch->natural_width);
        if (!value)
            return NULL;
        if (value->width < want_w) {
            value = sym_expr_zext(value, want_w);
        } else if (value->width > want_w) {
            value = sym_expr_extract(value, 0, want_w);
        }
        return value;
    }
    if (op->type == X86_OP_IMM) {
        return sym_expr_const((uint64_t)(int64_t)op->imm, want_w);
    }
    if (op->type == X86_OP_MEM) {
        if (!x86_constrain_mem_operand(ctx, x86, op, aux, arch, DSE_ADDRESS_READ)) {
            return NULL;
        }
        return dse_load_mem(ctx, aux, want_w, arch->big_endian);
    }
    return NULL;
}

//write symexpr to register
static bool commit_reg(DSECtx *ctx, const InsnAux *aux, const DseArch *arch, x86_reg dreg,
                       SymExpr *val, uint32_t w) {
    int rid = x86_reg_to_rid(dreg);
    if (rid < 0) {
        sym_expr_free(val);
        return false;
    }
    if (!val) {
        sym_state_set_reg(&ctx->state, rid, NULL);
        return false;
    }
    uint32_t low_bit = is_high_byte(dreg) ? 8 : 0;

    return dse_commit_slice(ctx, aux, rid, val, low_bit, w, arch->natural_width);
}

//work with operands
static bool commit_operand(DSECtx *ctx, const cs_x86 *x86, const InsnAux *aux, const DseArch *arch,
                           const cs_x86_op *destination, SymExpr *value, uint32_t width) {
    if (!destination || !value) {
        sym_expr_free(value);
        return false;
    }
    if (value->width < width) {
        value = sym_expr_zext(value, width);
    } else if (value->width > width) {
        value = sym_expr_extract(value, 0, width);
    }
    if (!value)
        return false;
    if (destination->type == X86_OP_REG) {
        return commit_reg(ctx, aux, arch, destination->reg, value, width);
    }
    if (destination->type == X86_OP_MEM) {
        if (!aux || !aux->has_mem_write) {
            sym_expr_free(value);
            return false;
        }
        if (!x86_constrain_mem_operand(ctx, x86, destination, aux, arch, DSE_ADDRESS_WRITE)) {
            sym_expr_free(value);
            return false;
        }
        return dse_store_mem(ctx, aux, value, arch->big_endian);
    }
    sym_expr_free(value);
    return false;
}

//lifter for mov inst
static bool lift_mov(DSECtx *ctx, const cs_insn *insn, const cs_x86 *x86, const InsnAux *aux,
                     const DseArch *arch) {
    if (x86->op_count != 2)
        return false;
    const cs_x86_op *dst = &x86->operands[0], *src = &x86->operands[1];
    uint32_t w = (uint32_t)dst->size * 8;
    SymExpr *src_e = get_operand_expr(ctx, x86, src, (uint32_t)src->size * 8, aux, arch);
    if (!src_e) {
        return false;
    } else {
        uint8_t sw = src_e->width;
        if (sw < w) {
            src_e = (insn->id == X86_INS_MOVSX) ? sym_expr_sext(src_e, w) : sym_expr_zext(src_e, w);
        } else if (sw > w) {
            src_e = sym_expr_extract(src_e, 0, w);
        }
    }
    return commit_operand(ctx, x86, aux, arch, dst, src_e, w);
}

static bool shift_or_rotate(unsigned int instruction_id) {
    switch (instruction_id) {
    case X86_INS_SHL:
    case X86_INS_SAL:
    case X86_INS_SHR:
    case X86_INS_SAR:
    case X86_INS_ROL:
    case X86_INS_ROR:
        return true;
    default:
        return false;
    }
}

static SymExpr *mask_x86_shift_count(SymExpr *count, uint32_t operand_width) {
    if (!count)
        return NULL;
    uint64_t mask = operand_width == 64 ? 0x3f : 0x1f;
    return sym_expr_and(count, sym_expr_const(mask, count->width));
}

//lifter for arithmetics
static bool lift_arith(DSECtx *ctx, const cs_insn *insn, const cs_x86 *x86, const InsnAux *aux,
                       const DseArch *arch) {
    if (x86->op_count < 2)
        return false;
    const cs_x86_op *dst = &x86->operands[0];
    const cs_x86_op *src = &x86->operands[1];
    if (dst->type != X86_OP_REG && dst->type != X86_OP_MEM) {
        return false;
    }
    uint32_t width = (uint32_t)dst->size * 8U;
    if (width == 0)
        return false;
    SymExpr *destination = get_operand_expr(ctx, x86, dst, width, aux, arch);
    uint32_t source_width = width;
    if (shift_or_rotate(insn->id) && src->size != 0) {
        source_width = (uint32_t)src->size * 8U;
    }
    SymExpr *source = get_operand_expr(ctx, x86, src, source_width, aux, arch);
    if (shift_or_rotate(insn->id)) {
        source = mask_x86_shift_count(source, width);
    }
    if (!destination || !source) {
        sym_expr_free(destination);
        sym_expr_free(source);
        return false;
    }
    SymExpr *flag_left = NULL;
    SymExpr *flag_right = NULL;
    if (insn->id == X86_INS_ADD || insn->id == X86_INS_SUB) {
        flag_left = sym_expr_clone(destination);
        flag_right = sym_expr_clone(source);
        if (!flag_left || !flag_right) {
            sym_expr_free(flag_left);
            sym_expr_free(flag_right);
            sym_expr_free(destination);
            sym_expr_free(source);
            return false;
        }
    }
    SymExpr *result = NULL;
    switch (insn->id) {
    case X86_INS_ADD:
        result = sym_expr_add(destination, source);
        break;
    case X86_INS_SUB:
        result = sym_expr_sub(destination, source);
        break;
    case X86_INS_XOR:
        result = sym_expr_xor(destination, source);
        break;
    case X86_INS_AND:
        result = sym_expr_and(destination, source);
        break;
    case X86_INS_OR:
        result = sym_expr_or(destination, source);
        break;
    case X86_INS_SHL:
    case X86_INS_SAL:
        result = sym_expr_shl(destination, source);
        break;
    case X86_INS_SHR:
        result = sym_expr_shr(destination, source);
        break;
    case X86_INS_SAR:
        result = sym_expr_sar(destination, source);
        break;
    case X86_INS_ROL:
        result = sym_expr_rol(destination, source);
        break;
    case X86_INS_ROR:
        result = sym_expr_ror(destination, source);
        break;
    default:
        sym_expr_free(flag_left);
        sym_expr_free(flag_right);
        sym_expr_free(destination);
        sym_expr_free(source);
        return false;
    }
    if (!result) {
        sym_expr_free(flag_left);
        sym_expr_free(flag_right);
        return false;
    }
    switch (insn->id) {
    case X86_INS_ADD:
        x86_set_arithmetic_flags(ctx, flag_left, flag_right, result, false, false);
        break;
    case X86_INS_SUB:
        x86_set_arithmetic_flags(ctx, flag_left, flag_right, result, true, false);
        break;
    case X86_INS_XOR:
    case X86_INS_AND:
    case X86_INS_OR:
        x86_set_logical_flags(ctx, result);
        break;
    case X86_INS_SHL:
    case X86_INS_SAL:
    case X86_INS_SHR:
    case X86_INS_SAR:
        dse_invalidate_x86_flags(ctx, X86_FLAG_TRACKED);
        break;
    case X86_INS_ROL:
    case X86_INS_ROR:
        dse_invalidate_x86_flags(ctx, X86_FLAG_CF | X86_FLAG_OF);
        break;
    default:
        break;
    }
    sym_expr_free(flag_left);
    sym_expr_free(flag_right);
    return commit_operand(ctx, x86, aux, arch, dst, result, width);
}

static bool lift_compare(DSECtx *ctx, const cs_insn *insn, const cs_x86 *x86, const InsnAux *aux,
                         const DseArch *arch) {
    if (!ctx || !insn || !x86 || !aux || !arch || x86->op_count != 2 ||
        (insn->id != X86_INS_CMP && insn->id != X86_INS_TEST)) {
        return false;
    }
    const cs_x86_op *left_operand = &x86->operands[0];
    const cs_x86_op *right_operand = &x86->operands[1];
    uint32_t width = (uint32_t)left_operand->size * 8U;
    if (width == 0)
        return false;

    SymExpr *left = get_operand_expr(ctx, x86, left_operand, width, aux, arch);
    SymExpr *right = get_operand_expr(ctx, x86, right_operand, width, aux, arch);
    if (!left || !right) {
        sym_expr_free(left);
        sym_expr_free(right);
        return false;
    }
    SymExpr *result = insn->id == X86_INS_CMP
                          ? sym_expr_sub(sym_expr_clone(left), sym_expr_clone(right))
                          : sym_expr_and(sym_expr_clone(left), sym_expr_clone(right));
    if (!result) {
        sym_expr_free(left);
        sym_expr_free(right);
        return false;
    }
    if (insn->id == X86_INS_CMP) {
        x86_set_arithmetic_flags(ctx, left, right, result, true, false);
    } else {
        x86_set_logical_flags(ctx, result);
    }
    sym_expr_free(result);
    sym_expr_free(left);
    sym_expr_free(right);
    return true;
}

//lifter for unary
static bool lift_unary(DSECtx *ctx, const cs_insn *insn, const cs_x86 *x86, const InsnAux *aux,
                       const DseArch *arch) {
    if (x86->op_count != 1)
        return false;
    const cs_x86_op *destination = &x86->operands[0];
    if (destination->type != X86_OP_REG && destination->type != X86_OP_MEM) {
        return false;
    }
    uint32_t width = (uint32_t)destination->size * 8U;
    if (width == 0)
        return false;
    SymExpr *old_value = get_operand_expr(ctx, x86, destination, width, aux, arch);
    if (!old_value)
        return false;
    SymExpr *flag_input = sym_expr_clone(old_value);
    if (!flag_input) {
        sym_expr_free(old_value);
        return false;
    }
    SymExpr *result = NULL;
    switch (insn->id) {
    case X86_INS_NOT:
        result = sym_expr_not(old_value);
        break;
    case X86_INS_NEG:
        result = sym_expr_neg(old_value);
        break;
    case X86_INS_INC:
        result = sym_expr_add(old_value, sym_expr_const(1, width));
        break;
    case X86_INS_DEC:
        result = sym_expr_sub(old_value, sym_expr_const(1, width));
        break;
    default:
        sym_expr_free(flag_input);
        sym_expr_free(old_value);
        return false;
    }
    if (!result) {
        sym_expr_free(flag_input);
        return false;
    }
    switch (insn->id) {
    case X86_INS_NEG: {
        SymExpr *zero = sym_expr_const(0, width);
        x86_set_arithmetic_flags(ctx, zero, flag_input, result, true, false);
        sym_expr_free(zero);
        break;
    }
    case X86_INS_INC: {
        SymExpr *one = sym_expr_const(1, width);
        x86_set_arithmetic_flags(ctx, flag_input, one, result, false, true);
        sym_expr_free(one);
        break;
    }
    case X86_INS_DEC: {
        SymExpr *one = sym_expr_const(1, width);
        x86_set_arithmetic_flags(ctx, flag_input, one, result, true, true);
        sym_expr_free(one);
        break;
    }
    case X86_INS_NOT:
    default:
        break;
    }
    sym_expr_free(flag_input);
    return commit_operand(ctx, x86, aux, arch, destination, result, width);
}

//lifter for lua
static bool lift_lea(DSECtx *ctx, const cs_insn *insn, const cs_x86 *x86, const InsnAux *aux,
                     const DseArch *arch) {
    (void)insn;
    if (x86->op_count != 2)
        return false;
    const cs_x86_op *dst = &x86->operands[0];
    const cs_x86_op *mem = &x86->operands[1];
    if (dst->type != X86_OP_REG || mem->type != X86_OP_MEM) {
        return false;
    }
    uint32_t width = (uint32_t)dst->size * 8U;
    if (width != 16U && width != 32U) {
        return false;
    }
    SymExpr *address = x86_effective_address_expr(ctx, x86, mem, aux, arch, false);
    if (!address)
        return false;
    if (address->width > width) {
        address = sym_expr_extract(address, 0, width);
    }
    return commit_reg(ctx, aux, arch, dst->reg, address, width);
}

//lifter for imul
static bool lift_imul(DSECtx *ctx, const cs_insn *insn, const cs_x86 *x86, const InsnAux *aux,
                      const DseArch *arch) {
    (void)insn;
    if (x86->op_count == 2) {
        const cs_x86_op *dst = &x86->operands[0], *src = &x86->operands[1];
        if (dst->type != X86_OP_REG)
            return false;
        uint32_t w = (uint32_t)dst->size * 8;
        SymExpr *a = get_operand_expr(ctx, x86, dst, w, aux, arch);
        SymExpr *b = get_operand_expr(ctx, x86, src, w, aux, arch);
        if (!a || !b) {
            sym_expr_free(a);
            sym_expr_free(b);
            return commit_reg(ctx, aux, arch, dst->reg, NULL, w);
        }
        SymExpr *result = sym_expr_mul(a, b);
        if (!result)
            return false;
        dse_invalidate_x86_flags(ctx, X86_FLAG_TRACKED);
        return commit_reg(ctx, aux, arch, dst->reg, result, w);
    }
    if (x86->op_count == 3) {
        const cs_x86_op *dst = &x86->operands[0], *src = &x86->operands[1],
                        *imm = &x86->operands[2];
        if (dst->type != X86_OP_REG || imm->type != X86_OP_IMM)
            return false;
        uint32_t w = (uint32_t)dst->size * 8;
        SymExpr *a = get_operand_expr(ctx, x86, src, w, aux, arch);
        SymExpr *b = sym_expr_const((uint64_t)(int64_t)imm->imm, w);
        if (!a) {
            sym_expr_free(b);
            return commit_reg(ctx, aux, arch, dst->reg, NULL, w);
        }
        SymExpr *result = sym_expr_mul(a, b);
        if (!result)
            return false;
        dse_invalidate_x86_flags(ctx, X86_FLAG_TRACKED);
        return commit_reg(ctx, aux, arch, dst->reg, result, w);
    }
    return false;
}

static uint8_t x86_tracked_flag_for_bit(uint32_t bit) {
    switch (bit) {
    case 0:
        return X86_FLAG_CF;
    case 2:
        return X86_FLAG_PF;
    case 4:
        return X86_FLAG_AF;
    case 6:
        return X86_FLAG_ZF;
    case 7:
        return X86_FLAG_SF;
    case 11:
        return X86_FLAG_OF;
    default:
        return 0;
    }
}

static SymExpr *x86_build_pushf_value(DSECtx *ctx, const InsnAux *aux, uint32_t width) {
    if (!ctx || !aux || !aux->eflags_valid || (width != 16U && width != 32U)) {
        return NULL;
    }
    SymExpr *value = NULL;
    for (uint32_t bit = 0; bit < width; bit++) {
        uint8_t tracked_flag = x86_tracked_flag_for_bit(bit);
        SymExpr *bit_value = tracked_flag != 0
                                 ? dse_get_x86_flag(ctx, aux, tracked_flag)
                                 : sym_expr_const((aux->eflags_before >> bit) & UINT32_C(1), 1);
        if (!bit_value) {
            sym_expr_free(value);
            return NULL;
        }
        value = value ? sym_expr_concat(bit_value, value) : bit_value;
        if (!value)
            return NULL;
    }
    return value;
}

static bool lift_pushf(DSECtx *ctx, const cs_insn *insn, const InsnAux *aux, const DseArch *arch) {
    if (!ctx || !insn || !aux || !arch || arch->natural_width != 32 || arch->big_endian ||
        !aux->eflags_valid || !aux->has_mem_write || aux->mem_write_overflow ||
        aux->mem_write_count != 1 || aux->mem_write_total != 1 || !aux->mem_writes[0].value_valid) {
        return false;
    }
    uint32_t pushed_bytes = aux->mem_writes[0].size;
    if ((pushed_bytes != 2U && pushed_bytes != 4U) || aux->mem_write_size != pushed_bytes ||
        aux->mem_write_addr != aux->mem_writes[0].addr) {
        return false;
    }

    uint32_t pushed_width = pushed_bytes * 8U;
    SymExpr *flags_value = x86_build_pushf_value(ctx, aux, pushed_width);
    if (!flags_value)
        return false;
    SymExpr *old_stack_pointer =
        dse_read_rid_observed_root(ctx, aux, REG_RSP, arch->natural_width, arch->natural_width);
    if (!old_stack_pointer) {
        sym_expr_free(flags_value);
        return false;
    }
    SymExpr *new_stack_pointer =
        sym_expr_sub(old_stack_pointer, sym_expr_const(pushed_bytes, arch->natural_width));
    if (!new_stack_pointer) {
        sym_expr_free(flags_value);
        return false;
    }
    if (!dse_constrain_observed_address(ctx, sym_expr_clone(new_stack_pointer),
                                        aux->mem_writes[0].addr, DSE_ADDRESS_WRITE)) {
        sym_expr_free(flags_value);
        sym_expr_free(new_stack_pointer);
        return false;
    }
    if (!dse_store_mem(ctx, aux, flags_value, false)) {
        sym_expr_free(new_stack_pointer);
        return false;
    }
    dse_set_reg(ctx, REG_RSP, new_stack_pointer, arch->natural_width);
    return true;
}

//lifter for push
static bool lift_push(DSECtx *ctx, const cs_insn *insn, const cs_x86 *x86, const InsnAux *aux,
                      const DseArch *arch) {
    (void)insn;
    if (x86->op_count != 1 || !aux || !aux->has_mem_write || arch->natural_width != 32) {
        return false;
    }

    const cs_x86_op *src = &x86->operands[0];
    if (src->type != X86_OP_REG && src->type != X86_OP_IMM && src->type != X86_OP_MEM) {
        return false;
    }

    bool operand_size_16 = false;
    for (unsigned i = 0; i < (sizeof(x86->prefix) / sizeof(x86->prefix[0])); i++) {
        if (x86->prefix[i] == 0x66) {
            operand_size_16 = true;
            break;
        }
    }
    uint32_t pointer_width = arch->natural_width;
    uint32_t pushed_width = operand_size_16 ? 16u : 32u;
    uint32_t pushed_bytes = pushed_width / 8u;
    uint32_t source_width = src->size != 0 ? (uint32_t)src->size * 8u : pushed_width;

    SymExpr *value = get_operand_expr(ctx, x86, src, source_width, aux, arch);
    if (!value)
        return false;
    if (value->width < pushed_width) {
        if (src->type == X86_OP_IMM) {
            value = sym_expr_sext(value, pushed_width);
        } else {
            value = sym_expr_zext(value, pushed_width);
        }
    } else if (value->width > pushed_width) {
        value = sym_expr_extract(value, 0, pushed_width);
    }
    if (!value)
        return false;

    SymExpr *old_stack_pointer =
        dse_read_rid_observed_root(ctx, aux, REG_RSP, pointer_width, pointer_width);
    if (!old_stack_pointer) {
        sym_expr_free(value);
        return false;
    }
    SymExpr *new_stack_pointer =
        sym_expr_sub(old_stack_pointer, sym_expr_const(pushed_bytes, pointer_width));
    if (!new_stack_pointer) {
        sym_expr_free(value);
        return false;
    }
    if (!dse_constrain_observed_address(ctx, sym_expr_clone(new_stack_pointer), aux->mem_write_addr,
                                        DSE_ADDRESS_WRITE)) {
        sym_expr_free(value);
        sym_expr_free(new_stack_pointer);
        return false;
    }
    if (!dse_store_mem(ctx, aux, value, arch->big_endian)) {
        sym_expr_free(new_stack_pointer);
        return false;
    }
    dse_set_reg(ctx, REG_RSP, new_stack_pointer, pointer_width);
    return true;
}

//lifter for pop
static bool lift_pop(DSECtx *ctx, const cs_insn *insn, const cs_x86 *x86, const InsnAux *aux,
                     const DseArch *arch) {
    (void)insn;
    if (x86->op_count != 1 || !aux || !aux->has_mem_read || arch->natural_width != 32) {
        return false;
    }

    const cs_x86_op *dst = &x86->operands[0];
    if (dst->type != X86_OP_REG && dst->type != X86_OP_MEM) {
        return false;
    }
    if (dst->type == X86_OP_MEM && !aux->has_mem_write) {
        return false;
    }

    bool operand_size_16 = false;
    for (unsigned i = 0; i < (sizeof(x86->prefix) / sizeof(x86->prefix[0])); i++) {
        if (x86->prefix[i] == 0x66) {
            operand_size_16 = true;
            break;
        }
    }

    uint32_t pointer_width = arch->natural_width;
    uint32_t popped_width = operand_size_16 ? 16u : 32u;
    uint32_t popped_bytes = popped_width / 8u;
    if (dst->size != 0 && (uint32_t)dst->size * 8u != popped_width) {
        return false;
    }

    SymExpr *old_stack_pointer =
        dse_read_rid_observed_root(ctx, aux, REG_RSP, pointer_width, pointer_width);
    if (!old_stack_pointer)
        return false;
    if (!dse_constrain_observed_address(ctx, sym_expr_clone(old_stack_pointer), aux->mem_read_addr,
                                        DSE_ADDRESS_READ)) {
        sym_expr_free(old_stack_pointer);
        return false;
    }

    SymExpr *value = dse_load_mem(ctx, aux, popped_width, arch->big_endian);
    if (!value) {
        sym_expr_free(old_stack_pointer);
        return false;
    }
    SymExpr *new_stack_pointer =
        sym_expr_add(old_stack_pointer, sym_expr_const(popped_bytes, pointer_width));
    if (!new_stack_pointer) {
        sym_expr_free(value);
        return false;
    }
    dse_set_reg(ctx, REG_RSP, new_stack_pointer, pointer_width);
    return commit_operand(ctx, x86, aux, arch, dst, value, popped_width);
}

//lifter leave
static bool lift_leave(DSECtx *ctx, const cs_insn *insn, const cs_x86 *x86, const InsnAux *aux,
                       const DseArch *arch) {
    (void)insn;
    if (!ctx || !x86 || !aux || !arch || !aux->has_mem_read || arch->natural_width != 32 ||
        x86->op_count != 0) {
        return false;
    }

    bool operand_size_16 = false;
    bool address_size_16 = false;
    for (unsigned i = 0; i < (sizeof(x86->prefix) / sizeof(x86->prefix[0])); i++) {
        if (x86->prefix[i] == 0x66) {
            operand_size_16 = true;
        }
        if (x86->prefix[i] == 0x67) {
            address_size_16 = true;
        }
    }
    if (address_size_16)
        return false;

    uint32_t popped_width = operand_size_16 ? 16u : 32u;
    uint32_t popped_bytes = popped_width / 8u;

    SymExpr *old_frame_pointer = dse_read_rid_observed_root(ctx, aux, REG_RBP, 32, 32);
    if (!old_frame_pointer)
        return false;
    if (!dse_constrain_observed_address(ctx, sym_expr_clone(old_frame_pointer), aux->mem_read_addr,
                                        DSE_ADDRESS_READ)) {
        sym_expr_free(old_frame_pointer);
        return false;
    }
    SymExpr *restored_frame_pointer = dse_load_mem(ctx, aux, popped_width, arch->big_endian);
    if (!restored_frame_pointer) {
        sym_expr_free(old_frame_pointer);
        return false;
    }
    SymExpr *new_stack_pointer = sym_expr_add(old_frame_pointer, sym_expr_const(popped_bytes, 32));
    if (!new_stack_pointer) {
        sym_expr_free(restored_frame_pointer);
        return false;
    }
    dse_set_reg(ctx, REG_RSP, new_stack_pointer, 32);

    if (operand_size_16) {
        return commit_reg(ctx, aux, arch, X86_REG_BP, restored_frame_pointer, 16);
    }
    dse_set_reg(ctx, REG_RBP, restored_frame_pointer, 32);

    return true;
}

//lifter popal
static bool lift_popal(DSECtx *ctx, const cs_insn *insn, const cs_x86 *x86, const InsnAux *aux,
                       const DseArch *arch) {
    (void)insn;
    if (!ctx || !x86 || !aux || !arch || arch->natural_width != 32 || x86->op_count != 0 ||
        aux->mem_read_count < 7) {
        return false;
    }
    for (unsigned i = 0; i < sizeof(x86->prefix) / sizeof(x86->prefix[0]); i++) {
        if (x86->prefix[i] == 0x66 || x86->prefix[i] == 0x67) {
            return false;
        }
    }
    static const uint32_t stack_offsets[7] = {0, 4, 8, 16, 20, 24, 28};
    static const x86_reg destination_registers[7] = {
        X86_REG_EDI, X86_REG_ESI, X86_REG_EBP, X86_REG_EBX, X86_REG_EDX, X86_REG_ECX, X86_REG_EAX};
    SymExpr *values[7] = {0};
    SymExpr *old_stack_pointer = NULL;
    int destination_rids[7];
    uint32_t old_esp = (uint32_t)aux->reg_vals[REG_RSP];
    old_stack_pointer = dse_read_rid_observed_root(ctx, aux, REG_RSP, 32, 32);
    if (!old_stack_pointer)
        goto fail;
    for (uint32_t i = 0; i < 7; i++) {
        destination_rids[i] = x86_reg_to_rid(destination_registers[i]);
        if (destination_rids[i] < 0 || destination_rids[i] >= REG_COUNT) {
            goto fail;
        }
        uint32_t expected_addr = old_esp + stack_offsets[i];
        const DseMemRead *read = NULL;
        for (uint32_t j = 0; j < aux->mem_read_count; j++) {
            const DseMemRead *candidate = &aux->mem_reads[j];
            if (candidate->value_valid && (uint32_t)candidate->addr == expected_addr &&
                candidate->size == 4) {
                read = candidate;
                break;
            }
        }
        if (!read)
            goto fail;
        SymExpr *read_address =
            sym_expr_add(sym_expr_clone(old_stack_pointer), sym_expr_const(stack_offsets[i], 32));
        if (!dse_constrain_observed_address(ctx, read_address, read->addr, DSE_ADDRESS_READ)) {
            goto fail;
        }
        InsnAux selected_read = *aux;
        selected_read.has_mem_read = true;
        selected_read.mem_read_addr = read->addr;
        selected_read.mem_read_val = read->value;
        selected_read.mem_read_taint = read->taint;
        selected_read.mem_read_value_valid = true;
        values[i] = dse_load_mem(ctx, &selected_read, 32, arch->big_endian);
        if (!values[i])
            goto fail;
    }
    SymExpr *new_stack_pointer = sym_expr_add(old_stack_pointer, sym_expr_const(32, 32));
    old_stack_pointer = NULL;
    if (!new_stack_pointer)
        goto fail;
    for (uint32_t i = 0; i < 7; i++) {
        dse_set_reg(ctx, destination_rids[i], values[i], 32);
        values[i] = NULL;
    }
    dse_set_reg(ctx, REG_RSP, new_stack_pointer, 32);
    return true;
fail:
    sym_expr_free(old_stack_pointer);
    for (uint32_t i = 0; i < 7; i++) {
        sym_expr_free(values[i]);
    }
    return false;
}

//lifter xchg
static bool lift_xchg(DSECtx *ctx, const cs_insn *insn, const cs_x86 *x86, const InsnAux *aux,
                      const DseArch *arch) {
    (void)insn;
    if (x86->op_count != 2)
        return false;
    const cs_x86_op *left = &x86->operands[0];
    const cs_x86_op *right = &x86->operands[1];
    if ((left->type != X86_OP_REG && left->type != X86_OP_MEM) ||
        (right->type != X86_OP_REG && right->type != X86_OP_MEM) ||
        (left->type == X86_OP_MEM && right->type == X86_OP_MEM)) {
        return false;
    }
    uint32_t left_width = (uint32_t)left->size * 8U;
    uint32_t right_width = (uint32_t)right->size * 8U;
    if (left_width == 0 || left_width != right_width) {
        return false;
    }
    SymExpr *left_value = get_operand_expr(ctx, x86, left, left_width, aux, arch);
    SymExpr *right_value = get_operand_expr(ctx, x86, right, right_width, aux, arch);
    if (!left_value || !right_value) {
        sym_expr_free(left_value);
        sym_expr_free(right_value);
        return false;
    }

    const cs_x86_op *memory_operand =
        left->type == X86_OP_MEM ? left : (right->type == X86_OP_MEM ? right : NULL);
    if (memory_operand &&
        !x86_constrain_mem_operand(ctx, x86, memory_operand, aux, arch, DSE_ADDRESS_WRITE)) {
        sym_expr_free(left_value);
        sym_expr_free(right_value);
        return false;
    }
    if (left->type == X86_OP_MEM) {
        if (!dse_store_mem(ctx, aux, right_value, arch->big_endian)) {
            sym_expr_free(left_value);
            return false;
        }
        return commit_reg(ctx, aux, arch, right->reg, left_value, right_width);
    }
    if (right->type == X86_OP_MEM) {
        if (!dse_store_mem(ctx, aux, left_value, arch->big_endian)) {
            sym_expr_free(right_value);
            return false;
        }
        return commit_reg(ctx, aux, arch, left->reg, right_value, left_width);
    }
    if (!commit_reg(ctx, aux, arch, left->reg, right_value, left_width)) {
        sym_expr_free(left_value);
        return false;
    }
    return commit_reg(ctx, aux, arch, right->reg, left_value, right_width);
}

static bool x86_constrain_string_base(DSECtx *ctx, const InsnAux *aux, const DseArch *arch,
                                      RegId register_id, uint64_t observed_address,
                                      DseAddressAccess access) {
    if (!ctx || !aux || !arch) {
        return false;
    }
    SymExpr *address =
        dse_read_rid_observed_root(ctx, aux, register_id, arch->natural_width, arch->natural_width);
    if (!address)
        return false;
    return dse_constrain_observed_address(ctx, address, observed_address, access);
}

static bool x86_constrain_string_count(DSECtx *ctx, const InsnAux *aux, const DseArch *arch,
                                       const DseStringSummary *summary) {
    if (!ctx || !aux || !arch || !summary) {
        return false;
    }
    if (!summary->has_rep_prefix)
        return summary->expected_iterations == 1U;
    SymExpr *count =
        dse_read_rid_observed_root(ctx, aux, REG_RCX, arch->natural_width, arch->natural_width);
    if (!count)
        return false;
    SymExpr *expected = sym_expr_const(summary->expected_iterations, arch->natural_width);
    if (!expected) {
        sym_expr_free(count);
        return false;
    }
    SymExpr *condition = sym_expr_eq(count, expected);
    if (!condition)
        return false;
    return dse_path_assert(ctx, condition, true);
}

static bool x86_update_string_index(DSECtx *ctx, const InsnAux *aux, const DseArch *arch,
                                    RegId register_id, uint32_t byte_count, int8_t direction) {
    if (!ctx || !aux || !arch || (direction != 1 && direction != -1)) {
        return false;
    }
    SymExpr *old_index =
        dse_read_rid_observed_root(ctx, aux, register_id, arch->natural_width, arch->natural_width);
    if (!old_index)
        return false;
    SymExpr *delta = sym_expr_const(byte_count, arch->natural_width);
    if (!delta) {
        sym_expr_free(old_index);
        return false;
    }
    SymExpr *new_index =
        direction > 0 ? sym_expr_add(old_index, delta) : sym_expr_sub(old_index, delta);
    if (!new_index)
        return false;
    dse_set_reg(ctx, register_id, new_index, arch->natural_width);
    return !ctx->resource_limit_hit;
}

static bool lift_lods(DSECtx *ctx, const cs_insn *insn, const cs_x86 *x86, const InsnAux *aux,
                      const DseArch *arch) {
    if (!ctx || !insn || !x86 || !aux || !arch || arch->natural_width != 32 || arch->big_endian ||
        x86_has_address_size_override(x86) || x86_has_segment_override(x86) ||
        !aux->execution_complete || !aux->has_mem_read || aux->mem_read_overflow ||
        aux->mem_read_count != 1 || aux->mem_read_total != 1 || !aux->eflags_valid) {
        return false;
    }
    for (unsigned prefix_index = 0; prefix_index < (sizeof(x86->prefix) / sizeof(x86->prefix[0]));
         prefix_index++) {
        if (x86->prefix[prefix_index] == 0xf2 || x86->prefix[prefix_index] == 0xf3) {
            return false;
        }
    }
    uint8_t element_size = x86_string_element_size(insn->id);
    if (element_size == 0 || element_size > 4 || aux->mem_reads[0].size != element_size) {
        return false;
    }
    SymExpr *source_address =
        dse_read_rid_observed_root(ctx, aux, REG_RSI, arch->natural_width, arch->natural_width);
    if (!source_address)
        return false;
    if (!dse_constrain_observed_address(ctx, source_address, aux->mem_reads[0].addr,
                                        DSE_ADDRESS_READ)) {
        return false;
    }
    SymExpr *loaded_value = dse_load_mem(ctx, aux, (uint32_t)element_size * 8U, false);
    if (!loaded_value)
        return false;
    if (!dse_commit_slice(ctx, aux, REG_RAX, loaded_value, 0, (uint32_t)element_size * 8U,
                          arch->natural_width)) {
        return false;
    }
    int8_t direction = (aux->eflags_before & (UINT32_C(1) << 10)) != 0 ? -1 : 1;
    return x86_update_string_index(ctx, aux, arch, REG_RSI, element_size, direction);
}

static bool lift_exact_string(DSECtx *ctx, const cs_insn *insn, const cs_x86 *x86,
                              const InsnAux *aux, const DseArch *arch) {
    if (!ctx || !insn || !x86 || !aux || !arch || arch->natural_width != 32 || arch->big_endian ||
        x86_has_address_size_override(x86) || x86_has_segment_override(x86)) {
        return false;
    }
    const DseStringSummary *summary = &aux->string_summary;
    uint8_t instruction_element_size = x86_string_element_size(insn->id);
    if (instruction_element_size == 0 || instruction_element_size != summary->element_size ||
        summary->element_size > (arch->natural_width / 8U) ||
        (summary->direction != 1 && summary->direction != -1)) {
        return false;
    }
    bool is_movs = insn->id == X86_INS_MOVSB || insn->id == X86_INS_MOVSW ||
                   insn->id == X86_INS_MOVSD || insn->id == X86_INS_MOVSQ;
    if (is_movs) {
        if (!dse_aux_has_exact_movs(aux))
            return false;
    } else {
        if (!dse_aux_has_exact_stos(aux))
            return false;
    }
    if (!x86_constrain_string_count(ctx, aux, arch, summary)) {
        return false;
    }
    if (summary->expected_iterations != 0) {
        if (is_movs && !x86_constrain_string_base(ctx, aux, arch, REG_RSI, summary->source_first,
                                                  DSE_ADDRESS_READ)) {
            return false;
        }
        if (!x86_constrain_string_base(ctx, aux, arch, REG_RDI, summary->destination_first,
                                       DSE_ADDRESS_WRITE)) {
            return false;
        }
    }
    SymExpr *pattern[8] = {0};

    for (uint32_t event = 0; event < summary->expected_iterations; event++) {
        uint8_t required_mask = 0;
        for (uint8_t byte = 0; byte < summary->element_size; byte++) {
            uint64_t destination = x86_string_event_byte_address(
                summary->destination_first, summary->direction, summary->element_size, event, byte);
            if (dse_memory_write_byte_required(ctx, destination)) {
                required_mask |= (uint8_t)(UINT8_C(1) << byte);
            }
        }
        if (required_mask == 0)
            continue;
        if (is_movs) {
            SymExpr *element[8] = {0};
            for (uint8_t byte = 0; byte < summary->element_size; byte++) {
                if ((required_mask & (uint8_t)(UINT8_C(1) << byte)) == 0) {
                    continue;
                }
                uint64_t captured_index = (uint64_t)event * summary->element_size + byte;
                if (!summary->values || !summary->value_taint ||
                    captured_index >= summary->bytes_captured) {
                    for (uint8_t cleanup = 0; cleanup < summary->element_size; cleanup++) {
                        sym_expr_free(element[cleanup]);
                    }
                    goto fail;
                }
                uint64_t source = x86_string_event_byte_address(
                    summary->source_first, summary->direction, summary->element_size, event, byte);
                uint8_t observed_value = summary->values[captured_index];
                if (!dse_load_tracked_byte_at(ctx, source, aux->seq_id, observed_value,
                                              summary->value_taint[captured_index] != 0,
                                              &element[byte])) {
                    for (uint8_t cleanup = 0; cleanup < summary->element_size; cleanup++) {
                        sym_expr_free(element[cleanup]);
                    }
                    goto fail;
                }
            }
            for (uint8_t byte = 0; byte < summary->element_size; byte++) {
                if ((required_mask & (uint8_t)(UINT8_C(1) << byte)) == 0) {
                    continue;
                }
                uint64_t destination =
                    x86_string_event_byte_address(summary->destination_first, summary->direction,
                                                  summary->element_size, event, byte);
                uint64_t captured_index = (uint64_t)event * summary->element_size + byte;
                SymExpr *value = element[byte];
                element[byte] = NULL;
                if (!dse_store_tracked_byte_at(ctx, destination, value, aux,
                                               summary->values[captured_index])) {
                    for (uint8_t cleanup = 0; cleanup < summary->element_size; cleanup++) {
                        sym_expr_free(element[cleanup]);
                    }
                    goto fail;
                }
            }
        } else {
            for (uint8_t byte = 0; byte < summary->element_size; byte++) {
                if ((required_mask & (uint8_t)(UINT8_C(1) << byte)) == 0) {
                    continue;
                }
                if (!pattern[byte]) {
                    pattern[byte] = dse_read_rid_slice(ctx, aux, REG_RAX, (uint32_t)byte * 8U, 8,
                                                       arch->natural_width);
                    if (!pattern[byte])
                        goto fail;
                }
                SymExpr *value = sym_expr_clone(pattern[byte]);
                if (!value)
                    goto fail;
                uint8_t observed_value =
                    (uint8_t)((aux->reg_vals[REG_RAX] >> (8U * byte)) & UINT64_C(0xff));
                uint64_t destination =
                    x86_string_event_byte_address(summary->destination_first, summary->direction,
                                                  summary->element_size, event, byte);
                if (!dse_store_tracked_byte_at(ctx, destination, value, aux, observed_value)) {
                    goto fail;
                }
            }
        }
    }
    for (uint8_t byte = 0; byte < 8; byte++) {
        sym_expr_free(pattern[byte]);
        pattern[byte] = NULL;
    }
    uint64_t total_bytes_64 = (uint64_t)summary->expected_iterations * summary->element_size;
    if (total_bytes_64 > UINT32_MAX)
        return false;
    uint32_t total_bytes = (uint32_t)total_bytes_64;

    if (is_movs &&
        !x86_update_string_index(ctx, aux, arch, REG_RSI, total_bytes, summary->direction)) {
        return false;
    }
    if (!x86_update_string_index(ctx, aux, arch, REG_RDI, total_bytes, summary->direction)) {
        return false;
    }
    if (summary->has_rep_prefix) {
        dse_set_reg(ctx, REG_RCX, sym_expr_const(0, arch->natural_width), arch->natural_width);
        if (ctx->resource_limit_hit) {
            return false;
        }
    }
    if (ctx->string_summaries != UINT32_MAX) {
        ctx->string_summaries++;
    }
    return true;
fail:
    for (uint8_t byte = 0; byte < 8; byte++) {
        sym_expr_free(pattern[byte]);
    }
    return false;
}

static bool lift_conditional_branch(DSECtx *ctx, const cs_insn *insn, const cs_x86 *x86,
                                    const InsnAux *aux) {
    if (!ctx || !insn || !x86 || !aux || x86->op_count != 1 ||
        x86->operands[0].type != X86_OP_IMM || !aux->next_pc_valid) {
        if (ctx) {
            ctx->path_model_complete = false;
            if (ctx->path_failures != UINT32_MAX) {
                ctx->path_failures++;
            }
        }
        return true;
    }
    X86ConditionCode code = x86_condition_code_from_id(insn->id);
    if (code == X86_CC_NONE) {
        ctx->path_model_complete = false;
        if (ctx->path_failures != UINT32_MAX) {
            ctx->path_failures++;
        }
        return true;
    }
    SymExpr *condition = x86_condition_expr(ctx, aux, code);
    if (!condition) {
        ctx->path_model_complete = false;
        return true;
    }
    uint32_t fallthrough = (uint32_t)(insn->address + insn->size);
    uint32_t target = (uint32_t)x86->operands[0].imm;
    uint32_t next_pc = (uint32_t)aux->next_pc;
    if (target == fallthrough) {
        sym_expr_free(condition);
        ctx->path_model_complete = false;
        if (ctx->path_failures != UINT32_MAX) {
            ctx->path_failures++;
        }
        return true;
    }

    bool taken;
    if (next_pc == target) {
        taken = true;
    } else if (next_pc == fallthrough) {
        taken = false;
    } else {
        sym_expr_free(condition);
        ctx->path_model_complete = false;
        if (ctx->path_failures != UINT32_MAX) {
            ctx->path_failures++;
        }
        return true;
    }
    (void)dse_path_assert(ctx, condition, taken);
    return true;
}

//lifter jmp
static bool lift_jmp(DSECtx *ctx, const cs_insn *insn, const cs_x86 *x86, const InsnAux *aux,
                     const DseArch *arch) {
    (void)insn;
    if (x86->op_count != 1)
        return false;
    const cs_x86_op *target = &x86->operands[0];
    if (target->type == X86_OP_MEM) {
        return x86_constrain_mem_operand(ctx, x86, target, aux, arch, DSE_ADDRESS_READ);
    }

    return target->type == X86_OP_IMM || target->type == X86_OP_REG;
}

//lifter call
static bool lift_call(DSECtx *ctx, const cs_insn *insn, const cs_x86 *x86, const InsnAux *aux,
                      const DseArch *arch) {
    if (x86->op_count != 1 || !aux || !aux->has_mem_write || arch->natural_width != 32) {
        return false;
    }

    const cs_x86_op *target = &x86->operands[0];
    if (target->type != X86_OP_IMM && target->type != X86_OP_REG && target->type != X86_OP_MEM) {
        return false;
    }
    if (target->type == X86_OP_MEM &&
        !x86_constrain_mem_operand(ctx, x86, target, aux, arch, DSE_ADDRESS_READ)) {
        return false;
    }

    bool operand_size_16 = false;
    for (unsigned i = 0; i < (sizeof(x86->prefix) / sizeof(x86->prefix[0])); i++) {
        if (x86->prefix[i] == 0x66) {
            operand_size_16 = true;
            break;
        }
    }
    uint32_t pointer_width = arch->natural_width;
    uint32_t pushed_width = operand_size_16 ? 16u : 32u;
    uint32_t pushed_bytes = pushed_width / 8u;
    SymExpr *old_stack_pointer =
        dse_read_rid_observed_root(ctx, aux, REG_RSP, pointer_width, pointer_width);
    if (!old_stack_pointer)
        return false;
    SymExpr *new_stack_pointer =
        sym_expr_sub(old_stack_pointer, sym_expr_const(pushed_bytes, pointer_width));
    if (!new_stack_pointer)
        return false;
    SymExpr *return_address = sym_expr_const(insn->address + insn->size, pushed_width);
    if (!return_address) {
        sym_expr_free(new_stack_pointer);
        return false;
    }
    if (!dse_constrain_observed_address(ctx, sym_expr_clone(new_stack_pointer), aux->mem_write_addr,
                                        DSE_ADDRESS_WRITE)) {
        sym_expr_free(return_address);
        sym_expr_free(new_stack_pointer);
        return false;
    }
    if (!dse_store_mem(ctx, aux, return_address, arch->big_endian)) {
        sym_expr_free(new_stack_pointer);
        return false;
    }
    dse_set_reg(ctx, REG_RSP, new_stack_pointer, pointer_width);
    return true;
}

//lifter ret
static bool lift_ret(DSECtx *ctx, const cs_insn *insn, const cs_x86 *x86, const InsnAux *aux,
                     const DseArch *arch) {
    (void)insn;
    if (!ctx || !x86 || !aux || !arch || !aux->has_mem_read || x86->op_count > 1 ||
        arch->natural_width != 32) {
        return false;
    }
    for (unsigned i = 0; i < (sizeof(x86->prefix) / sizeof(x86->prefix[0])); i++) {
        if (x86->prefix[i] == 0x66 || x86->prefix[i] == 0x67) {
            return false;
        }
    }
    uint32_t immediate_adjustment = 0;
    if (x86->op_count == 1) {
        if (x86->operands[0].type != X86_OP_IMM) {
            return false;
        }
        immediate_adjustment = (uint16_t)x86->operands[0].imm;
    }
    SymExpr *old_stack_pointer = dse_read_rid_observed_root(ctx, aux, REG_RSP, 32, 32);
    if (!old_stack_pointer)
        return false;
    if (!dse_constrain_observed_address(ctx, sym_expr_clone(old_stack_pointer), aux->mem_read_addr,
                                        DSE_ADDRESS_READ)) {
        sym_expr_free(old_stack_pointer);
        return false;
    }
    SymExpr *new_stack_pointer =
        sym_expr_add(old_stack_pointer, sym_expr_const(4U + immediate_adjustment, 32));

    if (!new_stack_pointer)
        return false;
    dse_set_reg(ctx, REG_RSP, new_stack_pointer, 32);
    return true;
}

//convert word group
static bool lift_cbw(DSECtx *ctx, const InsnAux *aux, const DseArch *arch) {
    int accumulator_rid = x86_reg_to_rid(X86_REG_EAX);
    if (accumulator_rid < 0)
        return false;

    SymExpr *al = dse_read_rid_slice(ctx, aux, accumulator_rid, 0, 8, arch->natural_width);
    if (!al)
        return false;
    SymExpr *ax = sym_expr_sext(al, 16);
    if (!ax)
        return false;

    return commit_reg(ctx, aux, arch, X86_REG_AX, ax, 16);
}

static bool lift_cwd(DSECtx *ctx, const InsnAux *aux, const DseArch *arch) {
    int accumulator_rid = x86_reg_to_rid(X86_REG_EAX);
    if (accumulator_rid < 0)
        return false;
    SymExpr *ax = dse_read_rid_slice(ctx, aux, accumulator_rid, 0, 16, arch->natural_width);
    if (!ax)
        return false;
    SymExpr *dx = sym_expr_sar(ax, sym_expr_const(15, 16));
    if (!dx)
        return false;

    return commit_reg(ctx, aux, arch, X86_REG_DX, dx, 16);
}

static bool lift_cwde(DSECtx *ctx, const InsnAux *aux, const DseArch *arch) {
    int accumulator_rid = x86_reg_to_rid(X86_REG_EAX);
    if (accumulator_rid < 0)
        return false;
    SymExpr *ax = dse_read_rid_slice(ctx, aux, accumulator_rid, 0, 16, arch->natural_width);
    if (!ax)
        return false;
    SymExpr *eax = sym_expr_sext(ax, 32);
    if (!eax)
        return false;

    return commit_reg(ctx, aux, arch, X86_REG_EAX, eax, 32);
}

static bool lift_cdq(DSECtx *ctx, const InsnAux *aux, const DseArch *arch) {
    int accumulator_rid = x86_reg_to_rid(X86_REG_EAX);
    if (accumulator_rid < 0)
        return false;
    SymExpr *eax = dse_read_rid_slice(ctx, aux, accumulator_rid, 0, 32, arch->natural_width);
    if (!eax)
        return false;
    SymExpr *edx = sym_expr_sar(eax, sym_expr_const(31, 32));
    if (!edx)
        return false;

    return commit_reg(ctx, aux, arch, X86_REG_EDX, edx, 32);
}

//all in one
static bool x86_lift_one(DSECtx *ctx, const cs_insn *insn, const InsnAux *aux,
                         const DseArch *arch) {
    const cs_x86 *x86 = &insn->detail->x86;
    switch (insn->id) {
    case X86_INS_MOV:
    case X86_INS_MOVZX:
    case X86_INS_MOVSX:
        return lift_mov(ctx, insn, x86, aux, arch);
    case X86_INS_LEA:
        return lift_lea(ctx, insn, x86, aux, arch);
    case X86_INS_ADD:
    case X86_INS_SUB:
    case X86_INS_XOR:
    case X86_INS_AND:
    case X86_INS_OR:
    case X86_INS_SHL:
    case X86_INS_SAL:
    case X86_INS_SHR:
    case X86_INS_SAR:
    case X86_INS_ROL:
    case X86_INS_ROR:
        return lift_arith(ctx, insn, x86, aux, arch);
    case X86_INS_NOT:
    case X86_INS_NEG:
    case X86_INS_INC:
    case X86_INS_DEC:
        return lift_unary(ctx, insn, x86, aux, arch);
    case X86_INS_IMUL:
        return lift_imul(ctx, insn, x86, aux, arch);
    case X86_INS_CMP:
    case X86_INS_TEST:
        return lift_compare(ctx, insn, x86, aux, arch);
    case X86_INS_PUSH:
        return lift_push(ctx, insn, x86, aux, arch);
    case X86_INS_PUSHF:
    case X86_INS_PUSHFD:
    case X86_INS_PUSHFQ:
        return lift_pushf(ctx, insn, aux, arch);
    case X86_INS_POP:
        return lift_pop(ctx, insn, x86, aux, arch);
    case X86_INS_LEAVE:
        return lift_leave(ctx, insn, x86, aux, arch);
    case X86_INS_POPAL:
        return lift_popal(ctx, insn, x86, aux, arch);
    case X86_INS_XCHG:
        return lift_xchg(ctx, insn, x86, aux, arch);
    case X86_INS_MOVSB:
    case X86_INS_MOVSW:
    case X86_INS_MOVSD:
    case X86_INS_MOVSQ:
    case X86_INS_STOSB:
    case X86_INS_STOSW:
    case X86_INS_STOSD:
    case X86_INS_STOSQ:
        return lift_exact_string(ctx, insn, x86, aux, arch);
    case X86_INS_LODSB:
    case X86_INS_LODSW:
    case X86_INS_LODSD:
    case X86_INS_LODSQ:
        return lift_lods(ctx, insn, x86, aux, arch);
    case X86_INS_NOP:
        return true;
    case X86_INS_JMP:
        return lift_jmp(ctx, insn, x86, aux, arch);
    case X86_INS_JO:
    case X86_INS_JNO:
    case X86_INS_JB:
    case X86_INS_JAE:
    case X86_INS_JE:
    case X86_INS_JNE:
    case X86_INS_JBE:
    case X86_INS_JA:
    case X86_INS_JS:
    case X86_INS_JNS:
    case X86_INS_JP:
    case X86_INS_JNP:
    case X86_INS_JL:
    case X86_INS_JGE:
    case X86_INS_JLE:
    case X86_INS_JG:
        return lift_conditional_branch(ctx, insn, x86, aux);
    case X86_INS_CALL:
        return lift_call(ctx, insn, x86, aux, arch);
    case X86_INS_RET:
        return lift_ret(ctx, insn, x86, aux, arch);
    case X86_INS_CBW:
        return lift_cbw(ctx, aux, arch);
    case X86_INS_CWDE:
        return lift_cwde(ctx, aux, arch);
    case X86_INS_CWD:
        return lift_cwd(ctx, aux, arch);
    case X86_INS_CDQ:
        return lift_cdq(ctx, aux, arch);
    default:
        return false; //unhandled case
    }
}

const DseArch dse_arch_x86 = {
    .name = "i386",
    .natural_width = 32,
    .big_endian = false,
    .reg_to_rid = x86_reg_to_rid,
    .lift_one = x86_lift_one,
};
