#include "trace_deps_x86.h"

#include <string.h>

static void promote_writes(TraceDeps *out) {
    memcpy(out->must_write, out->may_write, sizeof(out->must_write));
    out->special_must_write = out->special_may_write;
}

static void no_state_change(TraceDeps *out) {
    memset(out->may_write, 0, sizeof(out->may_write));
    memset(out->must_write, 0, sizeof(out->must_write));
    memset(out->value_uses, 0, sizeof(out->value_uses));
    memset(out->explicit_value_uses, 0, sizeof(out->explicit_value_uses));
    out->special_may_write = out->special_must_write = 0;
    out->special_value_uses = out->special_address_uses = 0;
    /* Recorded accesses remain available, including a zero-count memory RMW. */
}

static bool simple_shift(uint16_t id) {
    return id == X86_INS_SHL || id == X86_INS_SAL || id == X86_INS_SHR || id == X86_INS_SAR;
}

static void resolve_shift(const InsnMeta *meta, const InsnAux *aux, TraceDeps *out) {
    if (!simple_shift(meta->insn_id))
        return; /* conservative may-dependence only */
    /* Preservation is represented by may/must, not a read of every old flag. */
    out->special_value_uses = 0;
    if (!meta->shift_count_valid ||
        (meta->shift_operand_width != 8 && meta->shift_operand_width != 16 &&
         meta->shift_operand_width != 32)) {
        out->incomplete_reasons |= TRACE_DEPS_STATE_MISSING;
        return;
    }
    uint8_t count = meta->shift_count_imm;
    bool fixed = meta->shift_count_is_immediate;
    if (!fixed) {
        RegSlice slice = meta->shift_count_reg;
        if (!reg_slice_is_valid(slice) || slice.width != 1 ||
            !(aux->reg_value_valid_mask & (1U << slice.reg_id))) {
            out->incomplete_reasons |= TRACE_DEPS_STATE_MISSING;
            return;
        }
        count = (uint8_t)(aux->reg_vals[slice.reg_id] >> (slice.byte_offset * 8U));
        fixed = (aux->reg_taint[slice.reg_id] & slice.mask) == 0;
        uint64_t bits = UINT64_C(0xff) << (slice.byte_offset * 8U);
        out->value_uses[slice.reg_id] |= bits;
        out->explicit_value_uses[slice.reg_id] |= bits;
    }
    count &= 31U;
    if (fixed && count == 0) {
        no_state_change(out);
        return;
    }
    if (fixed)
        promote_writes(out);
    out->special_unknown_write |= trace_special_state_bit(X86_SPECIAL_STATE_AF);
    if (!fixed || count != 1)
        out->special_unknown_write |= trace_special_state_bit(X86_SPECIAL_STATE_OF);
    if (meta->insn_id != X86_INS_SAR && ((!fixed && meta->shift_operand_width < 32) ||
                                         (fixed && count >= meta->shift_operand_width)))
        out->special_unknown_write |= trace_special_state_bit(X86_SPECIAL_STATE_CF);
}

bool trace_deps_x86_build(const TraceEntry *entry, const InsnDesc *desc, const InsnMeta *meta,
                          const InsnAux *aux, const InsnOccurrence *occurrence,
                          uint8_t register_width, TraceDeps *out) {
    if (!out)
        return false;
    InsnDesc legacy = {0};
    if (entry && !entry->insn_desc_id && meta) {
        legacy.desc_id = entry->insn_desc_id;
        legacy.meta_id = entry->meta_id;
        legacy.pc = entry->pc;
        legacy.code_generation = entry->code_generation;
        legacy.bytes_hash = entry->bytes_hash;
        legacy.arch = TRACE_ARCH_X86;
        legacy.mode = TRACE_MODE_32;
        legacy.size = entry->size;
        memcpy(legacy.bytes, entry->instr_bytes, sizeof(legacy.bytes));
        legacy.native_insn_id = meta->insn_id;
        (void)trace_effect_summary_from_meta(meta, &legacy.effects);
        desc = &legacy;
    }
    bool complete = trace_deps_build(desc, occurrence, register_width, out);
    if (!entry || !meta || !desc || entry->size == 0 || entry->size > MAX_INSN_BYTES ||
        meta->size != entry->size || meta->pc != entry->pc || meta->meta_id != entry->meta_id ||
        memcmp(meta->instr_bytes, entry->instr_bytes, entry->size) != 0 ||
        desc->desc_id != entry->insn_desc_id || desc->size != entry->size ||
        desc->native_insn_id != meta->insn_id ||
        memcmp(desc->bytes, entry->instr_bytes, entry->size) != 0 ||
        (entry->insn_desc_id &&
         entry->bytes_hash != trace_instruction_bytes_hash(entry->instr_bytes, entry->size)) ||
        !occurrence || occurrence->seq_id != entry->seq_id ||
        occurrence->vcpu_index != entry->vcpu_index || occurrence->desc_id != entry->insn_desc_id ||
        occurrence->meta_id != entry->meta_id || occurrence->pc != entry->pc ||
        occurrence->code_generation != entry->code_generation ||
        occurrence->bytes_hash != entry->bytes_hash) {
        (void)trace_deps_build(NULL, occurrence, register_width, out);
        out->incomplete_reasons |= TRACE_DEPS_IDENTITY_MISMATCH;
        return false;
    }
    if (register_width != 32 || desc->arch != TRACE_ARCH_X86 || desc->mode != TRACE_MODE_32) {
        out->incomplete_reasons |= TRACE_DEPS_UNSUPPORTED_WIDTH;
        return false;
    }
    if (aux &&
        (!aux->valid || aux->seq_id != entry->seq_id || aux->meta_id != entry->meta_id ||
         aux->pc != entry->pc || aux->execution_complete != occurrence->execution_complete)) {
        (void)trace_deps_build(NULL, occurrence, register_width, out);
        out->incomplete_reasons |= TRACE_DEPS_IDENTITY_MISMATCH;
        return false;
    }
    if (!aux) {
        out->incomplete_reasons |= TRACE_DEPS_STATE_MISSING;
        return false;
    }
    if (aux->string_summary.active &&
        (meta->family != DTA_FAMILY_STRING ||
         aux->string_summary.element_size != meta->string_element_size ||
         aux->string_summary.has_rep_prefix != meta->has_rep_prefix ||
         (meta->has_rep_prefix &&
          (!(aux->reg_value_valid_mask & (1U << REG_RCX)) ||
           aux->string_summary.expected_iterations != (uint32_t)aux->reg_vals[REG_RCX])))) {
        (void)trace_deps_build(NULL, occurrence, register_width, out);
        out->incomplete_reasons |= TRACE_DEPS_IDENTITY_MISMATCH;
        return false;
    }
    /* Old single-access fields cannot prove an empty access list. */
    if ((aux->has_mem_read && !aux->mem_read_count && !aux->mem_read_total) ||
        (aux->has_mem_write && !aux->mem_write_count && !aux->mem_write_total) ||
        aux->mem_read_count > TRACE_MAX_MEM_EFFECTS || aux->mem_write_count > TRACE_MAX_MEM_EFFECTS)
        out->occurrence.incomplete_reasons |= TRACE_OCCURRENCE_RANGE_UNKNOWN;
    if (!complete)
        return false;

    if (meta->insn_id == X86_INS_LEA) {
        for (unsigned reg = 0; reg < REG_COUNT; reg++) {
            out->value_uses[reg] |= out->address_uses[reg];
            out->explicit_value_uses[reg] |= out->address_uses[reg];
        }
    }

    switch (meta->family) {
    case DTA_FAMILY_DATA_MOVEMENT:
    case DTA_FAMILY_LOGICAL:
    case DTA_FAMILY_ARITHMETIC:
    case DTA_FAMILY_COMPARE:
    case DTA_FAMILY_STACK:
        promote_writes(out);
        break;
    case DTA_FAMILY_SHIFT_ROTATE:
        resolve_shift(meta, aux, out);
        break;
    case DTA_FAMILY_STRING:
        /* MOVS/STOS/LODS read DF, not the arithmetic flags in EFLAGS. */
        out->special_value_uses = 0;
        if (!meta->has_rep_prefix) {
            promote_writes(out);
        } else if ((dse_aux_has_exact_movs(aux) || dse_aux_has_exact_stos(aux)) &&
                   !(aux->reg_taint[REG_RCX] & 0xfU)) {
            if (aux->string_summary.expected_iterations)
                promote_writes(out);
            else
                no_state_change(out);
        }
        break;
    default:
        break;
    }
    if (meta->insn_id == X86_INS_CLD || meta->insn_id == X86_INS_STD) {
        /* Capstone reports the EFLAGS container. Only DF changes here. */
        out->special_may_write = trace_special_state_bit(X86_SPECIAL_STATE_DF);
        out->special_must_write = out->special_may_write;
        out->special_value_uses = 0;
    }
    if (meta->insn_id == X86_INS_AND || meta->insn_id == X86_INS_OR ||
        meta->insn_id == X86_INS_XOR || meta->insn_id == X86_INS_TEST)
        out->special_unknown_write |= trace_special_state_bit(X86_SPECIAL_STATE_AF);
    if (meta->is_self_zeroing) {
        memset(out->value_uses, 0, sizeof(out->value_uses));
        memset(out->explicit_value_uses, 0, sizeof(out->explicit_value_uses));
        out->special_value_uses = 0;
    }
    return out->incomplete_reasons == 0;
}

uint8_t trace_deps_x86_legacy_flags(uint64_t special) {
    static const TraceSpecialStateId ids[] = {X86_SPECIAL_STATE_CF, X86_SPECIAL_STATE_PF,
                                              X86_SPECIAL_STATE_AF, X86_SPECIAL_STATE_ZF,
                                              X86_SPECIAL_STATE_SF, X86_SPECIAL_STATE_OF};
    static const uint8_t masks[] = {X86_FLAG_CF, X86_FLAG_PF, X86_FLAG_AF,
                                    X86_FLAG_ZF, X86_FLAG_SF, X86_FLAG_OF};
    uint8_t result = 0;
    for (unsigned i = 0; i < sizeof(ids) / sizeof(ids[0]); i++)
        if (special & trace_special_state_bit(ids[i]))
            result |= masks[i];
    return result;
}

uint64_t trace_deps_x86_forced_value_regs(const InsnMeta *meta, const uint8_t needed[REG_COUNT],
                                          uint8_t natural_mask) {
    if (!meta || !needed || !natural_mask)
        return 0;
    uint64_t forced = 0;
    switch (meta->insn_id) {
    case X86_INS_LEA:
        forced = meta->mem_addr_reg_mask;
        break;
    case X86_INS_PUSH:
    case X86_INS_POP:
    case X86_INS_PUSHF:
    case X86_INS_PUSHFD:
    case X86_INS_PUSHFQ:
    case X86_INS_CALL:
    case X86_INS_RET:
        if (needed[REG_RSP] & natural_mask)
            forced |= UINT64_C(1) << REG_RSP;
        break;
    case X86_INS_LEAVE:
        if (needed[REG_RSP] & natural_mask)
            forced |= UINT64_C(1) << REG_RBP;
        break;
    case X86_INS_MOVSB:
    case X86_INS_MOVSW:
    case X86_INS_MOVSD:
    case X86_INS_MOVSQ:
        if (needed[REG_RSI] & natural_mask)
            forced |= UINT64_C(1) << REG_RSI;
        if (needed[REG_RDI] & natural_mask)
            forced |= UINT64_C(1) << REG_RDI;
        break;
    case X86_INS_STOSB:
    case X86_INS_STOSW:
    case X86_INS_STOSD:
    case X86_INS_STOSQ:
        if (needed[REG_RDI] & natural_mask)
            forced |= UINT64_C(1) << REG_RDI;
        break;
    default:
        break;
    }
    return forced;
}
