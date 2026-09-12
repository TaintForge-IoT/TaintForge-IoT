#include "trace_deps.h"

#include <string.h>

uint64_t trace_deps_width_mask(uint8_t width) {
    if (width == 0 || width > 64)
        return 0;
    return width == 64 ? UINT64_MAX : (UINT64_C(1) << width) - 1U;
}

uint8_t trace_deps_bytes(uint64_t bits, bool require_whole_byte) {
    uint8_t result = 0;
    for (uint8_t index = 0; index < 8; index++) {
        uint8_t part = (uint8_t)(bits >> (index * 8U));
        if (require_whole_byte ? part == UINT8_MAX : part != 0)
            result |= (uint8_t)(1U << index);
    }
    return result;
}

static bool trace_deps_slice_bits(TraceRegSlice slice, uint8_t width, uint64_t *bits) {
    if (slice.reg_id >= TRACE_DEPS_REG_CAPACITY || !slice.bit_width || slice.bit_offset >= width ||
        slice.bit_width > width - slice.bit_offset)
        return false;
    *bits = trace_deps_width_mask((uint8_t)slice.bit_width) << slice.bit_offset;
    return true;
}

static void trace_deps_unknown_definitions(TraceDeps *out) {
    uint64_t full = trace_deps_width_mask(out->register_width);
    for (uint32_t reg = 0; reg < TRACE_DEPS_REG_CAPACITY; reg++) {
        out->may_write[reg] = full;
        out->must_write[reg] = 0;
    }
    out->special_may_write = UINT64_MAX;
    out->special_must_write = 0;
    out->may_read_memory = out->may_write_memory = true;
}

bool trace_deps_build(const InsnDesc *desc, const InsnOccurrence *occurrence,
                      uint8_t register_width, TraceDeps *out) {
    if (!out)
        return false;
    memset(out, 0, sizeof(*out));
    out->register_width = register_width;
    if (!trace_deps_width_mask(register_width)) {
        out->incomplete_reasons = TRACE_DEPS_UNSUPPORTED_WIDTH;
        return false;
    }
    if (occurrence)
        out->occurrence = *occurrence;
    if (!desc || (desc->effects.quality_flags & TRACE_EFFECT_META_MISSING)) {
        out->incomplete_reasons |= TRACE_DEPS_DESC_MISSING;
        trace_deps_unknown_definitions(out);
        return false;
    }
    const EffectSummary *effects = &desc->effects;
    out->special_value_uses = effects->special_value_uses;
    out->special_address_uses = effects->special_address_uses;
    out->special_control_uses = effects->special_control_uses;
    out->special_may_write = effects->special_defs;
    out->address_regs = effects->register_address_uses;
    out->read_address_regs = effects->register_memory_read_address_uses;
    out->write_address_regs = effects->register_memory_write_address_uses;
    out->branch_kind = effects->branch_kind;
    out->may_read_memory = effects->may_read_memory;
    out->may_write_memory = effects->may_write_memory;

    if ((effects->quality_flags & TRACE_EFFECT_SLICE_DETAIL_TRUNCATED) ||
        effects->value_use_slice_count > MAX_INSN_REG_SLICES ||
        effects->def_slice_count > MAX_INSN_REG_SLICES)
        out->incomplete_reasons |= TRACE_DEPS_DETAIL_TRUNCATED;
    for (uint32_t index = 0; index < effects->value_use_slice_count && index < MAX_INSN_REG_SLICES;
         index++) {
        TraceRegSlice slice = effects->value_use_slices[index];
        uint64_t bits = 0;
        if (!trace_deps_slice_bits(slice, register_width, &bits)) {
            out->incomplete_reasons |= TRACE_DEPS_INVALID_SLICE;
            continue;
        }
        out->value_uses[slice.reg_id] |= bits;
        out->explicit_value_uses[slice.reg_id] |= bits;
    }
    for (uint32_t index = 0; index < effects->def_slice_count && index < MAX_INSN_REG_SLICES;
         index++) {
        TraceRegSlice slice = effects->def_slices[index];
        uint64_t bits = 0;
        if (!trace_deps_slice_bits(slice, register_width, &bits)) {
            out->incomplete_reasons |= TRACE_DEPS_INVALID_SLICE;
            continue;
        }
        out->may_write[slice.reg_id] |= bits;
    }
    uint64_t full = trace_deps_width_mask(register_width);
    for (uint32_t reg = 0; reg < TRACE_DEPS_REG_CAPACITY; reg++) {
        uint64_t bit = UINT64_C(1) << reg;
        if ((effects->register_value_uses & bit) &&
            (!out->value_uses[reg] || out->incomplete_reasons))
            out->value_uses[reg] = full;
        if ((effects->register_defs & bit) && (!out->may_write[reg] || out->incomplete_reasons))
            out->may_write[reg] = full;
        if (effects->register_address_uses & bit)
            out->address_uses[reg] = full;
        if (effects->register_control_uses & bit)
            out->control_uses[reg] = full;
    }
    if (out->incomplete_reasons & TRACE_DEPS_INVALID_SLICE)
        trace_deps_unknown_definitions(out);
    if (!occurrence || !occurrence->dynamic_effects_available ||
        (occurrence->incomplete_reasons & TRACE_OCCURRENCE_AUX_MISSING))
        out->incomplete_reasons |= TRACE_DEPS_STATE_MISSING;
    if (occurrence && (!occurrence->execution_complete ||
                       (occurrence->incomplete_reasons & TRACE_OCCURRENCE_EXECUTION_PENDING)))
        out->incomplete_reasons |= TRACE_DEPS_EXECUTION_PENDING;
    if (occurrence &&
        (occurrence->desc_id != desc->desc_id || occurrence->meta_id != desc->meta_id ||
         occurrence->pc != desc->pc || occurrence->code_generation != desc->code_generation ||
         occurrence->bytes_hash != desc->bytes_hash)) {
        out->incomplete_reasons |= TRACE_DEPS_IDENTITY_MISMATCH;
        trace_deps_unknown_definitions(out);
    }
    return out->incomplete_reasons == 0;
}

static bool trace_deps_range_end(uint64_t address, uint64_t size, uint64_t *end) {
    if (!size || size - 1U > UINT64_MAX - address)
        return false;
    *end = address + size - 1U;
    return true;
}

TraceDepRelation trace_deps_memory_overlap(const TraceDeps *deps, TraceMemoryEffectKind kind,
                                           uint64_t address, uint64_t size) {
    uint64_t end = 0;
    if (!deps || !trace_deps_range_end(address, size, &end) ||
        (kind != TRACE_MEM_READ && kind != TRACE_MEM_WRITE))
        return TRACE_DEP_UNKNOWN;
    if (deps->incomplete_reasons &
        (TRACE_DEPS_DESC_MISSING | TRACE_DEPS_IDENTITY_MISMATCH | TRACE_DEPS_UNSUPPORTED_WIDTH))
        return TRACE_DEP_UNKNOWN;
    const InsnOccurrence *occ = &deps->occurrence;
    bool read = kind == TRACE_MEM_READ;
    uint32_t count = read ? occ->mem_read_count : occ->mem_write_count;
    uint32_t total = read ? occ->mem_read_total : occ->mem_write_total;
    const TraceMemoryEffect *accesses = read ? occ->mem_reads : occ->mem_writes;
    bool range_valid = read ? occ->mem_read_range_valid : occ->mem_write_range_valid;
    uint64_t first = read ? occ->mem_read_min_addr : occ->mem_write_min_addr;
    uint64_t last = read ? occ->mem_read_max_addr : occ->mem_write_max_addr;
    bool malformed = count > TRACE_MAX_MEM_EFFECTS || total < count;
    for (uint32_t index = 0; index < count && index < TRACE_MAX_MEM_EFFECTS; index++) {
        const TraceMemoryEffect *access = &accesses[index];
        uint64_t access_end = 0;
        if (access->kind != kind ||
            !trace_deps_range_end(access->address, access->size, &access_end)) {
            malformed = true;
            continue;
        }
        if (address <= access_end && access->address <= end)
            return TRACE_DEP_YES;
        if (range_valid && (access->address < first || access_end > last))
            malformed = true;
    }
    if (malformed)
        return TRACE_DEP_UNKNOWN;
    if (!occ->dynamic_effects_available) {
        bool may_access = read ? deps->may_read_memory : deps->may_write_memory;
        return may_access ? TRACE_DEP_UNKNOWN : TRACE_DEP_NO;
    }
    uint32_t overflow = read ? TRACE_OCCURRENCE_READ_OVERFLOW : TRACE_OCCURRENCE_WRITE_OVERFLOW;
    bool complete = occ->execution_complete && total == count &&
                    !(occ->incomplete_reasons &
                      (overflow | TRACE_OCCURRENCE_AUX_MISSING |
                       TRACE_OCCURRENCE_EXECUTION_PENDING | TRACE_OCCURRENCE_RANGE_UNKNOWN));
    if (complete)
        return TRACE_DEP_NO;
    if (occ->execution_complete && range_valid && first <= last &&
        !(occ->incomplete_reasons &
          (TRACE_OCCURRENCE_RANGE_UNKNOWN | TRACE_OCCURRENCE_EXECUTION_PENDING |
           TRACE_OCCURRENCE_AUX_MISSING)) &&
        (end < first || address > last))
        return TRACE_DEP_NO;
    return TRACE_DEP_UNKNOWN;
}
