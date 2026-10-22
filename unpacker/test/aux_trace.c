#include "aux_trace.h"
#include "dta.h"
#include "trace.h"
#include <capstone/capstone.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void dse_aux_capture_sources(DseSourceObservation *aux, const DtaVcpuState *state,
                             uint8_t register_bytes) {
    if (!aux)
        return;
    memset(aux, 0, sizeof(*aux));
    if (!state || !state->regs.registry || !register_bytes || register_bytes > MAX_REG_BYTES)
        return;
    aux->registry_instance = prov_registry_instance(state->regs.registry);
    for (unsigned reg = 0; reg < REG_COUNT; ++reg) {
        for (unsigned byte = 0; byte < register_bytes; ++byte) {
            aux->reg_source_labels[reg][byte] = state->regs.bytes[reg][byte];
            aux->reg_source_valid[reg] |= (uint8_t)(1U << byte);
        }
    }
    for (unsigned flag = 0; flag < DTA_FLAG_SLOT_COUNT; ++flag) {
        aux->flag_source_labels[flag] = state->flags.labels[flag];
        aux->flag_source_valid |= state->flags.valid_mask & (1U << flag);
    }
}

const DseSourceObservation *dse_aux_sources(const InsnAux *aux) {
    return aux && !aux->source_metadata_lost && aux->sources && aux->sources->seq_id == aux->seq_id
               ? aux->sources
               : NULL;
}

DseSourceObservation *dse_aux_sources_mut(InsnAux *aux) {
    return (DseSourceObservation *)dse_aux_sources(aux);
}

bool dse_aux_set_source_limit(DseAuxRing *ring, size_t bytes) {
    if (!ring || ring->source_history)
        return false;
    ring->max_source_bytes = bytes;
    return true;
}

size_t dse_aux_source_bytes(const DseAuxRing *ring) {
    return ring ? (size_t)ring->source_capacity * sizeof(DseSourceObservation) : 0;
}

bool dse_aux_record_sources(DseAuxRing *ring, InsnAux *aux, const DseSourceObservation *source) {
    if (!ring || !aux || !aux->seq_id)
        return false;
    aux->sources = NULL;
    if (!source)
        return true;
    aux->source_metadata_lost = true;
    if (!ring->source_history) {
        size_t capacity = ring->max_source_bytes / sizeof(DseSourceObservation);
        if (capacity > ring->capacity)
            capacity = ring->capacity;
        if (!capacity)
            return false;
        ring->source_history = calloc(capacity, sizeof(*ring->source_history));
        if (!ring->source_history)
            return false;
        ring->source_capacity = (uint32_t)capacity;
    }
    DseSourceObservation *slot = &ring->source_history[aux->seq_id % ring->source_capacity];
    *slot = *source;
    slot->seq_id = aux->seq_id;
    aux->sources = slot;
    aux->source_metadata_lost = false;
    return true;
}

void dse_aux_set_eflags(InsnAux *aux, uint32_t value, bool read_ok, bool provider_verified) {
    if (!aux)
        return;
    aux->eflags_valid = read_ok && provider_verified;
    aux->eflags_before = aux->eflags_valid ? value : 0;
}

static void dse_aux_mark_string_mismatch(InsnAux *aux, const char *reason, uint32_t event_index,
                                         uint64_t expected, uint64_t observed) {
    if (!aux)
        return;
    DseStringSummary *summary = &aux->string_summary;
    if (!summary->pattern_mismatch) {
        fprintf(stderr,
                "[DSE-STRING-MISMATCH] "
                "pc=0x%" PRIx64 " seq=%" PRIu64 " "
                "reason=%s event=%" PRIu32 " "
                "expected=0x%" PRIx64 " observed=0x%" PRIx64 "\n",
                aux->pc, aux->seq_id, reason ? reason : "unknown", event_index, expected, observed);
    }
    summary->pattern_mismatch = true;
}

static bool dse_aux_validate_string_address(InsnAux *aux, const char *reason,
                                            uint64_t first_address, uint32_t event_index,
                                            uint64_t observed_address) {
    if (!aux)
        return false;
    DseStringSummary *summary = &aux->string_summary;
    if (event_index == 0)
        return true;
    uint32_t first = (uint32_t)first_address;
    uint32_t observed = (uint32_t)observed_address;
    uint32_t distance = (uint32_t)((uint64_t)event_index * (uint64_t)summary->element_size);
    uint32_t forward = first + distance;
    uint32_t backward = first - distance;
    if (summary->direction == 0) {
        if (observed == forward) {
            summary->direction = 1;
            return true;
        }
        if (observed == backward) {
            summary->direction = -1;
            return true;
        }
        dse_aux_mark_string_mismatch(aux, reason, event_index, forward, observed);
        return false;
    }
    uint32_t expected = summary->direction > 0 ? forward : backward;
    if (observed != expected) {
        dse_aux_mark_string_mismatch(aux, reason, event_index, expected, observed);
        return false;
    }
    return true;
}

static void dse_aux_release_string(DseAuxRing *ring, InsnAux *aux) {
    if (!aux)
        return;
    DseStringSummary *summary = &aux->string_summary;
    uint64_t owned_bytes = (uint64_t)summary->capacity * 2U;
    free(summary->values);
    free(summary->value_taint);
    if (ring) {
        if (owned_bytes <= ring->dynamic_bytes) {
            ring->dynamic_bytes -= owned_bytes;
        } else {
            ring->dynamic_bytes = 0;
        }
    }
    memset(summary, 0, sizeof(*summary));
}

static bool dse_aux_string_reserve(DseAuxRing *ring, InsnAux *aux, uint32_t required) {
    if (!ring || !aux || required > DSE_MAX_STRING_BYTES_PER_INSN) {
        return false;
    }
    DseStringSummary *summary = &aux->string_summary;
    if (required <= summary->capacity) {
        return true;
    }
    uint32_t new_capacity = summary->capacity != 0 ? summary->capacity : 64U;
    while (new_capacity < required) {
        if (new_capacity >= DSE_MAX_STRING_BYTES_PER_INSN / 2U) {
            new_capacity = DSE_MAX_STRING_BYTES_PER_INSN;
            break;
        }
        new_capacity *= 2U;
    }
    uint64_t additional_bytes = (uint64_t)(new_capacity - summary->capacity) * 2U;
    if ((ring->dynamic_bytes > ring->max_dynamic_bytes) ||
        (additional_bytes > (ring->max_dynamic_bytes - ring->dynamic_bytes))) {
        return false;
    }
    uint8_t *new_values = malloc(new_capacity);
    uint8_t *new_taint = malloc(new_capacity);
    if (!new_values || !new_taint) {
        free(new_values);
        free(new_taint);
        return false;
    }
    if (summary->bytes_captured != 0) {
        memcpy(new_values, summary->values, summary->bytes_captured);
        memcpy(new_taint, summary->value_taint, summary->bytes_captured);
    }
    free(summary->values);
    free(summary->value_taint);
    summary->values = new_values;
    summary->value_taint = new_taint;
    summary->capacity = new_capacity;
    ring->dynamic_bytes += additional_bytes;
    return true;
}

DseAuxRing *dse_aux_create(uint32_t capacity) {
    if (!(capacity > 0 && (capacity & (capacity - 1)) == 0))
        return NULL;
    DseAuxRing *r = calloc(1, sizeof(*r));
    if (!r)
        return NULL;
    r->entries = calloc(capacity, sizeof(InsnAux));
    if (!r->entries) {
        free(r);
        return NULL;
    }
    r->capacity = capacity;
    r->dynamic_bytes = 0;
    r->max_dynamic_bytes = DSE_MAX_STRING_TRACE_BYTES;
    r->max_source_bytes = 8U * 1024U * 1024U;
    return r;
}

void dse_aux_destroy(DseAuxRing *ring) {
    if (!ring)
        return;
    if (ring->entries) {
        for (uint32_t index = 0; index < ring->capacity; index++) {
            dse_aux_release_string(ring, &ring->entries[index]);
        }
    }
    free(ring->entries);
    free(ring->source_history);
    free(ring);
}

static bool trace_entry_index(const TraceBuffer *tb, const TraceEntry *entry, uint32_t *out_idx) {
    if (!tb || !tb->entries || !entry || !out_idx)
        return false;
    uintptr_t base = (uintptr_t)tb->entries;
    uintptr_t ptr = (uintptr_t)entry;
    size_t bytes = (size_t)tb->capacity * sizeof(*tb->entries);
    if (ptr < base || ptr - base >= bytes)
        return false;
    uintptr_t offset = ptr - base;
    if (offset % sizeof(*tb->entries) != 0)
        return false;
    *out_idx = (uint32_t)(offset / sizeof(*tb->entries));
    return true;
}

InsnAux *dse_aux_record(DseAuxRing *r, const TraceBuffer *tb, const TraceEntry *entry,
                        const InsnAux *aux) {
    if (!r || !r->entries || !tb || !entry || !aux || entry->seq_id == 0)
        return NULL;
    uint32_t idx;
    if (!trace_entry_index(tb, entry, &idx) || idx >= r->capacity)
        return NULL;
    InsnAux *stored = &r->entries[idx];
    const DseSourceObservation *source = dse_aux_sources(aux);
    bool source_lost = aux->source_metadata_lost || (aux->sources && !source);
    dse_aux_release_string(r, stored);
    *stored = *aux;
    stored->valid = true;
    stored->seq_id = entry->seq_id;
    stored->meta_id = entry->meta_id;
    stored->pc = entry->pc;
    stored->source_metadata_lost = source_lost;
    (void)dse_aux_record_sources(r, stored, source);
    return stored;
}

void dse_aux_prepare_string(InsnAux *aux, const InsnMeta *meta) {
    if (!aux || !meta || meta->string_element_size == 0) {
        return;
    }
    DseStringSummary *summary = &aux->string_summary;
    summary->element_size = meta->string_element_size;
    summary->has_rep_prefix = meta->has_rep_prefix;
    summary->pattern_mismatch = false;
    summary->expected_iterations = meta->has_rep_prefix ? (uint32_t)aux->reg_vals[DTA_REG_RCX] : 1U;
    summary->direction = 0;
    switch (meta->insn_id) {
    case X86_INS_MOVSB:
    case X86_INS_MOVSW:
    case X86_INS_MOVSD:
    case X86_INS_MOVSQ:
        summary->kind = DSE_STRING_MOVS;
        break;
    case X86_INS_STOSB:
    case X86_INS_STOSW:
    case X86_INS_STOSD:
    case X86_INS_STOSQ:
        summary->kind = DSE_STRING_STOS;
        break;
    default:
        return;
    }
    uint32_t required_registers = 1U << DTA_REG_RDI;
    if (summary->kind == DSE_STRING_MOVS) {
        required_registers |= 1U << DTA_REG_RSI;
    } else {
        required_registers |= 1U << DTA_REG_RAX;
    }
    if (summary->has_rep_prefix) {
        required_registers |= 1U << DTA_REG_RCX;
    }
    if ((aux->reg_value_valid_mask & required_registers) != required_registers) {
        dse_aux_mark_string_mismatch(aux, "register-snapshot-incomplete", 0, required_registers,
                                     aux->reg_value_valid_mask);
    }
    summary->active = true;
}

bool dse_aux_capture_string_read(DseAuxRing *ring, InsnAux *aux, uint64_t address, uint64_t value,
                                 bool value_valid, uint8_t value_taint, uint32_t size) {
    if (!ring || !aux)
        return false;
    DseStringSummary *summary = &aux->string_summary;
    if (!summary->active || summary->kind != DSE_STRING_MOVS) {
        return false;
    }
    if (!value_valid) {
        dse_aux_mark_string_mismatch(aux, "read-value-unavailable", summary->read_events, 1, 0);
        return false;
    }
    if (size == 0 || size != summary->element_size || size > 8U) {
        dse_aux_mark_string_mismatch(aux, "read-element-size", summary->read_events,
                                     summary->element_size, size);
        return false;
    }
    uint32_t event_index = summary->read_events;
    if (event_index == 0) {
        summary->source_first = address;
        if ((uint32_t)address != (uint32_t)aux->reg_vals[DTA_REG_RSI]) {
            dse_aux_mark_string_mismatch(aux, "source-base", event_index,
                                         (uint32_t)aux->reg_vals[DTA_REG_RSI], (uint32_t)address);
        }
    } else {
        (void)dse_aux_validate_string_address(aux, "source-sequence", summary->source_first,
                                              event_index, address);
    }
    if (summary->read_events != UINT32_MAX) {
        summary->read_events++;
    }
    if (summary->bytes_captured > (DSE_MAX_STRING_BYTES_PER_INSN - size) ||
        !dse_aux_string_reserve(ring, aux, summary->bytes_captured + size)) {
        summary->overflow = true;
        return false;
    }
    for (uint32_t byte = 0; byte < size; byte++) {
        uint32_t index = summary->bytes_captured + byte;
        summary->values[index] = (uint8_t)((value >> (8U * byte)) & UINT64_C(0xff));
        summary->value_taint[index] = (value_taint & (uint8_t)(1U << byte)) != 0;
    }
    summary->bytes_captured += size;
    return true;
}

void dse_aux_capture_string_write(InsnAux *aux, uint64_t address, uint32_t size) {
    if (!aux)
        return;
    DseStringSummary *summary = &aux->string_summary;
    if (!summary->active)
        return;
    if (size == 0 || size != summary->element_size) {
        dse_aux_mark_string_mismatch(aux, "write-element-size", summary->write_events,
                                     summary->element_size, size);
        return;
    }
    uint32_t event_index = summary->write_events;
    if (event_index == 0) {
        summary->destination_first = address;
        if ((uint32_t)address != (uint32_t)aux->reg_vals[DTA_REG_RDI]) {
            dse_aux_mark_string_mismatch(aux, "destination-base", event_index,
                                         (uint32_t)aux->reg_vals[DTA_REG_RDI], (uint32_t)address);
        }
    } else {
        (void)dse_aux_validate_string_address(aux, "destination-sequence",
                                              summary->destination_first, event_index, address);
    }
    if (summary->write_events != UINT32_MAX) {
        summary->write_events++;
    }
}

static int8_t dse_aux_direction_from_post_state(uint32_t before, uint32_t after,
                                                uint32_t byte_count) {
    if (byte_count == 0) {
        return after == before ? 1 : 0;
    }
    uint32_t forward = before + byte_count;
    uint32_t backward = before - byte_count;
    if (after == forward)
        return 1;
    if (after == backward)
        return -1;
    return 0;
}

static bool dse_aux_resolve_string_post_state(InsnAux *aux, const uint64_t post_reg_vals[REG_COUNT],
                                              uint32_t post_reg_value_valid_mask) {
    if (!aux)
        return false;
    DseStringSummary *summary = &aux->string_summary;
    uint64_t byte_count_64 =
        (uint64_t)summary->expected_iterations * (uint64_t)summary->element_size;
    if (byte_count_64 > UINT32_MAX) {
        dse_aux_mark_string_mismatch(aux, "string-byte-count-overflow", 0, UINT32_MAX,
                                     byte_count_64);
        return false;
    }
    uint32_t required_registers = UINT32_C(1) << DTA_REG_RDI;
    if (summary->kind == DSE_STRING_MOVS) {
        required_registers |= UINT32_C(1) << DTA_REG_RSI;
    }
    if (summary->has_rep_prefix) {
        required_registers |= UINT32_C(1) << DTA_REG_RCX;
    }
    if ((aux->reg_value_valid_mask & required_registers) != required_registers) {
        dse_aux_mark_string_mismatch(aux, "pre-register-snapshot-incomplete", 0, required_registers,
                                     aux->reg_value_valid_mask);
        return false;
    }
    if (!post_reg_vals || (post_reg_value_valid_mask & required_registers) != required_registers) {
        dse_aux_mark_string_mismatch(aux, "post-register-snapshot-incomplete", 0,
                                     required_registers, post_reg_value_valid_mask);
        return false;
    }

    uint32_t byte_count = (uint32_t)byte_count_64;
    uint32_t edi_before = (uint32_t)aux->reg_vals[DTA_REG_RDI];
    uint32_t edi_after = (uint32_t)post_reg_vals[DTA_REG_RDI];
    int8_t resolved_direction =
        dse_aux_direction_from_post_state(edi_before, edi_after, byte_count);
    if (resolved_direction == 0) {
        dse_aux_mark_string_mismatch(aux, "destination-post-state", 0, byte_count,
                                     (uint32_t)(edi_after - edi_before));
        return false;
    }
    if (summary->kind == DSE_STRING_MOVS) {
        uint32_t esi_before = (uint32_t)aux->reg_vals[DTA_REG_RSI];
        uint32_t esi_after = (uint32_t)post_reg_vals[DTA_REG_RSI];
        int8_t source_direction =
            dse_aux_direction_from_post_state(esi_before, esi_after, byte_count);
        if (source_direction == 0) {
            dse_aux_mark_string_mismatch(aux, "source-post-state", 0, byte_count,
                                         (uint32_t)(esi_after - esi_before));
            return false;
        }
        if (source_direction != resolved_direction) {
            dse_aux_mark_string_mismatch(aux, "source-destination-direction", 0,
                                         resolved_direction > 0 ? 1U : 0U,
                                         source_direction > 0 ? 1U : 0U);
            return false;
        }
    }
    if (summary->direction != 0 && summary->direction != resolved_direction) {
        dse_aux_mark_string_mismatch(aux, "address-post-direction", 0,
                                     summary->direction > 0 ? 1U : 0U,
                                     resolved_direction > 0 ? 1U : 0U);
        return false;
    }
    summary->direction = resolved_direction;
    if (summary->has_rep_prefix && (uint32_t)post_reg_vals[DTA_REG_RCX] != 0) {
        dse_aux_mark_string_mismatch(aux, "rep-count-post-state", 0, 0,
                                     (uint32_t)post_reg_vals[DTA_REG_RCX]);
        return false;
    }
    return true;
}

void dse_aux_finalize(InsnAux *aux, uint64_t next_pc, const uint64_t post_reg_vals[REG_COUNT],
                      uint32_t post_reg_value_valid_mask) {
    if (!aux)
        return;
    aux->next_pc = next_pc;
    aux->next_pc_valid = true;
    aux->execution_complete = true;
    DseStringSummary *summary = &aux->string_summary;
    if (!summary->active)
        return;
    uint64_t expected_bytes =
        (uint64_t)summary->expected_iterations * (uint64_t)summary->element_size;
    bool post_state_valid =
        dse_aux_resolve_string_post_state(aux, post_reg_vals, post_reg_value_valid_mask);
    if (summary->kind == DSE_STRING_MOVS) {
        summary->exact = post_state_valid && !summary->overflow && !summary->pattern_mismatch &&
                         summary->read_events == summary->expected_iterations &&
                         summary->write_events == summary->expected_iterations &&
                         expected_bytes == summary->bytes_captured;
    } else if (summary->kind == DSE_STRING_STOS) {
        summary->exact = post_state_valid && !summary->overflow && !summary->pattern_mismatch &&
                         summary->write_events == summary->expected_iterations &&
                         expected_bytes <= DSE_MAX_STRING_BYTES_PER_INSN;
    }
}

static bool dse_aux_has_exact_string_kind(const InsnAux *aux, DseStringKind expected_kind) {
    if (!aux || !aux->execution_complete) {
        return false;
    }
    const DseStringSummary *summary = &aux->string_summary;
    if (!summary->active || !summary->exact || summary->kind != expected_kind ||
        summary->overflow || summary->pattern_mismatch ||
        (summary->element_size != 1U && summary->element_size != 2U &&
         summary->element_size != 4U && summary->element_size != 8U) ||
        (summary->direction != 1 && summary->direction != -1) ||
        (!summary->has_rep_prefix && summary->expected_iterations != 1U)) {
        return false;
    }
    uint64_t total_bytes = (uint64_t)summary->expected_iterations * summary->element_size;
    if (total_bytes > DSE_MAX_STRING_BYTES_PER_INSN) {
        return false;
    }
    if (summary->expected_iterations == 0) {
        return summary->has_rep_prefix && summary->read_events == 0 && summary->write_events == 0 &&
               aux->mem_read_total == 0 && aux->mem_write_total == 0;
    }
    if (!aux->mem_write_range_valid || aux->mem_write_range_unknown ||
        aux->mem_write_total != summary->expected_iterations ||
        summary->write_events != summary->expected_iterations) {
        return false;
    }
    if (expected_kind == DSE_STRING_MOVS) {
        return (aux->mem_read_range_valid && !aux->mem_read_range_unknown &&
                aux->mem_read_total == summary->expected_iterations &&
                summary->read_events == summary->expected_iterations &&
                summary->bytes_captured == total_bytes &&
                summary->capacity >= summary->bytes_captured && summary->values != NULL &&
                summary->value_taint != NULL);
    }
    return aux->mem_read_total == 0 && summary->read_events == 0 && summary->bytes_captured == 0;
}

bool dse_aux_has_exact_movs(const InsnAux *aux) {
    return dse_aux_has_exact_string_kind(aux, DSE_STRING_MOVS);
}

bool dse_aux_has_exact_stos(const InsnAux *aux) {
    return dse_aux_has_exact_string_kind(aux, DSE_STRING_STOS);
}

const InsnAux *dse_aux_for(const DseAuxRing *r, const TraceBuffer *tb, const TraceEntry *entry) {
    if (!r || !r->entries || !tb || !entry || entry->seq_id == 0)
        return NULL;
    uint32_t idx;
    if (!trace_entry_index(tb, entry, &idx) || idx >= r->capacity)
        return NULL;
    const InsnAux *aux = &r->entries[idx];
    if (!aux->valid || aux->pc != entry->pc || aux->seq_id != entry->seq_id ||
        aux->meta_id != entry->meta_id) {
        return NULL;
    }
    return aux;
}

bool dse_aux_materialize_occurrence(const DseAuxRing *ring, const TraceBuffer *trace,
                                    const TraceEntry *entry, InsnOccurrence *out) {
    if (!trace || !entry || !out || !trace_occurrence_from_entry(entry, out)) {
        return false;
    }
    const InsnDesc *desc = trace_insn_desc_get(trace, entry->insn_desc_id);
    if (!desc || desc->meta_id != entry->meta_id || desc->pc != entry->pc ||
        desc->code_generation != entry->code_generation || desc->bytes_hash != entry->bytes_hash) {
        out->incomplete_reasons |= TRACE_OCCURRENCE_DESC_MISSING;
    } else {
        out->incomplete_reasons &= ~TRACE_OCCURRENCE_DESC_MISSING;
    }

    const InsnAux *aux = dse_aux_for(ring, trace, entry);
    if (!aux) {
        out->incomplete_reasons |= TRACE_OCCURRENCE_AUX_MISSING;
        return true;
    }
    out->dynamic_effects_available = true;
    out->execution_complete = aux->execution_complete;
    out->next_pc_valid = aux->next_pc_valid;
    out->next_pc = aux->next_pc;
    if (!aux->execution_complete) {
        out->incomplete_reasons |= TRACE_OCCURRENCE_EXECUTION_PENDING;
    }
    if (aux->mem_read_overflow) {
        out->incomplete_reasons |= TRACE_OCCURRENCE_READ_OVERFLOW;
    }
    if (aux->mem_write_overflow) {
        out->incomplete_reasons |= TRACE_OCCURRENCE_WRITE_OVERFLOW;
    }
    if (aux->mem_read_range_unknown || aux->mem_write_range_unknown) {
        out->incomplete_reasons |= TRACE_OCCURRENCE_RANGE_UNKNOWN;
    }
    out->mem_read_total = aux->mem_read_total;
    out->mem_write_total = aux->mem_write_total;
    out->mem_read_range_valid = aux->mem_read_range_valid;
    out->mem_write_range_valid = aux->mem_write_range_valid;
    out->mem_read_min_addr = aux->mem_read_min_addr;
    out->mem_read_max_addr = aux->mem_read_max_addr;
    out->mem_write_min_addr = aux->mem_write_min_addr;
    out->mem_write_max_addr = aux->mem_write_max_addr;
    out->mem_read_count =
        aux->mem_read_count <= TRACE_MAX_MEM_EFFECTS ? aux->mem_read_count : TRACE_MAX_MEM_EFFECTS;
    out->mem_write_count = aux->mem_write_count <= TRACE_MAX_MEM_EFFECTS ? aux->mem_write_count
                                                                         : TRACE_MAX_MEM_EFFECTS;

    for (uint8_t index = 0; index < out->mem_read_count; index++) {
        const DseMemRead *source = &aux->mem_reads[index];
        TraceMemoryEffect *target = &out->mem_reads[index];
        target->kind = TRACE_MEM_READ;
        target->address = source->addr;
        target->value = source->value;
        target->size = source->size;
        target->taint_mask = source->taint;
        target->effective_taint_mask = source->effective_taint;
        target->value_valid = source->value_valid;
        target->address_tainted = source->address_tainted;
        if (!source->value_valid) {
            out->incomplete_reasons |= TRACE_OCCURRENCE_VALUE_MISSING;
        }
    }
    for (uint8_t index = 0; index < out->mem_write_count; index++) {
        const DseMemWrite *source = &aux->mem_writes[index];
        TraceMemoryEffect *target = &out->mem_writes[index];
        target->kind = TRACE_MEM_WRITE;
        target->address = source->addr;
        target->value = source->value;
        target->size = source->size;
        target->value_valid = source->value_valid;
        target->address_tainted = source->address_tainted;
        if (!source->value_valid) {
            out->incomplete_reasons |= TRACE_OCCURRENCE_VALUE_MISSING;
        }
    }
    return true;
}

bool dse_aux_archive_occurrence(const DseAuxRing *ring, TraceBuffer *trace,
                                const BranchEventBuffer *branch_events, uint64_t seq_id) {
    if (!ring || !trace || seq_id == 0) {
        if (trace) {
            trace_occurrence_archive_note_loss(trace);
        }
        return false;
    }

    const TraceEntry *entry = trace_find_seq(trace, seq_id, NULL);

    if (!entry) {
        trace_occurrence_archive_note_loss(trace);
        return false;
    }

    InsnOccurrence occurrence;

    if (!dse_aux_materialize_occurrence(ring, trace, entry, &occurrence)) {
        trace_occurrence_archive_note_loss(trace);
        return false;
    }

    const BranchEvent *event =
        branch_event_find_seq(branch_events, occurrence.seq_id, occurrence.vcpu_index);

    if (event) {
        (void)trace_occurrence_apply_branch_event(&occurrence, event);
    } else if (occurrence.execution_complete) {
        const InsnDesc *desc = trace_insn_desc_get(trace, occurrence.desc_id);

        if (desc && desc->effects.branch_kind == TRACE_BRANCH_CONDITIONAL) {
            occurrence.incomplete_reasons |= TRACE_OCCURRENCE_BRANCH_MISMATCH;
        }
    }

    return trace_occurrence_archive_append(trace, &occurrence);
}
