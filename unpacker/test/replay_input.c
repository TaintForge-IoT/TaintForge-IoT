#include "replay_input.h"

#include <stdlib.h>
#include <string.h>

typedef struct {
    ReplayStep step;
    InsnAux aux;
    InsnMeta meta;
    bool aux_valid;
    bool meta_valid;
} ReplayRecord;

struct ReplayInput {
    ReplayRecord *records; /* selected steps, followed by the trigger */
    uint32_t count;
    size_t bytes;
    uint32_t issues;
    ReplaySources *sources;
    ReplaySourceInfo source_info;
};

static const ReplayRecord *replay_record_find(const ReplayInput *input, uint64_t seq_id) {
    if (!input || !input->records || seq_id == 0)
        return NULL;
    size_t low = 0;
    size_t high = (size_t)input->count + 1U;
    while (low < high) {
        size_t middle = low + (high - low) / 2U;
        uint64_t candidate = input->records[middle].step.entry.seq_id;
        if (candidate < seq_id)
            low = middle + 1U;
        else
            high = middle;
    }
    return low <= input->count && input->records[low].step.entry.seq_id == seq_id
               ? &input->records[low]
               : NULL;
}

static bool replay_descriptor_matches(const InsnDesc *desc, const TraceEntry *entry) {
    return desc && desc->desc_id == entry->insn_desc_id && desc->meta_id == entry->meta_id &&
           desc->pc == entry->pc && desc->code_generation == entry->code_generation &&
           desc->bytes_hash == entry->bytes_hash && desc->size == entry->size && entry->size > 0 &&
           entry->size <= MAX_INSN_BYTES &&
           memcmp(desc->bytes, entry->instr_bytes, entry->size) == 0;
}

static void replay_entry_from_occurrence(TraceEntry *entry, const InsnOccurrence *occurrence,
                                         const InsnDesc *desc) {
    entry->seq_id = occurrence->seq_id;
    entry->vcpu_index = occurrence->vcpu_index;
    entry->insn_desc_id = occurrence->desc_id;
    entry->meta_id = occurrence->meta_id;
    entry->pc = occurrence->pc;
    entry->code_generation = occurrence->code_generation;
    entry->bytes_hash = occurrence->bytes_hash;
    entry->control_transfer_valid = occurrence->control_transfer_valid;
    entry->dcfg_edge_id = occurrence->dcfg_edge_id;
    entry->target_label = occurrence->target_label;
    if (desc && desc->size <= MAX_INSN_BYTES) {
        entry->size = desc->size;
        memcpy(entry->instr_bytes, desc->bytes, desc->size);
    }
}

static bool replay_copy_aux(ReplayInput *input, ReplayRecord *record, const InsnAux *source,
                            size_t max_bytes) {
    record->aux = *source;
    record->aux.sources = NULL;
    const DseSourceObservation *sources = dse_aux_sources(source);
    record->aux.source_metadata_lost =
        source->source_metadata_lost || (source->sources && !sources);
    DseStringSummary *target = &record->aux.string_summary;
    const DseStringSummary *summary = &source->string_summary;
    /* Clear borrowed pointers even when validation/allocation subsequently fails. */
    target->values = NULL;
    target->value_taint = NULL;
    target->capacity = 0;
    if (sources) {
        if (sizeof(*sources) > max_bytes - input->bytes)
            return false;
        record->aux.sources = malloc(sizeof(*sources));
        if (!record->aux.sources)
            return false;
        *record->aux.sources = *sources;
        input->bytes += sizeof(*sources);
    }
    if (summary->bytes_captured > summary->capacity ||
        summary->capacity > DSE_MAX_STRING_BYTES_PER_INSN ||
        (summary->bytes_captured != 0 && (!summary->values || !summary->value_taint))) {
        record->step.issues |= REPLAY_INPUT_STRING_INVALID;
        target->exact = false;
        target->pattern_mismatch = true;
        target->bytes_captured = 0;
        return true;
    }
    size_t bytes = (size_t)summary->bytes_captured * 2U;
    if (bytes > max_bytes - input->bytes)
        return false;
    if (bytes != 0) {
        target->values = malloc(summary->bytes_captured);
        target->value_taint = malloc(summary->bytes_captured);
        if (!target->values || !target->value_taint)
            return false;
        memcpy(target->values, summary->values, summary->bytes_captured);
        memcpy(target->value_taint, summary->value_taint, summary->bytes_captured);
        target->capacity = summary->bytes_captured;
        input->bytes += bytes;
    }
    record->aux_valid = true;
    return true;
}

static bool replay_capture_record(ReplayInput *input, ReplayRecord *record,
                                  const TraceBuffer *trace, const DseAuxRing *ring, uint64_t seq_id,
                                  bool is_trigger, size_t max_bytes) {
    ReplayStep *step = &record->step;
    const TraceEntry *entry = trace_find_seq(trace, seq_id, NULL);
    step->entry.seq_id = seq_id;
    if (!entry) {
        if (!trace_occurrence_archive_find(trace, seq_id, &step->occurrence)) {
            step->occurrence.seq_id = seq_id;
            step->occurrence.incomplete_reasons =
                TRACE_OCCURRENCE_DESC_MISSING | TRACE_OCCURRENCE_AUX_MISSING;
            step->issues |= REPLAY_INPUT_ENTRY_MISSING | REPLAY_INPUT_AUX_MISSING;
            return true;
        }
        const InsnDesc *desc = trace_insn_desc_get(trace, step->occurrence.desc_id);
        replay_entry_from_occurrence(&step->entry, &step->occurrence, desc);
        /* The occurrence archive deliberately does not promise register/REP state. */
        step->issues |= REPLAY_INPUT_AUX_MISSING;
    } else {
        step->entry = *entry;
        (void)dse_aux_materialize_occurrence(ring, trace, entry, &step->occurrence);
        InsnOccurrence archived;
        if (trace_occurrence_archive_find(trace, seq_id, &archived)) {
            if (archived.vcpu_index == entry->vcpu_index &&
                archived.desc_id == entry->insn_desc_id && archived.meta_id == entry->meta_id &&
                archived.pc == entry->pc && archived.code_generation == entry->code_generation &&
                archived.bytes_hash == entry->bytes_hash) {
                /* Includes the finalized BranchEvent and provenance label. */
                step->occurrence = archived;
            } else {
                step->issues |= REPLAY_INPUT_DESCRIPTOR_MISMATCH;
            }
        }
        const InsnAux *aux = dse_aux_for(ring, trace, entry);
        if (!aux)
            step->issues |= REPLAY_INPUT_AUX_MISSING;
        else {
            if (!is_trigger && !aux->execution_complete)
                step->issues |= REPLAY_INPUT_EXECUTION_PENDING;
            if (!replay_copy_aux(input, record, aux, max_bytes))
                return false;
        }
    }
    const InsnDesc *desc = trace_insn_desc_get(trace, step->entry.insn_desc_id);
    if (step->entry.insn_desc_id != INSN_DESC_ID_INVALID) {
        if (!replay_descriptor_matches(desc, &step->entry))
            step->issues |= REPLAY_INPUT_DESCRIPTOR_MISMATCH;
        else {
            step->descriptor = *desc;
            step->descriptor_valid = true;
        }
    }
    const InsnMeta *meta = meta_lookup_id(step->entry.meta_id);
    if (!meta)
        step->issues |= REPLAY_INPUT_META_MISSING;
    else if (meta->meta_id != step->entry.meta_id || meta->pc != step->entry.pc ||
             meta->size == 0 || meta->size > MAX_INSN_BYTES || meta->size != step->entry.size ||
             memcmp(meta->instr_bytes, step->entry.instr_bytes, meta->size) != 0)
        step->issues |= REPLAY_INPUT_META_MISMATCH;
    else {
        record->meta = *meta;
        record->meta_valid = true;
    }
    return true;
}

ReplayInput *replay_input_capture(const TraceBuffer *trace, const DseAuxRing *ring,
                                  const uint64_t *seq_ids, uint32_t count, uint64_t trigger_seq_id,
                                  size_t max_bytes, ReplayInputStatus *status) {
    if (status)
        *status = REPLAY_INPUT_INVALID_REQUEST;
    if (!trace || !ring || !trigger_seq_id || (count && !seq_ids))
        return NULL;
    for (uint32_t index = 0; index < count; index++) {
        if (!seq_ids[index] || seq_ids[index] >= trigger_seq_id ||
            (index && seq_ids[index - 1U] >= seq_ids[index]))
            return NULL;
    }
    if (status)
        *status = REPLAY_INPUT_RESOURCE_LIMIT;
    if (max_bytes < sizeof(ReplayInput) ||
        (uint64_t)count + 1U > (max_bytes - sizeof(ReplayInput)) / sizeof(ReplayRecord))
        return NULL;
    ReplayInput *input = calloc(1, sizeof(*input));
    if (!input)
        return NULL;
    input->count = count;
    input->bytes = sizeof(*input) + ((size_t)count + 1U) * sizeof(ReplayRecord);
    input->records = calloc((size_t)count + 1U, sizeof(ReplayRecord));
    if (!input->records) {
        replay_input_destroy(input);
        return NULL;
    }
    for (size_t index = 0; index <= count; index++) {
        if (!replay_capture_record(input, &input->records[index], trace, ring,
                                   index == count ? trigger_seq_id : seq_ids[index], index == count,
                                   max_bytes)) {
            replay_input_destroy(input);
            return NULL;
        }
    }
    const ReplayStep *trigger = &input->records[count].step;
    for (size_t index = 0; index <= count; index++) {
        ReplayStep *step = &input->records[index].step;
        if (!(step->issues & REPLAY_INPUT_ENTRY_MISSING) &&
            !(trigger->issues & REPLAY_INPUT_ENTRY_MISSING) &&
            step->entry.vcpu_index != trigger->entry.vcpu_index)
            step->issues |= REPLAY_INPUT_VCPU_MISMATCH;
        input->issues |= step->issues;
    }
    if (status)
        *status = input->issues ? REPLAY_INPUT_UNKNOWN : REPLAY_INPUT_READY;
    return input;
}

void replay_input_destroy(ReplayInput *input) {
    if (!input)
        return;
    replay_sources_release(input->sources);
    if (input->records) {
        for (size_t index = 0; index <= input->count; index++) {
            free(input->records[index].aux.sources);
            free(input->records[index].aux.string_summary.values);
            free(input->records[index].aux.string_summary.value_taint);
        }
        free(input->records);
    }
    free(input);
}

uint32_t replay_input_count(const ReplayInput *input) {
    return input ? input->count : 0;
}

size_t replay_input_bytes(const ReplayInput *input) {
    return input ? input->bytes + replay_sources_bytes(input->sources) : 0;
}

uint32_t replay_input_issues(const ReplayInput *input) {
    return input ? input->issues : REPLAY_INPUT_ENTRY_MISSING;
}

const ReplayStep *replay_input_step(const ReplayInput *input, uint32_t index) {
    return input && index < input->count ? &input->records[index].step : NULL;
}

const ReplayStep *replay_input_trigger(const ReplayInput *input) {
    return input ? &input->records[input->count].step : NULL;
}

const ReplayStep *replay_input_find(const ReplayInput *input, uint64_t seq_id) {
    const ReplayRecord *record = replay_record_find(input, seq_id);
    return record ? &record->step : NULL;
}

const InsnAux *replay_input_aux(const ReplayInput *input, uint64_t seq_id) {
    const ReplayRecord *record = replay_record_find(input, seq_id);
    return record && record->aux_valid ? &record->aux : NULL;
}

const InsnMeta *replay_input_meta(const ReplayInput *input, uint64_t seq_id) {
    const ReplayRecord *record = replay_record_find(input, seq_id);
    return record && record->meta_valid ? &record->meta : NULL;
}

ReplaySourceInfo replay_input_capture_sources(ReplayInput *input, ProvRegistry *registry,
                                              const ReplaySourceLimits *limits) {
    ReplaySourceInfo result = {.status = REPLAY_SOURCES_INVALID};
    if (!input || input->sources)
        return result;
    ReplaySourceLimits bound = limits ? *limits : replay_source_default_limits();
    if (!registry) {
        input->source_info = (ReplaySourceInfo){.status = REPLAY_SOURCES_NOT_CAPTURED};
        return input->source_info;
    }
    /* Only the first boundary's registers and flags are external inputs.
   * Read labels from all selected occurrences are retained; the IR bridge
   * subsequently excludes bytes read after a modeled STORE. */
    uint64_t cap = (uint64_t)REG_COUNT * MAX_REG_BYTES + DTA_FLAG_SLOT_COUNT +
                   (uint64_t)input->count * DSE_MAX_MEM_ACCESSES * MAX_REG_BYTES;
    uint64_t scan =
        cap + ((uint64_t)input->count + 1U) * (REG_COUNT + 2U * DSE_MAX_MEM_ACCESSES + 4U);
    if (cap > UINT32_MAX || cap > SIZE_MAX / sizeof(ProvLabelId) ||
        cap * sizeof(ProvLabelId) > bound.bytes || scan > bound.work) {
        result.status = REPLAY_SOURCES_RESOURCE_LIMIT;
        goto done;
    }
    uint64_t instance = prov_registry_instance(registry);
    bool history_missing = false;
    for (uint32_t i = 0; i <= input->count; ++i) {
        const InsnAux *aux = input->records[i].aux_valid ? &input->records[i].aux : NULL;
        if (!aux)
            continue;
        history_missing |= aux->source_metadata_lost;
        const DseSourceObservation *a = dse_aux_sources(aux);
        if (!a)
            continue;
        bool labels_present = a->flag_source_valid != 0;
        for (unsigned reg = 0; reg < REG_COUNT; ++reg)
            labels_present |= a->reg_source_valid[reg] != 0;
        for (unsigned m = 0; m < aux->mem_read_count && m < DSE_MAX_MEM_ACCESSES; ++m)
            labels_present |= a->read_valid[m] != 0;
        if (labels_present && a->registry_instance != instance) {
            result.status = REPLAY_SOURCES_UNKNOWN;
            result.issues = REPLAY_SOURCE_REGISTRY_MISMATCH;
            result.work = scan;
            goto done;
        }
    }
    size_t bytes = (size_t)cap * sizeof(ProvLabelId);
    ProvLabelId *labels = malloc(bytes);
    if (!labels) {
        result.status = REPLAY_SOURCES_OUT_OF_MEMORY;
        goto done;
    }
    uint32_t count = 0;
    const ReplayRecord *first = &input->records[0];
    const DseSourceObservation *first_sources =
        first->aux_valid ? dse_aux_sources(&first->aux) : NULL;
    if (first_sources) {
        for (unsigned reg = 0; reg < REG_COUNT; ++reg)
            for (unsigned byte = 0; byte < MAX_REG_BYTES; ++byte)
                if (first_sources->reg_source_valid[reg] & (1U << byte))
                    labels[count++] = first_sources->reg_source_labels[reg][byte];
        for (unsigned flag = 0; flag < DTA_FLAG_SLOT_COUNT; ++flag)
            if (first_sources->flag_source_valid & (1U << flag))
                labels[count++] = first_sources->flag_source_labels[flag];
    }
    for (uint32_t i = 0; i < input->count; ++i) {
        const ReplayRecord *record = &input->records[i];
        if (!record->aux_valid)
            continue;
        const DseSourceObservation *sources = dse_aux_sources(&record->aux);
        if (!sources)
            continue;
        for (unsigned m = 0; m < record->aux.mem_read_count && m < DSE_MAX_MEM_ACCESSES; ++m) {
            const DseMemRead *read = &record->aux.mem_reads[m];
            for (unsigned byte = 0; byte < read->size && byte < MAX_REG_BYTES; ++byte)
                if (sources->read_valid[m] & (1U << byte))
                    labels[count++] = sources->read_labels[m][byte];
        }
    }
    ReplaySourceLimits remaining = {.bytes = bound.bytes - bytes, .work = bound.work - scan};
    input->sources = replay_sources_capture(registry, labels, count, &remaining, &result);
    free(labels);
    result.work += scan;
    result.bytes += bytes;
    if (history_missing) {
        result.issues |= REPLAY_SOURCE_HISTORY_MISSING;
        if (result.status == REPLAY_SOURCES_READY)
            result.status = REPLAY_SOURCES_UNKNOWN;
    }
done:
    input->source_info = result;
    return result;
}

const ReplaySources *replay_input_sources(const ReplayInput *input) {
    return input ? input->sources : NULL;
}

ReplaySourceInfo replay_input_source_info(const ReplayInput *input) {
    return input ? input->source_info : (ReplaySourceInfo){.status = REPLAY_SOURCES_NOT_CAPTURED};
}
