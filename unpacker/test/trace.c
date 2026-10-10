#include "trace.h"
#include <glib.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "dta.h"

#define TRACE_ARCHIVE_DEFAULT_CHUNK_BYTES (64U * 1024U)
#define TRACE_ARCHIVE_INDEX_PAGE_BITS 12U
#define TRACE_ARCHIVE_INDEX_PAGE_SIZE (UINT64_C(1) << TRACE_ARCHIVE_INDEX_PAGE_BITS)
#define TRACE_ARCHIVE_RECORD_ALIGNMENT 8U

typedef struct {
    TraceArchKind arch;
    TraceArchMode mode;
    uint64_t pc;
    uint32_t code_generation;
    uint64_t bytes_hash;
    uint8_t size;
    uint8_t bytes[MAX_INSN_BYTES];
} InsnDescKey;

struct TraceDescriptorStore {
    GHashTable *by_key;
    GHashTable *by_location; /* Borrowed keys/values; NULL value marks conflicting bytes. */
    GPtrArray *by_id;
    GMutex lock;
    bool lock_initialized;
};

typedef struct TraceArchiveRecordHeader {
    uint64_t record_size;
} TraceArchiveRecordHeader;

typedef struct TraceArchiveChunk {
    struct TraceArchiveChunk *next;
    uint8_t *data;
    size_t capacity;
    size_t used;
} TraceArchiveChunk;

struct TraceOccurrenceArchive {
    TraceArchiveChunk *first_chunk;
    TraceArchiveChunk *last_chunk;
    TraceArchiveRecordHeader ***index_pages;
    size_t index_page_capacity;
    uint64_t record_count;
    uint64_t record_bytes;
    uint64_t incomplete_records;
    uint64_t dropped_records;
    GMutex lock;
    bool lock_initialized;
    bool complete;
};

static void trace_archive_note_loss_locked(struct TraceOccurrenceArchive *archive) {
    if (!archive)
        return;
    archive->complete = false;
    if (archive->dropped_records != UINT64_MAX) {
        archive->dropped_records++;
    }
}

static struct TraceOccurrenceArchive *trace_occurrence_archive_create(void) {
    struct TraceOccurrenceArchive *archive = calloc(1, sizeof(*archive));
    if (!archive)
        return NULL;
    g_mutex_init(&archive->lock);
    archive->lock_initialized = true;
    archive->complete = true;
    return archive;
}

static void trace_archive_chunk_destroy_all(TraceArchiveChunk *chunk) {
    while (chunk) {
        TraceArchiveChunk *next = chunk->next;
        free(chunk->data);
        free(chunk);
        chunk = next;
    }
}

static void trace_occurrence_archive_destroy(struct TraceOccurrenceArchive *archive) {
    if (!archive)
        return;
    if (archive->lock_initialized) {
        g_mutex_lock(&archive->lock);
    }
    trace_archive_chunk_destroy_all(archive->first_chunk);
    archive->first_chunk = NULL;
    archive->last_chunk = NULL;
    if (archive->index_pages) {
        for (size_t index = 0; index < archive->index_page_capacity; index++) {
            free(archive->index_pages[index]);
        }
        free(archive->index_pages);
        archive->index_pages = NULL;
    }
    if (archive->lock_initialized) {
        g_mutex_unlock(&archive->lock);
        g_mutex_clear(&archive->lock);
    }
    free(archive);
}

static bool trace_archive_align_size(size_t value, size_t *out) {
    if (!out || value > (SIZE_MAX - (TRACE_ARCHIVE_RECORD_ALIGNMENT - 1U))) {
        return false;
    }
    *out = (value + (TRACE_ARCHIVE_RECORD_ALIGNMENT - 1U)) &
           ~(size_t)(TRACE_ARCHIVE_RECORD_ALIGNMENT - 1U);
    return true;
}

static TraceArchiveChunk *trace_archive_chunk_create(size_t required) {
    size_t capacity = TRACE_ARCHIVE_DEFAULT_CHUNK_BYTES;
    if (required > capacity) {
        if (!trace_archive_align_size(required, &capacity)) {
            return NULL;
        }
    }
    TraceArchiveChunk *chunk = calloc(1, sizeof(*chunk));
    if (!chunk)
        return NULL;
    chunk->data = malloc(capacity);
    if (!chunk->data) {
        free(chunk);
        return NULL;
    }
    chunk->capacity = capacity;
    return chunk;
}

static bool trace_archive_index_slot(struct TraceOccurrenceArchive *archive, uint64_t seq_id,
                                     TraceArchiveRecordHeader ***out_slot) {
    if (!archive || seq_id == 0 || !out_slot) {
        return false;
    }
    uint64_t page_number = (seq_id - 1U) >> TRACE_ARCHIVE_INDEX_PAGE_BITS;
    uint64_t slot_number = (seq_id - 1U) & (TRACE_ARCHIVE_INDEX_PAGE_SIZE - 1U);
    if (page_number > SIZE_MAX) {
        return false;
    }
    size_t page_index = (size_t)page_number;
    if (page_index >= archive->index_page_capacity) {
        size_t new_capacity = archive->index_page_capacity != 0 ? archive->index_page_capacity : 4U;
        while (new_capacity <= page_index) {
            if (new_capacity > (SIZE_MAX / 2U)) {
                new_capacity = page_index + 1U;
                if (new_capacity <= page_index) {
                    return false;
                }
                break;
            }
            new_capacity *= 2U;
        }
        if (new_capacity > (SIZE_MAX / sizeof(*archive->index_pages))) {
            return false;
        }
        TraceArchiveRecordHeader ***new_pages =
            realloc(archive->index_pages, new_capacity * sizeof(*new_pages));
        if (!new_pages)
            return false;
        memset(new_pages + archive->index_page_capacity, 0,
               (new_capacity - archive->index_page_capacity) * sizeof(*new_pages));
        archive->index_pages = new_pages;
        archive->index_page_capacity = new_capacity;
    }
    if (!archive->index_pages[page_index]) {
        archive->index_pages[page_index] = calloc((size_t)TRACE_ARCHIVE_INDEX_PAGE_SIZE,
                                                  sizeof(*archive->index_pages[page_index]));
        if (!archive->index_pages[page_index]) {
            return false;
        }
    }
    *out_slot = &archive->index_pages[page_index][(size_t)slot_number];
    return true;
}

static TraceArchiveRecordHeader *
trace_archive_index_find(const struct TraceOccurrenceArchive *archive, uint64_t seq_id) {
    if (!archive || seq_id == 0) {
        return NULL;
    }
    uint64_t page_number = (seq_id - 1U) >> TRACE_ARCHIVE_INDEX_PAGE_BITS;
    uint64_t slot_number = (seq_id - 1U) & (TRACE_ARCHIVE_INDEX_PAGE_SIZE - 1U);
    if (page_number > SIZE_MAX || page_number >= archive->index_page_capacity) {
        return NULL;
    }
    TraceArchiveRecordHeader **page = archive->index_pages[(size_t)page_number];
    return page ? page[(size_t)slot_number] : NULL;
}

static guint insn_desc_key_hash(gconstpointer opaque) {
    const InsnDescKey *key = opaque;
    if (!key)
        return 0;
    uint64_t mixed = key->bytes_hash;
    mixed ^= key->pc + UINT64_C(0x9e3779b97f4a7c15) + (mixed << 6) + (mixed >> 2);
    mixed ^= (uint64_t)key->code_generation << 32;
    mixed ^= (uint64_t)(uint32_t)key->arch << 16;
    mixed ^= (uint64_t)(uint32_t)key->mode << 8;
    mixed ^= key->size;
    return (guint)(mixed ^ (mixed >> 32));
}

static gboolean insn_desc_key_equal(gconstpointer left_opaque, gconstpointer right_opaque) {
    const InsnDescKey *left = left_opaque;
    const InsnDescKey *right = right_opaque;
    if (!left || !right) {
        return left == right;
    }
    return left->arch == right->arch && left->mode == right->mode && left->pc == right->pc &&
           left->code_generation == right->code_generation &&
           left->bytes_hash == right->bytes_hash && left->size == right->size &&
           memcmp(left->bytes, right->bytes, left->size) == 0;
}

static guint insn_desc_location_hash(gconstpointer opaque) {
    const InsnDescKey *key = opaque;
    uint64_t mixed = key->pc ^ ((uint64_t)key->code_generation << 32) ^
                     ((uint64_t)key->arch << 16) ^ (uint32_t)key->mode;
    return (guint)(mixed ^ (mixed >> 32));
}

static gboolean insn_desc_location_equal(gconstpointer a, gconstpointer b) {
    const InsnDescKey *left = a, *right = b;
    return left->pc == right->pc && left->code_generation == right->code_generation &&
           left->arch == right->arch && left->mode == right->mode;
}

static struct TraceDescriptorStore *trace_descriptor_store_create(void) {
    struct TraceDescriptorStore *store = g_try_new0(struct TraceDescriptorStore, 1);
    if (!store)
        return NULL;
    store->by_key = g_hash_table_new_full(insn_desc_key_hash, insn_desc_key_equal, g_free, NULL);
    store->by_location = g_hash_table_new(insn_desc_location_hash, insn_desc_location_equal);
    store->by_id = g_ptr_array_new_with_free_func(g_free);
    if (!store->by_key || !store->by_location || !store->by_id) {
        if (store->by_location)
            g_hash_table_destroy(store->by_location);
        if (store->by_key) {
            g_hash_table_destroy(store->by_key);
        }
        if (store->by_id) {
            g_ptr_array_unref(store->by_id);
        }
        g_free(store);
        return NULL;
    }
    g_mutex_init(&store->lock);
    store->lock_initialized = true;
    return store;
}

static void trace_descriptor_store_destroy(struct TraceDescriptorStore *store) {
    if (!store)
        return;
    if (store->lock_initialized) {
        g_mutex_lock(&store->lock);
    }
    if (store->by_location)
        g_hash_table_destroy(store->by_location);
    if (store->by_key) {
        g_hash_table_destroy(store->by_key);
        store->by_key = NULL;
    }
    if (store->by_id) {
        g_ptr_array_unref(store->by_id);
        store->by_id = NULL;
    }
    if (store->lock_initialized) {
        g_mutex_unlock(&store->lock);
        g_mutex_clear(&store->lock);
    }
    g_free(store);
}

uint64_t trace_instruction_bytes_hash(const uint8_t *bytes, uint8_t size) {
    if (!bytes || size == 0 || size > MAX_INSN_BYTES) {
        return 0;
    }
    uint64_t hash = UINT64_C(14695981039346656037);
    for (uint8_t index = 0; index < size; index++) {
        hash ^= bytes[index];
        hash *= UINT64_C(1099511628211);
    }
    hash ^= size;
    hash *= UINT64_C(1099511628211);
    return hash != 0 ? hash : UINT64_C(1);
}

static uint64_t trace_x86_special_mask(uint8_t x86_mask) {
    uint64_t result = 0;
    if (x86_mask & X86_FLAG_CF) {
        result |= trace_special_state_bit(X86_SPECIAL_STATE_CF);
    }
    if (x86_mask & X86_FLAG_PF) {
        result |= trace_special_state_bit(X86_SPECIAL_STATE_PF);
    }
    if (x86_mask & X86_FLAG_AF) {
        result |= trace_special_state_bit(X86_SPECIAL_STATE_AF);
    }
    if (x86_mask & X86_FLAG_ZF) {
        result |= trace_special_state_bit(X86_SPECIAL_STATE_ZF);
    }
    if (x86_mask & X86_FLAG_SF) {
        result |= trace_special_state_bit(X86_SPECIAL_STATE_SF);
    }
    if (x86_mask & X86_FLAG_OF) {
        result |= trace_special_state_bit(X86_SPECIAL_STATE_OF);
    }
    return result;
}

static TraceRegSlice trace_reg_slice(RegSlice slice) {
    TraceRegSlice result = {0};
    if (!reg_slice_is_valid(slice)) {
        return result;
    }
    result.reg_id = (uint16_t)slice.reg_id;
    result.bit_offset = (uint16_t)slice.byte_offset * 8U;
    result.bit_width = (uint16_t)slice.width * 8U;
    return result;
}

static TraceBranchKind trace_x86_branch_kind(const InsnMeta *meta) {
    if (!meta) {
        return TRACE_BRANCH_NONE;
    }
    if (meta->is_conditional_branch) {
        return TRACE_BRANCH_CONDITIONAL;
    }
    switch (meta->insn_id) {
    case X86_INS_JMP:
        return meta->is_indirect_branch ? TRACE_BRANCH_JUMP_INDIRECT : TRACE_BRANCH_JUMP_DIRECT;
    case X86_INS_CALL:
        return meta->is_indirect_branch ? TRACE_BRANCH_CALL_INDIRECT : TRACE_BRANCH_CALL_DIRECT;
    case X86_INS_RET:
        return TRACE_BRANCH_RETURN;
    default:
        return TRACE_BRANCH_NONE;
    }
}

bool trace_effect_summary_from_meta(const InsnMeta *meta, EffectSummary *out) {
    if (!out)
        return false;
    memset(out, 0, sizeof(*out));
    if (!meta) {
        out->quality_flags = TRACE_EFFECT_META_MISSING;
        return false;
    }
    out->register_value_uses = meta->regs_read_mask;
    out->register_address_uses = meta->mem_addr_reg_mask;
    out->register_memory_read_address_uses = meta->mem_read_addr_reg_mask;
    out->register_memory_write_address_uses = meta->mem_write_addr_reg_mask;
    out->register_defs = meta->regs_written_mask;
    out->may_read_memory = meta->has_mem_read;
    out->may_write_memory = meta->has_mem_write;
    out->branch_kind = trace_x86_branch_kind(meta);
    out->direct_target_valid = meta->direct_target_valid;
    out->direct_target = meta->direct_target;
    uint64_t special_uses = trace_x86_special_mask(meta->flags_read_mask);
    if (meta->is_conditional_branch) {
        out->special_control_uses = special_uses;
    } else {
        out->special_value_uses = special_uses;
    }

    out->special_defs = trace_x86_special_mask(meta->flags_write_mask);
    if (meta->family == DTA_FAMILY_STRING || insn_meta_is_plain_scasd(meta)) {
        out->special_address_uses |= trace_special_state_bit(X86_SPECIAL_STATE_DF);
    }
    if (meta->writes_df) {
        out->special_defs |= trace_special_state_bit(X86_SPECIAL_STATE_DF);
    }
    if (insn_meta_is_plain_scasd(meta))
        out->special_address_uses |= trace_special_state_bit(X86_SPECIAL_STATE_ES);
    if (meta->writes_es)
        out->special_defs |= trace_special_state_bit(X86_SPECIAL_STATE_ES);
    if (meta->is_indirect_branch && meta->branch_target_reg >= 0 && meta->branch_target_reg < 64) {
        out->register_control_uses |= UINT64_C(1) << meta->branch_target_reg;
    }
    uint8_t value_use_count = meta->reg_read_count;
    if (meta->reg_slice_detail_truncated) {
        out->quality_flags |= TRACE_EFFECT_SLICE_DETAIL_TRUNCATED;
    }
    if (value_use_count > MAX_INSN_REG_SLICES) {
        value_use_count = MAX_INSN_REG_SLICES;
        out->quality_flags |= TRACE_EFFECT_SLICE_DETAIL_TRUNCATED;
    }
    for (uint8_t index = 0; index < value_use_count; index++) {
        out->value_use_slices[index] = trace_reg_slice(meta->reg_reads[index]);
    }
    out->value_use_slice_count = value_use_count;
    uint8_t def_count = meta->reg_write_count;
    if (def_count > MAX_INSN_REG_SLICES) {
        def_count = MAX_INSN_REG_SLICES;
        out->quality_flags |= TRACE_EFFECT_SLICE_DETAIL_TRUNCATED;
    }

    for (uint8_t index = 0; index < def_count; index++) {
        out->def_slices[index] = trace_reg_slice(meta->reg_writes[index]);
    }
    out->def_slice_count = def_count;
    if (meta->family == DTA_FAMILY_UNSUPPORTED) {
        out->quality_flags |= TRACE_EFFECT_NEEDS_FULL_LIFT;
    }
    return true;
}

InsnDescId trace_insn_desc_intern(TraceBuffer *tb, TraceArchKind arch, TraceArchMode mode,
                                  uint64_t pc, uint32_t code_generation, const uint8_t *bytes,
                                  uint8_t size, const InsnMeta *meta) {
    if (!tb || !tb->descriptor_store || !bytes || size == 0 || size > MAX_INSN_BYTES) {
        return INSN_DESC_ID_INVALID;
    }
    struct TraceDescriptorStore *store = tb->descriptor_store;
    InsnDescKey lookup = {0};
    lookup.arch = arch;
    lookup.mode = mode;
    lookup.pc = pc;
    lookup.code_generation = code_generation;
    lookup.size = size;
    lookup.bytes_hash = trace_instruction_bytes_hash(bytes, size);
    memcpy(lookup.bytes, bytes, size);
    g_mutex_lock(&store->lock);
    InsnDesc *existing = g_hash_table_lookup(store->by_key, &lookup);
    if (existing) {
        InsnDescId result = existing->desc_id;
        g_mutex_unlock(&store->lock);
        return result;
    }
    if (!store->by_id || store->by_id->len == G_MAXUINT) {
        g_mutex_unlock(&store->lock);
        return INSN_DESC_ID_INVALID;
    }

    InsnDescKey *stored_key = g_try_new(InsnDescKey, 1);
    InsnDesc *desc = g_try_new0(InsnDesc, 1);
    if (!stored_key || !desc) {
        g_free(stored_key);
        g_free(desc);
        g_mutex_unlock(&store->lock);
        return INSN_DESC_ID_INVALID;
    }
    *stored_key = lookup;
    desc->desc_id = (InsnDescId)store->by_id->len + 1U;
    desc->available_seq = tb->next_seq_id;
    desc->arch = arch;
    desc->mode = mode;
    desc->pc = pc;
    desc->code_generation = code_generation;
    desc->bytes_hash = lookup.bytes_hash;
    desc->size = size;
    memcpy(desc->bytes, bytes, size);

    bool meta_matches =
        meta && meta->pc == pc && meta->size == size && memcmp(meta->instr_bytes, bytes, size) == 0;
    if (meta_matches) {
        desc->meta_id = meta->meta_id;
        desc->native_insn_id = meta->insn_id;
        (void)trace_effect_summary_from_meta(meta, &desc->effects);
    } else {
        desc->meta_id = META_ID_INVALID;
        (void)trace_effect_summary_from_meta(NULL, &desc->effects);
    }
    g_ptr_array_add(store->by_id, desc);
    bool conflict = g_hash_table_contains(store->by_location, stored_key);
    g_hash_table_insert(store->by_location, stored_key, conflict ? NULL : desc);
    g_hash_table_insert(store->by_key, stored_key, desc);
    g_mutex_unlock(&store->lock);
    return desc->desc_id;
}

const InsnDesc *trace_insn_desc_get(const TraceBuffer *tb, InsnDescId desc_id) {
    if (!tb || !tb->descriptor_store || desc_id == INSN_DESC_ID_INVALID) {
        return NULL;
    }
    struct TraceDescriptorStore *store = tb->descriptor_store;
    g_mutex_lock(&store->lock);
    const InsnDesc *result = NULL;
    uint64_t index = desc_id - 1U;
    if (store->by_id && index < store->by_id->len) {
        result = g_ptr_array_index(store->by_id, (guint)index);
    }
    g_mutex_unlock(&store->lock);
    return result;
}

TraceDescLookup trace_insn_desc_find(const TraceBuffer *tb, TraceArchKind arch, TraceArchMode mode,
                                     uint64_t pc, uint32_t generation, uint64_t before_seq,
                                     const InsnDesc **out) {
    if (out)
        *out = NULL;
    if (!tb || !tb->descriptor_store || !out)
        return TRACE_DESC_ABSENT;
    InsnDescKey key = {.arch = arch, .mode = mode, .pc = pc, .code_generation = generation};
    struct TraceDescriptorStore *store = tb->descriptor_store;
    g_mutex_lock(&store->lock);
    gpointer value = NULL;
    bool found = g_hash_table_lookup_extended(store->by_location, &key, NULL, &value);
    const InsnDesc *desc = value;
    TraceDescLookup result = !found  ? TRACE_DESC_ABSENT
                             : !desc ? TRACE_DESC_AMBIGUOUS
                             : !desc->available_seq || desc->available_seq > before_seq
                                 ? TRACE_DESC_FUTURE
                                 : TRACE_DESC_FOUND;
    if (result == TRACE_DESC_FOUND)
        *out = desc;
    g_mutex_unlock(&store->lock);
    return result;
}

uint64_t trace_insn_desc_count(const TraceBuffer *tb) {
    if (!tb || !tb->descriptor_store) {
        return 0;
    }
    struct TraceDescriptorStore *store = tb->descriptor_store;
    g_mutex_lock(&store->lock);
    uint64_t result = store->by_id ? store->by_id->len : 0;
    g_mutex_unlock(&store->lock);
    return result;
}

TraceBuffer *trace_buffer_create(uint32_t capacity) {
    if (!(capacity > 0 && (capacity & (capacity - 1)) == 0)) {
        return NULL;
    }
    TraceBuffer *buff = calloc(1, sizeof(*buff));
    if (!buff)
        return NULL;
    buff->entries = calloc(capacity, sizeof(TraceEntry));
    if (!buff->entries) {
        free(buff);
        return NULL;
    }
    buff->descriptor_store = trace_descriptor_store_create();
    if (!buff->descriptor_store) {
        free(buff->entries);
        free(buff);
        return NULL;
    }
    buff->occurrence_archive = trace_occurrence_archive_create();
    if (!buff->occurrence_archive) {
        trace_descriptor_store_destroy(buff->descriptor_store);
        free(buff->entries);
        free(buff);
        return NULL;
    }
    buff->capacity = capacity;
    buff->head_pointer = 0;
    buff->counter = 0;
    buff->next_seq_id = 1;
    return buff;
}

void trace_buffer_destroy(TraceBuffer *tb) {
    if (!tb)
        return;
    trace_occurrence_archive_destroy(tb->occurrence_archive);
    trace_descriptor_store_destroy(tb->descriptor_store);
    free(tb->entries);
    free(tb);
}

const TraceEntry *trace_append(TraceBuffer *tb, const TraceEntry *entry) {
    if (!tb || !entry || tb->next_seq_id == 0) {
        return NULL;
    }
    const InsnDesc *desc = NULL;
    if (entry->insn_desc_id != INSN_DESC_ID_INVALID) {
        desc = trace_insn_desc_get(tb, entry->insn_desc_id);
        if (!desc || entry->pc != desc->pc) {
            return NULL;
        }
    }
    uint32_t idx = tb->head_pointer & (tb->capacity - 1);
    tb->entries[idx] = *entry;
    if (desc) {
        tb->entries[idx].meta_id = desc->meta_id;
        tb->entries[idx].code_generation = desc->code_generation;
        tb->entries[idx].bytes_hash = desc->bytes_hash;
        tb->entries[idx].size = desc->size;
        memcpy(tb->entries[idx].instr_bytes, desc->bytes, desc->size);
    }
    tb->entries[idx].seq_id = tb->next_seq_id++;
    tb->head_pointer++;
    if (tb->counter < tb->capacity) {
        tb->counter++;
    }
    return &tb->entries[idx];
}

// for backward reconstruction
const TraceEntry *trace_get_last(const TraceBuffer *tb, uint32_t i) {
    if (!tb)
        return NULL;
    if (i >= tb->counter)
        return NULL;
    uint32_t idx = (tb->head_pointer - 1 - i) & (tb->capacity - 1);
    return &tb->entries[idx];
}

const TraceEntry *trace_find_seq(const TraceBuffer *tb, uint64_t seq_id, uint32_t *back_index) {
    if (!tb || !tb->counter || seq_id == 0)
        return NULL;
    /* trace_append assigns consecutive sequence numbers. Subtract from the
     * newest entry, not next_seq_id, which can wrap at UINT64_MAX. */
    const TraceEntry *latest = trace_get_last(tb, 0);
    if (!latest || seq_id > latest->seq_id)
        return NULL;
    uint64_t distance = latest->seq_id - seq_id;
    if (distance >= tb->counter)
        return NULL;
    const TraceEntry *entry = trace_get_last(tb, (uint32_t)distance);
    if (!entry || entry->seq_id != seq_id)
        return NULL;
    if (back_index)
        *back_index = (uint32_t)distance;
    return entry;
}

bool trace_record_control_transfer(TraceBuffer *tb, uint64_t seq_id, DcfgEdgeId edge_id,
                                   ProvLabelId target_label) {
    if (!tb || seq_id == 0 || target_label == PROV_LABEL_ID_INVALID) {
        return false;
    }
    for (uint32_t i = 0; i < tb->counter; i++) {
        uint32_t index = (tb->head_pointer - 1U - i) & (tb->capacity - 1U);
        TraceEntry *entry = &tb->entries[index];
        if (entry->seq_id != seq_id)
            continue;
        entry->control_transfer_valid = true;
        entry->dcfg_edge_id = edge_id;
        entry->target_label = target_label;
        return true;
    }
    return false;
}

bool trace_occurrence_from_entry(const TraceEntry *entry, InsnOccurrence *out) {
    if (!entry || !out || entry->seq_id == 0) {
        return false;
    }
    memset(out, 0, sizeof(*out));
    out->seq_id = entry->seq_id;
    out->vcpu_index = entry->vcpu_index;
    out->desc_id = entry->insn_desc_id;
    out->meta_id = entry->meta_id;
    out->pc = entry->pc;
    out->code_generation = entry->code_generation;
    out->bytes_hash = entry->bytes_hash;
    out->control_transfer_valid = entry->control_transfer_valid;
    out->dcfg_edge_id = entry->dcfg_edge_id;
    out->target_label = entry->target_label;
    if (entry->insn_desc_id == INSN_DESC_ID_INVALID) {
        out->incomplete_reasons |= TRACE_OCCURRENCE_DESC_MISSING;
    }
    return true;
}

void trace_reset(TraceBuffer *tb) {
    if (!tb)
        return;
    tb->head_pointer = 0;
    tb->counter = 0;
}

bool trace_occurrence_archive_append(TraceBuffer *tb, const InsnOccurrence *occurrence) {
    if (!tb || !tb->occurrence_archive || !occurrence || occurrence->seq_id == 0 ||
        occurrence->mem_read_count > TRACE_MAX_MEM_EFFECTS ||
        occurrence->mem_write_count > TRACE_MAX_MEM_EFFECTS) {
        return false;
    }
    const size_t fixed_size = offsetof(InsnOccurrence, mem_reads);
    size_t effect_count = (size_t)occurrence->mem_read_count + (size_t)occurrence->mem_write_count;
    if (effect_count >
        (SIZE_MAX - sizeof(TraceArchiveRecordHeader) - fixed_size) / sizeof(TraceMemoryEffect)) {
        trace_occurrence_archive_note_loss(tb);
        return false;
    }
    size_t raw_size =
        sizeof(TraceArchiveRecordHeader) + fixed_size + effect_count * sizeof(TraceMemoryEffect);
    size_t record_size = 0;
    if (!trace_archive_align_size(raw_size, &record_size)) {
        trace_occurrence_archive_note_loss(tb);
        return false;
    }
    struct TraceOccurrenceArchive *archive = tb->occurrence_archive;
    g_mutex_lock(&archive->lock);
    TraceArchiveRecordHeader **index_slot = NULL;
    if (!trace_archive_index_slot(archive, occurrence->seq_id, &index_slot)) {
        trace_archive_note_loss_locked(archive);

        g_mutex_unlock(&archive->lock);

        return false;
    }

    if (*index_slot != NULL) {
        g_mutex_unlock(&archive->lock);
        return false;
    }

    TraceArchiveChunk *chunk = archive->last_chunk;

    if (!chunk || record_size > chunk->capacity - chunk->used) {
        TraceArchiveChunk *new_chunk = trace_archive_chunk_create(record_size);

        if (!new_chunk) {
            trace_archive_note_loss_locked(archive);

            g_mutex_unlock(&archive->lock);

            return false;
        }

        if (archive->last_chunk) {
            archive->last_chunk->next = new_chunk;
        } else {
            archive->first_chunk = new_chunk;
        }

        archive->last_chunk = new_chunk;

        chunk = new_chunk;
    }

    TraceArchiveRecordHeader *record =
        (TraceArchiveRecordHeader *)(void *)(chunk->data + chunk->used);

    memset(record, 0, record_size);

    record->record_size = record_size;

    uint8_t *payload = (uint8_t *)(void *)(record + 1);

    memcpy(payload, occurrence, fixed_size);

    uint8_t *effects = payload + fixed_size;

    if (occurrence->mem_read_count != 0) {
        memcpy(effects, occurrence->mem_reads,
               (size_t)occurrence->mem_read_count * sizeof(TraceMemoryEffect));
    }

    if (occurrence->mem_write_count != 0) {
        memcpy(effects + (size_t)occurrence->mem_read_count * sizeof(TraceMemoryEffect),
               occurrence->mem_writes,
               (size_t)occurrence->mem_write_count * sizeof(TraceMemoryEffect));
    }

    chunk->used += record_size;

    *index_slot = record;

    if (archive->record_count != UINT64_MAX) {
        archive->record_count++;
    }

    if (occurrence->incomplete_reasons != TRACE_OCCURRENCE_INCOMPLETE_NONE &&
        archive->incomplete_records != UINT64_MAX) {
        archive->incomplete_records++;
    }

    if (archive->record_bytes <= UINT64_MAX - record_size) {
        archive->record_bytes += record_size;
    } else {
        archive->record_bytes = UINT64_MAX;
    }

    g_mutex_unlock(&archive->lock);

    return true;
}

static bool trace_archive_record_materialize(const TraceArchiveRecordHeader *record,
                                             uint64_t expected_seq_id, InsnOccurrence *out) {
    if (!record || !out) {
        return false;
    }

    const size_t fixed_size = offsetof(InsnOccurrence, mem_reads);

    if (record->record_size < sizeof(*record) + fixed_size) {
        return false;
    }

    const uint8_t *payload = (const uint8_t *)(const void *)(record + 1);

    memset(out, 0, sizeof(*out));

    memcpy(out, payload, fixed_size);

    if (out->seq_id != expected_seq_id || out->mem_read_count > TRACE_MAX_MEM_EFFECTS ||
        out->mem_write_count > TRACE_MAX_MEM_EFFECTS) {
        memset(out, 0, sizeof(*out));

        return false;
    }

    size_t effect_count = (size_t)out->mem_read_count + (size_t)out->mem_write_count;

    if (effect_count > (SIZE_MAX - sizeof(*record) - fixed_size) / sizeof(TraceMemoryEffect)) {
        memset(out, 0, sizeof(*out));

        return false;
    }

    size_t required = sizeof(*record) + fixed_size + effect_count * sizeof(TraceMemoryEffect);

    if (required > record->record_size) {
        memset(out, 0, sizeof(*out));

        return false;
    }

    const uint8_t *effects = payload + fixed_size;

    if (out->mem_read_count != 0) {
        memcpy(out->mem_reads, effects, (size_t)out->mem_read_count * sizeof(TraceMemoryEffect));
    }

    if (out->mem_write_count != 0) {
        memcpy(out->mem_writes, effects + (size_t)out->mem_read_count * sizeof(TraceMemoryEffect),
               (size_t)out->mem_write_count * sizeof(TraceMemoryEffect));
    }

    return true;
}

bool trace_occurrence_archive_find(const TraceBuffer *tb, uint64_t seq_id, InsnOccurrence *out) {
    if (!tb || !tb->occurrence_archive || seq_id == 0 || !out) {
        return false;
    }

    struct TraceOccurrenceArchive *archive = tb->occurrence_archive;

    g_mutex_lock(&archive->lock);

    TraceArchiveRecordHeader *record = trace_archive_index_find(archive, seq_id);

    bool result = trace_archive_record_materialize(record, seq_id, out);

    g_mutex_unlock(&archive->lock);

    return result;
}

uint64_t trace_occurrence_archive_count(const TraceBuffer *tb) {
    if (!tb || !tb->occurrence_archive) {
        return 0;
    }

    struct TraceOccurrenceArchive *archive = tb->occurrence_archive;

    g_mutex_lock(&archive->lock);

    uint64_t result = archive->record_count;

    g_mutex_unlock(&archive->lock);

    return result;
}

uint64_t trace_occurrence_archive_bytes(const TraceBuffer *tb) {
    if (!tb || !tb->occurrence_archive) {
        return 0;
    }

    struct TraceOccurrenceArchive *archive = tb->occurrence_archive;

    g_mutex_lock(&archive->lock);

    uint64_t result = archive->record_bytes;

    g_mutex_unlock(&archive->lock);

    return result;
}

uint64_t trace_occurrence_archive_incomplete(const TraceBuffer *tb) {
    if (!tb || !tb->occurrence_archive) {
        return 0;
    }

    struct TraceOccurrenceArchive *archive = tb->occurrence_archive;

    g_mutex_lock(&archive->lock);

    uint64_t result = archive->incomplete_records;

    g_mutex_unlock(&archive->lock);

    return result;
}

uint64_t trace_occurrence_archive_dropped(const TraceBuffer *tb) {
    if (!tb || !tb->occurrence_archive) {
        return 0;
    }

    struct TraceOccurrenceArchive *archive = tb->occurrence_archive;

    g_mutex_lock(&archive->lock);

    uint64_t result = archive->dropped_records;

    g_mutex_unlock(&archive->lock);

    return result;
}

bool trace_occurrence_archive_is_complete(const TraceBuffer *tb) {
    if (!tb || !tb->occurrence_archive) {
        return false;
    }

    struct TraceOccurrenceArchive *archive = tb->occurrence_archive;

    g_mutex_lock(&archive->lock);

    bool result = archive->complete;

    g_mutex_unlock(&archive->lock);

    return result;
}

void trace_occurrence_archive_note_loss(TraceBuffer *tb) {
    if (!tb || !tb->occurrence_archive) {
        return;
    }

    struct TraceOccurrenceArchive *archive = tb->occurrence_archive;
    g_mutex_lock(&archive->lock);
    trace_archive_note_loss_locked(archive);
    g_mutex_unlock(&archive->lock);
}

/* Intrusive chains store ring slots, newest first. Append and eviction allocate
 * nothing; duplicate keys retain the same last-added result as linear search.
 * Access requires the same external serialization as the event ring itself. */
struct BranchEventIndex {
    uint32_t capacity;
    uint32_t links[]; /* bucket heads, next slots, previous slots */
};

#define BRANCH_INDEX_EMPTY UINT32_MAX

size_t branch_event_buffer_index_bytes(const BranchEventBuffer *buffer) {
    return buffer && buffer->index
               ? sizeof(*buffer->index) + (size_t)buffer->index->capacity * 3U * sizeof(uint32_t)
               : 0;
}

static struct BranchEventIndex *branch_index_create(uint32_t capacity) {
    size_t count = capacity;
    if (count > (SIZE_MAX - sizeof(struct BranchEventIndex)) / (3U * sizeof(uint32_t)))
        return NULL;
    size_t bytes = sizeof(struct BranchEventIndex) + count * 3U * sizeof(uint32_t);
    struct BranchEventIndex *index = malloc(bytes);
    if (!index)
        return NULL;
    index->capacity = capacity;
    memset(index->links, 0xff, bytes - sizeof(*index));
    return index;
}

static uint32_t branch_index_bucket(const BranchEventBuffer *buffer, uint64_t seq, uint32_t vcpu) {
    uint64_t h = seq ^ ((uint64_t)vcpu * UINT64_C(0x9e3779b97f4a7c15));
    h = (h ^ (h >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
    h = (h ^ (h >> 27)) * UINT64_C(0x94d049bb133111eb);
    h ^= h >> 31;
    return (uint32_t)h & (buffer->capacity - 1U);
}

static void branch_index_remove(BranchEventBuffer *buffer, uint32_t slot) {
    struct BranchEventIndex *index = buffer->index;
    const BranchEvent *event = &buffer->events[slot];
    if (!index || !event->branch_seq_id)
        return;
    uint32_t *next = index->links + buffer->capacity;
    uint32_t *prev = next + buffer->capacity;
    if (prev[slot] != BRANCH_INDEX_EMPTY)
        next[prev[slot]] = next[slot];
    else
        index->links[branch_index_bucket(buffer, event->branch_seq_id, event->vcpu_index)] =
            next[slot];
    if (next[slot] != BRANCH_INDEX_EMPTY)
        prev[next[slot]] = prev[slot];
}

static void branch_index_insert(BranchEventBuffer *buffer, uint32_t slot) {
    struct BranchEventIndex *index = buffer->index;
    const BranchEvent *event = &buffer->events[slot];
    if (!index || !event->branch_seq_id)
        return;
    uint32_t bucket = branch_index_bucket(buffer, event->branch_seq_id, event->vcpu_index);
    uint32_t *next = index->links + buffer->capacity;
    uint32_t *prev = next + buffer->capacity;
    uint32_t head = index->links[bucket];
    next[slot] = head;
    prev[slot] = BRANCH_INDEX_EMPTY;
    if (head != BRANCH_INDEX_EMPTY)
        prev[head] = slot;
    index->links[bucket] = slot;
}

BranchEventBuffer *branch_event_buffer_create(uint32_t capacity) {
    if (capacity == 0 || (capacity & (capacity - 1U)) != 0) {
        return NULL;
    }
    BranchEventBuffer *buffer = calloc(1, sizeof(*buffer));
    if (!buffer)
        return NULL;
    buffer->events = calloc(capacity, sizeof(*buffer->events));
    if (!buffer->events) {
        free(buffer);
        return NULL;
    }
    buffer->capacity = capacity;
    buffer->next_event_id = 1;
    buffer->index = branch_index_create(capacity);
    return buffer;
}

void branch_event_buffer_destroy(BranchEventBuffer *buffer) {
    if (!buffer)
        return;
    free(buffer->events);
    free(buffer->index);
    free(buffer);
}

const BranchEvent *branch_event_append(BranchEventBuffer *buffer, const BranchEvent *event) {
    if (!buffer || !event || buffer->next_event_id == 0) {
        return NULL;
    }
    uint32_t index = buffer->head_pointer & (buffer->capacity - 1U);
    /* event may point into this ring, including the slot being overwritten. */
    BranchEvent incoming = *event;
    if (buffer->counter == buffer->capacity)
        branch_index_remove(buffer, index);
    buffer->events[index] = incoming;
    buffer->events[index].event_id = buffer->next_event_id++;
    branch_index_insert(buffer, index);
    buffer->head_pointer++;
    if (buffer->counter < buffer->capacity) {
        buffer->counter++;
    }
    return &buffer->events[index];
}

const BranchEvent *branch_event_get_last(const BranchEventBuffer *buffer, uint32_t back_index) {
    if (!buffer || back_index >= buffer->counter) {
        return NULL;
    }
    uint32_t index = (buffer->head_pointer - 1U - back_index) & (buffer->capacity - 1U);
    return &buffer->events[index];
}

const BranchEvent *branch_event_find_seq(const BranchEventBuffer *buffer, uint64_t branch_seq_id,
                                         uint32_t vcpu_index) {
    if (!buffer || branch_seq_id == 0) {
        return NULL;
    }
    if (buffer->index) {
        const uint32_t *next = buffer->index->links + buffer->capacity;
        uint32_t slot =
            buffer->index->links[branch_index_bucket(buffer, branch_seq_id, vcpu_index)];
        while (slot != BRANCH_INDEX_EMPTY) {
            const BranchEvent *event = &buffer->events[slot];
            if (event->branch_seq_id == branch_seq_id && event->vcpu_index == vcpu_index)
                return event;
            slot = next[slot];
        }
        return NULL;
    }
    for (uint32_t back_index = 0; back_index < buffer->counter; back_index++) {
        const BranchEvent *event = branch_event_get_last(buffer, back_index);
        if (event && event->branch_seq_id == branch_seq_id && event->vcpu_index == vcpu_index) {
            return event;
        }
    }
    return NULL;
}

bool trace_occurrence_apply_branch_event(InsnOccurrence *occurrence, const BranchEvent *event) {
    if (!occurrence || !event || occurrence->seq_id == 0 ||
        event->branch_seq_id != occurrence->seq_id || event->vcpu_index != occurrence->vcpu_index) {
        if (occurrence) {
            occurrence->incomplete_reasons |= TRACE_OCCURRENCE_BRANCH_MISMATCH;
        }
        return false;
    }
    if ((occurrence->meta_id != META_ID_INVALID && event->meta_id != occurrence->meta_id) ||
        event->pc != occurrence->pc) {
        occurrence->incomplete_reasons |= TRACE_OCCURRENCE_BRANCH_MISMATCH;
        return false;
    }
    if (event->dcfg_edge_id != DCFG_EDGE_ID_INVALID &&
        occurrence->dcfg_edge_id != DCFG_EDGE_ID_INVALID &&
        occurrence->dcfg_edge_id != event->dcfg_edge_id) {
        occurrence->incomplete_reasons |= TRACE_OCCURRENCE_BRANCH_MISMATCH;
        return false;
    }
    occurrence->branch_event_valid = true;
    occurrence->branch_event_id = event->event_id;
    occurrence->branch_outcome = event->outcome;
    occurrence->observed_branch_target = event->observed_next_pc;
    occurrence->condition_label = event->condition_label;
    if (event->dcfg_edge_id != DCFG_EDGE_ID_INVALID) {
        occurrence->dcfg_edge_id = event->dcfg_edge_id;
    }
    return true;
}

void branch_event_buffer_reset(BranchEventBuffer *buffer) {
    if (!buffer)
        return;
    buffer->head_pointer = 0;
    buffer->counter = 0;
    if (buffer->index)
        memset(buffer->index->links, 0xff, (size_t)buffer->capacity * sizeof(uint32_t));
}
