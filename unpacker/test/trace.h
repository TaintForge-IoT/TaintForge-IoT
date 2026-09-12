#ifndef TRACE_COLLECTOR_H
#define TRACE_COLLECTOR_H

#include <stdbool.h>
#include <stdint.h>

#include "dcfg.h"
#include "dta.h"

typedef uint64_t InsnDescId;

#define INSN_DESC_ID_INVALID ((InsnDescId)0)

typedef enum {
    TRACE_ARCH_UNKNOWN = 0,
    TRACE_ARCH_X86,
    TRACE_ARCH_ARM,
    TRACE_ARCH_MIPS
} TraceArchKind;

typedef enum {
    TRACE_MODE_UNKNOWN = 0,
    TRACE_MODE_16 = 16,
    TRACE_MODE_32 = 32,
    TRACE_MODE_64 = 64
} TraceArchMode;

typedef uint8_t TraceSpecialStateId;

typedef struct {
    uint16_t reg_id;
    uint16_t bit_offset;
    uint16_t bit_width;
} TraceRegSlice;

typedef enum {
    TRACE_BRANCH_NONE = 0,
    TRACE_BRANCH_JUMP_DIRECT,
    TRACE_BRANCH_JUMP_INDIRECT,
    TRACE_BRANCH_CALL_DIRECT,
    TRACE_BRANCH_CALL_INDIRECT,
    TRACE_BRANCH_RETURN,
    TRACE_BRANCH_CONDITIONAL
} TraceBranchKind;

enum {
    TRACE_EFFECT_QUALITY_NONE = 0,
    TRACE_EFFECT_META_MISSING = 1U << 0,
    TRACE_EFFECT_NEEDS_FULL_LIFT = 1U << 1,
    TRACE_EFFECT_SLICE_DETAIL_TRUNCATED = 1U << 2
};

typedef struct {
    uint64_t register_value_uses;
    uint64_t register_address_uses;
    uint64_t register_memory_read_address_uses;
    uint64_t register_memory_write_address_uses;
    uint64_t register_control_uses;
    uint64_t register_defs;

    uint64_t special_value_uses;
    uint64_t special_address_uses;
    uint64_t special_control_uses;
    uint64_t special_defs;

    TraceRegSlice value_use_slices[MAX_INSN_REG_SLICES];
    uint8_t value_use_slice_count;
    TraceRegSlice def_slices[MAX_INSN_REG_SLICES];
    uint8_t def_slice_count;

    bool may_read_memory;
    bool may_write_memory;

    TraceBranchKind branch_kind;
    bool direct_target_valid;
    uint64_t direct_target;
    uint32_t quality_flags;
} EffectSummary;

typedef struct {
    InsnDescId desc_id;
    MetaId meta_id;

    TraceArchKind arch;
    TraceArchMode mode;

    uint64_t pc;
    uint32_t code_generation;
    uint64_t bytes_hash;
    uint8_t bytes[MAX_INSN_BYTES];
    uint8_t size;
    uint16_t native_insn_id;
    EffectSummary effects;
} InsnDesc;

#define TRACE_MAX_MEM_EFFECTS 8U

typedef enum {
    TRACE_MEM_READ = 1,
    TRACE_MEM_WRITE = 2
} TraceMemoryEffectKind;

typedef struct {
    TraceMemoryEffectKind kind;
    uint64_t address;
    uint64_t value;
    uint8_t size;
    uint8_t taint_mask;
    uint8_t effective_taint_mask;
    bool value_valid;
    bool address_tainted;
} TraceMemoryEffect;

typedef enum {
    BRANCH_OUTCOME_UNKNOWN = 0,
    BRANCH_OUTCOME_TAKEN,
    BRANCH_OUTCOME_NOT_TAKEN
} BranchOutcome;

// architecture-scoped condition encoding
typedef uint16_t TraceConditionCode;

#define TRACE_CONDITION_CODE_NONE ((TraceConditionCode)0)

enum {
    TRACE_OCCURRENCE_INCOMPLETE_NONE = 0,
    TRACE_OCCURRENCE_DESC_MISSING = 1U << 0,
    TRACE_OCCURRENCE_AUX_MISSING = 1U << 1,
    TRACE_OCCURRENCE_EXECUTION_PENDING = 1U << 2,
    TRACE_OCCURRENCE_READ_OVERFLOW = 1U << 3,
    TRACE_OCCURRENCE_WRITE_OVERFLOW = 1U << 4,
    TRACE_OCCURRENCE_RANGE_UNKNOWN = 1U << 5,
    TRACE_OCCURRENCE_VALUE_MISSING = 1U << 6,
    TRACE_OCCURRENCE_BRANCH_MISMATCH = 1U << 7
};

typedef struct {
    uint64_t seq_id;
    uint32_t vcpu_index;

    InsnDescId desc_id;
    MetaId meta_id;

    uint64_t pc;
    uint32_t code_generation;
    uint64_t bytes_hash;

    bool dynamic_effects_available;
    bool execution_complete;

    bool next_pc_valid;
    uint64_t next_pc;
    uint32_t incomplete_reasons;

    uint8_t mem_read_count;
    uint8_t mem_write_count;
    uint32_t mem_read_total;
    uint32_t mem_write_total;
    bool mem_read_range_valid;
    bool mem_write_range_valid;
    uint64_t mem_read_min_addr;
    uint64_t mem_read_max_addr;
    uint64_t mem_write_min_addr;
    uint64_t mem_write_max_addr;
    bool control_transfer_valid;
    DcfgEdgeId dcfg_edge_id;
    ProvLabelId target_label;
    bool branch_event_valid;
    uint64_t branch_event_id;
    BranchOutcome branch_outcome;
    uint64_t observed_branch_target;
    ProvLabelId condition_label;

    TraceMemoryEffect mem_reads[TRACE_MAX_MEM_EFFECTS];
    TraceMemoryEffect mem_writes[TRACE_MAX_MEM_EFFECTS];
} InsnOccurrence;

typedef struct {
    uint64_t seq_id;
    uint32_t vcpu_index;
    InsnDescId insn_desc_id;
    MetaId meta_id;
    uint64_t pc;
    uint32_t code_generation;
    uint64_t bytes_hash;
    uint8_t instr_bytes[MAX_INSN_BYTES];
    uint8_t size;
    bool control_transfer_valid;
    DcfgEdgeId dcfg_edge_id;
    ProvLabelId target_label;
} TraceEntry;

typedef struct {
    TraceEntry *entries;
    uint32_t capacity;
    uint32_t head_pointer;
    uint32_t counter;
    uint64_t next_seq_id;
    struct TraceDescriptorStore *descriptor_store;
    struct TraceOccurrenceArchive *occurrence_archive;
} TraceBuffer;

#define TRACE_SPECIAL_STATE_CAPACITY 64U

static inline uint64_t trace_special_state_bit(TraceSpecialStateId state_id) {
    return state_id < TRACE_SPECIAL_STATE_CAPACITY ? UINT64_C(1) << state_id : UINT64_C(0);
}

TraceBuffer *trace_buffer_create(uint32_t capacity);
void trace_buffer_destroy(TraceBuffer *tb);
uint64_t trace_instruction_bytes_hash(const uint8_t *bytes, uint8_t size);
bool trace_effect_summary_from_meta(const InsnMeta *meta, EffectSummary *out);
InsnDescId trace_insn_desc_intern(TraceBuffer *tb, TraceArchKind arch, TraceArchMode mode,
                                  uint64_t pc, uint32_t code_generation, const uint8_t *bytes,
                                  uint8_t size, const InsnMeta *meta);
const InsnDesc *trace_insn_desc_get(const TraceBuffer *tb, InsnDescId desc_id);
uint64_t trace_insn_desc_count(const TraceBuffer *tb);
const TraceEntry *trace_append(TraceBuffer *tb, const TraceEntry *entry);
const TraceEntry *trace_get_last(const TraceBuffer *tb, uint32_t i);
void trace_reset(TraceBuffer *tb);
const TraceEntry *trace_find_seq(const TraceBuffer *tb, uint64_t seq_id, uint32_t *back_index);
bool trace_record_control_transfer(TraceBuffer *tb, uint64_t seq_id, DcfgEdgeId edge_id,
                                   ProvLabelId target_label);

bool trace_occurrence_from_entry(const TraceEntry *entry, InsnOccurrence *out);
bool trace_occurrence_archive_append(TraceBuffer *tb, const InsnOccurrence *occurrence);
bool trace_occurrence_archive_find(const TraceBuffer *tb, uint64_t seq_id, InsnOccurrence *out);
uint64_t trace_occurrence_archive_count(const TraceBuffer *tb);
uint64_t trace_occurrence_archive_bytes(const TraceBuffer *tb);
uint64_t trace_occurrence_archive_incomplete(const TraceBuffer *tb);
uint64_t trace_occurrence_archive_dropped(const TraceBuffer *tb);
bool trace_occurrence_archive_is_complete(const TraceBuffer *tb);
void trace_occurrence_archive_note_loss(TraceBuffer *tb);

typedef struct {
    uint64_t event_id;
    uint64_t branch_seq_id;
    uint32_t vcpu_index;
    MetaId meta_id;
    uint64_t pc;
    uint64_t fallthrough;

    bool direct_target_valid;
    uint64_t direct_target;
    uint64_t observed_next_pc;
    TraceConditionCode condition_code;
    BranchOutcome outcome;
    ProvLabelId condition_label;
    DcfgEdgeId dcfg_edge_id;
} BranchEvent;

typedef struct {
    BranchEvent *events;
    uint32_t capacity;
    uint32_t head_pointer;
    uint32_t counter;
    uint64_t next_event_id;
} BranchEventBuffer;

BranchEventBuffer *branch_event_buffer_create(uint32_t capacity);
void branch_event_buffer_destroy(BranchEventBuffer *buffer);
const BranchEvent *branch_event_append(BranchEventBuffer *buffer, const BranchEvent *event);
const BranchEvent *branch_event_get_last(const BranchEventBuffer *buffer, uint32_t back_index);
const BranchEvent *branch_event_find_seq(const BranchEventBuffer *buffer, uint64_t branch_seq_id,
                                         uint32_t vcpu_index);
bool trace_occurrence_apply_branch_event(InsnOccurrence *occurrence, const BranchEvent *event);
void branch_event_buffer_reset(BranchEventBuffer *buffer);
#endif
