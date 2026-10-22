#ifndef DTA_SHADOW_H
#define DTA_SHADOW_H

#include <capstone/capstone.h>
#include <glib.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "provenance.h"

#define MAX_REG_BYTES 8
#define MAX_INSN_REG_SLICES 8
#define MAX_INSN_BYTES 15U
#define DTA_SHADOW_PAGE_SIZE 4096U
#define DTA_CMLB_BLOCK_SIZE 512U
#define DTA_CMLB_ENTRY_COUNT 1024U

typedef uint64_t MetaId;
#define META_ID_INVALID ((MetaId)0)

typedef struct ShadowMemory ShadowMemory;

typedef enum {
    DTA_REG_RAX = 0,
    DTA_REG_RCX,
    DTA_REG_RDX,
    DTA_REG_RBX,
    DTA_REG_RSP,
    DTA_REG_RBP,
    DTA_REG_RSI,
    DTA_REG_RDI,
    DTA_REG_R8,
    DTA_REG_R9,
    DTA_REG_R10,
    DTA_REG_R11,
    DTA_REG_R12,
    DTA_REG_R13,
    DTA_REG_R14,
    DTA_REG_R15,
    REG_COUNT,
    REG_INVALID = -1
} RegId;

typedef struct {
    RegId reg_id;
    uint8_t byte_offset;
    uint8_t width;
    uint8_t mask;
} RegSlice;

typedef enum {
    DTA_FAMILY_UNSUPPORTED = 0,
    DTA_FAMILY_DATA_MOVEMENT,
    DTA_FAMILY_LOGICAL,
    DTA_FAMILY_ARITHMETIC,
    DTA_FAMILY_COMPARE,
    DTA_FAMILY_SHIFT_ROTATE,
    DTA_FAMILY_STACK,
    DTA_FAMILY_STRING
} DtaInsnFamily;

typedef enum {
    DTA_TRANSFER_NOT_APPLICABLE = 0,
    DTA_TRANSFER_EXACT,
    DTA_TRANSFER_CONSERVATIVE,
    DTA_TRANSFER_INCOMPLETE
} DtaTransferResult;

enum {
    X86_FLAG_CF = 1U << 0,
    X86_FLAG_PF = 1U << 1,
    X86_FLAG_AF = 1U << 2,
    X86_FLAG_ZF = 1U << 3,
    X86_FLAG_SF = 1U << 4,
    X86_FLAG_OF = 1U << 5,
    X86_FLAG_TRACKED =
        X86_FLAG_CF | X86_FLAG_PF | X86_FLAG_AF | X86_FLAG_ZF | X86_FLAG_SF | X86_FLAG_OF
};

typedef enum {
    X86_SPECIAL_STATE_CF = 0,
    X86_SPECIAL_STATE_PF = 1,
    X86_SPECIAL_STATE_AF = 2,
    X86_SPECIAL_STATE_ZF = 3,
    X86_SPECIAL_STATE_SF = 4,
    X86_SPECIAL_STATE_OF = 5,
    X86_SPECIAL_STATE_DF = 6,
    X86_SPECIAL_STATE_ES = 7,
    X86_SPECIAL_STATE_COUNT = 8
} X86SpecialStateId;

typedef enum {
    X86_CC_NONE = 0,
    X86_CC_O,
    X86_CC_NO,
    X86_CC_B,
    X86_CC_AE,
    X86_CC_E,
    X86_CC_NE,
    X86_CC_BE,
    X86_CC_A,
    X86_CC_S,
    X86_CC_NS,
    X86_CC_P,
    X86_CC_NP,
    X86_CC_L,
    X86_CC_GE,
    X86_CC_LE,
    X86_CC_G
} X86ConditionCode;

typedef struct {
    MetaId meta_id;
    uint64_t pc;
    uint8_t instr_bytes[MAX_INSN_BYTES];
    uint8_t size;
    bool has_mem_read;
    bool has_mem_write;
    uint32_t regs_read_mask;
    uint32_t regs_written_mask;
    bool is_indirect_branch;
    uint16_t insn_id;
    RegId branch_target_reg;
    RegSlice branch_target_slice;
    DtaInsnFamily family;
    uint32_t mem_addr_reg_mask;
    uint32_t mem_read_addr_reg_mask;
    uint32_t mem_write_addr_reg_mask;

    RegSlice reg_reads[MAX_INSN_REG_SLICES];
    uint8_t reg_read_count;
    RegSlice reg_writes[MAX_INSN_REG_SLICES];
    uint8_t reg_write_count;
    bool reg_slice_detail_truncated;

    bool has_imm_operand;
    bool is_self_zeroing;

    /* Decode once for occurrence-aware dependencies; no disassembly in slice. */
    bool shift_count_valid;
    bool shift_count_is_immediate;
    uint8_t shift_operand_width;
    uint8_t shift_count_imm;
    RegSlice shift_count_reg;

    uint8_t flags_read_mask;
    uint8_t flags_write_mask;
    bool writes_df;
    bool writes_es;
    X86ConditionCode condition_code;
    bool is_conditional_branch;
    bool direct_target_valid;
    uint64_t direct_target;
    bool has_rep_prefix;
    uint8_t string_element_size;
} InsnMeta;

/* Narrow DSE contract; other SCAS widths/prefixes keep opaque effects. */
static inline bool insn_meta_is_plain_scasd(const InsnMeta *meta) {
    return meta && meta->insn_id == X86_INS_SCASD && meta->size == 1 &&
           meta->instr_bytes[0] == 0xaf;
}

ShadowMemory *shadow_create(uint8_t guest_bits);
ShadowMemory *shadow_create_with_registry(uint8_t guest_bits, ProvRegistry *registry);
void shadow_destroy(ShadowMemory *sm);
ProvRegistry *shadow_registry(ShadowMemory *sm);

/* Optional proof cache, initially disabled in the standalone API. All methods
 * use the ShadowMemory mutex. Registry must outlive its ShadowMemory. Cache
 * allocation failure leaves the ordinary path usable and returns false. */
bool shadow_set_cmlb_enabled(ShadowMemory *sm, bool enabled);
void shadow_cmlb_flush(ShadowMemory *sm);
/* Lost semantic updates poison all subsequent reads to PROV_LABEL_UNKNOWN.
 * Only destroying/recreating and reseeding the owner restores this contract;
 * cache flush, clean stores and stats reset cannot restore it. */
void shadow_mark_incomplete(ShadowMemory *sm);
bool shadow_knowledge_valid(ShadowMemory *sm);

typedef struct {
    bool enabled, cmlb_enabled, knowledge_valid;
    size_t page_count, page_bytes, cmlb_bytes;
    uint64_t read_calls, read_bytes, write_calls, write_bytes;
    uint64_t hash_lookups, hash_probes;
    uint64_t cmlb_probes, cmlb_hits, cmlb_misses, cmlb_full_hits;
    uint64_t cmlb_fills, cmlb_invalidations, cmlb_collisions, cmlb_flushes;
    uint64_t clean_store_skips, semantic_failures, cache_alloc_failures;
} ShadowStats;

/* Counters are opt-in; snapshots also report current health and allocation. */
void shadow_set_stats_enabled(ShadowMemory *sm, bool enabled);
bool shadow_get_stats(ShadowMemory *sm, ShadowStats *out);
void shadow_reset_stats(ShadowMemory *sm);
#ifdef TF_DTA_TESTING
/* Per-owner deterministic failures for page/table/cache allocations. -1 = off.
 * Neither these hooks nor their fields exist in a production build. */
bool shadow_test_allocation_budget(ShadowMemory *sm, int64_t successes);
void shadow_test_cmlb_generation(ShadowMemory *sm, uint64_t generation);
#endif
// for now, saved as safe API
void shadow_taint_byte(ShadowMemory *sm, uint64_t addr, uint64_t ip);
bool shadow_taint_range(ShadowMemory *sm, uint64_t addr, uint64_t size, uint64_t ip);
void shadow_untaint_byte(ShadowMemory *sm, uint64_t addr);
void shadow_untaint_range(ShadowMemory *sm, uint64_t addr, uint64_t size);
bool shadow_is_tainted(ShadowMemory *sm, uint64_t addr);
bool shadow_page_has_taint(ShadowMemory *sm, uint64_t addr);

ProvLabelId shadow_load_label(ShadowMemory *sm, uint64_t addr);
bool shadow_load_labels(ShadowMemory *sm, uint64_t addr, ProvLabelId *out_labels, uint32_t count);
bool shadow_store_label(ShadowMemory *sm, uint64_t addr, ProvLabelId label_id);
bool shadow_store_labels(ShadowMemory *sm, uint64_t addr, const ProvLabelId *labels,
                         uint32_t count);
bool shadow_fill_label(ShadowMemory *sm, uint64_t addr, uint64_t size, ProvLabelId label_id);

int x86_reg_to_rid(unsigned cs_reg);

RegSlice reg_slice_invalid(void);
RegSlice reg_slice_from_x86(unsigned cs_reg, uint8_t size_bytes);
bool reg_slice_is_valid(RegSlice slice);
bool reg_slice_equal(RegSlice left, RegSlice right);

RegSlice meta_first_reg_read(const InsnMeta *meta);
RegSlice meta_first_reg_write(const InsnMeta *meta);

typedef struct {
    ProvRegistry *registry;
    ProvLabelId bytes[REG_COUNT][MAX_REG_BYTES];
    uint64_t src_ip[REG_COUNT];
} RegShadow;

bool reg_shadow_init(RegShadow *rs, ProvRegistry *registry);
void reg_shadow_reset(RegShadow *rs);

void reg_taint_set(RegShadow *rs, RegId rid, uint8_t byte_mask, uint64_t ip);
void reg_taint_clear(RegShadow *rs, RegId rid, uint8_t byte_mask);
bool reg_is_tainted(const RegShadow *rs, RegId rid, uint8_t byte_mask);
void reg_slice_taint_set(RegShadow *rs, RegSlice slice, uint64_t ip);
void reg_slice_taint_clear(RegShadow *rs, RegSlice slice);
bool reg_slice_is_tainted(const RegShadow *rs, RegSlice slice);

typedef enum {
    DTA_FLAG_SLOT_CF = 0,
    DTA_FLAG_SLOT_PF,
    DTA_FLAG_SLOT_AF,
    DTA_FLAG_SLOT_ZF,
    DTA_FLAG_SLOT_SF,
    DTA_FLAG_SLOT_OF,
    DTA_FLAG_SLOT_COUNT
} DtaFlagSlot;

typedef struct {
    ProvLabelId labels[DTA_FLAG_SLOT_COUNT];
    uint8_t valid_mask;
} DtaFlagShadow;

typedef struct {
    bool active;
    uint64_t seq_id;
    MetaId meta_id;
    uint64_t pc;
    uint64_t fallthrough;
    bool direct_target_valid;
    uint64_t direct_target;
    X86ConditionCode condition_code;
    ProvLabelId condition_label;
} DtaPendingBranch;

typedef struct {
    uint32_t vcpu_index;
    ProvRegistry *registry;
    RegShadow regs;
    DtaFlagShadow flags;
    DtaPendingBranch pending_branch;
} DtaVcpuState;

bool dta_vcpu_state_init(DtaVcpuState *state, uint32_t vcpu_index, ProvRegistry *registry);
void dta_vcpu_state_reset(DtaVcpuState *state);

ProvLabelId dta_flag_get_label(const DtaVcpuState *state, DtaFlagSlot flag);
bool dta_flag_set_label(DtaVcpuState *state, DtaFlagSlot flag, ProvLabelId label_id);
bool dta_flag_set_mask(DtaVcpuState *state, uint8_t flag_mask, ProvLabelId label_id);
ProvLabelId dta_flag_join_mask(const DtaVcpuState *state, uint8_t flag_mask);
bool dta_flag_mask_is_tainted(const DtaVcpuState *state, uint8_t flag_mask);
DtaTransferResult dta_apply_flag_transfer(DtaVcpuState *state, const RegShadow *pre_regs,
                                          const InsnMeta *meta, const ProvLabelId *memory_labels,
                                          uint8_t memory_label_count);

void dta_pending_branch_clear(DtaVcpuState *state);
bool dta_pending_branch_begin(DtaVcpuState *state, uint64_t seq_id, MetaId meta_id, uint64_t pc,
                              uint64_t fallthrough, bool direct_target_valid,
                              uint64_t direct_target, X86ConditionCode condition_code,
                              ProvLabelId condition_label);

ProvLabelId reg_label_get(const RegShadow *rs, RegId rid, uint8_t byte_index);
bool reg_label_set(RegShadow *rs, RegId rid, uint8_t byte_mask, ProvLabelId label_id, uint64_t ip);
// Slice writes implement x86, AL/AH/AX preserve untouched bytes
bool reg_slice_set_label(RegShadow *rs, RegSlice slice, ProvLabelId label_id, uint64_t ip);
bool reg_slice_load_labels(const RegShadow *rs, RegSlice slice, ProvLabelId *out_labels);
bool reg_slice_store_labels(RegShadow *rs, RegSlice slice, const ProvLabelId *labels, uint8_t count,
                            uint64_t ip);

void propagate_reg2reg(RegShadow *rs, RegSlice dst, RegSlice src, uint16_t insn_id);
void propagate_mem2reg(RegShadow *rs, RegSlice dst, uint8_t mem_taint_mask, uint8_t mem_width,
                       uint16_t insn_id, bool overwrite);
void propagate_mem_labels2reg(RegShadow *rs, RegSlice dst, const ProvLabelId *mem_labels,
                              uint8_t mem_width, uint16_t insn_id, bool overwrite);
void reg_propagate_clear(RegShadow *rs, RegId dst);

DtaTransferResult dta_apply_reg_transfer(RegShadow *rs, const InsnMeta *meta);
DtaTransferResult dta_compute_mem_write_taint(const RegShadow *pre_regs, const InsnMeta *meta,
                                              uint8_t old_mem_taint, bool source_mem_valid,
                                              uint8_t source_mem_taint, uint8_t width,
                                              uint8_t *result_taint);
DtaTransferResult dta_apply_mem_read_transfer(RegShadow *rs, const RegShadow *pre_regs,
                                              const InsnMeta *meta, uint8_t mem_taint_mask,
                                              uint8_t mem_width);
uint8_t dta_effective_mem_read_taint(const RegShadow *pre_regs, const InsnMeta *meta,
                                     uint8_t mem_taint_mask, uint8_t mem_width);
DtaTransferResult dta_apply_mem_read_labels(RegShadow *rs, const RegShadow *pre_regs,
                                            const InsnMeta *meta, const ProvLabelId *mem_labels,
                                            uint8_t mem_width);
DtaTransferResult dta_compute_mem_write_labels(const RegShadow *pre_regs, const InsnMeta *meta,
                                               const ProvLabelId *old_mem_labels,
                                               bool source_mem_valid,
                                               const ProvLabelId *source_mem_labels, uint8_t width,
                                               ProvLabelId *result_labels);
bool dta_effective_mem_read_labels(const RegShadow *pre_regs, const InsnMeta *meta,
                                   const ProvLabelId *mem_labels, uint8_t mem_width,
                                   ProvLabelId *out_labels);

bool dta_address_mask_is_tainted(const RegShadow *pre_regs, uint32_t address_reg_mask);

void meta_init(void);
void meta_free(void);
InsnMeta *meta_decode(const uint8_t *bytes, size_t size, uint64_t pc, csh handle);
const InsnMeta *meta_store(uint64_t pc, InsnMeta *m);
const InsnMeta *meta_lookup(uint64_t pc);
const InsnMeta *meta_lookup_id(MetaId meta_id);
#endif
