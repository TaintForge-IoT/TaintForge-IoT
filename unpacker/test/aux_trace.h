#ifndef AUX_TRACE_H
#define AUX_TRACE_H

#include "dta.h"
#include "trace.h"
#include <capstone/capstone.h>
#include <stdbool.h>
#include <stdint.h>

#define DSE_MAX_MEM_ACCESSES TRACE_MAX_MEM_EFFECTS
#define DSE_MAX_STRING_BYTES_PER_INSN (64U * 1024U)
#define DSE_MAX_STRING_TRACE_BYTES (64U * 1024U * 1024U)
#define DSE_MEMFD_NAME_BYTES 250U /* Linux: at most 249 bytes and NUL. */
#define DSE_SYSCALL_WRITE_BYTES (64U * 1024U)
#define DSE_SYSCALL_PATH_BYTES 4096U
#define DSE_EXECUTABLE_SNAPSHOT_BYTES (4U * 1024U * 1024U)
#define DSE_PROC_EXE_API 1
#define DSE_BRK_STATE_MAGIC UINT32_C(0x42520101)

/* Optional, value-owned /proc/self/exe contract. Source bytes/name come from
 * the explicit immutable executable provider; reply comes independently from
 * guest memory after readlink. No guest fd is interpreted as a host fd. */
typedef struct {
    uint16_t path_size, link_size;
    uint32_t content_size, reply_size;
    uint64_t source_identity;
    bool path_observed, path_valid, source_observed, source_valid;
    bool reply_observed, reply_valid, content_valid;
    uint8_t path[DSE_SYSCALL_PATH_BYTES]; /* Includes NUL. */
    uint8_t link[DSE_SYSCALL_PATH_BYTES]; /* Does not include NUL. */
    uint8_t reply[DSE_SYSCALL_PATH_BYTES];
    uint8_t *contents;
} DseSyscallFileObservation;

// aux ring for trace add info
typedef struct {
    uint64_t addr;
    uint64_t value;
    uint8_t taint;
    uint8_t effective_taint; // with address taint
    bool value_valid;
    bool address_tainted;
    uint8_t size;
} DseMemRead;

typedef struct {
    uint64_t addr;
    uint64_t value;
    uint8_t size;
    bool value_valid;
    bool address_tainted;
} DseMemWrite;

typedef enum {
    DSE_STRING_NONE = 0,
    DSE_STRING_MOVS,
    DSE_STRING_STOS
} DseStringKind;

typedef struct {
    DseStringKind kind;
    bool active;
    bool exact;
    bool overflow;
    bool pattern_mismatch;
    bool has_rep_prefix;
    uint8_t element_size;
    int8_t direction;
    uint32_t expected_iterations;
    uint32_t read_events;
    uint32_t write_events;
    uint32_t bytes_captured;
    uint32_t capacity;
    uint64_t source_first;
    uint64_t destination_first;
    uint8_t *values;
    uint8_t *value_taint;
    /* Actual QEMU store values; independent of source/accumulator predictions.
     * Optional for legacy consumers, required by complete REP IR replay. */
    uint8_t *write_values;
    uint32_t write_bytes_captured, write_capacity;
    bool write_values_incomplete;
} DseStringSummary;

/* Optional source history; not embedded into every concrete aux record.
 * Raw read labels are separate from IR address dependencies. */
typedef struct {
    uint64_t seq_id, registry_instance;
    ProvLabelId reg_source_labels[REG_COUNT][MAX_REG_BYTES];
    uint8_t reg_source_valid[REG_COUNT];
    ProvLabelId flag_source_labels[DTA_FLAG_SLOT_COUNT];
    uint8_t flag_source_valid;
    ProvLabelId read_labels[DSE_MAX_MEM_ACCESSES][MAX_REG_BYTES];
    uint8_t read_valid[DSE_MAX_MEM_ACCESSES];
} DseSourceObservation;

/* An entry/return pair belongs to one exact dynamic instruction. The aux ring
 * and ReplayInput own separate copies; a missing pair never implies no effect. */
typedef struct {
    uint64_t seq_id, pc, bytes_hash, code_generation, descriptor_id;
    uint32_t vcpu_index;
    uint32_t number, args[6], result;
    bool returned, invalid;
    /* Independent next-instruction snapshot, owned with the entry/return pair.
     * The return callback alone does not certify the architectural post-state. */
    uint32_t post_regs[8], post_valid_mask;
    bool post_observed;
    uint32_t post_eflags;
    bool post_eflags_valid;
    /* Global syscall-entry order, including entries whose aux was lost.
     * Sealed at the next instruction; overlapping calls cannot certify it. */
    uint64_t boundary_id;
    bool boundary_ordered;
    uint16_t name_size;
    bool name_observed;
    uint8_t name[DSE_MEMFD_NAME_BYTES];
    uint32_t mmap_args[6]; /* old_mmap: addr, len, prot, flags, fd, byte offset */
    bool mmap_args_observed, mmap_args_valid;
    uint32_t write_size;
    bool write_observed, write_valid;
    /* Entry-time snapshot, allocated only for a bounded write. Deep copies
     * and resource accounting include its bytes as well as the header. */
    uint8_t *write_values;
    DseSyscallFileObservation *file;
    /* Value-owned tf_brk_state_v1 snapshots, read at syscall entry and at the
     * next instruction. No heap state is inferred from the return alone. */
    uint32_t brk_initial, brk_before, brk_after;
    bool brk_entry_valid, brk_post_valid;
} DseSyscallObservation;

#define DSE_TLS_SEGMENTS 2U /* FS, GS */

/* Value-owned provenance for DF on the observed prefix. A completed, ordinary
 * CLD/STD creates it; every intervening instruction must preserve DF and have
 * a verified flag observation. This is not a proof of the prefix's control
 * conditions, and importing it must keep that boundary incomplete. */
typedef struct {
    uint64_t writer_seq, writer_pc, writer_bytes_hash;
    InsnDescId writer_descriptor;
    uint64_t boundary_seq;
    uint32_t writer_generation, vcpu_index;
    uint32_t syscall_steps;
    uint8_t value;
    bool valid;
} DseDirectionFact;

/* tf_es_state_v1 observes the active hidden cache, in eight little-endian words.
 * Entry preservation is a separate fact, not implied by equal addresses. */
typedef struct {
    uint32_t selector, base, limit, access, mode, cs_selector;
    bool valid;
    bool entry_preserved;
} DseEsObservation;

typedef struct {
    bool valid;
    bool execution_complete;
    uint64_t seq_id;
    MetaId meta_id;
    uint64_t pc;
    uint64_t reg_vals[REG_COUNT];
    uint8_t reg_taint[REG_COUNT];
    /* Borrowed from the live ring, owned in ReplayInput. Always use the checked
   * accessor: the source history may wrap before the concrete aux ring. */
    DseSourceObservation *sources;
    bool source_metadata_lost;
    uint32_t reg_value_valid_mask;
    /* True only for a complete read from a verified observation provider. */
    bool eflags_valid;
    uint32_t eflags_before;
    DseDirectionFact df_before;
    DseEsObservation es_before;
    uint32_t tls_base[DSE_TLS_SEGMENTS];
    uint16_t tls_selector[DSE_TLS_SEGMENTS];
    uint8_t tls_valid_mask;
    DseSyscallObservation *syscall;
    bool syscall_metadata_lost;
    bool next_pc_valid;
    uint64_t next_pc;
    bool has_mem_read;
    uint64_t mem_read_addr;
    uint64_t mem_read_val;
    bool mem_read_value_valid;
    uint8_t mem_read_taint;
    uint8_t mem_read_effective_taint;
    bool mem_read_address_tainted;
    bool has_mem_write;
    uint64_t mem_write_addr;
    uint8_t mem_write_size;
    uint8_t mem_read_count;
    bool mem_read_overflow;
    uint32_t mem_read_total;
    bool mem_read_range_valid;
    bool mem_read_range_unknown;
    uint64_t mem_read_min_addr;
    uint64_t mem_read_max_addr;
    DseMemRead mem_reads[DSE_MAX_MEM_ACCESSES];
    uint8_t mem_write_count;
    bool mem_write_overflow;
    uint32_t mem_write_total;
    bool mem_write_range_valid;
    bool mem_write_range_unknown;
    uint64_t mem_write_min_addr;
    uint64_t mem_write_max_addr;
    DseMemWrite mem_writes[DSE_MAX_MEM_ACCESSES];
    DseStringSummary string_summary;
} InsnAux;

typedef struct {
    InsnAux *entries;
    uint32_t capacity;
    uint64_t dynamic_bytes;
    uint64_t max_dynamic_bytes;
    DseSourceObservation *source_history;
    uint32_t source_capacity;
    size_t max_source_bytes;
    uint64_t syscall_boundary_id;
    bool syscall_order_lost;
} DseAuxRing;

/* Clear both validity and payload when the provider is unverified or the
 * read failed. Applies equally to legacy DSE, REP summaries and IR replay. */
void dse_aux_set_eflags(InsnAux *aux, uint32_t value, bool read_ok, bool provider_verified);
/* Call before recording current and after finalizing previous. Missing/stale
 * records, another vCPU, unknown effects or changed observations clear the fact.
 * No live pointer to the writer survives in current or in ReplayInput. */
void dse_aux_carry_x86_df(InsnAux *current, const TraceEntry *entry,
                         const TraceBuffer *trace, const InsnAux *previous);
void dse_aux_set_es(InsnAux *aux, const uint32_t words[8], bool read_ok, bool provider_verified);
void dse_aux_carry_x86_es(InsnAux *current, const TraceEntry *entry,
                         const TraceBuffer *trace, const InsnAux *previous);
const char *dse_aux_es_contract_issue(const InsnAux *aux);
/* Only complete reads of a non-null user selector and its active segment-cache
 * base qualify. This does not certify the segment's limit/type. */
void dse_aux_set_tls(InsnAux *aux, unsigned segment, uint32_t base, uint32_t selector,
                     bool read_ok);
bool dse_aux_syscall_enter(DseAuxRing *ring, InsnAux *aux, const TraceEntry *entry, uint32_t number,
                           const uint32_t args[6]);
bool dse_aux_syscall_return(InsnAux *aux, uint64_t seq_id, uint32_t vcpu_index, uint32_t number,
                            uint32_t result);
/* NULL means only the i386 ftruncate return/register contract is checked.
 * File contents, length, aliases and mappings are NOT certified by this API. */
const char *dse_aux_ftruncate_issue(const TraceEntry *entry, const InsnAux *aux);
/* Successful, page-aligned Linux i386 mprotect, ordinary R/RW/RX/RWX/NONE
 * rights only. Fixed observed addresses and arguments; no byte-content effect. */
const char *dse_aux_mprotect_issue(const TraceEntry *entry, const InsnAux *aux);
/* Successful non-hugetlb memfd with explicit MFD_EXEC and optional CLOEXEC /
 * ALLOW_SEALING only. Default execution/sealing policy is not guessed. */
const char *dse_aux_memfd_issue(const TraceEntry *entry, const InsnAux *aux);
bool dse_aux_syscall_name(InsnAux *aux, const uint8_t *name, size_t size);
bool dse_aux_syscall_mmap_args(InsnAux *aux, const uint8_t *bytes, size_t size);
/* First non-fixed file mapping, ordinary rights, MAP_SHARED or MAP_PRIVATE.
 * File identity/content and overlap must additionally be checked by DSE. */
const char *dse_aux_old_mmap_issue(const TraceEntry *entry, const InsnAux *aux);
/* Common IR mapping contract; leaves the narrower legacy validator unchanged.
 * Normalize old_mmap's memory block or mmap2's six registers to byte offsets. */
const char *dse_aux_ir_mmap_issue(const TraceEntry *entry, const InsnAux *aux,
                                  uint32_t normalized[6]);
const char *dse_aux_msync_issue(const TraceEntry *entry, const InsnAux *aux);
void dse_aux_syscall_brk_state(InsnAux *aux, const uint32_t words[4], bool valid, bool post);
const char *dse_aux_brk_issue(const TraceEntry *entry, const InsnAux *aux);
bool dse_aux_syscall_write(DseAuxRing *ring, InsnAux *aux, const uint8_t *bytes, size_t size);
const char *dse_aux_write_issue(const TraceEntry *entry, const InsnAux *aux);
const char *dse_aux_close_issue(const TraceEntry *entry, const InsnAux *aux);
bool dse_aux_syscall_path(DseAuxRing *ring, InsnAux *aux, const uint8_t *path, size_t size);
bool dse_aux_syscall_executable(DseAuxRing *ring, InsnAux *aux, uint64_t identity,
                                 const uint8_t *link, size_t link_size,
                                 const uint8_t *contents, size_t content_size);
bool dse_aux_syscall_readlink_reply(InsnAux *aux, const uint8_t *bytes, size_t size);
const char *dse_aux_open_executable_issue(const TraceEntry *entry, const InsnAux *aux);
const char *dse_aux_readlink_executable_issue(const TraceEntry *entry, const InsnAux *aux);
size_t dse_aux_syscall_owned_bytes(const DseSyscallObservation *s);
DseSyscallObservation *dse_aux_syscall_copy(const DseSyscallObservation *s, size_t limit);
void dse_aux_syscall_free(DseSyscallObservation *s);
void dse_aux_syscall_seal_order(const DseAuxRing *ring, InsnAux *aux);
void dse_aux_syscall_post_flags(InsnAux *aux, uint32_t eflags, bool verified_read);

DseAuxRing *dse_aux_create(uint32_t capacity);
/* Snapshot labels before applying this instruction's DTA transfer. Does not
 * certify concrete register/flag validity; those have independent masks. */
void dse_aux_capture_sources(DseSourceObservation *out, const DtaVcpuState *state,
                             uint8_t register_bytes);
/* Configure before first source record. Default: 8 MiB, allocated lazily.
 * Zero disables this optional history. Old concrete aux records are retained. */
bool dse_aux_set_source_limit(DseAuxRing *ring, size_t bytes);
size_t dse_aux_source_bytes(const DseAuxRing *ring);
const DseSourceObservation *dse_aux_sources(const InsnAux *aux);
DseSourceObservation *dse_aux_sources_mut(InsnAux *aux);
bool dse_aux_record_sources(DseAuxRing *ring, InsnAux *aux, const DseSourceObservation *source);
void dse_aux_destroy(DseAuxRing *r);
InsnAux *dse_aux_record(DseAuxRing *r, const TraceBuffer *tb, const TraceEntry *entry,
                        const InsnAux *aux);
/* Release a slot when its instruction is replaced without a concrete aux.
 * The new entry must belong to this trace ring. Other slots/source history
 * are preserved; the discarded slot is invalid and owns no dynamic bytes. */
bool dse_aux_discard(DseAuxRing *ring, const TraceBuffer *trace, const TraceEntry *entry);
// support for get_slice
void dse_aux_prepare_string(InsnAux *aux, const InsnMeta *meta);
bool dse_aux_capture_string_read(DseAuxRing *ring, InsnAux *aux, uint64_t address, uint64_t value,
                                 bool value_valid, uint8_t value_taint, uint32_t size);
void dse_aux_capture_string_write(InsnAux *aux, uint64_t address, uint32_t size);
void dse_aux_capture_string_write_value(DseAuxRing *ring, InsnAux *aux, uint64_t address,
                                        uint32_t size, uint64_t value, bool value_valid);
void dse_aux_finalize(InsnAux *aux, uint64_t next_pc, const uint64_t post_reg_vals[REG_COUNT],
                      uint32_t post_reg_value_valid_mask);
bool dse_aux_has_exact_movs(const InsnAux *aux);
bool dse_aux_has_exact_stos(const InsnAux *aux);
const InsnAux *dse_aux_for(const DseAuxRing *r, const TraceBuffer *tb, const TraceEntry *e);
bool dse_aux_materialize_occurrence(const DseAuxRing *ring, const TraceBuffer *trace,
                                    const TraceEntry *entry, InsnOccurrence *out);
bool dse_aux_archive_occurrence(const DseAuxRing *ring, TraceBuffer *trace,
                                const BranchEventBuffer *branch_events, uint64_t seq_id);
#endif
