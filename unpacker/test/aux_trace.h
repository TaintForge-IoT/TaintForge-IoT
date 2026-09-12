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
} DseAuxRing;

/* Clear both validity and payload when the provider is unverified or the
 * read failed. Applies equally to legacy DSE, REP summaries and IR replay. */
void dse_aux_set_eflags(InsnAux *aux, uint32_t value, bool read_ok, bool provider_verified);

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
// support for get_slice
void dse_aux_prepare_string(InsnAux *aux, const InsnMeta *meta);
bool dse_aux_capture_string_read(DseAuxRing *ring, InsnAux *aux, uint64_t address, uint64_t value,
                                 bool value_valid, uint8_t value_taint, uint32_t size);
void dse_aux_capture_string_write(InsnAux *aux, uint64_t address, uint32_t size);
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
