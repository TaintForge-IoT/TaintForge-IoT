#ifndef DSE_H
#define DSE_H

#include <stdint.h>
#include <stdbool.h>
#include <z3.h>
#include <capstone/capstone.h>
#include "dta.h"
#include "trace.h"
#include "aux_trace.h"
#include "replay_input.h"

#define MAX_SLICE 512U
#define DSE_MAX_REPLAY_BYTES (64U * 1024U * 1024U)
#define DSE_MAX_EXPR_NODES 50000U
#define DSE_MAX_Z3_CACHE_NODES 50000U
#define DSE_MAX_PATH_CONSTRAINTS 128U
#define DSE_MAX_ROOT_LINEAGE 128U
#define DSE_MAX_ROOT_SCAN_NODES 4096U
#define DSE_MAX_RELEVANCE_ITERATIONS 64U
#define DSE_MAX_CONTROL_SCAN 4096U

typedef enum {
    DSE_SOLVER_NOT_RUN = 0,
    DSE_SOLVER_SAT,
    DSE_SOLVER_UNSAT,
    DSE_SOLVER_UNKNOWN
} DseSolverStatus;

typedef enum {
    DSE_EVIDENCE_NONE = 0,
    DSE_EVIDENCE_REPLAY_OK,
    DSE_EVIDENCE_SAT_NONUNIQUE,
    DSE_EVIDENCE_UNIQUE_ON_SLICE
} DseEvidence;

typedef enum {
    DSE_VERDICT_UNKNOWN = 0,
    DSE_VERDICT_CONFIRMED,
    DSE_VERDICT_REFUTED
} DseVerdict;

typedef enum {
    DSE_REASON_NONE = 0,
    DSE_REASON_INVALID_INPUT,
    DSE_REASON_NO_SLICE,
    DSE_REASON_TRIGGER_MISSING,
    DSE_REASON_SLICE_TRUNCATED,
    DSE_REASON_META_MISSING,
    DSE_REASON_AUX_MISSING,
    DSE_REASON_UNSUPPORTED_INSN,
    DSE_REASON_UNRESOLVED_DEPENDENCY,
    DSE_REASON_SYMBOLIC_ADDRESS,
    DSE_REASON_MEM_ACCESS_UNMODELED,
    DSE_REASON_TARGET_UNAVAILABLE,
    DSE_REASON_CONTEXT_INIT_FAILED,
    DSE_REASON_SOLVER_UNKNOWN,
    DSE_REASON_NONUNIQUE_TARGET,
    DSE_REASON_CONCRETE_REPLAY,
    DSE_REASON_REPLAY_MISMATCH,
    DSE_REASON_MODEL_INCOMPLETE,
    DSE_REASON_PATH_MODEL_INCOMPLETE,
    DSE_REASON_RESOURCE_LIMIT,
    DSE_REASON_DISABLED
} DseVerifyReason;

typedef enum {
    DSE_REPLAY_SITE_ROOT,
    DSE_REPLAY_SITE_ADDRESS_READ,
    DSE_REPLAY_SITE_ADDRESS_WRITE,
    DSE_REPLAY_SITE_BRANCH,
    DSE_REPLAY_SITE_REGISTER,
    DSE_REPLAY_SITE_MEMORY_READ,
    DSE_REPLAY_SITE_MEMORY_WRITE,
    DSE_REPLAY_SITE_TARGET,
    DSE_REPLAY_SITE_FLAG
} DseReplaySite;

typedef struct {
    bool present;
    bool root_rebind;
    bool origin_valid;
    TraceEntry origin;
    DseReplaySite site;
    uint64_t location; /* Register ID, memory address, root source or target, according to site. */
    uint32_t byte_index;
    uint32_t variable_id;
    uint32_t width;
    uint64_t expected; /* Current observation, masked to width. */
    uint64_t actual;   /* Replayed value, or the previous binding for root_rebind. */
} DseReplayDiagnostic;

enum {
    DSE_CONTROL_PARTIAL_CFG = 1U << 0,
    DSE_CONTROL_OPEN_BOUNDARY = 1U << 1,
    DSE_CONTROL_EVENT_MISSING = 1U << 2,
    DSE_CONTROL_EVENT_CONFLICT = 1U << 3,
    DSE_CONTROL_SCAN_LIMIT = 1U << 4,
    DSE_CONTROL_SLICE_LIMIT = 1U << 5,
    DSE_CONTROL_ORDER_CONFLICT = 1U << 6,
    DSE_CONTROL_METADATA_MISSING = 1U << 7
};

typedef enum {
    DSE_CFG_STOP_NONE = 0,
    DSE_CFG_STOP_TRACE_START,
    DSE_CFG_STOP_TRACE_BOUNDARY,
    DSE_CFG_STOP_SCAN_WINDOW,
    DSE_CFG_STOP_SCAN_BUDGET,
    DSE_CFG_STOP_TRACE_MISSING,
    DSE_CFG_STOP_SEQUENCE_GAP,
    DSE_CFG_STOP_VCPU_CHANGE,
    DSE_CFG_STOP_METADATA_MISSING,
    DSE_CFG_STOP_CODE_IDENTITY,
    DSE_CFG_STOP_UNSUPPORTED_MODE,
    DSE_CFG_STOP_AUX_MISSING,
    DSE_CFG_STOP_EXEC_INCOMPLETE,
    DSE_CFG_STOP_NEXT_PC_MISSING,
    DSE_CFG_STOP_NEXT_PC_MISMATCH,
    DSE_CFG_STOP_MEMORY_READ,
    DSE_CFG_STOP_MEMORY_WRITE,
    DSE_CFG_STOP_MEMORY_RMW,
    DSE_CFG_STOP_OPAQUE,
    DSE_CFG_STOP_NODE_BUDGET,
    DSE_CFG_STOP_RETURN,
    DSE_CFG_STOP_CALL,
    DSE_CFG_STOP_INDIRECT,
    DSE_CFG_STOP_COUNT
} DseCfgStopReason;

typedef enum {
    DSE_CFG_FAILURE_NONE = 0,
    DSE_CFG_FAILURE_REGION_BUDGET,
    DSE_CFG_FAILURE_REGION_IDENTITY,
    DSE_CFG_FAILURE_BRANCH_OUTSIDE,
    DSE_CFG_FAILURE_BOUNDARY_OUTSIDE,
    DSE_CFG_FAILURE_ORDER,
    DSE_CFG_FAILURE_BRANCH_MISSING,
    DSE_CFG_FAILURE_BOUNDARY_MISSING,
    DSE_CFG_FAILURE_SAME_NODE,
    DSE_CFG_FAILURE_IDENTITY,
    DSE_CFG_FAILURE_SUCCESSOR,
    DSE_CFG_FAILURE_OPAQUE,
    DSE_CFG_FAILURE_CYCLE,
    DSE_CFG_FAILURE_QUERY_BUDGET,
    DSE_CFG_FAILURE_INVALID,
    DSE_CFG_FAILURE_NOT_POSTDOMINATING,
    DSE_CFG_FAILURE_MEMORY_READ,
    DSE_CFG_FAILURE_COUNT
} DseCfgFailureReason;

typedef struct {
    DseCfgStopReason reason;
    bool site_present, expected_next_valid, observed_next_valid;
    TraceEntry site;
    uint64_t expected_next_pc, observed_next_pc;
} DseCfgBuildStop;

typedef enum {
    DSE_CFG_EDGE_NONE = 0,
    DSE_CFG_EDGE_ABSENT,
    DSE_CFG_EDGE_GENERATION
} DseCfgEdgeIssue;

typedef enum {
    DSE_CFG_RESOLVE_NONE = 0,
    DSE_CFG_RESOLVE_VERSION_MISSING,
    DSE_CFG_RESOLVE_STALE,
    DSE_CFG_RESOLVE_PAGE_BOUNDARY,
    DSE_CFG_RESOLVE_NOT_DECODED,
    DSE_CFG_RESOLVE_AMBIGUOUS,
    DSE_CFG_RESOLVE_FUTURE,
    DSE_CFG_RESOLVE_INVALID,
    DSE_CFG_RESOLVE_BUDGET,
    DSE_CFG_RESOLVE_HISTORY,
    DSE_CFG_RESOLVE_COUNT
} DseCfgResolveReason;

typedef struct {
    DseCfgFailureReason reason;
    uint32_t count;
    TraceEntry branch, boundary, at;
    bool at_present;
    DseCfgBuildStop build_stop;
    DseCfgEdgeIssue edge_issue;
    TraceBranchKind edge_kind;
    uint32_t successor_index, target_generation;
    uint64_t target_pc;
    DseCfgResolveReason resolution;
} DseCfgExample;

#define DSE_CFG_MAX_EXAMPLES 8U

typedef struct {
    uint64_t first_seq, trigger_seq;
    uint32_t vcpu, scanned, branches, retained, disjoint_retained, issues;
    uint32_t cfg_nodes, cfg_queries, cfg_pruned, cfg_unknown, cfg_effect_conflicts, cfg_issues;
    uint32_t cfg_regions, cfg_scanned; /* Nodes is the peak; scans share one per-slice budget. */
    uint32_t cfg_stops[DSE_CFG_STOP_COUNT], cfg_failures[DSE_CFG_FAILURE_COUNT];
    uint32_t cfg_resolve_attempts, cfg_resolve_lookups, cfg_resolve_added;
    uint32_t cfg_resolve_failures[DSE_CFG_RESOLVE_COUNT];
    uint32_t cfg_example_count, cfg_examples_omitted;
    DseCfgExample cfg_examples[DSE_CFG_MAX_EXAMPLES]; /* First example per cause; owned copies. */
    TraceEntry first_unknown; /* Owned occurrence identity; no borrowed metadata. */
} DseControlStats;

typedef struct {
    uint32_t seen, returns_modeled, observation_failures, unsupported, effects_unmodeled;
    uint32_t argument_constraints;
    uint32_t name_constraints, file_objects_created, file_objects_live;
    uint32_t file_resizes, file_state_invalidations;
    uint64_t last_file_id, last_file_size, last_file_version;
    uint32_t last_file_fd, last_file_flags;
    uint32_t mappings_created, mappings_live, mmap_argument_constraints;
    uint32_t mappings_replaced;
    uint64_t mapping_cells_discarded;
    uint64_t mapping_reads, mapping_zero_reads, mapping_writes, mapping_access_failures;
    uint64_t last_mapping_base, last_mapping_end, last_mapping_file, last_mapping_version;
    uint64_t mapping_bad_address;
    const char *mapping_first_reason;
    uint32_t file_write_calls, file_content_bytes;
    uint64_t file_write_bytes, file_write_shared_bytes, file_buffer_checks;
    uint64_t last_write_file, last_write_offset, last_write_size, last_file_position;
    uint32_t file_closes, file_descriptors_live, file_objects_released, close_mappings_preserved;
    uint64_t last_close_file;
    uint32_t last_close_fd;
    bool last_close_retained;
    TraceEntry first_unknown;
    uint32_t first_number, first_result;
    bool first_has_observation;
    const char *first_reason; /* Static diagnostic literal, never a borrowed trace pointer. */
} DseSyscallStats;

typedef struct {
    DseVerdict verdict;
    DseEvidence evidence;
    DseVerifyReason reason;
    DseSolverStatus candidate_query;
    DseSolverStatus alternative_query;

    uint32_t slice_len;
    uint32_t lifted_total;
    uint32_t concretized;
    uint32_t aux_miss;
    uint32_t unsupported;
    uint32_t meta_missing;
    uint32_t address_constraints;
    uint32_t address_failures;
    uint32_t path_constraints;
    uint32_t path_constraints_expected;
    uint32_t path_failures;
    uint32_t boundary_reg_bytes;
    uint32_t boundary_mem_bytes;
    uint32_t boundary_flag_bits;
    uint32_t address_root_bytes;
    uint32_t string_summaries;
    uint32_t string_summaries_expected;
    uint32_t expr_nodes_created;
    uint32_t z3_cache_nodes;
    uint32_t relevance_events_considered;
    uint32_t relevance_events_relevant;
    uint32_t relevance_events_unknown;
    uint32_t relevance_events_irrelevant;
    uint32_t relevance_iterations;

    bool target_symbolic;
    bool data_slice_complete;
    bool register_model_complete;
    bool memory_model_complete;
    bool address_model_complete;
    bool path_model_complete;
    bool lift_complete;
    bool proof_eligible;
    bool replay_valid;
    bool slice_complete;
    bool resource_limit_hit;
    bool relevance_applied;
    bool relevance_complete;
    uint32_t replay_checks;
    uint32_t replay_failures;
    uint32_t replay_missing_bindings;
    DseReplayDiagnostic first_replay_mismatch;
    DseControlStats control;
    DseSyscallStats syscalls;
} DseVerifyResult;

typedef struct {
    ProvRegistry *registry;
    DcfgGraph *dcfg;
    const BranchEventBuffer *branch_events;
} DseRelevanceContext;

typedef struct {
    ProvLabelId accumulated_label;
    uint32_t events_considered;
    uint32_t events_relevant;
    uint32_t events_unknown;
    uint32_t events_irrelevant;
    uint32_t iterations;
    bool applied;
    bool complete;
} DseRelevanceStats;

typedef enum {
    DSE_ADDRESS_READ = 0,
    DSE_ADDRESS_WRITE
} DseAddressAccess;

typedef enum {
    DSE_REPLAY_EVAL_OK = 0,
    DSE_REPLAY_EVAL_MISSING_BINDING,
    DSE_REPLAY_EVAL_INVALID_EXPR
} DseReplayEvalStatus;

typedef enum {
    DSE_SLICE_OK = 0,
    DSE_SLICE_INVALID_INPUT,
    DSE_SLICE_TRIGGER_MISSING,
    DSE_SLICE_META_MISSING,
    DSE_SLICE_AUX_MISSING,
    DSE_SLICE_TRUNCATED,
    DSE_SLICE_UNRESOLVED_REGISTER,
    DSE_SLICE_UNRESOLVED_MEMORY,
    DSE_SLICE_SYMBOLIC_ADDRESS,
    DSE_SLICE_MEM_ACCESS_UNMODELED,
    DSE_SLICE_DEPENDENCY_UNKNOWN
} DseSliceStatus;

typedef struct {
    DseSliceStatus status;
    uint32_t len;
    uint32_t meta_missing;
    uint32_t aux_missing;
    uint8_t unresolved_reg_bytes[REG_COUNT];
    uint8_t unresolved_mem_bytes;
    uint8_t boundary_reg_bytes[REG_COUNT];
    uint8_t boundary_mem_bytes;
    uint8_t address_root_reg_bytes[REG_COUNT];
    uint8_t boundary_flags; /* legacy x86 arithmetic-flag projection */
    uint64_t boundary_special;
    uint32_t dependency_unknown_reasons; /* TRACE_DEPS_* */
    uint32_t path_constraints_expected;
    uint32_t string_summaries;
    uint32_t boundary_mem_byte_count;
    DseRelevanceStats relevance;
    DseControlStats control;
    bool data_complete;
    bool path_complete;
    bool complete;
} DseSliceResult;

typedef enum {
    SYM_CONST,
    SYM_VAR,

    SYM_ADD,
    SYM_SUB,
    SYM_MUL,
    SYM_XOR,
    SYM_AND,
    SYM_OR,
    SYM_SHL,
    SYM_LSHR, //logic
    SYM_ASHR, //arith

    SYM_EXTRACT, /* extract low from high bytes*/
    SYM_ZEXT,    /* extend low to high with zeroes*/
    SYM_SEXT,    /* sign extension */
    SYM_CONCAT,  /* concatinate high and low bytes*/

    SYM_EQ,
    SYM_ULT,
    SYM_SLT,
    SYM_ITE
} SymOp;

typedef enum {
    DSE_VAR_GENERIC = 0,
    DSE_VAR_REGISTER_ROOT,
    DSE_VAR_MEMORY_ROOT,
    DSE_VAR_ADDRESS_ROOT,
    DSE_VAR_FLAG_ROOT
} DseVarKind;

typedef struct {
    uint64_t ids[DSE_MAX_ROOT_LINEAGE];
    uint16_t count;
    bool complete;
} DseRootSet;

typedef struct {
    uint32_t root_id;
    DseVarKind kind;
    uint64_t source;
    uint64_t variable_epoch;
    uint64_t origin_version;
    uint64_t first_event_seq;
    uint64_t last_event_seq;
    uint32_t width;
    uint16_t byte_offset;
    uint16_t lineage_count;
    bool lineage_complete;
    uint64_t *lineage_ids;
} DseRootProvenance;

typedef struct {
    uint64_t lineage_id;
    DseVarKind kind;
    uint64_t source;
    uint64_t origin_version;
    uint32_t width;
    uint16_t byte_offset;
} DseRootOrigin;

typedef struct SymExpr {
    uint32_t ref_count;
    SymOp type;
    uint8_t width; //control width for some operations like add, zext, etc.
    bool has_var;

    union {
        //for const
        uint64_t const_val;

        //for tainted
        struct {
            uint64_t src_addr;
            uint64_t epoch;
            uint32_t id;
            uint8_t kind;
        } var;

        //for bin operations
        struct {
            struct SymExpr *a;
            struct SymExpr *b;
        } binary;

        //for unary operations
        struct {
            struct SymExpr *a;
            uint32_t ext_to;       /* target width for ZEXT*/
            uint32_t extract_high; /* amount of high bytes*/
            uint32_t extract_low;  /* amount of low bytes*/
        } unary;

        //for ternary op
        struct {
            struct SymExpr *cond;
            struct SymExpr *when_true;
            struct SymExpr *when_false;
        } ternary;
    };
} SymExpr;

typedef enum {
    DSE_FLAG_SLOT_CF = 0,
    DSE_FLAG_SLOT_PF,
    DSE_FLAG_SLOT_AF,
    DSE_FLAG_SLOT_ZF,
    DSE_FLAG_SLOT_SF,
    DSE_FLAG_SLOT_OF,
    DSE_FLAG_SLOT_DF,
    DSE_FLAG_SLOT_COUNT
} DseFlagSlot;

typedef struct {
    //registers state taint/!taint
    SymExpr *reg[REG_COUNT];

    SymExpr *x86_flags[DSE_FLAG_SLOT_COUNT];
    //mem state taint/!taint
    GHashTable *sym_mem;
    //for deduplication
    GHashTable *var_cache;

    uint32_t var_counter; /* unique id*/
} SymState;

#define DSE_MAX_FILE_OBJECTS 64U
#define DSE_MAX_FILE_CONTENT_BYTES (64U * 1024U)
/* Fresh memfd objects: absent byte expressions denote zero within size.
 * One known open description per object; no dup/seek/external mutations.
 * A mapped file cannot be resized. Only exact shared-to-private replacement
 * of its one known mapping is supported; no partial ranges or aliases. */
typedef struct {
    uint64_t id, size, version, position;
    uint32_t fd, flags;
    bool mapped, fd_open;
    GHashTable *bytes; /* uint64_t file offsets -> owned SymExpr bytes */
} DseFileObject;

typedef struct {
    uint64_t base, end, offset, file_id, file_version, created_seq;
    uint32_t prot, flags;
    bool shared_tail_written;
} DseFileMapping;

typedef struct {
    DseFileObject objects[DSE_MAX_FILE_OBJECTS];
    DseFileMapping mappings[DSE_MAX_FILE_OBJECTS];
    uint32_t count, vcpu;
    uint32_t mapping_count;
    uint32_t content_bytes;
    uint64_t last_boundary, last_seq;
} DseFileState;

//DSE context
typedef struct {
    SymState state;
    Z3_context z3_ctx;     /* Z3 context*/
    Z3_solver z3_solver;   /* Z3 solver instance */
    Z3_ast path_predicate; /* path conditions */
    GHashTable *z3_expr_cache;
    GHashTable *observed_values;
    GHashTable *root_provenance;
    GHashTable *root_origins;
    GHashTable *lineage_origins;
    uint64_t next_lineage_id;
    bool root_provenance_complete;

    bool replay_model_complete;
    bool replay_mismatch;
    uint32_t replay_checks;
    uint32_t replay_failures;
    uint32_t replay_missing_bindings;
    DseReplayDiagnostic first_replay_mismatch;
    TraceEntry replay_origin;
    bool replay_origin_valid;

    bool has_solver;
    bool resource_limit_hit;
    uint32_t expr_nodes_created;
    uint32_t z3_cache_nodes;
    uint32_t address_constraints;
    uint32_t address_read_modeled;
    uint32_t address_write_modeled;
    uint32_t address_failures;
    bool address_model_complete;
    bool memory_model_complete;
    bool register_model_complete;
    bool path_model_complete;

    uint32_t path_constraints;
    uint32_t path_failures;
    uint32_t string_summaries;
    DseSyscallStats syscalls;
    DseFileState files;
    uint8_t x86_flags_poisoned;
    bool x86_df_poisoned;
    uint64_t replay_first_seq;
    uint64_t memory_root_epoch;
    uint64_t register_root_epoch[REG_COUNT];
    bool demand_active;
    uint64_t demand_seq_id;
    uint8_t demand_reg_live_after[REG_COUNT];
    bool demand_all_memory_writes;
    const GHashTable *demand_memory_writes;
} DSECtx;

/* Configure before running DSE; changes only text diagnostics. */
void dse_set_verbose_diagnostics(bool enabled);
void dse_replay_diagnostic_append_json(GString *out, const DseReplayDiagnostic *diagnostic);
void dse_syscall_append_json(GString *out, const DseSyscallStats *stats);

//multiarch support
typedef struct DseArch {
    const char *name;
    uint32_t natural_width;
    bool big_endian;
    int (*reg_to_rid)(unsigned cs_reg);
    bool (*lift_one)(DSECtx *ctx, const cs_insn *insn, const InsnAux *aux,
                     const struct DseArch *arch);
} DseArch;

//arch dependent
extern const DseArch dse_arch_x86;

SymExpr *dse_read_rid_fit(DSECtx *ctx, const InsnAux *aux, int rid, uint32_t want_w,
                          uint32_t natural_w);
SymExpr *dse_read_rid_observed_root(DSECtx *ctx, const InsnAux *aux, int rid, uint32_t want_w,
                                    uint32_t natural_w);
SymExpr *dse_load_mem(DSECtx *ctx, const InsnAux *aux, uint32_t width_bits, bool big_endian);
bool dse_store_mem(DSECtx *ctx, const InsnAux *aux, SymExpr *val, bool big_endian);
void dse_set_reg(DSECtx *ctx, int rid, SymExpr *val, uint32_t natural_w);
void dse_commit_low(DSECtx *ctx, const InsnAux *aux, int rid, SymExpr *val, uint32_t w,
                    uint32_t natural_w);
SymExpr *dse_read_rid_slice(DSECtx *ctx, const InsnAux *aux, int rid, uint32_t low_bit,
                            uint32_t width, uint32_t natural_width);
bool dse_commit_slice(DSECtx *ctx, const InsnAux *aux, int rid, SymExpr *value, uint32_t low_bit,
                      uint32_t width, uint32_t natural_width);

//init and basic operands DSE
SymExpr *sym_expr_const(uint64_t val, uint32_t width);
SymExpr *sym_expr_var(uint64_t src_addr, uint32_t idx, uint32_t width);
SymExpr *sym_expr_clone(const SymExpr *e);
SymExpr *sym_expr_add(SymExpr *a, SymExpr *b);
SymExpr *sym_expr_sub(SymExpr *a, SymExpr *b);
SymExpr *sym_expr_xor(SymExpr *a, SymExpr *b);
SymExpr *sym_expr_and(SymExpr *a, SymExpr *b);
SymExpr *sym_expr_eq(SymExpr *a, SymExpr *b);
SymExpr *sym_expr_ult(SymExpr *a, SymExpr *b);
SymExpr *sym_expr_slt(SymExpr *a, SymExpr *b);
SymExpr *sym_expr_ite(SymExpr *cond, SymExpr *when_true, SymExpr *when_false);
SymExpr *sym_expr_shl(SymExpr *a, SymExpr *b);
SymExpr *sym_expr_shr(SymExpr *a, SymExpr *count);
SymExpr *sym_expr_sar(SymExpr *a, SymExpr *count);
SymExpr *sym_expr_rol(SymExpr *a, SymExpr *count);
SymExpr *sym_expr_ror(SymExpr *a, SymExpr *count);
SymExpr *sym_expr_mul(SymExpr *a, SymExpr *b);
SymExpr *sym_expr_or(SymExpr *a, SymExpr *b);
SymExpr *sym_expr_sext(SymExpr *a, uint32_t to_width);
SymExpr *sym_expr_zext(SymExpr *a, uint32_t to_width);
SymExpr *sym_expr_extract(SymExpr *a, uint32_t low_bit, uint32_t out_width);
SymExpr *sym_expr_concat(SymExpr *high, SymExpr *low);
SymExpr *sym_expr_not(SymExpr *a);
SymExpr *sym_expr_neg(SymExpr *a);
void sym_expr_free(SymExpr *e);

//states for DSE
void sym_state_init(SymState *st);
void sym_state_clear(SymState *st);
SymExpr *sym_state_get_reg(const SymState *st, RegId rid);
void sym_state_set_reg(SymState *st, RegId rid, SymExpr *e);
SymExpr *sym_state_new_var(SymState *st, uint64_t src_addr, uint32_t width);

//context DSE
bool dse_ctx_init(DSECtx *ctx);
void dse_ctx_free(DSECtx *ctx);
bool dse_path_assert(DSECtx *ctx, SymExpr *cond, bool expected);
bool dse_constrain_observed_address(DSECtx *ctx, SymExpr *address, uint64_t observed_address,
                                    DseAddressAccess access);

//flags
SymExpr *dse_get_x86_flag(DSECtx *ctx, const InsnAux *aux, uint8_t flag);
/* Retains the symbolic input flag and checks its observed value before use. */
SymExpr *dse_get_x86_flag_checked(DSECtx *ctx, const InsnAux *aux, uint8_t flag);
void dse_set_x86_flag(DSECtx *ctx, uint8_t flag, SymExpr *value);
void dse_invalidate_x86_flags(DSECtx *ctx, uint8_t flags);
bool dse_check_x86_direction(DSECtx *ctx, const InsnAux *aux, int8_t direction);
/* Consumes offset; also requires verified, entry-preserved ES for path completeness. */
bool dse_constrain_observed_flat_es(DSECtx *ctx, SymExpr *offset, const InsnAux *aux);
bool dse_load_tracked_byte_at(DSECtx *ctx, uint64_t address, uint64_t epoch, uint8_t observed_value,
                              bool value_tainted, SymExpr **out_symbolic_value);
bool dse_store_tracked_byte_at(DSECtx *ctx, uint64_t address, SymExpr *symbolic_value,
                               const InsnAux *writer_aux, uint8_t observed_value);
bool dse_memory_write_byte_required(const DSECtx *ctx, uint64_t address);

//lifter, instr to z3
bool dse_lift_insn(DSECtx *ctx, const TraceEntry *entry, const InsnMeta *meta, csh cs_handle);
/* index == replay_input_count(input) lifts the finalized trigger itself. */
bool dse_lift_replay_step(DSECtx *ctx, const ReplayInput *input, uint32_t index, csh cs_handle);
void dse_lift_attach(const TraceBuffer *tb, const DseAuxRing *ring,
                     const DseArch *arch); //attach trace+aux
void dse_lift_begin(DSECtx *ctx);
//void dse_lift_end(void);
uint32_t dse_lift_total_count(void);       //counter instr lifted
uint32_t dse_lift_concretized_count(void); //to concrete
uint32_t dse_lift_aux_miss_count(void);
uint32_t dse_lift_unsupported_count(void);
DseReplayEvalStatus dse_eval_expr_observed(const DSECtx *ctx, const SymExpr *expr,
                                           uint64_t *out_value);
bool dse_expr_has_var(const SymExpr *e); //is SYM_VAR in the current AST
const DseRootProvenance *dse_root_provenance_lookup(const DSECtx *ctx, uint32_t root_id);
const DseRootOrigin *dse_root_origin_lookup(const DSECtx *ctx, uint64_t lineage_id);
bool dse_expr_collect_root_lineage(const DSECtx *ctx, const SymExpr *expr, DseRootSet *out);
bool dse_root_sets_may_intersect(const DseRootSet *left, const DseRootSet *right);

//dse check of oep
const char *dse_solver_status_name(DseSolverStatus status);
const char *dse_evidence_name(DseEvidence evidence);
const char *dse_verdict_name(DseVerdict verdict);
const char *dse_verify_reason_name(DseVerifyReason reason);
DseSliceResult dse_build_reg_slice(const TraceBuffer *tb, const DseAuxRing *ring,
                                   uint64_t trigger_seq_id, RegId target_reg,
                                   const TraceEntry **out_slice, uint32_t max_len);
DseSliceResult dse_build_mem_slice(const TraceBuffer *tb, const DseAuxRing *ring,
                                   uint64_t trigger_seq_id, uint64_t target_addr,
                                   uint8_t target_size, const TraceEntry **out_slice,
                                   uint32_t max_len);
bool dse_analyze_branch_relevance(const TraceBuffer *tb, uint64_t trigger_seq_id,
                                  const DseRelevanceContext *relevance,
                                  DseRelevanceStats *out_stats);
/* Data-label relevance is not a certificate of control independence. The
 * bounded trace slice retains earlier conditional branches even after its
 * data frontier becomes empty. A branch may be omitted only in a closed,
 * acyclic region whose boundary postdominates it and whose may-writes do not
 * intersect live state. Missing/conflicting evidence or truncated control
 * coverage makes path_complete false. Existing boundary-root semantics apply.
 * Output entries borrow tb and must be captured before it changes. */
DseSliceResult dse_build_reg_slice_with_relevance(const TraceBuffer *tb, const DseAuxRing *ring,
                                                  uint64_t trigger_seq_id, RegId target_reg,
                                                  const TraceEntry **out_slice, uint32_t max_len,
                                                  const DseRelevanceContext *relevance);
DseSliceResult dse_build_mem_slice_with_relevance(const TraceBuffer *tb, const DseAuxRing *ring,
                                                  uint64_t trigger_seq_id, uint64_t target_addr,
                                                  uint8_t target_size, const TraceEntry **out_slice,
                                                  uint32_t max_len,
                                                  const DseRelevanceContext *relevance);
void dse_control_append_json(GString *out, const DseControlStats *control);
/* Configure before analysis; false restores the 7.4f.3c control prefix. */
void dse_set_control_pruning(bool enabled);
DseSolverStatus dse_check_target_relation(DSECtx *ctx, SymExpr *target_expr, uint64_t oep_candidate,
                                          bool equal);
DseVerifyResult dse_verify_oep_candidate(TraceBuffer *tb, const DseAuxRing *ring,
                                         uint64_t trigger_seq_id, RegId target_reg,
                                         uint64_t oep_candidate, ShadowMemory *shadow,
                                         csh cs_handle);
DseVerifyResult dse_verify_oep_candidate_mem(TraceBuffer *tb, const DseAuxRing *ring,
                                             uint64_t trigger_seq_id, uint64_t target_addr,
                                             uint64_t oep_candidate, ShadowMemory *shadow,
                                             csh cs_handle);
DseVerifyResult dse_verify_oep_candidate_with_relevance(TraceBuffer *tb, const DseAuxRing *ring,
                                                        uint64_t trigger_seq_id, RegId target_reg,
                                                        uint64_t oep_candidate,
                                                        ShadowMemory *shadow, csh cs_handle,
                                                        const DseRelevanceContext *relevance);
DseVerifyResult dse_verify_oep_candidate_mem_with_relevance(TraceBuffer *tb, const DseAuxRing *ring,
                                                            uint64_t trigger_seq_id,
                                                            uint64_t target_addr,
                                                            uint64_t oep_candidate,
                                                            ShadowMemory *shadow, csh cs_handle,
                                                            const DseRelevanceContext *relevance);
#endif
