#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <qemu-plugin.h>
#include <math.h>
#include <capstone/capstone.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <inttypes.h>
#include <errno.h>

#include "dta.h"
#include "trace.h"
#include "dse.h"
#include "dcfg.h"
#include "ir_runtime.h"

/* Opt-in diagnostic consumer. Existing DSE verdict/scoring is independent. */
static IrRuntime g_ir_runtime;
static bool g_ir_enabled;
static FILE *g_ir_report;
static uint64_t g_ir_start_pc, g_ir_probe_pc;
static bool g_ir_has_start, g_ir_has_probe;
static bool g_x86_flags_verified;
/* Optional capability supplied by the QEMU x86 flag-observation patch.
 * Without it, flag snapshots remain unavailable to DSE, REP and IR replay. */
extern bool qemu_plugin_taintforge_x86_flags_v1(void) __attribute__((weak));
static unsigned g_ir_vcpus;
static uint32_t g_trace_capacity = 256U * 1024U;
static size_t g_ir_source_history_bytes = 8U * 1024U * 1024U;
static bool g_dta_cmlb_enabled;
static bool g_dta_shadow_stats;

static bool dta_shadow_options(int argc, char **argv) {
    for (int i = 0; i < argc; i++) {
        const char *arg = argv[i], *eq = strchr(arg, '=');
        size_t key = eq ? (size_t)(eq - arg) : strlen(arg);
        bool *option = NULL;
        if (key == sizeof("dta-cmlb") - 1 && !memcmp(arg, "dta-cmlb", key))
            option = &g_dta_cmlb_enabled;
        else if (key == sizeof("dta-shadow-stats") - 1 && !memcmp(arg, "dta-shadow-stats", key))
            option = &g_dta_shadow_stats;
        else
            continue;
        if (eq && !strcmp(eq + 1, "on"))
            *option = true;
        else if (eq && !strcmp(eq + 1, "off"))
            *option = false;
        else {
            fprintf(stderr, "[DTA] invalid option: %s\n", arg);
            return false;
        }
    }
    return true;
}

static void dta_shadow_report(ShadowMemory *shadow) {
    ShadowStats stats;
    if (!shadow_get_stats(shadow, &stats))
        return;
    if (!stats.knowledge_valid)
        fprintf(
            stderr,
            "[DTA] shadow knowledge lost; memory provenance is UNKNOWN until runtime recreation\n");
    if (!g_dta_shadow_stats)
        return;
    fprintf(stderr,
            "[DTA-SHADOW] {\"cmlb\":%s,\"knowledge_valid\":%s,"
            "\"page_count\":%zu,\"page_bytes\":%zu,\"cmlb_bytes\":%zu",
            stats.cmlb_enabled ? "true" : "false", stats.knowledge_valid ? "true" : "false",
            stats.page_count, stats.page_bytes, stats.cmlb_bytes);
#define SHADOW_REPORT(field) fprintf(stderr, ",\"" #field "\":%" PRIu64, stats.field)
    SHADOW_REPORT(read_calls);
    SHADOW_REPORT(read_bytes);
    SHADOW_REPORT(write_calls);
    SHADOW_REPORT(write_bytes);
    SHADOW_REPORT(hash_lookups);
    SHADOW_REPORT(hash_probes);
    SHADOW_REPORT(cmlb_probes);
    SHADOW_REPORT(cmlb_hits);
    SHADOW_REPORT(cmlb_misses);
    SHADOW_REPORT(cmlb_full_hits);
    SHADOW_REPORT(cmlb_fills);
    SHADOW_REPORT(cmlb_invalidations);
    SHADOW_REPORT(cmlb_collisions);
    SHADOW_REPORT(cmlb_flushes);
    SHADOW_REPORT(clean_store_skips);
    SHADOW_REPORT(semantic_failures);
    SHADOW_REPORT(cache_alloc_failures);
#undef SHADOW_REPORT
    fprintf(stderr, "}\n");
}

static bool ir_plugin_u64(const char *text, uint64_t maximum, uint64_t *out) {
    if (!text || !*text || *text == '-' || *text == '+' || g_ascii_isspace(*text))
        return false;
    char *end = NULL;
    errno = 0;
    unsigned long long n = strtoull(text, &end, 0);
    if (errno || !end || *end || n > maximum)
        return false;
    *out = n;
    return true;
}

static bool ir_plugin_options(int argc, char **argv) {
    IrRuntimeOptions options = ir_runtime_default_options();
    const char *path = "ir_runtime.jsonl";
    for (int i = 0; i < argc; ++i) {
        const char *arg = argv[i];
        if (strncmp(arg, "ir-", 3))
            continue; /* Preserve legacy non-IR options. */
        const char *eq = strchr(arg, '=');
        if (!eq)
            goto invalid;
        size_t key = (size_t)(eq - arg);
        const char *value = eq + 1;
        uint64_t n = 0;
#define IR_OPTION(name) (key == sizeof(name) - 1 && !memcmp(arg, name, key))
        if (IR_OPTION("ir-check")) {
            if (!strcmp(value, "on"))
                g_ir_enabled = true;
            else if (!strcmp(value, "off"))
                g_ir_enabled = false;
            else
                goto invalid;
        } else if (IR_OPTION("ir-flat-memory")) {
            if (!strcmp(value, "on"))
                options.replay.x86.flat32_ram = true;
            else if (!strcmp(value, "off"))
                options.replay.x86.flat32_ram = false;
            else
                goto invalid;
        } else if (IR_OPTION("ir-ssa")) {
            if (!strcmp(value, "on"))
                options.trace_ssa = true;
            else if (!strcmp(value, "off"))
                options.trace_ssa = false;
            else
                goto invalid;
        } else if (IR_OPTION("ir-ssa-work")) {
            if (!ir_plugin_u64(value, UINT64_C(128000000), &n))
                goto invalid;
            options.analysis.work = n;
        } else if (IR_OPTION("ir-ssa-bytes")) {
            if (!ir_plugin_u64(value, 512U * 1024U * 1024U, &n))
                goto invalid;
            options.analysis.bytes = (size_t)n;
        } else if (IR_OPTION("ir-inputs")) {
            if (!ir_plugin_u64(value, UINT64_C(0x1000000), &n))
                goto invalid;
            options.replay.inputs.inputs = (uint32_t)n;
        } else if (IR_OPTION("ir-input-bytes")) {
            if (!ir_plugin_u64(value, 256U * 1024U * 1024U, &n))
                goto invalid;
            options.replay.inputs.bytes = (size_t)n;
        } else if (IR_OPTION("ir-input-work")) {
            if (!ir_plugin_u64(value, UINT64_C(128000000), &n))
                goto invalid;
            options.replay.inputs.work = n;
        } else if (IR_OPTION("ir-source-bytes")) {
            if (!ir_plugin_u64(value, 64U * 1024U * 1024U, &n))
                goto invalid;
            options.sources.bytes = (size_t)n;
        } else if (IR_OPTION("ir-source-history-bytes")) {
            if (!ir_plugin_u64(value, 64U * 1024U * 1024U, &n))
                goto invalid;
            g_ir_source_history_bytes = (size_t)n;
        } else if (IR_OPTION("ir-source-work")) {
            if (!ir_plugin_u64(value, UINT64_C(32000000), &n))
                goto invalid;
            options.sources.work = n;
        } else if (IR_OPTION("ir-window")) {
            if (!ir_plugin_u64(value, IR_RUNTIME_MAX_WINDOW, &n) || !n)
                goto invalid;
            options.window_steps = (uint32_t)n;
        } else if (IR_OPTION("ir-max-checks")) {
            if (!ir_plugin_u64(value, IR_RUNTIME_MAX_CHECKS, &n) || !n)
                goto invalid;
            options.max_checks = (uint32_t)n;
        } else if (IR_OPTION("ir-capture-bytes")) {
            if (!ir_plugin_u64(value, 256U * 1024U * 1024U, &n) || !n)
                goto invalid;
            options.capture_bytes = (size_t)n;
        } else if (IR_OPTION("ir-eval-steps")) {
            if (!ir_plugin_u64(value, UINT64_C(10000000), &n))
                goto invalid;
            options.eval.steps = n;
        } else if (IR_OPTION("ir-start")) {
            if (!ir_plugin_u64(value, UINT32_MAX, &n))
                goto invalid;
            g_ir_start_pc = n;
            g_ir_has_start = true;
        } else if (IR_OPTION("ir-probe")) {
            if (!ir_plugin_u64(value, UINT32_MAX, &n))
                goto invalid;
            g_ir_probe_pc = n;
            g_ir_has_probe = true;
        } else if (IR_OPTION("ir-trace-capacity")) {
            if (!ir_plugin_u64(value, 256U * 1024U, &n) || n < 2)
                goto invalid;
            g_trace_capacity = (uint32_t)n;
        } else if (IR_OPTION("ir-report")) {
            if (!*value)
                goto invalid;
            path = value;
        } else
            goto invalid;
#undef IR_OPTION
        continue;
    invalid:
        fprintf(stderr, "[IR] invalid option: %s\n", arg);
        return false;
    }
    if (!ir_runtime_init(&g_ir_runtime, &options))
        return false;
    if (g_ir_enabled) {
        g_ir_report = fopen(path, "w");
        if (!g_ir_report) {
            fprintf(stderr, "[IR] cannot open report: %s\n", strerror(errno));
            return false;
        }
    }
    return true;
}

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

static size_t page_size = 4096;

//OEP scoring
#define W_DSE 0.70
#define W_UNMAP 0.20
#define W_PROL 0.10
#define W_ACTIVE (W_DSE + W_UNMAP + W_PROL)
//tolerance
#define SCORE_EPS 1e-9

//p_filesz fallback
#define MAX_INITIAL_TAINT_BYTES (256ULL * 1024ULL * 1024ULL)
#define MAX_PENDING_IOV 1024U
#define GUEST_MAP_ANONYMOUS 0x20U
#define MAX_AUXV_ARGC (1U << 20)

typedef enum {
    ARCH_X86_32,
    ARCH_ARM,
    ARCH_MIPS,
    ARCH_UNKNOWN
} arch_t;

typedef struct {
    int prot;
    bool written;
    bool exec_after_write;
    bool dyn_exec;
    uint64_t write_count;
    uint64_t last_write;
    uint8_t *wbitmap;
    uint32_t gen_written;
    bool exec_seen;
} page_t;

//multiple OEP vatiants
typedef struct {
    uint64_t addr;
    uint64_t jump_site;
    uint32_t generation;
    uint64_t icount;
    DseVerifyResult dse;
    bool target_tainted;
    bool has_prologue;
    bool jump_from_unmapped;
} oep_cand_t;

typedef struct {
    uint64_t pc;
    InsnDescId insn_desc_id;
    MetaId meta_id;
    uint32_t code_generation;
    uint64_t bytes_hash;
    const InsnMeta *meta;
    uint8_t instr_bytes[MAX_INSN_BYTES];
    uint8_t size;
} InsnExecCtx;

//got table reconstruct helper
typedef struct {
    uint64_t got_slot;
    uint64_t resolved_addr;
    const char *module;
    uint64_t lib_base;
} resolved_import_t;

static GHashTable *pages = NULL;
static ProvRegistry *g_prov_registry = NULL;
static ProvFdTable *g_prov_fd_table = NULL;
static ShadowMemory *g_shadow = NULL;
static bool oep_found = false;
static uint64_t oep_addr = 0;
static csh cs_handle;
static TraceBuffer *g_trace = NULL;
static DseAuxRing *g_aux = NULL;
static BranchEventBuffer *g_branch_events = NULL;
static DcfgGraph *g_dcfg = NULL;
static uint64_t g_analysis_scope_id = UINT64_C(1);
static uint64_t g_next_resource_object_id = UINT64_C(1);
static char *g_main_image_path = NULL;
static ProvResourceId g_main_image_resource_id = PROV_RESOURCE_ID_INVALID;
static uint64_t g_main_image_object_id = 0;
static __thread InsnAux *g_cur_aux = NULL;
static GPtrArray *g_insn_exec_contexts = NULL;
static GMutex g_insn_exec_contexts_lock;
static bool g_insn_exec_contexts_lock_initialized = false;
static bool g_taint_seen = false;
static struct qemu_plugin_register *g_reg_handle[REG_COUNT];
static struct qemu_plugin_register *g_eflags_handle = NULL;
static bool g_regs_ready = false;
static const char *g_reg_name_i386[8] = {"eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"};
static bool g_reg_read_error_reported[REG_COUNT];

static bool insn_exec_contexts_init(void) {
    if (g_insn_exec_contexts_lock_initialized) {
        return g_insn_exec_contexts != NULL;
    }
    g_mutex_init(&g_insn_exec_contexts_lock);
    g_insn_exec_contexts_lock_initialized = true;
    g_insn_exec_contexts = g_ptr_array_new_with_free_func(g_free);
    return g_insn_exec_contexts != NULL;
}

static void insn_exec_contexts_destroy(void) {
    if (!g_insn_exec_contexts_lock_initialized)
        return;
    g_mutex_lock(&g_insn_exec_contexts_lock);
    GPtrArray *contexts = g_insn_exec_contexts;
    g_insn_exec_contexts = NULL;
    g_mutex_unlock(&g_insn_exec_contexts_lock);
    if (contexts)
        g_ptr_array_unref(contexts);
    g_mutex_clear(&g_insn_exec_contexts_lock);
    g_insn_exec_contexts_lock_initialized = false;
}

static InsnExecCtx *insn_exec_context_create(uint64_t pc, const uint8_t *bytes, size_t size,
                                             const InsnMeta *meta, InsnDescId insn_desc_id,
                                             uint32_t code_generation, uint64_t bytes_hash) {
    InsnExecCtx *ctx = g_new0(InsnExecCtx, 1);
    ctx->pc = pc;
    ctx->meta = meta;
    ctx->insn_desc_id = insn_desc_id;
    ctx->meta_id = meta ? meta->meta_id : META_ID_INVALID;
    ctx->code_generation = code_generation;
    ctx->bytes_hash = bytes_hash;
    if (meta) {
        ctx->size = meta->size;
        memcpy(ctx->instr_bytes, meta->instr_bytes, meta->size);
    } else if (bytes && size != 0) {
        size_t copy_size = size < MAX_INSN_BYTES ? size : MAX_INSN_BYTES;
        ctx->size = (uint8_t)copy_size;
        memcpy(ctx->instr_bytes, bytes, copy_size);
    }
    if (!g_insn_exec_contexts_lock_initialized) {
        g_free(ctx);
        return NULL;
    }
    g_mutex_lock(&g_insn_exec_contexts_lock);
    if (!g_insn_exec_contexts) {
        g_mutex_unlock(&g_insn_exec_contexts_lock);
        g_free(ctx);
        return NULL;
    }
    g_ptr_array_add(g_insn_exec_contexts, ctx);
    g_mutex_unlock(&g_insn_exec_contexts_lock);
    return ctx;
}

//auxv read for threshold and determine precise page size
#ifndef AT_NULL
#define AT_NULL 0   //vector end
#define AT_PHDR 3   //phdr
#define AT_PHENT 4  //size of phdr
#define AT_PHNUM 5  //number of phdr
#define AT_PAGESZ 6 //page size
#define AT_BASE 7   // base of ld
#define AT_ENTRY 9  //entry point addr
#endif
//boundaries for main code
static uint64_t g_main_lo = 0;
static uint64_t g_main_hi = 0;
static bool g_main_known = false;
static bool g_initial_taint_seeded = false;
//ld base
static uint64_t g_ld_base = 0;
//AT_ENTRY in packed file typically points to packer's stub
static uint64_t g_stub_entry = 0;
static bool g_auxv_done = false;
static uint32_t g_auxv_attempts = 0;
static uint64_t g_auxv_next_retry = 1;
static bool g_initial_sp_valid = false;
static uint64_t g_initial_sp = 0;
//TODO stub for multiarch
static const DseArch *g_plugin_arch = &dse_arch_x86;
//additional OEP checks
static uint64_t g_icount = 0;
static uint32_t g_unpack_gen = 0;
static uint64_t g_last_cand_icount = 0;
static uint32_t g_layer = 0;
static bool g_layer_dirty = false;
static bool g_layer_has_cand = false;
static GList *oep_cands = NULL;
static GHashTable *unmapped_pages = NULL; //for munmaped pages

//addtional info for last indirect jump
static __thread uint64_t prev_jump_site = 0;
static __thread uint64_t prev_jump_seq_id = 0;
static __thread int prev_target_reg = REG_INVALID;
static __thread uint64_t prev_mem_taddr = 0;
static __thread bool prev_jump_pending = false;
static __thread uint64_t prev_mem_target_value = 0;
static __thread bool prev_mem_target_valid = false;
static __thread bool prev_target_tainted = false;

typedef struct {
    uint64_t pc;
    bool active;
    const InsnMeta *meta;
    RegShadow pre_regs;
    bool pre_esp_valid;
    uint32_t pre_esp;
    bool last_read_valid;
    uint32_t last_read_size;
    ProvLabelId last_read_labels[MAX_REG_BYTES];
    bool flags_pending;
    bool flags_applied;
} dta_mem_transfer_t;

typedef struct {
    bool active;
    DcfgEdgeKind kind;
    DcfgNodeKey source;
    uint64_t instruction_pc;
    uint64_t trace_seq_id;

    bool expected_target_valid;
    uint64_t expected_target;
    ProvLabelId target_label;
} dcfg_pending_transfer_t;

typedef struct {
    DtaVcpuState dta;
    dta_mem_transfer_t mem_transfer;
    uint64_t current_ip;
    InsnAux *current_aux;
    uint64_t current_aux_seq_id;
    uint64_t ir_start_seq;

    dcfg_pending_transfer_t dcfg_pending_transfer;
    bool dcfg_block_active;
    DcfgNodeKey dcfg_block_key;
    bool dcfg_last_insn_valid;
    uint64_t dcfg_last_insn_pc;
    uint8_t dcfg_last_insn_size;
} PluginVcpuState;

static void ir_plugin_check(PluginVcpuState *state, unsigned int vcpu, uint64_t trigger_seq,
                            IrRuntimeKind kind, uint64_t address, int reg) {
    if (!g_ir_enabled)
        return;
    IrRuntimeRequest request = {.kind = kind,
                                .trigger_seq = trigger_seq,
                                .first_seq = state->ir_start_seq,
                                .require_first_seq = g_ir_has_start,
                                .vcpu_index = vcpu,
                                .candidate_address = address,
                                .target_gpr = reg,
                                .flag_observations_trusted = g_x86_flags_verified,
                                .collector_serialized =
                                    __atomic_load_n(&g_ir_vcpus, __ATOMIC_ACQUIRE) == 1};
    IrRuntimeReport report;
    if (!ir_runtime_check_sources(&g_ir_runtime, g_trace, g_aux, g_prov_registry, &request,
                                  &report))
        return;
    if (!ir_runtime_report_json(g_ir_report, &report) || fflush(g_ir_report)) {
        fprintf(stderr, "[IR] report write failed; diagnostics disabled\n");
        g_ir_enabled = false;
    }
    fprintf(stderr,
            "[IR-CHECK] %s seq=%" PRIu64 " %s lifted=%u/%u stop=%" PRIu64
            " issues=%x/%x time_us=%" PRIu64 "\n",
            kind == IR_RUNTIME_CANDIDATE ? "candidate" : "probe", trigger_seq,
            ir_runtime_status_name(report.status), report.build.lifted_steps, report.selected_steps,
            report.build.stopped_seq, report.issues, report.build.issues, report.total_us);
}

static uint32_t next_code_generation(void) {
    uint32_t observed = __atomic_load_n(&g_unpack_gen, __ATOMIC_RELAXED);
    while (observed != UINT32_MAX) {
        uint32_t desired = observed + 1U;
        if (__atomic_compare_exchange_n(&g_unpack_gen, &observed, desired, false, __ATOMIC_RELAXED,
                                        __ATOMIC_RELAXED)) {
            return desired;
        }
    }
    return UINT32_MAX;
}

static GPtrArray *g_vcpu_states = NULL;
static GMutex g_vcpu_states_lock;
static bool g_vcpu_states_lock_initialized = false;
static __thread unsigned int g_tls_vcpu_index = G_MAXUINT;
static __thread PluginVcpuState *g_tls_vcpu_state = NULL;

static bool plugin_vcpu_states_init(void) {
    if (g_vcpu_states_lock_initialized) {
        return g_vcpu_states != NULL;
    }
    g_mutex_init(&g_vcpu_states_lock);
    g_vcpu_states_lock_initialized = true;
    g_vcpu_states = g_ptr_array_new_with_free_func(g_free);
    if (!g_vcpu_states) {
        g_mutex_clear(&g_vcpu_states_lock);
        g_vcpu_states_lock_initialized = false;
        return false;
    }
    return true;
}

static PluginVcpuState *plugin_vcpu_state_get(unsigned int vcpu_index) {
    if (g_tls_vcpu_state && g_tls_vcpu_index == vcpu_index) {
        return g_tls_vcpu_state;
    }
    if (!g_vcpu_states_lock_initialized || !g_vcpu_states || !g_prov_registry ||
        vcpu_index == G_MAXUINT) {
        return NULL;
    }
    g_mutex_lock(&g_vcpu_states_lock);
    if (vcpu_index >= g_vcpu_states->len) {
        g_ptr_array_set_size(g_vcpu_states, vcpu_index + 1U);
    }
    PluginVcpuState *state = g_ptr_array_index(g_vcpu_states, vcpu_index);
    if (!state) {
        state = g_try_new0(PluginVcpuState, 1);
        if (!state || !dta_vcpu_state_init(&state->dta, vcpu_index, g_prov_registry)) {
            g_free(state);
            g_mutex_unlock(&g_vcpu_states_lock);
            return NULL;
        }
        g_ptr_array_index(g_vcpu_states, vcpu_index) = state;
    }
    g_mutex_unlock(&g_vcpu_states_lock);
    g_tls_vcpu_index = vcpu_index;
    g_tls_vcpu_state = state;
    return state;
}

static void plugin_vcpu_states_destroy(void) {
    if (!g_vcpu_states_lock_initialized) {
        return;
    }
    g_mutex_lock(&g_vcpu_states_lock);
    GPtrArray *states = g_vcpu_states;
    g_vcpu_states = NULL;
    g_mutex_unlock(&g_vcpu_states_lock);
    if (states)
        g_ptr_array_unref(states);
    g_mutex_clear(&g_vcpu_states_lock);
    g_vcpu_states_lock_initialized = false;
    g_tls_vcpu_index = G_MAXUINT;
    g_tls_vcpu_state = NULL;
}

static void provenance_runtime_destroy(void) {
    plugin_vcpu_states_destroy();
    if (g_prov_fd_table) {
        prov_fd_table_destroy(g_prov_fd_table);
        g_prov_fd_table = NULL;
    }
    if (g_shadow) {
        shadow_destroy(g_shadow);
        g_shadow = NULL;
    }
    if (g_prov_registry) {
        prov_registry_destroy(g_prov_registry);
        g_prov_registry = NULL;
    }
    g_main_image_resource_id = PROV_RESOURCE_ID_INVALID;
    g_main_image_object_id = 0;
}

static bool provenance_runtime_init(uint8_t guest_bits) {
    if (g_prov_registry || g_prov_fd_table || g_shadow) {
        return false;
    }
    g_prov_registry = prov_registry_create(NULL);
    if (!g_prov_registry)
        return false;
    g_shadow = shadow_create_with_registry(guest_bits, g_prov_registry);
    if (!g_shadow) {
        prov_registry_destroy(g_prov_registry);
        g_prov_registry = NULL;
        return false;
    }
    shadow_set_stats_enabled(g_shadow, g_dta_shadow_stats);
    if (!shadow_set_cmlb_enabled(g_shadow, g_dta_cmlb_enabled))
        fprintf(stderr, "[DTA] CMLB allocation failed; using ordinary shadow lookups\n");
    g_prov_fd_table = prov_fd_table_create(g_prov_registry);
    if (!g_prov_fd_table) {
        shadow_destroy(g_shadow);
        g_shadow = NULL;
        prov_registry_destroy(g_prov_registry);
        g_prov_registry = NULL;
        return false;
    }
    if (!plugin_vcpu_states_init()) {
        prov_fd_table_destroy(g_prov_fd_table);
        g_prov_fd_table = NULL;
        shadow_destroy(g_shadow);
        g_shadow = NULL;
        prov_registry_destroy(g_prov_registry);
        g_prov_registry = NULL;
        return false;
    }
    return true;
}

static bool main_image_path_init(void) {
    if (g_main_image_path) {
        return true;
    }
    const char *reported_path = qemu_plugin_path_to_binary();
    if (!reported_path || reported_path[0] == '\0') {
        if (reported_path) {
            g_free((gpointer)reported_path);
        }
        return false;
    }
    char *canonical_path = g_canonicalize_filename(reported_path, NULL);
    g_free((gpointer)reported_path);
    if (!canonical_path || canonical_path[0] == '\0') {
        g_free(canonical_path);
        return false;
    }
    g_main_image_path = canonical_path;
    return true;
}

static bool main_image_resource_init(void) {
    if (g_main_image_resource_id != PROV_RESOURCE_ID_INVALID) {
        return true;
    }
    if (!g_prov_registry || !g_main_image_path || g_main_image_path[0] == '\0') {
        return false;
    }
    if (g_main_image_object_id == 0) {
        if (g_next_resource_object_id == 0) {
            fprintf(stderr, "[PROV] resource object-id space exhausted\n");
            return false;
        }
        g_main_image_object_id = g_next_resource_object_id++;
    }
    ProvResourceKey key = {.kind = PROV_RESOURCE_FILE,
                           .scope_id = g_analysis_scope_id,
                           .object_id = g_main_image_object_id,
                           .semantic_version = 0};
    g_main_image_resource_id = prov_resource_intern(g_prov_registry, &key, g_main_image_path,
                                                    PROV_RESOURCE_ROLE_MAIN_IMAGE);
    if (g_main_image_resource_id == PROV_RESOURCE_ID_INVALID) {
        return false;
    }
    fprintf(stderr, "[PROV] main image resource=%u path=%s\n", g_main_image_resource_id,
            g_main_image_path);
    return true;
}

typedef struct {
    bool active;
    int64_t syscall_num;
    uint64_t requested_addr;
    uint64_t size;
    int prot;
    uint32_t flags;
    int32_t fd;
    uint64_t offset;
} pending_mmap_t;

static __thread pending_mmap_t g_pending_mmap;

typedef struct {
    uint64_t base;
    uint64_t size;
} pending_iov_t;

typedef struct {
    bool active;
    int64_t syscall_num;
    int32_t fd;
    bool taint_source;
    uint32_t iov_count;
    uint64_t requested_size;
    pending_iov_t iov[MAX_PENDING_IOV];
    bool source_identity_valid;
    ProvResourceId resource_id;
    uint64_t source_offset;
    bool advances_ofd;
} pending_input_t;

static __thread pending_input_t g_pending_input;

//read <=8 raw bytes from guest memory
static bool guest_read_bytes(uint64_t gaddr, uint8_t *out, uint32_t n) {
    GByteArray *b = g_byte_array_new();
    bool ok = qemu_plugin_read_memory_vaddr(gaddr, b, n) && b->len >= n;
    if (ok)
        memcpy(out, b->data, n);
    g_byte_array_free(b, TRUE);
    return ok;
}

//read uint of sz bytes, saves the active endianness.
static bool guest_read_uint(uint64_t gaddr, uint32_t sz, uint64_t *out) {
    uint8_t raw[8];
    if (sz > 8 || !guest_read_bytes(gaddr, raw, sz))
        return false;
    uint64_t v = 0;
    if (g_plugin_arch && g_plugin_arch->big_endian)
        for (uint32_t i = 0; i < sz; i++)
            v = (v << 8) | raw[i];
    else
        for (uint32_t i = 0; i < sz; i++)
            v |= (uint64_t)raw[i] << (8 * i);
    *out = v;
    return true;
}

//32 -> 4, 64 -> 8
static uint32_t guest_ptr_bytes(void) {
    uint32_t w;
    if (g_plugin_arch) {
        w = g_plugin_arch->natural_width;
    } else {
        w = 32;
    }
    return (w >= 64) ? 8 : 4;
}

static bool read_socketcall_args(uint64_t block_addr, uint32_t out[6]) {
    if (!guest_read_bytes(block_addr, (uint8_t *)out, 24))
        return false;
    return true;
}

gint compare_keys(gconstpointer a, gconstpointer b) {
    uint64_t addr_a = (uint64_t)(uintptr_t)a;
    uint64_t addr_b = (uint64_t)(uintptr_t)b;
    if (addr_a < addr_b)
        return -1;
    if (addr_a > addr_b)
        return 1;
    return 0;
}

static arch_t current_arch = ARCH_UNKNOWN;
static bool is_i386 = false;

typedef struct {
    char *path;
    bool write;
    bool taint_source;
    ProvResourceId resource_id;
    uint64_t resource_object_id;
} file_dep_t;

typedef struct {
    char *path;
    uint64_t base;
    uint64_t size;
    uint64_t end;
} lib_mapping_t;

typedef struct {
    int fd;
    char op[16];
    int domain;
    int type;
    char ip[INET6_ADDRSTRLEN];
    uint16_t port;
    char *payload_hex;
} net_dep_t;

static GList *file_deps = NULL;
static GList *net_deps = NULL;
static GList *lib_deps = NULL;
static GHashTable *g_sockets = NULL;
static GHashTable *file_fd = NULL;
//fd
static __thread char *pending_open_path = NULL;
static __thread bool pending_open_is_lib = false;
static __thread bool pending_open_write = false;
static __thread uint32_t pending_open_flags = 0;

typedef enum {
    PENDING_FD_NONE = 0,
    PENDING_FD_DUP,
    PENDING_FD_CLOSE,
    PENDING_FD_LSEEK,
    PENDING_FD_LLSEEK
} pending_fd_kind_t;

typedef struct {
    bool active;
    int64_t syscall_num;
    pending_fd_kind_t kind;
    int32_t fd;
    uint64_t result_address;
} pending_fd_operation_t;

static __thread pending_fd_operation_t g_pending_fd;
static GList *resolved_imports = NULL;
static GHashTable *resolved_imports_by_slot = NULL; //got slot thing

//all sorts of taint like from file, network, etc.
static bool fd_is_taint_source(int32_t fd) {
    if (fd < 0)
        return false;
    if (g_sockets && g_hash_table_contains(g_sockets, GINT_TO_POINTER(fd))) {
        return true;
    }

    if (file_fd) {
        file_dep_t *file = g_hash_table_lookup(file_fd, GINT_TO_POINTER(fd));
        if (file) {
            return file->taint_source;
        }
    }
    return true;
}

static bool shadow_fill_incomplete(uint64_t address, uint64_t size, uint64_t reasons);

static ProvLabelId dta_incomplete_unknown_label(uint64_t reasons);

static bool dse_read_reg(int rid, uint64_t *out);

static bool dse_resolve_mem_target(uint64_t vaddr, const InsnMeta *meta, uint64_t *out_addr,
                                   uint64_t *out_val);

static const char *branch_outcome_name(BranchOutcome outcome) {
    switch (outcome) {
    case BRANCH_OUTCOME_TAKEN:
        return "taken";
    case BRANCH_OUTCOME_NOT_TAKEN:
        return "not-taken";
    case BRANCH_OUTCOME_UNKNOWN:
    default:
        return "unknown";
    }
}

static bool guest_pc_equal(uint64_t left, uint64_t right) {
    if (is_i386) {
        return (uint32_t)left == (uint32_t)right;
    }
    return left == right;
}

static void log_branch_root_set(uint64_t event_id, const char *channel, ProvRootSetId set_id) {
    ProvRootSetView set;
    if (!prov_root_set_get(g_prov_registry, set_id, &set)) {
        return;
    }
    for (uint32_t index = 0; index < set.count; index++) {
        ProvRootKey root;
        if (!prov_root_get(g_prov_registry, set.roots[index], &root)) {
            continue;
        }
        if (root.kind == PROV_ROOT_RESOURCE_BYTE) {
            ProvResourceView resource;
            const char *name = "<unknown>";
            if (root.source_id <= UINT32_MAX &&
                prov_resource_get(g_prov_registry, (ProvResourceId)root.source_id, &resource) &&
                resource.display_name) {
                name = resource.display_name;
            }
            fprintf(stderr,
                    "[BRANCH-ROOT] event=%" PRIu64 " channel=%s root=%u"
                    " resource=%" PRIu64 " path=%s offset=%" PRIu64 "\n",
                    event_id, channel, set.roots[index], root.source_id, name, root.offset);
        } else {
            fprintf(stderr,
                    "[BRANCH-ROOT] event=%" PRIu64 " channel=%s root=%u"
                    " kind=%u source=%" PRIu64 " discriminator=%u"
                    " offset=%" PRIu64 " instance=%" PRIu64 "\n",
                    event_id, channel, set.roots[index], (unsigned)root.kind, root.source_id,
                    root.discriminator, root.offset, root.semantic_instance);
        }
    }
}

static void log_dcfg_target_root_set(DcfgEdgeId edge_id, uint64_t sequence_id, const char *channel,
                                     ProvRootSetId set_id) {
    if (!g_prov_registry || !channel) {
        return;
    }
    ProvRootSetView set;
    if (!prov_root_set_get(g_prov_registry, set_id, &set)) {
        return;
    }
    for (uint32_t index = 0; index < set.count; index++) {
        ProvRootKey root;
        if (!prov_root_get(g_prov_registry, set.roots[index], &root)) {
            continue;
        }
        if (root.kind == PROV_ROOT_RESOURCE_BYTE) {
            ProvResourceView resource;
            const char *name = "<unknown>";
            if (root.source_id <= UINT32_MAX &&
                prov_resource_get(g_prov_registry, (ProvResourceId)root.source_id, &resource) &&
                resource.display_name) {
                name = resource.display_name;
            }
            fprintf(stderr,
                    "[DCFG-TARGET-ROOT] edge=%u"
                    " seq=%" PRIu64 " channel=%s root=%u"
                    " resource=%" PRIu64 " path=%s offset=%" PRIu64 "\n",
                    edge_id, sequence_id, channel, set.roots[index], root.source_id, name,
                    root.offset);
        } else {
            fprintf(stderr,
                    "[DCFG-TARGET-ROOT] edge=%u"
                    " seq=%" PRIu64 " channel=%s root=%u"
                    " kind=%u source=%" PRIu64 " discriminator=%u"
                    " offset=%" PRIu64 " instance=%" PRIu64 "\n",
                    edge_id, sequence_id, channel, set.roots[index], (unsigned)root.kind,
                    root.source_id, root.discriminator, root.offset, root.semantic_instance);
        }
    }
}

static uint32_t dcfg_code_generation_for_pc(uint64_t pc) {
    if (!pages || page_size == 0 || (page_size & (page_size - 1U)) != 0) {
        return 0;
    }
    uint64_t page_address = pc & ~((uint64_t)page_size - 1U);
    page_t *page = g_hash_table_lookup(pages, (gpointer)(uintptr_t)page_address);
    return page ? page->gen_written : 0;
}

static DcfgNodeKey dcfg_node_key_for_pc(uint64_t pc) {
    DcfgNodeKey key = {.start_pc = is_i386 ? (uint64_t)(uint32_t)pc : pc,
                       .code_generation = dcfg_code_generation_for_pc(pc),
                       .bytes_hash = 0};
    return key;
}

static TraceArchKind trace_current_arch_kind(void) {
    switch (current_arch) {
    case ARCH_X86_32:
        return TRACE_ARCH_X86;
    case ARCH_ARM:
        return TRACE_ARCH_ARM;
    case ARCH_MIPS:
        return TRACE_ARCH_MIPS;
    case ARCH_UNKNOWN:
    default:
        return TRACE_ARCH_UNKNOWN;
    }
}

static void dcfg_set_current_block(PluginVcpuState *vcpu_state, DcfgNodeKey key) {
    if (!vcpu_state)
        return;
    vcpu_state->dcfg_block_active = true;
    vcpu_state->dcfg_block_key = key;
}

static void dcfg_track_instruction(PluginVcpuState *vcpu_state, uint64_t pc, uint8_t size) {
    if (!vcpu_state)
        return;
    bool contiguous = false;
    if (vcpu_state->dcfg_last_insn_valid) {
        uint64_t expected = vcpu_state->dcfg_last_insn_pc + vcpu_state->dcfg_last_insn_size;
        if (is_i386)
            expected = (uint32_t)expected;
        contiguous = guest_pc_equal(pc, expected);
    }
    if (!vcpu_state->dcfg_block_active || !contiguous) {
        dcfg_set_current_block(vcpu_state, dcfg_node_key_for_pc(pc));
    }
    vcpu_state->dcfg_last_insn_valid = true;
    vcpu_state->dcfg_last_insn_pc = is_i386 ? (uint64_t)(uint32_t)pc : pc;
    vcpu_state->dcfg_last_insn_size = size;
}

static DcfgEdgeKind dcfg_jcc_kind(BranchOutcome outcome) {
    switch (outcome) {
    case BRANCH_OUTCOME_TAKEN:
        return DCFG_EDGE_JCC_TAKEN;
    case BRANCH_OUTCOME_NOT_TAKEN:
        return DCFG_EDGE_JCC_FALLTHROUGH;
    case BRANCH_OUTCOME_UNKNOWN:
    default:
        return DCFG_EDGE_JCC_UNKNOWN;
    }
}

static DcfgEdgeKind dcfg_control_transfer_kind(const InsnMeta *meta) {
    if (!meta || meta->is_conditional_branch) {
        return DCFG_EDGE_INVALID;
    }
    switch (meta->insn_id) {
    case X86_INS_JMP:
        return meta->is_indirect_branch ? DCFG_EDGE_INDIRECT_JMP : DCFG_EDGE_DIRECT_JMP;
    case X86_INS_CALL:
        return DCFG_EDGE_CALL;
    case X86_INS_RET:
        return DCFG_EDGE_RET;
    default:
        return DCFG_EDGE_INVALID;
    }
}

static void log_dcfg_transfer(const dcfg_pending_transfer_t *pending, DcfgEdgeId edge_id) {
    if (!pending || !g_dcfg || edge_id == DCFG_EDGE_ID_INVALID) {
        return;
    }
    DcfgEdgeView edge;
    DcfgNodeView source;
    DcfgNodeView target;
    if (!dcfg_edge_get(g_dcfg, edge_id, &edge) ||
        !dcfg_node_get(g_dcfg, edge.source_node, &source) ||
        !dcfg_node_get(g_dcfg, edge.target_node, &target)) {
        return;
    }
    ProvLabelView target_label;
    bool target_label_valid =
        g_prov_registry && prov_label_get(g_prov_registry, pending->target_label, &target_label);
    uint8_t complete_mask = target_label_valid ? target_label.complete_mask : 0;
    uint64_t incomplete_reasons =
        target_label_valid ? target_label.incomplete_reasons : PROV_INCOMPLETE_UNKNOWN;
    fprintf(stderr,
            "[DCFG-XFER] edge=%u"
            " src-node=%u dst-node=%u"
            " src=0x%" PRIx64 " dst=0x%" PRIx64 " pc=0x%" PRIx64 " src-gen=%u dst-gen=%u"
            " kind=%s count=%" PRIu64 " seq=%" PRIu64 " expected-valid=%u"
            " expected=0x%" PRIx64 " target-label=%u"
            " target-summary=%u"
            " complete=0x%02x"
            " reasons=0x%" PRIx64 "\n",
            edge.edge_id, edge.source_node, edge.target_node, source.key.start_pc,
            target.key.start_pc, pending->instruction_pc, source.key.code_generation,
            target.key.code_generation, dcfg_edge_kind_name(edge.kind), edge.occurrence_count,
            pending->trace_seq_id, pending->expected_target_valid ? 1U : 0U,
            pending->expected_target, pending->target_label, edge.target_summary, complete_mask,
            incomplete_reasons);
    if (target_label_valid) {
        log_dcfg_target_root_set(edge_id, pending->trace_seq_id, "data", target_label.data_roots);
        log_dcfg_target_root_set(edge_id, pending->trace_seq_id, "address",
                                 target_label.address_roots);
    }
}

static void finalize_pending_transfer(PluginVcpuState *vcpu_state, uint64_t observed_next_pc) {
    if (!vcpu_state || !vcpu_state->dcfg_pending_transfer.active) {
        return;
    }
    dcfg_pending_transfer_t pending = vcpu_state->dcfg_pending_transfer;
    memset(&vcpu_state->dcfg_pending_transfer, 0, sizeof(vcpu_state->dcfg_pending_transfer));
    DcfgNodeKey target_key = dcfg_node_key_for_pc(observed_next_pc);
    dcfg_set_current_block(vcpu_state, target_key);
    if (pending.expected_target_valid &&
        !guest_pc_equal(pending.expected_target, observed_next_pc)) {
        fprintf(stderr,
                "[DCFG] transfer target mismatch"
                " pc=0x%" PRIx64 " expected=0x%" PRIx64 " observed=0x%" PRIx64 "\n",
                pending.instruction_pc, pending.expected_target, observed_next_pc);
    }

    if (!g_dcfg) {
        if (g_trace) {
            (void)trace_record_control_transfer(g_trace, pending.trace_seq_id, DCFG_EDGE_ID_INVALID,
                                                pending.target_label);
        }
        return;
    }
    DcfgBranchObservation observation = {.source = pending.source,
                                         .target = target_key,
                                         .kind = pending.kind,
                                         .branch_seq_id = pending.trace_seq_id,
                                         .vcpu_index = vcpu_state->dta.vcpu_index,
                                         .condition_label = PROV_LABEL_CLEAN,
                                         .target_label = pending.target_label};
    DcfgEdgeId edge_id = DCFG_EDGE_ID_INVALID;

    if (!dcfg_record_branch(g_dcfg, &observation, &edge_id)) {
        if (g_trace) {
            (void)trace_record_control_transfer(g_trace, pending.trace_seq_id, DCFG_EDGE_ID_INVALID,
                                                pending.target_label);
        }
        fprintf(stderr,
                "[DCFG] failed to record transfer"
                " pc=0x%" PRIx64 " next=0x%" PRIx64 " seq=%" PRIu64 "\n",
                pending.instruction_pc, observed_next_pc, pending.trace_seq_id);
        return;
    }
    if (g_trace && !trace_record_control_transfer(g_trace, pending.trace_seq_id, edge_id,
                                                  pending.target_label)) {
        fprintf(stderr,
                "[TRACE] failed to attach control transfer"
                " seq=%" PRIu64 " edge=%u\n",
                pending.trace_seq_id, edge_id);
    }
    log_dcfg_transfer(&pending, edge_id);
}

static ProvLabelId dcfg_join_target_labels(const ProvLabelId *labels, uint32_t count,
                                           uint64_t failure_reason) {
    if (!g_prov_registry || (count != 0 && !labels)) {
        return PROV_LABEL_ID_INVALID;
    }
    ProvLabelId joined = prov_label_join_many(g_prov_registry, labels, count);
    if (joined != PROV_LABEL_ID_INVALID) {
        return joined;
    }
    return dta_incomplete_unknown_label(failure_reason);
}

static ProvLabelId dcfg_register_target_label(const dta_mem_transfer_t *transfer,
                                              const InsnMeta *meta) {
    if (!transfer || !meta || !reg_slice_is_valid(meta->branch_target_slice)) {
        return dta_incomplete_unknown_label(PROV_INCOMPLETE_IMPLICIT_OPERAND);
    }
    ProvLabelId labels[MAX_REG_BYTES];
    if (!reg_slice_load_labels(&transfer->pre_regs, meta->branch_target_slice, labels)) {
        return dta_incomplete_unknown_label(PROV_INCOMPLETE_IMPLICIT_OPERAND);
    }
    return dcfg_join_target_labels(labels, meta->branch_target_slice.width,
                                   PROV_INCOMPLETE_IMPLICIT_OPERAND);
}

static ProvLabelId dcfg_memory_target_label(uint64_t instruction_pc,
                                            const dta_mem_transfer_t *transfer,
                                            const InsnMeta *meta, bool *out_expected_target_valid,
                                            uint64_t *out_expected_target) {
    if (out_expected_target_valid) {
        *out_expected_target_valid = false;
    }
    if (out_expected_target) {
        *out_expected_target = 0;
    }
    if (!g_shadow || !transfer || !meta) {
        return dta_incomplete_unknown_label(PROV_INCOMPLETE_UNRESOLVED_MEMORY);
    }

    uint64_t target_address = 0;
    uint64_t target_value = 0;
    if (!dse_resolve_mem_target(instruction_pc, meta, &target_address, &target_value)) {
        return dta_incomplete_unknown_label(PROV_INCOMPLETE_UNRESOLVED_MEMORY);
    }
    if (is_i386) {
        target_value = (uint32_t)target_value;
    }
    if (out_expected_target_valid) {
        *out_expected_target_valid = true;
    }
    if (out_expected_target) {
        *out_expected_target = target_value;
    }
    uint32_t width = guest_ptr_bytes();
    if (width == 0 || width > MAX_REG_BYTES) {
        return dta_incomplete_unknown_label(PROV_INCOMPLETE_UNRESOLVED_MEMORY);
    }

    ProvLabelId raw_labels[MAX_REG_BYTES];
    ProvLabelId effective_labels[MAX_REG_BYTES];
    if (!shadow_load_labels(g_shadow, target_address, raw_labels, width) ||
        !dta_effective_mem_read_labels(&transfer->pre_regs, meta, raw_labels, (uint8_t)width,
                                       effective_labels)) {
        return dta_incomplete_unknown_label(PROV_INCOMPLETE_UNRESOLVED_MEMORY);
    }

    return dcfg_join_target_labels(effective_labels, width, PROV_INCOMPLETE_UNRESOLVED_MEMORY);
}

static void begin_pending_transfer(PluginVcpuState *vcpu_state, const InsnMeta *meta,
                                   uint64_t trace_seq_id) {
    if (!vcpu_state || !meta || trace_seq_id == 0) {
        return;
    }
    DcfgEdgeKind kind = dcfg_control_transfer_kind(meta);
    if (kind == DCFG_EDGE_INVALID)
        return;
    dcfg_pending_transfer_t pending;
    memset(&pending, 0, sizeof(pending));
    pending.active = true;
    pending.kind = kind;
    pending.source =
        vcpu_state->dcfg_block_active ? vcpu_state->dcfg_block_key : dcfg_node_key_for_pc(meta->pc);
    pending.instruction_pc = is_i386 ? (uint64_t)(uint32_t)meta->pc : meta->pc;
    pending.trace_seq_id = trace_seq_id;
    pending.target_label = PROV_LABEL_CLEAN;

    if (meta->direct_target_valid) {
        pending.expected_target_valid = true;
        pending.expected_target =
            is_i386 ? (uint64_t)(uint32_t)meta->direct_target : meta->direct_target;
    } else if (meta->is_indirect_branch && meta->branch_target_reg >= 0 &&
               meta->branch_target_reg < REG_COUNT) {
        pending.target_label = dcfg_register_target_label(&vcpu_state->mem_transfer, meta);
        uint64_t concrete_target = 0;
        if (dse_read_reg(meta->branch_target_reg, &concrete_target)) {
            uint32_t shift = (uint32_t)meta->branch_target_slice.byte_offset * 8U;
            uint32_t bits = (uint32_t)meta->branch_target_slice.width * 8U;
            concrete_target >>= shift;
            if (bits < 64U) {
                concrete_target &= (UINT64_C(1) << bits) - UINT64_C(1);
            }
            pending.expected_target_valid = true;
            pending.expected_target =
                is_i386 ? (uint64_t)(uint32_t)concrete_target : concrete_target;
        }
    } else if (meta->is_indirect_branch) {
        pending.target_label =
            dcfg_memory_target_label(pending.instruction_pc, &vcpu_state->mem_transfer, meta,
                                     &pending.expected_target_valid, &pending.expected_target);
    }
    if (!g_prov_registry || !prov_label_is_valid(g_prov_registry, pending.target_label)) {
        pending.target_label = dta_incomplete_unknown_label(PROV_INCOMPLETE_UNKNOWN);
    }
    if (pending.target_label == PROV_LABEL_ID_INVALID) {
        return;
    }
    vcpu_state->dcfg_pending_transfer = pending;
}

static void log_dcfg_branch(const BranchEvent *event) {
    if (!event || !g_dcfg || event->dcfg_edge_id == DCFG_EDGE_ID_INVALID) {
        return;
    }
    DcfgEdgeView edge;
    DcfgNodeView source;
    DcfgNodeView target;
    if (!dcfg_edge_get(g_dcfg, event->dcfg_edge_id, &edge) ||
        !dcfg_node_get(g_dcfg, edge.source_node, &source) ||
        !dcfg_node_get(g_dcfg, edge.target_node, &target)) {
        return;
    }
    fprintf(stderr,
            "[DCFG-JCC] event=%" PRIu64 " edge=%u"
            " src-node=%u"
            " dst-node=%u"
            " src=0x%" PRIx64 " dst=0x%" PRIx64 " pc=0x%" PRIx64 " src-gen=%u"
            " dst-gen=%u"
            " kind=%s"
            " count=%" PRIu64 " seq=%" PRIu64 " label=%u\n",
            event->event_id, edge.edge_id, edge.source_node, edge.target_node, source.key.start_pc,
            target.key.start_pc, event->pc, source.key.code_generation, target.key.code_generation,
            dcfg_edge_kind_name(edge.kind), edge.occurrence_count, event->branch_seq_id,
            event->condition_label);
}

static void log_branch_event(const BranchEvent *event) {
    if (!event || !g_prov_registry) {
        return;
    }
    ProvLabelView label;
    if (!prov_label_get(g_prov_registry, event->condition_label, &label)) {
        fprintf(stderr, "[BRANCH-PROV] event=%" PRIu64 " invalid-label=%u\n", event->event_id,
                event->condition_label);
        return;
    }
    fprintf(stderr,
            "[BRANCH-PROV] event=%" PRIu64 " edge=%u"
            " seq=%" PRIu64 " vcpu=%u pc=0x%" PRIx64 " next=0x%" PRIx64 " outcome=%s cc=%u label=%u"
            " complete=0x%02x reasons=0x%" PRIx64 "\n",
            event->event_id, event->dcfg_edge_id, event->branch_seq_id, event->vcpu_index,
            event->pc, event->observed_next_pc, branch_outcome_name(event->outcome),
            (unsigned)event->condition_code, event->condition_label, label.complete_mask,
            label.incomplete_reasons);

    log_branch_root_set(event->event_id, "data", label.data_roots);
    log_branch_root_set(event->event_id, "address", label.address_roots);
    log_dcfg_branch(event);
}

static void finalize_pending_branch(PluginVcpuState *vcpu_state, uint64_t observed_next_pc) {
    if (!vcpu_state || !vcpu_state->dta.pending_branch.active) {
        return;
    }
    DtaPendingBranch pending = vcpu_state->dta.pending_branch;
    dta_pending_branch_clear(&vcpu_state->dta);
    DcfgNodeKey source_key = vcpu_state->dcfg_block_active ? vcpu_state->dcfg_block_key
                                                           : dcfg_node_key_for_pc(pending.pc);
    DcfgNodeKey target_key = dcfg_node_key_for_pc(observed_next_pc);
    dcfg_set_current_block(vcpu_state, target_key);
    if (!g_branch_events) {
        if (g_trace) {
            (void)trace_record_control_transfer(g_trace, pending.seq_id, DCFG_EDGE_ID_INVALID,
                                                PROV_LABEL_CLEAN);
        }
        return;
    }
    BranchEvent event;
    memset(&event, 0, sizeof(event));
    event.branch_seq_id = pending.seq_id;
    event.vcpu_index = vcpu_state->dta.vcpu_index;
    event.meta_id = pending.meta_id;
    event.pc = pending.pc;
    event.fallthrough = pending.fallthrough;
    event.direct_target_valid = pending.direct_target_valid;
    event.direct_target = pending.direct_target;
    event.observed_next_pc = observed_next_pc;
    event.condition_code = pending.condition_code;
    event.condition_label = pending.condition_label;
    event.dcfg_edge_id = DCFG_EDGE_ID_INVALID;
    event.outcome = BRANCH_OUTCOME_UNKNOWN;
    bool is_fallthrough = guest_pc_equal(observed_next_pc, pending.fallthrough);
    bool is_target =
        pending.direct_target_valid && guest_pc_equal(observed_next_pc, pending.direct_target);
    if (is_fallthrough && !is_target) {
        event.outcome = BRANCH_OUTCOME_NOT_TAKEN;
    } else if (is_target && !is_fallthrough) {
        event.outcome = BRANCH_OUTCOME_TAKEN;
    }
    if (g_dcfg) {
        DcfgBranchObservation observation = {.source = source_key,
                                             .target = target_key,
                                             .kind = dcfg_jcc_kind(event.outcome),
                                             .branch_seq_id = event.branch_seq_id,
                                             .vcpu_index = event.vcpu_index,
                                             .condition_label = event.condition_label,
                                             .target_label = PROV_LABEL_CLEAN};
        if (!dcfg_record_branch(g_dcfg, &observation, &event.dcfg_edge_id)) {
            fprintf(stderr,
                    "[DCFG] failed to record Jcc"
                    " pc=0x%" PRIx64 " next=0x%" PRIx64 " seq=%" PRIu64 "\n",
                    event.pc, event.observed_next_pc, event.branch_seq_id);
        }
    }
    if (g_trace && !trace_record_control_transfer(g_trace, event.branch_seq_id, event.dcfg_edge_id,
                                                  PROV_LABEL_CLEAN)) {
        fprintf(stderr,
                "[TRACE] failed to attach conditional transfer"
                " seq=%" PRIu64 " edge=%u\n",
                event.branch_seq_id, event.dcfg_edge_id);
    }
    const BranchEvent *stored = branch_event_append(g_branch_events, &event);
    if (stored)
        log_branch_event(stored);
}

static void begin_pending_branch(PluginVcpuState *vcpu_state, const InsnMeta *meta,
                                 uint64_t trace_seq_id) {
    if (!vcpu_state || !meta || !meta->is_conditional_branch || trace_seq_id == 0) {
        return;
    }
    ProvLabelId condition_label = dta_flag_join_mask(&vcpu_state->dta, meta->flags_read_mask);
    if (condition_label == PROV_LABEL_ID_INVALID) {
        condition_label = dta_incomplete_unknown_label(PROV_INCOMPLETE_UNDEFINED_FLAG);
    }
    if (condition_label == PROV_LABEL_ID_INVALID) {
        return;
    }
    uint64_t fallthrough = meta->pc + meta->size;
    uint64_t direct_target = meta->direct_target;
    if (is_i386) {
        fallthrough = (uint32_t)fallthrough;
        direct_target = (uint32_t)direct_target;
    }
    (void)dta_pending_branch_begin(&vcpu_state->dta, trace_seq_id, meta->meta_id, meta->pc,
                                   fallthrough, meta->direct_target_valid, direct_target,
                                   meta->condition_code, condition_label);
}

static void finalize_missing_memory_flag_transfer(PluginVcpuState *vcpu_state) {
    if (!vcpu_state)
        return;
    dta_mem_transfer_t *transfer = &vcpu_state->mem_transfer;
    if (!transfer->active || !transfer->flags_pending || transfer->flags_applied ||
        !transfer->meta) {
        return;
    }
    (void)dta_apply_flag_transfer(&vcpu_state->dta, &transfer->pre_regs, transfer->meta, NULL, 0);
    transfer->flags_applied = true;
    g_taint_seen = true;
}

static void pending_input_attach_ofd(bool explicit_offset_valid, uint64_t explicit_offset) {
    if (!g_pending_input.active || !g_prov_fd_table) {
        return;
    }
    ProvOpenFileDescriptionView ofd;
    if (!prov_fd_table_lookup(g_prov_fd_table, g_pending_input.fd, &ofd)) {
        return;
    }
    if (ofd.resource_id == PROV_RESOURCE_ID_INVALID) {
        return;
    }
    g_pending_input.source_identity_valid = true;
    g_pending_input.resource_id = ofd.resource_id;
    g_pending_input.source_offset = explicit_offset_valid ? explicit_offset : ofd.current_offset;
    g_pending_input.advances_ofd = !explicit_offset_valid;
}

static void pending_input_reset(void) {
    memset(&g_pending_input, 0, sizeof(g_pending_input));
}

static void pending_input_capture_linear(int64_t syscall_num, int32_t fd, uint64_t buffer,
                                         uint64_t size, bool force_taint,
                                         bool explicit_offset_valid, uint64_t explicit_offset) {
    if (size == 0)
        return;
    g_pending_input.active = true;
    g_pending_input.syscall_num = syscall_num;
    g_pending_input.fd = fd;
    g_pending_input.taint_source = force_taint || fd_is_taint_source(fd);
    g_pending_input.iov_count = 1;
    g_pending_input.requested_size = size;
    g_pending_input.iov[0].base = buffer;
    g_pending_input.iov[0].size = size;
    pending_input_attach_ofd(explicit_offset_valid, explicit_offset);
}

static bool pending_input_capture_iov(int64_t syscall_num, int32_t fd, uint64_t iov_addr,
                                      int64_t iov_count, bool force_taint) {
    if (iov_count <= 0) {
        return iov_count == 0;
    }

    if ((uint64_t)iov_count > MAX_PENDING_IOV) {
        fprintf(stderr, "[DTA] readv iov_count=%ld exceeds limit %u\n", (long)iov_count,
                MAX_PENDING_IOV);
        return false;
    }

    uint32_t word_size = guest_ptr_bytes();
    uint64_t entry_size = (uint64_t)word_size * 2U;
    uint64_t requested_size = 0;
    for (uint32_t i = 0; i < (uint32_t)iov_count; i++) {
        if ((uint64_t)i > (UINT64_MAX - iov_addr) / entry_size) {
            fprintf(stderr, "[DTA] readv iovec address overflow\n");
            return false;
        }

        uint64_t entry = iov_addr + (uint64_t)i * entry_size;
        uint64_t base = 0;
        uint64_t size = 0;
        if (!guest_read_uint(entry, word_size, &base) ||
            !guest_read_uint(entry + word_size, word_size, &size)) {
            fprintf(stderr, "[DTA] failed to read iovec[%u] at 0x%lx\n", i, (unsigned long)entry);
            return false;
        }

        g_pending_input.iov[i].base = base;
        g_pending_input.iov[i].size = size;

        if (size > UINT64_MAX - requested_size) {
            fprintf(stderr, "[DTA] readv requested size overflow\n");
            return false;
        }
        requested_size += size;
    }
    if (requested_size == 0) {
        return true;
    }
    g_pending_input.active = true;
    g_pending_input.syscall_num = syscall_num;
    g_pending_input.fd = fd;
    g_pending_input.taint_source = force_taint || fd_is_taint_source(fd);
    g_pending_input.iov_count = (uint32_t)iov_count;
    g_pending_input.requested_size = requested_size;
    pending_input_attach_ofd(false, 0);
    return true;
}

static bool seed_resource_byte_labels(uint64_t guest_address, uint64_t size,
                                      ProvResourceId resource_id, uint64_t resource_offset) {
    if (!g_shadow || !g_prov_registry || resource_id == PROV_RESOURCE_ID_INVALID) {
        return false;
    }
    if (size == 0)
        return true;
    if (size - 1U > UINT64_MAX - guest_address || size - 1U > UINT64_MAX - resource_offset) {
        (void)shadow_fill_incomplete(guest_address, size, PROV_INCOMPLETE_SOURCE_IDENTITY);
        return false;
    }

    for (uint64_t byte = 0; byte < size; byte++) {
        ProvRootKey root_key = {.kind = PROV_ROOT_RESOURCE_BYTE,
                                .source_id = resource_id,
                                .discriminator = 0,
                                .offset = resource_offset + byte,
                                .semantic_instance = 0};
        ProvRootId root_id = prov_root_intern(g_prov_registry, &root_key);
        ProvLabelId label_id =
            root_id == PROV_ROOT_ID_INVALID
                ? PROV_LABEL_ID_INVALID
                : prov_label_from_root(g_prov_registry, root_id, PROV_CHANNEL_DATA);
        if (label_id == PROV_LABEL_ID_INVALID ||
            !shadow_store_label(g_shadow, guest_address + byte, label_id)) {
            uint64_t remaining = size - byte;
            (void)shadow_fill_incomplete(guest_address + byte, remaining,
                                         PROV_INCOMPLETE_SOURCE_IDENTITY);
            return false;
        }
    }
    return true;
}

static void apply_pending_input(int64_t syscall_num, int64_t syscall_ret) {
    if (!g_pending_input.active)
        return;
    if (g_pending_input.syscall_num != syscall_num) {
        fprintf(stderr, "[DTA] pending input mismatch: expected=%ld actual=%ld\n",
                (long)g_pending_input.syscall_num, (long)syscall_num);
        pending_input_reset();
        return;
    }
    if (syscall_ret <= 0) {
        pending_input_reset();
        return;
    }
    uint64_t completed = (uint64_t)syscall_ret;
    if (completed > g_pending_input.requested_size) {
        completed = g_pending_input.requested_size;
    }
    uint64_t remaining = completed;
    uint64_t source_displacement = 0;
    bool produced_taint = false;
    for (uint32_t index = 0; index < g_pending_input.iov_count && remaining != 0; index++) {
        uint64_t chunk = g_pending_input.iov[index].size;
        if (chunk > remaining) {
            chunk = remaining;
        }
        if (chunk == 0)
            continue;
        uint64_t destination = g_pending_input.iov[index].base;
        if (!g_pending_input.taint_source) {
            shadow_untaint_range(g_shadow, destination, chunk);
        } else if (g_pending_input.source_identity_valid &&
                   source_displacement <= (UINT64_MAX - g_pending_input.source_offset)) {
            uint64_t offset = g_pending_input.source_offset + source_displacement;
            if (!seed_resource_byte_labels(destination, chunk, g_pending_input.resource_id,
                                           offset)) {
                fprintf(stderr,
                        "[PROV] partial file-byte "
                        "seeding: fd=%d "
                        "addr=0x%" PRIx64 " size=0x%" PRIx64 "\n",
                        g_pending_input.fd, destination, chunk);
            }
            produced_taint = true;
        } else {
            if (!shadow_fill_incomplete(destination, chunk, PROV_INCOMPLETE_SOURCE_IDENTITY)) {
                fprintf(stderr,
                        "[PROV] failed to store "
                        "incomplete source label: "
                        "addr=0x%" PRIx64 " size=0x%" PRIx64 "\n",
                        destination, chunk);
            }
            produced_taint = true;
        }
        source_displacement += chunk;
        remaining -= chunk;
    }

    if (g_pending_input.source_identity_valid && g_pending_input.advances_ofd && completed != 0 &&
        !prov_fd_table_advance(g_prov_fd_table, g_pending_input.fd, completed)) {
        fprintf(stderr,
                "[PROV] failed to advance OFD: "
                "fd=%d bytes=%" PRIu64 "\n",
                g_pending_input.fd, completed);
    }
    if (produced_taint) {
        g_taint_seen = true;
    }
    pending_input_reset();
}

//stub for dynamic reconstruction
static const char *addr_lib_path(uint64_t addr) {
    if (addr == 0)
        return NULL;
    for (GList *l = lib_deps; l; l = l->next) {
        lib_mapping_t *lm = (lib_mapping_t *)l->data;
        if (!lm->base)
            continue;
        uint64_t end = (lm->end > lm->base) ? lm->end : (lm->base + lm->size);
        if (end <= lm->base)
            continue;
        if (addr >= lm->base && addr < end)
            return lm->path;
    }
    return NULL;
}

static uint64_t addr_lib_base(uint64_t addr) {
    if (addr == 0)
        return 0;
    for (GList *l = lib_deps; l; l = l->next) {
        lib_mapping_t *lm = (lib_mapping_t *)l->data;
        if (!lm->base)
            continue;
        uint64_t end = (lm->end > lm->base) ? lm->end : (lm->base + lm->size);
        if (end <= lm->base)
            continue;
        if (addr >= lm->base && addr < end)
            return lm->base;
    }
    return 0;
}

static const char *base_name(const char *path) {
    if (!path)
        return NULL;
    const char *s = strrchr(path, '/');
    return s ? s + 1 : path;
}

static bool syscall_ret_is_error(int64_t ret) {
    if (is_i386) {
        const uint32_t raw_ret = (uint32_t)ret;
        return raw_ret >= UINT32_MAX - 4094U;
    }
    return ret < 0;
}

static void record_resolved_import(uint64_t got_slot, uint64_t resolved_addr) {
    if (!resolved_addr)
        return;
    uint64_t lib_base = addr_lib_base(resolved_addr);
    if (!lib_base)
        return;
    if (addr_lib_base(got_slot))
        return;
    if (g_main_known && (got_slot < g_main_lo || got_slot >= g_main_hi))
        return;
    if (resolved_imports_by_slot &&
        g_hash_table_contains(resolved_imports_by_slot, (gpointer)(uintptr_t)got_slot))
        return;
    resolved_import_t *ri = g_new0(resolved_import_t, 1);
    ri->got_slot = got_slot;
    ri->resolved_addr = resolved_addr;
    ri->module = addr_lib_path(resolved_addr);
    ri->lib_base = lib_base;
    resolved_imports = g_list_append(resolved_imports, ri);
    if (resolved_imports_by_slot)
        g_hash_table_add(resolved_imports_by_slot, (gpointer)(uintptr_t)got_slot);
}

static bool parse_guest_sockaddr(uint64_t gaddr, int addrlen, char *ip_out, size_t ip_size,
                                 uint16_t *port_out) {
    if (addrlen <= 0 || gaddr == 0 || !ip_out || !port_out)
        return false;
    memset(ip_out, 0, ip_size);
    *port_out = 0;

    GByteArray *arr = g_byte_array_new();
    if (!qemu_plugin_read_memory_vaddr(gaddr, arr, addrlen)) {
        g_byte_array_free(arr, TRUE);
        return false;
    }

    bool parsed = false;
    if (arr->len >= sizeof(struct sockaddr_in)) {
        struct sockaddr_in *sin = (struct sockaddr_in *)arr->data;
        if (sin->sin_family == AF_INET) {
            inet_ntop(AF_INET, &sin->sin_addr, ip_out, ip_size);
            *port_out = ntohs(sin->sin_port);
            parsed = true;
        } else if (sin->sin_family == AF_INET6 && arr->len >= sizeof(struct sockaddr_in6)) {
            struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)arr->data;
            inet_ntop(AF_INET6, &sin6->sin6_addr, ip_out, ip_size);
            *port_out = ntohs(sin6->sin6_port);
            parsed = true;
        }
    }
    g_byte_array_free(arr, TRUE);
    return parsed;
}

static char *read_guest_string(uint64_t gaddr) {
    if (gaddr == 0)
        return NULL;

    GString *s = g_string_new(NULL);
    uint8_t chunk[64];
    for (size_t off = 0; off < 4096; off += sizeof chunk) {
        if (!guest_read_bytes(gaddr + off, chunk, sizeof chunk))
            break;
        size_t i = 0;
        for (; i < sizeof chunk; i++) {
            if (chunk[i] == '\0')
                break;
            g_string_append_c(s, chunk[i]);
        }
        if (i < sizeof chunk)
            break;
    }

    if (s->len == 0) {
        g_string_free(s, TRUE);
        return NULL;
    }
    return g_string_free(s, FALSE);
}

//dse helpers
static void dse_init_reg_handles(void) {
    GArray *regs = qemu_plugin_get_registers();
    if (!regs) {
        fprintf(stderr, "[REG] failed to enumerate QEMU registers\n");
        return;
    }
    memset(g_reg_handle, 0, sizeof(g_reg_handle));
    g_eflags_handle = NULL;
    int found = 0;
    for (guint i = 0; i < regs->len; i++) {
        qemu_plugin_reg_descriptor *descriptor =
            &g_array_index(regs, qemu_plugin_reg_descriptor, i);
        if (descriptor->name && (g_ascii_strcasecmp(descriptor->name, "eflags") == 0 ||
                                 g_ascii_strcasecmp(descriptor->name, "rflags") == 0)) {
            g_eflags_handle = descriptor->handle;
            fprintf(stderr, "[REG] QEMU reg: %s\n", descriptor->name);
        }
        for (int reg = 0; reg < 8; reg++) {
            if (!descriptor->name ||
                g_ascii_strcasecmp(descriptor->name, g_reg_name_i386[reg]) != 0) {
                continue;
            }
            if (!g_reg_handle[reg])
                found++;
            g_reg_handle[reg] = descriptor->handle;
            fprintf(stderr, "[REG] QEMU reg: %s\n", descriptor->name);
        }
    }
    g_array_free(regs, TRUE);
    g_regs_ready = found == 8;
    if (!g_regs_ready) {
        fprintf(stderr, "[REG] incomplete i386 register set: found %d/8\n", found);
    }
    if (!g_eflags_handle) {
        fprintf(
            stderr,
            "[REG] eflags/rflags register is unavailable; path-sensitive DSE will remain incomplete\n");
    }
}

static void dse_vcpu_init(qemu_plugin_id_t id, unsigned int vcpu_index) {
    (void)id;
    __atomic_fetch_add(&g_ir_vcpus, 1U, __ATOMIC_RELEASE);
    if (!plugin_vcpu_state_get(vcpu_index)) {
        fprintf(stderr, "[DTA] failed to initialize vCPU state: vcpu=%u\n", vcpu_index);
        return;
    }
    if (!g_regs_ready) {
        dse_init_reg_handles();
    }
}

static bool dse_read_reg(int rid, uint64_t *out) {
    if (!out || rid < 0 || rid >= REG_COUNT || !g_regs_ready || !g_reg_handle[rid])
        return false;
    static __thread GByteArray *buf = NULL;
    if (!buf)
        buf = g_byte_array_new();
    g_byte_array_set_size(buf, 0);
    int rc = qemu_plugin_read_register(g_reg_handle[rid], buf);
    if (rc <= 0 || buf->len == 0) {
        if (!g_reg_read_error_reported[rid]) {
            fprintf(stderr, "[REG] read failed for %s: rc=%d len=%u\n", g_reg_name_i386[rid], rc,
                    buf->len);
            g_reg_read_error_reported[rid] = true;
        }
        return false;
    }

    size_t n = buf->len < 4 ? buf->len : 4;
    uint64_t v = 0;
    for (size_t i = 0; i < n; i++)
        v |= (uint64_t)buf->data[i] << (8 * i);
    *out = v & 0xFFFFFFFFULL;
    return true;
}

static bool dse_read_eflags(uint32_t *out) {
    if (!out || !g_eflags_handle || !g_x86_flags_verified)
        return false;
    static __thread GByteArray *buf = NULL;
    static bool error_reported = false;
    if (!buf)
        buf = g_byte_array_new();
    g_byte_array_set_size(buf, 0);
    int rc = qemu_plugin_read_register(g_eflags_handle, buf);
    if (rc != 4 || buf->len != 4) {
        if (!error_reported) {
            fprintf(stderr, "[REG] read failed for eflags: rc=%d len=%u\n", rc, buf->len);
            error_reported = true;
        }
        return false;
    }
    uint32_t value = 0;
    size_t count = buf->len < 4 ? buf->len : 4;
    for (size_t i = 0; i < count; i++) {
        value |= (uint32_t)buf->data[i] << (8U * i);
    }
    *out = value;
    return true;
}

static uint32_t dse_read_register_snapshot(uint64_t values[REG_COUNT]) {
    if (!values)
        return 0;
    memset(values, 0, sizeof(uint64_t) * REG_COUNT);
    if (!g_regs_ready)
        dse_init_reg_handles();
    uint32_t valid_mask = 0;
    for (int rid = 0; rid < REG_COUNT; rid++) {
        uint64_t value = 0;
        if (dse_read_reg(rid, &value)) {
            values[rid] = value;
            valid_mask |= UINT32_C(1) << rid;
        }
    }
    return valid_mask;
}

static bool dse_resolve_mem_target(uint64_t vaddr, const InsnMeta *meta, uint64_t *out_addr,
                                   uint64_t *out_val) {
    if (!g_regs_ready)
        dse_init_reg_handles();
    uint64_t taddr = 0;
    if (meta->insn_id == X86_INS_RET) {
        if (!dse_read_reg(REG_RSP, &taddr))
            return false;
        taddr &= 0xFFFFFFFFULL;
    } else {
        uint8_t code[16];
        GByteArray *ib = g_byte_array_new();
        bool okr = qemu_plugin_read_memory_vaddr(vaddr, ib, meta->size > 16 ? 16 : meta->size);
        if (okr && ib->len)
            memcpy(code, ib->data, ib->len > 16 ? 16 : ib->len);
        g_byte_array_free(ib, TRUE);
        if (!okr)
            return false;

        cs_insn *insn = NULL;
        size_t n = cs_disasm(cs_handle, code, meta->size, vaddr, 1, &insn);
        if (n == 0)
            return false;
        bool ok = false;
        cs_x86 *x86 = &insn->detail->x86;
        if (x86->op_count >= 1 && x86->operands[0].type == X86_OP_MEM) {
            x86_op_mem *m = &x86->operands[0].mem;
            uint64_t ea = 0;
            if (m->base != X86_REG_INVALID) {
                uint64_t base = 0;
                int rid = x86_reg_to_rid(m->base);
                if (rid < 0 || !dse_read_reg(rid, &base)) {
                    cs_free(insn, n);
                    return false;
                }
                ea += base;
            }
            if (m->index != X86_REG_INVALID) {
                uint64_t index = 0;
                int rid = x86_reg_to_rid(m->index);
                if (rid < 0 || !dse_read_reg(rid, &index)) {
                    cs_free(insn, n);
                    return false;
                }
                ea += index * (uint64_t)m->scale;
            }
            ea += (uint64_t)(int64_t)m->disp;
            taddr = ea & 0xFFFFFFFFULL;
            ok = true;
        }
        cs_free(insn, n);
        if (!ok)
            return false;
    }
    GByteArray *arr = g_byte_array_new();
    bool read_ok = qemu_plugin_read_memory_vaddr(taddr, arr, 4);
    if (!read_ok || arr->len < 4) {
        g_byte_array_free(arr, TRUE);
        return false;
    }

    uint64_t value = 0;
    for (uint32_t i = 0; i < 4; i++) {
        value |= (uint64_t)arr->data[i] << (8 * i);
    }
    g_byte_array_free(arr, TRUE);
    *out_addr = taddr;
    *out_val = value;
    return true;
}

static uint8_t shadow_load_taint_mask(uint64_t vaddr, uint32_t size) {
    uint8_t result = 0;
    uint32_t width = size < MAX_REG_BYTES ? size : MAX_REG_BYTES;
    for (uint32_t byte = 0; byte < width; byte++) {
        if (shadow_is_tainted(g_shadow, vaddr + byte)) {
            result |= (uint8_t)(1U << byte);
        }
    }
    return result;
}

static bool plugin_label_may_be_tainted(ProvLabelId label) {
    if (!g_prov_registry) {
        return true;
    }
    if (!prov_label_is_valid(g_prov_registry, label)) {
        return true;
    }
    return prov_label_may_be_tainted(g_prov_registry, label);
}

static uint8_t label_array_taint_mask(const ProvLabelId *labels, uint32_t count) {
    if (count > MAX_REG_BYTES) {
        count = MAX_REG_BYTES;
    }
    if (!labels) {
        if (count >= MAX_REG_BYTES) {
            return UINT8_MAX;
        }
        return (uint8_t)((UINT32_C(1) << count) - 1U);
    }
    uint8_t result = 0;
    for (uint32_t byte = 0; byte < count; byte++) {
        if (plugin_label_may_be_tainted(labels[byte])) {
            result |= (uint8_t)(UINT32_C(1) << byte);
        }
    }
    return result;
}

static bool label_array_has_taint(const ProvLabelId *labels, uint32_t count) {
    if (count > MAX_REG_BYTES) {
        count = MAX_REG_BYTES;
    }
    if (!labels) {
        return count != 0;
    }
    for (uint32_t byte = 0; byte < count; byte++) {
        if (plugin_label_may_be_tainted(labels[byte])) {
            return true;
        }
    }
    return false;
}

static ProvLabelId dta_incomplete_unknown_label(uint64_t reasons) {
    if (!g_prov_registry) {
        return PROV_LABEL_ID_INVALID;
    }
    ProvLabelId unknown = prov_label_unknown(g_prov_registry);
    if (unknown == PROV_LABEL_ID_INVALID) {
        return PROV_LABEL_ID_INVALID;
    }
    return prov_label_mark_incomplete(g_prov_registry, unknown, PROV_COMPLETE_ALL, reasons);
}

static ProvLabelId plugin_label_mark_incomplete(ProvLabelId label, uint64_t reasons) {
    ProvLabelId result = PROV_LABEL_ID_INVALID;
    if (g_prov_registry && prov_label_is_valid(g_prov_registry, label)) {
        result = prov_label_mark_incomplete(g_prov_registry, label, PROV_COMPLETE_ALL, reasons);
    }
    if (result == PROV_LABEL_ID_INVALID) {
        result = dta_incomplete_unknown_label(reasons);
    }
    return result;
}

static bool mark_popal_destinations_incomplete(RegShadow *regs, uint64_t ip, uint64_t reasons) {
    static const unsigned destinations[] = {X86_REG_EDI, X86_REG_ESI, X86_REG_EBP, X86_REG_EBX,
                                            X86_REG_EDX, X86_REG_ECX, X86_REG_EAX};
    if (!regs)
        return false;
    bool success = true;
    for (size_t index = 0; index < (sizeof(destinations) / sizeof(destinations[0])); index++) {
        RegSlice destination = reg_slice_from_x86(destinations[index], 4);
        if (!reg_slice_is_valid(destination)) {
            success = false;
            continue;
        }
        ProvLabelId labels[4];
        if (reg_slice_load_labels(regs, destination, labels)) {
            for (uint8_t byte = 0; byte < 4; byte++) {
                labels[byte] = plugin_label_mark_incomplete(labels[byte], reasons);
            }
        } else {
            ProvLabelId fallback = dta_incomplete_unknown_label(reasons);
            for (uint8_t byte = 0; byte < 4; byte++) {
                labels[byte] = fallback;
            }
        }
        bool labels_valid = true;
        for (uint8_t byte = 0; byte < 4; byte++) {
            if (labels[byte] == PROV_LABEL_ID_INVALID) {
                labels_valid = false;
                break;
            }
        }
        if (!labels_valid || !reg_slice_store_labels(regs, destination, labels, 4, ip)) {
            success = false;
        }
    }
    return success;
}

static bool shadow_fill_incomplete(uint64_t address, uint64_t size, uint64_t reasons) {
    ProvLabelId label = dta_incomplete_unknown_label(reasons);
    if (label == PROV_LABEL_ID_INVALID || !shadow_fill_label(g_shadow, address, size, label)) {
        shadow_mark_incomplete(g_shadow);
        g_taint_seen = true;
        return false;
    }
    return true;
}

static void apply_memory_store_labels(PluginVcpuState *vcpu_state, uint64_t vaddr, uint32_t size,
                                      const InsnMeta *meta) {
    if (!g_shadow || !g_prov_registry || size == 0) {
        return;
    }
    dta_mem_transfer_t *transfer = vcpu_state ? &vcpu_state->mem_transfer : NULL;
    bool context_valid = vcpu_state && transfer->active && transfer->pc == vcpu_state->current_ip;
    if (!vcpu_state || !meta || !context_valid || size > MAX_REG_BYTES) {
        if (!shadow_fill_incomplete(vaddr, size, PROV_INCOMPLETE_UNSUPPORTED_INSTRUCTION)) {
            fprintf(stderr, "[DTA] failed to store incomplete label addr=0x%lx size=%u\n",
                    (unsigned long)vaddr, size);
        } else {
            g_taint_seen = true;
        }
        if (transfer) {
            transfer->last_read_valid = false;
        }
        return;
    }
    ProvLabelId old_memory[MAX_REG_BYTES];
    ProvLabelId effective_old_memory[MAX_REG_BYTES];
    ProvLabelId result_labels[MAX_REG_BYTES];
    if (!shadow_load_labels(g_shadow, vaddr, old_memory, size)) {
        (void)shadow_fill_incomplete(vaddr, size, PROV_INCOMPLETE_UNRESOLVED_MEMORY);
        transfer->last_read_valid = false;
        g_taint_seen = true;
        return;
    }
    memcpy(effective_old_memory, old_memory, size * sizeof(*old_memory));
    if (meta->has_mem_read && !dta_effective_mem_read_labels(&transfer->pre_regs, meta, old_memory,
                                                             (uint8_t)size, effective_old_memory)) {
        (void)shadow_fill_incomplete(vaddr, size, PROV_INCOMPLETE_UNRESOLVED_MEMORY);
        transfer->last_read_valid = false;
        g_taint_seen = true;
        return;
    }
    bool source_memory_valid = transfer->last_read_valid && transfer->last_read_size == size;
    const ProvLabelId *source_memory = source_memory_valid ? transfer->last_read_labels : NULL;
    DtaTransferResult result = dta_compute_mem_write_labels(
        &transfer->pre_regs, meta, effective_old_memory, source_memory_valid, source_memory,
        (uint8_t)size, result_labels);
    if (result == DTA_TRANSFER_NOT_APPLICABLE) {
        ProvLabelId fallback =
            dta_incomplete_unknown_label(PROV_INCOMPLETE_UNSUPPORTED_INSTRUCTION);
        for (uint32_t byte = 0; byte < size; byte++) {
            result_labels[byte] = fallback;
        }
    }

    if (meta->insn_id == X86_INS_XCHG) {
        (void)dta_apply_mem_read_labels(&vcpu_state->dta.regs, &transfer->pre_regs, meta,
                                        old_memory, (uint8_t)size);
    }
    if (!shadow_store_labels(g_shadow, vaddr, result_labels, size)) {
        shadow_mark_incomplete(g_shadow);
        g_taint_seen = true;
        fprintf(stderr, "[DTA] failed to store memory labels addr=0x%lx size=%u\n",
                (unsigned long)vaddr, size);
    } else if (label_array_has_taint(result_labels, size)) {
        g_taint_seen = true;
    }
    transfer->last_read_valid = false;
}

static void dse_aux_note_mem_access(uint32_t *total, bool *range_valid, bool *range_unknown,
                                    uint64_t *range_min, uint64_t *range_max, uint64_t address,
                                    uint32_t size) {
    if (!total || !range_valid || !range_unknown || !range_min || !range_max) {
        return;
    }
    if (*total != UINT32_MAX) {
        (*total)++;
    }
    if (size == 0 || address > UINT64_MAX - ((uint64_t)size - 1U)) {
        *range_unknown = true;
        return;
    }
    uint64_t end = address + (uint64_t)size - 1U;
    if (!*range_valid) {
        *range_valid = true;
        *range_min = address;
        *range_max = end;
        return;
    }
    if (address < *range_min)
        *range_min = address;
    if (end > *range_max)
        *range_max = end;
}

static bool dse_mem_access_value_u64(qemu_plugin_meminfo_t info, uint32_t size,
                                     uint64_t *out_value) {
    if (!out_value || size == 0 || size > sizeof(*out_value)) {
        return false;
    }
    qemu_plugin_mem_value observed = qemu_plugin_mem_get_value(info);
    switch (observed.type) {
    case QEMU_PLUGIN_MEM_VALUE_U8:
        if (size != 1U)
            return false;
        *out_value = observed.data.u8;
        return true;
    case QEMU_PLUGIN_MEM_VALUE_U16:
        if (size != 2U)
            return false;
        *out_value = observed.data.u16;
        return true;
    case QEMU_PLUGIN_MEM_VALUE_U32:
        if (size != 4U)
            return false;
        *out_value = observed.data.u32;
        return true;
    case QEMU_PLUGIN_MEM_VALUE_U64:
        if (size != 8U)
            return false;
        *out_value = observed.data.u64;
        return true;
    case QEMU_PLUGIN_MEM_VALUE_U128:
    default:
        return false;
    }
}

static void dse_on_mem(unsigned int vcpu, qemu_plugin_meminfo_t info, uint64_t vaddr, void *ud) {
    PluginVcpuState *vcpu_state = plugin_vcpu_state_get(vcpu);
    if (!vcpu_state)
        return;
    RegShadow *regs = &vcpu_state->dta.regs;
    dta_mem_transfer_t *transfer = &vcpu_state->mem_transfer;
    const InsnExecCtx *exec_ctx = (const InsnExecCtx *)ud;
    const InsnMeta *meta = exec_ctx ? exec_ctx->meta : NULL;
    if (exec_ctx && exec_ctx->pc != vcpu_state->current_ip) {
        meta = NULL;
    }
    uint32_t size = 1U << qemu_plugin_mem_size_shift(info);
    bool context_valid = transfer->active && transfer->pc == vcpu_state->current_ip;
    if (qemu_plugin_mem_is_store(info)) {
        uint64_t stored_value = 0;
        bool stored_value_valid = dse_mem_access_value_u64(info, size, &stored_value);
        bool address_tainted =
            meta && context_valid &&
            dta_address_mask_is_tainted(&transfer->pre_regs, meta->mem_write_addr_reg_mask);
        if (g_cur_aux) {
            dse_aux_capture_string_write(g_cur_aux, vaddr, size);
            dse_aux_note_mem_access(&g_cur_aux->mem_write_total, &g_cur_aux->mem_write_range_valid,
                                    &g_cur_aux->mem_write_range_unknown,
                                    &g_cur_aux->mem_write_min_addr, &g_cur_aux->mem_write_max_addr,
                                    vaddr, size);
            if (!g_cur_aux->has_mem_write) {
                g_cur_aux->mem_write_addr = vaddr;
                g_cur_aux->mem_write_size = size <= MAX_REG_BYTES ? (uint8_t)size : 0;
            }
            g_cur_aux->has_mem_write = true;
            if (size == 0 || size > MAX_REG_BYTES ||
                g_cur_aux->mem_write_count >= DSE_MAX_MEM_ACCESSES) {
                g_cur_aux->mem_write_overflow = true;
            } else {
                DseMemWrite *write = &g_cur_aux->mem_writes[g_cur_aux->mem_write_count++];
                write->addr = vaddr;
                write->value = stored_value;
                write->size = (uint8_t)size;
                write->value_valid = stored_value_valid;
                write->address_tainted = address_tainted;
            }
        }
        apply_memory_store_labels(vcpu_state, vaddr, size, meta);
        return;
    }

    uint8_t memory_width = (uint8_t)(size < MAX_REG_BYTES ? size : MAX_REG_BYTES);
    ProvLabelId raw_labels[MAX_REG_BYTES];
    ProvLabelId effective_labels[MAX_REG_BYTES];
    bool raw_labels_valid =
        size <= MAX_REG_BYTES && shadow_load_labels(g_shadow, vaddr, raw_labels, size);
    bool effective_labels_valid = raw_labels_valid;

    if (raw_labels_valid) {
        memcpy(effective_labels, raw_labels, size * sizeof(*raw_labels));
        if (meta && context_valid &&
            !dta_effective_mem_read_labels(&transfer->pre_regs, meta, raw_labels, memory_width,
                                           effective_labels)) {
            effective_labels_valid = false;
        }
    }
    if (meta && context_valid && transfer->flags_pending && !transfer->flags_applied) {
        const ProvLabelId *flag_memory_labels = effective_labels_valid ? effective_labels : NULL;
        uint8_t flag_memory_width = effective_labels_valid ? memory_width : 0;
        (void)dta_apply_flag_transfer(&vcpu_state->dta, &transfer->pre_regs, meta,
                                      flag_memory_labels, flag_memory_width);
        transfer->flags_applied = true;
        if (dta_flag_mask_is_tainted(&vcpu_state->dta, meta->flags_write_mask)) {
            g_taint_seen = true;
        }
    }

    uint8_t raw_taint = raw_labels_valid ? label_array_taint_mask(raw_labels, memory_width)
                                         : shadow_load_taint_mask(vaddr, size);
    uint8_t effective_taint =
        effective_labels_valid ? label_array_taint_mask(effective_labels, memory_width) : raw_taint;
    bool address_tainted =
        meta && context_valid &&
        dta_address_mask_is_tainted(&transfer->pre_regs, meta->mem_read_addr_reg_mask);
    if (context_valid) {
        transfer->last_read_valid = effective_labels_valid;
        transfer->last_read_size = size;
        if (effective_labels_valid) {
            memcpy(transfer->last_read_labels, effective_labels, size * sizeof(*effective_labels));
        }
    }

    if (meta && meta->insn_id == X86_INS_POPAL) {
        bool handled = false;
        uint64_t failure_reason = PROV_INCOMPLETE_NONE;
        if (!context_valid) {
            failure_reason = PROV_INCOMPLETE_UNKNOWN;
        } else if (!transfer->pre_esp_valid) {
            failure_reason = PROV_INCOMPLETE_IMPLICIT_OPERAND;
        } else if (size != 4 || !effective_labels_valid) {
            failure_reason = PROV_INCOMPLETE_UNRESOLVED_MEMORY;
        } else {
            uint32_t offset = (uint32_t)vaddr - transfer->pre_esp;
            unsigned destination_reg = X86_REG_INVALID;
            switch (offset) {
            case 0:
                destination_reg = X86_REG_EDI;
                break;
            case 4:
                destination_reg = X86_REG_ESI;
                break;
            case 8:
                destination_reg = X86_REG_EBP;
                break;
            case 12:
                handled = true;
                break;
            case 16:
                destination_reg = X86_REG_EBX;
                break;
            case 20:
                destination_reg = X86_REG_EDX;
                break;
            case 24:
                destination_reg = X86_REG_ECX;
                break;
            case 28:
                destination_reg = X86_REG_EAX;
                break;
            default:
                failure_reason = PROV_INCOMPLETE_UNKNOWN;
                break;
            }
            if (destination_reg != X86_REG_INVALID) {
                RegSlice destination = reg_slice_from_x86(destination_reg, 4);
                if (reg_slice_is_valid(destination) &&
                    reg_slice_store_labels(regs, destination, effective_labels, 4,
                                           vcpu_state->current_ip)) {
                    handled = true;
                } else {
                    failure_reason = PROV_INCOMPLETE_UNKNOWN;
                }
            }
        }
        if (!handled) {
            if (failure_reason == PROV_INCOMPLETE_NONE) {
                failure_reason = PROV_INCOMPLETE_UNKNOWN;
            }
            bool fallback_stored =
                mark_popal_destinations_incomplete(regs, vcpu_state->current_ip, failure_reason);
            g_taint_seen = true;
            if (!fallback_stored) {
                fprintf(stderr,
                        "[DTA] failed to mark POPAL destinations incomplete pc=0x%lx addr=0x%lx\n",
                        (unsigned long)vcpu_state->current_ip, (unsigned long)vaddr);
            }
        }
    } else if (meta && meta->insn_id == X86_INS_LEAVE) {
        RegSlice ebp_slice = reg_slice_from_x86(X86_REG_EBP, 4);
        RegSlice esp_slice = reg_slice_from_x86(X86_REG_ESP, 4);
        ProvLabelId old_ebp_labels[4];
        bool leave_valid = size == 4 && effective_labels_valid && reg_slice_is_valid(ebp_slice) &&
                           reg_slice_is_valid(esp_slice) &&
                           reg_slice_load_labels(&transfer->pre_regs, ebp_slice, old_ebp_labels);
        if (leave_valid) {
            (void)reg_slice_store_labels(regs, esp_slice, old_ebp_labels, 4,
                                         vcpu_state->current_ip);
            (void)reg_slice_store_labels(regs, ebp_slice, effective_labels, 4,
                                         vcpu_state->current_ip);
        } else {
            ProvLabelId incomplete =
                dta_incomplete_unknown_label(PROV_INCOMPLETE_UNRESOLVED_MEMORY);
            if (reg_slice_is_valid(esp_slice)) {
                (void)reg_slice_set_label(regs, esp_slice, incomplete, vcpu_state->current_ip);
            }
            if (reg_slice_is_valid(ebp_slice)) {
                (void)reg_slice_set_label(regs, ebp_slice, incomplete, vcpu_state->current_ip);
            }
        }
    } else if (meta && context_valid && raw_labels_valid) {
        DtaTransferResult result =
            dta_apply_mem_read_labels(regs, &transfer->pre_regs, meta, raw_labels, memory_width);
        if (result == DTA_TRANSFER_NOT_APPLICABLE) {
            RegSlice destination = meta_first_reg_write(meta);
            if (reg_slice_is_valid(destination) && meta->family != DTA_FAMILY_COMPARE) {
                ProvLabelId incomplete =
                    dta_incomplete_unknown_label(PROV_INCOMPLETE_UNRESOLVED_MEMORY);
                (void)reg_slice_set_label(regs, destination, incomplete, vcpu_state->current_ip);
            }
        }
    } else if (meta) {
        RegSlice destination = meta_first_reg_write(meta);
        if (reg_slice_is_valid(destination)) {
            ProvLabelId incomplete =
                dta_incomplete_unknown_label(PROV_INCOMPLETE_UNRESOLVED_MEMORY);
            (void)reg_slice_set_label(regs, destination, incomplete, vcpu_state->current_ip);
        }
    }

    if (g_cur_aux) {
        dse_aux_note_mem_access(&g_cur_aux->mem_read_total, &g_cur_aux->mem_read_range_valid,
                                &g_cur_aux->mem_read_range_unknown, &g_cur_aux->mem_read_min_addr,
                                &g_cur_aux->mem_read_max_addr, vaddr, size);
        uint64_t value = 0;
        bool value_valid = dse_mem_access_value_u64(info, size, &value);
        if (!g_cur_aux->has_mem_read) {
            g_cur_aux->mem_read_addr = vaddr;
            g_cur_aux->mem_read_val = value;
            g_cur_aux->mem_read_value_valid = value_valid;
            g_cur_aux->mem_read_taint = raw_taint;
            g_cur_aux->mem_read_effective_taint = effective_taint;
            g_cur_aux->mem_read_address_tainted = address_tainted;
        }
        (void)dse_aux_capture_string_read(g_aux, g_cur_aux, vaddr, value, value_valid, raw_taint,
                                          size);
        g_cur_aux->has_mem_read = true;
        if (size == 0 || size > MAX_REG_BYTES ||
            g_cur_aux->mem_read_count >= DSE_MAX_MEM_ACCESSES) {
            g_cur_aux->mem_read_overflow = true;
        } else {
            DseMemRead *read = &g_cur_aux->mem_reads[g_cur_aux->mem_read_count++];
            read->addr = vaddr;
            read->value = value;
            read->taint = raw_taint;
            read->effective_taint = effective_taint;
            read->value_valid = value_valid;
            read->address_tainted = address_tainted;
            read->size = (uint8_t)size;
            DseSourceObservation *sources = dse_aux_sources_mut(g_cur_aux);
            if (g_ir_enabled && raw_labels_valid && sources) {
                unsigned index = g_cur_aux->mem_read_count - 1U;
                memcpy(sources->read_labels[index], raw_labels, size * sizeof(*raw_labels));
                sources->read_valid[index] = (uint8_t)((1U << size) - 1U);
            }
        }
    }
}

static bool is_valid_path(const char *s) {
    if (!s || !*s)
        return false;
    if (*s != '/')
        return false;

    size_t len = strlen(s);
    if (len < 2 || len > 256)
        return false;

    char c = s[1];
    if (!(isalpha((unsigned char)c) || c == '_' || c == '.'))
        return false;

    for (const char *p = s + 2; *p; p++) {
        unsigned char c = *p;
        if (c < 32 || c > 126)
            return false;
        if (c == '<' || c == '>' || c == '|' || c == '*' || c == '?' || c == '"' || c == '\\' ||
            c == ',' || c == ';' || c == '$')
            return false;
    }
    return true;
}

//for exact lib dump
static void lib_update_mapping(uint32_t fd, uint64_t addr, uint64_t size) {
    if ((int)fd <= 0 || size == 0)
        return;
    gpointer val = g_hash_table_lookup(file_fd, (gpointer)(uintptr_t)fd);
    if (!val)
        return;
    file_dep_t *f = (file_dep_t *)val;
    for (GList *l = lib_deps; l; l = l->next) {
        lib_mapping_t *lm = (lib_mapping_t *)l->data;
        if (f->path && lm->path && strcmp(lm->path, f->path) == 0) {
            uint64_t end = addr + size;
            if (lm->base == 0 || addr < lm->base)
                lm->base = addr;
            if (end > lm->end)
                lm->end = end;
            return;
        }
    }
}

static void apply_pending_mmap(const pending_mmap_t *pending, uint64_t mapped_addr) {
    if (!pending || !pending->active || pending->size == 0) {
        return;
    }
    if (page_size == 0 || (page_size & (page_size - 1U)) != 0) {
        fprintf(stderr, "[MMAP] invalid page size: 0x%lx\n", (unsigned long)page_size);
        return;
    }
    if ((pending->size - 1U) > UINT64_MAX - mapped_addr) {
        fprintf(stderr,
                "[MMAP] range overflow:"
                " addr=0x%lx size=0x%lx\n",
                (unsigned long)mapped_addr, (unsigned long)pending->size);
        return;
    }
    const char *name = pending->syscall_num == 192 ? "mmap2" : "mmap";
    fprintf(stderr,
            "[SYSCALL] %s"
            " requested=0x%lx"
            " mapped=0x%lx"
            " size=0x%lx"
            " prot=0x%x"
            " flags=0x%x"
            " fd=%d"
            " offset=0x%lx\n",
            name, (unsigned long)pending->requested_addr, (unsigned long)mapped_addr,
            (unsigned long)pending->size, pending->prot, pending->flags, pending->fd,
            (unsigned long)pending->offset);
    lib_update_mapping((uint32_t)pending->fd, mapped_addr, pending->size);
    uint64_t page_mask = (uint64_t)page_size - 1U;
    uint64_t last_addr = mapped_addr + pending->size - 1U;
    uint64_t page_start = mapped_addr & ~page_mask;
    uint64_t page_last = last_addr & ~page_mask;
    uint64_t mapped_size = (page_last - page_start) + (uint64_t)page_size;
    shadow_untaint_range(g_shadow, page_start, mapped_size);
    bool anonymous_mapping = (pending->flags & GUEST_MAP_ANONYMOUS) != 0 || pending->fd < 0;

    if (!anonymous_mapping && fd_is_taint_source(pending->fd)) {
        if (!shadow_taint_range(g_shadow, mapped_addr, pending->size, 0)) {
            fprintf(stderr,
                    "[DTA] failed to taint"
                    " file-backed mmap"
                    " addr=0x%lx"
                    " size=0x%lx"
                    " fd=%d\n",
                    (unsigned long)mapped_addr, (unsigned long)pending->size, pending->fd);
        } else {
            g_taint_seen = true;
        }
    }
    if (!(pending->prot & 0x2) && !(pending->prot & 0x4)) {
        return;
    }
    uint32_t remap_generation = 0;
    for (uint64_t addr = page_start;; addr += page_size) {
        gpointer key = (gpointer)(uintptr_t)addr;
        page_t *page = g_hash_table_lookup(pages, key);
        if (page) {
            page->prot = pending->prot;
        } else {
            page = g_new0(page_t, 1);
            page->prot = pending->prot;
            g_hash_table_insert(pages, key, page);
        }
        if ((pending->prot & 0x4) && g_hash_table_contains(unmapped_pages, key)) {
            page->dyn_exec = true;
            if (remap_generation == 0) {
                remap_generation = next_code_generation();
            }
            page->gen_written = remap_generation;
            if (g_layer_has_cand) {
                g_layer_dirty = true;
            }
        }
        if (addr == page_last) {
            break;
        }
    }
}

static void apply_pending_mprotect(const pending_mmap_t *pending) {
    if (!pending || !pending->active || pending->size == 0) {
        return;
    }
    if (page_size == 0 || (page_size & (page_size - 1U)) != 0) {
        fprintf(stderr, "[MPROTECT] invalid page size: 0x%lx\n", (unsigned long)page_size);
        return;
    }

    uint64_t addr = pending->requested_addr;
    uint64_t size = pending->size;
    int prot = pending->prot;
    if (size > UINT64_MAX - addr || addr + size > UINT64_MAX - (page_size - 1U)) {
        fprintf(stderr,
                "[MPROTECT] range overflow:"
                " addr=0x%lx size=0x%lx\n",
                (unsigned long)addr, (unsigned long)size);
        return;
    }
    uint64_t page_mask = (uint64_t)page_size - 1U;
    uint64_t page_start = addr & ~page_mask;
    uint64_t page_end = (addr + size + page_size - 1U) & ~page_mask;
    fprintf(stderr, "[SYSCALL] mprotect(0x%lx, 0x%lx, prot=0x%x)\n", (unsigned long)addr,
            (unsigned long)size, prot);

    uint32_t remap_generation = 0;
    for (uint64_t page_addr = page_start; page_addr < page_end; page_addr += page_size) {
        gpointer key = (gpointer)(uintptr_t)page_addr;
        page_t *page = g_hash_table_lookup(pages, key);
        if (page) {
            page->prot = prot;
        } else {
            page = g_new0(page_t, 1);
            page->prot = prot;
            g_hash_table_insert(pages, key, page);
        }
        if (page->written && (prot & 0x4)) {
            page->exec_after_write = true;
        }
        if ((prot & 0x4) && g_hash_table_contains(unmapped_pages, key)) {
            page->dyn_exec = true;
            if (remap_generation == 0) {
                remap_generation = next_code_generation();
            }
            page->gen_written = remap_generation;
            if (g_layer_has_cand) {
                g_layer_dirty = true;
            }
        }
    }
}

static void apply_pending_munmap(const pending_mmap_t *pending) {
    if (!pending || !pending->active || pending->size == 0) {
        return;
    }
    if (page_size == 0 || (page_size & (page_size - 1)) != 0) {
        fprintf(stderr, "[MUNMAP] invalid page size: 0x%lx\n", (unsigned long)page_size);
        return;
    }

    uint64_t addr = pending->requested_addr;
    uint64_t size = pending->size;
    if ((size - 1) > UINT64_MAX - addr) {
        fprintf(stderr, "[MUNMAP] range overflow: addr=0x%lx size=0x%lx\n", (unsigned long)addr,
                (unsigned long)size);
        return;
    }
    uint64_t page_mask = (uint64_t)page_size - 1;
    uint64_t last_addr = addr + size - 1;
    uint64_t page_start = addr & ~page_mask;
    uint64_t page_last = last_addr & ~page_mask;
    uint64_t unmapped_size = (page_last - page_start) + (uint64_t)page_size;

    shadow_untaint_range(g_shadow, page_start, unmapped_size);

    for (uint64_t page_addr = page_start;; page_addr += page_size) {
        gpointer key = (gpointer)(uintptr_t)page_addr;
        g_hash_table_add(unmapped_pages, key);

        page_t *p = g_hash_table_lookup(pages, key);
        if (p) {
            g_hash_table_remove(pages, key);
            g_free(p->wbitmap);
            g_free(p);
        }
        if (page_addr == page_last) {
            break;
        }
    }

    fprintf(stderr, "[SYSCALL] munmap(0x%lx, 0x%lx)\n", (unsigned long)addr, (unsigned long)size);
}

static ProvResourceId ensure_file_resource(file_dep_t *file, uint32_t roles) {
    if (!file || !file->path || !g_prov_registry) {
        return PROV_RESOURCE_ID_INVALID;
    }
    bool is_main_image = g_main_image_path && g_main_image_object_id != 0 &&
                         strcmp(file->path, g_main_image_path) == 0;
    if (is_main_image) {
        file->resource_object_id = g_main_image_object_id;
        roles |= PROV_RESOURCE_ROLE_MAIN_IMAGE;
    }
    if (file->resource_object_id == 0) {
        if (g_next_resource_object_id == 0) {
            fprintf(stderr, "[PROV] file object-id space exhausted\n");
            return PROV_RESOURCE_ID_INVALID;
        }
        file->resource_object_id = g_next_resource_object_id++;
    }
    ProvResourceKey key = {.kind = PROV_RESOURCE_FILE,
                           .scope_id = g_analysis_scope_id,
                           .object_id = file->resource_object_id,
                           .semantic_version = 0};
    ProvResourceId resource_id = prov_resource_intern(g_prov_registry, &key, file->path, roles);
    if (resource_id != PROV_RESOURCE_ID_INVALID) {
        file->resource_id = resource_id;
    }
    return resource_id;
}

static file_dep_t *add_file_dep(const char *path, bool is_lib) {
    if (!path || !*path) {
        return NULL;
    }
    uint32_t roles = is_lib ? PROV_RESOURCE_ROLE_LIBRARY_IMAGE : PROV_RESOURCE_ROLE_FUZZ_INPUT;
    for (GList *node = file_deps; node; node = node->next) {
        file_dep_t *file = node->data;
        if (!file->path || strcmp(file->path, path) != 0) {
            continue;
        }
        if (is_lib)
            file->taint_source = false;
        (void)ensure_file_resource(file, roles);
        return file;
    }
    file_dep_t *file = g_try_new0(file_dep_t, 1);
    if (!file)
        return NULL;
    file->path = g_strdup(path);
    if (!file->path) {
        g_free(file);
        return NULL;
    }
    file->write = false;
    file->taint_source = !is_lib;
    file->resource_id = PROV_RESOURCE_ID_INVALID;
    (void)ensure_file_resource(file, roles);

    file_deps = g_list_append(file_deps, file);
    if (is_lib && !strstr(path, ".cache")) {
        for (GList *node = lib_deps; node; node = node->next) {
            lib_mapping_t *mapping = node->data;
            if (mapping->path && strcmp(mapping->path, path) == 0) {
                return file;
            }
        }
        lib_mapping_t *mapping = g_try_new0(lib_mapping_t, 1);
        if (mapping) {
            mapping->path = g_strdup(path);
            if (mapping->path) {
                lib_deps = g_list_append(lib_deps, mapping);
            } else {
                g_free(mapping);
            }
        }
    }
    return file;
}

//mark write
static void mark_written(uint64_t vaddr, uint32_t size) {
    if (size == 0)
        return;
    uint32_t write_generation = next_code_generation();
    while (size > 0) {
        uint64_t page_addr = vaddr & ~((uint64_t)page_size - 1U);
        uint32_t offset = (uint32_t)(vaddr & ((uint64_t)page_size - 1U));
        uint32_t chunk = MIN(size, (uint32_t)page_size - offset);
        page_t *page = g_hash_table_lookup(pages, (gpointer)(uintptr_t)page_addr);
        if (!page) {
            page = g_new0(page_t, 1);
            page->prot = 0x3;
            g_hash_table_insert(pages, (gpointer)(uintptr_t)page_addr, page);
        }
        if (!page->wbitmap) {
            page->wbitmap = g_malloc0(page_size / 8U);
        }
        for (uint32_t i = 0; i < chunk; i++) {
            uint32_t bit = offset + i;
            page->wbitmap[bit >> 3] |= (uint8_t)(1U << (bit & 7U));
        }
        page->written = true;
        page->write_count++;
        page->last_write = g_icount;
        page->gen_written = write_generation;
        page->exec_seen = false;
        if (g_layer_has_cand) {
            g_layer_dirty = true;
        }
        vaddr += chunk;
        size -= chunk;
    }
}

static void on_mem_write(unsigned int vcpu_idx, qemu_plugin_meminfo_t info, uint64_t vaddr,
                         void *userdata) {
    (void)vcpu_idx;
    (void)userdata;
    uint32_t size = 1u << qemu_plugin_mem_size_shift(info);
    mark_written(vaddr, size);
}

static bool bin_dumped = false;
static GString *saved_reg = NULL;
static uint64_t saved_base = 0;
static bool saved_base_set = false;
static uint64_t saved_oep = 0;
static double g_oep_confidence = 0.0;
static GString *g_oep_scoring = NULL;
static bool image_captured = false;
static bool g_static_binary = false;

//enhanced logic of choosing oep
static bool addr_in_lib(uint64_t addr) {
    if (addr == 0)
        return false;
    for (GList *l = lib_deps; l; l = l->next) {
        lib_mapping_t *lm = (lib_mapping_t *)l->data;
        if (!lm->base)
            continue;
        uint64_t end;
        if (lm->end > lm->base) {
            end = lm->end;
        } else {
            end = (lm->base + lm->size);
        }
        if (end <= lm->base)
            continue;
        if (addr >= lm->base && addr < end)
            return true;
    }
    return false;
}

static bool cand_in_main_image(const oep_cand_t *c) {
    if (!c)
        return false;
    if (addr_in_lib(c->addr))
        return false; // target in libc/ld
    return true;
}

//part of the concrete to total to determine the most accurate OEP
static double cand_dse_ratio(const oep_cand_t *c) {
    if (!c || c->dse.lifted_total == 0)
        return 1.0;
    uint32_t failed = c->dse.concretized;
    if (failed > c->dse.lifted_total) {
        failed = c->dse.lifted_total;
    }
    return (double)failed / (double)c->dse.lifted_total;
}

//check overall measurements
static double cand_dse_strength(const oep_cand_t *c) {
    if (!c || c->dse.verdict != DSE_VERDICT_CONFIRMED ||
        c->dse.evidence != DSE_EVIDENCE_UNIQUE_ON_SLICE || c->dse.lifted_total == 0) {
        return 0.0;
    }
    //lifting coverage
    double quality = 1.0 - cand_dse_ratio(c);
    uint32_t depth_total = c->dse.lifted_total;
    if (depth_total > MAX_SLICE) {
        depth_total = MAX_SLICE;
    }
    //depth check
    double depth = log1p((double)depth_total) / log1p((double)MAX_SLICE);

    return quality * depth;
}

//comparison of measurements
static bool cand_stronger(const oep_cand_t *a, const oep_cand_t *b) {
    double strength_a = cand_dse_strength(a);
    double strength_b = cand_dse_strength(b);
    if (strength_a != strength_b) {
        return strength_a > strength_b;
    }
    if (a->dse.verdict == DSE_VERDICT_CONFIRMED && b->dse.verdict == DSE_VERDICT_CONFIRMED) {
        if (a->dse.lifted_total != b->dse.lifted_total) {
            return a->dse.lifted_total > b->dse.lifted_total;
        }
        double ratio_a = cand_dse_ratio(a);
        double ratio_b = cand_dse_ratio(b);
        if (ratio_a != ratio_b) {
            return ratio_a < ratio_b;
        }
    }

    if (a->jump_from_unmapped != b->jump_from_unmapped) {
        return a->jump_from_unmapped;
    }
    if (a->has_prologue != b->has_prologue) {
        return a->has_prologue;
    }
    if (a->icount != b->icount) {
        return a->icount < b->icount;
    }
    return a->addr < b->addr;
}

//read first bytes at candidate addr and checks prologue: push ebp; mov ebp,esp or endbr32
static bool cand_has_prologue(uint64_t addr) {
    uint8_t p[4];
    if (!guest_read_bytes(addr, p, 4))
        return false;
    if (p[0] == 0x55 && p[1] == 0x89 && p[2] == 0xe5)
        return true; //push ebp;mov ebp,esp
    if (p[0] == 0xf3 && p[1] == 0x0f && p[2] == 0x1e && p[3] == 0xfb)
        return true; //endbr32
    return false;
}

//trying to determine jump from basic code or stub
static bool jump_site_is_unpacker(uint64_t jump_site) {
    if (jump_site == 0)
        return false; //don't know source
    uint64_t pg = jump_site & ~(page_size - 1);
    page_t *jp = g_hash_table_lookup(pages, (gpointer)(uintptr_t)pg);
    if (!jp)
        return true; //stub munmapped, high chanse of attempt to hide stub
    if (jp->dyn_exec && !addr_in_lib(jump_site))
        return true; //alloc on address of previously used page
    if (jp->written && jp->exec_after_write)
        return true; //write then execute
    return false;    //ordinary page
}

//OEP scroing counting
static double cand_score(const oep_cand_t *c) {
    if (!c)
        return 0.0;
    double s_dse = cand_dse_strength(c);
    double s_prologue = c->has_prologue ? 1.0 : 0.0;
    double s_unmap = c->jump_from_unmapped ? 1.0 : 0.0;
    return W_DSE * s_dse + W_UNMAP * s_unmap + W_PROL * s_prologue;
}

//tiebreak, SCORE_EPS difference
static bool cand_score_better(const oep_cand_t *a, const oep_cand_t *b) {
    double score_a = cand_score(a);
    double score_b = cand_score(b);
    if (score_a - score_b > SCORE_EPS)
        return true;
    if (score_b - score_a > SCORE_EPS)
        return false;
    return cand_stronger(a, b);
}

//confidence in [0,1]
static double cand_confidence(const oep_cand_t *c) {
    if (W_ACTIVE <= 0.0)
        return 0.0;

    return cand_score(c) / W_ACTIVE;
}

static bool cand_rank_better(const oep_cand_t *a, const oep_cand_t *b) {
    if (!a)
        return false;
    if (!b)
        return true;
    bool a_in_main = cand_in_main_image(a);
    bool b_in_main = cand_in_main_image(b);
    if (a_in_main != b_in_main) {
        return a_in_main;
    }

    return cand_score_better(a, b);
}

//union of oep choosing
static oep_cand_t *choose_oep_cand(void) {
    oep_cand_t *best = NULL;
    for (GList *l = oep_cands; l; l = l->next) {
        oep_cand_t *c = (oep_cand_t *)l->data;
        if (!best || cand_rank_better(c, best)) {
            best = c;
        }
    }
    return best;
}

//auxv PT_LOAD union, main logic
static bool window_from_phdrs(uint64_t phdr_va, uint64_t ent, uint64_t num, uint64_t base_adjust) {
    if (!phdr_va || !num || num > 512) {
        return false;
    }
    bool w64 = (guest_ptr_bytes() == 8);
    uint64_t off_vaddr = w64 ? 16 : 8;
    uint64_t off_memsz = w64 ? 40 : 20;
    uint64_t min_ent = w64 ? 56 : 32;
    uint32_t fld = w64 ? 8 : 4;
    if (ent < min_ent) {
        return false;
    }

    uint64_t lo = UINT64_MAX;
    uint64_t hi = 0;
    for (uint64_t i = 0; i < num; i++) {
        if (i > (UINT64_MAX - phdr_va) / ent) {
            return false;
        }
        uint64_t ph = phdr_va + i * ent;
        uint64_t p_type = 0;
        uint64_t p_vaddr = 0;
        uint64_t p_memsz = 0;
        if (!guest_read_uint(ph, 4, &p_type)) {
            return false;
        }
        if (p_type != 1) { // PT_LOAD
            continue;
        }
        if (ph > UINT64_MAX - off_memsz) {
            return false;
        }
        if (!guest_read_uint(ph + off_vaddr, fld, &p_vaddr) ||
            !guest_read_uint(ph + off_memsz, fld, &p_memsz)) {
            return false;
        }
        if (p_memsz == 0) {
            continue;
        }
        if (p_vaddr > UINT64_MAX - base_adjust) {
            return false;
        }
        uint64_t start = p_vaddr + base_adjust;
        if (!w64) {
            const uint64_t guest_limit = 1ULL << 32;
            if (start >= guest_limit) {
                continue;
            }
            if (p_memsz > guest_limit - start) {
                p_memsz = guest_limit - start;
            }
        }
        if (p_memsz > UINT64_MAX - start) {
            return false;
        }
        if (start < lo) {
            lo = start;
        }
        if (start + p_memsz > hi) {
            hi = start + p_memsz;
        }
    }
    if (hi > lo) {
        g_main_lo = lo;
        g_main_hi = hi;
        g_main_known = true;
        return true;
    }
    return false;
}

//init taint
static bool seed_main_file_taint(uint64_t phdr_va, uint64_t ent, uint64_t num,
                                 uint64_t base_adjust) {
    if (g_initial_taint_seeded)
        return true;
    if (!g_shadow || !g_prov_registry || !phdr_va || !num || num > 512) {
        return false;
    }
    if (!main_image_resource_init()) {
        fprintf(stderr, "[PROV] main image resource is unavailable\n");
        return false;
    }

    bool w64 = guest_ptr_bytes() == 8;
    uint64_t off_offset = w64 ? 8 : 4;
    uint64_t off_vaddr = w64 ? 16 : 8;
    uint64_t off_filesz = w64 ? 32 : 16;
    uint64_t off_memsz = w64 ? 40 : 20;
    uint64_t min_ent = w64 ? 56 : 32;
    uint32_t field_size = w64 ? 8 : 4;

    if (ent < min_ent)
        return false;

    typedef struct {
        uint64_t runtime_address;
        uint64_t size;
        uint64_t file_offset;
    } MainImageLoadRange;

    MainImageLoadRange ranges[512];
    uint32_t range_count = 0;
    uint64_t total = 0;

    for (uint64_t index = 0; index < num; index++) {
        if (index > (UINT64_MAX - phdr_va) / ent) {
            return false;
        }
        uint64_t phdr = phdr_va + index * ent;
        uint64_t p_type = 0;
        uint64_t p_offset = 0;
        uint64_t p_vaddr = 0;
        uint64_t p_filesz = 0;
        uint64_t p_memsz = 0;
        if (!guest_read_uint(phdr, 4, &p_type)) {
            return false;
        }
        if (p_type != 1)
            continue;
        if (phdr > UINT64_MAX - off_memsz ||
            !guest_read_uint(phdr + off_offset, field_size, &p_offset) ||
            !guest_read_uint(phdr + off_vaddr, field_size, &p_vaddr) ||
            !guest_read_uint(phdr + off_filesz, field_size, &p_filesz) ||
            !guest_read_uint(phdr + off_memsz, field_size, &p_memsz)) {
            return false;
        }

        if (p_filesz == 0 || p_memsz == 0) {
            continue;
        }
        if (p_filesz > p_memsz) {
            p_filesz = p_memsz;
        }
        if (p_vaddr > UINT64_MAX - base_adjust) {
            return false;
        }
        uint64_t runtime_address = p_vaddr + base_adjust;
        if (!w64) {
            const uint64_t guest_limit = UINT64_C(1) << 32;
            if (runtime_address >= guest_limit) {
                continue;
            }
            if (p_filesz > (guest_limit - runtime_address)) {
                p_filesz = guest_limit - runtime_address;
            }
        }
        if (p_filesz == 0)
            continue;
        if (p_filesz - 1U > UINT64_MAX - p_offset) {
            return false;
        }

        if (p_filesz > MAX_INITIAL_TAINT_BYTES - total) {
            fprintf(stderr,
                    "[PROV] initial main-image seed "
                    "exceeds limit 0x%" PRIx64 "\n",
                    (uint64_t)MAX_INITIAL_TAINT_BYTES);
            return false;
        }

        ranges[range_count].runtime_address = runtime_address;
        ranges[range_count].size = p_filesz;
        ranges[range_count].file_offset = p_offset;
        range_count++;
        total += p_filesz;
    }
    if (range_count == 0 || total == 0) {
        return false;
    }
    for (uint32_t index = 0; index < range_count; index++) {
        if (!seed_resource_byte_labels(ranges[index].runtime_address, ranges[index].size,
                                       g_main_image_resource_id, ranges[index].file_offset)) {
            fprintf(stderr,
                    "[PROV] failed to seed main PT_LOAD "
                    "addr=0x%" PRIx64 " size=0x%" PRIx64 " file_offset=0x%" PRIx64 "\n",
                    ranges[index].runtime_address, ranges[index].size, ranges[index].file_offset);
            return false;
        }
    }
    g_initial_taint_seeded = true;
    g_taint_seen = true;
    fprintf(stderr,
            "[PROV] seeded %" PRIu64 " source-aware bytes from main ELF "
            "resource=%u path=%s\n",
            total, g_main_image_resource_id, g_main_image_path);
    return true;
}

//read auxv
static bool read_auxv_from_stack(void) {
    if (!main_image_path_init()) {
        fprintf(stderr, "[AUXV] fail: cannot resolve main executable path\n");
        return false;
    }
    if (!main_image_resource_init()) {
        fprintf(stderr, "[AUXV] fail: cannot initialize main image resource\n");
        return false;
    }
    uint32_t pb = guest_ptr_bytes();
    uint64_t sp = 0;
    if (g_initial_sp_valid) {
        sp = g_initial_sp;
    } else {
        if (!dse_read_reg(REG_RSP, &sp)) {
            fprintf(stderr, "[AUXV] fail: cannot read initial REG_RSP\n");
            return false;
        }
        if (pb == 4) {
            sp &= 0xFFFFFFFFULL;
        }
        if (sp == 0) {
            fprintf(stderr, "[AUXV] fail: initial REG_RSP is zero\n");
            return false;
        }
        g_initial_sp = sp;
        g_initial_sp_valid = true;
    }
    uint64_t argc = 0;
    if (!guest_read_uint(sp, pb, &argc)) {
        fprintf(stderr, "[AUXV] fail: cannot read argc at sp=0x%lx\n", (unsigned long)sp);
        return false;
    }
    if (sp > UINT64_MAX - pb || argc > MAX_AUXV_ARGC || argc > (UINT64_MAX - sp - pb) / pb) {
        fprintf(stderr, "[AUXV] fail: invalid argc=%lu\n", (unsigned long)argc);
        return false;
    }
    uint64_t p = sp + pb + argc * pb;
    if (p > UINT64_MAX - pb) {
        return false;
    }
    p += pb;

    bool env_end_found = false;

    for (int guard = 0; guard < 8192; guard++) {
        uint64_t env = 0;
        if (!guest_read_uint(p, pb, &env)) {
            fprintf(stderr, "[AUXV] fail: envp read at 0x%lx\n", (unsigned long)p);
            return false;
        }
        if (p > UINT64_MAX - pb) {
            return false;
        }
        p += pb;
        if (env == 0) {
            env_end_found = true;
            break;
        }
    }
    if (!env_end_found) {
        fprintf(stderr, "[AUXV] fail: envp terminator not found\n");
        return false;
    }
    uint64_t at_phdr = 0;
    uint64_t at_phent = 0;
    uint64_t at_phnum = 0;
    uint64_t at_base = 0;
    uint64_t at_entry = 0;
    uint64_t at_pagesz = 0;
    bool aux_end_found = false;
    uint64_t scan = p;
    for (int guard = 0; guard < 128; guard++) {
        uint64_t type = 0;
        uint64_t val = 0;
        if (scan > UINT64_MAX - pb || !guest_read_uint(scan, pb, &type)) {
            fprintf(stderr, "[AUXV] fail: auxv type read at 0x%lx\n", (unsigned long)scan);
            return false;
        }
        if (!guest_read_uint(scan + pb, pb, &val)) {
            fprintf(stderr, "[AUXV] fail: auxv value read at 0x%lx\n", (unsigned long)(scan + pb));
            return false;
        }
        if (scan > UINT64_MAX - 2U * pb) {
            return false;
        }
        scan += 2U * pb;
        if (type == AT_NULL) {
            aux_end_found = true;
            break;
        }
        switch (type) {
        case AT_PHDR:
            at_phdr = val;
            break;
        case AT_PHENT:
            at_phent = val;
            break;
        case AT_PHNUM:
            at_phnum = val;
            break;
        case AT_BASE:
            at_base = val;
            break;
        case AT_ENTRY:
            at_entry = val;
            break;
        case AT_PAGESZ:
            at_pagesz = val;
            break;
        }
    }
    if (!aux_end_found) {
        fprintf(stderr, "[AUXV] fail: AT_NULL not found\n");
        return false;
    }
    bool w64 = (guest_ptr_bytes() == 8);
    uint64_t min_phent = w64 ? 56 : 32;

    if (!at_phdr || !at_phnum || at_phnum > 512 || at_phent < min_phent) {
        fprintf(stderr, "[AUXV] fail: invalid PHDR data (phdr=0x%lx phnum=%lu phent=%lu)\n",
                (unsigned long)at_phdr, (unsigned long)at_phnum, (unsigned long)at_phent);
        return false;
    }
    uint64_t off_vaddr = w64 ? 16 : 8;
    uint32_t fld = w64 ? 8 : 4;
    uint64_t ptphdr_vaddr = 0;
    uint64_t min_load_vaddr = UINT64_MAX;
    bool have_ptphdr = false;
    for (uint64_t i = 0; i < at_phnum; i++) {
        if (i > (UINT64_MAX - at_phdr) / at_phent) {
            return false;
        }
        uint64_t ph = at_phdr + i * at_phent;
        uint64_t p_type = 0;
        uint64_t p_vaddr = 0;
        if (!guest_read_uint(ph, 4, &p_type) || ph > UINT64_MAX - off_vaddr ||
            !guest_read_uint(ph + off_vaddr, fld, &p_vaddr)) {
            return false;
        }
        if (p_type == 6) { // PT_PHDR
            if (p_vaddr <= at_phdr) {
                ptphdr_vaddr = p_vaddr;
                have_ptphdr = true;
            }
        } else if (p_type == 1) { // PT_LOAD
            if (p_vaddr < min_load_vaddr) {
                min_load_vaddr = p_vaddr;
            }
        }
    }
    uint64_t effective_page_size = at_pagesz ? at_pagesz : page_size;

    if (effective_page_size == 0 || (effective_page_size & (effective_page_size - 1)) != 0) {
        fprintf(stderr, "[AUXV] fail: invalid AT_PAGESZ=0x%lx\n",
                (unsigned long)effective_page_size);
        return false;
    }
    uint64_t bias = 0;
    if (have_ptphdr) {
        if (at_phdr < ptphdr_vaddr) {
            return false;
        }
        bias = at_phdr - ptphdr_vaddr;
    } else if (min_load_vaddr != UINT64_MAX) {
        uint64_t page_mask = ~(effective_page_size - 1);
        uint64_t runtime_page = at_phdr & page_mask;
        uint64_t load_page = min_load_vaddr & page_mask;

        if (runtime_page < load_page) {
            return false;
        }
        bias = runtime_page - load_page;
    } else {
        fprintf(stderr, "[AUXV] fail: no PT_LOAD program header\n");
        return false;
    }
    //seeding + window = success
    if (!window_from_phdrs(at_phdr, at_phent, at_phnum, bias) ||
        !seed_main_file_taint(at_phdr, at_phent, at_phnum, bias)) {
        return false;
    }
    if (at_pagesz && at_pagesz != page_size) {
        fprintf(stderr, "[AUXV] AT_PAGESZ=0x%lx differs from default page_size=0x%lx\n",
                (unsigned long)at_pagesz, (unsigned long)page_size);
    }
    page_size = (size_t)effective_page_size;
    g_ld_base = at_base;
    g_stub_entry = at_entry;
    fprintf(stderr, "[WINDOW] auxv: main [0x%lx,0x%lx) ld_base=0x%lx entry=0x%lx bias=0x%lx\n",
            (unsigned long)g_main_lo, (unsigned long)g_main_hi, (unsigned long)g_ld_base,
            (unsigned long)g_stub_entry, (unsigned long)bias);
    return true;
}

//bases form ELF phdrs, fallback if no auxv read
static bool window_from_elf_header(uint64_t base) {
    if (!base)
        return false;
    uint8_t ident[16];
    if (!guest_read_bytes(base, ident, 16))
        return false;
    if (!(ident[0] == 0x7f && ident[1] == 'E' && ident[2] == 'L' && ident[3] == 'F'))
        return false;
    bool w64 = (ident[4] == 2);
    uint64_t e_type = 0, e_phoff = 0, e_phnum = 0, e_phentsize = 0;
    uint64_t off_type = 16;
    uint64_t off_phoff = w64 ? 32 : 28;
    uint64_t off_phent = w64 ? 54 : 42;
    uint64_t off_phnum = w64 ? 56 : 44;
    if (!guest_read_uint(base + off_type, 2, &e_type))
        return false;
    if (!guest_read_uint(base + off_phoff, w64 ? 8 : 4, &e_phoff))
        return false;
    if (!guest_read_uint(base + off_phent, 2, &e_phentsize))
        return false;
    if (!guest_read_uint(base + off_phnum, 2, &e_phnum))
        return false;
    uint64_t bias = (e_type == 3) ? base : 0;
    bool ok = window_from_phdrs(base + e_phoff, e_phentsize, e_phnum, bias);
    if (ok)
        fprintf(stderr, "[WINDOW] elf-header@0x%lx: main [0x%lx,0x%lx)\n", (unsigned long)base,
                (unsigned long)g_main_lo, (unsigned long)g_main_hi);
    return ok;
}

//get boundaries from contiguity, fallback if not both previous
static void window_from_pagetable(GList *keys) {
    const uint64_t GAP_MAX = 64 * page_size;
    uint64_t lo = 0, hi = 0;
    bool have = false;
    for (GList *k = keys; k; k = k->next) {
        uint64_t addr = (uint64_t)(uintptr_t)k->data;
        if (addr_in_lib(addr) || addr == 0)
            continue;
        if (!have) {
            lo = addr;
            hi = addr + page_size;
            have = true;
            continue;
        }
        if (addr <= hi + GAP_MAX)
            hi = addr + page_size;
        else
            break;
    }
    if (have) {
        g_main_lo = lo;
        g_main_hi = hi;
        g_main_known = true;
        fprintf(stderr, "[WINDOW] page-table heuristic: main [0x%lx,0x%lx)\n",
                (unsigned long)g_main_lo, (unsigned long)g_main_hi);
    }
}

//helper for determine which prefer
static void establish_main_window_fallback(GList *keys) {
    if (g_main_known)
        return;
    uint64_t base = 0;
    for (GList *k = keys; k; k = k->next) {
        uint64_t addr = (uint64_t)(uintptr_t)k->data;
        if (!addr_in_lib(addr)) {
            base = addr;
            break;
        }
    }
    if (window_from_elf_header(base))
        return;
    window_from_pagetable(keys);
}

//is page in boundaries
static bool page_is_program(uint64_t addr, const page_t *p) {
    if (addr_in_lib(addr))
        return false;
    if (!g_main_known)
        return true;
    if (addr >= g_main_lo && addr < g_main_hi)
        return true;
    if (p && (p->exec_seen || p->exec_after_write || p->dyn_exec))
        return true;
    return false;
}

static void do_dump(uint64_t oep) {
    GList *keys = g_hash_table_get_keys(pages);
    keys = g_list_sort(keys, compare_keys);

    establish_main_window_fallback(keys);

    g_static_binary = (lib_deps == NULL);

    if (!bin_dumped) {
        FILE *f_bin = fopen("unpacked.bin", "wb");
        if (f_bin) {
            for (GList *k = keys; k; k = k->next) {
                uint64_t addr = (uint64_t)(uintptr_t)k->data;
                page_t *p = g_hash_table_lookup(pages, k->data);
                if (!p)
                    continue;
                if (!page_is_program(addr, p))
                    continue;
                GByteArray *data = g_byte_array_new();
                if (qemu_plugin_read_memory_vaddr(addr, data, page_size) && data->len > 0) {
                    fwrite(data->data, 1, data->len, f_bin);
                }
                g_byte_array_free(data, TRUE);
            }
            fclose(f_bin);
            bin_dumped = true;
        }
    }

    if (!saved_reg) {
        saved_reg = g_string_new(NULL);
        g_string_append(saved_reg, "  \"regions\": [\n");
        bool in_region = false;
        bool first_region = true;
        uint64_t main_off = 0;
        uint64_t region_start = 0;
        uint64_t region_size = 0;
        int region_prot = 0;
        const char *region_mod = NULL;
        bool region_is_lib = false;
        uint64_t region_off = 0;
        char modbuf[512];

        for (GList *k = keys; k; k = k->next) {
            uint64_t addr = (uint64_t)(uintptr_t)k->data;
            page_t *p = g_hash_table_lookup(pages, k->data);
            if (!p)
                continue;
            if (!addr_in_lib(addr) && !page_is_program(addr, p))
                continue;

            GByteArray *data = g_byte_array_new();
            size_t written = 0;
            bool ok = qemu_plugin_read_memory_vaddr(addr, data, page_size);
            if (ok && data->len > 0) {
                written = data->len;
            } else {
                written = 0;
            }
            g_byte_array_free(data, TRUE);
            if (written == 0)
                continue;

            const char *mod = addr_lib_path(addr);
            bool is_lib = (mod != NULL);
            if (in_region && addr == region_start + region_size && p->prot == region_prot &&
                mod == region_mod) {
                region_size += written;
            } else {
                if (in_region) {
                    if (!first_region)
                        g_string_append(saved_reg, ",\n");
                    first_region = false;
                    if (region_mod) {
                        snprintf(modbuf, sizeof modbuf, "\"%s\"", base_name(region_mod));
                    } else if (g_static_binary) {
                        snprintf(modbuf, sizeof modbuf, "\"static\"");
                    } else if (g_main_known && region_start >= g_main_lo &&
                               region_start < g_main_hi) {
                        snprintf(modbuf, sizeof modbuf, "\"main\"");
                    } else {
                        snprintf(modbuf, sizeof modbuf, "null");
                    }
                    g_string_append_printf(
                        saved_reg,
                        "    {\"addr\": \"0x%lx\", \"size\": %lu, \"prot\": %d, \"offset\": %lu, \"lib\": %s, \"module\": %s}",
                        region_start, region_size, region_prot, region_off,
                        region_is_lib ? "true" : "false", modbuf);
                }
                region_start = addr;
                region_size = written;
                region_prot = p->prot;
                region_mod = mod;
                region_is_lib = is_lib;
                region_off = main_off;
                if (!is_lib && !saved_base_set) {
                    saved_base = region_start;
                    saved_base_set = true;
                }
                in_region = true;
            }
            if (!is_lib) {
                main_off += written;
            }
        }
        if (in_region) {
            if (!first_region)
                g_string_append(saved_reg, ",\n");
            if (region_mod) {
                snprintf(modbuf, sizeof modbuf, "\"%s\"", base_name(region_mod));
            } else if (g_static_binary) {
                snprintf(modbuf, sizeof modbuf, "\"static\"");
            } else if (g_main_known && region_start >= g_main_lo && region_start < g_main_hi) {
                snprintf(modbuf, sizeof modbuf, "\"main\"");
            } else {
                snprintf(modbuf, sizeof modbuf, "null");
            }
            g_string_append_printf(
                saved_reg,
                "    {\"addr\": \"0x%lx\", \"size\": %lu, \"prot\": %d, \"offset\": %lu, \"lib\": %s, \"module\": %s}\n",
                region_start, region_size, region_prot, region_off,
                region_is_lib ? "true" : "false", modbuf);
        }
        g_string_append(saved_reg, "  ],\n");
    }
    g_list_free(keys);
    image_captured = true;
    fprintf(stderr, "[DUMP] unpacked.bin captured (oep=0x%lx)\n", (unsigned long)oep);
}

static void write_report(void) {
    if (!image_captured)
        do_dump(saved_oep);

    FILE *f_json = fopen("unpacked.json", "w");
    if (!f_json)
        return;

    fprintf(f_json, "{\n");
    fprintf(f_json, "  \"oep\": \"0x%lx\",\n", saved_oep);
    fprintf(f_json, "  \"arch\": \"x86\",\n");
    fprintf(f_json, "  \"oep_confidence\": %.4f,\n", g_oep_confidence);
    if (g_oep_scoring)
        fprintf(f_json, "%s", g_oep_scoring->str);
    fprintf(f_json, "  \"base\": \"0x%lx\",\n", saved_base);
    fprintf(f_json, "%s", saved_reg ? saved_reg->str : "  \"regions\": [],\n");

    // files
    fprintf(f_json, "  \"file_dependencies\": [");
    bool first = true;
    for (GList *l = file_deps; l; l = l->next) {
        file_dep_t *f = (file_dep_t *)l->data;
        if (!f->path)
            continue;
        if (!first)
            fprintf(f_json, ",\n");
        fprintf(f_json, "    {\"path\": \"%s\", \"write\": %s}", f->path,
                f->write ? "true" : "false");
        first = false;
    }
    fprintf(f_json, "],\n");

    // libraries
    fprintf(f_json, "  \"library_dependencies\": [");
    first = true;
    for (GList *l = lib_deps; l; l = l->next) {
        lib_mapping_t *lm = (lib_mapping_t *)l->data;
        if (!lm->path || !*lm->path || *lm->path != '/' || !is_valid_path(lm->path))
            continue;
        uint64_t span;
        if (lm->end > lm->base) {
            span = (lm->end - lm->base);
        } else {
            span = lm->size;
        }
        if (!first)
            fprintf(f_json, ", ");
        fprintf(f_json, "{\"path\": \"%s\", \"base\": \"0x%lx\", \"size\": %lu}", lm->path,
                lm->base, span);
        first = false;
    }
    fprintf(f_json, "],\n");

    //got reconstruct
    fprintf(f_json, "  \"resolved_imports\": [");
    first = true;
    for (GList *l = resolved_imports; l; l = l->next) {
        resolved_import_t *ri = (resolved_import_t *)l->data;
        if (!ri || !ri->module)
            continue;
        if (g_main_known && (ri->got_slot < g_main_lo || ri->got_slot >= g_main_hi))
            continue;
        if (!first)
            fprintf(f_json, ", ");
        fprintf(
            f_json,
            "{\"got_slot\": \"0x%lx\", \"resolved_addr\": \"0x%lx\", \"module\": \"%s\", \"offset\": \"0x%lx\"}",
            (unsigned long)ri->got_slot, (unsigned long)ri->resolved_addr, ri->module,
            (unsigned long)(ri->resolved_addr - ri->lib_base));
        first = false;
    }
    fprintf(f_json, "],\n");

    // network
    fprintf(f_json, "  \"network_dependencies\": [\n");
    bool net_first = true;
    for (GList *l = net_deps; l; l = l->next) {
        net_dep_t *n = (net_dep_t *)l->data;
        if (!n)
            continue;
        if (!net_first)
            fprintf(f_json, ",\n");
        net_first = false;
        const char *type_str = (n->type == SOCK_STREAM)  ? "tcp"
                               : (n->type == SOCK_DGRAM) ? "udp"
                               : (n->type == SOCK_RAW)   ? "raw"
                                                         : "unknown";
        const char *domain_str = (n->domain == AF_INET)    ? "AF_INET"
                                 : (n->domain == AF_INET6) ? "AF_INET6"
                                                           : "unknown";
        if (strcmp(n->op, "socket") == 0) {
            fprintf(f_json, "    {\"op\":\"socket\",\"fd\":%d,\"domain\":\"%s\",\"type\":\"%s\"}",
                    n->fd, domain_str, type_str);
        } else if (strcmp(n->op, "bind") == 0 || strcmp(n->op, "connect") == 0) {
            fprintf(f_json,
                    "    {\"op\":\"%s\",\"fd\":%d,\"ip\":\"%s\",\"port\":%d,\"type\":\"%s\"}",
                    n->op, n->fd, n->ip, n->port, type_str);
        } else if (strcmp(n->op, "accept") == 0 && n->ip[0]) {
            fprintf(f_json, "    {\"op\":\"accept\",\"fd\":%d,\"peer_ip\":\"%s\",\"peer_port\":%d}",
                    n->fd, n->ip, n->port);
        } else {
            fprintf(f_json, "    {\"op\":\"%s\",\"fd\":%d}", n->op, n->fd);
        }
    }
    fprintf(f_json, "\n  ]\n}\n");

    fclose(f_json);
    fprintf(stderr, "[DUMP] unpacked.json complete\n");
}

//collect top-3 candidates by weighted score
static void build_oep_scoring(oep_cand_t *chosen) {
    g_oep_confidence = chosen ? cand_confidence(chosen) : 0.0;
    guint count = g_list_length(oep_cands);
    oep_cand_t **candidates = g_new0(oep_cand_t *, count ? count : 1);
    guint actual_count = 0;

    for (GList *l = oep_cands; l; l = l->next) {
        candidates[actual_count++] = (oep_cand_t *)l->data;
    }
    guint top_count = actual_count < 3 ? actual_count : 3;
    for (guint i = 0; i < top_count; i++) {
        guint best_index = i;
        for (guint j = i + 1; j < actual_count; j++) {
            if (cand_rank_better(candidates[j], candidates[best_index])) {
                best_index = j;
            }
        }
        oep_cand_t *temporary = candidates[i];
        candidates[i] = candidates[best_index];
        candidates[best_index] = temporary;
    }

    if (g_oep_scoring) {
        g_string_free(g_oep_scoring, TRUE);
    }
    g_oep_scoring = g_string_new(NULL);
    g_string_append(g_oep_scoring, "  \"oep_candidates\": [\n");

    for (guint i = 0; i < top_count; i++) {
        oep_cand_t *candidate = candidates[i];
        g_string_append_printf(
            g_oep_scoring,
            "    {\"addr\": \"0x%lx\", "
            "\"score\": %.4f, \"confidence\": %.4f, "
            "\"dse_verdict\": \"%s\", "
            "\"dse_evidence\": \"%s\", "
            "\"dse_reason\": \"%s\", "
            "\"candidate_query\": \"%s\", "
            "\"alternative_query\": \"%s\", "
            "\"target_symbolic\": %s, "
            "\"target_tainted\": %s, "
            "\"slice_complete\": %s, "
            "\"slice_len\": %u, \"concretized\": %u, "
            "\"total\": %u, \"aux_miss\": %u, "
            "\"unsupported\": %u, \"meta_missing\": %u, "
            "\"address_constraints\": %u, "
            "\"address_failures\": %u, "
            "\"relevance_applied\": %s, "
            "\"relevance_complete\": %s, "
            "\"relevance_considered\": %u, "
            "\"relevance_relevant\": %u, "
            "\"relevance_unknown\": %u, "
            "\"relevance_irrelevant\": %u, "
            "\"relevance_iterations\": %u, "
            "\"generation\": %u}%s\n",
            (unsigned long)candidate->addr, cand_score(candidate), cand_confidence(candidate),
            dse_verdict_name(candidate->dse.verdict), dse_evidence_name(candidate->dse.evidence),
            dse_verify_reason_name(candidate->dse.reason),
            dse_solver_status_name(candidate->dse.candidate_query),
            dse_solver_status_name(candidate->dse.alternative_query),
            candidate->dse.target_symbolic ? "true" : "false",
            candidate->target_tainted ? "true" : "false",
            candidate->dse.slice_complete ? "true" : "false", candidate->dse.slice_len,
            candidate->dse.concretized, candidate->dse.lifted_total, candidate->dse.aux_miss,
            candidate->dse.unsupported, candidate->dse.meta_missing,
            candidate->dse.address_constraints, candidate->dse.address_failures,
            candidate->dse.relevance_applied ? "true" : "false",
            candidate->dse.relevance_complete ? "true" : "false",
            candidate->dse.relevance_events_considered, candidate->dse.relevance_events_relevant,
            candidate->dse.relevance_events_unknown, candidate->dse.relevance_events_irrelevant,
            candidate->dse.relevance_iterations, candidate->generation,
            i + 1 < top_count ? "," : "");
    }

    g_string_append(g_oep_scoring, "  ],\n");
    g_free(candidates);
}

static oep_cand_t *find_oep_cand(uint64_t addr) {
    for (GList *l = oep_cands; l; l = l->next) {
        oep_cand_t *candidate = (oep_cand_t *)l->data;
        if (candidate->addr == addr)
            return candidate;
    }
    return NULL;
}

static void archive_pending_trace_occurrences(void) {
    if (!g_trace || !g_aux || !g_vcpu_states_lock_initialized || !g_vcpu_states) {
        g_cur_aux = NULL;
        return;
    }
    g_mutex_lock(&g_vcpu_states_lock);
    for (guint index = 0; index < g_vcpu_states->len; index++) {
        PluginVcpuState *state = g_ptr_array_index(g_vcpu_states, index);
        if (!state || state->current_aux_seq_id == 0) {
            continue;
        }
        (void)dse_aux_archive_occurrence(g_aux, g_trace, g_branch_events,
                                         state->current_aux_seq_id);
        state->current_aux = NULL;
        state->current_aux_seq_id = 0;
    }
    g_mutex_unlock(&g_vcpu_states_lock);
    g_cur_aux = NULL;
}

static void plugin_exit(qemu_plugin_id_t id, void *udata) {
    (void)id;
    (void)udata;
    archive_pending_trace_occurrences();
    dta_shadow_report(g_shadow);
    if (g_ir_report) {
        if (!ir_runtime_summary_json(g_ir_report, &g_ir_runtime))
            fprintf(stderr, "[IR] summary write failed\n");
        if (fclose(g_ir_report))
            fprintf(stderr, "[IR] report close failed\n");
        g_ir_report = NULL;
    }
    if (g_trace) {
        fprintf(stderr,
                "[TRACE-ARCHIVE] occurrences=%" PRIu64 " bytes=%" PRIu64 " incomplete=%" PRIu64
                " dropped=%" PRIu64 " complete=%s\n",
                trace_occurrence_archive_count(g_trace), trace_occurrence_archive_bytes(g_trace),
                trace_occurrence_archive_incomplete(g_trace),
                trace_occurrence_archive_dropped(g_trace),
                trace_occurrence_archive_is_complete(g_trace) ? "yes" : "no");
    }
    //oep choose
    oep_cand_t *chosen = NULL;
    if (oep_found) {
        chosen = find_oep_cand(oep_addr);
    }

    if (!oep_found && oep_cands) {
        chosen = choose_oep_cand();
        if (chosen) {
            oep_addr = chosen->addr;
            oep_found = true;
        }
    }
    if (oep_cands) {
        build_oep_scoring(chosen);
    }

    //write json-report
    saved_oep = oep_addr;
    write_report();
    //memory free
    for (GList *l = file_deps; l; l = l->next) {
        file_dep_t *f = (file_dep_t *)l->data;
        g_free(f->path);
        g_free(f);
    }
    g_list_free(file_deps);
    for (GList *l = lib_deps; l; l = l->next) {
        lib_mapping_t *lm = (lib_mapping_t *)l->data;
        g_free(lm->path);
        g_free(lm);
    }
    g_list_free(lib_deps);
    for (GList *l = net_deps; l; l = l->next) {
        net_dep_t *n = (net_dep_t *)l->data;
        g_free(n->payload_hex);
        g_free(n);
    }
    g_list_free(net_deps);
    g_hash_table_destroy(file_fd);

    if (unmapped_pages) {
        g_hash_table_destroy(unmapped_pages);
        unmapped_pages = NULL;
    }

    if (g_sockets) {
        GHashTableIter iter;
        gpointer key, value;
        g_hash_table_iter_init(&iter, g_sockets);
        while (g_hash_table_iter_next(&iter, &key, &value)) {
            net_dep_t *n = value;
            g_free(n->payload_hex);
            g_free(n);
        }
    }
    g_hash_table_destroy(g_sockets);

    //fd
    g_free(pending_open_path);

    //capstone handle
    cs_close(&cs_handle);
    insn_exec_contexts_destroy();
    meta_free();

    //tracer
    if (g_dcfg) {
        DcfgStats stats;
        dcfg_graph_get_stats(g_dcfg, &stats);
        fprintf(stderr,
                "[DCFG-SUMMARY]"
                " nodes=%u"
                " edges=%u"
                " occurrences=%" PRIu64 "\n",
                stats.node_count, stats.edge_count, stats.branch_occurrence_count);
        dcfg_graph_destroy(g_dcfg);
        g_dcfg = NULL;
    }
    if (g_branch_events) {
        branch_event_buffer_destroy(g_branch_events);
        g_branch_events = NULL;
    }
    dse_lift_attach(NULL, NULL, NULL);
    g_cur_aux = NULL;
    dse_aux_destroy(g_aux);
    g_aux = NULL;
    trace_buffer_destroy(g_trace);
    g_trace = NULL;

    //oeps
    if (saved_reg) {
        g_string_free(saved_reg, TRUE);
        saved_reg = NULL;
    }
    g_list_free_full(oep_cands, g_free);
    oep_cands = NULL;
    //got
    g_list_free_full(resolved_imports, g_free);
    resolved_imports = NULL;
    if (resolved_imports_by_slot) {
        g_hash_table_destroy(resolved_imports_by_slot);
        resolved_imports_by_slot = NULL;
    }
    provenance_runtime_destroy();
    g_clear_pointer(&g_main_image_path, g_free);
}

static bool insn_is_unpacked(uint64_t vaddr, size_t size) {
    for (size_t i = 0; i < size; i++) {
        uint64_t addr = vaddr + i;
        uint64_t page_addr = addr & ~(page_size - 1);
        page_t *page = g_hash_table_lookup(pages, (gpointer)(uintptr_t)page_addr);

        if (!page || !(page->prot & 0x4))
            continue;

        if (page->dyn_exec)
            return true;

        if (page->wbitmap) {
            unsigned offset = addr & (page_size - 1);
            if (page->wbitmap[offset >> 3] & (1u << (offset & 7)))
                return true;
        }
    }
    return false;
}

static void vcpu_insn_exec(unsigned int cpu_index, void *udata) {
    const InsnExecCtx *exec_ctx = (const InsnExecCtx *)udata;
    if (!exec_ctx)
        return;
    PluginVcpuState *vcpu_state = plugin_vcpu_state_get(cpu_index);
    if (!vcpu_state) {
        fprintf(stderr, "[DTA] missing vCPU state: vcpu=%u\n", cpu_index);
        return;
    }
    RegShadow *regs = &vcpu_state->dta.regs;
    dta_mem_transfer_t *transfer = &vcpu_state->mem_transfer;
    uint64_t vaddr = exec_ctx->pc;
    const InsnMeta *meta = exec_ctx->meta;
    finalize_missing_memory_flag_transfer(vcpu_state);
    finalize_pending_branch(vcpu_state, vaddr);
    finalize_pending_transfer(vcpu_state, vaddr);
    dcfg_track_instruction(vcpu_state, vaddr, exec_ctx->size);
    uint64_t current_reg_vals[REG_COUNT] = {0};
    uint32_t current_reg_value_valid_mask = 0;
    uint32_t current_eflags = 0;
    bool current_eflags_valid = false;
    InsnAux *previous_aux = vcpu_state->current_aux;
    uint64_t previous_aux_seq_id = vcpu_state->current_aux_seq_id;
    bool need_dse_snapshot = previous_aux != NULL || (g_trace != NULL && g_aux != NULL);
    if (need_dse_snapshot) {
        current_reg_value_valid_mask = dse_read_register_snapshot(current_reg_vals);
        if (dse_read_eflags(&current_eflags)) {
            current_eflags_valid = true;
        }
    }
    if (previous_aux && previous_aux_seq_id != 0 && previous_aux->valid &&
        previous_aux->seq_id == previous_aux_seq_id) {
        dse_aux_finalize(previous_aux, vaddr, current_reg_vals, current_reg_value_valid_mask);
        (void)dse_aux_archive_occurrence(g_aux, g_trace, g_branch_events, previous_aux_seq_id);
    } else if (previous_aux || previous_aux_seq_id != 0) {
        trace_occurrence_archive_note_loss(g_trace);
    }
    vcpu_state->current_aux = NULL;
    vcpu_state->current_aux_seq_id = 0;
    g_cur_aux = NULL;
    vcpu_state->current_ip = vaddr;
    transfer->active = true;
    transfer->pc = vaddr;
    transfer->pre_regs = *regs;
    transfer->pre_esp_valid = false;
    transfer->pre_esp = 0;
    transfer->meta = meta;
    transfer->flags_pending = meta && meta->flags_write_mask != 0 && meta->has_mem_read;
    transfer->flags_applied = false;
    if (meta && meta->insn_id == X86_INS_POPAL) {
        uint32_t rsp_bit = UINT32_C(1) << REG_RSP;
        if (current_reg_value_valid_mask & rsp_bit) {
            transfer->pre_esp = (uint32_t)current_reg_vals[REG_RSP];
            transfer->pre_esp_valid = true;
        } else {
            uint64_t pre_esp = 0;
            if (dse_read_reg(REG_RSP, &pre_esp)) {
                transfer->pre_esp = (uint32_t)pre_esp;
                transfer->pre_esp_valid = true;
            }
        }
    }
    transfer->last_read_valid = false;
    transfer->last_read_size = 0;
    for (uint8_t byte = 0; byte < MAX_REG_BYTES; byte++) {
        transfer->last_read_labels[byte] = PROV_LABEL_CLEAN;
    }
    g_icount++;
    if (!g_auxv_done && g_icount >= g_auxv_next_retry) {
        if (!g_regs_ready) {
            dse_init_reg_handles();
        }
        g_auxv_attempts++;
        g_auxv_done = read_auxv_from_stack();
        if (!g_auxv_done) {
            uint32_t shift = g_auxv_attempts < 16 ? g_auxv_attempts : 16;
            uint64_t delay = 1ULL << shift;
            g_auxv_next_retry = g_icount > UINT64_MAX - delay ? UINT64_MAX : g_icount + delay;
        }
    }
    uint64_t current_trace_seq_id = 0;
    if (g_trace) {
        TraceEntry entry = {0};
        entry.vcpu_index = cpu_index;
        entry.pc = vaddr;
        entry.insn_desc_id = exec_ctx->insn_desc_id;
        entry.meta_id = exec_ctx->meta_id;
        entry.code_generation = exec_ctx->code_generation;
        entry.bytes_hash = exec_ctx->bytes_hash;
        entry.size = exec_ctx->size;
        memcpy(entry.instr_bytes, exec_ctx->instr_bytes, exec_ctx->size);
        const TraceEntry *stored_entry = trace_append(g_trace, &entry);
        if (stored_entry) {
            current_trace_seq_id = stored_entry->seq_id;
        }
        if (stored_entry && g_aux) {
            InsnAux aux;
            DseSourceObservation source_snapshot;
            memset(&aux, 0, sizeof(aux));
            memcpy(aux.reg_vals, current_reg_vals, sizeof(aux.reg_vals));
            aux.reg_value_valid_mask = current_reg_value_valid_mask;
            if (g_ir_enabled) {
                dse_aux_capture_sources(&source_snapshot, &vcpu_state->dta, is_i386 ? 4 : 8);
                aux.sources = &source_snapshot;
            }
            dse_aux_set_eflags(&aux, current_eflags, current_eflags_valid, g_x86_flags_verified);
            for (int reg = 0; reg < REG_COUNT; reg++) {
                uint8_t taint_mask = 0;
                for (uint8_t byte = 0; byte < 4; byte++) {
                    if (plugin_label_may_be_tainted(regs->bytes[reg][byte])) {
                        taint_mask |= (uint8_t)(UINT32_C(1) << byte);
                    }
                }
                aux.reg_taint[reg] = taint_mask;
            }
            g_cur_aux = dse_aux_record(g_aux, g_trace, stored_entry, &aux);
            if (g_cur_aux)
                dse_aux_prepare_string(g_cur_aux, meta);
            vcpu_state->current_aux = g_cur_aux;
            vcpu_state->current_aux_seq_id = g_cur_aux ? g_cur_aux->seq_id : 0;
        } else {
            g_cur_aux = NULL;
            vcpu_state->current_aux = NULL;
            vcpu_state->current_aux_seq_id = 0;
        }
    }
    if (g_ir_enabled) {
        if (g_ir_has_start && vaddr == g_ir_start_pc)
            vcpu_state->ir_start_seq = current_trace_seq_id;
        if (g_ir_has_probe && vaddr == g_ir_probe_pc)
            ir_plugin_check(vcpu_state, cpu_index, current_trace_seq_id, IR_RUNTIME_PROBE, 0, -1);
    }
    if (!meta) {
        prev_jump_pending = false;
        prev_jump_site = 0;
        prev_jump_seq_id = 0;
        prev_target_reg = REG_INVALID;
        prev_mem_taddr = 0;
        prev_mem_target_value = 0;
        prev_mem_target_valid = false;
        prev_target_tainted = false;
        return;
    }
    //detect mov to upacked code
    bool now_unpacked = insn_is_unpacked(vaddr, meta->size);
    page_t *cur_pg = NULL;
    if (now_unpacked) {
        uint64_t page_addr = vaddr & ~(page_size - 1);
        cur_pg = g_hash_table_lookup(pages, (gpointer)(uintptr_t)page_addr);
    }

    bool prev_jump_matches = prev_jump_pending;
    if (prev_jump_matches && prev_mem_target_valid) {
        prev_jump_matches = ((uint32_t)vaddr == (uint32_t)prev_mem_target_value);
    }

    bool new_layer =
        now_unpacked && !oep_found && cur_pg && !cur_pg->exec_seen && prev_jump_matches;
    if (cur_pg)
        cur_pg->exec_seen = true;

    if (new_layer) {
        oep_cand_t *candidate = g_new0(oep_cand_t, 1);
        candidate->addr = vaddr;
        candidate->has_prologue = cand_has_prologue(vaddr);
        if (prev_jump_matches) {
            candidate->jump_site = prev_jump_site;
        } else {
            candidate->jump_site = 0;
        }
        candidate->jump_from_unmapped = jump_site_is_unpacker(candidate->jump_site);
        if (g_layer_dirty) {
            g_layer++;
            g_layer_dirty = false;
            g_layer_has_cand = false;
        }
        candidate->generation = g_layer;
        candidate->icount = g_icount;
        candidate->target_tainted = prev_target_tainted;
        ir_plugin_check(vcpu_state, cpu_index, prev_jump_seq_id, IR_RUNTIME_CANDIDATE, vaddr,
                        prev_target_reg);
        candidate->dse.verdict = DSE_VERDICT_UNKNOWN;
        candidate->dse.evidence = DSE_EVIDENCE_NONE;
        candidate->dse.reason = DSE_REASON_TARGET_UNAVAILABLE;
        candidate->dse.candidate_query = DSE_SOLVER_NOT_RUN;
        candidate->dse.alternative_query = DSE_SOLVER_NOT_RUN;

        if (prev_jump_matches) {
            DseRelevanceContext relevance_context = {
                .registry = g_prov_registry, .dcfg = g_dcfg, .branch_events = g_branch_events};
            if (prev_target_reg >= 0 && prev_target_reg < REG_COUNT) {
                candidate->dse = dse_verify_oep_candidate_with_relevance(
                    g_trace, g_aux, prev_jump_seq_id, prev_target_reg, vaddr, g_shadow, cs_handle,
                    &relevance_context);
            } else if (prev_mem_target_valid) {
                candidate->dse = dse_verify_oep_candidate_mem_with_relevance(
                    g_trace, g_aux, prev_jump_seq_id, prev_mem_taddr, vaddr, g_shadow, cs_handle,
                    &relevance_context);
            }
        }
        fprintf(stderr,
                "[OEP-CAND gen=%u] 0x%lx jmp@0x%lx "
                "target_taint=%s dse=%s evidence=%s reason=%s "
                "candidate=%s alternative=%s "
                "(slice %u; concretized %u/%u; aux_miss %u, "
                "unsup %u, meta_miss %u, addr_eq %u, addr_fail %u, "
                "roots reg=%u mem=%u addr=%u; "
                "relevance considered=%u relevant=%u unknown=%u skipped=%u "
                "iterations=%u applied=%s complete=%s)\n",
                candidate->generation, (unsigned long)candidate->addr,
                (unsigned long)candidate->jump_site, candidate->target_tainted ? "yes" : "no",
                dse_verdict_name(candidate->dse.verdict),
                dse_evidence_name(candidate->dse.evidence),
                dse_verify_reason_name(candidate->dse.reason),
                dse_solver_status_name(candidate->dse.candidate_query),
                dse_solver_status_name(candidate->dse.alternative_query), candidate->dse.slice_len,
                candidate->dse.concretized, candidate->dse.lifted_total, candidate->dse.aux_miss,
                candidate->dse.unsupported, candidate->dse.meta_missing,
                candidate->dse.address_constraints, candidate->dse.address_failures,
                candidate->dse.boundary_reg_bytes, candidate->dse.boundary_mem_bytes,
                candidate->dse.address_root_bytes, candidate->dse.relevance_events_considered,
                candidate->dse.relevance_events_relevant, candidate->dse.relevance_events_unknown,
                candidate->dse.relevance_events_irrelevant, candidate->dse.relevance_iterations,
                candidate->dse.relevance_applied ? "yes" : "no",
                candidate->dse.relevance_complete ? "yes" : "no");
        fprintf(stderr,
                "[DSE-MEM] expr_nodes=%u/%u "
                "z3_cache=%u/%u resource_limit=%s\n",
                candidate->dse.expr_nodes_created, DSE_MAX_EXPR_NODES,
                candidate->dse.z3_cache_nodes, DSE_MAX_Z3_CACHE_NODES,
                candidate->dse.resource_limit_hit ? "yes" : "no");
        oep_cands = g_list_append(oep_cands, candidate);
        g_layer_has_cand = true;
        g_last_cand_icount = g_icount;
    }
    prev_jump_pending = false;
    prev_jump_site = 0;
    prev_jump_seq_id = 0;
    prev_target_reg = REG_INVALID;
    prev_mem_taddr = 0;
    prev_mem_target_value = 0;
    prev_mem_target_valid = false;
    prev_target_tainted = false;
    //if we are too long in unpacked code without proceeding further - we end the cycle
    if (now_unpacked && !oep_found && g_last_cand_icount &&
        (g_icount - g_last_cand_icount) > 200000) {
        oep_cand_t *chosen = choose_oep_cand();
        if (chosen) {
            oep_addr = chosen->addr;
            oep_found = true;
            fprintf(stderr, "[OEP-FINAL gen=%u] 0x%lx\n", chosen->generation,
                    (unsigned long)chosen->addr);
            do_dump(oep_addr);
        }
    }
    if (meta->flags_write_mask != 0 && !meta->has_mem_read) {
        (void)dta_apply_flag_transfer(&vcpu_state->dta, &transfer->pre_regs, meta, NULL, 0);
        if (dta_flag_mask_is_tainted(&vcpu_state->dta, meta->flags_write_mask)) {
            g_taint_seen = true;
        }
    }
    (void)dta_apply_reg_transfer(regs, meta);
    bool track_indirect = meta->is_indirect_branch && !oep_found;
    if (track_indirect) { //indirect check
        bool target_resolved = false;
        bool target_tainted = false;
        bool mem_target_valid = false;
        uint64_t taddr = 0;
        uint64_t tval = 0;
        //jmp/call reg
        if (meta->branch_target_reg >= 0 && meta->branch_target_reg < REG_COUNT) {
            target_resolved = true;
            target_tainted = reg_is_tainted(regs, meta->branch_target_reg, 0x0F);
            //jmp/call [mem] or ret
        } else if (meta->branch_target_reg == REG_INVALID) {
            if (dse_resolve_mem_target(vaddr, meta, &taddr, &tval)) {
                target_resolved = true;
                mem_target_valid = true;
                //check target mem
                ProvLabelId raw_target_labels[4];
                ProvLabelId effective_target_labels[4];
                bool target_labels_valid =
                    shadow_load_labels(g_shadow, taddr, raw_target_labels, 4) &&
                    dta_effective_mem_read_labels(&transfer->pre_regs, meta, raw_target_labels, 4,
                                                  effective_target_labels);
                target_tainted =
                    !target_labels_valid || label_array_has_taint(effective_target_labels, 4);
            }
        }
        if (target_resolved) {
            prev_jump_site = vaddr;
            prev_jump_seq_id = current_trace_seq_id;
            prev_jump_pending = true;
            prev_target_reg = meta->branch_target_reg;
            prev_target_tainted = target_tainted;
            if (mem_target_valid) {
                prev_mem_taddr = taddr;
                prev_mem_target_value = (uint64_t)(uint32_t)tval;
                prev_mem_target_valid = true;
            } else {
                prev_mem_taddr = 0;
                prev_mem_target_value = 0;
                prev_mem_target_valid = false;
            }
        }
    }
    //got
    if (meta->is_indirect_branch && meta->branch_target_reg == REG_INVALID &&
        meta->insn_id != X86_INS_RET && lib_deps) {
        uint64_t slot = 0, val = 0;
        if (dse_resolve_mem_target(vaddr, meta, &slot, &val))
            record_resolved_import(slot, val);
    }
    begin_pending_branch(vcpu_state, meta, current_trace_seq_id);
    begin_pending_transfer(vcpu_state, meta, current_trace_seq_id);
}

//for network
static int pending_socketcall_subcall = -1;
static int pending_socket_domain = -1;
static int pending_socket_type = -1;

static void pending_open_reset(void) {
    g_free(pending_open_path);
    pending_open_path = NULL;
    pending_open_is_lib = false;
    pending_open_write = false;
    pending_open_flags = 0;
}

static void pending_fd_reset(void) {
    memset(&g_pending_fd, 0, sizeof(g_pending_fd));
}

static void pending_fd_capture(int64_t syscall_num, pending_fd_kind_t kind, int32_t fd,
                               uint64_t result_address) {
    g_pending_fd.active = true;
    g_pending_fd.syscall_num = syscall_num;
    g_pending_fd.kind = kind;
    g_pending_fd.fd = fd;
    g_pending_fd.result_address = result_address;
}

static void apply_pending_fd_success(int64_t syscall_num, int64_t syscall_ret) {
    pending_fd_operation_t operation = g_pending_fd;
    pending_fd_reset();
    if (!operation.active)
        return;
    if (operation.syscall_num != syscall_num) {
        fprintf(stderr, "[PROV] pending fd mismatch: expected=%ld actual=%ld\n",
                (long)operation.syscall_num, (long)syscall_num);
        return;
    }

    switch (operation.kind) {
    case PENDING_FD_DUP: {
        int32_t new_fd = (int32_t)(uint32_t)syscall_ret;
        file_dep_t *file =
            file_fd ? g_hash_table_lookup(file_fd, GINT_TO_POINTER(operation.fd)) : NULL;
        if (file) {
            g_hash_table_insert(file_fd, GINT_TO_POINTER(new_fd), file);
        }
        if (g_prov_fd_table && !prov_fd_table_dup(g_prov_fd_table, operation.fd, new_fd, NULL) &&
            file) {
            fprintf(stderr, "[PROV] failed to duplicate OFD: %d -> %d\n", operation.fd, new_fd);
        }
        break;
    }
    case PENDING_FD_CLOSE:
        if (file_fd) {
            g_hash_table_remove(file_fd, GINT_TO_POINTER(operation.fd));
        }
        if (g_prov_fd_table) {
            (void)prov_fd_table_close(g_prov_fd_table, operation.fd);
        }
        break;
    case PENDING_FD_LSEEK: {
        uint64_t new_offset = is_i386 ? (uint64_t)(uint32_t)syscall_ret : (uint64_t)syscall_ret;
        if (g_prov_fd_table) {
            (void)prov_fd_table_set_offset(g_prov_fd_table, operation.fd, new_offset);
        }
        break;
    }
    case PENDING_FD_LLSEEK: {
        uint64_t new_offset = 0;
        if (!guest_read_uint(operation.result_address, 8, &new_offset)) {
            fprintf(stderr, "[PROV] failed to read _llseek result at 0x%" PRIx64 "\n",
                    operation.result_address);
            break;
        }
        if (g_prov_fd_table) {
            (void)prov_fd_table_set_offset(g_prov_fd_table, operation.fd, new_offset);
        }
        break;
    }
    case PENDING_FD_NONE:
    default:
        break;
    }
}

static void vcpu_syscall(qemu_plugin_id_t id, unsigned int vcpu_idx, int64_t num, uint64_t a1,
                         uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6,
                         uint64_t a7, uint64_t a8) {
    (void)id;
    (void)vcpu_idx;
    (void)a7;
    (void)a8;
    pending_input_reset();
    pending_open_reset();
    pending_fd_reset();
    //x86
    if (is_i386 && num == 3) { // read
        pending_input_capture_linear(num, (int32_t)(uint32_t)a1, (uint64_t)(uint32_t)a2,
                                     (uint64_t)(uint32_t)a3, false, false, 0);
    } else if (is_i386 && num == 180) { // pread64
        uint64_t explicit_offset = (uint64_t)(uint32_t)a4 | ((uint64_t)(uint32_t)a5 << 32);
        pending_input_capture_linear(num, (int32_t)(uint32_t)a1, (uint64_t)(uint32_t)a2,
                                     (uint64_t)(uint32_t)a3, false, true, explicit_offset);
    } else if (is_i386 && num == 145) { // readv
        (void)pending_input_capture_iov(num, (int32_t)(uint32_t)a1, (uint64_t)(uint32_t)a2,
                                        (int32_t)(uint32_t)a3, false);
    } else if (is_i386 && num == 5) { //open
        char *path = read_guest_string((uint32_t)a1);
        if (path && *path && is_valid_path(path)) {
            pending_open_path = path;
            pending_open_is_lib = (g_str_has_suffix(path, ".so") || strstr(path, ".so.")) &&
                                  !g_str_has_suffix(path, ".cache");
            pending_open_flags = (uint32_t)a2;
            pending_open_write = (pending_open_flags & 3U) != 0;
        } else {
            g_free(path);
        }
    } else if (is_i386 && num == 295) { // openat
        char *path = read_guest_string((uint32_t)a2);
        if (path && *path && is_valid_path(path)) {
            pending_open_path = path;
            pending_open_is_lib = (g_str_has_suffix(path, ".so") || strstr(path, ".so.")) &&
                                  !g_str_has_suffix(path, ".cache");
            pending_open_flags = (uint32_t)a3;
            pending_open_write = (pending_open_flags & 3U) != 0;
        } else {
            g_free(path);
        }
    } else if (num == 4 || num == 146 || num == 181) { // write, writev pwrite
        gpointer val = g_hash_table_lookup(file_fd, GINT_TO_POINTER((int)a1));
        if (val) {
            file_dep_t *f = (file_dep_t *)val;
            f->write = true;
        }
    } else if (is_i386 && num == 41) { // dup
        pending_fd_capture(num, PENDING_FD_DUP, (int32_t)(uint32_t)a1, 0);
    } else if (is_i386 && (num == 63 || num == 330)) { // dup2 &dup3
        pending_fd_capture(num, PENDING_FD_DUP, (int32_t)(uint32_t)a1, 0);
    } else if (is_i386 && num == 6) { // close
        pending_fd_capture(num, PENDING_FD_CLOSE, (int32_t)(uint32_t)a1, 0);
    } else if (is_i386 && num == 19) { // lseek
        pending_fd_capture(num, PENDING_FD_LSEEK, (int32_t)(uint32_t)a1, 0);
    } else if (is_i386 && num == 140) { // _llseek
        pending_fd_capture(num, PENDING_FD_LLSEEK, (int32_t)(uint32_t)a1, (uint64_t)(uint32_t)a4);
    } else if (num == 33) { // access
        char *path = read_guest_string(a1);
        if (path && *path && is_valid_path(path)) {
            add_file_dep(path, false);
        } else {
            g_free(path);
        }
    } else if (num == 307) { //faccessat
        char *path = read_guest_string(a2);
        if (path && *path && is_valid_path(path)) {
            add_file_dep(path, false);
        } else {
            g_free(path);
        }
    } else if (num == 102) { // socketcall
        int subcall = (int)a1;
        uint32_t args[6] = {0};
        if (!read_socketcall_args(a2, args)) {
            fprintf(stderr, "[NET] socketcall: failed to read args block\n");
            return;
        }
        switch (subcall) {
        case 1: { //socket
            pending_socketcall_subcall = 1;
            pending_socket_domain = (int)args[0];
            pending_socket_type = (int)args[1];
            fprintf(stderr, "[NET] socketcall socket(domain=%d, type=%d)\n", pending_socket_domain,
                    pending_socket_type);
            break;
        }
        case 2: { //bind
            int fd = (int)args[0];
            uint64_t addr_ptr = args[1];
            int addrlen = (int)args[2];
            char ip[INET6_ADDRSTRLEN] = {0};
            uint16_t port = 0;
            if (parse_guest_sockaddr(addr_ptr, addrlen, ip, sizeof(ip), &port)) {
                net_dep_t *n = g_hash_table_lookup(g_sockets, GINT_TO_POINTER(fd));
                if (!n) {
                    n = g_new0(net_dep_t, 1);
                    n->fd = fd;
                    g_hash_table_insert(g_sockets, GINT_TO_POINTER(fd), n);
                }
                g_strlcpy(n->op, "bind", sizeof(n->op));
                g_strlcpy(n->ip, ip, sizeof(n->ip));
                n->port = port;
                net_dep_t *event = g_new0(net_dep_t, 1);
                memcpy(event, n, sizeof(net_dep_t));
                event->payload_hex = NULL;
                net_deps = g_list_append(net_deps, event);
                fprintf(stderr, "[NET] bind fd=%d -> %s:%d\n", fd, ip, port);
            } else {
                fprintf(stderr, "[NET] bind fd=%d: malformed sockaddr\n", fd);
            }
            break;
        }
        case 3: { //connect
            int fd = (int)args[0];
            uint64_t addr_ptr = args[1];
            int addrlen = (int)args[2];
            char ip[INET6_ADDRSTRLEN] = {0};
            uint16_t port = 0;
            if (parse_guest_sockaddr(addr_ptr, addrlen, ip, sizeof(ip), &port)) {
                net_dep_t *n = g_hash_table_lookup(g_sockets, GINT_TO_POINTER(fd));
                if (!n) {
                    n = g_new0(net_dep_t, 1);
                    n->fd = fd;
                    n->domain = (pending_socket_domain != -1) ? pending_socket_domain : AF_UNSPEC;
                    n->type = (pending_socket_type != -1) ? pending_socket_type : SOCK_STREAM;
                    g_hash_table_insert(g_sockets, GINT_TO_POINTER(fd), n);
                }
                g_strlcpy(n->op, "connect", sizeof(n->op));
                g_strlcpy(n->ip, ip, sizeof(n->ip));
                n->port = port;
                net_dep_t *event = g_new0(net_dep_t, 1);
                memcpy(event, n, sizeof(net_dep_t));
                event->payload_hex = NULL;
                net_deps = g_list_append(net_deps, event);
                fprintf(stderr, "[NET] connect fd=%d -> %s:%d\n", fd, ip, port);
            } else {
                fprintf(stderr, "[NET] connect fd=%d: malformed sockaddr\n", fd);
            }
            break;
        }
        case 4: { //listen
            int fd = (int)args[0];
            net_dep_t *event = g_new0(net_dep_t, 1);
            event->fd = fd;
            g_strlcpy(event->op, "listen", sizeof(event->op));
            net_deps = g_list_append(net_deps, event);
            fprintf(stderr, "[NET] listen fd=%d\n", fd);
            break;
        }
        case 5: { //accepnt
            int fd = (int)args[0];
            uint64_t addr_ptr = args[1];
            char ip[INET6_ADDRSTRLEN] = {0};
            uint16_t port = 0;
            if (addr_ptr) {
                GByteArray *tmp = g_byte_array_new();
                if (qemu_plugin_read_memory_vaddr(args[2], tmp, sizeof(uint32_t))) {
                    uint32_t guest_addrlen = *(uint32_t *)tmp->data;
                    parse_guest_sockaddr(addr_ptr, (int)guest_addrlen, ip, sizeof(ip), &port);
                }
                g_byte_array_free(tmp, TRUE);
            }

            net_dep_t *event = g_new0(net_dep_t, 1);
            event->fd = fd;
            g_strlcpy(event->op, "accept", sizeof(event->op));
            g_strlcpy(event->ip, ip, sizeof(event->ip));
            event->port = port;
            net_deps = g_list_append(net_deps, event);
            fprintf(stderr, "[NET] accept fd=%d peer=%s:%d\n", fd, ip[0] ? ip : "?", port);
            break;
        }
        case 9: { //send
            int fd = (int)args[0];
            net_dep_t *event = g_new0(net_dep_t, 1);
            event->fd = fd;
            g_strlcpy(event->op, "send", sizeof(event->op));
            net_deps = g_list_append(net_deps, event);
            fprintf(stderr, "[NET] send fd=%d\n", fd);
            break;
        }
        case 10: { // recv
            int fd = (int)args[0];
            pending_input_capture_linear(num, fd, (uint64_t)args[1], (uint64_t)args[2], true, false,
                                         0);
            net_dep_t *event = g_new0(net_dep_t, 1);
            event->fd = fd;
            g_strlcpy(event->op, "recv", sizeof(event->op));
            net_deps = g_list_append(net_deps, event);
            fprintf(stderr, "[NET] recv fd=%d\n", fd);
            break;
        }
        case 11: { //sendto
            int fd = (int)args[0];
            uint64_t addr_ptr = args[4];
            int addrlen = (int)args[5];
            char ip[INET6_ADDRSTRLEN] = {0};
            uint16_t port = 0;
            if (addr_ptr && parse_guest_sockaddr(addr_ptr, addrlen, ip, sizeof(ip), &port)) {
                net_dep_t *event = g_new0(net_dep_t, 1);
                event->fd = fd;
                g_strlcpy(event->op, "sendto", sizeof(event->op));
                g_strlcpy(event->ip, ip, sizeof(event->ip));
                event->port = port;
                net_deps = g_list_append(net_deps, event);
                fprintf(stderr, "[NET] sendto fd=%d -> %s:%d\n", fd, ip, port);
            } else {
                net_dep_t *event = g_new0(net_dep_t, 1);
                event->fd = fd;
                g_strlcpy(event->op, "send", sizeof(event->op));
                net_deps = g_list_append(net_deps, event);
                fprintf(stderr, "[NET] sendto fd=%d (no addr)\n", fd);
            }
            break;
        }
        case 12: { // recvfrom
            int fd = (int)args[0];
            pending_input_capture_linear(num, fd, (uint64_t)args[1], (uint64_t)args[2], true, false,
                                         0);
            net_dep_t *event = g_new0(net_dep_t, 1);
            event->fd = fd;
            g_strlcpy(event->op, "recv", sizeof(event->op));
            net_deps = g_list_append(net_deps, event);
            fprintf(stderr, "[NET] recvfrom fd=%d\n", fd);
            break;
        }
        case 13: { //shutdown
            int fd = (int)args[0];
            int how = (int)args[1];
            net_dep_t *event = g_new0(net_dep_t, 1);
            event->fd = fd;
            g_strlcpy(event->op, "shutdown", sizeof(event->op));
            net_deps = g_list_append(net_deps, event);
            fprintf(stderr, "[NET] shutdown fd=%d how=%d\n", fd, how);
            break;
        }

        default:
            fprintf(stderr, "[SYSCALL] unknown socketcall subcall=%d\n", subcall);
        }
    } else if ((is_i386 && num == 359) || (!is_i386 && num == 41)) { /* socket */
        pending_socket_domain = (int)a1;
        pending_socket_type = (int)a2;
        fprintf(stderr, "[NET] socket(domain=%ld, type=%ld)\n", a1, a2);
    } else if ((is_i386 && num == 361) || (!is_i386 && num == 49)) { /* bind */
        int fd = (int)a1;
        char ip[INET6_ADDRSTRLEN] = {0};
        uint16_t port = 0;

        if (parse_guest_sockaddr(a2, (int)a3, ip, sizeof(ip), &port)) {
            net_dep_t *n = g_hash_table_lookup(g_sockets, GINT_TO_POINTER(fd));
            if (!n) {
                n = g_new0(net_dep_t, 1);
                n->fd = fd;
                g_hash_table_insert(g_sockets, GINT_TO_POINTER(fd), n);
            }
            g_strlcpy(n->op, "bind", sizeof(n->op));
            g_strlcpy(n->ip, ip, sizeof(n->ip));
            n->port = port;
            net_dep_t *event = g_new0(net_dep_t, 1);
            memcpy(event, n, sizeof(net_dep_t));
            event->payload_hex = NULL;
            net_deps = g_list_append(net_deps, event);
            fprintf(stderr, "[NET] bind fd=%d -> %s:%d\n", fd, ip, port);
        } else {
            fprintf(stderr, "[NET] bind fd=%d: malformed sockaddr\n", fd);
        }
    } else if ((is_i386 && num == 362) || (!is_i386 && num == 42)) { /* connect */
        int fd = (int)a1;
        char ip[INET6_ADDRSTRLEN] = {0};
        uint16_t port = 0;

        if (parse_guest_sockaddr(a2, (int)a3, ip, sizeof(ip), &port)) {
            net_dep_t *n = g_hash_table_lookup(g_sockets, GINT_TO_POINTER(fd));
            if (!n) {
                n = g_new0(net_dep_t, 1);
                n->fd = fd;
                n->domain = (pending_socket_domain != -1) ? pending_socket_domain : AF_UNSPEC;
                n->type = (pending_socket_type != -1) ? pending_socket_type : SOCK_STREAM;
                g_hash_table_insert(g_sockets, GINT_TO_POINTER(fd), n);
            }
            g_strlcpy(n->op, "connect", sizeof(n->op));
            g_strlcpy(n->ip, ip, sizeof(n->ip));
            n->port = port;
            net_dep_t *event = g_new0(net_dep_t, 1);
            memcpy(event, n, sizeof(net_dep_t));
            event->payload_hex = NULL;
            net_deps = g_list_append(net_deps, event);
            fprintf(stderr, "[NET] connect fd=%d -> %s:%d\n", fd, ip, port);
        } else {
            fprintf(stderr, "[NET] connect fd=%d: malformed sockaddr\n", fd);
        }
    } else if ((is_i386 && num == 363) || (!is_i386 && num == 50)) { /* listen */
        net_dep_t *event = g_new0(net_dep_t, 1);
        event->fd = (int)a1;
        g_strlcpy(event->op, "listen", sizeof(event->op));
        net_deps = g_list_append(net_deps, event);
        fprintf(stderr, "[NET] listen fd=%d\n", (int)a1);
    } else if ((is_i386 && num == 364) || (!is_i386 && num == 43)) { /* accept */
        net_dep_t *event = g_new0(net_dep_t, 1);
        event->fd = (int)a1;
        g_strlcpy(event->op, "accept", sizeof(event->op));
        net_deps = g_list_append(net_deps, event);
        fprintf(stderr, "[NET] accept fd=%d\n", (int)a1);
    } else if (!is_i386 && num == 288) { // accept4
        net_dep_t *event = g_new0(net_dep_t, 1);
        event->fd = (int)a1;
        g_strlcpy(event->op, "accept4", sizeof(event->op));
        net_deps = g_list_append(net_deps, event);
        fprintf(stderr, "[NET] accept4 fd=%d flags=%ld\n", (int)a1, a3);
    } else if ((is_i386 && num == 369) || (!is_i386 && num == 44)) { // sendto
        char ip[INET6_ADDRSTRLEN] = {0};
        uint16_t port = 0;
        if (a5 && parse_guest_sockaddr(a5, (int)a6, ip, sizeof(ip), &port)) {
            net_dep_t *event = g_new0(net_dep_t, 1);
            event->fd = (int)a1;
            g_strlcpy(event->op, "sendto", sizeof(event->op));
            g_strlcpy(event->ip, ip, sizeof(event->ip));
            event->port = port;
            net_deps = g_list_append(net_deps, event);
            fprintf(stderr, "[NET] sendto fd=%d -> %s:%d\n", (int)a1, ip, port);
        } else {
            net_dep_t *event = g_new0(net_dep_t, 1);
            event->fd = (int)a1;
            g_strlcpy(event->op, "send", sizeof(event->op));
            net_deps = g_list_append(net_deps, event);
            fprintf(stderr, "[NET] sendto fd=%d (no addr)\n", (int)a1);
        }
    } else if ((is_i386 && num == 371) || (!is_i386 && num == 45)) { // recvfrom
        pending_input_capture_linear(num, (int32_t)(uint32_t)a1,
                                     is_i386 ? (uint64_t)(uint32_t)a2 : a2,
                                     is_i386 ? (uint64_t)(uint32_t)a3 : a3, true, false, 0);
        net_dep_t *event = g_new0(net_dep_t, 1);
        event->fd = (int)a1;
        g_strlcpy(event->op, "recv", sizeof(event->op));
        net_deps = g_list_append(net_deps, event);
        fprintf(stderr, "[NET] recvfrom fd=%d\n", (int)a1);
    } else if ((is_i386 && num == 373) || (!is_i386 && num == 48)) { // shutdown
        net_dep_t *event = g_new0(net_dep_t, 1);
        event->fd = (int)a1;
        g_strlcpy(event->op, "shutdown", sizeof(event->op));
        net_deps = g_list_append(net_deps, event);
        fprintf(stderr, "[NET] shutdown fd=%d how=%ld\n", (int)a1, a2);
    } else if (num == 192) { //mmap2
        memset(&g_pending_mmap, 0, sizeof(g_pending_mmap));

        g_pending_mmap.active = true;
        g_pending_mmap.syscall_num = num;
        g_pending_mmap.requested_addr = (uint32_t)a1;
        g_pending_mmap.size = (uint32_t)a2;
        g_pending_mmap.prot = (int)a3;
        g_pending_mmap.flags = (uint32_t)a4;
        g_pending_mmap.fd = (int32_t)(uint32_t)a5;
        g_pending_mmap.offset = ((uint64_t)(uint32_t)a6) << 12;
    } else if (num == 90) { //mmap
        memset(&g_pending_mmap, 0, sizeof(g_pending_mmap));
        GByteArray *buf = g_byte_array_new();
        if (qemu_plugin_read_memory_vaddr(a1, buf, 24) && buf->len >= 24) {
            uint32_t args[6];
            memcpy(args, buf->data, sizeof(args));
            g_pending_mmap.active = true;
            g_pending_mmap.syscall_num = num;
            g_pending_mmap.requested_addr = args[0];
            g_pending_mmap.size = args[1];
            g_pending_mmap.prot = (int)args[2];
            g_pending_mmap.flags = args[3];
            g_pending_mmap.fd = (int32_t)args[4];
            g_pending_mmap.offset = args[5];
        } else {
            fprintf(stderr, "[MMAP] failed to read old mmap arguments at 0x%lx\n",
                    (unsigned long)a1);
        }
        g_byte_array_free(buf, TRUE);
    } else if (num == 125 || num == 380 || num == 91) { //munmap & mprotect
        memset(&g_pending_mmap, 0, sizeof(g_pending_mmap));
        g_pending_mmap.active = true;
        g_pending_mmap.syscall_num = num;
        g_pending_mmap.requested_addr = (uint32_t)a1;
        g_pending_mmap.size = (uint32_t)a2;
        g_pending_mmap.prot = (num == 91) ? 0 : (int)(uint32_t)a3;
    }
}

static void vcpu_tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb *tb) {
    (void)id;
    size_t n_insns = qemu_plugin_tb_n_insns(tb);
    for (size_t i = 0; i < n_insns; i++) {
        struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);
        uint64_t vaddr = qemu_plugin_insn_vaddr(insn);
        size_t size = qemu_plugin_insn_size(insn);
        uint8_t *bytes = g_malloc(size);
        size_t copied = qemu_plugin_insn_data(insn, (char *)bytes, size);
        InsnMeta *decoded = meta_decode(bytes, copied, vaddr, cs_handle);
        const InsnMeta *meta = decoded ? meta_store(vaddr, decoded) : NULL;
        const uint8_t *desc_bytes = meta ? meta->instr_bytes : bytes;
        size_t desc_size_raw = meta ? meta->size : copied;
        uint8_t desc_size = desc_size_raw <= MAX_INSN_BYTES ? (uint8_t)desc_size_raw : 0;
        uint32_t code_generation = dcfg_code_generation_for_pc(vaddr);
        InsnDescId desc_id =
            trace_insn_desc_intern(g_trace, trace_current_arch_kind(), TRACE_MODE_32, vaddr,
                                   code_generation, desc_bytes, desc_size, meta);
        uint64_t bytes_hash = trace_instruction_bytes_hash(desc_bytes, desc_size);
        InsnExecCtx *exec_ctx = insn_exec_context_create(vaddr, bytes, copied, meta, desc_id,
                                                         code_generation, bytes_hash);
        g_free(bytes);
        if (!exec_ctx) {
            fprintf(stderr, "[TRACE] failed to create instruction context at 0x%lx\n",
                    (unsigned long)vaddr);
            continue;
        }
        if (desc_id == INSN_DESC_ID_INVALID) {
            fprintf(stderr, "[TRACE] reversible descriptor unavailable at 0x%lx\n",
                    (unsigned long)vaddr);
        }

        qemu_plugin_register_vcpu_insn_exec_cb(insn, vcpu_insn_exec, QEMU_PLUGIN_CB_R_REGS,
                                               exec_ctx);
        qemu_plugin_register_vcpu_mem_cb(insn, on_mem_write, QEMU_PLUGIN_CB_NO_REGS,
                                         QEMU_PLUGIN_MEM_W, exec_ctx);
        qemu_plugin_register_vcpu_mem_cb(insn, dse_on_mem, QEMU_PLUGIN_CB_NO_REGS,
                                         QEMU_PLUGIN_MEM_RW, exec_ctx);
    }
}

static void vcpu_syscall_ret(qemu_plugin_id_t id, unsigned int vcpu_idx, int64_t num, int64_t ret) {
    (void)id;
    (void)vcpu_idx;
    const bool syscall_failed = syscall_ret_is_error(ret);
    if (syscall_failed) {
        pending_input_reset();
    } else {
        apply_pending_input(num, ret);
    }
    if (g_pending_mmap.active) {
        pending_mmap_t pending = g_pending_mmap;
        memset(&g_pending_mmap, 0, sizeof(g_pending_mmap));
        if (pending.syscall_num != num) {
            fprintf(stderr,
                    "[SYSCALL] pending operation "
                    "mismatch: expected=%ld actual=%ld\n",
                    (long)pending.syscall_num, (long)num);
        } else if (syscall_failed) {
            fprintf(stderr,
                    "[SYSCALL] memory operation "
                    "failed: num=%ld ret=%ld\n",
                    (long)num, (long)ret);
        } else if (pending.syscall_num == 90 || pending.syscall_num == 192) {
            uint64_t mapped_address = is_i386 ? (uint64_t)(uint32_t)ret : (uint64_t)ret;
            apply_pending_mmap(&pending, mapped_address);
        } else if (pending.syscall_num == 125 || pending.syscall_num == 380) {
            apply_pending_mprotect(&pending);
        } else if (pending.syscall_num == 91) {
            apply_pending_munmap(&pending);
        }
    }
    if (syscall_failed) {
        pending_socketcall_subcall = -1;
        pending_socket_domain = -1;
        pending_socket_type = -1;
        pending_fd_reset();
        pending_open_reset();
        return;
    }
    if (pending_open_path) {
        int32_t fd = (int32_t)(uint32_t)ret;
        file_dep_t *file = add_file_dep(pending_open_path, pending_open_is_lib);
        if (file) {
            file->write |= pending_open_write;
            g_hash_table_insert(file_fd, GINT_TO_POINTER(fd), file);
            if (file->resource_id != PROV_RESOURCE_ID_INVALID) {
                if (!prov_fd_table_bind_new(g_prov_fd_table, fd, file->resource_id, 0,
                                            pending_open_flags, NULL)) {
                    fprintf(stderr,
                            "[PROV] failed to bind "
                            "fd=%d resource=%u\n",
                            fd, file->resource_id);
                }
            }
        }
        pending_open_reset();
    }
    apply_pending_fd_success(num, ret);

    if ((is_i386 && num == 359) || (!is_i386 && num == 41)) { // socket
        if (pending_socket_domain != -1) {
            net_dep_t *n = g_new0(net_dep_t, 1);
            n->fd = (int)ret;
            g_strlcpy(n->op, "socket", sizeof(n->op));
            n->domain = pending_socket_domain;
            n->type = pending_socket_type;
            g_hash_table_insert(g_sockets, (gpointer)(uintptr_t)(n->fd), n);
            net_dep_t *event = g_new0(net_dep_t, 1);
            memcpy(event, n, sizeof(net_dep_t));
            event->payload_hex = NULL;
            net_deps = g_list_append(net_deps, event);
            pending_socket_domain = -1;
            pending_socket_type = -1;
        }
    } else if (num == 102) {                   // socketcall
        if (pending_socketcall_subcall == 1) { // SYS_SOCKET
            net_dep_t *n = g_new0(net_dep_t, 1);
            n->fd = (int)ret;
            g_strlcpy(n->op, "socket", sizeof(n->op));
            n->domain = pending_socket_domain;
            n->type = pending_socket_type;
            g_hash_table_insert(g_sockets, (gpointer)(uintptr_t)(n->fd), n);
            pending_socketcall_subcall = -1;
            pending_socket_domain = -1;
            pending_socket_type = -1;
            net_dep_t *event = g_new0(net_dep_t, 1);
            memcpy(event, n, sizeof(net_dep_t));
            event->payload_hex = NULL;
            net_deps = g_list_append(net_deps, event);
            pending_socketcall_subcall = -1;
            pending_socket_domain = -1;
            pending_socket_type = -1;
        }
    }
}

static void plugin_install_cleanup(bool capstone_initialized, bool metadata_initialized) {
    dse_lift_attach(NULL, NULL, NULL);
    g_cur_aux = NULL;
    if (g_aux) {
        dse_aux_destroy(g_aux);
        g_aux = NULL;
    }
    if (g_trace) {
        trace_buffer_destroy(g_trace);
        g_trace = NULL;
    }
    if (g_branch_events) {
        branch_event_buffer_destroy(g_branch_events);
        g_branch_events = NULL;
    }
    if (g_dcfg) {
        dcfg_graph_destroy(g_dcfg);
        g_dcfg = NULL;
    }
    if (resolved_imports_by_slot) {
        g_hash_table_destroy(resolved_imports_by_slot);
        resolved_imports_by_slot = NULL;
    }
    if (unmapped_pages) {
        g_hash_table_destroy(unmapped_pages);
        unmapped_pages = NULL;
    }
    if (g_sockets) {
        g_hash_table_destroy(g_sockets);
        g_sockets = NULL;
    }
    if (file_fd) {
        g_hash_table_destroy(file_fd);
        file_fd = NULL;
    }
    if (pages) {
        g_hash_table_destroy(pages);
        pages = NULL;
    }
    insn_exec_contexts_destroy();
    if (metadata_initialized) {
        meta_free();
    }
    if (capstone_initialized) {
        cs_close(&cs_handle);
    }
    provenance_runtime_destroy();
    g_clear_pointer(&g_main_image_path, g_free);
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id, const qemu_info_t *info, int argc,
                                           char **argv) {
    bool capstone_initialized = false;
    bool metadata_initialized = false;
    if (!info || !info->target_name) {
        fprintf(stderr, "[PLUGIN] missing target information\n");
        return -1;
    }

    g_analysis_scope_id = (uint64_t)id;
    if (g_analysis_scope_id == 0) {
        g_analysis_scope_id = UINT64_C(1);
    }
    g_next_resource_object_id = UINT64_C(1);
    g_main_image_resource_id = PROV_RESOURCE_ID_INVALID;
    g_main_image_object_id = 0;
    __atomic_store_n(&g_unpack_gen, 0, __ATOMIC_RELAXED);
    g_clear_pointer(&g_main_image_path, g_free);

    const char *target = info->target_name;
    current_arch = ARCH_UNKNOWN;
    is_i386 = false;
    if (strstr(target, "i386")) {
        current_arch = ARCH_X86_32;
        is_i386 = true;
    } else if (strstr(target, "arm")) {
        current_arch = ARCH_ARM;
    } else if (strstr(target, "mips")) {
        current_arch = ARCH_MIPS;
    } else {
        fprintf(stderr, "[PLUGIN] unsupported architecture: %s\n", target);
        return -1;
    }

    fprintf(stderr, "[PLUGIN] Loaded for architecture: %s (enum=%d)\n", target, current_arch);
    if (!dta_shadow_options(argc, argv) || !ir_plugin_options(argc, argv))
        goto fail;
    if (g_ir_enabled && (!is_i386 || info->system_emulation)) {
        fprintf(stderr, "[IR] diagnostics require i386 linux-user and a serialized collector\n");
        goto fail;
    }
    g_x86_flags_verified = is_i386 && !info->system_emulation &&
                           qemu_plugin_taintforge_x86_flags_v1 &&
                           qemu_plugin_taintforge_x86_flags_v1();
    if (is_i386) {
        fprintf(stderr, "[REG] x86 flag observation contract: %s\n",
                g_x86_flags_verified ? "verified" : "unverified; EFLAGS unavailable to DSE/REP/IR");
    }
    if (!provenance_runtime_init(32)) {
        fprintf(stderr, "[PLUGIN] provenance runtime init failed\n");
        goto fail;
    }
    g_dcfg = dcfg_graph_create(g_prov_registry);
    if (!g_dcfg) {
        fprintf(stderr, "[PLUGIN] DCFG init failed\n");
        goto fail;
    }
    if (cs_open(CS_ARCH_X86, CS_MODE_32, &cs_handle) != CS_ERR_OK) {
        fprintf(stderr, "[PLUGIN] Capstone init failed\n");
        goto fail;
    }
    capstone_initialized = true;
    if (cs_option(cs_handle, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK) {
        fprintf(stderr, "[PLUGIN] failed to enable Capstone detail mode\n");
        goto fail;
    }

    meta_init();
    metadata_initialized = true;
    if (!insn_exec_contexts_init()) {
        fprintf(stderr, "[PLUGIN] instruction context storage init failed\n");
        goto fail;
    }

    pages = g_hash_table_new(g_direct_hash, g_direct_equal);
    file_fd = g_hash_table_new(g_direct_hash, g_direct_equal);
    g_sockets = g_hash_table_new(g_direct_hash, g_direct_equal);
    unmapped_pages = g_hash_table_new(g_direct_hash, g_direct_equal);
    resolved_imports_by_slot = g_hash_table_new(g_direct_hash, g_direct_equal);

    if (!pages || !file_fd || !g_sockets || !unmapped_pages || !resolved_imports_by_slot) {
        fprintf(stderr, "[PLUGIN] hash table init failed\n");
        goto fail;
    }
    g_trace = trace_buffer_create(g_trace_capacity);
    if (!g_trace) {
        fprintf(stderr, "[PLUGIN] Trace buffer init failed\n");
        goto fail;
    }
    g_branch_events = branch_event_buffer_create(64U * 1024U);
    if (!g_branch_events) {
        fprintf(stderr, "[PLUGIN] branch event buffer init failed\n");
        goto fail;
    }
    g_aux = dse_aux_create(g_trace_capacity);
    if (g_aux)
        (void)dse_aux_set_source_limit(g_aux, g_ir_enabled ? g_ir_source_history_bytes : 0);
    if (!g_aux) {
        fprintf(stderr, "[PLUGIN] aux ring init failed\n");
        goto fail;
    }
    dse_lift_attach(g_trace, g_aux, &dse_arch_x86);

    qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);
    qemu_plugin_register_vcpu_init_cb(id, dse_vcpu_init);
    qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans);
    qemu_plugin_register_vcpu_syscall_cb(id, vcpu_syscall);
    qemu_plugin_register_vcpu_syscall_ret_cb(id, vcpu_syscall_ret);

    return 0;

fail:
    if (g_ir_report) {
        fclose(g_ir_report);
        g_ir_report = NULL;
    }
    plugin_install_cleanup(capstone_initialized, metadata_initialized);

    return -1;
}
