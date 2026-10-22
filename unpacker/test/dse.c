#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <glib.h>
#include <capstone/capstone.h>
#include <z3.h>
#include "dta.h"
#include "trace.h"
#include "dse.h"
#include "trace_deps_x86.h"

#define DSE_Z3_TIMEOUT 2000U
#define REG_VAR_BASE 0xF000000000000000ULL
#define FLAG_VAR_BASE 0xE000000000000000ULL
#define STACK_MASK ((1U << DTA_REG_RSP) | (1U << DTA_REG_RBP))
#define DSE_PATH_MODEL_IMPLEMENTED 1
#define DSE_MAX_REPLAY_DEPTH 4096U
#define DSE_MAX_REPLAY_EVAL_NODES DSE_MAX_EXPR_NODES

static bool g_dse_verbose_diagnostics = true;
#define DSE_DIAGNOSTIC(...)                                                                        \
    do {                                                                                           \
        if (g_dse_verbose_diagnostics)                                                             \
            fprintf(__VA_ARGS__);                                                                  \
    } while (0)

void dse_set_verbose_diagnostics(bool enabled) {
    g_dse_verbose_diagnostics = enabled;
}

static void dse_diagnostic_origin(DSECtx *ctx, const TraceEntry *entry) {
    if (!ctx)
        return;
    ctx->replay_origin_valid =
        entry && entry->seq_id && entry->size && entry->size <= MAX_INSN_BYTES;
    if (ctx->replay_origin_valid)
        ctx->replay_origin = *entry;
    else
        memset(&ctx->replay_origin, 0, sizeof(ctx->replay_origin));
}

static void dse_capture_replay_mismatch(DSECtx *ctx, DseReplaySite site, uint64_t location,
                                        uint32_t byte_index, const SymExpr *expr, uint64_t expected,
                                        uint64_t actual, bool root_rebind) {
    if (!ctx || ctx->first_replay_mismatch.present || !expr)
        return;
    ctx->first_replay_mismatch =
        (DseReplayDiagnostic){.present = true,
                              .root_rebind = root_rebind,
                              .origin_valid = ctx->replay_origin_valid,
                              .origin = ctx->replay_origin,
                              .site = site,
                              .location = location,
                              .byte_index = byte_index,
                              .variable_id = expr->type == SYM_VAR ? expr->var.id : 0,
                              .width = expr->width,
                              .expected = expected,
                              .actual = actual};
}

void dse_replay_diagnostic_append_json(GString *out, const DseReplayDiagnostic *d) {
    if (!out)
        return;
    if (!d || !d->present) {
        g_string_append(out, "null");
        return;
    }
    static const char *const sites[] = {"root",     "address_read", "address_write", "branch",
                                        "register", "memory_read",  "memory_write",  "target"};
    const char *site = (unsigned)d->site < G_N_ELEMENTS(sites) ? sites[d->site] : "unknown";
    g_string_append_printf(out,
                           "{\"kind\":\"%s\",\"site\":\"%s\",\"origin_valid\":%s,"
                           "\"seq\":%" PRIu64 ",\"pc\":%" PRIu64 ",\"vcpu\":%u,"
                           "\"generation\":%u,\"descriptor\":%" PRIu64 ",\"location\":%" PRIu64
                           ",\"byte_index\":%u,\"variable_id\":%u,\"width\":%u,"
                           "\"expected\":%" PRIu64 ",\"actual\":%" PRIu64 ",\"bytes\":\"",
                           d->root_rebind ? "root_rebind" : "value_mismatch", site,
                           d->origin_valid ? "true" : "false", d->origin.seq_id, d->origin.pc,
                           d->origin.vcpu_index, d->origin.code_generation, d->origin.insn_desc_id,
                           d->location, d->byte_index, d->variable_id, d->width, d->expected,
                           d->actual);
    if (d->origin_valid) {
        for (unsigned i = 0; i < d->origin.size && i < MAX_INSN_BYTES; ++i)
            g_string_append_printf(out, "%02x", d->origin.instr_bytes[i]);
    }
    g_string_append(out, "\"}");
}

static _Thread_local DSECtx *g_active_expr_ctx = NULL;

typedef struct {
    uint64_t value;
    uint8_t width;
} DseObservedValue;

typedef struct {
    uint64_t value;
    DseReplayEvalStatus status;
    bool complete;
} DseReplayMemoEntry;

typedef struct {
    SymExpr *expr;
    uint64_t writer_seq;
    uint64_t writer_pc;
} DseMemCell;

typedef struct {
    uint64_t seq_id;
    uint64_t address;
} DseDemandMemKey;

typedef struct {
    uint64_t source;
    uint64_t origin_version;
    uint32_t width;
    uint16_t byte_offset;
    uint8_t kind;
} DseRootOriginKey;

typedef struct DseSlicePlan {
    uint64_t seq_id[MAX_SLICE];
    uint8_t data_reg_live_after[MAX_SLICE][REG_COUNT];
    uint8_t replay_reg_live_after[MAX_SLICE][REG_COUNT];
    bool data_all_memory_writes[MAX_SLICE];
    bool replay_all_memory_writes[MAX_SLICE];
    GHashTable *data_memory_writes;
    GHashTable *replay_memory_writes;
} DseSlicePlan;

typedef struct {
    GHashTable *by_seq_id;
    DseRelevanceStats stats;
} DseRelevanceSelection;

typedef enum {
    DSE_REPLAY_CHECK_OK = 0,
    DSE_REPLAY_CHECK_MISSING_BINDING,
    DSE_REPLAY_CHECK_MISMATCH,
    DSE_REPLAY_CHECK_INVALID_EXPR
} DseReplayCheckStatus;

//helpers
static inline uint64_t mask_w(uint64_t v, uint8_t w) {
    if (w >= 64) {
        return v;
    } else {
        return (v & (((uint64_t)1 << w) - 1));
    }
}

static void dse_mark_resource_limit(DSECtx *ctx) {
    if (ctx)
        ctx->resource_limit_hit = true;
}

static void dse_mem_cell_free(gpointer data) {
    DseMemCell *cell = data;
    if (!cell)
        return;
    sym_expr_free(cell->expr);
    g_free(cell);
}

static bool dse_ensure_sym_mem(DSECtx *ctx) {
    if (!ctx)
        return false;
    if (ctx->state.sym_mem)
        return true;
    ctx->state.sym_mem =
        g_hash_table_new_full(g_int64_hash, g_int64_equal, g_free, dse_mem_cell_free);
    if (!ctx->state.sym_mem) {
        dse_mark_resource_limit(ctx);
        return false;
    }
    return true;
}

static SymExpr *sym_expr_alloc(SymOp op, uint8_t width) {
    if (g_active_expr_ctx) {
        if (g_active_expr_ctx->resource_limit_hit ||
            g_active_expr_ctx->expr_nodes_created >= DSE_MAX_EXPR_NODES) {
            dse_mark_resource_limit(g_active_expr_ctx);
            return NULL;
        }
    }
    SymExpr *expr = calloc(1, sizeof(*expr));
    if (!expr) {
        dse_mark_resource_limit(g_active_expr_ctx);
        return NULL;
    }
    expr->ref_count = 1;
    expr->type = op;
    expr->width = width;
    if (g_active_expr_ctx) {
        g_active_expr_ctx->expr_nodes_created++;
    }
    return expr;
}

static SymExpr *mk_binary(SymOp op, uint8_t width, SymExpr *left, SymExpr *right) {
    if (!left || !right) {
        sym_expr_free(left);
        sym_expr_free(right);
        return NULL;
    }
    SymExpr *expr = sym_expr_alloc(op, width);
    if (!expr) {
        sym_expr_free(left);
        sym_expr_free(right);
        return NULL;
    }
    expr->binary.a = left;
    expr->binary.b = right;
    expr->has_var = left->has_var || right->has_var;
    return expr;
}

static SymExpr *mk_unary(SymOp op, uint8_t width, SymExpr *operand) {
    if (!operand)
        return NULL;
    SymExpr *expr = sym_expr_alloc(op, width);
    if (!expr) {
        sym_expr_free(operand);
        return NULL;
    }
    expr->unary.a = operand;
    expr->unary.ext_to = width;
    expr->unary.extract_high = 0;
    expr->unary.extract_low = 0;
    expr->has_var = operand->has_var;
    return expr;
}

static SymExpr *mk_ternary(SymOp op, uint8_t width, SymExpr *condition, SymExpr *when_true,
                           SymExpr *when_false) {
    if (!condition || !when_true || !when_false) {
        sym_expr_free(condition);
        sym_expr_free(when_true);
        sym_expr_free(when_false);
        return NULL;
    }
    SymExpr *expr = sym_expr_alloc(op, width);
    if (!expr) {
        sym_expr_free(condition);
        sym_expr_free(when_true);
        sym_expr_free(when_false);
        return NULL;
    }
    expr->ternary.cond = condition;
    expr->ternary.when_true = when_true;
    expr->ternary.when_false = when_false;
    expr->has_var = condition->has_var || when_true->has_var || when_false->has_var;
    return expr;
}

SymExpr *sym_expr_const(uint64_t value, uint32_t width) {
    if (width == 0 || width > 64) {
        return NULL;
    }
    SymExpr *expr = sym_expr_alloc(SYM_CONST, (uint8_t)width);
    if (!expr)
        return NULL;
    expr->has_var = false;
    expr->const_val = width == 64 ? value : value & ((UINT64_C(1) << width) - 1);
    return expr;
}

SymExpr *sym_expr_var(uint64_t src_addr, uint32_t idx, uint32_t width) {
    if (width == 0 || width > 64)
        return NULL;
    SymExpr *expr = sym_expr_alloc(SYM_VAR, (uint8_t)width);
    if (!expr)
        return NULL;
    expr->has_var = true;
    expr->var.src_addr = src_addr;
    expr->var.epoch = 0;
    expr->var.id = idx;
    expr->var.kind = DSE_VAR_GENERIC;
    return expr;
}

SymExpr *sym_expr_clone(const SymExpr *expr) {
    if (!expr)
        return NULL;
    SymExpr *retained = (SymExpr *)expr;
    if (retained->ref_count == UINT32_MAX) {
        dse_mark_resource_limit(g_active_expr_ctx);
        return NULL;
    }
    retained->ref_count++;
    return retained;
}

SymExpr *sym_expr_add(SymExpr *a, SymExpr *b) {
    if (!a || !b || (a->width != b->width)) {
        sym_expr_free(a);
        sym_expr_free(b);
        return NULL;
    }
    if (a->type == SYM_CONST && a->const_val == 0) {
        sym_expr_free(a);
        return b;
    }
    if (b->type == SYM_CONST && b->const_val == 0) {
        sym_expr_free(b);
        return a;
    }
    uint8_t w = a->width;
    if (a->type == SYM_CONST && b->type == SYM_CONST) {
        uint64_t v = (a->const_val + b->const_val);
        sym_expr_free(a);
        sym_expr_free(b);
        v = mask_w(v, w);
        return sym_expr_const(v, w);
    }
    return mk_binary(SYM_ADD, w, a, b);
}

SymExpr *sym_expr_sub(SymExpr *a, SymExpr *b) {
    if (!a || !b || (a->width != b->width)) {
        sym_expr_free(a);
        sym_expr_free(b);
        return NULL;
    }
    uint8_t w = a->width;
    if (b->type == SYM_CONST && b->const_val == 0) {
        sym_expr_free(b);
        return a;
    }
    if (a->type == SYM_CONST && b->type == SYM_CONST) {
        uint64_t v = mask_w(a->const_val - b->const_val, w);
        sym_expr_free(a);
        sym_expr_free(b);
        return sym_expr_const(v, w);
    }
    return mk_binary(SYM_SUB, w, a, b);
}

SymExpr *sym_expr_xor(SymExpr *a, SymExpr *b) {
    if (!a || !b || a->width != b->width) {
        sym_expr_free(a);
        sym_expr_free(b);
        return NULL;
    }
    uint8_t w = a->width;
    if (a->type == SYM_CONST && a->const_val == 0) {
        sym_expr_free(a);
        return b;
    }
    if (b->type == SYM_CONST && b->const_val == 0) {
        sym_expr_free(b);
        return a;
    }
    if (a->type == SYM_CONST && b->type == SYM_CONST) {
        uint64_t v = mask_w(a->const_val ^ b->const_val, w);
        sym_expr_free(a);
        sym_expr_free(b);
        return sym_expr_const(v, w);
    }
    return mk_binary(SYM_XOR, w, a, b);
}

SymExpr *sym_expr_and(SymExpr *a, SymExpr *b) {
    if (!a || !b || a->width != b->width) {
        sym_expr_free(a);
        sym_expr_free(b);
        return NULL;
    }
    uint8_t w = a->width;
    uint64_t all = mask_w(~0ULL, w);
    if (a->type == SYM_CONST && a->const_val == 0) {
        sym_expr_free(b);
        return a;
    }
    if (b->type == SYM_CONST && b->const_val == 0) {
        sym_expr_free(a);
        return b;
    }
    if (a->type == SYM_CONST && a->const_val == all) {
        sym_expr_free(a);
        return b;
    }
    if (b->type == SYM_CONST && b->const_val == all) {
        sym_expr_free(b);
        return a;
    }
    if (a->type == SYM_CONST && b->type == SYM_CONST) {
        uint64_t v = mask_w(a->const_val & b->const_val, w);
        sym_expr_free(a);
        sym_expr_free(b);
        return sym_expr_const(v, w);
    }
    return mk_binary(SYM_AND, w, a, b);
}

static SymExpr *sym_expr_compare(SymOp operation, SymExpr *left, SymExpr *right) {
    if (!left || !right || left->width != right->width) {
        sym_expr_free(left);
        sym_expr_free(right);
        return NULL;
    }
    if (left->type == SYM_CONST && right->type == SYM_CONST) {
        uint8_t width = left->width;
        uint64_t left_value = mask_w(left->const_val, width);
        uint64_t right_value = mask_w(right->const_val, width);
        bool comparison = false;
        switch (operation) {
        case SYM_EQ:
            comparison = left_value == right_value;
            break;
        case SYM_ULT:
            comparison = left_value < right_value;
            break;
        case SYM_SLT: {
            uint64_t sign = UINT64_C(1) << (width - 1U);
            comparison = (left_value ^ sign) < (right_value ^ sign);
            break;
        }
        default:
            sym_expr_free(left);
            sym_expr_free(right);
            return NULL;
        }
        sym_expr_free(left);
        sym_expr_free(right);
        return sym_expr_const(comparison ? 1U : 0U, 1);
    }
    return mk_binary(operation, 1, left, right);
}

SymExpr *sym_expr_eq(SymExpr *left, SymExpr *right) {
    return sym_expr_compare(SYM_EQ, left, right);
}

SymExpr *sym_expr_ult(SymExpr *left, SymExpr *right) {
    return sym_expr_compare(SYM_ULT, left, right);
}

SymExpr *sym_expr_slt(SymExpr *left, SymExpr *right) {
    return sym_expr_compare(SYM_SLT, left, right);
}

SymExpr *sym_expr_ite(SymExpr *condition, SymExpr *when_true, SymExpr *when_false) {
    if (!condition || condition->width != 1 || !when_true || !when_false ||
        when_true->width != when_false->width) {
        sym_expr_free(condition);
        sym_expr_free(when_true);
        sym_expr_free(when_false);
        return NULL;
    }

    if (condition->type == SYM_CONST) {
        bool choose_true = (condition->const_val & 1U) != 0;
        sym_expr_free(condition);
        if (choose_true) {
            sym_expr_free(when_false);
            return when_true;
        }
        sym_expr_free(when_true);
        return when_false;
    }
    return mk_ternary(SYM_ITE, when_true->width, condition, when_true, when_false);
}

SymExpr *sym_expr_shl(SymExpr *a, SymExpr *b) {
    if (!a || !b) {
        sym_expr_free(a);
        sym_expr_free(b);
        return NULL;
    }
    uint8_t w = a->width;
    if (b->width < w)
        b = sym_expr_zext(b, w);
    else if (b->width > w)
        b = sym_expr_extract(b, 0, w);
    if (!b) {
        sym_expr_free(a);
        return NULL;
    }
    if (b->type == SYM_CONST && b->const_val == 0) {
        sym_expr_free(b);
        return a;
    }
    if (a->type == SYM_CONST && b->type == SYM_CONST) {
        uint64_t v = 0;
        if (b->const_val < w)
            v = mask_w(a->const_val << b->const_val, w);
        sym_expr_free(a);
        sym_expr_free(b);
        return sym_expr_const(v, w);
    }
    return mk_binary(SYM_SHL, w, a, b);
}

SymExpr *sym_expr_shr(SymExpr *a, SymExpr *count) {
    if (!a || !count) {
        sym_expr_free(a);
        sym_expr_free(count);
        return NULL;
    }
    uint8_t width = a->width;
    if (count->width < width) {
        count = sym_expr_zext(count, width);
    } else if (count->width > width) {
        count = sym_expr_extract(count, 0, width);
    }
    if (!count) {
        sym_expr_free(a);
        return NULL;
    }
    if (count->type == SYM_CONST && count->const_val == 0) {
        sym_expr_free(count);
        return a;
    }

    if (a->type == SYM_CONST && count->type == SYM_CONST) {
        uint64_t shift = count->const_val;
        uint64_t result = 0;
        if (shift < width) {
            result = mask_w(a->const_val >> shift, width);
        }
        sym_expr_free(a);
        sym_expr_free(count);
        return sym_expr_const(result, width);
    }

    return mk_binary(SYM_LSHR, width, a, count);
}

SymExpr *sym_expr_sar(SymExpr *a, SymExpr *count) {
    if (!a || !count) {
        sym_expr_free(a);
        sym_expr_free(count);
        return NULL;
    }
    uint8_t width = a->width;
    if (count->width < width) {
        count = sym_expr_zext(count, width);
    } else if (count->width > width) {
        count = sym_expr_extract(count, 0, width);
    }

    if (!count) {
        sym_expr_free(a);
        return NULL;
    }

    if (count->type == SYM_CONST && count->const_val == 0) {
        sym_expr_free(count);
        return a;
    }

    return mk_binary(SYM_ASHR, width, a, count);
}

SymExpr *sym_expr_rol(SymExpr *a, SymExpr *count) {
    if (!a || !count) {
        sym_expr_free(a);
        sym_expr_free(count);
        return NULL;
    }
    uint8_t w = a->width;
    if (count->type != SYM_CONST) {
        sym_expr_free(a);
        sym_expr_free(count);
        return NULL;
    }
    uint32_t c = (uint32_t)(count->const_val % (w ? w : 1));
    sym_expr_free(count);
    if (c == 0)
        return a;
    SymExpr *hi = sym_expr_extract(sym_expr_clone(a), 0, w - c);
    SymExpr *lo = sym_expr_extract(a, w - c, c);
    return sym_expr_concat(hi, lo);
}

SymExpr *sym_expr_ror(SymExpr *a, SymExpr *count) {
    if (!a || !count) {
        sym_expr_free(a);
        sym_expr_free(count);
        return NULL;
    }
    uint8_t w = a->width;
    if (count->type != SYM_CONST) {
        sym_expr_free(a);
        sym_expr_free(count);
        return NULL;
    }
    uint32_t c = (uint32_t)(count->const_val % (w ? w : 1));
    sym_expr_free(count);
    if (c == 0)
        return a;
    SymExpr *hi = sym_expr_extract(sym_expr_clone(a), 0, c);
    SymExpr *lo = sym_expr_extract(a, c, w - c);
    return sym_expr_concat(hi, lo);
}

SymExpr *sym_expr_mul(SymExpr *a, SymExpr *b) {
    if (!a || !b || a->width != b->width) {
        sym_expr_free(a);
        sym_expr_free(b);
        return NULL;
    }
    uint8_t width = a->width;
    if (a->type == SYM_CONST && b->type == SYM_CONST) {
        uint64_t value = mask_w(a->const_val * b->const_val, width);
        sym_expr_free(a);
        sym_expr_free(b);
        return sym_expr_const(value, width);
    }
    if (a->type == SYM_CONST && a->const_val == 0) {
        sym_expr_free(b);
        return a;
    }

    if (b->type == SYM_CONST && b->const_val == 0) {
        sym_expr_free(a);
        return b;
    }
    if (a->type == SYM_CONST && a->const_val == 1) {
        sym_expr_free(a);
        return b;
    }

    if (b->type == SYM_CONST && b->const_val == 1) {
        sym_expr_free(b);
        return a;
    }
    return mk_binary(SYM_MUL, width, a, b);
}

SymExpr *sym_expr_or(SymExpr *left, SymExpr *right) {
    if (!left || !right || left->width != right->width) {
        sym_expr_free(left);
        sym_expr_free(right);
        return NULL;
    }
    uint8_t width = left->width;
    uint64_t all_bits = mask_w(~UINT64_C(0), width);
    if (left->type == SYM_CONST && left->const_val == 0) {
        sym_expr_free(left);
        return right;
    }
    if (right->type == SYM_CONST && right->const_val == 0) {
        sym_expr_free(right);
        return left;
    }
    if (left->type == SYM_CONST && left->const_val == all_bits) {
        sym_expr_free(right);
        return left;
    }
    if (right->type == SYM_CONST && right->const_val == all_bits) {
        sym_expr_free(left);
        return right;
    }
    if (left->type == SYM_CONST && right->type == SYM_CONST) {
        uint64_t result = mask_w(left->const_val | right->const_val, width);
        sym_expr_free(left);
        sym_expr_free(right);
        return sym_expr_const(result, width);
    }
    return mk_binary(SYM_OR, width, left, right);
}

SymExpr *sym_expr_sext(SymExpr *a, uint32_t to_width) {
    if (!a || to_width > 64 || to_width < a->width) {
        sym_expr_free(a);
        return NULL;
    }
    if (to_width == a->width)
        return a;
    if (a->type == SYM_CONST) {
        uint8_t sw = a->width;
        uint64_t v = mask_w(a->const_val, sw);
        if (sw < 64 && ((v >> (sw - 1)) & 1ULL))
            v |= (mask_w(~0ULL, (uint8_t)to_width) & ~mask_w(~0ULL, sw));
        sym_expr_free(a);
        return sym_expr_const(mask_w(v, (uint8_t)to_width), (uint8_t)to_width);
    }
    return mk_unary(SYM_SEXT, (uint8_t)to_width, a);
}

SymExpr *sym_expr_zext(SymExpr *a, uint32_t to_width) {
    if (!a || to_width > 64 || to_width < a->width) {
        sym_expr_free(a);
        return NULL;
    }
    if (to_width == a->width)
        return a;
    if (a->type == SYM_CONST) {
        uint64_t v = mask_w(a->const_val, a->width);
        sym_expr_free(a);
        return sym_expr_const(v, (uint8_t)to_width);
    }
    return mk_unary(SYM_ZEXT, (uint8_t)to_width, a);
}

SymExpr *sym_expr_extract(SymExpr *a, uint32_t low_bit, uint32_t out_width) {
    if (!a || out_width == 0 || low_bit + out_width > a->width) {
        sym_expr_free(a);
        return NULL;
    }
    if (low_bit == 0 && out_width == a->width)
        return a;
    if (a->type == SYM_CONST) {
        uint64_t v = mask_w(a->const_val >> low_bit, (uint8_t)out_width);
        sym_expr_free(a);
        return sym_expr_const(v, (uint8_t)out_width);
    }
    SymExpr *e = mk_unary(SYM_EXTRACT, (uint8_t)out_width, a);
    if (e) {
        e->unary.extract_low = low_bit;
        e->unary.extract_high = low_bit + out_width - 1;
    }
    return e;
}

SymExpr *sym_expr_concat(SymExpr *high, SymExpr *low) {
    if (!high || !low) {
        sym_expr_free(high);
        sym_expr_free(low);
        return NULL;
    }
    uint32_t w = (uint32_t)high->width + (uint32_t)low->width;
    if (w == 0 || w > 64) {
        sym_expr_free(high);
        sym_expr_free(low);
        return NULL;
    }
    if (high->type == SYM_CONST && low->type == SYM_CONST) {
        uint64_t v = (mask_w(high->const_val, high->width) << low->width) |
                     mask_w(low->const_val, low->width);
        sym_expr_free(high);
        sym_expr_free(low);
        return sym_expr_const(v, (uint8_t)w);
    }
    return mk_binary(SYM_CONCAT, (uint8_t)w, high, low);
}

SymExpr *sym_expr_not(SymExpr *a) {
    if (!a)
        return NULL;
    uint8_t w = a->width;
    return sym_expr_xor(a, sym_expr_const(mask_w(~0ULL, w), w));
}

SymExpr *sym_expr_neg(SymExpr *a) {
    if (!a)
        return NULL;
    uint8_t w = a->width;
    return sym_expr_sub(sym_expr_const(0, w), a);
}

void sym_expr_free(SymExpr *expr) {
    if (!expr)
        return;
    if (expr->ref_count == 0)
        return;
    expr->ref_count--;
    if (expr->ref_count != 0)
        return;
    switch (expr->type) {
    case SYM_ADD:
    case SYM_SUB:
    case SYM_MUL:
    case SYM_XOR:
    case SYM_AND:
    case SYM_OR:
    case SYM_SHL:
    case SYM_LSHR:
    case SYM_ASHR:
    case SYM_CONCAT:
    case SYM_EQ:
    case SYM_ULT:
    case SYM_SLT:
        sym_expr_free(expr->binary.a);
        sym_expr_free(expr->binary.b);
        break;
    case SYM_EXTRACT:
    case SYM_ZEXT:
    case SYM_SEXT:
        sym_expr_free(expr->unary.a);
        break;

    case SYM_ITE:
        sym_expr_free(expr->ternary.cond);
        sym_expr_free(expr->ternary.when_true);
        sym_expr_free(expr->ternary.when_false);
        break;
    case SYM_CONST:
    case SYM_VAR:
        break;
    }
    free(expr);
}

void sym_state_init(SymState *st) {
    memset(st, 0, sizeof(*st));
    st->sym_mem = NULL;
    st->var_cache = NULL;
}

typedef struct {
    uint64_t source;
    uint64_t epoch;
    uint32_t width;
    uint8_t kind;
} DseVarKey;

static guint dse_var_key_hash(gconstpointer data) {
    const DseVarKey *key = data;
    if (!key)
        return 0;
    uint64_t value = key->source;
    value ^= key->epoch + UINT64_C(0x9e3779b97f4a7c15) + (value << 6) + (value >> 2);
    value ^= (uint64_t)key->width * UINT64_C(0xbf58476d1ce4e5b9);
    value ^= (uint64_t)key->kind * UINT64_C(0x94d049bb133111eb);
    value ^= value >> 30;
    value *= UINT64_C(0xbf58476d1ce4e5b9);
    value ^= value >> 27;
    value *= UINT64_C(0x94d049bb133111eb);
    value ^= value >> 31;
    return (guint)(value ^ (value >> 32));
}

static gboolean dse_var_key_equal(gconstpointer left, gconstpointer right) {
    const DseVarKey *a = left;
    const DseVarKey *b = right;
    return a && b && a->source == b->source && a->epoch == b->epoch && a->width == b->width &&
           a->kind == b->kind;
}

static guint dse_root_origin_key_hash(gconstpointer data) {
    const DseRootOriginKey *key = data;
    if (!key)
        return 0;
    uint64_t value = key->source;
    value ^= key->origin_version + UINT64_C(0x9e3779b97f4a7c15) + (value << 6U) + (value >> 2U);
    value ^= (uint64_t)key->width * UINT64_C(0xbf58476d1ce4e5b9);
    value ^= (uint64_t)key->byte_offset * UINT64_C(0x94d049bb133111eb);
    value ^= (uint64_t)key->kind * UINT64_C(0xd6e8feb86659fd93);
    value ^= value >> 30U;
    value *= UINT64_C(0xbf58476d1ce4e5b9);
    value ^= value >> 27U;
    value *= UINT64_C(0x94d049bb133111eb);
    value ^= value >> 31U;
    return (guint)(value ^ (value >> 32U));
}

static gboolean dse_root_origin_key_equal(gconstpointer left, gconstpointer right) {
    const DseRootOriginKey *a = left;
    const DseRootOriginKey *b = right;
    return a && b && a->source == b->source && a->origin_version == b->origin_version &&
           a->width == b->width && a->byte_offset == b->byte_offset && a->kind == b->kind;
}

static void dse_root_provenance_free(gpointer data) {
    DseRootProvenance *provenance = data;
    if (!provenance)
        return;
    g_free(provenance->lineage_ids);
    provenance->lineage_ids = NULL;
    g_free(provenance);
}

static void dse_root_set_init(DseRootSet *set) {
    if (!set)
        return;
    memset(set, 0, sizeof(*set));
    set->complete = true;
}

static bool dse_root_set_contains(const DseRootSet *set, uint64_t lineage_id) {
    if (!set || lineage_id == 0)
        return false;
    for (uint16_t index = 0; index < set->count; index++) {
        if (set->ids[index] == lineage_id) {
            return true;
        }
    }
    return false;
}

static void dse_root_set_add(DseRootSet *set, uint64_t lineage_id) {
    if (!set || lineage_id == 0 || dse_root_set_contains(set, lineage_id)) {
        return;
    }
    if (set->count >= DSE_MAX_ROOT_LINEAGE) {
        set->complete = false;
        return;
    }
    set->ids[set->count++] = lineage_id;
}

bool dse_root_sets_may_intersect(const DseRootSet *left, const DseRootSet *right) {
    if (!left || !right || !left->complete || !right->complete) {
        return true;
    }
    for (uint16_t left_index = 0; left_index < left->count; left_index++) {
        for (uint16_t right_index = 0; right_index < right->count; right_index++) {
            if (left->ids[left_index] == right->ids[right_index]) {
                return true;
            }
        }
    }
    return false;
}

const DseRootProvenance *dse_root_provenance_lookup(const DSECtx *ctx, uint32_t root_id) {
    if (!ctx || !ctx->root_provenance)
        return NULL;
    return g_hash_table_lookup(ctx->root_provenance, &root_id);
}

const DseRootOrigin *dse_root_origin_lookup(const DSECtx *ctx, uint64_t lineage_id) {
    if (!ctx || !ctx->lineage_origins || lineage_id == 0) {
        return NULL;
    }
    gint64 lookup_id = (gint64)lineage_id;
    return g_hash_table_lookup(ctx->lineage_origins, &lookup_id);
}

static bool dse_root_origin_lineage_id(DSECtx *ctx, DseVarKind kind, uint64_t source,
                                       uint64_t origin_version, uint32_t width,
                                       uint16_t byte_offset, uint64_t *out_lineage_id) {
    if (out_lineage_id)
        *out_lineage_id = 0;
    if (!ctx || !ctx->root_origins || !ctx->lineage_origins || !out_lineage_id || width == 0 ||
        width > 64) {
        return false;
    }
    DseRootOriginKey lookup = {.source = source,
                               .origin_version = origin_version,
                               .width = width,
                               .byte_offset = byte_offset,
                               .kind = (uint8_t)kind};
    const uint64_t *existing = g_hash_table_lookup(ctx->root_origins, &lookup);
    if (existing) {
        *out_lineage_id = *existing;
        return true;
    }
    if (ctx->next_lineage_id == 0 || ctx->next_lineage_id >= UINT64_C(0x8000000000000000)) {
        ctx->root_provenance_complete = false;
        dse_mark_resource_limit(ctx);
        return false;
    }

    DseRootOriginKey *stored_key = g_try_new(DseRootOriginKey, 1);
    uint64_t *stored_id = g_try_new(uint64_t, 1);
    gint64 *lineage_key = g_try_new(gint64, 1);
    DseRootOrigin *origin = g_try_new0(DseRootOrigin, 1);
    if (!stored_key || !stored_id || !lineage_key || !origin) {
        g_free(stored_key);
        g_free(stored_id);
        g_free(lineage_key);
        g_free(origin);
        ctx->root_provenance_complete = false;
        dse_mark_resource_limit(ctx);
        return false;
    }
    *stored_key = lookup;
    *stored_id = ctx->next_lineage_id;
    *lineage_key = (gint64)*stored_id;
    origin->lineage_id = *stored_id;
    origin->kind = kind;
    origin->source = source;
    origin->origin_version = origin_version;
    origin->width = width;
    origin->byte_offset = byte_offset;
    g_hash_table_insert(ctx->root_origins, stored_key, stored_id);
    g_hash_table_insert(ctx->lineage_origins, lineage_key, origin);
    ctx->next_lineage_id++;
    *out_lineage_id = *stored_id;
    return true;
}

static bool dse_root_provenance_store_lineage(DSECtx *ctx, DseRootProvenance *provenance,
                                              const DseRootSet *lineage) {
    if (!ctx || !provenance || !lineage)
        return false;
    uint64_t *stored_ids = NULL;
    if (lineage->count != 0) {
        stored_ids = g_try_new(uint64_t, lineage->count);
        if (!stored_ids) {
            ctx->root_provenance_complete = false;
            dse_mark_resource_limit(ctx);
            return false;
        }
        memcpy(stored_ids, lineage->ids, (size_t)lineage->count * sizeof(*stored_ids));
    }
    g_free(provenance->lineage_ids);
    provenance->lineage_ids = stored_ids;
    provenance->lineage_count = lineage->count;
    provenance->lineage_complete = lineage->complete;
    if (!lineage->complete) {
        ctx->root_provenance_complete = false;
    }
    return true;
}

static bool dse_register_root_provenance(DSECtx *ctx, const SymExpr *root, DseVarKind kind,
                                         uint64_t source, uint64_t variable_epoch,
                                         uint64_t origin_version, uint64_t event_seq,
                                         uint16_t byte_offset, const DseRootSet *alias_lineage) {
    if (!ctx || !root || root->type != SYM_VAR || !ctx->root_provenance) {
        return false;
    }
    DseRootSet incoming;
    dse_root_set_init(&incoming);
    if (alias_lineage) {
        incoming = *alias_lineage;
    } else {
        uint64_t lineage_id = 0;
        if (!dse_root_origin_lineage_id(ctx, kind, source, origin_version, root->width, byte_offset,
                                        &lineage_id)) {
            return false;
        }
        dse_root_set_add(&incoming, lineage_id);
    }
    uint32_t lookup_id = root->var.id;
    DseRootProvenance *existing = g_hash_table_lookup(ctx->root_provenance, &lookup_id);
    if (existing) {
        if (existing->kind != kind || existing->source != source ||
            existing->variable_epoch != variable_epoch ||
            existing->origin_version != origin_version || existing->width != root->width ||
            existing->byte_offset != byte_offset) {
            ctx->root_provenance_complete = false;
            return false;
        }
        DseRootSet merged;
        dse_root_set_init(&merged);
        merged.complete = existing->lineage_complete && incoming.complete;
        for (uint16_t index = 0; index < existing->lineage_count; index++) {
            dse_root_set_add(&merged, existing->lineage_ids[index]);
        }
        for (uint16_t index = 0; index < incoming.count; index++) {
            dse_root_set_add(&merged, incoming.ids[index]);
        }
        if (event_seq < existing->first_event_seq) {
            existing->first_event_seq = event_seq;
        }
        if (event_seq > existing->last_event_seq) {
            existing->last_event_seq = event_seq;
        }
        return dse_root_provenance_store_lineage(ctx, existing, &merged);
    }
    uint32_t *stored_id = g_try_new(uint32_t, 1);
    DseRootProvenance *stored = g_try_new0(DseRootProvenance, 1);
    if (!stored_id || !stored) {
        g_free(stored_id);
        g_free(stored);
        ctx->root_provenance_complete = false;
        dse_mark_resource_limit(ctx);
        return false;
    }
    *stored_id = root->var.id;
    stored->root_id = root->var.id;
    stored->kind = kind;
    stored->source = source;
    stored->variable_epoch = variable_epoch;
    stored->origin_version = origin_version;
    stored->first_event_seq = event_seq;
    stored->last_event_seq = event_seq;
    stored->width = root->width;
    stored->byte_offset = byte_offset;
    if (!dse_root_provenance_store_lineage(ctx, stored, &incoming)) {
        g_free(stored_id);
        dse_root_provenance_free(stored);
        return false;
    }
    g_hash_table_insert(ctx->root_provenance, stored_id, stored);
    return true;
}

static bool dse_expr_collect_root_lineage_impl(const DSECtx *ctx, const SymExpr *expr,
                                               DseRootSet *out, GHashTable *visited,
                                               uint32_t depth) {
    if (!ctx || !expr || !out || !visited)
        return false;
    if (depth > DSE_MAX_REPLAY_DEPTH || g_hash_table_size(visited) >= DSE_MAX_ROOT_SCAN_NODES) {
        out->complete = false;
        return true;
    }
    if (g_hash_table_contains(visited, expr)) {
        return true;
    }
    g_hash_table_add(visited, (gpointer)expr);
    switch (expr->type) {
    case SYM_CONST:
        return true;
    case SYM_VAR: {
        const DseRootProvenance *provenance = dse_root_provenance_lookup(ctx, expr->var.id);
        if (!provenance) {
            out->complete = false;
            dse_root_set_add(out, UINT64_C(0x8000000000000000) | (uint64_t)expr->var.id);
            return true;
        }
        if (!provenance->lineage_complete) {
            out->complete = false;
        }
        for (uint16_t index = 0; index < provenance->lineage_count; index++) {
            dse_root_set_add(out, provenance->lineage_ids[index]);
        }
        return true;
    }
    case SYM_ADD:
    case SYM_SUB:
    case SYM_MUL:
    case SYM_XOR:
    case SYM_AND:
    case SYM_OR:
    case SYM_SHL:
    case SYM_LSHR:
    case SYM_ASHR:
    case SYM_CONCAT:
    case SYM_EQ:
    case SYM_ULT:
    case SYM_SLT:
        return expr->binary.a && expr->binary.b &&
               dse_expr_collect_root_lineage_impl(ctx, expr->binary.a, out, visited, depth + 1U) &&
               dse_expr_collect_root_lineage_impl(ctx, expr->binary.b, out, visited, depth + 1U);
    case SYM_EXTRACT:
    case SYM_ZEXT:
    case SYM_SEXT:
        return expr->unary.a &&
               dse_expr_collect_root_lineage_impl(ctx, expr->unary.a, out, visited, depth + 1U);
    case SYM_ITE:
        return expr->ternary.cond && expr->ternary.when_true && expr->ternary.when_false &&
               dse_expr_collect_root_lineage_impl(ctx, expr->ternary.cond, out, visited,
                                                  depth + 1U) &&
               dse_expr_collect_root_lineage_impl(ctx, expr->ternary.when_true, out, visited,
                                                  depth + 1U) &&
               dse_expr_collect_root_lineage_impl(ctx, expr->ternary.when_false, out, visited,
                                                  depth + 1U);
    }
    out->complete = false;
    return true;
}

bool dse_expr_collect_root_lineage(const DSECtx *ctx, const SymExpr *expr, DseRootSet *out) {
    if (!out)
        return false;
    dse_root_set_init(out);
    if (!ctx || !expr) {
        out->complete = false;
        return false;
    }
    GHashTable *visited = g_hash_table_new(g_direct_hash, g_direct_equal);
    if (!visited) {
        out->complete = false;
        return false;
    }
    bool ok = dse_expr_collect_root_lineage_impl(ctx, expr, out, visited, 0);
    g_hash_table_destroy(visited);
    if (!ok)
        out->complete = false;
    return ok;
}

void sym_state_clear(SymState *st) {
    for (uint8_t i = 0; i < REG_COUNT; i++) {
        sym_expr_free(st->reg[i]);
        st->reg[i] = NULL;
    }
    if (st->sym_mem != NULL) {
        g_hash_table_destroy(st->sym_mem);
        st->sym_mem = NULL;
    }
    if (st->var_cache != NULL) {
        g_hash_table_destroy(st->var_cache);
        st->var_cache = NULL;
    }
    st->var_counter = 0;
    for (uint8_t index = 0; index < DSE_FLAG_SLOT_COUNT; index++) {
        sym_expr_free(st->x86_flags[index]);
        st->x86_flags[index] = NULL;
    }
}

static SymExpr *sym_state_new_epoch_var(SymState *st, uint64_t src_addr, uint64_t epoch,
                                        uint32_t width, DseVarKind kind) {
    if (!st || width == 0 || width > 64)
        return NULL;
    if (!st->var_cache) {
        st->var_cache = g_hash_table_new_full(dse_var_key_hash, dse_var_key_equal, g_free,
                                              (GDestroyNotify)sym_expr_free);
        if (!st->var_cache)
            return NULL;
    }
    DseVarKey lookup_key = {
        .source = src_addr, .epoch = epoch, .width = width, .kind = (uint8_t)kind};
    SymExpr *cached = g_hash_table_lookup(st->var_cache, &lookup_key);
    if (cached) {
        SymExpr *out = sym_expr_clone(cached);
        if (!out)
            return NULL;
        if (out->width < width) {
            return sym_expr_zext(out, width);
        }
        if (out->width > width) {
            return sym_expr_extract(out, 0, width);
        }
        return out;
    }
    SymExpr *source = sym_expr_var(src_addr, st->var_counter++, width);
    if (!source)
        return NULL;
    source->var.epoch = epoch;
    source->var.kind = (uint8_t)kind;
    DseVarKey *key = g_new(DseVarKey, 1);
    *key = lookup_key;
    g_hash_table_insert(st->var_cache, key, source);
    return sym_expr_clone(source);
}

SymExpr *sym_state_new_var(SymState *st, uint64_t src_addr, uint32_t width) {
    return sym_state_new_epoch_var(st, src_addr, 0, width, DSE_VAR_GENERIC);
}

static void dse_record_replay_missing(DSECtx *ctx) {
    if (!ctx)
        return;
    ctx->replay_model_complete = false;
    if (ctx->replay_missing_bindings != UINT32_MAX) {
        ctx->replay_missing_bindings++;
    }
    if (ctx->replay_failures != UINT32_MAX) {
        ctx->replay_failures++;
    }
}

static void dse_record_replay_mismatch(DSECtx *ctx) {
    if (!ctx)
        return;
    ctx->replay_model_complete = false;
    ctx->replay_mismatch = true;
    if (ctx->replay_failures != UINT32_MAX) {
        ctx->replay_failures++;
    }
}

static DseReplayEvalStatus dse_bind_observed_var(DSECtx *ctx, const SymExpr *var,
                                                 uint64_t observed_value) {
    if (!ctx || !var || var->type != SYM_VAR || var->width == 0 || var->width > 64 ||
        !ctx->observed_values) {
        if (ctx)
            dse_record_replay_missing(ctx);
        return DSE_REPLAY_EVAL_INVALID_EXPR;
    }
    observed_value = mask_w(observed_value, var->width);
    uint32_t lookup_id = var->var.id;
    DseObservedValue *existing = g_hash_table_lookup(ctx->observed_values, &lookup_id);
    if (existing) {
        if (existing->width != var->width) {
            dse_record_replay_missing(ctx);
            return DSE_REPLAY_EVAL_INVALID_EXPR;
        }
        if (existing->value != observed_value) {
            dse_capture_replay_mismatch(ctx, DSE_REPLAY_SITE_ROOT, var->var.src_addr, 0, var,
                                        observed_value, existing->value, true);
            if (!ctx->replay_mismatch) {
                DSE_DIAGNOSTIC(
                    stderr, "[DSE-ROOT-REBIND] var=%u source=0x%lx width=%u old=0x%lx new=0x%lx\n",
                    var->var.id, (unsigned long)var->var.src_addr, (unsigned int)var->width,
                    (unsigned long)existing->value, (unsigned long)observed_value);
            }
            dse_record_replay_mismatch(ctx);
            return DSE_REPLAY_EVAL_INVALID_EXPR;
        }
        return DSE_REPLAY_EVAL_OK;
    }
    uint32_t *stored_id = g_try_new(uint32_t, 1);
    DseObservedValue *stored_value = g_try_new(DseObservedValue, 1);
    if (!stored_id || !stored_value) {
        g_free(stored_id);
        g_free(stored_value);
        dse_mark_resource_limit(ctx);
        dse_record_replay_missing(ctx);
        return DSE_REPLAY_EVAL_MISSING_BINDING;
    }
    *stored_id = lookup_id;
    stored_value->value = observed_value;
    stored_value->width = var->width;
    g_hash_table_insert(ctx->observed_values, stored_id, stored_value);
    return DSE_REPLAY_EVAL_OK;
}

static SymExpr *dse_new_observed_epoch_var(DSECtx *ctx, uint64_t src_addr, uint64_t variable_epoch,
                                           uint64_t origin_version, uint64_t event_seq,
                                           uint16_t byte_offset, uint32_t width, DseVarKind kind,
                                           uint64_t observed_value,
                                           const DseRootSet *alias_lineage) {
    if (!ctx)
        return NULL;
    SymExpr *root = sym_state_new_epoch_var(&ctx->state, src_addr, variable_epoch, width, kind);
    if (!root)
        return NULL;
    DseReplayEvalStatus status = dse_bind_observed_var(ctx, root, observed_value);
    if (status != DSE_REPLAY_EVAL_OK) {
        sym_expr_free(root);
        return NULL;
    }
    if (!dse_register_root_provenance(ctx, root, kind, src_addr, variable_epoch, origin_version,
                                      event_seq, byte_offset, alias_lineage)) {
        ctx->root_provenance_complete = false;
        sym_expr_free(root);
        return NULL;
    }
    return root;
}

SymExpr *sym_state_get_reg(const SymState *st, RegId rid) {
    if (rid < 0 || rid >= REG_COUNT) {
        return NULL;
    }
    return st->reg[rid];
}

void sym_state_set_reg(SymState *state, RegId rid, SymExpr *expr) {
    if (!state || rid < 0 || rid >= REG_COUNT) {
        sym_expr_free(expr);
        return;
    }
    SymExpr *old = state->reg[rid];
    state->reg[rid] = expr;
    sym_expr_free(old);
}

static void dse_reset_register_root_epochs(DSECtx *ctx) {
    if (!ctx)
        return;
    for (int rid = 0; rid < REG_COUNT; rid++) {
        ctx->register_root_epoch[rid] = 1;
    }
}

static void dse_advance_register_root_epoch(DSECtx *ctx, int rid) {
    if (!ctx || rid < 0 || rid >= REG_COUNT) {
        return;
    }
    if (ctx->register_root_epoch[rid] == UINT64_MAX) {
        ctx->register_model_complete = false;
        ctx->replay_model_complete = false;
        return;
    }
    ctx->register_root_epoch[rid]++;
    if (ctx->register_root_epoch[rid] == 0) {
        ctx->register_root_epoch[rid] = 1;
    }
}

static void dse_z3_error_handler(Z3_context c, Z3_error_code e) {
    (void)c;
    (void)e;
}

static void dse_z3_cache_clear(DSECtx *ctx) {
    if (!ctx || !ctx->z3_expr_cache) {
        return;
    }
    if (ctx->z3_ctx) {
        GHashTableIter iter;
        gpointer key = NULL;
        gpointer value = NULL;
        g_hash_table_iter_init(&iter, ctx->z3_expr_cache);
        while (g_hash_table_iter_next(&iter, &key, &value)) {
            (void)key;
            if (value) {
                Z3_dec_ref(ctx->z3_ctx, (Z3_ast)value);
            }
        }
    }
    g_hash_table_remove_all(ctx->z3_expr_cache);
    ctx->z3_cache_nodes = 0;
}

bool dse_ctx_init(DSECtx *ctx) {
    if (!ctx)
        return false;
    memset(ctx, 0, sizeof(*ctx));
    dse_reset_register_root_epochs(ctx);
    ctx->address_model_complete = true;
    sym_state_init(&ctx->state);
    Z3_config config = Z3_mk_config();
    Z3_set_param_value(config, "model", "true"); //witness mode
    ctx->z3_ctx = Z3_mk_context_rc(config);
    Z3_del_config(config);
    if (!ctx->z3_ctx)
        return false;
    Z3_set_error_handler(ctx->z3_ctx, dse_z3_error_handler);
    ctx->z3_solver = Z3_mk_solver(ctx->z3_ctx);
    if (!ctx->z3_solver) {
        Z3_del_context(ctx->z3_ctx);
        ctx->z3_ctx = NULL;
        return false;
    }
    Z3_solver_inc_ref(ctx->z3_ctx, ctx->z3_solver);
    Z3_params params = Z3_mk_params(ctx->z3_ctx);
    if (!params) {
        Z3_solver_dec_ref(ctx->z3_ctx, ctx->z3_solver);
        ctx->z3_solver = NULL;
        Z3_del_context(ctx->z3_ctx);
        ctx->z3_ctx = NULL;
        return false;
    }
    Z3_params_inc_ref(ctx->z3_ctx, params);
    Z3_symbol timeout = Z3_mk_string_symbol(ctx->z3_ctx, "timeout");
    Z3_params_set_uint(ctx->z3_ctx, params, timeout, DSE_Z3_TIMEOUT);
    Z3_solver_set_params(ctx->z3_ctx, ctx->z3_solver, params);
    Z3_params_dec_ref(ctx->z3_ctx, params);
    ctx->path_predicate = Z3_mk_true(ctx->z3_ctx);
    if (!ctx->path_predicate) {
        Z3_solver_dec_ref(ctx->z3_ctx, ctx->z3_solver);
        ctx->z3_solver = NULL;
        Z3_del_context(ctx->z3_ctx);
        ctx->z3_ctx = NULL;
        return false;
    }
    Z3_inc_ref(ctx->z3_ctx, ctx->path_predicate);
    ctx->z3_expr_cache =
        g_hash_table_new_full(g_direct_hash, g_direct_equal, (GDestroyNotify)sym_expr_free, NULL);
    if (!ctx->z3_expr_cache) {
        Z3_dec_ref(ctx->z3_ctx, ctx->path_predicate);
        ctx->path_predicate = NULL;
        Z3_solver_dec_ref(ctx->z3_ctx, ctx->z3_solver);
        ctx->z3_solver = NULL;
        Z3_del_context(ctx->z3_ctx);
        ctx->z3_ctx = NULL;
        return false;
    }
    ctx->observed_values = g_hash_table_new_full(g_int_hash, g_int_equal, g_free, g_free);
    if (!ctx->observed_values) {
        g_hash_table_destroy(ctx->z3_expr_cache);
        ctx->z3_expr_cache = NULL;
        Z3_dec_ref(ctx->z3_ctx, ctx->path_predicate);
        ctx->path_predicate = NULL;
        Z3_solver_dec_ref(ctx->z3_ctx, ctx->z3_solver);
        ctx->z3_solver = NULL;
        Z3_del_context(ctx->z3_ctx);
        ctx->z3_ctx = NULL;
        return false;
    }
    ctx->root_provenance =
        g_hash_table_new_full(g_int_hash, g_int_equal, g_free, dse_root_provenance_free);
    if (!ctx->root_provenance) {
        g_hash_table_destroy(ctx->observed_values);
        ctx->observed_values = NULL;
        g_hash_table_destroy(ctx->z3_expr_cache);
        ctx->z3_expr_cache = NULL;
        Z3_dec_ref(ctx->z3_ctx, ctx->path_predicate);
        ctx->path_predicate = NULL;
        Z3_solver_dec_ref(ctx->z3_ctx, ctx->z3_solver);
        ctx->z3_solver = NULL;
        Z3_del_context(ctx->z3_ctx);
        ctx->z3_ctx = NULL;
        return false;
    }
    ctx->root_origins =
        g_hash_table_new_full(dse_root_origin_key_hash, dse_root_origin_key_equal, g_free, g_free);
    if (!ctx->root_origins) {
        g_hash_table_destroy(ctx->root_provenance);
        ctx->root_provenance = NULL;
        g_hash_table_destroy(ctx->observed_values);
        ctx->observed_values = NULL;
        g_hash_table_destroy(ctx->z3_expr_cache);
        ctx->z3_expr_cache = NULL;
        Z3_dec_ref(ctx->z3_ctx, ctx->path_predicate);
        ctx->path_predicate = NULL;
        Z3_solver_dec_ref(ctx->z3_ctx, ctx->z3_solver);
        ctx->z3_solver = NULL;
        Z3_del_context(ctx->z3_ctx);
        ctx->z3_ctx = NULL;
        return false;
    }
    ctx->lineage_origins = g_hash_table_new_full(g_int64_hash, g_int64_equal, g_free, g_free);
    if (!ctx->lineage_origins) {
        g_hash_table_destroy(ctx->root_origins);
        ctx->root_origins = NULL;
        g_hash_table_destroy(ctx->root_provenance);
        ctx->root_provenance = NULL;
        g_hash_table_destroy(ctx->observed_values);
        ctx->observed_values = NULL;
        g_hash_table_destroy(ctx->z3_expr_cache);
        ctx->z3_expr_cache = NULL;
        Z3_dec_ref(ctx->z3_ctx, ctx->path_predicate);
        ctx->path_predicate = NULL;
        Z3_solver_dec_ref(ctx->z3_ctx, ctx->z3_solver);
        ctx->z3_solver = NULL;
        Z3_del_context(ctx->z3_ctx);
        ctx->z3_ctx = NULL;
        return false;
    }
    ctx->has_solver = true;
    g_active_expr_ctx = ctx;
    ctx->replay_model_complete = true;
    ctx->replay_mismatch = false;
    ctx->replay_checks = 0;
    ctx->replay_failures = 0;
    ctx->replay_missing_bindings = 0;
    ctx->memory_model_complete = true;
    ctx->register_model_complete = true;
    ctx->address_model_complete = true;
    ctx->path_model_complete = true;
    ctx->path_constraints = 0;
    ctx->path_failures = 0;
    ctx->string_summaries = 0;
    ctx->x86_flags_poisoned = 0;
    ctx->memory_root_epoch = 1;
    ctx->next_lineage_id = 1;
    ctx->root_provenance_complete = true;
    return true;
}

void dse_ctx_free(DSECtx *ctx) {
    if (!ctx)
        return;
    dse_z3_cache_clear(ctx);
    if (ctx->z3_expr_cache) {
        g_hash_table_destroy(ctx->z3_expr_cache);
        ctx->z3_expr_cache = NULL;
    }
    if (ctx->observed_values) {
        g_hash_table_destroy(ctx->observed_values);
        ctx->observed_values = NULL;
    }
    if (ctx->root_provenance) {
        g_hash_table_destroy(ctx->root_provenance);
        ctx->root_provenance = NULL;
    }
    if (ctx->root_origins) {
        g_hash_table_destroy(ctx->root_origins);
        ctx->root_origins = NULL;
    }
    if (ctx->lineage_origins) {
        g_hash_table_destroy(ctx->lineage_origins);
        ctx->lineage_origins = NULL;
    }
    sym_state_clear(&ctx->state);
    if (ctx->has_solver && ctx->z3_ctx) {
        if (ctx->path_predicate) {
            Z3_dec_ref(ctx->z3_ctx, ctx->path_predicate);
            ctx->path_predicate = NULL;
        }
        if (ctx->z3_solver) {
            Z3_solver_dec_ref(ctx->z3_ctx, ctx->z3_solver);
            ctx->z3_solver = NULL;
        }
        Z3_del_context(ctx->z3_ctx);
        ctx->z3_ctx = NULL;
        ctx->has_solver = false;
    }
    if (g_active_expr_ctx == ctx) {
        g_active_expr_ctx = NULL;
    }
}

static Z3_ast dse_z3_cache_lookup(DSECtx *ctx, const SymExpr *expr) {
    if (!ctx || !ctx->z3_expr_cache || !expr) {
        return NULL;
    }
    Z3_ast cached = (Z3_ast)g_hash_table_lookup(ctx->z3_expr_cache, expr);
    if (cached) {
        Z3_inc_ref(ctx->z3_ctx, cached);
    }
    return cached;
}

static bool dse_z3_cache_insert(DSECtx *ctx, const SymExpr *expr, Z3_ast ast) {
    if (!ctx || !ctx->z3_expr_cache || !expr || !ast) {
        return false;
    }
    if (g_hash_table_size(ctx->z3_expr_cache) >= DSE_MAX_Z3_CACHE_NODES) {
        dse_mark_resource_limit(ctx);
        return false;
    }
    SymExpr *key = sym_expr_clone(expr);
    if (!key) {
        dse_mark_resource_limit(ctx);
        return false;
    }
    Z3_inc_ref(ctx->z3_ctx, ast);
    g_hash_table_insert(ctx->z3_expr_cache, key, ast);
    ctx->z3_cache_nodes = (uint32_t)g_hash_table_size(ctx->z3_expr_cache);
    return true;
}

static Z3_ast dse_z3_cache_and_return(DSECtx *ctx, const SymExpr *expr, Z3_ast ast) {
    if (!ast)
        return NULL;
    Z3_inc_ref(ctx->z3_ctx, ast);
    if (!dse_z3_cache_insert(ctx, expr, ast)) {
        Z3_dec_ref(ctx->z3_ctx, ast);
        return NULL;
    }
    return ast;
}

static void dse_mark_address_failure(DSECtx *ctx) {
    if (!ctx)
        return;
    ctx->address_model_complete = false;
    ctx->address_failures++;
}

static DseReplayCheckStatus dse_replay_expect(DSECtx *ctx, const SymExpr *expr,
                                              uint64_t expected_value, DseReplaySite site,
                                              uint64_t location, uint32_t byte_index) {
    if (!ctx || !expr || expr->width == 0 || expr->width > 64) {
        if (ctx)
            dse_record_replay_missing(ctx);
        return DSE_REPLAY_CHECK_INVALID_EXPR;
    }
    if (ctx->replay_checks != UINT32_MAX)
        ctx->replay_checks++;
    uint64_t replayed_value = 0;
    DseReplayEvalStatus status = dse_eval_expr_observed(ctx, expr, &replayed_value);
    if (status == DSE_REPLAY_EVAL_MISSING_BINDING) {
        dse_record_replay_missing(ctx);
        return DSE_REPLAY_CHECK_MISSING_BINDING;
    }
    if (status != DSE_REPLAY_EVAL_OK) {
        ctx->replay_model_complete = false;
        if (ctx->replay_failures != UINT32_MAX)
            ctx->replay_failures++;
        return DSE_REPLAY_CHECK_INVALID_EXPR;
    }

    replayed_value = mask_w(replayed_value, expr->width);
    expected_value = mask_w(expected_value, expr->width);
    if (replayed_value != expected_value) {
        dse_capture_replay_mismatch(ctx, site, location, byte_index, expr, expected_value,
                                    replayed_value, false);
        dse_record_replay_mismatch(ctx);
        return DSE_REPLAY_CHECK_MISMATCH;
    }
    return DSE_REPLAY_CHECK_OK;
}

static Z3_ast dse_z3_bool_to_bv1_owned(DSECtx *ctx, Z3_ast relation) {
    if (!ctx || !ctx->z3_ctx || !relation) {
        return NULL;
    }
    Z3_context z3 = ctx->z3_ctx;
    Z3_ast bit_sort_ast = NULL;
    Z3_ast one = NULL;
    Z3_ast zero = NULL;
    Z3_ast result = NULL;
    Z3_inc_ref(z3, relation);
    Z3_sort bit_sort = Z3_mk_bv_sort(z3, 1);
    if (!bit_sort)
        goto cleanup;
    bit_sort_ast = Z3_sort_to_ast(z3, bit_sort);
    if (!bit_sort_ast)
        goto cleanup;
    Z3_inc_ref(z3, bit_sort_ast);
    one = Z3_mk_unsigned_int(z3, 1, bit_sort);
    if (!one)
        goto cleanup;
    Z3_inc_ref(z3, one);
    zero = Z3_mk_unsigned_int(z3, 0, bit_sort);
    if (!zero)
        goto cleanup;
    Z3_inc_ref(z3, zero);
    result = Z3_mk_ite(z3, relation, one, zero);
    if (result) {
        Z3_inc_ref(z3, result);
    }
cleanup:
    if (zero) {
        Z3_dec_ref(z3, zero);
    }
    if (one) {
        Z3_dec_ref(z3, one);
    }
    if (bit_sort_ast) {
        Z3_dec_ref(z3, bit_sort_ast);
    }
    Z3_dec_ref(z3, relation);
    return result;
}

static Z3_ast sym_expr_to_z3(DSECtx *ctx, const SymExpr *expr) {
    if (!ctx || !expr || !ctx->z3_ctx || ctx->resource_limit_hit) {
        return NULL;
    }
    Z3_ast cached = dse_z3_cache_lookup(ctx, expr);
    if (cached)
        return cached;
    Z3_context z3 = ctx->z3_ctx;
    switch (expr->type) {
    case SYM_CONST: {
        Z3_sort sort = Z3_mk_bv_sort(z3, expr->width);
        Z3_ast result = Z3_mk_unsigned_int64(z3, expr->const_val, sort);
        return dse_z3_cache_and_return(ctx, expr, result);
    }
    case SYM_VAR: {
        Z3_sort sort = Z3_mk_bv_sort(z3, expr->width);
        char name_buffer[32];
        snprintf(name_buffer, sizeof(name_buffer), "dse_v%u", expr->var.id);
        Z3_symbol name = Z3_mk_string_symbol(z3, name_buffer);
        Z3_ast result = Z3_mk_const(z3, name, sort);
        return dse_z3_cache_and_return(ctx, expr, result);
    }
    case SYM_ADD:
    case SYM_SUB:
    case SYM_MUL:
    case SYM_XOR:
    case SYM_AND:
    case SYM_OR:
    case SYM_SHL:
    case SYM_LSHR:
    case SYM_ASHR:
    case SYM_CONCAT:
    case SYM_EQ:
    case SYM_ULT:
    case SYM_SLT: {
        Z3_ast left = sym_expr_to_z3(ctx, expr->binary.a);
        Z3_ast right = sym_expr_to_z3(ctx, expr->binary.b);
        if (!left || !right) {
            if (left) {
                Z3_dec_ref(z3, left);
            }
            if (right) {
                Z3_dec_ref(z3, right);
            }
            return NULL;
        }
        Z3_ast result = NULL;
        switch (expr->type) {
        case SYM_ADD:
            result = Z3_mk_bvadd(z3, left, right);
            break;
        case SYM_SUB:
            result = Z3_mk_bvsub(z3, left, right);
            break;
        case SYM_MUL:
            result = Z3_mk_bvmul(z3, left, right);
            break;
        case SYM_XOR:
            result = Z3_mk_bvxor(z3, left, right);
            break;
        case SYM_AND:
            result = Z3_mk_bvand(z3, left, right);
            break;
        case SYM_OR:
            result = Z3_mk_bvor(z3, left, right);
            break;
        case SYM_SHL:
            result = Z3_mk_bvshl(z3, left, right);
            break;
        case SYM_LSHR:
            result = Z3_mk_bvlshr(z3, left, right);
            break;
        case SYM_ASHR:
            result = Z3_mk_bvashr(z3, left, right);
            break;
        case SYM_CONCAT:
            result = Z3_mk_concat(z3, left, right);
            break;
        case SYM_EQ:
        case SYM_ULT:
        case SYM_SLT: {
            Z3_ast relation = NULL;
            if (expr->type == SYM_EQ) {
                relation = Z3_mk_eq(z3, left, right);
            } else if (expr->type == SYM_ULT) {
                relation = Z3_mk_bvult(z3, left, right);
            } else {
                relation = Z3_mk_bvslt(z3, left, right);
            }
            Z3_ast protected_result = dse_z3_bool_to_bv1_owned(ctx, relation);
            Z3_ast cached_result = NULL;
            if (protected_result) {
                cached_result = dse_z3_cache_and_return(ctx, expr, protected_result);
                Z3_dec_ref(z3, protected_result);
            }
            Z3_dec_ref(z3, left);
            Z3_dec_ref(z3, right);
            return cached_result;
        }
        default:
            break;
        }
        Z3_ast owned_result = dse_z3_cache_and_return(ctx, expr, result);
        Z3_dec_ref(z3, left);
        Z3_dec_ref(z3, right);
        return owned_result;
    }
    case SYM_ITE: {
        Z3_ast condition = sym_expr_to_z3(ctx, expr->ternary.cond);
        Z3_ast when_true = sym_expr_to_z3(ctx, expr->ternary.when_true);
        Z3_ast when_false = sym_expr_to_z3(ctx, expr->ternary.when_false);
        Z3_ast bit_sort_ast = NULL;
        Z3_ast one = NULL;
        Z3_ast condition_bool = NULL;
        Z3_ast cached_result = NULL;
        if (!condition || !when_true || !when_false) {
            if (condition)
                Z3_dec_ref(z3, condition);
            if (when_true)
                Z3_dec_ref(z3, when_true);
            if (when_false)
                Z3_dec_ref(z3, when_false);
            return NULL;
        }
        Z3_sort bit_sort = Z3_mk_bv_sort(z3, 1);
        if (bit_sort)
            bit_sort_ast = Z3_sort_to_ast(z3, bit_sort);
        if (bit_sort_ast) {
            Z3_inc_ref(z3, bit_sort_ast);
            one = Z3_mk_unsigned_int(z3, 1, bit_sort);
            if (one) {
                Z3_inc_ref(z3, one);
                condition_bool = Z3_mk_eq(z3, condition, one);
                if (condition_bool) {
                    Z3_inc_ref(z3, condition_bool);
                    Z3_ast result = Z3_mk_ite(z3, condition_bool, when_true, when_false);
                    if (result) {
                        cached_result = dse_z3_cache_and_return(ctx, expr, result);
                    }
                }
            }
        }
        if (condition_bool)
            Z3_dec_ref(z3, condition_bool);
        if (one)
            Z3_dec_ref(z3, one);
        if (bit_sort_ast)
            Z3_dec_ref(z3, bit_sort_ast);
        Z3_dec_ref(z3, condition);
        Z3_dec_ref(z3, when_true);
        Z3_dec_ref(z3, when_false);
        return cached_result;
    }
    case SYM_ZEXT:
    case SYM_SEXT: {
        Z3_ast operand = sym_expr_to_z3(ctx, expr->unary.a);
        if (!operand)
            return NULL;
        unsigned extension = (unsigned)(expr->width - expr->unary.a->width);
        Z3_ast result = expr->type == SYM_ZEXT ? Z3_mk_zero_ext(z3, extension, operand)
                                               : Z3_mk_sign_ext(z3, extension, operand);
        Z3_ast owned_result = dse_z3_cache_and_return(ctx, expr, result);
        Z3_dec_ref(z3, operand);
        return owned_result;
    }
    case SYM_EXTRACT: {
        Z3_ast operand = sym_expr_to_z3(ctx, expr->unary.a);
        if (!operand)
            return NULL;
        Z3_ast result =
            Z3_mk_extract(z3, expr->unary.extract_high, expr->unary.extract_low, operand);
        Z3_ast owned_result = dse_z3_cache_and_return(ctx, expr, result);
        Z3_dec_ref(z3, operand);
        return owned_result;
    }
    }
    return NULL;
}

bool dse_constrain_observed_address(DSECtx *ctx, SymExpr *address, uint64_t observed_address,
                                    DseAddressAccess access) {
    if (!ctx || !address || !ctx->has_solver || !ctx->z3_ctx || !ctx->path_predicate ||
        address->width == 0 || address->width > 64 ||
        (access != DSE_ADDRESS_READ && access != DSE_ADDRESS_WRITE)) {
        sym_expr_free(address);
        dse_mark_address_failure(ctx);
        return false;
    }
    observed_address = mask_w(observed_address, address->width);
    DseReplayCheckStatus replay_status = dse_replay_expect(
        ctx, address, observed_address,
        access == DSE_ADDRESS_READ ? DSE_REPLAY_SITE_ADDRESS_READ : DSE_REPLAY_SITE_ADDRESS_WRITE,
        observed_address, 0);
    if (replay_status != DSE_REPLAY_CHECK_OK) {
        sym_expr_free(address);
        dse_mark_address_failure(ctx);
        return false;
    }
    if (!dse_expr_has_var(address)) {
        bool matches = address->type == SYM_CONST &&
                       mask_w(address->const_val, address->width) == observed_address;
        sym_expr_free(address);
        if (!matches) {
            dse_mark_address_failure(ctx);
            return false;
        }
        if (access == DSE_ADDRESS_READ) {
            ctx->address_read_modeled++;
        } else {
            ctx->address_write_modeled++;
        }
        return true;
    }
    Z3_context z3 = ctx->z3_ctx;
    Z3_ast symbolic_address = sym_expr_to_z3(ctx, address);
    Z3_sort sort = Z3_mk_bv_sort(z3, address->width);
    Z3_ast concrete_address = Z3_mk_unsigned_int64(z3, observed_address, sort);
    if (!symbolic_address || !concrete_address) {
        if (symbolic_address) {
            Z3_dec_ref(z3, symbolic_address);
        }
        sym_expr_free(address);
        dse_mark_address_failure(ctx);
        return false;
    }
    Z3_inc_ref(z3, concrete_address);
    Z3_ast equality = Z3_mk_eq(z3, symbolic_address, concrete_address);
    if (!equality) {
        Z3_dec_ref(z3, concrete_address);
        Z3_dec_ref(z3, symbolic_address);
        sym_expr_free(address);
        dse_mark_address_failure(ctx);
        return false;
    }
    Z3_inc_ref(z3, equality);
    Z3_ast conjuncts[2] = {ctx->path_predicate, equality};
    Z3_ast predicate = Z3_mk_and(z3, 2, conjuncts);
    if (!predicate) {
        Z3_dec_ref(z3, equality);
        Z3_dec_ref(z3, concrete_address);
        Z3_dec_ref(z3, symbolic_address);
        sym_expr_free(address);
        dse_mark_address_failure(ctx);
        return false;
    }
    Z3_inc_ref(z3, predicate);
    Z3_dec_ref(z3, ctx->path_predicate);
    ctx->path_predicate = predicate;
    Z3_dec_ref(z3, equality);
    Z3_dec_ref(z3, concrete_address);
    Z3_dec_ref(z3, symbolic_address);
    sym_expr_free(address);
    ctx->address_constraints++;
    if (access == DSE_ADDRESS_READ) {
        ctx->address_read_modeled++;
    } else {
        ctx->address_write_modeled++;
    }
    return true;
}

bool dse_path_assert(DSECtx *ctx, SymExpr *cond, bool expected) {
    if (!ctx || !cond || cond->width != 1 || !ctx->has_solver || !ctx->z3_ctx ||
        !ctx->path_predicate) {
        if (ctx) {
            ctx->path_model_complete = false;
            ctx->path_failures++;
        }
        sym_expr_free(cond);
        return false;
    }
    DseReplayCheckStatus replay_status =
        dse_replay_expect(ctx, cond, expected ? 1U : 0U, DSE_REPLAY_SITE_BRANCH, 0, 0);
    if (replay_status != DSE_REPLAY_CHECK_OK) {
        ctx->path_model_complete = false;
        if (ctx->path_failures != UINT32_MAX) {
            ctx->path_failures++;
        }
        sym_expr_free(cond);
        return false;
    }
    Z3_context z3 = ctx->z3_ctx;
    Z3_ast condition = sym_expr_to_z3(ctx, cond);
    Z3_sort bit_sort = Z3_mk_bv_sort(z3, 1);
    Z3_ast expected_bit = Z3_mk_unsigned_int(z3, expected ? 1U : 0U, bit_sort);
    if (!condition || !expected_bit) {
        if (condition)
            Z3_dec_ref(z3, condition);
        ctx->path_model_complete = false;
        ctx->path_failures++;
        sym_expr_free(cond);
        return false;
    }
    Z3_ast equality = Z3_mk_eq(z3, condition, expected_bit);
    Z3_ast conjuncts[2] = {ctx->path_predicate, equality};
    Z3_ast predicate = equality ? Z3_mk_and(z3, 2, conjuncts) : NULL;
    if (!predicate) {
        Z3_dec_ref(z3, condition);
        ctx->path_model_complete = false;
        ctx->path_failures++;
        sym_expr_free(cond);
        return false;
    }
    Z3_inc_ref(z3, predicate);
    Z3_dec_ref(z3, ctx->path_predicate);
    ctx->path_predicate = predicate;
    Z3_dec_ref(z3, condition);
    ctx->path_constraints++;
    sym_expr_free(cond);
    return true;
}

static int dse_x86_flag_slot(uint8_t flag) {
    switch (flag) {
    case X86_FLAG_CF:
        return DSE_FLAG_SLOT_CF;
    case X86_FLAG_PF:
        return DSE_FLAG_SLOT_PF;
    case X86_FLAG_AF:
        return DSE_FLAG_SLOT_AF;
    case X86_FLAG_ZF:
        return DSE_FLAG_SLOT_ZF;
    case X86_FLAG_SF:
        return DSE_FLAG_SLOT_SF;
    case X86_FLAG_OF:
        return DSE_FLAG_SLOT_OF;
    default:
        return -1;
    }
}

static int dse_x86_eflags_bit(uint8_t flag) {
    switch (flag) {
    case X86_FLAG_CF:
        return 0;
    case X86_FLAG_PF:
        return 2;
    case X86_FLAG_AF:
        return 4;
    case X86_FLAG_ZF:
        return 6;
    case X86_FLAG_SF:
        return 7;
    case X86_FLAG_OF:
        return 11;
    default:
        return -1;
    }
}

static void dse_mark_path_failure(DSECtx *ctx) {
    if (!ctx)
        return;
    ctx->path_model_complete = false;
    if (ctx->path_failures != UINT32_MAX) {
        ctx->path_failures++;
    }
}

SymExpr *dse_get_x86_flag(DSECtx *ctx, const InsnAux *aux, uint8_t flag) {
    int slot = dse_x86_flag_slot(flag);
    if (!ctx || slot < 0) {
        dse_mark_path_failure(ctx);
        return NULL;
    }
    if ((ctx->x86_flags_poisoned & flag) != 0) {
        dse_mark_path_failure(ctx);
        return NULL;
    }
    if (ctx->state.x86_flags[slot]) {
        SymExpr *result = sym_expr_clone(ctx->state.x86_flags[slot]);
        if (!result)
            dse_mark_path_failure(ctx);
        return result;
    }
    if (!aux || !aux->eflags_valid) {
        dse_mark_path_failure(ctx);
        return NULL;
    }
    int eflags_bit = dse_x86_eflags_bit(flag);
    if (eflags_bit < 0) {
        dse_mark_path_failure(ctx);
        return NULL;
    }
    uint64_t observed_value = (aux->eflags_before >> (uint32_t)eflags_bit) & 1U;
    SymExpr *root = dse_new_observed_epoch_var(ctx, FLAG_VAR_BASE | (uint64_t)(uint8_t)slot,
                                               aux->seq_id, aux->seq_id, aux->seq_id, 0, 1,
                                               DSE_VAR_FLAG_ROOT, observed_value, NULL);
    if (!root) {
        dse_mark_path_failure(ctx);
        return NULL;
    }
    ctx->state.x86_flags[slot] = sym_expr_clone(root);
    if (!ctx->state.x86_flags[slot]) {
        sym_expr_free(root);
        dse_mark_path_failure(ctx);
        return NULL;
    }
    return root;
}

void dse_set_x86_flag(DSECtx *ctx, uint8_t flag, SymExpr *value) {
    int slot = dse_x86_flag_slot(flag);
    if (!ctx || slot < 0) {
        sym_expr_free(value);
        return;
    }
    if (!value || value->width != 1) {
        sym_expr_free(value);
        sym_expr_free(ctx->state.x86_flags[slot]);
        ctx->state.x86_flags[slot] = NULL;
        ctx->x86_flags_poisoned |= flag;
        dse_mark_path_failure(ctx);
        return;
    }
    SymExpr *old = ctx->state.x86_flags[slot];
    ctx->state.x86_flags[slot] = value;
    ctx->x86_flags_poisoned &= (uint8_t)~flag;
    sym_expr_free(old);
}

void dse_invalidate_x86_flags(DSECtx *ctx, uint8_t flags) {
    if (!ctx)
        return;
    flags &= X86_FLAG_TRACKED;
    for (uint8_t flag = 1U; flag != 0; flag <<= 1U) {
        if ((flags & flag) == 0) {
            continue;
        }
        int slot = dse_x86_flag_slot(flag);
        if (slot < 0)
            continue;
        sym_expr_free(ctx->state.x86_flags[slot]);
        ctx->state.x86_flags[slot] = NULL;
    }
    ctx->x86_flags_poisoned |= flags;
}

//init all
static const TraceBuffer *g_tb = NULL;
static const DseAuxRing *g_ring = NULL;
static const DseArch *g_arch = NULL;
static uint32_t g_total = 0, g_concretized = 0;
static uint32_t g_aux_miss = 0, g_unsupported = 0;

static uint8_t dse_lift_natural_byte_mask(void) {
    if (!g_arch || g_arch->natural_width == 0 || g_arch->natural_width > 64 ||
        g_arch->natural_width % 8 != 0) {
        return 0;
    }
    uint32_t byte_count = g_arch->natural_width / 8;
    return byte_count >= 8 ? UINT8_MAX : (uint8_t)((1U << byte_count) - 1U);
}

static bool dse_address_reg_mask_is_tainted(const InsnAux *aux, uint32_t address_reg_mask) {
    if (!aux || address_reg_mask == 0)
        return false;
    uint8_t natural_mask = dse_lift_natural_byte_mask();
    if (natural_mask == 0)
        return true;
    for (int reg = 0; reg < REG_COUNT; reg++) {
        if ((address_reg_mask & (1U << reg)) != 0 && (aux->reg_taint[reg] & natural_mask) != 0) {
            return true;
        }
    }
    return false;
}

static uint32_t dse_observed_read_count(const InsnAux *aux) {
    if (!aux)
        return 0;
    if (dse_aux_has_exact_movs(aux)) {
        return aux->string_summary.expected_iterations != 0 ? 1U : 0U;
    }
    if (dse_aux_has_exact_stos(aux))
        return 0;
    return aux->mem_read_count;
}

static uint32_t dse_observed_write_count(const InsnAux *aux) {
    if (!aux)
        return 0;
    if (dse_aux_has_exact_movs(aux) || dse_aux_has_exact_stos(aux)) {
        return aux->string_summary.expected_iterations != 0 ? 1U : 0U;
    }
    return aux->mem_write_count;
}

//dealing with invalid lift
static void dse_invalidate_lift_outputs(DSECtx *ctx, const InsnMeta *meta, const InsnAux *aux) {
    if (!ctx || !meta)
        return;
    for (int rid = 0; rid < REG_COUNT; rid++) {
        if ((meta->regs_written_mask & (UINT32_C(1) << rid)) == 0) {
            continue;
        }
        sym_state_set_reg(&ctx->state, (RegId)rid, NULL);
        dse_advance_register_root_epoch(ctx, rid);
    }
    dse_invalidate_x86_flags(ctx, meta->flags_write_mask);
    bool writes_memory = meta->has_mem_write || (aux && aux->has_mem_write);
    if (writes_memory) {
        if (ctx->state.sym_mem) {
            g_hash_table_remove_all(ctx->state.sym_mem);
        }
        if (ctx->memory_root_epoch != UINT64_MAX) {
            ctx->memory_root_epoch++;
        } else {
            ctx->memory_model_complete = false;
            ctx->replay_model_complete = false;
        }
    }
}

//lifter
static bool dse_lift_observed_insn(DSECtx *ctx, const TraceEntry *entry, const InsnMeta *meta,
                                   const InsnAux *aux, const InsnDesc *desc, csh cs_handle) {
    if (!ctx || !entry || !meta || !g_arch) {
        return false;
    }
    if (ctx->resource_limit_hit)
        return false;
    g_total++;
    const uint8_t *instruction_bytes = entry->instr_bytes;
    uint8_t instruction_size = entry->size;
    if (entry->insn_desc_id != INSN_DESC_ID_INVALID) {
        if (!desc || desc->arch != TRACE_ARCH_X86 || desc->mode != TRACE_MODE_32 ||
            desc->pc != entry->pc || desc->meta_id != entry->meta_id ||
            desc->code_generation != entry->code_generation ||
            desc->bytes_hash != entry->bytes_hash) {
            dse_invalidate_lift_outputs(ctx, meta, aux);
            g_concretized++;
            return false;
        }
        instruction_bytes = desc->bytes;
        instruction_size = desc->size;
    }
    cs_insn *insn = NULL;
    size_t count = 0;
    if (cs_handle) {
        count = cs_disasm(cs_handle, instruction_bytes, instruction_size, entry->pc, 1, &insn);
    }
    if (count == 0 || !insn || !insn->detail || !aux || !aux->execution_complete) {
        dse_invalidate_lift_outputs(ctx, meta, aux);
        if (insn) {
            cs_free(insn, count);
        }
        if (!aux || !aux->execution_complete) {
            g_aux_miss++;
        }
        g_concretized++;
        return false;
    }

    bool tainted_read_address = dse_address_reg_mask_is_tainted(aux, meta->mem_read_addr_reg_mask);
    bool tainted_write_address =
        dse_address_reg_mask_is_tainted(aux, meta->mem_write_addr_reg_mask);
    uint32_t read_before = ctx->address_read_modeled;
    uint32_t write_before = ctx->address_write_modeled;
    uint32_t address_failures_before = ctx->address_failures;
    uint32_t replay_failures_before = ctx->replay_failures;
    bool ok = g_arch->lift_one(ctx, insn, aux, g_arch);
    if (ctx->resource_limit_hit) {
        cs_free(insn, count);
        return false;
    }
    bool address_check_failed = ctx->address_failures != address_failures_before;
    bool replay_check_failed = ctx->replay_failures != replay_failures_before;
    if (address_check_failed || replay_check_failed) {
        DSE_DIAGNOSTIC(stderr,
                       "[DSE-LIFT-CHECK-FAILED] pc=0x%lx replay=%s address=%s insn=\"%s %s\"\n",
                       (unsigned long)entry->pc, replay_check_failed ? "yes" : "no",
                       address_check_failed ? "yes" : "no", insn->mnemonic, insn->op_str);
        dse_invalidate_lift_outputs(ctx, meta, aux);
        g_concretized++;
        cs_free(insn, count);
        return false;
    }
    if (!ok) {
        DSE_DIAGNOSTIC(stderr, "[DSE-UNSUPPORTED] pc=0x%lx id=%u insn=\"%s %s\"\n",
                       (unsigned long)entry->pc, (unsigned int)insn->id, insn->mnemonic,
                       insn->op_str);
        dse_invalidate_lift_outputs(ctx, meta, aux);
        g_unsupported++;
        g_concretized++;
        cs_free(insn, count);
        return false;
    }

    uint32_t modeled_reads = ctx->address_read_modeled - read_before;
    uint32_t modeled_writes = ctx->address_write_modeled - write_before;
    uint32_t required_reads = tainted_read_address ? dse_observed_read_count(aux) : 0;
    uint32_t required_writes = tainted_write_address ? dse_observed_write_count(aux) : 0;
    bool address_incomplete = (tainted_read_address && modeled_reads < required_reads) ||
                              (tainted_write_address && modeled_writes < required_writes);
    if (address_incomplete) {
        dse_mark_address_failure(ctx);
        DSE_DIAGNOSTIC(stderr,
                       "[DSE-ADDR-UNMODELED] pc=0x%lx read=%u/%u write=%u/%u insn=\"%s %s\"\n",
                       (unsigned long)entry->pc, modeled_reads, required_reads, modeled_writes,
                       required_writes, insn->mnemonic, insn->op_str);
        dse_invalidate_lift_outputs(ctx, meta, aux);
        g_concretized++;
        cs_free(insn, count);
        return false;
    }
    cs_free(insn, count);
    return true;
}

bool dse_lift_insn(DSECtx *ctx, const TraceEntry *entry, const InsnMeta *meta, csh cs_handle) {
    const InsnAux *aux = dse_aux_for(g_ring, g_tb, entry);
    const InsnDesc *desc = entry ? trace_insn_desc_get(g_tb, entry->insn_desc_id) : NULL;
    dse_diagnostic_origin(ctx, entry);
    bool ok = dse_lift_observed_insn(ctx, entry, meta, aux, desc, cs_handle);
    dse_diagnostic_origin(ctx, NULL);
    return ok;
}

bool dse_lift_replay_step(DSECtx *ctx, const ReplayInput *input, uint32_t index, csh cs_handle) {
    const ReplayStep *step = index == replay_input_count(input) ? replay_input_trigger(input)
                                                                : replay_input_step(input, index);
    if (!step || step->issues != 0) {
        dse_record_replay_missing(ctx);
        return false;
    }
    const InsnMeta *meta = replay_input_meta(input, step->entry.seq_id);
    const InsnAux *aux = replay_input_aux(input, step->entry.seq_id);
    if (!meta || !aux) {
        dse_record_replay_missing(ctx);
        return false;
    }
    dse_diagnostic_origin(ctx, &step->entry);
    bool ok = dse_lift_observed_insn(ctx, &step->entry, meta, aux,
                                     step->descriptor_valid ? &step->descriptor : NULL, cs_handle);
    dse_diagnostic_origin(ctx, NULL);
    return ok;
}

void dse_lift_attach(const TraceBuffer *tb, const DseAuxRing *ring, const struct DseArch *arch) {
    g_tb = tb;
    g_ring = ring;
    g_arch = arch;
}

void dse_lift_begin(DSECtx *ctx) {
    if (ctx) {
        g_active_expr_ctx = ctx;
        dse_z3_cache_clear(ctx);
        sym_state_clear(&ctx->state);
        if (ctx->observed_values)
            g_hash_table_remove_all(ctx->observed_values);
        if (ctx->root_provenance)
            g_hash_table_remove_all(ctx->root_provenance);
        if (ctx->root_origins)
            g_hash_table_remove_all(ctx->root_origins);
        if (ctx->lineage_origins)
            g_hash_table_remove_all(ctx->lineage_origins);
        if (ctx->has_solver && ctx->z3_ctx && ctx->z3_solver) {
            Z3_solver_reset(ctx->z3_ctx, ctx->z3_solver);
        }
        if (ctx->z3_ctx) {
            if (ctx->path_predicate) {
                Z3_dec_ref(ctx->z3_ctx, ctx->path_predicate);
            }
            ctx->path_predicate = Z3_mk_true(ctx->z3_ctx);
            if (ctx->path_predicate) {
                Z3_inc_ref(ctx->z3_ctx, ctx->path_predicate);
            }
        }
        ctx->resource_limit_hit = false;
        ctx->replay_model_complete = ctx->observed_values != NULL;
        ctx->replay_mismatch = false;
        memset(&ctx->first_replay_mismatch, 0, sizeof(ctx->first_replay_mismatch));
        dse_diagnostic_origin(ctx, NULL);
        ctx->replay_checks = 0;
        ctx->replay_failures = 0;
        ctx->replay_missing_bindings = 0;
        ctx->expr_nodes_created = 0;
        ctx->z3_cache_nodes =
            ctx->z3_expr_cache ? (uint32_t)g_hash_table_size(ctx->z3_expr_cache) : 0;
        ctx->address_constraints = 0;
        ctx->address_read_modeled = 0;
        ctx->address_write_modeled = 0;
        ctx->address_failures = 0;
        ctx->address_model_complete = true;
        ctx->memory_model_complete = true;
        ctx->register_model_complete = true;
        ctx->path_model_complete = ctx->path_predicate != NULL;
        ctx->path_constraints = 0;
        ctx->path_failures = 0;
        ctx->string_summaries = 0;
        ctx->x86_flags_poisoned = 0;
        ctx->memory_root_epoch = 1;
        ctx->next_lineage_id = 1;
        ctx->root_provenance_complete = ctx->root_provenance != NULL && ctx->root_origins != NULL &&
                                        ctx->lineage_origins != NULL;
        dse_reset_register_root_epochs(ctx);
        ctx->demand_active = false;
        ctx->demand_seq_id = 0;
        memset(ctx->demand_reg_live_after, 0, sizeof(ctx->demand_reg_live_after));
        ctx->demand_all_memory_writes = false;
        ctx->demand_memory_writes = NULL;
    }
    g_total = 0;
    g_concretized = 0;
    g_aux_miss = 0;
    g_unsupported = 0;
}

uint32_t dse_lift_total_count(void) {
    return g_total;
}

uint32_t dse_lift_concretized_count(void) {
    return g_concretized;
}

uint32_t dse_lift_aux_miss_count(void) {
    return g_aux_miss;
}

uint32_t dse_lift_unsupported_count(void) {
    return g_unsupported;
}

bool dse_expr_has_var(const SymExpr *expr) {
    return expr && expr->has_var;
}

static DseReplayEvalStatus dse_eval_expr_observed_impl(const DSECtx *ctx, const SymExpr *expr,
                                                       uint64_t *out_value, uint32_t depth,
                                                       GHashTable *memo) {
    if (!ctx || !expr || !out_value || !memo || expr->width == 0 || expr->width > 64 ||
        depth > DSE_MAX_REPLAY_DEPTH) {
        return DSE_REPLAY_EVAL_INVALID_EXPR;
    }
    DseReplayMemoEntry *cached = g_hash_table_lookup(memo, expr);
    if (cached) {
        if (!cached->complete)
            return DSE_REPLAY_EVAL_INVALID_EXPR;
        *out_value = cached->value;
        return cached->status;
    }
    if ((uint32_t)g_hash_table_size(memo) >= DSE_MAX_REPLAY_EVAL_NODES) {
        return DSE_REPLAY_EVAL_INVALID_EXPR;
    }
    DseReplayMemoEntry *entry = g_try_new0(DseReplayMemoEntry, 1);
    if (!entry) {
        return DSE_REPLAY_EVAL_INVALID_EXPR;
    }
    entry->status = DSE_REPLAY_EVAL_INVALID_EXPR;
    g_hash_table_insert(memo, (gpointer)expr, entry);
    uint8_t width = expr->width;
    uint64_t value = 0;
    uint64_t left = 0;
    uint64_t right = 0;
    DseReplayEvalStatus status = DSE_REPLAY_EVAL_INVALID_EXPR;

    switch (expr->type) {
    case SYM_CONST:
        value = mask_w(expr->const_val, width);
        status = DSE_REPLAY_EVAL_OK;
        break;
    case SYM_VAR: {
        if (!ctx->observed_values) {
            status = DSE_REPLAY_EVAL_MISSING_BINDING;
            break;
        }
        uint32_t lookup_id = expr->var.id;
        const DseObservedValue *observed = g_hash_table_lookup(ctx->observed_values, &lookup_id);
        if (!observed) {
            status = DSE_REPLAY_EVAL_MISSING_BINDING;
            break;
        }
        if (observed->width != width) {
            status = DSE_REPLAY_EVAL_INVALID_EXPR;
            break;
        }
        value = mask_w(observed->value, width);
        status = DSE_REPLAY_EVAL_OK;
        break;
    }
    case SYM_ADD:
    case SYM_SUB:
    case SYM_MUL:
    case SYM_XOR:
    case SYM_AND:
    case SYM_OR:
    case SYM_SHL:
    case SYM_LSHR:
    case SYM_ASHR:
        if (!expr->binary.a || !expr->binary.b || expr->binary.a->width != width ||
            expr->binary.b->width != width) {
            break;
        }
        status = dse_eval_expr_observed_impl(ctx, expr->binary.a, &left, depth + 1U, memo);
        if (status != DSE_REPLAY_EVAL_OK)
            break;
        status = dse_eval_expr_observed_impl(ctx, expr->binary.b, &right, depth + 1U, memo);
        if (status != DSE_REPLAY_EVAL_OK)
            break;
        switch (expr->type) {
        case SYM_ADD:
            value = mask_w(left + right, width);
            break;
        case SYM_SUB:
            value = mask_w(left - right, width);
            break;
        case SYM_MUL:
            value = mask_w(left * right, width);
            break;
        case SYM_XOR:
            value = mask_w(left ^ right, width);
            break;
        case SYM_AND:
            value = mask_w(left & right, width);
            break;
        case SYM_OR:
            value = mask_w(left | right, width);
            break;
        case SYM_SHL:
            value = right >= width ? 0 : mask_w(left << right, width);
            break;
        case SYM_LSHR:
            value = right >= width ? 0 : mask_w(left >> right, width);
            break;
        case SYM_ASHR: {
            uint64_t source = mask_w(left, width);
            bool negative = ((source >> (width - 1U)) & 1U) != 0;
            if (right >= width) {
                value = negative ? mask_w(~UINT64_C(0), width) : 0;
                break;
            }
            value = source >> right;
            if (negative && right != 0) {
                uint8_t retained = (uint8_t)(width - right);
                uint64_t fill = mask_w(~UINT64_C(0), width) & ~mask_w(~UINT64_C(0), retained);
                value |= fill;
            }
            value = mask_w(value, width);
            break;
        }
        default:
            status = DSE_REPLAY_EVAL_INVALID_EXPR;
            break;
        }
        break;
    case SYM_CONCAT:
        if (!expr->binary.a || !expr->binary.b || expr->binary.a->width == 0 ||
            expr->binary.b->width == 0 ||
            ((uint32_t)expr->binary.a->width + expr->binary.b->width != width)) {
            break;
        }
        status = dse_eval_expr_observed_impl(ctx, expr->binary.a, &left, depth + 1U, memo);
        if (status != DSE_REPLAY_EVAL_OK)
            break;
        status = dse_eval_expr_observed_impl(ctx, expr->binary.b, &right, depth + 1U, memo);
        if (status != DSE_REPLAY_EVAL_OK)
            break;
        value = mask_w((left << expr->binary.b->width) | right, width);
        break;
    case SYM_EXTRACT:
        if (!expr->unary.a || expr->unary.extract_low > expr->unary.a->width ||
            width > (expr->unary.a->width - expr->unary.extract_low)) {
            break;
        }
        status = dse_eval_expr_observed_impl(ctx, expr->unary.a, &left, depth + 1U, memo);
        if (status != DSE_REPLAY_EVAL_OK)
            break;
        value = mask_w(left >> expr->unary.extract_low, width);
        break;
    case SYM_ZEXT:
    case SYM_SEXT:
        if (!expr->unary.a || width < expr->unary.a->width) {
            break;
        }
        status = dse_eval_expr_observed_impl(ctx, expr->unary.a, &left, depth + 1U, memo);
        if (status != DSE_REPLAY_EVAL_OK)
            break;
        if (expr->type == SYM_SEXT) {
            uint8_t source_width = expr->unary.a->width;
            left = mask_w(left, source_width);
            if (source_width < 64 && ((left >> (source_width - 1U)) & 1U) != 0) {
                left |= ~mask_w(~UINT64_C(0), source_width);
            }
        }
        value = mask_w(left, width);
        break;
    case SYM_EQ:
    case SYM_ULT:
    case SYM_SLT:
        if (width != 1 || !expr->binary.a || !expr->binary.b || expr->binary.a->width == 0 ||
            expr->binary.a->width != expr->binary.b->width) {
            break;
        }
        status = dse_eval_expr_observed_impl(ctx, expr->binary.a, &left, depth + 1U, memo);
        if (status != DSE_REPLAY_EVAL_OK)
            break;
        status = dse_eval_expr_observed_impl(ctx, expr->binary.b, &right, depth + 1U, memo);
        if (status != DSE_REPLAY_EVAL_OK)
            break;
        if (expr->type == SYM_EQ) {
            value = left == right;
        } else if (expr->type == SYM_ULT) {
            value = left < right;
        } else {
            uint8_t operand_width = expr->binary.a->width;
            uint64_t sign = UINT64_C(1) << (operand_width - 1U);
            value = (left ^ sign) < (right ^ sign);
        }
        break;
    case SYM_ITE: {
        if (!expr->ternary.cond || !expr->ternary.when_true || !expr->ternary.when_false ||
            expr->ternary.cond->width != 1 || expr->ternary.when_true->width != width ||
            expr->ternary.when_false->width != width) {
            break;
        }
        uint64_t condition = 0;
        status = dse_eval_expr_observed_impl(ctx, expr->ternary.cond, &condition, depth + 1U, memo);
        if (status != DSE_REPLAY_EVAL_OK)
            break;
        const SymExpr *selected =
            (condition & 1U) != 0 ? expr->ternary.when_true : expr->ternary.when_false;
        status = dse_eval_expr_observed_impl(ctx, selected, &left, depth + 1U, memo);
        if (status != DSE_REPLAY_EVAL_OK)
            break;
        value = mask_w(left, width);
        break;
    }
    }
    entry->status = status;
    entry->value = status == DSE_REPLAY_EVAL_OK ? mask_w(value, width) : 0;
    entry->complete = true;
    *out_value = entry->value;
    return status;
}

DseReplayEvalStatus dse_eval_expr_observed(const DSECtx *ctx, const SymExpr *expr,
                                           uint64_t *out_value) {
    if (out_value)
        *out_value = 0;
    if (!ctx || !expr || !out_value) {
        return DSE_REPLAY_EVAL_INVALID_EXPR;
    }
    GHashTable *memo = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, g_free);
    if (!memo)
        return DSE_REPLAY_EVAL_INVALID_EXPR;
    DseReplayEvalStatus status = dse_eval_expr_observed_impl(ctx, expr, out_value, 0, memo);
    g_hash_table_destroy(memo);
    return status;
}

static void dse_collect_register_byte_alias(DSECtx *ctx, const InsnAux *aux, int rid,
                                            uint32_t natural_width, uint32_t byte_index,
                                            DseRootSet *out) {
    dse_root_set_init(out);
    if (!ctx || !aux || !out || rid < 0 || rid >= REG_COUNT || natural_width == 0 ||
        natural_width > 64 || (natural_width % 8U) != 0 || byte_index >= (natural_width / 8U)) {
        if (out)
            out->complete = false;
        return;
    }
    uint8_t observed_byte = (uint8_t)((aux->reg_vals[rid] >> (8U * byte_index)) & UINT64_C(0xff));
    const SymExpr *current = ctx->state.reg[rid];
    if (current && current->width == natural_width) {
        SymExpr *selected = sym_expr_extract(sym_expr_clone(current), 8U * byte_index, 8);
        if (selected) {
            uint64_t replayed = 0;
            DseReplayEvalStatus status = dse_eval_expr_observed(ctx, selected, &replayed);
            if (status == DSE_REPLAY_EVAL_OK && (uint8_t)replayed == observed_byte &&
                dse_expr_has_var(selected)) {
                DseRootSet current_lineage;
                if (dse_expr_collect_root_lineage(ctx, selected, &current_lineage) &&
                    current_lineage.count != 0) {
                    *out = current_lineage;
                    sym_expr_free(selected);
                    return;
                }
            }
            sym_expr_free(selected);
        }
    }
    uint64_t source_id = REG_VAR_BASE | ((uint64_t)(uint32_t)rid << 8U) | (uint64_t)byte_index;
    /* A sparse slice can omit pointer updates. Without matching modeled data,
     * this is only the identity of an address observation, not a register root
     * binding or evidence of independence from any other input. */
    uint64_t lineage_id = 0;
    if (dse_root_origin_lineage_id(ctx, DSE_VAR_ADDRESS_ROOT, source_id, aux->seq_id, 8,
                                   (uint16_t)byte_index, &lineage_id))
        dse_root_set_add(out, lineage_id);
    out->complete = false;
}

static SymExpr *dse_build_reg_root(DSECtx *ctx, const InsnAux *aux, int rid, uint32_t natural_width,
                                   uint64_t epoch, DseVarKind kind) {
    if (!ctx || !aux || rid < 0 || rid >= REG_COUNT || natural_width == 0 || natural_width > 64 ||
        natural_width % 8 != 0) {
        return NULL;
    }
    if ((aux->reg_value_valid_mask & (1U << rid)) == 0) {
        ctx->register_model_complete = false;
        return NULL;
    }
    SymExpr *base = NULL;
    uint32_t byte_count = natural_width / 8;
    for (uint32_t byte_index = 0; byte_index < byte_count; byte_index++) {
        uint8_t concrete_byte = (uint8_t)((aux->reg_vals[rid] >> (8U * byte_index)) & 0xffU);
        bool tainted = (aux->reg_taint[rid] & (uint8_t)(1U << byte_index)) != 0;
        uint64_t source_id = REG_VAR_BASE | ((uint64_t)(uint32_t)rid << 8) | (uint64_t)byte_index;
        SymExpr *byte = NULL;
        if (!tainted) {
            byte = sym_expr_const(concrete_byte, 8);
        } else if (kind == DSE_VAR_ADDRESS_ROOT) {
            DseRootSet alias_lineage;
            dse_collect_register_byte_alias(ctx, aux, rid, natural_width, byte_index,
                                            &alias_lineage);
            byte = dse_new_observed_epoch_var(ctx, source_id, epoch, epoch, aux->seq_id,
                                              (uint16_t)byte_index, 8, kind, concrete_byte,
                                              &alias_lineage);
        } else {
            byte = dse_new_observed_epoch_var(ctx, source_id, epoch, epoch, aux->seq_id,
                                              (uint16_t)byte_index, 8, kind, concrete_byte, NULL);
        }
        if (!byte) {
            sym_expr_free(base);
            return NULL;
        }
        base = base ? sym_expr_concat(byte, base) : byte;
        if (!base)
            return NULL;
    }
    return base;
}

SymExpr *dse_read_rid_observed_root(DSECtx *ctx, const InsnAux *aux, int rid, uint32_t want_w,
                                    uint32_t natural_width) {
    if (!ctx || !aux || want_w == 0 || want_w > 64) {
        return NULL;
    }
    SymExpr *base =
        dse_build_reg_root(ctx, aux, rid, natural_width, aux->seq_id, DSE_VAR_ADDRESS_ROOT);
    if (!base)
        return NULL;
    if (want_w < natural_width) {
        base = sym_expr_extract(base, 0, want_w);
    } else if (want_w > natural_width) {
        base = sym_expr_zext(base, want_w);
    }
    return base;
}

static uint8_t dse_register_width_byte_mask(uint32_t natural_width) {
    if (natural_width == 0 || natural_width > 64 || natural_width % 8U != 0) {
        return 0;
    }
    uint32_t byte_count = natural_width / 8U;
    return byte_count >= 8U ? UINT8_MAX : (uint8_t)((UINT32_C(1) << byte_count) - UINT32_C(1));
}

static uint8_t dse_preserved_register_byte_mask(uint32_t low_bit, uint32_t width,
                                                uint32_t natural_width) {
    uint8_t natural_mask = dse_register_width_byte_mask(natural_width);
    if (natural_mask == 0 || width == 0 || width > natural_width ||
        low_bit > (natural_width - width)) {
        return 0;
    }
    if ((low_bit % 8U) != 0 || (width % 8U) != 0) {
        return natural_mask;
    }
    uint32_t first_byte = low_bit / 8U;
    uint32_t written_bytes = width / 8U;
    uint8_t written_mask =
        written_bytes >= 8U
            ? UINT8_MAX
            : (uint8_t)(((UINT32_C(1) << written_bytes) - UINT32_C(1)) << first_byte);
    return (uint8_t)(natural_mask & (uint8_t)~written_mask);
}

static SymExpr *dse_normalize_reg_value(DSECtx *ctx, const InsnAux *aux, int rid,
                                        uint32_t natural_width, uint8_t required_byte_mask) {
    if (!ctx || !aux || rid < 0 || rid >= REG_COUNT || natural_width == 0 || natural_width > 64 ||
        natural_width % 8U != 0) {
        return NULL;
    }
    uint8_t natural_mask = dse_register_width_byte_mask(natural_width);
    if (natural_mask == 0)
        return NULL;
    required_byte_mask &= natural_mask;
    if ((aux->reg_value_valid_mask & (UINT32_C(1) << rid)) == 0) {
        ctx->register_model_complete = false;
        dse_record_replay_missing(ctx);
        return NULL;
    }
    SymExpr *current = ctx->state.reg[rid];
    if (current && current->width != natural_width) {
        DSE_DIAGNOSTIC(
            stderr,
            "[DSE-REG-WIDTH-FAIL] pc=0x%lx seq=%lu rid=%d state_width=%u expected_width=%u\n",
            (unsigned long)aux->pc, (unsigned long)aux->seq_id, rid, (unsigned int)current->width,
            (unsigned int)natural_width);
        ctx->register_model_complete = false;
        dse_record_replay_missing(ctx);
        sym_state_set_reg(&ctx->state, (RegId)rid, NULL);
        dse_advance_register_root_epoch(ctx, rid);
        return NULL;
    }

    uint64_t root_epoch = ctx->register_root_epoch[rid];
    if (!current && root_epoch == 0) {
        root_epoch = 1;
        ctx->register_root_epoch[rid] = root_epoch;
    }
    SymExpr *normalized = NULL;
    uint32_t byte_count = natural_width / 8U;
    for (uint32_t byte_index = 0; byte_index < byte_count; byte_index++) {
        uint8_t observed_byte =
            (uint8_t)((aux->reg_vals[rid] >> (8U * byte_index)) & UINT64_C(0xff));
        bool tainted = (aux->reg_taint[rid] & (uint8_t)(UINT8_C(1) << byte_index)) != 0;
        bool required = (required_byte_mask & (uint8_t)(UINT8_C(1) << byte_index)) != 0;
        SymExpr *byte = NULL;
        if (!required || !tainted) {
            byte = sym_expr_const(observed_byte, 8);
        } else if (!current) {
            uint64_t source_id =
                REG_VAR_BASE | ((uint64_t)(uint32_t)rid << 8) | (uint64_t)byte_index;
            byte = dse_new_observed_epoch_var(ctx, source_id, root_epoch, root_epoch, aux->seq_id,
                                              (uint16_t)byte_index, 8, DSE_VAR_REGISTER_ROOT,
                                              observed_byte, NULL);
        } else {
            byte = sym_expr_extract(sym_expr_clone(current), 8U * byte_index, 8);
            if (!byte) {
                sym_expr_free(normalized);
                return NULL;
            }
            DseReplayCheckStatus replay_status = dse_replay_expect(
                ctx, byte, observed_byte, DSE_REPLAY_SITE_REGISTER, (uint64_t)rid, byte_index);
            if (replay_status != DSE_REPLAY_CHECK_OK) {
                uint64_t replayed_value = 0;
                DseReplayEvalStatus eval_status =
                    dse_eval_expr_observed(ctx, byte, &replayed_value);
                DSE_DIAGNOSTIC(
                    stderr,
                    "[DSE-REG-REPLAY-FAIL] pc=0x%lx seq=%lu rid=%d byte=%u tainted=yes expected=0x%02x replayed=0x%02lx eval_status=%u check_status=%u\n",
                    (unsigned long)aux->pc, (unsigned long)aux->seq_id, rid,
                    (unsigned int)byte_index, (unsigned int)observed_byte,
                    (unsigned long)(replayed_value & UINT64_C(0xff)), (unsigned int)eval_status,
                    (unsigned int)replay_status);
                sym_expr_free(byte);
                sym_expr_free(normalized);
                ctx->register_model_complete = false;
                sym_state_set_reg(&ctx->state, (RegId)rid, NULL);
                dse_advance_register_root_epoch(ctx, rid);
                return NULL;
            }
        }
        if (!byte) {
            sym_expr_free(normalized);
            return NULL;
        }
        normalized = normalized ? sym_expr_concat(byte, normalized) : byte;
        if (!normalized)
            return NULL;
    }
    return normalized;
}

//get reg in needed width
SymExpr *dse_read_rid_fit(DSECtx *ctx, const InsnAux *aux, int rid, uint32_t want_w,
                          uint32_t natural_width) {
    if (!ctx || !aux || rid < 0 || rid >= REG_COUNT || want_w == 0 || want_w > 64 ||
        natural_width == 0 || natural_width > 64 || natural_width % 8U != 0) {
        return NULL;
    }
    uint8_t required_byte_mask = dse_register_width_byte_mask(natural_width);
    SymExpr *base = dse_normalize_reg_value(ctx, aux, rid, natural_width, required_byte_mask);
    if (!base)
        return NULL;
    SymExpr *state_value = sym_expr_clone(base);
    if (!state_value) {
        sym_expr_free(base);
        dse_mark_resource_limit(ctx);
        return NULL;
    }
    sym_state_set_reg(&ctx->state, (RegId)rid, state_value);
    if (want_w < natural_width) {
        base = sym_expr_extract(base, 0, want_w);
    } else if (want_w > natural_width) {
        base = sym_expr_zext(base, want_w);
    }
    return base;
}

//create needed slice, for example 0:7 - al
SymExpr *dse_read_rid_slice(DSECtx *ctx, const InsnAux *aux, int rid, uint32_t low_bit,
                            uint32_t width, uint32_t natural_width) {
    if (!ctx || !aux || rid < 0 || rid >= REG_COUNT || width == 0 || natural_width == 0 ||
        natural_width > 64 || (natural_width % 8U) != 0 || width > natural_width ||
        low_bit > natural_width - width) {
        return NULL;
    }
    if ((low_bit % 8U) != 0 || (width % 8U) != 0) {
        return NULL;
    }
    uint8_t natural_byte_mask = dse_register_width_byte_mask(natural_width);
    if (natural_byte_mask == 0)
        return NULL;
    uint32_t first_byte = low_bit / 8U;
    uint32_t byte_count = width / 8U;
    uint8_t required_byte_mask =
        (uint8_t)(((UINT32_C(1) << byte_count) - UINT32_C(1)) << first_byte);
    if (ctx->demand_active) {
        required_byte_mask |= ctx->demand_reg_live_after[rid];
        required_byte_mask &= natural_byte_mask;
    }
    SymExpr *base = dse_normalize_reg_value(ctx, aux, rid, natural_width, required_byte_mask);
    if (!base)
        return NULL;
    SymExpr *state_value = sym_expr_clone(base);
    if (!state_value) {
        sym_expr_free(base);
        dse_mark_resource_limit(ctx);
        return NULL;
    }
    sym_state_set_reg(&ctx->state, (RegId)rid, state_value);
    if (low_bit == 0 && width == natural_width) {
        return base;
    }
    return sym_expr_extract(base, low_bit, width);
}

//write needed part into register with save of high bytes
bool dse_commit_slice(DSECtx *ctx, const InsnAux *aux, int rid, SymExpr *value, uint32_t low_bit,
                      uint32_t width, uint32_t natural_width) {
    if (!ctx || !aux || rid < 0 || rid >= REG_COUNT || !value || width == 0 ||
        width > natural_width || low_bit > natural_width - width) {
        sym_expr_free(value);
        return false;
    }

    if (value->width < width) {
        value = sym_expr_zext(value, width);
    } else if (value->width > width) {
        value = sym_expr_extract(value, 0, width);
    }
    if (!value) {
        return false;
    }
    if (low_bit == 0 && width == natural_width) {
        dse_set_reg(ctx, rid, value, natural_width);
        return true;
    }

    uint8_t preserved_byte_mask = dse_preserved_register_byte_mask(low_bit, width, natural_width);
    if (ctx->demand_active) {
        preserved_byte_mask &= ctx->demand_reg_live_after[rid];
    }
    SymExpr *old_value = dse_normalize_reg_value(ctx, aux, rid, natural_width, preserved_byte_mask);
    if (!old_value) {
        sym_expr_free(value);
        return false;
    }

    uint32_t high_width = natural_width - low_bit - width;
    SymExpr *low = NULL;
    SymExpr *high = NULL;
    if (low_bit != 0) {
        SymExpr *copy = sym_expr_clone(old_value);
        if (!copy) {
            sym_expr_free(old_value);
            sym_expr_free(value);
            return false;
        }
        low = sym_expr_extract(copy, 0, low_bit);
        if (!low) {
            sym_expr_free(old_value);
            sym_expr_free(value);
            return false;
        }
    }

    if (high_width != 0) {
        high = sym_expr_extract(old_value, low_bit + width, high_width);
        if (!high) {
            sym_expr_free(low);
            sym_expr_free(value);
            return false;
        }
    } else {
        sym_expr_free(old_value);
    }

    SymExpr *result = value;
    if (low) {
        result = sym_expr_concat(result, low);
        if (!result) {
            sym_expr_free(high);
            return false;
        }
    }
    if (high) {
        result = sym_expr_concat(high, result);
        if (!result) {
            return false;
        }
    }

    sym_state_set_reg(&ctx->state, rid, result);
    return true;
}

static bool dse_audit_range_contains(uint64_t base, uint32_t size, uint64_t address) {
    if (size == 0 || base > UINT64_MAX - ((uint64_t)size - 1U)) {
        return false;
    }
    return address >= base && address <= base + (uint64_t)size - 1U;
}

static uint64_t dse_audit_string_byte_address(uint64_t first, int8_t direction,
                                              uint8_t element_size, uint32_t event_index,
                                              uint8_t byte_index) {
    return (uint64_t)(uint32_t)((uint32_t)first +
                                (uint32_t)((int64_t)direction * (int64_t)event_index *
                                               (int64_t)element_size +
                                           (int64_t)byte_index));
}

static bool dse_audit_exact_string_write(const InsnAux *aux, uint64_t address, uint32_t *out_event,
                                         uint8_t *out_byte, uint8_t *out_value) {
    if (!aux || !out_event || !out_byte || !out_value) {
        return false;
    }
    bool is_movs = dse_aux_has_exact_movs(aux);
    bool is_stos = dse_aux_has_exact_stos(aux);
    if (!is_movs && !is_stos)
        return false;
    const DseStringSummary *summary = &aux->string_summary;
    for (uint32_t remaining = summary->expected_iterations; remaining != 0; remaining--) {
        uint32_t event = remaining - 1U;
        for (uint8_t byte = 0; byte < summary->element_size; byte++) {
            uint64_t written_address = dse_audit_string_byte_address(
                summary->destination_first, summary->direction, summary->element_size, event, byte);
            if (written_address != address)
                continue;
            if (is_movs) {
                uint64_t captured_index = (uint64_t)event * summary->element_size + byte;
                if (!summary->values || captured_index >= summary->bytes_captured) {
                    return false;
                }
                *out_value = summary->values[captured_index];
            } else {
                *out_value = (uint8_t)((aux->reg_vals[DTA_REG_RAX] >> (8U * byte)) & UINT64_C(0xff));
            }
            *out_event = event;
            *out_byte = byte;
            return true;
        }
    }
    return false;
}

static void dse_audit_last_memory_writer(uint64_t address, uint64_t symbolic_writer_seq,
                                         uint64_t read_seq) {
    if (!g_dse_verbose_diagnostics)
        return;
    if (!g_tb || !g_ring || read_seq == 0 || symbolic_writer_seq >= read_seq) {
        DSE_DIAGNOSTIC(
            stderr,
            "[DSE-LAST-WRITER-AUDIT] addr=0x%lx read_seq=%lu symbolic_writer_seq=%lu status=unavailable\n",
            (unsigned long)address, (unsigned long)read_seq, (unsigned long)symbolic_writer_seq);
        return;
    }
    for (uint32_t back_index = 0; back_index < g_tb->counter; back_index++) {
        const TraceEntry *entry = trace_get_last(g_tb, back_index);
        if (!entry)
            continue;
        if (entry->seq_id >= read_seq)
            continue;
        if (entry->seq_id <= symbolic_writer_seq)
            break;
        const InsnMeta *meta = meta_lookup_id(entry->meta_id);
        const InsnAux *aux = dse_aux_for(g_ring, g_tb, entry);
        if (!aux || !aux->execution_complete) {
            if (meta && meta->has_mem_write) {
                DSE_DIAGNOSTIC(
                    stderr,
                    "[DSE-LAST-WRITER-AUDIT] addr=0x%lx read_seq=%lu symbolic_writer_seq=%lu status=aux-unavailable candidate_pc=0x%lx candidate_seq=%lu\n",
                    (unsigned long)address, (unsigned long)read_seq,
                    (unsigned long)symbolic_writer_seq, (unsigned long)entry->pc,
                    (unsigned long)entry->seq_id);
                return;
            }
            continue;
        }
        if (!aux->has_mem_write)
            continue;
        bool exact_string = dse_aux_has_exact_movs(aux) || dse_aux_has_exact_stos(aux);
        if (exact_string) {
            uint32_t event = 0;
            uint8_t byte = 0;
            uint8_t value = 0;
            if (dse_audit_exact_string_write(aux, address, &event, &byte, &value)) {
                DSE_DIAGNOSTIC(
                    stderr,
                    "[DSE-LAST-WRITER-AUDIT] addr=0x%lx read_seq=%lu symbolic_writer_seq=%lu status=later-writer writer_pc=0x%lx writer_seq=%lu kind=exact-string event=%u byte=%u value=0x%02x\n",
                    (unsigned long)address, (unsigned long)read_seq,
                    (unsigned long)symbolic_writer_seq, (unsigned long)entry->pc,
                    (unsigned long)entry->seq_id, (unsigned int)event, (unsigned int)byte,
                    (unsigned int)value);
                return;
            }
            continue;
        }
        bool range_may_overlap =
            !aux->mem_write_range_valid || aux->mem_write_range_unknown ||
            (address >= aux->mem_write_min_addr && address <= aux->mem_write_max_addr);
        if (!range_may_overlap)
            continue;
        if (aux->mem_write_overflow) {
            DSE_DIAGNOSTIC(
                stderr,
                "[DSE-LAST-WRITER-AUDIT] addr=0x%lx read_seq=%lu symbolic_writer_seq=%lu status=overflow-unresolved writer_pc=0x%lx writer_seq=%lu\n",
                (unsigned long)address, (unsigned long)read_seq, (unsigned long)symbolic_writer_seq,
                (unsigned long)entry->pc, (unsigned long)entry->seq_id);
            return;
        }
        for (uint32_t remaining = aux->mem_write_count; remaining != 0; remaining--) {
            const DseMemWrite *write = &aux->mem_writes[remaining - 1U];
            if (!dse_audit_range_contains(write->addr, write->size, address)) {
                continue;
            }
            uint32_t offset = (uint32_t)(address - write->addr);
            if (!write->value_valid) {
                DSE_DIAGNOSTIC(
                    stderr,
                    "[DSE-LAST-WRITER-AUDIT] addr=0x%lx read_seq=%lu symbolic_writer_seq=%lu status=later-writer-value-unavailable writer_pc=0x%lx writer_seq=%lu access_addr=0x%lx size=%u\n",
                    (unsigned long)address, (unsigned long)read_seq,
                    (unsigned long)symbolic_writer_seq, (unsigned long)entry->pc,
                    (unsigned long)entry->seq_id, (unsigned long)write->addr,
                    (unsigned int)write->size);
                return;
            }
            uint32_t source_byte =
                g_arch && g_arch->big_endian ? (uint32_t)write->size - 1U - offset : offset;
            uint8_t value = (uint8_t)((write->value >> (8U * source_byte)) & UINT64_C(0xff));
            DSE_DIAGNOSTIC(
                stderr,
                "[DSE-LAST-WRITER-AUDIT] addr=0x%lx read_seq=%lu symbolic_writer_seq=%lu status=later-writer writer_pc=0x%lx writer_seq=%lu kind=ordinary access_addr=0x%lx size=%u byte=%u value=0x%02x\n",
                (unsigned long)address, (unsigned long)read_seq, (unsigned long)symbolic_writer_seq,
                (unsigned long)entry->pc, (unsigned long)entry->seq_id, (unsigned long)write->addr,
                (unsigned int)write->size, (unsigned int)offset, (unsigned int)value);
            return;
        }
    }
    DSE_DIAGNOSTIC(
        stderr,
        "[DSE-LAST-WRITER-AUDIT] addr=0x%lx read_seq=%lu symbolic_writer_seq=%lu status=no-later-tracked-writer\n",
        (unsigned long)address, (unsigned long)read_seq, (unsigned long)symbolic_writer_seq);
}

bool dse_load_tracked_byte_at(DSECtx *ctx, uint64_t address, uint64_t epoch, uint8_t observed_value,
                              bool value_tainted, SymExpr **out_symbolic_value) {
    if (out_symbolic_value)
        *out_symbolic_value = NULL;
    if (!ctx || !out_symbolic_value)
        return false;
    if (!value_tainted) {
        SymExpr *constant = sym_expr_const(observed_value, 8);
        if (!constant)
            return false;
        *out_symbolic_value = constant;
        return true;
    }
    if (ctx->state.sym_mem) {
        gint64 key = (gint64)address;
        DseMemCell *cell = g_hash_table_lookup(ctx->state.sym_mem, &key);
        if (cell && cell->expr) {
            SymExpr *value = sym_expr_clone(cell->expr);
            if (!value)
                return false;
            DseReplayCheckStatus replay_status = dse_replay_expect(
                ctx, value, observed_value, DSE_REPLAY_SITE_MEMORY_READ, address, 0);
            if (replay_status != DSE_REPLAY_CHECK_OK) {
                uint64_t replayed_value = 0;
                DseReplayEvalStatus eval_status =
                    dse_eval_expr_observed(ctx, value, &replayed_value);
                DSE_DIAGNOSTIC(
                    stderr,
                    "[DSE-MEM-REPLAY-FAIL] addr=0x%lx read_seq=%lu writer_pc=0x%lx writer_seq=%lu tainted=yes expected=0x%02x replayed=0x%02lx eval_status=%u check_status=%u\n",
                    (unsigned long)address, (unsigned long)epoch, (unsigned long)cell->writer_pc,
                    (unsigned long)cell->writer_seq, (unsigned int)observed_value,
                    (unsigned long)(replayed_value & UINT64_C(0xff)), (unsigned int)eval_status,
                    (unsigned int)replay_status);
                dse_audit_last_memory_writer(address, cell->writer_seq, epoch);
                sym_expr_free(value);
                return false;
            }
            *out_symbolic_value = value;
            return true;
        }
    }
    SymExpr *root = dse_new_observed_epoch_var(ctx, address, epoch, ctx->memory_root_epoch, epoch,
                                               0, 8, DSE_VAR_MEMORY_ROOT, observed_value, NULL);
    if (!root)
        return false;
    *out_symbolic_value = root;
    return true;
}

bool dse_store_tracked_byte_at(DSECtx *ctx, uint64_t address, SymExpr *symbolic_value,
                               const InsnAux *writer_aux, uint8_t observed_value) {
    if (!ctx) {
        sym_expr_free(symbolic_value);
        return false;
    }
    if (!symbolic_value || symbolic_value->width != 8) {
        sym_expr_free(symbolic_value);
        ctx->memory_model_complete = false;
        return false;
    }
    DseReplayCheckStatus replay_status = dse_replay_expect(
        ctx, symbolic_value, observed_value, DSE_REPLAY_SITE_MEMORY_WRITE, address, 0);
    if (replay_status != DSE_REPLAY_CHECK_OK) {
        uint64_t replayed_value = 0;
        DseReplayEvalStatus eval_status =
            dse_eval_expr_observed(ctx, symbolic_value, &replayed_value);
        DSE_DIAGNOSTIC(
            stderr,
            "[DSE-MEM-WRITE-REPLAY-FAIL] pc=0x%lx seq=%lu addr=0x%lx expected=0x%02x replayed=0x%02lx eval_status=%u check_status=%u\n",
            (unsigned long)(writer_aux ? writer_aux->pc : 0),
            (unsigned long)(writer_aux ? writer_aux->seq_id : 0), (unsigned long)address,
            (unsigned int)observed_value, (unsigned long)(replayed_value & UINT64_C(0xff)),
            (unsigned int)eval_status, (unsigned int)replay_status);
        sym_expr_free(symbolic_value);
        return false;
    }
    if (!dse_ensure_sym_mem(ctx)) {
        sym_expr_free(symbolic_value);
        return false;
    }

    gint64 *key = g_try_new(gint64, 1);
    DseMemCell *cell = g_try_new0(DseMemCell, 1);
    if (!key || !cell) {
        g_free(key);
        g_free(cell);
        sym_expr_free(symbolic_value);
        dse_mark_resource_limit(ctx);
        return false;
    }
    *key = (gint64)address;
    cell->expr = symbolic_value;
    cell->writer_seq = writer_aux ? writer_aux->seq_id : 0;
    cell->writer_pc = writer_aux ? writer_aux->pc : 0;
    g_hash_table_replace(ctx->state.sym_mem, key, cell);
    return true;
}

bool dse_memory_write_byte_required(const DSECtx *ctx, uint64_t address) {
    if (!ctx || !ctx->demand_active)
        return true;
    if (ctx->demand_all_memory_writes)
        return true;
    if (!ctx->demand_memory_writes || ctx->demand_seq_id == 0) {
        return false;
    }
    DseDemandMemKey key = {.seq_id = ctx->demand_seq_id, .address = address};
    return g_hash_table_contains((GHashTable *)ctx->demand_memory_writes, &key);
}

//from mem to symbolic
SymExpr *dse_load_mem(DSECtx *ctx, const InsnAux *aux, uint32_t width_bits, bool big_endian) {
    if (!ctx || !aux || width_bits == 0 || !aux->has_mem_read || !aux->mem_read_value_valid) {
        return NULL;
    }
    uint64_t base_address = aux->mem_read_addr;
    uint32_t byte_count = width_bits / 8U;
    if (byte_count == 0)
        byte_count = 1;
    if (byte_count > 8)
        byte_count = 8;
    SymExpr *result = NULL;
    for (uint32_t byte_index = 0; byte_index < byte_count; byte_index++) {
        bool tainted = ((aux->mem_read_taint >> byte_index) & 1U) != 0;
        uint8_t observed_value =
            (uint8_t)((aux->mem_read_val >> (8U * byte_index)) & UINT64_C(0xff));
        uint64_t byte_address =
            big_endian ? base_address + (byte_count - 1U - byte_index) : base_address + byte_index;
        SymExpr *byte = NULL;
        if (!dse_load_tracked_byte_at(ctx, byte_address, aux->seq_id, observed_value, tainted,
                                      &byte)) {
            sym_expr_free(result);
            return NULL;
        }
        if (!result) {
            result = byte;
        } else {
            result = sym_expr_concat(byte, result);
            if (!result)
                return NULL;
        }
    }
    return result;
}

//store from mem
bool dse_store_mem(DSECtx *ctx, const InsnAux *aux, SymExpr *val, bool big_endian) {
    if (!ctx || !aux) {
        sym_expr_free(val);
        return false;
    }
    if (!aux->has_mem_write || !val || aux->mem_write_overflow || aux->mem_write_count != 1 ||
        aux->mem_write_total != 1) {
        sym_expr_free(val);
        ctx->memory_model_complete = false;
        return false;
    }
    uint32_t nbytes = val->width / 8U;
    if (nbytes == 0)
        nbytes = 1;
    if (nbytes > 8)
        nbytes = 8;
    const DseMemWrite *write = &aux->mem_writes[0];
    if (!write->value_valid || write->addr != aux->mem_write_addr || write->size != nbytes ||
        aux->mem_write_size != nbytes) {
        DSE_DIAGNOSTIC(
            stderr,
            "[DSE-MEM-WRITE-META-FAIL] pc=0x%lx seq=%lu value_valid=%s recorded_addr=0x%lx primary_addr=0x%lx recorded_size=%u expected_size=%u\n",
            (unsigned long)aux->pc, (unsigned long)aux->seq_id, write->value_valid ? "yes" : "no",
            (unsigned long)write->addr, (unsigned long)aux->mem_write_addr,
            (unsigned int)write->size, (unsigned int)nbytes);
        sym_expr_free(val);
        ctx->memory_model_complete = false;
        return false;
    }

    uint64_t base = write->addr;
    for (uint32_t i = 0; i < nbytes; i++) {
        if (!dse_memory_write_byte_required(ctx, base + i))
            continue;
        uint32_t source_byte = big_endian ? (nbytes - 1U - i) : i;
        SymExpr *byte = sym_expr_extract(sym_expr_clone(val), 8U * source_byte, 8);
        uint32_t observed_shift = big_endian ? 8U * (nbytes - 1U - i) : 8U * i;
        uint8_t observed_byte = (uint8_t)((write->value >> observed_shift) & UINT64_C(0xff));
        if (!byte || !dse_store_tracked_byte_at(ctx, base + i, byte, aux, observed_byte)) {
            sym_expr_free(val);
            return false;
        }
    }
    sym_expr_free(val);
    return true;
}

void dse_set_reg(DSECtx *ctx, int rid, SymExpr *val, uint32_t natural_width) {
    if (!ctx || rid < 0 || rid >= REG_COUNT || natural_width == 0 || natural_width > 64) {
        sym_expr_free(val);
        return;
    }
    if (val) {
        if (val->width < natural_width) {
            val = sym_expr_zext(val, natural_width);
        } else if (val->width > natural_width) {
            val = sym_expr_extract(val, 0, natural_width);
        }
    }
    sym_state_set_reg(&ctx->state, (RegId)rid, val);
}

//part write
void dse_commit_low(DSECtx *ctx, const InsnAux *aux, int rid, SymExpr *val, uint32_t w,
                    uint32_t natw) {
    if (!ctx || !aux || rid < 0 || rid >= REG_COUNT || w == 0 || w >= natw) {
        sym_expr_free(val);
        return;
    }
    SymExpr *old;
    if (ctx->state.reg[rid]) {
        old = sym_expr_clone(ctx->state.reg[rid]);
    } else {
        old = sym_expr_const(aux->reg_vals[rid], natw);
    }
    SymExpr *hi = sym_expr_extract(old, w, natw - w);
    sym_state_set_reg(&ctx->state, rid, sym_expr_concat(hi, val));
}

const char *dse_solver_status_name(DseSolverStatus status) {
    switch (status) {
    case DSE_SOLVER_NOT_RUN:
        return "NOT_RUN";
    case DSE_SOLVER_SAT:
        return "SAT";
    case DSE_SOLVER_UNSAT:
        return "UNSAT";
    case DSE_SOLVER_UNKNOWN:
        return "UNKNOWN";
    }
    return "UNKNOWN";
}

const char *dse_evidence_name(DseEvidence evidence) {
    switch (evidence) {
    case DSE_EVIDENCE_NONE:
        return "NONE";
    case DSE_EVIDENCE_REPLAY_OK:
        return "REPLAY_OK";
    case DSE_EVIDENCE_SAT_NONUNIQUE:
        return "SAT_NONUNIQUE";
    case DSE_EVIDENCE_UNIQUE_ON_SLICE:
        return "UNIQUE_ON_SLICE";
    }
    return "NONE";
}

const char *dse_verdict_name(DseVerdict verdict) {
    switch (verdict) {
    case DSE_VERDICT_UNKNOWN:
        return "UNKNOWN";
    case DSE_VERDICT_CONFIRMED:
        return "CONFIRMED";
    case DSE_VERDICT_REFUTED:
        return "REFUTED";
    }
    return "UNKNOWN";
}

const char *dse_verify_reason_name(DseVerifyReason reason) {
    switch (reason) {
    case DSE_REASON_NONE:
        return "NONE";
    case DSE_REASON_INVALID_INPUT:
        return "INVALID_INPUT";
    case DSE_REASON_NO_SLICE:
        return "NO_SLICE";
    case DSE_REASON_SLICE_TRUNCATED:
        return "SLICE_TRUNCATED";
    case DSE_REASON_META_MISSING:
        return "META_MISSING";
    case DSE_REASON_AUX_MISSING:
        return "AUX_MISSING";
    case DSE_REASON_UNSUPPORTED_INSN:
        return "UNSUPPORTED_INSN";
    case DSE_REASON_TARGET_UNAVAILABLE:
        return "TARGET_UNAVAILABLE";
    case DSE_REASON_CONTEXT_INIT_FAILED:
        return "CONTEXT_INIT_FAILED";
    case DSE_REASON_SOLVER_UNKNOWN:
        return "SOLVER_UNKNOWN";
    case DSE_REASON_NONUNIQUE_TARGET:
        return "NONUNIQUE_TARGET";
    case DSE_REASON_MODEL_INCOMPLETE:
        return "MODEL_INCOMPLETE";
    case DSE_REASON_TRIGGER_MISSING:
        return "TRIGGER_MISSING";
    case DSE_REASON_UNRESOLVED_DEPENDENCY:
        return "UNRESOLVED_DEPENDENCY";
    case DSE_REASON_SYMBOLIC_ADDRESS:
        return "SYMBOLIC_ADDRESS";
    case DSE_REASON_MEM_ACCESS_UNMODELED:
        return "MEM_ACCESS_UNMODELED";
    case DSE_REASON_RESOURCE_LIMIT:
        return "RESOURCE_LIMIT";
    case DSE_REASON_CONCRETE_REPLAY:
        return "CONCRETE_REPLAY";
    case DSE_REASON_REPLAY_MISMATCH:
        return "REPLAY_MISMATCH";
    case DSE_REASON_PATH_MODEL_INCOMPLETE:
        return "PATH_MODEL_INCOMPLETE";
    }
    return "MODEL_INCOMPLETE";
}

static DseVerifyResult dse_unknown_result(DseVerifyReason reason) {
    DseVerifyResult result;
    memset(&result, 0, sizeof(result));
    result.verdict = DSE_VERDICT_UNKNOWN;
    result.evidence = DSE_EVIDENCE_NONE;
    result.reason = reason;
    result.candidate_query = DSE_SOLVER_NOT_RUN;
    result.alternative_query = DSE_SOLVER_NOT_RUN;
    return result;
}

static void dse_capture_verify_metrics(DseVerifyResult *result, const DSECtx *ctx,
                                       uint32_t slice_len, uint32_t meta_missing) {
    if (!result)
        return;
    result->slice_len = slice_len;
    result->lifted_total = dse_lift_total_count();
    result->concretized = dse_lift_concretized_count();
    result->aux_miss = dse_lift_aux_miss_count();
    result->unsupported = dse_lift_unsupported_count();
    result->meta_missing = meta_missing;
    if (ctx) {
        result->first_replay_mismatch = ctx->first_replay_mismatch;
        result->replay_checks = ctx->replay_checks;
        result->replay_failures = ctx->replay_failures;
        result->replay_missing_bindings = ctx->replay_missing_bindings;
        result->address_constraints = ctx->address_constraints;
        result->address_failures = ctx->address_failures;
        result->path_constraints = ctx->path_constraints;
        result->path_failures = ctx->path_failures;
        result->string_summaries = ctx->string_summaries;
        result->expr_nodes_created = ctx->expr_nodes_created;
        result->z3_cache_nodes = ctx->z3_cache_nodes;
        result->resource_limit_hit = ctx->resource_limit_hit;
        result->memory_model_complete = ctx->memory_model_complete;
        result->register_model_complete = ctx->register_model_complete;
        result->address_model_complete = ctx->address_model_complete;
        result->path_model_complete = ctx->path_model_complete;
    }
#if !DSE_PATH_MODEL_IMPLEMENTED
    result->path_model_complete = false;
#endif
    result->lift_complete =
        (result->meta_missing == 0 && result->aux_miss == 0 && result->unsupported == 0 &&
         result->concretized == 0 && !result->resource_limit_hit &&
         result->register_model_complete && result->memory_model_complete &&
         result->address_model_complete && result->path_model_complete);
    result->proof_eligible = result->data_slice_complete && result->lift_complete && ctx &&
                             ctx->replay_model_complete && !ctx->replay_mismatch;
}

DseSolverStatus dse_check_target_relation(DSECtx *ctx, SymExpr *target_expr, uint64_t oep_candidate,
                                          bool equal) {
    if (!ctx || !ctx->has_solver || !target_expr || ctx->resource_limit_hit ||
        !ctx->replay_model_complete || ctx->replay_mismatch) {
        return DSE_SOLVER_UNKNOWN;
    }
    Z3_context z3 = ctx->z3_ctx;
    Z3_ast target = sym_expr_to_z3(ctx, target_expr);
    if (!target) {
        return DSE_SOLVER_UNKNOWN;
    }
    Z3_sort sort = Z3_mk_bv_sort(z3, target_expr->width);
    Z3_ast candidate = Z3_mk_unsigned_int64(z3, mask_w(oep_candidate, target_expr->width), sort);
    if (!candidate) {
        Z3_dec_ref(z3, target);
        return DSE_SOLVER_UNKNOWN;
    }
    Z3_inc_ref(z3, candidate);
    Z3_ast equality = Z3_mk_eq(z3, target, candidate);
    if (!equality) {
        Z3_dec_ref(z3, candidate);
        Z3_dec_ref(z3, target);
        return DSE_SOLVER_UNKNOWN;
    }
    Z3_inc_ref(z3, equality);
    Z3_ast relation = equality;
    if (!equal) {
        relation = Z3_mk_not(z3, equality);
        if (!relation) {
            Z3_dec_ref(z3, equality);
            Z3_dec_ref(z3, candidate);
            Z3_dec_ref(z3, target);
            return DSE_SOLVER_UNKNOWN;
        }
        Z3_inc_ref(z3, relation);
    }
    Z3_solver_push(z3, ctx->z3_solver);
    Z3_solver_assert(z3, ctx->z3_solver, ctx->path_predicate);
    Z3_solver_assert(z3, ctx->z3_solver, relation);
    Z3_lbool solver_result = Z3_solver_check(z3, ctx->z3_solver);
    Z3_solver_pop(z3, ctx->z3_solver, 1);
    if (!equal) {
        Z3_dec_ref(z3, relation);
    }
    Z3_dec_ref(z3, equality);
    Z3_dec_ref(z3, candidate);
    Z3_dec_ref(z3, target);
    if (solver_result == Z3_L_TRUE) {
        return DSE_SOLVER_SAT;
    }
    if (solver_result == Z3_L_FALSE) {
        return DSE_SOLVER_UNSAT;
    }
    return DSE_SOLVER_UNKNOWN;
}

static void dse_capture_relevance_metrics(DseVerifyResult *result,
                                          const DseRelevanceStats *relevance) {
    if (!result || !relevance)
        return;
    result->relevance_events_considered = relevance->events_considered;
    result->relevance_events_relevant = relevance->events_relevant;
    result->relevance_events_unknown = relevance->events_unknown;
    result->relevance_events_irrelevant = relevance->events_irrelevant;
    result->relevance_iterations = relevance->iterations;
    result->relevance_applied = relevance->applied;
    result->relevance_complete = relevance->complete;
}

static DseVerifyReason dse_replay_failure_reason(const DSECtx *ctx) {
    if (!ctx)
        return DSE_REASON_MODEL_INCOMPLETE;
    if (ctx->replay_mismatch)
        return DSE_REASON_REPLAY_MISMATCH;
    if (!ctx->replay_model_complete)
        return DSE_REASON_MODEL_INCOMPLETE;
    return DSE_REASON_NONE;
}

static bool dse_replay_target(DSECtx *ctx, const SymExpr *target, uint64_t oep_candidate,
                              DseVerifyResult *result) {
    if (!ctx || !target || !result) {
        return false;
    }
    result->target_symbolic = dse_expr_has_var(target);
    DseReplayCheckStatus status =
        dse_replay_expect(ctx, target, oep_candidate, DSE_REPLAY_SITE_TARGET, oep_candidate, 0);
    result->replay_valid =
        status == DSE_REPLAY_CHECK_OK && ctx->replay_model_complete && !ctx->replay_mismatch;
    if (!result->replay_valid) {
        result->reason = dse_replay_failure_reason(ctx);
        if (result->reason == DSE_REASON_NONE) {
            result->reason = DSE_REASON_MODEL_INCOMPLETE;
        }
    }
    return result->replay_valid;
}

static void dse_classify_target(DSECtx *ctx, SymExpr *target, uint64_t oep_candidate,
                                DseVerifyResult *result) {
    if (!ctx || !target || !result) {
        return;
    }
    if (!result->replay_valid) {
        result->reason = dse_replay_failure_reason(ctx);
        if (result->reason == DSE_REASON_NONE) {
            result->reason = DSE_REASON_MODEL_INCOMPLETE;
        }
        return;
    }
    if (!result->target_symbolic) {
        result->evidence = DSE_EVIDENCE_REPLAY_OK;
        result->reason = DSE_REASON_CONCRETE_REPLAY;
        return;
    }
    if (!result->proof_eligible) {
        result->reason = !result->path_model_complete ? DSE_REASON_PATH_MODEL_INCOMPLETE
                                                      : DSE_REASON_MODEL_INCOMPLETE;
        return;
    }
    // P(path) AND target == candidate
    result->candidate_query = dse_check_target_relation(ctx, target, oep_candidate, true);
    if (result->candidate_query == DSE_SOLVER_UNKNOWN) {
        result->reason =
            ctx->resource_limit_hit ? DSE_REASON_RESOURCE_LIMIT : DSE_REASON_SOLVER_UNKNOWN;
        return;
    }
    if (result->candidate_query == DSE_SOLVER_UNSAT) {
        result->verdict = DSE_VERDICT_REFUTED;
        result->reason = DSE_REASON_NONE;
        return;
    }
    // P(path) AND target != candidate
    result->alternative_query = dse_check_target_relation(ctx, target, oep_candidate, false);
    if (result->alternative_query == DSE_SOLVER_UNKNOWN) {
        result->reason =
            ctx->resource_limit_hit ? DSE_REASON_RESOURCE_LIMIT : DSE_REASON_SOLVER_UNKNOWN;
        return;
    }
    if (result->alternative_query == DSE_SOLVER_SAT) {
        result->evidence = DSE_EVIDENCE_SAT_NONUNIQUE;
        result->reason = DSE_REASON_NONUNIQUE_TARGET;
        return;
    }
    // target == candidate SAT and target != candidate UNSAT
    result->evidence = DSE_EVIDENCE_UNIQUE_ON_SLICE;
    result->verdict = DSE_VERDICT_CONFIRMED;
    result->reason = DSE_REASON_NONE;
}

static DseSolverStatus dse_check_path_predicate(DSECtx *ctx) {
    if (!ctx || !ctx->has_solver || !ctx->z3_ctx || !ctx->z3_solver || !ctx->path_predicate ||
        !ctx->replay_model_complete || ctx->replay_mismatch) {
        return DSE_SOLVER_UNKNOWN;
    }
    Z3_solver_push(ctx->z3_ctx, ctx->z3_solver);
    Z3_solver_assert(ctx->z3_ctx, ctx->z3_solver, ctx->path_predicate);
    Z3_lbool status = Z3_solver_check(ctx->z3_ctx, ctx->z3_solver);
    Z3_solver_pop(ctx->z3_ctx, ctx->z3_solver, 1);
    if (status == Z3_L_TRUE) {
        return DSE_SOLVER_SAT;
    }
    if (status == Z3_L_FALSE) {
        return DSE_SOLVER_UNSAT;
    }
    return DSE_SOLVER_UNKNOWN;
}

static DseVerifyReason dse_lift_failure_reason(DSECtx *ctx, const DseVerifyResult *result) {
    if (!ctx || !result) {
        return DSE_REASON_MODEL_INCOMPLETE;
    }
    DseVerifyReason replay_failure = dse_replay_failure_reason(ctx);
    if (replay_failure != DSE_REASON_NONE) {
        return replay_failure;
    }
    if (ctx->resource_limit_hit || result->resource_limit_hit) {
        return DSE_REASON_RESOURCE_LIMIT;
    }
    if (result->meta_missing != 0) {
        return DSE_REASON_META_MISSING;
    }
    if (result->aux_miss != 0) {
        return DSE_REASON_AUX_MISSING;
    }
    if (result->unsupported != 0) {
        return DSE_REASON_UNSUPPORTED_INSN;
    }
    if (!ctx->memory_model_complete) {
        return DSE_REASON_MEM_ACCESS_UNMODELED;
    }
    if (!ctx->register_model_complete) {
        return DSE_REASON_MODEL_INCOMPLETE;
    }
    if (!ctx->address_model_complete || result->address_failures != 0) {
        return DSE_REASON_SYMBOLIC_ADDRESS;
    }
    if (!ctx->path_model_complete || result->path_failures != 0) {
        return DSE_REASON_PATH_MODEL_INCOMPLETE;
    }
    if (result->concretized != 0) {
        return DSE_REASON_MODEL_INCOMPLETE;
    }

    DseSolverStatus path_status = dse_check_path_predicate(ctx);
    if (path_status == DSE_SOLVER_UNKNOWN) {
        return DSE_REASON_SOLVER_UNKNOWN;
    }
    if (path_status == DSE_SOLVER_UNSAT) {
        return DSE_REASON_MODEL_INCOMPLETE;
    }
    return DSE_REASON_NONE;
}

static DseSliceResult dse_slice_result(DseSliceStatus status) {
    DseSliceResult result;
    memset(&result, 0, sizeof(result));
    result.status = status;
    return result;
}

static gpointer dse_relevance_encode(DcfgRelevance relevance) {
    return GUINT_TO_POINTER((guint)relevance + 1U);
}

static DcfgRelevance dse_relevance_decode(gpointer encoded) {
    if (!encoded)
        return DCFG_RELEVANCE_UNKNOWN;
    guint value = GPOINTER_TO_UINT(encoded);
    if (value == 0 || value > (guint)DCFG_RELEVANCE_UNKNOWN + 1U) {
        return DCFG_RELEVANCE_UNKNOWN;
    }
    return (DcfgRelevance)(value - 1U);
}

static bool dse_relevance_store(DseRelevanceSelection *selection, uint64_t seq_id,
                                DcfgRelevance relevance) {
    if (!selection || !selection->by_seq_id || seq_id == 0) {
        return false;
    }
    gint64 lookup = (gint64)seq_id;
    gint64 *stored = g_try_new(gint64, 1);
    if (!stored)
        return false;
    *stored = lookup;
    g_hash_table_replace(selection->by_seq_id, stored, dse_relevance_encode(relevance));
    return true;
}

static bool dse_relevance_lookup(const DseRelevanceSelection *selection, uint64_t seq_id,
                                 DcfgRelevance *out_relevance) {
    if (out_relevance) {
        *out_relevance = DCFG_RELEVANCE_UNKNOWN;
    }
    if (!selection || !selection->by_seq_id || seq_id == 0) {
        return false;
    }
    gint64 lookup = (gint64)seq_id;
    gpointer encoded = g_hash_table_lookup(selection->by_seq_id, &lookup);
    if (!encoded)
        return false;
    if (out_relevance) {
        *out_relevance = dse_relevance_decode(encoded);
    }
    return true;
}

static DcfgRelevance dse_relevance_combine(DcfgRelevance edge_relevance,
                                           DcfgRelevance event_relevance) {
    if (event_relevance == DCFG_RELEVANCE_RELEVANT) {
        return edge_relevance == DCFG_RELEVANCE_IRRELEVANT ? DCFG_RELEVANCE_UNKNOWN
                                                           : DCFG_RELEVANCE_RELEVANT;
    }
    if (event_relevance == DCFG_RELEVANCE_IRRELEVANT) {
        return DCFG_RELEVANCE_IRRELEVANT;
    }
    return DCFG_RELEVANCE_UNKNOWN;
}

static DcfgRelevance dse_classify_branch_event(const DseRelevanceContext *relevance,
                                               const BranchEvent *event,
                                               ProvLabelId accumulated_label) {
    if (!relevance || !relevance->registry || !relevance->dcfg || !event ||
        event->branch_seq_id == 0 ||
        !prov_label_is_valid(relevance->registry, event->condition_label) ||
        !prov_label_is_valid(relevance->registry, accumulated_label)) {
        return DCFG_RELEVANCE_UNKNOWN;
    }

    DcfgRelevance edge_relevance =
        dcfg_edge_data_relevance(relevance->dcfg, event->dcfg_edge_id, accumulated_label);
    DcfgRelevance event_relevance =
        dcfg_labels_data_relevance(relevance->dcfg, event->condition_label, accumulated_label);
    return dse_relevance_combine(edge_relevance, event_relevance);
}

static void dse_relevance_count_states(DseRelevanceSelection *selection) {
    if (!selection || !selection->by_seq_id) {
        return;
    }
    selection->stats.events_considered = 0;
    selection->stats.events_relevant = 0;
    selection->stats.events_unknown = 0;
    selection->stats.events_irrelevant = 0;

    GHashTableIter iterator;
    gpointer value = NULL;
    g_hash_table_iter_init(&iterator, selection->by_seq_id);
    while (g_hash_table_iter_next(&iterator, NULL, &value)) {
        selection->stats.events_considered++;
        switch (dse_relevance_decode(value)) {
        case DCFG_RELEVANCE_RELEVANT:
            selection->stats.events_relevant++;
            break;
        case DCFG_RELEVANCE_IRRELEVANT:
            selection->stats.events_irrelevant++;
            break;
        case DCFG_RELEVANCE_UNKNOWN:
        default:
            selection->stats.events_unknown++;
            selection->stats.complete = false;
            break;
        }
    }
}

static DseRelevanceSelection *dse_relevance_selection_create(const TraceBuffer *tb,
                                                             uint64_t trigger_seq_id,
                                                             const DseRelevanceContext *relevance) {
    if (!relevance)
        return NULL;
    DseRelevanceSelection *selection = g_try_new0(DseRelevanceSelection, 1);
    if (!selection)
        return NULL;
    selection->by_seq_id = g_hash_table_new_full(g_int64_hash, g_int64_equal, g_free, NULL);
    if (!selection->by_seq_id) {
        g_free(selection);
        return NULL;
    }
    selection->stats.applied = true;
    selection->stats.complete = true;
    selection->stats.accumulated_label = PROV_LABEL_ID_INVALID;
    uint32_t trigger_back_index = 0;
    const TraceEntry *trigger = trace_find_seq(tb, trigger_seq_id, &trigger_back_index);
    bool context_valid =
        trigger && relevance->registry && relevance->dcfg && relevance->branch_events;
    ProvLabelId accumulated_label = PROV_LABEL_ID_INVALID;
    if (context_valid && trigger->control_transfer_valid &&
        prov_label_is_valid(relevance->registry, trigger->target_label)) {
        accumulated_label = trigger->target_label;
    } else if (relevance->registry) {
        accumulated_label = prov_label_unknown(relevance->registry);
        selection->stats.complete = false;
    }
    selection->stats.accumulated_label = accumulated_label;
    GArray *events = g_array_new(FALSE, FALSE, sizeof(BranchEvent));
    if (!events) {
        g_hash_table_destroy(selection->by_seq_id);
        g_free(selection);
        return NULL;
    }
    if (context_valid) {
        const BranchEventBuffer *buffer = relevance->branch_events;
        const TraceEntry *oldest = tb->counter != 0 ? trace_get_last(tb, tb->counter - 1U) : NULL;
        uint64_t oldest_seq_id = oldest ? oldest->seq_id : trigger_seq_id;
        for (uint32_t i = 0; i < buffer->counter; i++) {
            const BranchEvent *event = branch_event_get_last(buffer, i);
            if (!event || event->branch_seq_id < oldest_seq_id ||
                event->branch_seq_id >= trigger_seq_id ||
                event->vcpu_index != trigger->vcpu_index) {
                continue;
            }
            g_array_append_val(events, *event);
            if (!dse_relevance_store(selection, event->branch_seq_id, DCFG_RELEVANCE_IRRELEVANT)) {
                selection->stats.complete = false;
            }
        }
    }
    uint64_t requested_iterations = (uint64_t)events->len + 1U;
    uint32_t maximum_iterations = requested_iterations > (uint64_t)DSE_MAX_RELEVANCE_ITERATIONS
                                      ? DSE_MAX_RELEVANCE_ITERATIONS
                                      : (uint32_t)requested_iterations;
    bool converged = !context_valid || events->len == 0;
    for (uint32_t iteration = 0; iteration < maximum_iterations && context_valid; iteration++) {
        bool changed = false;
        selection->stats.iterations = iteration + 1U;
        for (guint i = 0; i < events->len; i++) {
            const BranchEvent *event = &g_array_index(events, BranchEvent, i);
            DcfgRelevance current = DCFG_RELEVANCE_IRRELEVANT;
            (void)dse_relevance_lookup(selection, event->branch_seq_id, &current);
            DcfgRelevance classified =
                dse_classify_branch_event(relevance, event, accumulated_label);
            bool newly_selected =
                current == DCFG_RELEVANCE_IRRELEVANT && classified != DCFG_RELEVANCE_IRRELEVANT;

            if (!newly_selected)
                continue;
            if (!dse_relevance_store(selection, event->branch_seq_id, classified)) {
                selection->stats.complete = false;
                continue;
            }
            changed = true;
            if (prov_label_is_valid(relevance->registry, event->condition_label)) {
                ProvLabelId joined =
                    prov_label_join(relevance->registry, accumulated_label, event->condition_label);
                if (joined != PROV_LABEL_ID_INVALID) {
                    accumulated_label = joined;
                } else {
                    selection->stats.complete = false;
                }
            } else {
                selection->stats.complete = false;
            }
        }
        selection->stats.accumulated_label = accumulated_label;
        if (!changed) {
            converged = true;
            break;
        }
    }
    if (context_valid && !converged) {
        bool unresolved = false;
        for (guint i = 0; i < events->len; i++) {
            const BranchEvent *event = &g_array_index(events, BranchEvent, i);
            DcfgRelevance current = DCFG_RELEVANCE_UNKNOWN;
            if (!dse_relevance_lookup(selection, event->branch_seq_id, &current) ||
                current != DCFG_RELEVANCE_IRRELEVANT) {
                continue;
            }
            unresolved = true;
            if (!dse_relevance_store(selection, event->branch_seq_id, DCFG_RELEVANCE_UNKNOWN)) {
                selection->stats.complete = false;
            }
        }
        if (unresolved) {
            selection->stats.complete = false;
        }
    }

    if (trigger) {
        for (uint32_t i = trigger_back_index + 1U; i < tb->counter; i++) {
            const TraceEntry *entry = trace_get_last(tb, i);
            if (!entry || entry->vcpu_index != trigger->vcpu_index) {
                continue;
            }
            DcfgRelevance ignored;
            if (dse_relevance_lookup(selection, entry->seq_id, &ignored)) {
                continue;
            }
            const InsnMeta *meta = meta_lookup_id(entry->meta_id);
            if (!meta || !meta->is_conditional_branch) {
                continue;
            }
            (void)dse_relevance_store(selection, entry->seq_id, DCFG_RELEVANCE_UNKNOWN);
            selection->stats.complete = false;
        }
    }
    dse_relevance_count_states(selection);
    g_array_unref(events);
    return selection;
}

static void dse_relevance_selection_destroy(DseRelevanceSelection *selection) {
    if (!selection)
        return;
    if (selection->by_seq_id) {
        g_hash_table_destroy(selection->by_seq_id);
    }
    g_free(selection);
}

static DcfgRelevance dse_relevance_selection_get(const DseRelevanceSelection *selection,
                                                 uint64_t seq_id) {
    if (!selection) {
        return DCFG_RELEVANCE_RELEVANT;
    }
    DcfgRelevance relevance = DCFG_RELEVANCE_UNKNOWN;
    (void)dse_relevance_lookup(selection, seq_id, &relevance);
    return relevance;
}

bool dse_analyze_branch_relevance(const TraceBuffer *tb, uint64_t trigger_seq_id,
                                  const DseRelevanceContext *relevance,
                                  DseRelevanceStats *out_stats) {
    if (out_stats) {
        memset(out_stats, 0, sizeof(*out_stats));
    }
    if (!tb || trigger_seq_id == 0 || !relevance || !out_stats) {
        return false;
    }
    DseRelevanceSelection *selection =
        dse_relevance_selection_create(tb, trigger_seq_id, relevance);
    if (!selection)
        return false;
    *out_stats = selection->stats;
    dse_relevance_selection_destroy(selection);
    return true;
}

static uint8_t dse_byte_mask(uint32_t byte_count) {
    if (byte_count == 0 || byte_count > MAX_REG_BYTES)
        return 0;
    if (byte_count == MAX_REG_BYTES)
        return UINT8_MAX;
    return (uint8_t)((1U << byte_count) - 1U);
}

static uint8_t dse_natural_reg_mask(void) {
    if (!g_arch || g_arch->natural_width == 0 || g_arch->natural_width % 8 != 0) {
        return 0;
    }
    return dse_byte_mask(g_arch->natural_width / 8);
}

static bool dse_reg_worklist_empty(const uint8_t needed[REG_COUNT]) {
    for (int reg = 0; reg < REG_COUNT; reg++) {
        if (needed[reg] != 0)
            return false;
    }
    return true;
}

static void dse_copy_reg_worklist(uint8_t destination[REG_COUNT], const uint8_t source[REG_COUNT]) {
    memcpy(destination, source, REG_COUNT * sizeof(source[0]));
}

static void dse_entry_deps(const TraceBuffer *tb, const DseAuxRing *ring, const TraceEntry *entry,
                           const InsnMeta *meta, const InsnAux *aux, TraceDeps *out) {
    InsnOccurrence occurrence;
    bool have_occurrence = dse_aux_materialize_occurrence(ring, tb, entry, &occurrence);
    (void)trace_deps_x86_build(entry, trace_insn_desc_get(tb, entry->insn_desc_id), meta, aux,
                               have_occurrence ? &occurrence : NULL, g_arch->natural_width, out);
}

static bool dse_deps_writes_needed(const TraceDeps *deps, const uint8_t needed[REG_COUNT]) {
    for (int reg = 0; reg < REG_COUNT; reg++) {
        if (trace_deps_bytes(deps->may_write[reg], false) & needed[reg])
            return true;
    }
    return false;
}

static void dse_consume_deps_writes(const TraceDeps *deps, uint8_t needed[REG_COUNT]) {
    for (int reg = 0; reg < REG_COUNT; reg++) {
        needed[reg] &= (uint8_t)~trace_deps_bytes(deps->must_write[reg], true);
    }
}

static void dse_add_deps_value_inputs(const TraceDeps *deps, const InsnAux *aux,
                                      uint64_t excluded_address_mask, uint64_t forced_value_mask,
                                      uint8_t needed[REG_COUNT], uint8_t natural_mask) {
    for (int reg = 0; reg < REG_COUNT; reg++) {
        uint64_t bit = UINT64_C(1) << reg;
        uint64_t value_reads = deps->value_uses[reg];
        if ((excluded_address_mask & bit) && !(forced_value_mask & bit))
            value_reads = deps->explicit_value_uses[reg];
        uint8_t tainted_at_use = aux ? (uint8_t)(aux->reg_taint[reg] & natural_mask) : natural_mask;
        needed[reg] |= (uint8_t)(trace_deps_bytes(value_reads, false) & tainted_at_use);
    }
}

static void dse_add_address_inputs(uint64_t address_reg_mask, const InsnAux *aux,
                                   uint8_t needed[REG_COUNT], uint8_t natural_mask) {
    if (!needed || natural_mask == 0)
        return;
    for (int reg = 0; reg < REG_COUNT; reg++) {
        if ((address_reg_mask & (1U << reg)) != 0) {
            needed[reg] |= aux ? (uint8_t)(aux->reg_taint[reg] & natural_mask) : natural_mask;
        }
    }
}

static bool dse_append_dependency(DseSliceResult *result, const TraceEntry **out_slice,
                                  uint32_t max_len, const TraceEntry *entry) {
    if (!result || !out_slice || !entry || max_len == 0 || result->len >= max_len - 1) {
        if (result) {
            result->status = DSE_SLICE_TRUNCATED;
        }
        return false;
    }
    out_slice[result->len++] = entry;
    return true;
}

static bool dse_append_trigger(DseSliceResult *result, const TraceEntry **out_slice,
                               uint32_t max_len, const TraceEntry *trigger) {
    if (!result || !out_slice || !trigger || result->len >= max_len) {
        if (result) {
            result->status = DSE_SLICE_TRUNCATED;
        }
        return false;
    }
    out_slice[result->len++] = trigger;
    return true;
}

static void dse_reverse_dependencies(const TraceEntry **slice, uint32_t dependency_count,
                                     DseSlicePlan *plan) {
    for (uint32_t i = 0; i < (dependency_count / 2U); i++) {
        uint32_t opposite = dependency_count - 1U - i;
        const TraceEntry *temp_entry = slice[i];
        slice[i] = slice[opposite];
        slice[opposite] = temp_entry;
        if (!plan)
            continue;
        uint64_t temp_seq_id = plan->seq_id[i];
        uint8_t temp_data[REG_COUNT];
        uint8_t temp_replay[REG_COUNT];
        bool temp_data_all_memory_writes = plan->data_all_memory_writes[i];
        bool temp_replay_all_memory_writes = plan->replay_all_memory_writes[i];
        memcpy(temp_data, plan->data_reg_live_after[i], sizeof(temp_data));
        memcpy(temp_replay, plan->replay_reg_live_after[i], sizeof(temp_replay));
        plan->seq_id[i] = plan->seq_id[opposite];
        plan->data_all_memory_writes[i] = plan->data_all_memory_writes[opposite];
        plan->replay_all_memory_writes[i] = plan->replay_all_memory_writes[opposite];
        memcpy(plan->data_reg_live_after[i], plan->data_reg_live_after[opposite],
               sizeof(plan->data_reg_live_after[i]));
        memcpy(plan->replay_reg_live_after[i], plan->replay_reg_live_after[opposite],
               sizeof(plan->replay_reg_live_after[i]));
        plan->seq_id[opposite] = temp_seq_id;
        plan->data_all_memory_writes[opposite] = temp_data_all_memory_writes;
        plan->replay_all_memory_writes[opposite] = temp_replay_all_memory_writes;
        memcpy(plan->data_reg_live_after[opposite], temp_data,
               sizeof(plan->data_reg_live_after[opposite]));
        memcpy(plan->replay_reg_live_after[opposite], temp_replay,
               sizeof(plan->replay_reg_live_after[opposite]));
    }
}

static GHashTable *dse_mem_need_create(void) {
    return g_hash_table_new_full(g_int64_hash, g_int64_equal, g_free, NULL);
}

static bool dse_mem_need_contains(const GHashTable *needed_memory, uint64_t address) {
    if (!needed_memory)
        return false;
    gint64 key = (gint64)address;
    return g_hash_table_contains((GHashTable *)needed_memory, &key);
}

static bool dse_mem_need_add(GHashTable *needed_memory, uint64_t address) {
    if (!needed_memory)
        return false;
    if (dse_mem_need_contains(needed_memory, address)) {
        return true;
    }
    gint64 *key = g_new(gint64, 1);
    if (!key)
        return false;
    *key = (gint64)address;
    g_hash_table_add(needed_memory, key);
    return true;
}

static bool dse_mem_need_add_read(GHashTable *needed_memory, const DseMemRead *read) {
    if (!needed_memory || !read || read->size == 0 || read->size > MAX_REG_BYTES ||
        read->addr > (UINT64_MAX - (uint64_t)(read->size - 1))) {
        return false;
    }
    for (uint8_t byte = 0; byte < read->size; byte++) {
        if ((read->taint & (uint8_t)(1U << byte)) == 0) {
            continue;
        }
        if (!dse_mem_need_add(needed_memory, read->addr + byte)) {
            return false;
        }
    }
    return true;
}

static bool dse_mem_need_add_aux_reads(GHashTable *needed_memory, const InsnAux *aux) {
    if (!needed_memory || !aux)
        return false;
    if (aux->mem_read_overflow)
        return false;
    if (aux->has_mem_read && aux->mem_read_count == 0) {
        return false;
    }
    for (uint8_t i = 0; i < aux->mem_read_count; i++) {
        if (!dse_mem_need_add_read(needed_memory, &aux->mem_reads[i])) {
            return false;
        }
    }
    return true;
}

static void dse_mem_need_consume_write(GHashTable *needed_memory, const DseMemWrite *write) {
    if (!needed_memory || !write || write->size == 0 ||
        write->addr > (UINT64_MAX - (uint64_t)(write->size - 1))) {
        return;
    }
    for (uint8_t byte = 0; byte < write->size; byte++) {
        gint64 key = (gint64)(write->addr + byte);
        g_hash_table_remove(needed_memory, &key);
    }
}

static bool dse_aux_has_usable_exact_string(const InsnAux *aux) {
    if (!aux || !g_arch || g_arch->natural_width != 32) {
        return false;
    }
    if (aux->string_summary.element_size == 0 ||
        aux->string_summary.element_size > (g_arch->natural_width / 8U)) {
        return false;
    }
    return dse_aux_has_exact_movs(aux) || dse_aux_has_exact_stos(aux);
}

static uint64_t dse_string_event_byte_address(uint64_t first, int8_t direction,
                                              uint8_t element_size, uint32_t event_index,
                                              uint8_t byte_index) {
    return (uint64_t)(uint32_t)((uint32_t)first +
                                (uint32_t)((int64_t)direction * (int64_t)event_index *
                                               (int64_t)element_size +
                                           (int64_t)byte_index));
}

static bool dse_movs_summary_ranges_overlap(const DseStringSummary *summary) {
    if (!summary || summary->kind != DSE_STRING_MOVS || summary->expected_iterations == 0 ||
        summary->element_size == 0) {
        return false;
    }
    if (summary->direction != 1 && summary->direction != -1) {
        return true;
    }
    uint64_t total_bytes = (uint64_t)summary->expected_iterations * (uint64_t)summary->element_size;
    if (total_bytes >= (UINT64_C(1) << 32U)) {
        return true;
    }
    uint64_t backward_displacement =
        (uint64_t)(summary->expected_iterations - 1U) * (uint64_t)summary->element_size;
    uint32_t source_start = (uint32_t)summary->source_first;
    uint32_t destination_start = (uint32_t)summary->destination_first;
    if (summary->direction < 0) {
        source_start = (uint32_t)(source_start - (uint32_t)backward_displacement);
        destination_start = (uint32_t)(destination_start - (uint32_t)backward_displacement);
    }
    uint32_t source_to_destination = (uint32_t)(destination_start - source_start);
    uint32_t destination_to_source = (uint32_t)(source_start - destination_start);

    return (uint64_t)source_to_destination < total_bytes ||
           (uint64_t)destination_to_source < total_bytes;
}

static bool dse_exact_movs_requires_full_replay(const InsnAux *aux) {
    return dse_aux_has_exact_movs(aux) && dse_movs_summary_ranges_overlap(&aux->string_summary);
}

static bool dse_mem_need_exact_string_write_overlaps(const GHashTable *needed_memory,
                                                     const InsnAux *aux) {
    if (!needed_memory || g_hash_table_size((GHashTable *)needed_memory) == 0 ||
        !dse_aux_has_usable_exact_string(aux)) {
        return false;
    }
    const DseStringSummary *summary = &aux->string_summary;
    for (uint32_t event = 0; event < summary->expected_iterations; event++) {
        for (uint8_t byte = 0; byte < summary->element_size; byte++) {
            uint64_t destination = dse_string_event_byte_address(
                summary->destination_first, summary->direction, summary->element_size, event, byte);
            if (dse_mem_need_contains(needed_memory, destination)) {
                return true;
            }
        }
    }
    return false;
}

static bool dse_mem_need_apply_exact_string(GHashTable *needed_memory,
                                            uint8_t needed_registers[REG_COUNT],
                                            const InsnAux *aux) {
    if (!needed_memory || !needed_registers || !dse_aux_has_usable_exact_string(aux)) {
        return false;
    }
    const DseStringSummary *summary = &aux->string_summary;
    for (uint32_t remaining = summary->expected_iterations; remaining != 0; remaining--) {
        uint32_t event = remaining - 1U;
        uint8_t needed_mask = 0;
        for (uint8_t byte = 0; byte < summary->element_size; byte++) {
            uint64_t destination = dse_string_event_byte_address(
                summary->destination_first, summary->direction, summary->element_size, event, byte);
            if (dse_mem_need_contains(needed_memory, destination)) {
                needed_mask |= (uint8_t)(1U << byte);
            }
        }
        if (needed_mask == 0)
            continue;
        for (uint8_t byte = 0; byte < summary->element_size; byte++) {
            if ((needed_mask & (uint8_t)(1U << byte)) == 0) {
                continue;
            }
            uint64_t destination = dse_string_event_byte_address(
                summary->destination_first, summary->direction, summary->element_size, event, byte);
            gint64 key = (gint64)destination;
            g_hash_table_remove(needed_memory, &key);
        }
        if (summary->kind == DSE_STRING_MOVS) {
            for (uint8_t byte = 0; byte < summary->element_size; byte++) {
                if ((needed_mask & (uint8_t)(1U << byte)) == 0) {
                    continue;
                }
                uint32_t captured_index = event * summary->element_size + byte;
                if (summary->value_taint[captured_index] == 0) {
                    continue;
                }
                uint64_t source = dse_string_event_byte_address(
                    summary->source_first, summary->direction, summary->element_size, event, byte);
                if (!dse_mem_need_add(needed_memory, source))
                    return false;
            }
        } else {
            needed_registers[DTA_REG_RAX] |= (uint8_t)(needed_mask & aux->reg_taint[DTA_REG_RAX]);
        }
    }
    return true;
}

static uint8_t dse_mem_need_mask_for_range(const GHashTable *needed_memory, uint64_t address,
                                           uint8_t size) {
    if (!needed_memory || size == 0 || size > MAX_REG_BYTES ||
        address > (UINT64_MAX - (uint64_t)(size - 1))) {
        return 0;
    }
    uint8_t mask = 0;
    for (uint8_t byte = 0; byte < size; byte++) {
        if (dse_mem_need_contains(needed_memory, address + byte)) {
            mask |= (uint8_t)(1U << byte);
        }
    }
    return mask;
}

static void dse_log_mem_access_failure(const char *where, const TraceEntry *entry,
                                       const InsnAux *aux, uint8_t needed_memory,
                                       bool memory_relevant) {
    if (!g_dse_verbose_diagnostics)
        return;
    const InsnMeta *meta = entry ? meta_lookup_id(entry->meta_id) : NULL;

    DSE_DIAGNOSTIC(stderr,
                   "[DSE-SLICE-MEM] "
                   "where=%s pc=0x%lx seq=%lu insn_id=%u "
                   "reads=%u/%u read_overflow=%s "
                   "writes=%u/%u write_overflow=%s "
                   "needed=0x%02x relevant=%s complete=%s "
                   "write_range_valid=%s "
                   "write_range_unknown=%s "
                   "write_range=[0x%lx,0x%lx] ",
                   where ? where : "unknown", (unsigned long)(entry ? entry->pc : 0),
                   (unsigned long)(entry ? entry->seq_id : 0),
                   (unsigned int)(meta ? meta->insn_id : 0), aux ? aux->mem_read_count : 0,
                   aux ? aux->mem_read_total : 0, aux && aux->mem_read_overflow ? "yes" : "no",
                   aux ? aux->mem_write_count : 0, aux ? aux->mem_write_total : 0,
                   aux && aux->mem_write_overflow ? "yes" : "no", (unsigned int)needed_memory,
                   memory_relevant ? "yes" : "no", aux && aux->execution_complete ? "yes" : "no",
                   aux && aux->mem_write_range_valid ? "yes" : "no",
                   aux && aux->mem_write_range_unknown ? "yes" : "no",
                   (unsigned long)(aux ? aux->mem_write_min_addr : 0),
                   (unsigned long)(aux ? aux->mem_write_max_addr : 0));

    if (aux && aux->string_summary.active) {
        const DseStringSummary *summary = &aux->string_summary;

        DSE_DIAGNOSTIC(stderr,
                       "string={kind=%u exact=%s "
                       "overflow=%s mismatch=%s "
                       "elem=%u dir=%d expected=%u "
                       "reads=%u writes=%u bytes=%u} ",
                       (unsigned int)summary->kind, summary->exact ? "yes" : "no",
                       summary->overflow ? "yes" : "no", summary->pattern_mismatch ? "yes" : "no",
                       (unsigned int)summary->element_size, (int)summary->direction,
                       summary->expected_iterations, summary->read_events, summary->write_events,
                       summary->bytes_captured);
    }

    DSE_DIAGNOSTIC(stderr, "bytes=");

    if (entry) {
        for (uint8_t i = 0; i < entry->size && i < MAX_INSN_BYTES; i++) {
            DSE_DIAGNOSTIC(stderr, "%02x", entry->instr_bytes[i]);
        }
    }
    fputc('\n', stderr);
}

static void dse_log_mem_slice_truncation(const TraceEntry *entry, uint64_t target_addr,
                                         uint8_t target_size, uint8_t needed_memory,
                                         const uint8_t needed_regs[REG_COUNT], uint32_t slice_len,
                                         uint32_t scanned_entries, uint32_t register_dependencies,
                                         uint32_t memory_dependencies,
                                         bool current_register_relevant,
                                         bool current_memory_relevant) {
    if (!g_dse_verbose_diagnostics)
        return;
    const InsnMeta *meta = entry ? meta_lookup_id(entry->meta_id) : NULL;
    DSE_DIAGNOSTIC(
        stderr,
        "[DSE-SLICE-TRUNC] kind=mem pc=0x%lx seq=%lu insn_id=%u slice=%u scanned=%u reg_deps=%u mem_deps=%u current_reg=%s current_mem=%s target=0x%lx/%u needed_mem=0x%02x needed_regs=",
        (unsigned long)(entry ? entry->pc : 0), (unsigned long)(entry ? entry->seq_id : 0),
        (unsigned int)(meta ? meta->insn_id : 0), slice_len, scanned_entries, register_dependencies,
        memory_dependencies, current_register_relevant ? "yes" : "no",
        current_memory_relevant ? "yes" : "no", (unsigned long)target_addr,
        (unsigned int)target_size, (unsigned int)needed_memory);
    bool any_register = false;
    for (int reg = 0; reg < REG_COUNT; reg++) {
        if (needed_regs[reg] == 0) {
            continue;
        }
        DSE_DIAGNOSTIC(stderr, "%sr%d:0x%02x", any_register ? "," : "", reg,
                       (unsigned int)needed_regs[reg]);
        any_register = true;
    }
    if (!any_register) {
        DSE_DIAGNOSTIC(stderr, "none");
    }
    DSE_DIAGNOSTIC(stderr, " bytes=");
    if (entry) {
        for (uint8_t i = 0; i < entry->size && i < MAX_INSN_BYTES; i++) {
            DSE_DIAGNOSTIC(stderr, "%02x", entry->instr_bytes[i]);
        }
    }
    fputc('\n', stderr);
}

static bool dse_find_mem_read(const InsnAux *aux, uint64_t address, uint8_t size, DseMemRead *out) {
    if (!aux || !out || size == 0 || size > 8 || address > UINT64_MAX - (uint64_t)(size - 1)) {
        return false;
    }
    for (uint8_t i = 0; i < aux->mem_read_count; i++) {
        const DseMemRead *read = &aux->mem_reads[i];
        if (!read->value_valid || read->size == 0 || address < read->addr) {
            continue;
        }
        uint64_t offset = address - read->addr;
        if (offset > read->size || size > (uint8_t)(read->size - offset)) {
            continue;
        }
        *out = *read;
        out->addr = address;
        out->size = size;
        out->value = read->value >> (8U * (uint32_t)offset);
        out->taint = (uint8_t)(read->taint >> (uint32_t)offset);
        return true;
    }
    if (aux->mem_read_count == 0 && aux->has_mem_read && aux->mem_read_value_valid &&
        address == aux->mem_read_addr) {
        out->addr = address;
        out->value = aux->mem_read_val;
        out->taint = aux->mem_read_taint;
        out->effective_taint = aux->mem_read_effective_taint;
        out->value_valid = true;
        out->address_tainted = aux->mem_read_address_tainted;
        out->size = size;
        return true;
    }
    return false;
}

static uint32_t dse_count_mask_bytes(uint8_t mask) {
    uint32_t count = 0;
    while (mask != 0) {
        count += mask & 1U;
        mask >>= 1;
    }
    return count;
}

static uint32_t dse_count_reg_root_bytes(const uint8_t roots[REG_COUNT]) {
    uint32_t count = 0;
    for (int reg = 0; reg < REG_COUNT; reg++) {
        count += dse_count_mask_bytes(roots[reg]);
    }
    return count;
}

static DseVerifyReason dse_slice_failure_reason(DseSliceStatus status) {
    switch (status) {
    case DSE_SLICE_OK:
        return DSE_REASON_NONE;
    case DSE_SLICE_INVALID_INPUT:
        return DSE_REASON_INVALID_INPUT;
    case DSE_SLICE_TRIGGER_MISSING:
        return DSE_REASON_TRIGGER_MISSING;
    case DSE_SLICE_META_MISSING:
        return DSE_REASON_META_MISSING;
    case DSE_SLICE_AUX_MISSING:
        return DSE_REASON_AUX_MISSING;
    case DSE_SLICE_TRUNCATED:
        return DSE_REASON_SLICE_TRUNCATED;
    case DSE_SLICE_UNRESOLVED_REGISTER:
    case DSE_SLICE_UNRESOLVED_MEMORY:
        return DSE_REASON_UNRESOLVED_DEPENDENCY;
    case DSE_SLICE_SYMBOLIC_ADDRESS:
        return DSE_REASON_SYMBOLIC_ADDRESS;
    case DSE_SLICE_MEM_ACCESS_UNMODELED:
        return DSE_REASON_MEM_ACCESS_UNMODELED;
    case DSE_SLICE_DEPENDENCY_UNKNOWN:
        return DSE_REASON_MODEL_INCOMPLETE;
    }
    return DSE_REASON_MODEL_INCOMPLETE;
}

typedef enum {
    DSE_SLICE_SEED_REGISTER = 0,
    DSE_SLICE_SEED_MEMORY
} DseSliceSeedKind;

typedef struct {
    uint8_t regs[REG_COUNT];
    uint64_t special;
    GHashTable *memory;
} DseDependencyFrontier;

static guint dse_demand_mem_key_hash(gconstpointer data) {
    const DseDemandMemKey *key = data;
    if (!key) {
        return 0;
    }

    uint64_t value = key->seq_id;

    value ^= key->address + UINT64_C(0x9e3779b97f4a7c15) + (value << 6U) + (value >> 2U);

    value ^= value >> 30U;
    value *= UINT64_C(0xbf58476d1ce4e5b9);
    value ^= value >> 27U;
    value *= UINT64_C(0x94d049bb133111eb);
    value ^= value >> 31U;

    return (guint)(value ^ (value >> 32U));
}

static gboolean dse_demand_mem_key_equal(gconstpointer left, gconstpointer right) {
    const DseDemandMemKey *a = left;
    const DseDemandMemKey *b = right;
    return a && b && a->seq_id == b->seq_id && a->address == b->address;
}

static bool dse_slice_plan_init(DseSlicePlan *plan) {
    if (!plan)
        return false;
    memset(plan, 0, sizeof(*plan));
    plan->data_memory_writes =
        g_hash_table_new_full(dse_demand_mem_key_hash, dse_demand_mem_key_equal, g_free, NULL);
    plan->replay_memory_writes =
        g_hash_table_new_full(dse_demand_mem_key_hash, dse_demand_mem_key_equal, g_free, NULL);
    if (!plan->data_memory_writes || !plan->replay_memory_writes) {
        if (plan->data_memory_writes) {
            g_hash_table_destroy(plan->data_memory_writes);
        }
        if (plan->replay_memory_writes) {
            g_hash_table_destroy(plan->replay_memory_writes);
        }
        memset(plan, 0, sizeof(*plan));
        return false;
    }
    return true;
}

static void dse_slice_plan_destroy(DseSlicePlan *plan) {
    if (!plan)
        return;
    if (plan->data_memory_writes) {
        g_hash_table_destroy(plan->data_memory_writes);
    }
    if (plan->replay_memory_writes) {
        g_hash_table_destroy(plan->replay_memory_writes);
    }
    memset(plan, 0, sizeof(*plan));
}

static bool dse_slice_plan_add_memory_write(DseSlicePlan *plan, bool replay, uint64_t seq_id,
                                            uint64_t address) {
    if (!plan || seq_id == 0) {
        return false;
    }
    GHashTable *set = replay ? plan->replay_memory_writes : plan->data_memory_writes;

    if (!set)
        return false;
    DseDemandMemKey lookup = {.seq_id = seq_id, .address = address};
    if (g_hash_table_contains(set, &lookup))
        return true;
    DseDemandMemKey *stored = g_try_new(DseDemandMemKey, 1);
    if (!stored)
        return false;
    *stored = lookup;
    g_hash_table_add(set, stored);
    return true;
}

static bool dse_slice_plan_capture_memory_writes(DseSlicePlan *plan, bool replay,
                                                 uint32_t plan_index, uint64_t seq_id,
                                                 const GHashTable *needed_memory,
                                                 const InsnAux *aux) {
    if (!plan || plan_index >= MAX_SLICE || !needed_memory || !aux || seq_id == 0) {
        return false;
    }
    if (!aux->has_mem_write || g_hash_table_size((GHashTable *)needed_memory) == 0) {
        return true;
    }
    if (dse_exact_movs_requires_full_replay(aux)) {
        if (replay) {
            plan->replay_all_memory_writes[plan_index] = true;
        } else {
            plan->data_all_memory_writes[plan_index] = true;
        }
        return true;
    }
    if (dse_aux_has_usable_exact_string(aux)) {
        const DseStringSummary *summary = &aux->string_summary;
        for (uint32_t event = 0; event < summary->expected_iterations; event++) {
            for (uint8_t byte = 0; byte < summary->element_size; byte++) {
                uint64_t address =
                    dse_string_event_byte_address(summary->destination_first, summary->direction,
                                                  summary->element_size, event, byte);
                if (dse_mem_need_contains(needed_memory, address) &&
                    !dse_slice_plan_add_memory_write(plan, replay, seq_id, address)) {
                    return false;
                }
            }
        }
        return true;
    }
    if (aux->mem_write_overflow)
        return false;
    for (uint8_t write_index = 0; write_index < aux->mem_write_count; write_index++) {
        const DseMemWrite *write = &aux->mem_writes[write_index];
        if (write->size == 0 || write->addr > (UINT64_MAX - ((uint64_t)write->size - 1U))) {
            return false;
        }
        for (uint8_t byte = 0; byte < write->size; byte++) {
            uint64_t address = write->addr + byte;
            if (dse_mem_need_contains(needed_memory, address) &&
                !dse_slice_plan_add_memory_write(plan, replay, seq_id, address)) {
                return false;
            }
        }
    }
    return true;
}

static bool dse_slice_plan_activate(DSECtx *ctx, const DseSlicePlan *plan, uint32_t index,
                                    uint64_t expected_seq_id, bool replay) {
    if (!ctx || !plan || index >= MAX_SLICE || expected_seq_id == 0 ||
        plan->seq_id[index] != expected_seq_id) {
        if (ctx) {
            ctx->register_model_complete = false;
            ctx->memory_model_complete = false;
        }
        return false;
    }
    ctx->demand_active = true;
    ctx->demand_seq_id = plan->seq_id[index];
    ctx->demand_all_memory_writes =
        replay ? plan->replay_all_memory_writes[index] : plan->data_all_memory_writes[index];
    memcpy(ctx->demand_reg_live_after,
           replay ? plan->replay_reg_live_after[index] : plan->data_reg_live_after[index],
           sizeof(ctx->demand_reg_live_after));
    ctx->demand_memory_writes = replay ? plan->replay_memory_writes : plan->data_memory_writes;
    memcpy(ctx->demand_reg_live_after,
           replay ? plan->replay_reg_live_after[index] : plan->data_reg_live_after[index],
           sizeof(ctx->demand_reg_live_after));
    ctx->demand_memory_writes = replay ? plan->replay_memory_writes : plan->data_memory_writes;
    return true;
}

static void dse_slice_plan_deactivate(DSECtx *ctx) {
    if (!ctx)
        return;
    ctx->demand_active = false;
    ctx->demand_seq_id = 0;
    memset(ctx->demand_reg_live_after, 0, sizeof(ctx->demand_reg_live_after));
    ctx->demand_all_memory_writes = false;
    ctx->demand_memory_writes = NULL;
}

static bool dse_dependency_frontier_init(DseDependencyFrontier *frontier) {
    if (!frontier)
        return false;
    memset(frontier, 0, sizeof(*frontier));
    frontier->memory = dse_mem_need_create();
    return frontier->memory != NULL;
}

static void dse_dependency_frontier_destroy(DseDependencyFrontier *frontier) {
    if (!frontier)
        return;
    if (frontier->memory)
        g_hash_table_destroy(frontier->memory);
    memset(frontier, 0, sizeof(*frontier));
}

static bool dse_dependency_frontier_copy(DseDependencyFrontier *destination,
                                         const DseDependencyFrontier *source) {
    if (!destination || !source || !destination->memory || !source->memory) {
        return false;
    }
    memcpy(destination->regs, source->regs, sizeof(destination->regs));
    destination->special = source->special;
    g_hash_table_remove_all(destination->memory);
    GHashTableIter iterator;
    gpointer key = NULL;
    g_hash_table_iter_init(&iterator, (GHashTable *)source->memory);
    while (g_hash_table_iter_next(&iterator, &key, NULL)) {
        uint64_t address = (uint64_t)*(const gint64 *)key;
        if (!dse_mem_need_add(destination->memory, address)) {
            return false;
        }
    }
    return true;
}

static void dse_keep_only_data_dependencies(DseSliceResult *result, const TraceEntry **out_slice,
                                            bool *dependency_is_data, DseSlicePlan *plan) {
    if (!result || !out_slice || !dependency_is_data) {
        return;
    }
    uint32_t old_len = result->len;
    uint32_t write_index = 0;
    for (uint32_t read_index = 0; read_index < old_len; read_index++) {
        if (!dependency_is_data[read_index]) {
            continue;
        }
        out_slice[write_index] = out_slice[read_index];
        dependency_is_data[write_index] = true;
        if (plan && write_index != read_index) {
            plan->seq_id[write_index] = plan->seq_id[read_index];
            plan->data_all_memory_writes[write_index] = plan->data_all_memory_writes[read_index];
            plan->replay_all_memory_writes[write_index] =
                plan->replay_all_memory_writes[read_index];
            memcpy(plan->data_reg_live_after[write_index], plan->data_reg_live_after[read_index],
                   sizeof(plan->data_reg_live_after[write_index]));
            memcpy(plan->replay_reg_live_after[write_index],
                   plan->replay_reg_live_after[read_index],
                   sizeof(plan->replay_reg_live_after[write_index]));
        }
        write_index++;
    }
    for (uint32_t index = write_index; index < old_len; index++) {
        out_slice[index] = NULL;
        dependency_is_data[index] = false;
        if (plan) {
            plan->seq_id[index] = 0;
            plan->data_all_memory_writes[index] = false;
            plan->replay_all_memory_writes[index] = false;
            memset(plan->data_reg_live_after[index], 0, sizeof(plan->data_reg_live_after[index]));
            memset(plan->replay_reg_live_after[index], 0,
                   sizeof(plan->replay_reg_live_after[index]));
        }
    }
    result->len = write_index;
}

static bool dse_fallback_to_data_only(DseSliceResult *result, const TraceEntry **out_slice,
                                      bool *dependency_is_data,
                                      DseDependencyFrontier *replay_frontier,
                                      const DseDependencyFrontier *data_frontier,
                                      uint8_t replay_address_roots[REG_COUNT],
                                      const uint8_t data_address_roots[REG_COUNT],
                                      DseSlicePlan *plan) {
    if (!result || !out_slice || !dependency_is_data || !replay_frontier || !data_frontier ||
        !replay_address_roots || !data_address_roots) {
        return false;
    }
    dse_keep_only_data_dependencies(result, out_slice, dependency_is_data, plan);
    if (!dse_dependency_frontier_copy(replay_frontier, data_frontier)) {
        return false;
    }
    dse_copy_reg_worklist(replay_address_roots, data_address_roots);
    result->path_constraints_expected = 0;
    return true;
}

static bool dse_dependency_frontier_empty(const DseDependencyFrontier *frontier) {
    if (!frontier)
        return true;
    return dse_reg_worklist_empty(frontier->regs) && frontier->special == 0 &&
           (!frontier->memory || g_hash_table_size(frontier->memory) == 0);
}

static TraceDepRelation
dse_dependency_frontier_memory_relevant(const DseDependencyFrontier *frontier,
                                        const TraceDeps *deps, const InsnAux *aux) {
    if (!frontier || !frontier->memory || !g_hash_table_size(frontier->memory))
        return TRACE_DEP_NO;
    if (deps->incomplete_reasons &
        (TRACE_DEPS_DESC_MISSING | TRACE_DEPS_IDENTITY_MISMATCH | TRACE_DEPS_UNSUPPORTED_WIDTH))
        return TRACE_DEP_UNKNOWN;
    if (dse_aux_has_usable_exact_string(aux)) {
        return dse_mem_need_exact_string_write_overlaps(frontier->memory, aux) ? TRACE_DEP_YES
                                                                               : TRACE_DEP_NO;
    }
    TraceDepRelation result = TRACE_DEP_NO;
    GHashTableIter iterator;
    gpointer key = NULL;
    g_hash_table_iter_init(&iterator, frontier->memory);
    while (g_hash_table_iter_next(&iterator, &key, NULL)) {
        TraceDepRelation relation =
            trace_deps_memory_overlap(deps, TRACE_MEM_WRITE, (uint64_t)*(const gint64 *)key, 1);
        if (relation == TRACE_DEP_UNKNOWN)
            return relation;
        if (relation == TRACE_DEP_YES)
            result = relation;
    }
    return result;
}

static bool dse_dependency_frontier_apply(DseDependencyFrontier *frontier, const TraceDeps *deps,
                                          const InsnMeta *meta, const InsnAux *aux,
                                          bool register_relevant, bool memory_relevant,
                                          bool flag_relevant, bool path_relevant,
                                          uint8_t natural_mask) {
    if (!frontier || !frontier->memory || !meta || !aux) {
        return false;
    }
    uint8_t needed_before[REG_COUNT];
    dse_copy_reg_worklist(needed_before, frontier->regs);
    bool exact_string = dse_aux_has_usable_exact_string(aux);
    if (memory_relevant) {
        if (exact_string) {
            if (!dse_mem_need_apply_exact_string(frontier->memory, frontier->regs, aux)) {
                return false;
            }
        } else {
            for (uint8_t i = 0; i < aux->mem_write_count; i++) {
                dse_mem_need_consume_write(frontier->memory, &aux->mem_writes[i]);
            }
        }
    }
    frontier->special &= ~deps->special_must_write;
    if (flag_relevant || register_relevant || memory_relevant)
        frontier->special |= deps->special_value_uses;
    if (path_relevant) {
        frontier->special |= deps->special_control_uses;
        for (int reg = 0; reg < REG_COUNT; reg++)
            frontier->regs[reg] |= (uint8_t)(trace_deps_bytes(deps->control_uses[reg], false) &
                                             aux->reg_taint[reg] & natural_mask);
    }
    if (aux->has_mem_read || aux->has_mem_write || register_relevant)
        frontier->special |= deps->special_address_uses;
    dse_consume_deps_writes(deps, frontier->regs);
    uint64_t observed_address_mask = 0;
    if (aux->has_mem_read) {
        observed_address_mask |= deps->read_address_regs;
    }
    if (aux->has_mem_write) {
        observed_address_mask |= deps->write_address_regs;
    }
    uint64_t forced_value_mask =
        trace_deps_x86_forced_value_regs(meta, needed_before, natural_mask);
    uint64_t excluded_value_mask = observed_address_mask;

    if (exact_string && aux->string_summary.kind == DSE_STRING_STOS) {
        excluded_value_mask |= 1U << DTA_REG_RAX;
    }
    dse_add_deps_value_inputs(deps, aux, excluded_value_mask, forced_value_mask, frontier->regs,
                              natural_mask);

    if (!exact_string && aux->has_mem_read && !dse_mem_need_add_aux_reads(frontier->memory, aux)) {
        return false;
    }
    return true;
}

static DseSliceResult dse_build_value_slice(const TraceBuffer *tb, const DseAuxRing *ring,
                                            uint64_t trigger_seq_id, DseSliceSeedKind seed_kind,
                                            RegId target_reg, uint64_t target_addr,
                                            uint8_t target_size, const TraceEntry **out_slice,
                                            uint32_t max_len, DseSlicePlan *plan,
                                            const DseRelevanceContext *relevance) {
    DseSliceResult result = dse_slice_result(DSE_SLICE_INVALID_INPUT);
    DseDependencyFrontier data_frontier = {0};
    DseDependencyFrontier replay_frontier = {0};
    uint8_t natural_mask = dse_natural_reg_mask();
    uint8_t data_address_roots[REG_COUNT] = {0};
    uint8_t replay_address_roots[REG_COUNT] = {0};
    bool *dependency_is_data = NULL;
    const TraceEntry *trigger = NULL;
    uint32_t trigger_back_index = 0;
    uint32_t scanned_entries = 0;
    uint32_t register_dependencies = 0;
    uint32_t memory_dependencies = 0;
    bool path_budget_exhausted = false;
    bool path_budget_reported = false;
    bool path_tracking_active = true;
    bool success = false;
    DseRelevanceSelection *relevance_selection = NULL;

    if (!tb || !ring || !out_slice || max_len < 2 || trigger_seq_id == 0 || natural_mask == 0 ||
        (plan && max_len > MAX_SLICE)) {
        return result;
    }
    if (seed_kind == DSE_SLICE_SEED_REGISTER) {
        if (target_reg < 0 || target_reg >= REG_COUNT) {
            return result;
        }
    } else if (seed_kind == DSE_SLICE_SEED_MEMORY) {
        if (target_size == 0 || target_size > MAX_REG_BYTES ||
            target_addr > (UINT64_MAX - (uint64_t)(target_size - 1))) {
            return result;
        }
    } else {
        return result;
    }
    dependency_is_data = g_try_new0(bool, max_len);
    if (!dependency_is_data) {
        return result;
    }
    if (!dse_dependency_frontier_init(&data_frontier)) {
        g_free(dependency_is_data);
        return result;
    }
    if (!dse_dependency_frontier_init(&replay_frontier)) {
        goto cleanup;
    }
    trigger = trace_find_seq(tb, trigger_seq_id, &trigger_back_index);
    if (!trigger) {
        result.status = DSE_SLICE_TRIGGER_MISSING;
        goto cleanup;
    }
    relevance_selection = dse_relevance_selection_create(tb, trigger_seq_id, relevance);
    if (relevance_selection) {
        result.relevance = relevance_selection->stats;
    } else if (relevance) {
        result.relevance.applied = true;
        result.relevance.complete = false;
    }

    const InsnMeta *trigger_meta = meta_lookup_id(trigger->meta_id);
    if (!trigger_meta) {
        result.status = DSE_SLICE_META_MISSING;
        result.meta_missing = 1;
        goto cleanup;
    }
    const InsnAux *trigger_aux = dse_aux_for(ring, tb, trigger);
    if (!trigger_aux) {
        result.status = DSE_SLICE_AUX_MISSING;
        result.aux_missing = 1;
        goto cleanup;
    }
    if (!trigger_aux->execution_complete) {
        result.status = DSE_SLICE_AUX_MISSING;
        result.aux_missing = 1;
        dse_log_mem_access_failure("trigger-incomplete", trigger, trigger_aux, 0, false);
        goto cleanup;
    }

    if (trigger_aux->mem_read_overflow || trigger_aux->mem_write_overflow) {
        result.status = DSE_SLICE_MEM_ACCESS_UNMODELED;
        dse_log_mem_access_failure("trigger-overflow", trigger, trigger_aux, 0, false);
        goto cleanup;
    }
    TraceDeps trigger_deps;
    dse_entry_deps(tb, ring, trigger, trigger_meta, trigger_aux, &trigger_deps);
    if (trigger_deps.incomplete_reasons) {
        result.status = DSE_SLICE_DEPENDENCY_UNKNOWN;
        result.dependency_unknown_reasons = trigger_deps.incomplete_reasons;
        goto cleanup;
    }
    uint32_t trigger_address_mask = 0;
    if (trigger_aux->has_mem_read) {
        trigger_address_mask |= trigger_deps.read_address_regs;
    }
    if (trigger_aux->has_mem_write) {
        trigger_address_mask |= trigger_deps.write_address_regs;
    }
    dse_add_address_inputs(trigger_address_mask, trigger_aux, data_address_roots, natural_mask);
    dse_add_address_inputs(trigger_address_mask, trigger_aux, replay_address_roots, natural_mask);
    if (seed_kind == DSE_SLICE_SEED_REGISTER) {
        uint8_t seed = (uint8_t)(trigger_aux->reg_taint[target_reg] & natural_mask);
        data_frontier.regs[target_reg] = seed;
        replay_frontier.regs[target_reg] = seed;
    } else {
        DseMemRead target_read;
        if (!dse_find_mem_read(trigger_aux, target_addr, target_size, &target_read)) {
            result.status = DSE_SLICE_MEM_ACCESS_UNMODELED;
            dse_log_mem_access_failure("trigger-read-missing", trigger, trigger_aux, 0, false);
            goto cleanup;
        }
        for (uint8_t byte = 0; byte < target_size; byte++) {
            if ((target_read.taint & (uint8_t)(1U << byte)) == 0) {
                continue;
            }
            uint64_t address = target_addr + byte;
            if (!dse_mem_need_add(data_frontier.memory, address) ||
                !dse_mem_need_add(replay_frontier.memory, address)) {
                result.status = DSE_SLICE_INVALID_INPUT;
                goto cleanup;
            }
        }
    }
    for (uint32_t i = trigger_back_index + 1;
         i < tb->counter && !(path_tracking_active ? dse_dependency_frontier_empty(&replay_frontier)
                                                   : dse_dependency_frontier_empty(&data_frontier));
         i++) {
        bool path_window_open = !dse_dependency_frontier_empty(&data_frontier);
        const TraceEntry *entry = trace_get_last(tb, i);
        if (!entry || entry->vcpu_index != trigger->vcpu_index) {
            continue;
        }
        scanned_entries++;
        const InsnMeta *meta = meta_lookup_id(entry->meta_id);
        if (!meta) {
            result.status = DSE_SLICE_META_MISSING;
            result.meta_missing++;
            goto cleanup;
        }
        const InsnAux *aux = dse_aux_for(ring, tb, entry);
        TraceDeps deps;
        dse_entry_deps(tb, ring, entry, meta, aux, &deps);
        bool data_register_relevant = dse_deps_writes_needed(&deps, data_frontier.regs);
        bool replay_register_relevant = dse_deps_writes_needed(&deps, replay_frontier.regs);
        bool data_flag_relevant = (deps.special_may_write & data_frontier.special) != 0;
        bool replay_flag_relevant = (deps.special_may_write & replay_frontier.special) != 0;
        TraceDepRelation replay_memory =
            dse_dependency_frontier_memory_relevant(&replay_frontier, &deps, aux);
        TraceDepRelation data_memory =
            dse_dependency_frontier_memory_relevant(&data_frontier, &deps, aux);
        if (replay_memory == TRACE_DEP_UNKNOWN || data_memory == TRACE_DEP_UNKNOWN) {
            result.status = aux ? DSE_SLICE_MEM_ACCESS_UNMODELED : DSE_SLICE_AUX_MISSING;
            if (!aux)
                result.aux_missing++;
            result.dependency_unknown_reasons |=
                deps.incomplete_reasons | TRACE_DEPS_MEMORY_INCOMPLETE;
            goto cleanup;
        }
        bool data_memory_relevant = data_memory == TRACE_DEP_YES;
        bool replay_memory_relevant = replay_memory == TRACE_DEP_YES;
        bool data_relevant = data_register_relevant || data_memory_relevant || data_flag_relevant;
        DcfgRelevance branch_relevance =
            dse_relevance_selection_get(relevance_selection, entry->seq_id);
        bool path_relevant = false;
        if (path_tracking_active && path_window_open && meta->is_conditional_branch &&
            branch_relevance != DCFG_RELEVANCE_IRRELEVANT) {
            if (result.path_constraints_expected < DSE_MAX_PATH_CONSTRAINTS) {
                path_relevant = true;
            } else {
                uint32_t old_slice_len = result.len;
                path_budget_exhausted = true;
                path_tracking_active = false;
                if (!path_budget_reported) {
                    DSE_DIAGNOSTIC(
                        stderr,
                        "[DSE-PATH-BUDGET] trigger_seq=%lu limit=%u first_omitted_pc=0x%lx seq=%lu\n",
                        (unsigned long)trigger_seq_id, (unsigned int)DSE_MAX_PATH_CONSTRAINTS,
                        (unsigned long)entry->pc, (unsigned long)entry->seq_id);
                    path_budget_reported = true;
                }
                if (!dse_fallback_to_data_only(&result, out_slice, dependency_is_data,
                                               &replay_frontier, &data_frontier,
                                               replay_address_roots, data_address_roots, plan)) {
                    result.status = DSE_SLICE_INVALID_INPUT;
                    goto cleanup;
                }
                DSE_DIAGNOSTIC(
                    stderr,
                    "[DSE-PATH-FALLBACK] reason=constraint-budget trigger_seq=%lu kept=%u dropped=%u\n",
                    (unsigned long)trigger_seq_id, result.len, (old_slice_len - result.len));
                replay_register_relevant = data_register_relevant;
                replay_memory_relevant = data_memory_relevant;
                replay_flag_relevant = data_flag_relevant;
            }
        }
        if (!replay_register_relevant && !replay_memory_relevant && !replay_flag_relevant &&
            !path_relevant) {
            continue;
        }
        if (result.len >= max_len - 1 && path_tracking_active) {
            uint32_t old_slice_len = result.len;
            path_budget_exhausted = true;
            path_tracking_active = false;
            path_relevant = false;
            if (!dse_fallback_to_data_only(&result, out_slice, dependency_is_data, &replay_frontier,
                                           &data_frontier, replay_address_roots, data_address_roots,
                                           plan)) {
                result.status = DSE_SLICE_INVALID_INPUT;
                goto cleanup;
            }
            DSE_DIAGNOSTIC(
                stderr,
                "[DSE-PATH-FALLBACK] reason=slice-capacity trigger_seq=%lu kept=%u dropped=%u\n",
                (unsigned long)trigger_seq_id, result.len, (old_slice_len - result.len));
            replay_register_relevant = data_register_relevant;
            replay_memory_relevant = data_memory_relevant;
            replay_flag_relevant = data_flag_relevant;
            if (!data_relevant)
                continue;
        }
        if (!aux) {
            aux = dse_aux_for(ring, tb, entry);
        }
        if (!aux) {
            result.status = DSE_SLICE_AUX_MISSING;
            result.aux_missing++;
            goto cleanup;
        }
        if (!aux->execution_complete) {
            result.status = DSE_SLICE_AUX_MISSING;
            result.aux_missing++;
            dse_log_mem_access_failure(
                "dependency-incomplete", entry, aux,
                dse_mem_need_mask_for_range(replay_frontier.memory, target_addr, target_size),
                replay_memory_relevant);
            goto cleanup;
        }
        uint32_t dependency_issues = deps.incomplete_reasons;
        if (deps.special_unknown_write & replay_frontier.special)
            dependency_issues |= TRACE_DEPS_UNDEFINED_SPECIAL;
        if (dependency_issues) {
            result.status = DSE_SLICE_DEPENDENCY_UNKNOWN;
            result.dependency_unknown_reasons |= dependency_issues;
            goto cleanup;
        }
        bool exact_string = dse_aux_has_usable_exact_string(aux);
        bool read_access_unmodeled = aux->mem_read_overflow &&
                                     !(exact_string && aux->string_summary.kind == DSE_STRING_MOVS);
        bool relevant_write_unmodeled = replay_memory_relevant && !exact_string &&
                                        (aux->mem_write_overflow || aux->mem_write_count != 1);
        if (read_access_unmodeled || relevant_write_unmodeled) {
            result.status = DSE_SLICE_MEM_ACCESS_UNMODELED;
            result.dependency_unknown_reasons |= TRACE_DEPS_MEMORY_INCOMPLETE;
            dse_log_mem_access_failure(
                "dependency-unmodeled", entry, aux,
                dse_mem_need_mask_for_range(replay_frontier.memory, target_addr, target_size),
                replay_memory_relevant);
            goto cleanup;
        }
        uint8_t data_needed_before[REG_COUNT];
        uint8_t replay_needed_before[REG_COUNT];
        dse_copy_reg_worklist(data_needed_before, data_frontier.regs);
        dse_copy_reg_worklist(replay_needed_before, replay_frontier.regs);
        uint8_t target_needed_before =
            dse_mem_need_mask_for_range(replay_frontier.memory, target_addr, target_size);
        uint32_t appended_index = result.len;
        if (!dse_append_dependency(&result, out_slice, max_len, entry)) {
            dse_log_mem_slice_truncation(entry, target_addr, target_size, target_needed_before,
                                         replay_frontier.regs, result.len, scanned_entries,
                                         register_dependencies, memory_dependencies,
                                         replay_register_relevant, replay_memory_relevant);
            goto cleanup;
        }
        dependency_is_data[appended_index] = data_relevant;
        if (plan) {
            plan->seq_id[appended_index] = entry->seq_id;
            plan->data_all_memory_writes[appended_index] = false;
            plan->replay_all_memory_writes[appended_index] = false;
            memcpy(plan->data_reg_live_after[appended_index], data_needed_before,
                   sizeof(plan->data_reg_live_after[appended_index]));
            memcpy(plan->replay_reg_live_after[appended_index], replay_needed_before,
                   sizeof(plan->replay_reg_live_after[appended_index]));
            if ((data_memory_relevant &&
                 !dse_slice_plan_capture_memory_writes(plan, false, appended_index, entry->seq_id,
                                                       data_frontier.memory, aux)) ||
                (replay_memory_relevant &&
                 !dse_slice_plan_capture_memory_writes(plan, true, appended_index, entry->seq_id,
                                                       replay_frontier.memory, aux))) {
                result.status = DSE_SLICE_INVALID_INPUT;
                goto cleanup;
            }
        }
        if (replay_register_relevant)
            register_dependencies++;
        if (replay_memory_relevant)
            memory_dependencies++;
        uint64_t observed_address_mask = 0;
        if (aux->has_mem_read) {
            observed_address_mask |= deps.read_address_regs;
        }
        if (aux->has_mem_write) {
            observed_address_mask |= deps.write_address_regs;
        }
        uint64_t replay_forced_value_mask =
            trace_deps_x86_forced_value_regs(meta, replay_needed_before, natural_mask);
        dse_add_address_inputs(observed_address_mask & ~replay_forced_value_mask, aux,
                               replay_address_roots, natural_mask);
        if (data_relevant) {
            uint64_t data_forced_value_mask =
                trace_deps_x86_forced_value_regs(meta, data_needed_before, natural_mask);
            dse_add_address_inputs(observed_address_mask & ~data_forced_value_mask, aux,
                                   data_address_roots, natural_mask);
        }
        if (data_relevant && !dse_dependency_frontier_apply(
                                 &data_frontier, &deps, meta, aux, data_register_relevant,
                                 data_memory_relevant, data_flag_relevant, false, natural_mask)) {
            result.status = DSE_SLICE_MEM_ACCESS_UNMODELED;
            dse_log_mem_access_failure(
                "data-read-source-unmodeled", entry, aux,
                dse_mem_need_mask_for_range(data_frontier.memory, target_addr, target_size),
                data_memory_relevant);
            goto cleanup;
        }
        if (!dse_dependency_frontier_apply(&replay_frontier, &deps, meta, aux,
                                           replay_register_relevant, replay_memory_relevant,
                                           replay_flag_relevant, path_relevant, natural_mask)) {
            result.status = DSE_SLICE_MEM_ACCESS_UNMODELED;
            dse_log_mem_access_failure(
                "replay-read-source-unmodeled", entry, aux,
                dse_mem_need_mask_for_range(replay_frontier.memory, target_addr, target_size),
                replay_memory_relevant);
            goto cleanup;
        }
        if (path_relevant && result.path_constraints_expected != UINT32_MAX) {
            result.path_constraints_expected++;
        }
    }
    dse_copy_reg_worklist(result.boundary_reg_bytes, replay_frontier.regs);
    result.boundary_special = replay_frontier.special;
    result.boundary_flags = trace_deps_x86_legacy_flags(result.boundary_special);
    result.boundary_mem_byte_count = (uint32_t)g_hash_table_size(replay_frontier.memory);
    result.boundary_mem_bytes =
        dse_mem_need_mask_for_range(replay_frontier.memory, target_addr, target_size);
    dse_copy_reg_worklist(result.address_root_reg_bytes, replay_address_roots);
    memset(result.unresolved_reg_bytes, 0, sizeof(result.unresolved_reg_bytes));
    result.unresolved_mem_bytes = 0;
    uint32_t dependency_count = result.len;
    result.string_summaries = 0;
    for (uint32_t index = 0; index < dependency_count; index++) {
        const InsnAux *dependency_aux = dse_aux_for(ring, tb, out_slice[index]);
        if (dse_aux_has_usable_exact_string(dependency_aux) &&
            result.string_summaries != UINT32_MAX) {
            result.string_summaries++;
        }
    }
    dse_reverse_dependencies(out_slice, dependency_count, plan);
    uint32_t trigger_index = result.len;
    if (!dse_append_trigger(&result, out_slice, max_len, trigger)) {
        goto cleanup;
    }
    if (plan) {
        plan->seq_id[trigger_index] = trigger->seq_id;
        plan->data_all_memory_writes[trigger_index] = false;
        plan->replay_all_memory_writes[trigger_index] = false;
        memset(plan->data_reg_live_after[trigger_index], 0,
               sizeof(plan->data_reg_live_after[trigger_index]));
        memset(plan->replay_reg_live_after[trigger_index], 0,
               sizeof(plan->replay_reg_live_after[trigger_index]));
    }
    result.status = DSE_SLICE_OK;
    result.data_complete = true;
    result.path_complete = !path_budget_exhausted;
    result.complete = result.data_complete && result.path_complete;
    success = true;
cleanup:
    if (!success) {
        result.unresolved_mem_bytes =
            dse_mem_need_mask_for_range(replay_frontier.memory, target_addr, target_size);
        dse_copy_reg_worklist(result.unresolved_reg_bytes, replay_frontier.regs);
        dse_copy_reg_worklist(result.address_root_reg_bytes, replay_address_roots);
    }
    dse_dependency_frontier_destroy(&replay_frontier);
    dse_dependency_frontier_destroy(&data_frontier);
    if (relevance_selection) {
        result.relevance = relevance_selection->stats;
    }
    dse_relevance_selection_destroy(relevance_selection);
    g_free(dependency_is_data);
    return result;
}

DseSliceResult dse_build_reg_slice(const TraceBuffer *tb, const DseAuxRing *ring,
                                   uint64_t trigger_seq_id, RegId target_reg,
                                   const TraceEntry **out_slice, uint32_t max_len) {
    return dse_build_value_slice(tb, ring, trigger_seq_id, DSE_SLICE_SEED_REGISTER, target_reg, 0,
                                 0, out_slice, max_len, NULL, NULL);
}

DseSliceResult dse_build_mem_slice(const TraceBuffer *tb, const DseAuxRing *ring,
                                   uint64_t trigger_seq_id, uint64_t target_addr,
                                   uint8_t target_size, const TraceEntry **out_slice,
                                   uint32_t max_len) {
    return dse_build_value_slice(tb, ring, trigger_seq_id, DSE_SLICE_SEED_MEMORY, REG_INVALID,
                                 target_addr, target_size, out_slice, max_len, NULL, NULL);
}

static DseSliceResult dse_build_reg_slice_planned(const TraceBuffer *tb, const DseAuxRing *ring,
                                                  uint64_t trigger_seq_id, RegId target_reg,
                                                  const TraceEntry **out_slice, uint32_t max_len,
                                                  DseSlicePlan *plan,
                                                  const DseRelevanceContext *relevance) {
    return dse_build_value_slice(tb, ring, trigger_seq_id, DSE_SLICE_SEED_REGISTER, target_reg, 0,
                                 0, out_slice, max_len, plan, relevance);
}

static DseSliceResult dse_build_mem_slice_planned(const TraceBuffer *tb, const DseAuxRing *ring,
                                                  uint64_t trigger_seq_id, uint64_t target_addr,
                                                  uint8_t target_size, const TraceEntry **out_slice,
                                                  uint32_t max_len, DseSlicePlan *plan,
                                                  const DseRelevanceContext *relevance) {
    return dse_build_value_slice(tb, ring, trigger_seq_id, DSE_SLICE_SEED_MEMORY, REG_INVALID,
                                 target_addr, target_size, out_slice, max_len, plan, relevance);
}

static ReplayInput *dse_capture_slice_input(const TraceBuffer *tb, const DseAuxRing *ring,
                                            const TraceEntry *const *slice, uint32_t count,
                                            uint64_t trigger_seq_id, DseVerifyResult *result) {
    uint64_t seq_ids[MAX_SLICE];
    if (count == 0 || count > MAX_SLICE || !slice[count - 1U] ||
        slice[count - 1U]->seq_id != trigger_seq_id) {
        result->reason = DSE_REASON_INVALID_INPUT;
        return NULL;
    }
    for (uint32_t i = 0; i < count; i++) {
        seq_ids[i] = slice[i] ? slice[i]->seq_id : 0;
    }
    ReplayInputStatus status;
    /* Existing slices include the trigger as their last instruction. The
	 * owned input stores it separately as the observation point. */
    ReplayInput *input = replay_input_capture(tb, ring, seq_ids, count - 1U, trigger_seq_id,
                                              DSE_MAX_STRING_TRACE_BYTES, &status);
    if (status == REPLAY_INPUT_READY)
        return input;
    uint32_t issues = replay_input_issues(input);
    result->reason = DSE_REASON_MODEL_INCOMPLETE;
    if (status == REPLAY_INPUT_RESOURCE_LIMIT)
        result->reason = DSE_REASON_RESOURCE_LIMIT;
    else if (status == REPLAY_INPUT_INVALID_REQUEST)
        result->reason = DSE_REASON_INVALID_INPUT;
    else if (issues & (REPLAY_INPUT_META_MISSING | REPLAY_INPUT_META_MISMATCH))
        result->reason = DSE_REASON_META_MISSING;
    else if (issues & (REPLAY_INPUT_AUX_MISSING | REPLAY_INPUT_EXECUTION_PENDING))
        result->reason = DSE_REASON_AUX_MISSING;
    DSE_DIAGNOSTIC(stderr, "[DSE-REPLAY-INPUT] trigger_seq=%lu status=%u issues=0x%x\n",
                   (unsigned long)trigger_seq_id, (unsigned int)status, issues);
    replay_input_destroy(input);
    return NULL;
}

DseVerifyResult dse_verify_oep_candidate_with_relevance(TraceBuffer *tb, const DseAuxRing *ring,
                                                        uint64_t trigger_seq_id, RegId target_reg,
                                                        uint64_t oep_candidate,
                                                        ShadowMemory *shadow, csh cs_handle,
                                                        const DseRelevanceContext *relevance) {
    (void)shadow;
    DseVerifyResult result = dse_unknown_result(DSE_REASON_INVALID_INPUT);
    if (!tb || !ring || target_reg < 0 || target_reg >= REG_COUNT || !g_arch) {
        return result;
    }
    DseSlicePlan plan;
    ReplayInput *input = NULL;
    if (!dse_slice_plan_init(&plan)) {
        result.reason = DSE_REASON_RESOURCE_LIMIT;
        return result;
    }
    g_tb = tb;
    const TraceEntry *slice[MAX_SLICE];
    DseSliceResult slice_result = dse_build_reg_slice_planned(tb, ring, trigger_seq_id, target_reg,
                                                              slice, MAX_SLICE, &plan, relevance);
    dse_capture_relevance_metrics(&result, &slice_result.relevance);
    result.data_slice_complete = slice_result.data_complete;
    result.slice_complete = slice_result.complete;
    result.boundary_flag_bits = (uint32_t)__builtin_popcountll(slice_result.boundary_special);
    result.path_constraints_expected = slice_result.path_constraints_expected;
    result.string_summaries_expected = slice_result.string_summaries;
    result.slice_len = slice_result.len;
    result.meta_missing = slice_result.meta_missing;
    result.aux_miss = slice_result.aux_missing;
    result.boundary_reg_bytes = dse_count_reg_root_bytes(slice_result.boundary_reg_bytes);
    result.boundary_mem_bytes = slice_result.boundary_mem_byte_count;
    result.address_root_bytes = dse_count_reg_root_bytes(slice_result.address_root_reg_bytes);
    if (!slice_result.data_complete) {
        result.reason = dse_slice_failure_reason(slice_result.status);
        replay_input_destroy(input);
        dse_slice_plan_destroy(&plan);
        return result;
    }
    input = dse_capture_slice_input(tb, ring, slice, slice_result.len, trigger_seq_id, &result);
    if (!input) {
        dse_slice_plan_destroy(&plan);
        return result;
    }
    DSECtx ctx;
    if (!dse_ctx_init(&ctx)) {
        result.reason = DSE_REASON_CONTEXT_INIT_FAILED;
        replay_input_destroy(input);
        dse_slice_plan_destroy(&plan);
        return result;
    }
    dse_lift_begin(&ctx);
    if (!slice_result.path_complete) {
        ctx.path_model_complete = false;
        if (ctx.path_failures != UINT32_MAX) {
            ctx.path_failures++;
        }
    }
    uint32_t meta_missing = 0;
    bool use_replay_demands = slice_result.path_complete;
    for (uint32_t i = 0; i < slice_result.len; i++) {
        if (ctx.resource_limit_hit)
            break;
        const ReplayStep *step = i == replay_input_count(input) ? replay_input_trigger(input)
                                                                : replay_input_step(input, i);
        const TraceEntry *entry = step ? &step->entry : NULL;
        if (!entry || !dse_slice_plan_activate(&ctx, &plan, i, entry->seq_id, use_replay_demands)) {
            break;
        }
        const InsnMeta *meta = replay_input_meta(input, entry->seq_id);
        if (!meta) {
            meta_missing++;
            g_total++;
            g_concretized++;
            continue;
        }
        (void)dse_lift_replay_step(&ctx, input, i, cs_handle);
    }
    dse_slice_plan_deactivate(&ctx);
    if (ctx.path_constraints < slice_result.path_constraints_expected) {
        ctx.path_model_complete = false;
        ctx.path_failures += slice_result.path_constraints_expected - ctx.path_constraints;
    }
    if (ctx.string_summaries < slice_result.string_summaries) {
        ctx.memory_model_complete = false;
    }
    dse_capture_verify_metrics(&result, &ctx, slice_result.len, meta_missing);
    const ReplayStep *diagnostic_trigger = replay_input_trigger(input);
    dse_diagnostic_origin(&ctx, diagnostic_trigger ? &diagnostic_trigger->entry : NULL);
    const InsnAux *trigger_aux = replay_input_aux(input, trigger_seq_id);
    SymExpr *target = trigger_aux ? dse_read_rid_fit(&ctx, trigger_aux, target_reg,
                                                     g_arch->natural_width, g_arch->natural_width)
                                  : NULL;
    if (!target) {
        DseVerifyReason replay_failure = dse_replay_failure_reason(&ctx);
        result.reason = replay_failure != DSE_REASON_NONE
                            ? replay_failure
                            : (ctx.resource_limit_hit ? DSE_REASON_RESOURCE_LIMIT
                                                      : DSE_REASON_TARGET_UNAVAILABLE);
        dse_capture_verify_metrics(&result, &ctx, slice_result.len, meta_missing);
        dse_ctx_free(&ctx);
        replay_input_destroy(input);
        dse_slice_plan_destroy(&plan);
        return result;
    }
    (void)dse_replay_target(&ctx, target, oep_candidate, &result);
    dse_capture_verify_metrics(&result, &ctx, slice_result.len, meta_missing);
    DseVerifyReason failure = dse_lift_failure_reason(&ctx, &result);
    if (failure != DSE_REASON_NONE) {
        result.reason = failure;
        sym_expr_free(target);
        dse_ctx_free(&ctx);
        replay_input_destroy(input);
        dse_slice_plan_destroy(&plan);
        return result;
    }
    dse_classify_target(&ctx, target, oep_candidate, &result);
    dse_capture_verify_metrics(&result, &ctx, slice_result.len, meta_missing);
    sym_expr_free(target);
    dse_ctx_free(&ctx);
    replay_input_destroy(input);
    dse_slice_plan_destroy(&plan);
    return result;
}

DseVerifyResult dse_verify_oep_candidate_mem_with_relevance(TraceBuffer *tb, const DseAuxRing *ring,
                                                            uint64_t trigger_seq_id,
                                                            uint64_t target_addr,
                                                            uint64_t oep_candidate,
                                                            ShadowMemory *shadow, csh cs_handle,
                                                            const DseRelevanceContext *relevance) {
    (void)shadow;
    DseVerifyResult result = dse_unknown_result(DSE_REASON_INVALID_INPUT);
    if (!tb || !ring || !g_arch) {
        return result;
    }
    if (g_arch->natural_width == 0 || g_arch->natural_width % 8 != 0 ||
        g_arch->natural_width / 8 > MAX_REG_BYTES) {
        return result;
    }
    DseSlicePlan plan;
    ReplayInput *input = NULL;
    if (!dse_slice_plan_init(&plan)) {
        result.reason = DSE_REASON_RESOURCE_LIMIT;
        return result;
    }
    g_tb = tb;
    const TraceEntry *slice[MAX_SLICE];
    uint8_t target_size = (uint8_t)(g_arch->natural_width / 8);
    DseSliceResult slice_result = dse_build_mem_slice_planned(
        tb, ring, trigger_seq_id, target_addr, target_size, slice, MAX_SLICE, &plan, relevance);
    dse_capture_relevance_metrics(&result, &slice_result.relevance);
    result.data_slice_complete = slice_result.data_complete;
    result.slice_complete = slice_result.complete;
    result.boundary_flag_bits = (uint32_t)__builtin_popcountll(slice_result.boundary_special);
    result.path_constraints_expected = slice_result.path_constraints_expected;
    result.string_summaries_expected = slice_result.string_summaries;
    result.slice_len = slice_result.len;
    result.meta_missing = slice_result.meta_missing;
    result.aux_miss = slice_result.aux_missing;
    result.boundary_reg_bytes = dse_count_reg_root_bytes(slice_result.boundary_reg_bytes);
    result.boundary_mem_bytes = slice_result.boundary_mem_byte_count;
    result.address_root_bytes = dse_count_reg_root_bytes(slice_result.address_root_reg_bytes);
    if (!slice_result.data_complete) {
        result.reason = dse_slice_failure_reason(slice_result.status);
        replay_input_destroy(input);
        dse_slice_plan_destroy(&plan);
        return result;
    }
    input = dse_capture_slice_input(tb, ring, slice, slice_result.len, trigger_seq_id, &result);
    if (!input) {
        dse_slice_plan_destroy(&plan);
        return result;
    }
    DSECtx ctx;
    if (!dse_ctx_init(&ctx)) {
        result.reason = DSE_REASON_CONTEXT_INIT_FAILED;
        replay_input_destroy(input);
        dse_slice_plan_destroy(&plan);
        return result;
    }
    dse_lift_begin(&ctx);
    if (!slice_result.path_complete) {
        ctx.path_model_complete = false;
        if (ctx.path_failures != UINT32_MAX) {
            ctx.path_failures++;
        }
    }
    uint32_t meta_missing = 0;
    bool use_replay_demands = slice_result.path_complete;
    for (uint32_t i = 0; i < slice_result.len; i++) {
        if (ctx.resource_limit_hit)
            break;
        const ReplayStep *step = i == replay_input_count(input) ? replay_input_trigger(input)
                                                                : replay_input_step(input, i);
        const TraceEntry *entry = step ? &step->entry : NULL;
        if (!entry || !dse_slice_plan_activate(&ctx, &plan, i, entry->seq_id, use_replay_demands)) {
            break;
        }
        const InsnMeta *meta = replay_input_meta(input, entry->seq_id);
        if (!meta) {
            meta_missing++;
            g_total++;
            g_concretized++;
            continue;
        }
        (void)dse_lift_replay_step(&ctx, input, i, cs_handle);
    }
    dse_slice_plan_deactivate(&ctx);
    if (ctx.path_constraints < slice_result.path_constraints_expected) {
        ctx.path_model_complete = false;
        ctx.path_failures += slice_result.path_constraints_expected - ctx.path_constraints;
    }
    if (ctx.string_summaries < slice_result.string_summaries) {
        ctx.memory_model_complete = false;
    }
    dse_capture_verify_metrics(&result, &ctx, slice_result.len, meta_missing);
    const ReplayStep *diagnostic_trigger = replay_input_trigger(input);
    dse_diagnostic_origin(&ctx, diagnostic_trigger ? &diagnostic_trigger->entry : NULL);
    const InsnAux *trigger_aux = replay_input_aux(input, trigger_seq_id);
    DseMemRead target_read;
    InsnAux selected_aux;
    SymExpr *target = NULL;
    if (trigger_aux && dse_find_mem_read(trigger_aux, target_addr, target_size, &target_read)) {
        selected_aux = *trigger_aux;
        selected_aux.has_mem_read = true;
        selected_aux.mem_read_addr = target_read.addr;
        selected_aux.mem_read_val = target_read.value;
        selected_aux.mem_read_value_valid = true;
        selected_aux.mem_read_taint = target_read.taint;
        target = dse_load_mem(&ctx, &selected_aux, g_arch->natural_width, g_arch->big_endian);
    }
    if (!target) {
        DseVerifyReason replay_failure = dse_replay_failure_reason(&ctx);
        result.reason = replay_failure != DSE_REASON_NONE
                            ? replay_failure
                            : (ctx.resource_limit_hit ? DSE_REASON_RESOURCE_LIMIT
                                                      : DSE_REASON_TARGET_UNAVAILABLE);
        dse_capture_verify_metrics(&result, &ctx, slice_result.len, meta_missing);
        dse_ctx_free(&ctx);
        replay_input_destroy(input);
        dse_slice_plan_destroy(&plan);
        return result;
    }
    (void)dse_replay_target(&ctx, target, oep_candidate, &result);
    dse_capture_verify_metrics(&result, &ctx, slice_result.len, meta_missing);
    DseVerifyReason failure = dse_lift_failure_reason(&ctx, &result);
    if (failure != DSE_REASON_NONE) {
        result.reason = failure;
        sym_expr_free(target);
        dse_ctx_free(&ctx);
        replay_input_destroy(input);
        dse_slice_plan_destroy(&plan);
        return result;
    }
    dse_classify_target(&ctx, target, oep_candidate, &result);
    dse_capture_verify_metrics(&result, &ctx, slice_result.len, meta_missing);
    sym_expr_free(target);
    dse_ctx_free(&ctx);
    replay_input_destroy(input);
    dse_slice_plan_destroy(&plan);
    return result;
}

DseVerifyResult dse_verify_oep_candidate(TraceBuffer *tb, const DseAuxRing *ring,
                                         uint64_t trigger_seq_id, RegId target_reg,
                                         uint64_t oep_candidate, ShadowMemory *shadow,
                                         csh cs_handle) {
    return dse_verify_oep_candidate_with_relevance(tb, ring, trigger_seq_id, target_reg,
                                                   oep_candidate, shadow, cs_handle, NULL);
}

DseVerifyResult dse_verify_oep_candidate_mem(TraceBuffer *tb, const DseAuxRing *ring,
                                             uint64_t trigger_seq_id, uint64_t target_addr,
                                             uint64_t oep_candidate, ShadowMemory *shadow,
                                             csh cs_handle) {
    return dse_verify_oep_candidate_mem_with_relevance(tb, ring, trigger_seq_id, target_addr,
                                                       oep_candidate, shadow, cs_handle, NULL);
}
