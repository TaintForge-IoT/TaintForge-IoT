#define _POSIX_C_SOURCE 200809L
#include "ir_smt.h"
#include "ir_internal.h"

#include <z3.h>
#include <stdlib.h>
#include <string.h>

/* Values and validity travel together. Opaque symbols represent missing
 * information, not candidate inputs. A defined query can never rely on them. */
typedef struct {
    IrType type;
    Z3_ast value, mask;
    Z3_ast must_reach, may_reach;
    uint32_t reasons, reach_reasons;
} Sym;

typedef struct {
    bool used;
    uint64_t key;
    Sym sym;
} Binding;

typedef struct {
    IrSmtParameter spec;
    Z3_ast ast;
} Parameter;

struct IrSmt {
    const IrModule *module;
    uint64_t revision;
    IrInputs *inputs;
    IrSmtLimits limits;
    IrSmtInfo info;
    Z3_context ctx;
    Z3_sort bv[65], mem[65];
    /* Fixed-size, context-owned literals for local identities. No global or
     * unbounded term cache; all pointers expire with this backend's context. */
    Z3_ast bv_zero[65], bv_ones[65], bool_literal[2];
    Sym *values, *states, *branches;
    Binding *bindings;
    uint32_t binding_capacity;
    Parameter *parameters;
    uint32_t parameter_count, cell_count;
    bool *selected;
    IrInputId *canonical;
    Z3_ast *cell_symbols;
    Z3_ast must_reach, may_reach;
    uint32_t reach_reasons;
    const char *stage;
    IrInstId instruction;
    bool rc;
    Z3_ast temporaries[256];
    unsigned temporary_count;
    uint32_t *uses;
    IrValueId *query_ids;
    unsigned char *retained;
    uint32_t value_slots, value_id_bound, state_slots, branch_slots;
};

#include "ir_smt_diagnostics.h"

IrSmtLimits ir_smt_default_limits(void) {
    return (IrSmtLimits){UINT64_C(32000000), UINT64_C(2000000), (size_t)64 * 1024 * 1024};
}

IrSmtOptions ir_smt_default_options(void) {
    return (IrSmtOptions){.limits = ir_smt_default_limits()};
}

IrSmtQueryLimits ir_smt_default_query_limits(void) {
    return (IrSmtQueryLimits){UINT64_C(2000000), (size_t)16 * 1024 * 1024, 65536, 65536, 5000,
                              10000000};
}

static bool fail(IrSmt *s, IrStatus status, const char *why) {
    if (s->info.status == IR_OK) {
        s->info.status = status;
        s->info.message = why;
    }
    return false;
}

static bool spend(IrSmt *s, uint64_t n) {
    if (s->info.status != IR_OK)
        return false;
    if (n > s->limits.work - s->info.work)
        return fail(s, IR_RESOURCE_LIMIT, "SMT adapter work budget");
    s->info.work += n;
    return true;
}

static bool construct(IrSmt *s) {
    if (!spend(s, 1))
        return false;
    if (s->info.constructors >= s->limits.constructors)
        return fail(s, IR_RESOURCE_LIMIT, "SMT cumulative constructor budget");
    ++s->info.constructors;
    return true;
}

static bool allocation(IrSmt *s, uint64_t n) {
    if (n > SIZE_MAX || n > s->limits.bytes)
        return fail(s, IR_RESOURCE_LIMIT, "SMT adapter allocation budget");
    if (s->info.bytes < n)
        s->info.bytes = (size_t)n;
    return true;
}

static void z3_error(Z3_context ctx, Z3_error_code code) {
    (void)ctx;
    (void)code;
}

static bool z3_check(IrSmt *s, const char *api, bool null_result) {
    int saved_errno = errno;
    Z3_error_code e = Z3_get_error_code(s->ctx);
    if (e == Z3_OK) return true;
    if (s->info.status == IR_OK) smt_capture_error(s, e, api, null_result, saved_errno);
    return fail(s, e == Z3_MEMOUT_FAIL ? IR_OUT_OF_MEMORY : IR_INVALID, "Z3 API error");
}

static bool z3_ok(IrSmt *s, const char *api) {
    return z3_check(s, api, false);
}

static bool z3_result(IrSmt *s, bool present, const char *api) {
    int saved_errno = errno;
    if (!z3_check(s, api, !present)) return false;
    if (present) return true;
    if (s->info.status == IR_OK) smt_capture_error(s, Z3_OK, api, true, saved_errno);
    return fail(s, IR_OUT_OF_MEMORY, "Z3 object allocation");
}

#include "ir_smt_ownership.h"

static Z3_ast done(IrSmt *s, Z3_ast a, const char *api) {
    return z3_result(s, a != NULL, api) ? temporary(s, a) : NULL;
}

static Z3_sort bvsort(IrSmt *s, unsigned w) {
    if (s->info.status != IR_OK)
        return NULL;
    if (!s->bv[w] && construct(s)) {
        Z3_sort sort = Z3_mk_bv_sort(s->ctx, w);
        if (!z3_result(s, sort != NULL, "Z3_mk_bv_sort")) return NULL;
        if (!hold(s, Z3_sort_to_ast(s->ctx, sort))) return NULL;
        s->bv[w] = sort;
    }
    return s->bv[w];
}

static Z3_sort memsort(IrSmt *s, unsigned w) {
    if (s->info.status != IR_OK)
        return NULL;
    if (!s->mem[w]) {
        Z3_sort a = bvsort(s, w), b = bvsort(s, 8);
        if (a && b && construct(s)) {
            Z3_sort sort = Z3_mk_array_sort(s->ctx, a, b);
            if (!z3_result(s, sort != NULL, "Z3_mk_array_sort")) return NULL;
            if (!hold(s, Z3_sort_to_ast(s->ctx, sort))) return NULL;
            s->mem[w] = sort;
        }
    }
    return s->mem[w];
}

static Z3_ast num(IrSmt *s, unsigned w, uint64_t v) {
    if (!spend(s, 1)) return NULL;
    v &= ir_width_mask(w);
    Z3_ast *cached = v == 0 ? &s->bv_zero[w]
                    : v == ir_width_mask(w) ? &s->bv_ones[w] : NULL;
    if (cached && *cached) return *cached;
    Z3_sort sort = bvsort(s, w);
    Z3_ast result = sort && construct(s)
        ? done(s, Z3_mk_unsigned_int64(s->ctx, v, sort), "Z3_mk_unsigned_int64") : NULL;
    if (cached && result && !assign_ast(s, cached, result)) return NULL;
    return result;
}

static Z3_ast boolean(IrSmt *s, bool v) {
    if (!spend(s, 1)) return NULL;
    if (!s->bool_literal[v] && construct(s))
        assign_ast(s, &s->bool_literal[v], done(s, v ? Z3_mk_true(s->ctx) : Z3_mk_false(s->ctx),
                                  v ? "Z3_mk_true" : "Z3_mk_false"));
    return s->bool_literal[v];
}

/* Inspect only a literal, never evaluate an expression under the recorded
 * execution or ask the solver to simplify it. Widths come from validated IR.
 * Even cache hits and identity checks spend adapter work; constructors count
 * actual Z3 term/sort construction requests. A prior error stays sticky. */
static bool numeral(IrSmt *s, Z3_ast a, unsigned w, uint64_t *value) {
    if (!a || !spend(s, 1)) return false;
    if (a == s->bv_zero[w]) { *value = 0; return true; }
    if (a == s->bv_ones[w]) { *value = ir_width_mask(w); return true; }
    Z3_ast_kind kind = Z3_get_ast_kind(s->ctx, a);
    if (!z3_ok(s, "Z3_get_ast_kind") || kind != Z3_NUMERAL_AST) return false;
    if (!spend(s, 1)) return false;
    bool ok = Z3_get_numeral_uint64(s->ctx, a, value);
    return z3_ok(s, "Z3_get_numeral_uint64") && ok;
}

typedef Z3_ast (*Unary)(Z3_context, Z3_ast);
typedef Z3_ast (*Binary)(Z3_context, Z3_ast, Z3_ast);
typedef Z3_ast (*Ternary)(Z3_context, Z3_ast, Z3_ast, Z3_ast);

static Z3_ast un_named(IrSmt *s, Unary f, const char *api, Z3_ast a) {
    return a && construct(s) ? done(s, f(s->ctx, a), api) : NULL;
}

static Z3_ast bin_named(IrSmt *s, Binary f, const char *api, Z3_ast a, Z3_ast b) {
    return a && b && construct(s) ? done(s, f(s->ctx, a, b), api) : NULL;
}

static Z3_ast tri_named(IrSmt *s, Ternary f, const char *api, Z3_ast a, Z3_ast b, Z3_ast c) {
    return a && b && c && construct(s) ? done(s, f(s->ctx, a, b, c), api) : NULL;
}

#define un(s,f,a) un_named((s),(f),#f,(a))
#define bin(s,f,a,b) bin_named((s),(f),#f,(a),(b))
#define tri(s,f,a,b,c) tri_named((s),(f),#f,(a),(b),(c))

static Z3_ast both(IrSmt *s, Z3_ast a, Z3_ast b) {
    if (!a || !b || !spend(s, 1)) return NULL;
    if (a == b || b == s->bool_literal[1] || a == s->bool_literal[0]) return a;
    if (a == s->bool_literal[1] || b == s->bool_literal[0]) return b;
    Z3_ast args[] = {a, b};
    return construct(s) ? done(s, Z3_mk_and(s->ctx, 2, args), "Z3_mk_and") : NULL;
}

static Z3_ast either(IrSmt *s, Z3_ast a, Z3_ast b) {
    if (!a || !b || !spend(s, 1)) return NULL;
    if (a == b || b == s->bool_literal[0] || a == s->bool_literal[1]) return a;
    if (a == s->bool_literal[0] || b == s->bool_literal[1]) return b;
    Z3_ast args[] = {a, b};
    return construct(s) ? done(s, Z3_mk_or(s->ctx, 2, args), "Z3_mk_or") : NULL;
}

static Z3_ast eq(IrSmt *s, unsigned w, Z3_ast a, Z3_ast b) {
    if (!a || !b || !spend(s, 1)) return NULL;
    if (a == b) return boolean(s, true);
    uint64_t x, y;
    if (numeral(s, a, w, &x) && numeral(s, b, w, &y)) return boolean(s, x == y);
    return bin(s, Z3_mk_eq, a, b);
}

static Z3_ast inv(IrSmt *s, Z3_ast a) {
    if (!a || !spend(s, 1)) return NULL;
    if (a == s->bool_literal[0]) return boolean(s, true);
    if (a == s->bool_literal[1]) return boolean(s, false);
    return un(s, Z3_mk_not, a);
}

static Z3_ast ite(IrSmt *s, Z3_ast a, Z3_ast b, Z3_ast c) {
    if (!a || !b || !c || !spend(s, 1)) return NULL;
    if (b == c || a == s->bool_literal[1]) return b;
    if (a == s->bool_literal[0]) return c;
    return tri(s, Z3_mk_ite, a, b, c);
}

static Z3_ast bv_and(IrSmt *s, unsigned w, Z3_ast a, Z3_ast b) {
    if (!a || !b || !spend(s, 1)) return NULL;
    if (a == b || b == s->bv_ones[w] || a == s->bv_zero[w]) return a;
    if (a == s->bv_ones[w] || b == s->bv_zero[w]) return b;
    uint64_t x, y;
    if (numeral(s, a, w, &x) && numeral(s, b, w, &y)) return num(s, w, x & y);
    return bin(s, Z3_mk_bvand, a, b);
}

static Z3_ast bv_or(IrSmt *s, unsigned w, Z3_ast a, Z3_ast b) {
    if (!a || !b || !spend(s, 1)) return NULL;
    if (a == b || b == s->bv_zero[w] || a == s->bv_ones[w]) return a;
    if (a == s->bv_zero[w] || b == s->bv_ones[w]) return b;
    uint64_t x, y;
    if (numeral(s, a, w, &x) && numeral(s, b, w, &y)) return num(s, w, x | y);
    return bin(s, Z3_mk_bvor, a, b);
}

static Z3_ast bv_xor(IrSmt *s, unsigned w, Z3_ast a, Z3_ast b) {
    if (!a || !b || !spend(s, 1)) return NULL;
    if (a == b) return num(s, w, 0);
    if (a == s->bv_zero[w]) return b;
    if (b == s->bv_zero[w]) return a;
    uint64_t x, y;
    if (numeral(s, a, w, &x) && numeral(s, b, w, &y)) return num(s, w, x ^ y);
    return bin(s, Z3_mk_bvxor, a, b);
}

static Z3_ast bv_not(IrSmt *s, unsigned w, Z3_ast a) {
    if (!a || !spend(s, 1)) return NULL;
    uint64_t x;
    if (numeral(s, a, w, &x)) return num(s, w, ~x);
    return un(s, Z3_mk_bvnot, a);
}

static Z3_ast extract(IrSmt *s, unsigned from, Z3_ast a, unsigned low, unsigned w) {
    if (!a || !spend(s, 1)) return NULL;
    if (!low && from == w) return a;
    uint64_t x;
    if (numeral(s, a, from, &x)) return num(s, w, x >> low);
    return construct(s) ? done(s, Z3_mk_extract(s->ctx, low + w - 1, low, a), "Z3_mk_extract") : NULL;
}

static Z3_ast extend(IrSmt *s, unsigned from, Z3_ast a, unsigned n, bool sign) {
    if (!a || !spend(s, 1)) return NULL;
    if (!n)
        return a;
    uint64_t x;
    if (numeral(s, a, from, &x)) {
        if (sign && (x & (UINT64_C(1) << (from - 1)))) x |= ~ir_width_mask(from);
        return num(s, from + n, x);
    }
    return construct(s)
               ? done(s, sign ? Z3_mk_sign_ext(s->ctx, n, a) : Z3_mk_zero_ext(s->ctx, n, a), sign ? "Z3_mk_sign_ext" : "Z3_mk_zero_ext")
               : NULL;
}

static Z3_ast concat(IrSmt *s, unsigned high, unsigned low, Z3_ast a, Z3_ast b) {
    if (!a || !b || !spend(s, 1)) return NULL;
    uint64_t x, y;
    if (numeral(s, a, high, &x) && numeral(s, b, low, &y))
        return num(s, high + low, (x << low) | y);
    return bin(s, Z3_mk_concat, a, b);
}

static Z3_ast shift(IrSmt *s, unsigned w, IrOpcode op, Z3_ast a, Z3_ast b) {
    if (!a || !b || !spend(s, 1)) return NULL;
    uint64_t x, n;
    if (numeral(s, b, w, &n)) {
        if (!n) return a;
        if (n >= w && op != IR_OP_ASHR) return num(s, w, 0);
        if (numeral(s, a, w, &x)) {
            bool sign = op == IR_OP_ASHR && (x & (UINT64_C(1) << (w - 1)));
            if (n >= w) return num(s, w, sign ? UINT64_MAX : 0);
            uint64_t result = op == IR_OP_SHL ? x << n : x >> n;
            if (sign) result |= UINT64_MAX << (w - (unsigned)n);
            return num(s, w, result);
        }
    }
    Binary f = op == IR_OP_SHL ? Z3_mk_bvshl
               : op == IR_OP_LSHR ? Z3_mk_bvlshr : Z3_mk_bvashr;
    const char *api = op == IR_OP_SHL ? "Z3_mk_bvshl"
                      : op == IR_OP_LSHR ? "Z3_mk_bvlshr" : "Z3_mk_bvashr";
    return bin_named(s, f, api, a, b);
}

static Z3_ast fresh(IrSmt *s, IrType t, const char *prefix) {
    Z3_sort sort = t.kind == IR_TYPE_MEM ? memsort(s, t.bits) : bvsort(s, t.bits);
    return sort && construct(s) ? done(s, Z3_mk_fresh_const(s->ctx, prefix, sort), "Z3_mk_fresh_const") : NULL;
}

static Z3_ast zero_memory_mask(IrSmt *s, unsigned w) {
    Z3_sort sort = bvsort(s, w);
    Z3_ast z = num(s, 8, 0);
    return sort && z && construct(s) ? done(s, Z3_mk_const_array(s->ctx, sort, z), "Z3_mk_const_array") : NULL;
}

static Z3_ast defined_memory_mask(IrSmt *s, unsigned w) {
    Z3_sort sort = bvsort(s, w);
    Z3_ast byte = num(s, 8, 255);
    return sort && byte && construct(s) ? done(s, Z3_mk_const_array(s->ctx, sort, byte), "Z3_mk_const_array") : NULL;
}

static Z3_ast full(IrSmt *s, Sym a) {
    return eq(s, a.type.bits, a.mask, num(s, a.type.bits, UINT64_MAX));
}

static Z3_ast truth(IrSmt *s, Sym a) {
    return eq(s, 1, a.value, num(s, 1, 1));
}

static Z3_ast known_number(IrSmt *s, Sym a, uint64_t n) {
    return both(s, full(s, a), eq(s, a.type.bits, a.value, num(s, a.type.bits, n)));
}

static Z3_ast bit(IrSmt *s, Z3_ast b) {
    return ite(s, b, num(s, 1, 1), num(s, 1, 0));
}

static Sym opaque(IrSmt *s, IrType t, uint32_t reasons) {
    return (Sym){.type = t,
                 .value = fresh(s, t, "opaque"),
                 .mask = t.kind == IR_TYPE_MEM ? zero_memory_mask(s, t.bits) : num(s, t.bits, 0),
                 .reasons = reasons};
}

static Sym boundary_bv(IrSmt *s, unsigned w, IrBits bits, bool selected, const char *name) {
    Sym r = {.type = ir_type_bv(w)};
    uint64_t mask = ir_width_mask(w);
    if (selected) {
        r.value = fresh(s, r.type, name);
        r.mask = num(s, w, mask);
    } else {
        r.mask = num(s, w, bits.known_mask);
        r.value = num(s, w, bits.value & bits.known_mask);
        if ((bits.known_mask & mask) != mask) {
            Z3_ast unknown = fresh(s, r.type, "unbound");
            r.value = bv_or(s, w, r.value, bv_and(s, w, unknown, num(s, w, ~bits.known_mask)));
            r.reasons = bits.reasons ? bits.reasons : IR_REASON_UNBOUND_INPUT;
        }
    }
    return r;
}

static bool valid_bits(IrBits b, unsigned w) {
    return !((b.known_mask | b.value) & ~ir_width_mask(w)) && !(b.value & ~b.known_mask);
}

static Binding *binding(IrSmt *s, uint64_t key) {
    uint32_t slot = (uint32_t)((key ^ (key >> 32)) % s->binding_capacity);
    while (spend(s, 1)) {
        Binding *b = &s->bindings[slot];
        if (!b->used || b->key == key)
            return b;
        if (++slot == s->binding_capacity)
            slot = 0;
    }
    return NULL;
}

static bool initial_inputs(IrSmt *s, const IrSmtOptions *o) {
    const IrModule *m = s->module;
    for (uint32_t i = 0; i < o->symbolic_count; ++i) {
        if (!spend(s, 1))
            return false;
        IrInputId id = o->symbolic_inputs[i];
        if (!id || id > s->cell_count || s->selected[id])
            return fail(s, IR_INVALID, "invalid or duplicate symbolic InputId");
        s->selected[id] = true;
        const IrInputCell *c = ir_inputs_cell(s->inputs, id);
        if (!c) return fail(s, IR_INVALID, "missing symbolic cell");
        if (!assign_ast(s, &s->cell_symbols[id], fresh(s, ir_type_bv(c->width), "input"))) return false;
        clear_temporaries(s);
    }
    s->info.symbolic_inputs = o->symbolic_count;
    for (uint32_t i = 0; i < o->alias_count; ++i) {
        if (!spend(s, 1)) return false;
        IrSmtInputAlias a = o->aliases[i];
        if (!a.input || !a.canonical || a.input > s->cell_count ||
            a.canonical > s->cell_count || a.input == a.canonical ||
            !s->selected[a.input] || !s->selected[a.canonical] || s->canonical[a.input])
            return fail(s, IR_INVALID, "invalid or duplicate input alias");
        const IrInputCell *c = ir_inputs_cell(s->inputs, a.input);
        const IrInputCell *root = ir_inputs_cell(s->inputs, a.canonical);
        if (c->width != root->width || !ir_bits_complete(c->observed, c->width) ||
            !ir_bits_complete(root->observed, root->width) || c->observed.value != root->observed.value)
            return fail(s, IR_INVALID, "input alias observation mismatch");
        s->canonical[a.input] = a.canonical;
    }
    for (uint32_t i = 0; i < o->alias_count; ++i) {
        if (!spend(s, 1)) return false;
        IrSmtInputAlias a = o->aliases[i];
        if (s->canonical[a.canonical])
            return fail(s, IR_INVALID, "input alias chains or cycles are unsupported");
        if (!assign_ast(s, &s->cell_symbols[a.input], s->cell_symbols[a.canonical])) return false;
    }
    s->info.input_aliases = o->alias_count;
    for (uint32_t i = 0; i < m->state_count; ++i) {
        if (!spend(s, 1))
            return false;
        if (!assign_sym(s, &s->states[i], opaque(s, m->states[i].type, IR_REASON_UNBOUND_STATE))) return false;
        clear_temporaries(s);
    }
    for (uint32_t i = 0; i < ir_inputs_state_count(s->inputs); ++i) {
        if (!spend(s, 1))
            return false;
        const IrInputState *st = ir_inputs_state_at(s->inputs, i);
        const IrState *state = ir_module_state(m, st->state);
        if (!state || st->key != state->key || !ir_type_equal(st->type, state->type))
            return fail(s, IR_INVALID, "input catalogue state contract mismatch");
        if (st->type.kind == IR_TYPE_BV) {
            /* A sealed catalogue supplies a complete partition. Start from
             * zero and insert every slice below, including unknown slices. */
            if (!assign_ast(s, &s->states[st->state - 1].value, num(s, st->type.bits, 0)) ||
                !assign_ast(s, &s->states[st->state - 1].mask, num(s, st->type.bits, 0))) return false;
            s->states[st->state - 1].reasons = 0;
            clear_temporaries(s);
        }
    }
    for (IrInputId id = 1; id <= s->cell_count; ++id) {
        if (!spend(s, 1))
            return false;
        const IrInputCell *c = ir_inputs_cell(s->inputs, id);
        if (!c || !c->state || c->state > m->state_count)
            return fail(s, IR_INVALID, "unsealed or incompatible input catalogue");
        Sym v = s->selected[id]
            ? (Sym){.type = ir_type_bv(c->width), .value = s->cell_symbols[id],
                    .mask = num(s, c->width, ir_width_mask(c->width))}
            : boundary_bv(s, c->width, c->observed, false, "input");
        Sym *r = &s->states[c->state - 1];
        if (c->kind == IR_INPUT_MEMORY_BYTE) {
            Z3_ast addr = num(s, r->type.bits, c->address);
            if (!assign_ast(s, &r->value, tri(s, Z3_mk_store, r->value, addr, v.value)) ||
                !assign_ast(s, &r->mask, tri(s, Z3_mk_store, r->mask, addr, v.mask))) return false;
        } else {
            unsigned ext = r->type.bits - c->width;
            Z3_ast amount = num(s, r->type.bits, c->bit_offset);
            Z3_ast value = shift(s, r->type.bits, IR_OP_SHL,
                                 extend(s, v.type.bits, v.value, ext, false), amount);
            Z3_ast mask = shift(s, r->type.bits, IR_OP_SHL,
                                extend(s, v.type.bits, v.mask, ext, false), amount);
            if (!assign_ast(s, &r->value, bv_or(s, r->type.bits, r->value, value)) ||
                !assign_ast(s, &r->mask, bv_or(s, r->type.bits, r->mask, mask))) return false;
        }
        r->reasons |= v.reasons;
        clear_temporaries(s);
    }
    for (uint32_t i = 0; i < o->parameter_count; ++i) {
        if (!spend(s, 1))
            return false;
        IrSmtParameter p = o->parameters[i];
        if (!p.width || p.width > 64 || !valid_bits(p.observed, p.width))
            return fail(s, IR_INVALID, "invalid INPUT parameter");
        Binding *b = binding(s, p.key);
        if (!b)
            return false;
        if (b->used)
            return fail(s, IR_INVALID, "duplicate INPUT parameter key");
        b->used = true;
        b->key = p.key;
        if (!assign_sym(s, &b->sym, boundary_bv(s, p.width, p.observed, p.symbolic, "parameter"))) return false;
        s->parameters[i].spec = p;
        if (!assign_ast(s, &s->parameters[i].ast, b->sym.value)) return false;
        if (p.symbolic)
            ++s->info.symbolic_parameters;
        clear_temporaries(s);
    }
    return s->info.status == IR_OK;
}

static Sym arithmetic(IrSmt *s, const IrInstSpec *ins, Sym v[3]) {
    unsigned w = ins->type.bits;
    Sym a = v[0], b = v[1], c = v[2];
    Sym r = {.type = ins->type, .reasons = a.reasons | b.reasons | c.reasons};
    IrValueId identity = ir_identity_operand(s->module, ins);
    if (identity)
        for (unsigned i = 0; i < ir_opcode_arity(ins->op); ++i)
            if (ins->args[i] == identity)
                return v[i];
    if (ins->args[0] && ins->args[0] == ins->args[1]) {
        if (ins->op == IR_OP_XOR || ins->op == IR_OP_SUB || ins->op == IR_OP_ULT ||
            ins->op == IR_OP_SLT || ins->op == IR_OP_EQ) {
            r.value = num(s, w, ins->op == IR_OP_EQ);
            r.mask = num(s, w, UINT64_MAX);
            r.reasons = 0;
            return r;
        }
    }
    /* Prepare only the validity terms used by this opcode. In particular,
     * bitwise operations and casts compute their masks below and do not use
     * the all-or-nothing default. Constructing that default unconditionally
     * consumes the cumulative budget and retains unused ASTs in the context. */
    Z3_ast zero = NULL, ones = NULL, f0 = NULL, f1 = NULL;
    switch (ins->op) {
    case IR_OP_ADD:
    case IR_OP_SUB:
    case IR_OP_MUL:
    case IR_OP_NEG:
    case IR_OP_ULT:
    case IR_OP_SLT:
        zero = num(s, w, 0);
        ones = num(s, w, UINT64_MAX);
        f0 = full(s, a);
        f1 = b.value ? full(s, b) : NULL;
        r.mask = ite(s, f1 ? both(s, f0, f1) : f0, ones, zero);
        break;
    case IR_OP_SHL:
    case IR_OP_LSHR:
    case IR_OP_ASHR:
        zero = num(s, w, 0);
        ones = num(s, w, UINT64_MAX);
        f1 = full(s, b);
        break;
    case IR_OP_EQ:
        f0 = full(s, a);
        f1 = full(s, b);
        break;
    case IR_OP_ITE:
        f0 = full(s, a);
        break;
    default:
        break;
    }
    switch (ins->op) {
    case IR_OP_COPY:
        return a;
    case IR_OP_ADD:
        r.value = bin(s, Z3_mk_bvadd, a.value, b.value);
        r.mask =
            ite(s, known_number(s, a, 0), b.mask, ite(s, known_number(s, b, 0), a.mask, r.mask));
        break;
    case IR_OP_SUB:
        r.value = bin(s, Z3_mk_bvsub, a.value, b.value);
        r.mask = ite(s, known_number(s, b, 0), a.mask, r.mask);
        break;
    case IR_OP_MUL:
        r.value = bin(s, Z3_mk_bvmul, a.value, b.value);
        r.mask = ite(
            s, either(s, known_number(s, a, 0), known_number(s, b, 0)), ones,
            ite(s, known_number(s, a, 1), b.mask, ite(s, known_number(s, b, 1), a.mask, r.mask)));
        break;
    case IR_OP_AND:
        r.value = bv_and(s, w, a.value, b.value);
        r.mask = bv_or(
            s, w, bv_and(s, w, a.mask, b.mask),
            bv_or(s, w, bv_and(s, w, a.mask, bv_not(s, w, a.value)), bv_and(s, w, b.mask, bv_not(s, w, b.value))));
        break;
    case IR_OP_OR:
        r.value = bv_or(s, w, a.value, b.value);
        r.mask = bv_or(s, w, bv_and(s, w, a.mask, b.mask),
                       bv_or(s, w, bv_and(s, w, a.mask, a.value), bv_and(s, w, b.mask, b.value)));
        break;
    case IR_OP_XOR:
        r.value = bv_xor(s, w, a.value, b.value);
        r.mask = bv_and(s, w, a.mask, b.mask);
        break;
    case IR_OP_NOT:
        r.value = bv_not(s, w, a.value);
        r.mask = a.mask;
        break;
    case IR_OP_NEG:
        r.value = un(s, Z3_mk_bvneg, a.value);
        break;
    case IR_OP_SHL:
    case IR_OP_LSHR:
    case IR_OP_ASHR: {
        r.value = shift(s, w, ins->op, a.value, b.value);
        IrOpcode mask_op = ins->op == IR_OP_SHL ? IR_OP_SHL : IR_OP_LSHR;
        Z3_ast shifted = shift(s, w, mask_op, a.mask, b.value);
        Z3_ast fill = bv_not(s, w, shift(s, w, mask_op, ones, b.value));
        if (ins->op == IR_OP_ASHR)
            fill = ite(s, eq(s, 1, extract(s, w, a.mask, w - 1, 1), num(s, 1, 1)), fill, zero);
        r.mask = ite(s, f1, bv_or(s, w, shifted, fill), zero);
        break;
    }
    case IR_OP_EXTRACT:
        r.value = extract(s, a.type.bits, a.value, (unsigned)ins->immediate, w);
        r.mask = extract(s, a.type.bits, a.mask, (unsigned)ins->immediate, w);
        break;
    case IR_OP_CONCAT:
        r.value = concat(s, a.type.bits, b.type.bits, a.value, b.value);
        r.mask = concat(s, a.type.bits, b.type.bits, a.mask, b.mask);
        break;
    case IR_OP_ZEXT:
    case IR_OP_SEXT: {
        bool sign = ins->op == IR_OP_SEXT;
        r.value = extend(s, a.type.bits, a.value, w - a.type.bits, sign);
        r.mask = extend(s, a.type.bits, a.mask, w - a.type.bits, sign);
        if (!sign)
            r.mask = bv_or(s, w, r.mask, num(s, w, ~ir_width_mask(a.type.bits)));
        break;
    }
    case IR_OP_EQ:
        r.value = bit(s, eq(s, a.type.bits, a.value, b.value));
        r.mask = bit(
            s,
            either(s, both(s, f0, f1),
                   inv(s, eq(s, a.type.bits, bv_and(s, a.type.bits, bv_xor(s, a.type.bits, a.value, b.value), bv_and(s, a.type.bits, a.mask, b.mask)),
                             num(s, a.type.bits, 0)))));
        break;
    case IR_OP_ULT:
    case IR_OP_SLT:
        r.value =
            bit(s, bin_named(s, ins->op == IR_OP_ULT ? Z3_mk_bvult : Z3_mk_bvslt, ins->op == IR_OP_ULT ? "Z3_mk_bvult" : "Z3_mk_bvslt", a.value, b.value));
        break;
    case IR_OP_ITE:
        r.value = ite(s, truth(s, a), b.value, c.value);
        r.mask = ite(s, f0, ite(s, truth(s, a), b.mask, c.mask),
                     bv_and(s, w, bv_and(s, w, b.mask, c.mask), bv_not(s, w, bv_xor(s, w, b.value, c.value))));
        break;
    default:
        fail(s, IR_INVALID, "unsupported BV opcode");
        break;
    }
    return r;
}

static Sym memory(IrSmt *s, const IrInstSpec *ins, Sym v[3]) {
    Sym r = {.type = ins->type,
             .reasons = v[0].reasons | v[1].reasons | v[2].reasons | IR_REASON_MEMORY};
    if (ins->op == IR_OP_ITE) {
        if (v[1].value == v[2].value && v[1].mask == v[2].mask)
            return v[1];
        r.value = ite(s, truth(s, v[0]), v[1].value, v[2].value);
        r.mask = ite(s, full(s, v[0]), ite(s, truth(s, v[0]), v[1].mask, v[2].mask),
                     zero_memory_mask(s, r.type.bits));
        return r;
    }
    bool store = ins->op == IR_OP_STORE;
    unsigned w = store ? v[2].type.bits : r.type.bits;
    unsigned aw = v[1].type.bits;
    if (store) {
        r.value = v[0].value;
        r.mask = v[0].mask;
    }
    for (unsigned i = 0; i < w / 8; ++i) {
        Z3_ast addr = bin(s, Z3_mk_bvadd, v[1].value, num(s, aw, i));
        unsigned shift = 8 * (ins->endian == IR_ENDIAN_LE ? i : w / 8 - i - 1);
        if (store) {
            r.value = tri(s, Z3_mk_store, r.value, addr, extract(s, v[2].type.bits, v[2].value, shift, 8));
            r.mask = tri(s, Z3_mk_store, r.mask, addr, extract(s, v[2].type.bits, v[2].mask, shift, 8));
        } else {
            Z3_ast value = bin(s, Z3_mk_select, v[0].value, addr);
            Z3_ast mask = bin(s, Z3_mk_select, v[0].mask, addr);
            if (!i) {
                r.value = value;
                r.mask = mask;
            } else if (ins->endian == IR_ENDIAN_LE) {
                r.value = concat(s, 8, 8 * i, value, r.value);
                r.mask = concat(s, 8, 8 * i, mask, r.mask);
            } else {
                r.value = concat(s, 8 * i, 8, r.value, value);
                r.mask = concat(s, 8 * i, 8, r.mask, mask);
            }
        }
    }
    r.mask = ite(s, full(s, v[1]), r.mask, store ? zero_memory_mask(s, aw) : num(s, w, 0));
    return r;
}

static void reach_guard(IrSmt *s, Sym condition, bool taken, bool same_target, uint32_t reasons) {
    Z3_ast f = full(s, condition), t = truth(s, condition);
    if (!taken)
        t = inv(s, t);
    assign_ast(s, &s->must_reach, both(s, s->must_reach, same_target ? f : both(s, f, t)));
    if (!same_target)
        assign_ast(s, &s->may_reach, both(s, s->may_reach, either(s, inv(s, f), t)));
    s->reach_reasons |= condition.reasons | reasons;
}

static bool lower(IrSmt *s) {
    const IrModule *m = s->module;
    s->stage = "lower_initialization"; s->instruction = 0;
    if (!assign_ast(s, &s->must_reach, boolean(s, true)) ||
        !assign_ast(s, &s->may_reach, s->must_reach)) return false;
    clear_temporaries(s);
    IrBlockId block = m->entry;
    bool halted = false;
    for (uint32_t k = 0; k < m->block_count; ++k) {
        for (IrInstId id = m->blocks[block - 1].first; id; id = m->insts[id - 1].next) {
            if (!spend(s, 1))
                return false;
            const IrInst *inst = &m->insts[id - 1];
            if (inst->removed)
                continue;
            const IrInstSpec *ins = &inst->spec;
            s->info.origin = ins->origin;
            s->stage = "lower_instruction"; s->instruction = id;
            Sym v[3] = {0}, r = {.type = ins->type};
            for (unsigned i = 0; i < ir_opcode_arity(ins->op); ++i)
                v[i] = s->values[ins->args[i] - 1];
            if (halted) {
                /* An opaque effect may invalidate subsequent state/control.
                 * Do not prove UNSAT from the stale pre-barrier snapshot. */
                if (inst->result) r = opaque(s, ins->type, s->reach_reasons);
            } else
                switch (ins->op) {
                case IR_OP_CONST:
                    r.value = num(s, ins->type.bits, ins->immediate);
                    r.mask = num(s, ins->type.bits, UINT64_MAX);
                    break;
                case IR_OP_ZERO_MEMORY:
                    r.value = zero_memory_mask(s, ins->type.bits);
                    r.mask = defined_memory_mask(s, ins->type.bits);
                    break;
                case IR_OP_INPUT: {
                    Binding *b = binding(s, ins->immediate);
                    if (!b)
                        return false;
                    if (!b->used) {
                        b->used = true;
                        b->key = ins->immediate;
                        if (!assign_sym(s, &b->sym, opaque(s, ins->type, IR_REASON_UNBOUND_INPUT))) return false;
                    }
                    if (!ir_type_equal(b->sym.type, ins->type))
                        return fail(s, IR_INVALID, "INPUT key type mismatch");
                    r = b->sym;
                    break;
                }
                case IR_OP_UNKNOWN:
                    r = opaque(s, ins->type, (uint32_t)ins->immediate);
                    break;
                case IR_OP_COPY:
                    r = v[0];
                    break;
                case IR_OP_READ_STATE:
                    r = s->states[ins->state - 1];
                    break;
                case IR_OP_WRITE_STATE:
                    if (!assign_sym(s, &s->states[ins->state - 1], v[0])) return false;
                    break;
                case IR_OP_GUARD:
                    reach_guard(s, v[0], true, false, (uint32_t)ins->immediate | IR_REASON_GUARD);
                    break;
                case IR_OP_BARRIER:
                    assign_ast(s, &s->must_reach, boolean(s, false));
                    s->reach_reasons |= (uint32_t)ins->immediate;
                    halted = true;
                    break;
                case IR_OP_LOAD:
                case IR_OP_STORE:
                    r = memory(s, ins, v);
                    break;
                default:
                    r = ins->type.kind == IR_TYPE_MEM ? memory(s, ins, v) : arithmetic(s, ins, v);
                    break;
                }
            if (s->info.status != IR_OK)
                return false;
            if (inst->result) {
                if (!r.value || !r.mask)
                    return fail(s, IR_INVALID, "missing lowered value");
                r.must_reach = s->must_reach;
                r.may_reach = s->may_reach;
                r.reach_reasons = s->reach_reasons;
                if (!assign_sym(s, &s->values[inst->result - 1], r)) return false;
                ++s->info.values_live;
                if (s->info.values_peak < s->info.values_live) s->info.values_peak = s->info.values_live;
                ++s->info.lowered_values;
            }
            clear_temporaries(s);
            for (unsigned i = 0; i < ir_opcode_arity(ins->op); ++i)
                if (!consume_value(s, ins->args[i])) return false;
            if (inst->result) release_value(s, inst->result);
        }
        if (!spend(s, 1))
            return false;
        s->stage = "lower_terminator"; s->instruction = 0;
        const IrTerminator *t = &m->blocks[block - 1].terminator;
        if (t->kind == IR_TERM_CJUMP) {
            s->info.origin = t->origin;
            Sym condition =
                halted ? opaque(s, ir_type_bv(1), s->reach_reasons) : s->values[t->condition - 1];
            condition.must_reach = s->must_reach;
            condition.may_reach = s->may_reach;
            condition.reach_reasons = s->reach_reasons;
            if (!assign_sym(s, &s->branches[block - 1], condition)) return false;
        }
        bool valid;
        IrBlockId next = ir_trace_next(t, &valid);
        if (!halted && next && t->kind == IR_TERM_CJUMP) {
            bool yes = t->successors[0].kind == IR_TARGET_BLOCK;
            bool same = yes && t->successors[1].kind == IR_TARGET_BLOCK;
            s->info.origin = t->origin;
            reach_guard(s, s->values[t->condition - 1], yes, same, IR_REASON_TARGET);
        }
        clear_temporaries(s);
        if (t->kind == IR_TERM_CJUMP && !consume_value(s, t->condition)) return false;
        block = next;
    }
    return s->info.status == IR_OK;
}

IrSmt *ir_smt_build(const IrModule *m, const IrInputs *inputs, const IrSmtOptions *options,
                    IrSmtInfo *info) {
    IrSmtOptions o = options ? *options : ir_smt_default_options();
    IrSmt initial = {.module = m, .limits = o.limits, .info = {.message = "ok"}, .stage = "setup"};
    IrSmt *s = &initial, *result = NULL;
    uint32_t *rank = NULL;
    if (!m || (o.symbolic_count && !o.symbolic_inputs) || (o.parameter_count && !o.parameters) ||
        (o.alias_count && !o.aliases) || o.alias_count > o.symbolic_count ||
        (o.retained_value_count && !o.retained_values) ||
        (o.retained_values_only && o.legacy_context) ||
        (!o.retained_values_only && o.retained_value_count)) {
        fail(s, IR_INVALID, "missing module or option array");
        goto end;
    }
    if (!spend(s, 4 * (uint64_t)m->inst_count + 4 * (uint64_t)m->block_count + m->value_count +
                      m->state_count + m->output_count + 1) ||
        !allocation(s, sizeof(*s) + (uint64_t)m->state_count + 1))
        goto end;
    IrDiagnostic d;
    if (!ir_validate(m, &d)) {
        fail(s, d.status, d.message);
        goto end;
    }
    IrInputInfo ci = ir_inputs_info(inputs);
    if (inputs && !ir_inputs_ready(inputs)) {
        fail(s, IR_INVALID, "input catalogue not ready");
        goto end;
    }
    /* Binding slots serve IR_OP_INPUT keys, not every SSA value. Counting
     * active occurrences conservatively bounds distinct keys without a
     * multi-gigabyte empty table on long traces with no INPUT operations. */
    if (!spend(s, m->inst_count)) goto end;
    uint64_t input_ops = 0;
    for (uint32_t i = 0; i < m->inst_count; ++i)
        if (!m->insts[i].removed && m->insts[i].spec.op == IR_OP_INPUT) ++input_ops;
    uint64_t capacity = 2 * (input_ops + o.parameter_count) + 1;
    if (capacity > UINT32_MAX) {
        fail(s, IR_RESOURCE_LIMIT, "INPUT table capacity overflow");
        goto end;
    }
    uint64_t bytes =
        sizeof(*s) +
        ((uint64_t)m->value_count + m->state_count + m->block_count + 3) * sizeof(Sym) +
        capacity * sizeof(Binding) + ((uint64_t)o.parameter_count + 1) * sizeof(Parameter) +
        ((uint64_t)ci.count + 1) * (sizeof(bool) + sizeof(Z3_ast) + sizeof(IrInputId)) +
        ((uint64_t)m->block_count + 1) * sizeof(*rank);
    if (o.retained_values_only)
        bytes += ((uint64_t)m->value_count + 1) * sizeof(uint32_t) + (uint64_t)m->value_count / 8 + 1;
    if (!allocation(s, bytes))
        goto end;
    result = calloc(1, sizeof(*result));
    if (!result) {
        fail(s, IR_OUT_OF_MEMORY, "SMT owner allocation");
        goto end;
    }
    *result = initial;
    s = result;
    s->rc = !o.legacy_context;
    s->info.reference_counted = s->rc;
    s->info.retained_values_only = o.retained_values_only;
    s->revision = m->revision;
    s->value_slots = m->value_count;
    s->value_id_bound = m->value_count;
    s->state_slots = m->state_count;
    s->branch_slots = m->block_count;
    s->inputs = ir_inputs_retain(inputs);
    s->cell_count = ci.count;
    s->parameter_count = o.parameter_count;
    s->binding_capacity = (uint32_t)capacity;
    s->values = calloc((size_t)m->value_count + 1, sizeof(*s->values));
    s->info.value_table_bytes = ((uint64_t)m->value_count + 1) * sizeof(*s->values);
    s->states = calloc((size_t)m->state_count + 1, sizeof(*s->states));
    s->branches = calloc((size_t)m->block_count + 1, sizeof(*s->branches));
    s->bindings = calloc((size_t)capacity, sizeof(*s->bindings));
    s->parameters = calloc((size_t)o.parameter_count + 1, sizeof(*s->parameters));
    s->selected = calloc((size_t)ci.count + 1, sizeof(*s->selected));
    s->canonical = calloc((size_t)ci.count + 1, sizeof(*s->canonical));
    s->cell_symbols = calloc((size_t)ci.count + 1, sizeof(*s->cell_symbols));
    rank = calloc((size_t)m->block_count + 1, sizeof(*rank));
    if (o.retained_values_only) {
        s->uses = calloc((size_t)m->value_count + 1, sizeof(*s->uses));
        s->retained = calloc((size_t)m->value_count / 8 + 1, 1);
        s->info.value_index_bytes = ((uint64_t)m->value_count + 1) * sizeof(*s->uses);
    }
    if (!s->values || !s->states || !s->branches || !s->bindings || !s->parameters ||
        !s->selected || !s->canonical || !s->cell_symbols || !rank ||
        (o.retained_values_only && (!s->uses || !s->retained))) {
        fail(s, IR_OUT_OF_MEMORY, "SMT arrays allocation");
        goto end;
    }
    if (!ir_trace_shape(m, rank, false)) {
        fail(s, IR_INVALID, "SMT requires an acyclic trace chain without joins/unreachable blocks");
        goto end;
    }
    if (!prepare_uses(s, &o)) goto end;
    Z3_config config = Z3_mk_config();
    if (!config) {
        smt_capture_error(s, Z3_OK, "Z3_mk_config", true, errno);
        fail(s, IR_OUT_OF_MEMORY, "Z3 configuration allocation");
        goto end;
    }
    s->ctx = s->rc ? Z3_mk_context_rc(config) : Z3_mk_context(config);
    int context_errno = errno;
    Z3_del_config(config);
    if (!s->ctx) {
        smt_capture_error(s, Z3_OK, s->rc ? "Z3_mk_context_rc" : "Z3_mk_context", true, context_errno);
        fail(s, IR_OUT_OF_MEMORY, "Z3 context allocation");
        goto end;
    }
    Z3_set_error_handler(s->ctx, z3_error);
    if (!z3_ok(s, "Z3_set_error_handler")) goto end;
    s->stage = "input_initialization";
    if (!initial_inputs(s, &o) || !lower(s))
        goto end;
    if (!compact_values(s)) goto end;
    s->info.origin = (IrOrigin){0};
end:
    free(rank);
    if (result) {
        clear_temporaries(s);
        /* After successful compaction these counts became query_ids. A failed
         * build still releases the original count array here. */
        free(s->uses);
        s->uses = NULL;
    }
    if (info)
        *info = s->info;
    if (s->info.status != IR_OK) {
        ir_smt_destroy(result);
        result = NULL;
    }
    return result;
}

void ir_smt_destroy(IrSmt *s) {
    if (!s)
        return;
    if (s->ctx && s->rc) {
        /* Balance persistent roots before deleting the context, including on
         * partial builds and stale modules. No fallible cleanup budget. */
        clear_temporaries(s);
        Sym *arrays[] = {s->values, s->states, s->branches};
        uint32_t counts[] = {s->value_slots, s->state_slots, s->branch_slots};
        for (unsigned a = 0; a < 3; ++a) if (arrays[a])
            for (uint32_t i = 0; i < counts[a]; ++i) {
                Sym v = arrays[a][i];
                drop(s, v.value); drop(s, v.mask); drop(s, v.must_reach); drop(s, v.may_reach);
            }
        if (s->bindings) for (uint32_t i = 0; i < s->binding_capacity; ++i) {
            Sym v = s->bindings[i].sym;
            drop(s, v.value); drop(s, v.mask); drop(s, v.must_reach); drop(s, v.may_reach);
        }
        if (s->parameters) for (uint32_t i = 0; i < s->parameter_count; ++i) drop(s, s->parameters[i].ast);
        if (s->cell_symbols) for (uint32_t i = 1; i <= s->cell_count; ++i) drop(s, s->cell_symbols[i]);
        drop(s, s->must_reach); drop(s, s->may_reach);
        for (unsigned i = 0; i <= 64; ++i) {
            drop(s, s->bv_zero[i]); drop(s, s->bv_ones[i]);
            if (s->mem[i]) drop(s, Z3_sort_to_ast(s->ctx, s->mem[i]));
            if (s->bv[i]) drop(s, Z3_sort_to_ast(s->ctx, s->bv[i]));
        }
        drop(s, s->bool_literal[0]); drop(s, s->bool_literal[1]);
    }
    if (s->ctx)
        Z3_del_context(s->ctx);
    ir_inputs_release(s->inputs);
    free(s->values);
    free(s->states);
    free(s->branches);
    free(s->bindings);
    free(s->parameters);
    free(s->selected);
    free(s->canonical);
    free(s->cell_symbols);
    free(s->uses);
    free(s->query_ids);
    free(s->retained);
    free(s);
}

bool ir_smt_current(const IrSmt *s) {
    return s && s->revision == ir_module_revision(s->module) &&
           ir_module_status(s->module) == IR_OK;
}

IrSmtInfo ir_smt_info(const IrSmt *s) {
    return s ? s->info : (IrSmtInfo){.status = IR_INVALID, .message = "missing SMT backend"};
}

static IrSmtStatus status_from_ir(IrStatus status) {
    return status == IR_RESOURCE_LIMIT  ? IR_SMT_RESOURCE_LIMIT
           : status == IR_OUT_OF_MEMORY ? IR_SMT_OUT_OF_MEMORY
                                        : IR_SMT_INVALID;
}

static void answer_error(IrSmtAnswer *a, IrSmtStatus status, const char *why) {
    a->status = status;
    snprintf(a->diagnostic, sizeof(a->diagnostic), "%s", why);
    if (status == IR_SMT_RESOURCE_LIMIT)
        a->reasons |= IR_REASON_BUDGET;
}

static bool query_work(IrSmtAnswer *a, const IrSmtQueryLimits *l, uint64_t n) {
    if (n > l->work - a->work) {
        answer_error(a, IR_SMT_RESOURCE_LIMIT, "SMT query adapter work budget");
        return false;
    }
    a->work += n;
    return true;
}

static Sym *query_value(IrSmt *s, IrValueId id) {
    if (!id || id > s->value_id_bound) return NULL;
    uint32_t index = id - 1;
    if (s->info.values_compacted) {
        uint32_t lo = 0, hi = s->value_slots;
        while (lo < hi) {
            uint32_t mid = lo + (hi - lo) / 2;
            if (s->query_ids[mid] < id) lo = mid + 1;
            else hi = mid;
        }
        if (lo == s->value_slots || s->query_ids[lo] != id) return NULL;
        index = lo;
    }
    Sym *v = &s->values[index];
    return v->value && v->type.kind == IR_TYPE_BV ? v : NULL;
}

#include "ir_smt_checks.h"

static bool model_u64(IrSmt *s, Z3_model model, Z3_ast ast, uint64_t *value) {
    Z3_ast result = NULL;
    if (!ast) return false;
    bool ok = Z3_model_eval(s->ctx, model, ast, true, &result);
    if (!z3_ok(s, "Z3_model_eval") || !ok) return false;
    ok = Z3_get_numeral_uint64(s->ctx, result, value);
    return z3_ok(s, "Z3_get_numeral_uint64") && ok;
}

static bool model_bool(IrSmt *s, Z3_model model, Z3_ast ast, bool *value) {
    Z3_ast result = NULL;
    if (!ast) return false;
    bool ok = Z3_model_eval(s->ctx, model, ast, true, &result);
    if (!z3_ok(s, "Z3_model_eval") || !ok) return false;
    Z3_lbool b = Z3_get_bool_value(s->ctx, result);
    if (!z3_ok(s, "Z3_get_bool_value") || b == Z3_L_UNDEF) return false;
    *value = b == Z3_L_TRUE;
    return true;
}

static bool get_model(IrSmt *s, Z3_model model, const IrValueId *samples, uint32_t count,
                      IrSmtAnswer *a) {
    uint32_t n = 0;
    for (IrInputId id = 1; id <= s->cell_count; ++id)
        if (s->selected[id]) {
            uint64_t value;
            if (!model_u64(s, model, s->cell_symbols[id], &value))
                return false;
            const IrInputCell *c = ir_inputs_cell(s->inputs, id);
            a->inputs[n++] = (IrInputAssignment){id, ir_bits_known(value, c->width)};
        }
    a->input_count = n;
    n = 0;
    for (uint32_t i = 0; i < s->parameter_count; ++i)
        if (s->parameters[i].spec.symbolic) {
            uint64_t value;
            if (!model_u64(s, model, s->parameters[i].ast, &value))
                return false;
            a->parameters[n++] = (IrSmtParameterValue){s->parameters[i].spec.key,
                                                       s->parameters[i].spec.width, value};
        }
    a->parameter_count = n;
    for (uint32_t i = 0; i < count; ++i) {
        Sym v = *query_value(s, samples[i]);
        bool must, may;
        if (!model_bool(s, model, v.must_reach, &must) || !model_bool(s, model, v.may_reach, &may))
            return false;
        IrBits bits =
            ir_bits_unknown(may ? v.reach_reasons | IR_REASON_UNDEFINED : IR_REASON_NOT_EXECUTED);
        if (must) {
            uint64_t value, mask;
            if (!model_u64(s, model, v.value, &value) || !model_u64(s, model, v.mask, &mask))
                return false;
            bits =
                (IrBits){value & mask, mask,
                         mask == ir_width_mask(v.type.bits) ? 0 : v.reasons | IR_REASON_UNDEFINED};
        }
        a->samples[i] = (IrSmtSample){samples[i], bits};
    }
    a->sample_count = count;
    a->catalogue = ir_inputs_retain(s->inputs);
    return true;
}

static IrSmtAnswer query(IrSmt *s, const IrSmtConstraint *cs, const IrSmtBranchConstraint *bs,
                         bool at_branch, uint32_t nc, const IrValueId *samples, uint32_t ns,
                         const IrSmtQueryLimits *limits) {
    IrSmtQueryLimits l = limits ? *limits : ir_smt_default_query_limits();
    IrSmtAnswer a = {.status = IR_SMT_INVALID};
    Z3_solver solver = NULL;
    Z3_model model = NULL;
    Z3_params params = NULL;
    Z3_ast certain = NULL, possible = NULL;
    bool solver_owned = false, model_owned = false, params_owned = false;
    if (!ir_smt_current(s) || (nc && (at_branch ? !bs : !cs)) || (ns && !samples)) {
        answer_error(&a, IR_SMT_INVALID, "missing/stale backend or query array");
        return a;
    }
    if (s->info.status != IR_OK) {
        answer_error(&a, status_from_ir(s->info.status), s->info.message);
        return a;
    }
    if (nc > l.constraints || ns > l.samples || !l.timeout_ms || !l.rlimit) {
        answer_error(&a, IR_SMT_RESOURCE_LIMIT, "SMT query count/check budget");
        return a;
    }
    if (!query_work(&a, &l,
                    (uint64_t)nc + 5 * (uint64_t)ns + s->cell_count + s->parameter_count + 1))
        return a;
    /* At most 32 comparisons per lookup, two lookups per value request. */
    if (s->info.values_compacted &&
        !query_work(&a, &l, UINT64_C(64) * ((at_branch ? 0 : (uint64_t)nc) + ns))) return a;
    uint64_t bytes = (uint64_t)s->info.symbolic_inputs * sizeof(*a.inputs) +
                     (uint64_t)s->info.symbolic_parameters * sizeof(*a.parameters) +
                     (uint64_t)ns * sizeof(*a.samples);
    if (bytes > SIZE_MAX || bytes > l.bytes) {
        answer_error(&a, IR_SMT_RESOURCE_LIMIT, "SMT query allocation budget");
        return a;
    }
    a.bytes = (size_t)bytes;
    for (uint32_t i = 0; i < nc; ++i) {
        if (at_branch) {
            if (!bs[i].block || bs[i].block > s->module->block_count ||
                !s->branches[bs[i].block - 1].value) {
                answer_error(&a, IR_SMT_INVALID, "constraint does not name a CJUMP block");
                return a;
            }
            continue;
        }
        Sym *requested = query_value(s, cs[i].value);
        if (!requested || !cs[i].mask ||
            ((cs[i].mask | cs[i].expected) &
             ~ir_width_mask(requested->type.bits))) {
            answer_error(&a, IR_SMT_INVALID, "invalid constraint value/mask");
            return a;
        }
    }
    for (uint32_t i = 0; i < ns; ++i)
        if (!query_value(s, samples[i])) {
            answer_error(&a, IR_SMT_INVALID, "invalid sample value");
            return a;
        }
    s->stage = "query_constraints"; s->instruction = 0;
    s->info.origin = (IrOrigin){0};
    if (!assign_ast(s, &certain, boolean(s, true)) || !assign_ast(s, &possible, certain)) goto backend_error;
    clear_temporaries(s);
    for (uint32_t i = 0; i < nc; ++i) {
        if (!query_work(&a, &l, 24))
            goto finish;
        Sym v = at_branch ? s->branches[bs[i].block - 1] : *query_value(s, cs[i].value);
        a.reasons |= v.reasons | v.reach_reasons;
        a.origin =
            at_branch
                ? s->module->blocks[bs[i].block - 1].terminator.origin
                : s->module->insts[s->module->values[cs[i].value - 1].definition - 1].spec.origin;
        s->info.origin = a.origin;
        s->instruction = at_branch ? 0 : s->module->values[cs[i].value - 1].definition;
        Z3_ast mask = num(s, v.type.bits, at_branch ? 1 : cs[i].mask),
               expected = num(s, v.type.bits, at_branch ? (uint64_t)bs[i].taken : cs[i].expected);
        Z3_ast difference = bv_and(s, v.type.bits, bv_xor(s, v.type.bits, v.value, expected), mask),
               zero = num(s, v.type.bits, 0);
        Z3_ast defined = eq(s, v.type.bits, bv_and(s, v.type.bits, v.mask, mask), mask);
        if (!assign_ast(s, &certain,
            both(s, certain, both(s, v.must_reach, both(s, defined, eq(s, v.type.bits, difference, zero))))) ||
            !assign_ast(s, &possible,
            both(s, possible, both(s, v.may_reach, eq(s, v.type.bits, bv_and(s, v.type.bits, difference, v.mask), zero)))))
            goto backend_error;
        clear_temporaries(s);
    }
    if (s->info.status != IR_OK || !certain || !possible)
        goto backend_error;
    s->stage = "query_setup"; s->instruction = 0;
    solver = Z3_mk_solver(s->ctx);
    if (!z3_result(s, solver != NULL, "Z3_mk_solver"))
        goto backend_error;
    Z3_solver_inc_ref(s->ctx, solver);
    if (!z3_ok(s, "Z3_solver_inc_ref")) goto backend_error;
    solver_owned = true;
    params = Z3_mk_params(s->ctx);
    if (!z3_result(s, params != NULL, "Z3_mk_params"))
        goto backend_error;
    Z3_params_inc_ref(s->ctx, params);
    if (!z3_ok(s, "Z3_params_inc_ref")) goto backend_error;
    params_owned = true;
    Z3_symbol timeout_key = Z3_mk_string_symbol(s->ctx, "timeout");
    if (!z3_result(s, timeout_key != NULL, "Z3_mk_string_symbol")) goto backend_error;
    Z3_params_set_uint(s->ctx, params, timeout_key, l.timeout_ms);
    if (!z3_ok(s, "Z3_params_set_uint")) goto backend_error;
    Z3_symbol rlimit_key = Z3_mk_string_symbol(s->ctx, "rlimit");
    if (!z3_result(s, rlimit_key != NULL, "Z3_mk_string_symbol")) goto backend_error;
    Z3_params_set_uint(s->ctx, params, rlimit_key, l.rlimit);
    if (!z3_ok(s, "Z3_params_set_uint")) goto backend_error;
    Z3_solver_set_params(s->ctx, solver, params);
    if (!z3_ok(s, "Z3_solver_set_params"))
        goto backend_error;
    Z3_params_dec_ref(s->ctx, params);
    params_owned = false;
    if (!z3_ok(s, "Z3_params_dec_ref")) goto backend_error;
    for (unsigned pass = 0; pass < 2; ++pass) {
        Z3_ast assumption = pass ? possible : certain;
        s->stage = "query_check";
        IrSmtCheck *record = &a.checks[pass];
        record->pass = pass;
        record->timeout_ms = l.timeout_ms;
        record->rlimit = l.rlimit;
        if (!smt_statistics(s, solver, &record->statistics_before)) goto backend_error;
        smt_memory_snapshot(&record->before);
        record->recorded = true;
        uint64_t started_ns = smt_monotonic_ns();
        ++a.solver_checks;
        Z3_lbool result = Z3_solver_check_assumptions(s->ctx, solver, 1, &assumption);
        int check_errno = errno;
        uint64_t stopped_ns = smt_monotonic_ns();
        record->returned = true;
        record->result = result;
        record->clock_available = started_ns != UINT64_MAX && stopped_ns != UINT64_MAX && stopped_ns >= started_ns;
        if (record->clock_available) record->elapsed_ns = stopped_ns - started_ns;
        errno = check_errno;
        bool check_ok = z3_ok(s, "Z3_solver_check_assumptions");
        record->api_ok = check_ok;
        smt_memory_snapshot(&record->after);
        if (!check_ok)
            goto backend_error;
        if (result == Z3_L_UNDEF) {
            const char *why = Z3_solver_get_reason_unknown(s->ctx, solver);
            if (!z3_ok(s, "Z3_solver_get_reason_unknown")) goto backend_error;
            record->reason_truncated = smt_copy_text(record->reason_unknown, sizeof(record->reason_unknown), why);
        }
        if (!smt_statistics(s, solver, &record->statistics_after)) goto backend_error;
        smt_check_indicators(record);
        if (result == Z3_L_UNDEF) {
            const char *why = record->reason_unknown[0] ? record->reason_unknown : NULL;
            bool budget = why && (strstr(why, "timeout") || strstr(why, "resource") ||
                                  strstr(why, "canceled") || strstr(why, "rlimit"));
            answer_error(&a, budget ? IR_SMT_RESOURCE_LIMIT : IR_SMT_UNKNOWN,
                         why ? why : "Z3 returned unknown");
            goto finish;
        }
        if (result == Z3_L_FALSE) {
            if (!pass)
                continue;
            a.reasons = 0;
            answer_error(&a, IR_SMT_UNSAT, "no possible witness in this fragment");
            goto finish;
        }
        if (pass) {
            if (!a.reasons)
                a.reasons = IR_REASON_UNDEFINED;
            answer_error(&a, IR_SMT_UNKNOWN,
                         "possible witness depends on undefined data or reachability");
            goto finish;
        }
        s->stage = "model_extraction";
        model = Z3_solver_get_model(s->ctx, solver);
        if (!z3_result(s, model != NULL, "Z3_solver_get_model"))
            goto backend_error;
        Z3_model_inc_ref(s->ctx, model);
        if (!z3_ok(s, "Z3_model_inc_ref")) goto backend_error;
        model_owned = true;
        if (s->info.symbolic_inputs)
            a.inputs = calloc(s->info.symbolic_inputs, sizeof(*a.inputs));
        if (s->info.symbolic_parameters)
            a.parameters = calloc(s->info.symbolic_parameters, sizeof(*a.parameters));
        if (ns)
            a.samples = calloc(ns, sizeof(*a.samples));
        if ((s->info.symbolic_inputs && !a.inputs) ||
            (s->info.symbolic_parameters && !a.parameters) || (ns && !a.samples)) {
            answer_error(&a, IR_SMT_OUT_OF_MEMORY, "SMT answer allocation");
            goto finish;
        }
        if (!get_model(s, model, samples, ns, &a)) {
            if (s->info.status != IR_OK) goto backend_error;
            answer_error(&a, IR_SMT_UNKNOWN, "Z3 model extraction incomplete");
            goto finish;
        }
        a.reasons = 0;
        answer_error(&a, IR_SMT_SAT,
                     at_branch ? "defined witness at requested branches"
                               : "defined witness for requested values");
        goto finish;
    }
backend_error:
    answer_error(&a, status_from_ir(s->info.status),
                 s->info.status == IR_OK ? "Z3 query construction failed" : s->info.message);
finish:
    if (params_owned)
        Z3_params_dec_ref(s->ctx, params);
    if (model_owned)
        Z3_model_dec_ref(s->ctx, model);
    if (solver_owned)
        Z3_solver_dec_ref(s->ctx, solver);
    drop(s, certain); drop(s, possible);
    clear_temporaries(s);
    if (a.status != IR_SMT_SAT) {
        free(a.inputs);
        a.inputs = NULL;
        a.input_count = 0;
        free(a.parameters);
        a.parameters = NULL;
        a.parameter_count = 0;
        free(a.samples);
        a.samples = NULL;
        a.sample_count = 0;
        ir_inputs_release(a.catalogue);
        a.catalogue = NULL;
    }
    return a;
}

IrSmtAnswer ir_smt_query(IrSmt *s, const IrSmtConstraint *cs, uint32_t nc, const IrValueId *samples,
                         uint32_t ns, const IrSmtQueryLimits *limits) {
    return query(s, cs, NULL, false, nc, samples, ns, limits);
}

IrSmtAnswer ir_smt_query_branches(IrSmt *s, const IrSmtBranchConstraint *cs, uint32_t nc,
                                  const IrSmtQueryLimits *limits) {
    return query(s, NULL, cs, true, nc, NULL, 0, limits);
}

void ir_smt_answer_destroy(IrSmtAnswer *a) {
    if (!a)
        return;
    free(a->inputs);
    free(a->parameters);
    free(a->samples);
    ir_inputs_release(a->catalogue);
    memset(a, 0, sizeof(*a));
}
