#include "ir_eval.h"
#include "ir_internal.h"

#include <stdlib.h>
#include <string.h>

typedef enum {
    MEM_BASE,
    MEM_STORE,
    MEM_OPAQUE
} MemoryKind;

typedef struct {
    MemoryKind kind;
    uint8_t address_bits;
    uint8_t bytes;
    IrEndian endian;
    uint32_t parent;
    IrBindingKind binding_kind;
    uint64_t key;
    uint64_t address;
    bool address_known;
    IrBits data;
    uint32_t reasons;
} MemoryNode;

typedef struct {
    uint64_t key;
    IrEvalValue value;
} InputBinding;

struct IrEval {
    const IrModule *module;
    uint64_t revision;
    IrBindings bindings;
    IrEvalLimits limits;
    IrEvalValue *values;
    IrEvalValue *states;
    bool *state_seen;
    InputBinding *inputs;
    uint32_t input_count;
    MemoryNode *memory;
    uint32_t memory_count, memory_capacity;
    bool failed;
    IrEvalResult result;
};

size_t ir_eval_allocated_bytes(const IrEval *e) {
    if (!e)
        return 0;
    size_t nv = e->module->value_count ? e->module->value_count : 1;
    size_t ns = e->module->state_count ? e->module->state_count : 1;
    return sizeof(*e) + nv * (sizeof(*e->values) + sizeof(*e->inputs)) +
           ns * (sizeof(*e->states) + sizeof(*e->state_seen)) +
           (size_t)e->memory_capacity * sizeof(*e->memory);
}

IrBits ir_bits_known(uint64_t value, uint32_t width) {
    uint64_t mask = ir_width_mask(width);
    return (IrBits){value & mask, mask, 0};
}

IrBits ir_bits_unknown(uint32_t reasons) {
    return (IrBits){0, 0, reasons};
}

bool ir_bits_complete(IrBits bits, uint32_t width) {
    return width > 0 && width <= 64 &&
           (bits.known_mask & ir_width_mask(width)) == ir_width_mask(width);
}

static IrBits normalize(IrBits b, uint8_t width) {
    b.known_mask &= ir_width_mask(width);
    b.value &= b.known_mask;
    if (ir_bits_complete(b, width))
        b.reasons = 0;
    else if (!b.reasons)
        b.reasons = IR_REASON_UNDEFINED;
    return b;
}

static IrEvalValue unknown_value(IrType type, uint32_t reasons) {
    return (IrEvalValue){type, {0, 0, reasons}, 0};
}

static bool current(const IrEval *e) {
    return e && ir_module_status(e->module) == IR_OK &&
           e->revision == ir_module_revision(e->module);
}

static void fail_eval(IrEval *e, IrEvalStatus status, uint32_t reasons) {
    e->failed = true;
    e->result.status = status;
    e->result.reasons |= reasons;
}

IrEvalLimits ir_eval_default_limits(void) {
    return (IrEvalLimits){1000000, 4000000, 100000};
}

IrEval *ir_eval_create(const IrModule *m, const IrBindings *bindings, const IrEvalLimits *limits) {
    if (!ir_validate(m, NULL))
        return NULL;
    IrEval *e = calloc(1, sizeof(*e));
    if (!e)
        return NULL;
    e->module = m;
    e->revision = m->revision;
    e->bindings = bindings ? *bindings : (IrBindings){0};
    e->limits = limits ? *limits : ir_eval_default_limits();
    if (e->limits.memory_nodes == UINT32_MAX) {
        free(e);
        return NULL;
    }
    e->values = calloc(m->value_count ? m->value_count : 1, sizeof(*e->values));
    e->states = calloc(m->state_count ? m->state_count : 1, sizeof(*e->states));
    e->state_seen = calloc(m->state_count ? m->state_count : 1, sizeof(*e->state_seen));
    e->inputs = calloc(m->value_count ? m->value_count : 1, sizeof(*e->inputs));
    if (!e->values || !e->states || !e->state_seen || !e->inputs) {
        ir_eval_destroy(e);
        return NULL;
    }
    for (uint32_t i = 0; i < m->value_count; ++i)
        e->values[i] = unknown_value(m->values[i].type, IR_REASON_NOT_EXECUTED);
    for (uint32_t i = 0; i < m->state_count; ++i)
        e->states[i] = unknown_value(m->states[i].type, IR_REASON_UNBOUND_STATE);
    e->result.status = IR_EVAL_INVALID;
    return e;
}

void ir_eval_destroy(IrEval *e) {
    if (!e)
        return;
    free(e->values);
    free(e->states);
    free(e->state_seen);
    free(e->inputs);
    free(e->memory);
    free(e);
}

static uint32_t memory_add(IrEval *e, MemoryNode node) {
    if (e->memory_count >= e->limits.memory_nodes) {
        fail_eval(e, IR_EVAL_RESOURCE_LIMIT, IR_REASON_BUDGET);
        return 0;
    }
    if (e->memory_count == e->memory_capacity) {
        uint32_t limit = e->limits.memory_nodes;
        uint32_t cap = e->memory_capacity ? e->memory_capacity : (limit < 16 ? limit : 16);
        if (cap == e->memory_capacity)
            cap = cap > limit / 2 ? limit : cap * 2;
        size_t bytes = (size_t)cap * sizeof(*e->memory);
        if (bytes / sizeof(*e->memory) != cap) {
            fail_eval(e, IR_EVAL_RESOURCE_LIMIT, IR_REASON_BUDGET);
            return 0;
        }
        MemoryNode *p = realloc(e->memory, bytes);
        if (!p) {
            fail_eval(e, IR_EVAL_OUT_OF_MEMORY, IR_REASON_BUDGET);
            return 0;
        }
        e->memory = p;
        e->memory_capacity = cap;
    }
    e->memory[e->memory_count++] = node;
    return e->memory_count;
}

static IrEvalValue memory_base(IrEval *e, IrType type, IrBindingKind kind, uint64_t key,
                               uint32_t opaque_reason) {
    uint32_t reasons = opaque_reason ? opaque_reason
                       : e->bindings.read_byte
                           ? 0
                           : IR_REASON_MEMORY | (kind == IR_BIND_INPUT ? IR_REASON_UNBOUND_INPUT
                                                                       : IR_REASON_UNBOUND_STATE);
    MemoryNode node = {.kind = opaque_reason ? MEM_OPAQUE : MEM_BASE,
                       .address_bits = type.bits,
                       .binding_kind = kind,
                       .key = key,
                       .reasons = reasons};
    IrEvalValue value = unknown_value(type, reasons);
    value.memory = memory_add(e, node);
    if (!value.memory)
        value.bits.reasons |= IR_REASON_BUDGET;
    return value;
}

static IrEvalValue read_binding(IrEval *e, IrBindingKind kind, uint64_t key, IrType type) {
    if (type.kind == IR_TYPE_MEM)
        return memory_base(e, type, kind, key, 0);
    IrBits b = e->bindings.read_bv
                   ? e->bindings.read_bv(e->bindings.user, kind, key, type.bits)
                   : ir_bits_unknown(kind == IR_BIND_INPUT ? IR_REASON_UNBOUND_INPUT
                                                           : IR_REASON_UNBOUND_STATE);
    return (IrEvalValue){type, normalize(b, type.bits), 0};
}

static IrEvalValue read_state(IrEval *e, IrStateId id) {
    const IrState *s = &e->module->states[id - 1];
    if (!e->state_seen[id - 1]) {
        e->states[id - 1] = read_binding(e, IR_BIND_STATE, s->key, s->type);
        e->state_seen[id - 1] = true;
    }
    return e->states[id - 1];
}

static IrEvalValue read_input(IrEval *e, const IrInstSpec *s) {
    for (uint32_t i = 0; i < e->input_count; ++i)
        if (e->inputs[i].key == s->immediate)
            return e->inputs[i].value;
    IrEvalValue value = read_binding(e, IR_BIND_INPUT, s->immediate, s->type);
    e->inputs[e->input_count++] = (InputBinding){s->immediate, value};
    return value;
}

static IrBits memory_byte(IrEval *e, uint32_t handle, uint64_t address) {
    while (handle && handle <= e->memory_count) {
        if (e->result.memory_queries >= e->limits.memory_queries) {
            fail_eval(e, IR_EVAL_RESOURCE_LIMIT, IR_REASON_BUDGET);
            return ir_bits_unknown(IR_REASON_BUDGET | IR_REASON_MEMORY);
        }
        ++e->result.memory_queries;
        const MemoryNode *n = &e->memory[handle - 1];
        uint64_t mask = ir_width_mask(n->address_bits);
        address &= mask;
        if (n->kind == MEM_OPAQUE)
            return ir_bits_unknown(n->reasons | IR_REASON_MEMORY);
        if (n->kind == MEM_BASE) {
            IrBits b =
                e->bindings.read_byte
                    ? e->bindings.read_byte(e->bindings.user, n->binding_kind, n->key, address)
                    : ir_bits_unknown(n->reasons | IR_REASON_MEMORY);
            return normalize(b, 8);
        }
        if (!n->address_known)
            return ir_bits_unknown(n->reasons | IR_REASON_MEMORY);
        /* Reverse within a wide store too: very small address widths can wrap
         * more than once, and the last byte in increasing-address order wins. */
        for (unsigned i = n->bytes; i > 0; --i) {
            unsigned index = i - 1;
            if (((n->address + index) & mask) == address) {
                unsigned bit = 8U * (n->endian == IR_ENDIAN_LE ? index : n->bytes - 1U - index);
                return normalize(
                    (IrBits){n->data.value >> bit, n->data.known_mask >> bit, n->data.reasons}, 8);
            }
        }
        handle = n->parent;
    }
    return ir_bits_unknown(IR_REASON_MEMORY);
}

IrBits ir_eval_load(IrEval *e, IrEvalValue mem, uint64_t address, uint32_t width, IrEndian endian) {
    if (!current(e) || mem.type.kind != IR_TYPE_MEM || !ir_type_valid(mem.type) || !width ||
        width > 64 || width % 8 || (endian != IR_ENDIAN_LE && endian != IR_ENDIAN_BE) ||
        !mem.memory || mem.memory > e->memory_count ||
        e->memory[mem.memory - 1].address_bits != mem.type.bits)
        return ir_bits_unknown(IR_REASON_MEMORY);
    IrBits out = {0};
    unsigned bytes = width / 8;
    uint64_t mask = ir_width_mask(mem.type.bits);
    for (unsigned i = 0; i < bytes; ++i) {
        IrBits b = memory_byte(e, mem.memory, (address + i) & mask);
        unsigned bit = 8U * (endian == IR_ENDIAN_LE ? i : bytes - 1U - i);
        out.value |= b.value << bit;
        out.known_mask |= b.known_mask << bit;
        out.reasons |= b.reasons;
        if (e->result.status == IR_EVAL_RESOURCE_LIMIT || e->result.status == IR_EVAL_OUT_OF_MEMORY)
            break;
    }
    return normalize(out, (uint8_t)width);
}

static IrBits arithmetic(const IrModule *m, const IrInstSpec *s, IrEvalValue v[3]) {
    uint64_t a[3] = {0}, mask = ir_width_mask(s->type.bits), value;
    IrType types[3] = {{0}};
    IrBits r = {0};
    unsigned n = ir_opcode_arity(s->op);
    bool all_known = true;
    for (unsigned i = 0; i < n; ++i) {
        a[i] = v[i].bits.value;
        types[i] = v[i].type;
        all_known &= ir_bits_complete(v[i].bits, types[i].bits);
        r.reasons |= v[i].bits.reasons;
    }
    if (all_known && ir_compute_bv(s, types, a, &value))
        return ir_bits_known(value, s->type.bits);
    IrValueId identity = ir_identity_operand(m, s);
    if (identity)
        for (unsigned i = 0; i < n; ++i)
            if (s->args[i] == identity)
                return v[i].bits;
    if (n >= 2 && s->args[0] == s->args[1]) {
        if (s->op == IR_OP_XOR || s->op == IR_OP_SUB || s->op == IR_OP_ULT || s->op == IR_OP_SLT)
            return ir_bits_known(0, s->type.bits);
        if (s->op == IR_OP_EQ)
            return ir_bits_known(1, 1);
    }
    uint64_t k0 = v[0].bits.known_mask, k1 = v[1].bits.known_mask;
    bool full0 = ir_bits_complete(v[0].bits, types[0].bits);
    bool full1 = n > 1 && ir_bits_complete(v[1].bits, types[1].bits);
    switch (s->op) {
    case IR_OP_COPY:
        return v[0].bits;
    case IR_OP_AND:
        r.value = a[0] & a[1];
        r.known_mask = (k0 & k1) | (k0 & ~a[0]) | (k1 & ~a[1]);
        break;
    case IR_OP_OR:
        r.value = a[0] | a[1];
        r.known_mask = (k0 & k1) | (k0 & a[0]) | (k1 & a[1]);
        break;
    case IR_OP_XOR:
        r.value = a[0] ^ a[1];
        r.known_mask = k0 & k1;
        break;
    case IR_OP_NOT:
        r.value = ~a[0];
        r.known_mask = k0;
        break;
    case IR_OP_ADD:
        if (full0 && !a[0])
            return v[1].bits;
        if (full1 && !a[1])
            return v[0].bits;
        break;
    case IR_OP_SUB:
        if (full1 && !a[1])
            return v[0].bits;
        break;
    case IR_OP_MUL:
        if ((full0 && !a[0]) || (full1 && !a[1]))
            return ir_bits_known(0, s->type.bits);
        if (full0 && a[0] == 1)
            return v[1].bits;
        if (full1 && a[1] == 1)
            return v[0].bits;
        break;
    case IR_OP_EXTRACT:
        r.value = a[0] >> s->immediate;
        r.known_mask = k0 >> s->immediate;
        break;
    case IR_OP_CONCAT:
        r.value = (a[0] << types[1].bits) | a[1];
        r.known_mask = (k0 << types[1].bits) | k1;
        break;
    case IR_OP_ZEXT:
        r.value = a[0];
        r.known_mask = k0 | (mask ^ ir_width_mask(types[0].bits));
        break;
    case IR_OP_SEXT: {
        uint64_t sign = UINT64_C(1) << (types[0].bits - 1);
        uint64_t high = mask ^ ir_width_mask(types[0].bits);
        r.value = a[0] | (a[0] & sign ? high : 0);
        r.known_mask = k0 | (k0 & sign ? high : 0);
        break;
    }
    case IR_OP_SHL:
    case IR_OP_LSHR:
    case IR_OP_ASHR:
        if (full1) {
            uint64_t sign = UINT64_C(1) << (s->type.bits - 1);
            if (!a[1])
                return v[0].bits;
            if (a[1] >= s->type.bits) {
                if (s->op != IR_OP_ASHR)
                    return ir_bits_known(0, s->type.bits);
                if (k0 & sign)
                    return ir_bits_known(a[0] & sign ? mask : 0, s->type.bits);
            } else if (s->op == IR_OP_SHL) {
                r.value = a[0] << a[1];
                r.known_mask = (k0 << a[1]) | ((UINT64_C(1) << a[1]) - 1);
            } else {
                uint64_t high = mask ^ (mask >> a[1]);
                r.value = a[0] >> a[1];
                r.known_mask = k0 >> a[1];
                if (s->op == IR_OP_LSHR || (k0 & sign))
                    r.known_mask |= high;
                if (s->op == IR_OP_ASHR && (a[0] & sign))
                    r.value |= high;
            }
        }
        break;
    case IR_OP_EQ:
        if ((a[0] ^ a[1]) & k0 & k1)
            return ir_bits_known(0, 1);
        break;
    case IR_OP_ITE:
        if (full0)
            return v[a[0] ? 1 : 2].bits;
        r.known_mask = v[1].bits.known_mask & v[2].bits.known_mask & ~(a[1] ^ a[2]);
        r.value = a[1];
        break;
    default:
        break;
    }
    return normalize(r, s->type.bits);
}

static void execute(IrEval *e, const IrInst *inst) {
    const IrInstSpec *s = &inst->spec;
    IrEvalValue v[3] = {0};
    for (unsigned i = 0; i < ir_opcode_arity(s->op); ++i)
        v[i] = e->values[s->args[i] - 1];
    IrEvalValue r = unknown_value(s->type, IR_REASON_UNDEFINED);
    switch (s->op) {
    case IR_OP_CONST:
        r.bits = ir_bits_known(s->immediate, s->type.bits);
        break;
    case IR_OP_INPUT:
        r = read_input(e, s);
        break;
    case IR_OP_UNKNOWN:
        r = s->type.kind == IR_TYPE_MEM
                ? memory_base(e, s->type, IR_BIND_INPUT, 0, (uint32_t)s->immediate)
                : unknown_value(s->type, (uint32_t)s->immediate);
        break;
    case IR_OP_READ_STATE:
        r = read_state(e, s->state);
        break;
    case IR_OP_WRITE_STATE:
        e->states[s->state - 1] = v[0];
        e->state_seen[s->state - 1] = true;
        break;
    case IR_OP_BARRIER:
        fail_eval(e, IR_EVAL_UNKNOWN, (uint32_t)s->immediate);
        break;
    case IR_OP_GUARD:
        if (!ir_bits_complete(v[0].bits, 1) || !v[0].bits.value)
            fail_eval(e, IR_EVAL_UNKNOWN, (uint32_t)s->immediate | v[0].bits.reasons);
        break;
    case IR_OP_LOAD:
        if (ir_bits_complete(v[1].bits, v[1].type.bits))
            r.bits = ir_eval_load(e, v[0], v[1].bits.value, s->type.bits, s->endian);
        else
            r.bits = ir_bits_unknown(v[1].bits.reasons | IR_REASON_MEMORY);
        break;
    case IR_OP_STORE: {
        bool known_address = ir_bits_complete(v[1].bits, v[1].type.bits);
        MemoryNode node = {.kind = MEM_STORE,
                           .address_bits = s->type.bits,
                           .bytes = (uint8_t)(v[2].type.bits / 8),
                           .endian = s->endian,
                           .parent = v[0].memory,
                           .address = v[1].bits.value,
                           .address_known = known_address,
                           .data = v[2].bits,
                           .reasons = v[1].bits.reasons | v[2].bits.reasons};
        r.memory = memory_add(e, node);
        r.bits = ir_bits_unknown(v[0].bits.reasons | v[1].bits.reasons | v[2].bits.reasons);
        if (!r.memory)
            r.bits.reasons |= IR_REASON_BUDGET;
        break;
    }
    case IR_OP_COPY:
        r = v[0];
        break;
    case IR_OP_ITE:
        if (s->type.kind == IR_TYPE_MEM) {
            if (ir_bits_complete(v[0].bits, 1))
                r = v[v[0].bits.value ? 1 : 2];
            else if (v[1].memory == v[2].memory)
                r = v[1];
            else
                r = memory_base(e, s->type, IR_BIND_INPUT, 0, v[0].bits.reasons | IR_REASON_MEMORY);
            break;
        }
        r.bits = arithmetic(e->module, s, v);
        break;
    default:
        r.bits = arithmetic(e->module, s, v);
        break;
    }
    if (inst->result)
        e->values[inst->result - 1] = r;
}

static bool step(IrEval *e) {
    if (e->result.steps >= e->limits.steps) {
        fail_eval(e, IR_EVAL_RESOURCE_LIMIT, IR_REASON_BUDGET);
        return false;
    }
    ++e->result.steps;
    return true;
}

static uint32_t value_reasons(IrEvalValue v) {
    if (v.type.kind == IR_TYPE_BV && !ir_bits_complete(v.bits, v.type.bits))
        return v.bits.reasons ? v.bits.reasons : IR_REASON_UNDEFINED;
    if (v.type.kind == IR_TYPE_MEM)
        return v.bits.reasons | (v.memory ? 0 : IR_REASON_MEMORY);
    return 0;
}

static void finish(IrEval *e, IrEvalStatus status) {
    for (uint32_t i = 0; i < e->module->output_count; ++i)
        e->result.reasons |= value_reasons(e->values[e->module->outputs[i] - 1]);
    for (uint32_t i = 0; i < e->module->state_count; ++i)
        if (e->module->states[i].live_out) {
            IrEvalValue state = read_state(e, i + 1);
            e->result.reasons |= value_reasons(state);
            if (e->failed)
                return;
        }
    e->result.status = e->result.reasons ? IR_EVAL_UNKNOWN : status;
}

IrEvalResult ir_eval_run(IrEval *e) {
    if (!current(e))
        return (IrEvalResult){.status = IR_EVAL_INVALID};
    const IrModule *m = e->module;
    e->result = (IrEvalResult){.status = IR_EVAL_FRAGMENT_END, .quality = m->quality};
    e->failed = false;
    e->input_count = 0;
    e->memory_count = 0;
    memset(e->state_seen, 0, (m->state_count ? m->state_count : 1) * sizeof(*e->state_seen));
    for (uint32_t i = 0; i < m->value_count; ++i)
        e->values[i] = unknown_value(m->values[i].type, IR_REASON_NOT_EXECUTED);
    for (uint32_t i = 0; i < m->state_count; ++i)
        e->states[i] = unknown_value(m->states[i].type, IR_REASON_UNBOUND_STATE);
    IrBlockId block = m->entry;
    while (!e->failed) {
        e->result.block = block;
        const IrBlock *b = &m->blocks[block - 1];
        for (IrInstId id = b->first; id && !e->failed; id = m->insts[id - 1].next) {
            const IrInst *inst = &m->insts[id - 1];
            if (inst->removed)
                continue;
            e->result.instruction = id;
            e->result.origin = inst->spec.origin;
            if (!step(e))
                break;
            execute(e, inst);
        }
        if (e->failed)
            break;
        const IrTerminator *t = &b->terminator;
        e->result.instruction = 0;
        e->result.origin = t->origin;
        if (!step(e))
            break;
        if (t->kind == IR_TERM_FRAGMENT_END || t->kind == IR_TERM_PROGRAM_EXIT) {
            e->result.reasons |= t->reasons;
            finish(e,
                   t->kind == IR_TERM_FRAGMENT_END ? IR_EVAL_FRAGMENT_END : IR_EVAL_PROGRAM_EXIT);
            break;
        }
        if (t->kind == IR_TERM_UNKNOWN) {
            fail_eval(e, IR_EVAL_UNKNOWN, t->reasons);
            break;
        }
        if (t->kind == IR_TERM_INDIRECT) {
            IrEvalValue target = e->values[t->indirect_target - 1];
            e->result.target_known = ir_bits_complete(target.bits, target.type.bits);
            e->result.target_address = target.bits.value;
            fail_eval(e, IR_EVAL_UNKNOWN, IR_REASON_TARGET | target.bits.reasons | t->reasons);
            break;
        }
        unsigned successor = 0;
        if (t->kind == IR_TERM_CJUMP) {
            IrBits cond = e->values[t->condition - 1].bits;
            if (!ir_bits_complete(cond, 1)) {
                fail_eval(e, IR_EVAL_UNKNOWN, cond.reasons | t->reasons);
                break;
            }
            successor = cond.value ? 0 : 1;
        }
        IrTarget target = t->successors[successor];
        if (target.kind == IR_TARGET_BLOCK) {
            e->result.reasons |= t->reasons;
            block = target.block;
        } else {
            e->result.target_known = target.kind == IR_TARGET_ADDRESS;
            e->result.target_address = target.address;
            fail_eval(e, IR_EVAL_UNKNOWN, IR_REASON_TARGET | target.reasons | t->reasons);
        }
    }
    return e->result;
}

IrEvalResult ir_eval_result(const IrEval *e) {
    return current(e) ? e->result : (IrEvalResult){.status = IR_EVAL_INVALID};
}

IrEvalValue ir_eval_value(const IrEval *e, IrValueId id) {
    return current(e) && id > 0 && id <= e->module->value_count
               ? e->values[id - 1]
               : unknown_value(ir_type_void(), IR_REASON_NOT_EXECUTED);
}

IrEvalValue ir_eval_state(const IrEval *e, IrStateId id) {
    return current(e) && id > 0 && id <= e->module->state_count
               ? e->states[id - 1]
               : unknown_value(ir_type_void(), IR_REASON_UNBOUND_STATE);
}
