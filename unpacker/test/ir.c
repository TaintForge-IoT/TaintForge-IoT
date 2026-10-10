#include "ir_internal.h"

size_t ir_module_allocated_bytes(const IrModule *m) {
    if (!m)
        return 0;
    return sizeof(*m) + (size_t)m->inst_capacity * sizeof(*m->insts) +
           (size_t)m->value_capacity * sizeof(*m->values) +
           (size_t)m->block_capacity * sizeof(*m->blocks) +
           (size_t)m->state_capacity * sizeof(*m->states) +
           (size_t)m->output_capacity * sizeof(*m->outputs) +
           m->output_index_bytes +
           (m->trace_rank ? (size_t)m->block_count * sizeof(*m->trace_rank) : 0);
}

#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

IrType ir_type_void(void) {
    return (IrType){IR_TYPE_VOID, 0};
}

IrType ir_type_bv(uint32_t bits) {
    return (IrType){IR_TYPE_BV, bits <= 64 ? (uint8_t)bits : 0};
}

IrType ir_type_mem(uint32_t bits) {
    return (IrType){IR_TYPE_MEM, bits <= 64 ? (uint8_t)bits : 0};
}

bool ir_type_equal(IrType a, IrType b) {
    return a.kind == b.kind && a.bits == b.bits;
}

bool ir_type_valid(IrType t) {
    return t.kind == IR_TYPE_VOID
               ? t.bits == 0
               : (t.kind == IR_TYPE_BV || t.kind == IR_TYPE_MEM) && t.bits > 0 && t.bits <= 64;
}

uint64_t ir_width_mask(uint32_t bits) {
    return bits == 64 ? UINT64_MAX : bits > 0 && bits < 64 ? (UINT64_C(1) << bits) - 1 : 0;
}

static const char *const op_names[IR_OP_COUNT] = {
    "CONST",       "INPUT", "UNKNOWN", "COPY",  "ADD",    "SUB",  "MUL",  "AND",
    "OR",          "XOR",   "NOT",     "NEG",   "SHL",    "LSHR", "ASHR", "EXTRACT",
    "CONCAT",      "ZEXT",  "SEXT",    "EQ",    "ULT",    "SLT",  "ITE",  "READ_STATE",
    "WRITE_STATE", "LOAD",  "STORE",   "GUARD", "BARRIER", "ZERO_MEMORY"};
static const unsigned char op_arity[IR_OP_COUNT] = {0, 0, 0, 1, 2, 2, 2, 2, 2, 2, 1, 1, 2, 2, 2,
                                                    1, 2, 1, 1, 2, 2, 2, 3, 0, 1, 2, 3, 1, 0, 0};

const char *ir_opcode_name(IrOpcode op) {
    return (unsigned)op < IR_OP_COUNT ? op_names[op] : "INVALID";
}

unsigned ir_opcode_arity(IrOpcode op) {
    return (unsigned)op < IR_OP_COUNT ? op_arity[op] : 0;
}

bool ir_opcode_is_effect(IrOpcode op) {
    return op == IR_OP_WRITE_STATE || op == IR_OP_GUARD || op == IR_OP_BARRIER;
}

IrLimits ir_default_limits(void) {
    return (IrLimits){1000000, 1000000, 65536, 4096, 65536};
}

IrModule *ir_module_create(const IrLimits *limits) {
    IrModule *m = calloc(1, sizeof(*m));
    if (!m)
        return NULL;
    m->limits = limits ? *limits : ir_default_limits();
    if (m->limits.instructions == UINT32_MAX || m->limits.values == UINT32_MAX ||
        m->limits.blocks == UINT32_MAX || m->limits.states == UINT32_MAX ||
        m->limits.outputs == UINT32_MAX) {
        free(m);
        return NULL;
    }
    m->error = "ok";
    m->revision = 1;
    return m;
}

void ir_module_destroy(IrModule *m) {
    if (!m)
        return;
    free(m->insts);
    free(m->values);
    free(m->blocks);
    free(m->states);
    free(m->outputs);
    free(m->output_bits);
    free(m->trace_rank);
    free(m);
}

bool ir_fail(IrModule *m, IrStatus status, const char *message) {
    if (m && m->status == IR_OK) {
        m->status = status;
        m->error = message;
    }
    return false;
}

IrStatus ir_module_status(const IrModule *m) {
    return m ? m->status : IR_INVALID;
}

const char *ir_module_error(const IrModule *m) {
    return m ? m->error : "null module";
}

uint64_t ir_module_revision(const IrModule *m) {
    return m ? m->revision : 0;
}

IrQuality ir_module_quality(const IrModule *m) {
    return m ? m->quality : (IrQuality){0, 0, 0};
}

void ir_module_note_quality(IrModule *m, IrQuality quality) {
    if (!m || m->status != IR_OK)
        return;
    m->quality.semantic |= quality.semantic;
    m->quality.control |= quality.control;
    m->quality.observation |= quality.observation;
    ++m->revision;
}

/* Reserve before publishing counts/IDs. A failed operation never exposes a
 * half-built instruction, even when a preceding reserve has succeeded. */
static void *reserve(IrModule *m, void *ptr, uint32_t *capacity, uint32_t needed, uint32_t limit,
                     size_t size, IrBudgetKind kind) {
    if (needed > limit) {
        if (m->status == IR_OK)
            m->construction.failure = (IrBudgetFailure){kind, needed - 1U, limit, needed,
                                                        m->build_origin, m->build_phase};
        ir_fail(m, IR_RESOURCE_LIMIT, "module record budget");
        return NULL;
    }
    if (needed <= *capacity)
        return ptr;
    uint32_t cap = *capacity ? *capacity : (limit < 16 ? limit : 16);
    while (cap < needed)
        cap = cap > limit / 2 ? limit : cap * 2;
    if (cap > SIZE_MAX / size) {
        ir_fail(m, IR_RESOURCE_LIMIT, "allocation overflow");
        return NULL;
    }
    void *p = realloc(ptr, (size_t)cap * size);
    if (!p) {
        ir_fail(m, IR_OUT_OF_MEMORY, "allocation failed");
        return NULL;
    }
    *capacity = cap;
    return p;
}

const IrInst *ir_module_inst(const IrModule *m, IrInstId id) {
    return m && id > 0 && id <= m->inst_count ? &m->insts[id - 1] : NULL;
}

const IrValue *ir_module_value(const IrModule *m, IrValueId id) {
    return m && id > 0 && id <= m->value_count ? &m->values[id - 1] : NULL;
}

const IrBlock *ir_module_block(const IrModule *m, IrBlockId id) {
    return m && id > 0 && id <= m->block_count ? &m->blocks[id - 1] : NULL;
}

const IrState *ir_module_state(const IrModule *m, IrStateId id) {
    return m && id > 0 && id <= m->state_count ? &m->states[id - 1] : NULL;
}

uint32_t ir_module_inst_count(const IrModule *m) {
    return m ? m->inst_count : 0;
}

uint32_t ir_module_value_count(const IrModule *m) {
    return m ? m->value_count : 0;
}

uint32_t ir_module_block_count(const IrModule *m) {
    return m ? m->block_count : 0;
}

uint32_t ir_module_state_count(const IrModule *m) {
    return m ? m->state_count : 0;
}

uint32_t ir_module_output_count(const IrModule *m) {
    return m ? m->output_count : 0;
}

IrValueId ir_module_output(const IrModule *m, uint32_t i) {
    return m && i < m->output_count ? m->outputs[i] : 0;
}

uint32_t ir_module_active_inst_count(const IrModule *m) {
    uint32_t count = 0;
    if (m)
        for (uint32_t i = 0; i < m->inst_count; ++i)
            count += !m->insts[i].removed;
    return count;
}

IrBlockId ir_module_entry(const IrModule *m) {
    return m ? m->entry : 0;
}

IrBlockId ir_block_add(IrModule *m) {
    if (m && m->trace_rank)
        return ir_fail(m, IR_INVALID, "trace SSA structural builder is sealed");
    if (!m || m->status != IR_OK)
        return 0;
    IrBlock *blocks = reserve(m, m->blocks, &m->block_capacity, m->block_count + 1,
                              m->limits.blocks, sizeof(*m->blocks), IR_BUDGET_BLOCKS);
    if (!blocks)
        return 0;
    m->blocks = blocks;
    m->blocks[m->block_count] = (IrBlock){0};
    ++m->block_count;
    ++m->revision;
    if (!m->entry)
        m->entry = m->block_count;
    return m->block_count;
}

bool ir_module_set_entry(IrModule *m, IrBlockId block) {
    if (m && m->trace_rank)
        return ir_fail(m, IR_INVALID, "trace SSA structural builder is sealed");
    if (!m || m->status != IR_OK)
        return false;
    if (!ir_module_block(m, block))
        return ir_fail(m, IR_INVALID, "invalid entry block");
    m->entry = block;
    ++m->revision;
    return true;
}

IrStateId ir_state_add(IrModule *m, IrType type, uint64_t key, bool live_out) {
    if (m && m->trace_rank)
        return ir_fail(m, IR_INVALID, "trace SSA structural builder is sealed");
    if (!m || m->status != IR_OK)
        return 0;
    if (!ir_type_valid(type) || type.kind == IR_TYPE_VOID) {
        ir_fail(m, IR_INVALID, "invalid state type");
        return 0;
    }
    for (uint32_t i = 0; i < m->state_count; ++i)
        if (m->states[i].key == key) {
            ir_fail(m, IR_INVALID, "duplicate state key");
            return 0;
        }
    IrState *states = reserve(m, m->states, &m->state_capacity, m->state_count + 1,
                              m->limits.states, sizeof(*m->states), IR_BUDGET_STATES);
    if (!states)
        return 0;
    m->states = states;
    m->states[m->state_count++] = (IrState){type, key, live_out};
    ++m->revision;
    return m->state_count;
}

static bool local_value(const IrModule *m, IrBlockId block, IrInstId before, IrValueId id,
                        IrType *type) {
    const IrValue *v = ir_module_value(m, id);
    const IrInst *d = v ? ir_module_inst(m, v->definition) : NULL;
    if (!d || d->removed)
        return false;
    if (d->block == block) {
        if (v->definition >= before)
            return false;
    } else if (!m->trace_rank || m->trace_rank[d->block - 1] >= m->trace_rank[block - 1]) {
        return false;
    }
    if (type)
        *type = v->type;
    return true;
}

static bool spec_valid(const IrModule *m, IrBlockId block, IrInstId before, const IrInstSpec *s,
                       const char **why) {
    IrType a[3] = {{0}};
    bool ok = false;
    *why = "invalid instruction type or attributes";
    if ((unsigned)s->op >= IR_OP_COUNT || !ir_type_valid(s->type))
        return false;
    unsigned n = ir_opcode_arity(s->op);
    for (unsigned i = 0; i < 3; ++i) {
        if (i < n) {
            if (!local_value(m, block, before, s->args[i], &a[i])) {
                *why = "operand is missing, removed, forward, or from another block";
                return false;
            }
        } else if (s->args[i])
            return false;
    }
    if (s->state && s->op != IR_OP_READ_STATE && s->op != IR_OP_WRITE_STATE)
        return false;
    if (s->op != IR_OP_LOAD && s->op != IR_OP_STORE && s->endian != IR_ENDIAN_LE)
        return false;
    if (s->immediate && s->op != IR_OP_CONST && s->op != IR_OP_INPUT && s->op != IR_OP_UNKNOWN &&
        s->op != IR_OP_EXTRACT && s->op != IR_OP_GUARD && s->op != IR_OP_BARRIER)
        return false;
    switch (s->op) {
    case IR_OP_CONST:
        ok = s->type.kind == IR_TYPE_BV && (s->immediate & ~ir_width_mask(s->type.bits)) == 0;
        break;
    case IR_OP_ZERO_MEMORY:
        ok = s->type.kind == IR_TYPE_MEM;
        break;
    case IR_OP_INPUT:
        ok = s->type.kind != IR_TYPE_VOID;
        break;
    case IR_OP_UNKNOWN:
        ok = s->type.kind != IR_TYPE_VOID && s->immediate > 0 && s->immediate <= UINT32_MAX;
        break;
    case IR_OP_COPY:
        ok = ir_type_equal(s->type, a[0]);
        break;
    case IR_OP_ADD:
    case IR_OP_SUB:
    case IR_OP_MUL:
    case IR_OP_AND:
    case IR_OP_OR:
    case IR_OP_XOR:
    case IR_OP_SHL:
    case IR_OP_LSHR:
    case IR_OP_ASHR:
        ok = a[0].kind == IR_TYPE_BV && ir_type_equal(a[0], a[1]) && ir_type_equal(s->type, a[0]);
        break;
    case IR_OP_NOT:
    case IR_OP_NEG:
        ok = a[0].kind == IR_TYPE_BV && ir_type_equal(s->type, a[0]);
        break;
    case IR_OP_EXTRACT:
        ok = a[0].kind == IR_TYPE_BV && s->type.kind == IR_TYPE_BV && s->immediate < a[0].bits &&
             s->type.bits <= a[0].bits - s->immediate;
        break;
    case IR_OP_CONCAT:
        ok = a[0].kind == IR_TYPE_BV && a[1].kind == IR_TYPE_BV && s->type.kind == IR_TYPE_BV &&
             (unsigned)a[0].bits + a[1].bits == s->type.bits;
        break;
    case IR_OP_ZEXT:
    case IR_OP_SEXT:
        ok = a[0].kind == IR_TYPE_BV && s->type.kind == IR_TYPE_BV && s->type.bits >= a[0].bits;
        break;
    case IR_OP_EQ:
    case IR_OP_ULT:
    case IR_OP_SLT:
        ok = a[0].kind == IR_TYPE_BV && ir_type_equal(a[0], a[1]) &&
             ir_type_equal(s->type, ir_type_bv(1));
        break;
    case IR_OP_ITE:
        ok = ir_type_equal(a[0], ir_type_bv(1)) && ir_type_equal(a[1], a[2]) &&
             ir_type_equal(s->type, a[1]);
        break;
    case IR_OP_READ_STATE:
    case IR_OP_WRITE_STATE: {
        const IrState *state = ir_module_state(m, s->state);
        ok = state && (s->op == IR_OP_READ_STATE
                           ? ir_type_equal(s->type, state->type)
                           : s->type.kind == IR_TYPE_VOID && ir_type_equal(a[0], state->type));
        break;
    }
    case IR_OP_LOAD:
        ok = a[0].kind == IR_TYPE_MEM && a[1].kind == IR_TYPE_BV && a[0].bits == a[1].bits &&
             s->type.kind == IR_TYPE_BV && s->type.bits % 8 == 0 &&
             (s->endian == IR_ENDIAN_LE || s->endian == IR_ENDIAN_BE);
        break;
    case IR_OP_STORE:
        ok = a[0].kind == IR_TYPE_MEM && ir_type_equal(s->type, a[0]) && a[1].kind == IR_TYPE_BV &&
             a[1].bits == a[0].bits && a[2].kind == IR_TYPE_BV && a[2].bits % 8 == 0 &&
             (s->endian == IR_ENDIAN_LE || s->endian == IR_ENDIAN_BE);
        break;
    case IR_OP_GUARD:
        ok = s->type.kind == IR_TYPE_VOID && ir_type_equal(a[0], ir_type_bv(1)) &&
             s->immediate > 0 && s->immediate <= UINT32_MAX;
        break;
    case IR_OP_BARRIER:
        ok = s->type.kind == IR_TYPE_VOID && s->immediate > 0 && s->immediate <= UINT32_MAX;
        break;
    default:
        break;
    }
    return ok;
}

static IrInstId append(IrModule *m, IrBlockId block, IrInstSpec spec, bool effect) {
    if (m && m->trace_rank)
        return ir_fail(m, IR_INVALID, "trace SSA structural builder is sealed");
    if (!m || m->status != IR_OK)
        return 0;
    const IrBlock *b = ir_module_block(m, block);
    if (!b || b->terminator.kind != IR_TERM_NONE || effect != ir_opcode_is_effect(spec.op)) {
        ir_fail(m, IR_INVALID, "invalid block, terminated block, or wrong builder kind");
        return 0;
    }
    /* A literal is always reduced to its explicit BV width. */
    if (spec.op == IR_OP_CONST && spec.type.kind == IR_TYPE_BV)
        spec.immediate &= ir_width_mask(spec.type.bits);
    const char *why = NULL;
    if (!spec_valid(m, block, m->inst_count + 1, &spec, &why)) {
        ir_fail(m, IR_INVALID, why);
        return 0;
    }
    if (spec.op == IR_OP_INPUT)
        for (uint32_t i = 0; i < m->inst_count; ++i) {
            const IrInstSpec *other = &m->insts[i].spec;
            if (other->op == IR_OP_INPUT && other->immediate == spec.immediate &&
                !ir_type_equal(other->type, spec.type)) {
                ir_fail(m, IR_INVALID, "one input key has incompatible types");
                return 0;
            }
        }
    m->build_origin = spec.origin;
    IrInst *insts = reserve(m, m->insts, &m->inst_capacity, m->inst_count + 1,
                            m->limits.instructions, sizeof(*m->insts), IR_BUDGET_INSTRUCTIONS);
    if (!insts)
        return 0;
    m->insts = insts;
    if (!effect) {
        IrValue *values = reserve(m, m->values, &m->value_capacity, m->value_count + 1,
                                  m->limits.values, sizeof(*m->values), IR_BUDGET_VALUES);
        if (!values)
            return 0;
        m->values = values;
    }
    ++m->construction.opcodes[spec.op];
    ++m->construction.phases[m->build_phase];
    IrInstId id = m->inst_count + 1;
    IrValueId result = effect ? 0 : m->value_count + 1;
    m->insts[m->inst_count++] = (IrInst){spec, result, block, 0, false};
    if (!effect)
        m->values[m->value_count++] = (IrValue){spec.type, id};
    IrBlock *out = &m->blocks[block - 1];
    if (out->last)
        m->insts[out->last - 1].next = id;
    else
        out->first = id;
    out->last = id;
    ++m->revision;
    return id;
}

IrValueId ir_emit_value(IrModule *m, IrBlockId block, IrInstSpec spec) {
    IrInstId id = append(m, block, spec, false);
    return id ? m->insts[id - 1].result : 0;
}

bool ir_emit_effect(IrModule *m, IrBlockId block, IrInstSpec spec) {
    return append(m, block, spec, true) != 0;
}

static bool target_valid(const IrModule *m, const IrTarget *t) {
    switch (t->kind) {
    case IR_TARGET_BLOCK:
        return ir_module_block(m, t->block) != NULL;
    case IR_TARGET_ADDRESS:
        return t->block == 0;
    case IR_TARGET_UNKNOWN:
        return t->block == 0 && t->reasons != 0;
    default:
        return false;
    }
}

static bool term_valid(const IrModule *m, IrBlockId block, const IrTerminator *t) {
    IrType type;
    if (t->kind != IR_TERM_CJUMP && t->condition)
        return false;
    if (t->kind != IR_TERM_INDIRECT && t->indirect_target)
        return false;
    switch (t->kind) {
    case IR_TERM_FRAGMENT_END:
    case IR_TERM_PROGRAM_EXIT:
        return true;
    case IR_TERM_JUMP:
        return target_valid(m, &t->successors[0]);
    case IR_TERM_CJUMP:
        return local_value(m, block, m->inst_count + 1, t->condition, &type) &&
               ir_type_equal(type, ir_type_bv(1)) && target_valid(m, &t->successors[0]) &&
               target_valid(m, &t->successors[1]);
    case IR_TERM_INDIRECT:
        return local_value(m, block, m->inst_count + 1, t->indirect_target, &type) &&
               type.kind == IR_TYPE_BV;
    case IR_TERM_UNKNOWN:
        return t->reasons != 0;
    default:
        return false;
    }
}

bool ir_block_terminate(IrModule *m, IrBlockId block, IrTerminator term) {
    if (m && m->trace_rank)
        return ir_fail(m, IR_INVALID, "trace SSA structural builder is sealed");
    if (!m || m->status != IR_OK)
        return false;
    const IrBlock *b = ir_module_block(m, block);
    if (!b || b->terminator.kind != IR_TERM_NONE || !term_valid(m, block, &term))
        return ir_fail(m, IR_INVALID, "invalid or duplicate block terminator");
    m->blocks[block - 1].terminator = term;
    ++m->revision;
    return true;
}

void ir_outputs_clear(IrModule *m) {
    if (m->output_index_bytes)
        memset(m->output_bits, 0, m->output_index_bytes);
    m->output_count = 0;
}

static bool output_index_reserve(IrModule *m, uint32_t byte) {
    if (byte < m->output_index_bytes)
        return true;
    /* The value was validated before this call. Match the existing geometric
     * value allocation; avoid overflow in ceil(value_capacity / 8). */
    uint32_t bytes = m->value_capacity / 8U + (m->value_capacity % 8U != 0);
    unsigned char *bits = realloc(m->output_bits, bytes);
    if (!bits)
        return ir_fail(m, IR_OUT_OF_MEMORY, "output index allocation failed");
    memset(bits + m->output_index_bytes, 0, bytes - m->output_index_bytes);
    m->output_bits = bits;
    m->output_index_bytes = bytes;
    return true;
}

bool ir_module_add_output(IrModule *m, IrValueId id) {
    if (!m || m->status != IR_OK)
        return false;
    const IrValue *v = ir_module_value(m, id);
    const IrInst *d = v ? ir_module_inst(m, v->definition) : NULL;
    if (!d || d->removed)
        return ir_fail(m, IR_INVALID, "invalid output");
    uint32_t byte = (id - 1U) / 8U;
    unsigned char mask = (unsigned char)(1U << ((id - 1U) % 8U));
    if (byte < m->output_index_bytes && (m->output_bits[byte] & mask))
        return true;
    IrValueId *outputs = reserve(m, m->outputs, &m->output_capacity, m->output_count + 1,
                                 m->limits.outputs, sizeof(*m->outputs), IR_BUDGET_OUTPUTS);
    if (!outputs)
        return false;
    m->outputs = outputs;
    /* Keep output-budget failure precedence. Publish membership/count/revision
     * only after both allocations succeed. Duplicates never allocate. */
    if (!output_index_reserve(m, byte))
        return false;
    m->outputs[m->output_count++] = id;
    m->output_bits[byte] |= mask;
    ++m->revision;
    return true;
}

static bool diagnostic(IrDiagnostic *out, IrStatus status, IrBlockId block, IrInstId inst,
                       const char *message) {
    if (out)
        *out = (IrDiagnostic){status, block, inst, message};
    return status == IR_OK;
}

bool ir_validate(const IrModule *m, IrDiagnostic *out) {
    if (!m || m->status != IR_OK)
        return diagnostic(out, ir_module_status(m), 0, 0, ir_module_error(m));
    if (!ir_module_block(m, m->entry))
        return diagnostic(out, IR_INVALID, 0, 0, "missing entry");
    if (m->trace_rank && !ir_trace_shape(m, m->trace_rank, true))
        return diagnostic(out, IR_INVALID, 0, 0, "invalid trace SSA order");
    if (m->trace_rank) {
        bool *seen = calloc(m->state_count ? m->state_count : 1, sizeof(*seen));
        if (!seen)
            return diagnostic(out, IR_OUT_OF_MEMORY, 0, 0, "state validation allocation");
        IrBlockId b = m->entry;
        for (uint32_t k = 0; k < m->block_count; ++k) {
            uint32_t visited = 0;
            for (IrInstId id = m->blocks[b - 1].first; id;) {
                const IrInst *i = ir_module_inst(m, id);
                if (!i || ++visited > m->inst_count) {
                    free(seen);
                    return diagnostic(out, IR_INVALID, b, id, "invalid SSA chain");
                }
                if (!i->removed &&
                    (i->spec.op == IR_OP_READ_STATE || i->spec.op == IR_OP_WRITE_STATE)) {
                    IrStateId state = i->spec.state;
                    if (!state || state > m->state_count ||
                        (i->spec.op == IR_OP_READ_STATE && seen[state - 1])) {
                        free(seen);
                        return diagnostic(out, IR_INVALID, b, id,
                                          "SSA read is not an initial binding");
                    }
                    seen[state - 1] = true;
                }
                id = i->next;
            }
            bool valid;
            b = ir_trace_next(&m->blocks[b - 1].terminator, &valid);
        }
        free(seen);
    }
    uint32_t visited = 0;
    for (IrBlockId bi = 1; bi <= m->block_count; ++bi) {
        const IrBlock *b = &m->blocks[bi - 1];
        IrInstId prev = 0;
        for (IrInstId id = b->first; id;) {
            const IrInst *inst = ir_module_inst(m, id);
            if (!inst || inst->block != bi || id <= prev || ++visited > m->inst_count)
                return diagnostic(out, IR_INVALID, bi, id, "invalid block instruction chain");
            if (!inst->removed) {
                const char *why;
                if (!spec_valid(m, bi, id, &inst->spec, &why))
                    return diagnostic(out, IR_INVALID, bi, id, why);
            }
            if (ir_opcode_is_effect(inst->spec.op)) {
                if (inst->result)
                    return diagnostic(out, IR_INVALID, bi, id, "effect has a result");
            } else {
                const IrValue *v = ir_module_value(m, inst->result);
                if (!v || v->definition != id || !ir_type_equal(v->type, inst->spec.type))
                    return diagnostic(out, IR_INVALID, bi, id, "invalid result definition");
            }
            prev = id;
            id = inst->next;
        }
        if (prev != b->last || !term_valid(m, bi, &b->terminator))
            return diagnostic(out, IR_INVALID, bi, 0, "invalid block tail or terminator");
    }
    if (visited != m->inst_count)
        return diagnostic(out, IR_INVALID, 0, 0, "orphan instruction");
    for (uint32_t i = 0; i < m->value_count; ++i) {
        const IrInst *d = ir_module_inst(m, m->values[i].definition);
        if (!d || d->result != i + 1)
            return diagnostic(out, IR_INVALID, 0, 0, "orphan value");
    }
    for (uint32_t i = 0; i < m->output_count; ++i) {
        const IrValue *v = ir_module_value(m, m->outputs[i]);
        const IrInst *d = v ? ir_module_inst(m, v->definition) : NULL;
        if (!d || d->removed)
            return diagnostic(out, IR_INVALID, 0, 0, "removed or missing output");
    }
    return diagnostic(out, IR_OK, 0, 0, "ok");
}

bool ir_compute_bv(const IrInstSpec *s, const IrType t[3], const uint64_t a[3], uint64_t *out) {
    uint64_t r, mask = ir_width_mask(s->type.bits);
    switch (s->op) {
    case IR_OP_COPY:
        r = a[0];
        break;
    case IR_OP_ADD:
        r = a[0] + a[1];
        break;
    case IR_OP_SUB:
        r = a[0] - a[1];
        break;
    case IR_OP_MUL:
        r = a[0] * a[1];
        break;
    case IR_OP_AND:
        r = a[0] & a[1];
        break;
    case IR_OP_OR:
        r = a[0] | a[1];
        break;
    case IR_OP_XOR:
        r = a[0] ^ a[1];
        break;
    case IR_OP_NOT:
        r = ~a[0];
        break;
    case IR_OP_NEG:
        r = UINT64_C(0) - a[0];
        break;
    case IR_OP_SHL:
        r = a[1] >= t[0].bits ? 0 : a[0] << a[1];
        break;
    case IR_OP_LSHR:
        r = a[1] >= t[0].bits ? 0 : a[0] >> a[1];
        break;
    case IR_OP_ASHR: {
        bool sign = (a[0] & (UINT64_C(1) << (t[0].bits - 1))) != 0;
        if (a[1] >= t[0].bits)
            r = sign ? mask : 0;
        else if (!a[1])
            r = a[0];
        else
            r = (a[0] >> a[1]) | (sign ? mask ^ (mask >> a[1]) : 0);
        break;
    }
    case IR_OP_EXTRACT:
        r = a[0] >> s->immediate;
        break;
    case IR_OP_CONCAT:
        r = (a[0] << t[1].bits) | a[1];
        break;
    case IR_OP_ZEXT:
        r = a[0];
        break;
    case IR_OP_SEXT:
        r = a[0];
        if (r & (UINT64_C(1) << (t[0].bits - 1)))
            r |= ~ir_width_mask(t[0].bits);
        break;
    case IR_OP_EQ:
        r = a[0] == a[1];
        break;
    case IR_OP_ULT:
        r = a[0] < a[1];
        break;
    case IR_OP_SLT: {
        uint64_t sign = UINT64_C(1) << (t[0].bits - 1);
        r = (a[0] ^ sign) < (a[1] ^ sign);
        break;
    }
    case IR_OP_ITE:
        r = a[0] ? a[1] : a[2];
        break;
    default:
        return false;
    }
    *out = r & mask;
    return true;
}

bool ir_constant(const IrModule *m, IrValueId id, uint64_t *bits) {
    for (uint32_t n = 0; m && n < m->inst_count; ++n) {
        const IrValue *v = ir_module_value(m, id);
        const IrInst *d = v ? ir_module_inst(m, v->definition) : NULL;
        if (!d || d->removed)
            return false;
        if (d->spec.op == IR_OP_CONST) {
            *bits = d->spec.immediate;
            return true;
        }
        if (d->spec.op != IR_OP_COPY)
            return false;
        id = d->spec.args[0];
    }
    return false;
}

IrValueId ir_identity_operand(const IrModule *m, const IrInstSpec *s) {
    uint64_t x = 0, y = 0;
    bool cx = ir_constant(m, s->args[0], &x), cy = ir_constant(m, s->args[1], &y);
    uint64_t mask = ir_width_mask(s->type.bits);
    switch (s->op) {
    case IR_OP_COPY:
        return s->args[0];
    case IR_OP_ADD:
    case IR_OP_OR:
    case IR_OP_XOR:
        if (cx && x == 0)
            return s->args[1];
        if (cy && y == 0)
            return s->args[0];
        break;
    case IR_OP_SUB:
    case IR_OP_SHL:
    case IR_OP_LSHR:
    case IR_OP_ASHR:
        if (cy && y == 0)
            return s->args[0];
        break;
    case IR_OP_MUL:
        if (cx && x == 1)
            return s->args[1];
        if (cy && y == 1)
            return s->args[0];
        break;
    case IR_OP_AND:
        if (cx && x == mask)
            return s->args[1];
        if (cy && y == mask)
            return s->args[0];
        break;
    case IR_OP_ZEXT:
    case IR_OP_SEXT:
    case IR_OP_EXTRACT: {
        const IrValue *a = ir_module_value(m, s->args[0]);
        if (a && s->immediate == 0 && ir_type_equal(a->type, s->type))
            return s->args[0];
        break;
    }
    case IR_OP_ITE:
        if (cx)
            return s->args[x ? 1 : 2];
        if (s->args[1] == s->args[2])
            return s->args[1];
        break;
    default:
        break;
    }
    return 0;
}

static void dump_type(FILE *f, IrType t) {
    if (t.kind == IR_TYPE_VOID)
        fputs("VOID", f);
    else
        fprintf(f, "%s%u", t.kind == IR_TYPE_BV ? "BV" : "MEM", t.bits);
}

static void dump_target(FILE *f, IrTarget t) {
    if (t.kind == IR_TARGET_BLOCK)
        fprintf(f, "b%u", t.block);
    else if (t.kind == IR_TARGET_ADDRESS)
        fprintf(f, "external@0x%" PRIx64, t.address);
    else
        fprintf(f, "UNKNOWN(0x%x)", t.reasons);
}

bool ir_dump(const IrModule *m, FILE *f) {
    if (!m || !f)
        return false;
    fprintf(f, "ir revision=%" PRIu64 " entry=b%u status=%s quality=%x/%x/%x\n", m->revision,
            m->entry, m->error, m->quality.semantic, m->quality.control, m->quality.observation);
    if (m->trace_rank)
        fprintf(f, "form=trace_ssa\n");
    for (uint32_t i = 0; i < m->state_count; ++i) {
        fprintf(f, "state s%u key=%" PRIu64 " ", i + 1, m->states[i].key);
        dump_type(f, m->states[i].type);
        fprintf(f, " live_out=%u\n", m->states[i].live_out);
    }
    for (uint32_t bi = 0; bi < m->block_count; ++bi) {
        fprintf(f, "b%u:\n", bi + 1);
        uint32_t visited = 0;
        for (IrInstId id = m->blocks[bi].first; id && visited++ < m->inst_count;) {
            const IrInst *d = ir_module_inst(m, id);
            if (!d)
                return false;
            const IrInstSpec *s = &d->spec;
            fprintf(f, "  %si%u ", d->removed ? "[dead] " : "", id);
            if (d->result) {
                fprintf(f, "v%u:", d->result);
                dump_type(f, s->type);
                fputs(" = ", f);
            }
            fputs(ir_opcode_name(s->op), f);
            for (unsigned j = 0; j < ir_opcode_arity(s->op); ++j)
                fprintf(f, " v%u", s->args[j]);
            if (s->op == IR_OP_CONST || s->op == IR_OP_INPUT || s->op == IR_OP_UNKNOWN ||
                s->op == IR_OP_EXTRACT || s->op == IR_OP_GUARD || s->op == IR_OP_BARRIER)
                fprintf(f, " #0x%" PRIx64, s->immediate);
            if (s->state)
                fprintf(f, " s%u", s->state);
            if (s->op == IR_OP_LOAD || s->op == IR_OP_STORE)
                fputs(s->endian == IR_ENDIAN_LE ? " LE" : " BE", f);
            if (s->origin.has_trace_identity)
                fprintf(f,
                        " ; seq=%" PRIu64 " pc=0x%" PRIx64 " gen=%" PRIu64 " desc=%" PRIu64
                        " vcpu=%u",
                        s->origin.seq_id, s->origin.pc, s->origin.code_generation,
                        s->origin.descriptor_id, s->origin.vcpu_id);
            if (s->origin.provenance_label)
                fprintf(f, " label=%" PRIu64, s->origin.provenance_label);
            fputc('\n', f);
            id = d->next;
        }
        const IrTerminator *t = &m->blocks[bi].terminator;
        fputs("  ", f);
        switch (t->kind) {
        case IR_TERM_FRAGMENT_END:
            fputs("FRAGMENT_END", f);
            break;
        case IR_TERM_PROGRAM_EXIT:
            fputs("PROGRAM_EXIT", f);
            break;
        case IR_TERM_JUMP:
            fputs("JUMP ", f);
            dump_target(f, t->successors[0]);
            break;
        case IR_TERM_CJUMP:
            fprintf(f, "CJUMP v%u ", t->condition);
            dump_target(f, t->successors[0]);
            fputs(" / ", f);
            dump_target(f, t->successors[1]);
            break;
        case IR_TERM_INDIRECT:
            fprintf(f, "INDIRECT v%u", t->indirect_target);
            break;
        default:
            fprintf(f, "UNKNOWN_OR_UNSET kind=%u", (unsigned)t->kind);
            break;
        }
        if (t->reasons)
            fprintf(f, " reasons=0x%x", t->reasons);
        if (t->has_observation)
            fprintf(f, " ; observed=%u target=0x%" PRIx64, t->observed_taken, t->observed_target);
        if (t->origin.has_trace_identity)
            fprintf(f, " ; seq=%" PRIu64 " pc=0x%" PRIx64, t->origin.seq_id, t->origin.pc);
        fputc('\n', f);
    }
    fputs("outputs:", f);
    for (uint32_t i = 0; i < m->output_count; ++i)
        fprintf(f, " v%u", m->outputs[i]);
    fputc('\n', f);
    return !ferror(f);
}

bool ir_module_is_trace_ssa(const IrModule *m) {
    return m && m->trace_rank;
}

IrBlockId ir_trace_next(const IrTerminator *t, bool *valid) {
    IrBlockId next = 0;
    *valid = true;
    unsigned n = t->kind == IR_TERM_CJUMP ? 2 : t->kind == IR_TERM_JUMP ? 1 : 0;
    for (unsigned i = 0; i < n; ++i)
        if (t->successors[i].kind == IR_TARGET_BLOCK) {
            if (next && next != t->successors[i].block) {
                *valid = false;
                return 0;
            }
            next = t->successors[i].block;
        }
    return next;
}

bool ir_trace_shape(const IrModule *m, uint32_t *rank, bool verify) {
    IrBlockId b = m->entry;
    if (!verify)
        memset(rank, 0, (size_t)m->block_count * sizeof(*rank));
    for (uint32_t k = 1; k <= m->block_count; ++k) {
        if (!b || b > m->block_count || (verify ? rank[b - 1] != k : rank[b - 1] != 0))
            return false;
        if (!verify)
            rank[b - 1] = k;
        bool valid;
        b = ir_trace_next(&m->blocks[b - 1].terminator, &valid);
        if (!valid)
            return false;
    }
    return b == 0;
}

IrModule *ir_module_clone(const IrModule *m) {
    if (!ir_validate(m, NULL))
        return NULL;
    IrModule *n = ir_module_create(&m->limits);
    if (!n)
        return NULL;
    n->entry = m->entry;
    n->quality = m->quality;
    n->construction = m->construction;
    n->build_phase = m->build_phase;
    n->build_origin = m->build_origin;
    n->revision = m->revision;
#define COPY_ARRAY(field, count, cap)                                                              \
    do {                                                                                           \
        if (m->count) {                                                                            \
            n->field = malloc((size_t)m->count * sizeof(*n->field));                               \
            if (!n->field) {                                                                       \
                ir_module_destroy(n);                                                              \
                return NULL;                                                                       \
            }                                                                                      \
            memcpy(n->field, m->field, (size_t)m->count * sizeof(*n->field));                      \
        }                                                                                          \
        n->count = m->count;                                                                        \
        n->cap = m->count;                                                                          \
    } while (0)
    COPY_ARRAY(insts, inst_count, inst_capacity);
    COPY_ARRAY(values, value_count, value_capacity);
    COPY_ARRAY(blocks, block_count, block_capacity);
    COPY_ARRAY(states, state_count, state_capacity);
    COPY_ARRAY(outputs, output_count, output_capacity);
    COPY_ARRAY(output_bits, output_index_bytes, output_index_bytes);
#undef COPY_ARRAY
    if (m->trace_rank) {
        n->trace_rank = malloc((size_t)m->block_count * sizeof(*n->trace_rank));
        if (!n->trace_rank) {
            ir_module_destroy(n);
            return NULL;
        }
        memcpy(n->trace_rank, m->trace_rank, (size_t)m->block_count * sizeof(*n->trace_rank));
    }
    return n;
}

IrBuildPhase ir_module_build_phase(IrModule *m, IrBuildPhase phase) {
    IrBuildPhase old = m ? m->build_phase : IR_BUILD_OTHER;
    if (m && (unsigned)phase < IR_BUILD_PHASE_COUNT) m->build_phase = phase;
    return old;
}
void ir_module_build_origin(IrModule *m, IrOrigin origin) {
    if (m) m->build_origin = origin;
}
IrBuildMetrics ir_module_build_metrics(const IrModule *m) {
    if (!m) return (IrBuildMetrics){.status = IR_INVALID};
    IrBuildMetrics result = m->construction;
    result.records = (IrLimits){m->inst_count, m->value_count, m->block_count,
                               m->state_count, m->output_count};
    result.limits = m->limits;
    result.allocated_bytes = ir_module_allocated_bytes(m);
    result.status = m->status;
    return result;
}
const char *ir_budget_kind_name(IrBudgetKind kind) {
    static const char *const names[] = {"none", "instructions", "values", "blocks", "states",
        "outputs", "steps", "observations", "memory_bytes", "repeat_iterations"};
    return (unsigned)kind < sizeof(names)/sizeof(*names) ? names[kind] : "invalid";
}
const char *ir_build_phase_name(IrBuildPhase phase) {
    static const char *const names[] = {"other", "setup", "x86_semantics", "register_access",
        "arithmetic_flags", "memory_model", "environment", "replay_observations",
        "trace_control", "flag_definedness", "code_fetch"};
    return (unsigned)phase < IR_BUILD_PHASE_COUNT ? names[phase] : "invalid";
}
bool ir_budget_report_json(FILE *f, const IrBudgetFailure *v) {
    if (!f || !v) return false;
    if (v->kind == IR_BUDGET_NONE) { fputs("null", f); return !ferror(f); }
    fprintf(f, "{\"resource\":\"%s\",\"used\":%" PRIu64 ",\"limit\":%" PRIu64
        ",\"requested\":%" PRIu64 ",\"phase\":\"%s\",\"origin\":{\"seq\":%" PRIu64
        ",\"pc\":%" PRIu64 ",\"descriptor\":%" PRIu64 ",\"generation\":%" PRIu64
        ",\"vcpu\":%u,\"identity_valid\":%s}}", ir_budget_kind_name(v->kind), v->used,
        v->limit, v->requested, ir_build_phase_name(v->phase), v->origin.seq_id, v->origin.pc,
        v->origin.descriptor_id, v->origin.code_generation, v->origin.vcpu_id,
        v->origin.has_trace_identity ? "true" : "false");
    return !ferror(f);
}
static void limits_json(FILE *f, IrLimits v) {
    fprintf(f, "{\"instructions\":%u,\"values\":%u,\"blocks\":%u,\"states\":%u,\"outputs\":%u}",
        v.instructions, v.values, v.blocks, v.states, v.outputs);
}
bool ir_build_report_json(FILE *f, const IrBuildMetrics *v) {
    if (!f || !v) return false;
    fprintf(f, "{\"status\":%u,\"allocated_bytes\":%zu,\"records\":", v->status, v->allocated_bytes);
    limits_json(f, v->records); fputs(",\"limits\":", f); limits_json(f, v->limits);
    fputs(",\"failure\":", f); ir_budget_report_json(f, &v->failure);
    fputs(",\"opcodes\":{", f);
    for (unsigned i=0; i<IR_OP_COUNT; ++i)
        fprintf(f, "%s\"%s\":%" PRIu64, i ? "," : "", ir_opcode_name(i), v->opcodes[i]);
    fputs("},\"phases\":{", f);
    for (unsigned i=0; i<IR_BUILD_PHASE_COUNT; ++i)
        fprintf(f, "%s\"%s\":%" PRIu64, i ? "," : "", ir_build_phase_name(i), v->phases[i]);
    fputs("}}", f); return !ferror(f);
}
