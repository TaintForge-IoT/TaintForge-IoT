#include "ir_ssa.h"
#include "ir_internal.h"

#include <stdlib.h>
#include <string.h>

struct IrUseDef {
    const IrModule *module;
    uint64_t revision;
    uint32_t *offsets;
    IrUse *uses;
};

struct IrLiveness {
    const IrModule *module;
    uint64_t revision;
    bool *insts;
};

typedef struct {
    IrAnalysisLimits limits;
    IrAnalysisInfo info;
} Budget;

IrAnalysisLimits ir_analysis_default_limits(void) {
    return (IrAnalysisLimits){UINT64_C(32000000), (size_t)256 * 1024 * 1024};
}

IrTraceSsaOptions ir_trace_ssa_default_options(void) {
    return (IrTraceSsaOptions){.limits = ir_analysis_default_limits(),
                               .roots = {.keep_outputs = true, .all_exit_states = true},
                               .dce = true};
}

static bool error(Budget *b, IrStatus status, const char *why) {
    b->info.status = status;
    b->info.message = why;
    return false;
}

static bool work(Budget *b, uint64_t n) {
    if (n > b->limits.work - b->info.work)
        return error(b, IR_RESOURCE_LIMIT, "analysis work budget");
    b->info.work += n;
    return true;
}

static bool bytes(Budget *b, uint64_t n) {
    if (n > SIZE_MAX || n > b->limits.bytes)
        return error(b, IR_RESOURCE_LIMIT, "analysis allocation budget");
    if (b->info.bytes < n)
        b->info.bytes = (size_t)n;
    return true;
}

static Budget budget(const IrAnalysisLimits *l) {
    return (Budget){.limits = l ? *l : ir_analysis_default_limits(), .info = {.message = "ok"}};
}

static bool validate(const IrModule *m, bool ssa, Budget *b) {
    if (!m || (ssa && !m->trace_rank))
        return error(b, IR_INVALID, "trace SSA required");
    /* Account for validation scans and its transient state-seen array. */
    if (!work(b, 4 * (uint64_t)m->inst_count + 4 * (uint64_t)m->block_count + m->value_count +
                     m->state_count + m->output_count + 1) ||
        !bytes(b, (uint64_t)m->state_count + 1))
        return false;
    IrDiagnostic d;
    if (!ir_validate(m, &d))
        return error(b, d.status, d.message);
    return true;
}

static bool roots_valid(const IrModule *m, const IrSsaRoots *r, Budget *b) {
    if ((r->value_count && !r->values) || (r->state_count && !r->states))
        return error(b, IR_INVALID, "missing root array");
    for (uint32_t i = 0; i < r->value_count; ++i) {
        if (!work(b, 1))
            return false;
        const IrValue *v = ir_module_value(m, r->values[i]);
        if (!v || m->insts[v->definition - 1].removed)
            return error(b, IR_INVALID, "missing or removed value root");
    }
    for (uint32_t i = 0; i < r->state_count; ++i) {
        if (!work(b, 1))
            return false;
        if (!ir_module_state(m, r->states[i]))
            return error(b, IR_INVALID, "invalid state root");
    }
    return true;
}

static void publish(IrAnalysisInfo *out, const Budget *b) {
    if (out)
        *out = b->info;
}

bool ir_use_def_current(const IrUseDef *a) {
    return a && a->revision == ir_module_revision(a->module) &&
           ir_module_status(a->module) == IR_OK;
}

IrInstId ir_use_def_definition(const IrUseDef *a, IrValueId v) {
    if (!ir_use_def_current(a) || !v || v > a->module->value_count)
        return 0;
    IrInstId d = a->module->values[v - 1].definition;
    return a->module->insts[d - 1].removed ? 0 : d;
}

uint32_t ir_use_def_count(const IrUseDef *a, IrValueId v) {
    return ir_use_def_definition(a, v) ? a->offsets[v] - a->offsets[v - 1] : 0;
}

const IrUse *ir_use_def_use(const IrUseDef *a, IrValueId v, uint32_t i) {
    return i < ir_use_def_count(a, v) ? &a->uses[a->offsets[v - 1] + i] : NULL;
}

void ir_use_def_destroy(IrUseDef *a) {
    if (a) {
        free(a->offsets);
        free(a->uses);
        free(a);
    }
}

static bool put_use(IrUseDef *a, uint32_t *cursor, IrValueId v, IrUse use, Budget *b) {
    if (!work(b, 1))
        return false;
    if (cursor)
        a->uses[cursor[v - 1]++] = use;
    else
        ++a->offsets[v];
    return true;
}

static bool collect_uses(IrUseDef *a, uint32_t *cursor, Budget *b) {
    const IrModule *m = a->module;
    for (uint32_t i = 0; i < m->inst_count; ++i) {
        if (!work(b, 1))
            return false;
        const IrInst *ins = &m->insts[i];
        if (ins->removed)
            continue;
        for (unsigned j = 0; j < ir_opcode_arity(ins->spec.op); ++j)
            if (!put_use(a, cursor, ins->spec.args[j],
                         (IrUse){IR_USE_INSTRUCTION, i + 1, ins->block, j}, b))
                return false;
    }
    for (uint32_t i = 0; i < m->block_count; ++i) {
        if (!work(b, 1))
            return false;
        const IrTerminator *t = &m->blocks[i].terminator;
        if (t->condition &&
            !put_use(a, cursor, t->condition, (IrUse){IR_USE_CONDITION, 0, i + 1, 0}, b))
            return false;
        if (t->indirect_target &&
            !put_use(a, cursor, t->indirect_target, (IrUse){IR_USE_INDIRECT, 0, i + 1, 0}, b))
            return false;
    }
    for (uint32_t i = 0; i < m->output_count; ++i)
        if (!put_use(a, cursor, m->outputs[i], (IrUse){IR_USE_OUTPUT, 0, 0, i}, b))
            return false;
    return true;
}

IrUseDef *ir_use_def_build(const IrModule *m, const IrAnalysisLimits *limits,
                           IrAnalysisInfo *info) {
    Budget b = budget(limits);
    IrUseDef *a = NULL;
    uint32_t *cursor = NULL;
    if (!validate(m, true, &b))
        goto done;
    uint64_t max_uses =
        3 * (uint64_t)m->inst_count + 2 * (uint64_t)m->block_count + m->output_count;
    if (max_uses > UINT32_MAX) {
        error(&b, IR_RESOURCE_LIMIT, "use index overflow");
        goto done;
    }
    uint64_t fixed = sizeof(*a) + 2 * ((uint64_t)m->value_count + 1) * sizeof(uint32_t);
    if (!bytes(&b, fixed))
        goto done;
    a = calloc(1, sizeof(*a));
    if (!a)
        goto oom;
    a->module = m;
    a->revision = m->revision;
    a->offsets = calloc((size_t)m->value_count + 1, sizeof(*a->offsets));
    cursor = calloc((size_t)m->value_count + 1, sizeof(*cursor));
    if (!a->offsets || !cursor)
        goto oom;
    if (!collect_uses(a, NULL, &b))
        goto done;
    for (uint32_t i = 1; i <= m->value_count; ++i) {
        if (!work(&b, 1))
            goto done;
        a->offsets[i] += a->offsets[i - 1];
        cursor[i - 1] = a->offsets[i - 1];
    }
    uint32_t n = a->offsets[m->value_count];
    if (!bytes(&b, fixed + (uint64_t)(n ? n : 1) * sizeof(*a->uses)))
        goto done;
    a->uses = calloc(n ? n : 1, sizeof(*a->uses));
    if (!a->uses)
        goto oom;
    if (!collect_uses(a, cursor, &b))
        goto done;
    goto done;
oom:
    error(&b, IR_OUT_OF_MEMORY, "use-def allocation");
done:
    free(cursor);
    publish(info, &b);
    if (b.info.status != IR_OK) {
        ir_use_def_destroy(a);
        a = NULL;
    }
    return a;
}

bool ir_liveness_current(const IrLiveness *a) {
    return a && a->revision == ir_module_revision(a->module) &&
           ir_module_status(a->module) == IR_OK;
}

bool ir_liveness_inst(const IrLiveness *a, IrInstId i) {
    return ir_liveness_current(a) && i && i <= a->module->inst_count && a->insts[i - 1];
}

bool ir_liveness_value(const IrLiveness *a, IrValueId v) {
    return ir_liveness_current(a) && v && v <= a->module->value_count &&
           ir_liveness_inst(a, a->module->values[v - 1].definition);
}

void ir_liveness_destroy(IrLiveness *a) {
    if (a) {
        free(a->insts);
        free(a);
    }
}

static void mark(IrLiveness *a, IrInstId i, IrInstId *stack, uint32_t *n) {
    if (i && !a->insts[i - 1] && !a->module->insts[i - 1].removed) {
        a->insts[i - 1] = true;
        stack[(*n)++] = i;
    }
}

static void mark_value(IrLiveness *a, IrValueId v, IrInstId *stack, uint32_t *n) {
    if (v)
        mark(a, a->module->values[v - 1].definition, stack, n);
}

static bool mark_states(IrLiveness *a, const IrInstId *last, const bool *selected, bool all,
                        IrInstId *stack, uint32_t *n, Budget *b) {
    for (uint32_t s = 0; s < a->module->state_count; ++s) {
        if (!work(b, 1))
            return false;
        if (all || selected[s])
            mark(a, last[s], stack, n);
    }
    return true;
}

IrLiveness *ir_liveness_build(const IrModule *m, const IrSsaRoots *roots,
                              const IrAnalysisLimits *limits, IrAnalysisInfo *info) {
    Budget b = budget(limits);
    IrSsaRoots r = roots ? *roots : ir_trace_ssa_default_options().roots;
    IrLiveness *a = NULL;
    IrInstId *stack = NULL, *last = NULL;
    bool *selected = NULL;
    uint32_t n = 0;
    if (!validate(m, true, &b) || !roots_valid(m, &r, &b))
        goto done;
    if (!bytes(&b, sizeof(*a) + ((uint64_t)m->inst_count + 1) * (sizeof(bool) + sizeof(*stack)) +
                       ((uint64_t)m->state_count + 1) * (sizeof(*last) + sizeof(*selected))))
        goto done;
    a = calloc(1, sizeof(*a));
    if (!a)
        goto oom;
    a->module = m;
    a->revision = m->revision;
    a->insts = calloc(m->inst_count ? m->inst_count : 1, sizeof(*a->insts));
    stack = calloc(m->inst_count ? m->inst_count : 1, sizeof(*stack));
    last = calloc(m->state_count ? m->state_count : 1, sizeof(*last));
    selected = calloc(m->state_count ? m->state_count : 1, sizeof(*selected));
    if (!a->insts || !stack || !last || !selected)
        goto oom;
    for (uint32_t s = 0; s < m->state_count; ++s)
        selected[s] = m->states[s].live_out;
    for (uint32_t s = 0; s < r.state_count; ++s)
        selected[r.states[s] - 1] = true;
    if (r.keep_outputs)
        for (uint32_t i = 0; i < m->output_count; ++i) {
            if (!work(&b, 1))
                goto done;
            mark_value(a, m->outputs[i], stack, &n);
        }
    for (uint32_t i = 0; i < r.value_count; ++i)
        mark_value(a, r.values[i], stack, &n);
    IrBlockId block = m->entry;
    for (uint32_t k = 0; k < m->block_count; ++k) {
        for (IrInstId id = m->blocks[block - 1].first; id; id = m->insts[id - 1].next) {
            if (!work(&b, 1))
                goto done;
            const IrInst *ins = &m->insts[id - 1];
            if (ins->removed)
                continue;
            if (ins->spec.op == IR_OP_READ_STATE || ins->spec.op == IR_OP_WRITE_STATE)
                last[ins->spec.state - 1] = id;
            else if (ir_opcode_is_effect(ins->spec.op)) {
                mark(a, id, stack, &n);
                if (!mark_states(a, last, selected, true, stack, &n, &b))
                    goto done;
            }
        }
        if (!work(&b, 1))
            goto done;
        const IrTerminator *t = &m->blocks[block - 1].terminator;
        mark_value(a, t->condition, stack, &n);
        mark_value(a, t->indirect_target, stack, &n);
        bool valid;
        IrBlockId next = ir_trace_next(t, &valid);
        bool normal = t->kind == IR_TERM_FRAGMENT_END || t->kind == IR_TERM_PROGRAM_EXIT;
        if (!next || t->kind == IR_TERM_CJUMP) {
            if (!mark_states(a, last, selected, !normal || r.all_exit_states, stack, &n, &b))
                goto done;
        }
        block = next;
    }
    while (n) {
        if (!work(&b, 1))
            goto done;
        const IrInstSpec *s = &m->insts[stack[--n] - 1].spec;
        for (unsigned j = 0; j < ir_opcode_arity(s->op); ++j)
            mark_value(a, s->args[j], stack, &n);
    }
    goto done;
oom:
    error(&b, IR_OUT_OF_MEMORY, "liveness allocation");
done:
    free(stack);
    free(last);
    free(selected);
    publish(info, &b);
    if (b.info.status != IR_OK) {
        ir_liveness_destroy(a);
        a = NULL;
    }
    return a;
}

IrTraceSsaResult ir_trace_ssa(IrModule *m, const IrTraceSsaOptions *options) {
    IrTraceSsaOptions o = options ? *options : ir_trace_ssa_default_options();
    Budget b = budget(&o.limits);
    IrTraceSsaResult result = {0};
    IrModule *n = NULL;
    IrValueId *current = NULL;
    IrLiveness *live = NULL;
    if (!validate(m, false, &b) || !roots_valid(m, &o.roots, &b))
        goto done;
    uint64_t copy_bytes =
        sizeof(*m) + (uint64_t)m->inst_count * sizeof(*m->insts) +
        (uint64_t)m->value_count * sizeof(*m->values) +
        (uint64_t)m->block_count * (sizeof(*m->blocks) + sizeof(uint32_t)) +
        (uint64_t)m->state_count * sizeof(*m->states) +
        m->output_index_bytes + ((uint64_t)m->value_count + 7) / 8 +
        2 * ((uint64_t)m->output_count + o.roots.value_count + 16) * sizeof(*m->outputs) +
        ((uint64_t)m->state_count + 1) * (sizeof(*current) + sizeof(bool));
    if (!bytes(&b, copy_bytes))
        goto done;
    /* Clone validation and copying are bounded scans too. */
    if (!work(&b, 5 * (uint64_t)m->inst_count + 5 * (uint64_t)m->block_count +
                      2 * (uint64_t)m->value_count + 2 * (uint64_t)m->state_count +
                      2 * (uint64_t)m->output_count + 1 +
                      2 * (uint64_t)m->output_index_bytes + ((uint64_t)m->value_count + 7) / 8))
        goto done;
    n = ir_module_clone(m);
    if (!n) {
        error(&b, IR_OUT_OF_MEMORY, "SSA clone allocation");
        goto done;
    }
    if (!n->trace_rank)
        n->trace_rank = calloc(n->block_count, sizeof(*n->trace_rank));
    current = calloc(n->state_count ? n->state_count : 1, sizeof(*current));
    if (!n->trace_rank || !current) {
        error(&b, IR_OUT_OF_MEMORY, "SSA state allocation");
        goto done;
    }
    if (!work(&b, n->block_count) || !ir_trace_shape(n, n->trace_rank, false)) {
        if (b.info.status == IR_OK)
            error(&b, IR_INVALID, "requires one acyclic trace chain; CFG merges/loops unsupported");
        goto done;
    }
    IrBlockId block = n->entry;
    for (uint32_t k = 0; k < n->block_count; ++k) {
        for (IrInstId id = n->blocks[block - 1].first; id; id = n->insts[id - 1].next) {
            if (!work(&b, 1))
                goto done;
            IrInst *ins = &n->insts[id - 1];
            if (ins->removed)
                continue;
            IrStateId state = ins->spec.state;
            if (ins->spec.op == IR_OP_READ_STATE) {
                if (current[state - 1]) {
                    ins->spec = (IrInstSpec){.op = IR_OP_COPY,
                                             .type = ins->spec.type,
                                             .args = {current[state - 1]},
                                             .origin = ins->spec.origin};
                    ++result.renamed_reads;
                } else {
                    current[state - 1] = ins->result;
                    ++result.initial_reads;
                }
            } else if (ins->spec.op == IR_OP_WRITE_STATE)
                current[state - 1] = ins->spec.args[0];
        }
        bool valid;
        block = ir_trace_next(&n->blocks[block - 1].terminator, &valid);
    }
    if (!o.roots.keep_outputs)
        ir_outputs_clear(n);
    for (uint32_t i = 0; i < o.roots.value_count; ++i) {
        if (!work(&b, (uint64_t)n->output_count + 1))
            goto done;
        if (!ir_module_add_output(n, o.roots.values[i])) {
            error(&b, n->status, n->error);
            goto done;
        }
    }
    if (o.dce) {
        IrAnalysisLimits left = {o.limits.work - b.info.work, o.limits.bytes - (size_t)copy_bytes};
        IrAnalysisInfo li;
        live = ir_liveness_build(n, &o.roots, &left, &li);
        b.info.work += li.work;
        bytes(&b, copy_bytes + li.bytes);
        if (!live) {
            error(&b, li.status, li.message);
            goto done;
        }
        if (!work(&b, n->inst_count))
            goto done;
        for (uint32_t i = 0; i < n->inst_count; ++i)
            if (!n->insts[i].removed && !live->insts[i]) {
                n->insts[i].removed = true;
                ++result.removed;
                result.removed_writes += n->insts[i].spec.op == IR_OP_WRITE_STATE;
            }
    }
    if (!validate(n, true, &b))
        goto done;
    n->revision = m->revision + 1;
    {
        IrModule old = *m;
        *m = *n;
        *n = old;
    }
done:
    ir_liveness_destroy(live);
    free(current);
    ir_module_destroy(n);
    result.analysis = b.info;
    if (b.info.status != IR_OK)
        result.renamed_reads = result.initial_reads = result.removed = result.removed_writes = 0;
    return result;
}

IrModule *ir_trace_target_slice(const IrModule *m, const IrTargetSliceOptions *o,
                                 IrTargetSliceInfo *info) {
    Budget b = budget(o ? &o->limits : NULL);
    IrTargetSliceInfo result = {0};
    IrModule *copy = NULL;
    IrLiveness live = {.module = m};
    IrInstId *stack = NULL;
    uint32_t count = 0;
    if (!o || !o->value_count) { error(&b, IR_INVALID, "explicit target roots required"); goto done; }
    IrSsaRoots roots = {.values = o->values, .value_count = o->value_count};
    if (!validate(m, true, &b) || !roots_valid(m, &roots, &b)) goto done;
    const IrBlock *boundary = ir_module_block(m, o->boundary);
    if (!boundary || m->trace_rank[o->boundary - 1] != m->block_count ||
        boundary->terminator.kind != IR_TERM_FRAGMENT_END) {
        error(&b, IR_INVALID, "target boundary must be final fragment end"); goto done;
    }
    uint64_t copy_bytes = sizeof(*m) + (uint64_t)m->inst_count * sizeof(*m->insts) +
        (uint64_t)m->value_count * sizeof(*m->values) +
        (uint64_t)m->block_count * (sizeof(*m->blocks) + sizeof(uint32_t)) +
        (uint64_t)m->state_count * sizeof(*m->states) +
        m->output_index_bytes + ((uint64_t)m->value_count + 7) / 8 +
        2 * ((uint64_t)m->output_count + o->value_count + 16) * sizeof(*m->outputs);
    uint64_t scratch = ((uint64_t)m->inst_count + 1) * (sizeof(bool) + sizeof(*stack));
    if (!bytes(&b, copy_bytes + scratch + (uint64_t)m->state_count + 1)) goto done;
    live.insts = calloc(m->inst_count ? m->inst_count : 1, sizeof(*live.insts));
    stack = calloc(m->inst_count ? m->inst_count : 1, sizeof(*stack));
    if (!live.insts || !stack) goto oom;
    result.records = m->inst_count; result.outputs_before = m->output_count;
    for (uint32_t i = 0; i < o->value_count; ++i) {
        if (!work(&b, 1)) goto done;
        mark_value(&live, o->values[i], stack, &count);
    }
    for (uint32_t i = 0; i < m->inst_count; ++i) {
        if (!work(&b, 1)) goto done;
        const IrInst *ins = &m->insts[i];
        if (ins->removed) continue;
        ++result.active_before;
        if (ins->spec.op == IR_OP_GUARD || ins->spec.op == IR_OP_BARRIER) {
            result.guards += ins->spec.op == IR_OP_GUARD;
            result.barriers += ins->spec.op == IR_OP_BARRIER;
            mark(&live, i + 1, stack, &count);
        }
    }
    for (uint32_t i = 0; i < m->block_count; ++i) {
        if (!work(&b, 1)) goto done;
        const IrTerminator *term = &m->blocks[i].terminator;
        result.conditions += term->condition != 0;
        result.indirect_targets += term->indirect_target != 0;
        mark_value(&live, term->condition, stack, &count);
        mark_value(&live, term->indirect_target, stack, &count);
    }
    while (count) {
        const IrInst *ins = &m->insts[stack[--count] - 1];
        if (!work(&b, 1 + ir_opcode_arity(ins->spec.op))) goto done;
        for (unsigned i = 0; i < ir_opcode_arity(ins->spec.op); ++i)
            mark_value(&live, ins->spec.args[i], stack, &count);
    }
    /* Clone's validation and array copy are bounded too. */
    if (!work(&b, 5 * (uint64_t)m->inst_count + 5 * (uint64_t)m->block_count +
        2 * (uint64_t)m->value_count + 2 * (uint64_t)m->state_count +
        2 * (uint64_t)m->output_count + 1 +
        2 * (uint64_t)m->output_index_bytes + ((uint64_t)m->value_count + 7) / 8)) goto done;
    copy = ir_module_clone(m);
    if (!copy) goto oom;
    if (!work(&b, (uint64_t)m->inst_count + m->state_count)) goto done;
    for (uint32_t i = 0; i < m->inst_count; ++i) {
        IrInst *ins = &copy->insts[i];
        if (!ins->removed && !live.insts[i]) {
            ins->removed = true; ++result.removed;
            result.removed_writes += ins->spec.op == IR_OP_WRITE_STATE;
        }
    }
    for (uint32_t i = 0; i < copy->state_count; ++i) copy->states[i].live_out = false;
    ir_outputs_clear(copy);
    for (uint32_t i = 0; i < o->value_count; ++i) {
        if (!work(&b, (uint64_t)copy->output_count + 1)) goto done;
        if (!ir_module_add_output(copy, o->values[i])) {
            error(&b, copy->status, copy->error); goto done;
        }
    }
    if (!validate(copy, true, &b)) goto done;
    copy->revision = m->revision + 1;
    result.active_after = result.active_before - result.removed;
    result.outputs_after = copy->output_count;
    result.retained_bytes = ir_module_allocated_bytes(copy);
    goto done;
oom:
    error(&b, IR_OUT_OF_MEMORY, "target slice allocation");
done:
    free(live.insts); free(stack);
    if (b.info.status != IR_OK) { ir_module_destroy(copy); copy = NULL; }
    result.analysis = b.info;
    if (info) *info = result;
    return copy;
}
