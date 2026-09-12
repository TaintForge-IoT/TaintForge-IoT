#include "ir_opt.h"
#include "ir_internal.h"

#include <stdlib.h>

IrOptOptions ir_opt_default_options(void) {
    return (IrOptOptions){true, true, 8000000};
}

static bool spend(IrOptResult *r, uint64_t limit) {
    if (r->work >= limit) {
        r->status = IR_RESOURCE_LIMIT;
        return false;
    }
    ++r->work;
    return true;
}

static bool forced_constant(const IrModule *m, const IrInstSpec *s, uint64_t *out) {
    if (s->type.kind != IR_TYPE_BV)
        return false;
    if (ir_opcode_arity(s->op) >= 2 && s->args[0] == s->args[1]) {
        if (s->op == IR_OP_XOR || s->op == IR_OP_SUB || s->op == IR_OP_ULT || s->op == IR_OP_SLT) {
            *out = 0;
            return true;
        }
        if (s->op == IR_OP_EQ) {
            *out = 1;
            return true;
        }
    }
    uint64_t a = 0, b = 0, mask = ir_width_mask(s->type.bits);
    bool ca = ir_constant(m, s->args[0], &a), cb = ir_constant(m, s->args[1], &b);
    if ((s->op == IR_OP_AND || s->op == IR_OP_MUL) && ((ca && a == 0) || (cb && b == 0))) {
        *out = 0;
        return true;
    }
    if (s->op == IR_OP_OR && ((ca && a == mask) || (cb && b == mask))) {
        *out = mask;
        return true;
    }
    if ((s->op == IR_OP_SHL || s->op == IR_OP_LSHR) && cb && b >= s->type.bits) {
        *out = 0;
        return true;
    }
    return false;
}

static void replace(IrModule *m, IrInst *inst, IrOpcode op, IrValueId arg, uint64_t immediate) {
    IrOrigin origin = inst->spec.origin;
    IrType type = inst->spec.type;
    inst->spec = (IrInstSpec){
        .op = op, .type = type, .args = {arg, 0, 0}, .immediate = immediate, .origin = origin};
    ++m->revision;
}

static bool fold(IrModule *m, IrOptResult *r, uint64_t limit) {
    for (uint32_t i = 0; i < m->inst_count; ++i) {
        if (!spend(r, limit))
            return false;
        IrInst *inst = &m->insts[i];
        if (inst->removed)
            continue;
        IrInstSpec *s = &inst->spec;
        unsigned n = ir_opcode_arity(s->op);
        for (unsigned j = 0; j < n; ++j) {
            IrValueId original = s->args[j], id = original;
            for (;;) {
                const IrInst *d = &m->insts[m->values[id - 1].definition - 1];
                if (d->spec.op != IR_OP_COPY)
                    break;
                if (!spend(r, limit))
                    return false;
                id = d->spec.args[0];
            }
            if (id != original) {
                s->args[j] = id;
                ++r->copies_propagated;
                ++m->revision;
            }
        }
        if (!inst->result || s->op == IR_OP_CONST || s->op == IR_OP_INPUT ||
            s->op == IR_OP_UNKNOWN || s->op == IR_OP_READ_STATE)
            continue;
        uint64_t result = 0, args[3] = {0};
        IrType types[3] = {{0}};
        bool all = s->type.kind == IR_TYPE_BV && n > 0;
        for (unsigned j = 0; j < n; ++j) {
            types[j] = m->values[s->args[j] - 1].type;
            all &= ir_constant(m, s->args[j], &args[j]);
        }
        if ((all && ir_compute_bv(s, types, args, &result)) || forced_constant(m, s, &result)) {
            replace(m, inst, IR_OP_CONST, 0, result);
            ++r->constants_folded;
        } else {
            IrValueId id = ir_identity_operand(m, s);
            if (id && s->op != IR_OP_COPY) {
                replace(m, inst, IR_OP_COPY, id, 0);
                ++r->identities_folded;
            }
        }
    }
    return true;
}

static void mark_inst(const IrModule *m, IrInstId id, bool *live, IrInstId *work, uint32_t *n) {
    if (id && !live[id - 1] && !m->insts[id - 1].removed) {
        live[id - 1] = true;
        work[(*n)++] = id;
    }
}

static void mark_value(const IrModule *m, IrValueId id, bool *live, IrInstId *work, uint32_t *n) {
    if (id)
        mark_inst(m, m->values[id - 1].definition, live, work, n);
}

static void eliminate(IrModule *m, IrOptResult *r, uint64_t limit) {
    bool *live = calloc(m->inst_count ? m->inst_count : 1, sizeof(*live));
    IrInstId *work = calloc(m->inst_count ? m->inst_count : 1, sizeof(*work));
    if (!live || !work) {
        r->status = IR_OUT_OF_MEMORY;
        free(live);
        free(work);
        return;
    }
    uint32_t n = 0;
    for (uint32_t i = 0; i < m->inst_count; ++i) {
        if (!spend(r, limit))
            goto done;
        if (ir_opcode_is_effect(m->insts[i].spec.op))
            mark_inst(m, i + 1, live, work, &n);
    }
    for (uint32_t i = 0; i < m->output_count; ++i) {
        if (!spend(r, limit))
            goto done;
        mark_value(m, m->outputs[i], live, work, &n);
    }
    for (uint32_t i = 0; i < m->block_count; ++i) {
        if (!spend(r, limit))
            goto done;
        mark_value(m, m->blocks[i].terminator.condition, live, work, &n);
        mark_value(m, m->blocks[i].terminator.indirect_target, live, work, &n);
    }
    while (n) {
        if (!spend(r, limit))
            goto done;
        const IrInstSpec *s = &m->insts[work[--n] - 1].spec;
        for (unsigned j = 0; j < ir_opcode_arity(s->op); ++j)
            mark_value(m, s->args[j], live, work, &n);
    }
    /* Charge the sweep in advance so a budget failure cannot publish a
     * partially marked deletion set. */
    if (m->inst_count > limit - r->work) {
        r->status = IR_RESOURCE_LIMIT;
        goto done;
    }
    r->work += m->inst_count;
    for (uint32_t i = 0; i < m->inst_count; ++i)
        if (!live[i] && !m->insts[i].removed) {
            m->insts[i].removed = true;
            ++r->removed;
            ++m->revision;
        }
done:
    free(live);
    free(work);
}

IrOptResult ir_optimize(IrModule *m, const IrOptOptions *options) {
    IrOptResult r = {0};
    IrDiagnostic d;
    if (!ir_validate(m, &d)) {
        r.status = d.status;
        return r;
    }
    IrOptOptions o = options ? *options : ir_opt_default_options();
    if (o.fold && !fold(m, &r, o.max_work))
        return r;
    if (o.dce)
        eliminate(m, &r, o.max_work);
    if (!ir_validate(m, &d))
        r.status = d.status;
    return r;
}
