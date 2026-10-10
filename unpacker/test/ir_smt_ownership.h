#ifndef TAINTFORGE_IR_SMT_OWNERSHIP_H
#define TAINTFORGE_IR_SMT_OWNERSHIP_H
/* Every constructor result gets a short-lived root before another constructor
 * may run. Persistent slots acquire their own root before replacing an old
 * one. Scopes end only after all results have been installed. Thus identities,
 * duplicate operands, nested C argument evaluation and shared ASTs are safe. */
static Z3_ast hold(IrSmt *s, Z3_ast a) {
    if (!a || !s->rc) return a;
    if (!spend(s, 1)) return NULL;
    Z3_inc_ref(s->ctx, a);
    if (!z3_ok(s, "Z3_inc_ref")) return NULL;
    ++s->info.references_acquired;
    return a;
}
static void drop(IrSmt *s, Z3_ast a) {
    if (a && s->rc) {
        Z3_dec_ref(s->ctx, a);
        ++s->info.references_released;
    }
}
static Z3_ast temporary(IrSmt *s, Z3_ast a) {
    if (!a || !s->rc) return a;
    if (s->temporary_count == sizeof(s->temporaries) / sizeof(s->temporaries[0])) {
        fail(s, IR_RESOURCE_LIMIT, "SMT temporary root capacity");
        return NULL;
    }
    if (!hold(s, a)) return NULL;
    s->temporaries[s->temporary_count++] = a;
    if (s->info.temporary_peak < s->temporary_count)
        s->info.temporary_peak = s->temporary_count;
    return a;
}
static void clear_temporaries(IrSmt *s) {
    /* Cleanup never spends a fallible budget. Every release is bounded by a
     * previously budgeted acquire; it must also run after a failed build. */
    while (s->temporary_count) drop(s, s->temporaries[--s->temporary_count]);
}
static bool assign_ast(IrSmt *s, Z3_ast *slot, Z3_ast a) {
    if (*slot == a) return s->info.status == IR_OK;
    if (a && !hold(s, a)) return false;
    Z3_ast old = *slot;
    *slot = a;
    drop(s, old);
    return s->info.status == IR_OK;
}
static bool assign_sym(IrSmt *s, Sym *slot, Sym v) {
    /* Acquire ALL fields first: a new mask can alias an old value and vice
     * versa. Budget failure leaves the previous complete slot intact. */
    Z3_ast fields[] = {v.value, v.mask, v.must_reach, v.may_reach};
    for (unsigned i = 0; i < 4; ++i) if (fields[i] && !hold(s, fields[i])) {
        while (i) drop(s, fields[--i]);
        return false;
    }
    drop(s, slot->value); drop(s, slot->mask);
    drop(s, slot->must_reach); drop(s, slot->may_reach);
    *slot = v;
    return true;
}
static bool retained_value(const IrSmt *s, IrValueId id) {
    return s->retained && (s->retained[id / 8] & (1U << (id % 8)));
}
static void release_value(IrSmt *s, IrValueId id) {
    if (!s->uses || s->uses[id] || retained_value(s, id)) return;
    Sym *v = &s->values[id - 1];
    if (!v->value) return;
    drop(s, v->value); drop(s, v->mask);
    drop(s, v->must_reach); drop(s, v->may_reach);
    memset(v, 0, sizeof(*v));
    --s->info.values_live;
    ++s->info.values_released;
}
static bool consume_value(IrSmt *s, IrValueId id) {
    if (!s->uses) return true;
    if (!spend(s, 1)) return false;
    if (!s->uses[id]) return fail(s, IR_INVALID, "SMT operand use count underflow");
    --s->uses[id];
    release_value(s, id);
    return true;
}
static bool count_use(IrSmt *s, IrValueId id) {
    if (!spend(s, 1)) return false;
    if (s->uses[id] == UINT32_MAX)
        return fail(s, IR_RESOURCE_LIMIT, "SMT operand use count overflow");
    ++s->uses[id];
    return true;
}
static bool prepare_uses(IrSmt *s, const IrSmtOptions *o) {
    if (!o->retained_values_only) return true;
    const IrModule *m = s->module;
    for (uint32_t i = 0; i < o->retained_value_count; ++i) {
        if (!spend(s, 1)) return false;
        IrValueId id = o->retained_values[i];
        if (!id || id > m->value_count ||
            m->insts[m->values[id - 1].definition - 1].removed)
            return fail(s, IR_INVALID, "invalid retained SMT value");
        s->retained[id / 8] |= (unsigned char)(1U << (id % 8));
    }
    for (uint32_t i = 0; i < m->inst_count; ++i) {
        if (!spend(s, 1)) return false;
        const IrInst *ins = &m->insts[i];
        if (ins->removed) continue;
        for (unsigned j = 0; j < ir_opcode_arity(ins->spec.op); ++j)
            if (!count_use(s, ins->spec.args[j])) return false;
    }
    for (uint32_t i = 0; i < m->block_count; ++i) {
        if (!spend(s, 1)) return false;
        const IrTerminator *t = &m->blocks[i].terminator;
        if (t->kind == IR_TERM_CJUMP && !count_use(s, t->condition)) return false;
    }
    return true;
}

static bool compact_values(IrSmt *s) {
    if (!s->uses) return true;
    if (!spend(s, 2 * (uint64_t)s->value_slots)) return false;
    uint32_t count = 0;
    for (uint32_t i = 0; i < s->value_slots; ++i) {
        if (s->uses[i + 1]) return fail(s, IR_INVALID, "unconsumed SMT value use");
        if (s->values[i].value) {
            if (!retained_value(s, i + 1)) return fail(s, IR_INVALID, "unretained SMT query root");
            ++count;
        }
    }
    if ((uint64_t)count != s->info.values_live)
        return fail(s, IR_INVALID, "SMT live value count mismatch");
    /* Reuse the no-longer-needed use-count buffer as a sorted ID index. Move
     * ownership in place, without retaining ASTs twice or a second Sym array.
     * No failure can interrupt the moves after this point. */
    uint32_t at = 0;
    for (uint32_t i = 0; i < s->value_slots; ++i) if (s->values[i].value) {
        s->uses[at] = i + 1;
        if (at != i) {
            s->values[at] = s->values[i];
            memset(&s->values[i], 0, sizeof(s->values[i]));
        }
        ++at;
    }
    s->query_ids = s->uses; s->uses = NULL;
    s->value_slots = count;
    free(s->retained); s->retained = NULL;
    s->info.values_compacted = true;
    /* Shrinking is an optimization: if realloc cannot shrink, the old valid
     * allocation remains owned, and diagnostics retain its original size. */
    size_t table_bytes = ((size_t)count + 1) * sizeof(*s->values);
    Sym *values = realloc(s->values, table_bytes);
    if (values) {s->values = values; s->info.value_table_bytes = table_bytes;}
    size_t index_bytes = ((size_t)count + 1) * sizeof(*s->query_ids);
    IrValueId *ids = realloc(s->query_ids, index_bytes);
    if (ids) {s->query_ids = ids; s->info.value_index_bytes = index_bytes;}
    return true;
}
#endif
