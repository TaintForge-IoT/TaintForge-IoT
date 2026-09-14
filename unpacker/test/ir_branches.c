#include "ir_branches.h"
#include "ir_internal.h"

#include <stdlib.h>
#include <string.h>

struct IrBranches {
    const IrModule *module;
    uint64_t revision;
    IrInputs *inputs;
    IrBranch *entries;
    IrBranchInfo info;
};

IrBranchLimits ir_branch_default_limits(void) {
    return (IrBranchLimits){65536, UINT64_C(16000000), (size_t)32 * 1024 * 1024};
}

static uint64_t validation_work(const IrModule *m) {
    return 4 * (uint64_t)m->inst_count + 4 * (uint64_t)m->block_count + m->value_count +
           m->state_count + m->output_count + 1;
}

static bool identity_equal(IrOrigin a, IrOrigin b) {
    return a.has_trace_identity && b.has_trace_identity && a.seq_id == b.seq_id && a.pc == b.pc &&
           a.code_generation == b.code_generation && a.descriptor_id == b.descriptor_id &&
           a.vcpu_id == b.vcpu_id;
}

/* Replay starts each successor block with an entry checkpoint. Tombstones
 * retain that origin after DCE. Do not use a later instruction's PC if the
 * first instruction has no trace identity. An empty block uses its terminator. */
static bool target_address(const IrModule *m, IrTarget target, uint64_t *address) {
    if (target.kind == IR_TARGET_ADDRESS) {
        *address = target.address;
        return true;
    }
    if (target.kind != IR_TARGET_BLOCK)
        return false;
    const IrBlock *b = &m->blocks[target.block - 1];
    IrOrigin o = b->first ? m->insts[b->first - 1].spec.origin : b->terminator.origin;
    if (!o.has_trace_identity)
        return false;
    *address = o.pc;
    return true;
}

IrBranches *ir_branches_build(const IrModule *m, const IrInputs *inputs,
                              const IrBranchLimits *limits, IrBranchInfo *info) {
    IrBranchLimits l = limits ? *limits : ir_branch_default_limits();
    IrBranchInfo out = {.status = IR_INVALID, .message = "missing module or unsealed inputs"};
    IrBranches *c = NULL;
    uint32_t *rank = NULL;
    if (!m || (inputs && !ir_inputs_ready(inputs)))
        goto finish;
    out.work = validation_work(m) + 2 * (uint64_t)m->block_count;
    if (out.work > l.work) {
        out.status = IR_RESOURCE_LIMIT;
        out.message = "branch catalogue work budget";
        goto finish;
    }
    uint64_t bytes =
        sizeof(*c) + ((uint64_t)m->block_count + 1) * sizeof(*rank) + (uint64_t)m->state_count + 1;
    if (bytes > SIZE_MAX || bytes > l.bytes) {
        out.status = IR_RESOURCE_LIMIT;
        out.message = "branch catalogue validation allocation budget";
        goto finish;
    }
    IrDiagnostic d;
    if (!ir_validate(m, &d)) {
        out.status = d.status;
        out.message = d.message;
        goto finish;
    }
    uint32_t n = 0;
    for (uint32_t i = 0; i < m->block_count; ++i)
        if (m->blocks[i].terminator.kind == IR_TERM_CJUMP)
            ++n;
    bytes += (uint64_t)n * sizeof(IrBranch);
    if (n > l.branches || bytes > SIZE_MAX || bytes > l.bytes) {
        out.status = IR_RESOURCE_LIMIT;
        out.message = "branch catalogue count/allocation budget";
        goto finish;
    }
    out.bytes = (size_t)bytes;
    c = calloc(1, sizeof(*c));
    rank = calloc((size_t)m->block_count + 1, sizeof(*rank));
    if (c && n)
        c->entries = calloc(n, sizeof(*c->entries));
    if (!c || !rank || (n && !c->entries)) {
        out.status = IR_OUT_OF_MEMORY;
        out.message = "branch catalogue allocation";
        goto finish;
    }
    if (!ir_trace_shape(m, rank, false)) {
        out.message = "branch catalogue requires an acyclic trace chain";
        goto finish;
    }
    IrBlockId block = m->entry;
    IrOrigin previous = {0};
    for (uint32_t i = 0; i < m->block_count; ++i) {
        const IrTerminator *t = &m->blocks[block - 1].terminator;
        bool valid;
        IrBlockId next = ir_trace_next(t, &valid);
        if (t->kind == IR_TERM_CJUMP) {
            IrBranch b = {.id = out.count + 1,
                          .block = block,
                          .condition = t->condition,
                          .origin = t->origin,
                          .successors = {t->successors[0], t->successors[1]},
                          .has_observation = t->has_observation,
                          .observed_taken = t->observed_taken,
                          .observed_target = t->observed_target};
            if (!b.origin.has_trace_identity || !b.origin.seq_id)
                b.issues |= IR_BRANCH_IDENTITY_MISSING;
            if (previous.has_trace_identity && b.origin.has_trace_identity &&
                (previous.seq_id >= b.origin.seq_id || previous.vcpu_id != b.origin.vcpu_id))
                b.issues |= IR_BRANCH_ORDER_CONFLICT;
            if (b.origin.has_trace_identity)
                previous = b.origin;
            if (!b.has_observation)
                b.issues |= IR_BRANCH_OBSERVATION_MISSING;
            else {
                IrTarget observed = b.successors[b.observed_taken ? 0 : 1];
                if (next && (observed.kind != IR_TARGET_BLOCK || observed.block != next))
                    b.issues |= IR_BRANCH_ROUTE_CONFLICT;
                uint64_t address;
                if (!target_address(m, observed, &address))
                    b.issues |= IR_BRANCH_TARGET_UNVERIFIED;
                else if (address != b.observed_target)
                    b.issues |= IR_BRANCH_TARGET_CONFLICT;
            }
            out.issues |= b.issues;
            c->entries[out.count++] = b;
        }
        block = next;
    }
    out.status = IR_OK;
    out.message = out.issues ? "catalogue contains incomplete branch evidence" : "ok";
    c->module = m;
    c->revision = m->revision;
    c->inputs = ir_inputs_retain(inputs);
    c->info = out;
finish:
    free(rank);
    if (info)
        *info = out;
    if (out.status != IR_OK) {
        ir_branches_destroy(c);
        c = NULL;
    }
    return c;
}

void ir_branches_destroy(IrBranches *c) {
    if (!c)
        return;
    ir_inputs_release(c->inputs);
    free(c->entries);
    free(c);
}

bool ir_branches_current(const IrBranches *c) {
    return c && c->revision == ir_module_revision(c->module) &&
           ir_module_status(c->module) == IR_OK;
}

IrBranchInfo ir_branches_info(const IrBranches *c) {
    if (!ir_branches_current(c))
        return (IrBranchInfo){.status = IR_INVALID, .message = "missing/stale branch catalogue"};
    return c->info;
}

const IrBranch *ir_branches_at(const IrBranches *c, IrBranchId id) {
    return ir_branches_current(c) && id && id <= c->info.count ? &c->entries[id - 1] : NULL;
}

IrBranchId ir_branches_find(const IrBranches *c, IrOrigin origin) {
    if (!ir_branches_current(c) || !origin.has_trace_identity)
        return 0;
    IrBranchId found = 0;
    for (uint32_t i = 0; i < c->info.count; ++i)
        if (identity_equal(c->entries[i].origin, origin)) {
            if (found)
                return 0;
            found = i + 1;
        }
    return found;
}

IrInvertOptions ir_invert_default_options(void) {
    return (IrInvertOptions){.smt = ir_smt_default_options(),
                             .query = ir_smt_default_query_limits(),
                             .bindings = ir_input_default_limits(),
                             .evaluation = ir_eval_default_limits(),
                             .prefix_branches = 65536,
                             .work = UINT64_C(32000000),
                             .bytes = (size_t)64 * 1024 * 1024};
}

static IrInvertStatus from_ir(IrStatus status) {
    return status == IR_RESOURCE_LIMIT  ? IR_INVERT_RESOURCE_LIMIT
           : status == IR_OUT_OF_MEMORY ? IR_INVERT_OUT_OF_MEMORY
                                        : IR_INVERT_INVALID;
}

static void error(IrInvertResult *r, IrInvertStatus status, const char *message) {
    r->status = status;
    snprintf(r->diagnostic, sizeof(r->diagnostic), "%s", message);
    if (status == IR_INVERT_RESOURCE_LIMIT)
        r->reasons |= IR_REASON_BUDGET;
}

static bool work(IrInvertResult *r, const IrInvertOptions *o, uint64_t n) {
    if (n > o->work - r->work) {
        error(r, IR_INVERT_RESOURCE_LIMIT, "branch inversion wrapper work budget");
        return false;
    }
    r->work += n;
    return true;
}

typedef struct {
    IrBindings states;
    const IrBranches *catalogue;
    const IrInvertOptions *options;
    IrInvertResult *result;
    bool candidate, exhausted;
} Bindings;

static bool binding_work(Bindings *b, uint64_t n) {
    if (!work(b->result, b->options, n))
        b->exhausted = true;
    return !b->exhausted;
}

static IrBits read_bv(void *user, IrBindingKind kind, uint64_t key, uint8_t width) {
    Bindings *b = user;
    if (kind == IR_BIND_INPUT) {
        if (b->candidate)
            for (uint32_t i = 0; i < b->result->model.parameter_count; ++i) {
                if (!binding_work(b, 1))
                    return ir_bits_unknown(IR_REASON_BUDGET);
                const IrSmtParameterValue *p = &b->result->model.parameters[i];
                if (p->key == key && p->width == width)
                    return ir_bits_known(p->value, width);
            }
        for (uint32_t i = 0; i < b->options->smt.parameter_count; ++i) {
            if (!binding_work(b, 1))
                return ir_bits_unknown(IR_REASON_BUDGET);
            const IrSmtParameter *p = &b->options->smt.parameters[i];
            if (p->key == key && p->width == width)
                return p->observed;
        }
        return ir_bits_unknown(IR_REASON_UNBOUND_INPUT);
    }
    /* Charge an upper bound for the catalogue's state/slice lookup. */
    if (!binding_work(b, (uint64_t)ir_inputs_state_count(b->catalogue->inputs) + 65))
        return ir_bits_unknown(IR_REASON_BUDGET);
    return b->states.read_bv ? b->states.read_bv(b->states.user, kind, key, width)
                             : ir_bits_unknown(IR_REASON_UNBOUND_STATE);
}

static IrBits read_byte(void *user, IrBindingKind kind, uint64_t key, uint64_t address) {
    Bindings *b = user;
    if (!binding_work(b, (uint64_t)ir_inputs_state_count(b->catalogue->inputs) +
                             ir_inputs_info(b->catalogue->inputs).count + 1))
        return ir_bits_unknown(IR_REASON_BUDGET);
    return b->states.read_byte ? b->states.read_byte(b->states.user, kind, key, address)
                               : ir_bits_unknown(IR_REASON_MEMORY);
}

static bool concrete(const IrBranches *c, IrBranchId id, const IrInvertOptions *o,
                     IrInvertResult *r, IrEvalBranch *events, bool candidate) {
    IrInputInfo bi = {0};
    IrInputBindings *owner = NULL;
    if (c->inputs) {
        owner = ir_inputs_bindings_create(c->inputs, candidate ? r->model.inputs : NULL,
                                          candidate ? r->model.input_count : 0, &o->bindings, &bi);
        if (!owner) {
            error(r, from_ir(bi.status), "concrete boundary bindings failed");
            return false;
        }
    }
    Bindings context = {.states = ir_inputs_bindings(owner),
                        .catalogue = c,
                        .options = o,
                        .result = r,
                        .candidate = candidate};
    IrBindings bindings = {.user = &context, .read_bv = read_bv, .read_byte = read_byte};
    IrEval *eval = ir_eval_create(c->module, &bindings, &o->evaluation);
    if (!eval) {
        ir_inputs_bindings_destroy(owner);
        error(r, IR_INVERT_OUT_OF_MEMORY, "concrete evaluator allocation failed");
        return false;
    }
    uint32_t count = 0;
    IrEvalResult e = ir_eval_run_to_branch(eval, r->branch.block, events, id, &count);
    size_t bytes = ir_eval_allocated_bytes(eval);
    if (bytes > r->evaluator_bytes)
        r->evaluator_bytes = bytes;
    ir_eval_destroy(eval);
    ir_inputs_bindings_destroy(owner);
    if (candidate)
        r->candidate = e;
    else
        r->baseline = e;
    r->failure_origin = e.origin;
    if (context.exhausted)
        return false;
    r->reasons |= e.reasons;
    /* Compare every encountered outcome, including identical-successor Jcc.
     * A definite earlier mismatch takes precedence over a later UNKNOWN. */
    for (uint32_t i = 0; i < count; ++i) {
        const IrBranch *b = &c->entries[i];
        bool expected = candidate && i + 1 == id ? !b->observed_taken : b->observed_taken;
        if (events[i].block != b->block || !identity_equal(events[i].origin, b->origin) ||
            (ir_bits_complete(events[i].condition, 1) &&
             (bool)events[i].condition.value != expected)) {
            r->failure_origin = events[i].origin;
            error(r, IR_INVERT_MISMATCH,
                  candidate ? "candidate changed the wrong branch outcome"
                            : "observed branch outcome disagrees with boundary execution");
            return false;
        }
    }
    if (e.status != IR_EVAL_BRANCH || count != id) {
        IrInvertStatus status = e.status == IR_EVAL_RESOURCE_LIMIT  ? IR_INVERT_RESOURCE_LIMIT
                                : e.status == IR_EVAL_OUT_OF_MEMORY ? IR_INVERT_OUT_OF_MEMORY
                                : e.status == IR_EVAL_INVALID       ? IR_INVERT_INVALID
                                                                    : IR_INVERT_UNKNOWN;
        error(r, status,
              candidate ? "candidate prefix evaluation incomplete"
                        : "observed prefix evaluation incomplete");
        return false;
    }
    if (candidate)
        r->candidate_verified = true;
    else
        r->baseline_verified = true;
    return true;
}

IrInvertResult ir_branch_invert(const IrBranches *c, IrBranchId id,
                                const IrInvertOptions *options) {
    IrInvertOptions o = options ? *options : ir_invert_default_options();
    IrInvertResult r = {.status = IR_INVERT_INVALID,
                        .model = {.status = IR_SMT_INVALID},
                        .baseline = {.status = IR_EVAL_INVALID},
                        .candidate = {.status = IR_EVAL_INVALID},
                        .build = {.status = IR_INVALID, .message = "not built"}};
    IrSmt *smt = NULL;
    IrSmtBranchConstraint *constraints = NULL;
    IrEvalBranch *events = NULL;
    const IrBranch *selected = ir_branches_at(c, id);
    if (!selected) {
        error(&r, IR_INVERT_INVALID, "missing/stale catalogue or invalid BranchId");
        return r;
    }
    r.branch = *selected;
    r.prefix_count = id;
    r.failure_origin = selected->origin;
    if (id > o.prefix_branches || id > o.query.constraints) {
        error(&r, IR_INVERT_RESOURCE_LIMIT, "branch prefix count budget");
        return r;
    }
    if (!work(&r, &o, 2 * validation_work(c->module) + 4 * (uint64_t)id))
        return r;
    size_t evaluator_bound;
    uint64_t arrays = (uint64_t)id * (sizeof(*constraints) + sizeof(*events));
    if (!ir_eval_allocation_bound(c->module, &o.evaluation, &evaluator_bound) ||
        arrays > SIZE_MAX || arrays > o.bytes || evaluator_bound > o.bytes - arrays) {
        error(&r, IR_INVERT_RESOURCE_LIMIT, "branch prefix/evaluator allocation budget");
        return r;
    }
    r.bytes = (size_t)arrays + evaluator_bound;
    for (uint32_t i = 0; i < id; ++i)
        if (c->entries[i].issues) {
            r.failure_origin = c->entries[i].origin;
            r.reasons = IR_REASON_TRACE_GAP;
            error(&r, IR_INVERT_UNKNOWN,
                  "incomplete/conflicting branch identity, observation or target");
            return r;
        }
    smt = ir_smt_build(c->module, c->inputs, &o.smt, &r.build);
    if (!smt) {
        error(&r, from_ir(r.build.status), r.build.message);
        r.failure_origin = r.build.origin;
        goto finish;
    }
    constraints = calloc(id, sizeof(*constraints));
    events = calloc(id, sizeof(*events));
    if (!constraints || !events) {
        error(&r, IR_INVERT_OUT_OF_MEMORY, "branch prefix allocation failed");
        goto finish;
    }
    for (uint32_t i = 0; i < id; ++i)
        constraints[i] = (IrSmtBranchConstraint){c->entries[i].block,
                                                 i + 1 == id ? !c->entries[i].observed_taken
                                                             : c->entries[i].observed_taken};
    if (!concrete(c, id, &o, &r, events, false))
        goto finish;
    r.model = ir_smt_query_branches(smt, constraints, id, &o.query);
    r.reasons |= r.model.reasons;
    switch (r.model.status) {
    case IR_SMT_SAT:
        if (concrete(c, id, &o, &r, events, true)) {
            r.failure_origin = (IrOrigin){0};
            error(&r, IR_INVERT_VERIFIED,
                  "boundary witness preserves the prefix and inverts the selected branch");
        }
        break;
    case IR_SMT_UNSAT:
        error(&r, IR_INVERT_UNSAT,
              "no inversion for the selected boundary inputs and observed prefix");
        break;
    case IR_SMT_UNKNOWN:
        error(&r, IR_INVERT_UNKNOWN, r.model.diagnostic);
        break;
    case IR_SMT_RESOURCE_LIMIT:
        error(&r, IR_INVERT_RESOURCE_LIMIT, r.model.diagnostic);
        break;
    case IR_SMT_OUT_OF_MEMORY:
        error(&r, IR_INVERT_OUT_OF_MEMORY, r.model.diagnostic);
        break;
    case IR_SMT_INVALID:
        error(&r, IR_INVERT_INVALID, r.model.diagnostic);
        break;
    }
finish:
    if (smt)
        r.build = ir_smt_info(smt);
    ir_smt_destroy(smt);
    free(constraints);
    free(events);
    if (r.status != IR_INVERT_VERIFIED) {
        /* Preserve solver diagnostics without publishing an unchecked witness. */
        IrSmtAnswer diagnostic = r.model;
        ir_smt_answer_destroy(&r.model);
        diagnostic.inputs = NULL;
        diagnostic.parameters = NULL;
        diagnostic.samples = NULL;
        diagnostic.catalogue = NULL;
        diagnostic.input_count = diagnostic.parameter_count = diagnostic.sample_count = 0;
        r.model = diagnostic;
    }
    return r;
}

void ir_invert_result_destroy(IrInvertResult *r) {
    if (!r)
        return;
    ir_smt_answer_destroy(&r->model);
    memset(r, 0, sizeof(*r));
}
