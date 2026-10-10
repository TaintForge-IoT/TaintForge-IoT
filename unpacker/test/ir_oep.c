#include "ir_oep.h"

#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include "ir_oep_identity.h"

IrOepOptions ir_oep_default_options(void) {
    return (IrOepOptions){.replay = ir_replay_default_options(),
        .target_slice = true, .slice = ir_analysis_default_limits(),
        .ssa = ir_analysis_default_limits(), .branches = ir_branch_default_limits(),
        .smt = ir_smt_default_limits(), .query = ir_smt_default_query_limits(),
        .evaluation = ir_eval_default_limits(), .bindings = ir_input_default_limits(),
        .symbolic_inputs = 256, .prefix_branches = 4096,
        .work = UINT64_C(8000000), .bytes = 64U * 1024U * 1024U};
}

static void error(IrOepResult *r, IrOepStatus status, const char *message) {
    r->status = status;
    snprintf(r->diagnostic, sizeof(r->diagnostic), "%s", message ? message : "unknown");
}

static void phase(IrOepResult *r, const IrOepOptions *o, const char *name) {
    r->phase = name;
    if (o->progress) o->progress(o->progress_user, name);
}

static bool work(IrOepResult *r, const IrOepOptions *o, uint64_t n) {
    if (n > o->work - r->work) {
        error(r, IR_OEP_RESOURCE_LIMIT, "wrapper_work_budget");
        return false;
    }
    r->work += n;
    return true;
}

static IrOepStatus from_ir(IrStatus s) {
    return s == IR_RESOURCE_LIMIT ? IR_OEP_RESOURCE_LIMIT
         : s == IR_OUT_OF_MEMORY ? IR_OEP_OUT_OF_MEMORY : IR_OEP_INVALID;
}

static IrOepStatus from_eval(IrEvalStatus s) {
    return s == IR_EVAL_RESOURCE_LIMIT ? IR_OEP_RESOURCE_LIMIT
         : s == IR_EVAL_OUT_OF_MEMORY ? IR_OEP_OUT_OF_MEMORY
         : s == IR_EVAL_INVALID ? IR_OEP_INVALID : IR_OEP_UNKNOWN;
}

static IrOrigin origin(const ReplayStep *s) {
    return s ? (IrOrigin){.seq_id = s->entry.seq_id, .pc = s->entry.pc,
        .descriptor_id = s->entry.insn_desc_id, .code_generation = s->entry.code_generation,
        .vcpu_id = s->entry.vcpu_index, .has_trace_identity = s->descriptor_valid} : (IrOrigin){0};
}

static bool same_origin(IrOrigin a, IrOrigin b) {
    return a.has_trace_identity && b.has_trace_identity && a.seq_id == b.seq_id &&
        a.pc == b.pc && a.descriptor_id == b.descriptor_id &&
        a.code_generation == b.code_generation && a.vcpu_id == b.vcpu_id;
}

static bool select_inputs(const IrInputs *in, const IrOepRequest *q, const IrOepOptions *o,
                           IrOepResult *r, IrInputId *ids, IrSmtInputAlias *aliases) {
    uint32_t cells = ir_inputs_info(in).count;
    for (uint32_t i = 0; i < q->symbolic_count; ++i) {
        const IrOepInput *v = &q->symbolic_inputs[i];
        if ((v->kind != IR_INPUT_STATE_SLICE && v->kind != IR_INPUT_MEMORY_BYTE) ||
            !v->width || v->width > 64 || (uint32_t)v->bit_offset + v->width > 64 ||
            (v->kind == IR_INPUT_STATE_SLICE && v->address) ||
            (v->kind == IR_INPUT_MEMORY_BYTE &&
             (v->bit_offset || v->width != 8 || v->address > UINT32_MAX))) {
            error(r, IR_OEP_INVALID, "invalid_input_selector");
            return false;
        }
        for (IrInputId id = 1; id <= cells; ++id) {
            if (!work(r, o, 1)) return false;
            const IrInputCell *c = ir_inputs_cell(in, id);
            const IrInputState *s = c ? ir_inputs_state(in, c->state) : NULL;
            if (s && s->key == v->state_key && c->kind == v->kind && c->address == v->address &&
                c->bit_offset == v->bit_offset && c->width == v->width) {
                if (!ir_bits_complete(c->observed, c->width)) {
                    error(r, IR_OEP_UNKNOWN, "selected_input_observation_missing");
                    return false;
                }
                ids[i] = id;
                break;
            }
        }
        if (!ids[i]) {
            error(r, IR_OEP_INVALID, "selected_cell_not_in_boundary");
            return false;
        }
        for (uint32_t j = 0; j < i; ++j) {
            if (!work(r, o, 1)) return false;
            if (ids[i] == ids[j]) {
                error(r, IR_OEP_INVALID, "duplicate_symbolic_cell");
                return false;
            }
        }
        if (v->same_as) {
            if (v->same_as > i || q->symbolic_inputs[v->same_as - 1].same_as) {
                error(r, IR_OEP_INVALID, "invalid_alias_selector"); return false;
            }
            const IrInputCell *c = ir_inputs_cell(in, ids[i]);
            const IrInputCell *root = ir_inputs_cell(in, ids[v->same_as - 1]);
            if (c->width != root->width || c->observed.value != root->observed.value) {
                error(r, IR_OEP_INVALID, "alias_observation_mismatch"); return false;
            }
            aliases[r->input_aliases++] = (IrSmtInputAlias){ids[i], ids[v->same_as - 1]};
        }
    }
    r->symbolic_count = q->symbolic_count;
    return true;
}

typedef struct {
    IrBindings base;
    const IrInputs *inputs;
    const IrOepOptions *options;
    IrOepResult *result;
    bool exhausted;
} Bindings;

static IrBits read_bv(void *user, IrBindingKind kind, uint64_t key, uint8_t width) {
    Bindings *b = user;
    if (!work(b->result, b->options, (uint64_t)ir_inputs_state_count(b->inputs) + 65)) {
        b->exhausted = true;
        return ir_bits_unknown(IR_REASON_BUDGET);
    }
    return b->base.read_bv ? b->base.read_bv(b->base.user, kind, key, width)
                          : ir_bits_unknown(IR_REASON_UNBOUND_STATE);
}

static IrBits read_byte(void *user, IrBindingKind kind, uint64_t key, uint64_t address) {
    Bindings *b = user;
    if (!work(b->result, b->options, (uint64_t)ir_inputs_state_count(b->inputs) +
                                   ir_inputs_info(b->inputs).count + 1)) {
        b->exhausted = true;
        return ir_bits_unknown(IR_REASON_BUDGET);
    }
    return b->base.read_byte ? b->base.read_byte(b->base.user, kind, key, address)
                            : ir_bits_unknown(IR_REASON_MEMORY);
}

static bool witness(IrReplay *replay, const IrBranch *prefix, const IrOepOptions *o,
                      IrOepResult *r, IrEvalBranch *events, bool equal) {
    phase(r, o, equal ? "candidate_replay" : "alternative_replay");
    IrSmtAnswer *answer = equal ? &r->candidate : &r->alternative;
    if (answer->input_count != r->symbolic_count || answer->parameter_count) {
        error(r, IR_OEP_MISMATCH, "witness_input_domain_mismatch");
        return false;
    }
    IrInputInfo info = {0};
    const IrInputs *in = ir_replay_inputs(replay);
    IrInputBindings *owner = ir_inputs_bindings_create(in, answer->inputs, answer->input_count,
                                                       &o->bindings, &info);
    if (!owner) {
        error(r, from_ir(info.status), "witness_bindings_failed");
        return false;
    }
    Bindings b = {.base = ir_inputs_bindings(owner), .inputs = in, .options = o, .result = r};
    IrBindings bindings = {.user = &b, .read_bv = read_bv, .read_byte = read_byte};
    IrEval *eval = ir_eval_create(ir_replay_module(replay), &bindings, &o->evaluation);
    if (!eval) {
        ir_inputs_bindings_destroy(owner);
        error(r, IR_OEP_OUT_OF_MEMORY, "witness_evaluator_failed");
        return false;
    }
    IrReplayTarget target = ir_replay_target(replay);
    uint32_t count = 0;
    IrEvalResult execution = ir_eval_run_to_fragment(eval, target.boundary, events,
                                                     r->prefix_count, &count);
    IrEvalValue value = ir_eval_value(eval, target.value);
    size_t bytes = ir_eval_allocated_bytes(eval);
    if (bytes > r->evaluator_bytes) r->evaluator_bytes = bytes;
    ir_eval_destroy(eval);
    ir_inputs_bindings_destroy(owner);
    if (equal) {
        r->candidate_replay = execution;
        r->candidate_target = value.bits;
    } else {
        r->alternative_replay = execution;
        r->alternative_target = value.bits;
    }
    r->failure_origin = execution.origin;
    r->reasons |= execution.reasons;
    if (b.exhausted) return false;
    for (uint32_t i = 0; i < count; ++i) {
        if (!work(r, o, 1)) return false;
        const IrBranch *branch = &prefix[i];
        if (branch->block != events[i].block ||
            !same_origin(branch->origin, events[i].origin) ||
            (ir_bits_complete(events[i].condition, 1) &&
             (bool)events[i].condition.value != branch->observed_taken)) {
            r->failure_origin = events[i].origin;
            error(r, IR_OEP_MISMATCH, "witness_changed_prefix");
            return false;
        }
    }
    if (execution.status != IR_EVAL_FRAGMENT_END || count != r->prefix_count ||
        execution.quality.semantic || execution.quality.control || execution.quality.observation) {
        error(r, from_eval(execution.status), "witness_prefix_incomplete");
        return false;
    }
    if (value.type.kind != IR_TYPE_BV || value.type.bits != 32 ||
        !ir_bits_complete(value.bits, 32)) {
        error(r, IR_OEP_UNKNOWN, "witness_target_unknown");
        return false;
    }
    if ((value.bits.value == r->candidate_address) != equal) {
        error(r, IR_OEP_MISMATCH, "witness_target_relation_mismatch");
        return false;
    }
    if (equal) r->candidate_verified = true;
    else r->alternative_verified = true;
    return true;
}

static void solver_error(IrOepResult *r, const IrSmtAnswer *a) {
    IrOepStatus status = a->status == IR_SMT_RESOURCE_LIMIT ? IR_OEP_RESOURCE_LIMIT
                       : a->status == IR_SMT_OUT_OF_MEMORY ? IR_OEP_OUT_OF_MEMORY
                       : a->status == IR_SMT_INVALID ? IR_OEP_INVALID : IR_OEP_UNKNOWN;
    error(r, status, a->diagnostic);
}

static void discard_unchecked(IrSmtAnswer *a) {
    IrSmtAnswer info = *a;
    ir_smt_answer_destroy(a);
    info.inputs = NULL; info.parameters = NULL; info.samples = NULL; info.catalogue = NULL;
    info.input_count = info.parameter_count = info.sample_count = 0;
    *a = info;
}

static bool rebuild(const ReplayInput *input, const IrInputs *original_inputs,
                    const IrOepOptions *o, IrReplay **replay, IrOepResult *r) {
    phase(r, o, "rebuild"); r->rebuild_attempted = true;
    *replay = ir_replay_x86_build(input, &o->replay, &r->rebuilt_build);
    IrReplayBuildStatus status = r->rebuilt_build.status;
    if (!*replay || status != IR_REPLAY_READY || r->rebuilt_build.lifted_steps != r->selected_steps) {
        r->failure_origin = origin(replay_input_find(input, r->rebuilt_build.stopped_seq));
        error(r, status == IR_REPLAY_RESOURCE_LIMIT ||
                 (r->rebuilt_build.issues & (IR_REPLAY_BUDGET | IR_REPLAY_INPUT_BUDGET)) ? IR_OEP_RESOURCE_LIMIT
               : status == IR_REPLAY_OUT_OF_MEMORY ? IR_OEP_OUT_OF_MEMORY
               : status == IR_REPLAY_INVALID ? IR_OEP_INVALID : IR_OEP_UNKNOWN,
              "witness_rebuild_incomplete");
        return false;
    }
    phase(r, o, "rebuild_ssa");
    IrTraceSsaOptions ssa = ir_trace_ssa_default_options(); ssa.limits = o->ssa;
    r->rebuilt_ssa = ir_trace_ssa(ir_replay_module(*replay), &ssa);
    if (r->rebuilt_ssa.analysis.status != IR_OK) {
        error(r, from_ir(r->rebuilt_ssa.analysis.status), "witness_rebuild_ssa_failed"); return false;
    }
    phase(r, o, "rebuild_check");
    const IrInputs *in = ir_replay_inputs(*replay);
    if (!work(r, o, UINT64_C(20) * ir_inputs_info(original_inputs).count +
                    UINT64_C(6) * ir_inputs_state_count(original_inputs) + 16)) return false;
    if (!oep_inputs_equal(original_inputs, in)) {
        error(r, IR_OEP_MISMATCH, "witness_rebuild_inputs_changed"); return false;
    }
    if (!work(r, o, oep_hash_work(ir_replay_module(*replay)))) return false;
    if (!oep_hash_module(ir_replay_module(*replay), ir_replay_target(*replay), r->rebuilt_sha256)) {
        error(r, IR_OEP_OUT_OF_MEMORY, "witness_rebuild_hash_allocation"); return false;
    }
    if (strcmp(r->replay_sha256, r->rebuilt_sha256)) {
        error(r, IR_OEP_MISMATCH, "witness_rebuild_ir_changed"); return false;
    }
    r->rebuild_verified = true;
    return true;
}

IrOepResult ir_oep_verify(const ReplayInput *input, const IrOepRequest *request,
                          const IrOepOptions *options) {
    IrOepRequest resolved = request ? *request : (IrOepRequest){0};
    const IrOepRequest *q = &resolved;
    IrOepResult r = {.status = IR_OEP_UNKNOWN,
        .replay_build = {.status = IR_REPLAY_INVALID},
        .baseline = {.status = IR_REPLAY_CHECK_UNKNOWN, .execution = {.status = IR_EVAL_INVALID}},
        .ssa = {.analysis = {.status = IR_INVALID}}, .smt = {.status = IR_INVALID},
        .candidate = {.status = IR_SMT_INVALID}, .alternative = {.status = IR_SMT_INVALID},
        .candidate_replay = {.status = IR_EVAL_INVALID},
        .alternative_replay = {.status = IR_EVAL_INVALID},
        .rebuilt_build = {.status = IR_REPLAY_INVALID},
        .rebuilt_ssa = {.analysis = {.status = IR_INVALID}}};
    IrOepOptions o = options ? *options : ir_oep_default_options();
    IrReplay *replay = NULL;
    IrBranches *branches = NULL;
    IrBranch *prefix = NULL;
    IrInputs *catalogue = NULL;
    IrSmt *smt = NULL;
    IrModule *slice = NULL;
    IrInputId *ids = NULL;
    IrSmtInputAlias *aliases = NULL;
    IrSmtConstraint *constraints = NULL;
    IrValueId *retained = NULL;
    IrEvalBranch *events = NULL;
    const ReplayStep *first = replay_input_step(input, 0), *trigger = replay_input_trigger(input);
    uint32_t count = replay_input_count(input);
    r.phase = "request";
    if (!request || !input || !first || !trigger || !count || !q->first_seq || !q->trigger_seq ||
        q->candidate_address > UINT32_MAX ||
        first->entry.seq_id != q->first_seq || trigger->entry.seq_id != q->trigger_seq ||
        first->entry.vcpu_index != q->vcpu || trigger->entry.vcpu_index != q->vcpu ||
        (q->symbolic_count && !q->symbolic_inputs) ||
        (q->select_inputs && (q->symbolic_inputs || q->symbolic_count))) {
        error(&r, IR_OEP_INVALID, "request_boundary_identity");
        return r;
    }
    r.first_seq = q->first_seq; r.trigger_seq = q->trigger_seq;
    r.candidate_address = q->candidate_address; r.vcpu = q->vcpu;
    r.trigger = origin(trigger); r.selected_steps = count;
    if (o.rebuild_replay && !o.target_slice) {
        error(&r, IR_OEP_INVALID, "rebuild_requires_target_slice"); return r;
    }
    if (!q->flags_verified) {
        error(&r, IR_OEP_UNKNOWN, "flag_observations_unverified");
        return r;
    }
    if (!q->symbolic_count && !q->select_inputs) {
        error(&r, IR_OEP_UNKNOWN, "explicit_symbolic_inputs_required");
        return r;
    }
    if (!trigger->descriptor_valid || trigger->issues ||
        !trigger->occurrence.execution_complete || !trigger->occurrence.next_pc_valid ||
        trigger->occurrence.next_pc > UINT32_MAX) {
        error(&r, IR_OEP_UNKNOWN, "trigger_observation_incomplete");
        return r;
    }
    r.observed_target = trigger->occurrence.next_pc;
    if (q->symbolic_count > o.symbolic_inputs ||
        (uint64_t)q->symbolic_count * sizeof(*ids) > o.bytes ||
        !work(&r, &o, (uint64_t)count + q->symbolic_count)) {
        error(&r, IR_OEP_RESOURCE_LIMIT, "selection_budget");
        return r;
    }
    o.replay.capture_target = true;
    o.replay.compare_target = true;
    o.replay.target_candidate = (uint32_t)q->candidate_address;
    phase(&r, &o, "build");
    replay = ir_replay_x86_build(input, &o.replay, &r.replay_build);
    if (!replay || r.replay_build.status != IR_REPLAY_READY ||
        r.replay_build.lifted_steps != count) {
        r.failure_origin = origin(replay_input_find(input, r.replay_build.stopped_seq));
        IrReplayBuildStatus s = r.replay_build.status;
        error(&r, s == IR_REPLAY_RESOURCE_LIMIT ||
                  (r.replay_build.issues & (IR_REPLAY_BUDGET | IR_REPLAY_INPUT_BUDGET))
                      ? IR_OEP_RESOURCE_LIMIT
                  : s == IR_REPLAY_OUT_OF_MEMORY ? IR_OEP_OUT_OF_MEMORY
                  : s == IR_REPLAY_INVALID ? IR_OEP_INVALID : IR_OEP_UNKNOWN,
              "replay_build_incomplete");
        goto done;
    }
    IrReplayTarget target = ir_replay_target(replay);
    if (target.status != IR_X86_LIFT_OK || !target.value || !target.boundary ||
        !target.matches_candidate) {
        error(&r, IR_OEP_UNKNOWN, "target_projection_unsupported");
        goto done;
    }
    phase(&r, &o, "input_selection");
    if (q->select_inputs && !q->select_inputs(q->selection_user, ir_replay_inputs(replay),
            o.symbolic_inputs, &resolved.symbolic_inputs, &resolved.symbolic_count)) {
        error(&r, IR_OEP_UNKNOWN, "input_selection_policy_failed"); goto done;
    }
    if (!q->symbolic_count || !q->symbolic_inputs) {
        error(&r, IR_OEP_UNKNOWN, "explicit_symbolic_inputs_required"); goto done;
    }
    uint64_t selection_bytes = (uint64_t)q->symbolic_count * (sizeof(*ids) + sizeof(*aliases));
    if (q->symbolic_count > o.symbolic_inputs || selection_bytes > o.bytes ||
        !work(&r, &o, q->symbolic_count)) {
        error(&r, IR_OEP_RESOURCE_LIMIT, "selection_budget"); goto done;
    }
    ids = calloc(q->symbolic_count, sizeof(*ids));
    aliases = calloc(q->symbolic_count, sizeof(*aliases));
    if (!ids || !aliases) { error(&r, IR_OEP_OUT_OF_MEMORY, "input_selection_allocation"); goto done; }
    if (!select_inputs(ir_replay_inputs(replay), q, &o, &r, ids, aliases)) goto done;
    phase(&r, &o, "baseline");
    size_t eval_bytes = 0;
    if (!ir_eval_allocation_bound(ir_replay_module(replay), &o.evaluation, &eval_bytes) ||
        eval_bytes > o.bytes - (size_t)selection_bytes) {
        error(&r, IR_OEP_RESOURCE_LIMIT, "baseline_evaluator_budget");
        goto done;
    }
    r.baseline = ir_replay_check_target(replay, &o.evaluation, q->trigger_seq,
                                       (uint32_t)r.observed_target);
    if (r.baseline.status != IR_REPLAY_CHECK_MATCH) {
        r.failure_origin = r.baseline.has_first_mismatch ? r.baseline.first_mismatch.origin
                                                         : r.baseline.execution.origin;
        error(&r, r.baseline.status == IR_REPLAY_CHECK_MISMATCH ? IR_OEP_MISMATCH
                                                               : from_eval(r.baseline.execution.status),
              "baseline_replay_failed");
        goto done;
    }
    r.baseline_verified = true;
    phase(&r, &o, "ssa");
    IrTraceSsaOptions ssa = ir_trace_ssa_default_options();
    ssa.limits = o.ssa;
    r.ssa = ir_trace_ssa(ir_replay_module(replay), &ssa);
    if (r.ssa.analysis.status != IR_OK) {
        error(&r, from_ir(r.ssa.analysis.status), "trace_ssa_failed");
        goto done;
    }
    IrBranchInfo bi;
    phase(&r, &o, "branches");
    branches = ir_branches_build(ir_replay_module(replay), ir_replay_inputs(replay), &o.branches, &bi);
    if (!branches) { error(&r, from_ir(bi.status), "branch_catalogue_failed"); goto done; }
    r.prefix_count = bi.count;
    if (bi.issues) { error(&r, IR_OEP_UNKNOWN, "branch_evidence_incomplete"); goto done; }
    uint64_t owned = selection_bytes +
                    ((uint64_t)bi.count + 1) * sizeof(*constraints) +
                    ((uint64_t)bi.count + 2) * sizeof(*retained) +
                    (uint64_t)bi.count * (sizeof(*events) + sizeof(*prefix));
    if (bi.count > o.prefix_branches || bi.count > UINT32_MAX - 2 || owned > SIZE_MAX ||
        !ir_eval_allocation_bound(ir_replay_module(replay), &o.evaluation, &eval_bytes) ||
        owned > o.bytes || eval_bytes > o.bytes - (size_t)owned) {
        error(&r, IR_OEP_RESOURCE_LIMIT, "prefix_evaluator_budget");
        goto done;
    }
    r.bytes = (size_t)owned + eval_bytes;
    constraints = calloc((size_t)bi.count + 1, sizeof(*constraints));
    retained = calloc((size_t)bi.count + 2, sizeof(*retained));
    events = bi.count ? calloc(bi.count, sizeof(*events)) : NULL;
    prefix = bi.count ? calloc(bi.count, sizeof(*prefix)) : NULL;
    if (!constraints || !retained || (bi.count && (!events || !prefix))) {
        error(&r, IR_OEP_OUT_OF_MEMORY, "prefix_allocation"); goto done;
    }
    for (uint32_t i = 0; i < bi.count; ++i) {
        if (!work(&r, &o, 1)) goto done;
        const IrBranch *b = ir_branches_at(branches, i + 1);
        if (!b || b->issues || !b->has_observation || b->origin.seq_id >= q->trigger_seq) {
            error(&r, IR_OEP_UNKNOWN, "prefix_branch_missing"); goto done;
        }
        constraints[i] = (IrSmtConstraint){b->condition, b->observed_taken, 1};
        retained[i] = b->condition;
        prefix[i] = *b;
    }
    ir_branches_destroy(branches); branches = NULL;
    /* The final predicate is defined at the trigger, after ALL earlier
     * guards/effects. Its reachability is conjoined with every condition.
     * Thus an early condition/target definition cannot omit a later guard. */
    constraints[bi.count] = (IrSmtConstraint){target.matches_candidate, 1, 1};
    retained[bi.count] = target.matches_candidate;
    retained[bi.count + 1] = target.value;
    IrSmtOptions so = {.limits = o.smt, .symbolic_inputs = ids,
                       .symbolic_count = q->symbolic_count,
                       .aliases = aliases, .alias_count = r.input_aliases,
                       .legacy_context = o.legacy_smt_context,
                       .retained_values_only = !o.legacy_smt_context,
                       .retained_values = retained,
                       .retained_value_count = o.legacy_smt_context ? 0 : bi.count + 2};
    const IrModule *solver_module = ir_replay_module(replay);
    if (o.target_slice) {
        phase(&r, &o, "slice");
        IrValueId roots[] = {target.value, target.matches_candidate};
        IrTargetSliceOptions slice_options = {.limits = o.slice, .boundary = target.boundary,
                                               .values = roots, .value_count = 2};
        r.slice_attempted = true;
        slice = ir_trace_target_slice(solver_module, &slice_options, &r.slice);
        if (!slice) { error(&r, from_ir(r.slice.analysis.status), "target_slice_failed"); goto done; }
        solver_module = slice;
    }
    catalogue = ir_inputs_retain(ir_replay_inputs(replay));
    if (o.rebuild_replay) {
        phase(&r, &o, "replay_identity");
        if (!work(&r, &o, oep_hash_work(ir_replay_module(replay)))) goto done;
        if (!oep_hash_module(ir_replay_module(replay), target, r.replay_sha256)) {
            error(&r, IR_OEP_OUT_OF_MEMORY, "replay_hash_allocation"); goto done;
        }
        r.retained_input_bytes = ir_inputs_bytes(catalogue);
        size_t allocated = ir_replay_allocated_bytes(replay);
        r.released_replay_bytes = allocated >= r.retained_input_bytes ? allocated-r.retained_input_bytes : 0;
        phase(&r, &o, "release_replay");
        ir_replay_destroy(replay); replay = NULL; r.replay_released = true;
        phase(&r, &o, "replay_released");
    }
    phase(&r, &o, "smt_build");
    smt = ir_smt_build(solver_module, catalogue, &so, &r.smt);
    if (!smt) {
        r.failure_origin = r.smt.origin;
        error(&r, from_ir(r.smt.status), "smt_build_failed"); goto done;
    }
    r.candidate_attempted = true;
    phase(&r, &o, "candidate_query");
    r.candidate = ir_smt_query(smt, constraints, bi.count + 1, &target.value, 1, &o.query);
    r.reasons |= r.candidate.reasons;
    if (r.candidate.status == IR_SMT_UNSAT) {
        error(&r, IR_OEP_REFUTED, "candidate_unsat_in_fragment"); goto done;
    }
    if (r.candidate.status != IR_SMT_SAT) { solver_error(&r, &r.candidate); goto done; }
    if (!o.rebuild_replay && !witness(replay, prefix, &o, &r, events, true)) goto done;
    constraints[bi.count].expected = 0;
    r.alternative_attempted = true;
    phase(&r, &o, "alternative_query");
    r.alternative = ir_smt_query(smt, constraints, bi.count + 1, &target.value, 1, &o.query);
    r.reasons |= r.alternative.reasons;
    if (o.rebuild_replay) {
        r.smt = ir_smt_info(smt);
        phase(&r, &o, "release_smt");
        ir_smt_destroy(smt); smt = NULL;
        ir_module_destroy(slice); slice = NULL; r.smt_released = true;
        phase(&r, &o, "smt_released");
        if (!rebuild(input, catalogue, &o, &replay, &r)) goto done;
        if (!witness(replay, prefix, &o, &r, events, true)) goto done;
    }
    if (r.alternative.status == IR_SMT_UNSAT) {
        error(&r, IR_OEP_UNIQUE, "target_unique_for_selected_boundary_inputs");
    } else if (r.alternative.status == IR_SMT_SAT) {
        if (witness(replay, prefix, &o, &r, events, false))
            error(&r, IR_OEP_NONUNIQUE, "alternative_target_witness_verified");
    } else solver_error(&r, &r.alternative);
done:
    if (smt) r.smt = ir_smt_info(smt);
    ir_smt_destroy(smt);
    ir_module_destroy(slice);
    ir_branches_destroy(branches);
    ir_replay_destroy(replay);
    ir_inputs_release(catalogue);
    free(ids); free(aliases); free(constraints); free(retained); free(events); free(prefix);
    if (!r.candidate_verified) discard_unchecked(&r.candidate);
    if (!r.alternative_verified) discard_unchecked(&r.alternative);
    if (r.status == IR_OEP_UNIQUE || r.status == IR_OEP_NONUNIQUE || r.status == IR_OEP_REFUTED)
        r.failure_origin = (IrOrigin){0};
    return r;
}

void ir_oep_result_destroy(IrOepResult *r) {
    if (!r) return;
    ir_smt_answer_destroy(&r->candidate);
    ir_smt_answer_destroy(&r->alternative);
    memset(r, 0, sizeof(*r));
}

const char *ir_oep_status_name(IrOepStatus s) {
    static const char *const names[] = {"UNKNOWN", "UNIQUE_ON_FRAGMENT", "NONUNIQUE",
        "REFUTED_ON_FRAGMENT", "MISMATCH", "RESOURCE_LIMIT", "INVALID", "OUT_OF_MEMORY"};
    return (unsigned)s < sizeof(names) / sizeof(*names) ? names[s] : "INVALID";
}

static const char *query_name(bool attempted, IrSmtStatus status) {
    static const char *const names[] = {"SAT", "UNSAT", "UNKNOWN", "RESOURCE_LIMIT",
                                       "INVALID", "OUT_OF_MEMORY"};
    return !attempted ? "NOT_RUN"
         : (unsigned)status < sizeof(names) / sizeof(*names) ? names[status] : "INVALID";
}

static void json_string(FILE *f, const char *s) {
    fputc('"', f);
    for (const unsigned char *p = (const unsigned char *)s; *p; ++p) {
        if (*p == '"' || *p == '\\') { fputc('\\', f); fputc(*p, f); }
        else if (*p < 32) fprintf(f, "\\u%04x", *p);
        else fputc(*p, f);
    }
    fputc('"', f);
}

bool ir_oep_report_json(FILE *f, const IrOepResult *r) {
    if (!f || !r) return false;
    fprintf(f, "{\"schema\":1,\"scope\":\"boundary_fragment\",\"status\":\"%s\","
        "\"first_seq\":%" PRIu64 ",\"trigger_seq\":%" PRIu64 ",\"vcpu\":%u,"
        "\"candidate_address\":%" PRIu64 ",\"observed_target\":%" PRIu64 ","
        "\"selected_steps\":%u,\"symbolic_inputs\":%u,\"prefix_branches\":%u,"
        "\"baseline_verified\":%s,\"candidate_query\":\"%s\",\"alternative_query\":\"%s\","
        "\"candidate_verified\":%s,\"alternative_verified\":%s,\"reasons\":%u,"
        "\"stop_seq\":%" PRIu64 ",\"build_issues\":%u,\"solver_checks\":%u,\"diagnostic\":",
        ir_oep_status_name(r->status), r->first_seq, r->trigger_seq, r->vcpu,
        r->candidate_address, r->observed_target, r->selected_steps, r->symbolic_count,
        r->prefix_count, r->baseline_verified ? "true" : "false",
        query_name(r->candidate_attempted, r->candidate.status),
        query_name(r->alternative_attempted, r->alternative.status),
        r->candidate_verified ? "true" : "false", r->alternative_verified ? "true" : "false",
        r->reasons, r->replay_build.stopped_seq, r->replay_build.issues,
        r->candidate.solver_checks + r->alternative.solver_checks);
    json_string(f, r->diagnostic);
    fputs(",\"construction\":", f); ir_build_report_json(f, &r->replay_build.construction);
    fputs(",\"replay_budget\":", f); ir_budget_report_json(f, &r->replay_build.replay_budget);
    fprintf(f, ",\"slice\":{\"attempted\":%s,\"status\":%u,\"records\":%u,"
        "\"active_before\":%u,\"active_after\":%u,\"removed\":%u,\"removed_writes\":%u,"
        "\"outputs_before\":%u,\"outputs_after\":%u,\"guards\":%u,\"barriers\":%u,"
        "\"conditions\":%u,\"indirect_targets\":%u,\"retained_bytes\":%zu,\"work\":%" PRIu64
        ",\"peak_bytes\":%zu},\"smt_lowered_values\":%u",
        r->slice_attempted ? "true" : "false", r->slice.analysis.status, r->slice.records,
        r->slice.active_before, r->slice.active_after, r->slice.removed, r->slice.removed_writes,
        r->slice.outputs_before, r->slice.outputs_after, r->slice.guards, r->slice.barriers,
        r->slice.conditions, r->slice.indirect_targets, r->slice.retained_bytes,
        r->slice.analysis.work, r->slice.analysis.bytes, r->smt.lowered_values);
    fputs(",\"phase\":", f); json_string(f, r->phase ? r->phase : "request");
    fprintf(f, ",\"input_aliases\":%u,\"independent_inputs\":%u,"
        "\"wrapper_work\":%" PRIu64 ",\"wrapper_bytes\":%zu,\"evaluator_bytes\":%zu,"
        "\"baseline\":{\"status\":%u,\"checked\":%u,\"mismatches\":%u,\"unknown\":%u,"
        "\"steps\":%" PRIu64 ",\"memory_queries\":%" PRIu64 ",\"evaluator_bytes\":%zu},"
        "\"ssa\":{\"status\":%u,\"work\":%" PRIu64 ",\"peak_bytes\":%zu,\"removed\":%u},"
        "\"smt\":{\"status\":%u,\"work\":%" PRIu64 ",\"constructors\":%" PRIu64 ",\"bytes\":%zu,"
        "\"origin\":{\"seq\":%" PRIu64 ",\"pc\":%" PRIu64 "},\"message\":",
        r->input_aliases, r->symbolic_count >= r->input_aliases ? r->symbolic_count-r->input_aliases : 0,
        r->work, r->bytes, r->evaluator_bytes,
        r->baseline.status, r->baseline.checked, r->baseline.mismatches, r->baseline.unknown,
        r->baseline.execution.steps, r->baseline.execution.memory_queries, r->baseline.evaluator_bytes,
        r->ssa.analysis.status, r->ssa.analysis.work, r->ssa.analysis.bytes, r->ssa.removed,
        r->smt.status, r->smt.work, r->smt.constructors, r->smt.bytes,
        r->smt.origin.seq_id, r->smt.origin.pc);
    json_string(f, r->smt.message ? r->smt.message : "not_run");
    fprintf(f, "},\"failure_origin\":{\"seq\":%" PRIu64 ",\"pc\":%" PRIu64 "},"
        "\"candidate_diagnostic\":", r->failure_origin.seq_id, r->failure_origin.pc);
    json_string(f, r->candidate.diagnostic);
    fputs(",\"alternative_diagnostic\":", f); json_string(f, r->alternative.diagnostic);
    fprintf(f, ",\"candidate_replay\":{\"status\":%u,\"steps\":%" PRIu64 ",\"memory_queries\":%" PRIu64
        ",\"target\":%" PRIu64 ",\"target_mask\":%" PRIu64 "},"
        "\"alternative_replay\":{\"status\":%u,\"steps\":%" PRIu64 ",\"memory_queries\":%" PRIu64
        ",\"target\":%" PRIu64 ",\"target_mask\":%" PRIu64 "}",
        r->candidate_replay.status, r->candidate_replay.steps, r->candidate_replay.memory_queries,
        r->candidate_target.value, r->candidate_target.known_mask,
        r->alternative_replay.status, r->alternative_replay.steps, r->alternative_replay.memory_queries,
        r->alternative_target.value, r->alternative_target.known_mask);
    fputs(",\"z3_error\":", f); ir_smt_z3_error_report_json(f, &r->smt.z3_error);
    fputs(",\"smt_lifetime\":", f); ir_smt_lifetime_report_json(f, &r->smt);
    fputs(",\"candidate_checks\":", f); ir_smt_checks_report_json(f, &r->candidate);
    fputs(",\"alternative_checks\":", f); ir_smt_checks_report_json(f, &r->alternative);
    fprintf(f, ",\"lifetime\":{\"replay_released\":%s,\"smt_released\":%s,"
        "\"rebuild_attempted\":%s,\"rebuild_verified\":%s,\"released_replay_owned_bytes\":%zu,"
        "\"retained_input_bytes\":%zu,\"original_ir_sha256\":\"%s\",\"rebuilt_ir_sha256\":\"%s\","
        "\"rebuild_status\":%u,\"rebuild_lifted_steps\":%u,\"rebuild_stop_seq\":%" PRIu64 ","
        "\"rebuild_ssa_status\":%u,\"rebuild_ssa_work\":%" PRIu64 ",\"rebuild_ssa_peak_bytes\":%zu}}\n",
        r->replay_released ? "true" : "false", r->smt_released ? "true" : "false",
        r->rebuild_attempted ? "true" : "false", r->rebuild_verified ? "true" : "false",
        r->released_replay_bytes, r->retained_input_bytes, r->replay_sha256, r->rebuilt_sha256,
        r->rebuilt_build.status, r->rebuilt_build.lifted_steps, r->rebuilt_build.stopped_seq,
        r->rebuilt_ssa.analysis.status, r->rebuilt_ssa.analysis.work, r->rebuilt_ssa.analysis.bytes);
    return !ferror(f);
}
