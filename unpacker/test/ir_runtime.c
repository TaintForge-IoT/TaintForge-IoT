#include "ir_runtime.h"

#include <glib.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

IrRuntimeOptions ir_runtime_default_options(void) {
    IrRuntimeOptions o = {.window_steps = 64,
                          .max_checks = 16,
                          .capture_bytes = 8U * 1024U * 1024U,
                          .replay = ir_replay_default_options(),
                          .eval = ir_eval_default_limits(),
                          .trace_ssa = true,
                          .analysis = ir_analysis_default_limits()};
    o.sources = replay_source_default_limits();
    o.replay.max_steps = IR_RUNTIME_MAX_WINDOW;
    return o;
}

bool ir_runtime_init(IrRuntime *r, const IrRuntimeOptions *options) {
    if (!r)
        return false;
    IrRuntimeOptions o = options ? *options : ir_runtime_default_options();
    if (!o.window_steps || o.window_steps > IR_RUNTIME_MAX_WINDOW || !o.max_checks ||
        o.max_checks > IR_RUNTIME_MAX_CHECKS || !o.capture_bytes)
        return false;
    *r = (IrRuntime){.options = o};
    return true;
}

const char *ir_runtime_status_name(IrReplayCheckStatus s) {
    switch (s) {
    case IR_REPLAY_CHECK_MATCH:
        return "MATCH";
    case IR_REPLAY_CHECK_MISMATCH:
        return "MISMATCH";
    case IR_REPLAY_CHECK_UNKNOWN:
        return "UNKNOWN";
    default:
        return "ERROR";
    }
}

static uint64_t elapsed(gint64 start) {
    gint64 now = g_get_monotonic_time();
    return now >= start ? (uint64_t)(now - start) : 0;
}

static void account(IrRuntime *r, IrRuntimeReport *p, gint64 start) {
    p->total_us = elapsed(start);
    switch (p->status) {
    case IR_REPLAY_CHECK_MATCH:
        ++r->matches;
        break;
    case IR_REPLAY_CHECK_MISMATCH:
        ++r->mismatches;
        break;
    case IR_REPLAY_CHECK_UNKNOWN:
        ++r->unknown;
        break;
    default:
        ++r->errors;
        break;
    }
    r->selected_steps += p->selected_steps;
    r->lifted_steps += p->build.lifted_steps;
    r->total_us += p->total_us;
    if (p->capture_bytes > r->peak_capture_bytes)
        r->peak_capture_bytes = p->capture_bytes;
    if (p->replay_bytes > r->peak_replay_bytes)
        r->peak_replay_bytes = p->replay_bytes;
    if (p->check.evaluator_bytes > r->peak_evaluator_bytes)
        r->peak_evaluator_bytes = p->check.evaluator_bytes;
}

static bool target_supported(const ReplayStep *t, int reg) {
    return t && t->descriptor_valid && reg >= 0 && reg < (int)IR_X86_GPR_COUNT &&
           t->descriptor.arch == TRACE_ARCH_X86 && t->descriptor.mode == TRACE_MODE_32 &&
           t->entry.size == 2 && t->entry.instr_bytes[0] == 0xff &&
           t->entry.instr_bytes[1] == (uint8_t)(0xe0 + reg);
}

bool ir_runtime_check_sources(IrRuntime *r, const TraceBuffer *trace, const DseAuxRing *aux,
                              ProvRegistry *registry, const IrRuntimeRequest *request,
                              IrRuntimeReport *p) {
    if (!p)
        return false;
    *p = (IrRuntimeReport){
        .status = IR_REPLAY_CHECK_UNKNOWN,
        .capture_status = REPLAY_INPUT_INVALID_REQUEST,
        .build = {.status = IR_REPLAY_INVALID},
        .check = {.status = IR_REPLAY_CHECK_UNKNOWN, .candidate_status = IR_REPLAY_CHECK_UNKNOWN}};
    if (request)
        p->request = *request;
    if (!r || !request) {
        p->issues = IR_RUNTIME_BAD_REQUEST;
        p->status = IR_REPLAY_CHECK_ERROR;
        return false;
    }
    if (r->checks >= r->options.max_checks) {
        ++r->skipped_budget;
        p->issues = IR_RUNTIME_CHECK_BUDGET;
        return false;
    }
    ++r->checks;
    gint64 start = g_get_monotonic_time();
    ReplayInput *input = NULL;
    IrReplay *replay = NULL;
    if (!request->collector_serialized) {
        p->issues |= IR_RUNTIME_CONCURRENCY;
        goto done;
    }
    if (request->require_first_seq && !request->first_seq) {
        p->issues |= IR_RUNTIME_START_MISSING;
        goto done;
    }
    if (!trace || !aux || !request->trigger_seq || request->first_seq > request->trigger_seq ||
        (request->kind != IR_RUNTIME_PROBE && request->kind != IR_RUNTIME_CANDIDATE)) {
        p->issues |= IR_RUNTIME_BAD_REQUEST;
        p->status = IR_REPLAY_CHECK_ERROR;
        goto done;
    }
    uint64_t available = request->trigger_seq - 1;
    uint64_t wanted = request->first_seq ? request->trigger_seq - request->first_seq : available;
    p->selected_steps =
        wanted > r->options.window_steps ? r->options.window_steps : (uint32_t)wanted;
    p->first_seq = request->trigger_seq - p->selected_steps;
    if (wanted > p->selected_steps)
        p->issues |= IR_RUNTIME_WINDOW_CLIPPED;
    if (!p->selected_steps) {
        p->issues |= IR_RUNTIME_EMPTY_WINDOW;
        goto done;
    }
    uint64_t seq[IR_RUNTIME_MAX_WINDOW];
    for (uint32_t i = 0; i < p->selected_steps; ++i)
        seq[i] = p->first_seq + i;
    gint64 phase = g_get_monotonic_time();
    input = replay_input_capture(trace, aux, seq, p->selected_steps, request->trigger_seq,
                                 r->options.capture_bytes, &p->capture_status);
    p->capture_us = elapsed(phase);
    if (!input) {
        p->issues |= IR_RUNTIME_CAPTURE_FAILED;
        goto done;
    }
    ReplaySourceLimits source_limits = r->options.sources;
    size_t remaining = r->options.capture_bytes - replay_input_bytes(input);
    if (source_limits.bytes > remaining)
        source_limits.bytes = remaining;
    p->sources = replay_input_capture_sources(input, registry, &source_limits);
    p->capture_us = elapsed(phase);
    p->capture_bytes = replay_input_bytes(input);
    p->capture_issues = replay_input_issues(input);
    const InsnAux *first_aux = replay_input_aux(input, p->first_seq);
    if (first_aux) {
        memcpy(p->initial_gpr, first_aux->reg_vals, sizeof(p->initial_gpr));
        p->initial_gpr_mask = first_aux->reg_value_valid_mask;
        p->initial_eflags = first_aux->eflags_before;
        p->initial_eflags_valid = first_aux->eflags_valid;
    }
    const ReplayStep *trigger = replay_input_trigger(input);
    if (trigger->entry.vcpu_index != request->vcpu_index) {
        p->issues |= IR_RUNTIME_BAD_REQUEST;
        goto done;
    }
    IrReplayGprCandidate target = {.trigger_seq = request->trigger_seq,
                                   .gpr_index = (uint32_t)request->target_gpr,
                                   .expected_target = (uint32_t)request->candidate_address};
    bool candidate_ok = request->kind == IR_RUNTIME_CANDIDATE;
    if (candidate_ok && !target_supported(trigger, request->target_gpr)) {
        p->issues |= IR_RUNTIME_TARGET_UNSUPPORTED;
        candidate_ok = false;
    }
    if (request->kind == IR_RUNTIME_CANDIDATE &&
        (request->candidate_address > UINT32_MAX || !trigger->occurrence.execution_complete ||
         !trigger->occurrence.next_pc_valid ||
         trigger->occurrence.next_pc != request->candidate_address)) {
        p->issues |= IR_RUNTIME_TARGET_EVIDENCE;
        candidate_ok = false;
    }
    phase = g_get_monotonic_time();
    p->build_attempted = true;
    replay = ir_replay_x86_build(input, &r->options.replay, &p->build);
    p->build_us = elapsed(phase);
    if (p->build.stopped_seq) {
        const ReplayStep *stop = replay_input_find(input, p->build.stopped_seq);
        if (stop) {
            p->stopped = stop->entry;
            p->stopped_identity_valid = stop->descriptor_valid;
            if (stop->descriptor_valid)
                p->stopped_native_id = stop->descriptor.native_insn_id;
        }
    }
    if (!replay) {
        if (p->build.status == IR_REPLAY_INVALID || p->build.status == IR_REPLAY_OUT_OF_MEMORY)
            p->status = IR_REPLAY_CHECK_ERROR;
        goto done;
    }
    p->replay_bytes = ir_replay_allocated_bytes(replay);
    p->inputs = ir_replay_input_info(replay);
    p->inputs_available = ir_replay_inputs(replay) != NULL;
    IrModule *module = ir_replay_module(replay);
    p->ir_instructions = ir_module_inst_count(module);
    p->ir_values = ir_module_value_count(module);
    p->ir_blocks = ir_module_block_count(module);
    p->observations = ir_replay_observation_count(replay);
    if (!request->flag_observations_trusted) {
        p->issues |= IR_RUNTIME_FLAGS_UNVERIFIED;
        goto done;
    }
    replay_input_destroy(input);
    input = NULL;
    p->active_before_ssa = ir_module_active_inst_count(module);
    p->active_after_ssa = p->active_before_ssa;
    if (r->options.trace_ssa) {
        IrTraceSsaOptions options = ir_trace_ssa_default_options();
        options.limits = r->options.analysis;
        p->ssa_attempted = true;
        phase = g_get_monotonic_time();
        p->ssa = ir_trace_ssa(module, &options);
        p->ssa_us = elapsed(phase);
        p->active_after_ssa = ir_module_active_inst_count(module);
        if (p->ssa.analysis.status != IR_OK) {
            p->issues |= IR_RUNTIME_SSA_FAILED;
            if (p->ssa.analysis.status == IR_INVALID || p->ssa.analysis.status == IR_OUT_OF_MEMORY)
                p->status = IR_REPLAY_CHECK_ERROR;
            goto done;
        }
        p->replay_bytes = ir_replay_allocated_bytes(replay);
    }
    /* No collector object is accessed by the evaluator. */
    phase = g_get_monotonic_time();
    p->check_attempted = true;
    p->check =
        ir_replay_check_gpr_candidate(replay, &r->options.eval, candidate_ok ? &target : NULL);
    p->check_us = elapsed(phase);
    p->status = p->check.status;
    if (p->status == IR_REPLAY_CHECK_MATCH &&
        ((p->issues & (IR_RUNTIME_TARGET_UNSUPPORTED | IR_RUNTIME_TARGET_EVIDENCE)) ||
         (request->first_seq && (p->issues & IR_RUNTIME_WINDOW_CLIPPED))))
        p->status = IR_REPLAY_CHECK_UNKNOWN;
done:
    ir_replay_destroy(replay);
    replay_input_destroy(input);
    account(r, p, start);
    return true;
}

bool ir_runtime_check(IrRuntime *r, const TraceBuffer *trace, const DseAuxRing *aux,
                      const IrRuntimeRequest *request, IrRuntimeReport *p) {
    return ir_runtime_check_sources(r, trace, aux, NULL, request, p);
}

typedef struct {
    uint32_t bit;
    const char *name;
} IssueName;

static const IssueName runtime_names[] = {
    {IR_RUNTIME_WINDOW_CLIPPED, "window_clipped"},
    {IR_RUNTIME_CAPTURE_FAILED, "capture_failed"},
    {IR_RUNTIME_EMPTY_WINDOW, "empty_window"},
    {IR_RUNTIME_TARGET_UNSUPPORTED, "target_unsupported"},
    {IR_RUNTIME_TARGET_EVIDENCE, "target_evidence_missing"},
    {IR_RUNTIME_CONCURRENCY, "collector_not_serialized"},
    {IR_RUNTIME_CHECK_BUDGET, "check_budget"},
    {IR_RUNTIME_BAD_REQUEST, "bad_request"},
    {IR_RUNTIME_START_MISSING, "start_boundary_missing"},
    {IR_RUNTIME_FLAGS_UNVERIFIED, "flag_observations_unverified"},
    {IR_RUNTIME_SSA_FAILED, "trace_ssa_failed"}};
static const IssueName build_names[] = {{IR_REPLAY_IDENTITY, "identity"},
                                        {IR_REPLAY_MODE, "mode"},
                                        {IR_REPLAY_GAP, "gap"},
                                        {IR_REPLAY_UNSUPPORTED, "unsupported"},
                                        {IR_REPLAY_PENDING, "pending"},
                                        {IR_REPLAY_OBSERVATION_MISSING, "observation_missing"},
                                        {IR_REPLAY_OBSERVATION_SHAPE, "observation_shape"},
                                        {IR_REPLAY_CONTROL_MISMATCH, "control_mismatch"},
                                        {IR_REPLAY_MEMORY_MODEL, "memory_model"},
                                        {IR_REPLAY_BUDGET, "build_budget"},
                                        {IR_REPLAY_INPUT_BUDGET, "input_budget"}};

static void names_json(FILE *f, uint32_t bits, const IssueName *names, size_t n) {
    fputc('[', f);
    bool comma = false;
    for (size_t i = 0; i < n; ++i)
        if (bits & names[i].bit) {
            fprintf(f, "%s\"%s\"", comma ? "," : "", names[i].name);
            comma = true;
        }
    fputc(']', f);
}

static const char *build_name(IrReplayBuildStatus s) {
    switch (s) {
    case IR_REPLAY_READY:
        return "ready";
    case IR_REPLAY_UNKNOWN:
        return "unknown";
    case IR_REPLAY_RESOURCE_LIMIT:
        return "resource_limit";
    case IR_REPLAY_OUT_OF_MEMORY:
        return "out_of_memory";
    default:
        return "invalid";
    }
}

static const char *analysis_name(IrStatus status) {
    switch (status) {
    case IR_OK:
        return "ok";
    case IR_RESOURCE_LIMIT:
        return "resource_limit";
    case IR_OUT_OF_MEMORY:
        return "out_of_memory";
    default:
        return "invalid";
    }
}

static const char *eval_name(IrEvalStatus s) {
    switch (s) {
    case IR_EVAL_FRAGMENT_END:
        return "fragment_end";
    case IR_EVAL_PROGRAM_EXIT:
        return "program_exit";
    case IR_EVAL_UNKNOWN:
        return "unknown";
    case IR_EVAL_RESOURCE_LIMIT:
        return "resource_limit";
    case IR_EVAL_OUT_OF_MEMORY:
        return "out_of_memory";
    default:
        return "invalid";
    }
}

static const char *source_name(ReplaySourceStatus status) {
    switch (status) {
    case REPLAY_SOURCES_NOT_CAPTURED:
        return "not_captured";
    case REPLAY_SOURCES_READY:
        return "ready";
    case REPLAY_SOURCES_UNKNOWN:
        return "unknown";
    case REPLAY_SOURCES_RESOURCE_LIMIT:
        return "resource_limit";
    case REPLAY_SOURCES_OUT_OF_MEMORY:
        return "out_of_memory";
    default:
        return "invalid";
    }
}

bool ir_runtime_report_json(FILE *f, const IrRuntimeReport *p) {
    if (!f || !p)
        return false;
    fprintf(f,
            "{\"schema\":1,\"event\":\"check\",\"kind\":\"%s\",\"status\":\"%s\","
            "\"vcpu\":%u,\"trigger_seq\":%" PRIu64 ",\"first_seq\":%" PRIu64
            ",\"requested_first_seq\":%" PRIu64 ",\"candidate_address\":%" PRIu64 ","
            "\"selected_steps\":%u,\"lifted_steps\":%u,\"issues\":",
            p->request.kind == IR_RUNTIME_CANDIDATE ? "candidate" : "probe",
            ir_runtime_status_name(p->status), p->request.vcpu_index, p->request.trigger_seq,
            p->first_seq, p->request.first_seq, p->request.candidate_address, p->selected_steps,
            p->build.lifted_steps);
    names_json(f, p->issues, runtime_names, G_N_ELEMENTS(runtime_names));
    fprintf(
        f,
        ",\"capture_status\":%u,\"capture_issues\":%u,\"build_attempted\":%s,\"build_status\":%u,\"build_status_name\":\"%s\",\"build_issues\":",
        p->capture_status, p->capture_issues, p->build_attempted ? "true" : "false",
        p->build.status, p->build_attempted ? build_name(p->build.status) : "not_run");
    names_json(f, p->build.issues, build_names, G_N_ELEMENTS(build_names));
    fprintf(f, ",\"initial_state\":{\"gpr_mask\":%u,\"eflags_valid\":%s,\"eflags\":%u,\"gpr\":[",
            p->initial_gpr_mask, p->initial_eflags_valid ? "true" : "false", p->initial_eflags);
    for (unsigned i = 0; i < IR_X86_GPR_COUNT; ++i)
        fprintf(f, "%s%" PRIu64, i ? "," : "", p->initial_gpr[i]);
    fputs("]}", f);
    fprintf(f,
            ",\"stop\":{\"seq\":%" PRIu64 ",\"identity_valid\":%s,\"pc\":%" PRIu64
            ",\"generation\":%u,"
            "\"descriptor\":%" PRIu64 ",\"native_id\":%u,\"bytes\":\"",
            p->build.stopped_seq, p->stopped_identity_valid ? "true" : "false", p->stopped.pc,
            p->stopped.code_generation, p->stopped.insn_desc_id, p->stopped_native_id);
    for (uint32_t i = 0; i < p->stopped.size && i < MAX_INSN_BYTES; ++i)
        fprintf(f, "%02x", p->stopped.instr_bytes[i]);
    fprintf(
        f,
        "\"},\"check_attempted\":%s,\"checker_status\":\"%s\",\"checked\":%u,\"mismatches\":%u,"
        "\"unknown_observations\":%u,\"skipped_undefined\":%u,\"candidate_status\":\"%s\","
        "\"candidate_actual\":%" PRIu64 ",\"candidate_known_mask\":%" PRIu64 ","
        "\"eval_status\":%u,\"eval_status_name\":\"%s\",\"eval_reasons\":%u,\"eval_steps\":%" PRIu64
        ",\"memory_queries\":%" PRIu64 ","
        "\"ir_instructions\":%u,\"ir_values\":%u,\"ir_blocks\":%u,\"observations\":%u,"
        "\"capture_bytes\":%zu,\"replay_allocated_bytes\":%zu,\"evaluator_allocated_bytes\":%zu,"
        "\"capture_us\":%" PRIu64 ",\"build_us\":%" PRIu64 ",\"check_us\":%" PRIu64
        ",\"total_us\":%" PRIu64,
        p->check_attempted ? "true" : "false", ir_runtime_status_name(p->check.status),
        p->check.checked, p->check.mismatches, p->check.unknown, p->check.skipped_undefined,
        ir_runtime_status_name(p->check.candidate_status), p->check.candidate_actual.value,
        p->check.candidate_actual.known_mask, p->check.execution.status,
        p->check_attempted ? eval_name(p->check.execution.status) : "not_run",
        p->check.execution.reasons, p->check.execution.steps, p->check.execution.memory_queries,
        p->ir_instructions, p->ir_values, p->ir_blocks, p->observations, p->capture_bytes,
        p->replay_bytes, p->check.evaluator_bytes, p->capture_us, p->build_us, p->check_us,
        p->total_us);
    fprintf(f,
            ",\"ssa\":{\"attempted\":%s,\"status\":%u,\"status_name\":\"%s\",\"work\":%" PRIu64
            ",\"peak_pass_bytes\":%zu,\"renamed_reads\":%u,\"removed\":%u,\"removed_writes\":%u,"
            "\"active_before\":%u,\"active_after\":%u,\"us\":%" PRIu64 "}",
            p->ssa_attempted ? "true" : "false", p->ssa.analysis.status,
            p->ssa_attempted ? analysis_name(p->ssa.analysis.status) : "not_run",
            p->ssa.analysis.work, p->ssa.analysis.bytes, p->ssa.renamed_reads, p->ssa.removed,
            p->ssa.removed_writes, p->active_before_ssa, p->active_after_ssa, p->ssa_us);
    fprintf(f,
            ",\"inputs\":{\"available\":%s,\"scope\":\"boundary_snapshot\","
            "\"source_relation\":\"dependency_only\",\"count\":%u,\"missing_observations\":%u,"
            "\"missing_provenance\":%u,\"incomplete_provenance\":%u,\"unresolved_sources\":%u,"
            "\"dependent_inputs\":%u,\"bytes\":%zu,\"work\":%" PRIu64 ",\"source_status\":\"%s\","
            "\"source_issues\":%u,\"labels\":%u,\"roots\":%u,\"resources\":%u,"
            "\"source_capture_peak_bytes\":%zu,\"source_capture_work\":%" PRIu64 "}",
            p->inputs_available ? "true" : "false", p->inputs.count, p->inputs.missing_observations,
            p->inputs.missing_provenance, p->inputs.incomplete_provenance,
            p->inputs.unresolved_sources, p->inputs.dependent_inputs, p->inputs.bytes,
            p->inputs.work, source_name(p->sources.status), p->sources.issues, p->sources.labels,
            p->sources.roots, p->sources.resources, p->sources.bytes, p->sources.work);
    if (p->check.has_first_mismatch) {
        const IrReplayObservation *o = &p->check.first_mismatch;
        fprintf(f,
                ",\"first_mismatch\":{\"seq\":%" PRIu64 ",\"pc\":%" PRIu64 ",\"kind\":%u,"
                "\"index\":%u,\"width\":%u,\"expected\":%" PRIu64 ",\"actual\":%" PRIu64
                ",\"known_mask\":%" PRIu64 "}",
                o->origin.seq_id, o->origin.pc, o->kind, o->index, o->width, o->expected,
                p->check.actual.value, p->check.actual.known_mask);
    }
    fputs("}\n", f);
    return !ferror(f);
}

bool ir_runtime_summary_json(FILE *f, const IrRuntime *r) {
    if (!f || !r)
        return false;
    fprintf(
        f,
        "{\"schema\":1,\"event\":\"summary\",\"checks\":%u,\"matches\":%u,\"mismatches\":%u,"
        "\"unknown\":%u,\"errors\":%u,\"skipped_budget\":%" PRIu64 ",\"selected_steps\":%" PRIu64
        ","
        "\"lifted_steps\":%" PRIu64 ",\"total_us\":%" PRIu64 ",\"peak_capture_bytes\":%zu,"
        "\"peak_replay_allocated_bytes\":%zu,\"peak_evaluator_allocated_bytes\":%zu,"
        "\"window_limit\":%u,\"check_limit\":%u,\"capture_limit_bytes\":%zu,\"flat32_ram\":%s}\n",
        r->checks, r->matches, r->mismatches, r->unknown, r->errors, r->skipped_budget,
        r->selected_steps, r->lifted_steps, r->total_us, r->peak_capture_bytes,
        r->peak_replay_bytes, r->peak_evaluator_bytes, r->options.window_steps,
        r->options.max_checks, r->options.capture_bytes,
        r->options.replay.x86.flat32_ram ? "true" : "false");
    return !ferror(f);
}
