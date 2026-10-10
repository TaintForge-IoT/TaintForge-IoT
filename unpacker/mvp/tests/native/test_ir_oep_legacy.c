#include "ir_oep_test_helpers.h"
#include "dse.h"

/* Import exactly the request's boundary domain into the old expression
 * engine. No backward slicing or automatic taint-to-input policy is involved
 * in this comparison. Both engines consume the same owned ReplayInput. */
static bool selected(const OepFixture *f, IrInputKind kind, uint64_t key,
                     unsigned offset, uint64_t address) {
    for (uint32_t i = 0; i < f->variable_count; ++i) {
        const IrOepInput *v = &f->variables[i];
        if (v->kind == kind && v->state_key == key && v->bit_offset == offset &&
            v->address == address) return true;
    }
    return false;
}

static SymExpr *initial_byte(DSECtx *ctx, uint64_t binding, uint8_t value, bool variable) {
    SymExpr *e = NULL;
    if (variable) CHECK(dse_load_tracked_byte_at(ctx, binding, 1, value, true, &e));
    else e = sym_expr_const(value, 8);
    CHECK(e);
    return e;
}

static void initial_state(DSECtx *ctx, const OepFixture *f) {
    const ReplayStep *first = replay_input_step(f->input, 0);
    const InsnAux *a = replay_input_aux(f->input, first->entry.seq_id); CHECK(a);
    for (unsigned reg = 0; reg < IR_X86_GPR_COUNT; ++reg) {
        SymExpr *word = NULL;
        for (unsigned byte = 0; byte < 4; ++byte) {
            bool variable = selected(f, IR_INPUT_STATE_SLICE,
                                     IR_X86_GPR_KEY_BASE + reg, byte * 8, 0);
            SymExpr *part = initial_byte(ctx, UINT64_C(0x90000000) + reg * 4 + byte,
                                        (uint8_t)(a->reg_vals[reg] >> (byte * 8)), variable);
            word = byte ? sym_expr_concat(part, word) : part;
            CHECK(word);
        }
        dse_set_reg(ctx, (int)reg, word, 32);
    }
    for (unsigned flag = 0; flag < DSE_FLAG_SLOT_COUNT; ++flag) {
        ctx->state.x86_flags[flag] = sym_expr_const((a->eflags_before >> alu_flag_bits[flag]) & 1, 1);
        CHECK(ctx->state.x86_flags[flag]);
    }
    if (f->variables[0].kind == IR_INPUT_MEMORY_BYTE) {
        const InsnAux *t = replay_input_aux(f->input, replay_input_trigger(f->input)->entry.seq_id);
        CHECK(t && t->has_mem_read);
        for (unsigned byte = 0; byte < 4; ++byte) {
            uint32_t address = f->target_memory + byte;
            uint8_t value = (uint8_t)(t->mem_read_val >> (byte * 8));
            bool variable = selected(f, IR_INPUT_MEMORY_BYTE, IR_X86_MEMORY_KEY, 0, address);
            SymExpr *part = initial_byte(ctx, address, value, variable);
            CHECK(dse_store_tracked_byte_at(ctx, address, part, NULL, value));
        }
    }
}

static const char *solver_name(DseSolverStatus s) {
    return s == DSE_SOLVER_SAT ? "SAT" : s == DSE_SOLVER_UNSAT ? "UNSAT"
         : s == DSE_SOLVER_NOT_RUN ? "NOT_RUN" : "UNKNOWN";
}

static void comparison(unsigned kind, bool wrong, FILE *report) {
    OepFixture f = of_fixture(kind);
    IrOepRequest q = of_request(&f); IrOepOptions o = of_options();
    if (wrong) q.candidate_address++;
    IrOepResult r = ir_oep_verify(f.input, &q, &o);
    bool unique = kind == OF_EQUAL || kind == OF_SAME_SUCCESSOR || kind == OF_LATE_GUARD;
    of_status(&r, wrong ? IR_OEP_REFUTED : unique ? IR_OEP_UNIQUE : IR_OEP_NONUNIQUE);

    DSECtx ctx; csh decoder = 0;
    CHECK(cs_open(CS_ARCH_X86, CS_MODE_32, &decoder) == CS_ERR_OK);
    CHECK(cs_option(decoder, CS_OPT_DETAIL, CS_OPT_ON) == CS_ERR_OK);
    dse_lift_attach(NULL, NULL, &dse_arch_x86);
    CHECK(dse_ctx_init(&ctx)); dse_lift_begin(&ctx); initial_state(&ctx, &f);
    for (uint32_t i = 0; i < replay_input_count(f.input); ++i)
        CHECK(dse_lift_replay_step(&ctx, f.input, i, decoder));
    const InsnAux *trigger = replay_input_aux(f.input, q.trigger_seq); CHECK(trigger);
    SymExpr *target = f.target_register >= 0
        ? dse_read_rid_fit(&ctx, trigger, f.target_register, 32, 32)
        : dse_load_mem(&ctx, trigger, 32, false);
    uint64_t observed = 0;
    CHECK(target && dse_eval_expr_observed(&ctx, target, &observed) == DSE_REPLAY_EVAL_OK);
    CHECK(observed == f.target_address && ctx.replay_model_complete && !ctx.replay_failures);
    CHECK(ctx.register_model_complete && ctx.memory_model_complete);
    CHECK(ctx.path_model_complete == (kind != OF_SAME_SUCCESSOR));
    DseSolverStatus candidate = ctx.path_model_complete
        ? dse_check_target_relation(&ctx, target, q.candidate_address, true) : DSE_SOLVER_NOT_RUN;
    DseSolverStatus alternative = ctx.path_model_complete
        ? dse_check_target_relation(&ctx, target, q.candidate_address, false) : DSE_SOLVER_NOT_RUN;
    /* lift_jmp in the legacy lifter accepts a register transfer without
     * constraining its destination. The IR trace builder does preserve that
     * guard. Record this known contract difference; do not force false parity. */
    const char *difference = "null";
    if (kind == OF_SAME_SUCCESSOR) {
        /* The archived explicit outcome is sufficient for IR, but legacy
         * lift_conditional_branch deliberately rejects ambiguous next_pc. */
        difference = "\"legacy_same_successor_path_incomplete\"";
        CHECK(candidate == DSE_SOLVER_NOT_RUN && alternative == DSE_SOLVER_NOT_RUN);
    } else if (kind == OF_LATE_GUARD) {
        difference = "\"legacy_jmp_target_not_constrained\"";
        CHECK(candidate == DSE_SOLVER_SAT && alternative == DSE_SOLVER_SAT);
        CHECK(wrong ? r.candidate.status == IR_SMT_UNSAT : r.alternative.status == IR_SMT_UNSAT);
    } else {
        CHECK(candidate == (r.candidate.status == IR_SMT_SAT ? DSE_SOLVER_SAT : DSE_SOLVER_UNSAT));
        if (!wrong)
            CHECK(alternative == (r.alternative.status == IR_SMT_SAT ? DSE_SOLVER_SAT : DSE_SOLVER_UNSAT));
    }
    CHECK(fprintf(report, "{\"fixture\":%u,\"wrong_candidate\":%s,"
        "\"same_snapshot\":true,\"same_boundary_inputs\":true,\"scope\":\"boundary_fragment\","
        "\"ir\":\"%s\",\"legacy_candidate\":\"%s\",\"legacy_alternative\":\"%s\","
        "\"legacy_replay_failures\":%u,\"legacy_path_complete\":%s,\"expected_difference\":%s}\n",
        kind, wrong ? "true" : "false", ir_oep_status_name(r.status),
        solver_name(candidate), solver_name(alternative), ctx.replay_failures,
        ctx.path_model_complete ? "true" : "false", difference) > 0);
    sym_expr_free(target); dse_ctx_free(&ctx); dse_lift_attach(NULL, NULL, NULL);
    cs_close(&decoder); ir_oep_result_destroy(&r); replay_input_destroy(f.input);
}

int main(int argc, char **argv) {
    CHECK(argc == 2);
    FILE *report = fopen(argv[1], "w"); CHECK(report);
    for (unsigned kind = OF_EQUAL; kind <= OF_LATE_GUARD; ++kind) comparison(kind, false, report);
    comparison(OF_EQUAL, true, report);
    comparison(OF_SAME_SUCCESSOR, true, report);
    comparison(OF_LATE_GUARD, true, report);
    CHECK(!fclose(report));
    puts("PASS: 8 matched IR/legacy cases; 4 documented same-successor/indirect-guard differences; identical owned traces and explicit byte inputs");
    return 0;
}
