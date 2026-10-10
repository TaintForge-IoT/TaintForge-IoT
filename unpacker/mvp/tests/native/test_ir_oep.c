#include "ir_oep_test_helpers.h"

static void relations(FILE *report) {
    const unsigned kinds[] = {OF_EQUAL, OF_NOT_EQUAL, OF_SAME_SUCCESSOR, OF_LINEAR,
                              OF_MEMORY, OF_RET, OF_CALL, OF_STORE, OF_LATE_GUARD};
    for (unsigned i = 0; i < sizeof(kinds) / sizeof(*kinds); ++i) {
        OepFixture f = of_fixture(kinds[i]);
        IrOepRequest q = of_request(&f);
        IrOepOptions o = of_options();
        bool unique = kinds[i] == OF_EQUAL || kinds[i] == OF_SAME_SUCCESSOR ||
                      kinds[i] == OF_LATE_GUARD;
        IrOepResult r = ir_oep_verify(f.input, &q, &o);
        of_status(&r, unique ? IR_OEP_UNIQUE : IR_OEP_NONUNIQUE);
        CHECK(r.baseline_verified && r.candidate_verified && r.candidate.status == IR_SMT_SAT);
        CHECK(r.alternative_attempted && r.symbolic_count == 1);
        CHECK(r.candidate_target.value == f.target_address);
        if (!unique) {
            CHECK(r.alternative.status == IR_SMT_SAT && r.alternative_verified);
            CHECK(r.alternative_target.value != f.target_address);
        } else CHECK(r.alternative.status == IR_SMT_UNSAT && !r.alternative_verified);
        CHECK(ir_oep_report_json(report, &r));
        if (unique) {
            q.candidate_address++;
            IrOepResult wrong = ir_oep_verify(f.input, &q, &o);
            of_status(&wrong, IR_OEP_REFUTED);
            CHECK(wrong.baseline_verified && wrong.candidate.status == IR_SMT_UNSAT);
            CHECK(!wrong.alternative_attempted && !wrong.candidate_verified);
            CHECK(!wrong.candidate.inputs && !wrong.candidate.catalogue);
            CHECK(ir_oep_report_json(report, &wrong));
            ir_oep_result_destroy(&wrong);
        }
        replay_input_destroy(f.input);
        CHECK(r.candidate.catalogue && r.candidate.input_count == 1);
        CHECK(ir_inputs_cell(r.candidate.catalogue, r.candidate.inputs[0].input));
        ir_oep_result_destroy(&r);
        ir_oep_result_destroy(&r);
    }
    puts("PASS: unique/nonunique/refuted targets; JMP reg/mem, RET/CALL projection, symbolic STORE, zero-displacement Jcc and late indirect guard; owned witnesses");
}

static void rejected_evidence(FILE *report) {
    const unsigned cases[] = {OF_GAP, OF_UNSUPPORTED, OF_SYSCALL, OF_BAD_BASELINE, OF_BAD_BRANCH};
    for (unsigned i = 0; i < sizeof(cases) / sizeof(*cases); ++i) {
        OepFixture f = of_fixture(cases[i]);
        IrOepRequest q = of_request(&f); IrOepOptions o = of_options();
        IrOepResult r = ir_oep_verify(f.input, &q, &o);
        of_status(&r, cases[i] == OF_BAD_BASELINE ? IR_OEP_MISMATCH : IR_OEP_UNKNOWN);
        CHECK(!r.candidate_attempted && !r.alternative_attempted);
        CHECK(!r.candidate.inputs && !r.alternative.inputs);
        if (cases[i] == OF_GAP) CHECK(r.replay_build.issues & IR_REPLAY_GAP);
        if (cases[i] == OF_UNSUPPORTED) CHECK(r.replay_build.issues & IR_REPLAY_UNSUPPORTED);
        if (cases[i] == OF_SYSCALL) CHECK(r.replay_build.issues & IR_REPLAY_SYSCALL_MODEL);
        CHECK(ir_oep_report_json(report, &r));
        ir_oep_result_destroy(&r); replay_input_destroy(f.input);
    }
    OepFixture f = of_fixture(OF_LINEAR);
    IrOepOptions o = of_options();
    for (unsigned fault = 0; fault < 8; ++fault) {
        IrOepRequest q = of_request(&f);
        IrOepInput duplicate[2] = {f.variables[0], f.variables[0]};
        if (fault == 0) q.flags_verified = false;
        if (fault == 1) q.symbolic_count = 0;
        if (fault == 2) q.first_seq++;
        if (fault == 3) q.trigger_seq++;
        if (fault == 4) q.vcpu++;
        if (fault == 5) q.candidate_address = UINT64_C(1) << 32;
        if (fault == 6) { q.symbolic_inputs = duplicate; q.symbolic_count = 2; }
        if (fault == 7) { duplicate[0].state_key = UINT64_MAX; q.symbolic_inputs = duplicate; }
        IrOepResult r = ir_oep_verify(f.input, &q, &o);
        of_status(&r, fault <= 1 ? IR_OEP_UNKNOWN : IR_OEP_INVALID);
        CHECK(!r.candidate_attempted && !r.alternative_attempted);
        CHECK(ir_oep_report_json(report, &r));
        ir_oep_result_destroy(&r);
    }
    replay_input_destroy(f.input);
    puts("PASS: gaps, unsupported DIV/open, bad baseline/branch evidence, flag trust, explicit input policy, request identity and input-domain rejection");
}

static void budgets(FILE *report) {
    OepFixture f = of_fixture(OF_EQUAL);
    IrOepRequest q = of_request(&f);
    for (unsigned limit = 0; limit < 12; ++limit) {
        IrOepOptions o = of_options();
        if (limit == 0) o.work = 0;
        if (limit == 1) o.bytes = 0;
        if (limit == 2) o.symbolic_inputs = 0;
        if (limit == 3) o.replay.max_steps = 1;
        if (limit == 4) o.evaluation.steps = 0;
        if (limit == 5) o.ssa.work = 0;
        if (limit == 6) o.prefix_branches = 0;
        if (limit == 7) o.smt.work = 0;
        if (limit == 8) o.query.timeout_ms = 0;
        if (limit == 9) o.query.constraints = 0;
        if (limit == 10) o.bindings.inputs = 0;
        if (limit == 11) o.branches.branches = 0;
        IrOepResult r = ir_oep_verify(f.input, &q, &o);
        if (r.status != IR_OEP_RESOURCE_LIMIT) fprintf(stderr, "limit=%u\n", limit);
        of_status(&r, IR_OEP_RESOURCE_LIMIT);
        CHECK(!r.candidate_verified && !r.alternative_verified);
        CHECK(!r.candidate.inputs && !r.alternative.inputs);
        CHECK(ir_oep_report_json(report, &r));
        ir_oep_result_destroy(&r);
    }
    replay_input_destroy(f.input);
    puts("PASS: wrapper, replay, SSA, prefix, solver and witness budgets preserve non-proof results and hide unchecked models");
}

int main(int argc, char **argv) {
    CHECK(argc == 2);
    FILE *report = fopen(argv[1], "w"); CHECK(report);
    relations(report); rejected_evidence(report); budgets(report);
    CHECK(!fclose(report));
    puts("IR OEP service: PASS");
    return 0;
}
