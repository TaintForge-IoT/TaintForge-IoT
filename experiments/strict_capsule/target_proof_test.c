#include "ir_frontend_test_helpers.h"
#include "dse.h"

static void check_target(bool guarded) {
    const uint32_t target = 0x804b000;
    FrontFixture f = ff_new(16);
    ProvRegistry *registry = prov_registry_create(NULL);
    CHECK(registry);
    DcfgGraph *graph = dcfg_graph_create(registry);
    BranchEventBuffer *events = branch_event_buffer_create(16);
    CHECK(graph && events);
    ProvResourceKey key = {.kind = PROV_RESOURCE_FILE, .object_id = 1};
    ProvResourceId resource = prov_resource_intern(registry, &key, "guest-i386",
                                                  PROV_RESOURCE_ROLE_MAIN_IMAGE);
    ProvRootKey root = {.kind = PROV_ROOT_RESOURCE_BYTE, .source_id = resource, .offset = 0};
    ProvLabelId label = prov_label_from_root(registry, prov_root_intern(registry, &root),
                                            PROV_CHANNEL_DATA);
    CHECK(label != PROV_LABEL_ID_INVALID);
    dse_lift_attach(f.trace, f.aux, &dse_arch_x86);
    InsnAux a = {.reg_value_valid_mask = 0xff};
    dse_aux_set_eflags(&a, 0x202, true, true);
    ff_read(&a, 0x3000, target, 4, true);
    a.mem_read_taint = a.mem_read_effective_taint = 15;
    a.mem_reads[0].taint = a.mem_reads[0].effective_taint = 15;
    const uint8_t load[] = {0xa1, 0, 0x30, 0, 0};
    uint64_t seq = ff_emit(&f, 0x1000, load, sizeof(load), 1, 0, &a);
    ff_finish(&f, seq, 0x1005);
    a = (InsnAux){.reg_value_valid_mask = 0xff};
    a.reg_vals[DTA_REG_RAX] = target;
    a.reg_taint[DTA_REG_RAX] = 15;
    dse_aux_set_eflags(&a, 0x202, true, true);
    uint32_t pc = 0x1005;
    if (guarded) {
        const uint8_t cmp[] = {0x3d, 0, 0xb0, 4, 8};
        seq = ff_emit(&f, pc, cmp, sizeof(cmp), 1, 0, &a);
        pc += sizeof(cmp);
        ff_finish(&f, seq, pc);
        dse_aux_set_eflags(&a, 0x246, true, true);
        const uint8_t branch[] = {0x75, 4};
        seq = ff_emit(&f, pc, branch, sizeof(branch), 1, 0, &a);
        const TraceEntry *entry = trace_find_seq(f.trace, seq, NULL);
        CHECK(entry);
        InsnAux *stored = (InsnAux *)dse_aux_for(f.aux, f.trace, entry);
        dse_aux_finalize(stored, pc+2, NULL, 0);
        DcfgBranchObservation observation = {.source = {.start_pc = pc, .code_generation = 1},
            .target = {.start_pc = pc+2, .code_generation = 1}, .kind = DCFG_EDGE_JCC_FALLTHROUGH,
            .branch_seq_id = seq, .condition_label = label, .target_label = PROV_LABEL_CLEAN};
        DcfgEdgeId edge;
        CHECK(dcfg_record_branch(graph, &observation, &edge));
        BranchEvent event = {.branch_seq_id = seq, .pc = pc, .meta_id = entry->meta_id,
            .fallthrough = pc+2, .direct_target_valid = true, .direct_target = pc+6,
            .observed_next_pc = pc+2, .condition_code = X86_CC_NE,
            .outcome = BRANCH_OUTCOME_NOT_TAKEN, .condition_label = label, .dcfg_edge_id = edge};
        CHECK(branch_event_append(events, &event));
        CHECK(dse_aux_archive_occurrence(f.aux, f.trace, events, seq));
        pc += 2;
    }
    const uint8_t jump[] = {0xff, 0xe0};
    seq = ff_emit(&f, pc, jump, sizeof(jump), 1, 0, &a);
    ff_finish(&f, seq, target);
    CHECK(trace_record_control_transfer(f.trace, seq, 0, label));
    DseRelevanceContext relevance = {registry, graph, events};
    DseVerifyResult result = dse_verify_oep_candidate_with_relevance(
        f.trace, f.aux, seq, DTA_REG_RAX, target, NULL, f.decoder, &relevance);
    printf("{\"guarded\":%s,\"verdict\":\"%s\",\"reason\":\"%s\","
           "\"target_symbolic\":%s,\"replay_valid\":%s,\"proof_eligible\":%s}\n",
           guarded ? "true" : "false", dse_verdict_name(result.verdict),
           dse_verify_reason_name(result.reason), result.target_symbolic ? "true" : "false",
           result.replay_valid ? "true" : "false", result.proof_eligible ? "true" : "false");
    CHECK(result.target_symbolic && result.replay_valid && result.proof_eligible);
    CHECK(result.verdict == (guarded ? DSE_VERDICT_CONFIRMED : DSE_VERDICT_UNKNOWN));
    CHECK(result.reason == (guarded ? DSE_REASON_NONE : DSE_REASON_NONUNIQUE_TARGET));
    dse_lift_attach(NULL, NULL, NULL);
    ff_free(&f);
    branch_event_buffer_destroy(events);
    dcfg_graph_destroy(graph);
    prov_registry_destroy(registry);
}

int main(void) {
    dse_set_verbose_diagnostics(false);
    check_target(true);
    check_target(false);
    return 0;
}
