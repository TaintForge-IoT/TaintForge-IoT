#include "ir_frontend_test_helpers.h"
#include "ir_branches.h"
#include "dse.h"

typedef struct {
    FrontFixture f;
    ProvRegistry *registry;
    DcfgGraph *graph;
    BranchEventBuffer *events;
    ProvLabelId condition;
    bool page_snapshot;
} Fixture;

static Fixture fixture(uint32_t capacity) {
    Fixture t = {.f = ff_new(capacity)};
    t.registry = prov_registry_create(NULL);
    CHECK(t.registry);
    t.graph = dcfg_graph_create(t.registry);
    t.events = branch_event_buffer_create(capacity);
    CHECK(t.graph && t.events);
    ProvResourceKey key = {.kind = PROV_RESOURCE_FILE, .object_id = 1};
    ProvResourceId resource =
        prov_resource_intern(t.registry, &key, "input.bin", PROV_RESOURCE_ROLE_FUZZ_INPUT);
    ProvRootKey root = {.kind = PROV_ROOT_RESOURCE_BYTE, .source_id = resource, .offset = 2};
    t.condition =
        prov_label_from_root(t.registry, prov_root_intern(t.registry, &root), PROV_CHANNEL_DATA);
    CHECK(t.condition != PROV_LABEL_ID_INVALID);
    dse_lift_attach(t.f.trace, t.f.aux, &dse_arch_x86);
    return t;
}

static void destroy(Fixture *t) {
    dse_lift_attach(NULL, NULL, NULL);
    ff_free(&t->f);
    branch_event_buffer_destroy(t->events);
    dcfg_graph_destroy(t->graph);
    prov_registry_destroy(t->registry);
}

static InsnAux registers(void) {
    InsnAux a = {0};
    a.reg_value_valid_mask = 0xff;
    dse_aux_set_eflags(&a, 0x202, true, true);
    return a;
}

static void snapshot(Fixture *t, uint64_t seq) {
    if (t->page_snapshot) {
        TraceEntry *entry = (TraceEntry *)trace_find_seq(t->f.trace, seq, NULL);
        CHECK(entry);
        entry->code_page_size = 4096;
        entry->code_page_generation = entry->code_generation;
        entry->code_history_start = 1;
    }
}

static uint64_t emit(Fixture *t, uint32_t pc, const uint8_t *code, uint8_t n, InsnAux a,
                     uint32_t next, uint32_t generation, uint32_t vcpu) {
    uint64_t seq = ff_emit(&t->f, pc, code, n, generation, vcpu, &a);
    snapshot(t, seq);
    ff_finish(&t->f, seq, next);
    return seq;
}

static uint64_t branch_to(Fixture *t, uint32_t pc, InsnAux a, uint32_t next, uint32_t generation,
                          uint32_t vcpu, unsigned fault, uint32_t target) {
    const uint8_t code[] = {0x75, (uint8_t)(target - (pc + 2))};
    uint64_t seq = ff_emit(&t->f, pc, code, sizeof(code), generation, vcpu, &a);
    snapshot(t, seq);
    const TraceEntry *entry = trace_find_seq(t->f.trace, seq, NULL);
    CHECK(entry);
    InsnAux *stored = (InsnAux *)dse_aux_for(t->f.aux, t->f.trace, entry);
    dse_aux_finalize(stored, next, NULL, 0);
    bool taken = next != pc + 2;
    DcfgBranchObservation obs = {.source = {.start_pc = pc, .code_generation = generation},
                                 .target = {.start_pc = next, .code_generation = generation},
                                 .kind = taken ? DCFG_EDGE_JCC_TAKEN : DCFG_EDGE_JCC_FALLTHROUGH,
                                 .branch_seq_id = seq,
                                 .vcpu_index = vcpu,
                                 .condition_label = t->condition,
                                 .target_label = PROV_LABEL_CLEAN};
    DcfgEdgeId edge;
    CHECK(dcfg_record_branch(t->graph, &obs, &edge));
    BranchEvent event = {.branch_seq_id = seq,
                         .vcpu_index = vcpu,
                         .pc = pc,
                         .meta_id = entry->meta_id,
                         .fallthrough = pc + 2,
                         .direct_target_valid = true,
                         .direct_target = target,
                         .observed_next_pc = next,
                         .condition_code = X86_CC_NE,
                         .outcome = taken ? BRANCH_OUTCOME_TAKEN : BRANCH_OUTCOME_NOT_TAKEN,
                         .condition_label = t->condition,
                         .dcfg_edge_id = edge};
    if (fault == 2)
        event.pc++;
    if (fault == 3)
        event.outcome = taken ? BRANCH_OUTCOME_NOT_TAKEN : BRANCH_OUTCOME_TAKEN;
    if (fault == 4)
        event.observed_next_pc++;
    if (fault != 1)
        CHECK(branch_event_append(t->events, &event));
    CHECK(dse_aux_archive_occurrence(t->f.aux, t->f.trace, t->events, seq));
    return seq;
}

static uint64_t branch(Fixture *t, uint32_t pc, InsnAux a, uint32_t next, uint32_t generation,
                       uint32_t vcpu, unsigned fault) {
    return branch_to(t, pc, a, next, generation, vcpu, fault, pc + 9);
}

static DseRelevanceContext context(Fixture *t) {
    return (DseRelevanceContext){t->registry, t->graph, t->events};
}

static void diagnostic_counts(const DseControlStats *s) {
    unsigned stops = 0, failures = 0, examples = s->cfg_examples_omitted;
    for (unsigned i = 1; i < DSE_CFG_STOP_COUNT; ++i)
        stops += s->cfg_stops[i];
    for (unsigned i = 1; i < DSE_CFG_FAILURE_COUNT; ++i)
        failures += s->cfg_failures[i];
    CHECK(s->cfg_example_count <= DSE_CFG_MAX_EXAMPLES);
    for (unsigned i = 0; i < s->cfg_example_count; ++i)
        examples += s->cfg_examples[i].count;
    CHECK(stops == s->cfg_regions && failures == s->cfg_unknown && examples == failures);
    unsigned unresolved = 0;
    for (unsigned i = 1; i < DSE_CFG_RESOLVE_COUNT; ++i)
        unresolved += s->cfg_resolve_failures[i];
    CHECK(s->cfg_resolve_added + unresolved == s->cfg_resolve_attempts);
    CHECK(s->cfg_resolve_lookups <= DSE_MAX_CONTROL_SCAN);
}

static DseSliceResult slice(Fixture *t, uint64_t trigger, const TraceEntry **out,
                            uint32_t capacity) {
    DseRelevanceContext c = context(t);
    CHECK(trace_record_control_transfer(t->f.trace, trigger, 0, PROV_LABEL_CLEAN));
    DseSliceResult r = dse_build_reg_slice_with_relevance(t->f.trace, t->f.aux, trigger, DTA_REG_RAX,
                                                          out, capacity, &c);
    diagnostic_counts(&r.control);
    return r;
}

static void exact(const DseSliceResult *r, const TraceEntry **out, const uint64_t *seqs,
                  uint32_t count) {
    if (r->status != DSE_SLICE_OK || r->len != count) {
        fprintf(stderr, "status=%u len=%u expected=%u control=%x deps=%x\n", r->status, r->len,
                count, r->control.issues, r->dependency_unknown_reasons);
        for (uint32_t i = 0; i < r->len; ++i)
            fprintf(stderr, "seq=%llu pc=%llx\n", (unsigned long long)out[i]->seq_id,
                    (unsigned long long)out[i]->pc);
    }
    CHECK(r->status == DSE_SLICE_OK && r->data_complete && r->len == count);
    for (uint32_t i = 0; i < count; ++i)
        CHECK(out[i]->seq_id == seqs[i]);
}

typedef struct {
    IrBindings observed;
} Changed;

static IrBits unchanged_bv(void *user, IrBindingKind kind, uint64_t key, uint8_t width) {
    Changed *c = user;
    return c->observed.read_bv(c->observed.user, kind, key, width);
}

static IrBits changed_byte(void *user, IrBindingKind kind, uint64_t key, uint64_t address) {
    Changed *c = user;
    return address == 0x3000 ? ir_bits_known(0, 8)
                             : c->observed.read_byte(c->observed.user, kind, key, address);
}

static void changed_selector(IrReplay *replay, uint64_t seq) {
    Changed c = {.observed = ir_replay_observed_bindings(replay)};
    IrBindings bindings = {.user = &c, .read_bv = unchanged_bv, .read_byte = changed_byte};
    IrEval *eval = ir_eval_create(ir_replay_module(replay), &bindings, NULL);
    CHECK(eval);
    IrEvalResult r = ir_eval_run(eval);
    CHECK(r.status == IR_EVAL_UNKNOWN && r.target_known && r.target_address == 0x100b);
    CHECK(r.origin.seq_id == seq && (r.reasons & IR_REASON_TARGET));
    ir_eval_destroy(eval);
}

static void constant_choice(bool taken, unsigned fault, bool memory, FILE *json) {
    Fixture t = fixture(32);
    InsnAux a = registers();
    uint64_t seqs[6];
    const uint8_t load[] = {0x8b, 0x1d, 0, 0x30, 0, 0};
    const uint8_t cmp[] = {0x83, 0xfb, 0}, jump[] = {0xff, 0xe0};
    ff_read(&a, 0x3000, taken ? 1 : 0, 4, true);
    a.mem_reads[0].taint = 15;
    seqs[0] = emit(&t, 0x1000, load, sizeof(load), a, 0x1006, 7, 0);
    a = registers();
    a.reg_vals[DTA_REG_RBX] = taken ? 1 : 0;
    a.reg_taint[DTA_REG_RBX] = 15;
    seqs[1] = emit(&t, 0x1006, cmp, sizeof(cmp), a, 0x1009, 7, 0);
    a.eflags_before = taken ? 0x202 : 0x246;
    uint32_t dest = taken ? 0x1012 : 0x100b;
    seqs[2] = branch(&t, 0x1009, a, dest, 7, 0, fault);
    uint32_t value = taken ? 0x2000 : 0x3000;
    uint8_t mov[] = {0xb8, 0, (uint8_t)(value >> 8), 0, 0};
    uint8_t store[] = {0xc7, 5, 0, 0x40, 0, 0, 0, (uint8_t)(value >> 8), 0, 0};
    const uint8_t memjump[] = {0xff, 0x25, 0, 0x40, 0, 0};
    if (memory)
        ff_write(&a, 0x4000, value, 4, true);
    uint32_t length = memory ? sizeof(store) : sizeof(mov);
    seqs[3] = emit(&t, dest, memory ? store : mov, length, a, dest + length, 7, 0);
    a = registers();
    a.reg_vals[DTA_REG_RBX] = taken ? 1 : 0;
    a.reg_taint[DTA_REG_RBX] = 15;
    a.eflags_before = taken ? 0x202 : 0x246;
    a.reg_vals[DTA_REG_RAX] = memory ? 0 : value;
    if (memory)
        ff_read(&a, 0x4000, value, 4, true);
    seqs[4] = emit(&t, dest + length, memory ? memjump : jump,
                   memory ? sizeof(memjump) : sizeof(jump), a, value, 7, 0);
    CHECK(trace_record_control_transfer(t.f.trace, seqs[4], 0, PROV_LABEL_CLEAN));
    DseRelevanceContext c = context(&t);
    if (fault == 5) {
        TraceEntry *corrupt = (TraceEntry *)trace_find_seq(t.f.trace, seqs[2], NULL);
        corrupt->code_generation++;
    }
    if (fault == 6) {
        InsnAux *corrupt =
            (InsnAux *)dse_aux_for(t.f.aux, t.f.trace, trace_find_seq(t.f.trace, seqs[1], NULL));
        corrupt->next_pc++;
    }
    if (!fault) {
        /* A later occurrence of the same PC is outside the requested prefix. */
        branch(&t, 0x1009, a, 0x1012, 20, 0, 0);
    }
    const TraceEntry *out[16];
    DseSliceResult r = memory ? dse_build_mem_slice_with_relevance(t.f.trace, t.f.aux, seqs[4],
                                                                   0x4000, 4, out, 16, &c)
                              : slice(&t, seqs[4], out, 16);
    if (fault == 5) {
        CHECK(r.status == DSE_SLICE_DEPENDENCY_UNKNOWN && !r.complete);
        CHECK(r.control.issues & DSE_CONTROL_METADATA_MISSING);
        destroy(&t);
        return;
    }
    if (fault == 6) {
        exact(&r, out, seqs, 5);
        CHECK(!r.path_complete && (r.control.issues & DSE_CONTROL_ORDER_CONFLICT));
        CHECK(r.control.cfg_stops[DSE_CFG_STOP_NEXT_PC_MISMATCH] == 1);
        const DseCfgBuildStop *stop = &r.control.cfg_examples[0].build_stop;
        CHECK(stop->site_present && stop->site.pc == 0x1006 && stop->site.seq_id == seqs[1]);
        CHECK(stop->expected_next_valid && stop->expected_next_pc == 0x1009);
        CHECK(stop->observed_next_valid && stop->observed_next_pc == 0x100a);
        destroy(&t);
        return;
    }
    exact(&r, out, seqs, 5);
    CHECK(r.control.branches == 1 && r.control.retained == 1);
    if (fault == 1)
        CHECK(r.control.disjoint_retained == 0 && r.relevance.events_unknown == 1);
    else
        CHECK(r.control.disjoint_retained == 1 && r.relevance.events_irrelevant == 1);
    CHECK(r.control.first_unknown.seq_id == seqs[2] &&
          r.control.first_unknown.code_generation == 7);
    if (fault) {
        CHECK(!r.path_complete && !r.complete);
        CHECK(r.control.issues & (DSE_CONTROL_EVENT_MISSING | DSE_CONTROL_EVENT_CONFLICT));
        DseVerifyResult check = dse_verify_oep_candidate_with_relevance(
            t.f.trace, t.f.aux, seqs[4], DTA_REG_RAX, value, NULL, t.f.decoder, &c);
        CHECK(!check.proof_eligible && check.verdict == DSE_VERDICT_UNKNOWN);
        CHECK(check.control.trigger_seq == seqs[4] && !check.slice_complete);
        CHECK(check.control.issues & (DSE_CONTROL_EVENT_MISSING | DSE_CONTROL_EVENT_CONFLICT));
    } else {
        CHECK(r.path_complete && r.complete);
        CHECK(r.control.issues == DSE_CONTROL_PARTIAL_CFG);
        diagnostic_counts(&r.control);
        CHECK(r.control.cfg_example_count == 1);
        const DseCfgExample *example = &r.control.cfg_examples[0];
        CHECK(example->reason == DSE_CFG_FAILURE_SUCCESSOR);
        CHECK(example->build_stop.reason == DSE_CFG_STOP_TRACE_START);
        CHECK(example->build_stop.site.pc == 0x1000 && example->at.pc == 0x1009);
        CHECK(example->edge_issue == DSE_CFG_EDGE_ABSENT);
        CHECK(example->target_pc == (taken ? 0x100b : 0x1012));
        CHECK(example->successor_index == (taken ? 0U : 1U));
        if (!memory) {
            DseVerifyResult check = dse_verify_oep_candidate_with_relevance(
                t.f.trace, t.f.aux, seqs[4], DTA_REG_RAX, value, NULL, t.f.decoder, &c);
            if (!check.replay_valid || check.path_constraints != 1)
                fprintf(stderr, "legacy reason=%u replay=%d path=%u/%u failures=%u\n", check.reason,
                        check.replay_valid, check.path_constraints, check.path_constraints_expected,
                        check.replay_failures);
            CHECK(check.replay_valid && check.path_constraints == 1 && check.slice_complete);
            CHECK(check.control.retained == 1 && check.evidence == DSE_EVIDENCE_REPLAY_OK);
        }
    }
    if (!fault && taken && !memory) {
        ReplayInput *input = ff_capture(&t.f, seqs, 4, seqs[4]);
        DseControlStats saved = r.control;
        destroy(&t);
        IrReplayOptions options = ir_replay_default_options();
        options.x86.flat32_ram = true;
        IrReplayBuildInfo info;
        IrReplay *replay = ir_replay_x86_build(input, &options, &info);
        CHECK(replay && info.status == IR_REPLAY_READY);
        replay_input_destroy(input);
        ff_match(replay);
        changed_selector(replay, seqs[2]);
        ff_opt_match(replay);
        changed_selector(replay, seqs[2]);
        const IrModule *module = ir_replay_module(replay);
        unsigned branches = 0;
        for (uint32_t b = 1; b <= ir_module_block_count(module); ++b) {
            const IrBlock *block = ir_module_block(module, b);
            if (block->terminator.kind == IR_TERM_CJUMP) {
                CHECK(block->terminator.origin.seq_id == seqs[2]);
                ++branches;
            }
        }
        CHECK(branches == 1);
        GString *s = g_string_new(NULL);
        dse_control_append_json(s, &saved);
        if (json)
            fprintf(json, "%s\n", s->str);
        g_string_free(s, true);
        ir_replay_destroy(replay);
        return;
    }
    DseControlStats saved = r.control;
    destroy(&t);
    if (json) {
        GString *s = g_string_new(NULL);
        dse_control_append_json(s, &saved);
        fprintf(json, "%s\n", s->str);
        g_string_free(s, true);
    }
}

static void diagnostic_targets(FILE *json) {
    for (unsigned variant = 0; variant < 2; ++variant) {
        Fixture t = fixture(8);
        InsnAux a = registers();
        a.eflags_before = 0x246;
        branch_to(&t, 0x10, a, 0x12, 1, 0, 0, variant ? 0x12 : 0);
        const uint8_t dest[] = {0xb8, 0, 0x20, 0, 0}, jump[] = {0xff, 0xe0};
        emit(&t, 0x12, dest, sizeof(dest), a, 0x17, variant ? 2 : 1, 0);
        a.reg_vals[DTA_REG_RAX] = 0x2000;
        uint64_t trigger = emit(&t, 0x17, jump, sizeof(jump), a, 0x2000, variant ? 2 : 1, 0);
        const TraceEntry *out[8];
        DseSliceResult r = slice(&t, trigger, out, 8);
        CHECK(r.complete && r.control.cfg_unknown == 1 && !r.control.cfg_pruned);
        const DseCfgExample *e = &r.control.cfg_examples[0];
        CHECK(e->reason == DSE_CFG_FAILURE_SUCCESSOR && e->at.pc == 0x10);
        CHECK(e->build_stop.reason == DSE_CFG_STOP_TRACE_START);
        CHECK(e->target_pc == (variant ? 0x12U : 0U));
        CHECK(e->successor_index == (variant ? 0U : 1U));
        CHECK(e->edge_issue == (variant ? DSE_CFG_EDGE_GENERATION : DSE_CFG_EDGE_ABSENT));
        CHECK(!variant || e->target_generation == 2);
        DseControlStats saved = r.control;
        destroy(&t);
        if (json) {
            GString *s = g_string_new(NULL);
            dse_control_append_json(s, &saved);
            fprintf(json, "%s\n", s->str);
            g_string_free(s, true);
        }
    }
    puts("PASS: missing edges retain zero PC and distinguish generation mismatch");
}

static void diagnostic_barriers(FILE *json) {
    static const uint8_t code[7][10] = {
        {0x8b, 0x15, 0, 0x40, 0, 0},          /* mov edx, [0x4000] */
        {0xc7, 5, 0, 0x40, 0, 0, 2, 0, 0, 0}, /* mov [0x4000], 2 */
        {0xff, 5, 0, 0x40, 0, 0},             /* inc [0x4000] */
        {0xfc},                               /* cld */
        {0xc3},                               /* ret */
        {0xe8, 0, 0, 0, 0},                   /* call next */
        {0xff, 0xe3}                          /* jmp ebx */
    };
    static const uint8_t sizes[] = {6, 10, 6, 1, 1, 5, 2};
    static const DseCfgStopReason reasons[] = {DSE_CFG_STOP_MEMORY_READ, DSE_CFG_STOP_MEMORY_WRITE,
                                               DSE_CFG_STOP_MEMORY_RMW,  DSE_CFG_STOP_OPAQUE,
                                               DSE_CFG_STOP_RETURN,      DSE_CFG_STOP_CALL,
                                               DSE_CFG_STOP_INDIRECT};
    for (unsigned variant = 0; variant < G_N_ELEMENTS(sizes); ++variant) {
        Fixture t = fixture(8);
        InsnAux a = registers();
        a.eflags_before = 0x246;
        branch_to(&t, 0x1000, a, 0x1002, 1, 0, 0, 0x1002);
        if (variant == 0 || variant == 2)
            ff_read(&a, 0x4000, 1, 4, true);
        if (variant == 1 || variant == 2)
            ff_write(&a, 0x4000, 2, 4, true);
        uint32_t next = 0x1002 + sizes[variant];
        if (variant == 4) {
            a.reg_vals[DTA_REG_RSP] = 0x4000;
            ff_read(&a, 0x4000, next, 4, true);
        } else if (variant == 5) {
            a.reg_vals[DTA_REG_RSP] = 0x4004;
            ff_write(&a, 0x4000, next, 4, true);
        } else if (variant == 6) {
            a.reg_vals[DTA_REG_RBX] = next;
        }
        emit(&t, 0x1002, code[variant], sizes[variant], a, next, 1, 0);
        a = registers();
        const uint8_t dest[] = {0xb8, 0, 0x20, 0, 0}, jump[] = {0xff, 0xe0};
        emit(&t, next, dest, sizeof(dest), a, next + 5, 1, 0);
        a.reg_vals[DTA_REG_RAX] = 0x2000;
        uint64_t trigger = emit(&t, next + 5, jump, sizeof(jump), a, 0x2000, 1, 0);
        const TraceEntry *out[8];
        DseSliceResult r = slice(&t, trigger, out, 8);
        CHECK(r.complete && r.control.cfg_unknown == 1 && !r.control.cfg_pruned);
        const DseCfgExample *e = &r.control.cfg_examples[0];
        CHECK(e->edge_issue == DSE_CFG_EDGE_NONE);
        if (!variant) {
            CHECK(e->reason == DSE_CFG_FAILURE_MEMORY_READ && e->at.pc == 0x1002);
            CHECK(e->build_stop.reason == DSE_CFG_STOP_TRACE_START);
            CHECK(r.control.cfg_nodes == 3);
        } else {
            CHECK(e->reason == DSE_CFG_FAILURE_BRANCH_OUTSIDE);
            CHECK(e->build_stop.reason == reasons[variant] && e->build_stop.site.pc == 0x1002);
            CHECK(e->build_stop.expected_next_pc == next && e->build_stop.observed_next_pc == next);
        }
        DseControlStats saved = r.control;
        destroy(&t);
        if (json) {
            GString *s = g_string_new(NULL);
            dse_control_append_json(s, &saved);
            fprintf(json, "%s\n", s->str);
            g_string_free(s, true);
        }
    }
    puts(
        "PASS: reads are collected but not proved; writes, opaque operations, calls, returns and indirect jumps retain barriers");
}

static void imul_regions(void) {
    static const uint8_t code[][6] = {
        {0x6b, 0xd2, 0x68},       {0x69, 0xd2, 0x68, 0, 0, 0}, {0x0f, 0xaf, 0xd2},
        {0x66, 0x6b, 0xd2, 0x68}, {0x66, 0x69, 0xd2, 0x68, 0}, {0x66, 0x0f, 0xaf, 0xd2},
        {0x6b, 0xc0, 1},          {0x6b, 0xd2, 0x68}};
    static const uint8_t sizes[] = {3, 6, 3, 4, 5, 4, 3, 3};
    for (unsigned variant = 0; variant < G_N_ELEMENTS(sizes); ++variant) {
        Fixture t = fixture(16);
        InsnAux a = registers();
        const uint8_t initial[] = {0xb8, 0, 0x20, 0, 0}, add[] = {0x83, 0xc0, 0};
        const uint8_t adc[] = {0x83, 0xd0, 0}, jump[] = {0xff, 0xe0};
        emit(&t, 0xffb, initial, sizeof(initial), a, 0x1000, 1, 0);
        a.reg_vals[DTA_REG_RAX] = 0x2000;
        a.eflags_before = 0x246;
        uint32_t join = 0x1002 + sizes[variant];
        branch_to(&t, 0x1000, a, 0x1002, 1, 0, 0, join);
        uint64_t multiply = emit(&t, 0x1002, code[variant], sizes[variant], a, join, 1, 0);
        const TraceEntry *entry = trace_find_seq(t.f.trace, multiply, NULL);
        const InsnDesc *desc = trace_insn_desc_get(t.f.trace, entry->insn_desc_id);
        CHECK(desc->effects.register_defs == (UINT64_C(1) << (variant == 6 ? DTA_REG_RAX : DTA_REG_RDX)));
        uint64_t flags = trace_special_state_bit(X86_SPECIAL_STATE_CF) |
                         trace_special_state_bit(X86_SPECIAL_STATE_PF) |
                         trace_special_state_bit(X86_SPECIAL_STATE_AF) |
                         trace_special_state_bit(X86_SPECIAL_STATE_ZF) |
                         trace_special_state_bit(X86_SPECIAL_STATE_SF) |
                         trace_special_state_bit(X86_SPECIAL_STATE_OF);
        CHECK((desc->effects.special_defs & flags) == flags);
        emit(&t, join, variant == 7 ? adc : add, sizeof(add), a, join + 3, 1, 0);
        a.eflags_before = 0x206;
        uint64_t trigger = emit(&t, join + 3, jump, sizeof(jump), a, 0x2000, 1, 0);
        const TraceEntry *out[16];
        dse_set_control_pruning(false);
        DseSliceResult full = slice(&t, trigger, out, 16);
        dse_set_control_pruning(true);
        DseSliceResult reduced = slice(&t, trigger, out, 16);
        CHECK(full.complete && reduced.complete);
        CHECK(!reduced.control.cfg_stops[DSE_CFG_STOP_OPAQUE]);
        if (variant < 6) {
            CHECK(reduced.control.cfg_pruned == 1 && reduced.len + 1 == full.len);
            CHECK(!reduced.control.retained && full.control.retained == 1);
        } else {
            CHECK(!reduced.control.cfg_pruned && reduced.len == full.len);
            CHECK(reduced.control.cfg_unknown + reduced.control.cfg_effect_conflicts == 1);
        }
        destroy(&t);
    }
    puts("PASS: register IMUL forms build CFG; live destination and flag writes prevent pruning");
}

static void nested_and_occurrences(void) {
    Fixture t = fixture(32);
    InsnAux a = registers();
    a.reg_vals[DTA_REG_RCX] = 1;
    a.reg_taint[DTA_REG_RCX] = 15;
    const uint8_t cmpc[] = {0x83, 0xf9, 0}, cmpb[] = {0x83, 0xfb, 0};
    const uint8_t one[] = {0xbb, 1, 0, 0, 0}, dest[] = {0xb8, 0, 0x20, 0, 0};
    const uint8_t jump[] = {0xff, 0xe0};
    uint64_t expected[7];
    expected[0] = emit(&t, 0x2000, cmpc, sizeof(cmpc), a, 0x2003, 1, 0);
    expected[1] = branch(&t, 0x2003, a, 0x200c, 1, 0, 0);
    expected[2] = emit(&t, 0x200c, one, sizeof(one), a, 0x2011, 1, 0);
    a.reg_vals[DTA_REG_RBX] = 1;
    expected[3] = emit(&t, 0x2011, cmpb, sizeof(cmpb), a, 0x2014, 2, 0);
    const uint8_t back[] = {0xe9, 0xea, 0xff, 0xff, 0xff};
    emit(&t, 0x2014, back, sizeof(back), a, 0x2003, 2, 0);
    (void)branch(&t, 0x2003, a, 0x200c, 99, 1, 0);
    expected[4] = branch(&t, 0x2003, a, 0x200c, 2, 0, 0);
    expected[5] = emit(&t, 0x200c, dest, sizeof(dest), a, 0x2011, 2, 0);
    a.reg_vals[DTA_REG_RAX] = 0x2000;
    expected[6] = emit(&t, 0x2011, jump, sizeof(jump), a, 0x2000, 2, 0);
    const TraceEntry *out[16];
    DseSliceResult r = slice(&t, expected[6], out, 16);
    exact(&r, out, expected, 7);
    CHECK(r.control.retained == 2 && r.control.branches == 2 && r.path_complete);
    CHECK(out[1]->code_generation == 1 && out[4]->code_generation == 2);
    CHECK(out[1]->pc == out[4]->pc && out[1]->seq_id != out[4]->seq_id);
    destroy(&t);
}

static void boundaries_and_budgets(void) {
    const uint8_t dest[] = {0xb8, 0, 0x20, 0, 0}, jump[] = {0xff, 0xe0}, nop[] = {0x90};
    Fixture t = fixture(8);
    InsnAux a = registers();
    for (unsigned i = 0; i < 10; ++i)
        emit(&t, 0x1000, nop, 1, a, 0x1001, 1, 0);
    uint64_t def = emit(&t, 0x1001, dest, sizeof(dest), a, 0x1006, 1, 0);
    a.reg_vals[DTA_REG_RAX] = 0x2000;
    uint64_t trigger = emit(&t, 0x1006, jump, sizeof(jump), a, 0x2000, 1, 0);
    const TraceEntry *out[16];
    DseSliceResult r = slice(&t, trigger, out, 16);
    uint64_t expected[] = {def, trigger};
    exact(&r, out, expected, 2);
    CHECK(!r.path_complete && (r.control.issues & DSE_CONTROL_OPEN_BOUNDARY));
    destroy(&t);

    t = fixture(8192);
    a = registers();
    for (unsigned i = 0; i < DSE_MAX_CONTROL_SCAN + 1; ++i)
        emit(&t, 0x1000, nop, 1, a, 0x1001, 1, 0);
    emit(&t, 0x1001, dest, sizeof(dest), a, 0x1006, 1, 0);
    a.reg_vals[DTA_REG_RAX] = 0x2000;
    trigger = emit(&t, 0x1006, jump, sizeof(jump), a, 0x2000, 1, 0);
    r = slice(&t, trigger, out, 16);
    CHECK(r.status == DSE_SLICE_OK && !r.path_complete &&
          r.control.scanned == DSE_MAX_CONTROL_SCAN && (r.control.issues & DSE_CONTROL_SCAN_LIMIT));
    destroy(&t);

    t = fixture(256);
    a = registers();
    for (unsigned i = 0; i <= DSE_MAX_PATH_CONSTRAINTS; ++i)
        branch(&t, 0x1000, a, 0x1009, i, 0, 0);
    emit(&t, 0x1009, dest, sizeof(dest), a, 0x100e, 1, 0);
    a.reg_vals[DTA_REG_RAX] = 0x2000;
    trigger = emit(&t, 0x100e, jump, sizeof(jump), a, 0x2000, 1, 0);
    const TraceEntry *large[MAX_SLICE];
    r = slice(&t, trigger, large, MAX_SLICE);
    CHECK(r.status == DSE_SLICE_OK && !r.path_complete && !r.complete);
    CHECK((r.control.issues & DSE_CONTROL_SLICE_LIMIT) && r.control.retained == 0);
    r = slice(&t, trigger, out, 2);
    CHECK(!r.complete && (r.control.issues & DSE_CONTROL_SLICE_LIMIT));
    destroy(&t);

    t = fixture(1024);
    a = registers();
    emit(&t, 0xffb, dest, sizeof(dest), a, 0x1000, 1, 0);
    a.reg_vals[DTA_REG_RAX] = 0x2000;
    a.eflags_before = 0x246;
    branch_to(&t, 0x1000, a, 0x1002, 1, 0, 0, 0x1002);
    for (unsigned i = 0; i < DCFG_REGION_MAX_NODES; ++i)
        emit(&t, 0x1002 + i, nop, 1, a, 0x1003 + i, 1, 0);
    trigger = emit(&t, 0x1002 + DCFG_REGION_MAX_NODES, jump, sizeof(jump), a, 0x2000, 1, 0);
    r = slice(&t, trigger, out, 16);
    CHECK(r.complete && r.control.retained == 1 && r.control.cfg_pruned == 0);
    CHECK(r.control.cfg_nodes == DCFG_REGION_MAX_NODES &&
          (r.control.cfg_issues & DCFG_REGION_BUDGET));
    CHECK(r.control.cfg_stops[DSE_CFG_STOP_NODE_BUDGET] == 1);
    CHECK(r.control.cfg_examples[0].reason == DSE_CFG_FAILURE_REGION_BUDGET);
    CHECK(r.control.cfg_examples[0].edge_issue == DSE_CFG_EDGE_NONE);
    destroy(&t);

    t = fixture(8192);
    a = registers();
    emit(&t, 0xffb, dest, sizeof(dest), a, 0x1000, 1, 0);
    a.reg_vals[DTA_REG_RAX] = 0x2000;
    uint32_t pc = 0x1000;
    a.eflags_before = 0x246;
    for (unsigned i = 0; i < DSE_MAX_PATH_CONSTRAINTS; ++i) {
        branch_to(&t, pc, a, pc + 2, 1, 0, 0, pc + 2);
        pc += 2;
        for (unsigned j = 0; j < 31; ++j, ++pc)
            emit(&t, pc, nop, 1, a, pc + 1, 1, 0);
    }
    trigger = emit(&t, pc, jump, sizeof(jump), a, 0x2000, 1, 0);
    r = slice(&t, trigger, large, MAX_SLICE);
    CHECK(r.status == DSE_SLICE_OK && !r.path_complete && r.control.cfg_pruned == 0);
    if (r.control.cfg_scanned != DSE_MAX_CONTROL_SCAN)
        fprintf(stderr, "local CFG scanned=%u regions=%u issues=%x\n", r.control.cfg_scanned,
                r.control.cfg_regions, r.control.cfg_issues);
    CHECK(r.control.cfg_scanned == DSE_MAX_CONTROL_SCAN && r.control.cfg_regions > 1);
    CHECK(r.control.cfg_issues & DCFG_REGION_BUDGET);
    CHECK(r.control.cfg_stops[DSE_CFG_STOP_SCAN_BUDGET] > 0);
    destroy(&t);
}

static void enumerate_paths(const DcfgRegionNode *n, uint32_t id, uint32_t path,
                            uint32_t *intersection) {
    path |= 1U << id;
    if (n[id].terminal)
        *intersection &= path;
    for (uint32_t i = 0; i < n[id].successor_count; ++i)
        enumerate_paths(n, n[id].successors[i], path, intersection);
}

static void region_graphs(void) {
    DcfgRegionNode n[6] = {0};
    unsigned graphs = 0;
    /* Enumerate all five-node DAGs with at most two successors per node.
     * The independent oracle intersects complete paths, without memoization. */
    for (unsigned edges = 0; edges < (1U << 10); ++edges) {
        memset(n, 0, sizeof(n));
        unsigned bit = 0;
        bool valid = true;
        for (unsigned from = 1; from <= 5; ++from) {
            for (unsigned to = from + 1; to <= 5; ++to, ++bit) {
                if (!(edges & (1U << bit)))
                    continue;
                if (n[from].successor_count == 2) {
                    valid = false;
                    continue;
                }
                n[from].successors[n[from].successor_count++] = to;
            }
            n[from].terminal = !n[from].successor_count;
        }
        if (!valid)
            continue;
        ++graphs;
        uint32_t common[6];
        for (unsigned from = 1; from <= 5; ++from) {
            common[from] = UINT32_MAX;
            enumerate_paths(n, from, 0, &common[from]);
        }
        for (unsigned from = 1; from <= 5; ++from) {
            for (unsigned boundary = 1; boundary <= 5; ++boundary) {
                bool postdom = (common[from] & (1U << boundary)) != 0;
                bool controlled = false;
                for (unsigned j = 0; j < n[from].successor_count; ++j)
                    controlled |= !postdom && (common[n[from].successors[j]] & (1U << boundary));
                DcfgRegionResult r = dcfg_region_analyze(n, 5, from, boundary, 5);
                CHECK(!r.issues);
                CHECK(!r.witness_issue);
                CHECK(r.postdominates == (postdom ? DCFG_REGION_YES : DCFG_REGION_NO));
                CHECK(r.control_dependent == (controlled ? DCFG_REGION_YES : DCFG_REGION_NO));
            }
        }
    }
    memset(n, 0, sizeof(n));
    n[1] = (DcfgRegionNode){.successors = {2, 3}, .successor_count = 2};
    n[2] = (DcfgRegionNode){.successors = {4}, .successor_count = 1, .register_writes = 1};
    n[3] = (DcfgRegionNode){.successors = {4}, .successor_count = 1, .special_writes = 2};
    n[4] = (DcfgRegionNode){.terminal = true, .register_writes = 4};
    DcfgRegionResult r = dcfg_region_analyze(n, 4, 1, 4, 4);
    CHECK(r.postdominates == DCFG_REGION_YES && r.register_writes == 1 && r.special_writes == 2);
    r = dcfg_region_analyze(n, 4, 1, 4, 2);
    CHECK(r.witness_issue == DCFG_REGION_BUDGET && r.witness_node == 4 &&
          r.witness_successor == UINT32_MAX);
    n[3].successors[0] = 0;
    r = dcfg_region_analyze(n, 4, 1, 4, 4);
    CHECK(r.witness_issue == DCFG_REGION_OPEN && r.witness_node == 3 && r.witness_successor == 0);
    /* An unrelated open edge must not become the witness for another query. */
    CHECK(!dcfg_region_analyze(n, 4, 2, 4, 4).witness_issue);
    n[3].successors[0] = 5;
    r = dcfg_region_analyze(n, 4, 1, 4, 4);
    CHECK(r.witness_issue == DCFG_REGION_INVALID && r.witness_node == 3 &&
          r.witness_successor == 0);
    n[3].successors[0] = 4;
    n[3].successors[1] = 3;
    n[3].successor_count = 2;
    r = dcfg_region_analyze(n, 4, 1, 4, 4);
    CHECK(r.postdominates == DCFG_REGION_UNKNOWN && (r.issues & DCFG_REGION_CYCLE));
    CHECK(r.witness_issue == DCFG_REGION_CYCLE && r.witness_node == 3 &&
          r.witness_successor == UINT32_MAX);
    n[3].successor_count = 1;
    n[3].opaque = true;
    r = dcfg_region_analyze(n, 4, 1, 4, 4);
    CHECK(r.witness_issue == DCFG_REGION_OPAQUE && r.witness_node == 3 &&
          r.witness_successor == UINT32_MAX);
    r = dcfg_region_analyze(n, 4, 0, 4, 4);
    CHECK(r.witness_issue == DCFG_REGION_INVALID && !r.witness_node &&
          r.witness_successor == UINT32_MAX);
    printf(
        "PASS: %u exhaustive DAGs, postdominators/control dependence, all-arm effects, exits, unknown continuations, loops and budgets\n",
        graphs);
}

static void closed_diamond(unsigned variant, bool open_prefix, bool memory_boundary) {
    Fixture t = fixture(64);
    InsnAux a = registers();
    if (open_prefix) {
        const uint8_t nop[] = {0x90};
        for (unsigned i = 0; i < 64; ++i)
            emit(&t, 0xfb0 + i, nop, 1, a, 0xfb1 + i, 1, 0);
    }
    const uint8_t load[] = {0xa1, 0, 0x30, 0, 0}, init[] = {0xb9, 2, 0, 0, 0};
    const uint8_t entry[] = {0xe9, 1, 0, 0, 0};
    const uint8_t cmp[] = {0x83, 0xf9, 2}, dec[] = {0x49}, jump[] = {0xff, 0xe0};
    const uint8_t left[] = {0xba, 17, 0, 0, 0}, right[] = {0xba, 34, 0, 0, 0};
    const uint8_t clobber[] = {0xb8, 0, 0x90, 0, 0}, store[] = {0xa3, 0, 0x40, 0, 0};
    const uint8_t join_left[] = {0xeb, 7}, join_right[] = {0xeb, 0};
    uint64_t first_left = 0;
    ff_read(&a, 0x3000, 0x2000, 4, true);
    a.mem_reads[0].taint = 15;
    emit(&t, 0x0ff0, load, sizeof(load), a, 0x0ff5, 1, 0);
    a = registers();
    a.reg_vals[DTA_REG_RAX] = 0x2000;
    a.reg_taint[DTA_REG_RAX] = 15;
    emit(&t, 0x0ff5, init, sizeof(init), a, 0x0ffa, 1, 0);
    a.reg_vals[DTA_REG_RCX] = 2;
    emit(&t, 0x0ffa, entry, sizeof(entry), a, 0x1000, 1, 0);
    for (unsigned iteration = 0; iteration < 2; ++iteration) {
        emit(&t, 0x1000, cmp, sizeof(cmp), a, 0x1003, 1, 0);
        a.eflags_before = iteration ? 0x297 : 0x246;
        branch(&t, 0x1003, a, iteration ? 0x100c : 0x1005, 1, 0, 0);
        if (!iteration) {
            if (variant == 2)
                ff_write(&a, 0x4000, a.reg_vals[DTA_REG_RAX], 4, true);
            first_left = emit(&t, 0x1005,
                              variant == 1   ? clobber
                              : variant == 2 ? store
                                             : left,
                              5, a, 0x100a, 1, 0);
            a.has_mem_write = false;
            a.mem_write_count = a.mem_write_total = 0;
            a.mem_write_range_valid = false;
            if (variant == 1) {
                a.reg_vals[DTA_REG_RAX] = 0x9000;
                a.reg_taint[DTA_REG_RAX] = 0;
            } else if (variant != 2) {
                a.reg_vals[DTA_REG_RDX] = 17;
            }
            emit(&t, 0x100a, join_left, sizeof(join_left), a, 0x1013, 1, 0);
        } else {
            emit(&t, 0x100c, right, sizeof(right), a, 0x1011, 1, 0);
            a.reg_vals[DTA_REG_RDX] = 34;
            emit(&t, 0x1011, join_right, sizeof(join_right), a, 0x1013, 1, 0);
        }
        emit(&t, 0x1013, dec, sizeof(dec), a, 0x1014, 1, 0);
        --a.reg_vals[DTA_REG_RCX];
        a.eflags_before = iteration ? 0x247 : 0x202;
        branch_to(&t, 0x1014, a, iteration ? 0x1016 : 0x1000, 1, 0, 0, 0x1000);
    }
    uint64_t target = a.reg_vals[DTA_REG_RAX];
    const uint8_t memjump[] = {0xff, 0x22};
    uint32_t trigger_pc = 0x1016;
    if (memory_boundary) {
        const uint8_t dereference[] = {0x8b, 0};
        ff_read(&a, target, 0x3000, 4, true);
        a.mem_reads[0].taint = 15;
        emit(&t, trigger_pc, dereference, sizeof(dereference), a, trigger_pc + 2, 1, 0);
        trigger_pc += 2;
        target = 0x3000;
        a = registers();
        a.reg_vals[DTA_REG_RAX] = target;
        a.reg_taint[DTA_REG_RAX] = 15;
        a.reg_vals[DTA_REG_RDX] = 34;
        a.eflags_before = 0x247;
    }
    if (variant == 3)
        ff_read(&a, a.reg_vals[DTA_REG_RDX], target, 4, true);
    uint64_t trigger =
        emit(&t, trigger_pc, variant == 3 ? memjump : jump, sizeof(jump), a, target, 1, 0);
    CHECK(trace_record_control_transfer(t.f.trace, trigger, 0, PROV_LABEL_CLEAN));
    if (variant == 4) {
        InsnAux *bad_route =
            (InsnAux *)dse_aux_for(t.f.aux, t.f.trace, trace_find_seq(t.f.trace, first_left, NULL));
        CHECK(bad_route);
        ++bad_route->next_pc;
    }
    const TraceEntry *out[32];
    DseRelevanceContext c = context(&t);
    dse_set_control_pruning(false);
    DseSliceResult full =
        variant == 3
            ? dse_build_mem_slice_with_relevance(t.f.trace, t.f.aux, trigger, 34, 4, out, 32, &c)
            : slice(&t, trigger, out, 32);
    DseVerifyResult before =
        variant == 3 ? dse_verify_oep_candidate_mem_with_relevance(t.f.trace, t.f.aux, trigger, 34,
                                                                   target, NULL, t.f.decoder, &c)
                     : dse_verify_oep_candidate_with_relevance(t.f.trace, t.f.aux, trigger, DTA_REG_RAX,
                                                               target, NULL, t.f.decoder, &c);
    dse_set_control_pruning(true);
    DseSliceResult reduced =
        variant == 3
            ? dse_build_mem_slice_with_relevance(t.f.trace, t.f.aux, trigger, 34, 4, out, 32, &c)
            : slice(&t, trigger, out, 32);
    DseVerifyResult after =
        variant == 3 ? dse_verify_oep_candidate_mem_with_relevance(t.f.trace, t.f.aux, trigger, 34,
                                                                   target, NULL, t.f.decoder, &c)
                     : dse_verify_oep_candidate_with_relevance(t.f.trace, t.f.aux, trigger, DTA_REG_RAX,
                                                               target, NULL, t.f.decoder, &c);
    if (!before.replay_valid || !after.replay_valid)
        fprintf(stderr, "diamond %u before=%u/%u after=%u/%u\n", variant, before.reason,
                before.replay_failures, after.reason, after.replay_failures);
    CHECK(full.complete == (!open_prefix && variant != 4));
    CHECK(reduced.complete == (!open_prefix && variant != 4));
    CHECK(before.replay_valid && after.replay_valid);
    CHECK(before.verdict == after.verdict && before.candidate_query == after.candidate_query &&
          before.alternative_query == after.alternative_query);
    if (open_prefix || variant == 4) {
        unsigned issue = variant == 4 ? DSE_CONTROL_ORDER_CONFLICT : DSE_CONTROL_OPEN_BOUNDARY;
        CHECK(full.control.issues & issue);
        CHECK(reduced.control.issues & issue);
        CHECK(!after.proof_eligible && !after.path_model_complete);
        CHECK(after.verdict == DSE_VERDICT_UNKNOWN &&
              after.reason == DSE_REASON_PATH_MODEL_INCOMPLETE);
        CHECK(after.candidate_query == DSE_SOLVER_NOT_RUN &&
              after.alternative_query == DSE_SOLVER_NOT_RUN);
    }
    CHECK(reduced.control.cfg_scanned <= DSE_MAX_CONTROL_SCAN);
    CHECK(reduced.control.cfg_nodes <= DCFG_REGION_MAX_NODES);
    if (!variant) {
        CHECK(reduced.control.cfg_pruned == 2 && reduced.len < full.len);
        CHECK(after.path_constraints + 2 == before.path_constraints);
        CHECK(after.expr_nodes_created < before.expr_nodes_created);
        printf(
            "PASS: A/B open=%u memory-boundary=%u; slice %u -> %u, constraints %u -> %u, expressions %u -> %u; replay and proof status agree\n",
            open_prefix, memory_boundary, full.len, reduced.len, before.path_constraints,
            after.path_constraints, before.expr_nodes_created, after.expr_nodes_created);
    } else {
        CHECK(reduced.control.cfg_pruned == 0 && reduced.len == full.len);
        if (variant == 1 || variant == 3)
            CHECK(reduced.control.cfg_effect_conflicts > 0);
        puts(variant == 4   ? "PASS: broken occurrence routes cannot supply alternate-arm evidence"
             : variant == 1 ? "PASS: alternate-arm writes prevent pruning even after reconvergence"
             : variant == 2
                 ? "PASS: a possible code write prevents reuse of older arm bytes"
                 : "PASS: clean address registers remain protected from alternate-arm writes");
    }
    destroy(&t);
}

static InsnDescId decoded(Fixture *t, uint32_t pc, const uint8_t *bytes, uint8_t size,
                          uint32_t generation) {
    InsnMeta *m = meta_decode(bytes, size, pc, t->f.decoder);
    CHECK(m);
    const InsnMeta *stored = meta_store(pc, m);
    CHECK(stored);
    InsnDescId id = trace_insn_desc_intern(t->f.trace, TRACE_ARCH_X86, TRACE_MODE_32, pc,
                                           generation, bytes, size, stored);
    CHECK(id);
    return id;
}

static void descriptor_index(void) {
    Fixture t = fixture(8);
    const uint8_t nop[] = {0x90}, inc[] = {0x42};
    InsnDescId id = decoded(&t, 0, nop, 1, 7);
    CHECK(decoded(&t, 0, nop, 1, 7) == id && trace_insn_desc_count(t.f.trace) == 1);
    const InsnDesc *d = NULL;
    CHECK(trace_insn_desc_find(t.f.trace, TRACE_ARCH_X86, TRACE_MODE_32, 0, 7, 1, &d) ==
          TRACE_DESC_FOUND);
    CHECK(d->desc_id == id && d->available_seq == 1);
    CHECK(trace_insn_desc_find(t.f.trace, TRACE_ARCH_X86, TRACE_MODE_64, 0, 7, 1, &d) ==
              TRACE_DESC_ABSENT &&
          !d);
    CHECK(trace_insn_desc_find(t.f.trace, TRACE_ARCH_X86, TRACE_MODE_32, 0, 8, 1, &d) ==
              TRACE_DESC_ABSENT &&
          !d);
    emit(&t, 0, nop, 1, registers(), 1, 7, 0);
    decoded(&t, 1, nop, 1, 7);
    CHECK(trace_insn_desc_find(t.f.trace, TRACE_ARCH_X86, TRACE_MODE_32, 1, 7, 1, &d) ==
              TRACE_DESC_FUTURE &&
          !d);
    decoded(&t, 0, inc, 1, 7);
    CHECK(trace_insn_desc_find(t.f.trace, TRACE_ARCH_X86, TRACE_MODE_32, 0, 7, 1, &d) ==
              TRACE_DESC_AMBIGUOUS &&
          !d);
    trace_reset(t.f.trace);
    CHECK(trace_insn_desc_find(t.f.trace, TRACE_ARCH_X86, TRACE_MODE_32, 1, 7, 2, &d) ==
          TRACE_DESC_FOUND);
    destroy(&t);
    puts("PASS: descriptor index preserves zero PC, mode/generation, prefix cutoff and conflicts");
}

static void descriptor_continuations(unsigned variant, FILE *json) {
    Fixture t = fixture(64);
    t.page_snapshot = variant != 11;
    const uint8_t left[] = {0xba, 17, 0, 0, 0}, join[] = {0xeb, 7};
    const uint8_t clobber[] = {0xb8, 0, 0x20, 0, 0}, read[] = {0x8b, 0x17};
    const uint8_t store[] = {0x89, 0x17}, cycle[] = {0xeb, 0xfe};
    const uint8_t nested[] = {0x75, 0x19}, inner[] = {0xba, 51, 0, 0, 0};
    InsnDescId alternate = 0;
    if (variant != 1 && variant != 2) {
        const uint8_t *code = variant == 5                    ? clobber
                              : variant == 6 || variant == 19 ? read
                              : variant == 7                  ? store
                              : variant == 9                  ? cycle
                              : variant == 8 || variant == 14 ? nested
                                                              : left;
        uint8_t size = variant == 6 || variant == 7 || variant == 8 || variant == 9 ||
                               variant == 14 || variant == 19
                           ? 2
                           : 5;
        uint8_t long_jump[] = {0xe9, 0, 0, 0, 0};
        uint32_t dest = variant == 10 ? 0x2000 : variant == 15 ? 0x1ffe : 0x1100;
        if (variant == 10 || variant == 13 || variant == 15) {
            uint32_t displacement = dest - 0x100a;
            memcpy(long_jump + 1, &displacement, 4);
            code = long_jump;
            size = 5;
        }
        alternate = decoded(&t, 0x1005, code, size, variant == 3 ? 2 : 1);
        decoded(&t, 0x100a, join, sizeof(join), 1);
        if (variant == 19) {
            const uint8_t nop[] = {0x90}, exit[] = {0xeb, 9};
            decoded(&t, 0x1007, nop, 1, 1);
            decoded(&t, 0x1008, exit, sizeof(exit), 1);
        }
        if (variant == 4)
            decoded(&t, 0x1005, clobber, sizeof(clobber), 1);
        if (variant == 8 || variant == 14) {
            decoded(&t, 0x1007, inner, sizeof(inner), 1);
            if (variant == 14) {
                const uint8_t back[] = {0xeb, 0xf1};
                decoded(&t, 0x1020, back, sizeof(back), 1);
            }
        }
        if (variant == 10 || variant == 15)
            decoded(&t, dest, left, sizeof(left), 1);
        if (variant == 13) {
            const uint8_t nop[] = {0x90};
            for (uint32_t pc = dest; pc < dest + 600; ++pc)
                decoded(&t, pc, nop, 1, 1);
        }
        if (variant == 16) {
            InsnDesc *bad = (InsnDesc *)trace_insn_desc_get(t.f.trace, alternate);
            ++bad->bytes_hash;
        }
    }
    InsnAux a = registers();
    const uint8_t load[] = {0xa1, 0, 0x30, 0, 0}, cmp[] = {0x83, 0xf9, 2};
    const uint8_t right[] = {0xba, 34, 0, 0, 0}, back[] = {0xeb, 0}, jump[] = {0xff, 0xe0};
    ff_read(&a, 0x3000, 0x2000, 4, true);
    a.mem_reads[0].taint = 15;
    emit(&t, 0xffb, load, sizeof(load), a, 0x1000, 1, 0);
    a = registers();
    a.reg_vals[DTA_REG_RAX] = 0x2000;
    a.reg_taint[DTA_REG_RAX] = 15;
    a.reg_vals[DTA_REG_RCX] = 1;
    emit(&t, 0x1000, cmp, sizeof(cmp), a, 0x1003, 1, 0);
    a.eflags_before = 0x297;
    uint64_t decision = branch(&t, 0x1003, a, 0x100c, 1, 0, 0);
    emit(&t, 0x100c, right, sizeof(right), a, 0x1011, 1, 0);
    a.reg_vals[DTA_REG_RDX] = 34;
    emit(&t, 0x1011, back, sizeof(back), a, 0x1013, 1, 0);
    uint64_t trigger = emit(&t, 0x1013, jump, sizeof(jump), a, 0x2000, 1, 0);
    if (variant == 2) {
        decoded(&t, 0x1005, left, sizeof(left), 1);
        decoded(&t, 0x100a, join, sizeof(join), 1);
    }
    if (variant == 12 || variant == 17) {
        TraceEntry *e = (TraceEntry *)trace_find_seq(t.f.trace, decision, NULL);
        e->code_page_generation = variant == 12 ? 2 : UINT32_MAX;
    }
    if (variant == 18) {
        TraceEntry *e = (TraceEntry *)trace_find_seq(t.f.trace, decision, NULL);
        e->code_history_start = decision;
    }
    const TraceEntry *out[32];
    dse_set_control_pruning(false);
    DseSliceResult full = slice(&t, trigger, out, 32);
    DseRelevanceContext c = context(&t);
    DseVerifyResult before = dse_verify_oep_candidate_with_relevance(
        t.f.trace, t.f.aux, trigger, DTA_REG_RAX, 0x2000, NULL, t.f.decoder, &c);
    dse_set_control_pruning(true);
    DseSliceResult reduced = slice(&t, trigger, out, 32);
    DseVerifyResult after = dse_verify_oep_candidate_with_relevance(
        t.f.trace, t.f.aux, trigger, DTA_REG_RAX, 0x2000, NULL, t.f.decoder, &c);
    CHECK(before.replay_valid && after.replay_valid);
    CHECK(before.verdict == after.verdict && before.candidate_query == after.candidate_query &&
          before.alternative_query == after.alternative_query);
    if (variant == 0 || variant == 14) {
        CHECK(reduced.control.cfg_pruned == 1 && reduced.len < full.len);
        CHECK(reduced.control.cfg_resolve_added >= 2);
        CHECK(after.path_constraints + 1 == before.path_constraints);
    } else {
        CHECK(!reduced.control.cfg_pruned && reduced.len == full.len);
        if (variant == 5)
            CHECK(reduced.control.cfg_effect_conflicts == 1);
        if (variant == 6 || variant == 19)
            CHECK(reduced.control.cfg_failures[DSE_CFG_FAILURE_MEMORY_READ] == 1);
        if (variant == 19)
            CHECK(reduced.control.cfg_resolve_added == 3);
        if (variant == 9)
            CHECK(reduced.control.cfg_failures[DSE_CFG_FAILURE_CYCLE] == 1);
        DseCfgResolveReason reason =
            variant == 2                                   ? DSE_CFG_RESOLVE_FUTURE
            : variant == 4                                 ? DSE_CFG_RESOLVE_AMBIGUOUS
            : variant == 10 || variant == 15               ? DSE_CFG_RESOLVE_PAGE_BOUNDARY
            : variant == 11 || variant == 17               ? DSE_CFG_RESOLVE_VERSION_MISSING
            : variant == 12                                ? DSE_CFG_RESOLVE_STALE
            : variant == 13                                ? DSE_CFG_RESOLVE_BUDGET
            : variant == 16                                ? DSE_CFG_RESOLVE_INVALID
            : variant == 18                                ? DSE_CFG_RESOLVE_HISTORY
            : variant == 1 || variant == 3 || variant == 8 ? DSE_CFG_RESOLVE_NOT_DECODED
                                                           : DSE_CFG_RESOLVE_NONE;
        if (reason)
            CHECK(reduced.control.cfg_resolve_failures[reason] > 0);
    }
    CHECK(reduced.control.cfg_nodes <= DCFG_REGION_MAX_NODES);
    DseControlStats saved = reduced.control;
    destroy(&t);
    if (json) {
        GString *s = g_string_new(NULL);
        dse_control_append_json(s, &saved);
        fprintf(json, "%s\n", s->str);
        g_string_free(s, true);
    }
    printf("PASS: descriptor continuation case %u, added=%u pruned=%u\n", variant,
           saved.cfg_resolve_added, saved.cfg_pruned);
}

int main(int argc, char **argv) {
    FILE *json = argc == 2 ? fopen(argv[1], "w") : NULL;
    CHECK(argc == 1 || json);
    dse_set_verbose_diagnostics(false);
    region_graphs();
    imul_regions();
    closed_diamond(0, false, false);
    closed_diamond(0, true, false);
    closed_diamond(0, false, true);
    closed_diamond(0, true, true);
    closed_diamond(1, false, false);
    closed_diamond(2, false, false);
    closed_diamond(3, false, false);
    closed_diamond(1, true, false);
    closed_diamond(2, true, false);
    closed_diamond(3, true, false);
    closed_diamond(4, false, false);
    closed_diamond(4, true, false);
    constant_choice(true, 0, false, json);
    constant_choice(false, 0, false, NULL);
    constant_choice(true, 0, true, json);
    diagnostic_targets(json);
    diagnostic_barriers(json);
    descriptor_index();
    for (unsigned variant = 0; variant < 20; ++variant)
        descriptor_continuations(variant, variant == 6 ? json : NULL);
    puts(
        "PASS: disjoint labels and clean register/memory targets retain the selector and its definitions; owned IR keeps the branch through SSA/DCE");
    for (unsigned fault = 1; fault <= 6; ++fault)
        constant_choice(true, fault, false, NULL);
    puts(
        "PASS: missing/conflicting events, changed generations and broken routes remain UNKNOWN and cannot authorize a proof");
    nested_and_occurrences();
    puts("PASS: nested constant selectors, repeated PCs/generations and foreign vCPU exclusion");
    boundaries_and_budgets();
    puts("PASS: evicted prefix, bounded scan, path and slice capacity limits remain explicit");
    if (json)
        CHECK(fclose(json) == 0);
    return 0;
}
