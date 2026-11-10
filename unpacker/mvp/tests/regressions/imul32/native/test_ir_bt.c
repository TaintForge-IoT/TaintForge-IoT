#include "ir_oep_test_helpers.h"
#include "ir_concolic.h"

static uint32_t rng = 0x42740001;
static uint32_t random32(void) {
    rng ^= rng << 13; rng ^= rng >> 17; rng ^= rng << 5; return rng;
}

static unsigned hardware_cf(uint32_t base, uint32_t index, unsigned zf, unsigned *after_zf) {
#if defined(__i386__) || defined(__x86_64__)
    unsigned char cf, observed_zf;
    uint32_t seed = !zf;
    __asm__ volatile("testl %[seed], %[seed]\n\tbtl %[index], %[base]\n\tsetc %[cf]\n\tsetz %[zf]"
        : [cf] "=qm" (cf), [zf] "=qm" (observed_zf)
        : [seed] "r" (seed), [base] "r" (base), [index] "r" (index) : "cc");
    *after_zf = observed_zf; return cf;
#else
    (void)base; (void)index; (void)zf; (void)after_zf;
    CHECK(!"Native BT oracle needs an x86 host"); return 0;
#endif
}

static unsigned concrete_cases(void) {
    const uint8_t code[] = {0x0f, 0xa3, 0xd8}; /* BT EAX,EBX, actual observed bytes. */
    AluProgram p = alu_program(code, sizeof(code), 0x8049349);
    CHECK(p.lift.status == IR_X86_LIFT_OK && !p.lift.gpr_writes && !p.lift.memory_count);
    CHECK(p.lift.flags_written == 0x37 && p.lift.flags_undefined == 0x36);
    for (unsigned i = 0; i < 8; ++i) {
        IrValueId value = ir_emit_value(p.module,p.block,(IrInstSpec){.op=IR_OP_READ_STATE,
            .type=ir_type_bv(32),.state=p.state.gpr[i]});
        CHECK(value && ir_module_add_output(p.module,value));
    }
    alu_end(&p);
    unsigned count = 0;
    for (unsigned i = 0; i < 4096; ++i) {
        uint32_t base = i < 2048 ? (1U << (i % 32)) : random32();
        uint32_t index = i < 2048 ? i / 32 : random32();
        static const uint32_t edges[] = {0,1,23,31,32,55,63,64,95,UINT32_MAX,0x80000000,0x80000017};
        if (i >= 2048 && i < 2048 + sizeof(edges)/sizeof(*edges))
            index = edges[i-2048];
        if (i == 4095) { base = 0x800013; index = 23; }
        AluInputs in = {.eflags = (i & 1 ? 0x40 : 0) | (i & 2 ? 0x400 : 0)};
        for (unsigned j = 0; j < 8; ++j) in.gpr[j] = random32();
        in.gpr[DTA_REG_RAX] = base; in.gpr[DTA_REG_RBX] = index;
        IrBindings bindings = {.user = &in, .read_bv = alu_binding};
        IrEval *eval = ir_eval_create(p.module, &bindings, NULL); CHECK(eval);
        CHECK(ir_eval_run(eval).status == IR_EVAL_FRAGMENT_END);
        unsigned zf, cf = hardware_cf(base, index, (in.eflags >> 6) & 1, &zf);
        CHECK(cf == ((base >> (index & 31U)) & 1U));
        CHECK(alu_state(eval, p.state.flags[X86_SPECIAL_STATE_CF], 1) == cf);
        CHECK(alu_state(eval, p.state.flags[X86_SPECIAL_STATE_ZF], 1) == zf);
        CHECK(alu_state(eval, p.state.flags[X86_SPECIAL_STATE_DF], 1) == ((in.eflags >> 10) & 1));
        for (unsigned j = 0; j < 8; ++j) CHECK(alu_state(eval, p.state.gpr[j], 32) == in.gpr[j]);
        for (unsigned j = 0; j < 7; ++j) if (p.lift.flags_undefined & (1U << j)) {
            IrBits b = ir_eval_state(eval, p.state.flags[j]).bits;
            CHECK(!ir_bits_complete(b, 1) && (b.reasons & IR_REASON_UNDEFINED));
        }
        ir_eval_destroy(eval); ++count;
    }
    ir_module_destroy(p.module);
    return count;
}

static unsigned immediate_cases(void) {
    static const unsigned gprs[] = {DTA_REG_RAX, DTA_REG_RCX, DTA_REG_RDX, DTA_REG_RBX,
        DTA_REG_RSP, DTA_REG_RBP, DTA_REG_RSI, DTA_REG_RDI};
    unsigned comparisons = 0;
    for (unsigned reg = 0; reg < 8; ++reg) {
        for (unsigned index = 0; index < 256; ++index) {
            const uint8_t code[] = {0x0f, 0xba, 0xe0 | reg, index};
            AluProgram p = alu_program(code, sizeof(code), 0x1000);
            CHECK(p.lift.status == IR_X86_LIFT_OK && !p.lift.gpr_writes && !p.lift.memory_count);
            CHECK(p.lift.flags_written == 0x37 && p.lift.flags_undefined == 0x36);
            alu_end(&p);
            uint32_t mask = UINT32_C(1) << (index & 31U);
            for (unsigned phase = 0; phase < 3; ++phase) {
                if (phase == 1) CHECK(ir_trace_ssa(p.module, NULL).analysis.status == IR_OK);
                if (phase == 2) CHECK(ir_optimize(p.module, NULL).status == IR_OK);
                for (unsigned i = 0; i < 8; ++i) {
                    AluInputs in = {.eflags = (i & 2 ? 0x40 : 0) | (i & 4 ? 0x400 : 0)};
                    uint32_t base = random32() & ~mask;
                    if (i & 1) base |= mask;
                    in.gpr[gprs[reg]] = base;
                    IrBindings bindings = {.user = &in, .read_bv = alu_binding};
                    IrEval *eval = ir_eval_create(p.module, &bindings, NULL);
                    CHECK(eval && ir_eval_run(eval).status == IR_EVAL_FRAGMENT_END);
                    unsigned zf;
                    unsigned cf = hardware_cf(base, index, (i >> 1) & 1U, &zf);
                    CHECK(alu_state(eval, p.state.flags[X86_SPECIAL_STATE_CF], 1) == cf);
                    CHECK(alu_state(eval, p.state.flags[X86_SPECIAL_STATE_ZF], 1) == zf);
                    CHECK(alu_state(eval, p.state.flags[X86_SPECIAL_STATE_DF], 1) == ((i >> 2) & 1U));
                    ir_eval_destroy(eval);
                    ++comparisons;
                }
            }
            ir_module_destroy(p.module);
        }
    }
    return comparisons;
}

static void aliases_and_unknowns(void) {
    const uint8_t alias[] = {0x0f, 0xa3, 0xc0}; /* BT EAX,EAX */
    AluProgram p = alu_program(alias, sizeof(alias), 0x1000); alu_end(&p);
    for (unsigned i = 0; i < 64; ++i) {
        AluInputs in = {.gpr = {i}};
        IrBindings b = {.user = &in, .read_bv = alu_binding};
        IrEval *e = ir_eval_create(p.module, &b, NULL); CHECK(e);
        CHECK(ir_eval_run(e).status == IR_EVAL_FRAGMENT_END);
        CHECK(alu_state(e, p.state.flags[0], 1) == ((i >> (i & 31)) & 1));
        CHECK(alu_state(e, p.state.gpr[0], 32) == i); ir_eval_destroy(e);
    }
    ir_module_destroy(p.module);
    const uint8_t code[] = {0x0f, 0xa3, 0xd8};
    for (unsigned which = 0; which < 3; ++which) {
        p = alu_program(code, sizeof(code), 0x1000); alu_end(&p);
        AluInputs in = {.gpr = {0x800013, 0, 0, 23},
            .unknown_gpr = which < 2 ? (1U << (which ? DTA_REG_RBX : DTA_REG_RAX)) : 0,
            .unknown_flags = which == 2 ? (1U << X86_SPECIAL_STATE_ZF) : 0};
        IrBindings b = {.user = &in, .read_bv = alu_binding};
        IrEval *e = ir_eval_create(p.module, &b, NULL); CHECK(e);
        (void)ir_eval_run(e);
        unsigned flag = which == 2 ? X86_SPECIAL_STATE_ZF : X86_SPECIAL_STATE_CF;
        CHECK(!ir_bits_complete(ir_eval_state(e, p.state.flags[flag]).bits, 1));
        ir_eval_destroy(e); ir_module_destroy(p.module);
    }
}

static void unsupported_forms(void) {
    const uint8_t code[][6] = {
        {0x66,0x0f,0xa3,0xd8}, {0x0f,0xa3,0x18}, {0x0f,0xba,0x20,0x17},
        {0x66,0x0f,0xba,0xe0,0x17}, {0xf0,0x0f,0xba,0xe0,0x00},
        {0xf0,0x0f,0xa3,0xd8}, {0xf3,0x0f,0xa3,0xd8}, {0xf2,0x0f,0xa3,0xd8},
        {0x0f,0xab,0xd8}, {0x0f,0xb3,0xd8}, {0x0f,0xbb,0xd8}};
    const unsigned sizes[] = {4,3,4,5,5,4,4,4,3,3,3};
    for (unsigned i = 0; i < sizeof(sizes)/sizeof(*sizes); ++i) {
        /* Invalid LOCK/REP encodings can be rejected by Capstone before an
         * InsnDesc exists. Construct the valid BT descriptor and replace its
         * bytes for those cases so the frontend itself still sees the input. */
        FrontFixture f = ff_new(8); InsnAux a = of_registers();
        const uint8_t valid[] = {0x0f,0xa3,0xd8};
        uint64_t seq = ff_emit(&f,0x1000,valid,sizeof(valid),9,0,&a);
        const TraceEntry *e = trace_find_seq(f.trace,seq,NULL);
        InsnDesc d = *trace_insn_desc_get(f.trace,e->insn_desc_id);
        memcpy(d.bytes,code[i],sizes[i]); d.size = sizes[i];
        d.bytes_hash = trace_instruction_bytes_hash(d.bytes,d.size);
        cs_insn *decoded = NULL;
        size_t n = cs_disasm(f.decoder,d.bytes,d.size,d.pc,1,&decoded);
        if(n) { d.native_insn_id = decoded->id; cs_free(decoded,n); }
        IrModule *m = ir_module_create(NULL); CHECK(m);
        IrX86Frontend *front = ir_x86_frontend_create(m,NULL); CHECK(front);
        IrBlockId block = ir_block_add(m);
        IrOrigin o = {.has_trace_identity=true,.seq_id=seq,.pc=d.pc,
            .descriptor_id=d.desc_id,.code_generation=d.code_generation};
        uint32_t before = ir_module_value_count(m);
        IrX86LiftResult r = ir_x86_lift(front,block,&d,o);
        CHECK(r.status != IR_X86_LIFT_OK && before == ir_module_value_count(m));
        ir_x86_frontend_destroy(front); ir_module_destroy(m); ff_free(&f);
    }
}

static ReplayInput *concolic_fixture(bool unsupported, bool bad_cf, bool immediate) {
    FrontFixture f = ff_new(16); InsnAux a = of_registers();
    const uint8_t nop[] = {0x90}, load[] = {0x0f,0xb6,0x1d,0x00,0x30,0x00,0x00},
        load_base[] = {0x0f,0xb6,0x05,0x00,0x30,0x00,0x00},
        bt[] = {0x0f,0xa3,0xd8}, bt16[] = {0x66,0x0f,0xa3,0xd8},
        bt_imm[] = {0x0f,0xba,0xe0,0x20}, jb[] = {0x72,0x10};
    a.reg_vals[DTA_REG_RAX] = 0x800013;
    uint64_t seqs[3];
    (void)of_emit(&f,0x1000,nop,1,a,0x1001); /* Simulated completed read boundary. */
    InsnAux read = a; ff_read(&read,0x3000,23,1,true);
    read.mem_reads[0].taint = read.mem_reads[0].effective_taint = 1;
    seqs[0] = of_emit(&f,0x1001,immediate ? load_base : load,sizeof(load),read,0x1008);
    a.reg_vals[immediate ? DTA_REG_RAX : DTA_REG_RBX] = 23;
    unsigned bytes = immediate ? sizeof(bt_imm) : unsupported ? sizeof(bt16) : sizeof(bt);
    const uint8_t *test = immediate ? bt_imm : unsupported ? bt16 : bt;
    seqs[1] = of_emit(&f,0x1008,test,bytes,a,0x1008+bytes);
    a.eflags_before = (a.eflags_before & ~1U) | !bad_cf;
    seqs[2] = ff_emit(&f,0x1008+bytes,jb,sizeof(jb),9,0,&a);
    uint32_t next = 0x1008+bytes+2+0x10;
    ff_finish_branch(&f,seqs[2],next,true);
    uint64_t trigger = of_emit(&f,next,nop,1,a,next+1);
    ReplayInput *out = ff_capture(&f,seqs,3,trigger); ff_free(&f); return out;
}

static void concolic(void) {
    IrConcolicRead source = {.read_seq=1,.address=0x3000,.read_size=1,.count=1,
        .bytes={23},.completed_read=true,.flags_verified=true};
    for (unsigned mode = 0; mode < 5; ++mode) {
        bool immediate = mode >= 3;
        ReplayInput *input = concolic_fixture(mode == 1, mode == 2 || mode == 4, immediate);
        IrConcolicReadResult r = ir_concolic_read(input,&source,false,NULL);
        CHECK(r.replay_build_attempted);
        if (mode==1) {
            CHECK(!strcmp(r.status,"UNKNOWN") && !strcmp(r.reason,"replay_incomplete"));
            CHECK(r.replay_build_status==IR_REPLAY_UNKNOWN && r.replay_lifted_steps==1);
            CHECK(r.replay_build_issues & IR_REPLAY_UNSUPPORTED);
            CHECK(r.replay_stopped_origin.seq_id==3 && r.replay_stopped_origin.pc==0x1008);
        } else if (mode==2 || mode==4) {
            CHECK(!strcmp(r.status,"UNKNOWN") && !strcmp(r.reason,"baseline_observations"));
        } else {
            if(strcmp(r.status,"OBSERVED")) fprintf(stderr,"observe: %s %s issues=%x steps=%u\n",
                r.status,r.reason,r.replay_build_issues,r.replay_lifted_steps);
            CHECK(!strcmp(r.status,"OBSERVED") && r.replay_build_status==IR_REPLAY_READY);
            CHECK(r.replay_lifted_steps==3 && !r.replay_build_issues);
            r = ir_concolic_read(input,&source,true,NULL);
            if(strcmp(r.status,"BOUNDARY_WITNESS")) fprintf(stderr,"solve: %s %s\n",r.status,r.reason);
            CHECK(!strcmp(r.status,"BOUNDARY_WITNESS") && r.inputs[0] && r.candidates[0]!=23);
            unsigned cf = immediate ? r.candidates[0] & 1U : (0x800013U >> (r.candidates[0] & 31U)) & 1U;
            CHECK(!cf);
            CHECK(r.replay_build_attempted && r.replay_lifted_steps==3);
        }
        replay_input_destroy(input);
    }
    IrConcolicReadResult r = ir_concolic_read(NULL,NULL,false,NULL);
    CHECK(!r.replay_build_attempted);
}

int main(void) {
    unsigned cases = concrete_cases(); aliases_and_unknowns(); unsupported_forms(); concolic();
    printf("PASS BT_IMM32: hardware comparisons=%u; replay and SMT witness\n", immediate_cases());
    printf("PASS BT: %u hardware comparisons; aliases, UNKNOWN flags, unsupported forms, replay, SMT witness and stop diagnostics\n",cases);
    return 0;
}
