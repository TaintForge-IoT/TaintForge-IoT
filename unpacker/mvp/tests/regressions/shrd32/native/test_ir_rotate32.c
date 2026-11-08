#include "ir_oep_test_helpers.h"
#include "ir_concolic.h"
#include "ir_smt_test_helpers.h"

static uint32_t rng = 0x70170132;
static uint32_t random32(void) {rng ^= rng << 13; rng ^= rng >> 17; rng ^= rng << 5; return rng;}
static uint32_t reference(uint32_t value, unsigned count, bool right) {
    for (unsigned i = 0; i < (count & 31); ++i)
        value = right ? (value >> 1) | ((value & 1U) << 31)
                      : (value << 1) | (value >> 31);
    return value;
}
static uint32_t hardware(uint32_t value, unsigned count, bool right, uint32_t flags, uint64_t *after) {
    uint64_t saved, observed, wide = flags;
#define ROTATE(OP) __asm__ volatile("pushfq\n\tpopq %[saved]\n\tpushq %[initial]\n\tpopfq\n\t" \
    OP "l %%cl,%[value]\n\tpushfq\n\tpopq %[after]\n\tpushq %[saved]\n\tpopfq" \
    : [value]"+&r"(value), [saved]"=&r"(saved), [after]"=&r"(observed) \
    : "c"(count), [initial]"r"(wide) : "cc", "memory")
    if (right) {ROTATE("ror");} else {ROTATE("rol");}
#undef ROTATE
    *after = observed; return value;
}
static IrValueId state(AluProgram *p, IrStateId id, unsigned width) {
    return ir_emit_value(p->module, p->block, (IrInstSpec){.op=IR_OP_READ_STATE, .type=ir_type_bv(width), .state=id});
}
static void keep(AluProgram *p) {
    for (unsigned i=0; i<8; ++i) CHECK(ir_module_add_output(p->module, state(p, p->state.gpr[i], 32)));
}
static unsigned concrete(void) {
    unsigned cases=0;
    for (unsigned right=0; right<2; ++right) for (unsigned dst=0; dst<8; ++dst) {
        uint8_t code[]={0xd3, (uint8_t)((right?0xc8:0xc0)+dst)};
        AluProgram p=alu_program(code, 2, 0x1000); keep(&p); alu_end(&p);
        CHECK(p.lift.status==IR_X86_LIFT_OK && p.lift.gpr_writes==(1U<<dst) && !p.lift.memory_count);
        CHECK(p.lift.flags_written==0x21 && !p.lift.flags_undefined && p.lift.flags_preserved_when && p.lift.flags_defined[5]);
        for (unsigned phase=0; phase<3; ++phase) {
            if (phase==1) CHECK(ir_trace_ssa(p.module, NULL).analysis.status==IR_OK);
            if (phase==2) CHECK(ir_optimize(p.module, NULL).status==IR_OK);
            for (unsigned i=0; i<1024; ++i) {
                AluInputs in={.eflags=(i>>8)&1?0xcd7:0x202};
                for (unsigned r=0; r<8; ++r) in.gpr[r]=random32();
                in.gpr[dst]=i%8==0?0:i%8==1?UINT32_MAX:i%8==2?0x80000001:random32();
                in.gpr[1]=(in.gpr[1]&0xffffff00U)|(i&255);
                unsigned count=in.gpr[1]&31; uint64_t flags;
                uint32_t expected=hardware(in.gpr[dst], in.gpr[1], right, in.eflags, &flags);
                CHECK(expected==reference(in.gpr[dst], in.gpr[1], right));
                IrBindings bindings={.user=&in, .read_bv=alu_binding};
                IrEval *e=ir_eval_create(p.module, &bindings, NULL); CHECK(e);
                CHECK(ir_eval_run(e).status==(count>1?IR_EVAL_UNKNOWN:IR_EVAL_FRAGMENT_END));
                for (unsigned r=0; r<8; ++r) CHECK(alu_state(e, p.state.gpr[r], 32)==(r==dst?expected:in.gpr[r]));
                for (unsigned f=0; f<7; ++f) {
                    IrBits bits=ir_eval_state(e, p.state.flags[f]).bits;
                    if (f==5 && count>1) CHECK(!bits.known_mask && (bits.reasons&IR_REASON_UNDEFINED));
                    else CHECK(ir_bits_complete(bits,1) && bits.value==((flags>>alu_flag_bits[f])&1));
                    if (f!=0 && f!=5) CHECK(((flags>>alu_flag_bits[f])&1)==((in.eflags>>alu_flag_bits[f])&1));
                }
                ir_eval_destroy(e); ++cases;
            }
        }
        ir_module_destroy(p.module);
    }
    return cases;
}
static void negatives_and_unknowns(void) {
    const uint8_t codes[][4]={{0xd2,0xc0},{0xd2,0xc8},{0x66,0xd3,0xc0},{0xd3,0x00},{0xd3,0x08},
        {0xf2,0xd3,0xc0},{0xf3,0xd3,0xc8},{0x67,0xd3,0xc0},{0x2e,0xd3,0xc8},{0xf0,0xd3,0xc0},
        {0xd3,0xd0},{0xd3,0xd8},{0xd1,0xc0},{0xd1,0xc8},{0xc1,0xc0,7},{0xc1,0xc8,7}};
    const unsigned sizes[]={2,2,3,2,2,3,3,3,3,3,2,2,2,2,3,3};
    for (unsigned i=0; i<sizeof(sizes)/sizeof(*sizes); ++i) {
        FrontFixture f=ff_new(8); InsnAux a=ff_registers(); const uint8_t valid[]={0xd3,0xc0};
        uint64_t seq=ff_emit(&f, 0x1000, valid, 2, 9, 0, &a);
        const TraceEntry *entry=trace_find_seq(f.trace,seq,NULL); InsnDesc desc=*trace_insn_desc_get(f.trace,entry->insn_desc_id);
        desc.size=sizes[i]; memcpy(desc.bytes,codes[i],desc.size); desc.bytes_hash=trace_instruction_bytes_hash(desc.bytes,desc.size);
        cs_insn *decoded=NULL; size_t n=cs_disasm(f.decoder,desc.bytes,desc.size,desc.pc,1,&decoded);
        bool full=n && decoded->size==desc.size; if (full) desc.native_insn_id=decoded->id; if (n) cs_free(decoded,n);
        IrModule *m=ir_module_create(NULL); CHECK(m); IrBlockId b=ir_block_add(m);
        IrX86Frontend *front=ir_x86_frontend_create(m,NULL); CHECK(front);
        IrX86LiftResult lifted=ir_x86_lift(front,b,&desc,(IrOrigin){.has_trace_identity=true,.seq_id=seq,
            .descriptor_id=desc.desc_id,.pc=desc.pc,.code_generation=9});
        CHECK(lifted.status==(full?IR_X86_LIFT_UNSUPPORTED:IR_X86_LIFT_IDENTITY) && ir_module_inst_count(m)==0);
        ir_x86_frontend_destroy(front); ir_module_destroy(m); ff_free(&f);
    }
    const uint8_t code[]={0xd3,0xc0}; AluProgram p=alu_program(code,2,0x1000); keep(&p); alu_end(&p);
    for (unsigned unknown=0; unknown<3; ++unknown) for (unsigned count=0; count<3; ++count) {
        AluInputs in={.eflags=0x202, .unknown_gpr=unknown==0?1:unknown==1?2:0, .unknown_flags=unknown==2?0x7f:0};
        in.gpr[0]=0x12345678; in.gpr[1]=count;
        IrBindings bindings={.user=&in,.read_bv=alu_binding}; IrEval *e=ir_eval_create(p.module,&bindings,NULL); CHECK(e);
        CHECK(ir_eval_run(e).status==IR_EVAL_UNKNOWN);
        if (unknown<2) CHECK(!ir_bits_complete(ir_eval_state(e,p.state.gpr[0]).bits,32));
        if (unknown==2) {
            CHECK(alu_state(e,p.state.gpr[0],32)==reference(in.gpr[0],count,false));
            if (count) CHECK(alu_state(e,p.state.flags[0],1)==(reference(in.gpr[0],count,false)&1));
            for (unsigned f=1;f<5;++f) CHECK(!ir_eval_state(e,p.state.flags[f]).bits.known_mask);
        }
        ir_eval_destroy(e);
    }
    ir_module_destroy(p.module);
}
static unsigned symbolic(void) {
    unsigned queries=0;
    for (unsigned right=0; right<2; ++right) {
        FrontFixture f=ff_new(8); InsnAux a=of_registers(); uint8_t code[]={0xd3,(uint8_t)(right?0xc8:0xc0)};
        uint64_t seq=ff_emit(&f,0x1000,code,2,9,0,&a); const TraceEntry *entry=trace_find_seq(f.trace,seq,NULL);
        const InsnDesc *desc=trace_insn_desc_get(f.trace,entry->insn_desc_id);
        AluProgram p={.module=ir_module_create(NULL)}; CHECK(p.module);
        IrX86Frontend *front=ir_x86_frontend_create(p.module,NULL); CHECK(front);
        p.state=*ir_x86_frontend_state(front); p.block=ir_block_add(p.module);
        IrValueId source=ir_emit_value(p.module,p.block,(IrInstSpec){.op=IR_OP_INPUT,.type=ir_type_bv(32),.immediate=0x7010});
        IrValueId count=ir_emit_value(p.module,p.block,(IrInstSpec){.op=IR_OP_INPUT,.type=ir_type_bv(32),.immediate=0x7011});
        CHECK(ir_emit_effect(p.module,p.block,(IrInstSpec){.op=IR_OP_WRITE_STATE,.type=ir_type_void(),.state=p.state.gpr[0],.args={source}}));
        CHECK(ir_emit_effect(p.module,p.block,(IrInstSpec){.op=IR_OP_WRITE_STATE,.type=ir_type_void(),.state=p.state.gpr[1],.args={count}}));
        for (unsigned i=0;i<7;++i) {
            IrValueId value=ir_emit_value(p.module,p.block,(IrInstSpec){.op=IR_OP_CONST,.type=ir_type_bv(1),.immediate=1});
            CHECK(ir_emit_effect(p.module,p.block,(IrInstSpec){.op=IR_OP_WRITE_STATE,.type=ir_type_void(),.state=p.state.flags[i],.args={value}}));
        }
        p.lift=ir_x86_lift(front,p.block,desc,(IrOrigin){.has_trace_identity=true,.seq_id=seq,.descriptor_id=desc->desc_id,.pc=desc->pc,.code_generation=9});
        CHECK(p.lift.status==IR_X86_LIFT_OK); ir_x86_frontend_destroy(front); ff_free(&f);
        IrValueId result=state(&p,p.state.gpr[0],32), cf=state(&p,p.state.flags[0],1), of=state(&p,p.state.flags[5],1);
        CHECK(ir_module_add_output(p.module,result) && ir_module_add_output(p.module,cf) && ir_module_add_output(p.module,of)); alu_end(&p);
        for (unsigned phase=0;phase<3;++phase) {
            if (phase==1) CHECK(ir_trace_ssa(p.module,NULL).analysis.status==IR_OK);
            if (phase==2) CHECK(ir_optimize(p.module,NULL).status==IR_OK);
            IrSmtParameter parameters[2]={{.key=0x7010,.width=32,.symbolic=true,.observed=ir_bits_known(0x12345678,32)},
                                        {.key=0x7011,.width=32,.symbolic=true,.observed=ir_bits_known(3,32)}};
            IrSmtOptions options=ir_smt_default_options(); options.parameters=parameters; options.parameter_count=2;
            IrSmtInfo info; IrSmt *s=ir_smt_build(p.module,NULL,&options,&info); CHECK(s);
            for (unsigned k=0;k<256;++k) {
                uint32_t value=0x81234567, expected=reference(value,k,right), masked=k&31;
                IrSmtConstraint c[3]={{source,value,UINT32_MAX},{count,0x76540000U|k,UINT32_MAX},{result,expected,UINT32_MAX}};
                IrSmtAnswer answer=ir_smt_query(s,c,3,NULL,0,NULL); sm_status(&answer,IR_SMT_SAT); ir_smt_answer_destroy(&answer); ++queries;
                c[2].expected^=1; answer=ir_smt_query(s,c,3,NULL,0,NULL); sm_status(&answer,IR_SMT_UNSAT); ir_smt_answer_destroy(&answer); ++queries;
                c[2]=(IrSmtConstraint){cf,masked?(right?expected>>31:expected&1):1,1};
                answer=ir_smt_query(s,c,3,NULL,0,NULL); sm_status(&answer,IR_SMT_SAT); ir_smt_answer_destroy(&answer); ++queries;
                c[2].expected^=1; answer=ir_smt_query(s,c,3,NULL,0,NULL); sm_status(&answer,IR_SMT_UNSAT); ir_smt_answer_destroy(&answer); ++queries;
                unsigned overflow=masked?((expected>>31)^(right?(expected>>30)&1:expected&1)):1;
                c[2]=(IrSmtConstraint){of,overflow,1};
                answer=ir_smt_query(s,c,3,NULL,0,NULL); sm_status(&answer,masked>1?IR_SMT_UNKNOWN:IR_SMT_SAT); ir_smt_answer_destroy(&answer); ++queries;
                if (masked<=1) {
                    c[2].expected^=1; answer=ir_smt_query(s,c,3,NULL,0,NULL); sm_status(&answer,IR_SMT_UNSAT); ir_smt_answer_destroy(&answer); ++queries;
                }
            }
            for (unsigned k=0;k<32;++k) {
                uint32_t desired=reference(1,k,right);
                IrSmtConstraint free[2]={{source,1,UINT32_MAX},{result,desired,UINT32_MAX}};
                IrSmtAnswer answer=ir_smt_query(s,free,2,NULL,0,NULL); sm_status(&answer,IR_SMT_SAT);
                CHECK(answer.parameter_count==2); uint32_t chosen=0; bool found=false;
                for (size_t i=0;i<answer.parameter_count;++i) if (answer.parameters[i].key==0x7011) {chosen=answer.parameters[i].value;found=true;}
                CHECK(found && (chosen&31)==k && reference(1,chosen,right)==desired); ir_smt_answer_destroy(&answer); ++queries;
            }
            IrSmtConstraint free={result,0xdeadbeef,UINT32_MAX};
            IrSmtAnswer answer=ir_smt_query(s,&free,1,NULL,0,NULL); sm_status(&answer,IR_SMT_SAT);
            CHECK(answer.parameter_count==2); uint32_t value=0, chosen=0;
            for (size_t i=0;i<answer.parameter_count;++i) {
                if (answer.parameters[i].key==0x7010) value=answer.parameters[i].value;
                if (answer.parameters[i].key==0x7011) chosen=answer.parameters[i].value;
            }
            CHECK(reference(value,chosen,right)==0xdeadbeef); ir_smt_answer_destroy(&answer); ++queries;
            ir_smt_destroy(s);
        }
        ir_module_destroy(p.module);
    }
    return queries;
}
static ReplayInput *fixture(bool right,unsigned mode) {
    FrontFixture f=ff_new(32); InsnAux a=of_registers(); uint64_t selected[8]; unsigned n=0;
    uint32_t value=mode>=2?(right?0x80000000:0x40000000):0x12345678;
    unsigned count=mode==0?3:mode==1?32:mode==2?1:2;
    const uint8_t nop[]={0x90}, load[]={0xa1,0x00,0x30,0x00,0x00}, cl[]={0x0f,0xb6,0x0d,0x04,0x30,0x00,0x00};
    (void)of_emit(&f,0x1000,nop,1,a,0x1001); InsnAux read=a; of_read(&read,0x3000,value);
    selected[n++]=of_emit(&f,0x1001,load,5,read,0x1006); a.reg_vals[0]=value;
    read=a; ff_read(&read,0x3004,count,1,true); read.mem_read_taint=read.mem_read_effective_taint=1;
    read.mem_reads[0].taint=read.mem_reads[0].effective_taint=1;
    selected[n++]=of_emit(&f,0x1006,cl,7,read,0x100d); a.reg_vals[1]=count;
    uint8_t code[]={0xd3,(uint8_t)(right?0xc8:0xc0)};
    selected[n++]=of_emit(&f,0x100d,code,2,a,0x100f); uint64_t flags;
    a.reg_vals[0]=hardware(value,count,right,a.eflags_before,&flags); a.eflags_before=flags; uint32_t pc=0x100f;
    if (mode<2) {
        uint32_t expected=a.reg_vals[0]; uint8_t cmp[]={0x3d,expected,expected>>8,expected>>16,expected>>24};
        selected[n++]=of_emit(&f,pc,cmp,5,a,pc+5); a=alu_after(a,ALU_CMP,32,expected,expected,0,0,false); pc+=5;
    }
    uint8_t branch[]={mode<2?0x75:0x70,0x10}; bool taken=mode<2?false:((a.eflags_before>>11)&1);
    selected[n++]=ff_emit(&f,pc,branch,2,9,0,&a); uint32_t next=pc+(taken?18:2);
    ff_finish_branch(&f,selected[n-1],next,taken); uint64_t trigger=of_emit(&f,next,nop,1,a,next+1);
    ReplayInput *input=ff_capture(&f,selected,n,trigger); ff_free(&f); return input;
}
static void concolic(void) {
    for (unsigned right=0;right<2;++right) for (unsigned mode=0;mode<4;++mode) {
        ReplayInput *input=fixture(right,mode);
        uint32_t value=mode>=2?(right?0x80000000:0x40000000):0x12345678;
        unsigned count=mode==0?3:mode==1?32:mode==2?1:2;
        IrConcolicRead source={.read_seq=1,.address=0x3000,.read_size=5,.count=5,.offsets={0,1,2,3,4},
            .bytes={value,value>>8,value>>16,value>>24,count},.completed_read=true,.flags_verified=true};
        IrConcolicReadResult r=ir_concolic_read(input,&source,false,NULL);
        if (strcmp(r.status,mode==3?"UNKNOWN":"OBSERVED")) fprintf(stderr,"rotate observe right=%u mode=%u: %s %s\n",right,mode,r.status,r.reason);
        CHECK(!strcmp(r.status,mode==3?"UNKNOWN":"OBSERVED"));
        r=ir_concolic_read(input,&source,true,NULL);
        if (strcmp(r.status,mode==3?"UNKNOWN":"BOUNDARY_WITNESS")) fprintf(stderr,"rotate solve right=%u mode=%u: %s %s\n",right,mode,r.status,r.reason);
        CHECK(!strcmp(r.status,mode==3?"UNKNOWN":"BOUNDARY_WITNESS"));
        if (mode<3) {
            uint32_t candidate=0; for (unsigned i=0;i<4;++i) candidate|=(uint32_t)r.candidates[i]<<(8*i);
            if (mode<2) CHECK(reference(candidate,r.candidates[4],right)!=reference(value,count,right));
            else {
                unsigned masked=r.candidates[4]&31; CHECK(masked<=1);
                uint32_t rotated=reference(candidate,masked,right);
                unsigned overflow=masked?((rotated>>31)^(right?(rotated>>30)&1:rotated&1)):0;
                CHECK(!overflow);
            }
        }
        replay_input_destroy(input);
    }
}
int main(void) {
    unsigned cases=concrete(); negatives_and_unknowns(); unsigned queries=symbolic(); concolic();
    printf("PASS ROTATE32: hardware=%u register encodings=16 raw CL counts=256 SMT queries=%u; IR/SSA/optimization/ECX-alias/CF/OF/preserved flags/free symbolic count/concolic PASS; OF-count>1 UNKNOWN\n",cases,queries);
    return 0;
}
