#include "ir_oep_test_helpers.h"
#include "ir_concolic.h"
#include "ir_smt_test_helpers.h"

static uint32_t rng=0xb5f0b5a;
static uint32_t random32(void) {rng^=rng<<13;rng^=rng>>17;rng^=rng<<5;return rng;}
static unsigned reference(uint32_t source,bool reverse) {
    CHECK(source);unsigned result=0;
    for(unsigned bit=0;bit<32;++bit) if(source&(1U<<bit)) {result=bit;if(!reverse) break;}
    return result;
}
static uint32_t hardware(uint32_t source,bool reverse,uint32_t initial,uint32_t flags,uint64_t *after) {
    uint64_t saved,observed,wide=flags;uint32_t result=initial;
#define SCAN(OP) __asm__ volatile("pushfq\n\tpopq %[saved]\n\tpushq %[initial]\n\tpopfq\n\t" \
    OP "l %[source],%[result]\n\tpushfq\n\tpopq %[after]\n\tpushq %[saved]\n\tpopfq" \
    : [result]"+&r"(result),[saved]"=&r"(saved),[after]"=&r"(observed) \
    : [source]"r"(source),[initial]"r"(wide) : "cc","memory")
    if(reverse) {SCAN("bsr");} else {SCAN("bsf");}
#undef SCAN
    *after=observed;return result;
}
static IrValueId state(AluProgram *p,IrStateId id,unsigned width) {
    return ir_emit_value(p->module,p->block,(IrInstSpec){.op=IR_OP_READ_STATE,.type=ir_type_bv(width),.state=id});
}
static void keep(AluProgram *p) {
    for(unsigned i=0;i<8;++i) CHECK(ir_module_add_output(p->module,state(p,p->state.gpr[i],32)));
}
static void concrete(unsigned *nonzero,unsigned *zero) {
    for(unsigned reverse=0;reverse<2;++reverse) for(unsigned dst=0;dst<8;++dst) for(unsigned src=0;src<8;++src) {
        uint8_t code[]={0x0f,(uint8_t)(reverse?0xbd:0xbc),(uint8_t)(0xc0+dst*8+src)};
        AluProgram p=alu_program(code,3,0x80490c0);keep(&p);alu_end(&p);
        CHECK(p.lift.status==IR_X86_LIFT_OK&&p.lift.gpr_writes==(1U<<dst)&&!p.lift.memory_count);
        CHECK(p.lift.flags_written==0x3f&&p.lift.flags_undefined==0x37);
        for(unsigned phase=0;phase<3;++phase) {
            if(phase==1) CHECK(ir_trace_ssa(p.module,NULL).analysis.status==IR_OK);
            if(phase==2) CHECK(ir_optimize(p.module,NULL).status==IR_OK);
            for(unsigned i=0;i<256;++i) {
                AluInputs input={.eflags=(i+dst+src+phase)&1?0xcd7:0x202};for(unsigned j=0;j<8;++j) input.gpr[j]=random32();
                uint32_t value=i%64<32?1U<<(i%64):i%64==32?0:i%64==33?UINT32_MAX:random32();
                input.gpr[src]=value;uint64_t flags;
                uint32_t actual=hardware(value,reverse,input.gpr[dst],input.eflags,&flags);
                CHECK(((flags>>6)&1)==!value&&((flags>>10)&1)==((input.eflags>>10)&1));
                IrBindings bindings={.user=&input,.read_bv=alu_binding};IrEval *e=ir_eval_create(p.module,&bindings,NULL);CHECK(e);
                IrEvalResult evaluated=ir_eval_run(e);
                if(evaluated.status!=(value?IR_EVAL_FRAGMENT_END:IR_EVAL_UNKNOWN))
                    fprintf(stderr,"concrete reverse=%u dst=%u src=%u phase=%u i=%u value=%x status=%u reasons=%x\n",reverse,dst,src,phase,i,value,evaluated.status,evaluated.reasons);
                CHECK(evaluated.status==(value?IR_EVAL_FRAGMENT_END:IR_EVAL_UNKNOWN));
                for(unsigned j=0;j<8;++j) if(j!=dst) CHECK(alu_state(e,p.state.gpr[j],32)==input.gpr[j]);
                IrBits result=ir_eval_state(e,p.state.gpr[dst]).bits;
                if(value) {CHECK(actual==reference(value,reverse));CHECK(ir_bits_complete(result,32)&&result.value==actual);++*nonzero;}
                else {CHECK(!result.known_mask&&(result.reasons&IR_REASON_UNDEFINED));++*zero;}
                CHECK(alu_state(e,p.state.flags[3],1)==!value);
                CHECK(alu_state(e,p.state.flags[6],1)==((input.eflags>>10)&1));
                for(unsigned j=0;j<6;++j) if(j!=3) CHECK(!ir_eval_state(e,p.state.flags[j]).bits.known_mask);
                ir_eval_destroy(e);
            }
        }
        ir_module_destroy(p.module);
    }
}
static void negatives_and_unknowns(void) {
    const uint8_t codes[][5]={{0x66,0x0f,0xbc,0xc0},{0x66,0x0f,0xbd,0xc0},
        {0x0f,0xbc,0x01},{0x0f,0xbd,0x01},{0xf2,0x0f,0xbc,0xc0},{0xf2,0x0f,0xbd,0xc0},
        {0xf3,0x0f,0xbc,0xc0},{0xf3,0x0f,0xbd,0xc0},{0x67,0x0f,0xbc,0xc0},{0x2e,0x0f,0xbd,0xc0}};
    const unsigned sizes[]={4,4,3,3,4,4,4,4,4,4};
    for(unsigned i=0;i<sizeof(sizes)/sizeof(*sizes);++i) {
        FrontFixture f=ff_new(8);InsnAux a=ff_registers();const uint8_t valid[]={0x0f,0xbc,0xc0};
        uint64_t seq=ff_emit(&f,0x1000,valid,3,9,0,&a);const TraceEntry *entry=trace_find_seq(f.trace,seq,NULL);
        InsnDesc desc=*trace_insn_desc_get(f.trace,entry->insn_desc_id);
        desc.size=sizes[i];memcpy(desc.bytes,codes[i],desc.size);desc.bytes_hash=trace_instruction_bytes_hash(desc.bytes,desc.size);
        cs_insn *decoded=NULL;size_t n=cs_disasm(f.decoder,desc.bytes,desc.size,desc.pc,1,&decoded);
        bool decoded_full=n&&decoded->size==desc.size;if(decoded_full) desc.native_insn_id=decoded->id;if(n) cs_free(decoded,n);
        IrModule *m=ir_module_create(NULL);CHECK(m);IrBlockId b=ir_block_add(m);
        IrX86Frontend *front=ir_x86_frontend_create(m,NULL);CHECK(front);
        IrX86LiftResult lifted=ir_x86_lift(front,b,&desc,(IrOrigin){.has_trace_identity=true,.seq_id=seq,
            .descriptor_id=desc.desc_id,.pc=desc.pc,.code_generation=9});
        CHECK(lifted.status==(decoded_full?IR_X86_LIFT_UNSUPPORTED:IR_X86_LIFT_IDENTITY)&&ir_module_inst_count(m)==0);
        ir_x86_frontend_destroy(front);ir_module_destroy(m);ff_free(&f);
    }
    for(unsigned reverse=0;reverse<2;++reverse) {
        uint8_t code[]={0x0f,(uint8_t)(reverse?0xbd:0xbc),0xd8};AluProgram p=alu_program(code,3,0x1000);keep(&p);alu_end(&p);
        AluInputs input={.unknown_gpr=1,.eflags=0x202};IrBindings bindings={.user=&input,.read_bv=alu_binding};
        IrEval *e=ir_eval_create(p.module,&bindings,NULL);CHECK(e);CHECK(ir_eval_run(e).status==IR_EVAL_UNKNOWN);
        CHECK(!ir_eval_state(e,p.state.gpr[3]).bits.known_mask&&!ir_eval_state(e,p.state.flags[3]).bits.known_mask);
        ir_eval_destroy(e);ir_module_destroy(p.module);
    }
}
static unsigned symbolic(void) {
    unsigned queries=0;
    for(unsigned reverse=0;reverse<2;++reverse) {
        FrontFixture f=ff_new(8);InsnAux a=of_registers();uint8_t code[]={0x0f,(uint8_t)(reverse?0xbd:0xbc),0xc8};
        uint64_t seq=ff_emit(&f,0x1000,code,3,9,0,&a);const TraceEntry *entry=trace_find_seq(f.trace,seq,NULL);
        const InsnDesc *desc=trace_insn_desc_get(f.trace,entry->insn_desc_id);
        AluProgram p={.module=ir_module_create(NULL)};CHECK(p.module);IrX86Frontend *front=ir_x86_frontend_create(p.module,NULL);CHECK(front);
        p.state=*ir_x86_frontend_state(front);p.block=ir_block_add(p.module);
        IrValueId source=ir_emit_value(p.module,p.block,(IrInstSpec){.op=IR_OP_INPUT,.type=ir_type_bv(32),.immediate=0xb5f0});
        CHECK(ir_emit_effect(p.module,p.block,(IrInstSpec){.op=IR_OP_WRITE_STATE,.type=ir_type_void(),.state=p.state.gpr[0],.args={source}}));
        p.lift=ir_x86_lift(front,p.block,desc,(IrOrigin){.has_trace_identity=true,.seq_id=seq,.descriptor_id=desc->desc_id,.pc=desc->pc,.code_generation=9});
        CHECK(p.lift.status==IR_X86_LIFT_OK);ir_x86_frontend_destroy(front);ff_free(&f);
        IrValueId result=state(&p,p.state.gpr[1],32),zf=state(&p,p.state.flags[3],1),flags[6];
        CHECK(ir_module_add_output(p.module,result)&&ir_module_add_output(p.module,zf));
        for(unsigned j=0;j<6;++j) {flags[j]=state(&p,p.state.flags[j],1);CHECK(ir_module_add_output(p.module,flags[j]));}
        alu_end(&p);
        for(unsigned phase=0;phase<3;++phase) {
            if(phase==1) CHECK(ir_trace_ssa(p.module,NULL).analysis.status==IR_OK);
            if(phase==2) CHECK(ir_optimize(p.module,NULL).status==IR_OK);
            IrSmtParameter parameter={.key=0xb5f0,.width=32,.symbolic=true,.observed=ir_bits_known(0x12345678,32)};
            IrSmtOptions options=ir_smt_default_options();options.parameters=&parameter;options.parameter_count=1;
            IrSmtInfo info;IrSmt *s=ir_smt_build(p.module,NULL,&options,&info);CHECK(s);
            for(unsigned bit=0;bit<32;++bit) {
                IrSmtConstraint c[3]={{source,1U<<bit,UINT32_MAX},{result,bit,UINT32_MAX},{zf,0,1}};
                IrSmtAnswer answer=ir_smt_query(s,c,3,NULL,0,NULL);sm_status(&answer,IR_SMT_SAT);ir_smt_answer_destroy(&answer);++queries;
                c[1].expected^=1;answer=ir_smt_query(s,c,3,NULL,0,NULL);sm_status(&answer,IR_SMT_UNSAT);ir_smt_answer_destroy(&answer);++queries;
                IrSmtConstraint free[2]={{result,bit,UINT32_MAX},{zf,0,1}};
                answer=ir_smt_query(s,free,2,NULL,0,NULL);sm_status(&answer,IR_SMT_SAT);
                CHECK(answer.parameter_count==1&&answer.parameters[0].key==0xb5f0&&answer.parameters[0].value);
                CHECK(reference((uint32_t)answer.parameters[0].value,reverse)==bit);ir_smt_answer_destroy(&answer);++queries;
            }
            IrSmtConstraint zero_zf[2]={{source,0,UINT32_MAX},{zf,1,1}};
            IrSmtAnswer answer=ir_smt_query(s,zero_zf,2,NULL,0,NULL);sm_status(&answer,IR_SMT_SAT);ir_smt_answer_destroy(&answer);++queries;
            IrSmtConstraint zero_result[2]={{source,0,UINT32_MAX},{result,7,UINT32_MAX}};
            answer=ir_smt_query(s,zero_result,2,NULL,0,NULL);sm_status(&answer,IR_SMT_UNKNOWN);ir_smt_answer_destroy(&answer);++queries;
            zero_zf[0].expected=1;answer=ir_smt_query(s,zero_zf,2,NULL,0,NULL);sm_status(&answer,IR_SMT_UNSAT);ir_smt_answer_destroy(&answer);++queries;
            IrSmtConstraint range[2]={{result,32,UINT32_MAX},{zf,0,1}};
            answer=ir_smt_query(s,range,2,NULL,0,NULL);sm_status(&answer,IR_SMT_UNSAT);ir_smt_answer_destroy(&answer);++queries;
            for(unsigned j=0;j<6;++j) if(j!=3) {
                IrSmtConstraint c[2]={{source,16,UINT32_MAX},{flags[j],0,1}};
                answer=ir_smt_query(s,c,2,NULL,0,NULL);sm_status(&answer,IR_SMT_UNKNOWN);ir_smt_answer_destroy(&answer);++queries;
            }
            ir_smt_destroy(s);
        }
        ir_module_destroy(p.module);
    }
    return queries;
}
static ReplayInput *fixture(unsigned reverse,unsigned mode) {
    FrontFixture f=ff_new(16);InsnAux a=of_registers();uint64_t selected[6];unsigned count=0;
    uint32_t value=mode==1||mode==2?0:0x100;const uint8_t nop[]={0x90},load[]={0xa1,0x00,0x30,0x00,0x00};
    (void)of_emit(&f,0x1000,nop,1,a,0x1001);InsnAux read=a;of_read(&read,0x3000,value);
    selected[count++]=of_emit(&f,0x1001,load,5,read,0x1006);a.reg_vals[0]=value;uint32_t pc=0x1006;
    if(mode==0) {
        uint32_t mask=reverse?1:0x10000;uint8_t code[]={0x0d,mask,mask>>8,mask>>16,mask>>24};
        selected[count++]=of_emit(&f,pc,code,5,a,pc+5);a=alu_after(a,ALU_OR,32,value,mask,0,0,true);value|=mask;pc+=5;
    }
    uint8_t scan[]={0x0f,(uint8_t)(reverse?0xbd:0xbc),0xc8};
    selected[count++]=of_emit(&f,pc,scan,3,a,pc+3);pc+=3;
    if(value) a.reg_vals[1]=reference(value,reverse);
    a.eflags_before=value?0x202:0x242;
    if(mode==0||mode==2) {
        if(mode==0&&reverse) {const uint8_t invert[]={0x83,0xf1,31};
            selected[count++]=of_emit(&f,pc,invert,3,a,pc+3);a=alu_after(a,ALU_XOR,32,a.reg_vals[1],31,1,0,true);pc+=3;}
        uint32_t expected=a.reg_vals[1];uint8_t cmp[]={0x81,0xf9,expected,expected>>8,expected>>16,expected>>24};
        selected[count++]=of_emit(&f,pc,cmp,6,a,pc+6);a=alu_after(a,ALU_CMP,32,expected,expected,0,0,false);pc+=6;
    }
    uint8_t branch[]={mode==1?0x74:mode==3?0x72:0x75,0x10};bool taken=mode==1;
    selected[count++]=ff_emit(&f,pc,branch,2,9,0,&a);uint32_t next=pc+(taken?18:2);
    ff_finish_branch(&f,selected[count-1],next,taken);uint64_t trigger=of_emit(&f,next,nop,1,a,next+1);
    ReplayInput *input=ff_capture(&f,selected,count,trigger);ff_free(&f);return input;
}
static void concolic(void) {
    for(unsigned reverse=0;reverse<2;++reverse) for(unsigned mode=0;mode<4;++mode) {
        ReplayInput *input=fixture(reverse,mode);IrConcolicRead source={.read_seq=1,.address=0x3000,.read_size=4,.count=4,
            .offsets={0,1,2,3},.bytes={0,1,0,0},.completed_read=true,.flags_verified=true};
        if(mode==1||mode==2) memset(source.bytes,0,4);
        IrConcolicReadResult result=ir_concolic_read(input,&source,false,NULL);
        if(mode==0) {
            if(strcmp(result.status,"OBSERVED")) fprintf(stderr,"scan observe reverse=%u mode=%u %s %s\n",reverse,mode,result.status,result.reason);
            CHECK(!strcmp(result.status,"OBSERVED"));result=ir_concolic_read(input,&source,true,NULL);
            if(strcmp(result.status,"BOUNDARY_WITNESS")) fprintf(stderr,"scan solve reverse=%u mode=%u %s %s\n",reverse,mode,result.status,result.reason);
            CHECK(!strcmp(result.status,"BOUNDARY_WITNESS"));uint32_t candidate=0;
            for(unsigned j=0;j<4;++j) candidate|=(uint32_t)result.candidates[j]<<(8*j);
            candidate|=reverse?1:0x10000;CHECK((reverse?31^reference(candidate,true):reference(candidate,false))!=(reverse?23U:8U));
        } else {
            CHECK(!strcmp(result.status,"UNKNOWN"));result=ir_concolic_read(input,&source,true,NULL);CHECK(!strcmp(result.status,"UNKNOWN"));
        }
        replay_input_destroy(input);
    }
}
int main(void) {
    unsigned nonzero=0,zero=0;concrete(&nonzero,&zero);negatives_and_unknowns();unsigned queries=symbolic();concolic();
    printf("PASS BITSCAN32: hardware nonzero=%u zero-ZF=%u register encodings=128 SMT queries=%u; IR/SSA/optimization/aliases/portable unknowns/concolic PASS; zero-input prefixes remain UNKNOWN\n",nonzero,zero,queries);
    return 0;
}
