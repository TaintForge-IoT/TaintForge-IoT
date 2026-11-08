#include "ir_oep_test_helpers.h"
#include "ir_concolic.h"
#include "ir_smt_test_helpers.h"

static uint32_t rng=0x5d325d32;
static uint32_t random32(void) {rng^=rng<<13; rng^=rng>>17; rng^=rng<<5; return rng;}
static uint32_t reference(uint32_t low,uint32_t high,unsigned count) {
    return (uint32_t)((((uint64_t)high<<32)|low)>>(count&31));
}
static uint32_t hardware(uint32_t low,uint32_t high,unsigned count,uint32_t flags,uint64_t *after) {
    uint64_t saved,observed,initial=flags;
    __asm__ volatile("pushfq\n\tpopq %[saved]\n\tpushq %[initial]\n\tpopfq\n\t"
        "shrdl %%cl,%[high],%[low]\n\tpushfq\n\tpopq %[after]\n\tpushq %[saved]\n\tpopfq"
        : [low]"+&r"(low),[saved]"=&r"(saved),[after]"=&r"(observed)
        : [high]"r"(high),"c"(count),[initial]"r"(initial) : "cc","memory");
    *after=observed; return low;
}
static unsigned parity(uint32_t value) {
    unsigned ones=0; for(unsigned i=0;i<8;++i) ones+=(value>>i)&1; return !(ones&1);
}
static unsigned flag(unsigned f,uint32_t low,uint32_t high,unsigned count,uint32_t initial) {
    unsigned k=count&31; uint32_t value=reference(low,high,k);
    if(!k||f==6) return (initial>>alu_flag_bits[f])&1;
    switch(f) {
    case 0:return (low>>(k-1))&1;
    case 1:return parity(value);
    case 3:return value==0;
    case 4:return value>>31;
    case 5:CHECK(k==1);return (low^value)>>31;
    default:CHECK(false);return 0;
    }
}
static IrValueId state(AluProgram *p,IrStateId id,unsigned width) {
    return ir_emit_value(p->module,p->block,(IrInstSpec){.op=IR_OP_READ_STATE,.type=ir_type_bv(width),.state=id});
}
static void keep(AluProgram *p) {
    for(unsigned i=0;i<8;++i) CHECK(ir_module_add_output(p->module,state(p,p->state.gpr[i],32)));
}
static unsigned concrete(void) {
    unsigned cases=0;
    for(unsigned dst=0;dst<8;++dst) for(unsigned src=0;src<8;++src) {
        uint8_t code[]={0x0f,0xad,(uint8_t)(0xc0+src*8+dst)};
        AluProgram p=alu_program(code,3,0x1000);keep(&p);alu_end(&p);
        CHECK(p.lift.status==IR_X86_LIFT_OK&&p.lift.gpr_writes==(1U<<dst)&&!p.lift.memory_count);
        CHECK(p.lift.flags_written==0x3f&&p.lift.flags_preserved_when&&p.lift.flags_defined[2]&&p.lift.flags_defined[5]);
        for(unsigned phase=0;phase<3;++phase) {
            if(phase==1) CHECK(ir_trace_ssa(p.module,NULL).analysis.status==IR_OK);
            if(phase==2) CHECK(ir_optimize(p.module,NULL).status==IR_OK);
            for(unsigned i=0;i<512;++i) {
                AluInputs in={.eflags=(i>>8)&1?0xcd7:0x202};
                for(unsigned r=0;r<8;++r) in.gpr[r]=random32();
                in.gpr[dst]=i%8==0?0:i%8==1?UINT32_MAX:i%8==2?0x80000001:random32();
                in.gpr[src]=(i>>2)%8==0?0:(i>>2)%8==1?UINT32_MAX:random32();
                in.gpr[1]=(in.gpr[1]&0xffffff00U)|(i&255);
                unsigned k=in.gpr[1]&31;uint32_t low=in.gpr[dst],high=in.gpr[src];uint64_t flags;
                uint32_t value=hardware(low,high,in.gpr[1],in.eflags,&flags);
                CHECK(value==reference(low,high,in.gpr[1]));
                IrBindings bindings={.user=&in,.read_bv=alu_binding};IrEval *e=ir_eval_create(p.module,&bindings,NULL);CHECK(e);
                CHECK(ir_eval_run(e).status==(k?IR_EVAL_UNKNOWN:IR_EVAL_FRAGMENT_END));
                for(unsigned r=0;r<8;++r) CHECK(alu_state(e,p.state.gpr[r],32)==(r==dst?value:in.gpr[r]));
                for(unsigned f=0;f<7;++f) {
                    IrBits bits=ir_eval_state(e,p.state.flags[f]).bits;
                    if((f==2&&k)||(f==5&&k>1)) CHECK(!bits.known_mask&&(bits.reasons&IR_REASON_UNDEFINED));
                    else {
                        unsigned expected=flag(f,low,high,in.gpr[1],in.eflags);
                        CHECK(expected==((flags>>alu_flag_bits[f])&1));
                        CHECK(ir_bits_complete(bits,1)&&bits.value==expected);
                    }
                }
                ir_eval_destroy(e);++cases;
            }
        }
        ir_module_destroy(p.module);
    }
    return cases;
}
static void negatives_and_unknowns(void) {
    const uint8_t codes[][5]={{0x66,0x0f,0xad,0xd0},{0xf2,0x0f,0xad,0xd0},{0xf3,0x0f,0xad,0xd0},
        {0xf0,0x0f,0xad,0xd0},{0x67,0x0f,0xad,0xd0},{0x2e,0x0f,0xad,0xd0},
        {0x0f,0xad,0x10},{0x0f,0xad,0x14,0x24},{0x0f,0xac,0xd0,3},{0x0f,0xa5,0xd0}};
    const unsigned sizes[]={4,4,4,4,4,4,3,4,4,3};
    for(unsigned i=0;i<sizeof(sizes)/sizeof(*sizes);++i) {
        FrontFixture f=ff_new(8);InsnAux a=ff_registers();const uint8_t valid[]={0x0f,0xad,0xd0};
        uint64_t seq=ff_emit(&f,0x1000,valid,3,9,0,&a);const TraceEntry *entry=trace_find_seq(f.trace,seq,NULL);
        InsnDesc desc=*trace_insn_desc_get(f.trace,entry->insn_desc_id);
        desc.size=sizes[i];memcpy(desc.bytes,codes[i],desc.size);desc.bytes_hash=trace_instruction_bytes_hash(desc.bytes,desc.size);
        cs_insn *decoded=NULL;size_t n=cs_disasm(f.decoder,desc.bytes,desc.size,desc.pc,1,&decoded);
        bool full=n&&decoded->size==desc.size;if(full) desc.native_insn_id=decoded->id;if(n) cs_free(decoded,n);
        IrModule *m=ir_module_create(NULL);CHECK(m);IrBlockId b=ir_block_add(m);
        IrX86Frontend *front=ir_x86_frontend_create(m,NULL);CHECK(front);
        IrX86LiftResult r=ir_x86_lift(front,b,&desc,(IrOrigin){.has_trace_identity=true,.seq_id=seq,
            .descriptor_id=desc.desc_id,.pc=desc.pc,.code_generation=9});
        CHECK(r.status==(full?IR_X86_LIFT_UNSUPPORTED:IR_X86_LIFT_IDENTITY)&&ir_module_inst_count(m)==0);
        ir_x86_frontend_destroy(front);ir_module_destroy(m);ff_free(&f);
    }
    const uint8_t code[]={0x0f,0xad,0xd0};AluProgram p=alu_program(code,3,0x1000);keep(&p);alu_end(&p);
    for(unsigned kind=0;kind<4;++kind) for(unsigned k=0;k<3;++k) {
        AluInputs in={.eflags=0x202,.unknown_gpr=kind==0?1:kind==1?4:kind==2?2:0,.unknown_flags=kind==3?0x7f:0};
        in.gpr[0]=0x81234567;in.gpr[2]=0x76543210;in.gpr[1]=k;
        IrBindings bindings={.user=&in,.read_bv=alu_binding};IrEval *e=ir_eval_create(p.module,&bindings,NULL);CHECK(e);
        CHECK(ir_eval_run(e).status==IR_EVAL_UNKNOWN);
        if(kind==1&&!k) CHECK(alu_state(e,p.state.gpr[0],32)==in.gpr[0]);
        else if(kind<3) CHECK(!ir_bits_complete(ir_eval_state(e,p.state.gpr[0]).bits,32));
        if(kind==3) {
            CHECK(alu_state(e,p.state.gpr[0],32)==reference(in.gpr[0],in.gpr[2],k));
            if(k) for(unsigned f=0;f<6;++f) {
                if(f==2||(f==5&&k>1)) continue;
                CHECK(alu_state(e,p.state.flags[f],1)==flag(f,in.gpr[0],in.gpr[2],k,0x202));
            }
            CHECK(!ir_eval_state(e,p.state.flags[6]).bits.known_mask);
        }
        ir_eval_destroy(e);
    }
    ir_module_destroy(p.module);
}
static unsigned symbolic(void) {
    FrontFixture f=ff_new(8);InsnAux a=of_registers();const uint8_t code[]={0x0f,0xad,0xd0};
    uint64_t seq=ff_emit(&f,0x1000,code,3,9,0,&a);const TraceEntry *entry=trace_find_seq(f.trace,seq,NULL);
    const InsnDesc *desc=trace_insn_desc_get(f.trace,entry->insn_desc_id);
    AluProgram p={.module=ir_module_create(NULL)};CHECK(p.module);IrX86Frontend *front=ir_x86_frontend_create(p.module,NULL);CHECK(front);
    p.state=*ir_x86_frontend_state(front);p.block=ir_block_add(p.module);IrValueId inputs[3];unsigned regs[]={0,2,1};
    for(unsigned i=0;i<3;++i) {
        inputs[i]=ir_emit_value(p.module,p.block,(IrInstSpec){.op=IR_OP_INPUT,.type=ir_type_bv(32),.immediate=0x5d10+i});
        CHECK(ir_emit_effect(p.module,p.block,(IrInstSpec){.op=IR_OP_WRITE_STATE,.type=ir_type_void(),.state=p.state.gpr[regs[i]],.args={inputs[i]}}));
    }
    for(unsigned i=0;i<7;++i) {
        IrValueId v=ir_emit_value(p.module,p.block,(IrInstSpec){.op=IR_OP_CONST,.type=ir_type_bv(1),.immediate=1});
        CHECK(ir_emit_effect(p.module,p.block,(IrInstSpec){.op=IR_OP_WRITE_STATE,.type=ir_type_void(),.state=p.state.flags[i],.args={v}}));
    }
    p.lift=ir_x86_lift(front,p.block,desc,(IrOrigin){.has_trace_identity=true,.seq_id=seq,.descriptor_id=desc->desc_id,.pc=desc->pc,.code_generation=9});
    CHECK(p.lift.status==IR_X86_LIFT_OK);ir_x86_frontend_destroy(front);ff_free(&f);
    IrValueId result=state(&p,p.state.gpr[0],32),flags[7];CHECK(ir_module_add_output(p.module,result));
    for(unsigned i=0;i<7;++i) {flags[i]=state(&p,p.state.flags[i],1);CHECK(ir_module_add_output(p.module,flags[i]));}
    alu_end(&p);unsigned queries=0;
    for(unsigned phase=0;phase<3;++phase) {
        if(phase==1) CHECK(ir_trace_ssa(p.module,NULL).analysis.status==IR_OK);
        if(phase==2) CHECK(ir_optimize(p.module,NULL).status==IR_OK);
        IrSmtParameter params[3]={{.key=0x5d10,.width=32,.symbolic=true,.observed=ir_bits_known(0x81234567,32)},
            {.key=0x5d11,.width=32,.symbolic=true,.observed=ir_bits_known(0x76543210,32)},
            {.key=0x5d12,.width=32,.symbolic=true,.observed=ir_bits_known(3,32)}};
        IrSmtOptions options=ir_smt_default_options();options.parameters=params;options.parameter_count=3;
        IrSmtInfo info;IrSmt *s=ir_smt_build(p.module,NULL,&options,&info);CHECK(s);
        for(unsigned k=0;k<256;++k) {
            uint32_t low=0x81234567,high=0x76543210;
            IrSmtConstraint c[4]={{inputs[0],low,UINT32_MAX},{inputs[1],high,UINT32_MAX},
                {inputs[2],0x9abc0000U|k,UINT32_MAX},{result,reference(low,high,k),UINT32_MAX}};
            IrSmtAnswer answer=ir_smt_query(s,c,4,NULL,0,NULL);sm_status(&answer,IR_SMT_SAT);ir_smt_answer_destroy(&answer);++queries;
            c[3].expected^=1;answer=ir_smt_query(s,c,4,NULL,0,NULL);sm_status(&answer,IR_SMT_UNSAT);ir_smt_answer_destroy(&answer);++queries;
            for(unsigned j=0;j<7;++j) {
                bool undefined=(j==2&&(k&31))||(j==5&&(k&31)>1);
                c[3]=(IrSmtConstraint){flags[j],undefined?0:flag(j,low,high,k,0xcd7),1};
                answer=ir_smt_query(s,c,4,NULL,0,NULL);sm_status(&answer,undefined?IR_SMT_UNKNOWN:IR_SMT_SAT);ir_smt_answer_destroy(&answer);++queries;
                if(!undefined) {c[3].expected^=1;answer=ir_smt_query(s,c,4,NULL,0,NULL);sm_status(&answer,IR_SMT_UNSAT);ir_smt_answer_destroy(&answer);++queries;}
            }
        }
        for(unsigned k=0;k<32;++k) {
            IrSmtConstraint free[3]={{inputs[0],0,UINT32_MAX},{inputs[1],UINT32_MAX,UINT32_MAX},{result,reference(0,UINT32_MAX,k),UINT32_MAX}};
            IrSmtAnswer answer=ir_smt_query(s,free,3,NULL,0,NULL);sm_status(&answer,IR_SMT_SAT);CHECK(answer.parameter_count==3);
            bool found=false;uint32_t chosen=0;
            for(size_t i=0;i<answer.parameter_count;++i) if(answer.parameters[i].key==0x5d12) {chosen=answer.parameters[i].value;found=true;}
            CHECK(found&&(chosen&31)==k);ir_smt_answer_destroy(&answer);++queries;
        }
        IrSmtConstraint free={result,0xdeadc0de,UINT32_MAX};IrSmtAnswer answer=ir_smt_query(s,&free,1,NULL,0,NULL);sm_status(&answer,IR_SMT_SAT);
        CHECK(answer.parameter_count==3);uint32_t values[3]={0};
        for(size_t i=0;i<answer.parameter_count;++i) {CHECK(answer.parameters[i].key>=0x5d10&&answer.parameters[i].key<=0x5d12);values[answer.parameters[i].key-0x5d10]=answer.parameters[i].value;}
        CHECK(reference(values[0],values[1],values[2])==0xdeadc0de);ir_smt_answer_destroy(&answer);++queries;
        ir_smt_destroy(s);
    }
    ir_module_destroy(p.module);return queries;
}
static void initial(unsigned mode,uint32_t *low,uint32_t *high,unsigned *count) {
    *low=mode==5||mode==6?0:mode==7?0:0x80000001;*high=mode==7?1:mode==5||mode==6?0:0x12345678;
    *count=mode==1?32:mode==2||mode==4||mode==7?1:mode==3?2:3;
    if(mode==2) {*low=0x80000000;*high=0;}
}
static ReplayInput *fixture(unsigned mode) {
    FrontFixture f=ff_new(32);InsnAux a=of_registers();uint64_t selected[10];unsigned n=0;
    uint32_t low,high;unsigned count;initial(mode,&low,&high,&count);
    const uint8_t nop[]={0x90},load[]={0xa1,0,0x30,0,0},load_high[]={0x8b,0x15,4,0x30,0,0},cl[]={0x0f,0xb6,0x0d,8,0x30,0,0};
    (void)of_emit(&f,0x1000,nop,1,a,0x1001);InsnAux read=a;of_read(&read,0x3000,low);
    selected[n++]=of_emit(&f,0x1001,load,5,read,0x1006);a.reg_vals[0]=low;
    read=a;of_read(&read,0x3004,high);selected[n++]=of_emit(&f,0x1006,load_high,6,read,0x100c);a.reg_vals[2]=high;
    read=a;ff_read(&read,0x3008,count,1,true);read.mem_read_taint=read.mem_read_effective_taint=1;read.mem_reads[0].taint=read.mem_reads[0].effective_taint=1;
    selected[n++]=of_emit(&f,0x100c,cl,7,read,0x1013);a.reg_vals[1]=count;
    const uint8_t shrd[]={0x0f,0xad,0xd0};selected[n++]=of_emit(&f,0x1013,shrd,3,a,0x1016);uint64_t flags;
    a.reg_vals[0]=hardware(low,high,count,a.eflags_before,&flags);a.eflags_before=flags;uint32_t pc=0x1016;
    if(mode<2) {
        uint32_t expected=a.reg_vals[0];uint8_t cmp[]={0x3d,expected,expected>>8,expected>>16,expected>>24};
        selected[n++]=of_emit(&f,pc,cmp,5,a,pc+5);a=alu_after(a,ALU_CMP,32,expected,expected,0,0,false);pc+=5;
    }
    unsigned flag_index=mode==4?0:mode==5?3:mode==6?1:mode==7?4:5;
    uint8_t branch[]={mode<2?0x75:mode==4?0x72:mode==5?0x74:mode==6?0x7a:mode==7?0x78:0x70,0x10};
    bool taken=mode<2?false:((a.eflags_before>>alu_flag_bits[flag_index])&1);
    selected[n++]=ff_emit(&f,pc,branch,2,9,0,&a);uint32_t next=pc+(taken?18:2);ff_finish_branch(&f,selected[n-1],next,taken);
    uint64_t trigger=of_emit(&f,next,nop,1,a,next+1);ReplayInput *input=ff_capture(&f,selected,n,trigger);ff_free(&f);return input;
}
static void concolic(void) {
    for(unsigned mode=0;mode<8;++mode) {
        uint32_t low,high;unsigned count;initial(mode,&low,&high,&count);ReplayInput *input=fixture(mode);
        IrConcolicRead source={.read_seq=1,.address=0x3000,.read_size=9,.count=9,.offsets={0,1,2,3,4,5,6,7,8},
            .bytes={low,low>>8,low>>16,low>>24,high,high>>8,high>>16,high>>24,count},.completed_read=true,.flags_verified=true};
        IrConcolicReadResult r=ir_concolic_read(input,&source,false,NULL);
        if(strcmp(r.status,mode==3?"UNKNOWN":"OBSERVED")) fprintf(stderr,"SHRD observe mode=%u: %s %s\n",mode,r.status,r.reason);
        CHECK(!strcmp(r.status,mode==3?"UNKNOWN":"OBSERVED"));
        r=ir_concolic_read(input,&source,true,NULL);
        if(strcmp(r.status,mode==3?"UNKNOWN":"BOUNDARY_WITNESS")) fprintf(stderr,"SHRD solve mode=%u: %s %s\n",mode,r.status,r.reason);
        CHECK(!strcmp(r.status,mode==3?"UNKNOWN":"BOUNDARY_WITNESS"));
        if(mode!=3) {
            uint32_t a=0,b=0;for(unsigned i=0;i<4;++i) {a|=(uint32_t)r.candidates[i]<<(8*i);b|=(uint32_t)r.candidates[i+4]<<(8*i);}
            unsigned k=r.candidates[8]&31;
            if(mode<2) CHECK(reference(a,b,k)!=reference(low,high,count));
            else {
                unsigned f=mode==4?0:mode==5?3:mode==6?1:mode==7?4:5;
                if(f==5) CHECK(k<=1);
                CHECK(flag(f,a,b,k,0x202)!=flag(f,low,high,count,0x202));
            }
        }
        replay_input_destroy(input);
    }
}
int main(void) {
    unsigned cases=concrete();negatives_and_unknowns();unsigned queries=symbolic();concolic();
    printf("PASS SHRD32: hardware=%u register encodings=64 raw CL counts=256 SMT queries=%u; IR/SSA/optimization/aliases/zero-count/CF/PF/ZF/SF/OF/free symbolic operands and count/concolic PASS; nonzero AF and count>1 OF UNKNOWN\n",cases,queries);
    return 0;
}
