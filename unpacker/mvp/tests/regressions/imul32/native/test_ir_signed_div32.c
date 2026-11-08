#include "ir_oep_test_helpers.h"
#include "ir_concolic.h"
#include "ir_smt_test_helpers.h"
#include <signal.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

static uint32_t rng=0x1d1f0032;
static uint32_t rnd(void) {rng^=rng<<13;rng^=rng>>17;rng^=rng<<5;return rng;}
static int64_t signed32(uint32_t n) {return n<=INT32_MAX?n:(int64_t)n-INT64_C(0x100000000);}
static bool reference(uint32_t low,uint32_t high,uint32_t divisor,uint32_t *q,uint32_t *r) {
    uint64_t bits=((uint64_t)high<<32)|low;
    __int128 n=(__int128)bits,d=signed32(divisor);
    if(bits>>63) n-=((__int128)1<<64);
    if(!d) return false;
    __int128 quotient=n/d;
    if(quotient<INT32_MIN||quotient>INT32_MAX) return false;
    *q=(uint32_t)quotient;*r=(uint32_t)(n%d);return true;
}
static void hardware(uint32_t low,uint32_t high,uint32_t divisor,uint32_t *q,uint32_t *r) {
    __asm__ volatile("idivl %[d]" : "+a"(low),"+d"(high) : [d]"r"(divisor) : "cc");
    *q=low;*r=high;
}
static IrValueId read_state(AluProgram *p,IrStateId s,unsigned bits) {
    return ir_emit_value(p->module,p->block,(IrInstSpec){.op=IR_OP_READ_STATE,.type=ir_type_bv(bits),.state=s});
}
static void keep(AluProgram *p) {
    for(unsigned i=0;i<8;++i) CHECK(ir_module_add_output(p->module,read_state(p,p->state.gpr[i],32)));
}
static void cdq(void) {
    const uint8_t code[]={0x99};AluProgram p=alu_program(code,1,0x80490d5);keep(&p);alu_end(&p);
    CHECK(p.lift.status==IR_X86_LIFT_OK && p.lift.gpr_writes==4 && !p.lift.flags_written && !p.lift.memory_count);
    for(unsigned phase=0;phase<3;++phase) {
        if(phase==1) CHECK(ir_trace_ssa(p.module,NULL).analysis.status==IR_OK);
        if(phase==2) CHECK(ir_optimize(p.module,NULL).status==IR_OK);
        for(unsigned i=0;i<1024;++i) {
            AluInputs in={.eflags=i&1?0xcd7:0x202};for(unsigned j=0;j<8;++j) in.gpr[j]=rnd();
            if(i<4) in.gpr[0]=i==0?0:i==1?INT32_MAX:i==2?0x80000000:UINT32_MAX;
            uint32_t high;uint64_t saved,after,initial=in.eflags;
            __asm__ volatile("pushfq\n\tpopq %[saved]\n\tpushq %[initial]\n\tpopfq\n\t"
                "cltd\n\tpushfq\n\tpopq %[after]\n\tpushq %[saved]\n\tpopfq"
                : "=d"(high),[saved]"=&r"(saved),[after]"=&r"(after)
                : "a"(in.gpr[0]),[initial]"r"(initial) : "cc","memory");
            IrBindings b={.user=&in,.read_bv=alu_binding};IrEval *e=ir_eval_create(p.module,&b,NULL);CHECK(e);
            CHECK(ir_eval_run(e).status==IR_EVAL_FRAGMENT_END);
            for(unsigned j=0;j<8;++j) CHECK(alu_state(e,p.state.gpr[j],32)==(j==2?high:in.gpr[j]));
            CHECK(high==(in.gpr[0]>>31?UINT32_MAX:0));
            for(unsigned j=0;j<7;++j) CHECK(alu_state(e,p.state.flags[j],1)==((after>>alu_flag_bits[j])&1));
            ir_eval_destroy(e);
        }
    }
    ir_module_destroy(p.module);
}
static const uint32_t edges[][3]={
    {0,0,1},{0,0,0},{0x80000000,UINT32_MAX,UINT32_MAX},
    {0x80000000,0,UINT32_MAX},{0x80000000,UINT32_MAX,1},
    {0x80000000,0,1},{0x7fffffff,UINT32_MAX,1},
    {0,0x80000000,UINT32_MAX},{0,0x80000000,0x80000000},
    {UINT32_MAX,0,UINT32_MAX},{UINT32_MAX,UINT32_MAX,0x80000000},
    {2,UINT32_MAX,3},{UINT32_MAX,0x7fffffff,UINT32_MAX},
    {0,0,0x80000000},{0xfffffffe,UINT32_MAX,0x80000000}};
static void concrete(unsigned *valid,unsigned *faulted) {
    for(unsigned reg=0;reg<8;++reg) {
        uint8_t code[]={0xf7,(uint8_t)(0xf8+reg)};AluProgram p=alu_program(code,2,0x1000);
        CHECK(p.lift.status==IR_X86_LIFT_OK&&p.lift.gpr_writes==5&&p.lift.flags_written==0x3f&&p.lift.flags_undefined==0x3f);
        keep(&p);alu_end(&p);
        for(unsigned phase=0;phase<3;++phase) {
            if(phase==1) CHECK(ir_trace_ssa(p.module,NULL).analysis.status==IR_OK);
            if(phase==2) CHECK(ir_optimize(p.module,NULL).status==IR_OK);
            for(unsigned i=0;i<1024;++i) {
                AluInputs in={.eflags=i&1?0xcd7:0x202};for(unsigned j=0;j<8;++j) in.gpr[j]=rnd();
                uint32_t low=rnd(),high=low>>31?UINT32_MAX:0,divisor=rnd()|1;
                if(i%4==2) {
                    __int128 product=(__int128)signed32(rnd())*signed32(divisor);
                    uint64_t bits=(uint64_t)product;low=(uint32_t)bits;high=(uint32_t)(bits>>32);
                } else if(i%4==3) high=rnd();
                if(i<sizeof(edges)/sizeof(*edges)) {low=edges[i][0];high=edges[i][1];divisor=edges[i][2];}
                if(reg==2&&i>=sizeof(edges)/sizeof(*edges)&&i%2==0) {high=UINT32_MAX;low=0x80000001U|(rnd()&0x7fffffffU);}
                in.gpr[0]=low;in.gpr[2]=high;if(reg!=0&&reg!=2) in.gpr[reg]=divisor;
                uint32_t q=0,r=0;bool ok=reference(in.gpr[0],in.gpr[2],in.gpr[reg],&q,&r);
                IrBindings b={.user=&in,.read_bv=alu_binding};IrEval *e=ir_eval_create(p.module,&b,NULL);CHECK(e);
                IrEvalResult result=ir_eval_run(e);
                if(ok) {
                    uint32_t hq,hr;hardware(in.gpr[0],in.gpr[2],in.gpr[reg],&hq,&hr);CHECK(q==hq&&r==hr);
                    CHECK(result.status==IR_EVAL_FRAGMENT_END);
                    for(unsigned j=0;j<8;++j) CHECK(alu_state(e,p.state.gpr[j],32)==(j==0?q:j==2?r:in.gpr[j]));
                    for(unsigned j=0;j<6;++j) CHECK(!ir_eval_state(e,p.state.flags[j]).bits.known_mask);
                    CHECK(alu_state(e,p.state.flags[6],1)==((in.eflags>>10)&1));++*valid;
                } else {
                    CHECK(result.status==IR_EVAL_UNKNOWN&&(result.reasons&IR_REASON_GUARD));
                    CHECK(alu_state(e,p.state.gpr[0],32)==in.gpr[0]&&alu_state(e,p.state.gpr[2],32)==in.gpr[2]);++*faulted;
                }
                ir_eval_destroy(e);
            }
        }
        ir_module_destroy(p.module);
    }
    for(unsigned i=0;i<5;++i) {
        const unsigned indices[]={1,2,5,6,7};unsigned index=indices[i];uint32_t q,r;
        CHECK(!reference(edges[index][0],edges[index][1],edges[index][2],&q,&r));
        pid_t child=fork();CHECK(child>=0);
        if(!child) {struct rlimit limit={0,0};(void)setrlimit(RLIMIT_CORE,&limit);(void)signal(SIGFPE,SIG_DFL);
            hardware(edges[index][0],edges[index][1],edges[index][2],&q,&r);_exit(77);}
        int status;CHECK(waitpid(child,&status,0)==child);CHECK(WIFSIGNALED(status)&&WTERMSIG(status)==SIGFPE);
    }
}
static void negatives_and_unknowns(void) {
    const uint8_t codes[][4]={{0xf6,0xf9},{0x66,0xf7,0xf9},{0xf7,0x39},{0x66,0x99},{0x98}};
    const unsigned sizes[]={2,3,2,2,1};
    for(unsigned i=0;i<sizeof(sizes)/sizeof(*sizes);++i) {
        AluProgram p=alu_program(codes[i],sizes[i],0x1000);CHECK(p.lift.status==IR_X86_LIFT_UNSUPPORTED);
        CHECK(ir_module_inst_count(p.module)==0);ir_module_destroy(p.module);
    }
    const uint8_t div[]={0xf7,0xf9};
    for(unsigned missing=0;missing<3;++missing) {
        AluProgram p=alu_program(div,2,0x1000);keep(&p);alu_end(&p);
        AluInputs in={.gpr={-2000U,3,UINT32_MAX},.unknown_gpr=1U<<missing};
        IrBindings b={.user=&in,.read_bv=alu_binding};IrEval *e=ir_eval_create(p.module,&b,NULL);CHECK(e);
        CHECK(ir_eval_run(e).status==IR_EVAL_UNKNOWN);ir_eval_destroy(e);ir_module_destroy(p.module);
    }
}
static unsigned symbolic(void) {
    FrontFixture f=ff_new(8);InsnAux a=of_registers();const uint8_t div[]={0xf7,0xf9};
    uint64_t seq=ff_emit(&f,0x1000,div,2,9,0,&a);const TraceEntry *entry=trace_find_seq(f.trace,seq,NULL);
    const InsnDesc *desc=trace_insn_desc_get(f.trace,entry->insn_desc_id);
    AluProgram p={.module=ir_module_create(NULL)};CHECK(p.module);IrX86Frontend *front=ir_x86_frontend_create(p.module,NULL);CHECK(front);
    p.state=*ir_x86_frontend_state(front);p.block=ir_block_add(p.module);IrValueId input[3];
    for(unsigned i=0;i<3;++i) {
        input[i]=ir_emit_value(p.module,p.block,(IrInstSpec){.op=IR_OP_INPUT,.type=ir_type_bv(32),.immediate=0x7100+i});
        CHECK(ir_emit_effect(p.module,p.block,(IrInstSpec){.op=IR_OP_WRITE_STATE,.type=ir_type_void(),.state=p.state.gpr[i],.args={input[i]}}));
    }
    p.lift=ir_x86_lift(front,p.block,desc,(IrOrigin){.has_trace_identity=true,.seq_id=seq,.descriptor_id=desc->desc_id,.pc=desc->pc,.code_generation=9});
    CHECK(p.lift.status==IR_X86_LIFT_OK);ir_x86_frontend_destroy(front);ff_free(&f);
    IrValueId q=read_state(&p,p.state.gpr[0],32),r=read_state(&p,p.state.gpr[2],32),flags[6];
    CHECK(ir_module_add_output(p.module,q)&&ir_module_add_output(p.module,r));
    for(unsigned i=0;i<6;++i) {flags[i]=read_state(&p,p.state.flags[i],1);CHECK(ir_module_add_output(p.module,flags[i]));}
    alu_end(&p);unsigned count=0;
    for(unsigned phase=0;phase<3;++phase) {
        if(phase==1) CHECK(ir_trace_ssa(p.module,NULL).analysis.status==IR_OK);
        if(phase==2) CHECK(ir_optimize(p.module,NULL).status==IR_OK);
        IrSmtParameter parameters[3];for(unsigned i=0;i<3;++i) parameters[i]=(IrSmtParameter){.key=0x7100+i,.width=32,.symbolic=true,.observed=ir_bits_known(0,32)};
        IrSmtOptions options=ir_smt_default_options();options.parameters=parameters;options.parameter_count=3;
        IrSmtInfo info;IrSmt *s=ir_smt_build(p.module,NULL,&options,&info);CHECK(s);
        for(unsigned i=0;i<sizeof(edges)/sizeof(*edges);++i) {
            uint32_t quotient=0,remainder=0;bool valid=reference(edges[i][0],edges[i][1],edges[i][2],&quotient,&remainder);
            IrSmtConstraint c[5]={{input[0],edges[i][0],UINT32_MAX},{input[1],edges[i][2],UINT32_MAX},{input[2],edges[i][1],UINT32_MAX},
                {q,quotient,UINT32_MAX},{r,remainder,UINT32_MAX}};
            IrSmtAnswer answer=ir_smt_query(s,c,5,NULL,0,NULL);sm_status(&answer,valid?IR_SMT_SAT:IR_SMT_UNSAT);ir_smt_answer_destroy(&answer);++count;
            if(valid) {c[3].expected^=1;answer=ir_smt_query(s,c,5,NULL,0,NULL);sm_status(&answer,IR_SMT_UNSAT);ir_smt_answer_destroy(&answer);++count;}
        }
        for(unsigned i=0;i<6;++i) {sm_expect(s,flags[i],1,0,IR_SMT_UNKNOWN);++count;}
        ir_smt_destroy(s);
    }
    ir_module_destroy(p.module);return count;
}
static ReplayInput *concolic_fixture(unsigned mode) {
    FrontFixture f=ff_new(16);InsnAux a=of_registers();a.reg_vals[0]=-2000U;a.reg_vals[2]=0;
    const uint8_t nop[]={0x90},load[]={0x0f,0xb6,0x0d,0x00,0x30,0x00,0x00},cdq[]={0x99},cwd[]={0x66,0x99},
        div[]={0xf7,0xf9},cmp[]={0x3d,0x66,0xfd,0xff,0xff},jne[]={0x75,0x10};
    (void)of_emit(&f,0x1000,nop,1,a,0x1001);InsnAux read=a;ff_read(&read,0x3000,3,1,true);
    read.mem_reads[0].taint=read.mem_reads[0].effective_taint=1;uint64_t seq[5];
    seq[0]=of_emit(&f,0x1001,load,sizeof(load),read,0x1008);a.reg_vals[1]=3;
    unsigned size=mode==1?2:1;seq[1]=of_emit(&f,0x1008,mode==1?cwd:cdq,size,a,0x1008+size);a.reg_vals[2]=UINT32_MAX;
    uint32_t pc=0x1008+size;seq[2]=of_emit(&f,pc,div,2,a,pc+2);pc+=2;
    a.reg_vals[0]=mode==2?-665U:-666U;a.reg_vals[2]=-2U;
    seq[3]=of_emit(&f,pc,cmp,5,a,pc+5);a=alu_after(a,ALU_CMP,32,a.reg_vals[0],-666U,0,0,false);pc+=5;
    seq[4]=ff_emit(&f,pc,jne,2,9,0,&a);ff_finish_branch(&f,seq[4],pc+2,false);
    uint64_t trigger=of_emit(&f,pc+2,nop,1,a,pc+3);ReplayInput *input=ff_capture(&f,seq,5,trigger);ff_free(&f);return input;
}
static void concolic(void) {
    IrConcolicRead source={.read_seq=1,.address=0x3000,.read_size=1,.count=1,.bytes={3},.completed_read=true,.flags_verified=true};
    for(unsigned mode=0;mode<3;++mode) {
        ReplayInput *input=concolic_fixture(mode);IrConcolicReadResult result=ir_concolic_read(input,&source,false,NULL);
        if(mode==1) CHECK(!strcmp(result.status,"UNKNOWN")&&!strcmp(result.reason,"replay_incomplete"));
        else if(mode==2) CHECK(!strcmp(result.status,"UNKNOWN")&&!strcmp(result.reason,"baseline_observations"));
        else {
            if(strcmp(result.status,"OBSERVED")) fprintf(stderr,"observe %s %s\n",result.status,result.reason);
            CHECK(!strcmp(result.status,"OBSERVED")&&result.replay_lifted_steps==5);
            result=ir_concolic_read(input,&source,true,NULL);
            if(strcmp(result.status,"BOUNDARY_WITNESS")) fprintf(stderr,"solve %s %s\n",result.status,result.reason);
            CHECK(!strcmp(result.status,"BOUNDARY_WITNESS")&&result.candidates[0]&&result.candidates[0]!=3);
            uint32_t q,r;hardware(-2000U,UINT32_MAX,result.candidates[0],&q,&r);CHECK(q!=-666U);
        }
        replay_input_destroy(input);
    }
}
static void concolic_five_bytes(void) {
    /* Synthetic full-width numerator and byte divisor, both symbolic.
     * This checks a free inversion rather than fixing all SMT inputs. */
    for(unsigned use_remainder=0;use_remainder<2;++use_remainder) {
        FrontFixture f=ff_new(16);InsnAux a=of_registers();uint64_t seq[8];unsigned count=0;
        const uint8_t nop[]={0x90},load_n[]={0xa1,0x00,0x30,0x00,0x00},
            load_d[]={0x0f,0xb6,0x0d,0x04,0x30,0x00,0x00},add[]={0x83,0xc1,0x01},
            cdq_code[]={0x99},div[]={0xf7,0xf9},move_r[]={0x89,0xd0},jne[]={0x75,0x10};
        (void)of_emit(&f,0x1000,nop,1,a,0x1001);uint32_t pc=0x1001;InsnAux read=a;
        of_read(&read,0x3000,-12345U);seq[count++]=of_emit(&f,pc,load_n,sizeof(load_n),read,pc+sizeof(load_n));
        pc+=sizeof(load_n);a.reg_vals[0]=-12345U;read=a;ff_read(&read,0x3004,6,1,true);
        read.mem_reads[0].taint=read.mem_reads[0].effective_taint=1;
        seq[count++]=of_emit(&f,pc,load_d,sizeof(load_d),read,pc+sizeof(load_d));pc+=sizeof(load_d);a.reg_vals[1]=6;
        seq[count++]=of_emit(&f,pc,add,sizeof(add),a,pc+sizeof(add));pc+=sizeof(add);a.reg_vals[1]=7;
        seq[count++]=of_emit(&f,pc,cdq_code,1,a,pc+1);++pc;a.reg_vals[2]=UINT32_MAX;
        seq[count++]=of_emit(&f,pc,div,2,a,pc+2);pc+=2;a.reg_vals[0]=-1763U;a.reg_vals[2]=-4U;
        if(use_remainder) {seq[count++]=of_emit(&f,pc,move_r,2,a,pc+2);pc+=2;a.reg_vals[0]=-4U;}
        uint32_t expected=a.reg_vals[0];uint8_t cmp[]={0x3d,expected,expected>>8,expected>>16,expected>>24};
        seq[count++]=of_emit(&f,pc,cmp,5,a,pc+5);pc+=5;a=alu_after(a,ALU_CMP,32,expected,expected,0,0,false);
        seq[count++]=ff_emit(&f,pc,jne,2,9,0,&a);ff_finish_branch(&f,seq[count-1],pc+2,false);
        uint64_t trigger=of_emit(&f,pc+2,nop,1,a,pc+3);ReplayInput *input=ff_capture(&f,seq,count,trigger);ff_free(&f);
        IrConcolicRead source={.read_seq=1,.address=0x3000,.read_size=5,.count=5,.offsets={0,1,2,3,4},
            .bytes={0xc7,0xcf,0xff,0xff,6},.completed_read=true,.flags_verified=true};
        IrConcolicReadResult result=ir_concolic_read(input,&source,false,NULL);
        if(strcmp(result.status,"OBSERVED")) fprintf(stderr,"five-byte observe %s %s\n",result.status,result.reason);
        CHECK(!strcmp(result.status,"OBSERVED")&&result.replay_lifted_steps==count);
        result=ir_concolic_read(input,&source,true,NULL);
        if(strcmp(result.status,"BOUNDARY_WITNESS")) fprintf(stderr,"five-byte solve %s %s\n",result.status,result.reason);
        CHECK(!strcmp(result.status,"BOUNDARY_WITNESS"));
        uint32_t n=0;for(unsigned i=0;i<4;++i) n|=(uint32_t)result.candidates[i]<<(8*i);
        uint32_t q,r;hardware(n,n>>31?UINT32_MAX:0,(uint32_t)result.candidates[4]+1,&q,&r);
        CHECK((use_remainder?r:q)!=expected);replay_input_destroy(input);
    }
}
int main(void) {
    cdq();unsigned valid=0,faults=0;concrete(&valid,&faults);negatives_and_unknowns();unsigned queries=symbolic();concolic();concolic_five_bytes();
    printf("PASS SIGNED_DIV32: CDQ hardware cases=3072 IDIV hardware cases=%u guard cases=%u SMT queries=%u; aliases/full dividend/faults/SSA/optimization/replay/witness/five-byte free inversions PASS\n",valid,faults,queries);
    return 0;
}
