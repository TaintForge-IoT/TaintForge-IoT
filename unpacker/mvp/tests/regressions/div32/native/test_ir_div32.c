#include "ir_oep_test_helpers.h"
#include "ir_concolic.h"
#include "ir_smt_test_helpers.h"
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/resource.h>
#include <inttypes.h>

static uint32_t rng = 0xd1320001;
static uint32_t rnd(void) {
    rng ^= rng << 13; rng ^= rng >> 17; rng ^= rng << 5; return rng;
}
static void hardware(uint32_t low, uint32_t high, uint32_t divisor,
                     uint32_t *quotient, uint32_t *remainder) {
#if defined(__i386__) || defined(__x86_64__)
    __asm__ volatile("divl %[divisor]" : "+a"(low), "+d"(high)
                     : [divisor] "r"(divisor) : "cc");
    *quotient = low; *remainder = high;
#else
    (void)low; (void)high; (void)divisor; (void)quotient; (void)remainder;
    CHECK(!"DIV32 hardware oracle requires x86");
#endif
}
static IrValueId read_state(AluProgram *p, IrStateId id, unsigned bits) {
    return ir_emit_value(p->module,p->block,(IrInstSpec){.op=IR_OP_READ_STATE,
        .type=ir_type_bv(bits),.state=id});
}
static void keep_gpr(AluProgram *p) {
    for (unsigned j=0;j<8;++j) CHECK(ir_module_add_output(p->module,read_state(p,p->state.gpr[j],32)));
}
static unsigned concrete(void) {
    unsigned count=0;
    for (unsigned reg=0;reg<8;++reg) {
        uint8_t code[]={0xf7,(uint8_t)(0xf0+reg)};
        AluProgram p=alu_program(code,sizeof(code),0x80490b4);
        CHECK(p.lift.status==IR_X86_LIFT_OK && p.lift.gpr_writes==5 && !p.lift.memory_count);
        CHECK(p.lift.flags_written==0x3f && p.lift.flags_undefined==0x3f);
        keep_gpr(&p); alu_end(&p);
        for (unsigned phase=0;phase<3;++phase) {
            if(phase==1) CHECK(ir_trace_ssa(p.module,NULL).analysis.status==IR_OK);
            if(phase==2) CHECK(ir_optimize(p.module,NULL).status==IR_OK);
            for (unsigned i=0;i<1024;++i) {
                AluInputs in={.eflags=(i&1)?0xcd7:0x202};
                for(unsigned j=0;j<8;++j) in.gpr[j]=rnd();
                uint32_t d=i<16 ? (i?i:UINT32_MAX) : rnd()|1U;
                in.gpr[0]=i%4==0?UINT32_MAX:rnd(); in.gpr[2]=i%4==0?d-1:rnd()%d;
                if(reg==0) { in.gpr[0]=d; in.gpr[2]=rnd()%d; }
                else if(reg==2) { in.gpr[2]=d; }
                else in.gpr[reg]=d;
                IrBindings b={.user=&in,.read_bv=alu_binding};
                IrEval *e=ir_eval_create(p.module,&b,NULL); CHECK(e);
                IrEvalResult result=ir_eval_run(e);
                if(reg==2) {
                    CHECK(result.status==IR_EVAL_UNKNOWN && (result.reasons&IR_REASON_GUARD));
                    CHECK(alu_state(e,p.state.gpr[0],32)==in.gpr[0]);
                    CHECK(alu_state(e,p.state.gpr[2],32)==in.gpr[2]);
                } else {
                    uint32_t q,r; hardware(in.gpr[0],in.gpr[2],in.gpr[reg],&q,&r);
                    uint64_t n=((uint64_t)in.gpr[2]<<32)|in.gpr[0];
                    CHECK(q==n/in.gpr[reg] && r==n%in.gpr[reg]);
                    CHECK(result.status==IR_EVAL_FRAGMENT_END);
                    for(unsigned j=0;j<8;++j)
                        CHECK(alu_state(e,p.state.gpr[j],32)==(j==0?q:j==2?r:in.gpr[j]));
                    CHECK(alu_state(e,p.state.flags[6],1)==((in.eflags>>10)&1));
                    for(unsigned j=0;j<6;++j) {
                        IrBits v=ir_eval_state(e,p.state.flags[j]).bits;
                        CHECK(!v.known_mask && (v.reasons&IR_REASON_UNDEFINED));
                    }
                    ++count;
                }
                ir_eval_destroy(e);
            }
        }
        ir_module_destroy(p.module);
    }
    return count;
}
static void faults_and_unknowns(void) {
    const uint8_t code[]={0xf7,0xf1};
    AluProgram p=alu_program(code,sizeof(code),0x1000);keep_gpr(&p);alu_end(&p);
    for(unsigned phase=0;phase<3;++phase) {
        if(phase==1) CHECK(ir_trace_ssa(p.module,NULL).analysis.status==IR_OK);
        if(phase==2) CHECK(ir_optimize(p.module,NULL).status==IR_OK);
        for(unsigned i=0;i<7;++i) {
            AluInputs in={.gpr={2000,3,0},.eflags=0xcd7};
            if(i==0) in.gpr[1]=0;
            if(i==1) in.gpr[2]=3;
            if(i==2) in.gpr[2]=UINT32_MAX;
            if(i>=3 && i<=5) in.unknown_gpr=1U<<(i-3);
            if(i==6) in.unknown_flags=0x7f;
            IrBindings b={.user=&in,.read_bv=alu_binding};IrEval *e=ir_eval_create(p.module,&b,NULL);CHECK(e);
            IrEvalResult r=ir_eval_run(e);
            CHECK(r.status==IR_EVAL_UNKNOWN);
            if(i<3) {
                CHECK((r.reasons&IR_REASON_GUARD) && alu_state(e,p.state.gpr[0],32)==2000);
                CHECK(alu_state(e,p.state.gpr[2],32)==in.gpr[2]);
                CHECK(!ir_eval_state(e,p.state.flags[0]).bits.known_mask);
            }
            if(i==3) CHECK(!ir_eval_state(e,p.state.gpr[0]).bits.known_mask);
            if(i==6) CHECK(!ir_eval_state(e,p.state.flags[6]).bits.known_mask);
            ir_eval_destroy(e);
        }
    }
    ir_module_destroy(p.module);
    /* Native fault verification is isolated in children; no signal recovery
     * or undefined C division, and no core dumps. */
    for(unsigned i=0;i<3;++i) {
        pid_t child=fork();CHECK(child>=0);
        if(!child) {
            struct rlimit limit={0,0};(void)setrlimit(RLIMIT_CORE,&limit);
            (void)signal(SIGFPE,SIG_DFL);
            uint32_t q,r;hardware(0xffffffff,i?3:0,i?3:0,&q,&r);_exit(77);
        }
        int status;CHECK(waitpid(child,&status,0)==child);
        CHECK(WIFSIGNALED(status)&&WTERMSIG(status)==SIGFPE);
    }
}
static void unsupported(void) {
    static const uint8_t bytes[][4]={{0xf6,0xf1},{0x66,0xf7,0xf1},{0xf7,0x31},
        {0xf7,0xf9},{0xf3,0xf7,0xf1},{0xf2,0xf7,0xf1},{0xf0,0xf7,0xf1}};
    const unsigned sizes[]={2,3,2,2,3,3,3};
    for(unsigned i=0;i<sizeof(sizes)/sizeof(*sizes);++i) {
        FrontFixture f=ff_new(8);InsnAux a=ff_registers();const uint8_t valid[]={0xf7,0xf1};
        uint64_t seq=ff_emit(&f,0x1000,valid,sizeof(valid),0,0,&a);
        const TraceEntry *entry=trace_find_seq(f.trace,seq,NULL);
        InsnDesc d=*trace_insn_desc_get(f.trace,entry->insn_desc_id);
        d.size=sizes[i];memcpy(d.bytes,bytes[i],d.size);
        d.bytes_hash=trace_instruction_bytes_hash(d.bytes,d.size);
        cs_insn *decoded=NULL;size_t n=cs_disasm(f.decoder,d.bytes,d.size,d.pc,1,&decoded);
        if(n) {d.native_insn_id=decoded->id;cs_free(decoded,n);}
        IrModule *m=ir_module_create(NULL);IrBlockId b=ir_block_add(m);
        IrX86Frontend *front=ir_x86_frontend_create(m,NULL);CHECK(front);
        unsigned before=ir_module_inst_count(m);
        IrX86LiftResult r=ir_x86_lift(front,b,&d,(IrOrigin){.has_trace_identity=true,
            .seq_id=seq,.descriptor_id=d.desc_id,.pc=d.pc});
        CHECK(r.status!=IR_X86_LIFT_OK && ir_module_inst_count(m)==before);
        ir_x86_frontend_destroy(front);ir_module_destroy(m);ff_free(&f);
    }
}
static unsigned bitvectors(void) {
    unsigned count=0;
    for(unsigned w=1;w<=64;++w) for(unsigned which=0;which<2;++which) {
        for(unsigned mode=0;mode<4;++mode) {
            TestIr t=ti_new();uint64_t mask=ir_width_mask(w);
            uint64_t a=(((uint64_t)rnd()<<32)|rnd())&mask;
            uint64_t b=(mode==0?0:mode==1?1:mode==2?mask:rnd())&mask;
            IrValueId x=ti_const(t,w,a),y=ti_const(t,w,b);
            IrOpcode op=which?IR_OP_UREM:IR_OP_UDIV;
            IrValueId value=ir_emit_value(t.m,t.b,(IrInstSpec){.op=op,.type=ir_type_bv(w),.args={x,y}});
            CHECK(value && ir_module_add_output(t.m,value));ti_end(t);
            uint64_t expected=which?(b?a%b:a):(b?a/b:mask);
            for(unsigned phase=0;phase<2;++phase) {
                if(phase) CHECK(ir_optimize(t.m,NULL).status==IR_OK);
                IrEval *e=ir_eval_create(t.m,NULL,NULL);CHECK(e);
                CHECK(ir_eval_run(e).status==IR_EVAL_FRAGMENT_END);
                IrBits bits=ir_eval_value(e,value).bits;
                CHECK(ir_bits_complete(bits,w)&&bits.value==expected);ir_eval_destroy(e);
                IrSmt *s=sm_build(t,NULL,NULL);sm_expect(s,value,w,expected,IR_SMT_SAT);
                sm_expect(s,value,w,expected^1,IR_SMT_UNSAT);ir_smt_destroy(s);count+=2;
            }
            ir_module_destroy(t.m);
        }
    }
    return count;
}

static unsigned symbolic(void) {
    FrontFixture f=ff_new(8);InsnAux a=of_registers();const uint8_t div[]={0xf7,0xf1};
    uint64_t seq=ff_emit(&f,0x1000,div,sizeof(div),9,0,&a);
    const TraceEntry *entry=trace_find_seq(f.trace,seq,NULL);
    const InsnDesc *d=trace_insn_desc_get(f.trace,entry->insn_desc_id);
    AluProgram p={.module=ir_module_create(NULL)};CHECK(p.module);
    IrX86Frontend *front=ir_x86_frontend_create(p.module,NULL);CHECK(front);
    p.state=*ir_x86_frontend_state(front);p.block=ir_block_add(p.module);
    IrValueId inputs[3];
    for(unsigned i=0;i<3;++i) {
        inputs[i]=ir_emit_value(p.module,p.block,(IrInstSpec){.op=IR_OP_INPUT,
            .type=ir_type_bv(32),.immediate=0xd100+i});
        CHECK(ir_emit_effect(p.module,p.block,(IrInstSpec){.op=IR_OP_WRITE_STATE,
            .type=ir_type_void(),.state=p.state.gpr[i],.args={inputs[i]}}));
    }
    CHECK(ir_emit_effect(p.module,p.block,(IrInstSpec){.op=IR_OP_WRITE_STATE,
        .type=ir_type_void(),.state=p.state.flags[6],.args={ir_emit_value(p.module,p.block,
            (IrInstSpec){.op=IR_OP_CONST,.type=ir_type_bv(1),.immediate=1})}}));
    p.lift=ir_x86_lift(front,p.block,d,(IrOrigin){.has_trace_identity=true,
        .seq_id=seq,.descriptor_id=d->desc_id,.pc=d->pc,.code_generation=9});
    CHECK(p.lift.status==IR_X86_LIFT_OK);ir_x86_frontend_destroy(front);ff_free(&f);
    IrValueId q=read_state(&p,p.state.gpr[0],32),r=read_state(&p,p.state.gpr[2],32);
    IrValueId flags[7];for(unsigned i=0;i<7;++i) {
        flags[i]=read_state(&p,p.state.flags[i],1);CHECK(ir_module_add_output(p.module,flags[i]));
    }
    CHECK(ir_module_add_output(p.module,q)&&ir_module_add_output(p.module,r));alu_end(&p);
    unsigned count=0;
    for(unsigned phase=0;phase<3;++phase) {
        if(phase==1) CHECK(ir_trace_ssa(p.module,NULL).analysis.status==IR_OK);
        if(phase==2) CHECK(ir_optimize(p.module,NULL).status==IR_OK);
        IrSmtParameter parameters[3];
        for(unsigned i=0;i<3;++i) parameters[i]=(IrSmtParameter){.key=0xd100+i,
            .width=32,.symbolic=true,.observed=ir_bits_known(i==0?2000:i==1?3:0,32)};
        IrSmtOptions options=ir_smt_default_options();options.parameters=parameters;options.parameter_count=3;
        IrSmtInfo info;IrSmt *s=ir_smt_build(p.module,NULL,&options,&info);CHECK(s);
        for(unsigned i=0;i<5;++i) {
            IrSmtConstraint c[3]={{inputs[2],0,UINT32_MAX},{inputs[1],3,UINT32_MAX},
                {i&1?r:q,i==0?0:i==1?1:i==2?666:i==3?2:1000000000,UINT32_MAX}};
            IrSmtAnswer answer=ir_smt_query(s,c,3,NULL,0,NULL);sm_status(&answer,IR_SMT_SAT);
            uint32_t v[3]={0};for(unsigned j=0;j<answer.parameter_count;++j)
                v[answer.parameters[j].key-0xd100]=answer.parameters[j].value;
            CHECK(v[1]==3 && v[2]==0);uint32_t quotient,remainder;hardware(v[0],v[2],v[1],&quotient,&remainder);
            CHECK((i&1?remainder:quotient)==c[2].expected);
            ir_smt_answer_destroy(&answer);++count;
        }
        for(unsigned mode=0;mode<3;++mode) {
            IrSmtConstraint c[3]={{inputs[1],mode?3:0,UINT32_MAX},
                {inputs[2],mode==1?3:mode==2?UINT32_MAX:0,UINT32_MAX},{q,0,UINT32_MAX}};
            IrSmtAnswer answer=ir_smt_query(s,c,3,NULL,0,NULL);sm_status(&answer,IR_SMT_UNSAT);
            ir_smt_answer_destroy(&answer);++count;
        }
        for(unsigned i=0;i<6;++i) {sm_expect(s,flags[i],1,0,IR_SMT_UNKNOWN);++count;}
        sm_expect(s,flags[6],1,1,IR_SMT_SAT);++count;
        ir_smt_destroy(s);
    }
    ir_module_destroy(p.module);return count;
}

static ReplayInput *concolic_fixture(unsigned mode) {
    FrontFixture f=ff_new(16);InsnAux a=of_registers();a.reg_vals[0]=2000;a.reg_vals[2]=0;
    const uint8_t nop[]={0x90},load[]={0x0f,0xb6,0x0d,0x00,0x30,0x00,0x00},
        div[]={0xf7,0xf1},div16[]={0x66,0xf7,0xf1},
        cmp[]={0x3d,0x9a,0x02,0x00,0x00},jne[]={0x75,0x10};
    (void)of_emit(&f,0x1000,nop,1,a,0x1001);
    InsnAux read=a;ff_read(&read,0x3000,3,1,true);
    read.mem_reads[0].taint=read.mem_reads[0].effective_taint=1;
    uint64_t seq[4];seq[0]=of_emit(&f,0x1001,load,sizeof(load),read,0x1008);
    a.reg_vals[1]=3;unsigned size=mode==1?sizeof(div16):sizeof(div);
    seq[1]=of_emit(&f,0x1008,mode==1?div16:div,size,a,0x1008+size);
    a.reg_vals[0]=mode==2?667:666;a.reg_vals[2]=2;
    uint32_t pc=0x1008+size;seq[2]=of_emit(&f,pc,cmp,sizeof(cmp),a,pc+sizeof(cmp));
    a=alu_after(a,ALU_CMP,32,a.reg_vals[0],666,0,0,false);pc+=sizeof(cmp);
    seq[3]=ff_emit(&f,pc,jne,sizeof(jne),9,0,&a);ff_finish_branch(&f,seq[3],pc+2,false);
    uint64_t trigger=of_emit(&f,pc+2,nop,1,a,pc+3);
    ReplayInput *input=ff_capture(&f,seq,4,trigger);ff_free(&f);return input;
}
static void concolic(void) {
    IrConcolicRead source={.read_seq=1,.address=0x3000,.read_size=1,.count=1,
        .bytes={3},.completed_read=true,.flags_verified=true};
    for(unsigned mode=0;mode<3;++mode) {
        ReplayInput *input=concolic_fixture(mode);
        IrConcolicReadResult result=ir_concolic_read(input,&source,false,NULL);
        CHECK(result.replay_build_attempted);
        if(mode==1) {
            CHECK(!strcmp(result.status,"UNKNOWN")&&!strcmp(result.reason,"replay_incomplete"));
            CHECK(result.replay_build_status==IR_REPLAY_UNKNOWN && result.replay_lifted_steps==1);
            CHECK(result.replay_stopped_origin.pc==0x1008 && result.replay_stopped_bytes[0]==0x66);
        } else if(mode==2) {
            CHECK(!strcmp(result.status,"UNKNOWN")&&!strcmp(result.reason,"baseline_observations"));
        } else {
            if(strcmp(result.status,"OBSERVED")) fprintf(stderr,"DIV observe: %s %s\n",result.status,result.reason);
            CHECK(!strcmp(result.status,"OBSERVED")&&result.replay_lifted_steps==4);
            result=ir_concolic_read(input,&source,true,NULL);
            if(strcmp(result.status,"BOUNDARY_WITNESS")) fprintf(stderr,"DIV solve: %s %s\n",result.status,result.reason);
            CHECK(!strcmp(result.status,"BOUNDARY_WITNESS")&&result.candidates[0]&&result.candidates[0]!=3);
            uint32_t q,r;hardware(2000,0,result.candidates[0],&q,&r);CHECK(q!=666);
        }
        replay_input_destroy(input);
    }
}

static void prefix_forms(const char *path) {
    FILE *file=fopen(path,"r");CHECK(file);char line[256];
    IrModule *module=NULL;IrX86Frontend *front=NULL;IrBlockId block=0;
    csh decoder;CHECK(cs_open(CS_ARCH_X86,CS_MODE_32,&decoder)==CS_ERR_OK);
    unsigned prefixes=0,instructions=0,divisions=0;
    while(fgets(line,sizeof(line),file)) {
        if(line[0]=='#') {
            ir_x86_frontend_destroy(front);ir_module_destroy(module);
            module=ir_module_create(NULL);CHECK(module);block=ir_block_add(module);
            IrX86Options options={.flat32_ram=true};front=ir_x86_frontend_create(module,&options);CHECK(front);
            ++prefixes;continue;
        }
        uint64_t seq,pc;char hex[31];CHECK(sscanf(line,"%" SCNu64 " %" SCNx64 " %30s",&seq,&pc,hex)==3);
        InsnDesc d={.desc_id=seq,.pc=pc,.arch=TRACE_ARCH_X86,.mode=TRACE_MODE_32,.size=strlen(hex)/2};
        for(unsigned i=0;i<d.size;++i) {unsigned byte;CHECK(sscanf(hex+2*i,"%2x",&byte)==1);d.bytes[i]=byte;}
        d.bytes_hash=trace_instruction_bytes_hash(d.bytes,d.size);
        cs_insn *decoded=NULL;size_t n=cs_disasm(decoder,d.bytes,d.size,d.pc,1,&decoded);CHECK(n==1);
        d.native_insn_id=decoded->id;cs_free(decoded,n);
        IrX86LiftResult r=ir_x86_lift(front,block,&d,(IrOrigin){.has_trace_identity=true,
            .seq_id=seq,.descriptor_id=seq,.pc=pc});
        if(r.status!=IR_X86_LIFT_OK) fprintf(stderr,"prefix stop seq=%llu pc=%llx bytes=%s status=%u\n",
            (unsigned long long)seq,(unsigned long long)pc,hex,r.status);
        CHECK(r.status==IR_X86_LIFT_OK);++instructions;
        if(d.size==2&&d.bytes[0]==0xf7&&d.bytes[1]==0xf1) ++divisions;
    }
    ir_x86_frontend_destroy(front);ir_module_destroy(module);cs_close(&decoder);fclose(file);
    CHECK(prefixes==3&&instructions==90&&divisions==3);
    printf("PASS saved instruction forms: prefixes=%u/3 instructions=%u/90 DIVs=%u/3; form lifting only, no historical GPR/memory replay\n",prefixes,instructions,divisions);
}

int main(int argc,char **argv) {
    if(argc==2) {prefix_forms(argv[1]);return 0;}CHECK(argc==1);
    unsigned cases=concrete();faults_and_unknowns();unsupported();unsigned queries=bitvectors()+symbolic();concolic();
    printf("PASS DIV32: hardware_comparisons=%u; bitvector_smt_queries=%u; aliases, faults, undefined flags, SSA/optimization, replay and concolic witness PASS\n",cases,queries);
    return 0;
}
