#include "ir_oep_test_helpers.h"
#include "ir_concolic.h"
#include "ir_smt_test_helpers.h"

static uint32_t rng = 0x6d756c32;
static uint32_t random32(void) { rng ^= rng << 13; rng ^= rng >> 17; rng ^= rng << 5; return rng; }
static const uint32_t edges[] = {0,1,2,3,0xffff,0x10000,0x10001,0x7fffffff,0x80000000,0xfffffffe,0xffffffff};
static uint64_t reference(uint32_t a, uint32_t b) { return (uint64_t)a * b; }
static uint64_t hardware(uint32_t a, uint32_t b, uint32_t initial, bool memory, uint64_t *flags) {
    uint32_t low = a, high; uint64_t saved, after, before = initial;
    if (memory) {
        __asm__ volatile("pushfq\n\tpopq %[saved]\n\tpushq %[before]\n\tpopfq\n\t"
            "mull (%[source])\n\tpushfq\n\tpopq %[after]\n\tpushq %[saved]\n\tpopfq"
            : "+&a"(low), "=&d"(high), [saved]"=&r"(saved), [after]"=&r"(after)
            : [source]"r"(&b), [before]"r"(before) : "cc", "memory");
    } else {
        __asm__ volatile("pushfq\n\tpopq %[saved]\n\tpushq %[before]\n\tpopfq\n\t"
            "mull %[source]\n\tpushfq\n\tpopq %[after]\n\tpushq %[saved]\n\tpopfq"
            : "+&a"(low), "=&d"(high), [saved]"=&r"(saved), [after]"=&r"(after)
            : [source]"r"(b), [before]"r"(before) : "cc", "memory");
    }
    *flags = after; return ((uint64_t)high << 32) | low;
}
static IrValueId state(AluProgram *p, IrStateId id, unsigned width) {
    return ir_emit_value(p->module,p->block,(IrInstSpec){.op=IR_OP_READ_STATE,.type=ir_type_bv(width),.state=id});
}
static void keep(AluProgram *p) {
    for (unsigned r=0;r<8;++r) CHECK(ir_module_add_output(p->module,state(p,p->state.gpr[r],32)));
    if (p->lift.reads_memory) {
        CHECK(ir_module_add_output(p->module,p->lift.address));
        CHECK(ir_module_add_output(p->module,p->lift.read_data));
    }
}
typedef struct { AluInputs regs; uint32_t address, word; bool unknown_word; unsigned reads; } MemoryInputs;
static IrBits binding(void *user, IrBindingKind kind, uint64_t key, uint8_t width) {
    return alu_binding(&((MemoryInputs *)user)->regs,kind,key,width);
}
static IrBits byte_binding(void *user, IrBindingKind kind, uint64_t key, uint64_t address) {
    MemoryInputs *in=user; ++in->reads;
    uint32_t offset=(uint32_t)address-in->address;
    if (kind!=IR_BIND_STATE || key!=IR_X86_MEMORY_KEY || offset>=4 || in->unknown_word)
        return ir_bits_unknown(IR_REASON_MEMORY);
    return ir_bits_known((in->word>>(offset*8))&255,8);
}
typedef struct { uint8_t code[8]; unsigned size; int base, index; unsigned scale; uint32_t displacement; } MemoryForm;
static const MemoryForm forms[] = {
    {{0xf7,0x20},2,0,-1,1,0}, {{0xf7,0x21},2,1,-1,1,0},
    {{0xf7,0x22},2,2,-1,1,0}, {{0xf7,0x23},2,3,-1,1,0},
    {{0xf7,0x24,0x24},3,4,-1,1,0}, {{0xf7,0x65,0},3,5,-1,1,0},
    {{0xf7,0x26},2,6,-1,1,0}, {{0xf7,0x27},2,7,-1,1,0},
    {{0xf7,0x25,0xef,0xbe,0xad,0x0b},6,-1,-1,1,0x0badbeef},
    {{0xf7,0x64,0x90,0x10},4,0,2,4,0x10},
    {{0xf7,0x64,0x42,0xf0},4,2,0,2,0xfffffff0},
    {{0xf7,0xa4,0xc0,0x78,0x56,0x34,0x12},7,0,0,8,0x12345678},
    {{0xf7,0xa4,0xd2,0x78,0x56,0x34,0x12},7,2,2,8,0x12345678},
    {{0xf7,0x24,0x8d,0x78,0x56,0x34,0x12},7,-1,1,4,0x12345678},
    {{0xf7,0xa7,0x78,0x56,0x34,0x12},6,7,-1,1,0x12345678},
    {{0xf7,0x64,0xf5,0xff},4,5,6,8,0xffffffff}
};
static unsigned concrete(void) {
    unsigned count=0, memory_count=sizeof(forms)/sizeof(*forms);
    for (unsigned form=0;form<8+memory_count;++form) {
        bool memory=form>=8; uint8_t reg[]={0xf7,(uint8_t)(0xe0+form)};
        const MemoryForm *mem=memory?&forms[form-8]:NULL;
        AluProgram p=alu_program(memory?mem->code:reg,memory?mem->size:2,0x1000);
        CHECK(p.lift.status==IR_X86_LIFT_OK && p.lift.gpr_writes==5 && p.lift.flags_written==0x3f && p.lift.flags_undefined==0x1e);
        CHECK(p.lift.reads_memory==memory && !p.lift.writes_memory && p.lift.memory_count==(unsigned)memory);
        if (memory) CHECK(p.lift.memory_bytes==4 && !p.lift.memory[0].write && p.lift.memory[0].bytes==4);
        keep(&p); alu_end(&p);
        for (unsigned phase=0;phase<3;++phase) {
            if (phase==1) CHECK(ir_trace_ssa(p.module,NULL).analysis.status==IR_OK);
            if (phase==2) CHECK(ir_optimize(p.module,NULL).status==IR_OK);
            for (unsigned i=0;i<512;++i) {
                MemoryInputs in={.regs={.eflags=i&1?0xcd7:0x202}};
                for (unsigned r=0;r<8;++r) in.regs.gpr[r]=random32();
                in.regs.gpr[0]=i<121?edges[i/11]:random32();
                uint32_t b=i<121?edges[i%11]:random32();
                if (memory) {
                    in.address=mem->displacement;
                    if (mem->base>=0) in.address+=in.regs.gpr[mem->base];
                    if (mem->index>=0) in.address+=in.regs.gpr[mem->index]*mem->scale;
                    in.word=b;
                } else {
                    if (form!=0) in.regs.gpr[form]=b;
                    b=in.regs.gpr[form];
                }
                uint64_t flags, product=hardware(in.regs.gpr[0],b,in.regs.eflags,memory,&flags);
                CHECK(product==reference(in.regs.gpr[0],b));
                IrBindings bindings={.user=&in,.read_bv=binding,.read_byte=byte_binding};
                IrEval *e=ir_eval_create(p.module,&bindings,NULL); CHECK(e);
                CHECK(ir_eval_run(e).status==IR_EVAL_FRAGMENT_END);
                for (unsigned r=0;r<8;++r)
                    CHECK(alu_state(e,p.state.gpr[r],32)==(r==0?(uint32_t)product:r==2?(uint32_t)(product>>32):in.regs.gpr[r]));
                for (unsigned f=0;f<7;++f) {
                    IrBits bits=ir_eval_state(e,p.state.flags[f]).bits;
                    if (f>=1 && f<=4) CHECK(!bits.known_mask && (bits.reasons&IR_REASON_UNDEFINED));
                    else {
                        unsigned expected=f==6?((in.regs.eflags>>10)&1):(product>>32)!=0;
                        CHECK(expected==((flags>>alu_flag_bits[f])&1));
                        CHECK(ir_bits_complete(bits,1) && bits.value==expected);
                    }
                }
                if (memory) {
                    IrBits address=ir_eval_value(e,p.lift.address).bits, data=ir_eval_value(e,p.lift.read_data).bits;
                    CHECK(ir_bits_complete(address,32) && address.value==in.address);
                    CHECK(ir_bits_complete(data,32) && data.value==in.word && in.reads==4);
                    IrBits unchanged=ir_eval_load(e,ir_eval_state(e,p.state.memory),in.address,32,IR_ENDIAN_LE);
                    CHECK(ir_bits_complete(unchanged,32) && unchanged.value==in.word);
                } else CHECK(!in.reads);
                ir_eval_destroy(e); ++count;
            }
        }
        ir_module_destroy(p.module);
    }
    return count;
}
static void unknowns(void) {
    for (unsigned memory=0;memory<2;++memory) {
        const uint8_t reg[]={0xf7,0xe1}, mem[]={0xf7,0x22};
        AluProgram p=alu_program(memory?mem:reg,2,0x1000);keep(&p);alu_end(&p);
        for (unsigned phase=0;phase<3;++phase) {
            if (phase==1) CHECK(ir_trace_ssa(p.module,NULL).analysis.status==IR_OK);
            if (phase==2) CHECK(ir_optimize(p.module,NULL).status==IR_OK);
            for (unsigned mode=0;mode<6;++mode) {
                MemoryInputs in={.regs={.gpr={0,0,0x3000},.eflags=0xcd7},.address=0x3000};
                in.regs.gpr[0]=mode==0?0:mode==1?1:mode==2?0x80000000:mode==3?9:5;
                in.word=in.regs.gpr[1]=mode==4?0:mode==5?1:7;
                if (mode<3) { if (memory) in.unknown_word=true; else in.regs.unknown_gpr=2; }
                else if (mode==3) in.regs.unknown_flags=0x7f;
                else in.regs.unknown_gpr=1;
                IrBindings b={.user=&in,.read_bv=binding,.read_byte=byte_binding}; IrEval *e=ir_eval_create(p.module,&b,NULL); CHECK(e);
                CHECK(ir_eval_run(e).status==(mode==4?IR_EVAL_FRAGMENT_END:IR_EVAL_UNKNOWN));
                if (mode==0 || mode==4) {
                    CHECK(!alu_state(e,p.state.gpr[0],32) && !alu_state(e,p.state.gpr[2],32));
                    CHECK(!alu_state(e,p.state.flags[0],1) && !alu_state(e,p.state.flags[5],1));
                } else if (mode==1 || mode==5) {
                    CHECK(!ir_bits_complete(ir_eval_state(e,p.state.gpr[0]).bits,32));
                    CHECK(!alu_state(e,p.state.gpr[2],32) && !alu_state(e,p.state.flags[0],1));
                } else if (mode==2) CHECK(!ir_bits_complete(ir_eval_state(e,p.state.gpr[2]).bits,32));
                else {
                    CHECK(alu_state(e,p.state.gpr[0],32)==63 && !alu_state(e,p.state.gpr[2],32));
                    CHECK(!ir_eval_state(e,p.state.flags[6]).bits.known_mask);
                }
                ir_eval_destroy(e);
            }
        }
        ir_module_destroy(p.module);
    }
}
static void negative_and_guarded(void) {
    const uint8_t bytes[][5]={{0xf6,0xe1},{0x66,0xf7,0xe1},{0x67,0xf7,0x22},{0xf2,0xf7,0xe1},
        {0xf3,0xf7,0xe1},{0xf0,0xf7,0x22},{0x2e,0xf7,0x22},{0x64,0xf7,0x22},{0xf7,0xe9},{0xf7,0x22},{0xf7}};
    const unsigned sizes[]={2,3,3,3,3,3,3,3,2,2,1};
    for (unsigned i=0;i<sizeof(sizes)/sizeof(*sizes);++i) {
        FrontFixture f=ff_new(8); InsnAux a=ff_registers(); const uint8_t valid[]={0xf7,0xe1};
        uint64_t seq=ff_emit(&f,0x1000,valid,2,9,0,&a); const TraceEntry *entry=trace_find_seq(f.trace,seq,NULL);
        InsnDesc d=*trace_insn_desc_get(f.trace,entry->insn_desc_id);d.size=sizes[i];memcpy(d.bytes,bytes[i],d.size);
        d.bytes_hash=trace_instruction_bytes_hash(d.bytes,d.size); cs_insn *decoded=NULL;
        size_t n=cs_disasm(f.decoder,d.bytes,d.size,d.pc,1,&decoded);
        if (n) {d.native_insn_id=decoded->id;cs_free(decoded,n);}
        IrModule *m=ir_module_create(NULL);IrBlockId b=ir_block_add(m);IrX86Frontend *front=ir_x86_frontend_create(m,NULL);CHECK(front);
        IrX86LiftResult r=ir_x86_lift(front,b,&d,(IrOrigin){.has_trace_identity=true,.seq_id=seq,.descriptor_id=d.desc_id,.pc=d.pc,.code_generation=9});
        CHECK(r.status!=IR_X86_LIFT_OK && !ir_module_inst_count(m));
        if (i==9) CHECK(r.status==IR_X86_LIFT_MEMORY_MODEL);
        ir_x86_frontend_destroy(front);ir_module_destroy(m);ff_free(&f);
    }
    for (unsigned mode=0;mode<3;++mode) {
        FrontFixture f=ff_new(8);InsnAux a=ff_registers();const uint8_t code[]={0xf7,0x22};
        uint64_t seq=ff_emit(&f,0x1000,code,2,9,0,&a);const TraceEntry *entry=trace_find_seq(f.trace,seq,NULL);
        const InsnDesc *d=trace_insn_desc_get(f.trace,entry->insn_desc_id);
        AluProgram p={.module=ir_module_create(NULL)};IrX86Options options={.flat32_ram=true};
        IrX86Frontend *front=ir_x86_frontend_create(p.module,&options);CHECK(front);
        p.state=*ir_x86_frontend_state(front);p.block=ir_block_add(p.module);
        if (mode==0) CHECK(ir_x86_exclude_memory(front,0x3002,0x3003)==IR_OK);
        else CHECK(ir_x86_protect_memory(front,0x3000,0x3004,mode==1?IR_X86_ACCESS_WRITE:IR_X86_ACCESS_READ)==IR_OK);
        p.lift=ir_x86_lift(front,p.block,d,(IrOrigin){.has_trace_identity=true,.seq_id=seq,.descriptor_id=d->desc_id,.pc=d->pc,.code_generation=9});
        CHECK(p.lift.status==IR_X86_LIFT_OK);keep(&p);alu_end(&p);ir_x86_frontend_destroy(front);ff_free(&f);
        for (unsigned phase=0;phase<3;++phase) {
            if (phase==1) CHECK(ir_trace_ssa(p.module,NULL).analysis.status==IR_OK);
            if (phase==2) CHECK(ir_optimize(p.module,NULL).status==IR_OK);
            MemoryInputs in={.regs={.gpr={3,0,0x3000},.eflags=0x202},.address=0x3000,.word=5};
            IrBindings b={.user=&in,.read_bv=binding,.read_byte=byte_binding};IrEval *e=ir_eval_create(p.module,&b,NULL);CHECK(e);
            IrEvalResult r=ir_eval_run(e);CHECK(r.status==(mode==2?IR_EVAL_FRAGMENT_END:IR_EVAL_UNKNOWN));
            CHECK(alu_state(e,p.state.gpr[0],32)==(mode==2?15:3));
            CHECK(alu_state(e,p.state.gpr[2],32)==(mode==2?0:0x3000));
            if (mode<2) CHECK((r.reasons&IR_REASON_MEMORY) && !in.reads);
            ir_eval_destroy(e);
        }
        ir_module_destroy(p.module);
    }
}
static IrValueId constant(AluProgram *p, unsigned width, uint64_t value) {
    return ir_emit_value(p->module,p->block,(IrInstSpec){.op=IR_OP_CONST,.type=ir_type_bv(width),.immediate=value});
}
static void write_state(AluProgram *p, IrStateId id, IrValueId value) {
    CHECK(ir_emit_effect(p->module,p->block,(IrInstSpec){.op=IR_OP_WRITE_STATE,.type=ir_type_void(),.state=id,.args={value}}));
}
static unsigned symbolic(void) {
    unsigned queries=0;
    for (unsigned form=0;form<10;++form) {
        bool memory=form>=8; uint8_t code[]={0xf7,(uint8_t)(0xe0+form),0x82};
        unsigned size=2;if (form==8) code[1]=0x22;
        if (form==9) {code[1]=0x24;size=3;}
        FrontFixture f=ff_new(8);InsnAux a=of_registers();uint64_t seq=ff_emit(&f,0x1000,code,size,9,0,&a);
        const TraceEntry *entry=trace_find_seq(f.trace,seq,NULL);const InsnDesc *d=trace_insn_desc_get(f.trace,entry->insn_desc_id);
        AluProgram p={.module=ir_module_create(NULL)};IrX86Options options={.flat32_ram=true};
        IrX86Frontend *front=ir_x86_frontend_create(p.module,&options);CHECK(front);
        p.state=*ir_x86_frontend_state(front);p.block=ir_block_add(p.module);IrValueId inputs[2];
        for (unsigned i=0;i<2;++i) {
            inputs[i]=ir_emit_value(p.module,p.block,(IrInstSpec){.op=IR_OP_INPUT,.type=ir_type_bv(32),.immediate=0x6d10+i});
            CHECK(ir_module_add_output(p.module,inputs[i]));
        }
        for (unsigned i=0;i<8;++i) write_state(&p,p.state.gpr[i],constant(&p,32,0x3000+i));
        write_state(&p,p.state.gpr[0],inputs[0]);
        for (unsigned i=0;i<7;++i) write_state(&p,p.state.flags[i],constant(&p,1,1));
        if (memory) {
            write_state(&p,p.state.gpr[2],constant(&p,32,0x3000));
            IrValueId address=constant(&p,32,0x3000);
            if (form==9) address=ir_emit_value(p.module,p.block,(IrInstSpec){.op=IR_OP_ADD,.type=ir_type_bv(32),.args={address,
                ir_emit_value(p.module,p.block,(IrInstSpec){.op=IR_OP_MUL,.type=ir_type_bv(32),.args={inputs[0],constant(&p,32,4)}})}});
            CHECK(ir_x86_memory_write(front,p.block,(IrOrigin){0},address,4,inputs[1]));
        } else if (form!=0) write_state(&p,p.state.gpr[form],inputs[1]);
        p.lift=ir_x86_lift(front,p.block,d,(IrOrigin){.has_trace_identity=true,.seq_id=seq,.descriptor_id=d->desc_id,.pc=d->pc,.code_generation=9});
        CHECK(p.lift.status==IR_X86_LIFT_OK);ir_x86_frontend_destroy(front);ff_free(&f);
        IrValueId output[9]={state(&p,p.state.gpr[0],32),state(&p,p.state.gpr[2],32)};
        for (unsigned i=0;i<7;++i) output[i+2]=state(&p,p.state.flags[i],1);
        for (unsigned i=0;i<9;++i) CHECK(ir_module_add_output(p.module,output[i]));
        alu_end(&p);
        for (unsigned phase=0;phase<3;++phase) {
            if (phase==1) CHECK(ir_trace_ssa(p.module,NULL).analysis.status==IR_OK);
            if (phase==2) CHECK(ir_optimize(p.module,NULL).status==IR_OK);
            IrSmtParameter params[2]={{.key=0x6d10,.width=32,.symbolic=true,.observed=ir_bits_known(9,32)},
                {.key=0x6d11,.width=32,.symbolic=true,.observed=ir_bits_known(13,32)}};
            IrSmtOptions opts=ir_smt_default_options();opts.parameters=params;opts.parameter_count=2;
            IrSmt *s=sm_build((TestIr){.m=p.module,.b=p.block},NULL,&opts);
            for (unsigned i=0;i<11;++i) {
                uint32_t x=edges[i], y=edges[10-i];uint64_t product=reference(x,form==0?x:y);
                for (unsigned o=0;o<9;++o) {
                    bool undefined=o>=3 && o<=6;
                    uint64_t expected=o==0?(uint32_t)product:o==1?(uint32_t)(product>>32):o==8?1:(product>>32)!=0;
                    IrSmtConstraint c[3]={{inputs[0],x,UINT32_MAX},{inputs[1],y,UINT32_MAX},{output[o],expected,o<2?UINT32_MAX:1}};
                    IrSmtAnswer answer=ir_smt_query(s,c,3,NULL,0,NULL);
                    if (answer.status!=(undefined?IR_SMT_UNKNOWN:IR_SMT_SAT)) fprintf(stderr,"MUL SMT form=%u phase=%u vector=%u output=%u\n",form,phase,i,o);
                    sm_status(&answer,undefined?IR_SMT_UNKNOWN:IR_SMT_SAT);ir_smt_answer_destroy(&answer);++queries;
                    if (!undefined) {c[2].expected^=1;answer=ir_smt_query(s,c,3,NULL,0,NULL);sm_status(&answer,IR_SMT_UNSAT);ir_smt_answer_destroy(&answer);++queries;}
                }
            }
            IrSmtConstraint free[2]={{output[0],0,UINT32_MAX},{output[1],0,UINT32_MAX}};
            IrSmtAnswer answer=ir_smt_query(s,free,2,NULL,0,NULL);sm_status(&answer,IR_SMT_SAT);uint32_t chosen[2]={9,13};
            for (unsigned i=0;i<answer.parameter_count;++i) {CHECK(answer.parameters[i].key>=0x6d10&&answer.parameters[i].key<=0x6d11);chosen[answer.parameters[i].key-0x6d10]=answer.parameters[i].value;}
            CHECK(!reference(chosen[0],form==0?chosen[0]:chosen[1]));ir_smt_answer_destroy(&answer);++queries;ir_smt_destroy(s);
        }
        ir_module_destroy(p.module);
    }
    return queries;
}
static void initial(unsigned mode, uint32_t *a, uint32_t *b) {
    *a=mode<2?3:mode<4?0x80000000:0xfffffff0;*b=mode<2?5:mode<4?4:3;
}
static ReplayInput *fixture(unsigned mode) {
    bool memory=mode==1||mode==3||mode==6||mode==7||mode==9;
    FrontFixture f=ff_new(32);InsnAux a=of_registers();uint64_t selected[8];unsigned n=0;uint32_t x,y;initial(mode,&x,&y);
    const uint8_t nop[]={0x90}, low[]={0xa1,0,0x30,0,0}, src[]={0x8b,0x0d,4,0x30,0,0}, pointer[]={0xba,4,0x30,0,0};
    (void)of_emit(&f,0x1000,nop,1,a,0x1001);InsnAux read=a;of_read(&read,0x3000,x);
    selected[n++]=of_emit(&f,0x1001,low,5,read,0x1006);a.reg_vals[0]=x;uint32_t pc=0x1006;
    if (memory) {selected[n++]=of_emit(&f,pc,pointer,5,a,pc+5);a.reg_vals[2]=0x3004;pc+=5;}
    else {read=a;of_read(&read,0x3004,y);selected[n++]=of_emit(&f,pc,src,6,read,pc+6);a.reg_vals[1]=y;pc+=6;}
    const uint8_t mulreg[]={0xf7,0xe1}, mulmem[]={0xf7,0x22}, mul16[]={0x66,0xf7,0xe1};
    read=a;if (memory) of_read(&read,0x3004,y);unsigned size=mode==11?3:2;
    selected[n++]=of_emit(&f,pc,mode==11?mul16:memory?mulmem:mulreg,size,read,pc+size);pc+=size;
    uint64_t flags, product=hardware(x,y,a.eflags_before,memory,&flags);a.reg_vals[0]=product;a.reg_vals[2]=product>>32;a.eflags_before=flags;
    if (mode<4) {
        uint32_t value=mode<2?(uint32_t)product:(uint32_t)(product>>32);
        uint8_t cmp[]={0x81,mode<2?0xf8:0xfa,value,value>>8,value>>16,value>>24};
        selected[n++]=of_emit(&f,pc,cmp,6,a,pc+6);a=alu_after(a,ALU_CMP,32,value,value,mode<2?0:2,0,false);pc+=6;
    }
    unsigned flag=mode==4||mode==6?0:mode==5||mode==7?5:mode==9?1:mode==10?4:3;
    uint8_t branch[]={mode<4?0x75:mode==4||mode==6?0x72:mode==5||mode==7?0x70:mode==9?0x7a:mode==10?0x78:0x74,0x10};
    bool taken=mode<4?false:((a.eflags_before>>alu_flag_bits[flag])&1);
    selected[n++]=ff_emit(&f,pc,branch,2,9,0,&a);uint32_t next=pc+(taken?18:2);ff_finish_branch(&f,selected[n-1],next,taken);
    uint64_t trigger=of_emit(&f,next,nop,1,a,next+1);ReplayInput *input=ff_capture(&f,selected,n,trigger);ff_free(&f);return input;
}
static void concolic(void) {
    for (unsigned mode=0;mode<12;++mode) {
        uint32_t x,y;initial(mode,&x,&y);ReplayInput *input=fixture(mode);
        IrConcolicRead source={.read_seq=1,.address=0x3000,.read_size=8,.count=8,.offsets={0,1,2,3,4,5,6,7},
            .bytes={x,x>>8,x>>16,x>>24,y,y>>8,y>>16,y>>24},.completed_read=true,.flags_verified=true};
        for (unsigned solve=0;solve<2;++solve) {
            IrConcolicReadResult r=ir_concolic_read(input,&source,solve,NULL);
            const char *expected=mode>=8?"UNKNOWN":solve?"BOUNDARY_WITNESS":"OBSERVED";
            if (strcmp(r.status,expected)) fprintf(stderr,"MUL mode=%u solve=%u: %s %s\n",mode,solve,r.status,r.reason);
            CHECK(!strcmp(r.status,expected));
            if (solve && mode<8) {
                uint32_t a=0,b=0;for (unsigned i=0;i<4;++i) {a|=(uint32_t)r.candidates[i]<<(8*i);b|=(uint32_t)r.candidates[i+4]<<(8*i);}
                uint64_t fresh=reference(a,b), baseline=reference(x,y);
                if (mode<2) CHECK((uint32_t)fresh!=(uint32_t)baseline);
                else if (mode<4) CHECK((fresh>>32)!=(baseline>>32));
                else CHECK(((fresh>>32)!=0)!=((baseline>>32)!=0));
            }
        }
        replay_input_destroy(input);
    }
}
int main(void) {
    unsigned cases=concrete();unknowns();negative_and_guarded();unsigned queries=symbolic();concolic();
    printf("PASS MUL32: hardware=%u register encodings=8 memory address forms=16 SMT queries=%u; full EDX:EAX/CF/OF/DF/old-address aliases/RAM read guards/IR/SSA/optimization/free symbolic operands/concolic PASS; PF/AF/ZF/SF UNKNOWN\n",cases,queries);
    return 0;
}
