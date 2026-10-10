#include "ir_oep_test_helpers.h"
#include "ir_smt_test_helpers.h"
#include "ir_oep_file_inputs.h"

static unsigned callbacks, phases;
static void progress(void *user, const char *name) {
    CHECK(user == &phases && name && *name); ++phases;
}
static bool policy(void *user, const IrInputs *in, uint32_t limit,
                   const IrOepInput **selectors, uint32_t *count) {
    OepFixture *f = user; ++callbacks;
    CHECK(ir_inputs_ready(in) && limit >= f->variable_count);
    *selectors = f->variables; *count = f->variable_count; return true;
}
static OepFixture alias_fixture(void) {
    FrontFixture f = ff_new(16); InsnAux a = of_registers();
    uint64_t seqs[3]; uint32_t pc=0x1000;
    const uint8_t mov[]={0xa1,0x00,0x30,0,0}, xorr[]={0x33,0x05,0,0x40,0,0};
    const uint8_t add[]={0x83,0xc0,9}, jump[]={0xff,0xe0};
    of_read(&a,0x3000,8); seqs[0]=of_emit(&f,pc,mov,sizeof(mov),a,pc+5); pc+=5;
    a=of_registers(); of_read(&a,0x4000,8);
    seqs[1]=of_emit(&f,pc,xorr,sizeof(xorr),a,pc+6);pc+=6;
    a=alu_after(of_registers(),ALU_XOR,32,8,8,REG_RAX,0,true);
    seqs[2]=of_emit(&f,pc,add,sizeof(add),a,pc+3);pc+=3;
    a=alu_after(a,ALU_ADD,32,0,9,REG_RAX,0,true);
    uint64_t trigger=of_emit(&f,pc,jump,sizeof(jump),a,9);
    OepFixture out={.input=ff_capture(&f,seqs,3,trigger),.variable_count=2,.target_address=9};
    out.variables[0]=(IrOepInput){.kind=IR_INPUT_MEMORY_BYTE,.state_key=IR_X86_MEMORY_KEY,.address=0x3000,.width=8};
    out.variables[1]=(IrOepInput){.kind=IR_INPUT_MEMORY_BYTE,.state_key=IR_X86_MEMORY_KEY,.address=0x4000,.width=8};
    ff_free(&f);return out;
}
static void service(FILE *report) {
    OepFixture f=alias_fixture();
    for(unsigned mode=0;mode<3;++mode) for(unsigned aliased=0;aliased<2;++aliased) {
        f.variables[1].same_as=aliased;
        IrOepRequest q=of_request(&f); q.symbolic_inputs=NULL;q.symbolic_count=0;
        q.select_inputs=policy;q.selection_user=&f;
        IrOepOptions o=of_options();o.target_slice=mode>0;o.rebuild_replay=mode==2;o.progress=progress;o.progress_user=&phases;
        IrOepResult r=ir_oep_verify(f.input,&q,&o);
        of_status(&r,aliased?IR_OEP_UNIQUE:IR_OEP_NONUNIQUE);
        CHECK(r.baseline_verified && r.candidate_verified && r.input_aliases==aliased);
        CHECK(r.candidate.input_count==2);
        if(mode==2)CHECK(r.replay_released && r.smt_released && r.rebuild_verified);
        if(aliased)CHECK(r.candidate.inputs[0].bits.value==r.candidate.inputs[1].bits.value);
        else CHECK(r.alternative_verified && r.alternative_target.value!=9);
        CHECK(ir_oep_report_json(report,&r));ir_oep_result_destroy(&r);
    }
    CHECK(callbacks==6 && phases>=54);
    for(unsigned fault=0;fault<5;++fault) {
        IrOepRequest q=of_request(&f);IrOepOptions o=of_options();
        f.variables[1].same_as=fault==0?2:1;
        f.variables[0].same_as=fault==1?1:0;
        if(fault==2)f.variables[1].address=0x4001; /* baseline differs from canonical byte */
        if(fault==3) {q.select_inputs=policy;q.selection_user=&f;} /* conflicting policies */
        if(fault==4) {q.symbolic_inputs=NULL;q.symbolic_count=0;q.select_inputs=policy;q.selection_user=&f;f.variable_count=0;}
        IrOepResult r=ir_oep_verify(f.input,&q,&o);
        of_status(&r,fault==4?IR_OEP_UNKNOWN:IR_OEP_INVALID);
        CHECK(!r.candidate_attempted && !r.candidate.inputs);
        CHECK(ir_oep_report_json(report,&r));ir_oep_result_destroy(&r);
        f.variables[1].address=0x4000;
    }
    replay_input_destroy(f.input);
    puts("PASS: full/sliced/rebuilt OEP relations with two memory aliases, original-IR witnesses, explicit selector policy and rejection paths");
}
static void smt_aliases(void) {
    TestIr t=ti_new(); IrStateId mem=ir_state_add(t.m,ir_type_mem(32),123,false);
    IrInputCell c[3];for(unsigned i=0;i<3;++i)c[i]=(IrInputCell){.kind=IR_INPUT_MEMORY_BYTE,.state=mem,
        .address=0x3000+i,.width=8,.observed={8,255,0}};
    IrInputs *in=sm_catalogue(t.m,c,3);IrValueId m=ti_read(t,mem);
    IrValueId x=ti_load(t,m,ti_const(t,32,0x3000),8,IR_ENDIAN_LE);
    IrValueId y=ti_load(t,m,ti_const(t,32,0x3001),8,IR_ENDIAN_LE);
    IrValueId z=ti_op(t,IR_OP_XOR,8,x,y,0,0);ti_output(t,z);ti_end(t);
    IrInputId ids[]={1,2,3};IrSmtInputAlias a[2]={{2,1},{3,1}};
    IrSmtOptions o=ir_smt_default_options();o.symbolic_inputs=ids;o.symbolic_count=3;o.aliases=a;o.alias_count=2;
    IrSmt *s=sm_build(t,in,&o);sm_expect(s,z,8,1,IR_SMT_UNSAT);
    IrSmtAnswer answer=sm_query(s,z,8,0,IR_SMT_SAT);IrSmtParameter p[3]={{0}};
    sm_compare(t,&answer,in,p);CHECK(answer.inputs[0].bits.value==answer.inputs[1].bits.value);
    ir_smt_answer_destroy(&answer);ir_smt_destroy(s);
    for(unsigned fault=0;fault<6;++fault) {
        a[0]=(IrSmtInputAlias){2,1};a[1]=(IrSmtInputAlias){3,1};o.aliases=a;
        if(fault==0)a[0].input=4;
        if(fault==1)a[1].input=2;
        if(fault==2)a[1].canonical=2;
        if(fault==3)a[1]=(IrSmtInputAlias){1,2};
        if(fault==4)o.aliases=NULL;
        if(fault==5)a[0].canonical=2;
        IrSmtInfo info;s=ir_smt_build(t.m,in,&o,&info);CHECK(!s && info.status==IR_INVALID);
    }
    ir_inputs_release(in);ir_module_destroy(t.m);
    puts("PASS: SMT alias equality, concrete replay, invalid IDs/duplicates/chains/cycles and missing arrays");
}
static void sparse_input_table(void) {
    TestIr t=ti_new();IrValueId x=ti_const(t,32,1);
    for(unsigned i=0;i<10000;++i)x=ti_op(t,IR_OP_ADD,32,x,ti_const(t,32,i),0,0);
    ti_output(t,x);ti_end(t);
    IrSmtOptions o=ir_smt_default_options();o.limits.bytes=2U*1024*1024;
    IrSmt *s=sm_build(t,NULL,&o);sm_expect(s,x,32,49995001,IR_SMT_SAT);
    CHECK(ir_smt_info(s).bytes<2U*1024*1024);
    ir_smt_destroy(s);ir_module_destroy(t.m);
    puts("PASS: large value catalogue with no INPUT fits bounded SMT adapter allocation");
}

static void file_policy(void) {
    TestIr t=ti_new();IrStateId ram=ir_state_add(t.m,ir_type_mem(32),IR_X86_MEMORY_KEY,false);
    IrStateId file=ir_state_add(t.m,ir_type_mem(32),IR_PROC_EXE_INPUT_KEY,false);
    const unsigned char data[]={8,9,10,11};IrInputCell cells[6];
    for(unsigned i=0;i<4;++i)cells[i]=(IrInputCell){.kind=IR_INPUT_MEMORY_BYTE,.state=file,
        .address=i,.width=8,.observed={data[i],255,0}};
    cells[4]=(IrInputCell){.kind=IR_INPUT_MEMORY_BYTE,.state=ram,.address=0x3001,.width=8,.observed={9,255,0}};
    cells[5]=(IrInputCell){.kind=IR_INPUT_MEMORY_BYTE,.state=ram,.address=0x4001,.width=8,.observed={9,255,0}};
    IrOepFileMapping maps[]={{0x3000,0,4},{0x4000,0,4}};
    IrOepInput selected[6];uint32_t offsets[6];
    for(unsigned fault=0;fault<7;++fault) {
        IrOepFileInputs p={.bytes=data,.size=4,.count=4,.mappings=maps,.mapping_count=2,
            .selectors=selected,.file_offsets=offsets,.capacity=6};
        cells[5].observed.value=fault==1?10:9;
        if(fault==2)p.capacity=5;
        if(fault==3)p.count=0;
        if(fault==4)p.size=3;
        if(fault==5)p.first=1;
        IrInputs *in=sm_catalogue(t.m,cells,fault==6?3:6);
        const IrOepInput *out=NULL;uint32_t n=0;
        bool ok=ir_oep_select_file_inputs(&p,in,6,&out,&n);
        CHECK(ok==(fault==0));
        if(ok)CHECK(n==6 && p.aliases==2 && out[4].same_as==2 && out[5].same_as==2 && offsets[5]==1);
        else CHECK(!out && !n && strcmp(p.error,"ok"));
        ir_inputs_release(in);
    }
    ir_module_destroy(t.m);
    puts("PASS: file-byte roots, two loader aliases, missing snapshot, conflicting observations and bounded policy rejection");
}

int main(int argc,char **argv) {
    CHECK(argc==2);FILE *f=fopen(argv[1],"w");CHECK(f);
    service(f);smt_aliases();sparse_input_table();file_policy();CHECK(!fclose(f));return 0;
}
