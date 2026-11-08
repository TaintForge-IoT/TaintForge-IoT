#include "ir_oep_test_helpers.h"

typedef struct { ReplayInput *input; unsigned fault, released, smt_released, rebuilding, calls; } Watch;
static void observe(void *user,const char *name) {
    Watch *w=user;++w->calls;
    if(!strcmp(name,"replay_released"))++w->released;
    if(!strcmp(name,"smt_build"))CHECK(w->released==1);
    if(!strcmp(name,"smt_released"))++w->smt_released;
    if(!strcmp(name,"rebuild")) {
        CHECK(w->smt_released==1);++w->rebuilding;
        /* Fault injection deliberately violates the immutable capture contract.
         * The service must discard models if reconstruction changes semantics. */
        ReplayStep *step=(ReplayStep *)replay_input_step(w->input,0);
        if(w->fault==1)step->descriptor_valid=false;
        if(w->fault==2) {
            step->entry.instr_bytes[1]=0xc8; /* ADD EAX,1 -> OR EAX,1; both yield 9 for EAX=8. */
            step->descriptor.bytes[1]=0xc8;step->descriptor.native_insn_id=X86_INS_OR;
            uint64_t hash=trace_instruction_bytes_hash(step->descriptor.bytes,step->descriptor.size);
            step->entry.bytes_hash=hash;step->descriptor.bytes_hash=hash;step->occurrence.bytes_hash=hash;
        }
        if(w->fault==3) {
            InsnAux *a=(InsnAux *)replay_input_aux(w->input,step->entry.seq_id);
            a->reg_vals[DTA_REG_RCX]^=1;
        }
    }
    if(!strcmp(name,"candidate_replay") || !strcmp(name,"alternative_replay"))
        CHECK(w->released==1 && w->smt_released==1 && w->rebuilding==1);
}
static void compare(FILE *report,OepFixture *f) {
    IrOepRequest q=of_request(f);IrOepOptions o=of_options();
    IrOepResult a=ir_oep_verify(f->input,&q,&o);
    Watch w={.input=f->input};o.rebuild_replay=true;o.progress=observe;o.progress_user=&w;
    IrOepResult b=ir_oep_verify(f->input,&q,&o);
    if(a.status!=b.status)fprintf(stderr,"retained=%u rebuilt=%u %s\n",a.status,b.status,b.diagnostic);
    CHECK(a.status==b.status && a.baseline_verified==b.baseline_verified);
    CHECK(a.candidate_attempted==b.candidate_attempted && a.alternative_attempted==b.alternative_attempted);
    CHECK(a.candidate.status==b.candidate.status && a.alternative.status==b.alternative.status);
    CHECK(a.candidate_verified==b.candidate_verified && a.alternative_verified==b.alternative_verified);
    CHECK(a.baseline.checked==b.baseline.checked && a.baseline.mismatches==b.baseline.mismatches &&
          a.baseline.unknown==b.baseline.unknown && a.prefix_count==b.prefix_count);
    CHECK(a.slice.active_after==b.slice.active_after && a.smt.constructors==b.smt.constructors &&
          a.smt.lowered_values==b.smt.lowered_values);
    if(b.candidate_verified) {
        CHECK(b.replay_released && b.smt_released && b.rebuild_attempted && b.rebuild_verified);
        CHECK(b.released_replay_bytes>0 && b.retained_input_bytes>0);
        CHECK(strlen(b.replay_sha256)==64 && !strcmp(b.replay_sha256,b.rebuilt_sha256));
        CHECK(a.candidate_replay.steps==b.candidate_replay.steps);
        CHECK(a.candidate_target.value==b.candidate_target.value);
    }
    CHECK(ir_oep_report_json(report,&a));CHECK(ir_oep_report_json(report,&b));
    ir_oep_result_destroy(&a);ir_oep_result_destroy(&b);
}
static void failures(FILE *report) {
    for(unsigned fault=1;fault<=3;++fault) {
        OepFixture f=of_fixture(OF_LINEAR);IrOepRequest q=of_request(&f);IrOepOptions o=of_options();
        Watch w={.input=f.input,.fault=fault};o.rebuild_replay=true;o.progress=observe;o.progress_user=&w;
        IrOepResult r=ir_oep_verify(f.input,&q,&o);
        const char *why=fault==1?"witness_rebuild_incomplete":fault==2?"witness_rebuild_ir_changed":"witness_rebuild_inputs_changed";
        if(strcmp(r.diagnostic,why))fprintf(stderr,"fault=%u actual=%s expected=%s\n",fault,r.diagnostic,why);
        CHECK(!strcmp(r.diagnostic,why));
        of_status(&r,fault==1?IR_OEP_UNKNOWN:IR_OEP_MISMATCH);
        CHECK(r.replay_released && r.smt_released && r.rebuild_attempted && !r.rebuild_verified);
        CHECK(r.candidate_attempted && r.alternative_attempted && !r.candidate_verified && !r.alternative_verified);
        CHECK(!r.candidate.inputs && !r.candidate.catalogue && !r.alternative.inputs && !r.alternative.catalogue);
        CHECK(ir_oep_report_json(report,&r));ir_oep_result_destroy(&r);replay_input_destroy(f.input);
    }
    for(unsigned which=0;which<6;++which) {
        OepFixture f=of_fixture(OF_EQUAL);IrOepRequest q=of_request(&f);IrOepOptions o=of_options();o.rebuild_replay=true;
        if(which==0)o.target_slice=false;
        if(which==1)o.work=0;
        if(which==2)o.smt.work=0;
        if(which==3)o.query.timeout_ms=0;
        if(which==4)o.bindings.inputs=0;
        if(which==5)o.slice.work=0;
        IrOepResult r=ir_oep_verify(f.input,&q,&o);
        of_status(&r,which==0?IR_OEP_INVALID:IR_OEP_RESOURCE_LIMIT);
        CHECK(!r.candidate_verified && !r.alternative_verified && !r.candidate.inputs && !r.alternative.inputs);
        if(which==2 || which==3)CHECK(r.replay_released && !r.rebuild_attempted);
        if(which==4)CHECK(r.rebuild_verified && r.smt_released);
        CHECK(ir_oep_report_json(report,&r));ir_oep_result_destroy(&r);replay_input_destroy(f.input);
    }
    puts("PASS: altered instruction semantics, input catalogue, incomplete reconstruction and stage budgets fail closed");
}
static bool select_once(void *user,const IrInputs *in,uint32_t limit,const IrOepInput **out,uint32_t *n) {
    OepFixture *f=user;CHECK(limit>=2 && ir_inputs_ready(in));CHECK(f->variable_count==2);
    *out=f->variables;*n=f->variable_count;
    /* A second invocation would fail: selection must be reused, not rerun. */
    f->variable_count=0;return true;
}
static void owned_aliases(FILE *report) {
    OepFixture f=of_fixture(OF_LINEAR);f.variables[0]=of_register_byte(DTA_REG_RCX,0);
    f.variables[1]=of_register_byte(DTA_REG_RDX,0);f.variables[1].same_as=1;f.variable_count=2;
    IrOepRequest q=of_request(&f);q.symbolic_count=0;q.symbolic_inputs=NULL;q.select_inputs=select_once;q.selection_user=&f;
    IrOepOptions o=of_options();o.rebuild_replay=true;
    IrOepResult r=ir_oep_verify(f.input,&q,&o);of_status(&r,IR_OEP_UNIQUE);
    CHECK(r.rebuild_verified && r.input_aliases==1 && r.candidate.input_count==2);
    CHECK(r.candidate.inputs[0].bits.value==r.candidate.inputs[1].bits.value);
    replay_input_destroy(f.input);
    CHECK(ir_inputs_ready(r.candidate.catalogue) && ir_inputs_cell(r.candidate.catalogue,r.candidate.inputs[0].input));
    CHECK(ir_oep_report_json(report,&r));ir_oep_result_destroy(&r);ir_oep_result_destroy(&r);
    puts("PASS: selector called once, alias witnesses owned after trace destruction and repeated cleanup");
}
int main(int argc,char **argv) {
    CHECK(argc==2);FILE *report=fopen(argv[1],"w");CHECK(report);unsigned pairs=0;
    for(unsigned kind=OF_EQUAL;kind<=OF_BAD_BRANCH;++kind) {
        OepFixture f=of_fixture(kind);compare(report,&f);++pairs;
        if(kind==OF_EQUAL || kind==OF_SAME_SUCCESSOR || kind==OF_LATE_GUARD) {
            ++f.target_address;compare(report,&f);++pairs;
        }
        replay_input_destroy(f.input);
    }
    printf("PASS: %u retained/rebuilt A/B pairs, exact baseline/slice/SMT counts, original-IR witnesses\n",pairs);
    failures(report);owned_aliases(report);CHECK(!fclose(report));return 0;
}
