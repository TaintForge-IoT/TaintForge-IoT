#ifndef TAINTFORGE_IR_OEP_IDENTITY_H
#define TAINTFORGE_IR_OEP_IDENTITY_H
#include <glib.h>

/* Private, deterministic field serialization. Padding, addresses, allocation
 * capacities and revision counters are deliberately excluded. This is a
 * reconstruction-integrity check, never an external reachability argument. */
typedef struct { GChecksum *hash; uint64_t words[1024]; size_t used; } OepHash;
static void oep_hash_flush(OepHash *h) {
    if(h->used)g_checksum_update(h->hash,(const guchar *)h->words,h->used*sizeof(h->words[0]));
    h->used=0;
}
static void oep_hash_word(OepHash *h,uint64_t word) {
    h->words[h->used++]=GUINT64_TO_LE(word);
    if(h->used==G_N_ELEMENTS(h->words))oep_hash_flush(h);
}
static void oep_hash_origin(OepHash *h,IrOrigin v) {
    oep_hash_word(h,v.seq_id);oep_hash_word(h,v.descriptor_id);oep_hash_word(h,v.pc);
    oep_hash_word(h,v.code_generation);oep_hash_word(h,v.vcpu_id);
    oep_hash_word(h,v.has_trace_identity);oep_hash_word(h,v.provenance_label);
}
static bool oep_origin_equal(IrOrigin a,IrOrigin b) {
    return a.seq_id==b.seq_id && a.descriptor_id==b.descriptor_id && a.pc==b.pc &&
        a.code_generation==b.code_generation && a.vcpu_id==b.vcpu_id &&
        a.has_trace_identity==b.has_trace_identity && a.provenance_label==b.provenance_label;
}
static uint64_t oep_hash_work(const IrModule *m) {
    return UINT64_C(20)*ir_module_inst_count(m)+UINT64_C(24)*ir_module_block_count(m)+
        UINT64_C(3)*ir_module_value_count(m)+UINT64_C(4)*ir_module_state_count(m)+
        ir_module_output_count(m)+64;
}
static bool oep_hash_module(const IrModule *m,IrReplayTarget target,char digest[65]) {
    OepHash h={.hash=g_checksum_new(G_CHECKSUM_SHA256)};
    if(!h.hash)return false;
    oep_hash_word(&h,1); /* Encoding version. */
    oep_hash_word(&h,ir_module_inst_count(m));oep_hash_word(&h,ir_module_value_count(m));
    oep_hash_word(&h,ir_module_block_count(m));oep_hash_word(&h,ir_module_state_count(m));
    oep_hash_word(&h,ir_module_output_count(m));oep_hash_word(&h,ir_module_entry(m));
    oep_hash_word(&h,ir_module_status(m));oep_hash_word(&h,ir_module_is_trace_ssa(m));
    IrQuality quality=ir_module_quality(m);
    oep_hash_word(&h,quality.semantic);oep_hash_word(&h,quality.control);oep_hash_word(&h,quality.observation);
    oep_hash_word(&h,target.status);oep_hash_word(&h,target.value);oep_hash_word(&h,(uint64_t)(int64_t)target.gpr_index);
    oep_hash_word(&h,target.boundary);oep_hash_word(&h,target.matches_candidate);
    for(IrInstId id=1;id<=ir_module_inst_count(m);++id) {
        const IrInst *v=ir_module_inst(m,id);const IrInstSpec *s=&v->spec;
        oep_hash_word(&h,s->op);oep_hash_word(&h,s->type.kind);oep_hash_word(&h,s->type.bits);
        for(unsigned j=0;j<3;++j)oep_hash_word(&h,s->args[j]);
        oep_hash_word(&h,s->immediate);oep_hash_word(&h,s->state);oep_hash_word(&h,s->endian);
        oep_hash_origin(&h,s->origin);oep_hash_word(&h,v->result);oep_hash_word(&h,v->block);
        oep_hash_word(&h,v->next);oep_hash_word(&h,v->removed);
    }
    for(IrValueId id=1;id<=ir_module_value_count(m);++id) {
        const IrValue *v=ir_module_value(m,id);
        oep_hash_word(&h,v->type.kind);oep_hash_word(&h,v->type.bits);oep_hash_word(&h,v->definition);
    }
    for(IrStateId id=1;id<=ir_module_state_count(m);++id) {
        const IrState *v=ir_module_state(m,id);
        oep_hash_word(&h,v->type.kind);oep_hash_word(&h,v->type.bits);oep_hash_word(&h,v->key);oep_hash_word(&h,v->live_out);
    }
    for(IrBlockId id=1;id<=ir_module_block_count(m);++id) {
        const IrBlock *b=ir_module_block(m,id);const IrTerminator *t=&b->terminator;
        oep_hash_word(&h,b->first);oep_hash_word(&h,b->last);
        oep_hash_word(&h,t->kind);oep_hash_word(&h,t->condition);oep_hash_word(&h,t->indirect_target);
        for(unsigned j=0;j<2;++j) {
            IrTarget v=t->successors[j];oep_hash_word(&h,v.kind);oep_hash_word(&h,v.block);
            oep_hash_word(&h,v.address);oep_hash_word(&h,v.reasons);
        }
        oep_hash_word(&h,t->reasons);oep_hash_origin(&h,t->origin);
        oep_hash_word(&h,t->has_observation);oep_hash_word(&h,t->observed_taken);oep_hash_word(&h,t->observed_target);
    }
    for(uint32_t i=0;i<ir_module_output_count(m);++i)oep_hash_word(&h,ir_module_output(m,i));
    oep_hash_flush(&h);memcpy(digest,g_checksum_get_string(h.hash),65);g_checksum_free(h.hash);return true;
}
static bool oep_inputs_equal(const IrInputs *a,const IrInputs *b) {
    uint32_t states=ir_inputs_state_count(a),cells=ir_inputs_info(a).count;
    if(!ir_inputs_ready(a) || !ir_inputs_ready(b) || states!=ir_inputs_state_count(b) ||
       cells!=ir_inputs_info(b).count || ir_inputs_sources(a)!=ir_inputs_sources(b) ||
       !oep_origin_equal(ir_inputs_boundary(a),ir_inputs_boundary(b)))return false;
    for(uint32_t i=0;i<states;++i) {
        const IrInputState *x=ir_inputs_state_at(a,i),*y=ir_inputs_state_at(b,i);
        if(x->state!=y->state || !ir_type_equal(x->type,y->type) || x->key!=y->key ||
           x->first!=y->first || x->count!=y->count)return false;
    }
    for(IrInputId id=1;id<=cells;++id) {
        const IrInputCell *x=ir_inputs_cell(a,id),*y=ir_inputs_cell(b,id);
        if(x->kind!=y->kind || x->state!=y->state || x->address!=y->address ||
           x->bit_offset!=y->bit_offset || x->width!=y->width || x->observed.value!=y->observed.value ||
           x->observed.known_mask!=y->observed.known_mask || x->observed.reasons!=y->observed.reasons ||
           !oep_origin_equal(x->observation_origin,y->observation_origin) || x->label!=y->label ||
           x->label_present!=y->label_present || x->issues!=y->issues)return false;
    }
    return true;
}
#endif
