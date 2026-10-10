#ifndef TAINTFORGE_IR_OEP_FILE_INPUTS_H
#define TAINTFORGE_IR_OEP_FILE_INPUTS_H
#include "ir_oep.h"

/* Explicit fixed loader layout, supplied and verified by the caller. This is
 * not a loader implementation or a claim that a changed ELF will load alike. */
typedef struct { uint32_t address, offset, size; } IrOepFileMapping;
typedef struct {
    const unsigned char *bytes;
    uint32_t size, first, count;
    const IrOepFileMapping *mappings;
    uint32_t mapping_count;
    IrOepInput *selectors;
    uint32_t *file_offsets;
    uint32_t capacity, selected, aliases;
    const char *error;
} IrOepFileInputs;

static inline bool ir_oep_file_error(IrOepFileInputs *p, const char *s) {
    p->error=s;return false;
}
/* All selected file-snapshot cells are roots. Every observed initial RAM
 * alias within the supplied PT_LOAD file extents shares its corresponding
 * root. BSS and bytes outside those extents remain ordinary fixed boundary
 * cells. No address/label alone certifies an alias: observed bytes must agree.
 * Caller owns output arrays; work is bounded by catalogue size, file span,
 * and at most 16 mappings. A missing snapshot/root fails closed. */
static inline bool ir_oep_select_file_inputs(void *user, const IrInputs *in, uint32_t limit,
                                            const IrOepInput **out, uint32_t *count) {
    IrOepFileInputs *p=user;
    if(!p || !out || !count) return false;
    *out=NULL;*count=0;p->selected=0;p->aliases=0;p->error="ok";
    if(!ir_inputs_ready(in) || !p->bytes || !p->selectors || !p->file_offsets || !p->count ||
       p->size>1048576U || p->first>p->size || p->count>p->size-p->first ||
       !p->mapping_count || p->mapping_count>16 || !p->mappings)
        return ir_oep_file_error(p,"invalid_file_policy");
    for(uint32_t i=0;i<p->mapping_count;++i) {
        IrOepFileMapping m=p->mappings[i];
        if(m.offset>p->size || m.size>p->size-m.offset ||
           (uint64_t)m.address+m.size>UINT64_C(0x100000000))
            return ir_oep_file_error(p,"invalid_file_mapping");
    }
    IrStateId file=0,ram=0;
    for(uint32_t i=0;i<ir_inputs_state_count(in);++i) {
        const IrInputState *s=ir_inputs_state_at(in,i);
        if(s->key==IR_PROC_EXE_INPUT_KEY && s->type.kind==IR_TYPE_MEM && s->type.bits==32)file=s->state;
        if(s->key==IR_X86_MEMORY_KEY && s->type.kind==IR_TYPE_MEM && s->type.bits==32)ram=s->state;
    }
    if(!file || !ram)return ir_oep_file_error(p,"file_or_ram_state_missing");
    if(p->count>limit || p->count>p->capacity)return ir_oep_file_error(p,"selector_capacity");
    for(uint32_t j=0;j<p->count;++j) {
        uint32_t offset=p->first+j;
        IrInputId id=ir_inputs_find_byte(in,file,offset);
        const IrInputCell *c=ir_inputs_cell(in,id);
        if(!c || c->width!=8 || !ir_bits_complete(c->observed,8) || c->observed.value!=p->bytes[offset])
            return ir_oep_file_error(p,"file_snapshot_mismatch_or_missing");
        p->selectors[p->selected]=(IrOepInput){.kind=IR_INPUT_MEMORY_BYTE,
            .state_key=IR_PROC_EXE_INPUT_KEY,.address=offset,.width=8};
        p->file_offsets[p->selected++]=offset;
    }
    for(IrInputId id=1;id<=ir_inputs_info(in).count;++id) {
        const IrInputCell *c=ir_inputs_cell(in,id);
        if(c->state!=ram || c->kind!=IR_INPUT_MEMORY_BYTE)continue;
        bool mapped=false;uint32_t offset=0;
        for(uint32_t i=0;i<p->mapping_count;++i) {
            IrOepFileMapping m=p->mappings[i];
            if(c->address<m.address || c->address-m.address>=m.size)continue;
            uint32_t next=m.offset+(uint32_t)(c->address-m.address);
            if(mapped && next!=offset)return ir_oep_file_error(p,"ambiguous_file_mapping");
            mapped=true;offset=next;
        }
        if(!mapped || offset<p->first || offset-p->first>=p->count)continue;
        if(c->width!=8 || !ir_bits_complete(c->observed,8) || c->observed.value!=p->bytes[offset])
            return ir_oep_file_error(p,"ram_file_alias_mismatch");
        if(p->selected>=limit || p->selected>=p->capacity)return ir_oep_file_error(p,"selector_capacity");
        p->selectors[p->selected]=(IrOepInput){.kind=IR_INPUT_MEMORY_BYTE,
            .state_key=IR_X86_MEMORY_KEY,.address=c->address,.width=8,.same_as=offset-p->first+1};
        p->file_offsets[p->selected++]=offset;++p->aliases;
    }
    *out=p->selectors;*count=p->selected;return true;
}
#endif
