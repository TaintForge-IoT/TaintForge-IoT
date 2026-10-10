#include "ir_environment.h"

#include <glib.h>
#include <stdlib.h>

typedef struct {
    bool used, open, mapped_once, readonly;
    uint32_t fd, flags, size, position;
    uint64_t identity;
    IrStateId contents, shared_tail, shared_tail_dirty;
    GHashTable *written; /* Known syscall-write offsets before any mapping. */
} File;

typedef struct {
    bool used, anonymous;
    uint32_t base, offset, permissions, flags, file;
    uint64_t end;
    IrStateId view, dirty_tail;
} Mapping;

struct IrEnvironment {
    IrModule *module;
    IrStateId guest;
    File files[IR_ENV_MAX_FILES];
    Mapping mappings[IR_ENV_MAX_MAPPINGS];
    uint32_t max_files, max_cells, next_state, vcpu;
    uint64_t last_boundary, last_seq;
    const char *issue;
    bool budget;
    IrEnvironmentStats stats;
};

typedef struct { IrEnvironment *env; IrBlockId block; IrOrigin origin; } Emit;
static bool reject(IrEnvironment *e, const char *why, bool budget) {
    if (!e->issue) e->issue = why;
    e->budget |= budget;
    return false;
}
static IrValueId emit(Emit x, IrInstSpec s) {
    s.origin = x.origin;
    return ir_emit_value(x.env->module, x.block, s);
}
static IrValueId number(Emit x, unsigned bits, uint64_t n) {
    return emit(x, (IrInstSpec){.op=IR_OP_CONST,.type=ir_type_bv(bits),.immediate=n});
}
static IrValueId binary(Emit x, IrOpcode op, unsigned bits, IrValueId a, IrValueId b) {
    return emit(x, (IrInstSpec){.op=op,.type=ir_type_bv(bits),.args={a,b}});
}
static IrValueId read_state(Emit x, IrStateId state) {
    const IrState *s = ir_module_state(x.env->module, state);
    return s ? emit(x, (IrInstSpec){.op=IR_OP_READ_STATE,.type=s->type,.state=state}) : 0;
}
static void write_state(Emit x, IrStateId state, IrValueId value) {
    (void)ir_emit_effect(x.env->module,x.block,(IrInstSpec){.op=IR_OP_WRITE_STATE,
        .type=ir_type_void(),.args={value},.state=state,.origin=x.origin});
}
static IrValueId choose(Emit x, IrType type, IrValueId condition, IrValueId yes, IrValueId no) {
    return emit(x,(IrInstSpec){.op=IR_OP_ITE,.type=type,.args={condition,yes,no}});
}
static void guard(Emit x, IrValueId condition) {
    (void)ir_emit_effect(x.env->module,x.block,(IrInstSpec){.op=IR_OP_GUARD,
        .type=ir_type_void(),.args={condition},.immediate=IR_REASON_MEMORY,.origin=x.origin});
}
static IrValueId load(Emit x, IrValueId memory, IrValueId address, unsigned bytes) {
    return emit(x,(IrInstSpec){.op=IR_OP_LOAD,.type=ir_type_bv(bytes*8U),
        .args={memory,address},.endian=IR_ENDIAN_LE});
}
static IrValueId store(Emit x, IrValueId memory, IrValueId address, IrValueId data) {
    return emit(x,(IrInstSpec){.op=IR_OP_STORE,.type=ir_type_mem(32),
        .args={memory,address,data},.endian=IR_ENDIAN_LE});
}
static IrStateId new_state(IrEnvironment *e, IrType type) {
    return ir_state_add(e->module,type,IR_ENV_STATE_KEY_BASE + e->next_state++,false);
}
static bool ready(IrEnvironment *e) {
    IrStatus s=ir_module_status(e->module);
    return s==IR_OK || reject(e,"environment_ir_limit",s==IR_RESOURCE_LIMIT);
}
static File *by_fd(IrEnvironment *e, uint32_t fd) {
    for(unsigned i=0;i<IR_ENV_MAX_FILES;++i)
        if(e->files[i].used && e->files[i].open && e->files[i].fd==fd) return &e->files[i];
    return NULL;
}
static unsigned references(const IrEnvironment *e, const File *f) {
    unsigned count=0,index=(unsigned)(f-e->files);
    for(unsigned i=0;i<IR_ENV_MAX_MAPPINGS;++i)
        count+=e->mappings[i].used && e->mappings[i].file==index;
    return count;
}
static void release_file(IrEnvironment *e, File *f) {
    if(f->written) {
        e->stats.live_content_cells-=g_hash_table_size(f->written);
        g_hash_table_destroy(f->written);
    }
    *f=(File){0};
    --e->stats.files_live;
}
static bool overlap(const Mapping *m, uint32_t base, uint64_t end) {
    return m->used && base<m->end && m->base<end;
}
static IrValueId inside(Emit x,const Mapping *m,IrValueId address,IrValueId *offset) {
    IrValueId delta=binary(x,IR_OP_SUB,32,address,number(x,32,m->base));
    *offset=binary(x,IR_OP_ADD,32,delta,number(x,32,m->offset));
    /* A rounded anonymous mapping may cover the whole BV32 domain. Its
     * length cannot be encoded as BV32(2^32), which would become zero. */
    if(m->end-m->base==(UINT64_C(1)<<32)) return number(x,1,1);
    return binary(x,IR_OP_ULT,1,delta,number(x,32,m->end-m->base));
}

IrEnvironment *ir_environment_create(IrModule *m,IrStateId guest,uint32_t max_files,
                                     uint32_t max_cells) {
    const IrState *s=ir_module_state(m,guest);
    if(!s || !ir_type_equal(s->type,ir_type_mem(32)) || max_files>IR_ENV_MAX_FILES) return NULL;
    IrEnvironment *e=calloc(1,sizeof(*e));
    if(e) { e->module=m;e->guest=guest;e->max_files=max_files;e->max_cells=max_cells; }
    return e;
}
void ir_environment_destroy(IrEnvironment *e) {
    if(!e) return;
    for(unsigned i=0;i<IR_ENV_MAX_FILES;++i) if(e->files[i].written) g_hash_table_destroy(e->files[i].written);
    free(e);
}
IrEnvironmentStats ir_environment_stats(const IrEnvironment *e) { return e?e->stats:(IrEnvironmentStats){0}; }
const char *ir_environment_issue(const IrEnvironment *e) { return e?e->issue:NULL; }
bool ir_environment_budget(const IrEnvironment *e) { return e && e->budget; }
size_t ir_environment_bytes(const IrEnvironment *e) {
    return e?sizeof(*e)+(size_t)e->stats.live_content_cells*(sizeof(void*)*4U):0;
}
bool ir_environment_has_files(const IrEnvironment *e) { return e && e->stats.files_live; }
bool ir_environment_has_state(const IrEnvironment *e) {
    return e && (e->stats.files_live || e->stats.mappings_live || e->stats.brk_initialized);
}
/* Live mapping intervals are disjoint: map rejects partial overlap, fixed
 * replacement retires covered views, and anonymous unmap only splits them. */
static const Mapping *mapping_at(const IrEnvironment *e,uint32_t address) {
    if(e) for(unsigned i=0;i<IR_ENV_MAX_MAPPINGS;++i)
        if(overlap(&e->mappings[i],address,(uint64_t)address+1)) return &e->mappings[i];
    return NULL;
}
bool ir_environment_mapped(const IrEnvironment *e,uint32_t address) {
    return mapping_at(e,address)!=NULL;
}
bool ir_environment_order(IrEnvironment *e,uint64_t boundary,uint64_t seq,uint32_t vcpu,bool ordered) {
    if(!ordered || !boundary || !seq) return reject(e,"syscall_order_unverified",false);
    if(ir_environment_has_state(e) && (e->last_boundary==UINT64_MAX || boundary!=e->last_boundary+1 ||
        seq<=e->last_seq || vcpu!=e->vcpu)) return reject(e,"file_syscall_history_gap",false);
    e->last_boundary=boundary;e->last_seq=seq;e->vcpu=vcpu;
    return true;
}
bool ir_environment_file_create(IrEnvironment *e,IrBlockId b,IrOrigin o,uint32_t fd,
                                 uint32_t flags,uint64_t identity) {
    if(by_fd(e,fd)) return reject(e,"memfd_live_fd_collision",false);
    if(e->stats.files_live>=e->max_files) return reject(e,"file_object_budget",true);
    for(unsigned i=0;i<IR_ENV_MAX_FILES;++i) if(!e->files[i].used) {
        File *f=&e->files[i];
        *f=(File){.used=true,.open=true,.fd=fd,.flags=flags,.identity=identity,
            .contents=new_state(e,ir_type_mem(32)),
            .shared_tail=new_state(e,ir_type_mem(32)),.shared_tail_dirty=new_state(e,ir_type_bv(1))};
        Emit x={e,b,o};
        write_state(x,f->contents,emit(x,(IrInstSpec){.op=IR_OP_ZERO_MEMORY,.type=ir_type_mem(32)}));
        write_state(x,f->shared_tail,emit(x,(IrInstSpec){.op=IR_OP_ZERO_MEMORY,.type=ir_type_mem(32)}));
        write_state(x,f->shared_tail_dirty,number(x,1,0));
        ++e->stats.files_created;++e->stats.files_live;++e->stats.descriptors_live;
        return ready(e);
    }
    return reject(e,"file_object_budget",true);
}
bool ir_environment_file_open(IrEnvironment *e,IrBlockId b,IrOrigin o,uint32_t fd,
                               uint32_t flags,uint64_t identity,uint32_t size,IrValueId contents) {
    const IrValue *source=ir_module_value(e->module,contents);
    if(!source || !ir_type_equal(source->type,ir_type_mem(32)) || size>INT32_MAX)
        return reject(e,"external_file_source_invalid",false);
    if(!ir_environment_file_create(e,b,o,fd,flags,identity)) return false;
    File *f=by_fd(e,fd);f->readonly=true;f->size=size;
    Emit x={e,b,o};IrValueId memory=read_state(x,f->contents);
    for(uint32_t offset=0;offset<size;) {
        unsigned bytes=size-offset>=8?8:1;
        IrValueId address=number(x,32,offset);
        memory=store(x,memory,address,load(x,contents,address,bytes));
        offset+=bytes;
        if(!ready(e)) return false;
    }
    write_state(x,f->contents,memory);++e->stats.external_opens;
    return ready(e);
}
bool ir_environment_resize(IrEnvironment *e,IrBlockId b,IrOrigin o,uint32_t fd,uint32_t size) {
    File *f=by_fd(e,fd);
    if(!f) return reject(e,"truncate_file_object_missing",false);
    if(f->readonly) return reject(e,"truncate_readonly_file",false);
    if(size>INT32_MAX || f->mapped_once) return reject(e,"truncate_range_or_mapped_file",false);
    Emit x={e,b,o};
    if(f->written && size<f->size) {
        IrValueId memory=read_state(x,f->contents);
        GHashTableIter it;gpointer key;
        g_hash_table_iter_init(&it,f->written);
        while(g_hash_table_iter_next(&it,&key,NULL)) {
            uint32_t offset=GPOINTER_TO_UINT(key);
            if(offset>=size) {
                memory=store(x,memory,number(x,32,offset),number(x,8,0));
                g_hash_table_iter_remove(&it);--e->stats.live_content_cells;
            }
        }
        write_state(x,f->contents,memory);
    }
    f->size=size;++e->stats.resizes;
    return ready(e);
}
bool ir_environment_close(IrEnvironment *e,uint32_t fd) {
    File *f=by_fd(e,fd);
    if(!f) return reject(e,"close_file_object_missing",false);
    f->open=false;++e->stats.closes;--e->stats.descriptors_live;
    if(!references(e,f)) release_file(e,f);
    return true;
}
bool ir_environment_map(IrEnvironment *e,IrBlockId b,IrOrigin o,uint32_t fd,uint32_t base,
                         uint32_t length,uint32_t offset,uint32_t flags,uint32_t permissions) {
    bool anonymous=flags==0x32, fixed=(flags&0x10U)!=0;
    File *f=anonymous?NULL:by_fd(e,fd);
    if(!anonymous && !f) return reject(e,"mmap_file_object_missing",false);
    unsigned kind=flags&3U;
    if(f && f->readonly && kind==1 && (permissions&2U))
        return reject(e,"mmap_readonly_shared_write",false);
    uint64_t end=(uint64_t)base+(((uint64_t)length+4095U)&~UINT64_C(4095));
    if(!length || (base&4095U) || (offset&4095U) || end>(UINT64_C(1)<<32) ||
       (f && (uint64_t)offset+length>f->size) ||
       (flags!=1 && flags!=2 && flags!=0x11 && flags!=0x12 && flags!=0x32) ||
       (anonymous && (offset || fd!=UINT32_MAX)) ||
       (permissions&~7U) || (permissions && !(permissions&1U)))
        return reject(e,"mmap_file_range_or_flags",false);
    Mapping *slot=NULL;
    for(unsigned i=0;i<IR_ENV_MAX_MAPPINGS;++i) {
        Mapping *m=&e->mappings[i];
        if(overlap(m,base,end)) {
            /* Bounded MAP_FIXED: existing modeled views must be covered whole.
             * Excluded holes in the frontend may be split at any page boundary. */
            if(!fixed || base>m->base || end<m->end)
                return reject(e,"mmap_overlap_or_fixed_backing",false);
            if(flags==0x12 && (m->anonymous || m->base!=base || m->end!=end ||
                m->file!=(unsigned)(f-e->files) || m->offset!=offset || m->flags!=1))
                return reject(e,"mmap_overlap_or_fixed_backing",false);
            if(!slot) slot=m;
        }
    }
    if(flags==0x12 && !slot) return reject(e,"mmap_fixed_mapping_missing",false);
    if(f) for(unsigned i=0;i<IR_ENV_MAX_MAPPINGS;++i) {
        const Mapping *m=&e->mappings[i];
        if(m->used && !m->anonymous && m->file==(unsigned)(f-e->files) &&
           !(fixed && overlap(m,base,end))) return reject(e,"mmap_alias_unsupported",false);
    }
    if(!slot) for(unsigned i=0;i<IR_ENV_MAX_MAPPINGS;++i)
        if(!e->mappings[i].used) {slot=&e->mappings[i];break;}
    if(!slot) return reject(e,"mapping_budget",true);
    Emit x={e,b,o};
    /* A private view never silently loses a dirty shared EOF-page tail. */
    if(f && kind==2) guard(x,binary(x,IR_OP_EQ,1,read_state(x,f->shared_tail_dirty),number(x,1,0)));
    if(fixed) for(unsigned i=0;i<IR_ENV_MAX_MAPPINGS;++i) {
        Mapping *m=&e->mappings[i];
        if(overlap(m,base,end)) {
            File *old=m->anonymous?NULL:&e->files[m->file];
            m->used=false;--e->stats.mappings_live;++e->stats.replacements;
            if(old && !old->open && !references(e,old)) release_file(e,old);
        }
    }
    *slot=(Mapping){.used=true,.anonymous=anonymous,.base=base,.end=end,.offset=offset,
        .permissions=permissions,.flags=kind,.file=f?(unsigned)(f-e->files):UINT32_MAX};
    if(f && kind==1) {
        slot->view=f->shared_tail;slot->dirty_tail=f->shared_tail_dirty;
    } else {
        slot->view=new_state(e,ir_type_mem(32));
        write_state(x,slot->view,anonymous?
            emit(x,(IrInstSpec){.op=IR_OP_ZERO_MEMORY,.type=ir_type_mem(32)}):read_state(x,f->contents));
    }
    if(f) f->mapped_once=true;
    ++e->stats.mappings_live;++e->stats.mappings_created;
    if(anonymous) ++e->stats.anonymous_maps;
    if(flags==0x11) ++e->stats.shared_fixed_maps;
    return ready(e);
}
bool ir_environment_protect(IrEnvironment *e,uint32_t base,uint64_t end,uint32_t permissions,bool apply) {
    for(unsigned i=0;i<IR_ENV_MAX_MAPPINGS;++i) {
        Mapping *m=&e->mappings[i];
        if(overlap(m,base,end)) {
            if(!m->anonymous && e->files[m->file].readonly && m->flags==1 && (permissions&2U))
                return reject(e,"mprotect_readonly_shared_write",false);
            if(base>m->base || end<m->end) return reject(e,"mapped_mprotect_partial",false);
            if(apply) m->permissions=permissions;
        }
    }
    return true;
}
bool ir_environment_unmap(IrEnvironment *e,uint32_t base,uint64_t end,bool apply) {
    unsigned free_slots=0, splits=0;
    for(unsigned i=0;i<IR_ENV_MAX_MAPPINGS;++i) {
        const Mapping *m=&e->mappings[i];
        if(!m->used || (overlap(m,base,end) && base<=m->base && end>=m->end)) ++free_slots;
        if(overlap(m,base,end) && (base>m->base || end<m->end)) {
            if(!m->anonymous) return reject(e,"mapped_munmap_partial",false);
            if(base>m->base && end<m->end) ++splits;
        }
    }
    if(splits>free_slots) return reject(e,"mapping_budget",true);
    if(!apply) return true;
    /* Retire whole views first so splits can reuse their slots. */
    for(unsigned i=0;i<IR_ENV_MAX_MAPPINGS;++i) {
        Mapping *m=&e->mappings[i];
        if(overlap(m,base,end) && base<=m->base && end>=m->end) {
            File *f=m->anonymous?NULL:&e->files[m->file];m->used=false;
            --e->stats.mappings_live;++e->stats.unmapped;
            if(f && !f->open && !references(e,f)) release_file(e,f);
        }
    }
    for(unsigned i=0;i<IR_ENV_MAX_MAPPINGS;++i) {
        Mapping *m=&e->mappings[i];
        if(!overlap(m,base,end)) continue;
        if(base>m->base && end<m->end) {
            for(unsigned j=0;j<IR_ENV_MAX_MAPPINGS;++j) if(!e->mappings[j].used) {
                Mapping right=*m;right.offset+=(uint32_t)end-m->base;right.base=(uint32_t)end;
                e->mappings[j]=right;++e->stats.mappings_live;break;
            }
            m->end=base;
        } else if(base>m->base) m->end=base;
        else {m->offset+=(uint32_t)end-m->base;m->base=(uint32_t)end;}
        ++e->stats.unmapped;
    }
    return true;
}
bool ir_environment_sync(IrEnvironment *e,uint32_t base,uint32_t length,uint32_t flags) {
    uint64_t end=(uint64_t)base+length;
    if((base&4095U) || !length || end>(UINT64_C(1)<<32) || flags!=4)
        return reject(e,"msync_range_or_flags",false);
    for(unsigned i=0;i<IR_ENV_MAX_MAPPINGS;++i) {
        const Mapping *m=&e->mappings[i];
        if(m->used && !m->anonymous && m->flags==1 && !e->files[m->file].readonly &&
           base>=m->base && end<=m->end) {++e->stats.syncs;return true;}
    }
    return reject(e,"msync_shared_memfd_missing",false);
}
bool ir_environment_brk(IrEnvironment *e,IrBlockId b,IrOrigin o,uint32_t initial,
                         uint32_t before,uint32_t requested,uint32_t after) {
    if(!initial || (initial&4095U) || before<initial || after<initial ||
       (requested<initial && after!=before) || (after!=before && after!=requested))
        return reject(e,"brk_transition_invalid",false);
    if(e->stats.brk_initialized &&
       (e->stats.brk_initial!=initial || e->stats.brk_current!=before))
        return reject(e,"brk_history_mismatch",false);
    uint64_t lo=((uint64_t)before+4095U)&~UINT64_C(4095);
    uint64_t hi=((uint64_t)after+4095U)&~UINT64_C(4095);
    if(hi>lo) {
        if(lo>UINT32_MAX || hi-lo>UINT32_MAX) return reject(e,"brk_range_unsupported",false);
        for(unsigned i=0;i<IR_ENV_MAX_MAPPINGS;++i)
            if(overlap(&e->mappings[i],(uint32_t)lo,hi)) return reject(e,"brk_mapping_conflict",false);
        if(!ir_environment_map(e,b,o,UINT32_MAX,(uint32_t)lo,(uint32_t)(hi-lo),0,0x32,3)) return false;
    } else if(hi<lo) {
        for(unsigned i=0;i<IR_ENV_MAX_MAPPINGS;++i)
            if(overlap(&e->mappings[i],(uint32_t)hi,lo) && !e->mappings[i].anonymous)
                return reject(e,"brk_mapping_conflict",false);
        if(!ir_environment_unmap(e,(uint32_t)hi,lo,true)) return false;
    }
    e->stats.brk_initialized=true;e->stats.brk_initial=initial;e->stats.brk_current=after;
    ++e->stats.brk_calls;return ready(e);
}
bool ir_environment_write_check(IrEnvironment *e,uint32_t fd,uint32_t address,uint32_t written) {
    File *f=by_fd(e,fd);
    if(!f) return reject(e,"write_file_object_missing",false);
    if(f->readonly) return reject(e,"write_readonly_file",false);
    if(f->position>f->size || written>f->size-f->position || (uint64_t)address+written>(UINT64_C(1)<<32))
        return reject(e,"write_range_or_growth_unsupported",false);
    if(written>e->max_cells-e->stats.live_content_cells) return reject(e,"file_content_budget",true);
    for(unsigned i=0;i<IR_ENV_MAX_MAPPINGS;++i) {
        const Mapping *m=&e->mappings[i];
        if(!m->used || m->file!=(unsigned)(f-e->files) || !written) continue;
        if(m->flags!=1) return reject(e,"write_private_mapping_unsupported",false);
        if(m->permissions&4U) return reject(e,"write_executable_mapping_unsupported",false);
        if(overlap(m,address,(uint64_t)address+written)) return reject(e,"write_buffer_alias_unsupported",false);
    }
    return true;
}
bool ir_environment_write(IrEnvironment *e,IrBlockId b,IrOrigin o,uint32_t fd,
                           const IrValueId *bytes,uint32_t count) {
    File *f=by_fd(e,fd);
    if(!f || f->readonly || (count&&!bytes) || f->position>f->size || count>f->size-f->position)
        return reject(e,"write_file_range_invalid",false);
    if(count>e->max_cells-e->stats.live_content_cells) return reject(e,"file_content_budget",true);
    Emit x={e,b,o};IrValueId memory=read_state(x,f->contents);
    if(count && !f->written) f->written=g_hash_table_new(g_direct_hash,g_direct_equal);
    for(uint32_t i=0;i<count;++i) {
        uint32_t offset=f->position+i;
        memory=store(x,memory,number(x,32,offset),bytes[i]);
        if(g_hash_table_add(f->written,GUINT_TO_POINTER(offset))) ++e->stats.live_content_cells;
    }
    if(count) write_state(x,f->contents,memory);
    f->position+=count;++e->stats.writes;e->stats.bytes_stored+=count;
    return ready(e);
}

IrValueId ir_environment_load(IrEnvironment *e,IrBlockId b,IrOrigin o,IrValueId address,unsigned bytes) {
    Emit x={e,b,o};IrValueId guest=read_state(x,e->guest);
    if(!e->stats.mappings_live) return load(x,guest,address,bytes);
    /* The byte loop emits no state writes or mapping changes. Reuse only its
     * invariant definitions; each byte still selects its symbolic address
     * space and executes its own LOAD. This cache dies with this one access. */
    struct { IrValueId base, offset, bound, view, file_size, contents; }
        invariant[IR_ENV_MAX_MAPPINGS] = {{0}};
    IrValueId combined=0;
    for(unsigned j=0;j<bytes;++j) {
        IrValueId a=j?binary(x,IR_OP_ADD,32,address,number(x,32,j)):address;
        IrValueId selected_memory=guest,selected_address=a;
        for(unsigned i=0;i<IR_ENV_MAX_MAPPINGS;++i) {
            const Mapping *m=&e->mappings[i];if(!m->used) continue;
            const File *f=m->anonymous?NULL:&e->files[m->file];
            if(!j) invariant[i].base=number(x,32,m->base);
            IrValueId delta=binary(x,IR_OP_SUB,32,a,invariant[i].base);
            if(!j) invariant[i].offset=number(x,32,m->offset);
            IrValueId offset=binary(x,IR_OP_ADD,32,delta,invariant[i].offset);
            bool full=m->end-m->base==(UINT64_C(1)<<32);
            if(!j) invariant[i].bound=full?number(x,1,1):number(x,32,m->end-m->base);
            IrValueId condition=full?invariant[i].bound:
                binary(x,IR_OP_ULT,1,delta,invariant[i].bound);
            if(!j) invariant[i].view=read_state(x,m->view);
            IrValueId mapped=invariant[i].view;
            if(m->flags==1) {
                if(!j) invariant[i].file_size=number(x,32,f->size);
                IrValueId in_file=binary(x,IR_OP_ULT,1,offset,invariant[i].file_size);
                if(!j) invariant[i].contents=read_state(x,f->contents);
                mapped=choose(x,ir_type_mem(32),in_file,invariant[i].contents,mapped);
            }
            selected_memory=choose(x,ir_type_mem(32),condition,mapped,selected_memory);
            selected_address=choose(x,ir_type_bv(32),condition,offset,selected_address);
        }
        /* Select the address space before LOAD. The concrete evaluator never
         * walks an irrelevant unbound/long backing chain for an untaken view. */
        IrValueId value=load(x,selected_memory,selected_address,1);
        combined=j?binary(x,IR_OP_CONCAT,(j+1U)*8U,value,combined):value;
    }
    ++e->stats.memory_loads;
    return combined;
}
void ir_environment_store(IrEnvironment *e,IrBlockId b,IrOrigin o,IrValueId address,
                           unsigned bytes,IrValueId value) {
    Emit x={e,b,o};
    write_state(x,e->guest,store(x,read_state(x,e->guest),address,value));
    for(unsigned j=0;j<bytes && e->stats.mappings_live;++j) {
        IrValueId a=j?binary(x,IR_OP_ADD,32,address,number(x,32,j)):address;
        IrValueId data=bytes==1?value:emit(x,(IrInstSpec){.op=IR_OP_EXTRACT,
            .type=ir_type_bv(8),.args={value},.immediate=j*8U});
        for(unsigned i=0;i<IR_ENV_MAX_MAPPINGS;++i) {
            const Mapping *m=&e->mappings[i];if(!m->used) continue;
            const File *f=m->anonymous?NULL:&e->files[m->file];IrValueId offset;
            IrValueId condition=inside(x,m,a,&offset),old=read_state(x,m->view);
            write_state(x,m->view,choose(x,ir_type_mem(32),condition,store(x,old,offset,data),old));
            if(m->flags==1) {
                IrValueId in_file=binary(x,IR_OP_ULT,1,offset,number(x,32,f->size));
                IrValueId update=binary(x,IR_OP_AND,1,condition,in_file);
                old=read_state(x,f->contents);
                write_state(x,f->contents,choose(x,ir_type_mem(32),update,store(x,old,offset,data),old));
                IrValueId tail=binary(x,IR_OP_AND,1,condition,binary(x,IR_OP_EQ,1,in_file,number(x,1,0)));
                write_state(x,m->dirty_tail,binary(x,IR_OP_OR,1,read_state(x,m->dirty_tail),tail));
            }
        }
    }
    ++e->stats.memory_stores;
}
bool ir_environment_fetch(IrEnvironment *e,IrBlockId b,IrOrigin o,uint32_t pc,
                           const uint8_t *bytes,unsigned size) {
    Emit x={e,b,o};
    for(unsigned i=0;i<size;++i) {
        const Mapping *m=mapping_at(e,pc+i);
        if(!m) continue;
        /* PC is a fixed trace occurrence, not an observed value substituted
         * for a symbolic data address. Specialize only mapping/offset choice.
         * Keep LOAD from the current state and the byte equality GUARD, so
         * changed/unknown/self-modified code still cannot pass silently. */
        uint32_t offset=(pc+i)-m->base+m->offset;
        IrStateId contents=m->view;
        if(m->flags==1 && offset<e->files[m->file].size)
            contents=e->files[m->file].contents;
        IrValueId value=load(x,read_state(x,contents),number(x,32,offset),1);
        guard(x,binary(x,IR_OP_EQ,1,value,number(x,8,bytes[i])));
        ++e->stats.memory_loads;
        ++e->stats.fetch_bytes;
    }
    return ready(e);
}
