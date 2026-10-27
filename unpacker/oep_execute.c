/* Lift current computed instruction bytes and execute production typed IR from ELF entry.
 * This is a bounded IR interpreter; kernel and initial-state premises remain explicit.
 * No observed register/memory values are used while lifting the fixed bytes.
 */
#define _POSIX_C_SOURCE 200809L
#include <capstone/capstone.h>
#include <glib.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ir_lift_x86.h"

typedef struct {
 uint32_t pc,size,successors[2],count,stores;
 uint8_t bytes[16];
 IrModule *module;
 IrX86LiftResult lift;
 char sha[65],*dump;
 size_t dump_size;
 char mnemonic[48],operands[192];
 uint32_t native_insn_id;
 int repeat_iterations;
 bool opaque;
 uint32_t *producer_constants;
 bool producer_recorded;
} Node;

static void string_json(const char *data,size_t size) {
 fputc('"',stdout);
 for(size_t i=0;i<size;++i){
  unsigned char c=(unsigned char)data[i];
  if(c=='"'||c=='\\'){fputc('\\',stdout);fputc(c,stdout);}
  else if(c=='\n')fputs("\\n",stdout);
  else if(c=='\r')fputs("\\r",stdout);
  else if(c=='\t')fputs("\\t",stdout);
  else if(c<32)printf("\\u%04x",c);
  else fputc(c,stdout);
 }
 fputc('"',stdout);
}
static bool lift_node(csh decoder,const uint8_t *bytes,size_t remaining,uint32_t pc,int repeats,Node *n) {
 cs_insn *insn=NULL;
 size_t count=cs_disasm(decoder,bytes,remaining,pc,1,&insn);
 if(count!=1||!insn->detail||insn->size>15){if(count)cs_free(insn,count);return false;}
 n->pc=pc;n->size=insn->size;n->repeat_iterations=repeats;memcpy(n->bytes,insn->bytes,n->size);
 n->native_insn_id=insn->id;
 snprintf(n->mnemonic,sizeof(n->mnemonic),"%s",insn->mnemonic);
 snprintf(n->operands,sizeof(n->operands),"%s",insn->op_str);
 n->opaque=insn->id==X86_INS_INT;
 uint64_t identity=(uint64_t)pc+1;
 InsnDesc descriptor={.desc_id=identity,.arch=TRACE_ARCH_X86,.mode=TRACE_MODE_32,
  .pc=pc,.code_generation=1,.native_insn_id=insn->id,.size=n->size};
 memcpy(descriptor.bytes,n->bytes,n->size);
 descriptor.bytes_hash=trace_instruction_bytes_hash(descriptor.bytes,descriptor.size);
 cs_free(insn,count);
 IrLimits limits=ir_default_limits();
 limits.instructions=524288;limits.values=524288;limits.blocks=4;limits.states=32;limits.outputs=32;
 n->module=ir_module_create(&limits);
 IrBlockId block=n->module?ir_block_add(n->module):0;
 IrX86Options options={.flat32_ram=true};
 IrX86Frontend *front=n->module?ir_x86_frontend_create(n->module,&options):NULL;
 IrOrigin origin={.seq_id=identity,.descriptor_id=identity,.pc=pc,
  .code_generation=1,.has_trace_identity=true};
 bool ok=front&&block&&ir_module_set_entry(n->module,block);
 if(ok)n->lift=repeats>=0?ir_x86_lift_repeat(front,block,&descriptor,origin,(uint32_t)repeats,4096,NULL,NULL):ir_x86_lift(front,block,&descriptor,origin);
 bool explicit_kernel_boundary=n->opaque&&n->size==2&&n->bytes[0]==0xcd&&n->bytes[1]==0x80&&
  n->lift.status==IR_X86_LIFT_UNSUPPORTED&&ir_module_inst_count(n->module)==0;
 ok=ok&&!n->lift.segment_reads&&(n->lift.status==IR_X86_LIFT_OK||explicit_kernel_boundary);
 if(ok){
  n->count=n->lift.control==IR_X86_INDIRECT?0:1;
  n->successors[0]=n->lift.control==IR_X86_FALLTHROUGH?n->lift.fallthrough:n->lift.direct_target;
  if(n->lift.control==IR_X86_CONDITIONAL){n->count=2;n->successors[1]=n->lift.fallthrough;ok=n->lift.condition!=0;}
  for(IrInstId i=1;i<=ir_module_inst_count(n->module);++i){
   const IrInst *instruction=ir_module_inst(n->module,i);
   if(instruction->spec.op==IR_OP_STORE)++n->stores;
   if(instruction->spec.op==IR_OP_BARRIER)ok=false;
  }
  ok=ok&&ir_block_terminate(n->module,block,(IrTerminator){.kind=IR_TERM_FRAGMENT_END,.origin=origin})&&ir_validate(n->module,NULL);
 }
 ir_x86_frontend_destroy(front);
 if(!ok)return false;
 FILE *stream=open_memstream(&n->dump,&n->dump_size);
 if(!stream)return false;
 ok=ir_dump(n->module,stream);
 if(fclose(stream))ok=false;
 char *sha=ok?g_compute_checksum_for_data(G_CHECKSUM_SHA256,(guchar *)n->dump,n->dump_size):NULL;
 if(!sha)return false;
 memcpy(n->sha,sha,65);g_free(sha);
 return true;
}
static void node_json(const Node *n) {
 printf("{\"pc\":%u,\"size\":%u,\"bytes\":\"",n->pc,n->size);
 for(unsigned i=0;i<n->size;++i)printf("%02x",n->bytes[i]);
 fputs("\",\"successors\":[",stdout);
 if(n->count)printf("%u",n->successors[0]);
 if(n->count==2)printf(",%u",n->successors[1]);
 printf("],\"original_ir_sha256\":\"%s\",\"ir_instructions\":%u,\"ir_values\":%u,\"store_count\":%u,\"gpr_writes\":%u,\"esp_writes\":%u,\"original_condition_value_id\":%u,\"original_ir_dump\":",
  n->sha,ir_module_inst_count(n->module),ir_module_value_count(n->module),n->stores,
  n->lift.gpr_writes,!!(n->lift.gpr_writes&(1U<<REG_RSP)),n->lift.condition);
 string_json(n->dump,n->dump_size);
 printf(",\"control\":%u,\"call\":%s,\"fallthrough\":%u,\"direct_target\":%u,\"target_value_id\":%u,\"flags_written\":%u,\"flags_undefined\":%u",n->lift.control,n->lift.call?"true":"false",n->lift.fallthrough,n->lift.direct_target,n->lift.target,n->lift.flags_written,n->lift.flags_undefined);
 fputs(",\"repeat_expansion_iterations\":",stdout);
 if(n->repeat_iterations<0)fputs("null",stdout);else printf("%d",n->repeat_iterations);
 fputs(",\"instructions\":[",stdout);
 for(IrInstId k=1;k<=ir_module_inst_count(n->module);++k){
  const IrInst *o=ir_module_inst(n->module,k);
  const IrState *state=o->spec.state?ir_module_state(n->module,o->spec.state):NULL;
  printf("%s{\"instruction_id\":%u,\"value_id\":%u,\"opcode\":\"%s\",\"bits\":%u,\"type_kind\":%u,\"args\":[%u,%u,%u],\"immediate\":%" PRIu64 ",\"state_key\":%" PRIu64 ",\"endian\":%u}",k>1?",":"",k,o->result,ir_opcode_name(o->spec.op),o->spec.type.bits,o->spec.type.kind,o->spec.args[0],o->spec.args[1],o->spec.args[2],o->spec.immediate,state?state->key:0,o->spec.endian);
 }
 fputs("],\"mnemonic\":",stdout);string_json(n->mnemonic,strlen(n->mnemonic));
 fputs(",\"operands\":",stdout);string_json(n->operands,strlen(n->operands));
 printf(",\"native_insn_id\":%u,\"lift_status\":%u,\"repeated\":%s,\"string_move\":%s,\"string_bytes\":%u,\"string_address_bytes\":%u,\"reads_memory\":%s,\"writes_memory\":%s,\"memory_bytes\":%u,\"segment_reads\":%u,\"opaque_syscall\":%s,\"ir_validator_passed\":true,\"ir_semantics_modeled\":%s,\"kernel_boundary_kind\":%s,\"boundary_resume_pc\":%u}",
  n->native_insn_id,n->lift.status,n->lift.repeated?"true":"false",n->lift.string_move?"true":"false",n->lift.string_bytes,n->lift.string_address_bytes,
  n->lift.reads_memory?"true":"false",n->lift.writes_memory?"true":"false",n->lift.memory_bytes,n->lift.segment_reads,n->opaque?"true":"false",
  n->opaque?"false":"true",n->opaque?"\"UNMODELED_INT80_EXPLICIT_CONTRACT_REQUIRED\"":"null",n->opaque?n->pc+n->size:0);
}


/* A bounded, single-threaded concrete/known-bit IR machine.  All OS effects
 * below are admitted contracts, not instruction semantics or a kernel proof. */
typedef unsigned __int128 U;
typedef struct { U v,k; unsigned bits; bool mem; } Value;
typedef struct { uint8_t v[4096],k[4096],origin[4096],producer_written[4096]; unsigned prot; int file; uint32_t offset; uint64_t *producer; unsigned producer_ordinal;
#ifdef TF_GENERIC_REPLAY
 uint64_t generic_guest_store_generation;
 uint32_t generic_mapping_epoch;
 int generic_backing_file_id;
 uint32_t generic_backing_offset,generic_descriptor_epoch,generic_content_epoch;
#endif
} Page;
typedef struct { uint8_t *v,*k; size_t size,logical_size; uint64_t *producer;
#ifdef TF_GENERIC_REPLAY
 uint64_t *generic_guest_store;
 bool generic_tail_dirty;
#endif
} File;
static Page *pages[1048576];
static File files[32];
static int descriptors[64];
static unsigned file_count=1;
static Value states[1024];
static uint64_t version,steps,loads,stores,ir_rows,unknown_loads;
#ifndef TF_GENERIC_REPLAY
static uint64_t checkpoint_instructions;
#endif
#ifdef TF_GENERIC_REPLAY
static uint8_t *projection;
static size_t projection_size;
static uint32_t initial_stack_base;
typedef struct { uint32_t start,size; } GenericRange;
static GenericRange generic_ranges[256];
static unsigned generic_range_count;
static GChecksum *fetch_hash;
static FILE *generic_write_origins;
static uint32_t generic_brk;
static unsigned generic_stack_prot=7;
static bool generic_brk_known;
static bool generic_file_written[32];
static unsigned generic_boundary_selector_version=1;
/* GEN1C selects a calibrated callback contract in the authenticated config.
 * Legacy GEN1 keeps its original terminal-zero convention.  This selects
 * route accounting only; original ECX/IR guards still determine the count. */
static bool generic_rep_terminal_zero=true,generic_rep_macro_once,generic_rep_profile_explicit;
static const char *generic_rep_callback_mode(void) {
 if(generic_rep_macro_once)return "macro_once";
 return generic_rep_terminal_zero?"terminal_zero":"body_only";
}
static const char *generic_rep_count_semantics(void) {
 if(!generic_rep_profile_explicit)return "qemu_i386_normal_rep_n_plus_one_v1";
 if(generic_rep_macro_once)return "rep_macro_once_v1";
 return generic_rep_terminal_zero?"rep_terminal_zero_v1":"rep_body_only_v1";
}
static uint64_t generic_macro_steps,generic_rep_macros,generic_rep_extra_callbacks;
static unsigned generic_rep_trace_iteration;
static void generic_trace_instruction(const Node *n,uint64_t trace_ordinal,const char *event_kind);
static uint64_t generic_stop_instruction_ordinal,generic_stop_page_generation;
static uint32_t generic_stop_mapping_epoch;
static const char *generic_mapping_operation="none";
static uint32_t generic_mapping_address,generic_mapping_size,generic_mapping_prot,generic_mapping_effect_epoch;
static char generic_zero_fill_sha256[65];
static uint32_t generic_descriptor_epochs[64],generic_descriptor_offsets[64],generic_content_epochs[32];
/* V6 tracks only live shared local-memfd aliases.  PRIVATE mappings retain
 * their independent snapshots and conservatively block backing mutations. */
static GHashTable *generic_shared_pages[32];
static unsigned generic_private_pages[32];
static char generic_source_sha256[65],generic_file_initial_sha256[65];
static const char *generic_descriptor_operation;
static bool generic_file_mapping_present;
static bool generic_effect_shared;
static uint32_t generic_effect_fd,generic_effect_descriptor_epoch,generic_effect_file_offset;
static uint32_t generic_effect_file_bytes,generic_effect_zero_tail,generic_effect_cache_tail,generic_effect_file_id;
static const char *generic_mutation_operation;
static uint32_t generic_mutation_fd,generic_mutation_file_id,generic_mutation_descriptor_epoch;
static uint32_t generic_mutation_old_size,generic_mutation_new_size,generic_mutation_offset_before,generic_mutation_offset_after;
static uint32_t generic_mutation_write_address,generic_mutation_write_count,generic_mutation_zero_start,generic_mutation_zero_end;
static char generic_mutation_write_sha256[65];
#else
static uint8_t projection[20480];
static const size_t projection_size=sizeof projection;
static const uint32_t initial_stack_base=0x407fc000;
#endif
static unsigned initial_stack_known_bytes;
#ifndef TF_GENERIC_REPLAY
static Value checkpoint_registers[8],checkpoint_flags[7];
#endif
static Node *last_node;
static Value last_eax;
static uint32_t last_target;
static uint32_t pc;
static unsigned ordinal;
static FILE *contracts,*catalogue,*kernel_receipts,*initial_reads;
static GChecksum *path_hash;
static csh decoder;
static GHashTable *nodes;
static void producer_resize_file(unsigned file,size_t old_size,size_t size);
static void producer_map_page(Page *p,uint32_t address,int file);
static void producer_free_page(Page *p);
static void die(const char *message) {
 fprintf(stderr,"FAIL pc=0x%08x instructions=%" PRIu64 " syscall=%u: %s\n",pc,steps,ordinal,message);exit(1);
}
static U mask(unsigned bits) { return bits==128?~(U)0:(((U)1<<bits)-1); }
static Value val(unsigned bits,U value,U known) { U m=mask(bits);return (Value){value&known&m,known&m,bits,false}; }
static Value known(unsigned bits,U value) { return val(bits,value,mask(bits)); }
static Value token(void) { Value v=known(64,version);v.mem=true;return v; }
static uint64_t integer(Value v) {
 if(v.mem||v.bits>64||v.k!=mask(v.bits))die("unknown or non-scalar operand");return (uint64_t)v.v;
}
static Page *page(uint32_t a,unsigned permission) {
 Page *p=pages[a>>12];if(!p||(p->prot&permission)!=permission){fprintf(stderr,"address=0x%08x permission=%u ESP=0x%08x\n",a,permission,(unsigned)states[260].v);die("unmapped or denied RAM access");}return p;
}
#ifdef TF_GENERIC_REPLAY
static void generic_forget_file_page(Page *p,uint32_t address) {
 if(generic_boundary_selector_version<6||!p||p->generic_backing_file_id<=0)return;
 unsigned file=(unsigned)p->generic_backing_file_id;
 if(p->file>=0){
  if(!generic_shared_pages[file]||!g_hash_table_remove(generic_shared_pages[file],GUINT_TO_POINTER((address>>12)+1)))
   die("generic shared page lifetime index");
 }else{
  if(!generic_private_pages[file])die("generic private page lifetime index");
  --generic_private_pages[file];
 }
}
static void generic_shared_refresh(unsigned file,bool values,bool producers) {
 if(generic_boundary_selector_version<6||!generic_shared_pages[file])return;
 File *f=&files[file];GHashTableIter iter;gpointer key,data;
 g_hash_table_iter_init(&iter,generic_shared_pages[file]);
 while(g_hash_table_iter_next(&iter,&key,&data)){
  Page *p=data;
  if(p!=pages[GPOINTER_TO_UINT(key)-1]||p->file!=(int)file||p->offset+4096>f->size)
   die("generic shared alias identity");
  if(values){memcpy(p->v,f->v+p->offset,4096);memcpy(p->k,f->k+p->offset,4096);}
  if(producers&&p->producer)memcpy(p->producer,f->producer+p->offset,4096*sizeof(*p->producer));
  p->generic_content_epoch=generic_content_epochs[file];
  uint64_t generation=0;
  for(unsigned i=0;i<4096;++i)if(f->generic_guest_store[p->offset+i]>generation)
   generation=f->generic_guest_store[p->offset+i];
  p->generic_guest_store_generation=generation;
 }
}
#endif
static void resize_file(unsigned f,size_t size) {
 if(f>=32||size>1048576)die("file bound");
 File *q=&files[f];if(size<=q->size)return;
 q->v=g_realloc(q->v,size);q->k=g_realloc(q->k,size);
 memset(q->v+q->size,0,size-q->size);memset(q->k+q->size,255,size-q->size);producer_resize_file(f,q->size,size);
#ifdef TF_GENERIC_REPLAY
 q->generic_guest_store=g_realloc(q->generic_guest_store,size*sizeof(*q->generic_guest_store));
 memset(q->generic_guest_store+q->size,0,(size-q->size)*sizeof(*q->generic_guest_store));
#endif
 q->size=size;
}
static void mapping(uint32_t lo,uint32_t length,unsigned prot,int f,uint32_t off) {
 uint64_t hi=((uint64_t)lo+length+4095)&~UINT64_C(4095);
 if(lo%4096||!length||hi>UINT64_C(0x100000000)||hi-lo>1048576)die("mapping geometry");
 for(uint64_t a=lo;a<hi;a+=4096){
#ifdef TF_GENERIC_REPLAY
  generic_forget_file_page(pages[a>>12],(uint32_t)a);
#endif
  producer_free_page(pages[a>>12]);g_free(pages[a>>12]);Page *p=g_malloc0(sizeof(*p));pages[a>>12]=p;p->prot=prot;p->file=f;p->offset=off+(uint32_t)(a-lo);
  memset(p->k,255,4096);
#ifdef TF_GENERIC_REPLAY
  if(generic_boundary_selector_version>=3)p->generic_mapping_epoch=ordinal;
  p->generic_backing_file_id=-1;
#endif
  if(f>=0){resize_file(f,(size_t)p->offset+4096);memcpy(p->v,files[f].v+p->offset,4096);memcpy(p->k,files[f].k+p->offset,4096);}
  producer_map_page(p,(uint32_t)a,f);
 }
 ++version;states[768]=token();
}
static Value load(uint32_t address,unsigned bits,unsigned permission) {
 if(!bits||bits%8||bits>128||(uint64_t)address+bits/8>UINT64_C(0x100000000))die("load extent");
 U v=0,k=0;for(unsigned i=0;i<bits/8;++i){Page *p=page(address+i,permission);unsigned o=(address+i)&4095;v|=(U)p->v[o]<<(i*8);k|=(U)p->k[o]<<(i*8);if(p->origin[o]==1){if((uint64_t)address+i<initial_stack_base||(uint64_t)address+i>=(uint64_t)initial_stack_base+projection_size)die("initial origin outside snapshot");projection[address+i-initial_stack_base]=255;}else if(p->origin[o]==2){if(!initial_reads||fprintf(initial_reads,"{\"address\":%u,\"value\":%u,\"known\":%u}\n",address+i,p->v[o]&p->k[o],p->k[o])<0)die("initial read receipt write");p->origin[o]=3;}}
 ++loads;if(k!=mask(bits))++unknown_loads;return val(bits,v,k);
}
static void store(uint32_t address,Value data) {
 if(data.mem||!data.bits||data.bits%8||(uint64_t)address+data.bits/8>UINT64_C(0x100000000))die("store extent");
#ifdef TF_GENERIC_REPLAY
 if(generic_boundary_selector_version==1&&last_node&&last_node->repeat_iterations>=0){
  /* A calibrated REP can be fetched again by QEMU between iterations.  The
   * bounded expansion may reuse one lifted opcode only while every computed
   * STORE leaves those opcode bytes intact, including modeled file aliases. */
  if(generic_rep_trace_iteration>=(unsigned)last_node->repeat_iterations)die("generic REP STORE count");
  for(unsigned i=0;i<data.bits/8;++i){Page *written=page(address+i,2);
   for(unsigned j=0;j<last_node->size;++j){uint32_t fetched=last_node->pc+j;Page *code=page(fetched,4);
    if(address+i==fetched||(written->file>=0&&written->file==code->file&&
       (uint64_t)written->offset+((address+i)&4095)==(uint64_t)code->offset+(fetched&4095)))
     die("generic REP STORE overlaps active opcode bytes");
   }
  }
  if(!generic_rep_macro_once)
   generic_trace_instruction(last_node,steps+generic_rep_trace_iteration,"rep_iteration");
  ++generic_rep_trace_iteration;
 }
 uint32_t mapping_epoch=0,writer_mapping_epoch=0;
 int shared_file=-1;uint32_t shared_offset=0;
 if(generic_boundary_selector_version>=3){
  mapping_epoch=page(address,2)->generic_mapping_epoch;writer_mapping_epoch=page(pc,4)->generic_mapping_epoch;
  for(unsigned i=0;i<data.bits/8;++i)if(page(address+i,2)->generic_mapping_epoch!=mapping_epoch)
   die("generic STORE crosses mapping lifetimes");
 }
 if(generic_boundary_selector_version>=6){
  Page *first=page(address,2);
  if(first->file>=0){
   shared_file=first->file;shared_offset=first->offset+(address&4095);
   uint64_t limit=files[shared_file].logical_size;
   if(generic_boundary_selector_version>=7)limit=(limit+4095)&~UINT64_C(4095);
   if(shared_file<=0||generic_private_pages[shared_file]||data.k!=mask(data.bits)||
      (uint64_t)shared_offset+data.bits/8>limit)
    die("generic shared STORE private alias, unknown byte or EOF tail");
   for(unsigned i=0;i<data.bits/8;++i){Page *p=page(address+i,2);
    if(p->file!=shared_file||(uint64_t)p->offset+((address+i)&4095)!=(uint64_t)shared_offset+i)
     die("generic shared STORE backing extent");
   }
   if(generic_boundary_selector_version>=7&&
      (uint64_t)shared_offset+data.bits/8>files[shared_file].logical_size)
    files[shared_file].generic_tail_dirty=true;
  }else for(unsigned i=0;i<data.bits/8;++i)if(page(address+i,2)->file>=0)
   die("generic STORE crosses shared backing");
 }
#endif
 for(unsigned i=0;i<data.bits/8;++i){Page *p=page(address+i,2);unsigned o=(address+i)&4095;
  p->v[o]=(uint8_t)(data.v>>(i*8));p->k[o]=(uint8_t)(data.k>>(i*8));p->origin[o]=0;p->producer_written[o]=1;
  if(p->file>=0){File *f=&files[p->file];f->v[p->offset+o]=p->v[o];f->k[p->offset+o]=p->k[o];
#ifdef TF_GENERIC_REPLAY
   if(generic_boundary_selector_version>=6)f->generic_guest_store[p->offset+o]=stores+1;
#endif
  }
 }
 ++stores;++version;
#ifdef TF_GENERIC_REPLAY
 for(uint64_t a=address>>12;a<=((uint64_t)address+data.bits/8-1)>>12;++a)
  pages[a]->generic_guest_store_generation=stores;
 if(shared_file>=0)generic_shared_refresh((unsigned)shared_file,true,false);
 /* Chronological IR-store observations are compared with independent guest
  * callbacks. They do not initialize RAM, constrain a producer, or replace
  * the existing fetch/address/control schedule proof. */
 if(!generic_write_origins||fprintf(generic_write_origins,
    "{\"step\":%" PRIu64 ",\"pc\":%u,\"address\":%u,\"size\":%u,\"store_ordinal\":%" PRIu64,
    steps,pc,address,data.bits/8,stores)<0)die("generic write chronology output");
 if(generic_boundary_selector_version>=3&&fprintf(generic_write_origins,
    ",\"mapping_epoch\":%u,\"writer_mapping_epoch\":%u",mapping_epoch,writer_mapping_epoch)<0)
  die("generic mapping write chronology output");
 if(generic_boundary_selector_version>=6){
  if(shared_file<0){if(fputs(",\"shared_file_write\":null",generic_write_origins)==EOF)die("generic shared write chronology");}
  else{
   if(fprintf(generic_write_origins,",\"shared_file_write\":{\"file_id\":%u,\"file_offset\":%u,\"data_hex\":\"",
      (unsigned)shared_file,shared_offset)<0)die("generic shared write chronology");
   for(unsigned i=0;i<data.bits/8;++i)if(fprintf(generic_write_origins,"%02x",(unsigned)(data.v>>(8*i))&255)<0)
    die("generic shared write chronology");
   if(fputs("\"}",generic_write_origins)==EOF)die("generic shared write chronology");
  }
 }
 if(fputs("}\n",generic_write_origins)==EOF)die("generic write chronology output");
#endif
}
static Value operation(IrOpcode op,unsigned bits,Value a,Value b,Value c,uint64_t imm) {
 U m=mask(bits),v=0,k=m;
 if(op==IR_OP_CONST)return known(bits,imm);
 if(op==IR_OP_UNKNOWN)return val(bits,0,0);
 if(op==IR_OP_EXTRACT)return val(bits,a.v>>imm,a.k>>imm);
 if(op==IR_OP_ZEXT)return val(bits,a.v,a.k|(m^mask(a.bits)));
 if(op==IR_OP_SEXT){bool sign_known=(a.k>> (a.bits-1))&1;U extension=m^mask(a.bits);return val(bits,a.v|(((a.v>>(a.bits-1))&1)?extension:0),a.k|(sign_known?extension:0));}
 if(op==IR_OP_CONCAT)return val(bits,(a.v<<b.bits)|b.v,(a.k<<b.bits)|b.k);
 if(op==IR_OP_ITE){if(a.k==1)return a.v?b:c;return val(bits,b.v,b.k&c.k&~(b.v^c.v));}
 if(op==IR_OP_NOT)return val(bits,~a.v,a.k);
 if(op==IR_OP_AND)return val(bits,a.v&b.v,(a.k&b.k)|(a.k&~a.v)|(b.k&~b.v));
 if(op==IR_OP_OR)return val(bits,a.v|b.v,(a.k&b.k)|(a.k&a.v)|(b.k&b.v));
 if(op==IR_OP_XOR)return val(bits,a.v^b.v,a.k&b.k);
 if(op==IR_OP_EQ){if((a.v^b.v)&a.k&b.k)return known(1,0);if(a.k!=mask(a.bits)||b.k!=mask(b.bits))return val(1,0,0);return known(1,a.v==b.v);}
 if(op==IR_OP_ULT){U amax=a.v|(mask(a.bits)^a.k),bmax=b.v|(mask(b.bits)^b.k);if(amax<b.v)return known(1,1);if(a.v>=bmax)return known(1,0);return val(1,0,0);}
 if(a.k!=mask(a.bits)||(op!=IR_OP_NEG&&b.k!=mask(b.bits)))return val(bits,0,0);
 switch(op){
 case IR_OP_ADD:v=a.v+b.v;break;case IR_OP_SUB:v=a.v-b.v;break;case IR_OP_NEG:v=-a.v;break;
 case IR_OP_MUL:v=a.v*b.v;break;
 case IR_OP_SHL:v=b.v>=bits?0:a.v<<(unsigned)b.v;break;
 case IR_OP_LSHR:v=b.v>=bits?0:a.v>>(unsigned)b.v;break;
 case IR_OP_ASHR:{bool sign=(a.v>>(a.bits-1))&1;unsigned shift=b.v>=bits?bits:(unsigned)b.v;v=shift>=bits?(sign?m:0):(a.v>>shift)|(sign?(m^(m>>shift)):0);break;}
 default:die("unsupported IR opcode");
 }
 return val(bits,v,k);
}
#include "oep_producers.h"
static void generic_check_fetch_lifetime(uint32_t address,unsigned size) {
#ifdef TF_GENERIC_REPLAY
 if(generic_boundary_selector_version>=3){
  uint32_t epoch=page(address,5)->generic_mapping_epoch;
  for(unsigned i=0;i<size;++i)if(page(address+i,5)->generic_mapping_epoch!=epoch)
   die("generic instruction crosses mapping lifetimes");
 }
#else
 (void)address;(void)size;
#endif
}
static Node *get_node(void) {
 uint8_t bytes[15];size_t count=0;
 for(unsigned i=0;i<15&&(uint64_t)pc+i<UINT64_C(0x100000000);++i){Page *p=pages[(pc+i)>>12];if(!p||!(p->prot&4))break;unsigned o=(pc+i)&4095;if(p->k[o]!=255)die("unknown instruction byte");bytes[count++]=p->v[o];}
 if(!count)die("no executable instruction bytes");
 cs_insn *insn=NULL;if(cs_disasm(decoder,bytes,count,pc,1,&insn)!=1)die("decode failed");
 generic_check_fetch_lifetime(pc,insn->size);
 bool repeated=insn->detail->x86.prefix[0]==X86_PREFIX_REP&&
  (insn->id==X86_INS_MOVSB||insn->id==X86_INS_MOVSW||insn->id==X86_INS_MOVSD||
   insn->id==X86_INS_STOSB||insn->id==X86_INS_STOSW||insn->id==X86_INS_STOSD);
 int repeats=repeated?(int)integer(states[257]):-1;
#ifdef TF_GENERIC_REPLAY
 unsigned key_bytes=insn->size;
#else
 unsigned key_bytes=(unsigned)count;
#endif
 cs_free(insn,1);if(repeated&&(repeats<0||repeats>4096))die("REP expansion bound");
 char key[128];int pos=snprintf(key,sizeof(key),"%08x:%d:",pc,repeats);
 for(unsigned i=0;i<key_bytes;++i)pos+=snprintf(key+pos,sizeof(key)-(size_t)pos,"%02x",bytes[i]);
 Node *n=g_hash_table_lookup(nodes,key);if(n)return n;
 n=g_malloc0(sizeof(*n));if(!lift_node(decoder,bytes,count,pc,repeats,n))die("production frontend lift failed");
 g_hash_table_insert(nodes,g_strdup(key),n);FILE *saved=stdout;stdout=catalogue;node_json(n);fputc('\n',stdout);stdout=saved;fflush(catalogue);
 return n;
}
static void bytes_file(const char *path,uint32_t address,size_t size) __attribute__((unused));
static uint32_t execute(Node *n) {
 size_t count=ir_module_value_count(n->module)+1;Value *values=g_malloc0(count*sizeof(*values));
 uint32_t *producers=producers_enabled?g_malloc0(count*sizeof(*producers)):NULL;
 for(IrInstId i=1;i<=ir_module_inst_count(n->module);++i){
  const IrInst *r=ir_module_inst(n->module,i);IrOpcode op=r->spec.op;unsigned bits=r->spec.type.bits;
  Value a=values[r->spec.args[0]],b=values[r->spec.args[1]],c=values[r->spec.args[2]],v={0};
  const IrState *s=r->spec.state?ir_module_state(n->module,r->spec.state):NULL;
  uint32_t pa=producers?producers[r->spec.args[0]]:0,pb=producers?producers[r->spec.args[1]]:0,pcell=producers?producers[r->spec.args[2]]:0,presult=0;
  ++ir_rows;
  if(op==IR_OP_READ_STATE){if(!s||s->key>=1024)die("state identity");v=states[s->key];presult=producer_state[s->key];}
  else if(op==IR_OP_WRITE_STATE){if(!s||s->key>=1024)die("state identity");states[s->key]=a;producer_state[s->key]=pa;continue;}
  else if(op==IR_OP_GUARD){if(integer(a)!=1)die("IR guard failed");producer_condition(2,pa,1);continue;}
  else if(op==IR_OP_LOAD){if(!a.mem||a.v!=version||r->spec.endian!=IR_ENDIAN_LE)die("LOAD RAM version/endian");uint32_t address=(uint32_t)integer(b);v=load(address,bits,1);producer_condition(3,pb,address);presult=producer_load(address,bits);}
  else if(op==IR_OP_STORE){if(!a.mem||a.v!=version||r->spec.endian!=IR_ENDIAN_LE)die("STORE RAM version/endian");uint32_t address=(uint32_t)integer(b);store(address,c);producer_condition(4,pb,address);producer_store(address,c.bits,pcell);v=token();}
  else {v=operation(op,bits,a,b,c,r->spec.immediate);presult=producer_operation(n,r,pa,pb,pcell);}
  if(r->result>=count)die("SSA result bound");values[r->result]=v;if(producers)producers[r->result]=presult;
 }
 if(!states[768].mem||states[768].v!=version)die("uncommitted RAM state");
 uint32_t next=n->lift.fallthrough;
 producer_target=0;
 if(n->lift.control==IR_X86_CONDITIONAL){uint64_t condition=integer(values[n->lift.condition]);producer_condition(1,producers?producers[n->lift.condition]:0,condition);next=condition?n->lift.direct_target:n->lift.fallthrough;}
 else if(n->lift.control==IR_X86_DIRECT_JUMP||n->lift.control==IR_X86_INDIRECT){next=(uint32_t)integer(values[n->lift.target]);if(producers)producer_target=producers[n->lift.target];producer_condition(8,producer_target,next);}
 g_free(producers);g_free(values);return next;
}
static void bytes_file(const char *path,uint32_t address,size_t size) {
 FILE *f=fopen(path,"rb");if(!f)die("input file missing");
 for(size_t i=0;i<size;++i){int b=fgetc(f);if(b==EOF)die("short input file");Page *p=page(address+(uint32_t)i,0);p->v[(address+i)&4095]=(uint8_t)b;p->k[(address+i)&4095]=255;}
 if(fgetc(f)!=EOF||fclose(f))die("input size");
}
static unsigned syscall_arity(unsigned number,uint32_t flags) {
 switch(number){
 case 356:case 93:case 91:return 2;
 case 4:case 19:case 85:case 125:case 144:return 3;
 case 6:case 45:case 90:return 1;
 case 192:return 6;
 case 5:return (flags&0x40U)||(flags&0x410000U)==0x410000U?3:2;
 default:die("unsupported syscall ABI");return 0;
 }
}
/* Kernel receipts inspect model arrays directly.  They must not perform an IR
 * LOAD/STORE, change read-before-write origins, or affect execution counters. */
static void scalar_json(Value *values,unsigned count);
static bool model_same_mapping_epoch(const Page *a,const Page *b,uint64_t delta) {
#ifdef TF_GENERIC_REPLAY
 if(generic_boundary_selector_version>=4&&
    (a->generic_backing_file_id!=b->generic_backing_file_id||
     a->generic_descriptor_epoch!=b->generic_descriptor_epoch||
     (generic_boundary_selector_version>=5&&a->generic_content_epoch!=b->generic_content_epoch)||
     (a->generic_backing_file_id>=0&&
      (uint64_t)b->generic_backing_offset!=(uint64_t)a->generic_backing_offset+delta)))return false;
 if(generic_boundary_selector_version>=3)return a->generic_mapping_epoch==b->generic_mapping_epoch;
#else
 (void)a;(void)b;(void)delta;
#endif
 return true;
}
static uint32_t model_file_offset(const Page *p) {
#ifdef TF_GENERIC_REPLAY
 if(generic_boundary_selector_version>=4&&p->file<0)return 0;
#endif
 return p->offset;
}
static void model_mapping_epoch_json(const Page *p) {
#ifdef TF_GENERIC_REPLAY
 if(generic_boundary_selector_version>=3)printf(",\"mapping_epoch\":%u",p->generic_mapping_epoch);
 if(generic_boundary_selector_version>=4)printf(",\"backing_file_id\":%d,\"backing_offset\":%u,\"descriptor_epoch\":%u",
  p->generic_backing_file_id,p->generic_backing_offset,p->generic_descriptor_epoch);
 if(generic_boundary_selector_version>=5)printf(",\"content_epoch\":%u",p->generic_content_epoch);
 if(generic_boundary_selector_version>=6)printf(",\"backing_shared\":%s",p->file>=0?"true":"false");
#else
 (void)p;
#endif
}
static void model_vmas_json(void) {
 fputc('[',stdout);bool first=true;
 for(unsigned lo=0;lo<1048576;){
  Page *p=pages[lo];if(!p){++lo;continue;}unsigned hi=lo+1;
  while(hi<1048576&&pages[hi]&&model_same_mapping_epoch(p,pages[hi],(uint64_t)(hi-lo)*4096)&&pages[hi]->prot==p->prot&&pages[hi]->file==p->file&&
        (p->file<0||(uint64_t)pages[hi]->offset==(uint64_t)p->offset+(uint64_t)(hi-lo)*4096))++hi;
  printf("%s{\"start\":%" PRIu64 ",\"end\":%" PRIu64 ",\"permissions\":%u,\"file_id\":%d,\"offset\":%u",first?"":",",(uint64_t)lo*4096,(uint64_t)hi*4096,p->prot,p->file,model_file_offset(p));
  model_mapping_epoch_json(p);fputc('}',stdout);
  first=false;lo=hi;
 }
 fputc(']',stdout);
}
static void model_bytes_json(const uint8_t *value,const uint8_t *known_mask,size_t size) {
 fputc('"',stdout);for(size_t i=0;i<size;++i)printf("%02x",value[i]&known_mask[i]);fputc('"',stdout);
}
static void model_memory_bytes(uint32_t address,size_t size,uint8_t *value,uint8_t *known_mask) {
 size_t limit=131072;
#ifdef TF_GENERIC_REPLAY
 if(generic_boundary_selector_version>=3)limit=1048576;
#endif
 if(size>limit||(uint64_t)address+size>UINT64_C(0x100000000))die("kernel receipt memory bound");
 for(size_t i=0;i<size;++i){Page *p=page(address+(uint32_t)i,0);unsigned offset=(address+i)&4095;known_mask[i]=p->k[offset];value[i]=p->v[offset]&known_mask[i];}
}
static void model_memory_json(uint32_t address,size_t size,const uint8_t *value,const uint8_t *known_mask) {
 printf("{\"address\":%u,\"size\":%zu,\"data_hex\":",address,size);model_bytes_json(value,known_mask,size);
 fputs(",\"known_hex\":",stdout);model_bytes_json(known_mask,known_mask,size);fputc('}',stdout);
}
static void model_memory_range(uint32_t address,size_t size) {
 uint8_t *value=malloc(size?size:1),*known_mask=malloc(size?size:1);
 if(!value||!known_mask)die("kernel receipt allocation");model_memory_bytes(address,size,value,known_mask);
 model_memory_json(address,size,value,known_mask);free(value);free(known_mask);
}
static void model_file_json(unsigned fd,int file) {
 File *f=&files[file];if(f->logical_size>f->size||f->logical_size>1048576)die("kernel receipt file bound");
 printf("{\"fd\":%u,\"model_file_id\":%d,\"size\":%zu,\"data_hex\":",fd,file,f->logical_size);
 model_bytes_json(f->v,f->k,f->logical_size);fputs(",\"known_hex\":",stdout);model_bytes_json(f->k,f->k,f->logical_size);fputc('}',stdout);
}
static void kernel_receipt_start(const char *directory) {
 char path[4096];int length=snprintf(path,sizeof path,"%s/kernel.jsonl",directory);
 if(length<0||(size_t)length>=sizeof path)die("kernel receipt path");
 kernel_receipts=fopen(path,"wb");if(!kernel_receipts)die("kernel receipt open");
 length=snprintf(path,sizeof path,"%s/initial-reads.jsonl",directory);
 if(length<0||(size_t)length>=sizeof path)die("initial read receipt path");
 initial_reads=fopen(path,"wb");if(!initial_reads)die("initial read receipt open");
 FILE *saved=stdout;stdout=kernel_receipts;
 fputs("{\"schema_version\":1,\"kind\":\"initial_model\",\"source_kind\":\"computed_IR_model\",\"ordinal\":0,\"vmas\":",stdout);
 model_vmas_json();fputs("}\n",stdout);stdout=saved;
}
static void kernel_receipt(unsigned number,uint32_t before,const uint32_t args[6],
                           uint32_t changed_address,size_t changed_size,int file,unsigned fd,
                           const uint8_t *write_value,const uint8_t *write_known,size_t write_size) {
 FILE *saved=stdout;stdout=kernel_receipts;
 printf("{\"schema_version\":1,\"kind\":\"kernel_model\",\"source_kind\":\"computed_IR_model\",\"ordinal\":%u,\"number\":%u,\"pc_before\":%u,\"pc_after\":%u,\"registers\":",ordinal,number,before,pc);
 scalar_json(states+256,8);fputs(",\"flags\":",stdout);scalar_json(states+512,7);fputs(",\"vmas\":",stdout);model_vmas_json();
 fputs(",\"write_buffer\":",stdout);if(write_value)model_memory_json(args[1],write_size,write_value,write_known);else fputs("null",stdout);
 fputs(",\"changed_memory\":[",stdout);bool first=true;
 if(changed_size){model_memory_range(changed_address,changed_size);first=false;}
 int changed_file=file;
#ifdef TF_GENERIC_REPLAY
 if(generic_boundary_selector_version>=6&&number==4&&generic_mutation_operation)
  changed_file=(int)generic_mutation_file_id;
#endif
 if(number==4&&changed_file>=0){
  for(unsigned lo=0;lo<1048576;){
   if(!pages[lo]||pages[lo]->file!=changed_file){++lo;continue;}
   unsigned hi=lo+1;while(hi<1048576&&hi-lo<32&&pages[hi]&&pages[hi]->file==changed_file)++hi;
   if(!first)fputc(',',stdout);model_memory_range(lo*4096,(hi-lo)*4096);first=false;lo=hi;
  }
 }
 fputs("],\"files\":[",stdout);if(file>=0)model_file_json(fd,file);fputs("],\"descriptors\":[",stdout);first=true;
 for(unsigned i=0;i<64;++i)if(descriptors[i]>=0){printf("%s{\"fd\":%u,\"model_file_id\":%d}",first?"":",",i,descriptors[i]);first=false;}
 fputs("]",stdout);
#ifdef TF_GENERIC_REPLAY
 if(generic_boundary_selector_version>=3){
  printf(",\"mapping_effect\":{\"operation\":\"%s\",\"address\":%u,\"size\":%u,\"prot\":%u,\"mapping_epoch\":%u,\"zero_fill_sha256\":",
   generic_mapping_operation,generic_mapping_address,generic_mapping_size,generic_mapping_prot,generic_mapping_effect_epoch);
  if(generic_zero_fill_sha256[0])printf("\"%s\"",generic_zero_fill_sha256);else fputs("null",stdout);fputc('}',stdout);
 }
 if(generic_boundary_selector_version>=4){
  fputs(",\"file_mapping\":",stdout);
  if(generic_file_mapping_present){
   printf("{\"fd\":%u,\"file_id\":%u,\"descriptor_epoch\":%u,\"file_size\":%zu,\"file_offset\":%u,\"file_bytes\":%u,\"zero_tail_bytes\":%u,\"initial_bytes_sha256\":\"%s\"",
    generic_effect_fd,generic_effect_file_id,generic_effect_descriptor_epoch,files[generic_effect_file_id].logical_size,generic_effect_file_offset,
    generic_effect_file_bytes,generic_effect_zero_tail,generic_file_initial_sha256);
   if(generic_boundary_selector_version>=5)printf(",\"content_epoch\":%u",generic_content_epochs[generic_effect_file_id]);
   if(generic_boundary_selector_version>=6)printf(",\"shared\":%s",generic_effect_shared?"true":"false");
   if(generic_boundary_selector_version>=7)printf(",\"cache_tail_bytes\":%u",generic_effect_cache_tail);
   fputc('}',stdout);
  }else fputs("null",stdout);
  fputs(",\"file_descriptor\":",stdout);
  if(generic_descriptor_operation){
   printf("{\"operation\":\"%s\",\"fd\":%u,\"file_id\":%u,\"descriptor_epoch\":%u,\"file_size\":%zu,\"source_sha256\":",
    generic_descriptor_operation,generic_effect_fd,generic_effect_file_id,generic_effect_descriptor_epoch,
    files[generic_effect_file_id].logical_size);
   if(generic_effect_file_id)fputs("null",stdout);else printf("\"%s\"",generic_source_sha256);
   fputc('}',stdout);
  }else fputs("null",stdout);
 }
 if(generic_boundary_selector_version>=5){
  fputs(",\"file_mutation\":",stdout);
  if(generic_mutation_operation){
   printf("{\"operation\":\"%s\",\"fd\":%u,\"file_id\":%u,\"descriptor_epoch\":%u,\"content_epoch\":%u,\"old_size\":%u,\"new_size\":%u,\"offset_before\":%u,\"offset_after\":%u,\"write_address\":%u,\"write_count\":%u,\"zero_start\":%u,\"zero_end\":%u,\"write_sha256\":",
    generic_mutation_operation,generic_mutation_fd,generic_mutation_file_id,generic_mutation_descriptor_epoch,
    generic_content_epochs[generic_mutation_file_id],generic_mutation_old_size,generic_mutation_new_size,
    generic_mutation_offset_before,generic_mutation_offset_after,generic_mutation_write_address,generic_mutation_write_count,
    generic_mutation_zero_start,generic_mutation_zero_end);
   if(generic_mutation_write_sha256[0])printf("\"%s\"",generic_mutation_write_sha256);else fputs("null",stdout);
   fputc('}',stdout);
  }else fputs("null",stdout);
 }
#endif
 fputs(",\"kernel_implementation_verified\":false}\n",stdout);
 bool failed=ferror(kernel_receipts);stdout=saved;if(failed||fflush(kernel_receipts))die("kernel receipt write");
}
/* End side-effect-free kernel receipt serializers. */
#ifdef TF_GENERIC_REPLAY
/* This narrow V3 model admits a successful anonymous mapping constructor,
 * never a captured postimage. Its errno cases are only preflight EINVAL
 * geometries that Linux rejects before any mapping/protection mutation. */
/* Discarded or newly exposed bytes are constructor zero leaves even when an
 * existing allocation is reused. File writes retain their original LOAD DAG. */
static void generic_file_zero(unsigned file,size_t low,size_t high) {
 if(file==0||file>=file_count||low>high||high>files[file].size)die("generic mutable zero extent");
 File *f=&files[file];
 for(size_t i=low;i<high;++i){
  f->v[i]=0;f->k[i]=255;
  if(generic_boundary_selector_version>=6)f->generic_guest_store[i]=0;
  if(producers_enabled)f->producer[i]=producer_cell(producer_leaf(P_KERNEL_FILE_ZERO,8,
    ((uint64_t)file<<56)|((uint64_t)ordinal<<32)|i,0),0,8);
 }
}
static void generic_mapping_kernel(Node *n,uint32_t address,unsigned number,
                                   const uint32_t args[6],uint32_t result,const char *reply) {
 uint32_t effective[6]={0};
 bool file_profile=generic_boundary_selector_version>=4;
 bool mutable_profile=generic_boundary_selector_version>=5;
 bool shared_profile=generic_boundary_selector_version>=6;
 bool cache_profile=generic_boundary_selector_version>=7;
 if(mutable_profile&&ordinal>256)die("generic mutable syscall budget");
 size_t write_size=0;uint8_t *write_value=NULL,*write_known=NULL;
 if(number!=90&&number!=192&&number!=91&&number!=125&&
    !(cache_profile&&number==144)&&
    !(file_profile&&(number==5||number==6))&&
    !(mutable_profile&&(number==356||number==4||number==93||number==19)))die("generic mapping syscall unsupported");
 if(strcmp(reply,"-"))die("generic mapping unexpected reply bytes");
 generic_mapping_operation="none";generic_mapping_address=0;generic_mapping_size=0;
 generic_mapping_prot=0;generic_mapping_effect_epoch=0;generic_zero_fill_sha256[0]=0;
 generic_file_mapping_present=false;generic_effect_shared=false;generic_descriptor_operation=NULL;
 generic_effect_fd=0;generic_effect_descriptor_epoch=0;generic_effect_file_offset=0;
 generic_effect_file_bytes=0;generic_effect_zero_tail=0;generic_effect_cache_tail=0;generic_effect_file_id=0;generic_file_initial_sha256[0]=0;
 generic_mutation_operation=NULL;generic_mutation_write_sha256[0]=0;
 generic_mutation_write_address=0;generic_mutation_write_count=0;generic_mutation_zero_start=0;generic_mutation_zero_end=0;
 /* V7 admits only MS_SYNC over already modelled local shared mappings.  The
  * bytes remain in this memfd page cache; no observed bytes become sources. */
 if(cache_profile&&number==144){
  uint64_t size=((uint64_t)args[1]+4095)&~UINT64_C(4095);
  uint64_t end=(uint64_t)args[0]+size;
  if(result||args[2]!=4||!args[1]||size>1048576||args[0]<0x10000||
     args[0]%4096||end>UINT64_C(0x100000000))die("generic cache msync profile");
  for(uint64_t a=args[0];a<end;a+=4096){Page *p=pages[a>>12];
   if(!p||p->file<=0||p->generic_backing_file_id!=p->file)
    die("generic cache msync requires local shared mappings");
  }
  goto complete;
 }
 if(mutable_profile&&(number==356||number==4||number==93||number==19)){
  if(result>=UINT32_C(0xfffff001))die("generic mutable file failure unsupported");
  if(number==356){
   if((args[1]>1&&(!shared_profile||(args[1]!=16&&args[1]!=17)))||result<3||result>=64||descriptors[result]>=0||file_count>=32)
    die("generic memfd create descriptor or flags");
   bool terminated=false;
   for(unsigned i=0;i<64;++i){
    if((uint64_t)args[0]+i>UINT32_MAX)die("generic memfd name extent");
    unsigned byte=(unsigned)integer(load(args[0]+i,8,1));
    producer_condition(9,producer_load(args[0]+i,8),byte);
    if(!byte){terminated=true;break;}
   }
   if(!terminated)die("generic memfd name unterminated");
   unsigned file=file_count++;descriptors[result]=(int)file;
   generic_descriptor_epochs[result]=ordinal;generic_descriptor_offsets[result]=0;generic_content_epochs[file]=ordinal;
   generic_descriptor_operation="memfd_create";generic_effect_fd=result;
   generic_effect_file_id=file;generic_effect_descriptor_epoch=ordinal;
  }else{
   unsigned fd=args[0];
   if(fd<3||fd>=64||descriptors[fd]<=0||!generic_descriptor_epochs[fd])die("generic mutable file descriptor");
   unsigned file=(unsigned)descriptors[fd];File *f=&files[file];
   if(number!=19)for(unsigned i=0;i<1048576;++i)
    if(pages[i]&&pages[i]->generic_backing_file_id==(int)file&&
       (!shared_profile||number==93||pages[i]->file<0))die("generic mutation while private mapping live");
   size_t old_size=f->logical_size;uint32_t before=generic_descriptor_offsets[fd];
   generic_mutation_operation=number==4?"write":number==93?"truncate":"seek";
   generic_mutation_fd=fd;generic_mutation_file_id=file;generic_mutation_descriptor_epoch=generic_descriptor_epochs[fd];
   generic_mutation_old_size=(uint32_t)old_size;generic_mutation_offset_before=before;
   if(number==19){
    if(args[2]||args[1]>1048576||result!=args[1])die("generic mutable seek contract");
    generic_descriptor_offsets[fd]=result;
   }else if(number==93){
    if(result||args[1]>1048576)die("generic mutable truncate contract");
    if(cache_profile&&f->generic_tail_dirty)die("generic truncate after dirty EOF cache tail unsupported");
    size_t desired=args[1],capacity=(desired+4095)&~(size_t)4095;
    resize_file(file,capacity);
    if(desired!=old_size){
     size_t low=desired<old_size?desired:old_size;
     size_t high=desired<old_size?f->size:capacity;
     generic_file_zero(file,low,high);
     f->logical_size=desired;generic_content_epochs[file]=ordinal;
     if(desired>old_size){generic_mutation_zero_start=(uint32_t)old_size;generic_mutation_zero_end=(uint32_t)desired;}
    }
   }else{
    if(args[2]>1048576||result>args[2]||(uint64_t)args[1]+args[2]>UINT64_C(0x100000000)||
       (uint64_t)before+result>1048576)die("generic mutable write contract or extent");
    if(cache_profile&&f->generic_tail_dirty&&(uint64_t)before+result>old_size)
     die("generic write extension after dirty EOF cache tail unsupported");
    if(shared_profile&&generic_shared_pages[file]&&g_hash_table_size(generic_shared_pages[file])&&
       (uint64_t)before+result>old_size)die("generic shared live write extends logical EOF");
    write_size=args[2];write_value=g_malloc(write_size?write_size:1);write_known=g_malloc(write_size?write_size:1);
    model_memory_bytes(args[1],write_size,write_value,write_known);
    generic_mutation_write_address=args[1];generic_mutation_write_count=result;
    for(uint32_t i=0;i<result;++i)if(write_known[i]!=255)die("generic mutable write consumed unknown byte");
    gchar *sha=g_compute_checksum_for_data(G_CHECKSUM_SHA256,write_value,result);
    memcpy(generic_mutation_write_sha256,sha,65);g_free(sha);
    if(result){
     size_t desired=old_size>(size_t)before+result?old_size:(size_t)before+result;
     size_t capacity=(desired+4095)&~(size_t)4095;
     resize_file(file,capacity);
     /* An in-file write does not clear bytes in a memfd's final partial
      * cache page.  V1-V6 retain their existing constructor profile. */
     if(!cache_profile||desired>old_size)generic_file_zero(file,old_size,capacity);
     for(uint32_t i=0;i<result;++i){
      Value byte=load(args[1]+i,8,1);f->v[before+i]=(uint8_t)byte.v;f->k[before+i]=(uint8_t)byte.k;
      if(producers_enabled)f->producer[before+i]=producer_cell(producer_load(args[1]+i,8),0,8);
      if(shared_profile)f->generic_guest_store[before+i]=0;
     }
     if(before>old_size){generic_mutation_zero_start=(uint32_t)old_size;generic_mutation_zero_end=before;}
     f->logical_size=desired;generic_descriptor_offsets[fd]=before+result;generic_content_epochs[file]=ordinal;
     if(shared_profile)generic_shared_refresh(file,true,true);
    }
   }
   generic_mutation_new_size=(uint32_t)f->logical_size;generic_mutation_offset_after=generic_descriptor_offsets[fd];
  }
  goto complete;
 }
 if(file_profile&&(number==5||number==6)){
  if(result>=UINT32_C(0xfffff001))die("generic file descriptor failure unsupported");
  if(number==5){
   static const char path[]="/proc/self/exe";
   if(args[1]||result<3||result>=64||descriptors[result]>=0||
      (uint64_t)args[0]+sizeof path>UINT64_C(0x100000000))die("generic read-only source open profile");
   for(unsigned i=0;i<sizeof path;++i){
    if(integer(load(args[0]+i,8,1))!=(unsigned char)path[i])die("generic source open pathname differs");
    producer_condition(9,producer_load(args[0]+i,8),(unsigned char)path[i]);
   }
   descriptors[result]=0;generic_descriptor_epochs[result]=ordinal;generic_descriptor_offsets[result]=0;
   generic_descriptor_operation="open";generic_effect_fd=result;generic_effect_descriptor_epoch=ordinal;
   if(!generic_source_sha256[0]){
    gchar *sha=g_compute_checksum_for_data(G_CHECKSUM_SHA256,files[0].v,files[0].logical_size);
    memcpy(generic_source_sha256,sha,65);g_free(sha);
   }
  }else{
   unsigned fd=args[0];
   if(result||fd<3||fd>=64||(descriptors[fd]<0||(!mutable_profile&&descriptors[fd]!=0))||!generic_descriptor_epochs[fd])
    die("generic source close descriptor identity");
   generic_descriptor_operation="close";generic_effect_fd=fd;
   generic_effect_descriptor_epoch=generic_descriptor_epochs[fd];generic_effect_file_id=(uint32_t)descriptors[fd];
   descriptors[fd]=-1;generic_descriptor_epochs[fd]=0;generic_descriptor_offsets[fd]=0;
  }
  goto complete;
 }
 bool map=number==90||number==192;
 bool file_mapping=false;uint64_t file_offset=0;unsigned mapped_file=0;
 if(map){
  if(number==90){
   if((uint64_t)args[0]+24>UINT64_C(0x100000000))die("generic old_mmap argument extent");
   for(unsigned i=0;i<6;++i){
    effective[i]=(uint32_t)integer(load(args[0]+4*i,32,1));
    producer_condition(6,producer_load(args[0]+4*i,32),effective[i]);
   }
  }else memcpy(effective,args,sizeof effective);
  for(unsigned i=0;i<6;++i){uint32_t expected;
   if(fscanf(contracts,"%x",&expected)!=1||expected!=effective[i])die("computed mmap array differs");
  }
  if(effective[2]>7||!(effective[2]&1))die("generic mapping readable protection profile");
  if(file_profile&&(effective[3]==2||effective[3]==0x12||
       (shared_profile&&(effective[3]==1||effective[3]==0x11)))){
   unsigned fd=effective[4];
   if(fd<3||fd>=64||(descriptors[fd]<0||(!mutable_profile&&descriptors[fd]!=0))||!generic_descriptor_epochs[fd])
    die("generic private file mapping descriptor");
   mapped_file=(unsigned)descriptors[fd];
   if((effective[3]&3)==1&&!mapped_file)die("generic shared immutable source mapping unsupported");
   file_mapping=true;file_offset=(uint64_t)effective[5]*(number==192?4096:1);
   if(file_offset>UINT32_MAX||file_offset>1048576)die("generic file mapping offset budget");
  }else if((effective[3]!=0x22&&effective[3]!=0x32)||effective[4]!=UINT32_MAX||effective[5])
   die("generic anonymous private mapping profile");
 }
 uint32_t start=map?effective[0]:args[0],size=map?effective[1]:args[1];
 uint64_t rounded_size=((uint64_t)size+4095)&~UINT64_C(4095);
 if(rounded_size>1048576)die("generic mapping extent budget");
 if(number==125&&args[2]>7)die("generic mapping protection unsupported");
 bool invalid=map?(!size||((effective[3]&16)&&start%4096)||(file_mapping&&file_offset%4096)):
              number==91?(!size||start%4096):(start%4096)!=0;
 if(result>=UINT32_C(0xfffff001)){
  if(result!=UINT32_C(0xffffffea)||!invalid)die("generic mapping failure effect unsupported");
 }else{
  if(invalid||!size)die("generic mapping success has invalid geometry");
  uint32_t location=map?result:start;
  uint64_t end=(uint64_t)location+rounded_size;
  if(location<0x10000||location%4096||end>UINT64_C(0x100000000))die("generic mapping result geometry");
  if(map&&(effective[3]&16)&&result!=start)die("generic MAP_FIXED result differs");
  if(file_mapping&&(file_offset>=files[mapped_file].logical_size||
     file_offset+rounded_size>((files[mapped_file].logical_size+4095)&~(size_t)4095)))
   die("generic file mapping whole page beyond EOF unsupported");
  if(!map&&result)die("generic mapping nonzero success result");
  unsigned dynamic_pages=0;
  for(unsigned i=0;i<1048576;++i)if(pages[i]&&pages[i]->generic_mapping_epoch)++dynamic_pages;
  for(uint64_t a=location;a<end;a+=4096){Page *p=pages[a>>12];
   if(p&&!p->generic_mapping_epoch&&number!=125)die("generic mapping changes protected initial mapping");
   if(map&&p&&!(effective[3]&16))die("generic nonfixed mapping overlaps live mapping");
   if(number==125&&!p)die("generic protection touches unmapped memory");
   if(map&&!p)++dynamic_pages;
  }
  if(dynamic_pages>4096)die("generic live mapping page budget");
  generic_mapping_address=location;generic_mapping_size=(uint32_t)rounded_size;
  if(map){
   generic_mapping_operation="map";generic_mapping_prot=effective[2];generic_mapping_effect_epoch=ordinal;
   if(file_mapping){
    unsigned fd=effective[4];
    mapping(location,size,effective[2],(int)mapped_file,(uint32_t)file_offset);
    for(uint64_t a=location;a<end;a+=4096){Page *p=pages[a>>12];
     p->generic_backing_file_id=(int)mapped_file;p->generic_backing_offset=(uint32_t)(file_offset+a-location);
     p->generic_descriptor_epoch=generic_descriptor_epochs[fd];p->generic_content_epoch=generic_content_epochs[mapped_file];
     bool shared=shared_profile&&(effective[3]&3)==1;p->file=shared?(int)mapped_file:-1;
     if(shared_profile&&mapped_file){
      if(shared){
       if(!generic_shared_pages[mapped_file])generic_shared_pages[mapped_file]=g_hash_table_new(g_direct_hash,g_direct_equal);
       g_hash_table_insert(generic_shared_pages[mapped_file],GUINT_TO_POINTER((unsigned)(a>>12)+1),p);
      }else ++generic_private_pages[mapped_file];
      for(unsigned i=0;i<4096;++i)if(files[mapped_file].generic_guest_store[p->offset+i]>p->generic_guest_store_generation)
       p->generic_guest_store_generation=files[mapped_file].generic_guest_store[p->offset+i];
     }
    }
    generic_file_mapping_present=true;generic_effect_shared=shared_profile&&(effective[3]&3)==1;generic_effect_fd=fd;generic_effect_file_id=mapped_file;
    generic_effect_descriptor_epoch=generic_descriptor_epochs[fd];generic_effect_file_offset=(uint32_t)file_offset;
    uint64_t available=files[mapped_file].logical_size-file_offset;
    generic_effect_file_bytes=(uint32_t)(available<rounded_size?available:rounded_size);
    generic_effect_zero_tail=(uint32_t)rounded_size-generic_effect_file_bytes;
    if(cache_profile&&mapped_file){
     generic_effect_cache_tail=generic_effect_zero_tail;generic_effect_zero_tail=0;
    }
    gchar *sha=g_compute_checksum_for_data(G_CHECKSUM_SHA256,files[mapped_file].v+file_offset,(gsize)rounded_size);
    memcpy(generic_file_initial_sha256,sha,65);g_free(sha);
   }else{
    mapping(location,size,effective[2],-1,0);
    uint8_t *zeros=g_malloc0((gsize)rounded_size);
    gchar *sha=g_compute_checksum_for_data(G_CHECKSUM_SHA256,zeros,(gsize)rounded_size);
    memcpy(generic_zero_fill_sha256,sha,65);g_free(sha);g_free(zeros);
   }
  }else{
   generic_mapping_operation=number==91?"unmap":"protect";
   generic_mapping_prot=number==125?args[2]:0;
   for(uint64_t a=location;a<end;a+=4096){
    if(number==91){generic_forget_file_page(pages[a>>12],(uint32_t)a);producer_free_page(pages[a>>12]);g_free(pages[a>>12]);pages[a>>12]=NULL;}
    else pages[a>>12]->prot=args[2];
   }
   ++version;states[768]=token();
  }
 }
complete:
 states[256]=known(32,result);
 producer_state[256]=producer_leaf(P_KERNEL_RESULT,32,((uint64_t)ordinal<<32)|number,result);
 pc=n->pc+n->size;
 uint32_t changed_address=0;size_t changed_size=0;
 if(!strcmp(generic_mapping_operation,"map")||!strcmp(generic_mapping_operation,"protect")){
  changed_address=generic_mapping_address;changed_size=generic_mapping_size;
 }
 kernel_receipt(number,address,args,changed_address,changed_size,-1,0,write_value,write_known,write_size);
 g_free(write_value);g_free(write_known);
 fprintf(stderr,"kernel %u number=%u result=0x%08x instructions=%" PRIu64 " mapping_effect=%s\n",
  ordinal,number,result,steps,generic_mapping_operation);
}
#endif
static void kernel(Node *n) {
 unsigned number;uint32_t address,args[6],result;char reply[8193];
 if(fscanf(contracts,"%x %u %x %x %x %x %x %x %x %8192s",&address,&number,&args[0],&args[1],&args[2],&args[3],&args[4],&args[5],&result,reply)!=10)die("kernel contract missing");
 static const unsigned keys[]={259,257,258,262,263,261};
 ++ordinal;if(address!=pc||integer(states[256])!=number)die("computed syscall identity differs");
 producer_condition(6,producer_state[256],number);
 unsigned arity=syscall_arity(number,number==5?(uint32_t)integer(states[257]):0);
 for(unsigned i=0;i<arity;++i){if(integer(states[keys[i]])!=args[i])die("computed syscall arguments differ");producer_condition(6,producer_state[keys[i]],args[i]);}
#ifdef TF_GENERIC_REPLAY
 if(generic_boundary_selector_version>=3){generic_mapping_kernel(n,address,number,args,result,reply);return;}
#endif
 unsigned fd=args[0],receipt_fd=fd;int receipt_file=fd<64?descriptors[fd]:-1;
 uint32_t changed_address=0;size_t changed_size=0,write_size=0;uint8_t *write_value=NULL,*write_known=NULL;
 if(number==4){write_size=args[2];if(write_size>131072)die("kernel receipt write bound");write_value=malloc(write_size?write_size:1);write_known=malloc(write_size?write_size:1);if(!write_value||!write_known)die("kernel receipt allocation");model_memory_bytes(args[1],write_size,write_value,write_known);}
 #ifdef TF_GENERIC_REPLAY
 if(number==45){
  if(!generic_brk_known)die("generic initial brk was not source-constructed");
  if(result!=generic_brk)die("generic brk memory changes are unsupported");
 }
 if(number==93){
  if(fd>=64||descriptors[fd]<=0||args[1]<files[descriptors[fd]].logical_size)die("generic truncate source/shrink unsupported");
 }
 if(number==4){
  if(fd>=64||descriptors[fd]<=0||generic_file_written[descriptors[fd]])die("generic write requires one newly created file write");
  generic_file_written[descriptors[fd]]=true;
 }
#endif
 if(number==356){if(result>=64||file_count>=32||descriptors[result]>=0)die("memfd contract");descriptors[result]=file_count++;receipt_fd=result;receipt_file=descriptors[result];}
 else if(number==93){if(fd>=64||descriptors[fd]<0||result)die("ftruncate contract");resize_file(descriptors[fd],args[1]);files[descriptors[fd]].logical_size=args[1];}
 else if(number==4){if(fd>=64||descriptors[fd]<0||result!=args[2])die("write contract");int f=descriptors[fd];resize_file(f,((size_t)result+4095)&~(size_t)4095);
  for(uint32_t i=0;i<result;++i){Value v=load(args[1]+i,8,1);files[f].v[i]=(uint8_t)v.v;files[f].k[i]=(uint8_t)v.k;if(producers_enabled)files[f].producer[i]=producer_cell(producer_load(args[1]+i,8),0,8);}
  if(files[f].logical_size<result)files[f].logical_size=result;
  for(unsigned p=0;p<1048576;++p)if(pages[p]&&pages[p]->file==f){memcpy(pages[p]->v,files[f].v+pages[p]->offset,4096);memcpy(pages[p]->k,files[f].k+pages[p]->offset,4096);if(producers_enabled)memcpy(pages[p]->producer,files[f].producer+pages[p]->offset,4096*sizeof(*pages[p]->producer));}
 }
 else if(number==5){if(result>=64||descriptors[result]>=0)die("open descriptor contract");const char *path="/proc/self/exe";for(unsigned i=0;i<=strlen(path);++i){if(integer(load(args[0]+i,8,1))!=(unsigned char)path[i])die("open path");producer_condition(9,producer_load(args[0]+i,8),(unsigned char)path[i]);}descriptors[result]=0;receipt_fd=result;receipt_file=0;}
 else if(number==6){if(fd>=64||descriptors[fd]<0||result)die("close contract");descriptors[fd]=-1;}
 else if(number==85){size_t len=strlen(reply);if(len!=result*2||result>args[2])die("readlink reply contract");for(unsigned i=0;i<result;++i){unsigned x;if(sscanf(reply+2*i,"%2x",&x)!=1)die("readlink hex");store(args[1]+i,known(8,x));if(producers_enabled)producer_store(args[1]+i,8,producer_leaf(P_READLINK_BYTE,8,((uint64_t)ordinal<<32)|i,x));}states[768]=token();changed_address=args[1];changed_size=result;}
 else if(number==90||number==192){uint32_t a[6];if(number==90){for(unsigned i=0;i<6;++i)a[i]=(uint32_t)integer(load(args[0]+4*i,32,1));}else memcpy(a,args,sizeof(a));
  uint32_t expected[6];for(unsigned i=0;i<6;++i){if(fscanf(contracts,"%x",&expected[i])!=1||expected[i]!=a[i])die("computed mmap array differs");if(number==90)producer_condition(6,producer_load(args[0]+4*i,32),a[i]);}
  if((a[3]&16)&&result!=a[0])die("MAP_FIXED result");int f=-1;
  if(!(a[3]&32)){if(a[4]>=64||descriptors[a[4]]<0)die("mmap descriptor");f=descriptors[a[4]];}
  receipt_file=f;receipt_fd=a[4];changed_address=result;changed_size=(((uint64_t)result+a[1]+4095)&~UINT64_C(4095))-result;
  uint32_t off=number==192?a[5]*4096:a[5];
#ifdef TF_GENERIC_REPLAY
  uint64_t offset64=(uint64_t)a[5]*(number==192?4096:1),mapped=((uint64_t)a[1]+4095)&~UINT64_C(4095);
  if(a[2]>7||(a[3]&~UINT32_C(0x33))||((a[3]&3)!=1&&(a[3]&3)!=2)||offset64>UINT32_MAX||offset64%4096)die("generic mmap protection/offset unsupported");
  if(f>=0&&offset64+mapped>((files[f].logical_size+4095)&~(size_t)4095))die("generic file mapping beyond EOF unsupported");
  if(f>=0&&(a[3]&1))for(unsigned p=0;p<1048576;++p)if(pages[p]&&pages[p]->file==f&&
     !((uint64_t)p*4096>=result&&(uint64_t)p*4096<(uint64_t)result+mapped))die("generic simultaneous shared file aliases unsupported");
  off=(uint32_t)offset64;
#endif
  mapping(result,a[1],a[2],f,off);
  if(!(a[3]&1))for(uint64_t p=result>>12;p<((uint64_t)result+a[1]+4095)/4096;++p)pages[p]->file=-1;
 }
 else if(number==91||number==125){uint64_t hi=((uint64_t)args[0]+args[1]+4095)&~UINT64_C(4095);if(result||args[0]%4096||hi>UINT64_C(0x100000000))die("unmap/protect contract");
  for(uint64_t a=args[0];a<hi;a+=4096){if(number==91){producer_free_page(pages[a>>12]);g_free(pages[a>>12]);pages[a>>12]=NULL;}else{
#ifdef TF_GENERIC_REPLAY
   if(args[2]>7)die("generic protection flags unsupported");
#endif
   Page *p=page((uint32_t)a,0);p->prot=args[2];}}
  ++version;states[768]=token();if(number==125){changed_address=args[0];changed_size=hi-args[0];}receipt_file=-1;
 }
 else if(number==144){if(result)die("msync success contract");changed_address=args[0];changed_size=(((uint64_t)args[0]+args[1]+4095)&~UINT64_C(4095))-args[0];receipt_file=page(args[0],0)->file;receipt_fd=64;for(unsigned i=0;i<64;++i)if(descriptors[i]==receipt_file&&receipt_file>=0){receipt_fd=i;break;}}
 else if(number!=45)die("unsupported kernel contract");
 if(number==45||number==85)receipt_file=-1;
 states[256]=known(32,result);producer_state[256]=producer_leaf(P_KERNEL_RESULT,32,((uint64_t)ordinal<<32)|number,result);pc=n->pc+n->size;
 kernel_receipt(number,address,args,changed_address,changed_size,receipt_file,receipt_fd,write_value,write_known,write_size);free(write_value);free(write_known);
 fprintf(stderr,"kernel %u number=%u result=0x%08x instructions=%" PRIu64 "\n",ordinal,number,result,steps);
}
#ifndef TF_GENERIC_REPLAY
static void dump_ram(const char *dir,bool at_checkpoint) {
 const uint32_t ranges[][2]={{0x8048000,4096},{0x8049000,94208},{0x8060000,12288},{0x8063000,8192},{0x407fc000,20480},{0x40804000,8192},{0x8065000,51072}};
 char folder[4096];snprintf(folder,sizeof(folder),"%s/%s",dir,at_checkpoint?"checkpoint":"final");
 if(g_mkdir_with_parents(folder,0700))die("snapshot output directory");
 for(unsigned r=0;r<(at_checkpoint?7U:5U);++r){
  char path[8192];snprintf(path,sizeof(path),"%s/ram-%08x.bin",folder,ranges[r][0]);FILE *f=fopen(path,"wb");if(!f)die("RAM output");
  snprintf(path,sizeof(path),"%s/known-%08x.bin",folder,ranges[r][0]);FILE *k=fopen(path,"wb");if(!k)die("known output");
  for(unsigned i=0;i<ranges[r][1];++i){Page *p=page(ranges[r][0]+i,1);unsigned offset=(ranges[r][0]+i)&4095;fputc(p->v[offset],f);fputc(p->k[offset],k);}if(fclose(f)||fclose(k))die("RAM output write");
 }
}
#endif
static void scalar_json(Value *values,unsigned count) {
 fputc('[',stdout);for(unsigned i=0;i<count;++i)printf("%s{\"value\":%" PRIu64 ",\"known\":%" PRIu64 "}",i?",":"",(uint64_t)values[i].v,(uint64_t)values[i].k);fputc(']',stdout);
}
/* This is a receipt of the computed machine, not an observation of Linux VMAs.
 * Fetch/lift the boundary instruction without executing it or including it in
 * the executed catalogue, path digest, LOAD counts or instruction count. */
static void boundary_receipt(const char *directory) {
 uint8_t bytes[15];size_t count=0;
 for(unsigned i=0;i<sizeof bytes&&(uint64_t)pc+i<UINT64_C(0x100000000);++i){
  Page *p=pages[(pc+i)>>12];if(!p||!(p->prot&4))break;
  unsigned offset=(pc+i)&4095;if(p->k[offset]!=255)die("unknown boundary instruction byte");
  bytes[count++]=p->v[offset];
 }
 if(!last_node||last_target!=pc||!count)die("missing final transition or executable fetch");
 Node fetched={0};
 if(!lift_node(decoder,bytes,count,pc,-1,&fetched))die("boundary frontend lift failed");
 generic_check_fetch_lifetime(pc,fetched.size);
 producer_fetch_size=fetched.size;
 char path[4096];
 int length=snprintf(path,sizeof path,"%s/boundary.json",directory);
 if(length<0||(size_t)length>=sizeof path)die("boundary receipt path");
 FILE *output=fopen(path,"wb");if(!output)die("boundary receipt open");
 FILE *saved=stdout;stdout=output;
 printf("{\"schema_version\":1,\"source_kind\":\"computed_IR_model\",\"pc\":%u,\"instructions\":%" PRIu64 ",\"path_sha256\":\"%s\",\"memory_version\":%" PRIu64,pc,steps,g_checksum_get_string(path_hash),version);
#ifdef TF_GENERIC_REPLAY
 if(generic_boundary_selector_version==1)
  printf(",\"macro_instructions\":%" PRIu64 ",\"instruction_count_semantics\":\"%s\",\"rep_callback_mode\":\"%s\",\"rep_callback_profile_explicit\":%s,\"rep_macros\":%" PRIu64 ",\"rep_extra_callbacks\":%" PRIu64,
   generic_macro_steps,generic_rep_count_semantics(),generic_rep_callback_mode(),
   generic_rep_profile_explicit?"true":"false",generic_rep_macros,generic_rep_extra_callbacks);
 if(generic_boundary_selector_version>=2)
  printf(",\"boundary_selector_version\":%u,\"stop_instruction_ordinal\":%" PRIu64 ",\"stop_page_generation\":%" PRIu64,
   generic_boundary_selector_version,steps+1,pages[pc>>12]->generic_guest_store_generation);
 if(generic_boundary_selector_version>=3)printf(",\"stop_mapping_epoch\":%u",pages[pc>>12]->generic_mapping_epoch);
#endif
 fputs(",\"vmas\":[",stdout);
 bool first=true;
 for(unsigned lo=0;lo<1048576;){
  Page *p=pages[lo];if(!p){++lo;continue;}
  unsigned hi=lo+1;
  while(hi<1048576&&pages[hi]&&model_same_mapping_epoch(p,pages[hi],(uint64_t)(hi-lo)*4096)&&pages[hi]->prot==p->prot&&pages[hi]->file==p->file&&
        (p->file<0||(uint64_t)pages[hi]->offset==(uint64_t)p->offset+(uint64_t)(hi-lo)*4096))++hi;
  printf("%s{\"start\":%" PRIu64 ",\"end\":%" PRIu64 ",\"permissions\":%u,\"file_id\":%d,\"offset\":%u",first?"":",",(uint64_t)lo*4096,(uint64_t)hi*4096,p->prot,p->file,model_file_offset(p));
  model_mapping_epoch_json(p);fputc('}',stdout);
  first=false;lo=hi;
 }
 printf("],\"transition\":{\"pc\":%u,\"size\":%u,\"bytes_hex\":\"",last_node->pc,last_node->size);
 for(unsigned i=0;i<last_node->size;++i)printf("%02x",last_node->bytes[i]);
 printf("\",\"control\":%u,\"computed_target\":%u,\"computed_target_known\":true,\"instruction_ordinal\":%" PRIu64 ",\"eax\":{\"value\":%" PRIu64 ",\"known\":%" PRIu64 "},\"original_ir_sha256\":\"%s\",\"target_value_id\":%u},\"fetch\":{\"pc\":%u,\"size\":%u,\"bytes_hex\":\"",last_node->lift.control,last_target,steps,(uint64_t)last_eax.v,(uint64_t)last_eax.k,last_node->sha,last_node->lift.target,pc,fetched.size);
 for(unsigned i=0;i<fetched.size;++i)printf("%02x",fetched.bytes[i]);
 fputs("\",\"known_hex\":\"",stdout);
 for(unsigned i=0;i<fetched.size;++i)fputs("ff",stdout);
 printf("\",\"ir_validator_passed\":true,\"lift_status\":%u,\"original_ir_sha256\":\"%s\",\"original_ir_dump\":",fetched.lift.status,fetched.sha);
 string_json(fetched.dump,fetched.dump_size);
 printf(",\"ir_semantics_modeled\":%s,\"target_instruction_executed\":false},\"guest_permissions_independently_observed\":false,\"kernel_implementation_verified\":false,\"independent_entry_origins_proven\":false,\"target_instruction_executed\":false,\"oep_proof\":\"NOT_ESTABLISHED\"}\n",fetched.opaque?"false":"true");
 bool failed=ferror(output);stdout=saved;
 if(fclose(output))failed=true;
 ir_module_destroy(fetched.module);free(fetched.dump);
 if(failed)die("boundary receipt write");
}
#ifndef TF_GENERIC_REPLAY
int main(int argc,char **argv) {
 if(argc!=7){fputs("usage: m366-execute ELF STACK STACK_MASK SCALARS CONTRACTS OUTPUT_DIR\n",stderr);return 2;}
 for(unsigned i=0;i<64;++i)descriptors[i]=-1;
 FILE *f=fopen(argv[1],"rb");if(!f)die("ELF input");uint8_t elf[56256];if(fread(elf,1,sizeof(elf),f)!=sizeof(elf)||fgetc(f)!=EOF||fclose(f))die("ELF size");
 char *sha=g_compute_checksum_for_data(G_CHECKSUM_SHA256,elf,sizeof(elf));if(strcmp(sha,"7daac7415a92362184996750d19e878c49b9d5e866690e62851f4589a115bf2e"))die("ELF identity");g_free(sha);
 producer_begin();
 resize_file(0,57344);files[0].logical_size=sizeof(elf);memcpy(files[0].v,elf,sizeof(elf));
 mapping(0x8048000,118436,3,-1,0);for(unsigned i=0;i<4096;++i)pages[0x8048]->v[i]=elf[i];
 mapping(0x8065000,51072,5,-1,0);for(unsigned i=0;i<51072;++i)pages[(0x8065000+i)>>12]->v[(0x8065000+i)&4095]=elf[i];
 producer_packed_bytes(elf,sizeof elf);
 for(unsigned i=0x8048;i<0x8065;++i)if(pages[i])memset(pages[i]->origin,2,4096);
 for(unsigned i=0x8065;i<0x8072;++i)if(pages[i])memset(pages[i]->origin,2,4096);
 mapping(0x40700000,0x100000,3,-1,0);mapping(0x40800000,4096,3,-1,0);for(unsigned i=0x40700;i<0x40801;++i)memset(pages[i]->k,0,4096);bytes_file(argv[2],0x407fc000,20480);
 f=fopen(argv[3],"rb");if(!f)die("stack mask missing");
 for(unsigned i=0;i<20480;++i){int k=fgetc(f);if(k!=0&&k!=255)die("stack mask must contain exactly00/ff bytes");Page *p=page(0x407fc000+i,0);unsigned offset=(0x407fc000+i)&4095;p->k[offset]=(uint8_t)k;p->v[offset]&=(uint8_t)k;p->origin[offset]=1;if(k)++initial_stack_known_bytes;}
 if(fgetc(f)!=EOF||fclose(f))die("stack mask extent");
 f=fopen(argv[4],"r");if(!f)die("entry scalar input");uint32_t esp,df;if(fscanf(f,"%x %x",&esp,&df)!=2||df>1||fclose(f))die("entry ESP/DF");
 for(unsigned i=0;i<8;++i)states[256+i]=val(32,0,0);states[260]=known(32,esp);
 for(unsigned i=0;i<7;++i)states[512+i]=val(1,0,0);states[518]=known(1,df);states[768]=token();
 producer_entry(esp,df);
 contracts=fopen(argv[5],"r");if(!contracts)die("contracts file");char path[4096];snprintf(path,sizeof(path),"%s/original-ir.jsonl",argv[6]);catalogue=fopen(path,"w");if(!catalogue)die("catalogue output");
 if(cs_open(CS_ARCH_X86,CS_MODE_32,&decoder)!=CS_ERR_OK||cs_option(decoder,CS_OPT_DETAIL,CS_OPT_ON)!=CS_ERR_OK)die("Capstone initialization");
 nodes=g_hash_table_new(g_str_hash,g_str_equal);path_hash=g_checksum_new(G_CHECKSUM_SHA256);pc=0x8070300;kernel_receipt_start(argv[6]);
 while(pc!=0x8049096){
  if(pc==0x40804915){if(checkpoint_instructions||ordinal!=21)die("checkpoint order");checkpoint_instructions=steps;memcpy(checkpoint_registers,states+256,sizeof(checkpoint_registers));memcpy(checkpoint_flags,states+512,sizeof(checkpoint_flags));dump_ram(argv[6],true);}
  if(++steps>20000000)die("instruction budget");Node *n=get_node();uint32_t address=GUINT32_TO_LE(pc);g_checksum_update(path_hash,(guchar *)&address,4);
  producer_fetch(n);
  last_node=n;last_eax=states[256];
  if(n->opaque)kernel(n);else pc=execute(n);
  last_target=pc;
  if(steps%1000000==0)fprintf(stderr,"progress instructions=%" PRIu64 " pc=0x%08x\n",steps,pc);
 }
 if(!checkpoint_instructions||ordinal!=26)die("unexpected payload boundary");
 int extra;do{extra=fgetc(contracts);}while(extra==' '||extra=='\n'||extra=='\t'||extra=='\r');if(extra!=EOF)die("unused kernel contract");
 if(pages[0x40804]||pages[0x40805]||pages[0x8065])die("source/private unmap effects missing");
 dump_ram(argv[6],false);
 boundary_receipt(argv[6]);
 producer_finish((const char *const *)(argv+1));
 snprintf(path,sizeof(path),"%s/projection.bin",argv[6]);f=fopen(path,"wb");if(!f||fwrite(projection,1,sizeof(projection),f)!=sizeof(projection)||fclose(f))die("projection output");
 unsigned projected=0;for(unsigned i=0;i<sizeof(projection);++i)projected+=projection[i]!=0;
 printf("{\"schema_version\":1,\"status\":\"COMPUTED_REDUCED_PREMISE_ORIGINAL_ENTRY_TO_PAYLOAD_TRANSFER\",\"pc\":%u,\"instructions\":%" PRIu64 ",\"checkpoint_instructions\":%" PRIu64 ",\"ir_rows\":%" PRIu64 ",\"loads\":%" PRIu64 ",\"stores\":%" PRIu64 ",\"unknown_loads\":%" PRIu64 ",\"syscalls\":%u,\"fresh_ir_nodes\":%u,\"initial_known_GPRs\":1,\"initial_known_flags\":1,\"initial_stack_known_bytes\":%u,\"projection_bytes\":%u,\"path_sha256\":\"%s\",\"registers\":",pc,steps,checkpoint_instructions,ir_rows,loads,stores,unknown_loads,ordinal,g_hash_table_size(nodes),initial_stack_known_bytes,projected,g_checksum_get_string(path_hash));
 scalar_json(states+256,8);fputs(",\"flags\":",stdout);scalar_json(states+512,7);fputs(",\"checkpoint_registers\":",stdout);scalar_json(checkpoint_registers,8);fputs(",\"checkpoint_flags\":",stdout);scalar_json(checkpoint_flags,7);
 fputs(",\"checkpoint_used_as_seed\":false,\"kernel_implementation_verified\":false,\"independent_entry_origins_proven\":false,\"source_private_unmapped\":true,\"target_instruction_executed\":false,\"oep_proof\":\"NOT_ESTABLISHED\"}\n",stdout);
 return fclose(catalogue)||fclose(contracts)||fclose(kernel_receipts)||fclose(initial_reads)||ferror(stdout)?1:0;
}

#else
#include "oep_generic_execute.h"
#endif
