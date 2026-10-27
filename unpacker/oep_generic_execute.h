/* Generic, bounded static i386 replay entry point.  Initial mappings are
 * constructed from ELF file bytes; candidate bytes are conclusions only.
 * CLI: ELF STACK MASK SCALARS CONTRACTS CONFIG OUTPUT
 * SCALARS: hexadecimal ESP and DF (all other incoming scalars UNKNOWN).
 * CONFIG: TFOEPGEN1\nSTOP_HEX STACK_BASE_HEX MAX_INSTRUCTIONS_DEC\n
 *         RANGE_COUNT_DEC\nSTART_HEX SIZE_DEC\n... .
 * TFOEPGEN2 inserts ENTRY_SEQ_DEC PAGE_GUEST_STORE_GENERATION_DEC after the
 * STOP/STACK/LIMIT line.  This selector guides stopping, never initial state.
 * V2 supports only observed successful mprotect contracts (no remappings).
 * TFOEPGEN3 appends MAPPING_EPOCH_DEC to that selector line and admits the
 * bounded anonymous mapping-lifetime profile implemented by the kernel model.
 * TFOEPGEN4 uses the same selector and additionally permits read-only opens of
 * the immutable packed source and private file mappings of its bounded pages.
 * TFOEPGEN5 adds bounded mutable memfd constructors before PRIVATE mapping.
 * TFOEPGEN6 adds local memfd SHARED aliases and source-derived writeback.
 * TFOEPGEN7 preserves the final partial memfd cache page separately from the
 * logical file size; bounded MS_SYNC retains those bytes and their producers.
 * TFOEPGEN1C is GEN1 with one explicit calibrated callback token after the
 * STOP/STACK/LIMIT line: terminal_zero (N+1), body_only (max(1,N)), or
 * macro_once (one callback for the whole instruction).  The
 * token is a route-model choice, never an observed ECX assignment. */
#ifndef TAINTFORGE_OEP_GENERIC_EXECUTE_H
#define TAINTFORGE_OEP_GENERIC_EXECUTE_H
#include <elf.h>
#include <errno.h>

static uint64_t generic_selector_number(const char *text,uint64_t maximum) {
 char *end=NULL;errno=0;uint64_t value=strtoull(text,&end,10);
 if(!*text||strspn(text,"0123456789")!=strlen(text)||errno||!end||*end||value>maximum)
  die("generic exact boundary selector number");
 return value;
}

/* Optional bounded diagnostic route.  This observes the computed IR machine;
 * it never initializes state, changes the proof schedule, or normalizes the
 * existing proof relation.  GEN1 records each normal-mode callback using
 * computed IR states; legacy profiles retain their existing macro rows. */
static FILE *generic_trace;
static uint64_t generic_trace_start=1,generic_trace_limit=8192,generic_trace_rows;
static void generic_trace_open(void) {
 const char *path=getenv("TF_OEP_TRACE_PATH"),*start=getenv("TF_OEP_TRACE_START"),*limit=getenv("TF_OEP_TRACE_LIMIT");
 if(!path){if(start||limit)die("diagnostic trace controls require a path");return;}
 if(!*path)die("diagnostic trace path is empty");
 if(start){generic_trace_start=generic_selector_number(start,UINT64_C(30000001));if(!generic_trace_start)die("diagnostic trace start");}
 if(limit){generic_trace_limit=generic_selector_number(limit,UINT64_C(262144));if(!generic_trace_limit)die("diagnostic trace limit");}
 generic_trace=fopen(path,"wx");if(!generic_trace)die("diagnostic trace output must be new");
}
static void generic_trace_instruction(const Node *n,uint64_t trace_ordinal,const char *event_kind) {
 if(!generic_trace||trace_ordinal<generic_trace_start||generic_trace_rows>=generic_trace_limit)return;
 if(fprintf(generic_trace,"{\"ordinal\":%" PRIu64 ",\"pc\":%u,\"size\":%u,\"bytes_hex\":\"",trace_ordinal,n->pc,n->size)<0)die("diagnostic trace write");
 for(unsigned i=0;i<n->size;++i)if(fprintf(generic_trace,"%02x",n->bytes[i])<0)die("diagnostic trace write");
 static const unsigned keys[]={257,262,263};
 static const char *const names[]={"ecx","esi","edi"};
 if(fputc('"',generic_trace)==EOF)die("diagnostic trace write");
 for(unsigned i=0;i<3;++i){Value value=states[keys[i]];
  if(fprintf(generic_trace,",\"%s\":",names[i])<0)die("diagnostic trace write");
  if(value.bits==32&&!value.mem&&value.k==UINT32_MAX){if(fprintf(generic_trace,"%u",(uint32_t)value.v)<0)die("diagnostic trace write");}
  else if(fputs("null",generic_trace)==EOF)die("diagnostic trace write");
  if(fprintf(generic_trace,",\"%s_known\":%u",names[i],(uint32_t)value.k)<0)die("diagnostic trace write");
 }
 static const unsigned flag_bits[]={0,2,4,6,7,11,10};uint32_t flags=0,known_flags=0;
 for(unsigned i=0;i<7;++i)if(states[512+i].k&1){known_flags|=UINT32_C(1)<<flag_bits[i];if(states[512+i].v&1)flags|=UINT32_C(1)<<flag_bits[i];}
 if(fprintf(generic_trace,",\"eflags\":%u,\"eflags_known\":%u,\"repeat_iterations\":%d,\"event_kind\":\"%s\"}\n",flags,known_flags,n->repeat_iterations,event_kind)<0)die("diagnostic trace write");
 ++generic_trace_rows;
}
static void generic_trace_close(void) {
 if(generic_trace&&(ferror(generic_trace)||fclose(generic_trace)))die("diagnostic trace close");
 generic_trace=NULL;
}

static uint16_t generic_u16(const uint8_t *p) {
 return (uint16_t)p[0]|(uint16_t)p[1]<<8;
}
static uint32_t generic_u32(const uint8_t *p) {
 return (uint32_t)p[0]|(uint32_t)p[1]<<8|(uint32_t)p[2]<<16|(uint32_t)p[3]<<24;
}
static uint64_t generic_round(uint64_t value) {
 return (value+4095)&~UINT64_C(4095);
}
static void generic_eof(FILE *input,const char *message) {
 int c;do{c=fgetc(input);}while(c==' '||c=='\n'||c=='\t'||c=='\r');
 if(c!=EOF||ferror(input)||fclose(input))die(message);
}
static gchar *generic_blob(const char *path,gsize *size) {
 gchar *data=NULL;
 if(!g_file_get_contents(path,&data,size,NULL)||!*size||*size>1048576)die("generic input file bound");
 return data;
}
static uint32_t generic_loader(const uint8_t *elf,size_t size) {
 if(size<52||memcmp(elf,"\177ELF\1\1\1",7)||
    (elf[7]!=0&&elf[7]!=3)||elf[8]||generic_u16(elf+16)!=ET_EXEC||
    generic_u16(elf+18)!=EM_386||generic_u32(elf+20)!=1||generic_u32(elf+36)||
    generic_u16(elf+40)!=52||generic_u16(elf+42)!=32)die("generic static i386 ELF header");
 uint32_t entry=generic_u32(elf+24),phoff=generic_u32(elf+28);
 unsigned count=generic_u16(elf+44),loads_count=0;uint64_t total=0,highest_end=0;bool stack_header_seen=false;
 if(!count||count>256||phoff<52||(uint64_t)phoff+(uint64_t)count*32>size)die("generic ELF program headers");
 /* File producers are independent authenticated source leaves. */
 resize_file(0,(size_t)generic_round(size));files[0].logical_size=size;memcpy(files[0].v,elf,size);
 producer_packed_bytes(elf,size);
 for(unsigned index=0;index<count;++index){
  const uint8_t *h=elf+phoff+(size_t)index*32;
  uint32_t type=generic_u32(h),off=generic_u32(h+4),address=generic_u32(h+8);
  uint32_t file_size=generic_u32(h+16),memory_size=generic_u32(h+20),flags=generic_u32(h+24),align=generic_u32(h+28);
  if(type==PT_INTERP||type==PT_DYNAMIC||type==PT_TLS)die("generic dynamic/interpreter/TLS ELF unsupported");
  if(type==PT_GNU_STACK){
   if(stack_header_seen||flags>7)die("generic ambiguous/unsupported GNU_STACK");
   stack_header_seen=true;
   /* QEMU i386 defaults executable; setup_arg_pages always supplies RW,
    * and an explicit GNU_STACK controls only whether X is also present. */
   generic_stack_prot=3|((flags&PF_X)?4:0);
  }
  if(type!=PT_LOAD)continue;
  if(!address||!memory_size||file_size>memory_size||(uint64_t)off+file_size>size||
     (uint64_t)address+memory_size>UINT64_C(0x100000000)||flags>7||
     (address&4095)!=(off&4095)||(align>1&&((align&(align-1))||address%align!=off%align)))die("generic ELF LOAD geometry");
  uint32_t low=address&~UINT32_C(4095),file_low=off&~UINT32_C(4095);
  uint64_t end=generic_round((uint64_t)address+memory_size),file_end=generic_round((uint64_t)address+file_size);
  uint64_t length=end-low;if(end>highest_end)highest_end=end;
  if(!length||length>1048576||(total+=length)>16*UINT64_C(1048576))die("generic initial ELF map bound");
  for(uint64_t a=low;a<end;a+=4096)if(pages[a>>12])die("generic overlapping rounded ELF LOADs unsupported");
  unsigned prot=((flags&PF_R)?1:0)|((flags&PF_W)?2:0)|((flags&PF_X)?4:0);
  mapping(low,(uint32_t)length,prot,-1,0);
  if(file_size){
   uint64_t available=size-file_low,copy=file_end-low;if(copy>available)copy=available;
   for(uint64_t i=0;i<copy;++i){Page *p=pages[(low+i)>>12];unsigned o=(low+i)&4095;
    p->v[o]=elf[file_low+i];if(producers_enabled)p->producer[o]=producer_cell(producer_packed[file_low+i],0,8);
   }
  }
  /* padzero applies only when the segment has a BSS tail.  A segment whose
   * filesz == memsz retains the file-backed last page through real EOF. */
  if(memory_size>file_size)for(uint64_t a=(uint64_t)address+file_size;a<end;++a){
   Page *p=pages[a>>12];unsigned o=a&4095;p->v[o]=0;if(producers_enabled)p->producer[o]=0;
  }
  for(uint64_t a=low;a<end;a+=4096)memset(pages[a>>12]->origin,2,4096);
  ++loads_count;
 }
 if(!loads_count||!pages[entry>>12]||(pages[entry>>12]->prot&5)!=5)die("generic ELF entry is not executable");
 if(highest_end>UINT32_MAX)die("generic initial brk exceeds supported uint32 range");
 /* The selected static-loader model starts without a mapped heap.  Failed
  * or no-op brk requests may return this source-derived unchanged break. */
 generic_brk=(uint32_t)highest_end;generic_brk_known=true;
 return entry;
}
static void generic_dump(const char *directory) {
 char folder[4096];if(snprintf(folder,sizeof folder,"%s/final",directory)<0||g_mkdir_with_parents(folder,0700))die("generic dump directory");
 char path[8192];snprintf(path,sizeof path,"%s/regions.jsonl",directory);FILE *regions=fopen(path,"wb");if(!regions)die("generic region ledger");
 for(unsigned r=0;r<=generic_range_count;++r){
  uint32_t start=r==generic_range_count?initial_stack_base:generic_ranges[r].start;
  uint32_t size=r==generic_range_count?(uint32_t)projection_size:generic_ranges[r].size;
  snprintf(path,sizeof path,"%s/ram-%08x.bin",folder,start);FILE *value=fopen(path,"wb");
  snprintf(path,sizeof path,"%s/known-%08x.bin",folder,start);FILE *known_mask=fopen(path,"wb");
  if(!value||!known_mask)die("generic RAM output");
  for(uint32_t i=0;i<size;++i){Page *p=page(start+i,1);unsigned o=(start+i)&4095;
   if(fputc(p->v[o]&p->k[o],value)==EOF||fputc(p->k[o],known_mask)==EOF)die("generic RAM output write");
  }
  if(fclose(value)||fclose(known_mask)||fprintf(regions,"{\"address\":%u,\"size\":%u}\n",start,size)<0)die("generic RAM output close");
 }
 if(fclose(regions))die("generic region ledger close");
}
int main(int argc,char **argv) {
 if(argc!=8){fputs("usage: generic-execute ELF STACK MASK SCALARS CONTRACTS CONFIG OUTPUT\n",stderr);return 2;}
 for(unsigned i=0;i<64;++i)descriptors[i]=-1;
 gsize elf_size=0,stack_size=0,mask_size=0;
 gchar *elf=generic_blob(argv[1],&elf_size),*stack=generic_blob(argv[2],&stack_size),*stack_mask=generic_blob(argv[3],&mask_size);
 FILE *input=fopen(argv[6],"r");char magic[32];uint32_t stop;uint64_t instruction_limit;
 if(!input||fscanf(input,"%31s %x %x %" SCNu64,magic,&stop,&initial_stack_base,&instruction_limit)!=4||
    !instruction_limit||instruction_limit>30000000)die("generic configuration");
 if(!strcmp(magic,"TFOEPGEN1C")){
  char mode[32];
  if(fscanf(input,"%31s",mode)!=1||
     (strcmp(mode,"terminal_zero")&&strcmp(mode,"body_only")&&strcmp(mode,"macro_once")))
   die("generic calibrated REP callback profile");
  generic_rep_terminal_zero=!strcmp(mode,"terminal_zero");
  generic_rep_macro_once=!strcmp(mode,"macro_once");generic_rep_profile_explicit=true;
 }else if(!strcmp(magic,"TFOEPGEN2")||!strcmp(magic,"TFOEPGEN3")||!strcmp(magic,"TFOEPGEN4")||!strcmp(magic,"TFOEPGEN5")||!strcmp(magic,"TFOEPGEN6")||!strcmp(magic,"TFOEPGEN7")){
  generic_boundary_selector_version=(unsigned)(magic[8]-'0');
  char ordinal_text[32],generation_text[32];
  if(fscanf(input,"%31s %31s",ordinal_text,generation_text)!=2)die("generic exact boundary selector");
  generic_stop_instruction_ordinal=generic_selector_number(ordinal_text,instruction_limit+1);
  generic_stop_page_generation=generic_selector_number(generation_text,UINT32_MAX);
  if(generic_boundary_selector_version>=3){char epoch_text[32];
   if(fscanf(input,"%31s",epoch_text)!=1)die("generic mapping selector");
   generic_stop_mapping_epoch=(uint32_t)generic_selector_number(epoch_text,UINT32_MAX);
  }
  if(
     generic_stop_instruction_ordinal<=1||generic_stop_instruction_ordinal>instruction_limit+1||
     !generic_stop_page_generation||generic_stop_page_generation>UINT32_MAX)die("generic exact boundary selector");
 }else if(strcmp(magic,"TFOEPGEN1"))die("generic configuration version");
 if(fscanf(input,"%u",&generic_range_count)!=1||!generic_range_count||generic_range_count>256)die("generic configuration range count");
 uint64_t previous_end=0,total=0;
 for(unsigned i=0;i<generic_range_count;++i){uint32_t start,size;
  if(fscanf(input,"%x %u",&start,&size)!=2||!size||start%4096||size%4096||
     (uint64_t)start+size>UINT64_C(0x100000000)||start<previous_end||(total+=size)>16*UINT64_C(1048576))die("generic output range geometry");
  generic_ranges[i]=(GenericRange){start,size};previous_end=(uint64_t)start+size;
 }
 generic_eof(input,"generic configuration trailing data");
 if(stack_size!=mask_size||initial_stack_base%4096||stack_size%4096||
    (uint64_t)initial_stack_base+stack_size>UINT64_C(0x100000000))die("generic initial stack geometry");
 for(unsigned i=0;i<generic_range_count;++i)if((uint64_t)generic_ranges[i].start<initial_stack_base+stack_size&&
    (uint64_t)generic_ranges[i].start+generic_ranges[i].size>initial_stack_base)die("generic image goal overlaps initial stack");
 projection_size=stack_size;projection=g_malloc0(projection_size);producer_begin();
 uint32_t entry=generic_loader((const uint8_t *)elf,elf_size);
 for(uint64_t a=initial_stack_base;a<(uint64_t)initial_stack_base+stack_size;a+=4096)if(pages[a>>12])die("generic stack overlaps ELF");
 mapping(initial_stack_base,(uint32_t)stack_size,generic_stack_prot,-1,0);
 for(size_t i=0;i<stack_size;++i){unsigned k=(unsigned char)stack_mask[i];if(k!=0&&k!=255)die("generic stack mask byte");
  Page *p=pages[(initial_stack_base+i)>>12];unsigned o=(initial_stack_base+i)&4095;
  p->v[o]=(uint8_t)stack[i]&(uint8_t)k;p->k[o]=(uint8_t)k;p->origin[o]=1;if(k)++initial_stack_known_bytes;
 }
 input=fopen(argv[4],"r");uint32_t esp,df;
 if(!input||fscanf(input,"%x %x",&esp,&df)!=2||df>1||esp<initial_stack_base||(uint64_t)esp>=(uint64_t)initial_stack_base+stack_size)die("generic entry ESP/DF");
 generic_eof(input,"generic entry scalar trailing data");
 for(unsigned i=0;i<8;++i)states[256+i]=val(32,0,0);states[260]=known(32,esp);
 for(unsigned i=0;i<7;++i)states[512+i]=val(1,0,0);states[518]=known(1,df);states[768]=token();producer_entry(esp,df);
 contracts=fopen(argv[5],"r");if(!contracts)die("generic contracts input");
 if(g_mkdir_with_parents(argv[7],0700))die("generic output directory");
 char path[8192];snprintf(path,sizeof path,"%s/original-ir.jsonl",argv[7]);catalogue=fopen(path,"wb");if(!catalogue)die("generic catalogue output");
 snprintf(path,sizeof path,"%s/write-origins.jsonl",argv[7]);generic_write_origins=fopen(path,"wb");if(!generic_write_origins)die("generic write chronology open");
 if(cs_open(CS_ARCH_X86,CS_MODE_32,&decoder)!=CS_ERR_OK||cs_option(decoder,CS_OPT_DETAIL,CS_OPT_ON)!=CS_ERR_OK)die("generic Capstone initialization");
 nodes=g_hash_table_new(g_str_hash,g_str_equal);path_hash=g_checksum_new(G_CHECKSUM_SHA256);fetch_hash=g_checksum_new(G_CHECKSUM_SHA256);
 pc=entry;kernel_receipt_start(argv[7]);generic_trace_open();
 for(;;){
  if(generic_boundary_selector_version==1){if(pc==stop)break;}
  else if(steps+1==generic_stop_instruction_ordinal){
   Page *target=pages[pc>>12];
   if(pc!=stop||!target||target->generic_guest_store_generation!=generic_stop_page_generation||
      (generic_boundary_selector_version>=3&&target->generic_mapping_epoch!=generic_stop_mapping_epoch))
    die("generic exact boundary PC/occurrence/generation mismatch");
   break;
  }else if(steps+1>generic_stop_instruction_ordinal)die("generic exact boundary occurrence exceeded");
  if(++steps>instruction_limit)die("generic instruction budget");Node *n=get_node();++generic_macro_steps;
  bool normal_repeat=generic_boundary_selector_version==1&&n->repeat_iterations>=0;
  unsigned iterations=normal_repeat?(unsigned)n->repeat_iterations:0;
  unsigned callbacks=normal_repeat?(generic_rep_macro_once?1:
   generic_rep_terminal_zero?iterations+1:(iterations?iterations:1)):1;
  if(callbacks>instruction_limit-steps+1)die("generic callback instruction budget");
  if(normal_repeat){
   if(n->stores!=(unsigned)n->repeat_iterations)die("generic REP expansion STORE count");
   ++generic_rep_macros;generic_rep_extra_callbacks+=callbacks-1;generic_rep_trace_iteration=0;
   if(generic_rep_macro_once)generic_trace_instruction(n,steps,"rep_macro_once");
  }else generic_trace_instruction(n,steps,"instruction");
  /* terminal_zero/body_only include each body callback; terminal_zero also
   * includes ECX==0, while body_only includes it only with no body.  An
   * inline-TCG macro_once contract has one pre-expansion callback.  In every
   * case, the original ECX producer is constrained by
   * producer_fetch(kind7) and the lifted IR guard.  No observed ECX is used.
   * Opcode STORE guards below prevent changes between these fetches. */
  uint32_t encoded=GUINT32_TO_LE(pc);uint8_t encoded_size=(uint8_t)n->size;
  for(unsigned i=0;i<callbacks;++i){
   g_checksum_update(path_hash,(const guchar *)&encoded,4);g_checksum_update(fetch_hash,(const guchar *)&encoded,4);
   g_checksum_update(fetch_hash,&encoded_size,1);g_checksum_update(fetch_hash,n->bytes,n->size);
  }
  producer_fetch(n);last_node=n;last_eax=states[256];
  if(n->opaque){
   if(generic_boundary_selector_version==2&&(states[256].k!=mask(32)||states[256].v!=125))
    die("generic exact boundary supports only mprotect contracts");
   kernel(n);
   if(generic_boundary_selector_version==2&&(states[256].k!=mask(32)||states[256].v))
    die("generic exact boundary requires successful mprotect");
  }else pc=execute(n);last_target=pc;
  if(normal_repeat){
   if(generic_rep_trace_iteration!=(unsigned)n->repeat_iterations||integer(states[257])!=0)
    die("generic REP expansion poststate");
   if(!generic_rep_macro_once&&(generic_rep_terminal_zero||!iterations))
    generic_trace_instruction(n,steps+iterations,
     generic_rep_terminal_zero?"rep_terminal_zero":"rep_zero_count");
   steps+=callbacks-1;
  }
  if(steps%1000000==0)fprintf(stderr,"progress instructions=%" PRIu64 " pc=0x%08x\n",steps,pc);
 }
 if(!steps||!last_node||last_node->opaque||(last_node->lift.control!=IR_X86_DIRECT_JUMP&&last_node->lift.control!=IR_X86_INDIRECT))die("generic candidate is not a computed transfer boundary");
 generic_eof(contracts,"generic unused kernel contracts");contracts=NULL;
 generic_trace_close();generic_dump(argv[7]);boundary_receipt(argv[7]);producer_finish((const char *const *)(argv+1));
 snprintf(path,sizeof path,"%s/projection.bin",argv[7]);FILE *f=fopen(path,"wb");
 if(!f||fwrite(projection,1,projection_size,f)!=projection_size||fclose(f))die("generic projection output");
 unsigned projected=0;for(size_t i=0;i<projection_size;++i)projected+=projection[i]!=0;
 printf("{\"schema_version\":1,\"status\":\"COMPUTED_GENERIC_ENTRY_TO_SELECTED_TRANSFER\",\"entry\":%u,\"pc\":%u,\"instructions\":%" PRIu64 ",\"ir_rows\":%" PRIu64 ",\"loads\":%" PRIu64 ",\"stores\":%" PRIu64 ",\"unknown_loads\":%" PRIu64 ",\"syscalls\":%u,\"fresh_ir_nodes\":%u,\"initial_known_GPRs\":1,\"initial_known_flags\":1,\"initial_stack_base\":%u,\"initial_stack_size\":%zu,\"initial_stack_known_bytes\":%u,\"projection_bytes\":%u,\"path_sha256\":\"%s\",\"fetch_sha256\":\"%s\",\"fetch_hash_encoding\":\"LE32_PC_U8_SIZE_BYTES\",\"registers\":",entry,pc,steps,ir_rows,loads,stores,unknown_loads,ordinal,g_hash_table_size(nodes),initial_stack_base,projection_size,initial_stack_known_bytes,projected,g_checksum_get_string(path_hash),g_checksum_get_string(fetch_hash));
 scalar_json(states+256,8);fputs(",\"flags\":",stdout);scalar_json(states+512,7);
 if(generic_boundary_selector_version==1)
  printf(",\"macro_instructions\":%" PRIu64 ",\"instruction_count_semantics\":\"%s\",\"rep_callback_mode\":\"%s\",\"rep_callback_profile_explicit\":%s,\"rep_macros\":%" PRIu64 ",\"rep_extra_callbacks\":%" PRIu64,
   generic_macro_steps,generic_rep_count_semantics(),generic_rep_callback_mode(),
   generic_rep_profile_explicit?"true":"false",generic_rep_macros,generic_rep_extra_callbacks);
 if(generic_boundary_selector_version>=2)
  printf(",\"boundary_selector_version\":%u,\"stop_instruction_ordinal\":%" PRIu64 ",\"stop_page_generation\":%" PRIu64,
   generic_boundary_selector_version,steps+1,pages[pc>>12]->generic_guest_store_generation);
 if(generic_boundary_selector_version>=3)printf(",\"stop_mapping_epoch\":%u",pages[pc>>12]->generic_mapping_epoch);
 fputs(",\"checkpoint_used_as_seed\":false,\"observed_final_state_used_as_input\":false,\"kernel_implementation_verified\":false,\"independent_entry_origins_proven\":false,\"target_instruction_executed\":false,\"oep_proof\":\"NOT_ESTABLISHED\"}\n",stdout);
 g_free(elf);g_free(stack);g_free(stack_mask);
 return fclose(catalogue)||fclose(kernel_receipts)||fclose(initial_reads)||fclose(generic_write_origins)||ferror(stdout)?1:0;
}
#endif
