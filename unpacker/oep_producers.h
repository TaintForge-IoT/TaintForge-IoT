/* Optional, bounded producer ledger for the original-entry IR execution.
 * Nodes describe computations, not observed post-state assignments.  Resolving
 * RAM cells is conditional on the recorded execution/alias/fetch schedule.
 */
#ifndef TAINTFORGE_OEP_PRODUCERS_H
#define TAINTFORGE_OEP_PRODUCERS_H

enum {
 P_PACKED_BYTE=100, P_STACK_BYTE, P_INITIAL_RAM_ZERO, P_ENTRY_ESP,
 P_ENTRY_DF, P_KERNEL_RESULT, P_READLINK_BYTE, P_KERNEL_RAM_ZERO,
 P_INITIAL_FILE_PADDING_ZERO, P_KERNEL_FILE_ZERO
};
typedef struct {
 uint16_t opcode,bits;
 uint32_t a,b,c;
 uint64_t immediate,origin;
} ProducerRecord;
_Static_assert(sizeof(ProducerRecord)==32,"producer record layout");
static FILE *producer_nodes,*producer_inputs,*producer_conditions,*producer_origins;
static GChecksum *producer_node_hash,*producer_condition_hash;
static uint32_t producer_count,producer_input_count,producer_limit=UINT32_C(67108864),producer_state[1024],producer_target;
#ifdef TF_GENERIC_REPLAY
static uint32_t *producer_packed;
#else
static uint32_t producer_packed[56256];
#endif
static uint64_t producer_condition_count,producer_condition_kind_counts[10];
static unsigned producer_fetch_size;
static char producer_directory[4096];
static bool producers_enabled;
#ifdef TF_GENERIC_REPLAY
/* A cache miss preserves the original expression.  These entries only enable
 * exact bit-vector projection identities; no concrete execution values enter
 * the producer graph.  In particular, unknown discarded register bits remain
 * unknown and are removed only when the requested slice cannot depend on them. */
#define PRODUCER_SHAPE_CACHE_SIZE 16384U
typedef struct {
 uint32_t id,a,b;
 uint16_t opcode,bits,low_bits;
 uint64_t immediate;
} ProducerShape;
static ProducerShape producer_shapes[PRODUCER_SHAPE_CACHE_SIZE];
static ProducerShape *producer_shape(uint32_t id) {
 ProducerShape *shape=&producer_shapes[id%PRODUCER_SHAPE_CACHE_SIZE];
 return id&&shape->id==id?shape:NULL;
}
#endif

static uint32_t producer_node(unsigned opcode,unsigned bits,uint32_t a,uint32_t b,uint32_t c,uint64_t immediate) {
 if(!producers_enabled)return 0;
 if(!bits||bits>64||producer_count>=producer_limit||steps>UINT32_MAX)die("producer node budget or width");
 if(opcode<100&&(a>producer_count||b>producer_count||c>producer_count))die("producer dependency order");
 ProducerRecord record={GUINT16_TO_LE(opcode),GUINT16_TO_LE(bits),GUINT32_TO_LE(a),GUINT32_TO_LE(b),GUINT32_TO_LE(c),
  GUINT64_TO_LE(immediate),GUINT64_TO_LE((steps<<32)|pc)};
 if(fwrite(&record,sizeof record,1,producer_nodes)!=1)die("producer node write");
 g_checksum_update(producer_node_hash,(const guchar *)&record,sizeof record);
 ++producer_count;
#ifdef TF_GENERIC_REPLAY
 producer_shapes[producer_count%PRODUCER_SHAPE_CACHE_SIZE]=(ProducerShape){
  .id=producer_count,.a=a,.b=b,.opcode=opcode,.bits=bits,.immediate=immediate};
#endif
 return producer_count;
}
static uint32_t producer_concat(unsigned bits,uint32_t high,uint32_t low,unsigned low_bits) {
 if(!low_bits||low_bits>=bits)die("producer CONCAT widths");
 uint32_t id=producer_node(IR_OP_CONCAT,bits,high,low,0,0);
#ifdef TF_GENERIC_REPLAY
 if(producers_enabled)producer_shape(id)->low_bits=(uint16_t)low_bits;
#endif
 return id;
}
static uint32_t producer_extract_depth(unsigned bits,uint32_t source,unsigned offset,unsigned depth) {
#ifdef TF_GENERIC_REPLAY
 ProducerShape *found=producer_shape(source);
 if(found&&depth<64){
  ProducerShape shape=*found;
  if(offset<=shape.bits&&bits<=shape.bits-offset){
   if(!offset&&bits==shape.bits)return source;
   if(shape.opcode==IR_OP_EXTRACT&&shape.immediate<=64&&offset+shape.immediate<=64)
    return producer_extract_depth(bits,shape.a,offset+(unsigned)shape.immediate,depth+1);
   if(shape.opcode==IR_OP_CONCAT&&shape.low_bits&&shape.low_bits<shape.bits){
    unsigned low=shape.low_bits;
    if(offset>=low)return producer_extract_depth(bits,shape.a,offset-low,depth+1);
    if(bits<=low-offset)return producer_extract_depth(bits,shape.b,offset,depth+1);
    unsigned lower=low-offset,upper=bits-lower;
    uint32_t high=producer_extract_depth(upper,shape.a,0,depth+1);
    uint32_t tail=producer_extract_depth(lower,shape.b,offset,depth+1);
    return producer_concat(bits,high,tail,lower);
   }
  }
 }
#else
 (void)depth;
#endif
 return producer_node(IR_OP_EXTRACT,bits,source,0,0,offset);
}
static uint32_t producer_extract(unsigned bits,uint32_t source,unsigned offset) {
 return producer_extract_depth(bits,source,offset,0);
}
static uint32_t producer_leaf(unsigned kind,unsigned bits,uint64_t key,uint64_t value) {
 if(producers_enabled&&producer_input_count++>=UINT32_C(1048576))die("producer input budget");
 uint32_t id=producer_node(kind,bits,(uint32_t)key,(uint32_t)(key>>32),0,value);
 if(producers_enabled&&fprintf(producer_inputs,"{\"id\":%u,\"kind\":%u,\"key\":%" PRIu64 ",\"value\":%" PRIu64 ",\"known\":%" PRIu64 "}\n",
  id,kind,key,value,bits==64?UINT64_MAX:((UINT64_C(1)<<bits)-1))<0)die("producer input write");
 return id;
}
static uint64_t producer_cell(uint32_t id,unsigned offset,unsigned bits) {
 return (uint64_t)id|((uint64_t)offset<<32)|((uint64_t)bits<<40);
}
static void producer_condition(unsigned kind,uint32_t expression,uint64_t expected) {
 if(!producers_enabled)return;
 if(!kind||kind>=10||!expression||expression>producer_count||producer_condition_count>=UINT32_C(134217728))die("producer condition identity or budget");
 uint32_t record[4]={GUINT32_TO_LE(kind),GUINT32_TO_LE(expression),GUINT32_TO_LE((uint32_t)expected),GUINT32_TO_LE((uint32_t)(expected>>32))};
 if(fwrite(record,sizeof record,1,producer_conditions)!=1)die("producer condition write");
 g_checksum_update(producer_condition_hash,(const guchar *)record,sizeof record);++producer_condition_count;++producer_condition_kind_counts[kind];
}
static void producer_begin(void) {
 const char *directory=getenv("TF_OEP_PRODUCERS");if(!directory||!*directory)return;
 if(strlen(directory)>=sizeof producer_directory)die("producer directory extent");
 strcpy(producer_directory,directory);
 const char *limit=getenv("TF_OEP_PRODUCER_LIMIT");
 if(limit&&*limit){char *end;unsigned long long value=strtoull(limit,&end,10);if(*end||!value||value>UINT32_C(268435456))die("producer limit");producer_limit=(uint32_t)value;}
 if(g_mkdir_with_parents(directory,0700))die("producer directory create");
 char path[8192];snprintf(path,sizeof path,"%s/nodes.bin",directory);producer_nodes=fopen(path,"wb");
 snprintf(path,sizeof path,"%s/inputs.jsonl",directory);producer_inputs=fopen(path,"wb");
 snprintf(path,sizeof path,"%s/conditions.bin",directory);producer_conditions=fopen(path,"wb");
 snprintf(path,sizeof path,"%s/instruction-origins.jsonl",directory);producer_origins=fopen(path,"wb");
 if(!producer_nodes||!producer_inputs||!producer_conditions||!producer_origins)die("producer ledger open");
 const unsigned char magic[8]={'T','F','P','R','O','D','1',0};uint32_t header[2]={GUINT32_TO_LE(1),GUINT32_TO_LE(32)};
 if(fwrite(magic,sizeof magic,1,producer_nodes)!=1||fwrite(header,sizeof header,1,producer_nodes)!=1)die("producer header write");
 producer_node_hash=g_checksum_new(G_CHECKSUM_SHA256);producer_condition_hash=g_checksum_new(G_CHECKSUM_SHA256);
 g_checksum_update(producer_node_hash,magic,sizeof magic);g_checksum_update(producer_node_hash,(const guchar *)header,sizeof header);
 producers_enabled=true;
}
static void producer_resize_file(unsigned file,size_t old_size,size_t size) {
 if(!producers_enabled)return;
 File *f=&files[file];f->producer=g_realloc(f->producer,size*sizeof(*f->producer));
 for(size_t i=old_size;i<size;++i){
  unsigned kind=ordinal?P_KERNEL_FILE_ZERO:P_INITIAL_FILE_PADDING_ZERO;
  uint64_t key=ordinal?((uint64_t)file<<56)|((uint64_t)ordinal<<32)|i:((uint64_t)file<<32)|i;
  f->producer[i]=producer_cell(producer_leaf(kind,8,key,0),0,8);
 }
}
static void producer_map_page(Page *p,uint32_t address,int file) {
 if(!producers_enabled)return;
 p->producer=g_malloc0(4096*sizeof(*p->producer));p->producer_ordinal=ordinal;
 if(file>=0)memcpy(p->producer,files[file].producer+p->offset,4096*sizeof(*p->producer));
 (void)address;
}
static void producer_free_page(Page *p) {
 if(p)g_free(p->producer);
}
static uint32_t producer_byte(uint32_t address) {
 if(!producers_enabled)return 0;
 Page *p=page(address,0);unsigned offset=address&4095;uint64_t cell=p->producer[offset];uint32_t id=(uint32_t)cell;
 if(!id){
  if(p->producer_written[offset])die("computed RAM byte lacks producer");
  if(p->k[offset]!=255)id=producer_node(IR_OP_UNKNOWN,8,0,0,0,IR_REASON_UNDEFINED);
  else if(p->origin[offset]==1)id=producer_leaf(P_STACK_BYTE,8,address-initial_stack_base,p->v[offset]);
  else if(p->v[offset])die("producer initial nonzero byte lacks origin");
  else id=producer_leaf(p->producer_ordinal?P_KERNEL_RAM_ZERO:P_INITIAL_RAM_ZERO,8,
   ((uint64_t)p->producer_ordinal<<32)|address,0);
 }else{
  unsigned width=(unsigned)(cell>>40)&255,shift=(unsigned)(cell>>32)&255;
  if(width!=8||shift)id=producer_extract(8,id,shift);
 }
 p->producer[offset]=producer_cell(id,0,8);return id;
}
static uint32_t producer_load(uint32_t address,unsigned bits) {
 if(!producers_enabled)return 0;
 unsigned bytes=bits/8;
 if(!bits||bits%8||bits>64||(uint64_t)address+bytes>UINT64_C(0x100000000))die("producer LOAD extent");
 Page *p=page(address,0);uint64_t first=p->producer[address&4095];uint32_t id=(uint32_t)first;
 unsigned width=(unsigned)(first>>40)&255,shift=(unsigned)(first>>32)&255;bool same=id!=0;
 for(unsigned i=1;i<bytes&&same;++i){Page *q=page(address+i,0);uint64_t cell=q->producer[(address+i)&4095];
  same=(uint32_t)cell==id&&((unsigned)(cell>>40)&255)==width&&((unsigned)(cell>>32)&255)==shift+8*i;}
 if(same&&shift+bits<=width)return !shift&&bits==width?id:producer_extract(bits,id,shift);
 id=producer_byte(address);
 for(unsigned i=1;i<bytes;++i)id=producer_concat(8*(i+1),producer_byte(address+i),id,8*i);
 return id;
}
static void producer_store(uint32_t address,unsigned bits,uint32_t id) {
 if(!producers_enabled)return;
 if(!id||id>producer_count||!bits||bits%8||bits>64||(uint64_t)address+bits/8>UINT64_C(0x100000000))die("producer STORE extent");
 for(unsigned i=0;i<bits/8;++i){Page *p=page(address+i,0);unsigned offset=(address+i)&4095;
  uint64_t cell=producer_cell(id,8*i,bits);p->producer[offset]=cell;
  if(p->file>=0)files[p->file].producer[p->offset+offset]=cell;
 }
#ifdef TF_GENERIC_REPLAY
 if(generic_boundary_selector_version>=6&&page(address,0)->file>=0)
  generic_shared_refresh((unsigned)page(address,0)->file,false,true);
#endif
}
static void producer_packed_bytes(const uint8_t *elf,size_t size) {
 if(!producers_enabled)return;
 #ifdef TF_GENERIC_REPLAY
 producer_packed=g_malloc0(size*sizeof(*producer_packed));
#endif
 for(size_t i=0;i<size;++i){producer_packed[i]=producer_leaf(P_PACKED_BYTE,8,i,elf[i]);files[0].producer[i]=producer_cell(producer_packed[i],0,8);}
#ifndef TF_GENERIC_REPLAY
 for(unsigned i=0;i<4096;++i)pages[0x8048]->producer[i]=producer_cell(producer_packed[i],0,8);
 for(unsigned i=0;i<51072;++i)pages[(0x8065000+i)>>12]->producer[(0x8065000+i)&4095]=producer_cell(producer_packed[i],0,8);
#endif
}
static void producer_entry(uint32_t esp,uint32_t df) {
 if(!producers_enabled)return;
 for(unsigned i=0;i<8;++i)producer_state[256+i]=producer_node(IR_OP_UNKNOWN,32,0,0,0,IR_REASON_UNBOUND_STATE);
 for(unsigned i=0;i<7;++i)producer_state[512+i]=producer_node(IR_OP_UNKNOWN,1,0,0,0,IR_REASON_UNBOUND_STATE);
 producer_state[260]=producer_leaf(P_ENTRY_ESP,32,0,esp);producer_state[518]=producer_leaf(P_ENTRY_DF,1,0,df);
}
static void producer_fetch(Node *n) {
 if(!producers_enabled)return;
 uint32_t ids[15];for(unsigned i=0;i<n->size;++i){ids[i]=producer_byte(n->pc+i);producer_condition(5,ids[i],n->bytes[i]);}
 if(n->repeat_iterations>=0)producer_condition(7,producer_state[257],(uint32_t)n->repeat_iterations);
 if(!n->producer_recorded){
  fprintf(producer_origins,"{\"pc\":%u,\"first_step\":%" PRIu64 ",\"original_ir_sha256\":\"%s\",\"repeat_iterations\":%d,\"repeat_root\":%u,\"bytes_hex\":\"",
   n->pc,steps,n->sha,n->repeat_iterations,n->repeat_iterations>=0?producer_state[257]:0);
  for(unsigned i=0;i<n->size;++i)fprintf(producer_origins,"%02x",n->bytes[i]);
  fputs("\",\"fetch_roots\":[",producer_origins);for(unsigned i=0;i<n->size;++i)fprintf(producer_origins,"%s%u",i?",":"",ids[i]);
  if(fputs("]}\n",producer_origins)<0||ferror(producer_origins))die("producer instruction origins write");
  n->producer_recorded=true;
 }
}
static uint32_t producer_operation(Node *n,const IrInst *r,uint32_t a,uint32_t b,uint32_t c) {
 if(!producers_enabled)return 0;
 if(r->spec.op==IR_OP_EXTRACT)return producer_extract(r->spec.type.bits,a,(unsigned)r->spec.immediate);
 if(r->spec.op==IR_OP_CONCAT){
  const IrValue *low=ir_module_value(n->module,r->spec.args[1]);
  if(!low)die("producer CONCAT operand");
  return producer_concat(r->spec.type.bits,a,b,low->type.bits);
 }
 if(r->spec.op==IR_OP_CONST){
  if(!n->producer_constants)n->producer_constants=g_malloc0((ir_module_value_count(n->module)+1)*sizeof(*n->producer_constants));
  uint32_t *cached=&n->producer_constants[r->result];if(!*cached)*cached=producer_node(IR_OP_CONST,r->spec.type.bits,0,0,0,r->spec.immediate);return *cached;
 }
 return producer_node(r->spec.op,r->spec.type.bits,a,b,c,r->spec.immediate);
}
static void producer_goal(FILE *output,const char *kind,uint32_t address,unsigned bits,uint32_t id,unsigned offset,uint64_t value,uint64_t known_mask) {
 if(fprintf(output,"{\"kind\":\"%s\",\"address\":%u,\"bits\":%u,\"id\":%u,\"offset\":%u,\"value\":%" PRIu64 ",\"known\":%" PRIu64 "}\n",
  kind,address,bits,id,offset,value,known_mask)<0)die("producer goal write");
}
#ifdef TF_GENERIC_REPLAY
#define PRODUCER_SOURCE_KIND "computed_generic_entry_IR_producers"
#define PRODUCER_INPUT_COUNT 6U
#else
#define PRODUCER_SOURCE_KIND "computed_original_entry_IR_producers"
#define PRODUCER_INPUT_COUNT 5U
#endif
static void producer_finish(const char *const input_paths[]) {
 if(!producers_enabled)return;
 if(!producer_target||producer_target>producer_count)die("producer final target identity");
 char path[8192];snprintf(path,sizeof path,"%s/goals.jsonl",producer_directory);FILE *goals=fopen(path,"wb");if(!goals)die("producer goals open");
 producer_goal(goals,"target",pc,32,producer_target,0,last_target,UINT32_MAX);
#ifndef TF_GENERIC_REPLAY
 for(unsigned i=0;i<4;++i){uint32_t address=0x8048018+i;Page *p=page(address,0);producer_goal(goals,"elf_entry_byte",address,8,producer_byte(address),0,p->v[address&4095],p->k[address&4095]);}
#endif
 for(unsigned i=0;i<producer_fetch_size;++i){uint32_t address=pc+i;Page *p=page(address,0);producer_goal(goals,"target_fetch_byte",address,8,producer_byte(address),0,p->v[address&4095],p->k[address&4095]);}
#ifndef TF_GENERIC_REPLAY
 const uint32_t ranges[][2]={{0x8048000,308},{0x8049000,91187},{0x8060000,11432},{0x8063fe0,3780}};
 for(unsigned r=0;r<4;++r)for(uint32_t i=0;i<ranges[r][1];++i){uint32_t address=ranges[r][0]+i;Page *p=page(address,0);
  producer_goal(goals,"restored_image_byte",address,8,producer_byte(address),0,p->v[address&4095],p->k[address&4095]);}
#else
 for(unsigned r=0;r<generic_range_count;++r)for(uint32_t i=0;i<generic_ranges[r].size;++i){uint32_t address=generic_ranges[r].start+i;Page *p=page(address,0);
  producer_goal(goals,"observed_image_byte",address,8,producer_byte(address),0,p->v[address&4095],p->k[address&4095]);}
#endif
 if(fclose(goals)||fclose(producer_inputs)||fclose(producer_conditions)||fclose(producer_origins)||fclose(producer_nodes))die("producer ledger close");
 snprintf(path,sizeof path,"%s/manifest.json",producer_directory);FILE *output=fopen(path,"wb");if(!output)die("producer manifest open");
 fprintf(output,"{\"schema_version\":1,\"record_size\":32,\"header_bytes\":16,\"node_count\":%u,\"node_limit\":%u,\"nodes_sha256\":\"%s\",\"condition_record_size\":16,\"condition_count\":%" PRIu64 ",\"conditions_sha256\":\"%s\",\"instructions\":%" PRIu64 ",\"path_sha256\":\"%s\",\"target_root\":%u,\"source_kind\":\"%s\",\"checkpoint_used_as_seed\":false,\"observed_final_state_used_as_input\":false,\"selected_execution_alias_and_fetch_schedule\":true,\"all_initial_states_proven\":false,\"condition_schema_version\":1,\"computed_transfer_targets_recorded\":true,\"kernel_checked_path_bytes_recorded\":true,\"condition_kind_counts\":{",
  producer_count,producer_limit,g_checksum_get_string(producer_node_hash),producer_condition_count,g_checksum_get_string(producer_condition_hash),steps,g_checksum_get_string(path_hash),producer_target,PRODUCER_SOURCE_KIND);
 for(unsigned kind=1;kind<10;++kind)fprintf(output,"%s\"%u\":%" PRIu64,kind>1?",":"",kind,producer_condition_kind_counts[kind]);
 fputs("},\"input_files_sha256\":[",output);
 for(unsigned i=0;i<PRODUCER_INPUT_COUNT;++i){gchar *data=NULL;gsize size=0;if(!g_file_get_contents(input_paths[i],&data,&size,NULL)||size>1048576)die("producer source input read");
  gchar *digest=g_compute_checksum_for_data(G_CHECKSUM_SHA256,(const guchar *)data,size);fprintf(output,"%s\"%s\"",i?",":"",digest);g_free(data);g_free(digest);}
 fputs("]}\n",output);if(fclose(output))die("producer manifest close");
}
#endif
