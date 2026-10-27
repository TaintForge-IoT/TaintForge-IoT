/* Bounded preparation/evaluation for recorded original-entry conditions.
 * Evaluation supplies conjectures only. The Python caller authenticates source
 * leaves and proves every producer equality before using check's comparisons.
 */
#define _POSIX_C_SOURCE 200809L
#define _FILE_OFFSET_BITS 64
#include "ir.h"
#include "ir_eval.h"
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#define RAW_LIMIT UINT32_C(268435456)
#define COMPACT_LIMIT UINT32_C(67108864)
#define CONDITION_LIMIT UINT32_C(134217728)
#define BLOCK 4096U
typedef struct { unsigned char *data; size_t size; } Map;
typedef struct { uint16_t op, bits; uint32_t a, b, c; uint64_t immediate, origin; } Node;
typedef struct { uint32_t count, words, total; uint64_t *bits; uint32_t *rank; } Needed;
static const char *error_message = "ok";
static bool fail(const char *message) { error_message = message; return false; }
static uint32_t le32(const unsigned char *p) { return p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24; }
static uint64_t le64(const unsigned char *p) { return le32(p) | (uint64_t)le32(p + 4) << 32; }
static uint64_t mask(unsigned bits) { return bits == 64 ? UINT64_MAX : (UINT64_C(1) << bits) - 1; }
static unsigned arity(unsigned op) {
    static const unsigned char counts[] = {0,0,0,1,2,2,2,2,2,2,1,1,2,2,2,1,2,1,1,2,2,2,3};
    return op < sizeof(counts) ? counts[op] : 0;
}
static bool source(unsigned op) { return op >= 100 && op <= 109; }
static bool mapped(const char *path, Map *out) {
    int fd = open(path, O_RDONLY | O_NOFOLLOW); struct stat st;
    if (fd < 0) return fail("Cannot open input");
    bool ok = !fstat(fd, &st) && S_ISREG(st.st_mode) && st.st_size > 0 && (uint64_t)st.st_size <= (uint64_t)SIZE_MAX;
    if (ok) { out->size = (size_t)st.st_size; out->data = mmap(NULL, out->size, PROT_READ, MAP_PRIVATE, fd, 0); ok = out->data != MAP_FAILED; }
    close(fd);
    if (!ok) { out->data = NULL; return fail("Input mapping or extent"); }
    return true;
}
static void unmap(Map *m) { if (m->data) munmap(m->data, m->size); m->data = NULL; }
static bool producer_map(const char *path, Map *m, uint32_t *count, uint32_t limit) {
    if (!mapped(path, m)) return false;
    if (m->size < 48 || (m->size - 16) % 32 || memcmp(m->data, "TFPROD1\0", 8) || le32(m->data + 8) != 1 || le32(m->data + 12) != 32 || (m->size - 16) / 32 > limit)
        return fail("Producer framing or node budget");
    *count = (uint32_t)((m->size - 16) / 32); return true;
}
static Node node(const Map *m, uint32_t id) {
    const unsigned char *p = m->data + 16 + (size_t)(id - 1) * 32;
    return (Node){p[0] | (uint16_t)p[1] << 8, p[2] | (uint16_t)p[3] << 8,
                  le32(p + 4), le32(p + 8), le32(p + 12), le64(p + 16), le64(p + 24)};
}
static bool valid(Node p, uint32_t id) {
    if (!p.bits || p.bits > 64 || (p.op > IR_OP_ITE && !source(p.op)) || p.op == IR_OP_INPUT) return fail("Unsupported producer opcode or width");
    if (source(p.op)) return (!p.c && !(p.immediate & ~mask(p.bits))) || fail("Source metadata or value");
    uint32_t args[] = {p.a,p.b,p.c}; unsigned n = arity(p.op);
    for (unsigned i = 0; i < 3; ++i)
        if (i < n ? (!args[i] || args[i] >= id) : args[i] != 0) return fail("Producer dependency order");
    return p.op != IR_OP_CONST || !(p.immediate & ~mask(p.bits)) || fail("Constant width");
}
static bool condition_map(const char *path, Map *m, uint64_t *count) {
    if (!mapped(path, m)) return false;
    if (m->size % 16 || m->size / 16 > CONDITION_LIMIT) return fail("Condition framing or budget");
    *count = m->size / 16; return true;
}
static bool condition(const Map *nodes, uint32_t count, const unsigned char *p, uint32_t *kind, uint32_t *id, uint64_t *expected) {
    static const unsigned widths[] = {0,1,1,32,32,8,32,32,32,8};
    *kind = le32(p); *id = le32(p + 4); *expected = le64(p + 8);
    if (!*kind || *kind > 9 || !*id || *id > count) return fail("Condition identity or kind");
    Node r = node(nodes, *id);
    return (r.bits == widths[*kind] && !(*expected & ~mask(r.bits))) || fail("Condition width or expected value");
}
static bool needed_create(uint32_t count, Needed *n) {
    n->count = count; n->words = count / 64 + 1;
    n->bits = calloc(n->words, sizeof(*n->bits)); n->rank = calloc((size_t)n->words + 1, sizeof(*n->rank));
    return (n->bits && n->rank) || fail("Reachability allocation");
}
static bool has(const Needed *n, uint32_t id) { return (n->bits[id / 64] >> (id % 64)) & 1; }
static void mark(Needed *n, uint32_t id) { n->bits[id / 64] |= UINT64_C(1) << (id % 64); }
static bool rank_needed(Needed *n) {
    uint64_t total = 0;
    for (uint32_t w = 0; w < n->words; ++w) { n->rank[w] = (uint32_t)total; total += (unsigned)__builtin_popcountll(n->bits[w]); }
    if (!total || total > COMPACT_LIMIT) return fail("Compact closure budget");
    n->rank[n->words] = n->total = (uint32_t)total; return true;
}
static uint32_t compact_id(const Needed *n, uint32_t id) {
    unsigned bit = id % 64; uint64_t through = bit == 63 ? UINT64_MAX : (UINT64_C(1) << (bit + 1)) - 1;
    return n->rank[id / 64] + (unsigned)__builtin_popcountll(n->bits[id / 64] & through);
}
static void needed_free(Needed *n) { free(n->bits); free(n->rank); }
static bool put(FILE *f, uint64_t value, unsigned bytes) {
    unsigned char data[8]; for (unsigned i = 0; i < bytes; ++i) data[i] = (unsigned char)(value >> (8 * i));
    return fwrite(data, 1, bytes, f) == bytes || fail("Output write");
}
static bool header(FILE *f, const char *magic, uint32_t detail) { return fwrite(magic, 1, 8, f) == 8 && put(f, 1, 4) && put(f, detail, 4); }
static bool write_node(FILE *f, Node p) { return put(f,p.op,2) && put(f,p.bits,2) && put(f,p.a,4) && put(f,p.b,4) && put(f,p.c,4) && put(f,p.immediate,8) && put(f,p.origin,8); }
static FILE *create(const char *directory, const char *name) {
    char path[8192]; int n = snprintf(path, sizeof(path), "%s/%s", directory, name);
    if (n < 0 || (size_t)n >= sizeof(path)) { fail("Output path budget"); return NULL; }
    FILE *f = fopen(path, "wx"); if (!f) fail("Output already exists or cannot be created"); return f;
}
static bool roots(const char *path, uint32_t count, Needed *n) {
    FILE *f = fopen(path,"r"); if (!f) return fail("Cannot open final root IDs");
    char line[64]; uint32_t rows = 0; bool ok = true;
    while (fgets(line,sizeof(line),f)) {
        char *end; errno = 0; unsigned long long id = strtoull(line,&end,10);
        if (line[0] < '0' || line[0] > '9' || errno || !id || id > count || strcmp(end,"\n") || ++rows > 262144) { ok = fail("Final root ID framing or budget"); break; }
        mark(n,(uint32_t)id);
    }
    if (ferror(f)) ok = fail("Final root ID read");
    fclose(f); return ok;
}
static int prepare(const char *nodes_path, const char *conditions_path, const char *roots_path, const char *directory) {
    Map nodes = {0}, conditions = {0}; Needed needed = {0}; uint32_t count = 0;
    uint64_t nc = 0, kinds[10] = {0}, sources = 0, goals = 0; bool ok = false;
    uint64_t *expected = NULL; uint32_t *kind_masks = NULL;
    FILE *compact = NULL,*source_map = NULL,*bitmap = NULL,*ranks = NULL,*condition_goals = NULL;
    if (mkdir(directory,0700) && errno != EEXIST) { fail("Cannot create output directory"); goto done; }
    if (!producer_map(nodes_path,&nodes,&count,RAW_LIMIT) || !condition_map(conditions_path,&conditions,&nc) || !needed_create(count,&needed)) goto done;
    for (uint64_t i = 0; i < nc; ++i) { uint32_t k,id; uint64_t value; if (!condition(&nodes,count,conditions.data + i*16,&k,&id,&value)) goto done; mark(&needed,id); ++kinds[k]; }
    if (!roots(roots_path,count,&needed)) goto done;
    for (uint32_t id = count; id; --id) if (has(&needed,id)) {
        Node p = node(&nodes,id); if (!valid(p,id)) goto done;
        if (!source(p.op)) { uint32_t args[] = {p.a,p.b,p.c}; for (unsigned j=0;j<arity(p.op);++j) mark(&needed,args[j]); }
    }
    if (!rank_needed(&needed)) goto done;
    expected = calloc((size_t)needed.total + 1,sizeof(*expected)); kind_masks = calloc((size_t)needed.total + 1,sizeof(*kind_masks));
    if (!expected || !kind_masks) { fail("Deduplicated condition allocation"); goto done; }
    for (uint64_t i=0;i<nc;++i) { const unsigned char *p=conditions.data+i*16; uint32_t k=le32(p),id=compact_id(&needed,le32(p+4)); uint64_t value=le64(p+8);
        if (kind_masks[id] && expected[id] != value) { fail("Conflicting conditions for one producer"); goto done; }
        if (!kind_masks[id]) ++goals;
        kind_masks[id] |= UINT32_C(1) << k; expected[id] = value;
    }
    compact=create(directory,"compact.bin");source_map=create(directory,"source-map.jsonl");bitmap=create(directory,"needed.bitset");ranks=create(directory,"needed.rank");condition_goals=create(directory,"condition-goals.bin");
    if (!compact || !source_map || !bitmap || !ranks || !condition_goals || !header(compact,"TFPROD1\0",32) || !header(bitmap,"TFNEED1\0",count) || !header(ranks,"TFRANK1\0",count) || !header(condition_goals,"TFCND1\0\0",16)) goto done;
    for (uint32_t w=0;w<needed.words;++w) if (!put(bitmap,needed.bits[w],8) || !put(ranks,needed.rank[w],4)) goto done;
    if (!put(ranks,needed.total,4)) goto done;
    for (uint32_t id=1;id<=count;++id) if (has(&needed,id)) {
        Node p=node(&nodes,id);uint32_t cid=compact_id(&needed,id);
        if (source(p.op)) { ++sources;
            if (fprintf(source_map,"{\"id\":%u,\"old_id\":%u,\"record\":[%u,%u,%u,%u,%u,%" PRIu64 ",%" PRIu64 "]}\n",cid,id,p.op,p.bits,p.a,p.b,p.c,p.immediate,p.origin)<0) { fail("Source map write");goto done; }
        } else { if (p.a)p.a=compact_id(&needed,p.a);if(p.b)p.b=compact_id(&needed,p.b);if(p.c)p.c=compact_id(&needed,p.c); }
        if (!write_node(compact,p)) goto done;
        if (kind_masks[cid] && (!put(condition_goals,cid,4) || !put(condition_goals,kind_masks[cid],4) || !put(condition_goals,expected[cid],8))) goto done;
    }
    ok=true;
done:
    if(compact&&fclose(compact))ok=false;
    if(source_map&&fclose(source_map))ok=false;
    if(bitmap&&fclose(bitmap))ok=false;
    if(ranks&&fclose(ranks))ok=false;
    if(condition_goals&&fclose(condition_goals))ok=false;
    FILE *report=create(directory,"receipt.json");
    if(report){fprintf(report,"{\"schema_version\":1,\"status\":\"%s\",\"diagnostic\":\"%s\",\"nodes\":%u,\"compact_nodes\":%u,\"source_leaves\":%" PRIu64 ",\"condition_count\":%" PRIu64 ",\"condition_goal_count\":%" PRIu64 ",\"kind_counts\":[",ok?"PREPARED":"INVALID",error_message,count,needed.total,sources,nc,goals);for(unsigned i=0;i<10;++i)fprintf(report,"%s%" PRIu64,i?",":"",kinds[i]);fputs("]}\n",report);if(fclose(report))ok=false;}else ok=false;
    free(expected);free(kind_masks);needed_free(&needed);unmap(&nodes);unmap(&conditions);return ok?0:1;
}

typedef struct { const Map *nodes; unsigned char *values; uint32_t start,stop; } Evaluation;
static IrBits read_value(void *user, IrBindingKind kind, uint64_t key, uint8_t width) {
    Evaluation *e=user;if(kind!=IR_BIND_INPUT||!key||key>e->stop)return ir_bits_unknown(IR_REASON_UNBOUND_INPUT);
    Node p=node(e->nodes,(uint32_t)key);if(p.bits!=width)return ir_bits_unknown(IR_REASON_UNBOUND_INPUT);
    if(key<e->start)return ir_bits_known(le64(e->values+16+(size_t)(key-1)*8),width);
    return source(p.op)?ir_bits_known(p.immediate,width):ir_bits_unknown(IR_REASON_UNBOUND_INPUT);
}
static IrValueId emit_value(IrModule *m,IrBlockId b,IrOpcode op,unsigned bits,IrValueId a,IrValueId c,IrValueId d,uint64_t immediate) {
    return ir_emit_value(m,b,(IrInstSpec){.op=op,.type=ir_type_bv(bits),.args={a,c,d},.immediate=immediate});
}
static int compare_u32(const void *a,const void *b){uint32_t x=*(const uint32_t*)a,y=*(const uint32_t*)b;return x>y?1:x<y?-1:0;}
static uint32_t boundary_index(const uint32_t *ids,uint32_t count,uint32_t key){uint32_t lo=0,hi=count;while(lo<hi){uint32_t mid=lo+(hi-lo)/2;if(ids[mid]<key)lo=mid+1;else hi=mid;}return lo<count&&ids[lo]==key?lo:UINT32_MAX;}
static bool original_sources(const char *path,const Map *nodes,uint32_t count,unsigned char *seen,uint32_t *leaves) {
    FILE*f=fopen(path,"r");if(!f)return fail("Cannot open authenticated source premises");char line[256];bool ok=true;uint32_t rows=0;
    while(fgets(line,sizeof(line),f)){unsigned long long id,value,known;char tail;if(sscanf(line,"%llu %llx %llx %c",&id,&value,&known,&tail)!=3||!strchr(line,'\n')||!id||id>count||++rows>1048576){ok=fail("Source premise framing or budget");break;}
        Node p=node(nodes,(uint32_t)id);if(!valid(p,(uint32_t)id)){ok=false;break;}if(!source(p.op)||(seen[id/8]>>(id%8)&1)||value!=p.immediate||known!=mask(p.bits)){ok=fail("Source premise identity, value or mask");break;}seen[id/8]|=(unsigned char)(1U<<(id%8));
    }
    if(ferror(f))ok=fail("Source premise read");
    fclose(f);
    *leaves=0;for(uint32_t id=1;ok&&id<=count;++id){Node p=node(nodes,id);if(!valid(p,id)){ok=false;break;}if(source(p.op)){++*leaves;if(!(seen[id/8]>>(id%8)&1))ok=fail("Missing authenticated source premise");}}
    return ok;
}
static int evaluate(const char *nodes_path,const char *premises,const char *values_path,const char *report_path) {
    Map nodes={0};uint32_t count=0,leaves=0,completed=0;uint64_t steps=0;unsigned char*seen=NULL,*values=NULL;size_t values_size=0;int fd=-1;bool ok=false,unknown=false;
    if(!producer_map(nodes_path,&nodes,&count,COMPACT_LIMIT))goto done;
    seen=calloc((size_t)count/8+1,1);if(!seen){fail("Source premise allocation");goto done;}
    if(!original_sources(premises,&nodes,count,seen,&leaves))goto done;
    values_size=16+(size_t)count*8;fd=open(values_path,O_RDWR|O_CREAT|O_EXCL,0600);if(fd<0||ftruncate(fd,(off_t)values_size)){fail("Cannot create value conjecture file");goto done;}
    values=mmap(NULL,values_size,PROT_READ|PROT_WRITE,MAP_SHARED,fd,0);if(values==MAP_FAILED){values=NULL;fail("Conjecture mapping");goto done;}
    memcpy(values,"TFVALUES\1\0\0\0",12);for(unsigned j=0;j<4;++j)values[12+j]=(unsigned char)(count>>(8*j));
    for(uint32_t start=1;start<=count;){uint32_t stop=count-start+1>BLOCK?start+BLOCK-1:count;
        uint32_t boundary[3*BLOCK],nb=0;IrValueId boundary_values[3*BLOCK],current[BLOCK];
        for(uint32_t id=start;id<=stop;++id){Node p=node(&nodes,id);if(!source(p.op)){uint32_t args[]={p.a,p.b,p.c};for(unsigned j=0;j<arity(p.op);++j)if(args[j]<start)boundary[nb++]=args[j];}}
        qsort(boundary,nb,sizeof(*boundary),compare_u32);uint32_t unique=0;for(uint32_t i=0;i<nb;++i)if(!i||boundary[i]!=boundary[i-1])boundary[unique++]=boundary[i];nb=unique;
        uint32_t capacity=stop-start+1+nb+1;IrLimits limits={capacity,capacity,1,1,1};IrModule*m=ir_module_create(&limits);IrEval*eval=NULL;bool block_ok=false;
        if(!m){fail("Evaluation module allocation");goto block_done;}IrBlockId block=ir_block_add(m);if(!block||!ir_module_set_entry(m,block)){fail("Evaluation block");goto block_done;}
        for(uint32_t j=0;j<nb;++j){Node p=node(&nodes,boundary[j]);boundary_values[j]=emit_value(m,block,IR_OP_INPUT,p.bits,0,0,0,boundary[j]);if(!boundary_values[j]){fail("Evaluation boundary input");goto block_done;}}
        for(uint32_t id=start;id<=stop;++id){Node p=node(&nodes,id);IrValueId args[3]={0};uint32_t old[]={p.a,p.b,p.c};
            if(source(p.op))current[id-start]=emit_value(m,block,IR_OP_INPUT,p.bits,0,0,0,id);
            else{for(unsigned j=0;j<arity(p.op);++j){if(old[j]>=start)args[j]=current[old[j]-start];else{uint32_t at=boundary_index(boundary,nb,old[j]);if(at==UINT32_MAX){fail("Evaluation boundary identity");goto block_done;}args[j]=boundary_values[at];}}
                uint64_t immediate=p.op==IR_OP_UNKNOWN&&!p.immediate?IR_REASON_UNDEFINED:p.immediate;current[id-start]=emit_value(m,block,(IrOpcode)p.op,p.bits,args[0],args[1],args[2],immediate);}
            if(!current[id-start]){fail("Evaluation operation build");goto block_done;}}
        if(!ir_block_terminate(m,block,(IrTerminator){.kind=IR_TERM_FRAGMENT_END})||!ir_validate(m,NULL)){fail("Evaluation IR validation");goto block_done;}
        Evaluation context={&nodes,values,start,stop};IrBindings bindings={.user=&context,.read_bv=read_value};IrEvalLimits el=ir_eval_default_limits();el.steps=(uint64_t)capacity+1;
        eval=ir_eval_create(m,&bindings,&el);if(!eval){fail("Evaluation interpreter allocation");goto block_done;}IrEvalResult result=ir_eval_run(eval);steps+=result.steps;
        if(result.status!=IR_EVAL_FRAGMENT_END){unknown=result.status==IR_EVAL_UNKNOWN;fail("Streaming IR evaluation did not complete");goto block_done;}
        for(uint32_t id=start;id<=stop;++id){Node p=node(&nodes,id);IrEvalValue v=ir_eval_value(eval,current[id-start]);if(!ir_bits_complete(v.bits,p.bits)){unknown=true;fail("Required producer conjecture is UNKNOWN");goto block_done;}for(unsigned j=0;j<8;++j)values[16+(size_t)(id-1)*8+j]=(unsigned char)(v.bits.value>>(8*j));}
        completed=stop;block_ok=true;
block_done:
        ir_eval_destroy(eval);ir_module_destroy(m);if(!block_ok)goto done;start=stop+1;
    }
    ok=true;
done:
    if(values&&munmap(values,values_size))ok=false;
    if(fd>=0)close(fd);
    free(seen);unmap(&nodes);
    FILE*report=fopen(report_path,"wx");if(!report){fprintf(stderr,"Cannot create evaluation report\n");return 1;}
    fprintf(report,"{\"schema_version\":1,\"status\":\"%s\",\"diagnostic\":\"%s\",\"producer_nodes\":%u,\"source_premises\":%u,\"fully_known_nodes\":%u,\"eval_steps\":%" PRIu64 ",\"values_are_proposed_lemmas_only\":true,\"source_leaf_authentication\":\"caller\",\"observed_checkpoint_used_as_premise\":false}\n",ok?"EVALUATED":unknown?"UNKNOWN":"INVALID",error_message,count,leaves,completed,steps);if(fclose(report))ok=false;return ok?0:1;
}
static bool load_needed(const char *path,uint32_t count,Needed*n){Map bitmap={0};bool ok=false;if(!needed_create(count,n)||!mapped(path,&bitmap))goto done;
    if(bitmap.size!=16+(size_t)n->words*8||memcmp(bitmap.data,"TFNEED1\0",8)||le32(bitmap.data+8)!=1||le32(bitmap.data+12)!=count){fail("Needed bitmap framing");goto done;}
    for(uint32_t w=0;w<n->words;++w)n->bits[w]=le64(bitmap.data+16+(size_t)w*8);
    if(n->bits[0]&1||(count%64!=63&&(n->bits[n->words-1]>>(count%64+1)))){fail("Needed bitmap unused bits");goto done;}ok=rank_needed(n);
done:unmap(&bitmap);return ok;}
static int check(const char *nodes_path,const char *conditions_path,const char *bitmap_path,const char *values_path,const char *report_path){Map nodes={0},conditions={0},values={0};Needed needed={0};uint32_t count=0;uint64_t nc=0,checked=0,kinds[10]={0},mismatch=0;bool ok=false,bad=false;
    if(!producer_map(nodes_path,&nodes,&count,RAW_LIMIT)||!condition_map(conditions_path,&conditions,&nc)||!load_needed(bitmap_path,count,&needed)||!mapped(values_path,&values))goto done;
    if(values.size!=16+(size_t)needed.total*8||memcmp(values.data,"TFVALUES",8)||le32(values.data+8)!=1||le32(values.data+12)!=needed.total){fail("Proved-value file framing");goto done;}
    for(uint64_t i=0;i<nc;++i){uint32_t k,id;uint64_t expected;if(!condition(&nodes,count,conditions.data+i*16,&k,&id,&expected))goto done;if(!has(&needed,id)){fail("Required condition producer missing from closure");goto done;}Node p=node(&nodes,id);uint64_t actual=le64(values.data+16+(size_t)(compact_id(&needed,id)-1)*8);if(actual&~mask(p.bits)){fail("Producer value width");goto done;}if(actual!=expected){bad=true;mismatch=i+1;fail("Recorded condition differs from supplied producer value");goto done;}++checked;++kinds[k];}
    ok=true;
done:
    FILE*report=fopen(report_path,"wx");if(!report){fprintf(stderr,"Cannot create condition report\n");ok=false;}else{fprintf(report,"{\"schema_version\":1,\"status\":\"%s\",\"diagnostic\":\"%s\",\"condition_count\":%" PRIu64 ",\"checked_occurrences\":%" PRIu64 ",\"first_mismatching_occurrence\":%" PRIu64 ",\"proof_validation\":\"caller\",\"native_command_does_not_prove_supplied_values\":true,\"kind_counts\":[",ok?"MATCHED_PROVED_VALUES":bad?"MISMATCH":"INVALID",error_message,nc,checked,mismatch);for(unsigned i=0;i<10;++i)fprintf(report,"%s%" PRIu64,i?",":"",kinds[i]);fputs("]}\n",report);if(fclose(report))ok=false;}
    needed_free(&needed);unmap(&nodes);unmap(&conditions);unmap(&values);return ok?0:1;
}
int main(int argc,char**argv){
    if(argc==6&&!strcmp(argv[1],"prepare"))return prepare(argv[2],argv[3],argv[4],argv[5]);
    if(argc==6&&!strcmp(argv[1],"evaluate"))return evaluate(argv[2],argv[3],argv[4],argv[5]);
    if(argc==7&&!strcmp(argv[1],"check"))return check(argv[2],argv[3],argv[4],argv[5],argv[6]);
    fputs("Usage: oep-schedule prepare NODES CONDITIONS ROOT_IDS OUTPUT_DIR\n       oep-schedule evaluate COMPACT SOURCE_PREMISES VALUES REPORT\n       oep-schedule check NODES CONDITIONS NEEDED_BITSET VALUES REPORT\n",stderr);return 1;
}
