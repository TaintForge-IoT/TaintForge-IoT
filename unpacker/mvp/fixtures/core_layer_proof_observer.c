/* Standard-API observation of a fresh controlled static i386 prefix. No
 * observed checkpoint initializes replay; no selected target insn executes. */
#define _GNU_SOURCE
#include <elf.h>
#include <errno.h>
#include <glib.h>
#include <inttypes.h>
#include <qemu-plugin.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "qemu_plugin_compat.h"

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;
#define MAX_STAGES 8U
#define MAX_LOADS 32U
#define MAX_CONTEXTS 65536U
#define MAX_STEPS UINT64_C(1000000)
#define MAX_EVENTS (UINT64_C(32)*1024U*1024U)
#define MAX_IMAGE (1024U*1024U)
#define PAGE 4096U
typedef struct { uint32_t pc,size,predecessor,generation,mapping_epoch; uint64_t ordinal; } Stage;
typedef struct { uint32_t address,offset,filesz,memsz,start,size,prot; } Load;
typedef struct { uint32_t pc; uint8_t size,bytes[15]; } Insn;
static const char *names[9]={"eax","ecx","edx","ebx","esp","ebp","esi","edi","eflags"};
static struct qemu_plugin_register *handles[9];
static bool handle_present[9];
static GByteArray *memory_buffer,*register_buffer;
static GChecksum *events_hash,*path_hash,*fetch_hash;
static FILE *events;
static const char *guest_path,*events_path,*report_path,*run_id;
static gchar *elf_bytes,*elf_sha;
static gsize elf_size;
static Stage stages[MAX_STAGES];
static Load loads[MAX_LOADS];
static uint32_t stage_count,visited,load_count,initial_pc,stop_pc,stop_index;
static unsigned selector_version=1;
static bool stop_index_supplied;
static uint32_t page_generation[1U<<20],page_mapping_epoch[1U<<20];
static uint32_t current_registers[9],pending_args[6],pending_mmap_args[6],pending_number;
static uint8_t page_permissions[1U<<20];
static bool page_mapped[1U<<20],page_initial[1U<<20];
static unsigned stack_prot=7;
static uint64_t instructions,stores,event_bytes,syscall_count,syscall_returns;
static uint64_t pending_pc,pending_ordinal;
static uint32_t cpus,contexts,post_result;
static Insn *current;
static bool initialized,finished,boundary,pending_syscall,post_pending;
static gchar *pending_mapping_effect,*pending_file_mapping,*pending_file_descriptor,*pending_path;
static uint32_t descriptor_epochs[64];
/* V5 tracks an observed local file object separately from its fd and mapping
 * lifetimes. Its bytes are used only to audit constructor conclusions; native
 * proof inputs remain the original packed ELF and source-derived producers. */
typedef struct {
    uint8_t *bytes;
    uint32_t *store_generations;
    uint32_t size,capacity,content_epoch;
    /* A V7 shared STORE changed final-page cache bytes outside logical EOF.
     * Such bytes persist across our supported remaps, but truncate/growth
     * semantics are deliberately not inferred from this observation. */
    bool tail_dirty;
} ObservedFile;
static ObservedFile mutable_files[32];
static uint32_t next_file_id=1,descriptor_file_ids[64],descriptor_offsets[64];
/* Zero means anonymous/initial; otherwise stores the immutable object id + 1. */
static uint8_t page_backing_tokens[1U<<20];
static bool page_backing_shared[1U<<20];
static uint32_t page_backing_offsets[1U<<20];
static bool file_page_seen[1U<<20];
static uint32_t file_page_indices[65536],file_page_count;
static uint8_t *pending_write_bytes;
static gchar *pending_name,*pending_file_mutation;
static gchar *shared_store_observation(uint32_t address,uint32_t size);


static gchar *selector_json(void) {
    if(selector_version==1) return g_strdup("");
    gchar *epoch=selector_version>=3?g_strdup_printf(",\"stop_mapping_epoch\":%u",stages[stop_index].mapping_epoch):g_strdup("");
    gchar *result=g_strdup_printf(",\"boundary_selector_version\":%u,\"stop_instruction_ordinal\":%" PRIu64
        ",\"stop_page_generation\":%u,\"stop_stage_index\":%u%s",
        selector_version,stages[stop_index].ordinal,stages[stop_index].generation,stop_index,epoch);
    g_free(epoch);return result;
}

static gchar *epoch_json(uint32_t address) {
    return selector_version>=3?g_strdup_printf(",\"mapping_epoch\":%u",page_mapping_epoch[address>>12]):g_strdup("");
}

static void complete(bool success,const char *reason);
static void reject(const char *reason) {
    fprintf(stderr,"Layer proof observer: %s after %" PRIu64 " instructions\n",reason,instructions);
    complete(false,reason); _Exit(1);
}
static uint16_t u16(const uint8_t *p) { return (uint16_t)p[0]|(uint16_t)p[1]<<8; }
static uint32_t u32(const uint8_t *p) {
    return (uint32_t)p[0]|(uint32_t)p[1]<<8|(uint32_t)p[2]<<16|(uint32_t)p[3]<<24;
}
static uint64_t rounded(uint64_t n) { return (n+4095U)&~UINT64_C(4095); }
static gchar *hex(const uint8_t *bytes,size_t size) {
    static const char digits[]="0123456789abcdef";
    gchar *text=g_malloc(2U*size+1U);
    for(size_t i=0;i<size;++i) { text[2U*i]=digits[bytes[i]>>4]; text[2U*i+1]=digits[bytes[i]&15]; }
    text[2U*size]=0; return text;
}
static bool write_line(const char *text,bool footer) {
    size_t size=strlen(text); uint64_t limit=footer?MAX_EVENTS:MAX_EVENTS-8192U;
    if(!events || event_bytes>limit || size>limit-event_bytes || fwrite(text,1,size,events)!=size) return false;
    g_checksum_update(events_hash,(const guchar *)text,size); event_bytes+=size; return true;
}
static void record(const char *format,...) __attribute__((format(printf,1,2)));
static void record(const char *format,...) {
    va_list args; va_start(args,format); gchar *text=g_strdup_vprintf(format,args); va_end(args);
    bool ok=text && write_line(text,false); g_free(text);
    if(!ok) reject("event_write_or_budget");
}
static bool read_guest(uint64_t address,uint8_t *bytes,size_t size) {
    if(address>UINT32_MAX || size>MAX_IMAGE || size>(UINT64_C(1)<<32)-address) return false;
    while(size) {
        size_t part=size>PAGE?PAGE:size; g_byte_array_set_size(memory_buffer,0);
        if(!qemu_plugin_read_memory_vaddr(address,memory_buffer,part) || memory_buffer->len!=part) return false;
        memcpy(bytes,memory_buffer->data,part); address+=part; bytes+=part; size-=part;
    }
    return true;
}
static void registers(uint32_t values[9]) {
    for(unsigned i=0;i<9;++i) {
        if(!handle_present[i] || !tf_qemu_read_register_exact(handles[i],register_buffer,4)) reject("register_snapshot");
        values[i]=u32(register_buffer->data);
    }
}
static gchar *register_json(const uint32_t v[9]) {
    return g_strdup_printf("{\"eax\":%u,\"ecx\":%u,\"edx\":%u,\"ebx\":%u,\"esp\":%u,\"ebp\":%u,\"esi\":%u,\"edi\":%u,\"eflags\":%u}",
        v[0],v[1],v[2],v[3],v[4],v[5],v[6],v[7],v[8]);
}
static bool source_intact(void) {
    gchar *bytes=NULL; gsize size=0;
    bool ok=g_file_get_contents(guest_path,&bytes,&size,NULL) && size==elf_size && !memcmp(bytes,elf_bytes,size);
    g_free(bytes); return ok;
}
static void complete(bool success,const char *reason) {
    if(finished) return;
    finished=true;
    if(!events || !events_hash) return;
    if(success && (!source_intact() || cpus!=1 || visited!=stop_index+1U || !boundary ||
                   pending_syscall || post_pending || syscall_count!=syscall_returns)) {
        success=false; reason="incomplete_or_changed_source";
    }
    GChecksum *copy=g_checksum_copy(events_hash); gchar *prefix=g_strdup(g_checksum_get_string(copy));
    g_checksum_free(copy);
    gchar *selector=selector_json();
    gchar *footer=g_strdup_printf("{\"kind\":\"footer\",\"success\":%s,\"reason\":\"%s\",\"run_id\":\"%s\","
        "\"instructions\":%" PRIu64 ",\"stores\":%" PRIu64 ",\"syscall_count\":%" PRIu64 ",\"syscall_returns\":%" PRIu64 ","
        "\"entries\":%u,\"stop_pc\":%u,\"boundary_reached\":%s,\"target_instruction_executed\":false,"
        "\"executed_pc_sha256\":\"%s\",\"executed_fetch_sha256\":\"%s\",\"events_bytes_before_footer\":%" PRIu64 ","
        "\"events_sha256_before_footer\":\"%s\"%s}\n",success?"true":"false",reason,run_id,instructions,stores,
        syscall_count,syscall_returns,visited,stop_pc,boundary?"true":"false",g_checksum_get_string(path_hash),
        g_checksum_get_string(fetch_hash),event_bytes,prefix,selector);
    g_free(prefix);
    bool durable=footer && write_line(footer,true) && !fflush(events) && !fsync(fileno(events));
    g_free(footer);
    if(!durable) { g_free(selector);fclose(events); events=NULL; return; }
    FILE *report=fopen(report_path,"wx");
    if(!report) { g_free(selector);fclose(events); events=NULL; return; }
    int count=fprintf(report,"{\"schema_version\":%u,\"capture_kind\":\"BOUNDED_LAYER_PREFIX_V%u\",\"success\":%s,"
        "\"reason\":\"%s\",\"run_id\":\"%s\",\"initial_pc\":%u,\"stop_pc\":%u,\"elf_sha256\":\"%s\","
        "\"instructions\":%" PRIu64 ",\"stores\":%" PRIu64 ",\"syscall_count\":%" PRIu64 ",\"syscall_returns\":%" PRIu64 ","
        "\"entries\":%u,\"cpus\":%u,\"events_bytes\":%" PRIu64 ",\"events_sha256\":\"%s\","
        "\"executed_pc_sha256\":\"%s\",\"executed_fetch_sha256\":\"%s\",\"target_instruction_executed\":false,"
        "\"guest_permissions_independently_observed\":false,\"independent_OS_entry_origins_proven\":false,"
        "\"kernel_implementation_verified\":false,\"oep_proven\":false%s}\n",selector_version,selector_version,success?"true":"false",reason,run_id,
        initial_pc,stop_pc,elf_sha,instructions,stores,syscall_count,syscall_returns,visited,cpus,event_bytes,
        g_checksum_get_string(events_hash),g_checksum_get_string(path_hash),g_checksum_get_string(fetch_hash),selector);
    g_free(selector);
    bool ok=count>0 && !fflush(report) && !fsync(fileno(report));
    if(fclose(report)) ok=false;
    if(fclose(events)) ok=false;
    events=NULL;
    if(!ok) _Exit(1);
}

static bool parse_elf(void) {
    struct stat state;
    if(lstat(guest_path,&state) || !S_ISREG(state.st_mode) || state.st_size<=0 ||
       state.st_size>MAX_IMAGE || !g_file_get_contents(guest_path,&elf_bytes,&elf_size,NULL)) return false;
    const uint8_t *e=(const uint8_t *)elf_bytes;
    if(elf_size<52 || memcmp(e,"\177ELF\1\1\1",7) || u16(e+16)!=ET_EXEC || u16(e+18)!=EM_386 ||
       u32(e+20)!=1 || u16(e+40)!=52 || u16(e+42)!=32) return false;
    initial_pc=u32(e+24); uint32_t phoff=u32(e+28); unsigned count=u16(e+44); uint64_t total=0;
    if(!count || count>MAX_LOADS || phoff<52 || (uint64_t)phoff+32U*count>elf_size) return false;
    for(unsigned i=0;i<count;++i) {
        const uint8_t *h=e+phoff+32U*i; uint32_t kind=u32(h);
        if(kind==PT_INTERP || kind==PT_DYNAMIC || kind==PT_TLS) return false;
        if(kind==PT_GNU_STACK)stack_prot=3|((u32(h+24)&PF_X)?4U:0U);
        if(kind!=PT_LOAD) continue;
        Load r={.address=u32(h+8),.offset=u32(h+4),.filesz=u32(h+16),.memsz=u32(h+20)};
        uint32_t flags=u32(h+24),align=u32(h+28);
        if(r.address<0x10000 || !r.memsz || r.filesz>r.memsz || (uint64_t)r.offset+r.filesz>elf_size ||
           (uint64_t)r.address+r.memsz>(UINT64_C(1)<<32) || flags>7 || r.address%PAGE!=r.offset%PAGE ||
           (align>1 && ((align&(align-1)) || r.address%align!=r.offset%align))) return false;
        r.start=r.address&~UINT32_C(4095);
        uint64_t end=rounded((uint64_t)r.address+r.memsz),length=end-r.start;
        if(!length || length>MAX_IMAGE || (total+=length)>MAX_IMAGE) return false;
        r.size=(uint32_t)length; r.prot=((flags&PF_R)?1U:0U)|((flags&PF_W)?2U:0U)|((flags&PF_X)?4U:0U);
        for(unsigned j=0;j<load_count;++j)
            if(r.start<(uint64_t)loads[j].start+loads[j].size && loads[j].start<end) return false;
        for(uint64_t page=r.start>>12;page<end>>12;++page) {
            page_permissions[page]=(uint8_t)r.prot;page_mapped[page]=true;page_initial[page]=true;
        }
        loads[load_count++]=r;
    }
    bool executable=false;
    for(unsigned i=0;i<load_count;++i)
        if((loads[i].prot&5U)==5U && initial_pc>=loads[i].start &&
           initial_pc<(uint64_t)loads[i].start+loads[i].size) executable=true;
    elf_sha=g_compute_checksum_for_data(G_CHECKSUM_SHA256,e,elf_size);
    return executable;
}
static bool unsigned_token(const char **cursor,unsigned base,uint64_t maximum,uint64_t *value) {
    const char *text=*cursor;while(g_ascii_isspace(*text))++text;
    if((base==16?!g_ascii_isxdigit(*text):!g_ascii_isdigit(*text)))return false;
    char *end=NULL;errno=0;uint64_t parsed=strtoull(text,&end,base);
    if(errno||end==text||parsed>maximum||(*end&&!g_ascii_isspace(*end)))return false;
    *cursor=end;*value=parsed;return true;
}
static bool parse_stage_exact(const char *text,Stage *s) {
    uint64_t pc,size,previous,ordinal,generation,epoch=0;
    if(!unsigned_token(&text,16,UINT32_MAX,&pc)||!unsigned_token(&text,10,PAGE,&size)||
       !unsigned_token(&text,16,UINT32_MAX,&previous)||!unsigned_token(&text,10,MAX_STEPS+1,&ordinal)||
       !unsigned_token(&text,10,MAX_STEPS,&generation)||
       (selector_version>=3&&!unsigned_token(&text,10,selector_version>=5?256:32,&epoch)))return false;
    while(g_ascii_isspace(*text))++text;
    if(*text)return false;
    *s=(Stage){.pc=(uint32_t)pc,.size=(uint32_t)size,.predecessor=(uint32_t)previous,
        .ordinal=ordinal,.generation=(uint32_t)generation,.mapping_epoch=(uint32_t)epoch};return true;
}
static bool parse_stages(const char *path) {
    FILE *input=fopen(path,"r"); if(!input) return false;
    char text[160]; bool ok=true,found=false;
    while(fgets(text,sizeof text,input)) {
        if(!stage_count&&(!strcmp(text,"TFLAYERSTAGES2\n")||!strcmp(text,"TFLAYERSTAGES3\n")||!strcmp(text,"TFLAYERSTAGES4\n")||!strcmp(text,"TFLAYERSTAGES5\n")||!strcmp(text,"TFLAYERSTAGES6\n")||!strcmp(text,"TFLAYERSTAGES7\n"))) {
            if(selector_version!=1){ok=false;break;}
            selector_version=(unsigned)(text[13]-'0');continue;
        }
        Stage s={0}; char extra;
        if(!strchr(text,'\n') || stage_count==MAX_STAGES ||
           (selector_version==1?sscanf(text,"%" SCNx32 " %" SCNu32 " %" SCNx32 " %c",&s.pc,&s.size,&s.predecessor,&extra)!=3:
               !parse_stage_exact(text,&s)) ||
           s.pc<0x10000 || !s.size || s.size>PAGE || (uint64_t)s.pc+s.size>(UINT64_C(1)<<32) ||
           (!stage_count && (s.pc!=initial_pc || s.predecessor))) { ok=false; break; }
        if(selector_version>=2) {
            if((!stage_count&&(s.ordinal!=1||s.generation||s.mapping_epoch))||
               (stage_count&&(s.ordinal<=stages[stage_count-1].ordinal||!s.generation)))ok=false;
        }
        for(unsigned i=0;i<stage_count;++i)if(stages[i].pc==s.pc&&
            (selector_version==1||stages[i].generation>=s.generation||
             (selector_version>=3&&stages[i].mapping_epoch>s.mapping_epoch)))ok=false;
        if(!ok) break;
        if(selector_version==1&&s.pc==stop_pc) {
            if(!stage_count) { ok=false; break; }
            found=true; stop_index=stage_count;
        }
        stages[stage_count++]=s;
    }
    if(ferror(input)) ok=false;
    fclose(input);
    if(selector_version>=2)found=stop_index_supplied&&stop_index>0&&stop_index<stage_count&&stages[stop_index].pc==stop_pc;
    else if(stop_index_supplied)ok=false;
    return ok && found && stage_count>=2;
}
static void initialize(const Insn *insn) {
    if(insn->pc!=initial_pc || !source_intact()) reject("original_entry_identity");
    registers(current_registers);
    uint32_t esp=current_registers[4],df=(current_registers[8]>>10)&1U;
    if(df || (esp&~UINT32_C(4095))<PAGE || (uint64_t)(esp&~UINT32_C(4095))+PAGE>(UINT64_C(1)<<32))
        reject("initial_stack_or_DF");
    uint32_t base=(esp&~UINT32_C(4095))-PAGE; uint8_t stack[2U*PAGE];
    if(selector_version>=3)for(uint64_t page=base>>12;page<((uint64_t)base+2U*PAGE)>>12;++page) {
        if(page_mapped[page])reject("initial_stack_overlap");
        page_mapped[page]=true;page_initial[page]=true;page_permissions[page]=(uint8_t)stack_prot;
    }
    if(!read_guest(base,stack,sizeof stack)) reject("initial_stack_snapshot");
    gchar *encoded=hex(stack,sizeof stack),*regs=register_json(current_registers);
    record("{\"kind\":\"initial\",\"pc\":%u,\"registers\":%s,\"esp\":%u,\"df\":%u,"
           "\"stack_base\":%u,\"stack_size\":%zu,\"stack_hex\":\"%s\"}\n",initial_pc,regs,esp,df,base,sizeof stack,encoded);
    g_free(encoded);g_free(regs);
    for(unsigned i=0;i<load_count;++i) {
        Load r=loads[i]; uint8_t *wanted=g_malloc0(r.size),*observed=g_malloc(r.size);
        if(r.filesz) {
            uint64_t file_low=r.offset&~UINT32_C(4095),copy=rounded((uint64_t)r.address+r.filesz)-r.start;
            if(copy>elf_size-file_low) copy=elf_size-file_low;
            memcpy(wanted,elf_bytes+file_low,(size_t)copy);
        }
        if(r.memsz>r.filesz) {
            uint64_t begin=(uint64_t)r.address+r.filesz-r.start;
            memset(wanted+begin,0,r.size-(size_t)begin);
        }
        if(!read_guest(r.start,observed,r.size) || memcmp(wanted,observed,r.size)) reject("source_loader_bytes_mismatch");
        gchar *bytes=hex(observed,r.size),*sha=g_compute_checksum_for_data(G_CHECKSUM_SHA256,observed,r.size);
        record("{\"kind\":\"initial_load\",\"address\":%u,\"size\":%u,\"prot\":%u,\"bytes_hex\":\"%s\",\"sha256\":\"%s\"}\n",
               r.start,r.size,r.prot,bytes,sha);
        g_free(wanted);g_free(observed);g_free(bytes);g_free(sha);
    }
    initialized=true;
}
static bool preceding_jump(uint32_t destination,const uint32_t regs[9]) {
    if(!current) return false;
    if(current->size==5 && current->bytes[0]==0xe9)
        return (uint32_t)(current->pc+5U+u32(current->bytes+1))==destination;
    if(current->size==2 && current->bytes[0]==0xeb)
        return (uint32_t)(current->pc+2U+(int8_t)current->bytes[1])==destination;
    return current->size==2 && current->bytes[0]==0xff && (current->bytes[1]&0xf8U)==0xe0U &&
           regs[current->bytes[1]&7U]==destination;
}
static void observe_stage(const Insn *insn,const uint32_t regs[9]) {
    for(unsigned i=0;i<stage_count;++i) {
        Stage s=stages[i];
        if(selector_version>=2) {
            if(i!=visited)continue;
            if(instructions+1<s.ordinal) {
                if(s.pc==insn->pc&&page_generation[s.pc>>12]==s.generation&&
                   (selector_version<3||page_mapping_epoch[s.pc>>12]==s.mapping_epoch))
                    reject("early_stage_occurrence");
                continue;
            }
            if(instructions+1!=s.ordinal||s.pc!=insn->pc||page_generation[s.pc>>12]!=s.generation||
               (selector_version>=3&&(!page_mapped[s.pc>>12]||page_mapping_epoch[s.pc>>12]!=s.mapping_epoch)))
                reject("stage_PC_occurrence_or_generation");
        }else if(s.pc!=insn->pc)continue;
        if(i!=visited || (i && (!current || current->pc!=s.predecessor || !preceding_jump(s.pc,regs))))
            reject("stage_occurrence_or_transfer");
        uint8_t bytes[PAGE]; if(!read_guest(s.pc,bytes,s.size)) reject("stage_current_bytes");
        gchar *encoded=hex(bytes,s.size),*sha=g_compute_checksum_for_data(G_CHECKSUM_SHA256,bytes,s.size);
        gchar *previous=current?hex(current->bytes,current->size):g_strdup("");
        gchar *actual=hex(insn->bytes,insn->size),*registers_json=register_json(regs),*epoch=epoch_json(s.pc);
        record("{\"kind\":\"stage\",\"index\":%u,\"pc\":%u,\"size\":%u,\"bytes_hex\":\"%s\",\"sha256\":\"%s\","
               "\"instruction_size\":%u,\"instruction_bytes_hex\":\"%s\",\"seq\":%" PRIu64 ",\"instruction_ordinal\":%" PRIu64
               ",\"page_generation\":%u,\"predecessor_pc\":%u,\"predecessor_bytes_hex\":\"%s\","
               "\"predecessor_step\":%" PRIu64 ",\"registers\":%s%s}\n",i,s.pc,s.size,encoded,sha,insn->size,actual,
               instructions+1U,instructions+1U,page_generation[s.pc>>12],current?current->pc:0,previous,instructions,registers_json,epoch);
        g_free(encoded);g_free(sha);g_free(previous);g_free(actual);g_free(registers_json);g_free(epoch);++visited;
        if(selector_version>=2)break;
    }
}
static void execute(unsigned cpu,void *opaque) {
    Insn *insn=opaque;
    if(cpu || cpus!=1 || !insn || pending_syscall) reject("instruction_context");
    if(!initialized) initialize(insn);
    bool int80=insn->size==2 && insn->bytes[0]==0xcd && insn->bytes[1]==0x80,stage=false;
    for(unsigned i=0;i<stage_count;++i) stage|=stages[i].pc==insn->pc;
    uint32_t now[9]={0}; if(post_pending || int80 || stage) registers(now);
    if(post_pending) {
        if(!current || insn->pc!=pending_pc+2U || now[0]!=post_result) reject("syscall_post_identity");
        for(unsigned i=1;i<9;++i) if(now[i]!=current_registers[i]) reject("syscall_preserved_state");
        gchar *regs=register_json(now);
        gchar *effect=selector_version>=3?g_strdup_printf(",\"mapping_effect\":%s",pending_mapping_effect):g_strdup("");
        gchar *file=selector_version>=4?g_strdup_printf(",\"file_mapping\":%s,\"file_descriptor\":%s",
            pending_file_mapping?pending_file_mapping:"null",pending_file_descriptor?pending_file_descriptor:"null"):g_strdup("");
        gchar *mutation=selector_version>=5?g_strdup_printf(",\"file_mutation\":%s",
            pending_file_mutation?pending_file_mutation:"null"):g_strdup("");
        record("{\"kind\":\"syscall_post\",\"ordinal\":%" PRIu64 ",\"pc\":%u,\"number\":%u,\"registers\":%s%s%s%s}\n",
               pending_ordinal,insn->pc,pending_number,regs,effect,file,mutation);
        g_free(effect);g_free(file);g_free(mutation);g_clear_pointer(&pending_mapping_effect,g_free);
        g_clear_pointer(&pending_file_mapping,g_free);g_clear_pointer(&pending_file_descriptor,g_free);
        g_clear_pointer(&pending_file_mutation,g_free);g_clear_pointer(&pending_write_bytes,g_free);
        g_clear_pointer(&pending_name,g_free);g_free(regs);post_pending=false;
    }
    uint8_t actual[15];
    if(selector_version>=3)for(uint64_t page=insn->pc>>12;page<=((uint64_t)insn->pc+insn->size-1U)>>12;++page)
        if(!page_mapped[page]||(page_permissions[page]&5U)!=5U||
           page_mapping_epoch[page]!=page_mapping_epoch[insn->pc>>12])reject("instruction_mapping_or_permissions");
    if(!read_guest(insn->pc,actual,insn->size) || memcmp(actual,insn->bytes,insn->size)) reject("current_instruction_identity");
    if(stage||selector_version>=2)observe_stage(insn,now);
    if(selector_version==1?insn->pc==stop_pc:instructions+1==stages[stop_index].ordinal) {
        if(!current || !instructions || visited!=stop_index+1U || !preceding_jump(stop_pc,now)) reject("stop_boundary");
        uint32_t address=stop_pc&~UINT32_C(4095),prot=page_permissions[stop_pc>>12]; uint8_t bytes[PAGE];
        if((prot&5U)!=5U || !read_guest(address,bytes,sizeof bytes)) reject("target_page_snapshot_or_contract");
        gchar *encoded=hex(bytes,sizeof bytes),*sha=g_compute_checksum_for_data(G_CHECKSUM_SHA256,bytes,sizeof bytes),*epoch=epoch_json(address);
        record("{\"kind\":\"target_page\",\"address\":%u,\"size\":%u,\"prot\":%u,\"bytes_hex\":\"%s\","
               "\"sha256\":\"%s\",\"page_generation\":%u%s}\n",address,PAGE,prot,encoded,sha,page_generation[address>>12],epoch);
        g_free(encoded);g_free(sha);g_free(epoch);boundary=true;
        complete(true,"selected_stage_boundary");_Exit(0);
    }
    if(instructions>=MAX_STEPS) reject("instruction_budget");
    ++instructions;
    uint8_t code[5]; for(unsigned i=0;i<4;++i) code[i]=(uint8_t)(insn->pc>>(8U*i)); code[4]=insn->size;
    g_checksum_update(path_hash,code,4);g_checksum_update(fetch_hash,code,5);g_checksum_update(fetch_hash,actual,insn->size);
    current=insn; if(int80) memcpy(current_registers,now,sizeof now);
}
static void memory_write(unsigned cpu,qemu_plugin_meminfo_t info,uint64_t address,void *opaque) {
    Insn *writer=opaque; unsigned shift=qemu_plugin_mem_size_shift(info);
    if(cpu || !initialized || !current || writer!=current || !instructions || shift>4 || stores>=MAX_STEPS)
        reject("store_context_or_budget");
    uint32_t size=1U<<shift;
    if(address>UINT32_MAX || size>(UINT64_C(1)<<32)-address) reject("store_range");
    uint32_t epoch=page_mapping_epoch[address>>12];
    if(selector_version>=3) {
        if(!page_mapped[current->pc>>12]||(page_permissions[current->pc>>12]&5U)!=5U)reject("store_writer_mapping");
        for(uint64_t page=address>>12;page<=(address+size-1U)>>12;++page)
            if(!page_mapped[page]||!(page_permissions[page]&2U)||page_mapping_epoch[page]!=epoch)
                reject("store_mapping_or_lifetime");
    }
    ++stores;
    for(uint64_t page=address>>12;page<=(address+size-1U)>>12;++page) page_generation[page]=(uint32_t)stores;
    gchar *shared=selector_version>=6?shared_store_observation((uint32_t)address,size):g_strdup("");
    gchar *identity=selector_version>=3?g_strdup_printf(",\"mapping_epoch\":%u,\"writer_mapping_epoch\":%u",
        epoch,page_mapping_epoch[current->pc>>12]):g_strdup("");
    record("{\"kind\":\"store\",\"step\":%" PRIu64 ",\"pc\":%u,\"address\":%" PRIu64
           ",\"size\":%u,\"store_ordinal\":%" PRIu64 "%s%s}\n",instructions,current->pc,address,size,stores,identity,shared);
    g_free(identity);g_free(shared);
}
static void translate(qemu_plugin_id_t id,struct qemu_plugin_tb *tb) {
    (void)id;
    for(size_t i=0;i<qemu_plugin_tb_n_insns(tb);++i) {
        if(++contexts>MAX_CONTEXTS) reject("translation_budget");
        struct qemu_plugin_insn *guest=qemu_plugin_tb_get_insn(tb,i);
        uint64_t pc=qemu_plugin_insn_vaddr(guest);size_t size=qemu_plugin_insn_size(guest);
        if(pc>UINT32_MAX || !size || size>15 || size>(UINT64_C(1)<<32)-pc) reject("translated_instruction_extent");
        Insn *insn=g_new0(Insn,1);insn->pc=(uint32_t)pc;insn->size=(uint8_t)size;
        if(qemu_plugin_insn_data(guest,insn->bytes,size)!=size) reject("translated_instruction_bytes");
        qemu_plugin_register_vcpu_insn_exec_cb(guest,execute,QEMU_PLUGIN_CB_R_REGS,insn);
        qemu_plugin_register_vcpu_mem_cb(guest,memory_write,QEMU_PLUGIN_CB_NO_REGS,QEMU_PLUGIN_MEM_W,insn);
    }
}
static void cpu_init(qemu_plugin_id_t id,unsigned cpu) {
    (void)id;
    if(cpu || cpus++) reject("multiple_vcpus");
    GArray *regs=qemu_plugin_get_registers();if(!regs) reject("register_catalogue");
    for(guint i=0;i<regs->len;++i) {
        qemu_plugin_reg_descriptor *d=&g_array_index(regs,qemu_plugin_reg_descriptor,i);
        for(unsigned j=0;j<9;++j) if(d->name && !g_ascii_strcasecmp(d->name,names[j])) {
            if(handle_present[j]) reject("duplicate_register");
            handles[j]=d->handle;handle_present[j]=true;
        }
    }
    g_array_free(regs,TRUE);
    for(unsigned j=0;j<9;++j) if(!handle_present[j]) reject("missing_register");
}
/* V3 is a deliberately narrow mapping profile.  Successful effects are derived
 * from the admitted syscall result, never from a captured postimage.  The
 * observer checks the anonymous-zero constructor independently of guest STOREs.
 * Only preflight EINVAL failures known not to modify mappings are admitted. */
static gchar *source_open_path(void) {
    static const uint8_t wanted[]="/proc/self/exe";
    uint64_t address=pending_args[0];
    if(address+sizeof wanted>(UINT64_C(1)<<32))reject("source_open_path_extent");
    for(uint64_t page=address>>12;page<=(address+sizeof wanted-1U)>>12;++page)
        if(!page_mapped[page]||!(page_permissions[page]&1U))reject("source_open_path_mapping");
    uint8_t bytes[sizeof wanted];
    if(!read_guest(address,bytes,sizeof bytes)||memcmp(bytes,wanted,sizeof wanted))
        reject("unsupported_source_open_path");
    return hex(bytes,sizeof bytes);
}
static void readable_extent(uint32_t address,uint32_t size,const char *reason) {
    if(size>MAX_IMAGE||(uint64_t)address+size>(UINT64_C(1)<<32))reject(reason);
    if(!size)return;
    for(uint64_t p=address>>12;p<=((uint64_t)address+size-1U)>>12;++p)
        if(!page_mapped[p]||!(page_permissions[p]&1U))reject(reason);
}
static gchar *memfd_name(void) {
    uint8_t bytes[64];
    for(unsigned i=0;i<sizeof bytes;++i) {
        if((uint64_t)pending_args[0]+i>UINT32_MAX)reject("memfd_name_extent");
        uint32_t a=pending_args[0]+i;readable_extent(a,1,"memfd_name_mapping");
        if(!read_guest(a,bytes+i,1))reject("memfd_name_snapshot");
        if(!bytes[i])return hex(bytes,i+1U);
    }
    reject("memfd_name_unterminated");return NULL;
}
static unsigned mutable_descriptor(uint32_t fd) {
    if(fd<3||fd>=64||!descriptor_epochs[fd]||!descriptor_file_ids[fd]||
       descriptor_file_ids[fd]>=next_file_id)reject("mutable_descriptor_identity");
    return descriptor_file_ids[fd];
}
static bool live_file_mapping(unsigned file) {
    for(unsigned p=0;p<(1U<<20);++p)
        if(page_mapped[p]&&page_backing_tokens[p]==file+1U)return true;
    return false;
}
static bool live_private_file_mapping(unsigned file) {
    for(unsigned i=0;i<file_page_count;++i) {
        unsigned p=file_page_indices[i];
        if(page_mapped[p]&&page_backing_tokens[p]==file+1U&&!page_backing_shared[p])return true;
    }
    return false;
}
static uint32_t file_page_generation(unsigned file,uint32_t offset) {
    ObservedFile *f=mutable_files+file;uint32_t result=0;
    if(!f->store_generations||offset>=f->capacity)return 0;
    uint32_t end=offset+PAGE;if(end>f->capacity)end=f->capacity;
    for(uint32_t i=offset;i<end;++i)if(f->store_generations[i]>result)result=f->store_generations[i];
    return result;
}
/* Observed alias bytes are checked, never used as replay source leaves.  The
 * native model independently derives the same file bytes from guest STOREs. */
static void refresh_shared_aliases(unsigned file,uint32_t first,uint32_t size) {
    ObservedFile *f=mutable_files+file;
    for(unsigned i=0;i<file_page_count;++i) {
        unsigned p=file_page_indices[i];
        if(!page_mapped[p]||page_backing_tokens[p]!=file+1U||!page_backing_shared[p])continue;
        uint32_t off=page_backing_offsets[p];
        if(off>=(uint64_t)first+size||(uint64_t)off+PAGE<=first)continue;
        page_generation[p]=file_page_generation(file,off);
        uint32_t low=off>first?off:first,high=off+PAGE;
        if(high>(uint64_t)first+size)high=first+size;
        uint8_t actual[PAGE];
        if(!read_guest(((uint64_t)p<<12)+(low-off),actual,high-low)||
           memcmp(actual,f->bytes+low,high-low))reject("shared_alias_bytes_mismatch");
    }
}
static gchar *shared_store_observation(uint32_t address,uint32_t size) {
    if(!size||(uint64_t)address+size>(UINT64_C(1)<<32))reject("shared_store_extent");
    unsigned page=address>>12;
    if(!page_backing_shared[page]) {
        for(uint64_t p=page+1U;p<=((uint64_t)address+size-1U)>>12;++p)
            if(page_backing_shared[p])reject("shared_store_mapping_geometry");
        return g_strdup(",\"shared_file_write\":null");
    }
    unsigned token=page_backing_tokens[page];
    if(token<2||token>next_file_id)reject("shared_store_file_identity");
    unsigned file=token-1;ObservedFile *f=mutable_files+file;
    uint32_t offset=page_backing_offsets[page]+(address&4095U);
    uint64_t extent=selector_version>=7?rounded(f->size):f->size;
    if(!size||(uint64_t)offset+size>extent||!f->store_generations||live_private_file_mapping(file))
        reject("shared_store_private_alias_or_EOF");
    for(uint64_t p=page;p<=((uint64_t)address+size-1U)>>12;++p)
        if(!page_backing_shared[p]||page_backing_tokens[p]!=token||
           page_backing_offsets[p]!=page_backing_offsets[page]+(p-page)*PAGE)
            reject("shared_store_mapping_geometry");
    if(!read_guest(address,f->bytes+offset,size))reject("shared_store_bytes");
    if(selector_version>=7&&(uint64_t)offset+size>f->size)f->tail_dirty=true;
    for(uint32_t i=0;i<size;++i)f->store_generations[offset+i]=(uint32_t)stores;
    refresh_shared_aliases(file,offset,size);
    gchar *data=hex(f->bytes+offset,size),*result=g_strdup_printf(
        ",\"shared_file_write\":{\"file_id\":%u,\"file_offset\":%u,\"data_hex\":\"%s\"}",file,offset,data);
    g_free(data);return result;
}
static void mutable_capacity(ObservedFile *file,uint32_t size) {
    uint64_t capacity=rounded(size);
    if(size>MAX_IMAGE||capacity>MAX_IMAGE)reject("mutable_file_capacity_budget");
    if(capacity>file->capacity) {
        file->bytes=g_realloc(file->bytes,(gsize)capacity);
        memset(file->bytes+file->capacity,0,(size_t)capacity-file->capacity);
        if(selector_version>=6) {
            file->store_generations=g_realloc_n(file->store_generations,(gsize)capacity,sizeof(uint32_t));
            memset(file->store_generations+file->capacity,0,((size_t)capacity-file->capacity)*sizeof(uint32_t));
        }
        file->capacity=(uint32_t)capacity;
    }
}
static gchar *file_descriptor_effect(const char *operation,uint32_t fd,unsigned file,uint32_t epoch) {
    uint32_t size=file?mutable_files[file].size:(uint32_t)elf_size;
    gchar *source=file?g_strdup("null"):g_strdup_printf("\"%s\"",elf_sha);
    gchar *effect=g_strdup_printf("{\"operation\":\"%s\",\"fd\":%u,\"file_id\":%u,"
        "\"descriptor_epoch\":%u,\"file_size\":%u,\"source_sha256\":%s}",
        operation,fd,file,epoch,size,source);
    g_free(source);return effect;
}
static gchar *mapping_effect(const char *operation,uint32_t address,uint32_t size,
                             uint32_t prot,uint32_t epoch,const char *zero_hash);
static void mutable_return(uint32_t result) {
    pending_mapping_effect=mapping_effect("none",0,0,0,0,NULL);
    if(result>=UINT32_C(0xfffff001))reject("mutable_file_failed_contract");
    if(pending_number==356) {
        if(result<3||result>=64||descriptor_epochs[result]||next_file_id>=32)
            reject("memfd_create_descriptor_identity");
        unsigned file=next_file_id++;mutable_files[file].content_epoch=(uint32_t)pending_ordinal;
        descriptor_epochs[result]=(uint32_t)pending_ordinal;descriptor_file_ids[result]=file;
        descriptor_offsets[result]=0;
        pending_file_descriptor=file_descriptor_effect("memfd_create",result,file,(uint32_t)pending_ordinal);
        return;
    }
    uint32_t fd=pending_args[0];unsigned id=mutable_descriptor(fd);ObservedFile *file=mutable_files+id;
    uint32_t old_size=file->size,before=descriptor_offsets[fd],zero_start=0,zero_end=0;
    uint32_t write_address=0,write_count=0;gchar *write_hash=NULL;const char *operation;
    if(pending_number==4) {
        if(selector_version>=6?live_private_file_mapping(id):live_file_mapping(id))reject("write_with_live_private_mapping");
        if(result>pending_args[2]||(uint64_t)before+result>MAX_IMAGE)reject("mutable_write_result");
        if(selector_version>=7&&result&&(uint64_t)before+result>file->size&&
           (file->tail_dirty||live_file_mapping(id)))reject("write_growth_with_cached_tail_or_live_mapping");
        write_address=pending_args[1];write_count=result;
        write_hash=g_compute_checksum_for_data(G_CHECKSUM_SHA256,pending_write_bytes,result);
        if(result) {
            uint32_t size=before+result;if(size<file->size)size=file->size;
            mutable_capacity(file,size);
            if(before>file->size){zero_start=file->size;zero_end=before;memset(file->bytes+zero_start,0,zero_end-zero_start);}
            memcpy(file->bytes+before,pending_write_bytes,result);file->size=size;
            if(selector_version>=6) {
                /* Only guest STOREs provide causal ownership. Kernel writes
                 * replace bytes and therefore retract that ownership. */
                memset(file->store_generations+before,0,result*sizeof(uint32_t));
                refresh_shared_aliases(id,before,result);
            }
            descriptor_offsets[fd]=before+result;file->content_epoch=(uint32_t)pending_ordinal;
        }
        operation="write";
    }else if(pending_number==93) {
        if(selector_version>=7&&file->tail_dirty)reject("truncate_after_cached_tail_store");
        if(live_file_mapping(id))reject("truncate_with_live_private_mapping");
        if(result||pending_args[1]>MAX_IMAGE)reject("mutable_truncate_result");
        uint32_t size=pending_args[1];mutable_capacity(file,size);
        if(size!=file->size) {
            uint32_t first=size<file->size?size:file->size;
            if(file->capacity>first)memset(file->bytes+first,0,file->capacity-first);
            if(selector_version>=6&&file->capacity>first)
                memset(file->store_generations+first,0,(file->capacity-first)*sizeof(uint32_t));
            if(size>file->size){zero_start=file->size;zero_end=size;}
            file->size=size;file->content_epoch=(uint32_t)pending_ordinal;
        }
        operation="truncate";
    }else {
        if(pending_number!=19||pending_args[2]||pending_args[1]>MAX_IMAGE||result!=pending_args[1])
            reject("mutable_seek_result");
        descriptor_offsets[fd]=result;operation="seek";
    }
    gchar *hash=write_hash?g_strdup_printf("\"%s\"",write_hash):g_strdup("null");
    pending_file_mutation=g_strdup_printf("{\"operation\":\"%s\",\"fd\":%u,\"file_id\":%u,"
        "\"descriptor_epoch\":%u,\"content_epoch\":%u,\"old_size\":%u,\"new_size\":%u,"
        "\"offset_before\":%u,\"offset_after\":%u,\"write_address\":%u,\"write_count\":%u,"
        "\"zero_start\":%u,\"zero_end\":%u,\"write_sha256\":%s}",operation,fd,id,descriptor_epochs[fd],
        file->content_epoch,old_size,file->size,before,descriptor_offsets[fd],write_address,write_count,
        zero_start,zero_end,hash);
    g_free(hash);g_free(write_hash);
}
/* V7 admits only synchronous no-data-mutation contracts over readable local
 * shared cache pages. Actual post-syscall bytes must still match the shadow;
 * this check supplies no replay source bytes or new constructor leaf. */
static void sync_arguments(void) {
    uint32_t address=pending_args[0],size=pending_args[1];
    uint64_t end=(uint64_t)address+rounded(size);
    if(selector_version<7||pending_args[2]!=4||address<0x10000||address%PAGE||
       !size||size>MAX_IMAGE||end>(UINT64_C(1)<<32))reject("unsupported_memfd_sync_profile");
    for(uint64_t p=address>>12;p<end>>12;++p) {
        unsigned token=page_backing_tokens[p];
        if(!page_mapped[p]||!(page_permissions[p]&1U)||!page_backing_shared[p]||
           token<2||token>next_file_id)reject("sync_requires_local_shared_mapping");
        ObservedFile *file=mutable_files+token-1;
        if(page_backing_offsets[p]%PAGE||
           (uint64_t)page_backing_offsets[p]+PAGE>rounded(file->size))
            reject("sync_beyond_current_cache_extent");
    }
}
static void sync_return(uint32_t result) {
    sync_arguments();
    if(result)reject("unsupported_memfd_sync_result");
    uint64_t end=(uint64_t)pending_args[0]+rounded(pending_args[1]);
    for(uint64_t p=pending_args[0]>>12;p<end>>12;++p) {
        unsigned file=page_backing_tokens[p]-1;
        uint8_t actual[PAGE];
        if(!read_guest(p<<12,actual,PAGE)||
           memcmp(actual,mutable_files[file].bytes+page_backing_offsets[p],PAGE))
            reject("memfd_sync_cache_bytes_mismatch");
    }
    pending_mapping_effect=mapping_effect("none",0,0,0,0,NULL);
}
static void mapping_arguments(void) {
    if(pending_number==144) { sync_arguments();return; }
    if(selector_version>=5&&(pending_number==356||pending_number==4||pending_number==93||pending_number==19)) {
        if(pending_number==356) {
            if((pending_args[1]>1&&(selector_version<6||(pending_args[1]!=16&&pending_args[1]!=17)))||!pending_name)
                reject("unsupported_memfd_create_flags_or_name");
        }else {
            unsigned file=mutable_descriptor(pending_args[0]);
            if(selector_version>=7&&pending_number==93&&mutable_files[file].tail_dirty)
                reject("truncate_after_cached_tail_store");
            if((pending_number==93&&live_file_mapping(file))||
               (pending_number==4&&(selector_version>=6?live_private_file_mapping(file):live_file_mapping(file))))
                reject("mutation_with_live_private_mapping");
            if(pending_number==4) {
                readable_extent(pending_args[1],pending_args[2],"mutable_write_buffer_mapping");
            }else if(pending_args[1]>MAX_IMAGE||(pending_number==19&&pending_args[2]))
                reject("unsupported_mutable_file_geometry");
        }
        return;
    }
    if(selector_version>=4&&(pending_number==5||pending_number==6)) {
        if(pending_number==5&&pending_args[1])reject("unsupported_source_open_flags");
        if(pending_number==6&&(pending_args[0]<3||pending_args[0]>=64||!descriptor_epochs[pending_args[0]]))
            reject("close_untracked_source_descriptor");
        return;
    }
    if(pending_number==90||pending_number==192) {
        uint32_t *a=pending_mmap_args;
        if(a[1]>MAX_IMAGE||a[2]>7||!(a[2]&1U))reject("unsupported_mapping_profile");
        if(a[3]&32U) {
            if((a[3]!=0x22&&a[3]!=0x32)||a[4]!=UINT32_MAX||a[5])
                reject("unsupported_anonymous_mapping_profile");
        }else {
            bool shared=selector_version>=6&&(a[3]==1||a[3]==0x11);
            if(selector_version<4||(!shared&&a[3]!=2&&a[3]!=0x12)||a[4]<3||a[4]>=64||!descriptor_epochs[a[4]]||
               (shared&&!descriptor_file_ids[a[4]]))
                reject("unsupported_private_source_mapping_profile");
            /* Keep an unaligned old-mmap offset available to the explicit
             * preflight EINVAL branch. Successful mappings still require
             * this byte offset to be page-aligned. */
            uint64_t offset=(uint64_t)a[5]*(pending_number==192?PAGE:1U);
            if(offset>MAX_IMAGE)reject("source_mapping_offset_budget");
        }
    }else if(pending_args[1]>MAX_IMAGE||(pending_number==125&&pending_args[2]>7))
        reject("unsupported_mapping_range_profile");
}
static gchar *mapping_effect(const char *operation,uint32_t address,uint32_t size,
                             uint32_t prot,uint32_t epoch,const char *zero_hash) {
    gchar *hash=zero_hash?g_strdup_printf("\"%s\"",zero_hash):g_strdup("null");
    gchar *result=g_strdup_printf("{\"operation\":\"%s\",\"address\":%u,\"size\":%u,\"prot\":%u,"
        "\"mapping_epoch\":%u,\"zero_fill_sha256\":%s}",operation,address,size,prot,epoch,hash);
    g_free(hash);return result;
}
static bool preflight_EINVAL(void) {
    if(pending_number==90||pending_number==192)
        return !pending_mmap_args[1]||((pending_mmap_args[3]&16U)&&(pending_mmap_args[0]&4095U))||
               (selector_version>=4&&!(pending_mmap_args[3]&32U)&&pending_number==90&&(pending_mmap_args[5]&4095U));
    if(pending_number==91)return !pending_args[1]||(pending_args[0]&4095U);
    return pending_number==125&&(pending_args[0]&4095U);
}
static uint64_t effect_end(uint32_t address,uint32_t length) {
    uint64_t end=(uint64_t)address+rounded(length);
    if(address<0x10000||(address&4095U)||!length||length>MAX_IMAGE||end>(UINT64_C(1)<<32))
        reject("mapping_effect_geometry");
    return end;
}
static void mapping_return(uint32_t result) {
    if(pending_number==144) { sync_return(result);return; }
    if(selector_version>=5&&(pending_number==356||pending_number==4||pending_number==93||pending_number==19)) {
        mutable_return(result);return;
    }
    if(selector_version>=4&&(pending_number==5||pending_number==6)) {
        uint32_t fd=pending_number==5?result:pending_args[0];
        if(result>=UINT32_C(0xfffff001))reject("unsupported_source_descriptor_failure");
        if(pending_number==5) {
            if(fd<3||fd>=64||descriptor_epochs[fd])reject("source_open_descriptor_identity");
            descriptor_epochs[fd]=(uint32_t)pending_ordinal;
            if(selector_version>=5){descriptor_file_ids[fd]=0;descriptor_offsets[fd]=0;}
        }else if(result||fd<3||fd>=64||!descriptor_epochs[fd])reject("source_close_descriptor_identity");
        pending_mapping_effect=mapping_effect("none",0,0,0,0,NULL);
        if(selector_version>=5)pending_file_descriptor=file_descriptor_effect(
            pending_number==5?"open":"close",fd,descriptor_file_ids[fd],descriptor_epochs[fd]);
        else pending_file_descriptor=g_strdup_printf("{\"operation\":\"%s\",\"fd\":%u,\"file_id\":0,"
            "\"descriptor_epoch\":%u,\"file_size\":%zu,\"source_sha256\":\"%s\"}",
            pending_number==5?"open":"close",fd,descriptor_epochs[fd],(size_t)elf_size,elf_sha);
        if(pending_number==6) {
            descriptor_epochs[fd]=0;
            if(selector_version>=5){descriptor_file_ids[fd]=0;descriptor_offsets[fd]=0;}
        }
        return;
    }
    if(result>=UINT32_C(0xfffff001)) {
        if(result!=UINT32_C(0xffffffea)||!preflight_EINVAL())reject("unsupported_failed_mapping_effect");
        pending_mapping_effect=mapping_effect("none",0,0,0,0,NULL);return;
    }
    if(preflight_EINVAL())reject("successful_invalid_mapping_geometry");
    if(pending_number==90||pending_number==192) {
        uint32_t *a=pending_mmap_args;uint64_t end=effect_end(result,a[1]);
        if((a[3]&16U)&&result!=a[0])reject("MAP_FIXED_result");
        for(uint64_t page=result>>12;page<end>>12;++page)
            if(page_initial[page]||(!(a[3]&16U)&&page_mapped[page]))reject("mapping_replaces_protected_or_live_range");
        size_t size=(size_t)(end-result);
        uint64_t file_offset=(uint64_t)a[5]*(pending_number==192?PAGE:1U);
        unsigned file=selector_version>=5?descriptor_file_ids[a[4]<64?a[4]:0]:0;
        size_t file_size=file?mutable_files[file].size:elf_size;
        const uint8_t *file_bytes=file?mutable_files[file].bytes:(const uint8_t *)elf_bytes;
        if(selector_version>=4&&!(a[3]&32U)&&
           (file_offset%PAGE||file_offset+size>rounded(file_size)||file_offset>=file_size))
            reject("source_mapping_beyond_EOF");
        uint8_t *bytes=g_malloc(size);
        if(!read_guest(result,bytes,size))reject("mapping_constructor_snapshot");
        if(selector_version>=4&&!(a[3]&32U)) {
            uint64_t offset=file_offset;
            size_t copied=file_size-offset;if(copied>size)copied=size;
            bool cache_tail=selector_version>=7&&file;
            if(memcmp(bytes,file_bytes+offset,cache_tail?size:copied))reject("source_file_mapping_bytes_mismatch");
            if(!cache_tail)for(size_t i=copied;i<size;++i)if(bytes[i])reject("source_file_EOF_tail_mismatch");
            gchar *sha=g_compute_checksum_for_data(G_CHECKSUM_SHA256,bytes,size);
            pending_mapping_effect=mapping_effect("map",result,(uint32_t)size,a[2],(uint32_t)pending_ordinal,NULL);
            gchar *content=selector_version>=5?g_strdup_printf(",\"content_epoch\":%u",
                file?mutable_files[file].content_epoch:0):g_strdup("");
            gchar *shared=selector_version>=6?g_strdup_printf(",\"shared\":%s",(a[3]&3U)==1?"true":"false"):g_strdup("");
            gchar *cache=selector_version>=7?g_strdup_printf(",\"cache_tail_bytes\":%zu",cache_tail?size-copied:0):g_strdup("");
            pending_file_mapping=g_strdup_printf("{\"fd\":%u,\"file_id\":%u,\"descriptor_epoch\":%u,"
                "\"file_size\":%zu,\"file_offset\":%" PRIu64 ",\"file_bytes\":%zu,"
                "\"zero_tail_bytes\":%zu,\"initial_bytes_sha256\":\"%s\"%s%s%s}",a[4],file,descriptor_epochs[a[4]],
                file_size,offset,copied,cache_tail?0:size-copied,sha,content,shared,cache);
            g_free(sha);g_free(content);g_free(shared);g_free(cache);
        }else {
            for(size_t i=0;i<size;++i)if(bytes[i])reject("anonymous_zero_mapping_mismatch");
            gchar *sha=g_compute_checksum_for_data(G_CHECKSUM_SHA256,bytes,size);
            pending_mapping_effect=mapping_effect("map",result,(uint32_t)size,a[2],(uint32_t)pending_ordinal,sha);g_free(sha);
        }
        g_free(bytes);
        for(uint64_t page=result>>12;page<end>>12;++page) {
            page_mapped[page]=true;page_permissions[page]=(uint8_t)a[2];
            page_mapping_epoch[page]=(uint32_t)pending_ordinal;page_generation[page]=0;
            if(selector_version>=5)page_backing_tokens[page]=(a[3]&32U)?0:(uint8_t)(file+1U);
            if(selector_version>=6) {
                page_backing_shared[page]=!(a[3]&32U)&&(a[3]&3U)==1;
                page_backing_offsets[page]=(a[3]&32U)?0:(uint32_t)(file_offset+((page<<12)-result));
                if(!(a[3]&32U)&&file)page_generation[page]=file_page_generation(file,page_backing_offsets[page]);
                if(!(a[3]&32U)&&!file_page_seen[page]) {
                    if(file_page_count==G_N_ELEMENTS(file_page_indices))reject("shared_file_page_inventory_budget");
                    file_page_seen[page]=true;file_page_indices[file_page_count++]=(uint32_t)page;
                }
            }
        }
    }else {
        if(result)reject("mapping_zero_success_return");
        uint32_t address=pending_args[0];uint64_t end=effect_end(address,pending_args[1]);
        for(uint64_t page=address>>12;page<end>>12;++page) {
            if(pending_number==91&&page_initial[page])reject("unmap_protected_initial_range");
            if(pending_number==125&&!page_mapped[page])reject("protect_unconstructed_mapping");
        }
        uint32_t size=(uint32_t)(end-address),prot=pending_number==125?pending_args[2]:0;
        pending_mapping_effect=mapping_effect(pending_number==91?"unmap":"protect",address,size,prot,0,NULL);
        for(uint64_t page=address>>12;page<end>>12;++page) {
            if(pending_number==91) {
                page_mapped[page]=false;page_permissions[page]=0;page_mapping_epoch[page]=0;page_generation[page]=0;
                if(selector_version>=5)page_backing_tokens[page]=0;
                if(selector_version>=6){page_backing_shared[page]=false;page_backing_offsets[page]=0;}
            }else page_permissions[page]=(uint8_t)prot;
        }
    }
}
static void syscall_enter(qemu_plugin_id_t id,unsigned cpu,int64_t number,
        uint64_t a1,uint64_t a2,uint64_t a3,uint64_t a4,uint64_t a5,uint64_t a6,uint64_t a7,uint64_t a8) {
    (void)id;(void)a7;(void)a8;
    if(cpu || !initialized || !current || pending_syscall || post_pending ||
       (selector_version>=3?(number!=90&&number!=192&&number!=91&&number!=125&&
            !(selector_version>=4&&(number==5||number==6))&&
            !(selector_version>=5&&(number==356||number==4||number==93||number==19))&&
            !(selector_version>=7&&number==144)):number!=125) || current->size!=2 ||
       current->bytes[0]!=0xcd || current->bytes[1]!=0x80 || syscall_count>=(selector_version>=5?256U:32U)) reject("unsupported_syscall");
    uint64_t args[6]={a1,a2,a3,a4,a5,a6};
    for(unsigned i=0;i<6;++i) {
        /* linux-user may sign-extend abi_long syscall arguments, e.g. fd=-1.
         * Accept only canonical zero/sign extensions of the guest BV32 value. */
        if(args[i]>UINT32_MAX&&(selector_version<3||
           args[i]!=(uint64_t)(int64_t)(int32_t)(uint32_t)args[i]))reject("syscall_argument_width");
        pending_args[i]=(uint32_t)args[i];
    }
    pending_number=(uint32_t)number;
    g_clear_pointer(&pending_path,g_free);
    g_clear_pointer(&pending_name,g_free);g_clear_pointer(&pending_write_bytes,g_free);
    g_clear_pointer(&pending_file_mutation,g_free);
    if(current_registers[0]!=(uint32_t)number)reject("syscall_number_register");
    if(selector_version>=3) {
        static const unsigned keys[6]={3,1,2,6,7,5};
        unsigned arity=number==90||number==6?1:number==91||number==5||number==356||number==93?2:
            number==125||number==4||number==19||number==144?3:6;
        for(unsigned i=0;i<arity;++i)if(current_registers[keys[i]]!=pending_args[i])reject("syscall_argument_register");
        if(number==90) {
            if((uint64_t)pending_args[0]+24>(UINT64_C(1)<<32))reject("mmap_argument_array_extent");
            for(uint64_t page=pending_args[0]>>12;page<=((uint64_t)pending_args[0]+23)>>12;++page)
                if(!page_mapped[page]||!(page_permissions[page]&1U))reject("mmap_argument_array_mapping");
            uint8_t array[24];if(!read_guest(pending_args[0],array,sizeof array))reject("mmap_argument_array");
            for(unsigned i=0;i<6;++i)pending_mmap_args[i]=u32(array+4*i);
        }else if(number==192)memcpy(pending_mmap_args,pending_args,sizeof pending_args);
        else if(number==5) {
            pending_path=source_open_path();
        }
        else if(selector_version>=5&&number==356)pending_name=memfd_name();
        mapping_arguments();
        if(selector_version>=5&&number==4) {
            pending_write_bytes=g_malloc(pending_args[2]?pending_args[2]:1U);
            if(!read_guest(pending_args[1],pending_write_bytes,pending_args[2]))reject("mutable_write_buffer_snapshot");
        }
    }else if(current_registers[3]!=pending_args[0] || current_registers[1]!=pending_args[1] ||
       current_registers[2]!=pending_args[2] || !pending_args[1] || (pending_args[0]&4095U) || pending_args[2]>7 ||
       (uint64_t)pending_args[0]+rounded(pending_args[1])>(UINT64_C(1)<<32)) reject("syscall_geometry");
    pending_pc=current->pc;pending_ordinal=++syscall_count;pending_syscall=true;
    gchar *regs=register_json(current_registers);
    gchar *array=(selector_version>=3&&(number==90||number==192))?g_strdup_printf("[%u,%u,%u,%u,%u,%u]",
        pending_mmap_args[0],pending_mmap_args[1],pending_mmap_args[2],pending_mmap_args[3],pending_mmap_args[4],pending_mmap_args[5]):g_strdup("null");
    gchar *path=pending_path?g_strdup_printf("\"%s\"",pending_path):g_strdup("null");
    gchar *mutable_fields=g_strdup("");
    if(selector_version>=5) {
        gchar *name=pending_name?g_strdup_printf("\"%s\"",pending_name):g_strdup("null");
        gchar *write=g_strdup("null");
        if(number==4) {
            gchar *bytes=hex(pending_write_bytes,pending_args[2]);g_free(write);
            write=g_strdup_printf("{\"address\":%u,\"size\":%u,\"data_hex\":\"%s\"}",
                pending_args[1],pending_args[2],bytes);g_free(bytes);
        }
        g_free(mutable_fields);mutable_fields=g_strdup_printf(",\"name_hex\":%s,\"write_buffer\":%s",name,write);
        g_free(name);g_free(write);
    }
    record("{\"kind\":\"syscall_enter\",\"ordinal\":%" PRIu64 ",\"pc\":%" PRIu64 ",\"number\":%u,"
           "\"args\":[%u,%u,%u,%u,%u,%u],\"mmap_args\":%s,\"path_hex\":%s,\"registers\":%s%s}\n",
           pending_ordinal,pending_pc,pending_number,pending_args[0],pending_args[1],pending_args[2],pending_args[3],pending_args[4],pending_args[5],array,path,regs,mutable_fields);
    g_free(regs);g_free(array);g_free(path);g_free(mutable_fields);
}
static void syscall_return(qemu_plugin_id_t id,unsigned cpu,int64_t number,int64_t result) {
    (void)id;
    if(cpu || !pending_syscall || number!=pending_number ||
       (selector_version<3&&result!=0)||(result<INT32_MIN||result>UINT32_MAX))reject("mapping_syscall_result");
    post_result=(uint32_t)result;
    record("{\"kind\":\"syscall_return\",\"ordinal\":%" PRIu64 ",\"pc\":%" PRIu64
           ",\"number\":%u,\"result_u32\":%u,\"reply_hex\":null}\n",pending_ordinal,pending_pc,pending_number,post_result);
    ++syscall_returns;pending_syscall=false;post_pending=true;
    if(selector_version>=3)mapping_return(post_result);
    else {
        uint64_t end=(uint64_t)pending_args[0]+rounded(pending_args[1]);
        for(uint64_t page=pending_args[0]>>12;page<end>>12;++page)page_permissions[page]=(uint8_t)pending_args[2];
    }
}
static void finish(qemu_plugin_id_t id,void *opaque) {
    (void)id;(void)opaque;complete(false,"guest_ended_before_stage");
}
QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,const qemu_info_t *info,int argc,char **argv) {
    if(info->system_emulation || strcmp(info->target_name,"i386") || (argc!=6&&argc!=7)) return -1;
    const char *stage_path=NULL;unsigned fields=0;
    for(int i=0;i<argc;++i) {
        const char *arg=argv[i],*equal=strchr(arg,'=');if(!equal || !equal[1]) return -1;
        size_t length=(size_t)(equal-arg);const char *value=equal+1;unsigned bit=0;
        if(length==5 && !strncmp(arg,"guest",length)) { guest_path=value;bit=1; }
        else if(length==6 && !strncmp(arg,"events",length)) { events_path=value;bit=2; }
        else if(length==6 && !strncmp(arg,"report",length)) { report_path=value;bit=4; }
        else if(length==6 && !strncmp(arg,"run-id",length)) { run_id=value;bit=8; }
        else if(length==4 && !strncmp(arg,"stop",length)) {
            char *end=NULL;errno=0;uint64_t number=strtoull(value,&end,0);
            if(errno || !end || *end || !number || number>UINT32_MAX) return -1;
            stop_pc=(uint32_t)number;bit=16;
        } else if(length==6 && !strncmp(arg,"stages",length)) { stage_path=value;bit=32; }
        else if(length==10 && !strncmp(arg,"stop-index",length)) {
            char *end=NULL;errno=0;uint64_t index=strtoull(value,&end,10);
            if(!g_ascii_isdigit(*value)||errno||!end||*end||index>=MAX_STAGES)return -1;
            stop_index=(uint32_t)index;stop_index_supplied=true;bit=64;
        }
        else return -1;
        if(fields&bit) return -1;
        fields|=bit;
    }
    if((fields!=63&&fields!=127) || strlen(run_id)!=32 || strspn(run_id,"0123456789abcdef")!=32 ||
       !strcmp(events_path,report_path) || !parse_elf() || !parse_stages(stage_path)) return -1;
    events=fopen(events_path,"wx");if(!events) return -1;
    events_hash=g_checksum_new(G_CHECKSUM_SHA256);path_hash=g_checksum_new(G_CHECKSUM_SHA256);fetch_hash=g_checksum_new(G_CHECKSUM_SHA256);
    memory_buffer=g_byte_array_new();register_buffer=g_byte_array_new();
    gchar *selector=selector_json();
    record("{\"kind\":\"header\",\"schema_version\":%u,\"profile\":\"%s\","
           "\"run_id\":\"%s\",\"elf_sha256\":\"%s\",\"initial_pc\":%u,\"stop_pc\":%u,\"stage_count\":%u,"
           "\"maximum_instructions\":1000000,\"maximum_event_bytes\":33554432,\"custom_QEMU_APIs_used\":false%s}\n",
           selector_version,selector_version>=7?"controlled_static_i386_JMP_memfd_tail_prefix":
               selector_version>=6?"controlled_static_i386_JMP_shared_memfd_prefix":
               selector_version>=5?"controlled_static_i386_JMP_mutable_memfd_prefix":
               selector_version==4?"controlled_static_i386_JMP_private_file_mapping_prefix":
               selector_version==3?"controlled_static_i386_JMP_anonymous_mapping_prefix":"controlled_static_i386_JMP_mprotect_prefix",
           run_id,elf_sha,initial_pc,stop_pc,stage_count,selector);
    g_free(selector);
    TfQemuPluginCallbacks callbacks={.vcpu_init=cpu_init,.translate=translate,.syscall=syscall_enter,.syscall_ret=syscall_return,.finish=finish};
    tf_qemu_register_callbacks(id,&callbacks);
    return 0;
}
