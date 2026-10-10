#ifndef TAINTFORGE_IR_SMT_DIAGNOSTICS_H
#define TAINTFORGE_IR_SMT_DIAGNOSTICS_H
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <sys/resource.h>
#include <unistd.h>
#include <time.h>
#include <math.h>

/* Only called on the first API failure. Preserve the record before cleanup or
 * further context calls can replace the Z3 message. Never render an AST here. */
static bool smt_copy_text(char *out,size_t capacity,const char *text) {
    size_t i=0;
    if(text)while(i+1<capacity && text[i]) {out[i]=text[i];++i;}
    out[i]=0;
    return text && text[i];
}
static void smt_process_memory(IrSmtZ3Error *e) {
    e->vm_size_kib=e->vm_peak_kib=e->vm_rss_kib=e->vm_hwm_kib=e->vm_swap_kib=UINT64_MAX;
    char bytes[8192];size_t used=0;
    int fd=open("/proc/self/status",O_RDONLY);
    if(fd>=0) {
        while(used+1<sizeof(bytes)) {
            ssize_t n=read(fd,bytes+used,sizeof(bytes)-used-1);
            if(n>0)used+=(size_t)n;
            else if(n<0 && errno==EINTR)continue;
            else break;
        }
        close(fd);bytes[used]=0;
        const char *keys[]={"VmSize:","VmPeak:","VmRSS:","VmHWM:","VmSwap:"};
        uint64_t *values[]={&e->vm_size_kib,&e->vm_peak_kib,&e->vm_rss_kib,&e->vm_hwm_kib,&e->vm_swap_kib};
        for(unsigned i=0;i<5;++i) {
            const char *p=bytes;
            while(*p) {
                if(!strncmp(p,keys[i],strlen(keys[i]))) {
                    char *end;const char *begin=p+strlen(keys[i]);
                    unsigned long long v=strtoull(begin,&end,10);
                    if(end!=begin)*values[i]=(uint64_t)v;
                    break;
                }
                p=strchr(p,'\n');if(!p)break;++p;
            }
        }
    }
    struct rlimit cap;
    if(!getrlimit(RLIMIT_AS,&cap)) {
        e->rlimit_as_available=true;
        e->rlimit_as_soft_unlimited=cap.rlim_cur==RLIM_INFINITY;
        e->rlimit_as_hard_unlimited=cap.rlim_max==RLIM_INFINITY;
        if(!e->rlimit_as_soft_unlimited)e->rlimit_as_soft_bytes=(uint64_t)cap.rlim_cur;
        if(!e->rlimit_as_hard_unlimited)e->rlimit_as_hard_bytes=(uint64_t)cap.rlim_max;
    }
}
static void smt_capture_error(IrSmt *s,Z3_error_code code,const char *api,bool null_result,int saved_errno) {
    IrSmtZ3Error *e=&s->info.z3_error;
    if(e->present)return;
    e->present=true;e->code=(uint32_t)code;e->null_result=null_result;
    e->errno_at_api_return=saved_errno;
    smt_copy_text(e->api,sizeof(e->api),api);
    smt_copy_text(e->stage,sizeof(e->stage),s->stage);
    const char *message=s->ctx && code!=Z3_OK ? Z3_get_error_msg(s->ctx,code) : "Z3 API returned null without an error code";
    e->message_truncated=smt_copy_text(e->message,sizeof(e->message),message);
    e->version_truncated=smt_copy_text(e->version,sizeof(e->version),Z3_get_full_version());
    unsigned a,b,c,d;Z3_get_version(&a,&b,&c,&d);
    e->version_major=a;e->version_minor=b;e->version_build=c;e->version_revision=d;
    e->origin=s->info.origin;e->instruction=s->instruction;
    if(s->instruction) {
        const IrInst *inst=ir_module_inst(s->module,s->instruction);
        if(inst) {e->has_instruction=true;e->spec=inst->spec;e->result=inst->result;e->block=inst->block;}
    }
    e->work=s->info.work;e->constructors=s->info.constructors;e->lowered_values=s->info.lowered_values;
    e->z3_estimated_alloc_bytes=Z3_get_estimated_alloc_size();
    smt_process_memory(e);
    errno=saved_errno;
}
static const char *smt_error_code_name(uint32_t code) {
    switch(code) {
#define SMT_ERROR_CASE(v) case v:return #v
        SMT_ERROR_CASE(Z3_OK);SMT_ERROR_CASE(Z3_SORT_ERROR);SMT_ERROR_CASE(Z3_IOB);
        SMT_ERROR_CASE(Z3_INVALID_ARG);SMT_ERROR_CASE(Z3_PARSER_ERROR);SMT_ERROR_CASE(Z3_NO_PARSER);
        SMT_ERROR_CASE(Z3_INVALID_PATTERN);SMT_ERROR_CASE(Z3_MEMOUT_FAIL);SMT_ERROR_CASE(Z3_FILE_ACCESS_ERROR);
        SMT_ERROR_CASE(Z3_INTERNAL_FATAL);SMT_ERROR_CASE(Z3_INVALID_USAGE);SMT_ERROR_CASE(Z3_DEC_REF_ERROR);
        SMT_ERROR_CASE(Z3_EXCEPTION);
#undef SMT_ERROR_CASE
        default:return "Z3_UNRECOGNIZED_ERROR_CODE";
    }
}
static void smt_json_string(FILE *f,const char *text) {
    fputc('"',f);
    for(const unsigned char *p=(const unsigned char *)(text?text:"");*p;++p) {
        if(*p=='"' || *p=='\\') {fputc('\\',f);fputc(*p,f);}
        else if(*p<32)fprintf(f,"\\u%04x",*p);
        else fputc(*p,f);
    }
    fputc('"',f);
}
static void smt_json_metric(FILE *f,const char *key,uint64_t value) {
    fprintf(f,",\"%s\":",key);
    if(value==UINT64_MAX)fputs("null",f);else fprintf(f,"%"PRIu64,value);
}
bool ir_smt_z3_error_report_json(FILE *f,const IrSmtZ3Error *e) {
    if(!f)return false;
    if(!e || !e->present) {fputs("null",f);return !ferror(f);}
    fprintf(f,"{\"code\":%u,\"code_name\":",e->code);smt_json_string(f,smt_error_code_name(e->code));
    fputs(",\"api\":",f);smt_json_string(f,e->api);
    fputs(",\"message\":",f);smt_json_string(f,e->message);
    fprintf(f,",\"message_truncated\":%s,\"null_result\":%s,\"version\":",e->message_truncated?"true":"false",e->null_result?"true":"false");
    smt_json_string(f,e->version);
    fprintf(f,",\"version_truncated\":%s,\"version_numbers\":[%u,%u,%u,%u],\"stage\":",e->version_truncated?"true":"false",
        e->version_major,e->version_minor,e->version_build,e->version_revision);
    smt_json_string(f,e->stage);
    fprintf(f,",\"origin\":{\"seq\":%"PRIu64",\"pc\":%"PRIu64",\"vcpu\":%u,\"generation\":%"PRIu64",\"descriptor\":%"PRIu64"},\"ir\":",
        e->origin.seq_id,e->origin.pc,e->origin.vcpu_id,e->origin.code_generation,e->origin.descriptor_id);
    if(!e->has_instruction)fputs("null",f);
    else {
        fprintf(f,"{\"instruction\":%u,\"result\":%u,\"block\":%u,\"opcode\":",e->instruction,e->result,e->block);
        smt_json_string(f,ir_opcode_name(e->spec.op));
        fprintf(f,",\"opcode_number\":%u,\"type_kind\":%u,\"type_bits\":%u,\"args\":[%u,%u,%u],\"immediate\":%"PRIu64",\"state\":%u,\"endian\":%u}",
            (unsigned)e->spec.op,(unsigned)e->spec.type.kind,e->spec.type.bits,e->spec.args[0],e->spec.args[1],e->spec.args[2],
            e->spec.immediate,e->spec.state,(unsigned)e->spec.endian);
    }
    fprintf(f,",\"work\":%"PRIu64",\"constructors\":%"PRIu64",\"lowered_values\":%"PRIu64",\"z3_estimated_alloc_bytes\":%"PRIu64
        ",\"errno_at_api_return\":%d,\"memory\":{\"snapshot\":\"after_failed_api_before_backend_cleanup\"",
        e->work,e->constructors,e->lowered_values,e->z3_estimated_alloc_bytes,e->errno_at_api_return);
    smt_json_metric(f,"vm_size_kib",e->vm_size_kib);smt_json_metric(f,"vm_peak_kib",e->vm_peak_kib);
    smt_json_metric(f,"vm_rss_kib",e->vm_rss_kib);smt_json_metric(f,"vm_hwm_kib",e->vm_hwm_kib);
    smt_json_metric(f,"vm_swap_kib",e->vm_swap_kib);
    fprintf(f,",\"rlimit_as_available\":%s",e->rlimit_as_available?"true":"false");
    smt_json_metric(f,"rlimit_as_soft_bytes",!e->rlimit_as_available || e->rlimit_as_soft_unlimited?UINT64_MAX:e->rlimit_as_soft_bytes);
    smt_json_metric(f,"rlimit_as_hard_bytes",!e->rlimit_as_available || e->rlimit_as_hard_unlimited?UINT64_MAX:e->rlimit_as_hard_bytes);
    fprintf(f,",\"rlimit_as_soft_unlimited\":%s,\"rlimit_as_hard_unlimited\":%s}}",
        e->rlimit_as_soft_unlimited?"true":"false",e->rlimit_as_hard_unlimited?"true":"false");
    return !ferror(f);
}
#endif
