#include <glib.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <qemu-plugin.h>
#include "qemu_plugin_compat.h"
QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;
static struct qemu_plugin_register *flags_register;
static bool have_flags;
static FILE *output;
static unsigned count, cpus;
static bool failed;
static void init(qemu_plugin_id_t id, unsigned cpu) {
    (void)id;
    if (cpu || cpus++) { failed = true; return; }
    GArray *registers = qemu_plugin_get_registers();
    if (!registers) { failed = true; return; }
    for (guint i=0; i<registers->len; ++i) {
        qemu_plugin_reg_descriptor *d = &g_array_index(registers,qemu_plugin_reg_descriptor,i);
        if (d->name && (!g_ascii_strcasecmp(d->name,"eflags") || !g_ascii_strcasecmp(d->name,"rflags"))) {
            if (have_flags) failed=true;
            flags_register=d->handle; have_flags=true;
        }
    }
    g_array_free(registers,TRUE);
    if (!have_flags) failed=true;
}
static void check(unsigned cpu, void *pc) {
    GByteArray *bytes=g_byte_array_new();
    uint32_t flags=0;
    bool valid=!cpu && have_flags && tf_qemu_read_register_exact(flags_register,bytes,4);
    if (valid) for(unsigned i=0;i<4;++i) flags|=(uint32_t)bytes->data[i]<<(8*i);
    if(!valid || ++count>32) failed=true;
    fprintf(output,"{\"index\":%u,\"pc\":%llu,\"flags\":%u,\"valid\":%s}\n",count,
            (unsigned long long)(uintptr_t)pc,flags,valid?"true":"false");
    g_byte_array_free(bytes,TRUE);
}
static void translate(qemu_plugin_id_t id,struct qemu_plugin_tb *tb) {
    (void)id;
    for(size_t i=0;i<qemu_plugin_tb_n_insns(tb);++i) {
        struct qemu_plugin_insn *insn=qemu_plugin_tb_get_insn(tb,i);
        uint8_t byte=0;
        if(qemu_plugin_insn_size(insn)==1 && qemu_plugin_insn_data(insn,&byte,1)==1 && byte==0x9c)
            qemu_plugin_register_vcpu_insn_exec_cb(insn,check,QEMU_PLUGIN_CB_R_REGS,
                                                (void *)(uintptr_t)qemu_plugin_insn_vaddr(insn));
    }
}
static void finish(qemu_plugin_id_t id,void *opaque) {
    (void)id;(void)opaque;
    fprintf(output,"{\"summary\":true,\"checks\":%u,\"cpus\":%u,\"failed\":%s}\n",
            count,cpus,failed || count!=32 || cpus!=1?"true":"false");
    fclose(output);
}
QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,const qemu_info_t *info,int argc,char **argv) {
    if(info->system_emulation || strcmp(info->target_name,"i386") || argc!=1 || strncmp(argv[0],"report=",7)) return -1;
    output=fopen(argv[0]+7,"wx");
    if(!output) return -1;
    TfQemuPluginCallbacks callbacks={.vcpu_init=init,.translate=translate,.finish=finish};
    tf_qemu_register_callbacks(id,&callbacks);
    return 0;
}
