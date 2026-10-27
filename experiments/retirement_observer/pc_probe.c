/* Test-only QEMU plugin. Exercise the production snapshot reader/formatter
 * on every instruction without a control channel or retirement claims.
 * No register/memory API is mocked; the guest runs to its normal exit.
 */
#define qemu_plugin_install observer_install_unused
#include "observer.c"
#undef qemu_plugin_install

static uint64_t probe_sequence;

static void probe_instruction(unsigned vcpu, void *address)
{
    if (vcpu) abort_run(126, "probe_multiple_vcpu");
    uint64_t seq = ++probe_sequence;
    for (unsigned sample=1; sample<=2; ++sample) {
        char line[1024];
        format_snapshot(line, sizeof(line), 1, sample, seq, (uintptr_t)address);
        fprintf(stderr, "M2_PC_PROBE %s", line);
    }
}

static void probe_translation(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
    (void)id;
    for (size_t i=0; i<qemu_plugin_tb_n_insns(tb); ++i) {
        struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);
        qemu_plugin_register_vcpu_insn_exec_cb(insn, probe_instruction, QEMU_PLUGIN_CB_R_REGS,
            (void *)(uintptr_t)qemu_plugin_insn_vaddr(insn));
    }
}

static void probe_done(qemu_plugin_id_t id, void *unused)
{
    (void)id; (void)unused;
    fprintf(stderr, "M2_PC_PROBE_DONE %llu\n", (unsigned long long)probe_sequence);
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id, const qemu_info_t *info,
                                          int argc, char **argv)
{
    (void)argv;
    if (info->system_emulation || strcmp(info->target_name,"i386") ||
        info->version.cur != 6 || info->version.min > 6 || argc) return -1;
    qemu_plugin_register_vcpu_init_cb(id, init_vcpu);
    qemu_plugin_register_vcpu_tb_trans_cb(id, probe_translation);
    qemu_plugin_register_atexit_cb(id, probe_done, NULL);
    return 0;
}
