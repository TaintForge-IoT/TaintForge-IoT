/* SPDX-License-Identifier: GPL-2.0-or-later
 * Component verification only: real QEMU execution, no retirement claim.
 */
#define _GNU_SOURCE
#include <qemu-plugin.h>
#include "coverage.h"
_Static_assert(QEMU_PLUGIN_VERSION == 6, "QEMU 11.0.1 API 6 required");
QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;
extern int qemu_plugin_tf_warm_configure(const char *, const char *, uint64_t, int,
                                        void (*)(void), void (*)(void)) __attribute__((weak));
extern void qemu_plugin_tf_warm_arm(void) __attribute__((weak));
static void warm_prepare(void) {}
static void warm_child(void) { tf_afl_previous = 0; }


static void translated(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
    (void)id;
    qemu_plugin_register_vcpu_tb_exec_cb(tb, tf_afl_block, QEMU_PLUGIN_CB_NO_REGS,
        (void *)(uintptr_t)qemu_plugin_tb_vaddr(tb));
}

static void system_call(qemu_plugin_id_t id, unsigned int vcpu, int64_t num,
    uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5,
    uint64_t a6, uint64_t a7, uint64_t a8)
{
    (void)id; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7; (void)a8;
    if (vcpu) _exit(126);
    tf_afl_syscall(num, a1, a2);
}

static void finished(qemu_plugin_id_t id, void *data)
{
    (void)id; (void)data;
    tf_afl_finish();
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id, const qemu_info_t *info,
                                          int argc, char **argv)
{
    if ((argc < 2 || argc > 4) || info->system_emulation || strcmp(info->target_name, "i386") ||
        info->version.cur != 6 || strncmp(argv[0], "coverage=", 9) ||
        strncmp(argv[1], "input=", 6) || tf_afl_open_map(argv[0]+9, argv[1]+6)) return -1;
    if (argc >= 3) {
        uint64_t limit = 2048;
        bool unarmed = false;
        if (argc == 4) {
            if (!strcmp(argv[3], "rss=1")) limit = 1;
            else if (!strcmp(argv[3], "unarmed=on")) unarmed = true;
            else return -1;
        }
        if (strncmp(argv[2], "warm=", 5) || !qemu_plugin_tf_warm_configure ||
            !qemu_plugin_tf_warm_arm || qemu_plugin_tf_warm_configure(argv[1]+6, argv[2]+5,
                limit, -1, warm_prepare, warm_child)) return -1;
        if (!unarmed) qemu_plugin_tf_warm_arm();
    }
    tf_afl_arm();
    qemu_plugin_register_vcpu_tb_trans_cb(id, translated);
    qemu_plugin_register_vcpu_syscall_cb(id, system_call);
    qemu_plugin_register_vcpu_syscall_ret_cb(id, tf_afl_sysret);
    qemu_plugin_register_atexit_cb(id, finished, NULL);
    return 0;
}
