/* SPDX-License-Identifier: GPL-2.0-or-later
 * Component verification only: real QEMU execution, no retirement claim.
 */
#define _GNU_SOURCE
#include <qemu-plugin.h>
#include "coverage.h"
#include "no_core.h"
#include "../retirement_observer/control_guard.h"
_Static_assert(QEMU_PLUGIN_VERSION == 6, "QEMU 11.0.1 API 6 required");
QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;
extern int qemu_plugin_tf_warm_configure(const char *, const char *, uint64_t, int,
                                        void (*)(void), void (*)(void)) __attribute__((weak));
extern void qemu_plugin_tf_warm_arm(void) __attribute__((weak));
static void warm_prepare(void) {}
static bool warm_child_active;
static void warm_child(void)
{
    if (tf_afl_disable_core_dumps()) _exit(126);
    warm_child_active = true;
    tf_afl_previous = 0;
}


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
    (void)id; (void)a6; (void)a7; (void)a8;
    if (vcpu) _exit(126);
    cg_before(vcpu, num, a1, a2, a3, a4, a5);
    tf_afl_syscall(num, a1, a2);
}

static void system_return(qemu_plugin_id_t id, unsigned int vcpu, int64_t num, int64_t result)
{
    cg_after(num, result);
    tf_afl_sysret(id, vcpu, num, result);
}

static void finished(qemu_plugin_id_t id, void *data)
{
    (void)id; (void)data;
    if (warm_child_active && tf_afl_disable_core_dumps()) _exit(126);
    if (cg_enabled && warm_child_active) {
        char proof[512];
        cg_snapshot(proof, sizeof(proof));
        fprintf(stderr, "TF_COMPONENT_M5{\"pid\":%ld%s}\n", (long)getpid(), proof);
    }
    tf_afl_finish();
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id, const qemu_info_t *info,
                                          int argc, char **argv)
{
    if ((argc < 2 || argc > 5) || info->system_emulation || strcmp(info->target_name, "i386") ||
        info->version.cur != 6 || strncmp(argv[0], "coverage=", 9) ||
        strncmp(argv[1], "input=", 6) || tf_afl_open_map(argv[0]+9, argv[1]+6)) return -1;
    if (argc >= 3) {
        uint64_t limit = 2048;
        bool unarmed = false;
        bool guarded = false;
        for (int i = 3; i < argc; ++i) {
            if (!strcmp(argv[i], "rss=1")) limit = 1;
            else if (!strcmp(argv[i], "unarmed=on")) unarmed = true;
            else if (!strncmp(argv[i], "guard=", 6) && !guarded) {
                if (cg_enable(argv[i]+6)) return -1;
                guarded = true;
            }
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
    qemu_plugin_register_vcpu_syscall_ret_cb(id, system_return);
    qemu_plugin_register_atexit_cb(id, finished, NULL);
    return 0;
}
