#ifndef TAINTFORGE_QEMU_PLUGIN_COMPAT_H
#define TAINTFORGE_QEMU_PLUGIN_COMPAT_H

#include <limits.h>
#include <qemu-plugin.h>

/* API 6 returns a success flag from read_register; older APIs return a byte
 * count. Neither result alone proves that a complete register was captured.
 * The caller must have found the register in get_registers(): an opaque handle
 * may be NULL, so its pointer value cannot represent presence or absence. */
static inline bool tf_qemu_read_register_exact(struct qemu_plugin_register *reg, GByteArray *buffer,
                                               unsigned int size) {
    if (!buffer || !size || size > INT_MAX)
        return false;
    g_byte_array_set_size(buffer, 0);
#if QEMU_PLUGIN_VERSION >= 6
    bool ok = qemu_plugin_read_register(reg, buffer);
#else
    bool ok = qemu_plugin_read_register(reg, buffer) == (int)size;
#endif
    return ok && buffer->len == size;
}

/* Keep the plugin's callbacks independent of API 7's move from an implicit
 * plugin ID to explicit userdata. These consumers have one installation per
 * shared object; the adapter owns its context for that installation's lifetime. */
typedef struct TfQemuPluginCallbacks {
    void (*vcpu_init)(qemu_plugin_id_t id, unsigned int cpu);
    void (*translate)(qemu_plugin_id_t id, struct qemu_plugin_tb *tb);
    void (*syscall)(qemu_plugin_id_t id, unsigned int cpu, int64_t num, uint64_t a1, uint64_t a2,
                    uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6, uint64_t a7, uint64_t a8);
    void (*syscall_ret)(qemu_plugin_id_t id, unsigned int cpu, int64_t num, int64_t ret);
    void (*finish)(qemu_plugin_id_t id, void *userdata);
} TfQemuPluginCallbacks;

#if QEMU_PLUGIN_VERSION >= 7
typedef struct TfQemuPluginContext {
    qemu_plugin_id_t id;
    TfQemuPluginCallbacks callbacks;
} TfQemuPluginContext;

static inline void tf_qemu_vcpu_init_cb(unsigned int cpu, void *userdata) {
    TfQemuPluginContext *ctx = userdata;
    ctx->callbacks.vcpu_init(ctx->id, cpu);
}

static inline void tf_qemu_translate_cb(struct qemu_plugin_tb *tb, void *userdata) {
    TfQemuPluginContext *ctx = userdata;
    ctx->callbacks.translate(ctx->id, tb);
}

static inline void tf_qemu_syscall_cb(unsigned int cpu, int64_t num, uint64_t a1, uint64_t a2,
                                      uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6,
                                      uint64_t a7, uint64_t a8, void *userdata) {
    TfQemuPluginContext *ctx = userdata;
    ctx->callbacks.syscall(ctx->id, cpu, num, a1, a2, a3, a4, a5, a6, a7, a8);
}

static inline void tf_qemu_syscall_ret_cb(unsigned int cpu, int64_t num, int64_t ret,
                                          void *userdata) {
    TfQemuPluginContext *ctx = userdata;
    ctx->callbacks.syscall_ret(ctx->id, cpu, num, ret);
}

static inline void tf_qemu_finish_cb(void *userdata) {
    TfQemuPluginContext *ctx = userdata;
    ctx->callbacks.finish(ctx->id, NULL);
}
#endif

static inline void tf_qemu_register_callbacks(qemu_plugin_id_t id,
                                              const TfQemuPluginCallbacks *callbacks) {
#if QEMU_PLUGIN_VERSION >= 7
    static TfQemuPluginContext ctx;
    ctx.id = id;
    ctx.callbacks = *callbacks;
    if (callbacks->vcpu_init)
        qemu_plugin_register_vcpu_init_cb(id, tf_qemu_vcpu_init_cb, &ctx);
    if (callbacks->translate)
        qemu_plugin_register_vcpu_tb_trans_cb(id, tf_qemu_translate_cb, &ctx);
    if (callbacks->syscall)
        qemu_plugin_register_vcpu_syscall_cb(id, tf_qemu_syscall_cb, &ctx);
    if (callbacks->syscall_ret)
        qemu_plugin_register_vcpu_syscall_ret_cb(id, tf_qemu_syscall_ret_cb, &ctx);
    if (callbacks->finish)
        qemu_plugin_register_atexit_cb(id, tf_qemu_finish_cb, &ctx);
#else
    if (callbacks->vcpu_init)
        qemu_plugin_register_vcpu_init_cb(id, callbacks->vcpu_init);
    if (callbacks->translate)
        qemu_plugin_register_vcpu_tb_trans_cb(id, callbacks->translate);
    if (callbacks->syscall)
        qemu_plugin_register_vcpu_syscall_cb(id, callbacks->syscall);
    if (callbacks->syscall_ret)
        qemu_plugin_register_vcpu_syscall_ret_cb(id, callbacks->syscall_ret);
    if (callbacks->finish)
        qemu_plugin_register_atexit_cb(id, callbacks->finish, NULL);
#endif
}

#endif
