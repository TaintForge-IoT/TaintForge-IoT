/* SPDX-License-Identifier: GPL-2.0-or-later
 * Mock QEMU callbacks for transport/error tests ONLY. Not QEMU acceptance.
 * Includes the actual production C code and links the real GLib library.
 */
#define _GNU_SOURCE
#include <sys/socket.h>
static int mock_socket(int domain, int type, int protocol);
static int mock_connect(int fd, const struct sockaddr *address, socklen_t length);
#define socket mock_socket
#define connect mock_connect
#include "../probe.c"
#undef socket
#undef connect
static int mock_socket(int domain, int type, int protocol)
{
    const char *fd = getenv("MOCK_SOCKET_FD");
    return fd ? dup(atoi(fd)) : socket(domain, type, protocol);
}
static int mock_connect(int fd, const struct sockaddr *address, socklen_t length)
{
    return getenv("MOCK_SOCKET_FD") ? 0 : connect(fd, address, length);
}
static pthread_t cpu_thread;
static qemu_plugin_vcpu_simple_cb_t init_callback;
static qemu_plugin_udata_cb_t exit_callback;
static qemu_plugin_vcpu_tb_trans_cb_t translate_callback;
struct qemu_plugin_insn { uint64_t address; };
struct qemu_plugin_tb { unsigned int unused; };
static struct qemu_plugin_insn mock_insns[3];
static qemu_plugin_vcpu_udata_cb_t exec_callbacks[2];
static void *exec_data[2];
static uint32_t mock_values[9];
static unsigned int stage;
static void check_context(void)
{
    if (!pthread_equal(pthread_self(), cpu_thread)) {
        _exit(90);
    }
}
GArray *qemu_plugin_get_registers(void)
{
    check_context();
    GArray *result = g_array_new(false, false, sizeof(qemu_plugin_reg_descriptor));
    for (unsigned int i = 0; i < NREG; i++) {
        qemu_plugin_reg_descriptor r = {
            .handle = (void *)(uintptr_t)(i * 2 + (i == PC)),
            .name = reg_names[i], .feature = "mock-i386", .is_readonly = i == PC
        };
        if (getenv("MOCK_MISSING_REG") && i == 0) {
            continue;
        }
        g_array_append_val(result, r);
    }
    return result;
}
bool qemu_plugin_read_register(struct qemu_plugin_register *handle, GByteArray *data)
{
    check_context();
    if (getenv("MOCK_FAIL_REGISTER")) {
        return false;
    }
    uint32_t value = mock_values[(uintptr_t)handle >> 1];
    unsigned char bytes[4] = {value & 255, (value >> 8) & 255, (value >> 16) & 255, value >> 24};
    g_byte_array_append(data, bytes, 4);
    return true; /* API 6 returns bool, not the number of bytes. */
}
bool qemu_plugin_read_memory_vaddr(uint64_t address, GByteArray *data, size_t len)
{
    check_context();
    if (getenv("MOCK_FAIL_MEMORY")) {
        return false;
    }
    g_byte_array_set_size(data, (guint)len);
    if (address == buffer_addr && len == 16) {
        memcpy(data->data, stage == 0 ? "0123456789ABCDEF" : "fedcba9876543210", 16);
        return true;
    }
    if (address == mock_values[SP] && len == 32) {
        uint32_t stack[8] = {0x11223344, 0x55667788, 0x99aabbcc, 7, (uint32_t)getpid(),
                            0x4000, 0xdeadbeef, 0xcafebabe};
        memcpy(data->data, stack, 32);
        return true;
    }
    return false;
}
void qemu_plugin_register_vcpu_init_cb(qemu_plugin_id_t id, qemu_plugin_vcpu_simple_cb_t cb)
{
    (void)id;
    init_callback = cb;
}
void qemu_plugin_register_vcpu_tb_trans_cb(qemu_plugin_id_t id, qemu_plugin_vcpu_tb_trans_cb_t cb)
{
    (void)id;
    translate_callback = cb;
}
void qemu_plugin_register_atexit_cb(qemu_plugin_id_t id, qemu_plugin_udata_cb_t cb, void *udata)
{
    (void)id;
    (void)udata;
    exit_callback = cb;
}
size_t qemu_plugin_tb_n_insns(const struct qemu_plugin_tb *tb) { (void)tb; return 3; }
struct qemu_plugin_insn *qemu_plugin_tb_get_insn(const struct qemu_plugin_tb *tb, size_t index)
{ (void)tb; return &mock_insns[index]; }
uint64_t qemu_plugin_insn_vaddr(const struct qemu_plugin_insn *insn) { return insn->address; }
void qemu_plugin_register_vcpu_insn_exec_cb(struct qemu_plugin_insn *insn,
    qemu_plugin_vcpu_udata_cb_t cb, enum qemu_plugin_cb_flags flags, void *data)
{
    if (flags != QEMU_PLUGIN_CB_R_REGS || (uintptr_t)data > 1 ||
        insn->address != points[(uintptr_t)data]) {
        _exit(91);
    }
    exec_callbacks[(uintptr_t)data] = cb;
    exec_data[(uintptr_t)data] = data;
}
int main(int argc, char **argv)
{
    cpu_thread = pthread_self();
    qemu_info_t info = {.target_name = "i386", .version = {.min = 6, .cur = 6}};
    if (getenv("MOCK_BAD_API")) {
        info.version.cur = 7;
    }
    if (qemu_plugin_install(1, &info, argc - 1, argv + 1)) {
        return 1;
    }
    if (getenv("MOCK_SOCKET_FD")) {
        close(atoi(getenv("MOCK_SOCKET_FD")));
    }
    if (getenv("MOCK_HANG")) {
        sleep(10); /* watchdog must terminate without any CPU callback */
    }
    init_callback(1, 0);
    if (getenv("MOCK_SECOND_VCPU")) {
        init_callback(1, 1);
    }
    mock_insns[0].address = 0x5000;
    mock_insns[1].address = points[0];
    mock_insns[2].address = points[1];
    struct qemu_plugin_tb tb = {0};
    translate_callback(1, &tb);
    if (!exec_callbacks[0] || !exec_callbacks[1]) {
        return 92;
    }
    for (stage = 0; stage < 2; stage++) {
        uint32_t values[] = {(stage + 1) * 0x11111111, 7, (uint32_t)buffer_addr,
                            16, (uint32_t)getpid(), 7, 0x4000, 0x4000, (uint32_t)points[stage]};
        memcpy(mock_values, values, sizeof(values));
        if (getenv("MOCK_BAD_PC")) {
            mock_values[PC]++;
        }
        exec_callbacks[stage](0, exec_data[stage]);
    }
    exit_callback(1, NULL);
    return 0;
}
