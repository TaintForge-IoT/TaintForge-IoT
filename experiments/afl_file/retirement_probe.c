/* Native handoff test peer. Exercises QEMU's real asynchronous uninstall. */
#include <qemu-plugin.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;
static qemu_plugin_id_t owner;
static int control = -1;
static const char *input;
static const char *const names[] = {"eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"};
static struct qemu_plugin_register *handles[8];

static uint32_t register_value(struct qemu_plugin_register *reg)
{
    GByteArray *bytes = g_byte_array_new();
    if (!qemu_plugin_read_register(reg, bytes) || bytes->len != 4) _exit(126);
    uint32_t value = (uint32_t)bytes->data[0] | (uint32_t)bytes->data[1]<<8 |
                     (uint32_t)bytes->data[2]<<16 | (uint32_t)bytes->data[3]<<24;
    g_byte_array_free(bytes, true);
    return value;
}

static void init(qemu_plugin_id_t id, unsigned vcpu)
{
    (void)id;
    if (vcpu) _exit(126);
    bool found[8] = {false};
    GArray *registers = qemu_plugin_get_registers();
    for (unsigned i = 0; i < registers->len; ++i) {
        qemu_plugin_reg_descriptor *reg = &g_array_index(registers, qemu_plugin_reg_descriptor, i);
        for (unsigned k = 0; k < 8; ++k) {
            if (!strcmp(reg->name, names[k])) {
                handles[k] = reg->handle;
                found[k] = true;
            }
        }
    }
    g_array_free(registers, true);
    for (unsigned i = 0; i < 8; ++i)
        if (!found[i]) _exit(126);
}

static void transfer(void *buffer, size_t size, int sending)
{
    char *bytes = buffer;
    while (size) {
        ssize_t count = sending ? write(control, bytes, size) : read(control, bytes, size);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) _exit(126);
        bytes += count;
        size -= (size_t)count;
    }
}

static void removed(qemu_plugin_id_t id)
{
    if (id != owner) _exit(126);
    char value = 'D';
    transfer(&value, 1, 1);
    close(control);
    control = -1;
}

static void execute(unsigned vcpu, void *instruction_pc)
{
    if (vcpu) _exit(126);
    uint32_t number = register_value(handles[0]);
    if (number != 5 && number != 295) return;
    GByteArray *path = g_byte_array_new();
    size_t size = strlen(input)+1;
    uint32_t address = register_value(handles[number == 5 ? 1 : 2]);
    bool matches = qemu_plugin_read_memory_vaddr(address, path, size) &&
                   path->len == size && !memcmp(path->data, input, size);
    g_byte_array_free(path, true);
    if (!matches) return;
    uint32_t registers[9];
    for (unsigned i = 0; i < 8; ++i)
        registers[i] = htonl(register_value(handles[i]));
    registers[8] = htonl((uint32_t)(uintptr_t)instruction_pc);
    GByteArray *stack = g_byte_array_new();
    if (!qemu_plugin_read_memory_vaddr(ntohl(registers[7]), stack, 32) || stack->len != 32)
        _exit(126);
    char value = 'R';
    transfer(&value, 1, 1);
    transfer(registers, sizeof(registers), 1);
    transfer(stack->data, stack->len, 1);
    g_byte_array_free(stack, true);
    transfer(&value, 1, 0);
    if (value != 'G') _exit(126);
    qemu_plugin_uninstall(owner, removed);
}

static void translate(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
    (void)id;
    for (size_t i = 0; i < qemu_plugin_tb_n_insns(tb); ++i) {
        struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);
        unsigned char bytes[2];
        if (qemu_plugin_insn_size(insn) == 2 &&
            qemu_plugin_insn_data(insn, bytes, sizeof(bytes)) == 2 &&
            bytes[0] == 0xcd && bytes[1] == 0x80)
            qemu_plugin_register_vcpu_insn_exec_cb(insn, execute, QEMU_PLUGIN_CB_R_REGS,
                                                 (void *)(uintptr_t)qemu_plugin_insn_vaddr(insn));
    }
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,
                                          const qemu_info_t *info,
                                          int argc, char **argv)
{
    if (argc != 2 || strncmp(argv[0], "control=", 8) || strncmp(argv[1], "input=", 6) ||
        info->system_emulation || strcmp(info->target_name, "i386")) return -1;
    char *end;
    long fd = strtol(argv[0]+8, &end, 10);
    if (*end || fd < 3 || fd > 65535) return -1;
    owner = id;
    control = (int)fd;
    input = argv[1]+6;
    qemu_plugin_register_vcpu_init_cb(id, init);
    qemu_plugin_register_vcpu_tb_trans_cb(id, translate);
    return 0;
}
