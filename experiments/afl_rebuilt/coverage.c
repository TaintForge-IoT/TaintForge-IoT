/* SPDX-License-Identifier: GPL-2.0-or-later */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <glib.h>
#include "qemu-plugin.h"

#define MAP_SIZE 65536U
#define MAX_BRANCHES 4096U
#define MAX_INSNS 131072U
#define MAX_STEPS 4000000U

struct header {
    char magic[8];
    uint32_t version, map_size;
    uint64_t started, finished, blocks, first_pc, last_pc;
    uint64_t exit_seen, exit_code, input_bytes, branch_count, errors;
};
struct branch { uint64_t pc; uint32_t outcomes, reserved; };
struct record {
    struct header h;
    unsigned char map[MAP_SIZE];
    struct branch branches[MAX_BRANCHES];
};
struct instruction { uint32_t pc, next, target; bool conditional; };
_Static_assert(sizeof(struct header) == 96, "coverage header size");
_Static_assert(sizeof(struct branch) == 16, "branch record size");
static struct record *record;
static struct instruction decoded[MAX_INSNS];
static size_t decoded_count;
static const struct instruction *pending_branch;
static char *input_path;
static int64_t input_fd = -1;
static unsigned int pending_syscall;
static uint64_t pending_fd;
static uint32_t previous;
static uint64_t steps;

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

static void invalid(void)
{
    if (record) record->h.errors++;
}

/* The actual successor PC determines the outcome; no architectural flags are read. */
static void decode_branch(struct instruction *out, const unsigned char *data, size_t size)
{
    size_t i = 0;
    bool operand16 = false;
    while (i < size) {
        unsigned char c = data[i];
        if (c == 0x66) operand16 = true;
        else if (c != 0x67 && c != 0xf2 && c != 0xf3 && c != 0x2e && c != 0x3e &&
                 c != 0x26 && c != 0x36 && c != 0x64 && c != 0x65) break;
        i++;
    }
    if (i >= size) return;
    int32_t relative;
    if (((data[i] >= 0x70 && data[i] <= 0x7f) ||
         (data[i] >= 0xe0 && data[i] <= 0xe3)) && size == i + 2) {
        relative = (int8_t)data[i + 1];
    } else if (!operand16 && size == i + 6 && data[i] == 0x0f &&
               data[i + 1] >= 0x80 && data[i + 1] <= 0x8f) {
        uint32_t value = (uint32_t)data[i + 2] | ((uint32_t)data[i + 3] << 8) |
                         ((uint32_t)data[i + 4] << 16) | ((uint32_t)data[i + 5] << 24);
        memcpy(&relative, &value, sizeof(relative));
    } else return;
    out->target = out->next + (uint32_t)relative;
    /* A zero displacement does not reveal the condition from the successor. */
    out->conditional = out->target != out->next;
}

static void save_branch(uint32_t pc, bool taken)
{
    uint64_t n = record->h.branch_count;
    for (uint64_t i = 0; i < n; i++) {
        if (record->branches[i].pc == pc) {
            record->branches[i].outcomes |= taken ? 2U : 1U;
            return;
        }
    }
    if (n >= MAX_BRANCHES) { invalid(); return; }
    record->branches[n].pc = pc;
    record->branches[n].outcomes = taken ? 2U : 1U;
    record->h.branch_count++;
}

static void instruction_exec(unsigned int cpu, void *userdata)
{
    const struct instruction *insn = userdata;
    if (!record || cpu != 0) { invalid(); return; }
    if (++steps > MAX_STEPS) { invalid(); _exit(86); }
    if (!record->h.started) return;
    if (pending_branch) {
        if (insn->pc == pending_branch->next) save_branch(pending_branch->pc, false);
        else if (insn->pc == pending_branch->target) save_branch(pending_branch->pc, true);
        else invalid();
    }
    pending_branch = insn->conditional ? insn : NULL;
}

static void block_exec(unsigned int cpu, void *userdata)
{
    if (!record || cpu != 0) { invalid(); return; }
    if (!record->h.started) return;
    uint32_t pc = (uint32_t)(uintptr_t)userdata;
    uint32_t location = (pc >> 4) ^ (pc << 8);
    uint32_t index = (location ^ previous) & (MAP_SIZE - 1);
    unsigned char value = (unsigned char)(record->map[index] + 1U);
    record->map[index] = value ? value : 1;
    previous = location >> 1;
    if (!record->h.blocks) record->h.first_pc = pc;
    record->h.last_pc = pc;
    record->h.blocks++;
}

static void translate(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
    (void)id;
    qemu_plugin_register_vcpu_tb_exec_cb(tb, block_exec, QEMU_PLUGIN_CB_NO_REGS,
        (void *)(uintptr_t)qemu_plugin_tb_vaddr(tb));
    for (size_t i = 0; i < qemu_plugin_tb_n_insns(tb); i++) {
        if (decoded_count == MAX_INSNS) { invalid(); _exit(86); }
        struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);
        size_t size = qemu_plugin_insn_size(insn);
        unsigned char bytes[15];
        uint64_t pc = qemu_plugin_insn_vaddr(insn);
        if (pc > UINT32_MAX || !size || size > sizeof(bytes) ||
            qemu_plugin_insn_data(insn, bytes, size) != size) { invalid(); _exit(86); }
        struct instruction *entry = &decoded[decoded_count++];
        *entry = (struct instruction){.pc = (uint32_t)pc, .next = (uint32_t)(pc + size)};
        decode_branch(entry, bytes, size);
        qemu_plugin_register_vcpu_insn_exec_cb(insn, instruction_exec, QEMU_PLUGIN_CB_NO_REGS, entry);
    }
}

static bool path_matches(uint64_t address)
{
    size_t length = strlen(input_path) + 1;
    if (address > UINT32_MAX || length > UINT32_MAX - address) return false;
    GByteArray *bytes = g_byte_array_new();
    bool same = qemu_plugin_read_memory_vaddr(address, bytes, length) &&
                bytes->len == length && !memcmp(bytes->data, input_path, length);
    g_byte_array_free(bytes, true);
    return same;
}

static void syscall_enter(qemu_plugin_id_t id, unsigned int cpu, int64_t number,
    uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4,
    uint64_t a5, uint64_t a6, uint64_t a7, uint64_t a8)
{
    (void)id; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7; (void)a8;
    if (!record || cpu != 0) { invalid(); return; }
    pending_syscall = 0;
    pending_fd = a1;
    /* This profile has one ELF image, process and vCPU. */
    if (number == 2 || number == 11 || number == 120 || number == 190 || number == 358 || number == 435) {
        invalid(); _exit(86);
    }
    if (number == 1 || number == 252) {
        record->h.exit_seen = 1;
        record->h.exit_code = a1 & 255;
    }
    if ((number == 5 && path_matches(a1)) || (number == 295 && path_matches(a2))) pending_syscall = 1;
    else if (number == 6 && (int64_t)a1 == input_fd) pending_syscall = 2;
    else if ((number == 3 || number == 180) && (int64_t)a1 == input_fd) pending_syscall = 3;
}

static void syscall_return(qemu_plugin_id_t id, unsigned int cpu, int64_t number, int64_t result)
{
    (void)id; (void)number;
    if (!record || cpu != 0) { invalid(); return; }
    if (pending_syscall == 1 && result >= 0) input_fd = result;
    else if (pending_syscall == 2 && result == 0 && (int64_t)pending_fd == input_fd) input_fd = -1;
    else if (pending_syscall == 3 && result > 0) {
        record->h.input_bytes += (uint64_t)result;
        if (!record->h.started) {
            previous = 0;
            pending_branch = NULL;
            record->h.started = 1;
        }
    }
    pending_syscall = 0;
}

static void finished(qemu_plugin_id_t id, void *unused)
{
    (void)id; (void)unused;
    if (record) {
        if (pending_branch) invalid();
        record->h.finished = 1;
        munmap(record, sizeof(*record));
        record = NULL;
    }
    free(input_path);
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id, const qemu_info_t *info,
                                         int argc, char **argv)
{
    if (info->system_emulation || strcmp(info->target_name, "i386") || argc != 2 ||
        strncmp(argv[0], "output=", 7) || strncmp(argv[1], "input=/", 7)) return -1;
    const char *path = argv[0] + 7;
    struct stat st;
    int fd = open(path, O_RDWR | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return -1;
    if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_nlink != 1 || st.st_size != (off_t)sizeof(struct record)) {
        close(fd); return -1;
    }
    record = mmap(NULL, sizeof(*record), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    close(fd);
    if (record == MAP_FAILED) { record = NULL; return -1; }
    if (memcmp(record->h.magic, "TFRCOV1", 8) || record->h.version != 1 || record->h.map_size != MAP_SIZE) goto fail;
    const unsigned char *zero = (const unsigned char *)record + 16;
    for (size_t i = 0; i < sizeof(*record) - 16; i++) if (zero[i]) goto fail;
    input_path = strdup(argv[1] + 6);
    if (!input_path) goto fail;
    qemu_plugin_register_vcpu_tb_trans_cb(id, translate);
    qemu_plugin_register_vcpu_syscall_cb(id, syscall_enter);
    qemu_plugin_register_vcpu_syscall_ret_cb(id, syscall_return);
    qemu_plugin_register_atexit_cb(id, finished, NULL);
    return 0;
fail:
    munmap(record, sizeof(*record));
    record = NULL;
    return -1;
}
