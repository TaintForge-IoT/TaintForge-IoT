/* SPDX-License-Identifier: GPL-2.0-or-later */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <glib.h>
#include "qemu-plugin.h"
#include "../../unpacker/test/process_event.h"

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
/* Fixed-input tree replay uses one independently validated v1 record per PID. */
#define TREE_PROCESSES 8
struct slot {
    int32_t pid;
    uint32_t inherited_input;
    struct record coverage;
};
_Static_assert(sizeof(struct slot) == 8 + sizeof(struct record), "coverage slot size");
static struct slot *slots;
static int tree_socket = -1;
static int reserved_slot = -1;
static bool fork_had_input;
static void *mapping;
static size_t mapping_size;

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
    if (tree_socket >= 0 && private_fork_i386(number, a1, a2)) {
        /* Reserve before forking, so the process limit also bounds live children. */
        for (int i = 1; i < TREE_PROCESSES; i++) {
            int32_t free_slot = 0;
            if (__atomic_compare_exchange_n(&slots[i].pid, &free_slot, -1, false,
                                            __ATOMIC_ACQ_REL, __ATOMIC_RELAXED)) {
                reserved_slot = i;
                fork_had_input = record->h.started;
                return;
            }
        }
        invalid();
        tf_process_event(tree_socket, 'L', TREE_PROCESSES, 0);
        _exit(86);
    }
    if (process_transition_i386(number) || (tree_socket >= 0 && (number == 57 || number == 66))) {
        invalid();
        if (tree_socket >= 0) tf_process_event(tree_socket, '!', (int32_t)number, 0);
        _exit(86);
    }
    if (number == 1 || number == 252) {
        if (tree_socket >= 0 && !tf_process_event(tree_socket, 'X', a1 & 255, 0)) {
            invalid(); _exit(86);
        }
        record->h.exit_seen = 1;
        record->h.exit_code = a1 & 255;
    }
    if ((number == 5 && path_matches(a1)) || (number == 295 && path_matches(a2))) pending_syscall = 1;
    else if (number == 6 && (int64_t)a1 == input_fd) pending_syscall = 2;
    else if ((number == 3 || number == 180) && (int64_t)a1 == input_fd) pending_syscall = 3;
}

static void syscall_return(qemu_plugin_id_t id, unsigned int cpu, int64_t number, int64_t result)
{
    (void)id;
    if (!record || cpu != 0) { invalid(); return; }
    if (tree_socket >= 0 && (number == 2 || number == 120) && reserved_slot > 0) {
        struct slot *child = &slots[reserved_slot];
        reserved_slot = -1;
        if (result < 0) {
            __atomic_store_n(&child->pid, 0, __ATOMIC_RELEASE);
            return;
        }
        if (result == 0) {
            /* Everything else (previous edge, open input fd) is private after fork. */
            child->inherited_input = fork_had_input;
            record = &child->coverage;
            record->h.started = child->inherited_input;
            __atomic_store_n(&child->pid, getpid(), __ATOMIC_RELEASE);
        }
        if (!tf_process_event(tree_socket, result ? 'F' : 'C', result, result ? result : getpid())) {
            invalid(); _exit(86);
        }
        return;
    }
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
        munmap(mapping, mapping_size);
        record = NULL;
    }
    free(input_path);
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id, const qemu_info_t *info,
                                         int argc, char **argv)
{
    if (info->system_emulation || strcmp(info->target_name, "i386") || (argc != 2 && argc != 3) ||
        strncmp(argv[0], "output=", 7) || strncmp(argv[1], "input=/", 7)) return -1;
    if (argc == 3) {
        char *end;
        if (strncmp(argv[2], "tree-fd=", 8)) return -1;
        errno = 0;
        long fd = strtol(argv[2] + 8, &end, 10);
        if (errno || end == argv[2] + 8 || *end || fd < 3 || fd > INT_MAX) return -1;
        tree_socket = (int)fd;
    }
    mapping_size = tree_socket < 0 ? sizeof(*record) : TREE_PROCESSES * sizeof(*slots);
    const char *path = argv[0] + 7;
    struct stat st;
    int fd = open(path, O_RDWR | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return -1;
    if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_nlink != 1 || st.st_size != (off_t)mapping_size) {
        close(fd); return -1;
    }
    mapping = mmap(NULL, mapping_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    close(fd);
    if (mapping == MAP_FAILED) return -1;
    if (tree_socket >= 0) slots = mapping;
    for (int i = 0; i < (slots ? TREE_PROCESSES : 1); i++) {
        if (slots && (slots[i].pid || slots[i].inherited_input)) goto fail;
        record = slots ? &slots[i].coverage : mapping;
        if (memcmp(record->h.magic, "TFRCOV1", 8) || record->h.version != 1 || record->h.map_size != MAP_SIZE) goto fail;
        const unsigned char *zero = (const unsigned char *)record + 16;
        for (size_t j = 0; j < sizeof(*record) - 16; j++) if (zero[j]) goto fail;
    }
    if (slots) {
        record = &slots[0].coverage;
        slots[0].pid = getpid();
        if (!tf_process_event(tree_socket, 'S', 0, 0)) goto fail;
    }
    input_path = strdup(argv[1] + 6);
    if (!input_path) goto fail;
    qemu_plugin_register_vcpu_tb_trans_cb(id, translate);
    qemu_plugin_register_vcpu_syscall_cb(id, syscall_enter);
    qemu_plugin_register_vcpu_syscall_ret_cb(id, syscall_return);
    qemu_plugin_register_atexit_cb(id, finished, NULL);
    return 0;
fail:
    munmap(mapping, mapping_size);
    record = NULL;
    return -1;
}
