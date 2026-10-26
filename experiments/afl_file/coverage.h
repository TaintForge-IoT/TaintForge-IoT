/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef TF_AFL_FILE_COVERAGE_H
#define TF_AFL_FILE_COVERAGE_H
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#define TF_AFL_MAP_SIZE 65536U
struct tf_afl_header {
    char magic[8];
    uint32_t version, map_size;
    uint64_t started, finished, blocks, first_pc, last_pc, reserved;
};
_Static_assert(sizeof(struct tf_afl_header) == 64, "coverage header layout");
static struct tf_afl_header *tf_afl_record;
static unsigned char *tf_afl_map;
static const char *tf_afl_input;
static uint32_t tf_afl_previous;
static bool tf_afl_armed;
static int64_t tf_afl_fd = -1;
static int tf_afl_pending;
static int64_t tf_afl_pending_fd;

static inline int tf_afl_open_map(const char *path, const char *input)
{
    if (!path && !input) return 0;
    if (!path || !input || input[0] != '/') return -1;
    int fd = open(path, O_RDWR | O_CLOEXEC | O_NOFOLLOW);
    struct stat st;
    if (fd < 0) return -1;
    if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_nlink != 1 ||
        st.st_size != (off_t)(64 + TF_AFL_MAP_SIZE)) { close(fd); return -1; }
    void *memory = mmap(NULL, 64 + TF_AFL_MAP_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    close(fd);
    if (memory == MAP_FAILED) return -1;
    tf_afl_record = memory;
    if (memcmp(tf_afl_record->magic, "TFACOV1", 8) || tf_afl_record->version != 1 ||
        tf_afl_record->map_size != TF_AFL_MAP_SIZE || tf_afl_record->started ||
        tf_afl_record->finished || tf_afl_record->blocks || tf_afl_record->first_pc ||
        tf_afl_record->last_pc || tf_afl_record->reserved) {
        munmap(memory, 64 + TF_AFL_MAP_SIZE); tf_afl_record = NULL; return -1;
    }
    tf_afl_map = (unsigned char *)memory + 64;
    for (size_t i = 0; i < TF_AFL_MAP_SIZE; ++i) {
        if (tf_afl_map[i]) {
            munmap(memory, 64 + TF_AFL_MAP_SIZE); tf_afl_record = NULL;
            tf_afl_map = NULL; return -1;
        }
    }
    tf_afl_input = input;
    return 0;
}

static inline void tf_afl_arm(void) { tf_afl_armed = true; }

static inline void tf_afl_block(unsigned int vcpu, void *userdata)
{
    if (!tf_afl_record || !tf_afl_record->started || vcpu != 0) return;
    uint64_t pc = (uintptr_t)userdata;
    uint32_t location = (uint32_t)((pc >> 4) ^ (pc << 8));
    uint32_t slot = (location ^ tf_afl_previous) & (TF_AFL_MAP_SIZE - 1);
    unsigned char value = (unsigned char)(tf_afl_map[slot] + 1U);
    tf_afl_map[slot] = value ? value : 1;
    tf_afl_previous = location >> 1;
    if (!tf_afl_record->blocks) tf_afl_record->first_pc = pc;
    tf_afl_record->last_pc = pc;
    ++tf_afl_record->blocks;
}

static inline bool tf_afl_path_matches(uint64_t address)
{
    GByteArray *bytes = g_byte_array_new();
    bool equal = true;
    size_t length = strlen(tf_afl_input);
    if (address > UINT32_MAX || length > UINT32_MAX - address) {
        g_byte_array_free(bytes, true); return false;
    }
    for (size_t i = 0; i <= length; ++i) {
        g_byte_array_set_size(bytes, 0);
        if (!qemu_plugin_read_memory_vaddr(address + i, bytes, 1) || bytes->len != 1 ||
            bytes->data[0] != (unsigned char)tf_afl_input[i]) { equal = false; break; }
    }
    g_byte_array_free(bytes, true);
    return equal;
}

/* Single i386 process/vCPU. open/openat, close, read/pread64 are supported. */
static inline void tf_afl_syscall(int64_t number, uint64_t a1, uint64_t a2)
{
    if (!tf_afl_record) return;
    tf_afl_pending = 0;
    if ((number == 5 && tf_afl_path_matches(a1)) ||
        (number == 295 && tf_afl_path_matches(a2))) tf_afl_pending = 1;
    else if (number == 6 && (int64_t)a1 == tf_afl_fd) tf_afl_pending = 2;
    else if ((number == 3 || number == 180) && (int64_t)a1 == tf_afl_fd)
        tf_afl_pending = 3;
    tf_afl_pending_fd = (int64_t)a1;
}

static inline void tf_afl_sysret(qemu_plugin_id_t id, unsigned int vcpu,
                                  int64_t number, int64_t result)
{
    (void)id; (void)number;
    if (!tf_afl_record || vcpu != 0) return;
    if (tf_afl_pending == 1 && result >= 0) tf_afl_fd = result;
    else if (tf_afl_pending == 2 && result == 0 && tf_afl_pending_fd == tf_afl_fd)
        tf_afl_fd = -1;
    else if (tf_afl_pending == 3 && result > 0 && tf_afl_armed && !tf_afl_record->started) {
        tf_afl_previous = 0;
        tf_afl_record->started = 1;
    }
    tf_afl_pending = 0;
}

static inline void tf_afl_finish(void)
{
    if (tf_afl_record) {
        tf_afl_record->finished = 1;
        munmap(tf_afl_record, 64 + TF_AFL_MAP_SIZE);
        tf_afl_record = NULL;
    }
}
#endif
