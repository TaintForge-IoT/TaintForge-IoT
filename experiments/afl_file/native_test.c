/* Benign unit harness: the real coverage code with a mocked guest memory API. */
#define _GNU_SOURCE
#include <assert.h>
#include <qemu-plugin.h>
#include "coverage.h"

bool qemu_plugin_read_memory_vaddr(uint64_t address, GByteArray *bytes, size_t size)
{
    const char *path = "/etc/afl-input";
    if (size != 1 || address < 0x1000 || address > 0x1000 + strlen(path)) return false;
    g_byte_array_append(bytes, (const unsigned char *)path + address - 0x1000, 1);
    return true;
}

int main(int argc, char **argv)
{
    if (argc != 2 || tf_afl_open_map(argv[1], "/etc/afl-input")) return 2;
    tf_afl_block(0, (void *)(uintptr_t)0x8049000);
    assert(!tf_afl_record->started && !tf_afl_record->blocks);
    tf_afl_syscall(5, 0x1000, 0); tf_afl_sysret(0, 0, 5, 7);
    tf_afl_syscall(3, 7, 0); tf_afl_sysret(0, 0, 3, 4);
    assert(!tf_afl_record->started);  /* read before RESUME2 */
    tf_afl_arm();
    tf_afl_syscall(3, 8, 0); tf_afl_sysret(0, 0, 3, 4);
    assert(!tf_afl_record->started);  /* unrelated file descriptor */
    tf_afl_syscall(3, 7, 0); tf_afl_sysret(0, 0, 3, -1);
    assert(!tf_afl_record->started);  /* failed read */
    tf_afl_syscall(3, 7, 0); tf_afl_sysret(0, 0, 3, 0);
    assert(!tf_afl_record->started);  /* EOF */
    tf_afl_syscall(3, 7, 0); tf_afl_sysret(0, 0, 3, 4);
    assert(tf_afl_record->started);
    for (unsigned i = 0; i < 10000; ++i) tf_afl_block(0, (void *)(uintptr_t)0x8049000);
    assert(tf_afl_record->blocks == 10000);
    for (unsigned i = 0; i < TF_AFL_MAP_SIZE; ++i)
        if (tf_afl_map[i]) assert(tf_afl_map[i] >= 1);
    tf_afl_syscall(6, 7, 0); tf_afl_sysret(0, 0, 6, 0);
    assert(tf_afl_fd == -1);
    tf_afl_finish();
    return 0;
}
