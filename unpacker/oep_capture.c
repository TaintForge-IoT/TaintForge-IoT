/* Observe the fixed ELF loader and its tail, stopping before payload execution.
 * Captured bytes are evidence; this plugin never supplies guest memory values. */
#define _GNU_SOURCE
#include "test/qemu_plugin_compat.h"

#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/resource.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;
extern int qemu_plugin_taintforge_user_vmas_v1(uint64_t, uint64_t, uint64_t *, size_t, size_t *, uint32_t *) __attribute__((weak));
extern int qemu_plugin_taintforge_user_entry_v1(uint64_t *, size_t, size_t *, uint64_t *, size_t) __attribute__((weak));
extern int qemu_plugin_taintforge_user_brk_v1(uint64_t *, uint64_t *) __attribute__((weak));

#define ELF_SHA256 "7daac7415a92362184996750d19e878c49b9d5e866690e62851f4589a115bf2e"
#define ELF_BYTES 56256U
/* Authenticated M320 source_load has p_filesz == p_memsz == 51072.
 * The remaining ELF file tail is not part of that guest PT_LOAD mapping. */
#define SOURCE_MAPPED_BYTES 51072U
#define MAX_INSTRUCTIONS UINT64_C(30000000)
#define MAX_CONTEXTS 65536U
#define MAX_EVENT_BYTES (UINT64_C(32) * 1024U * 1024U)
#define MAX_TAIL_INSTRUCTIONS UINT64_C(8192)
#define MAX_TAIL_MEMORY UINT64_C(16384)
#define CHECKPOINT_PC UINT64_C(0x40804915)
#define TRAMPOLINE UINT64_C(0x0805f433)
#define TRAMPOLINE_JMP UINT64_C(0x0805f437)
#define LOADER_RET_PC UINT64_C(0x40804580)
#define PAYLOAD_ENTRY UINT64_C(0x08049096)

typedef struct { uint64_t pc; unsigned size; uint8_t bytes[15]; } Insn;
static const char *reg_names[] = {"eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi", "eflags"};
static struct qemu_plugin_register *reg_handles[9];
static bool reg_present[9];
static GByteArray *memory_buffer, *register_buffer;
static FILE *events;
static GChecksum *event_hash, *path_hash;
static const char *report_path;
static const char *run_id;
static const char *flags_provider = "source_trusted_gdbstub_live_flags";
typedef struct { uint32_t start, size, fd; bool shared; } Mapping;
static Mapping mappings[64];
static unsigned mapping_count;
static int code_fd = -1;
static gchar *file_bytes;
static gsize file_size;
static dev_t guest_device;
static ino_t guest_inode;
static uint32_t initial_entry;
static uint32_t current_registers[9], pending_args[6], pending_mmap[6];
static uint64_t instructions, event_bytes, syscall_entries, syscall_returns;
static uint64_t tail_instructions, tail_memory_events;
static uint64_t pending_number, pending_pc, pending_ordinal;
static uint64_t post_number, post_ordinal;
static unsigned contexts, vcpus;
static Insn *current;
static bool initialized, finished, pending_syscall, pending_mmap_valid, post_pending;
static bool checkpoint_reached, boundary_reached, rx_code_seen, close_code_seen;

static void complete(bool success, const char *reason);

static void reject(const char *reason) {
    fprintf(stderr, "OEP capture: %s after %" PRIu64 " instructions\n", reason, instructions);
    complete(false, reason);
    _Exit(1);
}

static bool write_line(const char *line, bool reserved) {
    size_t size = strlen(line);
    uint64_t limit = reserved ? MAX_EVENT_BYTES : MAX_EVENT_BYTES - 4096;
    if (!events || event_bytes > limit || size > limit - event_bytes ||
        fwrite(line, 1, size, events) != size) return false;
    g_checksum_update(event_hash, (const guchar *)line, size);
    event_bytes += size;
    return true;
}

static void record(const char *format, ...) __attribute__((format(printf, 1, 2)));

static void record(const char *format, ...) {
    va_list args;
    va_start(args, format);
    gchar *line = g_strdup_vprintf(format, args);
    va_end(args);
    if (!line) reject("event_allocation");
    bool ok = write_line(line, false);
    g_free(line);
    if (!ok) reject("event_write_or_budget");
}

static bool read_guest(uint64_t address, uint8_t *bytes, size_t size) {
    if (!memory_buffer || address >= (UINT64_C(1) << 32) ||
        size > (UINT64_C(1) << 32) - address || size > 131072) return false;
    g_byte_array_set_size(memory_buffer, 0);
    if (!qemu_plugin_read_memory_vaddr(address, memory_buffer, size) || memory_buffer->len != size)
        return false;
    memcpy(bytes, memory_buffer->data, size);
    return true;
}

static bool read_u32(uint64_t address, uint32_t *value) {
    uint8_t bytes[4];
    if (!read_guest(address, bytes, sizeof bytes)) return false;
    *value = (uint32_t)bytes[0] | (uint32_t)bytes[1] << 8 |
             (uint32_t)bytes[2] << 16 | (uint32_t)bytes[3] << 24;
    return true;
}

static gchar *to_hex(const uint8_t *bytes, size_t size) {
    static const char digits[] = "0123456789abcdef";
    gchar *hex = g_malloc(size * 2 + 1);
    for (size_t i = 0; i < size; ++i) {
        hex[2*i] = digits[bytes[i] >> 4];
        hex[2*i+1] = digits[bytes[i] & 15];
    }
    hex[2*size] = 0;
    return hex;
}

static void registers(uint32_t values[9]) {
    for (unsigned j = 0; j < 9; ++j) {
        if (!reg_present[j] || !tf_qemu_read_register_exact(reg_handles[j], register_buffer, 4))
            reject("register_read");
        values[j] = (uint32_t)register_buffer->data[0] | (uint32_t)register_buffer->data[1] << 8 |
                    (uint32_t)register_buffer->data[2] << 16 | (uint32_t)register_buffer->data[3] << 24;
    }
}

static gchar *register_json(const uint32_t values[9]) {
    return g_strdup_printf("{\"eax\":%u,\"ecx\":%u,\"edx\":%u,\"ebx\":%u,\"esp\":%u,"
        "\"ebp\":%u,\"esi\":%u,\"edi\":%u,\"eflags\":%u}",
        values[0], values[1], values[2], values[3], values[4], values[5], values[6], values[7], values[8]);
}

static void snapshot_at(const char *label, uint32_t address, unsigned size, uint64_t ordinal) {
    uint8_t *bytes = g_malloc(size);
    if (!read_guest(address, bytes, size)) { g_free(bytes); reject("snapshot_read"); }
    gchar *hex = to_hex(bytes, size);
    record("{\"kind\":\"snapshot\",\"label\":\"%s\",\"address\":%u,\"size\":%u,"
           "\"syscall_ordinal\":%" PRIu64 ",\"bytes_hex\":\"%s\"}\n",
           label, address, size, ordinal, hex);
    g_free(hex);
    g_free(bytes);
}

static void snapshot(const char *label, uint32_t address, unsigned size) {
    snapshot_at(label, address, size, syscall_returns);
}

static void vma_snapshot(const char *phase, uint64_t ordinal) {
    uint64_t data[4096 * 4];
    size_t count = 0;
    uint32_t page_size = 0;
    if (qemu_plugin_taintforge_user_vmas_v1(0, UINT64_C(1) << 32, data, 4096, &count, &page_size) ||
        count > 4096 || page_size != 4096) reject("guest_vma_backend");
    GString *regions = g_string_new("[");
    for (size_t i = 0; i < count; ++i) {
        uint64_t *r = data + i * 4;
        if (r[0] >= r[1] || r[1] > (UINT64_C(1) << 32) || r[0] % 4096 || r[1] % 4096 ||
            r[3] > 7 || (i && data[(i - 1) * 4 + 1] > r[0])) reject("guest_vma_geometry");
        g_string_append_printf(regions, "%s{\"start\":%" PRIu64 ",\"end\":%" PRIu64
            ",\"raw_flags\":%" PRIu64 ",\"prot\":%" PRIu64 "}", i ? "," : "", r[0], r[1], r[2], r[3]);
    }
    g_string_append_c(regions, ']');
    record("{\"kind\":\"vma_snapshot\",\"phase\":\"%s\",\"ordinal\":%" PRIu64
        ",\"page_size\":%u,\"regions\":%s}\n", phase, ordinal, page_size, regions->str);
    g_string_free(regions, TRUE);
}

static void brk_snapshot(const char *phase, uint64_t ordinal) {
    uint64_t initial = 0, current_brk = 0;
    if (qemu_plugin_taintforge_user_brk_v1(&initial, &current_brk) || initial > UINT32_MAX ||
        current_brk > UINT32_MAX) reject("brk_backend");
    record("{\"kind\":\"brk\",\"phase\":\"%s\",\"ordinal\":%" PRIu64
        ",\"initial\":%" PRIu64 ",\"current\":%" PRIu64 "}\n", phase, ordinal, initial, current_brk);
}

static void entry_construction(void) {
    uint64_t words[1024 * 3], meta[8] = {0};
    size_t count = 0;
    if (qemu_plugin_taintforge_user_entry_v1(words, 1024, &count, meta, 8) || count > 1024 ||
        meta[0] != 1 || meta[1] != 4 || meta[2] != current_registers[4] ||
        meta[5] != initial_entry || meta[7]) reject("entry_constructor_backend");
    GString *records = g_string_new("[");
    for (size_t i = 0; i < count; ++i) {
        uint64_t *w = words + i * 3;
        if (w[0] > UINT32_MAX - 3U || w[1] > UINT32_MAX || w[2] < 1 || w[2] > 4)
            reject("entry_constructor_word");
        uint32_t observed;
        if (!read_u32(w[0], &observed) || observed != w[1]) reject("entry_constructor_RAM_mismatch");
        g_string_append_printf(records, "%s[%" PRIu64 ",%" PRIu64 ",%" PRIu64 "]", i ? "," : "", w[0], w[1], w[2]);
    }
    g_string_append_c(records, ']');
    record("{\"kind\":\"entry_construction\",\"metadata\":[%" PRIu64 ",%" PRIu64 ",%" PRIu64
        ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 "],\"words\":%s}\n",
        meta[0], meta[1], meta[2], meta[3], meta[4], meta[5], meta[6], meta[7], records->str);
    g_string_free(records, TRUE);
}

static const char *fd_access(int flags) {
    switch (flags & O_ACCMODE) {
    case O_RDONLY: return "read";
    case O_WRONLY: return "write";
    case O_RDWR: return "read_write";
    default: reject("fd_access_mode"); return "";
    }
}

static void fd_initial(void) {
    struct rlimit limit;
    if (getrlimit(RLIMIT_NOFILE, &limit) || limit.rlim_cur > 4096) reject("initial_fd_scan_bound");
    GString *records = g_string_new("[");
    bool first = true;
    for (unsigned fd = 0; fd < limit.rlim_cur; ++fd) {
        errno = 0;
        int descriptor_flags = fcntl((int)fd, F_GETFD);
        if (descriptor_flags < 0) {
            if (errno == EBADF) continue;
            reject("initial_fd_flags");
        }
        int flags = fcntl((int)fd, F_GETFL);
        struct stat st;
        if (flags < 0 || fstat((int)fd, &st) || st.st_size < 0) reject("initial_fd_stat");
        errno = 0;
        off_t offset = lseek((int)fd, 0, SEEK_CUR);
        if (offset < 0 && errno != ESPIPE) reject("initial_fd_position");
        gchar *position = offset < 0 ? g_strdup("null") : g_strdup_printf("%" PRIuMAX, (uintmax_t)offset);
        g_string_append_printf(records, "%s{\"fd\":%u,\"file_id\":\"stat:%" PRIuMAX ":%" PRIuMAX
            "\",\"dev\":%" PRIuMAX ",\"ino\":%" PRIuMAX ",\"mode\":%u,\"size\":%" PRIuMAX
            ",\"access\":\"%s\",\"position\":%s,\"seekable\":%s,\"cloexec\":%s}",
            first ? "" : ",", fd, (uintmax_t)st.st_dev, (uintmax_t)st.st_ino, (uintmax_t)st.st_dev,
            (uintmax_t)st.st_ino, (unsigned)st.st_mode, (uintmax_t)st.st_size, fd_access(flags), position,
            offset < 0 ? "false" : "true", descriptor_flags & FD_CLOEXEC ? "true" : "false");
        g_free(position);
        first = false;
    }
    g_string_append_c(records, ']');
    record("{\"kind\":\"fd_initial\",\"limit\":%u,\"observer_fd\":%d,\"descriptors\":%s}\n",
        (unsigned)limit.rlim_cur, fileno(events), records->str);
    g_string_free(records, TRUE);
}

static void file_snapshot(const char *phase, unsigned fd, uint64_t ordinal) {
    struct stat st;
    int flags = fcntl((int)fd, F_GETFL);
    if (flags < 0 || fstat((int)fd, &st) || !S_ISREG(st.st_mode) ||
        (flags & O_ACCMODE) == O_WRONLY || st.st_size < 0 || st.st_size > 1024 * 1024)
        reject("selected_file_snapshot_extent_or_access");
    size_t size = (size_t)st.st_size;
    uint8_t *bytes = g_malloc(size ? size : 1);
    size_t done = 0;
    while (done < size) {
        ssize_t n = pread((int)fd, bytes + done, size - done, (off_t)done);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) reject("selected_file_snapshot_read");
        done += (size_t)n;
    }
    off_t offset = lseek((int)fd, 0, SEEK_CUR);
    if (offset < 0) reject("selected_file_snapshot_position");
    gchar *hex = to_hex(bytes, size);
    record("{\"kind\":\"file_snapshot\",\"phase\":\"%s\",\"ordinal\":%" PRIu64
        ",\"fd\":%u,\"file_id\":\"stat:%" PRIuMAX ":%" PRIuMAX "\",\"dev\":%" PRIuMAX
        ",\"ino\":%" PRIuMAX ",\"mode\":%u,\"size\":%zu,\"position\":%" PRIuMAX ",\"bytes_hex\":\"%s\"}\n",
        phase, ordinal, fd, (uintmax_t)st.st_dev, (uintmax_t)st.st_ino, (uintmax_t)st.st_dev,
        (uintmax_t)st.st_ino, (unsigned)st.st_mode, size, (uintmax_t)offset, hex);
    g_free(hex);
    g_free(bytes);
}

static void invalidate_mappings(uint32_t address, uint32_t size) {
    uint64_t end = ((uint64_t)address + size + 4095) & ~UINT64_C(4095);
    for (unsigned i = 0; i < mapping_count; ++i) {
        Mapping *m = mappings + i;
        if (m->size && address < (uint64_t)m->start + m->size && m->start < end) m->size = 0;
    }
}

static void changed_range(const char *prefix, uint32_t address, uint32_t size) {
    if (address % 4096 || !size || (uint64_t)address + size > (UINT64_C(1) << 32))
        reject("effect_snapshot_geometry");
    uint64_t rounded = ((uint64_t)size + 4095) & ~UINT64_C(4095);
    if (rounded > 131072) reject("effect_snapshot_bound");
    char label[80];
    snprintf(label, sizeof label, "%s_%" PRIu64, prefix, pending_ordinal);
    snapshot_at(label, address, (unsigned)rounded, pending_ordinal);
}

static void initialize(Insn *insn) {
    const char *binary_path = qemu_plugin_path_to_binary();
    struct stat st;
    bool matched = binary_path && !stat(binary_path, &st) &&
                   st.st_dev == guest_device && st.st_ino == guest_inode;
    g_free((gpointer)binary_path);
    if (!matched || insn->pc != initial_entry) reject("runtime_binary_or_entry_identity");
    GArray *regs = qemu_plugin_get_registers();
    if (!regs) reject("register_enumeration");
    for (guint i = 0; i < regs->len; ++i) {
        qemu_plugin_reg_descriptor *reg = &g_array_index(regs, qemu_plugin_reg_descriptor, i);
        for (unsigned j = 0; j < 9; ++j) {
            if (reg->name && !g_ascii_strcasecmp(reg->name, reg_names[j])) {
                if (reg_present[j]) reject("duplicate_register");
                reg_present[j] = true;
                reg_handles[j] = reg->handle;
            }
        }
    }
    g_array_free(regs, TRUE);
    registers(current_registers);
    initialized = true;
    record("{\"kind\":\"header\",\"capture_kind\":\"OEP_ENVIRONMENT_CAPTURE_V1\",\"schema_version\":1,\"elf_sha256\":\"%s\","
           "\"elf_size\":%zu,\"qemu_plugin_api_version\":%d,\"qemu_flags_verified\":false,"
           "\"eflags_provider_verified\":false,\"eflags_provider\":\"%s\","
           "\"run_id\":\"%s\",\"guest_vma_api_version\":1,\"entry_construction_api_version\":1,\"brk_api_version\":1,\"executed_pc_hash_encoding\":\"LE32_EXECUTED_PC\",\"initial_pc\":%u,\"initial_sp\":%u,\"initial_df\":%u,"
           "\"binary_path_matches\":true,\"captured_execution_only\":true}\n",
           ELF_SHA256, (size_t)file_size, QEMU_PLUGIN_VERSION, flags_provider,
           run_id, initial_entry, current_registers[4], (current_registers[8] >> 10) & 1);
    gchar *regs_json = register_json(current_registers);
    record("{\"kind\":\"initial\",\"pc\":%u,\"registers\":%s}\n", initial_entry, regs_json);
    g_free(regs_json);
    entry_construction();
    fd_initial();
    vma_snapshot("initial", 0);
    brk_snapshot("initial", 0);
    snapshot("initial_image", 0x08048000, 118784);
    snapshot("initial_stack", 0x407fc000, 20480);
    snapshot("initial_source", 0x08065000, SOURCE_MAPPED_BYTES);
}

static void complete(bool success, const char *reason) {
    if (finished) return;
    finished = true;
    if (!events || !event_hash) return;
    GChecksum *prefix = g_checksum_copy(event_hash);
    gchar *prefix_hash = g_strdup(g_checksum_get_string(prefix));
    g_checksum_free(prefix);
    gchar *footer = g_strdup_printf("{\"kind\":\"footer\",\"success\":%s,\"reason\":\"%s\","
        "\"instructions\":%" PRIu64 ",\"syscall_count\":%" PRIu64 ",\"syscall_returns\":%" PRIu64 ","
        "\"tail_instructions\":%" PRIu64 ",\"tail_memory_events\":%" PRIu64 ","
        "\"checkpoint_reached\":%s,\"payload_entry_reached\":%s,\"boundary_reached\":%s,"
        "\"stopped_before_instruction\":%s,\"target_instruction_executed\":false,"
        "\"qemu_flags_verified\":%s,\"executed_pc_sha256\":\"%s\",\"run_id\":\"%s\","
        "\"guest_permissions_independently_observed\":true,\"kernel_implementation_verified\":false,"
        "\"independent_OS_entry_origins_proven\":false,\"oep_proof\":\"NOT_ESTABLISHED\","
        "\"events_bytes_before_footer\":%" PRIu64 ",\"events_sha256_before_footer\":\"%s\"}\n",
        success ? "true" : "false", reason, instructions, syscall_entries, syscall_returns,
        tail_instructions, tail_memory_events, checkpoint_reached ? "true" : "false",
        boundary_reached ? "true" : "false", boundary_reached ? "true" : "false",
        boundary_reached ? "true" : "false", "false", g_checksum_get_string(path_hash), run_id, event_bytes, prefix_hash);
    g_free(prefix_hash);
    bool durable = footer && write_line(footer, true) && !fflush(events) && !fsync(fileno(events));
    g_free(footer);
    if (!durable) { fprintf(stderr, "OEP capture: footer flush failed\n"); return; }
    FILE *report = report_path ? fopen(report_path, "wb") : NULL;
    if (!report) { fprintf(stderr, "OEP capture: report open failed\n"); return; }
    int count = fprintf(report, "{\"schema_version\":1,\"capture_kind\":\"OEP_ENVIRONMENT_CAPTURE_V1\","
        "\"success\":%s,\"reason\":\"%s\",\"instructions\":%" PRIu64 ","
        "\"syscall_count\":%" PRIu64 ",\"syscall_returns\":%" PRIu64 ","
        "\"tail_instructions\":%" PRIu64 ",\"tail_memory_events\":%" PRIu64 ","
        "\"events_bytes\":%" PRIu64 ",\"events_sha256\":\"%s\","
        "\"checkpoint_reached\":%s,\"payload_entry_reached\":%s,\"boundary_reached\":%s,"
        "\"target_instruction_executed\":false,\"qemu_flags_verified\":%s,"
        "\"eflags_provider_verified\":%s,\"captured_execution_only\":true,"
        "\"guest_permissions_independently_observed\":true,\"kernel_implementation_verified\":false,"
        "\"independent_OS_entry_origins_proven\":false,\"executed_pc_sha256\":\"%s\","
        "\"run_id\":\"%s\",\"oep_proof\":\"NOT_ESTABLISHED\"}\n",
        success ? "true" : "false", reason, instructions, syscall_entries, syscall_returns,
        tail_instructions, tail_memory_events, event_bytes, g_checksum_get_string(event_hash),
        checkpoint_reached ? "true" : "false", boundary_reached ? "true" : "false",
        boundary_reached ? "true" : "false", "false",
        "false", g_checksum_get_string(path_hash), run_id);
    if (count < 0 || fflush(report) || fsync(fileno(report))) { fclose(report); _Exit(1); }
    fclose(report);
}

static void checkpoint_snapshots(void) {
    uint8_t code[6685];
    if (!read_guest(0x40804000, code, sizeof code)) reject("checkpoint_code_read");
    gchar *hash = g_compute_checksum_for_data(G_CHECKSUM_SHA256, code, sizeof code);
    bool equal = hash && !strcmp(hash, "eb88e775c07b29445a79fd017853b828c49e42c68d2fccc2cdf9662959e687ad");
    g_free(hash);
    if (!equal) reject("checkpoint_private_code_identity");
    snapshot("checkpoint_code", 0x08049000, 94208);
    snapshot("checkpoint_rodata", 0x08060000, 12288);
    snapshot("checkpoint_data", 0x08063000, 8192);
    snapshot("checkpoint_header", 0x08048000, 4096);
    snapshot("checkpoint_stack", 0x407fc000, 20480);
    snapshot("checkpoint_private", 0x40804000, 8192);
    snapshot("checkpoint_source", 0x08065000, SOURCE_MAPPED_BYTES);
}

static bool trampoline_instruction(const Insn *insn) {
    static const uint8_t bytes[] = {0xcd, 0x80, 0x61, 0x58, 0x3e, 0xff, 0xe0};
    unsigned offset, size;
    if (insn->pc == TRAMPOLINE) { offset = 0; size = 2; }
    else if (insn->pc == TRAMPOLINE + 2) { offset = 2; size = 1; }
    else if (insn->pc == TRAMPOLINE + 3) { offset = 3; size = 1; }
    else if (insn->pc == TRAMPOLINE_JMP) { offset = 4; size = 3; }
    else return false;
    return insn->size == size && !memcmp(insn->bytes, bytes + offset, size);
}

static void execute(unsigned cpu, void *userdata) {
    Insn *insn = userdata;
    if (cpu || !insn) reject("instruction_vcpu_or_context");
    if (pending_syscall) reject("instruction_during_syscall");
    if (!initialized) initialize(insn);
    uint32_t now[9] = {0};
    bool int80 = insn->size == 2 && insn->bytes[0] == 0xcd && insn->bytes[1] == 0x80;
    if (post_pending || int80 || insn->pc == CHECKPOINT_PC || checkpoint_reached) registers(now);
    if (post_pending) {
        gchar *reg_json = register_json(now);
        record("{\"kind\":\"syscall_post\",\"ordinal\":%" PRIu64 ",\"pc\":%" PRIu64 ","
               "\"number\":%" PRIu64 ",\"registers\":%s}\n", post_ordinal, insn->pc, post_number, reg_json);
        g_free(reg_json);
        post_pending = false;
    }
    uint8_t actual[15];
    if (!read_guest(insn->pc, actual, insn->size) || memcmp(actual, insn->bytes, insn->size))
        reject("current_instruction_bytes");
    if (insn->pc == PAYLOAD_ENTRY) {
        if (!checkpoint_reached || !current || current->pc != TRAMPOLINE_JMP ||
            syscall_entries != 26 || syscall_returns != 26 || !tail_instructions)
            reject("payload_boundary_predecessor_or_syscall_count");
        boundary_reached = true;
        vma_snapshot("payload_entry", syscall_returns);
        brk_snapshot("payload_entry", syscall_returns);
        snapshot("payload_code", 0x08049000, 94208);
        snapshot("payload_rodata", 0x08060000, 12288);
        snapshot("payload_data", 0x08063000, 8192);
        snapshot("payload_header", 0x08048000, 4096);
        snapshot("payload_stack", 0x407fc000, 20480);
        gchar *reg_json = register_json(now);
        record("{\"kind\":\"payload_entry\",\"pc\":%" PRIu64 ",\"previous_pc\":%" PRIu64 ","
               "\"registers\":%s,\"instructions\":%" PRIu64 ",\"syscall_count\":%" PRIu64 ","
               "\"tail_instructions\":%" PRIu64 ",\"tail_memory_events\":%" PRIu64 ","
               "\"stopped_before_instruction\":true,\"target_instruction_executed\":false}\n",
               insn->pc, current->pc, reg_json, instructions, syscall_entries, tail_instructions, tail_memory_events);
        g_free(reg_json);
        complete(true, "payload_entry_boundary");
        _Exit(0);
    }
    if (insn->pc == CHECKPOINT_PC) {
        if (checkpoint_reached || !current || current->pc != LOADER_RET_PC ||
            syscall_entries != 21 || syscall_returns != 21) reject("checkpoint_predecessor_or_syscall_count");
        checkpoint_snapshots();
        checkpoint_reached = true;
        gchar *reg_json = register_json(now);
        record("{\"kind\":\"checkpoint\",\"pc\":%" PRIu64 ",\"previous_pc\":%" PRIu64 ","
               "\"registers\":%s,\"instructions\":%" PRIu64 ",\"syscall_count\":%" PRIu64 ","
               "\"continued_after_checkpoint\":true}\n",
               insn->pc, current->pc, reg_json, instructions, syscall_entries);
        g_free(reg_json);
    }
    if (checkpoint_reached) {
        bool private_code = insn->pc >= 0x40804000 && insn->pc + insn->size <= 0x40804000 + 6685;
        if (!private_code && !trampoline_instruction(insn)) reject("tail_execution_outside_original_code_or_trampoline");
        if (tail_instructions >= MAX_TAIL_INSTRUCTIONS) reject("tail_instruction_budget");
        ++tail_instructions;
        gchar *reg_json = register_json(now), *hex = to_hex(insn->bytes, insn->size);
        record("{\"kind\":\"tail_insn\",\"tail_ordinal\":%" PRIu64 ",\"pc\":%" PRIu64 ","
               "\"size\":%u,\"bytes_hex\":\"%s\",\"registers\":%s}\n",
               tail_instructions, insn->pc, insn->size, hex, reg_json);
        g_free(reg_json); g_free(hex);
    } else if (insn->pc >= 0x08048000 && insn->pc < 0x08065000) {
        reject("premature_payload_execution_forbidden");
    }
    if (instructions >= MAX_INSTRUCTIONS) reject("instruction_budget");
    ++instructions;
    uint8_t encoded_pc[4];
    for (unsigned i = 0; i < 4; ++i) encoded_pc[i] = (uint8_t)(insn->pc >> (8 * i));
    g_checksum_update(path_hash, encoded_pc, sizeof encoded_pc);
    current = insn;
    if (int80) memcpy(current_registers, now, sizeof current_registers);
}

static void memory(unsigned cpu, qemu_plugin_meminfo_t info, uint64_t address, void *userdata) {
    if (!checkpoint_reached) return;
    if (cpu || !current || current != userdata || !tail_instructions || pending_syscall)
        reject("tail_memory_context");
    unsigned shift = qemu_plugin_mem_size_shift(info);
    if (shift > 4 || address >= (UINT64_C(1) << 32)) reject("tail_memory_width_or_address");
    unsigned size = 1U << shift;
    if (size > (UINT64_C(1) << 32) - address || qemu_plugin_mem_is_big_endian(info))
        reject("tail_memory_wrapping_or_endian");
    qemu_plugin_mem_value value = qemu_plugin_mem_get_value(info);
    if (value.type != (enum qemu_plugin_mem_value_type)shift) reject("tail_memory_value_width");
    uint64_t low = 0, high = 0;
    switch (value.type) {
    case QEMU_PLUGIN_MEM_VALUE_U8: low = value.data.u8; break;
    case QEMU_PLUGIN_MEM_VALUE_U16: low = value.data.u16; break;
    case QEMU_PLUGIN_MEM_VALUE_U32: low = value.data.u32; break;
    case QEMU_PLUGIN_MEM_VALUE_U64: low = value.data.u64; break;
    case QEMU_PLUGIN_MEM_VALUE_U128: low = value.data.u128.low; high = value.data.u128.high; break;
    default: reject("tail_memory_value_kind");
    }
    if (tail_memory_events >= MAX_TAIL_MEMORY) reject("tail_memory_event_budget");
    uint8_t bytes[16];
    for (unsigned i = 0; i < size; ++i) bytes[i] = (uint8_t)((i < 8 ? low : high) >> (8*(i%8)));
    gchar *hex = to_hex(bytes, size);
    record("{\"kind\":\"tail_memory\",\"ordinal\":%" PRIu64 ",\"tail_ordinal\":%" PRIu64 ","
           "\"pc\":%" PRIu64 ",\"address\":%" PRIu64 ",\"size\":%u,\"store\":%s,"
           "\"value_hex\":\"%s\"}\n",
           ++tail_memory_events, tail_instructions, current->pc, address, size,
           qemu_plugin_mem_is_store(info) ? "true" : "false", hex);
    g_free(hex);
}

static void translate(qemu_plugin_id_t id, struct qemu_plugin_tb *tb) {
    (void)id;
    for (size_t i = 0; i < qemu_plugin_tb_n_insns(tb); ++i) {
        if (++contexts > MAX_CONTEXTS) reject("translation_context_budget");
        struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);
        Insn *context = g_new0(Insn, 1);
        context->pc = qemu_plugin_insn_vaddr(insn);
        context->size = (unsigned)qemu_plugin_insn_size(insn);
        if (!context->size || context->size > sizeof context->bytes ||
            qemu_plugin_insn_data(insn, context->bytes, context->size) != context->size)
            reject("translated_instruction_extent");
        qemu_plugin_register_vcpu_insn_exec_cb(insn, execute, QEMU_PLUGIN_CB_R_REGS, context);
        qemu_plugin_register_vcpu_mem_cb(insn, memory, QEMU_PLUGIN_CB_NO_REGS, QEMU_PLUGIN_MEM_RW, context);
    }
}

static void vcpu_init(qemu_plugin_id_t id, unsigned cpu) {
    (void)id;
    if (++vcpus != 1 || cpu) reject("multiple_vcpus");
}

static gchar *read_path(uint32_t address) {
    uint8_t bytes[4096];
    for (unsigned i = 0; i < sizeof bytes; ++i) {
        if (!read_guest((uint64_t)address + i, bytes+i, 1)) return NULL;
        if (!bytes[i]) return to_hex(bytes, i);
    }
    return NULL;
}

static void syscall_enter(qemu_plugin_id_t id, unsigned cpu, int64_t number,
                          uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4,
                          uint64_t a5, uint64_t a6, uint64_t a7, uint64_t a8) {
    (void)id; (void)a7; (void)a8;
    if (cpu || !initialized || !current || pending_syscall || post_pending ||
        number < 0 || number > UINT32_MAX || current->size != 2 ||
        current->bytes[0] != 0xcd || current->bytes[1] != 0x80 || syscall_entries >= 26)
        reject("syscall_context_or_budget");
    if (syscall_entries >= 21) {
        static const uint32_t tail_numbers[] = {45, 91, 192, 6, 91};
        unsigned index = (unsigned)(syscall_entries - 21);
        if (!checkpoint_reached || index >= 5 || (uint64_t)number != tail_numbers[index] ||
            (index == 4 ? current->pc != TRAMPOLINE : current->pc != UINT64_C(0x40805875)))
            reject("unexpected_tail_syscall_identity");
    } else if (checkpoint_reached) reject("premature_tail_syscall");
    uint32_t args[6] = {(uint32_t)a1, (uint32_t)a2, (uint32_t)a3, (uint32_t)a4, (uint32_t)a5, (uint32_t)a6};
    pending_number = (uint64_t)number;
    pending_pc = current->pc;
    pending_ordinal = ++syscall_entries;
    pending_syscall = true;
    memcpy(pending_args, args, sizeof args);
    pending_mmap_valid = number == 90 || number == 192;
    if (number == 90) {
        for (unsigned i = 0; i < 6; ++i)
            if (!read_u32((uint64_t)args[0] + 4*i, pending_mmap+i)) reject("old_mmap_argument_read");
    } else if (number == 192) memcpy(pending_mmap, args, sizeof pending_mmap);
    gchar *mmap_json = pending_mmap_valid ? g_strdup_printf("[%u,%u,%u,%u,%u,%u]",
        pending_mmap[0], pending_mmap[1], pending_mmap[2], pending_mmap[3], pending_mmap[4], pending_mmap[5]) : g_strdup("null");
    gchar *path = NULL;
    if (number == 5 || number == 85 || number == 356) {
        path = read_path(args[0]);
        if (!path) reject("syscall_path_read");
    }
    gchar *path_json = path ? g_strdup_printf("\"%s\"", path) : g_strdup("null");
    gchar *regs_json = register_json(current_registers);
    record("{\"kind\":\"syscall_enter\",\"ordinal\":%" PRIu64 ",\"pc\":%" PRIu64 ","
           "\"number\":%" PRIu64 ",\"args\":[%u,%u,%u,%u,%u,%u],\"mmap_args\":%s,"
           "\"path_hex\":%s,\"registers\":%s}\n", pending_ordinal, pending_pc, pending_number,
           args[0], args[1], args[2], args[3], args[4], args[5], mmap_json, path_json, regs_json);
    g_free(mmap_json); g_free(path); g_free(path_json); g_free(regs_json);
    if (number == 4) {
        if (args[2] > 131072) reject("write_buffer_snapshot_bound");
        char label[80];
        snprintf(label, sizeof label, "write_buffer_%" PRIu64, pending_ordinal);
        snapshot_at(label, args[1], args[2], pending_ordinal);
    } else if (number == 6) file_snapshot("syscall_enter", args[0], pending_ordinal);
}

static void mapping_snapshots(uint32_t result) {
    if (!pending_mmap_valid || result >= 0xfffff001U || result != pending_mmap[0]) return;
    uint32_t address = pending_mmap[0], length = pending_mmap[1], prot = pending_mmap[2];
    if (address == 0x08048000 && length == 308 && prot == 3 && pending_mmap[3] == 0x32)
        snapshot("post_mmap_8048000", address, 4096);
    else if (address == 0x08049000 && prot == 3 && pending_mmap[3] == 0x11 &&
             length <= 94208 && length > 90112)
        snapshot("post_rw_code", address, 94208);
    else if (address == 0x08060000 && length == 11432)
        snapshot("post_mmap_8060000", address, 12288);
    else if (address == 0x08063000 && length == 4664)
        snapshot("post_mmap_8063000", address, 8192);
    else if (address == 0x08049000 && (prot & 4) && length <= 94208 && length > 90112) {
        if (rx_code_seen) reject("duplicate_rx_code_mapping");
        rx_code_seen = true;
        snapshot("post_rx_code", address, 94208);
    }
}

static void syscall_return(qemu_plugin_id_t id, unsigned cpu, int64_t number, int64_t result) {
    (void)id;
    if (cpu || !pending_syscall || number < 0 || (uint64_t)number != pending_number)
        reject("syscall_return_context");
    uint32_t result_u32 = (uint32_t)result;
    gchar *reply = NULL;
    if (number == 85 && (int32_t)result_u32 > 0) {
        if (result_u32 > 4096 || result_u32 > pending_args[2]) reject("readlink_reply_extent");
        uint8_t bytes[4096];
        if (!read_guest(pending_args[1], bytes, result_u32)) reject("readlink_reply_read");
        reply = to_hex(bytes, result_u32);
    }
    gchar *reply_json = reply ? g_strdup_printf("\"%s\"", reply) : g_strdup("null");
    record("{\"kind\":\"syscall_return\",\"ordinal\":%" PRIu64 ",\"pc\":%" PRIu64 ","
           "\"number\":%" PRIu64 ",\"result_u32\":%u,\"reply_hex\":%s}\n",
           pending_ordinal, pending_pc, pending_number, result_u32, reply_json);
    g_free(reply); g_free(reply_json);
    ++syscall_returns;
    mapping_snapshots(result_u32);
    if (number == 192 && pending_ordinal == 24 && result_u32 < 0xfffff001U &&
        !(result_u32 & 4095U))
        snapshot("post_mmap2_header", result_u32, 4096);
    if (number == 6 && code_fd >= 0 && pending_args[0] == (uint32_t)code_fd && result_u32 == 0 && rx_code_seen) {
        if (close_code_seen) reject("duplicate_post_rx_close");
        close_code_seen = true;
        snapshot("post_close_code", 0x08049000, 94208);
    }
    if (result_u32 < 0xfffff001U) {
        if (pending_mmap_valid) {
            uint32_t *a = pending_mmap;
            invalidate_mappings(result_u32, a[1]);
            if (mapping_count == 64) reject("effect_mapping_budget");
            uint64_t rounded = ((uint64_t)a[1] + 4095) & ~UINT64_C(4095);
            if (!rounded || rounded > UINT32_MAX) reject("effect_mapping_extent");
            mappings[mapping_count++] = (Mapping){result_u32, (uint32_t)rounded, a[4], (a[3] & 3) == 1};
            if (a[2] & 1) changed_range("syscall_mapping", result_u32, a[1]);
            if (!(a[3] & 32)) file_snapshot("syscall_return", a[4], pending_ordinal);
            if (result_u32 == 0x08049000 && a[2] == 3 && !(a[3] & 32)) code_fd = (int)a[4];
        } else if (number == 4) {
            file_snapshot("syscall_return", pending_args[0], pending_ordinal);
            for (unsigned i = 0; i < mapping_count; ++i) {
                Mapping *m = mappings + i;
                if (m->size && m->shared && m->fd == pending_args[0])
                    changed_range("syscall_memory", m->start, m->size);
            }
        } else if (number == 356 || number == 5) file_snapshot("syscall_return", result_u32, pending_ordinal);
        else if (number == 93) file_snapshot("syscall_return", pending_args[0], pending_ordinal);
        else if (number == 91) invalidate_mappings(pending_args[0], pending_args[1]);
        else if (number == 125 && (pending_args[2] & 1))
            changed_range("syscall_memory", pending_args[0], pending_args[1]);
        else if (number == 144) {
            changed_range("syscall_memory", pending_args[0], pending_args[1]);
            for (unsigned i = 0; i < mapping_count; ++i) {
                Mapping *m = mappings + i;
                if (m->size && m->shared && pending_args[0] < (uint64_t)m->start + m->size &&
                    m->start < (uint64_t)pending_args[0] + pending_args[1])
                    file_snapshot("syscall_return", m->fd, pending_ordinal);
            }
        }
    }
    vma_snapshot("syscall_return", pending_ordinal);
    brk_snapshot("syscall_return", pending_ordinal);
    pending_syscall = false;
    post_pending = true;
    post_number = pending_number;
    post_ordinal = pending_ordinal;
}

static void finish(qemu_plugin_id_t id, void *unused) {
    (void)id; (void)unused;
    if (!finished) complete(false, initialized ? "guest_exited_before_boundary" : "guest_not_initialized");
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id, const qemu_info_t *info,
                                          int argc, char **argv) {
    const char *guest_path = NULL, *events_path = NULL;
    if (!info || info->system_emulation || strcmp(info->target_name, "i386") ||
        !qemu_plugin_taintforge_user_vmas_v1 || !qemu_plugin_taintforge_user_entry_v1 ||
        !qemu_plugin_taintforge_user_brk_v1) return -1;
    for (int i = 0; i < argc; ++i) {
        if (!strncmp(argv[i], "guest=", 6) && !guest_path) guest_path = argv[i]+6;
        else if (!strncmp(argv[i], "events=", 7) && !events_path) events_path = argv[i]+7;
        else if (!strncmp(argv[i], "report=", 7) && !report_path) report_path = argv[i]+7;
        else if (!strncmp(argv[i], "run-id=", 7) && !run_id) run_id = argv[i]+7;
        else return -1;
    }
    if (!run_id || strlen(run_id) != 32 || strspn(run_id, "0123456789abcdef") != 32 ||
        !guest_path || !*guest_path || !events_path || !*events_path || !report_path || !*report_path ||
        !strcmp(guest_path, events_path) || !strcmp(guest_path, report_path) || !strcmp(events_path, report_path))
        return -1;
    struct stat st;
    if (stat(guest_path, &st) || !S_ISREG(st.st_mode)) return -1;
    guest_device = st.st_dev; guest_inode = st.st_ino;
    if (!g_file_get_contents(guest_path, &file_bytes, &file_size, NULL) || file_size != ELF_BYTES) return -1;
    gchar *hash = g_compute_checksum_for_data(G_CHECKSUM_SHA256, (const guchar *)file_bytes, file_size);
    bool identity = hash && !strcmp(hash, ELF_SHA256);
    g_free(hash);
    if (!identity || memcmp(file_bytes, ELFMAG, SELFMAG) || file_bytes[EI_CLASS] != ELFCLASS32 ||
        file_bytes[EI_DATA] != ELFDATA2LSB) return -1;
    const uint8_t *header = (const uint8_t *)file_bytes;
    if ((header[16] | (unsigned)header[17] << 8) != ET_EXEC ||
        (header[18] | (unsigned)header[19] << 8) != EM_386) return -1;
    initial_entry = (uint32_t)header[24] | (uint32_t)header[25] << 8 |
                    (uint32_t)header[26] << 16 | (uint32_t)header[27] << 24;
    report_path = g_strdup(report_path);
    run_id = g_strdup(run_id);
    events = fopen(events_path, "wb");
    if (!events) return -1;
    event_hash = g_checksum_new(G_CHECKSUM_SHA256);
    path_hash = g_checksum_new(G_CHECKSUM_SHA256);
    memory_buffer = g_byte_array_new(); register_buffer = g_byte_array_new();
    if (!event_hash || !path_hash || !memory_buffer || !register_buffer) return -1;
    TfQemuPluginCallbacks callbacks = {.vcpu_init=vcpu_init, .translate=translate,
        .syscall=syscall_enter, .syscall_ret=syscall_return, .finish=finish};
    tf_qemu_register_callbacks(id, &callbacks);
    return 0;
}
