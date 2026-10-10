#include "runtime.h"
extern const u8 fixture_table[40960];
static volatile u32 starts;
u8 input[4096], output[32768];
u32 output_length;

static int syscall3(u32 number, u32 a, u32 b, u32 c) {
    int result;
    __asm__ volatile("int $0x80" : "=a"(result) : "0"(number), "b"(a), "c"(b), "d"(c) : "memory", "cc");
    return result;
}

static int write_all(int fd, const u8 *data, u32 length) {
    while (length) {
        int count = syscall3(4, (u32)fd, (u32)data, length);
        if (count == -4) continue;
        if (count <= 0) return -1;
        data += count;
        length -= (u32)count;
    }
    return 0;
}

int read_input(const char *path) {
    int fd = path ? syscall3(5, (u32)path, 0, 0) : 0;
    if (fd < 0) return -1;
    u32 length = 0;
    int result;
    do {
        u8 extra;
        u8 *buffer = length == sizeof(input) ? &extra : input + length;
        u32 capacity = length == sizeof(input) ? 1 : (u32)sizeof(input) - length;
        result = syscall3(3, (u32)fd, (u32)buffer, capacity);
        if (result == -4) continue;
        if (result < 0 || (result > 0 && length == sizeof(input))) { length = 0; result = -1; break; }
        length += (u32)result;
    } while (result != 0);
    if (path) (void)syscall3(6, (u32)fd, 0, 0);
    return result < 0 ? -1 : (int)length;
}

int write_file(const char *path, const u8 *data, u32 length) {
    int fd = syscall3(5, (u32)path, 577, 0600);
    if (fd < 0) return -1;
    int result = write_all(fd, data, length);
    if (syscall3(6, (u32)fd, 0, 0) != 0) result = -1;
    return result;
}

int error(void) { output_length = 0; put_text("ERR\n"); return 2; }
void put_byte(u8 value) { if (output_length < sizeof(output)) output[output_length++] = value; }
void put_text(const char *text) { while (*text) put_byte((u8)*text++); }
void put_uint(u32 value) {
    u8 digits[10]; u32 n = 0;
    do { digits[n++] = (u8)('0' + value % 10); value /= 10; } while (value);
    while (n) put_byte(digits[--n]);
}
void put_int(i32 value) { if (value < 0) { put_byte('-'); put_uint(0u - (u32)value); } else put_uint((u32)value); }
u32 text_length(const char *text) { u32 n = 0; while (text[n]) n++; return n; }
int text_equal(const char *left, const char *right) { while (*left && *left == *right) { left++; right++; } return *left == *right; }
int space(u8 value) { return value == ' ' || value == '\t' || value == '\r' || value == '\n'; }
void skip_space(Cursor *cursor) { while (cursor->at < cursor->length && space(cursor->data[cursor->at])) cursor->at++; }
int uint_value(Cursor *cursor, u32 *value) {
    skip_space(cursor);
    u32 start = cursor->at, n = 0;
    while (cursor->at < cursor->length && cursor->data[cursor->at] >= '0' && cursor->data[cursor->at] <= '9') {
        u32 digit = cursor->data[cursor->at++] - '0';
        if (n > (0xffffffffu - digit) / 10) return 0;
        n = n * 10 + digit;
    }
    *value = n;
    return cursor->at != start;
}
int argument_uint(const char *text, u32 *value) {
    Cursor cursor = { (const u8 *)text, text_length(text), 0 };
    if (!uint_value(&cursor, value)) return 0;
    skip_space(&cursor);
    return cursor.at == cursor.length;
}
u32 fnv(const u8 *data, u32 length) { u32 value = 2166136261u; for (u32 i = 0; i < length; i++) value = (value ^ data[i]) * 16777619u; return value; }

__attribute__((noreturn)) void fixture_entry(int argc, char **argv) {
    int status;
    output_length = 0;
    u32 magic = (u32)fixture_table[0] | (u32)fixture_table[1] << 8 | (u32)fixture_table[2] << 16 | (u32)fixture_table[3] << 24;
    if (starts) { put_text("BADSTATE\n"); status = 4; }
    else if (magic != FIXTURE_TABLE_MAGIC || fixture_table[40959] != FIXTURE_TABLE_TAIL) { put_text("BADTABLE\n"); status = 5; }
    else { starts = 1; status = program_main(argc, argv); }
    if (write_all(1, output, output_length) != 0) status = 3;
    (void)syscall3(1, (u32)status, 0, 0);
    for (;;) { }
}
