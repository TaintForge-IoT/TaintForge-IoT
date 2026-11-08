/* File transport only. The tokenizer itself is the unmodified upstream header. */
#include "record.h"

static char input_bytes[TF_MAX_INPUT + 1];
static TfRecord output_record;

static int syscall3(int number, int a, int b, int c) {
    int result;
    __asm__ volatile("int $0x80" : "=a"(result)
        : "a"(number), "b"(a), "c"(b), "d"(c) : "memory", "cc");
    return result;
}

__attribute__((noreturn)) static void finish(int code) {
    syscall3(1, code, 0, 0);
    __builtin_unreachable();
}

__attribute__((noreturn)) void target_main(void) {
    int fd = syscall3(5, (int)TF_INPUT_PATH, 0, 0);
    if (fd < 0) finish(80);
    int size = syscall3(3, fd, (int)input_bytes, TF_MAX_INPUT);
    if (size < 0 || size > (int)TF_MAX_INPUT) finish(81);
    tf_parse_record(input_bytes, (tf_u32)size, &output_record);
    int written = syscall3(4, 1, (int)&output_record, sizeof(output_record));
    finish(written == (int)sizeof(output_record) ? 0 : 82);
}
