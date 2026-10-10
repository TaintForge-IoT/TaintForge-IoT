#include "runtime.h"
static u8 transformed[4096];
int program_main(int argc, char **argv) {
    u32 key = 0; int reverse = 0;
    if (argc == 2 && text_equal(argv[1], "copy")) { }
    else if (argc == 2 && text_equal(argv[1], "reverse")) reverse = 1;
    else if (argc == 3 && text_equal(argv[1], "xor") && argument_uint(argv[2], &key) && key <= 255) { }
    else return error();
    int length = read_input("input.bin"); if (length < 0) return error();
    for (int i = 0; i < length; i++) transformed[i] = input[reverse ? length - 1 - i : i] ^ (u8)key;
    if (write_file("output.bin", transformed, (u32)length) != 0) return error();
    put_text("n="); put_uint((u32)length); put_text(" hash="); put_uint(fnv(transformed, (u32)length)); put_byte('\n'); return 0;
}
