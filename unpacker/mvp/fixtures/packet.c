#include "runtime.h"
int program_main(int argc, char **argv) {
    (void)argc; (void)argv;
    int length = read_input(0);
    if (length < 4 || input[0] != 'T' || input[1] != 'F' || input[2] != 1) return error();
    u32 at = 4, sum = 0, x = 0, bytes = 0;
    for (u32 i = 0; i < input[3]; i++) {
        if (at + 2 > (u32)length) return error();
        u32 type = input[at++], count = input[at++];
        if (at + count > (u32)length || (type != 1 && type != 2)) return error();
        for (u32 j = 0; j < count; j++) { if (type == 1) sum += input[at+j]; else x ^= input[at+j]; }
        bytes += count; at += count;
    }
    if (at != (u32)length) return error();
    put_text("bytes="); put_uint(bytes); put_text(" sum="); put_uint(sum); put_text(" xor="); put_uint(x); put_byte('\n'); return 0;
}
