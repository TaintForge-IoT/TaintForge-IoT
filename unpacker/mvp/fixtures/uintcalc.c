#include "runtime.h"
int program_main(int argc, char **argv) {
    u32 left, right, value;
    if (argc != 4 || !argument_uint(argv[2], &left) || !argument_uint(argv[3], &right)) return error();
    if (text_equal(argv[1], "sum")) value = left + right;
    else if (text_equal(argv[1], "xor")) value = left ^ right;
    else if (text_equal(argv[1], "mul")) value = left * right;
    else if (text_equal(argv[1], "rot") && right < 32) value = right ? (left << right) | (left >> (32 - right)) : left;
    else return error();
    put_uint(value); put_byte('\n'); return 0;
}
