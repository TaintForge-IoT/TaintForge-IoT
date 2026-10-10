#include "runtime.h"
static int digit(u8 value) {
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    if (value >= 'A' && value <= 'F') return value - 'A' + 10;
    return -1;
}
int program_main(int argc, char **argv) {
    (void)argc; (void)argv;
    int length = read_input(0), high = -1;
    if (length < 0) return error();
    for (int i = 0; i < length; i++) {
        if (space(input[i])) continue;
        int value = digit(input[i]);
        if (value < 0) return error();
        if (high < 0) high = value;
        else { put_byte((u8)(high * 16 + value)); high = -1; }
    }
    return high < 0 ? 0 : error();
}
