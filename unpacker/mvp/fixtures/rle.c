#include "runtime.h"
int program_main(int argc, char **argv) {
    (void)argc; (void)argv;
    int length = read_input(0); if (length < 0 || length % 2) return error();
    for (int i = 0; i < length; i += 2) {
        u32 count = input[i];
        if (!count || output_length + count > 4096) return error();
        while (count--) put_byte(input[i+1]);
    }
    return 0;
}
