#include "runtime.h"
int program_main(int argc, char **argv) {
    (void)argc; (void)argv;
    int length = read_input(0); if (length < 0) return error();
    u32 at = 0, rows = 0, sum = 0;
    while (at < (u32)length) {
        u32 end = at; while (end < (u32)length && input[end] != '\n') end++;
        Cursor line = { input, end, at }; u32 a, b;
        if (!uint_value(&line, &a)) return error();
        skip_space(&line); if (line.at == end || input[line.at++] != ',') return error();
        if (!uint_value(&line, &b)) return error();
        skip_space(&line); if (line.at != end) return error();
        sum += a + b; rows++; at = end + 1;
    }
    put_text("rows="); put_uint(rows); put_text(" sum="); put_uint(sum); put_byte('\n'); return 0;
}
