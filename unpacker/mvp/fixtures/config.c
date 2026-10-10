#include "runtime.h"
int program_main(int argc, char **argv) {
    (void)argc; (void)argv;
    int length = read_input("input.bin");
    if (length < 0) return error();
    u32 port = 80, mode = 0, seen = 0, at = 0;
    while (at < (u32)length) {
        u32 end = at; while (end < (u32)length && input[end] != '\n') end++;
        Cursor line = { input, end, at }; skip_space(&line);
        u32 key = line.at; while (line.at < end && input[line.at] >= 'a' && input[line.at] <= 'z') line.at++;
        if (line.at - key != 4) return error();
        int is_port = input[key] == 'p' && input[key+1] == 'o' && input[key+2] == 'r' && input[key+3] == 't';
        int is_mode = input[key] == 'm' && input[key+1] == 'o' && input[key+2] == 'd' && input[key+3] == 'e';
        skip_space(&line);
        if (line.at == end || input[line.at++] != '=') return error();
        u32 value;
        if (!uint_value(&line, &value)) return error();
        skip_space(&line); if (line.at != end) return error();
        if (is_port && !(seen & 1) && value >= 1 && value <= 65535) { port = value; seen |= 1; }
        else if (is_mode && !(seen & 2) && value <= 3) { mode = value; seen |= 2; }
        else return error();
        at = end + 1;
    }
    put_text("port="); put_uint(port); put_text(" mode="); put_uint(mode); put_byte('\n'); return 0;
}
