#include "runtime.h"
static u8 stack[16];
int program_main(int argc, char **argv) {
    (void)argc; (void)argv;
    int length = read_input(0); if (length < 0) return error();
    u32 depth = 0, pairs = 0, strings = 0; int quote = 0, escape = 0;
    for (int i = 0; i < length; i++) {
        u8 ch = input[i];
        if (quote) {
            if (escape) escape = 0;
            else if (ch == '\\') escape = 1;
            else if (ch == '"') { quote = 0; strings++; }
        } else if (ch == '"') quote = 1;
        else if (ch == '(' || ch == '[' || ch == '{') { if (depth == 16) return error(); stack[depth++] = ch; }
        else if (ch == ')' || ch == ']' || ch == '}') {
            u8 expected = ch == ')' ? '(' : ch == ']' ? '[' : '{';
            if (!depth || stack[--depth] != expected) return error();
            pairs++;
        }
    }
    if (quote || depth) return error();
    put_text("pairs="); put_uint(pairs); put_text(" strings="); put_uint(strings); put_text(" hash="); put_uint(fnv(input, (u32)length)); put_byte('\n'); return 0;
}
