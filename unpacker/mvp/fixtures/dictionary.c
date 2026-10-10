#include "runtime.h"
static u32 keys[32], values[32];
static u8 present[32];
static int find(u32 key) { for (u32 i = 0; i < 32; i++) if (present[i] && keys[i] == key) return (int)i; return -1; }
int program_main(int argc, char **argv) {
    (void)argc; (void)argv;
    int length = read_input(0); if (length < 0) return error();
    Cursor cursor = { input, (u32)length, 0 }; skip_space(&cursor);
    while (cursor.at < cursor.length) {
        u8 op = input[cursor.at++]; u32 key, value;
        if ((op != '+' && op != '-' && op != '?') || !uint_value(&cursor, &key)) return error();
        int slot = find(key);
        if (op == '+') {
            if (!uint_value(&cursor, &value)) return error();
            if (slot < 0) { for (u32 i = 0; i < 32; i++) if (!present[i]) { slot = (int)i; break; } }
            if (slot < 0) return error();
            present[slot] = 1; keys[slot] = key; values[slot] = value;
        } else if (op == '-') { if (slot >= 0) present[slot] = 0; }
        else if (slot >= 0) { put_uint(values[slot]); put_byte('\n'); }
        else put_text("MISSING\n");
        skip_space(&cursor);
        if (cursor.at < cursor.length && input[cursor.at++] != ';') return error();
        skip_space(&cursor);
    }
    return 0;
}
