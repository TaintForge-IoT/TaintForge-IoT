#include "runtime.h"
static i32 values[32];
int program_main(int argc, char **argv) {
    (void)argc; (void)argv;
    int length = read_input(0); if (length < 0) return error();
    Cursor cursor = { input, (u32)length, 0 }; u32 count = 0;
    skip_space(&cursor);
    while (cursor.at < cursor.length) {
        if (count == 32) return error();
        int negative = input[cursor.at] == '-'; if (negative) cursor.at++;
        if (cursor.at == cursor.length || input[cursor.at] < '0' || input[cursor.at] > '9') return error();
        u32 value;
        if (!uint_value(&cursor, &value) || value > (negative ? 2147483648u : 2147483647u)) return error();
        if (cursor.at < cursor.length && !space(input[cursor.at])) return error();
        values[count++] = (i32)(negative ? 0u - value : value); skip_space(&cursor);
    }
    for (u32 i = 1; i < count; i++) {
        i32 value = values[i]; u32 j = i;
        while (j && values[j-1] > value) { values[j] = values[j-1]; j--; }
        values[j] = value;
    }
    for (u32 i = 0; i < count; i++) { if (i) put_byte(','); put_int(values[i]); }
    put_byte('\n'); return 0;
}
