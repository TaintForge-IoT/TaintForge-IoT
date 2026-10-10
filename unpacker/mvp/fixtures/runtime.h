#ifndef TF_FIXTURE_RUNTIME_H
#define TF_FIXTURE_RUNTIME_H
typedef unsigned char u8;
typedef unsigned int u32;
typedef int i32;
typedef struct { const u8 *data; u32 length, at; } Cursor;
extern u8 input[4096];
extern u8 output[32768];
extern u32 output_length;
int read_input(const char *path);
int write_file(const char *path, const u8 *data, u32 length);
int error(void);
void put_byte(u8 value);
void put_text(const char *text);
void put_uint(u32 value);
void put_int(i32 value);
u32 text_length(const char *text);
int text_equal(const char *left, const char *right);
int space(u8 value);
void skip_space(Cursor *cursor);
int uint_value(Cursor *cursor, u32 *value);
int argument_uint(const char *text, u32 *value);
u32 fnv(const u8 *data, u32 length);
int program_main(int argc, char **argv);
#endif
