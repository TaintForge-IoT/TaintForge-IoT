#include "runtime.h"
extern const u8 scale_blob[CV_IMAGE_BYTES];
int program_main(int argc, char **argv) {
    u32 iterations, value;
    if (argc != 3 || !argument_uint(argv[1], &iterations) || !argument_uint(argv[2], &value) || iterations > 1000000) return error();
    for (u32 i = 0; i < CV_IMAGE_BYTES; i++) value = (value ^ scale_blob[i]) * 16777619u;
    for (u32 i = 0; i < iterations; i++) value = value * 1664525u + 1013904223u;
    put_text("img="); put_uint(CV_IMAGE_BYTES); put_text(" iters="); put_uint(iterations); put_text(" value="); put_uint(value); put_byte('\n'); return 0;
}
