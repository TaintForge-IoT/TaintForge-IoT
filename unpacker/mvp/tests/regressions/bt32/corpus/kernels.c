/* Fixed bounded parser kernels for instruction-coverage evaluation. */
typedef unsigned int u32;
typedef unsigned char u8;
typedef int s32;
_Static_assert(sizeof(u32) == 4 && sizeof(s32) == 4, "32-bit arithmetic required");

__attribute__((noinline)) u32 tf_kernel(const u8 *p, u32 n) {
#if TF_KIND == 0
    if (n < 4) return 0xffffffffu;
    u32 value = 0;
    for (u32 i = 0; i < 4; ++i) {
        u32 c = p[i], digit;
        if (c >= '0' && c <= '9') digit = c - '0';
        else if (c >= 'a' && c <= 'f') digit = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') digit = c - 'A' + 10;
        else return 0xffff0000u | i;
        value = (value << 4) | digit;
    }
    return value;
#elif TF_KIND == 1
    if (!n || p[0] > 4 || (u32)p[0] + 1 > n) return 0xffffffffu;
    u32 value = 0;
    for (u32 i = 0; i < p[0]; ++i) value |= (u32)p[i + 1] << (8 * i);
    return value;
#elif TF_KIND == 2
    u32 value = 0;
    for (u32 i = 0; i < n && i < 4; ++i) {
        value |= (u32)(p[i] & 127u) << (7 * i);
        if (!(p[i] & 128u)) return value;
    }
    return 0xffffffffu;
#elif TF_KIND == 3
    u32 value = 2166136261u;
    for (u32 i = 0; i < n; ++i) value = (value ^ p[i]) * 16777619u;
    return value;
#elif TF_KIND == 4
    u32 value = 0;
    for (u32 i = 0; i < n; ++i) {
        value ^= p[i];
        for (u32 j = 0; j < 8; ++j)
            value = ((value << 1) ^ ((value & 128u) ? 7u : 0u)) & 255u;
    }
    return value;
#elif TF_KIND == 5
    if (!n) return 0xffffffffu;
    u8 carry;
    __asm__ volatile("btl %2, %1\n\tsetc %0"
        : "=qm"(carry) : "r"(0x800013u), "r"((u32)p[0]) : "cc");
    return carry;
#elif TF_KIND == 6
    if (n < 4) return 0xffffffffu;
    u32 value = (u32)p[0] | ((u32)p[1] << 8) | ((u32)p[2] << 16) | ((u32)p[3] << 24);
    return __builtin_bswap32(value);
#elif TF_KIND == 7
    if (n < 5) return 0xffffffffu;
    u32 value = (u32)p[0] | ((u32)p[1] << 8) | ((u32)p[2] << 16) | ((u32)p[3] << 24);
    s32 signed_value = (s32)value;
    if (signed_value > 1000) signed_value = 1000;
    if (signed_value < -1000) signed_value = -1000;
    return (u32)(signed_value + 1000) / ((u32)(p[4] & 15u) + 1u);
#else
#error Unsupported kernel kind
#endif
}
