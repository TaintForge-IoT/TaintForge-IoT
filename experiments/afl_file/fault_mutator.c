/* Deterministic benign acceptance fixture, never enabled by production campaigns. */
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
void *afl_custom_init(void *afl, unsigned int seed)
{
    (void)afl; (void)seed;
    return calloc(1, sizeof(unsigned));
}
size_t afl_custom_fuzz(void *data, unsigned char *buf, size_t n, unsigned char **out,
                       unsigned char *other, size_t other_n, size_t maximum)
{
    static unsigned char value[89];
    (void)buf; (void)n; (void)other; (void)other_n;
    const unsigned char sequence[] = {'C','H','A','S','B','E','A','A'};
    memset(value, 'x', sizeof(value));
    unsigned index = (*(unsigned *)data)++;
    value[0] = index < sizeof(sequence) ? sequence[index] : 'A';
    *out = value;
    return value[0] == 'C' && maximum >= sizeof(value) ? sizeof(value) : 1;
}
void afl_custom_deinit(void *data) { free(data); }
