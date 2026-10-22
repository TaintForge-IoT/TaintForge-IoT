#ifndef TF_PHASE1_RESOURCES_H
#define TF_PHASE1_RESOURCES_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

bool tf_resources_configure(int argc, char **argv);
bool tf_resources_enabled(void);
size_t tf_resources_reserved(void);
uint64_t tf_resources_remaining(void);
void tf_resources_json(FILE *stream, bool owners);
int tf_resources_summary(char *output, size_t size);
void *tf_alloc_malloc(size_t size, const char *owner);
void *tf_alloc_malloc_array(size_t count, size_t size, const char *owner);
void *tf_alloc_calloc(size_t count, size_t size, const char *owner);
void *tf_alloc_realloc(void *data, size_t size, const char *owner);
void *tf_alloc_realloc_array(void *data, size_t count, size_t size, const char *owner);
void tf_alloc_free(void *data);
char *tf_alloc_strdup(const char *text, const char *owner);
char *tf_alloc_strndup(const char *text, size_t size, const char *owner);
char *tf_alloc_printf(const char *owner, const char *format, ...)
    __attribute__((format(printf, 2, 3)));

#endif
