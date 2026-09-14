#ifndef TF_ELF_IMAGE_H
#define TF_ELF_IMAGE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define TF_ELF_MAX_LOADS 512

typedef bool (*TfElfRead)(void *context, uint64_t offset, uint8_t *bytes, size_t size);

typedef struct {
    uint64_t phdr, phent, phnum, entry, page_size;
    unsigned pointer_bytes;
    bool big_endian;
} TfElfAux;

typedef struct {
    uint64_t address, memory_size, file_offset, file_size;
    uint32_t flags;
} TfElfLoad;

typedef struct {
    uint64_t bias, entry, lo, hi, file_bytes;
    size_t load_count;
    TfElfLoad loads[TF_ELF_MAX_LOADS];
} TfElfImage;

typedef enum {
    TF_ELF_OK,
    TF_ELF_INVALID,
    TF_ELF_READ_FAILED,
    TF_ELF_IDENTITY_MISMATCH,
    TF_ELF_ADDRESS_MISMATCH,
    TF_ELF_OVERLAPPING_LOADS,
    TF_ELF_BUDGET
} TfElfStatus;

/* Resolve before the first guest instruction. All readers must return an exact
 * read. The output is untouched on failure; no memory labels are applied here.
 * Negative ET_DYN biases and LOADs sharing virtual pages are unsupported.
 * File-offset aliases at distinct virtual addresses are supported. */
TfElfStatus tf_elf_image_resolve(TfElfRead file_read, void *file_context, uint64_t file_size,
                                 TfElfRead guest_read, void *guest_context, const TfElfAux *aux,
                                 uint64_t seed_budget, TfElfImage *out);
const char *tf_elf_status_name(TfElfStatus status);

#endif
