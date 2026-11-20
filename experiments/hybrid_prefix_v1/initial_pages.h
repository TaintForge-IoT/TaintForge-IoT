#ifndef TF_HYBRID_INITIAL_PAGES_H
#define TF_HYBRID_INITIAL_PAGES_H
#include <stdbool.h>
#include <stdint.h>
#include "elf_image.h"

typedef bool (*TfHybridInstallPage)(void *, uint64_t, unsigned);

/* This experiment admits a static i386 image with disjoint load pages.
 * Establish protections before any guest STORE. A STORE alone never adds X. */
static inline bool tf_hybrid_initial_pages(const TfElfImage *image, uint64_t page_size,
                                           void *context, TfHybridInstallPage install)
{
    if (!image || !install || page_size != 4096 || !image->load_count ||
        image->load_count > TF_ELF_MAX_LOADS)
        return false;
    uint64_t total = 0;
    for (size_t i = 0; i < image->load_count; ++i) {
        const TfElfLoad *load = &image->loads[i];
        if (!load->memory_size || (load->flags & ~7U) ||
            load->address >= (UINT64_C(1) << 32) ||
            load->memory_size > (UINT64_C(1) << 32) - load->address)
            return false;
        uint64_t begin = load->address & ~(page_size - 1);
        uint64_t end = (load->address + load->memory_size + page_size - 1) & ~(page_size - 1);
        total += (end - begin) / page_size;
        if (total > 4096)
            return false;
        for (size_t j = 0; j < i; ++j) {
            const TfElfLoad *other = &image->loads[j];
            uint64_t low = other->address & ~(page_size - 1);
            uint64_t high = (other->address + other->memory_size + page_size - 1) & ~(page_size - 1);
            if (begin < high && low < end)
                return false;
        }
    }
    for (size_t i = 0; i < image->load_count; ++i) {
        const TfElfLoad *load = &image->loads[i];
        uint64_t begin = load->address & ~(page_size - 1);
        uint64_t end = (load->address + load->memory_size + page_size - 1) & ~(page_size - 1);
        unsigned prot = ((load->flags & 4U) ? 1U : 0U) |
                        ((load->flags & 2U) ? 2U : 0U) |
                        ((load->flags & 1U) ? 4U : 0U);
        for (uint64_t address = begin; address < end; address += page_size)
            if (!install(context, address, prot))
                return false;
    }
    return true;
}
#endif
